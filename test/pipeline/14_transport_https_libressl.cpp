// test/pipeline/14_transport_https_libressl.cpp
// Test TransportProcess<LibreSSLPolicy> with XDP Poll against HTTPS server
//
// Usage: ./test_pipeline_transport_https_libressl <interface> <bpf_path> <ignored> <ignored>
// (Called by scripts/test_xdp.sh 14_transport_https_libressl.cpp)
//
// Build: make build-test-pipeline-transport_https_libressl USE_XDP=1 USE_LIBRESSL=1
//
// This test:
// - Forks XDP Poll process (core 2) and Transport process (core 4)
// - Connects to nginx.org on port 443 (HTTPS with LibreSSL)
// - Sends HTTPS GET requests every 0.5s until 3 messages sent OR 5 seconds elapsed
// - Verifies HTTP 200 responses via MSG_METADATA
// - Verifies HTTP/1.1 keep-alive: all requests must use the same connection
// - Verifies responses in MSG_INBOX are in series (not mixed out of order)
// - Waits 2 seconds after sending, then checks ringbuffer consumer caught up
// - Verifies response is complete (contains full HTML like curl output)
//
// Safety: Uses dedicated test interface, never touches default route

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <string>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>

#ifdef USE_XDP

#define DEBUG 0
#define DEBUG_IPC 0

// pipeline_data.hpp must be included FIRST as it includes disruptor headers
// before pipeline_config.hpp to avoid CACHE_LINE_SIZE macro conflict
#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/xdp_poll_process.hpp"
#include "../../src/pipeline/transport_process.hpp"
#include "../../src/pipeline/msg_inbox.hpp"
#include "../../src/policy/ssl.hpp"  // LibreSSLPolicy

using namespace websocket::pipeline;

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignments for latency-critical processes
constexpr int XDP_POLL_CPU_CORE = 2;
constexpr int TRANSPORT_CPU_CORE = 4;

// Test parameters
constexpr int MAX_MESSAGES = 3;                            // Max HTTPS requests to send
constexpr int TIMEOUT_SECONDS = 5;                         // Total timeout
constexpr int SEND_INTERVAL_MS = 500;                      // Send every 0.5s
constexpr int FINAL_DRAIN_MS = 2000;                       // Wait 2s after sending to check ringbuffer

// Hardcoded target (ignores script args)
static constexpr const char* HTTPS_HOST = "nginx.org";
static constexpr uint16_t HTTPS_PORT = 443;

// HTTP request format (sent over TLS)
static const char* HTTP_REQUEST =
    "GET / HTTP/1.1\r\n"
    "Host: nginx.org\r\n"
    "User-Agent: xdp-test/1.0\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

// Test configuration
std::string g_local_ip;  // Detected from interface

// Global shutdown flag
std::atomic<bool> g_shutdown{false};

void signal_handler(int) {
    g_shutdown.store(true, std::memory_order_release);
}

// Pin current process to specified CPU core with SCHED_FIFO priority
void pin_to_cpu(int core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        fprintf(stderr, "[CPU] WARNING: Failed to pin to core %d: %s\n", core, strerror(errno));
        return;
    }

    struct sched_param param = {};
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
        fprintf(stderr, "[CPU] WARNING: Failed to set SCHED_FIFO on core %d: %s\n", core, strerror(errno));
    }

    fprintf(stderr, "[CPU] Pinned to core %d\n", core);
}

uint64_t get_monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

// TSC frequency calibration
double g_tsc_freq_ghz = 0.0;

void calibrate_tsc() {
    uint64_t start_tsc = rdtsc();
    uint64_t start_ns = get_monotonic_ns();
    usleep(100000);  // 100ms
    uint64_t end_tsc = rdtsc();
    uint64_t end_ns = get_monotonic_ns();

    uint64_t elapsed_tsc = end_tsc - start_tsc;
    uint64_t elapsed_ns = end_ns - start_ns;
    g_tsc_freq_ghz = static_cast<double>(elapsed_tsc) / static_cast<double>(elapsed_ns);
    printf("[TSC] Calibrated: %.3f GHz (%.3f cycles/ns)\n", g_tsc_freq_ghz, g_tsc_freq_ghz);
}

// Resolve hostname to IP at runtime
std::string resolve_hostname(const char* hostname) {
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, nullptr, &hints, &res) != 0 || !res) {
        fprintf(stderr, "FAIL: Cannot resolve %s\n", hostname);
        return "";
    }

    auto* addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
    freeaddrinfo(res);

    printf("Resolved %s -> %s\n", hostname, ip_str);
    return ip_str;
}

}  // namespace

// ============================================================================
// IPC Ring Creation
// ============================================================================

class IPCRingManager {
public:
    IPCRingManager() {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string("transport_https_libressl_test_") + timestamp;
    }

    ~IPCRingManager() {
        cleanup();
    }

    bool create_ring(const char* name, size_t buffer_size, size_t event_size, uint8_t max_consumers = 1) {
        std::string base_path = std::string("/dev/shm/hft/") + ipc_ring_dir_ + "/" + name;
        std::string hdr_path = base_path + ".hdr";
        std::string dat_path = base_path + ".dat";

        uint32_t producer_offset = hftshm::default_producer_offset();
        uint32_t consumer_0_offset = hftshm::default_consumer_0_offset();
        uint32_t header_size = hftshm::header_segment_size(max_consumers);

        int hdr_fd = open(hdr_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (hdr_fd < 0) {
            fprintf(stderr, "[IPC] Failed to create header: %s\n", hdr_path.c_str());
            return false;
        }
        if (ftruncate(hdr_fd, header_size) < 0) {
            close(hdr_fd);
            return false;
        }
        void* hdr_ptr = mmap(nullptr, header_size, PROT_READ | PROT_WRITE, MAP_SHARED, hdr_fd, 0);
        close(hdr_fd);
        if (hdr_ptr == MAP_FAILED) return false;

        hftshm::metadata_init(hdr_ptr, max_consumers, event_size, buffer_size,
                              producer_offset, consumer_0_offset, header_size);

        auto* cursor = reinterpret_cast<std::atomic<int64_t>*>(
            static_cast<char*>(hdr_ptr) + producer_offset);
        auto* published = reinterpret_cast<std::atomic<int64_t>*>(
            static_cast<char*>(hdr_ptr) + producer_offset + hftshm::CACHE_LINE);
        cursor->store(-1, std::memory_order_relaxed);
        published->store(-1, std::memory_order_relaxed);

        for (uint8_t i = 0; i < max_consumers; ++i) {
            auto* cons_seq = reinterpret_cast<std::atomic<int64_t>*>(
                static_cast<char*>(hdr_ptr) + consumer_0_offset + i * 2 * hftshm::CACHE_LINE);
            cons_seq->store(-1, std::memory_order_relaxed);
        }

        munmap(hdr_ptr, header_size);

        int dat_fd = open(dat_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (dat_fd < 0) {
            fprintf(stderr, "[IPC] Failed to create data: %s\n", dat_path.c_str());
            unlink(hdr_path.c_str());
            return false;
        }
        if (ftruncate(dat_fd, buffer_size) < 0) {
            close(dat_fd);
            unlink(hdr_path.c_str());
            return false;
        }

        void* dat_ptr = mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, dat_fd, 0);
        close(dat_fd);
        if (dat_ptr == MAP_FAILED) {
            unlink(hdr_path.c_str());
            return false;
        }
        memset(dat_ptr, 0, buffer_size);
        munmap(dat_ptr, buffer_size);

        return true;
    }

    bool create_all_rings() {
        mkdir("/dev/shm/hft", 0755);
        std::string full_dir = "/dev/shm/hft/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "[IPC] Failed to create directory: %s\n", full_dir.c_str());
            return false;
        }

        // XDP Poll <-> Transport rings
        if (!create_ring("raw_inbox", RAW_INBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("raw_outbox", RAW_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("ack_outbox", ACK_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("pong_outbox", PONG_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;

        // Transport <-> Test rings
        if (!create_ring("msg_outbox", MSG_OUTBOX_SIZE * sizeof(MsgOutboxEvent),
                         sizeof(MsgOutboxEvent), 1)) return false;
        if (!create_ring("msg_metadata", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                         sizeof(MsgMetadata), 1)) return false;
        if (!create_ring("pongs", PONGS_SIZE * sizeof(PongFrameAligned),
                         sizeof(PongFrameAligned), 1)) return false;

        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;

        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = {
            "raw_inbox", "raw_outbox", "ack_outbox", "pong_outbox",
            "msg_outbox", "msg_metadata", "pongs"
        };

        for (const char* name : ring_names) {
            unlink((base + "/" + name + ".hdr").c_str());
            unlink((base + "/" + name + ".dat").c_str());
        }
        rmdir(base.c_str());
    }

    std::string get_ring_name(const char* ring) const {
        return ipc_ring_dir_ + "/" + ring;
    }

private:
    std::string ipc_ring_dir_;
};

// ============================================================================
// Network Helpers
// ============================================================================

bool get_interface_mac(const char* interface, uint8_t* mac_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    close(fd);

    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

bool get_interface_ip(const char* interface, std::string& ip_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    close(fd);

    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    ip_out = inet_ntoa(addr->sin_addr);
    return true;
}

bool get_gateway_mac(const char* interface, const char* gateway_ip, uint8_t* mac_out) {
    FILE* fp = fopen("/proc/net/arp", "r");
    if (!fp) return false;

    char line[256];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        char ip[64], hw_type[16], flags[16], mac_str[32], mask[16], dev[32];
        if (sscanf(line, "%63s %15s %15s %31s %15s %31s",
                   ip, hw_type, flags, mac_str, mask, dev) == 6) {
            if (strcmp(ip, gateway_ip) == 0 && strcmp(dev, interface) == 0) {
                unsigned int m[6];
                if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++) mac_out[i] = (uint8_t)m[i];
                    fclose(fp);
                    return true;
                }
            }
        }
    }
    fclose(fp);
    return false;
}

bool get_default_gateway(const char* interface, std::string& gateway_out) {
    FILE* fp = fopen("/proc/net/route", "r");
    if (!fp) return false;

    char line[256];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        char iface[32];
        unsigned int dest, gateway, flags;
        if (sscanf(line, "%31s %x %x %x", iface, &dest, &gateway, &flags) >= 4) {
            if (strcmp(iface, interface) == 0 && dest == 0 && gateway != 0) {
                struct in_addr addr;
                addr.s_addr = gateway;
                gateway_out = inet_ntoa(addr);
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

// ============================================================================
// Type Aliases
// ============================================================================

static constexpr bool PROFILING_ENABLED = true;

using XDPPollType = XDPPollProcess<
    IPCRingProducer<UMEMFrameDescriptor>,
    IPCRingConsumer<UMEMFrameDescriptor>,
    true,
    PROFILING_ENABLED>;

// Transport with LibreSSL
using TransportType = TransportProcess<
    LibreSSLPolicy,                        // LibreSSL for HTTPS
    IPCRingConsumer<UMEMFrameDescriptor>,
    IPCRingProducer<UMEMFrameDescriptor>,
    IPCRingProducer<UMEMFrameDescriptor>,
    IPCRingProducer<UMEMFrameDescriptor>,
    IPCRingConsumer<MsgOutboxEvent>,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>,
    PROFILING_ENABLED>;

// ============================================================================
// Test Class
// ============================================================================

class TransportHTTPSLibreSSLTest {
public:
    TransportHTTPSLibreSSLTest(const char* interface, const char* bpf_path)
        : interface_(interface), bpf_path_(bpf_path) {}

    bool setup() {
        printf("\n=== Setting up Transport HTTPS LibreSSL Test ===\n");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);

        https_target_ip_ = resolve_hostname(HTTPS_HOST);
        if (https_target_ip_.empty()) {
            fprintf(stderr, "FAIL: Cannot resolve %s\n", HTTPS_HOST);
            return false;
        }
        printf("Target:      %s:%u (%s)\n\n", HTTPS_HOST, HTTPS_PORT, https_target_ip_.c_str());

        calibrate_tsc();

        if (!get_interface_mac(interface_, local_mac_)) {
            fprintf(stderr, "FAIL: Cannot get MAC address for %s\n", interface_);
            return false;
        }
        printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_mac_[0], local_mac_[1], local_mac_[2],
               local_mac_[3], local_mac_[4], local_mac_[5]);

        if (!get_interface_ip(interface_, local_ip_)) {
            fprintf(stderr, "FAIL: Cannot get IP address for %s\n", interface_);
            return false;
        }
        printf("Local IP:  %s\n", local_ip_.c_str());
        g_local_ip = local_ip_;

        if (!get_default_gateway(interface_, gateway_ip_)) {
            fprintf(stderr, "FAIL: Cannot get gateway for %s\n", interface_);
            return false;
        }
        printf("Gateway:   %s\n", gateway_ip_.c_str());

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s >/dev/null 2>&1", gateway_ip_.c_str());
        [[maybe_unused]] int ping_ret = system(cmd);

        if (!get_gateway_mac(interface_, gateway_ip_.c_str(), gateway_mac_)) {
            fprintf(stderr, "FAIL: Cannot get gateway MAC for %s\n", gateway_ip_.c_str());
            return false;
        }
        printf("Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               gateway_mac_[0], gateway_mac_[1], gateway_mac_[2],
               gateway_mac_[3], gateway_mac_[4], gateway_mac_[5]);

        printf("HTTPS Target IP: %s\n", https_target_ip_.c_str());

        if (!ipc_manager_.create_all_rings()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        umem_size_ = UMEM_TOTAL_SIZE;
        umem_area_ = mmap(nullptr, umem_size_,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB,
                         -1, 0);
        if (umem_area_ == MAP_FAILED) {
            printf("WARN: Huge pages not available\n");
            umem_area_ = mmap(nullptr, umem_size_,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS,
                              -1, 0);
            if (umem_area_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate UMEM\n");
                return false;
            }
        }
        printf("UMEM: %p (%zu bytes)\n", umem_area_, umem_size_);

        msg_inbox_ = static_cast<MsgInbox*>(
            mmap(nullptr, sizeof(MsgInbox),
                 PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS,
                 -1, 0));
        if (msg_inbox_ == MAP_FAILED) {
            fprintf(stderr, "FAIL: Cannot allocate MsgInbox\n");
            return false;
        }
        msg_inbox_->init();

        conn_state_ = static_cast<ConnStateShm*>(
            mmap(nullptr, sizeof(ConnStateShm),
                 PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS,
                 -1, 0));
        if (conn_state_ == MAP_FAILED) {
            fprintf(stderr, "FAIL: Cannot allocate ConnStateShm\n");
            return false;
        }
        conn_state_->init();

        strncpy(conn_state_->target_host, https_target_ip_.c_str(), sizeof(conn_state_->target_host) - 1);
        conn_state_->target_port = HTTPS_PORT;
        strncpy(conn_state_->bpf_path, bpf_path_, sizeof(conn_state_->bpf_path) - 1);
        strncpy(conn_state_->interface_name, interface_, sizeof(conn_state_->interface_name) - 1);

        struct in_addr addr;
        inet_aton(local_ip_.c_str(), &addr);
        conn_state_->local_ip = addr.s_addr;
        memcpy(conn_state_->local_mac, local_mac_, 6);
        memcpy(conn_state_->remote_mac, gateway_mac_, 6);
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        if constexpr (PROFILING_ENABLED) {
            profiling_ = static_cast<ProfilingShm*>(
                mmap(nullptr, sizeof(ProfilingShm),
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS,
                     -1, 0));
            if (profiling_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate ProfilingShm\n");
                return false;
            }
            profiling_->init();
        }

        try {
            raw_inbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_inbox"));
            raw_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_outbox"));
            ack_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("ack_outbox"));
            pong_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pong_outbox"));
            msg_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_outbox"));
            msg_metadata_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata"));
            pongs_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pongs"));
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
            return false;
        }

        printf("=== Setup Complete ===\n\n");
        return true;
    }

    void teardown() {
        printf("\n=== Teardown ===\n");

        if (conn_state_) conn_state_->shutdown_all();
        g_shutdown.store(true);

        if (xdp_pid_ > 0) {
            kill(xdp_pid_, SIGTERM);
            waitpid(xdp_pid_, nullptr, 0);
        }
        if (transport_pid_ > 0) {
            kill(transport_pid_, SIGTERM);
            waitpid(transport_pid_, nullptr, 0);
        }

        delete raw_inbox_region_;
        delete raw_outbox_region_;
        delete ack_outbox_region_;
        delete pong_outbox_region_;
        delete msg_outbox_region_;
        delete msg_metadata_region_;
        delete pongs_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED) munmap(conn_state_, sizeof(ConnStateShm));
        if (msg_inbox_ && msg_inbox_ != MAP_FAILED) munmap(msg_inbox_, sizeof(MsgInbox));
        if (profiling_ && profiling_ != MAP_FAILED) munmap(profiling_, sizeof(ProfilingShm));
        if (umem_area_ && umem_area_ != MAP_FAILED) munmap(umem_area_, umem_size_);

        printf("=== Teardown Complete ===\n");
    }

    bool fork_processes() {
        xdp_pid_ = fork();
        if (xdp_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for XDP Poll failed\n");
            return false;
        }

        if (xdp_pid_ == 0) {
            run_xdp_poll_process();
            _exit(0);
        }

        printf("[PARENT] Forked XDP Poll process (PID %d)\n", xdp_pid_);

        printf("[PARENT] Waiting for XDP Poll ready...\n");
        if (!conn_state_->wait_for_handshake_xdp_ready(10000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for XDP Poll ready\n");
            return false;
        }
        printf("[PARENT] XDP Poll ready\n");

        transport_pid_ = fork();
        if (transport_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for Transport failed\n");
            return false;
        }

        if (transport_pid_ == 0) {
            run_transport_process();
            _exit(0);
        }

        printf("[PARENT] Forked Transport process (PID %d)\n", transport_pid_);

        printf("[PARENT] Waiting for TLS handshake (LibreSSL)...\n");
        auto start = std::chrono::steady_clock::now();
        while (!conn_state_->is_handshake_tls_ready()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > 15000) {
                fprintf(stderr, "FAIL: Timeout waiting for TLS handshake\n");
                return false;
            }
            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "FAIL: Transport process exited during TLS handshake\n");
                return false;
            }
            usleep(1000);
        }
        printf("[PARENT] TLS handshake complete (LibreSSL)\n");

        return true;
    }

    bool run_https_test() {
        printf("\n--- HTTPS GET Test (max %d msgs, %dms interval, %ds timeout) ---\n",
               MAX_MESSAGES, SEND_INTERVAL_MS, TIMEOUT_SECONDS);

        IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(*msg_outbox_region_);
        IPCRingConsumer<MsgMetadata> msg_metadata_cons(*msg_metadata_region_);

        int sent = 0;
        int received_chunks = 0;
        int complete_responses = 0;
        size_t total_response_bytes = 0;
        bool keep_alive_working = true;
        bool responses_in_order = true;
        int current_response_num = 0;
        uint32_t current_response_start = 0;
        uint32_t last_chunk_end = 0;
        bool in_response = false;

        std::vector<size_t> response_sizes;
        std::string accumulated_response;
        accumulated_response.reserve(1024 * 1024);

        auto start_time = std::chrono::steady_clock::now();
        auto last_send_time = start_time - std::chrono::seconds(1);

        size_t http_request_len = strlen(HTTP_REQUEST);

        auto process_response_chunk = [&](const MsgMetadata& meta) {
            if (meta.decrypted_len == 0) return;

            // Log new nic_packet_ct field
            printf("[META] offset=%u len=%u nic_packet_ct=%u\n",
                   meta.msg_inbox_offset, meta.decrypted_len, meta.nic_packet_ct);

            total_response_bytes += meta.decrypted_len;
            received_chunks++;

            const char* data = reinterpret_cast<const char*>(msg_inbox_->data_at(meta.msg_inbox_offset));
            uint32_t chunk_start = meta.msg_inbox_offset;
            uint32_t chunk_end = chunk_start + meta.decrypted_len;

            accumulated_response.append(data, meta.decrypted_len);

            const char* eol = static_cast<const char*>(memchr(data, '\r', meta.decrypted_len));
            size_t status_len = eol ? static_cast<size_t>(eol - data) : std::min<size_t>(meta.decrypted_len, 60);

            bool is_response_start = (meta.decrypted_len >= 12 && strncmp(data, "HTTP/1.", 7) == 0);

            if (is_response_start) {
                current_response_num++;
                printf("[RECV] Response #%d start @ offset %u: %.*s\n",
                       current_response_num, chunk_start, (int)status_len, data);

                if (in_response) {
                    fprintf(stderr, "[ORDER] ERROR: Response started before previous ended\n");
                    responses_in_order = false;
                }

                current_response_start = chunk_start;
                in_response = true;
            } else {
                printf("[RECV] Chunk %d @ offset %u: %u bytes\n", received_chunks, chunk_start, meta.decrypted_len);

                if (in_response && chunk_start < current_response_start) {
                    fprintf(stderr, "[ORDER] ERROR: Chunk offset out of order\n");
                    responses_in_order = false;
                }
            }

            last_chunk_end = chunk_end;

            if (accumulated_response.find("</html>") != std::string::npos ||
                accumulated_response.find("</HTML>") != std::string::npos) {
                complete_responses++;
                response_sizes.push_back(accumulated_response.size());
                printf("[RECV] Complete response #%d (%zu bytes)\n", complete_responses, accumulated_response.size());
                in_response = false;
                accumulated_response.clear();
            }
        };

        while (sent < MAX_MESSAGES) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            if (elapsed_s >= TIMEOUT_SECONDS) {
                printf("[TEST] Timeout reached\n");
                break;
            }

            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "[TEST] Transport died - keep-alive FAILED\n");
                keep_alive_working = false;
                break;
            }

            auto since_last = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_send_time).count();
            if (since_last >= SEND_INTERVAL_MS) {
                int64_t slot = msg_outbox_prod.try_claim();
                if (slot >= 0) {
                    auto& event = msg_outbox_prod[slot];
                    event.data_len = static_cast<uint16_t>(http_request_len);
                    event.msg_type = MSG_TYPE_DATA;
                    memcpy(event.data, HTTP_REQUEST, http_request_len);
                    msg_outbox_prod.publish(slot);
                    sent++;
                    last_send_time = now;
                    printf("[SENT] HTTPS GET #%d (keep-alive)\n", sent);
                }
            }

            MsgMetadata meta;
            while (msg_metadata_cons.try_consume(meta)) {
                process_response_chunk(meta);
            }

            usleep(1000);
        }

        if (!conn_state_->is_running(PROC_TRANSPORT) && complete_responses < sent) {
            keep_alive_working = false;
        }

        printf("[TEST] Draining responses...\n");
        auto drain_start = std::chrono::steady_clock::now();
        constexpr int MAX_DRAIN_MS = 10000;

        while (true) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - drain_start).count();

            if ((elapsed_ms >= FINAL_DRAIN_MS && complete_responses >= sent) || elapsed_ms >= MAX_DRAIN_MS) break;

            if (!conn_state_->is_running(PROC_TRANSPORT)) break;

            MsgMetadata meta;
            while (msg_metadata_cons.try_consume(meta)) {
                process_response_chunk(meta);
            }

            usleep(1000);
        }

        // Final wait
        auto final_wait_start = std::chrono::steady_clock::now();
        while (true) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - final_wait_start).count();
            if (elapsed_ms >= FINAL_DRAIN_MS) break;

            MsgMetadata meta;
            while (msg_metadata_cons.try_consume(meta)) {
                process_response_chunk(meta);
            }
            usleep(1000);
        }

        bool sizes_similar = true;
        size_t min_size = 0, max_size = 0, avg_size = 0;
        if (!response_sizes.empty()) {
            min_size = *std::min_element(response_sizes.begin(), response_sizes.end());
            max_size = *std::max_element(response_sizes.begin(), response_sizes.end());
            size_t sum = 0;
            for (size_t s : response_sizes) sum += s;
            avg_size = sum / response_sizes.size();
            if (min_size > 0) {
                double ratio = static_cast<double>(max_size) / static_cast<double>(min_size);
                sizes_similar = (ratio <= 1.20);
            }
        }

        printf("\n=== Test Results ===\n");
        printf("  Sent:              %d requests\n", sent);
        printf("  Complete responses: %d\n", complete_responses);
        printf("  Total bytes:       %zu\n", total_response_bytes);
        printf("  Keep-alive:        %s\n", keep_alive_working ? "WORKING" : "FAILED");
        printf("  Response order:    %s\n", responses_in_order ? "IN SERIES" : "MIXED");

        printf("\n--- Ring Buffer Status ---\n");
        int64_t metadata_prod_seq = msg_metadata_region_->producer_published()->load(std::memory_order_acquire);
        int64_t metadata_cons_seq = msg_metadata_cons.sequence();
        bool metadata_caught_up = metadata_cons_seq >= metadata_prod_seq;
        printf("  MSG_METADATA: caught_up=%s\n", metadata_caught_up ? "yes" : "NO");

        int64_t outbox_prod_seq = msg_outbox_region_->producer_published()->load(std::memory_order_acquire);
        int64_t outbox_cons_seq = msg_outbox_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        bool outbox_caught_up = outbox_cons_seq >= outbox_prod_seq;
        printf("  MSG_OUTBOX: caught_up=%s\n", outbox_caught_up ? "yes" : "NO");

        fflush(stdout);

        conn_state_->shutdown_all();
        if (xdp_pid_ > 0) waitpid(xdp_pid_, nullptr, 0);
        if (transport_pid_ > 0) waitpid(transport_pid_, nullptr, 0);
        xdp_pid_ = 0;
        transport_pid_ = 0;

        save_profiling_data();

        if (!keep_alive_working) { printf("\nFAIL: Keep-alive not working\n"); return false; }
        if (!responses_in_order) { printf("\nFAIL: Responses out of order\n"); return false; }
        if (complete_responses == 0) { printf("\nFAIL: No complete responses\n"); return false; }
        if (complete_responses < sent) { printf("\nFAIL: Missing responses\n"); return false; }
        if (!metadata_caught_up || !outbox_caught_up) { printf("\nFAIL: Ring buffer not caught up\n"); return false; }
        if (total_response_bytes < 1000) { printf("\nFAIL: Response too small\n"); return false; }
        if (!sizes_similar) { printf("\nFAIL: Response sizes differ\n"); return false; }

        printf("\nPASS: HTTPS/1.1 keep-alive working (LibreSSL)\n");
        return true;
    }

    void save_profiling_data() {
        if constexpr (!PROFILING_ENABLED) return;
        if (!profiling_) return;

        pid_t pid = getpid();

        auto save_buffer = [pid](const CycleSampleBuffer& buf, const char* name) {
            char filename[256];
            snprintf(filename, sizeof(filename), "/tmp/%s_profiling_%d.bin", name, pid);

            FILE* f = fopen(filename, "wb");
            if (!f) return;

            uint32_t count = std::min(buf.total_count, CycleSampleBuffer::SAMPLE_COUNT);
            uint32_t start_idx = (buf.total_count > CycleSampleBuffer::SAMPLE_COUNT)
                ? (buf.write_idx & CycleSampleBuffer::MASK) : 0;

            fwrite(&buf.total_count, sizeof(uint32_t), 1, f);
            fwrite(&count, sizeof(uint32_t), 1, f);

            for (uint32_t i = 0; i < count; ++i) {
                uint32_t idx = (start_idx + i) & CycleSampleBuffer::MASK;
                fwrite(&buf.samples[idx], sizeof(CycleSample), 1, f);
            }
            fclose(f);
            printf("[PROFILING] %s saved to %s\n", name, filename);
        };

        save_buffer(profiling_->xdp_poll, "xdp_poll");
        save_buffer(profiling_->transport, "transport");

        // Save NIC latency data
        {
            char filename[256];
            snprintf(filename, sizeof(filename), "/tmp/nic_latency_profiling_%d.bin", pid);

            FILE* f = fopen(filename, "wb");
            if (f) {
                const auto& buf = profiling_->nic_latency;
                uint32_t count = std::min(buf.total_count, NicLatencyBuffer::SAMPLE_COUNT);
                uint32_t start_idx = (buf.total_count > NicLatencyBuffer::SAMPLE_COUNT)
                    ? (buf.write_idx & NicLatencyBuffer::MASK) : 0;

                fwrite(&buf.total_count, sizeof(uint32_t), 1, f);
                fwrite(&count, sizeof(uint32_t), 1, f);

                for (uint32_t i = 0; i < count; ++i) {
                    uint32_t idx = (start_idx + i) & NicLatencyBuffer::MASK;
                    fwrite(&buf.samples[idx], sizeof(NicLatencySample), 1, f);
                }
                fclose(f);
                printf("[PROFILING] nic_latency saved to %s (%u samples)\n", filename, count);
            }
        }
    }

private:
    void run_xdp_poll_process() {
        pin_to_cpu(XDP_POLL_CPU_CORE);

        IPCRingProducer<UMEMFrameDescriptor> raw_inbox_prod(*raw_inbox_region_);
        IPCRingConsumer<UMEMFrameDescriptor> raw_outbox_cons(*raw_outbox_region_);
        IPCRingConsumer<UMEMFrameDescriptor> ack_outbox_cons(*ack_outbox_region_);
        IPCRingConsumer<UMEMFrameDescriptor> pong_outbox_cons(*pong_outbox_region_);

        XDPPollType xdp_poll(interface_);

        if constexpr (PROFILING_ENABLED) {
            xdp_poll.set_profiling_data(&profiling_->xdp_poll);
            xdp_poll.set_nic_latency_data(&profiling_->nic_latency);
        }

        bool ok = xdp_poll.init(
            umem_area_, umem_size_, bpf_path_,
            &raw_inbox_prod, &raw_outbox_cons, &ack_outbox_cons, &pong_outbox_cons,
            conn_state_);

        if (!ok) {
            fprintf(stderr, "[XDP-POLL] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        auto* bpf = xdp_poll.get_bpf_loader();
        if (bpf) {
            fprintf(stderr, "[XDP-POLL] Configuring BPF: local=%s, exchange=%s, port=%u\n",
                    g_local_ip.c_str(), https_target_ip_.c_str(), HTTPS_PORT);
            bpf->set_local_ip(g_local_ip.c_str());
            bpf->add_exchange_ip(https_target_ip_.c_str());
            bpf->add_exchange_port(HTTPS_PORT);
        }
        xdp_poll.run();
        xdp_poll.cleanup();
    }

    void run_transport_process() {
        pin_to_cpu(TRANSPORT_CPU_CORE);

        IPCRingConsumer<UMEMFrameDescriptor> raw_inbox_cons(*raw_inbox_region_);
        IPCRingProducer<UMEMFrameDescriptor> raw_outbox_prod(*raw_outbox_region_);
        IPCRingProducer<UMEMFrameDescriptor> ack_outbox_prod(*ack_outbox_region_);
        IPCRingProducer<UMEMFrameDescriptor> pong_outbox_prod(*pong_outbox_region_);
        IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(*msg_outbox_region_);
        IPCRingProducer<MsgMetadata> msg_metadata_prod(*msg_metadata_region_);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);

        TransportType transport;

        if constexpr (PROFILING_ENABLED) {
            transport.set_profiling_data(&profiling_->transport);
        }

        // Pass the hostname (not IP) for SNI - TCP stack will resolve it
        bool ok = transport.init_with_handshake(
            umem_area_, FRAME_SIZE,
            HTTPS_HOST, HTTPS_PORT,
            &raw_inbox_cons, &raw_outbox_prod, &ack_outbox_prod, &pong_outbox_prod,
            &msg_outbox_cons, &msg_metadata_prod, &pongs_cons,
            msg_inbox_, conn_state_);

        if (!ok) {
            fprintf(stderr, "[TRANSPORT] init_with_handshake() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        transport.run();
    }

    const char* interface_;
    const char* bpf_path_;
    std::string https_target_ip_;

    IPCRingManager ipc_manager_;

    void* umem_area_ = nullptr;
    size_t umem_size_ = 0;
    uint8_t local_mac_[6] = {};
    uint8_t gateway_mac_[6] = {};
    std::string local_ip_;
    std::string gateway_ip_;

    MsgInbox* msg_inbox_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;
    ProfilingShm* profiling_ = nullptr;

    disruptor::ipc::shared_region* raw_inbox_region_ = nullptr;
    disruptor::ipc::shared_region* raw_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* ack_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* pong_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_metadata_region_ = nullptr;
    disruptor::ipc::shared_region* pongs_region_ = nullptr;

    pid_t xdp_pid_ = 0;
    pid_t transport_pid_ = 0;
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [ignored...]\n", argv[0]);
        fprintf(stderr, "NOTE: Use ./scripts/test_xdp.sh 14_transport_https_libressl.cpp\n");
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];

    if (geteuid() == 0) {
        fprintf(stderr, "ERROR: Do NOT run as root!\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  Transport HTTPS Test (LibreSSLPolicy)       \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (HTTPS)\n", HTTPS_HOST, HTTPS_PORT);
    printf("  SSL:        LibreSSL\n");
    printf("==============================================\n\n");

    TransportHTTPSLibreSSLTest test(interface, bpf_path);

    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    if (!test.fork_processes()) {
        fprintf(stderr, "\nFATAL: Failed to fork processes\n");
        test.teardown();
        return 1;
    }

    usleep(500000);

    int result = 0;
    if (!test.run_https_test()) {
        result = 1;
    }

    test.teardown();

    printf("\n==============================================\n");
    printf("  TEST %s\n", result == 0 ? "PASSED" : "FAILED");
    printf("==============================================\n");

    return result;
}

#else

int main() {
    fprintf(stderr, "Error: Build with USE_XDP=1 USE_LIBRESSL=1\n");
    return 1;
}

#endif
