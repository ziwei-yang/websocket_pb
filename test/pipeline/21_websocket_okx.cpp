// test/pipeline/21_websocket_okx.cpp
// Test WebSocketProcess with XDP Poll + Transport against OKX WSS stream
//
// Usage: ./test_pipeline_websocket_okx <interface> <bpf_path> [ignored...] [--timeout <ms>]
// (Called by scripts/test_xdp.sh 21_websocket_okx.cpp)
//
// Build: make build-test-pipeline-websocket_okx USE_XDP=1 USE_WOLFSSL=1
//
// Options:
//   --timeout <ms>   Stream timeout in milliseconds (default: 5000)
//                    If <= 0, run forever and display every message received
//
// This test:
// - Forks XDP Poll (core 2), Transport (core 4), WebSocket (core 6)
// - Connects to ws.okx.com on port 8443 (WSS with WolfSSL)
// - WebSocketProcess handles HTTP+WS handshake, frame parsing
// - Parent consumes WS_FRAME_INFO ring, validates JSON orderbook events
// - Verifies ring buffer consumers caught up
//
// Safety: Uses dedicated test interface, never touches default route

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
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
#include "../../src/pipeline/00_xdp_poll_process.hpp"
#include "../../src/pipeline/10_tcp_ssl_process.hpp"
#include "../../src/pipeline/20_ws_process.hpp"
#include "../../src/pipeline/msg_inbox.hpp"
#include "../../src/core/http.hpp"
#include "../../src/policy/ssl.hpp"  // WolfSSLPolicy

using namespace websocket::pipeline;

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignments for latency-critical processes
constexpr int XDP_POLL_CPU_CORE = 2;
constexpr int TRANSPORT_CPU_CORE = 4;
constexpr int WEBSOCKET_CPU_CORE = 6;

// Test parameters (defaults, can be overridden by --timeout argument)
constexpr int DEFAULT_STREAM_DURATION_MS = 5000;   // Stream for 5 seconds
constexpr int FINAL_DRAIN_MS = 2000;               // Wait 2s after streaming
constexpr int MIN_EXPECTED_UPDATES = 10;           // Expect at least 10 orderbook updates in 5s for BTC-USDT-SWAP

// Runtime timeout (set by --timeout argument)
int g_timeout_ms = DEFAULT_STREAM_DURATION_MS;     // -1 or 0 = run forever

// WebSocket target
static constexpr const char* WSS_HOST = "ws.okx.com";
static constexpr uint16_t WSS_PORT = 8443;
static constexpr const char* WSS_PATH = "/ws/v5/public";

// Test configuration
std::string g_local_ip;  // Detected from interface

// Global shutdown flag and connection state pointer for signal handler
std::atomic<bool> g_shutdown{false};
ConnStateShm* g_conn_state = nullptr;  // Set after setup, used by signal handler

void signal_handler(int sig) {
    g_shutdown.store(true, std::memory_order_release);
    // Notify all processes to stop immediately
    if (g_conn_state) {
        g_conn_state->shutdown_all();
    }
    fprintf(stderr, "\n[SIGNAL] Received signal %d, initiating graceful shutdown...\n", sig);
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

// Validate OKX orderbook JSON
bool is_valid_orderbook_json(const char* data, size_t len) {
    std::string_view sv(data, len);
    // OKX books5 events have {"arg":{"channel":"books5",...},"data":[...]}
    if (sv.find("\"arg\"") == std::string_view::npos) return false;
    if (sv.find("\"channel\":\"books5\"") == std::string_view::npos) return false;
    if (sv.find("\"data\"") == std::string_view::npos) return false;
    return true;
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
        ipc_ring_dir_ = std::string("websocket_okx_test_") + timestamp;
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

        // Transport <-> WebSocket rings
        if (!create_ring("msg_outbox", MSG_OUTBOX_SIZE * sizeof(MsgOutboxEvent),
                         sizeof(MsgOutboxEvent), 1)) return false;
        if (!create_ring("msg_metadata", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                         sizeof(MsgMetadata), 1)) return false;
        if (!create_ring("pongs", PONGS_SIZE * sizeof(PongFrameAligned),
                         sizeof(PongFrameAligned), 1)) return false;

        // WebSocket <-> Parent (Test) ring
        if (!create_ring("ws_frame_info", WS_FRAME_INFO_SIZE * sizeof(WSFrameInfo),
                         sizeof(WSFrameInfo), 1)) return false;

        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;

        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = {
            "raw_inbox", "raw_outbox", "ack_outbox", "pong_outbox",
            "msg_outbox", "msg_metadata", "pongs", "ws_frame_info"
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

// Enable debug modes
static constexpr bool PROFILING_ENABLED = true;
static constexpr bool DEBUG_TCP_ENABLED = true;  // TCP debug mode for retransmit detection
static constexpr bool DEBUG_XDP_ENABLED = true;  // XDP debug mode for fill-ring monitoring

// XDP Poll Process types (with profiling and debug enabled)
using XDPPollType = XDPPollProcess<
    IPCRingProducer<UMEMFrameDescriptor>,
    IPCRingConsumer<UMEMFrameDescriptor>,
    true,                                   // TrickleEnabled
    PROFILING_ENABLED,                      // Profiling
    256,                                    // FrameHeadroom (default)
    2048,                                   // FrameSize (default)
    DEBUG_XDP_ENABLED>;                     // DebugXDP - fill-ring monitoring

// Transport Process types (with WolfSSL and profiling enabled)
using TransportType = TransportProcess<
    WolfSSLPolicy,                         // WolfSSL for WSS
    IPCRingConsumer<UMEMFrameDescriptor>,  // RawInboxCons
    IPCRingProducer<UMEMFrameDescriptor>,  // RawOutboxProd
    IPCRingProducer<UMEMFrameDescriptor>,  // AckOutboxProd
    IPCRingProducer<UMEMFrameDescriptor>,  // PongOutboxProd
    IPCRingConsumer<MsgOutboxEvent>,       // MsgOutboxCons
    IPCRingProducer<MsgMetadata>,          // MsgMetadataProd
    IPCRingConsumer<PongFrameAligned>,     // PongsCons
    PROFILING_ENABLED,                     // Profiling
    true,                                  // TCPTimestampEnabled (RFC 7323)
    DEBUG_TCP_ENABLED,                     // DebugTCP - retransmit detection
    2,                                     // TcpDelackNum (ACK after N packets)
    40,                                    // TcpDelackMinMs (min delay before ACK)
    200>;                                  // TcpDelackMaxMs (max delay, forced ACK)

// WebSocket Process types
using WebSocketType = WebSocketProcess<
    IPCRingConsumer<MsgMetadata>,          // MsgMetadataCons
    IPCRingProducer<WSFrameInfo>,          // WSFrameInfoProd
    IPCRingProducer<PongFrameAligned>,     // PongsProd
    IPCRingProducer<MsgOutboxEvent>>;      // MsgOutboxProd

// ============================================================================
// Test Class
// ============================================================================

class WebSocketOkxTest {
public:
    WebSocketOkxTest(const char* interface, const char* bpf_path)
        : interface_(interface), bpf_path_(bpf_path) {}

    bool setup() {
        printf("\n=== Setting up WebSocket OKX Test ===\n");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);

        // Resolve WSS target
        wss_target_ip_ = resolve_hostname(WSS_HOST);
        if (wss_target_ip_.empty()) {
            fprintf(stderr, "FAIL: Cannot resolve %s\n", WSS_HOST);
            return false;
        }
        printf("Target:      %s:%u (%s)\n", WSS_HOST, WSS_PORT, wss_target_ip_.c_str());
        printf("Path:        %s\n\n", WSS_PATH);

        calibrate_tsc();

        // Get interface MAC
        if (!get_interface_mac(interface_, local_mac_)) {
            fprintf(stderr, "FAIL: Cannot get MAC address for %s\n", interface_);
            return false;
        }
        printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_mac_[0], local_mac_[1], local_mac_[2],
               local_mac_[3], local_mac_[4], local_mac_[5]);

        // Get interface IP
        if (!get_interface_ip(interface_, local_ip_)) {
            fprintf(stderr, "FAIL: Cannot get IP address for %s\n", interface_);
            return false;
        }
        printf("Local IP:  %s\n", local_ip_.c_str());
        g_local_ip = local_ip_;

        // Get gateway
        if (!get_default_gateway(interface_, gateway_ip_)) {
            fprintf(stderr, "FAIL: Cannot get gateway for %s\n", interface_);
            return false;
        }
        printf("Gateway:   %s\n", gateway_ip_.c_str());

        // Ping gateway to populate ARP cache
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

        printf("WSS Target IP: %s (route must be set by test script)\n", wss_target_ip_.c_str());

        // Create IPC rings
        if (!ipc_manager_.create_all_rings()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        // Allocate UMEM (shared between processes via MAP_SHARED)
        umem_size_ = UMEM_TOTAL_SIZE;
        umem_area_ = mmap(nullptr, umem_size_,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB,
                         -1, 0);
        if (umem_area_ == MAP_FAILED) {
            printf("WARN: Huge pages not available, using regular pages\n");
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

        // Allocate MsgInbox (shared)
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
        printf("MsgInbox: %p\n", msg_inbox_);

        // Allocate ConnStateShm (shared)
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

        // Set target and network config in shared state (use resolved IP)
        strncpy(conn_state_->target_host, WSS_HOST, sizeof(conn_state_->target_host) - 1);
        conn_state_->target_port = WSS_PORT;
        strncpy(conn_state_->target_path, WSS_PATH, sizeof(conn_state_->target_path) - 1);
        strncpy(conn_state_->bpf_path, bpf_path_, sizeof(conn_state_->bpf_path) - 1);
        strncpy(conn_state_->interface_name, interface_, sizeof(conn_state_->interface_name) - 1);

        // Set subscription JSON for OKX books5 channel
        strncpy(conn_state_->subscription_json,
                R"({"op":"subscribe","args":[{"channel":"books5","instId":"BTC-USDT-SWAP"}]})",
                sizeof(conn_state_->subscription_json) - 1);

        // Set local IP in network byte order
        struct in_addr addr;
        inet_aton(local_ip_.c_str(), &addr);
        conn_state_->local_ip = addr.s_addr;

        // Set local MAC
        memcpy(conn_state_->local_mac, local_mac_, 6);
        memcpy(conn_state_->remote_mac, gateway_mac_, 6);

        // Set TSC frequency
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        printf("ConnStateShm: %p\n", conn_state_);

        // Allocate ProfilingShm (shared between processes)
        if constexpr (PROFILING_ENABLED) {
            profiling_ = static_cast<ProfilingShm*>(
                mmap(nullptr, sizeof(ProfilingShm),
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS,
                     -1, 0));
            if (profiling_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate ProfilingShm (%zu bytes)\n", sizeof(ProfilingShm));
                return false;
            }
            profiling_->init();
            printf("ProfilingShm: %p (%zu bytes)\n", profiling_, sizeof(ProfilingShm));
        }

        // Open shared regions (after ring files created, before fork)
        try {
            raw_inbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_inbox"));
            raw_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_outbox"));
            ack_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("ack_outbox"));
            pong_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pong_outbox"));
            msg_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_outbox"));
            msg_metadata_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata"));
            pongs_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pongs"));
            ws_frame_info_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("ws_frame_info"));
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

        // Wait for child processes
        if (xdp_pid_ > 0) {
            kill(xdp_pid_, SIGTERM);
            waitpid(xdp_pid_, nullptr, 0);
        }
        if (transport_pid_ > 0) {
            kill(transport_pid_, SIGTERM);
            waitpid(transport_pid_, nullptr, 0);
        }
        if (websocket_pid_ > 0) {
            kill(websocket_pid_, SIGTERM);
            waitpid(websocket_pid_, nullptr, 0);
        }

        // Cleanup shared regions
        delete raw_inbox_region_;
        delete raw_outbox_region_;
        delete ack_outbox_region_;
        delete pong_outbox_region_;
        delete msg_outbox_region_;
        delete msg_metadata_region_;
        delete pongs_region_;
        delete ws_frame_info_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED) {
            munmap(conn_state_, sizeof(ConnStateShm));
        }
        if (msg_inbox_ && msg_inbox_ != MAP_FAILED) {
            munmap(msg_inbox_, sizeof(MsgInbox));
        }
        if (profiling_ && profiling_ != MAP_FAILED) {
            munmap(profiling_, sizeof(ProfilingShm));
        }
        if (umem_area_ && umem_area_ != MAP_FAILED) {
            munmap(umem_area_, umem_size_);
        }

        printf("=== Teardown Complete ===\n");
    }

    bool fork_processes() {
        // Fork XDP Poll process
        xdp_pid_ = fork();
        if (xdp_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for XDP Poll failed\n");
            return false;
        }

        if (xdp_pid_ == 0) {
            // Child: XDP Poll process
            run_xdp_poll_process();
            _exit(0);
        }

        printf("[PARENT] Forked XDP Poll process (PID %d)\n", xdp_pid_);

        // Wait for XDP Poll to be ready
        printf("[PARENT] Waiting for XDP Poll ready...\n");
        if (!conn_state_->wait_for_handshake_xdp_ready(10000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for XDP Poll ready\n");
            return false;
        }
        printf("[PARENT] XDP Poll ready\n");

        // Fork Transport process
        transport_pid_ = fork();
        if (transport_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for Transport failed\n");
            return false;
        }

        if (transport_pid_ == 0) {
            // Child: Transport process
            run_transport_process();
            _exit(0);
        }

        printf("[PARENT] Forked Transport process (PID %d)\n", transport_pid_);

        // Wait for TLS handshake to complete (WolfSSL requires actual TLS handshake)
        printf("[PARENT] Waiting for TLS handshake (WolfSSL)...\n");
        auto start = std::chrono::steady_clock::now();
        while (!conn_state_->is_handshake_tls_ready()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > 15000) {  // 15s timeout for TLS handshake
                fprintf(stderr, "FAIL: Timeout waiting for TLS handshake\n");
                return false;
            }
            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "FAIL: Transport process exited during TLS handshake\n");
                return false;
            }
            usleep(1000);
        }
        printf("[PARENT] TLS handshake complete (WolfSSL)\n");

        // Fork WebSocket process
        websocket_pid_ = fork();
        if (websocket_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for WebSocket failed\n");
            return false;
        }

        if (websocket_pid_ == 0) {
            // Child: WebSocket process
            run_websocket_process();
            _exit(0);
        }

        printf("[PARENT] Forked WebSocket process (PID %d)\n", websocket_pid_);

        // Wait for WebSocket handshake to complete
        printf("[PARENT] Waiting for WebSocket handshake...\n");
        if (!conn_state_->wait_for_handshake_ws_ready(30000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for WebSocket handshake\n");
            return false;
        }
        printf("[PARENT] WebSocket handshake complete\n");

        return true;
    }

    bool run_stream_test() {
        bool run_forever = (g_timeout_ms <= 0);

        if (run_forever) {
            printf("\n--- WSS Stream Test (FOREVER MODE - Ctrl+C to stop) ---\n");
        } else {
            printf("\n--- WSS Stream Test (%dms, expect %d+ orderbook updates) ---\n",
                   g_timeout_ms, MIN_EXPECTED_UPDATES);
        }

        // Create consumer for WS_FRAME_INFO ring
        IPCRingConsumer<WSFrameInfo> ws_frame_cons(*ws_frame_info_region_);

        // Tracking metrics
        uint64_t total_frames = 0;
        uint64_t text_frames = 0;
        uint64_t binary_frames = 0;
        uint64_t ping_frames = 0;
        uint64_t pong_frames = 0;
        uint64_t close_frames = 0;
        uint64_t valid_updates = 0;
        int64_t last_sequence = -1;
        bool sequence_error = false;

        auto start_time = std::chrono::steady_clock::now();
        auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

        printf("[WSS] Starting stream reception...\n");

        // Main streaming loop
        while (run_forever || std::chrono::steady_clock::now() < stream_end) {
            if (g_shutdown.load(std::memory_order_acquire)) {
                printf("[WSS] Shutdown signal received\n");
                break;
            }

            if (!conn_state_->is_running(PROC_WEBSOCKET)) {
                fprintf(stderr, "[WSS] WebSocket process exited during streaming\n");
                break;
            }

            // Process WS_FRAME_INFO events
            WSFrameInfo frame;
            bool end_of_batch;
            while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
                total_frames++;

                // Verify sequence ordering
                int64_t current_seq = ws_frame_cons.sequence();
                if (last_sequence != -1 && current_seq != last_sequence + 1) {
                    fprintf(stderr, "WARN: Out-of-order frame! Expected %ld, got %ld\n",
                            last_sequence + 1, current_seq);
                    sequence_error = true;
                }
                last_sequence = current_seq;

                // Count by opcode
                switch (frame.opcode) {
                    case 0x01:  // TEXT
                        text_frames++;
                        // Validate JSON orderbook data
                        if (frame.payload_len > 0) {
                            const uint8_t* payload = msg_inbox_->data_at(frame.msg_inbox_offset);
                            if (is_valid_orderbook_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                                valid_updates++;
                                // In forever mode, display every message; otherwise only first 3
                                if (run_forever || valid_updates <= 3) {
                                    printf("[ORDERBOOK #%lu] %.*s\n",
                                           valid_updates,
                                           (int)std::min(static_cast<uint32_t>(500), frame.payload_len),
                                           reinterpret_cast<const char*>(payload));
                                }
                            }
                        }
                        break;

                    case 0x02:  // BINARY
                        binary_frames++;
                        break;

                    case 0x09:  // PING
                        ping_frames++;
                        {
                            auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
                                std::chrono::steady_clock::now() - start_time).count();
                            int64_t pongs_prod = pongs_region_->producer_published()->load(std::memory_order_acquire);
                            int64_t pongs_cons = pongs_region_->consumer_sequence(0)->load(std::memory_order_acquire);
                            printf("[PING @%lds] Received PING (payload_len=%u) - PONGS ring: prod=%ld, cons=%ld\n",
                                   elapsed_s, frame.payload_len, pongs_prod, pongs_cons);
                            fflush(stdout);
                        }
                        break;

                    case 0x0A:  // PONG
                        pong_frames++;
                        break;

                    case 0x08:  // CLOSE
                        close_frames++;
                        printf("[CLOSE] Received CLOSE frame\n");
                        break;

                    default:
                        break;
                }
            }

            // Status logging consolidated in TRANSPORT process (see transport_process.hpp)

            __builtin_ia32_pause();
        }

        // Final drain (skip in forever mode since we're exiting on signal)
        if (!run_forever) {
            printf("[WSS] Final %dms drain...\n", FINAL_DRAIN_MS);
            auto drain_start = std::chrono::steady_clock::now();

            while (true) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - drain_start).count();
                if (elapsed_ms >= FINAL_DRAIN_MS) break;

                WSFrameInfo frame;
                while (ws_frame_cons.try_consume(frame)) {
                    total_frames++;
                    if (frame.opcode == 0x01) {
                        text_frames++;
                        if (frame.payload_len > 0) {
                            const uint8_t* payload = msg_inbox_->data_at(frame.msg_inbox_offset);
                            if (is_valid_orderbook_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                                valid_updates++;
                            }
                        }
                    }
                }
                usleep(1000);
            }
        }

        auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();

        printf("\n=== Test Results ===\n");
        printf("  Duration:        %ld ms\n", actual_duration);
        printf("  Total frames:    %lu\n", total_frames);
        printf("  TEXT frames:     %lu\n", text_frames);
        printf("  BINARY frames:   %lu\n", binary_frames);
        printf("  PING frames:     %lu\n", ping_frames);
        printf("  PONG frames:     %lu\n", pong_frames);
        // PONG deficit check: compare PINGs received with PONGs queued
        {
            int64_t pongs_queued = pongs_region_->producer_published()->load(std::memory_order_acquire) + 1;  // +1 for 0-based
            int64_t deficit = static_cast<int64_t>(ping_frames) - pongs_queued;
            if (deficit > 0) {
                printf("  PONG DEFICIT:    %ld (PINGs received but PONGs not queued - INVESTIGATE!)\n", deficit);
            } else {
                printf("  PONG balance:    OK (all PINGs have corresponding PONGs queued)\n");
            }
        }
        printf("  CLOSE frames:    %lu\n", close_frames);
        printf("  Valid updates:   %lu\n", valid_updates);
        printf("  Sequence errors: %s\n", sequence_error ? "YES" : "none");

        // Verify ring buffer status
        printf("\n--- Ring Buffer Status ---\n");

        // WS_FRAME_INFO
        int64_t ws_frame_prod = ws_frame_info_region_->producer_published()->load(std::memory_order_acquire);
        int64_t ws_frame_cons_seq = ws_frame_cons.sequence();
        bool ws_frame_caught_up = ws_frame_cons_seq >= ws_frame_prod;
        printf("  WS_FRAME_INFO producer: %ld, consumer: %ld\n", ws_frame_prod, ws_frame_cons_seq);
        printf("  Consumer caught up: %s\n", ws_frame_caught_up ? "yes" : "NO - FAIL");

        // MSG_METADATA
        int64_t meta_prod = msg_metadata_region_->producer_published()->load(std::memory_order_acquire);
        int64_t meta_cons = msg_metadata_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        bool meta_caught_up = meta_cons >= meta_prod - 1;  // Allow 1 pending
        printf("  MSG_METADATA producer: %ld, consumer: %ld\n", meta_prod, meta_cons);
        printf("  Consumer caught up: %s\n", meta_caught_up ? "yes" : "NO - FAIL");

        // MSG_OUTBOX
        int64_t outbox_prod = msg_outbox_region_->producer_published()->load(std::memory_order_acquire);
        int64_t outbox_cons = msg_outbox_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        bool outbox_caught_up = outbox_cons >= outbox_prod;
        printf("  MSG_OUTBOX producer: %ld, consumer: %ld\n", outbox_prod, outbox_cons);
        printf("  Consumer caught up: %s\n", outbox_caught_up ? "yes" : "NO - FAIL");

        // PONGS
        int64_t pongs_prod = pongs_region_->producer_published()->load(std::memory_order_acquire);
        int64_t pongs_cons = pongs_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        bool pongs_caught_up = pongs_cons >= pongs_prod;
        printf("  PONGS producer: %ld, consumer: %ld\n", pongs_prod, pongs_cons);
        printf("  Consumer caught up: %s\n", pongs_caught_up ? "yes" : "NO - FAIL");

        printf("====================\n");
        fflush(stdout);

        // Signal children to stop and wait
        conn_state_->shutdown_all();
        if (xdp_pid_ > 0) waitpid(xdp_pid_, nullptr, 0);
        if (transport_pid_ > 0) waitpid(transport_pid_, nullptr, 0);
        if (websocket_pid_ > 0) waitpid(websocket_pid_, nullptr, 0);
        xdp_pid_ = 0;
        transport_pid_ = 0;
        websocket_pid_ = 0;

        // Save profiling data
        save_profiling_data();

        // === FAILURE CONDITIONS ===

        // In forever mode, always pass if we got frames (was killed by timeout command or Ctrl+C)
        if (run_forever) {
            printf("\nFOREVER MODE: Received %lu orderbook updates over %ld ms\n",
                   valid_updates, actual_duration);
            printf("PASS: Forever mode completed (terminated by signal)\n");
            return true;
        }

        // 1. Check we received WebSocket frames
        if (total_frames == 0) {
            printf("\nFAIL: No WebSocket frames received\n");
            return false;
        }

        // 2. Check we received orderbook data
        if (valid_updates < static_cast<uint64_t>(MIN_EXPECTED_UPDATES)) {
            printf("\nFAIL: Only %lu orderbook updates received (expected %d+)\n",
                   valid_updates, MIN_EXPECTED_UPDATES);
            return false;
        }

        // 3. Check ringbuffer consumer caught up
        if (!ws_frame_caught_up) {
            printf("\nFAIL: WS_FRAME_INFO consumer did not catch up with producer\n");
            return false;
        }

        // 4. Check for sequence errors
        if (sequence_error) {
            printf("\nFAIL: Out-of-order frame delivery detected\n");
            return false;
        }

        printf("\nPASS: WebSocket process working, received %lu orderbook updates in %ld ms\n",
               valid_updates, actual_duration);
        return true;
    }

    void save_profiling_data() {
        if constexpr (!PROFILING_ENABLED) return;
        if (!profiling_) return;

        pid_t pid = getpid();

        // Helper to save a CycleSampleBuffer to file
        auto save_buffer = [pid](const CycleSampleBuffer& buf, const char* name) {
            char filename[256];
            snprintf(filename, sizeof(filename), "/tmp/%s_profiling_%d.bin", name, pid);

            FILE* f = fopen(filename, "wb");
            if (!f) {
                fprintf(stderr, "[PROFILING] Failed to create %s\n", filename);
                return;
            }

            uint32_t count = std::min(buf.total_count, CycleSampleBuffer::SAMPLE_COUNT);
            uint32_t start_idx = (buf.total_count > CycleSampleBuffer::SAMPLE_COUNT)
                ? (buf.write_idx & CycleSampleBuffer::MASK)
                : 0;

            // Write header: total_count, sample_count
            fwrite(&buf.total_count, sizeof(uint32_t), 1, f);
            fwrite(&count, sizeof(uint32_t), 1, f);

            // Write samples in order (oldest to newest)
            for (uint32_t i = 0; i < count; ++i) {
                uint32_t idx = (start_idx + i) & CycleSampleBuffer::MASK;
                fwrite(&buf.samples[idx], sizeof(CycleSample), 1, f);
            }
            fclose(f);
            printf("[PROFILING] %s saved to %s (%u samples, %u total)\n",
                   name, filename, count, buf.total_count);
        };

        save_buffer(profiling_->xdp_poll, "xdp_poll");
        save_buffer(profiling_->transport, "transport");

        // Save NIC latency data
        {
            char filename[256];
            snprintf(filename, sizeof(filename), "/tmp/nic_latency_profiling_%d.bin", pid);

            FILE* f = fopen(filename, "wb");
            if (!f) {
                fprintf(stderr, "[PROFILING] Failed to create %s\n", filename);
                return;
            }

            const auto& buf = profiling_->nic_latency;
            uint32_t count = std::min(buf.total_count, NicLatencyBuffer::SAMPLE_COUNT);
            uint32_t start_idx = (buf.total_count > NicLatencyBuffer::SAMPLE_COUNT)
                ? (buf.write_idx & NicLatencyBuffer::MASK)
                : 0;

            // Write header: total_count, sample_count
            fwrite(&buf.total_count, sizeof(uint32_t), 1, f);
            fwrite(&count, sizeof(uint32_t), 1, f);

            // Write samples in order (oldest to newest)
            for (uint32_t i = 0; i < count; ++i) {
                uint32_t idx = (start_idx + i) & NicLatencyBuffer::MASK;
                fwrite(&buf.samples[idx], sizeof(NicLatencySample), 1, f);
            }
            fclose(f);
            printf("[PROFILING] nic_latency saved to %s (%u samples, %u total)\n",
                   filename, count, buf.total_count);
        }
    }

    // Getter for connection state (used by signal handler)
    ConnStateShm* get_conn_state() const { return conn_state_; }

private:
    // XDP Poll child process
    void run_xdp_poll_process() {
        pin_to_cpu(XDP_POLL_CPU_CORE);

        // Create ring adapters in child process
        IPCRingProducer<UMEMFrameDescriptor> raw_inbox_prod(*raw_inbox_region_);
        IPCRingConsumer<UMEMFrameDescriptor> raw_outbox_cons(*raw_outbox_region_);
        IPCRingConsumer<UMEMFrameDescriptor> ack_outbox_cons(*ack_outbox_region_);
        IPCRingConsumer<UMEMFrameDescriptor> pong_outbox_cons(*pong_outbox_region_);

        XDPPollType xdp_poll(interface_);

        // Set profiling data buffers
        if constexpr (PROFILING_ENABLED) {
            xdp_poll.set_profiling_data(&profiling_->xdp_poll);
            xdp_poll.set_nic_latency_data(&profiling_->nic_latency);
        }

        bool ok = xdp_poll.init(
            umem_area_, umem_size_, bpf_path_,
            &raw_inbox_prod,
            &raw_outbox_cons,
            &ack_outbox_cons,
            &pong_outbox_cons,
            conn_state_);

        if (!ok) {
            fprintf(stderr, "[XDP-POLL] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        // Configure BPF maps for WSS target traffic
        auto* bpf = xdp_poll.get_bpf_loader();
        if (bpf) {
            fprintf(stderr, "[XDP-POLL] Configuring BPF maps: local_ip=%s, exchange_ip=%s, port=%u\n",
                    g_local_ip.c_str(), wss_target_ip_.c_str(), WSS_PORT);
            bpf->set_local_ip(g_local_ip.c_str());
            bpf->add_exchange_ip(wss_target_ip_.c_str());
            bpf->add_exchange_port(WSS_PORT);
        } else {
            fprintf(stderr, "[XDP-POLL] WARNING: BPF loader is NULL!\n");
        }
        xdp_poll.run();
        xdp_poll.cleanup();
    }

    // Transport child process
    void run_transport_process() {
        pin_to_cpu(TRANSPORT_CPU_CORE);

        // Create ring adapters in child process
        IPCRingConsumer<UMEMFrameDescriptor> raw_inbox_cons(*raw_inbox_region_);
        IPCRingProducer<UMEMFrameDescriptor> raw_outbox_prod(*raw_outbox_region_);
        IPCRingProducer<UMEMFrameDescriptor> ack_outbox_prod(*ack_outbox_region_);
        IPCRingProducer<UMEMFrameDescriptor> pong_outbox_prod(*pong_outbox_region_);
        IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(*msg_outbox_region_);
        IPCRingProducer<MsgMetadata> msg_metadata_prod(*msg_metadata_region_);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);

        TransportType transport;

        // Set profiling data buffer
        if constexpr (PROFILING_ENABLED) {
            transport.set_profiling_data(&profiling_->transport);
        }

        // Pass the hostname (not IP) for SNI
        bool ok = transport.init_with_handshake(
            umem_area_, FRAME_SIZE,
            WSS_HOST, WSS_PORT,
            &raw_inbox_cons,
            &raw_outbox_prod,
            &ack_outbox_prod,
            &pong_outbox_prod,
            &msg_outbox_cons,
            &msg_metadata_prod,
            &pongs_cons,
            msg_inbox_,
            conn_state_);

        if (!ok) {
            fprintf(stderr, "[TRANSPORT] init_with_handshake() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        fprintf(stderr, "[TRANSPORT] TLS handshake complete, running main loop\n");
        transport.run();
    }

    // WebSocket child process
    void run_websocket_process() {
        pin_to_cpu(WEBSOCKET_CPU_CORE);

        // Create ring adapters in child process
        IPCRingConsumer<MsgMetadata> msg_metadata_cons(*msg_metadata_region_);
        IPCRingProducer<WSFrameInfo> ws_frame_info_prod(*ws_frame_info_region_);
        IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(*msg_outbox_region_);
        IPCRingProducer<PongFrameAligned> pongs_prod(*pongs_region_);

        WebSocketType ws_process;

        bool ok = ws_process.init(
            msg_inbox_,
            &msg_metadata_cons,
            &ws_frame_info_prod,
            &pongs_prod,
            &msg_outbox_prod,
            conn_state_);

        if (!ok) {
            fprintf(stderr, "[WS-PROCESS] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        // Run with handshake (performs HTTP upgrade, subscription, then main loop)
        ws_process.run_with_handshake();
    }

    const char* interface_;
    const char* bpf_path_;
    std::string wss_target_ip_;  // Resolved IP of WSS_HOST

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
    disruptor::ipc::shared_region* ws_frame_info_region_ = nullptr;

    pid_t xdp_pid_ = 0;
    pid_t transport_pid_ = 0;
    pid_t websocket_pid_ = 0;
};

// ============================================================================
// Main
// ============================================================================

// Parse --timeout argument from argv
void parse_args(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            g_timeout_ms = atoi(argv[i + 1]);
            printf("[ARGS] Timeout set to %d ms%s\n",
                   g_timeout_ms, g_timeout_ms <= 0 ? " (FOREVER MODE)" : "");
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [ignored...] [--timeout <ms>]\n", argv[0]);
        fprintf(stderr, "NOTE: Do NOT run directly. Use: USE_WOLFSSL=1 ./scripts/test_xdp.sh 21_websocket_okx.cpp\n");
        fprintf(stderr, "\nOptions:\n");
        fprintf(stderr, "  --timeout <ms>   Stream timeout in milliseconds (default: %d)\n", DEFAULT_STREAM_DURATION_MS);
        fprintf(stderr, "                   If <= 0, run forever (display all messages, Ctrl+C to stop)\n");
        fprintf(stderr, "\nThis test:\n");
        fprintf(stderr, "  - Forks XDP Poll (core 2), Transport<WolfSSL> (core 4), WebSocket (core 6)\n");
        fprintf(stderr, "  - Connects to %s:%u (WSS with WolfSSL)\n", WSS_HOST, WSS_PORT);
        fprintf(stderr, "  - WebSocketProcess handles HTTP+WS handshake\n");
        fprintf(stderr, "  - Streams BTC-USDT-SWAP books5 orderbook updates for the specified timeout\n");
        fprintf(stderr, "  - Parent consumes WS_FRAME_INFO, validates JSON orderbook data\n");
        fprintf(stderr, "  - Expects at least %d orderbook updates (BTC-USDT-SWAP is very liquid)\n", MIN_EXPECTED_UPDATES);
        fprintf(stderr, "  - Waits %dms, then verifies ringbuffer consumers caught up\n", FINAL_DRAIN_MS);
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  USE_WOLFSSL=1 ./scripts/test_xdp.sh 21_websocket_okx.cpp                # Default 5s\n");
        fprintf(stderr, "  USE_WOLFSSL=1 ./scripts/test_xdp.sh 21_websocket_okx.cpp --timeout 10000  # 10s\n");
        fprintf(stderr, "  USE_WOLFSSL=1 ./scripts/test_xdp.sh 21_websocket_okx.cpp --timeout -1     # Forever\n");
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];

    // Parse optional arguments
    parse_args(argc, argv);

    // PREVENT ROOT USER FROM RUNNING
    if (geteuid() == 0) {
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "ERROR: Do NOT run as root!\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "\nRun via the wrapper script which sets capabilities properly:\n");
        fprintf(stderr, "  USE_WOLFSSL=1 ./scripts/test_xdp.sh 21_websocket_okx.cpp\n");
        return 1;
    }

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  WebSocket OKX Test                          \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (WSS)\n", WSS_HOST, WSS_PORT);
    printf("  Path:       %s\n", WSS_PATH);
    printf("  SSL:        WolfSSL\n");
    printf("  Processes:  XDP Poll (core %d)\n", XDP_POLL_CPU_CORE);
    printf("              Transport (core %d)\n", TRANSPORT_CPU_CORE);
    printf("              WebSocket (core %d)\n", WEBSOCKET_CPU_CORE);
    if (g_timeout_ms <= 0) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
        printf("  Mode:       Display all messages\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
        printf("  Expected:   %d+ orderbook updates\n", MIN_EXPECTED_UPDATES);
        printf("  Drain:      %dms then check ringbuffers\n", FINAL_DRAIN_MS);
    }
    printf("==============================================\n\n");

    WebSocketOkxTest test(interface, bpf_path);

    // Setup
    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    // Set global conn_state for signal handler to use
    g_conn_state = test.get_conn_state();

    // Fork processes
    if (!test.fork_processes()) {
        fprintf(stderr, "\nFATAL: Failed to fork processes\n");
        test.teardown();
        return 1;
    }

    // Give processes time to stabilize
    usleep(500000);  // 500ms

    // Run streaming test
    int result = 0;
    if (!test.run_stream_test()) {
        result = 1;
    }

    // Cleanup
    test.teardown();

    // Summary
    printf("\n==============================================\n");
    if (result == 0) {
        printf("  TEST PASSED\n");
    } else {
        printf("  TEST FAILED\n");
    }
    printf("==============================================\n");

    return result;
}

#else  // !USE_XDP

int main() {
    fprintf(stderr, "Error: Build with USE_XDP=1 USE_WOLFSSL=1\n");
    fprintf(stderr, "Example: make build-test-pipeline-websocket_okx USE_XDP=1 USE_WOLFSSL=1\n");
    return 1;
}

#endif  // USE_XDP
