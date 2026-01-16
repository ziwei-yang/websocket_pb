// test/pipeline/10_transport_tcp.cpp
// Test TransportProcess<NoSSLPolicy> with XDP Poll against TCP echo server
//
// Usage: ./test_pipeline_transport_tcp <interface> <bpf_path> <echo_ip> <echo_port>
// (Called by scripts/test_xdp.sh 10_transport_tcp.cpp)
//
// This test:
// - Forks XDP Poll process (core 2) and Transport process (core 4)
// - Connects to TCP echo server (no TLS via NoSSLPolicy)
// - Sends 5000 messages at 1ms intervals via MSG_OUTBOX
// - Verifies echo responses via MSG_METADATA
// - Timeout: 5 seconds total
//
// Safety: Uses dedicated test interface, never touches default route

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#ifdef USE_XDP

#define DEBUG 0
#define DEBUG_IPC 0

// pipeline_data.hpp must be included FIRST as it includes disruptor headers
// before pipeline_config.hpp to avoid CACHE_LINE_SIZE macro conflict
#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/xdp_poll_process.hpp"
#include "../../src/pipeline/transport_process.hpp"
#include "../../src/pipeline/msg_inbox.hpp"
#include "../../src/policy/ssl.hpp"  // NoSSLPolicy

using namespace websocket::pipeline;

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignments for latency-critical processes
constexpr int XDP_POLL_CPU_CORE = 2;
constexpr int TRANSPORT_CPU_CORE = 4;

// Test parameters
constexpr int MAX_MESSAGES = 5000;                         // Max messages to send
constexpr int TIMEOUT_SECONDS = 5;                         // Total timeout
constexpr int SEND_INTERVAL_MS = 1;                        // Send every 1ms
constexpr uint64_t TEST_TIMEOUT_NS = 5'000'000'000ULL;     // 5 seconds in ns

// Test configuration - set from command line
std::string g_echo_server_ip = "139.162.79.171";
uint16_t g_echo_server_port = 12345;
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

// Get realtime clock (for comparison with NIC PHC timestamp)
uint64_t get_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

// ============================================================================
// Latency Statistics
// ============================================================================

struct LatencyStats {
    int64_t min_ns = INT64_MAX;
    int64_t max_ns = INT64_MIN;
    int64_t sum_ns = 0;
    uint64_t count = 0;

    // Histogram buckets (in microseconds): <4, 4-5, 5-6, 6-7, 7-8, 8-10, 10-15, 15-20, 20-50, 50+
    static constexpr int NUM_BUCKETS = 10;
    uint64_t histogram[NUM_BUCKETS] = {};

    int get_bucket(int64_t latency_ns) const {
        int64_t us = latency_ns / 1000;  // Convert to microseconds
        if (us < 4) return 0;
        if (us < 5) return 1;
        if (us < 6) return 2;
        if (us < 7) return 3;
        if (us < 8) return 4;
        if (us < 10) return 5;
        if (us < 15) return 6;
        if (us < 20) return 7;
        if (us < 50) return 8;
        return 9;
    }

    void update(int64_t latency_ns) {
        if (latency_ns < min_ns) min_ns = latency_ns;
        if (latency_ns > max_ns) max_ns = latency_ns;
        sum_ns += latency_ns;
        count++;
        histogram[get_bucket(latency_ns)]++;
    }

    void print(const char* name) const {
        if (count == 0) {
            printf("\n=== %s Latency Stats ===\n", name);
            printf("No samples - cannot compute latency\n");
            printf("=====================================\n\n");
            return;
        }

        int64_t avg_ns = sum_ns / static_cast<int64_t>(count);

        printf("\n=== %s Latency Stats ===\n", name);
        printf("  Samples:    %lu\n", count);
        printf("  Min:        %ld ns (%.3f us)\n", min_ns, min_ns / 1000.0);
        printf("  Max:        %ld ns (%.3f us)\n", max_ns, max_ns / 1000.0);
        printf("  Avg:        %ld ns (%.3f us)\n", avg_ns, avg_ns / 1000.0);

        // Print histogram
        printf("\n  Latency Histogram:\n");
        const char* bucket_labels[NUM_BUCKETS] = {
            "  < 4us", "  4-5us", "  5-6us", "  6-7us", "  7-8us",
            " 8-10us", "10-15us", "15-20us", "20-50us", "  50+us"
        };

        // Find max bucket for scaling
        uint64_t max_bucket = 0;
        for (int i = 0; i < NUM_BUCKETS; i++) {
            if (histogram[i] > max_bucket) max_bucket = histogram[i];
        }

        // Print histogram bars
        constexpr int BAR_WIDTH = 40;
        for (int i = 0; i < NUM_BUCKETS; i++) {
            uint64_t b = histogram[i];
            double pct = (count > 0) ? 100.0 * b / count : 0;
            int bar_len = (max_bucket > 0) ? static_cast<int>(BAR_WIDTH * b / max_bucket) : 0;

            printf("  %s |", bucket_labels[i]);
            for (int j = 0; j < bar_len; j++) printf("█");
            for (int j = bar_len; j < BAR_WIDTH; j++) printf(" ");
            printf("| %6lu (%5.1f%%)\n", b, pct);
        }
        printf("=====================================\n");
        fflush(stdout);
    }
};

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
        ipc_ring_dir_ = std::string("transport_tcp_test_") + timestamp;
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

        // XDP Poll <-> Transport rings (all use UMEMFrameDescriptor for type unification)
        if (!create_ring("raw_inbox", RAW_INBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("raw_outbox", RAW_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("ack_outbox", ACK_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("pong_outbox", PONG_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;

        // Transport <-> Test (Parent) rings
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

// Enable profiling
static constexpr bool PROFILING_ENABLED = true;

// XDP Poll Process types (with profiling enabled)
using XDPPollType = XDPPollProcess<
    IPCRingProducer<UMEMFrameDescriptor>,
    IPCRingConsumer<UMEMFrameDescriptor>,
    true,                                   // TrickleEnabled
    PROFILING_ENABLED>;                     // Profiling

// Transport Process types (with profiling enabled)
// All outbox rings use UMEMFrameDescriptor for XDPPollProcess compatibility
using TransportType = TransportProcess<
    NoSSLPolicy,
    IPCRingConsumer<UMEMFrameDescriptor>,  // RawInboxCons
    IPCRingProducer<UMEMFrameDescriptor>,  // RawOutboxProd
    IPCRingProducer<UMEMFrameDescriptor>,  // AckOutboxProd (unified type)
    IPCRingProducer<UMEMFrameDescriptor>,  // PongOutboxProd (unified type)
    IPCRingConsumer<MsgOutboxEvent>,       // MsgOutboxCons
    IPCRingProducer<MsgMetadata>,          // MsgMetadataProd
    IPCRingConsumer<PongFrameAligned>,     // PongsCons
    PROFILING_ENABLED>;                    // Profiling

// ============================================================================
// Test Class
// ============================================================================

class TransportTCPTest {
public:
    TransportTCPTest(const char* interface, const char* bpf_path,
                     const char* echo_ip, uint16_t echo_port)
        : interface_(interface), bpf_path_(bpf_path),
          echo_ip_(echo_ip), echo_port_(echo_port) {}

    bool setup() {
        printf("\n=== Setting up Transport TCP Test ===\n");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);
        printf("Echo Server: %s:%u\n\n", echo_ip_, echo_port_);

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

        // Set target and network config in shared state
        strncpy(conn_state_->target_host, echo_ip_, sizeof(conn_state_->target_host) - 1);
        conn_state_->target_port = echo_port_;
        strncpy(conn_state_->bpf_path, bpf_path_, sizeof(conn_state_->bpf_path) - 1);
        strncpy(conn_state_->interface_name, interface_, sizeof(conn_state_->interface_name) - 1);

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

        // Cleanup shared regions
        delete raw_inbox_region_;
        delete raw_outbox_region_;
        delete ack_outbox_region_;
        delete pong_outbox_region_;
        delete msg_outbox_region_;
        delete msg_metadata_region_;
        delete pongs_region_;

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

        // Wait for TCP handshake to complete (TLS skipped for NoSSLPolicy)
        printf("[PARENT] Waiting for TCP handshake...\n");
        auto start = std::chrono::steady_clock::now();
        while (!conn_state_->is_handshake_tls_ready()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > 10000) {
                fprintf(stderr, "FAIL: Timeout waiting for TCP handshake\n");
                return false;
            }
            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "FAIL: Transport process exited during handshake\n");
                return false;
            }
            usleep(1000);
        }
        printf("[PARENT] TCP handshake complete (TLS skipped for NoSSLPolicy)\n");

        return true;
    }

    bool run_roundtrip_test() {
        printf("\n--- Roundtrip Echo Test (max %d msgs, timeout %ds, interval %dms) ---\n",
               MAX_MESSAGES, TIMEOUT_SECONDS, SEND_INTERVAL_MS);

        // Create producer/consumer for parent
        IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(*msg_outbox_region_);
        IPCRingConsumer<MsgMetadata> msg_metadata_cons(*msg_metadata_region_);

        int sent = 0;
        int received = 0;
        int metadata_count = 0;
        size_t received_bytes = 0;
        auto start_time = std::chrono::steady_clock::now();
        auto last_send_time = start_time;

        // Latency tracking
        LatencyStats nic_to_xdp_latency;      // NIC PHC -> XDP Poll
        LatencyStats xdp_to_transport_latency; // XDP Poll -> Transport
        LatencyStats transport_to_ssl_latency; // Transport -> SSL read
        LatencyStats total_latency;            // NIC PHC -> SSL read

        // Helper to process metadata and compute latencies
        auto process_metadata = [&](const MsgMetadata& meta) {
            if (meta.decrypted_len == 0) return;

            metadata_count++;
            received_bytes += meta.decrypted_len;

            // Parse concatenated messages: count "TEST_MSG_" occurrences
            const char* data = reinterpret_cast<const char*>(msg_inbox_) + meta.msg_inbox_offset;
            for (uint32_t i = 0; i + 9 <= meta.decrypted_len; i++) {
                if (memcmp(data + i, "TEST_MSG_", 9) == 0) {
                    received++;
                }
            }

            // Compute latencies from timestamp chain
            // All latencies use "latest" packet timestamps for consistency (same packet through pipeline)
            // NIC PHC -> XDP Poll: convert XDP poll cycle to realtime and compare with NIC timestamp
            if (meta.latest_nic_timestamp_ns != 0 && meta.latest_nic_frame_poll_cycle != 0) {
                uint64_t now_tsc = rdtsc();
                uint64_t now_realtime_ns = get_realtime_ns();
                uint64_t elapsed_cycles = now_tsc - meta.latest_nic_frame_poll_cycle;
                uint64_t elapsed_ns = static_cast<uint64_t>(elapsed_cycles / g_tsc_freq_ghz);
                uint64_t xdp_poll_realtime_ns = now_realtime_ns - elapsed_ns;

                int64_t nic_to_xdp_ns = static_cast<int64_t>(xdp_poll_realtime_ns) -
                                       static_cast<int64_t>(meta.latest_nic_timestamp_ns);
                if (nic_to_xdp_ns > 0 && nic_to_xdp_ns < 1'000'000'000) {  // Sanity check < 1s
                    nic_to_xdp_latency.update(nic_to_xdp_ns);
                }
            }

            // XDP Poll -> Transport: cycle difference (same packet)
            // XDP Poll -> Transport: use latest packet timestamps (same packet)
            if (meta.latest_nic_frame_poll_cycle != 0 && meta.latest_raw_frame_poll_cycle != 0) {
                uint64_t cycles = meta.latest_raw_frame_poll_cycle - meta.latest_nic_frame_poll_cycle;
                int64_t ns = static_cast<int64_t>(cycles / g_tsc_freq_ghz);
                if (ns > 0 && ns < 1'000'000'000) {
                    xdp_to_transport_latency.update(ns);
                }
            }

            // Transport -> SSL read: cycle difference
            if (meta.latest_raw_frame_poll_cycle != 0 && meta.ssl_read_cycle != 0) {
                uint64_t cycles = meta.ssl_read_cycle - meta.latest_raw_frame_poll_cycle;
                int64_t ns = static_cast<int64_t>(cycles / g_tsc_freq_ghz);
                if (ns > 0 && ns < 1'000'000'000) {
                    transport_to_ssl_latency.update(ns);
                }
            }

            // Total: NIC PHC -> SSL read (using latest packet for consistency)
            if (meta.latest_nic_timestamp_ns != 0 && meta.ssl_read_cycle != 0) {
                uint64_t now_tsc = rdtsc();
                uint64_t now_realtime_ns = get_realtime_ns();
                uint64_t elapsed_cycles = now_tsc - meta.ssl_read_cycle;
                uint64_t elapsed_ns = static_cast<uint64_t>(elapsed_cycles / g_tsc_freq_ghz);
                uint64_t ssl_read_realtime_ns = now_realtime_ns - elapsed_ns;

                int64_t total_ns = static_cast<int64_t>(ssl_read_realtime_ns) -
                                  static_cast<int64_t>(meta.latest_nic_timestamp_ns);
                if (total_ns > 0 && total_ns < 1'000'000'000) {
                    total_latency.update(total_ns);
                }
            }
        };

        // Main test loop
        while (sent < MAX_MESSAGES) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            if (elapsed_s >= TIMEOUT_SECONDS) {
                printf("[TEST] Timeout reached after %ld seconds\n", elapsed_s);
                break;
            }

            // Check if Transport is still running
            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "[TEST] Transport process exited\n");
                break;
            }

            // Send next message if 1ms has passed
            auto since_last = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_send_time).count();
            if (since_last >= SEND_INTERVAL_MS) {
                // Prepare test message
                char msg[64];
                snprintf(msg, sizeof(msg), "TEST_MSG_%04d", sent);
                size_t msg_len = strlen(msg);

                // Send via MSG_OUTBOX: try_claim() + fill + publish()
                int64_t slot = msg_outbox_prod.try_claim();
                if (slot >= 0) {
                    auto& event = msg_outbox_prod[slot];
                    event.data_len = static_cast<uint16_t>(msg_len);
                    event.msg_type = MSG_TYPE_DATA;
                    memcpy(event.data, msg, msg_len);
                    msg_outbox_prod.publish(slot);
                    sent++;
                    last_send_time = now;

                    if (sent % 500 == 0) {
                        printf("[PROGRESS] Sent: %d, Received: %d\n", sent, received);
                    }
                }
            }

            // Check for echo responses via MSG_METADATA
            MsgMetadata meta;
            if (msg_metadata_cons.try_consume(meta)) {
                process_metadata(meta);
            }
        }

        // Wait 10ms for pipeline to drain
        usleep(10000);

        // Check for any remaining responses
        MsgMetadata meta;
        while (msg_metadata_cons.try_consume(meta)) {
            process_metadata(meta);
        }

        auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();

        // Calculate expected bytes (each message is "TEST_MSG_XXXX" = 13 bytes)
        size_t sent_bytes = sent * 13;

        printf("\n=== Test Results ===\n");
        printf("  Duration:     %ld ms\n", total_time);
        printf("  Sent:         %d messages (%zu bytes)\n", sent, sent_bytes);
        printf("  Received:     %d messages in %d metadata entries (%zu bytes)\n",
               received, metadata_count, received_bytes);
        printf("  Message success: %.1f%%\n", sent > 0 ? 100.0 * received / sent : 0);
        printf("  Byte success:    %.1f%%\n", sent_bytes > 0 ? 100.0 * received_bytes / sent_bytes : 0);

        // Verify ring buffer status
        printf("\n--- Ring Buffer Status ---\n");
        int64_t msg_metadata_cons_seq = msg_metadata_cons.sequence();
        printf("  MSG_METADATA consumer seq:  %ld\n", msg_metadata_cons_seq);
        printf("  Consumer caught up: %s\n", (metadata_count > 0 && msg_metadata_cons_seq >= 0) ? "yes" : "no");

        printf("====================\n");
        fflush(stdout);

        // Signal children to stop and wait for them before printing latency stats
        // This prevents child stderr from interleaving with latency output
        conn_state_->shutdown_all();
        if (xdp_pid_ > 0) waitpid(xdp_pid_, nullptr, 0);
        if (transport_pid_ > 0) waitpid(transport_pid_, nullptr, 0);
        xdp_pid_ = 0;
        transport_pid_ = 0;

        // Print latency statistics
        nic_to_xdp_latency.print("NIC-to-XDP_Poll");
        xdp_to_transport_latency.print("XDP_Poll-to-Transport");
        transport_to_ssl_latency.print("Transport-to-SSL_Read");
        total_latency.print("Total (NIC-to-SSL_Read)");

        if (received == 0) {
            printf("\nFAIL: No echo responses received\n");
            return false;
        }

        // Save profiling data to /tmp
        save_profiling_data();

        printf("\nPASS: Received %d/%d echo responses\n", received, sent);
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

        // Configure BPF maps for echo server traffic
        auto* bpf = xdp_poll.get_bpf_loader();
        if (bpf) {
            bpf->set_local_ip(g_local_ip.c_str());
            bpf->add_exchange_ip(echo_ip_);
            bpf->add_exchange_port(echo_port_);
        }
        xdp_poll.run();
        xdp_poll.cleanup();
    }

    // Transport child process
    void run_transport_process() {
        pin_to_cpu(TRANSPORT_CPU_CORE);

        // Create ring adapters in child process (all use UMEMFrameDescriptor)
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

        bool ok = transport.init_with_handshake(
            umem_area_, FRAME_SIZE,
            echo_ip_, echo_port_,
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

        transport.run();
    }

    const char* interface_;
    const char* bpf_path_;
    const char* echo_ip_;
    uint16_t echo_port_;

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

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> <echo_ip> <echo_port>\n", argv[0]);
        fprintf(stderr, "NOTE: Do NOT run directly. Use: ./scripts/test_xdp.sh 10_transport_tcp.cpp\n");
        fprintf(stderr, "\nThis test:\n");
        fprintf(stderr, "  - Forks XDP Poll (core 2) and Transport<NoSSLPolicy> (core 4)\n");
        fprintf(stderr, "  - Connects to TCP echo server (no TLS)\n");
        fprintf(stderr, "  - Sends up to %d messages at %dms intervals\n", MAX_MESSAGES, SEND_INTERVAL_MS);
        fprintf(stderr, "  - Timeout: %d seconds\n", TIMEOUT_SECONDS);
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];
    const char* echo_ip = argv[3];
    uint16_t echo_port = static_cast<uint16_t>(atoi(argv[4]));

    // Store in globals
    g_echo_server_ip = echo_ip;
    g_echo_server_port = echo_port;

    // PREVENT ROOT USER FROM RUNNING
    if (geteuid() == 0) {
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "ERROR: Do NOT run as root!\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "\nRun via the wrapper script which sets capabilities properly:\n");
        fprintf(stderr, "  ./scripts/test_xdp.sh 10_transport_tcp.cpp\n");
        return 1;
    }

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  Transport TCP Test (NoSSLPolicy)            \n");
    printf("==============================================\n");
    printf("  Interface: %s\n", interface);
    printf("  Target:    %s:%u\n", echo_ip, echo_port);
    printf("  Messages:  up to %d (every %dms)\n", MAX_MESSAGES, SEND_INTERVAL_MS);
    printf("  Timeout:   %d seconds\n", TIMEOUT_SECONDS);
    printf("==============================================\n\n");

    TransportTCPTest test(interface, bpf_path, echo_ip, echo_port);

    // Setup
    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    // Fork processes
    if (!test.fork_processes()) {
        fprintf(stderr, "\nFATAL: Failed to fork processes\n");
        test.teardown();
        return 1;
    }

    // Give processes time to stabilize
    usleep(500000);  // 500ms

    // Run test
    int result = 0;
    if (!test.run_roundtrip_test()) {
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
    fprintf(stderr, "Error: Build with USE_XDP=1\n");
    fprintf(stderr, "Example: make build-test-pipeline-transport-tcp USE_XDP=1\n");
    return 1;
}

#endif  // USE_XDP
