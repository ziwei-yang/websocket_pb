// test/pipeline/00_xdp_poll_ping.cpp
// Segregated test for XDP Poll process with ICMP ping
//
// PURPOSE: Test XDP Poll's ability to send and receive ICMP packets
// with latency measurement (NIC-to-XDP_poll).
//
// What this test does:
// 1. Sends ICMP echo requests (ping) to target host
// 2. Waits for ICMP echo replies
// 3. Measures and prints NIC-to-XDP_poll latency for each response
// 4. 5 second total timeout, 100ms per-message timeout
//
// Safety: Uses dedicated test interface (enp108s0), never touches default route
//
// Prerequisites:
// 1. Capabilities set by test script (CAP_NET_ADMIN, CAP_BPF, CAP_SYS_NICE)
// 2. BPF program compiled: make bpf
// 3. Route to target host via test interface
// 4. NIC PHC clock synced: ./scripts/nic_local_clock_sync.sh start
//
// Usage: ./scripts/test_pipeline_xdp_poll.sh [interface]
//        (Do NOT run binary directly or as root - use the wrapper script)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#ifdef USE_XDP

// Set to 1 to enable verbose debug logging
#define DEBUG 0
#define DEBUG_IPC 0

// pipeline_data.hpp must be included FIRST as it includes disruptor headers
// before pipeline_config.hpp to avoid CACHE_LINE_SIZE macro conflict
#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/00_xdp_poll_process.hpp"

// Stack headers for packet building
#include "../../src/stack/mac/ethernet.hpp"
#include "../../src/stack/ip/ip_layer.hpp"
#include "../../src/stack/ip/checksum.hpp"

using namespace websocket::pipeline;
using namespace userspace_stack;

// ============================================================================
// ICMP Constants and Structures
// ============================================================================

constexpr uint8_t ICMP_ECHO_REQUEST = 8;
constexpr uint8_t ICMP_ECHO_REPLY = 0;
constexpr size_t ICMP_HEADER_LEN = 8;

struct __attribute__((packed)) ICMPHeader {
    uint8_t  type;       // ICMP type (8 = echo request, 0 = echo reply)
    uint8_t  code;       // ICMP code (0 for echo)
    uint16_t checksum;   // ICMP checksum
    uint16_t id;         // Identifier
    uint16_t seq;        // Sequence number
};

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignments for latency-critical threads
constexpr int XDP_POLL_CPU_CORE = 2;      // XDP Poll process core
constexpr int TRANSPORT_CPU_CORE = 4;     // Transport process core (consumer + test)

// Test configuration - set from command line
std::string g_ping_target_ip;  // Default: auto-detect gateway
std::string g_local_ip;  // Detected from interface

// Test parameters
// Send 2x ACK_FRAMES to test UMEM frame wrapping/recycling
constexpr int NUM_PINGS = static_cast<int>(ACK_FRAMES * 2);  // 16384 pings
constexpr uint64_t TEST_TIMEOUT_NS = 30'000'000'000ULL;  // 30 seconds for 16384 pings
constexpr uint64_t MSG_TIMEOUT_NS = 10'000'000ULL;       // 10ms per-ping timeout

// Global shutdown flag
std::atomic<bool> g_shutdown{false};

void signal_handler(int) {
    g_shutdown.store(true, std::memory_order_release);
}

// Pin current thread to specified CPU core with SCHED_FIFO priority
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
        // SCHED_FIFO may require root, just warn
        fprintf(stderr, "[CPU] WARNING: Failed to set SCHED_FIFO on core %d: %s\n", core, strerror(errno));
    }

    printf("[CPU] Pinned to core %d\n", core);
}

uint64_t get_monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

uint64_t get_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

// TSC frequency calibration (cycles per nanosecond)
double g_tsc_freq_ghz = 0.0;

void calibrate_tsc() {
    uint64_t start_tsc = rdtsc();
    uint64_t start_ns = get_monotonic_ns();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    uint64_t end_tsc = rdtsc();
    uint64_t end_ns = get_monotonic_ns();

    uint64_t elapsed_tsc = end_tsc - start_tsc;
    uint64_t elapsed_ns = end_ns - start_ns;

    g_tsc_freq_ghz = static_cast<double>(elapsed_tsc) / static_cast<double>(elapsed_ns);
    printf("[TSC] Calibrated: %.3f GHz (%.3f cycles/ns)\n", g_tsc_freq_ghz, g_tsc_freq_ghz);
}

// ICMP checksum calculation
uint16_t icmp_checksum(const void* data, size_t len) {
    const uint16_t* ptr = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

}  // namespace

// ============================================================================
// Test Metrics
// ============================================================================

struct TestMetrics {
    // TX metrics
    std::atomic<uint64_t> tx_submitted{0};
    std::atomic<uint64_t> tx_wrap_count{0};   // Number of times TX allocation wrapped

    // RX metrics
    std::atomic<uint64_t> rx_consumed{0};
    std::atomic<uint64_t> last_rx_timestamp{0};       // NIC PHC timestamp (ns)
    std::atomic<uint64_t> last_rx_poll_cycle{0};      // TSC cycle when frame was polled
    std::atomic<uint32_t> last_rx_frame_type{0};
    std::atomic<uint32_t> last_rx_len{0};
    std::atomic<uint64_t> last_rx_addr{0};

    // NIC-to-XDP-Poll latency stats
    std::atomic<int64_t> last_nic_xdp_poll_latency_ns{0};
    std::atomic<int64_t> min_nic_xdp_poll_latency_ns{INT64_MAX};
    std::atomic<int64_t> max_nic_xdp_poll_latency_ns{INT64_MIN};
    std::atomic<int64_t> sum_nic_xdp_poll_latency_ns{0};

    // Histogram buckets (in microseconds): <4, 4-5, 5-6, 6-7, 7-8, 8-10, 10-15, 15-20, 20-50, 50+
    static constexpr int NUM_BUCKETS = 10;
    std::atomic<uint64_t> histogram[NUM_BUCKETS] = {};

    void reset() {
        tx_submitted.store(0);
        tx_wrap_count.store(0);
        rx_consumed.store(0);
        last_rx_timestamp.store(0);
        last_rx_poll_cycle.store(0);
        last_rx_frame_type.store(0);
        last_rx_len.store(0);
        last_rx_addr.store(0);
        last_nic_xdp_poll_latency_ns.store(0);
        min_nic_xdp_poll_latency_ns.store(INT64_MAX);
        max_nic_xdp_poll_latency_ns.store(INT64_MIN);
        sum_nic_xdp_poll_latency_ns.store(0);
        for (int i = 0; i < NUM_BUCKETS; i++) {
            histogram[i].store(0);
        }
    }

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

    void update_nic_xdp_poll_latency(int64_t latency_ns) {
        last_nic_xdp_poll_latency_ns.store(latency_ns, std::memory_order_relaxed);
        sum_nic_xdp_poll_latency_ns.fetch_add(latency_ns, std::memory_order_relaxed);

        // Update histogram
        int bucket = get_bucket(latency_ns);
        histogram[bucket].fetch_add(1, std::memory_order_relaxed);

        // Update min (CAS loop for atomic min)
        int64_t current_min = min_nic_xdp_poll_latency_ns.load(std::memory_order_relaxed);
        while (latency_ns < current_min) {
            if (min_nic_xdp_poll_latency_ns.compare_exchange_weak(current_min, latency_ns)) break;
        }

        // Update max (CAS loop for atomic max)
        int64_t current_max = max_nic_xdp_poll_latency_ns.load(std::memory_order_relaxed);
        while (latency_ns > current_max) {
            if (max_nic_xdp_poll_latency_ns.compare_exchange_weak(current_max, latency_ns)) break;
        }
    }

    void print_latency_stats() const {
        uint64_t count = rx_consumed.load();
        if (count == 0) {
            printf("\n=== NIC-to-XDP-Poll Latency Stats ===\n");
            printf("No frames received - cannot compute latency\n");
            printf("=====================================\n\n");
            return;
        }

        int64_t min_ns = min_nic_xdp_poll_latency_ns.load();
        int64_t max_ns = max_nic_xdp_poll_latency_ns.load();
        int64_t sum_ns = sum_nic_xdp_poll_latency_ns.load();
        int64_t avg_ns = sum_ns / static_cast<int64_t>(count);

        printf("\n=== NIC-to-XDP-Poll Latency Stats ===\n");
        printf("  (Time from NIC PHC timestamp to XDP Poll retrieval)\n");
        printf("  Frames:     %lu\n", count);
        printf("  Min:        %ld ns (%.3f us)\n", min_ns, min_ns / 1000.0);
        printf("  Max:        %ld ns (%.3f us)\n", max_ns, max_ns / 1000.0);
        printf("  Avg:        %ld ns (%.3f us)\n", avg_ns, avg_ns / 1000.0);

        // Print histogram
        printf("\n  Latency Histogram:\n");
        const char* bucket_labels[NUM_BUCKETS] = {
            "  < 4us", "  4-5us", "  5-6us", "  6-7us", "  7-8us",
            " 8-10us", "10-15us", "15-20us", "20-50us", "  50+us"
        };

        // Find max bucket count for scaling
        uint64_t max_bucket = 0;
        for (int i = 0; i < NUM_BUCKETS; i++) {
            uint64_t b = histogram[i].load();
            if (b > max_bucket) max_bucket = b;
        }

        // Print histogram bars
        constexpr int BAR_WIDTH = 40;
        for (int i = 0; i < NUM_BUCKETS; i++) {
            uint64_t b = histogram[i].load();
            double pct = (count > 0) ? 100.0 * b / count : 0;
            int bar_len = (max_bucket > 0) ? static_cast<int>(BAR_WIDTH * b / max_bucket) : 0;

            printf("  %s |", bucket_labels[i]);
            for (int j = 0; j < bar_len; j++) printf("█");
            for (int j = bar_len; j < BAR_WIDTH; j++) printf(" ");
            printf("| %6lu (%5.1f%%)\n", b, pct);
        }

        printf("=====================================\n\n");
    }
};

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
        ipc_ring_dir_ = std::string("xdp_ping_test_") + timestamp;
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

        if (!create_ring("raw_inbox", RAW_INBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("raw_outbox", RAW_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("ack_outbox", ACK_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;
        if (!create_ring("pong_outbox", PONG_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;

        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;

        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = {"raw_inbox", "raw_outbox", "ack_outbox", "pong_outbox"};

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
// Stub Consumer Thread - Consumes from RAW_INBOX
// ============================================================================

void stub_consumer_thread(
    disruptor::ipc::shared_region* raw_inbox_region,
    ConnStateShm* conn_state,
    TestMetrics* metrics)
{
    pin_to_cpu(TRANSPORT_CPU_CORE);

    IPCRingConsumer<UMEMFrameDescriptor> cons(*raw_inbox_region);

    printf("[CONSUMER] Started\n");

    while (!g_shutdown.load() && conn_state->is_running(PROC_TRANSPORT)) {
        UMEMFrameDescriptor desc;

        if (cons.try_consume(desc)) {
            metrics->rx_consumed.fetch_add(1, std::memory_order_relaxed);
            metrics->last_rx_timestamp.store(desc.nic_timestamp_ns, std::memory_order_relaxed);
            metrics->last_rx_poll_cycle.store(desc.nic_frame_poll_cycle, std::memory_order_relaxed);
            metrics->last_rx_frame_type.store(desc.frame_type, std::memory_order_relaxed);
            metrics->last_rx_len.store(desc.frame_len, std::memory_order_relaxed);
            metrics->last_rx_addr.store(desc.umem_addr, std::memory_order_relaxed);

            // Compute latency: NIC PHC timestamp -> XDP Poll retrieval time
            if (desc.nic_timestamp_ns != 0 && desc.nic_frame_poll_cycle != 0) {
                uint64_t now_tsc = rdtsc();
                uint64_t now_realtime_ns = get_realtime_ns();
                uint64_t elapsed_cycles = now_tsc - desc.nic_frame_poll_cycle;
                uint64_t elapsed_ns = static_cast<uint64_t>(static_cast<double>(elapsed_cycles) / g_tsc_freq_ghz);
                uint64_t poll_time_realtime_ns = now_realtime_ns - elapsed_ns;

                int64_t latency_ns = static_cast<int64_t>(poll_time_realtime_ns) -
                                     static_cast<int64_t>(desc.nic_timestamp_ns);

                metrics->update_nic_xdp_poll_latency(latency_ns);
            }
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }

    printf("[CONSUMER] Stopped\n");
}

// ============================================================================
// XDP Poll Thread
// ============================================================================

// Enable profiling
static constexpr bool PROFILING_ENABLED = true;

using XDPPollType = XDPPollProcess<
    IPCRingProducer<UMEMFrameDescriptor>,
    IPCRingConsumer<UMEMFrameDescriptor>,
    true,                    // TrickleEnabled
    PROFILING_ENABLED>;      // Profiling

void xdp_poll_thread(
    XDPPollType* xdp_poll,
    void* umem_area,
    size_t umem_size,
    const char* bpf_path,
    disruptor::ipc::shared_region* raw_inbox_region,
    disruptor::ipc::shared_region* raw_outbox_region,
    disruptor::ipc::shared_region* ack_outbox_region,
    disruptor::ipc::shared_region* pong_outbox_region,
    ConnStateShm* conn_state,
    ProfilingShm* profiling)
{
    pin_to_cpu(XDP_POLL_CPU_CORE);

    IPCRingProducer<UMEMFrameDescriptor> raw_inbox_prod(*raw_inbox_region);
    IPCRingConsumer<UMEMFrameDescriptor> raw_outbox_cons(*raw_outbox_region);
    IPCRingConsumer<UMEMFrameDescriptor> ack_outbox_cons(*ack_outbox_region);
    IPCRingConsumer<UMEMFrameDescriptor> pong_outbox_cons(*pong_outbox_region);

    bool ok = xdp_poll->init(
        umem_area, umem_size, bpf_path,
        &raw_inbox_prod,
        &raw_outbox_cons,
        &ack_outbox_cons,
        &pong_outbox_cons,
        conn_state);

    if (!ok) {
        fprintf(stderr, "[XDP-POLL] init() failed\n");
        conn_state->shutdown_all();
        return;
    }

    // Set profiling data buffers
    if constexpr (PROFILING_ENABLED) {
        if (profiling) {
            xdp_poll->set_profiling_data(&profiling->xdp_poll);
            xdp_poll->set_nic_latency_data(&profiling->nic_latency);
        }
    }

    printf("[XDP-POLL] Initialized, configuring BPF maps...\n");

    // Configure BPF maps for ping target traffic
    auto* bpf = xdp_poll->get_bpf_loader();
    if (bpf) {
        bpf->set_local_ip(g_local_ip.c_str());
        bpf->add_exchange_ip(g_ping_target_ip.c_str());
        // No port for ICMP - BPF should match by IP only
        printf("[XDP-POLL] BPF configured: local_ip=%s, target_ip=%s (ICMP)\n",
               g_local_ip.c_str(), g_ping_target_ip.c_str());
    }

    printf("[XDP-POLL] Starting main loop...\n");
    xdp_poll->run();

    printf("[XDP-POLL] Main loop exited\n");
    xdp_poll->cleanup();
}

// ============================================================================
// ICMP Ping Test
// ============================================================================

class ICMPPingTest {
public:
    ICMPPingTest(const char* interface, const char* bpf_path, const char* target_ip)
        : interface_(interface), bpf_path_(bpf_path), target_ip_(target_ip),
          xdp_poll_(interface) {}

    bool setup() {
        printf("\n=== Setting up ICMP Ping Test ===\n");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);
        printf("Target:      %s\n\n", target_ip_);

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

        // Parse IPs
        local_ip_n_ = IPLayer::string_to_ip(local_ip_.c_str());
        target_ip_n_ = IPLayer::string_to_ip(target_ip_);

        // Create IPC rings
        if (!ipc_manager_.create_all_rings()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        // Allocate UMEM
        umem_size_ = UMEM_TOTAL_SIZE;
        umem_area_ = mmap(nullptr, umem_size_,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                          -1, 0);
        if (umem_area_ == MAP_FAILED) {
            printf("WARN: Huge pages not available, using regular pages\n");
            umem_area_ = mmap(nullptr, umem_size_,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS,
                              -1, 0);
            if (umem_area_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate UMEM\n");
                return false;
            }
        }
        printf("UMEM: %p (%zu bytes)\n", umem_area_, umem_size_);

        // Open shared regions
        try {
            raw_inbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_inbox"));
            raw_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_outbox"));
            ack_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("ack_outbox"));
            pong_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pong_outbox"));
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
            return false;
        }

        // Create producers for injecting test frames
        raw_outbox_prod_ = new IPCRingProducer<UMEMFrameDescriptor>(*raw_outbox_region_);
        ack_outbox_prod_ = new IPCRingProducer<UMEMFrameDescriptor>(*ack_outbox_region_);
        pong_outbox_prod_ = new IPCRingProducer<UMEMFrameDescriptor>(*pong_outbox_region_);

        // Initialize shared state
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

        // Allocate ProfilingShm (shared between threads)
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

        printf("=== Setup Complete ===\n\n");
        return true;
    }

    void teardown() {
        printf("\n=== Teardown ===\n");

        if (conn_state_) conn_state_->shutdown_all();
        g_shutdown.store(true);

        if (xdp_thread_.joinable()) xdp_thread_.join();
        if (consumer_thread_.joinable()) consumer_thread_.join();

        delete raw_outbox_prod_;
        delete ack_outbox_prod_;
        delete pong_outbox_prod_;
        raw_outbox_prod_ = nullptr;
        ack_outbox_prod_ = nullptr;
        pong_outbox_prod_ = nullptr;

        delete raw_inbox_region_;
        delete raw_outbox_region_;
        delete ack_outbox_region_;
        delete pong_outbox_region_;
        raw_inbox_region_ = nullptr;
        raw_outbox_region_ = nullptr;
        ack_outbox_region_ = nullptr;
        pong_outbox_region_ = nullptr;

        if (conn_state_ && conn_state_ != MAP_FAILED) {
            munmap(conn_state_, sizeof(ConnStateShm));
            conn_state_ = nullptr;
        }
        if (profiling_ && profiling_ != MAP_FAILED) {
            munmap(profiling_, sizeof(ProfilingShm));
            profiling_ = nullptr;
        }
        if (umem_area_ && umem_area_ != MAP_FAILED) {
            munmap(umem_area_, umem_size_);
            umem_area_ = nullptr;
        }

        printf("=== Teardown Complete ===\n");
    }

    bool start_threads() {
        xdp_thread_ = std::thread(
            xdp_poll_thread,
            &xdp_poll_,
            umem_area_,
            umem_size_,
            bpf_path_,
            raw_inbox_region_,
            raw_outbox_region_,
            ack_outbox_region_,
            pong_outbox_region_,
            conn_state_,
            profiling_);

        printf("[MAIN] Waiting for XDP Poll to initialize...\n");
        uint64_t start = get_monotonic_ns();
        while (!conn_state_->is_handshake_xdp_ready()) {
            if (get_monotonic_ns() - start > 10'000'000'000ULL) {
                fprintf(stderr, "FAIL: Timeout waiting for XDP Poll ready\n");
                return false;
            }
            if (!conn_state_->is_running(PROC_XDP_POLL)) {
                fprintf(stderr, "FAIL: XDP Poll exited during init\n");
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        printf("[MAIN] XDP Poll ready\n");

        consumer_thread_ = std::thread(
            stub_consumer_thread,
            raw_inbox_region_,
            conn_state_,
            &metrics_);

        return true;
    }

    // ========================================================================
    // Main Test: ICMP ping with request-response pattern
    // ========================================================================

    bool run_ping_test() {
        printf("\n--- ICMP Ping Test (%d pings, 100ms timeout per ping, %ds total) ---\n",
               NUM_PINGS, static_cast<int>(TEST_TIMEOUT_NS / 1'000'000'000ULL));
        printf("  Target: %s\n\n", target_ip_);

        metrics_.reset();

        int sent = 0;
        int received = 0;
        int timeouts = 0;
        uint64_t test_start = get_monotonic_ns();

        // Request-response loop: send ping, wait for reply, repeat
        for (int i = 0; i < NUM_PINGS; i++) {
            uint64_t now = get_monotonic_ns();

            // Check total test timeout
            if (now - test_start > TEST_TIMEOUT_NS) {
                printf("[TEST] Total timeout (%ds) reached after %d pings\n",
                       static_cast<int>(TEST_TIMEOUT_NS / 1'000'000'000ULL), sent);
                break;
            }

            // Send ICMP echo request
            uint64_t pre_rx_count = metrics_.rx_consumed.load();
            inject_ping(static_cast<uint16_t>(i + 1));
            sent++;

            // Wait for echo reply (up to 100ms)
            uint64_t msg_start = get_monotonic_ns();
            bool got_reply = false;

            while (get_monotonic_ns() - msg_start < MSG_TIMEOUT_NS) {
                uint64_t current_rx_count = metrics_.rx_consumed.load();
                if (current_rx_count > pre_rx_count) {
                    uint64_t rx_addr = metrics_.last_rx_addr.load();
                    uint32_t rx_len = metrics_.last_rx_len.load();

                    if (rx_addr != 0 && rx_len > 0) {
                        const uint8_t* rx_frame = static_cast<const uint8_t*>(umem_area_) + rx_addr;

                        // Check if this is an ICMP echo reply
                        if (parse_icmp_reply(rx_frame, rx_len, static_cast<uint16_t>(i + 1))) {
                            received++;
                            got_reply = true;
                            break;
                        }
                    }
                    pre_rx_count = current_rx_count;
                }
                std::this_thread::yield();
            }

            if (!got_reply) {
                timeouts++;
            }

            // Progress indicator every 500 pings
            if (sent % 500 == 0) {
                printf("[PROGRESS] Sent: %d, Received: %d, Timeouts: %d\n", sent, received, timeouts);
            }
        }

        // Wait 10ms for consumer to catch up with producer
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // Check ring buffer status via shared_region API
        int64_t prod_seq = raw_inbox_region_->producer_published()->load(std::memory_order_acquire);
        int64_t cons_seq = raw_inbox_region_->consumer_sequence(0)->load(std::memory_order_acquire);

        uint64_t total_time_ns = get_monotonic_ns() - test_start;
        double total_time_s = total_time_ns / 1e9;
        double msg_rate = (sent > 0) ? sent / total_time_s : 0;
        uint64_t total_rx_frames = metrics_.rx_consumed.load();
        double success_rate = (sent > 0) ? 100.0 * received / sent : 0;
        double timeout_rate = (sent > 0) ? 100.0 * timeouts / sent : 0;

        printf("\n");
        printf("=== Ring Buffer Status ===\n");
        printf("  RAW_INBOX producer: %ld\n", prod_seq);
        printf("  RAW_INBOX consumer: %ld\n", cons_seq);
        printf("  Consumer lag:       %ld frames\n", prod_seq - cons_seq);
        if (prod_seq == cons_seq) {
            printf("  Status: Consumer caught up (OK)\n");
        } else {
            printf("  Status: Consumer behind by %ld frames (WARN)\n", prod_seq - cons_seq);
        }
        printf("==========================\n");

        printf("\n");
        printf("=== Test Results ===\n");
        printf("  Total time:       %.2f s\n", total_time_s);
        printf("  Sent:             %d pings\n", sent);
        printf("  Received:         %d (%.1f%%)\n", received, success_rate);
        printf("  Timeouts:         %d (%.1f%%)\n", timeouts, timeout_rate);
        printf("  RX frames:        %lu (total ICMP frames)\n", total_rx_frames);
        printf("  Ping rate:        %.0f ping/s\n", msg_rate);
        printf("  TX UMEM wraps:    %lu (reused %lu frames)\n",
               metrics_.tx_wrap_count.load(),
               metrics_.tx_wrap_count.load() * ACK_FRAMES);
        printf("====================\n");

        // Print latency stats
        metrics_.print_latency_stats();

        if (received == 0) {
            printf("FAIL: No ping replies received\n");
            return false;
        }

        printf("PASS: Received %d/%d ping replies (%.1f%% success)\n",
               received, sent, success_rate);
        return true;
    }

    // ========================================================================
    // ACK/PONG Outbox Test - Verify XDP Poll consumes from all TX queues
    // ========================================================================

    bool run_outbox_test() {
        constexpr int OUTBOX_PINGS = 100;
        printf("\n--- ACK/PONG Outbox Test (50 pings each via ACK_OUTBOX and PONG_OUTBOX) ---\n");

        uint64_t pre_rx_count = metrics_.rx_consumed.load();
        int ack_sent = 0;
        int pong_sent = 0;
        int received = 0;

        // Send 50 pings via ACK_OUTBOX
        printf("[OUTBOX] Sending %d pings via ACK_OUTBOX...\n", OUTBOX_PINGS / 2);
        for (int i = 0; i < OUTBOX_PINGS / 2; i++) {
            inject_ping_via_outbox(ack_outbox_prod_, ACK_POOL_START, ACK_FRAMES,
                                   static_cast<uint16_t>(20000 + i), ack_inject_count_);
            ack_sent++;
        }

        // Send 50 pings via PONG_OUTBOX
        printf("[OUTBOX] Sending %d pings via PONG_OUTBOX...\n", OUTBOX_PINGS / 2);
        for (int i = 0; i < OUTBOX_PINGS / 2; i++) {
            inject_ping_via_outbox(pong_outbox_prod_, PONG_POOL_START, PONG_FRAMES,
                                   static_cast<uint16_t>(30000 + i), pong_inject_count_);
            pong_sent++;
        }

        // Wait for replies (up to 2 seconds total)
        printf("[OUTBOX] Waiting for replies...\n");
        uint64_t start = get_monotonic_ns();
        constexpr uint64_t OUTBOX_TIMEOUT_NS = 2'000'000'000ULL;  // 2 seconds

        while (get_monotonic_ns() - start < OUTBOX_TIMEOUT_NS) {
            uint64_t current_rx = metrics_.rx_consumed.load();
            received = static_cast<int>(current_rx - pre_rx_count);
            if (received >= OUTBOX_PINGS) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        uint64_t final_rx = metrics_.rx_consumed.load();
        received = static_cast<int>(final_rx - pre_rx_count);

        printf("\n=== ACK/PONG Outbox Results ===\n");
        printf("  ACK_OUTBOX sent:   %d pings\n", ack_sent);
        printf("  PONG_OUTBOX sent:  %d pings\n", pong_sent);
        printf("  Total sent:        %d pings\n", ack_sent + pong_sent);
        printf("  Received:          %d replies\n", received);
        printf("===============================\n");

        if (received < OUTBOX_PINGS * 90 / 100) {  // Allow 10% loss
            printf("FAIL: ACK/PONG outbox test - received %d/%d (< 90%%)\n",
                   received, OUTBOX_PINGS);
            return false;
        }

        printf("PASS: ACK/PONG outbox test - received %d/%d replies\n",
               received, OUTBOX_PINGS);
        return true;
    }

    // ========================================================================
    // Packet Helpers
    // ========================================================================

    void inject_ping(uint16_t seq) {
        uint64_t tx_frame_idx = ACK_POOL_START + (inject_count_ % ACK_FRAMES);
        uint64_t tx_addr = tx_frame_idx * FRAME_SIZE;
        uint8_t* frame_ptr = static_cast<uint8_t*>(umem_area_) + tx_addr;

        size_t frame_len = build_icmp_echo_request(frame_ptr, FRAME_SIZE, seq);
        if (frame_len == 0) {
            fprintf(stderr, "WARN: build_icmp_echo_request failed\n");
            return;
        }

        int64_t slot = raw_outbox_prod_->try_claim();
        if (slot < 0) {
            fprintf(stderr, "WARN: RAW_OUTBOX full\n");
            return;
        }

        auto& desc = (*raw_outbox_prod_)[slot];
        desc.umem_addr = tx_addr;
        desc.frame_len = static_cast<uint16_t>(frame_len);
        desc.frame_type = FRAME_TYPE_ACK;
        desc.consumed = 0;
        desc.nic_timestamp_ns = 0;
        desc.nic_frame_poll_cycle = 0;

        raw_outbox_prod_->publish(slot);

        // Detect UMEM wrap (when modulo resets to lower value)
        uint64_t prev_inject = inject_count_;
        inject_count_++;
        if ((prev_inject % ACK_FRAMES) > (inject_count_ % ACK_FRAMES)) {
            metrics_.tx_wrap_count.fetch_add(1, std::memory_order_relaxed);
        }
        metrics_.tx_submitted.fetch_add(1, std::memory_order_relaxed);
    }

    // Inject ping via a specific outbox (ACK_OUTBOX or PONG_OUTBOX)
    void inject_ping_via_outbox(IPCRingProducer<UMEMFrameDescriptor>* prod,
                                 size_t pool_start, size_t pool_size,
                                 uint16_t seq, uint64_t& counter) {
        uint64_t tx_frame_idx = pool_start + (counter % pool_size);
        uint64_t tx_addr = tx_frame_idx * FRAME_SIZE;
        uint8_t* frame_ptr = static_cast<uint8_t*>(umem_area_) + tx_addr;

        size_t frame_len = build_icmp_echo_request(frame_ptr, FRAME_SIZE, seq);
        if (frame_len == 0) {
            fprintf(stderr, "WARN: build_icmp_echo_request failed\n");
            return;
        }

        int64_t slot = prod->try_claim();
        if (slot < 0) {
            fprintf(stderr, "WARN: Outbox full\n");
            return;
        }

        auto& desc = (*prod)[slot];
        desc.umem_addr = tx_addr;
        desc.frame_len = static_cast<uint16_t>(frame_len);
        desc.frame_type = (pool_start == ACK_POOL_START) ? FRAME_TYPE_ACK : FRAME_TYPE_PONG;
        desc.consumed = 0;
        desc.nic_timestamp_ns = 0;
        desc.nic_frame_poll_cycle = 0;

        prod->publish(slot);
        counter++;
    }

    size_t build_icmp_echo_request(uint8_t* buffer, size_t capacity, uint16_t seq) {
        // Layout: Ethernet (14) + IP (20) + ICMP (8) + payload (56) = 98 bytes
        constexpr size_t PAYLOAD_LEN = 56;  // Standard ping payload
        constexpr size_t TOTAL_LEN = ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN + PAYLOAD_LEN;

        if (capacity < TOTAL_LEN) return 0;

        // Build Ethernet header
        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(buffer);
        memcpy(eth->dst_mac, gateway_mac_, 6);
        memcpy(eth->src_mac, local_mac_, 6);
        eth->ethertype = htons(ETH_TYPE_IP);

        // Build IP header
        IPv4Header* ip = reinterpret_cast<IPv4Header*>(buffer + ETH_HEADER_LEN);
        ip->version_ihl = 0x45;
        ip->tos = 0;
        ip->tot_len = htons(static_cast<uint16_t>(IP_HEADER_LEN + ICMP_HEADER_LEN + PAYLOAD_LEN));
        ip->id = htons(ip_id_++);
        ip->frag_off = htons(0x4000);  // Don't fragment
        ip->ttl = 64;
        ip->protocol = IP_PROTO_ICMP;
        ip->check = 0;
        ip->saddr = htonl(local_ip_n_);
        ip->daddr = htonl(target_ip_n_);
        ip->check = htons(ip_checksum(ip));

        // Build ICMP header
        ICMPHeader* icmp = reinterpret_cast<ICMPHeader*>(buffer + ETH_HEADER_LEN + IP_HEADER_LEN);
        icmp->type = ICMP_ECHO_REQUEST;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->id = htons(icmp_id_);
        icmp->seq = htons(seq);

        // Fill payload with pattern
        uint8_t* payload = buffer + ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN;
        for (size_t i = 0; i < PAYLOAD_LEN; i++) {
            payload[i] = static_cast<uint8_t>(i);
        }

        // Calculate ICMP checksum (covers header + payload)
        icmp->checksum = icmp_checksum(icmp, ICMP_HEADER_LEN + PAYLOAD_LEN);

        return TOTAL_LEN;
    }

    bool parse_icmp_reply(const uint8_t* frame, size_t len, uint16_t expected_seq) {
        // Minimum: Ethernet (14) + IP (20) + ICMP (8)
        if (len < ETH_HEADER_LEN + IP_HEADER_LEN + ICMP_HEADER_LEN) {
            return false;
        }

        // Check Ethernet type
        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(frame);
        if (ntohs(eth->ethertype) != ETH_TYPE_IP) {
            return false;
        }

        // Check IP protocol
        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(frame + ETH_HEADER_LEN);
        if (ip->protocol != IP_PROTO_ICMP) {
            return false;
        }

        // Check source IP is our target
        if (ntohl(ip->saddr) != target_ip_n_) {
            return false;
        }

        // Check ICMP type and ID
        const ICMPHeader* icmp = reinterpret_cast<const ICMPHeader*>(
            frame + ETH_HEADER_LEN + IP_HEADER_LEN);

        if (icmp->type != ICMP_ECHO_REPLY) {
            return false;
        }

        if (ntohs(icmp->id) != icmp_id_) {
            return false;
        }

        // Optionally check sequence (for strict matching)
        // uint16_t reply_seq = ntohs(icmp->seq);
        // if (reply_seq != expected_seq) return false;
        (void)expected_seq;

        return true;
    }

    void save_profiling_data() {
        if constexpr (!PROFILING_ENABLED) return;
        if (!profiling_) return;

        pid_t pid = getpid();

        auto save_buffer = [&](CycleSampleBuffer& buf, const char* name) {
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

        printf("[PROFILING] To analyze: ./build/xdp_poll_profiling %d\n", pid);
    }

    void print_bpf_stats() {
        auto* bpf = xdp_poll_.get_bpf_loader();
        if (!bpf) {
            printf("      No BPF loader available\n");
            return;
        }

        auto stats = bpf->get_stats();
        printf("\n=== BPF Statistics ===\n");
        printf("  Total packets:    %lu\n", stats.total_packets);
        printf("  Exchange packets: %lu (redirected to AF_XDP)\n", stats.exchange_packets);
        printf("  Kernel packets:   %lu\n", stats.kernel_packets);
        printf("  IPv4 packets:     %lu\n", stats.ipv4_packets);
        printf("  TCP packets:      %lu\n", stats.tcp_packets);
        printf("======================\n");
    }

private:
    const char* interface_;
    const char* bpf_path_;
    const char* target_ip_;

    IPCRingManager ipc_manager_;

    void* umem_area_ = nullptr;
    size_t umem_size_ = 0;
    uint8_t local_mac_[6] = {};
    uint8_t gateway_mac_[6] = {};
    std::string local_ip_;
    std::string gateway_ip_;
    uint32_t local_ip_n_ = 0;
    uint32_t target_ip_n_ = 0;

    uint16_t ip_id_ = 0;
    uint16_t icmp_id_ = 0;

    disruptor::ipc::shared_region* raw_inbox_region_ = nullptr;
    disruptor::ipc::shared_region* raw_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* ack_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* pong_outbox_region_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;
    ProfilingShm* profiling_ = nullptr;

    IPCRingProducer<UMEMFrameDescriptor>* raw_outbox_prod_ = nullptr;
    IPCRingProducer<UMEMFrameDescriptor>* ack_outbox_prod_ = nullptr;
    IPCRingProducer<UMEMFrameDescriptor>* pong_outbox_prod_ = nullptr;

    XDPPollType xdp_poll_;
    TestMetrics metrics_;

    std::thread xdp_thread_;
    std::thread consumer_thread_;

    uint64_t inject_count_ = 0;
    uint64_t ack_inject_count_ = 0;
    uint64_t pong_inject_count_ = 0;
};

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [target_ip]\n", argv[0]);
        fprintf(stderr, "NOTE: Do NOT run directly. Use a wrapper script instead.\n");
        fprintf(stderr, "\nIf target_ip is omitted, pings the default gateway.\n");
        fprintf(stderr, "\nThis test:\n");
        fprintf(stderr, "  - Sends ICMP echo requests (ping) to target\n");
        fprintf(stderr, "  - Waits for ICMP echo replies\n");
        fprintf(stderr, "  - 10ms timeout per ping, 5 second total timeout\n");
        fprintf(stderr, "  - Measures NIC-to-XDP_poll latency for responses\n");
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];
    std::string target_ip_str;

    // If target_ip provided, use it; otherwise fetch gateway at runtime
    if (argc >= 4) {
        target_ip_str = argv[3];
    } else {
        // Fetch gateway IP for this interface
        if (!get_default_gateway(interface, target_ip_str)) {
            fprintf(stderr, "FATAL: Cannot detect gateway for interface %s\n", interface);
            return 1;
        }
        printf("[AUTO] Using gateway as ping target: %s\n", target_ip_str.c_str());
    }

    const char* target_ip = target_ip_str.c_str();

    // Store in globals for BPF configuration
    g_ping_target_ip = target_ip;

    // PREVENT ROOT USER FROM RUNNING
    if (geteuid() == 0) {
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "ERROR: Do NOT run as root!\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "This program requires specific capabilities, not root access.\n");
        fprintf(stderr, "Run via the wrapper script which sets capabilities properly:\n");
        fprintf(stderr, "\n");
        fprintf(stderr, "  ./scripts/test_pipeline_xdp_poll.sh %s\n", interface);
        fprintf(stderr, "\n");
        fprintf(stderr, "The script uses 'setcap' to grant:\n");
        fprintf(stderr, "  - CAP_NET_ADMIN: AF_XDP socket creation\n");
        fprintf(stderr, "  - CAP_NET_RAW:   Raw socket access\n");
        fprintf(stderr, "  - CAP_BPF:       BPF program loading\n");
        fprintf(stderr, "  - CAP_PERFMON:   BPF tracing\n");
        fprintf(stderr, "  - CAP_IPC_LOCK:  Memory locking for UMEM\n");
        fprintf(stderr, "  - CAP_SYS_NICE:  SCHED_FIFO for real-time priority\n");
        fprintf(stderr, "========================================\n");
        return 1;
    }

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Seed random for ID generation
    srand(static_cast<unsigned>(time(nullptr)));

    printf("==============================================\n");
    printf("  XDP Poll ICMP Ping Test                     \n");
    printf("==============================================\n");
    printf("  Target: %s\n", target_ip);
    printf("  Pings: up to %d (request-response)\n", NUM_PINGS);
    printf("  Per-ping timeout: %dms, Total: %ds\n",
           static_cast<int>(MSG_TIMEOUT_NS / 1'000'000ULL),
           static_cast<int>(TEST_TIMEOUT_NS / 1'000'000'000ULL));
    printf("==============================================\n\n");

    ICMPPingTest test(interface, bpf_path, target_ip);

    // Setup
    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    // Start threads
    if (!test.start_threads()) {
        fprintf(stderr, "\nFATAL: Failed to start threads\n");
        test.teardown();
        return 1;
    }

    // Give threads time to stabilize
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Run ACK/PONG outbox test first (verify XDP Poll consumes from all TX queues)
    int result = 0;
    if (!test.run_outbox_test()) {
        result = 1;
    }

    // Run main ping test
    if (result == 0 && !test.run_ping_test()) {
        result = 1;
    }

    // Print BPF stats
    test.print_bpf_stats();

    // Save profiling data
    test.save_profiling_data();

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
    fprintf(stderr, "Example: make USE_XDP=1 XDP_INTERFACE=enp108s0\n");
    return 1;
}

#endif  // USE_XDP
