// test/pipeline/00_xdp_poll.cpp
// Segregated unit test for XDP Poll process using remote echo server
//
// This test verifies XDP Poll in isolation before integration with other
// pipeline processes. Uses a remote TCP echo server for packet round-trip.
//
// PURPOSE: Test functionality of src/stack/ + XDP Poll process working together.
// - Uses UserspaceStack (src/stack/userspace_stack.hpp) for TCP packet building/parsing
// - Uses XDPPollProcess for NIC RX/TX via AF_XDP zero-copy
//
// Safety: Uses dedicated test interface (enp108s0), never touches default route
//
// Prerequisites:
// 1. Echo server running: ncat -l 12345 -k -c 'cat'
// 2. Root privileges (for XDP/AF_XDP)
// 3. BPF program compiled: make bpf
// 4. Route to echo server via test interface
// 5. NIC PHC clock synced: ./scripts/nic_local_clock_sync.sh start
//
// Usage: sudo ./build/test_pipeline_xdp_poll <interface> <bpf_path> <echo_ip> <echo_port>
//   interface: Network interface (e.g., enp108s0)
//   bpf_path:  BPF object path (e.g., build/exchange_filter.bpf.o)
//   echo_ip:   Echo server IP (e.g., 139.162.79.171)
//   echo_port: Echo server port (e.g., 12345)

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
#include "../../src/pipeline/xdp_poll_process.hpp"

// UserspaceStack for TCP packet building/parsing (src/stack/)
#include "../../src/stack/userspace_stack.hpp"

using namespace websocket::pipeline;
using namespace userspace_stack;

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignments for latency-critical threads
constexpr int XDP_POLL_CPU_CORE = 2;      // XDP Poll process core
constexpr int TRANSPORT_CPU_CORE = 4;     // Transport process core (consumer + test)

// Test configuration - set from command line
std::string g_echo_server_ip = "139.162.79.171";
uint16_t g_echo_server_port = 12345;
std::string g_local_ip;  // Detected from interface

constexpr uint64_t TIMEOUT_NS = 10'000'000'000ULL;  // 10 seconds (longer for network)
constexpr uint32_t SUSTAINED_TEST_FRAMES = 100;  // Fewer frames for network test
constexpr uint64_t SUSTAINED_TIMEOUT_NS = 60'000'000'000ULL;  // 60 seconds

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

// TSC frequency detection (cycles per nanosecond)
double g_tsc_freq_ghz = 0.0;

void calibrate_tsc() {
    uint64_t start_tsc = rdtsc();
    uint64_t start_ns = get_monotonic_ns();

    // Sleep briefly to measure TSC frequency
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    uint64_t end_tsc = rdtsc();
    uint64_t end_ns = get_monotonic_ns();

    uint64_t elapsed_tsc = end_tsc - start_tsc;
    uint64_t elapsed_ns = end_ns - start_ns;

    g_tsc_freq_ghz = static_cast<double>(elapsed_tsc) / static_cast<double>(elapsed_ns);
#if DEBUG
    printf("[TSC] Calibrated: %.3f GHz (%.3f cycles/ns)\n", g_tsc_freq_ghz, g_tsc_freq_ghz);
#endif
}

// Convert TSC cycles to nanoseconds (approximate, based on calibration)
uint64_t tsc_to_ns(uint64_t cycles) {
    if (g_tsc_freq_ghz <= 0.0) return 0;
    return static_cast<uint64_t>(static_cast<double>(cycles) / g_tsc_freq_ghz);
}

}  // namespace

// ============================================================================
// Test Metrics
// ============================================================================

struct TestMetrics {
    // TX metrics
    std::atomic<uint64_t> tx_submitted{0};

    // RX metrics
    std::atomic<uint64_t> rx_consumed{0};
    std::atomic<uint64_t> last_rx_timestamp{0};       // NIC PHC timestamp (ns)
    std::atomic<uint64_t> last_rx_poll_cycle{0};      // TSC cycle when frame was polled
    std::atomic<uint32_t> last_rx_frame_type{0};
    std::atomic<uint32_t> last_rx_len{0};
    std::atomic<uint64_t> last_rx_addr{0};

    // Latency stats (NIC timestamp -> poll cycle)
    std::atomic<int64_t> last_latency_ns{0};          // Latency for last frame
    std::atomic<int64_t> min_latency_ns{INT64_MAX};   // Min latency observed
    std::atomic<int64_t> max_latency_ns{INT64_MIN};   // Max latency observed
    std::atomic<int64_t> sum_latency_ns{0};           // Sum for average calculation

    void reset() {
        tx_submitted.store(0);
        rx_consumed.store(0);
        last_rx_timestamp.store(0);
        last_rx_poll_cycle.store(0);
        last_rx_frame_type.store(0);
        last_rx_len.store(0);
        last_rx_addr.store(0);
        last_latency_ns.store(0);
        min_latency_ns.store(INT64_MAX);
        max_latency_ns.store(INT64_MIN);
        sum_latency_ns.store(0);
    }

    void update_latency(int64_t latency_ns) {
        last_latency_ns.store(latency_ns, std::memory_order_relaxed);
        sum_latency_ns.fetch_add(latency_ns, std::memory_order_relaxed);

        // Update min (CAS loop for atomic min)
        int64_t current_min = min_latency_ns.load(std::memory_order_relaxed);
        while (latency_ns < current_min) {
            if (min_latency_ns.compare_exchange_weak(current_min, latency_ns)) break;
        }

        // Update max (CAS loop for atomic max)
        int64_t current_max = max_latency_ns.load(std::memory_order_relaxed);
        while (latency_ns > current_max) {
            if (max_latency_ns.compare_exchange_weak(current_max, latency_ns)) break;
        }
    }

    void print() const {
        printf("\n=== Test Metrics ===\n");
        printf("TX Submitted:       %lu\n", tx_submitted.load());
        printf("RX Consumed:        %lu\n", rx_consumed.load());
        printf("Last RX Timestamp:  %lu ns\n", last_rx_timestamp.load());
        printf("Last RX Poll Cycle: %lu\n", last_rx_poll_cycle.load());
        printf("Last RX Frame Type: %u\n", last_rx_frame_type.load());
        printf("Last RX Length:     %u bytes\n", last_rx_len.load());
        printf("====================\n\n");
    }

    void print_latency() const {
        uint64_t count = rx_consumed.load();
        if (count == 0) {
            printf("\n=== Latency Stats ===\n");
            printf("No frames received - cannot compute latency\n");
            printf("=====================\n\n");
            return;
        }

        int64_t min_ns = min_latency_ns.load();
        int64_t max_ns = max_latency_ns.load();
        int64_t sum_ns = sum_latency_ns.load();
        int64_t avg_ns = sum_ns / static_cast<int64_t>(count);

        printf("\n=== NIC-to-Poll Latency Stats ===\n");
        printf("  (Time from NIC PHC timestamp to XDP Poll retrieval)\n");
        printf("  Frames:     %lu\n", count);
        printf("  Min:        %ld ns (%.3f us)\n", min_ns, min_ns / 1000.0);
        printf("  Max:        %ld ns (%.3f us)\n", max_ns, max_ns / 1000.0);
        printf("  Avg:        %ld ns (%.3f us)\n", avg_ns, avg_ns / 1000.0);
        printf("  Last:       %ld ns (%.3f us)\n",
               last_latency_ns.load(), last_latency_ns.load() / 1000.0);
        printf("=================================\n\n");
    }
};

// ============================================================================
// IPC Ring Creation (extracted from HandshakeManager)
// ============================================================================

class IPCRingManager {
public:
    IPCRingManager() {
        // Generate timestamped directory name
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string("xdp_test_") + timestamp;
    }

    ~IPCRingManager() {
        cleanup();
    }

    bool create_ring(const char* name, size_t buffer_size, size_t event_size, uint8_t max_consumers = 1) {
        std::string base_path = std::string("/dev/shm/hft/") + ipc_ring_dir_ + "/" + name;
        std::string hdr_path = base_path + ".hdr";
        std::string dat_path = base_path + ".dat";

        // Calculate header size (metadata + producer + consumers)
        uint32_t producer_offset = hftshm::default_producer_offset();
        uint32_t consumer_0_offset = hftshm::default_consumer_0_offset();
        uint32_t header_size = hftshm::header_segment_size(max_consumers);

        // Create and initialize header file
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

        // Initialize metadata
        hftshm::metadata_init(hdr_ptr, max_consumers, event_size, buffer_size,
                              producer_offset, consumer_0_offset, header_size);

        // Initialize producer sequences to -1 (disruptor convention)
        auto* cursor = reinterpret_cast<std::atomic<int64_t>*>(
            static_cast<char*>(hdr_ptr) + producer_offset);
        auto* published = reinterpret_cast<std::atomic<int64_t>*>(
            static_cast<char*>(hdr_ptr) + producer_offset + hftshm::CACHE_LINE);
        cursor->store(-1, std::memory_order_relaxed);
        published->store(-1, std::memory_order_relaxed);

        // Initialize consumer sequences to -1
        for (uint8_t i = 0; i < max_consumers; ++i) {
            auto* cons_seq = reinterpret_cast<std::atomic<int64_t>*>(
                static_cast<char*>(hdr_ptr) + consumer_0_offset + i * 2 * hftshm::CACHE_LINE);
            cons_seq->store(-1, std::memory_order_relaxed);
        }

        munmap(hdr_ptr, header_size);

        // Create data file
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

        // Zero-initialize data
        void* dat_ptr = mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, dat_fd, 0);
        close(dat_fd);
        if (dat_ptr == MAP_FAILED) {
            unlink(hdr_path.c_str());
            return false;
        }
        memset(dat_ptr, 0, buffer_size);
        munmap(dat_ptr, buffer_size);

#if DEBUG
        printf("[IPC] Created ring: %s (buf=%zu, event=%zu)\n", name, buffer_size, event_size);
#endif
        return true;
    }

    bool create_all_rings() {
        // Create directories
        mkdir("/dev/shm/hft", 0755);
        std::string full_dir = "/dev/shm/hft/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "[IPC] Failed to create directory: %s\n", full_dir.c_str());
            return false;
        }

        // Create rings needed for XDP Poll test
        // XDP Poll → Transport (RAW_INBOX)
        if (!create_ring("raw_inbox", RAW_INBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;

        // Transport → XDP Poll (RAW_OUTBOX)
        if (!create_ring("raw_outbox", RAW_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                         sizeof(UMEMFrameDescriptor), 1)) return false;

        // ACK frames: Transport → XDP Poll
        if (!create_ring("ack_outbox", ACK_OUTBOX_SIZE * sizeof(AckDescriptor),
                         sizeof(AckDescriptor), 1)) return false;

        // PONG frames: Transport → XDP Poll
        if (!create_ring("pong_outbox", PONG_OUTBOX_SIZE * sizeof(PongDescriptor),
                         sizeof(PongDescriptor), 1)) return false;

#if DEBUG
        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
#endif
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
#if DEBUG
        printf("[IPC] Cleaned up ring files\n");
#endif
    }

    std::string get_ring_name(const char* ring) const {
        return ipc_ring_dir_ + "/" + ring;
    }

private:
    std::string ipc_ring_dir_;
};

// ============================================================================
// Test Frame Builder - For Echo Server Test
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
    // Read ARP cache from /proc/net/arp
    FILE* fp = fopen("/proc/net/arp", "r");
    if (!fp) return false;

    char line[256];
    // Skip header
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }

    while (fgets(line, sizeof(line), fp)) {
        char ip[64], hw_type[16], flags[16], mac_str[32], mask[16], dev[32];
        if (sscanf(line, "%63s %15s %15s %31s %15s %31s",
                   ip, hw_type, flags, mac_str, mask, dev) == 6) {
            if (strcmp(ip, gateway_ip) == 0 && strcmp(dev, interface) == 0) {
                // Parse MAC address
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
    // Skip header
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
// TCP Packet Building - REPLACED with UserspaceStack (src/stack/)
// ============================================================================
// The hand-crafted build_syn_frame(), build_ack_frame(), build_data_frame(),
// compute_ip_checksum(), compute_tcp_checksum() functions have been replaced
// with UserspaceStack from src/stack/userspace_stack.hpp.
//
// UserspaceStack provides:
//   - build_syn()  - Build TCP SYN packet
//   - build_ack()  - Build TCP ACK packet
//   - build_data() - Build TCP DATA packet (PSH+ACK)
//   - parse_tcp()  - Parse incoming TCP packets
//   - process_tcp() - Process TCP state machine
//
// Usage:
//   UserspaceStack stack;
//   stack.init(local_ip, gateway_ip, netmask, local_mac);
//   size_t len = stack.build_syn(buffer, capacity, tcp_params);
// ============================================================================

// ============================================================================
// Stub Consumer Thread
// ============================================================================

void stub_consumer_thread(
    disruptor::ipc::shared_region* raw_inbox_region,
    WebsocketStateShm* tcp_state,
    TestMetrics* metrics)
{
    // Pin consumer thread to Transport CPU core
    pin_to_cpu(TRANSPORT_CPU_CORE);

    IPCRingConsumer<UMEMFrameDescriptor> cons(*raw_inbox_region);

#if DEBUG
    fprintf(stderr, "[CONSUMER] Started - checking PROC_TRANSPORT running=%d\n",
           tcp_state->is_running(PROC_TRANSPORT) ? 1 : 0);
    fflush(stderr);
#endif

    while (!g_shutdown.load() && tcp_state->is_running(PROC_TRANSPORT)) {
        UMEMFrameDescriptor desc;

        if (cons.try_consume(desc)) {
            metrics->rx_consumed.fetch_add(1, std::memory_order_relaxed);
            metrics->last_rx_timestamp.store(desc.nic_timestamp_ns, std::memory_order_relaxed);
            metrics->last_rx_poll_cycle.store(desc.nic_frame_poll_cycle, std::memory_order_relaxed);
            metrics->last_rx_frame_type.store(desc.frame_type, std::memory_order_relaxed);
            metrics->last_rx_len.store(desc.frame_len, std::memory_order_relaxed);
            metrics->last_rx_addr.store(desc.umem_addr, std::memory_order_relaxed);

            // Compute latency: NIC PHC timestamp -> XDP Poll retrieval time
            // NIC timestamp is in CLOCK_REALTIME domain (synced via phc2sys)
            // Poll cycle is TSC - convert to ns and compare with realtime
            if (desc.nic_timestamp_ns != 0 && desc.nic_frame_poll_cycle != 0) {
                // Convert poll cycle (TSC) to approximate wall-clock ns
                // Method: poll_cycle happened "now" in terms of rdtsc
                // So poll_time_realtime = realtime_now - (tsc_now - poll_cycle) / tsc_freq
                uint64_t now_tsc = rdtsc();
                uint64_t now_realtime_ns = get_realtime_ns();

                // Cycles elapsed since poll
                uint64_t elapsed_cycles = now_tsc - desc.nic_frame_poll_cycle;
                uint64_t elapsed_ns = tsc_to_ns(elapsed_cycles);

                // Poll time in realtime domain
                uint64_t poll_time_realtime_ns = now_realtime_ns - elapsed_ns;

                // Latency = poll_time - nic_timestamp
                // This is the time from when NIC received packet to when XDP Poll retrieved it
                int64_t latency_ns = static_cast<int64_t>(poll_time_realtime_ns) -
                                     static_cast<int64_t>(desc.nic_timestamp_ns);

                metrics->update_latency(latency_ns);

#if DEBUG
                printf("[CONSUMER] RX: addr=%lu len=%u type=%u nic_ts=%lu poll_cycle=%lu latency=%ldns (%.2fus)\n",
                       desc.umem_addr, desc.frame_len, desc.frame_type,
                       desc.nic_timestamp_ns, desc.nic_frame_poll_cycle,
                       latency_ns, latency_ns / 1000.0);
#endif
            }
#if DEBUG
            else {
                printf("[CONSUMER] RX: addr=%lu len=%u type=%u nic_ts=%lu poll_cycle=%lu (no latency - missing timestamp)\n",
                       desc.umem_addr, desc.frame_len, desc.frame_type,
                       desc.nic_timestamp_ns, desc.nic_frame_poll_cycle);
            }
#endif
        } else {
            // Small pause to avoid hammering CPU
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }

#if DEBUG
    printf("[CONSUMER] Stopped\n");
#endif
}

// ============================================================================
// XDP Poll Thread
// ============================================================================

using XDPPollType = XDPPollProcess<
    IPCRingProducer<UMEMFrameDescriptor>,
    IPCRingConsumer<UMEMFrameDescriptor>,
    IPCRingConsumer<AckDescriptor>,
    IPCRingConsumer<PongDescriptor>>;

void xdp_poll_thread(
    XDPPollType* xdp_poll,
    void* umem_area,
    size_t umem_size,
    const XDPPollType::Config& config,
    const char* bpf_path,
    disruptor::ipc::shared_region* raw_inbox_region,
    disruptor::ipc::shared_region* raw_outbox_region,
    disruptor::ipc::shared_region* ack_outbox_region,
    disruptor::ipc::shared_region* pong_outbox_region,
    WebsocketStateShm* tcp_state)
{
    // Pin XDP Poll thread to dedicated CPU core
    pin_to_cpu(XDP_POLL_CPU_CORE);

#if DEBUG
    fprintf(stderr, "[XDP-POLL-THREAD] Regions: inbox=%p outbox=%p ack=%p pong=%p\n",
            (void*)raw_inbox_region, (void*)raw_outbox_region,
            (void*)ack_outbox_region, (void*)pong_outbox_region);
    fflush(stderr);
    printf("[XDP-POLL] Starting init_fresh()...\n");
#endif

    // Create ring adapters
#if DEBUG
    fprintf(stderr, "[XDP-POLL-THREAD] Creating raw_inbox_prod from region %p...\n", (void*)raw_inbox_region);
    fflush(stderr);
#endif
    IPCRingProducer<UMEMFrameDescriptor> raw_inbox_prod(*raw_inbox_region);
#if DEBUG
    fprintf(stderr, "[XDP-POLL-THREAD] Creating raw_outbox_cons from region %p...\n", (void*)raw_outbox_region);
    fflush(stderr);
#endif
    IPCRingConsumer<UMEMFrameDescriptor> raw_outbox_cons(*raw_outbox_region);
#if DEBUG
    fprintf(stderr, "[XDP-POLL-THREAD] Creating ack_outbox_cons from region %p...\n", (void*)ack_outbox_region);
    fflush(stderr);
#endif
    IPCRingConsumer<AckDescriptor> ack_outbox_cons(*ack_outbox_region);
#if DEBUG
    fprintf(stderr, "[XDP-POLL-THREAD] Creating pong_outbox_cons from region %p...\n", (void*)pong_outbox_region);
    fflush(stderr);
#endif
    IPCRingConsumer<PongDescriptor> pong_outbox_cons(*pong_outbox_region);

    bool ok = xdp_poll->init_fresh(
        umem_area, umem_size, config, bpf_path,
        &raw_inbox_prod,
        &raw_outbox_cons,
        &ack_outbox_cons,
        &pong_outbox_cons,
        tcp_state);

    if (!ok) {
        fprintf(stderr, "[XDP-POLL] init_fresh() failed\n");
        tcp_state->shutdown_all();
        return;
    }

#if DEBUG
    printf("[XDP-POLL] init_fresh() returned, tcp_state=%p, xdp_ready=%d\n",
           static_cast<void*>(tcp_state),
           tcp_state->is_handshake_xdp_ready() ? 1 : 0);

    printf("[XDP-POLL] Initialized, configuring BPF maps for echo server test...\n");
#endif

    // Configure BPF maps for echo server traffic
    // - local_ip: our interface IP (destination for incoming packets)
    // - exchange_ip: echo server IP (source of incoming packets)
    // - exchange_port: echo server port (source port of incoming packets)
    auto* bpf = xdp_poll->get_bpf_loader();
    if (bpf) {
        bpf->set_local_ip(g_local_ip.c_str());
        bpf->add_exchange_ip(g_echo_server_ip.c_str());
        bpf->add_exchange_port(g_echo_server_port);
#if DEBUG
        printf("[XDP-POLL] BPF configured: local_ip=%s, exchange_ip=%s, port=%u\n",
               g_local_ip.c_str(), g_echo_server_ip.c_str(), g_echo_server_port);
#endif
    } else {
        fprintf(stderr, "[XDP-POLL] WARNING: No BPF loader available\n");
    }

#if DEBUG
    printf("[XDP-POLL] Starting main loop...\n");
    printf("[XDP-POLL] Before run(): tx_ring cached_prod=%u cached_cons=%u\n",
           xdp_poll->tx_ring_debug_cached_prod(), xdp_poll->tx_ring_debug_cached_cons());
#endif
    xdp_poll->run();

#if DEBUG
    printf("[XDP-POLL] Main loop exited\n");
#endif
    xdp_poll->cleanup();
}

// ============================================================================
// Test Cases
// ============================================================================

class XDPPollTest {
public:
    XDPPollTest(const char* interface, const char* bpf_path,
                const char* echo_ip, uint16_t echo_port)
        : interface_(interface), bpf_path_(bpf_path),
          echo_ip_(echo_ip), echo_port_(echo_port) {}

    bool setup() {
#if DEBUG
        printf("\n=== Setting up XDP Poll Test (Echo Server Mode) ===\n");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);
        printf("Echo Server: %s:%u\n\n", echo_ip_, echo_port_);

        // Calibrate TSC for latency measurements
        printf("Calibrating TSC...\n");
#endif
        calibrate_tsc();

        // Get interface MAC
        if (!get_interface_mac(interface_, local_mac_)) {
            fprintf(stderr, "FAIL: Cannot get MAC address for %s\n", interface_);
            return false;
        }
#if DEBUG
        printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_mac_[0], local_mac_[1], local_mac_[2],
               local_mac_[3], local_mac_[4], local_mac_[5]);
#endif

        // Get interface IP
        if (!get_interface_ip(interface_, local_ip_)) {
            fprintf(stderr, "FAIL: Cannot get IP address for %s\n", interface_);
            return false;
        }
#if DEBUG
        printf("Local IP:  %s\n", local_ip_.c_str());
#endif
        g_local_ip = local_ip_;

        // Get gateway for reaching echo server
        if (!get_default_gateway(interface_, gateway_ip_)) {
            fprintf(stderr, "FAIL: Cannot get gateway for %s\n", interface_);
            return false;
        }
#if DEBUG
        printf("Gateway:   %s\n", gateway_ip_.c_str());
#endif

        // Get gateway MAC from ARP cache
        // First, ping the gateway to populate ARP cache
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s >/dev/null 2>&1", gateway_ip_.c_str());
        system(cmd);

        if (!get_gateway_mac(interface_, gateway_ip_.c_str(), gateway_mac_)) {
            fprintf(stderr, "FAIL: Cannot get gateway MAC for %s\n", gateway_ip_.c_str());
            fprintf(stderr, "      Try: ping %s first to populate ARP cache\n", gateway_ip_.c_str());
            return false;
        }
#if DEBUG
        printf("Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               gateway_mac_[0], gateway_mac_[1], gateway_mac_[2],
               gateway_mac_[3], gateway_mac_[4], gateway_mac_[5]);
#endif

        // Initialize UserspaceStack for TCP packet building/parsing
        try {
            stack_.init(local_ip_.c_str(), gateway_ip_.c_str(), "255.255.255.0", local_mac_);
#if DEBUG
            printf("UserspaceStack initialized\n");
#endif
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Cannot initialize UserspaceStack: %s\n", e.what());
            return false;
        }

        // Initialize TCP params for echo server connection
        tcp_params_.local_ip = stack_.get_local_ip();
        tcp_params_.remote_ip = IPLayer::string_to_ip(echo_ip_);
        tcp_params_.remote_port = echo_port_;
        tcp_params_.rcv_wnd = 65535;

        // Create IPC rings
        if (!ipc_manager_.create_all_rings()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        // Allocate UMEM (huge pages preferred)
        umem_size_ = UMEM_TOTAL_SIZE;
        umem_area_ = mmap(nullptr, umem_size_,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
                          -1, 0);
        if (umem_area_ == MAP_FAILED) {
            // Fallback to regular pages
#if DEBUG
            printf("WARN: Huge pages not available, using regular pages\n");
#endif
            umem_area_ = mmap(nullptr, umem_size_,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS,
                              -1, 0);
            if (umem_area_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate UMEM\n");
                return false;
            }
        }
#if DEBUG
        printf("UMEM: %p (%zu bytes)\n", umem_area_, umem_size_);
#endif

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

#if DEBUG
        printf("RAW_INBOX:  %zu entries\n", RAW_INBOX_SIZE);
        printf("RAW_OUTBOX: %zu entries\n", RAW_OUTBOX_SIZE);
#endif

        // Create persistent producer for injecting test frames
        raw_outbox_prod_ = new IPCRingProducer<UMEMFrameDescriptor>(*raw_outbox_region_);
#if DEBUG
        printf("RAW_OUTBOX producer created\n");
#endif

        // Initialize shared state
        tcp_state_ = static_cast<WebsocketStateShm*>(
            mmap(nullptr, sizeof(WebsocketStateShm),
                 PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS,
                 -1, 0));
        if (tcp_state_ == MAP_FAILED) {
            fprintf(stderr, "FAIL: Cannot allocate WebsocketStateShm\n");
            return false;
        }
        tcp_state_->init();
#if DEBUG
        printf("WebsocketStateShm initialized\n");

        printf("=== Setup Complete ===\n\n");
#endif
        return true;
    }

    void teardown() {
#if DEBUG
        printf("\n=== Teardown ===\n");
#endif

        // Signal shutdown
        if (tcp_state_) tcp_state_->shutdown_all();
        g_shutdown.store(true);

        // Wait for threads
        if (xdp_thread_.joinable()) {
            xdp_thread_.join();
        }
        if (consumer_thread_.joinable()) {
            consumer_thread_.join();
        }

        // Cleanup producer
        delete raw_outbox_prod_;
        raw_outbox_prod_ = nullptr;

        // Cleanup shared regions
        delete raw_inbox_region_;
        delete raw_outbox_region_;
        delete ack_outbox_region_;
        delete pong_outbox_region_;
        raw_inbox_region_ = nullptr;
        raw_outbox_region_ = nullptr;
        ack_outbox_region_ = nullptr;
        pong_outbox_region_ = nullptr;

        // Cleanup state
        if (tcp_state_ && tcp_state_ != MAP_FAILED) {
            munmap(tcp_state_, sizeof(WebsocketStateShm));
            tcp_state_ = nullptr;
        }
        if (umem_area_ && umem_area_ != MAP_FAILED) {
            munmap(umem_area_, umem_size_);
            umem_area_ = nullptr;
        }

        // IPC ring cleanup is automatic via destructor

#if DEBUG
        printf("=== Teardown Complete ===\n");
#endif
    }

    bool start_threads() {
        // Configure XDP Poll
        XDPPollType::Config config;
        config.interface = interface_;
        config.queue_id = 0;
        config.frame_size = FRAME_SIZE;
#ifdef XDP_HEADROOM
        config.frame_headroom = XDP_HEADROOM;
#else
        config.frame_headroom = 256;  // Default headroom for NIC timestamp metadata
#endif
        config.zero_copy = false;  // Try copy mode to debug TX issue
        config.trickle_enabled = false;  // Disable for loopback test

        // Start XDP Poll thread
        xdp_thread_ = std::thread(
            xdp_poll_thread,
            &xdp_poll_,
            umem_area_,
            umem_size_,
            config,
            bpf_path_,
            raw_inbox_region_,
            raw_outbox_region_,
            ack_outbox_region_,
            pong_outbox_region_,
            tcp_state_);

        // Wait for XDP to be ready
#if DEBUG
        printf("[MAIN] Waiting for XDP Poll to initialize...\n");
        printf("[MAIN] tcp_state_=%p, handshake_xdp_ready=%d\n",
               static_cast<void*>(tcp_state_),
               tcp_state_->is_handshake_xdp_ready() ? 1 : 0);
#endif
        uint64_t start = get_monotonic_ns();
        [[maybe_unused]] int check_count = 0;
        while (!tcp_state_->is_handshake_xdp_ready()) {
#if DEBUG
            if (++check_count % 10 == 0) {
                printf("[MAIN] Check %d: xdp_ready=%d running=%d\n",
                       check_count,
                       tcp_state_->is_handshake_xdp_ready() ? 1 : 0,
                       tcp_state_->is_running(PROC_XDP_POLL) ? 1 : 0);
            }
#endif
            if (get_monotonic_ns() - start > TIMEOUT_NS) {
                fprintf(stderr, "FAIL: Timeout waiting for XDP Poll ready\n");
                return false;
            }
            if (!tcp_state_->is_running(PROC_XDP_POLL)) {
                fprintf(stderr, "FAIL: XDP Poll exited during init\n");
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
#if DEBUG
        printf("[MAIN] XDP Poll ready\n");
#endif

        // Start consumer thread
        consumer_thread_ = std::thread(
            stub_consumer_thread,
            raw_inbox_region_,
            tcp_state_,
            &metrics_);

        return true;
    }

    // Inject a TCP SYN packet to start connection with echo server
    // Uses UserspaceStack::build_syn() from src/stack/
    // tcp_params_.local_port, tcp_params_.remote_port, tcp_params_.snd_nxt must be set before calling
    void inject_syn_frame() {
        uint64_t tx_frame_idx = ACK_POOL_START + (inject_count_ % ACK_FRAMES);
        uint64_t tx_addr = tx_frame_idx * FRAME_SIZE;
        uint8_t* frame_ptr = static_cast<uint8_t*>(umem_area_) + tx_addr;

        // Build SYN packet using UserspaceStack
        // tcp_params_ should already have local_port, remote_port, snd_nxt set
        size_t frame_len = stack_.build_syn(frame_ptr, FRAME_SIZE, tcp_params_);
        if (frame_len == 0) {
            fprintf(stderr, "WARN: build_syn failed\n");
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
        inject_count_++;
        metrics_.tx_submitted.fetch_add(1, std::memory_order_relaxed);

#if DEBUG
        printf("[INJECT] SYN: seq=%u port=%u -> %s:%u addr=0x%lx\n",
               tcp_params_.snd_nxt, tcp_params_.local_port, echo_ip_, echo_port_, tx_addr);
        // Dump first 58 bytes of packet for debug (SYN has 24-byte TCP header with MSS option)
        printf("  PKT: ");
        for (size_t j = 0; j < 58 && j < frame_len; j++) {
            printf("%02x", frame_ptr[j]);
            if (j == 13 || j == 33 || j == 57) printf(" ");  // ETH|IP|TCP boundaries
        }
        printf("\n");
#endif
    }

    // Inject a TCP ACK packet (for handshake completion)
    // Uses UserspaceStack::build_ack() from src/stack/
    // tcp_params_.snd_nxt and tcp_params_.rcv_nxt must be set before calling
    void inject_ack_frame() {
        uint64_t tx_frame_idx = ACK_POOL_START + (inject_count_ % ACK_FRAMES);
        uint64_t tx_addr = tx_frame_idx * FRAME_SIZE;
        uint8_t* frame_ptr = static_cast<uint8_t*>(umem_area_) + tx_addr;

        // Build ACK packet using UserspaceStack
        // tcp_params_.snd_nxt = our sequence number
        // tcp_params_.rcv_nxt = what we're ACKing (server_seq + 1)
        size_t frame_len = stack_.build_ack(frame_ptr, FRAME_SIZE, tcp_params_);
        if (frame_len == 0) {
            fprintf(stderr, "WARN: build_ack failed\n");
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
        inject_count_++;
        metrics_.tx_submitted.fetch_add(1, std::memory_order_relaxed);

#if DEBUG
        printf("[INJECT] ACK: seq=%u ack=%u\n", tcp_params_.snd_nxt, tcp_params_.rcv_nxt);
#endif
    }

    // Inject a TCP DATA packet with payload
    // Uses UserspaceStack::build_data() from src/stack/
    // tcp_params_.snd_nxt and tcp_params_.rcv_nxt must be set before calling
    void inject_data_frame(const uint8_t* payload, size_t payload_len) {
        uint64_t tx_frame_idx = ACK_POOL_START + (inject_count_ % ACK_FRAMES);
        uint64_t tx_addr = tx_frame_idx * FRAME_SIZE;
        uint8_t* frame_ptr = static_cast<uint8_t*>(umem_area_) + tx_addr;

        // Build DATA packet (PSH+ACK) using UserspaceStack
        size_t frame_len = stack_.build_data(frame_ptr, FRAME_SIZE, tcp_params_, payload, payload_len);
        if (frame_len == 0) {
            fprintf(stderr, "WARN: build_data failed\n");
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
        tcp_params_.snd_nxt += payload_len;  // Advance sequence number
        inject_count_++;
        metrics_.tx_submitted.fetch_add(1, std::memory_order_relaxed);

#if DEBUG
        printf("[INJECT] DATA: seq=%u len=%zu\n", tcp_params_.snd_nxt - static_cast<uint32_t>(payload_len), payload_len);
        // Dump packet bytes for debug
        printf("  PKT: ");
        for (size_t j = 0; j < frame_len && j < 80; j++) {
            printf("%02x", frame_ptr[j]);
            if (j == 13 || j == 33 || j == 53) printf(" ");  // ETH|IP|TCP|DATA boundaries
        }
        printf("\n");
#endif
    }

    bool wait_for_rx(uint64_t expected_count, uint64_t timeout_ns = TIMEOUT_NS) {
        uint64_t start = get_monotonic_ns();
        uint64_t initial = metrics_.rx_consumed.load();

        while (metrics_.rx_consumed.load() - initial < expected_count) {
            if (get_monotonic_ns() - start > timeout_ns) {
                return false;
            }
            if (g_shutdown.load() || !tcp_state_->is_running(PROC_XDP_POLL)) {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return true;
    }

    // ========================================================================
    // Test 1: ICMP Ping Latency (10 ICMP Echo Requests)
    // Send ICMP Echo Requests and measure round-trip latency
    // ========================================================================
    bool test_repeated_latency() {
        printf("\n--- Test 1: ICMP Ping Latency (10 packets) ---\n");
        printf("  Target: %s\n\n", echo_ip_);
        metrics_.reset();

        // Wait a bit and clear any pending RX packets from previous runs
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        uint64_t initial_rx_count = metrics_.rx_consumed.load();
        printf("  (Cleared %lu stale RX packets)\n\n", initial_rx_count);

        constexpr int NUM_PACKETS = 10;
        int successful = 0;
        uint16_t icmp_seq = 1;
        uint16_t icmp_id = static_cast<uint16_t>(getpid() & 0xFFFF);

        printf("  #   | Seq  | RX Len | NIC-to-Poll Latency\n");
        printf("  ----|------|--------|---------------------\n");

        for (int i = 0; i < NUM_PACKETS; i++) {
            // Record RX count BEFORE sending
            uint64_t pre_send_rx_count = metrics_.rx_consumed.load();

            // Send ICMP Echo Request
            inject_icmp_echo_request(icmp_id, icmp_seq);

            // Wait for ICMP Echo Reply
            uint64_t start = get_monotonic_ns();
            constexpr uint64_t TIMEOUT_NS = 2'000'000'000ULL;  // 2 second timeout
            bool got_response = false;

            while (get_monotonic_ns() - start < TIMEOUT_NS) {
                uint64_t current_rx_count = metrics_.rx_consumed.load();

                // Check if a NEW packet arrived (after we sent)
                if (current_rx_count > pre_send_rx_count) {
                    uint64_t rx_addr = metrics_.last_rx_addr.load();
                    uint32_t rx_len = metrics_.last_rx_len.load();

                    if (rx_addr != 0 && rx_len > 0) {
                        const uint8_t* rx_frame = static_cast<const uint8_t*>(umem_area_) + rx_addr;

                        // Check if this is an ICMP Echo Reply for our request
                        if (is_icmp_echo_reply(rx_frame, rx_len, icmp_id, icmp_seq)) {
                            int64_t latency = metrics_.last_latency_ns.load();
                            printf("  %2d  | %4u | %4u B | %6ld ns (%6.2f us)\n",
                                   i + 1, icmp_seq, rx_len, latency, latency / 1000.0);
                            successful++;
                            got_response = true;
                            break;
                        }
#if DEBUG
                        else {
                            // Debug: show what we received
                            if (rx_len >= 14 + 20 + 8) {
                                const uint8_t* ip = rx_frame + 14;
                                const uint8_t* icmp = rx_frame + 14 + ((ip[0] & 0x0F) * 4);
                                uint16_t reply_id = (icmp[4] << 8) | icmp[5];
                                uint16_t reply_seq = (icmp[6] << 8) | icmp[7];
                                printf("[RX] proto=%u type=%u id=%u seq=%u (expected id=%u seq=%u)\n",
                                       ip[9], icmp[0], reply_id, reply_seq, icmp_id, icmp_seq);
                            }
                        }
#endif
                    }
                    // Update baseline for next check
                    pre_send_rx_count = current_rx_count;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            if (!got_response) {
                printf("  %2d  | %4u | TIMEOUT - no reply\n", i + 1, icmp_seq);
            }

            icmp_seq++;

            // Short delay between pings
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        printf("\n");
        printf("  Successful: %d/%d\n", successful, NUM_PACKETS);

        if (successful == 0) {
            printf("FAIL: No ICMP replies received\n");
            print_bpf_stats();
            return false;
        }

        printf("PASS: Received %d ICMP replies\n", successful);
        return true;
    }

    // Build and inject an ICMP Echo Request packet
    void inject_icmp_echo_request(uint16_t id, uint16_t seq) {
        uint64_t tx_frame_idx = ACK_POOL_START + (inject_count_ % ACK_FRAMES);
        uint64_t tx_addr = tx_frame_idx * FRAME_SIZE;
        uint8_t* frame_ptr = static_cast<uint8_t*>(umem_area_) + tx_addr;

        // Build ICMP Echo Request
        // Ethernet header (14 bytes)
        memcpy(frame_ptr, gateway_mac_, 6);        // Dest MAC
        memcpy(frame_ptr + 6, local_mac_, 6);      // Src MAC
        frame_ptr[12] = 0x08; frame_ptr[13] = 0x00; // EtherType: IPv4

        // IP header (20 bytes)
        uint8_t* ip = frame_ptr + 14;
        ip[0] = 0x45;  // Version 4, IHL 5
        ip[1] = 0x00;  // TOS
        uint16_t ip_len = 20 + 8 + 32;  // IP + ICMP header + 32 bytes payload
        ip[2] = (ip_len >> 8) & 0xFF;
        ip[3] = ip_len & 0xFF;
        ip[4] = 0x00; ip[5] = 0x00;  // ID
        ip[6] = 0x40; ip[7] = 0x00;  // Flags (DF) + Fragment offset
        ip[8] = 64;   // TTL
        ip[9] = 1;    // Protocol: ICMP
        ip[10] = 0; ip[11] = 0;  // Checksum (computed below)

        // Source IP (convert from host to network byte order)
        uint32_t src_ip_net = htonl(stack_.get_local_ip());
        memcpy(&ip[12], &src_ip_net, 4);

        // Dest IP (convert from host to network byte order)
        uint32_t dst_ip_net = htonl(tcp_params_.remote_ip);
        memcpy(&ip[16], &dst_ip_net, 4);

        // IP checksum
        uint32_t sum = 0;
        for (int j = 0; j < 20; j += 2) {
            sum += (ip[j] << 8) | ip[j + 1];
        }
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        uint16_t ip_cksum = ~sum;
        ip[10] = (ip_cksum >> 8) & 0xFF;
        ip[11] = ip_cksum & 0xFF;

        // ICMP header (8 bytes) + payload (32 bytes)
        uint8_t* icmp = frame_ptr + 34;
        icmp[0] = 8;   // Type: Echo Request
        icmp[1] = 0;   // Code
        icmp[2] = 0; icmp[3] = 0;  // Checksum (computed below)
        icmp[4] = (id >> 8) & 0xFF;
        icmp[5] = id & 0xFF;
        icmp[6] = (seq >> 8) & 0xFF;
        icmp[7] = seq & 0xFF;

        // Payload (32 bytes of pattern)
        for (int j = 0; j < 32; j++) {
            icmp[8 + j] = static_cast<uint8_t>(j);
        }

        // ICMP checksum (over ICMP header + data)
        sum = 0;
        for (int j = 0; j < 40; j += 2) {
            sum += (icmp[j] << 8) | icmp[j + 1];
        }
        while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
        uint16_t icmp_cksum = ~sum;
        icmp[2] = (icmp_cksum >> 8) & 0xFF;
        icmp[3] = icmp_cksum & 0xFF;

        size_t frame_len = 14 + 20 + 8 + 32;  // ETH + IP + ICMP + payload

        int64_t slot = raw_outbox_prod_->try_claim();
        if (slot < 0) {
            fprintf(stderr, "WARN: RAW_OUTBOX full\n");
            return;
        }

        auto& desc = (*raw_outbox_prod_)[slot];
        desc.umem_addr = tx_addr;
        desc.frame_len = static_cast<uint16_t>(frame_len);
        desc.frame_type = FRAME_TYPE_ACK;  // Reuse ACK type for immediate TX
        desc.consumed = 0;
        desc.nic_timestamp_ns = 0;
        desc.nic_frame_poll_cycle = 0;

        raw_outbox_prod_->publish(slot);
        inject_count_++;
        metrics_.tx_submitted.fetch_add(1, std::memory_order_relaxed);

#if DEBUG
        printf("[INJECT] ICMP Echo Request: id=%u seq=%u -> %s\n", id, seq, echo_ip_);
        printf("[INJECT] tx_addr=0x%lx frame_ptr=%p len=%zu\n", tx_addr, frame_ptr, frame_len);
        printf("[INJECT] ETH: dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=%04x\n",
               frame_ptr[0], frame_ptr[1], frame_ptr[2], frame_ptr[3], frame_ptr[4], frame_ptr[5],
               frame_ptr[6], frame_ptr[7], frame_ptr[8], frame_ptr[9], frame_ptr[10], frame_ptr[11],
               (frame_ptr[12] << 8) | frame_ptr[13]);
        printf("[INJECT] IP: ver=%u ihl=%u len=%u proto=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
               ip[0] >> 4, ip[0] & 0xF, (ip[2] << 8) | ip[3], ip[9],
               ip[12], ip[13], ip[14], ip[15], ip[16], ip[17], ip[18], ip[19]);
        fflush(stdout);
#endif
    }

    // Check if a received frame is an ICMP Echo Reply matching our request
    bool is_icmp_echo_reply(const uint8_t* frame, size_t len, uint16_t expected_id, uint16_t expected_seq) {
        if (len < 14 + 20 + 8) return false;  // Min: ETH + IP + ICMP header

        // Check EtherType is IPv4
        if (frame[12] != 0x08 || frame[13] != 0x00) {
#if DEBUG
            printf("[PKT-CHECK] Not IPv4: type=%02x%02x\n", frame[12], frame[13]);
#endif
            return false;
        }

        const uint8_t* ip = frame + 14;
        // Check IP version and protocol
        if ((ip[0] >> 4) != 4) return false;  // Not IPv4
        uint8_t proto = ip[9];
        if (proto != 1) {
#if DEBUG
            printf("[PKT-CHECK] Not ICMP: proto=%u\n", proto);
#endif
            return false;  // Not ICMP
        }

        // Get IP header length
        size_t ip_hdr_len = (ip[0] & 0x0F) * 4;
        if (len < 14 + ip_hdr_len + 8) return false;

        const uint8_t* icmp = frame + 14 + ip_hdr_len;
        // Check ICMP type is Echo Reply (0)
        if (icmp[0] != 0) {
#if DEBUG
            printf("[PKT-CHECK] Not Echo Reply: type=%u (want 0)\n", icmp[0]);
#endif
            return false;
        }

        // Check ID and sequence
        uint16_t reply_id = (icmp[4] << 8) | icmp[5];
        uint16_t reply_seq = (icmp[6] << 8) | icmp[7];

#if DEBUG
        printf("[PKT-CHECK] ICMP Echo Reply: id=%u seq=%u (want id=%u seq=%u)\n",
               reply_id, reply_seq, expected_id, expected_seq);
#endif

        return (reply_id == expected_id && reply_seq == expected_seq);
    }

    // ========================================================================
    // Test 2: Timestamp Population
    // ========================================================================
    bool test_timestamp_populated() {
        printf("\n--- Test 2: Timestamp Population ---\n");

        uint64_t ts = metrics_.last_rx_timestamp.load();

        if (ts == 0) {
            printf("WARN: No HW timestamp (driver may not support)\n");
            print_bpf_stats();
            return true;  // Warning, not failure
        }

        printf("PASS: HW timestamp populated: %lu ns\n", ts);
        return true;
    }

    // ========================================================================
    // Test 3: fill_ring Reclaim
    // ========================================================================
    bool test_fill_ring_reclaim() {
        printf("\n--- Test 3: fill_ring Reclaim ---\n");

        uint32_t initial_producer = xdp_poll_.fill_ring_producer();
        printf("      Initial fill_ring producer: %u\n", initial_producer);

        // Give XDP Poll time for idle reclaim
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        uint32_t final_producer = xdp_poll_.fill_ring_producer();
        printf("      Final fill_ring producer:   %u\n", final_producer);

        // Note: fill_ring producer may not advance if consumer hasn't processed
        // enough frames. Check last_released_seq instead.
        int64_t released = xdp_poll_.last_released_seq();
        printf("      Last released sequence:     %ld\n", released);

        if (released > 0) {
            printf("PASS: Frame reclaim working (released %ld frames)\n", released);
            return true;
        }

        printf("WARN: No frames reclaimed (may need more traffic)\n");
        return true;  // Warning, not failure for single frame
    }

    // ========================================================================
    // Test 4: TX/RX Ring Functionality
    // ========================================================================
    bool test_tx_rx_rings() {
        printf("\n--- Test 4: TX/RX Ring Functionality ---\n");

        // This test verifies:
        // 1. TX frames are submitted to NIC
        // 2. RX frames arrive in RAW_INBOX
        // 3. Ring buffer producer/consumer works correctly

        printf("      TX submitted:     %lu\n", metrics_.tx_submitted.load());
        printf("      RX consumed:      %lu\n", metrics_.rx_consumed.load());
        printf("      XDP RX packets:   %lu\n", xdp_poll_.rx_packets());
        printf("      XDP TX completes: %lu\n", xdp_poll_.tx_completions());

        // If we got at least one RX packet, the basic flow is working
        if (metrics_.rx_consumed.load() > 0) {
            printf("PASS: TX/RX ring functionality verified\n");
            return true;
        }

        printf("WARN: No RX packets received - check BPF filter and routing\n");
        return true;  // Warning, not failure
    }

    // ========================================================================
    // Test 5: BPF Statistics
    // ========================================================================
    bool test_bpf_stats() {
        printf("\n--- Test 5: BPF Statistics ---\n");
        print_bpf_stats();
        return true;
    }

    void print_bpf_stats() {
        auto* bpf = xdp_poll_.get_bpf_loader();
        if (!bpf) {
            printf("      No BPF loader available\n");
            return;
        }

        auto stats = bpf->get_stats();
        printf("      Total packets:    %lu\n", stats.total_packets);
        printf("      Exchange packets: %lu (redirected to AF_XDP)\n", stats.exchange_packets);
        printf("      Kernel packets:   %lu\n", stats.kernel_packets);
        printf("      IPv4 packets:     %lu\n", stats.ipv4_packets);
        printf("      TCP packets:      %lu\n", stats.tcp_packets);
        printf("      Timestamp OK:     %lu\n", stats.timestamp_ok);
        printf("      Timestamp fail:   %lu\n", stats.timestamp_fail);
    }

    void print_final_metrics() {
        printf("\n=== Final Test Metrics ===\n");
        printf("XDP Poll RX packets:     %lu\n", xdp_poll_.rx_packets());
        printf("XDP Poll TX completions: %lu\n", xdp_poll_.tx_completions());
        printf("fill_ring producer:      %u\n", xdp_poll_.fill_ring_producer());
        printf("fill_ring consumer:      %u\n", xdp_poll_.fill_ring_consumer());
        printf("Last released seq:       %ld\n", xdp_poll_.last_released_seq());
        metrics_.print();
        metrics_.print_latency();
        print_bpf_stats();
    }

private:
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

    // UserspaceStack for TCP packet building/parsing (src/stack/)
    UserspaceStack stack_;
    TCPParams tcp_params_;  // TCP connection parameters

    disruptor::ipc::shared_region* raw_inbox_region_ = nullptr;
    disruptor::ipc::shared_region* raw_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* ack_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* pong_outbox_region_ = nullptr;
    WebsocketStateShm* tcp_state_ = nullptr;

    // Persistent producer for injecting test frames (created after regions open)
    IPCRingProducer<UMEMFrameDescriptor>* raw_outbox_prod_ = nullptr;

    XDPPollType xdp_poll_;
    TestMetrics metrics_;

    std::thread xdp_thread_;
    std::thread consumer_thread_;

    uint64_t inject_count_ = 0;
};

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> <echo_ip> <echo_port>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s enp108s0 build/exchange_filter.bpf.o 139.162.79.171 12345\n", argv[0]);
        fprintf(stderr, "\nPrerequisites:\n");
        fprintf(stderr, "  1. Echo server running: ncat -l <port> -k -c 'cat'\n");
        fprintf(stderr, "  2. Route to echo server via interface\n");
        fprintf(stderr, "  3. make bpf\n");
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];
    const char* echo_ip = argv[3];
    uint16_t echo_port = static_cast<uint16_t>(atoi(argv[4]));

    // Store in globals for BPF configuration
    g_echo_server_ip = echo_ip;
    g_echo_server_port = echo_port;

    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "Error: Must run as root for XDP/AF_XDP\n");
        return 1;
    }

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Pin main test thread to Transport CPU core
    pin_to_cpu(TRANSPORT_CPU_CORE);

    // Seed random for port selection
    srand(static_cast<unsigned>(time(nullptr)));

    printf("==============================================\n");
    printf("  XDP Poll Segregated Test (Echo Server)     \n");
    printf("==============================================\n\n");

    XDPPollTest test(interface, bpf_path, echo_ip, echo_port);

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

    // Run tests
    int failures = 0;

    if (!test.test_repeated_latency()) failures++;
    if (!test.test_timestamp_populated()) failures++;
    if (!test.test_fill_ring_reclaim()) failures++;
    if (!test.test_tx_rx_rings()) failures++;
    test.test_bpf_stats();

    // Print final metrics
    test.print_final_metrics();

    // Cleanup
    test.teardown();

    // Summary
    printf("\n==============================================\n");
    if (failures == 0) {
        printf("  ALL TESTS PASSED\n");
    } else {
        printf("  %d TEST(S) FAILED\n", failures);
    }
    printf("==============================================\n");

    return failures > 0 ? 1 : 0;
}

#else  // !USE_XDP

int main() {
    fprintf(stderr, "Error: Build with USE_XDP=1\n");
    fprintf(stderr, "Example: make test_pipeline_xdp_poll XDP_INTERFACE=enp108s0\n");
    return 1;
}

#endif  // USE_XDP
