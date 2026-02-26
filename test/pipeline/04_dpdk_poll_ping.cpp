// test/pipeline/04_dpdk_poll_ping.cpp  
// DPDK Poll Process ICMP Ping Test
//
// DPDK equivalent of 00_xdp_poll_ping.cpp.
// Tests DPDKPollProcess in isolation with ICMP echo request/reply.
//
// Architecture (2-thread):
//   Main Thread: ICMP TX builder + RX consumer
//   DPDK Thread: DPDKPollProcess (rte_eth_rx/tx_burst)
//
// Prerequisites:
//   1. NIC bound to vfio-pci: ./scripts/dpdk_bind.sh enp108s0
//   2. Hugepages: echo 512 > /proc/sys/vm/nr_hugepages
//   3. IOMMU enabled: intel_iommu=on iommu=pt
//
// Usage: sudo ./build/test_pipeline_04_dpdk_poll_ping <interface> [target_ip]
//        (No BPF path needed - DPDK uses userspace filter)

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

#ifdef USE_DPDK

#define DEBUG 0
#define DEBUG_IPC 0

#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/01_dpdk_poll_process.hpp"

// Stack headers for packet building
#include "../../src/stack/mac/ethernet.hpp"
#include "../../src/stack/ip/ip_layer.hpp"
#include "../../src/stack/ip/checksum.hpp"

using namespace websocket::pipeline;
using namespace userspace_stack;
using websocket::xdp::PacketFrameDescriptor;

// ============================================================================
// ICMP Constants and Structures
// ============================================================================

constexpr uint8_t ICMP_ECHO_REQUEST = 8;
constexpr uint8_t ICMP_ECHO_REPLY = 0;
constexpr size_t ICMP_HEADER_LEN = 8;

struct __attribute__((packed)) ICMPHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

// ============================================================================
// Configuration
// ============================================================================

namespace {

constexpr int DPDK_POLL_CPU_CORE = 2;
constexpr int TEST_CPU_CORE = 4;

std::string g_ping_target_ip;
std::string g_local_ip;

constexpr int NUM_PINGS = 100;  // Fewer pings for DPDK test
constexpr uint64_t TEST_TIMEOUT_NS = 10'000'000'000ULL;  // 10 seconds
constexpr uint64_t MSG_TIMEOUT_NS = 100'000'000ULL;      // 100ms per-ping timeout

std::atomic<bool> g_shutdown{false};

void signal_handler(int) {
    g_shutdown.store(true, std::memory_order_release);
}

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

double g_tsc_freq_ghz = 0.0;

void calibrate_tsc() {
    uint64_t start_tsc = rdtsc();
    uint64_t start_ns = get_monotonic_ns();
    usleep(100000);
    uint64_t end_tsc = rdtsc();
    uint64_t end_ns = get_monotonic_ns();
    g_tsc_freq_ghz = static_cast<double>(end_tsc - start_tsc) / static_cast<double>(end_ns - start_ns);
    printf("[TSC] Calibrated: %.3f GHz\n", g_tsc_freq_ghz);
}

// Helper to get interface MAC
bool get_interface_mac(const char* iface, uint8_t* mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return false; }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

bool get_interface_ip(const char* iface, std::string& ip_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return false; }
    close(fd);
    auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    ip_out = inet_ntoa(addr->sin_addr);
    return true;
}

bool get_default_gateway(const char* iface, std::string& gw_out) {
    FILE* fp = fopen("/proc/net/route", "r");
    if (!fp) return false;
    char line[256];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return false; }
    while (fgets(line, sizeof(line), fp)) {
        char ifname[32];
        unsigned int dest, gateway, flags;
        if (sscanf(line, "%31s %x %x %x", ifname, &dest, &gateway, &flags) >= 4) {
            if (strcmp(ifname, iface) == 0 && dest == 0 && gateway != 0) {
                struct in_addr addr;
                addr.s_addr = gateway;
                gw_out = inet_ntoa(addr);
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

bool get_gateway_mac(const char* iface, const char* gw_ip, uint8_t* mac_out) {
    FILE* fp = fopen("/proc/net/arp", "r");
    if (!fp) return false;
    char line[256];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return false; }
    while (fgets(line, sizeof(line), fp)) {
        char ip[64], hw_type[16], flags[16], mac_str[32], mask[16], dev[32];
        if (sscanf(line, "%63s %15s %15s %31s %15s %31s",
                   ip, hw_type, flags, mac_str, mask, dev) == 6) {
            if (strcmp(ip, gw_ip) == 0 && strcmp(dev, iface) == 0) {
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

}  // namespace

// ============================================================================
// DPDK Poll Type
// ============================================================================

using DPDKPollType = DPDKPollProcess<
    IPCRingProducer<PacketFrameDescriptor>,
    IPCRingConsumer<PacketFrameDescriptor>,
    false>;  // Profiling disabled

// ============================================================================
// IPC Ring Manager (simplified — only RAW_INBOX + RAW_OUTBOX)
// ============================================================================

class IPCRingManager {
public:
    IPCRingManager() {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string("dpdk_04_test_") + timestamp;
    }

    ~IPCRingManager() { cleanup(); }

    bool create_ring(const char* name, size_t buffer_size, size_t event_size, uint8_t max_consumers = 1) {
        std::string base_path = std::string("/dev/shm/hft/") + ipc_ring_dir_ + "/" + name;
        std::string hdr_path = base_path + ".hdr";
        std::string dat_path = base_path + ".dat";

        uint32_t producer_offset = hftshm::default_producer_offset();
        uint32_t consumer_0_offset = hftshm::default_consumer_0_offset();
        uint32_t header_size = hftshm::header_segment_size(max_consumers);

        int hdr_fd = open(hdr_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (hdr_fd < 0) return false;
        if (ftruncate(hdr_fd, header_size) < 0) { close(hdr_fd); return false; }
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
        if (dat_fd < 0) { unlink(hdr_path.c_str()); return false; }
        if (ftruncate(dat_fd, buffer_size) < 0) { close(dat_fd); unlink(hdr_path.c_str()); return false; }
        void* dat_ptr = mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, dat_fd, 0);
        close(dat_fd);
        if (dat_ptr == MAP_FAILED) { unlink(hdr_path.c_str()); return false; }
        memset(dat_ptr, 0, buffer_size);
        munmap(dat_ptr, buffer_size);

        return true;
    }

    bool create_all_rings() {
        mkdir("/dev/shm/hft", 0755);
        std::string full_dir = "/dev/shm/hft/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) return false;

        if (!create_ring("raw_inbox", RAW_INBOX_SIZE * sizeof(PacketFrameDescriptor),
                         sizeof(PacketFrameDescriptor), 1)) return false;
        if (!create_ring("raw_outbox", RAW_OUTBOX_SIZE * sizeof(PacketFrameDescriptor),
                         sizeof(PacketFrameDescriptor), 1)) return false;
        printf("[IPC] Created ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;
        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = { "raw_inbox", "raw_outbox" };
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
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [target_ip]\n", argv[0]);
        fprintf(stderr, "\nPrerequisites:\n");
        fprintf(stderr, "  1. NIC bound to vfio-pci: ./scripts/dpdk_bind.sh <interface>\n");
        fprintf(stderr, "  2. Hugepages configured\n");
        fprintf(stderr, "  3. Run as root: sudo %s <interface>\n", argv[0]);
        fprintf(stderr, "\nNote: DPDKPollProcess filter matches TCP only.\n");
        fprintf(stderr, "      ICMP ping test requires filter extension (TODO).\n");
        fprintf(stderr, "      This test validates DPDK init, port setup, and lifecycle.\n");
        return 1;
    }

    const char* interface = argv[1];

    // Detect target IP (default: gateway)
    if (argc >= 3) {
        g_ping_target_ip = argv[2];
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  DPDK Poll Process Ping Test                 \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);

    calibrate_tsc();

    // Get interface info (before binding — may not be available after vfio-pci)
    uint8_t local_mac[6] = {};
    uint8_t gw_mac[6] = {};
    std::string gw_ip;

    // Note: after NIC is bound to vfio-pci, sysfs/ioctl queries won't work.
    // Interface info should be captured before binding, or passed as arguments.
    if (!get_interface_ip(interface, g_local_ip)) {
        fprintf(stderr, "WARN: Cannot get IP for %s (may be bound to vfio-pci)\n", interface);
        fprintf(stderr, "      Pass target_ip as argument if needed\n");
    } else {
        printf("  Local IP:   %s\n", g_local_ip.c_str());
    }

    if (g_ping_target_ip.empty()) {
        if (!get_default_gateway(interface, gw_ip)) {
            fprintf(stderr, "WARN: Cannot detect gateway for %s\n", interface);
            g_ping_target_ip = "8.8.8.8";  // Fallback
        } else {
            g_ping_target_ip = gw_ip;
        }
    }
    printf("  Target IP:  %s\n", g_ping_target_ip.c_str());

    // Create IPC rings
    IPCRingManager ipc_manager;
    if (!ipc_manager.create_all_rings()) {
        fprintf(stderr, "FAIL: Cannot create IPC rings\n");
        return 1;
    }

    // Allocate UMEM at a low VA for DPDK IOMMU compatibility
    // The IOMMU SAGAW is 39-bit (512 GB limit). Default mmap VAs are in the TB range,
    // causing DMA faults. MAP_FIXED_NOREPLACE at DPDK_UMEM_BASE_VA (8 GB) ensures
    // all IOVAs (= VAs in --iova-mode=va) fit within the IOMMU address width.
    void* umem_area = mmap(reinterpret_cast<void*>(DPDK_UMEM_BASE_VA), UMEM_TOTAL_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_FIXED_NOREPLACE,
                           -1, 0);
    if (umem_area == MAP_FAILED) {
        // Fallback: try without hugepages at the same low VA
        umem_area = mmap(reinterpret_cast<void*>(DPDK_UMEM_BASE_VA), UMEM_TOTAL_SIZE,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                         -1, 0);
        if (umem_area == MAP_FAILED) {
            fprintf(stderr, "FAIL: Cannot allocate UMEM at low VA 0x%lx\n", DPDK_UMEM_BASE_VA);
            return 1;
        }
        printf("[UMEM] Allocated %zu bytes at %p (regular pages, low VA)\n", UMEM_TOTAL_SIZE, umem_area);
    } else {
        printf("[UMEM] Allocated %zu bytes at %p (huge pages, low VA)\n", UMEM_TOTAL_SIZE, umem_area);
    }

    // Allocate ConnStateShm
    auto* conn_state = static_cast<ConnStateShm*>(
        mmap(nullptr, sizeof(ConnStateShm), PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (conn_state == MAP_FAILED) {
        fprintf(stderr, "FAIL: Cannot allocate ConnStateShm\n");
        return 1;
    }
    conn_state->init();

    // Populate exchange IPs for filter
    struct in_addr target_addr;
    if (inet_pton(AF_INET, g_ping_target_ip.c_str(), &target_addr) == 1) {
        conn_state->exchange_ips[0] = target_addr.s_addr;
        conn_state->exchange_ip_count = 1;
    }
    conn_state->target_port = 0;  // ICMP has no port
    strncpy(conn_state->interface_name, interface, sizeof(conn_state->interface_name) - 1);
    conn_state->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

    // Open shared regions
    disruptor::ipc::shared_region* raw_inbox_region = nullptr;
    disruptor::ipc::shared_region* raw_outbox_region = nullptr;
    try {
        raw_inbox_region = new disruptor::ipc::shared_region(ipc_manager.get_ring_name("raw_inbox"));
        raw_outbox_region = new disruptor::ipc::shared_region(ipc_manager.get_ring_name("raw_outbox"));
    } catch (const std::exception& e) {
        fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
        return 1;
    }

    // Launch DPDK Poll thread
    std::atomic<bool> dpdk_ready{false};
    std::atomic<bool> dpdk_failed{false};

    std::thread dpdk_thread([&]() {
        pin_to_cpu(DPDK_POLL_CPU_CORE);

        IPCRingProducer<PacketFrameDescriptor> raw_inbox_prod(*raw_inbox_region);
        IPCRingConsumer<PacketFrameDescriptor> raw_outbox_cons(*raw_outbox_region);

        DPDKPollType dpdk_poll(interface);

        if (!dpdk_poll.init(umem_area, UMEM_TOTAL_SIZE, nullptr,
                            &raw_inbox_prod, &raw_outbox_cons, conn_state)) {
            fprintf(stderr, "[DPDK-POLL] init() failed\n");
            dpdk_failed.store(true);
            conn_state->shutdown_all();
            return;
        }

        dpdk_ready.store(true);
        printf("[DPDK-POLL] Initialized, running main loop\n");
        dpdk_poll.run();
        dpdk_poll.cleanup();
        printf("[DPDK-POLL] Exited\n");
    });

    // Wait for DPDK ready or failure
    while (!dpdk_ready.load() && !dpdk_failed.load()) {
        usleep(1000);
    }

    if (dpdk_failed.load()) {
        fprintf(stderr, "\nFATAL: DPDK Poll initialization failed\n");
        conn_state->shutdown_all();
        dpdk_thread.join();
        delete raw_inbox_region;
        delete raw_outbox_region;
        munmap(conn_state, sizeof(ConnStateShm));
        munmap(umem_area, UMEM_TOTAL_SIZE);
        return 1;
    }

    // Wait for handshake
    if (!conn_state->wait_for_handshake_xdp_ready(10000000)) {
        fprintf(stderr, "FAIL: Timeout waiting for DPDK Poll ready\n");
        conn_state->shutdown_all();
        dpdk_thread.join();
        delete raw_inbox_region;
        delete raw_outbox_region;
        munmap(conn_state, sizeof(ConnStateShm));
        munmap(umem_area, UMEM_TOTAL_SIZE);
        return 1;
    }

    printf("[MAIN] DPDK Poll ready\n");
    printf("\n--- DPDK Initialization Test PASSED ---\n");
    printf("Note: ICMP ping requires filter extension (match_exchange_packet TCP-only).\n");
    printf("      Full pipeline test (20_websocket_binance) validates end-to-end with TCP.\n");

    // Let it run briefly to verify no crashes
    printf("[MAIN] Running for 2 seconds to verify stability...\n");
    for (int i = 0; i < 20 && !g_shutdown.load(); i++) {
        usleep(100000);  // 100ms
    }

    printf("[MAIN] Shutting down...\n");
    conn_state->shutdown_all();
    dpdk_thread.join();

    // Cleanup
    delete raw_inbox_region;
    delete raw_outbox_region;
    munmap(conn_state, sizeof(ConnStateShm));
    munmap(umem_area, UMEM_TOTAL_SIZE);

    printf("\n==============================================\n");
    printf("  DPDK POLL INIT+LIFECYCLE TEST PASSED\n");
    printf("==============================================\n");
    return 0;
}

#else  // !USE_DPDK

int main() {
    fprintf(stderr, "Error: Build with USE_DPDK=1\n");
    fprintf(stderr, "Example: make build-test-pipeline-04_dpdk_poll_ping USE_DPDK=1 DPDK_INTERFACE=enp108s0\n");
    return 1;
}

#endif  // USE_DPDK
