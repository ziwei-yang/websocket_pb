// test/pipeline/05_dpdk_disruptor_packetio_tcp.cpp
// Test PacketTransport<DisruptorPacketIO> with DPDK as I/O backend
//
// Architecture (2-process):
//   DPDK Poll (core 2)                  Test / Transport (core 4)
//   ┌──────────────────┐               ┌──────────────────────────┐
//   │ DPDK PMD ←→ NIC  │               │ PacketTransport          │
//   │                   │◄── RAW_OUTBOX │   <DisruptorPacketIO>    │
//   │                   │──► RAW_INBOX  │                          │
//   └──────────────────┘  (shared mem)  └──────────────────────────┘
//
// DPDK equivalent of 03_disruptor_packetio_tcp.cpp:
//   - Child (core 2): DPDKPollProcess — handles DPDK PMD interface
//   - Parent (core 4): PacketTransport<DisruptorPacketIO> — TCP echo test via IPC rings
//
// Usage: sudo ./build/test_pipeline_05_dpdk_disruptor_packetio_tcp <interface> [echo_host] [echo_port] [throttle_cycles]
//        (No BPF path needed - DPDK uses userspace filter)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <string>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>

#ifdef USE_DPDK

#define DEBUG 0
#define DEBUG_IPC 0
#define DEBUG_PIO 1

#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/01_dpdk_poll_process.hpp"
#include "../../src/pipeline/disruptor_packet_io.hpp"
#include "../../src/policy/transport.hpp"

using namespace websocket::transport;
using namespace websocket::pipeline;
using websocket::xdp::PacketFrameDescriptor;

// ============================================================================
// Type Aliases
// ============================================================================

using DPDKPollType = DPDKPollProcess<
    IPCRingProducer<PacketFrameDescriptor>,
    IPCRingConsumer<PacketFrameDescriptor>,
    false>;  // Profiling disabled

// ============================================================================
// Configuration
// ============================================================================

namespace {

constexpr int DPDK_POLL_CPU_CORE = 2;
constexpr int TEST_CPU_CORE = 4;

constexpr int MAX_MESSAGES = 500;
constexpr int SEND_TIMEOUT_SECONDS = 20;
constexpr int RECV_DRAIN_SECONDS = 3;

static uint64_t g_tx_throttle_cycles = 0;

std::atomic<bool> g_shutdown{false};
ConnStateShm* g_conn_state = nullptr;

void signal_handler(int sig) {
    g_shutdown.store(true, std::memory_order_release);
    if (g_conn_state) {
        g_conn_state->shutdown_all();
    }
    fprintf(stderr, "\n[SIGNAL] Received signal %d, initiating graceful shutdown...\n", sig);
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

}  // namespace

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
        ipc_ring_dir_ = std::string("dpdk_05_test_") + timestamp;
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
// Test Class
// ============================================================================

class DPDKDisruptorTCPTest {
public:
    DPDKDisruptorTCPTest(const char* interface, const char* echo_host, uint16_t echo_port)
        : interface_(interface), echo_host_(echo_host), echo_port_(echo_port) {}

    bool setup() {
        printf("\n=== Setting up DPDK DisruptorPacketIO TCP Test (2-Process) ===\n");
        printf("Interface:   %s\n", interface_);
        printf("Echo Server: %s:%u\n\n", echo_host_, echo_port_);

        calibrate_tsc();

        if (!ipc_manager_.create_all_rings()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        // Allocate UMEM at a low VA for DPDK IOMMU compatibility
        // IOMMU SAGAW=39-bit (512 GB limit). MAP_FIXED_NOREPLACE ensures low VA.
        umem_area_ = mmap(reinterpret_cast<void*>(DPDK_UMEM_BASE_VA), UMEM_TOTAL_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | MAP_FIXED_NOREPLACE,
                          -1, 0);
        if (umem_area_ == MAP_FAILED) {
            umem_area_ = mmap(reinterpret_cast<void*>(DPDK_UMEM_BASE_VA), UMEM_TOTAL_SIZE,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                              -1, 0);
            if (umem_area_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate UMEM at low VA 0x%lx\n", DPDK_UMEM_BASE_VA);
                return false;
            }
            printf("[UMEM] Allocated %zu bytes at %p (regular pages, low VA)\n", UMEM_TOTAL_SIZE, umem_area_);
        } else {
            printf("[UMEM] Allocated %zu bytes at %p (huge pages, low VA)\n", UMEM_TOTAL_SIZE, umem_area_);
        }

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
        g_conn_state = conn_state_;

        // Resolve echo server IP
        struct in_addr addr;
        if (inet_pton(AF_INET, echo_host_, &addr) == 1) {
            conn_state_->exchange_ips[0] = addr.s_addr;
            conn_state_->exchange_ip_count = 1;
        } else {
            struct addrinfo hints = {};
            struct addrinfo* result = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            if (getaddrinfo(echo_host_, nullptr, &hints, &result) != 0 || !result) {
                fprintf(stderr, "FAIL: Cannot resolve %s\n", echo_host_);
                return false;
            }

            uint8_t count = 0;
            for (struct addrinfo* p = result; p && count < ConnStateShm::MAX_EXCHANGE_IPS; p = p->ai_next) {
                if (p->ai_family == AF_INET) {
                    auto* sa = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
                    conn_state_->exchange_ips[count] = sa->sin_addr.s_addr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sa->sin_addr, ip_str, sizeof(ip_str));
                    printf("[DNS] Resolved IP %u: %s\n", count, ip_str);
                    count++;
                }
            }
            conn_state_->exchange_ip_count = count;
            freeaddrinfo(result);

            if (count == 0) {
                fprintf(stderr, "FAIL: No IPv4 addresses resolved\n");
                return false;
            }
        }

        conn_state_->target_port = echo_port_;
        strncpy(conn_state_->interface_name, interface_, sizeof(conn_state_->interface_name) - 1);
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        // Pre-populate local IP from cached config (NIC bound to DPDK, no kernel interface)
        // MAC is populated by DPDKPollProcess::init() via rte_eth_macaddr_get()
        {
            char cache_path[128];
            snprintf(cache_path, sizeof(cache_path), "/tmp/dpdk_ip_%s", interface_);
            FILE* f = fopen(cache_path, "r");
            if (f) {
                char ip_str[32];
                if (fgets(ip_str, sizeof(ip_str), f)) {
                    ip_str[strcspn(ip_str, "\n")] = '\0';
                    struct in_addr a;
                    if (inet_pton(AF_INET, ip_str, &a) == 1) {
                        conn_state_->local_ip = a.s_addr;  // network byte order
                        printf("[DPDK] Loaded cached local IP: %s\n", ip_str);
                    }
                }
                fclose(f);
            }
            if (conn_state_->local_ip == 0) {
                fprintf(stderr, "WARN: No cached IP for %s. Run: ./scripts/dpdk_bind.sh %s\n",
                        interface_, interface_);
            }
        }

        try {
            raw_inbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_inbox"));
            raw_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_outbox"));
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

        if (dpdk_poll_pid_ > 0) {
            kill(dpdk_poll_pid_, SIGTERM);
            waitpid(dpdk_poll_pid_, nullptr, 0);
        }

        delete raw_inbox_region_;
        delete raw_outbox_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED)
            munmap(conn_state_, sizeof(ConnStateShm));
        if (umem_area_ && umem_area_ != MAP_FAILED)
            munmap(umem_area_, UMEM_TOTAL_SIZE);

        printf("=== Teardown Complete ===\n");
    }

    bool fork_dpdk_poll() {
        dpdk_poll_pid_ = fork();
        if (dpdk_poll_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for DPDK Poll failed\n");
            return false;
        }

        if (dpdk_poll_pid_ == 0) {
            run_dpdk_poll_process();
            _exit(0);
        }

        printf("[PARENT] Forked DPDK Poll process (PID %d) on core %d\n",
               dpdk_poll_pid_, DPDK_POLL_CPU_CORE);

        printf("[PARENT] Waiting for DPDK to be ready...\n");
        if (!conn_state_->wait_for_handshake_xdp_ready(10000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for DPDK ready\n");
            return false;
        }
        printf("[PARENT] DPDK ready\n");

        return true;
    }

    bool run_tcp_echo_test() {
        printf("\n--- TCP Echo Test (max %d msgs, send timeout %ds, drain %ds) ---\n",
               MAX_MESSAGES, SEND_TIMEOUT_SECONDS, RECV_DRAIN_SECONDS);

        pin_to_cpu(TEST_CPU_CORE);

        IPCRingConsumer<PacketFrameDescriptor> raw_inbox_cons(*raw_inbox_region_);
        IPCRingProducer<PacketFrameDescriptor> raw_outbox_prod(*raw_outbox_region_);

        DisruptorPacketIOConfig pio_config;
        pio_config.umem_area = umem_area_;
        pio_config.frame_size = FRAME_SIZE;
        pio_config.raw_inbox_cons = &raw_inbox_cons;
        pio_config.raw_outbox_prod = &raw_outbox_prod;
        pio_config.conn_state = conn_state_;

        transport_.init_with_pio_config(pio_config);
        transport_.add_exchange_port(echo_port_);

        printf("[TEST] Connecting to %s:%u via userspace TCP (DisruptorPacketIO + DPDK)...\n",
               echo_host_, echo_port_);
        try {
            transport_.connect(echo_host_, echo_port_);
        } catch (const std::exception& e) {
            fprintf(stderr, "[TEST] Connection failed: %s\n", e.what());
            return false;
        }
        printf("[TEST] Connected!\n");

        int sent = 0;
        int received = 0;
        char send_buf[64];
        char recv_buf[1024];

        auto start = std::chrono::steady_clock::now();
        auto send_deadline = start + std::chrono::seconds(SEND_TIMEOUT_SECONDS);
        bool sending_done = false;

        while (!sending_done || received < sent) {
            auto now = std::chrono::steady_clock::now();

            if (!sending_done) {
                if (sent >= MAX_MESSAGES) {
                    sending_done = true;
                    printf("[TEST] All %d messages sent, waiting %ds for responses...\n",
                           sent, RECV_DRAIN_SECONDS);
                } else if (now >= send_deadline) {
                    sending_done = true;
                    printf("[TEST] Send timeout, sent %d/%d\n", sent, MAX_MESSAGES);
                }
            }

            if (sending_done) {
                auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(RECV_DRAIN_SECONDS);
                while (received < sent && std::chrono::steady_clock::now() < drain_deadline) {
                    if (g_shutdown.load(std::memory_order_acquire)) break;
                    transport_.poll();
                    ssize_t n = transport_.recv(recv_buf, sizeof(recv_buf) - 1);
                    if (n > 0) {
                        recv_buf[n] = '\0';
                        for (char* p = recv_buf; (p = strstr(p, "MSG_")) != nullptr; p += 4)
                            received++;
                    }
                    usleep(100);
                }
                break;
            }

            if (g_shutdown.load(std::memory_order_acquire)) break;

            transport_.poll();

            if (sent < MAX_MESSAGES) {
                snprintf(send_buf, sizeof(send_buf), "MSG_%04d\n", sent);
                ssize_t n = transport_.send(send_buf, strlen(send_buf));
                if (n > 0) {
                    if (sent % 100 == 0)
                        printf("[TX] MSG_%04d | RX=%d\n", sent, received);
                    sent++;

                    if (g_tx_throttle_cycles > 0) {
                        uint64_t start_cycle = rdtsc();
                        while (rdtsc() - start_cycle < g_tx_throttle_cycles)
                            __builtin_ia32_pause();
                    }
                }
            }

            ssize_t n = transport_.recv(recv_buf, sizeof(recv_buf) - 1);
            if (n > 0) {
                recv_buf[n] = '\0';
                for (char* p = recv_buf; (p = strstr(p, "MSG_")) != nullptr; p += 4)
                    received++;
            }

            usleep(100);
        }

        auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();

        printf("\n=== Test Results ===\n");
        printf("  Duration:  %ld ms\n", total_time);
        printf("  Sent:      %d messages\n", sent);
        printf("  Received:  %d messages\n", received);

        int64_t raw_inbox_prod = raw_inbox_region_->producer_published()->load(std::memory_order_acquire);
        int64_t raw_inbox_cons_seq = raw_inbox_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        printf("  RAW_INBOX  producer: %ld, consumer: %ld\n", raw_inbox_prod, raw_inbox_cons_seq);

        int64_t raw_outbox_prod_seq = raw_outbox_region_->producer_published()->load(std::memory_order_acquire);
        int64_t raw_outbox_cons_seq = raw_outbox_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        printf("  RAW_OUTBOX producer: %ld, consumer: %ld\n", raw_outbox_prod_seq, raw_outbox_cons_seq);
        printf("====================\n");
        fflush(stdout);

        transport_.print_rx_debug_stats();
        transport_.close();

        conn_state_->shutdown_all();
        if (dpdk_poll_pid_ > 0) {
            waitpid(dpdk_poll_pid_, nullptr, 0);
            dpdk_poll_pid_ = 0;
        }

        if (received == 0) {
            printf("\nFAIL: No echo responses received\n");
            return false;
        }
        if (received != sent) {
            printf("\nWARN: Only %d/%d messages received\n", received, sent);
        }
        printf("\nPASS: Received %d/%d echo responses\n", received, sent);
        return received > 0;
    }

private:
    void run_dpdk_poll_process() {
        pin_to_cpu(DPDK_POLL_CPU_CORE);

        IPCRingProducer<PacketFrameDescriptor> raw_inbox_prod(*raw_inbox_region_);
        IPCRingConsumer<PacketFrameDescriptor> raw_outbox_cons(*raw_outbox_region_);

        DPDKPollType dpdk_poll(interface_);

        if (!dpdk_poll.init(umem_area_, UMEM_TOTAL_SIZE, nullptr,
                            &raw_inbox_prod, &raw_outbox_cons, conn_state_)) {
            fprintf(stderr, "[DPDK-POLL] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        printf("[DPDK-POLL] Initialized, running main loop\n");
        dpdk_poll.run();
        dpdk_poll.cleanup();
    }

    const char* interface_;
    const char* echo_host_;
    uint16_t echo_port_;

    IPCRingManager ipc_manager_;

    void* umem_area_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    disruptor::ipc::shared_region* raw_inbox_region_ = nullptr;
    disruptor::ipc::shared_region* raw_outbox_region_ = nullptr;

    pid_t dpdk_poll_pid_ = 0;

    PacketTransport<DisruptorPacketIO> transport_;
};

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [echo_host] [echo_port] [throttle_cycles]\n", argv[0]);
        fprintf(stderr, "\nPrerequisites:\n");
        fprintf(stderr, "  1. NIC bound to vfio-pci: ./scripts/dpdk_bind.sh <interface>\n");
        fprintf(stderr, "  2. Hugepages configured\n");
        fprintf(stderr, "  3. Run as root: sudo %s <interface>\n", argv[0]);
        return 1;
    }

    const char* interface = argv[1];
    const char* echo_host = (argc >= 3) ? argv[2] : "139.162.79.171";
    uint16_t echo_port = (argc >= 4) ? static_cast<uint16_t>(atoi(argv[3])) : 12345;

    if (argc >= 5) {
        g_tx_throttle_cycles = static_cast<uint64_t>(atoll(argv[4]));
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  DPDK DisruptorPacketIO TCP Test (2-Process)  \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (plain TCP)\n", echo_host, echo_port);
    printf("  DPDK Poll:  core %d\n", DPDK_POLL_CPU_CORE);
    printf("  Transport:  core %d (PacketTransport<DisruptorPacketIO>)\n", TEST_CPU_CORE);
    printf("  Messages:   up to %d\n", MAX_MESSAGES);
    printf("  Throttle:   %lu cycles\n", g_tx_throttle_cycles);
    printf("==============================================\n\n");

    DPDKDisruptorTCPTest test(interface, echo_host, echo_port);

    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    if (!test.fork_dpdk_poll()) {
        fprintf(stderr, "\nFATAL: Failed to fork DPDK Poll\n");
        test.teardown();
        return 1;
    }

    int result = 0;
    if (!test.run_tcp_echo_test()) {
        result = 1;
    }

    test.teardown();

    printf("\n==============================================\n");
    if (result == 0) {
        printf("  TEST PASSED\n");
    } else {
        printf("  TEST FAILED\n");
    }
    printf("==============================================\n");

    return result;
}

#else  // !USE_DPDK

int main() {
    fprintf(stderr, "Error: Build with USE_DPDK=1\n");
    fprintf(stderr, "Example: make build-test-pipeline-05_dpdk_disruptor_packetio_tcp USE_DPDK=1 DPDK_INTERFACE=enp108s0\n");
    return 1;
}

#endif  // USE_DPDK
