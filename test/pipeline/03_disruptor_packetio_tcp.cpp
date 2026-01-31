// test/pipeline/03_disruptor_packetio_tcp.cpp
// Test PacketTransport<DisruptorPacketIO> with plain TCP (no SSL) against echo server
//
// Architecture (2-process):
//   XDP Poll (core 2)                  Test / Transport (core 4)
//   ┌──────────────────┐               ┌──────────────────────────┐
//   │ AF_XDP ←→ NIC    │               │ PacketTransport          │
//   │                   │◄── RAW_OUTBOX │   <DisruptorPacketIO>    │
//   │                   │──► RAW_INBOX  │                          │
//   └──────────────────┘  (shared mem)  └──────────────────────────┘
//
// This test uses 2 processes:
//   - Child (core 2): XDPPollProcess — handles AF_XDP kernel interface
//   - Parent (core 4): PacketTransport<DisruptorPacketIO> — TCP echo test via IPC rings
//
// The DisruptorPacketIO delegates packet I/O to XDP Poll via shared UMEM and
// IPC Disruptor rings (RAW_INBOX for RX, RAW_OUTBOX for TX).
//
// Usage: ./test_pipeline_03_disruptor_packetio_tcp <interface> <bpf_path> <echo_ip> <echo_port> [throttle_cycles]
// (Called by scripts/build_xdp.sh 03_disruptor_packetio_tcp.cpp)
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
#define DEBUG_PIO 1
#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/00_xdp_poll_process.hpp"
#include "../../src/pipeline/disruptor_packet_io.hpp"
#include "../../src/policy/transport.hpp"

using namespace websocket::transport;
using namespace websocket::pipeline;
using websocket::xdp::PacketFrameDescriptor;

// ============================================================================
// Type Aliases
// ============================================================================

// XDP Poll Process type (no trickle for simple TCP test, no profiling)
using XDPPollType = XDPPollProcess<
    IPCRingProducer<PacketFrameDescriptor>,
    IPCRingConsumer<PacketFrameDescriptor>,
    true,        // TrickleEnabled
    false,       // Profiling
    256,         // FrameHeadroom
    FRAME_SIZE>; // FrameSize — from pipeline_config.hpp (4096 for MTU=1500)

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignments (2 processes)
constexpr int XDP_POLL_CPU_CORE = 2;     // XDP Poll process
constexpr int TEST_CPU_CORE = 4;         // Transport/Test process

// Test parameters
constexpr int MAX_MESSAGES = 500;
constexpr int SEND_TIMEOUT_SECONDS = 20;
constexpr int RECV_DRAIN_SECONDS = 3;

// TX throttle: cycles between sends (0 = no throttle)
static uint64_t g_tx_throttle_cycles = 0;

// Global shutdown flag and connection state pointer for signal handler
std::atomic<bool> g_shutdown{false};
ConnStateShm* g_conn_state = nullptr;

void signal_handler(int sig) {
    g_shutdown.store(true, std::memory_order_release);
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
    printf("[TSC] Calibrated: %.3f GHz\n", g_tsc_freq_ghz);
}

}  // namespace

// ============================================================================
// IPC Ring Creation (simplified — only RAW_INBOX + RAW_OUTBOX)
// ============================================================================

class IPCRingManager {
public:
    IPCRingManager() {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string("disruptor_03_test_") + timestamp;
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

        // Only 2 rings: RAW_INBOX + RAW_OUTBOX (unified TX via RAW_OUTBOX)
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

class DisruptorPacketIOTCPTest {
public:
    DisruptorPacketIOTCPTest(const char* interface, const char* bpf_path,
                              const char* echo_host, uint16_t echo_port)
        : interface_(interface), bpf_path_(bpf_path),
          echo_host_(echo_host), echo_port_(echo_port) {}

    bool setup() {
        printf("\n=== Setting up DisruptorPacketIO TCP Test (2-Process) ===\n");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);
        printf("Echo Server: %s:%u\n\n", echo_host_, echo_port_);

        calibrate_tsc();

        // Create IPC rings
        if (!ipc_manager_.create_all_rings()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        // Allocate UMEM (shared between XDP Poll and Transport)
        umem_area_ = mmap(nullptr, UMEM_TOTAL_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB,
                          -1, 0);
        if (umem_area_ == MAP_FAILED) {
            // Fall back to regular pages
            umem_area_ = mmap(nullptr, UMEM_TOTAL_SIZE,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS,
                              -1, 0);
            if (umem_area_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate UMEM\n");
                return false;
            }
            printf("[UMEM] Allocated %zu bytes (regular pages)\n", UMEM_TOTAL_SIZE);
        } else {
            printf("[UMEM] Allocated %zu bytes (huge pages)\n", UMEM_TOTAL_SIZE);
        }

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
        g_conn_state = conn_state_;

        // Store echo server IP in exchange_ips for BPF filter
        struct in_addr addr;
        if (inet_pton(AF_INET, echo_host_, &addr) == 1) {
            conn_state_->exchange_ips[0] = addr.s_addr;
            conn_state_->exchange_ip_count = 1;
            printf("[DNS] Echo server IP: %s\n", echo_host_);
        } else {
            // Try DNS resolution
            struct addrinfo hints = {};
            struct addrinfo* result = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            int ret = getaddrinfo(echo_host_, nullptr, &hints, &result);
            if (ret != 0 || !result) {
                fprintf(stderr, "FAIL: Cannot resolve %s\n", echo_host_);
                if (result) freeaddrinfo(result);
                return false;
            }

            uint8_t count = 0;
            for (struct addrinfo* p = result; p != nullptr && count < ConnStateShm::MAX_EXCHANGE_IPS; p = p->ai_next) {
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
                fprintf(stderr, "FAIL: No IPv4 addresses resolved for %s\n", echo_host_);
                return false;
            }
        }

        conn_state_->target_port = echo_port_;
        strncpy(conn_state_->interface_name, interface_, sizeof(conn_state_->interface_name) - 1);
        strncpy(conn_state_->bpf_path, bpf_path_, sizeof(conn_state_->bpf_path) - 1);
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        // Open shared regions
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

        // Wait for child process
        if (xdp_poll_pid_ > 0) {
            kill(xdp_poll_pid_, SIGTERM);
            waitpid(xdp_poll_pid_, nullptr, 0);
        }

        // Cleanup shared regions
        delete raw_inbox_region_;
        delete raw_outbox_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED) {
            munmap(conn_state_, sizeof(ConnStateShm));
        }
        if (umem_area_ && umem_area_ != MAP_FAILED) {
            munmap(umem_area_, UMEM_TOTAL_SIZE);
        }

        printf("=== Teardown Complete ===\n");
    }

    bool fork_xdp_poll() {
        // Fork XDP Poll process (Core 2)
        xdp_poll_pid_ = fork();
        if (xdp_poll_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for XDP Poll failed\n");
            return false;
        }

        if (xdp_poll_pid_ == 0) {
            // Child: XDP Poll process
            run_xdp_poll_process();
            _exit(0);
        }

        printf("[PARENT] Forked XDP Poll process (PID %d) on core %d\n",
               xdp_poll_pid_, XDP_POLL_CPU_CORE);

        // Wait for XDP to be ready
        printf("[PARENT] Waiting for XDP to be ready...\n");
        if (!conn_state_->wait_for_handshake_xdp_ready(10000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for XDP ready\n");
            return false;
        }
        printf("[PARENT] XDP ready\n");

        return true;
    }

    bool run_tcp_echo_test() {
        printf("\n--- TCP Echo Test (max %d msgs, send timeout %ds, drain %ds) ---\n",
               MAX_MESSAGES, SEND_TIMEOUT_SECONDS, RECV_DRAIN_SECONDS);

        pin_to_cpu(TEST_CPU_CORE);

        // Initialize DisruptorPacketIO via transport
        IPCRingConsumer<PacketFrameDescriptor> raw_inbox_cons(*raw_inbox_region_);
        IPCRingProducer<PacketFrameDescriptor> raw_outbox_prod(*raw_outbox_region_);

        DisruptorPacketIOConfig pio_config;
        pio_config.umem_area = umem_area_;
        pio_config.frame_size = FRAME_SIZE;
        pio_config.raw_inbox_cons = &raw_inbox_cons;
        pio_config.raw_outbox_prod = &raw_outbox_prod;
        pio_config.conn_state = conn_state_;

        transport_.init_with_pio_config(pio_config);

        // Add echo server port to BPF filter
        transport_.add_exchange_port(echo_port_);

        // TCP connect
        printf("[TEST] Connecting to %s:%u via userspace TCP (DisruptorPacketIO)...\n",
               echo_host_, echo_port_);
        try {
            transport_.connect(echo_host_, echo_port_);
        } catch (const std::exception& e) {
            fprintf(stderr, "[TEST] Connection failed: %s\n", e.what());
            return false;
        }
        printf("[TEST] Connected!\n");

        // Send/receive loop
        int sent = 0;
        int received = 0;
        char send_buf[64];
        char recv_buf[1024];

        auto start = std::chrono::steady_clock::now();
        auto send_deadline = start + std::chrono::seconds(SEND_TIMEOUT_SECONDS);
        bool sending_done = false;

        // Phase 1: Send messages (with concurrent receive)
        while (!sending_done || received < sent) {
            auto now = std::chrono::steady_clock::now();

            // Check if sending phase is done
            if (!sending_done) {
                if (sent >= MAX_MESSAGES) {
                    sending_done = true;
                    printf("[TEST] All %d messages sent, waiting %ds for responses...\n",
                           sent, RECV_DRAIN_SECONDS);
                } else if (now >= send_deadline) {
                    sending_done = true;
                    printf("[TEST] Send timeout after %ds, sent %d/%d, waiting %ds for responses...\n",
                           SEND_TIMEOUT_SECONDS, sent, MAX_MESSAGES, RECV_DRAIN_SECONDS);
                }
            }

            // Phase 2: Drain - wait for remaining responses
            if (sending_done) {
                auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(RECV_DRAIN_SECONDS);
                while (received < sent && std::chrono::steady_clock::now() < drain_deadline) {
                    if (g_shutdown.load(std::memory_order_acquire)) break;

                    transport_.poll();
                    ssize_t n = transport_.recv(recv_buf, sizeof(recv_buf) - 1);
                    if (n > 0) {
                        recv_buf[n] = '\0';
                        for (char* p = recv_buf; (p = strstr(p, "MSG_")) != nullptr; p += 4) {
                            received++;
                        }
                    }
                    usleep(100);
                }
                break;  // Exit main loop after drain
            }

            // Check for shutdown
            if (g_shutdown.load(std::memory_order_acquire)) {
                printf("[TEST] Shutdown signal received\n");
                break;
            }

            // Poll transport for incoming data
            transport_.poll();

            // Send next message with optional CPU cycle throttle
            if (sent < MAX_MESSAGES) {
                snprintf(send_buf, sizeof(send_buf), "MSG_%04d\n", sent);
                ssize_t n = transport_.send(send_buf, strlen(send_buf));
                if (n > 0) {
                    if (sent % 100 == 0) {
                        printf("[TX] MSG_%04d | RX=%d\n", sent, received);
                    }
                    sent++;

                    // CPU cycle throttle
                    if (g_tx_throttle_cycles > 0) {
                        uint64_t start_cycle = rdtsc();
                        while (rdtsc() - start_cycle < g_tx_throttle_cycles) {
                            __builtin_ia32_pause();
                        }
                    }
                }
            }

            // Try to receive
            ssize_t n = transport_.recv(recv_buf, sizeof(recv_buf) - 1);
            if (n > 0) {
                recv_buf[n] = '\0';
                for (char* p = recv_buf; (p = strstr(p, "MSG_")) != nullptr; p += 4) {
                    received++;
                }
                if (received % 100 == 0) {
                    printf("[RX] Received %d messages so far\n", received);
                }
            }

            usleep(100);
        }

        auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();

        printf("\n=== Test Results ===\n");
        printf("  Duration:  %ld ms\n", total_time);
        printf("  Sent:      %d messages\n", sent);
        printf("  Received:  %d messages\n", received);

        // Ring status
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

        // Signal XDP Poll to stop
        conn_state_->shutdown_all();
        if (xdp_poll_pid_ > 0) {
            waitpid(xdp_poll_pid_, nullptr, 0);
            xdp_poll_pid_ = 0;
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

    ConnStateShm* get_conn_state() const { return conn_state_; }

private:
    // XDP Poll child process
    void run_xdp_poll_process() {
        pin_to_cpu(XDP_POLL_CPU_CORE);

        // Create ring adapters
        IPCRingProducer<PacketFrameDescriptor> raw_inbox_prod(*raw_inbox_region_);
        IPCRingConsumer<PacketFrameDescriptor> raw_outbox_cons(*raw_outbox_region_);

        XDPPollType xdp_poll(interface_);

        if (!xdp_poll.init(umem_area_, UMEM_TOTAL_SIZE,
                           bpf_path_,
                           &raw_inbox_prod,
                           &raw_outbox_cons,
                           conn_state_)) {
            fprintf(stderr, "[XDP-POLL] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        printf("[XDP-POLL] Initialized, running main loop\n");
        xdp_poll.run();
        xdp_poll.cleanup();
    }

    const char* interface_;
    const char* bpf_path_;
    const char* echo_host_;
    uint16_t echo_port_;

    IPCRingManager ipc_manager_;

    void* umem_area_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    disruptor::ipc::shared_region* raw_inbox_region_ = nullptr;
    disruptor::ipc::shared_region* raw_outbox_region_ = nullptr;

    pid_t xdp_poll_pid_ = 0;

    PacketTransport<DisruptorPacketIO> transport_;
};

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [echo_host] [echo_port] [throttle_cycles]\n", argv[0]);
        fprintf(stderr, "NOTE: Do NOT run directly. Use: ./scripts/build_xdp.sh 03_disruptor_packetio_tcp.cpp\n");
        fprintf(stderr, "\nThis test:\n");
        fprintf(stderr, "  - Uses PacketTransport<DisruptorPacketIO> (2-process)\n");
        fprintf(stderr, "  - XDP Poll (core %d): AF_XDP kernel interface\n", XDP_POLL_CPU_CORE);
        fprintf(stderr, "  - Transport (core %d): TCP echo via IPC rings\n", TEST_CPU_CORE);
        fprintf(stderr, "  - Sends up to %d messages\n", MAX_MESSAGES);
        fprintf(stderr, "  - Send timeout: %d seconds\n", SEND_TIMEOUT_SECONDS);
        fprintf(stderr, "  - Drain timeout: %d second(s)\n", RECV_DRAIN_SECONDS);
        fprintf(stderr, "\nThrottle cycles (optional 5th arg):\n");
        fprintf(stderr, "  - 0 = no throttle (default)\n");
        fprintf(stderr, "  - 100 = ~42ns between sends @ 2.4GHz\n");
        fprintf(stderr, "  - 1000 = ~417ns between sends\n");
        fprintf(stderr, "  - 10000 = ~4.2us between sends\n");
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];
    const char* echo_host = (argc >= 4) ? argv[3] : "139.162.79.171";
    uint16_t echo_port = (argc >= 5) ? static_cast<uint16_t>(atoi(argv[4])) : 12345;

    // Optional throttle cycles
    if (argc >= 6) {
        g_tx_throttle_cycles = static_cast<uint64_t>(atoll(argv[5]));
    }

    if (geteuid() == 0) {
        fprintf(stderr, "ERROR: Do NOT run as root! Use: ./scripts/build_xdp.sh 03_disruptor_packetio_tcp.cpp\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  DisruptorPacketIO TCP Test (2-Process)       \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (plain TCP)\n", echo_host, echo_port);
    printf("  XDP Poll:   core %d\n", XDP_POLL_CPU_CORE);
    printf("  Transport:  core %d (PacketTransport<DisruptorPacketIO>)\n", TEST_CPU_CORE);
    printf("  Messages:   up to %d\n", MAX_MESSAGES);
    printf("  Send:       %d seconds\n", SEND_TIMEOUT_SECONDS);
    printf("  Drain:      %d second(s)\n", RECV_DRAIN_SECONDS);
    printf("  Throttle:   %lu cycles", g_tx_throttle_cycles);
    if (g_tx_throttle_cycles > 0 && g_tsc_freq_ghz > 0) {
        double ns = static_cast<double>(g_tx_throttle_cycles) / g_tsc_freq_ghz;
        printf(" (~%.0fns)", ns);
    }
    printf("\n");
    printf("==============================================\n\n");

    DisruptorPacketIOTCPTest test(interface, bpf_path, echo_host, echo_port);

    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    // Fork XDP Poll child process
    if (!test.fork_xdp_poll()) {
        fprintf(stderr, "\nFATAL: Failed to fork XDP Poll\n");
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

#else  // !USE_XDP

int main() {
    fprintf(stderr, "Error: Build with USE_XDP=1\n");
    fprintf(stderr, "Example: ./scripts/build_xdp.sh 03_disruptor_packetio_tcp.cpp\n");
    return 1;
}

#endif  // USE_XDP
