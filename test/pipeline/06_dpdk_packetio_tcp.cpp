// test/pipeline/06_dpdk_packetio_tcp.cpp
// Test PacketTransport<DPDKPacketIO> with plain TCP (no SSL) against echo server
//
// Architecture (single-process):
//   ┌──────────────────────────────────────────┐
//   │  Test Process (Core 4)                   │
//   │                                          │
//   │  PacketTransport<DPDKPacketIO>           │
//   │       │                                  │
//   │       └── DPDK PMD → NIC                │
//   │              ↓                           │
//   │          Echo Server Test                │
//   └──────────────────────────────────────────┘
//
// This test uses the single-process DPDKPacketIO path (no fork, no IPC rings).
// PacketTransport handles TCP state machine, DPDKPacketIO handles DPDK PMD I/O.
//
// Usage: ./test_pipeline_06_dpdk_packetio_tcp <interface> <echo_ip> <echo_port> [throttle_cycles]
// (Called by scripts/build_dpdk.sh 06_dpdk_packetio_tcp.cpp)
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
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#ifdef USE_DPDK

#define DEBUG 0
#define DEBUG_PIO 1

#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/dpdk_packet_io.hpp"
#include "../../src/policy/transport.hpp"

#include <sys/mman.h>
#include <netdb.h>

using namespace websocket::transport;

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignment
constexpr int TEST_CPU_CORE = 4;

// Test parameters
constexpr int MAX_MESSAGES = 500;
constexpr int SEND_TIMEOUT_SECONDS = 20;
constexpr int RECV_DRAIN_SECONDS = 3;

// TX throttle: cycles between sends (0 = no throttle)
static uint64_t g_tx_throttle_cycles = 0;

// Global shutdown flag
std::atomic<bool> g_shutdown{false};

void signal_handler(int sig) {
    g_shutdown.store(true, std::memory_order_release);
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
// Test Class
// ============================================================================

class DPDKPacketIOTCPTest {
public:
    DPDKPacketIOTCPTest(const char* interface,
                         const char* echo_host, uint16_t echo_port)
        : interface_(interface),
          echo_host_(echo_host), echo_port_(echo_port) {}

    ~DPDKPacketIOTCPTest() {
        if (conn_state_ && conn_state_ != MAP_FAILED)
            munmap(conn_state_, sizeof(websocket::pipeline::ConnStateShm));
    }

    bool setup() {
        printf("\n=== Setting up DPDKPacketIO TCP Test (Single-Process) ===\n");
        printf("Interface:   %s\n", interface_);
        printf("Echo Server: %s:%u\n\n", echo_host_, echo_port_);

        calibrate_tsc();

        // Allocate ConnStateShm for cached IP/MAC config
        // (NIC is bound to vfio-pci, kernel interface is gone)
        conn_state_ = static_cast<websocket::pipeline::ConnStateShm*>(
            mmap(nullptr, sizeof(websocket::pipeline::ConnStateShm),
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0));
        if (conn_state_ == MAP_FAILED) {
            fprintf(stderr, "FAIL: Cannot allocate ConnStateShm\n");
            return false;
        }
        conn_state_->init();
        strncpy(conn_state_->interface_name, interface_,
                sizeof(conn_state_->interface_name) - 1);
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        // Load cached local IP from /tmp/dpdk_ip_<interface>
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
                        conn_state_->local_ip = a.s_addr;
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

        // Load cached MAC from /tmp/dpdk_mac_<interface>
        {
            char cache_path[128];
            snprintf(cache_path, sizeof(cache_path), "/tmp/dpdk_mac_%s", interface_);
            FILE* f = fopen(cache_path, "r");
            if (f) {
                char mac_str[32];
                if (fgets(mac_str, sizeof(mac_str), f)) {
                    mac_str[strcspn(mac_str, "\n")] = '\0';
                    unsigned int m[6];
                    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                        for (int i = 0; i < 6; i++)
                            conn_state_->local_mac[i] = static_cast<uint8_t>(m[i]);
                        printf("[DPDK] Loaded cached MAC: %s\n", mac_str);
                    }
                }
                fclose(f);
            }
        }

        // Resolve echo server IP for exchange filter
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
            for (struct addrinfo* p = result; p && count < websocket::pipeline::ConnStateShm::MAX_EXCHANGE_IPS; p = p->ai_next) {
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

        // Initialize transport with DPDKPacketIOConfig
        try {
            websocket::pipeline::DPDKPacketIOConfig pio_config;
            pio_config.interface = interface_;
            pio_config.conn_state = conn_state_;
            // umem_area = nullptr → DPDKPacketIO self-allocates at DPDK_UMEM_BASE_VA
            transport_.init_with_pio_config(pio_config);
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Transport init failed: %s\n", e.what());
            return false;
        }

        // Add echo server IP and port to userspace filter
        transport_.add_exchange_ip(echo_host_);
        transport_.add_exchange_port(echo_port_);

        printf("=== Setup Complete ===\n\n");
        return true;
    }

    void teardown() {
        printf("\n=== Teardown ===\n");
        g_shutdown.store(true);
        transport_.close();
        printf("=== Teardown Complete ===\n");
    }

    bool run_tcp_echo_test() {
        printf("\n--- TCP Echo Test (max %d msgs, send timeout %ds, drain %ds) ---\n",
               MAX_MESSAGES, SEND_TIMEOUT_SECONDS, RECV_DRAIN_SECONDS);

        pin_to_cpu(TEST_CPU_CORE);

        // TCP connect
        printf("[TEST] Connecting to %s:%u via userspace TCP (DPDKPacketIO)...\n", echo_host_, echo_port_);
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

        // Raw inbox: accumulate all received bytes for post-test dump
        static constexpr size_t RAW_INBOX_CAP = MAX_MESSAGES * 16;
        char raw_inbox[RAW_INBOX_CAP];
        size_t raw_inbox_len = 0;

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
                        if (raw_inbox_len + n < RAW_INBOX_CAP) {
                            memcpy(raw_inbox + raw_inbox_len, recv_buf, n);
                            raw_inbox_len += n;
                        }
                        for (char* p = recv_buf; (p = strstr(p, "MSG_")) != nullptr; p += 4) {
                            received++;
                        }
                    }
                    usleep(100);
                }
                break;
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
                if (raw_inbox_len + n < RAW_INBOX_CAP) {
                    memcpy(raw_inbox + raw_inbox_len, recv_buf, n);
                    raw_inbox_len += n;
                }
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
        printf("====================\n");

        // Dump raw inbox
        raw_inbox[raw_inbox_len] = '\0';
        printf("\n=== RAW INBOX (%zu bytes) ===\n", raw_inbox_len);
        fwrite(raw_inbox, 1, raw_inbox_len, stdout);
        printf("\n=== END RAW INBOX ===\n");

        // Re-count from contiguous raw inbox
        int recount = 0;
        for (char* p = raw_inbox; (p = strstr(p, "MSG_")) != nullptr; p += 4) {
            recount++;
        }
        printf("  strstr recount from raw inbox: %d\n", recount);
        fflush(stdout);

        transport_.close();

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
    const char* interface_;
    const char* echo_host_;
    uint16_t echo_port_;

    websocket::pipeline::ConnStateShm* conn_state_ = nullptr;
    PacketTransport<websocket::pipeline::DPDKPacketIO> transport_;
};

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [echo_host] [echo_port] [throttle_cycles]\n", argv[0]);
        fprintf(stderr, "NOTE: Build with: ./scripts/build_dpdk.sh 06_dpdk_packetio_tcp.cpp\n");
        fprintf(stderr, "\nThis test:\n");
        fprintf(stderr, "  - Uses PacketTransport<DPDKPacketIO> (core %d)\n", TEST_CPU_CORE);
        fprintf(stderr, "  - Single-process DPDK (no fork, no IPC rings)\n");
        fprintf(stderr, "  - Connects to TCP echo server (no SSL)\n");
        fprintf(stderr, "  - Sends up to %d messages\n", MAX_MESSAGES);
        fprintf(stderr, "  - Send timeout: %d seconds\n", SEND_TIMEOUT_SECONDS);
        fprintf(stderr, "  - Drain timeout: %d second(s)\n", RECV_DRAIN_SECONDS);
        fprintf(stderr, "\nThrottle cycles (optional 4th arg):\n");
        fprintf(stderr, "  - 0 = no throttle (default)\n");
        fprintf(stderr, "  - 100 = ~42ns between sends @ 2.4GHz\n");
        fprintf(stderr, "  - 1000 = ~417ns between sends\n");
        fprintf(stderr, "  - 10000 = ~4.2us between sends\n");
        fprintf(stderr, "\nArchitecture (single-process):\n");
        fprintf(stderr, "  - PacketTransport<DPDKPacketIO> (core %d): DPDK PMD + userspace TCP\n", TEST_CPU_CORE);
        return 1;
    }

    const char* interface = argv[1];
    const char* echo_host = (argc >= 3) ? argv[2] : "139.162.79.171";
    uint16_t echo_port = (argc >= 4) ? static_cast<uint16_t>(atoi(argv[3])) : 12345;

    // Optional throttle cycles
    if (argc >= 5) {
        g_tx_throttle_cycles = static_cast<uint64_t>(atoll(argv[4]));
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  DPDKPacketIO TCP Test (Single-Process)      \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (plain TCP)\n", echo_host, echo_port);
    printf("  Process:    PacketTransport<DPDKPacketIO> (core %d)\n", TEST_CPU_CORE);
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

    DPDKPacketIOTCPTest test(interface, echo_host, echo_port);

    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
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
    fprintf(stderr, "Example: ./scripts/build_dpdk.sh 06_dpdk_packetio_tcp.cpp\n");
    return 1;
}

#endif  // USE_DPDK
