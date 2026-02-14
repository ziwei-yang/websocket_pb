// test/pipeline/110_bsd_transport_tcp.cpp
// Test BSDSocketTransportProcess<NoSSLPolicy> against TCP echo server
//
// Usage:
//   ./test_pipeline_bsd_transport_tcp                    # localhost echo (default)
//   ./test_pipeline_bsd_transport_tcp localhost          # localhost echo server
//   ./test_pipeline_bsd_transport_tcp <ip> <port>        # remote echo server
//
// This test:
// - Creates IPC rings (MSG_OUTBOX, MSG_METADATA, PONGS)
// - Optionally starts a localhost TCP echo server
// - Forks BSDSocketTransportProcess (2-thread: RX + TX)
// - Sends messages with embedded timestamps via MSG_OUTBOX
// - Measures FULL round-trip latency (send → echo → receive)
// - Also measures recv syscall latency
//
// Unlike XDP transport test, this test:
// - Does NOT require XDP/BPF
// - Does NOT require special permissions
// - Uses standard BSD sockets with kernel TCP

// pipeline_data.hpp must be included FIRST as it includes disruptor headers
// before pipeline_config.hpp to avoid CACHE_LINE_SIZE and TCP_MSS macro conflicts
#include "../../src/pipeline/pipeline_data.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include "../../src/pipeline/11_bsd_tcp_ssl_process.hpp"
#include "../../src/pipeline/msg_inbox.hpp"
#include "../../src/policy/ssl.hpp"  // NoSSLPolicy

using namespace websocket::pipeline;

// ============================================================================
// Configuration
// ============================================================================

namespace {

// Test parameters
constexpr int MAX_MESSAGES = 5000;                         // Max messages to send
constexpr int TIMEOUT_SECONDS = 10;                        // Total timeout
constexpr int SEND_INTERVAL_MS = 1;                        // Send every 1ms
constexpr uint16_t LOCALHOST_ECHO_PORT = 19345;            // Port for localhost echo server

// Message format: "<16-hex-tsc>:<msg_id>" for RTT measurement
// Example: "0000123456789abc:TEST_MSG_0001"
constexpr size_t TSC_HEX_LEN = 16;
constexpr size_t MSG_PREFIX_LEN = TSC_HEX_LEN + 1;  // tsc + ':'

// Global shutdown flag
std::atomic<bool> g_shutdown{false};

void signal_handler(int) {
    g_shutdown.store(true, std::memory_order_release);
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

// Parse hex TSC from message prefix
uint64_t parse_tsc_hex(const char* hex_str) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        char c = hex_str[i];
        uint64_t digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return 0;  // Invalid
        result = (result << 4) | digit;
    }
    return result;
}

// ============================================================================
// Localhost TCP Echo Server
// ============================================================================

class LocalhostEchoServer {
public:
    LocalhostEchoServer() = default;
    ~LocalhostEchoServer() { stop(); }

    bool start(uint16_t port) {
        port_ = port;

        // Create socket
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) {
            perror("[EchoServer] socket");
            return false;
        }

        // Set SO_REUSEADDR
        int opt = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        // Bind
        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            perror("[EchoServer] bind");
            close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        // Listen
        if (listen(listen_fd_, 1) < 0) {
            perror("[EchoServer] listen");
            close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        // Start server thread
        running_.store(true, std::memory_order_release);
        server_thread_ = std::thread([this]() { run(); });

        printf("[EchoServer] Listening on 127.0.0.1:%u\n", port);
        return true;
    }

    void stop() {
        running_.store(false, std::memory_order_release);

        if (listen_fd_ >= 0) {
            shutdown(listen_fd_, SHUT_RDWR);
            close(listen_fd_);
            listen_fd_ = -1;
        }

        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

private:
    void run() {
        while (running_.load(std::memory_order_acquire)) {
            // Poll for incoming connection
            struct pollfd pfd = { listen_fd_, POLLIN, 0 };
            int ret = poll(&pfd, 1, 100);  // 100ms timeout

            if (ret <= 0) continue;

            // Accept connection
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(listen_fd_, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);

            if (client_fd < 0) {
                if (running_.load(std::memory_order_acquire)) {
                    perror("[EchoServer] accept");
                }
                continue;
            }

            printf("[EchoServer] Client connected\n");

            // Set TCP_NODELAY for low latency
            int flag = 1;
            setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

            // Echo loop
            char buf[4096];
            while (running_.load(std::memory_order_acquire)) {
                struct pollfd cpfd = { client_fd, POLLIN, 0 };
                ret = poll(&cpfd, 1, 100);

                if (ret < 0) break;
                if (ret == 0) continue;

                if (cpfd.revents & (POLLERR | POLLHUP)) {
                    break;
                }

                ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
                if (n <= 0) break;

                // Echo back immediately
                ssize_t sent = 0;
                while (sent < n) {
                    ssize_t s = send(client_fd, buf + sent, n - sent, 0);
                    if (s <= 0) break;
                    sent += s;
                }
            }

            close(client_fd);
            printf("[EchoServer] Client disconnected\n");
        }
    }

    int listen_fd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::thread server_thread_;
};

// ============================================================================
// Latency Statistics
// ============================================================================

struct LatencyStats {
    int64_t min_ns = INT64_MAX;
    int64_t max_ns = INT64_MIN;
    int64_t sum_ns = 0;
    uint64_t count = 0;

    // Histogram buckets (in microseconds)
    static constexpr int NUM_BUCKETS = 10;
    uint64_t histogram[NUM_BUCKETS] = {};

    int get_bucket(int64_t latency_ns) const {
        int64_t us = latency_ns / 1000;
        if (us < 10) return 0;    // <10us
        if (us < 20) return 1;    // 10-20us
        if (us < 50) return 2;    // 20-50us
        if (us < 100) return 3;   // 50-100us
        if (us < 200) return 4;   // 100-200us
        if (us < 500) return 5;   // 200-500us
        if (us < 1000) return 6;  // 500us-1ms
        if (us < 5000) return 7;  // 1-5ms
        if (us < 10000) return 8; // 5-10ms
        return 9;                 // 10ms+
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
            printf("\n=== %s ===\n", name);
            printf("No samples\n");
            printf("=====================================\n\n");
            return;
        }

        int64_t avg_ns = sum_ns / static_cast<int64_t>(count);

        printf("\n=== %s ===\n", name);
        printf("  Samples:    %llu\n", static_cast<unsigned long long>(count));
        printf("  Min:        %lld ns (%.3f us)\n", static_cast<long long>(min_ns), min_ns / 1000.0);
        printf("  Max:        %lld ns (%.3f us)\n", static_cast<long long>(max_ns), max_ns / 1000.0);
        printf("  Avg:        %lld ns (%.3f us)\n", static_cast<long long>(avg_ns), avg_ns / 1000.0);

        printf("\n  Latency Histogram:\n");
        const char* bucket_labels[NUM_BUCKETS] = {
            "   <10us", " 10-20us", " 20-50us", "50-100us", "100-200us",
            "200-500us", "0.5-1ms", "   1-5ms", "  5-10ms", "   10ms+"
        };

        uint64_t max_bucket = 0;
        for (int i = 0; i < NUM_BUCKETS; i++) {
            if (histogram[i] > max_bucket) max_bucket = histogram[i];
        }

        constexpr int BAR_WIDTH = 40;
        for (int i = 0; i < NUM_BUCKETS; i++) {
            uint64_t b = histogram[i];
            double pct = (count > 0) ? 100.0 * b / count : 0;
            int bar_len = (max_bucket > 0) ? static_cast<int>(BAR_WIDTH * b / max_bucket) : 0;

            printf("  %s |", bucket_labels[i]);
            for (int j = 0; j < bar_len; j++) printf("#");
            for (int j = bar_len; j < BAR_WIDTH; j++) printf(" ");
            printf("| %6llu (%5.1f%%)\n", static_cast<unsigned long long>(b), pct);
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
        ipc_ring_dir_ = std::string("bsd_transport_test_") + timestamp;
    }

    ~IPCRingManager() {
        cleanup();
    }

    bool create_ring(const char* name, size_t buffer_size, size_t event_size, uint8_t max_consumers = 1) {
#ifdef __APPLE__
        std::string base_path = std::string("/tmp/hft/") + ipc_ring_dir_ + "/" + name;
#else
        std::string base_path = std::string("/dev/shm/hft/") + ipc_ring_dir_ + "/" + name;
#endif
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
#ifdef __APPLE__
        const char* shm_base = "/tmp/hft";
#else
        const char* shm_base = "/dev/shm/hft";
#endif
        mkdir(shm_base, 0755);
        std::string full_dir = std::string(shm_base) + "/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "[IPC] Failed to create directory: %s\n", full_dir.c_str());
            return false;
        }

        // BSD Transport rings (simplified - no raw frame rings)
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

#ifdef __APPLE__
        std::string base = "/tmp/hft/" + ipc_ring_dir_;
#else
        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
#endif
        const char* ring_names[] = {"msg_outbox", "msg_metadata", "pongs"};

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
// Type Aliases
// ============================================================================

using BSDTransportType = BSDSocketTransportProcess<
    websocket::ssl::NoSSLPolicy,
    DefaultBlockingIO,
    InlineSSL,
    IPCRingConsumer<MsgOutboxEvent>,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>
>;

// ============================================================================
// Test Class
// ============================================================================

class BSDTransportTCPTest {
public:
    BSDTransportTCPTest(const char* echo_ip, uint16_t echo_port, bool use_localhost)
        : echo_ip_(echo_ip), echo_port_(echo_port), use_localhost_(use_localhost) {}

    bool setup() {
        printf("\n=== Setting up BSD Transport TCP Test ===\n");

        calibrate_tsc();

        // Start localhost echo server if needed
        if (use_localhost_) {
            if (!echo_server_.start(echo_port_)) {
                fprintf(stderr, "FAIL: Cannot start localhost echo server\n");
                return false;
            }
            usleep(50000);  // 50ms for server to be ready
        }

        printf("Echo Server: %s:%u%s\n\n", echo_ip_, echo_port_,
               use_localhost_ ? " (localhost)" : " (remote)");

        // Create IPC rings
        if (!ipc_manager_.create_all_rings()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

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
        printf("MsgInbox: %p\n", static_cast<void*>(msg_inbox_));

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
        printf("ConnStateShm: %p\n", static_cast<void*>(conn_state_));

        // Set TSC frequency
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        // Open shared regions
        try {
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

        // Wait for child process
        if (transport_pid_ > 0) {
            kill(transport_pid_, SIGTERM);
            waitpid(transport_pid_, nullptr, 0);
        }

        // Stop echo server
        echo_server_.stop();

        // Cleanup shared regions
        delete msg_outbox_region_;
        delete msg_metadata_region_;
        delete pongs_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED) {
            munmap(conn_state_, sizeof(ConnStateShm));
        }
        if (msg_inbox_ && msg_inbox_ != MAP_FAILED) {
            munmap(msg_inbox_, sizeof(MsgInbox));
        }

        printf("=== Teardown Complete ===\n");
    }

    bool fork_transport_process() {
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

        printf("[PARENT] Forked BSD Transport process (PID %d)\n", transport_pid_);

        // Wait for TCP + TLS handshake to complete
        printf("[PARENT] Waiting for connection...\n");
        auto start = std::chrono::steady_clock::now();
        while (!conn_state_->is_handshake_tls_ready()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > 10000) {
                fprintf(stderr, "FAIL: Timeout waiting for connection\n");
                return false;
            }
            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "FAIL: Transport process exited during connection\n");
                return false;
            }
            usleep(1000);
        }
        printf("[PARENT] Connection established\n");

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
        int rtt_samples = 0;
        int metadata_count = 0;
        size_t received_bytes = 0;
        auto start_time = std::chrono::steady_clock::now();
        auto last_send_time = start_time;

        // Latency tracking
        LatencyStats rtt_latency;    // Full round-trip: send → echo → receive
        LatencyStats recv_latency;   // recv_start → recv_end (syscall overhead)

        // Helper to process metadata and extract RTT
        auto process_metadata = [&](const MsgMetadata& meta) {
            if (meta.decrypted_len == 0) return;

            metadata_count++;
            received_bytes += meta.decrypted_len;

            uint64_t recv_cycle = meta.ssl_read_end_cycle;

            // Parse messages and extract TSC timestamps for RTT
            const char* data = reinterpret_cast<const char*>(msg_inbox_->data_at(meta.msg_inbox_offset));
            uint32_t pos = 0;

            while (pos + MSG_PREFIX_LEN + 9 <= meta.decrypted_len) {
                // Look for message pattern: <16-hex>:TEST_MSG_
                if (data[pos + TSC_HEX_LEN] == ':' &&
                    memcmp(data + pos + MSG_PREFIX_LEN, "TEST_MSG_", 9) == 0) {

                    // Parse send TSC from hex prefix
                    uint64_t send_cycle = parse_tsc_hex(data + pos);

                    if (send_cycle > 0 && recv_cycle > send_cycle) {
                        // Calculate full RTT
                        uint64_t rtt_cycles = recv_cycle - send_cycle;
                        int64_t rtt_ns = static_cast<int64_t>(rtt_cycles / g_tsc_freq_ghz);

                        if (rtt_ns > 0 && rtt_ns < 1'000'000'000) {
                            rtt_latency.update(rtt_ns);
                            rtt_samples++;
                        }
                    }

                    received++;
                    pos += MSG_PREFIX_LEN + 13;  // Skip past this message (17 + 13 = 30 bytes)
                } else {
                    pos++;
                }
            }

            // Compute recv syscall latency (poll → recv complete)
            if (meta.latest_nic_frame_poll_cycle != 0 && meta.ssl_read_end_cycle != 0) {
                uint64_t cycles = meta.ssl_read_end_cycle - meta.latest_nic_frame_poll_cycle;
                int64_t ns = static_cast<int64_t>(cycles / g_tsc_freq_ghz);
                if (ns > 0 && ns < 1'000'000'000) {
                    recv_latency.update(ns);
                }
            }
        };

        // Main test loop
        while (sent < MAX_MESSAGES) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            if (elapsed_s >= TIMEOUT_SECONDS) {
                printf("[TEST] Timeout reached after %lld seconds\n", static_cast<long long>(elapsed_s));
                break;
            }

            // Check if Transport is still running
            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "[TEST] Transport process exited\n");
                break;
            }

            // Send next message if interval has passed
            auto since_last = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_send_time).count();
            if (since_last >= SEND_INTERVAL_MS) {
                // Get current TSC for RTT measurement
                uint64_t send_tsc = rdtscp();

                // Prepare test message with embedded TSC: "<16-hex-tsc>:TEST_MSG_XXXX"
                char msg[64];
                snprintf(msg, sizeof(msg), "%016llx:TEST_MSG_%04d",
                         static_cast<unsigned long long>(send_tsc), sent);
                size_t msg_len = strlen(msg);

                // Send via MSG_OUTBOX
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
                        printf("[PROGRESS] Sent: %d, Received: %d, RTT samples: %d\n",
                               sent, received, rtt_samples);
                    }
                }
            }

            // Check for echo responses via MSG_METADATA
            MsgMetadata meta;
            if (msg_metadata_cons.try_consume(meta)) {
                process_metadata(meta);
            }
        }

        // Wait for remaining responses
        printf("[TEST] Waiting for remaining responses...\n");
        auto drain_start = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - drain_start).count() < 500) {
            MsgMetadata meta;
            if (msg_metadata_cons.try_consume(meta)) {
                process_metadata(meta);
                drain_start = std::chrono::steady_clock::now();  // Reset timeout on activity
            } else {
                usleep(1000);
            }
        }

        auto total_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();

        // Calculate expected bytes (each message is "<16-hex>:TEST_MSG_XXXX" = 30 bytes)
        size_t sent_bytes = sent * 30;

        printf("\n=== Test Results ===\n");
        printf("  Duration:     %lld ms\n", static_cast<long long>(total_time));
        printf("  Sent:         %d messages (%zu bytes)\n", sent, sent_bytes);
        printf("  Received:     %d messages in %d metadata entries (%zu bytes)\n",
               received, metadata_count, received_bytes);
        printf("  RTT samples:  %d\n", rtt_samples);
        printf("  Message success: %.1f%%\n", sent > 0 ? 100.0 * received / sent : 0);
        printf("  Byte success:    %.1f%%\n", sent_bytes > 0 ? 100.0 * received_bytes / sent_bytes : 0);
        printf("====================\n");
        fflush(stdout);

        // Signal child to stop and wait
        conn_state_->shutdown_all();
        if (transport_pid_ > 0) {
            waitpid(transport_pid_, nullptr, 0);
            transport_pid_ = 0;
        }

        // Print latency statistics
        rtt_latency.print("Full Round-Trip Latency (send -> echo -> receive)");
        recv_latency.print("Recv Syscall Latency (poll -> recv complete)");

        if (received == 0) {
            printf("\nFAIL: No echo responses received\n");
            return false;
        }

        printf("\nPASS: Received %d/%d echo responses, %d RTT samples\n", received, sent, rtt_samples);
        return true;
    }

private:
    // Transport child process
    void run_transport_process() {
        // Create ring adapters in child process
        IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(*msg_outbox_region_);
        IPCRingProducer<MsgMetadata> msg_metadata_prod(*msg_metadata_region_);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);

        BSDTransportType transport;

        bool ok = transport.init(
            echo_ip_, echo_port_,
            &msg_outbox_cons,
            &msg_metadata_prod,
            &pongs_cons,
            msg_inbox_,
            conn_state_);

        if (!ok) {
            fprintf(stderr, "[TRANSPORT] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        transport.run();
    }

    const char* echo_ip_;
    uint16_t echo_port_;
    bool use_localhost_;

    LocalhostEchoServer echo_server_;
    IPCRingManager ipc_manager_;

    MsgInbox* msg_inbox_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    disruptor::ipc::shared_region* msg_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_metadata_region_ = nullptr;
    disruptor::ipc::shared_region* pongs_region_ = nullptr;

    pid_t transport_pid_ = 0;
};

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    const char* echo_ip = "127.0.0.1";
    uint16_t echo_port = LOCALHOST_ECHO_PORT;
    bool use_localhost = true;

    if (argc >= 2) {
        if (strcmp(argv[1], "localhost") == 0) {
            // Explicit localhost mode
            use_localhost = true;
            echo_ip = "127.0.0.1";
            echo_port = LOCALHOST_ECHO_PORT;
        } else {
            // Remote server mode
            use_localhost = false;
            echo_ip = argv[1];
            if (argc >= 3) {
                echo_port = static_cast<uint16_t>(atoi(argv[2]));
            } else {
                echo_port = 12345;  // Default remote port
            }
        }
    }

    // Install signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  BSD Transport TCP Test (NoSSLPolicy)        \n");
    printf("==============================================\n");
    printf("  Target:    %s:%u%s\n", echo_ip, echo_port,
           use_localhost ? " (localhost echo)" : "");
    printf("  Messages:  up to %d (every %dms)\n", MAX_MESSAGES, SEND_INTERVAL_MS);
    printf("  Timeout:   %d seconds\n", TIMEOUT_SECONDS);
    printf("  RTT:       Full round-trip measurement enabled\n");
    printf("==============================================\n\n");

    BSDTransportTCPTest test(echo_ip, echo_port, use_localhost);

    // Setup
    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    // Fork transport process
    if (!test.fork_transport_process()) {
        fprintf(stderr, "\nFATAL: Failed to fork transport process\n");
        test.teardown();
        return 1;
    }

    // Give process time to stabilize
    usleep(100000);  // 100ms

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
