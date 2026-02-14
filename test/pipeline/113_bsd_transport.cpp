// test/pipeline/113_bsd_transport.cpp
// Test unified BSDSocketTransportProcess with all configurations
//
// Usage:
//   ./test_bsd_transport                        # Test all configurations
//   ./test_bsd_transport 2thread                # 2-thread BlockingIO + InlineSSL (NoSSL)
//   ./test_bsd_transport 3thread                # 3-thread BlockingIO + DedicatedSSL (SSL)
//   ./test_bsd_transport iouring                # 1-thread io_uring (Linux only)
//   ./test_bsd_transport ssl                    # 2-thread with SSL against nginx.org
//
// Tests the unified 11_bsd_tcp_ssl_process.hpp with:
//   - NoSSLPolicy + BlockingIO + InlineSSL (2-thread) - localhost echo
//   - NoSSLPolicy + AsyncIO + InlineSSL (1-thread io_uring, Linux only)
//   - OpenSSL/LibreSSL/WolfSSL + BlockingIO + InlineSSL (2-thread) - nginx.org:443
//   - OpenSSL/LibreSSL/WolfSSL + BlockingIO + DedicatedSSL (3-thread) - nginx.org:443
//
// C++20, policy-based design

// pipeline_data.hpp must be included FIRST
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
#include "../../src/policy/ssl.hpp"

using namespace websocket::pipeline;

// ============================================================================
// Configuration
// ============================================================================

namespace {

// NoSSL echo test parameters
constexpr int MAX_MESSAGES = 1000;
constexpr int TIMEOUT_SECONDS = 10;
constexpr int SEND_INTERVAL_MS = 2;
constexpr uint16_t LOCALHOST_ECHO_PORT = 19345;
constexpr size_t TSC_HEX_LEN = 16;
constexpr size_t MSG_PREFIX_LEN = TSC_HEX_LEN + 1;

// SSL test parameters (nginx.org)
constexpr const char* SSL_TEST_HOST = "nginx.org";
constexpr uint16_t SSL_TEST_PORT = 443;
constexpr int SSL_TIMEOUT_SECONDS = 15;

std::atomic<bool> g_shutdown{false};

void signal_handler(int) {
    g_shutdown.store(true, std::memory_order_release);
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

    uint64_t elapsed_tsc = end_tsc - start_tsc;
    uint64_t elapsed_ns = end_ns - start_ns;
    g_tsc_freq_ghz = static_cast<double>(elapsed_tsc) / static_cast<double>(elapsed_ns);
    printf("[TSC] Calibrated: %.3f GHz\n", g_tsc_freq_ghz);
}

uint64_t parse_tsc_hex(const char* hex_str) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        char c = hex_str[i];
        uint64_t digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return 0;
        result = (result << 4) | digit;
    }
    return result;
}

// ============================================================================
// Localhost TCP Echo Server (for NoSSL tests)
// ============================================================================

class LocalhostEchoServer {
public:
    LocalhostEchoServer() = default;
    ~LocalhostEchoServer() { stop(); }

    bool start(uint16_t port) {
        port_ = port;
        listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) return false;

        int opt = 1;
        setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

        if (listen(listen_fd_, 1) < 0) {
            close(listen_fd_);
            listen_fd_ = -1;
            return false;
        }

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
        if (server_thread_.joinable()) server_thread_.join();
    }

private:
    void run() {
        while (running_.load(std::memory_order_acquire)) {
            struct pollfd pfd = { listen_fd_, POLLIN, 0 };
            int ret = poll(&pfd, 1, 100);
            if (ret <= 0) continue;

            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(listen_fd_, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
            if (client_fd < 0) continue;

            printf("[EchoServer] Client connected\n");
            int flag = 1;
            setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

            char buf[4096];
            while (running_.load(std::memory_order_acquire)) {
                struct pollfd cpfd = { client_fd, POLLIN, 0 };
                ret = poll(&cpfd, 1, 100);
                if (ret < 0) break;
                if (ret == 0) continue;
                if (cpfd.revents & (POLLERR | POLLHUP)) break;

                ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
                if (n <= 0) break;

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

    void update(int64_t latency_ns) {
        if (latency_ns < min_ns) min_ns = latency_ns;
        if (latency_ns > max_ns) max_ns = latency_ns;
        sum_ns += latency_ns;
        count++;
    }

    void print(const char* name) const {
        if (count == 0) {
            printf("\n=== %s ===\n  No samples\n", name);
            return;
        }
        int64_t avg_ns = sum_ns / static_cast<int64_t>(count);
        printf("\n=== %s ===\n", name);
        printf("  Samples: %llu\n", static_cast<unsigned long long>(count));
        printf("  Min:     %.3f us\n", min_ns / 1000.0);
        printf("  Max:     %.3f us\n", max_ns / 1000.0);
        printf("  Avg:     %.3f us\n", avg_ns / 1000.0);
    }
};

// ============================================================================
// IPC Ring Manager
// ============================================================================

class IPCRingManager {
public:
    IPCRingManager(const char* suffix = "") {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string("bsd_unified_test_") + timestamp + suffix;
    }

    ~IPCRingManager() { cleanup(); }

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
#ifdef __APPLE__
        const char* shm_base = "/tmp/hft";
#else
        const char* shm_base = "/dev/shm/hft";
#endif
        mkdir(shm_base, 0755);
        std::string full_dir = std::string(shm_base) + "/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) return false;

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
// Test Configurations
// ============================================================================

enum class TestConfig {
    BLOCKING_2THREAD,     // NoSSL + BlockingIO + InlineSSL
    BLOCKING_3THREAD,     // SSL + BlockingIO + DedicatedSSL
    BLOCKING_SSL,         // SSL + BlockingIO + InlineSSL
    ASYNC_IOURING,        // NoSSL + AsyncIO + InlineSSL (Linux only)
};

const char* config_name(TestConfig config) {
    switch (config) {
        case TestConfig::BLOCKING_2THREAD: return "2-Thread BlockingIO (NoSSL)";
        case TestConfig::BLOCKING_3THREAD: return "3-Thread BlockingIO (SSL + DedicatedSSL)";
        case TestConfig::BLOCKING_SSL:     return "2-Thread BlockingIO (SSL + InlineSSL)";
        case TestConfig::ASYNC_IOURING:    return "1-Thread AsyncIO (io_uring)";
        default: return "Unknown";
    }
}

// Type aliases for different configurations
using Transport2Thread = BSDSocketTransportProcess<
    websocket::ssl::NoSSLPolicy,
    DefaultBlockingIO,
    InlineSSL,
    IPCRingConsumer<MsgOutboxEvent>,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>
>;

// SSL types (requires SSL library)
#if defined(HAVE_OPENSSL) || defined(USE_LIBRESSL) || defined(HAVE_WOLFSSL)

#if defined(HAVE_WOLFSSL)
using SSLPolicyType = websocket::ssl::WolfSSLPolicy;
#define SSL_POLICY_NAME "WolfSSL"
#elif defined(USE_LIBRESSL)
using SSLPolicyType = websocket::ssl::LibreSSLPolicy;
#define SSL_POLICY_NAME "LibreSSL"
#else
using SSLPolicyType = websocket::ssl::OpenSSLPolicy;
#define SSL_POLICY_NAME "OpenSSL"
#endif

using Transport3Thread = BSDSocketTransportProcess<
    SSLPolicyType,
    DefaultBlockingIO,
    DedicatedSSL,
    IPCRingConsumer<MsgOutboxEvent>,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>
>;

using TransportSSL2Thread = BSDSocketTransportProcess<
    SSLPolicyType,
    DefaultBlockingIO,
    InlineSSL,
    IPCRingConsumer<MsgOutboxEvent>,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>
>;

#define HAS_SSL 1
#else
#define HAS_SSL 0
#endif

#ifdef __linux__
using TransportIoUring = BSDSocketTransportProcess<
    websocket::ssl::NoSSLPolicy,
    AsyncIO,
    InlineSSL,
    IPCRingConsumer<MsgOutboxEvent>,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>
>;
#endif

// ============================================================================
// Generic Echo Test Runner (for NoSSL tests)
// ============================================================================

template<typename TransportType>
class EchoTestRunner {
public:
    EchoTestRunner(const char* name, const char* echo_ip, uint16_t echo_port)
        : name_(name), echo_ip_(echo_ip), echo_port_(echo_port), ipc_manager_("_echo") {}

    bool run() {
        printf("\n========================================\n");
        printf("  Testing: %s\n", name_);
        printf("  Mode: Echo (localhost)\n");
        printf("========================================\n");

        if (!setup()) {
            printf("FAIL: Setup failed\n");
            teardown();
            return false;
        }

        if (!fork_transport_process()) {
            printf("FAIL: Fork failed\n");
            teardown();
            return false;
        }

        usleep(100000);  // 100ms stabilization

        bool result = run_echo_test();
        teardown();

        printf("\n--- %s: %s ---\n", name_, result ? "PASS" : "FAIL");
        return result;
    }

private:
    bool setup() {
        if (!echo_server_.start(echo_port_)) return false;
        usleep(50000);

        if (!ipc_manager_.create_all_rings()) return false;

        msg_inbox_ = static_cast<MsgInbox*>(
            mmap(nullptr, sizeof(MsgInbox), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        if (msg_inbox_ == MAP_FAILED) return false;
        msg_inbox_->init();

        conn_state_ = static_cast<ConnStateShm*>(
            mmap(nullptr, sizeof(ConnStateShm), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        if (conn_state_ == MAP_FAILED) return false;
        conn_state_->init();
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        try {
            msg_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_outbox"));
            msg_metadata_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata"));
            pongs_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pongs"));
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
            return false;
        }

        return true;
    }

    void teardown() {
        if (conn_state_) conn_state_->shutdown_all();
        g_shutdown.store(true);

        if (transport_pid_ > 0) {
            kill(transport_pid_, SIGTERM);
            waitpid(transport_pid_, nullptr, 0);
        }

        echo_server_.stop();

        delete msg_outbox_region_;
        delete msg_metadata_region_;
        delete pongs_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED)
            munmap(conn_state_, sizeof(ConnStateShm));
        if (msg_inbox_ && msg_inbox_ != MAP_FAILED)
            munmap(msg_inbox_, sizeof(MsgInbox));
    }

    bool fork_transport_process() {
        transport_pid_ = fork();
        if (transport_pid_ < 0) return false;

        if (transport_pid_ == 0) {
            run_transport_child();
            _exit(0);
        }

        printf("[PARENT] Forked transport (PID %d)\n", transport_pid_);

        auto start = std::chrono::steady_clock::now();
        while (!conn_state_->is_handshake_tls_ready()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > 10000) return false;
            if (!conn_state_->is_running(PROC_TRANSPORT)) return false;
            usleep(1000);
        }

        printf("[PARENT] Connection established\n");
        return true;
    }

    void run_transport_child() {
        IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(*msg_outbox_region_);
        IPCRingProducer<MsgMetadata> msg_metadata_prod(*msg_metadata_region_);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);

        TransportType transport;
        bool ok = transport.init(echo_ip_, echo_port_,
                                 &msg_outbox_cons, &msg_metadata_prod, &pongs_cons,
                                 msg_inbox_, conn_state_);
        if (!ok) {
            conn_state_->shutdown_all();
            return;
        }
        transport.run();
    }

    bool run_echo_test() {
        IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(*msg_outbox_region_);
        IPCRingConsumer<MsgMetadata> msg_metadata_cons(*msg_metadata_region_);

        int sent = 0, received = 0, rtt_samples = 0;
        LatencyStats rtt_latency;

        auto start_time = std::chrono::steady_clock::now();
        auto last_send_time = start_time;

        while (sent < MAX_MESSAGES) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            if (elapsed_s >= TIMEOUT_SECONDS) break;
            if (!conn_state_->is_running(PROC_TRANSPORT)) break;

            auto since_last = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_send_time).count();
            if (since_last >= SEND_INTERVAL_MS) {
                uint64_t send_tsc = rdtscp();
                char msg[64];
                snprintf(msg, sizeof(msg), "%016llx:TEST_MSG_%04d",
                         static_cast<unsigned long long>(send_tsc), sent);
                size_t msg_len = strlen(msg);

                int64_t slot = msg_outbox_prod.try_claim();
                if (slot >= 0) {
                    auto& event = msg_outbox_prod[slot];
                    event.data_len = static_cast<uint16_t>(msg_len);
                    event.msg_type = MSG_TYPE_DATA;
                    memcpy(event.data, msg, msg_len);
                    msg_outbox_prod.publish(slot);
                    sent++;
                    last_send_time = now;
                }
            }

            MsgMetadata meta;
            if (msg_metadata_cons.try_consume(meta)) {
                if (meta.decrypted_len == 0) continue;

                uint64_t recv_cycle = meta.ssl_read_end_cycle;
                const char* data = reinterpret_cast<const char*>(
                    msg_inbox_->data_at(meta.msg_inbox_offset));
                uint32_t pos = 0;

                while (pos + MSG_PREFIX_LEN + 9 <= meta.decrypted_len) {
                    if (data[pos + TSC_HEX_LEN] == ':' &&
                        memcmp(data + pos + MSG_PREFIX_LEN, "TEST_MSG_", 9) == 0) {

                        uint64_t send_cycle = parse_tsc_hex(data + pos);
                        if (send_cycle > 0 && recv_cycle > send_cycle) {
                            uint64_t rtt_cycles = recv_cycle - send_cycle;
                            int64_t rtt_ns = static_cast<int64_t>(rtt_cycles / g_tsc_freq_ghz);
                            if (rtt_ns > 0 && rtt_ns < 1'000'000'000) {
                                rtt_latency.update(rtt_ns);
                                rtt_samples++;
                            }
                        }
                        received++;
                        pos += MSG_PREFIX_LEN + 13;
                    } else {
                        pos++;
                    }
                }
            }
        }

        // Drain remaining
        auto drain_start = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - drain_start).count() < 500) {
            MsgMetadata meta;
            if (msg_metadata_cons.try_consume(meta)) {
                if (meta.decrypted_len > 0) received++;
                drain_start = std::chrono::steady_clock::now();
            } else {
                usleep(1000);
            }
        }

        conn_state_->shutdown_all();
        if (transport_pid_ > 0) {
            waitpid(transport_pid_, nullptr, 0);
            transport_pid_ = 0;
        }

        printf("\n  Sent: %d, Received: %d, RTT samples: %d\n", sent, received, rtt_samples);
        rtt_latency.print("Round-Trip Latency");

        return received > 0;
    }

    const char* name_;
    const char* echo_ip_;
    uint16_t echo_port_;

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
// SSL HTTPS Test Runner (for SSL tests against nginx.org)
// ============================================================================

#if HAS_SSL

template<typename TransportType>
class SSLTestRunner {
public:
    SSLTestRunner(const char* name, const char* host, uint16_t port, const char* suffix)
        : name_(name), host_(host), port_(port), ipc_manager_(suffix) {}

    bool run() {
        printf("\n========================================\n");
        printf("  Testing: %s\n", name_);
        printf("  Mode: HTTPS GET (%s:%u)\n", host_, port_);
        printf("  SSL Library: %s\n", SSL_POLICY_NAME);
        printf("========================================\n");

        if (!setup()) {
            printf("FAIL: Setup failed\n");
            teardown();
            return false;
        }

        if (!fork_transport_process()) {
            printf("FAIL: Fork/connect failed\n");
            teardown();
            return false;
        }

        usleep(100000);  // 100ms stabilization

        bool result = run_https_test();
        teardown();

        printf("\n--- %s: %s ---\n", name_, result ? "PASS" : "FAIL");
        return result;
    }

private:
    bool setup() {
        if (!ipc_manager_.create_all_rings()) return false;

        msg_inbox_ = static_cast<MsgInbox*>(
            mmap(nullptr, sizeof(MsgInbox), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        if (msg_inbox_ == MAP_FAILED) return false;
        msg_inbox_->init();

        conn_state_ = static_cast<ConnStateShm*>(
            mmap(nullptr, sizeof(ConnStateShm), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        if (conn_state_ == MAP_FAILED) return false;
        conn_state_->init();
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        try {
            msg_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_outbox"));
            msg_metadata_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata"));
            pongs_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pongs"));
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
            return false;
        }

        return true;
    }

    void teardown() {
        if (conn_state_) conn_state_->shutdown_all();

        if (transport_pid_ > 0) {
            kill(transport_pid_, SIGTERM);
            waitpid(transport_pid_, nullptr, 0);
        }

        delete msg_outbox_region_;
        delete msg_metadata_region_;
        delete pongs_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED)
            munmap(conn_state_, sizeof(ConnStateShm));
        if (msg_inbox_ && msg_inbox_ != MAP_FAILED)
            munmap(msg_inbox_, sizeof(MsgInbox));
    }

    bool fork_transport_process() {
        transport_pid_ = fork();
        if (transport_pid_ < 0) return false;

        if (transport_pid_ == 0) {
            run_transport_child();
            _exit(0);
        }

        printf("[PARENT] Forked SSL transport (PID %d)\n", transport_pid_);

        // Wait for TLS handshake
        auto start = std::chrono::steady_clock::now();
        while (!conn_state_->is_handshake_tls_ready()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > SSL_TIMEOUT_SECONDS) {
                fprintf(stderr, "FAIL: TLS handshake timeout\n");
                return false;
            }
            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "FAIL: Transport exited during handshake\n");
                return false;
            }
            usleep(10000);
        }

        printf("[PARENT] TLS connection established to %s:%u\n", host_, port_);
        return true;
    }

    void run_transport_child() {
        IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(*msg_outbox_region_);
        IPCRingProducer<MsgMetadata> msg_metadata_prod(*msg_metadata_region_);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);

        TransportType transport;
        bool ok = transport.init(host_, port_,
                                 &msg_outbox_cons, &msg_metadata_prod, &pongs_cons,
                                 msg_inbox_, conn_state_);
        if (!ok) {
            fprintf(stderr, "[CHILD] Transport init failed\n");
            conn_state_->shutdown_all();
            return;
        }
        transport.run();
    }

    bool run_https_test() {
        IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(*msg_outbox_region_);
        IPCRingConsumer<MsgMetadata> msg_metadata_cons(*msg_metadata_region_);

        // Send HTTP GET request
        char http_request[512];
        snprintf(http_request, sizeof(http_request),
                 "GET / HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: BSDTransportTest/1.0\r\n"
                 "Accept: */*\r\n"
                 "Connection: close\r\n"
                 "\r\n", host_);

        size_t req_len = strlen(http_request);
        printf("[TEST] Sending HTTP GET request (%zu bytes)...\n", req_len);

        uint64_t send_cycle = rdtscp();

        int64_t slot = msg_outbox_prod.try_claim();
        if (slot < 0) {
            fprintf(stderr, "FAIL: Cannot claim outbox slot\n");
            conn_state_->shutdown_all();
            return false;
        }

        auto& event = msg_outbox_prod[slot];
        event.data_len = static_cast<uint16_t>(req_len);
        event.msg_type = MSG_TYPE_DATA;
        memcpy(event.data, http_request, req_len);
        msg_outbox_prod.publish(slot);

        printf("[TEST] Request sent, waiting for response...\n");

        // Wait for response
        size_t total_received = 0;
        bool got_http_response = false;
        std::string response_preview;

        auto start_time = std::chrono::steady_clock::now();
        while (true) {
            auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start_time).count();
            if (elapsed_s >= SSL_TIMEOUT_SECONDS) {
                printf("[TEST] Timeout waiting for response\n");
                break;
            }

            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                // Transport closed (expected with Connection: close)
                break;
            }

            MsgMetadata meta;
            if (msg_metadata_cons.try_consume(meta)) {
                if (meta.decrypted_len == 0) continue;

                uint64_t recv_cycle = meta.ssl_read_end_cycle;
                total_received += meta.decrypted_len;

                // Check for HTTP response
                const char* data = reinterpret_cast<const char*>(
                    msg_inbox_->data_at(meta.msg_inbox_offset));

                if (!got_http_response && meta.decrypted_len >= 12) {
                    if (strncmp(data, "HTTP/1.", 7) == 0) {
                        got_http_response = true;

                        // Calculate response latency
                        uint64_t latency_cycles = recv_cycle - send_cycle;
                        double latency_ms = (latency_cycles / g_tsc_freq_ghz) / 1000000.0;
                        printf("[TEST] First response received (latency: %.2f ms)\n", latency_ms);

                        // Extract status line
                        const char* end = static_cast<const char*>(memchr(data, '\r', meta.decrypted_len));
                        if (end) {
                            response_preview = std::string(data, end - data);
                        } else {
                            response_preview = std::string(data, std::min<size_t>(meta.decrypted_len, 100));
                        }
                        printf("[TEST] Response: %s\n", response_preview.c_str());
                    }
                }
            } else {
                usleep(1000);
            }
        }

        // Cleanup
        conn_state_->shutdown_all();
        if (transport_pid_ > 0) {
            waitpid(transport_pid_, nullptr, 0);
            transport_pid_ = 0;
        }

        printf("\n  Total received: %zu bytes\n", total_received);
        printf("  HTTP response: %s\n", got_http_response ? "YES" : "NO");

        // Success if we got an HTTP response with 200 OK or 301/302 redirect
        if (got_http_response && total_received > 0) {
            if (response_preview.find("200") != std::string::npos ||
                response_preview.find("301") != std::string::npos ||
                response_preview.find("302") != std::string::npos) {
                return true;
            }
        }

        return got_http_response && total_received > 100;
    }

    const char* name_;
    const char* host_;
    uint16_t port_;

    IPCRingManager ipc_manager_;

    MsgInbox* msg_inbox_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    disruptor::ipc::shared_region* msg_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_metadata_region_ = nullptr;
    disruptor::ipc::shared_region* pongs_region_ = nullptr;

    pid_t transport_pid_ = 0;
};

#endif  // HAS_SSL

}  // namespace

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    calibrate_tsc();

    const char* echo_ip = "127.0.0.1";
    int passed = 0, failed = 0;

    printf("================================================\n");
    printf("  Unified BSD Transport Test Suite\n");
    printf("================================================\n");
#if HAS_SSL
    printf("  SSL Library: %s\n", SSL_POLICY_NAME);
#else
    printf("  SSL Library: None (SSL tests will be skipped)\n");
#endif
    printf("================================================\n");

    auto run_config = [&](TestConfig config) {
        bool result = false;
        switch (config) {
            case TestConfig::BLOCKING_2THREAD: {
                EchoTestRunner<Transport2Thread> test(
                    config_name(config), echo_ip, LOCALHOST_ECHO_PORT);
                result = test.run();
                break;
            }
#ifdef __linux__
            case TestConfig::ASYNC_IOURING: {
                EchoTestRunner<TransportIoUring> test(
                    config_name(config), echo_ip, LOCALHOST_ECHO_PORT + 1);
                result = test.run();
                break;
            }
#else
            case TestConfig::ASYNC_IOURING:
                printf("\n[SKIP] %s - Linux only\n", config_name(config));
                return;
#endif
#if HAS_SSL
            case TestConfig::BLOCKING_SSL: {
                SSLTestRunner<TransportSSL2Thread> test(
                    config_name(config), SSL_TEST_HOST, SSL_TEST_PORT, "_ssl2");
                result = test.run();
                break;
            }
            case TestConfig::BLOCKING_3THREAD: {
                SSLTestRunner<Transport3Thread> test(
                    config_name(config), SSL_TEST_HOST, SSL_TEST_PORT, "_ssl3");
                result = test.run();
                break;
            }
#else
            case TestConfig::BLOCKING_SSL:
            case TestConfig::BLOCKING_3THREAD:
                printf("\n[SKIP] %s - SSL not available\n", config_name(config));
                return;
#endif
            default:
                printf("\n[SKIP] %s - not implemented\n", config_name(config));
                return;
        }

        if (result) passed++;
        else failed++;
    };

    if (argc == 1) {
        // Run all configurations
        run_config(TestConfig::BLOCKING_2THREAD);
#ifdef __linux__
        run_config(TestConfig::ASYNC_IOURING);
#endif
#if HAS_SSL
        run_config(TestConfig::BLOCKING_SSL);
        run_config(TestConfig::BLOCKING_3THREAD);
#endif
    } else {
        // Run specific configuration
        const char* mode = argv[1];
        if (strcmp(mode, "2thread") == 0) {
            run_config(TestConfig::BLOCKING_2THREAD);
        } else if (strcmp(mode, "3thread") == 0) {
            run_config(TestConfig::BLOCKING_3THREAD);
        } else if (strcmp(mode, "ssl") == 0) {
            run_config(TestConfig::BLOCKING_SSL);
        } else if (strcmp(mode, "iouring") == 0) {
            run_config(TestConfig::ASYNC_IOURING);
        } else if (strcmp(mode, "all") == 0) {
            run_config(TestConfig::BLOCKING_2THREAD);
#ifdef __linux__
            run_config(TestConfig::ASYNC_IOURING);
#endif
#if HAS_SSL
            run_config(TestConfig::BLOCKING_SSL);
            run_config(TestConfig::BLOCKING_3THREAD);
#endif
        } else {
            printf("Unknown mode: %s\n", mode);
            printf("Usage: %s [2thread|3thread|ssl|iouring|all]\n", argv[0]);
            return 1;
        }
    }

    printf("\n================================================\n");
    printf("  Results: %d passed, %d failed\n", passed, failed);
    printf("================================================\n");

    return failed > 0 ? 1 : 0;
}
