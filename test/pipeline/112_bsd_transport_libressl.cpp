// test/pipeline/112_bsd_transport_libressl.cpp
// Test BSDSocketTransportProcess with LibreSSL (both Linux and macOS)
//
// Usage:
//   ./test_pipeline_bsd_transport_libressl           # Test all (2-thread + 3-thread SSL)
//   ./test_pipeline_bsd_transport_libressl 2thread   # 2-thread InlineSSL only
//   ./test_pipeline_bsd_transport_libressl 3thread   # 3-thread DedicatedSSL only
//
// Tests:
//   - LibreSSLPolicy + BlockingIO + InlineSSL (2-thread) - nginx.org:443
//   - LibreSSLPolicy + BlockingIO + DedicatedSSL (3-thread) - nginx.org:443

#if defined(HAVE_WOLFSSL) || defined(WOLFSSL_USER_SETTINGS)
#error "This test requires LibreSSL, not WolfSSL"
#endif

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

namespace {

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
        ipc_ring_dir_ = std::string("bsd_libressl_test_") + timestamp + suffix;
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
// Configuration
// ============================================================================

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

// ============================================================================
// Type Aliases for LibreSSL
// ============================================================================

using LibreSSL2Thread = BSDSocketTransportProcess<
    websocket::ssl::LibreSSLPolicy,
    DefaultBlockingIO,
    InlineSSL,
    IPCRingConsumer<MsgOutboxEvent>,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>
>;

using LibreSSL3Thread = BSDSocketTransportProcess<
    websocket::ssl::LibreSSLPolicy,
    DefaultBlockingIO,
    DedicatedSSL,
    IPCRingConsumer<MsgOutboxEvent>,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>
>;

// ============================================================================
// SSL Test Runner
// ============================================================================

template<typename TransportType>
class SSLTestRunner {
public:
    SSLTestRunner(const char* name, const char* host, uint16_t port, const char* suffix)
        : name_(name), host_(host), port_(port), ipc_manager_(suffix) {}

    bool run() {
        printf("\n========================================\n");
        printf("  Testing: %s\n", name_);
        printf("  Mode: HTTPS GET (%s:%u)\n", host_, port_);
        printf("  SSL Library: LibreSSL\n");
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

        usleep(100000);

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

        printf("[PARENT] Forked LibreSSL transport (PID %d)\n", transport_pid_);

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

        char http_request[512];
        snprintf(http_request, sizeof(http_request),
                 "GET / HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: LibreSSLTransportTest/1.0\r\n"
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

            if (!conn_state_->is_running(PROC_TRANSPORT)) break;

            MsgMetadata meta;
            if (msg_metadata_cons.try_consume(meta)) {
                if (meta.decrypted_len == 0) continue;

                uint64_t recv_cycle = meta.ssl_read_end_cycle;
                total_received += meta.decrypted_len;

                const char* data = reinterpret_cast<const char*>(
                    msg_inbox_->data_at(meta.msg_inbox_offset));

                if (!got_http_response && meta.decrypted_len >= 12) {
                    if (strncmp(data, "HTTP/1.", 7) == 0) {
                        got_http_response = true;

                        uint64_t latency_cycles = recv_cycle - send_cycle;
                        double latency_ms = (latency_cycles / g_tsc_freq_ghz) / 1000000.0;
                        printf("[TEST] First response received (latency: %.2f ms)\n", latency_ms);

                        size_t preview_len = std::min(meta.decrypted_len, 50u);
                        response_preview.assign(data, preview_len);
                        for (auto& c : response_preview) {
                            if (c == '\r' || c == '\n') c = ' ';
                        }
                        printf("[TEST] Response: %s\n", response_preview.c_str());
                    }
                }
            } else {
                usleep(1000);
            }
        }

        conn_state_->shutdown_all();
        usleep(100000);

        printf("\n  Total received: %zu bytes\n", total_received);
        printf("  HTTP response: %s\n", got_http_response ? "YES" : "NO");

        return got_http_response && total_received > 0;
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
    pid_t transport_pid_ = -1;
};

}  // namespace

int main(int argc, char* argv[]) {
    bool test_2thread = true;
    bool test_3thread = true;

    if (argc >= 2) {
        if (strcmp(argv[1], "2thread") == 0) test_3thread = false;
        else if (strcmp(argv[1], "3thread") == 0) test_2thread = false;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("================================================\n");
    printf("  LibreSSL Transport Test Suite\n");
    printf("================================================\n");

    calibrate_tsc();

    int passed = 0, failed = 0;

    if (test_2thread) {
        SSLTestRunner<LibreSSL2Thread> runner(
            "2-Thread LibreSSL (InlineSSL)",
            SSL_TEST_HOST, SSL_TEST_PORT, "_libressl2");
        if (runner.run()) passed++; else failed++;
        usleep(200000);
    }

    if (test_3thread) {
        SSLTestRunner<LibreSSL3Thread> runner(
            "3-Thread LibreSSL (DedicatedSSL)",
            SSL_TEST_HOST, SSL_TEST_PORT, "_libressl3");
        if (runner.run()) passed++; else failed++;
    }

    printf("\n================================================\n");
    printf("  Results: %d passed, %d failed\n", passed, failed);
    printf("================================================\n");

    return (failed > 0) ? 1 : 0;
}
