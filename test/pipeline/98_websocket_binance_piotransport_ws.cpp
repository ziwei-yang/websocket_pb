// test/pipeline/98_websocket_binance.cpp
// Test UnifiedXDPSSLProcess (98_*) + WebSocketProcess (20_ws) against Binance WSS stream
//
// Architecture (2 child processes):
//   - Child 1 (Core 4): UnifiedXDPSSLProcess - XDP + TCP + SSL (outputs MSG_METADATA)
//   - Child 2 (Core 6): WebSocketProcess - WS frame parsing (outputs WS_FRAME_INFO)
//   - Parent: Consumes WS_FRAME_INFO, prints latency
//
// Usage: ./test_pipeline_98_websocket_binance <interface> <bpf_path> [--timeout <ms>]
//
// Build: ./scripts/build_xdp.sh 98_websocket_binance.cpp
//
// Options:
//   --timeout <ms>   Stream timeout in milliseconds (default: 5000)
//                    If <= 0, run forever and display every message received

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
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
#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/98_xdp_tcp_ssl_process.hpp"
#include "../../src/pipeline/20_ws_process.hpp"
#include "../../src/pipeline/msg_inbox.hpp"
#include "../../src/core/http.hpp"
#include "../../src/policy/ssl.hpp"

using namespace websocket::pipeline;
using namespace websocket::ssl;

// Select SSL policy based on compile-time flags
#if defined(USE_OPENSSL)
using SSLPolicyType = OpenSSLPolicy;
#elif defined(USE_WOLFSSL)
using SSLPolicyType = WolfSSLPolicy;
#else
#error "Must define USE_OPENSSL or USE_WOLFSSL"
#endif

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignments
constexpr int UNIFIED_SSL_CPU_CORE = 4;  // XDP + TCP + SSL process
constexpr int WEBSOCKET_CPU_CORE = 6;    // WebSocket parsing process

// Test parameters
constexpr int DEFAULT_STREAM_DURATION_MS = 5000;
constexpr int FINAL_DRAIN_MS = 2000;
constexpr int MIN_EXPECTED_TRADES = 10;

// Runtime timeout
int g_timeout_ms = DEFAULT_STREAM_DURATION_MS;

// WebSocket target
static constexpr const char* WSS_HOST = "stream.binance.com";
static constexpr uint16_t WSS_PORT = 443;
static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade";

// Test configuration
std::string g_local_ip;

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

// Validate Binance trade JSON
bool is_valid_trade_json(const char* data, size_t len) {
    std::string_view sv(data, len);
    if (sv.find("\"stream\"") == std::string_view::npos) return false;
    if (sv.find("btcusdt@trade") == std::string_view::npos) return false;
    if (sv.find("\"data\"") == std::string_view::npos) return false;
    if (sv.find("\"e\":\"trade\"") == std::string_view::npos) return false;
    return true;
}

// Parse "E" field (event timestamp) from Binance JSON
uint64_t parse_event_time(const uint8_t* payload, size_t len) {
    const char* e_pos = (const char*)memmem(payload, len, "\"E\":", 4);
    if (e_pos) {
        return strtoull(e_pos + 4, nullptr, 10);
    }
    return 0;
}

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
        ipc_ring_dir_ = std::string("websocket_98_test_") + timestamp;
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

        // UnifiedSSL <-> WebSocket rings
        if (!create_ring("msg_outbox", MSG_OUTBOX_SIZE * sizeof(MsgOutboxEvent),
                         sizeof(MsgOutboxEvent), 1)) return false;
        if (!create_ring("msg_metadata", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                         sizeof(MsgMetadata), 1)) return false;
        if (!create_ring("pongs", PONGS_SIZE * sizeof(PongFrameAligned),
                         sizeof(PongFrameAligned), 1)) return false;

        // WebSocket <-> Parent ring
        if (!create_ring("ws_frame_info", WS_FRAME_INFO_SIZE * sizeof(WSFrameInfo),
                         sizeof(WSFrameInfo), 1)) return false;

        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;

        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = {
            "msg_outbox", "msg_metadata", "pongs", "ws_frame_info"
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
// Type Aliases
// ============================================================================

// UnifiedXDPSSL Process types (with profiling enabled)
using UnifiedSSLType = UnifiedXDPSSLProcess<
    SSLPolicyType,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>,
    true>;  // Profiling

// WebSocket Process types
using WebSocketType = WebSocketProcess<
    IPCRingConsumer<MsgMetadata>,
    IPCRingProducer<WSFrameInfo>,
    IPCRingProducer<PongFrameAligned>,
    IPCRingProducer<MsgOutboxEvent>>;

// ============================================================================
// Test Class
// ============================================================================

class WebSocket98Test {
public:
    WebSocket98Test(const char* interface, const char* bpf_path)
        : interface_(interface), bpf_path_(bpf_path) {}

    bool setup() {
        printf("\n=== Setting up WebSocket 98 Test ===\n");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);
        printf("Target:      %s:%u\n", WSS_HOST, WSS_PORT);
        printf("Path:        %s\n\n", WSS_PATH);

        calibrate_tsc();

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

        // Set target configuration
        strncpy(conn_state_->target_host, WSS_HOST, sizeof(conn_state_->target_host) - 1);
        conn_state_->target_port = WSS_PORT;
        strncpy(conn_state_->target_path, WSS_PATH, sizeof(conn_state_->target_path) - 1);
        strncpy(conn_state_->bpf_path, bpf_path_, sizeof(conn_state_->bpf_path) - 1);
        strncpy(conn_state_->interface_name, interface_, sizeof(conn_state_->interface_name) - 1);

        // Set TSC frequency
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        printf("ConnStateShm: %p\n", conn_state_);

        // Open shared regions
        try {
            msg_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_outbox"));
            msg_metadata_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata"));
            pongs_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pongs"));
            ws_frame_info_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("ws_frame_info"));
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
        if (unified_ssl_pid_ > 0) {
            kill(unified_ssl_pid_, SIGTERM);
            waitpid(unified_ssl_pid_, nullptr, 0);
        }
        if (websocket_pid_ > 0) {
            kill(websocket_pid_, SIGTERM);
            waitpid(websocket_pid_, nullptr, 0);
        }

        // Cleanup shared regions
        delete msg_outbox_region_;
        delete msg_metadata_region_;
        delete pongs_region_;
        delete ws_frame_info_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED) {
            munmap(conn_state_, sizeof(ConnStateShm));
        }
        if (msg_inbox_ && msg_inbox_ != MAP_FAILED) {
            munmap(msg_inbox_, sizeof(MsgInbox));
        }

        printf("=== Teardown Complete ===\n");
    }

    bool fork_processes() {
        // Build URL
        char url[512];
        snprintf(url, sizeof(url), "wss://%s:%u%s", WSS_HOST, WSS_PORT, WSS_PATH);

        // Fork UnifiedSSL process (Core 4)
        unified_ssl_pid_ = fork();
        if (unified_ssl_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for UnifiedSSL failed\n");
            return false;
        }

        if (unified_ssl_pid_ == 0) {
            // Child: UnifiedSSL process
            run_unified_ssl_process(url);
            _exit(0);
        }

        printf("[PARENT] Forked UnifiedSSL process (PID %d) on core %d\n",
               unified_ssl_pid_, UNIFIED_SSL_CPU_CORE);

        // Wait for TLS handshake to complete
        printf("[PARENT] Waiting for TLS handshake (%s)...\n", SSLPolicyType::name());
        if (!conn_state_->wait_for_handshake_tls_ready(15000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for TLS handshake\n");
            return false;
        }
        printf("[PARENT] TLS handshake complete\n");

        // Fork WebSocket process (Core 6)
        websocket_pid_ = fork();
        if (websocket_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for WebSocket failed\n");
            return false;
        }

        if (websocket_pid_ == 0) {
            // Child: WebSocket process
            run_websocket_process();
            _exit(0);
        }

        printf("[PARENT] Forked WebSocket process (PID %d) on core %d\n",
               websocket_pid_, WEBSOCKET_CPU_CORE);

        // Wait for WebSocket handshake to complete
        printf("[PARENT] Waiting for WebSocket handshake...\n");
        if (!conn_state_->wait_for_handshake_ws_ready(30000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for WebSocket handshake\n");
            return false;
        }
        printf("[PARENT] WebSocket handshake complete\n");

        return true;
    }

    bool run_stream_test() {
        bool run_forever = (g_timeout_ms <= 0);

        if (run_forever) {
            printf("\n--- WSS Stream Test (FOREVER MODE - Ctrl+C to stop) ---\n");
        } else {
            printf("\n--- WSS Stream Test (%dms, expect %d+ trades) ---\n",
                   g_timeout_ms, MIN_EXPECTED_TRADES);
        }

        // Create consumer for WS_FRAME_INFO ring
        IPCRingConsumer<WSFrameInfo> ws_frame_cons(*ws_frame_info_region_);

        // Tracking metrics
        uint64_t total_frames = 0;
        uint64_t text_frames = 0;
        uint64_t binary_frames = 0;
        uint64_t ping_frames = 0;
        uint64_t pong_frames = 0;
        uint64_t close_frames = 0;
        uint64_t valid_trades = 0;
        int64_t last_sequence = -1;
        bool sequence_error = false;

        auto start_time = std::chrono::steady_clock::now();
        auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

        printf("[WSS] Starting stream reception...\n");

        // Main streaming loop
        while (run_forever || std::chrono::steady_clock::now() < stream_end) {
            if (g_shutdown.load(std::memory_order_acquire)) {
                printf("[WSS] Shutdown signal received\n");
                break;
            }

            if (!conn_state_->is_running(PROC_WEBSOCKET)) {
                fprintf(stderr, "[WSS] WebSocket process exited during streaming\n");
                break;
            }

            // Process WS_FRAME_INFO events
            WSFrameInfo frame;
            bool end_of_batch;
            while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
                total_frames++;

                // Verify sequence ordering
                int64_t current_seq = ws_frame_cons.sequence();
                if (last_sequence != -1 && current_seq != last_sequence + 1) {
                    fprintf(stderr, "WARN: Out-of-order frame! Expected %ld, got %ld\n",
                            last_sequence + 1, current_seq);
                    sequence_error = true;
                }
                last_sequence = current_seq;

                // Count by opcode
                switch (frame.opcode) {
                    case 0x01:  // TEXT
                        text_frames++;
                        if (frame.payload_len > 0) {
                            const uint8_t* payload = msg_inbox_->data_at(frame.msg_inbox_offset);
                            if (is_valid_trade_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                                valid_trades++;

                                // Parse "E" field for exchange latency
                                uint64_t event_time_ms = parse_event_time(payload, frame.payload_len);
                                if (event_time_ms > 0) {
                                    struct timespec ts;
                                    clock_gettime(CLOCK_REALTIME, &ts);
                                    uint64_t local_time_ms = (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
                                    int64_t exchange_latency_ms = (int64_t)local_time_ms - (int64_t)event_time_ms;

                                    if (run_forever || valid_trades <= 3) {
                                        printf("\n[MSG #%lu] %.*s\n",
                                               valid_trades,
                                               (int)std::min(static_cast<uint32_t>(200), frame.payload_len),
                                               reinterpret_cast<const char*>(payload));
                                        printf("  Exchange latency: %ld ms\n", exchange_latency_ms);
                                    }
                                }
                            }
                        }
                        break;

                    case 0x02:  // BINARY
                        binary_frames++;
                        break;

                    case 0x09:  // PING
                        ping_frames++;
                        printf("[PING] Received PING #%lu\n", ping_frames);
                        break;

                    case 0x0A:  // PONG
                        pong_frames++;
                        break;

                    case 0x08:  // CLOSE
                        close_frames++;
                        printf("[CLOSE] Received CLOSE frame\n");
                        break;

                    default:
                        break;
                }
            }

            __builtin_ia32_pause();
        }

        // Final drain
        if (!run_forever) {
            printf("[WSS] Final %dms drain...\n", FINAL_DRAIN_MS);
            auto drain_start = std::chrono::steady_clock::now();

            while (true) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - drain_start).count();
                if (elapsed_ms >= FINAL_DRAIN_MS) break;

                WSFrameInfo frame;
                while (ws_frame_cons.try_consume(frame)) {
                    total_frames++;
                    if (frame.opcode == 0x01) {
                        text_frames++;
                        if (frame.payload_len > 0) {
                            const uint8_t* payload = msg_inbox_->data_at(frame.msg_inbox_offset);
                            if (is_valid_trade_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                                valid_trades++;
                            }
                        }
                    }
                }
                usleep(1000);
            }
        }

        auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();

        printf("\n=== Test Results ===\n");
        printf("  Duration:        %ld ms\n", actual_duration);
        printf("  Total frames:    %lu\n", total_frames);
        printf("  TEXT frames:     %lu\n", text_frames);
        printf("  BINARY frames:   %lu\n", binary_frames);
        printf("  PING frames:     %lu\n", ping_frames);
        printf("  PONG frames:     %lu\n", pong_frames);
        printf("  CLOSE frames:    %lu\n", close_frames);
        printf("  Valid trades:    %lu\n", valid_trades);
        printf("  Sequence errors: %s\n", sequence_error ? "YES" : "none");

        // Verify ring buffer status
        printf("\n--- Ring Buffer Status ---\n");

        int64_t ws_frame_prod = ws_frame_info_region_->producer_published()->load(std::memory_order_acquire);
        int64_t ws_frame_cons_seq = ws_frame_cons.sequence();
        bool ws_frame_caught_up = ws_frame_cons_seq >= ws_frame_prod;
        printf("  WS_FRAME_INFO producer: %ld, consumer: %ld\n", ws_frame_prod, ws_frame_cons_seq);
        printf("  Consumer caught up: %s\n", ws_frame_caught_up ? "yes" : "NO - FAIL");

        int64_t meta_prod = msg_metadata_region_->producer_published()->load(std::memory_order_acquire);
        int64_t meta_cons = msg_metadata_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        printf("  MSG_METADATA producer: %ld, consumer: %ld\n", meta_prod, meta_cons);

        int64_t pongs_prod = pongs_region_->producer_published()->load(std::memory_order_acquire);
        int64_t pongs_cons = pongs_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        printf("  PONGS producer: %ld, consumer: %ld\n", pongs_prod, pongs_cons);

        printf("====================\n");
        fflush(stdout);

        // Signal children to stop and wait
        conn_state_->shutdown_all();
        if (unified_ssl_pid_ > 0) waitpid(unified_ssl_pid_, nullptr, 0);
        if (websocket_pid_ > 0) waitpid(websocket_pid_, nullptr, 0);
        unified_ssl_pid_ = 0;
        websocket_pid_ = 0;

        // Failure conditions
        if (run_forever) {
            printf("\nFOREVER MODE: Received %lu trades over %ld ms\n",
                   valid_trades, actual_duration);
            printf("PASS: Forever mode completed (terminated by signal)\n");
            return true;
        }

        if (total_frames == 0) {
            printf("\nFAIL: No WebSocket frames received\n");
            return false;
        }

        if (valid_trades < static_cast<uint64_t>(MIN_EXPECTED_TRADES)) {
            printf("\nFAIL: Only %lu trades received (expected %d+)\n",
                   valid_trades, MIN_EXPECTED_TRADES);
            return false;
        }

        if (!ws_frame_caught_up) {
            printf("\nFAIL: WS_FRAME_INFO consumer did not catch up\n");
            return false;
        }

        if (sequence_error) {
            printf("\nFAIL: Out-of-order frame delivery detected\n");
            return false;
        }

        printf("\nPASS: WebSocket pipeline working, received %lu trades in %ld ms\n",
               valid_trades, actual_duration);
        return true;
    }

    ConnStateShm* get_conn_state() const { return conn_state_; }

private:
    // UnifiedSSL child process
    void run_unified_ssl_process(const char* url) {
        pin_to_cpu(UNIFIED_SSL_CPU_CORE);

        // Create ring adapters
        IPCRingProducer<MsgMetadata> msg_metadata_prod(*msg_metadata_region_);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);

        UnifiedSSLType unified_ssl(
            interface_,
            bpf_path_,
            url,
            msg_inbox_,
            &msg_metadata_prod,
            &pongs_cons,
            conn_state_);

        if (!unified_ssl.init()) {
            fprintf(stderr, "[UNIFIED-SSL] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        unified_ssl.run();
        unified_ssl.cleanup();
    }

    // WebSocket child process
    void run_websocket_process() {
        pin_to_cpu(WEBSOCKET_CPU_CORE);

        // Create ring adapters
        IPCRingConsumer<MsgMetadata> msg_metadata_cons(*msg_metadata_region_);
        IPCRingProducer<WSFrameInfo> ws_frame_info_prod(*ws_frame_info_region_);
        IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(*msg_outbox_region_);
        IPCRingProducer<PongFrameAligned> pongs_prod(*pongs_region_);

        WebSocketType ws_process;

        bool ok = ws_process.init(
            msg_inbox_,
            &msg_metadata_cons,
            &ws_frame_info_prod,
            &pongs_prod,
            &msg_outbox_prod,
            conn_state_);

        if (!ok) {
            fprintf(stderr, "[WS-PROCESS] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        // Wait for WS ready (98_* handles the HTTP upgrade)
        printf("[WS-PROCESS] Waiting for WS ready from UnifiedSSL...\n");
        while (!conn_state_->is_handshake_ws_ready()) {
            if (!conn_state_->is_running(PROC_WEBSOCKET)) {
                fprintf(stderr, "[WS-PROCESS] Shutdown during WS ready wait\n");
                return;
            }
            __builtin_ia32_pause();
        }
        printf("[WS-PROCESS] WS ready, starting frame parsing\n");

        // Skip handshake - 98_* already did HTTP upgrade
        // Go straight to main loop for WS frame parsing
        ws_process.run();
    }

    const char* interface_;
    const char* bpf_path_;

    IPCRingManager ipc_manager_;

    MsgInbox* msg_inbox_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    disruptor::ipc::shared_region* msg_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_metadata_region_ = nullptr;
    disruptor::ipc::shared_region* pongs_region_ = nullptr;
    disruptor::ipc::shared_region* ws_frame_info_region_ = nullptr;

    pid_t unified_ssl_pid_ = 0;
    pid_t websocket_pid_ = 0;
};

// ============================================================================
// Main
// ============================================================================

void parse_args(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            g_timeout_ms = atoi(argv[i + 1]);
            printf("[ARGS] Timeout set to %d ms%s\n",
                   g_timeout_ms, g_timeout_ms <= 0 ? " (FOREVER MODE)" : "");
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [--timeout <ms>]\n", argv[0]);
        fprintf(stderr, "NOTE: Do NOT run directly. Use: ./scripts/build_xdp.sh 98_websocket_binance.cpp\n");
        fprintf(stderr, "\nOptions:\n");
        fprintf(stderr, "  --timeout <ms>   Stream timeout (default: %d, <= 0 = forever)\n", DEFAULT_STREAM_DURATION_MS);
        fprintf(stderr, "\nArchitecture (2 processes):\n");
        fprintf(stderr, "  - UnifiedXDPSSL (core %d): XDP + TCP + SSL + WS upgrade\n", UNIFIED_SSL_CPU_CORE);
        fprintf(stderr, "  - WebSocket (core %d): WS frame parsing\n", WEBSOCKET_CPU_CORE);
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];

    parse_args(argc, argv);

    if (geteuid() == 0) {
        fprintf(stderr, "ERROR: Do NOT run as root! Use: ./scripts/build_xdp.sh 98_websocket_binance.cpp\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  WebSocket 98 Test (UnifiedSSL + WS)         \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (WSS)\n", WSS_HOST, WSS_PORT);
    printf("  Path:       %s\n", WSS_PATH);
    printf("  SSL:        %s\n", SSLPolicyType::name());
    printf("  Processes:  UnifiedSSL (core %d)\n", UNIFIED_SSL_CPU_CORE);
    printf("              WebSocket (core %d)\n", WEBSOCKET_CPU_CORE);
    if (g_timeout_ms <= 0) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
    }
    printf("==============================================\n\n");

    WebSocket98Test test(interface, bpf_path);

    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    g_conn_state = test.get_conn_state();

    if (!test.fork_processes()) {
        fprintf(stderr, "\nFATAL: Failed to fork processes\n");
        test.teardown();
        return 1;
    }

    usleep(500000);  // 500ms stabilization

    int result = 0;
    if (!test.run_stream_test()) {
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
    fprintf(stderr, "Error: Build with USE_XDP=1 USE_WOLFSSL=1\n");
    fprintf(stderr, "Example: ./scripts/build_xdp.sh 98_websocket_binance.cpp\n");
    return 1;
}

#endif  // USE_XDP
