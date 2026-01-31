// test/pipeline/99_websocket_binance.cpp
// Test UnifiedXDPProcess - single-process XDP+TCP+SSL+WS pipeline
//
// Usage: ./test_pipeline_99_websocket_binance <interface> <bpf_path> [--timeout <ms>]
//
// Build: make build-test-pipeline-99-websocket-binance USE_XDP=1 USE_WOLFSSL=1
//
// Architecture (simpler than 20_websocket_binance.cpp):
//   Child Process (core 6): UnifiedXDPProcess (XDP + TCP + SSL + WS combined)
//   Parent Process: Consumes WS_FRAME_INFO, reads MSG_INBOX, prints latency
//
// Options:
//   --timeout <ms>   Run duration in milliseconds (default: -1 = forever)
//
// Output:
//   [MSG #N] {"e":"trade","E":1706312345678,...}
//     Exchange latency: 2.5ms

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <sched.h>

#ifdef USE_XDP

// Pipeline data structures (must be included FIRST)
#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/99_xdp_tcp_ssl_ws_process.hpp"
#include "../../src/pipeline/msg_inbox.hpp"
#include "../../src/policy/ssl.hpp"
#include "../../src/core/timing.hpp"

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

// CPU core for unified process
constexpr int UNIFIED_CPU_CORE = 6;

// Test parameters
int g_timeout_ms = -1;  // -1 = run forever

// WebSocket target (hardcoded for Binance)
static constexpr const char* WSS_URL = "wss://stream.binance.com/stream?streams=btcusdt@trade";

// Global shutdown flag
std::atomic<bool> g_shutdown{false};
ConnStateShm* g_conn_state = nullptr;

void signal_handler(int sig) {
    g_shutdown.store(true, std::memory_order_release);
    if (g_conn_state) {
        g_conn_state->shutdown_all();
    }
    fprintf(stderr, "\n[SIGNAL] Received signal %d, shutting down...\n", sig);
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

// Get current time in milliseconds
inline uint64_t get_current_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// TSC frequency calibration
uint64_t g_tsc_freq_hz = 0;

void calibrate_tsc() {
    uint64_t start_tsc = rdtsc();
    struct timespec start_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    usleep(100000);  // 100ms

    uint64_t end_tsc = rdtsc();
    struct timespec end_ts;
    clock_gettime(CLOCK_MONOTONIC, &end_ts);

    uint64_t elapsed_tsc = end_tsc - start_tsc;
    uint64_t elapsed_ns = (end_ts.tv_sec - start_ts.tv_sec) * 1000000000ULL +
                          (end_ts.tv_nsec - start_ts.tv_nsec);

    g_tsc_freq_hz = (elapsed_tsc * 1000000000ULL) / elapsed_ns;
    printf("[TSC] Calibrated: %.3f GHz\n", g_tsc_freq_hz / 1e9);
}

}  // namespace

// ============================================================================
// IPC Ring Creation (simplified)
// ============================================================================

class IPCRingManager {
public:
    IPCRingManager() {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string("unified_binance_test_") + timestamp;
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

        // Only need WS_FRAME_INFO ring for unified process
        if (!create_ring("ws_frame_info", WS_FRAME_INFO_SIZE * sizeof(WSFrameInfo),
                         sizeof(WSFrameInfo), 1)) return false;

        // Optional: PONGS ring for PONG response tracking
        if (!create_ring("pongs", PONGS_SIZE * sizeof(PongFrameAligned),
                         sizeof(PongFrameAligned), 1)) return false;

        printf("[IPC] Created ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;

        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = { "ws_frame_info", "pongs" };

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
// Main Test
// ============================================================================

int main(int argc, char** argv) {
    printf("============================================================\n");
    printf("  Unified XDP+TCP+SSL+WS Pipeline Test (99_websocket_binance)\n");
    printf("============================================================\n\n");

    // Parse arguments
    const char* interface = nullptr;
    const char* bpf_path = nullptr;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            g_timeout_ms = atoi(argv[++i]);
            continue;
        }
        if (!interface) {
            interface = argv[i];
        } else if (!bpf_path) {
            bpf_path = argv[i];
        }
    }

    if (!interface || !bpf_path) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [--timeout <ms>]\n", argv[0]);
        fprintf(stderr, "  --timeout: Run duration in ms (-1 = forever, default)\n");
        return 1;
    }

    printf("Interface: %s\n", interface);
    printf("BPF Path:  %s\n", bpf_path);
    printf("URL:       %s\n", WSS_URL);
    printf("Timeout:   %d ms\n", g_timeout_ms);
    printf("\n");

    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    // Calibrate TSC
    calibrate_tsc();

    // Create IPC rings
    IPCRingManager ipc_manager;
    if (!ipc_manager.create_all_rings()) {
        fprintf(stderr, "FAIL: Cannot create IPC rings\n");
        return 1;
    }

    // Allocate shared MsgInbox
    MsgInbox* msg_inbox = static_cast<MsgInbox*>(
        mmap(nullptr, sizeof(MsgInbox),
             PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANONYMOUS,
             -1, 0));
    if (msg_inbox == MAP_FAILED) {
        fprintf(stderr, "FAIL: Cannot allocate MsgInbox\n");
        return 1;
    }
    msg_inbox->init();
    printf("MsgInbox: %p\n", msg_inbox);

    // Allocate shared ConnStateShm
    ConnStateShm* conn_state = static_cast<ConnStateShm*>(
        mmap(nullptr, sizeof(ConnStateShm),
             PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANONYMOUS,
             -1, 0));
    if (conn_state == MAP_FAILED) {
        fprintf(stderr, "FAIL: Cannot allocate ConnStateShm\n");
        munmap(msg_inbox, sizeof(MsgInbox));
        return 1;
    }
    conn_state->init();
    conn_state->tsc_freq_hz = g_tsc_freq_hz;
    g_conn_state = conn_state;
    printf("ConnStateShm: %p\n", conn_state);

    // Open shared regions
    disruptor::ipc::shared_region* ws_frame_info_region = nullptr;
    disruptor::ipc::shared_region* pongs_region = nullptr;

    try {
        ws_frame_info_region = new disruptor::ipc::shared_region(ipc_manager.get_ring_name("ws_frame_info"));
        pongs_region = new disruptor::ipc::shared_region(ipc_manager.get_ring_name("pongs"));
    } catch (const std::exception& e) {
        fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
        munmap(msg_inbox, sizeof(MsgInbox));
        munmap(conn_state, sizeof(ConnStateShm));
        return 1;
    }

    printf("\n=== Forking unified process ===\n");

    // Fork child process for unified pipeline
    pid_t child_pid = fork();
    if (child_pid < 0) {
        fprintf(stderr, "FAIL: fork() failed\n");
        delete ws_frame_info_region;
        delete pongs_region;
        munmap(msg_inbox, sizeof(MsgInbox));
        munmap(conn_state, sizeof(ConnStateShm));
        return 1;
    }

    if (child_pid == 0) {
        // Child process: Run unified XDP+TCP+SSL+WS pipeline
        pin_to_cpu(UNIFIED_CPU_CORE);

        // Create ring producers
        IPCRingProducer<WSFrameInfo> ws_frame_info_prod(*ws_frame_info_region);
        IPCRingProducer<PongFrameAligned> pongs_prod(*pongs_region);

        // Create unified process with profiling enabled
        using UnifiedType = UnifiedXDPProcess<SSLPolicyType,
                                               IPCRingProducer<WSFrameInfo>,
                                               IPCRingProducer<PongFrameAligned>,
                                               true>;  // Profiling enabled

        UnifiedType unified(interface, bpf_path, WSS_URL,
                           msg_inbox, &ws_frame_info_prod, conn_state, &pongs_prod);

        if (!unified.init()) {
            fprintf(stderr, "[CHILD] Unified process init failed\n");
            _exit(1);
        }

        unified.run();
        unified.cleanup();
        _exit(0);
    }

    // Parent process: Consume WS_FRAME_INFO and print latency
    printf("[PARENT] Forked unified process (PID %d)\n", child_pid);

    // Wait for WS handshake to complete
    printf("[PARENT] Waiting for WebSocket handshake...\n");
    if (!conn_state->wait_for_handshake_ws_ready(30000000)) {
        fprintf(stderr, "[PARENT] Timeout waiting for WebSocket handshake\n");
        kill(child_pid, SIGTERM);
        waitpid(child_pid, nullptr, 0);
        delete ws_frame_info_region;
        delete pongs_region;
        munmap(msg_inbox, sizeof(MsgInbox));
        munmap(conn_state, sizeof(ConnStateShm));
        return 1;
    }
    printf("[PARENT] WebSocket handshake complete\n\n");

    // Create consumer for WS_FRAME_INFO ring
    IPCRingConsumer<WSFrameInfo> ws_frame_cons(*ws_frame_info_region);

    // Tracking metrics
    uint64_t total_frames = 0;
    uint64_t text_frames = 0;
    uint64_t ping_frames = 0;

    auto start_time = std::chrono::steady_clock::now();

    printf("=== Streaming messages ===\n\n");

    // Main consumption loop
    bool run_forever = (g_timeout_ms <= 0);
    auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

    while (run_forever || std::chrono::steady_clock::now() < stream_end) {
        if (g_shutdown.load(std::memory_order_acquire)) {
            printf("\n[PARENT] Shutdown signal received\n");
            break;
        }

        if (!conn_state->is_running(PROC_TRANSPORT)) {
            printf("\n[PARENT] Child process exited\n");
            break;
        }

        // Process WS_FRAME_INFO events
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;

            if (frame.opcode == 0x01) {  // TEXT
                text_frames++;

                // Read payload from MSG_INBOX
                const uint8_t* payload = msg_inbox->data_at(frame.msg_inbox_offset);

                // Parse "E" (event time) field from Binance JSON
                uint64_t event_time_ms = 0;
                const char* e_pos = strstr((const char*)payload, "\"E\":");
                if (e_pos) {
                    event_time_ms = strtoull(e_pos + 4, nullptr, 10);
                }

                // Calculate exchange latency
                int64_t exchange_latency_ms = 0;
                if (event_time_ms > 0) {
                    uint64_t local_time_ms = get_current_time_ms();
                    exchange_latency_ms = (int64_t)local_time_ms - (int64_t)event_time_ms;
                }

                // Print message and latency
                printf("[TEST-MSG] #%lu %.*s\n",
                       text_frames,
                       (int)std::min(frame.payload_len, 200u),
                       (const char*)payload);
                printf("  Exchange latency: %ld ms\n\n", exchange_latency_ms);

            } else if (frame.opcode == 0x09) {  // PING
                ping_frames++;
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start_time).count();
                printf("[PING #%lu @%lds] payload_len=%u\n\n",
                       ping_frames, elapsed, frame.payload_len);
            }
        }

        __builtin_ia32_pause();
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    // Shutdown and wait for child
    printf("\n=== Shutting down ===\n");
    conn_state->shutdown_all();
    kill(child_pid, SIGTERM);
    waitpid(child_pid, nullptr, 0);

    // Print results
    printf("\n=== Results ===\n");
    printf("  Duration:      %ld ms\n", actual_duration);
    printf("  Total frames:  %lu\n", total_frames);
    printf("  TEXT frames:   %lu\n", text_frames);
    printf("  PING frames:   %lu\n", ping_frames);

    // Ring buffer status
    int64_t ws_frame_prod = ws_frame_info_region->producer_published()->load(std::memory_order_acquire);
    int64_t ws_frame_cons_seq = ws_frame_cons.sequence();
    printf("\n  WS_FRAME_INFO: producer=%ld, consumer=%ld\n", ws_frame_prod, ws_frame_cons_seq);
    printf("  Consumer caught up: %s\n", (ws_frame_cons_seq >= ws_frame_prod) ? "yes" : "no");

    // Cleanup
    delete ws_frame_info_region;
    delete pongs_region;
    munmap(msg_inbox, sizeof(MsgInbox));
    munmap(conn_state, sizeof(ConnStateShm));

    printf("\n=== Test complete ===\n");
    return 0;
}

#else  // !USE_XDP

int main() {
    fprintf(stderr, "This test requires USE_XDP=1\n");
    return 1;
}

#endif  // USE_XDP
