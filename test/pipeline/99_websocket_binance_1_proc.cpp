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
#include <algorithm>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>
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
    // write() is async-signal-safe; fprintf is NOT (deadlocks if signal
    // interrupts printf, which is the common case during timeline printing)
    const char msg[] = "\n[SIGNAL] Shutting down...\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)sig;
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

// ============================================================================
// Frame Recording (NIC-to-message latency)
// ============================================================================

static constexpr size_t MAX_FRAME_RECORDS = 65536;

void dump_frame_records(const WSFrameInfo* records, size_t count, const char* tag) {
    if (count == 0) return;
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s_frame_records_%d.bin", tag, getpid());
    FILE* f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "Failed to create %s\n", path); return; }
    uint32_t n = static_cast<uint32_t>(count);
    uint32_t sz = static_cast<uint32_t>(sizeof(WSFrameInfo));
    fwrite(&n, 4, 1, f);
    fwrite(&sz, 4, 1, f);
    fwrite(records, sizeof(WSFrameInfo), count, f);
    fclose(f);
    printf("[FRAME-RECORDS] Saved %u records to %s\n", n, path);
}

// Write shutdown summary to a file that survives broken pipes (tee + Ctrl+C)
// Also writes to /dev/tty for immediate visibility if stdout pipe is dead
void write_summary(const char* tag,
                   int64_t duration_ms,
                   uint64_t total_frames, uint64_t text_frames, uint64_t ping_frames,
                   const std::vector<WSFrameInfo>& frame_records, uint64_t tsc_freq,
                   const char* dump_path,
                   int64_t ws_frame_prod, int64_t ws_frame_cons_seq) {
    // Build summary into a buffer
    char buf[8192];
    int pos = 0;

    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== Shutting down ===\n");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== Results ===\n");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Duration:      %ld ms\n", duration_ms);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Total frames:  %lu\n", total_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  TEXT frames:   %lu\n", text_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  PING frames:   %lu\n", ping_frames);

    // Latency percentiles
    std::vector<double> msg_latencies_us;
    for (const auto& r : frame_records) {
        if (r.opcode == 0x01 &&
            !r.is_fragmented &&
            r.ssl_read_ct == 1 &&
            r.nic_packet_ct == 1 &&
            r.first_poll_cycle > 0 &&
            r.ws_frame_publish_cycle > r.first_poll_cycle &&
            r.payload_len >= 100) {
            uint64_t lat_ns = cycles_to_ns(
                r.ws_frame_publish_cycle - r.first_poll_cycle, tsc_freq);
            msg_latencies_us.push_back(static_cast<double>(lat_ns) / 1000.0);
        }
    }
    if (!msg_latencies_us.empty()) {
        std::sort(msg_latencies_us.begin(), msg_latencies_us.end());
        size_t n = msg_latencies_us.size();
        auto pctile = [&](double p) -> double {
            return msg_latencies_us[static_cast<size_t>(p / 100.0 * (n - 1))];
        };
        double sum = 0;
        for (double v : msg_latencies_us) sum += v;
        pos += snprintf(buf + pos, sizeof(buf) - pos,
            "\n=== NIC-to-Message Latency (poll->publish, 1-pkt 1-ssl TEXT) (N=%zu) ===\n", n);
        pos += snprintf(buf + pos, sizeof(buf) - pos, "  Min:    %.2f us\n", msg_latencies_us.front());
        pos += snprintf(buf + pos, sizeof(buf) - pos, "  P50:    %.2f us\n", pctile(50));
        pos += snprintf(buf + pos, sizeof(buf) - pos, "  P90:    %.2f us\n", pctile(90));
        pos += snprintf(buf + pos, sizeof(buf) - pos, "  P99:    %.2f us\n", pctile(99));
        pos += snprintf(buf + pos, sizeof(buf) - pos, "  Max:    %.2f us\n", msg_latencies_us.back());
        pos += snprintf(buf + pos, sizeof(buf) - pos, "  Mean:   %.2f us\n", sum / n);
    } else {
        pos += snprintf(buf + pos, sizeof(buf) - pos,
            "\n=== NIC-to-Message Latency: No qualifying samples ===\n");
    }

    // main_late: to_time(ws_last_op_cycle) - first_bpf_entry_ns (single-process)
    {
        std::vector<double> main_late_us;
        for (const auto& r : frame_records) {
            if (r.opcode == 0x01 &&
                !r.is_fragmented &&
                r.ssl_read_ct == 1 &&
                r.nic_packet_ct == 1 &&
                r.first_poll_cycle > 0 &&
                r.first_bpf_entry_ns > 0 &&
                r.ws_last_op_cycle > 0 &&
                r.payload_len >= 100 &&
                tsc_freq > 0) {
                double ns_per_cycle = 1e9 / static_cast<double>(tsc_freq);
                double late_ns = static_cast<double>(
                    static_cast<int64_t>(r.ws_last_op_cycle - r.first_poll_cycle)) * ns_per_cycle;
                if (late_ns >= 0.0) main_late_us.push_back(late_ns / 1000.0);
            }
        }
        if (!main_late_us.empty()) {
            std::sort(main_late_us.begin(), main_late_us.end());
            size_t n = main_late_us.size();
            auto pctile = [&](double p) -> double {
                return main_late_us[static_cast<size_t>(p / 100.0 * (n - 1))];
            };
            double sum = 0;
            for (double v : main_late_us) sum += v;
            size_t n_late = 0, n_idle = 0;
            for (double v : main_late_us) { if (v > 0) n_late++; else n_idle++; }
            pos += snprintf(buf + pos, sizeof(buf) - pos,
                "\n=== main_late (1-pkt 1-ssl TEXT) (N=%zu) ===\n", n);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Min:    %.2f us\n", main_late_us.front());
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P50:    %.2f us\n", pctile(50));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P90:    %.2f us\n", pctile(90));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P99:    %.2f us\n", pctile(99));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Max:    %.2f us\n", main_late_us.back());
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Mean:   %.2f us\n", sum / n);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Late:   %zu/%zu (%.1f%%) — loop was busy when pkt arrived\n",
                n_late, n, n > 0 ? 100.0 * n_late / n : 0.0);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Idle:   %zu/%zu (%.1f%%) — loop was waiting\n",
                n_idle, n, n > 0 ? 100.0 * n_idle / n : 0.0);
        } else {
            pos += snprintf(buf + pos, sizeof(buf) - pos,
                "\n=== main_late: No qualifying samples ===\n");
        }
    }

    if (dump_path) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, "[FRAME-RECORDS] %s\n", dump_path);
    }

    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "\n  WS_FRAME_INFO: producer=%ld, consumer=%ld\n", ws_frame_prod, ws_frame_cons_seq);
    pos += snprintf(buf + pos, sizeof(buf) - pos,
        "  Consumer caught up: %s\n", (ws_frame_cons_seq >= ws_frame_prod) ? "yes" : "no");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== Test complete ===\n");

    // Flush stdio before raw write to avoid reordering
    fflush(stdout);
    fflush(stderr);

    // 1. Try stdout (works when pipe is alive / normal timeout exit)
    ssize_t wr = write(STDOUT_FILENO, buf, pos);

    // 2. If stdout write failed (broken pipe from tee + Ctrl+C), write to /dev/tty
    if (wr <= 0) {
        int tty_fd = open("/dev/tty", O_WRONLY);
        if (tty_fd >= 0) {
            (void)write(tty_fd, buf, pos);
            close(tty_fd);
        }
    }

    // 3. Always write summary to a file alongside the frame records dump
    char summary_path[256];
    snprintf(summary_path, sizeof(summary_path), "/tmp/%s_summary_%d.txt", tag, getpid());
    int sfd = open(summary_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (sfd >= 0) {
        write(sfd, buf, pos);
        close(sfd);
    }
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
    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE so tee dying doesn't kill us

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

    // Frame recording for latency analysis
    std::vector<WSFrameInfo> frame_records;
    frame_records.reserve(MAX_FRAME_RECORDS);
    uint64_t tsc_freq = conn_state->tsc_freq_hz;

    uint64_t prev_publish_mono_ns = 0;
    uint64_t prev_latest_poll_cycle = 0;

    auto start_time = std::chrono::steady_clock::now();

    printf("=== Streaming messages ===\n\n");

    // Main consumption loop
    bool run_forever = (g_timeout_ms <= 0);
    auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

    while (run_forever || std::chrono::steady_clock::now() < stream_end) {
        if (g_shutdown.load(std::memory_order_acquire)) {
            // Ignore further signals so second Ctrl+C doesn't kill before dump
            signal(SIGINT, SIG_IGN);
            signal(SIGQUIT, SIG_IGN);
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
            frame.print_timeline(tsc_freq, prev_publish_mono_ns, prev_latest_poll_cycle);
            prev_publish_mono_ns = frame.publish_time_ts;
            prev_latest_poll_cycle = frame.latest_poll_cycle;

            if (frame_records.size() < MAX_FRAME_RECORDS) {
                frame_records.push_back(frame);
            }

            if (frame.opcode == 0x01) {
                text_frames++;
            } else if (frame.opcode == 0x09) {
                ping_frames++;
            }
        }

        __builtin_ia32_pause();
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    // Drain remaining frames from ring before killing child
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;
            frame.print_timeline(tsc_freq, prev_publish_mono_ns, prev_latest_poll_cycle);
            prev_publish_mono_ns = frame.publish_time_ts;
            prev_latest_poll_cycle = frame.latest_poll_cycle;
            if (frame_records.size() < MAX_FRAME_RECORDS) {
                frame_records.push_back(frame);
            }
            if (frame.opcode == 0x01) {
                text_frames++;
            } else if (frame.opcode == 0x09) {
                ping_frames++;
            }
        }
    }

    // Shutdown child (with timeout to avoid blocking on SSL_shutdown)
    conn_state->shutdown_all();
    kill(child_pid, SIGTERM);
    {
        auto wait_start = std::chrono::steady_clock::now();
        while (true) {
            int wstatus;
            pid_t ret = waitpid(child_pid, &wstatus, WNOHANG);
            if (ret == child_pid || ret < 0) break;
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - wait_start).count();
            if (elapsed > 2000) {
                kill(child_pid, SIGKILL);
                waitpid(child_pid, nullptr, 0);
                break;
            }
            usleep(1000);
        }
    }

    // Dump frame records binary
    dump_frame_records(frame_records.data(), frame_records.size(), "binance_99");

    // Build dump path string for summary
    char dump_path[256];
    snprintf(dump_path, sizeof(dump_path), "/tmp/binance_99_frame_records_%d.bin", getpid());

    // Ring buffer status
    int64_t ws_frame_prod = ws_frame_info_region->producer_published()->load(std::memory_order_acquire);
    int64_t ws_frame_cons_seq = ws_frame_cons.sequence();

    // Write summary (survives broken pipes from tee + Ctrl+C)
    write_summary("binance_99", actual_duration,
                  total_frames, text_frames, ping_frames,
                  frame_records, tsc_freq,
                  frame_records.empty() ? nullptr : dump_path,
                  ws_frame_prod, ws_frame_cons_seq);

    // Cleanup
    delete ws_frame_info_region;
    delete pongs_region;
    munmap(msg_inbox, sizeof(MsgInbox));
    munmap(conn_state, sizeof(ConnStateShm));
    return 0;
}

#else  // !USE_XDP

int main() {
    fprintf(stderr, "This test requires USE_XDP=1\n");
    return 1;
}

#endif  // USE_XDP
