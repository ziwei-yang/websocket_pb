// test/pipeline/20_websocket_binance.cpp
// Test WebSocketProcess with XDP Poll + Transport against Binance WSS stream
//
// Usage: ./test_pipeline_websocket_binance <interface> <bpf_path> [ignored...] [--timeout <ms>]
// (Called by scripts/test_xdp.sh 20_websocket_binance.cpp)
//
// Build: make build-test-pipeline-websocket-binance USE_XDP=1 USE_WOLFSSL=1
//
// Options:
//   --timeout <ms>   Stream timeout in milliseconds (default: 5000)
//                    If <= 0, run forever and display every message received
//
// This test:
// - Forks XDP Poll (core 2), Transport (core 4), WebSocket (core 6)
// - Connects to stream.binance.com on port 443 (WSS with WolfSSL)
// - WebSocketProcess handles HTTP+WS handshake, frame parsing
// - Parent consumes WS_FRAME_INFO ring, validates JSON trade events
// - Verifies ring buffer consumers caught up
//
// Safety: Uses dedicated test interface, never touches default route

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
#include <fcntl.h>

#ifdef USE_XDP

#define DEBUG 0
#define DEBUG_IPC 0

// ============================================================================
// Compile-time toggles (from -D flags)
// Must be captured and #undef'd BEFORE including websocket_pipeline.hpp
// to prevent macro collision with Traits member names (e.g., Traits::ENABLE_AB)
// ============================================================================

#ifdef ENABLE_AB
static constexpr bool AB_ENABLED = true;
#else
static constexpr bool AB_ENABLED = false;
#endif
#undef ENABLE_AB

#ifdef ENABLE_RECONNECT
static constexpr bool RECONNECT_ENABLED = true;
#else
static constexpr bool RECONNECT_ENABLED = false;
#endif
#undef ENABLE_RECONNECT

#include "../../src/pipeline/websocket_pipeline.hpp"
#include "../../src/policy/ssl.hpp"  // OpenSSLPolicy / WolfSSLPolicy

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
// PipelineTraits for Binance
// ============================================================================

struct BinanceTraits : DefaultPipelineConfig {
    using SSLPolicy  = SSLPolicyType;
    using AppHandler = NullAppHandler;

    static constexpr int XDP_POLL_CORE   = 2;
    static constexpr int TRANSPORT_CORE  = 4;
    static constexpr int WEBSOCKET_CORE  = 6;

    static constexpr bool ENABLE_AB      = AB_ENABLED;
    static constexpr bool AUTO_RECONNECT = RECONNECT_ENABLED;
    static constexpr bool PROFILING      = true;

    static constexpr const char* WSS_HOST = "stream.binance.com";
    static constexpr uint16_t WSS_PORT    = 443;
    static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade";
};

static_assert(PipelineTraitsConcept<BinanceTraits>);

// ============================================================================
// Configuration
// ============================================================================

namespace {

// Test parameters (defaults, can be overridden by --timeout argument)
constexpr int DEFAULT_STREAM_DURATION_MS = 5000;   // Stream for 5 seconds
constexpr int FINAL_DRAIN_MS = 2000;               // Wait 2s after streaming
constexpr int MIN_EXPECTED_TRADES = 10;            // Expect at least 10 trades in 5s for BTCUSDT

// Runtime timeout (set by --timeout argument)
int g_timeout_ms = DEFAULT_STREAM_DURATION_MS;     // -1 or 0 = run forever

// Global shutdown flag and connection state pointer for signal handler
std::atomic<bool> g_shutdown{false};
ConnStateShm* g_conn_state = nullptr;

void signal_handler(int sig) {
    (void)sig;
    g_shutdown.store(true, std::memory_order_release);
    if (g_conn_state) {
        g_conn_state->shutdown_all();
    }
    const char* msg = "\n[SIGNAL] Received signal, initiating graceful shutdown...\n";
    [[maybe_unused]] auto _ = write(STDERR_FILENO, msg, strlen(msg));
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
void write_summary(const char* tag,
                   int64_t duration_ms,
                   uint64_t total_frames, uint64_t partial_events,
                   uint64_t text_frames, uint64_t binary_frames,
                   uint64_t ping_frames, uint64_t pong_frames, uint64_t close_frames,
                   uint64_t valid_trades, bool sequence_error, int64_t pong_deficit,
                   const std::vector<WSFrameInfo>& frame_records, uint64_t tsc_freq,
                   const char* dump_path,
                   int64_t ws_frame_prod, int64_t ws_frame_cons_seq,
                   int64_t meta_prod, int64_t meta_cons,
                   int64_t outbox_prod, int64_t outbox_cons,
                   int64_t pongs_prod, int64_t pongs_cons) {
    char buf[16384];
    int pos = 0;

    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== Shutting down ===\n");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== Test Results ===\n");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Duration:        %ld ms\n", duration_ms);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Total events:    %lu (ring events incl. partial)\n", total_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Partial events:  %lu\n", partial_events);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  TEXT frames:     %lu\n", text_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  BINARY frames:   %lu\n", binary_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  PING frames:     %lu\n", ping_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  PONG frames:     %lu\n", pong_frames);
    if (pong_deficit > 0) {
        pos += snprintf(buf + pos, sizeof(buf) - pos,
            "  PONG DEFICIT:    %ld (PINGs received but PONGs not queued - INVESTIGATE!)\n", pong_deficit);
    } else {
        pos += snprintf(buf + pos, sizeof(buf) - pos,
            "  PONG balance:    OK (all PINGs have corresponding PONGs queued)\n");
    }
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  CLOSE frames:    %lu\n", close_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Valid trades:    %lu\n", valid_trades);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Sequence errors: %s\n", sequence_error ? "YES" : "none");

    // NIC-to-message latency stats
    {
        std::vector<double> msg_latencies_us;
        for (const auto& r : frame_records) {
            if (r.opcode == 0x01 &&
                !r.is_fragmented() &&
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
    }

    // ssl_late + ws_late (multi-process)
    {
        std::vector<double> ssl_late_us, ws_late_us;
        for (const auto& r : frame_records) {
            if (r.opcode == 0x01 &&
                !r.is_fragmented() &&
                r.ssl_read_ct == 1 &&
                r.nic_packet_ct == 1 &&
                r.first_poll_cycle > 0 &&
                r.first_bpf_entry_ns > 0 &&
                r.payload_len >= 100 &&
                tsc_freq > 0) {
                double ns_per_cycle = 1e9 / static_cast<double>(tsc_freq);
                if (r.ssl_last_op_cycle > 0) {
                    double late_ns = static_cast<double>(
                        static_cast<int64_t>(r.ssl_last_op_cycle - r.first_poll_cycle)) * ns_per_cycle;
                    if (late_ns >= 0.0) ssl_late_us.push_back(late_ns / 1000.0);
                }
                if (r.ws_last_op_cycle > 0 && r.latest_ssl_read_end_cycle > 0) {
                    double late_ns = static_cast<double>(
                        static_cast<int64_t>(r.ws_last_op_cycle - r.latest_ssl_read_end_cycle)) * ns_per_cycle;
                    if (late_ns >= 0.0) ws_late_us.push_back(late_ns / 1000.0);
                }
            }
        }
        auto print_late = [&](const char* name, std::vector<double>& vals) {
            if (vals.empty()) {
                pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== %s: No qualifying samples ===\n", name);
                return;
            }
            std::sort(vals.begin(), vals.end());
            size_t n = vals.size();
            auto pctile = [&](double p) -> double {
                return vals[static_cast<size_t>(p / 100.0 * (n - 1))];
            };
            double sum = 0;
            for (double v : vals) sum += v;
            size_t n_late = 0, n_idle = 0;
            for (double v : vals) { if (v > 0) n_late++; else n_idle++; }
            pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== %s (1-pkt 1-ssl TEXT) (N=%zu) ===\n", name, n);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Min:    %.2f us\n", vals.front());
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P50:    %.2f us\n", pctile(50));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P90:    %.2f us\n", pctile(90));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P99:    %.2f us\n", pctile(99));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Max:    %.2f us\n", vals.back());
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Mean:   %.2f us\n", sum / n);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Late:   %zu/%zu (%.1f%%)\n", n_late, n, n > 0 ? 100.0 * n_late / n : 0.0);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Idle:   %zu/%zu (%.1f%%)\n", n_idle, n, n > 0 ? 100.0 * n_idle / n : 0.0);
        };
        print_late("ssl_late", ssl_late_us);
        print_late("ws_late", ws_late_us);
    }

    if (dump_path) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, "[FRAME-RECORDS] %s\n", dump_path);
    }

    // Ring buffer status
    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n--- Ring Buffer Status ---\n");
    bool ws_caught = ws_frame_cons_seq >= ws_frame_prod;
    bool meta_caught = meta_cons >= meta_prod - 1;
    bool outbox_caught = outbox_cons >= outbox_prod;
    bool pongs_caught = pongs_cons >= pongs_prod;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  WS_FRAME_INFO producer: %ld, consumer: %ld (%s)\n",
        ws_frame_prod, ws_frame_cons_seq, ws_caught ? "ok" : "NO - FAIL");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  MSG_METADATA  producer: %ld, consumer: %ld (%s)\n",
        meta_prod, meta_cons, meta_caught ? "ok" : "NO - FAIL");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  MSG_OUTBOX    producer: %ld, consumer: %ld (%s)\n",
        outbox_prod, outbox_cons, outbox_caught ? "ok" : "NO - FAIL");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  PONGS         producer: %ld, consumer: %ld (%s)\n",
        pongs_prod, pongs_cons, pongs_caught ? "ok" : "NO - FAIL");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "====================\n");

    fflush(stdout);
    fflush(stderr);

    ssize_t wr = write(STDOUT_FILENO, buf, pos);
    if (wr <= 0) {
        int tty_fd = open("/dev/tty", O_WRONLY);
        if (tty_fd >= 0) {
            (void)write(tty_fd, buf, pos);
            close(tty_fd);
        }
    }

    char summary_path[256];
    snprintf(summary_path, sizeof(summary_path), "/tmp/%s_summary_%d.txt", tag, getpid());
    int sfd = open(summary_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (sfd >= 0) {
        (void)write(sfd, buf, pos);
        close(sfd);
    }
}

}  // namespace

// ============================================================================
// Main
// ============================================================================

// Parse --timeout argument from argv
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
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [ignored...] [--timeout <ms>]\n", argv[0]);
        fprintf(stderr, "NOTE: Do NOT run directly. Use: ./scripts/build_xdp.sh 20_websocket_binance.cpp\n");
        fprintf(stderr, "\nOptions:\n");
        fprintf(stderr, "  --timeout <ms>   Stream timeout in milliseconds (default: %d)\n", DEFAULT_STREAM_DURATION_MS);
        fprintf(stderr, "                   If <= 0, run forever (display all messages, Ctrl+C to stop)\n");
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];

    parse_args(argc, argv);

    if (geteuid() == 0) {
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "ERROR: Do NOT run as root!\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "\nRun via the build script which sets capabilities properly:\n");
        fprintf(stderr, "  ./scripts/build_xdp.sh 20_websocket_binance.cpp\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    printf("==============================================\n");
    printf("  WebSocket Binance Test                      \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (WSS)\n", BinanceTraits::WSS_HOST, BinanceTraits::WSS_PORT);
    printf("  Path:       %s\n", BinanceTraits::WSS_PATH);
    printf("  SSL:        %s\n", SSLPolicyType::name());
    printf("  Processes:  XDP Poll (core %d)\n", BinanceTraits::XDP_POLL_CORE);
    printf("              Transport (core %d)\n", BinanceTraits::TRANSPORT_CORE);
    printf("              WebSocket (core %d)\n", BinanceTraits::WEBSOCKET_CORE);
    if (g_timeout_ms <= 0) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
        printf("  Mode:       Display all messages\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
        printf("  Expected:   %d+ trades\n", MIN_EXPECTED_TRADES);
        printf("  Drain:      %dms then check ringbuffers\n", FINAL_DRAIN_MS);
    }
    printf("==============================================\n\n");

    // Setup pipeline
    WebSocketPipeline<BinanceTraits> pipeline;

    if (!pipeline.setup(interface, bpf_path)) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    g_conn_state = pipeline.conn_state();

    if (!pipeline.start()) {
        fprintf(stderr, "\nFATAL: Failed to start pipeline\n");
        pipeline.shutdown();
        return 1;
    }

    // Give processes time to stabilize
    usleep(500000);  // 500ms

    // ========================================================================
    // Stream test
    // ========================================================================

    bool run_forever = (g_timeout_ms <= 0);
    constexpr size_t NUM_CONN = AB_ENABLED ? 2 : 1;

    if (run_forever) {
        printf("\n--- WSS Stream Test (FOREVER MODE - Ctrl+C to stop) ---\n");
    } else {
        printf("\n--- WSS Stream Test (%dms, expect %d+ trades) ---\n",
               g_timeout_ms, MIN_EXPECTED_TRADES);
    }

    // Create consumer for WS_FRAME_INFO ring
    IPCRingConsumer<WSFrameInfo> ws_frame_cons(*pipeline.ws_frame_info_region());

    // Tracking metrics
    uint64_t total_frames = 0;
    uint64_t text_frames = 0;
    uint64_t binary_frames = 0;
    uint64_t ping_frames = 0;
    uint64_t pong_frames = 0;
    uint64_t close_frames = 0;
    uint64_t valid_trades = 0;
    uint64_t partial_events = 0;
    int64_t last_sequence = -1;
    bool sequence_error = false;

    // Frame recording for latency analysis
    std::vector<WSFrameInfo> frame_records;
    frame_records.reserve(MAX_FRAME_RECORDS);
    uint64_t tsc_freq = pipeline.conn_state()->tsc_freq_hz;

    uint64_t prev_publish_mono_ns[NUM_CONN] = {};
    uint64_t prev_latest_poll_cycle[NUM_CONN] = {};

    auto start_time = std::chrono::steady_clock::now();
    auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

    printf("[WSS] Starting stream reception...\n");

    // Main streaming loop
    while (run_forever || std::chrono::steady_clock::now() < stream_end) {
        if (g_shutdown.load(std::memory_order_acquire)) {
            signal(SIGINT, SIG_IGN);
            signal(SIGQUIT, SIG_IGN);
            printf("[WSS] Shutdown signal received\n");
            break;
        }

        if (!pipeline.conn_state()->is_running(PROC_WEBSOCKET)) {
            fprintf(stderr, "[WSS] WebSocket process exited during streaming\n");
            break;
        }

        WSFrameInfo frame;
        bool end_of_batch;
        while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
            total_frames++;
            uint8_t ci = frame.connection_id;
            frame.print_timeline(tsc_freq, prev_publish_mono_ns[ci], prev_latest_poll_cycle[ci],
                                 pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset));
            prev_publish_mono_ns[ci] = frame.ssl_read_end_mono_ns(tsc_freq);
            prev_latest_poll_cycle[ci] = frame.latest_poll_cycle;

            if (frame_records.size() < MAX_FRAME_RECORDS) {
                frame_records.push_back(frame);
            }

            int64_t current_seq = ws_frame_cons.sequence();
            if (last_sequence != -1 && current_seq != last_sequence + 1) {
                fprintf(stderr, "WARN: Out-of-order frame! Expected %ld, got %ld\n",
                        last_sequence + 1, current_seq);
                sequence_error = true;
            }
            last_sequence = current_seq;

            if (frame.is_fragmented() && !frame.is_last_fragment()) {
                partial_events++;
                continue;
            }

            switch (frame.opcode) {
                case 0x01:  // TEXT
                    text_frames++;
                    if (frame.payload_len > 0) {
                        const uint8_t* payload = pipeline.msg_inbox(frame.connection_id)->data_at(frame.msg_inbox_offset);
                        if (is_valid_trade_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                            valid_trades++;
                        }
                    }
                    break;
                case 0x02: binary_frames++; break;
                case 0x09: ping_frames++; break;
                case 0x0A: pong_frames++; break;
                case 0x08:
                    close_frames++;
                    printf("[CLOSE] Received CLOSE frame\n");
                    break;
                default: break;
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
                uint8_t ci = frame.connection_id;
                frame.print_timeline(tsc_freq, prev_publish_mono_ns[ci], prev_latest_poll_cycle[ci],
                                     pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset));
                prev_publish_mono_ns[ci] = frame.ssl_read_end_mono_ns(tsc_freq);
                prev_latest_poll_cycle[ci] = frame.latest_poll_cycle;
                if (frame_records.size() < MAX_FRAME_RECORDS) {
                    frame_records.push_back(frame);
                }
                if (frame.is_fragmented() && !frame.is_last_fragment()) {
                    partial_events++;
                    continue;
                }
                if (frame.opcode == 0x01) {
                    text_frames++;
                    if (frame.payload_len > 0) {
                        const uint8_t* payload = pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset);
                        if (is_valid_trade_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                            valid_trades++;
                        }
                    }
                }
            }
            usleep(1000);
        }
    }

    // Drain remaining frames
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;
            uint8_t ci = frame.connection_id;
            frame.print_timeline(tsc_freq, prev_publish_mono_ns[ci], prev_latest_poll_cycle[ci],
                                 pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset));
            prev_publish_mono_ns[ci] = frame.ssl_read_end_mono_ns(tsc_freq);
            prev_latest_poll_cycle[ci] = frame.latest_poll_cycle;
            if (frame_records.size() < MAX_FRAME_RECORDS) {
                frame_records.push_back(frame);
            }
            if (frame.is_fragmented() && !frame.is_last_fragment()) {
                partial_events++;
                continue;
            }
            switch (frame.opcode) {
                case 0x01:
                    text_frames++;
                    if (frame.payload_len > 0) {
                        const uint8_t* payload = pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset);
                        if (is_valid_trade_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                            valid_trades++;
                        }
                    }
                    break;
                case 0x02: binary_frames++; break;
                case 0x09: ping_frames++; break;
                case 0x0A: pong_frames++; break;
                case 0x08: close_frames++; break;
                default: break;
            }
        }
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    // Save profiling data
    pipeline.save_profiling_data();

    // Dump frame records
    dump_frame_records(frame_records.data(), frame_records.size(), "binance");

    char dump_path[256];
    snprintf(dump_path, sizeof(dump_path), "/tmp/binance_frame_records_%d.bin", getpid());

    // Ring buffer status
    auto* ws_fi_region = pipeline.ws_frame_info_region();
    int64_t ws_frame_prod = ws_fi_region->producer_published()->load(std::memory_order_acquire);
    int64_t ws_frame_cons_seq = ws_frame_cons.sequence();
    int64_t meta_prod = pipeline.msg_metadata_region(0)->producer_published()->load(std::memory_order_acquire);
    int64_t meta_cons = pipeline.msg_metadata_region(0)->consumer_sequence(0)->load(std::memory_order_acquire);
    int64_t outbox_prod = pipeline.msg_outbox_region()->producer_published()->load(std::memory_order_acquire);
    int64_t outbox_cons = pipeline.msg_outbox_region()->consumer_sequence(0)->load(std::memory_order_acquire);
    int64_t pongs_prod_seq = pipeline.pongs_region()->producer_published()->load(std::memory_order_acquire);
    int64_t pongs_cons_seq = pipeline.pongs_region()->consumer_sequence(0)->load(std::memory_order_acquire);

    int64_t pongs_queued = pongs_prod_seq + 1;
    int64_t pong_deficit = static_cast<int64_t>(ping_frames) - pongs_queued;

    write_summary("binance", actual_duration,
                  total_frames, partial_events,
                  text_frames, binary_frames, ping_frames, pong_frames, close_frames,
                  valid_trades, sequence_error, pong_deficit,
                  frame_records, tsc_freq,
                  frame_records.empty() ? nullptr : dump_path,
                  ws_frame_prod, ws_frame_cons_seq,
                  meta_prod, meta_cons,
                  outbox_prod, outbox_cons,
                  pongs_prod_seq, pongs_cons_seq);

    // Shutdown pipeline
    pipeline.shutdown();

    // Determine result
    int result = 0;
    if (!run_forever) {
        bool ws_frame_caught_up = ws_frame_cons_seq >= ws_frame_prod;
        if (total_frames == 0) result = 1;
        if (valid_trades < static_cast<uint64_t>(MIN_EXPECTED_TRADES)) result = 1;
        if (!ws_frame_caught_up) result = 1;
        if (sequence_error) result = 1;
    }

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
    fprintf(stderr, "Example: make build-test-pipeline-websocket_binance USE_XDP=1 USE_WOLFSSL=1\n");
    return 1;
}

#endif  // USE_XDP
