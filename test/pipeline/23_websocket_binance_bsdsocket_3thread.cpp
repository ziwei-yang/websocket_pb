// test/pipeline/23_websocket_binance_bsdsocket_3thread.cpp
// BSD Socket WebSocket Binance Test - 3-thread DedicatedSSL mode
//
// Uses BSDWebSocketPipeline launcher for IP probe, IPC ring setup, and fork orchestration.
//
// Architecture:
//   - BSD Transport Process (3-thread: RX + SSL + TX) with DedicatedSSL
//   - WebSocket Process: WS handshake + frame parsing
//
// Threading model:
//   - RX thread: recv() raw bytes -> encrypted_rx_ring
//   - SSL thread: decrypt RX via SSL_read, encrypt TX via SSL_write
//   - TX thread: encrypted_tx_ring -> send() raw bytes
//
// Usage:
//   make build-test-pipeline-websocket_binance_bsdsocket_3thread NIC_MTU=1500 USE_OPENSSL=1
//   make test-pipeline-websocket-binance-bsdsocket-3thread NIC_MTU=1500 USE_OPENSSL=1
//
// Options:
//   --timeout <ms>   Stream timeout in milliseconds (default: 5000)
//                    If <= 0, run forever (Ctrl+C to stop)

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

#include "../../src/pipeline/bsd_websocket_pipeline.hpp"
#include "../../src/policy/ssl.hpp"

using namespace websocket::pipeline;

// ============================================================================
// SSL Policy Selection (compile-time)
// ============================================================================

#if defined(USE_OPENSSL)
using SSLPolicyType = websocket::ssl::OpenSSLPolicy;
#elif defined(USE_WOLFSSL) || defined(HAVE_WOLFSSL)
using SSLPolicyType = websocket::ssl::WolfSSLPolicy;
#elif defined(USE_LIBRESSL)
using SSLPolicyType = websocket::ssl::LibreSSLPolicy;
#else
#error "Must define USE_OPENSSL, USE_WOLFSSL, or USE_LIBRESSL"
#endif

// ============================================================================
// Pipeline Traits (3-thread DedicatedSSL)
// ============================================================================

struct BinanceBSD3ThreadTraits : DefaultBSDPipelineConfig {
    using SSLPolicy          = SSLPolicyType;
    using IOPolicy           = DefaultBlockingIO;
    using SSLThreadingPolicy = DedicatedSSL;
    using AppHandler         = NullAppHandler;

    static constexpr int TRANSPORT_CORE = -1;
    static constexpr int WEBSOCKET_CORE = -1;

    static constexpr const char* WSS_HOST = "stream.binance.com";
    static constexpr uint16_t WSS_PORT = 443;
    static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade";

    static constexpr bool ENABLE_AB        = true;
    static constexpr bool AUTO_RECONNECT   = true;
};

// ============================================================================
// Configuration
// ============================================================================

namespace {

constexpr int DEFAULT_STREAM_DURATION_MS = 5000;
constexpr int FINAL_DRAIN_MS = 2000;
constexpr int MIN_EXPECTED_TRADES = 10;

int g_timeout_ms = DEFAULT_STREAM_DURATION_MS;

std::atomic<bool> g_shutdown{false};
ConnStateShm* g_conn_state = nullptr;

void signal_handler(int) {
    g_shutdown.store(true, std::memory_order_release);
    if (g_conn_state) {
        g_conn_state->shutdown_all();
    }
    const char* msg = "\n[SIGNAL] Received signal, initiating graceful shutdown...\n";
    [[maybe_unused]] auto _ = write(STDERR_FILENO, msg, strlen(msg));
}

// ============================================================================
// Validation
// ============================================================================

bool is_valid_trade_json(const char* data, size_t len) {
    std::string_view sv(data, len);
    if (sv.find("\"stream\"") == std::string_view::npos) return false;
    if (sv.find("btcusdt@trade") == std::string_view::npos) return false;
    if (sv.find("\"data\"") == std::string_view::npos) return false;
    if (sv.find("\"e\":\"trade\"") == std::string_view::npos) return false;
    return true;
}

// ============================================================================
// Frame Recording
// ============================================================================

constexpr size_t MAX_FRAME_RECORDS = 65536;

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

// ============================================================================
// Summary Output (pipe-resilient)
// ============================================================================

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

    // Poll-to-publish latency stats
    {
        std::vector<double> msg_latencies_us;
        for (const auto& r : frame_records) {
            if (r.opcode == 0x01 &&
                !r.is_fragmented() &&
                r.ssl_read_ct == 1 &&
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
                "\n=== Poll-to-Publish Latency (1-ssl TEXT) (N=%zu) ===\n", n);
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Min:    %.2f us\n", msg_latencies_us.front());
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P50:    %.2f us\n", pctile(50));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P90:    %.2f us\n", pctile(90));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  P99:    %.2f us\n", pctile(99));
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Max:    %.2f us\n", msg_latencies_us.back());
            pos += snprintf(buf + pos, sizeof(buf) - pos, "  Mean:   %.2f us\n", sum / n);
        } else {
            pos += snprintf(buf + pos, sizeof(buf) - pos,
                "\n=== Poll-to-Publish Latency: No qualifying samples ===\n");
        }
    }

    // ssl_late + ws_late
    {
        std::vector<double> ssl_late_us, ws_late_us;
        for (const auto& r : frame_records) {
            if (r.opcode == 0x01 &&
                !r.is_fragmented() &&
                r.ssl_read_ct == 1 &&
                r.first_poll_cycle > 0 &&
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
            pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== %s (1-ssl TEXT) (N=%zu) ===\n", name, n);
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

// ============================================================================
// Stream Test
// ============================================================================

bool run_stream_test(BSDWebSocketPipeline<BinanceBSD3ThreadTraits>& pipeline) {
    bool run_forever = (g_timeout_ms <= 0);

    if (run_forever) {
        printf("\n--- WSS Stream Test (FOREVER MODE - Ctrl+C to stop) ---\n");
    } else {
        printf("\n--- WSS Stream Test (%dms, expect %d+ trades) ---\n",
               g_timeout_ms, MIN_EXPECTED_TRADES);
    }

    IPCRingConsumer<WSFrameInfo> ws_frame_cons(*pipeline.ws_frame_info_region());
    MsgInbox* msg_inbox = pipeline.msg_inbox(0);
    ConnStateShm* conn_state = pipeline.conn_state();

    uint64_t total_frames = 0, text_frames = 0, binary_frames = 0;
    uint64_t ping_frames = 0, pong_frames = 0, close_frames = 0;
    uint64_t valid_trades = 0, partial_events = 0;
    int64_t last_sequence = -1;
    bool sequence_error = false;

    std::vector<WSFrameInfo> frame_records;
    frame_records.reserve(MAX_FRAME_RECORDS);
    uint64_t tsc_freq = conn_state->tsc_freq_hz;

    uint64_t prev_publish_mono_ns = 0;
    uint64_t prev_latest_poll_cycle = 0;

    auto start_time = std::chrono::steady_clock::now();
    auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

    printf("[WSS] Starting stream reception...\n");

    // Helper lambda for frame processing
    auto process_frame = [&](WSFrameInfo& frame) {
        total_frames++;
        frame.print_timeline(tsc_freq, prev_publish_mono_ns, prev_latest_poll_cycle,
                             msg_inbox->data_at(frame.msg_inbox_offset));
        prev_publish_mono_ns = frame.ssl_read_end_mono_ns(tsc_freq);
        prev_latest_poll_cycle = frame.latest_poll_cycle;

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
            return;
        }

        switch (frame.opcode) {
            case 0x01:
                text_frames++;
                if (frame.payload_len > 0) {
                    const uint8_t* payload = msg_inbox->data_at(frame.msg_inbox_offset);
                    if (is_valid_trade_json(reinterpret_cast<const char*>(payload), frame.payload_len))
                        valid_trades++;
                }
                break;
            case 0x02: binary_frames++; break;
            case 0x09: ping_frames++; break;
            case 0x0A: pong_frames++; break;
            case 0x08: close_frames++; printf("[CLOSE] Received CLOSE frame\n"); break;
            default: break;
        }
    };

    // Main streaming loop
    while (run_forever || std::chrono::steady_clock::now() < stream_end) {
        if (g_shutdown.load(std::memory_order_acquire)) {
            signal(SIGINT, SIG_IGN);
            signal(SIGQUIT, SIG_IGN);
            printf("[WSS] Shutdown signal received\n");
            break;
        }

        if (!conn_state->is_running(PROC_WEBSOCKET)) {
            fprintf(stderr, "[WSS] WebSocket process exited during streaming\n");
            break;
        }

        WSFrameInfo frame;
        bool end_of_batch;
        while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
            process_frame(frame);
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
                process_frame(frame);
            }
            usleep(1000);
        }
    }

    // Drain remaining
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            process_frame(frame);
        }
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    dump_frame_records(frame_records.data(), frame_records.size(), "bsd_binance");

    char dump_path[256];
    snprintf(dump_path, sizeof(dump_path), "/tmp/bsd_binance_frame_records_%d.bin", getpid());

    // Ring buffer status
    auto* ws_fi_region = pipeline.ws_frame_info_region();
    auto* meta_region = pipeline.msg_metadata_region(0);
    auto* outbox_region = pipeline.msg_outbox_region();
    auto* pongs_region = pipeline.pongs_region();

    int64_t ws_frame_prod = ws_fi_region->producer_published()->load(std::memory_order_acquire);
    int64_t ws_frame_cons_seq = ws_frame_cons.sequence();
    int64_t meta_prod = meta_region->producer_published()->load(std::memory_order_acquire);
    int64_t meta_cons = meta_region->consumer_sequence(0)->load(std::memory_order_acquire);
    int64_t outbox_prod = outbox_region->producer_published()->load(std::memory_order_acquire);
    int64_t outbox_cons = outbox_region->consumer_sequence(0)->load(std::memory_order_acquire);
    int64_t pongs_prod_seq = pongs_region->producer_published()->load(std::memory_order_acquire);
    int64_t pongs_cons_seq = pongs_region->consumer_sequence(0)->load(std::memory_order_acquire);

    int64_t pongs_queued = pongs_prod_seq + 1;
    int64_t pong_deficit = static_cast<int64_t>(ping_frames) - pongs_queued;

    write_summary("bsd_binance", actual_duration,
                  total_frames, partial_events,
                  text_frames, binary_frames, ping_frames, pong_frames, close_frames,
                  valid_trades, sequence_error, pong_deficit,
                  frame_records, tsc_freq,
                  frame_records.empty() ? nullptr : dump_path,
                  ws_frame_prod, ws_frame_cons_seq,
                  meta_prod, meta_cons,
                  outbox_prod, outbox_cons,
                  pongs_prod_seq, pongs_cons_seq);

    if (run_forever) return true;

    bool ws_frame_caught_up = ws_frame_cons_seq >= ws_frame_prod;
    if (total_frames == 0) return false;
    if (valid_trades < static_cast<uint64_t>(MIN_EXPECTED_TRADES)) return false;
    if (!ws_frame_caught_up) return false;
    if (sequence_error) return false;
    return true;
}

// ============================================================================
// Argument Parsing
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

}  // namespace

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    parse_args(argc, argv);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    printf("==============================================\n");
    printf("  BSD Socket WebSocket Binance Test (3-thread)\n");
    printf("==============================================\n");
    printf("  Target:     %s:%u (WSS)\n", BinanceBSD3ThreadTraits::WSS_HOST, BinanceBSD3ThreadTraits::WSS_PORT);
    printf("  Path:       %s\n", BinanceBSD3ThreadTraits::WSS_PATH);
    printf("  SSL:        %s\n", SSLPolicyType::name());
    printf("  Threading:  3-thread (DedicatedSSL)\n");
    printf("  Processes:  BSD Transport + WebSocket\n");
    if (g_timeout_ms <= 0) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
        printf("  Mode:       Display all messages\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
        printf("  Expected:   %d+ trades\n", MIN_EXPECTED_TRADES);
        printf("  Drain:      %dms then check ringbuffers\n", FINAL_DRAIN_MS);
    }
    printf("==============================================\n\n");

    BSDWebSocketPipeline<BinanceBSD3ThreadTraits> pipeline;

    if (!pipeline.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    g_conn_state = pipeline.conn_state();

    if (!pipeline.start()) {
        fprintf(stderr, "\nFATAL: Failed to start pipeline\n");
        pipeline.shutdown();
        return 1;
    }

    usleep(500000);  // 500ms stabilization

    int result = 0;
    if (!run_stream_test(pipeline)) {
        result = 1;
    }

    pipeline.shutdown();

    printf("\n==============================================\n");
    if (result == 0) {
        printf("  TEST PASSED\n");
    } else {
        printf("  TEST FAILED\n");
    }
    printf("==============================================\n");

    return result;
}
