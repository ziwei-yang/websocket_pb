// test/pipeline/24_binance_sbe_xdp.cpp
// Test WebSocketProcess with SBE binary protocol against Binance SBE stream
//
// Usage: ./test_pipeline_binance_sbe_xdp <interface> <bpf_path> [ignored...] [--timeout <ms>]
// (Called by scripts/build_xdp.sh 24_binance_sbe_xdp.cpp)
//
// Build: make build-test-pipeline-binance_sbe_xdp XDP_INTERFACE=enp108s0 USE_WOLFSSL=1
//
// This test:
// - Connects to stream-sbe.binance.com:443 (SBE binary protocol)
// - Sends X-MBX-APIKEY header via UpgradeCustomizer (BINANCE_API_KEY env var)
// - Subscribes to btcusdt@trade stream
// - Parent consumes WSFrameInfo from disruptor ring, decodes SBE, prints timeline
// - WS process uses NullAppHandler (publishes WSFrameInfo to ring, no inline decode)

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
#include <thread>
#include <unistd.h>
#include <fcntl.h>

#ifdef USE_XDP

#define DEBUG 0
#define DEBUG_IPC 0

// ============================================================================
// Compile-time toggles (from -D flags)
// Must be captured and #undef'd BEFORE including websocket_pipeline.hpp
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
#include "../../src/policy/ssl.hpp"
#include "../../src/msg/binance_sbe.hpp"

using namespace websocket::pipeline;
using namespace websocket::ssl;
namespace sbe = websocket::sbe;

// Select SSL policy based on compile-time flags
#if defined(USE_OPENSSL)
using SSLPolicyType = OpenSSLPolicy;
#elif defined(USE_WOLFSSL)
using SSLPolicyType = WolfSSLPolicy;
#else
#error "Must define USE_OPENSSL or USE_WOLFSSL"
#endif

// ============================================================================
// BinanceUpgradeCustomizer — adds X-MBX-APIKEY header from env var
// ============================================================================

struct BinanceUpgradeCustomizer {
    static void customize(const ConnStateShm*,
        std::vector<std::pair<std::string, std::string>>& headers) {
        const char* key = getenv("BINANCE_API_KEY");
        if (key && key[0]) {
            headers.emplace_back("X-MBX-APIKEY", key);
        }
    }
};

// ============================================================================
// PipelineTraits for Binance SBE
// ============================================================================

struct BinanceSBETraits : DefaultPipelineConfig {
    using SSLPolicy          = SSLPolicyType;
    using AppHandler         = NullAppHandler;
    using UpgradeCustomizer  = BinanceUpgradeCustomizer;

    static constexpr int XDP_POLL_CORE   = 2;
    static constexpr int TRANSPORT_CORE  = 4;
    static constexpr int WEBSOCKET_CORE  = 6;

    static constexpr bool ENABLE_AB      = AB_ENABLED;
    static constexpr bool AUTO_RECONNECT = RECONNECT_ENABLED;
    static constexpr bool PROFILING      = true;

    static constexpr const char* WSS_HOST = "stream-sbe.binance.com";
    static constexpr uint16_t WSS_PORT    = 443;
    static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade";
};

static_assert(PipelineTraitsConcept<BinanceSBETraits>);

// ============================================================================
// Configuration
// ============================================================================

namespace {

constexpr int DEFAULT_STREAM_DURATION_MS = 10000;   // Stream for 10 seconds
int g_timeout_ms = DEFAULT_STREAM_DURATION_MS;

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

// Write message to stdout, fall back to /dev/tty if pipe is broken
void write_tty(const char* msg, int len) {
    ssize_t wr = write(STDOUT_FILENO, msg, len);
    if (wr <= 0) {
        int fd = open("/dev/tty", O_WRONLY);
        if (fd >= 0) { (void)write(fd, msg, len); close(fd); }
    }
}

// Periodic profiling save thread (every 10 minutes)
constexpr int PROFILING_SAVE_INTERVAL_S = 600;

template<typename Pipeline>
void profiling_save_thread(Pipeline& pipeline) {
    int elapsed = 0;
    while (!g_shutdown.load(std::memory_order_acquire)) {
        usleep(1000000);  // 1s granularity
        if (g_shutdown.load(std::memory_order_acquire)) break;
        if (++elapsed >= PROFILING_SAVE_INTERVAL_S) {
            elapsed = 0;
            pipeline.save_profiling_data();
            // Print confirmation with tty fallback
            char msg[128];
            int n = snprintf(msg, sizeof(msg),
                "[PROFILING] Periodic save complete (every %d min)\n",
                PROFILING_SAVE_INTERVAL_S / 60);
            write_tty(msg, n);
        }
    }
}

}  // namespace

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [ignored...] [--timeout <ms>]\n", argv[0]);
        fprintf(stderr, "\nBinance SBE binary protocol test.\n");
        fprintf(stderr, "Requires BINANCE_API_KEY env var with Ed25519 API key.\n");
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];

    parse_args(argc, argv);

    // Check API key
    const char* api_key = getenv("BINANCE_API_KEY");
    if (!api_key || !api_key[0]) {
        fprintf(stderr, "WARNING: BINANCE_API_KEY not set. SBE stream may reject connection.\n");
    }

    if (geteuid() == 0) {
        fprintf(stderr, "ERROR: Do NOT run as root! Use build_xdp.sh which sets capabilities.\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    bool run_forever = (g_timeout_ms <= 0);

    printf("==============================================\n");
    printf("  Binance SBE Binary Protocol Test            \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (WSS)\n", BinanceSBETraits::WSS_HOST, BinanceSBETraits::WSS_PORT);
    printf("  Path:       %s\n", BinanceSBETraits::WSS_PATH);
    printf("  SSL:        %s\n", SSLPolicyType::name());
    printf("  API Key:    %s\n", (api_key && api_key[0]) ? "set" : "NOT SET");
    printf("  Dual A/B:   %s\n", AB_ENABLED ? "yes" : "no");
    printf("  Reconnect:  %s\n", RECONNECT_ENABLED ? "yes" : "no");
    if (run_forever) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
    }
    printf("==============================================\n\n");

    // Setup pipeline
    WebSocketPipeline<BinanceSBETraits> pipeline;

    if (!pipeline.setup(interface, bpf_path)) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    g_conn_state = pipeline.conn_state();

    // Set subscription JSON
    pipeline.set_subscription_json(
        R"({"method":"SUBSCRIBE","params":["btcusdt@trade"],"id":1})");

    if (!pipeline.start()) {
        fprintf(stderr, "\nFATAL: Failed to start pipeline\n");
        pipeline.shutdown();
        return 1;
    }

    // Give processes time to stabilize
    usleep(500000);  // 500ms

    // Start periodic profiling save thread
    std::thread prof_thread(profiling_save_thread<decltype(pipeline)>,
                            std::ref(pipeline));

    // ========================================================================
    // Main loop — consume WSFrameInfo from disruptor ring in parent process
    // ========================================================================

    constexpr size_t NUM_CONN = AB_ENABLED ? 2 : 1;

    // Create consumer for WS_FRAME_INFO ring
    IPCRingConsumer<WSFrameInfo> ws_frame_cons(*pipeline.ws_frame_info_region());

    uint64_t tsc_freq = pipeline.conn_state()->tsc_freq_hz;
    uint64_t prev_publish_mono_ns[NUM_CONN] = {};
    uint64_t prev_latest_poll_cycle[NUM_CONN] = {};

    uint64_t total_frames = 0;
    uint64_t text_frames = 0;
    uint64_t binary_frames = 0;
    uint64_t sbe_decode_errors = 0;

    printf("\n--- SBE Stream Test (%s) ---\n",
           run_forever ? "FOREVER MODE - Ctrl+C to stop" :
           (std::to_string(g_timeout_ms) + "ms").c_str());

    auto start_time = std::chrono::steady_clock::now();
    auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

    while (run_forever || std::chrono::steady_clock::now() < stream_end) {
        if (g_shutdown.load(std::memory_order_acquire)) {
            signal(SIGINT, SIG_IGN);
            signal(SIGQUIT, SIG_IGN);
            printf("[SBE] Shutdown signal received\n");
            break;
        }

        if (!pipeline.conn_state()->is_running(PROC_WEBSOCKET)) {
            fprintf(stderr, "[SBE] WebSocket process exited during streaming\n");
            break;
        }

        WSFrameInfo frame;
        bool end_of_batch;
        while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
            total_frames++;
            uint8_t ci = frame.connection_id;
            const uint8_t* payload = pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset);

            // Extract exchange event time from SBE binary frames
            int64_t event_time_ms = 0;
            if (frame.opcode == 0x02 && frame.payload_len >= sbe::HEADER_SIZE + 8) {
                binary_frames++;
                sbe::SBEHeader hdr;
                if (sbe::decode_header(payload, frame.payload_len, hdr)) {
                    // All Binance SBE stream types have eventTime (utcTimestampUs) at body offset 0
                    int64_t event_time_us = sbe::read_i64(payload + sbe::HEADER_SIZE);
                    event_time_ms = event_time_us / 1000;
                } else {
                    sbe_decode_errors++;
                }
            } else if (frame.opcode == 0x01) {
                text_frames++;
            }

            frame.print_timeline(tsc_freq, prev_publish_mono_ns[ci],
                                 prev_latest_poll_cycle[ci], payload, event_time_ms);
            prev_publish_mono_ns[ci] = frame.ssl_read_end_mono_ns(tsc_freq);
            prev_latest_poll_cycle[ci] = frame.latest_poll_cycle;
        }

        __builtin_ia32_pause();
    }

    // Drain remaining frames after loop exit
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;
            uint8_t ci = frame.connection_id;
            const uint8_t* payload = pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset);

            int64_t event_time_ms = 0;
            if (frame.opcode == 0x02 && frame.payload_len >= sbe::HEADER_SIZE + 8) {
                binary_frames++;
                sbe::SBEHeader hdr;
                if (sbe::decode_header(payload, frame.payload_len, hdr)) {
                    // All Binance SBE stream types have eventTime (utcTimestampUs) at body offset 0
                    event_time_ms = sbe::read_i64(payload + sbe::HEADER_SIZE) / 1000;
                } else {
                    sbe_decode_errors++;
                }
            } else if (frame.opcode == 0x01) {
                text_frames++;
            }

            frame.print_timeline(tsc_freq, prev_publish_mono_ns[ci],
                                 prev_latest_poll_cycle[ci], payload, event_time_ms);
            prev_publish_mono_ns[ci] = frame.ssl_read_end_mono_ns(tsc_freq);
            prev_latest_poll_cycle[ci] = frame.latest_poll_cycle;
        }
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    // ========================================================================
    // Shutdown summary (write to buffer, then tty fallback for broken pipes)
    // ========================================================================

    pipeline.conn_state()->shutdown_all();

    // Stop periodic profiling thread
    if (prof_thread.joinable()) prof_thread.join();

    usleep(200000);  // 200ms for processes to quiesce

    // Drain remaining frames after shutdown
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;
            uint8_t ci = frame.connection_id;
            if (frame.opcode == 0x02) binary_frames++;
            else if (frame.opcode == 0x01) text_frames++;
        }
    }

    // Save profiling data before shutdown (processes still alive, shared memory valid)
    // Redirect stdout to /dev/tty so save_profiling_data() printf is visible
    fflush(stdout);
    int saved_stdout = dup(STDOUT_FILENO);
    int tty_fd = open("/dev/tty", O_WRONLY);
    if (tty_fd >= 0) {
        dup2(tty_fd, STDOUT_FILENO);
        close(tty_fd);
    }
    pipeline.save_profiling_data();
    // Restore stdout
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }

    // Ring buffer status
    auto* ws_fi_region = pipeline.ws_frame_info_region();
    int64_t ws_frame_prod = ws_fi_region->producer_published()->load(std::memory_order_acquire);
    int64_t ws_frame_cons_seq = ws_frame_cons.sequence();

    auto* meta_region = pipeline.msg_metadata_region(0);
    int64_t meta_prod = meta_region->producer_published()->load(std::memory_order_acquire);
    int64_t meta_cons = meta_region->consumer_sequence(0)->load(std::memory_order_acquire);

    auto* outbox_region = pipeline.msg_outbox_region();
    int64_t outbox_prod = outbox_region->producer_published()->load(std::memory_order_acquire);
    int64_t outbox_cons = outbox_region->consumer_sequence(0)->load(std::memory_order_acquire);

    auto* pongs_reg = pipeline.pongs_region();
    int64_t pongs_prod = pongs_reg->producer_published()->load(std::memory_order_acquire);
    int64_t pongs_cons = pongs_reg->consumer_sequence(0)->load(std::memory_order_acquire);

    // Build summary in stack buffer (survives broken pipes from tee + Ctrl+C)
    char summary[4096];
    int pos = 0;
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n=== Shutting down ===\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n=== SBE Test Results ===\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Duration:        %ld ms\n", actual_duration);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Total frames:    %lu\n", total_frames);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Binary (SBE):    %lu\n", binary_frames);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Text (JSON):     %lu\n", text_frames);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  SBE errors:      %lu\n", sbe_decode_errors);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n--- Ring Buffer Status ---\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  WS_FRAME_INFO producer: %ld, consumer: %ld (%s)\n",
           ws_frame_prod, ws_frame_cons_seq, (ws_frame_cons_seq >= ws_frame_prod) ? "ok" : "BEHIND");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  MSG_METADATA  producer: %ld, consumer: %ld (%s)\n",
           meta_prod, meta_cons, (meta_cons >= meta_prod - 1) ? "ok" : "BEHIND");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  MSG_OUTBOX    producer: %ld, consumer: %ld (%s)\n",
           outbox_prod, outbox_cons, (outbox_cons >= outbox_prod) ? "ok" : "BEHIND");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  PONGS         producer: %ld, consumer: %ld (%s)\n",
           pongs_prod, pongs_cons, (pongs_cons >= pongs_prod) ? "ok" : "BEHIND");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "====================\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n==============================================\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  SBE TEST COMPLETE\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "==============================================\n");

    // Try stdout first; fall back to /dev/tty if pipe is broken
    fflush(stdout);
    fflush(stderr);
    ssize_t wr = write(STDOUT_FILENO, summary, pos);
    if (wr <= 0) {
        int tty_fd = open("/dev/tty", O_WRONLY);
        if (tty_fd >= 0) {
            (void)write(tty_fd, summary, pos);
            close(tty_fd);
        }
    }

    // Also save to /tmp for persistence
    {
        char path[256];
        snprintf(path, sizeof(path), "/tmp/sbe_summary_%d.txt", getpid());
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            (void)write(fd, summary, pos);
            close(fd);
        }
    }

    pipeline.shutdown();

    return 0;
}

#else  // !USE_XDP

int main() {
    fprintf(stderr, "Error: Build with USE_XDP=1 USE_WOLFSSL=1\n");
    fprintf(stderr, "Example: make build-test-pipeline-binance_sbe_xdp XDP_INTERFACE=enp108s0 USE_WOLFSSL=1\n");
    return 1;
}

#endif  // USE_XDP
