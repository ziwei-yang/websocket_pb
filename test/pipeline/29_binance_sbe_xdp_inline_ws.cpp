// test/pipeline/29_binance_sbe_xdp_inline_ws.cpp
// XDP Binance SBE Test - InlineWS mode (transport + WS in single process)
//
// Uses WebSocketPipeline launcher with INLINE_WS=true.
// Transport embeds WSCore directly — no IPC rings between transport and WS,
// no separate WS process fork. 2 processes total (XDP Poll + Transport+WS).
//
// Architecture:
//   - XDP Poll Process (core 2): AF_XDP → RAW_INBOX ring
//   - InlineWS Transport Process (core 4): recv → decrypt → WS parse → WSFrameInfo ring
//   - Parent Process: consume WSFrameInfo ring, SBE decode + print_timeline
//
// Usage: ./test_pipeline_binance_sbe_xdp_inline_ws <interface> <bpf_path> [--timeout <ms>]
// (Called by scripts/build_xdp.sh 29_binance_sbe_xdp_inline_ws.cpp)
//
// Build: make build-test-pipeline-binance_sbe_xdp_inline_ws XDP_INTERFACE=enp108s0 USE_WOLFSSL=1 ENABLE_AB=1 ENABLE_RECONNECT=1

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

// ENABLE_RECONNECT is required for InlineWS — always force true
#ifdef ENABLE_RECONNECT
static constexpr bool RECONNECT_ENABLED = true;
#else
static constexpr bool RECONNECT_ENABLED = true;  // InlineWS requires AUTO_RECONNECT
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
// PipelineTraits for Binance SBE (InlineWS)
// ============================================================================

struct BinanceSBEInlineWSTraits : DefaultPipelineConfig {
    using SSLPolicy          = SSLPolicyType;
    using AppHandler         = NullAppHandler;
    using UpgradeCustomizer  = BinanceUpgradeCustomizer;

    static constexpr int XDP_POLL_CORE   = 2;
    static constexpr int TRANSPORT_CORE  = 4;
    static constexpr int WEBSOCKET_CORE  = 4;  // unused in InlineWS, same as transport

    static constexpr bool ENABLE_AB      = AB_ENABLED;
    static constexpr bool AUTO_RECONNECT = true;   // required for InlineWS
    static constexpr bool PROFILING      = true;
    static constexpr bool INLINE_WS      = true;   // key toggle

    static constexpr const char* WSS_HOST = "stream-sbe.binance.com";
    static constexpr uint16_t WSS_PORT    = 443;
    static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade";
};

static_assert(PipelineTraitsConcept<BinanceSBEInlineWSTraits>);

// ============================================================================
// Configuration
// ============================================================================

namespace {

constexpr int DEFAULT_STREAM_DURATION_MS = 10000;
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

void write_tty(const char* msg, int len) {
    ssize_t wr = write(STDOUT_FILENO, msg, len);
    if (wr <= 0) {
        int fd = open("/dev/tty", O_WRONLY);
        if (fd >= 0) { (void)write(fd, msg, len); close(fd); }
    }
}

constexpr int PROFILING_SAVE_INTERVAL_S = 600;

template<typename Pipeline>
void profiling_save_thread(Pipeline& pipeline) {
    int elapsed = 0;
    while (!g_shutdown.load(std::memory_order_acquire)) {
        usleep(1000000);
        if (g_shutdown.load(std::memory_order_acquire)) break;
        if (++elapsed >= PROFILING_SAVE_INTERVAL_S) {
            elapsed = 0;
            pipeline.save_profiling_data();
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
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [--timeout <ms>]\n", argv[0]);
        fprintf(stderr, "\nBinance SBE binary protocol test (InlineWS mode).\n");
        fprintf(stderr, "Requires BINANCE_API_KEY env var with Ed25519 API key.\n");
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];

    parse_args(argc, argv);

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
    printf("  Binance SBE Test (XDP InlineWS)             \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (WSS)\n", BinanceSBEInlineWSTraits::WSS_HOST, BinanceSBEInlineWSTraits::WSS_PORT);
    printf("  Path:       %s\n", BinanceSBEInlineWSTraits::WSS_PATH);
    printf("  SSL:        %s\n", SSLPolicyType::name());
    printf("  Mode:       InlineWS (transport + WS in single process)\n");
    printf("  Processes:  2 (XDP Poll + Transport+WS)\n");
    printf("  API Key:    %s\n", (api_key && api_key[0]) ? "set" : "NOT SET");
    printf("  Dual A/B:   %s\n", AB_ENABLED ? "yes" : "no");
    printf("  Reconnect:  yes (required)\n");
    if (run_forever) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
    }
    printf("==============================================\n\n");

    WebSocketPipeline<BinanceSBEInlineWSTraits> pipeline;

    if (!pipeline.setup(interface, bpf_path)) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    g_conn_state = pipeline.conn_state();

    pipeline.set_subscription_json(
        R"({"method":"SUBSCRIBE","params":["btcusdt@trade"],"id":1})");

    if (!pipeline.start()) {
        fprintf(stderr, "\nFATAL: Failed to start pipeline\n");
        pipeline.shutdown();
        return 1;
    }

    usleep(500000);  // 500ms stabilization

    std::thread prof_thread(profiling_save_thread<decltype(pipeline)>,
                            std::ref(pipeline));

    // ========================================================================
    // Main loop — consume WSFrameInfo from disruptor ring in parent process
    // ========================================================================

    constexpr size_t NUM_CONN = AB_ENABLED ? 2 : 1;

    IPCRingConsumer<WSFrameInfo> ws_frame_cons(*pipeline.ws_frame_info_region());

    uint64_t tsc_freq = pipeline.conn_state()->tsc_freq_hz;
    uint64_t prev_publish_mono_ns[NUM_CONN] = {};
    uint64_t prev_latest_poll_cycle[NUM_CONN] = {};

    uint64_t total_frames = 0, prev_total = 0;
    uint64_t text_frames = 0;
    uint64_t binary_frames = 0;
    uint64_t sbe_decode_errors = 0;

    printf("\n--- SBE InlineWS Stream Test (%s) ---\n",
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

        // InlineWS: check PROC_TRANSPORT (no separate WS process)
        if (!pipeline.conn_state()->is_running(PROC_TRANSPORT)) {
            fprintf(stderr, "[SBE] Transport process exited during streaming\n");
            break;
        }

        WSFrameInfo frame;
        bool end_of_batch;
        while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
            total_frames++;
            uint8_t ci = frame.connection_id;
            const uint8_t* payload = pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset);

            int64_t event_time_ms = 0;
            if (frame.opcode == 0x02 && frame.payload_len >= sbe::HEADER_SIZE + 8) {
                binary_frames++;
                sbe::SBEHeader hdr;
                if (sbe::decode_header(payload, frame.payload_len, hdr)) {
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

        if (total_frames == prev_total) usleep(1000);
        prev_total = total_frames;
    }

    // Drain remaining
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;
            uint8_t ci = frame.connection_id;
            if (frame.opcode == 0x02) binary_frames++;
            else if (frame.opcode == 0x01) text_frames++;
        }
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    // ========================================================================
    // Shutdown summary
    // ========================================================================

    g_shutdown.store(true, std::memory_order_release);
    pipeline.conn_state()->shutdown_all();

    if (prof_thread.joinable()) prof_thread.join();

    usleep(200000);  // 200ms for processes to quiesce

    // Drain remaining after shutdown
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;
            if (frame.opcode == 0x02) binary_frames++;
            else if (frame.opcode == 0x01) text_frames++;
        }
    }

    // Save profiling data
    fflush(stdout);
    int saved_stdout = dup(STDOUT_FILENO);
    int tty_fd = open("/dev/tty", O_WRONLY);
    if (tty_fd >= 0) {
        dup2(tty_fd, STDOUT_FILENO);
        close(tty_fd);
    }
    pipeline.save_profiling_data();
    if (saved_stdout >= 0) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }

    // Ring buffer status (InlineWS: only ws_frame_info and msg_outbox rings)
    auto* ws_fi_region = pipeline.ws_frame_info_region();
    int64_t ws_frame_prod = ws_fi_region->producer_published()->load(std::memory_order_acquire);
    int64_t ws_frame_cons_seq = ws_frame_cons.sequence();

    auto* outbox_region = pipeline.msg_outbox_region();
    int64_t outbox_prod = outbox_region->producer_published()->load(std::memory_order_acquire);
    int64_t outbox_cons = outbox_region->consumer_sequence(0)->load(std::memory_order_acquire);

    char summary[4096];
    int pos = 0;
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n=== Shutting down ===\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n=== SBE InlineWS Test Results ===\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Duration:        %ld ms\n", actual_duration);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Total frames:    %lu\n", total_frames);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Binary (SBE):    %lu\n", binary_frames);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Text (JSON):     %lu\n", text_frames);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  SBE errors:      %lu\n", sbe_decode_errors);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n--- Ring Buffer Status (InlineWS) ---\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  WS_FRAME_INFO producer: %ld, consumer: %ld (%s)\n",
           ws_frame_prod, ws_frame_cons_seq, (ws_frame_cons_seq >= ws_frame_prod) ? "ok" : "BEHIND");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  MSG_OUTBOX    producer: %ld, consumer: %ld (%s)\n",
           outbox_prod, outbox_cons, (outbox_cons >= outbox_prod) ? "ok" : "BEHIND");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  (No msg_metadata/pongs rings — InlineWS)\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "====================\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n==============================================\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  SBE INLINE_WS TEST COMPLETE\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "==============================================\n");

    fflush(stdout);
    fflush(stderr);
    ssize_t wr = write(STDOUT_FILENO, summary, pos);
    if (wr <= 0) {
        int tty_fd2 = open("/dev/tty", O_WRONLY);
        if (tty_fd2 >= 0) {
            (void)write(tty_fd2, summary, pos);
            close(tty_fd2);
        }
    }

    {
        char path[256];
        snprintf(path, sizeof(path), "/tmp/sbe_inline_ws_summary_%d.txt", getpid());
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
    fprintf(stderr, "Error: Build with USE_XDP=1 USE_WOLFSSL=1 ENABLE_AB=1 ENABLE_RECONNECT=1\n");
    fprintf(stderr, "Example: make build-test-pipeline-binance_sbe_xdp_inline_ws XDP_INTERFACE=enp108s0 USE_WOLFSSL=1 ENABLE_AB=1 ENABLE_RECONNECT=1\n");
    return 1;
}

#endif  // USE_XDP
