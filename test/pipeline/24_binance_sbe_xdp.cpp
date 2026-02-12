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
// - Decodes SBE binary frames via AppHandler (zero-copy, inline in WS process)
// - Logs decoded trade fields: id, price, qty, buyer/maker, symbol

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
// BinanceSBEHandler — inline AppHandler that decodes SBE binary frames
// ============================================================================

struct BinanceSBEHandler {
    static constexpr bool enabled = true;

    // Timeline state (set before fork via pipeline.app_handler())
    uint64_t tsc_freq_hz = 0;
    uint64_t prev_publish_mono_ns[2] = {};
    uint64_t prev_latest_poll_cycle[2] = {};

    // Counters (running in WS process child — single thread, no atomics needed)
    uint64_t text_frames = 0;
    uint64_t binary_frames = 0;
    uint64_t sbe_decode_errors = 0;

    void on_ws_frame(uint8_t ci, uint8_t opcode, const uint8_t* payload,
                     uint32_t len, const WSFrameInfo& info) {
        // Text frames: JSON subscription confirmation
        if (opcode == 0x01) {
            text_frames++;
            struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
            fprintf(stderr, "[%ld.%06ld] [SBE] TEXT frame (conn %u, %u bytes): %.*s\n",
                    ts.tv_sec, ts.tv_nsec / 1000, ci, len,
                    (int)std::min(len, 512u), reinterpret_cast<const char*>(payload));
            return;
        }

        // Only process binary frames
        if (opcode != 0x02) return;
        binary_frames++;

        // Validate SBE header (size + decode check)
        sbe::SBEHeader hdr;
        if (len < sbe::HEADER_SIZE || !sbe::decode_header(payload, len, hdr)) {
            sbe_decode_errors++;
            return;
        }

        // Print compact timeline (same format as test 20)
        info.print_timeline(tsc_freq_hz, prev_publish_mono_ns[ci],
                            prev_latest_poll_cycle[ci], payload);
        prev_publish_mono_ns[ci] = info.ssl_read_end_mono_ns(tsc_freq_hz);
        prev_latest_poll_cycle[ci] = info.latest_poll_cycle;
    }
};

// ============================================================================
// PipelineTraits for Binance SBE
// ============================================================================

struct BinanceSBETraits : DefaultPipelineConfig {
    using SSLPolicy          = SSLPolicyType;
    using AppHandler         = BinanceSBEHandler;
    using UpgradeCustomizer  = BinanceUpgradeCustomizer;

    static constexpr int XDP_POLL_CORE   = 2;
    static constexpr int TRANSPORT_CORE  = 4;
    static constexpr int WEBSOCKET_CORE  = 6;

    static constexpr bool ENABLE_AB      = AB_ENABLED;
    static constexpr bool AUTO_RECONNECT = RECONNECT_ENABLED;
    static constexpr bool PROFILING      = false;

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

    // Configure AppHandler timeline (copied into WS child at fork)
    pipeline.app_handler().tsc_freq_hz = pipeline.conn_state()->tsc_freq_hz;

    if (!pipeline.start()) {
        fprintf(stderr, "\nFATAL: Failed to start pipeline\n");
        pipeline.shutdown();
        return 1;
    }

    // Give processes time to stabilize
    usleep(500000);  // 500ms

    // ========================================================================
    // Main loop — AppHandler processes frames inline in WS process.
    // Parent just waits for timeout/signal.
    // ========================================================================

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

        usleep(100000);  // 100ms — parent is idle, all work happens in WS child
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    // ========================================================================
    // Shutdown summary
    // ========================================================================

    printf("\n=== Shutting down ===\n");
    pipeline.conn_state()->shutdown_all();
    usleep(500000);  // 500ms for processes to quiesce

    // Ring buffer status
    auto* meta_region = pipeline.msg_metadata_region(0);
    int64_t meta_prod = meta_region->producer_published()->load(std::memory_order_acquire);
    int64_t meta_cons = meta_region->consumer_sequence(0)->load(std::memory_order_acquire);

    auto* outbox_region = pipeline.msg_outbox_region();
    int64_t outbox_prod = outbox_region->producer_published()->load(std::memory_order_acquire);
    int64_t outbox_cons = outbox_region->consumer_sequence(0)->load(std::memory_order_acquire);

    auto* pongs_reg = pipeline.pongs_region();
    int64_t pongs_prod = pongs_reg->producer_published()->load(std::memory_order_acquire);
    int64_t pongs_cons = pongs_reg->consumer_sequence(0)->load(std::memory_order_acquire);

    printf("\n=== SBE Test Results ===\n");
    printf("  Duration:        %ld ms\n", actual_duration);
    printf("  (Frame counts are logged by WS child process via AppHandler)\n");
    printf("\n--- Ring Buffer Status ---\n");
    printf("  MSG_METADATA  producer: %ld, consumer: %ld (%s)\n",
           meta_prod, meta_cons, (meta_cons >= meta_prod - 1) ? "ok" : "BEHIND");
    printf("  MSG_OUTBOX    producer: %ld, consumer: %ld (%s)\n",
           outbox_prod, outbox_cons, (outbox_cons >= outbox_prod) ? "ok" : "BEHIND");
    printf("  PONGS         producer: %ld, consumer: %ld (%s)\n",
           pongs_prod, pongs_cons, (pongs_cons >= pongs_prod) ? "ok" : "BEHIND");
    printf("====================\n");

    pipeline.shutdown();

    printf("\n==============================================\n");
    printf("  SBE TEST COMPLETE\n");
    printf("==============================================\n");

    return 0;
}

#else  // !USE_XDP

int main() {
    fprintf(stderr, "Error: Build with USE_XDP=1 USE_WOLFSSL=1\n");
    fprintf(stderr, "Example: make build-test-pipeline-binance_sbe_xdp XDP_INTERFACE=enp108s0 USE_WOLFSSL=1\n");
    return 1;
}

#endif  // USE_XDP
