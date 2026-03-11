// test/pipeline/270_binance_usdm_dpdk_packetio_inline_ws.cpp
// DPDK Direct PacketIO Binance USD-M Futures JSON Test - Single child process (no poll process)
//
// Uses WebSocketPipeline launcher with INLINE_WS=true and PacketIOType=DPDKPacketIO.
// Transport handles NIC I/O (DPDK PMD) + TCP + SSL + WS parse directly — no IPC
// ring hop between a poll process and transport. 1 child process total.
//
// Architecture:
//   - DirectIO Transport Process (core 4): DPDK PMD → recv → decrypt → WS parse → WSFrameInfo ring
//   - Parent Process: consume WSFrameInfo + MktEvent rings, simdjson decode + print_timeline
//
// Streams: btcusdt@aggTrade/btcusdt@depth20/btcusdt@depth@0ms/btcusdt@depth@100ms/btcusdt@depth/btcusdt@depth@500ms
// Public endpoint — no API key required.
//
// Usage: sudo ./test_pipeline_270_binance_usdm_dpdk_packetio_inline_ws <interface> [--timeout <ms>]
//
// Build: ENABLE_RECONNECT=1 MAX_CONN=2 USE_WOLFSSL=1 ./scripts/build_dpdk.sh 270_binance_usdm_dpdk_packetio_inline_ws.cpp
// Link: requires simdjson.o

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <thread>
#include <unistd.h>
#include <fcntl.h>

#ifdef USE_DPDK

#define DEBUG 0
#define DEBUG_IPC 0

// ============================================================================
// Compile-time toggles (from -D flags)
// Must be captured and #undef'd BEFORE including websocket_pipeline.hpp
// ============================================================================

#ifdef MAX_CONN
static constexpr size_t CONN_COUNT = MAX_CONN;
#else
static constexpr size_t CONN_COUNT = 16;  // DNS capping limits to available IPs
#endif

// ENABLE_RECONNECT is required for InlineWS — always force true
#ifdef ENABLE_RECONNECT
static constexpr bool RECONNECT_ENABLED = true;
#else
static constexpr bool RECONNECT_ENABLED = true;  // InlineWS requires AUTO_RECONNECT
#endif
#undef ENABLE_RECONNECT

#include "../../src/pipeline/websocket_pipeline.hpp"
#include "../../src/policy/ssl.hpp"
#include "../../src/msg/03_binance_usdm_simdjson.hpp"
#include "../../src/msg/mkt_event.hpp"
#include "../../src/msg/mkt_dedup.hpp"

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
// PipelineTraits for Binance USD-M Futures JSON (DPDK DirectIO — no poll process)
// ============================================================================

struct BinanceUSDMTraits : DefaultPipelineConfig {
    using SSLPolicy          = SSLPolicyType;
    using MktEventHandler    = websocket::json::BinanceUSDMSimdjsonParser;
    using UpgradeCustomizer  = NullUpgradeCustomizer;
    using PacketIOType       = DPDKPacketIO;  // Direct NIC I/O (no poll process)

    static constexpr int XDP_POLL_CORE   = 2;   // unused (no poll process)
    static constexpr int TRANSPORT_CORE  = 4;
    static constexpr int WEBSOCKET_CORE  = 4;   // unused (InlineWS)

    static constexpr size_t MAX_CONN     = CONN_COUNT;
    static constexpr bool AUTO_RECONNECT = true;   // required for InlineWS
    static constexpr bool PROFILING      = true;
    static constexpr bool INLINE_WS      = true;   // key toggle
    static constexpr bool WS_FRAME_INFO_RING = true;  // publish to ring even with MktEventHandler

    static constexpr const char* WSS_HOST = "fstream.binance.com";
    static constexpr uint16_t WSS_PORT    = 443;
    static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@aggTrade/btcusdt@depth20/btcusdt@depth@0ms/btcusdt@depth@100ms/btcusdt@depth/btcusdt@depth@500ms";
};

static_assert(PipelineTraitsConcept<BinanceUSDMTraits>);

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
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [--timeout <ms>]\n", argv[0]);
        fprintf(stderr, "\nBinance USD-M Futures JSON test (DPDK DirectIO mode).\n");
        fprintf(stderr, "Public streams — no API key required.\n");
        return 1;
    }

    const char* interface = argv[1];

    parse_args(argc, argv);

    if (geteuid() != 0) {
        fprintf(stderr, "WARN: Not running as root. DPDK may fail without capabilities.\n");
        fprintf(stderr, "      Fix: sudo setcap 'cap_ipc_lock,cap_net_admin,cap_net_raw,cap_sys_nice,cap_sys_rawio+ep' %s\n", argv[0]);
        fprintf(stderr, "      Or:  sudo %s %s ...\n", argv[0], argv[1]);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    bool run_forever = (g_timeout_ms <= 0);

    printf("==============================================\n");
    printf("  USDM JSON Test (DPDK DirectIO)              \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  I/O:        DPDK PMD (Direct — no poll process)\n");
    printf("  Target:     %s:%u (WSS)\n", BinanceUSDMTraits::WSS_HOST, BinanceUSDMTraits::WSS_PORT);
    printf("  Path:       %s\n", BinanceUSDMTraits::WSS_PATH);
    printf("  SSL:        %s\n", SSLPolicyType::name());
    printf("  Mode:       DirectIO + InlineWS (single child process)\n");
    printf("  Processes:  1 child (Transport+NIC+WS)\n");
    printf("  Streams:    btcusdt@aggTrade, depth20, depth@0ms, depth@100ms, depth (250ms default), depth@500ms\n");
    printf("  Connections: %zu\n", CONN_COUNT);
    printf("  Reconnect:  yes (required)\n");
    if (run_forever) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
    }
    printf("==============================================\n\n");

    // Setup pipeline
    WebSocketPipeline<BinanceUSDMTraits> pipeline;

    if (!pipeline.setup(interface, "/dev/null")) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    g_conn_state = pipeline.conn_state();
    pipeline.mkt_event_handler().instrument_id = 1;  // btcusdt

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
    // Main loop — consume WSFrameInfo + MktEvent from disruptor rings
    // ========================================================================

    constexpr size_t NUM_CONN = CONN_COUNT;

    // Create consumer for WS_FRAME_INFO ring
    IPCRingConsumer<WSFrameInfo> ws_frame_cons(*pipeline.ws_frame_info_region());
    std::unique_ptr<IPCRingConsumer<websocket::msg::MktEvent>> mkt_event_cons;
    if (pipeline.mkt_event_region()) {
        mkt_event_cons = std::make_unique<IPCRingConsumer<websocket::msg::MktEvent>>(*pipeline.mkt_event_region());
    }

    uint64_t tsc_freq = pipeline.conn_state()->tsc_freq_hz;
    uint64_t prev_publish_mono_ns[NUM_CONN] = {};
    uint64_t prev_latest_poll_cycle[NUM_CONN] = {};

    uint64_t total_frames = 0, prev_total = 0;
    uint64_t json_frames = 0;

    // MktEvent dedup state (shared logic from mkt_dedup.hpp)
    websocket::msg::MktDedupState<4> mkt_dedup;
    uint64_t mkt_event_count = 0;
    uint64_t discard_early_count = 0;

    printf("\n--- USDM JSON DirectIO Stream Test (%s) ---\n",
           run_forever ? "FOREVER MODE - Ctrl+C to stop" :
           (std::to_string(g_timeout_ms) + "ms").c_str());

    auto start_time = std::chrono::steady_clock::now();
    auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

    while (run_forever || std::chrono::steady_clock::now() < stream_end) {
        if (g_shutdown.load(std::memory_order_acquire)) {
            signal(SIGINT, SIG_IGN);
            signal(SIGQUIT, SIG_IGN);
            printf("[USDM] Shutdown signal received\n");
            break;
        }

        // DirectIO InlineWS: check PROC_TRANSPORT (no separate WS or poll process)
        if (!pipeline.conn_state()->is_running(PROC_TRANSPORT)) {
            fprintf(stderr, "[USDM] Transport process exited during streaming\n");
            break;
        }

        WSFrameInfo frame;
        bool end_of_batch;
        while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
            total_frames++;
            uint8_t ci = frame.connection_id;
            const uint8_t* payload = pipeline.msg_inbox(ci)->data_at(frame.msg_inbox_offset);

            if (frame.opcode == 0x01) {
                json_frames++;
                if (frame.is_discard_early()) discard_early_count++;
            }

            frame.print_timeline(tsc_freq, prev_publish_mono_ns[ci],
                                 prev_latest_poll_cycle[ci], payload);
            prev_publish_mono_ns[ci] = frame.ssl_read_end_mono_ns(tsc_freq);
            prev_latest_poll_cycle[ci] = frame.latest_poll_cycle;

            if (mkt_event_cons) {
                websocket::msg::MktEvent mkt;
                while (mkt_event_cons->try_consume(mkt)) {
                    if (mkt.is_system_status()) {
                        auto& st = mkt.payload.status;
                        const char* type_str =
                            st.status_type == 0 ? "HEARTBEAT" :
                            st.status_type == 1 ? "DISCONNECTED" :
                            st.status_type == 2 ? "RECONNECTED" : "UNKNOWN";
                        struct timespec ts;
                        clock_gettime(CLOCK_REALTIME, &ts);
                        fprintf(stderr, "[%ld.%06ld] [STATUS] %s conn=%u %s\n",
                                ts.tv_sec, ts.tv_nsec / 1000, type_str, st.connection_id, st.message);
                    } else {
                        mkt_event_count++;
                        auto dr = mkt_dedup.check(mkt);
                        if (dr.is_dup()) {
                            const char* type_str =
                                mkt.is_book_delta() ? "BOOK" :
                                mkt.is_book_snapshot() ? "SNAP" :
                                mkt.is_trade_array() ? "TRADE" : "BBO";
                            fprintf(stderr, "\033[91m[DUP] %s seq %ld (dup #%lu)\033[0m\n",
                                    type_str, mkt.src_seq, mkt_dedup.dup_count);
                        }
                        if (dr.flush_gap)
                            fprintf(stderr, "\033[33m[WARN] [FLUSH_GAP] ch=%u seq=%ld fi=%u\033[0m\n",
                                    dr.channel, mkt.src_seq, mkt.flush_index());
                        mkt.print();
                    }
                }
            }
        }

        if (total_frames == prev_total) usleep(1000);
        prev_total = total_frames;
    }

    // Drain remaining frames after loop exit
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;
            if (frame.opcode == 0x01) {
                json_frames++;
                if (frame.is_discard_early()) discard_early_count++;
            }
        }
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    // ========================================================================
    // Shutdown summary
    // ========================================================================

    g_shutdown.store(true, std::memory_order_release);
    pipeline.conn_state()->shutdown_all();

    // Stop periodic profiling thread
    if (prof_thread.joinable()) prof_thread.join();

    usleep(200000);  // 200ms for processes to quiesce

    // Drain remaining after shutdown
    {
        WSFrameInfo frame;
        while (ws_frame_cons.try_consume(frame)) {
            total_frames++;
            if (frame.opcode == 0x01) {
                json_frames++;
                if (frame.is_discard_early()) discard_early_count++;
            }
        }
    }
    if (mkt_event_cons) {
        websocket::msg::MktEvent mkt;
        while (mkt_event_cons->try_consume(mkt)) {
            if (mkt.is_system_status()) {
                auto& st = mkt.payload.status;
                const char* type_str =
                    st.status_type == 0 ? "HEARTBEAT" :
                    st.status_type == 1 ? "DISCONNECTED" :
                    st.status_type == 2 ? "RECONNECTED" : "UNKNOWN";
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                fprintf(stderr, "[%ld.%06ld] [STATUS] %s conn=%u %s\n",
                        ts.tv_sec, ts.tv_nsec / 1000, type_str, st.connection_id, st.message);
            } else {
                mkt_event_count++;
                auto dr = mkt_dedup.check(mkt);
                if (dr.flush_gap)
                    fprintf(stderr, "\033[33m[WARN] [FLUSH_GAP] ch=%u seq=%ld fi=%u\033[0m\n",
                            dr.channel, mkt.src_seq, mkt.flush_index());
                mkt.print();
            }
        }
    }

    // Save profiling data before shutdown
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

    // Ring buffer status
    auto* ws_fi_region = pipeline.ws_frame_info_region();
    int64_t ws_frame_prod = ws_fi_region->producer_published()->load(std::memory_order_acquire);
    int64_t ws_frame_cons_seq = ws_frame_cons.sequence();

    auto* outbox_region = pipeline.msg_outbox_region();
    int64_t outbox_prod = outbox_region->producer_published()->load(std::memory_order_acquire);
    int64_t outbox_cons = outbox_region->consumer_sequence(0)->load(std::memory_order_acquire);

    // Build summary in stack buffer
    char summary[4096];
    int pos = 0;
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n=== Shutting down ===\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n=== USDM JSON DirectIO Test Results (DPDK) ===\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Duration:        %ld ms\n", actual_duration);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Total frames:    %lu\n", total_frames);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  JSON frames:     %lu\n", json_frames);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  MktEvents:       %lu\n", mkt_event_count);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  MktEvent dups:   %lu%s\n", mkt_dedup.dup_count,
           mkt_dedup.dup_count > 0 ? " *** DUPLICATES DETECTED ***" : " (clean)");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  Discard early:   %lu (%.1f%% of JSON)\n",
           discard_early_count,
           json_frames > 0 ? 100.0 * discard_early_count / json_frames : 0.0);
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n--- Ring Buffer Status (DirectIO) ---\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  WS_FRAME_INFO producer: %ld, consumer: %ld (%s)\n",
           ws_frame_prod, ws_frame_cons_seq, (ws_frame_cons_seq >= ws_frame_prod) ? "ok" : "BEHIND");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  MSG_OUTBOX    producer: %ld, consumer: %ld (%s)\n",
           outbox_prod, outbox_cons, (outbox_cons >= outbox_prod) ? "ok" : "BEHIND");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  (No raw_inbox/raw_outbox/metadata/pongs rings — DirectIO + InlineWS)\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "====================\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "\n==============================================\n");
    pos += snprintf(summary + pos, sizeof(summary) - pos, "  USDM JSON DIRECT_IO TEST COMPLETE (DPDK)\n");
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

    // Also save to /tmp for persistence
    {
        char path[256];
        snprintf(path, sizeof(path), "/tmp/usdm_dpdk_directio_summary_%d.txt", getpid());
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            (void)write(fd, summary, pos);
            close(fd);
        }
    }

    pipeline.shutdown();

    return 0;
}

#else  // !USE_DPDK

int main() {
    fprintf(stderr, "Error: Build with USE_DPDK=1 USE_WOLFSSL=1 MAX_CONN=2 ENABLE_RECONNECT=1\n");
    fprintf(stderr, "Example: ENABLE_RECONNECT=1 MAX_CONN=2 USE_WOLFSSL=1 ./scripts/build_dpdk.sh 270_binance_usdm_dpdk_packetio_inline_ws.cpp\n");
    return 1;
}

#endif  // USE_DPDK
