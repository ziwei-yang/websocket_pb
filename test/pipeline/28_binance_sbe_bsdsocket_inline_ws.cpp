// test/pipeline/28_binance_sbe_bsdsocket_inline_ws.cpp
// BSD Socket Binance SBE Test - InlineWS mode (transport + WS in single process)
//
// Uses BSDWebSocketPipeline launcher with INLINE_WS=true.
// Transport embeds WSCore directly — no IPC rings between transport and WS,
// no separate WS process fork. Only 1 child process.
//
// Architecture:
//   - InlineWS Transport Process (1-thread: recv → decrypt → WS parse → WSFrameInfo ring)
//   - Parent Process: consume WSFrameInfo ring, SBE decode + print_timeline
//
// Usage:
//   make build-test-pipeline-binance_sbe_bsdsocket_inline_ws NIC_MTU=1500 USE_OPENSSL=1
//   OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES BINANCE_API_KEY=<key> \
//     ./build/test_pipeline_binance_sbe_bsdsocket_inline_ws --timeout 10000
//
// Options:
//   --timeout <ms>   Stream timeout in milliseconds (default: 10000)
//                    If <= 0, run forever (Ctrl+C to stop)

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
#include <unistd.h>
#include <fcntl.h>

#include "../../src/pipeline/bsd_websocket_pipeline.hpp"
#include "../../src/policy/ssl.hpp"
#include "../../src/msg/00_binance_spot_sbe.hpp"
#include "../../src/msg/mkt_event.hpp"

using namespace websocket::pipeline;
namespace sbe = websocket::sbe;

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
// SBEAppHandler — inline market data processing in WS core
// ============================================================================

struct SBEAppHandler {
    static constexpr bool enabled = true;
    IPCRingProducer<websocket::msg::MktEvent>* mkt_event_prod = nullptr;
    ConnStateShm* conn_state = nullptr;
    int64_t last_book_seq_ = 0;
    int64_t last_trade_id_ = 0;
    uint8_t active_ci_ = 0xFF;
    WSFrameInfo* current_info_ = nullptr;

    void on_ws_frame(uint8_t ci, uint8_t, const uint8_t* payload,
                     uint32_t len, WSFrameInfo& info) {
        auto e = sbe::BinanceSpotSBEDecoder::decode_essential(payload, len);
        if (!e.valid) {
            info.set_mkt_event_info(
                static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS), 0);
            return;
        }

        // Set type early from decode_essential — full decode may refine count later
        switch (e.msg_type) {
        case sbe::TRADES_STREAM:
            info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY),
                                    static_cast<uint8_t>(e.count));
            break;
        case sbe::BEST_BID_ASK_STREAM:
        case sbe::DEPTH_SNAPSHOT_STREAM:
            info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT),
                                    static_cast<uint8_t>(e.count));
            break;
        case sbe::DEPTH_DIFF_STREAM:
            info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA),
                                    static_cast<uint8_t>(e.count));
            break;
        default:
            info.set_mkt_event_info(
                static_cast<uint8_t>(websocket::msg::EventType::SYSTEM_STATUS), 0);
            break;
        }

        // Fast-path: skip stale messages without full decode
        if (e.sequence > 0) {
            bool stale = (e.msg_type == sbe::TRADES_STREAM)
                ? (e.sequence <= last_trade_id_)
                : (e.sequence <= last_book_seq_);
            if (stale) {
                info.set_discard_early(true);
                return;
            }
        }

        current_info_ = &info;

        switch (e.msg_type) {
        case sbe::TRADES_STREAM: {
            sbe::TradesView tv;
            if (sbe::TradesView::decode(e.body, e.body_len, e.block_length, tv)) {
                info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY),
                                        static_cast<uint8_t>(tv.count()));
                publish_trades(ci, tv);
            }
            break;
        }
        case sbe::BEST_BID_ASK_STREAM: {
            sbe::BestBidAskView bv;
            if (sbe::BestBidAskView::decode(e.body, e.body_len, e.block_length, bv)) {
                info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT), 1);
                publish_bbo(ci, bv);
            }
            break;
        }
        case sbe::DEPTH_SNAPSHOT_STREAM: {
            sbe::DepthSnapshotView sv;
            if (sbe::DepthSnapshotView::decode(e.body, e.body_len, e.block_length, sv)) {
                info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT),
                                        static_cast<uint8_t>(sv.bids().count + sv.asks().count));
                publish_depth_snapshot(ci, sv);
            }
            break;
        }
        case sbe::DEPTH_DIFF_STREAM: {
            sbe::DepthDiffView dv;
            if (sbe::DepthDiffView::decode(e.body, e.body_len, e.block_length, dv)) {
                info.set_mkt_event_info(static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA),
                                        static_cast<uint8_t>(dv.bids().count + dv.asks().count));
                publish_depth_diff(ci, dv);
            }
            break;
        }
        }
        current_info_ = nullptr;
    }

    // Book events: deduplicate by bookUpdateId, set active connection
    void publish_bbo(uint8_t ci, const sbe::BestBidAskView& bv) {
        int64_t seq = bv.book_update_id();
        if (seq <= last_book_seq_) return;
        last_book_seq_ = seq;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& e) {
            e.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
            e.src_seq = seq;
            e.event_ts_ns = bv.event_time_us() * 1000;
            e.count = 1;
            e.count2 = 1;
            e.payload.snapshot.levels[0] = { bv.bid_price_mantissa(), bv.bid_qty_mantissa() };
            e.payload.snapshot.levels[1] = { bv.ask_price_mantissa(), bv.ask_qty_mantissa() };
        });
    }

    void publish_depth_snapshot(uint8_t ci, const sbe::DepthSnapshotView& sv) {
        int64_t seq = sv.book_update_id();
        if (seq <= last_book_seq_) return;
        last_book_seq_ = seq;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& e) {
            e.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_SNAPSHOT);
            e.flags = websocket::msg::EventFlags::SNAPSHOT;
            e.src_seq = seq;
            e.event_ts_ns = sv.event_time_us() * 1000;
            auto& sb = sv.bids();
            auto& sa = sv.asks();
            e.count = static_cast<uint8_t>(std::min<uint16_t>(sb.count, websocket::msg::MAX_BOOK_LEVELS / 2));
            e.count2 = static_cast<uint8_t>(std::min<uint16_t>(sa.count, websocket::msg::MAX_BOOK_LEVELS / 2));
            for (uint8_t i = 0; i < e.count; i++) {
                auto lv = sb.level(i);
                e.payload.snapshot.levels[i] = { lv.price_mantissa(), lv.qty_mantissa() };
            }
            for (uint8_t i = 0; i < e.count2; i++) {
                auto lv = sa.level(i);
                e.payload.snapshot.levels[e.count + i] = { lv.price_mantissa(), lv.qty_mantissa() };
            }
        });
    }

    void publish_depth_diff(uint8_t ci, const sbe::DepthDiffView& dv) {
        int64_t seq = dv.last_book_update_id();
        if (seq <= last_book_seq_) return;
        last_book_seq_ = seq;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& e) {
            e.event_type = static_cast<uint8_t>(websocket::msg::EventType::BOOK_DELTA);
            e.src_seq = seq;
            e.event_ts_ns = dv.event_time_us() * 1000;
            auto& db = dv.bids();
            auto& da = dv.asks();
            uint8_t n = 0;
            for (uint16_t i = 0; i < db.count && n < websocket::msg::MAX_DELTAS; i++, n++) {
                auto lv = db.level(i);
                auto& de = e.payload.deltas.entries[n];
                de.price = lv.price_mantissa();
                de.qty = lv.qty_mantissa();
                de.action = (lv.qty_mantissa() == 0)
                    ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
                    : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
                de.flags = 0;  // bid
            }
            for (uint16_t i = 0; i < da.count && n < websocket::msg::MAX_DELTAS; i++, n++) {
                auto lv = da.level(i);
                auto& de = e.payload.deltas.entries[n];
                de.price = lv.price_mantissa();
                de.qty = lv.qty_mantissa();
                de.action = (lv.qty_mantissa() == 0)
                    ? static_cast<uint8_t>(websocket::msg::DeltaAction::DELETE)
                    : static_cast<uint8_t>(websocket::msg::DeltaAction::UPDATE);
                de.flags = websocket::msg::DeltaFlags::SIDE_ASK;
            }
            e.count = n;
        });
    }

    void publish_trades(uint8_t ci, const sbe::TradesView& tv) {
        if (tv.count() == 0) return;
        int64_t max_id = tv.trade(tv.count() - 1).id();
        if (max_id <= last_trade_id_) return;
        last_trade_id_ = max_id;
        record_win(ci);
        publish_event([&](websocket::msg::MktEvent& e) {
            e.event_type = static_cast<uint8_t>(websocket::msg::EventType::TRADE_ARRAY);
            e.src_seq = max_id;
            e.event_ts_ns = tv.event_time_us() * 1000;
            uint8_t n = static_cast<uint8_t>(std::min<uint32_t>(tv.count(), websocket::msg::MAX_TRADES));
            e.count = n;
            for (uint8_t i = 0; i < n; i++) {
                auto t = tv.trade(i);
                auto& te = e.payload.trades.entries[i];
                te.price = t.price_mantissa();
                te.qty = t.qty_mantissa();
                te.trade_id = t.id();
                te.trade_time_ns = tv.event_time_us() * 1000;
                te.flags = t.is_buyer_maker() ? 0 : websocket::msg::TradeFlags::IS_BUYER;
            }
        });
    }

    template<typename F>
    void publish_event(F&& build) {
        if (!mkt_event_prod) return;
        int64_t slot = mkt_event_prod->try_claim();
        if (slot < 0) return;
        auto& e = (*mkt_event_prod)[slot];
        e.clear();
        e.venue_id = static_cast<uint8_t>(websocket::msg::VenueId::BINANCE);
        struct timespec ts_real, ts_mono;
        clock_gettime(CLOCK_REALTIME, &ts_real);
        clock_gettime(CLOCK_MONOTONIC, &ts_mono);
        int64_t real_ns = static_cast<int64_t>(ts_real.tv_sec) * 1000000000LL + ts_real.tv_nsec;
        int64_t mono_ns = static_cast<int64_t>(ts_mono.tv_sec) * 1000000000LL + ts_mono.tv_nsec;
        e.recv_ts_ns = real_ns;
        // Convert CLOCK_MONOTONIC NIC arrival time to CLOCK_REALTIME.
        // XDP: bpf_entry_ns (bpf_ktime_get_ns) is CLOCK_MONOTONIC.
        //      first_byte_ts = raw NIC PHC clock (NOT CLOCK_MONOTONIC) — last resort only.
        // BSD: first_byte_ts (drain_hw_timestamps converts REAL→MONO) is CLOCK_MONOTONIC.
        if (current_info_) {
            int64_t mono_arrival = 0;
            if (current_info_->latest_bpf_entry_ns > 0)
                mono_arrival = static_cast<int64_t>(current_info_->latest_bpf_entry_ns);
            else if (current_info_->first_byte_ts > 0)
                mono_arrival = static_cast<int64_t>(current_info_->first_byte_ts);
            if (mono_arrival > 0)
                e.nic_ts_ns = real_ns - (mono_ns - mono_arrival);
        }
        build(e);
        mkt_event_prod->publish(slot);
    }

    void record_win(uint8_t ci) {
        if (ci != active_ci_) {
            active_ci_ = ci;
            if (conn_state)
                conn_state->conn_priority.active_connection.store(ci, std::memory_order_release);
        }
    }
};

// ============================================================================
// Pipeline Traits (InlineWS — transport + WS in single process)
// ============================================================================

struct BinanceSBEInlineWSTraits : DefaultBSDPipelineConfig {
    using SSLPolicy          = SSLPolicyType;
    using IOPolicy           = DefaultBlockingIO;
    using SSLThreadingPolicy = SingleThreadSSL;
    using AppHandler         = SBEAppHandler;
    using UpgradeCustomizer  = BinanceUpgradeCustomizer;

    static constexpr int TRANSPORT_CORE = -1;
    static constexpr int WEBSOCKET_CORE = -1;

    static constexpr const char* WSS_HOST = "stream-sbe.binance.com";
    static constexpr uint16_t WSS_PORT    = 443;
    static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade/btcusdt@depth/btcusdt@depth20/btcusdt@bestBidAsk";

    static constexpr bool ENABLE_AB      = true;
    static constexpr bool AUTO_RECONNECT = true;
    static constexpr bool INLINE_WS      = true;   // <-- key difference
    static constexpr bool WS_FRAME_INFO_RING = true;  // publish to ring even with AppHandler
};

// ============================================================================
// Configuration
// ============================================================================

namespace {

constexpr int DEFAULT_STREAM_DURATION_MS = 10000;
constexpr int FINAL_DRAIN_MS = 2000;

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
// SBE Validation
// ============================================================================

bool validate_sbe_frame(const uint8_t* payload, uint32_t len, sbe::SBEHeader& hdr) {
    if (len < sbe::HEADER_SIZE) return false;
    if (!sbe::decode_header(payload, len, hdr)) return false;
    if (hdr.template_id != sbe::TRADES_STREAM &&
        hdr.template_id != sbe::BEST_BID_ASK_STREAM &&
        hdr.template_id != sbe::DEPTH_SNAPSHOT_STREAM &&
        hdr.template_id != sbe::DEPTH_DIFF_STREAM) return false;

    const uint8_t* body = payload + sbe::HEADER_SIZE;
    size_t body_len = len - sbe::HEADER_SIZE;

    // All SBE messages have eventTime (int64 us) at body offset 0
    if (body_len < 8) return false;
    int64_t event_time_us = sbe::read_i64(body);
    // Sanity: after 2020-01-01 in microseconds
    if (event_time_us < 1577836800000000LL) return false;

    if (hdr.template_id == sbe::TRADES_STREAM) {
        sbe::TradesView tv;
        if (!sbe::TradesView::decode(body, body_len, hdr.block_length, tv)) return false;
        if (tv.count() == 0) return false;
        auto t0 = tv.trade(0);
        if (t0.price_mantissa() <= 0 || t0.qty_mantissa() <= 0) return false;
    } else if (hdr.template_id == sbe::BEST_BID_ASK_STREAM) {
        sbe::BestBidAskView bv;
        if (!sbe::BestBidAskView::decode(body, body_len, hdr.block_length, bv)) return false;
        if (bv.bid_price_mantissa() <= 0 || bv.ask_price_mantissa() <= 0) return false;
    }

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
                   uint64_t sbe_valid_events, uint64_t sbe_decode_errors,
                   bool sequence_error,
                   const std::vector<WSFrameInfo>& frame_records, uint64_t tsc_freq,
                   const char* dump_path,
                   int64_t ws_frame_prod, int64_t ws_frame_cons_seq) {
    char buf[16384];
    int pos = 0;

    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== Shutting down ===\n");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== SBE InlineWS Test Results ===\n");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Duration:        %ld ms\n", duration_ms);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Total events:    %lu (ring events incl. partial)\n", total_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Partial events:  %lu\n", partial_events);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  TEXT frames:     %lu\n", text_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  BINARY frames:   %lu\n", binary_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  PING frames:     %lu\n", ping_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  PONG frames:     %lu\n", pong_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  CLOSE frames:    %lu\n", close_frames);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  SBE valid:       %lu\n", sbe_valid_events);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  SBE errors:      %lu\n", sbe_decode_errors);
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  Sequence errors: %s\n", sequence_error ? "YES" : "none");

    // Poll-to-publish latency stats (BINARY frames only)
    {
        std::vector<double> msg_latencies_us;
        for (const auto& r : frame_records) {
            if (r.opcode == 0x02 &&
                !r.is_fragmented() &&
                r.ssl_read_ct == 1 &&
                r.first_poll_cycle > 0 &&
                r.ws_frame_publish_cycle > r.first_poll_cycle &&
                r.payload_len >= 16) {
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
                "\n=== Poll-to-Publish Latency (1-ssl BINARY) (N=%zu) ===\n", n);
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
            if (r.opcode == 0x02 &&
                !r.is_fragmented() &&
                r.ssl_read_ct == 1 &&
                r.first_poll_cycle > 0 &&
                r.payload_len >= 16 &&
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
            pos += snprintf(buf + pos, sizeof(buf) - pos, "\n=== %s (1-ssl BINARY) (N=%zu) ===\n", name, n);
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

    // Ring buffer status (InlineWS: only ws_frame_info ring exists)
    pos += snprintf(buf + pos, sizeof(buf) - pos, "\n--- Ring Buffer Status (InlineWS) ---\n");
    bool ws_caught = ws_frame_cons_seq >= ws_frame_prod;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  WS_FRAME_INFO producer: %ld, consumer: %ld (%s)\n",
        ws_frame_prod, ws_frame_cons_seq, ws_caught ? "ok" : "NO - FAIL");
    pos += snprintf(buf + pos, sizeof(buf) - pos, "  (No msg_metadata/pongs rings — InlineWS; msg_outbox available for client sends)\n");
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

bool run_stream_test(BSDWebSocketPipeline<BinanceSBEInlineWSTraits>& pipeline) {
    bool run_forever = (g_timeout_ms <= 0);

    if (run_forever) {
        printf("\n--- SBE InlineWS Stream Test (FOREVER MODE - Ctrl+C to stop) ---\n");
    } else {
        printf("\n--- SBE InlineWS Stream Test (%dms) ---\n", g_timeout_ms);
    }

    IPCRingConsumer<WSFrameInfo> ws_frame_cons(*pipeline.ws_frame_info_region());
    std::unique_ptr<IPCRingConsumer<websocket::msg::MktEvent>> mkt_event_cons;
    if (pipeline.mkt_event_region()) {
        mkt_event_cons = std::make_unique<IPCRingConsumer<websocket::msg::MktEvent>>(*pipeline.mkt_event_region());
    }
    ConnStateShm* conn_state = pipeline.conn_state();

    uint64_t total_frames = 0, text_frames = 0, binary_frames = 0;
    uint64_t ping_frames = 0, pong_frames = 0, close_frames = 0;
    uint64_t sbe_valid_events = 0, sbe_decode_errors = 0, partial_events = 0;
    int64_t last_sequence = -1;
    bool sequence_error = false;

    std::vector<WSFrameInfo> frame_records;
    frame_records.reserve(MAX_FRAME_RECORDS);
    uint64_t tsc_freq = conn_state->tsc_freq_hz;

    uint64_t prev_publish_mono_ns = 0;
    uint64_t prev_latest_poll_cycle = 0;
    int64_t pending_event_time_ms[2] = {};  // per-connection carry for fragmented messages

    auto start_time = std::chrono::steady_clock::now();
    auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

    printf("[SBE] Starting stream reception...\n");

    // Helper lambda for frame processing
    auto process_frame = [&](WSFrameInfo& frame) {
        total_frames++;

        int64_t current_seq = ws_frame_cons.sequence();
        if (last_sequence != -1 && current_seq != last_sequence + 1) {
            fprintf(stderr, "WARN: Out-of-order frame! Expected %ld, got %ld\n",
                    last_sequence + 1, current_seq);
            sequence_error = true;
        }
        last_sequence = current_seq;

        auto* inbox = pipeline.msg_inbox(frame.connection_id);
        const uint8_t* payload = inbox->data_at(frame.msg_inbox_offset);

        // Extract SBE event time from binary payload (all Binance SBE messages
        // have eventTime at offset 8: 8-byte SBE header + int64 utcTimestampUs)
        auto extract_sbe_event_time_ms = [](const uint8_t* p, uint32_t len) -> int64_t {
            if (len < 16) return 0;
            uint16_t template_id, schema_id;
            std::memcpy(&template_id, p + 2, 2);
            std::memcpy(&schema_id, p + 4, 2);
            if (template_id >= 10000 && template_id <= 10003 && schema_id == 1) {
                int64_t event_time_us;
                std::memcpy(&event_time_us, p + 8, 8);
                return event_time_us / 1000;
            }
            return 0;
        };

        // Skip intermediate fragments — carry eventTime for last fragment
        if (frame.is_fragmented() && !frame.is_last_fragment()) {
            if (frame.opcode == 0x02) {
                int64_t et = extract_sbe_event_time_ms(payload, frame.payload_len);
                if (et > 0) pending_event_time_ms[frame.connection_id] = et;
            }
            prev_publish_mono_ns = frame.ssl_read_end_mono_ns(tsc_freq);
            prev_latest_poll_cycle = frame.latest_poll_cycle;
            partial_events++;
            return;
        }

        // For complete binary frames, extract from payload; for last fragments, use carried value
        int64_t event_time_ms = 0;
        if (frame.is_fragmented() && frame.is_last_fragment()) {
            event_time_ms = pending_event_time_ms[frame.connection_id];
            pending_event_time_ms[frame.connection_id] = 0;
        } else if (frame.opcode == 0x02) {
            event_time_ms = extract_sbe_event_time_ms(payload, frame.payload_len);
        }

        frame.print_timeline(tsc_freq, prev_publish_mono_ns, prev_latest_poll_cycle, payload, event_time_ms);
        prev_publish_mono_ns = frame.ssl_read_end_mono_ns(tsc_freq);
        prev_latest_poll_cycle = frame.latest_poll_cycle;

        if (mkt_event_cons) {
            websocket::msg::MktEvent mkt;
            while (mkt_event_cons->try_consume(mkt)) {
                mkt.print();
            }
        }

        if (frame_records.size() < MAX_FRAME_RECORDS) {
            frame_records.push_back(frame);
        }

        switch (frame.opcode) {
            case 0x00:  // continuation (last fragment)
                binary_frames++;
                break;
            case 0x01:
                text_frames++;
                break;
            case 0x02: {
                binary_frames++;
                const uint8_t* contig;
                bool is_contig = inbox->read_contiguous(frame.msg_inbox_offset, frame.payload_len, contig);
                sbe::SBEHeader hdr;
                if (!is_contig || validate_sbe_frame(contig, frame.payload_len, hdr)) {
                    sbe_valid_events++;
                } else {
                    sbe_decode_errors++;
                }
                // mkt.on_ws_frame() now runs inline in WSCore via SBEAppHandler
                break;
            }
            case 0x09: ping_frames++; break;
            case 0x0A: pong_frames++; break;
            case 0x08: close_frames++; printf("[CLOSE] Received CLOSE frame\n"); break;
            default: break;
        }
    };

    // Main streaming loop
    // InlineWS: only 1 child process (transport), check PROC_TRANSPORT
    while (run_forever || std::chrono::steady_clock::now() < stream_end) {
        if (g_shutdown.load(std::memory_order_acquire)) {
            signal(SIGINT, SIG_IGN);
            signal(SIGQUIT, SIG_IGN);
            printf("[SBE] Shutdown signal received\n");
            break;
        }

        if (!conn_state->is_running(PROC_TRANSPORT)) {
            fprintf(stderr, "[SBE] Transport process exited during streaming\n");
            break;
        }

        bool got_frame = false;
        WSFrameInfo frame;
        bool end_of_batch;
        while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
            process_frame(frame);
            got_frame = true;
        }

        if (got_frame) {
        }

        usleep(1000);
    }

    // Final drain
    if (!run_forever) {
        printf("[SBE] Final %dms drain...\n", FINAL_DRAIN_MS);
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
    if (mkt_event_cons) {
        websocket::msg::MktEvent mkt;
        while (mkt_event_cons->try_consume(mkt)) {
            mkt.print();
        }
    }

    auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    dump_frame_records(frame_records.data(), frame_records.size(), "bsd_sbe_inline");

    char dump_path[256];
    snprintf(dump_path, sizeof(dump_path), "/tmp/bsd_sbe_inline_frame_records_%d.bin", getpid());

    // Ring buffer status (InlineWS: only ws_frame_info ring)
    auto* ws_fi_region = pipeline.ws_frame_info_region();
    int64_t ws_frame_prod = ws_fi_region->producer_published()->load(std::memory_order_acquire);
    int64_t ws_frame_cons_seq = ws_frame_cons.sequence();

    write_summary("bsd_sbe_inline", actual_duration,
                  total_frames, partial_events,
                  text_frames, binary_frames, ping_frames, pong_frames, close_frames,
                  sbe_valid_events, sbe_decode_errors, sequence_error,
                  frame_records, tsc_freq,
                  frame_records.empty() ? nullptr : dump_path,
                  ws_frame_prod, ws_frame_cons_seq);

    if (run_forever) return true;

    bool ws_frame_caught_up = ws_frame_cons_seq >= ws_frame_prod;
    if (total_frames == 0) return false;
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

    // Check API key (required for SBE endpoint)
    const char* api_key = getenv("BINANCE_API_KEY");
    if (!api_key || !api_key[0]) {
        fprintf(stderr, "FATAL: BINANCE_API_KEY not set. SBE endpoint requires X-MBX-APIKEY header.\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);

    bool run_forever = (g_timeout_ms <= 0);

    printf("==============================================\n");
    printf("  BSD Socket Binance SBE Test (InlineWS)      \n");
    printf("==============================================\n");
    printf("  Target:     %s:%u (WSS)\n", BinanceSBEInlineWSTraits::WSS_HOST, BinanceSBEInlineWSTraits::WSS_PORT);
    printf("  Path:       %s\n", BinanceSBEInlineWSTraits::WSS_PATH);
    printf("  SSL:        %s\n", SSLPolicyType::name());
    printf("  Threading:  InlineWS (transport + WS in single process)\n");
    printf("  Processes:  1 child (transport embeds WS)\n");
    printf("  API Key:    set\n");
    printf("  Dual A/B:   yes\n");
    printf("  Reconnect:  yes\n");
    if (run_forever) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
        printf("  Drain:      %dms then check ringbuffers\n", FINAL_DRAIN_MS);
    }
    printf("==============================================\n\n");

    BSDWebSocketPipeline<BinanceSBEInlineWSTraits> pipeline;

    if (!pipeline.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    g_conn_state = pipeline.conn_state();

    // Set subscription JSON
    pipeline.set_subscription_json(
        R"({"method":"SUBSCRIBE","params":["btcusdt@trade","btcusdt@depth","btcusdt@depth20","btcusdt@bestBidAsk"],"id":1})");

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
        printf("  SBE TEST PASSED (InlineWS)\n");
    } else {
        printf("  SBE TEST FAILED (InlineWS)\n");
    }
    printf("==============================================\n");

    return result;
}
