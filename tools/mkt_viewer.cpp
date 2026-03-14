// tools/mkt_viewer.cpp
// Full-screen MktEvent ring viewer — live orderbook, trades, and event log
// Pure ANSI escape codes, no ncurses dependency.
//
// Usage:
//   ./build/mkt_viewer Binance BTC-USDT
//   Opens /dev/shm/hft/mkt_event.Binance.BTC-USDT.{hdr,dat}

#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <cmath>
#include <ctime>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <sys/ioctl.h>

#include "pipeline/pipeline_data.hpp"
#include "msg/mkt_event.hpp"
#include "msg/mkt_dedup.hpp"
#include "msg/orderbook.hpp"
#include "msg/market_conf.hpp"

using namespace websocket::msg;
using namespace websocket::pipeline;

// ============================================================================
// Constants
// ============================================================================

static constexpr int MAX_BOOK   = 30;  // matches MAX_BOOK_LEVELS in MktEvent

static const char* venue_name(uint8_t venue_id) {
    switch (venue_id) {
    case static_cast<uint8_t>(VenueId::BINANCE):      return "Binance";
    case static_cast<uint8_t>(VenueId::OKX):           return "OKX";
    case static_cast<uint8_t>(VenueId::BINANCE_USDM):  return "BinanceUSDM";
    default:                                            return nullptr;
    }
}

// Layout bounds
static constexpr int BOOK_MAX    = 10;
static constexpr int BOOK_MIN    = 4;
static constexpr int TRADE_MIN   = 2;
static constexpr int LOG_MAX     = 5;
static constexpr int LOG_MIN     = 1;
// ANSI
static constexpr const char* RST    = "\033[0m";
static constexpr const char* BOLD   = "\033[1m";
static constexpr const char* GREEN  = "\033[32m";
static constexpr const char* YELLOW = "\033[33m";
static constexpr const char* RED    = "\033[31m";
static constexpr const char* CYAN   = "\033[36m";
static constexpr const char* DIM    = "\033[2m";
static constexpr const char* BG_GREEN  = "\033[42m";
static constexpr const char* BG_YELLOW = "\033[43m";
static constexpr const char* BG_RED    = "\033[41m";
static constexpr const char* BG_CYAN   = "\033[46m";

// ============================================================================
// Data structures
// ============================================================================

static constexpr int MAX_LATENCY_SAMPLES = 65536;

struct ViewerState {
    static constexpr int DEPTH_CHANNELS = 4;
    OrderBook ob_channels[DEPTH_CHANNELS];
    MktDedupState<DEPTH_CHANNELS> dedup;
    int64_t   ob_channel_recv_ns[DEPTH_CHANNELS] = {};  // recv_ts of last depth update per channel
    int       latest_ob_channel = -1;
    int64_t   bbo_recv_ns = 0;                           // recv_ts of last BBO update
    // Cached BBO for re-application after delta
    int64_t   last_bbo_seq = 0;
    int64_t   cached_bbo_bid_price = 0, cached_bbo_bid_qty = 0;
    int64_t   cached_bbo_ask_price = 0, cached_bbo_ask_qty = 0;

    OrderBook& latest_orderbook() {
        if (latest_ob_channel >= 0) return ob_channels[latest_ob_channel];
        return ob_channels[0];
    }
    const OrderBook& latest_orderbook() const {
        if (latest_ob_channel >= 0) return ob_channels[latest_ob_channel];
        return ob_channels[0];
    }
    void update_latest_channel() {
        int best = -1;
        int64_t best_seq = -1;
        for (int i = 0; i < DEPTH_CHANNELS; i++) {
            if (dedup.ob_channel_seq[i] > best_seq) { best_seq = dedup.ob_channel_seq[i]; best = i; }
        }
        latest_ob_channel = best;
    }

    static constexpr size_t TRADE_BUF = 65536;
    static constexpr size_t TRADE_MASK = TRADE_BUF - 1;
    TradeEntry trades[TRADE_BUF];
    size_t     trade_write = 0;
    size_t     trade_count = 0;

    uint64_t   total_events = 0;
    uint64_t   snap_count = 0, delta_count = 0, bbo_count = 0, trade_msg_count = 0;

    int64_t    last_recv_ts_ns = 0;   // most recent recv timestamp (epoch ns)
    int64_t    last_event_ts_ns = 0;  // most recent exchange timestamp (epoch ns)
    int64_t    last_nic_ts_ns = 0;    // most recent NIC HW timestamp (epoch ns)

    // Latency history (recv_ts - nic_ts)
    float      latency_us[MAX_LATENCY_SAMPLES];
    size_t     latency_write = 0;
    size_t     latency_count = 0;
    float      latency_min = 0, latency_max = 0;
    int64_t    latency_max_seq = 0;  // exchange src_seq of the event that caused max latency
    double     latency_sum = 0;

    char       log_lines[64][160];
    size_t     log_write = 0;
    size_t     log_count = 0;

    // Packet interval histogram (rolling 10-minute window)
    // Buckets: 0 2 5 20 50 100 200 500 1k 2k 5k 10k 20k ns + 50us+ overflow
    static constexpr int INTERVAL_BUCKETS = 14;   // 13 buckets + 1 overflow
    static constexpr int HIST_SEGMENTS    = 60;    // 60 × 10s = 10 minutes
    static constexpr int64_t HIST_SEG_NS  = 10'000'000'000LL;  // 10s per segment

    int64_t  prev_nic_ts_ns = 0;

    struct HistSegment {
        uint32_t bins[INTERVAL_BUCKETS] = {};
        uint32_t count = 0;
    };
    HistSegment hist_segs[HIST_SEGMENTS] = {};
    int     hist_seg_cur = 0;
    int64_t hist_seg_start_ns = 0;  // start time of current segment

    // 1-minute rolling trade volume (buy/sell separate)
    static constexpr int VOL_SEGMENTS = 6;
    static constexpr int64_t VOL_SEG_NS = 10'000'000'000LL;  // 10s per segment

    struct VolSegment {
        double buy_qty  = 0;
        double sell_qty = 0;
        uint32_t buy_count  = 0;
        uint32_t sell_count = 0;
    };
    VolSegment vol_segs[VOL_SEGMENTS] = {};
    int     vol_seg_cur = 0;
    int64_t vol_seg_start_ns = 0;

    // 1-minute rolling depth average (same segment cadence as vol)
    struct DepthSegment {
        double depth_sum = 0;     // accumulated depth_sum samples
        uint32_t samples = 0;    // number of samples in this segment
    };
    DepthSegment depth_segs[VOL_SEGMENTS] = {};
    int     depth_seg_cur = 0;
    int64_t depth_seg_start_ns = 0;

    // 1-minute rolling event count (same segment cadence)
    uint32_t evt_segs[VOL_SEGMENTS] = {};
    int     evt_seg_cur = 0;
    int64_t evt_seg_start_ns = 0;

    // Perpetual contract data (detected from mark_price/liquidation events)
    bool     is_perp = false;
    uint64_t liq_count = 0;
    uint64_t mark_price_count = 0;
    // Latest mark price data
    int64_t  last_mark_price = 0;
    int64_t  last_index_price = 0;
    int64_t  last_funding_rate = 0;
    int64_t  last_next_funding_ns = 0;
    int64_t  last_mark_recv_ns = 0;
    // Liquidation tape (circular buffer)
    static constexpr size_t LIQ_BUF = 256;
    static constexpr size_t LIQ_MASK = LIQ_BUF - 1;
    LiquidationEntry liqs[LIQ_BUF];
    size_t   liq_write = 0;
    size_t   liq_tape_count = 0;
    // Liquidation volume segments (rolling 60s)
    VolSegment liq_vol_segs[VOL_SEGMENTS] = {};

    char       exchange[32];
    char       symbol[32];

    // Connection status
    uint8_t  last_status_type = 0xFF;    // 0xFF = no status yet
    uint8_t  last_status_conn = 0;
    int64_t  last_status_ts_ns = 0;      // recv_ts of last status event
    char     last_status_msg[64] = "";
    uint8_t  last_mkt_conn = 0;          // connection_id from last market data event
};

// ============================================================================
// Signal handling
// ============================================================================

static volatile bool running = true;
static void sighandler(int) { running = false; }

static inline void tty_write(const void* buf, size_t len) {
    [[maybe_unused]] auto r = write(STDOUT_FILENO, buf, len);
}

// ============================================================================
// Terminal size
// ============================================================================

static int get_term_rows() {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0)
        return ws.ws_row;
    return 24;
}

static int get_term_cols() {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    return 80;
}

// ============================================================================
// Price formatting (normalized exponent from market_conf.hpp)
// ============================================================================

static constexpr int8_t PRICE_EXP = websocket::market::BinanceUSDM::price_exp;
static constexpr int8_t QTY_EXP   = websocket::market::BinanceUSDM::qty_exp;

static constexpr double pow10_table[] = {
    1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 1e-1, 1.0
};

static double mantissa_to_double(int64_t mantissa, int8_t exponent) {
    int idx = exponent + 8;
    if (idx >= 0 && idx <= 8) return mantissa * pow10_table[idx];
    return mantissa * std::pow(10.0, exponent);
}

static void fmt_price(char* buf, size_t sz, int64_t mantissa, int8_t exp) {
    if (mantissa == 0) { buf[0] = '0'; buf[1] = '\0'; return; }
    int n = snprintf(buf, sz, "%.10f", mantissa_to_double(mantissa, exp));
    char* dot = std::strchr(buf, '.');
    if (dot) {
        char* end = buf + n - 1;
        while (end > dot && *end == '0') end--;
        if (end == dot) *end = '\0';
        else *(end + 1) = '\0';
    }
}

static void fmt_qty(char* buf, size_t sz, int64_t mantissa, int8_t exp) {
    fmt_price(buf, sz, mantissa, exp);
    if (buf[0] == '0' && buf[1] == '.') {
        std::memmove(buf, buf + 1, std::strlen(buf));
    }
    // Replace leading zeros after '.' with spaces: ".00008" → ".    8"
    if (buf[0] == '.') {
        for (int i = 1; buf[i] == '0'; i++)
            buf[i] = ' ';
    }
}

// Count digits after decimal point (0 if no dot, -1 if empty string)
static int decimal_digits(const char* s) {
    if (!s[0]) return -1;
    const char* dot = std::strchr(s, '.');
    return dot ? static_cast<int>(std::strlen(dot + 1)) : 0;
}

// Pad with spaces after last digit to reach target decimal width
static void pad_to_decimals(char* s, int target) {
    int cur = decimal_digits(s);
    if (cur < 0 || cur >= target) return;
    int len = static_cast<int>(std::strlen(s));
    if (cur == 0 && target > 0) {
        s[len++] = '.';
    }
    for (int i = cur; i < target; i++)
        s[len++] = ' ';
    s[len] = '\0';
}

// ============================================================================
// Depth sampling (rolling 1-min average via segments)
// ============================================================================

static void sample_depth(ViewerState& s, int64_t ts_ns) {
    double inst_depth = 0;
    for (int i = 0; i < 10 && i < s.latest_orderbook().bid_count; i++)
        inst_depth += mantissa_to_double(s.latest_orderbook().bids[i].qty, QTY_EXP);
    for (int i = 0; i < 10 && i < s.latest_orderbook().ask_count; i++)
        inst_depth += mantissa_to_double(s.latest_orderbook().asks[i].qty, QTY_EXP);

    // Advance depth segments
    if (s.depth_seg_start_ns == 0)
        s.depth_seg_start_ns = ts_ns;
    int depth_advances = 0;
    while (ts_ns >= s.depth_seg_start_ns + ViewerState::VOL_SEG_NS
           && depth_advances < ViewerState::VOL_SEGMENTS) {
        s.depth_seg_cur = (s.depth_seg_cur + 1) % ViewerState::VOL_SEGMENTS;
        s.depth_segs[s.depth_seg_cur] = {};
        s.depth_seg_start_ns += ViewerState::VOL_SEG_NS;
        depth_advances++;
    }
    if (depth_advances >= ViewerState::VOL_SEGMENTS)
        s.depth_seg_start_ns = ts_ns;

    s.depth_segs[s.depth_seg_cur].depth_sum += inst_depth;
    s.depth_segs[s.depth_seg_cur].samples++;
}

// ============================================================================
// Event processing
// ============================================================================

static void apply_event(ViewerState& s, const MktEvent& evt) {
    if (evt.is_system_status()) {
        auto& st = evt.payload.status;
        s.last_status_type = st.status_type;
        s.last_status_conn = st.connection_id;
        s.last_status_ts_ns = evt.recv_ts_ns();
        std::strncpy(s.last_status_msg, st.message, sizeof(s.last_status_msg) - 1);
        s.last_status_msg[sizeof(s.last_status_msg) - 1] = '\0';
        s.total_events++;
        return;
    }

    s.total_events++;
    // Update venue and symbol from every event
    const char* vn = venue_name(evt.venue_id());
    if (vn) std::strncpy(s.exchange, vn, sizeof(s.exchange) - 1);
    else    std::strncpy(s.exchange, "????", sizeof(s.exchange) - 1);

    if (evt.instrument_id() != 0)
        std::snprintf(s.symbol, sizeof(s.symbol), "#%u", evt.instrument_id());
    else
        std::strncpy(s.symbol, "????", sizeof(s.symbol) - 1);
    int64_t evt_recv_ts_ns = evt.recv_ts_ns();
    s.last_recv_ts_ns = evt_recv_ts_ns;
    s.last_event_ts_ns = evt.event_ts_ns;
    s.last_nic_ts_ns = evt.nic_ts_ns;
    s.last_mkt_conn = evt.connection_id();

    // Advance event-count segments (rolling 60s)
    if (s.evt_seg_start_ns == 0)
        s.evt_seg_start_ns = evt_recv_ts_ns;
    int evt_advances = 0;
    while (evt_recv_ts_ns >= s.evt_seg_start_ns + ViewerState::VOL_SEG_NS
           && evt_advances < ViewerState::VOL_SEGMENTS) {
        s.evt_seg_cur = (s.evt_seg_cur + 1) % ViewerState::VOL_SEGMENTS;
        s.evt_segs[s.evt_seg_cur] = 0;
        s.evt_seg_start_ns += ViewerState::VOL_SEG_NS;
        evt_advances++;
    }
    if (evt_advances >= ViewerState::VOL_SEGMENTS)
        s.evt_seg_start_ns = evt_recv_ts_ns;
    s.evt_segs[s.evt_seg_cur]++;

    // Collect packet interval sample (rolling 10-min window)
    if (evt.nic_ts_ns > 0 && s.prev_nic_ts_ns > 0 && evt.nic_ts_ns > s.prev_nic_ts_ns) {
        int64_t dt_ns = evt.nic_ts_ns - s.prev_nic_ts_ns;
        // Thresholds: upper bounds for buckets 0..12, bucket 13 = overflow (50us+)
        static constexpr int64_t thresholds[] = {
            2, 5, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000
        };
        int bucket = ViewerState::INTERVAL_BUCKETS - 1;  // overflow
        for (int b = 0; b < ViewerState::INTERVAL_BUCKETS - 1; b++) {
            if (dt_ns < thresholds[b]) { bucket = b; break; }
        }
        // Advance time segments
        if (s.hist_seg_start_ns == 0)
            s.hist_seg_start_ns = evt.nic_ts_ns;
        int advances = 0;
        while (evt.nic_ts_ns >= s.hist_seg_start_ns + ViewerState::HIST_SEG_NS
               && advances < ViewerState::HIST_SEGMENTS) {
            s.hist_seg_cur = (s.hist_seg_cur + 1) % ViewerState::HIST_SEGMENTS;
            s.hist_segs[s.hist_seg_cur] = {};
            s.hist_seg_start_ns += ViewerState::HIST_SEG_NS;
            advances++;
        }
        if (advances >= ViewerState::HIST_SEGMENTS)
            s.hist_seg_start_ns = evt.nic_ts_ns;
        s.hist_segs[s.hist_seg_cur].bins[bucket]++;
        s.hist_segs[s.hist_seg_cur].count++;
    }
    s.prev_nic_ts_ns = evt.nic_ts_ns;

    // Collect latency sample
    if (evt.nic_ts_ns > 0 && evt.recv_local_latency_ns > 0) {
        float lat = static_cast<float>(evt.recv_local_latency_ns) / 1000.0f;
        s.latency_us[s.latency_write % MAX_LATENCY_SAMPLES] = lat;
        s.latency_write++;
        if (s.latency_count < MAX_LATENCY_SAMPLES) s.latency_count++;
        if (s.latency_count == 1) { s.latency_min = s.latency_max = lat; s.latency_max_seq = evt.src_seq; }
        else { s.latency_min = std::min(s.latency_min, lat); if (lat > s.latency_max) { s.latency_max = lat; s.latency_max_seq = evt.src_seq; } }
        s.latency_sum += lat;
    }

    auto dr = s.dedup.check(evt);

    if (dr.flush_gap)
        std::fprintf(stderr, "\033[33m[WARN] [FLUSH_GAP] ch=%u seq=%ld fi=%u\033[0m\n",
                     dr.channel, evt.src_seq, evt.flush_index());

    if (evt.is_book_snapshot()) {
        for (int c = 0; c < ViewerState::DEPTH_CHANNELS; c++) {
            if (dr.snap_accepted & (1 << c)) {
                s.ob_channels[c].apply_snapshot(evt);
                s.ob_channel_recv_ns[c] = evt_recv_ts_ns;
            }
        }
        if (!dr.is_dup()) s.update_latest_channel();
        s.snap_count++;
        sample_depth(s, evt_recv_ts_ns);
    } else if (evt.is_book_delta()) {
        if (dr.is_dup()) { s.delta_count++; return; }
        uint8_t ch = dr.channel;
        s.ob_channel_recv_ns[ch] = evt_recv_ts_ns;
        s.ob_channels[ch].apply_deltas(evt);
        // Re-apply cached BBO if it's newer than this channel's book
        int64_t ch_seq = s.dedup.ob_channel_seq[ch];
        if (s.last_bbo_seq > ch_seq) {
            auto& ob = s.ob_channels[ch];
            ob.bbo_seq = s.last_bbo_seq;
            ob.bbo_bid_price = s.cached_bbo_bid_price;
            ob.bbo_bid_qty = s.cached_bbo_bid_qty;
            ob.bbo_ask_price = s.cached_bbo_ask_price;
            ob.bbo_ask_qty = s.cached_bbo_ask_qty;
            ob.reconcile_bbo();
        }
        s.update_latest_channel();
        s.delta_count++;
        sample_depth(s, evt_recv_ts_ns);
    } else if (evt.is_bbo_array()) {
        if (dr.is_dup()) { s.bbo_count++; return; }
        s.bbo_recv_ns = evt_recv_ts_ns;
        // Cache BBO values
        auto entries = evt.bbo_entries();
        if (entries.count > 0) {
            auto& last = entries.data[entries.count - 1];
            s.last_bbo_seq = last.book_update_id;
            s.cached_bbo_bid_price = last.bid_price;
            s.cached_bbo_bid_qty = last.bid_qty;
            s.cached_bbo_ask_price = last.ask_price;
            s.cached_bbo_ask_qty = last.ask_qty;
        }
        // Only apply to orderbook if BBO is newer than latest depth
        if (s.latest_ob_channel >= 0) {
            int64_t latest_depth_seq = s.dedup.ob_channel_seq[s.latest_ob_channel];
            if (s.last_bbo_seq > latest_depth_seq)
                s.ob_channels[s.latest_ob_channel].apply_bbo(evt);
        }
        s.bbo_count++;
        sample_depth(s, evt_recv_ts_ns);
    } else if (evt.is_trade_array()) {
        if (dr.is_dup()) { s.trade_msg_count++; return; }

        // Advance volume segments based on recv_ts
        if (s.vol_seg_start_ns == 0)
            s.vol_seg_start_ns = evt_recv_ts_ns;
        int vol_advances = 0;
        while (evt_recv_ts_ns >= s.vol_seg_start_ns + ViewerState::VOL_SEG_NS
               && vol_advances < ViewerState::VOL_SEGMENTS) {
            s.vol_seg_cur = (s.vol_seg_cur + 1) % ViewerState::VOL_SEGMENTS;
            s.vol_segs[s.vol_seg_cur] = {};
            s.vol_seg_start_ns += ViewerState::VOL_SEG_NS;
            vol_advances++;
        }
        if (vol_advances >= ViewerState::VOL_SEGMENTS)
            s.vol_seg_start_ns = evt_recv_ts_ns;

        for (uint8_t i = 0; i < evt.count && i < MAX_TRADES; i++) {
            const auto& t = evt.payload.trades.entries[i];
            double q = mantissa_to_double(t.qty, QTY_EXP);
            if (t.is_buyer()) {
                s.vol_segs[s.vol_seg_cur].buy_qty += q;
                s.vol_segs[s.vol_seg_cur].buy_count++;
            } else {
                s.vol_segs[s.vol_seg_cur].sell_qty += q;
                s.vol_segs[s.vol_seg_cur].sell_count++;
            }
            s.trades[s.trade_write & ViewerState::TRADE_MASK] = t;
            s.trade_write++;
            if (s.trade_count < ViewerState::TRADE_BUF) s.trade_count++;
        }
        s.trade_msg_count++;
    } else if (evt.is_liquidation()) {
        if (!dr.is_dup()) {
            s.is_perp = true;
            s.liq_count++;
            for (uint8_t i = 0; i < evt.count && i < MAX_LIQUIDATIONS; i++) {
                const auto& liq = evt.payload.liquidations.entries[i];
                s.liqs[s.liq_write & ViewerState::LIQ_MASK] = liq;
                s.liq_write++;
                if (s.liq_tape_count < ViewerState::LIQ_BUF) s.liq_tape_count++;
                // Accumulate liq volume into segments (same cadence as trades)
                double q = mantissa_to_double(liq.filled_qty, QTY_EXP);
                bool is_sell = (liq.flags & LiqFlags::SIDE_SELL);
                auto& seg = s.liq_vol_segs[s.vol_seg_cur];
                if (is_sell) { seg.sell_qty += q; seg.sell_count++; }
                else         { seg.buy_qty += q; seg.buy_count++; }
            }
        }
    } else if (evt.is_mark_price()) {
        if (!dr.is_dup()) {
            s.is_perp = true;
            if (evt.count > 0) {
                auto& mp = evt.payload.mark_prices.entries[0];
                s.last_mark_price = mp.mark_price;
                s.last_index_price = mp.index_price;
                s.last_funding_rate = mp.funding_rate;
                s.last_next_funding_ns = mp.next_funding_ns;
                s.last_mark_recv_ns = evt_recv_ts_ns;
            }
            s.mark_price_count++;
        }
    }
}

static void add_log_line(ViewerState& s, const MktEvent& evt) {
    char* line = s.log_lines[s.log_write & 63];

    const char* type_str =
        evt.is_book_snapshot() ? (evt.is_snapshot() ? "SNAPSHOT" : "BBO     ") :
        evt.is_bbo_array()     ? "BBO     " :
        evt.is_book_delta()    ? "DELTA   " :
        evt.is_liquidation()   ? "LIQUIDAT" :
        evt.is_mark_price()    ? "MARKPRIC" :
        evt.is_system_status() ? "STATUS  " : "?       ";

    char counts[16] = "";
    if (evt.is_book_snapshot()) {
        snprintf(counts, sizeof(counts), "%ub/%ua", evt.count, evt.count2);
    } else if (evt.is_book_delta()) {
        if (evt.count2 > 0)
            snprintf(counts, sizeof(counts), "%ud#%u", evt.count, evt.count2);
        else
            snprintf(counts, sizeof(counts), "%ud", evt.count);
    } else if (evt.is_bbo_array()) {
        snprintf(counts, sizeof(counts), "%ub", evt.count);
    } else if (evt.is_trade_array()) {
        snprintf(counts, sizeof(counts), "%ut", evt.count);
    } else if (evt.is_liquidation()) {
        snprintf(counts, sizeof(counts), "%uL", evt.count);
    } else if (evt.is_mark_price()) {
        snprintf(counts, sizeof(counts), "%uM", evt.count);
    } else if (evt.is_system_status()) {
        const char* st_name =
            evt.payload.status.status_type == 0 ? "HBEAT" :
            evt.payload.status.status_type == 1 ? "DISC" :
            evt.payload.status.status_type == 2 ? "RECON" : "?";
        snprintf(counts, sizeof(counts), "c%u %s", evt.payload.status.connection_id, st_name);
    }

    snprintf(line, 160,
             " c%u %-14ld %s %-8s r=%-19ld e=%ld",
             evt.connection_id(), evt.src_seq, type_str, counts,
             evt.recv_ts_ns(), evt.event_ts_ns);

    s.log_write++;
    if (s.log_count < 64) s.log_count++;
}

// ============================================================================
// Rendering
// ============================================================================

static int fb_put(char* fb, int pos, const char* s, int n) {
    std::memcpy(fb + pos, s, n);
    return pos + n;
}
static int fb_puts(char* fb, int pos, const char* s) {
    return fb_put(fb, pos, s, std::strlen(s));
}

// ============================================================================
// Latency chart rendering (3 rows: title + 2 data rows)
// ============================================================================

static constexpr float CHART_MAX_US = 10.0f;
static constexpr int CHART_LEVELS = 16;  // 2 rows × 8 sub-levels

// UTF-8 block elements: index 0 = space, 1-8 = ▁▂▃▄▅▆▇█
static const char* BLOCKS[] = {
    " ",
    "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83", "\xe2\x96\x84",
    "\xe2\x96\x85", "\xe2\x96\x86", "\xe2\x96\x87", "\xe2\x96\x88"
};

static float percentile(const ViewerState& s, float pct) {
    static float tmp[MAX_LATENCY_SAMPLES];
    size_t n = s.latency_count;
    size_t start = (s.latency_write - n) % MAX_LATENCY_SAMPLES;
    for (size_t i = 0; i < n; i++)
        tmp[i] = s.latency_us[(start + i) % MAX_LATENCY_SAMPLES];
    std::sort(tmp, tmp + n);
    size_t idx = static_cast<size_t>(pct * n);
    if (idx >= n) idx = n - 1;
    return tmp[idx];
}

static int render_latency_chart(const ViewerState& s, char* fb, int pos, int term_cols) {
    static constexpr const char* K = "\033[K";

    int chart_width = term_cols - 4;  // margin for "10│" / " 0│"
    if (chart_width < 10) chart_width = 10;

    // ── Compute bar levels for visible columns ──
    int visible = std::min(chart_width, (int)s.latency_count);
    // We'll render chart_width columns; leftmost may be empty if count < width

    // Top row: "10|..."
    pos = fb_puts(fb, pos, DIM);
    pos = fb_puts(fb, pos, "10");
    pos = fb_puts(fb, pos, RST);
    fb[pos++] = '|';

    for (int col = 0; col < chart_width; col++) {
        int sample_idx = col - (chart_width - visible);
        if (sample_idx < 0) {
            fb[pos++] = ' ';
            continue;
        }
        // Map to circular buffer: oldest visible is at (write - visible), newest at (write - 1)
        size_t buf_idx = (s.latency_write - visible + sample_idx) % MAX_LATENCY_SAMPLES;
        float lat = s.latency_us[buf_idx];
        int level = static_cast<int>(lat * CHART_LEVELS / CHART_MAX_US);
        if (level < 0) level = 0;
        if (level > CHART_LEVELS) level = CHART_LEVELS;

        int top_level = (level > 8) ? (level - 8) : 0;

        // Color based on latency value
        const char* color = (lat <= 3.0f) ? GREEN : (lat <= 7.0f) ? YELLOW : RED;
        pos = fb_puts(fb, pos, color);
        pos = fb_puts(fb, pos, BLOCKS[top_level]);
        pos = fb_puts(fb, pos, RST);
    }
    pos = fb_puts(fb, pos, K);
    fb[pos++] = '\n';

    // Bottom row: " 0|..."
    pos = fb_puts(fb, pos, DIM);
    pos = fb_puts(fb, pos, " 0");
    pos = fb_puts(fb, pos, RST);
    fb[pos++] = '|';

    for (int col = 0; col < chart_width; col++) {
        int sample_idx = col - (chart_width - visible);
        if (sample_idx < 0) {
            fb[pos++] = ' ';
            continue;
        }
        size_t buf_idx = (s.latency_write - visible + sample_idx) % MAX_LATENCY_SAMPLES;
        float lat = s.latency_us[buf_idx];
        int level = static_cast<int>(lat * CHART_LEVELS / CHART_MAX_US);
        if (level < 0) level = 0;
        if (level > CHART_LEVELS) level = CHART_LEVELS;

        int bot_level = (level > 8) ? 8 : level;

        const char* color = (lat <= 3.0f) ? GREEN : (lat <= 7.0f) ? YELLOW : RED;
        pos = fb_puts(fb, pos, color);
        pos = fb_puts(fb, pos, BLOCKS[bot_level]);
        pos = fb_puts(fb, pos, RST);
    }
    pos = fb_puts(fb, pos, K);
    fb[pos++] = '\n';

    return pos;
}

// ============================================================================
// Interval histogram rendering
// ============================================================================

// Fractional horizontal block elements for sub-column precision (1/8 increments)
static const char* HBLOCKS[] = {
    " ", "\xe2\x96\x8f", "\xe2\x96\x8e", "\xe2\x96\x8d",
    "\xe2\x96\x8c", "\xe2\x96\x8b", "\xe2\x96\x8a", "\xe2\x96\x89", "\xe2\x96\x88"
};

static const char* interval_bucket_label(int bucket) {
    // Returns a 5-char label for each bucket
    static const char* labels[] = {
        "  0ns",  // <2ns
        "  2ns",  // 2-5ns
        "  5ns",  // 5-20ns
        " 20ns",  // 20-50ns
        " 50ns",  // 50-100ns
        "100ns",  // 100-200ns
        "200ns",  // 200-500ns
        "500ns",  // 500ns-1us
        " 1us ",  // 1-2us
        " 2us ",  // 2-5us
        " 5us ",  // 5-10us
        "10us ",  // 10-20us
        "20us ",  // 20-50us
        "50us+",  // overflow >=50us
    };
    if (bucket < 0 || bucket >= ViewerState::INTERVAL_BUCKETS) return "?????";
    return labels[bucket];
}

static int render_interval_bar(char* fb, int pos, const char* label,
                                uint32_t count, uint32_t max_count, int bar_width) {
    // label (5 chars) + | + bar
    pos = fb_puts(fb, pos, DIM);
    pos = fb_put(fb, pos, label, 5);
    pos = fb_puts(fb, pos, RST);
    fb[pos++] = '|';

    if (count == 0 || max_count == 0 || bar_width <= 0) {
        for (int j = 0; j < bar_width; j++) fb[pos++] = ' ';
        return pos;
    }

    // Scale: count/max_count * bar_width, with 1/8 sub-column precision
    float frac = static_cast<float>(count) / static_cast<float>(max_count);
    float cols = frac * bar_width;
    int full = static_cast<int>(cols);
    int sub = static_cast<int>((cols - full) * 8.0f);
    if (sub < 0) sub = 0;
    if (sub > 8) sub = 8;

    int bar_cols = full + (sub > 0 ? 1 : 0);

    pos = fb_puts(fb, pos, CYAN);
    for (int j = 0; j < full && j < bar_width; j++)
        pos = fb_puts(fb, pos, HBLOCKS[8]);  // █
    if (full < bar_width && sub > 0)
        pos = fb_puts(fb, pos, HBLOCKS[sub]);
    pos = fb_puts(fb, pos, RST);

    // Pad remaining columns
    for (int j = bar_cols; j < bar_width; j++) fb[pos++] = ' ';

    return pos;
}

// Render a strength bar growing left-to-right with label prefix and percentage suffix.
// Format: "S ████▌  42%" — label (1 char) + space + bar + percentage
// bar_width = total display columns available for the bar+pct portion.
// scale = the value that maps to full bar width (max of both strengths, at least 1.0).
static int render_strength_bar(char* fb, int pos, const char* color,
                                char label, float strength, int bar_width, float scale) {
    // "S " or "B " prefix
    pos = fb_puts(fb, pos, color);
    fb[pos++] = label;
    fb[pos++] = ' ';

    // Format percentage label
    char pct[8];
    int pct_len;
    if (strength < 0.001f) {
        pct[0] = '\0'; pct_len = 0;
    } else if (strength < 9.995f) {
        pct_len = snprintf(pct, sizeof(pct), "%d%%", static_cast<int>(strength * 100 + 0.5f));
    } else {
        pct_len = snprintf(pct, sizeof(pct), "%dx", static_cast<int>(strength + 0.5f));
    }

    // Reserve space for percentage at end
    int avail = bar_width - pct_len;
    if (avail < 1) avail = 1;

    float fill = (scale > 0) ? std::min(strength / scale, 1.0f) : 0.0f;
    float cols = fill * avail;
    int full = static_cast<int>(cols);
    int sub = static_cast<int>((cols - full) * 8.0f);
    if (sub < 0) sub = 0;
    if (sub > 8) sub = 8;

    for (int j = 0; j < full && j < avail; j++)
        pos = fb_puts(fb, pos, HBLOCKS[8]);
    if (full < avail && sub > 0)
        pos = fb_puts(fb, pos, HBLOCKS[sub]);

    pos = fb_puts(fb, pos, RST);

    // Spaces between bar end and percentage
    int bar_cols = full + (sub > 0 ? 1 : 0);
    int gap = avail - bar_cols;
    for (int j = 0; j < gap; j++)
        fb[pos++] = ' ';

    // Percentage
    if (pct_len > 0) {
        pos = fb_puts(fb, pos, DIM);
        pos = fb_put(fb, pos, pct, pct_len);
        pos = fb_puts(fb, pos, RST);
    }

    return pos;
}

static int render(const ViewerState& s, char* fb, int book_rows, int trade_rows, int log_rows, bool wide_mode, bool show_hist, int term_cols) {
    int pos = 0;
    char tmp[512];
    static constexpr const char* K = "\033[K";  // erase-to-EOL

    pos = fb_puts(fb, pos, "\033[H");

    // ── Merged header + latency title ───────────────────────────────────────
    {
        // Left part: " BINANCE BTC-USDT"
        pos = fb_puts(fb, pos, BOLD);
        int n = snprintf(tmp, sizeof(tmp), " %s %s", s.exchange, s.symbol);
        pos = fb_put(fb, pos, tmp, n);
        int used = 1 + static_cast<int>(std::strlen(s.exchange)) + 1 + static_cast<int>(std::strlen(s.symbol));
        pos = fb_puts(fb, pos, RST);

        // Connection badge with server latency: background-colored " conn0:+1.5ms "
        if (s.last_status_type != 0xFF) {
            char conn_name[8];
            if (s.last_status_type == 0xFF)
                snprintf(conn_name, sizeof(conn_name), "conn*");
            else
                snprintf(conn_name, sizeof(conn_name), "conn%2u", s.last_mkt_conn);
            // Base color: RED for Disconn(1), GREEN for Heartbt(0)/Reconn(2)/Failovr(3)
            const char* bg_color = (s.last_status_type == 1) ? BG_RED : BG_GREEN;
            char badge[48];
            int badge_len;
            if (s.last_recv_ts_ns > 0 && s.last_event_ts_ns > 0) {
                double srv_ms = (s.last_recv_ts_ns - s.last_event_ts_ns) / 1e6;
                // Override: YELLOW when srv > 100ms (and not disconnected)
                if (s.last_status_type != 1 && srv_ms > 100.0)
                    bg_color = BG_YELLOW;
                badge_len = snprintf(badge, sizeof(badge), " %s:%+.1fms ", conn_name, srv_ms);
            } else {
                badge_len = snprintf(badge, sizeof(badge), " %s ", conn_name);
            }
            pos = fb_puts(fb, pos, " ");
            pos = fb_puts(fb, pos, "\033[97m");  // bright white fg
            pos = fb_puts(fb, pos, bg_color);
            pos = fb_put(fb, pos, badge, badge_len);
            pos = fb_puts(fb, pos, RST);
            used += 1 + badge_len;
        }

        if (s.dedup.dup_count > 0) {
            char dup[48];
            int dup_len = snprintf(dup, sizeof(dup), " dup:%lu #%ld ", s.dedup.dup_count, s.dedup.last_dup_seq);
            pos = fb_puts(fb, pos, " ");
            pos = fb_puts(fb, pos, "\033[97m\033[41m");  // bright white on red bg
            pos = fb_put(fb, pos, dup, dup_len);
            pos = fb_puts(fb, pos, RST);
            used += 1 + dup_len;
        }

        if (s.dedup.flush_gap_count > 0) {
            char fg[48];
            int fg_len = snprintf(fg, sizeof(fg), " flush_gap:%lu ", s.dedup.flush_gap_count);
            pos = fb_puts(fb, pos, " ");
            pos = fb_puts(fb, pos, "\033[97m\033[43m");  // bright white on yellow bg
            pos = fb_put(fb, pos, fg, fg_len);
            pos = fb_puts(fb, pos, RST);
            used += 1 + fg_len;
        }

        // Right part: latency stats + latest value (if available)
        if (s.latency_count > 0) {
            float p50 = percentile(s, 0.50f);
            float p99 = percentile(s, 0.99f);
            float p999 = percentile(s, 0.999f);
            float p9999 = percentile(s, 0.9999f);
            float latest = s.latency_us[(s.latency_write - 1) % MAX_LATENCY_SAMPLES];

            char stats[160];
            int stats_len = snprintf(stats, sizeof(stats), " min %.1f  P50 %.1f  P99 %.1f  P999 %.1f  P9999 %.1f  max %.1f (#%ld) ",
                                     s.latency_min, p50, p99, p999, p9999, s.latency_max, s.latency_max_seq);

            char latest_str[16];
            int latest_len = snprintf(latest_str, sizeof(latest_str), " %.1fus", latest);

            // Fill dashes between left part and stats
            pos = fb_puts(fb, pos, DIM);
            fb[pos++] = ' ';
            used += 1;

            int right_len = stats_len + latest_len;
            int avail = term_cols - used;

            if (avail >= right_len + 2) {
                // Enough room: dashes + stats + latest
                int fill_before = avail - right_len;
                for (int i = 0; i < fill_before && i < 300; i++)
                    pos = fb_put(fb, pos, "\xe2\x94\x80", 3);
                pos = fb_put(fb, pos, stats, stats_len);
                pos = fb_put(fb, pos, latest_str, latest_len);
            } else if (avail > 0) {
                // Not enough room: concat stats+latest and truncate to fit
                char combined[160];
                int comb_len = snprintf(combined, sizeof(combined), "%s%s", stats, latest_str);
                int print_len = std::min(comb_len, avail);
                pos = fb_put(fb, pos, combined, print_len);
            }
            pos = fb_puts(fb, pos, RST);
        }

        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
    }

    // ── Latency chart bars ──────────────────────────────────────────────────
    if (s.latency_count > 0)
        pos = render_latency_chart(s, fb, pos, term_cols);

    // ── Pre-format book levels ──────────────────────────────────────────────
    struct FmtLevel { char bp[32], bq[32], ap[32], aq[32]; };
    FmtLevel fl[MAX_BOOK];
    int max_pdec = 0, max_qdec = 0;

    int book_level_rows = book_rows - 1;  // last row reserved for channel status
    for (int i = 0; i < book_level_rows; i++) {
        auto& f = fl[i];
        f.bp[0] = f.bq[0] = f.ap[0] = f.aq[0] = '\0';
        if (i < s.latest_orderbook().bid_count) {
            fmt_price(f.bp, sizeof(f.bp), s.latest_orderbook().bids[i].price, PRICE_EXP);
            fmt_qty(f.bq, sizeof(f.bq), s.latest_orderbook().bids[i].qty, QTY_EXP);
            max_pdec = std::max(max_pdec, decimal_digits(f.bp));
            max_qdec = std::max(max_qdec, decimal_digits(f.bq));
        }
        if (i < s.latest_orderbook().ask_count) {
            fmt_price(f.ap, sizeof(f.ap), s.latest_orderbook().asks[i].price, PRICE_EXP);
            fmt_qty(f.aq, sizeof(f.aq), s.latest_orderbook().asks[i].qty, QTY_EXP);
            max_pdec = std::max(max_pdec, decimal_digits(f.ap));
            max_qdec = std::max(max_qdec, decimal_digits(f.aq));
        }
    }
    for (int i = 0; i < book_level_rows; i++) {
        auto& f = fl[i];
        if (f.bp[0]) pad_to_decimals(f.bp, max_pdec);
        if (f.bq[0]) pad_to_decimals(f.bq, max_qdec);
        if (f.ap[0]) pad_to_decimals(f.ap, max_pdec);
        if (f.aq[0]) pad_to_decimals(f.aq, max_qdec);
    }

    // ── Pre-format trades (fold consecutive same-price same-side) ───────────
    int max_trade_show = wide_mode ? book_level_rows : trade_rows;
    static constexpr int MAX_TRADE_DISPLAY = 16;
    if (max_trade_show > MAX_TRADE_DISPLAY) max_trade_show = MAX_TRADE_DISPLAY;
    struct FmtTrade { char tp[32], tq[32], tt[16], tf[12]; bool is_buyer; bool valid; };
    FmtTrade ft[MAX_TRADE_DISPLAY];
    int tmax_pdec = 0, tmax_qdec = 0;
    int actual_trades = 0;

    {
        int raw_idx = 0;
        int raw_count = (int)s.trade_count;
        while (actual_trades < max_trade_show && raw_idx < raw_count) {
            size_t idx = (s.trade_write - 1 - raw_idx) & ViewerState::TRADE_MASK;
            const auto& t = s.trades[idx];
            int64_t acc_qty = t.qty;
            int fold_count = 0;
            raw_idx++;
            // Fold consecutive trades with same price and side
            while (raw_idx < raw_count) {
                size_t ni = (s.trade_write - 1 - raw_idx) & ViewerState::TRADE_MASK;
                const auto& nt = s.trades[ni];
                if (nt.price != t.price || nt.is_buyer() != t.is_buyer()) break;
                acc_qty += nt.qty;
                fold_count++;
                raw_idx++;
            }
            auto& f = ft[actual_trades];
            f.valid = true;
            f.is_buyer = t.is_buyer();
            fmt_price(f.tp, sizeof(f.tp), t.price, PRICE_EXP);
            fmt_qty(f.tq, sizeof(f.tq), acc_qty, QTY_EXP);
            tmax_pdec = std::max(tmax_pdec, decimal_digits(f.tp));
            tmax_qdec = std::max(tmax_qdec, decimal_digits(f.tq));
            f.tt[0] = '\0';
            if (t.trade_time_ns > 0) {
                int64_t ts_ms = t.trade_time_ns / 1000000;
                time_t secs = static_cast<time_t>(ts_ms / 1000);
                int millis = static_cast<int>(ts_ms % 1000);
                struct tm tm_buf;
                localtime_r(&secs, &tm_buf);
                if (wide_mode)
                    snprintf(f.tt, sizeof(f.tt), "%02d:%02d:%02d.%03d",
                             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, millis);
                else
                    snprintf(f.tt, sizeof(f.tt), "%02d:%02d:%02d",
                             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
            }
            if (fold_count > 0)
                snprintf(f.tf, sizeof(f.tf), "+%d", fold_count);
            else
                f.tf[0] = '\0';
            actual_trades++;
        }
    }
    for (int i = actual_trades; i < MAX_TRADE_DISPLAY; i++)
        ft[i].valid = false;
    for (int i = 0; i < actual_trades; i++) {
        pad_to_decimals(ft[i].tp, tmax_pdec);
        pad_to_decimals(ft[i].tq, tmax_qdec);
    }

    // ── Pre-compute rolling 10-min histogram ────────────────────────────────
    uint32_t interval_hist[ViewerState::INTERVAL_BUCKETS] = {};
    uint32_t interval_total = 0;
    uint32_t hist_max_count = 0;
    int hist_bar_width = 0;
    if (show_hist) {
        for (int i = 0; i < ViewerState::HIST_SEGMENTS; i++) {
            for (int b = 0; b < ViewerState::INTERVAL_BUCKETS; b++)
                interval_hist[b] += s.hist_segs[i].bins[b];
            interval_total += s.hist_segs[i].count;
        }
        for (int b = 0; b < ViewerState::INTERVAL_BUCKETS - 1; b++)
            hist_max_count = std::max(hist_max_count, interval_hist[b]);
        hist_bar_width = term_cols - 93;  // 84 book+trades + 3 sep + 5 label + 1 │
    }

    // ── Pre-compute buy/sell strength ────────────────────────────────────────
    double depth_total = 0;
    uint32_t depth_samples = 0;
    for (int i = 0; i < ViewerState::VOL_SEGMENTS; i++) {
        depth_total += s.depth_segs[i].depth_sum;
        depth_samples += s.depth_segs[i].samples;
    }
    double avg_depth = (depth_samples > 0) ? depth_total / depth_samples : 0;

    double buy_vol = 0, sell_vol = 0;
    for (int i = 0; i < ViewerState::VOL_SEGMENTS; i++) {
        buy_vol  += s.vol_segs[i].buy_qty;
        sell_vol += s.vol_segs[i].sell_qty;
    }
    float buy_strength  = (avg_depth > 0) ? static_cast<float>(buy_vol / avg_depth) : 0;
    float sell_strength = (avg_depth > 0) ? static_cast<float>(sell_vol / avg_depth) : 0;
    float strength_scale = std::max(1.0f, std::max(buy_strength, sell_strength));

    // ── Pre-compute perp liquidation strength + tape ─────────────────────────
    double liq_buy_vol = 0, liq_sell_vol = 0;
    float liq_buy_strength = 0, liq_sell_strength = 0;
    float liq_strength_scale = 1.0f;

    static constexpr int MAX_LIQ_DISPLAY = 16;
    struct FmtLiq { char lp[32], lq[32], lt[16]; bool is_sell; bool valid; };
    FmtLiq flq[MAX_LIQ_DISPLAY];
    int actual_liqs = 0;
    int lmax_pdec = 0, lmax_qdec = 0;

    if (s.is_perp) {
        for (int i = 0; i < ViewerState::VOL_SEGMENTS; i++) {
            liq_buy_vol  += s.liq_vol_segs[i].buy_qty;
            liq_sell_vol += s.liq_vol_segs[i].sell_qty;
        }
        liq_buy_strength  = (avg_depth > 0) ? static_cast<float>(liq_buy_vol / avg_depth) : 0;
        liq_sell_strength = (avg_depth > 0) ? static_cast<float>(liq_sell_vol / avg_depth) : 0;
        liq_strength_scale = std::max(1.0f, std::max(liq_buy_strength, liq_sell_strength));

        int max_liq_show = wide_mode ? (book_rows - 4) : trade_rows;
        if (max_liq_show > MAX_LIQ_DISPLAY) max_liq_show = MAX_LIQ_DISPLAY;
        if (max_liq_show < 0) max_liq_show = 0;

        for (int i = 0; i < max_liq_show && i < (int)s.liq_tape_count; i++) {
            size_t idx = (s.liq_write - 1 - i) & ViewerState::LIQ_MASK;
            const auto& liq = s.liqs[idx];
            auto& f = flq[actual_liqs];
            f.valid = true;
            f.is_sell = (liq.flags & LiqFlags::SIDE_SELL);
            fmt_price(f.lp, sizeof(f.lp), liq.price, PRICE_EXP);
            fmt_qty(f.lq, sizeof(f.lq), liq.filled_qty, QTY_EXP);
            lmax_pdec = std::max(lmax_pdec, decimal_digits(f.lp));
            lmax_qdec = std::max(lmax_qdec, decimal_digits(f.lq));
            f.lt[0] = '\0';
            if (liq.trade_time_ns > 0) {
                int64_t ts_ms = liq.trade_time_ns / 1000000;
                time_t secs = static_cast<time_t>(ts_ms / 1000);
                struct tm tm_buf;
                localtime_r(&secs, &tm_buf);
                snprintf(f.lt, sizeof(f.lt), "%02d:%02d:%02d",
                         tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec);
            }
            actual_liqs++;
        }
        for (int i = actual_liqs; i < MAX_LIQ_DISPLAY; i++)
            flq[i].valid = false;
        for (int i = 0; i < actual_liqs; i++) {
            pad_to_decimals(flq[i].lp, lmax_pdec);
            pad_to_decimals(flq[i].lq, lmax_qdec);
        }
    }

    // ── Book rows (+ trades in wide mode) ───────────────────────────────────
    for (int i = 0; i < book_level_rows; i++) {
        auto& f = fl[i];
        int n;

        // Bid side (green): qty right-aligned, price right-aligned
        pos = fb_puts(fb, pos, GREEN);
        if (wide_mode)
            n = snprintf(tmp, sizeof(tmp), "%9.9s %9.9s", f.bq, f.bp);
        else
            n = snprintf(tmp, sizeof(tmp), "%8.8s %8.8s", f.bq, f.bp);
        pos = fb_put(fb, pos, tmp, n);
        pos = fb_puts(fb, pos, RST);

        // Book separator
        if (wide_mode)
            pos = fb_puts(fb, pos, " | ");
        else
            fb[pos++] = '|';

        // Ask side (red): price left-aligned, qty right-aligned
        pos = fb_puts(fb, pos, RED);
        if (wide_mode)
            n = snprintf(tmp, sizeof(tmp), "%-9.9s %9.9s", f.ap, f.aq);
        else
            n = snprintf(tmp, sizeof(tmp), "%-8.8s %8.8s", f.ap, f.aq);
        pos = fb_put(fb, pos, tmp, n);
        pos = fb_puts(fb, pos, RST);

        // Wide: append trade column
        if (wide_mode) {
            pos = fb_puts(fb, pos, " | ");
            if (i == 0) {
                // Sell strength bar (grows right) + volume
                pos = render_strength_bar(fb, pos, RED, 'S', sell_strength, 32, strength_scale);
                n = snprintf(tmp, sizeof(tmp), "%6.3f", sell_vol);
                if (n > 6) n = 6;
                pos = fb_puts(fb, pos, RED);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
            } else if (i == 1) {
                // Buy strength bar (grows right) + volume
                pos = render_strength_bar(fb, pos, GREEN, 'B', buy_strength, 32, strength_scale);
                n = snprintf(tmp, sizeof(tmp), "%6.3f", buy_vol);
                if (n > 6) n = 6;
                pos = fb_puts(fb, pos, GREEN);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
            } else {
                int ti = i - 2;  // trades shift down by 2
                if (ti < actual_trades && ft[ti].valid) {
                    auto& t = ft[ti];
                    pos = fb_puts(fb, pos, t.is_buyer ? GREEN : RED);
                    n = snprintf(tmp, sizeof(tmp), "%c %9.9s %9.9s %12.12s",
                                 t.is_buyer ? 'B' : 'S', t.tp, t.tq, t.tt);
                    pos = fb_put(fb, pos, tmp, n);
                    pos = fb_puts(fb, pos, RST);
                    pos = fb_puts(fb, pos, DIM);
                    n = snprintf(tmp, sizeof(tmp), " %-5s", t.tf);
                    pos = fb_put(fb, pos, tmp, n);
                    pos = fb_puts(fb, pos, RST);
                } else {
                    for (int j = 0; j < 40; j++) fb[pos++] = ' ';
                }
            }
        }

        // Wide + hist/perp: append interval histogram or perp info column
        if (show_hist && !s.is_perp) {
            pos = fb_puts(fb, pos, " | ");
            if (i == 0) {
                // Title row — fills label(5)+pipe(1)+bar area
                n = snprintf(tmp, sizeof(tmp), "INTERVALS (%u)", interval_total);
                int title_width = hist_bar_width + 6;
                if (n > title_width) n = title_width;
                pos = fb_puts(fb, pos, BOLD);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
                for (int j = n; j < title_width; j++) fb[pos++] = ' ';
            } else {
                int bucket = i - 1;
                if (bucket < ViewerState::INTERVAL_BUCKETS - 1) {
                    pos = render_interval_bar(fb, pos, interval_bucket_label(bucket),
                                              interval_hist[bucket], hist_max_count, hist_bar_width);
                } else if (bucket == ViewerState::INTERVAL_BUCKETS - 1) {
                    // Overflow bucket: show percentage only, no bar
                    uint32_t cnt = interval_hist[bucket];
                    pos = fb_puts(fb, pos, DIM);
                    pos = fb_put(fb, pos, interval_bucket_label(bucket), 5);
                    pos = fb_puts(fb, pos, RST);
                    fb[pos++] = '|';
                    int pct_len = 0;
                    if (cnt > 0 && interval_total > 0) {
                        float pct = 100.0f * cnt / interval_total;
                        pct_len = snprintf(tmp, sizeof(tmp), "%.1f%%", pct);
                        if (pct_len > hist_bar_width) pct_len = hist_bar_width;
                        pos = fb_puts(fb, pos, DIM);
                        pos = fb_put(fb, pos, tmp, pct_len);
                        pos = fb_puts(fb, pos, RST);
                    }
                    for (int j = pct_len; j < hist_bar_width; j++) fb[pos++] = ' ';
                } else {
                    // Rows beyond histogram — pad full hist column width
                    for (int j = 0; j < hist_bar_width + 6; j++) fb[pos++] = ' ';
                }
            }
        } else if (wide_mode && s.is_perp) {
            int perp_col_w = std::max(hist_bar_width + 6, 30);
            pos = fb_puts(fb, pos, " | ");
            if (i == 0) {
                // Title: PERP Mark:XXXXX.XX Fund:X.XXXX% XhXXm
                char mp_str[32] = "-";
                if (s.last_mark_price != 0)
                    fmt_price(mp_str, sizeof(mp_str), s.last_mark_price, PRICE_EXP);
                char fund_str[16] = "-";
                if (s.last_funding_rate != 0) {
                    // funding_rate mantissa: e.g. 38167 from "0.00038167" → 0.038167%
                    double rate_pct = mantissa_to_double(s.last_funding_rate, PRICE_EXP) * 100.0;
                    snprintf(fund_str, sizeof(fund_str), "%.4f%%", rate_pct);
                }
                char countdown[16] = "";
                if (s.last_next_funding_ns > 0 && s.last_mark_recv_ns > 0) {
                    int64_t remain_s = (s.last_next_funding_ns - s.last_mark_recv_ns) / 1000000000LL;
                    if (remain_s < 0) remain_s = 0;
                    int hrs = static_cast<int>(remain_s / 3600);
                    int mins = static_cast<int>((remain_s % 3600) / 60);
                    snprintf(countdown, sizeof(countdown), " %dh%02dm", hrs, mins);
                }
                n = snprintf(tmp, sizeof(tmp), "PERP Mk:%s Fd:%s%s", mp_str, fund_str, countdown);
                if (n > perp_col_w) n = perp_col_w;
                pos = fb_puts(fb, pos, BOLD);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
                for (int j = n; j < perp_col_w; j++) fb[pos++] = ' ';
            } else if (i == 1) {
                // Liq sell strength bar
                pos = render_strength_bar(fb, pos, RED, 'S', liq_sell_strength, perp_col_w - 2, liq_strength_scale);
            } else if (i == 2) {
                // Liq buy strength bar
                pos = render_strength_bar(fb, pos, GREEN, 'B', liq_buy_strength, perp_col_w - 2, liq_strength_scale);
            } else {
                // Recent liquidation orders
                int li = i - 3;
                if (li < actual_liqs && flq[li].valid) {
                    auto& f = flq[li];
                    pos = fb_puts(fb, pos, f.is_sell ? RED : GREEN);
                    n = snprintf(tmp, sizeof(tmp), "%c %9.9s %9.9s %8.8s",
                                 f.is_sell ? 'S' : 'B', f.lp, f.lq, f.lt);
                    pos = fb_put(fb, pos, tmp, n);
                    pos = fb_puts(fb, pos, RST);
                    for (int j = n; j < perp_col_w; j++) fb[pos++] = ' ';
                } else {
                    for (int j = 0; j < perp_col_w; j++) fb[pos++] = ' ';
                }
            }
        }

        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
    }

    // ── Channel status row (last book row) ────────────────────────────────
    {
        // 5 items (D0, D1, D2, D3, BBO) spread across book column width
        int book_col_w = wide_mode ? 41 : 35;  // 19+3+19 or 17+1+17
        int field_w = book_col_w / 5;           // ~8 wide, ~7 narrow
        int visible = 0;
        int n;

        for (int c = 0; c < ViewerState::DEPTH_CHANNELS; c++) {
            bool is_active = (c == s.latest_ob_channel);
            char label[24];
            int64_t ms_ago_d = s.ob_channel_recv_ns[c] == 0 ? -1
                : (s.last_recv_ts_ns - s.ob_channel_recv_ns[c]) / 1'000'000;
            if (ms_ago_d < 0) ms_ago_d = -1;
            if (s.ob_channel_recv_ns[c] == 0 || ms_ago_d >= 99'900)
                n = snprintf(label, sizeof(label), "D%d -", c);
            else if (ms_ago_d >= 1000)
                n = snprintf(label, sizeof(label), "D%d %.1fs", c, ms_ago_d / 1000.0);
            else
                n = snprintf(label, sizeof(label), "D%d %ldms", c, (long)ms_ago_d);
            pos = fb_puts(fb, pos, is_active ? BOLD : DIM);
            if (is_active) pos = fb_puts(fb, pos, BG_GREEN);
            pos = fb_put(fb, pos, label, n);
            pos = fb_puts(fb, pos, RST);
            for (int j = n; j < field_w; j++) fb[pos++] = ' ';
            visible += field_w;
        }
        // BBO — fills remaining width
        {
            int bbo_w = book_col_w - visible;
            char label[24];
            int64_t ms_ago_b = s.bbo_recv_ns == 0 ? -1
                : (s.last_recv_ts_ns - s.bbo_recv_ns) / 1'000'000;
            if (ms_ago_b < 0) ms_ago_b = -1;
            if (s.bbo_recv_ns == 0 || ms_ago_b >= 99'900)
                n = snprintf(label, sizeof(label), "BBO -");
            else if (ms_ago_b >= 1000)
                n = snprintf(label, sizeof(label), "BBO %.1fs", ms_ago_b / 1000.0);
            else
                n = snprintf(label, sizeof(label), "BBO %ldms", (long)ms_ago_b);
            bool bbo_active = (s.latest_ob_channel >= 0 &&
                               s.last_bbo_seq > s.dedup.ob_channel_seq[s.latest_ob_channel]);
            pos = fb_puts(fb, pos, bbo_active ? BOLD : DIM);
            if (bbo_active) pos = fb_puts(fb, pos, BG_CYAN);
            pos = fb_put(fb, pos, label, n);
            pos = fb_puts(fb, pos, RST);
            for (int j = n; j < bbo_w; j++) fb[pos++] = ' ';
        }

        if (wide_mode) {
            pos = fb_puts(fb, pos, " | ");
            auto& aob = s.latest_orderbook();
            char depth_label[32];
            int dn = snprintf(depth_label, sizeof(depth_label),
                              "max %d/%d", aob.max_bid_depth, aob.max_ask_depth);
            pos = fb_puts(fb, pos, DIM);
            pos = fb_put(fb, pos, depth_label, dn);
            pos = fb_puts(fb, pos, RST);
            for (int j = dn; j < 40; j++) fb[pos++] = ' ';
            if ((show_hist && !s.is_perp) || (wide_mode && s.is_perp)) {
                int col_w = s.is_perp ? std::max(hist_bar_width + 6, 30) : hist_bar_width + 6;
                pos = fb_puts(fb, pos, " | ");
                for (int j = 0; j < col_w; j++) fb[pos++] = ' ';
            }
        }

        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
    }

    // ── Narrow: stacked trades section ──────────────────────────────────────
    if (!wide_mode) {
        // Two strength bar lines replace TRADES title
        int narrow_bar_w = term_cols - 3 - 6;  // " " + "S " + bar + 6-char vol
        if (narrow_bar_w < 4) narrow_bar_w = 4;
        int n;
        fb[pos++] = ' ';
        pos = render_strength_bar(fb, pos, RED, 'S', sell_strength, narrow_bar_w, strength_scale);
        n = snprintf(tmp, sizeof(tmp), "%6.3f", sell_vol);
        if (n > 6) n = 6;
        pos = fb_puts(fb, pos, RED);
        pos = fb_put(fb, pos, tmp, n);
        pos = fb_puts(fb, pos, RST);
        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
        fb[pos++] = ' ';
        pos = render_strength_bar(fb, pos, GREEN, 'B', buy_strength, narrow_bar_w, strength_scale);
        n = snprintf(tmp, sizeof(tmp), "%6.3f", buy_vol);
        if (n > 6) n = 6;
        pos = fb_puts(fb, pos, GREEN);
        pos = fb_put(fb, pos, tmp, n);
        pos = fb_puts(fb, pos, RST);
        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';

        for (int i = 0; i < trade_rows; i++) {
            if (i < actual_trades && ft[i].valid) {
                auto& t = ft[i];
                pos = fb_puts(fb, pos, t.is_buyer ? GREEN : RED);
                int n = snprintf(tmp, sizeof(tmp), " %c %8.8s %8.8s %8.8s",
                                 t.is_buyer ? 'B' : 'S', t.tp, t.tq, t.tt);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
                pos = fb_puts(fb, pos, DIM);
                n = snprintf(tmp, sizeof(tmp), " %-5s", t.tf);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
            }
            pos = fb_puts(fb, pos, K);
            fb[pos++] = '\n';
        }
    }

    // ── Narrow: perp section below trades ──────────────────────────────────
    if (!wide_mode && s.is_perp) {
        int narrow_bar_w = term_cols - 3 - 6;
        if (narrow_bar_w < 4) narrow_bar_w = 4;
        int n;
        // Perp title line
        {
            char mp_str[32] = "-";
            if (s.last_mark_price != 0)
                fmt_price(mp_str, sizeof(mp_str), s.last_mark_price, PRICE_EXP);
            char fund_str[16] = "-";
            if (s.last_funding_rate != 0) {
                double rate_pct = mantissa_to_double(s.last_funding_rate, PRICE_EXP) * 100.0;
                snprintf(fund_str, sizeof(fund_str), "%.4f%%", rate_pct);
            }
            char countdown[16] = "";
            if (s.last_next_funding_ns > 0 && s.last_mark_recv_ns > 0) {
                int64_t remain_s = (s.last_next_funding_ns - s.last_mark_recv_ns) / 1000000000LL;
                if (remain_s < 0) remain_s = 0;
                int hrs = static_cast<int>(remain_s / 3600);
                int mins = static_cast<int>((remain_s % 3600) / 60);
                snprintf(countdown, sizeof(countdown), " %dh%02dm", hrs, mins);
            }
            n = snprintf(tmp, sizeof(tmp), "PERP Mk:%s Fd:%s%s", mp_str, fund_str, countdown);
            pos = fb_puts(fb, pos, BOLD);
            pos = fb_put(fb, pos, tmp, n);
            pos = fb_puts(fb, pos, RST);
        }
        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
        // Liq sell strength
        fb[pos++] = ' ';
        pos = render_strength_bar(fb, pos, RED, 'S', liq_sell_strength, narrow_bar_w, liq_strength_scale);
        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
        // Liq buy strength
        fb[pos++] = ' ';
        pos = render_strength_bar(fb, pos, GREEN, 'B', liq_buy_strength, narrow_bar_w, liq_strength_scale);
        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
        // Recent liquidations
        for (int i = 0; i < std::min(actual_liqs, 4); i++) {
            auto& f = flq[i];
            if (!f.valid) break;
            pos = fb_puts(fb, pos, f.is_sell ? RED : GREEN);
            n = snprintf(tmp, sizeof(tmp), " %c %8.8s %8.8s %8.8s",
                         f.is_sell ? 'S' : 'B', f.lp, f.lq, f.lt);
            pos = fb_put(fb, pos, tmp, n);
            pos = fb_puts(fb, pos, RST);
            pos = fb_puts(fb, pos, K);
            fb[pos++] = '\n';
        }
    }

    // ── Log lines ───────────────────────────────────────────────────────────
    // Pre-format updates/60s badge for bottom-right
    char upd_badge[32] = "";
    int upd_badge_len = 0;
    {
        uint32_t evt_total = 0;
        for (int i = 0; i < ViewerState::VOL_SEGMENTS; i++)
            evt_total += s.evt_segs[i];
        if (evt_total > 0)
            upd_badge_len = snprintf(upd_badge, sizeof(upd_badge), " %u/60s ", evt_total);
    }

    for (int i = 0; i < log_rows; i++) {
        if (i < (int)s.log_count) {
            size_t idx = (s.log_write - 1 - i) & 63;
            pos = fb_puts(fb, pos, DIM);
            pos = fb_puts(fb, pos, s.log_lines[idx]);
            pos = fb_puts(fb, pos, RST);
        }
        pos = fb_puts(fb, pos, K);
        // Last log row: right-align updates/60s badge
        if (i == log_rows - 1 && upd_badge_len > 0) {
            int col = term_cols - upd_badge_len + 1;
            if (col < 1) col = 1;
            char cuf[16];
            int cuf_len = snprintf(cuf, sizeof(cuf), "\033[%dG", col);
            pos = fb_put(fb, pos, cuf, cuf_len);
            pos = fb_puts(fb, pos, DIM);
            pos = fb_put(fb, pos, upd_badge, upd_badge_len);
            pos = fb_puts(fb, pos, RST);
        }
        // No trailing \n on the very last line — avoids scrolling the terminal
        if (i < log_rows - 1) fb[pos++] = '\n';
    }

    return pos;
}

// ============================================================================
// Main
// ============================================================================

#ifndef MKT_VIEWER_NO_MAIN
int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <exchange> <symbol>\n", argv[0]);
        fprintf(stderr, "  e.g.: %s Binance BTC-USDT\n", argv[0]);
        return 1;
    }

    std::string ring_name = std::string("mkt_event.") + argv[1] + "." + argv[2];
    fprintf(stderr, "Opening ring: %s\n", ring_name.c_str());

    disruptor::ipc::shared_region region(ring_name);
    IPCRingConsumer<MktEvent> consumer(region);

    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);

    ViewerState state{};
    // exchange and symbol are populated from MktEvent fields, not argv

    tty_write("\033[?25l\033[2J", 10);

    static char frame_buf[65536];
    uint64_t last_render_events = 0;
    int last_term_rows = 0;
    int last_term_cols = 0;

    while (running) {
        MktEvent evt;
        bool eob;
        while (consumer.try_consume(evt, &eob)) {
            apply_event(state, evt);
            if (!evt.is_trade_array())
                add_log_line(state, evt);
        }

        int term_rows = get_term_rows();
        int term_cols = get_term_cols();
        if (state.total_events != last_render_events || term_rows != last_term_rows || term_cols != last_term_cols) {
            bool wide_mode = (term_cols >= 80);

            // Dynamic layout
            int chart_rows = (state.latency_count > 0) ? 2 : 0;  // 2 bar rows (title merged into header)
            int fixed_rows = 1 + chart_rows + (wide_mode ? 0 : 2);  // header + chart bars; narrow adds 2 strength bars
            int content = term_rows - fixed_rows;
            int book_rows = std::clamp(term_rows * 40 / 100, BOOK_MIN, BOOK_MAX);
            int trade_rows = 0;
            int log_rows;

            if (wide_mode) {
                // Trades share book rows — fill screen up to MAX_BOOK
                book_rows = std::min(content - LOG_MIN, MAX_BOOK);
                if (book_rows < BOOK_MIN) book_rows = BOOK_MIN;
                log_rows = std::clamp(content - book_rows, LOG_MIN, LOG_MAX);
            } else {
                trade_rows = std::max(term_rows * 50 / 100, TRADE_MIN);
                log_rows = std::clamp(content - book_rows - trade_rows, LOG_MIN, LOG_MAX);
                int total = book_rows + trade_rows + log_rows;
                if (total > content) {
                    trade_rows -= (total - content);
                    if (trade_rows < TRADE_MIN) trade_rows = TRADE_MIN;
                }
            }

            // Reclaim unused book/trade rows for logs
            if (wide_mode) {
                int data_depth = std::max((int)state.latest_orderbook().book_depth(), (int)state.trade_count);
                int needed = std::max(data_depth, BOOK_MIN) + 1;  // +1 for channel status row
                if (needed < book_rows) {
                    log_rows += book_rows - needed;
                    book_rows = needed;
                }
            } else {
                int book_depth = state.latest_orderbook().book_depth();
                int needed_book = std::max(book_depth, BOOK_MIN) + 1;  // +1 for channel status row
                if (needed_book < book_rows) {
                    log_rows += book_rows - needed_book;
                    book_rows = needed_book;
                }
                int needed_trade = std::max((int)state.trade_count, TRADE_MIN);
                if (needed_trade < trade_rows) {
                    log_rows += trade_rows - needed_trade;
                    trade_rows = needed_trade;
                }
            }

            if (term_rows != last_term_rows || term_cols != last_term_cols) {
                tty_write("\033[2J", 4);
                last_term_rows = term_rows;
                last_term_cols = term_cols;
            }

            bool has_intervals = false;
            for (int i = 0; i < ViewerState::HIST_SEGMENTS && !has_intervals; i++)
                has_intervals = state.hist_segs[i].count > 0;
            bool show_hist = wide_mode && has_intervals && (term_cols >= 120);

            // When showing histogram, ensure enough book rows for bucket display
            if (show_hist && book_rows < ViewerState::INTERVAL_BUCKETS + 1) {
                int want = ViewerState::INTERVAL_BUCKETS + 1;  // +1 for title row
                if (want > content - LOG_MIN) want = content - LOG_MIN;
                if (want > book_rows) {
                    log_rows -= (want - book_rows);
                    if (log_rows < LOG_MIN) log_rows = LOG_MIN;
                    book_rows = want;
                }
            }

            int len = render(state, frame_buf, book_rows, trade_rows, log_rows, wide_mode, show_hist, term_cols);
            tty_write(frame_buf, len);
            last_render_events = state.total_events;
        }

        usleep(1000);
    }

    tty_write("\033[?25h\033[0m", 10);
    fprintf(stderr, "\nTotal events: %lu (snap=%lu delta=%lu bbo=%lu trade=%lu)\n",
            state.total_events, state.snap_count, state.delta_count,
            state.bbo_count, state.trade_msg_count);

    return 0;
}
#endif // MKT_VIEWER_NO_MAIN
