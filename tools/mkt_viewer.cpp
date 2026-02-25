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

using namespace websocket::msg;
using namespace websocket::pipeline;

// ============================================================================
// Constants
// ============================================================================

static constexpr int MAX_BOOK   = 29;  // matches MAX_BOOK_LEVELS in MktEvent

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

// ============================================================================
// Data structures
// ============================================================================

static constexpr int MAX_LATENCY_SAMPLES = 65536;

struct ViewerState {
    BookLevel bids[MAX_BOOK], asks[MAX_BOOK];
    uint8_t   bid_count = 0, ask_count = 0;
    int64_t   book_seq = 0;

    static constexpr size_t TRADE_BUF = 65536;
    static constexpr size_t TRADE_MASK = TRADE_BUF - 1;
    TradeEntry trades[TRADE_BUF];
    size_t     trade_write = 0;
    size_t     trade_count = 0;
    int64_t    trade_seq = 0;

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

    char       exchange[32];
    char       symbol[32];

    // Connection status
    uint8_t  last_status_type = 0xFF;    // 0xFF = no status yet
    uint8_t  last_status_conn = 0;
    int64_t  last_status_ts_ns = 0;      // recv_ts of last status event
    char     last_status_msg[64] = "";
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
// Price formatting (Binance SBE: exponent = -8)
// ============================================================================

static constexpr int8_t PRICE_EXP = -8;
static constexpr int8_t QTY_EXP   = -8;

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
// Book delta application
// ============================================================================

static void apply_delta(const DeltaEntry& d, BookLevel* levels, uint8_t& count, bool is_bid) {
    for (uint8_t i = 0; i < count; i++) {
        if (levels[i].price == d.price) {
            if (d.qty == 0) {
                if (i + 1 < count)
                    std::memmove(&levels[i], &levels[i + 1], (count - i - 1) * sizeof(BookLevel));
                count--;
            } else {
                levels[i].qty = d.qty;
            }
            return;
        }
    }
    if (d.qty > 0 && count < MAX_BOOK) {
        uint8_t pos = count;
        for (uint8_t i = 0; i < count; i++) {
            if (is_bid ? (d.price > levels[i].price) : (d.price < levels[i].price)) {
                pos = i;
                break;
            }
        }
        if (pos < count)
            std::memmove(&levels[pos + 1], &levels[pos], (count - pos) * sizeof(BookLevel));
        levels[pos].price = d.price;
        levels[pos].qty = d.qty;
        count++;
    }
}

// ============================================================================
// Depth sampling (rolling 1-min average via segments)
// ============================================================================

static void sample_depth(ViewerState& s, int64_t ts_ns) {
    double inst_depth = 0;
    for (int i = 0; i < 10 && i < s.bid_count; i++)
        inst_depth += mantissa_to_double(s.bids[i].qty, QTY_EXP);
    for (int i = 0; i < 10 && i < s.ask_count; i++)
        inst_depth += mantissa_to_double(s.asks[i].qty, QTY_EXP);

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
        s.last_status_ts_ns = evt.recv_ts_ns;
        std::strncpy(s.last_status_msg, st.message, sizeof(s.last_status_msg) - 1);
        s.last_status_msg[sizeof(s.last_status_msg) - 1] = '\0';
        s.total_events++;
        return;
    }

    s.total_events++;
    s.last_recv_ts_ns = evt.recv_ts_ns;
    s.last_event_ts_ns = evt.event_ts_ns;
    s.last_nic_ts_ns = evt.nic_ts_ns;

    // Advance event-count segments (rolling 60s)
    if (s.evt_seg_start_ns == 0)
        s.evt_seg_start_ns = evt.recv_ts_ns;
    int evt_advances = 0;
    while (evt.recv_ts_ns >= s.evt_seg_start_ns + ViewerState::VOL_SEG_NS
           && evt_advances < ViewerState::VOL_SEGMENTS) {
        s.evt_seg_cur = (s.evt_seg_cur + 1) % ViewerState::VOL_SEGMENTS;
        s.evt_segs[s.evt_seg_cur] = 0;
        s.evt_seg_start_ns += ViewerState::VOL_SEG_NS;
        evt_advances++;
    }
    if (evt_advances >= ViewerState::VOL_SEGMENTS)
        s.evt_seg_start_ns = evt.recv_ts_ns;
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
    if (evt.nic_ts_ns > 0 && evt.recv_ts_ns > evt.nic_ts_ns) {
        float lat = static_cast<float>(evt.recv_ts_ns - evt.nic_ts_ns) / 1000.0f;
        s.latency_us[s.latency_write % MAX_LATENCY_SAMPLES] = lat;
        s.latency_write++;
        if (s.latency_count < MAX_LATENCY_SAMPLES) s.latency_count++;
        if (s.latency_count == 1) { s.latency_min = s.latency_max = lat; s.latency_max_seq = evt.src_seq; }
        else { s.latency_min = std::min(s.latency_min, lat); if (lat > s.latency_max) { s.latency_max = lat; s.latency_max_seq = evt.src_seq; } }
        s.latency_sum += lat;
    }

    if (evt.is_book_snapshot()) {
        if (evt.flags & EventFlags::SNAPSHOT) {
            auto b = evt.bids(), a = evt.asks();
            s.bid_count = std::min<uint8_t>(b.count, MAX_BOOK);
            s.ask_count = std::min<uint8_t>(a.count, MAX_BOOK);
            std::memcpy(s.bids, b.data, s.bid_count * sizeof(BookLevel));
            std::memcpy(s.asks, a.data, s.ask_count * sizeof(BookLevel));
            s.book_seq = evt.src_seq;
            s.snap_count++;
            sample_depth(s, evt.recv_ts_ns);
        } else {
            auto b = evt.bids(), a = evt.asks();
            if (b.count > 0) {
                if (s.bid_count == 0) s.bid_count = 1;
                s.bids[0] = b.data[0];
            }
            if (a.count > 0) {
                if (s.ask_count == 0) s.ask_count = 1;
                s.asks[0] = a.data[0];
            }
            s.book_seq = evt.src_seq;
            s.bbo_count++;
            sample_depth(s, evt.recv_ts_ns);
        }
    } else if (evt.is_book_delta()) {
        for (uint8_t i = 0; i < evt.count; i++) {
            const auto& d = evt.payload.deltas.entries[i];
            if (d.is_bid())
                apply_delta(d, s.bids, s.bid_count, true);
            else
                apply_delta(d, s.asks, s.ask_count, false);
        }
        s.book_seq = evt.src_seq;
        s.delta_count++;
        sample_depth(s, evt.recv_ts_ns);
    } else if (evt.is_trade_array()) {
        // Advance volume segments based on recv_ts
        if (s.vol_seg_start_ns == 0)
            s.vol_seg_start_ns = evt.recv_ts_ns;
        int vol_advances = 0;
        while (evt.recv_ts_ns >= s.vol_seg_start_ns + ViewerState::VOL_SEG_NS
               && vol_advances < ViewerState::VOL_SEGMENTS) {
            s.vol_seg_cur = (s.vol_seg_cur + 1) % ViewerState::VOL_SEGMENTS;
            s.vol_segs[s.vol_seg_cur] = {};
            s.vol_seg_start_ns += ViewerState::VOL_SEG_NS;
            vol_advances++;
        }
        if (vol_advances >= ViewerState::VOL_SEGMENTS)
            s.vol_seg_start_ns = evt.recv_ts_ns;

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
        s.trade_seq = evt.src_seq;
        s.trade_msg_count++;
    }
}

static void add_log_line(ViewerState& s, const MktEvent& evt) {
    char* line = s.log_lines[s.log_write & 63];

    const char* type_str =
        evt.is_book_snapshot() ? (evt.is_snapshot() ? "SNAPSHOT" : "BBO     ") :
        evt.is_book_delta()    ? "DELTA   " :
        evt.is_system_status() ? "STATUS  " : "?       ";

    char counts[16] = "";
    if (evt.is_book_snapshot()) {
        snprintf(counts, sizeof(counts), "%ub/%ua", evt.count, evt.count2);
    } else if (evt.is_book_delta()) {
        snprintf(counts, sizeof(counts), "%ud", evt.count);
    } else if (evt.is_trade_array()) {
        snprintf(counts, sizeof(counts), "%ut", evt.count);
    } else if (evt.is_system_status()) {
        const char* st_name =
            evt.payload.status.status_type == 0 ? "HBEAT" :
            evt.payload.status.status_type == 1 ? "DISC" :
            evt.payload.status.status_type == 2 ? "RECON" : "?";
        snprintf(counts, sizeof(counts), "c%u %s", evt.payload.status.connection_id, st_name);
    }

    snprintf(line, 160,
             " %-14ld %s %-8s r=%-19ld e=%ld",
             evt.src_seq, type_str, counts,
             evt.recv_ts_ns, evt.event_ts_ns);

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

    // Top row: "10│..."
    pos = fb_puts(fb, pos, DIM);
    pos = fb_puts(fb, pos, "10");
    pos = fb_puts(fb, pos, RST);
    pos = fb_put(fb, pos, "\xe2\x94\x82", 3);  // │

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

    // Bottom row: " 0│..."
    pos = fb_puts(fb, pos, DIM);
    pos = fb_puts(fb, pos, " 0");
    pos = fb_puts(fb, pos, RST);
    pos = fb_put(fb, pos, "\xe2\x94\x82", 3);  // │

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
    // label (4 chars) + │ + bar
    pos = fb_puts(fb, pos, DIM);
    pos = fb_put(fb, pos, label, 5);
    pos = fb_puts(fb, pos, RST);
    pos = fb_put(fb, pos, "\xe2\x94\x82", 3);  // │

    if (count == 0 || max_count == 0 || bar_width <= 0)
        return pos;

    // Scale: count/max_count * bar_width, with 1/8 sub-column precision
    float frac = static_cast<float>(count) / static_cast<float>(max_count);
    float cols = frac * bar_width;
    int full = static_cast<int>(cols);
    int sub = static_cast<int>((cols - full) * 8.0f);
    if (sub < 0) sub = 0;
    if (sub > 8) sub = 8;

    pos = fb_puts(fb, pos, CYAN);
    for (int j = 0; j < full && j < bar_width; j++)
        pos = fb_puts(fb, pos, HBLOCKS[8]);  // █
    if (full < bar_width && sub > 0)
        pos = fb_puts(fb, pos, HBLOCKS[sub]);
    pos = fb_puts(fb, pos, RST);

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

        // Status indicator
        if (s.last_status_type != 0xFF) {
            const char* st_name =
                s.last_status_type == 0 ? "Heartbt" :
                s.last_status_type == 1 ? "Disconn" :
                s.last_status_type == 2 ? "Reconn" : "?";
            const char* dot_color = (s.last_status_type == 1) ? RED : GREEN;
            double age_s = 0;
            if (s.last_recv_ts_ns > 0 && s.last_status_ts_ns > 0)
                age_s = (s.last_recv_ts_ns - s.last_status_ts_ns) / 1e9;
            char st_buf[48];
            int st_len = snprintf(st_buf, sizeof(st_buf), " %s %.1fs", st_name, age_s);
            pos = fb_puts(fb, pos, " ");
            pos = fb_puts(fb, pos, dot_color);
            pos = fb_put(fb, pos, "\xe2\x97\x8f", 3);  // ●
            pos = fb_puts(fb, pos, RST);
            pos = fb_puts(fb, pos, DIM);
            pos = fb_put(fb, pos, st_buf, st_len);
            pos = fb_puts(fb, pos, RST);
            used += 2 + st_len;  // dot + space + text
        }

        // Update frequency (rolling 60s)
        uint32_t evt_total = 0;
        for (int i = 0; i < ViewerState::VOL_SEGMENTS; i++)
            evt_total += s.evt_segs[i];
        if (evt_total > 0) {
            char upd[32];
            int upd_len = snprintf(upd, sizeof(upd), " updates: %u/60s", evt_total);
            pos = fb_puts(fb, pos, DIM);
            pos = fb_put(fb, pos, upd, upd_len);
            used += upd_len;
        }

        // Server latency (local CLOCK_REALTIME - exchange event_ts)
        if (s.last_recv_ts_ns > 0 && s.last_event_ts_ns > 0 &&
            s.last_recv_ts_ns > s.last_event_ts_ns) {
            double srv_ms = (s.last_recv_ts_ns - s.last_event_ts_ns) / 1e6;
            char srv[32];
            int srv_len = snprintf(srv, sizeof(srv), " srv:%.1fms", srv_ms);
            pos = fb_puts(fb, pos, DIM);
            pos = fb_put(fb, pos, srv, srv_len);
            pos = fb_puts(fb, pos, RST);
            used += srv_len;
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

    for (int i = 0; i < book_rows; i++) {
        auto& f = fl[i];
        f.bp[0] = f.bq[0] = f.ap[0] = f.aq[0] = '\0';
        if (i < s.bid_count) {
            fmt_price(f.bp, sizeof(f.bp), s.bids[i].price, PRICE_EXP);
            fmt_qty(f.bq, sizeof(f.bq), s.bids[i].qty, QTY_EXP);
            max_pdec = std::max(max_pdec, decimal_digits(f.bp));
            max_qdec = std::max(max_qdec, decimal_digits(f.bq));
        }
        if (i < s.ask_count) {
            fmt_price(f.ap, sizeof(f.ap), s.asks[i].price, PRICE_EXP);
            fmt_qty(f.aq, sizeof(f.aq), s.asks[i].qty, QTY_EXP);
            max_pdec = std::max(max_pdec, decimal_digits(f.ap));
            max_qdec = std::max(max_qdec, decimal_digits(f.aq));
        }
    }
    for (int i = 0; i < book_rows; i++) {
        auto& f = fl[i];
        if (f.bp[0]) pad_to_decimals(f.bp, max_pdec);
        if (f.bq[0]) pad_to_decimals(f.bq, max_qdec);
        if (f.ap[0]) pad_to_decimals(f.ap, max_pdec);
        if (f.aq[0]) pad_to_decimals(f.aq, max_qdec);
    }

    // ── Pre-format trades (fold consecutive same-price same-side) ───────────
    int max_trade_show = wide_mode ? book_rows : trade_rows;
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

    // ── Book rows (+ trades in wide mode) ───────────────────────────────────
    for (int i = 0; i < book_rows; i++) {
        auto& f = fl[i];
        int n;

        // Bid side (green): qty right-aligned, price right-aligned
        pos = fb_puts(fb, pos, GREEN);
        if (wide_mode)
            n = snprintf(tmp, sizeof(tmp), "%9s %9s", f.bq, f.bp);
        else
            n = snprintf(tmp, sizeof(tmp), "%8s %8s", f.bq, f.bp);
        pos = fb_put(fb, pos, tmp, n);
        pos = fb_puts(fb, pos, RST);

        // Book separator
        if (wide_mode)
            pos = fb_puts(fb, pos, " \xe2\x94\x82 ");   // ` │ `
        else
            pos = fb_put(fb, pos, "\xe2\x94\x82", 3);    // `│`

        // Ask side (red): price left-aligned, qty right-aligned
        pos = fb_puts(fb, pos, RED);
        if (wide_mode)
            n = snprintf(tmp, sizeof(tmp), "%-9s %9s", f.ap, f.aq);
        else
            n = snprintf(tmp, sizeof(tmp), "%-8s %8s", f.ap, f.aq);
        pos = fb_put(fb, pos, tmp, n);
        pos = fb_puts(fb, pos, RST);

        // Wide: append trade column
        if (wide_mode) {
            pos = fb_puts(fb, pos, " \xe2\x94\x82 ");    // ` │ `
            if (i == 0) {
                // Sell strength bar (grows right) + volume
                pos = render_strength_bar(fb, pos, RED, 'S', sell_strength, 32, strength_scale);
                n = snprintf(tmp, sizeof(tmp), "%6.3f", sell_vol);
                pos = fb_puts(fb, pos, RED);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
            } else if (i == 1) {
                // Buy strength bar (grows right) + volume
                pos = render_strength_bar(fb, pos, GREEN, 'B', buy_strength, 32, strength_scale);
                n = snprintf(tmp, sizeof(tmp), "%6.3f", buy_vol);
                pos = fb_puts(fb, pos, GREEN);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
            } else {
                int ti = i - 2;  // trades shift down by 2
                if (ti < actual_trades && ft[ti].valid) {
                    auto& t = ft[ti];
                    pos = fb_puts(fb, pos, t.is_buyer ? GREEN : RED);
                    n = snprintf(tmp, sizeof(tmp), "%c %9s %9s %12s",
                                 t.is_buyer ? 'B' : 'S', t.tp, t.tq, t.tt);
                    pos = fb_put(fb, pos, tmp, n);
                    pos = fb_puts(fb, pos, RST);
                    pos = fb_puts(fb, pos, DIM);
                    n = snprintf(tmp, sizeof(tmp), " %-5s", t.tf);
                    pos = fb_put(fb, pos, tmp, n);
                    pos = fb_puts(fb, pos, RST);
                }
            }
        }

        // Wide + hist: append interval histogram column
        if (show_hist) {
            pos = fb_puts(fb, pos, " \xe2\x94\x82 ");  // ` │ `
            if (i == 0) {
                // Title row
                n = snprintf(tmp, sizeof(tmp), "INTERVALS (%u)", interval_total);
                pos = fb_puts(fb, pos, BOLD);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
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
                    pos = fb_put(fb, pos, "\xe2\x94\x82", 3);  // │
                    if (cnt > 0 && interval_total > 0) {
                        float pct = 100.0f * cnt / interval_total;
                        n = snprintf(tmp, sizeof(tmp), "%.1f%%", pct);
                        pos = fb_puts(fb, pos, DIM);
                        pos = fb_put(fb, pos, tmp, n);
                        pos = fb_puts(fb, pos, RST);
                    }
                }
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
        pos = fb_puts(fb, pos, RED);
        pos = fb_put(fb, pos, tmp, n);
        pos = fb_puts(fb, pos, RST);
        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
        fb[pos++] = ' ';
        pos = render_strength_bar(fb, pos, GREEN, 'B', buy_strength, narrow_bar_w, strength_scale);
        n = snprintf(tmp, sizeof(tmp), "%6.3f", buy_vol);
        pos = fb_puts(fb, pos, GREEN);
        pos = fb_put(fb, pos, tmp, n);
        pos = fb_puts(fb, pos, RST);
        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';

        for (int i = 0; i < trade_rows; i++) {
            if (i < actual_trades && ft[i].valid) {
                auto& t = ft[i];
                pos = fb_puts(fb, pos, t.is_buyer ? GREEN : RED);
                int n = snprintf(tmp, sizeof(tmp), " %c %8s %8s %8s",
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

    // ── Log lines ───────────────────────────────────────────────────────────
    for (int i = 0; i < log_rows; i++) {
        if (i < (int)s.log_count) {
            size_t idx = (s.log_write - 1 - i) & 63;
            pos = fb_puts(fb, pos, DIM);
            pos = fb_puts(fb, pos, s.log_lines[idx]);
            pos = fb_puts(fb, pos, RST);
        }
        pos = fb_puts(fb, pos, K);
        // No trailing \n on the very last line — avoids scrolling the terminal
        if (i < log_rows - 1) fb[pos++] = '\n';
    }

    return pos;
}

// ============================================================================
// Main
// ============================================================================

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
    std::strncpy(state.exchange, argv[1], sizeof(state.exchange) - 1);
    std::strncpy(state.symbol, argv[2], sizeof(state.symbol) - 1);

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
                int data_depth = std::max({(int)state.bid_count, (int)state.ask_count, (int)state.trade_count});
                int needed = std::max(data_depth, BOOK_MIN);
                if (needed < book_rows) {
                    log_rows += book_rows - needed;
                    book_rows = needed;
                }
            } else {
                int book_depth = std::max((int)state.bid_count, (int)state.ask_count);
                int needed_book = std::max(book_depth, BOOK_MIN);
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
