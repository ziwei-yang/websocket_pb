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

static constexpr int MAX_LATENCY_SAMPLES = 512;

struct ViewerState {
    BookLevel bids[MAX_BOOK], asks[MAX_BOOK];
    uint8_t   bid_count = 0, ask_count = 0;
    int64_t   book_seq = 0;

    TradeEntry trades[16];
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

    char       exchange[32];
    char       symbol[32];
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
// Event processing
// ============================================================================

static void apply_event(ViewerState& s, const MktEvent& evt) {
    s.total_events++;
    s.last_recv_ts_ns = evt.recv_ts_ns;
    s.last_event_ts_ns = evt.event_ts_ns;
    s.last_nic_ts_ns = evt.nic_ts_ns;

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
    } else if (evt.is_trade_array()) {
        for (uint8_t i = 0; i < evt.count && i < MAX_TRADES; i++) {
            s.trades[s.trade_write & 15] = evt.payload.trades.entries[i];
            s.trade_write++;
            if (s.trade_count < 16) s.trade_count++;
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

static int render(const ViewerState& s, char* fb, int book_rows, int trade_rows, int log_rows, bool wide_mode, int term_cols) {
    int pos = 0;
    char tmp[512];
    static constexpr const char* K = "\033[K";  // erase-to-EOL

    pos = fb_puts(fb, pos, "\033[H");

    // ── Merged header + latency title ───────────────────────────────────────
    {
        char delay_str[48] = "";
        int delay_len = 0;
        if (s.last_recv_ts_ns > 0) {
            int64_t svr_ms = (s.last_recv_ts_ns - s.last_event_ts_ns) / 1000000;
            if (s.last_nic_ts_ns > 0) {
                double local_us = static_cast<double>(s.last_recv_ts_ns - s.last_nic_ts_ns) / 1000.0;
                delay_len = snprintf(delay_str, sizeof(delay_str),
                                     "%.1fus %+ldms", local_us, svr_ms);
            } else {
                delay_len = snprintf(delay_str, sizeof(delay_str),
                                     "%+ldms", svr_ms);
            }
        }

        // Left part: " BINANCE BTC-USDT 2.3us +42ms"
        pos = fb_puts(fb, pos, BOLD);
        int n = snprintf(tmp, sizeof(tmp), " %s %s", s.exchange, s.symbol);
        pos = fb_put(fb, pos, tmp, n);
        int used = 1 + static_cast<int>(std::strlen(s.exchange)) + 1 + static_cast<int>(std::strlen(s.symbol));

        if (delay_len > 0) {
            fb[pos++] = ' ';
            pos = fb_puts(fb, pos, RST);
            pos = fb_puts(fb, pos, DIM);
            pos = fb_put(fb, pos, delay_str, delay_len);
            pos = fb_puts(fb, pos, RST);
            used += 1 + delay_len;
        } else {
            pos = fb_puts(fb, pos, RST);
        }

        // Right part: latency stats + latest value (if available)
        if (s.latency_count > 0) {
            float avg = static_cast<float>(s.latency_sum / s.latency_write);
            float latest = s.latency_us[(s.latency_write - 1) % MAX_LATENCY_SAMPLES];

            char stats[80];
            int stats_len = snprintf(stats, sizeof(stats), " min %.1f  avg %.1f  max %.1f (#%ld) ",
                                     s.latency_min, avg, s.latency_max, s.latency_max_seq);

            char latest_str[16];
            int latest_len = snprintf(latest_str, sizeof(latest_str), " %.1fus", latest);

            // Fill dashes between left part and stats
            pos = fb_puts(fb, pos, DIM);
            fb[pos++] = ' ';
            used += 1;

            int fill_before = term_cols - used - stats_len - latest_len;
            // At least 2 dashes before stats
            if (fill_before < 2) fill_before = 2;
            for (int i = 0; i < fill_before && i < 300; i++)
                pos = fb_put(fb, pos, "\xe2\x94\x80", 3);

            pos = fb_put(fb, pos, stats, stats_len);
            pos = fb_put(fb, pos, latest_str, latest_len);
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

    // ── Pre-format trades ───────────────────────────────────────────────────
    int max_trade_show = wide_mode ? book_rows : trade_rows;
    if (max_trade_show > 16) max_trade_show = 16;
    struct FmtTrade { char tp[32], tq[32], tt[16]; bool is_buyer; bool valid; };
    FmtTrade ft[16];
    int tmax_pdec = 0, tmax_qdec = 0;
    int actual_trades = std::min(max_trade_show, (int)s.trade_count);

    for (int i = 0; i < actual_trades; i++) {
        size_t idx = (s.trade_write - 1 - i) & 15;
        const auto& t = s.trades[idx];
        auto& f = ft[i];
        f.valid = true;
        f.is_buyer = t.is_buyer();
        fmt_price(f.tp, sizeof(f.tp), t.price, PRICE_EXP);
        fmt_qty(f.tq, sizeof(f.tq), t.qty, QTY_EXP);
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
    }
    for (int i = actual_trades; i < max_trade_show; i++)
        ft[i].valid = false;
    for (int i = 0; i < actual_trades; i++) {
        pad_to_decimals(ft[i].tp, tmax_pdec);
        pad_to_decimals(ft[i].tq, tmax_qdec);
    }

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
            if (i < actual_trades && ft[i].valid) {
                auto& t = ft[i];
                pos = fb_puts(fb, pos, t.is_buyer ? GREEN : RED);
                n = snprintf(tmp, sizeof(tmp), "%c %9s %9s %12s",
                             t.is_buyer ? 'B' : 'S', t.tp, t.tq, t.tt);
                pos = fb_put(fb, pos, tmp, n);
                pos = fb_puts(fb, pos, RST);
            }
        }

        pos = fb_puts(fb, pos, K);
        fb[pos++] = '\n';
    }

    // ── Narrow: stacked trades section ──────────────────────────────────────
    if (!wide_mode) {
        pos = fb_puts(fb, pos, BOLD);
        pos = fb_puts(fb, pos, " TRADES");
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
            int fixed_rows = 1 + chart_rows + (wide_mode ? 0 : 1);  // header + chart bars; narrow adds trades_header
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

            int len = render(state, frame_buf, book_rows, trade_rows, log_rows, wide_mode, term_cols);
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
