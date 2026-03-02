// End-to-end line-width verification for mkt_viewer render()
//
// Unity-includes mkt_viewer.cpp (with main() suppressed), creates synthetic
// ViewerState data, calls render() in multiple configurations, and verifies
// that every output line has exactly term_cols visible characters.
//
// Build:
//   g++ -std=c++20 -O2 -DMKT_VIEWER_NO_MAIN -DNIC_MTU=1500 \
//       -I./src -I../01_shared_headers -D__linux__ \
//       -o /tmp/test_mkt_width tools/test_mkt_viewer_width.cpp
//
// Run:
//   /tmp/test_mkt_width

#ifndef MKT_VIEWER_NO_MAIN
#define MKT_VIEWER_NO_MAIN
#endif
#include "mkt_viewer.cpp"

#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>
#include <string>

// Count visible (display) columns in a raw framebuffer line.
// Skips ANSI escape sequences (\033[...letter) and \033[K.
// UTF-8 multi-byte codepoints count as 1 column (all our chars are width-1).
static int visible_width(const char* line, int len) {
    int w = 0;
    int i = 0;
    while (i < len) {
        if (line[i] == '\033') {
            // Skip ESC [ ... <letter>
            i++;
            if (i < len && line[i] == '[') {
                i++;
                while (i < len && !((line[i] >= 'A' && line[i] <= 'Z') ||
                                     (line[i] >= 'a' && line[i] <= 'z')))
                    i++;
                if (i < len) i++;  // skip final letter
            }
            continue;
        }
        unsigned char c = static_cast<unsigned char>(line[i]);
        if (c < 0x80) {
            w++; i++;
        } else if (c < 0xC0) {
            i++;  // continuation byte
        } else if (c < 0xE0) {
            w++; i += 2;
        } else if (c < 0xF0) {
            w++; i += 3;
        } else {
            w++; i += 4;
        }
    }
    return w;
}

// Split framebuffer into lines, skipping the leading \033[H (cursor home).
// Returns vector of (start, length) pairs.
static std::vector<std::pair<int,int>> split_lines(const char* fb, int len) {
    std::vector<std::pair<int,int>> lines;
    int start = 0;
    // Skip leading \033[H
    if (len >= 4 && fb[0] == '\033' && fb[1] == '[' && fb[2] == 'H')
        start = 3;
    int line_start = start;
    for (int i = start; i < len; i++) {
        if (fb[i] == '\n') {
            lines.push_back({line_start, i - line_start});
            line_start = i + 1;
        }
    }
    // Last line (no trailing \n)
    if (line_start < len)
        lines.push_back({line_start, len - line_start});
    return lines;
}

// Populate a ViewerState with synthetic but realistic data
static void populate_state(ViewerState& s, int num_levels, int num_trades,
                           bool with_latency, bool with_histogram) {
    std::strncpy(s.exchange, "Binance", sizeof(s.exchange) - 1);
    std::strncpy(s.symbol, "BTC-USDT", sizeof(s.symbol) - 1);

    // Orderbook levels
    s.ob.bid_count = num_levels;
    s.ob.ask_count = num_levels;
    for (int i = 0; i < num_levels && i < MAX_BOOK; i++) {
        s.ob.bids[i] = {static_cast<int64_t>((100000 - i * 10) * 1e8), static_cast<int64_t>(12345678)};
        s.ob.asks[i] = {static_cast<int64_t>((100000 + i * 10) * 1e8), static_cast<int64_t>(98765432)};
    }

    // Trades
    s.trade_count = num_trades;
    s.trade_write = num_trades;
    for (int i = 0; i < num_trades && i < (int)ViewerState::TRADE_BUF; i++) {
        auto& t = s.trades[i];
        t.price          = static_cast<int64_t>(99999 * 1e8);
        t.qty            = static_cast<int64_t>(12345678);
        t.trade_time_ns  = 1700000000000000000LL + i * 100000000LL;
        t.trade_id       = 1000 + i;
        t.flags          = (i % 2 == 0) ? TradeFlags::IS_BUYER : 0;
    }

    // Latency data
    if (with_latency) {
        for (int i = 0; i < 200; i++) {
            s.latency_us[i] = 1.0f + (i % 10) * 0.5f;
        }
        s.latency_count = 200;
        s.latency_write = 200;
        s.latency_min = 1.0f;
        s.latency_max = 6.0f;
        s.latency_sum = 700.0;
    }

    // Histogram data
    if (with_histogram) {
        for (int seg = 0; seg < ViewerState::HIST_SEGMENTS; seg++) {
            for (int b = 0; b < ViewerState::INTERVAL_BUCKETS; b++) {
                s.hist_segs[seg].bins[b] = 10 + b * 5 + seg;
                s.hist_segs[seg].count += s.hist_segs[seg].bins[b];
            }
        }
    }

    // Volume/depth data
    for (int i = 0; i < ViewerState::VOL_SEGMENTS; i++) {
        s.vol_segs[i].buy_qty  = 1.5;
        s.vol_segs[i].sell_qty = 2.3;
        s.depth_segs[i].depth_sum = 100.0;
        s.depth_segs[i].samples = 10;
    }

    // Connection status
    s.last_status_type = 0;  // heartbeat
    s.last_status_conn = 0;
    s.last_recv_ts_ns = 1700000000000000000LL;
    s.last_event_ts_ns = 1700000000000000000LL - 1500000LL;  // 1.5ms

    // Log lines
    s.log_count = 5;
    s.log_write = 5;
    for (int i = 0; i < 5; i++) {
        snprintf(s.log_lines[i], 160, " %-14d DELTA    %dd    r=%-19lld e=%lld",
                 1000 + i, 3 + i, 1700000000000000000LL, 1700000000000000000LL);
    }

    s.total_events = 100;
}

struct TestConfig {
    const char* name;
    int term_cols;
    int term_rows;
    bool wide_mode;
    bool show_hist;
    int book_rows;
    int trade_rows;
    int log_rows;
    int num_levels;
    int num_trades;
    bool with_latency;
    bool with_histogram;
};

static int run_test(const TestConfig& cfg) {
    ViewerState state{};
    populate_state(state, cfg.num_levels, cfg.num_trades,
                   cfg.with_latency, cfg.with_histogram);

    static char fb[65536];
    int len = render(state, fb, cfg.book_rows, cfg.trade_rows, cfg.log_rows,
                     cfg.wide_mode, cfg.show_hist, cfg.term_cols);

    auto lines = split_lines(fb, len);

    int errors = 0;
    int line_no = 0;

    // Identify which lines are which section
    // Line 0: header
    // Lines 1-2: latency chart (if with_latency)
    // Then: book_rows lines (wide) or book_rows + 2 strength + trade_rows (narrow)
    // Then: log_rows lines

    // For wide+hist mode, check book rows are exactly term_cols wide.
    // This is the primary fix target.
    if (cfg.wide_mode && cfg.show_hist) {
        int chart_rows = cfg.with_latency ? 2 : 0;
        int book_start = 1 + chart_rows;

        for (int i = 0; i < cfg.book_rows && (book_start + i) < (int)lines.size(); i++) {
            auto& [start, line_len] = lines[book_start + i];
            int w = visible_width(fb + start, line_len);
            if (w != cfg.term_cols) {
                fprintf(stderr, "  FAIL book row %d (line %d): width=%d, expected=%d\n",
                        i, book_start + i, w, cfg.term_cols);
                errors++;
            }
        }
    }

    // For wide mode (no hist), book rows should be exactly 84 visible chars:
    // book(19+3+19=41) + trade_sep(3) + trade(40) = 84
    // Only test when term_cols >= 84 (otherwise the row inherently overflows).
    if (cfg.wide_mode && !cfg.show_hist && cfg.term_cols >= 84) {
        int chart_rows = cfg.with_latency ? 2 : 0;
        int book_start = 1 + chart_rows;
        int expected_book_w = 84;

        for (int i = 0; i < cfg.book_rows && (book_start + i) < (int)lines.size(); i++) {
            auto& [start, line_len] = lines[book_start + i];
            int w = visible_width(fb + start, line_len);
            if (w != expected_book_w) {
                fprintf(stderr, "  FAIL wide-nohist book row %d (line %d): width=%d, expected=%d\n",
                        i, book_start + i, w, expected_book_w);
                errors++;
            }
        }
    }

    // For narrow mode, check book rows are consistent width:
    // book(17+1+17=35) with \033[K clearing remainder — just verify <= term_cols.
    if (!cfg.wide_mode) {
        int book_start = 1;  // after header
        for (int i = 0; i < cfg.book_rows && (book_start + i) < (int)lines.size(); i++) {
            auto& [start, line_len] = lines[book_start + i];
            int w = visible_width(fb + start, line_len);
            if (w > cfg.term_cols) {
                fprintf(stderr, "  FAIL narrow book row %d (line %d): width=%d > term_cols=%d\n",
                        i, book_start + i, w, cfg.term_cols);
                errors++;
            }
        }
    }

    return errors;
}

int main() {
    int total_errors = 0;

    // Test configurations:
    TestConfig tests[] = {
        // ── Wide + histogram: primary fix target ──

        // Various term widths
        {"wide+hist tc=120, 10 book, 5 trades, latency+hist",
         120, 30, true, true, 10, 0, 3, 10, 5, true, true},
        {"wide+hist tc=140, 10 book, 8 trades, latency+hist",
         140, 30, true, true, 10, 0, 3, 10, 8, true, true},
        {"wide+hist tc=160, 15 book, 3 trades, latency+hist",
         160, 40, true, true, 15, 0, 3, 15, 3, true, true},
        {"wide+hist tc=200, 10 book, 0 trades, latency+hist",
         200, 30, true, true, 10, 0, 3, 10, 0, true, true},

        // Edge: minimum hist width (tc=120 → hist_bar_width=27)
        {"wide+hist tc=120 min-hist, 15 book, 0 trades",
         120, 35, true, true, 15, 0, 3, 15, 0, true, true},

        // Edge: very wide terminal
        {"wide+hist tc=250, 10 book, 5 trades",
         250, 30, true, true, 10, 0, 3, 10, 5, true, true},

        // No latency chart
        {"wide+hist tc=130, 8 book, 4 trades, no-latency+hist",
         130, 25, true, true, 8, 0, 3, 8, 4, false, true},

        // More book rows than hist buckets (14) — tests beyond-hist padding
        {"wide+hist tc=140, 18 book (>14 hist buckets), 5 trades",
         140, 35, true, true, 18, 0, 3, 10, 5, true, true},

        // Edge: 20 book rows, only 1 trade — tests many empty trade slots
        {"wide+hist tc=140, 20 book, 1 trade (many empty)",
         140, 40, true, true, 20, 0, 3, 20, 1, true, true},

        // 0 levels, 0 trades — all rows are empty
        {"wide+hist tc=120, 10 book, 0 levels 0 trades",
         120, 30, true, true, 10, 0, 3, 0, 0, true, true},

        // Row 0 (title) + row 1-13 (buckets) + row 14 (overflow) — exactly 15 rows
        {"wide+hist tc=140, 16 book (title+13bars+overflow+1beyond)",
         140, 35, true, true, 16, 0, 3, 10, 5, true, true},

        // All hist buckets populated + overflow
        {"wide+hist tc=150, 15 book, 10 trades, full hist",
         150, 35, true, true, 15, 0, 3, 10, 10, true, true},

        // ── Wide, no histogram ──
        {"wide-nohist tc=100, 10 book, 5 trades, latency",
         100, 30, true, false, 10, 0, 3, 10, 5, true, false},
        {"wide-nohist tc=84 (exact fit), 6 book, 2 trades",
         84, 20, true, false, 6, 0, 3, 6, 2, false, false},

        // ── Narrow mode ──
        {"narrow tc=60, 6 book, 4 trade_rows, 2 log",
         60, 20, false, false, 6, 4, 2, 6, 4, false, false},
        {"narrow tc=40, 4 book, 3 trade_rows, 1 log",
         40, 15, false, false, 4, 3, 1, 4, 3, false, false},
    };

    for (auto& t : tests) {
        printf("TEST: %s\n", t.name);
        int errors = run_test(t);
        if (errors == 0) {
            printf("  PASS\n");
        } else {
            printf("  %d error(s)\n", errors);
        }
        total_errors += errors;
    }

    printf("\n========================================\n");
    if (total_errors == 0) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("FAILED: %d total error(s)\n", total_errors);
    }

    return total_errors > 0 ? 1 : 0;
}
