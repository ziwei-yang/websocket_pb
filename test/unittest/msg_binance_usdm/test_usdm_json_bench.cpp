// test/unittest/test_usdm_json_bench.cpp
// Benchmark: custom position-aware JSON parser vs yyjson 0.12.0
// Pure parsing benchmark — no IPC rings, no pipeline_data.hpp
//
// Build:  make bench-usdm-json-parser NIC_MTU=1500
// Run:    ./build/test_usdm_json_bench

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>

// Part 1 only — no pipeline_data.hpp needed
#include "msg/01_binance_usdm_json.hpp"
#include "msg/02_binance_usdm_yyjson.hpp"

#include "core/timing.hpp"

using namespace websocket::json;
using namespace websocket::msg;

// ============================================================================
// Test JSON payloads
// ============================================================================

static constexpr const char* AGG_TRADE_JSON = R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":123456789,"s":"BTCUSDT","a":5933014,"p":"0.001","q":"100","nq":"100","f":100,"l":105,"T":123456785,"m":true}})";

static constexpr const char* DEPTH_PARTIAL_JSON = R"({"stream":"btcusdt@depth20","data":{"e":"depthUpdate","E":1571889248277,"T":1571889248276,"s":"BTCUSDT","U":390497796,"u":390497878,"pu":390497794,"b":[["7403.89","0.002"],["7403.90","3.906"],["7404.00","1.428"],["7404.85","5.239"],["7405.43","2.562"]],"a":[["7405.96","3.340"],["7406.63","4.525"],["7407.08","2.475"],["7407.15","4.800"],["7407.20","0.175"]]}})";

static constexpr const char* DEPTH_DIFF_JSON = R"({"stream":"btcusdt@depth@100ms","data":{"e":"depthUpdate","E":123456789,"T":123456788,"s":"BTCUSDT","U":157,"u":160,"pu":149,"b":[["0.0024","10"]],"a":[["0.0026","100"]]}})";

// ============================================================================
// Benchmark parameters
// ============================================================================

static constexpr int WARMUP_ITERS = 100;
static constexpr int BENCH_ITERS  = 1000;

// ============================================================================
// Volatile sink to prevent dead-code elimination
// ============================================================================

static volatile int64_t g_sink_i64;
static volatile bool    g_sink_bool;

static inline void sink(int64_t v) { g_sink_i64 = v; }
static inline void sink(bool v)    { g_sink_bool = v; }

// ============================================================================
// Stats
// ============================================================================

struct BenchStats {
    uint64_t min_ns;
    uint64_t median_ns;
    uint64_t mean_ns;
    uint64_t max_ns;
};

static BenchStats compute_stats(std::vector<uint64_t>& cycles, uint64_t tsc_freq) {
    std::sort(cycles.begin(), cycles.end());
    uint64_t sum = 0;
    for (auto c : cycles) sum += c;

    BenchStats s;
    s.min_ns    = cycles_to_ns(cycles.front(), tsc_freq);
    s.median_ns = cycles_to_ns(cycles[cycles.size() / 2], tsc_freq);
    s.mean_ns   = cycles_to_ns(sum / cycles.size(), tsc_freq);
    s.max_ns    = cycles_to_ns(cycles.back(), tsc_freq);
    return s;
}

static void print_stats(const char* label, const BenchStats& s) {
    std::printf("  %-8s min=%luns  med=%luns  mean=%luns  max=%luns\n",
                label,
                (unsigned long)s.min_ns, (unsigned long)s.median_ns,
                (unsigned long)s.mean_ns, (unsigned long)s.max_ns);
}

// ============================================================================
// Custom parser benchmarks
// ============================================================================

static std::vector<uint64_t> bench_custom_agg_trade(const uint8_t* json, uint32_t len) {
    std::vector<uint64_t> cycles(BENCH_ITERS);

    // Warmup
    for (int i = 0; i < WARMUP_ITERS; i++) {
        auto hdr = parse_combined_stream(json, len);
        auto tf = parse_agg_trade_fields(hdr.data_start, hdr.data_start + hdr.data_len);
        sink(tf.event_time_ms); sink(tf.agg_trade_id); sink(tf.price_mantissa);
        sink(tf.qty_mantissa); sink(tf.trade_time_ms); sink(tf.buyer_is_maker);
    }

    // Timed
    for (int i = 0; i < BENCH_ITERS; i++) {
        uint64_t t0 = rdtscp();
        auto hdr = parse_combined_stream(json, len);
        auto tf = parse_agg_trade_fields(hdr.data_start, hdr.data_start + hdr.data_len);
        sink(tf.event_time_ms); sink(tf.agg_trade_id); sink(tf.price_mantissa);
        sink(tf.qty_mantissa); sink(tf.trade_time_ms); sink(tf.buyer_is_maker);
        uint64_t t1 = rdtscp();
        cycles[i] = t1 - t0;
    }
    return cycles;
}

static std::vector<uint64_t> bench_custom_depth_partial(const uint8_t* json, uint32_t len) {
    std::vector<uint64_t> cycles(BENCH_ITERS);
    BookLevel bids[20], asks[20];

    for (int i = 0; i < WARMUP_ITERS; i++) {
        auto hdr = parse_combined_stream(json, len);
        const uint8_t* data_end = hdr.data_start + hdr.data_len;
        auto df = parse_depth_fields(hdr.data_start, data_end);
        uint8_t bc = parse_book_levels(df.bids_array, data_end, bids, 20);
        uint8_t ac = parse_book_levels(df.asks_array, data_end, asks, 20);
        sink(df.event_time_ms); sink(df.txn_time_ms); sink(df.last_update_id);
        for (uint8_t j = 0; j < bc; j++) { sink(bids[j].price); sink(bids[j].qty); }
        for (uint8_t j = 0; j < ac; j++) { sink(asks[j].price); sink(asks[j].qty); }
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        uint64_t t0 = rdtscp();
        auto hdr = parse_combined_stream(json, len);
        const uint8_t* data_end = hdr.data_start + hdr.data_len;
        auto df = parse_depth_fields(hdr.data_start, data_end);
        uint8_t bc = parse_book_levels(df.bids_array, data_end, bids, 20);
        uint8_t ac = parse_book_levels(df.asks_array, data_end, asks, 20);
        sink(df.event_time_ms); sink(df.txn_time_ms); sink(df.last_update_id);
        for (uint8_t j = 0; j < bc; j++) { sink(bids[j].price); sink(bids[j].qty); }
        for (uint8_t j = 0; j < ac; j++) { sink(asks[j].price); sink(asks[j].qty); }
        uint64_t t1 = rdtscp();
        cycles[i] = t1 - t0;
    }
    return cycles;
}

static std::vector<uint64_t> bench_custom_depth_diff(const uint8_t* json, uint32_t len) {
    std::vector<uint64_t> cycles(BENCH_ITERS);
    DeltaEntry bids[32], asks[32];

    for (int i = 0; i < WARMUP_ITERS; i++) {
        auto hdr = parse_combined_stream(json, len);
        const uint8_t* data_end = hdr.data_start + hdr.data_len;
        auto df = parse_depth_fields(hdr.data_start, data_end);
        uint8_t bc = parse_delta_levels(df.bids_array, data_end, bids, 32, false);
        uint8_t ac = parse_delta_levels(df.asks_array, data_end, asks, 32, true);
        sink(df.event_time_ms); sink(df.txn_time_ms); sink(df.last_update_id);
        for (uint8_t j = 0; j < bc; j++) { sink(bids[j].price); sink(bids[j].qty); }
        for (uint8_t j = 0; j < ac; j++) { sink(asks[j].price); sink(asks[j].qty); }
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        uint64_t t0 = rdtscp();
        auto hdr = parse_combined_stream(json, len);
        const uint8_t* data_end = hdr.data_start + hdr.data_len;
        auto df = parse_depth_fields(hdr.data_start, data_end);
        uint8_t bc = parse_delta_levels(df.bids_array, data_end, bids, 32, false);
        uint8_t ac = parse_delta_levels(df.asks_array, data_end, asks, 32, true);
        sink(df.event_time_ms); sink(df.txn_time_ms); sink(df.last_update_id);
        for (uint8_t j = 0; j < bc; j++) { sink(bids[j].price); sink(bids[j].qty); }
        for (uint8_t j = 0; j < ac; j++) { sink(asks[j].price); sink(asks[j].qty); }
        uint64_t t1 = rdtscp();
        cycles[i] = t1 - t0;
    }
    return cycles;
}

// ============================================================================
// yyjson benchmarks (using yy:: namespace from 02_binance_usdm_yyjson.hpp)
// ============================================================================

using namespace websocket::json::yy;

static std::vector<uint64_t> bench_yyjson_agg_trade(const uint8_t* json, uint32_t len) {
    std::vector<uint64_t> cycles(BENCH_ITERS);

    for (int i = 0; i < WARMUP_ITERS; i++) {
        auto res = yy_parse_combined(json, len);
        auto tf = yy_parse_agg_trade(res.data);
        sink(tf.event_time_ms); sink(tf.agg_trade_id); sink(tf.price_mantissa);
        sink(tf.qty_mantissa); sink(tf.trade_time_ms); sink(tf.buyer_is_maker);
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        uint64_t t0 = rdtscp();
        auto res = yy_parse_combined(json, len);
        auto tf = yy_parse_agg_trade(res.data);
        sink(tf.event_time_ms); sink(tf.agg_trade_id); sink(tf.price_mantissa);
        sink(tf.qty_mantissa); sink(tf.trade_time_ms); sink(tf.buyer_is_maker);
        uint64_t t1 = rdtscp();
        cycles[i] = t1 - t0;
    }
    return cycles;
}

static std::vector<uint64_t> bench_yyjson_depth_partial(const uint8_t* json, uint32_t len) {
    std::vector<uint64_t> cycles(BENCH_ITERS);
    BookLevel bids[20], asks[20];

    for (int i = 0; i < WARMUP_ITERS; i++) {
        auto res = yy_parse_combined(json, len);
        auto df = yy_parse_depth(res.data);
        sink(df.event_time_ms); sink(df.txn_time_ms); sink(df.last_update_id);
        uint8_t bc = yy_parse_book_levels(df.bids_val, bids, 20);
        uint8_t ac = yy_parse_book_levels(df.asks_val, asks, 20);
        for (uint8_t j = 0; j < bc; j++) { sink(bids[j].price); sink(bids[j].qty); }
        for (uint8_t j = 0; j < ac; j++) { sink(asks[j].price); sink(asks[j].qty); }
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        uint64_t t0 = rdtscp();
        auto res = yy_parse_combined(json, len);
        auto df = yy_parse_depth(res.data);
        sink(df.event_time_ms); sink(df.txn_time_ms); sink(df.last_update_id);
        uint8_t bc = yy_parse_book_levels(df.bids_val, bids, 20);
        uint8_t ac = yy_parse_book_levels(df.asks_val, asks, 20);
        for (uint8_t j = 0; j < bc; j++) { sink(bids[j].price); sink(bids[j].qty); }
        for (uint8_t j = 0; j < ac; j++) { sink(asks[j].price); sink(asks[j].qty); }
        uint64_t t1 = rdtscp();
        cycles[i] = t1 - t0;
    }
    return cycles;
}

static std::vector<uint64_t> bench_yyjson_depth_diff(const uint8_t* json, uint32_t len) {
    std::vector<uint64_t> cycles(BENCH_ITERS);
    DeltaEntry bid_deltas[32], ask_deltas[32];

    for (int i = 0; i < WARMUP_ITERS; i++) {
        auto res = yy_parse_combined(json, len);
        auto df = yy_parse_depth(res.data);
        sink(df.event_time_ms); sink(df.txn_time_ms); sink(df.last_update_id);
        uint8_t bc = yy_parse_delta_levels(df.bids_val, bid_deltas, 32, false);
        uint8_t ac = yy_parse_delta_levels(df.asks_val, ask_deltas, 32, true);
        for (uint8_t j = 0; j < bc; j++) { sink(bid_deltas[j].price); sink(bid_deltas[j].qty); }
        for (uint8_t j = 0; j < ac; j++) { sink(ask_deltas[j].price); sink(ask_deltas[j].qty); }
    }

    for (int i = 0; i < BENCH_ITERS; i++) {
        uint64_t t0 = rdtscp();
        auto res = yy_parse_combined(json, len);
        auto df = yy_parse_depth(res.data);
        sink(df.event_time_ms); sink(df.txn_time_ms); sink(df.last_update_id);
        uint8_t bc = yy_parse_delta_levels(df.bids_val, bid_deltas, 32, false);
        uint8_t ac = yy_parse_delta_levels(df.asks_val, ask_deltas, 32, true);
        for (uint8_t j = 0; j < bc; j++) { sink(bid_deltas[j].price); sink(bid_deltas[j].qty); }
        for (uint8_t j = 0; j < ac; j++) { sink(ask_deltas[j].price); sink(ask_deltas[j].qty); }
        uint64_t t1 = rdtscp();
        cycles[i] = t1 - t0;
    }
    return cycles;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    uint64_t tsc_freq = calibrate_tsc_freq();

    std::printf("=== USDM JSON Parse Benchmark (%d iterations) ===\n", BENCH_ITERS);
    std::printf("TSC freq: %.2f GHz\n\n", tsc_freq / 1e9);

    // aggTrade
    {
        auto len = static_cast<uint32_t>(std::strlen(AGG_TRADE_JSON));
        auto custom_cycles = bench_custom_agg_trade((const uint8_t*)AGG_TRADE_JSON, len);
        auto yyjson_cycles = bench_yyjson_agg_trade((const uint8_t*)AGG_TRADE_JSON, len);

        auto cs = compute_stats(custom_cycles, tsc_freq);
        auto ys = compute_stats(yyjson_cycles, tsc_freq);

        std::printf("aggTrade:\n");
        print_stats("custom:", cs);
        print_stats("yyjson:", ys);
        std::printf("  speedup: %.1fx\n\n",
                    (double)ys.median_ns / (double)(cs.median_ns ? cs.median_ns : 1));
    }

    // depthUpdate (partial, 5+5 levels)
    {
        auto len = static_cast<uint32_t>(std::strlen(DEPTH_PARTIAL_JSON));
        auto custom_cycles = bench_custom_depth_partial((const uint8_t*)DEPTH_PARTIAL_JSON, len);
        auto yyjson_cycles = bench_yyjson_depth_partial((const uint8_t*)DEPTH_PARTIAL_JSON, len);

        auto cs = compute_stats(custom_cycles, tsc_freq);
        auto ys = compute_stats(yyjson_cycles, tsc_freq);

        std::printf("depthUpdate (partial, 5+5 levels):\n");
        print_stats("custom:", cs);
        print_stats("yyjson:", ys);
        std::printf("  speedup: %.1fx\n\n",
                    (double)ys.median_ns / (double)(cs.median_ns ? cs.median_ns : 1));
    }

    // depthUpdate (diff, 1+1 levels)
    {
        auto len = static_cast<uint32_t>(std::strlen(DEPTH_DIFF_JSON));
        auto custom_cycles = bench_custom_depth_diff((const uint8_t*)DEPTH_DIFF_JSON, len);
        auto yyjson_cycles = bench_yyjson_depth_diff((const uint8_t*)DEPTH_DIFF_JSON, len);

        auto cs = compute_stats(custom_cycles, tsc_freq);
        auto ys = compute_stats(yyjson_cycles, tsc_freq);

        std::printf("depthUpdate (diff, 1+1 levels):\n");
        print_stats("custom:", cs);
        print_stats("yyjson:", ys);
        std::printf("  speedup: %.1fx\n\n",
                    (double)ys.median_ns / (double)(cs.median_ns ? cs.median_ns : 1));
    }

    return 0;
}
