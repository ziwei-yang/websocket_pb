// test/unittest/test_usdm_json_parser.cpp
// Unit tests for BinanceUSDMJsonParser (JSON market data for USD-M futures)
// Creates real IPC ring files in /dev/shm/hft/test_usdm_json/ to test publish path.

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

// pipeline_data.hpp must come first (defines PIPELINE_DATA_HPP_INCLUDED)
#include "pipeline/pipeline_data.hpp"
#include "msg/01_binance_usdm_json.hpp"
#include "msg/02_binance_usdm_yyjson.hpp"

using namespace websocket::json;
using namespace websocket::pipeline;
using namespace websocket::msg;

// ============================================================================
// Test JSON payloads (from Binance docs)
// ============================================================================

constexpr const char* AGG_TRADE_JSON = R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":123456789,"s":"BTCUSDT","a":5933014,"p":"0.001","q":"100","nq":"100","f":100,"l":105,"T":123456785,"m":true}})";

constexpr const char* DEPTH_PARTIAL_JSON = R"({"stream":"btcusdt@depth20","data":{"e":"depthUpdate","E":1571889248277,"T":1571889248276,"s":"BTCUSDT","U":390497796,"u":390497878,"pu":390497794,"b":[["7403.89","0.002"],["7403.90","3.906"],["7404.00","1.428"],["7404.85","5.239"],["7405.43","2.562"]],"a":[["7405.96","3.340"],["7406.63","4.525"],["7407.08","2.475"],["7407.15","4.800"],["7407.20","0.175"]]}})";

constexpr const char* DEPTH_DIFF_JSON = R"({"stream":"btcusdt@depth@100ms","data":{"e":"depthUpdate","E":123456789,"T":123456788,"s":"BTCUSDT","U":157,"u":160,"pu":149,"b":[["0.0024","10"]],"a":[["0.0026","100"]]}})";

constexpr const char* DEPTH_DIFF_DELETE_JSON = R"({"stream":"btcusdt@depth@250ms","data":{"e":"depthUpdate","E":123456790,"T":123456789,"s":"BTCUSDT","U":161,"u":165,"pu":160,"b":[["0.0024","0"]],"a":[["0.0026","50"]]}})";

// ============================================================================
// Ring setup/teardown helpers (same as test_sbe_handler.cpp)
// ============================================================================

static constexpr const char* SHM_BASE =
#ifdef __APPLE__
    "/tmp/hft";
#else
    "/dev/shm/hft";
#endif

static constexpr const char* RING_DIR = "test_usdm_json";
static constexpr size_t RING_ELEMENTS = 64;

struct RingFiles {
    std::string hdr_path;
    std::string dat_path;
};

static RingFiles create_ring_files(const char* name, size_t element_size = sizeof(MktEvent)) {
    size_t buffer_size = RING_ELEMENTS * element_size;

    std::string dir = std::string(SHM_BASE) + "/" + RING_DIR;
    mkdir(SHM_BASE, 0755);
    mkdir(dir.c_str(), 0755);

    std::string base = dir + "/" + name;
    RingFiles rf;
    rf.hdr_path = base + ".hdr";
    rf.dat_path = base + ".dat";

    uint32_t producer_offset = hftshm::default_producer_offset();
    uint32_t consumer_0_offset = hftshm::default_consumer_0_offset();
    uint32_t header_size = hftshm::header_segment_size(1);

    int hdr_fd = open(rf.hdr_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0644);
    assert(hdr_fd >= 0);
    assert(ftruncate(hdr_fd, header_size) == 0);
    void* hdr_ptr = mmap(nullptr, header_size, PROT_READ | PROT_WRITE, MAP_SHARED, hdr_fd, 0);
    close(hdr_fd);
    assert(hdr_ptr != MAP_FAILED);

    hftshm::metadata_init(hdr_ptr, 1, element_size, buffer_size,
                          producer_offset, consumer_0_offset, header_size);

    auto* cursor = reinterpret_cast<std::atomic<int64_t>*>(
        static_cast<char*>(hdr_ptr) + producer_offset);
    auto* published = reinterpret_cast<std::atomic<int64_t>*>(
        static_cast<char*>(hdr_ptr) + producer_offset + hftshm::CACHE_LINE);
    cursor->store(-1, std::memory_order_relaxed);
    published->store(-1, std::memory_order_relaxed);

    auto* cons_seq = reinterpret_cast<std::atomic<int64_t>*>(
        static_cast<char*>(hdr_ptr) + consumer_0_offset);
    cons_seq->store(-1, std::memory_order_relaxed);

    munmap(hdr_ptr, header_size);

    int dat_fd = open(rf.dat_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0644);
    assert(dat_fd >= 0);
    assert(ftruncate(dat_fd, buffer_size) == 0);
    void* dat_ptr = mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, dat_fd, 0);
    close(dat_fd);
    assert(dat_ptr != MAP_FAILED);
    memset(dat_ptr, 0, buffer_size);
    munmap(dat_ptr, buffer_size);

    return rf;
}

static void cleanup_ring_files() {
    std::string dir = std::string(SHM_BASE) + "/" + RING_DIR;
    const char* names[] = { "mkt_event", "ws_frame_info" };
    for (auto* name : names) {
        unlink((dir + "/" + name + ".hdr").c_str());
        unlink((dir + "/" + name + ".dat").c_str());
    }
    rmdir(dir.c_str());
}

// ============================================================================
// Read published MktEvents from the ring
// ============================================================================

static std::vector<MktEvent> read_published_events(
    IPCRingProducer<MktEvent>& prod) {
    std::vector<MktEvent> events;
    int64_t pub_seq = prod.published_sequence();
    for (int64_t seq = 0; seq <= pub_seq; seq++) {
        events.push_back(prod[seq]);
    }
    return events;
}

// ============================================================================
// Test harness
// ============================================================================

struct TestHarness {
    RingFiles rf;
    disruptor::ipc::shared_region* region = nullptr;
    IPCRingProducer<MktEvent>* prod = nullptr;

    RingFiles ws_rf;
    disruptor::ipc::shared_region* ws_region = nullptr;
    IPCRingProducer<WSFrameInfo>* ws_prod = nullptr;

    BinanceUSDMYyjsonParser handler;

    TestHarness() {
        rf = create_ring_files("mkt_event");
        std::string ring_name = std::string(RING_DIR) + "/mkt_event";
        region = new disruptor::ipc::shared_region(ring_name);
        prod = new IPCRingProducer<MktEvent>(*region);
        handler.mkt_event_prod = prod;
        handler.merge_enabled = true;

        ws_rf = create_ring_files("ws_frame_info", sizeof(WSFrameInfo));
        std::string ws_ring_name = std::string(RING_DIR) + "/ws_frame_info";
        ws_region = new disruptor::ipc::shared_region(ws_ring_name);
        ws_prod = new IPCRingProducer<WSFrameInfo>(*ws_region);
        handler.ws_frame_info_prod_ = ws_prod;
    }

    ~TestHarness() {
        delete ws_prod;
        delete ws_region;
        delete prod;
        delete region;
    }

    void feed_frame(uint8_t ci, const char* json) {
        WSFrameInfo info{};
        info.clear();
        info.connection_id = ci;
        handler.on_ws_data(handler.sbe_state_[ci], ci,
                           (const uint8_t*)json, static_cast<uint32_t>(strlen(json)), info);
        handler.sbe_state_[ci].reset();

        // Mimic WSCore: publish WSFrameInfo to ring, fill pending_ring_seq_slot_
        int64_t seq = ws_prod->try_claim();
        assert(seq >= 0);
        (*ws_prod)[seq] = info;
        ws_prod->publish(seq);
        if (handler.pending_ring_seq_slot_) {
            *handler.pending_ring_seq_slot_ = seq;
            handler.pending_ring_seq_slot_ = nullptr;
        }
    }

    void idle() {
        handler.on_batch_end(0);
    }

    std::vector<MktEvent> published() {
        return read_published_events(*prod);
    }
};

// ============================================================================
// Test counters
// ============================================================================

static int tests_passed = 0;
static int tests_total = 0;

#define RUN_TEST(fn) do { \
    tests_total++; \
    fn(); \
    tests_passed++; \
    std::printf("  PASS  %s\n", #fn); \
} while(0)

// ============================================================================
// JSON Parsing Primitive Tests
// ============================================================================

void test_parse_int64_fast() {
    // Positive
    {
        const uint8_t* s = (const uint8_t*)"123456789,";
        const uint8_t* p = s;
        const uint8_t* end = s + 10;
        int64_t v = parse_int64_fast(p, end);
        assert(v == 123456789);
        assert(*p == ',');
    }
    // Negative
    {
        const uint8_t* s = (const uint8_t*)"-42,";
        const uint8_t* p = s;
        int64_t v = parse_int64_fast(p, s + 4);
        assert(v == -42);
    }
    // Zero
    {
        const uint8_t* s = (const uint8_t*)"0,";
        const uint8_t* p = s;
        int64_t v = parse_int64_fast(p, s + 2);
        assert(v == 0);
    }
    // Large
    {
        const uint8_t* s = (const uint8_t*)"1571889248277,";
        const uint8_t* p = s;
        int64_t v = parse_int64_fast(p, s + 14);
        assert(v == 1571889248277LL);
    }
}

void test_parse_decimal_string() {
    // "0.001" -> 1 (all digits, dot ignored)
    {
        const uint8_t* s = (const uint8_t*)"\"0.001\",";
        const uint8_t* p = s;
        int64_t v = parse_decimal_string(p, s + 8);
        assert(v == 1);
    }
    // "100" -> 100
    {
        const uint8_t* s = (const uint8_t*)"\"100\",";
        const uint8_t* p = s;
        int64_t v = parse_decimal_string(p, s + 6);
        assert(v == 100);
    }
    // "7403.89" -> 740389
    {
        const uint8_t* s = (const uint8_t*)"\"7403.89\",";
        const uint8_t* p = s;
        int64_t v = parse_decimal_string(p, s + 10);
        assert(v == 740389);
    }
    // "0.0024" -> 24
    {
        const uint8_t* s = (const uint8_t*)"\"0.0024\",";
        const uint8_t* p = s;
        int64_t v = parse_decimal_string(p, s + 9);
        assert(v == 24);
    }
    // "3.340" -> 3340
    {
        const uint8_t* s = (const uint8_t*)"\"3.340\",";
        const uint8_t* p = s;
        int64_t v = parse_decimal_string(p, s + 8);
        assert(v == 3340);
    }
    // "0" -> 0
    {
        const uint8_t* s = (const uint8_t*)"\"0\",";
        const uint8_t* p = s;
        int64_t v = parse_decimal_string(p, s + 4);
        assert(v == 0);
    }
}

void test_classify_stream() {
    {
        const char* s = "btcusdt@aggTrade";
        auto t = classify_stream((const uint8_t*)s, strlen(s));
        assert(t == UsdmStreamType::AGG_TRADE);
    }
    {
        const char* s = "btcusdt@depth20";
        auto t = classify_stream((const uint8_t*)s, strlen(s));
        assert(t == UsdmStreamType::DEPTH_PARTIAL);
    }
    {
        const char* s = "btcusdt@depth5";
        auto t = classify_stream((const uint8_t*)s, strlen(s));
        assert(t == UsdmStreamType::DEPTH_PARTIAL);
    }
    {
        const char* s = "btcusdt@depth10";
        auto t = classify_stream((const uint8_t*)s, strlen(s));
        assert(t == UsdmStreamType::DEPTH_PARTIAL);
    }
    {
        const char* s = "btcusdt@depth@100ms";
        auto t = classify_stream((const uint8_t*)s, strlen(s));
        assert(t == UsdmStreamType::DEPTH_DIFF);
    }
    {
        const char* s = "btcusdt@depth@250ms";
        auto t = classify_stream((const uint8_t*)s, strlen(s));
        assert(t == UsdmStreamType::DEPTH_DIFF);
    }
    {
        const char* s = "unknown_stream";
        auto t = classify_stream((const uint8_t*)s, strlen(s));
        assert(t == UsdmStreamType::UNKNOWN);
    }
}

void test_parse_combined_stream() {
    auto hdr = parse_combined_stream((const uint8_t*)AGG_TRADE_JSON,
                                     static_cast<uint32_t>(strlen(AGG_TRADE_JSON)));
    assert(hdr.type == UsdmStreamType::AGG_TRADE);
    assert(hdr.data_start != nullptr);
    assert(*hdr.data_start == '{');
    assert(hdr.data_len > 0);

    // Verify data object starts with {"e":"aggTrade"
    assert(std::memcmp(hdr.data_start, "{\"e\":\"aggTrade\"", 15) == 0);
}

// ============================================================================
// yyjson Primitive Tests
// ============================================================================

void test_yy_decimal_cstr_to_int64() {
    using websocket::json::yy::decimal_cstr_to_int64;
    assert(decimal_cstr_to_int64(nullptr) == 0);
    assert(decimal_cstr_to_int64("0") == 0);
    assert(decimal_cstr_to_int64("0.001") == 1);
    assert(decimal_cstr_to_int64("7403.89") == 740389);
    assert(decimal_cstr_to_int64("-42.5") == -425);
}

void test_yy_parse_combined() {
    auto res = websocket::json::yy::yy_parse_combined(
        (const uint8_t*)AGG_TRADE_JSON,
        static_cast<uint32_t>(strlen(AGG_TRADE_JSON)));
    assert(res.type == UsdmStreamType::AGG_TRADE);
    assert(res.data != nullptr);

    auto res2 = websocket::json::yy::yy_parse_combined(
        (const uint8_t*)DEPTH_PARTIAL_JSON,
        static_cast<uint32_t>(strlen(DEPTH_PARTIAL_JSON)));
    assert(res2.type == UsdmStreamType::DEPTH_PARTIAL);
    assert(res2.data != nullptr);

    auto res3 = websocket::json::yy::yy_parse_combined(
        (const uint8_t*)DEPTH_DIFF_JSON,
        static_cast<uint32_t>(strlen(DEPTH_DIFF_JSON)));
    assert(res3.type == UsdmStreamType::DEPTH_DIFF);
    assert(res3.data != nullptr);
}

void test_yy_parse_agg_trade() {
    auto res = websocket::json::yy::yy_parse_combined(
        (const uint8_t*)AGG_TRADE_JSON,
        static_cast<uint32_t>(strlen(AGG_TRADE_JSON)));
    auto tf = websocket::json::yy::yy_parse_agg_trade(res.data);
    assert(tf.valid);
    assert(tf.event_time_ms == 123456789);
    assert(tf.agg_trade_id == 5933014);
    assert(tf.price_mantissa == 1);       // "0.001" -> 1
    assert(tf.qty_mantissa == 100);       // "100" -> 100
    assert(tf.trade_time_ms == 123456785);
    assert(tf.buyer_is_maker == true);
}

void test_yy_parse_depth_partial() {
    auto res = websocket::json::yy::yy_parse_combined(
        (const uint8_t*)DEPTH_PARTIAL_JSON,
        static_cast<uint32_t>(strlen(DEPTH_PARTIAL_JSON)));
    auto df = websocket::json::yy::yy_parse_depth(res.data);
    assert(df.valid);
    assert(df.event_time_ms == 1571889248277LL);
    assert(df.txn_time_ms == 1571889248276LL);
    assert(df.last_update_id == 390497878);

    BookLevel bids[20], asks[20];
    uint8_t bc = websocket::json::yy::yy_parse_book_levels(df.bids_val, bids, 20);
    uint8_t ac = websocket::json::yy::yy_parse_book_levels(df.asks_val, asks, 20);
    assert(bc == 5);
    assert(ac == 5);
    assert(bids[0].price == 740389);  // "7403.89"
    assert(bids[0].qty == 2);         // "0.002"
    assert(asks[0].price == 740596);  // "7405.96"
    assert(asks[0].qty == 3340);      // "3.340"
}

void test_yy_parse_depth_diff() {
    auto res = websocket::json::yy::yy_parse_combined(
        (const uint8_t*)DEPTH_DIFF_JSON,
        static_cast<uint32_t>(strlen(DEPTH_DIFF_JSON)));
    auto df = websocket::json::yy::yy_parse_depth(res.data);
    assert(df.valid);
    assert(df.event_time_ms == 123456789);
    assert(df.txn_time_ms == 123456788);
    assert(df.last_update_id == 160);

    DeltaEntry bid_deltas[32], ask_deltas[32];
    uint8_t bc = websocket::json::yy::yy_parse_delta_levels(df.bids_val, bid_deltas, 32, false);
    uint8_t ac = websocket::json::yy::yy_parse_delta_levels(df.asks_val, ask_deltas, 32, true);
    assert(bc == 1);
    assert(ac == 1);
    assert(bid_deltas[0].price == 24);   // "0.0024"
    assert(bid_deltas[0].qty == 10);
    assert(bid_deltas[0].action == static_cast<uint8_t>(DeltaAction::UPDATE));
    assert(bid_deltas[0].is_bid());
    assert(ask_deltas[0].price == 26);   // "0.0026"
    assert(ask_deltas[0].qty == 100);
    assert(ask_deltas[0].action == static_cast<uint8_t>(DeltaAction::UPDATE));
    assert(ask_deltas[0].is_ask());
}

// ============================================================================
// aggTrade Handling Tests
// ============================================================================

void test_agg_trade_single() {
    TestHarness h;
    h.feed_frame(0, AGG_TRADE_JSON);
    h.idle();

    auto events = h.published();
    assert(events.size() == 1);
    auto& e = events[0];
    assert(e.is_trade_array());
    assert(e.count == 1);
    assert(e.event_ts_ns == 123456789LL * 1000000LL);
    assert(e.src_seq == 5933014);

    auto& te = e.payload.trades.entries[0];
    assert(te.trade_id == 5933014);
    assert(te.price == 1000000);       // "0.001" -> 1 * price_scale(10^6)
    assert(te.qty == 10000000);        // "100" -> 100 * qty_scale(10^5)
    assert(te.trade_time_ns == 123456785LL * 1000000LL);
    // m=true means buyer is maker, taker is seller -> NOT IS_BUYER
    assert(!te.is_buyer());
}

void test_agg_trade_merge() {
    TestHarness h;

    // 3 aggTrades with different ids
    char buf1[512], buf2[512], buf3[512];
    snprintf(buf1, sizeof(buf1), R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":100,"s":"BTCUSDT","a":5933014,"p":"0.001","q":"100","nq":"100","f":100,"l":105,"T":99,"m":true}})");
    snprintf(buf2, sizeof(buf2), R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":101,"s":"BTCUSDT","a":5933015,"p":"0.002","q":"200","nq":"200","f":106,"l":110,"T":100,"m":false}})");
    snprintf(buf3, sizeof(buf3), R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":102,"s":"BTCUSDT","a":5933016,"p":"0.003","q":"300","nq":"300","f":111,"l":115,"T":101,"m":true}})");

    h.feed_frame(0, buf1);
    h.feed_frame(0, buf2);
    h.feed_frame(0, buf3);
    h.idle();

    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].count == 3);
    assert(events[0].payload.trades.entries[0].trade_id == 5933014);
    assert(events[0].payload.trades.entries[1].trade_id == 5933015);
    assert(events[0].payload.trades.entries[2].trade_id == 5933016);
}

void test_agg_trade_merge_overflow() {
    TestHarness h;

    // Feed 15 aggTrades — should flush at MAX_TRADES(11) + remainder(4)
    for (int i = 0; i < 15; i++) {
        char buf[512];
        snprintf(buf, sizeof(buf),
            R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":%d,"s":"BTCUSDT","a":%d,"p":"1.00","q":"10","nq":"10","f":%d,"l":%d,"T":%d,"m":true}})",
            100 + i, 1000 + i, i * 10, i * 10 + 5, 100 + i);
        h.feed_frame(0, buf);
    }
    h.idle();

    auto events = h.published();
    // First flush at count=11, then remaining 4 flushed by idle()
    assert(events.size() == 2);
    assert(events[0].count == 11);
    assert(events[1].count == 4);
}

void test_agg_trade_dedup() {
    TestHarness h;

    // Feed same aggTrade twice (same id)
    h.feed_frame(0, AGG_TRADE_JSON);
    h.feed_frame(0, AGG_TRADE_JSON);
    h.idle();

    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].count == 1);
}

void test_agg_trade_no_merge() {
    TestHarness h;
    h.handler.merge_enabled = false;

    h.feed_frame(0, AGG_TRADE_JSON);

    // Should publish immediately without idle()
    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_trade_array());
    assert(events[0].count == 1);
    assert(events[0].payload.trades.entries[0].trade_id == 5933014);
}

// ============================================================================
// Depth Snapshot Tests
// ============================================================================

void test_depth_snapshot_parse() {
    TestHarness h;
    h.feed_frame(0, DEPTH_PARTIAL_JSON);

    auto events = h.published();
    assert(events.size() == 1);
    auto& e = events[0];
    assert(e.is_book_snapshot());
    assert(e.is_snapshot());
    assert(e.event_ts_ns == 1571889248277LL * 1000000LL);
    assert(e.src_seq == 390497878);
    assert(e.count == 5);   // 5 bids
    assert(e.count2 == 5);  // 5 asks

    // Verify first bid: "7403.89" -> 740389 * price_scale(10^6)
    assert(e.payload.snapshot.levels[0].price == 740389000000LL);
    assert(e.payload.snapshot.levels[0].qty == 200000LL);  // "0.002" -> 2 * qty_scale(10^5)

    // Verify first ask: "7405.96" -> 740596 * price_scale(10^6)
    assert(e.payload.snapshot.levels[5].price == 740596000000LL);
    assert(e.payload.snapshot.levels[5].qty == 334000000LL);  // "3.340" -> 3340 * qty_scale(10^5)
}

void test_depth_snapshot_dedup() {
    TestHarness h;
    h.feed_frame(0, DEPTH_PARTIAL_JSON);
    h.feed_frame(0, DEPTH_PARTIAL_JSON);

    auto events = h.published();
    assert(events.size() == 1);
}

// ============================================================================
// Depth Delta Tests
// ============================================================================

void test_depth_delta_parse() {
    TestHarness h;
    h.feed_frame(0, DEPTH_DIFF_JSON);

    auto events = h.published();
    assert(events.size() == 1);
    auto& e = events[0];
    assert(e.is_book_delta());
    assert(e.src_seq == 160);
    assert(e.event_ts_ns == 123456789LL * 1000000LL);
    assert(e.count == 2);  // 1 bid + 1 ask

    // Bid delta: "0.0024" -> 24 * price_scale(10^6), qty "10" -> 10 * qty_scale(10^5)
    auto& bid = e.payload.deltas.entries[0];
    assert(bid.price == 24000000LL);
    assert(bid.qty == 1000000LL);
    assert(bid.action == static_cast<uint8_t>(DeltaAction::UPDATE));
    assert(bid.is_bid());

    // Ask delta: "0.0026" -> 26 * price_scale(10^6), qty "100" -> 100 * qty_scale(10^5)
    auto& ask = e.payload.deltas.entries[1];
    assert(ask.price == 26000000LL);
    assert(ask.qty == 10000000LL);
    assert(ask.action == static_cast<uint8_t>(DeltaAction::UPDATE));
    assert(ask.is_ask());
}

void test_depth_delta_delete() {
    TestHarness h;
    // First feed a diff to set baseline seq
    h.feed_frame(0, DEPTH_DIFF_JSON);
    // Then feed the delete diff (higher seq)
    h.feed_frame(0, DEPTH_DIFF_DELETE_JSON);

    auto events = h.published();
    assert(events.size() == 2);
    auto& e = events[1];
    assert(e.is_book_delta());
    assert(e.src_seq == 165);
    assert(e.count == 2);

    // Bid: qty "0" -> DELETE (0 * scale = 0)
    auto& bid = e.payload.deltas.entries[0];
    assert(bid.price == 24000000LL);
    assert(bid.qty == 0);
    assert(bid.action == static_cast<uint8_t>(DeltaAction::DELETE));

    // Ask: qty "50" -> UPDATE, scaled
    auto& ask = e.payload.deltas.entries[1];
    assert(ask.price == 26000000LL);
    assert(ask.qty == 5000000LL);
    assert(ask.action == static_cast<uint8_t>(DeltaAction::UPDATE));
}

void test_depth_delta_dedup() {
    TestHarness h;
    h.feed_frame(0, DEPTH_DIFF_JSON);
    // Same seq (160) should be discarded
    h.feed_frame(0, DEPTH_DIFF_JSON);

    auto events = h.published();
    assert(events.size() == 1);
}

// ============================================================================
// Cross-Type Tests
// ============================================================================

void test_cross_type_flush_trades_then_depth() {
    TestHarness h;

    // Feed 2 aggTrades (pending)
    char buf1[512], buf2[512];
    snprintf(buf1, sizeof(buf1), R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":100,"s":"BTCUSDT","a":1000,"p":"1.00","q":"10","nq":"10","f":1,"l":1,"T":99,"m":true}})");
    snprintf(buf2, sizeof(buf2), R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":101,"s":"BTCUSDT","a":1001,"p":"2.00","q":"20","nq":"20","f":2,"l":2,"T":100,"m":false}})");
    h.feed_frame(0, buf1);
    h.feed_frame(0, buf2);

    // Now feed a depth20 — should flush trades first
    h.feed_frame(0, DEPTH_PARTIAL_JSON);

    auto events = h.published();
    assert(events.size() >= 2);
    // First event should be the flushed trade array
    assert(events[0].is_trade_array());
    assert(events[0].count == 2);
    // Second event should be book snapshot
    assert(events[1].is_book_snapshot());
}

void test_batch_end_flushes_trades() {
    TestHarness h;

    char buf1[512], buf2[512];
    snprintf(buf1, sizeof(buf1), R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":100,"s":"BTCUSDT","a":2000,"p":"1.00","q":"10","nq":"10","f":1,"l":1,"T":99,"m":true}})");
    snprintf(buf2, sizeof(buf2), R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":101,"s":"BTCUSDT","a":2001,"p":"2.00","q":"20","nq":"20","f":2,"l":2,"T":100,"m":false}})");
    h.feed_frame(0, buf1);
    h.feed_frame(0, buf2);

    // Nothing published yet (merged)
    auto pre = h.published();
    assert(pre.size() == 0);

    h.idle();

    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_trade_array());
    assert(events[0].count == 2);
}

void test_disconnect_reconnect() {
    TestHarness h;

    h.handler.on_disconnected(0);
    h.handler.on_reconnected(0);

    auto events = h.published();
    assert(events.size() == 2);

    assert(events[0].is_system_status());
    assert(events[0].payload.status.status_type ==
           static_cast<uint8_t>(SystemStatusType::DISCONNECTED));
    assert(events[0].payload.status.connection_id == 0);

    assert(events[1].is_system_status());
    assert(events[1].payload.status.status_type ==
           static_cast<uint8_t>(SystemStatusType::RECONNECTED));
    assert(events[1].payload.status.connection_id == 0);
}

// ============================================================================
// Cross-connection monotonic ordering tests (ported from SBE tests 40, 43, 45)
// ============================================================================

void test_cross_conn_merge_flush_before_mix() {
    TestHarness h;
    h.handler.merge_enabled = true;

    // Conn 0 feeds aggTrade id=1000
    char buf0[512];
    snprintf(buf0, sizeof(buf0),
        R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":100,"s":"BTCUSDT","a":1000,"p":"1.00","q":"10","nq":"10","f":1,"l":1,"T":99,"m":true}})");
    h.feed_frame(0, buf0);
    // Pending buffer now has 1 entry from conn 0

    // Conn 1 feeds aggTrade id=2000 — different connection
    char buf1[512];
    snprintf(buf1, sizeof(buf1),
        R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":200,"s":"BTCUSDT","a":2000,"p":"2.00","q":"20","nq":"20","f":2,"l":2,"T":199,"m":false}})");
    h.feed_frame(1, buf1);
    // Cross-conn flush should have flushed conn 0's pending before adding conn 1's

    // Flush remaining
    h.idle();

    auto events = h.published();

    // Should have 2 separate TRADE_ARRAY events (not mixed)
    int trade_count = 0;
    int64_t prev_seq = 0;
    for (auto& ev : events) {
        if (ev.event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY)) {
            assert(ev.src_seq > prev_seq);
            prev_seq = ev.src_seq;
            trade_count++;
        }
    }
    assert(trade_count == 2);

    // First event should be conn 0's trade (src_seq = 1000)
    // Second event should be conn 1's trade (src_seq = 2000)
    bool found_1000 = false, found_2000 = false;
    for (auto& ev : events) {
        if (ev.event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY)) {
            if (ev.src_seq == 1000) found_1000 = true;
            if (ev.src_seq == 2000) found_2000 = true;
        }
    }
    assert(found_1000);
    assert(found_2000);
}

void test_cross_conn_pending_ci_attribution() {
    TestHarness h;
    h.handler.merge_enabled = true;

    // Conn 0 feeds 2 trades (ids 1000, 1001)
    char buf0a[512], buf0b[512];
    snprintf(buf0a, sizeof(buf0a),
        R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":100,"s":"BTCUSDT","a":1000,"p":"1.00","q":"10","nq":"10","f":1,"l":1,"T":99,"m":true}})");
    snprintf(buf0b, sizeof(buf0b),
        R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":101,"s":"BTCUSDT","a":1001,"p":"1.00","q":"10","nq":"10","f":2,"l":2,"T":100,"m":true}})");
    h.feed_frame(0, buf0a);
    h.feed_frame(0, buf0b);
    // Pending buffer has 2 entries from conn 0

    assert(h.handler.has_pending_trades_ == true);
    assert(h.handler.pending_trades_ci_ == 0);

    // Conn 2 feeds 2 trades (ids 2000, 2001) — different connection
    char buf2a[512], buf2b[512];
    snprintf(buf2a, sizeof(buf2a),
        R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":200,"s":"BTCUSDT","a":2000,"p":"2.00","q":"20","nq":"20","f":3,"l":3,"T":199,"m":false}})");
    snprintf(buf2b, sizeof(buf2b),
        R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":201,"s":"BTCUSDT","a":2001,"p":"2.00","q":"20","nq":"20","f":4,"l":4,"T":200,"m":false}})");
    h.feed_frame(2, buf2a);
    h.feed_frame(2, buf2b);

    // After cross-conn flush: conn 0's trades published, then conn 2's pending
    // pending_trades_ci_ should now be 2
    assert(h.handler.pending_trades_ci_ == 2);

    // Flush remaining
    h.idle();

    auto events = h.published();
    int trade_count = 0;
    for (auto& ev : events) {
        if (ev.event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY))
            trade_count++;
    }
    // Two separate batches
    assert(trade_count == 2);
}

void test_pending_max_id_monotonic() {
    TestHarness h;
    h.handler.merge_enabled = true;

    // Conn 0: trade with id=509
    char buf0[512];
    snprintf(buf0, sizeof(buf0),
        R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":100,"s":"BTCUSDT","a":509,"p":"1.00","q":"10","nq":"10","f":1,"l":1,"T":99,"m":true}})");
    h.feed_frame(0, buf0);
    // pending_trades_max_id_ = 509
    assert(h.handler.pending_trades_max_id_ >= 509);

    // Conn 0: older trade id=100 (should be caught by dedup: 100 <= eff_tid 509)
    char buf1[512];
    snprintf(buf1, sizeof(buf1),
        R"({"stream":"btcusdt@aggTrade","data":{"e":"aggTrade","E":50,"s":"BTCUSDT","a":100,"p":"1.00","q":"10","nq":"10","f":1,"l":1,"T":49,"m":true}})");
    h.feed_frame(0, buf1);

    // pending_trades_max_id_ should NOT decrease
    assert(h.handler.pending_trades_max_id_ >= 509);

    h.idle();
    // last_trade_id_ should be at least 509
    assert(h.handler.last_trade_id_ >= 509);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    cleanup_ring_files();

    std::printf("=== BinanceUSDMYyjsonParser Unit Tests ===\n");

    // JSON parsing primitives
    RUN_TEST(test_parse_int64_fast);
    RUN_TEST(test_parse_decimal_string);
    RUN_TEST(test_classify_stream);
    RUN_TEST(test_parse_combined_stream);

    // yyjson primitives
    RUN_TEST(test_yy_decimal_cstr_to_int64);
    RUN_TEST(test_yy_parse_combined);
    RUN_TEST(test_yy_parse_agg_trade);
    RUN_TEST(test_yy_parse_depth_partial);
    RUN_TEST(test_yy_parse_depth_diff);

    // aggTrade handling
    RUN_TEST(test_agg_trade_single);
    RUN_TEST(test_agg_trade_merge);
    RUN_TEST(test_agg_trade_merge_overflow);
    RUN_TEST(test_agg_trade_dedup);
    RUN_TEST(test_agg_trade_no_merge);

    // Depth snapshot
    RUN_TEST(test_depth_snapshot_parse);
    RUN_TEST(test_depth_snapshot_dedup);

    // Depth delta
    RUN_TEST(test_depth_delta_parse);
    RUN_TEST(test_depth_delta_delete);
    RUN_TEST(test_depth_delta_dedup);

    // Cross-type
    RUN_TEST(test_cross_type_flush_trades_then_depth);
    RUN_TEST(test_batch_end_flushes_trades);
    RUN_TEST(test_disconnect_reconnect);

    std::printf("\n--- Cross-connection monotonic ordering ---\n");
    cleanup_ring_files();
    RUN_TEST(test_cross_conn_merge_flush_before_mix);
    cleanup_ring_files();
    RUN_TEST(test_cross_conn_pending_ci_attribution);
    cleanup_ring_files();
    RUN_TEST(test_pending_max_id_monotonic);

    std::printf("\n%d/%d tests passed\n", tests_passed, tests_total);
    cleanup_ring_files();

    return (tests_passed == tests_total) ? 0 : 1;
}
