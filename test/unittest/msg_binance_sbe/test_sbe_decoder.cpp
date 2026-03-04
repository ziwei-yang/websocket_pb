// test/unittest/test_sbe_decoder.cpp
// Offline unit tests for Binance Spot SBE decoders (src/msg/00_binance_spot_sbe.hpp)
// Constructs binary SBE payloads and verifies every decoder against the schema.
// No network, no SSL, no XDP — pure header-only decode logic.

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <string_view>

#include "msg/00_binance_spot_sbe.hpp"
#include "msg/mkt_event.hpp"

// ============================================================================
// SBEBuilder — construct binary SBE payloads in a stack buffer
// ============================================================================

struct SBEBuilder {
    uint8_t buf[4096];
    size_t pos = 0;

    void write_u8(uint8_t v)   { buf[pos++] = v; }
    void write_i8(int8_t v)    { std::memcpy(buf + pos, &v, 1); pos += 1; }
    void write_u16(uint16_t v) { std::memcpy(buf + pos, &v, 2); pos += 2; }
    void write_u32(uint32_t v) { std::memcpy(buf + pos, &v, 4); pos += 4; }
    void write_i64(int64_t v)  { std::memcpy(buf + pos, &v, 8); pos += 8; }
    void write_u64(uint64_t v) { std::memcpy(buf + pos, &v, 8); pos += 8; }

    void write_header(uint16_t block_length, uint16_t template_id,
                      uint16_t schema_id = 1, uint16_t version = 0) {
        write_u16(block_length);
        write_u16(template_id);
        write_u16(schema_id);
        write_u16(version);
    }

    // groupSizeEncoding: u16 block_length + u32 num_in_group = 6 bytes
    void write_group_size(uint16_t block_length, uint32_t num_in_group) {
        write_u16(block_length);
        write_u32(num_in_group);
    }

    // groupSize16Encoding: u16 block_length + u16 num_in_group = 4 bytes
    void write_group_size16(uint16_t block_length, uint16_t num_in_group) {
        write_u16(block_length);
        write_u16(num_in_group);
    }

    // varString8: u8 length + data
    void write_var_string8(std::string_view s) {
        write_u8(static_cast<uint8_t>(s.size()));
        std::memcpy(buf + pos, s.data(), s.size());
        pos += s.size();
    }

    // Pad to reach a specific position (relative to current start)
    void pad_to(size_t target) {
        while (pos < target) buf[pos++] = 0;
    }

    const uint8_t* data() const { return buf; }
    size_t size() const { return pos; }
    void reset() { pos = 0; }
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
// Part 1: Primitive read helpers
// ============================================================================

void test_read_helpers() {
    using namespace websocket::sbe;

    // i64
    {
        int64_t val = -123456789012345LL;
        uint8_t buf[8];
        std::memcpy(buf, &val, 8);
        assert(read_i64(buf) == val);
    }
    // u64
    {
        uint64_t val = 0xDEADBEEFCAFEBABEULL;
        uint8_t buf[8];
        std::memcpy(buf, &val, 8);
        assert(read_u64(buf) == val);
    }
    // u32
    {
        uint32_t val = 0x12345678;
        uint8_t buf[4];
        std::memcpy(buf, &val, 4);
        assert(read_u32(buf) == val);
    }
    // u16
    {
        uint16_t val = 0xABCD;
        uint8_t buf[2];
        std::memcpy(buf, &val, 2);
        assert(read_u16(buf) == val);
    }
    // i8
    {
        uint8_t buf[1] = { 0xF6 };  // -10 as signed
        assert(read_i8(buf) == -10);
    }
    // u8
    {
        uint8_t buf[1] = { 255 };
        assert(read_u8(buf) == 255);
    }
    // Zero values
    {
        uint8_t buf[8] = {};
        assert(read_i64(buf) == 0);
        assert(read_u64(buf) == 0);
        assert(read_u32(buf) == 0);
        assert(read_u16(buf) == 0);
        assert(read_i8(buf) == 0);
        assert(read_u8(buf) == 0);
    }
}

void test_to_double() {
    using namespace websocket::sbe;

    // Standard crypto exponents: -8 (satoshi precision)
    assert(to_double(12345678, -8) == 0.12345678);

    // exponent = 0
    assert(to_double(100, 0) == 100.0);

    // exponent = -1
    assert(to_double(5, -1) == 0.5);

    // Negative mantissa
    assert(to_double(-100, -2) == -1.0);

    // BUG 4 fix: positive exponents now in fast path
    assert(to_double(5, 1) == 50.0);
    assert(to_double(3, 2) == 300.0);
    assert(to_double(1, 8) == 1e8);

    // Edge of table: exponent = -8 (idx=0) and +8 (idx=16)
    assert(to_double(1, -8) == 1e-8);
    assert(to_double(1, 8) == 1e8);

    // Outside table range: should use fallback
    double v9 = to_double(1, 9);
    assert(std::fabs(v9 - 1e9) < 1.0);
    double vm9 = to_double(1, -9);
    assert(std::fabs(vm9 - 1e-9) < 1e-15);

    // Zero mantissa
    assert(to_double(0, -8) == 0.0);
    assert(to_double(0, 5) == 0.0);
}

// ============================================================================
// Part 2: SBE Header
// ============================================================================

void test_decode_header() {
    using namespace websocket::sbe;

    SBEBuilder b;
    b.write_header(18, 10001, 1, 0);

    SBEHeader hdr{};
    assert(decode_header(b.data(), b.size(), hdr));
    assert(hdr.block_length == 18);
    assert(hdr.template_id == 10001);
    assert(hdr.schema_id == 1);
    assert(hdr.version == 0);

    // Too short
    assert(!decode_header(b.data(), 7, hdr));
    assert(!decode_header(b.data(), 0, hdr));

    // Exact 8 bytes
    assert(decode_header(b.data(), 8, hdr));
}

// ============================================================================
// Part 3: Group encodings and varString8
// ============================================================================

void test_read_group_size() {
    using namespace websocket::sbe;

    SBEBuilder b;
    b.write_group_size(25, 3);

    GroupSize gs;
    assert(read_group_size(b.data(), b.size(), gs));
    assert(gs.block_length == 25);
    assert(gs.num_in_group == 3);

    // Too short
    assert(!read_group_size(b.data(), 5, gs));
    assert(!read_group_size(b.data(), 0, gs));

    // Large num_in_group (u32)
    b.reset();
    b.write_group_size(25, 100000);
    assert(read_group_size(b.data(), b.size(), gs));
    assert(gs.num_in_group == 100000);
}

void test_read_group_size16() {
    using namespace websocket::sbe;

    SBEBuilder b;
    b.write_group_size16(16, 10);

    GroupSize16 gs;
    assert(read_group_size16(b.data(), b.size(), gs));
    assert(gs.block_length == 16);
    assert(gs.num_in_group == 10);

    // Too short
    assert(!read_group_size16(b.data(), 3, gs));
}

void test_read_var_string8() {
    using namespace websocket::sbe;

    // Normal string
    {
        SBEBuilder b;
        b.write_var_string8("BTCUSDT");
        auto sv = read_var_string8(b.data(), b.size());
        assert(sv == "BTCUSDT");
    }
    // Empty string
    {
        SBEBuilder b;
        b.write_var_string8("");
        auto sv = read_var_string8(b.data(), b.size());
        assert(sv.empty());
    }
    // No data at all
    {
        auto sv = read_var_string8(nullptr, 0);
        assert(sv.empty());
    }
    // Length byte present but not enough data
    {
        uint8_t buf[2] = { 5, 'A' };  // says 5 bytes but only 1 available
        auto sv = read_var_string8(buf, 2);
        assert(sv.empty());
    }
}

void test_var_string8_max_len() {
    using namespace websocket::sbe;

    // 255-byte string (max for u8 length prefix)
    SBEBuilder b;
    char big[255];
    std::memset(big, 'X', 255);
    b.write_u8(255);
    std::memcpy(b.buf + b.pos, big, 255);
    b.pos += 255;

    auto sv = read_var_string8(b.data(), b.size());
    assert(sv.size() == 255);
    assert(sv[0] == 'X');
    assert(sv[254] == 'X');
}

// ============================================================================
// Part 4: TradesView (templateId=10000)
// ============================================================================

// Build a Trades wire message (header + body)
// Root block: event_time@0(i64), transact_time@8(i64), price_exp@16(i8), qty_exp@17(i8) = 18 bytes
// Group: groupSizeEncoding(6B) + entries(25B each)
// Var: symbol (varString8)

static SBEBuilder build_trades_msg(int64_t event_time, int64_t transact_time,
                                    int8_t price_exp, int8_t qty_exp,
                                    uint32_t num_trades,
                                    // Each trade: id, price_mantissa, qty_mantissa, is_buyer_maker
                                    const int64_t* ids, const int64_t* prices,
                                    const int64_t* qtys, const bool* buyer_maker,
                                    std::string_view symbol) {
    SBEBuilder b;
    // SBE header
    b.write_header(18, 10000, 1, 0);
    // Root block (18 bytes)
    b.write_i64(event_time);
    b.write_i64(transact_time);
    b.write_i8(price_exp);
    b.write_i8(qty_exp);
    // Group
    b.write_group_size(25, num_trades);
    for (uint32_t i = 0; i < num_trades; i++) {
        b.write_i64(ids[i]);
        b.write_i64(prices[i]);
        b.write_i64(qtys[i]);
        b.write_u8(buyer_maker[i] ? 1 : 0);
    }
    // Symbol
    b.write_var_string8(symbol);
    return b;
}

void test_trades_single() {
    using namespace websocket::sbe;

    int64_t ids[] = { 42 };
    int64_t prices[] = { 5000000 };
    int64_t qtys[] = { 100000 };
    bool bm[] = { true };

    auto b = build_trades_msg(1000000, 1000001, -8, -8, 1, ids, prices, qtys, bm, "BTCUSDT");

    // Full decode
    SBEHeader hdr{};
    assert(decode_header(b.data(), b.size(), hdr));
    assert(hdr.template_id == TRADES_STREAM);

    TradesView tv{};
    const uint8_t* body = b.data() + HEADER_SIZE;
    size_t body_len = b.size() - HEADER_SIZE;
    assert(TradesView::decode(body, body_len, hdr.block_length, tv));

    assert(tv.event_time_us() == 1000000);
    assert(tv.transact_time_us() == 1000001);
    assert(tv.price_exponent() == -8);
    assert(tv.qty_exponent() == -8);
    assert(tv.count() == 1);

    auto t0 = tv.trade(0);
    assert(t0.id() == 42);
    assert(t0.price_mantissa() == 5000000);
    assert(t0.qty_mantissa() == 100000);
    assert(t0.is_buyer_maker() == true);
    assert(t0.is_best_match() == true);  // constant

    assert(tv.symbol() == "BTCUSDT");
}

void test_trades_multiple() {
    using namespace websocket::sbe;

    int64_t ids[] = { 100, 101, 102 };
    int64_t prices[] = { 5000000, 5000100, 4999900 };
    int64_t qtys[] = { 10000, 20000, 30000 };
    bool bm[] = { true, false, true };

    auto b = build_trades_msg(2000000, 2000001, -8, -4, 3, ids, prices, qtys, bm, "ETHUSDT");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);
    TradesView tv{};
    assert(TradesView::decode(b.data() + HEADER_SIZE, b.size() - HEADER_SIZE, hdr.block_length, tv));

    assert(tv.count() == 3);
    assert(tv.qty_exponent() == -4);

    assert(tv.trade(0).id() == 100);
    assert(tv.trade(1).id() == 101);
    assert(tv.trade(2).id() == 102);

    assert(tv.trade(0).is_buyer_maker() == true);
    assert(tv.trade(1).is_buyer_maker() == false);
    assert(tv.trade(2).is_buyer_maker() == true);

    assert(tv.symbol() == "ETHUSDT");
}

void test_trades_empty_group() {
    using namespace websocket::sbe;

    auto b = build_trades_msg(3000000, 3000001, -8, -8, 0, nullptr, nullptr, nullptr, nullptr, "BTCUSDT");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);
    TradesView tv{};
    assert(TradesView::decode(b.data() + HEADER_SIZE, b.size() - HEADER_SIZE, hdr.block_length, tv));
    assert(tv.count() == 0);
    assert(tv.symbol() == "BTCUSDT");
}

void test_trades_buyer_maker() {
    using namespace websocket::sbe;

    int64_t ids[] = { 1, 2 };
    int64_t prices[] = { 100, 200 };
    int64_t qtys[] = { 10, 20 };
    bool bm[] = { false, true };

    auto b = build_trades_msg(0, 0, -2, -2, 2, ids, prices, qtys, bm, "X");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);
    TradesView tv{};
    assert(TradesView::decode(b.data() + HEADER_SIZE, b.size() - HEADER_SIZE, hdr.block_length, tv));

    assert(tv.trade(0).is_buyer_maker() == false);
    assert(tv.trade(1).is_buyer_maker() == true);
}

void test_trades_truncated() {
    using namespace websocket::sbe;

    int64_t ids[] = { 1 };
    int64_t prices[] = { 100 };
    int64_t qtys[] = { 10 };
    bool bm[] = { true };

    auto b = build_trades_msg(0, 0, -8, -8, 1, ids, prices, qtys, bm, "BTC");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);

    TradesView tv{};
    // Truncate body to just past root block but before trade entries
    assert(!TradesView::decode(b.data() + HEADER_SIZE, 20, hdr.block_length, tv));
}

void test_trades_schema_offsets() {
    using namespace websocket::sbe;

    // Verify field offsets within root block match schema
    SBEBuilder b;
    b.write_header(18, 10000, 1, 0);
    // Root block
    int64_t event_time = 0x1122334455667788LL;
    int64_t transact_time = 0xAABBCCDDEEFF0011LL;
    b.write_i64(event_time);
    b.write_i64(transact_time);
    b.write_i8(-8);
    b.write_i8(-4);
    // Empty group + symbol
    b.write_group_size(25, 0);
    b.write_var_string8("S");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);
    assert(hdr.block_length == 18);

    const uint8_t* body = b.data() + HEADER_SIZE;
    // Verify raw offsets
    assert(read_i64(body + 0) == event_time);      // event_time @ offset 0
    assert(read_i64(body + 8) == transact_time);    // transact_time @ offset 8
    assert(read_i8(body + 16) == -8);               // price_exponent @ offset 16
    assert(read_i8(body + 17) == -4);               // qty_exponent @ offset 17
}

// ============================================================================
// Part 5: BestBidAskView (templateId=10001)
// ============================================================================

// Root block: 50 bytes
//   event_time@0(i64), book_update_id@8(i64), price_exp@16(i8), qty_exp@17(i8),
//   bid_price@18(i64), bid_qty@26(i64), ask_price@34(i64), ask_qty@42(i64)
// Then: varString8 symbol

static SBEBuilder build_bbo_msg(int64_t event_time, int64_t book_update_id,
                                 int8_t price_exp, int8_t qty_exp,
                                 int64_t bid_price, int64_t bid_qty,
                                 int64_t ask_price, int64_t ask_qty,
                                 std::string_view symbol,
                                 uint16_t root_block_len = 50) {
    SBEBuilder b;
    b.write_header(root_block_len, 10001, 1, 0);
    b.write_i64(event_time);
    b.write_i64(book_update_id);
    b.write_i8(price_exp);
    b.write_i8(qty_exp);
    b.write_i64(bid_price);
    b.write_i64(bid_qty);
    b.write_i64(ask_price);
    b.write_i64(ask_qty);
    // Pad root block if needed (e.g., future schema version with larger root block)
    size_t root_written = 50;  // 8+8+1+1+8+8+8+8
    while (root_written < root_block_len) {
        b.write_u8(0);
        root_written++;
    }
    b.write_var_string8(symbol);
    return b;
}

void test_bbo_basic() {
    using namespace websocket::sbe;

    auto b = build_bbo_msg(5000000, 12345, -8, -8,
                           5000000000LL, 100000, 5000100000LL, 200000, "BTCUSDT");

    SBEHeader hdr{};
    assert(decode_header(b.data(), b.size(), hdr));
    assert(hdr.template_id == BEST_BID_ASK_STREAM);

    BestBidAskView bbo{};
    const uint8_t* body = b.data() + HEADER_SIZE;
    size_t body_len = b.size() - HEADER_SIZE;
    assert(BestBidAskView::decode(body, body_len, hdr.block_length, bbo));

    assert(bbo.event_time_us() == 5000000);
    assert(bbo.book_update_id() == 12345);
    assert(bbo.price_exponent() == -8);
    assert(bbo.qty_exponent() == -8);
    assert(bbo.bid_price_mantissa() == 5000000000LL);
    assert(bbo.bid_qty_mantissa() == 100000);
    assert(bbo.ask_price_mantissa() == 5000100000LL);
    assert(bbo.ask_qty_mantissa() == 200000);
    assert(bbo.symbol() == "BTCUSDT");
}

void test_bbo_symbol_offset_uses_root_block_len() {
    using namespace websocket::sbe;

    // BUG 2 test: with a larger root block (e.g., 56 bytes), the symbol should
    // still be read correctly because we use root_block_len_ instead of hardcoded 50
    auto b = build_bbo_msg(1000, 2000, -8, -8, 100, 200, 300, 400, "ETHUSDT", 56);

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);
    assert(hdr.block_length == 56);

    BestBidAskView bbo{};
    const uint8_t* body = b.data() + HEADER_SIZE;
    size_t body_len = b.size() - HEADER_SIZE;
    assert(BestBidAskView::decode(body, body_len, hdr.block_length, bbo));

    // With the bug fix, symbol() uses root_block_len_ (56) instead of hardcoded 50
    assert(bbo.root_block_len_ == 56);
    assert(bbo.symbol() == "ETHUSDT");
}

void test_bbo_truncated() {
    using namespace websocket::sbe;

    auto b = build_bbo_msg(1000, 2000, -8, -8, 100, 200, 300, 400, "BTC");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);

    BestBidAskView bbo{};
    // Too short for root block
    assert(!BestBidAskView::decode(b.data() + HEADER_SIZE, 10, hdr.block_length, bbo));
}

void test_bbo_schema_offsets() {
    using namespace websocket::sbe;

    auto b = build_bbo_msg(0x1111111111111111LL, 0x2222222222222222LL, -3, -5,
                           0x3333333333333333LL, 0x4444444444444444LL,
                           0x5555555555555555LL, 0x6666666666666666LL, "AB");

    const uint8_t* body = b.data() + HEADER_SIZE;
    assert(read_i64(body + 0)  == 0x1111111111111111LL);  // event_time @ 0
    assert(read_i64(body + 8)  == 0x2222222222222222LL);  // book_update_id @ 8
    assert(read_i8(body + 16)  == -3);                     // price_exponent @ 16
    assert(read_i8(body + 17)  == -5);                     // qty_exponent @ 17
    assert(read_i64(body + 18) == 0x3333333333333333LL);  // bid_price @ 18
    assert(read_i64(body + 26) == 0x4444444444444444LL);  // bid_qty @ 26
    assert(read_i64(body + 34) == 0x5555555555555555LL);  // ask_price @ 34
    assert(read_i64(body + 42) == 0x6666666666666666LL);  // ask_qty @ 42
}

// ============================================================================
// Part 6: DepthSnapshotView (templateId=10002)
// ============================================================================

// Root block: 18 bytes
//   event_time@0(i64), book_update_id@8(i64), price_exp@16(i8), qty_exp@17(i8)
// Bids group: groupSize16Encoding(4B) + entries(16B each: price_mantissa@0(i64), qty_mantissa@8(i64))
// Asks group: groupSize16Encoding(4B) + entries(16B each)
// Var: symbol (varString8)

struct PriceLevel { int64_t price; int64_t qty; };

static SBEBuilder build_depth_snapshot_msg(int64_t event_time, int64_t book_update_id,
                                            int8_t price_exp, int8_t qty_exp,
                                            const PriceLevel* bids, uint16_t bid_count,
                                            const PriceLevel* asks, uint16_t ask_count,
                                            std::string_view symbol) {
    SBEBuilder b;
    b.write_header(18, 10002, 1, 0);
    // Root block
    b.write_i64(event_time);
    b.write_i64(book_update_id);
    b.write_i8(price_exp);
    b.write_i8(qty_exp);
    // Bids group
    b.write_group_size16(16, bid_count);
    for (uint16_t i = 0; i < bid_count; i++) {
        b.write_i64(bids[i].price);
        b.write_i64(bids[i].qty);
    }
    // Asks group
    b.write_group_size16(16, ask_count);
    for (uint16_t i = 0; i < ask_count; i++) {
        b.write_i64(asks[i].price);
        b.write_i64(asks[i].qty);
    }
    // Symbol
    b.write_var_string8(symbol);
    return b;
}

void test_depth_snapshot_basic() {
    using namespace websocket::sbe;

    PriceLevel bids[] = { {5000000, 100}, {4999000, 200} };
    PriceLevel asks[] = { {5001000, 150}, {5002000, 250}, {5003000, 50} };

    auto b = build_depth_snapshot_msg(7000000, 99999, -8, -8,
                                      bids, 2, asks, 3, "BTCUSDT");

    SBEHeader hdr{};
    assert(decode_header(b.data(), b.size(), hdr));
    assert(hdr.template_id == DEPTH_SNAPSHOT_STREAM);

    DepthSnapshotView dsv{};
    const uint8_t* body = b.data() + HEADER_SIZE;
    size_t body_len = b.size() - HEADER_SIZE;
    assert(DepthSnapshotView::decode(body, body_len, hdr.block_length, dsv));

    assert(dsv.event_time_us() == 7000000);
    assert(dsv.book_update_id() == 99999);
    assert(dsv.price_exponent() == -8);
    assert(dsv.qty_exponent() == -8);

    assert(dsv.bids().count == 2);
    assert(dsv.bids().level(0).price_mantissa() == 5000000);
    assert(dsv.bids().level(0).qty_mantissa() == 100);
    assert(dsv.bids().level(1).price_mantissa() == 4999000);
    assert(dsv.bids().level(1).qty_mantissa() == 200);

    assert(dsv.asks().count == 3);
    assert(dsv.asks().level(0).price_mantissa() == 5001000);
    assert(dsv.asks().level(2).price_mantissa() == 5003000);

    assert(dsv.symbol() == "BTCUSDT");
}

void test_depth_snapshot_empty() {
    using namespace websocket::sbe;

    auto b = build_depth_snapshot_msg(0, 0, -8, -8, nullptr, 0, nullptr, 0, "X");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);
    DepthSnapshotView dsv{};
    assert(DepthSnapshotView::decode(b.data() + HEADER_SIZE, b.size() - HEADER_SIZE,
                                     hdr.block_length, dsv));
    assert(dsv.bids().count == 0);
    assert(dsv.asks().count == 0);
    assert(dsv.symbol() == "X");
}

void test_depth_snapshot_truncated_bids() {
    using namespace websocket::sbe;

    PriceLevel bids[] = { {100, 10} };
    auto b = build_depth_snapshot_msg(0, 0, -8, -8, bids, 1, nullptr, 0, "X");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);

    DepthSnapshotView dsv{};
    // Truncate: root(18) + group_header(4) but not enough for the bid entry
    assert(!DepthSnapshotView::decode(b.data() + HEADER_SIZE, 18 + 4 + 8,
                                      hdr.block_length, dsv));
}

void test_depth_snapshot_truncated_asks() {
    using namespace websocket::sbe;

    PriceLevel bids[] = { {100, 10} };
    PriceLevel asks[] = { {200, 20} };
    auto b = build_depth_snapshot_msg(0, 0, -8, -8, bids, 1, asks, 1, "X");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);

    DepthSnapshotView dsv{};
    // Truncate: root(18) + bids_header(4) + bid_entry(16) + asks_header(4) but no ask entry
    assert(!DepthSnapshotView::decode(b.data() + HEADER_SIZE, 18 + 4 + 16 + 4,
                                      hdr.block_length, dsv));
}

void test_depth_snapshot_schema_offsets() {
    using namespace websocket::sbe;

    auto b = build_depth_snapshot_msg(0xAAAABBBBCCCCDDDDLL, 0x1111222233334444LL,
                                       -6, -3, nullptr, 0, nullptr, 0, "Z");

    const uint8_t* body = b.data() + HEADER_SIZE;
    assert(read_i64(body + 0)  == (int64_t)0xAAAABBBBCCCCDDDDLL);  // event_time @ 0
    assert(read_i64(body + 8)  == 0x1111222233334444LL);             // book_update_id @ 8
    assert(read_i8(body + 16)  == -6);                                // price_exponent @ 16
    assert(read_i8(body + 17)  == -3);                                // qty_exponent @ 17
}

// ============================================================================
// Part 7: DepthDiffView (templateId=10003)
// ============================================================================

// Root block: 26 bytes
//   event_time@0(i64), first_book_update_id@8(i64), last_book_update_id@16(i64),
//   price_exp@24(i8), qty_exp@25(i8)
// Same bid/ask group structure as DepthSnapshot

static SBEBuilder build_depth_diff_msg(int64_t event_time,
                                        int64_t first_book_update_id,
                                        int64_t last_book_update_id,
                                        int8_t price_exp, int8_t qty_exp,
                                        const PriceLevel* bids, uint16_t bid_count,
                                        const PriceLevel* asks, uint16_t ask_count,
                                        std::string_view symbol) {
    SBEBuilder b;
    b.write_header(26, 10003, 1, 0);
    // Root block
    b.write_i64(event_time);
    b.write_i64(first_book_update_id);
    b.write_i64(last_book_update_id);
    b.write_i8(price_exp);
    b.write_i8(qty_exp);
    // Bids group
    b.write_group_size16(16, bid_count);
    for (uint16_t i = 0; i < bid_count; i++) {
        b.write_i64(bids[i].price);
        b.write_i64(bids[i].qty);
    }
    // Asks group
    b.write_group_size16(16, ask_count);
    for (uint16_t i = 0; i < ask_count; i++) {
        b.write_i64(asks[i].price);
        b.write_i64(asks[i].qty);
    }
    // Symbol
    b.write_var_string8(symbol);
    return b;
}

void test_depth_diff_basic() {
    using namespace websocket::sbe;

    PriceLevel bids[] = { {4000000, 50} };
    PriceLevel asks[] = { {4001000, 75}, {4002000, 25} };

    auto b = build_depth_diff_msg(8000000, 1000, 1005, -8, -8,
                                  bids, 1, asks, 2, "BTCUSDT");

    SBEHeader hdr{};
    assert(decode_header(b.data(), b.size(), hdr));
    assert(hdr.template_id == DEPTH_DIFF_STREAM);

    DepthDiffView ddv{};
    const uint8_t* body = b.data() + HEADER_SIZE;
    size_t body_len = b.size() - HEADER_SIZE;
    assert(DepthDiffView::decode(body, body_len, hdr.block_length, ddv));

    assert(ddv.event_time_us() == 8000000);
    assert(ddv.first_book_update_id() == 1000);
    assert(ddv.last_book_update_id() == 1005);
    assert(ddv.price_exponent() == -8);
    assert(ddv.qty_exponent() == -8);

    assert(ddv.bids().count == 1);
    assert(ddv.bids().level(0).price_mantissa() == 4000000);
    assert(ddv.bids().level(0).qty_mantissa() == 50);

    assert(ddv.asks().count == 2);
    assert(ddv.asks().level(0).price_mantissa() == 4001000);
    assert(ddv.asks().level(1).price_mantissa() == 4002000);

    assert(ddv.symbol() == "BTCUSDT");
}

void test_depth_diff_empty() {
    using namespace websocket::sbe;

    auto b = build_depth_diff_msg(0, 100, 100, -8, -8, nullptr, 0, nullptr, 0, "Y");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);
    DepthDiffView ddv{};
    assert(DepthDiffView::decode(b.data() + HEADER_SIZE, b.size() - HEADER_SIZE,
                                 hdr.block_length, ddv));
    assert(ddv.bids().count == 0);
    assert(ddv.asks().count == 0);
    assert(ddv.symbol() == "Y");
}

void test_depth_diff_schema_offsets() {
    using namespace websocket::sbe;

    auto b = build_depth_diff_msg(0x1111111111111111LL, 0x2222222222222222LL,
                                   0x3333333333333333LL, -4, -2,
                                   nullptr, 0, nullptr, 0, "Z");

    const uint8_t* body = b.data() + HEADER_SIZE;
    assert(read_i64(body + 0)  == 0x1111111111111111LL);  // event_time @ 0
    assert(read_i64(body + 8)  == 0x2222222222222222LL);  // first_book_update_id @ 8
    assert(read_i64(body + 16) == 0x3333333333333333LL);  // last_book_update_id @ 16
    assert(read_i8(body + 24)  == -4);                     // price_exponent @ 24
    assert(read_i8(body + 25)  == -2);                     // qty_exponent @ 25
}

void test_depth_diff_large_group() {
    using namespace websocket::sbe;

    // 100 bid levels, 50 ask levels
    PriceLevel bids[100];
    PriceLevel asks[50];
    for (int i = 0; i < 100; i++) bids[i] = { 5000000 - i * 100, (int64_t)(i + 1) * 10 };
    for (int i = 0; i < 50; i++)  asks[i] = { 5000100 + i * 100, (int64_t)(i + 1) * 20 };

    auto b = build_depth_diff_msg(0, 500, 600, -8, -8, bids, 100, asks, 50, "BTCUSDT");

    SBEHeader hdr{};
    decode_header(b.data(), b.size(), hdr);
    DepthDiffView ddv{};
    assert(DepthDiffView::decode(b.data() + HEADER_SIZE, b.size() - HEADER_SIZE,
                                 hdr.block_length, ddv));

    assert(ddv.bids().count == 100);
    assert(ddv.asks().count == 50);
    assert(ddv.bids().level(0).price_mantissa() == 5000000);
    assert(ddv.bids().level(99).price_mantissa() == 5000000 - 99 * 100);
    assert(ddv.asks().level(49).price_mantissa() == 5000100 + 49 * 100);
}

// ============================================================================
// Part 8: decode_essential()
// ============================================================================

void test_essential_trades() {
    using namespace websocket::sbe;

    int64_t ids[] = { 77, 88 };
    int64_t prices[] = { 100, 200 };
    int64_t qtys[] = { 10, 20 };
    bool bm[] = { true, false };

    auto b = build_trades_msg(0, 0, -8, -8, 2, ids, prices, qtys, bm, "BTC");

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == TRADES_STREAM);
    assert(e.block_length == 18);
    assert(e.count == 2);
    // sequence = last trade id
    assert(e.sequence == 88);
}

void test_essential_bbo() {
    using namespace websocket::sbe;

    auto b = build_bbo_msg(0, 54321, -8, -8, 100, 200, 300, 400, "ETH");

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == BEST_BID_ASK_STREAM);
    assert(e.sequence == 54321);
    assert(e.count == 2);  // always 1 bid + 1 ask
}

void test_essential_depth_snapshot() {
    using namespace websocket::sbe;

    PriceLevel bids[] = { {100, 10}, {200, 20} };
    PriceLevel asks[] = { {300, 30} };

    auto b = build_depth_snapshot_msg(0, 77777, -8, -8, bids, 2, asks, 1, "X");

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == DEPTH_SNAPSHOT_STREAM);
    assert(e.sequence == 77777);
    assert(e.count == 3);  // 2 bids + 1 ask
}

void test_essential_depth_diff() {
    using namespace websocket::sbe;

    PriceLevel bids[] = { {100, 10} };
    PriceLevel asks[] = { {200, 20}, {300, 30}, {400, 40} };

    auto b = build_depth_diff_msg(0, 1000, 2000, -8, -8, bids, 1, asks, 3, "Y");

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == DEPTH_DIFF_STREAM);
    assert(e.sequence == 2000);  // last_book_update_id
    assert(e.count == 4);  // 1 bid + 3 asks
}

void test_essential_invalid() {
    using namespace websocket::sbe;

    // Too short for header
    uint8_t tiny[4] = {};
    auto e = BinanceSpotSBEDecoder::decode_essential(tiny, 4);
    assert(!e.valid);

    // Empty
    auto e2 = BinanceSpotSBEDecoder::decode_essential(nullptr, 0);
    assert(!e2.valid);
}

void test_essential_unknown() {
    using namespace websocket::sbe;

    // Unknown template ID
    SBEBuilder b;
    b.write_header(10, 9999, 1, 0);
    b.pad_to(18);

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);  // header parses OK
    assert(e.msg_type == 9999);
    assert(e.sequence == 0);  // no case matched
    assert(e.count == 0);
}

void test_essential_trade_count_truncation() {
    using namespace websocket::sbe;

    // BUG 3 test: num_trades > 65535 should clamp, not silently truncate
    SBEBuilder b;
    b.write_header(18, 10000, 1, 0);
    // Root block
    b.write_i64(0);   // event_time
    b.write_i64(0);   // transact_time
    b.write_i8(-8);   // price_exp
    b.write_i8(-8);   // qty_exp
    // Group with num_in_group = 70000 (> 65535)
    b.write_group_size(25, 70000);
    // We don't need actual entries for decode_essential to read the count
    // (it will fail to read sequence if entries are missing, but count is set)
    b.pad_to(b.pos + 100);  // some padding

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == TRADES_STREAM);
    // With BUG 3 fix: clamped to 65535 instead of truncated to 70000 & 0xFFFF = 4464
    assert(e.count == 65535);
}

// ============================================================================
// Part 9: MktEvent layout
// ============================================================================

void test_mkt_event_layout() {
    using namespace websocket::msg;

    // Size and alignment
    static_assert(sizeof(MktEvent) == 512);
    static_assert(alignof(MktEvent) == 512);

    // Header offsets
    static_assert(offsetof(MktEvent, src_seq) == 8);
    static_assert(offsetof(MktEvent, recv_ts_ns) == 16);
    static_assert(offsetof(MktEvent, event_ts_ns) == 24);
    static_assert(offsetof(MktEvent, nic_ts_ns) == 32);
    static_assert(offsetof(MktEvent, payload) == 40);

    // Entry sizes
    static_assert(sizeof(DeltaEntry) == 24);
    static_assert(sizeof(BookLevel) == 16);
    static_assert(sizeof(TradeEntry) == 40);

    // MAX constants
    static_assert(MAX_DELTAS == 19);       // 472 / 24
    static_assert(MAX_BOOK_LEVELS == 29);  // 472 / 16
    static_assert(MAX_TRADES == 11);       // 472 / 40

    // Trivially copyable
    static_assert(std::is_trivially_copyable_v<MktEvent>);
    static_assert(std::is_trivially_copyable_v<DeltaEntry>);
    static_assert(std::is_trivially_copyable_v<BookLevel>);
    static_assert(std::is_trivially_copyable_v<TradeEntry>);

    // Standard layout
    static_assert(std::is_standard_layout_v<MktEvent>);

    // Runtime check: clear() zeroes everything
    alignas(512) MktEvent evt;
    evt.event_type = 99;
    evt.venue_id = 1;
    evt.src_seq = 12345;
    evt.clear();
    assert(evt.event_type == 0);
    assert(evt.venue_id == 0);
    assert(evt.src_seq == 0);
    assert(evt.recv_ts_ns == 0);
}

// ============================================================================
// Part 10: Roundtrip tests (header + decode_essential + View::decode)
// ============================================================================

void test_roundtrip_trades() {
    using namespace websocket::sbe;

    int64_t ids[] = { 500, 501, 502 };
    int64_t prices[] = { 6700000000LL, 6700100000LL, 6699900000LL };
    int64_t qtys[] = { 50000, 75000, 100000 };
    bool bm[] = { true, false, true };

    auto b = build_trades_msg(1718000000000LL, 1718000000001LL, -8, -8,
                              3, ids, prices, qtys, bm, "BTCUSDT");

    // Step 1: decode_essential
    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == TRADES_STREAM);
    assert(e.sequence == 502);  // last trade id
    assert(e.count == 3);

    // Step 2: Full decode using essential's body/block_length
    TradesView tv{};
    assert(TradesView::decode(e.body, e.body_len, e.block_length, tv));
    assert(tv.event_time_us() == 1718000000000LL);
    assert(tv.transact_time_us() == 1718000000001LL);
    assert(tv.count() == 3);
    assert(tv.trade(0).id() == 500);
    assert(tv.trade(2).price_mantissa() == 6699900000LL);
    assert(tv.symbol() == "BTCUSDT");
}

void test_roundtrip_bbo() {
    using namespace websocket::sbe;

    auto b = build_bbo_msg(1718000000000LL, 999888, -8, -8,
                           6700000000LL, 100000, 6700100000LL, 200000, "BTCUSDT");

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == BEST_BID_ASK_STREAM);
    assert(e.sequence == 999888);

    BestBidAskView bbo{};
    assert(BestBidAskView::decode(e.body, e.body_len, e.block_length, bbo));
    assert(bbo.bid_price_mantissa() == 6700000000LL);
    assert(bbo.ask_price_mantissa() == 6700100000LL);
    assert(bbo.symbol() == "BTCUSDT");
}

void test_roundtrip_depth_snapshot() {
    using namespace websocket::sbe;

    PriceLevel bids[] = { {6700000000LL, 100}, {6699000000LL, 200} };
    PriceLevel asks[] = { {6701000000LL, 150} };

    auto b = build_depth_snapshot_msg(1718000000000LL, 888777, -8, -8,
                                      bids, 2, asks, 1, "BTCUSDT");

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == DEPTH_SNAPSHOT_STREAM);
    assert(e.sequence == 888777);
    assert(e.count == 3);

    DepthSnapshotView dsv{};
    assert(DepthSnapshotView::decode(e.body, e.body_len, e.block_length, dsv));
    assert(dsv.bids().count == 2);
    assert(dsv.asks().count == 1);
    assert(dsv.symbol() == "BTCUSDT");
}

void test_roundtrip_depth_diff() {
    using namespace websocket::sbe;

    PriceLevel bids[] = { {6700000000LL, 50} };
    PriceLevel asks[] = { {6701000000LL, 75}, {6702000000LL, 25} };

    auto b = build_depth_diff_msg(1718000000000LL, 1000, 1010, -8, -8,
                                  bids, 1, asks, 2, "BTCUSDT");

    auto e = BinanceSpotSBEDecoder::decode_essential(b.data(), static_cast<uint32_t>(b.size()));
    assert(e.valid);
    assert(e.msg_type == DEPTH_DIFF_STREAM);
    assert(e.sequence == 1010);
    assert(e.count == 3);

    DepthDiffView ddv{};
    assert(DepthDiffView::decode(e.body, e.body_len, e.block_length, ddv));
    assert(ddv.bids().count == 1);
    assert(ddv.asks().count == 2);
    assert(ddv.first_book_update_id() == 1000);
    assert(ddv.last_book_update_id() == 1010);
    assert(ddv.symbol() == "BTCUSDT");
}

// ============================================================================
// Part 11: Edge cases
// ============================================================================

void test_is_best_match_constant() {
    // TradeEntryView::is_best_match() is a compile-time constant
    static_assert(websocket::sbe::TradeEntryView::is_best_match() == true);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::printf("=== SBE Decoder Unit Tests ===\n\n");

    std::printf("--- Primitives ---\n");
    RUN_TEST(test_read_helpers);
    RUN_TEST(test_to_double);
    RUN_TEST(test_decode_header);
    RUN_TEST(test_read_group_size);
    RUN_TEST(test_read_group_size16);
    RUN_TEST(test_read_var_string8);
    RUN_TEST(test_var_string8_max_len);

    std::printf("\n--- TradesView (10000) ---\n");
    RUN_TEST(test_trades_single);
    RUN_TEST(test_trades_multiple);
    RUN_TEST(test_trades_empty_group);
    RUN_TEST(test_trades_buyer_maker);
    RUN_TEST(test_trades_truncated);
    RUN_TEST(test_trades_schema_offsets);

    std::printf("\n--- BestBidAskView (10001) ---\n");
    RUN_TEST(test_bbo_basic);
    RUN_TEST(test_bbo_symbol_offset_uses_root_block_len);
    RUN_TEST(test_bbo_truncated);
    RUN_TEST(test_bbo_schema_offsets);

    std::printf("\n--- DepthSnapshotView (10002) ---\n");
    RUN_TEST(test_depth_snapshot_basic);
    RUN_TEST(test_depth_snapshot_empty);
    RUN_TEST(test_depth_snapshot_truncated_bids);
    RUN_TEST(test_depth_snapshot_truncated_asks);
    RUN_TEST(test_depth_snapshot_schema_offsets);

    std::printf("\n--- DepthDiffView (10003) ---\n");
    RUN_TEST(test_depth_diff_basic);
    RUN_TEST(test_depth_diff_empty);
    RUN_TEST(test_depth_diff_schema_offsets);
    RUN_TEST(test_depth_diff_large_group);

    std::printf("\n--- decode_essential() ---\n");
    RUN_TEST(test_essential_trades);
    RUN_TEST(test_essential_bbo);
    RUN_TEST(test_essential_depth_snapshot);
    RUN_TEST(test_essential_depth_diff);
    RUN_TEST(test_essential_invalid);
    RUN_TEST(test_essential_unknown);
    RUN_TEST(test_essential_trade_count_truncation);

    std::printf("\n--- MktEvent layout ---\n");
    RUN_TEST(test_mkt_event_layout);

    std::printf("\n--- Roundtrip ---\n");
    RUN_TEST(test_roundtrip_trades);
    RUN_TEST(test_roundtrip_bbo);
    RUN_TEST(test_roundtrip_depth_snapshot);
    RUN_TEST(test_roundtrip_depth_diff);

    std::printf("\n--- Edge cases ---\n");
    RUN_TEST(test_is_best_match_constant);

    std::printf("\n=== %d/%d tests passed ===\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}
