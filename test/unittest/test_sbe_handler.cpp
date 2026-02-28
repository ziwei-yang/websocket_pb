// test/unittest/test_sbe_handler.cpp
// Unit tests for BinanceSBEHandler merge logic (inner-loop flush, dedup, FIFO order)
// Creates real IPC ring files in /dev/shm/hft/test_sbe_handler/ to test publish path.

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
#include "msg/00_binance_spot_sbe.hpp"

using namespace websocket::sbe;
using namespace websocket::pipeline;
using namespace websocket::msg;

// ============================================================================
// SBEBuilder — construct binary SBE payloads in a stack buffer
// ============================================================================

struct SBEBuilder {
    uint8_t buf[32768];
    size_t pos = 0;

    void write_u8(uint8_t v)   { buf[pos++] = v; }
    void write_i8(int8_t v)    { std::memcpy(buf + pos, &v, 1); pos += 1; }
    void write_u16(uint16_t v) { std::memcpy(buf + pos, &v, 2); pos += 2; }
    void write_u32(uint32_t v) { std::memcpy(buf + pos, &v, 4); pos += 4; }
    void write_i64(int64_t v)  { std::memcpy(buf + pos, &v, 8); pos += 8; }

    void write_header(uint16_t block_length, uint16_t template_id,
                      uint16_t schema_id = 1, uint16_t version = 0) {
        write_u16(block_length);
        write_u16(template_id);
        write_u16(schema_id);
        write_u16(version);
    }

    void write_group_size(uint16_t block_length, uint32_t num_in_group) {
        write_u16(block_length);
        write_u32(num_in_group);
    }

    void write_var_string8(std::string_view s) {
        write_u8(static_cast<uint8_t>(s.size()));
        std::memcpy(buf + pos, s.data(), s.size());
        pos += s.size();
    }

    const uint8_t* data() const { return buf; }
    size_t size() const { return pos; }
    void reset() { pos = 0; }
};

static SBEBuilder build_trades_msg(int64_t event_time, int64_t transact_time,
                                    int8_t price_exp, int8_t qty_exp,
                                    uint32_t num_trades,
                                    const int64_t* ids, const int64_t* prices,
                                    const int64_t* qtys, const bool* buyer_maker,
                                    std::string_view symbol) {
    SBEBuilder b;
    b.write_header(18, 10000, 1, 0);
    b.write_i64(event_time);
    b.write_i64(transact_time);
    b.write_i8(price_exp);
    b.write_i8(qty_exp);
    b.write_group_size(25, num_trades);
    for (uint32_t i = 0; i < num_trades; i++) {
        b.write_i64(ids[i]);
        b.write_i64(prices[i]);
        b.write_i64(qtys[i]);
        b.write_u8(buyer_maker[i] ? 1 : 0);
    }
    b.write_var_string8(symbol);
    return b;
}

static SBEBuilder build_bbo_msg(int64_t event_time, int64_t book_update_id,
                                 int8_t price_exp, int8_t qty_exp,
                                 int64_t bid_price, int64_t bid_qty,
                                 int64_t ask_price, int64_t ask_qty,
                                 std::string_view symbol) {
    SBEBuilder b;
    b.write_header(50, 10001, 1, 0);  // block_length=50, templateId=10001
    b.write_i64(event_time);
    b.write_i64(book_update_id);
    b.write_i8(price_exp);
    b.write_i8(qty_exp);
    b.write_i64(bid_price);
    b.write_i64(bid_qty);
    b.write_i64(ask_price);
    b.write_i64(ask_qty);
    b.write_var_string8(symbol);
    return b;
}

static SBEBuilder build_depth_snapshot_msg(int64_t event_time, int64_t book_update_id,
                                            int8_t price_exp, int8_t qty_exp,
                                            uint16_t num_bids, const int64_t* bid_prices, const int64_t* bid_qtys,
                                            uint16_t num_asks, const int64_t* ask_prices, const int64_t* ask_qtys,
                                            std::string_view symbol) {
    SBEBuilder b;
    b.write_header(18, 10002, 1, 0);
    b.write_i64(event_time);
    b.write_i64(book_update_id);
    b.write_i8(price_exp);
    b.write_i8(qty_exp);
    b.write_u16(16);  // bids group block_length
    b.write_u16(num_bids);
    for (uint16_t i = 0; i < num_bids; i++) { b.write_i64(bid_prices[i]); b.write_i64(bid_qtys[i]); }
    b.write_u16(16);  // asks group block_length
    b.write_u16(num_asks);
    for (uint16_t i = 0; i < num_asks; i++) { b.write_i64(ask_prices[i]); b.write_i64(ask_qtys[i]); }
    b.write_var_string8(symbol);
    return b;
}

// ============================================================================
// Ring setup/teardown helpers
// ============================================================================

static constexpr const char* SHM_BASE =
#ifdef __APPLE__
    "/tmp/hft";
#else
    "/dev/shm/hft";
#endif

static constexpr const char* RING_DIR = "test_sbe_handler";
static constexpr size_t RING_ELEMENTS = 64;  // power-of-2
static constexpr size_t RING_BUFFER_SIZE = RING_ELEMENTS * sizeof(MktEvent);

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
    // Events are published from seq 0, 1, 2, ...
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

    BinanceSBEHandler handler;

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

    void feed_frame(uint8_t ci, const SBEBuilder& b) {
        WSFrameInfo info{};
        info.clear();
        info.connection_id = ci;
        handler.on_ws_frame(ci, 2 /* BINARY */, b.data(),
                            static_cast<uint32_t>(b.size()), info);

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

    WSFrameInfo& ring_info(int64_t seq) { return (*ws_prod)[seq]; }
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
// Helper: build N-trade arrays
// ============================================================================

struct TradeSet {
    std::vector<int64_t> ids;
    std::vector<int64_t> prices;
    std::vector<int64_t> qtys;
    std::vector<bool> bm_vec;
    std::unique_ptr<bool[]> bm_raw;  // contiguous bool array for .data()-like access
    uint32_t count_;

    TradeSet(int64_t start_id, uint32_t count) : count_(count) {
        bm_raw = std::make_unique<bool[]>(count);
        for (uint32_t i = 0; i < count; i++) {
            ids.push_back(start_id + i);
            prices.push_back(5000000 + i * 100);
            qtys.push_back(10000 + i);
            bm_raw[i] = (i % 2 == 0);
        }
    }

    SBEBuilder build(int64_t event_time = 1000000, int64_t transact_time = 1000001) const {
        return build_trades_msg(event_time, transact_time, -8, -8,
                                count_, ids.data(), prices.data(), qtys.data(),
                                bm_raw.get(), "BTCUSDT");
    }
};

// ============================================================================
// Test 1: Inner flush uses correct max_id (the bug being fixed)
// ============================================================================

void test_merge_inner_flush_correct_max_id() {
    TestHarness h;

    // Frame1: 3 trades (ids 100-102)
    TradeSet ts1(100, 3);
    auto b1 = ts1.build(1000000);
    h.feed_frame(0, b1);

    // Frame2: 20 trades (ids 103-122) — will cause inner-loop flushes
    TradeSet ts2(103, 20);
    auto b2 = ts2.build(2000000);
    h.feed_frame(0, b2);

    auto events = h.published();
    // Inner flushes should have happened: 3+20 = 23 trades, MAX_TRADES=11
    // First inner flush at trade index 8 of frame2 (3 cached + 8 = 11)
    // Second inner flush at trade index 19 of frame2 (11 more)
    // Remaining: 23 - 22 = 1 trade cached
    assert(!events.empty());

    // Each batch's src_seq == its last trade_id (per-batch, not frame-wide max_id)
    // Batch 0: trades 100-110, src_seq = 110
    assert(events[0].src_seq == 110);
    // Batch 1: trades 111-121, src_seq = 121
    assert(events[1].src_seq == 121);

    // last_trade_id_ should be 122
    assert(h.handler.last_trade_id_ == 122);

    // Should have 1 remaining cached trade
    assert(h.handler.pending_trade_count_ == 1);
}

// ============================================================================
// Test 2: Flushed trades are oldest (FIFO order)
// ============================================================================

void test_merge_flushed_trades_are_oldest() {
    TestHarness h;

    // Frame1: 3 trades (ids 100-102)
    TradeSet ts1(100, 3);
    h.feed_frame(0, ts1.build(1000000));

    // Frame2: 20 trades (ids 103-122) → inner-loop flushes
    TradeSet ts2(103, 20);
    h.feed_frame(0, ts2.build(2000000));

    auto events = h.published();
    // First flush: trades 100-110 (oldest 11)
    assert(events.size() >= 2);
    assert(events[0].count == 11);
    for (uint8_t i = 0; i < 11; i++) {
        assert(events[0].payload.trades.entries[i].trade_id == 100 + i);
    }

    // Second flush: trades 111-121 (next 11)
    assert(events[1].count == 11);
    for (uint8_t i = 0; i < 11; i++) {
        assert(events[1].payload.trades.entries[i].trade_id == 111 + i);
    }

    // Remaining: trade 122
    assert(h.handler.pending_trade_count_ == 1);
    assert(h.handler.pending_trade_entries_[0].trade_id == 122);

    // Per-batch src_seq
    assert(events[0].src_seq == 110);  // last of trades 100-110
    assert(events[1].src_seq == 121);  // last of trades 111-121

    // on_batch_end flushes the remainder
    h.idle();
    events = h.published();
    assert(events.size() == 3);
    assert(events[2].count == 1);
    assert(events[2].payload.trades.entries[0].trade_id == 122);
    assert(events[2].src_seq == 122);  // last (and only) of trade 122
}

// ============================================================================
// Test 3: Full batch only (single frame, multiple inner flushes)
// ============================================================================

void test_merge_full_batch_only() {
    TestHarness h;

    // Frame: 25 trades (ids 1-25)
    TradeSet ts(1, 25);
    h.feed_frame(0, ts.build());

    auto events = h.published();
    // 25 trades, MAX_TRADES=11: 2 inner flushes (11 + 11), 3 cached
    assert(events.size() == 2);

    // Flush 1: trades 1-11
    assert(events[0].count == 11);
    for (uint8_t i = 0; i < 11; i++) {
        assert(events[0].payload.trades.entries[i].trade_id == 1 + i);
    }

    // Flush 2: trades 12-22
    assert(events[1].count == 11);
    for (uint8_t i = 0; i < 11; i++) {
        assert(events[1].payload.trades.entries[i].trade_id == 12 + i);
    }

    // 3 cached
    assert(h.handler.pending_trade_count_ == 3);

    // on_batch_end: trades 23-25
    h.idle();
    events = h.published();
    assert(events.size() == 3);
    assert(events[2].count == 3);
    for (uint8_t i = 0; i < 3; i++) {
        assert(events[2].payload.trades.entries[i].trade_id == 23 + i);
    }

    // Per-batch src_seq == last trade_id in each batch
    assert(events[0].src_seq == 11);  // trades 1-11
    assert(events[1].src_seq == 22);  // trades 12-22
    assert(events[2].src_seq == 25);  // trades 23-25 (on_batch_end)
}

// ============================================================================
// Test 4: Dedup after inner flush
// ============================================================================

void test_merge_dedup_after_inner_flush() {
    TestHarness h;

    // Frame from conn 0: 15 trades (ids 1-15) → 1 flush + 4 cached
    TradeSet ts(1, 15);
    h.feed_frame(0, ts.build());

    auto events_after_frame1 = h.published();
    // 15 trades: 1 inner flush at 11, 4 cached
    assert(events_after_frame1.size() == 1);
    assert(events_after_frame1[0].src_seq == 11);  // last of trades 1-11
    assert(h.handler.pending_trade_count_ == 4);

    // Same frame from conn 1 (duplicate): should be discarded
    h.feed_frame(1, ts.build());

    auto events_after_frame2 = h.published();
    // No new events published — deduped
    assert(events_after_frame2.size() == 1);
    // Pending count unchanged
    assert(h.handler.pending_trade_count_ == 4);
}

// ============================================================================
// Test 5: Accumulation across frames
// ============================================================================

void test_merge_accumulation_across_frames() {
    TestHarness h;

    // Frame1: 5 trades (ids 1-5) → 5 cached
    TradeSet ts1(1, 5);
    h.feed_frame(0, ts1.build(1000000));
    assert(h.published().empty());
    assert(h.handler.pending_trade_count_ == 5);

    // Frame2: 7 trades (ids 6-12) → 5+7=12, inner flush triggers at i=6 when count reaches 11
    // After flush: trade 12 remains cached (count=1)
    TradeSet ts2(6, 7);
    h.feed_frame(0, ts2.build(2000000));

    auto events = h.published();
    assert(events.size() == 1);
    // Flushed batch: trades 1-11 (FIFO order, oldest first)
    assert(events[0].count == 11);
    assert(events[0].src_seq == 11);  // last of trades 1-11
    for (uint8_t i = 0; i < 11; i++) {
        assert(events[0].payload.trades.entries[i].trade_id == 1 + i);
    }
    assert(h.handler.pending_trade_count_ == 1);

    // Frame3: 3 trades (ids 13-15) → 1+3=4 cached
    TradeSet ts3(13, 3);
    h.feed_frame(0, ts3.build(3000000));
    assert(h.handler.pending_trade_count_ == 4);

    // on_batch_end → flush 4
    h.idle();
    events = h.published();
    assert(events.size() == 2);
    assert(events[1].count == 4);
    assert(events[1].payload.trades.entries[0].trade_id == 12);
    assert(events[1].payload.trades.entries[1].trade_id == 13);
    assert(events[1].payload.trades.entries[2].trade_id == 14);
    assert(events[1].payload.trades.entries[3].trade_id == 15);
    assert(events[1].src_seq == 15);  // last of trades 12-15 (on_batch_end)
}

// ============================================================================
// Test 6: Exact MAX_TRADES (boundary case)
// ============================================================================

void test_merge_exact_max_trades() {
    TestHarness h;

    // Frame: exactly 11 trades → inner flush at end, 0 remaining
    TradeSet ts(1, MAX_TRADES);
    h.feed_frame(0, ts.build());

    auto events = h.published();
    // The loop accumulates 11 trades; at i=10 (the 11th), pending_trade_count_ becomes 11,
    // then the NEXT iteration's check (i=11, but total_trades=11 so loop ends).
    // Actually: the check is at the TOP of the loop for the NEXT iteration.
    // With 11 trades: i=0..10. At i=0: count=0, no flush, count→1.
    // At i=10: count=10, no flush (10 < 11), count→11.
    // Loop ends. 11 trades cached, no inner flush.
    assert(events.empty());
    assert(h.handler.pending_trade_count_ == 11);

    // on_batch_end flushes all 11
    h.idle();
    events = h.published();
    assert(events.size() == 1);
    assert(events[0].count == 11);
    assert(events[0].src_seq == 11);  // last of trades 1-11
    for (uint8_t i = 0; i < 11; i++) {
        assert(events[0].payload.trades.entries[i].trade_id == 1 + i);
    }
}

// ============================================================================
// Test 7: Large trade frame (66 trades, 6 batches of 11)
// ============================================================================

void test_merge_large_trade_frame_batch_count() {
    TestHarness h;

    // Frame: 66 trades (ids 1-66) — mimics the real burst observed in logs
    TradeSet ts(1, 66);
    h.feed_frame(0, ts.build());

    auto events = h.published();
    // 66 trades, MAX_TRADES=11: 5 inner flushes (55 trades), 11 remaining cached
    assert(events.size() == 5);
    assert(h.handler.pending_trade_count_ == 11);

    // on_batch_end flushes the remainder
    h.idle();
    events = h.published();
    assert(events.size() == 6);

    // All 6 batches have count == 11
    for (size_t i = 0; i < 6; i++) {
        assert(events[i].count == 11);
    }

    // Per-batch src_seq == last trade_id in each batch
    assert(events[0].src_seq == 11);
    assert(events[1].src_seq == 22);
    assert(events[2].src_seq == 33);
    assert(events[3].src_seq == 44);
    assert(events[4].src_seq == 55);
    assert(events[5].src_seq == 66);

    // Verify FIFO order: batch i contains trades (i*11+1) .. ((i+1)*11)
    for (size_t b = 0; b < 6; b++) {
        for (uint8_t j = 0; j < 11; j++) {
            assert(events[b].payload.trades.entries[j].trade_id ==
                   static_cast<int64_t>(b * 11 + j + 1));
        }
    }
}

// ============================================================================
// Test 8: Multi-frame merge M-flag preservation
// ============================================================================

void test_multi_frame_merge_m_flag() {
    TestHarness h;

    // Frame 1: 1 trade (id 1)
    TradeSet ts1(1, 1);
    h.feed_frame(0, ts1.build());

    // Frame 2: 7 trades (ids 2-8)
    TradeSet ts2(2, 7);
    h.feed_frame(0, ts2.build());

    // Frame 3: 54 trades (ids 9-62) — causes mid-frame flushes
    TradeSet ts3(9, 54);
    h.feed_frame(0, ts3.build());

    // Verify M flags on ring: all 3 frames should be M (still accumulating)
    assert(h.ring_info(0).is_merged() == true);   // frame 1
    assert(h.ring_info(1).is_merged() == true);   // frame 2
    assert(h.ring_info(2).is_merged() == true);   // frame 3

    // on_batch_end clears M on last frame only
    h.idle();
    assert(h.ring_info(0).is_merged() == true);   // frame 1: stays M
    assert(h.ring_info(1).is_merged() == true);   // frame 2: stays M
    assert(h.ring_info(2).is_merged() == false);  // frame 3: winning frame, cleared
}

// ============================================================================
// Test 9: Multiple BBOs across frames merge into one on idle
// ============================================================================

void test_multi_frame_bbo_merge_on_idle() {
    TestHarness h;
    auto bbo1 = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");
    auto bbo2 = build_bbo_msg(1001, 101, -8, -8, 50001, 1001, 50101, 2001, "BTCUSDT");
    auto bbo3 = build_bbo_msg(1002, 102, -8, -8, 50002, 1002, 50102, 2002, "BTCUSDT");

    h.feed_frame(0, bbo1);
    assert(h.published().empty());

    h.feed_frame(0, bbo2);  // accumulates with bbo1
    assert(h.published().empty());

    h.feed_frame(0, bbo3);  // accumulates with bbo1,bbo2
    assert(h.published().empty());

    h.idle();  // flush → all 3 BBOs published as one event
    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_bbo_array());
    assert(events[0].count == 3);
    assert(events[0].src_seq == 102);  // last BBO seq
    assert(events[0].payload.bbo_array.entries[0].book_update_id == 100);
    assert(events[0].payload.bbo_array.entries[1].book_update_id == 101);
    assert(events[0].payload.bbo_array.entries[2].book_update_id == 102);
    assert(events[0].payload.bbo_array.entries[0].bid_price == 50000);
    assert(events[0].payload.bbo_array.entries[2].ask_price == 50102);
}

// ============================================================================
// Test 10: Multiple trade frames across TLS records accumulate on idle
// ============================================================================

void test_multi_frame_trade_merge_on_idle() {
    TestHarness h;
    TradeSet ts1(1, 5);
    TradeSet ts2(6, 3);

    h.feed_frame(0, ts1.build(1000000));  // 5 trades buffered
    assert(h.published().empty());

    h.feed_frame(0, ts2.build(2000000));  // 8 trades accumulated
    assert(h.published().empty());

    h.idle();  // flush all 8
    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].count == 8);
    assert(events[0].payload.trades.entries[0].trade_id == 1);
    assert(events[0].payload.trades.entries[7].trade_id == 8);
}

// ============================================================================
// Test 11: Idle flush with nothing pending
// ============================================================================

void test_idle_flush_with_no_pending() {
    TestHarness h;
    h.idle();  // should be no-op, no crash
    assert(h.published().empty());
}

// ============================================================================
// Test 12: BBO dedup across connections — same book_update_id discarded
// ============================================================================

void test_bbo_dedup_no_false_merge_flag() {
    TestHarness h;
    auto bbo_a = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");
    auto bbo_b = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");

    h.feed_frame(0, bbo_a);    // conn 0: buffered with M=true
    assert(h.published().empty());

    h.feed_frame(1, bbo_b);    // conn 1: same book_update_id → discarded
    assert(h.published().empty());

    h.idle();                   // flush → publish bbo_a, clear M
    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_bbo_array());
    assert(events[0].count == 1);
    assert(events[0].src_seq == 100);
    assert(events[0].payload.bbo_array.entries[0].bid_price == 50000);
    assert(h.ring_info(0).is_merged() == false);    // winning frame: M cleared
    assert(h.ring_info(1).is_discard_early() == true);  // dup: discarded
}

// ============================================================================
// Test 13: BBO flushed on type transition (BBO → Trade)
// ============================================================================

void test_bbo_flushed_on_type_transition() {
    TestHarness h;
    auto bbo = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");
    TradeSet ts(1, 3);

    h.feed_frame(0, bbo);             // BBO buffered, M=true
    assert(h.published().empty());

    h.feed_frame(0, ts.build());      // Trade → flushes BBO → accumulates trades
    auto events = h.published();
    assert(events.size() == 1);                        // BBO published inline
    assert(events[0].is_bbo_array());                  // BBO_ARRAY type
    assert(events[0].count == 1);                      // single BBO
    assert(events[0].src_seq == 100);                  // BBO seq
    assert(events[0].payload.bbo_array.entries[0].bid_price == 50000);
    assert(h.ring_info(0).is_merged() == false);       // M cleared

    h.idle();                          // on_batch_end → flush trades
    events = h.published();
    assert(events.size() == 2);                        // BBO + trades
    assert(events[1].count == 3);                      // 3 trades
}

// ============================================================================
// Test 14: BBO buffer overflow — >9 BBOs triggers mid-batch flush
// ============================================================================

void test_bbo_buffer_overflow() {
    TestHarness h;

    // Feed 12 BBOs — should trigger flush at 10th (buffer full at 9, flush + new batch)
    for (int i = 0; i < 12; i++) {
        auto bbo = build_bbo_msg(1000 + i, 100 + i, -8, -8,
                                  50000 + i, 1000 + i, 50100 + i, 2000 + i, "BTCUSDT");
        h.feed_frame(0, bbo);
    }

    // Mid-batch flush should have happened: 9 BBOs flushed, 3 remaining
    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_bbo_array());
    assert(events[0].count == 9);
    assert(events[0].payload.bbo_array.entries[0].book_update_id == 100);
    assert(events[0].payload.bbo_array.entries[8].book_update_id == 108);

    h.idle();  // flush remaining 3
    events = h.published();
    assert(events.size() == 2);
    assert(events[1].is_bbo_array());
    assert(events[1].count == 3);
    assert(events[1].payload.bbo_array.entries[0].book_update_id == 109);
    assert(events[1].payload.bbo_array.entries[2].book_update_id == 111);
}

// ============================================================================
// Test 15: BBO does not block OB with same seq
// ============================================================================

void test_bbo_does_not_block_ob_same_seq() {
    TestHarness h;
    auto bbo = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");
    int64_t bp[] = {50000, 49000}, bq[] = {1000, 2000};
    int64_t ap[] = {50100, 51000}, aq[] = {1500, 2500};
    auto ob = build_depth_snapshot_msg(1000, 100, -8, -8, 2, bp, bq, 2, ap, aq, "BTCUSDT");

    h.feed_frame(0, bbo);
    assert(h.published().empty());

    h.feed_frame(0, ob);
    auto events = h.published();
    assert(events.size() == 2);
    assert(events[0].is_bbo_array());
    assert(events[1].is_book_snapshot());
}

// ============================================================================
// Test 16: OB blocks BBO with same seq
// ============================================================================

void test_ob_blocks_bbo_same_seq() {
    TestHarness h;
    int64_t bp[] = {50000}, bq[] = {1000};
    int64_t ap[] = {50100}, aq[] = {1500};
    auto ob = build_depth_snapshot_msg(1000, 100, -8, -8, 1, bp, bq, 1, ap, aq, "BTCUSDT");
    auto bbo = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");

    h.feed_frame(0, ob);
    h.feed_frame(0, bbo);

    h.idle();
    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_book_snapshot());
}

// ============================================================================
// Test 17: BBO does not block older OB
// ============================================================================

void test_bbo_does_not_block_older_ob() {
    TestHarness h;
    auto bbo = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");
    int64_t bp[] = {50000}, bq[] = {1000};
    int64_t ap[] = {50100}, aq[] = {1500};
    auto ob = build_depth_snapshot_msg(999, 99, -8, -8, 1, bp, bq, 1, ap, aq, "BTCUSDT");

    h.feed_frame(0, bbo);
    assert(h.published().empty());

    h.feed_frame(0, ob);
    auto events = h.published();
    assert(events.size() == 2);
    assert(events[0].is_bbo_array());
    assert(events[0].src_seq == 100);
    assert(events[1].is_book_snapshot());
    assert(events[1].src_seq == 99);
}

// ============================================================================
// Test 18: Fragment — 20KB trades message, on_ws_fragment reads header
// ============================================================================

void test_fragment_trades_20kb() {
    TestHarness h;

    // Build ~20KB trades message: 800 trades × 25 bytes = 20000 + header
    TradeSet ts(1000, 800);
    int64_t event_time = 1700000000000LL;  // microseconds
    auto b = ts.build(event_time, event_time + 1);

    // Verify message is large enough
    assert(b.size() > 16000);

    // Simulate fragment: call on_ws_fragment with first 16000 bytes
    WSFrameInfo frag_info{};
    frag_info.clear();
    h.handler.on_ws_fragment(b.data(), 16000, frag_info);

    assert(frag_info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));
    assert(frag_info.exchange_event_time_us == event_time);
    // mkt_event_count should be the total trade count from group header (800, capped to uint16)
    assert(frag_info.mkt_event_count == 800);
    // mkt_event_seq: last trade_id may or may not be reachable in 16KB fragment
    // With 800 trades, last entry at offset 18+6+(799*25)=19999 from body start
    // Fragment is 16000 bytes total, body starts at offset 8, so body_len=15992
    // after_root = body+18, remaining = 15974
    // last_entry_offset = 6 + 799*25 = 19981 — exceeds remaining, so seq stays 0
    // That's fine — fragment may not contain the last trade
    // (But the count and type are still available from the header)

    // Verify on_ws_frame with full payload populates WSFrameInfo correctly
    // (Use a standalone handler without ring to avoid ring overflow with 800 trades)
    BinanceSBEHandler handler2;
    WSFrameInfo full_info{};
    full_info.clear();
    handler2.on_ws_frame(0, 2, b.data(), static_cast<uint32_t>(b.size()), full_info);

    assert(full_info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));
    assert(full_info.exchange_event_time_us == event_time);
    assert(full_info.mkt_event_count == 800);
    assert(full_info.mkt_event_seq == 1799);  // last trade id = 1000 + 799
}

// ============================================================================
// Test 19: Fragment — 20KB depth snapshot, on_ws_fragment reads header
// ============================================================================

static SBEBuilder build_large_depth_snapshot(int64_t event_time, int64_t book_update_id,
                                              uint16_t num_bids, uint16_t num_asks) {
    SBEBuilder b;
    b.write_header(18, 10002, 1, 0);  // DEPTH_SNAPSHOT_STREAM
    b.write_i64(event_time);
    b.write_i64(book_update_id);
    b.write_i8(-8);   // price_exponent
    b.write_i8(-8);   // qty_exponent
    b.write_u16(16);  // bids group block_length
    b.write_u16(num_bids);
    for (uint16_t i = 0; i < num_bids; i++) {
        b.write_i64(50000000 - static_cast<int64_t>(i) * 100);  // price
        b.write_i64(1000 + i);                                   // qty
    }
    b.write_u16(16);  // asks group block_length
    b.write_u16(num_asks);
    for (uint16_t i = 0; i < num_asks; i++) {
        b.write_i64(50100000 + static_cast<int64_t>(i) * 100);  // price
        b.write_i64(2000 + i);                                   // qty
    }
    b.write_var_string8("BTCUSDT");
    return b;
}

void test_fragment_depth_snapshot_20kb() {
    TestHarness h;

    // Build ~20KB depth snapshot: 625 bids + 625 asks × 16 bytes each
    int64_t event_time = 1700000000000LL;
    int64_t book_update_id = 88928438912LL;
    auto b = build_large_depth_snapshot(event_time, book_update_id, 625, 625);

    // Verify message is large enough
    assert(b.size() > 16000);

    // Simulate fragment: call on_ws_fragment with first 16000 bytes
    WSFrameInfo frag_info{};
    frag_info.clear();
    h.handler.on_ws_fragment(b.data(), 16000, frag_info);

    assert(frag_info.mkt_event_type == static_cast<uint8_t>(EventType::BOOK_SNAPSHOT));
    assert(frag_info.exchange_event_time_us == event_time);
    assert(frag_info.mkt_event_seq == book_update_id);
    // mkt_event_count: at least the bid count should be readable
    assert(frag_info.mkt_event_count > 0);

    // Now call on_ws_frame with the FULL payload
    WSFrameInfo full_info{};
    full_info.clear();
    h.handler.on_ws_frame(0, 2, b.data(), static_cast<uint32_t>(b.size()), full_info);

    assert(full_info.mkt_event_type == static_cast<uint8_t>(EventType::BOOK_SNAPSHOT));
    assert(full_info.exchange_event_time_us == event_time);
    assert(full_info.mkt_event_seq == book_update_id);
    assert(full_info.mkt_event_count == 1250);  // 625 bids + 625 asks
}

// ============================================================================
// Test 20: Fragment — too small (< SBE header), graceful no-op
// ============================================================================

void test_fragment_too_small() {
    WSFrameInfo info{};
    info.clear();

    // Build a valid small SBE message
    TradeSet ts(1, 1);
    auto b = ts.build();

    BinanceSBEHandler handler;
    handler.on_ws_fragment(b.data(), 4, info);  // only 4 bytes — less than 8-byte SBE header

    // All fields should remain 0
    assert(info.mkt_event_type == 0);
    assert(info.mkt_event_count == 0);
    assert(info.mkt_event_seq == 0);
    assert(info.exchange_event_time_us == 0);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::printf("=== SBE Handler Unit Tests ===\n\n");

    // Clean up any leftover files from previous runs
    cleanup_ring_files();

    std::printf("--- Merge logic ---\n");
    RUN_TEST(test_merge_inner_flush_correct_max_id);
    cleanup_ring_files();

    RUN_TEST(test_merge_flushed_trades_are_oldest);
    cleanup_ring_files();

    RUN_TEST(test_merge_full_batch_only);
    cleanup_ring_files();

    RUN_TEST(test_merge_dedup_after_inner_flush);
    cleanup_ring_files();

    RUN_TEST(test_merge_accumulation_across_frames);
    cleanup_ring_files();

    RUN_TEST(test_merge_exact_max_trades);
    cleanup_ring_files();

    RUN_TEST(test_merge_large_trade_frame_batch_count);
    cleanup_ring_files();

    RUN_TEST(test_multi_frame_merge_m_flag);
    cleanup_ring_files();

    std::printf("\n--- Idle-scoped merge ---\n");
    RUN_TEST(test_bbo_flushed_on_type_transition);
    cleanup_ring_files();

    RUN_TEST(test_bbo_dedup_no_false_merge_flag);
    cleanup_ring_files();

    RUN_TEST(test_multi_frame_bbo_merge_on_idle);
    cleanup_ring_files();

    RUN_TEST(test_multi_frame_trade_merge_on_idle);
    cleanup_ring_files();

    RUN_TEST(test_idle_flush_with_no_pending);
    cleanup_ring_files();

    RUN_TEST(test_bbo_buffer_overflow);
    cleanup_ring_files();

    std::printf("\n--- BBO/OB dedup ---\n");
    RUN_TEST(test_bbo_does_not_block_ob_same_seq);
    cleanup_ring_files();

    RUN_TEST(test_ob_blocks_bbo_same_seq);
    cleanup_ring_files();

    RUN_TEST(test_bbo_does_not_block_older_ob);
    cleanup_ring_files();

    std::printf("\n--- Fragment parsing ---\n");
    RUN_TEST(test_fragment_trades_20kb);
    cleanup_ring_files();

    RUN_TEST(test_fragment_depth_snapshot_20kb);
    cleanup_ring_files();

    RUN_TEST(test_fragment_too_small);
    cleanup_ring_files();

    std::printf("\n=== %d/%d tests passed ===\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}
