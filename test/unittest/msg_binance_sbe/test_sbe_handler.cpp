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
        handler.on_ws_data(handler.sbe_state_[ci], ci, b.data(),
                           static_cast<uint32_t>(b.size()), info);
        // Complete frame: reset state
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

    // Feed truncated payload — does NOT reset state (simulates continuation fragment)
    void feed_fragment(uint8_t ci, const SBEBuilder& b, uint32_t truncated_len) {
        WSFrameInfo info{};
        info.clear();
        info.connection_id = ci;
        handler.on_ws_data(handler.sbe_state_[ci], ci, b.data(), truncated_len, info);
        // Do NOT reset state — continuation fragment

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
    // BBO uses independent stale detection (last_bbo_seq_ only).
    // OB seq=100 does NOT block BBO seq=100 — they use separate sequence trackers.
    // But BBO seq=100 DOES block a second BBO with same seq.
    TestHarness h;
    int64_t bp[] = {50000}, bq[] = {1000};
    int64_t ap[] = {50100}, aq[] = {1500};
    auto ob = build_depth_snapshot_msg(1000, 100, -8, -8, 1, bp, bq, 1, ap, aq, "BTCUSDT");
    auto bbo1 = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");
    auto bbo2 = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");

    h.feed_frame(0, ob);
    h.feed_frame(0, bbo1);   // BBO seq=100 accepted (last_bbo_seq_ was 0)
    h.feed_frame(0, bbo2);   // BBO seq=100 rejected (last_bbo_seq_ is now 100)

    h.idle();
    auto events = h.published();
    assert(events.size() == 2);  // snapshot + first BBO
    assert(events[0].is_book_snapshot());
    assert(events[1].is_bbo_array());
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
// Test 18: Fragment — 20KB trades, streaming parse with state machine
// ============================================================================

void test_fragment_trades_20kb() {
    TestHarness h;

    // Build ~20KB trades message: 800 trades × 25 bytes = 20000 + header
    TradeSet ts(1000, 800);
    int64_t event_time = 1700000000000LL;  // microseconds
    auto b = ts.build(event_time, event_time + 1);

    // Verify message is large enough
    assert(b.size() > 16000);

    // Simulate fragment: call on_ws_data with first 16000 bytes
    SBEParseState state{};
    WSFrameInfo frag_info{};
    frag_info.clear();
    h.handler.on_ws_data(state, 0, b.data(), 16000, frag_info);

    assert(frag_info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));
    assert(frag_info.exchange_event_time_us == event_time);
    // mkt_event_count should be the total trade count from group header (800, capped to uint16)
    assert(frag_info.mkt_event_count == 800);
    // State should be in TRADES_ENTRIES (partially parsed)
    assert(state.phase == SBEParseState::TRADES_ENTRIES);
    // Some trades should have been published incrementally
    assert(state.group_published > 0);
    assert(state.group_published < 800);  // not all, since fragment is partial

    // Now call on_ws_data with FULL payload — state machine resumes
    WSFrameInfo full_info{};
    full_info.clear();
    h.handler.on_ws_data(state, 0, b.data(), static_cast<uint32_t>(b.size()), full_info);
    state.reset();

    assert(full_info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));
    assert(full_info.exchange_event_time_us == event_time);
    assert(full_info.mkt_event_count == 800);
    assert(full_info.mkt_event_seq == 1799);  // last trade id = 1000 + 799
}

// ============================================================================
// Test 19: Fragment — 20KB depth snapshot, streaming parse with state machine
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

    // Simulate fragment: call on_ws_data with first 16000 bytes
    SBEParseState state{};
    WSFrameInfo frag_info{};
    frag_info.clear();
    h.handler.on_ws_data(state, 0, b.data(), 16000, frag_info);

    assert(frag_info.mkt_event_type == static_cast<uint8_t>(EventType::BOOK_SNAPSHOT));
    assert(frag_info.exchange_event_time_us == event_time);
    assert(frag_info.mkt_event_seq == book_update_id);
    // State machine should have made progress
    assert(state.phase != SBEParseState::IDLE);
    // Some bid entries should have been parsed
    assert(state.bids_published > 0);

    // Now call on_ws_data with FULL payload
    WSFrameInfo full_info{};
    full_info.clear();
    h.handler.on_ws_data(state, 0, b.data(), static_cast<uint32_t>(b.size()), full_info);
    state.reset();

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
    SBEParseState state{};
    handler.on_ws_data(state, 0, b.data(), 4, info);  // only 4 bytes — less than 8-byte SBE header

    // All fields should remain 0
    assert(info.mkt_event_type == 0);
    assert(info.mkt_event_count == 0);
    assert(info.mkt_event_seq == 0);
    assert(info.exchange_event_time_us == 0);
    assert(state.phase == SBEParseState::IDLE);  // not advanced
}

// ============================================================================
// Test 21: Streaming incremental — feed data in small chunks, verify progress
// ============================================================================

void test_streaming_incremental_trades() {
    TestHarness h;

    // Build a message with 5 trades
    TradeSet ts(100, 5);
    auto b = ts.build(1000000, 1000001);

    // SBE header=8, root block=18, group header=6, 5 entries × 25 = 125
    // Total = 8+18+6+125+symbol = ~165 bytes
    assert(b.size() > 50);

    SBEParseState state{};
    WSFrameInfo info{};

    // Feed only the SBE header (8 bytes) — not enough for root block
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), 8, info);
    assert(state.phase == SBEParseState::IDLE);  // need root block too

    // Feed header + root block (8+18=26 bytes) — but not group header
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), 26, info);
    assert(state.phase == SBEParseState::HEADER_PARSED);
    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));

    // Feed through group header (26+6=32 bytes) — should know trade count
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), 32, info);
    assert(state.phase == SBEParseState::TRADES_HEADER ||
           state.phase == SBEParseState::TRADES_ENTRIES);
    assert(info.mkt_event_count == 5);

    // Feed all data — all trades parsed
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), static_cast<uint32_t>(b.size()), info);
    assert(state.phase == SBEParseState::DONE);
    assert(info.mkt_event_seq == 104);  // last trade id = 100+4
    state.reset();

    // Verify trades were published via merge buffer
    h.idle();
    auto events = h.published();
    assert(!events.empty());
    assert(events[0].is_trade_array());
    assert(events[0].count == 5);
}

// ============================================================================
// Test 22: Streaming depth diff — verify deltas published incrementally
// ============================================================================

static SBEBuilder build_depth_diff_msg(int64_t event_time, int64_t first_id, int64_t last_id,
                                        int8_t price_exp, int8_t qty_exp,
                                        uint16_t num_bids, const int64_t* bid_prices, const int64_t* bid_qtys,
                                        uint16_t num_asks, const int64_t* ask_prices, const int64_t* ask_qtys,
                                        std::string_view symbol) {
    SBEBuilder b;
    b.write_header(26, 10003, 1, 0);  // DEPTH_DIFF_STREAM, block_length=26
    b.write_i64(event_time);
    b.write_i64(first_id);
    b.write_i64(last_id);
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

void test_streaming_depth_diff() {
    TestHarness h;

    // Build depth diff: 3 bids, 2 asks
    int64_t bp[] = {50000, 49000, 48000}, bq[] = {1000, 2000, 3000};
    int64_t ap[] = {50100, 51000}, aq[] = {1500, 2500};
    auto b = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                   3, bp, bq, 2, ap, aq, "BTCUSDT");

    // Feed complete frame via on_ws_data
    SBEParseState state{};
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), static_cast<uint32_t>(b.size()), info);
    state.reset();

    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::BOOK_DELTA));
    assert(info.mkt_event_seq == 505);
    assert(info.mkt_event_count == 5);  // 3 bids + 2 asks

    // Depth now deferred to batch end
    h.idle();

    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_book_delta());
    assert(events[0].count == 5);
    assert(events[0].src_seq == 505);

    // Verify bid/ask flags
    for (uint8_t i = 0; i < 3; i++)
        assert(events[0].payload.deltas.entries[i].is_bid());
    for (uint8_t i = 3; i < 5; i++)
        assert(events[0].payload.deltas.entries[i].is_ask());
}

// ============================================================================
// Test 23: State reset on disconnect
// ============================================================================

void test_state_reset_on_disconnect() {
    TestHarness h;

    // Start parsing a fragmented message
    TradeSet ts(1, 5);
    auto b = ts.build();

    // Feed partial data to set up state
    SBEParseState& state = h.handler.sbe_state_[0];
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), 32, info);
    assert(state.phase != SBEParseState::IDLE);

    // Disconnect should reset state
    h.handler.on_disconnected(0);
    assert(state.phase == SBEParseState::IDLE);
    assert(state.bytes_consumed == 0);

    // Reconnect should also reset
    state.phase = SBEParseState::HEADER_PARSED;  // simulate partial state
    h.handler.on_reconnected(0);
    assert(state.phase == SBEParseState::IDLE);
}

// ============================================================================
// Test 24: DONE state repopulates info on re-call
// ============================================================================

void test_done_state_repopulates_info() {
    TestHarness h;

    // Build a complete depth diff: 2 bids, 1 ask
    int64_t bp[] = {50000, 49000}, bq[] = {1000, 2000};
    int64_t ap[] = {50100}, aq[] = {1500};
    auto b = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                   2, bp, bq, 1, ap, aq, "BTCUSDT");

    // Feed complete frame to reach DONE state
    SBEParseState state{};
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), static_cast<uint32_t>(b.size()), info);
    assert(state.phase == SBEParseState::DONE);
    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::BOOK_DELTA));
    assert(info.exchange_event_time_us == 1000000);
    assert(info.mkt_event_seq == 505);
    assert(info.mkt_event_count == 3);  // 2 bids + 1 ask

    // Call again with a fresh WSFrameInfo (simulates subsequent TLS record delivery)
    WSFrameInfo info2{};
    info2.clear();
    h.handler.on_ws_data(state, 0, b.data(), static_cast<uint32_t>(b.size()), info2);

    // Bug 1 fix: info2 must be repopulated from state, not left at 0
    assert(info2.mkt_event_type == static_cast<uint8_t>(EventType::BOOK_DELTA));
    assert(info2.exchange_event_time_us == 1000000);
    assert(info2.mkt_event_seq == 505);
    assert(info2.mkt_event_count == 3);
}

// ============================================================================
// Test 25: Stale depth diff preserves type and exchange time
// ============================================================================

void test_stale_depth_diff_preserves_type() {
    TestHarness h;

    // Feed a fresh depth diff (seq=100) to set last_book_seq_
    int64_t bp[] = {50000}, bq[] = {1000};
    int64_t ap[] = {50100}, aq[] = {1500};
    auto b1 = build_depth_diff_msg(2000000, 90, 100, -8, -8,
                                    1, bp, bq, 1, ap, aq, "BTCUSDT");
    h.feed_frame(0, b1);

    // Feed a stale depth diff (seq=99, lower than last_book_seq_=100)
    auto b2 = build_depth_diff_msg(1500000, 89, 99, -8, -8,
                                    1, bp, bq, 1, ap, aq, "BTCUSDT");
    SBEParseState state{};
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 0, b2.data(), static_cast<uint32_t>(b2.size()), info);

    // Bug 2 fix: stale discard_early frames must still have type + exchange time
    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::BOOK_DELTA));
    assert(info.is_discard_early() == true);
    assert(info.exchange_event_time_us == 1500000);
    assert(info.mkt_event_seq == 99);
}

// ============================================================================
// Test 26: print_timeline() typed-frame check handles BOOK_DELTA=0
// ============================================================================

void test_print_timeline_book_delta_no_hex_dump() {
    WSFrameInfo info{};
    info.clear();
    info.mkt_event_type = 0;  // BOOK_DELTA = 0
    info.mkt_event_count = 0;
    info.exchange_event_time_us = 1000000;
    info.set_discard_early(true);
    info.opcode = 0x02;  // binary frame
    info.first_poll_cycle = 1;  // BSD mode: first_bpf_entry_ns==0 && first_poll_cycle>0
    info.ws_frame_publish_cycle = 9000000000ULL;  // non-zero so print_timeline doesn't early-return

    // Capture stderr output from print_timeline
    // Redirect stderr to a pipe
    int pipefd[2];
    assert(pipe(pipefd) == 0);
    int saved_stderr = dup(STDERR_FILENO);
    dup2(pipefd[1], STDERR_FILENO);

    info.print_timeline(3000000000ULL);  // 3 GHz TSC

    // Flush and restore stderr
    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    close(pipefd[1]);

    // Read captured output
    char captured[4096] = {};
    ssize_t n = read(pipefd[0], captured, sizeof(captured) - 1);
    close(pipefd[0]);
    assert(n > 0);
    captured[n] = '\0';

    // Bug 3 fix: should show "Dp" type, NOT hex dump "[op="
    assert(strstr(captured, "Dp") != nullptr);
    assert(strstr(captured, "[op=") == nullptr);
}

// ============================================================================
// Test 27: print_timeline() fragment suffix for BOOK_DELTA=0
// ============================================================================

void test_print_timeline_fragment_suffix_book_delta() {
    WSFrameInfo info{};
    info.clear();
    info.mkt_event_type = 0;  // BOOK_DELTA = 0
    info.mkt_event_count = 0;
    info.exchange_event_time_us = 1000000;
    info.set_fragmented(true);
    info.set_last_fragment(false);
    info.opcode = 0x02;
    info.first_poll_cycle = 1;
    info.ws_frame_publish_cycle = 9000000000ULL;

    int pipefd[2];
    assert(pipe(pipefd) == 0);
    int saved_stderr = dup(STDERR_FILENO);
    dup2(pipefd[1], STDERR_FILENO);

    info.print_timeline(3000000000ULL);

    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    close(pipefd[1]);

    char captured[4096] = {};
    ssize_t n = read(pipefd[0], captured, sizeof(captured) - 1);
    close(pipefd[0]);
    assert(n > 0);
    captured[n] = '\0';

    // Should show "Dp" type with underline (fragment indicator), NOT hex dump or Fg suffix
    assert(strstr(captured, "Dp") != nullptr);
    assert(strstr(captured, "\033[4m") != nullptr);   // underline on
    assert(strstr(captured, "\033[24m") != nullptr);  // underline off
    assert(strstr(captured, " Fg") == nullptr);        // no Fg suffix
    assert(strstr(captured, "[op=") == nullptr);
}

// ============================================================================
// Test 28: Non-merge trades are batched (not 1-per-event)
// ============================================================================

void test_non_merge_trades_batched() {
    TestHarness h;
    h.handler.merge_enabled = false;

    // Feed 25 trades (ids 1-25)
    TradeSet ts(1, 25);
    h.feed_frame(0, ts.build());

    auto events = h.published();
    // 25 trades, MAX_TRADES=11: 2 full batches (11 each) + 1 remainder (3)
    assert(events.size() == 3);
    assert(events[0].count == 11);
    assert(events[1].count == 11);
    assert(events[2].count == 3);

    // src_seq = last trade_id in each batch
    assert(events[0].src_seq == 11);   // trades 1-11
    assert(events[1].src_seq == 22);   // trades 12-22
    assert(events[2].src_seq == 25);   // trades 23-25

    // Verify FIFO order within each batch
    for (uint8_t i = 0; i < 11; i++)
        assert(events[0].payload.trades.entries[i].trade_id == 1 + i);
    for (uint8_t i = 0; i < 11; i++)
        assert(events[1].payload.trades.entries[i].trade_id == 12 + i);
    for (uint8_t i = 0; i < 3; i++)
        assert(events[2].payload.trades.entries[i].trade_id == 23 + i);

    // All events should be TRADE_ARRAY
    for (auto& ev : events)
        assert(ev.is_trade_array());
}

// ============================================================================
// Test 29: Stale trade via fragment — discard_early with type preserved
// ============================================================================

void test_stale_trade_via_fragment() {
    TestHarness h;

    // Feed 5 fresh trades (ids 100-104) → sets last_trade_id_ = 104
    TradeSet ts1(100, 5);
    h.feed_frame(0, ts1.build(1000000));
    h.idle();  // flush pending

    assert(h.handler.last_trade_id_ == 104);

    // Build a stale trades message (ids 100-104, same as before)
    TradeSet ts_stale(100, 5);
    auto b = ts_stale.build(2000000, 2000001);

    // Feed incrementally: first 26 bytes (header + root block only)
    // This parses the SBE header and sets mkt_event_type, but can't read group header yet
    SBEParseState state{};
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), 26, info);
    assert(state.phase == SBEParseState::HEADER_PARSED);
    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));
    assert(info.exchange_event_time_us == 2000000);

    // Feed full data — now group header + all entries are visible
    // HEADER_PARSED → TRADES_HEADER transition reads last trade_id, triggers stale check
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), static_cast<uint32_t>(b.size()), info);
    assert(info.is_discard_early() == true);
    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));
    assert(info.exchange_event_time_us == 2000000);
    assert(info.mkt_event_seq == 104);  // last stale trade_id
}

// ============================================================================
// Test 30: Depth delta overflow — >MAX_DELTAS triggers mid-stream flushes
// ============================================================================

void test_depth_delta_overflow() {
    TestHarness h;

    // Build depth diff with 25 bids + 20 asks = 45 total deltas (> MAX_DELTAS=19)
    std::vector<int64_t> bp(25), bq(25), ap(20), aq(20);
    for (int i = 0; i < 25; i++) { bp[i] = 50000 - i * 100; bq[i] = 1000 + i; }
    for (int i = 0; i < 20; i++) { ap[i] = 50100 + i * 100; aq[i] = 2000 + i; }

    auto b = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                   25, bp.data(), bq.data(),
                                   20, ap.data(), aq.data(), "BTCUSDT");

    h.feed_frame(0, b);
    h.idle();  // depth now deferred to batch end

    auto events = h.published();
    // 45 deltas, MAX_DELTAS=19: 2 overflow publishes (19 each) + 1 final at idle (7)
    assert(events.size() == 3);
    assert(events[0].count == 19);
    assert(events[1].count == 19);
    assert(events[2].count == 7);

    // First 19: all bids (from 25 bids)
    for (uint8_t i = 0; i < 19; i++)
        assert(events[0].payload.deltas.entries[i].is_bid());

    // Second 19: 6 remaining bids + 13 asks
    for (uint8_t i = 0; i < 6; i++)
        assert(events[1].payload.deltas.entries[i].is_bid());
    for (uint8_t i = 6; i < 19; i++)
        assert(events[1].payload.deltas.entries[i].is_ask());

    // Third 7: remaining 7 asks
    for (uint8_t i = 0; i < 7; i++)
        assert(events[2].payload.deltas.entries[i].is_ask());

    // All events should be BOOK_DELTA
    for (auto& ev : events)
        assert(ev.is_book_delta());
}

// ============================================================================
// Test 31: Stale BBO preserves type and exchange time
// ============================================================================

void test_stale_bbo_preserves_type() {
    TestHarness h;

    // Feed fresh BBO (seq=100) to set last_bbo_seq_
    auto bbo1 = build_bbo_msg(1000, 100, -8, -8, 50000, 1000, 50100, 2000, "BTCUSDT");
    h.feed_frame(0, bbo1);
    h.idle();  // flush pending BBO

    // Feed stale BBO (seq=99)
    auto bbo2 = build_bbo_msg(999, 99, -8, -8, 49000, 500, 49100, 1500, "BTCUSDT");
    SBEParseState state{};
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 0, bbo2.data(), static_cast<uint32_t>(bbo2.size()), info);

    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::BBO_ARRAY));
    assert(info.is_discard_early() == true);
    assert(info.exchange_event_time_us == 999);
}

// ============================================================================
// Test 32: print_timeline() fresh BOOK_DELTA=0 gets blue highlight
// ============================================================================

void test_print_timeline_fresh_book_delta_is_mkt() {
    WSFrameInfo info{};
    info.clear();
    info.mkt_event_type = 0;  // BOOK_DELTA = 0
    info.mkt_event_count = 5;
    info.exchange_event_time_us = 1000000;
    // NOT discard_early, NOT merged → should be is_mkt=true
    info.opcode = 0x02;
    info.first_poll_cycle = 1;  // BSD mode
    info.ws_frame_publish_cycle = 9000000000ULL;

    int pipefd[2];
    assert(pipe(pipefd) == 0);
    int saved_stderr = dup(STDERR_FILENO);
    dup2(pipefd[1], STDERR_FILENO);

    info.print_timeline(3000000000ULL);

    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    close(pipefd[1]);

    char captured[4096] = {};
    ssize_t n = read(pipefd[0], captured, sizeof(captured) - 1);
    close(pipefd[0]);
    assert(n > 0);
    captured[n] = '\0';

    // Bug Fix A: fresh non-stale non-merged BOOK_DELTA should get blue ANSI color
    assert(strstr(captured, "\033[34m") != nullptr);
}

// ============================================================================
// Test 33: Depth snapshot streaming — verify published payload content
// ============================================================================

void test_depth_snapshot_streaming_publish_content() {
    TestHarness h;

    // Build depth snapshot with 5 bids + 5 asks (total 10, fits in one flush since MAX_DELTAS=19)
    int64_t bp[] = {50000, 49000, 48000, 47000, 46000};
    int64_t bq[] = {1000, 2000, 3000, 4000, 5000};
    int64_t ap[] = {50100, 51000, 52000, 53000, 54000};
    int64_t aq[] = {1500, 2500, 3500, 4500, 5500};
    auto b = build_depth_snapshot_msg(1000000, 88928438912LL, -8, -8,
                                       5, bp, bq, 5, ap, aq, "BTCUSDT");

    h.feed_frame(0, b);

    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_book_snapshot());
    assert(events[0].count == 5);   // 5 bids
    assert(events[0].count2 == 5);  // 5 asks
    assert(events[0].src_seq == 88928438912LL);

    // Verify bid levels (payload.snapshot.levels[0..count-1])
    auto b_span = events[0].bids();
    assert(b_span.count == 5);
    for (uint8_t i = 0; i < 5; i++) {
        assert(b_span.data[i].price == bp[i]);
        assert(b_span.data[i].qty == bq[i]);
    }
    // Verify ask levels (payload.snapshot.levels[count..count+count2-1])
    auto a_span = events[0].asks();
    assert(a_span.count == 5);
    for (uint8_t i = 0; i < 5; i++) {
        assert(a_span.data[i].price == ap[i]);
        assert(a_span.data[i].qty == aq[i]);
    }
}

// ============================================================================
// Test 34: Cross-type flush — trades flushed before depth
// ============================================================================

void test_cross_type_flush_trades_then_depth() {
    TestHarness h;

    // Accumulate 3 trades (pending, not yet flushed)
    TradeSet ts(1, 3);
    h.feed_frame(0, ts.build(1000000));
    assert(h.published().empty());  // trades buffered via merge
    assert(h.handler.has_pending_trades_ == true);
    assert(h.handler.pending_trade_count_ == 3);

    // Feed a depth diff → should trigger cross-type flush_pending_trades() first
    int64_t bp[] = {50000}, bq[] = {1000};
    int64_t ap[] = {50100}, aq[] = {1500};
    auto depth = build_depth_diff_msg(2000000, 500, 505, -8, -8,
                                       1, bp, bq, 1, ap, aq, "BTCUSDT");
    h.feed_frame(0, depth);
    h.idle();  // depth now deferred to batch end

    auto events = h.published();
    // Should have trades event (from cross-type flush) + depth event (from idle)
    assert(events.size() == 2);
    assert(events[0].is_trade_array());
    assert(events[0].count == 3);
    assert(events[0].payload.trades.entries[0].trade_id == 1);
    assert(events[0].payload.trades.entries[2].trade_id == 3);

    assert(events[1].is_book_delta());
    assert(events[1].count == 2);  // 1 bid + 1 ask
    assert(events[1].src_seq == 505);
}

// ============================================================================
// Test 35: Fragment stale trade — first entry dedup (core bug repro)
// ============================================================================

void test_fragment_stale_trade_first_entry_dedup() {
    TestHarness h;

    // Feed 100 fresh trades (ids 1000-1099) → sets last_trade_id_ = 1099
    TradeSet ts_fresh(1000, 100);
    h.feed_frame(0, ts_fresh.build(1000000));
    h.idle();
    assert(h.handler.last_trade_id_ == 1099);

    // Build identical stale message (ids 1000-1099), ~2500+ bytes
    TradeSet ts_stale(1000, 100);
    auto b = ts_stale.build(2000000, 2000001);
    // 8 (SBE header) + 18 (root block) + 6 (group header) + 100*25 = 2532 bytes
    assert(b.size() >= 2500);

    // Feed as fragment: only first 1400 bytes — enters TRADES_HEADER
    // since len < entries_end, state.sequence stays 0 (can't read last entry)
    SBEParseState state{};
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 1, b.data(), 1400, info);

    // The fallback check should fire: first_tid=1000 <= 1099 → discard
    assert(info.is_discard_early() == true);
    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));
    assert(info.exchange_event_time_us == 2000000);
}

// ============================================================================
// Test 36: Fragment fresh trade — not falsely discarded
// ============================================================================

void test_fragment_fresh_trade_not_falsely_discarded() {
    TestHarness h;

    // Feed 5 fresh trades (ids 100-104) → sets last_trade_id_ = 104
    TradeSet ts1(100, 5);
    h.feed_frame(0, ts1.build(1000000));
    h.idle();
    assert(h.handler.last_trade_id_ == 104);

    // Build NEW trades (ids 200-299), ~2500+ bytes
    TradeSet ts_new(200, 100);
    auto b = ts_new.build(2000000, 2000001);
    assert(b.size() >= 2500);

    // Feed as fragment: only first 1400 bytes
    SBEParseState state{};
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 1, b.data(), 1400, info);

    // first_tid=200 > 104 → should NOT discard
    assert(info.is_discard_early() == false);
    assert(info.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));

    // Feed full data → trades should parse
    info.clear();
    h.handler.on_ws_data(state, 1, b.data(), static_cast<uint32_t>(b.size()), info);

    assert(state.phase == SBEParseState::TRADES_ENTRIES ||
           state.phase == SBEParseState::DONE);
    // Not discarded
    assert(info.is_discard_early() == false);
}

// ============================================================================
// Test 37: Fragment stale trade — multi-connection dedup
// ============================================================================

void test_fragment_stale_trade_multi_conn() {
    TestHarness h;

    // Feed 50 fresh trades (ids 500-549) from conn 0
    TradeSet ts(500, 50);
    h.feed_frame(0, ts.build(1000000));
    h.idle();
    assert(h.handler.last_trade_id_ == 549);

    auto events_before = h.published();

    // Feed identical message from conn 1 as fragment (partial)
    auto b = ts.build(1000000, 1000001);
    SBEParseState state1{};
    WSFrameInfo info1{};
    info1.clear();
    h.handler.on_ws_data(state1, 1, b.data(), 1400, info1);
    assert(info1.is_discard_early() == true);

    // Feed identical message from conn 2 as full frame via feed_frame
    h.feed_frame(2, ts.build(1000000));
    h.idle();

    auto events_after = h.published();
    // The full-frame feed from conn 2 should also be discarded (existing stale check)
    // No new trade events should appear beyond what conn 0 published
    assert(events_after.size() == events_before.size());
}

// ============================================================================
// Test 38: Fragment stale trade — merge mode with pending buffer
// ============================================================================

void test_fragment_stale_trade_merge_mode() {
    TestHarness h;
    // merge is enabled by default in TestHarness

    // Feed 50 trades from conn 0 (enters pending buffer, NOT flushed yet)
    TradeSet ts(500, 50);
    h.feed_frame(0, ts.build(1000000));
    // DO NOT idle() — trades stay in pending buffer
    assert(h.handler.has_pending_trades_ == true);
    assert(h.handler.pending_trades_max_id_ == 549);

    // Feed same trades from conn 1 as fragment
    auto b = ts.build(1000000, 1000001);
    SBEParseState state1{};
    WSFrameInfo info1{};
    info1.clear();
    h.handler.on_ws_data(state1, 1, b.data(), 1400, info1);

    // eff_tid = max(last_trade_id_=0, pending_trades_max_id_=549) = 549
    // first_tid = 500 <= 549 → discard
    assert(info1.is_discard_early() == true);

    // Now flush
    h.idle();

    // Published events should contain only conn 0's trades
    auto events = h.published();
    assert(!events.empty());
    for (auto& ev : events) {
        if (ev.is_trade_array()) {
            for (uint8_t i = 0; i < ev.count; i++)
                assert(ev.payload.trades.entries[i].trade_id >= 500 &&
                       ev.payload.trades.entries[i].trade_id <= 549);
        }
    }
}

// ============================================================================
// Test 39: Full message stale — first_tid catches race with partial eff_tid
//
// Scenario: conn A processes a 56-trade fragment, inner-flushes set
// last_trade_id_ to a PARTIAL max (e.g., entry 43's id). Conn B then
// receives the FULL message — state.sequence (last entry) barely exceeds
// eff_tid, but first_tid is well below it. The first-entry check catches
// this even when state.sequence > 0.
// ============================================================================

void test_full_message_stale_via_first_entry() {
    TestHarness h;

    // Build a 56-trade message: ids 1000-1055
    TradeSet ts(1000, 56);
    auto b = ts.build(1000000, 1000001);
    // 8 + 18 + 6 + 56*25 = 1432 bytes total

    // Simulate conn 0 processing only 44 entries (partial fragment)
    // This means 4 inner flushes (11 each), last_trade_id_ = max of 44th entry
    // Feed as fragment: give enough bytes for header + 44 entries
    uint32_t partial_len = 8 + 18 + 6 + 44 * 25;  // 1132 bytes
    assert(partial_len < b.size());

    SBEParseState state0{};
    WSFrameInfo info0{};
    info0.clear();
    h.handler.on_ws_data(state0, 0, b.data(), partial_len, info0);

    // state0.sequence should be 0 (can't read last of 56 entries in 44-entry fragment)
    // Inner flushes occur at entry 11 (flush 0-10), 22 (flush 11-21), 33 (flush 22-32)
    // pending_trades_max_id_ updated BEFORE flush, so:
    //   flush at entry 11: last_trade_id_ = 1011
    //   flush at entry 22: last_trade_id_ = 1022
    //   flush at entry 33: last_trade_id_ = 1033
    // Entries 33-43 remain in pending buffer (unflushed, count=11)
    assert(h.handler.last_trade_id_ == 1033);
    assert(h.handler.pending_trades_max_id_ == 1043);
    assert(state0.group_published == 44);

    // Now conn 1 gets the FULL message
    // state.sequence = 1055 (last entry)
    // eff_tid = max(last_trade_id_=1033, pending_trades_max_id_=1043) = 1043
    // Without first_tid check: 1055 > 1043 → passes stale check → DUP!
    // With first_tid check: first_tid=1000 <= 1043 → DISCARD ✓
    SBEParseState state1{};
    WSFrameInfo info1{};
    info1.clear();
    h.handler.on_ws_data(state1, 1, b.data(), static_cast<uint32_t>(b.size()), info1);

    assert(info1.is_discard_early() == true);
    assert(info1.mkt_event_type == static_cast<uint8_t>(EventType::TRADE_ARRAY));
}

// ============================================================================
// Test 40: Cross-connection merge flush prevents mixed batches
// ============================================================================

void test_cross_conn_merge_flush_before_mix() {
    TestHarness h;
    h.handler.merge_enabled = true;

    // Conn 0 feeds 10 trades (ids 100-109)
    TradeSet ts0(100, 10);
    auto b0 = ts0.build(1000000, 1000001);
    h.feed_frame(0, b0);
    // Pending buffer now has 10 entries from conn 0, not yet flushed

    // Conn 1 feeds 10 trades (ids 200-209) — different connection
    TradeSet ts1(200, 10);
    auto b1 = ts1.build(1000000, 1000001);
    h.feed_frame(1, b1);
    // Cross-conn flush should have flushed conn 0's pending before adding conn 1's

    // Flush remaining
    h.idle();

    auto events = h.published();

    // Should have 2 separate TRADE_ARRAY events (not mixed)
    int trade_count = 0;
    int64_t prev_seq = 0;
    for (auto& ev : events) {
        if (ev.event_type() == static_cast<uint8_t>(EventType::TRADE_ARRAY)) {
            assert(ev.src_seq > prev_seq);
            prev_seq = ev.src_seq;
            trade_count++;
        }
    }
    assert(trade_count == 2);

    // First event should be conn 0's trades (src_seq = 109)
    // Second event should be conn 1's trades (src_seq = 209)
    bool found_109 = false, found_209 = false;
    for (auto& ev : events) {
        if (ev.event_type() == static_cast<uint8_t>(EventType::TRADE_ARRAY)) {
            if (ev.src_seq == 109) found_109 = true;
            if (ev.src_seq == 209) found_209 = true;
        }
    }
    assert(found_109);
    assert(found_209);
}

// ============================================================================
// Test 41: Fragment interleave — stale resumption discarded (merge mode)
// ============================================================================

void test_fragment_interleave_stale_resumption() {
    TestHarness h;
    h.handler.merge_enabled = true;

    // Conn 0: large fragmented trade message (ids 1000-1104, 105 entries)
    TradeSet ts0(1000, 105);
    auto b0 = ts0.build(1000000, 1000001);
    // Fragment 1: enough bytes for header + 56 entries
    // header=8, block=18, group_header=6, 56*25=1400  →  1432 bytes
    uint32_t frag1_len = 8 + 18 + 6 + 56 * 25;
    assert(frag1_len < b0.size());

    SBEParseState state0{};
    WSFrameInfo info0{};
    info0.clear();
    h.handler.on_ws_data(state0, 0, b0.data(), frag1_len, info0);
    // state0 is mid-fragment: group_published=56 (or less due to inner flushes)
    assert(state0.group_published > 0);
    assert(state0.group_published < 105);

    // Simulate batch boundary — flushes partial trades from conn 0
    h.idle();

    // Record last_trade_id_ after conn 0's partial flush
    int64_t ltid_after_conn0 = h.handler.last_trade_id_;
    assert(ltid_after_conn0 > 0);

    // Conn 1: different, NEWER trade message (ids 1200-1249, 50 entries)
    TradeSet ts1(1200, 50);
    auto b1 = ts1.build(1000000, 1000001);
    h.feed_frame(1, b1);
    h.idle();

    // last_trade_id_ should now be 1249 (conn 1's max)
    assert(h.handler.last_trade_id_ == 1249);

    // Conn 0: fragment 2 — feed remaining data
    WSFrameInfo info0b{};
    info0b.clear();
    h.handler.on_ws_data(state0, 0, b0.data(), static_cast<uint32_t>(b0.size()), info0b);

    // Fragment resumption stale check: next_tid (1056) <= last_trade_id_ (1249) → discard
    assert(info0b.is_discard_early() == true);

    // Verify all published src_seqs are monotonic
    auto events = h.published();
    int64_t prev_seq = 0;
    for (auto& ev : events) {
        if (ev.event_type() == static_cast<uint8_t>(EventType::TRADE_ARRAY)) {
            assert(ev.src_seq > prev_seq);
            prev_seq = ev.src_seq;
        }
    }
}

// ============================================================================
// Test 42: Fragment interleave — stale resumption discarded (non-merge mode)
// ============================================================================

void test_fragment_interleave_non_merge() {
    TestHarness h;
    h.handler.merge_enabled = false;

    // Conn 0: large fragmented trade message (ids 1000-1104, 105 entries)
    TradeSet ts0(1000, 105);
    auto b0 = ts0.build(1000000, 1000001);
    uint32_t frag1_len = 8 + 18 + 6 + 56 * 25;  // header + 56 entries

    SBEParseState state0{};
    WSFrameInfo info0{};
    info0.clear();
    h.handler.on_ws_data(state0, 0, b0.data(), frag1_len, info0);
    // Non-merge publishes immediately — 56 entries published in batches of MAX_TRADES
    assert(state0.group_published == 56);

    // Conn 1: newer trades (ids 1200-1249)
    TradeSet ts1(1200, 50);
    auto b1 = ts1.build(1000000, 1000001);
    h.feed_frame(1, b1);

    // last_trade_id_ should now be 1249
    assert(h.handler.last_trade_id_ == 1249);

    // Conn 0: fragment 2 — remaining entries (ids 1056-1104)
    WSFrameInfo info0b{};
    info0b.clear();
    h.handler.on_ws_data(state0, 0, b0.data(), static_cast<uint32_t>(b0.size()), info0b);

    // Fragment resumption stale check: next_tid (1056) <= 1249 → discard
    assert(info0b.is_discard_early() == true);

    // Verify monotonic src_seq across all published events
    auto events = h.published();
    int64_t prev_seq = 0;
    for (auto& ev : events) {
        if (ev.event_type() == static_cast<uint8_t>(EventType::TRADE_ARRAY)) {
            assert(ev.src_seq > prev_seq);
            prev_seq = ev.src_seq;
        }
    }
}

// ============================================================================
// Test 43: Cross-connection pending attribution is correct
// ============================================================================

void test_cross_conn_pending_ci_attribution() {
    TestHarness h;
    h.handler.merge_enabled = true;

    // Conn 0 feeds 5 trades (ids 100-104)
    TradeSet ts0(100, 5);
    auto b0 = ts0.build(1000000, 1000001);
    h.feed_frame(0, b0);
    // Pending buffer has 5 entries from conn 0

    assert(h.handler.has_pending_trades_ == true);
    assert(h.handler.pending_trades_ci_ == 0);

    // Conn 2 feeds 5 trades (ids 200-204) — different connection
    TradeSet ts2(200, 5);
    auto b2 = ts2.build(1000000, 1000001);
    h.feed_frame(2, b2);

    // After cross-conn flush: conn 0's trades published, then conn 2's pending
    // pending_trades_ci_ should now be 2
    assert(h.handler.pending_trades_ci_ == 2);

    // Flush remaining
    h.idle();

    auto events = h.published();
    int trade_count = 0;
    for (auto& ev : events) {
        if (ev.event_type() == static_cast<uint8_t>(EventType::TRADE_ARRAY))
            trade_count++;
    }
    // Two separate batches
    assert(trade_count == 2);
}

// ============================================================================
// Test 44: Header-only fragment (zero entries parsed) — stale on resumption
// ============================================================================

void test_header_only_fragment_stale_on_resume() {
    TestHarness h;
    h.handler.merge_enabled = true;

    // Build a single-trade message (id 5000)
    TradeSet ts(5000, 1);
    auto b = ts.build(1000000, 1000001);
    // SBE: header=8, root_block=18, group_header=6, 1*25=25 → total 57 bytes

    // Fragment 1: only give enough for header + group header (no entries)
    // 8 (SBE header) + 18 (root block) + 6 (group header) = 32 bytes
    uint32_t hdr_only_len = 32;
    assert(hdr_only_len < b.size());

    SBEParseState state0{};
    WSFrameInfo info0{};
    info0.clear();
    h.handler.on_ws_data(state0, 0, b.data(), hdr_only_len, info0);
    // Header parsed, group header parsed, but no entry data available
    // state.sequence = 0 (can't read last entry)
    // state.phase should be TRADES_ENTRIES (entered entry loop but broke immediately)
    assert(state0.group_count == 1);
    assert(state0.group_published == 0);
    assert(info0.is_discard_early() == false);  // stale checks couldn't read any tid

    // Advance last_trade_id_ via conn 1 with newer trades
    TradeSet ts1(6000, 10);
    auto b1 = ts1.build(1000000, 1000001);
    h.feed_frame(1, b1);
    h.idle();
    assert(h.handler.last_trade_id_ == 6009);

    // Fragment 2: conn 0 resumes with full data
    WSFrameInfo info0b{};
    info0b.clear();
    h.handler.on_ws_data(state0, 0, b.data(), static_cast<uint32_t>(b.size()), info0b);

    // Stale re-check: next_tid (5000) <= last_trade_id_ (6009) → DISCARD
    assert(info0b.is_discard_early() == true);

    // Verify no non-monotonic published events
    auto events = h.published();
    int64_t prev_seq = 0;
    for (auto& ev : events) {
        if (ev.event_type() == static_cast<uint8_t>(EventType::TRADE_ARRAY)) {
            assert(ev.src_seq > prev_seq);
            prev_seq = ev.src_seq;
        }
    }
}

// ============================================================================
// Test 45: pending_trades_max_id_ monotonic (never decreases)
// ============================================================================

void test_pending_max_id_monotonic() {
    TestHarness h;
    h.handler.merge_enabled = true;

    // Conn 0: newer trades (ids 500-509)
    TradeSet ts0(500, 10);
    auto b0 = ts0.build(1000000, 1000001);
    h.feed_frame(0, b0);
    // pending_trades_max_id_ = 509
    assert(h.handler.pending_trades_max_id_ >= 509);

    // Conn 0: older trades from same connection (ids 100-109, same batch)
    // These should be caught by stale check (first_tid 100 <= eff_tid 509)
    TradeSet ts1(100, 10);
    auto b1 = ts1.build(1000000, 1000001);
    h.feed_frame(0, b1);

    // pending_trades_max_id_ should NOT decrease
    assert(h.handler.pending_trades_max_id_ >= 509);

    h.idle();
    // last_trade_id_ should be at least 509
    assert(h.handler.last_trade_id_ >= 509);
}

// ============================================================================
// Test 46: Fragment depth superseded by other connection
// ============================================================================

void test_fragment_depth_superseded_by_other_conn() {
    TestHarness h;

    // Build large depth snapshot: seq=1000, 40 bids + 40 asks
    // ~8 + 18 + 4 + 40*16 + 4 + 40*16 + 8 = 1322 bytes
    auto b = build_large_depth_snapshot(1000000, 1000, 40, 40);

    // Fragment: first 700 bytes from conn 0
    SBEParseState state0{};
    WSFrameInfo info0{};
    info0.clear();
    h.handler.on_ws_data(state0, 0, b.data(), 700, info0);
    // Should be mid-stream (BIDS_ENTRIES or similar)
    assert(state0.phase != SBEParseState::IDLE);
    assert(state0.phase != SBEParseState::DONE);
    assert(h.handler.last_book_seq_ == 1000);  // claimed on acceptance

    auto events_after_frag = h.published();

    // Complete depth diff from conn 1: seq=2000 (supersedes)
    int64_t bp[] = {49000}, bq[] = {100};
    int64_t ap[] = {51000}, aq[] = {200};
    auto b2 = build_depth_diff_msg(2000000, 1999, 2000, -8, -8,
                                    1, bp, bq, 1, ap, aq, "BTCUSDT");
    h.feed_frame(1, b2);
    h.idle();
    assert(h.handler.last_book_seq_ == 2000);  // superseded

    auto events_after_supersede = h.published();

    // Resume conn 0 fragment with full payload
    WSFrameInfo info0_resume{};
    info0_resume.clear();
    h.handler.on_ws_data(state0, 0, b.data(), static_cast<uint32_t>(b.size()), info0_resume);

    // Fix: should detect seq=1000 < last_book_seq_=2000, set discard_early, stop
    assert(info0_resume.is_discard_early() == true);

    auto events_after_resume = h.published();
    // No new depth events from the stale conn 0 resume
    size_t new_events = events_after_resume.size() - events_after_supersede.size();
    assert(new_events == 0);
}

// ============================================================================
// Test 47: Fragment depth deduped DONE propagates discard
// ============================================================================

void test_fragment_depth_deduped_done_propagates_discard() {
    TestHarness h;

    // Establish watermark with depth diff seq=505
    int64_t bp[] = {50000}, bq[] = {1000};
    int64_t ap[] = {50100}, aq[] = {1500};
    auto b = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                   1, bp, bq, 1, ap, aq, "BTCUSDT");
    h.feed_frame(0, b);
    h.idle();
    assert(h.handler.last_book_seq_ == 505);

    // Same seq=505 as full frame from conn 1 → initial dedup → DONE
    SBEParseState state1{};
    WSFrameInfo info1{};
    info1.clear();
    h.handler.on_ws_data(state1, 1, b.data(), static_cast<uint32_t>(b.size()), info1);
    assert(state1.phase == SBEParseState::DONE);
    assert(info1.is_discard_early() == true);

    // Simulate next TLS record hitting non-IDLE DONE path
    WSFrameInfo info1b{};
    info1b.clear();
    h.handler.on_ws_data(state1, 1, b.data(), static_cast<uint32_t>(b.size()), info1b);
    assert(info1b.is_discard_early() == true);  // deduped flag propagates
}

// ============================================================================
// Test: print_timeline() column alignment across varying digit counts
// ============================================================================

void test_print_timeline_column_alignment() {
    // 9 test cases from real Binance DPDK output, varying digit counts
    // in nic_packet_ct, ssl_read_ct, payload_len/ssl_read_total_bytes, and mkt_event_count
    struct Case {
        uint8_t  conn;
        uint8_t  pkt;
        uint8_t  ssl;
        uint32_t payload;
        uint32_t total;
        uint16_t batch;
        uint16_t evt_count;  // mkt_event_count: 0, 1-9, 10-99, 100-999
    };
    constexpr Case cases[] = {
        {7,  9,  9, 13116, 13120,  9,   5},  // 5-digit sz, 1-digit pkt/ssl, 1-digit cnt
        {0,  1,  1,  1436,  1440,  1,   0},  // 4-digit sz, 1-digit, 0 cnt (discard_early)
        {7, 10, 10, 14588, 14592, 10,   5},  // 5-digit sz, 2-digit pkt/ssl
        {0,  2,  2,  2908,  2912,  2,   1},  // 4-digit sz, 1-digit cnt
        {2,  9,  9, 13116, 13120,  9, 219},  // 3-digit cnt (the key alignment case)
        {0,  3,  3,  4364,  4368,  3,  42},  // 2-digit cnt
        {2, 11, 10, 14609, 14613, 10,   9},  // mismatched pkt/ssl, 1-digit cnt
        {0,  4,  4,  4782,  4786,  4, 219},  // 3-digit cnt, active conn
        {5,  1,  1,  1436,  1440,  1,   0},  // 0 cnt, discard_early, different conn
    };
    constexpr int N = sizeof(cases) / sizeof(cases[0]);

    constexpr uint64_t TSC_FREQ = 3000000000ULL;
    constexpr uint64_t REF_CYCLE = 9000000000ULL;
    constexpr uint64_t PUBLISH_MONO = 1000000000000ULL;

    // Capture all outputs
    std::string lines[N];
    for (int i = 0; i < N; ++i) {
        WSFrameInfo info{};
        info.clear();
        info.connection_id = cases[i].conn;
        info.nic_packet_ct = cases[i].pkt;
        info.ssl_read_ct = cases[i].ssl;
        info.payload_len = cases[i].payload;
        info.ssl_read_total_bytes = cases[i].total;
        info.ssl_read_batch_num = cases[i].batch;
        info.opcode = 0x02;
        info.mkt_event_type = 0;  // BOOK_DELTA
        info.mkt_event_count = cases[i].evt_count;
        info.exchange_event_time_us = 1000000;
        if (cases[i].evt_count == 0) {
            info.set_discard_early(true);  // X mark for 0-count
        }
        info.transport_mode = static_cast<uint8_t>(TransportMode::DPDK_DISRUPTOR);
        info.first_bpf_entry_ns = PUBLISH_MONO - 500000;
        info.latest_bpf_entry_ns = PUBLISH_MONO - 400000;
        info.ws_frame_publish_cycle = REF_CYCLE;
        info.publish_time_ts = PUBLISH_MONO;
        // Vary poll cycles so each is detected as a new packet
        info.first_poll_cycle = REF_CYCLE - 900000 - i * 1000;
        info.latest_poll_cycle = REF_CYCLE - 800000 - i * 1000;
        info.first_ssl_read_start_cycle = REF_CYCLE - 600000;
        info.latest_ssl_read_end_cycle = REF_CYCLE - 300000;
        info.ws_parse_cycle = REF_CYCLE - 150000;

        int pipefd[2];
        assert(pipe(pipefd) == 0);
        int saved_stderr = dup(STDERR_FILENO);
        dup2(pipefd[1], STDERR_FILENO);

        info.print_timeline(TSC_FREQ);

        fflush(stderr);
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
        close(pipefd[1]);

        char captured[4096] = {};
        ssize_t n = read(pipefd[0], captured, sizeof(captured) - 1);
        close(pipefd[0]);
        assert(n > 0);
        captured[n] = '\0';
        lines[i] = captured;
    }

    // Strip ANSI escape sequences from each line
    auto strip_ansi = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '\033' && i + 1 < s.size() && s[i + 1] == '[') {
                i += 2;
                while (i < s.size() && s[i] != 'm') ++i;
            } else {
                out += s[i];
            }
        }
        return out;
    };

    // Find column positions in stripped lines
    size_t ssl_pos[N], ws_pos[N], at_pos[N];
    for (int i = 0; i < N; ++i) {
        std::string stripped = strip_ansi(lines[i]);
        // Find "ssl " (matches both "*ssl " and " ssl ")
        size_t p = stripped.find("ssl ");
        if (p == std::string::npos) {
            fprintf(stderr, "FAIL: line[%d] missing 'ssl ': %s", i, stripped.c_str());
        }
        assert(p != std::string::npos);
        ssl_pos[i] = p;

        p = stripped.find("| WS");
        if (p == std::string::npos) {
            fprintf(stderr, "FAIL: line[%d] missing '| WS': %s", i, stripped.c_str());
        }
        assert(p != std::string::npos);
        ws_pos[i] = p;

        // Find "@ " in the mkt section (after "| WS")
        p = stripped.find("@ ", ws_pos[i]);
        if (p == std::string::npos) {
            fprintf(stderr, "FAIL: line[%d] missing '@ ': %s", i, stripped.c_str());
        }
        assert(p != std::string::npos);
        at_pos[i] = p;
    }

    // Assert all ssl column positions are identical
    for (int i = 1; i < N; ++i) {
        if (ssl_pos[i] != ssl_pos[0]) {
            fprintf(stderr, "FAIL: ssl column mismatch: line[0]=%zu vs line[%d]=%zu\n",
                    ssl_pos[0], i, ssl_pos[i]);
            fprintf(stderr, "  line[0]: %s", strip_ansi(lines[0]).c_str());
            fprintf(stderr, "  line[%d]: %s", i, strip_ansi(lines[i]).c_str());
        }
        assert(ssl_pos[i] == ssl_pos[0]);
    }

    // Assert all WS column positions are identical
    for (int i = 1; i < N; ++i) {
        if (ws_pos[i] != ws_pos[0]) {
            fprintf(stderr, "FAIL: WS column mismatch: line[0]=%zu vs line[%d]=%zu\n",
                    ws_pos[0], i, ws_pos[i]);
            fprintf(stderr, "  line[0]: %s", strip_ansi(lines[0]).c_str());
            fprintf(stderr, "  line[%d]: %s", i, strip_ansi(lines[i]).c_str());
        }
        assert(ws_pos[i] == ws_pos[0]);
    }

    // Assert all @ column positions are identical (mkt_event_count alignment)
    for (int i = 1; i < N; ++i) {
        if (at_pos[i] != at_pos[0]) {
            fprintf(stderr, "FAIL: @ column mismatch: line[0]=%zu vs line[%d]=%zu\n",
                    at_pos[0], i, at_pos[i]);
            fprintf(stderr, "  line[0]: %s", strip_ansi(lines[0]).c_str());
            fprintf(stderr, "  line[%d]: %s", i, strip_ansi(lines[i]).c_str());
        }
        assert(at_pos[i] == at_pos[0]);
    }
}

// ============================================================================
// Test: Fragment depth flush at boundary — deltas flushed when fragment ends
// ============================================================================

void test_fragment_depth_flush_at_boundary() {
    TestHarness h;

    // Build depth diff: 60 bids, 0 asks
    // SBE layout: header(8) + root(26) + bids_group_hdr(4) + 60×16(960) + asks_group_hdr(4) + 0 + var_str(~8) = ~1010 bytes
    std::vector<int64_t> bp(60), bq(60);
    for (int i = 0; i < 60; i++) { bp[i] = 50000 - i * 100; bq[i] = 1000 + i; }

    std::vector<int64_t> ap, aq;  // 0 asks
    auto b = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                   60, bp.data(), bq.data(),
                                   0, ap.data(), aq.data(), "BTCUSDT");

    // Verify layout: 8+26+4+960+4+0+8 = 1010
    assert(b.size() == 1010);

    // Fragment 1: truncate at 600 bytes
    // 600 - 8(header) - 26(root) - 4(bids_group_hdr) = 562 bytes of bid entries
    // 35 complete entries (35×16=560), 2 bytes leftover
    SBEParseState state{};
    WSFrameInfo info{};
    info.clear();
    h.handler.on_ws_data(state, 0, b.data(), 600, info);

    assert(state.phase == SBEParseState::BIDS_ENTRIES);
    assert(state.bids_published == 35);

    // Fragment 2: feed full payload — resumes from entry 35, parses remaining 25 bids + 0 asks
    WSFrameInfo info2{};
    info2.clear();
    h.handler.on_ws_data(state, 0, b.data(), static_cast<uint32_t>(b.size()), info2);
    assert(state.phase == SBEParseState::DONE);
    state.reset();
    h.idle();  // depth now deferred to batch end

    auto events = h.published();
    // Expected: flush#0=19 (overflow), flush#1=16 (overflow), flush#2=19 (overflow), flush#3=6 (idle)
    assert(events.size() == 4);
    assert(events[0].count == 19);
    assert(events[1].count == 16);
    assert(events[2].count == 19);
    assert(events[3].count == 6);

    // All BOOK_DELTA, all bids
    for (auto& ev : events) {
        assert(ev.is_book_delta());
        for (uint8_t i = 0; i < ev.count; i++)
            assert(ev.payload.deltas.entries[i].is_bid());
    }

    // Flags: first has no CONTINUATION, rest have CONTINUATION; only last has LAST_IN_BATCH
    assert(!events[0].is_continuation());
    assert(!events[0].is_last_in_batch());
    assert(events[1].is_continuation());
    assert(!events[1].is_last_in_batch());
    assert(events[2].is_continuation());
    assert(!events[2].is_last_in_batch());
    assert(events[3].is_continuation());
    assert(events[3].is_last_in_batch());

    // Total deltas: 19+16+19+6 = 60
    uint32_t total = 0;
    for (auto& ev : events) total += ev.count;
    assert(total == 60);
}

// ============================================================================
// Test: Cross-frame depth merge within single batch
// Two complete depth diffs without idle → merged into 1 MktEvent at idle
// ============================================================================

void test_cross_frame_depth_merge_within_batch() {
    TestHarness h;

    // Depth diff 1: 8 deltas (4 bids + 4 asks), seq=100
    int64_t bp1[] = {50000, 49000, 48000, 47000}, bq1[] = {1000, 2000, 3000, 4000};
    int64_t ap1[] = {50100, 51000, 52000, 53000}, aq1[] = {1500, 2500, 3500, 4500};
    auto d1 = build_depth_diff_msg(1000000, 90, 100, -8, -8,
                                    4, bp1, bq1, 4, ap1, aq1, "BTCUSDT");

    // Depth diff 2: 6 deltas (3 bids + 3 asks), seq=101
    int64_t bp2[] = {46000, 45000, 44000}, bq2[] = {5000, 6000, 7000};
    int64_t ap2[] = {54000, 55000, 56000}, aq2[] = {5500, 6500, 7500};
    auto d2 = build_depth_diff_msg(2000000, 100, 101, -8, -8,
                                    3, bp2, bq2, 3, ap2, aq2, "BTCUSDT");

    h.feed_frame(0, d1);
    h.feed_frame(0, d2);
    assert(h.published().empty());  // all buffered

    h.idle();
    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_book_delta());
    assert(events[0].count == 14);  // 8 + 6 merged
    assert(events[0].src_seq == 101);  // latest seq
    assert(events[0].is_last_in_batch());
    assert(!events[0].is_continuation());

    // Verify bid/ask flags: 4 bids, 4 asks, 3 bids, 3 asks
    for (uint8_t i = 0; i < 4; i++)
        assert(events[0].payload.deltas.entries[i].is_bid());
    for (uint8_t i = 4; i < 8; i++)
        assert(events[0].payload.deltas.entries[i].is_ask());
    for (uint8_t i = 8; i < 11; i++)
        assert(events[0].payload.deltas.entries[i].is_bid());
    for (uint8_t i = 11; i < 14; i++)
        assert(events[0].payload.deltas.entries[i].is_ask());
}

// ============================================================================
// Test: Cross-type depth flush — trade after depth flushes pending depth
// ============================================================================

void test_cross_type_depth_then_trades() {
    TestHarness h;

    // Accumulate depth (3 deltas, 2 bids + 1 ask)
    int64_t bp[] = {50000, 49000}, bq[] = {1000, 2000};
    int64_t ap[] = {50100}, aq[] = {1500};
    auto depth = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                       2, bp, bq, 1, ap, aq, "BTCUSDT");
    h.feed_frame(0, depth);
    assert(h.published().empty());  // depth buffered
    assert(h.handler.has_pending_depth_ == true);

    // Feed trades → should trigger cross-type flush of pending depth first
    TradeSet ts(1, 3);
    h.feed_frame(0, ts.build(2000000));

    // Depth should have been flushed by cross-type flush
    auto events = h.published();
    assert(events.size() == 1);
    assert(events[0].is_book_delta());
    assert(events[0].count == 3);
    assert(events[0].src_seq == 505);

    // Trades still pending until idle
    h.idle();
    events = h.published();
    assert(events.size() == 2);
    assert(events[1].is_trade_array());
    assert(events[1].count == 3);
}

// ============================================================================
// Same-SEQ interleave tests
// ============================================================================

// Helper: count delta entries across all BOOK_DELTA events
static int sbe_count_delta_entries(const std::vector<MktEvent>& events) {
    int total = 0;
    for (auto& e : events) {
        if (e.is_book_delta()) total += e.count;
    }
    return total;
}

// Test: conn0 finishes depth diff, conn1 same seq → fully deduped
void test_sbe_interleave_basic() {
    TestHarness h;

    int64_t bp[] = {50000, 49000, 48000}, bq[] = {1000, 2000, 3000};
    int64_t ap[] = {50100, 51000}, aq[] = {1500, 2500};
    auto b = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                   3, bp, bq, 2, ap, aq, "BTCUSDT");

    // conn0: complete frame → 5 entries committed, finished=true
    h.feed_frame(0, b);
    h.idle();

    auto events0 = h.published();
    int entries0 = sbe_count_delta_entries(events0);
    assert(entries0 == 5);

    // conn1: same seq=505, same data → deduped (finished fast-path)
    h.feed_frame(1, b);
    h.idle();

    auto events1 = h.published();
    int entries1 = sbe_count_delta_entries(events1);
    assert(entries1 == entries0);  // no new entries
}

// Test: conn0 fragment (partial), conn1 complete → conn1 fills in excess entries
void test_sbe_interleave_conn1_faster() {
    TestHarness h;

    // Build depth diff with 5 bids + 5 asks = 10 entries
    int64_t bp[5], bq[5], ap[5], aq[5];
    for (int i = 0; i < 5; i++) {
        bp[i] = 50000 + i * 100;
        bq[i] = 1000 + i;
        ap[i] = 60000 + i * 100;
        aq[i] = 2000 + i;
    }
    auto b = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                   5, bp, bq, 5, ap, aq, "BTCUSDT");

    // conn0: fragment — truncate partway through bids group entries.
    // Header(8) + root(26) = 34 bytes. Then bids group header(4) + 3 entries(48) = 52.
    // Total for 3 bids parsed: 34 + 4 + 48 = 86 bytes.
    uint32_t trunc_after_3_bids = 8 + 26 + 4 + 3 * 16;  // 86
    assert(trunc_after_3_bids < b.size());

    h.feed_fragment(0, b, trunc_after_3_bids);
    // interleave_.committed_count = 3 (3 bids parsed and flushed)

    // conn1: complete frame (10 entries total)
    // Bids (5 entries): cumul=5, committed=3 → prev_cumul=0 < committed=3 < 5=cumul
    //   boundary check at entry[2]: should match → skip=3, publish 2 bids
    // Asks (5 entries): cumul=10, prev_cumul=5, committed=5 → prev_cumul < committed is false
    //   skip=0, publish all 5 asks
    h.feed_frame(1, b);
    h.idle();

    auto events_after_conn1 = h.published();
    int entries_after_conn1 = sbe_count_delta_entries(events_after_conn1);
    // 3 from conn0 fragment + 2 from conn1 bids + 5 from conn1 asks = 10
    assert(entries_after_conn1 >= 10);

    // Finish conn0 — should not add more (conn1 finished)
    {
        WSFrameInfo info2{};
        info2.clear();
        info2.connection_id = 0;
        h.handler.on_ws_data(h.handler.sbe_state_[0], 0, b.data(),
                             static_cast<uint32_t>(b.size()), info2);
        h.handler.sbe_state_[0].reset();
    }
    h.idle();

    auto events_final = h.published();
    int final_entries = sbe_count_delta_entries(events_final);
    assert(final_entries == entries_after_conn1);
}

// Test: conn0 finishes, conn1 arrives → immediate discard
void test_sbe_interleave_finished_fast_path() {
    TestHarness h;

    int64_t bp[] = {50000, 49000}, bq[] = {1000, 2000};
    int64_t ap[] = {50100, 51000}, aq[] = {1500, 2500};
    auto b = build_depth_diff_msg(1000000, 500, 505, -8, -8,
                                   2, bp, bq, 2, ap, aq, "BTCUSDT");

    // conn0: complete
    h.feed_frame(0, b);
    h.idle();

    auto events0 = h.published();
    int entries0 = sbe_count_delta_entries(events0);
    assert(entries0 == 4);

    // conn1: same seq → deduped immediately
    h.feed_frame(1, b);
    h.idle();

    auto events1 = h.published();
    assert(sbe_count_delta_entries(events1) == entries0);
}

// Test: consecutive depth diffs with different sequences should reset flush_index
void test_sbe_consecutive_depth_diff_seq_change_resets_flush_index() {
    TestHarness h;

    // Build large depth diff: 15 bids + 10 asks = 25 entries (> MAX_DELTAS=20)
    // seq A (last_id=200)
    int64_t bp_a[15], bq_a[15], ap_a[10], aq_a[10];
    for (int i = 0; i < 15; i++) { bp_a[i] = 50000 + i * 100; bq_a[i] = 1000 + i; }
    for (int i = 0; i < 10; i++) { ap_a[i] = 60000 + i * 100; aq_a[i] = 2000 + i; }
    auto b_a = build_depth_diff_msg(1000000, 190, 200, -8, -8,
                                     15, bp_a, bq_a, 10, ap_a, aq_a, "BTCUSDT");

    // Build smaller depth diff: 3 bids + 2 asks = 5 entries
    // seq B (last_id=300)
    int64_t bp_b[] = {80000, 79000, 78000}, bq_b[] = {500, 600, 700};
    int64_t ap_b[] = {81000, 82000}, aq_b[] = {800, 900};
    auto b_b = build_depth_diff_msg(2000000, 290, 300, -8, -8,
                                     3, bp_b, bq_b, 2, ap_b, aq_b, "BTCUSDT");

    // Feed both without idle() between them
    h.feed_frame(0, b_a);
    h.feed_frame(0, b_b);
    h.idle();

    auto events = h.published();

    // Collect flush_indices per seq
    std::vector<uint8_t> fi_a, fi_b;
    for (auto& e : events) {
        if (!e.is_book_delta()) continue;
        if (e.src_seq == 200) fi_a.push_back(e.flush_index());
        if (e.src_seq == 300) fi_b.push_back(e.flush_index());
    }

    // seq A should have multiple flushes starting from 0
    assert(fi_a.size() >= 2);
    assert(fi_a[0] == 0);
    for (size_t i = 1; i < fi_a.size(); i++)
        assert(fi_a[i] == i);

    // seq B MUST start from flush_index 0
    assert(!fi_b.empty());
    assert(fi_b[0] == 0);
    for (size_t i = 1; i < fi_b.size(); i++)
        assert(fi_b[i] == i);
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

    std::printf("\n--- Streaming fragment parsing ---\n");
    RUN_TEST(test_fragment_trades_20kb);
    cleanup_ring_files();

    RUN_TEST(test_fragment_depth_snapshot_20kb);
    cleanup_ring_files();

    RUN_TEST(test_fragment_too_small);
    cleanup_ring_files();

    RUN_TEST(test_streaming_incremental_trades);
    cleanup_ring_files();

    RUN_TEST(test_streaming_depth_diff);
    cleanup_ring_files();

    RUN_TEST(test_state_reset_on_disconnect);
    cleanup_ring_files();

    std::printf("\n--- Display fix regression ---\n");
    RUN_TEST(test_done_state_repopulates_info);
    cleanup_ring_files();

    RUN_TEST(test_stale_depth_diff_preserves_type);
    cleanup_ring_files();

    RUN_TEST(test_print_timeline_book_delta_no_hex_dump);

    RUN_TEST(test_print_timeline_fragment_suffix_book_delta);

    std::printf("\n--- Non-merge + regression ---\n");
    RUN_TEST(test_non_merge_trades_batched);
    cleanup_ring_files();

    RUN_TEST(test_stale_trade_via_fragment);
    cleanup_ring_files();

    std::printf("\n--- Depth overflow + stale ---\n");
    RUN_TEST(test_depth_delta_overflow);
    cleanup_ring_files();

    RUN_TEST(test_stale_bbo_preserves_type);
    cleanup_ring_files();

    std::printf("\n--- Display + content ---\n");
    RUN_TEST(test_print_timeline_fresh_book_delta_is_mkt);

    RUN_TEST(test_depth_snapshot_streaming_publish_content);
    cleanup_ring_files();

    RUN_TEST(test_cross_type_flush_trades_then_depth);
    cleanup_ring_files();

    std::printf("\n--- Fragment trade dedup ---\n");
    RUN_TEST(test_fragment_stale_trade_first_entry_dedup);
    cleanup_ring_files();

    RUN_TEST(test_fragment_fresh_trade_not_falsely_discarded);
    cleanup_ring_files();

    RUN_TEST(test_fragment_stale_trade_multi_conn);
    cleanup_ring_files();

    RUN_TEST(test_fragment_stale_trade_merge_mode);
    cleanup_ring_files();

    RUN_TEST(test_full_message_stale_via_first_entry);
    cleanup_ring_files();

    std::printf("\n--- Cross-connection monotonic ordering ---\n");
    RUN_TEST(test_cross_conn_merge_flush_before_mix);
    cleanup_ring_files();

    RUN_TEST(test_fragment_interleave_stale_resumption);
    cleanup_ring_files();

    RUN_TEST(test_fragment_interleave_non_merge);
    cleanup_ring_files();

    RUN_TEST(test_cross_conn_pending_ci_attribution);
    cleanup_ring_files();

    RUN_TEST(test_header_only_fragment_stale_on_resume);
    cleanup_ring_files();

    RUN_TEST(test_pending_max_id_monotonic);
    cleanup_ring_files();

    std::printf("\n--- Streaming depth dedup ---\n");
    RUN_TEST(test_fragment_depth_superseded_by_other_conn);
    cleanup_ring_files();

    RUN_TEST(test_fragment_depth_deduped_done_propagates_discard);
    cleanup_ring_files();

    std::printf("\n--- Fragment depth flush at boundary ---\n");
    RUN_TEST(test_fragment_depth_flush_at_boundary);
    cleanup_ring_files();

    std::printf("\n--- print_timeline column alignment ---\n");
    RUN_TEST(test_print_timeline_column_alignment);

    std::printf("\n--- Deferred depth merge ---\n");
    RUN_TEST(test_cross_frame_depth_merge_within_batch);
    cleanup_ring_files();

    RUN_TEST(test_cross_type_depth_then_trades);
    cleanup_ring_files();

    std::printf("\n--- Same-SEQ interleave ---\n");
    RUN_TEST(test_sbe_interleave_basic);
    cleanup_ring_files();

    RUN_TEST(test_sbe_interleave_conn1_faster);
    cleanup_ring_files();

    RUN_TEST(test_sbe_interleave_finished_fast_path);
    cleanup_ring_files();

    RUN_TEST(test_sbe_consecutive_depth_diff_seq_change_resets_flush_index);
    cleanup_ring_files();

    std::printf("\n=== %d/%d tests passed ===\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}
