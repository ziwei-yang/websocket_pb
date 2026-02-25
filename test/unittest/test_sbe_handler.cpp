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
    uint8_t buf[8192];
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
        info.set_connection_id(ci);
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

    void batch_end() {
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
    bool bm[256];  // fixed-size bool array (vector<bool> has no .data())
    uint32_t count_;

    TradeSet(int64_t start_id, uint32_t count) : count_(count) {
        assert(count <= 256);
        for (uint32_t i = 0; i < count; i++) {
            ids.push_back(start_id + i);
            prices.push_back(5000000 + i * 100);
            qtys.push_back(10000 + i);
            bm[i] = (i % 2 == 0);
        }
    }

    SBEBuilder build(int64_t event_time = 1000000, int64_t transact_time = 1000001) const {
        return build_trades_msg(event_time, transact_time, -8, -8,
                                count_, ids.data(), prices.data(), qtys.data(),
                                bm, "BTCUSDT");
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
    h.batch_end();
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
    h.batch_end();
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
    h.batch_end();
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
    h.batch_end();
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
    h.batch_end();
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
    h.batch_end();
    assert(h.ring_info(0).is_merged() == true);   // frame 1: stays M
    assert(h.ring_info(1).is_merged() == true);   // frame 2: stays M
    assert(h.ring_info(2).is_merged() == false);  // frame 3: winning frame, cleared
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

    std::printf("\n=== %d/%d tests passed ===\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}
