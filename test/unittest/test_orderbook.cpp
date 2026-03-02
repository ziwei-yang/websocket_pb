// test/unittest/test_orderbook.cpp
// Unit tests for OrderBook snapshot/delta/BBO reconciliation logic.
// No network, no IPC — pure header-only struct logic.

#include <cassert>
#include <cstdio>
#include <cstring>

#include "msg/mkt_event.hpp"
#include "msg/orderbook.hpp"

using namespace websocket::msg;

// ============================================================================
// Helpers — build MktEvent for each type
// ============================================================================

static MktEvent make_snapshot(int64_t seq,
                              const BookLevel* bids, uint8_t bid_n,
                              const BookLevel* asks, uint8_t ask_n) {
    MktEvent e;
    e.clear();
    e.event_type = static_cast<uint8_t>(EventType::BOOK_SNAPSHOT);
    e.flags = EventFlags::SNAPSHOT;
    e.src_seq = seq;
    e.count = bid_n;
    e.count2 = ask_n;
    for (uint8_t i = 0; i < bid_n; i++)
        e.payload.snapshot.levels[i] = bids[i];
    for (uint8_t i = 0; i < ask_n; i++)
        e.payload.snapshot.levels[bid_n + i] = asks[i];
    return e;
}

static MktEvent make_deltas(int64_t seq,
                            const DeltaEntry* deltas, uint8_t count) {
    MktEvent e;
    e.clear();
    e.event_type = static_cast<uint8_t>(EventType::BOOK_DELTA);
    e.src_seq = seq;
    e.count = count;
    std::memcpy(e.payload.deltas.entries, deltas, count * sizeof(DeltaEntry));
    return e;
}

static MktEvent make_bbo(int64_t book_update_id,
                         int64_t bid_price, int64_t bid_qty,
                         int64_t ask_price, int64_t ask_qty) {
    MktEvent e;
    e.clear();
    e.event_type = static_cast<uint8_t>(EventType::BBO_ARRAY);
    e.count = 1;
    auto& be = e.payload.bbo_array.entries[0];
    be.bid_price = bid_price;
    be.bid_qty = bid_qty;
    be.ask_price = ask_price;
    be.ask_qty = ask_qty;
    be.book_update_id = book_update_id;
    return e;
}

static DeltaEntry bid_delta(int64_t price, int64_t qty) {
    DeltaEntry d{};
    d.price = price;
    d.qty = qty;
    d.action = (qty == 0) ? static_cast<uint8_t>(DeltaAction::DELETE)
                          : static_cast<uint8_t>(DeltaAction::UPDATE);
    d.flags = 0;  // bid
    return d;
}

static DeltaEntry ask_delta(int64_t price, int64_t qty) {
    DeltaEntry d{};
    d.price = price;
    d.qty = qty;
    d.action = (qty == 0) ? static_cast<uint8_t>(DeltaAction::DELETE)
                          : static_cast<uint8_t>(DeltaAction::UPDATE);
    d.flags = DeltaFlags::SIDE_ASK;
    return d;
}

// ============================================================================
// Tests
// ============================================================================

static int tests_run = 0, tests_passed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        std::fprintf(stderr, "  [%d] %-55s", tests_run, name); \
    } while(0)

#define PASS() \
    do { \
        tests_passed++; \
        std::fprintf(stderr, " \033[32mPASS\033[0m\n"); \
    } while(0)

// --- Test 1: apply_snapshot sets book correctly ---
static void test_snapshot_basic() {
    TEST("apply_snapshot sets book correctly");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50}, {9900, 30}, {9800, 20} };
    BookLevel asks[] = { {10100, 40}, {10200, 25} };
    auto evt = make_snapshot(100, bids, 3, asks, 2);
    ob.apply_snapshot(evt);

    assert(ob.bid_count == 3);
    assert(ob.ask_count == 2);
    assert(ob.bids[0].price == 10000 && ob.bids[0].qty == 50);
    assert(ob.bids[1].price == 9900  && ob.bids[1].qty == 30);
    assert(ob.bids[2].price == 9800  && ob.bids[2].qty == 20);
    assert(ob.asks[0].price == 10100 && ob.asks[0].qty == 40);
    assert(ob.asks[1].price == 10200 && ob.asks[1].qty == 25);
    assert(ob.book_seq == 100);
    PASS();
}

// --- Test 2: apply_deltas updates book ---
static void test_deltas_update() {
    TEST("apply_deltas updates book");

    OrderBook ob{};
    // Start with a snapshot
    BookLevel bids[] = { {10000, 50}, {9900, 30} };
    BookLevel asks[] = { {10100, 40}, {10200, 25} };
    ob.apply_snapshot(make_snapshot(100, bids, 2, asks, 2));

    // Insert new bid level at 9950 (between 10000 and 9900)
    DeltaEntry deltas[] = {
        bid_delta(9950, 15),    // insert
        bid_delta(10000, 60),   // update qty
        ask_delta(10100, 0),    // delete
        ask_delta(10300, 10),   // insert
    };
    ob.apply_deltas(make_deltas(101, deltas, 4));

    // Bids: 10000(60), 9950(15), 9900(30) — sorted desc
    assert(ob.bid_count == 3);
    assert(ob.bids[0].price == 10000 && ob.bids[0].qty == 60);
    assert(ob.bids[1].price == 9950  && ob.bids[1].qty == 15);
    assert(ob.bids[2].price == 9900  && ob.bids[2].qty == 30);

    // Asks: 10200(25), 10300(10) — 10100 deleted, sorted asc
    assert(ob.ask_count == 2);
    assert(ob.asks[0].price == 10200 && ob.asks[0].qty == 25);
    assert(ob.asks[1].price == 10300 && ob.asks[1].qty == 10);

    assert(ob.book_seq == 101);
    PASS();
}

// --- Test 3: apply_bbo with newer seq updates top-of-book ---
static void test_bbo_newer_seq() {
    TEST("apply_bbo with newer seq updates top-of-book");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50} };
    BookLevel asks[] = { {10100, 40} };
    ob.apply_snapshot(make_snapshot(100, bids, 1, asks, 1));

    // BBO with seq > book_seq
    auto bbo = make_bbo(105, 10050, 20, 10080, 35);
    ob.apply_bbo(bbo);

    assert(ob.bbo_seq == 105);
    // Top-of-book should be updated by reconcile_bbo
    assert(ob.bids[0].price == 10050);
    assert(ob.bids[0].qty == 20);
    assert(ob.asks[0].price == 10080);
    assert(ob.asks[0].qty == 35);
    PASS();
}

// --- Test 4: apply_bbo with stale seq is rejected ---
static void test_bbo_stale_rejected() {
    TEST("apply_bbo with stale seq is rejected");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50} };
    BookLevel asks[] = { {10100, 40} };
    ob.apply_snapshot(make_snapshot(100, bids, 1, asks, 1));

    // BBO with seq <= book_seq → rejected
    auto bbo = make_bbo(99, 9999, 99, 10101, 99);
    ob.apply_bbo(bbo);

    assert(ob.bbo_seq == 0);  // unchanged
    assert(ob.bids[0].price == 10000);  // unchanged
    assert(ob.asks[0].price == 10100);  // unchanged
    PASS();
}

// --- Test 5: apply_bbo with duplicate seq is rejected ---
static void test_bbo_duplicate_rejected() {
    TEST("apply_bbo with duplicate seq is rejected");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50} };
    BookLevel asks[] = { {10100, 40} };
    ob.apply_snapshot(make_snapshot(100, bids, 1, asks, 1));

    // First BBO accepted
    ob.apply_bbo(make_bbo(105, 10050, 20, 10080, 35));
    assert(ob.bbo_seq == 105);

    // Second BBO with same seq → rejected
    ob.apply_bbo(make_bbo(105, 9999, 99, 10101, 99));
    assert(ob.bbo_bid_price == 10050);  // unchanged
    assert(ob.bbo_ask_price == 10080);  // unchanged
    PASS();
}

// --- Test 6: snapshot then BBO reconcile ---
static void test_snapshot_then_bbo() {
    TEST("snapshot then BBO reconcile");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50}, {9900, 30} };
    BookLevel asks[] = { {10100, 40}, {10200, 25} };
    ob.apply_snapshot(make_snapshot(100, bids, 2, asks, 2));

    // BBO with higher seq → accepted, top-of-book updated
    ob.apply_bbo(make_bbo(105, 10010, 22, 10090, 33));
    assert(ob.bbo_seq == 105);
    assert(ob.bids[0].price == 10010);
    assert(ob.bids[0].qty == 22);
    assert(ob.asks[0].price == 10090);
    assert(ob.asks[0].qty == 33);

    // Stale BBO → rejected
    ob.apply_bbo(make_bbo(99, 9999, 1, 10999, 1));
    assert(ob.bbo_seq == 105);  // unchanged
    PASS();
}

// --- Test 7: BBO then snapshot overrides ---
static void test_bbo_then_snapshot() {
    TEST("BBO then snapshot overrides");

    OrderBook ob{};
    // BBO first (no book yet)
    ob.apply_bbo(make_bbo(50, 10000, 50, 10100, 40));
    assert(ob.bbo_seq == 50);
    assert(ob.bid_count == 1);  // reconcile_bbo sets up 1 level from BBO

    // Snapshot with higher seq → book fully replaced
    BookLevel bids[] = { {10050, 60}, {9950, 30} };
    BookLevel asks[] = { {10150, 45}, {10250, 20} };
    ob.apply_snapshot(make_snapshot(100, bids, 2, asks, 2));

    assert(ob.book_seq == 100);
    assert(ob.bid_count == 2);
    assert(ob.ask_count == 2);
    // BBO (seq=50) is now stale (50 <= 100), reconcile_bbo does nothing
    assert(ob.bids[0].price == 10050);
    assert(ob.asks[0].price == 10150);
    PASS();
}

// --- Test 8: deltas then BBO reconcile ---
static void test_deltas_then_bbo() {
    TEST("deltas then BBO reconcile");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50} };
    BookLevel asks[] = { {10100, 40} };
    ob.apply_snapshot(make_snapshot(100, bids, 1, asks, 1));

    // Delta advancing book_seq
    DeltaEntry deltas[] = { bid_delta(9900, 25) };
    ob.apply_deltas(make_deltas(102, deltas, 1));
    assert(ob.book_seq == 102);
    assert(ob.bid_count == 2);

    // BBO with higher seq → top-of-book updated
    ob.apply_bbo(make_bbo(110, 10020, 15, 10080, 30));
    assert(ob.bbo_seq == 110);
    assert(ob.bids[0].price == 10020);
    assert(ob.asks[0].price == 10080);
    PASS();
}

// --- Test 9: snapshot reapplies latest BBO ---
static void test_snapshot_reapplies_bbo() {
    TEST("snapshot reapplies latest BBO");

    OrderBook ob{};
    // BBO arrives first with high seq
    ob.apply_bbo(make_bbo(200, 10500, 70, 10600, 55));
    assert(ob.bbo_seq == 200);

    // Snapshot with lower seq — reconcile_bbo should apply BBO (200 > 100)
    BookLevel bids[] = { {10400, 60}, {10300, 30} };
    BookLevel asks[] = { {10700, 45}, {10800, 20} };
    ob.apply_snapshot(make_snapshot(100, bids, 2, asks, 2));

    assert(ob.book_seq == 100);
    // BBO (200) > book_seq (100), so reconcile_bbo inserts BBO at top
    assert(ob.bids[0].price == 10500);
    assert(ob.bids[0].qty == 70);
    assert(ob.asks[0].price == 10600);
    assert(ob.asks[0].qty == 55);
    PASS();
}

// --- Test 10: apply() dispatches snapshot correctly ---
static void test_apply_snapshot() {
    TEST("apply() dispatches snapshot correctly");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50}, {9900, 30} };
    BookLevel asks[] = { {10100, 40} };
    auto evt = make_snapshot(100, bids, 2, asks, 1);
    bool modified = ob.apply(evt);

    assert(modified == true);
    assert(ob.bid_count == 2);
    assert(ob.ask_count == 1);
    assert(ob.book_seq == 100);
    assert(ob.bids[0].price == 10000);
    PASS();
}

// --- Test 11: apply() dispatches deltas correctly ---
static void test_apply_deltas() {
    TEST("apply() dispatches deltas correctly");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50} };
    BookLevel asks[] = { {10100, 40} };
    ob.apply_snapshot(make_snapshot(100, bids, 1, asks, 1));

    DeltaEntry deltas[] = { bid_delta(9900, 25) };
    bool modified = ob.apply(make_deltas(101, deltas, 1));

    assert(modified == true);
    assert(ob.bid_count == 2);
    assert(ob.book_seq == 101);
    PASS();
}

// --- Test 12: apply() dispatches BBO correctly (accept and reject) ---
static void test_apply_bbo() {
    TEST("apply() dispatches BBO (accept/reject)");

    OrderBook ob{};
    BookLevel bids[] = { {10000, 50} };
    BookLevel asks[] = { {10100, 40} };
    ob.apply_snapshot(make_snapshot(100, bids, 1, asks, 1));

    // Accepted: seq > book_seq
    bool accepted = ob.apply(make_bbo(105, 10050, 20, 10080, 35));
    assert(accepted == true);
    assert(ob.bbo_seq == 105);

    // Rejected: stale seq
    bool rejected = ob.apply(make_bbo(99, 9999, 1, 10999, 1));
    assert(rejected == false);
    assert(ob.bbo_seq == 105);  // unchanged
    PASS();
}

// --- Test 13: apply() returns false for non-book events ---
static void test_apply_non_book() {
    TEST("apply() returns false for non-book events");

    OrderBook ob{};
    // Trade event
    MktEvent trade;
    trade.clear();
    trade.event_type = static_cast<uint8_t>(EventType::TRADE_ARRAY);
    trade.count = 1;
    assert(ob.apply(trade) == false);

    // System status event
    MktEvent status;
    status.clear();
    status.event_type = static_cast<uint8_t>(EventType::SYSTEM_STATUS);
    assert(ob.apply(status) == false);

    // Book should be untouched
    assert(ob.bid_count == 0);
    assert(ob.ask_count == 0);
    assert(ob.book_seq == 0);
    PASS();
}

// --- Test 14: book_depth() returns max(bid_count, ask_count) ---
static void test_book_depth() {
    TEST("book_depth() returns max(bid_count, ask_count)");

    OrderBook ob{};
    assert(ob.book_depth() == 0);

    BookLevel bids[] = { {10000, 50}, {9900, 30}, {9800, 20} };
    BookLevel asks[] = { {10100, 40} };
    ob.apply_snapshot(make_snapshot(100, bids, 3, asks, 1));
    assert(ob.book_depth() == 3);  // max(3, 1)

    BookLevel bids2[] = { {10000, 50} };
    BookLevel asks2[] = { {10100, 40}, {10200, 25}, {10300, 10}, {10400, 5} };
    ob.apply_snapshot(make_snapshot(101, bids2, 1, asks2, 4));
    assert(ob.book_depth() == 4);  // max(1, 4)
    PASS();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::fprintf(stderr, "\n=== OrderBook Unit Tests ===\n\n");

    test_snapshot_basic();
    test_deltas_update();
    test_bbo_newer_seq();
    test_bbo_stale_rejected();
    test_bbo_duplicate_rejected();
    test_snapshot_then_bbo();
    test_bbo_then_snapshot();
    test_deltas_then_bbo();
    test_snapshot_reapplies_bbo();
    test_apply_snapshot();
    test_apply_deltas();
    test_apply_bbo();
    test_apply_non_book();
    test_book_depth();

    std::fprintf(stderr, "\n  %d/%d tests passed\n\n", tests_passed, tests_run);
    if (tests_passed != tests_run) {
        std::fprintf(stderr, "FAILED\n");
        return 1;
    }
    std::fprintf(stderr, "ALL TESTS PASSED\n\n");
    return 0;
}
