// test/unittest/test_mkt_event_bitfields.cpp
// Unit tests for MktEvent bitfield packing: event_type, depth_channel,
// connection_id, venue_instrument, flags — all packed into 32-bit header.

#include <cassert>
#include <cstdio>
#include <cstring>

#include "msg/mkt_event.hpp"

using namespace websocket::msg;

// ============================================================================
// Minimal test framework (same as test_orderbook.cpp)
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

// ============================================================================
// Test 1: event_type survives flag |=
// ============================================================================

static void test_event_type_survives_flags() {
    TEST("event_type survives flag |=");

    MktEvent e;
    e.clear();
    e.set_event_type(static_cast<uint8_t>(EventType::BOOK_SNAPSHOT));
    e.flags |= EventFlags::SNAPSHOT | EventFlags::CONTINUATION | EventFlags::LAST_IN_BATCH;

    assert(e.event_type() == static_cast<uint8_t>(EventType::BOOK_SNAPSHOT));
    assert(e.is_book_snapshot());
    assert(e.is_snapshot());
    assert(e.is_continuation());
    assert(e.is_last_in_batch());

    PASS();
}

// ============================================================================
// Test 2: All EventType values roundtrip
// ============================================================================

static void test_event_type_roundtrip() {
    TEST("all EventType values roundtrip");

    for (uint8_t v = 0; v <= 6; v++) {
        MktEvent e;
        e.clear();
        e.set_event_type(v);
        assert(e.event_type() == v);
    }

    PASS();
}

// ============================================================================
// Test 3: depth_channel doesn't corrupt event_type
// ============================================================================

static void test_depth_channel_independent() {
    TEST("depth_channel doesn't corrupt event_type");

    MktEvent e;
    e.clear();
    e.set_event_type(static_cast<uint8_t>(EventType::BOOK_SNAPSHOT));
    e.set_depth_channel(5);

    assert(e.event_type() == static_cast<uint8_t>(EventType::BOOK_SNAPSHOT));
    assert(e.depth_channel() == 5);

    PASS();
}

// ============================================================================
// Test 4: connection_id doesn't corrupt event_type or depth_channel
// ============================================================================

static void test_connection_id_independent() {
    TEST("connection_id doesn't corrupt other fields");

    MktEvent e;
    e.clear();
    e.set_event_type(static_cast<uint8_t>(EventType::TRADE_ARRAY));
    e.set_depth_channel(7);
    e.set_connection_id(42);

    assert(e.event_type() == static_cast<uint8_t>(EventType::TRADE_ARRAY));
    assert(e.depth_channel() == 7);
    assert(e.connection_id() == 42);

    PASS();
}

// ============================================================================
// Test 5: venue_instrument packing roundtrip
// ============================================================================

static void test_venue_instrument_packing() {
    TEST("venue_instrument packing roundtrip");

    MktEvent e;
    e.clear();
    e.set_venue_id(15);          // 4-bit max
    e.set_instrument_id(4095);   // 12-bit max

    assert(e.venue_id() == 15);
    assert(e.instrument_id() == 4095);

    // Verify independence
    e.set_venue_id(1);
    assert(e.instrument_id() == 4095);
    e.set_instrument_id(0);
    assert(e.venue_id() == 1);

    PASS();
}

// ============================================================================
// Test 6: all flags fields independent (set every bitfield to max)
// ============================================================================

static void test_all_fields_independent() {
    TEST("all bitfields independent at max values");

    MktEvent e;
    e.clear();

    // Set all packed fields to max values
    e.flags |= EventFlags::SNAPSHOT | EventFlags::CONTINUATION | EventFlags::LAST_IN_BATCH;
    e.set_depth_channel(7);        // 3-bit max
    e.set_event_type(7);           // 3-bit max
    e.set_connection_id(127);      // 7-bit max
    e.set_venue_id(15);            // 4-bit max
    e.set_instrument_id(4095);     // 12-bit max

    // Verify all read back correctly
    assert(e.is_snapshot());
    assert(e.is_continuation());
    assert(e.is_last_in_batch());
    assert(e.depth_channel() == 7);
    assert(e.event_type() == 7);
    assert(e.connection_id() == 127);
    assert(e.venue_id() == 15);
    assert(e.instrument_id() == 4095);

    // All 16 bits of flags should be set
    assert(e.flags == 0xFFFF);

    PASS();
}

// ============================================================================
// Test 7: clear() zeroes everything
// ============================================================================

static void test_clear_zeroes_all() {
    TEST("clear() zeroes everything");

    MktEvent e;
    e.clear();

    // Set everything non-zero
    e.flags |= EventFlags::SNAPSHOT | EventFlags::CONTINUATION | EventFlags::LAST_IN_BATCH;
    e.set_depth_channel(3);
    e.set_event_type(static_cast<uint8_t>(EventType::MARK_PRICE));
    e.set_connection_id(10);
    e.set_venue_id(3);
    e.set_instrument_id(100);
    e.count = 5;
    e.count2 = 3;
    e.src_seq = 12345;
    e.nic_ts_ns = 1000;
    e.recv_local_latency_ns = 500;
    e.event_ts_ns = 99999;

    e.clear();

    assert(e.flags == 0);
    assert(e.venue_instrument == 0);
    assert(e.event_type() == 0);
    assert(e.depth_channel() == 0);
    assert(e.connection_id() == 0);
    assert(e.venue_id() == 0);
    assert(e.instrument_id() == 0);
    assert(e.count == 0);
    assert(e.count2 == 0);
    assert(e.src_seq == 0);
    assert(e.nic_ts_ns == 0);
    assert(e.recv_local_latency_ns == 0);
    assert(e.event_ts_ns == 0);

    PASS();
}

// ============================================================================
// Test 8: recv_ts_ns() reconstruction
// ============================================================================

static void test_recv_ts_ns_reconstruction() {
    TEST("recv_ts_ns() = nic_ts_ns + recv_local_latency_ns");

    MktEvent e;
    e.clear();
    e.nic_ts_ns = 1000;
    e.recv_local_latency_ns = 500;

    assert(e.recv_ts_ns() == 1500);

    // Edge: zero latency
    e.recv_local_latency_ns = 0;
    assert(e.recv_ts_ns() == 1000);

    // Edge: max latency (uint16_t)
    e.recv_local_latency_ns = 65535;
    assert(e.recv_ts_ns() == 1000 + 65535);

    PASS();
}

// ============================================================================
// main
// ============================================================================

int main() {
    std::fprintf(stderr, "\n=== MktEvent Bitfield Unit Tests ===\n\n");

    test_event_type_survives_flags();
    test_event_type_roundtrip();
    test_depth_channel_independent();
    test_connection_id_independent();
    test_venue_instrument_packing();
    test_all_fields_independent();
    test_clear_zeroes_all();
    test_recv_ts_ns_reconstruction();

    std::fprintf(stderr, "\n  %d/%d tests passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
