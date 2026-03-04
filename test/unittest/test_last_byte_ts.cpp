// test/unittest/test_last_byte_ts.cpp
// Unit test: Reproduce last_byte_ts=0 bug from partially-consumed recv_buffer frames
//
// Bug: process_ssl_read_for_conn() gates hw_timestamp reads on packet_count > 0.
// But ZeroCopyReceiveBuffer::read() only increments packet_count at first touch
// (frame.offset == 0), while timestamps are always reported. When a second SSL
// read consumes the remainder of a partially-read frame, packet_count=0 but
// latest_timestamp_ns is valid. The if/else gate zeros out the valid timestamp.

#include "../../src/stack/tcp/tcp_retransmit.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

using namespace userspace_stack;

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout);

#define PASS() \
    printf("PASS\n"); \
    tests_passed++;

#define FAIL(msg) \
    printf("FAIL: %s\n", msg); \
    tests_failed++;

// Simulated UMEM data (two packets)
static uint8_t pkt_a_data[100];
static uint8_t pkt_b_data[200];

// =============================================================================
// Test 1: First read consumes frame A + part of frame B — packet_count=2
// =============================================================================
void test_first_read_full_and_partial() {
    TEST("first read consumes frameA + partial frameB — packet_count=2, timestamps valid");

    memset(pkt_a_data, 'A', sizeof(pkt_a_data));
    memset(pkt_b_data, 'B', sizeof(pkt_b_data));

    ZeroCopyReceiveBuffer buf;
    // Push frame A: 100 bytes, hw_ts=1000, bpf=2000, poll=3000
    buf.push_frame(pkt_a_data, 100, /*frame_idx=*/0, /*umem_addr=*/0,
                   /*hw_timestamp_ns=*/1000, /*bpf_entry_ns=*/2000, /*poll_cycle=*/3000);
    // Push frame B: 200 bytes, hw_ts=4000, bpf=5000, poll=6000
    buf.push_frame(pkt_b_data, 200, /*frame_idx=*/1, /*umem_addr=*/0,
                   /*hw_timestamp_ns=*/4000, /*bpf_entry_ns=*/5000, /*poll_cycle=*/6000);

    // Read 150 bytes: all of A (100) + first 50 of B (200)
    uint8_t out[300];
    ssize_t n = buf.read(out, 150);
    const auto& stats = buf.get_last_read_stats();

    if (n != 150) { FAIL("read returned wrong byte count"); return; }
    if (stats.packet_count != 2) {
        printf("(packet_count=%u, expected 2) ", stats.packet_count);
        FAIL("packet_count should be 2 (both frames touched at offset=0)");
        return;
    }
    if (stats.oldest_timestamp_ns != 1000) { FAIL("oldest_timestamp_ns wrong"); return; }
    if (stats.latest_timestamp_ns != 4000) { FAIL("latest_timestamp_ns wrong"); return; }
    if (stats.oldest_bpf_entry_ns != 2000) { FAIL("oldest_bpf_entry_ns wrong"); return; }
    if (stats.latest_bpf_entry_ns != 5000) { FAIL("latest_bpf_entry_ns wrong"); return; }

    PASS();
}

// =============================================================================
// Test 2: Second read consumes rest of frame B — packet_count=0 but timestamps valid
// =============================================================================
void test_second_read_partial_frame_timestamps() {
    TEST("second read of partial frameB — packet_count=0, timestamps still valid");

    memset(pkt_a_data, 'A', sizeof(pkt_a_data));
    memset(pkt_b_data, 'B', sizeof(pkt_b_data));

    ZeroCopyReceiveBuffer buf;
    buf.push_frame(pkt_a_data, 100, 0, 0, 1000, 2000, 3000);
    buf.push_frame(pkt_b_data, 200, 1, 0, 4000, 5000, 6000);

    // First read: consume A + partial B
    uint8_t out[300];
    buf.read(out, 150);

    // Second read: consume remaining 150 bytes of B (200 - 50 consumed in first read)
    ssize_t n = buf.read(out, 300);
    const auto& stats = buf.get_last_read_stats();

    if (n != 150) {
        printf("(got %zd, expected 150) ", n);
        FAIL("read returned wrong byte count");
        return;
    }

    // KEY ASSERTION: packet_count is 0 (frame B at offset > 0)
    if (stats.packet_count != 0) {
        printf("(packet_count=%u, expected 0) ", stats.packet_count);
        FAIL("packet_count should be 0 for offset>0 frame");
        return;
    }

    // BUT timestamps must still be valid (this is the root cause of the bug)
    if (stats.latest_timestamp_ns != 4000) {
        printf("(latest_timestamp_ns=%lu, expected 4000) ", stats.latest_timestamp_ns);
        FAIL("latest_timestamp_ns should be 4000 even with offset>0");
        return;
    }
    if (stats.oldest_timestamp_ns != 4000) {
        printf("(oldest_timestamp_ns=%lu, expected 4000) ", stats.oldest_timestamp_ns);
        FAIL("oldest_timestamp_ns should be 4000 for single partial frame");
        return;
    }
    if (stats.latest_bpf_entry_ns != 5000) {
        FAIL("latest_bpf_entry_ns should be 5000 even with offset>0");
        return;
    }
    if (stats.latest_poll_cycle != 6000) {
        FAIL("latest_poll_cycle should be 6000 even with offset>0");
        return;
    }

    PASS();
}

// =============================================================================
// Test 3: Simulate old (buggy) vs new (fixed) gating logic
// =============================================================================
void test_gating_logic_comparison() {
    TEST("old gated logic zeros timestamps, new unconditional logic preserves them");

    memset(pkt_a_data, 'A', sizeof(pkt_a_data));
    memset(pkt_b_data, 'B', sizeof(pkt_b_data));

    ZeroCopyReceiveBuffer buf;
    buf.push_frame(pkt_a_data, 100, 0, 0, 1000, 2000, 3000);
    buf.push_frame(pkt_b_data, 200, 1, 0, 4000, 5000, 6000);

    uint8_t out[300];
    // First read: consume all of A + partial B
    buf.read(out, 150);
    // Second read: consume rest of B (simulating after reset_recv_stats)
    buf.read(out, 300);
    const auto& stats = buf.get_last_read_stats();

    uint32_t packet_count = stats.packet_count;   // will be 0
    uint64_t oldest_ts = stats.oldest_timestamp_ns;
    uint64_t latest_ts = stats.latest_timestamp_ns;

    // OLD (buggy) logic:
    uint64_t old_latest = 0;
    if (packet_count > 0) {
        old_latest = latest_ts;
    } else {
        old_latest = 0;  // BUG: discards valid timestamp
    }

    // NEW (fixed) logic:
    uint64_t new_oldest = oldest_ts;
    uint64_t new_latest = latest_ts;

    // Verify old logic produces the bug
    if (old_latest != 0) {
        FAIL("old logic should produce latest=0 (that's the bug)");
        return;
    }

    // Verify new logic preserves the timestamp
    if (new_latest != 4000) {
        printf("(new_latest=%lu, expected 4000) ", new_latest);
        FAIL("new logic should preserve latest_timestamp=4000");
        return;
    }
    if (new_oldest != 4000) {
        printf("(new_oldest=%lu, expected 4000) ", new_oldest);
        FAIL("new logic should preserve oldest_timestamp=4000");
        return;
    }

    PASS();
}

// =============================================================================
// Test 4: Metadata propagation — latest_nic_timestamp_ns must be non-zero
// =============================================================================
void test_metadata_propagation() {
    TEST("metadata latest_nic_timestamp_ns is non-zero when packet_count=0");

    memset(pkt_a_data, 'A', sizeof(pkt_a_data));
    memset(pkt_b_data, 'B', sizeof(pkt_b_data));

    ZeroCopyReceiveBuffer buf;
    buf.push_frame(pkt_a_data, 100, 0, 0, 1000, 2000, 3000);
    buf.push_frame(pkt_b_data, 200, 1, 0, 4000, 5000, 6000);

    uint8_t out[300];
    buf.read(out, 150);  // First read: full A + partial B
    buf.read(out, 300);  // Second read: rest of B
    const auto& stats = buf.get_last_read_stats();

    // Simulate what process_ssl_read_for_conn does with the FIXED code:
    // (no if/else gate — always read timestamps)
    uint32_t hw_timestamp_count = stats.packet_count;
    uint64_t hw_timestamp_oldest_ns = stats.oldest_timestamp_ns;
    uint64_t hw_timestamp_latest_ns = stats.latest_timestamp_ns;

    // Simulate MsgMetadata population
    struct TestMeta {
        uint64_t first_nic_timestamp_ns;
        uint64_t latest_nic_timestamp_ns;
        uint32_t nic_packet_ct;
    } meta{};

    meta.first_nic_timestamp_ns = hw_timestamp_oldest_ns;
    meta.latest_nic_timestamp_ns = hw_timestamp_latest_ns;
    meta.nic_packet_ct = hw_timestamp_count;

    // The critical check: latest_nic_timestamp_ns must NOT be 0
    if (meta.latest_nic_timestamp_ns == 0) {
        FAIL("latest_nic_timestamp_ns is 0 — this is the last_byte_ts=0 bug!");
        return;
    }
    if (meta.latest_nic_timestamp_ns != 4000) {
        printf("(latest_nic_timestamp_ns=%lu, expected 4000) ", meta.latest_nic_timestamp_ns);
        FAIL("latest_nic_timestamp_ns has wrong value");
        return;
    }
    if (meta.first_nic_timestamp_ns != 4000) {
        printf("(first_nic_timestamp_ns=%lu, expected 4000) ", meta.first_nic_timestamp_ns);
        FAIL("first_nic_timestamp_ns has wrong value");
        return;
    }

    PASS();
}

// =============================================================================
// main
// =============================================================================
int main() {
    printf("=== last_byte_ts=0 partial-frame timestamp bug ===\n\n");

    test_first_read_full_and_partial();
    test_second_read_partial_frame_timestamps();
    test_gating_logic_comparison();
    test_metadata_propagation();

    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
