// test/unittest/test_tcp_state.cpp
// Unit tests for TCP state machine helpers

#include "../../src/stack/tcp/tcp_state.hpp"
#include "../../src/stack/tcp/tcp_retransmit.hpp"
#include "../../src/stack/tcp/tcp_reorder.hpp"
#include <iostream>
#include <cassert>

using namespace userspace_stack;

int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) \
    std::cout << "Testing " << name << "... "; \
    try {

#define END_TEST \
        std::cout << "✅ PASS" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "❌ FAIL: " << e.what() << std::endl; \
        tests_failed++; \
    }

#define ASSERT(condition, msg) \
    if (!(condition)) throw std::runtime_error(msg);

// Test sequence number comparison (handles wraparound)
void test_seq_comparison() {
    TEST("Sequence number comparison")
        // Basic comparison
        ASSERT(seq_lt(100, 200), "100 < 200");
        ASSERT(seq_gt(200, 100), "200 > 100");
        ASSERT(seq_le(100, 100), "100 <= 100");
        ASSERT(seq_ge(100, 100), "100 >= 100");

        // Wraparound at 2^32
        uint32_t near_max = 0xFFFFFFF0;  // Near UINT32_MAX
        uint32_t after_wrap = 0x00000010; // After wraparound

        ASSERT(seq_lt(near_max, after_wrap), "Wraparound: near_max < after_wrap");
        ASSERT(seq_gt(after_wrap, near_max), "Wraparound: after_wrap > near_max");

        // Edge case: exactly at wraparound
        ASSERT(seq_lt(0xFFFFFFFF, 0x00000000), "UINT32_MAX < 0");
    END_TEST
}

// Test TCP flags string conversion
void test_tcp_flags_string() {
    TEST("TCP flags to string conversion")
        std::string flags_syn = tcp_flags_string(TCP_FLAG_SYN);
        ASSERT(flags_syn == "SYN", "SYN flag string");

        std::string flags_syn_ack = tcp_flags_string(TCP_FLAG_SYN | TCP_FLAG_ACK);
        ASSERT(flags_syn_ack == "SYN ACK", "SYN+ACK flag string");

        std::string flags_all = tcp_flags_string(TCP_FLAG_FIN | TCP_FLAG_SYN |
                                                 TCP_FLAG_RST | TCP_FLAG_PSH |
                                                 TCP_FLAG_ACK | TCP_FLAG_URG);
        ASSERT(flags_all == "FIN SYN RST PSH ACK URG", "All flags string");

        std::string flags_none = tcp_flags_string(0);
        ASSERT(flags_none == "", "No flags string");
    END_TEST
}

// Test TCP state names
void test_state_names() {
    TEST("TCP state names")
        ASSERT(std::string(tcp_state_name(TCPState::CLOSED)) == "CLOSED", "CLOSED state");
        ASSERT(std::string(tcp_state_name(TCPState::SYN_SENT)) == "SYN_SENT", "SYN_SENT state");
        ASSERT(std::string(tcp_state_name(TCPState::ESTABLISHED)) == "ESTABLISHED", "ESTABLISHED state");
        ASSERT(std::string(tcp_state_name(TCPState::FIN_WAIT_1)) == "FIN_WAIT_1", "FIN_WAIT_1 state");
    END_TEST
}

// Test retransmit queue operations
void test_retransmit_queue() {
    TEST("Retransmit queue: add and remove")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);  // 1 MHz TSC, 100ms RTO

        // Add segments using add_ref(seq, flags, frame_idx, frame_len, payload_len)
        ASSERT(queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 5), "Add segment 1");
        ASSERT(queue.add_ref(1005, TCP_FLAG_ACK, 1, 100, 5), "Add segment 2");
        ASSERT(queue.size() == 2, "Queue size should be 2");

        // Remove acknowledged segments - remove_acked returns count
        size_t removed = queue.remove_acked(1005);
        ASSERT(removed == 1, "Should remove 1 segment");
        ASSERT(queue.size() == 1, "Queue size should be 1");

        // Remove remaining
        removed = queue.remove_acked(1010);
        ASSERT(removed == 1, "Should remove 1 more segment");
        ASSERT(queue.empty(), "Queue should be empty");
    END_TEST
}

// Test retransmit queue with SYN/FIN (consume sequence number)
void test_retransmit_queue_syn_fin() {
    TEST("Retransmit queue: SYN/FIN sequence consumption")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        // SYN consumes 1 sequence number (payload_len=0, but SYN flag adds 1)
        queue.add_ref(1000, TCP_FLAG_SYN, 0, 54, 0);  // frame_len=54 (headers only)
        ASSERT(queue.size() == 1, "SYN added");

        // ACK should be 1001 (seq + 1 for SYN)
        size_t removed = queue.remove_acked(1001);
        ASSERT(removed == 1, "SYN acknowledged");
        ASSERT(queue.empty(), "Queue empty after SYN ACK");

        // FIN also consumes 1 sequence number
        queue.add_ref(2000, TCP_FLAG_FIN, 1, 54, 0);
        removed = queue.remove_acked(2001);
        ASSERT(removed == 1, "FIN acknowledged");
    END_TEST
}

// Test zero-copy receive buffer
void test_receive_buffer() {
    TEST("ZeroCopyReceiveBuffer: push_frame and read")
        ZeroCopyReceiveBuffer buffer;

        // Simulate UMEM frames with test data
        const char* data1 = "Hello, ";
        const char* data2 = "World!";

        // Push frames (no release callback for simple test)
        ASSERT(buffer.push_frame((const uint8_t*)data1, 7, 0x1000), "Push frame 1");
        ASSERT(buffer.push_frame((const uint8_t*)data2, 6, 0x2000), "Push frame 2");
        ASSERT(buffer.available() == 13, "13 bytes available");
        ASSERT(buffer.frame_count() == 2, "2 frames held");

        // Read data (scatter-gather across frames)
        uint8_t read_buf[20];
        ssize_t n = buffer.read(read_buf, sizeof(read_buf));
        ASSERT(n == 13, "Read 13 bytes");
        read_buf[13] = '\0';
        ASSERT(std::string((char*)read_buf) == "Hello, World!", "Data matches");

        ASSERT(buffer.empty(), "Buffer should be empty");
        ASSERT(buffer.frame_count() == 0, "No frames held");
    END_TEST
}

// Test zero-copy receive buffer partial reads
void test_receive_buffer_partial() {
    TEST("ZeroCopyReceiveBuffer: partial reads across frames")
        ZeroCopyReceiveBuffer buffer;

        // Two frames with data
        const char* frame1 = "12345";
        const char* frame2 = "67890";
        buffer.push_frame((const uint8_t*)frame1, 5, 0x1000);
        buffer.push_frame((const uint8_t*)frame2, 5, 0x2000);

        ASSERT(buffer.frame_count() == 2, "2 frames held");

        // Read in chunks (partial read within frame)
        uint8_t chunk1[3];
        ssize_t n1 = buffer.read(chunk1, 3);
        ASSERT(n1 == 3, "Read 3 bytes");
        ASSERT(std::string((char*)chunk1, 3) == "123", "First chunk");
        ASSERT(buffer.frame_count() == 2, "Still 2 frames (first partially consumed)");

        // Read remaining of first frame + part of second
        uint8_t chunk2[4];
        ssize_t n2 = buffer.read(chunk2, 4);
        ASSERT(n2 == 4, "Read 4 bytes");
        ASSERT(std::string((char*)chunk2, 4) == "4567", "Second chunk spans frames");
        ASSERT(buffer.frame_count() == 1, "First frame released, one remaining");

        // Read rest
        uint8_t chunk3[5];
        ssize_t n3 = buffer.read(chunk3, 5);
        ASSERT(n3 == 3, "Read remaining 3 bytes");
        ASSERT(std::string((char*)chunk3, 3) == "890", "Third chunk");

        ASSERT(buffer.empty(), "Buffer empty after partial reads");
        ASSERT(buffer.frame_count() == 0, "All frames released");
    END_TEST
}

// Test retransmit queue overflow
void test_retransmit_queue_overflow() {
    TEST("Retransmit queue: overflow handling")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        // Fill queue (max 256 segments)
        for (int i = 0; i < 256; i++) {
            ASSERT(queue.add_ref(i * 1460, TCP_FLAG_ACK, i, 100, 0),
                   "Add segment to queue");
        }

        ASSERT(queue.size() == 256, "Queue at max capacity");

        // Try to add one more (should fail)
        ASSERT(!queue.add_ref(256 * 1460, TCP_FLAG_ACK, 256, 100, 0),
               "Queue should reject when full");

        ASSERT(queue.size() == 256, "Queue size unchanged");
    END_TEST
}

// ============================================================================
// SACK Block Extraction Tests (RFC 2018)
// ============================================================================

// Test empty OOO buffer returns no SACK blocks
void test_sack_empty_buffer() {
    TEST("SACK: empty buffer returns no blocks")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;

        uint8_t count = buffer.extract_sack_blocks(1000, out);
        ASSERT(count == 0, "No blocks from empty buffer");
        ASSERT(out.count == 0, "Output count is 0");
    END_TEST
}

// Test single OOO segment generates one SACK block
void test_sack_single_block() {
    TEST("SACK: single OOO segment")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;

        // Buffer one OOO segment: seq=2000, len=500 (gap from rcv_nxt=1000)
        uint8_t dummy_data[10] = {0};
        buffer.buffer_segment(2000, 500, dummy_data);

        uint8_t count = buffer.extract_sack_blocks(1000, out);
        ASSERT(count == 1, "One SACK block");
        ASSERT(out.blocks[0].left_edge == 2000, "Left edge = 2000");
        ASSERT(out.blocks[0].right_edge == 2500, "Right edge = 2500");
    END_TEST
}

// Test multiple non-contiguous segments generate multiple blocks
void test_sack_multiple_blocks() {
    TEST("SACK: multiple non-contiguous segments")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;
        uint8_t dummy_data[10] = {0};

        // Buffer 3 non-contiguous segments in arrival order
        buffer.buffer_segment(2000, 500, dummy_data);   // arrival_id=0
        buffer.buffer_segment(4000, 500, dummy_data);   // arrival_id=1
        buffer.buffer_segment(6000, 500, dummy_data);   // arrival_id=2 (most recent)

        uint8_t count = buffer.extract_sack_blocks(1000, out);
        ASSERT(count == 3, "Three SACK blocks");

        // RFC 2018 Section 4: Most recent first
        ASSERT(out.blocks[0].left_edge == 6000, "First block is most recent (seq=6000)");
        ASSERT(out.blocks[0].right_edge == 6500, "First block right edge");
        ASSERT(out.blocks[1].left_edge == 4000, "Second block is second most recent");
        ASSERT(out.blocks[2].left_edge == 2000, "Third block is oldest");
    END_TEST
}

// Test RFC 2018 Section 4: most recently arrived segment's block comes first
void test_sack_arrival_order() {
    TEST("SACK: RFC 2018 Section 4 - most recent first")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;
        uint8_t dummy_data[10] = {0};

        // Buffer segments in non-sequential order (simulating network reordering)
        // Arrival order: seq=4000, then seq=2000, then seq=6000
        buffer.buffer_segment(4000, 500, dummy_data);   // arrival_id=0
        buffer.buffer_segment(2000, 500, dummy_data);   // arrival_id=1
        buffer.buffer_segment(6000, 500, dummy_data);   // arrival_id=2 (most recent)

        uint8_t count = buffer.extract_sack_blocks(1000, out);
        ASSERT(count == 3, "Three SACK blocks");

        // Most recent (6000) should be first, then 2000 (arrival_id=1), then 4000 (arrival_id=0)
        ASSERT(out.blocks[0].left_edge == 6000, "First = most recent arrival (seq=6000)");
        ASSERT(out.blocks[1].left_edge == 2000, "Second = second most recent (seq=2000)");
        ASSERT(out.blocks[2].left_edge == 4000, "Third = oldest arrival (seq=4000)");
    END_TEST
}

// Test adjacent segments are merged into single block
void test_sack_merge_adjacent() {
    TEST("SACK: merge adjacent segments")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;
        uint8_t dummy_data[10] = {0};

        // Two adjacent segments: [2000-2500) and [2500-3000)
        buffer.buffer_segment(2000, 500, dummy_data);   // arrival_id=0
        buffer.buffer_segment(2500, 500, dummy_data);   // arrival_id=1 (most recent)

        uint8_t count = buffer.extract_sack_blocks(1000, out);
        ASSERT(count == 1, "Merged into one SACK block");
        ASSERT(out.blocks[0].left_edge == 2000, "Merged left edge");
        ASSERT(out.blocks[0].right_edge == 3000, "Merged right edge");
    END_TEST
}

// Test overlapping segments are merged
void test_sack_merge_overlapping() {
    TEST("SACK: merge overlapping segments")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;
        uint8_t dummy_data[10] = {0};

        // Overlapping segments: [2000-2600) and [2400-3000)
        buffer.buffer_segment(2000, 600, dummy_data);
        buffer.buffer_segment(2400, 600, dummy_data);

        uint8_t count = buffer.extract_sack_blocks(1000, out);
        ASSERT(count == 1, "Merged into one SACK block");
        ASSERT(out.blocks[0].left_edge == 2000, "Merged left edge");
        ASSERT(out.blocks[0].right_edge == 3000, "Merged right edge");
    END_TEST
}

// Test max_blocks parameter limits output
void test_sack_max_blocks_limit() {
    TEST("SACK: max_blocks parameter limits output")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;
        uint8_t dummy_data[10] = {0};

        // Buffer 5 non-contiguous segments
        buffer.buffer_segment(2000, 500, dummy_data);   // arrival_id=0
        buffer.buffer_segment(4000, 500, dummy_data);   // arrival_id=1
        buffer.buffer_segment(6000, 500, dummy_data);   // arrival_id=2
        buffer.buffer_segment(8000, 500, dummy_data);   // arrival_id=3
        buffer.buffer_segment(10000, 500, dummy_data);  // arrival_id=4 (most recent)

        // Request only 3 blocks (simulating timestamps enabled)
        uint8_t count = buffer.extract_sack_blocks(1000, out, 3);
        ASSERT(count == 3, "Limited to 3 blocks");

        // Should be the 3 most recent
        ASSERT(out.blocks[0].left_edge == 10000, "First = most recent (seq=10000)");
        ASSERT(out.blocks[1].left_edge == 8000, "Second = seq=8000");
        ASSERT(out.blocks[2].left_edge == 6000, "Third = seq=6000");
    END_TEST
}

// Test segments below rcv_nxt are excluded
void test_sack_exclude_below_rcv_nxt() {
    TEST("SACK: exclude segments at or below rcv_nxt")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;
        uint8_t dummy_data[10] = {0};

        // Buffer segments: one below rcv_nxt, one at rcv_nxt, one above
        buffer.buffer_segment(500, 200, dummy_data);    // Below rcv_nxt=1000
        buffer.buffer_segment(1000, 200, dummy_data);   // At rcv_nxt (should be excluded)
        buffer.buffer_segment(2000, 200, dummy_data);   // Above rcv_nxt

        uint8_t count = buffer.extract_sack_blocks(1000, out);
        ASSERT(count == 1, "Only one block above rcv_nxt");
        ASSERT(out.blocks[0].left_edge == 2000, "Block is the one above rcv_nxt");
    END_TEST
}

// Test merged block inherits max arrival_id (for recency ordering)
void test_sack_merged_block_recency() {
    TEST("SACK: merged block uses max arrival_id for ordering")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;
        uint8_t dummy_data[10] = {0};

        // First: isolated block at 6000 (arrival_id=0)
        buffer.buffer_segment(6000, 500, dummy_data);

        // Then: two segments that merge into [2000-3000)
        buffer.buffer_segment(2000, 500, dummy_data);   // arrival_id=1
        buffer.buffer_segment(2500, 500, dummy_data);   // arrival_id=2 (most recent in merged block)

        uint8_t count = buffer.extract_sack_blocks(1000, out);
        ASSERT(count == 2, "Two blocks (one merged)");

        // Merged block [2000-3000) has higher max arrival_id (2) than [6000-6500) (0)
        ASSERT(out.blocks[0].left_edge == 2000, "Merged block first (most recent arrival)");
        ASSERT(out.blocks[0].right_edge == 3000, "Merged block right edge");
        ASSERT(out.blocks[1].left_edge == 6000, "Isolated block second");
    END_TEST
}

// Test realistic scenario from user bug report
void test_sack_realistic_scenario() {
    TEST("SACK: realistic OOO scenario (user bug report)")
        ZeroCopyTCPReorderBuffer<const uint8_t*> buffer;
        SACKBlockArray out;
        uint8_t dummy_data[10] = {0};

        // Simulating: PKT 8 arrives, then PKT 10, then PKT 12
        // Each is a separate non-contiguous block
        uint32_t base_seq = 402459397;  // From user's log

        buffer.buffer_segment(base_seq, 942, dummy_data);          // PKT 8, arrival_id=0
        buffer.buffer_segment(base_seq + 1448, 942, dummy_data);   // PKT 10, arrival_id=1
        buffer.buffer_segment(base_seq + 2896, 942, dummy_data);   // PKT 12, arrival_id=2

        uint32_t rcv_nxt = 402458891;  // From user's log

        uint8_t count = buffer.extract_sack_blocks(rcv_nxt, out, 3);
        ASSERT(count == 3, "Three SACK blocks");

        // Expected order: PKT 12 first (most recent), then PKT 10, then PKT 8
        ASSERT(out.blocks[0].left_edge == base_seq + 2896, "First = PKT 12 (most recent)");
        ASSERT(out.blocks[1].left_edge == base_seq + 1448, "Second = PKT 10");
        ASSERT(out.blocks[2].left_edge == base_seq, "Third = PKT 8 (oldest)");
    END_TEST
}

int main() {
    std::cout << "╔════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   Userspace Stack: TCP State Unit Tests       ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;

    // Run tests
    test_seq_comparison();
    test_tcp_flags_string();
    test_state_names();
    test_retransmit_queue();
    test_retransmit_queue_syn_fin();
    test_receive_buffer();
    test_receive_buffer_partial();
    test_retransmit_queue_overflow();

    // SACK block extraction tests (RFC 2018)
    test_sack_empty_buffer();
    test_sack_single_block();
    test_sack_multiple_blocks();
    test_sack_arrival_order();
    test_sack_merge_adjacent();
    test_sack_merge_overlapping();
    test_sack_max_blocks_limit();
    test_sack_exclude_below_rcv_nxt();
    test_sack_merged_block_recency();
    test_sack_realistic_scenario();

    // Summary
    std::cout << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
