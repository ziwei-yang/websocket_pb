// test/unittest/test_tcp_state.cpp
// Unit tests for TCP state machine helpers

#include "../../src/stack/tcp/tcp_state.hpp"
#include "../../src/stack/tcp/tcp_retransmit.hpp"
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
        RetransmitQueue queue;

        // Add segments
        uint8_t data1[] = "Hello";
        uint8_t data2[] = "World";

        ASSERT(queue.add_segment(1000, TCP_FLAG_ACK, data1, 5), "Add segment 1");
        ASSERT(queue.add_segment(1005, TCP_FLAG_ACK, data2, 5), "Add segment 2");
        ASSERT(queue.size() == 2, "Queue size should be 2");

        // Remove acknowledged segments
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
        RetransmitQueue queue;

        // SYN consumes 1 sequence number
        queue.add_segment(1000, TCP_FLAG_SYN, nullptr, 0);
        ASSERT(queue.size() == 1, "SYN added");

        // ACK should be 1001 (seq + 1 for SYN)
        size_t removed = queue.remove_acked(1001);
        ASSERT(removed == 1, "SYN acknowledged");
        ASSERT(queue.empty(), "Queue empty after SYN ACK");

        // FIN also consumes 1 sequence number
        queue.add_segment(2000, TCP_FLAG_FIN, nullptr, 0);
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
        RetransmitQueue queue;

        // Fill queue (max 256 segments)
        for (int i = 0; i < 256; i++) {
            ASSERT(queue.add_segment(i * 1460, TCP_FLAG_ACK, nullptr, 0),
                   "Add segment to queue");
        }

        ASSERT(queue.size() == 256, "Queue at max capacity");

        // Try to add one more (should fail)
        ASSERT(!queue.add_segment(256 * 1460, TCP_FLAG_ACK, nullptr, 0),
               "Queue should reject when full");

        ASSERT(queue.size() == 256, "Queue size unchanged");
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

    // Summary
    std::cout << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
