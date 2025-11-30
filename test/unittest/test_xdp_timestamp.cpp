// test/unittest/test_xdp_timestamp.cpp
// Unit tests for XDP hardware timestamp functionality
//
// Compile:
//   g++ -std=c++17 -I./src test/unittest/test_xdp_timestamp.cpp -o build/test_xdp_timestamp
// Run:
//   ./build/test_xdp_timestamp

#include <cstdio>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <cstdint>

// Include XDP frame header
#include "xdp/xdp_frame.hpp"

using namespace websocket::xdp;

// Test counter
static int tests_passed = 0;

#define TEST(name) \
    void name(); \
    static void run_##name() { \
        printf("Running %s...", #name); \
        fflush(stdout); \
        name(); \
        tests_passed++; \
        printf(" PASS\n"); \
    } \
    void name()

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("\n  FAIL: %s (line %d)\n", message, __LINE__); \
            exit(1); \
        } \
    } while(0)

// ============================================================================
// Timestamp Constant Tests
// ============================================================================

TEST(test_timestamp_headroom_offset) {
    // Verify the constant matches the BPF program's TIMESTAMP_HEADROOM_OFFSET
    ASSERT(TIMESTAMP_HEADROOM_OFFSET == 8, "Timestamp headroom offset should be 8 bytes");
}

// ============================================================================
// XDPFrame Timestamp Field Tests
// ============================================================================

TEST(test_frame_timestamp_field_init) {
    XDPFrame frame;
    frame.clear();

    ASSERT(frame.hw_timestamp_ns == 0, "hw_timestamp_ns should be 0 after clear()");
}

TEST(test_frame_timestamp_field_assignment) {
    XDPFrame frame;
    frame.clear();

    // Simulate setting timestamp
    frame.hw_timestamp_ns = 1234567890123456789ULL;

    ASSERT(frame.hw_timestamp_ns == 1234567890123456789ULL, "hw_timestamp_ns should store large values");
}

TEST(test_frame_clear_resets_timestamp) {
    XDPFrame frame;
    frame.hw_timestamp_ns = 9999999999ULL;

    frame.clear();

    ASSERT(frame.hw_timestamp_ns == 0, "clear() should reset hw_timestamp_ns to 0");
}

// ============================================================================
// read_hw_timestamp() Method Tests
// ============================================================================

TEST(test_read_hw_timestamp_null_data) {
    XDPFrame frame;
    frame.data = nullptr;

    uint64_t ts = frame.read_hw_timestamp();

    ASSERT(ts == 0, "read_hw_timestamp() should return 0 when data is nullptr");
}

TEST(test_read_hw_timestamp_from_buffer) {
    // Create a buffer that simulates UMEM layout:
    // [headroom...][8-byte timestamp][packet data]
    uint8_t buffer[256 + 8 + 100];  // headroom + timestamp + data
    memset(buffer, 0, sizeof(buffer));

    // Write a known timestamp value at offset 256 (just before packet data)
    uint64_t expected_ts = 0x123456789ABCDEF0ULL;
    memcpy(buffer + 256, &expected_ts, sizeof(expected_ts));

    // Setup frame with data pointer at buffer + 256 + 8 (after timestamp)
    XDPFrame frame;
    frame.data = buffer + 256 + 8;  // Points to packet data
    frame.len = 100;

    // read_hw_timestamp() reads 8 bytes BEFORE data pointer
    uint64_t ts = frame.read_hw_timestamp();

    ASSERT(ts == expected_ts, "read_hw_timestamp() should read timestamp from headroom");
}

TEST(test_read_hw_timestamp_zero_value) {
    // Simulate case where BPF couldn't get timestamp (writes 0)
    uint8_t buffer[256 + 8 + 100];
    memset(buffer, 0, sizeof(buffer));

    // Timestamp area is already 0 from memset

    XDPFrame frame;
    frame.data = buffer + 256 + 8;
    frame.len = 100;

    uint64_t ts = frame.read_hw_timestamp();

    ASSERT(ts == 0, "read_hw_timestamp() should return 0 when BPF wrote 0");
}

TEST(test_read_hw_timestamp_various_values) {
    uint8_t buffer[256 + 8 + 100];

    // Test various timestamp values
    uint64_t test_values[] = {
        0ULL,
        1ULL,
        1000000000ULL,          // 1 second in ns
        1700000000000000000ULL, // ~2023 epoch in ns
        UINT64_MAX
    };

    for (uint64_t expected : test_values) {
        memset(buffer, 0, sizeof(buffer));
        memcpy(buffer + 256, &expected, sizeof(expected));

        XDPFrame frame;
        frame.data = buffer + 256 + 8;
        frame.len = 100;

        uint64_t ts = frame.read_hw_timestamp();

        ASSERT(ts == expected, "read_hw_timestamp() should correctly read various values");
    }
}

// ============================================================================
// Integration-style Tests (simulating peek_rx_frame behavior)
// ============================================================================

TEST(test_frame_setup_with_timestamp) {
    // Simulate what peek_rx_frame() does
    uint8_t buffer[2048];  // Simulated UMEM frame
    memset(buffer, 0, sizeof(buffer));

    // BPF writes timestamp at offset 256 (headroom) - 8
    // Actually: data starts at offset 256 (XDP_HEADROOM), timestamp is at 256-8=248
    uint64_t bpf_timestamp = 1699999999123456789ULL;
    memcpy(buffer + 256 - 8, &bpf_timestamp, sizeof(bpf_timestamp));

    // Fill in some packet data
    const char* packet = "\x45\x00\x00\x28";  // IP header start
    memcpy(buffer + 256, packet, 4);

    // Setup frame like peek_rx_frame() does
    XDPFrame frame;
    frame.addr = 0;
    frame.data = buffer + 256;  // Points past headroom
    frame.len = 100;
    frame.capacity = 2048 - 256;
    frame.offset = 0;
    frame.owned = true;

    // Read timestamp like peek_rx_frame() does
    frame.hw_timestamp_ns = frame.read_hw_timestamp();

    ASSERT(frame.hw_timestamp_ns == bpf_timestamp, "Frame should have BPF-written timestamp");
    ASSERT(frame.data[0] == 0x45, "Packet data should be accessible");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("============================================================\n");
    printf("          XDP Hardware Timestamp Unit Tests                 \n");
    printf("============================================================\n\n");

    printf("Timestamp Constants:\n");
    run_test_timestamp_headroom_offset();
    printf("\n");

    printf("XDPFrame Timestamp Field:\n");
    run_test_frame_timestamp_field_init();
    run_test_frame_timestamp_field_assignment();
    run_test_frame_clear_resets_timestamp();
    printf("\n");

    printf("read_hw_timestamp() Method:\n");
    run_test_read_hw_timestamp_null_data();
    run_test_read_hw_timestamp_from_buffer();
    run_test_read_hw_timestamp_zero_value();
    run_test_read_hw_timestamp_various_values();
    printf("\n");

    printf("Integration Tests:\n");
    run_test_frame_setup_with_timestamp();
    printf("\n");

    printf("============================================================\n");
    printf("                 ALL TESTS PASSED (%d tests)                \n", tests_passed);
    printf("============================================================\n");

    return 0;
}
