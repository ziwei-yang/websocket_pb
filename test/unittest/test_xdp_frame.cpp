// test/unittest/test_xdp_frame.cpp
// Unit tests for XDP frame reference and frame pool
//
// Compile:
//   g++ -std=c++17 -I./src test/unittest/test_xdp_frame.cpp -o build/test_xdp_frame
// Run:
//   ./build/test_xdp_frame

#include <cstdio>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <vector>

// Include XDP frame header
#include "xdp/xdp_frame.hpp"

using namespace websocket::xdp;

// Test counter
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    void name(); \
    static void run_##name() { \
        printf("Running %s...", #name); \
        fflush(stdout); \
        name(); \
        tests_passed++; \
        printf(" ✓\n"); \
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
// XDPFrame Tests
// ============================================================================

TEST(test_frame_initialization) {
    uint8_t buffer[2048];
    XDPFrame frame;

    frame.addr = 0;
    frame.data = buffer;
    frame.len = 100;
    frame.capacity = 1792;  // 2048 - 256 headroom
    frame.offset = 0;
    frame.owned = true;

    ASSERT(frame.data == buffer, "Data pointer should be set");
    ASSERT(frame.len == 100, "Length should be 100");
    ASSERT(frame.capacity == 1792, "Capacity should be 1792");
    ASSERT(frame.offset == 0, "Offset should be 0");
    ASSERT(frame.owned == true, "Should be owned");
}

TEST(test_frame_current_pointer) {
    uint8_t buffer[2048];
    XDPFrame frame;

    frame.data = buffer;
    frame.len = 100;
    frame.offset = 0;

    ASSERT(frame.current() == buffer, "Current should point to start");

    frame.offset = 50;
    ASSERT(frame.current() == buffer + 50, "Current should advance");
}

TEST(test_frame_remaining) {
    XDPFrame frame;
    frame.len = 100;
    frame.offset = 0;

    ASSERT(frame.remaining() == 100, "Should have 100 bytes remaining");

    frame.offset = 50;
    ASSERT(frame.remaining() == 50, "Should have 50 bytes remaining");

    frame.offset = 100;
    ASSERT(frame.remaining() == 0, "Should have 0 bytes remaining");

    frame.offset = 150;  // Past end
    ASSERT(frame.remaining() == 0, "Should return 0 when past end");
}

TEST(test_frame_advance) {
    XDPFrame frame;
    frame.len = 100;
    frame.offset = 0;

    bool ok = frame.advance(50);
    ASSERT(ok, "Should advance successfully");
    ASSERT(frame.offset == 50, "Offset should be 50");

    ok = frame.advance(50);
    ASSERT(ok, "Should advance to end");
    ASSERT(frame.offset == 100, "Offset should be 100");

    ok = frame.advance(1);
    ASSERT(!ok, "Should fail to advance past end");
    ASSERT(frame.offset == 100, "Offset should remain at 100");
}

TEST(test_frame_reset) {
    XDPFrame frame;
    frame.len = 100;
    frame.offset = 75;

    frame.reset();
    ASSERT(frame.offset == 0, "Offset should be reset to 0");
}

TEST(test_frame_consumed) {
    XDPFrame frame;
    frame.len = 100;
    frame.offset = 0;

    ASSERT(!frame.consumed(), "Should not be consumed");

    frame.offset = 50;
    ASSERT(!frame.consumed(), "Should not be consumed");

    frame.offset = 100;
    ASSERT(frame.consumed(), "Should be consumed");

    frame.offset = 150;
    ASSERT(frame.consumed(), "Should be consumed");
}

TEST(test_frame_available) {
    XDPFrame frame;
    frame.capacity = 1792;
    frame.len = 0;

    ASSERT(frame.available() == 1792, "Should have full capacity available");

    frame.len = 1000;
    ASSERT(frame.available() == 792, "Should have 792 bytes available");

    frame.len = 1792;
    ASSERT(frame.available() == 0, "Should have 0 bytes available");
}

TEST(test_frame_append) {
    uint8_t buffer[2048];
    XDPFrame frame;

    frame.data = buffer;
    frame.len = 0;
    frame.capacity = 1792;

    const char* msg1 = "Hello";
    uint32_t n = frame.append(msg1, strlen(msg1));

    ASSERT(n == 5, "Should append 5 bytes");
    ASSERT(frame.len == 5, "Length should be 5");
    ASSERT(memcmp(buffer, "Hello", 5) == 0, "Data should match");

    const char* msg2 = " World";
    n = frame.append(msg2, strlen(msg2));

    ASSERT(n == 6, "Should append 6 bytes");
    ASSERT(frame.len == 11, "Length should be 11");
    ASSERT(memcmp(buffer, "Hello World", 11) == 0, "Data should match");
}

TEST(test_frame_append_overflow) {
    uint8_t buffer[100];
    XDPFrame frame;

    frame.data = buffer;
    frame.len = 0;
    frame.capacity = 100;

    uint8_t large[200];
    memset(large, 'A', 200);

    uint32_t n = frame.append(large, 200);

    ASSERT(n == 100, "Should only append 100 bytes");
    ASSERT(frame.len == 100, "Length should be 100");
}

TEST(test_frame_set_length) {
    XDPFrame frame;
    frame.capacity = 1792;
    frame.len = 0;

    bool ok = frame.set_length(1000);
    ASSERT(ok, "Should set length");
    ASSERT(frame.len == 1000, "Length should be 1000");

    ok = frame.set_length(2000);
    ASSERT(!ok, "Should fail to exceed capacity");
    ASSERT(frame.len == 1000, "Length should remain 1000");
}

TEST(test_frame_clear) {
    XDPFrame frame;
    frame.len = 100;
    frame.offset = 50;
    frame.owned = true;

    frame.clear();

    ASSERT(frame.len == 0, "Length should be 0");
    ASSERT(frame.offset == 0, "Offset should be 0");
    ASSERT(frame.owned == false, "Should not be owned");
}

// NOTE: FramePool tests removed - FramePool class was removed from xdp_frame.hpp
// The XDPFrame struct is now used directly without a pool manager.

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║               XDP Frame Reference Tests                           ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    printf("XDPFrame Tests:\n");
    run_test_frame_initialization();
    run_test_frame_current_pointer();
    run_test_frame_remaining();
    run_test_frame_advance();
    run_test_frame_reset();
    run_test_frame_consumed();
    run_test_frame_available();
    run_test_frame_append();
    run_test_frame_append_overflow();
    run_test_frame_set_length();
    run_test_frame_clear();
    printf("\n");

    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                      ALL TESTS PASSED ✅                           ║\n");
    printf("║                                                                    ║\n");
    printf("║  Total: %2d/%2d tests passed                                       ║\n", tests_passed, tests_passed);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");

    return 0;
}
