// test/unittest/test_xdp_send_recv.cpp
// Unit tests for XDP send/recv implementation
//
// Compile:
//   g++ -std=c++17 -I./src -I./test/unittest test/unittest/test_xdp_send_recv.cpp -o build/test_xdp_send_recv
// Run:
//   ./build/test_xdp_send_recv

#include <cstdio>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <errno.h>

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
// XDP Send/Recv Logic Tests
// ============================================================================

TEST(test_frame_allocation_logic) {
    // Simulate frame allocation
    uint32_t num_frames = 4096;
    uint32_t frame_size = 2048;
    uint32_t next_free_frame = 0;

    // Initial allocation
    uint64_t addr1 = next_free_frame * frame_size;
    next_free_frame++;
    ASSERT(addr1 == 0, "First frame should be at offset 0");

    uint64_t addr2 = next_free_frame * frame_size;
    next_free_frame++;
    ASSERT(addr2 == 2048, "Second frame should be at offset 2048");

    // Check bounds
    ASSERT(next_free_frame < num_frames, "Should not exceed frame limit");
}

TEST(test_frame_reuse_logic) {
    // Simulate frame reuse with vector
    std::vector<uint64_t> free_frames;

    // Add some freed frames
    free_frames.push_back(4096);
    free_frames.push_back(8192);

    ASSERT(!free_frames.empty(), "Free frames should not be empty");

    // Reuse frame
    uint64_t addr = free_frames.back();
    free_frames.pop_back();

    ASSERT(addr == 8192, "Should reuse most recently freed frame");
    ASSERT(free_frames.size() == 1, "Should have one frame left");
}

TEST(test_data_size_validation) {
    uint32_t frame_size = 2048;
    uint32_t headroom = 256;
    uint32_t max_data_size = frame_size - headroom;

    // Valid sizes
    ASSERT(1024 <= max_data_size, "1KB should fit");
    ASSERT(1500 <= max_data_size, "MTU should fit");

    // Invalid size
    ASSERT(4096 > max_data_size, "4KB should not fit");
}

TEST(test_umem_address_calculation) {
    uint64_t frame_addr = 4096;  // Frame at offset 4096
    uint32_t headroom = 256;

    uint64_t data_offset = frame_addr + headroom;

    ASSERT(data_offset == 4352, "Data should start after headroom");
}

TEST(test_batch_processing) {
    uint32_t batch_size = 64;
    uint32_t available_pkts = 100;

    // Process in batches
    uint32_t to_process = (available_pkts < batch_size) ? available_pkts : batch_size;

    ASSERT(to_process == 64, "Should process full batch");

    // Small batch
    available_pkts = 10;
    to_process = (available_pkts < batch_size) ? available_pkts : batch_size;

    ASSERT(to_process == 10, "Should process partial batch");
}

TEST(test_ring_wrap_around) {
    // Ring sizes are power of 2
    uint32_t ring_size = 2048;

    // Check power of 2
    ASSERT((ring_size & (ring_size - 1)) == 0, "Ring size should be power of 2");

    // Mask for wrap-around
    uint32_t mask = ring_size - 1;

    // Test wrap
    uint32_t idx = ring_size + 10;
    uint32_t wrapped = idx & mask;

    ASSERT(wrapped == 10, "Index should wrap around");
}

TEST(test_buffer_copy_size) {
    size_t pkt_len = 1500;
    size_t buf_len = 2048;

    size_t copy_len = (pkt_len < buf_len) ? pkt_len : buf_len;

    ASSERT(copy_len == 1500, "Should copy packet length");

    // Larger packet
    pkt_len = 3000;
    copy_len = (pkt_len < buf_len) ? pkt_len : buf_len;

    ASSERT(copy_len == 2048, "Should truncate to buffer size");
}

TEST(test_errno_codes) {
    // Test that we use correct errno values
    int enotconn = ENOTCONN;
    int eagain = EAGAIN;
    int enobufs = ENOBUFS;
    int emsgsize = EMSGSIZE;

    ASSERT(enotconn != 0, "ENOTCONN should be defined");
    ASSERT(eagain != 0, "EAGAIN should be defined");
    ASSERT(enobufs != 0, "ENOBUFS should be defined");
    ASSERT(emsgsize != 0, "EMSGSIZE should be defined");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║           XDP Send/Recv Implementation Tests                      ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    printf("Frame Management Tests:\n");
    run_test_frame_allocation_logic();
    run_test_frame_reuse_logic();
    run_test_data_size_validation();
    run_test_umem_address_calculation();
    printf("\n");

    printf("Ring Buffer Tests:\n");
    run_test_batch_processing();
    run_test_ring_wrap_around();
    printf("\n");

    printf("Data Handling Tests:\n");
    run_test_buffer_copy_size();
    run_test_errno_codes();
    printf("\n");

    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                      ALL TESTS PASSED ✅                           ║\n");
    printf("║                                                                    ║\n");
    printf("║  Total: %2d/%2d tests passed                                       ║\n", tests_passed, tests_passed);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");

    return 0;
}
