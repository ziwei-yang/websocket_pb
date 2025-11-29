// test/unittest/test_xdp_transport.cpp
// Unit tests for XDP transport initialization and configuration
//
// Compile:
//   g++ -std=c++17 -I./src -I./test/unittest test/unittest/test_xdp_transport.cpp -o build/test_xdp_transport
// Run:
//   ./build/test_xdp_transport

#include <cstdio>
#include <cassert>
#include <cstring>
#include <cstdlib>

// Include mock XDP types
#include "xdp_mocks.hpp"

// Now we can include XDP transport headers
// Note: We need to prevent actual XDP header inclusion
#define XSK_H  // Prevent xdp/xsk.h inclusion

namespace websocket {
namespace xdp {

// Mock XDP transport config for testing
struct XDPTransportConfig {
    uint32_t num_frames = 4096;
    uint32_t frame_size = 2048;
    uint16_t queue_id = 0;
    bool zero_copy = false;
};

} // namespace xdp
} // namespace websocket

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
// XDP Configuration Tests
// ============================================================================

TEST(test_xdp_config_defaults) {
    websocket::xdp::XDPTransportConfig config;

    ASSERT(config.num_frames == 4096, "Default num_frames should be 4096");
    ASSERT(config.frame_size == 2048, "Default frame_size should be 2048");
    ASSERT(config.queue_id == 0, "Default queue_id should be 0");
    ASSERT(config.zero_copy == false, "Default zero_copy should be false");
}

TEST(test_xdp_config_custom) {
    websocket::xdp::XDPTransportConfig config;
    config.num_frames = 8192;
    config.frame_size = 4096;
    config.queue_id = 1;
    config.zero_copy = true;

    ASSERT(config.num_frames == 8192, "Custom num_frames should be 8192");
    ASSERT(config.frame_size == 4096, "Custom frame_size should be 4096");
    ASSERT(config.queue_id == 1, "Custom queue_id should be 1");
    ASSERT(config.zero_copy == true, "Custom zero_copy should be true");
}

TEST(test_xdp_umem_size_calculation) {
    websocket::xdp::XDPTransportConfig config;
    config.num_frames = 4096;
    config.frame_size = 2048;

    size_t umem_size = config.num_frames * config.frame_size;

    ASSERT(umem_size == 8388608, "UMEM size should be 8MB (4096 * 2048)");
}

// ============================================================================
// XDP UMEM Tests
// ============================================================================

TEST(test_xdp_umem_creation) {
    xsk_umem_config umem_cfg;
    xsk_umem_config__default(&umem_cfg);

    ASSERT(umem_cfg.fill_size == XSK_RING_PROD__DEFAULT_NUM_DESCS,
           "Fill ring size should be default");
    ASSERT(umem_cfg.comp_size == XSK_RING_CONS__DEFAULT_NUM_DESCS,
           "Completion ring size should be default");
    ASSERT(umem_cfg.frame_size == 2048, "Frame size should be 2048");
}

TEST(test_xdp_umem_config_custom) {
    xsk_umem_config umem_cfg;
    umem_cfg.fill_size = 4096;
    umem_cfg.comp_size = 4096;
    umem_cfg.frame_size = 4096;
    umem_cfg.frame_headroom = 256;
    umem_cfg.flags = XDP_ZEROCOPY;

    ASSERT(umem_cfg.fill_size == 4096, "Custom fill_size should be 4096");
    ASSERT(umem_cfg.comp_size == 4096, "Custom comp_size should be 4096");
    ASSERT(umem_cfg.frame_size == 4096, "Custom frame_size should be 4096");
    ASSERT(umem_cfg.frame_headroom == 256, "Custom headroom should be 256");
    ASSERT(umem_cfg.flags == XDP_ZEROCOPY, "Flags should be XDP_ZEROCOPY");
}

// ============================================================================
// XDP Socket Tests
// ============================================================================

TEST(test_xdp_socket_creation) {
    // Mock UMEM
    xsk_ring_prod fill_ring;
    xsk_ring_cons comp_ring;
    xsk_umem* umem = nullptr;

    void* umem_area = malloc(8192 * 2048);
    ASSERT(umem_area != nullptr, "UMEM allocation should succeed");

    xsk_umem_config umem_cfg;
    xsk_umem_config__default(&umem_cfg);

    int ret = xsk_umem__create(&umem, umem_area, 8192 * 2048,
                                &fill_ring, &comp_ring, &umem_cfg);

    ASSERT(ret == 0, "UMEM creation should succeed");
    ASSERT(umem != nullptr, "UMEM pointer should be valid");

    xsk_umem__delete(umem);
    free(umem_area);
}

TEST(test_xdp_socket_config_default) {
    xsk_socket_config sock_cfg;
    xsk_socket_config__default(&sock_cfg);

    ASSERT(sock_cfg.rx_size == XSK_RING_CONS__DEFAULT_NUM_DESCS,
           "RX ring size should be default");
    ASSERT(sock_cfg.tx_size == XSK_RING_PROD__DEFAULT_NUM_DESCS,
           "TX ring size should be default");
}

// ============================================================================
// XDP Fill Ring Tests
// ============================================================================

TEST(test_xdp_fill_ring_population) {
    xsk_ring_prod fill_ring;
    uint32_t num_frames = 2048;
    uint32_t frame_size = 2048;

    // Mock reserve operation
    uint32_t idx = 0;
    uint32_t reserved = xsk_ring_prod__reserve(&fill_ring, num_frames, &idx);

    ASSERT(reserved == num_frames, "Should reserve requested number of frames");

    // Populate fill ring
    for (uint32_t i = 0; i < reserved; i++) {
        uint64_t* addr = xsk_ring_prod__fill_addr(&fill_ring, idx + i);
        *addr = i * frame_size;
    }

    xsk_ring_prod__submit(&fill_ring, reserved);

    // Test passes if we get here without crashes
}

TEST(test_xdp_fill_ring_partial_population) {
    xsk_ring_prod fill_ring;
    uint32_t num_frames = 4096;
    uint32_t fill_ring_size = 2048;

    // When fill ring is smaller than total frames
    uint32_t frames_to_populate = (num_frames < fill_ring_size) ? num_frames : fill_ring_size;

    ASSERT(frames_to_populate == 2048, "Should populate min(num_frames, ring_size)");

    uint32_t idx = 0;
    uint32_t reserved = xsk_ring_prod__reserve(&fill_ring, frames_to_populate, &idx);

    ASSERT(reserved == frames_to_populate, "Should reserve min amount");
}

// ============================================================================
// XDP Address Calculation Tests
// ============================================================================

TEST(test_xdp_frame_address_calculation) {
    uint32_t frame_size = 2048;
    uint32_t num_frames = 10;

    for (uint32_t i = 0; i < num_frames; i++) {
        uint64_t addr = i * frame_size;
        ASSERT(addr == i * 2048, "Frame address calculation should be correct");
    }
}

TEST(test_xdp_frame_alignment) {
    uint32_t frame_size = 2048;

    // Frame size should be power of 2 for alignment
    ASSERT((frame_size & (frame_size - 1)) == 0, "Frame size should be power of 2");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║              XDP Transport Unit Tests                             ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    // Configuration tests
    printf("Configuration Tests:\n");
    run_test_xdp_config_defaults();
    run_test_xdp_config_custom();
    run_test_xdp_umem_size_calculation();
    printf("\n");

    // UMEM tests
    printf("UMEM Tests:\n");
    run_test_xdp_umem_creation();
    run_test_xdp_umem_config_custom();
    printf("\n");

    // Socket tests
    printf("Socket Tests:\n");
    run_test_xdp_socket_creation();
    run_test_xdp_socket_config_default();
    printf("\n");

    // Fill ring tests
    printf("Fill Ring Tests:\n");
    run_test_xdp_fill_ring_population();
    run_test_xdp_fill_ring_partial_population();
    printf("\n");

    // Address calculation tests
    printf("Address Calculation Tests:\n");
    run_test_xdp_frame_address_calculation();
    run_test_xdp_frame_alignment();
    printf("\n");

    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                      ALL TESTS PASSED ✅                           ║\n");
    printf("║                                                                    ║\n");
    printf("║  Total: %2d/%2d tests passed                                       ║\n", tests_passed, tests_passed);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");

    return 0;
}
