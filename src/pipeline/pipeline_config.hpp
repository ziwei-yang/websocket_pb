// pipeline/pipeline_config.hpp
// Pipeline configuration constants, UMEM layout, and compile-time validation
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>

namespace websocket::pipeline {

// ============================================================================
// Compile-time Configuration (passed via Makefile -D flags)
// ============================================================================

#ifndef PATH_MTU
#define PATH_MTU 1500
#endif

// FRAME_SIZE calculation: MTU + headers, rounded up to 1KB alignment
// Formula: ((PATH_MTU + 94 + 1023) / 1024) * 1024
// - 94 bytes for: Ethernet(14) + IP(20) + TCP(60 max options)
// - 1KB alignment for cache efficiency
#ifndef FRAME_SIZE
#define FRAME_SIZE (((PATH_MTU + 94 + 1023) / 1024) * 1024)
#endif

// Cache line size (configurable for different architectures)
#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

// ============================================================================
// UMEM Configuration
// ============================================================================

inline constexpr size_t TOTAL_UMEM_FRAMES = 65536;  // 16x larger for high throughput

// UMEM partition fractions (1/2 + 1/8 + 1/8 + 1/4 = 1)
inline constexpr size_t RX_FRAMES   = TOTAL_UMEM_FRAMES / 2;      // 32768 - incoming packets
inline constexpr size_t ACK_FRAMES  = TOTAL_UMEM_FRAMES / 8;      // 8192  - TCP ACKs
inline constexpr size_t PONG_FRAMES = TOTAL_UMEM_FRAMES / 8;      // 8192  - encrypted WS PONGs
inline constexpr size_t MSG_FRAMES  = TOTAL_UMEM_FRAMES / 4;      // 16384 - WS messages

// Pool start indices
inline constexpr size_t RX_POOL_START   = 0;
inline constexpr size_t ACK_POOL_START  = RX_FRAMES;
inline constexpr size_t PONG_POOL_START = RX_FRAMES + ACK_FRAMES;
inline constexpr size_t MSG_POOL_START  = RX_FRAMES + ACK_FRAMES + PONG_FRAMES;

// Pool end indices (exclusive)
inline constexpr size_t RX_POOL_END   = ACK_POOL_START;
inline constexpr size_t ACK_POOL_END  = PONG_POOL_START;
inline constexpr size_t PONG_POOL_END = MSG_POOL_START;
inline constexpr size_t MSG_POOL_END  = TOTAL_UMEM_FRAMES;

// TX pool combined size (for ACK tracking)
inline constexpr size_t TX_POOL_SIZE = ACK_FRAMES + PONG_FRAMES + MSG_FRAMES;

// Trickle frame (outside pools, at end of UMEM)
// Gap N1: Trickle frame stored in reserved UMEM region, sent via XDP tx_ring
inline constexpr size_t TRICKLE_FRAME_SIZE = 64;  // Cache-line aligned
inline constexpr size_t TRICKLE_FRAME_INDEX = TOTAL_UMEM_FRAMES;  // Frame index beyond pools
inline constexpr size_t TRICKLE_PACKET_LEN = 43;  // Actual packet size (ETH + IP + UDP + 1 byte)

// Page size for UMEM alignment (must be page-aligned for mmap)
inline constexpr size_t PAGE_SIZE = 4096;

// Total UMEM size including trickle frame, rounded up to page boundary
// Note: UMEM must be page-aligned for xsk_umem__create to succeed
inline constexpr size_t UMEM_TOTAL_SIZE_RAW = TOTAL_UMEM_FRAMES * FRAME_SIZE + TRICKLE_FRAME_SIZE;
inline constexpr size_t UMEM_TOTAL_SIZE = ((UMEM_TOTAL_SIZE_RAW + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;

// ============================================================================
// Ring Buffer Sizes (power of 2)
// ============================================================================

inline constexpr size_t RAW_INBOX_SIZE      = 32768;  // 16x larger
inline constexpr size_t RAW_OUTBOX_SIZE     = 32768;  // 16x larger (match RAW_INBOX)
inline constexpr size_t ACK_OUTBOX_SIZE     = 8192;   // 16x larger
inline constexpr size_t PONG_OUTBOX_SIZE    = 1024;   // 16x larger
inline constexpr size_t MSG_METADATA_SIZE   = 65536;  // 16x larger
inline constexpr size_t WS_FRAME_INFO_SIZE  = 65536;  // 16x larger
inline constexpr size_t PONGS_SIZE          = 1024;   // 16x larger
inline constexpr size_t MSG_OUTBOX_SIZE     = 8192;   // 16x larger

// MSG_INBOX byte stream buffer size (64MB - 16x larger)
inline constexpr size_t MSG_INBOX_SIZE = 64 * 1024 * 1024;

// ============================================================================
// TCP/TLS Configuration
// ============================================================================

inline constexpr size_t TCP_MSS = PATH_MTU - 40;  // MTU - IP(20) - TCP(20)

// TLS overhead for record size calculation
inline constexpr size_t TLS_RECORD_HEADER = 5;    // Content type(1) + version(2) + length(2)
inline constexpr size_t TLS_MAC_SIZE = 16;        // AES-GCM tag
inline constexpr size_t TLS_OVERHEAD = TLS_RECORD_HEADER + TLS_MAC_SIZE;

// Max TLS record payload to fit in single TCP segment
inline constexpr size_t MAX_TLS_RECORD_PAYLOAD = TCP_MSS - TLS_OVERHEAD;

// ============================================================================
// Batch Sizes
// ============================================================================

inline constexpr uint32_t RX_BATCH = 32;
inline constexpr uint32_t TX_BATCH_SIZE = 32;
inline constexpr uint32_t COMP_BATCH = 32;

// ============================================================================
// Timing Configuration
// ============================================================================

// Adaptive ACK thresholds
inline constexpr uint32_t ACK_PACKET_THRESHOLD = 8;      // Send ACK after N packets
inline constexpr uint64_t ACK_TIMEOUT_US = 100;          // Send ACK after N microseconds

// Retransmit timeout (initial RTO)
inline constexpr uint64_t INITIAL_RTO_US = 200000;       // 200ms initial RTO

// Trickle interval for igc driver workaround
inline constexpr uint32_t TRICKLE_INTERVAL_ITERATIONS = 8;

// ============================================================================
// Frame Type Enum
// ============================================================================

enum FrameType : uint8_t {
    FRAME_TYPE_RX   = 0,  // RX frames [0, RX_FRAMES) - incoming packets
    FRAME_TYPE_ACK  = 1,  // ACK frames - pure TCP ACK (no payload, immediate release)
    FRAME_TYPE_PONG = 2,  // PONG frames - WebSocket PONG (ACK-based release)
    FRAME_TYPE_MSG  = 3,  // MSG frames - data messages (ACK-based release)
};

// ============================================================================
// Message Type Constants
// ============================================================================

inline constexpr uint8_t MSG_TYPE_DATA     = 0;
inline constexpr uint8_t MSG_TYPE_WS_CLOSE = 1;

// ============================================================================
// WebSocket Opcodes
// ============================================================================

enum WebSocketOpcode : uint8_t {
    WS_OP_CONTINUATION = 0x00,
    WS_OP_TEXT         = 0x01,
    WS_OP_BINARY       = 0x02,
    WS_OP_CLOSE        = 0x08,
    WS_OP_PING         = 0x09,
    WS_OP_PONG         = 0x0A,
};

// ============================================================================
// Shared Memory Paths
// ============================================================================

namespace shm_paths {
    // UMEM buffer (single file)
    inline constexpr const char* UMEM = "/dev/shm/pipeline/umem.dat";

    // Ring buffers (base paths)
    inline constexpr const char* RAW_INBOX     = "/dev/shm/pipeline/raw_inbox";
    inline constexpr const char* RAW_OUTBOX    = "/dev/shm/pipeline/raw_outbox";
    inline constexpr const char* ACK_OUTBOX    = "/dev/shm/pipeline/ack_outbox";
    inline constexpr const char* PONG_OUTBOX   = "/dev/shm/pipeline/pong_outbox";
    inline constexpr const char* MSG_METADATA  = "/dev/shm/pipeline/msg_metadata";
    inline constexpr const char* MSG_OUTBOX    = "/dev/shm/pipeline/msg_outbox";
    inline constexpr const char* PONGS         = "/dev/shm/pipeline/pongs";
    inline constexpr const char* WS_FRAME_INFO = "/dev/shm/pipeline/ws_frame_info";

    // MSG_INBOX byte stream (single file)
    inline constexpr const char* MSG_INBOX = "/dev/shm/pipeline/msg_inbox.dat";

    // State structures (single files)
    inline constexpr const char* TCP_STATE      = "/dev/shm/pipeline/tcp_state.dat";

    // Pipeline directory
    inline constexpr const char* PIPELINE_DIR = "/dev/shm/pipeline";
}

// ============================================================================
// Compile-time Validation
// ============================================================================

static_assert(FRAME_SIZE >= PATH_MTU + 94, "FRAME_SIZE must fit PATH_MTU + headers");
static_assert((FRAME_SIZE & (FRAME_SIZE - 1)) == 0 || FRAME_SIZE % 1024 == 0,
              "FRAME_SIZE should be power of 2 or 1KB aligned");
static_assert(RX_FRAMES + ACK_FRAMES + PONG_FRAMES + MSG_FRAMES == TOTAL_UMEM_FRAMES,
              "UMEM partition must equal total frames");
static_assert((RAW_INBOX_SIZE & (RAW_INBOX_SIZE - 1)) == 0, "RAW_INBOX_SIZE must be power of 2");
static_assert((MSG_METADATA_SIZE & (MSG_METADATA_SIZE - 1)) == 0, "MSG_METADATA_SIZE must be power of 2");
static_assert((WS_FRAME_INFO_SIZE & (WS_FRAME_INFO_SIZE - 1)) == 0, "WS_FRAME_INFO_SIZE must be power of 2");
static_assert((MSG_INBOX_SIZE & (MSG_INBOX_SIZE - 1)) == 0, "MSG_INBOX_SIZE must be power of 2");

// ============================================================================
// Helper Functions
// ============================================================================

// Derive pool type from UMEM address
constexpr FrameType get_pool_from_addr(uint64_t addr, uint32_t frame_size) {
    uint32_t frame_idx = static_cast<uint32_t>(addr / frame_size);
    if (frame_idx < RX_POOL_END) return FRAME_TYPE_RX;
    if (frame_idx < ACK_POOL_END) return FRAME_TYPE_ACK;
    if (frame_idx < PONG_POOL_END) return FRAME_TYPE_PONG;
    return FRAME_TYPE_MSG;
}

// Get frame index from UMEM address
constexpr uint32_t addr_to_frame_idx(uint64_t addr, uint32_t frame_size) {
    return static_cast<uint32_t>(addr / frame_size);
}

// Get UMEM address from frame index
constexpr uint64_t frame_idx_to_addr(uint32_t frame_idx, uint32_t frame_size) {
    return static_cast<uint64_t>(frame_idx) * frame_size;
}

}  // namespace websocket::pipeline
