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

// NIC_MTU must be passed as a compile-time argument via -DNIC_MTU=<value>
#ifndef NIC_MTU
#error "NIC_MTU must be defined at compile time (e.g., -DNIC_MTU=1500)"
#endif

// FRAME_SIZE calculation: MTU + headers, rounded up to next power of 2
// For MTU=1500: 1500 + 14 + 20 + 60 + 500 = 2094 -> 4096 (minimum for igc driver)
//
// Why 4096 minimum (not 2048):
// The igc driver (Intel I225) sets hardware RX buffer size via IGC_SRRCTL_BSIZEPKT
// which stores size right-shifted by 10 (1KB granularity). With frame_size=2048:
//   frame_len = 2048 - 256(headroom) - 256(XDP_PACKET_HEADROOM) = 1536
//   hardware register: 1536 >> 10 = 1 (truncated from 1.5) -> 1024 bytes
//   after DMA overhead -> max deliverable frame = ~1008 bytes (truncates 1514-byte frames)
// With frame_size=4096: frame_len=3584, 3584>>10 = 3 -> 3072 bytes -> full frames OK.
constexpr uint32_t calculate_frame_size(uint32_t mtu) {
    uint32_t min_size = mtu + 14 + 20 + 60 + 500;  // Headers + margin
    uint32_t v = min_size - 1;
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16;
    uint32_t result = v + 1;
    return result < 4096 ? 4096 : result;  // min 4096 for igc driver GRO headroom
}
#ifndef FRAME_SIZE
inline constexpr uint32_t FRAME_SIZE = calculate_frame_size(NIC_MTU);
#endif

// Cache line size (configurable for different architectures)
#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

// ============================================================================
// UMEM Configuration
// ============================================================================

// UMEM layout: [RX_FRAMES | TX_POOL_SIZE]
// TX pool is unified — no sub-pool distinction (ACKs, PONGs, MSGs all share one FIFO)
inline constexpr size_t RX_FRAMES   = 2048;
inline constexpr size_t TX_POOL_SIZE = 2048;
inline constexpr size_t TOTAL_UMEM_FRAMES = RX_FRAMES + TX_POOL_SIZE;  // 4096

// TX throttle: max MSG packets in flight before blocking RAW_OUTBOX
// This implements congestion control at XDP level to prevent overwhelming
// remote servers with limited initial cwnd
inline constexpr uint32_t MAX_PACKETS_INFLIGHT = 32;

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

inline constexpr size_t RAW_INBOX_SIZE      = 4096;
inline constexpr size_t RAW_OUTBOX_SIZE     = 4096;
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

// Note: Named PIPELINE_TCP_MSS to avoid conflict with system header
// /usr/include/netinet/tcp.h which defines #define TCP_MSS 512
// With TCP timestamps enabled (12 bytes: 10 for TS option + 2 NOP padding),
// effective MSS = MTU - IP(20) - TCP(20) - TS(12) = MTU - 52
inline constexpr size_t PIPELINE_TCP_MSS = NIC_MTU - 52;  // MTU - IP(20) - TCP(32 with TS)

// TLS overhead for record size calculation
inline constexpr size_t TLS_RECORD_HEADER = 5;    // Content type(1) + version(2) + length(2)
inline constexpr size_t TLS_MAC_SIZE = 16;        // AES-GCM tag
inline constexpr size_t TLS13_OVERHEAD = TLS_RECORD_HEADER + TLS_MAC_SIZE;  // 5 + 16 = 21

// Max TLS record payload to fit in single TCP segment
inline constexpr size_t MAX_TLS_RECORD_PAYLOAD = PIPELINE_TCP_MSS - TLS13_OVERHEAD;

// Max bytes returned per ssl_read_by_chunk() call (limits burst latency).
// Also used as chunk size for AES-CTR decryption into MSG_INBOX.
// Smaller values let the upper pipeline start processing sooner (pipelining),
// larger values reduce metadata overhead per chunk.
inline constexpr size_t SSL_DECRYPT_CHUNK_SIZE = 2048;

// ============================================================================
// Batch Sizes
// ============================================================================

inline constexpr uint32_t RX_BATCH = 32;
inline constexpr uint32_t TX_BATCH_SIZE = 32;
inline constexpr uint32_t COMP_BATCH = 32;

// ============================================================================
// XDP Socket Configuration
// ============================================================================

// XDP headroom (override via -DXDP_HEADROOM=N, default 0)
#ifndef XDP_HEADROOM
#define XDP_HEADROOM 0
#endif
inline constexpr uint32_t XDP_FRAME_HEADROOM = XDP_HEADROOM;

// XSK ring sizes (must match fill/comp sizes for optimal throughput)
inline constexpr uint32_t XDP_RX_RING_SIZE = RX_FRAMES;       // 2048
inline constexpr uint32_t XDP_TX_RING_SIZE = TX_POOL_SIZE;     // 2048

// Batch size for XDP RX/TX/COMP operations
inline constexpr uint32_t XDP_BATCH_SIZE = 64;

// SO_BUSY_POLL settings
inline constexpr uint32_t XDP_BUSY_POLL_USEC = 1000;     // 1ms busy-poll duration
inline constexpr uint32_t XDP_BUSY_POLL_BUDGET = 64;     // packets per poll

// RX trickle (igc driver TX completion workaround)
inline constexpr uint32_t XDP_TRICKLE_INTERVAL_US = 2000; // 500 Hz

// ============================================================================
// Timing Configuration
// ============================================================================

// Retransmit timeout (initial RTO)
inline constexpr uint64_t INITIAL_RTO_US = 200000;       // 200ms initial RTO

// Retransmit check interval (skip check when busy, check every N loops when idle)
inline constexpr uint32_t RETRANSMIT_CHECK_INTERVAL = 1024;

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

static_assert(FRAME_SIZE >= NIC_MTU + 94, "FRAME_SIZE must fit NIC_MTU + headers");
static_assert((FRAME_SIZE & (FRAME_SIZE - 1)) == 0 || FRAME_SIZE % 1024 == 0,
              "FRAME_SIZE should be power of 2 or 1KB aligned");
static_assert(RX_FRAMES + TX_POOL_SIZE == TOTAL_UMEM_FRAMES,
              "UMEM partition must equal total frames");
static_assert((RAW_INBOX_SIZE & (RAW_INBOX_SIZE - 1)) == 0, "RAW_INBOX_SIZE must be power of 2");
static_assert((MSG_METADATA_SIZE & (MSG_METADATA_SIZE - 1)) == 0, "MSG_METADATA_SIZE must be power of 2");
static_assert((WS_FRAME_INFO_SIZE & (WS_FRAME_INFO_SIZE - 1)) == 0, "WS_FRAME_INFO_SIZE must be power of 2");
static_assert((MSG_INBOX_SIZE & (MSG_INBOX_SIZE - 1)) == 0, "MSG_INBOX_SIZE must be power of 2");

// ============================================================================
// Helper Functions
// ============================================================================

// Derive pool type from UMEM address (RX vs TX)
constexpr FrameType get_pool_from_addr(uint64_t addr, uint32_t frame_size) {
    uint32_t frame_idx = static_cast<uint32_t>(addr / frame_size);
    if (frame_idx < RX_FRAMES) return FRAME_TYPE_RX;
    return FRAME_TYPE_MSG;  // All TX frames are in one unified pool
}

// Get frame index from UMEM address
constexpr uint32_t addr_to_frame_idx(uint64_t addr, uint32_t frame_size) {
    return static_cast<uint32_t>(addr / frame_size);
}

// Get UMEM address from frame index
constexpr uint64_t frame_idx_to_addr(uint32_t frame_idx, uint32_t frame_size) {
    return static_cast<uint64_t>(frame_idx) * frame_size;
}

// ============================================================================
// NullRingAdapter - Sentinel type for unused IPC rings (InlineWS mode)
// ============================================================================

struct NullRingAdapter {
    // Satisfies ring consumer/producer concepts structurally but is never used.
    // InlineWS mode skips all outbox/pongs/metadata ring access at compile time.
};

}  // namespace websocket::pipeline
