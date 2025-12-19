// websocket_txrx/shm_batch_header.hpp
// Shared memory batch header for WebSocket RX ring buffer
// Part of websocket_pb export headers - designed for external consumers
//
// Usage:
//   #include <websocket_txrx/shm_batch_header.hpp>
//   const ShmBatchHeader* hdr = ...;
//   if (hdr->is_status_only()) { /* handle connection events */ }
//   for (uint16_t i = 0; i < hdr->frame_count; i++) { /* process frames */ }
//
#pragma once

#include <cstdint>
#include <cstddef>

// Platform-specific cache line size
#ifndef CACHE_LINE_SIZE
#if defined(__aarch64__) && defined(__APPLE__)
#define CACHE_LINE_SIZE 128  // Apple Silicon
#else
#define CACHE_LINE_SIZE 64   // x86/x64, other ARM
#endif
#endif

// =============================================================================
// Status bits for ShmBatchHeader::status field
// =============================================================================

// bit 0: Connection state (0=connected, 1=disconnected)
constexpr uint8_t SHM_STATUS_DISCONNECTED = 0x01;

// bit 1: Reconnect feature (0=disabled, 1=enabled)
constexpr uint8_t SHM_STATUS_RECONNECT_ON = 0x02;

// bit 2: Frame opcode (0=binary/0x02, 1=text/0x01)
constexpr uint8_t SHM_STATUS_TEXT_OPCODE  = 0x04;

// =============================================================================
// Frame descriptor (8 bytes each)
// =============================================================================

struct ShmFrameDesc {
    uint32_t payload_start;  // Offset from SSL data start to payload
    uint32_t payload_len;    // Payload length in bytes
};
static_assert(sizeof(ShmFrameDesc) == 8, "ShmFrameDesc must be 8 bytes");

// =============================================================================
// Constants for descriptor layout
// =============================================================================

// Descriptors per cache line (64/8 = 8 on x86, 128/8 = 16 on Apple Silicon)
constexpr size_t DESCS_PER_CLS = CACHE_LINE_SIZE / sizeof(ShmFrameDesc);
constexpr size_t DESCS_PER_CLS_SHIFT = (CACHE_LINE_SIZE == 128) ? 4 : 3;
constexpr size_t DESCS_PER_CLS_MASK = DESCS_PER_CLS - 1;
constexpr size_t CLS_SHIFT = (CACHE_LINE_SIZE == 128) ? 7 : 6;

// Number of embedded frame descriptors in header
// Header overhead: 16 bytes (ssl_data_len_in_CLS + frame_count + status + padding + cpucycle)
// 64-byte CLS: (64-16)/8 = 6 frames
// 128-byte CLS: (128-16)/8 = 14 frames
constexpr size_t EMBEDDED_FRAME_NUM = (CACHE_LINE_SIZE - 16) / sizeof(ShmFrameDesc);

// =============================================================================
// Batch header structure (exactly one cache line)
// =============================================================================

struct alignas(CACHE_LINE_SIZE) ShmBatchHeader {
    uint16_t ssl_data_len_in_CLS;  // SSL data length in cache line units
    uint16_t frame_count;          // Number of WebSocket frames (up to 65535)
    uint8_t  status;               // Status byte (see SHM_STATUS_* constants)
    uint8_t  padding[3];           // Align to 8 bytes
    uint64_t cpucycle;             // TSC when last frame parsed, batch ready to commit
    ShmFrameDesc embedded[EMBEDDED_FRAME_NUM];  // First N frames embedded here

    // ==========================================================================
    // Helper methods for status interpretation
    // ==========================================================================

    // Check if websocket is connected (bit 0 = 0)
    bool is_connected() const { return !(status & SHM_STATUS_DISCONNECTED); }

    // Check if reconnect feature is enabled (bit 1 = 1)
    bool is_reconnect_enabled() const { return status & SHM_STATUS_RECONNECT_ON; }

    // Check if frames are text (bit 2 = 1) or binary (bit 2 = 0)
    bool is_text() const { return status & SHM_STATUS_TEXT_OPCODE; }

    // Check if this is a status-only batch (connection event, no frames)
    // External process should check status bits and potentially refill TX for re-subscription
    bool is_status_only() const { return frame_count == 0 && ssl_data_len_in_CLS == 0; }

    // Get WebSocket opcode (0x01 for text, 0x02 for binary)
    uint8_t opcode() const { return is_text() ? 0x01 : 0x02; }
};
static_assert(sizeof(ShmBatchHeader) == CACHE_LINE_SIZE, "ShmBatchHeader must be exactly one cache line");

// =============================================================================
// Helper functions
// =============================================================================

// Convert bytes to cache line units (rounded up)
constexpr uint16_t bytes_to_cls(size_t bytes) {
    return static_cast<uint16_t>((bytes + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE);
}

// Convert cache line units to bytes
constexpr size_t cls_to_bytes(uint16_t cls) {
    return static_cast<size_t>(cls) * CACHE_LINE_SIZE;
}

// Calculate overflow frame count (frames beyond embedded capacity)
constexpr uint16_t overflow_frame_count(uint16_t frame_count) {
    return (frame_count > EMBEDDED_FRAME_NUM) ? (frame_count - static_cast<uint16_t>(EMBEDDED_FRAME_NUM)) : 0;
}

// Calculate size of overflow descriptor region (cache-line padded)
constexpr size_t overflow_descs_size(uint16_t frame_count) {
    uint16_t overflow = overflow_frame_count(frame_count);
    if (overflow == 0) return 0;
    size_t raw = overflow * sizeof(ShmFrameDesc);
    return (raw + CACHE_LINE_SIZE - 1) & ~(size_t)(CACHE_LINE_SIZE - 1);
}

// Calculate total batch size in bytes
constexpr size_t batch_total_size(uint16_t ssl_cls, uint16_t frame_count) {
    return sizeof(ShmBatchHeader) + cls_to_bytes(ssl_cls) + overflow_descs_size(frame_count);
}
