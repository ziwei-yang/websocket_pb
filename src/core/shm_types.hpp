// core/shm_types.hpp
// Cache-line aligned types for shared memory WebSocket batch format
#pragma once

#include <cstdint>
#include <cstddef>

// Compile-time cache line size (64 or 128 bytes)
#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

// Frame descriptor (9 bytes packed)
#pragma pack(push, 1)
struct ShmFrameDesc {
    uint32_t payload_start;   // Offset from ssl_data start to payload
    uint32_t payload_len;     // Payload length
    uint8_t  opcode;          // WebSocket opcode
};
#pragma pack(pop)
static_assert(sizeof(ShmFrameDesc) == 9);

// Number of frame descriptors that fit in header's reserved space
// 64-byte CLS: (64-3)/9 = 6 frames, 128-byte CLS: (128-3)/9 = 13 frames
constexpr size_t EMBEDDED_FRAMES = (CACHE_LINE_SIZE - 3) / sizeof(ShmFrameDesc);

// Batch format for HftShm RX buffer entries:
// Case 1 (≤EMBEDDED_FRAMES): [ShmBatchHeader with embedded descs: CLS][raw_ssl_data padded: N*CLS]
// Case 2 (>EMBEDDED_FRAMES): [Header: CLS][ssl_data: N*CLS][overflow descs: M*CLS]

struct alignas(CACHE_LINE_SIZE) ShmBatchHeader {
    uint16_t ssl_data_len_in_CLS;  // SSL data length in cache line units
    uint8_t  frame_count;          // Total number of WebSocket frames
    ShmFrameDesc embedded[EMBEDDED_FRAMES];  // First 6 (or 13) frames embedded here
    uint8_t  padding[CACHE_LINE_SIZE - 3 - EMBEDDED_FRAMES * sizeof(ShmFrameDesc)];
};
static_assert(sizeof(ShmBatchHeader) == CACHE_LINE_SIZE);

// Helper functions
inline uint16_t bytes_to_cls(size_t bytes) {
    return static_cast<uint16_t>((bytes + CACHE_LINE_SIZE - 1) / CACHE_LINE_SIZE);
}

inline size_t cls_to_bytes(uint16_t cls) {
    return static_cast<size_t>(cls) * CACHE_LINE_SIZE;
}

// Number of overflow frames (frames beyond what fits in header)
inline uint8_t overflow_frame_count(uint8_t frame_count) {
    return (frame_count > EMBEDDED_FRAMES) ? (frame_count - EMBEDDED_FRAMES) : 0;
}

// Size of overflow descriptor region (cache-line padded), 0 if all fit in header
inline size_t overflow_descs_size(uint8_t frame_count) {
    uint8_t overflow = overflow_frame_count(frame_count);
    if (overflow == 0) return 0;
    size_t raw = overflow * sizeof(ShmFrameDesc);
    return (raw + CACHE_LINE_SIZE - 1) & ~(size_t)(CACHE_LINE_SIZE - 1);
}

// Total batch size
inline size_t batch_total_size(uint16_t ssl_cls, uint8_t frame_count) {
    return sizeof(ShmBatchHeader) + cls_to_bytes(ssl_cls) + overflow_descs_size(frame_count);
}
