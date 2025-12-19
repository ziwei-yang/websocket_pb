// websocket_txrx/circular_helpers.hpp
// Circular buffer helper functions
// Part of websocket_pb export headers
//
// Usage:
//   circular_read(buffer, capacity, pos, dest, len);
//
#pragma once

#include <cstdint>
#include <cstddef>
#include <algorithm>

// =============================================================================
// Circular buffer read function
// =============================================================================

// Read len bytes from circular buffer starting at logical position
// Handles wrap-around transparently
constexpr void circular_read(const uint8_t* buffer, size_t capacity, size_t pos,
                             uint8_t* dest, size_t len) {
    pos = pos % capacity;  // Normalize position
    size_t first = std::min(len, capacity - pos);
    std::copy(buffer + pos, buffer + pos + first, dest);
    if (len > first) {
        std::copy(buffer, buffer + (len - first), dest + first);
    }
}

// Get pointer with wrap-around
constexpr const uint8_t* circular_ptr(const uint8_t* buffer, size_t capacity, size_t pos) {
    return buffer + (pos % capacity);
}
