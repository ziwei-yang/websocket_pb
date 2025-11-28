// src/xdp/xdp_frame.hpp
// Frame reference structure for zero-copy XDP operations
// Enables direct access to UMEM frames without memcpy

#ifndef WEBSOCKET_XDP_FRAME_HPP
#define WEBSOCKET_XDP_FRAME_HPP

#include <cstdint>
#include <cstddef>

namespace websocket {
namespace xdp {

/**
 * @brief Reference to an XDP frame in UMEM
 *
 * This structure provides a zero-copy view into UMEM frames.
 * Instead of copying data from UMEM to user buffers, we work
 * directly with frame references.
 *
 * Memory layout:
 * ┌─────────────┬──────────────────────────────────────────┐
 * │ Headroom    │  Data (starting at 'data' pointer)       │
 * │ (256 bytes) │  Length: 'len', Capacity: 'capacity'     │
 * └─────────────┴──────────────────────────────────────────┘
 *               ^
 *               data pointer
 */
struct XDPFrame {
    uint64_t addr;           ///< UMEM frame address (for ring operations)
    uint8_t* data;           ///< Pointer to usable data in UMEM (post-headroom)
    uint32_t len;            ///< Current data length
    uint32_t capacity;       ///< Maximum data capacity (frame_size - headroom)
    uint32_t offset;         ///< Current read offset for sequential access
    bool owned;              ///< True if frame is owned by application (not yet released)

    /**
     * @brief Get pointer to current read position
     */
    uint8_t* current() {
        return data + offset;
    }

    /**
     * @brief Get remaining bytes from current offset
     */
    uint32_t remaining() const {
        return (len > offset) ? (len - offset) : 0;
    }

    /**
     * @brief Advance read offset
     * @param n Bytes to advance
     * @return true if successful, false if would exceed length
     */
    bool advance(uint32_t n) {
        if (offset + n > len) {
            return false;
        }
        offset += n;
        return true;
    }

    /**
     * @brief Reset read offset to beginning
     */
    void reset() {
        offset = 0;
    }

    /**
     * @brief Check if all data has been consumed
     */
    bool consumed() const {
        return offset >= len;
    }

    /**
     * @brief Get available space for writing
     */
    uint32_t available() const {
        return (capacity > len) ? (capacity - len) : 0;
    }

    /**
     * @brief Append data to frame (for TX path)
     * @param src Source buffer
     * @param n Bytes to append
     * @return Bytes actually appended
     */
    uint32_t append(const void* src, uint32_t n) {
        uint32_t to_copy = (n < available()) ? n : available();
        if (to_copy > 0) {
            memcpy(data + len, src, to_copy);
            len += to_copy;
        }
        return to_copy;
    }

    /**
     * @brief Set data length for TX (when data is written directly)
     * @param new_len New length (must be <= capacity)
     * @return true if successful
     */
    bool set_length(uint32_t new_len) {
        if (new_len > capacity) {
            return false;
        }
        len = new_len;
        return true;
    }

    /**
     * @brief Clear frame for reuse
     */
    void clear() {
        len = 0;
        offset = 0;
        owned = false;
    }
};

// NOTE: FramePool was removed as unnecessary.
// XDPTransport now uses two simple XDPFrame instances (rx_frame_, tx_frame_)
// directly populated from UMEM descriptors, avoiding the indirection.

} // namespace xdp
} // namespace websocket

#endif // WEBSOCKET_XDP_FRAME_HPP
