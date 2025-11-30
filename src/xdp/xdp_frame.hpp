// src/xdp/xdp_frame.hpp
// Frame reference structure for zero-copy XDP operations
// Enables direct access to UMEM frames without memcpy

#ifndef WEBSOCKET_XDP_FRAME_HPP
#define WEBSOCKET_XDP_FRAME_HPP

#include <cstdint>
#include <cstddef>

namespace websocket {
namespace xdp {

// XDP user metadata structure (must match xdp_user_metadata in exchange_filter.bpf.c)
// BPF program writes this structure to XDP metadata area via bpf_xdp_adjust_meta()
// Layout in UMEM: [xdp_user_metadata][packet data]
//                 ^                  ^
//                 data_meta          data
// In AF_XDP userspace, the descriptor's addr points to data_meta when metadata is present
struct xdp_user_metadata {
    uint64_t rx_timestamp_ns;   // Hardware RX timestamp (nanoseconds, 0 if unavailable)
};
constexpr uint32_t XDP_METADATA_SIZE = sizeof(xdp_user_metadata);

/**
 * @brief Reference to an XDP frame in UMEM
 *
 * This structure provides a zero-copy view into UMEM frames.
 * Instead of copying data from UMEM to user buffers, we work
 * directly with frame references.
 *
 * Memory layout:
 * ┌─────────────────────────┬──────────────────────┬─────────────────────────────┐
 * │ Headroom (248 bytes)    │ xdp_user_metadata    │  Data (starting at 'data')  │
 * │                         │ (8 bytes = timestamp)│  Length: 'len'              │
 * └─────────────────────────┴──────────────────────┴─────────────────────────────┘
 *                           ^                      ^
 *                           data - 8 (data_meta)   data pointer
 *
 * The BPF program writes the hardware RX timestamp (nanoseconds) to the
 * xdp_user_metadata struct in the metadata area immediately before packet data.
 */
struct XDPFrame {
    uint64_t addr;           ///< UMEM frame address (for ring operations)
    uint8_t* data;           ///< Pointer to usable data in UMEM (post-headroom)
    uint32_t len;            ///< Current data length
    uint32_t capacity;       ///< Maximum data capacity (frame_size - headroom)
    uint32_t offset;         ///< Current read offset for sequential access
    bool owned;              ///< True if frame is owned by application (not yet released)
    uint64_t hw_timestamp_ns; ///< NIC hardware RX timestamp (nanoseconds, 0 if unavailable)

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
        hw_timestamp_ns = 0;
    }

    /**
     * @brief Read hardware timestamp from XDP metadata area
     *
     * When the BPF program calls bpf_xdp_adjust_meta(), it creates a metadata
     * area before the packet data. The AF_XDP descriptor addr includes this
     * metadata, so in userspace the timestamp is at the start of the buffer.
     *
     * This method reads from a specified metadata pointer (data_meta).
     *
     * @param data_meta Pointer to the start of metadata area
     * @return Hardware timestamp in nanoseconds, or 0 if unavailable
     */
    static uint64_t read_hw_timestamp_from_meta(const uint8_t* data_meta) {
        if (data_meta == nullptr) {
            return 0;
        }
        return *reinterpret_cast<const uint64_t*>(data_meta);
    }
};

// NOTE: FramePool was removed as unnecessary.
// XDPTransport now uses two simple XDPFrame instances (rx_frame_, tx_frame_)
// directly populated from UMEM descriptors, avoiding the indirection.

} // namespace xdp
} // namespace websocket

#endif // WEBSOCKET_XDP_FRAME_HPP
