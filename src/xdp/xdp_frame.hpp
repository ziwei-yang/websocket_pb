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

/**
 * @brief Frame pool for managing XDP frame references
 *
 * Manages a pool of XDPFrame structures that reference UMEM frames.
 * This allows reuse of frame metadata without heap allocation.
 */
class FramePool {
public:
    /**
     * @brief Initialize frame pool
     * @param umem_base Base address of UMEM
     * @param frame_size Size of each frame
     * @param num_frames Total number of frames
     * @param headroom Headroom bytes per frame
     */
    void init(void* umem_base, uint32_t frame_size, uint32_t num_frames, uint32_t headroom) {
        umem_base_ = (uint8_t*)umem_base;
        frame_size_ = frame_size;
        num_frames_ = num_frames;
        headroom_ = headroom;

        printf("[FRAME-POOL] Init: umem_base=%p, frame_size=%u, num_frames=%u, headroom=%u\n",
               umem_base, frame_size, num_frames, headroom);

        // Pre-allocate frame structures
        frames_.resize(num_frames);

        // Initialize each frame reference
        for (uint32_t i = 0; i < num_frames; i++) {
            frames_[i].addr = i * frame_size;
            frames_[i].data = umem_base_ + frames_[i].addr + headroom;
            frames_[i].len = 0;
            frames_[i].capacity = frame_size - headroom;
            frames_[i].offset = 0;
            frames_[i].owned = false;
            if (i < 3) {
                printf("[FRAME-POOL] Frame %u: addr=0x%lx, data=%p\n",
                       i, frames_[i].addr, (void*)frames_[i].data);
            }
        }
    }

    /**
     * @brief Get frame reference by UMEM address
     * @param addr UMEM frame address
     * @return Pointer to XDPFrame or nullptr if invalid
     */
    XDPFrame* get_frame(uint64_t addr) {
        uint32_t idx = addr / frame_size_;
        if (idx >= num_frames_) {
            return nullptr;
        }
        return &frames_[idx];
    }

    /**
     * @brief Get frame reference by index
     * @param idx Frame index
     * @return Pointer to XDPFrame or nullptr if invalid
     */
    XDPFrame* get_frame_by_index(uint32_t idx) {
        if (idx >= num_frames_) {
            return nullptr;
        }
        return &frames_[idx];
    }

    /**
     * @brief Update frame length (for RX path)
     * @param frame Frame to update
     * @param len New data length
     */
    void set_rx_length(XDPFrame* frame, uint32_t len) {
        if (frame && len <= frame->capacity) {
            frame->len = len;
            frame->offset = 0;
            frame->owned = true;
        }
    }

    /**
     * @brief Release frame back to pool
     * @param frame Frame to release
     */
    void release(XDPFrame* frame) {
        if (frame) {
            frame->clear();
        }
    }

private:
    uint8_t* umem_base_;
    uint32_t frame_size_;
    uint32_t num_frames_;
    uint32_t headroom_;
    std::vector<XDPFrame> frames_;
};

} // namespace xdp
} // namespace websocket

#endif // WEBSOCKET_XDP_FRAME_HPP
