// pipeline/msg_inbox.hpp
// Byte stream ring buffer for decrypted TLS data
// Transport writes, WebSocket/AppClient reads
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <cstring>
#include "pipeline_config.hpp"

namespace websocket::pipeline {

// ============================================================================
// MsgInbox - Single-producer single-consumer byte stream buffer
//
// Layout in shared memory:
//   - write_pos: Transport's write position (updated by Transport)
//   - app_consumed_pos: AppClient's consumed position (updated by AppClient)
//   - wrap_flag: Set when Transport wraps to beginning
//   - dirty_flag: Set if Transport overwrites unconsumed data (data loss)
//   - data[MSG_INBOX_SIZE]: Circular buffer for decrypted data
//
// Flow:
//   1. Transport writes decrypted SSL data via write_ptr() + advance_write()
//   2. WebSocket reads via data_at() using offsets from MsgMetadata
//   3. AppClient updates app_consumed_pos when done with data
//   4. Transport checks app_consumed_pos to avoid overwriting
//
// Wrap handling:
//   - When write_pos approaches end, Transport sets wrap_flag and resets to 0
//   - WebSocket sees wrap_flag and adjusts reading accordingly
//   - AppClient must handle wrapped payloads in on_message_wrapped()
// ============================================================================

struct MsgInbox {
    // Control fields (first cache line)
    alignas(64) std::atomic<uint32_t> write_pos;           // Transport's current write position
    std::atomic<uint32_t> app_consumed_pos;                // AppClient's consumed position
    std::atomic<uint8_t>  wrap_flag;                       // Set when write wraps to beginning
    std::atomic<uint8_t>  dirty_flag;                      // Data loss indicator
    uint8_t _pad[54];

    // Data buffer (starts at offset 64 for cache alignment)
    alignas(64) uint8_t data[MSG_INBOX_SIZE];

    // ========================================================================
    // Initialization
    // ========================================================================

    void init() {
        write_pos.store(0, std::memory_order_relaxed);
        app_consumed_pos.store(0, std::memory_order_relaxed);
        wrap_flag.store(0, std::memory_order_relaxed);
        dirty_flag.store(0, std::memory_order_relaxed);
    }

    // ========================================================================
    // Reader API (WebSocket/AppClient)
    // ========================================================================

    // Get pointer to data at offset (for reading)
    const uint8_t* data_at(uint32_t offset) const {
        return &data[offset % MSG_INBOX_SIZE];
    }

    // Get mutable pointer (for internal use)
    uint8_t* data_at_mut(uint32_t offset) {
        return &data[offset % MSG_INBOX_SIZE];
    }

    // Get current write position
    uint32_t get_write_pos() const {
        return write_pos.load(std::memory_order_acquire);
    }

    // Get current consumed position
    uint32_t get_app_consumed() const {
        return app_consumed_pos.load(std::memory_order_acquire);
    }

    // Set consumed position (AppClient updates this)
    void set_app_consumed(uint32_t pos) {
        app_consumed_pos.store(pos, std::memory_order_release);
    }

    // Check and clear wrap flag
    bool check_and_clear_wrap_flag() {
        return wrap_flag.exchange(0, std::memory_order_acq_rel) != 0;
    }

    // Check dirty flag (data loss occurred)
    bool is_dirty() const {
        return dirty_flag.load(std::memory_order_acquire) != 0;
    }

    // Clear dirty flag
    void clear_dirty() {
        dirty_flag.store(0, std::memory_order_release);
    }

    // ========================================================================
    // Writer API (Transport)
    // ========================================================================

    // Get pointer to write position
    uint8_t* write_ptr() {
        return &data[write_pos.load(std::memory_order_relaxed) % MSG_INBOX_SIZE];
    }

    // Get current write position (for calculating offsets)
    uint32_t current_write_pos() const {
        return write_pos.load(std::memory_order_relaxed);
    }

    // Advance write position after writing data
    void advance_write(uint32_t len) {
        uint32_t pos = write_pos.load(std::memory_order_relaxed);
        write_pos.store(pos + len, std::memory_order_release);
    }

    // Calculate linear space available before wrap
    uint32_t linear_space_to_wrap() const {
        uint32_t pos = write_pos.load(std::memory_order_relaxed) % MSG_INBOX_SIZE;
        return MSG_INBOX_SIZE - pos;
    }

    // Calculate available space considering consumer position
    uint32_t available_space() const {
        uint32_t wp = write_pos.load(std::memory_order_relaxed);
        uint32_t cp = app_consumed_pos.load(std::memory_order_acquire);

        // If positions haven't wrapped differently, simple subtraction
        // Note: Using modular arithmetic, (wp - cp) gives bytes written
        uint32_t used = wp - cp;  // Wraps correctly for uint32_t
        if (used >= MSG_INBOX_SIZE) {
            return 0;  // Buffer full or overflowed
        }
        return MSG_INBOX_SIZE - used - 1;  // Leave 1 byte to distinguish full from empty
    }

    // Set wrap flag and reset write position to beginning
    void set_wrap_flag() {
        wrap_flag.store(1, std::memory_order_release);
    }

    // Reset write position to head (after wrap)
    void reset_to_head() {
        write_pos.store(0, std::memory_order_release);
    }

    // Check if we're about to overwrite unconsumed data
    bool would_overwrite(uint32_t write_len) const {
        uint32_t wp = write_pos.load(std::memory_order_relaxed);
        uint32_t cp = app_consumed_pos.load(std::memory_order_acquire);

        // Calculate new write end position
        uint32_t new_wp = wp + write_len;

        // Check if write would lap the consumer
        // Using unsigned arithmetic: if (new_wp - cp) >= MSG_INBOX_SIZE, we'd overwrite
        return (new_wp - cp) >= MSG_INBOX_SIZE;
    }

    // Set dirty flag (called when overwriting unconsumed data)
    void set_dirty() {
        dirty_flag.store(1, std::memory_order_release);
    }

    // ========================================================================
    // Copy Helpers
    // ========================================================================

    // Write data handling wrap-around (for Transport)
    // Returns actual bytes written (may be less if would overwrite)
    uint32_t write_data(const uint8_t* src, uint32_t len) {
        uint32_t wp = write_pos.load(std::memory_order_relaxed);
        uint32_t pos_in_buf = wp % MSG_INBOX_SIZE;
        uint32_t linear = MSG_INBOX_SIZE - pos_in_buf;

        if (len <= linear) {
            // Fits without wrapping
            std::memcpy(&data[pos_in_buf], src, len);
        } else {
            // Need to wrap
            std::memcpy(&data[pos_in_buf], src, linear);
            std::memcpy(&data[0], src + linear, len - linear);
            set_wrap_flag();
        }

        write_pos.store(wp + len, std::memory_order_release);
        return len;
    }

    // Read data handling wrap-around (for WebSocket/AppClient)
    // offset: absolute position in stream
    // len: bytes to read
    // Returns true if data is contiguous, false if wrapped
    bool read_contiguous(uint32_t offset, uint32_t len, const uint8_t*& ptr) const {
        uint32_t pos_in_buf = offset % MSG_INBOX_SIZE;
        uint32_t linear = MSG_INBOX_SIZE - pos_in_buf;

        if (len <= linear) {
            ptr = &data[pos_in_buf];
            return true;
        }
        // Data wraps - caller must handle two segments
        ptr = &data[pos_in_buf];
        return false;
    }

    // Get second segment for wrapped read
    void get_wrapped_segments(uint32_t offset, uint32_t len,
                              const uint8_t*& seg1, uint32_t& seg1_len,
                              const uint8_t*& seg2, uint32_t& seg2_len) const {
        uint32_t pos_in_buf = offset % MSG_INBOX_SIZE;
        uint32_t linear = MSG_INBOX_SIZE - pos_in_buf;

        if (len <= linear) {
            seg1 = &data[pos_in_buf];
            seg1_len = len;
            seg2 = nullptr;
            seg2_len = 0;
        } else {
            seg1 = &data[pos_in_buf];
            seg1_len = linear;
            seg2 = &data[0];
            seg2_len = len - linear;
        }
    }
};

// Verify size (header + data buffer)
static_assert(offsetof(MsgInbox, data) == 64, "MsgInbox data must start at offset 64");

}  // namespace websocket::pipeline
