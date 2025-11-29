// src/stack/tcp/tcp_retransmit.hpp
// TCP Retransmit Queue and Zero-Copy Receive Buffer (Internal)
//
// INTERNAL: These classes are used by transport policy, not by stack.
// Transport policy owns TCP state, including retransmit queue and receive buffer.
//
// Provides:
//   - RetransmitQueue: Tracks unacknowledged segments for retransmission
//   - ZeroCopyReceiveBuffer: Zero-copy buffer holding UMEM frame pointers
//
// Note: Simplified for HFT (low packet loss, in-order delivery expected)

#pragma once

#include "tcp_state.hpp"
#include <deque>
#include <vector>
#include <cstring>
#include <chrono>

namespace userspace_stack {

// Retransmission segment
struct RetransmitSegment {
    uint32_t seq;                // Sequence number
    uint8_t flags;               // TCP flags
    uint8_t data[USERSPACE_TCP_MSS];       // Segment data
    uint16_t len;                // Data length
    uint64_t send_time_us;       // Send time (microseconds)
    uint8_t retransmit_count;    // Number of retransmissions
};

class RetransmitQueue {
private:
    std::deque<RetransmitSegment> queue_;
    size_t max_queue_size_ = 256;  // Maximum queue size
    uint8_t max_retransmits_ = 5;  // Maximum retransmissions before giving up

public:
    RetransmitQueue() = default;

    // Add segment to queue
    bool add_segment(uint32_t seq, uint8_t flags, const uint8_t* data, uint16_t len) {
        if (queue_.size() >= max_queue_size_) {
            return false;  // Queue full
        }

        if (len > USERSPACE_TCP_MSS) {
            return false;  // Invalid length
        }

        RetransmitSegment seg;
        seg.seq = seq;
        seg.flags = flags;
        seg.len = len;
        seg.send_time_us = get_time_us();
        seg.retransmit_count = 0;

        if (data && len > 0) {
            std::memcpy(seg.data, data, len);
        }

        queue_.push_back(seg);
        return true;
    }

    // Remove acknowledged segments (up to ack_seq)
    // Returns number of segments removed
    size_t remove_acked(uint32_t ack_seq) {
        size_t removed = 0;

        while (!queue_.empty()) {
            const auto& seg = queue_.front();

            // Calculate segment end sequence
            uint32_t seg_end = seg.seq + seg.len;
            if (seg.flags & TCP_FLAG_SYN || seg.flags & TCP_FLAG_FIN) {
                seg_end++;  // SYN and FIN consume one sequence number
            }

            // Check if segment is fully acknowledged
            if (seq_le(seg_end, ack_seq)) {
                queue_.pop_front();
                removed++;
            } else {
                break;  // Remaining segments not yet acknowledged
            }
        }

        return removed;
    }

    // Get segments that need retransmission
    // rto_ms: Retransmission timeout in milliseconds
    // Returns segments to retransmit
    std::vector<RetransmitSegment*> get_retransmit_segments(uint32_t rto_ms) {
        std::vector<RetransmitSegment*> segments;
        uint64_t now = get_time_us();
        uint64_t rto_us = static_cast<uint64_t>(rto_ms) * 1000;

        for (auto& seg : queue_) {
            // Check if segment timed out
            if (now - seg.send_time_us >= rto_us) {
                if (seg.retransmit_count < max_retransmits_) {
                    segments.push_back(&seg);
                }
                // If max retransmits reached, connection is dead (handled elsewhere)
            }
        }

        return segments;
    }

    // Update send time for retransmitted segment
    void mark_retransmitted(uint32_t seq) {
        for (auto& seg : queue_) {
            if (seg.seq == seq) {
                seg.send_time_us = get_time_us();
                seg.retransmit_count++;
                break;
            }
        }
    }

    // Check if any segment has exceeded max retransmits
    bool has_failed_segment() const {
        for (const auto& seg : queue_) {
            if (seg.retransmit_count >= max_retransmits_) {
                return true;
            }
        }
        return false;
    }

    // Get queue size
    size_t size() const {
        return queue_.size();
    }

    // Check if queue is empty
    bool empty() const {
        return queue_.empty();
    }

    // Clear queue
    void clear() {
        queue_.clear();
    }

    // Get oldest unacknowledged sequence number
    uint32_t get_oldest_seq() const {
        if (queue_.empty()) {
            return 0;
        }
        return queue_.front().seq;
    }

private:
    // Get current time in microseconds
    static uint64_t get_time_us() {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(
            now.time_since_epoch()).count();
    }
};

// ============================================================================
// Zero-Copy Receive Buffer
// ============================================================================
//
// Instead of copying TCP payload into a linear buffer, this keeps pointers
// to UMEM frames and reads directly from them. Frames are released back to
// the FILL ring only after SSL has fully consumed them.
//
// Benefits:
//   - Eliminates one memcpy (TCP payload → buffer)
//   - Data stays in UMEM until final consumer (SSL) reads it
//
// Trade-offs:
//   - UMEM frames held longer (until SSL consumes)
//   - More complex frame lifetime management
//   - Higher FILL ring pressure under load

// Callback type for releasing frames back to XDP
using FrameReleaseCallback = void(*)(uint64_t umem_addr, void* user_data);

// Reference to a received frame's TCP payload
struct FrameRef {
    const uint8_t* data;    // Pointer to TCP payload in UMEM
    uint16_t len;           // Payload length
    uint16_t offset;        // Current read offset within payload
    uint64_t umem_addr;     // UMEM address for releasing to FILL ring
};

class ZeroCopyReceiveBuffer {
private:
    static constexpr size_t MAX_FRAMES = 256;  // Max frames in flight

    FrameRef frames_[MAX_FRAMES];   // Circular buffer of frame refs
    size_t head_ = 0;               // Next frame to read from
    size_t tail_ = 0;               // Next slot to write to
    size_t count_ = 0;              // Number of frames in buffer

    // Callback for releasing frames
    FrameReleaseCallback release_cb_ = nullptr;
    void* release_user_data_ = nullptr;

public:
    ZeroCopyReceiveBuffer() = default;

    // Set the frame release callback
    // Called when a frame is fully consumed and can be returned to FILL ring
    void set_release_callback(FrameReleaseCallback cb, void* user_data) {
        release_cb_ = cb;
        release_user_data_ = user_data;
    }

    // Add a received frame (zero-copy - just stores pointer)
    // Returns false if buffer is full
    bool push_frame(const uint8_t* payload, uint16_t len, uint64_t umem_addr) {
        if (count_ >= MAX_FRAMES) {
            return false;  // Buffer full
        }

        frames_[tail_] = {payload, len, 0, umem_addr};
        tail_ = (tail_ + 1) % MAX_FRAMES;
        count_++;
        return true;
    }

    // Read data across frames (scatter-gather read)
    // Only copies when reading - the final necessary copy to output buffer
    ssize_t read(uint8_t* output, size_t max_len) {
        if (count_ == 0) {
            return 0;  // No data available
        }

        size_t total_read = 0;

        while (total_read < max_len && count_ > 0) {
            FrameRef& frame = frames_[head_];

            // How much left in this frame?
            size_t remaining = frame.len - frame.offset;
            size_t to_read = std::min(remaining, max_len - total_read);

            // Copy from UMEM to output (only copy)
            std::memcpy(output + total_read, frame.data + frame.offset, to_read);
            frame.offset += to_read;
            total_read += to_read;

            // Frame fully consumed?
            if (frame.offset >= frame.len) {
                // Release frame back to FILL ring
                if (release_cb_) {
                    release_cb_(frame.umem_addr, release_user_data_);
                }

                head_ = (head_ + 1) % MAX_FRAMES;
                count_--;
            }
        }

        return static_cast<ssize_t>(total_read);
    }

    // Get total available bytes across all frames
    size_t available() const {
        size_t total = 0;
        size_t idx = head_;
        for (size_t i = 0; i < count_; i++) {
            total += frames_[idx].len - frames_[idx].offset;
            idx = (idx + 1) % MAX_FRAMES;
        }
        return total;
    }

    // Check if buffer has no data
    bool empty() const {
        return count_ == 0;
    }

    // Get number of frames held
    size_t frame_count() const {
        return count_;
    }

    // Clear buffer and release all frames
    void clear() {
        while (count_ > 0) {
            if (release_cb_) {
                release_cb_(frames_[head_].umem_addr, release_user_data_);
            }
            head_ = (head_ + 1) % MAX_FRAMES;
            count_--;
        }
        head_ = 0;
        tail_ = 0;
    }
};

} // namespace userspace_stack
