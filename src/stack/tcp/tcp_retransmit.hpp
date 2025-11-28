// src/stack/tcp/tcp_retransmit.hpp
// TCP Retransmit Queue and Receive Buffer (Internal)
//
// INTERNAL: These classes are used by transport policy, not by stack.
// Transport policy owns TCP state, including retransmit queue and receive buffer.
//
// Provides:
//   - RetransmitQueue: Tracks unacknowledged segments for retransmission
//   - ReceiveBuffer: Simple buffer for in-order TCP data reception
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

// Receive buffer for out-of-order segments (simplified)
// For HFT, we expect in-order delivery, so this is minimal
class ReceiveBuffer {
private:
    static constexpr size_t BUFFER_SIZE = 65536;  // 64KB buffer
    uint8_t buffer_[BUFFER_SIZE];
    size_t write_pos_ = 0;
    size_t read_pos_ = 0;

public:
    ReceiveBuffer() = default;

    // Append data to buffer
    bool append(const uint8_t* data, size_t len) {
        if (len == 0) return true;

        size_t available = BUFFER_SIZE - write_pos_;
        if (len > available) {
            return false;  // Buffer full
        }

        std::memcpy(buffer_ + write_pos_, data, len);
        write_pos_ += len;
        return true;
    }

    // Read data from buffer
    ssize_t read(uint8_t* output, size_t max_len) {
        if (write_pos_ == read_pos_) {
            return 0;  // No data available
        }

        size_t available = write_pos_ - read_pos_;
        size_t to_read = std::min(available, max_len);

        std::memcpy(output, buffer_ + read_pos_, to_read);
        read_pos_ += to_read;

        // Reset positions if buffer is empty
        if (read_pos_ == write_pos_) {
            read_pos_ = 0;
            write_pos_ = 0;
        }

        return static_cast<ssize_t>(to_read);
    }

    // Get available data size
    size_t available() const {
        return write_pos_ - read_pos_;
    }

    // Check if buffer is empty
    bool empty() const {
        return write_pos_ == read_pos_;
    }

    // Get free space
    size_t free_space() const {
        // After reading, we compact the buffer
        return BUFFER_SIZE - (write_pos_ - read_pos_);
    }

    // Clear buffer
    void clear() {
        write_pos_ = 0;
        read_pos_ = 0;
    }
};

} // namespace userspace_stack
