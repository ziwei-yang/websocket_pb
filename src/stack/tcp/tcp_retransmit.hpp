// src/stack/tcp/tcp_retransmit.hpp
// Zero-Copy TCP Retransmit Queue and Zero-Copy Receive Buffer (Internal)
//
// INTERNAL: These classes are used by transport policy, not by stack.
// Transport policy owns TCP state, including retransmit queue and receive buffer.
//
// Provides:
//   - ZeroCopyRetransmitQueue: Zero-copy retransmit tracking via UMEM frame references
//   - ZeroCopyReceiveBuffer: Zero-copy buffer holding UMEM frame pointers
//
// Note: Simplified for HFT (low packet loss, in-order delivery expected)

#pragma once

#include "tcp_state.hpp"
#include "../../core/timing.hpp"  // rdtsc()
#include <deque>
#include <vector>
#include <cstring>

namespace userspace_stack {

// ============================================================================
// Zero-Copy Retransmit Queue
// ============================================================================
//
// Instead of copying segment data, stores references to UMEM TX frames.
// Benefits:
//   - No memcpy on add_ref() - just stores frame index
//   - Fast retransmit - re-submit same frame, no rebuild/re-encrypt
//   - Uses TSC for timing (~20 cycles vs ~50-100 cycles for chrono)
//   - 24 bytes per segment vs 1488 bytes (62x reduction)
//
// Assumes:
//   - UMEM has sufficient frames (HFT scenario)
//   - TX completion always before ACK (NIC DMA ~μs, network RTT ~ms)

// Zero-copy segment reference (replaces RetransmitSegment)
struct RetransmitSegmentRef {
    uint32_t seq;              // TCP sequence number
    uint32_t frame_idx;        // UMEM frame index
    uint16_t frame_len;        // Total frame length for retransmit
    uint16_t payload_len;      // TCP payload length for ACK tracking (seq + payload_len = seg_end)
    uint8_t  retransmit_count;
    uint8_t  flags;            // TCP flags (for SYN/FIN seq adjustment)
    uint64_t send_cycle;       // TSC cycle at send time
};
// Size: 26 bytes (was 24, +2 for payload_len)

// Zero-copy retransmit queue
struct ZeroCopyRetransmitQueue {
    ZeroCopyRetransmitQueue() = default;

    // Initialize with TSC frequency (call once before use)
    void init(uint64_t tsc_freq_hz, uint32_t rto_ms) {
        tsc_freq_hz_ = tsc_freq_hz;
        rto_cycles_ = (static_cast<uint64_t>(rto_ms) * tsc_freq_hz) / 1000;
    }

    // Add segment reference (no data copy)
    // frame_len = total Ethernet frame length for retransmit
    // payload_len = TCP payload length for ACK tracking
    bool add_ref(uint32_t seq, uint8_t flags, uint32_t frame_idx, uint16_t frame_len, uint16_t payload_len) {
        if (queue_.size() >= max_queue_size_) {
            return false;
        }

        queue_.push_back({seq, frame_idx, frame_len, payload_len, 0, flags, rdtsc()});
        return true;
    }

    // Remove acknowledged segments, return frame indices for release
    std::vector<uint32_t> remove_acked(uint32_t ack_seq) {
        std::vector<uint32_t> released;

        while (!queue_.empty()) {
            const auto& ref = queue_.front();
            // Use payload_len for ACK tracking, not frame_len
            uint32_t seg_end = ref.seq + ref.payload_len;
            if (ref.flags & TCP_FLAG_SYN || ref.flags & TCP_FLAG_FIN) {
                seg_end++;
            }

            if (seq_le(seg_end, ack_seq)) {
                released.push_back(ref.frame_idx);
                queue_.pop_front();
            } else {
                break;
            }
        }
        return released;
    }

    // Get segments needing retransmission
    std::vector<RetransmitSegmentRef*> get_retransmit_refs() {
        std::vector<RetransmitSegmentRef*> refs;
        uint64_t now = rdtsc();

        for (auto& ref : queue_) {
            if (now - ref.send_cycle >= rto_cycles_ && ref.retransmit_count < max_retransmits_) {
                refs.push_back(&ref);
            }
        }
        return refs;
    }

    // Mark segment as retransmitted
    void mark_retransmitted(uint32_t seq) {
        for (auto& ref : queue_) {
            if (ref.seq == seq) {
                ref.send_cycle = rdtsc();
                ref.retransmit_count++;
                break;
            }
        }
    }

    // Check if any segment has exceeded max retransmits
    bool has_failed_segment() const {
        for (const auto& ref : queue_) {
            if (ref.retransmit_count >= max_retransmits_) {
                return true;
            }
        }
        return false;
    }

    size_t size() const { return queue_.size(); }
    bool empty() const { return queue_.empty(); }
    void clear() { queue_.clear(); }

    uint32_t get_oldest_seq() const {
        return queue_.empty() ? 0 : queue_.front().seq;
    }

private:
    std::deque<RetransmitSegmentRef> queue_;
    uint64_t tsc_freq_hz_ = 0;
    uint64_t rto_cycles_ = 0;
    size_t max_queue_size_ = 256;
    uint8_t max_retransmits_ = 5;
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
    const uint8_t* data;       // Pointer to TCP payload in UMEM
    uint16_t len;              // Payload length
    uint16_t offset;           // Current read offset within payload
    uint64_t umem_addr;        // UMEM address for releasing to FILL ring
    uint64_t hw_timestamp_ns;  // NIC hardware RX timestamp (0 if unavailable)
};

// Statistics from a read() operation
struct ReadStats {
    uint32_t packet_count = 0;        // Number of frames consumed
    uint64_t oldest_timestamp_ns = 0; // Oldest HW timestamp in consumed frames
    uint64_t latest_timestamp_ns = 0; // Latest HW timestamp in consumed frames
};

struct ZeroCopyReceiveBuffer {
    ZeroCopyReceiveBuffer() = default;

    // Set the frame release callback
    // Called when a frame is fully consumed and can be returned to FILL ring
    void set_release_callback(FrameReleaseCallback cb, void* user_data) {
        release_cb_ = cb;
        release_user_data_ = user_data;
    }

    // Add a received frame (zero-copy - just stores pointer)
    // Returns false if buffer is full
    bool push_frame(const uint8_t* payload, uint16_t len, uint64_t umem_addr,
                    uint64_t hw_timestamp_ns = 0) {
        if (count_ >= MAX_FRAMES) {
            return false;  // Buffer full
        }

        frames_[tail_] = {payload, len, 0, umem_addr, hw_timestamp_ns};
        tail_ = (tail_ + 1) % MAX_FRAMES;
        count_++;
        return true;
    }

    // Read data across frames (scatter-gather read)
    // Only copies when reading - the final necessary copy to output buffer
    // Tracks ReadStats for frames consumed during this read
    ssize_t read(uint8_t* output, size_t max_len) {
        // Reset stats at start of each read
        last_read_stats_ = {};

        if (count_ == 0) {
            return 0;  // No data available
        }

        size_t total_read = 0;

        while (total_read < max_len && count_ > 0) {
            FrameRef& frame = frames_[head_];

            // Track stats when starting to read from a new frame (offset == 0)
            if (frame.offset == 0 && frame.hw_timestamp_ns > 0) {
                last_read_stats_.packet_count++;
                if (last_read_stats_.oldest_timestamp_ns == 0) {
                    last_read_stats_.oldest_timestamp_ns = frame.hw_timestamp_ns;
                }
                last_read_stats_.latest_timestamp_ns = frame.hw_timestamp_ns;
            }

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

    // Get stats from the last read() operation
    const ReadStats& get_last_read_stats() const { return last_read_stats_; }

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

private:
    static constexpr size_t MAX_FRAMES = 256;  // Max frames in flight

    FrameRef frames_[MAX_FRAMES];   // Circular buffer of frame refs
    size_t head_ = 0;               // Next frame to read from
    size_t tail_ = 0;               // Next slot to write to
    size_t count_ = 0;              // Number of frames in buffer

    // Callback for releasing frames
    FrameReleaseCallback release_cb_ = nullptr;
    void* release_user_data_ = nullptr;

    // Stats from last read() operation
    ReadStats last_read_stats_;
};

} // namespace userspace_stack
