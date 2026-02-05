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
//
// HFT DESIGN: Uses fixed-size circular arrays instead of std::deque
//   - No heap allocation in hot path
//   - Predictable memory layout for cache efficiency
//   - Deterministic latency

#pragma once

#include "tcp_state.hpp"
#include "../../core/timing.hpp"  // rdtsc()
#include <cstring>
#include <cstdint>

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
//   - Fixed-size circular array (no heap allocation)
//
// Assumes:
//   - UMEM has sufficient frames (HFT scenario)
//   - TX completion always before ACK (NIC DMA ~us, network RTT ~ms)

// Zero-copy segment reference
struct RetransmitSegmentRef {
    uint32_t seq;              // TCP sequence number
    uint32_t frame_idx;        // UMEM frame index
    uint16_t frame_len;        // Total frame length for retransmit
    uint16_t payload_len;      // TCP payload length for ACK tracking (seq + payload_len = seg_end)
    uint8_t  retransmit_count;
    uint8_t  flags;            // TCP flags (for SYN/FIN seq adjustment)
    uint64_t send_cycle;       // TSC cycle at send time
};
// Size: 26 bytes

// Zero-copy retransmit queue - Fixed-size circular array (no heap allocation)
struct ZeroCopyRetransmitQueue {
    static constexpr size_t MAX_SEGMENTS = 1024;      // Max segments in flight
    static constexpr uint8_t MAX_RETRANSMITS = 5;     // Connection dead after this many retries

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
        if (count_ >= MAX_SEGMENTS) {
            return false;
        }

        segments_[tail_] = {seq, frame_idx, frame_len, payload_len, 0, flags, rdtsc()};
        tail_ = (tail_ + 1) % MAX_SEGMENTS;
        count_++;
        return true;
    }

    // Remove acknowledged segments, return count of released frames
    // Populates released_frames array with frame indices (caller provides buffer)
    size_t remove_acked(uint32_t ack_seq, uint32_t* released_frames = nullptr, size_t max_released = 0) {
        size_t released_count = 0;

        while (count_ > 0) {
            RetransmitSegmentRef& ref = segments_[head_];
            // Use payload_len for ACK tracking, not frame_len
            uint32_t seg_end = ref.seq + ref.payload_len;
            if (ref.flags & TCP_FLAG_SYN || ref.flags & TCP_FLAG_FIN) {
                seg_end++;
            }

            if (seq_le(seg_end, ack_seq)) {
                if (released_frames && released_count < max_released) {
                    released_frames[released_count] = ref.frame_idx;
                }
                released_count++;
                head_ = (head_ + 1) % MAX_SEGMENTS;
                count_--;
            } else {
                break;
            }
        }
        return released_count;
    }

    // Iterate ALL expired segments via lambda callback (zero allocation)
    // Lambda signature: bool(RetransmitSegmentRef& seg) - return false to stop iteration
    // Returns number of segments where callback returned true
    template<typename Func>
    size_t for_each_expired(uint64_t now_tsc, uint64_t rto_cycles, Func&& callback) {
        size_t processed = 0;
        size_t idx = head_;
        size_t remaining = count_;

        while (remaining > 0) {
            RetransmitSegmentRef& seg = segments_[idx];
            if (now_tsc - seg.send_cycle >= rto_cycles) {
                if (!callback(seg)) {
                    break;  // Callback requested stop
                }
                processed++;
            }
            idx = (idx + 1) % MAX_SEGMENTS;
            remaining--;
        }
        return processed;
    }

    // Mark segment as retransmitted (by seq)
    // Updates send_cycle and increments retransmit_count
    void mark_retransmitted(uint32_t seq, uint64_t now_tsc) {
        size_t idx = head_;
        size_t remaining = count_;
        while (remaining > 0) {
            if (segments_[idx].seq == seq) {
                segments_[idx].send_cycle = now_tsc;
                segments_[idx].retransmit_count++;
                return;
            }
            idx = (idx + 1) % MAX_SEGMENTS;
            remaining--;
        }
    }

    // Check if any segment has exceeded max retransmits
    bool has_failed_segment() const {
        size_t idx = head_;
        size_t remaining = count_;
        while (remaining > 0) {
            if (segments_[idx].retransmit_count >= MAX_RETRANSMITS) {
                return true;
            }
            idx = (idx + 1) % MAX_SEGMENTS;
            remaining--;
        }
        return false;
    }

    size_t size() const { return count_; }
    bool empty() const { return count_ == 0; }

    void clear() {
        head_ = 0;
        tail_ = 0;
        count_ = 0;
    }

    uint32_t get_oldest_seq() const {
        return count_ == 0 ? 0 : segments_[head_].seq;
    }

    // Access internal RTO cycles (for use with for_each_expired)
    uint64_t get_rto_cycles() const { return rto_cycles_; }

private:
    RetransmitSegmentRef segments_[MAX_SEGMENTS];  // Fixed-size circular buffer
    size_t head_ = 0;                              // Pop from here
    size_t tail_ = 0;                              // Push to here
    size_t count_ = 0;                             // Current number of entries
    uint64_t tsc_freq_hz_ = 0;
    uint64_t rto_cycles_ = 0;
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
//   - Eliminates one memcpy (TCP payload -> buffer)
//   - Data stays in UMEM until final consumer (SSL) reads it
//
// Trade-offs:
//   - UMEM frames held longer (until SSL consumes)
//   - More complex frame lifetime management
//   - Higher FILL ring pressure under load

// Callback type for releasing frames back to XDP
// Uses frame_idx for the new mark_frame_consumed() API
using FrameReleaseCallback = void(*)(uint32_t frame_idx, void* user_data);

// Reference to a received frame's TCP payload
struct FrameRef {
    const uint8_t* data;       // Pointer to TCP payload in UMEM
    uint16_t len;              // Payload length
    uint16_t offset;           // Current read offset within payload
    uint32_t frame_idx;        // RX frame index for mark_frame_consumed()
    uint64_t umem_addr;        // UMEM address (frame pointer, kept for compatibility)
    uint64_t hw_timestamp_ns;  // NIC hardware RX timestamp (0 if unavailable)
    uint64_t bpf_entry_ns;    // BPF entry bpf_ktime_get_ns() (CLOCK_MONOTONIC ns)
    uint64_t poll_cycle;       // XDP Poll rdtscp cycle when packet was polled
};

// Statistics from a read() operation
struct ReadStats {
    uint32_t packet_count = 0;        // Number of frames consumed
    uint64_t oldest_timestamp_ns = 0; // Oldest HW timestamp in consumed frames
    uint64_t latest_timestamp_ns = 0; // Latest HW timestamp in consumed frames
    uint64_t oldest_bpf_entry_ns = 0; // Oldest BPF entry timestamp
    uint64_t latest_bpf_entry_ns = 0; // Latest BPF entry timestamp
    uint64_t oldest_poll_cycle = 0;   // Oldest XDP Poll rdtscp cycle
    uint64_t latest_poll_cycle = 0;   // Latest XDP Poll rdtscp cycle
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
    // Parameters:
    //   - payload: pointer to TCP payload data in UMEM
    //   - len: payload length
    //   - frame_idx: RX frame index for mark_frame_consumed()
    //   - umem_addr: UMEM address (frame pointer, for compatibility)
    //   - hw_timestamp_ns: NIC hardware RX timestamp (0 if unavailable)
    bool push_frame(const uint8_t* payload, uint16_t len, uint32_t frame_idx,
                    uint64_t umem_addr, uint64_t hw_timestamp_ns = 0,
                    uint64_t bpf_entry_ns = 0, uint64_t poll_cycle = 0) {
        if (count_ >= MAX_FRAMES) {
            return false;  // Buffer full
        }

        frames_[tail_] = {payload, len, 0, frame_idx, umem_addr,
                          hw_timestamp_ns, bpf_entry_ns, poll_cycle};
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
            if (frame.offset == 0) {
                if (frame.hw_timestamp_ns > 0) {
                    last_read_stats_.packet_count++;
                    if (last_read_stats_.oldest_timestamp_ns == 0) {
                        last_read_stats_.oldest_timestamp_ns = frame.hw_timestamp_ns;
                    }
                    last_read_stats_.latest_timestamp_ns = frame.hw_timestamp_ns;
                }
                if (frame.bpf_entry_ns > 0) {
                    if (last_read_stats_.oldest_bpf_entry_ns == 0) {
                        last_read_stats_.oldest_bpf_entry_ns = frame.bpf_entry_ns;
                    }
                    last_read_stats_.latest_bpf_entry_ns = frame.bpf_entry_ns;
                }
                if (frame.poll_cycle > 0) {
                    if (last_read_stats_.oldest_poll_cycle == 0) {
                        last_read_stats_.oldest_poll_cycle = frame.poll_cycle;
                    }
                    last_read_stats_.latest_poll_cycle = frame.poll_cycle;
                }
            }

            // How much left in this frame?
            size_t remaining = frame.len - frame.offset;
            size_t to_read = remaining < (max_len - total_read) ? remaining : (max_len - total_read);

            // Copy from UMEM to output (only copy)
            std::memcpy(output + total_read, frame.data + frame.offset, to_read);
            frame.offset += to_read;
            total_read += to_read;

            // Frame fully consumed?
            if (frame.offset >= frame.len) {
                // Release frame back to FILL ring via mark_frame_consumed()
                if (release_cb_) {
                    release_cb_(frame.frame_idx, release_user_data_);
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

    // Read up to MaxLen bytes without consuming (non-destructive peek)
    // Walks frames from head_ respecting offset, copies to output.
    // Does NOT advance head_, offset, or release frames.
    // MaxLen capped at 64 — larger peeks contradict zero-copy design.
    template <size_t MaxLen>
    size_t peek(uint8_t* output) const {
        static_assert(MaxLen <= 64, "peek MaxLen must be <= 64 (use zero-copy read for larger)");
        if (count_ == 0) return 0;

        size_t total_read = 0;
        size_t idx = head_;
        size_t remaining_frames = count_;

        // Start from current offset of head frame
        size_t frame_pos = frames_[idx].offset;

        while (total_read < MaxLen && remaining_frames > 0) {
            const FrameRef& frame = frames_[idx];
            size_t avail = frame.len - frame_pos;
            size_t to_copy = (MaxLen - total_read < avail) ? (MaxLen - total_read) : avail;

            std::memcpy(output + total_read, frame.data + frame_pos, to_copy);
            total_read += to_copy;
            frame_pos += to_copy;

            if (frame_pos >= frame.len) {
                idx = (idx + 1) % MAX_FRAMES;
                remaining_frames--;
                frame_pos = 0;  // Next frame starts at offset 0
            }
        }

        return total_read;
    }

    // Consume N bytes without copying (advance offset, release fully consumed frames)
    // Used after ssl_read_by_chunk() has already processed the data via peek().
    void skip(size_t n) {
        size_t remaining = n;

        while (remaining > 0 && count_ > 0) {
            FrameRef& frame = frames_[head_];
            size_t avail = frame.len - frame.offset;

            if (remaining >= avail) {
                // Consume entire remaining frame
                remaining -= avail;

                // Release frame back to FILL ring
                if (release_cb_) {
                    release_cb_(frame.frame_idx, release_user_data_);
                }

                head_ = (head_ + 1) % MAX_FRAMES;
                count_--;
            } else {
                // Partial consume within frame
                frame.offset += static_cast<uint16_t>(remaining);
                remaining = 0;
            }
        }
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
                release_cb_(frames_[head_].frame_idx, release_user_data_);
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
