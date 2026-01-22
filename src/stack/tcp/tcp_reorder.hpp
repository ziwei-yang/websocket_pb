// src/stack/tcp/tcp_reorder.hpp
// Zero-copy TCP out-of-order segment reordering buffer
//
// Design:
//   - Template-based to decouple from UMEM/pipeline types
//   - Zero-copy: stores pointers to external data, no copying
//   - Fixed-size buffer for predictable memory usage
//   - Callback-based delivery for flexible integration
//
// Usage:
//   ZeroCopyTCPReorderBuffer<const uint8_t*> ooo_buffer;
//
//   // Buffer an OOO segment
//   if (!ooo_buffer.is_buffered(seq)) {
//       ooo_buffer.buffer_segment(seq, len, payload_ptr);
//   }
//
//   // Deliver in-order segments
//   ooo_buffer.try_deliver(rcv_nxt, [](const uint8_t* data, uint16_t offset, uint16_t len) {
//       // Process data + offset, len bytes
//       return true;  // Continue delivery
//   });

#pragma once

#include <cstdint>
#include <cstddef>
#include <climits>

#include "tcp_state.hpp"  // For SACKBlock, SACKBlockArray, SACK_MAX_BLOCKS

namespace userspace_stack {

// ----------------------------------------------------------------------------
// ZeroCopyOOOSegment: Single out-of-order segment descriptor
// ----------------------------------------------------------------------------

template<typename PayloadPtr>
struct ZeroCopyOOOSegment {
    uint32_t seq = 0;           // TCP sequence number
    uint16_t len = 0;           // Payload length in bytes
    bool valid = false;         // Is this slot in use?
    PayloadPtr data{};          // Pointer to payload data (zero-copy)
    int64_t ext_id = -1;        // External ID (e.g., UMEM ring position for safe commit)

    void clear() {
        seq = 0;
        len = 0;
        valid = false;
        data = PayloadPtr{};
        ext_id = -1;
    }
};

// ----------------------------------------------------------------------------
// ZeroCopyTCPReorderBuffer: Fixed-size OOO segment buffer
// ----------------------------------------------------------------------------

template<typename PayloadPtr, size_t MaxSegments = 8>
class ZeroCopyTCPReorderBuffer {
public:
    using Segment = ZeroCopyOOOSegment<PayloadPtr>;

    // ------------------------------------------------------------------------
    // Buffer Management
    // ------------------------------------------------------------------------

    /**
     * Buffer an out-of-order segment
     * @param seq TCP sequence number
     * @param len Payload length
     * @param data Pointer to payload (must remain valid until delivered)
     * @param ext_id External ID (e.g., UMEM ring position) for tracking, -1 if unused
     * @return true if buffered, false if buffer full
     */
    bool buffer_segment(uint32_t seq, uint16_t len, PayloadPtr data, int64_t ext_id = -1) {
        if (count_ >= MaxSegments) {
            return false;  // Buffer full
        }

        // Find empty slot
        for (size_t i = 0; i < MaxSegments; i++) {
            if (!segments_[i].valid) {
                segments_[i].seq = seq;
                segments_[i].len = len;
                segments_[i].data = data;
                segments_[i].ext_id = ext_id;
                segments_[i].valid = true;
                count_++;
                // Track minimum ext_id for safe commit
                if (ext_id >= 0 && ext_id < min_ext_id_) {
                    min_ext_id_ = ext_id;
                }
                return true;
            }
        }
        return false;  // Should not reach here if count_ < MaxSegments
    }

    /**
     * Check if a segment with given sequence number is already buffered
     * @param seq TCP sequence number to check
     * @return true if segment exists in buffer
     */
    bool is_buffered(uint32_t seq) const {
        for (size_t i = 0; i < MaxSegments; i++) {
            if (segments_[i].valid && segments_[i].seq == seq) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------------
    // Delivery
    // ------------------------------------------------------------------------

    /**
     * Try to deliver in-order segments via callback
     *
     * Iterates through buffered segments and delivers any that are now in-order.
     * Handles exact matches, overlaps, and duplicates.
     *
     * @param rcv_nxt Current receive next sequence number (updated on delivery)
     * @param callback Called for each deliverable segment:
     *                 bool callback(PayloadPtr data, uint16_t offset, uint16_t len)
     *                 - data: pointer to segment payload
     *                 - offset: bytes to skip (for overlap handling)
     *                 - len: bytes to deliver (after offset)
     *                 Returns true if delivered successfully, false to abort
     * @return Number of segments delivered
     */
    template<typename DeliverCallback>
    size_t try_deliver(uint32_t& rcv_nxt, DeliverCallback&& callback) {
        size_t delivered = 0;
        bool need_recompute_min = false;

        while (count_ > 0) {
            bool found = false;

            for (size_t i = 0; i < MaxSegments; i++) {
                if (!segments_[i].valid) continue;

                uint32_t seg_seq = segments_[i].seq;
                uint32_t seg_end = seg_seq + segments_[i].len;
                int32_t diff = static_cast<int32_t>(seg_seq - rcv_nxt);

                if (diff == 0) {
                    // Exact match: segment starts at rcv_nxt
                    if (!callback(segments_[i].data, 0, segments_[i].len)) {
                        return delivered;  // Callback failed, stop delivery
                    }
                    rcv_nxt += segments_[i].len;
                    // Track if we need to recompute min_ext_id
                    if (segments_[i].ext_id >= 0 && segments_[i].ext_id == min_ext_id_) {
                        need_recompute_min = true;
                    }
                    segments_[i].clear();
                    count_--;
                    delivered++;
                    found = true;
                    break;

                } else if (diff < 0 && static_cast<int32_t>(seg_end - rcv_nxt) > 0) {
                    // Overlap: segment starts before rcv_nxt but extends past it
                    uint16_t overlap = static_cast<uint16_t>(rcv_nxt - seg_seq);
                    uint16_t useful_len = segments_[i].len - overlap;

                    if (!callback(segments_[i].data, overlap, useful_len)) {
                        return delivered;  // Callback failed, stop delivery
                    }
                    rcv_nxt += useful_len;
                    // Track if we need to recompute min_ext_id
                    if (segments_[i].ext_id >= 0 && segments_[i].ext_id == min_ext_id_) {
                        need_recompute_min = true;
                    }
                    segments_[i].clear();
                    count_--;
                    delivered++;
                    found = true;
                    break;

                } else if (diff < 0) {
                    // Fully duplicate: segment entirely before rcv_nxt
                    // Track if we need to recompute min_ext_id
                    if (segments_[i].ext_id >= 0 && segments_[i].ext_id == min_ext_id_) {
                        need_recompute_min = true;
                    }
                    segments_[i].clear();
                    count_--;
                    found = true;
                    break;
                }
                // diff > 0: Still out-of-order, skip
            }

            if (!found) break;  // No more deliverable segments
        }

        // Recompute min_ext_id if we removed the segment with minimum ext_id
        if (need_recompute_min) {
            recompute_min_ext_id();
        }

        return delivered;
    }

    // ------------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------------

    void clear() {
        for (size_t i = 0; i < MaxSegments; i++) {
            segments_[i].clear();
        }
        count_ = 0;
        min_ext_id_ = INT64_MAX;
    }

    size_t count() const { return count_; }
    bool is_full() const { return count_ >= MaxSegments; }
    bool is_empty() const { return count_ == 0; }

    static constexpr size_t max_segments() { return MaxSegments; }

    // Debug: dump OOO buffer contents to stderr
    void debug_dump(const char* prefix = "[OOO-DUMP]") const {
        fprintf(stderr, "%s count=%zu segments:", prefix, count_);
        for (size_t i = 0; i < MaxSegments; i++) {
            if (segments_[i].valid) {
                fprintf(stderr, " [seq=%u len=%u ext=%ld]",
                        segments_[i].seq, segments_[i].len, segments_[i].ext_id);
            }
        }
        fprintf(stderr, "\n");
    }

    // Minimum ext_id among all buffered segments (for safe commit)
    // Returns INT64_MAX if no segments have ext_id set
    int64_t min_ext_id() const { return min_ext_id_; }

    // Returns true if any segment has a valid ext_id (not INT64_MAX)
    bool has_ext_id_segments() const { return min_ext_id_ != INT64_MAX; }

    // ------------------------------------------------------------------------
    // SACK Block Extraction (RFC 2018)
    // ------------------------------------------------------------------------

    /**
     * Extract SACK blocks from buffered OOO segments
     *
     * Collects all segments beyond rcv_nxt, sorts by sequence number,
     * merges adjacent/overlapping ranges, and returns up to SACK_MAX_BLOCKS.
     *
     * @param rcv_nxt Current receive next sequence number
     * @param out Output array to store SACK blocks
     * @return Number of blocks extracted (0 to SACK_MAX_BLOCKS)
     */
    uint8_t extract_sack_blocks(uint32_t rcv_nxt, SACKBlockArray& out) const {
        out.clear();
        if (count_ == 0) return 0;

        // Collect valid segments beyond rcv_nxt into temporary array
        struct SegRange {
            uint32_t left;
            uint32_t right;
        };
        SegRange ranges[MaxSegments];
        size_t range_count = 0;

        for (size_t i = 0; i < MaxSegments; i++) {
            if (!segments_[i].valid) continue;

            uint32_t seg_seq = segments_[i].seq;
            uint32_t seg_end = seg_seq + segments_[i].len;

            // Only include segments that start after rcv_nxt (truly OOO)
            int32_t diff = static_cast<int32_t>(seg_seq - rcv_nxt);
            if (diff > 0) {
                ranges[range_count].left = seg_seq;
                ranges[range_count].right = seg_end;
                range_count++;
            }
        }

        if (range_count == 0) return 0;

        // Simple insertion sort by left edge (small array, O(n^2) is fine)
        for (size_t i = 1; i < range_count; i++) {
            SegRange key = ranges[i];
            size_t j = i;
            while (j > 0 && static_cast<int32_t>(ranges[j-1].left - key.left) > 0) {
                ranges[j] = ranges[j-1];
                j--;
            }
            ranges[j] = key;
        }

        // Merge overlapping/adjacent ranges
        SACKBlock merged[MaxSegments];
        size_t merged_count = 0;

        merged[0].left_edge = ranges[0].left;
        merged[0].right_edge = ranges[0].right;
        merged_count = 1;

        for (size_t i = 1; i < range_count; i++) {
            SACKBlock& last = merged[merged_count - 1];
            // Check if ranges overlap or are adjacent (right_edge >= next left)
            int32_t gap = static_cast<int32_t>(ranges[i].left - last.right_edge);
            if (gap <= 0) {
                // Merge: extend right edge if needed
                if (static_cast<int32_t>(ranges[i].right - last.right_edge) > 0) {
                    last.right_edge = ranges[i].right;
                }
            } else {
                // New block
                merged[merged_count].left_edge = ranges[i].left;
                merged[merged_count].right_edge = ranges[i].right;
                merged_count++;
            }
        }

        // Copy up to SACK_MAX_BLOCKS to output
        out.count = static_cast<uint8_t>(merged_count > SACK_MAX_BLOCKS ? SACK_MAX_BLOCKS : merged_count);
        for (uint8_t i = 0; i < out.count; i++) {
            out.blocks[i] = merged[i];
        }

        return out.count;
    }

private:
    // Recompute min_ext_id by scanning all valid segments
    void recompute_min_ext_id() {
        min_ext_id_ = INT64_MAX;
        for (size_t i = 0; i < MaxSegments; i++) {
            if (segments_[i].valid && segments_[i].ext_id >= 0 &&
                segments_[i].ext_id < min_ext_id_) {
                min_ext_id_ = segments_[i].ext_id;
            }
        }
    }

    Segment segments_[MaxSegments];
    size_t count_ = 0;
    int64_t min_ext_id_ = INT64_MAX;  // Minimum ext_id for safe commit tracking
};

}  // namespace userspace_stack
