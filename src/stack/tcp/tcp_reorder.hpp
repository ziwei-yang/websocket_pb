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
    uint32_t arrival_id = 0;    // Monotonic arrival counter (RFC 2018 Section 4 ordering)

    void clear() {
        seq = 0;
        len = 0;
        valid = false;
        data = PayloadPtr{};
        ext_id = -1;
        arrival_id = 0;
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
                segments_[i].arrival_id = next_arrival_id_++;  // RFC 2018 Section 4 ordering
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
        next_arrival_id_ = 0;
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
     * Extract SACK blocks from OOO buffer for ACK packet (RFC 2018).
     *
     * RFC 2018 Section 4: "The first SACK block MUST specify the segment
     * that triggered this ACK" (i.e., most recently received segment).
     *
     * Expected Behavior:
     *   OOO Buffer has 10 segments, can only report 3 blocks (with timestamps):
     *
     *   After PKT 12: SACK [PKT12]
     *   After PKT 14: SACK [PKT14] [PKT12]              <- PKT14 first (newest)
     *   After PKT 16: SACK [PKT16] [PKT14] [PKT12]      <- PKT16 first (newest)
     *   After PKT 18: SACK [PKT18] [PKT16] [PKT14]      <- PKT18 first, PKT12 rotated out
     *   After PKT 20: SACK [PKT20] [PKT18] [PKT16]      <- PKT20 first, PKT14 rotated out
     *
     *   Each ACK is different because the most recent segment always goes first.
     *
     * Why This Matters:
     *   The server uses the first SACK block to identify which segment just arrived:
     *   - Helps RACK algorithm estimate RTT
     *   - Identifies which retransmit "filled" a hole
     *   - Guides fast retransmit decisions
     *
     * @param rcv_nxt Current receive next sequence number
     * @param out Output array for SACK blocks
     * @param max_blocks Maximum blocks to return (3 with timestamps, 4 without)
     * @return Number of blocks written to out
     */
    uint8_t extract_sack_blocks(uint32_t rcv_nxt, SACKBlockArray& out,
                                uint8_t max_blocks = SACK_MAX_BLOCKS) const {
        out.clear();
        if (count_ == 0) return 0;

        // Step 1: Collect valid segments beyond rcv_nxt with arrival info
        struct SegRange {
            uint32_t left;
            uint32_t right;
            uint32_t max_arrival_id;  // Track newest arrival in this range
        };
        SegRange ranges[MaxSegments];
        size_t range_count = 0;

        fprintf(stderr, "[SACK-DEBUG] Step1: Collecting segments (rcv_nxt=%u, count=%zu)\n", rcv_nxt, count_);
        for (size_t i = 0; i < MaxSegments; i++) {
            if (!segments_[i].valid) continue;

            uint32_t seg_seq = segments_[i].seq;
            uint32_t seg_end = seg_seq + segments_[i].len;

            // Only include segments that start after rcv_nxt (truly OOO)
            int32_t diff = static_cast<int32_t>(seg_seq - rcv_nxt);
            fprintf(stderr, "[SACK-DEBUG]   slot[%zu]: seq=%u len=%u arrival_id=%u diff=%d\n",
                    i, seg_seq, segments_[i].len, segments_[i].arrival_id, diff);
            if (diff > 0) {
                ranges[range_count].left = seg_seq;
                ranges[range_count].right = seg_end;
                ranges[range_count].max_arrival_id = segments_[i].arrival_id;
                range_count++;
            }
        }

        if (range_count == 0) return 0;

        // Step 2: Sort by left edge (simple insertion sort, small array)
        for (size_t i = 1; i < range_count; i++) {
            SegRange key = ranges[i];
            size_t j = i;
            while (j > 0 && static_cast<int32_t>(ranges[j-1].left - key.left) > 0) {
                ranges[j] = ranges[j-1];
                j--;
            }
            ranges[j] = key;
        }

        // Step 3: Merge overlapping/adjacent ranges, track max arrival_id
        SACKBlock merged[MaxSegments];
        uint32_t merged_arrival[MaxSegments];
        size_t merged_count = 0;

        merged[0].left_edge = ranges[0].left;
        merged[0].right_edge = ranges[0].right;
        merged_arrival[0] = ranges[0].max_arrival_id;
        merged_count = 1;

        for (size_t i = 1; i < range_count; i++) {
            SACKBlock& last = merged[merged_count - 1];
            int32_t gap = static_cast<int32_t>(ranges[i].left - last.right_edge);
            if (gap <= 0) {
                // Merge: extend right edge and update max arrival
                if (static_cast<int32_t>(ranges[i].right - last.right_edge) > 0) {
                    last.right_edge = ranges[i].right;
                }
                if (ranges[i].max_arrival_id > merged_arrival[merged_count - 1]) {
                    merged_arrival[merged_count - 1] = ranges[i].max_arrival_id;
                }
            } else {
                // New block
                merged[merged_count].left_edge = ranges[i].left;
                merged[merged_count].right_edge = ranges[i].right;
                merged_arrival[merged_count] = ranges[i].max_arrival_id;
                merged_count++;
            }
        }

        // Step 4: Sort blocks by arrival_id descending (most recent first)
        // Use insertion sort on indices to avoid moving SACKBlock structs
        size_t order[MaxSegments];
        for (size_t i = 0; i < merged_count; i++) {
            order[i] = i;
        }
        fprintf(stderr, "[SACK-DEBUG] Step4: Before sort (merged_count=%zu):\n", merged_count);
        for (size_t i = 0; i < merged_count; i++) {
            fprintf(stderr, "[SACK-DEBUG]   merged[%zu]: [%u-%u] arrival=%u\n",
                    i, merged[i].left_edge, merged[i].right_edge, merged_arrival[i]);
        }
        for (size_t i = 1; i < merged_count; i++) {
            size_t key = order[i];
            uint32_t key_arrival = merged_arrival[key];
            size_t j = i;
            // Sort descending by arrival_id (higher = more recent = earlier position)
            while (j > 0 && merged_arrival[order[j-1]] < key_arrival) {
                order[j] = order[j-1];
                j--;
            }
            order[j] = key;
        }
        fprintf(stderr, "[SACK-DEBUG] Step4: After sort, order=[");
        for (size_t i = 0; i < merged_count; i++) {
            fprintf(stderr, "%zu%s", order[i], i+1 < merged_count ? "," : "");
        }
        fprintf(stderr, "]\n");

        // Step 5: Output blocks in recency order (RFC 2018 Section 4)
        for (size_t i = 0; i < merged_count && out.count < max_blocks; i++) {
            out.blocks[out.count++] = merged[order[i]];
            fprintf(stderr, "[SACK-DEBUG] Step5: out[%u] = merged[%zu] = [%u-%u]\n",
                    out.count-1, order[i], merged[order[i]].left_edge, merged[order[i]].right_edge);
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
    uint32_t next_arrival_id_ = 0;    // Monotonic counter for RFC 2018 Section 4 ordering
};

}  // namespace userspace_stack
