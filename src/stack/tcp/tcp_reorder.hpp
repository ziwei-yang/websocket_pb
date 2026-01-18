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

    void clear() {
        seq = 0;
        len = 0;
        valid = false;
        data = PayloadPtr{};
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
     * @return true if buffered, false if buffer full
     */
    bool buffer_segment(uint32_t seq, uint16_t len, PayloadPtr data) {
        if (count_ >= MaxSegments) {
            return false;  // Buffer full
        }

        // Find empty slot
        for (size_t i = 0; i < MaxSegments; i++) {
            if (!segments_[i].valid) {
                segments_[i].seq = seq;
                segments_[i].len = len;
                segments_[i].data = data;
                segments_[i].valid = true;
                count_++;
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
                    segments_[i].valid = false;
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
                    segments_[i].valid = false;
                    count_--;
                    delivered++;
                    found = true;
                    break;

                } else if (diff < 0) {
                    // Fully duplicate: segment entirely before rcv_nxt
                    segments_[i].valid = false;
                    count_--;
                    found = true;
                    break;
                }
                // diff > 0: Still out-of-order, skip
            }

            if (!found) break;  // No more deliverable segments
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
    }

    size_t count() const { return count_; }
    bool is_full() const { return count_ >= MaxSegments; }
    bool is_empty() const { return count_ == 0; }

    static constexpr size_t max_segments() { return MaxSegments; }

private:
    Segment segments_[MaxSegments];
    size_t count_ = 0;
};

}  // namespace userspace_stack
