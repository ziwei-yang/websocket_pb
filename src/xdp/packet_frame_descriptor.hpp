// src/xdp/packet_frame_descriptor.hpp
// Unified frame descriptor for symmetric TX/RX batch APIs
//
// PacketFrameDescriptor provides a uniform representation for all frame
// metadata in the new batch-based PacketIO API. Used by both TX and RX paths.

#pragma once

#include <cstdint>
#include <cstring>

namespace websocket {
namespace xdp {

/**
 * Frame type enumeration for TX/RX classification
 */
enum FrameType : uint8_t {
    FRAME_TYPE_RX       = 0,    // Received frame
    FRAME_TYPE_TX_DATA  = 1,    // TX data segment
    FRAME_TYPE_TX_ACK   = 2,    // TX pure ACK (no data)
    FRAME_TYPE_TX_SYN   = 3,    // TX SYN (connection initiation)
    FRAME_TYPE_TX_FIN   = 4,    // TX FIN (connection termination)
    FRAME_TYPE_TX_RETX  = 5,    // TX retransmission
};

/**
 * PacketFrameDescriptor - Unified descriptor for all frame metadata
 *
 * This structure provides a uniform representation for frame metadata
 * in both TX and RX paths. It is 32-byte aligned for cache efficiency.
 *
 * For TX path:
 *   - frame_ptr: Points to data area (after headroom) where caller writes packet
 *   - frame_len: Set by caller after building packet
 *   - frame_type: Set by caller (TX_DATA, TX_ACK, TX_SYN, etc.)
 *   - acked: Set by mark_frame_acked() when ACK received
 *
 * For RX path:
 *   - frame_ptr: Points to received packet data
 *   - frame_len: Actual received frame length
 *   - nic_timestamp_ns: NIC hardware timestamp (nanoseconds)
 *   - consumed: Set by mark_frame_consumed() when processing done
 */
struct alignas(32) PacketFrameDescriptor {
    uint64_t frame_ptr;              // Base address of frame data (after headroom)
    uint64_t nic_timestamp_ns;       // NIC hardware timestamp (ns), 0 if unavailable
    uint64_t nic_frame_poll_cycle;   // TSC cycle when frame was retrieved/claimed
    uint16_t frame_len;              // Actual frame length (Ethernet + IP + TCP + payload)
    uint8_t  frame_type;             // FrameType enum (RX/TX_DATA/TX_ACK/TX_SYN/etc)
    uint8_t  consumed;               // For RX: set when frame processing done
    uint8_t  acked;                  // For TX: set when ACK received
    uint8_t  _pad[3];                // Padding to 32 bytes

    /**
     * Clear all fields to zero
     */
    void clear() {
        std::memset(this, 0, sizeof(*this));
    }

    /**
     * Get typed pointer to frame data
     */
    uint8_t* data() const {
        return reinterpret_cast<uint8_t*>(frame_ptr);
    }

    /**
     * Check if frame has been consumed (RX) or acked (TX)
     */
    bool is_released() const {
        return consumed || acked;
    }
};

static_assert(sizeof(PacketFrameDescriptor) == 32,
              "PacketFrameDescriptor must be 32 bytes for cache alignment");

}  // namespace xdp
}  // namespace websocket
