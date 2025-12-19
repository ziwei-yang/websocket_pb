// websocket_txrx/message_info.hpp
// Simplified message info for external consumers
// Part of websocket_pb export headers
//
// Usage:
//   const ShmMessageInfo* msgs = ...;
//   for (uint16_t i = 0; i < hdr->frame_count; i++) {
//       const uint8_t* payload = consumer.resolve_payload(msgs[i]);
//       int32_t len = msgs[i].len;
//   }
//
#pragma once

#include <cstdint>

// =============================================================================
// Message info structure (8 bytes each)
// =============================================================================

// Simplified message descriptor for RXRingBufferConsumer
// Contains offset relative to SSL data start and payload length
//
// Offset encoding:
//   offset >= 0: Payload is at ssl_data_ptr + offset (normal case)
//   offset <  0: Payload is in assembly buffer at position (-offset - 1)
//               Use consumer.get_assembly_buffer() + (-offset - 1)
//
struct ShmMessageInfo {
    int32_t offset;  // Offset from SSL data start (or negative for assembly buffer)
    int32_t len;     // Payload length in bytes
};
static_assert(sizeof(ShmMessageInfo) == 8, "ShmMessageInfo must be 8 bytes");
