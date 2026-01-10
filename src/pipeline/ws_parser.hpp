// pipeline/ws_parser.hpp
// WebSocket frame parser with partial frame support
// Handles frames that span multiple SSL_read calls
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include "pipeline_config.hpp"

namespace websocket::pipeline {

// ============================================================================
// WebSocket Frame Header (RFC 6455)
//
// Byte 0: [FIN:1][RSV:3][OPCODE:4]
// Byte 1: [MASK:1][PAYLOAD_LEN:7]
// If PAYLOAD_LEN == 126: Bytes 2-3 = 16-bit length
// If PAYLOAD_LEN == 127: Bytes 2-9 = 64-bit length
// If MASK == 1: 4 bytes masking key follows (client->server only)
//
// Server-to-client frames are NOT masked per RFC 6455
// ============================================================================

// ============================================================================
// PartialWebSocketFrame - State for parsing frames across SSL_reads
// ============================================================================

struct PartialWebSocketFrame {
    // Header parsing state
    uint8_t  header_buf[14];          // Max header: 2 + 8 (extended len) + 4 (mask)
    uint8_t  header_bytes_received;   // Bytes of header received so far
    uint8_t  expected_header_len;     // Total expected header length (2-14)
    bool     header_complete;         // Header fully parsed

    // Parsed header values
    uint8_t  opcode;                  // Frame opcode
    bool     fin;                     // FIN bit
    bool     masked;                  // MASK bit (should be false for server frames)
    uint64_t payload_len;             // Payload length (from header)
    uint8_t  mask_key[4];             // Masking key (if masked)

    // Payload state
    uint64_t payload_bytes_received;  // Bytes of payload received so far

    void clear() {
        header_bytes_received = 0;
        expected_header_len = 2;  // Minimum header size
        header_complete = false;
        opcode = 0;
        fin = false;
        masked = false;
        payload_len = 0;
        payload_bytes_received = 0;
    }

    bool is_complete() const {
        return header_complete && payload_bytes_received >= payload_len;
    }

    uint64_t payload_remaining() const {
        return payload_len - payload_bytes_received;
    }
};

// ============================================================================
// WebSocket Parser Functions
// ============================================================================

// Calculate expected header length from first 2 bytes
inline uint8_t calculate_header_len(uint8_t byte0, uint8_t byte1) {
    uint8_t len = 2;  // Base header

    // Check payload length field
    uint8_t payload_len_field = byte1 & 0x7F;
    if (payload_len_field == 126) {
        len += 2;  // 16-bit extended length
    } else if (payload_len_field == 127) {
        len += 8;  // 64-bit extended length
    }

    // Check mask bit
    if (byte1 & 0x80) {
        len += 4;  // Masking key
    }

    return len;
}

// Parse completed header buffer
// Call after header_complete == true
inline void parse_completed_header(PartialWebSocketFrame& frame) {
    const uint8_t* h = frame.header_buf;

    // Byte 0: FIN + opcode
    frame.fin = (h[0] & 0x80) != 0;
    frame.opcode = h[0] & 0x0F;

    // Byte 1: MASK + payload length
    frame.masked = (h[1] & 0x80) != 0;
    uint8_t len_field = h[1] & 0x7F;

    // Parse payload length
    size_t offset = 2;
    if (len_field < 126) {
        frame.payload_len = len_field;
    } else if (len_field == 126) {
        frame.payload_len = (static_cast<uint64_t>(h[2]) << 8) |
                            static_cast<uint64_t>(h[3]);
        offset = 4;
    } else {  // len_field == 127
        frame.payload_len = (static_cast<uint64_t>(h[2]) << 56) |
                            (static_cast<uint64_t>(h[3]) << 48) |
                            (static_cast<uint64_t>(h[4]) << 40) |
                            (static_cast<uint64_t>(h[5]) << 32) |
                            (static_cast<uint64_t>(h[6]) << 24) |
                            (static_cast<uint64_t>(h[7]) << 16) |
                            (static_cast<uint64_t>(h[8]) << 8) |
                            static_cast<uint64_t>(h[9]);
        offset = 10;
    }

    // Parse masking key if present
    if (frame.masked) {
        std::memcpy(frame.mask_key, h + offset, 4);
    }
}

// Start parsing a new frame
// Returns bytes consumed from data
// Sets frame.header_complete if header is fully received
inline size_t start_parse_frame(PartialWebSocketFrame& frame,
                                const uint8_t* data, size_t len) {
    frame.clear();

    if (len == 0) return 0;

    size_t consumed = 0;

    // Read first byte
    frame.header_buf[0] = data[0];
    frame.header_bytes_received = 1;
    consumed = 1;

    if (len < 2) {
        // Need more data for second byte
        return consumed;
    }

    // Read second byte and calculate header length
    frame.header_buf[1] = data[1];
    frame.header_bytes_received = 2;
    frame.expected_header_len = calculate_header_len(data[0], data[1]);
    consumed = 2;

    // Try to complete header
    size_t header_remaining = frame.expected_header_len - 2;
    size_t available = len - 2;
    size_t to_copy = (available < header_remaining) ? available : header_remaining;

    if (to_copy > 0) {
        std::memcpy(frame.header_buf + 2, data + 2, to_copy);
        frame.header_bytes_received += to_copy;
        consumed += to_copy;
    }

    if (frame.header_bytes_received >= frame.expected_header_len) {
        frame.header_complete = true;
        parse_completed_header(frame);
    }

    return consumed;
}

// Continue parsing partial frame (header or payload)
// Returns bytes consumed from data
inline size_t continue_partial_frame(PartialWebSocketFrame& frame,
                                     const uint8_t* data, size_t len) {
    if (len == 0) return 0;

    size_t consumed = 0;

    // Complete header if needed
    if (!frame.header_complete) {
        // Need second byte to know header length
        if (frame.header_bytes_received == 1) {
            frame.header_buf[1] = data[0];
            frame.header_bytes_received = 2;
            frame.expected_header_len = calculate_header_len(frame.header_buf[0],
                                                             frame.header_buf[1]);
            consumed = 1;
        }

        // Read remaining header bytes
        size_t header_remaining = frame.expected_header_len - frame.header_bytes_received;
        size_t available = len - consumed;
        size_t to_copy = (available < header_remaining) ? available : header_remaining;

        if (to_copy > 0) {
            std::memcpy(frame.header_buf + frame.header_bytes_received,
                        data + consumed, to_copy);
            frame.header_bytes_received += to_copy;
            consumed += to_copy;
        }

        if (frame.header_bytes_received >= frame.expected_header_len) {
            frame.header_complete = true;
            parse_completed_header(frame);
        }
    }

    // Note: Payload tracking is done externally by WebSocketProcess
    // since payload is written directly to MSG_INBOX

    return consumed;
}

// Unmask payload in place (if masked)
// For client->server masking only; server->client is not masked
inline void unmask_payload(uint8_t* payload, size_t len, const uint8_t* mask_key) {
    // Optimize for common case of 4-byte aligned data
    size_t i = 0;

    // Process 4 bytes at a time if possible
    if (len >= 4) {
        uint32_t mask32;
        std::memcpy(&mask32, mask_key, 4);

        for (; i + 4 <= len; i += 4) {
            uint32_t* p = reinterpret_cast<uint32_t*>(payload + i);
            *p ^= mask32;
        }
    }

    // Handle remaining bytes
    for (; i < len; i++) {
        payload[i] ^= mask_key[i & 3];
    }
}

// Build WebSocket frame header
// Returns header length (2-14 bytes written to header_buf)
inline size_t build_ws_header(uint8_t* header_buf, uint8_t opcode, size_t payload_len,
                              bool fin = true, bool mask = true,
                              const uint8_t* mask_key = nullptr) {
    size_t offset = 0;

    // Byte 0: FIN + opcode
    header_buf[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0F);
    offset = 1;

    // Byte 1: MASK + payload length
    uint8_t mask_bit = mask ? 0x80 : 0x00;

    if (payload_len < 126) {
        header_buf[1] = mask_bit | static_cast<uint8_t>(payload_len);
        offset = 2;
    } else if (payload_len <= 65535) {
        header_buf[1] = mask_bit | 126;
        header_buf[2] = static_cast<uint8_t>(payload_len >> 8);
        header_buf[3] = static_cast<uint8_t>(payload_len & 0xFF);
        offset = 4;
    } else {
        header_buf[1] = mask_bit | 127;
        header_buf[2] = static_cast<uint8_t>(payload_len >> 56);
        header_buf[3] = static_cast<uint8_t>(payload_len >> 48);
        header_buf[4] = static_cast<uint8_t>(payload_len >> 40);
        header_buf[5] = static_cast<uint8_t>(payload_len >> 32);
        header_buf[6] = static_cast<uint8_t>(payload_len >> 24);
        header_buf[7] = static_cast<uint8_t>(payload_len >> 16);
        header_buf[8] = static_cast<uint8_t>(payload_len >> 8);
        header_buf[9] = static_cast<uint8_t>(payload_len & 0xFF);
        offset = 10;
    }

    // Masking key (client->server only)
    if (mask && mask_key) {
        std::memcpy(header_buf + offset, mask_key, 4);
        offset += 4;
    }

    return offset;
}

// Generate random mask key
inline void generate_mask_key(uint8_t* mask_key) {
    // Simple PRNG for masking (doesn't need to be cryptographic)
    static uint32_t seed = 0x12345678;
    seed = seed * 1103515245 + 12345;
    std::memcpy(mask_key, &seed, 4);
}

}  // namespace websocket::pipeline
