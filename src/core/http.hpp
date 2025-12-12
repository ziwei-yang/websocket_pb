// src/core/http.hpp
// Transport-agnostic HTTP/WebSocket utilities
//
// This module provides HTTP upgrade and WebSocket frame parsing/building
// utilities that can be reused across different transport layers:
//   - BSD sockets (src/websocket.hpp)
//   - DPDK (src/dpdk/...)
//
// Key features:
//   - WebSocket frame parsing (RFC 6455)
//   - WebSocket frame building (PONG, TEXT, BINARY, CLOSE)
//   - HTTP upgrade request/response handling
//   - Transport-agnostic design (no socket/SSL dependencies)

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <random>
#include <stdexcept>

namespace websocket {
namespace http {

// ═══════════════════════════════════════════════════════════════════════════
// HTTP Utilities
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate HTTP header key/value for CRLF injection attacks
 *
 * @param key Header name
 * @param value Header value
 * @return true if safe, false if contains CRLF or invalid
 */
inline bool is_valid_header(const std::string& key, const std::string& value) {
    // Check for CRLF sequences that could allow header injection
    if (key.find("\r\n") != std::string::npos || key.find('\n') != std::string::npos) {
        return false;
    }
    if (value.find("\r\n") != std::string::npos || value.find('\n') != std::string::npos) {
        return false;
    }
    // Check for empty key
    if (key.empty()) {
        return false;
    }
    return true;
}

/**
 * Generate random WebSocket key (RFC 6455 compliance)
 *
 * Generates 16 random bytes and base64-encodes them to produce
 * a 24-character WebSocket key for the Sec-WebSocket-Key header.
 *
 * @return Base64-encoded 24-character key
 */
inline std::string generate_websocket_key() {
    // Generate 16 random bytes
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    uint8_t nonce[16];
    for (int i = 0; i < 16; ++i) {
        nonce[i] = static_cast<uint8_t>(dis(gen));
    }

    // Base64 encode (simplified - produces 24 character output)
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    encoded.reserve(24);

    for (int i = 0; i < 16; i += 3) {
        uint32_t val = (nonce[i] << 16);
        if (i + 1 < 16) val |= (nonce[i + 1] << 8);
        if (i + 2 < 16) val |= nonce[i + 2];

        encoded.push_back(base64_chars[(val >> 18) & 0x3F]);
        encoded.push_back(base64_chars[(val >> 12) & 0x3F]);
        encoded.push_back((i + 1 < 16) ? base64_chars[(val >> 6) & 0x3F] : '=');
        encoded.push_back((i + 2 < 16) ? base64_chars[val & 0x3F] : '=');
    }

    return encoded;
}

/**
 * Build HTTP WebSocket upgrade request
 *
 * @param host Hostname (e.g., "stream.binance.com")
 * @param path Path (e.g., "/stream?streams=btcusdt@trade")
 * @param custom_headers Additional headers (optional, as vector of key-value pairs)
 * @param out_buffer Output buffer to write request
 * @param buffer_size Size of output buffer
 * @return Number of bytes written to buffer
 */
inline size_t build_websocket_upgrade_request(
    const char* host,
    const char* path,
    const std::vector<std::pair<std::string, std::string>>& custom_headers,
    char* out_buffer,
    size_t buffer_size)
{
    // Build HTTP request dynamically with std::string for flexibility
    std::string request;
    request.reserve(2048);

    // Generate random WebSocket key
    std::string ws_key = generate_websocket_key();

    // Request line and required headers
    request += "GET ";
    request += path;
    request += " HTTP/1.1\r\n";
    request += "Host: ";
    request += host;
    request += "\r\n";
    request += "Upgrade: websocket\r\n";
    request += "Connection: Upgrade\r\n";
    request += "Sec-WebSocket-Key: ";
    request += ws_key;
    request += "\r\n";
    request += "Sec-WebSocket-Version: 13\r\n";

    // Add custom headers with validation
    for (const auto& [key, value] : custom_headers) {
        if (!is_valid_header(key, value)) {
            continue;  // Skip invalid headers
        }

        request += key;
        request += ": ";
        request += value;
        request += "\r\n";
    }

    // End of headers
    request += "\r\n";

    // Copy to output buffer
    size_t len = request.size();
    if (len > buffer_size) {
        throw std::runtime_error("Upgrade request too large for buffer");
    }

    memcpy(out_buffer, request.data(), len);
    return len;
}

/**
 * Validate HTTP upgrade response
 *
 * @param response Response buffer
 * @param len Response length
 * @return true if contains "101 Switching Protocols", false otherwise
 */
inline bool validate_http_upgrade_response(const uint8_t* response, size_t len) {
    // Simple validation: check for "101" status code
    if (len < 12) {
        return false;  // Too short to contain HTTP response
    }

    // Look for "101" in response (should be in status line)
    const char* resp_str = reinterpret_cast<const char*>(response);
    for (size_t i = 0; i < len - 2; i++) {
        if (resp_str[i] == '1' && resp_str[i + 1] == '0' && resp_str[i + 2] == '1') {
            return true;
        }
    }

    return false;
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket Frame Structures
// ═══════════════════════════════════════════════════════════════════════════

/**
 * WebSocket frame opcodes (RFC 6455)
 */
enum class WebSocketOpcode : uint8_t {
    CONTINUATION = 0x00,
    TEXT = 0x01,
    BINARY = 0x02,
    CLOSE = 0x08,
    PING = 0x09,
    PONG = 0x0A,
};

/**
 * Parsed WebSocket frame header
 */
struct WebSocketFrame {
    bool fin;                  // FIN bit (final fragment)
    uint8_t opcode;            // Opcode (0x00-0x0F)
    bool masked;               // MASK bit
    uint64_t payload_len;      // Payload length
    uint8_t mask_key[4];       // Masking key (if masked)
    size_t header_len;         // Total header length (2-14 bytes)
    const uint8_t* payload;    // Pointer to payload (not copied)
};

/**
 * Parse WebSocket frame header
 *
 * Parses the frame header and returns metadata. Does NOT copy payload data.
 * Caller must ensure buffer remains valid while using the frame.
 *
 * @param data Frame buffer
 * @param len Buffer length
 * @param out_frame Parsed frame metadata
 * @return true if successfully parsed, false if incomplete/invalid
 */
inline bool parse_websocket_frame(const uint8_t* data, size_t len, WebSocketFrame& out_frame) {
    // Need at least 2 bytes for basic header
    if (len < 2) {
        return false;
    }

    // Parse byte 0: FIN + opcode
    uint8_t byte0 = data[0];
    out_frame.fin = (byte0 & 0x80) != 0;
    out_frame.opcode = byte0 & 0x0F;

    // Parse byte 1: MASK + payload length
    uint8_t byte1 = data[1];
    out_frame.masked = (byte1 & 0x80) != 0;
    uint64_t payload_len = byte1 & 0x7F;

    size_t header_len = 2;

    // Extended payload length
    if (payload_len == 126) {
        // 16-bit length
        if (len < 4) return false;
        payload_len = (data[2] << 8) | data[3];
        header_len = 4;
    } else if (payload_len == 127) {
        // 64-bit length
        if (len < 10) return false;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | data[2 + i];
        }
        header_len = 10;
    }

    out_frame.payload_len = payload_len;

    // Masking key (if present)
    if (out_frame.masked) {
        if (len < header_len + 4) return false;
        memcpy(out_frame.mask_key, data + header_len, 4);
        header_len += 4;
    }

    out_frame.header_len = header_len;

    // Check if full frame is available
    if (len < header_len + payload_len) {
        return false;  // Incomplete frame
    }

    // Payload pointer (not copied)
    out_frame.payload = data + header_len;

    return true;
}

/**
 * Unmask WebSocket payload in-place
 *
 * @param payload Payload buffer to unmask
 * @param len Payload length
 * @param mask_key 4-byte masking key
 */
inline void unmask_payload(uint8_t* payload, size_t len, const uint8_t mask_key[4]) {
    for (size_t i = 0; i < len; i++) {
        payload[i] ^= mask_key[i % 4];
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket Frame Builders
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Build WebSocket PONG frame
 *
 * Builds a PONG frame in response to PING. Client frames must be masked.
 * RFC 6455: Control frames must have payload <= 125 bytes.
 *
 * @param payload PING payload to echo back
 * @param payload_len Payload length (will be capped at 125)
 * @param out_buffer Output buffer (must be >= 131 bytes)
 * @param mask_key 4-byte masking key (use {0x12, 0x34, 0x56, 0x78} for simplicity)
 * @return Total frame size (6 + payload_len)
 */
inline size_t build_pong_frame(const uint8_t* payload, size_t payload_len,
                                uint8_t* out_buffer, const uint8_t mask_key[4]) {
    // Validate payload length (RFC 6455: control frames <= 125 bytes)
    if (payload_len > 125) {
        payload_len = 125;  // Truncate
    }

    // Byte 0: FIN + opcode 0x0A (PONG)
    out_buffer[0] = 0x8A;

    // Byte 1: MASK + payload length
    out_buffer[1] = 0x80 | (uint8_t)payload_len;

    // Masking key
    memcpy(out_buffer + 2, mask_key, 4);

    // Masked payload
    for (size_t i = 0; i < payload_len; i++) {
        out_buffer[6 + i] = payload[i] ^ mask_key[i % 4];
    }

    return 6 + payload_len;
}

/**
 * Build WebSocket TEXT frame
 *
 * @param payload Text payload
 * @param payload_len Payload length
 * @param out_buffer Output buffer
 * @param buffer_size Buffer size
 * @param mask_key 4-byte masking key
 * @return Total frame size
 */
inline size_t build_text_frame(const uint8_t* payload, size_t payload_len,
                                uint8_t* out_buffer, size_t buffer_size,
                                const uint8_t mask_key[4]) {
    size_t header_len = 2;

    // Byte 0: FIN + opcode 0x01 (TEXT)
    out_buffer[0] = 0x81;

    // Byte 1: MASK + payload length
    if (payload_len <= 125) {
        out_buffer[1] = 0x80 | (uint8_t)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        out_buffer[1] = 0x80 | 126;
        out_buffer[2] = (payload_len >> 8) & 0xFF;
        out_buffer[3] = payload_len & 0xFF;
        header_len = 4;
    } else {
        out_buffer[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) {
            out_buffer[2 + i] = (payload_len >> (56 - i * 8)) & 0xFF;
        }
        header_len = 10;
    }

    // Masking key
    memcpy(out_buffer + header_len, mask_key, 4);
    header_len += 4;

    // Check buffer size
    if (header_len + payload_len > buffer_size) {
        throw std::runtime_error("Buffer too small for TEXT frame");
    }

    // Masked payload
    for (size_t i = 0; i < payload_len; i++) {
        out_buffer[header_len + i] = payload[i] ^ mask_key[i % 4];
    }

    return header_len + payload_len;
}

/**
 * Build WebSocket BINARY frame
 *
 * @param payload Binary payload
 * @param payload_len Payload length
 * @param out_buffer Output buffer
 * @param buffer_size Buffer size
 * @param mask_key 4-byte masking key
 * @return Total frame size
 */
inline size_t build_binary_frame(const uint8_t* payload, size_t payload_len,
                                  uint8_t* out_buffer, size_t buffer_size,
                                  const uint8_t mask_key[4]) {
    size_t header_len = 2;

    // Byte 0: FIN + opcode 0x02 (BINARY)
    out_buffer[0] = 0x82;

    // Byte 1: MASK + payload length
    if (payload_len <= 125) {
        out_buffer[1] = 0x80 | (uint8_t)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        out_buffer[1] = 0x80 | 126;
        out_buffer[2] = (payload_len >> 8) & 0xFF;
        out_buffer[3] = payload_len & 0xFF;
        header_len = 4;
    } else {
        out_buffer[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) {
            out_buffer[2 + i] = (payload_len >> (56 - i * 8)) & 0xFF;
        }
        header_len = 10;
    }

    // Masking key
    memcpy(out_buffer + header_len, mask_key, 4);
    header_len += 4;

    // Check buffer size
    if (header_len + payload_len > buffer_size) {
        throw std::runtime_error("Buffer too small for BINARY frame");
    }

    // Masked payload
    for (size_t i = 0; i < payload_len; i++) {
        out_buffer[header_len + i] = payload[i] ^ mask_key[i % 4];
    }

    return header_len + payload_len;
}

/**
 * Build WebSocket frame with specified opcode
 *
 * @param payload Payload data
 * @param payload_len Payload length
 * @param out_buffer Output buffer
 * @param buffer_size Buffer size
 * @param mask_key 4-byte masking key
 * @param opcode WebSocket opcode (0x01=text, 0x02=binary)
 * @return Total frame size
 */
inline size_t build_websocket_frame(const uint8_t* payload, size_t payload_len,
                                     uint8_t* out_buffer, size_t buffer_size,
                                     const uint8_t mask_key[4], uint8_t opcode) {
    size_t header_len = 2;

    // Byte 0: FIN + opcode
    out_buffer[0] = 0x80 | (opcode & 0x0F);

    // Byte 1: MASK + payload length
    if (payload_len <= 125) {
        out_buffer[1] = 0x80 | (uint8_t)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        out_buffer[1] = 0x80 | 126;
        out_buffer[2] = (payload_len >> 8) & 0xFF;
        out_buffer[3] = payload_len & 0xFF;
        header_len = 4;
    } else {
        out_buffer[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) {
            out_buffer[2 + i] = (payload_len >> (56 - i * 8)) & 0xFF;
        }
        header_len = 10;
    }

    // Masking key
    memcpy(out_buffer + header_len, mask_key, 4);
    header_len += 4;

    // Check buffer size
    if (header_len + payload_len > buffer_size) {
        return 0;  // Buffer too small
    }

    // Masked payload
    for (size_t i = 0; i < payload_len; i++) {
        out_buffer[header_len + i] = payload[i] ^ mask_key[i % 4];
    }

    return header_len + payload_len;
}

/**
 * Build WebSocket frame header only (for zero-copy TX)
 *
 * Uses mask=0x00000000 so payload doesn't need XOR transformation.
 * Caller sends header then raw payload in separate writes.
 *
 * @param out_header Output buffer for header (must be >= 14 bytes)
 * @param payload_len Length of payload that will follow
 * @param opcode WebSocket opcode (0x01=text, 0x02=binary)
 * @return Header size (6, 8, or 14 bytes depending on payload_len)
 */
inline size_t build_websocket_header_zerocopy(uint8_t* out_header,
                                               size_t payload_len,
                                               uint8_t opcode) {
    size_t header_len = 2;

    // Byte 0: FIN + opcode
    out_header[0] = 0x80 | (opcode & 0x0F);

    // Byte 1: MASK + payload length
    if (payload_len <= 125) {
        out_header[1] = 0x80 | static_cast<uint8_t>(payload_len);
        header_len = 2;
    } else if (payload_len <= 65535) {
        out_header[1] = 0x80 | 126;
        out_header[2] = (payload_len >> 8) & 0xFF;
        out_header[3] = payload_len & 0xFF;
        header_len = 4;
    } else {
        out_header[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) {
            out_header[2 + i] = (payload_len >> (56 - i * 8)) & 0xFF;
        }
        header_len = 10;
    }

    // Zero masking key (payload XOR 0 = payload, no transformation needed)
    out_header[header_len++] = 0;
    out_header[header_len++] = 0;
    out_header[header_len++] = 0;
    out_header[header_len++] = 0;

    return header_len;
}

/**
 * Build WebSocket CLOSE frame
 *
 * @param status_code Close status code (1000 = normal closure)
 * @param reason Close reason (optional, max 123 bytes)
 * @param reason_len Reason length
 * @param out_buffer Output buffer
 * @param mask_key 4-byte masking key
 * @return Total frame size
 */
inline size_t build_close_frame(uint16_t status_code,
                                 const uint8_t* reason, size_t reason_len,
                                 uint8_t* out_buffer,
                                 const uint8_t mask_key[4]) {
    // Payload: 2-byte status code + reason (max 123 bytes)
    if (reason_len > 123) {
        reason_len = 123;
    }

    size_t payload_len = 2 + reason_len;

    // Byte 0: FIN + opcode 0x08 (CLOSE)
    out_buffer[0] = 0x88;

    // Byte 1: MASK + payload length
    out_buffer[1] = 0x80 | (uint8_t)payload_len;

    // Masking key
    memcpy(out_buffer + 2, mask_key, 4);

    // Build payload (status code + reason)
    uint8_t payload[125];
    payload[0] = (status_code >> 8) & 0xFF;
    payload[1] = status_code & 0xFF;
    if (reason_len > 0) {
        memcpy(payload + 2, reason, reason_len);
    }

    // Masked payload
    for (size_t i = 0; i < payload_len; i++) {
        out_buffer[6 + i] = payload[i] ^ mask_key[i % 4];
    }

    return 6 + payload_len;
}

}  // namespace http
}  // namespace websocket
