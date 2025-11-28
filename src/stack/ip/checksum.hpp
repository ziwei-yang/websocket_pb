// src/stack/ip/checksum.hpp
// IP and TCP Checksum Calculation (Internal)
//
// INTERNAL: Used by tcp_packet.hpp and ip_layer.hpp.
//
// Implements RFC 1071 - Computing the Internet Checksum
//
// Provides:
//   - ip_checksum()        - Calculate IP header checksum
//   - verify_ip_checksum() - Verify IP header checksum
//   - tcp_checksum()       - Calculate TCP checksum (with pseudo-header)
//   - verify_tcp_checksum() - Verify TCP checksum

#pragma once

#include <cstdint>
#include <cstddef>
#include <arpa/inet.h>

namespace userspace_stack {

// Compute Internet checksum (RFC 1071)
// Used for IP header and TCP/UDP checksums
inline uint16_t internet_checksum(const void* data, size_t len) {
    const uint8_t* buf = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;

    // Sum all 16-bit words (in network byte order)
    while (len > 1) {
        // Combine two bytes into 16-bit word (network byte order = big endian)
        sum += (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
        buf += 2;
        len -= 2;
    }

    // Add leftover byte if odd length (as high byte)
    if (len == 1) {
        sum += static_cast<uint16_t>(buf[0]) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    return static_cast<uint16_t>(~sum);
}

// Compute IP header checksum
// Assumes 20-byte IPv4 header (no options)
inline uint16_t ip_checksum(const void* ip_header) {
    return internet_checksum(ip_header, 20);
}

// Verify IP header checksum
// Returns 0 if valid, non-zero if invalid
inline int verify_ip_checksum(const void* ip_header) {
    // Computing checksum of header with checksum field should yield 0
    return internet_checksum(ip_header, 20);
}

// TCP pseudo-header for checksum calculation
struct __attribute__((packed)) TCPPseudoHeader {
    uint32_t src_ip;    // Source IP address
    uint32_t dst_ip;    // Destination IP address
    uint8_t  zero;      // Reserved (must be 0)
    uint8_t  protocol;  // Protocol (6 for TCP)
    uint16_t tcp_len;   // TCP header + data length
};

// Compute TCP checksum
// src_ip, dst_ip: In HOST byte order (not network byte order!)
// tcp_header: Points to TCP header
// tcp_header_len: TCP header length (usually 20)
// tcp_data: Points to TCP data (can be nullptr if no data)
// tcp_data_len: TCP data length (can be 0)
inline uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                            const void* tcp_header, size_t tcp_header_len,
                            const void* tcp_data, size_t tcp_data_len) {
    uint32_t sum = 0;

    // Sum pseudo-header
    // Source IP (2 x 16-bit words in big-endian order)
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;

    // Dest IP (2 x 16-bit words in big-endian order)
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;

    // Protocol (as 16-bit word: 0x0006)
    sum += 6;  // TCP protocol

    // TCP length (add as 16-bit value - checksum algorithm treats as big-endian)
    uint16_t tcp_len = static_cast<uint16_t>(tcp_header_len + tcp_data_len);
    sum += tcp_len;

    // Sum TCP header
    const uint8_t* buf = static_cast<const uint8_t*>(tcp_header);
    size_t len = tcp_header_len;
    while (len > 1) {
        sum += (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
        buf += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += static_cast<uint16_t>(buf[0]) << 8;
    }

    // Sum TCP data
    if (tcp_data && tcp_data_len > 0) {
        buf = static_cast<const uint8_t*>(tcp_data);
        len = tcp_data_len;
        while (len > 1) {
            sum += (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
            buf += 2;
            len -= 2;
        }
        if (len == 1) {
            sum += static_cast<uint16_t>(buf[0]) << 8;
        }
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return one's complement
    return static_cast<uint16_t>(~sum);
}

// Verify TCP checksum
// Returns 0 if valid, non-zero if invalid
inline int verify_tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                               const void* tcp_header, size_t tcp_header_len,
                               const void* tcp_data, size_t tcp_data_len) {
    // Simply recompute checksum and check if it's 0xFFFF (or ~0)
    // When the checksum field is included in the sum, the result should be 0xFFFF
    uint32_t sum = 0;

    // Sum pseudo-header
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;
    sum += 6;  // Protocol
    sum += static_cast<uint16_t>(tcp_header_len + tcp_data_len);

    // Sum TCP header
    const uint8_t* buf = static_cast<const uint8_t*>(tcp_header);
    size_t len = tcp_header_len;
    while (len > 1) {
        sum += (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
        buf += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += static_cast<uint16_t>(buf[0]) << 8;
    }

    // Sum TCP data
    if (tcp_data && tcp_data_len > 0) {
        buf = static_cast<const uint8_t*>(tcp_data);
        len = tcp_data_len;
        while (len > 1) {
            sum += (static_cast<uint16_t>(buf[0]) << 8) | buf[1];
            buf += 2;
            len -= 2;
        }
        if (len == 1) {
            sum += static_cast<uint16_t>(buf[0]) << 8;
        }
    }

    // Fold to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement - should be 0 if checksum is valid
    return static_cast<uint16_t>(~sum);
}

} // namespace userspace_stack
