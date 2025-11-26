// src/stack/ip/icmp.hpp
// Minimal ICMP for WebSocket HFT
// Only handle ping (echo request/reply)

#pragma once

#include "ip_layer.hpp"
#include "checksum.hpp"

namespace userspace_stack {

// ICMP constants
constexpr uint8_t ICMP_ECHO_REPLY = 0;
constexpr uint8_t ICMP_ECHO_REQUEST = 8;
constexpr size_t ICMP_HEADER_LEN = 8;

// ICMP header structure
struct __attribute__((packed)) ICMPHeader {
    uint8_t  type;       // Message type
    uint8_t  code;       // Message code
    uint16_t checksum;   // Checksum
    uint16_t id;         // Identifier (for echo)
    uint16_t seq;        // Sequence number (for echo)
};

class ICMP {
private:
    IPLayer* ip_ = nullptr;

public:
    ICMP() = default;

    // Initialize ICMP
    void init(IPLayer* ip) {
        if (!ip) {
            throw std::runtime_error("ICMP: IP layer is null");
        }
        ip_ = ip;
    }

    // Send ping request
    // dst_ip: Destination IP (host byte order)
    // id, seq: Ping identifier and sequence number
    // data: Optional ping data
    // len: Data length
    void send_ping(uint32_t dst_ip, uint16_t id, uint16_t seq,
                  const uint8_t* data = nullptr, size_t len = 0) {
        if (!ip_) {
            throw std::runtime_error("ICMP: Not initialized");
        }

        // Build ICMP echo request
        uint8_t packet[1480];
        ICMPHeader* icmp = reinterpret_cast<ICMPHeader*>(packet);

        icmp->type = ICMP_ECHO_REQUEST;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->id = htons(id);
        icmp->seq = htons(seq);

        // Copy data if provided
        if (data && len > 0) {
            std::memcpy(packet + ICMP_HEADER_LEN, data, len);
        }

        // Calculate checksum
        icmp->checksum = internet_checksum(packet, ICMP_HEADER_LEN + len);

        // Send via IP layer
        ip_->send_packet(dst_ip, IP_PROTO_ICMP, packet, ICMP_HEADER_LEN + len);
    }

    // Process incoming ICMP packet
    // Called by poll loop
    // Returns true if ICMP packet processed
    bool process_rx() {
        if (!ip_) {
            return false;
        }

        uint8_t protocol;
        uint8_t* payload;
        size_t len;
        uint32_t src_ip;

        if (!ip_->recv_packet(&protocol, &payload, &len, &src_ip)) {
            return false;  // No packet
        }

        // Check if ICMP packet
        if (protocol != IP_PROTO_ICMP) {
            ip_->release_rx_packet();
            return false;
        }

        // Validate ICMP packet size
        if (len < ICMP_HEADER_LEN) {
            ip_->release_rx_packet();
            return false;
        }

        // Parse ICMP header
        ICMPHeader* icmp = reinterpret_cast<ICMPHeader*>(payload);

        // Verify checksum
        if (internet_checksum(payload, len) != 0) {
            ip_->release_rx_packet();
            return false;
        }

        // Handle ICMP echo request (ping)
        if (icmp->type == ICMP_ECHO_REQUEST) {
            // Send echo reply
            send_ping_reply(src_ip, icmp, payload + ICMP_HEADER_LEN,
                          len - ICMP_HEADER_LEN);
            ip_->release_rx_packet();
            return true;
        }

        // Handle ICMP echo reply (pong)
        if (icmp->type == ICMP_ECHO_REPLY) {
            // Application can handle this
            ip_->release_rx_packet();
            return true;
        }

        ip_->release_rx_packet();
        return false;
    }

private:
    // Send ping reply
    void send_ping_reply(uint32_t dst_ip, const ICMPHeader* request,
                        const uint8_t* data, size_t len) {
        uint8_t packet[1480];
        ICMPHeader* icmp = reinterpret_cast<ICMPHeader*>(packet);

        icmp->type = ICMP_ECHO_REPLY;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->id = request->id;     // Echo back same ID
        icmp->seq = request->seq;   // Echo back same seq

        // Copy data
        if (data && len > 0) {
            std::memcpy(packet + ICMP_HEADER_LEN, data, len);
        }

        // Calculate checksum
        icmp->checksum = internet_checksum(packet, ICMP_HEADER_LEN + len);

        // Send via IP layer
        ip_->send_packet(dst_ip, IP_PROTO_ICMP, packet, ICMP_HEADER_LEN + len);
    }
};

} // namespace userspace_stack
