// src/stack/ip/ip_layer.hpp
// IPv4 Packet Building and Parsing (Internal)
//
// INTERNAL: Use UserspaceStack (userspace_stack.hpp) as the entry point.
//
// Provides:
//   - IPv4Header struct (20-byte IP header)
//   - IPLayer::build_packet() - Build IP packet into buffer
//   - IPLayer::parse_packet() - Parse IP packet from Ethernet frame
//   - IP protocol constants (IP_PROTO_TCP, IP_PROTO_UDP, etc.)
//
// Note: No IP options support (HFT optimization)

#pragma once

#include "../mac/ethernet.hpp"
#include "../mac/arp.hpp"
#include "checksum.hpp"
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>

namespace userspace_stack {

// IP constants
constexpr uint8_t IP_PROTO_ICMP = 1;
constexpr uint8_t IP_PROTO_TCP = 6;
constexpr uint8_t IP_PROTO_UDP = 17;
constexpr size_t IP_HEADER_LEN = 20;  // No options
constexpr uint8_t IP_VERSION = 4;
constexpr uint8_t IP_DEFAULT_TTL = 64;

// IPv4 header structure (20 bytes, no options)
struct __attribute__((packed)) IPv4Header {
    uint8_t  version_ihl;    // 4 bits version + 4 bits IHL (header length)
    uint8_t  tos;            // Type of service
    uint16_t tot_len;        // Total length (header + data)
    uint16_t id;             // Identification
    uint16_t frag_off;       // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;            // Time to live
    uint8_t  protocol;       // Protocol (1=ICMP, 6=TCP, 17=UDP)
    uint16_t check;          // Header checksum
    uint32_t saddr;          // Source address
    uint32_t daddr;          // Destination address
};

class IPLayer {
private:
    MACLayer* mac_ = nullptr;
    ARP* arp_ = nullptr;

    uint32_t local_ip_ = 0;     // Host byte order
    uint32_t gateway_ip_ = 0;   // Host byte order
    uint32_t netmask_ = 0;      // Host byte order

    uint16_t ip_id_ = 0;        // IP identification counter

    // Current RX packet being processed
    const uint8_t* current_rx_payload_ = nullptr;
    size_t current_rx_len_ = 0;
    bool has_current_rx_ = false;

public:
    IPLayer() = default;
    ~IPLayer() = default;

    // Initialize IP layer
    // local_ip, gateway_ip, netmask: In host byte order (e.g., 0xC0A80164 for 192.168.1.100)
    void init(MACLayer* mac, ARP* arp, uint32_t local_ip, uint32_t gateway_ip,
             uint32_t netmask = 0xFFFFFF00) {
        if (!mac || !arp) {
            throw std::runtime_error("IPLayer: MAC or ARP is null");
        }

        mac_ = mac;
        arp_ = arp;
        local_ip_ = local_ip;
        gateway_ip_ = gateway_ip;
        netmask_ = netmask;
        ip_id_ = static_cast<uint16_t>(std::rand());
    }

    // Get local IP address (host byte order)
    uint32_t get_local_ip() const {
        return local_ip_;
    }

    // Get gateway IP address (host byte order)
    uint32_t get_gateway_ip() const {
        return gateway_ip_;
    }

    // Get gateway MAC (for TX path)
    const uint8_t* get_gateway_mac() const {
        return mac_ ? mac_->get_gateway_mac() : nullptr;
    }

    // Get next IP ID (for zero-copy TX path)
    uint16_t get_next_id() {
        return ip_id_++;
    }

    // --- TX Path: Build IP packet into buffer ---

    // Build IP packet into provided buffer
    // dst_ip: Destination IP in host byte order
    // protocol: IP_PROTO_TCP (6), IP_PROTO_UDP (17), etc.
    // payload: Packet payload (TCP/UDP)
    // len: Payload length
    // out_buffer: Output buffer (must have room for IP_HEADER_LEN + len)
    // Returns: Total packet length, or 0 on error
    size_t build_packet(uint32_t dst_ip, uint8_t protocol,
                        const uint8_t* payload, size_t len,
                        uint8_t* out_buffer, size_t buffer_capacity) {
        if (!payload || len == 0 || len > 1480) {
            return 0;
        }
        if (buffer_capacity < IP_HEADER_LEN + len) {
            return 0;
        }

        // Build IP header
        IPv4Header* hdr = reinterpret_cast<IPv4Header*>(out_buffer);
        hdr->version_ihl = 0x45;           // Version 4, IHL 5 (20 bytes)
        hdr->tos = 0;                      // No special service
        hdr->tot_len = htons(static_cast<uint16_t>(IP_HEADER_LEN + len));
        hdr->id = htons(ip_id_++);
        hdr->frag_off = htons(0x4000);     // Don't fragment flag set
        hdr->ttl = IP_DEFAULT_TTL;
        hdr->protocol = protocol;
        hdr->check = 0;                    // Calculate later
        hdr->saddr = htonl(local_ip_);
        hdr->daddr = htonl(dst_ip);

        // Calculate IP header checksum
        hdr->check = htons(ip_checksum(hdr));

        // Copy payload after IP header
        std::memcpy(out_buffer + IP_HEADER_LEN, payload, len);

        return IP_HEADER_LEN + len;
    }

    // --- RX Path: Parse IP packet from buffer ---

    // Parse IP packet from MAC layer's current RX frame
    // Returns true if valid IP packet for us
    // protocol: Output protocol (IP_PROTO_TCP, etc.)
    // payload: Output pointer to payload
    // len: Output payload length
    // src_ip: Output source IP address (host byte order)
    bool parse_packet(uint8_t* protocol, const uint8_t** payload, size_t* len,
                      uint32_t* src_ip = nullptr) {
        if (!mac_) {
            return false;
        }

        // Parse Ethernet frame first
        uint16_t ethertype;
        const uint8_t* eth_payload;
        size_t eth_len;

        if (!mac_->parse_frame(&ethertype, &eth_payload, &eth_len)) {
            return false;  // No valid frame
        }

        // Check if IPv4 packet
        if (ethertype != ETH_TYPE_IP) {
            return false;
        }

        // Validate packet size
        if (eth_len < IP_HEADER_LEN) {
            return false;
        }

        // Parse IP header
        const IPv4Header* hdr = reinterpret_cast<const IPv4Header*>(eth_payload);

        // Validate IP version and header length (reject options for HFT)
        if ((hdr->version_ihl >> 4) != IP_VERSION ||
            (hdr->version_ihl & 0x0F) != 5) {  // Require exactly IHL=5 (no options)
            return false;
        }

        // Verify checksum
        if (verify_ip_checksum(hdr) != 0) {
            return false;
        }

        // Drop fragmented packets (HFT optimization: no reassembly)
        uint16_t frag_off = ntohs(hdr->frag_off);
        if ((frag_off & 0x3FFF) != 0) {  // Check MF flag or fragment offset
            return false;
        }

        // Check if packet is for us
        uint32_t dst = ntohl(hdr->daddr);
        if (dst != local_ip_ && dst != 0xFFFFFFFF) {  // Not for us and not broadcast
            return false;
        }

        // Extract payload (use constant since we reject options)
        uint16_t total_len = ntohs(hdr->tot_len);
        if (total_len < IP_HEADER_LEN || total_len > eth_len) {
            return false;
        }

        size_t payload_len = total_len - IP_HEADER_LEN;

        // Return packet info
        *protocol = hdr->protocol;
        *payload = eth_payload + IP_HEADER_LEN;
        *len = payload_len;

        if (src_ip) {
            *src_ip = ntohl(hdr->saddr);
        }

        // Keep reference to current packet
        current_rx_payload_ = *payload;
        current_rx_len_ = *len;
        has_current_rx_ = true;

        return true;
    }

    // Clear current RX state
    void clear_rx_packet() {
        current_rx_payload_ = nullptr;
        current_rx_len_ = 0;
        has_current_rx_ = false;
    }

    // Helper: Check if IP is in local subnet
    bool is_local_subnet(uint32_t ip) const {
        return (ip & netmask_) == (local_ip_ & netmask_);
    }

    // Helper: Convert IP to string (for debugging)
    static std::string ip_to_string(uint32_t ip_host_order) {
        char buf[INET_ADDRSTRLEN];
        uint32_t ip_net = htonl(ip_host_order);
        if (inet_ntop(AF_INET, &ip_net, buf, sizeof(buf))) {
            return std::string(buf);
        }
        return "?.?.?.?";
    }

    // Helper: Parse IP string to uint32_t (host byte order)
    static uint32_t string_to_ip(const char* ip_str) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) == 1) {
            return ntohl(addr.s_addr);
        }
        throw std::runtime_error("Invalid IP address string");
    }
};

} // namespace userspace_stack
