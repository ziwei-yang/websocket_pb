// src/stack/ip/ip_layer.hpp
// Minimal IPv4 Layer for WebSocket HFT
// No fragmentation, no options, direct routing

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
    uint8_t* current_rx_payload_ = nullptr;
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

    // Send IP packet
    // dst_ip: Destination IP in host byte order
    // protocol: IP_PROTO_TCP (6), IP_PROTO_UDP (17), etc.
    // payload: Packet payload (TCP/UDP/ICMP)
    // len: Payload length
    void send_packet(uint32_t dst_ip, uint8_t protocol,
                    const uint8_t* payload, size_t len) {
        if (!mac_ || !arp_) {
            throw std::runtime_error("IPLayer: Not initialized");
        }
        if (!payload || len == 0 || len > 1480) {
            throw std::runtime_error("IPLayer: Invalid payload");
        }

        // Ensure gateway is resolved
        if (!arp_->is_resolved()) {
            throw std::runtime_error("IPLayer: Gateway MAC not resolved");
        }

        // Build IP header
        IPv4Header hdr = {};
        hdr.version_ihl = 0x45;           // Version 4, IHL 5 (20 bytes)
        hdr.tos = 0;                      // No special service
        hdr.tot_len = htons(static_cast<uint16_t>(IP_HEADER_LEN + len));
        hdr.id = htons(ip_id_++);
        hdr.frag_off = htons(0x4000);     // Don't fragment flag set
        hdr.ttl = IP_DEFAULT_TTL;
        hdr.protocol = protocol;
        hdr.check = 0;                    // Calculate later
        hdr.saddr = htonl(local_ip_);
        hdr.daddr = htonl(dst_ip);

        // Calculate IP header checksum
        hdr.check = htons(ip_checksum(&hdr));

        // Construct complete IP packet
        uint8_t packet[1500];
        std::memcpy(packet, &hdr, IP_HEADER_LEN);
        std::memcpy(packet + IP_HEADER_LEN, payload, len);

        // Determine next hop MAC address
        // For simplicity, always send to gateway (no local network routing)
        const uint8_t* next_hop_mac = arp_->get_gateway_mac();

        // Send via MAC layer
        mac_->send_frame(next_hop_mac, ETH_TYPE_IP, packet, IP_HEADER_LEN + len);
    }

    // Receive IP packet
    // Returns true if packet received
    // protocol: Output protocol (IP_PROTO_TCP, etc.)
    // payload: Output pointer to payload (points into frame data)
    // len: Output payload length
    // src_ip: Output source IP address (host byte order)
    bool recv_packet(uint8_t* protocol, uint8_t** payload, size_t* len,
                    uint32_t* src_ip = nullptr) {
        if (!mac_) {
            throw std::runtime_error("IPLayer: Not initialized");
        }

        // Release previous packet if any
        release_rx_packet();

        uint16_t ethertype;
        uint8_t* frame_payload;
        size_t frame_len;

        if (!mac_->recv_frame(&ethertype, &frame_payload, &frame_len)) {
            return false;  // No frame
        }

        // Check if IPv4 packet
        if (ethertype != ETH_TYPE_IP) {
            mac_->release_rx_frame();
            return false;
        }

        // Validate packet size
        if (frame_len < IP_HEADER_LEN) {
            mac_->release_rx_frame();
            return false;
        }

        // Parse IP header
        const IPv4Header* hdr = reinterpret_cast<const IPv4Header*>(frame_payload);

        // Validate IP version and header length (reject options for HFT)
        if ((hdr->version_ihl >> 4) != IP_VERSION ||
            (hdr->version_ihl & 0x0F) != 5) {  // Require exactly IHL=5 (no options)
            mac_->release_rx_frame();
            return false;
        }

        // Verify checksum
        if (verify_ip_checksum(hdr) != 0) {
            mac_->release_rx_frame();
            return false;
        }

        // Drop fragmented packets (HFT optimization: no reassembly)
        uint16_t frag_off = ntohs(hdr->frag_off);
        if ((frag_off & 0x3FFF) != 0) {  // Check MF flag or fragment offset
            mac_->release_rx_frame();
            return false;
        }

        // Check if packet is for us
        uint32_t dst = ntohl(hdr->daddr);
        if (dst != local_ip_ && dst != 0xFFFFFFFF) {  // Not for us and not broadcast
            mac_->release_rx_frame();
            return false;
        }

        // Extract payload (use constant since we reject options)
        uint16_t total_len = ntohs(hdr->tot_len);
        if (total_len < IP_HEADER_LEN || total_len > frame_len) {
            mac_->release_rx_frame();
            return false;
        }

        size_t payload_len = total_len - IP_HEADER_LEN;

        // Return packet info
        *protocol = hdr->protocol;
        *payload = frame_payload + IP_HEADER_LEN;
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

    // Release current RX packet (must be called after processing)
    void release_rx_packet() {
        if (has_current_rx_) {
            mac_->release_rx_frame();
            current_rx_payload_ = nullptr;
            current_rx_len_ = 0;
            has_current_rx_ = false;
        }
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
