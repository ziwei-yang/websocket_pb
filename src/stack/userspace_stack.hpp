// src/stack/userspace_stack.hpp
// Userspace TCP/IP Stack - Entry Point
//
// This is the SOLE entry point to the stack layer (./src/stack/).
// External code should only include this file, not internal headers.
//
// Architecture:
//   Transport Policy (src/policy/transport.hpp)
//       │
//       ▼
//   UserspaceStack (this file) ← ENTRY POINT
//       │
//       ├── tcp/tcp_packet.hpp   - TCP packet build/parse
//       ├── tcp/tcp_state.hpp    - TCP types & helpers
//       ├── ip/ip_layer.hpp      - IP packet build/parse
//       ├── ip/checksum.hpp      - Checksum calculation
//       ├── mac/ethernet.hpp     - Ethernet frame build/parse
//       └── mac/arp.hpp          - Gateway MAC resolution
//
// Design Principles:
//   - PURE PACKET OPERATIONS: Build and parse packets only
//   - NO I/O: Transport policy handles XDP read/write
//   - NO CONTROL FLOW: Transport policy owns loops, timers, retransmits
//   - NO STATE: TCP state owned by transport policy
//
// Usage:
//   UserspaceStack stack;
//   stack.init(local_ip, gateway_ip, netmask, local_mac);
//
//   // Build packets (returns frame length)
//   size_t len = stack.build_syn(buffer, capacity, tcp_params);
//   size_t len = stack.build_ack(buffer, capacity, tcp_params);
//   size_t len = stack.build_data(buffer, capacity, tcp_params, data, data_len);
//
//   // Parse packets
//   TCPParseResult parsed = stack.parse_tcp(frame, len, local_port, remote_ip, remote_port);
//
//   // Process through state machine (pure function)
//   TCPProcessResult result = stack.process_tcp(current_state, tcp_params, parsed);

#pragma once

#include "mac/ethernet.hpp"
#include "mac/arp.hpp"
#include "ip/ip_layer.hpp"
#include "tcp/tcp_packet.hpp"
#include "tcp/tcp_state.hpp"
#include "tcp/tcp_retransmit.hpp"
#include <functional>
#include <cstdlib>
#include <ctime>

namespace userspace_stack {

/**
 * Pure Userspace TCP/IP Stack
 *
 * Provides packet building/parsing operations only.
 * All control flow belongs in transport policy.
 */
struct UserspaceStack {
    UserspaceStack() = default;
    ~UserspaceStack() = default;

    /**
     * Initialize stack with network configuration
     *
     * @param local_ip_str Local IP (e.g., "192.168.1.100")
     * @param gateway_ip_str Gateway IP (e.g., "192.168.1.1")
     * @param netmask_str Netmask (e.g., "255.255.255.0")
     * @param local_mac 6-byte MAC address
     */
    void init(const char* local_ip_str,
              const char* gateway_ip_str,
              const char* netmask_str,
              const uint8_t* local_mac) {
        if (!local_ip_str || !gateway_ip_str || !netmask_str || !local_mac) {
            throw std::runtime_error("UserspaceStack: Invalid parameters");
        }

        // Parse IP addresses
        local_ip_ = IPLayer::string_to_ip(local_ip_str);
        gateway_ip_ = IPLayer::string_to_ip(gateway_ip_str);
        netmask_ = IPLayer::string_to_ip(netmask_str);
        std::memcpy(local_mac_, local_mac, 6);

        // Initialize layers
        mac_.init(local_mac);
        arp_.init(&mac_, local_ip_, gateway_ip_);
        ip_.init(&mac_, &arp_, local_ip_, gateway_ip_, netmask_);

        // Seed random for ISN generation
        std::srand(static_cast<unsigned>(std::time(nullptr)));

        initialized_ = true;

        // Resolve gateway MAC from /proc/net/arp
        if (!arp_.resolve_gateway(2000)) {
            throw std::runtime_error("UserspaceStack: Failed to resolve gateway MAC");
        }
    }

    // =========================================================================
    // PACKET BUILDING (Pure operations - write directly to provided buffer)
    // =========================================================================

    /**
     * Build a TCP SYN packet
     *
     * @param buffer Output buffer (UMEM frame)
     * @param capacity Buffer capacity
     * @param params TCP parameters (will use snd_nxt as seq)
     * @return Frame length, or 0 on error
     */
    size_t build_syn(uint8_t* buffer, size_t capacity, const TCPParams& params) {
        return TCPPacket::build(buffer, capacity, params, TCP_FLAG_SYN,
                               nullptr, 0, local_mac_, get_gateway_mac(), get_next_ip_id());
    }

    /**
     * Build a TCP ACK packet
     */
    size_t build_ack(uint8_t* buffer, size_t capacity, const TCPParams& params) {
        return TCPPacket::build(buffer, capacity, params, TCP_FLAG_ACK,
                               nullptr, 0, local_mac_, get_gateway_mac(), get_next_ip_id());
    }

    /**
     * Build a TCP data packet (PSH+ACK)
     */
    size_t build_data(uint8_t* buffer, size_t capacity, const TCPParams& params,
                      const uint8_t* data, size_t len) {
        return TCPPacket::build(buffer, capacity, params, TCP_FLAG_ACK | TCP_FLAG_PSH,
                               data, len, local_mac_, get_gateway_mac(), get_next_ip_id());
    }

    /**
     * Build a TCP FIN+ACK packet
     */
    size_t build_fin(uint8_t* buffer, size_t capacity, const TCPParams& params) {
        return TCPPacket::build(buffer, capacity, params, TCP_FLAG_FIN | TCP_FLAG_ACK,
                               nullptr, 0, local_mac_, get_gateway_mac(), get_next_ip_id());
    }

    /**
     * Build a TCP packet with custom flags
     */
    size_t build_tcp(uint8_t* buffer, size_t capacity, const TCPParams& params,
                     uint8_t flags, const uint8_t* data, size_t len) {
        return TCPPacket::build(buffer, capacity, params, flags,
                               data, len, local_mac_, get_gateway_mac(), get_next_ip_id());
    }

    // =========================================================================
    // PACKET PARSING (Pure operations)
    // =========================================================================

    /**
     * Parse a raw Ethernet frame containing TCP
     *
     * @param frame Raw frame data
     * @param len Frame length
     * @param local_port Expected destination port
     * @param remote_ip Expected source IP (0 to accept any)
     * @param remote_port Expected source port (0 to accept any)
     * @return Parse result
     */
    TCPParseResult parse_tcp(const uint8_t* frame, size_t len,
                             uint16_t local_port,
                             uint32_t remote_ip = 0,
                             uint16_t remote_port = 0) {
        return TCPPacket::parse(frame, len, local_ip_, local_port, remote_ip, remote_port);
    }

    /**
     * Process a parsed TCP segment through state machine
     *
     * Pure function: current_state + input → action + new_state
     */
    TCPProcessResult process_tcp(TCPState current_state, const TCPParams& params,
                                 const TCPParseResult& parsed) {
        return TCPPacket::process(current_state, params, parsed);
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    /**
     * Generate random ephemeral port (32768-60999)
     */
    static uint16_t generate_port() {
        return static_cast<uint16_t>(32768 + (std::rand() % 28232));
    }

    /**
     * Generate initial sequence number
     */
    static uint32_t generate_isn() {
        return static_cast<uint32_t>(std::rand());
    }

    /**
     * Get next IP identification number
     */
    uint16_t get_next_ip_id() {
        return ip_id_++;
    }

    // =========================================================================
    // GETTERS
    // =========================================================================

    uint32_t get_local_ip() const { return local_ip_; }
    uint32_t get_gateway_ip() const { return gateway_ip_; }
    const uint8_t* get_local_mac() const { return local_mac_; }

    const uint8_t* get_gateway_mac() const {
        if (!arp_.is_resolved()) {
            return nullptr;
        }
        return arp_.get_gateway_mac();
    }

    bool is_initialized() const { return initialized_; }

    // =========================================================================
    // STATIC HELPERS
    // =========================================================================

    static std::string ip_to_string(uint32_t ip) {
        return IPLayer::ip_to_string(ip);
    }

    static std::string mac_to_string(const uint8_t* mac) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    }

private:
    // Stack layers
    MACLayer mac_;
    ARP arp_;
    IPLayer ip_;

    // Configuration
    uint32_t local_ip_ = 0;      // Host byte order
    uint32_t gateway_ip_ = 0;    // Host byte order
    uint32_t netmask_ = 0;       // Host byte order
    uint8_t local_mac_[6] = {};

    // IP identification counter (random start like Python/kernel)
    uint16_t ip_id_ = static_cast<uint16_t>(std::time(nullptr) ^ (std::time(nullptr) >> 16));

    bool initialized_ = false;
};

} // namespace userspace_stack
