// src/stack/userspace_stack.hpp
// Minimal Userspace TCP/IP Stack for WebSocket HFT
// Unified interface for MAC + IP + TCP layers

#pragma once

#include "mac/ethernet.hpp"
#include "mac/arp.hpp"
#include "ip/ip_layer.hpp"
#include "ip/icmp.hpp"
#include "tcp/tcp_connection.hpp"

#ifdef USE_XDP
#include "../xdp/xdp_transport.hpp"
#endif

namespace userspace_stack {

class UserspaceStack {
private:
    // Stack layers
    MACLayer mac_;
    ARP arp_;
    IPLayer ip_;
    ICMP icmp_;
    TCPConnection tcp_;

    // Configuration
    uint32_t local_ip_ = 0;      // Host byte order
    uint32_t gateway_ip_ = 0;    // Host byte order
    uint32_t netmask_ = 0;       // Host byte order
    uint8_t local_mac_[6] = {};

    bool initialized_ = false;

public:
    UserspaceStack() = default;
    ~UserspaceStack() = default;

#ifdef USE_XDP
    // Initialize stack with XDP transport
    // local_ip_str: e.g., "192.168.1.100"
    // gateway_ip_str: e.g., "192.168.1.1"
    // netmask_str: e.g., "255.255.255.0"
    // local_mac: 6-byte MAC address
    void init(websocket::xdp::XDPTransport* xdp,
             const char* local_ip_str,
             const char* gateway_ip_str,
             const char* netmask_str,
             const uint8_t* local_mac) {
        if (!xdp || !local_ip_str || !gateway_ip_str || !netmask_str || !local_mac) {
            throw std::runtime_error("UserspaceStack: Invalid parameters");
        }

        // Parse IP addresses
        local_ip_ = IPLayer::string_to_ip(local_ip_str);
        gateway_ip_ = IPLayer::string_to_ip(gateway_ip_str);
        netmask_ = IPLayer::string_to_ip(netmask_str);
        std::memcpy(local_mac_, local_mac, 6);

        // Initialize layers (bottom-up)
        mac_.init(xdp, local_mac);
        arp_.init(&mac_, local_ip_, gateway_ip_);
        ip_.init(&mac_, &arp_, local_ip_, gateway_ip_, netmask_);
        icmp_.init(&ip_);
        tcp_.init(&ip_, local_ip_);

        initialized_ = true;

        // Resolve gateway MAC address
        if (!arp_.resolve_gateway(2000)) {
            throw std::runtime_error("UserspaceStack: Failed to resolve gateway MAC");
        }
    }
#endif

    // Connect TCP to remote host
    // remote_ip_str: e.g., "52.192.2.5"
    // remote_port: e.g., 443
    void connect(const char* remote_ip_str, uint16_t remote_port,
                uint32_t timeout_ms = 5000) {
        if (!initialized_) {
            throw std::runtime_error("UserspaceStack: Not initialized");
        }

        uint32_t remote_ip = IPLayer::string_to_ip(remote_ip_str);
        tcp_.connect(remote_ip, remote_port, timeout_ms);
    }

    // Connect TCP to remote host (IP as uint32_t)
    void connect(uint32_t remote_ip, uint16_t remote_port,
                uint32_t timeout_ms = 5000) {
        if (!initialized_) {
            throw std::runtime_error("UserspaceStack: Not initialized");
        }

        tcp_.connect(remote_ip, remote_port, timeout_ms);
    }

    // Send TCP data
    ssize_t send(const void* data, size_t len) {
        if (!initialized_) {
            return -1;
        }
        return tcp_.send(static_cast<const uint8_t*>(data), len);
    }

    // Receive TCP data
    ssize_t recv(void* buffer, size_t len) {
        if (!initialized_) {
            return -1;
        }
        return tcp_.recv(static_cast<uint8_t*>(buffer), len);
    }

    // Close TCP connection
    void close() {
        if (!initialized_) {
            return;
        }
        tcp_.close();
    }

    // Poll for packets (must be called periodically)
    void poll() {
        if (!initialized_) {
            return;
        }

        // NOTE: ARP and ICMP process_rx() are REMOVED from the poll loop.
        // Bug: They were consuming TCP frames by calling recv_frame()/recv_packet()
        // and releasing non-ARP/non-ICMP frames, leaving nothing for TCP.
        //
        // For HFT: Gateway MAC is resolved once at init, no runtime ARP needed.
        // ICMP (ping) is not critical for WebSocket connections.
        //
        // If ARP needs to be re-resolved or ICMP responses are needed,
        // they should be called explicitly, not in the poll loop.

        // Process TCP packets only
        tcp_.poll();
    }

    // Get TCP connection state
    TCPState get_state() const {
        return tcp_.get_state();
    }

    // Check if TCP is connected
    bool is_connected() const {
        return tcp_.is_connected();
    }

    // Get local IP address (host byte order)
    uint32_t get_local_ip() const {
        return local_ip_;
    }

    // Get gateway IP address (host byte order)
    uint32_t get_gateway_ip() const {
        return gateway_ip_;
    }

    // Get local MAC address
    const uint8_t* get_local_mac() const {
        return local_mac_;
    }

    // Get gateway MAC address (after ARP resolution)
    const uint8_t* get_gateway_mac() const {
        if (!arp_.is_resolved()) {
            return nullptr;
        }
        return arp_.get_gateway_mac();
    }

    // Helper: Convert IP to string
    static std::string ip_to_string(uint32_t ip) {
        return IPLayer::ip_to_string(ip);
    }

    // Helper: Convert MAC to string
    static std::string mac_to_string(const uint8_t* mac) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    }
};

} // namespace userspace_stack
