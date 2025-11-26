// src/stack/mac/ethernet.hpp
// Minimal Ethernet Layer for WebSocket HFT
// Single outbound connection, direct gateway routing

#pragma once

#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <arpa/inet.h>

#ifdef USE_XDP
#include "../../xdp/xdp_transport.hpp"
#include "../../xdp/xdp_frame.hpp"
#endif

namespace userspace_stack {

// Ethernet frame constants
constexpr uint16_t ETH_TYPE_IP = 0x0800;
constexpr uint16_t ETH_TYPE_ARP = 0x0806;
constexpr size_t ETH_HEADER_LEN = 14;
constexpr size_t ETH_ADDR_LEN = 6;

// Ethernet header structure
struct __attribute__((packed)) EthernetHeader {
    uint8_t dst_mac[ETH_ADDR_LEN];
    uint8_t src_mac[ETH_ADDR_LEN];
    uint16_t ethertype;  // Network byte order
};

class MACLayer {
private:
#ifdef USE_XDP
    websocket::xdp::XDPTransport* xdp_ = nullptr;
#endif
    uint8_t local_mac_[ETH_ADDR_LEN] = {};
    uint8_t gateway_mac_[ETH_ADDR_LEN] = {};
    bool gateway_resolved_ = false;

    // Current RX frame being processed
#ifdef USE_XDP
    websocket::xdp::XDPFrame* current_rx_frame_ = nullptr;
#endif

public:
    MACLayer() = default;
    ~MACLayer() {
        cleanup_rx_frame();
    }

    // Initialize with XDP transport and local MAC address
#ifdef USE_XDP
    void init(websocket::xdp::XDPTransport* xdp, const uint8_t* local_mac) {
        if (!xdp) {
            throw std::runtime_error("MACLayer: XDP transport is null");
        }
        if (!local_mac) {
            throw std::runtime_error("MACLayer: Local MAC is null");
        }

        xdp_ = xdp;
        std::memcpy(local_mac_, local_mac, ETH_ADDR_LEN);
        gateway_resolved_ = false;
    }
#endif

    // Set gateway MAC address (from ARP resolution)
    void set_gateway_mac(const uint8_t* gateway_mac) {
        if (!gateway_mac) {
            throw std::runtime_error("MACLayer: Gateway MAC is null");
        }
        std::memcpy(gateway_mac_, gateway_mac, ETH_ADDR_LEN);
        gateway_resolved_ = true;
    }

    // Get local MAC address
    const uint8_t* get_local_mac() const {
        return local_mac_;
    }

    // Check if gateway is resolved
    bool is_gateway_resolved() const {
        return gateway_resolved_;
    }

    // Send Ethernet frame
    // dst_mac: Destination MAC (usually gateway)
    // ethertype: 0x0800 for IP, 0x0806 for ARP
    // payload: Packet payload
    // len: Payload length
    void send_frame(const uint8_t* dst_mac, uint16_t ethertype,
                   const uint8_t* payload, size_t len) {
#ifdef USE_XDP
        if (!xdp_) {
            throw std::runtime_error("MACLayer: Not initialized");
        }
        if (!dst_mac || !payload) {
            throw std::runtime_error("MACLayer: Null pointer in send_frame");
        }
        if (len == 0 || len > 1500) {
            throw std::runtime_error("MACLayer: Invalid payload length");
        }

        // Get TX frame from XDP
        websocket::xdp::XDPFrame* frame = xdp_->get_tx_frame();
        if (!frame) {
            throw std::runtime_error("MACLayer: Failed to get TX frame");
        }

        // Construct Ethernet header
        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(frame->data);
        std::memcpy(eth->dst_mac, dst_mac, ETH_ADDR_LEN);
        std::memcpy(eth->src_mac, local_mac_, ETH_ADDR_LEN);
        eth->ethertype = htons(ethertype);

        // Copy payload
        std::memcpy(frame->data + ETH_HEADER_LEN, payload, len);

        // Send frame
        xdp_->send_frame(frame, ETH_HEADER_LEN + len);
#else
        (void)dst_mac;
        (void)ethertype;
        (void)payload;
        (void)len;
        throw std::runtime_error("MACLayer: XDP support not compiled");
#endif
    }

    // Receive Ethernet frame
    // Returns true if frame received
    // ethertype: Output ethertype (0x0800 for IP, 0x0806 for ARP)
    // payload: Output pointer to payload (points into frame data)
    // len: Output payload length
    // src_mac: Optional output source MAC address
    bool recv_frame(uint16_t* ethertype, uint8_t** payload, size_t* len,
                   uint8_t* src_mac = nullptr) {
#ifdef USE_XDP
        if (!xdp_) {
            throw std::runtime_error("MACLayer: Not initialized");
        }

        // Release previous frame if any
        cleanup_rx_frame();

        // Peek next RX frame
        current_rx_frame_ = xdp_->peek_rx_frame();
        if (!current_rx_frame_) {
            // Debug: print every 5000 calls
            static int call_count = 0;
            if (++call_count % 5000 == 0) {
                printf("[MAC-DEBUG] peek_rx_frame returned null (%d calls)\n", call_count);
            }
            return false;  // No frame available
        }

        printf("[MAC-DEBUG] Received frame! len=%u, data=%p, addr=0x%lx\n",
               current_rx_frame_->len, (void*)current_rx_frame_->data, current_rx_frame_->addr);

        // Validate frame size
        if (current_rx_frame_->len < ETH_HEADER_LEN) {
            cleanup_rx_frame();
            return false;  // Frame too short
        }

        // Parse Ethernet header
        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(
            current_rx_frame_->data);

        // Check if frame is for us (or broadcast)
        bool for_us = (std::memcmp(eth->dst_mac, local_mac_, ETH_ADDR_LEN) == 0) ||
                     (std::memcmp(eth->dst_mac, "\xff\xff\xff\xff\xff\xff", ETH_ADDR_LEN) == 0);

        if (!for_us) {
            // Debug: print MAC addresses
            printf("[MAC-DEBUG] Frame rejected - dst_mac=%02x:%02x:%02x:%02x:%02x:%02x local_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                   eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2], eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5],
                   local_mac_[0], local_mac_[1], local_mac_[2], local_mac_[3], local_mac_[4], local_mac_[5]);
            printf("[MAC-DEBUG] Packet hex (first 64 bytes): ");
            for (int i = 0; i < 64 && i < (int)current_rx_frame_->len; i++) {
                printf("%02x ", current_rx_frame_->data[i]);
            }
            printf("\n");
            cleanup_rx_frame();
            return false;  // Not for us
        }

        // Return frame info
        *ethertype = ntohs(eth->ethertype);
        *payload = current_rx_frame_->data + ETH_HEADER_LEN;
        *len = current_rx_frame_->len - ETH_HEADER_LEN;

        if (src_mac) {
            std::memcpy(src_mac, eth->src_mac, ETH_ADDR_LEN);
        }

        return true;
#else
        (void)ethertype;
        (void)payload;
        (void)len;
        (void)src_mac;
        return false;
#endif
    }

    // Release current RX frame (must be called after processing)
    void release_rx_frame() {
        cleanup_rx_frame();
    }

private:
    void cleanup_rx_frame() {
#ifdef USE_XDP
        if (current_rx_frame_) {
            xdp_->release_rx_frame(current_rx_frame_);
            current_rx_frame_ = nullptr;
        }
#endif
    }
};

} // namespace userspace_stack
