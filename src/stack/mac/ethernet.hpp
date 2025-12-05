// src/stack/mac/ethernet.hpp
// Ethernet Frame Building and Parsing (Internal)
//
// INTERNAL: Use UserspaceStack (userspace_stack.hpp) as the entry point.
//
// Provides:
//   - EthernetHeader struct (14-byte Ethernet header)
//   - MACLayer::build_frame() - Build Ethernet frame into buffer
//   - MACLayer::parse_frame() - Parse Ethernet frame
//   - TxFrameContext / RxFrameContext - Frame buffer contexts
//   - Ethertype constants (ETH_TYPE_IP, ETH_TYPE_ARP)

#pragma once

#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <arpa/inet.h>

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

/**
 * @brief TX frame context for building outgoing packets
 *
 * Transport policy allocates frame buffer and passes to stack.
 * Stack writes headers/data, returns total length.
 */
struct TxFrameContext {
    uint8_t* data;       // Frame buffer (transport-owned)
    size_t capacity;     // Buffer capacity
    size_t len;          // Written length (set by stack)
};

/**
 * @brief RX frame context for parsing incoming packets
 *
 * Transport policy receives frame and passes to stack.
 * Stack parses headers and returns payload pointer.
 */
struct RxFrameContext {
    const uint8_t* data;  // Frame data (transport-owned)
    size_t len;           // Frame length
};

struct MACLayer {
    MACLayer() = default;
    ~MACLayer() = default;

    // Initialize with local MAC address (no transport pointer needed)
    void init(const uint8_t* local_mac) {
        if (!local_mac) {
            throw std::runtime_error("MACLayer: Local MAC is null");
        }
        std::memcpy(local_mac_, local_mac, ETH_ADDR_LEN);
        gateway_resolved_ = false;
    }

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

    // Get gateway MAC address
    const uint8_t* get_gateway_mac() const {
        return gateway_mac_;
    }

    // Check if gateway is resolved
    bool is_gateway_resolved() const {
        return gateway_resolved_;
    }

    // --- TX Path: Build Ethernet frame into provided buffer ---

    // Set TX frame context (called by transport policy before sending)
    void set_tx_frame(TxFrameContext* tx) {
        current_tx_ = tx;
    }

    // Build Ethernet frame header into TX buffer
    // dst_mac: Destination MAC (usually gateway)
    // ethertype: 0x0800 for IP, 0x0806 for ARP
    // payload: Packet payload
    // len: Payload length
    // Returns: Total frame length, or 0 on error
    size_t build_frame(const uint8_t* dst_mac, uint16_t ethertype,
                       const uint8_t* payload, size_t len) {
        if (!current_tx_ || !current_tx_->data) {
            return 0;
        }
        if (!dst_mac || !payload) {
            return 0;
        }
        if (len == 0 || len > 1500) {
            return 0;
        }
        if (ETH_HEADER_LEN + len > current_tx_->capacity) {
            return 0;
        }

        // Construct Ethernet header
        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(current_tx_->data);
        std::memcpy(eth->dst_mac, dst_mac, ETH_ADDR_LEN);
        std::memcpy(eth->src_mac, local_mac_, ETH_ADDR_LEN);
        eth->ethertype = htons(ethertype);

        // Copy payload
        std::memcpy(current_tx_->data + ETH_HEADER_LEN, payload, len);

        current_tx_->len = ETH_HEADER_LEN + len;
        return current_tx_->len;
    }

    // --- RX Path: Parse Ethernet frame from provided buffer ---

    // Set RX frame context (called by transport policy when frame received)
    void set_rx_frame(RxFrameContext* rx) {
        current_rx_ = rx;
    }

    // Clear RX frame context
    void clear_rx_frame() {
        current_rx_ = nullptr;
    }

    // Parse Ethernet frame from RX buffer
    // ethertype: Output ethertype (0x0800 for IP, 0x0806 for ARP)
    // payload: Output pointer to payload (points into frame data)
    // len: Output payload length
    // src_mac: Optional output source MAC address
    // Returns: true if valid frame for us, false otherwise
    bool parse_frame(uint16_t* ethertype, const uint8_t** payload, size_t* len,
                     uint8_t* src_mac = nullptr) {
        if (!current_rx_ || !current_rx_->data) {
            return false;
        }

        // Validate frame size
        if (current_rx_->len < ETH_HEADER_LEN) {
            return false;  // Frame too short
        }

        // Parse Ethernet header
        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(
            current_rx_->data);

        // Check if frame is for us (or broadcast)
        bool for_us = (std::memcmp(eth->dst_mac, local_mac_, ETH_ADDR_LEN) == 0) ||
                      (std::memcmp(eth->dst_mac, "\xff\xff\xff\xff\xff\xff", ETH_ADDR_LEN) == 0);

        if (!for_us) {
            return false;  // Not for us
        }

        // Return frame info
        *ethertype = ntohs(eth->ethertype);
        *payload = current_rx_->data + ETH_HEADER_LEN;
        *len = current_rx_->len - ETH_HEADER_LEN;

        if (src_mac) {
            std::memcpy(src_mac, eth->src_mac, ETH_ADDR_LEN);
        }

        return true;
    }

private:
    uint8_t local_mac_[ETH_ADDR_LEN] = {};
    uint8_t gateway_mac_[ETH_ADDR_LEN] = {};
    bool gateway_resolved_ = false;

    // Current RX/TX frame contexts (set by transport policy)
    RxFrameContext* current_rx_ = nullptr;
    TxFrameContext* current_tx_ = nullptr;
};

} // namespace userspace_stack
