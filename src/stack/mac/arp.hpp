// src/stack/mac/arp.hpp
// Minimal ARP for WebSocket HFT
// Single gateway entry only (no cache, no timeout)

#pragma once

#include "ethernet.hpp"
#include <chrono>
#include <thread>

namespace userspace_stack {

// ARP constants
constexpr uint16_t ARP_HTYPE_ETHERNET = 1;
constexpr uint16_t ARP_PTYPE_IP = 0x0800;
constexpr uint16_t ARP_OP_REQUEST = 1;
constexpr uint16_t ARP_OP_REPLY = 2;
constexpr size_t ARP_PACKET_LEN = 28;

// ARP packet structure (for Ethernet + IPv4)
struct __attribute__((packed)) ARPPacket {
    uint16_t htype;          // Hardware type (Ethernet = 1)
    uint16_t ptype;          // Protocol type (IPv4 = 0x0800)
    uint8_t  hlen;           // Hardware address length (6 for MAC)
    uint8_t  plen;           // Protocol address length (4 for IPv4)
    uint16_t oper;           // Operation (1 = request, 2 = reply)
    uint8_t  sha[6];         // Sender hardware address (MAC)
    uint32_t spa;            // Sender protocol address (IP)
    uint8_t  tha[6];         // Target hardware address (MAC)
    uint32_t tpa;            // Target protocol address (IP)
};

class ARP {
private:
    MACLayer* mac_ = nullptr;
    uint32_t local_ip_ = 0;    // Network byte order
    uint32_t gateway_ip_ = 0;  // Network byte order
    uint8_t gateway_mac_[6] = {};
    bool resolved_ = false;

public:
    ARP() = default;

    // Initialize ARP
    void init(MACLayer* mac, uint32_t local_ip, uint32_t gateway_ip) {
        if (!mac) {
            throw std::runtime_error("ARP: MAC layer is null");
        }

        mac_ = mac;
        local_ip_ = htonl(local_ip);     // Convert to network byte order
        gateway_ip_ = htonl(gateway_ip); // Convert to network byte order
        resolved_ = false;
    }

    // Resolve gateway MAC address
    // Sends ARP request and waits for reply
    // timeout_ms: Timeout in milliseconds
    // Returns true if resolved, false on timeout
    bool resolve_gateway(uint32_t timeout_ms = 2000) {
        if (!mac_) {
            throw std::runtime_error("ARP: Not initialized");
        }

        if (resolved_) {
            return true;  // Already resolved
        }

        // Try to read from system ARP table first (workaround for no flow steering)
        if (read_arp_from_system()) {
            mac_->set_gateway_mac(gateway_mac_);
            return true;
        }

        auto start = std::chrono::steady_clock::now();
        int retries = 0;
        const int max_retries = 3;

        while (retries < max_retries) {
            // Send ARP request
            send_arp_request();

            // Wait for reply (with timeout)
            auto request_start = std::chrono::steady_clock::now();
            while (true) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - start).count();

                if (elapsed_ms >= timeout_ms) {
                    return false;  // Overall timeout
                }

                // Check for ARP reply
                if (process_rx()) {
                    if (resolved_) {
                        mac_->set_gateway_mac(gateway_mac_);
                        return true;
                    }
                }

                // Retry after 500ms
                auto retry_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - request_start).count();
                if (retry_elapsed >= 500) {
                    break;  // Retry
                }

                // Sleep briefly to avoid busy loop
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }

            retries++;
        }

        return false;  // Failed after retries
    }

    // Get gateway MAC (must call resolve_gateway first)
    const uint8_t* get_gateway_mac() const {
        if (!resolved_) {
            throw std::runtime_error("ARP: Gateway not resolved");
        }
        return gateway_mac_;
    }

    // Check if gateway is resolved
    bool is_resolved() const {
        return resolved_;
    }

    // Process incoming ARP packets (called by poll loop)
    bool process_rx() {
        if (!mac_) {
            return false;
        }

        uint16_t ethertype;
        uint8_t* payload;
        size_t len;
        uint8_t src_mac[6];

        if (!mac_->recv_frame(&ethertype, &payload, &len, src_mac)) {
            return false;  // No frame
        }

        // Check if ARP packet
        if (ethertype != ETH_TYPE_ARP) {
            mac_->release_rx_frame();
            return false;
        }

        // Validate ARP packet size
        if (len < ARP_PACKET_LEN) {
            mac_->release_rx_frame();
            return false;
        }

        // Parse ARP packet
        const ARPPacket* arp = reinterpret_cast<const ARPPacket*>(payload);

        // Validate ARP header
        if (ntohs(arp->htype) != ARP_HTYPE_ETHERNET ||
            ntohs(arp->ptype) != ARP_PTYPE_IP ||
            arp->hlen != 6 || arp->plen != 4) {
            mac_->release_rx_frame();
            return false;
        }

        uint16_t oper = ntohs(arp->oper);

        // Handle ARP request (we are the target)
        if (oper == ARP_OP_REQUEST && arp->tpa == local_ip_) {
            // Send ARP reply
            send_arp_reply(src_mac, arp->spa, arp->sha);
            mac_->release_rx_frame();
            return true;
        }

        // Handle ARP reply (we sent the request)
        if (oper == ARP_OP_REPLY && arp->spa == gateway_ip_) {
            // This is the gateway's reply
            std::memcpy(gateway_mac_, arp->sha, 6);
            resolved_ = true;
            mac_->release_rx_frame();
            return true;
        }

        mac_->release_rx_frame();
        return false;
    }

private:
    // Try to read gateway MAC from system ARP table
    // Workaround when flow steering is not available
    bool read_arp_from_system() {
        // Convert gateway IP from network byte order to string
        uint32_t gw_host = ntohl(gateway_ip_);
        char gateway_ip_str[32];
        snprintf(gateway_ip_str, sizeof(gateway_ip_str), "%u.%u.%u.%u",
                 (gw_host >> 24) & 0xFF,
                 (gw_host >> 16) & 0xFF,
                 (gw_host >> 8) & 0xFF,
                 gw_host & 0xFF);

        printf("[ARP] Looking for gateway %s in system ARP table\n", gateway_ip_str);

        FILE* fp = fopen("/proc/net/arp", "r");
        if (!fp) {
            printf("[ARP] Failed to open /proc/net/arp\n");
            return false;
        }

        char line[256];
        // Skip header
        if (!fgets(line, sizeof(line), fp)) {
            fclose(fp);
            return false;
        }

        // Parse ARP entries
        while (fgets(line, sizeof(line), fp)) {
            char ip[64], hw_type[16], flags[16], hw_addr[32], mask[16], device[32];
            if (sscanf(line, "%s %s %s %s %s %s",
                      ip, hw_type, flags, hw_addr, mask, device) == 6) {
                printf("[ARP] Found entry: IP=%s MAC=%s Device=%s\n", ip, hw_addr, device);
                if (strcmp(ip, gateway_ip_str) == 0) {
                    printf("[ARP] Gateway matched! Parsing MAC: %s\n", hw_addr);
                    // Found gateway - parse MAC
                    unsigned int mac[6];
                    if (sscanf(hw_addr, "%x:%x:%x:%x:%x:%x",
                              &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                        for (int i = 0; i < 6; i++) {
                            gateway_mac_[i] = static_cast<uint8_t>(mac[i]);
                        }
                        resolved_ = true;
                        printf("[ARP] Successfully read gateway MAC from system: %02x:%02x:%02x:%02x:%02x:%02x\n",
                               gateway_mac_[0], gateway_mac_[1], gateway_mac_[2],
                               gateway_mac_[3], gateway_mac_[4], gateway_mac_[5]);
                        fclose(fp);
                        return true;
                    }
                }
            }
        }

        printf("[ARP] Gateway not found in system ARP table\n");
        fclose(fp);
        return false;
    }

    // Send ARP request for gateway
    void send_arp_request() {
        ARPPacket arp = {};
        arp.htype = htons(ARP_HTYPE_ETHERNET);
        arp.ptype = htons(ARP_PTYPE_IP);
        arp.hlen = 6;
        arp.plen = 4;
        arp.oper = htons(ARP_OP_REQUEST);

        // Sender = us
        std::memcpy(arp.sha, mac_->get_local_mac(), 6);
        arp.spa = local_ip_;

        // Target = gateway (MAC unknown, IP known)
        std::memset(arp.tha, 0, 6);
        arp.tpa = gateway_ip_;

        // Send as Ethernet broadcast
        const uint8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        mac_->send_frame(broadcast, ETH_TYPE_ARP,
                        reinterpret_cast<const uint8_t*>(&arp), ARP_PACKET_LEN);
    }

    // Send ARP reply
    void send_arp_reply(const uint8_t* dst_mac, uint32_t dst_ip, const uint8_t* dst_hw) {
        ARPPacket arp = {};
        arp.htype = htons(ARP_HTYPE_ETHERNET);
        arp.ptype = htons(ARP_PTYPE_IP);
        arp.hlen = 6;
        arp.plen = 4;
        arp.oper = htons(ARP_OP_REPLY);

        // Sender = us
        std::memcpy(arp.sha, mac_->get_local_mac(), 6);
        arp.spa = local_ip_;

        // Target = requester
        std::memcpy(arp.tha, dst_hw, 6);
        arp.tpa = dst_ip;

        // Send to requester
        mac_->send_frame(dst_mac, ETH_TYPE_ARP,
                        reinterpret_cast<const uint8_t*>(&arp), ARP_PACKET_LEN);
    }
};

} // namespace userspace_stack
