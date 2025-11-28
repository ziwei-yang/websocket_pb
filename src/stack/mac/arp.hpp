// src/stack/mac/arp.hpp
// Gateway MAC Resolution via /proc/net/arp (Internal)
//
// INTERNAL: Use UserspaceStack (userspace_stack.hpp) as the entry point.
//
// Provides:
//   - ARP::resolve_gateway() - Read gateway MAC from /proc/net/arp
//   - ARP::get_gateway_mac() - Get resolved gateway MAC
//
// Note: Does NOT send ARP packets. Relies on kernel ARP cache.
// The kernel populates /proc/net/arp when traffic flows through the gateway.

#pragma once

#include "ethernet.hpp"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>

namespace userspace_stack {

class ARP {
private:
    MACLayer* mac_ = nullptr;
    uint32_t gateway_ip_ = 0;  // Host byte order
    uint8_t gateway_mac_[6] = {};
    bool resolved_ = false;

public:
    ARP() = default;

    // Initialize ARP
    void init(MACLayer* mac, uint32_t local_ip, uint32_t gateway_ip) {
        (void)local_ip;  // Not needed for /proc/net/arp approach
        if (!mac) {
            throw std::runtime_error("ARP: MAC layer is null");
        }
        mac_ = mac;
        gateway_ip_ = gateway_ip;  // Keep in host byte order
        resolved_ = false;
    }

    // Resolve gateway MAC address from /proc/net/arp
    // Returns true if resolved, false on failure
    bool resolve_gateway(uint32_t timeout_ms = 2000) {
        (void)timeout_ms;  // Not used for /proc/net/arp

        if (resolved_) {
            return true;
        }

        // Convert gateway IP to string
        char gateway_ip_str[32];
        snprintf(gateway_ip_str, sizeof(gateway_ip_str), "%u.%u.%u.%u",
                 (gateway_ip_ >> 24) & 0xFF,
                 (gateway_ip_ >> 16) & 0xFF,
                 (gateway_ip_ >> 8) & 0xFF,
                 gateway_ip_ & 0xFF);

        printf("[ARP] Looking for gateway %s in /proc/net/arp\n", gateway_ip_str);

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
                if (strcmp(ip, gateway_ip_str) == 0) {
                    // Found gateway - parse MAC
                    unsigned int mac[6];
                    if (sscanf(hw_addr, "%x:%x:%x:%x:%x:%x",
                              &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                        for (int i = 0; i < 6; i++) {
                            gateway_mac_[i] = static_cast<uint8_t>(mac[i]);
                        }
                        resolved_ = true;
                        printf("[ARP] Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                               gateway_mac_[0], gateway_mac_[1], gateway_mac_[2],
                               gateway_mac_[3], gateway_mac_[4], gateway_mac_[5]);
                        fclose(fp);

                        // Update MAC layer
                        if (mac_) {
                            mac_->set_gateway_mac(gateway_mac_);
                        }
                        return true;
                    }
                }
            }
        }

        printf("[ARP] Gateway not found in /proc/net/arp\n");
        fclose(fp);
        return false;
    }

    // Get gateway MAC (must call resolve_gateway first)
    const uint8_t* get_gateway_mac() const {
        return gateway_mac_;
    }

    // Check if gateway is resolved
    bool is_resolved() const {
        return resolved_;
    }
};

} // namespace userspace_stack
