// src/xdp/bpf_loader.hpp
// BPF program loader and management for XDP packet filtering
//
// This class loads the eBPF exchange filter program, attaches it to the network
// interface, and provides APIs to configure exchange IPs/ports at runtime.

#pragma once

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <net/if.h>

// BPF_F_XDP_DEV_BOUND_ONLY flag for device-bound XDP programs
// Required for XDP metadata kfuncs (bpf_xdp_metadata_rx_timestamp, etc.)
#ifndef BPF_F_XDP_DEV_BOUND_ONLY
#define BPF_F_XDP_DEV_BOUND_ONLY (1U << 6)
#endif
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>
#include <fcntl.h>

namespace websocket::xdp {

// BPF statistics indices (must match exchange_filter.bpf.c)
enum BPFStat {
    STAT_TOTAL_PACKETS = 0,
    STAT_EXCHANGE_PACKETS = 1,
    STAT_KERNEL_PACKETS = 2,
    STAT_DROPPED_PACKETS = 3,
    STAT_PARSE_ERRORS = 4,
    STAT_IPV4_PACKETS = 5,
    STAT_TCP_PACKETS = 6,
    STAT_NON_TCP_PACKETS = 7,
    STAT_INCOMING_CHECK = 8,
    STAT_IP_MATCH = 9,
    STAT_TIMESTAMP_OK = 10,
    STAT_TIMESTAMP_FAIL = 11,
};

struct BPFStats {
    uint64_t total_packets;
    uint64_t exchange_packets;
    uint64_t kernel_packets;
    uint64_t dropped_packets;
    uint64_t parse_errors;
    uint64_t ipv4_packets;
    uint64_t tcp_packets;
    uint64_t non_tcp_packets;
    uint64_t timestamp_ok;
    uint64_t timestamp_fail;
};

class BPFLoader {
private:
    struct bpf_object* bpf_obj_ = nullptr;
    struct bpf_program* bpf_prog_ = nullptr;
    int prog_fd_ = -1;
    int ifindex_ = -1;

    // Map file descriptors
    int xsks_map_fd_ = -1;
    int exchange_ips_fd_ = -1;
    int exchange_ports_fd_ = -1;
    int stats_fd_ = -1;
    int local_ip_fd_ = -1;  // Phase 1: Local IP for destination-based filtering

    bool attached_ = false;
    uint32_t xdp_flags_ = 0;  // Track flags used during attach
    std::string interface_;
    std::string bpf_obj_path_;

public:
    BPFLoader() = default;

    ~BPFLoader() {
        cleanup();
    }

    // Load BPF program from object file
    void load(const char* interface, const char* bpf_obj_path) {
        if (!interface || !bpf_obj_path) {
            throw std::runtime_error("BPFLoader: Invalid parameters");
        }

        interface_ = interface;
        bpf_obj_path_ = bpf_obj_path;

        // Get interface index
        ifindex_ = if_nametoindex(interface);
        if (ifindex_ == 0) {
            throw std::runtime_error(std::string("BPFLoader: Interface not found: ") + interface);
        }

        printf("[BPF] Loading program from: %s\n", bpf_obj_path);

        // Open BPF object file
        bpf_obj_ = bpf_object__open_file(bpf_obj_path, nullptr);
        if (libbpf_get_error(bpf_obj_)) {
            throw std::runtime_error("BPFLoader: Failed to open BPF object file");
        }

        // Find the XDP program first (before loading)
        bpf_prog_ = bpf_object__find_program_by_name(bpf_obj_, "exchange_packet_filter");
        if (!bpf_prog_) {
            bpf_object__close(bpf_obj_);
            bpf_obj_ = nullptr;
            throw std::runtime_error("BPFLoader: Failed to find XDP program 'exchange_packet_filter'");
        }

        // Device-bound loading for XDP metadata kfuncs (bpf_xdp_metadata_rx_timestamp)
        // Requires kernel 6.3+ with fix 714070c4cb7a for XDP_REDIRECT to XSKMAP
        bpf_program__set_ifindex(bpf_prog_, ifindex_);
        bpf_program__set_flags(bpf_prog_, BPF_F_XDP_DEV_BOUND_ONLY);
        printf("[BPF] Device-bound loading ENABLED (ifindex=%d)\n", ifindex_);

        // Load BPF program into kernel
        if (bpf_object__load(bpf_obj_)) {
            bpf_object__close(bpf_obj_);
            bpf_obj_ = nullptr;
            throw std::runtime_error("BPFLoader: Failed to load BPF program into kernel");
        }

        prog_fd_ = bpf_program__fd(bpf_prog_);
        if (prog_fd_ < 0) {
            cleanup();
            throw std::runtime_error("BPFLoader: Failed to get program FD");
        }

        // Get map file descriptors
        xsks_map_fd_ = bpf_object__find_map_fd_by_name(bpf_obj_, "xsks_map");
        exchange_ips_fd_ = bpf_object__find_map_fd_by_name(bpf_obj_, "exchange_ips");
        exchange_ports_fd_ = bpf_object__find_map_fd_by_name(bpf_obj_, "exchange_ports");
        stats_fd_ = bpf_object__find_map_fd_by_name(bpf_obj_, "stats");
        local_ip_fd_ = bpf_object__find_map_fd_by_name(bpf_obj_, "local_ip");

        if (xsks_map_fd_ < 0 || exchange_ips_fd_ < 0 ||
            exchange_ports_fd_ < 0 || stats_fd_ < 0 || local_ip_fd_ < 0) {
            cleanup();
            throw std::runtime_error("BPFLoader: Failed to get map FDs");
        }

        printf("[BPF] ✅ Program loaded successfully\n");
        printf("[BPF]    Program FD: %d\n", prog_fd_);
        printf("[BPF]    XSKS map FD: %d\n", xsks_map_fd_);
        printf("[BPF]    Exchange IPs map FD: %d\n", exchange_ips_fd_);
        printf("[BPF]    Exchange ports map FD: %d\n", exchange_ports_fd_);
        printf("[BPF]    Stats map FD: %d\n", stats_fd_);
        printf("[BPF]    Local IP map FD: %d\n", local_ip_fd_);
    }

    // Attach BPF program to interface
    void attach(uint32_t xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST) {
        if (prog_fd_ < 0) {
            throw std::runtime_error("BPFLoader: Program not loaded");
        }

        if (attached_) {
            return;  // Already attached
        }

        printf("[BPF] Attaching to interface %s (ifindex=%d)...\n", interface_.c_str(), ifindex_);

        // First, try to query if there's an existing program
        // We'll use REPLACE flag to atomically replace it
        __u32 existing_prog_id = 0;
        __u32 existing_flags = 0;

        // Query existing XDP program
        int query_ret = bpf_xdp_query_id(ifindex_, 0, &existing_prog_id);
        if (query_ret == 0 && existing_prog_id != 0) {
            printf("[BPF] Found existing XDP program (ID %u), will replace\n", existing_prog_id);
            xdp_flags |= XDP_FLAGS_REPLACE;
        }

        // Attach our program (will replace any existing program)
        int ret = bpf_xdp_attach(ifindex_, prog_fd_, xdp_flags, nullptr);

        if (ret < 0) {
            // If it still fails, try with SKB mode
            printf("[BPF] Native mode failed (%s), trying SKB mode...\n", strerror(-ret));
            xdp_flags = XDP_FLAGS_SKB_MODE;
            ret = bpf_xdp_attach(ifindex_, prog_fd_, xdp_flags, nullptr);
        }

        if (ret < 0) {
            throw std::runtime_error(
                std::string("BPFLoader: Failed to attach XDP program: ") + strerror(-ret));
        }

        xdp_flags_ = xdp_flags;  // Store flags for later detach
        attached_ = true;
        printf("[BPF] ✅ Program attached to %s\n", interface_.c_str());
    }

    // Detach BPF program from interface
    void detach() {
        if (!attached_ || ifindex_ == 0) {
            return;
        }

        printf("[BPF] Detaching from interface %s...\n", interface_.c_str());

        // Use the same flags that were used during attach
        bpf_xdp_detach(ifindex_, xdp_flags_, nullptr);
        attached_ = false;
        xdp_flags_ = 0;

        printf("[BPF] ✅ Program detached\n");
    }

    // Register AF_XDP socket in xsks_map
    // Note: When using XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, you must call this
    // with the xsk_socket pointer, not just the FD
    void register_xsk_socket(struct xsk_socket* xsk) {
        if (xsks_map_fd_ < 0) {
            throw std::runtime_error("BPFLoader: XSKS map not available");
        }

        if (!xsk) {
            throw std::runtime_error("BPFLoader: Invalid XSK socket pointer");
        }

        int xsk_fd = xsk_socket__fd(xsk);

        // Get map ID to verify we're updating the correct map
        struct bpf_map_info map_info = {};
        uint32_t info_len = sizeof(map_info);
        int ret_info = bpf_obj_get_info_by_fd(xsks_map_fd_, &map_info, &info_len);
        if (ret_info == 0) {
            printf("[BPF] Registering XSK socket: fd=%d, map_fd=%d, map_id=%u, map_name=%s\n",
                   xsk_fd, xsks_map_fd_, map_info.id, map_info.name);
        } else {
            printf("[BPF] Registering XSK socket: fd=%d, map_fd=%d (failed to get map info: %s)\n",
                   xsk_fd, xsks_map_fd_, strerror(errno));
        }

        // Verify FD is valid before registering
        int fd_flags = fcntl(xsk_fd, F_GETFD);
        if (fd_flags < 0) {
            throw std::runtime_error(
                std::string("BPFLoader: XSK FD is invalid: ") + strerror(errno));
        }
        printf("[BPF]   XSK FD is valid (flags=0x%x)\n", fd_flags);

        // Use libxsk API to update the xsks_map - this is the proper way!
        // This function knows how to correctly register the socket in the map
        int ret = xsk_socket__update_xskmap(xsk, xsks_map_fd_);
        if (ret < 0) {
            throw std::runtime_error(
                std::string("BPFLoader: Failed to register XSK socket: ") + strerror(-ret));
        }

        printf("[BPF] ✅ Registered AF_XDP socket using xsk_socket__update_xskmap()\n");

        // Verify registration by reading back from map
        uint32_t key = 0;  // We always use queue_id = 0
        int map_xsk_fd = -1;
        ret = bpf_map_lookup_elem(xsks_map_fd_, &key, &map_xsk_fd);
        if (ret == 0) {
            printf("[BPF] ✓ Verified: xsks_map[%u] = %d (expected %d)\n", key, map_xsk_fd, xsk_fd);
            if (map_xsk_fd != xsk_fd) {
                printf("[BPF] ⚠️  WARNING: Map contains different FD than expected!\n");
            }
        } else {
            printf("[BPF] ⚠️  WARNING: Could not read back xsks_map[%u]: %s\n", key, strerror(-ret));
        }
    }

    // Legacy method for backward compatibility
    void register_xsk(uint32_t queue_id, int xsk_fd) {
        if (xsks_map_fd_ < 0) {
            throw std::runtime_error("BPFLoader: XSKS map not available");
        }

        printf("[BPF] Registering XSK (legacy): queue=%u, fd=%d, map_fd=%d\n", queue_id, xsk_fd, xsks_map_fd_);

        int ret = bpf_map_update_elem(xsks_map_fd_, &queue_id, &xsk_fd, BPF_ANY);
        if (ret < 0) {
            throw std::runtime_error(
                std::string("BPFLoader: Failed to register XSK: ") + strerror(errno));
        }

        printf("[BPF] ✅ Registered AF_XDP socket (queue=%u, fd=%d)\n", queue_id, xsk_fd);
    }

    // Add exchange IP address (network byte order)
    void add_exchange_ip(uint32_t ip_net) {
        if (exchange_ips_fd_ < 0) {
            throw std::runtime_error("BPFLoader: Exchange IPs map not available");
        }

        uint8_t val = 1;
        int ret = bpf_map_update_elem(exchange_ips_fd_, &ip_net, &val, BPF_ANY);
        if (ret < 0) {
            throw std::runtime_error(
                std::string("BPFLoader: Failed to add exchange IP: ") + strerror(errno));
        }

        // Convert to string for logging
        struct in_addr addr;
        addr.s_addr = ip_net;
        printf("[BPF] Added exchange IP: %s\n", inet_ntoa(addr));
    }

    // Add exchange IP address (string)
    void add_exchange_ip(const char* ip_str) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) != 1) {
            throw std::runtime_error(
                std::string("BPFLoader: Invalid IP address: ") + ip_str);
        }

        add_exchange_ip(addr.s_addr);  // Already in network byte order
    }

    // Remove exchange IP address
    void remove_exchange_ip(uint32_t ip_net) {
        if (exchange_ips_fd_ < 0) {
            return;
        }

        bpf_map_delete_elem(exchange_ips_fd_, &ip_net);

        struct in_addr addr;
        addr.s_addr = ip_net;
        printf("[BPF] Removed exchange IP: %s\n", inet_ntoa(addr));
    }

    // Add exchange port (host byte order)
    void add_exchange_port(uint16_t port) {
        if (exchange_ports_fd_ < 0) {
            throw std::runtime_error("BPFLoader: Exchange ports map not available");
        }

        uint8_t val = 1;
        int ret = bpf_map_update_elem(exchange_ports_fd_, &port, &val, BPF_ANY);
        if (ret < 0) {
            throw std::runtime_error(
                std::string("BPFLoader: Failed to add exchange port: ") + strerror(errno));
        }

        printf("[BPF] Added exchange port: %u\n", port);
    }

    // Remove exchange port
    void remove_exchange_port(uint16_t port) {
        if (exchange_ports_fd_ < 0) {
            return;
        }

        bpf_map_delete_elem(exchange_ports_fd_, &port);
        printf("[BPF] Removed exchange port: %u\n", port);
    }

    // Set local IP address (Phase 1: destination-based filtering)
    void set_local_ip(uint32_t ip_net) {
        if (local_ip_fd_ < 0) {
            throw std::runtime_error("BPFLoader: Local IP map not available");
        }

        uint32_t key = 0;  // Array map with single entry
        int ret = bpf_map_update_elem(local_ip_fd_, &key, &ip_net, BPF_ANY);
        if (ret < 0) {
            throw std::runtime_error(
                std::string("BPFLoader: Failed to set local IP: ") + strerror(errno));
        }

        // Convert to string for logging
        struct in_addr addr;
        addr.s_addr = ip_net;
        printf("[BPF] Set local IP: %s (Phase 1 filtering)\n", inet_ntoa(addr));
    }

    // Set local IP address (string)
    void set_local_ip(const char* ip_str) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) != 1) {
            throw std::runtime_error(
                std::string("BPFLoader: Invalid IP address: ") + ip_str);
        }

        set_local_ip(addr.s_addr);  // Already in network byte order
    }

    // Get statistics
    BPFStats get_stats() const {
        BPFStats stats = {};

        if (stats_fd_ < 0) {
            return stats;
        }

        uint32_t key;
        uint64_t value;

        // Read each statistic
        key = STAT_TOTAL_PACKETS;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.total_packets = value;
        }

        key = STAT_EXCHANGE_PACKETS;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.exchange_packets = value;
        }

        key = STAT_KERNEL_PACKETS;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.kernel_packets = value;
        }

        key = STAT_DROPPED_PACKETS;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.dropped_packets = value;
        }

        key = STAT_PARSE_ERRORS;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.parse_errors = value;
        }

        key = STAT_IPV4_PACKETS;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.ipv4_packets = value;
        }

        key = STAT_TCP_PACKETS;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.tcp_packets = value;
        }

        key = STAT_NON_TCP_PACKETS;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.non_tcp_packets = value;
        }

        key = STAT_TIMESTAMP_OK;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.timestamp_ok = value;
        }

        key = STAT_TIMESTAMP_FAIL;
        if (bpf_map_lookup_elem(stats_fd_, &key, &value) == 0) {
            stats.timestamp_fail = value;
        }

        return stats;
    }

    // Print statistics
    void print_stats() const {
        BPFStats stats = get_stats();

        printf("\n[BPF] Statistics:\n");
        printf("  Total packets:     %lu\n", stats.total_packets);
        printf("  Exchange packets:  %lu (%.1f%%)\n",
               stats.exchange_packets,
               stats.total_packets > 0 ? (stats.exchange_packets * 100.0 / stats.total_packets) : 0.0);
        printf("  Kernel packets:    %lu (%.1f%%)\n",
               stats.kernel_packets,
               stats.total_packets > 0 ? (stats.kernel_packets * 100.0 / stats.total_packets) : 0.0);
        printf("  IPv4 packets:      %lu\n", stats.ipv4_packets);
        printf("  TCP packets:       %lu\n", stats.tcp_packets);
        printf("  Non-TCP packets:   %lu\n", stats.non_tcp_packets);
        printf("  Parse errors:      %lu\n", stats.parse_errors);
        printf("  Dropped packets:   %lu\n", stats.dropped_packets);
        printf("  HW timestamp OK:   %lu\n", stats.timestamp_ok);
        printf("  HW timestamp fail: %lu\n", stats.timestamp_fail);
    }

    // Get map FDs (for advanced usage)
    int get_xsks_map_fd() const { return xsks_map_fd_; }
    int get_exchange_ips_fd() const { return exchange_ips_fd_; }
    int get_exchange_ports_fd() const { return exchange_ports_fd_; }
    int get_stats_fd() const { return stats_fd_; }

private:
    void cleanup() {
        detach();

        if (bpf_obj_) {
            bpf_object__close(bpf_obj_);
            bpf_obj_ = nullptr;
        }

        prog_fd_ = -1;
        xsks_map_fd_ = -1;
        exchange_ips_fd_ = -1;
        exchange_ports_fd_ = -1;
        stats_fd_ = -1;
    }
};

} // namespace websocket::xdp
