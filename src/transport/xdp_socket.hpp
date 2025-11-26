// src/transport/xdp_socket.hpp
// XDP Socket - Socket interface for XDP transport
//
// Policy-based design: No inheritance, no virtual functions, zero runtime overhead
// Implements the socket interface using XDP + UserspaceStack

#pragma once

#include <cstddef>
#include <sys/types.h>
#include <string>
#include <vector>
#include <cstring>

#ifdef USE_XDP
#include "../xdp/xdp_transport.hpp"
#include "../stack/userspace_stack.hpp"
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace websocket {
namespace transport {

#ifdef USE_XDP

/**
 * XDP Socket Configuration
 */
struct XDPSocketConfig {
    // Network interface
    const char* interface;         // e.g., "enp108s0"
    uint32_t queue_id;             // XDP queue (usually 0)

    // Local network configuration
    const char* local_ip;          // e.g., "192.168.0.122"
    const char* gateway_ip;        // e.g., "192.168.0.1"
    const char* netmask;           // e.g., "255.255.255.0"
    uint8_t local_mac[6];          // Host MAC address

    // XDP configuration
    const char* bpf_program;       // BPF filter path
    bool enable_bpf_filter;        // Enable eBPF packet filtering

    // Performance tuning
    uint32_t num_frames;           // UMEM frames (default: 4096)
    uint32_t frame_size;           // Frame size (default: 2048)

    XDPSocketConfig()
        : interface("eth0")
        , queue_id(0)
        , local_ip("192.168.1.100")
        , gateway_ip("192.168.1.1")
        , netmask("255.255.255.0")
        , bpf_program("src/xdp/bpf/exchange_filter.bpf.o")
        , enable_bpf_filter(true)
        , num_frames(4096)
        , frame_size(2048)
    {
        std::memset(local_mac, 0, 6);
    }
};

/**
 * XDPSocket - Socket interface using XDP + UserspaceStack
 *
 * Zero-cost abstraction for XDP transport. No virtual functions,
 * all methods inlined for maximum performance.
 *
 * Socket Interface (duck typing):
 *   void init(const XDPSocketConfig& config)
 *   void connect(const char* host, uint16_t port)
 *   void close()
 *   bool is_connected() const
 *   ssize_t send(const void* data, size_t len)
 *   ssize_t recv(void* buffer, size_t len)
 *   void poll()
 *   int get_fd() const
 *   websocket::xdp::XDPTransport* get_xdp()  // For XDP_BIO
 */
struct XDPSocket {
    websocket::xdp::XDPTransport xdp_;
    userspace_stack::UserspaceStack stack_;

    XDPSocketConfig config_;
    bool initialized_;
    bool connected_;

    // Current connection
    std::string remote_host_;
    uint32_t remote_ip_;     // Host byte order
    uint16_t remote_port_;

    XDPSocket()
        : initialized_(false)
        , connected_(false)
        , remote_ip_(0)
        , remote_port_(0)
    {}

    ~XDPSocket() {
        close();
    }

    // =====================
    // Socket Interface
    // =====================

    void init(const XDPSocketConfig& config) {
        config_ = config;

        // Initialize XDP transport
        websocket::xdp::XDPConfig xdp_config;
        xdp_config.interface = config_.interface;
        xdp_config.queue_id = config_.queue_id;
        xdp_config.num_frames = config_.num_frames;
        xdp_config.frame_size = config_.frame_size;

        xdp_.init(xdp_config, config_.enable_bpf_filter, config_.bpf_program);

        // Initialize userspace TCP/IP stack
        stack_.init(&xdp_, config_.local_ip, config_.gateway_ip,
                   config_.netmask, config_.local_mac);

        initialized_ = true;

        printf("[XDP Socket] Initialized on %s\n", config_.interface);
        printf("             Local IP: %s, Gateway: %s\n",
               config_.local_ip, config_.gateway_ip);
    }

    void connect(const char* host, uint16_t port) {
        if (!initialized_) {
            throw std::runtime_error("XDPSocket: Not initialized (call init() first)");
        }

        remote_host_ = host;
        remote_port_ = port;

        printf("[XDP Socket] Resolving %s...\n", host);

        // Resolve hostname to IP addresses
        auto ips = resolve_hostname(host);
        if (ips.empty()) {
            throw std::runtime_error(std::string("Failed to resolve hostname: ") + host);
        }

        printf("[XDP Socket] Found %zu IP(s)\n", ips.size());

        // Try each IP until one succeeds
        bool connect_succeeded = false;
        for (const auto& ip_str : ips) {
            printf("[XDP Socket] Trying %s:%u...\n", ip_str.c_str(), port);

            // Add IP to BPF filter (if enabled)
            if (config_.enable_bpf_filter) {
                xdp_.add_exchange_ip(ip_str.c_str());
            }

            try {
                // Convert IP string to uint32_t (host byte order)
                struct in_addr addr;
                if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
                    printf("[XDP Socket] Invalid IP: %s\n", ip_str.c_str());
                    continue;
                }
                remote_ip_ = ntohl(addr.s_addr);  // Network to host byte order

                // Attempt TCP connection via userspace stack
                stack_.connect(remote_ip_, port, 5000);  // 5 second timeout

                connect_succeeded = true;
                printf("[XDP Socket] ✅ Connected to %s:%u\n", ip_str.c_str(), port);
                break;

            } catch (const std::exception& e) {
                printf("[XDP Socket] Connection failed: %s\n", e.what());
                // Try next IP
            }
        }

        if (!connect_succeeded) {
            throw std::runtime_error(std::string("Failed to connect to any IP for: ") + host);
        }

        // Add port to BPF filter (if enabled)
        if (config_.enable_bpf_filter) {
            xdp_.add_exchange_port(port);
        }

        connected_ = true;
    }

    void close() {
        if (connected_) {
            stack_.close();
            connected_ = false;
            printf("[XDP Socket] Connection closed\n");
        }
    }

    bool is_connected() const {
        return connected_ && stack_.is_connected();
    }

    ssize_t send(const void* data, size_t len) {
        if (!connected_) {
            return -1;
        }
        return stack_.send(data, len);
    }

    ssize_t recv(void* buffer, size_t len) {
        if (!connected_) {
            return -1;
        }
        return stack_.recv(buffer, len);
    }

    void poll() {
        if (initialized_) {
            stack_.poll();  // Process packets (ARP, ICMP, TCP)
        }
    }

    int get_fd() const {
        return -1;  // No file descriptor for XDP
    }

    // =====================
    // XDP-Specific Methods
    // =====================

    /**
     * Get XDP transport pointer (for XDP_BIO)
     * This allows SSL to use zero-copy BIO
     */
    websocket::xdp::XDPTransport* get_xdp() {
        return &xdp_;
    }

    /**
     * Get BPF statistics
     */
    void print_stats() const {
        if (xdp_.is_bpf_enabled()) {
            xdp_.print_bpf_stats();
        }
    }

private:
    std::vector<std::string> resolve_hostname(const char* hostname) {
        std::vector<std::string> ips;

        struct addrinfo hints = {}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, nullptr, &hints, &result) == 0) {
            for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET) {
                    auto* ipv4 = (struct sockaddr_in*)rp->ai_addr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
                    ips.push_back(ip_str);
                }
            }
            freeaddrinfo(result);
        }

        return ips;
    }
};

#else

// Stub when XDP not available
struct XDPSocketConfig {};
struct XDPSocket {
    void init(const XDPSocketConfig&) {
        throw std::runtime_error("XDP not available (build with USE_XDP=1)");
    }
    void connect(const char*, uint16_t) {}
    void close() {}
    bool is_connected() const { return false; }
    ssize_t send(const void*, size_t) { return -1; }
    ssize_t recv(void*, size_t) { return -1; }
    void poll() {}
    int get_fd() const { return -1; }
};

#endif // USE_XDP

} // namespace transport
} // namespace websocket
