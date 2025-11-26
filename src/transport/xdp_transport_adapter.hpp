// src/transport/xdp_transport_adapter.hpp
// XDP Transport Adapter - Bridges XDP with WebSocketClient
//
// This adapter integrates:
// - XDPTransport (AF_XDP zero-copy I/O)
// - UserspaceStack (TCP/IP in userspace)
// - XDP_BIO (Zero-copy SSL via OpenSSL BIO)
// - eBPF packet filtering (IP + PORT)
//
// Architecture:
//   WebSocketClient → XDPTransportAdapter → UserspaceStack → XDPTransport → NIC
//                                        └→ OpenSSLPolicy (XDP_BIO)

#pragma once

#include "transport_policy.hpp"
#include "../policy/ssl.hpp"

#ifdef USE_XDP
#include "../xdp/xdp_transport.hpp"
#include "../xdp/xdp_bio.hpp"
#include "../stack/userspace_stack.hpp"
#include <cstring>
#include <vector>
#include <netdb.h>
#include <arpa/inet.h>
#endif

namespace websocket {
namespace transport {

#ifdef USE_XDP

/**
 * XDP Transport Adapter
 *
 * Provides a TransportPolicy implementation that uses XDP + UserspaceStack
 * for ultra-low-latency WebSocket connections.
 *
 * Performance:
 * - End-to-end latency: <5μs (vs ~20-50μs kernel stack)
 * - Zero-copy SSL via XDP_BIO
 * - eBPF packet filtering (reduces CPU load)
 * - Native driver mode (5-10x faster than SKB mode)
 *
 * Usage:
 *   XDPTransportAdapter transport;
 *   transport.init(config);
 *   transport.connect("stream.binance.com", 443);
 *   transport.ssl_handshake(ssl_policy);
 *   transport.send_http_upgrade("stream.binance.com", "/ws/btcusdt@trade", {});
 *   transport.recv_http_response();
 *   // Now ready for WebSocket frames
 */
class XDPTransportAdapter : public ITransportPolicy<websocket::ssl::OpenSSLPolicy> {
public:
    /**
     * Configuration for XDP transport
     */
    struct Config {
        // Network interface
        const char* interface;         // e.g., "enp108s0"
        uint32_t queue_id;             // XDP queue (usually 0)

        // Local network configuration
        const char* local_ip;          // e.g., "192.168.0.122"
        const char* gateway_ip;        // e.g., "192.168.0.1"
        const char* netmask;           // e.g., "255.255.255.0"
        uint8_t local_mac[6];          // Host MAC address

        // XDP configuration
        const char* bpf_program;       // BPF filter path (e.g., "src/xdp/bpf/exchange_filter.bpf.o")
        bool enable_bpf_filter;        // Enable eBPF packet filtering

        // Performance tuning
        uint32_t num_frames;           // UMEM frames (default: 4096)
        uint32_t frame_size;           // Frame size (default: 2048)

        Config()
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

private:
    websocket::xdp::XDPTransport xdp_;
    userspace_stack::UserspaceStack stack_;
    websocket::ssl::OpenSSLPolicy* ssl_;  // Non-owning pointer (set during ssl_handshake)

    Config config_;
    bool initialized_;
    bool connected_;

    // Current connection
    std::string remote_host_;
    uint32_t remote_ip_;     // Host byte order
    uint16_t remote_port_;

public:
    XDPTransportAdapter()
        : ssl_(nullptr)
        , initialized_(false)
        , connected_(false)
        , remote_ip_(0)
        , remote_port_(0)
    {}

    ~XDPTransportAdapter() {
        close();
    }

    /**
     * Initialize XDP transport with configuration
     * Must be called before connect()
     */
    void init(const Config& config) {
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

        printf("[XDP Transport] Initialized on %s\n", config_.interface);
        printf("                Local IP: %s, Gateway: %s\n",
               config_.local_ip, config_.gateway_ip);
    }

    // =====================
    // ITransportPolicy Implementation
    // =====================

    void connect(const char* host, uint16_t port) override {
        if (!initialized_) {
            throw std::runtime_error("XDPTransportAdapter: Not initialized (call init() first)");
        }

        remote_host_ = host;
        remote_port_ = port;

        printf("[XDP Transport] Resolving %s...\n", host);

        // Resolve hostname to IP addresses
        auto ips = resolve_hostname(host);
        if (ips.empty()) {
            throw std::runtime_error(std::string("Failed to resolve hostname: ") + host);
        }

        printf("[XDP Transport] Found %zu IP(s)\n", ips.size());

        // Try each IP until one succeeds
        bool connect_succeeded = false;
        for (const auto& ip_str : ips) {
            printf("[XDP Transport] Trying %s:%u...\n", ip_str.c_str(), port);

            // Add IP to BPF filter (if enabled)
            if (config_.enable_bpf_filter) {
                xdp_.add_exchange_ip(ip_str.c_str());
            }

            try {
                // Convert IP string to uint32_t (host byte order)
                struct in_addr addr;
                if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
                    printf("[XDP Transport] Invalid IP: %s\n", ip_str.c_str());
                    continue;
                }
                remote_ip_ = ntohl(addr.s_addr);  // Network to host byte order

                // Attempt TCP connection via userspace stack
                stack_.connect(remote_ip_, port, 5000);  // 5 second timeout

                connect_succeeded = true;
                printf("[XDP Transport] ✅ Connected to %s:%u\n", ip_str.c_str(), port);
                break;

            } catch (const std::exception& e) {
                printf("[XDP Transport] Connection failed: %s\n", e.what());
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

    void close() override {
        if (connected_) {
            stack_.close();
            connected_ = false;
            printf("[XDP Transport] Connection closed\n");
        }
    }

    bool is_connected() const override {
        return connected_ && stack_.is_connected();
    }

    void ssl_handshake(websocket::ssl::OpenSSLPolicy& ssl) override {
        if (!connected_) {
            throw std::runtime_error("XDPTransportAdapter: Not connected");
        }

        ssl_ = &ssl;

        printf("[XDP Transport] Starting SSL handshake...\n");

        // Use OpenSSLPolicy's XDP-specific handshake method
        // This creates XDP_BIO and performs handshake via userspace stack
        ssl_->handshake_xdp_transport(&xdp_);

        printf("[XDP Transport] ✅ SSL handshake complete\n");
    }

    ssize_t ssl_send(const void* data, size_t len) override {
        if (!ssl_) {
            return -1;
        }

        // Send via OpenSSL (which uses XDP_BIO → UserspaceStack)
        return ssl_->write(static_cast<const uint8_t*>(data), len);
    }

    ssize_t ssl_recv(void* buffer, size_t len) override {
        if (!ssl_) {
            return -1;
        }

        // Before reading, process any pending packets
        stack_.poll();

        // Receive via OpenSSL (which uses XDP_BIO → UserspaceStack)
        return ssl_->read(static_cast<uint8_t*>(buffer), len);
    }

    int get_fd() const override {
        return -1;  // No file descriptor for XDP
    }

    void poll() override {
        // Process pending packets (ARP, ICMP, TCP)
        stack_.poll();
    }

    void send_http_upgrade(const char* host, const char* path,
                          const std::vector<std::pair<std::string, std::string>>& custom_headers) override {
        if (!connected_ || !ssl_) {
            throw std::runtime_error("XDPTransportAdapter: Not connected or SSL not initialized");
        }

        // Build HTTP upgrade request
        std::string request = build_http_upgrade_request(host, path, custom_headers);

        printf("[XDP Transport] Sending HTTP upgrade request (%zu bytes)...\n", request.size());

        // Send request via SSL
        size_t total_sent = 0;
        while (total_sent < request.size()) {
            ssize_t sent = ssl_send(request.data() + total_sent, request.size() - total_sent);
            if (sent < 0) {
                throw std::runtime_error("Failed to send HTTP upgrade request");
            }
            total_sent += sent;

            // Process ACKs
            stack_.poll();
        }

        printf("[XDP Transport] ✅ HTTP upgrade request sent\n");
    }

    void recv_http_response() override {
        if (!connected_ || !ssl_) {
            throw std::runtime_error("XDPTransportAdapter: Not connected or SSL not initialized");
        }

        printf("[XDP Transport] Receiving HTTP upgrade response...\n");

        // Read HTTP response (up to 4KB)
        char buffer[4096];
        size_t total = 0;

        // Read with timeout (5 seconds)
        for (int i = 0; i < 5000 && total < sizeof(buffer); i++) {
            stack_.poll();  // Process incoming packets

            ssize_t n = ssl_recv(buffer + total, sizeof(buffer) - total);
            if (n > 0) {
                total += n;

                // Check if we have complete HTTP response
                if (total >= 4 && std::strstr(buffer, "\r\n\r\n")) {
                    break;  // Complete response received
                }
            } else if (n == 0) {
                throw std::runtime_error("Connection closed during HTTP upgrade");
            }

            // Sleep 1ms between polls
            usleep(1000);
        }

        if (total == 0) {
            throw std::runtime_error("No HTTP response received (timeout)");
        }

        buffer[total] = '\0';

        // Validate response (must be "101 Switching Protocols")
        if (std::strstr(buffer, "HTTP/1.1 101") == nullptr &&
            std::strstr(buffer, "HTTP/1.0 101") == nullptr) {
            printf("[XDP Transport] Invalid HTTP response:\n%s\n", buffer);
            throw std::runtime_error("HTTP upgrade failed (expected 101 Switching Protocols)");
        }

        printf("[XDP Transport] ✅ HTTP upgrade successful\n");
    }

    void print_stats() const override {
        if (xdp_.is_bpf_enabled()) {
            xdp_.print_bpf_stats();
        }
    }

private:
    /**
     * Resolve hostname to IP addresses
     */
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

    /**
     * Build HTTP WebSocket upgrade request
     */
    std::string build_http_upgrade_request(const char* host, const char* path,
                                          const std::vector<std::pair<std::string, std::string>>& custom_headers) {
        // Generate WebSocket key
        char ws_key[25];
        generate_websocket_key(ws_key);

        // Build request
        std::string request;
        request.reserve(512);

        request += "GET ";
        request += path;
        request += " HTTP/1.1\r\n";
        request += "Host: ";
        request += host;
        request += "\r\n";
        request += "Upgrade: websocket\r\n";
        request += "Connection: Upgrade\r\n";
        request += "Sec-WebSocket-Key: ";
        request += ws_key;
        request += "\r\n";
        request += "Sec-WebSocket-Version: 13\r\n";

        // Add custom headers
        for (const auto& header : custom_headers) {
            request += header.first;
            request += ": ";
            request += header.second;
            request += "\r\n";
        }

        request += "\r\n";

        return request;
    }

    /**
     * Generate random WebSocket key (Base64 encoded)
     */
    void generate_websocket_key(char* key) {
        static const char base64_chars[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        // Generate 16 random bytes
        uint8_t random_bytes[16];
        for (int i = 0; i < 16; i++) {
            random_bytes[i] = rand() % 256;
        }

        // Base64 encode (simplified - just for WebSocket key)
        for (int i = 0; i < 22; i++) {
            key[i] = base64_chars[random_bytes[i % 16] % 64];
        }
        key[22] = '=';
        key[23] = '=';
        key[24] = '\0';
    }
};

#else

// Stub implementation when XDP not available
class XDPTransportAdapter {
public:
    struct Config {};
    void init(const Config&) {
        throw std::runtime_error("XDP not available (build with USE_XDP=1)");
    }
};

#endif // USE_XDP

} // namespace transport
} // namespace websocket
