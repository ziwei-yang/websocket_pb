// src/transport/transport_policy.hpp
// Transport Policy Requirements (Compile-time polymorphism)
//
// This file documents the interface that transport implementations must provide.
// No virtual functions - all resolved at compile time via templates.
//
// Design Philosophy:
// - Zero-cost abstraction (no vtable, no runtime overhead)
// - Policy-based design (compile-time polymorphism)
// - Works with both BSD sockets and XDP transport
//
// Required Interface:
//   struct SomeTransport {
//       void init(...);
//       void connect(const char* host, uint16_t port);
//       void close();
//       bool is_connected() const;
//       ssize_t send(const void* data, size_t len);
//       ssize_t recv(void* buffer, size_t len);
//       void poll();
//       int get_fd() const;  // -1 if no fd (XDP)
//   };

#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <type_traits>
#include <sys/types.h>

namespace websocket {
namespace transport {

/**
 * TransportPolicy - Wraps socket types and provides unified interface
 *
 * This is a compile-time wrapper that adds SSL capabilities on top of
 * any socket type (BSD or XDP). No virtual functions - all inlined.
 *
 * Template Parameters:
 *   SocketType - Must implement socket interface (BSDSocket, XDPSocket)
 *   SSLPolicy - SSL policy (OpenSSLPolicy, NoSSLPolicy, etc.)
 *
 * Usage:
 *   using BSDTransport = TransportPolicy<BSDSocket, OpenSSLPolicy>;
 *   using XDPTransport = TransportPolicy<XDPSocket, OpenSSLPolicy>;
 *
 *   BSDTransport transport;
 *   transport.init();
 *   transport.connect("example.com", 443);
 *   transport.ssl_handshake();
 *   transport.ssl_send(data, len);
 *   transport.ssl_recv(buffer, len);
 */
template<typename SocketType, typename SSLPolicy>
struct TransportPolicy {
    SocketType socket;
    SSLPolicy ssl;
    bool ssl_initialized;

    TransportPolicy() : ssl_initialized(false) {}

    // =====================
    // Initialization
    // =====================

    /**
     * Initialize transport
     * Forwards to socket.init() if it exists
     */
    template<typename... Args>
    void init(Args&&... args) {
        socket.init(std::forward<Args>(args)...);
        ssl.init();
    }

    // =====================
    // Connection Management
    // =====================

    void connect(const char* host, uint16_t port) {
        socket.connect(host, port);
    }

    void close() {
        if (ssl_initialized) {
            ssl.shutdown();
        }
        socket.close();
        ssl_initialized = false;
    }

    bool is_connected() const {
        return socket.is_connected();
    }

    // =====================
    // SSL/TLS Integration
    // =====================

    /**
     * Perform SSL handshake
     * Automatically calls the right SSL handshake method based on socket type
     */
    void ssl_handshake() {
        if constexpr (has_get_xdp<SocketType>::value) {
            // XDP socket - use zero-copy XDP_BIO
            ssl.handshake_xdp_transport(socket.get_xdp());
        } else {
            // BSD socket - use file descriptor
            ssl.handshake(socket.get_fd());
        }
        ssl_initialized = true;
    }

    /**
     * Send data over SSL
     * Zero-copy for XDP (SSL writes directly to UMEM)
     */
    ssize_t ssl_send(const void* data, size_t len) {
        if (!ssl_initialized) {
            return -1;
        }
        return ssl.write(static_cast<const uint8_t*>(data), len);
    }

    /**
     * Receive data from SSL
     * Zero-copy for XDP (SSL reads directly from UMEM)
     */
    ssize_t ssl_recv(void* buffer, size_t len) {
        if (!ssl_initialized) {
            return -1;
        }

        // Poll socket before receiving (for XDP packet processing)
        socket.poll();

        return ssl.read(static_cast<uint8_t*>(buffer), len);
    }

    // =====================
    // Raw I/O (non-SSL)
    // =====================

    ssize_t send(const void* data, size_t len) {
        return socket.send(data, len);
    }

    ssize_t recv(void* buffer, size_t len) {
        socket.poll();
        return socket.recv(buffer, len);
    }

    // =====================
    // Event Loop Integration
    // =====================

    int get_fd() const {
        return socket.get_fd();
    }

    void poll() {
        socket.poll();
    }

private:
    // SFINAE helper to detect if socket has get_xdp() method
    template<typename T>
    struct has_get_xdp {
        template<typename U>
        static auto test(int) -> decltype(std::declval<U>().get_xdp(), std::true_type{});

        template<typename U>
        static std::false_type test(...);

        static constexpr bool value = decltype(test<T>(0))::value;
    };
};

} // namespace transport
} // namespace websocket
