// src/transport/bsd_socket.hpp
// BSD Socket - Socket interface for traditional kernel stack
//
// Policy-based design: No inheritance, no virtual functions, zero runtime overhead
// Implements the socket interface using standard BSD sockets

#pragma once

#include <cstddef>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <cstring>
#include <string>
#include <stdexcept>

#ifdef __linux__
#include <linux/sockios.h>
#include <linux/net_tstamp.h>
#endif

namespace websocket {
namespace transport {

/**
 * BSD Socket Configuration (optional)
 */
struct BSDSocketConfig {
    bool tcp_nodelay;      // Disable Nagle's algorithm (default: true)
    bool hw_timestamping;  // Enable hardware timestamping (default: false)

    BSDSocketConfig()
        : tcp_nodelay(true)
        , hw_timestamping(false)
    {}
};

/**
 * BSDSocket - Socket interface using standard BSD sockets
 *
 * Zero-cost abstraction for BSD sockets. No virtual functions,
 * all methods inlined for maximum performance.
 *
 * Socket Interface (duck typing):
 *   void init(const BSDSocketConfig& config)
 *   void connect(const char* host, uint16_t port)
 *   void close()
 *   bool is_connected() const
 *   ssize_t send(const void* data, size_t len)
 *   ssize_t recv(void* buffer, size_t len)
 *   void poll()
 *   int get_fd() const
 */
struct BSDSocket {
    int fd_;
    bool connected_;
    BSDSocketConfig config_;

    BSDSocket()
        : fd_(-1)
        , connected_(false)
    {}

    ~BSDSocket() {
        close();
    }

    // =====================
    // Socket Interface
    // =====================

    void init(const BSDSocketConfig& config = BSDSocketConfig()) {
        config_ = config;
        // BSD sockets don't need explicit initialization
    }

    void connect(const char* host, uint16_t port) {
        // Create socket
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Set TCP_NODELAY (disable Nagle's algorithm)
        if (config_.tcp_nodelay) {
            int flag = 1;
            if (::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
                printf("[WARN] Failed to set TCP_NODELAY: %s\n", strerror(errno));
            }
        }

        // Enable hardware timestamping (if requested)
        if (config_.hw_timestamping) {
            enable_hw_timestamping();
        }

        // Resolve hostname
        struct addrinfo hints = {};
        struct addrinfo* result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(host, nullptr, &hints, &result);
        if (ret != 0) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error(std::string("getaddrinfo() failed: ") + gai_strerror(ret));
        }

        if (!result || !result->ai_addr) {
            if (result) freeaddrinfo(result);
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error("getaddrinfo() returned invalid result");
        }

        auto* addr = (struct sockaddr_in*)result->ai_addr;
        addr->sin_port = htons(port);

        // Set non-blocking mode for timeout support
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            freeaddrinfo(result);
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error("Failed to set non-blocking mode");
        }

        // Attempt non-blocking connect
        ret = ::connect(fd_, (struct sockaddr*)addr, sizeof(*addr));
        freeaddrinfo(result);

        // Handle non-blocking connect
        if (ret < 0 && errno != EINPROGRESS) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error(std::string("connect() failed: ") + strerror(errno));
        }

        // Wait for connection with timeout
        if (ret < 0) {  // EINPROGRESS
            fd_set write_fds, error_fds;
            FD_ZERO(&write_fds);
            FD_ZERO(&error_fds);
            FD_SET(fd_, &write_fds);
            FD_SET(fd_, &error_fds);

            struct timeval tv;
            tv.tv_sec = 5;   // 5 second timeout
            tv.tv_usec = 0;

            ret = select(fd_ + 1, nullptr, &write_fds, &error_fds, &tv);

            if (ret <= 0) {
                ::close(fd_);
                fd_ = -1;
                if (ret == 0) {
                    throw std::runtime_error("connect() timeout after 5 seconds");
                } else {
                    throw std::runtime_error(std::string("select() failed: ") + strerror(errno));
                }
            }

            // Check connection status
            int sock_error = 0;
            socklen_t len = sizeof(sock_error);
            if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &sock_error, &len) < 0) {
                ::close(fd_);
                fd_ = -1;
                throw std::runtime_error("getsockopt() failed");
            }

            if (sock_error != 0) {
                ::close(fd_);
                fd_ = -1;
                throw std::runtime_error(std::string("connect() failed: ") + strerror(sock_error));
            }
        }

        // Restore blocking mode
        if (fcntl(fd_, F_SETFL, flags) < 0) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error("Failed to restore blocking mode");
        }

        connected_ = true;
        printf("[BSD Socket] Connected to %s:%u\n", host, port);
    }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
            connected_ = false;
        }
    }

    bool is_connected() const {
        return connected_ && fd_ >= 0;
    }

    ssize_t send(const void* data, size_t len) {
        if (fd_ < 0) {
            return -1;
        }
        return ::send(fd_, data, len, 0);
    }

    ssize_t recv(void* buffer, size_t len) {
        if (fd_ < 0) {
            return -1;
        }
        return ::recv(fd_, buffer, len, 0);
    }

    void poll() {
        // No-op for BSD sockets (kernel handles everything)
    }

    int get_fd() const {
        return fd_;
    }

private:
    void enable_hw_timestamping() {
#ifdef __linux__
        // Enable RX timestamping
        int flags = SOF_TIMESTAMPING_RX_HARDWARE |
                   SOF_TIMESTAMPING_RAW_HARDWARE |
                   SOF_TIMESTAMPING_RX_SOFTWARE;

        if (::setsockopt(fd_, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
            printf("[WARN] Failed to enable hardware timestamping: %s\n", strerror(errno));
        } else {
            printf("[BSD Socket] Hardware timestamping enabled\n");
        }
#endif
    }
};

} // namespace transport
} // namespace websocket
