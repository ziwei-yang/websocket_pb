// websocket.hpp
// High-performance WebSocket client using policy-based design
#pragma once

#include "ws_policies.hpp"
#include "core/timing.hpp"
#include <functional>
#include <string>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#ifdef __linux__
#include <linux/sockios.h>
#endif

template<
    typename SSLPolicy_,
    typename EventPolicy_,
    typename RxBufferPolicy_,      // Separate RX buffer (can have different size)
    typename TxBufferPolicy_       // Separate TX buffer (can have different size)
>
class WebSocketClient {
public:
    // Type aliases for policy introspection
    using SSLPolicy = SSLPolicy_;
    using EventPolicy = EventPolicy_;
    using RxBufferPolicy = RxBufferPolicy_;
    using TxBufferPolicy = TxBufferPolicy_;

    // Message callback now includes timing information
    using MessageCallback = std::function<void(const uint8_t*, size_t, const timing_record_t&)>;

    WebSocketClient()
        : fd_(-1)
        , connected_(false)
        , msg_count_(0)
    {
        rx_buffer_.init();  // Buffer initializes with its template parameter size
        tx_buffer_.init();
        event_loop_.init();
        event_loop_.set_wait_timeout(1000);  // Set default 1 second timeout
        ssl_.init();

        // Initialize timing record
        memset(&timing_, 0, sizeof(timing_));
    }

    ~WebSocketClient() {
        disconnect();
    }

    // Connect to WebSocket server
    void connect(const char* host, uint16_t port, const char* path) {
        // 1. Create socket
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Enable TCP_NODELAY for low-latency (disable Nagle's algorithm)
        int flag = 1;
        if (::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
            printf("[WARN] Failed to set TCP_NODELAY: %s\n", strerror(errno));
            // Continue anyway - not critical
        }

        // Enable RX timestamping (must be done before data arrives)
        enable_hw_timestamping(fd_);

        // 2. TCP connect
        struct addrinfo hints = {};
        struct addrinfo* result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(host, nullptr, &hints, &result);
        if (ret != 0) {
            ::close(fd_);
            throw std::runtime_error(std::string("getaddrinfo() failed: ") + gai_strerror(ret));
        }

        // Validate getaddrinfo result
        if (!result || !result->ai_addr) {
            if (result) freeaddrinfo(result);
            ::close(fd_);
            throw std::runtime_error("getaddrinfo() returned invalid result");
        }

        auto* addr = (struct sockaddr_in*)result->ai_addr;
        addr->sin_port = htons(port);

        // Set socket to non-blocking mode before connect (for timeout support)
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            freeaddrinfo(result);
            ::close(fd_);
            throw std::runtime_error("Failed to set non-blocking mode");
        }

        // Attempt non-blocking connect
        ret = ::connect(fd_, (struct sockaddr*)addr, sizeof(*addr));
        freeaddrinfo(result);

        // Handle non-blocking connect
        if (ret < 0 && errno != EINPROGRESS) {
            ::close(fd_);
            throw std::runtime_error(std::string("connect() failed: ") + strerror(errno));
        }

        // Wait for connection with 5-second timeout
        if (ret < 0) {  // EINPROGRESS - connection in progress
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
                if (ret == 0) {
                    throw std::runtime_error("connect() timeout after 5 seconds");
                } else {
                    throw std::runtime_error(std::string("select() failed: ") + strerror(errno));
                }
            }

            // Check if connection succeeded or failed
            int sock_error = 0;
            socklen_t len = sizeof(sock_error);
            if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &sock_error, &len) < 0) {
                ::close(fd_);
                throw std::runtime_error("getsockopt() failed");
            }

            if (sock_error != 0) {
                ::close(fd_);
                throw std::runtime_error(std::string("connect() failed: ") + strerror(sock_error));
            }
        }

        // Restore blocking mode for SSL handshake
        if (fcntl(fd_, F_SETFL, flags) < 0) {
            ::close(fd_);
            throw std::runtime_error("Failed to restore blocking mode");
        }

        // 3. SSL/TLS handshake
        ssl_.handshake(fd_);

        // 4. Report TLS mode (kTLS auto-enabled by OpenSSL if available)
        if (ssl_.ktls_enabled()) {
            printf("[KTLS] Kernel TLS offload active\n");
        } else {
            printf("[TLS] Standard user-space TLS mode\n");
        }

        // 5. HTTP upgrade to WebSocket
        send_http_upgrade(host, path);
        recv_http_response();

        // 6. Set non-blocking mode
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            ::close(fd_);
            throw std::runtime_error("Failed to set non-blocking mode");
        }

        // 7. Register with event loop
        event_loop_.add_read(fd_);

        connected_ = true;
        printf("[WS] Connected to %s:%d%s\n", host, port, path);
    }

    // Main event loop - runs until disconnected
    void run(MessageCallback on_message) {
        on_message_ = on_message;

        while (connected_) {
            // Wait for events (uses pre-configured timeout)
            int ready = event_loop_.wait_with_timeout();
            if (ready <= 0) continue;

            int ready_fd = event_loop_.get_ready_fd();
            if (ready_fd != fd_) continue;

            // Stage 1: Extract hardware RX timestamp from NIC
            // Returns 0 if hardware timestamps not supported (e.g., consumed by SSL layer)
            timing_.hw_timestamp_ns = extract_hw_timestamp(fd_);

            // Stage 2: Record CPU cycle when event loop processing starts
            timing_.event_cycle = rdtsc();

            // Read data into ring buffer
            if (!recv_into_buffer()) {
                break;  // Connection closed or error
            }

            // Process WebSocket frames
            process_frames();
        }

        printf("[WS] Event loop terminated\n");
    }

    // Graceful disconnect
    void disconnect() {
        if (fd_ >= 0) {
            ssl_.shutdown();
            ::close(fd_);
            fd_ = -1;
            connected_ = false;
            printf("[WS] Disconnected\n");
        }
    }

    // Get message count for statistics
    uint64_t get_message_count() const { return msg_count_; }

    // Get RX buffer reference (for diagnostic/stats)
    const RxBufferPolicy& get_rx_buffer() const {
        return rx_buffer_;
    }

    // Get TX buffer reference (for diagnostic/stats)
    const TxBufferPolicy& get_tx_buffer() const {
        return tx_buffer_;
    }

    // Check if kTLS is enabled
    bool ktls_enabled() const {
        return ssl_.ktls_enabled();
    }

private:
    // Read from SSL into ring buffer (zero-copy)
    bool recv_into_buffer() {
        // Get writable region from ring buffer
        size_t available = 0;
        uint8_t* write_ptr = rx_buffer_.next_write_region(&available);

        if (available == 0) {
            printf("[WARN] Ring buffer full!\n");
            return true;  // Not an error, just buffer full
        }

        // Stage 3: Record timestamp before SSL_read/recv
        timing_.recv_start_cycle = rdtsc();

        // Read directly into ring buffer (zero-copy)
        ssize_t n = ssl_.read(write_ptr, available);

        // Stage 4: Record timestamp after SSL_read/recv completed
        timing_.recv_end_cycle = rdtscp();

        if (n > 0) {
            rx_buffer_.commit_write(n);
            return true;
        } else if (n == 0) {
            // Connection closed gracefully
            connected_ = false;
            return false;
        } else {
            // Would block or error (SSL returns -1 for both SSL_ERROR_WANT_READ and errors)
            // For non-blocking sockets, -1 with EAGAIN is normal - just continue
            return true;  // Continue event loop, not an error
        }
    }

    // Process WebSocket frames from ring buffer
    void process_frames() {
        while (rx_buffer_.readable() >= 2) {  // Minimum frame header size
            size_t available_len = 0;
            const uint8_t* read_ptr = rx_buffer_.next_read_region(&available_len);

            if (available_len < 2) break;

            // Parse WebSocket frame header
            uint8_t byte0 = read_ptr[0];
            uint8_t byte1 = read_ptr[1];

            bool fin = (byte0 & 0x80) != 0;
            uint8_t opcode = byte0 & 0x0F;
            bool masked = (byte1 & 0x80) != 0;
            uint64_t payload_len = byte1 & 0x7F;

            // Reject fragmented messages (not supported)
            if (!fin) {
                printf("[ERROR] Fragmented WebSocket messages not supported (FIN=0)\n");
                printf("[ERROR] This library is designed for single-frame messages only\n");
                connected_ = false;
                break;
            }

            size_t header_len = 2;

            // Extended payload length
            if (payload_len == 126) {
                if (available_len < 4) break;  // Need more data
                payload_len = (read_ptr[2] << 8) | read_ptr[3];
                header_len = 4;
            } else if (payload_len == 127) {
                if (available_len < 10) break;  // Need more data
                payload_len = 0;
                for (int i = 0; i < 8; i++) {
                    payload_len = (payload_len << 8) | read_ptr[2 + i];
                }
                header_len = 10;
            }

            // Masking key (if present)
            if (masked) {
                header_len += 4;
                // Check bounds after adding masking key length
                if (available_len < header_len) {
                    break;  // Need more data for masking key
                }
            }

            // Check for integer overflow before calculating frame_len
            if (payload_len > SIZE_MAX - header_len) {
                printf("[ERROR] Frame too large: payload_len=%lu exceeds SIZE_MAX\n",
                       (unsigned long)payload_len);
                connected_ = false;
                break;
            }

            // Check if full frame is available
            size_t frame_len = header_len + payload_len;
            if (available_len < frame_len) {
                break;  // Need more data
            }

            // Stage 5: Frame parsing completed
            timing_.frame_parsed_cycle = rdtscp();
            timing_.payload_len = payload_len;
            timing_.opcode = opcode;

            // Handle different frame types
            if (opcode == 0x09) {  // PING frame
                static int ping_count = 0;
                ping_count++;
                if (ping_count <= 3) {  // Only log first 3 pings
                    printf("[WS] Received PING #%d, sending PONG (%zu bytes payload)\n",
                           ping_count, (size_t)payload_len);
                }
                send_pong(read_ptr + header_len, payload_len);
                rx_buffer_.commit_read(frame_len);
            }
            else if (opcode == 0x01 || opcode == 0x02) {  // Text or Binary frame
                // Invoke user callback with zero-copy pointer and timing data
                // Stage 6 is implemented inside the callback by user code
                if (on_message_) {
                    on_message_(read_ptr + header_len, payload_len, timing_);
                }
                msg_count_++;
                rx_buffer_.commit_read(frame_len);
            }
            else if (opcode == 0x0A) {  // PONG frame (response to our ping)
                // Server sent a pong, just ignore it
                rx_buffer_.commit_read(frame_len);
            }
            else if (opcode == 0x08) {  // Close frame
                printf("[WS] Received close frame from server\n");
                if (payload_len > 0 && payload_len < 126) {
                    // Close frame can have status code and reason
                    uint16_t status_code = (read_ptr[header_len] << 8) | read_ptr[header_len + 1];
                    printf("[WS] Close status code: %u\n", status_code);
                    if (payload_len > 2) {
                        printf("[WS] Close reason: %.*s\n", (int)(payload_len - 2),
                               read_ptr + header_len + 2);
                    }
                }
                connected_ = false;
                rx_buffer_.commit_read(frame_len);
                break;
            }
            else {
                // Unknown opcode, skip frame
                printf("[WARN] Unknown opcode: 0x%02X, payload_len: %zu\n", opcode, (size_t)payload_len);
                rx_buffer_.commit_read(frame_len);
            }
        }
    }

    // Send HTTP upgrade request
    void send_http_upgrade(const char* host, const char* path) {
        char request[2048];
        int len = snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n",
            path, host);

        ssize_t n = ssl_.write(request, len);
        if (n <= 0) {
            throw std::runtime_error("Failed to send HTTP upgrade");
        }
    }

    // Receive HTTP 101 Switching Protocols response
    void recv_http_response() {
        uint8_t buf[4097];  // +1 for null terminator
        ssize_t n = ssl_.read(buf, sizeof(buf) - 1);  // Reserve space for '\0'

        if (n <= 0) {
            throw std::runtime_error("Failed to receive HTTP response");
        }

        // Simple validation: check for "101 Switching Protocols"
        buf[n] = '\0';  // Safe: n <= 4096
        if (strstr((char*)buf, "101") == nullptr) {
            throw std::runtime_error("HTTP upgrade failed");
        }
    }

    // Send PONG frame in response to PING
    void send_pong(const uint8_t* payload, size_t len) {
        // Validate payload length (RFC 6455: control frames <= 125 bytes)
        if (len > 125) {
            printf("[WARN] PING payload too large (%zu bytes), truncating to 125\n", len);
            len = 125;
        }

        uint8_t pong[256];

        // PONG frame: FIN + opcode 0x0A
        pong[0] = 0x8A;

        // Payload length (now guaranteed < 126)
        pong[1] = 0x80 | (uint8_t)len;  // Masked

        // Masking key (client must mask)
        // Note: Static key is intentional for performance (single-threaded HFT env)
        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
        memcpy(pong + 2, mask, 4);

        // Masked payload
        for (size_t i = 0; i < len; i++) {
            pong[6 + i] = payload[i] ^ mask[i % 4];
        }

        // Check write return value
        ssize_t ret = ssl_.write(pong, 6 + len);
        if (ret <= 0) {
            printf("[WARN] Failed to send PONG response\n");
        }
    }

private:
    SSLPolicy_ ssl_;
    EventPolicy_ event_loop_;
    RxBufferPolicy_ rx_buffer_;  // Separate RX buffer type/size
    TxBufferPolicy_ tx_buffer_;  // Separate TX buffer type/size

    int fd_;
    bool connected_;
    uint64_t msg_count_;
    MessageCallback on_message_;
    timing_record_t timing_;  // Timing information for current message
};
