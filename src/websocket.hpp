// websocket.hpp
// High-performance WebSocket client using policy-based design
//
// TransportPolicy Design:
//   WebSocketClient now uses TransportPolicy instead of separate EventPolicy.
//   TransportPolicy encapsulates both transport mechanism (BSD socket or XDP)
//   and event waiting strategy (epoll/select/io_uring or busy-polling).
//
// Supported Transports:
//   - BSDSocketTransport<EventPolicy>: BSD sockets + event loop (kernel TCP/IP)
//   - XDPUserspaceTransport: XDP + userspace TCP/IP stack (kernel bypass)
//
// SSL Integration (compile-time dispatch):
//   - BSD sockets: Uses fd-based SSL handshake (supports kTLS)
//   - XDP: Uses UserspaceTransportBIO for SSL over userspace transport
//   - Dispatch is done at compile-time using is_fd_based_transport<T> trait
//
#pragma once

#include "ws_policies.hpp"
#include "core/timing.hpp"
#include "core/http.hpp"
#include <functional>
#include <string>
#include <vector>
#include <random>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <type_traits>
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

// ============================================================================
// Transport Type Traits (Compile-Time Dispatch)
// ============================================================================

namespace websocket {
namespace traits {

/**
 * Primary template: Default to userspace transport (XDP, DPDK, etc.)
 * Userspace transports don't have a kernel file descriptor.
 */
template<typename T, typename = void>
struct is_fd_based_transport : std::false_type {};

/**
 * Specialization: BSD socket transports have get_fd() returning >= 0
 * Detected by checking if T has get_fd() method returning int.
 */
template<typename T>
struct is_fd_based_transport<T,
    std::enable_if_t<std::is_same_v<decltype(std::declval<T>().get_fd()), int>>>
    : std::true_type {};

/**
 * Helper variable template for cleaner syntax
 */
template<typename T>
inline constexpr bool is_fd_based_transport_v = is_fd_based_transport<T>::value;

} // namespace traits
} // namespace websocket

template<
    typename SSLPolicy_,
    typename TransportPolicy_,     // Unified transport (BSD+event or XDP)
    typename RxBufferPolicy_,      // Separate RX buffer (can have different size)
    typename TxBufferPolicy_       // Separate TX buffer (can have different size)
>
class WebSocketClient {
public:
    // Type aliases for policy introspection
    using SSLPolicy = SSLPolicy_;
    using TransportPolicy = TransportPolicy_;
    using RxBufferPolicy = RxBufferPolicy_;
    using TxBufferPolicy = TxBufferPolicy_;

    // HTTP header customization support
    using HeaderMap = std::vector<std::pair<std::string, std::string>>;

    // Message callback now includes timing information
    using MessageCallback = std::function<void(const uint8_t*, size_t, const timing_record_t&)>;

    WebSocketClient()
        : connected_(false)
        , msg_count_(0)
    {
        rx_buffer_.init();  // Buffer initializes with its template parameter size
        tx_buffer_.init();
        ssl_.init();

        // Initialize timing record
        memset(&timing_, 0, sizeof(timing_));
    }

    ~WebSocketClient() {
        disconnect();
    }

    // Connect to WebSocket server with optional custom HTTP headers
    void connect(const char* host, uint16_t port, const char* path,
                 const HeaderMap& custom_headers = {}) {
        // Compile-time constant for transport type dispatch
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        // 1. Initialize transport (event loop for BSD, XDP resources for XDP)
        transport_.init();

        // 2. TCP connect (kernel TCP for BSD, userspace TCP for XDP)
        transport_.connect(host, port);

        // 3. Enable HW timestamping for BSD sockets (compile-time dispatch)
        if constexpr (is_fd_based) {
            int fd = transport_.get_fd();
            if (fd >= 0) {
                enable_hw_timestamping(fd);
            }
        }

        // 4. SSL/TLS handshake - compile-time dispatch based on transport type
        ssl_handshake_dispatch();

        // 5. Report TLS mode (compile-time optimized)
        if constexpr (is_fd_based) {
            if (transport_.supports_ktls() && ssl_.ktls_enabled()) {
                printf("[KTLS] Kernel TLS offload active\n");
            } else {
                printf("[TLS] Standard user-space TLS mode\n");
            }
        } else {
            // Userspace transports never support kTLS
            printf("[TLS] Standard user-space TLS mode (userspace transport)\n");
        }

        // 6. HTTP upgrade to WebSocket
        send_http_upgrade(host, path, custom_headers);
        recv_http_response();

        // 7. Start event loop monitoring for BSD sockets (compile-time dispatch)
        if constexpr (is_fd_based) {
            transport_.start_event_loop();
        }

        // 8. Configure wait timeout (1 second default)
        transport_.set_wait_timeout(1000);

        connected_ = true;
        printf("[WS] Connected to %s:%d%s\n", host, port, path);
    }

private:
    /**
     * SSL handshake dispatch - compile-time selection between fd-based and userspace BIO
     *
     * For BSD sockets (is_fd_based_transport_v = true):
     *   Uses ssl_.handshake(fd) with kernel file descriptor
     *   Supports kTLS offload on Linux
     *
     * For userspace transports (is_fd_based_transport_v = false):
     *   Uses ssl_.handshake_userspace_transport(&transport_)
     *   Uses custom OpenSSL BIO for userspace TCP stack
     */
    void ssl_handshake_dispatch() {
        if constexpr (websocket::traits::is_fd_based_transport_v<TransportPolicy_>) {
            // BSD socket: use fd-based handshake (supports kTLS)
            int fd = transport_.get_fd();
            ssl_.handshake(fd);
        } else {
            // XDP/Userspace: use userspace transport BIO
            ssl_.handshake_userspace_transport(&transport_);
        }
    }

public:

    // Main event loop - runs until disconnected
    void run(MessageCallback on_message) {
        // Compile-time constant for transport type dispatch
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        on_message_ = on_message;

        while (connected_) {
            // Wait for events (epoll/select/io_uring for BSD, busy-poll for XDP)
            int ready = transport_.wait();
            if (ready <= 0) continue;

            // For BSD sockets: verify ready fd and drain HW timestamps (compile-time dispatch)
            if constexpr (is_fd_based) {
                int fd = transport_.get_fd();
                int ready_fd = transport_.get_ready_fd();
                if (ready_fd != fd) continue;

                // Stage 1: Drain hardware RX timestamps from NIC/kernel queue
                // Only applicable for BSD sockets (XDP has no kernel timestamps)
                drain_hw_timestamps(fd, &timing_);
            }

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
        if (connected_ || transport_.is_connected()) {
            ssl_.shutdown();
            transport_.close();
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
        using namespace websocket::http;

        while (rx_buffer_.readable() >= 2) {  // Minimum frame header size
            size_t available_len = 0;
            const uint8_t* read_ptr = rx_buffer_.next_read_region(&available_len);

            if (available_len < 2) break;

            // Parse WebSocket frame using core utilities
            WebSocketFrame frame;
            if (!parse_websocket_frame(read_ptr, available_len, frame)) {
                break;  // Need more data or invalid frame
            }

            // Reject fragmented messages (not supported)
            if (!frame.fin) {
                printf("[ERROR] Fragmented WebSocket messages not supported (FIN=0)\n");
                printf("[ERROR] This library is designed for single-frame messages only\n");
                connected_ = false;
                break;
            }

            // Check for integer overflow before calculating frame_len
            if (frame.payload_len > SIZE_MAX - frame.header_len) {
                printf("[ERROR] Frame too large: payload_len=%lu exceeds SIZE_MAX\n",
                       (unsigned long)frame.payload_len);
                connected_ = false;
                break;
            }

            size_t frame_len = frame.header_len + frame.payload_len;

            // Stage 5: Frame parsing completed
            timing_.frame_parsed_cycle = rdtscp();
            timing_.payload_len = frame.payload_len;
            timing_.opcode = frame.opcode;

            // Handle different frame types
            if (frame.opcode == 0x09) {  // PING frame
                // Silently respond with PONG (no logging for production HFT performance)
                send_pong(frame.payload, frame.payload_len);
                rx_buffer_.commit_read(frame_len);
            }
            else if (frame.opcode == 0x01 || frame.opcode == 0x02) {  // Text or Binary frame
                // Invoke user callback with zero-copy pointer and timing data
                // Stage 6 is implemented inside the callback by user code
                if (on_message_) {
                    on_message_(frame.payload, frame.payload_len, timing_);
                }
                msg_count_++;
                rx_buffer_.commit_read(frame_len);
            }
            else if (frame.opcode == 0x0A) {  // PONG frame (response to our ping)
                // Server sent a pong, just ignore it
                rx_buffer_.commit_read(frame_len);
            }
            else if (frame.opcode == 0x08) {  // Close frame
                printf("[WS] Received close frame from server\n");
                if (frame.payload_len > 0 && frame.payload_len < 126) {
                    // Close frame can have status code and reason
                    uint16_t status_code = (frame.payload[0] << 8) | frame.payload[1];
                    printf("[WS] Close status code: %u\n", status_code);
                    if (frame.payload_len > 2) {
                        printf("[WS] Close reason: %.*s\n", (int)(frame.payload_len - 2),
                               frame.payload + 2);
                    }
                }
                connected_ = false;
                rx_buffer_.commit_read(frame_len);
                break;
            }
            else {
                // Unknown opcode, skip frame
                printf("[WARN] Unknown opcode: 0x%02X, payload_len: %zu\n",
                       frame.opcode, (size_t)frame.payload_len);
                rx_buffer_.commit_read(frame_len);
            }
        }
    }


    // Send HTTP upgrade request with custom headers
    void send_http_upgrade(const char* host, const char* path,
                          const HeaderMap& custom_headers) {
        using namespace websocket::http;

        char request[4096];
        size_t len = build_websocket_upgrade_request(host, path, custom_headers,
                                                       request, sizeof(request));

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
        using namespace websocket::http;

        uint8_t pong[256];

        // Static masking key for performance (single-threaded HFT env)
        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};

        // Build PONG frame using core utilities
        size_t frame_len = build_pong_frame(payload, len, pong, mask);

        // Check write return value
        ssize_t ret = ssl_.write(pong, frame_len);
        if (ret <= 0) {
            printf("[WARN] Failed to send PONG response\n");
        }
    }

    // Access to transport for advanced configuration (e.g., XDP init)
    TransportPolicy_& transport() { return transport_; }
    const TransportPolicy_& transport() const { return transport_; }

private:
    SSLPolicy_ ssl_;
    TransportPolicy_ transport_;     // Unified transport (owns connection + event loop)
    RxBufferPolicy_ rx_buffer_;      // Separate RX buffer type/size
    TxBufferPolicy_ tx_buffer_;      // Separate TX buffer type/size

    bool connected_;
    uint64_t msg_count_;
    MessageCallback on_message_;
    timing_record_t timing_;  // Timing information for current message
};
