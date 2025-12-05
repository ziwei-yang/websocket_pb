// websocket.hpp
// High-performance WebSocket client using policy-based design
//
// TransportPolicy Design:
//   WebSocketClient uses TransportPolicy to encapsulate both transport mechanism
//   (BSD socket or XDP) and event waiting strategy (epoll/select/io_uring or busy-polling).
//
// Supported Transports:
//   - BSDSocketTransport<EventPolicy>: BSD sockets + event loop (kernel TCP/IP)
//   - XDPUserspaceTransport: AF_XDP zero-copy + userspace TCP/IP stack (complete kernel bypass)
//
// XDP Mode Features (AF_XDP Zero-Copy):
//   - Native driver mode (XDP_FLAGS_DRV_MODE) with zero-copy (XDP_ZEROCOPY)
//   - Complete kernel bypass using userspace TCP/IP stack
//   - NIC hardware timestamp support (Stage 1 latency measurement)
//   - NAPI modes: NAPI_IRQ, NAPI_TIMER, USER_POLL (lowest latency)
//   - RX trickle workaround for igc driver TX completion stall (see xdp_transport.hpp)
//
// SSL Integration (compile-time dispatch):
//   - BSD sockets: Uses fd-based SSL handshake (supports kTLS)
//   - XDP: Uses UserspaceTransportBIO for SSL over userspace transport
//   - Dispatch is done at compile-time using is_fd_based_transport<T> trait
//
// 6-Stage Latency Measurement:
//   Stage 1: NIC hardware timestamp (XDP metadata or SO_TIMESTAMPING)
//   Stage 2: Event loop entry (rdtsc)
//   Stage 3: Before SSL read (rdtsc)
//   Stage 4: After SSL read (rdtscp)
//   Stage 5: WebSocket frame parsed (rdtscp)
//   Stage 6: User callback entry (rdtscp)
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

// Forward declare XDPUserspaceTransport for trait specialization
#ifdef USE_XDP
namespace websocket { namespace transport { class XDPUserspaceTransport; } }

// Explicit specialization: XDPUserspaceTransport is NOT fd-based (userspace transport)
namespace websocket { namespace traits {
template<>
struct is_fd_based_transport<websocket::transport::XDPUserspaceTransport, void> : std::false_type {};
} }
#endif

template<
    typename SSLPolicy_,
    typename TransportPolicy_,     // Unified transport (BSD+event or XDP)
    typename RxBufferPolicy_,      // Separate RX buffer (can have different size)
    typename TxBufferPolicy_       // Separate TX buffer (can have different size)
>
struct WebSocketClient {
    // Type aliases for policy introspection
    using SSLPolicy = SSLPolicy_;
    using TransportPolicy = TransportPolicy_;
    using RxBufferPolicy = RxBufferPolicy_;
    using TxBufferPolicy = TxBufferPolicy_;

    // HTTP header customization support
    using HeaderMap = std::vector<std::pair<std::string, std::string>>;

    // Batch message callback - receives array of messages with per-message timing
    // timing_record_t contains batch-level SSL timing, MessageInfo has per-message parse_cycle
    // Returns: true to continue receiving, false to exit run() loop
    using MessageCallback = std::function<bool(const MessageInfo*, size_t, const timing_record_t&)>;

    WebSocketClient()
        : connected_(false)
        , xdp_initialized_(false)
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

    /**
     * Initialize XDP transport with domain name or IP (resolves DNS internally)
     *
     * @param interface  Network interface name (e.g., "enp108s0")
     * @param bpf_obj    Path to BPF object file (e.g., "src/xdp/bpf/exchange_filter.bpf.o")
     * @param domain     Exchange domain to filter (e.g., "stream.binance.com")
     * @param port       Exchange port to filter (e.g., 443)
     */
    template<typename T = TransportPolicy_>
    typename std::enable_if<!websocket::traits::is_fd_based_transport_v<T>, void>::type
    init_xdp(const char* interface, const char* bpf_obj,
             const char* domain, uint16_t port) {
        printf("[XDP] Initializing AF_XDP transport...\n");
        printf("[XDP]   Interface: %s\n", interface);
        printf("[XDP]   BPF object: %s\n", bpf_obj);
        printf("[XDP]   Domain: %s, Port: %u\n", domain, port);

        // Resolve domain to IPs
        auto ips = resolve_hostname(domain);
        if (ips.empty()) {
            throw std::runtime_error(std::string("Failed to resolve domain: ") + domain);
        }
        printf("[XDP]   Resolved %zu IP(s)\n", ips.size());

        // Initialize XDP transport with interface and BPF program
        transport_.init(interface, bpf_obj);

        // Configure BPF filter for all resolved IPs
        for (const auto& ip : ips) {
            transport_.add_exchange_ip(ip.c_str());
            printf("[XDP]     Added IP: %s\n", ip.c_str());
        }
        transport_.add_exchange_port(port);

        xdp_initialized_ = true;
        printf("[XDP] Transport initialized successfully\n");
    }

    // Connect to WebSocket server with optional custom HTTP headers
    void connect(const char* host, uint16_t port, const char* path,
                 const HeaderMap& custom_headers = {}) {
        // Compile-time constant for transport type dispatch
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        // 1. Initialize transport (skip if XDP was already initialized via init_xdp())
        if constexpr (is_fd_based) {
            // BSD sockets: always initialize here
            transport_.init();
        } else {
            // XDP: must be initialized via init_xdp() first
            if (!xdp_initialized_) {
                throw std::runtime_error(
                    "XDP transport not initialized. Call init_xdp() before connect()");
            }
        }

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

        // 9. Configure wait timeout (1 second default)
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
            if (ready <= 0) {
                // Even on timeout, check TX outbox for pending messages
                drain_tx_buffer();
                continue;
            }

            // For BSD sockets: verify ready fd and drain HW timestamps (compile-time dispatch)
            if constexpr (is_fd_based) {
                int fd = transport_.get_fd();
                int ready_fd = transport_.get_ready_fd();
                if (ready_fd != fd) continue;

                // Stage 1: Drain hardware RX timestamps from NIC/kernel queue
                // Only applicable for BSD sockets (XDP has no kernel timestamps)
                drain_hw_timestamps(fd, &timing_);
            } else {
                // Stage 1: Get hardware RX timestamps from XDP metadata
                // XDP captures timestamp via bpf_xdp_metadata_rx_timestamp() kfunc
                // For multi-packet messages, oldest = first packet, latest = most recent
                uint32_t count = transport_.get_hw_timestamp_count();
                if (count > 0) {
                    timing_.hw_timestamp_oldest_ns = transport_.get_oldest_rx_hw_timestamp();
                    timing_.hw_timestamp_latest_ns = transport_.get_latest_rx_hw_timestamp();
                    timing_.hw_timestamp_count = count;
                    timing_.hw_timestamp_byte_count = transport_.get_hw_timestamp_byte_count();
                    // Reset for next message
                    transport_.reset_hw_timestamps();
                }
            }

            // Stage 2: Record CPU cycle when event loop processing starts
            timing_.event_cycle = rdtsc();

            // Read data into ring buffer
            if (!recv_into_buffer()) {
                break;  // Connection closed or error
            }

            // Process WebSocket frames
            if (!process_frames()) {
                break;  // Callback requested stop
            }

            // Drain TX outbox after processing RX
            drain_tx_buffer();
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

    /**
     * Set external TX buffer for shared memory outbox (IPC)
     *
     * Enables another process to post raw (un-framed) messages to a shared
     * memory region. WebSocketClient will automatically wrap payloads in
     * WebSocket frames (opcode, FIN, mask, length) and send via SSL.
     *
     * Pass nullptr to disable custom outbox (default behavior).
     * Must be called before connect() if using external buffer.
     *
     * @param buffer  Pointer to shared memory region, or nullptr to disable
     * @param size    Size of shared memory (must match TxBufferPolicy capacity)
     * @param opcode  WebSocket opcode for messages (0x01=text, 0x02=binary)
     */
    void set_tx_buffer(void* buffer, size_t size, uint8_t opcode = 0x01) {
        if (buffer == nullptr) {
            tx_outbox_enabled_ = false;
            return;
        }
        tx_buffer_.init_external(buffer, size);
        tx_outbox_enabled_ = true;
        tx_opcode_ = opcode;
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

        // First read
        ssize_t n = ssl_.read(write_ptr, available);

        if (n > 0) {
            rx_buffer_.commit_write(n);
            ssize_t total_read = n;

            // Continue reading while more data available (drain all SSL records)
            // This ensures multiple WebSocket frames are batched together
            while (true) {
                write_ptr = rx_buffer_.next_write_region(&available);
                if (available == 0) break;  // Buffer full

                n = ssl_.read(write_ptr, available);
                if (n > 0) {
                    rx_buffer_.commit_write(n);
                    total_read += n;
                } else {
                    // No more data (EAGAIN) or error - stop reading
                    break;
                }
            }

            // Stage 4: Record timestamp after all SSL_read completed
            timing_.recv_end_cycle = rdtscp();
            timing_.ssl_read_bytes = total_read;
            return true;
        } else if (n == 0) {
            // Connection closed gracefully
            timing_.recv_end_cycle = rdtscp();
            timing_.ssl_read_bytes = 0;
            connected_ = false;
            return false;
        } else {
            // Would block (EAGAIN) or error - just continue event loop
            timing_.recv_end_cycle = rdtscp();
            timing_.ssl_read_bytes = 0;
            return true;
        }
    }

    /**
     * Drain TX outbox - frame and send pending raw messages
     *
     * Called from event loop after processing RX. Reads raw payloads from
     * tx_buffer_, wraps each in a WebSocket frame, and sends via SSL.
     *
     * Producer writes raw text/binary data to shared memory ring buffer.
     * This method wraps in WebSocket frame (opcode, FIN=1, mask, length).
     */
    void drain_tx_buffer() {
        using namespace websocket::http;

        if (!tx_outbox_enabled_) return;

        // Static masking key for HFT performance (single-threaded env)
        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};

        while (tx_buffer_.readable() > 0) {
            size_t payload_len = 0;
            const uint8_t* payload = tx_buffer_.next_read_region(&payload_len);
            if (!payload || payload_len == 0) break;

            // Build WebSocket frame from raw payload
            // Max frame: 14 bytes header + payload
            uint8_t frame[14 + 65536];  // Support up to 64KB messages
            if (payload_len > 65536) {
                printf("[WARN] TX message too large (%zu bytes), truncating\n", payload_len);
                payload_len = 65536;
            }

            size_t frame_len = build_websocket_frame(
                payload, payload_len, frame, sizeof(frame), mask, tx_opcode_);

            // Send framed message through SSL
            ssize_t sent = ssl_.write(frame, frame_len);
            if (sent > 0) {
                tx_buffer_.commit_read(payload_len);
            } else {
                break;  // Would block or error - retry next cycle
            }
        }
    }

    // Process WebSocket frames from ring buffer
    // Returns: true to continue, false if callback requested stop
    bool process_frames() {
        using namespace websocket::http;

        // Reset batch for this processing round
        batch_count_ = 0;

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

            // Handle different frame types
            if (frame.opcode == 0x09) {  // PING frame
                // Silently respond with PONG (no logging for production HFT performance)
                send_pong(frame.payload, frame.payload_len);
                rx_buffer_.commit_read(frame_len);
            }
            else if (frame.opcode == 0x01 || frame.opcode == 0x02) {  // Text or Binary frame
                // Collect into batch instead of immediate callback
                if (batch_count_ < MAX_BATCH_SIZE) {
                    // Stage 5: Record parse time for this message
                    message_batch_[batch_count_] = {
                        frame.payload,
                        frame.payload_len,
                        rdtscp(),      // Per-message parse cycle
                        frame.opcode
                    };
                    batch_count_++;
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

        // Invoke batch callback if we collected any messages
        if (batch_count_ > 0 && on_message_) {
            if (!on_message_(message_batch_, batch_count_, timing_)) {
                return false;  // Callback requested stop
            }
        }
        return true;  // Continue processing
    }


    // Send HTTP upgrade request with custom headers
    void send_http_upgrade(const char* host, const char* path,
                          const HeaderMap& custom_headers) {
        using namespace websocket::http;
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        char request[4096];
        size_t len = build_websocket_upgrade_request(host, path, custom_headers,
                                                       request, sizeof(request));

        if constexpr (is_fd_based) {
            // BSD sockets: single blocking write
            ssize_t n = ssl_.write(request, len);
            if (n <= 0) {
                throw std::runtime_error("Failed to send HTTP upgrade");
            }
        } else {
            // XDP/Userspace: polling loop required
            size_t total_sent = 0;
            int max_attempts = 2000;
            int attempts = 0;

            while (total_sent < len && attempts < max_attempts) {
                transport_.poll();
                ssize_t sent = ssl_.write(request + total_sent, len - total_sent);

                if (sent > 0) {
                    total_sent += sent;
                } else if (sent < 0 && errno != EAGAIN) {
                    throw std::runtime_error("Failed to send HTTP upgrade");
                }

                usleep(1000);  // 1ms between polls
                attempts++;
            }

            if (total_sent < len) {
                throw std::runtime_error("Failed to send complete HTTP upgrade");
            }
        }
    }

    // Receive HTTP 101 Switching Protocols response
    void recv_http_response() {
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        uint8_t buf[4097];  // +1 for null terminator
        ssize_t n = 0;

        if constexpr (is_fd_based) {
            // BSD sockets: single blocking read
            n = ssl_.read(buf, sizeof(buf) - 1);
        } else {
            // XDP/Userspace: polling loop required
            int max_attempts = 2000;
            int attempts = 0;

            while (attempts < max_attempts) {
                transport_.poll();
                n = ssl_.read(buf, sizeof(buf) - 1);

                if (n > 0) {
                    break;  // Got data
                } else if (n < 0 && errno != EAGAIN) {
                    throw std::runtime_error("SSL read error during HTTP response");
                }

                usleep(1000);  // 1ms between polls
                attempts++;
            }
        }

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

public:
    // Access to transport for advanced configuration (e.g., XDP init, stats)
    TransportPolicy_& transport() { return transport_; }
    const TransportPolicy_& transport() const { return transport_; }

private:
    // Helper to resolve hostname to IP addresses for BPF filter
    static std::vector<std::string> resolve_hostname(const char* hostname) {
        std::vector<std::string> ips;
        struct addrinfo hints = {};
        struct addrinfo* result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(hostname, nullptr, &hints, &result);
        if (ret != 0 || !result) {
            if (result) freeaddrinfo(result);
            return ips;
        }

        for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                auto* addr = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
                ips.push_back(ip_str);
            }
        }
        freeaddrinfo(result);
        return ips;
    }

    SSLPolicy_ ssl_;
    TransportPolicy_ transport_;     // Unified transport (owns connection + event loop)
    RxBufferPolicy_ rx_buffer_;      // Separate RX buffer type/size
    TxBufferPolicy_ tx_buffer_;      // Separate TX buffer type/size

    bool connected_;
    bool xdp_initialized_;           // True if init_xdp() was called (XDP mode only)
    bool tx_outbox_enabled_ = false; // True if external TX outbox is set via set_tx_buffer()
    uint8_t tx_opcode_ = 0x01;       // WebSocket opcode for TX outbox (0x01=text, 0x02=binary)
    uint64_t msg_count_;
    MessageCallback on_message_;
    timing_record_t timing_;  // Batch-level timing (SSL read timing shared by all messages)

    // Batch message collection
    static constexpr size_t MAX_BATCH_SIZE = 256;
    MessageInfo message_batch_[MAX_BATCH_SIZE];
    size_t batch_count_ = 0;
};
