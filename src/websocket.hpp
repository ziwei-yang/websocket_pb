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
#include "core/ringbuffer.hpp"  // For circular_read/circular_write helpers
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

// Shared memory batch types (always included for if constexpr branches)
#include "core/shm_types.hpp"

#ifdef USE_HFTSHM
#include "core/hftshm_ringbuffer.hpp"
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

    // Compile-time detection of HftShm buffers
    // Both RingBuffer and HftShmRingBuffer have is_hftshm static member
    static constexpr bool uses_hftshm = RxBufferPolicy_::is_hftshm;
    static constexpr bool uses_hftshm_tx = TxBufferPolicy_::is_hftshm;

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
        try {
            rx_buffer_.init();  // Buffer initializes with its template parameter size
        } catch (const std::runtime_error& e) {
            throw std::runtime_error(
                "RX buffer init failed (shared memory segment missing?): " +
                std::string(e.what()));
        }

        try {
            tx_buffer_.init();
        } catch (const std::runtime_error& e) {
            throw std::runtime_error(
                "TX buffer init failed (shared memory segment missing?): " +
                std::string(e.what()));
        }

        // Auto-enable TX outbox for HftShm buffers (have is_hftshm trait)
        enable_hftshm_tx_outbox();

        ssl_.init();

        // Initialize timing record
        memset(&timing_, 0, sizeof(timing_));

        // Allocate initial message batch buffer
        message_batch_ = new MessageInfo[INITIAL_BATCH_CAPACITY];
    }

    ~WebSocketClient() {
        disconnect();
        delete[] message_batch_;
        message_batch_ = nullptr;
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

        // Store connection params for reconnection
        host_ = host;
        port_ = port;
        path_ = path;

        connected_ = true;
        printf("[WS] Connected to %s:%d%s\n", host, port, path);

        // Invoke on_connect callback to populate subscription messages
        invoke_on_connect();
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
    // If on_close callback is set and returns true, will reconnect automatically
    void run(MessageCallback on_message) {
        // Compile-time constant for transport type dispatch
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        on_message_ = on_message;

        while (true) {  // Outer reconnect loop
            // Inner event loop
            while (connected_ && (!stop_flag_ || *stop_flag_)) {
                // Wait for events (epoll/select/io_uring for BSD, busy-poll for XDP)
                // If set_wait_timeout() was called, wait() will respect the timeout
                int ready = transport_.wait();

                if (ready <= 0) {
                    // Attempt non-blocking SSL_read to drain TLS record buffer
                    // This prevents stalls when epoll misses buffered data (edge-triggered)
                    if (!try_read_on_timeout()) {
                        break;  // Connection closed
                    }

                    // Even on timeout, send subscriptions and check TX outbox
                    send_subscribe_messages();
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
                // For HftShm: always process to write structured entries to buffer
                // For standard: only if callback is configured
                if constexpr (uses_hftshm) {
                    if (!process_frames()) {
                        break;
                    }
                } else {
                    if (on_message_) {
                        if (!process_frames()) {
                            break;  // Callback requested stop
                        }
                    }
                }

                // Send subscriptions then drain TX outbox after processing RX
                send_subscribe_messages();
                drain_tx_buffer();
            }

            printf("[WS] Event loop terminated\n");

            // Check for reconnection: invoke on_close if set, reconnect if it returns true
            if (on_close_ && on_close_() && (!stop_flag_ || *stop_flag_)) {
                printf("[WS] Reconnecting...\n");
                // Clean up old connection before reconnecting
                disconnect();
                try {
                    connect(host_.c_str(), port_, path_.c_str());
                    continue;  // Resume event loop
                } catch (const std::exception& e) {
                    printf("[WS] Reconnect failed: %s\n", e.what());
                }
            }
            break;  // Exit if no on_close, callback returns false, or reconnect failed
        }
    }

    // Graceful disconnect
    void disconnect() {
        if (connected_ || transport_.is_connected()) {
            ssl_.shutdown();
            transport_.close();
            connected_ = false;
            // Reset HftShm state to avoid stale data on reconnect
            hftshm_batch_start_pos_ = 0;
            hftshm_data_written_ = 0;
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
            return true;  // Not an error, just buffer full
        }

        // Stage 3: Record timestamp before SSL_read/recv
        timing_.recv_start_cycle = rdtsc();

        if constexpr (uses_hftshm) {
            // HftShm circular buffer mode: SSL_read directly into ring buffer
            // Format: [ShmBatchHeader (CLS)][raw_ssl_data padded (N*CLS)][ShmFrameDesc[] padded (M*CLS)]
            // Data can wrap around buffer boundary seamlessly
            constexpr size_t HDR_SIZE = sizeof(ShmBatchHeader);  // CACHE_LINE_SIZE
            // Minimum batch: header + 1 CLS of data + 1 CLS of descriptors
            size_t min_needed = HDR_SIZE + CACHE_LINE_SIZE + CACHE_LINE_SIZE;

            // Check total writable space (may span wrap point)
            size_t total_writable = rx_buffer_.writable();
            if (total_writable < min_needed) {
                timing_.recv_end_cycle = rdtscp();
                timing_.ssl_read_bytes = 0;
                return true;  // Buffer full, wait for consumer
            }

            // Get circular buffer info
            uint8_t* buffer = rx_buffer_.buffer_base();
            size_t capacity = rx_buffer_.buffer_capacity();
            size_t write_pos = rx_buffer_.current_write_pos();

            // Record batch start position for process_frames()
            hftshm_batch_start_pos_ = write_pos;

            // Calculate data region (after header), accounting for leftover from previous batch
            // New batch's data region starts at (write_pos + HDR_SIZE)
            // If leftover exists, copy it from old position to new data region start
            size_t data_pos = (write_pos + HDR_SIZE) % capacity;

            // Copy leftover bytes from old position to new position
            // After commit_write(), write_pos advanced but leftover stayed at old location
            if (leftover_len_ > 0 && leftover_pos_ != data_pos) {
                circular_copy(buffer, capacity, leftover_pos_, data_pos, leftover_len_);
            }

            // SSL_read writes after leftover
            size_t write_offset = leftover_len_;
            size_t ssl_write_pos = (data_pos + write_offset) % capacity;
            size_t data_available = total_writable - HDR_SIZE - CACHE_LINE_SIZE - write_offset;

            // SSL_read into circular buffer (after leftover)
            // If data region spans wrap point, do two reads
            size_t to_end = capacity - ssl_write_pos;
            ssize_t n = 0;

            if (data_available <= to_end) {
                // No wrap - single read
                n = ssl_.read(buffer + ssl_write_pos, data_available);
            } else {
                // Split read: first part to end, then from start if more available
                n = ssl_.read(buffer + ssl_write_pos, to_end);
                if (n == static_cast<ssize_t>(to_end)) {
                    // First part full, try to fill second part
                    ssize_t n2 = ssl_.read(buffer, data_available - to_end);
                    if (n2 > 0) n += n2;
                }
            }

            if (n > 0) {
                // Store for process_frames() to parse and commit
                // Total data = leftover + new SSL_read bytes
                hftshm_data_written_ = write_offset + static_cast<size_t>(n);
                timing_.recv_end_cycle = rdtscp();
                timing_.ssl_read_bytes = n;
                return true;
            } else if (n == 0) {
                // Connection closed
                printf("[RECV] Connection closed (SSL_read=0) in recv_into_buffer\n");
                fflush(stdout);
                timing_.recv_end_cycle = rdtscp();
                timing_.ssl_read_bytes = 0;
                connected_ = false;
                return false;
            } else {
                // SSL_read error (WANT_READ/WANT_WRITE)
                timing_.recv_end_cycle = rdtscp();
                timing_.ssl_read_bytes = 0;
                return true;
            }
        } else {
            // Standard mode: Direct SSL_read into buffer
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
    }

    // Non-blocking SSL read during timeout - drains TLS buffer to handle ping frames
    // Returns false if connection closed, true otherwise
    // This prevents stalls when epoll misses buffered TLS data (edge-triggered mode)
    // IMPORTANT: Must loop to drain ALL data (edge-triggered epoll won't re-notify)
    bool try_read_on_timeout() {
        // Only for HftShm mode (where the issue was observed)
        if constexpr (!uses_hftshm) {
            return true;  // Standard mode not affected
        }

        constexpr size_t HDR_SIZE = sizeof(ShmBatchHeader);
        constexpr size_t TAILER_RESERVE = 32 * sizeof(ShmFrameDesc) + 1;
        constexpr size_t MIN_DATA_SPACE = 256;
        size_t min_needed = HDR_SIZE + MIN_DATA_SPACE + TAILER_RESERVE;

        // Loop to drain all available data from SSL buffer
        while (true) {
            // Check total writable space
            size_t total_writable = rx_buffer_.writable();
            if (total_writable < min_needed) {
                return true;  // Buffer full or not enough space
            }

            // Get circular buffer info
            uint8_t* buffer = rx_buffer_.buffer_base();
            size_t capacity = rx_buffer_.buffer_capacity();
            size_t write_pos = rx_buffer_.current_write_pos();

            // Record batch start position
            hftshm_batch_start_pos_ = write_pos;

            // Calculate data region
            size_t data_pos = (write_pos + HDR_SIZE) % capacity;
            size_t data_available = total_writable - HDR_SIZE - TAILER_RESERVE;

            // SSL_read into circular buffer
            size_t to_end = capacity - data_pos;
            ssize_t n = 0;

            if (data_available <= to_end) {
                n = ssl_.read(buffer + data_pos, data_available);
            } else {
                n = ssl_.read(buffer + data_pos, to_end);
                if (n == static_cast<ssize_t>(to_end)) {
                    ssize_t n2 = ssl_.read(buffer, data_available - to_end);
                    if (n2 > 0) n += n2;
                }
            }

            if (n > 0) {
                // Data found - process it and loop to check for more
                hftshm_data_written_ = static_cast<size_t>(n);

                // Process frames (handles ping/pong)
                if (!process_frames()) {
                    return false;  // Callback requested stop or connection closed
                }
                // Loop back to try reading more data
            } else if (n == 0) {
                // Connection closed by peer
                connected_ = false;
                return false;
            } else {
                // WANT_READ/WRITE - no more data available, exit loop
                break;
            }
        }

        return true;
    }

    /**
     * Invoke on_connect callback to populate subscription messages
     * Resets state and calls user callback to set subscribe_messages_
     */
    void invoke_on_connect() {
        num_subscribe_messages_ = 0;
        subscribe_messages_sent_ = false;
        if (on_connect_) {
            on_connect_(subscribe_messages_, num_subscribe_messages_);
        }
    }

    /**
     * Send stored subscription messages (called before drain_tx_buffer)
     * Sends all messages populated by on_connect callback
     */
    void send_subscribe_messages() {
        using namespace websocket::http;

        if (subscribe_messages_sent_ || num_subscribe_messages_ == 0) return;

        for (size_t i = 0; i < num_subscribe_messages_; ++i) {
            size_t msg_len = strlen(subscribe_messages_[i]);
            uint8_t header[14];
            size_t header_len = build_websocket_header_zerocopy(header, msg_len, 0x01);

            if (ssl_.write(header, header_len) <= 0) return;  // Retry next cycle
            if (ssl_.write(reinterpret_cast<const uint8_t*>(subscribe_messages_[i]),
                          msg_len) <= 0) return;
        }
        subscribe_messages_sent_ = true;
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

        // For HftShm TX buffers, always process; otherwise require explicit enable
        if constexpr (!uses_hftshm_tx) {
            if (!tx_outbox_enabled_) return;
        }

        while (tx_buffer_.readable() > 0) {
            size_t payload_len = 0;
            const uint8_t* payload = tx_buffer_.next_read_region(&payload_len);
            if (!payload || payload_len == 0) break;

            // Zero-copy TX: Build header only, send header + raw payload separately
            // mask=0 means payload XOR 0 = payload, no transformation needed
            uint8_t header[14];  // Max header size: 10 + 4 mask bytes
            size_t header_len = build_websocket_header_zerocopy(header, payload_len, tx_opcode_);

            // Send header first
            ssize_t sent = ssl_.write(header, header_len);
            if (sent <= 0) {
                break;  // Would block or error - retry next cycle
            }

            // Send payload directly from TX buffer (zero-copy!)
            sent = ssl_.write(payload, payload_len);
            if (sent > 0) {
                tx_buffer_.commit_read(payload_len);
            } else {
                // Header sent but payload failed - connection may be in bad state
                printf("[WARN] TX header sent but payload failed\n");
                break;
            }
        }
    }

    // Process WebSocket frames from ring buffer
    // Returns: true to continue, false if callback requested stop
    bool process_frames() {
        using namespace websocket::http;

        // Reset batch for this processing round
        batch_count_ = 0;

        if constexpr (uses_hftshm) {
            // HftShm circular buffer mode: Parse frames with circular access
            // Format: [ShmBatchHeader (CLS)][raw_ssl_data padded (N*CLS)][ShmFrameDesc[] padded (M*CLS)]
            // Data may wrap around buffer boundary seamlessly
            if (hftshm_data_written_ == 0) return true;

            constexpr size_t HDR_SIZE = sizeof(ShmBatchHeader);  // CACHE_LINE_SIZE

            uint8_t* buffer = rx_buffer_.buffer_base();
            size_t capacity = rx_buffer_.buffer_capacity();
            size_t batch_pos = hftshm_batch_start_pos_;
            size_t ssl_data_pos = (batch_pos + HDR_SIZE) % capacity;
            size_t ssl_data_len = hftshm_data_written_;

            // Frame descriptors: embedded go directly to header, overflow written at commit
            // Increased limit: 255 frames max (uint8_t frame_count in ShmBatchHeader)
            constexpr size_t MAX_FRAMES = 255;
            ShmFrameDesc frame_descs[MAX_FRAMES];
            uint8_t frame_count = 0;
            uint16_t suspicious_ctrl_count = 0;  // Track likely frame misalignment

            // Parsing starts at offset 0 (includes leftover from previous batch)
            size_t parse_offset = 0;

            // Restore persistent fragment state (if any)
            bool local_accumulating = persistent_accumulating_;
            uint8_t accum_opcode = persistent_opcode_;
            size_t accum_payload_len = persistent_accum_len_;
            uint32_t accum_payload_start = 0;  // Leftover always starts at offset 0

            while (parse_offset + 2 <= ssl_data_len && frame_count < MAX_FRAMES) {
                // Read frame header from circular buffer (max 14 bytes)
                uint8_t header_bytes[14];
                size_t header_pos = (ssl_data_pos + parse_offset) % capacity;
                size_t remaining = ssl_data_len - parse_offset;
                size_t peek_len = std::min(size_t(14), remaining);
                circular_read(buffer, capacity, header_pos, header_bytes, peek_len);

                WebSocketFrame frame;
                // Pass 'remaining' as available length so parse_websocket_frame can check
                // if the full frame (header + payload) fits in the available data
                if (!parse_websocket_frame(header_bytes, remaining, frame)) {
                    break;  // Incomplete frame header or payload
                }

                size_t frame_len = frame.header_len + frame.payload_len;
                if (parse_offset + frame_len > ssl_data_len) break;  // Incomplete frame

                // For circular payloads, update frame.payload to point into buffer
                // Note: This pointer may only be valid for first part if wrap occurs
                size_t payload_pos = (ssl_data_pos + parse_offset + frame.header_len) % capacity;
                frame.payload = buffer + payload_pos;

                // Debug: Log non-data frames (PING/PONG/CLOSE)
                if (frame.opcode >= 0x08) {
                    printf("[WS-CTRL] op=0x%02x len=%lu\n", frame.opcode, frame.payload_len);
                    fflush(stdout);
                }

                // Handle fragmented WebSocket messages (text/binary only)
                if ((frame.opcode == 0x01 || frame.opcode == 0x02) && !frame.fin) {
                    // First fragment: Start accumulation
                    local_accumulating = true;
                    accum_payload_start = static_cast<uint32_t>(parse_offset + frame.header_len);
                    accum_payload_len = frame.payload_len;
                    accum_opcode = frame.opcode;
                    parse_offset += frame_len;
                    continue;
                }

                if (frame.opcode == 0x00) {
                    // Continuation fragment
                    if (local_accumulating) {
                        accum_payload_len += frame.payload_len;
                        if (frame.fin) {
                            // Final fragment: Record complete reassembled message
                            uint32_t payload_start = accum_payload_start;
                            uint32_t payload_len = static_cast<uint32_t>(accum_payload_len);

                            if (payload_start + payload_len <= ssl_data_len) {
                                frame_descs[frame_count].payload_start = payload_start;
                                frame_descs[frame_count].payload_len = payload_len;
                                frame_descs[frame_count].opcode = accum_opcode;
                                frame_count++;
                                msg_count_++;

                                // Collect for callback (circular pointer)
                                ensure_batch_capacity();
                                size_t cb_payload_pos = (ssl_data_pos + payload_start) % capacity;
                                message_batch_[batch_count_++] = {
                                    buffer + cb_payload_pos, accum_payload_len,
                                    rdtscp(), accum_opcode
                                };
                            }
                            local_accumulating = false;
                        }
                    }
                    parse_offset += frame_len;
                    continue;
                }

                if (frame.opcode == 0x01 || frame.opcode == 0x02) {  // Text/Binary (complete frame)
                    uint32_t payload_start = static_cast<uint32_t>(parse_offset + frame.header_len);
                    uint32_t payload_len = static_cast<uint32_t>(frame.payload_len);

                    // Validate offsets
                    if (payload_start + payload_len > ssl_data_len) {
                        printf("[ERROR] Frame offset out of bounds: start=%u len=%u ssl_len=%zu\n",
                               payload_start, payload_len, ssl_data_len);
                        break;
                    }

                    // Record frame descriptor (offsets are relative to ssl_data start)
                    frame_descs[frame_count].payload_start = payload_start;
                    frame_descs[frame_count].payload_len = payload_len;
                    frame_descs[frame_count].opcode = frame.opcode;
                    frame_count++;
                    msg_count_++;

                    // Collect for callback (circular pointer)
                    ensure_batch_capacity();
                    message_batch_[batch_count_++] = {
                        frame.payload, frame.payload_len, rdtscp(), frame.opcode
                    };
                }
                else if (frame.opcode == 0x09) {  // PING
                    printf("[WS] PING received, len=%u, sending PONG\n", frame.payload_len);
                    if (frame.payload_len <= 125) {
                        // For PONG, need contiguous payload - copy if wrapped
                        size_t pong_pos = (ssl_data_pos + parse_offset + frame.header_len) % capacity;
                        size_t to_end = capacity - pong_pos;
                        if (frame.payload_len <= to_end) {
                            send_pong(buffer + pong_pos, frame.payload_len);
                        } else {
                            // Payload wraps - copy to temp buffer (RFC 6455 max 125 bytes)
                            uint8_t ping_buf[125];
                            circular_read(buffer, capacity, pong_pos, ping_buf, frame.payload_len);
                            send_pong(ping_buf, frame.payload_len);
                        }
                    } else {
                        printf("[WS] PING too large (%u bytes), ignoring\n", frame.payload_len);
                        suspicious_ctrl_count++;
                    }
                }
                else if (frame.opcode == 0x08) {  // CLOSE
                    // Read close code from circular buffer
                    uint16_t close_code = 0;
                    if (frame.payload_len >= 2) {
                        uint8_t code_bytes[2];
                        size_t code_pos = (ssl_data_pos + parse_offset + frame.header_len) % capacity;
                        circular_read(buffer, capacity, code_pos, code_bytes, 2);
                        close_code = (static_cast<uint16_t>(code_bytes[0]) << 8) |
                                     static_cast<uint16_t>(code_bytes[1]);
                    }
                    bool valid_code = (close_code >= 1000 && close_code <= 1015) ||
                                      (close_code >= 3000 && close_code <= 4999);
                    if (valid_code) {
                        printf("[WS] CLOSE: code=%u msgs=%zu\n", close_code, msg_count_);
                        connected_ = false;
                        break;
                    }
                    suspicious_ctrl_count++;
                    parse_offset += frame_len;
                    continue;
                }

                parse_offset += frame_len;
            }

            // Commit batch if we parsed any complete frames
            // Partial frames at the end stay in buffer for next SSL_read
            if (frame_count > 0) {
                size_t committed_ssl_len = parse_offset;  // SSL data actually consumed

                // Calculate padded sizes for cache alignment
                // Embedded descriptors are in header, overflow goes after SSL data
                uint16_t ssl_cls = bytes_to_cls(committed_ssl_len);
                size_t padded_ssl_len = cls_to_bytes(ssl_cls);
                size_t overflow_size = overflow_descs_size(frame_count);
                size_t total_size = HDR_SIZE + padded_ssl_len + overflow_size;

                // Verify we have space for entire cache-aligned batch
                if (total_size > rx_buffer_.writable()) {
                    // Not enough space - don't commit this batch
                    fprintf(stderr, "[ERROR] RX buffer full: need %zu bytes, available %zu. "
                            "Discarding %u frames. Consumer too slow?\n",
                            total_size, rx_buffer_.writable(), frame_count);
                    hftshm_data_written_ = 0;
                    leftover_len_ = 0;  // Can't preserve - data will be overwritten
                    leftover_pos_ = 0;
                    return true;
                }

                // Build header with embedded frame descriptors
                ShmBatchHeader hdr{};  // Zero-initialize (clears padding)
                hdr.ssl_data_len_in_CLS = ssl_cls;
                hdr.frame_count = frame_count;

                // Copy first EMBEDDED_FRAMES descriptors into header
                uint8_t embedded_count = std::min(frame_count, static_cast<uint8_t>(EMBEDDED_FRAMES));
                memcpy(hdr.embedded, frame_descs, embedded_count * sizeof(ShmFrameDesc));

                // Write overflow descriptors if any (after padded SSL data)
                uint8_t overflow_count = overflow_frame_count(frame_count);
                if (overflow_count > 0) {
                    size_t overflow_pos = (ssl_data_pos + padded_ssl_len) % capacity;
                    circular_write(buffer, capacity, overflow_pos,
                                   reinterpret_cast<uint8_t*>(frame_descs + EMBEDDED_FRAMES),
                                   overflow_count * sizeof(ShmFrameDesc));
                }

                // Write header using circular write
                circular_write(buffer, capacity, batch_pos,
                               reinterpret_cast<uint8_t*>(&hdr), HDR_SIZE);

                // Commit total cache-aligned batch size
                rx_buffer_.commit_write(total_size);
            }
            // Update leftover state for next SSL_read
            if (parse_offset < ssl_data_len) {
                // Partial frame at end - preserve for next batch
                leftover_len_ = ssl_data_len - parse_offset;
                leftover_pos_ = (ssl_data_pos + parse_offset) % capacity;
                persistent_accumulating_ = false;  // Partial frame, not fragment
                persistent_accum_len_ = 0;
            } else if (local_accumulating) {
                // Fragment incomplete - all data becomes leftover
                leftover_len_ = ssl_data_len;
                leftover_pos_ = ssl_data_pos;
                persistent_accumulating_ = true;
                persistent_opcode_ = accum_opcode;
                persistent_accum_len_ = accum_payload_len;
            } else {
                // All complete - reset leftover state
                leftover_len_ = 0;
                leftover_pos_ = 0;
                persistent_accumulating_ = false;
                persistent_accum_len_ = 0;
            }

            hftshm_data_written_ = 0;

            // Invoke callback if set
            if (batch_count_ > 0 && on_message_) {
                if (!on_message_(message_batch_, batch_count_, timing_)) {
                    return false;
                }
            }
        } else {
            // Standard mode: Read from rx_buffer_, process, commit_read
            // NOTE: Standard mode does NOT support fragmented WebSocket messages.
            // If the server sends fragmented frames, they will be skipped.
            // Use HftShm mode (USE_HFTSHM=1) for full fragment support.
            while (rx_buffer_.readable() >= 2) {
                size_t available_len = 0;
                const uint8_t* read_ptr = rx_buffer_.next_read_region(&available_len);

                if (available_len < 2) break;

                WebSocketFrame frame;
                if (!parse_websocket_frame(read_ptr, available_len, frame)) {
                    break;
                }

                if (!frame.fin || frame.opcode == 0x00) {
                    // Skip fragmented/continuation frames (standard mode limitation)
                    static bool warned = false;
                    if (!warned) {
                        fprintf(stderr, "[WARN] Fragmented WebSocket frame skipped (standard mode). "
                                "Use HftShm mode for fragment support.\n");
                        warned = true;
                    }
                    size_t skip_len = frame.header_len + frame.payload_len;
                    rx_buffer_.commit_read(skip_len);
                    continue;
                }

                if (frame.payload_len > SIZE_MAX - frame.header_len) {
                    printf("[ERROR] Frame too large\n");
                    connected_ = false;
                    break;
                }

                size_t frame_len = frame.header_len + frame.payload_len;

                if (frame.opcode == 0x09) {  // PING
                    // Binance pings contain millisecond timestamp (~13 bytes)
                    // Pings may not be sent when data is actively flowing
                    send_pong(frame.payload, frame.payload_len);
                    rx_buffer_.commit_read(frame_len);
                }
                else if (frame.opcode == 0x01 || frame.opcode == 0x02) {  // Text/Binary
                    ensure_batch_capacity();
                    message_batch_[batch_count_++] = {
                        frame.payload, frame.payload_len, rdtscp(), frame.opcode
                    };
                    msg_count_++;
                    rx_buffer_.commit_read(frame_len);
                }
                else if (frame.opcode == 0x0A) {  // PONG
                    rx_buffer_.commit_read(frame_len);
                }
                else if (frame.opcode == 0x08) {  // CLOSE
                    // Parse close frame: [2-byte status code][reason string]
                    uint16_t close_code = 0;
                    if (frame.payload_len >= 2) {
                        close_code = (static_cast<uint16_t>(frame.payload[0]) << 8) |
                                     static_cast<uint16_t>(frame.payload[1]);
                    }
                    // Standard close codes: 1000-1015, 3000-4999
                    bool likely_valid = (close_code >= 1000 && close_code <= 1015) ||
                                        (close_code >= 3000 && close_code <= 4999);
                    printf("[WS] CLOSE: code=%u msgs=%zu valid=%d reason=%.*s\n",
                           close_code, msg_count_, likely_valid,
                           frame.payload_len > 2 ? (int)(frame.payload_len - 2) : 0,
                           frame.payload_len > 2 ? reinterpret_cast<const char*>(frame.payload + 2) : "");
                    connected_ = false;
                    rx_buffer_.commit_read(frame_len);
                    break;
                }
                else {
                    printf("[WARN] Unknown opcode: 0x%02X\n", frame.opcode);
                    rx_buffer_.commit_read(frame_len);
                }
            }

            if (batch_count_ > 0 && on_message_) {
                if (!on_message_(message_batch_, batch_count_, timing_)) {
                    return false;
                }
            }
        }
        return true;
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
    // Access to TX buffer for external writes (e.g., sending SUBSCRIBE commands)
    // Non-const version allows writing to buffer
    TxBufferPolicy_& get_tx_buffer_mut() { return tx_buffer_; }

    // Set wait timeout for event loop (required when using TX buffer for sending)
    // Without timeout, wait() blocks indefinitely and drain_tx_buffer() never runs
    void set_wait_timeout(int ms) {
        transport_.set_wait_timeout(ms);
    }

    // Set external stop flag for graceful shutdown (Ctrl+C handling)
    // When flag becomes false, run() loop exits on next iteration
    void set_stop_flag(volatile bool* flag) {
        stop_flag_ = flag;
    }

    // Set on_close callback for reconnection handling
    // Callback is invoked when connection closes; return true to reconnect
    void set_on_close(std::function<bool()> cb) {
        on_close_ = cb;
    }

    // Set on_connect callback to populate subscription messages
    // Callback receives: (subscribe_messages_ array, num_subscribe_messages_ ref)
    // Called after connect() and after each reconnect
    void set_on_connect(std::function<void(char(*)[512], size_t&)> cb) {
        on_connect_ = cb;
    }

    // Access to transport for advanced configuration (e.g., XDP init, stats)
    TransportPolicy_& transport() { return transport_; }
    const TransportPolicy_& transport() const { return transport_; }

private:
    // SFINAE helper to detect if TxBufferPolicy_ has is_hftshm trait
    template<typename T, typename = void>
    struct has_is_hftshm : std::false_type {};

    template<typename T>
    struct has_is_hftshm<T, std::void_t<decltype(T::is_hftshm)>> : std::true_type {};

    // Enable TX outbox if buffer is HftShm type
    void enable_hftshm_tx_outbox() {
        if constexpr (has_is_hftshm<TxBufferPolicy_>::value) {
            if (TxBufferPolicy_::is_hftshm) {
                tx_outbox_enabled_ = true;
                tx_opcode_ = 0x01;  // Text by default
            }
        }
    }

    // Ensure message_batch_ has capacity for at least one more message
    // Doubles capacity when full (amortized O(1) per message)
    void ensure_batch_capacity() {
        if (batch_count_ >= message_batch_capacity_) {
            size_t new_capacity = message_batch_capacity_ * 2;
            MessageInfo* new_batch = new MessageInfo[new_capacity];
            memcpy(new_batch, message_batch_, batch_count_ * sizeof(MessageInfo));
            delete[] message_batch_;
            message_batch_ = new_batch;
            message_batch_capacity_ = new_capacity;
            fprintf(stderr, "[WARN] message_batch_ resized to %zu (>%zu frames in single batch)\n",
                    new_capacity, batch_count_);
        }
    }

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

    // Batch message collection (dynamically resizable)
    static constexpr size_t INITIAL_BATCH_CAPACITY = 256;
    size_t message_batch_capacity_ = INITIAL_BATCH_CAPACITY;
    MessageInfo* message_batch_ = nullptr;
    size_t batch_count_ = 0;

    // Graceful shutdown support
    volatile bool* stop_flag_ = nullptr;

    // HftShm circular buffer state (only used when uses_hftshm is true)
    size_t hftshm_batch_start_pos_ = 0;   // Logical write position where current batch starts
    size_t hftshm_data_written_ = 0;       // Bytes of SSL data written in current batch (not yet committed)

    // Unified leftover state (partial frames AND fragments across SSL_reads)
    size_t leftover_len_ = 0;              // Bytes of partial/incomplete data at batch end
    size_t leftover_pos_ = 0;              // Circular buffer position where leftover bytes start
    bool persistent_accumulating_ = false; // Fragment accumulation in progress
    uint8_t persistent_opcode_ = 0;        // Opcode of incomplete fragment (0x01=text, 0x02=binary)
    size_t persistent_accum_len_ = 0;      // Total accumulated payload length so far

    // Reconnection support
    std::string host_;
    std::string path_;
    uint16_t port_ = 0;
    std::function<bool()> on_close_;  // Returns true to reconnect

    // Subscription messages - populated by on_connect callback, sent automatically
    char subscribe_messages_[128][512];       // Max 128 messages, 512 bytes each
    size_t num_subscribe_messages_ = 0;       // Count set by callback
    bool subscribe_messages_sent_ = false;    // Flag: true after all sent
    std::function<void(char(*)[512], size_t&)> on_connect_;  // Callback to populate subscribe_messages_
};
