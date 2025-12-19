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

// Debug printing - enable with -DDEBUG
#ifdef DEBUG
#define DEBUG_PRINT(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)
#define DEBUG_FPRINTF(...) do { fprintf(__VA_ARGS__); fflush(stderr); } while(0)
#else
#define DEBUG_PRINT(...) ((void)0)
#define DEBUG_FPRINTF(...) ((void)0)
#endif

#include "ws_policies.hpp"
#include "core/timing.hpp"
#include "core/http.hpp"
#include "ringbuffer.hpp"  // Unified ringbuffer with batch format
#include "policy/simulator_transport.hpp"  // Simulator transport for replay
#include <functional>
#include <limits>
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

// Shared memory batch types included in ringbuffer.hpp

// ============================================================================
// Compile-Time Debug Flag
// ============================================================================
// Use `if constexpr (websocket::debug_enabled)` instead of `#ifdef DEBUG`

namespace websocket {

// Compile-time debug flag - use if constexpr (debug_enabled) instead of #ifdef DEBUG
#ifndef WEBSOCKET_DEBUG_ENABLED_DEFINED
#define WEBSOCKET_DEBUG_ENABLED_DEFINED
constexpr bool debug_enabled =
#ifdef DEBUG
    true;
#else
    false;
#endif
#endif

} // namespace websocket

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

// ============================================================================
// Compile-Time Conditional Callback State (MessageBatchState)
// ============================================================================
// - PrivateWebSocketClient: MessageBatchState<true> holds callback + message_batch_[MAX_FRAMES]
// - ShmWebSocketClient: MessageBatchState<false> empty struct (0 bytes)

namespace callback {

// MAX_FRAMES derived from ShmBatchHeader::frame_count type (uint16_t → max 65535)
inline constexpr size_t MAX_FRAMES =
    std::numeric_limits<decltype(ShmBatchHeader::frame_count)>::max();

// Batch message callback type
// timing_record_t contains batch-level SSL timing, MessageInfo has per-message parse_cycle
// Returns: true to continue receiving, false to exit run() loop
using MessageCallback = std::function<bool(const MessageInfo*, size_t, const timing_record_t&)>;

// Primary template: disabled callback (ShmWebSocketClient)
template<bool Enable>
struct MessageBatchState {
    // Empty - no callback or message_batch_ allocation
    void reset() {}
    bool has_callback() const { return false; }
    void set_callback(MessageCallback) {}  // No-op
    void add_message(const uint8_t*, uint32_t, uint64_t, uint8_t) {}  // No-op
    bool invoke_callback(const timing_record_t&) { return true; }
};

// Specialization: enabled callback (PrivateWebSocketClient)
template<>
struct MessageBatchState<true> {
    MessageCallback on_message_;
    MessageInfo message_batch_[MAX_FRAMES];  // ~2MB pre-allocated (65535 × 32B)
    size_t batch_count_ = 0;

    void reset() { batch_count_ = 0; }
    bool has_callback() const { return static_cast<bool>(on_message_); }
    void set_callback(MessageCallback cb) { on_message_ = std::move(cb); }

    void add_message(const uint8_t* payload, uint32_t len, uint64_t parse_cycle, uint8_t opcode) {
        message_batch_[batch_count_++] = { payload, len, parse_cycle, opcode };
    }

    bool invoke_callback(const timing_record_t& timing) {
        if (batch_count_ > 0 && on_message_) {
            bool result = on_message_(message_batch_, batch_count_, timing);
            batch_count_ = 0;  // Reset for next batch
            return result;
        }
        return true;  // No callback or no messages - continue
    }
};

} // namespace callback
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

// Forward declare SimulatorTransport for trait specialization
namespace websocket { namespace transport { struct SimulatorTransport; } }

// Explicit specialization: SimulatorTransport is NOT fd-based (replay from file)
namespace websocket { namespace traits {
template<>
struct is_fd_based_transport<websocket::transport::SimulatorTransport, void> : std::false_type {};
} }

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

    // Compile-time detection for TX buffer (RX unified - no branching needed)
    static constexpr bool uses_hftshm_tx = TxBufferPolicy_::is_hftshm;

    // Detect NullBuffer policy (TX disabled at compile-time)
    // NullBuffer::is_null_buffer = true, other buffers don't have this trait
    template<typename T, typename = void>
    struct get_is_null_buffer : std::false_type {};
    template<typename T>
    struct get_is_null_buffer<T, std::void_t<decltype(T::is_null_buffer)>>
        : std::bool_constant<T::is_null_buffer> {};

    // TX outbox supported: false when TxBufferPolicy is NullBuffer
    static constexpr bool is_null_tx_buffer = get_is_null_buffer<TxBufferPolicy_>::value;
    static constexpr bool tx_outbox_supported = !is_null_tx_buffer;

    // Replay mode: SimulatorTransport replays recorded traffic (no real network)
    static constexpr bool is_replay_mode =
        websocket::transport::is_simulator_transport_v<TransportPolicy_>;

    // Buffer mode detection (unified HftShmRingBuffer provides these traits)
    // - is_private: true for PrivateRingBuffer, false for ShmRxBuffer
    // - uses_runtime_path: true for ShmRxBuffer, false for PrivateRingBuffer
    static constexpr bool uses_private_buffer = RxBufferPolicy_::is_private;
    static constexpr bool requires_runtime_path = !uses_private_buffer;

    // Compile-time callback control: only PrivateWebSocketClient gets callback + message_batch_
    static constexpr bool enables_callback = uses_private_buffer;

    // Class-level constants (derived from ShmBatchHeader types)
    static constexpr size_t MAX_FRAMES =
        std::numeric_limits<decltype(ShmBatchHeader::frame_count)>::max();  // 65535
    static constexpr size_t HDR_SIZE = sizeof(ShmBatchHeader);  // = CACHE_LINE_SIZE

    // WebSocket frame header constants (RFC 6455)
    static constexpr size_t MAX_WS_HEADER_SIZE = 14;    // 2 base + 8 ext len + 4 mask
    static constexpr uint8_t WS_PAYLOAD_LEN_16BIT = 126;  // Extended 16-bit length follows
    static constexpr uint8_t WS_PAYLOAD_LEN_64BIT = 127;  // Extended 64-bit length follows
    static constexpr size_t WS_HEADER_BASE = 2;         // Minimum header (opcode + len7)
    static constexpr size_t WS_HEADER_16BIT = 4;        // 2 base + 2 ext len
    static constexpr size_t WS_HEADER_64BIT = 10;       // 2 base + 8 ext len

    // HTTP header customization support
    using HeaderMap = std::vector<std::pair<std::string, std::string>>;

    // Use callback types from websocket::callback namespace
    using MessageCallback = websocket::callback::MessageCallback;
    template<bool Enable>
    using MessageBatchState = websocket::callback::MessageBatchState<Enable>;

    // Constructor with optional shared memory path
    // Two buffer modes (based on RxBufferPolicy template parameter):
    // - PrivateRingBuffer: allocates private memory, on_messages() ENABLED
    // - ShmRxBuffer: opens hft-shm files at rx_shmem_path, on_messages() DISABLED
    WebSocketClient(const char* rx_shmem_path = nullptr)
        : connected_(false)
        , msg_count_(0)
    {
        try {
            if constexpr (uses_private_buffer) {
                // Private mode: allocate private memory
                rx_buffer_.init();
            } else {
                // Shared mode: requires runtime path to hft-shm files
                if (!rx_shmem_path) {
                    throw std::runtime_error("Shared mode requires rx_shmem_path");
                }
                rx_buffer_.init(rx_shmem_path);
                // Reset sequences to clear stale state from previous runs
                rx_buffer_.reset();
            }
        } catch (const std::runtime_error& e) {
            throw std::runtime_error(
                "RX buffer init failed: " + std::string(e.what()));
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
    }

    ~WebSocketClient() {
        disable_debug_traffic();  // Close debug file if open
        disconnect();
    }

    // Connect to WebSocket server with optional custom HTTP headers
    // For XDP mode: call transport_.init(interface, bpf_path, domain, port) before connect()
    void connect(const char* host, uint16_t port, const char* path,
                 const HeaderMap& custom_headers = {}) {
        // Compile-time constant for transport type dispatch
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        // 1. Initialize transport (BSD sockets only - XDP must call transport_.init() before connect)
        if constexpr (is_fd_based) {
            transport_.init();
        }
        // XDP mode: transport_.init() must be called before connect() with 4 args

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
        if constexpr (is_fd_based) {
            // BSD socket: use fd-based handshake (supports kTLS)
            int fd = transport_.get_fd();
            ssl_.handshake(fd);
        } else {
            // XDP/Userspace: use userspace transport BIO
            ssl_.handshake_userspace_transport(&transport_);
        }

        // 5. Report TLS mode (compile-time optimized)
        if constexpr (is_fd_based) {
            if (transport_.supports_ktls() && ssl_.ktls_enabled()) {
                DEBUG_PRINT("[KTLS] Kernel TLS offload active\n");
            } else {
                DEBUG_PRINT("[TLS] Standard user-space TLS mode\n");
            }
        } else {
            // Userspace transports never support kTLS
            DEBUG_PRINT("[TLS] Standard user-space TLS mode (userspace transport)\n");
        }

        // 6. HTTP upgrade to WebSocket (skip in replay mode - data is post-handshake)
        if constexpr (!is_replay_mode) {
            send_http_upgrade(host, path, custom_headers);
            recv_http_response();
        }

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

#ifdef DEBUG
        // Record connection start time for duration tracking
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        connect_time_ns_ = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif

        DEBUG_PRINT("[WS] Connected to %s:%d%s\n", host, port, path);

        // Invoke on_connect callback to populate subscription messages (inlined)
        num_subscribe_messages_ = 0;
        subscribe_messages_sent_ = false;
        if (on_connect_) {
            on_connect_(subscribe_messages_, num_subscribe_messages_);
        }
    }

public:

    // Set message callback (can be used before run())
    void set_message_callback(MessageCallback callback) {
        if constexpr (enables_callback) {
            msg_state_.set_callback(callback);
        }
    }

    // Main event loop - runs until disconnected
    // If on_close callback is set and returns true, will reconnect automatically
    void run(MessageCallback on_message) {
        // Compile-time constant for transport type dispatch
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        if constexpr (enables_callback) {
            // Only overwrite if a callback is provided (allows pre-set callback via set_message_callback)
            if (on_message) {
                msg_state_.set_callback(on_message);
            }
        }

        while (true) {  // Outer reconnect loop
            // Inner event loop
            while (connected_ && (!stop_flag_ || *stop_flag_)) {
                // Wait for events (epoll/select/io_uring for BSD, busy-poll for XDP)
                // If set_wait_timeout() was called, wait() will respect the timeout
                DEBUG_PRINT("[WAIT-ENTER] transport_.wait()\n");
                int ready = transport_.wait();
                DEBUG_PRINT("[WAIT-EXIT] transport_.wait() returned %d\n", ready);

                if (ready <= 0) {
                    // For replay mode: wait() returns 0 when file exhausted, exit loop
                    if constexpr (is_replay_mode) {
                        connected_ = false;
                        break;
                    }
                    // Check if transport disconnected (SimulatorTransport sets this on EOF/error)
                    if (!transport_.is_connected()) {
                        DEBUG_PRINT("[WS] Transport disconnected, exiting event loop\n");
                        connected_ = false;
                        break;
                    }
                    // Track consecutive timeouts - detect dead connection
                    consecutive_timeouts_++;
                    if (consecutive_timeouts_ >= NO_DATA_TIMEOUT_COUNT) {
                        DEBUG_PRINT("[WS] No data for %d consecutive timeouts (%d seconds), disconnecting\n",
                                   consecutive_timeouts_, consecutive_timeouts_);
                        connected_ = false;
                        break;
                    }
                    // Timeout - just handle TX (SSL buffer draining now in recv_into_buffer)
                    send_subscribe_messages();
                    drain_tx_buffer();
                    continue;
                }
                // Reset timeout counter on successful wait
                consecutive_timeouts_ = 0;

                // For BSD sockets: verify ready fd and drain HW timestamps (compile-time dispatch)
                if constexpr (is_fd_based) {
                    int fd = transport_.get_fd();
                    int ready_fd = transport_.get_ready_fd();
                    if (ready_fd != fd) continue;

                    // Check for socket errors (EPOLLHUP/EPOLLERR) - connection died
                    if (transport_.is_error()) {
                        DEBUG_PRINT("[WS] Socket error detected (EPOLLHUP/EPOLLERR), disconnecting\n");
                        connected_ = false;
                        break;
                    }

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

                // Read data into ring buffer and process frames
                // recv_into_buffer() now loops with SSL_pending() and calls process_frames() internally
                if (!recv_into_buffer()) {
                    break;  // Connection closed, callback stop, or error
                }

                // Send subscriptions then drain TX outbox after processing RX
                send_subscribe_messages();
                drain_tx_buffer();
            }

            DEBUG_PRINT("[WS] Event loop terminated\n");

            // Check for reconnection: invoke on_close if set, reconnect if it returns true
            // Skip reconnect in debug mode to preserve traffic log for analysis
#ifdef DEBUG
            DEBUG_PRINT("[DEBUG] Reconnect disabled in debug mode - analyze debug_traffic.dat\n");
            break;
#endif
            if (on_close_ && on_close_() && (!stop_flag_ || *stop_flag_)) {
                DEBUG_PRINT("[WS] Reconnecting...\n");
                // Clean up old connection before reconnecting
                disconnect();
                try {
                    connect(host_.c_str(), port_, path_.c_str());
                    continue;  // Resume event loop
                } catch (const std::exception& e) {
                    DEBUG_PRINT("[WS] Reconnect failed: %s\n", e.what());
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
            // Reset batch state to avoid stale data on reconnect
            batch_start_pos_ = 0;
            data_written_ = 0;
            // Reset fragment and PONG state for clean reconnection
            persistent_accumulating_ = false;
            persistent_opcode_ = 0;
            persistent_accum_len_ = 0;
            persistent_parse_offset_ = 0;
            persistent_frame_count_ = 0;
            deferred_pending_ = false;
            pending_pong_count_ = 0;
            DEBUG_PRINT("[WS] Disconnected\n");
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
    // UNIFIED CODEPATH: All buffer types use same batch format
    // Loops with SSL_pending() to drain any buffered TLS data
    // Deferred commit mode: accumulates data across SSL_reads until no partial frame
    bool recv_into_buffer() {
        // Compile-time constant for transport type dispatch
        constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy_>;

        // Stage 3: Record timestamp before SSL_read/recv
        timing_.recv_start_cycle = rdtsc();

        size_t min_needed = HDR_SIZE + CACHE_LINE_SIZE + CACHE_LINE_SIZE;

        // Loop to drain all available data (SSL buffer + socket)
        while (true) {
            // XDP mode: Poll transport to process pending XDP RX frames
            // This is critical - XDP frames sit in the ring until poll() is called
            // The integration test calls transport.poll() before every ssl.read()
            if constexpr (!is_fd_based) {
                transport_.poll();
            }

            // Get circular buffer info
            uint8_t* buffer = rx_buffer_.buffer_base();
            size_t capacity = rx_buffer_.buffer_capacity();

            // Check if we have uncommitted data from previous read (deferred commit)
            size_t ssl_write_pos;
            size_t data_available;

            if (data_written_ > 0) {
                // Continue accumulating - append to existing uncommitted batch
                ssl_write_pos = (batch_start_pos_ + HDR_SIZE + data_written_) % capacity;
                // Calculate available space from current write pos to buffer end or writable limit
                size_t total_writable = rx_buffer_.writable();
                if (total_writable < CACHE_LINE_SIZE) {
                    DEBUG_PRINT("[BUFFER-FULL] recv_into_buffer: waiting for consumer | shmem batch_start=%zu data_written=%zu writable=%zu cap=%zu\n",
                           batch_start_pos_, data_written_, total_writable, capacity);
                    break;  // Buffer full, wait for consumer
                }
                data_available = total_writable - CACHE_LINE_SIZE;
            } else {
                // Fresh batch - start new batch header position
                size_t total_writable = rx_buffer_.writable();
                if (total_writable < min_needed) {
                    DEBUG_PRINT("[BUFFER-FULL] recv_into_buffer: waiting for consumer (fresh) | shmem writable=%zu need=%zu cap=%zu\n",
                           total_writable, min_needed, capacity);
                    break;  // Buffer full, wait for consumer
                }
                size_t write_pos = rx_buffer_.current_write_pos();
                batch_start_pos_ = write_pos;
                ssl_write_pos = (write_pos + HDR_SIZE) % capacity;
                data_available = total_writable - HDR_SIZE - CACHE_LINE_SIZE;
            }

            // SSL_read into circular buffer (after leftover)
            size_t to_end = capacity - ssl_write_pos;
            ssize_t n = 0;

            DEBUG_PRINT("[SSL-ENTER] ssl_.read() avail=%zu to_end=%zu pos=%zu\n",
                   data_available, to_end, ssl_write_pos);

            if (data_available <= to_end) {
                n = ssl_.read(buffer + ssl_write_pos, data_available);
                DEBUG_PRINT("[SSL-EXIT] ssl_.read() returned %zd\n", n);
            } else {
                n = ssl_.read(buffer + ssl_write_pos, to_end);
                DEBUG_PRINT("[SSL-EXIT] ssl_.read() returned %zd (first part)\n", n);
                if (n == static_cast<ssize_t>(to_end)) {
                    DEBUG_PRINT("[SSL-ENTER] ssl_.read() wrap-around part\n");
                    ssize_t n2 = ssl_.read(buffer, data_available - to_end);
                    DEBUG_PRINT("[SSL-EXIT] ssl_.read() returned %zd (wrap part)\n", n2);
                    if (n2 > 0) n += n2;
                }
            }

            if (n > 0) {
                // Accumulate data (may span multiple SSL_reads until batch commits)
                data_written_ += static_cast<size_t>(n);
                timing_.recv_end_cycle = rdtscp();
                timing_.ssl_read_bytes = n;

                // Debug traffic recording - write raw SSL data to file
                if constexpr (websocket::debug_enabled && !is_replay_mode) {
                    transport_.write_record(buffer, ssl_write_pos, n, capacity, data_written_);
                }

                // Peek at first 4 bytes to show frame header info (including extended length)
#ifdef DEBUG
                // Debug: log EVERY SSL_read with full state for tracing stuck situations
                static uint64_t ssl_read_count = 0;
                ssl_read_count++;
                bool is_accumulating = (data_written_ > static_cast<size_t>(n));  // Had prior data

                uint8_t peek_byte0 = buffer[ssl_write_pos];
                uint8_t peek_byte1 = (n > 1) ? buffer[(ssl_write_pos + 1) % capacity] : 0;
                uint8_t peek_byte2 = (n > 2) ? buffer[(ssl_write_pos + 2) % capacity] : 0;
                uint8_t peek_byte3 = (n > 3) ? buffer[(ssl_write_pos + 3) % capacity] : 0;
                const char* state_str = is_accumulating ? "ACCUM" : "FRESH";

                // Also peek at batch start position (for FRESH) to verify buffer contents
                size_t data_pos = (batch_start_pos_ + HDR_SIZE) % capacity;
                uint8_t batch_byte0 = buffer[data_pos];
                uint8_t batch_byte1 = buffer[(data_pos + 1) % capacity];
                uint8_t batch_byte2 = buffer[(data_pos + 2) % capacity];
                uint8_t batch_byte3 = buffer[(data_pos + 3) % capacity];

                DEBUG_PRINT("[SSL-READ#%lu] %s +%zd bytes @%zu, total=%zu | batch[%zu] cap=%zu | write=[%02x %02x %02x %02x] batch_data=[%02x %02x %02x %02x] pending=%zu\n",
                       ssl_read_count, state_str, n, ssl_write_pos, data_written_,
                       batch_start_pos_, capacity,
                       peek_byte0, peek_byte1, peek_byte2, peek_byte3,
                       batch_byte0, batch_byte1, batch_byte2, batch_byte3,
                       (size_t)ssl_.pending());

                // MISMATCH CHECK: For FRESH reads, write bytes should match batch_data
                // If they differ, something is wrong (memory corruption, race condition)
                if (!is_accumulating && data_pos == ssl_write_pos) {
                    if (peek_byte0 != batch_byte0 || peek_byte1 != batch_byte1 ||
                        peek_byte2 != batch_byte2 || peek_byte3 != batch_byte3) {
                        DEBUG_PRINT("[CORRUPTION!] write=[%02x %02x %02x %02x] != batch_data=[%02x %02x %02x %02x] at pos %zu\n",
                               peek_byte0, peek_byte1, peek_byte2, peek_byte3,
                               batch_byte0, batch_byte1, batch_byte2, batch_byte3, ssl_write_pos);
                    }
                }
#endif

                // Process frames immediately
                if (!process_frames()) {
                    return false;  // Callback requested stop or connection closed
                }

                // Check if more data buffered in SSL - if so, loop to drain it
                if (ssl_.pending() == 0) {
                    break;  // No more buffered data
                }
                // Continue loop to drain SSL buffer
            } else if (n == 0) {
                // Connection closed by server (no WebSocket CLOSE frame)
#ifdef DEBUG
                struct timespec ts_close;
                clock_gettime(CLOCK_MONOTONIC, &ts_close);
                uint64_t now_ns = ts_close.tv_sec * 1000000000ULL + ts_close.tv_nsec;
                uint64_t duration_ns = now_ns - connect_time_ns_;
                uint64_t duration_sec = duration_ns / 1000000000ULL;
                DEBUG_PRINT("[RECV] Server closed connection (SSL_read=0) duration=%lus msgs=%zu uncommitted=%zu\n",
                       duration_sec, msg_count_, data_written_);
#endif
                timing_.recv_end_cycle = rdtscp();
                timing_.ssl_read_bytes = 0;
                connected_ = false;
                return false;
            } else {
                // WANT_READ/WANT_WRITE - no more data available
                timing_.recv_end_cycle = rdtscp();
                timing_.ssl_read_bytes = 0;
                break;
            }
        }

        return true;
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
            uint8_t header[MAX_WS_HEADER_SIZE];
            size_t header_len = build_websocket_header_zerocopy(header, msg_len, 0x01);

            // Record TX for debug (combine header + payload for analysis)
            if constexpr (websocket::debug_enabled && !is_replay_mode) {
                uint8_t tx_frame[1024];
                if (header_len + msg_len <= sizeof(tx_frame)) {
                    memcpy(tx_frame, header, header_len);
                    memcpy(tx_frame + header_len, subscribe_messages_[i], msg_len);
                    transport_.write_tx_record(tx_frame, header_len + msg_len);
                }
            }

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

        // TX outbox disabled at compile-time when TxBufferPolicy is NullBuffer
        if constexpr (!tx_outbox_supported) {
            return;  // Compile-time elimination
        }

        while (tx_buffer_.readable() > 0) {
            size_t payload_len = 0;
            const uint8_t* payload = tx_buffer_.next_read_region(&payload_len);
            if (!payload || payload_len == 0) break;

            // Zero-copy TX: Build header only, send header + raw payload separately
            // mask=0 means payload XOR 0 = payload, no transformation needed
            uint8_t header[MAX_WS_HEADER_SIZE];  // Max: 2 base + 8 ext len + 4 mask
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
                DEBUG_PRINT("[WARN] TX header sent but payload failed\n");
                break;
            }
        }
    }

    // Process WebSocket frames from ring buffer
    // Returns: true to continue, false if callback requested stop
    // Process WebSocket frames from ring buffer
    // UNIFIED CODEPATH: All buffer types use same batch format
    // Returns: true to continue, false if callback requested stop
    bool process_frames() {
        using namespace websocket::http;

        // Reset batch for this processing round
        if constexpr (enables_callback) {
            msg_state_.reset();  // Reset batch_count_ to 0
        }

        // Circular buffer mode: Parse frames with circular access
        // Format: [ShmBatchHeader (CLS)][raw_ssl_data padded (N*CLS)][ShmFrameDesc[] padded (M*CLS)]
        // Data may wrap around buffer boundary seamlessly
        if (data_written_ == 0) return true;

        uint8_t* buffer = rx_buffer_.buffer_base();
        size_t capacity = rx_buffer_.buffer_capacity();
        size_t batch_pos = batch_start_pos_;
        size_t ssl_data_pos = (batch_pos + HDR_SIZE) % capacity;
        size_t ssl_data_len = data_written_;

        // Frame descriptors: embedded written directly to header, overflow written directly to shm
        // No local array needed - write descriptors directly to shared memory
        // Direct pointer to header (already reserved at batch_pos)
        ShmBatchHeader* hdr = reinterpret_cast<ShmBatchHeader*>(buffer + batch_pos);
        ShmFrameDesc* embedded = hdr->embedded;
        uint16_t frame_count = persistent_frame_count_;  // Resume from deferred state
        uint16_t suspicious_ctrl_count = 0;  // Track likely frame misalignment

        // Batch opcode: first data frame's opcode, warn on mismatch
        uint8_t batch_opcode = batch_opcode_;  // Resume from deferred state (0 if fresh batch)

        // Resume parsing from where we left off (deferred commit case)
        size_t parse_offset = persistent_parse_offset_;

        // Restore persistent fragment state (if any)
        bool local_accumulating = persistent_accumulating_;
        uint8_t accum_opcode = persistent_opcode_;
        size_t accum_payload_len = persistent_accum_len_;
        uint32_t accum_payload_start = 0;  // Leftover always starts at offset 0

        while (parse_offset + WS_HEADER_BASE <= ssl_data_len && frame_count < MAX_FRAMES) {
            // Read frame header from circular buffer
            uint8_t header_bytes[MAX_WS_HEADER_SIZE];
            size_t header_pos = (ssl_data_pos + parse_offset) % capacity;
            size_t remaining = ssl_data_len - parse_offset;
            size_t peek_len = std::min(MAX_WS_HEADER_SIZE, remaining);
            circular_read(buffer, capacity, header_pos, header_bytes, peek_len);

            WebSocketFrame frame;
            // Pass 'remaining' as available length so parse_websocket_frame can check
            // if the full frame (header + payload) fits in the available data
            if (!parse_websocket_frame(header_bytes, remaining, frame)) {
#ifdef DEBUG
                // Debug: show WHY parsing stopped (incomplete frame)
                uint64_t peek_payload_len = header_bytes[1] & 0x7F;
                size_t expected_hdr = WS_HEADER_BASE;
                if (peek_payload_len == WS_PAYLOAD_LEN_16BIT) { expected_hdr = WS_HEADER_16BIT; peek_payload_len = (header_bytes[2] << 8) | header_bytes[3]; }
                else if (peek_payload_len == WS_PAYLOAD_LEN_64BIT) { expected_hdr = WS_HEADER_64BIT; }
                DEBUG_PRINT("[PARSE-INCOMPLETE] @%zu/%zu: need frame hdr=%zu+payload=%lu, have %zu bytes | hdr[0:1]=%02x %02x\n",
                       parse_offset, ssl_data_len, expected_hdr, (unsigned long)peek_payload_len, remaining,
                       header_bytes[0], header_bytes[1]);
#endif
                break;  // Incomplete frame header or payload
            }

            size_t frame_len = frame.header_len + frame.payload_len;
            if (parse_offset + frame_len > ssl_data_len) {
                DEBUG_PRINT("[PARSE-INCOMPLETE] @%zu/%zu: frame_len=%zu exceeds remaining=%zu\n",
                       parse_offset, ssl_data_len, frame_len, ssl_data_len - parse_offset);
                break;  // Incomplete frame
            }

#ifdef DEBUG
            // Debug: show each frame parsed with raw header bytes for diagnosis
            size_t this_frame_total = frame.header_len + frame.payload_len;
            DEBUG_PRINT("[FRAME#%u] op=%02x fin=%d hdr=%zu payload=%zu total=%zu @%zu | batch_pos=%zu | raw=[%02x %02x %02x %02x] pos=%zu\n",
                   frame_count, frame.opcode, frame.fin, frame.header_len, frame.payload_len, this_frame_total,
                   parse_offset, batch_start_pos_,
                   header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3], header_pos);

            // Sanity check: if first frame and its total doesn't match SSL data, we may have a misparse
            // This catches the case where payload length was incorrectly read (e.g., 200 instead of 264)
            if (frame_count == 0 && this_frame_total < ssl_data_len) {
                size_t leftover = ssl_data_len - this_frame_total;
                // Check if leftover looks like a valid frame start (0x8X for fin=1, data)
                size_t leftover_pos = (ssl_data_pos + this_frame_total) % capacity;
                uint8_t leftover_byte0 = buffer[leftover_pos];
                uint8_t leftover_byte1 = buffer[(leftover_pos + 1) % capacity];
                // If leftover starts with JSON data ('{', '[', or numbers), we might have misaligned
                // A real frame should start with 0x8X (fin=1 + opcode) or 0x0X (continuation)
                if (leftover_byte0 >= 0x20 && leftover_byte0 < 0x80 && leftover_byte0 != 0x00) {
                    DEBUG_PRINT("[MISALIGN-WARN] Frame#0 ends at %zu but %zu bytes remain; leftover starts with [%02x %02x] (ASCII?)\n",
                           this_frame_total, leftover, leftover_byte0, leftover_byte1);
                }
            }
#endif

            // For circular payloads, update frame.payload to point into buffer
            // Note: This pointer may only be valid for first part if wrap occurs
            size_t payload_pos = (ssl_data_pos + parse_offset + frame.header_len) % capacity;
            frame.payload = buffer + payload_pos;

            // Debug: Log ALL control frames with header bytes for diagnosis
            if (frame.opcode >= 0x08) {
                // Reserved opcodes (0x0B-0x0F) indicate misalignment
                bool is_reserved = (frame.opcode >= 0x0B && frame.opcode <= 0x0F);
                // Unsolicited PONG (0x0A) is suspicious - we don't send PINGs
                bool is_unsolicited_pong = (frame.opcode == 0x0A);
                bool is_suspicious = is_reserved || is_unsolicited_pong;

                // Always log control frames with full context
                DEBUG_PRINT("[WS-CTRL] op=0x%02x len=%zu offset=%zu/%zu hdr_len=%zu%s\n",
                       frame.opcode, frame.payload_len, parse_offset, ssl_data_len,
                       frame.header_len, is_suspicious ? " [SUSPICIOUS]" : "");
                DEBUG_PRINT("[WS-CTRL] header: ");
                for (size_t i = 0; i < std::min(MAX_WS_HEADER_SIZE, ssl_data_len - parse_offset); i++) {
                    DEBUG_PRINT("%02x ", header_bytes[i]);
                }
                DEBUG_PRINT("\n");

                if (is_suspicious) {
                    suspicious_ctrl_count++;
                    if (suspicious_ctrl_count >= 3) {
                        DEBUG_PRINT("[WS-WARNING] Suspicious frames (%u), continuing processing...\n",
                               suspicious_ctrl_count);
                        // Continue processing - don't break. Allow recovery from temporary misalignment.
                    }
                }
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
                            // Track batch opcode (first data frame, warn on mismatch)
                            if (frame_count == 0) {
                                batch_opcode = accum_opcode;
                            } else if (accum_opcode != batch_opcode) {
                                fprintf(stderr, "[WARN] Mixed opcodes in batch: 0x%02x vs 0x%02x\n",
                                        batch_opcode, accum_opcode);
                            }

                            // Write descriptor directly to shm (embedded or overflow)
                            if (frame_count < EMBEDDED_FRAMES) {
                                embedded[frame_count].payload_start = payload_start;
                                embedded[frame_count].payload_len = payload_len;
                            } else {
                                // Overflow region: use bit shifts for fast addressing
                                size_t overflow_idx = frame_count - EMBEDDED_FRAMES;
                                if (using_deferred_frame_descs_) {
                                    // Writing to deferred buffer (during deferred state)
                                    deferred_frame_descs_[overflow_idx] = {payload_start, payload_len};
                                } else {
                                    // Calculate padded SSL length for overflow position
                                    size_t padded_ssl_len = cls_to_bytes(bytes_to_cls(ssl_data_len));
                                    size_t overflow_cls_idx = overflow_idx >> DESCS_PER_CLS_SHIFT;
                                    size_t overflow_cls_pos = (ssl_data_pos + padded_ssl_len + (overflow_cls_idx << CLS_SHIFT)) % capacity;
                                    ShmFrameDesc* overflow_cls = reinterpret_cast<ShmFrameDesc*>(buffer + overflow_cls_pos);
                                    overflow_cls[overflow_idx & DESCS_PER_CLS_MASK] = {payload_start, payload_len};
                                }
                            }
                            frame_count++;
                            msg_count_++;

                            // Collect for callback (circular pointer)
                            if constexpr (enables_callback) {
                                size_t cb_payload_pos = (ssl_data_pos + payload_start) % capacity;
                                msg_state_.add_message(
                                    buffer + cb_payload_pos, accum_payload_len,
                                    rdtscp(), accum_opcode
                                );
                            }
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
                    DEBUG_PRINT("[ERROR] Frame offset out of bounds: start=%u len=%u ssl_len=%zu\n",
                           payload_start, payload_len, ssl_data_len);
                    break;
                }

                // Track batch opcode (first data frame, warn on mismatch)
                if (frame_count == 0) {
                    batch_opcode = frame.opcode;
                } else if (frame.opcode != batch_opcode) {
                    fprintf(stderr, "[WARN] Mixed opcodes in batch: 0x%02x vs 0x%02x\n",
                            batch_opcode, frame.opcode);
                }

                // Write descriptor directly to shm (embedded or overflow)
                if (frame_count < EMBEDDED_FRAMES) {
                    embedded[frame_count].payload_start = payload_start;
                    embedded[frame_count].payload_len = payload_len;
                } else {
                    // Overflow region: use bit shifts for fast addressing
                    size_t overflow_idx = frame_count - EMBEDDED_FRAMES;
                    if (using_deferred_frame_descs_) {
                        // Writing to deferred buffer (during deferred state)
                        deferred_frame_descs_[overflow_idx] = {payload_start, payload_len};
                    } else {
                        // Calculate padded SSL length for overflow position
                        size_t padded_ssl_len = cls_to_bytes(bytes_to_cls(ssl_data_len));
                        size_t overflow_cls_idx = overflow_idx >> DESCS_PER_CLS_SHIFT;
                        size_t overflow_cls_pos = (ssl_data_pos + padded_ssl_len + (overflow_cls_idx << CLS_SHIFT)) % capacity;
                        ShmFrameDesc* overflow_cls = reinterpret_cast<ShmFrameDesc*>(buffer + overflow_cls_pos);
                        overflow_cls[overflow_idx & DESCS_PER_CLS_MASK] = {payload_start, payload_len};
                    }
                }
                frame_count++;
                msg_count_++;

#ifdef DEBUG
                // Track data flow timing
                struct timespec ts_data;
                clock_gettime(CLOCK_MONOTONIC, &ts_data);
                last_data_frame_ns_ = ts_data.tv_sec * 1000000000ULL + ts_data.tv_nsec;
                ping_without_data_count_ = 0;  // Reset PING-only counter
#endif

                // Collect for callback (circular pointer)
                if constexpr (enables_callback) {
                    msg_state_.add_message(
                        frame.payload, frame.payload_len, rdtscp(), frame.opcode
                    );
                }
            }
            else if (frame.opcode == 0x09) {  // PING
#ifdef DEBUG
                // Track consecutive PINGs without data
                ping_without_data_count_++;
                if (ping_without_data_count_ >= 2 && last_data_frame_ns_ > 0) {
                    struct timespec ts_now;
                    clock_gettime(CLOCK_MONOTONIC, &ts_now);
                    uint64_t now_ns = ts_now.tv_sec * 1000000000ULL + ts_now.tv_nsec;
                    uint64_t gap_sec = (now_ns - last_data_frame_ns_) / 1000000000ULL;
                    DEBUG_PRINT("[WS-WARN] No data for %lu sec (%u PINGs) accum=%zu frag=%d\n",
                           gap_sec, ping_without_data_count_, data_written_, persistent_accumulating_);
                }
#endif
                if constexpr (is_replay_mode) {
                    // Replay mode: just log PING, don't queue PONG (no real connection)
                    DEBUG_PRINT("[REPLAY] PING received, len=%zu (PONG skipped in replay)\n", frame.payload_len);
                } else {
                    // Queue PONG for sending after batch commit (deferred commit mode)
                    if (frame.payload_len <= 125 && pending_pong_count_ < MAX_PENDING_PONGS) {
                        size_t pong_pos = (ssl_data_pos + parse_offset + frame.header_len) % capacity;
                        circular_read(buffer, capacity, pong_pos,
                                      pending_pong_payloads_[pending_pong_count_], frame.payload_len);
                        pending_pong_lens_[pending_pong_count_] = frame.payload_len;
                        pending_pong_count_++;
                        DEBUG_PRINT("[WS] PING received, len=%zu, PONG queued (will send after commit)\n", frame.payload_len);
                    } else if (frame.payload_len > 125) {
                        DEBUG_PRINT("[WS] PING too large (%zu bytes), ignoring\n", frame.payload_len);
                        suspicious_ctrl_count++;
                    } else {
                        DEBUG_PRINT("[WS] Too many pending PONGs, ignoring PING\n");
                    }
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

#ifdef DEBUG
                // Calculate connection duration
                struct timespec ts_now;
                clock_gettime(CLOCK_MONOTONIC, &ts_now);
                uint64_t now_ns = ts_now.tv_sec * 1000000000ULL + ts_now.tv_nsec;
                uint64_t duration_ns = now_ns - connect_time_ns_;
                uint64_t duration_sec = duration_ns / 1000000000ULL;
                uint64_t duration_ms = (duration_ns % 1000000000ULL) / 1000000ULL;

                // Always show full context for CLOSE frames
                DEBUG_PRINT("[WS] CLOSE: code=%u len=%zu valid=%d msgs=%zu suspicious_before=%u duration=%lu.%03lus\n",
                       close_code, frame.payload_len, valid_code, msg_count_, suspicious_ctrl_count,
                       duration_sec, duration_ms);

                // Read and show close reason if present
                if (frame.payload_len > 2) {
                    size_t reason_pos = (ssl_data_pos + parse_offset + frame.header_len + 2) % capacity;
                    size_t reason_len = std::min(frame.payload_len - 2, size_t(64));
                    uint8_t reason_buf[64];
                    circular_read(buffer, capacity, reason_pos, reason_buf, reason_len);
                    DEBUG_PRINT("[WS] CLOSE reason: %.*s\n", (int)reason_len, reason_buf);
                }
#endif

                if (valid_code) {
                    connected_ = false;
                    break;
                }
                // Invalid close code - treat as suspicious
                suspicious_ctrl_count++;
                parse_offset += frame_len;
                continue;
            }

            parse_offset += frame_len;
        }

        // Debug: parsing loop summary
        DEBUG_PRINT("[PARSE-DONE] parsed %zu/%zu bytes, %u frames, accum=%d | batch[%zu] data_written=%zu\n",
               parse_offset, ssl_data_len, frame_count, local_accumulating ? 1 : 0,
               batch_start_pos_, data_written_);

        // DEFERRED COMMIT: Only commit when ALL data consumed (no partial frame)
        // If partial frame exists, keep data_written_ intact for next SSL_read to append
        bool all_consumed = (parse_offset == ssl_data_len) && !local_accumulating;

        if (frame_count > 0 && all_consumed) {
            // All data consumed - commit the batch
            size_t committed_ssl_len = parse_offset;

            // Calculate padded sizes for cache alignment
            uint16_t ssl_cls = bytes_to_cls(committed_ssl_len);
            size_t padded_ssl_len = cls_to_bytes(ssl_cls);
            size_t overflow_size = overflow_descs_size(frame_count);
            size_t total_size = HDR_SIZE + padded_ssl_len + overflow_size;

            // Check if write would overwrite unread data
            if constexpr (RxBufferPolicy_::is_shm_ringbuffer) {
                if (total_size > rx_buffer_.writable()) {
                    rx_buffer_.mark_reader_dirty();
                    DEBUG_FPRINTF(stderr, "[WARN] RX buffer wraparound - consumer too slow, marking dirty\n");
                }
            } else {
                if (total_size > rx_buffer_.writable()) {
                    DEBUG_FPRINTF(stderr, "[ERROR] RX buffer full: need %zu bytes, available %zu. "
                            "Discarding %u frames.\n", total_size, rx_buffer_.writable(), frame_count);
                    data_written_ = 0;
                    return true;
                }
            }

            // Write header fields directly to shared memory (hdr already points to shm)
            // Embedded descriptors already written during parsing phase
            hdr->ssl_data_len_in_CLS = ssl_cls;
            hdr->frame_count = frame_count;
            hdr->opcode = batch_opcode;

            // Handle overflow descriptors
            uint16_t overflow_count = overflow_frame_count(frame_count);
            if (overflow_count > 0 && using_deferred_frame_descs_) {
                // Copy deferred overflow back to shared memory
                size_t overflow_pos = (ssl_data_pos + padded_ssl_len) % capacity;
                circular_write(buffer, capacity, overflow_pos,
                               reinterpret_cast<uint8_t*>(deferred_frame_descs_),
                               overflow_count * sizeof(ShmFrameDesc));
            }
            // Note: if !using_deferred_frame_descs_, overflow already written during parsing

            // Commit to shared memory
            rx_buffer_.commit_write(total_size);

            // In replay mode: immediately advance read position to match write
            // This prevents buffer full since there's no external consumer
            if constexpr (is_replay_mode) {
                rx_buffer_.commit_read(total_size);
            }

            data_written_ = 0;  // Reset for next batch
            persistent_parse_offset_ = 0;  // Reset parse position
            persistent_frame_count_ = 0;  // Reset frame state
            persistent_accumulating_ = false;  // Clear fragment state
            using_deferred_frame_descs_ = false;  // Clear deferred state
            batch_opcode_ = 0;  // Reset batch opcode

            // Send any queued PONGs after commit (skip in replay mode - no real connection)
            if constexpr (!is_replay_mode) {
                if (pending_pong_count_ > 0) {
                    for (uint8_t i = 0; i < pending_pong_count_; i++) {
                        send_pong(pending_pong_payloads_[i], pending_pong_lens_[i]);
                    }
                    if (deferred_pending_) {
                        DEBUG_PRINT("[BATCH-COMMIT] process_frames: %u frames, %zu bytes, %u PONGs | shmem[%zu..%zu] cap=%zu\n",
                               frame_count, total_size, pending_pong_count_,
                               batch_start_pos_, (batch_start_pos_ + sizeof(ShmBatchHeader) + total_size) % capacity,
                               capacity);
                    }
                    pending_pong_count_ = 0;
                } else if (deferred_pending_) {
                    DEBUG_PRINT("[BATCH-COMMIT] process_frames: %u frames, %zu bytes | shmem[%zu..%zu] cap=%zu\n",
                           frame_count, total_size,
                           batch_start_pos_, (batch_start_pos_ + sizeof(ShmBatchHeader) + total_size) % capacity,
                           capacity);
                }
                deferred_pending_ = false;  // Reset after commit
            }
        } else if (!all_consumed) {
            // Partial frame or fragment - defer commit, keep data_written_ intact
#ifdef DEBUG
            size_t partial_leftover = ssl_data_len - parse_offset;

            // If we parsed 0 bytes, show pending frame size to explain why
            size_t pending_frame_size = 0;
            if (parse_offset == 0 && ssl_data_len >= WS_HEADER_BASE) {
                // Peek at frame header to get expected size
                uint8_t peek[WS_HEADER_64BIT];  // Max header for length parsing (no mask)
                circular_read(buffer, capacity, ssl_data_pos, peek, std::min(WS_HEADER_64BIT, ssl_data_len));
                uint64_t payload_len = peek[1] & 0x7F;
                size_t hdr_len = WS_HEADER_BASE;
                if (payload_len == WS_PAYLOAD_LEN_16BIT && ssl_data_len >= WS_HEADER_16BIT) {
                    payload_len = (peek[2] << 8) | peek[3];
                    hdr_len = WS_HEADER_16BIT;
                } else if (payload_len == WS_PAYLOAD_LEN_64BIT && ssl_data_len >= WS_HEADER_64BIT) {
                    payload_len = 0;
                    for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | peek[2 + i];
                    hdr_len = WS_HEADER_64BIT;
                }
                pending_frame_size = hdr_len + payload_len;
            }

            // Calculate SSL data position for debug output
            size_t ssl_data_start = (batch_start_pos_ + sizeof(ShmBatchHeader)) % capacity;
            size_t ssl_data_end = (ssl_data_start + data_written_) % capacity;

            if (pending_frame_size > 0) {
                DEBUG_PRINT("[BATCH-DEFER] process_frames: need %zu bytes, have %zu (%.1f%%) | shmem[%zu..%zu] data_off=%zu len=%zu cap=%zu\n",
                       pending_frame_size, data_written_, 100.0 * data_written_ / pending_frame_size,
                       batch_start_pos_, ssl_data_end, ssl_data_start, data_written_, capacity);
            } else {
                DEBUG_PRINT("[BATCH-DEFER] process_frames: %u frames, %zu/%zu bytes consumed, %zu partial | shmem[%zu..%zu] data_off=%zu len=%zu cap=%zu\n",
                       frame_count, parse_offset, ssl_data_len, partial_leftover,
                       batch_start_pos_, ssl_data_end, ssl_data_start, data_written_, capacity);
            }
#endif
            deferred_pending_ = true;  // Mark that we deferred (for BATCH-COMMIT logging)
            // Preserve parse offset so next call resumes from where we left off
            persistent_parse_offset_ = parse_offset;
            persistent_frame_count_ = frame_count;
            batch_opcode_ = batch_opcode;  // Preserve batch opcode for resume

            // Copy overflow descriptors from shm to deferred buffer (if not already using it)
            // Embedded descriptors stay in shm header - no copy needed
            if (frame_count > EMBEDDED_FRAMES && !using_deferred_frame_descs_) {
                uint16_t overflow_count = frame_count - static_cast<uint16_t>(EMBEDDED_FRAMES);
                size_t padded_ssl_len = cls_to_bytes(bytes_to_cls(ssl_data_len));
                size_t overflow_pos = (ssl_data_pos + padded_ssl_len) % capacity;
                circular_read(buffer, capacity, overflow_pos,
                              reinterpret_cast<uint8_t*>(deferred_frame_descs_),
                              overflow_count * sizeof(ShmFrameDesc));
                using_deferred_frame_descs_ = true;
            }
            // Preserve fragment state if accumulating
            if (local_accumulating) {
                persistent_accumulating_ = true;
                persistent_opcode_ = accum_opcode;
                persistent_accum_len_ = accum_payload_len;
            }
            // data_written_ stays intact - next SSL_read will append
        } else if (all_consumed && frame_count == 0) {
            // Control frames only (e.g., PING) - no data to commit, but all consumed
            // Reset state and send any queued PONGs now
            data_written_ = 0;
            persistent_parse_offset_ = 0;
            persistent_frame_count_ = 0;
            using_deferred_frame_descs_ = false;
            batch_opcode_ = 0;
            // Send pending PONGs (skip in replay mode - no real connection)
            if constexpr (!is_replay_mode) {
                if (pending_pong_count_ > 0) {
                    for (uint8_t i = 0; i < pending_pong_count_; i++) {
                        send_pong(pending_pong_payloads_[i], pending_pong_lens_[i]);
                    }
                    DEBUG_PRINT("[CTRL-ONLY] Sent %u PONGs (no data frames)\n", pending_pong_count_);
                    pending_pong_count_ = 0;
                }
            }
        }

        // Invoke callback if set (compile-time conditional: only PrivateWebSocketClient)
        // Note: callback sees frames only after commit
        if constexpr (enables_callback) {
            if (!msg_state_.invoke_callback(timing_)) {
                return false;
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
        if constexpr (is_replay_mode) {
            (void)payload; (void)len;  // Suppress unused warnings
            return;  // No-op in replay mode (no real connection)
        } else {
            using namespace websocket::http;

            uint8_t pong[256];

            // Static masking key for performance (single-threaded HFT env)
            uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};

            // Build PONG frame using core utilities
            size_t frame_len = build_pong_frame(payload, len, pong, mask);

            // Record TX before sending (for debug analysis)
            if constexpr (websocket::debug_enabled) {
                transport_.write_tx_record(pong, frame_len);
            }

            // Check write return value
            ssize_t ret = ssl_.write(pong, frame_len);
            if (ret <= 0) {
                DEBUG_PRINT("[WARN] Failed to send PONG response\n");
            }
        }
    }

public:
    // Access to TX buffer for external writes (e.g., sending SUBSCRIBE commands)
    // Non-const version allows writing to buffer
    TxBufferPolicy_& get_tx_buffer_mut() { return tx_buffer_; }

    // Debug traffic recording - record all SSL_read data to file for debugging
    // Resets file on enable, writes 32-byte header + raw data per SSL_read
    // NOTE: Only functional when compiled with -DDEBUG (uses transport_.enable_recording())
    void enable_debug_traffic(const char* path = "debug_traffic.dat") {
        if constexpr (websocket::debug_enabled && !is_replay_mode) {
            transport_.enable_recording(path);
            DEBUG_PRINT("[DEBUG] Traffic recording enabled: %s\n", path);
        } else {
            (void)path;  // Suppress unused warning
        }
    }

    void disable_debug_traffic() {
        if constexpr (websocket::debug_enabled && !is_replay_mode) {
            transport_.disable_recording();
            DEBUG_PRINT("[DEBUG] Traffic recording disabled\n");
        }
    }

    constexpr bool is_debug_traffic_enabled() const {
        return websocket::debug_enabled && !is_replay_mode;
    }

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

    // Enable TX outbox if buffer is HftShm type (compile-time check)
    void enable_hftshm_tx_outbox() {
        if constexpr (tx_outbox_supported && uses_hftshm_tx) {
            tx_opcode_ = 0x01;  // Text by default
        }
        // No-op when NullBuffer - compile-time eliminated
    }

    // Note: Debug traffic recording moved to transport layer (transport_.write_record())

    SSLPolicy_ ssl_;
    TransportPolicy_ transport_;     // Unified transport (owns connection + event loop)
    RxBufferPolicy_ rx_buffer_;      // Separate RX buffer type/size
    TxBufferPolicy_ tx_buffer_;      // Separate TX buffer type/size

    bool connected_;
    uint8_t tx_opcode_ = 0x01;       // WebSocket opcode for TX outbox (0x01=text, 0x02=binary)
    uint64_t msg_count_;
    timing_record_t timing_;  // Batch-level timing (SSL read timing shared by all messages)

    // Compile-time conditional callback state
    // - PrivateWebSocketClient: MessageBatchState<true> with callback + message_batch_[MAX_FRAMES]
    // - ShmWebSocketClient: MessageBatchState<false> empty struct (0 bytes)
    MessageBatchState<enables_callback> msg_state_;

    // Graceful shutdown support
    volatile bool* stop_flag_ = nullptr;

    // Circular buffer batch state (unified for all buffer types)
    size_t batch_start_pos_ = 0;          // Logical write position where current batch starts
    size_t data_written_ = 0;             // Bytes of SSL data accumulated (not yet committed)

    // Fragment state (for fragmented WebSocket messages across SSL_reads)
    bool persistent_accumulating_ = false; // Fragment accumulation in progress
    uint8_t persistent_opcode_ = 0;        // Opcode of incomplete fragment (0x01=text, 0x02=binary)
    size_t persistent_accum_len_ = 0;      // Total accumulated payload length so far
    size_t persistent_parse_offset_ = 0;   // Bytes already parsed (for deferred commit resume)

    // Deferred commit: overflow frame descriptors from partial batch
    // MAX_FRAMES defined at class level (65535, from ShmBatchHeader::frame_count type)
    // Only used when frame_count > EMBEDDED_FRAMES AND batch is deferred
    ShmFrameDesc deferred_frame_descs_[MAX_FRAMES];  // ~512KB always allocated
    bool using_deferred_frame_descs_ = false;  // True when overflow is in deferred buffer
    uint16_t persistent_frame_count_ = 0;
    uint8_t batch_opcode_ = 0;  // Batch-wide opcode (from first data frame)
    bool deferred_pending_ = false;  // True when BATCH-DEFER occurred, for logging

    // Deferred PONG: store PING payloads during parse, send after commit
    static constexpr size_t MAX_PENDING_PONGS = 4;
    uint8_t pending_pong_payloads_[MAX_PENDING_PONGS][125];  // RFC 6455 max PING payload
    size_t pending_pong_lens_[MAX_PENDING_PONGS] = {0};
    uint8_t pending_pong_count_ = 0;

    // Reconnection support
    std::string host_;
    std::string path_;
    uint16_t port_ = 0;
    std::function<bool()> on_close_;  // Returns true to reconnect

#ifdef DEBUG
    // Connection timing (for duration tracking - debug only)
    uint64_t connect_time_ns_ = 0;    // Timestamp when connected (clock_gettime MONOTONIC)
    uint64_t last_data_frame_ns_ = 0; // Timestamp of last data frame (for flow monitoring)
    uint32_t ping_without_data_count_ = 0; // Count consecutive PINGs without data frames
#endif

    // Dead connection detection - disconnect after N consecutive timeouts (1 sec each)
    static constexpr int NO_DATA_TIMEOUT_COUNT = 60;  // 60 seconds without data
    int consecutive_timeouts_ = 0;

    // Subscription messages - populated by on_connect callback, sent automatically
    char subscribe_messages_[128][512];       // Max 128 messages, 512 bytes each
    size_t num_subscribe_messages_ = 0;       // Count set by callback
    bool subscribe_messages_sent_ = false;    // Flag: true after all sent
    std::function<void(char(*)[512], size_t&)> on_connect_;  // Callback to populate subscribe_messages_

    // Note: Debug traffic recording now handled by transport layer (transport_.write_record())
};
