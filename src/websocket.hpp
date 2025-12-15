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
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define DEBUG_FPRINTF(...) fprintf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) ((void)0)
#define DEBUG_FPRINTF(...) ((void)0)
#endif

#include "ws_policies.hpp"
#include "core/timing.hpp"
#include "core/http.hpp"
#include "ringbuffer.hpp"  // Unified ringbuffer with batch format
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

// Shared memory batch types included in ringbuffer.hpp

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

    // Compile-time detection for TX buffer (RX unified - no branching needed)
    static constexpr bool uses_hftshm_tx = TxBufferPolicy_::is_hftshm;

    // Buffer mode detection (unified HftShmRingBuffer provides these traits)
    // - is_private: true for PrivateRingBuffer, false for ShmRxBuffer
    // - uses_runtime_path: true for ShmRxBuffer, false for PrivateRingBuffer
    static constexpr bool uses_private_buffer = RxBufferPolicy_::is_private;
    static constexpr bool requires_runtime_path = !uses_private_buffer;

    // HTTP header customization support
    using HeaderMap = std::vector<std::pair<std::string, std::string>>;

    // Batch message callback - receives array of messages with per-message timing
    // timing_record_t contains batch-level SSL timing, MessageInfo has per-message parse_cycle
    // Returns: true to continue receiving, false to exit run() loop
    using MessageCallback = std::function<bool(const MessageInfo*, size_t, const timing_record_t&)>;

#ifdef SIMULATOR_MODE
    // Simulator mode constructor - allocates private buffer, skips shmem/SSL/transport init
    WebSocketClient()
        : connected_(false)
        , xdp_initialized_(false)
        , rx_callback_enabled_(true)  // Enable callback for simulation
        , msg_count_(0)
    {
        // Allocate private 4MB buffer (no shared memory)
        sim_private_buffer_.resize(4 * 1024 * 1024);

        // Initialize timing record
        memset(&timing_, 0, sizeof(timing_));

        // Allocate initial message batch buffer
        message_batch_ = new MessageInfo[INITIAL_BATCH_CAPACITY];

        // Initialize batch state
        batch_start_pos_ = 0;
        data_written_ = 0;
        persistent_parse_offset_ = 0;
        persistent_frame_count_ = 0;
        persistent_accumulating_ = false;
        persistent_opcode_ = 0;
        persistent_accum_len_ = 0;

        DEBUG_PRINT("[SIM] WebSocketClient created in simulator mode (4MB private buffer)\n");
    }
#else
    // Constructor with optional shared memory path
    // Two buffer modes (based on RxBufferPolicy template parameter):
    // - PrivateRingBuffer: allocates private memory, on_messages() ENABLED
    // - ShmRxBuffer: opens hft-shm files at rx_shmem_path, on_messages() DISABLED
    WebSocketClient(const char* rx_shmem_path = nullptr)
        : connected_(false)
        , xdp_initialized_(false)
        , rx_callback_enabled_(uses_private_buffer)  // Enable callback only for private mode
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

        // Allocate initial message batch buffer
        message_batch_ = new MessageInfo[INITIAL_BATCH_CAPACITY];
    }
#endif

    ~WebSocketClient() {
        disable_debug_traffic();  // Close debug file if open
#ifdef SIMULATOR_MODE
        if (sim_traffic_fp_) {
            fclose(sim_traffic_fp_);
            sim_traffic_fp_ = nullptr;
        }
#else
        disconnect();
#endif
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
        DEBUG_PRINT("[XDP] Initializing AF_XDP transport...\n");
        DEBUG_PRINT("[XDP]   Interface: %s\n", interface);
        DEBUG_PRINT("[XDP]   BPF object: %s\n", bpf_obj);
        DEBUG_PRINT("[XDP]   Domain: %s, Port: %u\n", domain, port);

        // Resolve domain to IPs
        auto ips = resolve_hostname(domain);
        if (ips.empty()) {
            throw std::runtime_error(std::string("Failed to resolve domain: ") + domain);
        }
        DEBUG_PRINT("[XDP]   Resolved %zu IP(s)\n", ips.size());

        // Initialize XDP transport with interface and BPF program
        transport_.init(interface, bpf_obj);

        // Configure BPF filter for all resolved IPs
        for (const auto& ip : ips) {
            transport_.add_exchange_ip(ip.c_str());
            DEBUG_PRINT("[XDP]     Added IP: %s\n", ip.c_str());
        }
        transport_.add_exchange_port(port);

        xdp_initialized_ = true;
        DEBUG_PRINT("[XDP] Transport initialized successfully\n");
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
                DEBUG_PRINT("[KTLS] Kernel TLS offload active\n");
            } else {
                DEBUG_PRINT("[TLS] Standard user-space TLS mode\n");
            }
        } else {
            // Userspace transports never support kTLS
            DEBUG_PRINT("[TLS] Standard user-space TLS mode (userspace transport)\n");
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

        // Record connection start time for duration tracking
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        connect_time_ns_ = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        DEBUG_PRINT("[WS] Connected to %s:%d%s\n", host, port, path);

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

#ifdef SIMULATOR_MODE
    // ============================================================================
    // Simulator Mode Methods (compile-time only)
    // ============================================================================

    // Open traffic replay file
    bool open_replay_file(const char* path = "debug_traffic.dat") {
        sim_traffic_fp_ = fopen(path, "rb");
        if (!sim_traffic_fp_) {
            DEBUG_FPRINTF(stderr, "[SIM] Cannot open %s\n", path);
            return false;
        }
        fseek(sim_traffic_fp_, 0, SEEK_END);
        long file_size = ftell(sim_traffic_fp_);
        fseek(sim_traffic_fp_, 0, SEEK_SET);
        DEBUG_PRINT("[SIM] Opened %s (%ld bytes)\n", path, file_size);
        return true;
    }

    // Replay one SSL_read record from debug_traffic.dat into private buffer
    // Returns: bytes "read" (0 = EOF, -1 = error, >0 = data replayed)
    ssize_t replay_traffic_into_buffer() {
        if (!sim_traffic_fp_) return -1;

        // DebugTrafficHeader: 32 bytes
        uint8_t hdr[32];
        if (fread(hdr, 32, 1, sim_traffic_fp_) != 1) return 0;  // EOF

        bool is_rx = (memcmp(hdr, "SSLR", 4) == 0);
        bool is_tx = (memcmp(hdr, "SSLT", 4) == 0);
        if (!is_rx && !is_tx) {
            DEBUG_FPRINTF(stderr, "[SIM] Invalid magic at offset %ld: %02x %02x %02x %02x\n",
                    ftell(sim_traffic_fp_) - 32, hdr[0], hdr[1], hdr[2], hdr[3]);
            return -1;
        }

        uint32_t ssl_bytes, accum_before;
        memcpy(&ssl_bytes, hdr + 12, 4);
        memcpy(&accum_before, hdr + 16, 4);

        // Skip TX records
        if (is_tx) {
            fseek(sim_traffic_fp_, ssl_bytes, SEEK_CUR);
            sim_tx_count_++;
            return replay_traffic_into_buffer();  // Recursively get next RX
        }

        sim_ssl_read_count_++;
        bool is_fresh = (accum_before == 0);

        uint8_t* buffer = sim_private_buffer_.data();
        size_t capacity = sim_private_buffer_.size();
        constexpr size_t HDR_SIZE = CACHE_LINE_SIZE;  // ShmBatchHeader size

        // Determine write position (same logic as recv_into_buffer)
        size_t ssl_write_pos;
        if (is_fresh) {
            // Start new batch - align batch_start_pos
            batch_start_pos_ = (batch_start_pos_ + HDR_SIZE + data_written_ + (CACHE_LINE_SIZE-1))
                               & ~(CACHE_LINE_SIZE-1);
            batch_start_pos_ %= capacity;
            data_written_ = 0;
            persistent_parse_offset_ = 0;
            persistent_frame_count_ = 0;
            ssl_write_pos = (batch_start_pos_ + HDR_SIZE) % capacity;
        } else {
            // Accumulating - append to existing data
            ssl_write_pos = (batch_start_pos_ + HDR_SIZE + data_written_) % capacity;
        }

        // Read SSL data from file into circular buffer
        size_t to_end = capacity - ssl_write_pos;
        if (ssl_bytes <= to_end) {
            size_t read = fread(buffer + ssl_write_pos, 1, ssl_bytes, sim_traffic_fp_);
            if (read != ssl_bytes) {
                DEBUG_FPRINTF(stderr, "[SIM] Short read: expected %u, got %zu\n", ssl_bytes, read);
                return -1;
            }
        } else {
            size_t r1 = fread(buffer + ssl_write_pos, 1, to_end, sim_traffic_fp_);
            size_t r2 = fread(buffer, 1, ssl_bytes - to_end, sim_traffic_fp_);
            (void)r1; (void)r2;  // Suppress unused warnings
        }
        data_written_ += ssl_bytes;

        // Debug print (match production format)
        const char* state_str = is_fresh ? "FRESH" : "ACCUM";
        uint8_t b0 = buffer[(batch_start_pos_ + HDR_SIZE) % capacity];
        uint8_t b1 = buffer[(batch_start_pos_ + HDR_SIZE + 1) % capacity];
        uint8_t b2 = buffer[(batch_start_pos_ + HDR_SIZE + 2) % capacity];
        uint8_t b3 = buffer[(batch_start_pos_ + HDR_SIZE + 3) % capacity];
        DEBUG_PRINT("[SIM-SSL#%lu] %s +%u bytes @%zu, total=%zu | batch[%zu] | data=[%02x %02x %02x %02x]\n",
               sim_ssl_read_count_, state_str, ssl_bytes, ssl_write_pos, data_written_,
               batch_start_pos_, b0, b1, b2, b3);

        return ssl_bytes;
    }

    // Main simulation loop - replay all traffic and process frames
    bool run_simulator(const char* traffic_file = "debug_traffic.dat") {
        if (!open_replay_file(traffic_file)) return false;

        DEBUG_PRINT("[SIM] Starting replay...\n");

        while (true) {
            ssize_t n = replay_traffic_into_buffer();
            if (n <= 0) break;  // EOF or error

            // Call actual process_frames() - the core of the simulation!
            process_frames();
        }

        if (sim_traffic_fp_) {
            fclose(sim_traffic_fp_);
            sim_traffic_fp_ = nullptr;
        }

        DEBUG_PRINT("\n[SIM] === Replay Complete ===\n");
        DEBUG_PRINT("[SIM] SSL reads: %lu\n", sim_ssl_read_count_);
        DEBUG_PRINT("[SIM] TX skipped: %lu\n", sim_tx_count_);
        DEBUG_PRINT("[SIM] Messages: %lu\n", msg_count_);

        return true;
    }
#endif

    // Set message callback (used by simulator and can be used before run())
    void set_message_callback(MessageCallback callback) {
        on_message_ = callback;
    }

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
                    // Timeout - just handle TX (SSL buffer draining now in recv_into_buffer)
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
            if (debug_traffic_enabled_) {
                DEBUG_PRINT("[DEBUG] Reconnect disabled in debug mode - analyze debug_traffic.dat\n");
                break;
            }
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
    // UNIFIED CODEPATH: All buffer types use same batch format
    // Loops with SSL_pending() to drain any buffered TLS data
    // Deferred commit mode: accumulates data across SSL_reads until no partial frame
    bool recv_into_buffer() {
        // Stage 3: Record timestamp before SSL_read/recv
        timing_.recv_start_cycle = rdtsc();

        constexpr size_t HDR_SIZE = sizeof(ShmBatchHeader);  // CACHE_LINE_SIZE
        size_t min_needed = HDR_SIZE + CACHE_LINE_SIZE + CACHE_LINE_SIZE;

        // Loop to drain all available data (SSL buffer + socket)
        while (true) {
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
                    fflush(stdout);
                    break;  // Buffer full, wait for consumer
                }
                data_available = total_writable - CACHE_LINE_SIZE;
            } else {
                // Fresh batch - start new batch header position
                size_t total_writable = rx_buffer_.writable();
                if (total_writable < min_needed) {
                    DEBUG_PRINT("[BUFFER-FULL] recv_into_buffer: waiting for consumer (fresh) | shmem writable=%zu need=%zu cap=%zu\n",
                           total_writable, min_needed, capacity);
                    fflush(stdout);
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

            if (data_available <= to_end) {
                n = ssl_.read(buffer + ssl_write_pos, data_available);
            } else {
                n = ssl_.read(buffer + ssl_write_pos, to_end);
                if (n == static_cast<ssize_t>(to_end)) {
                    ssize_t n2 = ssl_.read(buffer, data_available - to_end);
                    if (n2 > 0) n += n2;
                }
            }

            if (n > 0) {
                // Accumulate data (may span multiple SSL_reads until batch commits)
                data_written_ += static_cast<size_t>(n);
                timing_.recv_end_cycle = rdtscp();
                timing_.ssl_read_bytes = n;

                // Debug traffic recording - write raw SSL data to file
                if (debug_traffic_enabled_) {
                    write_debug_record(buffer, ssl_write_pos, n, capacity);
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
                fflush(stdout);

                // MISMATCH CHECK: For FRESH reads, write bytes should match batch_data
                // If they differ, something is wrong (memory corruption, race condition)
                if (!is_accumulating && data_pos == ssl_write_pos) {
                    if (peek_byte0 != batch_byte0 || peek_byte1 != batch_byte1 ||
                        peek_byte2 != batch_byte2 || peek_byte3 != batch_byte3) {
                        DEBUG_PRINT("[CORRUPTION!] write=[%02x %02x %02x %02x] != batch_data=[%02x %02x %02x %02x] at pos %zu\n",
                               peek_byte0, peek_byte1, peek_byte2, peek_byte3,
                               batch_byte0, batch_byte1, batch_byte2, batch_byte3, ssl_write_pos);
                        fflush(stdout);
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
                fflush(stdout);
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

            // Record TX for debug (combine header + payload for analysis)
            if (debug_traffic_enabled_) {
                uint8_t tx_frame[1024];
                if (header_len + msg_len <= sizeof(tx_frame)) {
                    memcpy(tx_frame, header, header_len);
                    memcpy(tx_frame + header_len, subscribe_messages_[i], msg_len);
                    write_debug_tx_record(tx_frame, header_len + msg_len);
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
        batch_count_ = 0;

        // Circular buffer mode: Parse frames with circular access
        // Format: [ShmBatchHeader (CLS)][raw_ssl_data padded (N*CLS)][ShmFrameDesc[] padded (M*CLS)]
        // Data may wrap around buffer boundary seamlessly
        if (data_written_ == 0) return true;

        constexpr size_t HDR_SIZE = sizeof(ShmBatchHeader);  // CACHE_LINE_SIZE

#ifdef SIMULATOR_MODE
        uint8_t* buffer = sim_private_buffer_.data();
        size_t capacity = sim_private_buffer_.size();
#else
        uint8_t* buffer = rx_buffer_.buffer_base();
        size_t capacity = rx_buffer_.buffer_capacity();
#endif
        size_t batch_pos = batch_start_pos_;
        size_t ssl_data_pos = (batch_pos + HDR_SIZE) % capacity;
        size_t ssl_data_len = data_written_;

        // Frame descriptors: embedded go directly to header, overflow written at commit
        // Practical stack limit: 4096 frames = 48KB (4MB buffer / 200 bytes ≈ 20K frames max)
        constexpr size_t MAX_FRAMES = 4096;
        ShmFrameDesc frame_descs[MAX_FRAMES];
        uint16_t frame_count = persistent_frame_count_;  // Resume from deferred state
        uint16_t suspicious_ctrl_count = 0;  // Track likely frame misalignment

        // Restore frame descriptors from deferred state
        if (frame_count > 0) {
            memcpy(frame_descs, persistent_frame_descs_, frame_count * sizeof(ShmFrameDesc));
        }

        // Resume parsing from where we left off (deferred commit case)
        size_t parse_offset = persistent_parse_offset_;

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
#ifdef DEBUG
                // Debug: show WHY parsing stopped (incomplete frame)
                uint64_t peek_payload_len = header_bytes[1] & 0x7F;
                size_t expected_hdr = 2;
                if (peek_payload_len == 126) { expected_hdr = 4; peek_payload_len = (header_bytes[2] << 8) | header_bytes[3]; }
                else if (peek_payload_len == 127) { expected_hdr = 10; }
                DEBUG_PRINT("[PARSE-INCOMPLETE] @%zu/%zu: need frame hdr=%zu+payload=%lu, have %zu bytes | hdr[0:1]=%02x %02x\n",
                       parse_offset, ssl_data_len, expected_hdr, (unsigned long)peek_payload_len, remaining,
                       header_bytes[0], header_bytes[1]);
                fflush(stdout);
#endif
                break;  // Incomplete frame header or payload
            }

            size_t frame_len = frame.header_len + frame.payload_len;
            if (parse_offset + frame_len > ssl_data_len) {
                DEBUG_PRINT("[PARSE-INCOMPLETE] @%zu/%zu: frame_len=%zu exceeds remaining=%zu\n",
                       parse_offset, ssl_data_len, frame_len, ssl_data_len - parse_offset);
                fflush(stdout);
                break;  // Incomplete frame
            }

#ifdef DEBUG
            // Debug: show each frame parsed with raw header bytes for diagnosis
            size_t this_frame_total = frame.header_len + frame.payload_len;
            DEBUG_PRINT("[FRAME#%u] op=%02x fin=%d hdr=%zu payload=%zu total=%zu @%zu | batch_pos=%zu | raw=[%02x %02x %02x %02x] pos=%zu\n",
                   frame_count, frame.opcode, frame.fin, frame.header_len, frame.payload_len, this_frame_total,
                   parse_offset, batch_start_pos_,
                   header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3], header_pos);
            fflush(stdout);

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
                    fflush(stdout);
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
                for (size_t i = 0; i < std::min(size_t(14), ssl_data_len - parse_offset); i++) {
                    DEBUG_PRINT("%02x ", header_bytes[i]);
                }
                DEBUG_PRINT("\n");
                fflush(stdout);

                if (is_suspicious) {
                    suspicious_ctrl_count++;
                    if (suspicious_ctrl_count >= 3) {
                        DEBUG_PRINT("[WS-WARNING] Suspicious frames (%u), continuing processing...\n",
                               suspicious_ctrl_count);
                        fflush(stdout);
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
                    DEBUG_PRINT("[ERROR] Frame offset out of bounds: start=%u len=%u ssl_len=%zu\n",
                           payload_start, payload_len, ssl_data_len);
                    break;
                }

                // Record frame descriptor (offsets are relative to ssl_data start)
                frame_descs[frame_count].payload_start = payload_start;
                frame_descs[frame_count].payload_len = payload_len;
                frame_descs[frame_count].opcode = frame.opcode;
                frame_count++;
                msg_count_++;

                // Track data flow timing
                struct timespec ts_data;
                clock_gettime(CLOCK_MONOTONIC, &ts_data);
                last_data_frame_ns_ = ts_data.tv_sec * 1000000000ULL + ts_data.tv_nsec;
                ping_without_data_count_ = 0;  // Reset PING-only counter

                // Collect for callback (circular pointer)
                ensure_batch_capacity();
                message_batch_[batch_count_++] = {
                    frame.payload, frame.payload_len, rdtscp(), frame.opcode
                };
            }
            else if (frame.opcode == 0x09) {  // PING
                // Track consecutive PINGs without data
                ping_without_data_count_++;
#ifdef DEBUG
                if (ping_without_data_count_ >= 2 && last_data_frame_ns_ > 0) {
                    struct timespec ts_now;
                    clock_gettime(CLOCK_MONOTONIC, &ts_now);
                    uint64_t now_ns = ts_now.tv_sec * 1000000000ULL + ts_now.tv_nsec;
                    uint64_t gap_sec = (now_ns - last_data_frame_ns_) / 1000000000ULL;
                    DEBUG_PRINT("[WS-WARN] No data for %lu sec (%u PINGs) accum=%zu frag=%d\n",
                           gap_sec, ping_without_data_count_, data_written_, persistent_accumulating_);
                }
#endif
#ifdef SIMULATOR_MODE
                // Simulator: just log PING, don't queue PONG
                DEBUG_PRINT("[SIM] PING received, len=%zu (PONG skipped in simulator)\n", frame.payload_len);
#else
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
#endif
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
                fflush(stdout);
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
        fflush(stdout);

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

#ifndef SIMULATOR_MODE
            // Check if write would overwrite unread data (skip in simulator - no consumer)
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

            // Build header with embedded frame descriptors
            ShmBatchHeader hdr{};
            hdr.ssl_data_len_in_CLS = ssl_cls;
            hdr.frame_count = frame_count;

            uint8_t embedded_count = static_cast<uint8_t>(std::min(frame_count, static_cast<uint16_t>(EMBEDDED_FRAMES)));
            memcpy(hdr.embedded, frame_descs, embedded_count * sizeof(ShmFrameDesc));

            // Write overflow descriptors if any
            uint16_t overflow_count = overflow_frame_count(frame_count);
            if (overflow_count > 0) {
                size_t overflow_pos = (ssl_data_pos + padded_ssl_len) % capacity;
                circular_write(buffer, capacity, overflow_pos,
                               reinterpret_cast<uint8_t*>(frame_descs + EMBEDDED_FRAMES),
                               overflow_count * sizeof(ShmFrameDesc));
            }

            // Write header
            circular_write(buffer, capacity, batch_pos,
                           reinterpret_cast<uint8_t*>(&hdr), HDR_SIZE);

            // Commit to shared memory
            rx_buffer_.commit_write(total_size);
#else
            // Simulator: just log commit, no actual buffer commit
            DEBUG_PRINT("[SIM-COMMIT] %u frames, %zu bytes\n", frame_count, total_size);
#endif
            data_written_ = 0;  // Reset for next batch
            persistent_parse_offset_ = 0;  // Reset parse position
            persistent_frame_count_ = 0;  // Reset frame state
            persistent_accumulating_ = false;  // Clear fragment state

#ifndef SIMULATOR_MODE
            // Send any queued PONGs after commit (production only)
            if (pending_pong_count_ > 0) {
                for (uint8_t i = 0; i < pending_pong_count_; i++) {
                    send_pong(pending_pong_payloads_[i], pending_pong_lens_[i]);
                }
                if (deferred_pending_) {
                    DEBUG_PRINT("[BATCH-COMMIT] process_frames: %u frames, %zu bytes, %u PONGs | shmem[%zu..%zu] cap=%zu\n",
                           frame_count, total_size, pending_pong_count_,
                           batch_start_pos_, (batch_start_pos_ + sizeof(ShmBatchHeader) + total_size) % capacity,
                           capacity);
                    fflush(stdout);
                }
                pending_pong_count_ = 0;
            } else if (deferred_pending_) {
                DEBUG_PRINT("[BATCH-COMMIT] process_frames: %u frames, %zu bytes | shmem[%zu..%zu] cap=%zu\n",
                       frame_count, total_size,
                       batch_start_pos_, (batch_start_pos_ + sizeof(ShmBatchHeader) + total_size) % capacity,
                       capacity);
                fflush(stdout);
            }
            deferred_pending_ = false;  // Reset after commit
#endif
        } else if (!all_consumed) {
            // Partial frame or fragment - defer commit, keep data_written_ intact
#ifdef DEBUG
            size_t partial_leftover = ssl_data_len - parse_offset;

            // If we parsed 0 bytes, show pending frame size to explain why
            size_t pending_frame_size = 0;
            if (parse_offset == 0 && ssl_data_len >= 2) {
                // Peek at frame header to get expected size
                uint8_t peek[10];
                circular_read(buffer, capacity, ssl_data_pos, peek, std::min(size_t(10), ssl_data_len));
                uint64_t payload_len = peek[1] & 0x7F;
                size_t hdr_len = 2;
                if (payload_len == 126 && ssl_data_len >= 4) {
                    payload_len = (peek[2] << 8) | peek[3];
                    hdr_len = 4;
                } else if (payload_len == 127 && ssl_data_len >= 10) {
                    payload_len = 0;
                    for (int i = 0; i < 8; i++) payload_len = (payload_len << 8) | peek[2 + i];
                    hdr_len = 10;
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
            fflush(stdout);
            deferred_pending_ = true;  // Mark that we deferred (for BATCH-COMMIT logging)
            // Preserve parse offset so next call resumes from where we left off
            persistent_parse_offset_ = parse_offset;
            // Preserve frame descriptors so we don't lose already-parsed frames
            persistent_frame_count_ = frame_count;
            if (frame_count > 0) {
                memcpy(persistent_frame_descs_, frame_descs, frame_count * sizeof(ShmFrameDesc));
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
#ifndef SIMULATOR_MODE
            if (pending_pong_count_ > 0) {
                for (uint8_t i = 0; i < pending_pong_count_; i++) {
                    send_pong(pending_pong_payloads_[i], pending_pong_lens_[i]);
                }
                DEBUG_PRINT("[CTRL-ONLY] Sent %u PONGs (no data frames)\n", pending_pong_count_);
                fflush(stdout);
                pending_pong_count_ = 0;
            }
#endif
        }

        // Invoke callback if set AND enabled (disabled when shmem path provided)
        // Note: callback sees frames only after commit (batch_count_ updated during parse)
        if (batch_count_ > 0 && on_message_ && rx_callback_enabled_) {
            if (!on_message_(message_batch_, batch_count_, timing_)) {
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
#ifdef SIMULATOR_MODE
        (void)payload; (void)len;  // Suppress unused warnings
        return;  // No-op in simulator mode
#else
        using namespace websocket::http;

        uint8_t pong[256];

        // Static masking key for performance (single-threaded HFT env)
        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};

        // Build PONG frame using core utilities
        size_t frame_len = build_pong_frame(payload, len, pong, mask);

        // Record TX before sending (for debug analysis)
        if (debug_traffic_enabled_) {
            write_debug_tx_record(pong, frame_len);
        }

        // Check write return value
        ssize_t ret = ssl_.write(pong, frame_len);
        if (ret <= 0) {
            DEBUG_PRINT("[WARN] Failed to send PONG response\n");
        }
#endif  // !SIMULATOR_MODE
    }

public:
    // Access to TX buffer for external writes (e.g., sending SUBSCRIBE commands)
    // Non-const version allows writing to buffer
    TxBufferPolicy_& get_tx_buffer_mut() { return tx_buffer_; }

    // Debug traffic recording - record all SSL_read data to file for debugging
    // Resets file on enable, writes 32-byte header + raw data per SSL_read
    void enable_debug_traffic(const char* path = "debug_traffic.dat") {
        disable_debug_traffic();  // Close existing if any
        debug_traffic_fp_ = fopen(path, "wb");
        if (debug_traffic_fp_) {
            debug_traffic_enabled_ = true;
            DEBUG_PRINT("[DEBUG] Traffic recording enabled: %s\n", path);
        } else {
            DEBUG_PRINT("[DEBUG] Failed to open traffic file: %s\n", path);
        }
    }

    void disable_debug_traffic() {
        if (debug_traffic_fp_) {
            fclose(debug_traffic_fp_);
            debug_traffic_fp_ = nullptr;
            DEBUG_PRINT("[DEBUG] Traffic recording disabled\n");
        }
        debug_traffic_enabled_ = false;
    }

    bool is_debug_traffic_enabled() const { return debug_traffic_enabled_; }

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

    // Write debug traffic record: 32-byte header + raw SSL data
    // Header format: "SSLR"/"SSLT" magic, timestamp_ns, ssl_bytes, leftover_before, leftover_after, frag_state, frame_count
    // Magic: "SSLR" = RX (received), "SSLT" = TX (transmitted)
    void write_debug_record(uint8_t* buffer, size_t pos, ssize_t n, size_t capacity) {
        if (!debug_traffic_fp_ || n <= 0) return;

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t ts_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        // Build 32-byte header
        uint8_t header[32] = {0};
        memcpy(header, "SSLR", 4);                                    // 0-3: magic (RX)
        memcpy(header + 4, &ts_ns, 8);                                // 4-11: timestamp_ns
        uint32_t bytes = static_cast<uint32_t>(n);
        memcpy(header + 12, &bytes, 4);                               // 12-15: ssl_read_bytes
        // data_written_ already includes this read, so subtract to get "accum before"
        uint32_t accum_before = static_cast<uint32_t>(data_written_ - n);
        memcpy(header + 16, &accum_before, 4);                        // 16-19: accumulated_before
        uint8_t frag = persistent_accumulating_ ? 1 : 0;
        header[24] = frag;                                            // 24: frag_state
        // 25-31: reserved

        fwrite(header, 1, 32, debug_traffic_fp_);

        // Write SSL data (handle circular buffer wrap)
        size_t to_end = capacity - pos;
        if (static_cast<size_t>(n) <= to_end) {
            fwrite(buffer + pos, 1, n, debug_traffic_fp_);
        } else {
            fwrite(buffer + pos, 1, to_end, debug_traffic_fp_);
            fwrite(buffer, 1, n - to_end, debug_traffic_fp_);
        }
        fflush(debug_traffic_fp_);
    }

    // Write TX debug record: 32-byte header + data sent
    // Magic "SSLT" distinguishes from RX records
    void write_debug_tx_record(const uint8_t* data, size_t len) {
        if (!debug_traffic_fp_ || len == 0) return;

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t ts_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        // Build 32-byte header
        uint8_t header[32] = {0};
        memcpy(header, "SSLT", 4);                                    // 0-3: magic (TX)
        memcpy(header + 4, &ts_ns, 8);                                // 4-11: timestamp_ns
        uint32_t bytes = static_cast<uint32_t>(len);
        memcpy(header + 12, &bytes, 4);                               // 12-15: bytes sent
        // 16-31: reserved for TX (no leftover/frag state)

        fwrite(header, 1, 32, debug_traffic_fp_);
        fwrite(data, 1, len, debug_traffic_fp_);
        fflush(debug_traffic_fp_);
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
            DEBUG_FPRINTF(stderr, "[WARN] message_batch_ resized to %zu (>%zu frames in single batch)\n",
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
    bool rx_callback_enabled_ = true; // False when shmem path provided (data flows to shm only)
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

    // Circular buffer batch state (unified for all buffer types)
    size_t batch_start_pos_ = 0;          // Logical write position where current batch starts
    size_t data_written_ = 0;             // Bytes of SSL data accumulated (not yet committed)

    // Fragment state (for fragmented WebSocket messages across SSL_reads)
    bool persistent_accumulating_ = false; // Fragment accumulation in progress
    uint8_t persistent_opcode_ = 0;        // Opcode of incomplete fragment (0x01=text, 0x02=binary)
    size_t persistent_accum_len_ = 0;      // Total accumulated payload length so far
    size_t persistent_parse_offset_ = 0;   // Bytes already parsed (for deferred commit resume)

    // Deferred commit: frame descriptors from partial batch
    static constexpr size_t MAX_PERSISTENT_FRAMES = 4096;
    ShmFrameDesc persistent_frame_descs_[MAX_PERSISTENT_FRAMES];
    uint16_t persistent_frame_count_ = 0;
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

    // Connection timing (for duration tracking)
    uint64_t connect_time_ns_ = 0;    // Timestamp when connected (clock_gettime MONOTONIC)
    uint64_t last_data_frame_ns_ = 0; // Timestamp of last data frame (for flow monitoring)
    uint32_t ping_without_data_count_ = 0; // Count consecutive PINGs without data frames

    // Subscription messages - populated by on_connect callback, sent automatically
    char subscribe_messages_[128][512];       // Max 128 messages, 512 bytes each
    size_t num_subscribe_messages_ = 0;       // Count set by callback
    bool subscribe_messages_sent_ = false;    // Flag: true after all sent
    std::function<void(char(*)[512], size_t&)> on_connect_;  // Callback to populate subscribe_messages_

    // Debug traffic recording (SSL_read data to file for debugging stuck issues)
    FILE* debug_traffic_fp_ = nullptr;
    bool debug_traffic_enabled_ = false;

#ifdef SIMULATOR_MODE
    // Simulator-only state (not compiled in production builds)
    FILE* sim_traffic_fp_ = nullptr;         // Replay file handle
    uint64_t sim_ssl_read_count_ = 0;        // SSL read counter for replay
    uint64_t sim_tx_count_ = 0;              // TX records skipped
    std::vector<uint8_t> sim_private_buffer_; // Private 4MB buffer (no shmem)
#endif
};
