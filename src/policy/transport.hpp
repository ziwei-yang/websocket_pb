// policy/transport.hpp
// Transport Layer Policy - Network Transport Abstraction
//
// This header provides transport implementations for different network stacks:
//   - BSDSocketTransport<EventPolicy>: BSD sockets + event loop (kernel TCP/IP stack)
//   - PacketTransport<PacketIO>: Policy-based userspace TCP/IP stack (e.g., XDPPacketIO)
//
// Architecture (PacketTransport<XDPPacketIO>):
//   Transport Policy (this file)
//       │
//       ├── Owns: TCP state, timers, retransmit queue, receive buffer
//       ├── Owns: All control flow (connect loop, send/recv, close)
//       ├── Uses: PacketIO policy (XDPPacketIO for AF_XDP zero-copy)
//       │
//       └── Uses: UserspaceStack (pure packet operations)
//                 ├── build_syn(), build_ack(), build_data(), build_fin()
//                 ├── parse_tcp() - parse raw frames
//                 └── process_tcp() - pure state machine
//
// XDP Mode Features:
//   - AF_XDP zero-copy mode (XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP)
//   - Native driver mode (XDP_FLAGS_DRV_MODE) for maximum performance
//   - NAPI modes: NAPI_IRQ, NAPI_TIMER, USER_POLL (SO_BUSY_POLL)
//   - NIC hardware timestamps via bpf_xdp_metadata_rx_timestamp()
//   - RX trickle workaround for igc driver TX completion stall
//
// TransportPolicy concept (unified interface):
//   - void init()
//   - void connect(const char* host, uint16_t port)
//   - ssize_t send(const void* buf, size_t len)
//   - ssize_t recv(void* buf, size_t len)
//   - void close()
//   - bool is_connected() const
//   - void set_wait_timeout(int timeout_ms)  // Event waiting config
//   - int wait()                              // Wait for data (epoll/select or busy-poll)
//   - int get_fd() const                      // For BSD sockets, -1 for XDP
//   - void* get_transport_ptr()               // For userspace transport BIO
//   - bool supports_ktls() const              // kTLS availability (false for XDP)

#pragma once

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <cstring>
#include <stdexcept>
#include <cstdio>
#include <chrono>
#include <thread>
#include "../core/timing.hpp"  // rdtsc(), calibrate_tsc_freq()

// macOS doesn't have MSG_NOSIGNAL, define as 0
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace websocket {

// Compile-time debug flag (for standalone transport.hpp compilation)
#ifndef WEBSOCKET_DEBUG_ENABLED_DEFINED
#define WEBSOCKET_DEBUG_ENABLED_DEFINED
constexpr bool debug_enabled =
#ifdef DEBUG
    true;
#else
    false;
#endif
#endif

namespace transport {

/**
 * BSD Socket Transport Policy (Templated on EventPolicy)
 *
 * Uses traditional BSD sockets with kernel TCP/IP stack.
 * Integrates event loop (epoll/select/io_uring/kqueue) for wait operations.
 *
 * Suitable for: Standard deployments, kTLS support, multi-platform
 *
 * Template parameter:
 *   EventPolicy - EpollPolicy, SelectPolicy, IoUringPolicy, or KqueuePolicy
 */
template<typename EventPolicy>
struct BSDSocketTransport {
    BSDSocketTransport() : fd_(-1), connected_(false) {}

    ~BSDSocketTransport() {
        close();
    }

    // Prevent copying
    BSDSocketTransport(const BSDSocketTransport&) = delete;
    BSDSocketTransport& operator=(const BSDSocketTransport&) = delete;

    // Allow moving
    BSDSocketTransport(BSDSocketTransport&& other) noexcept
        : fd_(other.fd_)
        , connected_(other.connected_)
        , event_(std::move(other.event_))
    {
        other.fd_ = -1;
        other.connected_ = false;
    }

    BSDSocketTransport& operator=(BSDSocketTransport&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = other.fd_;
            connected_ = other.connected_;
            event_ = std::move(other.event_);
            other.fd_ = -1;
            other.connected_ = false;
        }
        return *this;
    }

    /**
     * Initialize transport (event loop)
     */
    void init() {
        event_.init();
    }

    /**
     * Connect to remote host
     */
    void connect(const char* host, uint16_t port) {
        if (connected_) {
            throw std::runtime_error("Already connected");
        }

        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Enable TCP_NODELAY for low latency
        int flag = 1;
        if (::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
            printf("[WARN] Failed to set TCP_NODELAY: %s\n", strerror(errno));
        }

#ifdef SO_NOSIGPIPE
        // macOS/BSD: Prevent SIGPIPE on write to closed socket
        // Linux uses MSG_NOSIGNAL flag in send() instead
        if (::setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &flag, sizeof(flag)) < 0) {
            printf("[WARN] Failed to set SO_NOSIGPIPE: %s\n", strerror(errno));
        }
#endif

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
            throw std::runtime_error("getaddrinfo() returned no addresses");
        }

        auto* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
        addr->sin_port = htons(port);

        // Set non-blocking for async connect
        set_nonblocking();

        ret = ::connect(fd_, result->ai_addr, result->ai_addrlen);
        freeaddrinfo(result);

        if (ret < 0 && errno != EINPROGRESS) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error(std::string("connect() failed: ") + strerror(errno));
        }

        // Wait for connection with timeout
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(fd_, &write_fds);

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        ret = ::select(fd_ + 1, nullptr, &write_fds, nullptr, &tv);
        if (ret <= 0) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error("Connection timeout");
        }

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error(std::string("Connection failed: ") + strerror(so_error));
        }

        // Restore blocking mode for SSL handshake
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);
        }

        connected_ = true;
        printf("[BSD] Connected to %s:%u (fd=%d)\n", host, port, fd_);
    }

    /**
     * Send data
     */
    ssize_t send(const void* buf, size_t len) {
        if (!connected_ || fd_ < 0) {
            errno = ENOTCONN;
            return -1;
        }
        return ::send(fd_, buf, len, MSG_NOSIGNAL);
    }

    /**
     * Receive data
     */
    ssize_t recv(void* buf, size_t len) {
        if (!connected_ || fd_ < 0) {
            errno = ENOTCONN;
            return -1;
        }
        return ::recv(fd_, buf, len, 0);
    }

    /**
     * Close connection
     */
    void close() {
        if (fd_ >= 0) {
            event_.remove(fd_);
            ::close(fd_);
            fd_ = -1;
            connected_ = false;
        }
    }

    /**
     * Check if connected
     */
    bool is_connected() const { return connected_; }

    // =========================================================================
    // Event waiting (TransportPolicy interface)
    // =========================================================================

    /**
     * Set timeout for wait operations
     * @param timeout_ms Timeout in milliseconds (-1 = infinite)
     */
    void set_wait_timeout(int timeout_ms) {
        event_.set_wait_timeout(timeout_ms);
    }

    /**
     * Wait for data to be available
     * @return >0 if data ready, 0 on timeout, -1 on error
     */
    int wait() {
        return event_.wait_with_timeout();
    }

    /**
     * Get ready file descriptor after wait()
     */
    int get_ready_fd() const {
        return event_.get_ready_fd();
    }

    /**
     * Check if last wait() detected socket error (EPOLLHUP/EPOLLERR)
     * Call after wait() returns > 0 to detect peer disconnect
     */
    bool is_error() const {
        return event_.has_error();
    }

    // =========================================================================
    // SSL integration (TransportPolicy interface)
    // =========================================================================

    /**
     * Get file descriptor for SSL handshake
     */
    int get_fd() const { return fd_; }

    /**
     * Get transport pointer for userspace BIO (not used for BSD sockets)
     */
    void* get_transport_ptr() { return nullptr; }

    /**
     * Check if kTLS is supported (yes for BSD sockets on Linux)
     */
    bool supports_ktls() const {
#ifdef __linux__
        return true;
#else
        return false;
#endif
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /**
     * Set socket to non-blocking mode
     */
    void set_nonblocking() {
        if (fd_ < 0) return;
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags < 0) {
            throw std::runtime_error("fcntl(F_GETFL) failed");
        }
        if (fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
            throw std::runtime_error("fcntl(F_SETFL) failed");
        }
    }

    /**
     * Start event loop monitoring. Call AFTER SSL handshake is complete.
     * Sets non-blocking mode and registers with event loop.
     */
    void start_event_loop() {
        if (fd_ < 0) return;

        // Set non-blocking mode
        set_nonblocking();

        // Register with event loop for read events
        event_.add_read(fd_);
    }

    /**
     * Poll (no-op for BSD sockets - event loop handles this)
     */
    void poll() {
        // BSD sockets don't need explicit polling
    }

    /**
     * Get event policy name
     */
    static constexpr const char* event_policy_name() {
        return EventPolicy::name();
    }

    // =========================================================================
    // Debug Traffic Recording (controlled by websocket::debug_enabled)
    // =========================================================================

    /**
     * Enable recording of decrypted traffic to file
     * Called from WebSocketClient when debug_enabled is true
     */
    void enable_recording(const char* path) {
        if constexpr (websocket::debug_enabled) {
            if (recording_fp_) fclose(recording_fp_);
            recording_fp_ = fopen(path, "wb");
        } else {
            (void)path;
        }
    }

    /**
     * Disable traffic recording
     */
    void disable_recording() {
        if constexpr (websocket::debug_enabled) {
            if (recording_fp_) {
                fclose(recording_fp_);
                recording_fp_ = nullptr;
            }
        }
    }

    /**
     * Write RX traffic record: 32-byte header + decrypted SSL data
     * Header: "SSLR" magic, timestamp_ns, ssl_bytes, accumulated_before
     *
     * @param buffer     Circular buffer base pointer
     * @param pos        Write position in circular buffer
     * @param n          Bytes written
     * @param capacity   Buffer capacity (for wrap handling)
     * @param data_written  Total accumulated bytes (for accum_before calculation)
     */
    void write_record(uint8_t* buffer, size_t pos, ssize_t n, size_t capacity, size_t data_written) {
        if constexpr (websocket::debug_enabled) {
            if (!recording_fp_ || n <= 0) return;

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t ts_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

            // Build 32-byte header
            uint8_t header[32] = {0};
            memcpy(header, "SSLR", 4);                                    // 0-3: magic (RX)
            memcpy(header + 4, &ts_ns, 8);                                // 4-11: timestamp_ns
            uint32_t bytes = static_cast<uint32_t>(n);
            memcpy(header + 12, &bytes, 4);                               // 12-15: ssl_read_bytes
            // data_written already includes this read, so subtract to get "accum before"
            uint32_t accum_before = static_cast<uint32_t>(data_written - static_cast<size_t>(n));
            memcpy(header + 16, &accum_before, 4);                        // 16-19: accumulated_before
            // 20-31: reserved

            fwrite(header, 1, 32, recording_fp_);

            // Write SSL data (handle circular buffer wrap)
            size_t to_end = capacity - pos;
            if (static_cast<size_t>(n) <= to_end) {
                fwrite(buffer + pos, 1, n, recording_fp_);
            } else {
                fwrite(buffer + pos, 1, to_end, recording_fp_);
                fwrite(buffer, 1, n - to_end, recording_fp_);
            }
            fflush(recording_fp_);
        } else {
            (void)buffer; (void)pos; (void)n; (void)capacity; (void)data_written;
        }
    }

    /**
     * Write TX traffic record: 32-byte header + data sent
     * Header: "SSLT" magic, timestamp_ns, bytes_sent
     */
    void write_tx_record(const uint8_t* data, size_t len) {
        if constexpr (websocket::debug_enabled) {
            if (!recording_fp_ || len == 0) return;

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            uint64_t ts_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

            // Build 32-byte header
            uint8_t header[32] = {0};
            memcpy(header, "SSLT", 4);                                    // 0-3: magic (TX)
            memcpy(header + 4, &ts_ns, 8);                                // 4-11: timestamp_ns
            uint32_t bytes = static_cast<uint32_t>(len);
            memcpy(header + 12, &bytes, 4);                               // 12-15: bytes sent
            // 16-31: reserved

            fwrite(header, 1, 32, recording_fp_);
            fwrite(data, 1, len, recording_fp_);
            fflush(recording_fp_);
        } else {
            (void)data; (void)len;
        }
    }

private:
    int fd_;
    bool connected_;
    EventPolicy event_;
    FILE* recording_fp_ = nullptr;  // Debug traffic recording (optimized away when !debug_enabled)
};

} // namespace transport
} // namespace websocket

// Include XDP headers outside namespace to avoid conflicts
#ifdef USE_XDP
#include "../xdp/xdp_packet_io.hpp"
#include "../xdp/xdp_frame.hpp"
#include "../stack/userspace_stack.hpp"
#include <net/if.h>
#include <sys/ioctl.h>
#endif

namespace websocket {
namespace transport {

#ifdef USE_XDP

// NOTE: Legacy XDPUserspaceTransport has been removed.
// Use PacketTransport<XDPPacketIO> instead (see below).

// ============================================================================
// PacketTransport<PacketIO> - Policy-based Transport Abstraction
// ============================================================================
//
// This template abstracts TCP+SSL transport logic from the underlying
// packet I/O mechanism. The same transport logic works with:
//   - XDPPacketIO (AF_XDP zero-copy)
//   - DPDKPacketIO (future: DPDK)
//   - DisruptorPacketIO (future: pipeline-based)
//
// Architecture:
//   Application
//       │ send()/recv()
//       ▼
//   PacketTransport<PacketIO>
//       ├── PacketIO (pio_) - Zero-copy I/O, frame management, polling
//       ├── UserspaceStack (stack_) - Packet building/parsing
//       └── TCP State Machine - state_, tcp_params_, retransmit queue
//
// PacketTransport provides a policy-based userspace transport implementation
// with pluggable packet I/O backends (e.g., XDPPacketIO for AF_XDP).
// ============================================================================

/**
 * PacketTransport - Policy-based userspace transport
 *
 * Template Parameters:
 *   PacketIO - Packet I/O policy (e.g., XDPPacketIO)
 *
 * PacketIO concept requirements:
 *   - init(config) - Initialize I/O
 *   - close() - Cleanup
 *   - process_rx_frames() / mark_frame_consumed() - RX path (batch API)
 *   - claim_tx_frames() / commit_tx_frames() - TX path (batch API)
 *   - mark_frame_acked() - ACK-based release (auto FIFO release)
 *   - retransmit_frame() - Retransmit existing frame (TCP retransmit)
 *   - poll_wait() - Event polling
 *   - frame_idx_to_addr() / get_frame_ptr() / frame_ptr_to_idx() / frame_capacity() - Frame utilities
 *   - get_mode() / get_interface() - Configuration access
 *   - add_remote_ip() / set_local_ip() / is_bpf_enabled() - BPF filter
 *   - print_stats() - Statistics
 *   - stop_rx_trickle_thread() - Thread control
 */
template<typename PacketIO>
struct PacketTransport {
    PacketTransport()
        : pio_()
        , stack_()
        , state_(userspace_stack::TCPState::CLOSED)
        , connected_(false)
        , oldest_rx_hw_timestamp_ns_(0)
        , latest_rx_hw_timestamp_ns_(0)
        , hw_timestamp_count_(0)
        , hw_timestamp_byte_ct_(0)
    {}

    ~PacketTransport() {
        close();
    }

    // Prevent copying
    PacketTransport(const PacketTransport&) = delete;
    PacketTransport& operator=(const PacketTransport&) = delete;

    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * Initialize transport without DNS resolution (caller manages BPF filter)
     */
    void init(const char* interface, const char* bpf_path, bool zero_copy = true) {
        // Configure PacketIO
        typename std::remove_reference_t<decltype(pio_)>::config_type config;
        // Use structured binding to set config if it's XDPPacketIOConfig-like
        init_packet_io_config(config, interface, bpf_path, zero_copy);

        pio_.init(config);

        // Get local interface configuration
        uint8_t local_mac[6];
        uint32_t local_ip, gateway_ip, netmask;

        if (!get_interface_config(interface, local_mac, &local_ip, &gateway_ip, &netmask)) {
            throw std::runtime_error("Failed to get interface configuration");
        }

        // Initialize stack
        char local_ip_str[16], gateway_ip_str[16], netmask_str[16];
        ip_to_string(local_ip, local_ip_str);
        ip_to_string(gateway_ip, gateway_ip_str);
        ip_to_string(netmask, netmask_str);

        stack_.init(local_ip_str, gateway_ip_str, netmask_str, local_mac);

        // Initialize TCP params
        tcp_params_.local_ip = local_ip;

        // Set local IP in BPF filter
        if (pio_.is_bpf_enabled()) {
            pio_.set_local_ip(local_ip_str);
        }

        // Set up zero-copy receive buffer callback
        recv_buffer_.set_release_callback(frame_release_callback, this);

        printf("[PacketTransport] Initialized on %s\n", interface);
        printf("  Local IP:  %s\n", local_ip_str);
        printf("  Gateway:   %s\n", gateway_ip_str);
        printf("  MAC:       %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_mac[0], local_mac[1], local_mac[2],
               local_mac[3], local_mac[4], local_mac[5]);
    }

    /**
     * Initialize transport with DNS resolution and BPF filter setup
     */
    void init(const char* interface, const char* bpf_path,
              const char* domain, uint16_t port) {
        // First init without domain
        init(interface, bpf_path);

        // DNS resolution for exchange domain
        auto ips = resolve_hostname(domain);
        if (ips.empty()) {
            throw std::runtime_error(std::string("Failed to resolve domain: ") + domain);
        }

        // Configure BPF filter for all resolved IPs
        for (const auto& ip : ips) {
            add_exchange_ip(ip.c_str());
        }

        printf("[PacketTransport] Configured for %s:%u (%zu IPs)\n",
               domain, port, ips.size());
    }

    /**
     * Initialize transport with pre-configured PacketIO config
     * Used by DisruptorPacketIO which receives config from XDP Poll process
     *
     * @param config Pre-configured PacketIO config (e.g., DisruptorPacketIOConfig)
     */
    template<typename ConfigT>
    void init_with_pio_config(const ConfigT& config) {
        pio_.init(config);

        // Get interface name from conn_state if available
        const char* interface = nullptr;
        if constexpr (requires { config.conn_state; }) {
            if (config.conn_state && config.conn_state->interface_name[0] != '\0') {
                interface = config.conn_state->interface_name;
            }
        }

        if (!interface) {
            throw std::runtime_error("No interface name in config");
        }

        // Get local interface configuration
        uint8_t local_mac[6];
        uint32_t local_ip, gateway_ip, netmask;

        if (!get_interface_config(interface, local_mac, &local_ip, &gateway_ip, &netmask)) {
            throw std::runtime_error("Failed to get interface configuration");
        }

        // Initialize stack
        char local_ip_str[16], gateway_ip_str[16], netmask_str[16];
        ip_to_string(local_ip, local_ip_str);
        ip_to_string(gateway_ip, gateway_ip_str);
        ip_to_string(netmask, netmask_str);

        stack_.init(local_ip_str, gateway_ip_str, netmask_str, local_mac);

        // Initialize TCP params
        tcp_params_.local_ip = local_ip;

        // Set up zero-copy receive buffer callback
        recv_buffer_.set_release_callback(frame_release_callback, this);

        printf("[PacketTransport] Initialized with PIO config on %s\n", interface);
        printf("  Local IP:  %s\n", local_ip_str);
        printf("  Gateway:   %s\n", gateway_ip_str);
        printf("  MAC:       %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_mac[0], local_mac[1], local_mac[2],
               local_mac[3], local_mac[4], local_mac[5]);
    }

    // ========================================================================
    // Connection
    // ========================================================================

    /**
     * Connect to remote host via userspace TCP (3-way handshake)
     */
    void connect(const char* host, uint16_t port) {
        if (connected_) {
            throw std::runtime_error("Already connected");
        }

        // Resolve hostname
        struct addrinfo hints = {};
        struct addrinfo* result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(host, nullptr, &hints, &result);
        if (ret != 0 || !result || !result->ai_addr) {
            if (result) freeaddrinfo(result);
            throw std::runtime_error(std::string("Failed to resolve host: ") + host);
        }

        auto* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
        uint32_t remote_ip = ntohl(addr->sin_addr.s_addr);
        freeaddrinfo(result);

        // Convert IP to string for BPF filter and logging
        char remote_ip_str[INET_ADDRSTRLEN];
        struct in_addr in_addr_tmp;
        in_addr_tmp.s_addr = htonl(remote_ip);
        inet_ntop(AF_INET, &in_addr_tmp, remote_ip_str, sizeof(remote_ip_str));

        // Ensure resolved IP is in BPF filter
        if (pio_.is_bpf_enabled()) {
            pio_.add_remote_ip(remote_ip_str);
        }

        printf("[PacketTransport] Connecting to %s:%u (%s) via userspace TCP...\n",
               host, port, remote_ip_str);

        // Setup TCP parameters
        tcp_params_.remote_ip = remote_ip;
        tcp_params_.remote_port = port;
        tcp_params_.local_port = userspace_stack::UserspaceStack::generate_port();
        tcp_params_.snd_una = tcp_params_.snd_nxt = userspace_stack::UserspaceStack::generate_isn();
        tcp_params_.rcv_nxt = 0;
        tcp_params_.snd_wnd = userspace_stack::TCP_MAX_WINDOW;
        tcp_params_.rcv_wnd = userspace_stack::TCP_MAX_WINDOW;

        // Initialize retransmit queue
        if (tsc_freq_hz_ == 0) {
            tsc_freq_hz_ = calibrate_tsc_freq();
        }
        retransmit_queue_.init(tsc_freq_hz_, timers_.rto);

        // Send SYN using batch TX API
        uint32_t syn_frame_idx;
        size_t syn_len = 0;
        uint32_t claimed = pio_.claim_tx_frames(1, [&](uint32_t i, websocket::xdp::PacketFrameDescriptor& desc) {
            syn_frame_idx = pio_.frame_ptr_to_idx(desc.frame_ptr);
            uint8_t* syn_buffer = reinterpret_cast<uint8_t*>(desc.frame_ptr);
            syn_len = stack_.build_syn(syn_buffer, pio_.frame_capacity(), tcp_params_);
            desc.frame_len = static_cast<uint16_t>(syn_len);
        });

        if (claimed == 0 || syn_len == 0) {
            throw std::runtime_error("Failed to allocate TX frame for SYN");
        }

        pio_.commit_tx_frames(syn_frame_idx, syn_frame_idx);
        state_ = userspace_stack::TCPState::SYN_SENT;
        fprintf(stderr, "[PacketTransport] SYN sent (seq=%u, frame_idx=%u, len=%zu)\n",
                tcp_params_.snd_nxt - 1, syn_frame_idx, syn_len);

        // Add SYN to retransmit queue
        retransmit_queue_.add_ref(tcp_params_.snd_nxt, userspace_stack::TCP_FLAG_SYN,
                                  syn_frame_idx, static_cast<uint16_t>(syn_len), 0);
        tcp_params_.snd_nxt++;

        // Wait for SYN-ACK with timeout
        auto start = std::chrono::steady_clock::now();
        constexpr uint32_t timeout_ms = 5000;
        static int handshake_debug_count = 0;

        while (state_ == userspace_stack::TCPState::SYN_SENT) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();

            if (elapsed_ms >= timeout_ms) {
                fprintf(stderr, "[PacketTransport] Connection timeout - stats:\n");
                pio_.print_stats();
                state_ = userspace_stack::TCPState::CLOSED;
                throw std::runtime_error("Connection timeout");
            }

            if (handshake_debug_count < 5 && (elapsed_ms / 1000) > handshake_debug_count) {
                fprintf(stderr, "[PacketTransport] Handshake %lds - stats:\n", elapsed_ms / 1000);
                pio_.print_stats();
                handshake_debug_count++;
            }

            pio_.poll_wait();
            poll_rx_and_process();
            check_retransmit();

            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        if (state_ != userspace_stack::TCPState::ESTABLISHED) {
            throw std::runtime_error("Failed to establish connection");
        }

        connected_ = true;
        printf("[PacketTransport] Connected to %s:%u\n", host, port);
    }

    bool is_connected() const {
        return connected_ && state_ == userspace_stack::TCPState::ESTABLISHED;
    }

    // ========================================================================
    // Data Transfer
    // ========================================================================

    /**
     * Send data via userspace TCP (zero-copy path)
     */
    ssize_t send(const void* buf, size_t len) {
        if (!connected_ || state_ != userspace_stack::TCPState::ESTABLISHED) {
            errno = ENOTCONN;
            return -1;
        }

        if (!buf || len == 0) {
            return 0;
        }

        const uint8_t* data = static_cast<const uint8_t*>(buf);
        size_t sent = 0;

        while (sent < len) {
            size_t remaining = len - sent;
            size_t chunk_size = std::min(remaining, static_cast<size_t>(tcp_params_.snd_mss));

            uint32_t frame_idx;
            size_t frame_len = 0;
            uint32_t claimed = pio_.claim_tx_frames(1, [&](uint32_t i, websocket::xdp::PacketFrameDescriptor& desc) {
                frame_idx = pio_.frame_ptr_to_idx(desc.frame_ptr);
                uint8_t* frame_data = reinterpret_cast<uint8_t*>(desc.frame_ptr);
                frame_len = stack_.build_data(frame_data, pio_.frame_capacity(),
                                              tcp_params_, data + sent, chunk_size);
                desc.frame_len = static_cast<uint16_t>(frame_len);
            });

            if (claimed == 0) {
                if (sent > 0) break;
                errno = ENOBUFS;
                return -1;
            }

            if (frame_len == 0) {
                if (sent > 0) break;
                errno = EINVAL;
                return -1;
            }

            pio_.commit_tx_frames(frame_idx, frame_idx);

            retransmit_queue_.add_ref(tcp_params_.snd_nxt,
                                      userspace_stack::TCP_FLAG_ACK | userspace_stack::TCP_FLAG_PSH,
                                      frame_idx, static_cast<uint16_t>(frame_len),
                                      static_cast<uint16_t>(chunk_size));

            tcp_params_.snd_nxt += chunk_size;
            sent += chunk_size;
        }

        return static_cast<ssize_t>(sent);
    }

    /**
     * Receive data from userspace TCP
     */
    ssize_t recv(void* buf, size_t len) {
        if (!connected_) {
            errno = ENOTCONN;
            return -1;
        }

        if (!buf || len == 0) {
            return 0;
        }

        pio_.poll_wait();
        poll_rx_and_process();

        ssize_t result = recv_buffer_.read(static_cast<uint8_t*>(buf), len);

        if (result == 0) {
            if (state_ == userspace_stack::TCPState::ESTABLISHED) {
                errno = EAGAIN;
                return -1;
            }
            return 0;
        }

        if (result > 0) {
            const auto& stats = recv_buffer_.get_last_read_stats();
            consumed_recv_packet_count_ += stats.packet_count;
            if (consumed_recv_oldest_timestamp_ns_ == 0 && stats.oldest_timestamp_ns > 0) {
                consumed_recv_oldest_timestamp_ns_ = stats.oldest_timestamp_ns;
            }
            if (stats.latest_timestamp_ns > 0) {
                consumed_recv_latest_timestamp_ns_ = stats.latest_timestamp_ns;
            }
        }

        return result;
    }

    // ========================================================================
    // Polling
    // ========================================================================

    void set_wait_timeout(int timeout_ms) {
        poll_interval_us_ = timeout_ms * 1000;
        if (tsc_freq_hz_ == 0) {
            tsc_freq_hz_ = calibrate_tsc_freq();
        }
        if (poll_interval_us_ > 0 && tsc_freq_hz_ > 0) {
            timeout_cycles_ = ((uint64_t)poll_interval_us_ * tsc_freq_hz_) / 1000000ULL;
        } else {
            timeout_cycles_ = 0;
        }
    }

    int wait() {
        uint64_t start_cycle = rdtsc();

        do {
            pio_.poll_wait();
            poll_rx_and_process();

            if (recv_buffer_.available() > 0) {
                check_retransmit();
                return 1;
            }
        } while (timeout_cycles_ == 0 || (rdtsc() - start_cycle) < timeout_cycles_);

        check_retransmit();
        return 0;
    }

    void poll() {
        pio_.poll_wait();
        poll_rx_and_process();
        check_retransmit();
        // Note: FIFO release now happens automatically in mark_frame_acked()
    }

    // ========================================================================
    // Close
    // ========================================================================

    void close() {
        if (state_ == userspace_stack::TCPState::CLOSED) {
            return;
        }

        if (state_ == userspace_stack::TCPState::ESTABLISHED) {
            uint32_t fin_frame_idx;
            size_t fin_len = 0;
            uint32_t claimed = pio_.claim_tx_frames(1, [&](uint32_t i, websocket::xdp::PacketFrameDescriptor& desc) {
                fin_frame_idx = pio_.frame_ptr_to_idx(desc.frame_ptr);
                uint8_t* fin_buffer = reinterpret_cast<uint8_t*>(desc.frame_ptr);
                fin_len = stack_.build_fin(fin_buffer, pio_.frame_capacity(), tcp_params_);
                desc.frame_len = static_cast<uint16_t>(fin_len);
            });

            if (claimed > 0 && fin_len > 0) {
                pio_.commit_tx_frames(fin_frame_idx, fin_frame_idx);
                retransmit_queue_.add_ref(tcp_params_.snd_nxt,
                                          userspace_stack::TCP_FLAG_FIN | userspace_stack::TCP_FLAG_ACK,
                                          fin_frame_idx, static_cast<uint16_t>(fin_len), 0);
                tcp_params_.snd_nxt++;
                state_ = userspace_stack::TCPState::FIN_WAIT_1;
            }

            auto start = std::chrono::steady_clock::now();
            while (state_ != userspace_stack::TCPState::CLOSED &&
                   state_ != userspace_stack::TCPState::TIME_WAIT) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
                if (elapsed_ms >= 2000) break;

                poll_rx_and_process();
                check_retransmit();
                // Note: FIFO release now happens automatically in mark_frame_acked()
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }

        state_ = userspace_stack::TCPState::CLOSED;
        connected_ = false;
        retransmit_queue_.clear();
        recv_buffer_.clear();
        pio_.close();
    }

    // ========================================================================
    // SSL Integration
    // ========================================================================

    void* get_transport_ptr() { return this; }
    bool supports_ktls() const { return false; }
    int get_fd() const { return -1; }

    // ========================================================================
    // BPF Configuration
    // ========================================================================

    void add_exchange_ip(const char* ip) { pio_.add_remote_ip(ip); }
    void add_exchange_port(uint16_t port) { pio_.add_remote_port(port); }

    // ========================================================================
    // Statistics
    // ========================================================================

    void print_bpf_stats() const { pio_.print_stats(); }

    // ========================================================================
    // Hardware Timestamps
    // ========================================================================

    uint64_t get_recv_oldest_timestamp() const { return consumed_recv_oldest_timestamp_ns_; }
    uint64_t get_recv_latest_timestamp() const { return consumed_recv_latest_timestamp_ns_; }
    uint32_t get_recv_packet_count() const { return consumed_recv_packet_count_; }

    void reset_recv_stats() {
        consumed_recv_packet_count_ = 0;
        consumed_recv_oldest_timestamp_ns_ = 0;
        consumed_recv_latest_timestamp_ns_ = 0;
    }

    void reset_hw_timestamps() {
        oldest_rx_hw_timestamp_ns_ = 0;
        latest_rx_hw_timestamp_ns_ = 0;
        hw_timestamp_count_ = 0;
        hw_timestamp_byte_ct_ = 0;
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    const char* get_xdp_mode() const { return pio_.get_mode(); }
    const char* get_interface() const { return pio_.get_interface(); }
    uint32_t get_queue_id() const { return pio_.get_queue_id(); }
    bool is_bpf_enabled() const { return pio_.is_bpf_enabled(); }
    void stop_rx_trickle_thread() { pio_.stop_rx_trickle_thread(); }

    // Hardware timestamp statistics
    uint32_t get_hw_timestamp_count() const { return hw_timestamp_count_; }
    uint64_t get_hw_timestamp_byte_count() const { return hw_timestamp_byte_ct_; }

    PacketIO* get_packet_io() { return &pio_; }
    const userspace_stack::TCPParams& tcp_params() const { return tcp_params_; }
    const uint8_t* get_local_mac() const { return stack_.get_local_mac(); }
    const uint8_t* get_gateway_mac() const { return stack_.get_gateway_mac(); }

private:
    // ========================================================================
    // PacketIO Config Initialization (specialization helper)
    // ========================================================================

    // Default: assume XDPPacketIOConfig-like interface
    template<typename ConfigT>
    void init_packet_io_config(ConfigT& config, const char* interface,
                               const char* bpf_path, bool zero_copy) {
        config.interface = interface;
        config.bpf_path = bpf_path;
        config.zero_copy = zero_copy;
    }

    // ========================================================================
    // RX Processing
    // ========================================================================

    void poll_rx_and_process() {
        [[maybe_unused]] uint64_t poll_enter_cycle = rdtsc();
        pio_.process_rx_frames(SIZE_MAX, [this, poll_enter_cycle](uint32_t idx, websocket::xdp::PacketFrameDescriptor& desc) {
            uint32_t frame_idx = pio_.frame_ptr_to_idx(desc.frame_ptr);
            uint8_t* frame_data = reinterpret_cast<uint8_t*>(desc.frame_ptr);
            uint16_t frame_len = desc.frame_len;
            uint64_t hw_timestamp_ns = desc.nic_timestamp_ns;

            dbg_rx_total_++;

            if (hw_timestamp_ns > 0) {
                if (hw_timestamp_count_ == 0) {
                    oldest_rx_hw_timestamp_ns_ = hw_timestamp_ns;
                }
                latest_rx_hw_timestamp_ns_ = hw_timestamp_ns;
                hw_timestamp_count_++;
            }

            auto parsed = stack_.parse_tcp(frame_data, frame_len,
                                           tcp_params_.local_port,
                                           tcp_params_.remote_ip,
                                           tcp_params_.remote_port);

            bool frame_consumed = false;  // Track if frame was pushed to recv_buffer_

            if (parsed.valid) {
                dbg_rx_valid_++;
                if (parsed.payload_len > 0) dbg_rx_has_payload_++;
                auto result = stack_.process_tcp(state_, tcp_params_, parsed);

                if (result.state_changed) {
                    state_ = result.new_state;
                }

                switch (result.action) {
                case userspace_stack::TCPAction::SEND_ACK:
                    dbg_rx_send_ack_++;
                    if (parsed.flags & userspace_stack::TCP_FLAG_SYN) {
                        dbg_rx_syn_ack_++;
                    } else if (parsed.flags & userspace_stack::TCP_FLAG_FIN) {
                        dbg_rx_fin_++;
                    } else if (parsed.payload_len > 0) {
                        dbg_rx_ooo_data_++;
                    }
                    if (parsed.flags & userspace_stack::TCP_FLAG_SYN) {
                        tcp_params_.rcv_nxt = parsed.seq + 1;
                    } else if (parsed.flags & userspace_stack::TCP_FLAG_FIN) {
                        tcp_params_.rcv_nxt++;
                    }
                    send_ack();
                    break;

                case userspace_stack::TCPAction::DATA_RECEIVED:
                    dbg_rx_data_++;
                    if (result.data && result.data_len > 0) {
                        dbg_rx_data_bytes_ += result.data_len;
                        hw_timestamp_byte_ct_ += result.data_len;
                        uint64_t umem_addr = desc.frame_ptr;  // Use frame_ptr as umem_addr for compatibility
                        bool push_ok = recv_buffer_.push_frame(result.data, result.data_len,
                                                               frame_idx, umem_addr, hw_timestamp_ns);
                        if (push_ok) {
                            frame_consumed = true;  // Don't mark_frame_consumed now, recv_buffer_ will do it
                        } else {
                            dbg_rx_push_fail_++;
                        }
                        tcp_params_.rcv_nxt += result.data_len;
                        send_ack();
                    }
                    break;

                case userspace_stack::TCPAction::CLOSED:
                    connected_ = false;
                    break;

                default:
                    dbg_rx_other_action_++;
                    break;
                }

                if (parsed.flags & userspace_stack::TCP_FLAG_ACK) {
                    dbg_rx_has_ack_flag_++;
                    if (userspace_stack::seq_gt(parsed.ack, tcp_params_.snd_una)) {
                        dbg_rx_ack_advance_++;
                        uint32_t released_frames[256];
                        size_t released_count = retransmit_queue_.remove_acked(parsed.ack,
                                                                                released_frames, 256);
                        for (size_t i = 0; i < released_count; i++) {
                            pio_.mark_frame_acked(released_frames[i]);
                        }
                        tcp_params_.snd_una = parsed.ack;
                    }
                }

                tcp_params_.snd_wnd = parsed.window;
            } else {
                dbg_rx_invalid_++;
            }

            // Mark frame consumed if not pushed to recv_buffer_ (which manages its own release)
            if (!frame_consumed) {
                pio_.mark_frame_consumed(frame_idx);
            }
        });
    }

    // ========================================================================
    // TX Helpers
    // ========================================================================

    void send_ack() {
        // Pure ACKs go through ACK_OUTBOX (separate from data path)
        // This avoids congestion control tracking issues - ACKs don't need retransmit
        uint32_t frame_idx = pio_.commit_ack_frame([this](websocket::xdp::PacketFrameDescriptor& desc) {
            uint8_t* ack_buffer = reinterpret_cast<uint8_t*>(desc.frame_ptr);
            desc.frame_len = static_cast<uint16_t>(
                stack_.build_ack(ack_buffer, pio_.frame_capacity(), tcp_params_));
        });

        if (frame_idx == 0) {
            fprintf(stderr, "[TRANSPORT] WARNING: Failed to send ACK (ACK_OUTBOX full?)\n");
        }
    }

    // ========================================================================
    // Retransmit Handling
    // ========================================================================

    void check_retransmit() {
        uint64_t now_tsc = rdtsc();
        uint64_t rto_cycles = retransmit_queue_.get_rto_cycles();

        retransmit_queue_.for_each_expired(now_tsc, rto_cycles,
            [this, now_tsc](userspace_stack::RetransmitSegmentRef& ref) -> bool {
                ssize_t sent = pio_.retransmit_frame(ref.frame_idx, ref.frame_len);
                if (sent > 0) {
                    retransmit_queue_.mark_retransmitted(ref.seq, now_tsc);
                }
                return true;
            });

        if (retransmit_queue_.has_failed_segment()) {
            struct timespec ts_fatal;
            clock_gettime(CLOCK_MONOTONIC, &ts_fatal);
            fprintf(stderr, "[%ld.%06ld] [RETX] FATAL: Segment exceeded max retransmits, closing connection\n",
                    ts_fatal.tv_sec, ts_fatal.tv_nsec / 1000);
            state_ = userspace_stack::TCPState::CLOSED;
            connected_ = false;
        }
    }

    // ========================================================================
    // Utility
    // ========================================================================

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

    bool get_interface_config(const char* interface,
                             uint8_t* local_mac,
                             uint32_t* local_ip,
                             uint32_t* gateway_ip,
                             uint32_t* netmask) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return false;

        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

        if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
            ::close(fd);
            return false;
        }
        *local_ip = ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            ::close(fd);
            return false;
        }
        memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);

        if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
            ::close(fd);
            return false;
        }
        *netmask = ntohl(((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr);

        ::close(fd);
        *gateway_ip = (*local_ip & *netmask) | 1;

        return true;
    }

    void ip_to_string(uint32_t ip, char* buf) {
        snprintf(buf, 16, "%u.%u.%u.%u",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF);
    }

    static void frame_release_callback(uint32_t frame_idx, void* user_data) {
        auto* self = static_cast<PacketTransport*>(user_data);
        self->pio_.mark_frame_consumed(frame_idx);
    }

    // ========================================================================
    // Member Variables
    // ========================================================================

    PacketIO pio_;
    userspace_stack::UserspaceStack stack_;

    userspace_stack::TCPState state_;
    userspace_stack::TCPParams tcp_params_;
    userspace_stack::TCPTimers timers_;
    userspace_stack::ZeroCopyRetransmitQueue retransmit_queue_;
    userspace_stack::ZeroCopyReceiveBuffer recv_buffer_;

    bool connected_;

    uint64_t oldest_rx_hw_timestamp_ns_;
    uint64_t latest_rx_hw_timestamp_ns_;
    uint32_t hw_timestamp_count_;
    uint64_t hw_timestamp_byte_ct_;

    uint32_t consumed_recv_packet_count_ = 0;
    uint64_t consumed_recv_oldest_timestamp_ns_ = 0;
    uint64_t consumed_recv_latest_timestamp_ns_ = 0;

    int poll_interval_us_ = 0;
    uint64_t tsc_freq_hz_ = 0;
    uint64_t timeout_cycles_ = 0;

    // Debug RX accounting (always active, negligible overhead)
    uint32_t dbg_rx_total_ = 0;        // Frames delivered from RAW_INBOX
    uint32_t dbg_rx_valid_ = 0;        // Parsed as valid TCP
    uint32_t dbg_rx_invalid_ = 0;      // Failed TCP parse
    uint32_t dbg_rx_has_payload_ = 0;  // Valid TCP with payload_len > 0
    uint32_t dbg_rx_send_ack_ = 0;     // Action: SEND_ACK (SYN-ACK, FIN, OOO)
    uint32_t dbg_rx_syn_ack_ = 0;      // SEND_ACK due to SYN-ACK
    uint32_t dbg_rx_fin_ = 0;          // SEND_ACK due to FIN
    uint32_t dbg_rx_ooo_data_ = 0;     // SEND_ACK due to OOO data (payload>0, no SYN/FIN, seq!=rcv_nxt)
    uint32_t dbg_rx_data_ = 0;         // Action: DATA_RECEIVED
    uint32_t dbg_rx_data_bytes_ = 0;   // Total data bytes received
    uint32_t dbg_rx_push_fail_ = 0;    // recv_buffer_.push_frame() failed
    uint32_t dbg_rx_other_action_ = 0; // Action: NONE/CLOSED/other
    uint32_t dbg_rx_has_ack_flag_ = 0; // RX frames with ACK flag set
    uint32_t dbg_rx_ack_advance_ = 0;  // ACK advanced snd_una

public:
    void print_rx_debug_stats() const {
        fprintf(stderr, "[TRANSPORT-RX-STATS] total=%u valid=%u invalid=%u "
                        "has_payload=%u send_ack=%u(syn=%u fin=%u ooo=%u) "
                        "data=%u(%u bytes) push_fail=%u other=%u "
                        "ack_flag=%u ack_advance=%u\n",
                dbg_rx_total_, dbg_rx_valid_, dbg_rx_invalid_,
                dbg_rx_has_payload_,
                dbg_rx_send_ack_, dbg_rx_syn_ack_, dbg_rx_fin_, dbg_rx_ooo_data_,
                dbg_rx_data_, dbg_rx_data_bytes_,
                dbg_rx_push_fail_, dbg_rx_other_action_,
                dbg_rx_has_ack_flag_, dbg_rx_ack_advance_);
    }
};

#endif  // USE_XDP

} // namespace transport
} // namespace websocket

// ============================================================================
// C++20 TransportPolicyConcept - Compile-Time Validation
// ============================================================================

#if __cplusplus >= 202002L
#include <concepts>

namespace websocket {
namespace transport {

/**
 * TransportPolicyConcept - Defines required interface for transport policies
 *
 * All transport policies must provide:
 *   - init(...) - Initialize transport (variadic for different transports)
 *   - connect(host, port) - Establish TCP connection
 *   - send(buf, len) - Send data
 *   - recv(buf, len) - Receive data
 *   - close() - Close connection
 *   - is_connected() - Check connection state
 *   - wait() - Wait for data availability
 *   - set_wait_timeout(timeout_ms) - Configure wait timeout
 *   - get_fd() - Get file descriptor (-1 for userspace transports)
 *   - get_transport_ptr() - Get transport pointer for custom BIO
 *   - supports_ktls() - Check kTLS support
 *
 * Note: init() has different signatures for different transports:
 *   - BSDSocketTransport: init() - no arguments
 *   - PacketTransport<XDPPacketIO>: init(interface, bpf_path) - two arguments
 */
template<typename T>
concept TransportPolicyConcept = requires(T transport, const char* host, uint16_t port,
                                          const void* buf, void* recv_buf, size_t len,
                                          int timeout_ms) {
    // Connection lifecycle
    { transport.connect(host, port) } -> std::same_as<void>;
    { transport.close() } -> std::same_as<void>;
    { transport.is_connected() } -> std::convertible_to<bool>;

    // Data transfer
    { transport.send(buf, len) } -> std::convertible_to<ssize_t>;
    { transport.recv(recv_buf, len) } -> std::convertible_to<ssize_t>;

    // Event loop integration
    { transport.wait() } -> std::convertible_to<int>;
    { transport.set_wait_timeout(timeout_ms) } -> std::same_as<void>;

    // Transport introspection
    { transport.get_fd() } -> std::convertible_to<int>;
    { transport.get_transport_ptr() } -> std::convertible_to<void*>;
    { transport.supports_ktls() } -> std::convertible_to<bool>;
};

/**
 * FdBasedTransportConcept - Additional requirements for fd-based transports
 *
 * Extends TransportPolicyConcept with:
 *   - start_event_loop() - Register fd with event loop
 *   - get_ready_fd() - Get fd that triggered event
 */
template<typename T>
concept FdBasedTransportConcept = TransportPolicyConcept<T> && requires(T transport) {
    { transport.start_event_loop() } -> std::same_as<void>;
    { transport.get_ready_fd() } -> std::convertible_to<int>;
};

/**
 * UserspaceTransportConcept - Additional requirements for userspace transports
 *
 * Extends TransportPolicyConcept with:
 *   - poll() - Process pending packets
 *   - add_exchange_ip(ip) - Configure BPF filter for exchange IP
 *   - add_exchange_port(port) - Configure BPF filter for exchange port
 */
template<typename T>
concept UserspaceTransportConcept = TransportPolicyConcept<T> && requires(T transport,
                                                                           const char* ip,
                                                                           uint16_t port) {
    { transport.poll() } -> std::same_as<void>;
    { transport.add_exchange_ip(ip) } -> std::same_as<void>;
    { transport.add_exchange_port(port) } -> std::same_as<void>;
};

// Verify BSDSocketTransport conforms to concepts
template<typename EventPolicy>
concept BSDSocketTransportValid = FdBasedTransportConcept<BSDSocketTransport<EventPolicy>>;

// Note: PacketTransport validation is conditional on USE_XDP
#ifdef USE_XDP
static_assert(UserspaceTransportConcept<PacketTransport<websocket::xdp::XDPPacketIO>>,
              "PacketTransport<XDPPacketIO> must conform to UserspaceTransportConcept");
#endif

} // namespace transport
} // namespace websocket

#endif // C++20
