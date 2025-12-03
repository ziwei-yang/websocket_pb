// policy/transport.hpp
// Transport Layer Policy - Network Transport Abstraction
//
// This header provides transport implementations for different network stacks:
//   - BSDSocketTransport<EventPolicy>: BSD sockets + event loop (kernel TCP/IP stack)
//   - XDPUserspaceTransport: AF_XDP zero-copy + userspace TCP/IP stack (complete kernel bypass)
//
// Architecture (XDPUserspaceTransport):
//   Transport Policy (this file)
//       │
//       ├── Owns: TCP state, timers, retransmit queue, receive buffer
//       ├── Owns: All control flow (connect loop, send/recv, close)
//       ├── Owns: XDP I/O operations (xdp_transport.hpp)
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

namespace websocket {
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
class BSDSocketTransport {
public:
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

private:
    int fd_;
    bool connected_;
    EventPolicy event_;
};

} // namespace transport
} // namespace websocket

// Include XDP headers outside namespace to avoid conflicts
#ifdef USE_XDP
#include "../xdp/xdp_transport.hpp"
#include "../xdp/xdp_frame.hpp"
#include "../stack/userspace_stack.hpp"
#include <net/if.h>
#include <sys/ioctl.h>
#endif

namespace websocket {
namespace transport {

#ifdef USE_XDP
/**
 * XDP Userspace Transport Policy
 *
 * Uses XDP driver mode with userspace TCP/IP stack (complete kernel bypass).
 *
 * Architecture:
 *   - Stack: Pure packet building/parsing (no I/O, no control flow)
 *   - Transport: Owns all I/O and control flow (connect loops, retransmits, timers)
 *
 * This class owns:
 *   - TCP state machine (state_, tcp_params_)
 *   - Retransmit queue and timers
 *   - Receive buffer
 *   - XDP I/O operations
 */
class XDPUserspaceTransport {
public:
    XDPUserspaceTransport()
        : xdp_()
        , stack_()
        , state_(userspace_stack::TCPState::CLOSED)
        , connected_(false)
        , oldest_rx_hw_timestamp_ns_(0)
        , latest_rx_hw_timestamp_ns_(0)
        , hw_timestamp_count_(0)
    {}

    ~XDPUserspaceTransport() {
        close();
    }

    // Prevent copying
    XDPUserspaceTransport(const XDPUserspaceTransport&) = delete;
    XDPUserspaceTransport& operator=(const XDPUserspaceTransport&) = delete;

    /**
     * Initialize XDP transport with userspace stack
     *
     * @param interface Network interface name (e.g., "eth0", "enp108s0")
     * @param bpf_path Path to BPF object file
     */
    void init(const char* interface = "eth0",
              const char* bpf_path = "src/xdp/bpf/exchange_filter.bpf.o") {
        // Configure XDP
        websocket::xdp::XDPConfig config;
        config.interface = interface;
        config.queue_id = 0;
        config.frame_size = 4096;
        config.num_frames = 4096;
        config.zero_copy = true;
        config.batch_size = 64;

        xdp_.init(config, bpf_path);

        // Get local interface configuration
        uint8_t local_mac[6];
        uint32_t local_ip, gateway_ip, netmask;

        if (!get_interface_config(interface, local_mac, &local_ip, &gateway_ip, &netmask)) {
            throw std::runtime_error("Failed to get interface configuration");
        }

        // Initialize stack (pure packet ops only)
        char local_ip_str[16], gateway_ip_str[16], netmask_str[16];
        ip_to_string(local_ip, local_ip_str);
        ip_to_string(gateway_ip, gateway_ip_str);
        ip_to_string(netmask, netmask_str);

        stack_.init(local_ip_str, gateway_ip_str, netmask_str, local_mac);

        // Initialize TCP params
        tcp_params_.local_ip = local_ip;

        // Set local IP in BPF filter
        if (xdp_.is_bpf_enabled()) {
            xdp_.set_local_ip(local_ip_str);
        }

        // Set up zero-copy receive buffer callback
        recv_buffer_.set_release_callback(frame_release_callback, this);

        printf("[XDP-Userspace] Initialized on %s\n", interface);
        printf("  Local IP:  %s\n", local_ip_str);
        printf("  Gateway:   %s\n", gateway_ip_str);
        printf("  MAC:       %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_mac[0], local_mac[1], local_mac[2],
               local_mac[3], local_mac[4], local_mac[5]);
    }

    /**
     * Connect to remote host via userspace TCP (3-way handshake)
     *
     * ALL control flow is here in transport, not in stack.
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

        // Ensure resolved IP is in BPF filter (DNS round-robin may return different IPs)
        if (xdp_.is_bpf_enabled()) {
            xdp_.add_exchange_ip(remote_ip_str);
        }

        printf("[XDP-Userspace] Connecting to %s:%u (%s) via userspace TCP...\n", host, port, remote_ip_str);

        // Setup TCP parameters
        tcp_params_.remote_ip = remote_ip;
        tcp_params_.remote_port = port;
        tcp_params_.local_port = userspace_stack::UserspaceStack::generate_port();
        tcp_params_.snd_una = tcp_params_.snd_nxt = userspace_stack::UserspaceStack::generate_isn();
        tcp_params_.rcv_nxt = 0;
        tcp_params_.snd_wnd = userspace_stack::TCP_MAX_WINDOW;
        tcp_params_.rcv_wnd = userspace_stack::TCP_MAX_WINDOW;

        send_syn();
        state_ = userspace_stack::TCPState::SYN_SENT;

        // Add SYN to retransmit queue
        retransmit_queue_.add_segment(tcp_params_.snd_nxt, userspace_stack::TCP_FLAG_SYN, nullptr, 0);
        tcp_params_.snd_nxt++;  // SYN consumes one sequence number

        // Wait for SYN-ACK with timeout
        auto start = std::chrono::steady_clock::now();
        constexpr uint32_t timeout_ms = 5000;

        while (state_ == userspace_stack::TCPState::SYN_SENT) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();

            if (elapsed_ms >= timeout_ms) {
                state_ = userspace_stack::TCPState::CLOSED;
                throw std::runtime_error("Connection timeout");
            }

            // Poll XDP for RX frames and process
            poll_rx_and_process();

            // Check retransmissions
            check_retransmit();

            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        if (state_ != userspace_stack::TCPState::ESTABLISHED) {
            throw std::runtime_error("Failed to establish connection");
        }

        connected_ = true;
        printf("[XDP-Userspace] Connected to %s:%u\n", host, port);
    }

    /**
     * Send data via userspace TCP
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

        // NOTE: Caller must poll for ACKs via wait() to advance snd_una and open send window.
        // This function only sends data; it does not process incoming ACKs.
        while (sent < len) {
            size_t remaining = len - sent;
            size_t chunk_size = std::min(remaining, static_cast<size_t>(tcp_params_.snd_mss));

            send_data(data + sent, chunk_size);

            retransmit_queue_.add_segment(tcp_params_.snd_nxt,
                                          userspace_stack::TCP_FLAG_ACK | userspace_stack::TCP_FLAG_PSH,
                                          data + sent, static_cast<uint16_t>(chunk_size));

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

        // Use poll() to trigger SO_BUSY_POLL
        // This is critical for TX completion processing with igc driver
        xdp_.poll_wait();

        // Poll for incoming packets
        poll_rx_and_process();

        // Read from receive buffer
        return recv_buffer_.read(static_cast<uint8_t*>(buf), len);
    }

    int get_fd() const { return -1; }
    void set_nonblocking() { /* Always non-blocking */ }

    /**
     * Close TCP connection
     */
    void close() {
        if (state_ == userspace_stack::TCPState::CLOSED) {
            return;
        }

        if (state_ == userspace_stack::TCPState::ESTABLISHED) {
            send_fin();
            retransmit_queue_.add_segment(tcp_params_.snd_nxt,
                                          userspace_stack::TCP_FLAG_FIN | userspace_stack::TCP_FLAG_ACK,
                                          nullptr, 0);
            tcp_params_.snd_nxt++;
            state_ = userspace_stack::TCPState::FIN_WAIT_1;

            // Wait briefly for FIN-ACK
            auto start = std::chrono::steady_clock::now();
            while (state_ != userspace_stack::TCPState::CLOSED &&
                   state_ != userspace_stack::TCPState::TIME_WAIT) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
                if (elapsed_ms >= 2000) break;

                poll_rx_and_process();
                check_retransmit();
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        }

        state_ = userspace_stack::TCPState::CLOSED;
        connected_ = false;
        retransmit_queue_.clear();
        recv_buffer_.clear();
    }

    bool is_connected() const {
        return connected_ && state_ == userspace_stack::TCPState::ESTABLISHED;
    }

    /**
     * Poll for RX and handle retransmits (call periodically)
     *
     * Uses poll() on AF_XDP socket to trigger SO_BUSY_POLL behavior
     * which processes both RX and TX completions.
     * This is critical during SSL handshake where TX completion timing affects success.
     */
    void poll() {
        // Use poll() to trigger SO_BUSY_POLL for TX completions
        xdp_.poll_wait();

        poll_rx_and_process();
        check_retransmit();
    }

    // =========================================================================
    // Event waiting (TransportPolicy interface)
    // =========================================================================

    /**
     * Set timeout for wait operations
     * @param timeout_us Timeout in microseconds (0 = busy poll)
     *
     * For XDP, this controls the sleep between poll iterations.
     * 0 = pure busy-poll (lowest latency, highest CPU)
     */
    void set_wait_timeout(int timeout_us) {
        poll_interval_us_ = timeout_us;
    }

    /**
     * Wait for data to be available
     * @return 1 if data available in recv buffer, 0 otherwise
     *
     * Polls XDP for incoming packets and processes them.
     * For HFT, use set_wait_timeout(0) for pure busy-polling.
     *
     * Uses poll() on AF_XDP socket to trigger SO_BUSY_POLL behavior
     * which processes both RX and TX completions.
     */
    int wait() {
        // Use poll() to trigger SO_BUSY_POLL
        // This is critical for TX completion processing with igc driver
        // SO_BUSY_POLL causes kernel to busy-poll for configured duration
        xdp_.poll_wait();

        // Always check for RX data - poll() with timeout=0 may return 0
        // even when data is available from previous busy-poll iterations
        poll_rx_and_process();
        check_retransmit();

        // Sleep if configured (reduces CPU at cost of latency)
        // Note: For USER_POLL mode, this is usually 0 (pure busy-poll)
        if (poll_interval_us_ > 0) {
            struct timespec ts;
            ts.tv_sec = poll_interval_us_ / 1000000;
            ts.tv_nsec = (poll_interval_us_ % 1000000) * 1000;
            nanosleep(&ts, nullptr);
        }

        // Return 1 if we have data, 0 otherwise
        return recv_buffer_.available() > 0 ? 1 : 0;
    }

    /**
     * Get ready file descriptor (not applicable for XDP)
     * Always returns -1 as XDP doesn't use file descriptors
     */
    int get_ready_fd() const {
        return -1;
    }

    // =========================================================================
    // SSL integration (TransportPolicy interface)
    // =========================================================================

    /**
     * Get transport pointer for userspace BIO
     * Used by UserspaceTransportBIO to call send/recv
     */
    void* get_transport_ptr() { return this; }

    /**
     * Check if kTLS is supported (no for XDP - no kernel socket)
     */
    bool supports_ktls() const { return false; }

    // XDP/BPF configuration
    void add_exchange_ip(const char* ip) { xdp_.add_exchange_ip(ip); }
    void add_exchange_port(uint16_t port) { xdp_.add_exchange_port(port); }
    websocket::xdp::XDPTransport* get_xdp_transport() { return &xdp_; }
    const char* get_xdp_mode() const { return xdp_.get_xdp_mode(); }
    const char* get_interface() const { return xdp_.get_interface(); }
    uint32_t get_queue_id() const { return xdp_.get_queue_id(); }
    bool is_bpf_enabled() const { return xdp_.is_bpf_enabled(); }
    void print_bpf_stats() const { xdp_.print_bpf_stats(); }
    void stop_rx_trickle_thread() { xdp_.stop_rx_trickle_thread(); }

    /**
     * Get oldest RX hardware timestamp since last reset (Stage 1)
     * For multi-packet messages, this is the timestamp of the first packet
     * @return Hardware timestamp in nanoseconds (CLOCK_REALTIME domain for XDP), 0 if unavailable
     */
    uint64_t get_oldest_rx_hw_timestamp() const { return oldest_rx_hw_timestamp_ns_; }

    /**
     * Get latest RX hardware timestamp since last reset (Stage 1)
     * For multi-packet messages, this is the timestamp of the most recent packet
     * @return Hardware timestamp in nanoseconds (CLOCK_REALTIME domain for XDP), 0 if unavailable
     */
    uint64_t get_latest_rx_hw_timestamp() const { return latest_rx_hw_timestamp_ns_; }

    /**
     * Get count of packets with hardware timestamps since last reset
     * @return Number of packets timestamped (>1 indicates multi-packet message)
     */
    uint32_t get_hw_timestamp_count() const { return hw_timestamp_count_; }

    /**
     * Reset hardware timestamp tracking for new message
     * Call this after copying timestamps to timing_record_t
     */
    void reset_hw_timestamps() {
        oldest_rx_hw_timestamp_ns_ = 0;
        latest_rx_hw_timestamp_ns_ = 0;
        hw_timestamp_count_ = 0;
    }

private:
    // =========================================================================
    // PACKET SENDING (uses stack's pure packet building)
    // =========================================================================

    void send_syn() {
        auto [buffer, capacity] = alloc_tx_buffer();
        if (!buffer) {
            throw std::runtime_error("Failed to allocate TX buffer for SYN");
        }

        size_t len = stack_.build_syn(buffer, capacity, tcp_params_);
        if (len == 0) {
            throw std::runtime_error("Failed to build SYN packet");
        }

        send_tx_buffer(len);
    }

    void send_ack() {
        auto [buffer, capacity] = alloc_tx_buffer();
        if (!buffer) return;

        size_t len = stack_.build_ack(buffer, capacity, tcp_params_);
        if (len > 0) {
            send_tx_buffer(len);
        }
    }

    void send_data(const uint8_t* data, size_t data_len) {
        auto [buffer, capacity] = alloc_tx_buffer();
        if (!buffer) {
            throw std::runtime_error("Failed to allocate TX buffer for data");
        }

        size_t len = stack_.build_data(buffer, capacity, tcp_params_, data, data_len);
        if (len == 0) {
            throw std::runtime_error("Failed to build data packet");
        }

        send_tx_buffer(len);
    }

    void send_fin() {
        auto [buffer, capacity] = alloc_tx_buffer();
        if (!buffer) return;

        size_t len = stack_.build_fin(buffer, capacity, tcp_params_);
        if (len > 0) {
            send_tx_buffer(len);
        }
    }

    // =========================================================================
    // RX PROCESSING
    // =========================================================================

    void poll_rx_and_process() {
        // Process ALL available packets in the RX ring
        websocket::xdp::XDPFrame* frame = xdp_.peek_rx_frame();

        while (frame) {
            // Capture hardware timestamp from XDP metadata
            if (frame->hw_timestamp_ns > 0) {
                if (hw_timestamp_count_ == 0) {
                    oldest_rx_hw_timestamp_ns_ = frame->hw_timestamp_ns;
                }
                latest_rx_hw_timestamp_ns_ = frame->hw_timestamp_ns;
                hw_timestamp_count_++;
            }

            auto parsed = stack_.parse_tcp(frame->data, frame->len,
                                           tcp_params_.local_port,
                                           tcp_params_.remote_ip,
                                           tcp_params_.remote_port);

            if (parsed.valid) {
                auto result = stack_.process_tcp(state_, tcp_params_, parsed);

                if (result.state_changed) {
                    state_ = result.new_state;
                }

                switch (result.action) {
                case userspace_stack::TCPAction::SEND_ACK:
                    if (parsed.flags & userspace_stack::TCP_FLAG_SYN) {
                        tcp_params_.rcv_nxt = parsed.seq + 1;
                    } else if (parsed.flags & userspace_stack::TCP_FLAG_FIN) {
                        tcp_params_.rcv_nxt++;
                    }
                    send_ack();
                    break;

                case userspace_stack::TCPAction::DATA_RECEIVED:
                    if (result.data && result.data_len > 0) {
                        uint64_t umem_addr = xdp_.release_rx_frame(frame, true);
                        if (umem_addr != 0) {
                            recv_buffer_.push_frame(result.data, result.data_len, umem_addr);
                            frame = nullptr;
                        }
                        tcp_params_.rcv_nxt += result.data_len;
                        send_ack();
                    }
                    break;

                case userspace_stack::TCPAction::CLOSED:
                    connected_ = false;
                    break;

                default:
                    break;
                }

                // Process ACKs (update snd_una, remove from retransmit queue)
                if (parsed.flags & userspace_stack::TCP_FLAG_ACK) {
                    if (userspace_stack::seq_gt(parsed.ack, tcp_params_.snd_una)) {
                        retransmit_queue_.remove_acked(parsed.ack);
                        tcp_params_.snd_una = parsed.ack;
                    }
                }

                // Update window
                tcp_params_.snd_wnd = parsed.window;
            }

            // Release frame if not already handled by zero-copy path
            if (frame != nullptr) {
                xdp_.release_rx_frame(frame);
            }

            // Try to get next packet
            frame = xdp_.peek_rx_frame();
        }
    }

    // =========================================================================
    // RETRANSMIT HANDLING
    // =========================================================================

    void check_retransmit() {
        auto segments = retransmit_queue_.get_retransmit_segments(timers_.rto);

        for (auto* seg : segments) {
            // Retransmit the segment
            auto [buffer, capacity] = alloc_tx_buffer();
            if (!buffer) continue;

            // Build packet with original seq number
            userspace_stack::TCPParams retx_params = tcp_params_;
            retx_params.snd_nxt = seg->seq;

            size_t len = stack_.build_tcp(buffer, capacity, retx_params, seg->flags,
                                          seg->data, seg->len);
            if (len > 0) {
                send_tx_buffer(len);
                retransmit_queue_.mark_retransmitted(seg->seq);
            }
        }

        // Check for failed segments
        if (retransmit_queue_.has_failed_segment()) {
            state_ = userspace_stack::TCPState::CLOSED;
            connected_ = false;
        }
    }

    // =========================================================================
    // XDP I/O HELPERS
    // =========================================================================

    std::pair<uint8_t*, size_t> alloc_tx_buffer() {
        current_tx_frame_ = xdp_.get_tx_frame();
        if (!current_tx_frame_) {
            return {nullptr, 0};
        }
        return {current_tx_frame_->data, current_tx_frame_->capacity};
    }

    void send_tx_buffer(size_t len) {
        if (!current_tx_frame_) return;
        xdp_.send_frame(current_tx_frame_, len);
        current_tx_frame_ = nullptr;
    }

    // =========================================================================
    // UTILITY
    // =========================================================================

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

    // XDP and Stack (pure packet ops)
    websocket::xdp::XDPTransport xdp_;
    userspace_stack::UserspaceStack stack_;

    // TCP state (owned by transport, not stack)
    userspace_stack::TCPState state_;
    userspace_stack::TCPParams tcp_params_;
    userspace_stack::TCPTimers timers_;
    userspace_stack::RetransmitQueue retransmit_queue_;
    userspace_stack::ZeroCopyReceiveBuffer recv_buffer_;  // Zero-copy: holds UMEM frame refs

    // Connection state
    bool connected_;

    // Stage 1: Hardware timestamps from NIC (nanoseconds, CLOCK_REALTIME domain)
    // Track oldest/latest for multi-packet messages
    uint64_t oldest_rx_hw_timestamp_ns_;  // First packet timestamp
    uint64_t latest_rx_hw_timestamp_ns_;  // Most recent packet timestamp
    uint32_t hw_timestamp_count_;         // Packets received since last reset

    // Polling configuration
    int poll_interval_us_ = 0;  // 0 = busy poll (default for HFT)

    // Current TX frame
    websocket::xdp::XDPFrame* current_tx_frame_ = nullptr;

    // Static callback for releasing frames from ZeroCopyReceiveBuffer
    static void frame_release_callback(uint64_t umem_addr, void* user_data) {
        auto* self = static_cast<XDPUserspaceTransport*>(user_data);
        self->xdp_.refill_frame(umem_addr);
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
 *   - XDPUserspaceTransport: init(interface, bpf_path) - two arguments
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

// Note: XDPUserspaceTransport validation is conditional on USE_XDP
#ifdef USE_XDP
static_assert(UserspaceTransportConcept<XDPUserspaceTransport>,
              "XDPUserspaceTransport must conform to UserspaceTransportConcept");
#endif

} // namespace transport
} // namespace websocket

#endif // C++20
