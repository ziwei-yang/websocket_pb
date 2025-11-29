// policy/transport.hpp
// Transport Layer Policy - Network Transport Abstraction
//
// This header provides transport implementations for different network stacks:
//   - BSDSocketTransport: Traditional BSD sockets (kernel TCP/IP stack)
//   - XDPUserspaceTransport: XDP + Userspace TCP/IP stack (complete kernel bypass)
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
// TransportPolicy concept:
//   - void init()
//   - void connect(const char* host, uint16_t port)
//   - ssize_t send(const void* buf, size_t len)
//   - ssize_t recv(void* buf, size_t len)
//   - int get_fd() const  // For BSD sockets, -1 for XDP
//   - void set_nonblocking()
//   - void close()
//   - void poll()         // For XDP: process RX and retransmits
//   - bool is_connected() const

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
 * BSD Socket Transport Policy
 *
 * Uses traditional BSD sockets with kernel TCP/IP stack.
 * Suitable for: Standard deployments, kTLS support, multi-platform
 */
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
    {
        other.fd_ = -1;
        other.connected_ = false;
    }

    BSDSocketTransport& operator=(BSDSocketTransport&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = other.fd_;
            connected_ = other.connected_;
            other.fd_ = -1;
            other.connected_ = false;
        }
        return *this;
    }

    void init() {
        // No initialization needed for BSD sockets
    }

    void connect(const char* host, uint16_t port) {
        if (connected_) {
            throw std::runtime_error("Already connected");
        }

        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        int flag = 1;
        if (::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
            printf("[WARN] Failed to set TCP_NODELAY: %s\n", strerror(errno));
        }

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

        set_nonblocking();

        ret = ::connect(fd_, result->ai_addr, result->ai_addrlen);
        freeaddrinfo(result);

        if (ret < 0 && errno != EINPROGRESS) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error(std::string("connect() failed: ") + strerror(errno));
        }

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

        connected_ = true;
        printf("[BSD] Connected to %s:%u (fd=%d)\n", host, port, fd_);
    }

    ssize_t send(const void* buf, size_t len) {
        if (!connected_ || fd_ < 0) {
            errno = ENOTCONN;
            return -1;
        }
        return ::send(fd_, buf, len, 0);
    }

    ssize_t recv(void* buf, size_t len) {
        if (!connected_ || fd_ < 0) {
            errno = ENOTCONN;
            return -1;
        }
        return ::recv(fd_, buf, len, 0);
    }

    int get_fd() const { return fd_; }

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

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
            connected_ = false;
        }
    }

    bool is_connected() const { return connected_; }

private:
    int fd_;
    bool connected_;
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
    {}

    ~XDPUserspaceTransport() {
        close();
    }

    // Prevent copying
    XDPUserspaceTransport(const XDPUserspaceTransport&) = delete;
    XDPUserspaceTransport& operator=(const XDPUserspaceTransport&) = delete;

    /**
     * Initialize XDP transport with userspace stack
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

        printf("[XDP-Userspace] Connecting to %s:%u via userspace TCP...\n", host, port);

        // Setup TCP parameters
        tcp_params_.remote_ip = remote_ip;
        tcp_params_.remote_port = port;
        tcp_params_.local_port = userspace_stack::UserspaceStack::generate_port();
        tcp_params_.snd_una = tcp_params_.snd_nxt = userspace_stack::UserspaceStack::generate_isn();
        tcp_params_.rcv_nxt = 0;
        tcp_params_.snd_wnd = userspace_stack::TCP_MAX_WINDOW;
        tcp_params_.rcv_wnd = userspace_stack::TCP_MAX_WINDOW;

        // Send SYN
        printf("[TCP] Sending SYN to %s:%u (local port %u, seq=%u)\n",
               userspace_stack::UserspaceStack::ip_to_string(remote_ip).c_str(),
               port, tcp_params_.local_port, tcp_params_.snd_nxt);

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

        while (sent < len) {
            // Poll for incoming packets (ACKs)
            poll_rx_and_process();

            // Calculate chunk size (MSS limit)
            size_t remaining = len - sent;
            size_t chunk_size = std::min(remaining, static_cast<size_t>(tcp_params_.snd_mss));

            // Build and send data packet
            send_data(data + sent, chunk_size);

            // Add to retransmit queue
            retransmit_queue_.add_segment(tcp_params_.snd_nxt,
                                          userspace_stack::TCP_FLAG_ACK | userspace_stack::TCP_FLAG_PSH,
                                          data + sent, static_cast<uint16_t>(chunk_size));

            tcp_params_.snd_nxt += chunk_size;
            sent += chunk_size;
        }

        // Poll after sending
        poll_rx_and_process();

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
            // Send FIN
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
     */
    void poll() {
        poll_rx_and_process();
        check_retransmit();
    }

    // XDP/BPF configuration
    void add_exchange_ip(const char* ip) { xdp_.add_exchange_ip(ip); }
    void add_exchange_port(uint16_t port) { xdp_.add_exchange_port(port); }
    websocket::xdp::XDPTransport* get_xdp_transport() { return &xdp_; }
    const char* get_xdp_mode() const { return xdp_.get_xdp_mode(); }
    const char* get_interface() const { return xdp_.get_interface(); }
    uint32_t get_queue_id() const { return xdp_.get_queue_id(); }
    bool is_bpf_enabled() const { return xdp_.is_bpf_enabled(); }
    void print_bpf_stats() const { xdp_.print_bpf_stats(); }

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
        websocket::xdp::XDPFrame* frame = xdp_.peek_rx_frame();
        if (!frame) return;

        // Parse the TCP packet using stack's pure parsing
        auto parsed = stack_.parse_tcp(frame->data, frame->len,
                                       tcp_params_.local_port,
                                       tcp_params_.remote_ip,
                                       tcp_params_.remote_port);

        if (parsed.valid) {
            // Process through state machine (pure function)
            auto result = stack_.process_tcp(state_, tcp_params_, parsed);

            // Handle state transition
            if (result.state_changed) {
                state_ = result.new_state;
            }

            // Handle action
            switch (result.action) {
            case userspace_stack::TCPAction::SEND_ACK:
                // Update rcv_nxt before sending ACK
                if (parsed.flags & userspace_stack::TCP_FLAG_SYN) {
                    tcp_params_.rcv_nxt = parsed.seq + 1;
                } else if (parsed.flags & userspace_stack::TCP_FLAG_FIN) {
                    tcp_params_.rcv_nxt++;
                }
                send_ack();
                break;

            case userspace_stack::TCPAction::DATA_RECEIVED:
                // Zero-copy: push frame reference to receive buffer
                if (result.data && result.data_len > 0) {
                    // Release RX ring but defer FILL ring refill
                    uint64_t umem_addr = xdp_.release_rx_frame_deferred(frame);
                    if (umem_addr != 0) {
                        // Push frame ref - data stays in UMEM until SSL consumes it
                        recv_buffer_.push_frame(result.data, result.data_len, umem_addr);
                        frame = nullptr;  // Mark as handled (don't release again)
                    }
                    tcp_params_.rcv_nxt += result.data_len;
                    send_ack();
                }
                break;

            case userspace_stack::TCPAction::CONNECTED:
                printf("[TCP] Connection ESTABLISHED!\n");
                break;

            case userspace_stack::TCPAction::CLOSED:
                printf("[TCP] Connection closed\n");
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
