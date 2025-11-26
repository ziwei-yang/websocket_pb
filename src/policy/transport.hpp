// policy/transport.hpp
// Transport layer policy interface
//
// Abstracts the underlying network transport mechanism:
//   - BSDSocketTransport: Traditional BSD sockets (kernel TCP/IP stack)
//   - DPDKTransport: DPDK userspace networking (bypass kernel)
//
// TransportPolicy concept:
//   - void init()
//   - void connect(const char* host, uint16_t port)
//   - ssize_t send(const void* buf, size_t len)
//   - ssize_t recv(void* buf, size_t len)
//   - int get_fd() const  // For BSD sockets, -1 for DPDK
//   - void set_nonblocking()
//   - void close()
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

    /**
     * Initialize transport (no-op for BSD sockets)
     */
    void init() {
        // No initialization needed for BSD sockets
    }

    /**
     * Connect to remote host via TCP
     *
     * @param host Hostname or IP address
     * @param port Port number
     * @throws std::runtime_error on connection failure
     */
    void connect(const char* host, uint16_t port) {
        if (connected_) {
            throw std::runtime_error("Already connected");
        }

        // Create socket
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Enable TCP_NODELAY for low-latency (disable Nagle's algorithm)
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

        // Set port
        auto* addr = reinterpret_cast<struct sockaddr_in*>(result->ai_addr);
        addr->sin_port = htons(port);

        // Connect with timeout
        set_nonblocking();

        ret = ::connect(fd_, result->ai_addr, result->ai_addrlen);
        freeaddrinfo(result);

        if (ret < 0 && errno != EINPROGRESS) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error(std::string("connect() failed: ") + strerror(errno));
        }

        // Wait for connection with 5-second timeout
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

        // Check for socket errors
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

    /**
     * Send data via socket
     *
     * @param buf Data buffer
     * @param len Data length
     * @return Number of bytes sent, or -1 on error (check errno)
     */
    ssize_t send(const void* buf, size_t len) {
        if (!connected_ || fd_ < 0) {
            errno = ENOTCONN;
            return -1;
        }
        return ::send(fd_, buf, len, 0);
    }

    /**
     * Receive data from socket
     *
     * @param buf Buffer to store received data
     * @param len Buffer size
     * @return Number of bytes received, 0 on EOF, -1 on error (check errno)
     */
    ssize_t recv(void* buf, size_t len) {
        if (!connected_ || fd_ < 0) {
            errno = ENOTCONN;
            return -1;
        }
        return ::recv(fd_, buf, len, 0);
    }

    /**
     * Get socket file descriptor
     *
     * @return File descriptor, or -1 if not connected
     */
    int get_fd() const {
        return fd_;
    }

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
     * Close socket connection
     */
    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
            connected_ = false;
        }
    }

    /**
     * Check if transport is connected
     */
    bool is_connected() const {
        return connected_;
    }

private:
    int fd_;
    bool connected_;
};

} // namespace transport
} // namespace websocket

// Include XDP headers outside namespace to avoid conflicts
#ifdef USE_XDP
#include "../xdp/xdp_transport.hpp"
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
 * Suitable for: Ultra-low latency HFT, sub-microsecond packet processing
 *
 * Architecture:
 *   Application → XDPUserspaceTransport → Userspace TCP/IP → XDP (AF_XDP) → NIC
 *
 * Performance:
 *   - RX latency: ~1-2μs (NIC to app)
 *   - TX latency: ~1μs (app to wire)
 *   - 5-25x faster than kernel stack
 */
class XDPUserspaceTransport {
public:
    XDPUserspaceTransport()
        : xdp_()
        , stack_()
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
     *
     * @param interface Network interface (e.g., "enp108s0")
     * @param enable_bpf Enable eBPF packet filtering (default: true)
     * @param bpf_path Path to BPF object file
     */
    void init(const char* interface = "eth0",
              bool enable_bpf = true,
              const char* bpf_path = "src/xdp/bpf/exchange_filter.bpf.o") {
        // Configure XDP
        websocket::xdp::XDPConfig config;
        config.interface = interface;
        config.queue_id = 0;
        config.frame_size = 4096;  // Increased from 2048 to handle MTU-sized packets
        config.num_frames = 4096;
        config.zero_copy = true;  // Enable zero-copy for HFT performance
        config.batch_size = 64;

        // Initialize XDP transport with BPF filtering
        xdp_.init(config, enable_bpf, bpf_path);

        // Get local interface configuration
        uint8_t local_mac[6];
        uint32_t local_ip, gateway_ip, netmask;

        if (!get_interface_config(interface, local_mac, &local_ip, &gateway_ip, &netmask)) {
            throw std::runtime_error("Failed to get interface configuration");
        }

        // Initialize userspace TCP/IP stack
        char local_ip_str[16], gateway_ip_str[16], netmask_str[16];
        ip_to_string(local_ip, local_ip_str);
        ip_to_string(gateway_ip, gateway_ip_str);
        ip_to_string(netmask, netmask_str);

        stack_.init(&xdp_, local_ip_str, gateway_ip_str, netmask_str, local_mac);

        // Phase 1: Set local IP in BPF filter for destination-based filtering
        if (xdp_.is_bpf_enabled()) {
            xdp_.set_local_ip(local_ip_str);
        }

        printf("[XDP-Userspace] Initialized on %s\n", interface);
        printf("  Local IP:  %s\n", local_ip_str);
        printf("  Gateway:   %s\n", gateway_ip_str);
        printf("  MAC:       %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_mac[0], local_mac[1], local_mac[2],
               local_mac[3], local_mac[4], local_mac[5]);
    }

    /**
     * Connect to remote host via userspace TCP
     *
     * @param host Hostname or IP address
     * @param port Port number
     * @throws std::runtime_error on connection failure
     */
    void connect(const char* host, uint16_t port) {
        if (connected_) {
            throw std::runtime_error("Already connected");
        }

        // Resolve hostname to IP
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

        // Connect via userspace TCP stack (3-way handshake)
        stack_.connect(remote_ip, port, 5000);

        connected_ = true;
        printf("[XDP-Userspace] Connected to %s:%u\n", host, port);
    }

    /**
     * Send data via userspace TCP
     *
     * @param buf Data buffer
     * @param len Data length
     * @return Number of bytes sent, or -1 on error (check errno)
     */
    ssize_t send(const void* buf, size_t len) {
        if (!connected_) {
            errno = ENOTCONN;
            return -1;
        }

        // Poll stack before sending
        stack_.poll();

        ssize_t result = stack_.send(buf, len);

        // Poll after sending to process ACKs
        stack_.poll();

        return result;
    }

    /**
     * Receive data from userspace TCP
     *
     * @param buf Buffer to store received data
     * @param len Buffer size
     * @return Number of bytes received, 0 on EOF, -1 on error (check errno)
     */
    ssize_t recv(void* buf, size_t len) {
        if (!connected_) {
            errno = ENOTCONN;
            return -1;
        }

        // Poll stack to process incoming packets
        stack_.poll();

        return stack_.recv(buf, len);
    }

    /**
     * Get file descriptor (not available for userspace stack)
     *
     * @return -1 (no kernel FD for userspace TCP)
     */
    int get_fd() const {
        return -1;  // Userspace stack doesn't have kernel FD
    }

    /**
     * Set non-blocking mode (userspace stack is always non-blocking)
     */
    void set_nonblocking() {
        // Userspace stack is inherently non-blocking
    }

    /**
     * Close TCP connection
     */
    void close() {
        if (connected_) {
            stack_.close();
            connected_ = false;
        }
    }

    /**
     * Check if transport is connected
     */
    bool is_connected() const {
        return connected_ && stack_.is_connected();
    }

    /**
     * Get XDP transport for SSL handshake
     */
    websocket::xdp::XDPTransport* get_xdp_transport() {
        return &xdp_;
    }

    /**
     * Add exchange IP to BPF filter
     */
    void add_exchange_ip(const char* ip) {
        xdp_.add_exchange_ip(ip);
    }

    /**
     * Add exchange port to BPF filter
     */
    void add_exchange_port(uint16_t port) {
        xdp_.add_exchange_port(port);
    }

    /**
     * Poll userspace stack (must be called periodically)
     */
    void poll() {
        stack_.poll();
    }

    /**
     * Get XDP mode (for verification)
     */
    const char* get_xdp_mode() const {
        return xdp_.get_xdp_mode();
    }

    /**
     * Get interface name
     */
    const char* get_interface() const {
        return xdp_.get_interface();
    }

    /**
     * Get queue ID
     */
    uint32_t get_queue_id() const {
        return xdp_.get_queue_id();
    }

    /**
     * Check if BPF filtering is enabled
     */
    bool is_bpf_enabled() const {
        return xdp_.is_bpf_enabled();
    }

    /**
     * Print BPF statistics
     */
    void print_bpf_stats() const {
        xdp_.print_bpf_stats();
    }

private:
    /**
     * Get interface configuration (IP, MAC, gateway, netmask)
     */
    bool get_interface_config(const char* interface,
                             uint8_t* local_mac,
                             uint32_t* local_ip,
                             uint32_t* gateway_ip,
                             uint32_t* netmask) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return false;

        // Get local IP
        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

        if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
            ::close(fd);
            return false;
        }
        *local_ip = ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);

        // Get MAC address
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            ::close(fd);
            return false;
        }
        memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);

        // Get netmask
        if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
            ::close(fd);
            return false;
        }
        *netmask = ntohl(((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr);

        ::close(fd);

        // Calculate gateway (assume .1 in subnet)
        *gateway_ip = (*local_ip & *netmask) | 1;

        return true;
    }

    /**
     * Convert IP (host byte order) to string
     */
    void ip_to_string(uint32_t ip, char* buf) {
        snprintf(buf, 16, "%u.%u.%u.%u",
                (ip >> 24) & 0xFF,
                (ip >> 16) & 0xFF,
                (ip >> 8) & 0xFF,
                ip & 0xFF);
    }

    websocket::xdp::XDPTransport xdp_;
    userspace_stack::UserspaceStack stack_;
    bool connected_;
};
#endif  // USE_XDP

} // namespace transport
} // namespace websocket
