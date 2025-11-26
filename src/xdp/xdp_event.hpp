// xdp/xdp_event.hpp
// XDP Event Policy for WebSocket Event Loop
//
// Provides event polling compatible with XDP transport, using epoll
// on the underlying TCP socket file descriptor.
//
// Architecture:
//   - Uses epoll/poll on XDP transport's TCP socket FD
//   - Compatible with existing EventPolicy interface
//   - Can be optimized later to poll XDP RX ring directly

#pragma once

#include "xdp_transport.hpp"
#include <sys/epoll.h>
#include <unistd.h>
#include <functional>
#include <stdexcept>
#include <cstring>

namespace websocket {
namespace xdp {

#ifdef USE_XDP

/**
 * XDP Event Policy - epoll-based event loop for XDP transport
 *
 * Uses epoll to monitor the underlying TCP socket file descriptor
 * from XDPTransport.
 *
 * Future optimization: Could poll XDP RX ring directly for lower latency.
 */
class XDPEventPolicy {
public:
    XDPEventPolicy() : epoll_fd_(-1), running_(false) {}

    ~XDPEventPolicy() {
        if (epoll_fd_ >= 0) {
            close(epoll_fd_);
        }
    }

    /**
     * Initialize event loop
     */
    void init() {
        epoll_fd_ = epoll_create1(0);
        if (epoll_fd_ < 0) {
            throw std::runtime_error("epoll_create1() failed");
        }
    }

    /**
     * Add XDP transport to event loop
     *
     * @param transport XDP transport instance
     * @param events Event mask (EPOLLIN, EPOLLOUT, etc.)
     * @return 0 on success, -1 on error
     */
    int add(XDPTransport* transport, uint32_t events) {
        if (!transport) return -1;

        int fd = transport->get_fd();
        if (fd < 0) return -1;

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = events | EPOLLET;  // Edge-triggered
        ev.data.ptr = transport;

        return epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev);
    }

    /**
     * Modify events for XDP transport
     *
     * @param transport XDP transport instance
     * @param events New event mask
     * @return 0 on success, -1 on error
     */
    int modify(XDPTransport* transport, uint32_t events) {
        if (!transport) return -1;

        int fd = transport->get_fd();
        if (fd < 0) return -1;

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = events | EPOLLET;
        ev.data.ptr = transport;

        return epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev);
    }

    /**
     * Remove XDP transport from event loop
     *
     * @param transport XDP transport instance
     * @return 0 on success, -1 on error
     */
    int remove(XDPTransport* transport) {
        if (!transport) return -1;

        int fd = transport->get_fd();
        if (fd < 0) return -1;

        return epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
    }

    /**
     * Wait for events (single iteration)
     *
     * @param callback Function to call with event flags
     * @param timeout_ms Timeout in milliseconds (-1 = infinite)
     * @return Number of events, 0 on timeout, -1 on error
     */
    int wait(std::function<void(uint32_t)> callback, int timeout_ms = -1) {
        struct epoll_event events[32];
        int nfds = epoll_wait(epoll_fd_, events, 32, timeout_ms);

        if (nfds < 0) {
            if (errno == EINTR) return 0;  // Interrupted, try again
            return -1;
        }

        for (int i = 0; i < nfds; i++) {
            callback(events[i].events);
        }

        return nfds;
    }

    /**
     * Run event loop continuously
     *
     * @param callback Function to call with event flags
     */
    void run(std::function<void(uint32_t)> callback) {
        running_ = true;

        while (running_) {
            int ret = wait(callback, 100);  // 100ms timeout
            if (ret < 0) {
                break;  // Error
            }
        }
    }

    /**
     * Stop event loop
     */
    void stop() {
        running_ = false;
    }

    /**
     * Get epoll file descriptor
     */
    int get_fd() const {
        return epoll_fd_;
    }

private:
    int epoll_fd_;
    bool running_;
};

#else  // !USE_XDP

// Stub when XDP is not enabled
class XDPEventPolicy {
public:
    void init() {
        throw std::runtime_error("XDP support not compiled. Build with USE_XDP=1");
    }
    int add(void*, uint32_t) { return -1; }
    int modify(void*, uint32_t) { return -1; }
    int remove(void*) { return -1; }
    int wait(std::function<void(uint32_t)>, int = -1) { return -1; }
    void run(std::function<void(uint32_t)>) {}
    void stop() {}
    int get_fd() const { return -1; }
};

#endif  // USE_XDP

}  // namespace xdp
}  // namespace websocket
