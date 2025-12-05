// policy/event.hpp
// Unified Event Loop Policy - merges epoll and kqueue
//
// This header provides platform-specific event notification mechanisms:
//   - Linux: EpollPolicy
//   - macOS/BSD: KqueuePolicy
//
// All policies conform to the EventPolicyConcept interface:
//   - void init()
//   - void add_read(int fd)
//   - void add_write(int fd)
//   - void modify(int fd, uint32_t events)
//   - int wait()                        // Wait indefinitely (no timeout)
//   - void set_wait_timeout(int ms)     // Pre-convert timeout (call once)
//   - int wait_with_timeout()           // Wait with pre-converted timeout
//   - int get_ready_fd() const
//
// Namespace: websocket::event_policies

#pragma once

#include <stdexcept>
#include <cstdint>

// ============================================================================
// Platform Detection
// ============================================================================

#if defined(__linux__)
    #define EVENT_POLICY_LINUX 1
    #include <sys/epoll.h>
    #include <unistd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #define EVENT_POLICY_BSD 1
    #include <sys/event.h>
    #include <sys/time.h>
    #include <unistd.h>
#else
    #error "Unsupported platform for event policy"
#endif

namespace websocket {
namespace event_policies {

// ============================================================================
// Linux: epoll Event Policy
// ============================================================================

#ifdef EVENT_POLICY_LINUX

/**
 * EpollPolicy - Linux epoll-based event notification
 *
 * Uses edge-triggered mode (EPOLLET) for optimal performance in HFT scenarios.
 *
 * Performance characteristics:
 *   - O(1) add/modify/wait operations
 *   - Edge-triggered reduces system calls
 *   - Low latency: sub-microsecond event notification
 *
 * Thread safety: Not thread-safe (designed for single-threaded event loops)
 */
struct EpollPolicy {
    EpollPolicy() : epfd_(-1), ready_fd_(-1), ready_events_(0) {
        // Initialize default timeout (infinite)
        timeout_ms_ = -1;
        timeout_ts_.tv_sec = 0;
        timeout_ts_.tv_nsec = 0;
    }

    ~EpollPolicy() {
        cleanup();
    }

    // Prevent copying
    EpollPolicy(const EpollPolicy&) = delete;
    EpollPolicy& operator=(const EpollPolicy&) = delete;

    // Allow moving
    EpollPolicy(EpollPolicy&& other) noexcept
        : epfd_(other.epfd_)
        , ready_fd_(other.ready_fd_)
        , ready_events_(other.ready_events_)
        , timeout_ms_(other.timeout_ms_)
        , timeout_ts_(other.timeout_ts_)
    {
        other.epfd_ = -1;
        other.ready_fd_ = -1;
        other.ready_events_ = 0;
    }

    EpollPolicy& operator=(EpollPolicy&& other) noexcept {
        if (this != &other) {
            cleanup();
            epfd_ = other.epfd_;
            ready_fd_ = other.ready_fd_;
            ready_events_ = other.ready_events_;
            timeout_ms_ = other.timeout_ms_;
            timeout_ts_ = other.timeout_ts_;
            other.epfd_ = -1;
            other.ready_fd_ = -1;
            other.ready_events_ = 0;
        }
        return *this;
    }

    /**
     * Initialize epoll instance
     *
     * @throws std::runtime_error if epoll_create1() fails
     */
    void init() {
        epfd_ = epoll_create1(EPOLL_CLOEXEC);
        if (epfd_ < 0) {
            throw std::runtime_error("epoll_create1() failed");
        }
    }

    /**
     * Register file descriptor for read events (EPOLLIN)
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if epoll_ctl() fails
     */
    void add_read(int fd) {
        struct epoll_event ev = {};
        ev.events = EPOLLIN | EPOLLET;  // Edge-triggered for HFT performance
        ev.data.fd = fd;

        if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            throw std::runtime_error("epoll_ctl(ADD, EPOLLIN) failed");
        }
    }

    /**
     * Register file descriptor for write events (EPOLLOUT)
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if epoll_ctl() fails
     */
    void add_write(int fd) {
        struct epoll_event ev = {};
        ev.events = EPOLLOUT | EPOLLET;  // Edge-triggered
        ev.data.fd = fd;

        if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            throw std::runtime_error("epoll_ctl(ADD, EPOLLOUT) failed");
        }
    }

    /**
     * Register file descriptor for both read and write events
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if epoll_ctl() fails
     */
    void add_readwrite(int fd) {
        struct epoll_event ev = {};
        ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
        ev.data.fd = fd;

        if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            throw std::runtime_error("epoll_ctl(ADD, EPOLLIN|EPOLLOUT) failed");
        }
    }

    /**
     * Modify event registration for file descriptor
     *
     * @param fd File descriptor
     * @param events Event mask (EPOLLIN=0x01, EPOLLOUT=0x04)
     * @throws std::runtime_error if epoll_ctl() fails
     */
    void modify(int fd, uint32_t events) {
        struct epoll_event ev = {};
        ev.events = events | EPOLLET;  // Always edge-triggered
        ev.data.fd = fd;

        if (epoll_ctl(epfd_, EPOLL_CTL_MOD, fd, &ev) < 0) {
            throw std::runtime_error("epoll_ctl(MOD) failed");
        }
    }

    /**
     * Remove file descriptor from epoll monitoring
     *
     * @param fd File descriptor to remove
     */
    void remove(int fd) {
        epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr);
    }

    /**
     * Wait for events indefinitely (no timeout)
     *
     * Optimized for minimal overhead - no timeout processing.
     *
     * @return Number of ready file descriptors (-1 = error)
     */
    int wait() {
        struct epoll_event events[MAX_EVENTS];
        int n = epoll_wait(epfd_, events, MAX_EVENTS, -1);

        if (n > 0) {
            // Store first ready event (single-FD optimization)
            ready_fd_ = events[0].data.fd;
            ready_events_ = events[0].events;
            return n;
        } else {
            // Error (timeout cannot occur with -1)
            return -1;
        }
    }

    /**
     * Set timeout value for wait_with_timeout()
     *
     * Pre-converts timeout to avoid conversion overhead on every wait call.
     * Optimized for HFT scenarios where same timeout is used repeatedly.
     *
     * @param timeout_ms Timeout in milliseconds (-1 = infinite, 0 = poll)
     */
    void set_wait_timeout(int timeout_ms) {
        timeout_ms_ = timeout_ms;
    }

    /**
     * Wait for events with pre-configured timeout
     *
     * Uses timeout set by set_wait_timeout(). No conversion overhead.
     * For best performance, call set_wait_timeout() once during setup.
     *
     * @return Number of ready file descriptors (0 = timeout, -1 = error)
     */
    int wait_with_timeout() {
        struct epoll_event events[MAX_EVENTS];
        int n = epoll_wait(epfd_, events, MAX_EVENTS, timeout_ms_);

        if (n > 0) {
            // Store first ready event (single-FD optimization)
            ready_fd_ = events[0].data.fd;
            ready_events_ = events[0].events;
            return n;
        } else if (n == 0) {
            // Timeout
            return 0;
        } else {
            // Error
            return -1;
        }
    }

    /**
     * Get the file descriptor that triggered the most recent event
     *
     * @return File descriptor (-1 if no event)
     */
    int get_ready_fd() const {
        return ready_fd_;
    }

    /**
     * Check if ready event is readable
     */
    bool is_readable() const {
        return ready_events_ & EPOLLIN;
    }

    /**
     * Check if ready event is writable
     */
    bool is_writable() const {
        return ready_events_ & EPOLLOUT;
    }

    /**
     * Check if ready event has error
     */
    bool has_error() const {
        return ready_events_ & (EPOLLERR | EPOLLHUP);
    }

    /**
     * Get event loop type name
     */
    static constexpr const char* name() {
        return "epoll";
    }

    static constexpr int MAX_EVENTS = 64;  // Max events per wait() call

    int epfd_;             // epoll file descriptor
    int ready_fd_;         // Most recently ready file descriptor
    uint32_t ready_events_; // Events for ready_fd_
    int timeout_ms_;       // Pre-configured timeout for wait_with_timeout()
    struct timespec timeout_ts_;  // Pre-converted timespec (reserved for future use)
};

#endif // EVENT_POLICY_LINUX

// ============================================================================
// BSD/macOS: kqueue Event Policy
// ============================================================================

#ifdef EVENT_POLICY_BSD

/**
 * KqueuePolicy - BSD/macOS kqueue-based event notification
 *
 * kqueue is the BSD equivalent of Linux's epoll, providing efficient
 * event notification for multiple file descriptors.
 *
 * Performance characteristics:
 *   - O(1) add/modify/wait operations
 *   - Edge-cleared mode (EV_CLEAR) for edge-triggered behavior
 *   - Low latency on macOS and BSD systems
 *
 * Thread safety: Not thread-safe (designed for single-threaded event loops)
 */
struct KqueuePolicy {
    KqueuePolicy() : kq_(-1), ready_fd_(-1), ready_filter_(0) {
        // Initialize default timeout (infinite)
        timeout_ts_.tv_sec = 0;
        timeout_ts_.tv_nsec = 0;
        use_timeout_ = false;
    }

    ~KqueuePolicy() {
        cleanup();
    }

    // Prevent copying
    KqueuePolicy(const KqueuePolicy&) = delete;
    KqueuePolicy& operator=(const KqueuePolicy&) = delete;

    // Allow moving
    KqueuePolicy(KqueuePolicy&& other) noexcept
        : kq_(other.kq_)
        , ready_fd_(other.ready_fd_)
        , ready_filter_(other.ready_filter_)
        , timeout_ts_(other.timeout_ts_)
        , use_timeout_(other.use_timeout_)
    {
        other.kq_ = -1;
        other.ready_fd_ = -1;
        other.ready_filter_ = 0;
    }

    KqueuePolicy& operator=(KqueuePolicy&& other) noexcept {
        if (this != &other) {
            cleanup();
            kq_ = other.kq_;
            ready_fd_ = other.ready_fd_;
            ready_filter_ = other.ready_filter_;
            timeout_ts_ = other.timeout_ts_;
            use_timeout_ = other.use_timeout_;
            other.kq_ = -1;
            other.ready_fd_ = -1;
            other.ready_filter_ = 0;
        }
        return *this;
    }

    /**
     * Initialize kqueue instance
     *
     * @throws std::runtime_error if kqueue() fails
     */
    void init() {
        kq_ = kqueue();
        if (kq_ < 0) {
            throw std::runtime_error("kqueue() failed");
        }
    }

    /**
     * Register file descriptor for read events (EVFILT_READ)
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if kevent() fails
     */
    void add_read(int fd) {
        struct kevent ev;
        // EV_CLEAR provides edge-triggered behavior (similar to EPOLLET)
        EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, nullptr);

        if (kevent(kq_, &ev, 1, nullptr, 0, nullptr) < 0) {
            throw std::runtime_error("kevent(EV_ADD, EVFILT_READ) failed");
        }
    }

    /**
     * Register file descriptor for write events (EVFILT_WRITE)
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if kevent() fails
     */
    void add_write(int fd) {
        struct kevent ev;
        EV_SET(&ev, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, nullptr);

        if (kevent(kq_, &ev, 1, nullptr, 0, nullptr) < 0) {
            throw std::runtime_error("kevent(EV_ADD, EVFILT_WRITE) failed");
        }
    }

    /**
     * Register file descriptor for both read and write events
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if kevent() fails
     */
    void add_readwrite(int fd) {
        struct kevent evs[2];
        EV_SET(&evs[0], fd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, nullptr);
        EV_SET(&evs[1], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, nullptr);

        if (kevent(kq_, evs, 2, nullptr, 0, nullptr) < 0) {
            throw std::runtime_error("kevent(EV_ADD, READ|WRITE) failed");
        }
    }

    /**
     * Modify event registration for file descriptor
     *
     * Note: kqueue doesn't have explicit "modify" - we delete and re-add
     *
     * @param fd File descriptor
     * @param events Event mask (0x01=read, 0x04=write)
     * @throws std::runtime_error if operation fails
     */
    void modify(int fd, uint32_t events) {
        struct kevent ev;

        // Remove existing events (ignore errors)
        EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        kevent(kq_, &ev, 1, nullptr, 0, nullptr);

        EV_SET(&ev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        kevent(kq_, &ev, 1, nullptr, 0, nullptr);

        // Add new events based on flags
        if (events & 0x01) {  // Read (EPOLLIN compatible)
            add_read(fd);
        }
        if (events & 0x04) {  // Write (EPOLLOUT compatible)
            add_write(fd);
        }
    }

    /**
     * Remove file descriptor from kqueue monitoring
     *
     * @param fd File descriptor to remove
     */
    void remove(int fd) {
        struct kevent ev;

        // Delete read filter
        EV_SET(&ev, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        kevent(kq_, &ev, 1, nullptr, 0, nullptr);

        // Delete write filter
        EV_SET(&ev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        kevent(kq_, &ev, 1, nullptr, 0, nullptr);
    }

    /**
     * Wait for events indefinitely (no timeout)
     *
     * Optimized for minimal overhead - no timeout processing.
     * Passes nullptr for timeout to kevent() for infinite wait.
     *
     * @return Number of ready file descriptors (-1 = error)
     */
    int wait() {
        struct kevent events[MAX_EVENTS];

        int n = kevent(kq_, nullptr, 0, events, MAX_EVENTS, nullptr);

        if (n > 0) {
            // Store first ready event (single-FD optimization)
            ready_fd_ = static_cast<int>(events[0].ident);
            ready_filter_ = events[0].filter;
            return n;
        } else {
            // Error (timeout cannot occur with nullptr)
            return -1;
        }
    }

    /**
     * Set timeout value for wait_with_timeout()
     *
     * Pre-converts timeout to timespec to avoid conversion overhead.
     * Optimized for HFT scenarios where same timeout is used repeatedly.
     *
     * @param timeout_ms Timeout in milliseconds (-1 = infinite, 0 = poll)
     */
    void set_wait_timeout(int timeout_ms) {
        if (timeout_ms < 0) {
            // Infinite timeout - will use nullptr
            use_timeout_ = false;
        } else {
            timeout_ts_.tv_sec = timeout_ms / 1000;
            timeout_ts_.tv_nsec = (timeout_ms % 1000) * 1000000L;
            use_timeout_ = true;
        }
    }

    /**
     * Wait for events with pre-configured timeout
     *
     * Uses timeout set by set_wait_timeout(). No conversion overhead.
     * For best performance, call set_wait_timeout() once during setup.
     *
     * @return Number of ready file descriptors (0 = timeout, -1 = error)
     */
    int wait_with_timeout() {
        struct kevent events[MAX_EVENTS];
        struct timespec* timeout_ptr = use_timeout_ ? &timeout_ts_ : nullptr;

        int n = kevent(kq_, nullptr, 0, events, MAX_EVENTS, timeout_ptr);

        if (n > 0) {
            // Store first ready event (single-FD optimization)
            ready_fd_ = static_cast<int>(events[0].ident);
            ready_filter_ = events[0].filter;
            return n;
        } else if (n == 0) {
            // Timeout
            return 0;
        } else {
            // Error
            return -1;
        }
    }

    /**
     * Get the file descriptor that triggered the most recent event
     *
     * @return File descriptor (-1 if no event)
     */
    int get_ready_fd() const {
        return ready_fd_;
    }

    /**
     * Get the filter (event type) that triggered
     *
     * @return Filter type (EVFILT_READ or EVFILT_WRITE)
     */
    int16_t get_ready_filter() const {
        return ready_filter_;
    }

    /**
     * Check if ready event is readable
     */
    bool is_readable() const {
        return ready_filter_ == EVFILT_READ;
    }

    /**
     * Check if ready event is writable
     */
    bool is_writable() const {
        return ready_filter_ == EVFILT_WRITE;
    }

    /**
     * Check if ready event has error
     *
     * Note: kqueue returns errors via EV_ERROR flag in events
     */
    bool has_error() const {
        // In practice, check flags field from kevent result
        // This simplified version returns false
        return false;
    }

    /**
     * Get event loop type name
     */
    static constexpr const char* name() {
        return "kqueue";
    }

    static constexpr int MAX_EVENTS = 64;  // Max events per wait() call

private:
    void cleanup() {
        if (kq_ >= 0) {
            ::close(kq_);
            kq_ = -1;
        }
    }

    int kq_;              // kqueue file descriptor
    int ready_fd_;        // Most recently ready file descriptor
    int16_t ready_filter_; // Filter that triggered (EVFILT_READ/WRITE)
    struct timespec timeout_ts_;  // Pre-converted timeout for wait_with_timeout()
    bool use_timeout_;             // Whether to use timeout (false = infinite)
};

#endif // EVENT_POLICY_BSD

// ============================================================================
// Universal: select() Event Policy (Fallback)
// ============================================================================

/**
 * SelectPolicy - POSIX select()-based event notification
 *
 * select() is the most portable event mechanism, available on all POSIX systems.
 * However, it has limitations compared to epoll/kqueue:
 *   - Limited to FD_SETSIZE file descriptors (typically 1024)
 *   - O(n) performance (scans all FDs)
 *   - Not edge-triggered (level-triggered only)
 *
 * Use this as a fallback when epoll/kqueue are unavailable.
 *
 * Performance characteristics:
 *   - O(n) operations (n = number of registered FDs)
 *   - Level-triggered only
 *   - Works on all POSIX platforms
 *
 * Thread safety: Not thread-safe
 */
struct SelectPolicy {
    SelectPolicy() : ready_fd_(-1), ready_events_(0), max_fd_(-1) {
        FD_ZERO(&read_fds_);
        FD_ZERO(&write_fds_);
        timeout_tv_.tv_sec = 0;
        timeout_tv_.tv_usec = 0;
        use_timeout_ = false;
    }

    ~SelectPolicy() {
        cleanup();
    }

    // Prevent copying
    SelectPolicy(const SelectPolicy&) = delete;
    SelectPolicy& operator=(const SelectPolicy&) = delete;

    // Allow moving
    SelectPolicy(SelectPolicy&& other) noexcept
        : read_fds_(other.read_fds_)
        , write_fds_(other.write_fds_)
        , ready_fd_(other.ready_fd_)
        , ready_events_(other.ready_events_)
        , max_fd_(other.max_fd_)
        , timeout_tv_(other.timeout_tv_)
        , use_timeout_(other.use_timeout_)
    {
        other.ready_fd_ = -1;
        other.ready_events_ = 0;
        other.max_fd_ = -1;
        FD_ZERO(&other.read_fds_);
        FD_ZERO(&other.write_fds_);
    }

    SelectPolicy& operator=(SelectPolicy&& other) noexcept {
        if (this != &other) {
            cleanup();
            read_fds_ = other.read_fds_;
            write_fds_ = other.write_fds_;
            ready_fd_ = other.ready_fd_;
            ready_events_ = other.ready_events_;
            max_fd_ = other.max_fd_;
            timeout_tv_ = other.timeout_tv_;
            use_timeout_ = other.use_timeout_;
            other.ready_fd_ = -1;
            other.ready_events_ = 0;
            other.max_fd_ = -1;
            FD_ZERO(&other.read_fds_);
            FD_ZERO(&other.write_fds_);
        }
        return *this;
    }

    /**
     * Initialize select (no-op for select)
     */
    void init() {
        // select() doesn't need initialization
        FD_ZERO(&read_fds_);
        FD_ZERO(&write_fds_);
        max_fd_ = -1;
    }

    /**
     * Register file descriptor for read events
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if fd >= FD_SETSIZE
     */
    void add_read(int fd) {
        if (fd >= FD_SETSIZE) {
            throw std::runtime_error("fd >= FD_SETSIZE in select()");
        }
        FD_SET(fd, &read_fds_);
        if (fd > max_fd_) {
            max_fd_ = fd;
        }
    }

    /**
     * Register file descriptor for write events
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if fd >= FD_SETSIZE
     */
    void add_write(int fd) {
        if (fd >= FD_SETSIZE) {
            throw std::runtime_error("fd >= FD_SETSIZE in select()");
        }
        FD_SET(fd, &write_fds_);
        if (fd > max_fd_) {
            max_fd_ = fd;
        }
    }

    /**
     * Register file descriptor for both read and write events
     *
     * @param fd File descriptor to monitor
     * @throws std::runtime_error if fd >= FD_SETSIZE
     */
    void add_readwrite(int fd) {
        if (fd >= FD_SETSIZE) {
            throw std::runtime_error("fd >= FD_SETSIZE in select()");
        }
        FD_SET(fd, &read_fds_);
        FD_SET(fd, &write_fds_);
        if (fd > max_fd_) {
            max_fd_ = fd;
        }
    }

    /**
     * Modify event registration for file descriptor
     *
     * @param fd File descriptor
     * @param events Event mask (0x01=read, 0x04=write)
     * @throws std::runtime_error if fd >= FD_SETSIZE
     */
    void modify(int fd, uint32_t events) {
        if (fd >= FD_SETSIZE) {
            throw std::runtime_error("fd >= FD_SETSIZE in select()");
        }

        // Clear existing
        FD_CLR(fd, &read_fds_);
        FD_CLR(fd, &write_fds_);

        // Add based on events
        if (events & 0x01) {  // Read (EPOLLIN compatible)
            FD_SET(fd, &read_fds_);
        }
        if (events & 0x04) {  // Write (EPOLLOUT compatible)
            FD_SET(fd, &write_fds_);
        }

        if (fd > max_fd_) {
            max_fd_ = fd;
        }
    }

    /**
     * Remove file descriptor from monitoring
     *
     * @param fd File descriptor to remove
     */
    void remove(int fd) {
        FD_CLR(fd, &read_fds_);
        FD_CLR(fd, &write_fds_);

        // Recalculate max_fd if necessary
        if (fd == max_fd_) {
            max_fd_ = -1;
            for (int i = 0; i < FD_SETSIZE; ++i) {
                if (FD_ISSET(i, &read_fds_) || FD_ISSET(i, &write_fds_)) {
                    max_fd_ = i;
                }
            }
        }
    }

    /**
     * Wait for events indefinitely (no timeout)
     *
     * @return Number of ready file descriptors (-1 = error)
     */
    int wait() {
        fd_set tmp_read = read_fds_;
        fd_set tmp_write = write_fds_;

        int n = ::select(max_fd_ + 1, &tmp_read, &tmp_write, nullptr, nullptr);

        if (n > 0) {
            // Find first ready fd
            for (int fd = 0; fd <= max_fd_; ++fd) {
                uint32_t events = 0;
                if (FD_ISSET(fd, &tmp_read)) events |= 0x01;  // EPOLLIN
                if (FD_ISSET(fd, &tmp_write)) events |= 0x04;  // EPOLLOUT

                if (events) {
                    ready_fd_ = fd;
                    ready_events_ = events;
                    return n;
                }
            }
        }

        return n;
    }

    /**
     * Set timeout value for wait_with_timeout()
     *
     * @param timeout_ms Timeout in milliseconds (-1 = infinite, 0 = poll)
     */
    void set_wait_timeout(int timeout_ms) {
        if (timeout_ms < 0) {
            use_timeout_ = false;
        } else {
            timeout_tv_.tv_sec = timeout_ms / 1000;
            timeout_tv_.tv_usec = (timeout_ms % 1000) * 1000;
            use_timeout_ = true;
        }
    }

    /**
     * Wait for events with pre-configured timeout
     *
     * @return Number of ready file descriptors (0 = timeout, -1 = error)
     */
    int wait_with_timeout() {
        fd_set tmp_read = read_fds_;
        fd_set tmp_write = write_fds_;

        struct timeval tv = timeout_tv_;
        struct timeval* tv_ptr = use_timeout_ ? &tv : nullptr;

        int n = ::select(max_fd_ + 1, &tmp_read, &tmp_write, nullptr, tv_ptr);

        if (n > 0) {
            for (int fd = 0; fd <= max_fd_; ++fd) {
                uint32_t events = 0;
                if (FD_ISSET(fd, &tmp_read)) events |= 0x01;
                if (FD_ISSET(fd, &tmp_write)) events |= 0x04;

                if (events) {
                    ready_fd_ = fd;
                    ready_events_ = events;
                    return n;
                }
            }
        }

        return n;
    }

    /**
     * Get the file descriptor that triggered the most recent event
     *
     * @return File descriptor (-1 if no event)
     */
    int get_ready_fd() const {
        return ready_fd_;
    }

    /**
     * Check if ready event is readable
     */
    bool is_readable() const {
        return ready_events_ & 0x01;
    }

    /**
     * Check if ready event is writable
     */
    bool is_writable() const {
        return ready_events_ & 0x04;
    }

    /**
     * Check if ready event has error
     */
    bool has_error() const {
        // select() doesn't provide error information in fd_sets
        return false;
    }

    /**
     * Get event loop type name
     */
    static constexpr const char* name() {
        return "select";
    }

private:
    void cleanup() {
        // select() doesn't have resources to clean up
        ready_fd_ = -1;
        max_fd_ = -1;
    }

    fd_set read_fds_;           // Read file descriptor set
    fd_set write_fds_;          // Write file descriptor set
    int ready_fd_;              // Most recently ready file descriptor
    uint32_t ready_events_;     // Events for ready_fd_
    int max_fd_;                // Highest file descriptor number
    struct timeval timeout_tv_; // Pre-converted timeout for wait_with_timeout()
    bool use_timeout_;          // Whether to use timeout
};

} // namespace event_policies
} // namespace websocket

// ============================================================================
// Backward-Compatible Type Aliases (Global Scope)
// ============================================================================

#ifdef EVENT_POLICY_LINUX
using EpollPolicy = websocket::event_policies::EpollPolicy;
#endif

#ifdef EVENT_POLICY_BSD
using KqueuePolicy = websocket::event_policies::KqueuePolicy;
#endif

// SelectPolicy is always available as fallback
using SelectPolicy = websocket::event_policies::SelectPolicy;

// ============================================================================
// Default Event Policy Selection
// ============================================================================
// Platform-specific event policy aliases for use in unit tests and generic code.
// ws_configs.hpp uses DefaultEventPolicy for the full policy composition.

#if defined(__linux__)
    #ifdef USE_SELECT
        using EventPolicy = websocket::event_policies::SelectPolicy;
    #else
        using EventPolicy = websocket::event_policies::EpollPolicy;
    #endif
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    using EventPolicy = websocket::event_policies::KqueuePolicy;
#else
    using EventPolicy = websocket::event_policies::SelectPolicy;
#endif

// ============================================================================
// Event Policy Concepts (C++20)
// ============================================================================

#if __cplusplus >= 202002L
#include <concepts>

/**
 * EventPolicyConcept - Defines required interface for event policies
 *
 * All event policies must provide:
 *   - init() - Initialize event mechanism
 *   - add_read(fd) - Monitor fd for read events
 *   - add_write(fd) - Monitor fd for write events
 *   - modify(fd, events) - Change event monitoring
 *   - wait() - Wait for events indefinitely
 *   - set_wait_timeout(timeout_ms) - Pre-convert timeout (call once during setup)
 *   - wait_with_timeout() - Wait with pre-converted timeout (no conversion overhead)
 *   - get_ready_fd() - Get ready file descriptor
 */
template<typename T>
concept EventPolicyConcept = requires(T event, int fd, uint32_t events, int timeout) {
    { event.init() } -> std::same_as<void>;
    { event.add_read(fd) } -> std::same_as<void>;
    { event.add_write(fd) } -> std::same_as<void>;
    { event.modify(fd, events) } -> std::same_as<void>;
    { event.wait() } -> std::convertible_to<int>;
    { event.set_wait_timeout(timeout) } -> std::same_as<void>;
    { event.wait_with_timeout() } -> std::convertible_to<int>;
    { event.get_ready_fd() } -> std::convertible_to<int>;
};

// Verify our policies conform to the concept
// NOTE: These are now verified in ws_configs.hpp after policy selection
// static_assert(EventPolicyConcept<EventPolicy>);
// static_assert(EventPolicyConcept<DefaultEventPolicy>);

#ifdef EVENT_POLICY_LINUX
static_assert(EventPolicyConcept<EpollPolicy>);
#endif

#ifdef EVENT_POLICY_BSD
static_assert(EventPolicyConcept<KqueuePolicy>);
#endif

// SelectPolicy is always available
static_assert(EventPolicyConcept<SelectPolicy>);

#endif // C++20

// ============================================================================
// Usage Example
// ============================================================================

/*

// Example 1: Using platform-default event policy
EventPolicy event;
event.init();
event.add_read(sockfd);

// Option A: Wait indefinitely (no timeout)
// Best for pure event-driven code
while (true) {
    int n = event.wait();  // Wait forever until event
    if (n > 0) {
        int fd = event.get_ready_fd();
        if (event.is_readable()) {
            // Handle read event
        }
    }
}

// Option B: Wait with timeout (optimized for HFT)
// Pre-convert timeout once during setup, then use wait_with_timeout()
event.set_wait_timeout(1000);  // 1 second timeout - converted once!

while (true) {
    int n = event.wait_with_timeout();  // No conversion overhead!
    if (n > 0) {
        int fd = event.get_ready_fd();
        if (event.is_readable()) {
            // Handle read event
        }
    } else if (n == 0) {
        // Timeout - do periodic work
    }
}

// Example 2: Explicit policy selection (Linux)
#ifdef __linux__
EpollPolicy epoll_event;
epoll_event.init();
epoll_event.add_readwrite(sockfd);
epoll_event.wait();

// Or use io_uring if available
#ifdef ENABLE_IO_URING
IoUringPolicy uring_event;
uring_event.init();
uring_event.add_read(sockfd);
uring_event.wait();
#endif
#endif

// Example 3: Policy-based template
template <typename EventPolicy>
struct EventLoop {
    void run() {
        event_.init();
        event_.add_read(listen_fd_);
        while (running_) {
            if (event_.wait(100) > 0) {
                handle_event(event_.get_ready_fd());
            }
        }
    }

private:
    EventPolicy event_;
};

// Instantiate with different policies
EventLoop<EpollPolicy> linux_loop;
EventLoop<KqueuePolicy> macos_loop;
EventLoop<IoUringPolicy> uring_loop;

*/
