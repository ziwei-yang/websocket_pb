// src/policy/xdp_event_policy.hpp
// Event policy for XDP transport (polling-based)
//
// Unlike Epoll/IOUring which wait on file descriptors, XDP requires explicit
// polling. This event policy provides a polling-based event loop that calls
// a user-provided poll callback.
//
// Note: The UserspaceStack is now pure packet operations only.
// The transport policy (XDPUserspaceTransport) owns the poll loop.
// This event policy is for integration with generic event loop code.

#pragma once

#include <cstdint>
#include <unistd.h>
#include <time.h>
#include <functional>

namespace websocket {

/**
 * XDP Event Policy
 *
 * Polling-based event loop for XDP transport. Unlike epoll/io_uring which wait
 * for kernel notifications, this policy actively calls a poll callback to
 * process incoming packets.
 *
 * Performance Characteristics:
 * - Latency: ~1-5μs (no syscall overhead)
 * - CPU: High (busy polling) or Low (with sleep)
 * - Throughput: Very high (zero-copy packet processing)
 *
 * Usage:
 *   XDPEventPolicy event_loop;
 *   event_loop.init();
 *   event_loop.set_poll_callback([&transport]() { transport.poll(); });
 *   event_loop.set_wait_timeout(100);  // 100μs polling interval
 *
 *   while (running) {
 *       int ready = event_loop.wait_with_timeout();
 *       if (ready > 0) {
 *           // Process data
 *       }
 *   }
 */
struct XDPEventPolicy {
    using PollCallback = std::function<void()>;

    PollCallback poll_callback_;
    int timeout_us_;        // Polling interval in microseconds
    bool busy_poll_;        // If true, busy poll (no sleep)
    uint64_t poll_count_;   // Statistics

    XDPEventPolicy()
        : poll_callback_()
        , timeout_us_(100)   // Default: 100μs polling interval
        , busy_poll_(false)  // Default: sleep-based polling
        , poll_count_(0)
    {}

    ~XDPEventPolicy() = default;

    /**
     * Initialize event policy
     * No-op for XDP (no file descriptors to set up)
     */
    void init() {
        poll_count_ = 0;
    }

    /**
     * Set the poll callback
     * This callback is invoked on each wait_with_timeout() call.
     * Typically set to transport.poll() to process RX and retransmits.
     */
    void set_poll_callback(PollCallback cb) {
        poll_callback_ = std::move(cb);
    }

    /**
     * Set polling interval
     * @param timeout_us Interval in microseconds (0 = busy poll)
     *
     * Trade-offs:
     * - 0μs: Maximum throughput, 100% CPU usage
     * - 1-10μs: Good latency, high CPU usage
     * - 50-100μs: Balanced latency/CPU
     * - 1000μs+: Low CPU, higher latency
     */
    void set_wait_timeout(int timeout_us) {
        timeout_us_ = timeout_us;
        busy_poll_ = (timeout_us == 0);
    }

    /**
     * Add read interest (no-op for XDP)
     * XDP doesn't use file descriptors, so this is ignored.
     * Kept for interface compatibility with Epoll/IOUring policies.
     */
    void add_read(int fd) {
        (void)fd;  // Unused
    }

    /**
     * Remove read interest (no-op for XDP)
     */
    void del_read(int fd) {
        (void)fd;  // Unused
    }

    /**
     * Wait for events with timeout
     * @return 1 if ready (always), 0 on timeout, -1 on error
     *
     * Calls the poll callback and optionally sleeps.
     * Always returns 1 (ready) to signal that polling occurred.
     *
     * Note: Unlike epoll which blocks until events, this always returns
     *       after one poll cycle (with optional sleep).
     */
    int wait_with_timeout() {
        // Call user-provided poll callback (e.g., transport.poll())
        if (poll_callback_) {
            poll_callback_();
        }

        poll_count_++;

        // Sleep if not busy polling
        if (!busy_poll_ && timeout_us_ > 0) {
            // Use nanosleep for microsecond precision
            struct timespec ts;
            ts.tv_sec = timeout_us_ / 1000000;
            ts.tv_nsec = (timeout_us_ % 1000000) * 1000;
            nanosleep(&ts, nullptr);
        }

        return 1;  // Always ready (polling occurred)
    }

    /**
     * Get ready file descriptor
     * @return 0 (dummy value, not used)
     *
     * XDP doesn't use file descriptors. This returns a dummy value
     * for interface compatibility.
     */
    int get_ready_fd() const {
        return 0;
    }

    /**
     * Get poll statistics
     * @return Number of poll() calls made
     */
    uint64_t get_poll_count() const {
        return poll_count_;
    }

    /**
     * Reset statistics
     */
    void reset_stats() {
        poll_count_ = 0;
    }

    /**
     * Enable busy polling (0% sleep)
     * Use for maximum throughput at cost of 100% CPU
     */
    void enable_busy_poll() {
        busy_poll_ = true;
        timeout_us_ = 0;
    }

    /**
     * Disable busy polling (use timed polling)
     * Use to reduce CPU usage at cost of slightly higher latency
     */
    void disable_busy_poll() {
        busy_poll_ = false;
        if (timeout_us_ == 0) {
            timeout_us_ = 100;  // Default to 100μs
        }
    }

    /**
     * Check if using busy polling
     */
    bool is_busy_polling() const {
        return busy_poll_;
    }

    /**
     * Print event policy statistics
     */
    void print_stats() const {
        printf("[XDP Event Policy] Poll count: %lu, Busy poll: %s, Interval: %dus\n",
               poll_count_, busy_poll_ ? "yes" : "no", timeout_us_);
    }
};

} // namespace websocket
