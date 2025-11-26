// src/policy/xdp_event_policy.hpp
// Event policy for XDP transport (polling-based)
//
// Unlike Epoll/IOUring which wait on file descriptors, XDP requires explicit
// polling via UserspaceStack::poll(). This event policy provides that interface.

#pragma once

#include <cstdint>
#include <unistd.h>
#include <time.h>

#ifdef USE_XDP
#include "../stack/userspace_stack.hpp"
#endif

namespace websocket {

/**
 * XDP Event Policy
 *
 * Polling-based event loop for XDP transport. Unlike epoll/io_uring which wait
 * for kernel notifications, this policy actively polls the UserspaceStack to
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
 *   event_loop.set_stack(&userspace_stack);
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
#ifdef USE_XDP
    userspace_stack::UserspaceStack* stack_;
#endif
    int timeout_us_;        // Polling interval in microseconds
    bool busy_poll_;        // If true, busy poll (no sleep)
    uint64_t poll_count_;   // Statistics
    XDPEventPolicy()
#ifdef USE_XDP
        : stack_(nullptr)
        , timeout_us_(100)   // Default: 100μs polling interval
#else
        : timeout_us_(100)
#endif
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

#ifdef USE_XDP
    /**
     * Set the UserspaceStack to poll
     * Must be called before wait_with_timeout()
     */
    void set_stack(userspace_stack::UserspaceStack* stack) {
        stack_ = stack;
    }
#endif

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
     * For XDP, this polls the UserspaceStack and optionally sleeps.
     * Always returns 1 (ready) to signal that polling occurred.
     *
     * Note: Unlike epoll which blocks until events, this always returns
     *       after one poll cycle (with optional sleep).
     */
    int wait_with_timeout() {
#ifdef USE_XDP
        if (stack_) {
            // Poll the userspace stack to process packets
            stack_->poll();
        }
#endif

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
