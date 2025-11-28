// policy/iobackend.hpp
// Unified I/O Backend - asynchronous I/O abstraction
//
// This header provides platform-specific async I/O mechanisms:
//   - Linux: EpollBackend (default) or IoUringBackend (with ENABLE_IO_URING)
//   - macOS/BSD: KqueueBackend
//   - Portable: SelectBackend (fallback)
//
// All backends conform to the IOBackendConcept interface:
//   - void set_timeout(int timeout_ms)
//   - bool init()
//   - void run()
//   - void stop()
//   - bool add_listen_socket(int listen_fd)
//   - void async_accept(int listen_fd, AcceptHandler cb)
//   - void async_read(int fd, void* buf, size_t len, IOHandler cb)
//   - void async_write(int fd, const void* buf, size_t len, IOHandler cb)
//   - void close(int fd)
//
// Single-threaded design - optimized for HFT event loops
//
// Namespace: websocket::iobackend

#pragma once

#include "policy/event.hpp"
#include "core/ringbuffer.hpp"
#include <functional>
#include <unordered_map>
#include <cstdint>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// io_uring header must be included outside namespace to avoid polluting it
#ifdef ENABLE_IO_URING
#include <liburing.h>
#endif

// Platform-specific socket flags
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0  // macOS doesn't have MSG_NOSIGNAL
#endif

namespace websocket {
namespace iobackend {

// ============================================================================
// Type Definitions
// ============================================================================

// Socket type (just an int, but more descriptive)
using Socket = int;

// I/O result codes
enum class IOResult {
    SUCCESS = 0,       // Operation completed successfully
    WOULD_BLOCK = 1,   // Operation would block (EAGAIN/EWOULDBLOCK)
    ERROR = 2,         // Error occurred
    CLOSED = 3,        // Connection closed by peer
    PARTIAL = 4        // Partial read/write (try again)
};

// Accept handler: called when new connection is accepted
// Parameters: (accepted_fd, client_addr, result)
using AcceptHandler = std::function<void(Socket, struct sockaddr_storage, IOResult)>;

// I/O handler: called when read/write completes
// Parameters: (fd, bytes_transferred, result)
using IOHandler = std::function<void(Socket, std::size_t, IOResult)>;

// ============================================================================
// Helper: Connection State Tracking with RingBuffers
// ============================================================================

// Default buffer size: 64KB for each connection (RX and TX)
constexpr size_t DEFAULT_CONN_BUFFER_SIZE = 64 * 1024;

template<size_t BufferSize = DEFAULT_CONN_BUFFER_SIZE>
struct ConnectionState {
    bool active = false;
    bool reading = false;
    bool writing = false;

    // RX buffer: reads from socket go here
    RingBuffer<BufferSize> rx_buffer;

    // TX buffer: writes to socket come from here
    RingBuffer<BufferSize> tx_buffer;

    // Pending read operation
    IOHandler read_cb;

    // Pending write operation
    std::size_t write_pending = 0;  // Bytes pending in TX buffer
    IOHandler write_cb;

    ConnectionState() {
        rx_buffer.init();
        tx_buffer.init();
    }
};

// ============================================================================
// Linux: Epoll-based I/O Backend
// ============================================================================

#ifdef EVENT_POLICY_LINUX

/**
 * EpollBackend - Linux epoll-based asynchronous I/O
 *
 * Uses non-blocking sockets with epoll edge-triggered notifications.
 * Optimized for single-threaded event loops in HFT scenarios.
 *
 * Template parameter:
 *   - BufferSize: Size of RX and TX RingBuffers per connection (default: 64KB)
 *
 * Performance characteristics:
 *   - Zero-copy operations with RingBuffer
 *   - Minimal allocations (pre-allocated connection state)
 *   - Edge-triggered mode reduces syscalls
 *
 * Thread safety: Not thread-safe (single-threaded design)
 */
template<size_t BufferSize = DEFAULT_CONN_BUFFER_SIZE>
struct EpollBackend {
    EpollBackend() : running_(false), timeout_ms_(1000) {}

    ~EpollBackend() {
        stop();
    }

    // Prevent copying
    EpollBackend(const EpollBackend&) = delete;
    EpollBackend& operator=(const EpollBackend&) = delete;

    /**
     * Set event loop timeout
     *
     * @param timeout_ms Timeout in milliseconds for event loop iteration
     */
    void set_timeout(int timeout_ms) {
        timeout_ms_ = timeout_ms;
        event_.set_wait_timeout(timeout_ms);
    }

    /**
     * Initialize I/O backend
     *
     * @return true on success, false on failure
     */
    bool init() {
        try {
            event_.init();
            event_.set_wait_timeout(timeout_ms_);
            return true;
        } catch (...) {
            return false;
        }
    }

    /**
     * Run blocking event loop
     *
     * Processes I/O events until stop() is called or no active connections.
     * This is the main event loop - call from your main thread.
     */
    void run() {
        running_ = true;

        while (running_) {
            // Check if there's any work to do
            if (connections_.empty() && listen_sockets_.empty()) {
                break;  // No work - exit
            }

            // Wait for events
            int n = event_.wait_with_timeout();

            if (n < 0) {
                // Error - but continue for now
                continue;
            } else if (n == 0) {
                // Timeout - continue
                continue;
            }

            // Process ready event
            int ready_fd = event_.get_ready_fd();

            // Check if it's a listen socket
            auto listen_it = listen_sockets_.find(ready_fd);
            if (listen_it != listen_sockets_.end()) {
                // Process accept
                process_accept(ready_fd, listen_it->second);
                continue;
            }

            // Regular connection - process I/O
            auto conn_it = connections_.find(ready_fd);
            if (conn_it != connections_.end()) {
                if (event_.is_readable() && conn_it->second.reading) {
                    process_read(ready_fd, conn_it->second);
                }
                if (event_.is_writable() && conn_it->second.writing) {
                    process_write(ready_fd, conn_it->second);
                }
            }
        }

        running_ = false;
    }

    /**
     * Request event loop exit
     *
     * Sets flag to stop the event loop after current iteration.
     */
    void stop() {
        running_ = false;
    }

    /**
     * Add listening socket to event loop
     *
     * @param listen_fd Listening socket file descriptor (must be non-blocking)
     * @return true on success
     */
    bool add_listen_socket(Socket listen_fd) {
        try {
            event_.add_read(listen_fd);
            listen_sockets_[listen_fd] = AcceptHandler();  // No default handler
            return true;
        } catch (...) {
            return false;
        }
    }

    /**
     * Asynchronously accept connections
     *
     * @param listen_fd Listening socket
     * @param cb Callback to invoke when connection is accepted
     */
    void async_accept(Socket listen_fd, AcceptHandler cb) {
        listen_sockets_[listen_fd] = std::move(cb);
    }

    /**
     * Asynchronously read data into internal RX RingBuffer
     *
     * Data is read into the connection's RX RingBuffer. User can access
     * the data via the RingBuffer pointer in the callback.
     *
     * @param fd Socket file descriptor
     * @param cb Callback to invoke when read completes (fd, bytes_read, result)
     */
    void async_read(Socket fd, IOHandler cb) {
        auto& conn = connections_[fd];

        if (!conn.active) {
            // First time - register with epoll
            event_.add_read(fd);
            conn.active = true;
        }

        conn.reading = true;
        conn.read_cb = std::move(cb);

        // Try immediate read (may succeed without waiting)
        process_read(fd, conn);
    }

    /**
     * Asynchronously write data from TX RingBuffer
     *
     * Data is first copied into the connection's TX RingBuffer, then written
     * to the socket asynchronously.
     *
     * @param fd Socket file descriptor
     * @param buf Buffer to write from
     * @param len Bytes to write
     * @param cb Callback to invoke when write completes (fd, bytes_written, result)
     */
    void async_write(Socket fd, const void* buf, std::size_t len, IOHandler cb) {
        auto& conn = connections_[fd];

        if (!conn.active) {
            // First time - register with epoll
            event_.add_write(fd);
            conn.active = true;
        }

        // Copy user data into TX RingBuffer
        size_t available = 0;
        uint8_t* write_ptr = conn.tx_buffer.next_write_region(&available);

        if (available < len) {
            // Buffer full - invoke callback with error
            cb(fd, 0, IOResult::ERROR);
            return;
        }

        memcpy(write_ptr, buf, len);
        conn.tx_buffer.commit_write(len);

        conn.writing = true;
        conn.write_pending = len;
        conn.write_cb = std::move(cb);

        // Try immediate write (may succeed without waiting)
        process_write(fd, conn);
    }

    /**
     * Close socket and cleanup
     *
     * @param fd Socket file descriptor to close
     */
    void close(Socket fd) {
        event_.remove(fd);
        connections_.erase(fd);
        ::close(fd);
    }

    /**
     * Get RX RingBuffer for a connection
     *
     * @param fd Socket file descriptor
     * @return Pointer to RX RingBuffer, or nullptr if connection not found
     */
    RingBuffer<BufferSize>* get_rx_buffer(Socket fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            return &it->second.rx_buffer;
        }
        return nullptr;
    }

    /**
     * Get TX RingBuffer for a connection
     *
     * @param fd Socket file descriptor
     * @return Pointer to TX RingBuffer, or nullptr if connection not found
     */
    RingBuffer<BufferSize>* get_tx_buffer(Socket fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            return &it->second.tx_buffer;
        }
        return nullptr;
    }

    /**
     * Get event loop running status
     */
    bool is_running() const {
        return running_;
    }

    /**
     * Get number of active connections
     */
    std::size_t connection_count() const {
        return connections_.size();
    }

private:
    void process_accept(Socket listen_fd, AcceptHandler& cb) {
        if (!cb) return;  // No handler registered

        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd,
                               reinterpret_cast<struct sockaddr*>(&client_addr),
                               &addr_len);

        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No connection available right now
                return;
            }
            cb(-1, client_addr, IOResult::ERROR);
            return;
        }

        // Success - make client socket non-blocking
        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

        cb(client_fd, client_addr, IOResult::SUCCESS);
    }

    void process_read(Socket fd, ConnectionState<BufferSize>& conn) {
        if (!conn.reading) return;

        // Get writable region from RX RingBuffer
        size_t available = 0;
        uint8_t* write_ptr = conn.rx_buffer.next_write_region(&available);

        if (available == 0) {
            // Buffer full - invoke callback with error
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, 0, IOResult::ERROR);
            return;
        }

        // Read from socket directly into RingBuffer (zero-copy)
        ssize_t bytes_read = recv(fd, write_ptr, available, 0);

        if (bytes_read > 0) {
            // Success - commit to RingBuffer
            conn.rx_buffer.commit_write(static_cast<size_t>(bytes_read));
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, static_cast<std::size_t>(bytes_read), IOResult::SUCCESS);
        } else if (bytes_read == 0) {
            // Connection closed
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, 0, IOResult::CLOSED);
        } else {
            // Error or would block
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Would block - wait for next event
                return;
            }
            // Real error
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, 0, IOResult::ERROR);
        }
    }

    void process_write(Socket fd, ConnectionState<BufferSize>& conn) {
        if (!conn.writing) return;

        // Get readable region from TX RingBuffer
        size_t available = 0;
        const uint8_t* read_ptr = conn.tx_buffer.next_read_region(&available);

        if (available == 0) {
            // Nothing to write
            conn.writing = false;
            auto cb = std::move(conn.write_cb);
            cb(fd, 0, IOResult::SUCCESS);
            return;
        }

        // Write from RingBuffer to socket (zero-copy)
        ssize_t bytes_written = send(fd, read_ptr, available, MSG_NOSIGNAL);

        if (bytes_written > 0) {
            // Commit consumed bytes from TX RingBuffer
            conn.tx_buffer.commit_read(static_cast<size_t>(bytes_written));
            conn.write_pending -= bytes_written;

            if (conn.write_pending == 0) {
                // Complete write
                conn.writing = false;
                auto cb = std::move(conn.write_cb);
                cb(fd, bytes_written, IOResult::SUCCESS);
            }
            // Otherwise, partial write - will continue on next event
        } else {
            // Error or would block
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Would block - wait for next event
                return;
            }
            // Real error
            conn.writing = false;
            auto cb = std::move(conn.write_cb);
            cb(fd, 0, IOResult::ERROR);
        }
    }

    websocket::event_policies::EpollPolicy event_;
    std::unordered_map<Socket, ConnectionState<BufferSize>> connections_;
    std::unordered_map<Socket, AcceptHandler> listen_sockets_;
    bool running_;
    int timeout_ms_;
};

#endif // EVENT_POLICY_LINUX

// ============================================================================
// BSD/macOS: Kqueue-based I/O Backend
// ============================================================================

#ifdef EVENT_POLICY_BSD

/**
 * KqueueBackend - BSD/macOS kqueue-based asynchronous I/O
 *
 * Uses non-blocking sockets with kqueue edge-triggered notifications.
 * Optimized for single-threaded event loops.
 *
 * Template parameter:
 *   - BufferSize: Size of RX and TX RingBuffers per connection (default: 64KB)
 *
 * Thread safety: Not thread-safe (single-threaded design)
 */
template<size_t BufferSize = DEFAULT_CONN_BUFFER_SIZE>
struct KqueueBackend {
    KqueueBackend() : running_(false), timeout_ms_(1000) {}

    ~KqueueBackend() {
        stop();
    }

    // Prevent copying
    KqueueBackend(const KqueueBackend&) = delete;
    KqueueBackend& operator=(const KqueueBackend&) = delete;

    void set_timeout(int timeout_ms) {
        timeout_ms_ = timeout_ms;
        event_.set_wait_timeout(timeout_ms);
    }

    bool init() {
        try {
            event_.init();
            event_.set_wait_timeout(timeout_ms_);
            return true;
        } catch (...) {
            return false;
        }
    }

    void run() {
        running_ = true;

        while (running_) {
            if (connections_.empty() && listen_sockets_.empty()) {
                break;
            }

            int n = event_.wait_with_timeout();

            if (n < 0) {
                continue;
            } else if (n == 0) {
                continue;
            }

            int ready_fd = event_.get_ready_fd();

            auto listen_it = listen_sockets_.find(ready_fd);
            if (listen_it != listen_sockets_.end()) {
                process_accept(ready_fd, listen_it->second);
                continue;
            }

            auto conn_it = connections_.find(ready_fd);
            if (conn_it != connections_.end()) {
                if (event_.is_readable() && conn_it->second.reading) {
                    process_read(ready_fd, conn_it->second);
                }
                if (event_.is_writable() && conn_it->second.writing) {
                    process_write(ready_fd, conn_it->second);
                }
            }
        }

        running_ = false;
    }

    void stop() {
        running_ = false;
    }

    bool add_listen_socket(Socket listen_fd) {
        try {
            event_.add_read(listen_fd);
            listen_sockets_[listen_fd] = AcceptHandler();
            return true;
        } catch (...) {
            return false;
        }
    }

    void async_accept(Socket listen_fd, AcceptHandler cb) {
        listen_sockets_[listen_fd] = std::move(cb);
    }

    void async_read(Socket fd, IOHandler cb) {
        auto& conn = connections_[fd];

        if (!conn.active) {
            event_.add_read(fd);
            conn.active = true;
        }

        conn.reading = true;
        conn.read_cb = std::move(cb);

        process_read(fd, conn);
    }

    void async_write(Socket fd, const void* buf, std::size_t len, IOHandler cb) {
        auto& conn = connections_[fd];

        if (!conn.active) {
            event_.add_write(fd);
            conn.active = true;
        }

        // Copy user data into TX RingBuffer
        size_t available = 0;
        uint8_t* write_ptr = conn.tx_buffer.next_write_region(&available);

        if (available < len) {
            cb(fd, 0, IOResult::ERROR);
            return;
        }

        memcpy(write_ptr, buf, len);
        conn.tx_buffer.commit_write(len);

        conn.writing = true;
        conn.write_pending = len;
        conn.write_cb = std::move(cb);

        process_write(fd, conn);
    }

    void close(Socket fd) {
        event_.remove(fd);
        connections_.erase(fd);
        ::close(fd);
    }

    RingBuffer<BufferSize>* get_rx_buffer(Socket fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            return &it->second.rx_buffer;
        }
        return nullptr;
    }

    RingBuffer<BufferSize>* get_tx_buffer(Socket fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            return &it->second.tx_buffer;
        }
        return nullptr;
    }

    bool is_running() const {
        return running_;
    }

    std::size_t connection_count() const {
        return connections_.size();
    }

private:
    void process_accept(Socket listen_fd, AcceptHandler& cb) {
        if (!cb) return;

        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(listen_fd,
                               reinterpret_cast<struct sockaddr*>(&client_addr),
                               &addr_len);

        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            cb(-1, client_addr, IOResult::ERROR);
            return;
        }

        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

        cb(client_fd, client_addr, IOResult::SUCCESS);
    }

    void process_read(Socket fd, ConnectionState<BufferSize>& conn) {
        if (!conn.reading) return;

        size_t available = 0;
        uint8_t* write_ptr = conn.rx_buffer.next_write_region(&available);

        if (available == 0) {
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, 0, IOResult::ERROR);
            return;
        }

        ssize_t bytes_read = recv(fd, write_ptr, available, 0);

        if (bytes_read > 0) {
            conn.rx_buffer.commit_write(static_cast<size_t>(bytes_read));
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, static_cast<std::size_t>(bytes_read), IOResult::SUCCESS);
        } else if (bytes_read == 0) {
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, 0, IOResult::CLOSED);
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, 0, IOResult::ERROR);
        }
    }

    void process_write(Socket fd, ConnectionState<BufferSize>& conn) {
        if (!conn.writing) return;

        size_t available = 0;
        const uint8_t* read_ptr = conn.tx_buffer.next_read_region(&available);

        if (available == 0) {
            conn.writing = false;
            auto cb = std::move(conn.write_cb);
            cb(fd, 0, IOResult::SUCCESS);
            return;
        }

        ssize_t bytes_written = send(fd, read_ptr, available, 0);

        if (bytes_written > 0) {
            conn.tx_buffer.commit_read(static_cast<size_t>(bytes_written));
            conn.write_pending -= bytes_written;

            if (conn.write_pending == 0) {
                conn.writing = false;
                auto cb = std::move(conn.write_cb);
                cb(fd, bytes_written, IOResult::SUCCESS);
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            conn.writing = false;
            auto cb = std::move(conn.write_cb);
            cb(fd, 0, IOResult::ERROR);
        }
    }

    websocket::event_policies::KqueuePolicy event_;
    std::unordered_map<Socket, ConnectionState<BufferSize>> connections_;
    std::unordered_map<Socket, AcceptHandler> listen_sockets_;
    bool running_;
    int timeout_ms_;
};

#endif // EVENT_POLICY_BSD

// ============================================================================
// Linux: io_uring-based I/O Backend
// ============================================================================

#ifdef ENABLE_IO_URING

/**
 * IoUringBackend - Linux io_uring-based asynchronous I/O
 *
 * Uses io_uring for true async I/O with minimal syscall overhead.
 * Best performance on Linux 5.5+.
 *
 * Unlike IoUringPolicy in event.hpp (which was just notification),
 * this performs actual async I/O operations (read/write/accept).
 *
 * Template parameter:
 *   - BufferSize: Size of RX and TX RingBuffers per connection (default: 64KB)
 *
 * Performance characteristics:
 *   - True async I/O (kernel performs I/O operations)
 *   - Batched submission/completion (reduced syscalls)
 *   - Zero-copy operations with RingBuffer
 *   - Best for high-throughput scenarios
 *
 * Thread safety: Not thread-safe (single-threaded design)
 */
template<size_t BufferSize = DEFAULT_CONN_BUFFER_SIZE>
struct IoUringBackend {
    IoUringBackend() : running_(false), timeout_ms_(1000) {}

    ~IoUringBackend() {
        stop();
        io_uring_queue_exit(&ring_);
    }

    // Prevent copying
    IoUringBackend(const IoUringBackend&) = delete;
    IoUringBackend& operator=(const IoUringBackend&) = delete;

    void set_timeout(int timeout_ms) {
        timeout_ms_ = timeout_ms;
    }

    bool init() {
        int ret = io_uring_queue_init(256, &ring_, 0);
        if (ret < 0) {
            return false;
        }
        return true;
    }

    void run() {
        running_ = true;
        struct __kernel_timespec ts;
        ts.tv_sec = timeout_ms_ / 1000;
        ts.tv_nsec = (timeout_ms_ % 1000) * 1000000L;

        while (running_) {
            if (connections_.empty() && listen_sockets_.empty()) {
                break;
            }

            struct io_uring_cqe* cqe;
            int ret = io_uring_wait_cqe_timeout(&ring_, &cqe, &ts);

            if (ret == 0 && cqe) {
                process_completion(cqe);
                io_uring_cqe_seen(&ring_, cqe);
            }
        }
    }

    void stop() {
        running_ = false;
    }

    bool add_listen_socket(Socket listen_fd) {
        listen_sockets_[listen_fd] = nullptr;
        return true;
    }

    void async_accept(Socket listen_fd, AcceptHandler cb) {
        listen_sockets_[listen_fd] = std::move(cb);
        submit_accept(listen_fd);
    }

    void async_read(Socket fd, IOHandler cb) {
        auto& conn = connections_[fd];
        if (!conn.active) {
            conn.active = true;
        }
        conn.reading = true;
        conn.read_cb = std::move(cb);

        // Get writable region from RX RingBuffer
        size_t available = 0;
        uint8_t* write_ptr = conn.rx_buffer.next_write_region(&available);

        if (available == 0) {
            cb(fd, 0, IOResult::ERROR);
            return;
        }

        submit_read(fd, write_ptr, available);
    }

    void async_write(Socket fd, const void* buf, std::size_t len, IOHandler cb) {
        auto& conn = connections_[fd];
        if (!conn.active) {
            conn.active = true;
        }

        // Copy user data into TX RingBuffer
        size_t available = 0;
        uint8_t* write_ptr = conn.tx_buffer.next_write_region(&available);

        if (available < len) {
            cb(fd, 0, IOResult::ERROR);
            return;
        }

        memcpy(write_ptr, buf, len);
        conn.tx_buffer.commit_write(len);

        conn.writing = true;
        conn.write_pending = len;
        conn.write_cb = std::move(cb);

        // Get readable region from TX RingBuffer for submission
        const uint8_t* read_ptr = conn.tx_buffer.next_read_region(&available);
        submit_write(fd, read_ptr, len);
    }

    void close(Socket fd) {
        connections_.erase(fd);
        ::close(fd);
    }

    RingBuffer<BufferSize>* get_rx_buffer(Socket fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            return &it->second.rx_buffer;
        }
        return nullptr;
    }

    RingBuffer<BufferSize>* get_tx_buffer(Socket fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            return &it->second.tx_buffer;
        }
        return nullptr;
    }

private:
    enum OpType : uint64_t {
        OP_ACCEPT = 1,
        OP_READ = 2,
        OP_WRITE = 3
    };

    struct OpData {
        OpType type;
        Socket fd;
        struct sockaddr_storage addr;
        socklen_t addrlen;
    };

    void submit_accept(Socket listen_fd) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
        if (!sqe) return;

        OpData* op = new OpData{OP_ACCEPT, listen_fd, {}, sizeof(struct sockaddr_storage)};
        io_uring_prep_accept(sqe, listen_fd, (struct sockaddr*)&op->addr, &op->addrlen, 0);
        io_uring_sqe_set_data(sqe, op);
        io_uring_submit(&ring_);
    }

    void submit_read(Socket fd, void* buf, std::size_t len) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
        if (!sqe) return;

        OpData* op = new OpData{OP_READ, fd, {}, 0};
        io_uring_prep_recv(sqe, fd, buf, len, 0);
        io_uring_sqe_set_data(sqe, op);
        io_uring_submit(&ring_);
    }

    void submit_write(Socket fd, const void* buf, std::size_t len) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
        if (!sqe) return;

        OpData* op = new OpData{OP_WRITE, fd, {}, 0};
        io_uring_prep_send(sqe, fd, buf, len, MSG_NOSIGNAL);
        io_uring_sqe_set_data(sqe, op);
        io_uring_submit(&ring_);
    }

    void process_completion(struct io_uring_cqe* cqe) {
        OpData* op = static_cast<OpData*>(io_uring_cqe_get_data(cqe));
        if (!op) return;

        int result = cqe->res;

        if (op->type == OP_ACCEPT) {
            auto it = listen_sockets_.find(op->fd);
            if (it != listen_sockets_.end() && it->second) {
                if (result >= 0) {
                    Socket client_fd = result;
                    // Make non-blocking
                    int flags = fcntl(client_fd, F_GETFL, 0);
                    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

                    it->second(client_fd, op->addr, IOResult::SUCCESS);
                } else {
                    it->second(-1, {}, IOResult::ERROR);
                }
            }
        } else if (op->type == OP_READ) {
            auto it = connections_.find(op->fd);
            if (it != connections_.end()) {
                auto& conn = it->second;
                conn.reading = false;

                if (result > 0) {
                    // Commit read bytes to RX RingBuffer
                    conn.rx_buffer.commit_write(result);
                    auto cb = std::move(conn.read_cb);
                    cb(op->fd, result, IOResult::SUCCESS);
                } else if (result == 0) {
                    auto cb = std::move(conn.read_cb);
                    cb(op->fd, 0, IOResult::CLOSED);
                } else {
                    auto cb = std::move(conn.read_cb);
                    cb(op->fd, 0, IOResult::ERROR);
                }
            }
        } else if (op->type == OP_WRITE) {
            auto it = connections_.find(op->fd);
            if (it != connections_.end()) {
                auto& conn = it->second;
                conn.writing = false;

                if (result > 0) {
                    // Commit written bytes from TX RingBuffer
                    conn.tx_buffer.commit_read(result);
                    conn.write_pending -= result;
                    auto cb = std::move(conn.write_cb);
                    cb(op->fd, result, IOResult::SUCCESS);
                } else {
                    auto cb = std::move(conn.write_cb);
                    cb(op->fd, 0, IOResult::ERROR);
                }
            }
        }

        delete op;
    }

    struct io_uring ring_;
    std::unordered_map<Socket, ConnectionState<BufferSize>> connections_;
    std::unordered_map<Socket, AcceptHandler> listen_sockets_;
    bool running_;
    int timeout_ms_;
};

#endif // ENABLE_IO_URING

// ============================================================================
// Universal: select()-based I/O Backend (Fallback)
// ============================================================================

/**
 * SelectBackend - POSIX select()-based asynchronous I/O
 *
 * Uses non-blocking sockets with select() for event notification.
 * Most portable option - works on all POSIX systems.
 *
 * Built on top of SelectPolicy from event.hpp.
 *
 * Template parameter:
 *   - BufferSize: Size of RX and TX RingBuffers per connection (default: 64KB)
 *
 * Performance characteristics:
 *   - O(n) performance (n = number of FDs)
 *   - Limited to FD_SETSIZE file descriptors
 *   - Level-triggered only
 *   - Zero-copy operations with RingBuffer
 *   - Works everywhere
 *
 * Thread safety: Not thread-safe (single-threaded design)
 */
template<size_t BufferSize = DEFAULT_CONN_BUFFER_SIZE>
struct SelectBackend {
    SelectBackend() : running_(false), timeout_ms_(1000) {}

    ~SelectBackend() {
        stop();
    }

    // Prevent copying
    SelectBackend(const SelectBackend&) = delete;
    SelectBackend& operator=(const SelectBackend&) = delete;

    void set_timeout(int timeout_ms) {
        timeout_ms_ = timeout_ms;
        event_.set_wait_timeout(timeout_ms);
    }

    bool init() {
        event_.init();
        return true;
    }

    void run() {
        running_ = true;

        while (running_) {
            if (connections_.empty() && listen_sockets_.empty()) {
                break;
            }

            int n = event_.wait_with_timeout();
            if (n <= 0) {
                continue;
            }

            int ready_fd = event_.get_ready_fd();

            // Check if it's a listen socket
            auto listen_it = listen_sockets_.find(ready_fd);
            if (listen_it != listen_sockets_.end()) {
                if (event_.is_readable()) {
                    process_accept(ready_fd, listen_it->second);
                }
                continue;
            }

            // Otherwise, it's a client connection
            auto conn_it = connections_.find(ready_fd);
            if (conn_it != connections_.end()) {
                auto& conn = conn_it->second;

                if (event_.is_readable() && conn.reading) {
                    process_read(ready_fd, conn);
                }
                if (event_.is_writable() && conn.writing) {
                    process_write(ready_fd, conn);
                }
            }
        }
    }

    void stop() {
        running_ = false;
    }

    bool add_listen_socket(Socket listen_fd) {
        // Make non-blocking
        int flags = fcntl(listen_fd, F_GETFL, 0);
        if (flags < 0) return false;
        if (fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK) < 0) return false;

        listen_sockets_[listen_fd] = nullptr;
        event_.add_read(listen_fd);
        return true;
    }

    void async_accept(Socket listen_fd, AcceptHandler cb) {
        listen_sockets_[listen_fd] = std::move(cb);
    }

    void async_read(Socket fd, IOHandler cb) {
        auto& conn = connections_[fd];
        if (!conn.active) {
            event_.add_read(fd);
            conn.active = true;
        }
        conn.reading = true;
        conn.read_cb = std::move(cb);

        process_read(fd, conn);
    }

    void async_write(Socket fd, const void* buf, std::size_t len, IOHandler cb) {
        auto& conn = connections_[fd];
        if (!conn.active) {
            event_.add_write(fd);
            conn.active = true;
        }

        // Copy user data into TX RingBuffer
        size_t available = 0;
        uint8_t* write_ptr = conn.tx_buffer.next_write_region(&available);

        if (available < len) {
            cb(fd, 0, IOResult::ERROR);
            return;
        }

        memcpy(write_ptr, buf, len);
        conn.tx_buffer.commit_write(len);

        conn.writing = true;
        conn.write_pending = len;
        conn.write_cb = std::move(cb);

        process_write(fd, conn);
    }

    void close(Socket fd) {
        event_.remove(fd);
        connections_.erase(fd);
        ::close(fd);
    }

    RingBuffer<BufferSize>* get_rx_buffer(Socket fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            return &it->second.rx_buffer;
        }
        return nullptr;
    }

    RingBuffer<BufferSize>* get_tx_buffer(Socket fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            return &it->second.tx_buffer;
        }
        return nullptr;
    }

private:
    void process_accept(Socket listen_fd, AcceptHandler& handler) {
        if (!handler) return;

        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);

        Socket client_fd = accept(listen_fd, (struct sockaddr*)&addr, &addrlen);

        if (client_fd >= 0) {
            // Make non-blocking
            int flags = fcntl(client_fd, F_GETFL, 0);
            fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

            handler(client_fd, addr, IOResult::SUCCESS);
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                handler(-1, {}, IOResult::ERROR);
            }
        }
    }

    void process_read(Socket fd, ConnectionState<BufferSize>& conn) {
        if (!conn.reading) return;

        size_t available = 0;
        uint8_t* write_ptr = conn.rx_buffer.next_write_region(&available);

        if (available == 0) {
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, 0, IOResult::ERROR);
            return;
        }

        ssize_t bytes_read = recv(fd, write_ptr, available, 0);

        if (bytes_read > 0) {
            conn.rx_buffer.commit_write(static_cast<size_t>(bytes_read));
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, bytes_read, IOResult::SUCCESS);
        } else if (bytes_read == 0) {
            conn.reading = false;
            auto cb = std::move(conn.read_cb);
            cb(fd, 0, IOResult::CLOSED);
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                conn.reading = false;
                auto cb = std::move(conn.read_cb);
                cb(fd, 0, IOResult::ERROR);
            }
        }
    }

    void process_write(Socket fd, ConnectionState<BufferSize>& conn) {
        if (!conn.writing) return;

        size_t available = 0;
        const uint8_t* read_ptr = conn.tx_buffer.next_read_region(&available);

        if (available == 0) {
            conn.writing = false;
            auto cb = std::move(conn.write_cb);
            cb(fd, 0, IOResult::SUCCESS);
            return;
        }

        ssize_t bytes_written = send(fd, read_ptr, available, MSG_NOSIGNAL);

        if (bytes_written > 0) {
            conn.tx_buffer.commit_read(static_cast<size_t>(bytes_written));
            conn.write_pending -= bytes_written;

            if (conn.write_pending == 0) {
                conn.writing = false;
                auto cb = std::move(conn.write_cb);
                cb(fd, bytes_written, IOResult::SUCCESS);
            }
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                conn.writing = false;
                auto cb = std::move(conn.write_cb);
                cb(fd, 0, IOResult::ERROR);
            }
        }
    }

    websocket::event_policies::SelectPolicy event_;
    std::unordered_map<Socket, ConnectionState<BufferSize>> connections_;
    std::unordered_map<Socket, AcceptHandler> listen_sockets_;
    bool running_;
    int timeout_ms_;
};

} // namespace iobackend
} // namespace websocket

// ============================================================================
// Default I/O Backend Selection
// ============================================================================

#if defined(ENABLE_IO_URING)
    // Linux with io_uring enabled
    using DefaultIOBackend = websocket::iobackend::IoUringBackend<>;
    using IOBackend = websocket::iobackend::IoUringBackend<>;
#elif defined(EVENT_POLICY_LINUX)
    // Linux with epoll (default)
    using DefaultIOBackend = websocket::iobackend::EpollBackend<>;
    using IOBackend = websocket::iobackend::EpollBackend<>;
#elif defined(EVENT_POLICY_BSD)
    // macOS/BSD with kqueue
    using DefaultIOBackend = websocket::iobackend::KqueueBackend<>;
    using IOBackend = websocket::iobackend::KqueueBackend<>;
#else
    // Fallback to select (portable)
    using DefaultIOBackend = websocket::iobackend::SelectBackend<>;
    using IOBackend = websocket::iobackend::SelectBackend<>;
#endif

// ============================================================================
// Usage Example
// ============================================================================

/*

#include "policy/io.hpp"
#include <iostream>

int main() {
    // Create I/O backend
    IOBackend io;
    io.set_timeout(1000);  // 1 second timeout

    if (!io.init()) {
        std::cerr << "Failed to initialize I/O backend" << std::endl;
        return 1;
    }

    // Create listening socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    // ... bind and listen ...

    // Make non-blocking
    int flags = fcntl(listen_fd, F_GETFL, 0);
    fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);

    // Add to I/O loop
    io.add_listen_socket(listen_fd);

    // Accept connections
    io.async_accept(listen_fd, [&io](Socket client_fd,
                                      struct sockaddr_storage addr,
                                      IOResult result) {
        if (result == IOResult::SUCCESS) {
            std::cout << "Accepted connection: " << client_fd << std::endl;

            // Start reading
            static char buf[4096];
            io.async_read(client_fd, buf, sizeof(buf),
                [&io, client_fd](Socket fd, std::size_t bytes, IOResult res) {
                    if (res == IOResult::SUCCESS) {
                        std::cout << "Read " << bytes << " bytes" << std::endl;

                        // Echo back
                        io.async_write(fd, buf, bytes,
                            [&io](Socket fd, std::size_t written, IOResult res) {
                                std::cout << "Written " << written << " bytes" << std::endl;
                                io.close(fd);
                            });
                    }
                });
        }
    });

    // Run event loop
    std::cout << "Starting I/O event loop..." << std::endl;
    io.run();

    return 0;
}

*/
