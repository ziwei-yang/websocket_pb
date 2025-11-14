// ws_policies.h
// Policy interface documentation and requirements
#pragma once

#include <cstddef>
#include <cstdint>

// Policy-based design interfaces for WebSocket library
// Each policy defines a compile-time behavioral aspect

// ============================================================================
// SocketPolicy: Handles low-level socket operations
// ============================================================================
// Required methods:
//   int create()
//     - Creates socket, returns file descriptor
//
//   void connect(int fd, const char* host, uint16_t port)
//     - Establishes TCP connection
//
//   void set_nonblocking(int fd)
//     - Sets socket to non-blocking mode
//
//   void close(int fd)
//     - Closes socket
//
// Implementations:
//   - BSDSocketPolicy: Standard BSD socket API (socket.h)
//   - IoUringSocketPolicy: io_uring-based async socket operations

// ============================================================================
// SSLPolicy: Handles SSL/TLS operations
// ============================================================================
// Required methods:
//   void init()
//     - Initialize SSL context
//
//   void handshake(int fd)
//     - Perform TLS handshake on socket
//
//   ssize_t read(void* buf, size_t len)
//     - Read decrypted data
//
//   ssize_t write(const void* buf, size_t len)
//     - Write encrypted data
//
//   bool ktls_enabled() const
//     - Returns true if kernel TLS is active
//
//   int get_fd() const
//     - Get underlying socket file descriptor
//
//   void shutdown()
//     - Clean shutdown of SSL connection
//
// Implementations:
//   - OpenSSLPolicy: OpenSSL with optional kTLS support (Linux)
//   - WolfSSLPolicy: WolfSSL library
//   - LibreSSLPolicy: LibreSSL (macOS default)

// ============================================================================
// EventPolicy: Handles I/O event notification
// ============================================================================
// Required methods:
//   void init()
//     - Initialize event loop
//
//   void add_read(int fd)
//     - Register file descriptor for read events
//
//   void add_write(int fd)
//     - Register file descriptor for write events
//
//   void modify(int fd, uint32_t events)
//     - Modify event registration
//
//   int wait(int timeout_ms)
//     - Wait for events, returns number of ready descriptors
//
//   int get_ready_fd()
//     - Get file descriptor that triggered event
//
// Implementations:
//   - EpollPolicy: Linux epoll (edge-triggered)
//   - KqueuePolicy: BSD/macOS kqueue
//   - IoUringEventPolicy: io_uring event loop

// ============================================================================
// BufferPolicy: Handles ring buffer operations
// ============================================================================
// Required methods:
//   void init(size_t capacity)
//     - Initialize buffer with given capacity
//
//   uint8_t* next_write_region(size_t* available_len)
//     - Get pointer to next writable region (zero-copy)
//
//   void commit_write(size_t len)
//     - Commit written bytes
//
//   const uint8_t* next_read_region(size_t* available_len)
//     - Get pointer to next readable region (zero-copy)
//
//   void commit_read(size_t len)
//     - Commit consumed bytes
//
//   size_t readable() const
//     - Get number of bytes available for reading
//
//   size_t writable() const
//     - Get number of bytes available for writing
//
// Implementations:
//   - RingBufferPolicy: Lock-free single-producer single-consumer ring buffer

// ============================================================================
// C++20 Concept Definitions (optional, for better error messages)
// ============================================================================

#if __cplusplus >= 202002L
#include <concepts>

template<typename T>
concept SocketPolicyConcept = requires(T socket, int fd, const char* host, uint16_t port) {
    { socket.create() } -> std::convertible_to<int>;
    { socket.connect(fd, host, port) } -> std::same_as<void>;
    { socket.set_nonblocking(fd) } -> std::same_as<void>;
    { socket.close(fd) } -> std::same_as<void>;
};

template<typename T>
concept SSLPolicyConcept = requires(T ssl, int fd, void* buf, size_t len) {
    { ssl.init() } -> std::same_as<void>;
    { ssl.handshake(fd) } -> std::same_as<void>;
    { ssl.read(buf, len) } -> std::convertible_to<ssize_t>;
    { ssl.write(buf, len) } -> std::convertible_to<ssize_t>;
    { ssl.ktls_enabled() } -> std::convertible_to<bool>;
    { ssl.get_fd() } -> std::convertible_to<int>;
    { ssl.shutdown() } -> std::same_as<void>;
};

template<typename T>
concept EventPolicyConcept = requires(T event, int fd, uint32_t events, int timeout) {
    { event.init() } -> std::same_as<void>;
    { event.add_read(fd) } -> std::same_as<void>;
    { event.add_write(fd) } -> std::same_as<void>;
    { event.modify(fd, events) } -> std::same_as<void>;
    { event.wait(timeout) } -> std::convertible_to<int>;
    { event.get_ready_fd() } -> std::convertible_to<int>;
};

template<typename T>
concept BufferPolicyConcept = requires(T buffer, size_t cap, size_t len, size_t* out_len) {
    { buffer.init(cap) } -> std::same_as<void>;
    { buffer.next_write_region(out_len) } -> std::convertible_to<uint8_t*>;
    { buffer.commit_write(len) } -> std::same_as<void>;
    { buffer.next_read_region(out_len) } -> std::convertible_to<const uint8_t*>;
    { buffer.commit_read(len) } -> std::same_as<void>;
    { buffer.readable() } -> std::convertible_to<size_t>;
    { buffer.writable() } -> std::convertible_to<size_t>;
};

#endif // C++20
