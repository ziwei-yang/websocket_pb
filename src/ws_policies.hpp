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
//   void init()
//     - Initialize buffer (capacity is compile-time template param or from shm)
//
//   uint8_t* next_write_region(size_t* available_len)
//     - Get pointer to next writable region (zero-copy, producer only)
//
//   void commit_write(size_t len)
//     - Commit written bytes (producer only)
//
//   const uint8_t* next_read_region(size_t* available_len)
//     - Get pointer to next readable region (zero-copy, consumer only)
//
//   void commit_read(size_t len)
//     - Commit consumed bytes (consumer only)
//
//   size_t readable() const
//     - Get number of bytes available for reading (consumer)
//
//   size_t writable() const
//     - Get number of bytes available for writing (producer)
//
//   size_t capacity() const
//     - Get total buffer capacity in bytes
//
//   bool is_mmap() const
//     - Returns true if buffer uses memory-mapped allocation
//
//   bool is_mirrored() const
//     - Returns true if buffer uses virtual memory mirroring (zero-wraparound)
//
// Implementations:
//   - RingBuffer<Capacity>: Lock-free SPSC ring buffer (private memory)
//   - HftShmRxBuffer<Name>: Shared memory ring buffer (producer role)
//   - HftShmTxBuffer<Name>: Shared memory ring buffer (consumer role)

// ============================================================================
// C++20 Concept Definitions
// ============================================================================
//
// NOTE: The actual C++20 concept definitions are in the policy implementation files:
//   - SSLPolicyConcept:    policy/ssl.hpp
//   - EventPolicyConcept:  policy/event.hpp
//   - TransportPolicyConcept: policy/transport.hpp
//
// BufferPolicyConcept is defined below since it's not in a separate policy file.
//

#if __cplusplus >= 202002L
#include <concepts>

// BufferPolicyConcept - defines the interface for RingBuffer and HftShmRingBuffer
template<typename T>
concept BufferPolicyConcept = requires(T buffer, size_t len, size_t* out_len) {
    { buffer.init() } -> std::same_as<void>;
    { buffer.next_write_region(out_len) } -> std::convertible_to<uint8_t*>;
    { buffer.commit_write(len) } -> std::same_as<void>;
    { buffer.next_read_region(out_len) } -> std::convertible_to<const uint8_t*>;
    { buffer.commit_read(len) } -> std::same_as<void>;
    { buffer.readable() } -> std::convertible_to<size_t>;
    { buffer.writable() } -> std::convertible_to<size_t>;
    { buffer.capacity() } -> std::convertible_to<size_t>;
    { buffer.is_mmap() } -> std::convertible_to<bool>;
    { buffer.is_mirrored() } -> std::convertible_to<bool>;
};

#endif // C++20
