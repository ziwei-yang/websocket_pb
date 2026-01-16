# Pipeline Process 1: BSDSocketTransportProcess (Alternative to XDP Transport)

**Related Documents**:
- [Architecture Overview](pipeline_architecture.md)
- [XDP Transport Process](pipeline_1_trans.md)
- [SSL Transport Process](pipeline_1_socketssl.md)
- [WebSocket Process](pipeline_2_ws.md)

---

## Overview

BSDSocketTransportProcess provides the **same upstream interface** as the XDP-based TransportProcess but uses standard **BSD sockets** instead of AF_XDP. The kernel handles TCP state, retransmission, and ACKs - simplifying the implementation significantly.

### XDP vs BSD Socket Comparison

| Aspect | XDP TransportProcess | BSDSocketTransportProcess |
|--------|----------------------|---------------------------|
| **Transport** | AF_XDP zero-copy | BSD TCP sockets |
| **TCP Stack** | Userspace (UserspaceStack) | Kernel |
| **Retransmission** | Manual (ZeroCopyRetransmitQueue) | Kernel |
| **ACK Handling** | Manual (adaptive batching) | Kernel |
| **Memory** | UMEM frames (2048B each) | Kernel socket buffers |
| **Latency** | ~1-5 μs (NIC to app) | ~10-50 μs (kernel overhead) |
| **Complexity** | High (full TCP/IP stack) | Low (compose policies) |
| **HW Timestamps** | XDP metadata | SO_TIMESTAMPING |
| **Use Case** | Ultra-low latency HFT | Standard applications |

### Key Design Principles

1. **Same Upstream Interface**: Identical IPC rings as XDP TransportProcess
   - **Consumes**: `MSG_OUTBOX`, `PONGS`
   - **Produces**: `MSG_INBOX`, `MSG_METADATA`

2. **Simplified Architecture**: Kernel handles TCP
   - No UMEM frames
   - No retransmission queues
   - No ACK handling
   - No TCP state machine

3. **Compose Existing Policies**: Reuse existing policy classes
   - `BSDSocketTransport<EventPolicy>` from `transport.hpp`
   - `SSLPolicy` (OpenSSL/LibreSSL/WolfSSL/NoSSL) from `ssl.hpp`
   - `EventPolicy` (Epoll/Kqueue/Select) from `event.hpp`

---

## Threading Model Options

BSDSocketTransportProcess supports three threading models depending on SSL configuration:

### Option B: 2-Thread Model (NoSSL or kTLS)

For unencrypted connections or when kernel TLS (kTLS) is enabled:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    OPTION B: 2-THREAD (NoSSL or kTLS)                           │
│              Kernel handles encryption, threads do raw socket I/O               │
└─────────────────────────────────────────────────────────────────────────────────┘

     MSG_OUTBOX                                                    MSG_INBOX
     PONGS                                                         MSG_METADATA
         │                                                              ▲
         │                                                              │
         ▼                                                              │
  ┌─────────────┐                                              ┌─────────────┐
  │  TX Thread  │                                              │  RX Thread  │
  │  (Core N)   │                                              │  (Core N+2) │
  └──────┬──────┘                                              └──────┬──────┘
         │                                                            │
         │ send()                                              recv() │
         │ (plaintext if kTLS,                         (plaintext if  │
         │  or raw if NoSSL)                           kTLS/NoSSL)    │
         │                                                            │
         ▼                                                            │
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                         KERNEL TCP STACK                                     │
  │  • TCP state machine    • Retransmission    • ACK handling    • kTLS        │
  └─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                              ┌───────────┐
                              │    NIC    │
                              └───────────┘
```

**When to Use**:
- Linux with kTLS support (kernel 4.13+ for TLS 1.2, 4.17+ for TLS 1.3)
- Unencrypted internal connections (NoSSL)
- When userspace SSL overhead is acceptable

### Option C: 3-Thread Model (Userspace SSL)

When kTLS is unavailable and encryption is required:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    OPTION C: 3-THREAD (Userspace SSL)                           │
│              Separate SSL thread to avoid blocking I/O threads                  │
└─────────────────────────────────────────────────────────────────────────────────┘

     MSG_OUTBOX                                                    MSG_INBOX
     PONGS                                                         MSG_METADATA
         │                                                              ▲
         │                                                              │
         ▼                                                              │
  ┌─────────────┐           ┌─────────────┐           ┌─────────────┐
  │  TX Thread  │           │  SSL Thread │           │  RX Thread  │
  │  (Core N)   │           │  (Core N+2) │           │  (Core N+4) │
  └──────┬──────┘           └──────┬──────┘           └──────┬──────┘
         │                         │                         │
         │ ENCRYPTED_TX_RING       │ PLAINTEXT_RING          │ ENCRYPTED_RX_RING
         │◀────────────────────────│                         │────────────────────▶│
         │                         │                         │
         │                         │ SSL_write() / SSL_read()│
         │                         │ (userspace crypto)      │
         │                         │                         │
         │ send()                  │                  recv() │
         ▼                         │                         │
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                         KERNEL TCP STACK                                     │
  │  • TCP state machine    • Retransmission    • ACK handling                  │
  │  (No kTLS - raw encrypted bytes)                                            │
  └─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                              ┌───────────┐
                              │    NIC    │
                              └───────────┘
```

**Internal Rings** (between threads, not IPC to other processes):
- `ENCRYPTED_RX_RING`: Raw encrypted bytes from RX Thread to SSL Thread
- `ENCRYPTED_TX_RING`: Encrypted bytes from SSL Thread to TX Thread
- `PLAINTEXT_RING`: Decrypted bytes from SSL Thread to upstream

**When to Use**:
- macOS/BSD (no kTLS support)
- Older Linux kernels without kTLS
- When hardware doesn't support kTLS cipher suites

### Option E: Single-Thread io_uring Async (NoSSL/kTLS only)

For maximum efficiency on Linux 5.1+ with io_uring:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    OPTION E: SINGLE-THREAD io_uring                             │
│              Async I/O with completion queue - single thread handles all        │
└─────────────────────────────────────────────────────────────────────────────────┘

     MSG_OUTBOX          MSG_INBOX
     PONGS               MSG_METADATA
         │                    ▲
         │                    │
         ▼                    │
  ┌─────────────────────────────────────┐
  │         Single I/O Thread           │
  │              (Core N)               │
  │                                     │
  │  ┌─────────────────────────────┐    │
  │  │    io_uring Submission      │    │
  │  │    • IORING_OP_SEND         │    │
  │  │    • IORING_OP_RECV         │    │
  │  └─────────────────────────────┘    │
  │                │                    │
  │                ▼                    │
  │  ┌─────────────────────────────┐    │
  │  │    io_uring Completion      │    │
  │  │    • Process send results   │    │
  │  │    • Process recv data      │    │
  │  └─────────────────────────────┘    │
  └─────────────────────────────────────┘
                   │
                   ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │                         KERNEL TCP STACK + io_uring                          │
  │  • TCP state machine    • Retransmission    • Async completion              │
  └─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                              ┌───────────┐
                              │    NIC    │
                              └───────────┘
```

**When to Use**:
- Linux 5.1+ with io_uring support
- When minimizing thread count is important
- High-throughput scenarios (fewer context switches)

**Limitation**: Only works with NoSSL or kTLS (no userspace SSL).

---

## Threading Model Selection Logic

```cpp
// Compile-time selection based on SSLPolicy and platform
template<typename SSLPolicy, typename EventPolicy>
constexpr auto select_threading_model() {
    if constexpr (std::is_same_v<SSLPolicy, NoSSLPolicy>) {
        // No encryption - use simplest model
        #if defined(__linux__) && defined(ENABLE_IO_URING)
            return ThreadingModel::SINGLE_IOURING;  // Option E
        #else
            return ThreadingModel::TWO_THREAD;      // Option B
        #endif
    } else {
        // Has SSL - check kTLS availability
        #if defined(__linux__) && defined(ENABLE_KTLS)
            // kTLS available at compile time, runtime check still needed
            return ThreadingModel::TWO_THREAD_KTLS; // Option B with kTLS
        #else
            return ThreadingModel::THREE_THREAD;    // Option C
        #endif
    }
}

// Runtime kTLS detection (after SSL handshake)
bool detect_ktls_enabled(SSLPolicy& ssl) {
    return ssl.ktls_enabled();  // Returns true if kernel took over encryption
}
```

### Decision Tree

```
                           ┌──────────────────────┐
                           │  SSL Required?       │
                           └──────────┬───────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    │ NO                               │ YES
                    ▼                                  ▼
           ┌─────────────────┐                ┌─────────────────┐
           │  io_uring       │                │  kTLS           │
           │  available?     │                │  available?     │
           └────────┬────────┘                └────────┬────────┘
                    │                                  │
          ┌────────┴────────┐              ┌──────────┴──────────┐
          │ YES         │ NO              │ YES              │ NO
          ▼             ▼                 ▼                  ▼
    ┌──────────┐  ┌──────────┐     ┌──────────┐       ┌──────────┐
    │ Option E │  │ Option B │     │ Option B │       │ Option C │
    │ io_uring │  │ 2-thread │     │ 2-thread │       │ 3-thread │
    │ single   │  │ NoSSL    │     │ kTLS     │       │ userspace│
    └──────────┘  └──────────┘     └──────────┘       └──────────┘
```

---

## Template Parameters

### SSLPolicy Requirements

From `src/policy/ssl.hpp`, all SSL policies implement:

```cpp
template<typename T>
concept SSLPolicyConcept = requires(T ssl, int fd, void* buf, size_t len) {
    // Lifecycle
    { ssl.init() } -> std::same_as<void>;
    { ssl.handshake(fd) } -> std::same_as<void>;    // BSD socket mode
    { ssl.shutdown() } -> std::same_as<void>;

    // Read/Write (for Option C userspace SSL)
    { ssl.read(buf, len) } -> std::convertible_to<ssize_t>;
    { ssl.write(buf, len) } -> std::convertible_to<ssize_t>;
    { ssl.pending() } -> std::convertible_to<size_t>;

    // Status
    { ssl.ktls_enabled() } -> std::convertible_to<bool>;
    { ssl.get_fd() } -> std::convertible_to<int>;
};
```

**Available Policies**:
| Policy | kTLS Support | Use Case |
|--------|--------------|----------|
| `OpenSSLPolicy` | Yes (Linux) | Production, kTLS preferred |
| `LibreSSLPolicy` | No | macOS default |
| `WolfSSLPolicy` | No | Embedded, lightweight |
| `NoSSLPolicy` | N/A | Plain TCP, testing |

### EventPolicy Requirements

From `src/policy/event.hpp`, all event policies implement:

```cpp
template<typename T>
concept EventPolicyConcept = requires(T event, int fd, int timeout) {
    { event.init() } -> std::same_as<void>;
    { event.add_read(fd) } -> std::same_as<void>;
    { event.add_write(fd) } -> std::same_as<void>;
    { event.set_wait_timeout(timeout) } -> std::same_as<void>;
    { event.wait_with_timeout() } -> std::convertible_to<int>;
    { event.get_ready_fd() } -> std::convertible_to<int>;
    { event.is_readable() } -> std::convertible_to<bool>;
    { event.is_writable() } -> std::convertible_to<bool>;
    { event.has_error() } -> std::convertible_to<bool>;
};
```

**Available Policies**:
| Policy | Platform | Notes |
|--------|----------|-------|
| `EpollPolicy` | Linux | Edge-triggered, O(1) |
| `KqueuePolicy` | macOS/BSD | EV_CLEAR for edge-triggered |
| `SelectPolicy` | All | Fallback, O(n), FD_SETSIZE limit |

---

## Class Definition

### Option B: 2-Thread Model

```cpp
template<typename SSLPolicy, typename EventPolicy = DefaultEventPolicy>
class BSDSocketTransportProcess_TwoThread {
public:
    // Same upstream interface as XDP TransportProcess
    bool init(const char* host, uint16_t port,
              ConnStateShm* conn_state,
              MsgOutboxCons* msg_outbox_cons,
              PongsCons* pongs_cons,
              MsgInbox* msg_inbox,
              MsgMetadataProd* msg_metadata_prod);

    void run();      // Spawns RX and TX threads
    void shutdown();

private:
    // Transport and SSL
    BSDSocketTransport<EventPolicy> transport_;
    SSLPolicy ssl_policy_;

    // Shared state (same as XDP Transport)
    ConnStateShm* conn_state_ = nullptr;

    // IPC rings (same interface as XDP Transport)
    MsgOutboxCons* msg_outbox_cons_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;
    MsgInbox* msg_inbox_ = nullptr;
    MsgMetadataProd* msg_metadata_prod_ = nullptr;

    // Timestamp tracking (simplified - no UMEM timestamps)
    uint64_t last_recv_cycle_ = 0;

    // Thread handles
    std::thread rx_thread_;
    std::thread tx_thread_;
    std::atomic<bool> running_{false};

    // Internal methods
    void rx_thread_main();
    void tx_thread_main();
};
```

### Option C: 3-Thread Model

```cpp
template<typename SSLPolicy, typename EventPolicy = DefaultEventPolicy>
class BSDSocketTransportProcess_ThreeThread {
public:
    // Same upstream interface
    bool init(const char* host, uint16_t port, /* ... same params ... */);
    void run();
    void shutdown();

private:
    // Transport and SSL
    BSDSocketTransport<EventPolicy> transport_;
    SSLPolicy ssl_policy_;

    // Shared state and IPC rings (same as 2-thread)
    ConnStateShm* conn_state_ = nullptr;
    MsgOutboxCons* msg_outbox_cons_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;
    MsgInbox* msg_inbox_ = nullptr;
    MsgMetadataProd* msg_metadata_prod_ = nullptr;

    // Internal rings (between threads)
    // SPSC for minimal overhead
    using EncryptedRing = SPSCRingBuffer<EncryptedChunk, 1024>;
    using PlaintextRing = SPSCRingBuffer<PlaintextChunk, 1024>;

    EncryptedRing encrypted_rx_ring_;   // RX Thread → SSL Thread
    EncryptedRing encrypted_tx_ring_;   // SSL Thread → TX Thread
    PlaintextRing plaintext_rx_ring_;   // SSL Thread → MSG_INBOX

    // Thread handles
    std::thread rx_thread_;
    std::thread ssl_thread_;
    std::thread tx_thread_;
    std::atomic<bool> running_{false};

    // Thread entry points
    void rx_thread_main();
    void ssl_thread_main();
    void tx_thread_main();
};
```

### Option E: Single-Thread io_uring

```cpp
#ifdef __linux__
#include <liburing.h>

template<typename SSLPolicy>  // Must be NoSSL or kTLS-capable
class BSDSocketTransportProcess_IoUring {
public:
    // Same upstream interface
    bool init(const char* host, uint16_t port, /* ... same params ... */);
    void run();      // Single-threaded event loop
    void shutdown();

private:
    // Transport (no separate EventPolicy - io_uring handles events)
    int sockfd_ = -1;
    SSLPolicy ssl_policy_;

    // io_uring state
    struct io_uring ring_;
    static constexpr unsigned QUEUE_DEPTH = 256;

    // Receive buffer pool (for IORING_OP_RECV)
    static constexpr size_t RECV_BUFSIZE = 16384;
    std::array<uint8_t, RECV_BUFSIZE * 16> recv_pool_;
    int recv_buf_group_id_ = 0;

    // Shared state and IPC rings (same interface)
    ConnStateShm* conn_state_ = nullptr;
    MsgOutboxCons* msg_outbox_cons_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;
    MsgInbox* msg_inbox_ = nullptr;
    MsgMetadataProd* msg_metadata_prod_ = nullptr;

    std::atomic<bool> running_{false};

    // io_uring helpers
    void submit_recv();
    void submit_send(const uint8_t* data, size_t len);
    void process_completions();
};
#endif
```

---

## Lifecycle & Handshake

Unlike XDP TransportProcess which performs handshake via IPC rings, BSDSocketTransportProcess performs a **blocking handshake** before spawning worker threads:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      BSD SOCKET TRANSPORT LIFECYCLE                             │
└─────────────────────────────────────────────────────────────────────────────────┘

  Main Thread (init)                     Worker Threads (run)
  ──────────────────                     ────────────────────
        │
        ▼
  ┌─────────────────┐
  │ transport_.init()
  │ (create event loop)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ transport_.connect(host, port)
  │ (blocking TCP handshake)
  │ - socket()
  │ - connect() with timeout
  │ - setsockopt(TCP_NODELAY)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ ssl_policy_.init()
  │ ssl_policy_.handshake(fd)
  │ (blocking TLS handshake)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │ Check kTLS status
  │ ssl_policy_.ktls_enabled()
  └────────┬────────┘
           │
           ├─────────── if kTLS ────────▶ ┌─────────────────┐
           │                              │ Option B setup  │
           │                              │ (2-thread)      │
           │                              └────────┬────────┘
           │                                       │
           ├─────────── if NoSSL ───────▶ ┌─────────────────┐
           │                              │ Option B setup  │
           │                              │ (2-thread)      │
           │                              └────────┬────────┘
           │                                       │
           └─────────── if userspace SSL ▶ ┌─────────────────┐
                                           │ Option C setup  │
                                           │ (3-thread)      │
                                           └────────┬────────┘
                                                    │
                                                    ▼
                                          ┌─────────────────┐
                                          │ transport_.start_event_loop()
                                          │ (set non-blocking)
                                          │ (register with epoll/kqueue)
                                          └────────┬────────┘
                                                   │
                                                   ▼
                                          ┌─────────────────┐
                                          │ Spawn threads   │
                                          │ - rx_thread_    │
                                          │ - tx_thread_    │
                                          │ - ssl_thread_   │ (if Option C)
                                          └────────┬────────┘
                                                   │
                                                   ▼
                                          ┌─────────────────┐
                                          │ Signal ready    │
                                          │ conn_state_->   │
                                          │   set_handshake_│
                                          │   tls_ready()   │
                                          └─────────────────┘
```

### Initialization Code

```cpp
template<typename SSLPolicy, typename EventPolicy>
bool BSDSocketTransportProcess_TwoThread<SSLPolicy, EventPolicy>::init(
        const char* host, uint16_t port, /* ... */) {

    conn_state_ = conn_state;
    msg_outbox_cons_ = msg_outbox_cons;
    pongs_cons_ = pongs_cons;
    msg_inbox_ = msg_inbox;
    msg_metadata_prod_ = msg_metadata_prod;

    // Initialize transport (creates event loop)
    transport_.init();

    // Blocking TCP connect
    try {
        transport_.connect(host, port);
    } catch (const std::exception& e) {
        printf("[BSDSocket] TCP connect failed: %s\n", e.what());
        return false;
    }

    // Initialize and perform SSL handshake
    ssl_policy_.init();
    try {
        ssl_policy_.handshake(transport_.get_fd());
    } catch (const std::exception& e) {
        printf("[BSDSocket] TLS handshake failed: %s\n", e.what());
        return false;
    }

    // Check kTLS status
    if (ssl_policy_.ktls_enabled()) {
        printf("[BSDSocket] kTLS enabled - kernel handles encryption\n");
    } else {
        printf("[BSDSocket] Userspace SSL - application handles encryption\n");
        // NOTE: For 2-thread model, this still works but with higher CPU usage
        // Consider upgrading to 3-thread model for better performance
    }

    // Start event loop monitoring (sets non-blocking, registers fd)
    transport_.start_event_loop();

    // Enable hardware timestamps if available
    #ifdef __linux__
    int flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
    setsockopt(transport_.get_fd(), SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));
    #endif

    return true;
}
```

---

## Main Loop Implementation

### Option B: RX Thread

```cpp
template<typename SSLPolicy, typename EventPolicy>
void BSDSocketTransportProcess_TwoThread<SSLPolicy, EventPolicy>::rx_thread_main() {
    constexpr size_t RECV_BUFSIZE = 16384;  // TLS record max size
    std::array<uint8_t, RECV_BUFSIZE> recv_buf;

    // Set thread affinity if configured
    // set_cpu_affinity(conn_state_->rx_core_id);

    transport_.set_wait_timeout(1);  // 1ms timeout for responsive shutdown

    while (running_.load(std::memory_order_acquire)) {
        // Wait for data (epoll/kqueue)
        int ready = transport_.wait_with_timeout();

        if (ready <= 0) {
            continue;  // Timeout or interrupted
        }

        if (transport_.is_error()) {
            printf("[RX] Socket error detected\n");
            running_.store(false, std::memory_order_release);
            break;
        }

        // Record timestamp before SSL_read
        uint64_t recv_start_cycle = rdtscp();

        // Read decrypted data (kTLS: kernel decrypts, NoSSL: raw bytes)
        ssize_t n = ssl_policy_.read(recv_buf.data(), recv_buf.size());

        if (n > 0) {
            uint64_t recv_end_cycle = rdtscp();

            // Write to MSG_INBOX (same as XDP Transport)
            uint32_t write_pos = msg_inbox_->current_write_pos();
            msg_inbox_->write_data(recv_buf.data(), n);

            // Publish MsgMetadata (simplified - no NIC HW timestamps)
            int64_t seq = msg_metadata_prod_->try_claim();
            if (seq >= 0) {
                auto& meta = (*msg_metadata_prod_)[seq];
                meta.clear();

                // BSD socket timestamps (SW kernel timestamp if available)
                meta.first_nic_timestamp_ns = 0;      // No HW timestamp
                meta.first_nic_frame_poll_cycle = 0;
                meta.latest_nic_timestamp_ns = 0;
                meta.latest_nic_frame_poll_cycle = 0;
                meta.latest_raw_frame_poll_cycle = recv_start_cycle;
                meta.ssl_read_cycle = recv_end_cycle;
                meta.msg_inbox_offset = write_pos;
                meta.decrypted_len = static_cast<uint32_t>(n);

                msg_metadata_prod_->publish(seq);
            }
        } else if (n == 0) {
            // Connection closed
            printf("[RX] Connection closed by peer\n");
            running_.store(false, std::memory_order_release);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // Error (not would-block)
            printf("[RX] recv error: %s\n", strerror(errno));
            running_.store(false, std::memory_order_release);
        }
    }
}
```

### Option B: TX Thread

```cpp
template<typename SSLPolicy, typename EventPolicy>
void BSDSocketTransportProcess_TwoThread<SSLPolicy, EventPolicy>::tx_thread_main() {

    while (running_.load(std::memory_order_acquire)) {
        bool did_work = false;

        // Process MSG_OUTBOX (pre-framed messages from upstream)
        size_t processed = msg_outbox_cons_->process_manually(
            [&](MsgOutboxEvent& event, int64_t seq, bool end_of_batch) {
                if (event.data_len > 0) {
                    // Send encrypted (kTLS: kernel encrypts, NoSSL: raw)
                    ssize_t sent = ssl_policy_.write(event.data, event.data_len);

                    if (sent < 0 && errno != EAGAIN) {
                        printf("[TX] send error: %s\n", strerror(errno));
                        running_.store(false, std::memory_order_release);
                        return false;  // Stop processing
                    }
                }

                if (event.msg_type == MSG_TYPE_WS_CLOSE) {
                    // Graceful shutdown requested
                    running_.store(false, std::memory_order_release);
                    return false;
                }

                return true;  // Continue processing
            },
            16  // Max events per batch
        );

        if (processed > 0) {
            msg_outbox_cons_->commit_manually();
            did_work = true;
        }

        // Process PONGS (pre-framed PONG responses)
        processed = pongs_cons_->process_manually(
            [&](PongFrameAligned& pong, int64_t seq, bool end_of_batch) {
                if (pong.data_len > 0) {
                    ssize_t sent = ssl_policy_.write(pong.data, pong.data_len);

                    if (sent < 0 && errno != EAGAIN) {
                        printf("[TX] PONG send error: %s\n", strerror(errno));
                    }
                }
                return true;
            },
            8  // PONG priority - process fewer per batch
        );

        if (processed > 0) {
            pongs_cons_->commit_manually();
            did_work = true;
        }

        // Yield if no work (avoid busy-spin when idle)
        if (!did_work) {
            std::this_thread::yield();
        }
    }
}
```

### Option C: SSL Thread (Additional)

```cpp
template<typename SSLPolicy, typename EventPolicy>
void BSDSocketTransportProcess_ThreeThread<SSLPolicy, EventPolicy>::ssl_thread_main() {
    // SSL thread handles encryption/decryption between RX/TX threads

    while (running_.load(std::memory_order_acquire)) {
        bool did_work = false;

        // Process RX: encrypted → decrypted
        while (encrypted_rx_ring_.has_data()) {
            EncryptedChunk chunk;
            if (encrypted_rx_ring_.try_consume(chunk)) {
                // Feed to SSL
                ssl_policy_.append_encrypted_view(chunk.data, chunk.len);

                // Attempt to read decrypted data
                uint8_t decrypt_buf[16384];
                ssize_t n = ssl_policy_.read(decrypt_buf, sizeof(decrypt_buf));

                if (n > 0) {
                    // Write to MSG_INBOX and publish metadata
                    uint32_t write_pos = msg_inbox_->current_write_pos();
                    msg_inbox_->write_data(decrypt_buf, n);

                    int64_t seq = msg_metadata_prod_->try_claim();
                    if (seq >= 0) {
                        auto& meta = (*msg_metadata_prod_)[seq];
                        meta.clear();
                        meta.latest_raw_frame_poll_cycle = chunk.recv_cycle;
                        meta.ssl_read_cycle = rdtscp();
                        meta.msg_inbox_offset = write_pos;
                        meta.decrypted_len = static_cast<uint32_t>(n);
                        msg_metadata_prod_->publish(seq);
                    }
                }

                did_work = true;
            }
        }

        // Process TX: plaintext → encrypted
        // (MSG_OUTBOX consumer runs in this thread for Option C)
        size_t processed = msg_outbox_cons_->process_manually(
            [&](MsgOutboxEvent& event, int64_t seq, bool end_of_batch) {
                if (event.data_len > 0) {
                    // Encrypt via SSL
                    uint8_t encrypt_buf[16384 + 256];  // TLS record + overhead
                    ssl_policy_.set_encrypted_output(encrypt_buf, sizeof(encrypt_buf));
                    ssl_policy_.write(event.data, event.data_len);
                    size_t encrypted_len = ssl_policy_.encrypted_output_len();
                    ssl_policy_.clear_encrypted_output();

                    // Queue encrypted data for TX thread
                    EncryptedChunk out_chunk;
                    memcpy(out_chunk.data, encrypt_buf, encrypted_len);
                    out_chunk.len = encrypted_len;
                    encrypted_tx_ring_.try_publish(out_chunk);
                }
                return true;
            },
            16
        );

        if (processed > 0) {
            msg_outbox_cons_->commit_manually();
            did_work = true;
        }

        if (!did_work) {
            std::this_thread::yield();
        }
    }
}
```

---

## Timestamp Mapping

BSDSocketTransportProcess produces `MsgMetadata` with timestamps, but the available precision differs from XDP:

### MsgMetadata Fields

| Field | XDP Transport | BSD Socket Transport |
|-------|---------------|----------------------|
| `first_nic_timestamp_ns` | NIC HW timestamp | 0 (or SO_TIMESTAMPING SW timestamp) |
| `first_nic_frame_poll_cycle` | XDP Poll rdtscp | 0 |
| `latest_nic_timestamp_ns` | NIC HW timestamp | 0 (or SO_TIMESTAMPING SW timestamp) |
| `latest_nic_frame_poll_cycle` | XDP Poll rdtscp | 0 |
| `latest_raw_frame_poll_cycle` | Transport rdtscp | rdtscp before SSL_read |
| `ssl_read_cycle` | After SSL_read | After SSL_read |
| `msg_inbox_offset` | Same | Same |
| `decrypted_len` | Same | Same |

### SO_TIMESTAMPING Support (Linux)

BSD sockets can request software/hardware timestamps via SO_TIMESTAMPING:

```cpp
// Enable timestamps on socket
int flags = SOF_TIMESTAMPING_RX_SOFTWARE |
            SOF_TIMESTAMPING_SOFTWARE;

#ifdef SOF_TIMESTAMPING_RX_HARDWARE
flags |= SOF_TIMESTAMPING_RX_HARDWARE |
         SOF_TIMESTAMPING_RAW_HARDWARE;
#endif

setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));

// Retrieve timestamps via recvmsg() ancillary data
struct msghdr msg = {};
struct iovec iov = { recv_buf, sizeof(recv_buf) };
char control[256];

msg.msg_iov = &iov;
msg.msg_iovlen = 1;
msg.msg_control = control;
msg.msg_controllen = sizeof(control);

ssize_t n = recvmsg(fd, &msg, 0);

// Parse control messages for timestamp
for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
        struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);
        // ts[0] = software timestamp
        // ts[1] = deprecated
        // ts[2] = hardware timestamp (if available)
    }
}
```

---

## Key Differences from XDP TransportProcess

### Removed Components

| XDP Transport | BSD Socket | Reason |
|---------------|------------|--------|
| `UserspaceStack` | Not needed | Kernel handles TCP |
| `ZeroCopyRetransmitQueue` | Not needed | Kernel handles retransmit |
| Adaptive ACK batching | Not needed | Kernel handles ACKs |
| UMEM frame management | Not needed | Kernel socket buffers |
| RAW_INBOX/RAW_OUTBOX | Not needed | No raw frame exchange |
| ACK_OUTBOX/PONG_OUTBOX | Not needed | No separate ACK/PONG frames |
| `TxFrameState` | Not needed | No TX frame allocation |

### Changed Components

| Aspect | XDP Transport | BSD Socket |
|--------|---------------|------------|
| Handshake | Via IPC rings (fork-first) | Blocking connect() + SSL_handshake() |
| Timestamps | NIC HW + XDP Poll cycle | SO_TIMESTAMPING SW + recv cycle |
| Threading | Single thread | 2 or 3 threads |
| TX path | UMEM → RAW_OUTBOX | send() directly |
| RX path | RAW_INBOX → UMEM | recv() directly |

### Unchanged Components

| Component | Notes |
|-----------|-------|
| `MSG_INBOX` | Same byte stream ring |
| `MSG_METADATA` | Same structure (some fields zeroed) |
| `MSG_OUTBOX` | Same pre-framed message ring |
| `PONGS` | Same pre-framed PONG ring |
| `ConnStateShm` | Same (TCP fields unused) |
| Upstream interface | Identical to WebSocket Process |

---

## NoSSLPolicy Enhancement

The existing `NoSSLPolicy` in `ssl.hpp` already supports both transport modes:

1. **Transport mode**: Direct `recv_fn_`/`send_fn_` calls (for handshake_userspace_transport)
2. **Zero-copy mode**: Ring buffer views (for XDP pipeline)

For BSD socket usage, `NoSSLPolicy` works directly with the socket fd:

```cpp
// NoSSLPolicy enhancement for unified API
struct NoSSLPolicy {
    // Existing methods work for BSD sockets:
    void init() { /* no-op */ }
    void handshake(int fd) { fd_ = fd; /* no-op */ }
    void shutdown() { fd_ = -1; }

    // Read/write pass-through to socket
    ssize_t read(void* buf, size_t len) {
        return ::recv(fd_, buf, len, 0);
    }

    ssize_t write(const void* buf, size_t len) {
        return ::send(fd_, buf, len, MSG_NOSIGNAL);
    }

    bool ktls_enabled() const { return false; }
    int get_fd() const { return fd_; }

private:
    int fd_ = -1;  // Store fd for read/write
};
```

This allows `BSDSocketTransportProcess<NoSSLPolicy>` to work identically to SSL variants, just without encryption overhead.

---

## Future Improvements

### 1. io_uring with SSL (Hybrid)

For io_uring with userspace SSL, a hybrid approach could use:
- io_uring for async socket I/O
- Separate SSL thread for encryption/decryption
- Shared ring buffers between completion handler and SSL thread

### 2. KTLS + io_uring

Linux 5.17+ supports kTLS with io_uring, enabling true async encrypted I/O:

```cpp
// Enable kTLS first, then use io_uring SEND/RECV
// Kernel handles encryption/decryption asynchronously
io_uring_prep_send(sqe, fd, plaintext, len, 0);  // kTLS encrypts
io_uring_prep_recv(sqe, fd, buf, len, 0);        // kTLS decrypts
```

### 3. Zero-Copy sendfile/splice

For large message TX, consider `sendfile()` or `splice()` for zero-copy from user buffers to socket, combined with kTLS for encrypted zero-copy TX.
