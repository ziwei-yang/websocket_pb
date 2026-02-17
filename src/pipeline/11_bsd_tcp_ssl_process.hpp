// pipeline/11_bsd_tcp_ssl_process.hpp
// Unified BSDSocketTransportProcess - Policy-based BSD socket transport
//
// Supports:
//   - SSLPolicy: NoSSLPolicy, OpenSSLPolicy, LibreSSLPolicy, kTLSPolicy
//   - IOPolicy: BlockingIO<EventPolicy> or AsyncIO (io_uring)
//   - SSLThreadingPolicy: InlineSSL (2-thread), DedicatedSSL (3-thread), SingleThreadSSL (1-thread)
//
// Thread Models:
//   - BlockingIO + SingleThreadSSL: 1 thread (single-thread RX+TX loop, no spinlocks)
//   - BlockingIO + InlineSSL: 2 threads (RX + TX, SSL inline)
//   - BlockingIO + DedicatedSSL: 3 threads (RX + SSL + TX)
//   - AsyncIO + InlineSSL: 1 thread (io_uring event loop)
//
// C++20, policy-based design
#pragma once

#include <cstdint>
#include <cstring>
#include <atomic>
#include <thread>
#include <chrono>
#include <array>
#include <memory>
#include <variant>
#include <type_traits>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>

#ifdef __linux__
#include <liburing.h>
#endif

#include "pipeline_data.hpp"
#include "pipeline_config.hpp"
#include "msg_inbox.hpp"
#include "../core/timing.hpp"
#include "../policy/event.hpp"
#include "../policy/ssl.hpp"
#include "21_ws_core.hpp"

namespace websocket::pipeline {

// ============================================================================
// I/O Policy Definitions
// ============================================================================

/**
 * BlockingIO - Event-based blocking I/O policy
 *
 * Uses select/poll/epoll/kqueue for event notification with blocking recv/send.
 *
 * @tparam EventPolicy Event notification policy (EpollPolicy, KqueuePolicy, SelectPolicy)
 */
template<typename EventPolicy>
struct BlockingIO {
    static constexpr bool is_async = false;
    using event_policy_t = EventPolicy;
};

/**
 * AsyncIO - io_uring-based async I/O policy (Linux only)
 *
 * Uses io_uring for fully asynchronous I/O. Single-threaded event loop.
 * Only supports NoSSL or kTLS (no userspace SSL).
 */
struct AsyncIO {
    static constexpr bool is_async = true;
};

// Convenience type aliases for common configurations
#ifdef EVENT_POLICY_LINUX
using BlockingEpoll = BlockingIO<websocket::event_policies::EpollPolicy>;
#endif

#ifdef EVENT_POLICY_BSD
using BlockingKqueue = BlockingIO<websocket::event_policies::KqueuePolicy>;
#endif

using BlockingSelect = BlockingIO<websocket::event_policies::SelectPolicy>;

// Platform-default blocking I/O
#if defined(__linux__)
    using DefaultBlockingIO = BlockingEpoll;
#elif defined(__APPLE__) || defined(__FreeBSD__)
    using DefaultBlockingIO = BlockingKqueue;
#else
    using DefaultBlockingIO = BlockingSelect;
#endif

// ============================================================================
// SSL Threading Policy Definitions
// ============================================================================

/**
 * InlineSSL - SSL operations inline with I/O threads
 *
 * For BlockingIO: RX thread does recv + SSL_read, TX thread does SSL_write + send
 * For AsyncIO: Single thread handles all I/O (no userspace SSL)
 */
struct InlineSSL {
    static constexpr bool has_ssl_thread = false;
    static constexpr bool is_single_thread = false;
};

/**
 * DedicatedSSL - Separate SSL thread for encryption/decryption
 *
 * Only valid with BlockingIO:
 *   - RX thread: recv() raw bytes -> encrypted_rx_ring
 *   - SSL thread: decrypt RX, encrypt TX
 *   - TX thread: encrypted_tx_ring -> send() raw bytes
 *
 * Not valid with AsyncIO (kernel handles encryption via kTLS)
 */
struct DedicatedSSL {
    static constexpr bool has_ssl_thread = true;
    static constexpr bool is_single_thread = false;
};

/**
 * SingleThreadSSL - Single-threaded RX+TX in one loop
 *
 * Only valid with BlockingIO:
 *   - Single thread: poll(all sockets, 1ms) → recv → decrypt → publish, then TX
 *   - No spinlocks (no concurrent SSL access)
 *   - Trade-off: TX latency depends on poll timeout
 *
 * Best for market-data-only scenarios where TX latency is not critical.
 */
struct SingleThreadSSL {
    static constexpr bool has_ssl_thread = false;
    static constexpr bool is_single_thread = true;
};

// ============================================================================
// Policy Traits and Validation
// ============================================================================

namespace detail {

// Check if SSL policy is userspace (requires SSL thread potentially)
template<typename SSLPolicy>
struct is_userspace_ssl : std::true_type {};

template<>
struct is_userspace_ssl<websocket::ssl::NoSSLPolicy> : std::false_type {};

// kTLSPolicy would also be false if we had one
// template<>
// struct is_userspace_ssl<kTLSPolicy> : std::false_type {};

template<typename SSLPolicy>
inline constexpr bool is_userspace_ssl_v = is_userspace_ssl<SSLPolicy>::value;

} // namespace detail

// ============================================================================
// Local Ring Buffer (Non-IPC, for internal thread communication)
// ============================================================================

/**
 * LocalRingBuffer - SPSC ring buffer for internal thread communication
 *
 * Lock-free using acquire/release memory ordering.
 * API similar to IPCRingProducer/Consumer for consistency.
 *
 * @tparam T Element type
 * @tparam N Ring size (must be power of 2)
 */
template<typename T, size_t N>
class LocalRingBuffer {
    static_assert((N & (N - 1)) == 0, "N must be power of 2");
    static constexpr size_t MASK = N - 1;

public:
    LocalRingBuffer() = default;

    // ========================================================================
    // Producer API (try_claim + publish pattern)
    // ========================================================================

    /**
     * Try to claim the next slot in the ring buffer
     * @return sequence number >= 0 on success, -1 if buffer full
     */
    int64_t try_claim() {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t next_head = (head + 1) & MASK;

        if (next_head == tail_.load(std::memory_order_acquire)) {
            return -1;  // Full
        }

        claimed_head_ = head;
        return static_cast<int64_t>(head);
    }

    /**
     * Access slot at claimed sequence
     */
    T& operator[](int64_t seq) {
        return buffer_[static_cast<size_t>(seq) & MASK];
    }

    const T& operator[](int64_t seq) const {
        return buffer_[static_cast<size_t>(seq) & MASK];
    }

    /**
     * Publish the claimed sequence (makes it visible to consumer)
     */
    void publish(int64_t /*seq*/) {
        size_t next = (claimed_head_ + 1) & MASK;
        head_.store(next, std::memory_order_release);
    }

    // ========================================================================
    // Consumer API (process_manually + commit_manually pattern)
    // ========================================================================

    /**
     * Check if data is available
     */
    bool has_data() const {
        size_t tail = consumer_tail_.load(std::memory_order_relaxed);
        size_t head = head_.load(std::memory_order_acquire);
        return tail != head;
    }

    /**
     * Process available events with handler
     *
     * @tparam F Callable: bool(T&, int64_t, bool) or void(T&, int64_t, bool)
     * @param handler Event handler
     * @param max_events Maximum events to process
     * @return Number of events processed
     */
    template<typename F>
    size_t process_manually(F&& handler, size_t max_events = SIZE_MAX) {
        size_t tail = consumer_tail_.load(std::memory_order_relaxed);
        size_t head = head_.load(std::memory_order_acquire);

        if (tail == head) {
            return 0;  // Empty
        }

        size_t available = (head >= tail) ? (head - tail) : (N - tail + head);
        size_t to_process = std::min(available, max_events);
        size_t count = 0;

        for (size_t i = 0; i < to_process; ++i) {
            size_t idx = (tail + i) & MASK;
            bool is_end = (i == to_process - 1);

            if constexpr (std::is_invocable_r_v<bool, F, T&, int64_t, bool>) {
                if (!handler(buffer_[idx], static_cast<int64_t>(idx), is_end)) {
                    last_processed_ = (tail + count) & MASK;
                    ++count;
                    return count;
                }
            } else if constexpr (std::is_invocable_v<F, T&, int64_t, bool>) {
                handler(buffer_[idx], static_cast<int64_t>(idx), is_end);
            } else {
                handler(buffer_[idx]);
            }
            ++count;
        }

        last_processed_ = (tail + count - 1) & MASK;
        return count;
    }

    /**
     * Commit processed events (allows producer to reuse slots)
     */
    void commit_manually() {
        size_t tail = consumer_tail_.load(std::memory_order_relaxed);
        size_t head = head_.load(std::memory_order_acquire);

        if (tail != head) {
            // Advance tail past processed items
            size_t new_tail = (last_processed_ + 1) & MASK;
            consumer_tail_.store(new_tail, std::memory_order_release);
            tail_.store(new_tail, std::memory_order_release);
        }
    }

    /**
     * Simple try_pop for single-item consumption
     */
    bool try_pop(T& item) {
        size_t tail = tail_.load(std::memory_order_relaxed);
        size_t head = head_.load(std::memory_order_acquire);

        if (tail == head) {
            return false;  // Empty
        }

        item = buffer_[tail];
        tail_.store((tail + 1) & MASK, std::memory_order_release);
        consumer_tail_.store((tail + 1) & MASK, std::memory_order_relaxed);
        return true;
    }

    /**
     * Simple try_push for single-item production
     */
    bool try_push(const T& item) {
        int64_t seq = try_claim();
        if (seq < 0) return false;
        buffer_[static_cast<size_t>(seq) & MASK] = item;
        publish(seq);
        return true;
    }

    bool empty() const {
        return head_.load(std::memory_order_acquire) ==
               tail_.load(std::memory_order_acquire);
    }

private:
    alignas(64) std::atomic<size_t> head_{0};
    size_t claimed_head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
    std::atomic<size_t> consumer_tail_{0};
    size_t last_processed_{0};
    alignas(64) std::array<T, N> buffer_;
};

// ============================================================================
// Encrypted Data Chunk (for 3-thread model internal rings)
// ============================================================================

struct EncryptedChunk {
    static constexpr size_t MAX_SIZE = 16640;  // 16KB + TLS overhead

    uint8_t data[MAX_SIZE];
    uint32_t len;
    uint64_t recv_cycle;  // Timestamp for metadata tracking (poll cycle)
    // HW timestamp fields (populated on Linux only)
    uint64_t hw_timestamp_oldest_ns;
    uint64_t hw_timestamp_latest_ns;
    uint32_t hw_timestamp_count;
    // TCP segment delta (from TCP_INFO/TCP_CONNECTION_INFO)
    uint32_t tcp_seg_delta;
    // Connection index (for EnableAB dual connections)
    uint8_t connection_id = 0;
};

// ============================================================================
// BSD Zero-Copy Recv Buffer (for AES-CTR ssl_read_by_chunk in 2-thread mode)
// ============================================================================

/**
 * BSDRecvSlot - One recv() result with per-packet metadata.
 * Analogous to UMEM FrameRef: data stays in-place after recv().
 */
struct BSDRecvSlot {
    uint8_t data[16384];              // recv() fills this (one TCP segment max)
    uint16_t len = 0;                 // Bytes received
    uint16_t offset = 0;             // Current read position within slot
    uint64_t poll_cycle = 0;          // rdtscp at poll wakeup
    uint64_t hw_timestamp_oldest_ns = 0;
    uint64_t hw_timestamp_latest_ns = 0;
    uint32_t hw_timestamp_count = 0;
    uint32_t tcp_seg_delta = 0;
};

/**
 * BSDReadStats - Accumulated per-read statistics across scatter-gather slots.
 * Analogous to ReadStats in ZeroCopyReceiveBuffer.
 */
struct BSDReadStats {
    uint32_t packet_count = 0;
    uint64_t oldest_poll_cycle = 0;
    uint64_t latest_poll_cycle = 0;
    uint64_t oldest_hw_ns = 0;
    uint64_t latest_hw_ns = 0;
    uint32_t total_hw_count = 0;
    uint32_t total_seg_delta = 0;
};

/**
 * BSDZeroCopyRecvBuffer - Ring of recv slots with scatter-gather read.
 *
 * Follows the same zero-copy design as ZeroCopyReceiveBuffer:
 * - Pool of recv slots (data stays in-place)
 * - push via recv_into_next() stores pointer + metadata
 * - read() scatter-gathers across slots, accumulates ReadStats
 * - Slots recycle after full consumption (ring buffer, no compaction)
 */
struct BSDZeroCopyRecvBuffer {
    static constexpr size_t POOL_SIZE = 32;
    static constexpr size_t POOL_MASK = POOL_SIZE - 1;

    BSDRecvSlot slots[POOL_SIZE];
    size_t head_ = 0;      // First unconsumed slot
    size_t tail_ = 0;      // Next slot to write
    size_t count_ = 0;     // Slots with data
    BSDReadStats last_read_stats_{};
    bool stats_recorded_ = false;  // Current head slot stats already recorded

    bool has_space() const { return count_ < POOL_SIZE; }

    /**
     * recv() into next available slot, storing per-packet metadata.
     */
    ssize_t recv_into_next(int fd, uint64_t poll_cycle,
                           uint64_t hw_oldest_ns, uint64_t hw_latest_ns,
                           uint32_t hw_count, uint32_t seg_delta) {
        if (!has_space()) return -1;
        auto& slot = slots[tail_ & POOL_MASK];
        ssize_t n = ::recv(fd, slot.data, sizeof(slot.data), 0);
        if (n > 0) {
            slot.len = static_cast<uint16_t>(n);
            slot.offset = 0;
            slot.poll_cycle = poll_cycle;
            slot.hw_timestamp_oldest_ns = hw_oldest_ns;
            slot.hw_timestamp_latest_ns = hw_latest_ns;
            slot.hw_timestamp_count = hw_count;
            slot.tcp_seg_delta = seg_delta;
            tail_++;
            count_++;
        }
        return n;
    }

    /**
     * Total bytes available across all unconsumed slots.
     */
    size_t available() const {
        size_t total = 0;
        size_t idx = head_;
        for (size_t i = 0; i < count_; i++) {
            total += slots[idx & POOL_MASK].len - slots[idx & POOL_MASK].offset;
            idx++;
        }
        return total;
    }

    /**
     * Scatter-gather read across slots into dest buffer.
     * Tracks BSDReadStats for each slot touched during this read.
     * Uses stats_recorded_ flag to avoid double-counting a slot across reads
     * while ensuring a mid-slot resume after reset_read_stats() still records.
     */
    size_t read(uint8_t* dest, size_t max_len) {
        size_t total_read = 0;

        while (total_read < max_len && count_ > 0) {
            auto& slot = slots[head_ & POOL_MASK];

            // Track stats for each slot touched in this read
            // stats_recorded_ is cleared by reset_read_stats(), so a partially
            // consumed slot gets re-recorded after a reset (matching XDP behavior).
            if (!stats_recorded_) {
                last_read_stats_.packet_count++;
                if (last_read_stats_.oldest_poll_cycle == 0)
                    last_read_stats_.oldest_poll_cycle = slot.poll_cycle;
                last_read_stats_.latest_poll_cycle = slot.poll_cycle;
                if (last_read_stats_.oldest_hw_ns == 0 && slot.hw_timestamp_oldest_ns > 0)
                    last_read_stats_.oldest_hw_ns = slot.hw_timestamp_oldest_ns;
                if (slot.hw_timestamp_latest_ns > 0)
                    last_read_stats_.latest_hw_ns = slot.hw_timestamp_latest_ns;
                last_read_stats_.total_hw_count += slot.hw_timestamp_count;
                last_read_stats_.total_seg_delta += slot.tcp_seg_delta;
                stats_recorded_ = true;
            }

            size_t remaining = slot.len - slot.offset;
            size_t to_read = std::min(remaining, max_len - total_read);
            std::memcpy(dest + total_read, slot.data + slot.offset, to_read);
            slot.offset += static_cast<uint16_t>(to_read);
            total_read += to_read;

            if (slot.offset >= slot.len) {
                head_++;
                count_--;
                stats_recorded_ = false;  // Next slot needs recording
            }
        }
        return total_read;
    }

    void reset_read_stats() { last_read_stats_ = {}; stats_recorded_ = false; }
    const BSDReadStats& get_last_read_stats() const { return last_read_stats_; }
};

// ============================================================================
// ChunkPoolBuffer - EncryptedChunk pool adapter for ssl_read_by_chunk
//   (3-thread mode: wraps the EncryptedChunk pool that ssl_thread_main maintains)
// ============================================================================

struct ChunkPoolBuffer {
    std::array<EncryptedChunk, 128>* pool_ = nullptr;
    size_t head_ = 0;        // First unconsumed chunk in pool
    size_t tail_ = 0;        // One past last valid chunk in pool
    size_t offset_ = 0;      // Read offset within current head chunk
    BSDReadStats last_read_stats_{};
    bool stats_recorded_ = false;  // Current head chunk stats already recorded

    static constexpr size_t POOL_MASK = 127;

    void push(size_t pool_idx) {
        // Called after popping a chunk into pool slot pool_idx.
        // tail_ tracks one past the last valid chunk.
        tail_ = pool_idx + 1;
    }

    size_t available() const {
        size_t total = 0;
        size_t idx = head_;
        size_t off = offset_;
        while (idx < tail_) {
            auto& chunk = (*pool_)[idx & POOL_MASK];
            total += chunk.len - off;
            off = 0;
            idx++;
        }
        return total;
    }

    size_t read(uint8_t* dest, size_t max_len) {
        size_t total_read = 0;

        while (total_read < max_len && head_ < tail_) {
            auto& chunk = (*pool_)[head_ & POOL_MASK];

            // Track stats for each chunk touched in this read.
            // stats_recorded_ cleared by reset_read_stats() so a partially
            // consumed chunk gets re-recorded after reset (matching XDP behavior).
            if (!stats_recorded_) {
                last_read_stats_.packet_count++;
                if (last_read_stats_.oldest_poll_cycle == 0)
                    last_read_stats_.oldest_poll_cycle = chunk.recv_cycle;
                last_read_stats_.latest_poll_cycle = chunk.recv_cycle;
                if (last_read_stats_.oldest_hw_ns == 0 && chunk.hw_timestamp_oldest_ns > 0)
                    last_read_stats_.oldest_hw_ns = chunk.hw_timestamp_oldest_ns;
                if (chunk.hw_timestamp_latest_ns > 0)
                    last_read_stats_.latest_hw_ns = chunk.hw_timestamp_latest_ns;
                last_read_stats_.total_hw_count += chunk.hw_timestamp_count;
                last_read_stats_.total_seg_delta += chunk.tcp_seg_delta;
                stats_recorded_ = true;
            }

            size_t remaining = chunk.len - offset_;
            size_t to_read = std::min(remaining, max_len - total_read);
            std::memcpy(dest + total_read, chunk.data + offset_, to_read);
            offset_ += to_read;
            total_read += to_read;

            if (offset_ >= chunk.len) {
                head_++;
                offset_ = 0;
                stats_recorded_ = false;  // Next chunk needs recording
            }
        }
        return total_read;
    }

    void reset_read_stats() { last_read_stats_ = {}; stats_recorded_ = false; }
    const BSDReadStats& get_last_read_stats() const { return last_read_stats_; }
    size_t chunks_consumed() const { return head_; }
};

// ============================================================================
// ConnPhase / ReconnectCtx (BSD socket reconnect state machine)
// ============================================================================

enum class BSDConnPhase : uint8_t {
    ACTIVE = 0,          // Normal: direct AES-CTR decrypt → msg_metadata
    TCP_CONNECTING,      // connect() in progress (EINPROGRESS)
    TLS_HANDSHAKING,     // SSL_connect() non-blocking steps
    TLS_READY,           // TLS done, reading via SSL for WS handshake
    WAITING_RETRY,       // Error occurred, waiting for backoff before retry
};

struct BSDReconnectCtx {
    BSDConnPhase phase = BSDConnPhase::TCP_CONNECTING;
    uint32_t attempts = 0;
    uint64_t phase_start_cycle = 0;
    uint64_t last_attempt_cycle = 0;

    void reset() {
        phase = BSDConnPhase::ACTIVE;
        attempts = 0;
        phase_start_cycle = 0;
        last_attempt_cycle = 0;
    }
};

// ============================================================================
// NullRingAdapter - Sentinel type for unused IPC rings (InlineWS mode)
// ============================================================================

struct NullRingAdapter {
    // Satisfies ring consumer/producer concepts structurally but is never used.
    // InlineWS mode skips all outbox/pongs/metadata ring access at compile time.
};

// ============================================================================
// BSDSocketTransportProcess - Unified BSD Socket Transport
// ============================================================================

/**
 * BSDSocketTransportProcess - Policy-based BSD socket transport
 *
 * @tparam SSLPolicy SSL policy (NoSSLPolicy, OpenSSLPolicy, LibreSSLPolicy)
 * @tparam IOPolicy I/O policy (BlockingIO<EventPolicy> or AsyncIO)
 * @tparam SSLThreadingPolicy Threading model (InlineSSL or DedicatedSSL)
 * @tparam MsgOutboxCons Consumer for MSG_OUTBOX ring
 * @tparam MsgMetadataProd Producer for MSG_METADATA ring
 * @tparam PongsCons Consumer for PONGS ring
 * @tparam EnableAB Enable dual A/B connections (default: false)
 * @tparam AutoReconnect Enable automatic reconnection (default: false)
 */
template<
    typename SSLPolicy,
    typename IOPolicy,
    typename SSLThreadingPolicy,
    typename MsgOutboxCons,
    typename MsgMetadataProd,
    typename PongsCons,
    bool EnableAB = false,
    bool AutoReconnect = false,
    typename WSProcessor = void
>
class BSDSocketTransportProcess {
    // ========================================================================
    // Policy Restrictions (compile-time validation)
    // ========================================================================

    // DedicatedSSL requires userspace SSL
    static_assert(
        !(std::is_same_v<SSLPolicy, websocket::ssl::NoSSLPolicy> && SSLThreadingPolicy::has_ssl_thread),
        "DedicatedSSL is invalid with NoSSLPolicy (no encryption to offload)"
    );

    // AsyncIO cannot work with userspace SSL (only NoSSL or kTLS)
    static_assert(
        !(IOPolicy::is_async && detail::is_userspace_ssl_v<SSLPolicy>),
        "AsyncIO only supports NoSSLPolicy or kTLS (no userspace SSL)"
    );

    // AsyncIO cannot have dedicated SSL thread
    static_assert(
        !(IOPolicy::is_async && SSLThreadingPolicy::has_ssl_thread),
        "AsyncIO cannot use DedicatedSSL"
    );

    // InlineWS: transport embeds WS processing directly (no IPC to WS process)
    static constexpr bool InlineWS = !std::is_same_v<WSProcessor, void>;

    // InlineWS requires SingleThreadSSL (ssl_.write from same thread as ssl_.read)
    static_assert(
        !InlineWS || SSLThreadingPolicy::is_single_thread,
        "InlineWS requires SingleThreadSSL (single-thread RX+TX)"
    );

    // InlineWS requires AutoReconnect (event-driven handshake, no blocking metadata poll)
    static_assert(
        !InlineWS || AutoReconnect,
        "InlineWS requires AutoReconnect=true"
    );

    // Number of connections
    static constexpr size_t NUM_CONN = EnableAB ? 2 : 1;

    // Ring buffer configuration
    static constexpr size_t RING_SIZE = 64;  // Must be power of 2

    // Reconnect backoff constants
    static constexpr uint32_t RECONNECT_BACKOFF_BASE_MS = 1000;
    static constexpr uint32_t RECONNECT_BACKOFF_MAX_MS  = 30000;

public:
    BSDSocketTransportProcess() {
        for (size_t i = 0; i < NUM_CONN; i++) {
            sockfd_[i] = -1;
            msg_inbox_[i] = nullptr;
            msg_metadata_prod_[i] = nullptr;
            tls_keys_valid_[i] = false;
            tls_seq_num_[i] = 0;
            ssl_read_count_[i] = 0;
            last_op_cycle_[i] = 0;
            prev_tcp_segs_in_[i] = 0;
        }
    }
    ~BSDSocketTransportProcess() {
        shutdown();
    }

    // Non-copyable
    BSDSocketTransportProcess(const BSDSocketTransportProcess&) = delete;
    BSDSocketTransportProcess& operator=(const BSDSocketTransportProcess&) = delete;

    /**
     * Initialize and connect to server
     *
     * When AutoReconnect=false: blocking TCP connect + SSL handshake (original path).
     * When AutoReconnect=true: non-blocking connect, state machine drives handshake.
     *
     * Optional _b params for EnableAB dual connections.
     */
    bool init(const char* host, uint16_t port,
              MsgOutboxCons* msg_outbox_cons,
              MsgMetadataProd* msg_metadata_prod,
              PongsCons* pongs_cons,
              MsgInbox* msg_inbox,
              ConnStateShm* conn_state,
              MsgInbox* msg_inbox_b = nullptr,
              MsgMetadataProd* msg_metadata_prod_b = nullptr) {

        msg_outbox_cons_ = msg_outbox_cons;
        msg_metadata_prod_[0] = msg_metadata_prod;
        pongs_cons_ = pongs_cons;
        msg_inbox_[0] = msg_inbox;
        conn_state_ = conn_state;
        host_ = host;
        port_ = port;

        if constexpr (EnableAB) {
            msg_inbox_[1] = msg_inbox_b;
            msg_metadata_prod_[1] = msg_metadata_prod_b;
        }

        if constexpr (AutoReconnect) {
            // Non-blocking startup: initiate TCP connect for all connections
            // State machine in run() handles TCP→TLS→TLS_READY→ACTIVE
            for (size_t ci = 0; ci < NUM_CONN; ci++) {
                int rc = create_and_connect_nonblocking(ci);
                reconn_[ci].phase = (rc == 0) ? BSDConnPhase::TCP_CONNECTING : BSDConnPhase::WAITING_RETRY;
                reconn_[ci].phase_start_cycle = rdtsc();
            }

            // Signal TCP ready (non-blocking connect initiated)
            if (conn_state_) {
                conn_state_->set_handshake_tcp_ready();
            }

            // Print threading model info
            if constexpr (IOPolicy::is_async) {
                printf("[BSD-Transport] Initialized AutoReconnect (1-thread io_uring mode)\n");
            } else if constexpr (SSLThreadingPolicy::has_ssl_thread) {
                printf("[BSD-Transport] Initialized AutoReconnect (3-thread mode: RX + SSL + TX)\n");
            } else if constexpr (SSLThreadingPolicy::is_single_thread) {
                printf("[BSD-Transport] Initialized AutoReconnect (1-thread mode: single-thread RX+TX)\n");
            } else {
                printf("[BSD-Transport] Initialized AutoReconnect (2-thread mode: RX + TX)\n");
            }
            return true;
        }

        // !AutoReconnect: blocking TCP connect + SSL handshake for each connection
        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            // Create socket
            sockfd_[ci] = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd_[ci] < 0) {
                printf("[BSD-Transport] socket() failed for conn %zu: %s\n", ci, strerror(errno));
                return false;
            }

            // Set TCP_NODELAY for low latency
            int flag = 1;
            setsockopt(sockfd_[ci], IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

            // Blocking TCP connect — prefer pool IP if available
            int ret;
            if (conn_state_ && conn_state_->conn_target_ip[ci] != 0) {
                struct sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_port = htons(port);
                addr.sin_addr.s_addr = conn_state_->conn_target_ip[ci];
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
                printf("[BSD-Transport] Connecting conn %zu to %s:%u (pool IP)...\n", ci, ip_str, port);
                ret = connect(sockfd_[ci], (struct sockaddr*)&addr, sizeof(addr));
            } else {
                // Fallback: DNS resolve
                struct addrinfo hints = {};
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;

                struct addrinfo* result = nullptr;
                char port_str[16];
                snprintf(port_str, sizeof(port_str), "%u", port);

                int gai_ret = getaddrinfo(host, port_str, &hints, &result);
                if (gai_ret != 0) {
                    printf("[BSD-Transport] getaddrinfo(%s) failed: %s\n", host, gai_strerror(gai_ret));
                    close(sockfd_[ci]);
                    sockfd_[ci] = -1;
                    return false;
                }

                printf("[BSD-Transport] Connecting conn %zu to %s:%u...\n", ci, host, port);
                ret = connect(sockfd_[ci], result->ai_addr, result->ai_addrlen);
                freeaddrinfo(result);
            }

            if (ret < 0) {
                printf("[BSD-Transport] connect() failed for conn %zu: %s\n", ci, strerror(errno));
                close(sockfd_[ci]);
                sockfd_[ci] = -1;
                return false;
            }

            printf("[BSD-Transport] TCP connected (conn %zu)\n", ci);

            // Signal TCP ready on first connection
            if (ci == 0 && conn_state_) {
                conn_state_->set_handshake_tcp_ready();
            }

            // Initialize and perform SSL handshake (blocking)
            ssl_[ci].init();
            ssl_[ci].set_hostname(host);
            try {
                ssl_[ci].handshake(sockfd_[ci]);
            } catch (const std::exception& e) {
                fprintf(stderr, "[BSD-Transport] SSL handshake failed (conn %zu): %s\n", ci, e.what());
                close(sockfd_[ci]);
                sockfd_[ci] = -1;
                return false;
            }

            if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
                printf("[BSD-Transport] SSL handshake complete (conn %zu)\n", ci);
            } else {
                printf("[BSD-Transport] NoSSL mode (conn %zu)\n", ci);
            }

            // Extract TLS keys and configure BIO
            if constexpr (!IOPolicy::is_async) {
                setup_post_handshake(ci);
            }

            // Set socket to non-blocking for event-driven I/O
            int flags_val = fcntl(sockfd_[ci], F_GETFL, 0);
            fcntl(sockfd_[ci], F_SETFL, flags_val | O_NONBLOCK);

#ifdef __linux__
            enable_hw_timestamping(sockfd_[ci]);
#endif
        }

        // Signal TLS ready
        if (conn_state_) {
            conn_state_->set_handshake_tls_ready();
        }

        // Initialize I/O mechanism (for AsyncIO, init io_uring)
        if constexpr (IOPolicy::is_async) {
#ifdef __linux__
            struct io_uring_params params = {};
            int ret = io_uring_queue_init_params(QUEUE_DEPTH, &ring_, &params);
            if (ret < 0) {
                printf("[BSD-Transport] io_uring_queue_init failed: %s\n", strerror(-ret));
                return false;
            }
            ring_initialized_ = true;
            printf("[BSD-Transport] io_uring initialized (queue depth: %u)\n", QUEUE_DEPTH);
#endif
        }

        // Print threading model info
        if constexpr (IOPolicy::is_async) {
            printf("[BSD-Transport] Initialized (1-thread io_uring mode)\n");
        } else if constexpr (SSLThreadingPolicy::has_ssl_thread) {
            printf("[BSD-Transport] Initialized (3-thread mode: RX + SSL + TX)\n");
        } else if constexpr (SSLThreadingPolicy::is_single_thread) {
            printf("[BSD-Transport] Initialized (1-thread mode: single-thread RX+TX)\n");
        } else {
            printf("[BSD-Transport] Initialized (2-thread mode: RX + TX)\n");
        }

        return true;
    }

    /**
     * Run the transport
     *
     * Dispatches to appropriate run method based on policies.
     * Blocks until shutdown() is called or connection closes.
     */
    void run() {
        running_.store(true, std::memory_order_release);

        if constexpr (IOPolicy::is_async) {
            // Single-threaded io_uring event loop
            run_async();
        } else if constexpr (SSLThreadingPolicy::has_ssl_thread) {
            // 3-thread: RX + SSL + TX
            run_blocking_3thread();
        } else if constexpr (SSLThreadingPolicy::is_single_thread) {
            // 1-thread: single-thread RX+TX loop
            run_blocking_1thread();
        } else {
            // 2-thread: RX + TX
            run_blocking_2thread();
        }
    }

    /**
     * Signal shutdown
     */
    void shutdown() {
        running_.store(false, std::memory_order_release);

        // Close all sockets to unblock recv/send
        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            if (sockfd_[ci] >= 0) {
                ::shutdown(sockfd_[ci], SHUT_RDWR);
                close(sockfd_[ci]);
                sockfd_[ci] = -1;
            }
        }

        // Wait for threads
        if (rx_thread_.joinable()) {
            rx_thread_.join();
        }
        if constexpr (SSLThreadingPolicy::has_ssl_thread && !IOPolicy::is_async) {
            if (ssl_thread_.joinable()) {
                ssl_thread_.join();
            }
        }
        if (tx_thread_.joinable()) {
            tx_thread_.join();
        }

#ifdef __linux__
        if constexpr (IOPolicy::is_async) {
            if (ring_initialized_) {
                io_uring_queue_exit(&ring_);
                ring_initialized_ = false;
            }
        }
#endif

        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            ssl_[ci].shutdown();
        }
    }

    /**
     * Check if transport is running
     */
    bool is_running() const {
        return running_.load(std::memory_order_acquire);
    }

    /**
     * Get socket file descriptor for connection ci
     */
    int get_fd(size_t ci = 0) const {
        return sockfd_[ci];
    }

private:
    // ========================================================================
    // Shared Helpers (used by both 2-thread and 3-thread RX paths)
    // ========================================================================

    /**
     * RxPollResult - Result of rx_poll_wait() event loop preamble
     */
    struct RxPollResult {
        uint64_t poll_cycle = 0;
        uint64_t hw_oldest_ns = 0;
        uint64_t hw_latest_ns = 0;
        uint32_t hw_count = 0;
        uint64_t segs_before = 0;
        bool ready = false;
        bool shutdown = false;
    };

    /**
     * rx_poll_wait() - Shared poll/event-loop preamble for RX threads
     *
     * @param event_policy Event policy instance
     * @param sockfd Socket to query for timestamps/segments (-1 to skip)
     */
    template<typename EventPolicyT>
    RxPollResult rx_poll_wait(EventPolicyT& event_policy, int sockfd = -1) {
        RxPollResult result{};

        if (conn_state_ && !conn_state_->is_running(PROC_TRANSPORT)) {
            printf("[RX] ConnStateShm signals shutdown\n");
            running_.store(false, std::memory_order_release);
            result.shutdown = true;
            return result;
        }

        int ready = event_policy.wait_with_timeout();

        if (ready < 0) {
            if (errno == EINTR) return result;
            printf("[RX] event wait error: %s\n", strerror(errno));
            running_.store(false, std::memory_order_release);
            result.shutdown = true;
            return result;
        }

        if (ready == 0) return result;

        if (event_policy.has_error()) {
            printf("[RX] Socket error detected\n");
            running_.store(false, std::memory_order_release);
            result.shutdown = true;
            return result;
        }

        if (!event_policy.is_readable()) return result;

        result.ready = true;
        result.poll_cycle = rdtscp();

#ifdef __linux__
        if (sockfd >= 0) {
            timing_record_t hw_timing = {};
            drain_hw_timestamps(sockfd, &hw_timing);
            result.hw_oldest_ns = hw_timing.hw_timestamp_oldest_ns;
            result.hw_latest_ns = hw_timing.hw_timestamp_latest_ns;
            result.hw_count = hw_timing.hw_timestamp_count;
        }
#endif

        if (sockfd >= 0) result.segs_before = query_tcp_segs_in(sockfd);
        return result;
    }

    /**
     * publish_rx_metadata() - Shared metadata publishing for all RX paths
     *
     * @param ci Connection index (for per-connection metadata producer)
     */
    void publish_rx_metadata(size_t ci, const BSDReadStats& stats,
                             uint32_t write_pos, uint32_t decrypted_len,
                             uint64_t ssl_start, uint64_t ssl_end,
                             bool tls_record_end) {
        MsgMetadata meta{};
        meta.clear();
        meta.first_nic_frame_poll_cycle = stats.oldest_poll_cycle;
        meta.latest_nic_frame_poll_cycle = stats.latest_poll_cycle;
        meta.ssl_read_start_cycle = ssl_start;
        meta.ssl_read_end_cycle = ssl_end;
        meta.ssl_last_op_cycle = last_op_cycle_[ci];
        meta.ssl_read_id = ssl_read_count_[ci];
        meta.msg_inbox_offset = write_pos;
        meta.decrypted_len = decrypted_len;
        meta.tls_record_end = tls_record_end;
        meta.nic_packet_ct = (stats.total_hw_count > 0)
            ? stats.total_hw_count
            : (stats.total_seg_delta > 0)
                ? stats.total_seg_delta
                : stats.packet_count;
#ifdef __linux__
        if (stats.oldest_hw_ns > 0) {
            meta.first_nic_timestamp_ns = stats.oldest_hw_ns;
            meta.latest_nic_timestamp_ns = stats.latest_hw_ns;
        }
#endif
        if constexpr (InlineWS) {
            inline_ws_.ws_core.feed(static_cast<uint8_t>(ci), meta);
        } else {
            int64_t seq = msg_metadata_prod_[ci]->try_claim();
            if (seq >= 0) {
                (*msg_metadata_prod_[ci])[seq] = meta;
                msg_metadata_prod_[ci]->publish(seq);
            }
        }
        last_op_cycle_[ci] = rdtscp();
        ssl_read_count_[ci]++;
    }

    /**
     * Publish a control event (TCP_DISCONNECTED, TLS_CONNECTED) on the metadata ring.
     */
    void publish_control_event(size_t ci, MetaEventType event_type) {
        if constexpr (InlineWS) {
            if (event_type == MetaEventType::TLS_CONNECTED) {
                inline_ws_.ws_core.on_tls_connected(static_cast<uint8_t>(ci));
            } else if (event_type == MetaEventType::TCP_DISCONNECTED) {
                inline_ws_.ws_core.on_tcp_disconnected(static_cast<uint8_t>(ci));
            }
        } else {
            auto* prod = msg_metadata_prod_[ci];
            int64_t seq = prod->try_claim();
            if (seq < 0) {
                fprintf(stderr, "[BSD-Transport] WARNING: MSG_METADATA full for control event\n");
                return;
            }
            auto& meta = (*prod)[seq];
            meta.clear();
            meta.event_type = static_cast<uint8_t>(event_type);
            prod->publish(seq);
        }
    }

    // ========================================================================
    // Post-handshake setup: extract TLS keys + configure BIO for a connection
    // ========================================================================
    void setup_post_handshake(size_t ci) {
        if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
            // Extract AES-GCM keys for direct AES-CTR decryption (required)
            if (ssl_[ci].extract_record_keys(tls_keys_[ci])) {
                websocket::crypto::expand_keys(tls_keys_[ci]);
                tls_parser_[ci] = websocket::crypto::TLSRecordParser{};
                // server_record_count_ is reset to 0 at handshake completion, then
                // incremented for each post-handshake record consumed by SSL_read
                // during TLS_READY. For TLS 1.3, this is the correct starting
                // sequence number (nonce = IV XOR seq_num).
                tls_seq_num_[ci] = ssl_[ci].get_server_record_count();
                tls_keys_valid_[ci] = true;
                fprintf(stderr, "[BSD-Transport] Direct AES-CTR decryption enabled (conn %zu, TLS %s, %zu-bit key, seq=%lu)\n",
                       ci, tls_keys_[ci].is_tls13 ? "1.3" : "1.2", tls_keys_[ci].key_len * 8,
                       (unsigned long)tls_seq_num_[ci]);
            } else {
                // FATAL: AES-GCM cipher required but key extraction failed
                fprintf(stderr, "[BSD-Transport] FATAL: extract_record_keys failed (conn %zu)"
                        " — AES-GCM cipher required. Triggering reconnect.\n", ci);
                if constexpr (AutoReconnect) {
                    start_reconnect(ci);
                }
                return;  // Do not proceed to ACTIVE
            }

            if constexpr (SSLThreadingPolicy::has_ssl_thread) {
                // 3-thread: always need zero-copy BIO
                ssl_[ci].switch_to_zero_copy_bio();
                fprintf(stderr, "[BSD-Transport] Switched to zero-copy BIO for 3-thread mode (conn %zu)\n", ci);
            }
            // 2-thread/1-thread: no BIO switch needed (viewring already set from TLS_READY,
            // and AES-CTR path doesn't use SSL_read at all)
        }
    }

    // ========================================================================
    // Reconnect State Machine Methods (AutoReconnect only)
    // ========================================================================

    /**
     * Connect to a specific IPv4 address (network byte order) without DNS.
     * Creates a new non-blocking socket and initiates connect().
     * @return 0 on success (EINPROGRESS or immediate), -1 on failure
     */
    int connect_to_ip_nonblocking(size_t ci, uint32_t ip_net, uint16_t port) {
        if (sockfd_[ci] >= 0) { close(sockfd_[ci]); sockfd_[ci] = -1; }
        sockfd_[ci] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_[ci] < 0) {
            fprintf(stderr, "[RECONNECT] socket() failed for conn %zu: %s\n", ci, strerror(errno));
            return -1;
        }
        int flag = 1;
        setsockopt(sockfd_[ci], IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        int flags_val = fcntl(sockfd_[ci], F_GETFL, 0);
        fcntl(sockfd_[ci], F_SETFL, flags_val | O_NONBLOCK);
        struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = ip_net;
        int ret = connect(sockfd_[ci], (struct sockaddr*)&addr, sizeof(addr));
        if (ret == 0 || errno == EINPROGRESS) return 0;
        fprintf(stderr, "[RECONNECT] connect_to_ip() failed for conn %zu: %s\n", ci, strerror(errno));
        close(sockfd_[ci]); sockfd_[ci] = -1;
        return -1;
    }

    /**
     * Create a socket and initiate non-blocking connect.
     * Prefers pool IP (conn_state_->conn_target_ip[ci]) if available, falls back to DNS.
     * @return 0 on success (EINPROGRESS), -1 on failure
     */
    int create_and_connect_nonblocking(size_t ci) {
        // Prefer pool IP if available (set by BSDWebSocketPipeline from IP probe)
        if (conn_state_ && conn_state_->conn_target_ip[ci] != 0) {
            return connect_to_ip_nonblocking(ci, conn_state_->conn_target_ip[ci], port_);
        }

        // Fallback: DNS resolve (original path, for non-pipeline usage)
        if (sockfd_[ci] >= 0) {
            close(sockfd_[ci]);
            sockfd_[ci] = -1;
        }

        sockfd_[ci] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_[ci] < 0) {
            fprintf(stderr, "[RECONNECT] socket() failed for conn %zu: %s\n", ci, strerror(errno));
            return -1;
        }

        // TCP_NODELAY
        int flag = 1;
        setsockopt(sockfd_[ci], IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        // O_NONBLOCK
        int flags_val = fcntl(sockfd_[ci], F_GETFL, 0);
        fcntl(sockfd_[ci], F_SETFL, flags_val | O_NONBLOCK);

        // Resolve and connect
        struct addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo* result = nullptr;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%u", port_);

        int gai_ret = getaddrinfo(host_.c_str(), port_str, &hints, &result);
        if (gai_ret != 0) {
            fprintf(stderr, "[RECONNECT] getaddrinfo(%s) failed: %s\n", host_.c_str(), gai_strerror(gai_ret));
            close(sockfd_[ci]);
            sockfd_[ci] = -1;
            return -1;
        }

        int ret = connect(sockfd_[ci], result->ai_addr, result->ai_addrlen);
        freeaddrinfo(result);

        if (ret == 0) {
            // Immediate connection (unlikely but possible on localhost)
            return 0;
        }
        if (errno == EINPROGRESS) {
            return 0;  // Normal non-blocking connect
        }

        fprintf(stderr, "[RECONNECT] connect() failed for conn %zu: %s\n", ci, strerror(errno));
        close(sockfd_[ci]);
        sockfd_[ci] = -1;
        return -1;
    }

    /**
     * Start reconnect for connection ci: publish disconnect event, shutdown SSL,
     * close socket, initiate new non-blocking connect.
     */
    void start_reconnect(size_t ci) {
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [RECONNECT] Starting reconnect for conn %zu (attempt %u)\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci, reconn_[ci].attempts + 1);

        // Set phase FIRST so SSL thread stops accessing ssl_[ci]
        reconn_[ci].phase = BSDConnPhase::TCP_CONNECTING;
        std::atomic_thread_fence(std::memory_order_release);

        publish_control_event(ci, MetaEventType::TCP_DISCONNECTED);

        // Defer ssl shutdown to reconnect_bsd() which frees the old SSL
        // object when TCP connect completes. In 2-thread mode the TX thread
        // may be mid-ssl_[ci].write(); in 3-thread mode the SSL thread may
        // be mid-operation. Both are safe because reconnect_bsd() runs after
        // phase transitions away from ACTIVE (no concurrent SSL access).

        // Pick a different IP from the startup pool (same logic as XDP transport)
        if (conn_state_ && conn_state_->exchange_ip_count > 1) {
            uint32_t current_ip = conn_state_->conn_target_ip[ci];
            uint32_t other_ip = 0;
            if constexpr (EnableAB) {
                other_ip = conn_state_->conn_target_ip[1 - ci];
            }
            uint32_t new_ip = current_ip;
            uint8_t count = conn_state_->exchange_ip_count;
            for (uint8_t i = 0; i < count; i++) {
                uint8_t idx = (reconn_[ci].attempts + i) % count;
                uint32_t candidate = conn_state_->exchange_ips[idx];
                if (candidate != current_ip && candidate != other_ip) {
                    new_ip = candidate;
                    break;
                }
            }
            if (new_ip != current_ip) {
                conn_state_->conn_target_ip[ci] = new_ip;
                char ip_str[INET_ADDRSTRLEN];
                struct in_addr tmp; tmp.s_addr = new_ip;
                inet_ntop(AF_INET, &tmp, ip_str, sizeof(ip_str));
                fprintf(stderr, "[%ld.%06ld] [RECONNECT] Switched to pool IP: conn %zu -> %s\n",
                        _ts.tv_sec, _ts.tv_nsec / 1000, ci, ip_str);
            }
        }

        int rc = create_and_connect_nonblocking(ci);
        reconn_[ci].phase = (rc == 0) ? BSDConnPhase::TCP_CONNECTING : BSDConnPhase::WAITING_RETRY;
        reconn_[ci].phase_start_cycle = rdtsc();
        reconn_[ci].attempts++;
        reconn_[ci].last_attempt_cycle = rdtsc();
    }

    /**
     * Poll for TCP connect completion on connection ci.
     */
    void step_tcp_connect(size_t ci) {
        struct pollfd pfd = { sockfd_[ci], POLLOUT, 0 };
        int ret = poll(&pfd, 1, 0);

        if (ret > 0 && (pfd.revents & POLLOUT)) {
            // Check if connect succeeded
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(sockfd_[ci], SOL_SOCKET, SO_ERROR, &so_error, &len);

            if (so_error != 0) {
                struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
                fprintf(stderr, "[%ld.%06ld] [RECONNECT] TCP connect error for conn %zu: %s\n",
                        _ts.tv_sec, _ts.tv_nsec / 1000, ci, strerror(so_error));
                if (should_backoff(ci)) return;
                start_reconnect_from_tcp(ci);
                return;
            }

            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TCP established for conn %zu\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);

#ifdef __linux__
            enable_hw_timestamping(sockfd_[ci]);
#endif

            // Prepare TLS handshake
            ssl_[ci].set_hostname(host_.c_str());
            if (ssl_[ci].reconnect_bsd(sockfd_[ci]) != 0) {
                fprintf(stderr, "[RECONNECT] SSL reconnect_bsd failed for conn %zu, restarting\n", ci);
                if (should_backoff(ci)) return;
                start_reconnect_from_tcp(ci);
                return;
            }
            reconn_[ci].phase = BSDConnPhase::TLS_HANDSHAKING;
            reconn_[ci].phase_start_cycle = rdtsc();
            return;
        }

        // Timeout check (5s)
        uint64_t elapsed = rdtsc() - reconn_[ci].phase_start_cycle;
        uint64_t tsc_freq = conn_state_ ? conn_state_->tsc_freq_hz : 2400000000ULL;
        uint64_t timeout_cycles = 5ULL * tsc_freq;
        if (elapsed > timeout_cycles) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TCP connect timeout for conn %zu, restarting\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
            if (should_backoff(ci)) return;
            start_reconnect_from_tcp(ci);
        }
    }

    /**
     * Step TLS handshake for connection ci.
     */
    void step_tls_handshake(size_t ci) {
        using HR = typename SSLPolicy::HandshakeResult;
        auto result = ssl_[ci].step_bsd_handshake();

        if (result == HR::SUCCESS) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TLS handshake complete for conn %zu\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);

            publish_control_event(ci, MetaEventType::TLS_CONNECTED);
            reconn_[ci].phase = BSDConnPhase::TLS_READY;
            reconn_[ci].phase_start_cycle = rdtsc();

            // Switch BIO for TLS_READY phase:
            // 3-thread: zero-copy BIO (SSL thread handles both RX and TX)
            // 2-thread: viewring read BIO (RX thread does recv→append→SSL_read,
            //           TX thread does SSL_write through fd-based write BIO)
            if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
                if constexpr (SSLThreadingPolicy::has_ssl_thread) {
                    ssl_[ci].switch_to_zero_copy_bio();
                } else {
                    ssl_[ci].switch_to_viewring_read_bio_for_bsdsocket(sockfd_[ci]);
                }
            }

            // Signal TLS ready on first connection
            if (!tls_ready_signaled_) {
                if (conn_state_) conn_state_->set_handshake_tls_ready();
                tls_ready_signaled_ = true;
            }
            return;
        }

        if (result == HR::ERROR) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TLS handshake error for conn %zu, restarting\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
            if (should_backoff(ci)) return;
            start_reconnect_from_tcp(ci);
            return;
        }

        // IN_PROGRESS: timeout check (5s)
        uint64_t elapsed = rdtsc() - reconn_[ci].phase_start_cycle;
        uint64_t tsc_freq = conn_state_ ? conn_state_->tsc_freq_hz : 2400000000ULL;
        uint64_t timeout_cycles = 5ULL * tsc_freq;
        if (elapsed > timeout_cycles) {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            fprintf(stderr, "[%ld.%06ld] [RECONNECT] TLS handshake timeout for conn %zu, restarting\n",
                    _ts.tv_sec, _ts.tv_nsec / 1000, ci);
            if (should_backoff(ci)) return;
            start_reconnect_from_tcp(ci);
        }
    }

    /**
     * Switch connection ci from TLS_READY to ACTIVE (direct AES-CTR decrypt).
     */
    void switch_to_direct_decrypt(size_t ci) {
        setup_post_handshake(ci);
        reconn_[ci].reset();  // phase → ACTIVE
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        fprintf(stderr, "[%ld.%06ld] [RECONNECT] Switched to direct decrypt for conn %zu\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, ci);
    }

    /**
     * Check if backoff timer has elapsed.
     * @return true if still in backoff (should wait), false if backoff complete
     */
    bool should_backoff(size_t ci) {
        uint64_t tsc_freq = conn_state_ ? conn_state_->tsc_freq_hz : 2400000000ULL;
        uint32_t backoff_ms = std::min(RECONNECT_BACKOFF_BASE_MS * (1u << std::min(reconn_[ci].attempts, 5u)),
                                       RECONNECT_BACKOFF_MAX_MS);
        uint64_t backoff_cycles = static_cast<uint64_t>(backoff_ms) * tsc_freq / 1000;
        uint64_t elapsed = rdtsc() - reconn_[ci].last_attempt_cycle;
        if (elapsed < backoff_cycles) {
            reconn_[ci].phase = BSDConnPhase::WAITING_RETRY;
            return true;
        }
        return false;
    }

    /**
     * Restart reconnect from TCP level (shutdown SSL, new socket).
     */
    void start_reconnect_from_tcp(size_t ci) {
        // ssl shutdown deferred to reconnect_bsd() — see start_reconnect() comment.
        int rc = create_and_connect_nonblocking(ci);
        reconn_[ci].phase = (rc == 0) ? BSDConnPhase::TCP_CONNECTING : BSDConnPhase::WAITING_RETRY;
        reconn_[ci].phase_start_cycle = rdtsc();
        reconn_[ci].last_attempt_cycle = rdtsc();
    }

    /**
     * Shared SSL_read → publish loop for TLS_READY phase.
     * Caller must have already fed encrypted data into the view ring
     * via append_encrypted_view(). Loops ssl_[ci].read() until WANT_READ
     * to consume all complete TLS records, then clears the view ring.
     * Used by both 2-thread and 3-thread models.
     */
    void ssl_read_and_publish(size_t ci) {
        uint8_t decrypt_buf[16384];
        uint64_t ssl_start = rdtscp();
        ssize_t n;
        while ((n = ssl_[ci].read(decrypt_buf, sizeof(decrypt_buf))) > 0) {
            uint64_t ssl_end = rdtscp();
            uint32_t write_pos = msg_inbox_[ci]->current_write_pos();
            msg_inbox_[ci]->write_data(decrypt_buf, static_cast<uint32_t>(n));

            BSDReadStats stats{};
            stats.oldest_poll_cycle = ssl_start;
            stats.latest_poll_cycle = ssl_start;
            publish_rx_metadata(ci, stats, write_pos, static_cast<uint32_t>(n),
                                ssl_start, ssl_end, ssl_[ci].pending() == 0);
            ssl_start = rdtscp();
        }
        ssl_[ci].clear_encrypted_view();
    }

    /**
     * Process TLS_READY reads: recv → view ring → ssl_read_and_publish.
     * Used by 2-thread and 1-thread models.
     */
    void process_tls_ready_read(size_t ci) {
        uint8_t raw_buf[16384];
        ssize_t raw_n = ::recv(sockfd_[ci], raw_buf, sizeof(raw_buf), 0);
        if (raw_n > 0) {
            ssl_[ci].append_encrypted_view(raw_buf, static_cast<size_t>(raw_n));
            ssl_read_and_publish(ci);
        } else if (raw_n == 0) {
            // Peer closed during TLS_READY
            if constexpr (AutoReconnect) {
                start_reconnect(ci);
            } else {
                running_.store(false, std::memory_order_release);
            }
        }
    }

    // ========================================================================
    // Shared helpers for both thread models
    // ========================================================================

    /**
     * Re-initialize event policy for a connection's socket (after reconnect/init).
     * Templated on EventPolicyT to work with the stack-local arrays in both threads.
     */
    template<typename EventPolicyT>
    void reinit_event_policy(size_t ci, EventPolicyT& ep) {
        if (sockfd_[ci] >= 0) {
            ep.init();
            ep.add_read(sockfd_[ci]);
            ep.set_wait_timeout(1);
        }
    }

    /**
     * Dispatch reconnect state machine phases shared by both thread models.
     * Returns:
     *   SKIP       — handled internally (TCP_CONNECTING, TLS_HANDSHAKING, WAITING_RETRY)
     *   TLS_READY  — caller should handle TLS_READY (differs per thread model)
     *   ACTIVE     — caller should proceed to normal ACTIVE path
     */
    enum class ReconnDispatch : uint8_t { SKIP, TLS_READY, ACTIVE };

    template<typename EventPolicyT>
    ReconnDispatch dispatch_reconnect_phase(size_t ci, EventPolicyT& ep) {
        // Check WS-initiated reconnect request — always honor,
        // even if already in a reconnect phase (watchdog override)
        if (conn_state_->get_reconnect_request(ci)) {
            conn_state_->clear_reconnect_request(ci);
            start_reconnect(ci);
            reinit_event_policy(ci, ep);
        }

        switch (reconn_[ci].phase) {
        case BSDConnPhase::TCP_CONNECTING:
            step_tcp_connect(ci);
            if (reconn_[ci].phase == BSDConnPhase::TLS_HANDSHAKING) {
                reinit_event_policy(ci, ep);
            }
            return ReconnDispatch::SKIP;
        case BSDConnPhase::TLS_HANDSHAKING:
            step_tls_handshake(ci);
            return ReconnDispatch::SKIP;
        case BSDConnPhase::TLS_READY:
            return ReconnDispatch::TLS_READY;
        case BSDConnPhase::WAITING_RETRY:
            if (!should_backoff(ci)) {
                start_reconnect_from_tcp(ci);
                reinit_event_policy(ci, ep);
            }
            return ReconnDispatch::SKIP;
        case BSDConnPhase::ACTIVE:
            return ReconnDispatch::ACTIVE;
        }
        return ReconnDispatch::SKIP;  // unreachable
    }

    /**
     * AES-CTR decrypt loop: ssl_read_by_chunk → advance_write → publish_rx_metadata.
     * Shared by both 2-thread (BSDZeroCopyRecvBuffer) and 3-thread (ChunkPoolBuffer).
     * @return true if any data was decrypted
     */
    template<typename BufferT>
    bool aes_ctr_decrypt_loop(size_t ci, BufferT& buf) {
        bool did_work = false;
        while (true) {
            uint32_t write_pos = msg_inbox_[ci]->current_write_pos();
            uint32_t linear_space = msg_inbox_[ci]->linear_space_to_wrap();
            if (linear_space > SSL_DECRYPT_CHUNK_SIZE) linear_space = SSL_DECRYPT_CHUNK_SIZE;
            if (linear_space < 16) break;

            buf.reset_read_stats();
            uint64_t ssl_start = rdtscp();

            int decrypted = ssl_read_by_chunk(ci, buf,
                msg_inbox_[ci]->write_ptr(), linear_space,
                [](const uint8_t*, size_t) {});
            if (decrypted <= 0) break;

            uint64_t ssl_end = rdtscp();
            bool tls_boundary = (tls_parser_[ci].state == websocket::crypto::TLSRecordState::NEED_HEADER);

            msg_inbox_[ci]->advance_write(static_cast<uint32_t>(decrypted));

            publish_rx_metadata(ci, buf.get_last_read_stats(),
                                write_pos, static_cast<uint32_t>(decrypted),
                                ssl_start, ssl_end, tls_boundary);
            did_work = true;
        }
        return did_work;
    }

    // ========================================================================
    // BlockingIO - 2 Thread Model (InlineSSL)
    // ========================================================================

    void run_blocking_2thread() {
        rx_thread_ = std::thread([this]() { rx_thread_inline_ssl(); });
        tx_thread_ = std::thread([this]() { tx_thread_inline_ssl(); });

        if (rx_thread_.joinable()) rx_thread_.join();
        if (tx_thread_.joinable()) tx_thread_.join();

        printf("[BSD-Transport] 2-thread mode stopped\n");
    }

    // -----------------------------------------------------------------------
    // ssl_read_by_chunk(): TLS record parser + AES-CTR decryptor
    //
    // Same state machine as PacketTransport::ssl_read_by_chunk (transport.hpp)
    // but reads from BSDZeroCopyRecvBuffer instead of ZeroCopyReceiveBuffer.
    // Decrypts partial TLS records (16-byte aligned) as they arrive.
    // -----------------------------------------------------------------------
    template<typename BufferT, typename ChunkCallback>
    int ssl_read_by_chunk(size_t ci, BufferT& buf, uint8_t* dest, size_t chunk_size, ChunkCallback&& callback) {
        if (!tls_keys_valid_[ci]) return 0;

        int offset = 0;

        auto& parser = tls_parser_[ci];
        auto& keys = tls_keys_[ci];
        auto& seq_num = tls_seq_num_[ci];

        for (;;) {
            switch (parser.state) {

            case websocket::crypto::TLSRecordState::NEED_HEADER: {
                if (buf.available() < 5) return offset;

                uint8_t hdr[5];
                buf.read(hdr, 5);

                parser.content_type = hdr[0];
                parser.record_length = (static_cast<uint16_t>(hdr[3]) << 8) | hdr[4];
                parser.payload_consumed = 0;
                parser.tag_consumed = 0;

                if (keys.is_tls13) {
                    parser.ciphertext_length = parser.record_length - 16;
                } else {
                    if (buf.available() < 8) {
                        parser.ciphertext_length = parser.record_length - 8 - 16;
                        return offset;
                    }
                    uint8_t explicit_nonce[8];
                    buf.read(explicit_nonce, 8);
                    websocket::crypto::derive_nonce_tls12(keys.iv, explicit_nonce, parser.nonce);
                    parser.ciphertext_length = parser.record_length - 8 - 16;
                }

                if (keys.is_tls13) {
                    websocket::crypto::derive_nonce_tls13(keys.iv, seq_num, parser.nonce);
                }

                parser.block_counter = 2;  // GCM convention

                // Non-application data: skip entire record
                if (parser.content_type != 0x17) {
                    uint16_t to_skip = parser.ciphertext_length + 16;
                    if (!keys.is_tls13) {
                        // explicit nonce already consumed
                    }
                    size_t avail = buf.available();
                    size_t skip_now = (avail < to_skip) ? avail : to_skip;
                    { uint8_t discard[256]; size_t skipped = 0;
                      while (skipped < skip_now) {
                          size_t chunk_sz = (skip_now - skipped < sizeof(discard)) ? (skip_now - skipped) : sizeof(discard);
                          buf.read(discard, chunk_sz);
                          skipped += chunk_sz;
                      }
                    }
                    if (skip_now < to_skip) {
                        parser.payload_consumed = static_cast<uint16_t>(skip_now);
                        parser.state = websocket::crypto::TLSRecordState::NEED_TAG;
                        parser.tag_consumed = 0;
                        parser.ciphertext_length = to_skip - static_cast<uint16_t>(skip_now);
                        return offset;
                    }
                    seq_num++;
                    parser.state = websocket::crypto::TLSRecordState::NEED_HEADER;
                    if (offset == 0) return -1;
                    continue;
                }

                if (offset == 0) {
                    buf.reset_read_stats();
                }

                parser.state = websocket::crypto::TLSRecordState::NEED_PAYLOAD;
                continue;
            }

            case websocket::crypto::TLSRecordState::NEED_PAYLOAD: {
                uint16_t payload_remaining = parser.ciphertext_length - parser.payload_consumed;

                if (payload_remaining == 0) {
                    parser.state = websocket::crypto::TLSRecordState::NEED_TAG;
                    parser.tag_consumed = 0;
                    continue;
                }

                size_t avail = buf.available();
                if (avail == 0) return offset;

                size_t can_decrypt = chunk_size - static_cast<size_t>(offset);
                if (can_decrypt > payload_remaining) can_decrypt = payload_remaining;
                if (can_decrypt > avail) can_decrypt = avail;

                bool is_final = (can_decrypt >= payload_remaining);

                if (!is_final) {
                    can_decrypt = (can_decrypt / 16) * 16;
                    if (can_decrypt == 0) return offset;
                }

                size_t read_ct = buf.read(dest + offset, can_decrypt);
                if (read_ct < can_decrypt) {
                    can_decrypt = read_ct;
                    is_final = false;
                    can_decrypt = (can_decrypt / 16) * 16;
                    if (can_decrypt == 0) return offset;
                }

                parser.block_counter = websocket::crypto::AESCTRDecryptor::decrypt(
                    keys.round_keys, keys.num_rounds,
                    parser.nonce, parser.block_counter,
                    dest + offset, dest + offset, can_decrypt);
                parser.payload_consumed += static_cast<uint16_t>(can_decrypt);

                size_t chunk_len = can_decrypt;

                if (is_final && keys.is_tls13 && chunk_len > 0) {
                    uint8_t* chunk_start = dest + offset;
                    size_t pos = chunk_len - 1;
                    while (pos > 0 && chunk_start[pos] == 0) {
                        pos--;
                    }
                    uint8_t inner_ct = chunk_start[pos];
                    chunk_len = pos;

                    if (inner_ct != 0x17) {
                        parser.state = websocket::crypto::TLSRecordState::NEED_TAG;
                        parser.tag_consumed = 0;
                        seq_num++;
                        continue;
                    }
                }

                if (chunk_len > 0) {
                    callback(dest + offset, chunk_len);
                    offset += static_cast<int>(chunk_len);
                }

                if (parser.payload_consumed >= parser.ciphertext_length) {
                    parser.state = websocket::crypto::TLSRecordState::NEED_TAG;
                    parser.tag_consumed = 0;
                }
                continue;
            }

            case websocket::crypto::TLSRecordState::NEED_TAG: {
                if (parser.content_type != 0x17) {
                    uint16_t remaining = parser.ciphertext_length;
                    if (remaining > 0) {
                        size_t avail = buf.available();
                        size_t skip_now = (avail < remaining) ? avail : remaining;
                        { uint8_t discard[256]; size_t skipped = 0;
                          while (skipped < skip_now) {
                              size_t chunk_sz = (skip_now - skipped < sizeof(discard)) ? (skip_now - skipped) : sizeof(discard);
                              buf.read(discard, chunk_sz);
                              skipped += chunk_sz;
                          }
                        }
                        parser.ciphertext_length -= static_cast<uint16_t>(skip_now);
                        if (parser.ciphertext_length > 0) return offset;
                    }
                    seq_num++;
                    parser.state = websocket::crypto::TLSRecordState::NEED_HEADER;
                    continue;
                }

                uint16_t tag_remaining = 16 - parser.tag_consumed;
                size_t avail = buf.available();
                size_t skip_now = (avail < tag_remaining) ? avail : tag_remaining;
                { uint8_t discard[16];
                  buf.read(discard, skip_now);
                }
                parser.tag_consumed += static_cast<uint16_t>(skip_now);

                if (parser.tag_consumed >= 16) {
                    seq_num++;
                    parser.state = websocket::crypto::TLSRecordState::NEED_HEADER;
                    continue;
                }
                return offset;
            }

            } // switch
        } // for
    }

    /**
     * RX Thread (2-thread model): recv → AES-CTR decrypt → MSG_INBOX
     *
     * With AutoReconnect: dispatches per-connection state machine.
     * Without AutoReconnect: direct ACTIVE path for all connections.
     */
    void rx_thread_inline_ssl() {
        // Per-connection event policies and recv buffers
        typename IOPolicy::event_policy_t event_policy[NUM_CONN];
        std::unique_ptr<BSDZeroCopyRecvBuffer> recv_buf[NUM_CONN];
        constexpr size_t RAW_RECV_BUFSIZE = 16384;
        [[maybe_unused]] uint8_t raw_recv_buf[RAW_RECV_BUFSIZE];  // Used by NoSSL path

        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            reinit_event_policy(ci, event_policy[ci]);
            recv_buf[ci] = std::make_unique<BSDZeroCopyRecvBuffer>();
        }

        while (running_.load(std::memory_order_acquire)) {
            for (size_t ci = 0; ci < NUM_CONN; ci++) {

                if constexpr (AutoReconnect) {
                    auto disp = dispatch_reconnect_phase(ci, event_policy[ci]);
                    if (disp == ReconnDispatch::SKIP) continue;
                    if (disp == ReconnDispatch::TLS_READY) {
                        process_tls_ready_read(ci);
                        if (conn_state_->get_ws_handshake_done(ci)) {
                            conn_state_->clear_ws_handshake_done(ci);
                            switch_to_direct_decrypt(ci);
                            recv_buf[ci] = std::make_unique<BSDZeroCopyRecvBuffer>();
                        }
                        continue;
                    }
                    // disp == ACTIVE: fall through
                }

                // Normal ACTIVE path: poll → recv → decrypt → publish
                if (sockfd_[ci] < 0) continue;

                auto poll = rx_poll_wait(event_policy[ci], sockfd_[ci]);
                if (poll.shutdown) break;
                if (!poll.ready) continue;

                // =================================================================
                // Path A: Direct AES-CTR decryption (AES-GCM guaranteed)
                // =================================================================
                if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
                    ssize_t raw_n = recv_buf[ci]->recv_into_next(sockfd_[ci], poll.poll_cycle,
                        poll.hw_oldest_ns, poll.hw_latest_ns, poll.hw_count, 0);

                    if (raw_n > 0) {
                        uint64_t segs_after_recv = query_tcp_segs_in(sockfd_[ci]);
                        uint32_t seg_delta = static_cast<uint32_t>(segs_after_recv - prev_tcp_segs_in_[ci]);
                        prev_tcp_segs_in_[ci] = segs_after_recv;
                        auto& last_slot = recv_buf[ci]->slots[(recv_buf[ci]->tail_ - 1) & BSDZeroCopyRecvBuffer::POOL_MASK];
                        last_slot.tcp_seg_delta = seg_delta;

                        aes_ctr_decrypt_loop(ci, *recv_buf[ci]);
                    } else if (raw_n == 0) {
                        printf("[RX] Connection %zu closed by peer\n", ci);
                        if constexpr (AutoReconnect) { start_reconnect(ci); }
                        else { running_.store(false, std::memory_order_release); }
                    } else {
                        prev_tcp_segs_in_[ci] = poll.segs_before;
                    }
                    continue;
                }

                // =================================================================
                // Path C: NoSSL — raw recv → MSG_INBOX
                // =================================================================
                if constexpr (!detail::is_userspace_ssl_v<SSLPolicy>) {
                    uint64_t ssl_read_start_cycle = rdtscp();
                    ssize_t n = ::recv(sockfd_[ci], raw_recv_buf, RAW_RECV_BUFSIZE, 0);

                    if (n > 0) {
                        uint64_t ssl_read_end_cycle = rdtscp();

                        uint64_t segs_after = query_tcp_segs_in(sockfd_[ci]);
                        uint32_t seg_delta = static_cast<uint32_t>(segs_after - prev_tcp_segs_in_[ci]);
                        prev_tcp_segs_in_[ci] = segs_after;

                        uint32_t write_pos = msg_inbox_[ci]->current_write_pos();
                        msg_inbox_[ci]->write_data(raw_recv_buf, static_cast<uint32_t>(n));

                        BSDReadStats stats{};
                        stats.oldest_poll_cycle = poll.poll_cycle;
                        stats.latest_poll_cycle = poll.poll_cycle;
                        stats.oldest_hw_ns = poll.hw_oldest_ns;
                        stats.latest_hw_ns = poll.hw_latest_ns;
                        stats.total_hw_count = poll.hw_count;
                        stats.total_seg_delta = seg_delta;
                        publish_rx_metadata(ci, stats, write_pos, static_cast<uint32_t>(n),
                                            ssl_read_start_cycle, ssl_read_end_cycle, false);
                    } else if (n == 0) {
                        printf("[RX] Connection %zu closed by peer\n", ci);
                        if constexpr (AutoReconnect) { start_reconnect(ci); }
                        else { running_.store(false, std::memory_order_release); }
                    } else {
                        prev_tcp_segs_in_[ci] = poll.segs_before;
                    }
                }
            } // for each connection
        }

        printf("[RX] Thread exiting\n");
    }

    /**
     * TX Thread (2-thread model): MSG_OUTBOX + PONGS → SSL_write + send
     *
     * Routes by connection_id when EnableAB is true.
     */
    void tx_thread_inline_ssl() {
        while (running_.load(std::memory_order_acquire)) {
            bool did_work = false;

            if (conn_state_ && !conn_state_->is_running(PROC_TRANSPORT)) {
                printf("[TX] ConnStateShm signals shutdown\n");
                running_.store(false, std::memory_order_release);
                break;
            }

            // Process MSG_OUTBOX
            size_t processed = msg_outbox_cons_->process_manually(
                [&](MsgOutboxEvent& event, int64_t seq, bool end_of_batch) {
                    (void)seq;
                    (void)end_of_batch;

                    if (event.data_len > 0) {
                        size_t ci = EnableAB ? event.connection_id : 0;

                        // Skip if connection is not sendable
                        if constexpr (AutoReconnect) {
                            if (reconn_[ci].phase != BSDConnPhase::ACTIVE &&
                                reconn_[ci].phase != BSDConnPhase::TLS_READY) {
                                return true;  // Drop: connection not ready
                            }
                        }

                        ssize_t total_sent = 0;
                        while (total_sent < event.data_len) {
                            ssize_t sent;
                            if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
                                sent = ssl_[ci].write(
                                    event.data + total_sent,
                                    event.data_len - total_sent
                                );
                            } else {
                                sent = ::send(sockfd_[ci],
                                    event.data + total_sent,
                                    event.data_len - total_sent,
                                    MSG_NOSIGNAL);
                            }

                            if (sent < 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    std::this_thread::yield();
                                    continue;
                                }
                                printf("[TX] send error (conn %zu): %s\n", ci, strerror(errno));
                                if constexpr (AutoReconnect) {
                                    break;  // Don't shut down, let RX handle reconnect
                                } else {
                                    running_.store(false, std::memory_order_release);
                                    return false;
                                }
                            }
                            total_sent += sent;
                        }
                    }

                    if (event.msg_type == MSG_TYPE_WS_CLOSE) {
                        printf("[TX] Close requested by upstream\n");
                        running_.store(false, std::memory_order_release);
                        return false;
                    }

                    return true;
                },
                16
            );

            if (processed > 0) {
                msg_outbox_cons_->commit_manually();
                did_work = true;
            }

            // Process PONGS
            processed = pongs_cons_->process_manually(
                [&](PongFrameAligned& pong, int64_t seq, bool end_of_batch) {
                    (void)seq;
                    (void)end_of_batch;

                    if (pong.data_len > 0) {
                        size_t ci = EnableAB ? pong.connection_id : 0;

                        // Skip if connection is not sendable
                        if constexpr (AutoReconnect) {
                            if (reconn_[ci].phase != BSDConnPhase::ACTIVE &&
                                reconn_[ci].phase != BSDConnPhase::TLS_READY) {
                                return true;
                            }
                        }

                        ssize_t sent;
                        if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
                            sent = ssl_[ci].write(pong.data, pong.data_len);
                        } else {
                            sent = ::send(sockfd_[ci], pong.data, pong.data_len, MSG_NOSIGNAL);
                        }

                        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            printf("[TX] PONG send error (conn %zu): %s\n", ci, strerror(errno));
                        }
                    }
                    return true;
                },
                8
            );

            if (processed > 0) {
                pongs_cons_->commit_manually();
                did_work = true;
            }

            if (!did_work) {
                std::this_thread::yield();
            }
        }

        printf("[TX] Thread exiting\n");
    }

    // ========================================================================
    // BlockingIO - 1 Thread Model (SingleThreadSSL)
    // ========================================================================

    /**
     * run_blocking_1thread() - Single-threaded RX+TX main loop
     *
     * Combines recv/decrypt and outbox/pong send in one loop:
     *   1. Drive reconnect state machines (if AutoReconnect)
     *   2. Unified poll() across all ACTIVE/TLS_READY sockets (1ms timeout)
     *   3. Per-ready-connection: recv → Path A (AES-CTR) or Path C (NoSSL) → MSG_INBOX + MSG_METADATA
     *   4. Process MSG_OUTBOX (max 16) and PONGS (max 8) → SSL_write/send
     *
     * No child threads, no spinlocks. Runs on caller's thread.
     * TX latency is bounded by poll timeout (1ms worst case).
     */
    void run_blocking_1thread() {
        // Per-connection event policies (used only for reconnect state machine)
        typename IOPolicy::event_policy_t event_policy[NUM_CONN];
        std::unique_ptr<BSDZeroCopyRecvBuffer> recv_buf[NUM_CONN];
        constexpr size_t RAW_RECV_BUFSIZE = 16384;
        [[maybe_unused]] uint8_t raw_recv_buf[RAW_RECV_BUFSIZE];  // Used by NoSSL path

        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            reinit_event_policy(ci, event_policy[ci]);
            recv_buf[ci] = std::make_unique<BSDZeroCopyRecvBuffer>();
        }

        struct pollfd pfds[NUM_CONN];
        size_t pfd_to_ci[NUM_CONN];

        while (running_.load(std::memory_order_acquire)) {
            // Check ConnStateShm shutdown
            if (conn_state_ && !conn_state_->is_running(PROC_TRANSPORT)) {
                printf("[1T] ConnStateShm signals shutdown\n");
                running_.store(false, std::memory_order_release);
                break;
            }

            // ── AutoReconnect: drive state machines for non-ACTIVE connections ──
            if constexpr (AutoReconnect) {
                for (size_t ci = 0; ci < NUM_CONN; ci++) {
                    auto disp = dispatch_reconnect_phase(ci, event_policy[ci]);
                    if (disp == ReconnDispatch::TLS_READY) {
                        process_tls_ready_read(ci);
                        if (conn_state_->get_ws_handshake_done(ci)) {
                            conn_state_->clear_ws_handshake_done(ci);
                            switch_to_direct_decrypt(ci);
                            recv_buf[ci] = std::make_unique<BSDZeroCopyRecvBuffer>();
                        }
                    }
                    // ACTIVE: will be collected into pfds[] below
                    // SKIP: nothing to do
                }
            }

            // ── RX Phase: unified poll + per-connection recv/decrypt ──
            int nfds = 0;
            for (size_t ci = 0; ci < NUM_CONN; ci++) {
                if (sockfd_[ci] < 0) continue;
                if constexpr (AutoReconnect) {
                    if (reconn_[ci].phase != BSDConnPhase::ACTIVE) continue;
                }
                pfds[nfds] = { sockfd_[ci], POLLIN, 0 };
                pfd_to_ci[nfds] = ci;
                nfds++;
            }

            int ready = 0;
            if (nfds > 0) {
                ready = ::poll(pfds, static_cast<nfds_t>(nfds), 1);  // 1ms timeout
            } else {
                // No sockets ready — sleep 1ms to avoid busy-spin during reconnect
                usleep(1000);
            }

            if (ready > 0) {
                for (int fi = 0; fi < nfds; fi++) {
                    if (!(pfds[fi].revents & POLLIN)) continue;
                    size_t ci = pfd_to_ci[fi];

                    uint64_t poll_cycle = rdtscp();

#ifdef __linux__
                    uint64_t hw_oldest_ns = 0, hw_latest_ns = 0;
                    uint32_t hw_count = 0;
                    {
                        timing_record_t hw_timing = {};
                        drain_hw_timestamps(sockfd_[ci], &hw_timing);
                        hw_oldest_ns = hw_timing.hw_timestamp_oldest_ns;
                        hw_latest_ns = hw_timing.hw_timestamp_latest_ns;
                        hw_count = hw_timing.hw_timestamp_count;
                    }
#endif

                    // =============================================================
                    // Path A: Direct AES-CTR decryption (AES-GCM guaranteed)
                    // =============================================================
                    if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
                        ssize_t raw_n = recv_buf[ci]->recv_into_next(sockfd_[ci], poll_cycle,
#ifdef __linux__
                            hw_oldest_ns, hw_latest_ns, hw_count,
#else
                            0, 0, 0,
#endif
                            0);

                        if (raw_n > 0) {
                            uint64_t segs_after_recv = query_tcp_segs_in(sockfd_[ci]);
                            uint32_t seg_delta = static_cast<uint32_t>(segs_after_recv - prev_tcp_segs_in_[ci]);
                            prev_tcp_segs_in_[ci] = segs_after_recv;
                            auto& last_slot = recv_buf[ci]->slots[(recv_buf[ci]->tail_ - 1) & BSDZeroCopyRecvBuffer::POOL_MASK];
                            last_slot.tcp_seg_delta = seg_delta;

                            aes_ctr_decrypt_loop(ci, *recv_buf[ci]);
                        } else if (raw_n == 0) {
                            printf("[1T] Connection %zu closed by peer\n", ci);
                            if constexpr (AutoReconnect) { start_reconnect(ci); }
                            else { running_.store(false, std::memory_order_release); }
                        }
                        continue;
                    }

                    // =============================================================
                    // Path C: NoSSL — raw recv → MSG_INBOX
                    // =============================================================
                    if constexpr (!detail::is_userspace_ssl_v<SSLPolicy>) {
                        uint64_t ssl_read_start_cycle = rdtscp();
                        ssize_t n = ::recv(sockfd_[ci], raw_recv_buf, RAW_RECV_BUFSIZE, 0);

                        if (n > 0) {
                            uint64_t ssl_read_end_cycle = rdtscp();

                            uint64_t segs_after = query_tcp_segs_in(sockfd_[ci]);
                            uint32_t seg_delta = static_cast<uint32_t>(segs_after - prev_tcp_segs_in_[ci]);
                            prev_tcp_segs_in_[ci] = segs_after;

                            uint32_t write_pos = msg_inbox_[ci]->current_write_pos();
                            msg_inbox_[ci]->write_data(raw_recv_buf, static_cast<uint32_t>(n));

                            BSDReadStats stats{};
                            stats.oldest_poll_cycle = poll_cycle;
                            stats.latest_poll_cycle = poll_cycle;
#ifdef __linux__
                            stats.oldest_hw_ns = hw_oldest_ns;
                            stats.latest_hw_ns = hw_latest_ns;
                            stats.total_hw_count = hw_count;
#endif
                            stats.total_seg_delta = seg_delta;
                            publish_rx_metadata(ci, stats, write_pos, static_cast<uint32_t>(n),
                                                ssl_read_start_cycle, ssl_read_end_cycle, false);
                        } else if (n == 0) {
                            printf("[1T] Connection %zu closed by peer\n", ci);
                            if constexpr (AutoReconnect) { start_reconnect(ci); }
                            else { running_.store(false, std::memory_order_release); }
                        }
                    }
                } // for each ready pfd
            } // if (ready > 0)

            // ── TX Phase ──
            if constexpr (InlineWS) {
                // InlineWS: TX is handled by DirectTXSink (ssl_.write from WSCore).
                // Idle tick: ping/pong/watchdog
                inline_ws_.ws_core.idle_tick();
            } else {
                // IPC mode: MSG_OUTBOX + PONGS — no locks needed
                size_t processed = msg_outbox_cons_->process_manually(
                    [&](MsgOutboxEvent& event, int64_t seq, bool end_of_batch) {
                        (void)seq;
                        (void)end_of_batch;

                        if (event.data_len > 0) {
                            size_t ci = EnableAB ? event.connection_id : 0;

                            if constexpr (AutoReconnect) {
                                if (reconn_[ci].phase != BSDConnPhase::ACTIVE &&
                                    reconn_[ci].phase != BSDConnPhase::TLS_READY) {
                                    return true;  // Drop: connection not ready
                                }
                            }

                            ssize_t total_sent = 0;
                            while (total_sent < event.data_len) {
                                ssize_t sent;
                                if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
                                    sent = ssl_[ci].write(
                                        event.data + total_sent,
                                        event.data_len - total_sent
                                    );
                                } else {
                                    sent = ::send(sockfd_[ci],
                                        event.data + total_sent,
                                        event.data_len - total_sent,
                                        MSG_NOSIGNAL);
                                }

                                if (sent < 0) {
                                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                        std::this_thread::yield();
                                        continue;
                                    }
                                    printf("[1T] send error (conn %zu): %s\n", ci, strerror(errno));
                                    if constexpr (AutoReconnect) {
                                        break;
                                    } else {
                                        running_.store(false, std::memory_order_release);
                                        return false;
                                    }
                                }
                                total_sent += sent;
                            }
                        }

                        if (event.msg_type == MSG_TYPE_WS_CLOSE) {
                            printf("[1T] Close requested by upstream\n");
                            running_.store(false, std::memory_order_release);
                            return false;
                        }

                        return true;
                    },
                    16
                );

                if (processed > 0) {
                    msg_outbox_cons_->commit_manually();
                }

                // Process PONGS
                processed = pongs_cons_->process_manually(
                    [&](PongFrameAligned& pong, int64_t seq, bool end_of_batch) {
                        (void)seq;
                        (void)end_of_batch;

                        if (pong.data_len > 0) {
                            size_t ci = EnableAB ? pong.connection_id : 0;

                            if constexpr (AutoReconnect) {
                                if (reconn_[ci].phase != BSDConnPhase::ACTIVE &&
                                    reconn_[ci].phase != BSDConnPhase::TLS_READY) {
                                    return true;
                                }
                            }

                            ssize_t sent;
                            if constexpr (detail::is_userspace_ssl_v<SSLPolicy>) {
                                sent = ssl_[ci].write(pong.data, pong.data_len);
                            } else {
                                sent = ::send(sockfd_[ci], pong.data, pong.data_len, MSG_NOSIGNAL);
                            }

                            if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                                printf("[1T] PONG send error (conn %zu): %s\n", ci, strerror(errno));
                            }
                        }
                        return true;
                    },
                    8
                );

                if (processed > 0) {
                    pongs_cons_->commit_manually();
                }
            }
        }

        printf("[1T] Single-thread loop exiting\n");
    }

    // ========================================================================
    // BlockingIO - 3 Thread Model (DedicatedSSL)
    // ========================================================================

    void run_blocking_3thread() {
        rx_thread_ = std::thread([this]() { rx_raw_thread(); });
        ssl_thread_ = std::thread([this]() { ssl_thread_main(); });
        tx_thread_ = std::thread([this]() { tx_raw_thread(); });

        if (rx_thread_.joinable()) rx_thread_.join();
        if (ssl_thread_.joinable()) ssl_thread_.join();
        if (tx_thread_.joinable()) tx_thread_.join();

        printf("[BSD-Transport] 3-thread mode stopped\n");
    }

    /**
     * RX Raw Thread (3-thread model): recv() raw bytes → encrypted_rx_ring
     *
     * With AutoReconnect: drives TCP connect + TLS handshake state machine.
     * ACTIVE/TLS_READY connections: recv → encrypted_rx_ring_[ci].
     */
    void rx_raw_thread() {
        constexpr size_t RECV_BUFSIZE = 16384;
        uint8_t recv_buf[RECV_BUFSIZE];

        typename IOPolicy::event_policy_t event_policy[NUM_CONN];
        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            reinit_event_policy(ci, event_policy[ci]);
        }

        while (running_.load(std::memory_order_acquire)) {
            for (size_t ci = 0; ci < NUM_CONN; ci++) {

                if constexpr (AutoReconnect) {
                    auto disp = dispatch_reconnect_phase(ci, event_policy[ci]);
                    if (disp == ReconnDispatch::SKIP) continue;
                    // TLS_READY and ACTIVE both fall through to recv → encrypted_rx_ring
                }

                if (sockfd_[ci] < 0) continue;

                auto poll = rx_poll_wait(event_policy[ci], sockfd_[ci]);
                if (poll.shutdown) break;
                if (!poll.ready) continue;

                ssize_t n = ::recv(sockfd_[ci], recv_buf, sizeof(recv_buf), 0);

                if (n > 0) {
                    uint64_t segs_after = query_tcp_segs_in(sockfd_[ci]);
                    uint32_t seg_delta = static_cast<uint32_t>(segs_after - prev_tcp_segs_in_[ci]);
                    prev_tcp_segs_in_[ci] = segs_after;

                    EncryptedChunk chunk;
                    chunk.len = static_cast<uint32_t>(n);
                    chunk.recv_cycle = poll.poll_cycle;
                    chunk.tcp_seg_delta = seg_delta;
                    chunk.hw_timestamp_oldest_ns = poll.hw_oldest_ns;
                    chunk.hw_timestamp_latest_ns = poll.hw_latest_ns;
                    chunk.hw_timestamp_count = poll.hw_count;
                    chunk.connection_id = static_cast<uint8_t>(ci);
                    memcpy(chunk.data, recv_buf, n);

                    while (!encrypted_rx_ring_[ci].try_push(chunk)) {
                        if (!running_.load(std::memory_order_acquire)) break;
                        std::this_thread::yield();
                    }
                } else if (n == 0) {
                    printf("[RX-Raw] Connection %zu closed by peer\n", ci);
                    if constexpr (AutoReconnect) { start_reconnect(ci); }
                    else { running_.store(false, std::memory_order_release); }
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    prev_tcp_segs_in_[ci] = poll.segs_before;
                } else {
                    if constexpr (AutoReconnect) { start_reconnect(ci); }
                    else { running_.store(false, std::memory_order_release); }
                }
            } // for each connection
        }

        printf("[RX-Raw] Thread exiting\n");
    }

    /**
     * SSL Thread (3-thread model): decrypt RX, encrypt TX
     *
     * Per-connection RX path:
     *   - TLS_READY: pop chunks → append_encrypted_view → SSL_read (WS handshake)
     *   - ACTIVE: pop chunks → ChunkPoolBuffer → ssl_read_by_chunk (AES-CTR)
     * TX path: route MSG_OUTBOX/PONGS by connection_id → ssl_[ci].write()
     */
    void ssl_thread_main() {
        // Encryption buffer for SSL_write output
        uint8_t encrypt_buf[16384];

        // Per-connection pool and state for RX decryption
        static constexpr size_t RX_POOL_SIZE = 128;  // Must be power of 2
        static constexpr size_t RX_POOL_MASK = RX_POOL_SIZE - 1;

        struct PerConnSSLState {
            std::unique_ptr<std::array<EncryptedChunk, RX_POOL_SIZE>> rx_pool;
            size_t pool_write_idx = 0;
            ChunkPoolBuffer chunk_pool_buf;
        };
        PerConnSSLState conn_ssl[NUM_CONN];
        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            conn_ssl[ci].rx_pool = std::make_unique<std::array<EncryptedChunk, RX_POOL_SIZE>>();
            conn_ssl[ci].chunk_pool_buf.pool_ = conn_ssl[ci].rx_pool.get();
        }

        while (running_.load(std::memory_order_acquire)) {
            bool did_work = false;

            if (conn_state_ && !conn_state_->is_running(PROC_TRANSPORT)) {
                running_.store(false, std::memory_order_release);
                break;
            }

            // ========== RX Path: Per-connection decrypt ==========
            for (size_t ci = 0; ci < NUM_CONN; ci++) {
                auto& cs = conn_ssl[ci];

                if constexpr (AutoReconnect) {
                    // Acquire fence pairs with release fence in start_reconnect()
                    std::atomic_thread_fence(std::memory_order_acquire);
                    auto phase = reconn_[ci].phase;

                    // Non-ACTIVE/TLS_READY: perform deferred SSL shutdown (safe here,
                    // only SSL thread accesses ssl_[ci] in 3-thread mode) and skip.
                    if (phase != BSDConnPhase::ACTIVE && phase != BSDConnPhase::TLS_READY) {
                        // Drain stale RX ring entries from before reconnect
                        EncryptedChunk discard;
                        while (encrypted_rx_ring_[ci].try_pop(discard)) {}
                        // Reset pool state
                        cs.pool_write_idx = 0;
                        cs.chunk_pool_buf = ChunkPoolBuffer{};
                        cs.chunk_pool_buf.pool_ = cs.rx_pool.get();
                        continue;
                    }

                    // TLS_READY: pop encrypted chunks → shared ssl_read_and_publish
                    if (phase == BSDConnPhase::TLS_READY) {
                        EncryptedChunk chunk;
                        while (encrypted_rx_ring_[ci].try_pop(chunk)) {
                            ssl_[ci].append_encrypted_view(chunk.data, chunk.len);
                            did_work = true;
                        }

                        ssl_read_and_publish(ci);

                        // Check if WS handshake completed → switch to direct decrypt
                        if (conn_state_->get_ws_handshake_done(ci)) {
                            conn_state_->clear_ws_handshake_done(ci);
                            switch_to_direct_decrypt(ci);
                            // Reset pool state for ACTIVE mode
                            cs.pool_write_idx = 0;
                            cs.chunk_pool_buf = ChunkPoolBuffer{};
                            cs.chunk_pool_buf.pool_ = cs.rx_pool.get();
                        }
                        continue;
                    }
                    // phase == ACTIVE: fall through to decrypt path
                }

                // ACTIVE: AES-CTR path (AES-GCM guaranteed)
                {
                    size_t live = cs.pool_write_idx - cs.chunk_pool_buf.chunks_consumed();

                    while (live < RX_POOL_SIZE) {
                        auto& slot = (*cs.rx_pool)[cs.pool_write_idx & RX_POOL_MASK];
                        if (!encrypted_rx_ring_[ci].try_pop(slot)) break;

                        cs.chunk_pool_buf.push(cs.pool_write_idx);
                        cs.pool_write_idx++;
                        live++;
                        did_work = true;
                    }

                    // Drain TLS records via AES-CTR decryption into MSG_INBOX
                    if (aes_ctr_decrypt_loop(ci, cs.chunk_pool_buf))
                        did_work = true;
                }
            } // for each connection

            // ========== TX Path: Encrypt ==========
            // Process MSG_OUTBOX — route by connection_id
            size_t processed = msg_outbox_cons_->process_manually(
                [&](MsgOutboxEvent& event, int64_t seq, bool end_of_batch) {
                    (void)seq;
                    (void)end_of_batch;

                    if (event.data_len > 0) {
                        size_t ci = EnableAB ? event.connection_id : 0;

                        if constexpr (AutoReconnect) {
                            if (reconn_[ci].phase != BSDConnPhase::ACTIVE &&
                                reconn_[ci].phase != BSDConnPhase::TLS_READY) {
                                return true;  // Drop: connection not ready
                            }
                        }

                        ssl_[ci].set_encrypted_output(encrypt_buf, sizeof(encrypt_buf));
                        ssize_t ret = ssl_[ci].write(event.data, event.data_len);
                        if (ret <= 0) {
                            printf("[SSL] Encrypt failed (conn %zu)\n", ci);
                            if constexpr (AutoReconnect) return true;
                            running_.store(false, std::memory_order_release);
                            return false;
                        }

                        size_t encrypted_len = ssl_[ci].encrypted_output_len();
                        ssl_[ci].clear_encrypted_output();

                        EncryptedChunk tx_chunk;
                        tx_chunk.len = static_cast<uint32_t>(encrypted_len);
                        memcpy(tx_chunk.data, encrypt_buf, encrypted_len);
                        tx_chunk.recv_cycle = 0;
                        tx_chunk.connection_id = static_cast<uint8_t>(ci);

                        while (!encrypted_tx_ring_[ci].try_push(tx_chunk)) {
                            if (!running_.load(std::memory_order_acquire)) return false;
                            std::this_thread::yield();
                        }
                    }

                    if (event.msg_type == MSG_TYPE_WS_CLOSE) {
                        running_.store(false, std::memory_order_release);
                        return false;
                    }

                    return true;
                },
                16
            );

            if (processed > 0) {
                msg_outbox_cons_->commit_manually();
                did_work = true;
            }

            // Process PONGS — route by connection_id
            processed = pongs_cons_->process_manually(
                [&](PongFrameAligned& pong, int64_t seq, bool end_of_batch) {
                    (void)seq;
                    (void)end_of_batch;

                    if (pong.data_len > 0) {
                        size_t ci = EnableAB ? pong.connection_id : 0;

                        if constexpr (AutoReconnect) {
                            if (reconn_[ci].phase != BSDConnPhase::ACTIVE &&
                                reconn_[ci].phase != BSDConnPhase::TLS_READY) {
                                return true;
                            }
                        }

                        ssl_[ci].set_encrypted_output(encrypt_buf, sizeof(encrypt_buf));
                        ssize_t ret = ssl_[ci].write(pong.data, pong.data_len);
                        if (ret <= 0) {
                            printf("[SSL] PONG encrypt failed (conn %zu)\n", ci);
                            return true;
                        }

                        size_t encrypted_len = ssl_[ci].encrypted_output_len();
                        ssl_[ci].clear_encrypted_output();

                        EncryptedChunk tx_chunk;
                        tx_chunk.len = static_cast<uint32_t>(encrypted_len);
                        memcpy(tx_chunk.data, encrypt_buf, encrypted_len);
                        tx_chunk.recv_cycle = 0;
                        tx_chunk.connection_id = static_cast<uint8_t>(ci);

                        while (!encrypted_tx_ring_[ci].try_push(tx_chunk)) {
                            if (!running_.load(std::memory_order_acquire)) return false;
                            std::this_thread::yield();
                        }
                    }
                    return true;
                },
                8
            );

            if (processed > 0) {
                pongs_cons_->commit_manually();
                did_work = true;
            }

            if (!did_work) {
                std::this_thread::yield();
            }
        }

        printf("[SSL] Thread exiting\n");
    }

    /**
     * TX Raw Thread (3-thread model): encrypted_tx_ring_[ci] → send(sockfd_[ci]) raw bytes
     */
    void tx_raw_thread() {
        while (running_.load(std::memory_order_acquire)) {
            if (conn_state_ && !conn_state_->is_running(PROC_TRANSPORT)) {
                running_.store(false, std::memory_order_release);
                break;
            }

            bool did_work = false;
            for (size_t ci = 0; ci < NUM_CONN; ci++) {
                if (sockfd_[ci] < 0) continue;

                EncryptedChunk tx_chunk;
                if (encrypted_tx_ring_[ci].try_pop(tx_chunk)) {
                    ssize_t total_sent = 0;
                    while (static_cast<uint32_t>(total_sent) < tx_chunk.len) {
                        ssize_t sent = ::send(sockfd_[ci],
                            tx_chunk.data + total_sent,
                            tx_chunk.len - total_sent,
                            MSG_NOSIGNAL);

                        if (sent < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                std::this_thread::yield();
                                continue;
                            }
                            printf("[TX-Raw] send error (conn %zu): %s\n", ci, strerror(errno));
                            if constexpr (AutoReconnect) {
                                break;  // Don't shut down, let RX handle reconnect
                            } else {
                                running_.store(false, std::memory_order_release);
                            }
                            break;
                        }
                        total_sent += sent;
                    }
                    did_work = true;
                }
            }

            if (!did_work) {
                std::this_thread::yield();
            }
        }

        printf("[TX-Raw] Thread exiting\n");
    }

    // ========================================================================
    // AsyncIO - Single Thread io_uring Event Loop
    // ========================================================================

#ifdef __linux__
    static constexpr size_t RECV_BUFSIZE = 16384;
    static constexpr unsigned QUEUE_DEPTH = 256;
    static constexpr unsigned MAX_INFLIGHT_SENDS = 64;
    static constexpr size_t SEND_BUFSIZE = 4096;

    enum class IoUringOpType : uint8_t {
        RECV = 1,
        SEND = 2,
    };

    struct IoUringUserData {
        IoUringOpType op_type;
        uint8_t buffer_idx;
        uint16_t reserved;
        uint32_t len;
    };
#endif

    void run_async() {
#ifdef __linux__
        if constexpr (IOPolicy::is_async) {
            submit_recv();

            while (running_.load(std::memory_order_acquire)) {
                if (conn_state_ && !conn_state_->is_running(PROC_TRANSPORT)) {
                    running_.store(false, std::memory_order_release);
                    break;
                }

                process_outbox_async();
                process_pongs_async();
                process_completions_async();
            }

            printf("[BSD-Transport] io_uring mode stopped\n");
        }
#endif
    }

#ifdef __linux__
    void submit_recv() {
        if constexpr (IOPolicy::is_async) {
            struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
            if (!sqe) return;

            io_uring_prep_recv(sqe, sockfd_[0], recv_buf_.data(), recv_buf_.size(), 0);

            IoUringUserData user_data = {};
            user_data.op_type = IoUringOpType::RECV;
            sqe->user_data = *reinterpret_cast<uint64_t*>(&user_data);

            recv_pending_ = true;
        }
    }

    void submit_send(const uint8_t* data, size_t len) {
        if constexpr (IOPolicy::is_async) {
            if (inflight_sends_ >= MAX_INFLIGHT_SENDS) return;

            struct io_uring_sqe* sqe = io_uring_get_sqe(&ring_);
            if (!sqe) return;

            size_t buf_idx = send_buf_write_idx_ % MAX_INFLIGHT_SENDS;
            if (len > SEND_BUFSIZE) return;
            memcpy(send_bufs_[buf_idx], data, len);

            io_uring_prep_send(sqe, sockfd_[0], send_bufs_[buf_idx], len, MSG_NOSIGNAL);

            IoUringUserData user_data = {};
            user_data.op_type = IoUringOpType::SEND;
            user_data.buffer_idx = static_cast<uint8_t>(buf_idx);
            user_data.len = static_cast<uint32_t>(len);
            sqe->user_data = *reinterpret_cast<uint64_t*>(&user_data);

            send_buf_write_idx_++;
            inflight_sends_++;
        }
    }

    void process_outbox_async() {
        if constexpr (IOPolicy::is_async) {
            size_t processed = msg_outbox_cons_->process_manually(
                [&](MsgOutboxEvent& event, int64_t seq, bool end_of_batch) {
                    (void)seq;
                    (void)end_of_batch;

                    if (event.data_len > 0) {
                        submit_send(event.data, event.data_len);
                    }

                    if (event.msg_type == MSG_TYPE_WS_CLOSE) {
                        running_.store(false, std::memory_order_release);
                        return false;
                    }

                    return true;
                },
                16
            );

            if (processed > 0) {
                msg_outbox_cons_->commit_manually();
            }
        }
    }

    void process_pongs_async() {
        if constexpr (IOPolicy::is_async) {
            size_t processed = pongs_cons_->process_manually(
                [&](PongFrameAligned& pong, int64_t seq, bool end_of_batch) {
                    (void)seq;
                    (void)end_of_batch;

                    if (pong.data_len > 0) {
                        submit_send(pong.data, pong.data_len);
                    }
                    return true;
                },
                8
            );

            if (processed > 0) {
                pongs_cons_->commit_manually();
            }
        }
    }

    void process_completions_async() {
        if constexpr (IOPolicy::is_async) {
            io_uring_submit(&ring_);

            struct __kernel_timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
            struct io_uring_cqe* cqe;
            int ret = io_uring_wait_cqe_timeout(&ring_, &cqe, &ts);

            if (ret == -ETIME || ret == -EINTR) {
                if (!recv_pending_) submit_recv();
                return;
            }

            if (ret < 0) return;

            unsigned head;
            unsigned completed = 0;

            io_uring_for_each_cqe(&ring_, head, cqe) {
                handle_completion_async(cqe);
                completed++;
            }

            io_uring_cq_advance(&ring_, completed);
        }
    }

    void handle_completion_async(struct io_uring_cqe* cqe) {
        if constexpr (IOPolicy::is_async) {
            IoUringUserData user_data = *reinterpret_cast<IoUringUserData*>(&cqe->user_data);

            if (user_data.op_type == IoUringOpType::RECV) {
                handle_recv_completion_async(cqe);
            } else if (user_data.op_type == IoUringOpType::SEND) {
                handle_send_completion_async(cqe, user_data);
            }
        }
    }

    void handle_recv_completion_async(struct io_uring_cqe* cqe) {
        if constexpr (IOPolicy::is_async) {
            recv_pending_ = false;
            int32_t res = cqe->res;

            if (res > 0) {
                uint64_t recv_cycle = rdtscp();

                // TCP segment delta since last completion
                uint64_t segs_now = query_tcp_segs_in(sockfd_[0]);
                uint32_t seg_delta = static_cast<uint32_t>(segs_now - prev_tcp_segs_in_[0]);
                prev_tcp_segs_in_[0] = segs_now;

                uint32_t write_pos = msg_inbox_[0]->current_write_pos();
                msg_inbox_[0]->write_data(recv_buf_.data(), static_cast<uint32_t>(res));

                int64_t seq = msg_metadata_prod_[0]->try_claim();
                if (seq >= 0) {
                    auto& meta = (*msg_metadata_prod_[0])[seq];
                    meta.clear();
                    meta.first_nic_frame_poll_cycle = recv_cycle;
                    meta.latest_nic_frame_poll_cycle = recv_cycle;
                    meta.ssl_read_start_cycle = recv_cycle;   // No SSL in io_uring mode
                    meta.ssl_read_end_cycle = recv_cycle;
                    meta.ssl_last_op_cycle = last_op_cycle_[0];
                    meta.msg_inbox_offset = write_pos;
                    meta.decrypted_len = static_cast<uint32_t>(res);
                    meta.nic_packet_ct = seg_delta;
                    msg_metadata_prod_[0]->publish(seq);
                }

                last_op_cycle_[0] = rdtscp();
                submit_recv();
            } else if (res == 0) {
                running_.store(false, std::memory_order_release);
            } else {
                if (-res != EAGAIN && -res != EWOULDBLOCK && -res != ECANCELED) {
                    running_.store(false, std::memory_order_release);
                } else {
                    submit_recv();
                }
            }
        }
    }

    void handle_send_completion_async(struct io_uring_cqe* cqe, const IoUringUserData& user_data) {
        if constexpr (IOPolicy::is_async) {
            inflight_sends_--;
            (void)cqe;
            (void)user_data;
        }
    }
#endif

    // ========================================================================
    // TCP Segment Counting (cross-platform)
    // ========================================================================

    /**
     * Query cumulative TCP segments received on socket.
     * Uses TCP_INFO (Linux) or TCP_CONNECTION_INFO (macOS).
     * Returns 0 on failure or unsupported platform.
     */
    uint64_t query_tcp_segs_in(int sockfd) const {
#ifdef __linux__
        // netinet/tcp.h defines a truncated tcp_info (104 bytes) missing tcpi_segs_in.
        // The kernel's full struct has it at offset 140 (__u32).
        // Read into a raw buffer to access it without requiring linux/tcp.h.
        static constexpr size_t TCPI_SEGS_IN_OFFSET = 140;
        static constexpr size_t KERNEL_TCP_INFO_SIZE = 256;  // generous upper bound
        char buf[KERNEL_TCP_INFO_SIZE] = {};
        socklen_t len = sizeof(buf);
        if (getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, buf, &len) == 0 &&
            len >= TCPI_SEGS_IN_OFFSET + sizeof(uint32_t)) {
            uint32_t segs_in;
            std::memcpy(&segs_in, buf + TCPI_SEGS_IN_OFFSET, sizeof(segs_in));
            return segs_in;
        }
#endif
        (void)sockfd;
        return 0;
    }

    // ========================================================================
    // InlineWS State (conditional)
    // ========================================================================

    struct InlineWSState {
        WSProcessor ws_core;
        DirectTXSink<SSLPolicy, EnableAB> tx_sink;
    };
    struct EmptyState {};
    [[no_unique_address]] std::conditional_t<InlineWS, InlineWSState, EmptyState> inline_ws_{};

public:
    /**
     * Initialize InlineWS mode: wire WSCore to msg_inbox, ws_frame_info_prod, DirectTXSink.
     * Called by pipeline launcher before run().
     */
    template<typename WSFrameInfoProd>
    void init_inline(WSFrameInfoProd* ws_frame_info_prod,
                     ConnStateShm* conn_state,
                     MsgInbox* msg_inbox_a,
                     MsgInbox* msg_inbox_b = nullptr) {
        static_assert(InlineWS, "init_inline() only valid when WSProcessor != void");
        inline_ws_.tx_sink.ssl_ = ssl_;
        if constexpr (EnableAB) {
            inline_ws_.ws_core.init(msg_inbox_a, ws_frame_info_prod,
                                    &inline_ws_.tx_sink, conn_state, msg_inbox_b);
        } else {
            inline_ws_.ws_core.init(msg_inbox_a, ws_frame_info_prod,
                                    &inline_ws_.tx_sink, conn_state);
        }
    }

    /**
     * Access the inline WSCore's app_handler (for AppHandler propagation).
     */
    auto& inline_app_handler() {
        static_assert(InlineWS);
        return inline_ws_.ws_core.app_handler();
    }

private:
    // ========================================================================
    // Member Variables
    // ========================================================================

    // Per-connection state
    int sockfd_[NUM_CONN]{};                    // Socket FDs (init to -1 in constructor)
    SSLPolicy ssl_[NUM_CONN]{};                 // SSL policy instances
    MsgInbox* msg_inbox_[NUM_CONN]{};           // Per-connection MSG_INBOX
    MsgMetadataProd* msg_metadata_prod_[NUM_CONN]{};  // Per-connection metadata producers

    // Internal rings for 3-thread model (per-connection)
    LocalRingBuffer<EncryptedChunk, RING_SIZE> encrypted_rx_ring_[NUM_CONN];
    LocalRingBuffer<EncryptedChunk, RING_SIZE> encrypted_tx_ring_[NUM_CONN];

    // Direct AES-CTR decryption state (per-connection)
    websocket::crypto::TLSRecordKeys tls_keys_[NUM_CONN]{};
    websocket::crypto::TLSRecordParser tls_parser_[NUM_CONN]{};
    uint64_t tls_seq_num_[NUM_CONN]{};
    bool tls_keys_valid_[NUM_CONN]{};

    // Timestamp tracking (per-connection)
    uint64_t last_op_cycle_[NUM_CONN]{};
    uint64_t prev_tcp_segs_in_[NUM_CONN]{};
    uint64_t ssl_read_count_[NUM_CONN]{};

    // Reconnect state (per-connection)
    BSDReconnectCtx reconn_[NUM_CONN]{};
    std::string host_;
    uint16_t port_ = 0;
    bool tls_ready_signaled_ = false;

    // External ring adapters (shared, single instance)
    MsgOutboxCons* msg_outbox_cons_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;

    // Shared state
    ConnStateShm* conn_state_ = nullptr;

    // Thread management
    std::thread rx_thread_;
    std::thread ssl_thread_;
    std::thread tx_thread_;
    std::atomic<bool> running_{false};

    // io_uring state (Linux only, AsyncIO only)
#ifdef __linux__
    struct io_uring ring_;
    bool ring_initialized_ = false;
    std::array<uint8_t, RECV_BUFSIZE> recv_buf_;
    bool recv_pending_ = false;
    uint8_t send_bufs_[MAX_INFLIGHT_SENDS][SEND_BUFSIZE];
    size_t send_buf_write_idx_ = 0;
    unsigned inflight_sends_ = 0;
#endif
};

// ============================================================================
// Type Aliases for Common Configurations
// ============================================================================

// 2-thread blocking with platform-default event policy
template<typename SSLPolicy, typename MsgOutboxCons, typename MsgMetadataProd, typename PongsCons,
         bool EnableAB = false, bool AutoReconnect = false>
using BSDSocketTransport2Thread = BSDSocketTransportProcess<
    SSLPolicy, DefaultBlockingIO, InlineSSL,
    MsgOutboxCons, MsgMetadataProd, PongsCons,
    EnableAB, AutoReconnect>;

// 3-thread blocking with platform-default event policy
template<typename SSLPolicy, typename MsgOutboxCons, typename MsgMetadataProd, typename PongsCons,
         bool EnableAB = false, bool AutoReconnect = false>
using BSDSocketTransport3Thread = BSDSocketTransportProcess<
    SSLPolicy, DefaultBlockingIO, DedicatedSSL,
    MsgOutboxCons, MsgMetadataProd, PongsCons,
    EnableAB, AutoReconnect>;

// 1-thread blocking with platform-default event policy (single-thread RX+TX, no spinlocks)
template<typename SSLPolicy, typename MsgOutboxCons, typename MsgMetadataProd, typename PongsCons,
         bool EnableAB = false, bool AutoReconnect = false>
using BSDSocketTransport1Thread = BSDSocketTransportProcess<
    SSLPolicy, DefaultBlockingIO, SingleThreadSSL,
    MsgOutboxCons, MsgMetadataProd, PongsCons,
    EnableAB, AutoReconnect>;

#ifdef __linux__
// 1-thread io_uring (Linux only, NoSSL or kTLS only)
template<typename MsgOutboxCons, typename MsgMetadataProd, typename PongsCons>
using BSDSocketTransportIoUring = BSDSocketTransportProcess<
    websocket::ssl::NoSSLPolicy, AsyncIO, InlineSSL,
    MsgOutboxCons, MsgMetadataProd, PongsCons>;
#endif

}  // namespace websocket::pipeline
