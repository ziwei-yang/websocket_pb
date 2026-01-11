// pipeline/pipeline_data.hpp
// Data structures for inter-process communication
// All structs are cache-line aligned for zero-copy IPC
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <cstring>
#include <chrono>

// Disruptor IPC includes (MUST be before pipeline_config.hpp to avoid macro conflict)
#include <disruptor/src/ipc/shared_region.hpp>
#include <disruptor/src/core/ring_buffer.hpp>
#include <disruptor/src/core/sequence.hpp>
#include <disruptor/src/core/sequence_barrier.hpp>
#include <disruptor/src/core/event_processor.hpp>
#include <disruptor/src/policy/sequence_policy.hpp>
#include <disruptor/src/policy/storage_policy.hpp>
#include <disruptor/src/policy/memory_ordering_policy.hpp>
#include <disruptor/src/policy/wait_policy.hpp>
#include <disruptor/src/policy/batch_policy.hpp>
#include <disruptor/src/policy/error_policy.hpp>
#include <hftshm/layout.hpp>

#include "pipeline_config.hpp"

namespace websocket::pipeline {

// ============================================================================
// UMEMFrameDescriptor - Passed through RAW_INBOX/OUTBOX rings
// Size: 32 bytes (fits 2 per cache line)
// ============================================================================

struct alignas(32) UMEMFrameDescriptor {
    uint64_t umem_addr;              // UMEM base address of frame
    uint64_t nic_timestamp_ns;       // NIC hardware timestamp (ns)
    uint64_t nic_frame_poll_cycle;   // TSC cycle when XDP Poll retrieved frame from NIC
    uint16_t frame_len;              // Actual frame length (Ethernet + IP + TCP + payload)
    uint8_t  frame_type;             // FrameType enum (RX/ACK/PONG/MSG)
    uint8_t  consumed;               // Set by Transport when frame processing done
    uint8_t  _pad[4];                // Padding to 32 bytes

    void clear() {
        umem_addr = 0;
        nic_timestamp_ns = 0;
        nic_frame_poll_cycle = 0;
        frame_len = 0;
        frame_type = FRAME_TYPE_RX;
        consumed = 0;
    }
};
static_assert(sizeof(UMEMFrameDescriptor) == 32, "UMEMFrameDescriptor must be 32 bytes");

// ============================================================================
// MsgMetadata - Passed through MSG_METADATA_INBOX ring
// Size: 64 bytes (1 per cache line)
// Tracks timestamps from NIC through SSL_read
// ============================================================================

struct alignas(64) MsgMetadata {
    // Timestamp chain (first packet of this SSL_read batch)
    uint64_t first_nic_timestamp_ns;       // NIC timestamp of first packet
    uint64_t first_raw_frame_poll_cycle;   // Poll cycle when first raw frame retrieved

    // Timestamp chain (latest packet)
    uint64_t latest_nic_timestamp_ns;      // NIC timestamp of most recent packet
    uint64_t latest_raw_frame_poll_cycle;  // Poll cycle when latest raw frame retrieved

    // SSL_read timing
    uint64_t ssl_read_cycle;               // TSC when SSL_read completed

    // Data location in MSG_INBOX
    uint32_t msg_inbox_offset;             // Start offset in MSG_INBOX buffer
    uint32_t decrypted_len;                // Length of decrypted data from this SSL_read

    // Reserved for future use
    uint8_t  _pad[8];

    void clear() {
        first_nic_timestamp_ns = 0;
        first_raw_frame_poll_cycle = 0;
        latest_nic_timestamp_ns = 0;
        latest_raw_frame_poll_cycle = 0;
        ssl_read_cycle = 0;
        msg_inbox_offset = 0;
        decrypted_len = 0;
    }
};
static_assert(sizeof(MsgMetadata) == 64, "MsgMetadata must be 64 bytes");

// ============================================================================
// WSFrameInfo - Passed through WS_FRAME_INFO_RING to AppClient
// Size: 128 bytes (2 per cache line)
// Full timestamp chain from NIC to WS parse completion
// ============================================================================

struct alignas(64) WSFrameInfo {
    // Location in MSG_INBOX (for non-fragmented messages)
    uint32_t msg_inbox_offset;             // Start offset of WS payload in MSG_INBOX
    uint32_t payload_len;                  // WebSocket payload length

    // WebSocket frame info
    uint8_t  opcode;                       // WS opcode (TEXT=1, BINARY=2, etc.)
    uint8_t  is_fin;                       // FIN bit set (last frame of message)
    uint8_t  is_fragmented;                // True if payload spans multiple fragments
    uint8_t  _pad1;

    // For fragmented messages (is_fragmented=true):
    // - msg_inbox_offset is NOT valid (fragments scattered)
    // - frame_total_len gives total bytes consumed in MSG_INBOX
    uint32_t frame_total_len;              // Total WS frame length(s) including headers

    // Full timestamp chain (Gap N6: renamed to match design doc)
    uint64_t first_byte_ts;                // NIC timestamp when first byte arrived
    uint64_t first_raw_frame_poll_cycle;   // XDP Poll cycle (first raw frame)
    uint64_t last_byte_ts;                 // NIC timestamp when frame completed
    uint64_t latest_raw_frame_poll_cycle;  // XDP Poll cycle (latest raw frame)
    uint64_t ssl_read_cycle;               // SSL_read completion cycle
    uint64_t ws_parse_cycle;               // WS frame parse completion cycle

    // Reserved for alignment
    uint8_t  _pad2[32];

    void clear() {
        msg_inbox_offset = 0;
        payload_len = 0;
        opcode = 0;
        is_fin = 0;
        is_fragmented = 0;
        frame_total_len = 0;
        first_byte_ts = 0;
        first_raw_frame_poll_cycle = 0;
        last_byte_ts = 0;
        latest_raw_frame_poll_cycle = 0;
        ssl_read_cycle = 0;
        ws_parse_cycle = 0;
    }
};
static_assert(sizeof(WSFrameInfo) == 128, "WSFrameInfo must be 128 bytes");

// ============================================================================
// PongFrameAligned - PONG payload passed through PONGS ring
// Size: 128 bytes
// WebSocket PONG payload (max 125 bytes per RFC 6455)
// ============================================================================

struct alignas(64) PongFrameAligned {
    uint8_t  payload[125];            // PONG payload (copied from PING)
    uint8_t  payload_len;             // Actual payload length (0-125)
    uint8_t  _pad[2];

    void clear() {
        payload_len = 0;
    }

    void set(const uint8_t* data, size_t len) {
        payload_len = static_cast<uint8_t>(len > 125 ? 125 : len);
        if (payload_len > 0) {
            std::memcpy(payload, data, payload_len);
        }
    }
};
static_assert(sizeof(PongFrameAligned) == 128, "PongFrameAligned must be 128 bytes");

// ============================================================================
// MsgOutboxEvent - AppClient TX messages through MSG_OUTBOX
// Size: 2KB (to fit large WS messages)
// ============================================================================

struct alignas(2048) MsgOutboxEvent {
    // Header room for WS framing (14 bytes max: 2-byte short + 8-byte extended + 4-byte mask)
    // Left at beginning so data can be contiguous after WS header
    uint8_t  header_room[14];

    // User message data
    uint8_t  data[2030];              // User payload (fits within 2KB total)
    uint16_t data_len;                // Actual data length
    uint8_t  opcode;                  // WS opcode (TEXT=1, BINARY=2)
    uint8_t  msg_type;                // MSG_TYPE_DATA or MSG_TYPE_WS_CLOSE

    void clear() {
        data_len = 0;
        opcode = WS_OP_TEXT;
        msg_type = MSG_TYPE_DATA;
    }

    // Set message content
    bool set_text(const char* msg, size_t len) {
        if (len > sizeof(data)) return false;
        std::memcpy(data, msg, len);
        data_len = static_cast<uint16_t>(len);
        opcode = WS_OP_TEXT;
        msg_type = MSG_TYPE_DATA;
        return true;
    }

    bool set_binary(const uint8_t* msg, size_t len) {
        if (len > sizeof(data)) return false;
        std::memcpy(data, msg, len);
        data_len = static_cast<uint16_t>(len);
        opcode = WS_OP_BINARY;
        msg_type = MSG_TYPE_DATA;
        return true;
    }

    // Build CLOSE frame
    void set_close(uint16_t status_code, const char* reason = nullptr, size_t reason_len = 0) {
        data[0] = static_cast<uint8_t>(status_code >> 8);
        data[1] = static_cast<uint8_t>(status_code & 0xFF);
        data_len = 2;
        if (reason && reason_len > 0) {
            size_t copy_len = (reason_len > sizeof(data) - 2) ? sizeof(data) - 2 : reason_len;
            std::memcpy(data + 2, reason, copy_len);
            data_len += static_cast<uint16_t>(copy_len);
        }
        opcode = WS_OP_CLOSE;
        msg_type = MSG_TYPE_WS_CLOSE;
    }
};
static_assert(sizeof(MsgOutboxEvent) == 2048, "MsgOutboxEvent must be 2048 bytes");

// ============================================================================
// ProcessId - Identifies each pipeline process for running flags
// ============================================================================

enum ProcessId : uint8_t {
    PROC_XDP_POLL   = 0,
    PROC_TRANSPORT  = 1,
    PROC_WEBSOCKET  = 2,
    PROC_APPCLIENT  = 3,
    PROC_COUNT      = 4
};

// ============================================================================
// PaddedRunning - Cache-line-padded running flag (avoids false sharing)
// ============================================================================

struct alignas(CACHE_LINE_SIZE) PaddedRunning {
    std::atomic<uint8_t> flag{1};  // 1=running, 0=shutdown
    char padding[CACHE_LINE_SIZE - sizeof(std::atomic<uint8_t>)];
};

// ============================================================================
// ConnStateShm - Shared pipeline state (renamed from ConnStateShm)
// Includes per-process running flags, target URL, TCP state, and TX frame state
// ============================================================================

struct alignas(CACHE_LINE_SIZE) ConnStateShm {
    // ========================================================================
    // Cache Lines 0-3: Per-process running flags (padded to avoid false sharing)
    // ========================================================================
    PaddedRunning running[PROC_COUNT];  // 4 × CACHE_LINE_SIZE bytes

    // ========================================================================
    // Cache Lines 4-7: Per-process ready flags (for startup synchronization)
    // Processes set their flag to 1 when ready. Others can wait_for_ready().
    // ========================================================================
    PaddedRunning ready[PROC_COUNT];    // 4 × CACHE_LINE_SIZE bytes

    // ========================================================================
    // Cache Line 4: Handshake Stage Flags (fork-first architecture)
    // ========================================================================
    alignas(CACHE_LINE_SIZE) struct {
        std::atomic<uint8_t> xdp_ready;       // XDP Poll: XSK socket created, BPF attached
        std::atomic<uint8_t> tcp_ready;       // Transport: TCP ESTABLISHED
        std::atomic<uint8_t> tls_ready;       // Transport: TLS handshake complete
        std::atomic<uint8_t> ws_ready;        // Transport: WebSocket upgraded, subscription sent
        uint8_t _pad[60];                     // Pad to cache line
    } handshake_stage;

    // ========================================================================
    // Cache Line 5: Target URL + TSC frequency (set once, read-only after init)
    // ========================================================================
    alignas(CACHE_LINE_SIZE) char target_host[64];  // e.g., "stream.binance.com"
    uint16_t target_port;                           // e.g., 443
    uint8_t  _pad_url[6];
    char target_path[128];                          // e.g., "/stream"
    uint64_t tsc_freq_hz;                           // TSC frequency for latency

    // ========================================================================
    // Extended Target Config (for fork-first architecture)
    // ========================================================================
    char subscription_json[4096];                   // Subscription message to send after WS upgrade
    char bpf_path[256];                             // Path to BPF object file
    char interface_name[64];                        // Network interface name

    // ========================================================================
    // Cache Line 5: TCP state (Transport process only - no atomics needed)
    // ========================================================================
    alignas(CACHE_LINE_SIZE) uint32_t snd_nxt;  // Next send sequence
    uint32_t snd_una;                         // Oldest unacked sequence
    uint32_t rcv_nxt;                         // Next expected receive sequence
    uint32_t peer_recv_window;                // Peer advertised window
    uint8_t  window_scale;                    // Window scale factor
    uint8_t  tcp_conn_state;                   // TCP_ESTABLISHED, etc.
    uint8_t  _pad_tcp1[2];

    // Addressing (set during handshake, read-only after)
    uint32_t local_ip;                        // Local IP (network byte order)
    uint32_t remote_ip;                       // Remote IP (network byte order)
    uint16_t local_port;                      // Local port (host byte order)
    uint16_t remote_port;                     // Remote port (host byte order)
    uint8_t  local_mac[6];                    // Local MAC address
    uint8_t  remote_mac[6];                   // Remote (gateway) MAC address

    // MSS from SYN-ACK
    uint16_t peer_mss;
    uint8_t  _pad_tcp2[6];

    // RTT tracking (Transport only)
    uint64_t last_ack_cycle;                  // TSC when last ACK sent
    uint64_t srtt_us;                         // Smoothed RTT in microseconds
    uint64_t rttvar_us;                       // RTT variance in microseconds

    // ========================================================================
    // Cache Line 6: TX Frame Allocation (hot path for XDP Poll + Transport)
    // Merged from TxFrameState
    // ========================================================================
    alignas(CACHE_LINE_SIZE) struct {
        // ACK pool (Transport allocates, XDP Poll releases)
        std::atomic<uint64_t> ack_alloc_pos;
        std::atomic<uint64_t> ack_release_pos;

        // PONG pool (Transport allocates, XDP Poll releases after ACK)
        std::atomic<uint64_t> pong_alloc_pos;
        std::atomic<uint64_t> pong_release_pos;
        std::atomic<uint64_t> pong_acked_pos;

        // MSG pool (Transport allocates, XDP Poll releases after ACK)
        std::atomic<uint64_t> msg_alloc_pos;
        std::atomic<uint64_t> msg_release_pos;
        std::atomic<uint64_t> msg_acked_pos;

        // Pad to 2 cache lines (9 × 8 = 72 bytes, need 128)
        char _pad[2 * CACHE_LINE_SIZE - 72];
    } tx_frame;

    // ========================================================================
    // Helper Methods
    // ========================================================================
    bool is_running(ProcessId proc) const {
        return running[proc].flag.load(std::memory_order_acquire) != 0;
    }

    void shutdown_all() {
        for (int i = 0; i < PROC_COUNT; ++i) {
            running[i].flag.store(0, std::memory_order_release);
        }
    }

    // Ready flag methods for startup synchronization
    void set_ready(ProcessId proc) {
        ready[proc].flag.store(1, std::memory_order_release);
    }

    bool is_ready(ProcessId proc) const {
        return ready[proc].flag.load(std::memory_order_acquire) != 0;
    }

    void wait_for_ready(ProcessId proc) const {
        while (!is_ready(proc) && is_running(proc)) {
            __builtin_ia32_pause();  // Hint for spin-wait
        }
    }

    // Handshake stage methods (fork-first architecture)
    void set_handshake_xdp_ready() {
        handshake_stage.xdp_ready.store(1, std::memory_order_release);
    }

    void set_handshake_tcp_ready() {
        handshake_stage.tcp_ready.store(1, std::memory_order_release);
    }

    void set_handshake_tls_ready() {
        handshake_stage.tls_ready.store(1, std::memory_order_release);
    }

    void set_handshake_ws_ready() {
        handshake_stage.ws_ready.store(1, std::memory_order_release);
    }

    bool is_handshake_xdp_ready() const {
        return handshake_stage.xdp_ready.load(std::memory_order_acquire) != 0;
    }

    bool is_handshake_tcp_ready() const {
        return handshake_stage.tcp_ready.load(std::memory_order_acquire) != 0;
    }

    bool is_handshake_tls_ready() const {
        return handshake_stage.tls_ready.load(std::memory_order_acquire) != 0;
    }

    bool is_handshake_ws_ready() const {
        return handshake_stage.ws_ready.load(std::memory_order_acquire) != 0;
    }

    // Wait for handshake stage with timeout (returns false on timeout)
    bool wait_for_handshake_xdp_ready(uint64_t timeout_us = 10000000) const {
        auto start = std::chrono::steady_clock::now();
        while (!is_handshake_xdp_ready()) {
            if (!is_running(PROC_XDP_POLL)) {
                return false;
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (static_cast<uint64_t>(elapsed) > timeout_us) {
                return false;
            }
            __builtin_ia32_pause();
        }
        return true;
    }

    bool wait_for_handshake_ws_ready(uint64_t timeout_us = 30000000) const {
        auto start = std::chrono::steady_clock::now();
        while (!is_handshake_ws_ready()) {
            if (!is_running(PROC_TRANSPORT)) return false;
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (static_cast<uint64_t>(elapsed) > timeout_us) return false;
            __builtin_ia32_pause();
        }
        return true;
    }

    void init() {
        // Initialize running flags
        for (int i = 0; i < PROC_COUNT; ++i) {
            running[i].flag.store(1, std::memory_order_relaxed);
        }

        // Initialize ready flags (all not ready)
        for (int i = 0; i < PROC_COUNT; ++i) {
            ready[i].flag.store(0, std::memory_order_relaxed);
        }

        // Initialize handshake stage flags (fork-first architecture)
        handshake_stage.xdp_ready.store(0, std::memory_order_relaxed);
        handshake_stage.tcp_ready.store(0, std::memory_order_relaxed);
        handshake_stage.tls_ready.store(0, std::memory_order_relaxed);
        handshake_stage.ws_ready.store(0, std::memory_order_relaxed);

        // Target URL (set by handshake manager)
        std::memset(target_host, 0, sizeof(target_host));
        target_port = 0;
        std::memset(target_path, 0, sizeof(target_path));
        tsc_freq_hz = 0;

        // Extended target config (fork-first architecture)
        std::memset(subscription_json, 0, sizeof(subscription_json));
        std::memset(bpf_path, 0, sizeof(bpf_path));
        std::memset(interface_name, 0, sizeof(interface_name));

        // TCP state (plain assignments - Transport only)
        snd_nxt = 0;
        snd_una = 0;
        rcv_nxt = 0;
        peer_recv_window = 65535;
        window_scale = 0;
        tcp_conn_state = 0;
        local_ip = 0;
        remote_ip = 0;
        local_port = 0;
        remote_port = 0;
        std::memset(local_mac, 0, 6);
        std::memset(remote_mac, 0, 6);
        peer_mss = 1460;
        last_ack_cycle = 0;
        srtt_us = 100000;   // Initial 100ms
        rttvar_us = 50000;  // Initial 50ms

        // TX frame allocation
        tx_frame.ack_alloc_pos.store(0, std::memory_order_relaxed);
        tx_frame.ack_release_pos.store(0, std::memory_order_relaxed);
        tx_frame.pong_alloc_pos.store(0, std::memory_order_relaxed);
        tx_frame.pong_release_pos.store(0, std::memory_order_relaxed);
        tx_frame.pong_acked_pos.store(0, std::memory_order_relaxed);
        tx_frame.msg_alloc_pos.store(0, std::memory_order_relaxed);
        tx_frame.msg_release_pos.store(0, std::memory_order_relaxed);
        tx_frame.msg_acked_pos.store(0, std::memory_order_relaxed);
    }
};


// TCP states
inline constexpr uint8_t TCP_CLOSED      = 0;
inline constexpr uint8_t TCP_SYN_SENT    = 1;
inline constexpr uint8_t TCP_ESTABLISHED = 2;
inline constexpr uint8_t TCP_FIN_WAIT_1  = 3;
inline constexpr uint8_t TCP_FIN_WAIT_2  = 4;
inline constexpr uint8_t TCP_CLOSING     = 5;
inline constexpr uint8_t TCP_TIME_WAIT   = 6;
inline constexpr uint8_t TCP_CLOSE_WAIT  = 7;
inline constexpr uint8_t TCP_LAST_ACK    = 8;

// ============================================================================
// AckDescriptor - Simple ACK frame descriptor for ACK_OUTBOX
// Size: 16 bytes
// ============================================================================

struct alignas(16) AckDescriptor {
    uint64_t umem_addr;               // UMEM address of pre-built ACK packet
    uint16_t frame_len;               // ACK packet length
    uint8_t  _pad[6];

    void clear() {
        umem_addr = 0;
        frame_len = 0;
    }
};
static_assert(sizeof(AckDescriptor) == 16, "AckDescriptor must be 16 bytes");

// ============================================================================
// PongDescriptor - Encrypted PONG frame descriptor for PONG_OUTBOX
// Size: 32 bytes
// ============================================================================

struct alignas(32) PongDescriptor {
    uint64_t umem_addr;               // UMEM address of encrypted PONG packet
    uint16_t frame_len;               // Total frame length
    uint8_t  _pad[22];

    void clear() {
        umem_addr = 0;
        frame_len = 0;
    }
};
static_assert(sizeof(PongDescriptor) == 32, "PongDescriptor must be 32 bytes");

// ============================================================================
// IPC Ring Types (hftshm-backed disruptor rings)
// ============================================================================

// IPC ring buffer using external storage (data in shared memory)
template<typename T, size_t SIZE>
using IPCRingBuffer = disruptor::ring_buffer<T, SIZE,
    disruptor::storage_policies::external_storage_policy,
    disruptor::padding_policies::no_padding>;

// IPC sequence using external atomic (sequence in shared memory header)
using IPCSequence = disruptor::sequence<
    disruptor::sequence_policies::external_atomic_sequence,
    disruptor::memory_ordering_policies::acquire_release>;

// IPC sequence barrier
using IPCSequenceBarrier = disruptor::sequence_barrier<
    disruptor::sequence_policies::external_atomic_sequence,
    disruptor::memory_ordering_policies::acquire_release,
    disruptor::wait_policies::busy_spin_wait_policy>;

// IPC event processor template
template<typename T, typename Handler>
using IPCEventProcessor = disruptor::event_processor<T, Handler,
    disruptor::sequence_policies::external_atomic_sequence,
    disruptor::memory_ordering_policies::acquire_release,
    disruptor::wait_policies::busy_spin_wait_policy,
    disruptor::batch_policies::auto_batch,
    disruptor::error_policies::throw_on_error,
    disruptor::storage_policies::external_storage_policy,
    disruptor::padding_policies::no_padding>;

// Concrete IPC ring types
using MsgMetadataIPCRing = IPCRingBuffer<MsgMetadata, MSG_METADATA_SIZE>;
using WSFrameInfoIPCRing = IPCRingBuffer<WSFrameInfo, WS_FRAME_INFO_SIZE>;
using MsgOutboxIPCRing = IPCRingBuffer<MsgOutboxEvent, MSG_OUTBOX_SIZE>;

// ============================================================================
// IPC Ring Adapters
// Provide try_publish()/try_consume() interface over hftshm shared_region
// These wrap disruptor::ipc::shared_region for use with existing process classes
// ============================================================================

// IPC Ring Producer - wraps shared_region for try_publish() API
// Used by producers (XDP Poll for RAW_INBOX, Transport for MSG_METADATA, etc.)
template<typename T>
struct IPCRingProducer {
    disruptor::ipc::shared_region& region_;
    size_t element_count_;   // buffer_size / sizeof(T)
    size_t element_mask_;    // element_count - 1 (for element indexing)

    explicit IPCRingProducer(disruptor::ipc::shared_region& r) : region_(r) {
        // Compute element-based sizes (metadata stores bytes, we need element count)
        element_count_ = region_.buffer_size() / sizeof(T);
        element_mask_ = element_count_ - 1;
    }

    // Non-copyable but movable
    IPCRingProducer(const IPCRingProducer&) = delete;
    IPCRingProducer& operator=(const IPCRingProducer&) = delete;
    IPCRingProducer(IPCRingProducer&&) = default;
    IPCRingProducer& operator=(IPCRingProducer&&) = default;

    // Get consumer sequence (for producer to track what has been consumed)
    int64_t consumer_sequence() const {
        return region_.consumer_sequence(0)->load(std::memory_order_acquire);
    }

    // Get data pointer for direct access (used by XDP Poll for frame reclaim)
    T* data() { return region_.template data<T>(); }
    const T* data() const { return region_.template data<T>(); }

    // Get element mask for ring buffer indexing (NOT byte mask!)
    size_t index_mask() const { return element_mask_; }

    // ========================================================================
    // Two-step API: try_claim() + publish() for zero-copy writes
    // ========================================================================

    // Try to claim the next slot in the ring buffer
    // Returns sequence number >= 0 on success, -1 if buffer full
    // Note: Disruptor convention - cursor stores "last claimed", claim returns "next slot"
    int64_t try_claim() {
        auto* cursor = region_.producer_cursor();
        auto* consumer_seq = region_.consumer_sequence(0);

        // Claim next slot: fetch_add returns OLD value, we want NEW value
        int64_t old_cursor = cursor->fetch_add(1, std::memory_order_relaxed);
        int64_t next_seq = old_cursor + 1;  // The slot we just claimed
        int64_t cons = consumer_seq->load(std::memory_order_acquire);

        // Check if buffer full (producer wrapped around to consumer)
        if (next_seq - cons >= static_cast<int64_t>(element_count_)) {
            cursor->fetch_sub(1, std::memory_order_relaxed);  // Rollback
            return -1;
        }

        return next_seq;
    }

    // Access slot at claimed sequence (for zero-copy writes)
    T& operator[](int64_t seq) {
        T* data_ptr = region_.template data<T>();
        return data_ptr[seq & element_mask_];
    }

    // Publish the claimed sequence (makes it visible to consumers)
    void publish(int64_t seq) {
        auto* published = region_.producer_published();

        // Wait for in-order publishing (ensures no gaps in published sequence)
        int64_t expected = seq - 1;

        while (published->load(std::memory_order_acquire) != expected) {
            __builtin_ia32_pause();
        }

        // Publish
        published->store(seq, std::memory_order_release);
    }

    // ========================================================================
    // Single-step API: try_publish() for convenience (copies data)
    // ========================================================================

    bool try_publish(const T& item) {
        auto* cursor = region_.producer_cursor();
        auto* published = region_.producer_published();
        auto* consumer_seq = region_.consumer_sequence(0);

        // Claim next slot: fetch_add returns OLD value, we want NEW value
        int64_t old_cursor = cursor->fetch_add(1, std::memory_order_relaxed);
        int64_t seq = old_cursor + 1;  // The slot we just claimed
        int64_t cons = consumer_seq->load(std::memory_order_acquire);

        // Check if buffer full (producer wrapped around to consumer)
        if (seq - cons >= static_cast<int64_t>(element_count_)) {
            cursor->fetch_sub(1, std::memory_order_relaxed);  // Rollback
            return false;
        }

        // Write data to buffer
        T* data = region_.data<T>();
        data[seq & element_mask_] = item;

        // Wait for in-order publishing (ensures no gaps in published sequence)
        // This is required for correct disruptor semantics
        int64_t expected = seq - 1;
        while (published->load(std::memory_order_acquire) != expected) {
            __builtin_ia32_pause();
        }

        // Publish
        published->store(seq, std::memory_order_release);
        return true;
    }
};

// IPC Ring Consumer - wraps shared_region for try_consume() API
// Used by consumers (Transport for RAW_INBOX, WebSocket for MSG_METADATA, etc.)
//
// Two consumption patterns:
// 1. try_consume() - single-item consumption with immediate commit (simple, more atomics)
// 2. process_manually() + commit_manually() - batch processing with deferred commit (fewer atomics)
template<typename T>
struct IPCRingConsumer {
    disruptor::ipc::shared_region& region_;
    size_t element_count_;         // buffer_size / sizeof(T)
    size_t element_mask_;          // element_count - 1 (for element indexing)
    int64_t sequence_ = -1;        // Last committed sequence
    int64_t last_processed_ = -1;  // Last processed sequence (for deferred commit)

    explicit IPCRingConsumer(disruptor::ipc::shared_region& r) : region_(r) {
        // Compute element-based sizes (metadata stores bytes, we need element count)
        element_count_ = region_.buffer_size() / sizeof(T);
        element_mask_ = element_count_ - 1;
    }

    // Non-copyable but movable
    IPCRingConsumer(const IPCRingConsumer&) = delete;
    IPCRingConsumer& operator=(const IPCRingConsumer&) = delete;
    IPCRingConsumer(IPCRingConsumer&&) = default;
    IPCRingConsumer& operator=(IPCRingConsumer&&) = default;

    // ========================================================================
    // Check if data is available (non-consuming peek)
    // ========================================================================

    bool has_data() const {
        auto* published = region_.producer_published();
        int64_t avail = published->load(std::memory_order_acquire);
        return sequence_ < avail;
    }

    // ========================================================================
    // Pattern 1: Single-item consumption with immediate commit
    // ========================================================================

    bool try_consume(T& item, bool* end_of_batch = nullptr) {
        auto* published = region_.producer_published();
        int64_t avail = published->load(std::memory_order_acquire);

        if (sequence_ >= avail) {
            return false;  // Nothing available
        }

        sequence_++;
        T* data = region_.data<T>();
        item = data[sequence_ & element_mask_];

        // Update consumer sequence (allows producer to reclaim slot)
        region_.consumer_sequence(0)->store(sequence_, std::memory_order_release);

        if (end_of_batch) {
            *end_of_batch = (sequence_ >= avail);
        }
        return true;
    }

    // ========================================================================
    // Pattern 2: Batch processing with deferred commit
    // ========================================================================

    /**
     * Process available events in a batch without committing
     * @tparam F Callable with signature: void(T& event, int64_t sequence, bool end_of_batch)
     *           or bool(T& event, int64_t sequence, bool end_of_batch) - return false to stop
     * @param max_events Maximum events to process in this call
     * @return Number of events processed
     *
     * Call commit_manually() after processing to update consumer sequence.
     */
    template<typename F>
    size_t process_manually(F&& handler, size_t max_events = SIZE_MAX) {
        auto* published = region_.producer_published();
        int64_t avail = published->load(std::memory_order_acquire);
        int64_t next = sequence_ + 1;

        if (avail < next) {
            return 0;  // No events available
        }

        // Limit to max_events (handle SIZE_MAX overflow by capping at avail)
        int64_t end;
        if (max_events >= static_cast<size_t>(INT64_MAX)) {
            end = avail;  // No limit effectively
        } else {
            end = std::min(avail, next + static_cast<int64_t>(max_events) - 1);
        }

        T* data = region_.data<T>();
        size_t count = 0;

        for (int64_t seq = next; seq <= end; ++seq) {
            T& event = data[seq & element_mask_];
            bool is_end = (seq == end);

            // Support multiple handler signatures:
            // 1. (T&, int64_t, bool) -> bool  (3-param with stop control)
            // 2. (T&, int64_t) -> bool        (2-param with stop control)
            // 3. (T&, int64_t, bool) -> void  (3-param, no stop)
            // 4. (T&, int64_t) -> void        (2-param, no stop)
            if constexpr (std::is_invocable_r_v<bool, F, T&, int64_t, bool>) {
                if (!handler(event, seq, is_end)) {
                    ++count;
                    last_processed_ = seq;
                    return count;  // Handler requested stop
                }
            } else if constexpr (std::is_invocable_r_v<bool, F, T&, int64_t>) {
                if (!handler(event, seq)) {
                    ++count;
                    last_processed_ = seq;
                    return count;  // Handler requested stop
                }
            } else if constexpr (std::is_invocable_v<F, T&, int64_t, bool>) {
                handler(event, seq, is_end);
            } else {
                handler(event, seq);
            }
            ++count;
        }

        last_processed_ = end;
        return count;
    }

    /**
     * Commit progress: mark all processed events as consumed
     * Updates consumer sequence so producer knows slots can be reused.
     * Call this after process_manually() when done with the batch.
     */
    void commit_manually() {
        if (last_processed_ > sequence_) {
            sequence_ = last_processed_;
            region_.consumer_sequence(0)->store(sequence_, std::memory_order_release);
        }
        last_processed_ = -1;  // Reset for next batch
    }

    /**
     * Get number of events available without consuming
     */
    size_t available() const {
        auto* published = region_.producer_published();
        int64_t avail = published->load(std::memory_order_acquire);
        return (avail > sequence_) ? static_cast<size_t>(avail - sequence_) : 0;
    }

    /**
     * Direct access to event at sequence (for zero-copy processing)
     * Only valid for sequences between (sequence_+1) and last available
     */
    T& operator[](int64_t seq) {
        T* data = region_.data<T>();
        return data[seq & element_mask_];
    }

    const T& operator[](int64_t seq) const {
        const T* data = region_.data<T>();
        return data[seq & element_mask_];
    }

    // Get current committed sequence (for debugging/stats)
    int64_t sequence() const { return sequence_; }

    // Get last processed sequence (for deferred commit tracking)
    int64_t last_processed() const { return last_processed_; }
};

}  // namespace websocket::pipeline
