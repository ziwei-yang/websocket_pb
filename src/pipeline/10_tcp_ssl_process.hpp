// pipeline/10_tcp_ssl_process.hpp
// Transport Process - SSL/TCP layer with zero-copy I/O
// Handles encryption, retransmission, and adaptive ACK
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <netdb.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <type_traits>
#include <variant>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "msg_inbox.hpp"
#include "../core/timing.hpp"
#include "../stack/userspace_stack.hpp"
#include "../stack/tcp/tcp_reorder.hpp"
#include "../policy/ssl.hpp"  // OpenSSLPolicy, LibreSSLPolicy, WolfSSLPolicy, NoSSLPolicy

namespace websocket::pipeline {

// ============================================================================
// RetransmitSegmentRef - Reference to a sent TCP segment for retransmission
// Size: 32 bytes data (padded to 64 for cache alignment)
// ============================================================================

struct alignas(64) RetransmitSegmentRef {
    uint64_t alloc_pos;        // [0:7]   Frame allocation position (for acked_pos calculation)
    uint64_t send_tsc;         // [8:15]  TSC when segment was sent (for RTO calculation)
    uint32_t frame_idx;        // [16:19] UMEM frame index for retransmit
    uint32_t seq_start;        // [20:23] TCP sequence number at frame start
    uint32_t seq_end;          // [24:27] TCP sequence number at frame end (exclusive)
    uint16_t frame_len;        // [28:29] Total frame length (Eth + IP + TCP + payload)
    uint8_t  flags;            // [30]    TCP flags (PSH|ACK, etc.)
    uint8_t  retransmit_count; // [31]    Number of retransmits so far
    uint8_t  reserved[32];     // [32:63] Padding to cache line
};
static_assert(sizeof(RetransmitSegmentRef) == 64, "RetransmitSegmentRef must be 64 bytes");

// Track last PONG packet for ACK confirmation logging
struct LastPongInfo {
    uint32_t seq_start = 0;      // TCP sequence number at PONG start
    uint32_t seq_end = 0;        // TCP sequence number at PONG end (need ACK >= this)
    uint64_t send_tsc = 0;       // TSC when PONG was sent
    uint32_t frame_idx = 0;      // UMEM frame index
    uint16_t plaintext_len = 0;  // Original plaintext length
    bool pending = false;        // True if waiting for ACK

    void clear() {
        seq_start = seq_end = frame_idx = 0;
        send_tsc = 0;
        plaintext_len = 0;
        pending = false;
    }
};

// ============================================================================
// ZeroCopyRetransmitQueue - Circular queue of unacked segments
// Maps TCP sequence numbers to UMEM frame positions for retransmission
// "ZeroCopy" emphasizes that we store references (frame indices), not data copies
// ============================================================================

class ZeroCopyRetransmitQueue {
public:
    static constexpr size_t MAX_SEGMENTS = MSG_FRAMES;  // Match TX frame pool size
    static constexpr uint64_t DEFAULT_RTO_US = 200000;  // 200ms initial RTO
    static constexpr uint8_t MAX_RETRANSMITS = 5;       // Connection dead after this many retries

    ZeroCopyRetransmitQueue() = default;

    // Push a new segment reference onto the queue
    // Returns false if queue is full
    bool push(const RetransmitSegmentRef& ref) {
        size_t next_tail = (tail_ + 1) % MAX_SEGMENTS;
        if (next_tail == head_) {
            return false;  // Queue full
        }
        segments_[tail_] = ref;
        tail_ = next_tail;
        count_++;
        return true;
    }

    // Pop the oldest segment from the queue
    bool pop() {
        if (head_ == tail_) {
            return false;  // Queue empty
        }
        head_ = (head_ + 1) % MAX_SEGMENTS;
        count_--;
        return true;
    }

    // Peek at the oldest segment
    RetransmitSegmentRef* front() {
        if (head_ == tail_) {
            return nullptr;
        }
        return &segments_[head_];
    }

    bool empty() const { return head_ == tail_; }
    size_t size() const { return count_; }

    // Process cumulative ACK: Remove all segments with seq_end <= ack_seq
    // Returns the highest alloc_pos that was ACKed (for frame release)
    uint64_t ack_up_to(uint32_t ack_seq) {
        uint64_t highest_acked_pos = 0;

        while (head_ != tail_) {
            RetransmitSegmentRef& seg = segments_[head_];

            // TCP sequence comparison with wraparound
            int32_t diff = static_cast<int32_t>(ack_seq - seg.seq_end);
            if (diff >= 0) {
                // This segment is fully ACKed
                if (seg.alloc_pos + 1 > highest_acked_pos) {
                    highest_acked_pos = seg.alloc_pos + 1;
                }
                head_ = (head_ + 1) % MAX_SEGMENTS;
                count_--;
            } else {
                // This segment not fully ACKed, stop here
                break;
            }
        }

        return highest_acked_pos;
    }

    // Iterate ALL expired segments via lambda callback (zero allocation)
    // Lambda signature: bool(RetransmitSegmentRef& seg) - return false to stop iteration
    // Returns number of segments processed
    template<typename Func>
    size_t for_each_expired(uint64_t now_tsc, uint64_t rto_cycles, Func&& callback) {
        if (head_ == tail_) {
            return 0;
        }

        size_t processed = 0;
        size_t idx = head_;
        size_t remaining = count_;

        while (remaining > 0) {
            RetransmitSegmentRef& seg = segments_[idx];
            if (now_tsc - seg.send_tsc >= rto_cycles) {
                if (!callback(seg)) {
                    break;  // Callback requested stop (e.g., RAW_OUTBOX full)
                }
                processed++;
            }
            idx = (idx + 1) % MAX_SEGMENTS;
            remaining--;
        }
        return processed;
    }

    // Mark specific segment as retransmitted (by seq_start)
    // Updates send_tsc and increments retransmit_count
    void mark_retransmitted(uint32_t seq_start, uint64_t now_tsc) {
        size_t idx = head_;
        size_t remaining = count_;
        while (remaining > 0) {
            if (segments_[idx].seq_start == seq_start) {
                segments_[idx].send_tsc = now_tsc;
                segments_[idx].retransmit_count++;
                return;
            }
            idx = (idx + 1) % MAX_SEGMENTS;
            remaining--;
        }
    }

    // Clear the queue
    void clear() {
        head_ = 0;
        tail_ = 0;
        count_ = 0;
    }

private:
    RetransmitSegmentRef segments_[MAX_SEGMENTS];
    size_t head_ = 0;
    size_t tail_ = 0;
    size_t count_ = 0;
};

// ============================================================================
// DebugPacketHistory - Ring buffer for retransmit detection via timestamp
// Only has storage when Enabled=true - zero memory overhead when disabled
// ============================================================================

template<bool Enabled>
struct DebugPacketHistory {
    // Empty when disabled - takes no space
    void record([[maybe_unused]] uint32_t seq, [[maybe_unused]] uint32_t tsval) {}
    bool is_retransmit([[maybe_unused]] uint32_t new_seq, [[maybe_unused]] uint32_t new_tsval) const { return false; }
};

template<>
struct DebugPacketHistory<true> {
    struct PacketRecord {
        uint32_t seq = 0;
        uint32_t tsval = 0;
        bool valid = false;
    };
    static constexpr size_t kSize = 16;
    PacketRecord history[kSize] = {};
    size_t idx = 0;

    void record(uint32_t seq, uint32_t tsval) {
        auto& slot = history[idx];
        slot.seq = seq;
        slot.tsval = tsval;
        slot.valid = true;
        idx = (idx + 1) % kSize;
    }

    // Check if incoming packet is a retransmit based on timestamp comparison
    // Logic: if saved_packet.seq >= new_packet.seq && saved_packet.tsval < new_packet.tsval
    // This detects when:
    // - A packet covers sequence numbers we've seen before (saved.seq >= new.seq)
    // - But has a newer timestamp (saved.tsval < new.tsval)
    // - Meaning: the sender retransmitted this segment
    bool is_retransmit(uint32_t new_seq, uint32_t new_tsval) const {
        for (size_t i = 0; i < kSize; ++i) {
            if (!history[i].valid) continue;
            if (history[i].seq >= new_seq && history[i].tsval < new_tsval) {
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// TransportProcess - SSL/TCP handler with zero-copy packet I/O
//
// Responsibilities:
// 1. RX: RAW_INBOX → TCP parse → BIO_write → SSL_read → MSG_INBOX
// 2. TX: MSG_OUTBOX → WS header → SSL_write → RAW_OUTBOX
// 3. ACK: Adaptive ACK (pkts >= 8 OR timeout >= 100us)
// 4. Retransmit: Check timeout, re-queue unacked segments
// 5. PONG: Encrypt pending PONGs during idle time
//
// Timestamp Tracking:
// - first_nic_timestamp_ns_: NIC timestamp of first packet since last SSL_read
// - latest_nic_timestamp_ns_: NIC timestamp of most recent packet
// - Timestamps published to MSG_METADATA_INBOX for downstream latency calc
// ============================================================================

/**
 * TransportProcess - SSL/TCP layer with zero-copy I/O
 *
 * Template parameters:
 *   SSLPolicy       - SSL policy class (OpenSSLPolicy, LibreSSLPolicy, WolfSSLPolicy, or NoSSLPolicy)
 *                     Must provide: append_encrypted_view(), read(), write(), set_encrypted_output(), encrypted_output_len()
 *   RawInboxCons    - IPCRingConsumer<UMEMFrameDescriptor>
 *   RawOutboxProd   - IPCRingProducer<UMEMFrameDescriptor>
 *   AckOutboxProd   - IPCRingProducer<AckDescriptor>
 *   PongOutboxProd  - IPCRingProducer<PongDescriptor>
 *   MsgOutboxCons   - IPCRingConsumer<MsgOutboxEvent>
 *   MsgMetadataProd - IPCRingProducer<MsgMetadata>
 *   PongsCons       - IPCRingConsumer<PongFrameAligned>
 *   Profiling       - Enable cycle profiling (default false)
 *   TCPTimestampEnabled - Enable TCP Timestamps RFC 7323 (default true, like Linux kernel)
 */
template<typename SSLPolicy,
         typename RawInboxCons,
         typename RawOutboxProd,
         typename AckOutboxProd,
         typename PongOutboxProd,
         typename MsgOutboxCons,
         typename MsgMetadataProd,
         typename PongsCons,
         bool Profiling = false,
         bool TCPTimestampEnabled = true,  // RFC 7323 TCP Timestamps (default enabled like kernel)
         bool DebugTCP = false,            // Debug mode for retransmit detection via timestamps
         uint32_t TcpDelackNum = 2,        // ACK after N packets received
         uint32_t TcpDelackMinMs = 40,     // Minimum delay before ACK (ms)
         uint32_t TcpDelackMaxMs = 200>    // Maximum delay before forced ACK (ms)
struct TransportProcess {
    static constexpr bool kProfiling = Profiling;
    static constexpr bool kTimestampEnabled = TCPTimestampEnabled;
    static constexpr bool kDebugTCP = DebugTCP;
    static constexpr uint32_t kTcpDelackNum = TcpDelackNum;
    static constexpr uint32_t kTcpDelackMinMs = TcpDelackMinMs;
    static constexpr uint32_t kTcpDelackMaxMs = TcpDelackMaxMs;

    // Transport phase state machine for unified main loop
    enum class TransportPhase {
        TCP_HANDSHAKE,      // Waiting for SYN-ACK, sending ACK
        TLS_HANDSHAKE,      // TLS negotiation
        RUNNING,            // Normal operation
        FINISHED            // Connection closed
    };

    // Debug printf - only prints when DebugTCP is enabled (zero overhead otherwise)
    template<typename... Args>
    static void debug_printf([[maybe_unused]] const char* fmt, [[maybe_unused]] Args&&... args) {
        if constexpr (kDebugTCP) {
            fprintf(stderr, fmt, std::forward<Args>(args)...);
        }
    }

    // Profiling helper: wraps function, measures cycles, stores result and cycles
    // Uses pointer to shared memory slot (no stack allocation)
    // Optional condition parameter: if false, skips function and records 0
    template<typename Func>
    inline auto profile_op(Func&& func, CycleSample* slot, size_t idx, bool condition = true) {
        using ReturnType = decltype(func());
        if constexpr (Profiling) {
            if (!condition) {
                slot->op_details[idx] = 0;
                slot->op_cycles[idx] = 0;
                return ReturnType{};
            }
            uint64_t start = rdtsc();
            auto result = func();
            uint64_t end = rdtsc();
            slot->op_details[idx] = static_cast<int32_t>(result);
            slot->op_cycles[idx] = static_cast<int32_t>(end - start);
            return result;
        } else {
            if (!condition) return ReturnType{};
            return func();
        }
    }
    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * Initialize with handshake - performs TCP/TLS handshake (fork-first architecture)
     *
     * This is the preferred init method for fork-first architecture where:
     * 1. XDP Poll has already created XSK socket and signaled ready
     * 2. Transport performs TCP handshake + TLS handshake (if SSL policy enabled) via IPC rings
     * 3. No inherited state - all created fresh in this process
     *
     * NOTE: Transport is protocol-agnostic. Application protocol handshakes (WebSocket upgrade,
     *       HTTP, etc.) are handled by upstream processes via MSG_OUTBOX/MSG_INBOX after tls_ready.
     *
     * @param umem_area       Shared UMEM memory
     * @param frame_size      Size of each UMEM frame
     * @param target_host     Target hostname (e.g., "stream.binance.com")
     * @param target_port     Target port (e.g., 443)
     * @param raw_inbox_cons  Consumer for RAW_INBOX ring
     * @param raw_outbox_prod Producer for RAW_OUTBOX ring
     * @param ack_outbox_prod Producer for ACK_OUTBOX ring
     * @param pong_outbox_prod Producer for PONG_OUTBOX ring
     * @param msg_outbox_cons Consumer for MSG_OUTBOX ring
     * @param msg_metadata_prod Producer for MSG_METADATA ring
     * @param pongs_cons      Consumer for PONGS ring
     * @param msg_inbox       MsgInbox for decrypted data
     * @param conn_state       Shared TCP state structure
     */
    bool init_with_handshake(void* umem_area, uint32_t frame_size,
                             const char* target_host, uint16_t target_port,
                             RawInboxCons* raw_inbox_cons,
                             RawOutboxProd* raw_outbox_prod,
                             AckOutboxProd* ack_outbox_prod,
                             PongOutboxProd* pong_outbox_prod,
                             MsgOutboxCons* msg_outbox_cons,
                             MsgMetadataProd* msg_metadata_prod,
                             PongsCons* pongs_cons,
                             MsgInbox* msg_inbox,
                             ConnStateShm* conn_state) {

        umem_area_ = static_cast<uint8_t*>(umem_area);
        frame_size_ = frame_size;
        raw_inbox_cons_ = raw_inbox_cons;
        raw_outbox_prod_ = raw_outbox_prod;
        ack_outbox_prod_ = ack_outbox_prod;
        pong_outbox_prod_ = pong_outbox_prod;
        msg_outbox_cons_ = msg_outbox_cons;
        msg_metadata_prod_ = msg_metadata_prod;
        pongs_cons_ = pongs_cons;
        msg_inbox_ = msg_inbox;
        conn_state_ = conn_state;

        // Initialize timestamp tracking
        reset_timestamps();

        // Initialize retransmit queues and pre-calculate cycle thresholds
        msg_retransmit_queue_.clear();
        pong_retransmit_queue_.clear();
        last_pong_.clear();
        // Handshake buffer and RX frame tracking reset
        handshake_rx_len_ = 0;
        handshake_rx_appended_ = 0;
        uint64_t tsc_freq = conn_state_->tsc_freq_hz;
        rto_cycles_ = (ZeroCopyRetransmitQueue::DEFAULT_RTO_US * tsc_freq) / 1000000;
        // Convert delayed ACK timeouts to CPU cycles
        delack_min_cycles_ = (static_cast<uint64_t>(kTcpDelackMinMs) * tsc_freq) / 1000;
        delack_max_cycles_ = (static_cast<uint64_t>(kTcpDelackMaxMs) * tsc_freq) / 1000;
        health_interval_cycles_ = tsc_freq;  // 1 second in cycles
        health_last_cycle_ = rdtsc();

        // Initialize userspace TCP stack with local network info from shared state
        {
            char local_ip_str[16], gateway_ip_str[16], netmask_str[16];
            uint32_t local_ip_h = ntohl(conn_state_->local_ip);
            snprintf(local_ip_str, sizeof(local_ip_str), "%u.%u.%u.%u",
                     (local_ip_h >> 24) & 0xFF, (local_ip_h >> 16) & 0xFF,
                     (local_ip_h >> 8) & 0xFF, local_ip_h & 0xFF);
            // Gateway - for now assume same subnet, use local IP with .1
            // TODO: This should be read from shared state or config
            snprintf(gateway_ip_str, sizeof(gateway_ip_str), "%u.%u.%u.1",
                     (local_ip_h >> 24) & 0xFF, (local_ip_h >> 16) & 0xFF,
                     (local_ip_h >> 8) & 0xFF);
            snprintf(netmask_str, sizeof(netmask_str), "255.255.255.0");
            try {
                stack_.init(local_ip_str, gateway_ip_str, netmask_str, conn_state_->local_mac);
            } catch (const std::exception& e) {
                fprintf(stderr, "[TRANSPORT] Stack init exception: %s\n", e.what());
                return false;
            }
        }

        // Start TCP handshake (non-blocking) - sends SYN and returns immediately
        // Handshake completion (SYN-ACK recv, ACK send, TLS) happens in run() via unified loop
        if (!start_tcp_handshake(target_host, target_port)) {
            return false;
        }

        // NOTE: TCP handshake, TLS handshake, and application protocol handshakes
        // (WebSocket upgrade, HTTP, etc.) are now handled in run() via the unified main loop.
        // The handshake_tcp_ready and handshake_tls_ready flags are set as each phase completes.
        return true;
    }

    /**
     * Initialize with SSL policy that adopts externally-created SSL/BIO
     * DEPRECATED: Use init_with_handshake() for fork-first architecture
     * Used when handshake is done by HandshakeManager (legacy mode)
     * Note: ssl_handle, bio_in, bio_out types depend on SSL library:
     *       - OpenSSL: SSL*, BIO*, BIO*
     *       - WolfSSL: WOLFSSL*, nullptr, nullptr (uses memory callbacks)
     */
    [[deprecated("Use init_with_handshake() for fork-first architecture")]]
    bool init(void* umem_area, uint32_t frame_size,
              void* ssl_handle, void* bio_in, void* bio_out,
              RawInboxCons* raw_inbox_cons,
              RawOutboxProd* raw_outbox_prod,
              AckOutboxProd* ack_outbox_prod,
              PongOutboxProd* pong_outbox_prod,
              MsgOutboxCons* msg_outbox_cons,
              MsgMetadataProd* msg_metadata_prod,
              PongsCons* pongs_cons,
              MsgInbox* msg_inbox,
              ConnStateShm* conn_state) {

        umem_area_ = static_cast<uint8_t*>(umem_area);
        frame_size_ = frame_size;

        // Adopt externally-created SSL objects into our policy
        // Cast void* to appropriate types based on SSL library
#ifdef SSL_POLICY_OPENSSL
        ssl_policy_.adopt(static_cast<SSL*>(ssl_handle),
                          static_cast<BIO*>(bio_in),
                          static_cast<BIO*>(bio_out));
#elif defined(SSL_POLICY_WOLFSSL)
        ssl_policy_.adopt(static_cast<WOLFSSL*>(ssl_handle), bio_in, bio_out);
#else
        (void)ssl_handle; (void)bio_in; (void)bio_out;
#endif

        raw_inbox_cons_ = raw_inbox_cons;
        raw_outbox_prod_ = raw_outbox_prod;
        ack_outbox_prod_ = ack_outbox_prod;
        pong_outbox_prod_ = pong_outbox_prod;
        msg_outbox_cons_ = msg_outbox_cons;
        msg_metadata_prod_ = msg_metadata_prod;
        pongs_cons_ = pongs_cons;
        msg_inbox_ = msg_inbox;
        conn_state_ = conn_state;

        // Initialize timestamp tracking
        reset_timestamps();

        // Initialize retransmit queues
        msg_retransmit_queue_.clear();
        pong_retransmit_queue_.clear();
        // Calculate cycle thresholds: timeout_us * (TSC_freq_hz / 1,000,000)
        uint64_t tsc_freq = conn_state_->tsc_freq_hz;
        rto_cycles_ = (ZeroCopyRetransmitQueue::DEFAULT_RTO_US * tsc_freq) / 1000000;
        // Convert delayed ACK timeouts to CPU cycles
        delack_min_cycles_ = (static_cast<uint64_t>(kTcpDelackMinMs) * tsc_freq) / 1000;
        delack_max_cycles_ = (static_cast<uint64_t>(kTcpDelackMaxMs) * tsc_freq) / 1000;
        health_interval_cycles_ = tsc_freq;  // 1 second in cycles
        health_last_cycle_ = rdtsc();

        return true;
    }

    // ========================================================================
    // Main Loop
    // ========================================================================

    void run() {
        // Mark ourselves as ready so XDP Poll can start processing
        conn_state_->set_ready(PROC_TRANSPORT);

        // Record connection start time for duration tracking in on_finished()
        connection_start_cycle_ = rdtsc();

        uint64_t loop_id = 0;
        uint32_t loops_since_retransmit_check = 0;

        // Unified main loop - handles all phases
        while (phase_ != TransportPhase::FINISHED && conn_state_->is_running(PROC_TRANSPORT)) {
            [[maybe_unused]] uint64_t loop_start = 0;
            [[maybe_unused]] CycleSample* slot = nullptr;
            if constexpr (Profiling) {
                loop_start = rdtsc();
                oldest_poll_cycle_ = UINT64_MAX;      // Reset for this iteration
                oldest_nic_timestamp_ns_ = 0;         // Reset for this iteration
                oldest_transport_poll_cycle_ = 0;     // Reset for this iteration
                slot = profiling_data_->next_slot();
            }

            // Phase-specific processing
            if (phase_ == TransportPhase::TCP_HANDSHAKE ||
                phase_ == TransportPhase::TLS_HANDSHAKE) {
                // Handshake phase: only RX processing and timeout check
                [[maybe_unused]] int32_t rx_count = process_rx_unified();

                // Check for timeout
                if (check_handshake_timeout()) {
                    on_finished(false);
                    break;
                }

                // Profiling: record handshake loop
                if constexpr (Profiling) {
                    slot->packet_nic_ns = 0;
                    slot->nic_poll_cycle = 0;
                    slot->transport_poll_cycle = 0;
                    profiling_data_->commit();
                }

                loop_id++;
                continue;  // Skip normal processing during handshake
            }

            // RUNNING phase: normal operation
            // 0. TX MSG
            int32_t msg_count = profile_op(
                [this]{ return static_cast<int32_t>(process_outbound<TxType::MSG>()); }, slot, 0);

            // 1. RX (use unified RX that routes to normal processing)
            int32_t rx_count = profile_op(
                [this]{ return static_cast<int32_t>(process_rx_unified()); }, slot, 1);

            bool data_moved = (msg_count > 0) || (rx_count > 0);

            // 2. Deferred ACK (idle only) - send ACK/SACK if we saw DUP or OOO packets
            profile_op([this]{
                // OOO/DUP: immediate ACK (RFC requirement)
                if (seen_dup_packet_ || seen_ooo_packet_) {
                    send_ack();  // Includes SACK automatically when OOO exists (RFC 5681)
                    seen_dup_packet_ = false;
                    seen_ooo_packet_ = false;
                    has_unacked_packets_ = false;
                    return true;
                }
                // Normal path: delayed ACK with packet count and min/max timeout
                if (has_unacked_packets_) {
                    // Check timeout every 1024 iterations (avoid rdtsc() overhead)
                    if ((++idle_loop_counter_ & 0x3FF) == 0) {
                        uint64_t now = rdtsc();
                        uint64_t elapsed = now - first_unacked_cycle_;

                        // Force ACK after max timeout (regardless of packet count)
                        if (elapsed >= delack_max_cycles_) {
                            send_ack();
                            has_unacked_packets_ = false;
                            return true;
                        }

                        // ACK after N packets AND min timeout elapsed
                        if (packets_since_ack_ >= kTcpDelackNum && elapsed >= delack_min_cycles_) {
                            send_ack();
                            has_unacked_packets_ = false;
                            return true;
                        }
                    }
                }
                return false;
            }, slot, 2, !data_moved);

            // 3. PONG (idle only)
            profile_op(
                [this]{ return static_cast<int32_t>(process_outbound<TxType::PONG>()); },
                slot, 3, !data_moved);

            // 4-5. Retransmit check condition
            loops_since_retransmit_check++;
            bool should_check_retransmit = !data_moved || loops_since_retransmit_check >= RETRANSMIT_CHECK_INTERVAL;
            if (should_check_retransmit) {
                loops_since_retransmit_check = 0;
            }

            // 4. MSG retransmit
            profile_op(
                [this]{
                    uint64_t now_tsc = rdtsc();
                    process_retransmit_queue(msg_retransmit_queue_, FRAME_TYPE_MSG, "MSG", now_tsc);
                    return 1;  // Indicate it ran
                }, slot, 4, should_check_retransmit);

            // 5. PONG retransmit
            profile_op(
                [this]{
                    uint64_t now_tsc = rdtsc();
                    process_retransmit_queue(pong_retransmit_queue_, FRAME_TYPE_PONG, "PONG", now_tsc);
                    return 1;  // Indicate it ran
                }, slot, 5, should_check_retransmit);

            // Record sample - write directly to shared memory slot
            if constexpr (Profiling) {
                slot->packet_nic_ns = oldest_nic_timestamp_ns_;
                slot->nic_poll_cycle = oldest_poll_cycle_ == UINT64_MAX ? 0 : oldest_poll_cycle_;
                slot->transport_poll_cycle = oldest_transport_poll_cycle_;
                profiling_data_->commit();
            }

            // Periodic connection health summary (every 1 second)
            {
                uint64_t now = rdtsc();
                if (now - health_last_cycle_ >= health_interval_cycles_) {
                    // Calculate elapsed seconds since connection start
                    uint64_t elapsed_cycles = now - connection_start_cycle_;
                    int64_t elapsed_s = static_cast<int64_t>(elapsed_cycles / conn_state_->tsc_freq_hz);

                    // Get current state from rings
                    int64_t meta_prod = msg_metadata_prod_->published_sequence();
                    int64_t pongs_prod = pongs_cons_->published_sequence();  // pings received
                    int64_t pongs_cons = pongs_cons_->sequence();            // pongs sent
                    int64_t raw_inbox_prod = raw_inbox_cons_->published_sequence();
                    int64_t ack_prod = ack_outbox_prod_->published_sequence();
                    int64_t pong_outbox_prod = pong_outbox_prod_->published_sequence();

                    // Change detection - only print if something interesting changed
                    bool changed = (meta_prod != last_health_.meta_prod ||
                                    pongs_prod != last_health_.pongs_prod ||
                                    pongs_cons != last_health_.pongs_cons ||
                                    health_rx_frames_ != last_health_.rx_frames ||
                                    health_tx_frames_ != last_health_.tx_frames ||
                                    health_ooo_packets_ != last_health_.ooo_packets ||
                                    health_dup_packets_ != last_health_.dup_packets ||
                                    health_retransmits_ != last_health_.retransmits ||
                                    conn_state_->rcv_nxt != last_health_.rcv_nxt ||
                                    conn_state_->snd_nxt != last_health_.snd_nxt ||
                                    conn_state_->snd_una != last_health_.snd_una ||
                                    ooo_buffer_.count() != last_health_.ooo_count ||
                                    msg_retransmit_queue_.size() != last_health_.msg_rtx_size ||
                                    pong_retransmit_queue_.size() != last_health_.pong_rtx_size ||
                                    raw_inbox_prod != last_health_.raw_inbox_prod ||
                                    ack_prod != last_health_.ack_prod ||
                                    pong_outbox_prod != last_health_.pong_outbox_prod);

                    if (changed) {
                        // Calculate derived values
                        int64_t trades = meta_prod + 1;       // 0-based seq, so +1 for count
                        int64_t pings = pongs_prod + 1;       // pings received (producer to PONG ring)
                        int64_t pong_deficit = pings - (pongs_cons + 1);  // pings - pongs sent

                        // Print consolidated status in table format
                        fprintf(stderr, "\n[TRANSPORT] Status @%lds\n", elapsed_s);
                        fprintf(stderr, "┌─────────────────────────────────────────────────────────────┐\n");
                        fprintf(stderr, "│ trades=%-12ld pings=%-12ld pong_deficit=%-5ld%s│\n",
                                trades, pings, pong_deficit,
                                pong_deficit > 0 ? "!" : " ");
                        fprintf(stderr, "│ rcv_nxt=%-10u snd_nxt=%-10u snd_una=%-10u │\n",
                                conn_state_->rcv_nxt, conn_state_->snd_nxt, conn_state_->snd_una);
                        fprintf(stderr, "│ peer_wnd=%-10u (scale=%u, eff=%uK)                     │\n",
                                conn_state_->peer_recv_window,
                                conn_state_->window_scale,
                                conn_state_->peer_recv_window / 1024);
                        fprintf(stderr, "├──────────┬──────────┬──────────┬──────────┬─────────────────┤\n");
                        fprintf(stderr, "│ RX=%-5lu │ TX=%-5lu │ OOO=%-4lu │ DUP=%-4lu │ RTX=%-10lu │\n",
                                health_rx_frames_, health_tx_frames_,
                                health_ooo_packets_, health_dup_packets_, health_retransmits_);
                        fprintf(stderr, "├──────────┴──────────┴──────────┴──────────┴─────────────────┤\n");
                        fprintf(stderr, "│ ooo_buf=%zu/%-9zu rtx_queue: MSG=%-4zu PONG=%-4zu          │\n",
                                ooo_buffer_.count(), ooo_buffer_.max_segments(),
                                msg_retransmit_queue_.size(), pong_retransmit_queue_.size());
                        fprintf(stderr, "├─────────────────────────────────────────────────────────────┤\n");
                        fprintf(stderr, "│ RAW_IN(%ld/%ld)  ACK(%ld/%ld)  PONG(%ld/%ld)  META(%ld/%ld) │\n",
                                raw_inbox_cons_->sequence(), raw_inbox_prod,
                                ack_outbox_prod_->consumer_sequence(), ack_prod,
                                pongs_cons, pongs_prod,
                                msg_metadata_prod_->consumer_sequence(), meta_prod);
                        fprintf(stderr, "└─────────────────────────────────────────────────────────────┘\n");

                        // Update last state
                        last_health_.meta_prod = meta_prod;
                        last_health_.pongs_prod = pongs_prod;
                        last_health_.pongs_cons = pongs_cons;
                        last_health_.rx_frames = health_rx_frames_;
                        last_health_.tx_frames = health_tx_frames_;
                        last_health_.ooo_packets = health_ooo_packets_;
                        last_health_.dup_packets = health_dup_packets_;
                        last_health_.retransmits = health_retransmits_;
                        last_health_.rcv_nxt = conn_state_->rcv_nxt;
                        last_health_.snd_nxt = conn_state_->snd_nxt;
                        last_health_.snd_una = conn_state_->snd_una;
                        last_health_.ooo_count = ooo_buffer_.count();
                        last_health_.msg_rtx_size = msg_retransmit_queue_.size();
                        last_health_.pong_rtx_size = pong_retransmit_queue_.size();
                        last_health_.raw_inbox_prod = raw_inbox_prod;
                        last_health_.ack_prod = ack_prod;
                        last_health_.pong_outbox_prod = pong_outbox_prod;
                    }

                    // Reset interval counters
                    health_rx_frames_ = 0;
                    health_tx_frames_ = 0;
                    health_ooo_packets_ = 0;
                    health_dup_packets_ = 0;
                    health_retransmits_ = 0;
                    health_last_cycle_ = now;
                }
            }

            loop_id++;
        }

        // Loop exited - running flag was set to false (e.g., WS CLOSE, external shutdown)
        // Call on_finished() to perform graceful teardown
        on_finished(true);
    }

    // ========================================================================
    // RX Path
    // ========================================================================

    /**
     * Unified RX processing for all phases (handshake and normal operation)
     * Routes packets to handshake_packet_recv() or normal process_rx() based on phase
     *
     * @return Number of frames processed
     */
    uint32_t process_rx_unified() {
        if (phase_ == TransportPhase::TCP_HANDSHAKE ||
            phase_ == TransportPhase::TLS_HANDSHAKE) {
            // Handshake phase: process packets via handshake handler
            uint32_t rx_count = 0;

            raw_inbox_cons_->process_manually(
                [&](UMEMFrameDescriptor& desc, [[maybe_unused]] int64_t seq) -> bool {
                    rx_count++;
                    uint8_t* frame = umem_area_ + desc.frame_ptr;
                    return handshake_packet_recv(frame, desc.frame_len, desc);
                }, 16);  // Process up to 16 frames per call

            raw_inbox_cons_->commit_manually();
            return rx_count;

        } else if (phase_ == TransportPhase::RUNNING) {
            // Normal operation: use regular process_rx()
            return process_rx();
        }

        return 0;  // FINISHED or other state
    }

    /**
     * Check handshake timeout
     * @return true if handshake has timed out, false otherwise
     */
    bool check_handshake_timeout() {
        if (phase_ != TransportPhase::TCP_HANDSHAKE &&
            phase_ != TransportPhase::TLS_HANDSHAKE) {
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - handshake_start_time_).count();

        int timeout_ms = (phase_ == TransportPhase::TCP_HANDSHAKE)
            ? TCP_HANDSHAKE_TIMEOUT_MS
            : TLS_HANDSHAKE_TIMEOUT_MS;

        if (elapsed >= timeout_ms) {
            fprintf(stderr, "[TRANSPORT] %s handshake timeout after %lldms\n",
                    phase_ == TransportPhase::TCP_HANDSHAKE ? "TCP" : "TLS",
                    static_cast<long long>(elapsed));
            phase_ = TransportPhase::FINISHED;
            return true;
        }

        return false;
    }

    uint32_t process_rx() {
        uint32_t rx_count = 0;
        uint32_t payload_frames = 0;  // Frames with payload (added to SSL view ring)
        bool out_of_order = false;

        // Use process_manually() with lambda for batched processing
        // This is the disruptor pattern: process batch, then commit_manually()
        raw_inbox_cons_->process_manually(
            [&](UMEMFrameDescriptor& desc, int64_t seq) -> bool {
                rx_count++;
                // Capture Transport timestamp immediately
                uint64_t raw_poll_cycle = rdtscp();

                // Update timestamp tracking (first and latest for batch analysis)
                if (!has_pending_timestamps_) {
                    first_nic_timestamp_ns_ = desc.nic_timestamp_ns;
                    first_nic_frame_poll_cycle_ = desc.nic_frame_poll_cycle;  // XDP Poll timestamp
                    first_raw_frame_poll_cycle_ = raw_poll_cycle;  // Transport timestamp of first packet
                    has_pending_timestamps_ = true;
                }
                latest_nic_timestamp_ns_ = desc.nic_timestamp_ns;
                latest_nic_frame_poll_cycle_ = desc.nic_frame_poll_cycle;  // XDP Poll timestamp
                latest_raw_frame_poll_cycle_ = raw_poll_cycle;  // Transport timestamp of latest packet

                // Track oldest event by nic_frame_poll_cycle (for profiling)
                // Use the frame with the smallest XDP poll cycle as the "oldest"
                // This captures NIC->XDP->Transport latency chain for that event
                if constexpr (Profiling) {
                    if (desc.nic_frame_poll_cycle > 0 && desc.nic_frame_poll_cycle < oldest_poll_cycle_) {
                        oldest_poll_cycle_ = desc.nic_frame_poll_cycle;
                        oldest_nic_timestamp_ns_ = desc.nic_timestamp_ns;
                        oldest_transport_poll_cycle_ = raw_poll_cycle;
                    } else if (oldest_transport_poll_cycle_ == 0) {
                        // Fallback: if no valid nic_frame_poll_cycle yet, still capture transport cycle
                        oldest_poll_cycle_ = desc.nic_frame_poll_cycle;
                        oldest_nic_timestamp_ns_ = desc.nic_timestamp_ns;
                        oldest_transport_poll_cycle_ = raw_poll_cycle;
                    }
                }

                // Parse TCP using TCPPacket::parse directly (we have all params in conn_state_)
                // Note: conn_state_ stores IPs in network byte order, parse() expects host byte order
                uint8_t* frame = umem_area_ + desc.frame_ptr;
                auto parsed = userspace_stack::TCPPacket::parse(
                    frame, desc.frame_len,
                    ntohl(conn_state_->local_ip),
                    conn_state_->local_port,
                    ntohl(conn_state_->remote_ip),
                    conn_state_->remote_port);

                // Debug: Print UMEM frame ID on Transport RX
                uint32_t umem_frame_id = static_cast<uint32_t>(desc.frame_ptr / frame_size_);
                if (!parsed.valid) {
                    fprintf(stderr, "[TRANSPORT-RX] umem_id=%u INVALID slot=%ld\n",
                            umem_frame_id, seq);
                    return true;
                }

                // Log received packet with wall-clock time, seq, ack, flags, len, window for tcpdump comparison
                // Window is raw value; multiply by 2^window_scale for effective window
                if constexpr (kDebugTCP) {
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    struct tm tm_info;
                    localtime_r(&ts.tv_sec, &tm_info);
                    fprintf(stderr, "[TRANSPORT-RX-DATA] %02d:%02d:%02d.%06ld seq=%u ack=%u flags=0x%02x win=%u payload=%zu len=%u\n",
                            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                            parsed.seq, parsed.ack, parsed.flags, parsed.window, parsed.payload_len, desc.frame_len);
                    // Full frame hex dump for tcpdump comparison
                    fprintf(stderr, "[TRANSPORT-RX-DATA-HEX] ");
                    for (uint16_t i = 0; i < desc.frame_len; i++) {
                        fprintf(stderr, "%02x ", frame[i]);
                    }
                    fprintf(stderr, "\n");
                    fflush(stderr);
                }

                // DEBUG: Retransmit detection via TCP timestamp comparison (RFC 7323 PAWS)
                // Only enabled when DebugTCP=true - zero overhead otherwise
                if constexpr (kDebugTCP) {
                    if (conn_state_->timestamp_enabled && parsed.payload_len > 0) {
                        uint8_t* frame = umem_area_ + desc.frame_ptr;
                        auto ts_result = parse_timestamp_option(frame, desc.frame_len);
                        if (ts_result.found) {
                            // Check BEFORE recording (compare against previous packets)
                            bool is_retransmit = debug_packet_history_.is_retransmit(parsed.seq, ts_result.ts_val);

                            if (is_retransmit) {
                                debug_printf("[TRANSPORT] TCP RETRANSMIT-DETECTED seq=%u len=%zu tsval=%u\n",
                                             parsed.seq, parsed.payload_len, ts_result.ts_val);
                            }

                            // Record AFTER check (to compare against previous packets only)
                            debug_packet_history_.record(parsed.seq, ts_result.ts_val);
                        }
                    }
                }

                // DEBUG: Print TCP flags for debugging stuck connection
                if (parsed.flags & userspace_stack::TCP_FLAG_FIN) {
                    // Enhanced FIN logging with OOO context
                    fprintf(stderr, "\n");
                    fprintf(stderr, "╔══════════════════════════════════════════════════════════════════╗\n");
                    fprintf(stderr, "║  [TRANSPORT] TCP FIN RECEIVED                                    ║\n");
                    fprintf(stderr, "╠══════════════════════════════════════════════════════════════════╣\n");
                    fprintf(stderr, "║  FIN seq=%u ack=%u len=%zu                        \n",
                            parsed.seq, parsed.ack, parsed.payload_len);
                    fprintf(stderr, "║  rcv_nxt=%u gap=%d bytes                          \n",
                            conn_state_->rcv_nxt,
                            static_cast<int32_t>(parsed.seq - conn_state_->rcv_nxt));
                    fprintf(stderr, "║  OOO buffer: count=%zu/%zu has_ext_id=%s           \n",
                            ooo_buffer_.count(), ooo_buffer_.max_segments(),
                            ooo_buffer_.has_ext_id_segments() ? "yes" : "no");
                    if (ooo_buffer_.count() > 0) {
                        fprintf(stderr, "║  OOO min_ext_id=%ld (packets held in OOO buffer)    \n",
                                ooo_buffer_.min_ext_id());
                    }
                    fprintf(stderr, "║  NOTE: If gap > 0, FIN arrived out-of-order!                     ║\n");
                    fprintf(stderr, "║        Missing data between rcv_nxt and FIN may contain          ║\n");
                    fprintf(stderr, "║        WebSocket CLOSE frame with actual close reason.           ║\n");
                    fprintf(stderr, "╚══════════════════════════════════════════════════════════════════╝\n");

                    // Trigger graceful shutdown, send our FIN back
                    on_finished(true);
                }
                if (parsed.flags & userspace_stack::TCP_FLAG_RST) {
                    fprintf(stderr, "[TRANSPORT] TCP RST received from server! seq=%u\n", parsed.seq);
                    // RST = abrupt termination, no FIN handshake needed
                    on_finished(false);
                }

                // DEBUG: Track TCP sequence gaps
                if (parsed.payload_len > 0) {
                    int32_t seq_diff = static_cast<int32_t>(parsed.seq - conn_state_->rcv_nxt);
                    if (seq_diff > 0) {
                        fprintf(stderr, "[TRANSPORT] TCP GAP! expected_seq=%u got_seq=%u gap=%d bytes\n",
                                conn_state_->rcv_nxt, parsed.seq, seq_diff);
                    } else if (seq_diff < 0) {
                        fprintf(stderr, "[TRANSPORT] TCP OVERLAP/RETRANSMIT seq=%u expected=%u overlap=%d\n",
                                parsed.seq, conn_state_->rcv_nxt, -seq_diff);
                    }
                }

                // Update TCP state from ACK
                if (parsed.flags & userspace_stack::TCP_FLAG_ACK) {
                    process_ack(parsed.ack, parsed.window);
                }

                // Check sequence number for out-of-order detection
                if (parsed.payload_len > 0) {
                    int32_t seq_diff = static_cast<int32_t>(parsed.seq - conn_state_->rcv_nxt);

                    if (seq_diff > 0) {
                        // GAP detected: segment ahead of expected

                        // Skip if we already sent an OOO ACK for this frame
                        if (desc.acked) {
                            return true;  // Continue without triggering another ACK
                        }

                        // Buffer UMEM pointer (zero-copy - frame NOT committed, UMEM stays valid)
                        // Pass ring sequence as ext_id so safe_commit_rx() knows which frames are held
                        if (!ooo_buffer_.is_buffered(parsed.seq)) {
                            bool buffered = ooo_buffer_.buffer_segment(parsed.seq,
                                                       static_cast<uint16_t>(parsed.payload_len),
                                                       reinterpret_cast<const uint8_t*>(parsed.payload),
                                                       seq);  // ext_id = ring sequence for safe commit
                            if (!buffered) {
                                fprintf(stderr, "[TRANSPORT] OOO BUFFER FULL! Dropping segment seq=%u len=%zu (buffer has %zu/%zu)\n",
                                        parsed.seq, parsed.payload_len, ooo_buffer_.count(), ooo_buffer_.max_segments());
                            } else {
                                debug_printf("[TRANSPORT-RX] OOO DETECTED @%lu: seq=%u len=%zu rcv_nxt=%u gap=%d\n",
                                             rdtsc(), parsed.seq, parsed.payload_len, conn_state_->rcv_nxt, seq_diff);
                            }
                        }
                        out_of_order = true;
                        health_ooo_packets_++;  // Track for health summary
                        desc.acked = 1;  // Mark frame so we don't send another ACK on reprocess
                        // Continue processing - UMEMs stay valid until commit_manually()
                        // Don't add to SSL view yet (stored in OOO buffer above)
                        return true;
                    } else if (seq_diff < 0) {
                        // Duplicate or overlapping segment
                        int32_t overlap = -seq_diff;
                        if (static_cast<size_t>(overlap) >= parsed.payload_len) {
                            fprintf(stderr, "[TRANSPORT] TCP FULL DUP seq=%u len=%zu (rcv_nxt=%u) - will ACK in IDLE\n",
                                    parsed.seq, parsed.payload_len, conn_state_->rcv_nxt);
                            seen_dup_packet_ = true;  // Deferred ACK in IDLE
                            // Capture DSACK info (RFC 2883)
                            dup_seq_ = parsed.seq;
                            dup_len_ = static_cast<uint16_t>(parsed.payload_len);
                            health_dup_packets_++;    // Track for health summary
                            return true;  // Entire segment is duplicate, skip
                        }
                        // Partial overlap - adjust payload
                        fprintf(stderr, "[TRANSPORT] TCP PARTIAL OVERLAP seq=%u overlap=%d new_len=%zu rcv_nxt=%u\n",
                                parsed.seq, overlap, parsed.payload_len - overlap, conn_state_->rcv_nxt);
                        parsed.payload += overlap;
                        parsed.payload_len -= overlap;
                        parsed.seq = conn_state_->rcv_nxt;
                    }
                }

                // Update rcv_nxt using actual payload length for in-order data
                uint32_t old_rcv_nxt = conn_state_->rcv_nxt;
                conn_state_->rcv_nxt += parsed.payload_len;

                // Update peer_ts_val for in-order packets only (RFC 7323 §4.1 RTTM)
                if constexpr (kTimestampEnabled) {
                    if (conn_state_->timestamp_enabled) {
                        uint8_t* frame = umem_area_ + desc.frame_ptr;
                        auto ts_result = parse_timestamp_option(frame, desc.frame_len);
                        if (ts_result.found) {
                            conn_state_->peer_ts_val = ts_result.ts_val;
                        }
                    }
                }

                fprintf(stderr, "[TRANSPORT] TCP IN-ORDER seq=%u len=%zu rcv_nxt: %u -> %u\n",
                        parsed.seq, parsed.payload_len, old_rcv_nxt, conn_state_->rcv_nxt);

                // Append encrypted view to ring buffer for SSL decryption (zero-copy: points to UMEM)
                if (parsed.payload_len > 0) {
                    if (ssl_policy_.append_encrypted_view(
                            reinterpret_cast<const uint8_t*>(parsed.payload), parsed.payload_len) != 0) {
                        fprintf(stderr, "[FATAL] SSL view ring buffer overflow - aborting\n");
                        std::abort();
                    }
                    payload_frames++;  // Track frames with payload for commit logic
                    // Only count full MSS-sized packets for delayed ACK threshold (per RFC 1122)
                    if (parsed.payload_len >= PIPELINE_TCP_MSS) {
                        packets_since_ack_++;
                    }
                    pending_packet_ct_++;  // Track packets for MsgMetadata.nic_packet_ct

                    // Track first unacked packet time for delayed ACK timeout
                    if (!has_unacked_packets_) {
                        first_unacked_cycle_ = rdtsc();
                        has_unacked_packets_ = true;
                    }

                    // Check OOO buffer for now-in-order segments
                    uint32_t rcv_nxt_before_ooo = conn_state_->rcv_nxt;
                    size_t delivered = ooo_buffer_.try_deliver(conn_state_->rcv_nxt,
                        [this](const uint8_t* data, uint16_t offset, uint16_t len) {
                            fprintf(stderr, "[TRANSPORT] OOO DELIVER: offset=%u len=%u\n", offset, len);
                            if (ssl_policy_.append_encrypted_view(data + offset, len) != 0) {
                                fprintf(stderr, "[FATAL] SSL view ring buffer overflow (OOO) - aborting\n");
                                std::abort();
                            }
                            return true;
                        });
                    if (delivered > 0) {
                        fprintf(stderr, "[TRANSPORT] OOO delivered %zu segments, rcv_nxt: %u -> %u\n",
                                delivered, rcv_nxt_before_ooo, conn_state_->rcv_nxt);
                    }
                }

                // Note: packets_since_ack_ only incremented for payload packets (above)
                // Don't ACK pure ACKs - prevents ACK storm

                // Mark frame as consumed for XDP Poll to reclaim
                desc.consumed = 1;

                return true;  // Continue processing
            });

        // CRITICAL: Read from views BEFORE commit_manually()
        // Views point to UMEM frame data. After commit, XDP Poll may reclaim frames.
        // This prevents use-after-free when XDP Poll returns frames to fill ring.
        if (rx_count > 0) {
            fprintf(stderr, "[TRANSPORT] RX: %d frames, payload_frames=%d\n", rx_count, payload_frames);
            health_rx_frames_ += rx_count;  // Track for health summary
            ssl_read_to_msg_inbox();
        }

        // Commit frames - for SSL, frames should only be released after SSL has consumed
        // For NoSSLPolicy, read() immediately consumes all data, safe to commit
        // For real SSL (TLS), we defer commit until SSL has no partial data pending
        // CRITICAL: Use safe_commit_rx() to prevent releasing frames held by OOO buffer
        if constexpr (std::is_same_v<SSLPolicy, ssl::NoSSLPolicy>) {
            // NoSSL: immediate commit (no decryption delay)
            safe_commit_rx();
        } else {
            // Real SSL: defer commit until SSL has consumed all data from frames
            rx_frames_pending_ += payload_frames;
            commit_rx_consumed();

            // FIX: Commit pure ACK frames only when no payload is pending
            // They have no payload, so no SSL decryption needed
            if (rx_frames_pending_ == 0 && rx_count > 0 && payload_frames == 0) {
                safe_commit_rx();
            }
        }

        // RFC 5681: Send immediate ACKs with SACK when OOO detected (don't wait for IDLE)
        // Fast retransmit requires 3 duplicate ACKs. Send 3 ACKs for first OOO
        // to trigger fast retransmit before any in-order packet changes ack number.
        if (out_of_order) {
            debug_printf("[TRANSPORT-TX] OOO immediate ACK @%lu rcv_nxt=%u ooo_count=%zu\n",
                         rdtsc(), conn_state_->rcv_nxt, ooo_buffer_.count());
            seen_ooo_packet_ = true;  // Mark for IDLE loop stats
            // Send 3 SACK ACKs for first OOO of a gap (triggers fast retransmit)
            // For subsequent OOO in same gap, send 1 ACK (maintains SACK info)
            size_t ack_count = (ooo_buffer_.count() == 1) ? 3 : 1;
            for (size_t i = 0; i < ack_count; i++) {
                send_ack();
            }
        }

        return rx_count;
    }

    // Helper: Safe commit that respects OOO buffer references
    // Prevents use-after-free by not releasing frames still held in OOO buffer
    void safe_commit_rx() {
        if (ooo_buffer_.has_ext_id_segments()) {
            // OOO buffer holds frame references - only commit up to min_ext_id - 1
            int64_t safe_commit = ooo_buffer_.min_ext_id() - 1;
            int64_t current_seq = raw_inbox_cons_->sequence();
            int64_t last_proc = raw_inbox_cons_->last_processed();
            fprintf(stderr, "[TRANSPORT] safe_commit_rx: min_ext_id=%ld safe_commit=%ld current_seq=%ld last_proc=%ld ooo_count=%zu\n",
                    ooo_buffer_.min_ext_id(), safe_commit, current_seq, last_proc, ooo_buffer_.count());
            if (safe_commit < current_seq) {
                fprintf(stderr, "[TRANSPORT] safe_commit_rx: BLOCKED - nothing safe to commit\n");
                return;  // Nothing safe to commit
            }
            raw_inbox_cons_->commit_up_to(safe_commit);
        } else {
            // No OOO segments - safe to commit all processed frames
            raw_inbox_cons_->commit_manually();
        }
    }

    // Helper: Commit RX frames after SSL has fully consumed from view ring
    // Only commits when SSL has no partial data pending (needs more frames to decrypt)
    void commit_rx_consumed() {
        if (rx_frames_pending_ == 0) {
            return;
        }

        // Key insight: if SSL has no partial view, it has consumed all the data
        // it can from the current frames. Safe to commit and release to XDP Poll.
        //
        // For NoSSLPolicy: read() immediately consumes all data, has_partial_view() = false
        // For real SSL: has_partial_view() = true if mid-TLS-record (needs more data)
        if (!ssl_policy_.has_partial_view()) {
            safe_commit_rx();
            rx_frames_pending_ = 0;
        }
    }

    void ssl_read_to_msg_inbox() {
        ssize_t ret;

        // ZERO-COPY: Read directly into MSG_INBOX buffer
        while (true) {
            // Get current write position and available linear space
            uint32_t write_offset = msg_inbox_->current_write_pos();
            uint32_t linear = msg_inbox_->linear_space_to_wrap();

            // Check for wrap-around before reading
            if (linear < 16384) {  // TLS record max size
                // Check if AppClient is behind before wrapping
                // This prevents silent data loss by setting dirty_flag
                uint32_t app_consumed = msg_inbox_->get_app_consumed();
                uint32_t write_pos = msg_inbox_->current_write_pos();

                // Check if AppClient is more than 50% behind using circular distance
                constexpr uint32_t BEHIND_THRESHOLD = MSG_INBOX_SIZE / 2;
                uint32_t distance = (write_pos - app_consumed) % MSG_INBOX_SIZE;
                if (distance > BEHIND_THRESHOLD) {
                    // AppClient is falling behind - set dirty_flag for metrics/debugging
                    // Continue writing (graceful degradation) rather than aborting
                    msg_inbox_->set_dirty();
                }

                // Need to wrap
                msg_inbox_->set_wrap_flag();
                msg_inbox_->reset_to_head();
                write_offset = 0;
                linear = msg_inbox_->linear_space_to_wrap();
            }

            // ZERO-COPY: SSL_read decrypts directly into MSG_INBOX
            ret = ssl_policy_.read(msg_inbox_->write_ptr(), linear);
            if (ret <= 0) break;

            fprintf(stderr, "[TRANSPORT] SSL_read: %zd bytes\n", ret);
            uint64_t ssl_read_cycle = rdtsc();
            msg_inbox_->advance_write(static_cast<uint32_t>(ret));

            // Publish metadata - FATAL if ring full
            int64_t meta_seq = msg_metadata_prod_->try_claim();
            if (meta_seq < 0) {
                fprintf(stderr, "[TRANSPORT] FATAL: MSG_METADATA full\n");
                abort();
            }

            auto& meta = (*msg_metadata_prod_)[meta_seq];
            meta.first_nic_timestamp_ns = first_nic_timestamp_ns_;
            meta.first_nic_frame_poll_cycle = first_nic_frame_poll_cycle_;
            meta.latest_nic_timestamp_ns = latest_nic_timestamp_ns_;
            meta.latest_nic_frame_poll_cycle = latest_nic_frame_poll_cycle_;
            meta.latest_raw_frame_poll_cycle = latest_raw_frame_poll_cycle_;
            meta.ssl_read_cycle = ssl_read_cycle;
            meta.msg_inbox_offset = write_offset;
            meta.decrypted_len = static_cast<uint32_t>(ret);
            meta.nic_packet_ct = pending_packet_ct_;
            msg_metadata_prod_->publish(meta_seq);

            // Reset timestamps for next batch
            reset_timestamps();
        }

        // ret == 0 means SSL shutdown (clean close_notify received)
        if (ret == 0) {
            fprintf(stderr, "\n");
            fprintf(stderr, "╔══════════════════════════════════════════════════════════════════╗\n");
            fprintf(stderr, "║  [TRANSPORT] SSL SHUTDOWN DETECTED (SSL_read returned 0)         ║\n");
            fprintf(stderr, "╠══════════════════════════════════════════════════════════════════╣\n");
            fprintf(stderr, "║  Server sent TLS close_notify alert (clean shutdown)             ║\n");
            fprintf(stderr, "║  This typically follows a WebSocket CLOSE frame.                 ║\n");
            fprintf(stderr, "╚══════════════════════════════════════════════════════════════════╝\n");

            // Trigger graceful shutdown (FIN may already be sent if TCP FIN triggered first)
            on_finished(true);
        }

        // ret < 0 with errno == EAGAIN means need more data (normal for pipeline)
        if (ret < 0 && errno != EAGAIN) {
            fprintf(stderr, "[TRANSPORT] SSL read error: %s (errno=%d)\n", strerror(errno), errno);
        } else if (ret < 0) {
            // EAGAIN - DEBUG: track how many bytes are pending in the view ring
            fprintf(stderr, "[TRANSPORT] SSL_read EAGAIN (need more data to complete TLS record)\n");
        }

        // Note: Ring buffer auto-cycles, no need to clear_encrypted_view() here
        // clear_encrypted_view() is only called on reconnection/shutdown
    }

    // ========================================================================
    // TX Path
    // ========================================================================

    // TX types for unified process_outbound<TxType>() template
    enum class TxType { MSG, PONG };

    // Unified TX processing for MSG and PONG frames
    // Uses if constexpr for compile-time type selection - no runtime overhead
    template<TxType Type>
    uint32_t process_outbound() {
        // Select consumer, producer, alloc position, and retransmit queue based on TxType
        auto& consumer = [this]() -> auto& {
            if constexpr (Type == TxType::MSG) return *msg_outbox_cons_;
            else return *pongs_cons_;
        }();
        auto& producer = [this]() -> auto& {
            if constexpr (Type == TxType::MSG) return *raw_outbox_prod_;
            else return *pong_outbox_prod_;
        }();
        auto& rtx_queue = [this]() -> ZeroCopyRetransmitQueue& {
            if constexpr (Type == TxType::MSG) return msg_retransmit_queue_;
            else return pong_retransmit_queue_;
        }();
        constexpr const char* type_name = (Type == TxType::MSG) ? "MSG" : "PONG";

        // Check how many events are available
        size_t available = consumer.available();
        if (available == 0) {
            return 0;
        }

        // BATCHING STRATEGY:
        // 1. Claim ALL available output slots upfront with try_claim_batch(N)
        // 2. Build packets directly into pre-claimed UMEM frames
        // 3. Publish in TX_BATCH_SIZE chunks via publish_batch(lo, hi)
        //
        // This enables XDP Poll to send multiple packets in a single xsk_ring_prod__submit()
        //
        // NOTE: Transport is protocol-agnostic. Input ring contains pre-framed data
        //       from upstream (e.g., WebSocket Process already built WS frames).
        //       Transport just encrypts and sends raw bytes.

        // Claim ALL available slots upfront
        auto batch_ctx = producer.try_claim_batch(available);
        if (batch_ctx.count == 0) {
            fprintf(stderr, "[TRANSPORT] FATAL: %s_OUTBOX full\n", type_name);
            std::abort();
        }

        uint32_t slot_idx = 0;
        int64_t batch_start = batch_ctx.start;
        int64_t publish_lo = batch_start;

        consumer.process_manually(
            [&, this](auto& event, int64_t seq) -> bool {
                // Get data pointer and length (different field names for MSG vs PONG)
                const uint8_t* data_ptr;
                uint32_t data_len;
                if constexpr (Type == TxType::MSG) {
                    data_ptr = event.data;
                    data_len = event.data_len;
                } else {
                    data_ptr = event.data;
                    data_len = event.data_len;
                }

                // ZERO-COPY TX: Allocate frame FIRST (need UMEM address for output buffer)
                // FrameAllocResult contains both frame_idx and alloc_pos for retransmit tracking
                FrameAllocResult alloc_result;
                if constexpr (Type == TxType::MSG) {
                    alloc_result = allocate_msg_frame();
                } else {
                    alloc_result = allocate_pong_frame();
                }
                if (!alloc_result.success()) {
                    fprintf(stderr, "[TRANSPORT] FATAL: %s frame pool exhausted\n", type_name);
                    std::abort();
                }

                // Set output buffer to UMEM payload area BEFORE SSL_write
                // TCP header: 20 bytes without timestamps, 32 bytes with timestamps
                constexpr size_t TCP_HDR_LEN = kTimestampEnabled
                    ? (userspace_stack::TCP_HEADER_MIN_LEN + userspace_stack::TCP_TIMESTAMP_PADDED_LEN)
                    : userspace_stack::TCP_HEADER_MIN_LEN;
                constexpr size_t HEADER_LEN = userspace_stack::ETH_HEADER_LEN +
                                              userspace_stack::IP_HEADER_LEN +
                                              TCP_HDR_LEN;
                uint64_t umem_addr = frame_idx_to_addr(alloc_result.frame_idx, frame_size_);
                uint8_t* frame = umem_area_ + umem_addr;
                uint8_t* payload_ptr = frame + HEADER_LEN;
                size_t payload_capacity = frame_size_ - HEADER_LEN;

                // Validate message fits in single TCP segment (no fragmentation support)
                // TLS adds 21 bytes overhead: 5 (record header) + 16 (AES-GCM tag)
                size_t max_plaintext = payload_capacity - TLS13_OVERHEAD;
                if (data_len > max_plaintext) {
                    fprintf(stderr, "[FATAL] %s event too large: %u > %zu bytes\n",
                            type_name, data_len, max_plaintext);
                    std::abort();
                }

                ssl_policy_.set_encrypted_output(payload_ptr, payload_capacity);

                // Protocol-agnostic TX: SSL_write encrypts directly into UMEM
                ssize_t ret = ssl_policy_.write(data_ptr, data_len);
                if (ret <= 0) {
                    fprintf(stderr, "[TRANSPORT] FATAL: SSL_write failed for %s\n", type_name);
                    ssl_policy_.clear_encrypted_output();
                    std::abort();
                }

                // Get encrypted length and clear output buffer
                size_t encrypted_len = ssl_policy_.encrypted_output_len();
                if (encrypted_len == 0) {
                    fprintf(stderr, "[TRANSPORT] FATAL: encrypted_output_len() == 0 for %s\n", type_name);
                    std::abort();
                }
                ssl_policy_.clear_encrypted_output();

                // Build headers + add to retransmit queue
                auto [umem_addr_ret, frame_len] = prepare_encrypted_packet(
                    alloc_result.frame_idx, encrypted_len, alloc_result.alloc_pos, rtx_queue);

                // Log data packet TX with sequence info for timeline reconstruction
                uint64_t tx_cycle = rdtsc();
                fprintf(stderr, "[TRANSPORT-TX] %s DATA umem_id=%u seq=%u len=%zu\n",
                        type_name, alloc_result.frame_idx, conn_state_->snd_nxt - static_cast<uint32_t>(encrypted_len),
                        encrypted_len);

                // Track and log PONG for ACK confirmation
                if constexpr (Type == TxType::PONG) {
                    last_pong_.seq_start = conn_state_->snd_nxt - static_cast<uint32_t>(encrypted_len);
                    last_pong_.seq_end = conn_state_->snd_nxt;
                    last_pong_.send_tsc = tx_cycle;
                    last_pong_.frame_idx = alloc_result.frame_idx;
                    last_pong_.plaintext_len = data_len;
                    last_pong_.pending = true;

                    fprintf(stderr, "[PONG-TX] seq=%u-%u len=%zu umem=%u plaintext=%u (awaiting ACK >= %u)\n",
                            last_pong_.seq_start, last_pong_.seq_end, encrypted_len,
                            alloc_result.frame_idx, data_len, last_pong_.seq_end);
                }

                // Write descriptor to output ring (different descriptor types)
                int64_t out_seq = batch_start + slot_idx;
                if constexpr (Type == TxType::MSG) {
                    UMEMFrameDescriptor& desc = producer[out_seq];
                    desc.frame_ptr = umem_addr_ret;
                    desc.frame_len = frame_len;
                    desc.frame_type = FRAME_TYPE_MSG;
                    desc.nic_frame_poll_cycle = rdtsc();
                    desc.consumed = 0;
                } else {
                    UMEMFrameDescriptor& desc = producer[out_seq];
                    desc.frame_ptr = umem_addr_ret;
                    desc.frame_len = frame_len;
                    desc.frame_type = FRAME_TYPE_PONG;
                    desc.nic_timestamp_ns = 0;
                    desc.nic_frame_poll_cycle = 0;
                    desc.consumed = 0;
                }

                // Full frame hex dump with wall-clock time for tcpdump comparison
                if constexpr (kDebugTCP) {
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    struct tm tm_info;
                    localtime_r(&ts.tv_sec, &tm_info);
                    const uint8_t* frame_data = umem_area_ + umem_addr_ret;
                    const char* pkt_type = (Type == TxType::MSG) ? "MSG" : "PONG";
                    fprintf(stderr, "[TRANSPORT-TX-%s] %02d:%02d:%02d.%06ld seq=%u len=%u\n",
                            pkt_type, tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                            conn_state_->snd_nxt - static_cast<uint32_t>(encrypted_len), frame_len);
                    fprintf(stderr, "[TRANSPORT-TX-%s-HEX] ", pkt_type);
                    for (uint16_t i = 0; i < frame_len; i++) {
                        fprintf(stderr, "%02x ", frame_data[i]);
                    }
                    fprintf(stderr, "\n");
                    fflush(stderr);
                }

                slot_idx++;

                // Publish chunk when reaching TX_BATCH_SIZE
                if (slot_idx % TX_BATCH_SIZE == 0) {
                    int64_t publish_hi = batch_start + slot_idx - 1;
                    producer.publish_batch(publish_lo, publish_hi);
                    publish_lo = publish_hi + 1;
                }

                return true;  // Continue processing
            });
        consumer.commit_manually();

        // Publish any remaining packets
        if (slot_idx > 0 && slot_idx % TX_BATCH_SIZE != 0) {
            producer.publish_batch(publish_lo, batch_start + slot_idx - 1);
        }

        // Track TX frames for health summary
        if (slot_idx > 0) {
            health_tx_frames_ += slot_idx;
        }

        return slot_idx;
    }

    // Build ETH/IP/TCP packet headers and add to retransmit queue
    // Zero-copy: SSL writes encrypted data directly into UMEM frame, headers built in-place
    //
    // @param frame_idx       Pre-allocated frame index (encrypted payload already written)
    // @param encrypted_len   Length of encrypted payload already written to frame
    // @param alloc_pos       Atomic alloc position for this frame type (msg or pong)
    // @param rtx_queue       Retransmit queue for this frame type
    //
    // @return {umem_addr, frame_len} - caller writes descriptor to output ring
    std::pair<uint64_t, uint16_t> prepare_encrypted_packet(
            uint32_t frame_idx,
            size_t encrypted_len,
            uint64_t alloc_pos_val,  // The actual allocation position (pre-increment value)
            ZeroCopyRetransmitQueue& rtx_queue) {
        // HFT DESIGN DECISION: Abort on buffer full
        if (rtx_queue.size() >= ZeroCopyRetransmitQueue::MAX_SEGMENTS) {
            fprintf(stderr, "[TRANSPORT] FATAL: Retransmit queue full - increase MAX_SEGMENTS\n");
            std::abort();
        }

        // ZERO-COPY TX: Encrypted payload already written to UMEM by SSL_write
        // Just need to build headers in-place (no payload copy)
        uint64_t umem_addr = frame_idx_to_addr(frame_idx, frame_size_);
        uint8_t* frame = umem_area_ + umem_addr;

        // Build ETH/IP/TCP headers in-place (payload already at offset 54)
        auto params = build_tcp_params();
        uint32_t seq_start = params.snd_nxt;

        size_t frame_len = userspace_stack::TCPPacket::build_headers(
            frame, frame_size_, params,
            userspace_stack::TCP_FLAG_PSH | userspace_stack::TCP_FLAG_ACK,
            static_cast<size_t>(encrypted_len),
            conn_state_->local_mac, conn_state_->remote_mac,
            ip_id_++);
        if (frame_len == 0) {
            fprintf(stderr, "[TRANSPORT] FATAL: TCPPacket::build_headers() returned 0\n");
            std::abort();
        }

        uint32_t seq_end = seq_start + encrypted_len;

        // Update snd_nxt BEFORE adding to retransmit queue
        conn_state_->snd_nxt = seq_end;

        // Add to retransmit queue (alloc_pos_val is the actual frame allocation position)
        uint64_t now_tsc = rdtsc();

        RetransmitSegmentRef ref;
        ref.alloc_pos = alloc_pos_val;
        ref.send_tsc = now_tsc;
        ref.frame_idx = frame_idx;
        ref.seq_start = seq_start;
        ref.seq_end = seq_end;
        ref.frame_len = static_cast<uint16_t>(frame_len);
        ref.flags = userspace_stack::TCP_FLAG_PSH | userspace_stack::TCP_FLAG_ACK;
        ref.retransmit_count = 0;

        if (!rtx_queue.push(ref)) {
            fprintf(stderr, "[TRANSPORT] FATAL: Retransmit queue full\n");
            std::abort();
        }

        return {umem_addr, static_cast<uint16_t>(frame_len)};
    }

    // ========================================================================
    // ACK Processing
    // ========================================================================

    void process_ack(uint32_t ack_num, uint16_t window) {
        // Check if ACK advances snd_una (plain access - Transport only)
        int32_t advance = static_cast<int32_t>(ack_num - conn_state_->snd_una);
        if (advance > 0) {
            conn_state_->snd_una = ack_num;

            // Release ACKed MSG frames via retransmit queue
            // ack_up_to() removes all segments with seq_end <= ack_num
            // and returns the highest alloc_pos that was ACKed
            uint64_t msg_acked_pos = msg_retransmit_queue_.ack_up_to(ack_num);
            if (msg_acked_pos > 0) {
                // Update msg_acked_pos so XDP Poll can release frames (atomic - cross-process)
                conn_state_->tx_frame.msg_acked_pos.store(msg_acked_pos, std::memory_order_release);
            }

            // Release ACKed PONG frames via pong retransmit queue
            uint64_t pong_acked_pos = pong_retransmit_queue_.ack_up_to(ack_num);
            if (pong_acked_pos > 0) {
                // Update pong_acked_pos so XDP Poll can release frames (atomic - cross-process)
                conn_state_->tx_frame.pong_acked_pos.store(pong_acked_pos, std::memory_order_release);

                // Log PONG ACK confirmation if this ACK covers our last PONG
                if (last_pong_.pending && static_cast<int32_t>(ack_num - last_pong_.seq_end) >= 0) {
                    uint64_t now_tsc = rdtsc();
                    uint64_t rtt_cycles = now_tsc - last_pong_.send_tsc;
                    double rtt_us = static_cast<double>(rtt_cycles) * 1000000.0 / conn_state_->tsc_freq_hz;
                    fprintf(stderr, "[PONG-ACK] seq=%u-%u CONFIRMED by ack=%u rtt=%.1fus\n",
                            last_pong_.seq_start, last_pong_.seq_end, ack_num, rtt_us);
                    last_pong_.pending = false;
                }
            }
        }

        // Update peer window (plain access - Transport only)
        conn_state_->peer_recv_window = static_cast<uint32_t>(window) << conn_state_->window_scale;
    }

    void send_ack() {
        debug_printf("[TRANSPORT-TX] send_ack() called @%lu rcv_nxt=%u ooo_count=%zu\n",
                     rdtsc(), conn_state_->rcv_nxt, ooo_buffer_.count());

        uint32_t frame_idx = allocate_ack_frame();
        if (frame_idx == UINT32_MAX) {
            fprintf(stderr, "[TRANSPORT] FATAL: ACK frame pool exhausted\n");
            std::abort();
        }

        uint64_t umem_addr = frame_idx_to_addr(frame_idx, frame_size_);
        uint8_t* frame = umem_area_ + umem_addr;

        auto params = build_tcp_params();
        size_t frame_len = 0;

        // Build combined SACK block array: DSACK first (RFC 2883), then OOO blocks
        userspace_stack::SACKBlockArray sack_blocks;
        sack_blocks.count = 0;

        // Calculate max SACK blocks based on timestamp setting (compile-time + runtime)
        // params.ts_val is set by build_tcp_params() based on timestamp_enabled
        const bool ts_in_packet = (params.ts_val != 0);
        const uint8_t max_sack_blocks = ts_in_packet
            ? userspace_stack::SACK_MAX_BLOCKS_WITH_TS
            : userspace_stack::SACK_MAX_BLOCKS;

        // DSACK block (RFC 2883) - first block reports duplicate segment
        if (dup_len_ > 0) {
            sack_blocks.blocks[0].left_edge = dup_seq_;
            sack_blocks.blocks[0].right_edge = dup_seq_ + dup_len_;
            sack_blocks.count = 1;
            fprintf(stderr, "[TRANSPORT-TX] DSACK block [%u-%u] (dup below rcv_nxt=%u)\n",
                    dup_seq_, dup_seq_ + dup_len_, conn_state_->rcv_nxt);
            // Clear after use
            dup_len_ = 0;
        }

        // Regular SACK blocks from OOO buffer (RFC 2018)
        if (conn_state_->sack_enabled && !ooo_buffer_.is_empty()) {
            // Calculate remaining blocks available after DSACK
            const uint8_t remaining_blocks = max_sack_blocks - sack_blocks.count;
            userspace_stack::SACKBlockArray ooo_blocks;
            ooo_buffer_.extract_sack_blocks(conn_state_->rcv_nxt, ooo_blocks, remaining_blocks);

            // Append OOO blocks after DSACK (RFC 2018 Section 4: most recent first)
            for (uint8_t i = 0; i < ooo_blocks.count && sack_blocks.count < max_sack_blocks; i++) {
                sack_blocks.blocks[sack_blocks.count++] = ooo_blocks.blocks[i];
            }
        }

        // Build ACK with SACK/DSACK if we have blocks
        if (sack_blocks.count > 0) {
            frame_len = userspace_stack::TCPPacket::build_ack_with_sack(
                frame, frame_size_, params, sack_blocks,
                conn_state_->local_mac, conn_state_->remote_mac,
                ip_id_++);

            // sack_blocks.count is already limited to max_sack_blocks (calculated earlier)
            uint8_t actual_blocks = sack_blocks.count;
            // DEBUG: show timestamp state
            fprintf(stderr, "[DEBUG-SACK] ts_val=%u ts_enabled=%d peer_ts=%u max_blocks=%u actual=%u\n",
                    params.ts_val, conn_state_->timestamp_enabled, conn_state_->peer_ts_val,
                    max_sack_blocks, actual_blocks);

            // Dump OOO buffer FIRST so formatter sees it before SACK line
            if (!ooo_buffer_.is_empty()) {
                ooo_buffer_.debug_dump("[OOO-BUFFER]");
            }
            fprintf(stderr, "[TRANSPORT-TX] SACK ACK umem_id=%u rcv_nxt=%u blocks=%u",
                    frame_idx, params.rcv_nxt, actual_blocks);
            for (uint8_t i = 0; i < actual_blocks; i++) {
                fprintf(stderr, " [%u-%u]", sack_blocks.blocks[i].left_edge,
                        sack_blocks.blocks[i].right_edge);
            }
            fprintf(stderr, "\n");
            // Hex dump TCP options (SACK area) - starts at offset 54 (ETH+IP+TCP_MIN)
            if (frame_len > 54) {
                fprintf(stderr, "[SACK-HEX] TCP opts: ");
                for (size_t i = 54; i < frame_len && i < 54 + 40; i++) {
                    fprintf(stderr, "%02x ", frame[i]);
                }
                fprintf(stderr, "\n");
                fflush(stderr);
            }
        }

        // Fallback to regular ACK (no SACK or empty blocks)
        if (frame_len == 0) {
            frame_len = userspace_stack::TCPPacket::build(
                frame, frame_size_, params,
                userspace_stack::TCP_FLAG_ACK,
                nullptr, 0,
                conn_state_->local_mac, conn_state_->remote_mac,
                ip_id_++);
            fprintf(stderr, "[TRANSPORT-TX] ACK umem_id=%u rcv_nxt=%u\n",
                    frame_idx, params.rcv_nxt);
        }

        if (frame_len == 0) {
            fprintf(stderr, "[TRANSPORT] FATAL: TCPPacket::build() failed for ACK\n");
            std::abort();
        }

        // Publish to ACK_OUTBOX - FATAL if full
        int64_t seq = ack_outbox_prod_->try_claim();
        if (seq < 0) std::abort();  // ACK_OUTBOX full

        auto& desc = (*ack_outbox_prod_)[seq];
        desc.frame_ptr = umem_addr;
        desc.frame_len = static_cast<uint16_t>(frame_len);
        desc.frame_type = FRAME_TYPE_ACK;
        desc.nic_timestamp_ns = 0;
        desc.nic_frame_poll_cycle = 0;
        desc.consumed = 0;
        ack_outbox_prod_->publish(seq);

        // Full frame hex dump with wall-clock time for tcpdump comparison
        if constexpr (kDebugTCP) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            struct tm tm_info;
            localtime_r(&ts.tv_sec, &tm_info);
            fprintf(stderr, "[TRANSPORT-TX-ACK] %02d:%02d:%02d.%06ld seq=%u ack=%u flags=0x10 win=%u len=%zu\n",
                    tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                    params.snd_nxt, params.rcv_nxt, params.rcv_wnd, frame_len);
            fprintf(stderr, "[TRANSPORT-TX-ACK-HEX] ");
            for (size_t i = 0; i < frame_len; i++) {
                fprintf(stderr, "%02x ", frame[i]);
            }
            fprintf(stderr, "\n");
            fflush(stderr);
        }

        // Reset ACK timing (flags are managed by IDLE loop)
        packets_since_ack_ = 0;
        last_ack_cycle_ = rdtsc();
    }

    // ========================================================================
    // Connection Teardown
    // ========================================================================

    /**
     * Send TCP FIN+ACK packet to complete the 4-way handshake.
     * Uses ACK frame pool and ACK_OUTBOX (same path as regular ACKs).
     * FIN consumes 1 sequence number.
     */
    void send_tcp_fin() {
        uint32_t frame_idx = allocate_ack_frame();
        if (frame_idx == UINT32_MAX) {
            fprintf(stderr, "[TRANSPORT] WARNING: Cannot send FIN - ACK frame pool exhausted\n");
            return;
        }

        uint64_t umem_addr = frame_idx_to_addr(frame_idx, frame_size_);
        uint8_t* frame = umem_area_ + umem_addr;

        auto params = build_tcp_params();

        // Build FIN+ACK packet
        size_t frame_len = userspace_stack::TCPPacket::build(
            frame, frame_size_, params,
            userspace_stack::TCP_FLAG_FIN | userspace_stack::TCP_FLAG_ACK,
            nullptr, 0,
            conn_state_->local_mac, conn_state_->remote_mac,
            ip_id_++);

        if (frame_len == 0) {
            fprintf(stderr, "[TRANSPORT] WARNING: TCPPacket::build() failed for FIN\n");
            return;
        }

        // FIN consumes 1 sequence number
        conn_state_->snd_nxt++;

        // Publish to ACK_OUTBOX
        int64_t seq = ack_outbox_prod_->try_claim();
        if (seq < 0) {
            fprintf(stderr, "[TRANSPORT] WARNING: Cannot send FIN - ACK_OUTBOX full\n");
            return;
        }

        auto& desc = (*ack_outbox_prod_)[seq];
        desc.frame_ptr = umem_addr;
        desc.frame_len = static_cast<uint16_t>(frame_len);
        desc.frame_type = FRAME_TYPE_ACK;
        desc.nic_timestamp_ns = 0;
        desc.nic_frame_poll_cycle = 0;
        desc.consumed = 0;
        ack_outbox_prod_->publish(seq);

        fprintf(stderr, "[TRANSPORT-TX] FIN+ACK umem_id=%u seq=%u ack=%u\n",
                frame_idx, params.snd_nxt, params.rcv_nxt);
    }

    /**
     * Handle graceful connection teardown.
     * Called when server sends TCP FIN or TLS close_notify.
     * Logs connection duration, optionally sends FIN, and signals all processes to stop.
     *
     * @param send_fin If true, send TCP FIN to complete 4-way handshake
     */
    void on_finished(bool send_fin = false) {
        // Prevent double-invocation (FIN and close_notify often arrive together)
        if (finished_called_) return;
        finished_called_ = true;

        // Calculate connection duration
        uint64_t now_cycle = rdtsc();
        uint64_t duration_cycles = now_cycle - connection_start_cycle_;
        double duration_sec = static_cast<double>(duration_cycles) / conn_state_->tsc_freq_hz;

        fprintf(stderr, "\n");
        fprintf(stderr, "╔══════════════════════════════════════════════════════════════════╗\n");
        fprintf(stderr, "║  [TRANSPORT] on_finished() - Connection teardown initiated       ║\n");
        fprintf(stderr, "╠══════════════════════════════════════════════════════════════════╣\n");
        fprintf(stderr, "║  Connection duration: %.3f seconds                              \n", duration_sec);
        fprintf(stderr, "╚══════════════════════════════════════════════════════════════════╝\n");

        // Send TCP FIN to complete 4-way handshake if requested
        if (send_fin) {
            send_tcp_fin();
        }

        // Signal all processes to stop
        conn_state_->shutdown_all();
    }

    // ========================================================================
    // Retransmit
    // ========================================================================

    void process_retransmit() {
        uint64_t now_tsc = rdtsc();
        process_retransmit_queue(msg_retransmit_queue_, FRAME_TYPE_MSG, "MSG", now_tsc);
        process_retransmit_queue(pong_retransmit_queue_, FRAME_TYPE_PONG, "PONG", now_tsc);
    }

    void process_retransmit_queue(ZeroCopyRetransmitQueue& queue, uint8_t frame_type,
                                  const char* name, uint64_t now_tsc) {
        if (queue.empty()) {
            return;
        }

        // First pass: Check for any maxed-out segments (connection dead)
        // and count only retransmittable segments
        size_t expired_count = 0;
        bool has_fatal = false;
        queue.for_each_expired(now_tsc, rto_cycles_,
            [&](RetransmitSegmentRef& seg) -> bool {
                if (seg.retransmit_count >= ZeroCopyRetransmitQueue::MAX_RETRANSMITS) {
                    fprintf(stderr, "[TRANSPORT] FATAL: %s segment seq=%u exceeded max retransmits (%u)\n",
                            name, seg.seq_start, ZeroCopyRetransmitQueue::MAX_RETRANSMITS);
                    has_fatal = true;
                    return false;  // Stop counting, will shutdown
                }
                expired_count++;
                return true;
            });

        if (has_fatal) {
            // Max retransmits exceeded - connection is dead, trigger shutdown
            on_finished(false);  // No FIN needed, connection unresponsive
            return;
        }

        if (expired_count == 0) {
            return;
        }

        // Claim batch of slots for retransmits
        auto batch_ctx = raw_outbox_prod_->try_claim_batch(expired_count);
        if (batch_ctx.count == 0) {
            fprintf(stderr, "[TRANSPORT] %s Retransmit blocked: RAW_OUTBOX full\n", name);
            return;
        }

        uint32_t slot_idx = 0;
        int64_t batch_start = batch_ctx.start;
        int64_t publish_lo = batch_start;

        // Second pass: Process expired segments and write to claimed slots
        // (FATAL check already done in first pass)
        queue.for_each_expired(now_tsc, rto_cycles_,
            [&](RetransmitSegmentRef& seg) -> bool {
                if (slot_idx >= batch_ctx.count) {
                    return false;  // Stop if we've used all claimed slots
                }

                // Rebuild TCP header with current ACK number
                rebuild_tcp_header_for_retransmit(&seg);

                // Log retransmit with sequence info
                fprintf(stderr, "[TRANSPORT-TX] RETRANSMIT %s umem_id=%u seq=%u-%u len=%u attempt=%u\n",
                        name, seg.frame_idx, seg.seq_start, seg.seq_end,
                        seg.seq_end - seg.seq_start, seg.retransmit_count + 1);
                health_retransmits_++;  // Track for health summary

                // Write descriptor to pre-claimed slot
                int64_t out_seq = batch_start + slot_idx;
                UMEMFrameDescriptor& desc = (*raw_outbox_prod_)[out_seq];
                desc.frame_ptr = static_cast<uint64_t>(seg.frame_idx) * frame_size_;
                desc.frame_len = seg.frame_len;
                desc.frame_type = frame_type;
                desc.nic_timestamp_ns = 0;
                desc.nic_frame_poll_cycle = now_tsc;
                desc.consumed = 0;

                // Update retransmit state
                queue.mark_retransmitted(seg.seq_start, now_tsc);

                slot_idx++;

                // Publish chunk when reaching TX_BATCH_SIZE
                if (slot_idx % TX_BATCH_SIZE == 0) {
                    int64_t publish_hi = batch_start + slot_idx - 1;
                    raw_outbox_prod_->publish_batch(publish_lo, publish_hi);
                    publish_lo = publish_hi + 1;
                }

                return true;  // Continue processing
            });

        // Publish any remaining packets
        if (slot_idx > 0 && slot_idx % TX_BATCH_SIZE != 0) {
            raw_outbox_prod_->publish_batch(publish_lo, batch_start + slot_idx - 1);
        }
    }

    // Rebuild TCP header with current ACK number before retransmit
    // Updates: TCP ack_seq, IP id, TCP checksum, IP checksum
    void rebuild_tcp_header_for_retransmit(RetransmitSegmentRef* seg) {
        uint64_t umem_addr = static_cast<uint64_t>(seg->frame_idx) * frame_size_;
        uint8_t* frame = umem_area_ + umem_addr;

        // Get current TCP state
        auto params = build_tcp_params();

        // Get pointers to headers
        constexpr size_t ETH_LEN = userspace_stack::ETH_HEADER_LEN;
        constexpr size_t IP_LEN = userspace_stack::IP_HEADER_LEN;

        auto* ip_hdr = reinterpret_cast<userspace_stack::IPv4Header*>(frame + ETH_LEN);
        auto* tcp_hdr = reinterpret_cast<userspace_stack::TCPHeader*>(frame + ETH_LEN + IP_LEN);

        // Get actual TCP header length from doff field (handles timestamps)
        size_t tcp_hdr_len = ((tcp_hdr->doff_reserved >> 4) & 0x0F) * 4;

        // Calculate payload length from segment sequence range
        size_t payload_len = seg->seq_end - seg->seq_start;

        // Update TCP ACK number to current rcv_nxt
        tcp_hdr->ack_seq = htonl(params.rcv_nxt);

        // Update TCP timestamp if present (update ts_val for retransmit)
        if constexpr (kTimestampEnabled) {
            if (tcp_hdr_len >= userspace_stack::TCP_HEADER_MIN_LEN + userspace_stack::TCP_TIMESTAMP_PADDED_LEN) {
                // Timestamp option at offset 20 (after base header): NOP NOP TS len TSval TSecr
                uint8_t* opt = frame + ETH_LEN + IP_LEN + userspace_stack::TCP_HEADER_MIN_LEN;
                if (opt[2] == userspace_stack::TCP_OPT_TIMESTAMP) {
                    // Update TSval with fresh timestamp
                    uint32_t ts_val_n = htonl(generate_ts_val());
                    std::memcpy(&opt[4], &ts_val_n, 4);
                    // Update TSecr with latest peer timestamp
                    uint32_t ts_ecr_n = htonl(conn_state_->peer_ts_val);
                    std::memcpy(&opt[8], &ts_ecr_n, 4);
                }
            }
        }

        // Update IP ID (use fresh ID to avoid middlebox issues)
        ip_hdr->id = htons(ip_id_++);

        // Recalculate TCP checksum (ACK number and possibly timestamp changed)
        tcp_hdr->check = 0;
        const uint8_t* payload_ptr = frame + ETH_LEN + IP_LEN + tcp_hdr_len;
        tcp_hdr->check = htons(userspace_stack::tcp_checksum(
            params.local_ip, params.remote_ip,
            tcp_hdr, tcp_hdr_len, payload_ptr, payload_len));

        // Recalculate IP checksum (IP ID changed)
        ip_hdr->check = 0;
        ip_hdr->check = htons(userspace_stack::ip_checksum(ip_hdr));
    }

    // ========================================================================
    // Frame Allocation
    // ========================================================================

    // Return type for frame allocation (frame_idx and alloc_pos for retransmit tracking)
    struct FrameAllocResult {
        uint32_t frame_idx;
        uint64_t alloc_pos;
        bool success() const { return frame_idx != UINT32_MAX; }
    };

    uint32_t allocate_ack_frame() {
        uint32_t pos = conn_state_->tx_frame.ack_alloc_pos.fetch_add(1, std::memory_order_relaxed);
        uint32_t rel = conn_state_->tx_frame.ack_release_pos.load(std::memory_order_acquire);
        if (pos - rel >= ACK_FRAMES) {
            conn_state_->tx_frame.ack_alloc_pos.fetch_sub(1, std::memory_order_relaxed);
            return UINT32_MAX;
        }
        return ACK_POOL_START + (pos % ACK_FRAMES);
    }

    FrameAllocResult allocate_pong_frame() {
        uint64_t pos = conn_state_->tx_frame.pong_alloc_pos.fetch_add(1, std::memory_order_relaxed);
        uint64_t rel = conn_state_->tx_frame.pong_release_pos.load(std::memory_order_acquire);
        if (pos - rel >= PONG_FRAMES) {
            conn_state_->tx_frame.pong_alloc_pos.fetch_sub(1, std::memory_order_relaxed);
            return {UINT32_MAX, 0};
        }
        return {static_cast<uint32_t>(PONG_POOL_START + (pos % PONG_FRAMES)), pos};
    }

    FrameAllocResult allocate_msg_frame() {
        uint64_t pos = conn_state_->tx_frame.msg_alloc_pos.fetch_add(1, std::memory_order_relaxed);
        uint64_t rel = conn_state_->tx_frame.msg_release_pos.load(std::memory_order_acquire);
        if (pos - rel >= MSG_FRAMES) {
            conn_state_->tx_frame.msg_alloc_pos.fetch_sub(1, std::memory_order_relaxed);
            return {UINT32_MAX, 0};
        }
        return {static_cast<uint32_t>(MSG_POOL_START + (pos % MSG_FRAMES)), pos};
    }

    // ========================================================================
    // TCP Timestamp Helper (RFC 7323)
    // ========================================================================

    /**
     * Generate timestamp value for TCP Timestamps option
     * Uses TSC >> 21 for ~1ms granularity (RFC 7323 recommends ~1ms)
     * 2.4GHz TSC >> 21 ≈ 1.14ms per tick
     */
    static uint32_t generate_ts_val() {
        return static_cast<uint32_t>(rdtsc() >> 21);
    }

    // ========================================================================
    // TCP Params Helper (builds TCPParams from shared state)
    // ========================================================================

    userspace_stack::TCPParams build_tcp_params() const {
        userspace_stack::TCPParams params;
        // IPs in shared state are network byte order, stack expects host byte order
        params.local_ip = ntohl(conn_state_->local_ip);
        params.remote_ip = ntohl(conn_state_->remote_ip);
        params.local_port = conn_state_->local_port;
        params.remote_port = conn_state_->remote_port;
        params.snd_nxt = conn_state_->snd_nxt;
        params.rcv_nxt = conn_state_->rcv_nxt;
        params.rcv_wnd = userspace_stack::TCP_MAX_WINDOW;  // Advertise configured window

        // Populate timestamps if enabled at compile-time AND runtime
        if constexpr (kTimestampEnabled) {
            if (conn_state_->timestamp_enabled) {
                params.ts_val = generate_ts_val();
                params.ts_ecr = conn_state_->peer_ts_val;
            }
        }
        return params;
    }

private:
    // ========================================================================
    // Handshake Helpers (fork-first architecture)
    // These methods perform TCP/TLS/WS handshake via IPC rings
    // ========================================================================

    /**
     * Perform TCP 3-way handshake via IPC rings
     * Uses UserspaceStack to build/parse packets, IPC rings for I/O
     */
    bool perform_tcp_handshake_via_ipc(const char* target_host, uint16_t target_port) {
        // Resolve hostname to IP
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int gai_ret = getaddrinfo(target_host, nullptr, &hints, &res);
        if (gai_ret != 0 || !res) {
            return false;
        }
        uint32_t remote_ip = ntohl(reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr);
        freeaddrinfo(res);

        // Initialize TCP params
        tcp_params_.remote_ip = remote_ip;
        tcp_params_.remote_port = target_port;
        tcp_params_.local_ip = ntohl(conn_state_->local_ip);
        tcp_params_.local_port = userspace_stack::UserspaceStack::generate_port();
        tcp_params_.snd_nxt = userspace_stack::UserspaceStack::generate_isn();
        tcp_params_.snd_una = tcp_params_.snd_nxt;
        tcp_params_.rcv_nxt = 0;
        tcp_params_.snd_wnd = userspace_stack::TCP_MAX_WINDOW;
        tcp_params_.rcv_wnd = userspace_stack::TCP_MAX_WINDOW;

        // Store in shared state for later use
        conn_state_->local_port = tcp_params_.local_port;
        conn_state_->remote_port = target_port;
        conn_state_->remote_ip = htonl(remote_ip);

        // Allocate frame for SYN
        auto syn_alloc = allocate_msg_frame();
        if (!syn_alloc.success()) {
            return false;
        }
        uint64_t syn_addr = frame_idx_to_addr(syn_alloc.frame_idx, frame_size_);
        uint8_t* syn_buffer = umem_area_ + syn_addr;

        // Set timestamp for SYN (ts_ecr = 0 for initial SYN per RFC 7323)
        if constexpr (kTimestampEnabled) {
            tcp_params_.ts_val = generate_ts_val();
            tcp_params_.ts_ecr = 0;
        }

        // Build SYN packet
        size_t syn_len = stack_.build_syn(syn_buffer, frame_size_, tcp_params_);
        if (syn_len == 0) {
            return false;
        }

        // Send SYN via RAW_OUTBOX
        int64_t syn_seq = raw_outbox_prod_->try_claim();
        if (syn_seq < 0) {
            return false;
        }
        auto& syn_desc = (*raw_outbox_prod_)[syn_seq];
        syn_desc.frame_ptr = syn_addr;
        syn_desc.frame_len = static_cast<uint16_t>(syn_len);
        syn_desc.frame_type = FRAME_TYPE_MSG;
        syn_desc.nic_frame_poll_cycle = rdtsc();
        syn_desc.consumed = 0;
        raw_outbox_prod_->publish(syn_seq);

        // Log SYN with wall-clock time and full TCP details
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            struct tm tm_info;
            localtime_r(&ts.tv_sec, &tm_info);
            if constexpr (kTimestampEnabled) {
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld SYN seq=%u ack=0 flags=0x02 win=%u ts_val=%u ts_ecr=0 len=%zu\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.snd_wnd, tcp_params_.ts_val, syn_len);
            } else {
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld SYN seq=%u ack=0 flags=0x02 win=%u len=%zu\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.snd_wnd, syn_len);
            }
            // Log additional fields: IP ID, checksums, source port
            if constexpr (kDebugTCP) {
                // Parse IP header fields (offset 14 = after Ethernet header)
                uint16_t ip_id = (syn_buffer[18] << 8) | syn_buffer[19];
                uint16_t ip_checksum = (syn_buffer[24] << 8) | syn_buffer[25];
                uint16_t src_port = (syn_buffer[34] << 8) | syn_buffer[35];
                uint16_t tcp_checksum = (syn_buffer[50] << 8) | syn_buffer[51];
                fprintf(stderr, "[TRANSPORT-TX-SYN-DEBUG] src_port=%u ip_id=0x%04x ip_csum=0x%04x tcp_csum=0x%04x\n",
                        src_port, ip_id, ip_checksum, tcp_checksum);
                // Full hex dump
                fprintf(stderr, "[TRANSPORT-TX-SYN-HEX] ");
                for (size_t i = 0; i < syn_len; i++) {
                    fprintf(stderr, "%02x ", syn_buffer[i]);
                }
                fprintf(stderr, "\n");
                fflush(stderr);
            }
        }
        tcp_params_.snd_nxt++;  // SYN consumes 1 seq

        // Wait for SYN-ACK via RAW_INBOX using process_manually()
        auto start = std::chrono::steady_clock::now();
        constexpr int timeout_ms = 5000;
        bool got_synack = false;

        while (!got_synack) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed >= timeout_ms) {
                return false;
            }

            raw_inbox_cons_->process_manually(
                [&](UMEMFrameDescriptor& rx_desc, int64_t) -> bool {
                    uint8_t* frame = umem_area_ + rx_desc.frame_ptr;
                    auto parsed = stack_.parse_tcp(frame, rx_desc.frame_len,
                                                   tcp_params_.local_port,
                                                   tcp_params_.remote_ip,
                                                   tcp_params_.remote_port);
                    if (parsed.valid && (parsed.flags & userspace_stack::TCP_FLAG_SYN) &&
                        (parsed.flags & userspace_stack::TCP_FLAG_ACK)) {
                        // Got SYN-ACK
                        tcp_params_.rcv_nxt = parsed.seq + 1;  // SYN consumes 1 seq
                        tcp_params_.snd_una = parsed.ack;
                        conn_state_->rcv_nxt = tcp_params_.rcv_nxt;
                        conn_state_->snd_una = tcp_params_.snd_una;
                        conn_state_->snd_nxt = tcp_params_.snd_nxt;
                        conn_state_->peer_recv_window = parsed.window;

                        // Parse TCP options for SACK_OK - MUST check before using SACK (RFC 2018)
                        conn_state_->sack_enabled = parse_sack_ok_option(frame, rx_desc.frame_len);

                        // Parse TCP options for Window Scale (RFC 7323)
                        conn_state_->window_scale = parse_window_scale_option(frame, rx_desc.frame_len);

                        // Parse TCP options for MSS (RFC 879) - server's receive MSS
                        uint16_t peer_mss = parse_mss_option(frame, rx_desc.frame_len);
                        if (peer_mss > 0) {
                            conn_state_->peer_mss = peer_mss;
                        }

                        // Parse TCP options for Timestamps (RFC 7323)
                        // Log SYN-ACK with wall-clock time and full TCP details
                        struct timespec ts;
                        clock_gettime(CLOCK_REALTIME, &ts);
                        struct tm tm_info;
                        localtime_r(&ts.tv_sec, &tm_info);
                        if constexpr (kTimestampEnabled) {
                            auto ts_result = parse_timestamp_option(frame, rx_desc.frame_len);
                            conn_state_->timestamp_enabled = ts_result.found;
                            if (ts_result.found) {
                                conn_state_->peer_ts_val = ts_result.ts_val;
                            }
                            fprintf(stderr, "[TRANSPORT-RX] %02d:%02d:%02d.%06ld SYN-ACK seq=%u ack=%u flags=0x%02x win=%u MSS=%u SACK=%s TS=%s WS=%u len=%u\n",
                                    tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                                    parsed.seq, parsed.ack, parsed.flags, parsed.window,
                                    conn_state_->peer_mss,
                                    conn_state_->sack_enabled ? "ON" : "OFF",
                                    conn_state_->timestamp_enabled ? "ON" : "OFF",
                                    conn_state_->window_scale, rx_desc.frame_len);
                        } else {
                            conn_state_->timestamp_enabled = false;
                            fprintf(stderr, "[TRANSPORT-RX] %02d:%02d:%02d.%06ld SYN-ACK seq=%u ack=%u flags=0x%02x win=%u MSS=%u SACK=%s WS=%u len=%u\n",
                                    tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                                    parsed.seq, parsed.ack, parsed.flags, parsed.window,
                                    conn_state_->peer_mss,
                                    conn_state_->sack_enabled ? "ON" : "OFF",
                                    conn_state_->window_scale, rx_desc.frame_len);
                        }
                        // Log additional fields: IP ID, checksums, source port
                        if constexpr (kDebugTCP) {
                            // Parse IP header fields (offset 14 = after Ethernet header)
                            uint16_t ip_id = (frame[18] << 8) | frame[19];
                            uint16_t ip_checksum = (frame[24] << 8) | frame[25];
                            uint16_t src_port = (frame[34] << 8) | frame[35];
                            uint16_t tcp_checksum = (frame[50] << 8) | frame[51];
                            fprintf(stderr, "[TRANSPORT-RX-SYNACK-DEBUG] src_port=%u ip_id=0x%04x ip_csum=0x%04x tcp_csum=0x%04x\n",
                                    src_port, ip_id, ip_checksum, tcp_checksum);
                            // Full hex dump
                            fprintf(stderr, "[TRANSPORT-RX-SYNACK-HEX] ");
                            for (uint16_t i = 0; i < rx_desc.frame_len; i++) {
                                fprintf(stderr, "%02x ", frame[i]);
                            }
                            fprintf(stderr, "\n");
                            fflush(stderr);
                        }

                        got_synack = true;
                    }
                    return true;  // Continue processing, commit this frame
                }, 1);  // Process one frame at a time

            // Always commit after processing - TCP handshake doesn't need SSL, safe to release UMEM
            raw_inbox_cons_->commit_manually();

            if (!got_synack) {
                usleep(100);
            }
        }

        // Send ACK to complete 3-way handshake
        uint32_t ack_frame_idx = allocate_ack_frame();
        if (ack_frame_idx == UINT32_MAX) {
            return false;
        }
        uint64_t ack_addr = frame_idx_to_addr(ack_frame_idx, frame_size_);
        uint8_t* ack_buffer = umem_area_ + ack_addr;

        // Set timestamps for ACK (echo peer's ts_val from SYN-ACK)
        if constexpr (kTimestampEnabled) {
            if (conn_state_->timestamp_enabled) {
                tcp_params_.ts_val = generate_ts_val();
                tcp_params_.ts_ecr = conn_state_->peer_ts_val;
            }
        }

        size_t ack_len = stack_.build_ack(ack_buffer, frame_size_, tcp_params_);
        if (ack_len == 0) {
            return false;
        }

        int64_t ack_seq = ack_outbox_prod_->try_claim();
        if (ack_seq < 0) {
            return false;
        }
        auto& ack_desc = (*ack_outbox_prod_)[ack_seq];
        ack_desc.frame_ptr = ack_addr;
        ack_desc.frame_len = static_cast<uint16_t>(ack_len);
        ack_desc.frame_type = FRAME_TYPE_ACK;
        ack_desc.nic_timestamp_ns = 0;
        ack_desc.nic_frame_poll_cycle = 0;
        ack_desc.consumed = 0;
        ack_outbox_prod_->publish(ack_seq);

        // Log TCP handshake ACK with wall-clock time
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            struct tm tm_info;
            localtime_r(&ts.tv_sec, &tm_info);
            if constexpr (kTimestampEnabled) {
                if (conn_state_->timestamp_enabled) {
                    fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TCP-ACK seq=%u ack=%u flags=0x10 win=%u ts_val=%u ts_ecr=%u len=%zu\n",
                            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                            tcp_params_.snd_nxt, tcp_params_.rcv_nxt, tcp_params_.snd_wnd,
                            tcp_params_.ts_val, tcp_params_.ts_ecr, ack_len);
                } else {
                    fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TCP-ACK seq=%u ack=%u flags=0x10 win=%u len=%zu (no TS)\n",
                            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                            tcp_params_.snd_nxt, tcp_params_.rcv_nxt, tcp_params_.snd_wnd, ack_len);
                }
            } else {
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TCP-ACK seq=%u ack=%u flags=0x10 win=%u len=%zu\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.rcv_nxt, tcp_params_.snd_wnd, ack_len);
            }
            // Log additional fields: IP ID, checksums, source port
            if constexpr (kDebugTCP) {
                // Parse IP header fields (offset 14 = after Ethernet header)
                uint16_t ip_id = (ack_buffer[18] << 8) | ack_buffer[19];
                uint16_t ip_checksum = (ack_buffer[24] << 8) | ack_buffer[25];
                uint16_t src_port = (ack_buffer[34] << 8) | ack_buffer[35];
                uint16_t tcp_checksum = (ack_buffer[50] << 8) | ack_buffer[51];
                fprintf(stderr, "[TRANSPORT-TX-ACK-DEBUG] src_port=%u ip_id=0x%04x ip_csum=0x%04x tcp_csum=0x%04x\n",
                        src_port, ip_id, ip_checksum, tcp_checksum);
                // Full hex dump
                fprintf(stderr, "[TRANSPORT-TX-ACK-HEX] ");
                for (size_t i = 0; i < ack_len; i++) {
                    fprintf(stderr, "%02x ", ack_buffer[i]);
                }
                fprintf(stderr, "\n");
                fflush(stderr);
            }
        }

        return true;
    }

    /**
     * Perform TLS handshake via IPC rings
     * Uses SSL policy with zero-copy BIO mode, IPC rings for network I/O
     */
    bool perform_tls_handshake_via_ipc(const char* target_host) {
        // NoSSLPolicy: skip TLS handshake entirely (plain TCP)
        if constexpr (std::is_same_v<SSLPolicy, NoSSLPolicy>) {
            rx_frames_pending_ = 0;
            return true;
        } else {

        // Initialize handshake RX buffer
        handshake_rx_len_ = 0;
        handshake_rx_appended_ = 0;

        // Initialize OOO buffer
        ooo_buffer_.clear();

        // Initialize SSL policy with zero-copy BIO (creates context and SSL object)
        ssl_policy_.init_zero_copy_bio();

        rx_frames_pending_ = 0;

        // Set SNI (Server Name Indication)
#ifdef SSL_POLICY_WOLFSSL
        wolfSSL_UseSNI(ssl_policy_.ssl_, WOLFSSL_SNI_HOST_NAME,
                       target_host, static_cast<unsigned short>(strlen(target_host)));
#else
        // OpenSSL/LibreSSL SNI
        SSL_set_tlsext_host_name(ssl_policy_.ssl_, target_host);
#endif

        // Allocate a handshake output buffer
        uint8_t handshake_out_buf[4096];
        ssl_policy_.set_encrypted_output(handshake_out_buf, sizeof(handshake_out_buf));

        // Perform non-blocking TLS handshake loop
        auto start = std::chrono::steady_clock::now();
        constexpr int timeout_ms = 10000;
        bool handshake_complete = false;
        int iteration = 0;

        while (!handshake_complete) {
            iteration++;
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed >= timeout_ms) {
                ssl_policy_.clear_encrypted_output();
                return false;
            }

#ifdef SSL_POLICY_WOLFSSL
            int ret = wolfSSL_connect(ssl_policy_.ssl_);

            if (ret == WOLFSSL_SUCCESS) {
                // FIX: TLS 1.3 client Finished message may be pending even on SUCCESS.
                // Must send it before declaring handshake complete, otherwise server
                // will close connection (missing Finished = incomplete handshake).
                size_t pending = ssl_policy_.encrypted_output_len();
                if (pending > 0) {
                    tls_handshake_send_from_buffer(handshake_out_buf);
                }

                // Log TLS handshake details
                const char* cipher_name = wolfSSL_get_cipher(ssl_policy_.ssl_);
                const char* tls_version = wolfSSL_get_version(ssl_policy_.ssl_);
                debug_printf("[TLS] Handshake SUCCESS\n");
                debug_printf("[TLS]   Version: %s\n", tls_version ? tls_version : "unknown");
                debug_printf("[TLS]   Cipher:  %s\n", cipher_name ? cipher_name : "unknown");

                handshake_complete = true;
                break;
            }

            int err = wolfSSL_get_error(ssl_policy_.ssl_, ret);

            if (err == WOLFSSL_ERROR_WANT_READ) {
                // Send any pending output before waiting for input
                size_t pending = ssl_policy_.encrypted_output_len();
                if (pending > 0) {
                    tls_handshake_send_from_buffer(handshake_out_buf);
                }
                if (!tls_handshake_recv()) {
                    usleep(100);
                }
            } else if (err == WOLFSSL_ERROR_WANT_WRITE) {
                tls_handshake_send_from_buffer(handshake_out_buf);
            } else {
                ssl_policy_.clear_encrypted_output();
                return false;
            }
#else
            // OpenSSL/LibreSSL handshake
            int ret = SSL_do_handshake(ssl_policy_.ssl_);

            if (ret == 1) {
                handshake_complete = true;
                break;
            }

            int err = SSL_get_error(ssl_policy_.ssl_, ret);
            size_t pending_out = ssl_policy_.encrypted_output_len();

            if (err == SSL_ERROR_WANT_READ) {
                // First, send any pending output data before waiting for input
                if (pending_out > 0) {
                    tls_handshake_send_from_buffer(handshake_out_buf);
                }
                if (!tls_handshake_recv()) {
                    usleep(100);
                }
            } else if (err == SSL_ERROR_WANT_WRITE) {
                tls_handshake_send_from_buffer(handshake_out_buf);
            } else {
                ssl_policy_.clear_encrypted_output();
                return false;
            }
#endif

            // Always check for pending outbound data and send it
            tls_handshake_send_from_buffer(handshake_out_buf);
        }

        // Final commit: when handshake succeeds, SSL has consumed all needed data
        raw_inbox_cons_->commit_manually();
        ssl_policy_.clear_encrypted_output();

        rx_frames_pending_ = 0;

        return true;
        } // else (SSL policies)
    }

    // Helper: Send pending encrypted data via IPC during TLS handshake
    // Supports multi-segment transmission for large TLS handshake messages (e.g., ClientHello)
    // that exceed the TCP MSS. This is the "Hybrid Approach" for MTU handling.
    bool tls_handshake_send_from_buffer(uint8_t* handshake_buf) {
        if constexpr (std::is_same_v<SSLPolicy, NoSSLPolicy>) {
            (void)handshake_buf;
            return false;
        } else {
        size_t pending = ssl_policy_.encrypted_output_len();
        if (pending == 0) {
            return false;
        }

        // Debug: Hex dump TLS handshake data (includes ClientHello)
        if constexpr (kDebugTCP) {
            // Parse TLS record to identify message type
            uint8_t content_type = handshake_buf[0];  // 22 = handshake
            uint16_t tls_version = (handshake_buf[1] << 8) | handshake_buf[2];
            uint16_t record_len = (handshake_buf[3] << 8) | handshake_buf[4];

            const char* msg_type = "unknown";
            if (content_type == 22 && pending > 5) {  // Handshake
                uint8_t hs_type = handshake_buf[5];
                if (hs_type == 1) msg_type = "ClientHello";
                else if (hs_type == 2) msg_type = "ServerHello";
                else if (hs_type == 11) msg_type = "Certificate";
                else if (hs_type == 16) msg_type = "ClientKeyExchange";
                else if (hs_type == 20) msg_type = "Finished";
            } else if (content_type == 20) {
                msg_type = "ChangeCipherSpec";
            } else if (content_type == 23) {
                msg_type = "ApplicationData";
            }

            fprintf(stderr, "[TLS-TX-DEBUG] %s: content_type=%u tls_version=0x%04x record_len=%u pending=%zu\n",
                    msg_type, content_type, tls_version, record_len, pending);

            // Full hex dump for ClientHello analysis
            if (handshake_buf[5] == 1 && content_type == 22) {  // ClientHello
                fprintf(stderr, "[TLS-TX-CLIENTHELLO-HEX] ");
                for (size_t i = 0; i < pending && i < 600; i++) {
                    fprintf(stderr, "%02x ", handshake_buf[i]);
                }
                fprintf(stderr, "\n");
                fflush(stderr);
            }
        }

        // Calculate MSS for segmentation (MTU - IP(20) - TCP(20) = 1460 for MTU 1500)
        constexpr size_t MSS = PIPELINE_TCP_MSS;

        // If data fits in single segment, use fast path
        if (pending <= MSS) {
            auto alloc = allocate_msg_frame();
            if (!alloc.success()) {
                return false;
            }

            uint64_t addr = frame_idx_to_addr(alloc.frame_idx, frame_size_);
            uint8_t* frame = umem_area_ + addr;

            size_t frame_len = stack_.build_data(frame, frame_size_, tcp_params_,
                                                  handshake_buf, pending);
            if (frame_len == 0) {
                return false;
            }

            int64_t seq = raw_outbox_prod_->try_claim();
            if (seq < 0) {
                return false;
            }

            ssl_policy_.reset_encrypted_output_len();

            auto& desc = (*raw_outbox_prod_)[seq];
            desc.frame_ptr = addr;
            desc.frame_len = static_cast<uint16_t>(frame_len);
            desc.frame_type = FRAME_TYPE_MSG;
            desc.nic_frame_poll_cycle = rdtsc();
            desc.consumed = 0;
            raw_outbox_prod_->publish(seq);

            // Log TLS handshake TX with wall-clock time
            {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                struct tm tm_info;
                localtime_r(&ts.tv_sec, &tm_info);
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TLS-DATA seq=%u ack=%u flags=0x18 win=%u payload=%zu len=%zu\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.rcv_nxt, tcp_params_.snd_wnd, pending, frame_len);
            }

            tcp_params_.snd_nxt += pending;
            conn_state_->snd_nxt = tcp_params_.snd_nxt;

            return true;
        }

        // Multi-segment path: split large handshake data across multiple TCP segments
        // This handles TLS 1.3 ClientHello (~1540 bytes) or other large handshake messages
        size_t sent = 0;
        while (sent < pending) {
            size_t seg_len = std::min(MSS, pending - sent);

            auto alloc = allocate_msg_frame();
            if (!alloc.success()) {
                // Partial send - update state for what was sent
                if (sent > 0) {
                    tcp_params_.snd_nxt += sent;
                    conn_state_->snd_nxt = tcp_params_.snd_nxt;
                }
                return sent > 0;
            }

            uint64_t addr = frame_idx_to_addr(alloc.frame_idx, frame_size_);
            uint8_t* frame = umem_area_ + addr;

            size_t frame_len = stack_.build_data(frame, frame_size_, tcp_params_,
                                                  handshake_buf + sent, seg_len);
            if (frame_len == 0) {
                if (sent > 0) {
                    tcp_params_.snd_nxt += sent;
                    conn_state_->snd_nxt = tcp_params_.snd_nxt;
                }
                return sent > 0;
            }

            int64_t seq = raw_outbox_prod_->try_claim();
            if (seq < 0) {
                if (sent > 0) {
                    tcp_params_.snd_nxt += sent;
                    conn_state_->snd_nxt = tcp_params_.snd_nxt;
                }
                return sent > 0;
            }

            auto& desc = (*raw_outbox_prod_)[seq];
            desc.frame_ptr = addr;
            desc.frame_len = static_cast<uint16_t>(frame_len);
            desc.frame_type = FRAME_TYPE_MSG;
            desc.nic_frame_poll_cycle = rdtsc();
            desc.consumed = 0;
            raw_outbox_prod_->publish(seq);

            // Log TLS handshake TX segment with wall-clock time
            {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                struct tm tm_info;
                localtime_r(&ts.tv_sec, &tm_info);
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TLS-DATA seq=%u ack=%u flags=0x18 payload=%zu len=%zu (seg %zu/%zu)\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.rcv_nxt, seg_len, frame_len, sent + seg_len, pending);
            }

            // Update tcp_params_ for next segment (sequence number advances)
            tcp_params_.snd_nxt += seg_len;
            sent += seg_len;
        }

        ssl_policy_.reset_encrypted_output_len();
        conn_state_->snd_nxt = tcp_params_.snd_nxt;

        return true;
        }  // else (real SSL policy)
    }

    // Helper: Receive encrypted data via IPC during TLS handshake
    // During handshake, we COPY data to a buffer (handshake is small and infrequent)
    bool tls_handshake_recv() {
        bool got_data = false;

        raw_inbox_cons_->process_manually(
            [&](UMEMFrameDescriptor& desc, int64_t) -> bool {
                uint8_t* frame = umem_area_ + desc.frame_ptr;

                auto parsed = stack_.parse_tcp(frame, desc.frame_len,
                                                tcp_params_.local_port,
                                                tcp_params_.remote_ip,
                                                tcp_params_.remote_port);

                if (!parsed.valid) {
                    return true;  // Skip invalid, continue to next
                }

                // Log TLS handshake RX with wall-clock time
                {
                    struct timespec ts;
                    clock_gettime(CLOCK_REALTIME, &ts);
                    struct tm tm_info;
                    localtime_r(&ts.tv_sec, &tm_info);
                    fprintf(stderr, "[TRANSPORT-RX] %02d:%02d:%02d.%06ld TLS-DATA seq=%u ack=%u flags=0x%02x win=%u payload=%zu len=%u\n",
                            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                            parsed.seq, parsed.ack, parsed.flags, parsed.window, parsed.payload_len, desc.frame_len);
                }

                // Update ACK tracking
                if (parsed.flags & userspace_stack::TCP_FLAG_ACK) {
                    tcp_params_.snd_una = parsed.ack;
                    conn_state_->snd_una = parsed.ack;
                }

                if (parsed.payload_len > 0) {
                    int32_t seq_diff = static_cast<int32_t>(parsed.seq - tcp_params_.rcv_nxt);

                    if (seq_diff > 0) {
                        // GAP: segment ahead of expected - buffer UMEM pointer
                        size_t ooo_count_before = ooo_buffer_.count();
                        if (!ooo_buffer_.is_buffered(parsed.seq)) {
                            ooo_buffer_.buffer_segment(parsed.seq,
                                                       static_cast<uint16_t>(parsed.payload_len),
                                                       parsed.payload);
                        }
                        // RFC 5681: Send 3 dup-ACKs for first OOO of a gap to trigger fast retransmit
                        // Must send 3 before any in-order packet arrives and changes ack number
                        size_t ack_count = (ooo_count_before == 0) ? 3 : 1;
                        for (size_t i = 0; i < ack_count; i++) {
                            send_ack_during_handshake();
                        }
                        return false;  // Don't commit - UMEM stays valid
                    } else if (seq_diff < 0) {
                        int32_t overlap = -seq_diff;
                        if (static_cast<size_t>(overlap) >= parsed.payload_len) {
                            send_ack_during_handshake();
                            return true;  // Duplicate, skip
                        }
                        // Partial overlap - skip duplicate part
                        parsed.payload += overlap;
                        parsed.payload_len -= overlap;
                        parsed.seq = tcp_params_.rcv_nxt;
                    }

                    tcp_params_.rcv_nxt += parsed.payload_len;
                    conn_state_->rcv_nxt = tcp_params_.rcv_nxt;

                    // Copy to handshake buffer
                    size_t space = sizeof(handshake_rx_buf_) - handshake_rx_len_;
                    if (parsed.payload_len > space) {
                        fprintf(stderr, "[FATAL] Handshake RX buffer overflow\n");
                        std::abort();
                    }
                    memcpy(handshake_rx_buf_ + handshake_rx_len_, parsed.payload, parsed.payload_len);
                    handshake_rx_len_ += parsed.payload_len;
                    got_data = true;

                    // Check OOO buffer for now-in-order segments
                    ooo_buffer_.try_deliver(tcp_params_.rcv_nxt,
                        [this](const uint8_t* data, uint16_t offset, uint16_t len) {
                            size_t space = sizeof(handshake_rx_buf_) - handshake_rx_len_;
                            if (len > space) {
                                fprintf(stderr, "[FATAL] OOO: Handshake buffer overflow\n");
                                std::abort();
                            }
                            memcpy(handshake_rx_buf_ + handshake_rx_len_, data + offset, len);
                            handshake_rx_len_ += len;
                            return true;
                        });
                    // Sync after try_deliver updates tcp_params_.rcv_nxt
                    conn_state_->rcv_nxt = tcp_params_.rcv_nxt;

                    // Only send ACK when we received payload data (don't ACK pure ACKs)
                    send_ack_during_handshake();
                }

                // No ACK for pure ACK frames (payload_len == 0) - prevents ACK storm
                return true;  // Continue processing more frames
            }, 16);  // Process up to 16 frames per call

        raw_inbox_cons_->commit_manually();

        // Append new data to SSL view ring
        size_t new_data = handshake_rx_len_ - handshake_rx_appended_;
        if (new_data > 0) {
            uint8_t* new_data_ptr = handshake_rx_buf_ + handshake_rx_appended_;
            if (ssl_policy_.append_encrypted_view(new_data_ptr, new_data) != 0) {
                fprintf(stderr, "[FATAL] SSL view ring buffer overflow during handshake\n");
                std::abort();
            }
            handshake_rx_appended_ = handshake_rx_len_;
        }

        return got_data;
    }

    // NOTE: Handshake commit is now done immediately in tls_handshake_recv()
    // because we copy TLS data to a stable buffer, allowing immediate frame release.

    // Helper: Send ACK during handshake (with SACK support for OOO packets)
    void send_ack_during_handshake() {
        uint32_t frame_idx = allocate_ack_frame();
        if (frame_idx == UINT32_MAX) return;

        uint64_t addr = frame_idx_to_addr(frame_idx, frame_size_);
        uint8_t* frame = umem_area_ + addr;

        size_t len = 0;

        // Build SACK blocks from OOO buffer if SACK is enabled and we have OOO segments
        // This enables fast retransmit during TLS handshake (RFC 2018)
        if (conn_state_->sack_enabled && !ooo_buffer_.is_empty()) {
            userspace_stack::SACKBlockArray sack_blocks;
            sack_blocks.count = 0;

            // Calculate max SACK blocks (3 with timestamps, 4 without)
            const bool ts_in_packet = (tcp_params_.ts_val != 0);
            const uint8_t max_sack_blocks = ts_in_packet
                ? userspace_stack::SACK_MAX_BLOCKS_WITH_TS
                : userspace_stack::SACK_MAX_BLOCKS;

            // Extract SACK blocks from OOO buffer
            ooo_buffer_.extract_sack_blocks(conn_state_->rcv_nxt, sack_blocks, max_sack_blocks);

            if (sack_blocks.count > 0) {
                len = userspace_stack::TCPPacket::build_ack_with_sack(
                    frame, frame_size_, tcp_params_, sack_blocks,
                    conn_state_->local_mac, conn_state_->remote_mac, ip_id_++);

                debug_printf("[TRANSPORT-TX] TLS handshake SACK ACK: rcv_nxt=%u blocks=%u [%u-%u]\n",
                             tcp_params_.rcv_nxt, sack_blocks.count,
                             sack_blocks.blocks[0].left_edge, sack_blocks.blocks[0].right_edge);
            }
        }

        // Fall back to plain ACK if no SACK blocks
        if (len == 0) {
            len = stack_.build_ack(frame, frame_size_, tcp_params_);
        }
        if (len == 0) return;

        int64_t seq = ack_outbox_prod_->try_claim();
        if (seq < 0) return;  // Skip if outbox full
        auto& desc = (*ack_outbox_prod_)[seq];
        desc.frame_ptr = addr;
        desc.frame_len = static_cast<uint16_t>(len);
        desc.frame_type = FRAME_TYPE_ACK;
        desc.nic_timestamp_ns = 0;
        desc.nic_frame_poll_cycle = 0;
        desc.consumed = 0;
        ack_outbox_prod_->publish(seq);

        // Log handshake ACK with wall-clock time
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            struct tm tm_info;
            localtime_r(&ts.tv_sec, &tm_info);
            fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TLS-ACK seq=%u ack=%u flags=0x10 win=%u len=%zu\n",
                    tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                    tcp_params_.snd_nxt, tcp_params_.rcv_nxt, tcp_params_.snd_wnd, len);
        }
    }

    // ========================================================================
    // Unified Handshake Packet Handler (called from main loop)
    // ========================================================================

    /**
     * Handle incoming packet during handshake phase (TCP or TLS)
     * Called from process_rx_unified() when phase_ is TCP_HANDSHAKE or TLS_HANDSHAKE
     *
     * @param frame Raw Ethernet frame
     * @param frame_len Frame length
     * @param desc UMEM frame descriptor
     * @return true if frame should be committed (released), false to keep UMEM valid
     */
    bool handshake_packet_recv(uint8_t* frame, uint16_t frame_len, UMEMFrameDescriptor& desc) {
        auto parsed = stack_.parse_tcp(frame, frame_len,
                                        tcp_params_.local_port,
                                        tcp_params_.remote_ip,
                                        tcp_params_.remote_port);

        if (!parsed.valid) {
            return true;  // Skip invalid, commit frame
        }

        if (phase_ == TransportPhase::TCP_HANDSHAKE) {
            // Handle SYN-ACK during TCP handshake
            if ((parsed.flags & userspace_stack::TCP_FLAG_SYN) &&
                (parsed.flags & userspace_stack::TCP_FLAG_ACK)) {
                // Got SYN-ACK
                tcp_params_.rcv_nxt = parsed.seq + 1;  // SYN consumes 1 seq
                tcp_params_.snd_una = parsed.ack;
                conn_state_->rcv_nxt = tcp_params_.rcv_nxt;
                conn_state_->snd_una = tcp_params_.snd_una;
                conn_state_->snd_nxt = tcp_params_.snd_nxt;
                conn_state_->peer_recv_window = parsed.window;

                // Parse TCP options for SACK_OK (RFC 2018)
                conn_state_->sack_enabled = parse_sack_ok_option(frame, frame_len);

                // Parse TCP options for Window Scale (RFC 7323)
                conn_state_->window_scale = parse_window_scale_option(frame, frame_len);

                // Parse TCP options for MSS (RFC 879)
                uint16_t peer_mss = parse_mss_option(frame, frame_len);
                if (peer_mss > 0) {
                    conn_state_->peer_mss = peer_mss;
                }

                // Parse TCP options for Timestamps (RFC 7323)
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                struct tm tm_info;
                localtime_r(&ts.tv_sec, &tm_info);
                if constexpr (kTimestampEnabled) {
                    auto ts_result = parse_timestamp_option(frame, frame_len);
                    conn_state_->timestamp_enabled = ts_result.found;
                    if (ts_result.found) {
                        conn_state_->peer_ts_val = ts_result.ts_val;
                    }
                    fprintf(stderr, "[TRANSPORT-RX] %02d:%02d:%02d.%06ld SYN-ACK seq=%u ack=%u flags=0x%02x win=%u MSS=%u SACK=%s TS=%s WS=%u len=%u\n",
                            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                            parsed.seq, parsed.ack, parsed.flags, parsed.window,
                            conn_state_->peer_mss,
                            conn_state_->sack_enabled ? "ON" : "OFF",
                            conn_state_->timestamp_enabled ? "ON" : "OFF",
                            conn_state_->window_scale, frame_len);
                } else {
                    conn_state_->timestamp_enabled = false;
                    fprintf(stderr, "[TRANSPORT-RX] %02d:%02d:%02d.%06ld SYN-ACK seq=%u ack=%u flags=0x%02x win=%u MSS=%u SACK=%s WS=%u len=%u\n",
                            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                            parsed.seq, parsed.ack, parsed.flags, parsed.window,
                            conn_state_->peer_mss,
                            conn_state_->sack_enabled ? "ON" : "OFF",
                            conn_state_->window_scale, frame_len);
                }
                // Log additional fields: IP ID, checksums, source port
                if constexpr (kDebugTCP) {
                    // Parse IP header fields (offset 14 = after Ethernet header)
                    uint16_t ip_id = (frame[18] << 8) | frame[19];
                    uint16_t ip_checksum = (frame[24] << 8) | frame[25];
                    uint16_t src_port = (frame[34] << 8) | frame[35];
                    uint16_t tcp_checksum = (frame[50] << 8) | frame[51];
                    fprintf(stderr, "[TRANSPORT-RX-SYNACK-DEBUG] src_port=%u ip_id=0x%04x ip_csum=0x%04x tcp_csum=0x%04x\n",
                            src_port, ip_id, ip_checksum, tcp_checksum);
                    // Full hex dump
                    fprintf(stderr, "[TRANSPORT-RX-SYNACK-HEX] ");
                    for (uint16_t i = 0; i < frame_len; i++) {
                        fprintf(stderr, "%02x ", frame[i]);
                    }
                    fprintf(stderr, "\n");
                    fflush(stderr);
                }

                // Send ACK to complete 3-way handshake
                send_tcp_handshake_ack();

                // Transition to TLS handshake (or RUNNING if NoSSL)
                conn_state_->set_handshake_tcp_ready();
                if constexpr (std::is_same_v<SSLPolicy, NoSSLPolicy>) {
                    phase_ = TransportPhase::RUNNING;
                    conn_state_->set_handshake_tls_ready();
                } else {
                    start_tls_handshake();
                }
            }
            return true;  // Commit frame

        } else if (phase_ == TransportPhase::TLS_HANDSHAKE) {
            // Log TLS handshake RX
            {
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                struct tm tm_info;
                localtime_r(&ts.tv_sec, &tm_info);
                fprintf(stderr, "[TRANSPORT-RX] %02d:%02d:%02d.%06ld TLS-DATA seq=%u ack=%u flags=0x%02x win=%u payload=%zu len=%u\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        parsed.seq, parsed.ack, parsed.flags, parsed.window, parsed.payload_len, frame_len);
            }

            // Update ACK tracking
            if (parsed.flags & userspace_stack::TCP_FLAG_ACK) {
                tcp_params_.snd_una = parsed.ack;
                conn_state_->snd_una = parsed.ack;
            }

            if (parsed.payload_len > 0) {
                int32_t seq_diff = static_cast<int32_t>(parsed.seq - tcp_params_.rcv_nxt);

                if (seq_diff > 0) {
                    // GAP: segment ahead of expected - buffer UMEM pointer
                    size_t ooo_count_before = ooo_buffer_.count();
                    if (!ooo_buffer_.is_buffered(parsed.seq)) {
                        ooo_buffer_.buffer_segment(parsed.seq,
                                                   static_cast<uint16_t>(parsed.payload_len),
                                                   parsed.payload);
                    }
                    // RFC 5681: Send 3 dup-ACKs for first OOO of a gap to trigger fast retransmit
                    size_t ack_count = (ooo_count_before == 0) ? 3 : 1;
                    for (size_t i = 0; i < ack_count; i++) {
                        send_ack_during_handshake();
                    }
                    return false;  // Don't commit - UMEM stays valid
                } else if (seq_diff < 0) {
                    int32_t overlap = -seq_diff;
                    if (static_cast<size_t>(overlap) >= parsed.payload_len) {
                        send_ack_during_handshake();
                        return true;  // Duplicate, skip
                    }
                    // Partial overlap - skip duplicate part
                    parsed.payload += overlap;
                    parsed.payload_len -= overlap;
                    parsed.seq = tcp_params_.rcv_nxt;
                }

                tcp_params_.rcv_nxt += parsed.payload_len;
                conn_state_->rcv_nxt = tcp_params_.rcv_nxt;

                // Copy to handshake buffer
                size_t space = sizeof(handshake_rx_buf_) - handshake_rx_len_;
                if (parsed.payload_len > space) {
                    fprintf(stderr, "[FATAL] Handshake RX buffer overflow\n");
                    std::abort();
                }
                memcpy(handshake_rx_buf_ + handshake_rx_len_, parsed.payload, parsed.payload_len);
                handshake_rx_len_ += parsed.payload_len;

                // Check OOO buffer for now-in-order segments
                ooo_buffer_.try_deliver(tcp_params_.rcv_nxt,
                    [this](const uint8_t* data, uint16_t offset, uint16_t len) {
                        size_t space = sizeof(handshake_rx_buf_) - handshake_rx_len_;
                        if (len > space) {
                            fprintf(stderr, "[FATAL] OOO: Handshake buffer overflow\n");
                            std::abort();
                        }
                        memcpy(handshake_rx_buf_ + handshake_rx_len_, data + offset, len);
                        handshake_rx_len_ += len;
                        return true;
                    });
                conn_state_->rcv_nxt = tcp_params_.rcv_nxt;

                // Send ACK for received payload
                send_ack_during_handshake();

                // Try to advance TLS handshake
                advance_tls_handshake();
            }
            return true;  // Commit frame
        }

        return true;  // Default: commit frame
    }

    /**
     * Send TCP handshake ACK (third packet of 3-way handshake)
     */
    void send_tcp_handshake_ack() {
        uint32_t ack_frame_idx = allocate_ack_frame();
        if (ack_frame_idx == UINT32_MAX) {
            fprintf(stderr, "[TRANSPORT] FATAL: Failed to allocate ACK frame for TCP handshake\n");
            return;
        }
        uint64_t ack_addr = frame_idx_to_addr(ack_frame_idx, frame_size_);
        uint8_t* ack_buffer = umem_area_ + ack_addr;

        // Set timestamps for ACK (echo peer's ts_val from SYN-ACK)
        if constexpr (kTimestampEnabled) {
            if (conn_state_->timestamp_enabled) {
                tcp_params_.ts_val = generate_ts_val();
                tcp_params_.ts_ecr = conn_state_->peer_ts_val;
            }
        }

        // Use small window for handshake ACK to match Python fingerprint
        tcp_params_.rcv_wnd = userspace_stack::TCP_HANDSHAKE_ACK_WINDOW;

        size_t ack_len = stack_.build_ack(ack_buffer, frame_size_, tcp_params_);
        if (ack_len == 0) {
            fprintf(stderr, "[TRANSPORT] FATAL: Failed to build TCP handshake ACK\n");
            return;
        }

        int64_t ack_seq = ack_outbox_prod_->try_claim();
        if (ack_seq < 0) {
            fprintf(stderr, "[TRANSPORT] FATAL: ACK outbox full for TCP handshake\n");
            return;
        }
        auto& ack_desc = (*ack_outbox_prod_)[ack_seq];
        ack_desc.frame_ptr = ack_addr;
        ack_desc.frame_len = static_cast<uint16_t>(ack_len);
        ack_desc.frame_type = FRAME_TYPE_ACK;
        ack_desc.nic_timestamp_ns = 0;
        ack_desc.nic_frame_poll_cycle = 0;
        ack_desc.consumed = 0;
        ack_outbox_prod_->publish(ack_seq);

        // Log TCP handshake ACK
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm tm_info;
        localtime_r(&ts.tv_sec, &tm_info);
        if constexpr (kTimestampEnabled) {
            if (conn_state_->timestamp_enabled) {
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TCP-ACK seq=%u ack=%u flags=0x10 win=%u ts_val=%u ts_ecr=%u len=%zu\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.rcv_nxt, tcp_params_.snd_wnd,
                        tcp_params_.ts_val, tcp_params_.ts_ecr, ack_len);
            } else {
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TCP-ACK seq=%u ack=%u flags=0x10 win=%u len=%zu (no TS)\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.rcv_nxt, tcp_params_.snd_wnd, ack_len);
            }
        } else {
            fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld TCP-ACK seq=%u ack=%u flags=0x10 win=%u len=%zu\n",
                    tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                    tcp_params_.snd_nxt, tcp_params_.rcv_nxt, tcp_params_.snd_wnd, ack_len);
        }
        // Log additional fields: IP ID, checksums, source port
        if constexpr (kDebugTCP) {
            // Parse IP header fields (offset 14 = after Ethernet header)
            uint16_t ip_id = (ack_buffer[18] << 8) | ack_buffer[19];
            uint16_t ip_checksum = (ack_buffer[24] << 8) | ack_buffer[25];
            uint16_t src_port = (ack_buffer[34] << 8) | ack_buffer[35];
            uint16_t tcp_checksum = (ack_buffer[50] << 8) | ack_buffer[51];
            fprintf(stderr, "[TRANSPORT-TX-ACK-DEBUG] src_port=%u ip_id=0x%04x ip_csum=0x%04x tcp_csum=0x%04x\n",
                    src_port, ip_id, ip_checksum, tcp_checksum);
            // Full hex dump
            fprintf(stderr, "[TRANSPORT-TX-ACK-HEX] ");
            for (size_t i = 0; i < ack_len; i++) {
                fprintf(stderr, "%02x ", ack_buffer[i]);
            }
            fprintf(stderr, "\n");
            fflush(stderr);
        }
    }

    /**
     * Start TCP handshake (non-blocking)
     * Resolves hostname, initializes TCP params, sends SYN, returns immediately
     * SYN-ACK handling is done via handshake_packet_recv() in main loop
     *
     * @param target_host Target hostname (e.g., "stream.binance.com")
     * @param target_port Target port (e.g., 443)
     * @return true if SYN was sent successfully, false on error
     */
    bool start_tcp_handshake(const char* target_host, uint16_t target_port) {
        // Store target host for SNI during TLS handshake
        strncpy(target_host_, target_host, sizeof(target_host_) - 1);
        target_host_[sizeof(target_host_) - 1] = '\0';

        // Resolve hostname to IP
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int gai_ret = getaddrinfo(target_host, nullptr, &hints, &res);
        if (gai_ret != 0 || !res) {
            fprintf(stderr, "[TRANSPORT] Failed to resolve hostname: %s\n", target_host);
            return false;
        }
        uint32_t remote_ip = ntohl(reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr);
        freeaddrinfo(res);

        // Initialize TCP params
        tcp_params_.remote_ip = remote_ip;
        tcp_params_.remote_port = target_port;
        tcp_params_.local_ip = ntohl(conn_state_->local_ip);
        tcp_params_.local_port = userspace_stack::UserspaceStack::generate_port();
        tcp_params_.snd_nxt = userspace_stack::UserspaceStack::generate_isn();
        tcp_params_.snd_una = tcp_params_.snd_nxt;
        tcp_params_.rcv_nxt = 0;
        tcp_params_.snd_wnd = userspace_stack::TCP_MAX_WINDOW;
        tcp_params_.rcv_wnd = userspace_stack::TCP_MAX_WINDOW;

        // Store in shared state
        conn_state_->local_port = tcp_params_.local_port;
        conn_state_->remote_port = target_port;
        conn_state_->remote_ip = htonl(remote_ip);

        // Allocate frame for SYN
        auto syn_alloc = allocate_msg_frame();
        if (!syn_alloc.success()) {
            fprintf(stderr, "[TRANSPORT] Failed to allocate SYN frame\n");
            return false;
        }
        uint64_t syn_addr = frame_idx_to_addr(syn_alloc.frame_idx, frame_size_);
        uint8_t* syn_buffer = umem_area_ + syn_addr;

        // Set timestamp for SYN (ts_ecr = 0 for initial SYN per RFC 7323)
        if constexpr (kTimestampEnabled) {
            tcp_params_.ts_val = generate_ts_val();
            tcp_params_.ts_ecr = 0;
        }

        // Build SYN packet
        size_t syn_len = stack_.build_syn(syn_buffer, frame_size_, tcp_params_);
        if (syn_len == 0) {
            fprintf(stderr, "[TRANSPORT] Failed to build SYN packet\n");
            return false;
        }

        // Send SYN via RAW_OUTBOX
        int64_t syn_seq = raw_outbox_prod_->try_claim();
        if (syn_seq < 0) {
            fprintf(stderr, "[TRANSPORT] RAW_OUTBOX full, cannot send SYN\n");
            return false;
        }
        auto& syn_desc = (*raw_outbox_prod_)[syn_seq];
        syn_desc.frame_ptr = syn_addr;
        syn_desc.frame_len = static_cast<uint16_t>(syn_len);
        syn_desc.frame_type = FRAME_TYPE_MSG;
        syn_desc.nic_frame_poll_cycle = rdtsc();
        syn_desc.consumed = 0;
        raw_outbox_prod_->publish(syn_seq);

        // Log SYN
        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            struct tm tm_info;
            localtime_r(&ts.tv_sec, &tm_info);
            if constexpr (kTimestampEnabled) {
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld SYN seq=%u ack=0 flags=0x02 win=%u ts_val=%u ts_ecr=0 len=%zu\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.snd_wnd, tcp_params_.ts_val, syn_len);
            } else {
                fprintf(stderr, "[TRANSPORT-TX] %02d:%02d:%02d.%06ld SYN seq=%u ack=0 flags=0x02 win=%u len=%zu\n",
                        tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec / 1000,
                        tcp_params_.snd_nxt, tcp_params_.snd_wnd, syn_len);
            }
            // Log additional fields: IP ID, checksums, source port
            if constexpr (kDebugTCP) {
                // Parse IP header fields (offset 14 = after Ethernet header)
                uint16_t ip_id = (syn_buffer[18] << 8) | syn_buffer[19];
                uint16_t ip_checksum = (syn_buffer[24] << 8) | syn_buffer[25];
                uint16_t src_port = (syn_buffer[34] << 8) | syn_buffer[35];
                uint16_t tcp_checksum = (syn_buffer[50] << 8) | syn_buffer[51];
                fprintf(stderr, "[TRANSPORT-TX-SYN-DEBUG] src_port=%u ip_id=0x%04x ip_csum=0x%04x tcp_csum=0x%04x\n",
                        src_port, ip_id, ip_checksum, tcp_checksum);
                // Full hex dump
                fprintf(stderr, "[TRANSPORT-TX-SYN-HEX] ");
                for (size_t i = 0; i < syn_len; i++) {
                    fprintf(stderr, "%02x ", syn_buffer[i]);
                }
                fprintf(stderr, "\n");
                fflush(stderr);
            }
        }
        tcp_params_.snd_nxt++;  // SYN consumes 1 seq

        // Set phase and start timeout
        phase_ = TransportPhase::TCP_HANDSHAKE;
        handshake_start_time_ = std::chrono::steady_clock::now();

        return true;
    }

    /**
     * Initialize TLS handshake (non-blocking)
     * Sets up SSL context and initiates handshake, returns immediately
     * Called after TCP handshake completes
     */
    void start_tls_handshake() {
        if constexpr (std::is_same_v<SSLPolicy, NoSSLPolicy>) {
            phase_ = TransportPhase::RUNNING;
            return;
        }

        // Initialize handshake state
        handshake_rx_len_ = 0;
        handshake_rx_appended_ = 0;
        ooo_buffer_.clear();
        rx_frames_pending_ = 0;

        // Initialize SSL policy with zero-copy BIO
        ssl_policy_.init_zero_copy_bio();

        // Set SNI (Server Name Indication) - stored in target_host_
#ifdef SSL_POLICY_WOLFSSL
        wolfSSL_UseSNI(ssl_policy_.ssl_, WOLFSSL_SNI_HOST_NAME,
                       target_host_, static_cast<unsigned short>(strlen(target_host_)));
#else
        SSL_set_tlsext_host_name(ssl_policy_.ssl_, target_host_);
#endif

        // Set output buffer for encrypted data
        ssl_policy_.set_encrypted_output(tls_handshake_out_buf_, sizeof(tls_handshake_out_buf_));

        // Set phase and start timeout
        phase_ = TransportPhase::TLS_HANDSHAKE;
        handshake_start_time_ = std::chrono::steady_clock::now();

        // Initiate TLS handshake (will return WANT_READ/WANT_WRITE)
        advance_tls_handshake();
    }

    /**
     * Advance TLS handshake state machine (non-blocking)
     * Called after receiving TLS data to progress the handshake
     */
    void advance_tls_handshake() {
        if constexpr (std::is_same_v<SSLPolicy, NoSSLPolicy>) {
            phase_ = TransportPhase::RUNNING;
            return;
        }

        // Append any new handshake data to SSL view ring
        size_t new_data = handshake_rx_len_ - handshake_rx_appended_;
        if (new_data > 0) {
            uint8_t* new_data_ptr = handshake_rx_buf_ + handshake_rx_appended_;
            if (ssl_policy_.append_encrypted_view(new_data_ptr, new_data) != 0) {
                fprintf(stderr, "[FATAL] SSL view ring buffer overflow during handshake\n");
                std::abort();
            }
            handshake_rx_appended_ = handshake_rx_len_;
        }

#ifdef SSL_POLICY_WOLFSSL
        int ret = wolfSSL_connect(ssl_policy_.ssl_);

        if (ret == WOLFSSL_SUCCESS) {
            // TLS 1.3: client Finished message may be pending
            size_t pending = ssl_policy_.encrypted_output_len();
            if (pending > 0) {
                tls_handshake_send_from_buffer(tls_handshake_out_buf_);
            }

            // Log TLS handshake success
            const char* cipher_name = wolfSSL_get_cipher(ssl_policy_.ssl_);
            const char* tls_version = wolfSSL_get_version(ssl_policy_.ssl_);
            debug_printf("[TLS] Handshake SUCCESS\n");
            debug_printf("[TLS]   Version: %s\n", tls_version ? tls_version : "unknown");
            debug_printf("[TLS]   Cipher:  %s\n", cipher_name ? cipher_name : "unknown");

            // Cleanup and transition
            ssl_policy_.clear_encrypted_output();
            conn_state_->set_handshake_tls_ready();
            phase_ = TransportPhase::RUNNING;
            return;
        }

        int err = wolfSSL_get_error(ssl_policy_.ssl_, ret);

        if (err == WOLFSSL_ERROR_WANT_READ) {
            // Send any pending output before waiting for input
            size_t pending = ssl_policy_.encrypted_output_len();
            if (pending > 0) {
                tls_handshake_send_from_buffer(tls_handshake_out_buf_);
            }
            // Stay in TLS_HANDSHAKE, wait for more data
        } else if (err == WOLFSSL_ERROR_WANT_WRITE) {
            tls_handshake_send_from_buffer(tls_handshake_out_buf_);
        } else {
            // TLS handshake failed
            fprintf(stderr, "[TLS] Handshake FAILED: error=%d\n", err);
            ssl_policy_.clear_encrypted_output();
            phase_ = TransportPhase::FINISHED;
        }
#else
        // OpenSSL/LibreSSL handshake
        int ret = SSL_do_handshake(ssl_policy_.ssl_);

        if (ret == 1) {
            ssl_policy_.clear_encrypted_output();
            conn_state_->set_handshake_tls_ready();
            phase_ = TransportPhase::RUNNING;
            return;
        }

        int err = SSL_get_error(ssl_policy_.ssl_, ret);
        size_t pending_out = ssl_policy_.encrypted_output_len();

        if (err == SSL_ERROR_WANT_READ) {
            if (pending_out > 0) {
                tls_handshake_send_from_buffer(tls_handshake_out_buf_);
            }
            // Stay in TLS_HANDSHAKE, wait for more data
        } else if (err == SSL_ERROR_WANT_WRITE) {
            tls_handshake_send_from_buffer(tls_handshake_out_buf_);
        } else {
            fprintf(stderr, "[TLS] Handshake FAILED: error=%d\n", err);
            ssl_policy_.clear_encrypted_output();
            phase_ = TransportPhase::FINISHED;
        }
#endif

        // Always send any remaining pending output
        tls_handshake_send_from_buffer(tls_handshake_out_buf_);
    }

    // ========================================================================
    // General Helpers
    // ========================================================================

    /**
     * Parse TCP options in SYN-ACK to check for SACK_OK (RFC 2018)
     * Must be called on SYN-ACK frames during handshake.
     *
     * @param frame Raw Ethernet frame
     * @param frame_len Frame length
     * @return true if SACK_OK option found, false otherwise
     */
    static bool parse_sack_ok_option(const uint8_t* frame, size_t frame_len) {
        constexpr size_t ETH_LEN = userspace_stack::ETH_HEADER_LEN;
        constexpr size_t IP_LEN = userspace_stack::IP_HEADER_LEN;
        constexpr size_t TCP_MIN = userspace_stack::TCP_HEADER_MIN_LEN;

        // Minimum size check
        if (frame_len < ETH_LEN + IP_LEN + TCP_MIN) {
            return false;
        }

        const auto* tcp = reinterpret_cast<const userspace_stack::TCPHeader*>(
            frame + ETH_LEN + IP_LEN);

        // Get TCP header length from data offset field
        size_t tcp_header_len = ((tcp->doff_reserved >> 4) & 0x0F) * 4;
        if (tcp_header_len <= TCP_MIN) {
            return false;  // No options
        }

        // Validate frame has full TCP header
        if (frame_len < ETH_LEN + IP_LEN + tcp_header_len) {
            return false;
        }

        // Parse TCP options
        const uint8_t* options = frame + ETH_LEN + IP_LEN + TCP_MIN;
        size_t options_len = tcp_header_len - TCP_MIN;
        size_t pos = 0;

        while (pos < options_len) {
            uint8_t kind = options[pos];

            if (kind == userspace_stack::TCP_OPT_EOL) {
                break;  // End of options list
            }
            if (kind == userspace_stack::TCP_OPT_NOP) {
                pos++;
                continue;
            }

            // All other options have length byte
            if (pos + 1 >= options_len) {
                break;  // Malformed
            }
            uint8_t len = options[pos + 1];
            if (len < 2 || pos + len > options_len) {
                break;  // Malformed
            }

            // Check for SACK_OK (kind=4, length=2)
            if (kind == userspace_stack::TCP_OPT_SACK_OK && len == 2) {
                return true;  // Found SACK_OK!
            }

            pos += len;
        }

        return false;
    }

    /**
     * Parse TCP options to extract Window Scale value (RFC 7323)
     *
     * @param frame Raw Ethernet frame
     * @param frame_len Frame length
     * @return Window scale shift value (0-14), or 0 if not found
     */
    static uint8_t parse_window_scale_option(const uint8_t* frame, size_t frame_len) {
        constexpr size_t ETH_LEN = userspace_stack::ETH_HEADER_LEN;
        constexpr size_t IP_LEN = userspace_stack::IP_HEADER_LEN;
        constexpr size_t TCP_MIN = userspace_stack::TCP_HEADER_MIN_LEN;

        // Minimum size check
        if (frame_len < ETH_LEN + IP_LEN + TCP_MIN) {
            return 0;
        }

        const auto* tcp = reinterpret_cast<const userspace_stack::TCPHeader*>(
            frame + ETH_LEN + IP_LEN);

        // Get TCP header length from data offset field
        size_t tcp_header_len = ((tcp->doff_reserved >> 4) & 0x0F) * 4;
        if (tcp_header_len <= TCP_MIN) {
            return 0;  // No options
        }

        // Validate frame has full TCP header
        if (frame_len < ETH_LEN + IP_LEN + tcp_header_len) {
            return 0;
        }

        // Parse TCP options
        const uint8_t* options = frame + ETH_LEN + IP_LEN + TCP_MIN;
        size_t options_len = tcp_header_len - TCP_MIN;
        size_t pos = 0;

        while (pos < options_len) {
            uint8_t kind = options[pos];

            if (kind == userspace_stack::TCP_OPT_EOL) {
                break;  // End of options list
            }
            if (kind == userspace_stack::TCP_OPT_NOP) {
                pos++;
                continue;
            }

            // All other options have length byte
            if (pos + 1 >= options_len) {
                break;  // Malformed
            }
            uint8_t len = options[pos + 1];
            if (len < 2 || pos + len > options_len) {
                break;  // Malformed
            }

            // Check for Window Scale (kind=3, length=3)
            if (kind == userspace_stack::TCP_OPT_WSCALE && len == userspace_stack::TCP_OPT_WSCALE_LEN) {
                uint8_t shift = options[pos + 2];
                // RFC 7323: max shift is 14
                return (shift > 14) ? 14 : shift;
            }

            pos += len;
        }

        return 0;  // Not found
    }

    /**
     * Parse TCP options to extract timestamp values (RFC 7323)
     *
     * @param frame Raw Ethernet frame
     * @param frame_len Frame length
     * @return {found, ts_val, ts_ecr} - ts_val and ts_ecr from peer
     */
    struct TimestampParseResult {
        bool found = false;
        uint32_t ts_val = 0;  // Peer's timestamp value
        uint32_t ts_ecr = 0;  // Peer's echoed timestamp (our previous ts_val)
    };

    static TimestampParseResult parse_timestamp_option(const uint8_t* frame, size_t frame_len) {
        TimestampParseResult result;
        constexpr size_t ETH_LEN = userspace_stack::ETH_HEADER_LEN;
        constexpr size_t IP_LEN = userspace_stack::IP_HEADER_LEN;
        constexpr size_t TCP_MIN = userspace_stack::TCP_HEADER_MIN_LEN;

        // Minimum size check
        if (frame_len < ETH_LEN + IP_LEN + TCP_MIN) {
            return result;
        }

        const auto* tcp = reinterpret_cast<const userspace_stack::TCPHeader*>(
            frame + ETH_LEN + IP_LEN);

        // Get TCP header length from data offset field
        size_t tcp_header_len = ((tcp->doff_reserved >> 4) & 0x0F) * 4;
        if (tcp_header_len <= TCP_MIN) {
            return result;  // No options
        }

        // Validate frame has full TCP header
        if (frame_len < ETH_LEN + IP_LEN + tcp_header_len) {
            return result;
        }

        // Parse TCP options
        const uint8_t* options = frame + ETH_LEN + IP_LEN + TCP_MIN;
        size_t options_len = tcp_header_len - TCP_MIN;
        size_t pos = 0;

        while (pos < options_len) {
            uint8_t kind = options[pos];

            if (kind == userspace_stack::TCP_OPT_EOL) {
                break;  // End of options list
            }
            if (kind == userspace_stack::TCP_OPT_NOP) {
                pos++;
                continue;
            }

            // All other options have length byte
            if (pos + 1 >= options_len) {
                break;  // Malformed
            }
            uint8_t len = options[pos + 1];
            if (len < 2 || pos + len > options_len) {
                break;  // Malformed
            }

            // Check for Timestamp (kind=8, length=10)
            if (kind == userspace_stack::TCP_OPT_TIMESTAMP && len == 10) {
                // TSval at offset +2, TSecr at offset +6
                uint32_t ts_val_n, ts_ecr_n;
                std::memcpy(&ts_val_n, &options[pos + 2], 4);
                std::memcpy(&ts_ecr_n, &options[pos + 6], 4);
                result.found = true;
                result.ts_val = ntohl(ts_val_n);
                result.ts_ecr = ntohl(ts_ecr_n);
                return result;
            }

            pos += len;
        }

        return result;
    }

    /**
     * Parse TCP options to extract MSS value (RFC 879)
     * Must be called on SYN-ACK frames during handshake.
     *
     * @param frame Raw Ethernet frame
     * @param frame_len Frame length
     * @return MSS value from peer, or 0 if not found
     */
    static uint16_t parse_mss_option(const uint8_t* frame, size_t frame_len) {
        constexpr size_t ETH_LEN = userspace_stack::ETH_HEADER_LEN;
        constexpr size_t IP_LEN = userspace_stack::IP_HEADER_LEN;
        constexpr size_t TCP_MIN = userspace_stack::TCP_HEADER_MIN_LEN;

        // Minimum size check
        if (frame_len < ETH_LEN + IP_LEN + TCP_MIN) {
            return 0;
        }

        const auto* tcp = reinterpret_cast<const userspace_stack::TCPHeader*>(
            frame + ETH_LEN + IP_LEN);

        // Get TCP header length from data offset field
        size_t tcp_header_len = ((tcp->doff_reserved >> 4) & 0x0F) * 4;
        if (tcp_header_len <= TCP_MIN) {
            return 0;  // No options
        }

        // Validate frame has full TCP header
        if (frame_len < ETH_LEN + IP_LEN + tcp_header_len) {
            return 0;
        }

        // Parse TCP options
        const uint8_t* options = frame + ETH_LEN + IP_LEN + TCP_MIN;
        size_t options_len = tcp_header_len - TCP_MIN;
        size_t pos = 0;

        while (pos < options_len) {
            uint8_t kind = options[pos];

            if (kind == userspace_stack::TCP_OPT_EOL) {
                break;  // End of options list
            }
            if (kind == userspace_stack::TCP_OPT_NOP) {
                pos++;
                continue;
            }

            // All other options have length byte
            if (pos + 1 >= options_len) {
                break;  // Malformed
            }
            uint8_t len = options[pos + 1];
            if (len < 2 || pos + len > options_len) {
                break;  // Malformed
            }

            // Check for MSS (kind=2, length=4)
            if (kind == userspace_stack::TCP_OPT_MSS && len == 4) {
                // MSS value at offset +2 (2 bytes, network byte order)
                uint16_t mss_n;
                std::memcpy(&mss_n, &options[pos + 2], 2);
                return ntohs(mss_n);
            }

            pos += len;
        }

        return 0;  // Not found
    }

    void reset_timestamps() {
        has_pending_timestamps_ = false;
        first_nic_timestamp_ns_ = 0;
        first_nic_frame_poll_cycle_ = 0;
        first_raw_frame_poll_cycle_ = 0;
        latest_nic_timestamp_ns_ = 0;
        latest_nic_frame_poll_cycle_ = 0;
        latest_raw_frame_poll_cycle_ = 0;
        pending_packet_ct_ = 0;
    }

    // Accessors
    SSLPolicy& ssl_policy() { return ssl_policy_; }
    const SSLPolicy& ssl_policy() const { return ssl_policy_; }

    // State
    uint8_t* umem_area_ = nullptr;
    uint32_t frame_size_ = 0;
    SSLPolicy ssl_policy_;  // SSL policy (abstracts library-specific details)
    char target_host_[256] = {};  // Target hostname for SNI (stored during TCP handshake init)

    // Memory BIO pointers for SSL I/O (OpenSSL/LibreSSL only)
    // - OpenSSL/LibreSSL: Use memory BIOs for userspace transport
    // - WolfSSL: Uses native I/O callbacks, no BIO needed
    // - NoSSL: Pass-through, no SSL at all
    //
    // Use type traits to conditionally include BIO pointers at compile time
    // void* avoids OpenSSL header dependency; cast to BIO* when needed
    // [[no_unique_address]] ensures std::monostate takes zero space
    static constexpr bool needs_bio_ = !std::is_same_v<SSLPolicy, WolfSSLPolicy> &&
                                       !std::is_same_v<SSLPolicy, NoSSLPolicy>;
    [[no_unique_address]] std::conditional_t<needs_bio_, void*, std::monostate> bio_in_{};
    [[no_unique_address]] std::conditional_t<needs_bio_, void*, std::monostate> bio_out_{};

    // Ring pointers (each with proper element type)
    RawInboxCons* raw_inbox_cons_ = nullptr;
    RawOutboxProd* raw_outbox_prod_ = nullptr;
    AckOutboxProd* ack_outbox_prod_ = nullptr;
    PongOutboxProd* pong_outbox_prod_ = nullptr;
    MsgOutboxCons* msg_outbox_cons_ = nullptr;
    MsgMetadataProd* msg_metadata_prod_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;
    MsgInbox* msg_inbox_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    // Timestamp tracking (first and latest for batch analysis)
    bool has_pending_timestamps_ = false;
    uint64_t first_nic_timestamp_ns_ = 0;
    uint64_t first_nic_frame_poll_cycle_ = 0;   // XDP Poll rdtscp of first packet
    uint64_t first_raw_frame_poll_cycle_ = 0;   // Transport rdtscp of first packet
    uint64_t latest_nic_timestamp_ns_ = 0;
    uint64_t latest_nic_frame_poll_cycle_ = 0;  // XDP Poll rdtscp of latest packet
    uint64_t latest_raw_frame_poll_cycle_ = 0;  // Transport rdtscp of latest packet
    uint32_t pending_packet_ct_ = 0;           // Packets since last SSL_read

    // Profiling: track oldest event in batch (smallest nic_frame_poll_cycle)
    uint64_t oldest_poll_cycle_ = UINT64_MAX;       // Reset each iteration, track min nic_frame_poll_cycle
    uint64_t oldest_nic_timestamp_ns_ = 0;          // NIC timestamp of oldest packet
    uint64_t oldest_transport_poll_cycle_ = 0;      // Transport poll cycle of oldest packet

    // ACK state
    uint32_t packets_since_ack_ = 0;
    uint64_t last_ack_cycle_ = 0;
    // Deferred ACK flags for IDLE processing
    bool seen_dup_packet_ = false;   // Set when FULL DUP received, triggers ACK in IDLE
    bool seen_ooo_packet_ = false;   // Set when OOO packet received, triggers SACK in IDLE
    // DSACK state (RFC 2883) - captures duplicate segment info for DSACK block
    uint32_t dup_seq_ = 0;           // Start seq of duplicate segment
    uint16_t dup_len_ = 0;           // Length of duplicate segment

    // Connection health summary stats (reset each 1s interval)
    uint64_t health_rx_frames_ = 0;        // RX frames this interval
    uint64_t health_tx_frames_ = 0;        // TX frames this interval
    uint64_t health_ooo_packets_ = 0;      // OOO packets this interval
    uint64_t health_dup_packets_ = 0;      // Duplicate packets this interval
    uint64_t health_retransmits_ = 0;      // Retransmits this interval
    uint64_t health_last_cycle_ = 0;       // Last health summary timestamp
    uint64_t health_interval_cycles_ = 0;  // 1 second in cycles (set in init)

    // Track last printed state for change detection
    struct LastHealthState {
        int64_t meta_prod = -1;             // META ring producer seq (trades)
        int64_t pongs_prod = -1;            // PONG ring producer seq (pings received)
        int64_t pongs_cons = -1;            // PONG ring consumer seq (pongs sent)
        uint64_t rx_frames = 0;             // RX frames
        uint64_t tx_frames = 0;             // TX frames
        uint64_t ooo_packets = 0;           // OOO packets
        uint64_t dup_packets = 0;           // Duplicate packets
        uint64_t retransmits = 0;           // Retransmits
        uint32_t rcv_nxt = 0;               // TCP rcv_nxt
        uint32_t snd_nxt = 0;               // TCP snd_nxt
        uint32_t snd_una = 0;               // TCP snd_una
        size_t ooo_count = 0;               // OOO buffer count
        size_t msg_rtx_size = 0;            // MSG retransmit queue size
        size_t pong_rtx_size = 0;           // PONG retransmit queue size
        int64_t raw_inbox_prod = -1;        // RAW_INBOX producer seq
        int64_t ack_prod = -1;              // ACK_OUTBOX producer seq
        int64_t pong_outbox_prod = -1;      // PONG_OUTBOX producer seq
    } last_health_;

    // Connection lifecycle tracking
    uint64_t connection_start_cycle_ = 0;  // TSC cycle when run() begins (post-handshake)
    bool finished_called_ = false;         // Prevent double-invocation of on_finished()

    // Transport phase state (unified main loop)
    TransportPhase phase_ = TransportPhase::TCP_HANDSHAKE;
    std::chrono::steady_clock::time_point handshake_start_time_;  // For timeout tracking
    static constexpr int TCP_HANDSHAKE_TIMEOUT_MS = 5000;   // 5 second TCP handshake timeout
    static constexpr int TLS_HANDSHAKE_TIMEOUT_MS = 10000;  // 10 second TLS handshake timeout

    // TLS handshake output buffer (set during TLS phase)
    uint8_t tls_handshake_out_buf_[4096];

    // Retransmit state - separate queues for MSG and PONG frames
    ZeroCopyRetransmitQueue msg_retransmit_queue_;       // MSG frames
    ZeroCopyRetransmitQueue pong_retransmit_queue_;  // PONG frames
    LastPongInfo last_pong_;  // Track last PONG for explicit ACK logging
    uint64_t rto_cycles_ = 0;          // Calculated from TSC frequency in init()

    // Delayed ACK state
    uint64_t delack_min_cycles_ = 0;       // TcpDelackMinMs converted to CPU cycles
    uint64_t delack_max_cycles_ = 0;       // TcpDelackMaxMs converted to CPU cycles
    uint64_t first_unacked_cycle_ = 0;     // TSC when first unacked packet arrived
    bool has_unacked_packets_ = false;     // True if packets pending ACK
    uint32_t idle_loop_counter_ = 0;       // Counter for periodic timeout check

    // Handshake RX buffer - used to copy TLS data during handshake
    // This allows immediate frame commit while keeping data valid for SSL
    // Size: 32KB is enough for typical TLS 1.3 handshake (< 16KB)
    static constexpr size_t HANDSHAKE_RX_BUF_SIZE = 32768;
    uint8_t handshake_rx_buf_[HANDSHAKE_RX_BUF_SIZE];
    size_t handshake_rx_len_ = 0;              // Total data length in buffer
    size_t handshake_rx_appended_ = 0;         // How much has been appended to SSL view

    // Out-of-order (OOO) buffer for TCP segment reordering
    // Zero-copy: stores UMEM pointers, frames stay valid until batch commit
    // process_manually() returns true for all frames -> UMEMs valid until commit_manually()
    // 64 slots to handle high packet reordering on WAN connections
    using OOOBuffer = userspace_stack::ZeroCopyTCPReorderBuffer<const uint8_t*, 64>;
    OOOBuffer ooo_buffer_;

    // RX frame lifecycle - track frames pending SSL consumption in main loop
    size_t rx_frames_pending_ = 0;

    // IP identification counter for outgoing packets (random start like Python/kernel)
    uint16_t ip_id_ = static_cast<uint16_t>(std::time(nullptr) ^ (std::time(nullptr) >> 16));

    // Userspace TCP stack for building/parsing packets (fork-first handshake)
    userspace_stack::UserspaceStack stack_;
    userspace_stack::TCPParams tcp_params_;

    // Profiling data (optional, set via set_profiling_data())
    CycleSampleBuffer* profiling_data_ = nullptr;

    // Debug packet history for retransmit detection (zero-size when disabled)
    [[no_unique_address]] DebugPacketHistory<kDebugTCP> debug_packet_history_;

public:
    // Profiling setter
    void set_profiling_data(CycleSampleBuffer* data) { profiling_data_ = data; }
};

}  // namespace websocket::pipeline
