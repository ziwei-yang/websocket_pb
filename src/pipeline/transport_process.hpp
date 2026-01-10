// pipeline/transport_process.hpp
// Transport Process - SSL/TCP layer with zero-copy I/O
// Handles encryption, retransmission, and adaptive ACK
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <netdb.h>
#include <unistd.h>
#include <algorithm>
#include <chrono>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "msg_inbox.hpp"
#include "ws_parser.hpp"
#include "../core/timing.hpp"
#include "../stack/userspace_stack.hpp"
#include "../policy/ssl.hpp"  // PipelineSSLPolicy

namespace websocket::pipeline {

// ============================================================================
// RetransmitSegmentRef - Reference to a sent TCP segment for retransmission
// Size: 40 bytes (padded to 64 for cache alignment)
// ============================================================================

struct alignas(64) RetransmitSegmentRef {
    uint64_t alloc_pos;        // Frame allocation position (for acked_pos calculation)
    uint64_t send_tsc;         // TSC when segment was sent (for RTO calculation)
    uint32_t frame_idx;        // UMEM frame index for retransmit
    uint32_t seq_start;        // TCP sequence number at frame start
    uint32_t seq_end;          // TCP sequence number at frame end (exclusive)
    uint16_t frame_len;        // Total frame length (Eth + IP + TCP + payload)
    uint8_t  flags;            // TCP flags (PSH|ACK, etc.)
    uint8_t  retransmit_count; // Number of retransmits so far
    uint8_t  _pad[24];         // Pad to 64 bytes
};
static_assert(sizeof(RetransmitSegmentRef) == 64, "RetransmitSegmentRef must be 64 bytes");

// ============================================================================
// RetransmitQueue - Circular queue of unacked segments
// Maps TCP sequence numbers to UMEM frame positions for retransmission
// ============================================================================

class RetransmitQueue {
public:
    static constexpr size_t MAX_SEGMENTS = 256;
    static constexpr uint64_t DEFAULT_RTO_US = 200000;  // 200ms initial RTO

    RetransmitQueue() = default;

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

    // Find the first segment with expired RTO
    // Returns nullptr if no segment has expired
    RetransmitSegmentRef* get_expired(uint64_t now_tsc, uint64_t rto_cycles) {
        if (head_ == tail_) {
            return nullptr;
        }

        // Check oldest segment first (most likely to be expired)
        RetransmitSegmentRef& seg = segments_[head_];
        if (now_tsc - seg.send_tsc >= rto_cycles) {
            return &seg;
        }

        return nullptr;
    }

    // Update send time after retransmit
    void mark_retransmitted(uint64_t now_tsc) {
        if (head_ != tail_) {
            segments_[head_].send_tsc = now_tsc;
            segments_[head_].retransmit_count++;
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
 *   SSLPolicy       - SSL policy class (default: PipelineSSLPolicy)
 *                     Must provide: feed_encrypted(), read(), write(), encrypted_pending(), get_encrypted()
 *   RawInboxCons    - IPCRingConsumer<UMEMFrameDescriptor>
 *   RawOutboxProd   - IPCRingProducer<UMEMFrameDescriptor>
 *   AckOutboxProd   - IPCRingProducer<AckDescriptor>
 *   PongOutboxProd  - IPCRingProducer<PongDescriptor>
 *   MsgOutboxCons   - IPCRingConsumer<MsgOutboxEvent>
 *   MsgMetadataProd - IPCRingProducer<MsgMetadata>
 *   PongsCons       - IPCRingConsumer<PongFrameAligned>
 */
template<typename SSLPolicy,
         typename RawInboxCons,
         typename RawOutboxProd,
         typename AckOutboxProd,
         typename PongOutboxProd,
         typename MsgOutboxCons,
         typename MsgMetadataProd,
         typename PongsCons>
struct TransportProcess {
    // ========================================================================
    // Initialization
    // ========================================================================

    /**
     * Initialize with handshake - performs TCP/TLS/WS handshake (fork-first architecture)
     *
     * This is the preferred init method for fork-first architecture where:
     * 1. XDP Poll has already created XSK socket and signaled ready
     * 2. Transport performs TCP/TLS/WebSocket handshake via IPC rings
     * 3. No inherited state - all created fresh in this process
     *
     * @param umem_area       Shared UMEM memory
     * @param frame_size      Size of each UMEM frame
     * @param target_host     Target hostname (e.g., "stream.binance.com")
     * @param target_port     Target port (e.g., 443)
     * @param target_path     Target path (e.g., "/stream")
     * @param subscription    Subscription JSON message
     * @param raw_inbox_cons  Consumer for RAW_INBOX ring
     * @param raw_outbox_prod Producer for RAW_OUTBOX ring
     * @param ack_outbox_prod Producer for ACK_OUTBOX ring
     * @param pong_outbox_prod Producer for PONG_OUTBOX ring
     * @param msg_outbox_cons Consumer for MSG_OUTBOX ring
     * @param msg_metadata_prod Producer for MSG_METADATA ring
     * @param pongs_cons      Consumer for PONGS ring
     * @param msg_inbox       MsgInbox for decrypted data
     * @param tcp_state       Shared TCP state structure
     */
    bool init_with_handshake(void* umem_area, uint32_t frame_size,
                             const char* target_host, uint16_t target_port,
                             const char* target_path, const char* subscription,
                             RawInboxCons* raw_inbox_cons,
                             RawOutboxProd* raw_outbox_prod,
                             AckOutboxProd* ack_outbox_prod,
                             PongOutboxProd* pong_outbox_prod,
                             MsgOutboxCons* msg_outbox_cons,
                             MsgMetadataProd* msg_metadata_prod,
                             PongsCons* pongs_cons,
                             MsgInbox* msg_inbox,
                             TCPStateShm* tcp_state) {

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
        tcp_state_ = tcp_state;

        fprintf(stderr, "[TRANSPORT] init_with_handshake() called\n");
        fflush(stderr);

        // Initialize timestamp tracking
        reset_timestamps();

        // Initialize retransmit queues
        retransmit_queue_.clear();
        pong_retransmit_queue_.clear();
        uint64_t tsc_freq = tcp_state_->tsc_freq_hz;
        rto_cycles_ = (RetransmitQueue::DEFAULT_RTO_US * tsc_freq) / 1000000;

        fprintf(stderr, "[TRANSPORT] Starting handshake to %s:%u%s\n", target_host, target_port, target_path);
        fflush(stderr);

        // Initialize userspace TCP stack with local network info from shared state
        {
            char local_ip_str[16], gateway_ip_str[16], netmask_str[16];
            // Local IP is stored in network byte order, convert to host for string conversion
            fprintf(stderr, "[TRANSPORT] tcp_state_->local_ip = 0x%08x\n", tcp_state_->local_ip);
            fflush(stderr);
            uint32_t local_ip_h = ntohl(tcp_state_->local_ip);
            snprintf(local_ip_str, sizeof(local_ip_str), "%u.%u.%u.%u",
                     (local_ip_h >> 24) & 0xFF, (local_ip_h >> 16) & 0xFF,
                     (local_ip_h >> 8) & 0xFF, local_ip_h & 0xFF);
            // Gateway - for now assume same subnet, use local IP with .1
            // TODO: This should be read from shared state or config
            snprintf(gateway_ip_str, sizeof(gateway_ip_str), "%u.%u.%u.1",
                     (local_ip_h >> 24) & 0xFF, (local_ip_h >> 16) & 0xFF,
                     (local_ip_h >> 8) & 0xFF);
            snprintf(netmask_str, sizeof(netmask_str), "255.255.255.0");
            fprintf(stderr, "[TRANSPORT] Initializing stack: local=%s gateway=%s\n", local_ip_str, gateway_ip_str);
            fflush(stderr);
            try {
                stack_.init(local_ip_str, gateway_ip_str, netmask_str, tcp_state_->local_mac);
                fprintf(stderr, "[TRANSPORT] Stack initialized successfully\n");
                fflush(stderr);
            } catch (const std::exception& e) {
                fprintf(stderr, "[TRANSPORT] Stack init exception: %s\n", e.what());
                fflush(stderr);
                return false;
            }
        }

        // Step 1: TCP handshake via IPC rings
        // This uses the userspace TCP stack to send SYN, receive SYN-ACK, send ACK
        if (!perform_tcp_handshake_via_ipc(target_host, target_port)) {
            fprintf(stderr, "[TRANSPORT] TCP handshake failed\n");
            return false;
        }
        tcp_state_->set_handshake_tcp_ready();
        printf("[TRANSPORT] TCP connected\n");

        // Step 2: TLS handshake
        if (!perform_tls_handshake_via_ipc(target_host)) {
            fprintf(stderr, "[TRANSPORT] TLS handshake failed\n");
            return false;
        }
        tcp_state_->set_handshake_tls_ready();
        printf("[TRANSPORT] TLS connected\n");

        // Step 3: WebSocket upgrade
        if (!perform_websocket_upgrade_via_ipc(target_host, target_path)) {
            fprintf(stderr, "[TRANSPORT] WebSocket upgrade failed\n");
            return false;
        }
        fprintf(stderr, "[TRANSPORT] WebSocket upgraded\n");
        fflush(stderr);

        // Step 4: Send subscription
        if (subscription && strlen(subscription) > 0) {
            if (!send_subscription_via_ipc(subscription)) {
                fprintf(stderr, "[TRANSPORT] Subscription failed\n");
                return false;
            }
            fprintf(stderr, "[TRANSPORT] Subscription sent\n");
            fflush(stderr);
        }

        fprintf(stderr, "[TRANSPORT] Handshake complete (RTO=%lu cycles)\n", rto_cycles_);
        fflush(stderr);
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
              TCPStateShm* tcp_state) {

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
        tcp_state_ = tcp_state;

        // Initialize timestamp tracking
        reset_timestamps();

        // Initialize retransmit queues
        retransmit_queue_.clear();
        pong_retransmit_queue_.clear();
        // Calculate RTO in TSC cycles: RTO_US * (TSC_freq_hz / 1,000,000)
        uint64_t tsc_freq = tcp_state_->tsc_freq_hz;
        rto_cycles_ = (RetransmitQueue::DEFAULT_RTO_US * tsc_freq) / 1000000;

        printf("[TRANSPORT] Initialized (RTO=%lu cycles)\n", rto_cycles_);
        return true;
    }

    // ========================================================================
    // Main Loop
    // ========================================================================

    void run() {
        printf("[TRANSPORT] Starting main loop\n");

        // Mark ourselves as ready so XDP Poll can start processing
        tcp_state_->set_ready(PROC_TRANSPORT);

        uint64_t loop_count = 0;
        uint64_t total_rx = 0;

        while (tcp_state_->is_running(PROC_TRANSPORT)) {
            loop_count++;

            // Debug: Print every 1M iterations
            if ((loop_count & 0xFFFFF) == 0) {
                fprintf(stderr, "[TRANSPORT] loops=%lu rx=%lu\n", loop_count, total_rx);
            }
            // 0. Check retransmit (highest priority)
            check_retransmit();

            // 1. TX: MSG_OUTBOX → SSL_write → RAW_OUTBOX
            process_tx();

            // 2. RX: RAW_INBOX → TCP parse → SSL_read → MSG_INBOX
            total_rx += process_rx();

            // 3. Adaptive ACK
            check_and_send_ack();

            // 4. PONG processing (idle work)
            process_pongs();
        }

        printf("[TRANSPORT] Main loop ended\n");
    }

    // ========================================================================
    // RX Path
    // ========================================================================

    uint32_t process_rx() {
        UMEMFrameDescriptor desc;
        uint32_t rx_count = 0;

        while (raw_inbox_cons_->try_consume(desc)) {
            rx_count++;
            // Update timestamp tracking
            if (!has_pending_timestamps_) {
                first_nic_timestamp_ns_ = desc.nic_timestamp_ns;
                first_raw_frame_poll_cycle_ = desc.nic_frame_poll_cycle;
                has_pending_timestamps_ = true;
            }
            latest_nic_timestamp_ns_ = desc.nic_timestamp_ns;
            latest_raw_frame_poll_cycle_ = desc.nic_frame_poll_cycle;

            // Parse TCP using TCPPacket::parse directly (we have all params in tcp_state_)
            uint8_t* frame = umem_area_ + desc.umem_addr;
            auto parsed = userspace_stack::TCPPacket::parse(
                frame, desc.frame_len,
                tcp_state_->local_ip,
                tcp_state_->local_port,
                tcp_state_->remote_ip,
                tcp_state_->remote_port);

            if (!parsed.valid) {
                static int invalid_debug_count = 0;
                if (invalid_debug_count < 10) {
                    fprintf(stderr, "[TRANSPORT] Invalid TCP packet (frame_len=%u umem_addr=%lu)\n",
                            desc.frame_len, desc.umem_addr);
                    fprintf(stderr, "[TRANSPORT] Expected: local=%u.%u.%u.%u:%u remote=%u.%u.%u.%u:%u\n",
                            (tcp_state_->local_ip >> 24) & 0xFF, (tcp_state_->local_ip >> 16) & 0xFF,
                            (tcp_state_->local_ip >> 8) & 0xFF, tcp_state_->local_ip & 0xFF,
                            tcp_state_->local_port,
                            (tcp_state_->remote_ip >> 24) & 0xFF, (tcp_state_->remote_ip >> 16) & 0xFF,
                            (tcp_state_->remote_ip >> 8) & 0xFF, tcp_state_->remote_ip & 0xFF,
                            tcp_state_->remote_port);

                    // Hexdump first 60 bytes of frame
                    fprintf(stderr, "[TRANSPORT] Frame hex dump:\n");
                    for (uint16_t i = 0; i < desc.frame_len && i < 60; i++) {
                        fprintf(stderr, "%02x ", frame[i]);
                        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
                    }
                    fprintf(stderr, "\n");

                    // Parse frame manually to see what's inside
                    if (desc.frame_len >= 34) {  // Eth (14) + IP (20) minimum
                        // Ethernet: dst_mac (6), src_mac (6), ethertype (2)
                        uint16_t ethertype = (frame[12] << 8) | frame[13];
                        fprintf(stderr, "[TRANSPORT] Ethertype: 0x%04x (IPv4=0x0800)\n", ethertype);

                        if (ethertype == 0x0800) {
                            // IP header starts at offset 14
                            uint8_t ip_proto = frame[23];
                            uint32_t src_ip = (frame[26] << 24) | (frame[27] << 16) | (frame[28] << 8) | frame[29];
                            uint32_t dst_ip = (frame[30] << 24) | (frame[31] << 16) | (frame[32] << 8) | frame[33];
                            fprintf(stderr, "[TRANSPORT] IP: proto=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
                                    ip_proto,
                                    (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF,
                                    (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);

                            if (ip_proto == 6 && desc.frame_len >= 54) {  // TCP (14+20+20)
                                uint16_t src_port = (frame[34] << 8) | frame[35];
                                uint16_t dst_port = (frame[36] << 8) | frame[37];
                                fprintf(stderr, "[TRANSPORT] TCP: src_port=%u dst_port=%u\n", src_port, dst_port);
                            }
                        }
                    }
                    invalid_debug_count++;
                }
                continue;  // Invalid packet, skip
            }

            // Update TCP state from ACK
            if (parsed.flags & userspace_stack::TCP_FLAG_ACK) {
                process_ack(parsed.ack, parsed.window);
            }

            // Check sequence number
            static int seq_debug_count = 0;
            if (seq_debug_count < 10) {
                fprintf(stderr, "[TRANSPORT] RX: seq=%u rcv_nxt=%u payload_len=%u\n",
                        parsed.seq, tcp_state_->rcv_nxt, parsed.payload_len);
                seq_debug_count++;
            }

            if (parsed.seq != tcp_state_->rcv_nxt) {
                // Out of order - send duplicate ACK immediately for fast retransmit (Gap N4)
                // This enables sender's fast retransmit mechanism (3 dup ACKs = retransmit)
                if (seq_debug_count <= 10) {
                    fprintf(stderr, "[TRANSPORT] Out of order! Expected %u got %u\n",
                            tcp_state_->rcv_nxt, parsed.seq);
                }
                send_ack();  // Immediate dup ACK, not waiting for threshold
                continue;
            }

            // Update rcv_nxt (plain assignment - Transport only)
            tcp_state_->rcv_nxt += parsed.payload_len;

            // Feed to BIO for SSL decryption
            if (parsed.payload_len > 0) {
                ssl_policy_.feed_encrypted(parsed.payload, parsed.payload_len);
            }

            packets_since_ack_++;

            // Attempt SSL_read
            ssl_read_to_msg_inbox();
        }

        return rx_count;
    }

    void ssl_read_to_msg_inbox() {
        uint8_t read_buf[16384];  // TLS record max size
        ssize_t ret;

        while ((ret = ssl_policy_.read(read_buf, sizeof(read_buf))) > 0) {
            uint64_t ssl_read_cycle = rdtsc();

            // Get current write position
            uint32_t write_offset = msg_inbox_->current_write_pos();

            // Check for wrap-around
            uint32_t linear = msg_inbox_->linear_space_to_wrap();
            if (static_cast<uint32_t>(ret) > linear) {
                // Need to wrap
                msg_inbox_->set_wrap_flag();
                msg_inbox_->reset_to_head();
                write_offset = 0;
            }

            // Write to MSG_INBOX
            memcpy(msg_inbox_->write_ptr(), read_buf, ret);
            msg_inbox_->advance_write(static_cast<uint32_t>(ret));

            // Publish metadata
            MsgMetadata meta;
            meta.first_nic_timestamp_ns = first_nic_timestamp_ns_;
            meta.first_raw_frame_poll_cycle = first_raw_frame_poll_cycle_;
            meta.latest_nic_timestamp_ns = latest_nic_timestamp_ns_;
            meta.latest_raw_frame_poll_cycle = latest_raw_frame_poll_cycle_;
            meta.ssl_read_cycle = ssl_read_cycle;
            meta.msg_inbox_offset = write_offset;
            meta.decrypted_len = static_cast<uint32_t>(ret);

            if (!msg_metadata_prod_->try_publish(meta)) {
                fprintf(stderr, "[TRANSPORT] FATAL: MSG_METADATA full\n");
                abort();
            }

            // Reset timestamps for next batch
            reset_timestamps();
        }

        // ret < 0 with errno == EAGAIN means need more data (normal for pipeline)
        if (ret < 0 && errno != EAGAIN) {
            fprintf(stderr, "[TRANSPORT] SSL read error: %s\n", strerror(errno));
        }
    }

    // ========================================================================
    // TX Path
    // ========================================================================

    void process_tx() {
        MsgOutboxEvent event;

        while (msg_outbox_cons_->try_consume(event)) {
            // Build WebSocket frame header
            uint8_t ws_header[14];
            uint8_t mask_key[4];
            generate_mask_key(mask_key);

            size_t header_len = build_ws_header(ws_header, event.opcode, event.data_len,
                                                true, true, mask_key);

            // Mask payload
            uint8_t masked_payload[2048];
            memcpy(masked_payload, event.data, event.data_len);
            unmask_payload(masked_payload, event.data_len, mask_key);

            // Build TLS record: header + masked payload
            uint8_t tls_plaintext[2048 + 14];
            memcpy(tls_plaintext, ws_header, header_len);
            memcpy(tls_plaintext + header_len, masked_payload, event.data_len);

            // SSL write via policy
            ssize_t ret = ssl_policy_.write(tls_plaintext, header_len + event.data_len);
            if (ret <= 0) {
                fprintf(stderr, "[TRANSPORT] SSL write error: %s\n", strerror(errno));
                continue;
            }

            // Read encrypted data from BIO and build TCP packet
            send_encrypted_data();
        }
    }

    void send_encrypted_data() {
        uint8_t encrypted[4096];
        size_t pending;

        while ((pending = ssl_policy_.encrypted_pending()) > 0) {
            ssize_t ret = ssl_policy_.get_encrypted(encrypted, sizeof(encrypted));
            if (ret <= 0) break;

            // Allocate MSG frame
            uint32_t frame_idx = allocate_msg_frame();
            if (frame_idx == UINT32_MAX) {
                fprintf(stderr, "[TRANSPORT] No MSG frames available\n");
                return;
            }

            // Build TCP packet in UMEM using UserspaceStack
            uint64_t umem_addr = frame_idx_to_addr(frame_idx, frame_size_);
            uint8_t* frame = umem_area_ + umem_addr;

            // Build TCPParams from current state
            auto params = build_tcp_params();
            uint32_t seq_start = params.snd_nxt;

            // Use TCPPacket::build directly (we have MAC addresses already)
            size_t frame_len = userspace_stack::TCPPacket::build(
                frame, frame_size_, params,
                userspace_stack::TCP_FLAG_PSH | userspace_stack::TCP_FLAG_ACK,
                encrypted, ret,
                tcp_state_->local_mac, tcp_state_->remote_mac,
                ip_id_++);
            if (frame_len == 0) {
                fprintf(stderr, "[TRANSPORT] Failed to build TCP packet\n");
                continue;
            }

            uint32_t seq_end = seq_start + ret;

            // Add to retransmit queue BEFORE publishing to RAW_OUTBOX
            uint64_t alloc_pos = tcp_state_->tx_frame.msg_alloc_pos.load(std::memory_order_relaxed);
            uint64_t now_tsc = rdtsc();

            RetransmitSegmentRef ref;
            ref.alloc_pos = alloc_pos;
            ref.send_tsc = now_tsc;
            ref.frame_idx = frame_idx;
            ref.seq_start = seq_start;
            ref.seq_end = seq_end;
            ref.frame_len = static_cast<uint16_t>(frame_len);
            ref.flags = userspace_stack::TCP_FLAG_PSH | userspace_stack::TCP_FLAG_ACK;
            ref.retransmit_count = 0;

            if (!retransmit_queue_.push(ref)) {
                fprintf(stderr, "[TRANSPORT] WARNING: Retransmit queue full\n");
            }

            // Publish to RAW_OUTBOX
            UMEMFrameDescriptor desc;
            desc.umem_addr = umem_addr;
            desc.frame_len = static_cast<uint16_t>(frame_len);
            desc.frame_type = FRAME_TYPE_MSG;
            desc.nic_frame_poll_cycle = now_tsc;
            desc.consumed = 0;

            if (!raw_outbox_prod_->try_publish(desc)) {
                fprintf(stderr, "[TRANSPORT] FATAL: RAW_OUTBOX full\n");
                abort();
            }

            // Update snd_nxt (plain assignment - Transport only)
            tcp_state_->snd_nxt = seq_end;
        }
    }

    // ========================================================================
    // ACK Processing
    // ========================================================================

    void process_ack(uint32_t ack_num, uint16_t window) {
        // Check if ACK advances snd_una (plain access - Transport only)
        int32_t advance = static_cast<int32_t>(ack_num - tcp_state_->snd_una);
        if (advance > 0) {
            tcp_state_->snd_una = ack_num;

            // Release ACKed MSG frames via retransmit queue
            // ack_up_to() removes all segments with seq_end <= ack_num
            // and returns the highest alloc_pos that was ACKed
            uint64_t msg_acked_pos = retransmit_queue_.ack_up_to(ack_num);
            if (msg_acked_pos > 0) {
                // Update msg_acked_pos so XDP Poll can release frames (atomic - cross-process)
                tcp_state_->tx_frame.msg_acked_pos.store(msg_acked_pos, std::memory_order_release);
            }

            // Release ACKed PONG frames via pong retransmit queue
            uint64_t pong_acked_pos = pong_retransmit_queue_.ack_up_to(ack_num);
            if (pong_acked_pos > 0) {
                // Update pong_acked_pos so XDP Poll can release frames (atomic - cross-process)
                tcp_state_->tx_frame.pong_acked_pos.store(pong_acked_pos, std::memory_order_release);
            }
        }

        // Update peer window (plain access - Transport only)
        tcp_state_->peer_recv_window = static_cast<uint32_t>(window) << tcp_state_->window_scale;
    }

    void check_and_send_ack() {
        // Debug: Print checks when we have packets pending
        static int check_debug_count = 0;
        if (check_debug_count < 20 && packets_since_ack_ > 0) {
            uint64_t now = rdtsc();
            uint64_t tsc_freq = tcp_state_->tsc_freq_hz;
            uint64_t elapsed_us = (tsc_freq > 0) ? cycles_to_ns(now - last_ack_cycle_, tsc_freq) / 1000 : 0;
            fprintf(stderr, "[TRANSPORT] check_ack: packets=%u elapsed_us=%lu threshold=%u timeout=%u\n",
                    packets_since_ack_, elapsed_us, ACK_PACKET_THRESHOLD, ACK_TIMEOUT_US);
            check_debug_count++;
        }

        if (packets_since_ack_ == 0) return;

        bool should_ack = false;

        // Check packet threshold
        if (packets_since_ack_ >= ACK_PACKET_THRESHOLD) {
            should_ack = true;
        }

        // Check timeout (100us)
        if (!should_ack) {
            uint64_t now = rdtsc();
            uint64_t tsc_freq = tcp_state_->tsc_freq_hz;
            if (tsc_freq > 0) {
                uint64_t elapsed_us = cycles_to_ns(now - last_ack_cycle_, tsc_freq) / 1000;
                if (elapsed_us >= ACK_TIMEOUT_US) {
                    should_ack = true;
                }
            }
        }

        if (should_ack) {
            send_ack();
        }
    }

    void send_ack() {
        // Debug: Print ACK attempt
        static int ack_attempt_count = 0;
        if (ack_attempt_count < 10) {
            fprintf(stderr, "[TRANSPORT] send_ack called (attempt=%d)\n", ack_attempt_count);
            ack_attempt_count++;
        }

        // Allocate ACK frame
        uint32_t frame_idx = allocate_ack_frame();
        if (frame_idx == UINT32_MAX) {
            static int alloc_fail_count = 0;
            if (alloc_fail_count < 10) {
                fprintf(stderr, "[TRANSPORT] ACK frame allocation failed!\n");
                alloc_fail_count++;
            }
            return;
        }

        uint64_t umem_addr = frame_idx_to_addr(frame_idx, frame_size_);
        uint8_t* frame = umem_area_ + umem_addr;

        // Build pure ACK using TCPPacket::build
        auto params = build_tcp_params();
        size_t frame_len = userspace_stack::TCPPacket::build(
            frame, frame_size_, params,
            userspace_stack::TCP_FLAG_ACK,
            nullptr, 0,
            tcp_state_->local_mac, tcp_state_->remote_mac,
            ip_id_++);
        if (frame_len == 0) return;

        // Publish to ACK_OUTBOX
        AckDescriptor desc;
        desc.umem_addr = umem_addr;
        desc.frame_len = static_cast<uint16_t>(frame_len);

        static int ack_debug_count = 0;
        if (ack_outbox_prod_->try_publish(desc)) {
            if (ack_debug_count < 10) {
                fprintf(stderr, "[TRANSPORT] ACK sent to ACK_OUTBOX (addr=%lu len=%u)\n",
                        umem_addr, frame_len);
                ack_debug_count++;
            }
            packets_since_ack_ = 0;
            last_ack_cycle_ = rdtsc();
        } else {
            if (ack_debug_count < 10) {
                fprintf(stderr, "[TRANSPORT] ACK_OUTBOX full!\n");
                ack_debug_count++;
            }
        }
    }

    // ========================================================================
    // PONG Processing (Idle Work)
    // ========================================================================

    void process_pongs() {
        PongFrameAligned pong;

        // Process at most one PONG per iteration (low priority)
        if (!pongs_cons_->try_consume(pong)) return;

        // Build WebSocket PONG frame
        uint8_t ws_header[14];
        uint8_t mask_key[4];
        generate_mask_key(mask_key);

        size_t header_len = build_ws_header(ws_header, WS_OP_PONG, pong.payload_len,
                                            true, true, mask_key);

        // Mask payload
        uint8_t masked[125];
        memcpy(masked, pong.payload, pong.payload_len);
        unmask_payload(masked, pong.payload_len, mask_key);

        // Encrypt via SSL policy
        uint8_t plaintext[139];
        memcpy(plaintext, ws_header, header_len);
        memcpy(plaintext + header_len, masked, pong.payload_len);

        ssize_t ret = ssl_policy_.write(plaintext, header_len + pong.payload_len);
        if (ret <= 0) return;

        // Read encrypted and send via PONG_OUTBOX
        uint8_t encrypted[256];
        size_t pending = ssl_policy_.encrypted_pending();
        if (pending == 0) return;

        ret = ssl_policy_.get_encrypted(encrypted, sizeof(encrypted));
        if (ret <= 0) return;

        // Allocate PONG frame
        uint32_t frame_idx = allocate_pong_frame();
        if (frame_idx == UINT32_MAX) return;

        uint64_t umem_addr = frame_idx_to_addr(frame_idx, frame_size_);
        uint8_t* frame = umem_area_ + umem_addr;

        // Build TCP packet using TCPPacket::build
        auto params = build_tcp_params();
        uint32_t seq_start = params.snd_nxt;
        size_t frame_len = userspace_stack::TCPPacket::build(
            frame, frame_size_, params,
            userspace_stack::TCP_FLAG_PSH | userspace_stack::TCP_FLAG_ACK,
            encrypted, ret,
            tcp_state_->local_mac, tcp_state_->remote_mac,
            ip_id_++);
        if (frame_len == 0) return;

        uint32_t seq_end = seq_start + ret;

        // Update snd_nxt for PONG data
        tcp_state_->snd_nxt = seq_end;

        // Add to PONG retransmit queue for TCP reliability
        uint64_t alloc_pos = tcp_state_->tx_frame.pong_alloc_pos.load(std::memory_order_relaxed);
        uint64_t now_tsc = rdtsc();

        RetransmitSegmentRef ref;
        ref.alloc_pos = alloc_pos;
        ref.send_tsc = now_tsc;
        ref.frame_idx = frame_idx;
        ref.seq_start = seq_start;
        ref.seq_end = seq_end;
        ref.frame_len = static_cast<uint16_t>(frame_len);
        ref.flags = userspace_stack::TCP_FLAG_PSH | userspace_stack::TCP_FLAG_ACK;
        ref.retransmit_count = 0;

        if (!pong_retransmit_queue_.push(ref)) {
            fprintf(stderr, "[TRANSPORT] WARNING: PONG retransmit queue full\n");
        }

        // Publish to PONG_OUTBOX
        PongDescriptor desc;
        desc.umem_addr = umem_addr;
        desc.frame_len = static_cast<uint16_t>(frame_len);

        pong_outbox_prod_->try_publish(desc);
    }

    // ========================================================================
    // Retransmit
    // ========================================================================

    void check_retransmit() {
        uint64_t now_tsc = rdtsc();

        // Check MSG retransmit queue
        check_retransmit_queue(retransmit_queue_, FRAME_TYPE_MSG, "MSG", now_tsc);

        // Check PONG retransmit queue
        check_retransmit_queue(pong_retransmit_queue_, FRAME_TYPE_PONG, "PONG", now_tsc);
    }

    void check_retransmit_queue(RetransmitQueue& queue, uint8_t frame_type,
                                const char* name, uint64_t now_tsc) {
        if (queue.empty()) {
            return;
        }

        RetransmitSegmentRef* seg = queue.get_expired(now_tsc, rto_cycles_);
        if (!seg) {
            return;
        }

        // Segment has timed out - retransmit it
        // The frame is still in UMEM at seg->frame_idx, we just need to re-queue it

        UMEMFrameDescriptor desc;
        desc.umem_addr = static_cast<uint64_t>(seg->frame_idx) * frame_size_;
        desc.frame_len = seg->frame_len;
        desc.frame_type = frame_type;
        desc.nic_timestamp_ns = 0;  // No NIC timestamp for retransmit
        desc.nic_frame_poll_cycle = now_tsc;
        desc.consumed = 0;

        if (raw_outbox_prod_->try_publish(desc)) {
            // Update retransmit state
            queue.mark_retransmitted(now_tsc);

            printf("[TRANSPORT] %s Retransmit: seq=%u-%u frame=%u count=%u\n",
                   name, seg->seq_start, seg->seq_end, seg->frame_idx, seg->retransmit_count);
        }
        // If publish fails (ring full), we'll retry on next iteration
    }

    // ========================================================================
    // Frame Allocation
    // ========================================================================

    uint32_t allocate_ack_frame() {
        uint32_t pos = tcp_state_->tx_frame.ack_alloc_pos.fetch_add(1, std::memory_order_relaxed);
        uint32_t rel = tcp_state_->tx_frame.ack_release_pos.load(std::memory_order_acquire);
        if (pos - rel >= ACK_FRAMES) {
            tcp_state_->tx_frame.ack_alloc_pos.fetch_sub(1, std::memory_order_relaxed);
            return UINT32_MAX;
        }
        return ACK_POOL_START + (pos % ACK_FRAMES);
    }

    uint32_t allocate_pong_frame() {
        uint32_t pos = tcp_state_->tx_frame.pong_alloc_pos.fetch_add(1, std::memory_order_relaxed);
        uint32_t rel = tcp_state_->tx_frame.pong_release_pos.load(std::memory_order_acquire);
        if (pos - rel >= PONG_FRAMES) {
            tcp_state_->tx_frame.pong_alloc_pos.fetch_sub(1, std::memory_order_relaxed);
            return UINT32_MAX;
        }
        return PONG_POOL_START + (pos % PONG_FRAMES);
    }

    uint32_t allocate_msg_frame() {
        uint32_t pos = tcp_state_->tx_frame.msg_alloc_pos.fetch_add(1, std::memory_order_relaxed);
        uint32_t rel = tcp_state_->tx_frame.msg_release_pos.load(std::memory_order_acquire);
        if (pos - rel >= MSG_FRAMES) {
            tcp_state_->tx_frame.msg_alloc_pos.fetch_sub(1, std::memory_order_relaxed);
            return UINT32_MAX;
        }
        return MSG_POOL_START + (pos % MSG_FRAMES);
    }

    // ========================================================================
    // TCP Params Helper (builds TCPParams from shared state)
    // ========================================================================

    userspace_stack::TCPParams build_tcp_params() const {
        userspace_stack::TCPParams params;
        // IPs in shared state are network byte order, stack expects host byte order
        params.local_ip = ntohl(tcp_state_->local_ip);
        params.remote_ip = ntohl(tcp_state_->remote_ip);
        params.local_port = tcp_state_->local_port;
        params.remote_port = tcp_state_->remote_port;
        params.snd_nxt = tcp_state_->snd_nxt;
        params.rcv_nxt = tcp_state_->rcv_nxt;
        params.rcv_wnd = 65535;  // Advertise full window
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
        fprintf(stderr, "[TRANSPORT] TCP handshake to %s:%u via IPC\n", target_host, target_port);
        fflush(stderr);

        // Resolve hostname to IP
        struct addrinfo hints = {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        int gai_ret = getaddrinfo(target_host, nullptr, &hints, &res);
        if (gai_ret != 0 || !res) {
            fprintf(stderr, "[TRANSPORT] DNS resolution failed: %s\n", gai_strerror(gai_ret));
            return false;
        }
        uint32_t remote_ip = ntohl(reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr.s_addr);
        freeaddrinfo(res);
        fprintf(stderr, "[TRANSPORT] Resolved %s to %u.%u.%u.%u\n", target_host,
               (remote_ip >> 24) & 0xFF, (remote_ip >> 16) & 0xFF,
               (remote_ip >> 8) & 0xFF, remote_ip & 0xFF);
        fflush(stderr);

        // Initialize TCP params
        tcp_params_.remote_ip = remote_ip;
        tcp_params_.remote_port = target_port;
        tcp_params_.local_ip = ntohl(tcp_state_->local_ip);
        tcp_params_.local_port = userspace_stack::UserspaceStack::generate_port();
        tcp_params_.snd_nxt = userspace_stack::UserspaceStack::generate_isn();
        tcp_params_.snd_una = tcp_params_.snd_nxt;
        tcp_params_.rcv_nxt = 0;
        tcp_params_.snd_wnd = userspace_stack::TCP_MAX_WINDOW;
        tcp_params_.rcv_wnd = userspace_stack::TCP_MAX_WINDOW;

        // Store in shared state for later use
        tcp_state_->local_port = tcp_params_.local_port;
        tcp_state_->remote_port = target_port;
        tcp_state_->remote_ip = htonl(remote_ip);

        fprintf(stderr, "[TRANSPORT] TCP params: local=%u.%u.%u.%u:%u remote=%u.%u.%u.%u:%u ISN=%u\n",
               (tcp_params_.local_ip >> 24) & 0xFF, (tcp_params_.local_ip >> 16) & 0xFF,
               (tcp_params_.local_ip >> 8) & 0xFF, tcp_params_.local_ip & 0xFF, tcp_params_.local_port,
               (tcp_params_.remote_ip >> 24) & 0xFF, (tcp_params_.remote_ip >> 16) & 0xFF,
               (tcp_params_.remote_ip >> 8) & 0xFF, tcp_params_.remote_ip & 0xFF, tcp_params_.remote_port,
               tcp_params_.snd_nxt);
        fflush(stderr);

        // Allocate frame for SYN
        uint32_t syn_frame_idx = allocate_msg_frame();
        if (syn_frame_idx == UINT32_MAX) {
            fprintf(stderr, "[TRANSPORT] Failed to allocate SYN frame\n");
            return false;
        }
        uint64_t syn_addr = frame_idx_to_addr(syn_frame_idx, frame_size_);
        uint8_t* syn_buffer = umem_area_ + syn_addr;

        // Build SYN packet
        size_t syn_len = stack_.build_syn(syn_buffer, frame_size_, tcp_params_);
        if (syn_len == 0) {
            fprintf(stderr, "[TRANSPORT] Failed to build SYN packet\n");
            return false;
        }
        fprintf(stderr, "[TRANSPORT] Built SYN packet (len=%zu)\n", syn_len);
        fflush(stderr);

        // Send SYN via RAW_OUTBOX
        UMEMFrameDescriptor syn_desc;
        syn_desc.umem_addr = syn_addr;
        syn_desc.frame_len = static_cast<uint16_t>(syn_len);
        syn_desc.frame_type = FRAME_TYPE_MSG;
        syn_desc.nic_frame_poll_cycle = rdtsc();
        syn_desc.consumed = 0;
        if (!raw_outbox_prod_->try_publish(syn_desc)) {
            fprintf(stderr, "[TRANSPORT] Failed to publish SYN to RAW_OUTBOX\n");
            return false;
        }
        tcp_params_.snd_nxt++;  // SYN consumes 1 seq
        fprintf(stderr, "[TRANSPORT] SYN sent, waiting for SYN-ACK...\n");
        fflush(stderr);

        // Wait for SYN-ACK via RAW_INBOX
        auto start = std::chrono::steady_clock::now();
        constexpr int timeout_ms = 5000;
        bool got_synack = false;

        while (!got_synack) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed >= timeout_ms) {
                fprintf(stderr, "[TRANSPORT] SYN-ACK timeout after %ldms\n", elapsed);
                return false;
            }

            UMEMFrameDescriptor rx_desc;
            if (raw_inbox_cons_->try_consume(rx_desc)) {
                uint8_t* frame = umem_area_ + rx_desc.umem_addr;
                auto parsed = stack_.parse_tcp(frame, rx_desc.frame_len,
                                               tcp_params_.local_port,
                                               tcp_params_.remote_ip,
                                               tcp_params_.remote_port);
                if (parsed.valid && (parsed.flags & userspace_stack::TCP_FLAG_SYN) &&
                    (parsed.flags & userspace_stack::TCP_FLAG_ACK)) {
                    // Got SYN-ACK
                    fprintf(stderr, "[TRANSPORT] Received SYN-ACK (seq=%u ack=%u)\n", parsed.seq, parsed.ack);
                    fflush(stderr);
                    tcp_params_.rcv_nxt = parsed.seq + 1;  // SYN consumes 1 seq
                    tcp_params_.snd_una = parsed.ack;
                    tcp_state_->rcv_nxt = tcp_params_.rcv_nxt;
                    tcp_state_->snd_una = tcp_params_.snd_una;
                    tcp_state_->snd_nxt = tcp_params_.snd_nxt;
                    tcp_state_->peer_recv_window = parsed.window;
                    got_synack = true;
                } else if (parsed.valid) {
                    fprintf(stderr, "[TRANSPORT] Got unexpected packet flags=0x%02x\n", parsed.flags);
                    fflush(stderr);
                }
            }
            usleep(100);
        }

        // Send ACK to complete 3-way handshake
        uint32_t ack_frame_idx = allocate_ack_frame();
        if (ack_frame_idx == UINT32_MAX) {
            fprintf(stderr, "[TRANSPORT] Failed to allocate ACK frame\n");
            return false;
        }
        uint64_t ack_addr = frame_idx_to_addr(ack_frame_idx, frame_size_);
        uint8_t* ack_buffer = umem_area_ + ack_addr;

        size_t ack_len = stack_.build_ack(ack_buffer, frame_size_, tcp_params_);
        if (ack_len == 0) {
            fprintf(stderr, "[TRANSPORT] Failed to build ACK packet\n");
            return false;
        }

        AckDescriptor ack_desc;
        ack_desc.umem_addr = ack_addr;
        ack_desc.frame_len = static_cast<uint16_t>(ack_len);
        if (!ack_outbox_prod_->try_publish(ack_desc)) {
            fprintf(stderr, "[TRANSPORT] Failed to publish ACK\n");
            return false;
        }

        fprintf(stderr, "[TRANSPORT] TCP ESTABLISHED (snd_nxt=%u rcv_nxt=%u)\n",
               tcp_params_.snd_nxt, tcp_params_.rcv_nxt);
        fflush(stderr);
        return true;
    }

    /**
     * Perform TLS handshake via IPC rings
     * Uses PipelineSSLPolicy with memory buffers, IPC rings for network I/O
     */
    bool perform_tls_handshake_via_ipc(const char* target_host) {
        fprintf(stderr, "[TRANSPORT] TLS handshake to %s via IPC\n", target_host);
        fflush(stderr);

        // Initialize SSL policy (creates context and SSL object)
        ssl_policy_.init();

        // Set SNI (Server Name Indication)
#ifdef SSL_POLICY_WOLFSSL
        wolfSSL_UseSNI(ssl_policy_.ssl(), WOLFSSL_SNI_HOST_NAME,
                       target_host, static_cast<unsigned short>(strlen(target_host)));
#endif

        // Perform non-blocking TLS handshake loop
        auto start = std::chrono::steady_clock::now();
        constexpr int timeout_ms = 10000;
        bool handshake_complete = false;

        while (!handshake_complete) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed >= timeout_ms) {
                fprintf(stderr, "[TRANSPORT] TLS handshake timeout after %ldms\n", elapsed);
                return false;
            }

            // Try to advance handshake
#ifdef SSL_POLICY_WOLFSSL
            int ret = wolfSSL_connect(ssl_policy_.ssl());
            if (ret == WOLFSSL_SUCCESS) {
                handshake_complete = true;
                break;
            }

            int err = wolfSSL_get_error(ssl_policy_.ssl(), ret);
            if (err == WOLFSSL_ERROR_WANT_READ) {
                // Need to receive data from network
                if (!tls_handshake_recv()) {
                    usleep(100);
                }
            } else if (err == WOLFSSL_ERROR_WANT_WRITE) {
                // Need to send data to network
                if (!tls_handshake_send()) {
                    usleep(100);
                }
            } else {
                char err_buf[256];
                wolfSSL_ERR_error_string(err, err_buf);
                fprintf(stderr, "[TRANSPORT] TLS handshake error: %s (err=%d)\n", err_buf, err);
                return false;
            }
#else
            fprintf(stderr, "[TRANSPORT] TLS handshake requires WolfSSL\n");
            return false;
#endif

            // Always check for pending outbound data and send it
            tls_handshake_send();
        }

        fprintf(stderr, "[TRANSPORT] TLS handshake complete\n");
        fflush(stderr);
        return true;
    }

    // Helper: Send pending encrypted data via IPC during TLS handshake
    bool tls_handshake_send() {
        size_t pending = ssl_policy_.encrypted_pending();
        if (pending == 0) return false;

        uint8_t encrypted[4096];
        ssize_t ret = ssl_policy_.get_encrypted(encrypted, sizeof(encrypted));
        if (ret <= 0) return false;

        // Allocate frame and build TCP packet
        uint32_t frame_idx = allocate_msg_frame();
        if (frame_idx == UINT32_MAX) return false;

        uint64_t addr = frame_idx_to_addr(frame_idx, frame_size_);
        uint8_t* frame = umem_area_ + addr;

        size_t frame_len = stack_.build_data(frame, frame_size_, tcp_params_,
                                              encrypted, static_cast<size_t>(ret));
        if (frame_len == 0) return false;

        // Publish to RAW_OUTBOX
        UMEMFrameDescriptor desc;
        desc.umem_addr = addr;
        desc.frame_len = static_cast<uint16_t>(frame_len);
        desc.frame_type = FRAME_TYPE_MSG;
        desc.nic_frame_poll_cycle = rdtsc();
        desc.consumed = 0;
        if (!raw_outbox_prod_->try_publish(desc)) return false;

        tcp_params_.snd_nxt += ret;
        tcp_state_->snd_nxt = tcp_params_.snd_nxt;
        return true;
    }

    // Helper: Receive encrypted data via IPC during TLS handshake
    bool tls_handshake_recv() {
        UMEMFrameDescriptor rx_desc;
        if (!raw_inbox_cons_->try_consume(rx_desc)) return false;

        uint8_t* frame = umem_area_ + rx_desc.umem_addr;
        auto parsed = stack_.parse_tcp(frame, rx_desc.frame_len,
                                        tcp_params_.local_port,
                                        tcp_params_.remote_ip,
                                        tcp_params_.remote_port);
        if (!parsed.valid) return false;

        // Update ACK tracking
        if (parsed.flags & userspace_stack::TCP_FLAG_ACK) {
            tcp_params_.snd_una = parsed.ack;
            tcp_state_->snd_una = parsed.ack;
        }

        // Update receive sequence
        if (parsed.payload_len > 0) {
            tcp_params_.rcv_nxt += parsed.payload_len;
            tcp_state_->rcv_nxt = tcp_params_.rcv_nxt;
            // Feed encrypted data to SSL
            ssl_policy_.feed_encrypted(parsed.payload, parsed.payload_len);
            // Send ACK
            send_ack_during_handshake();
        }

        return parsed.payload_len > 0;
    }

    // Helper: Send ACK during handshake
    void send_ack_during_handshake() {
        uint32_t frame_idx = allocate_ack_frame();
        if (frame_idx == UINT32_MAX) return;

        uint64_t addr = frame_idx_to_addr(frame_idx, frame_size_);
        uint8_t* frame = umem_area_ + addr;

        size_t len = stack_.build_ack(frame, frame_size_, tcp_params_);
        if (len == 0) return;

        AckDescriptor desc;
        desc.umem_addr = addr;
        desc.frame_len = static_cast<uint16_t>(len);
        ack_outbox_prod_->try_publish(desc);
    }

    /**
     * Perform WebSocket upgrade via SSL/IPC
     */
    bool perform_websocket_upgrade_via_ipc(const char* target_host, const char* target_path) {
        fprintf(stderr, "[TRANSPORT] WebSocket upgrade to %s%s via IPC\n", target_host, target_path);
        fflush(stderr);

        // Generate WebSocket key
        char ws_key[32];
        generate_websocket_key(ws_key);

        // Build HTTP upgrade request
        char request[1024];
        int req_len = snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n",
            target_path, target_host, ws_key);

        // Send via SSL
        ssize_t written = ssl_policy_.write(request, req_len);
        if (written != req_len) {
            fprintf(stderr, "[TRANSPORT] Failed to write WS upgrade request\n");
            return false;
        }

        // Send encrypted data
        if (!tls_handshake_send()) {
            fprintf(stderr, "[TRANSPORT] Failed to send WS upgrade\n");
            return false;
        }

        // Wait for 101 response
        auto start = std::chrono::steady_clock::now();
        constexpr int timeout_ms = 5000;
        char response[2048];
        size_t response_len = 0;

        while (true) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
            if (elapsed >= timeout_ms) {
                fprintf(stderr, "[TRANSPORT] WS upgrade timeout\n");
                return false;
            }

            // Receive data
            if (tls_handshake_recv()) {
                // Try to read decrypted response
                ssize_t ret = ssl_policy_.read(response + response_len,
                                               sizeof(response) - response_len - 1);
                if (ret > 0) {
                    response_len += ret;
                    response[response_len] = '\0';

                    // Check for complete response
                    if (strstr(response, "\r\n\r\n")) {
                        if (strstr(response, "101")) {
                            fprintf(stderr, "[TRANSPORT] WebSocket upgraded (got 101)\n");
                            fflush(stderr);
                            return true;
                        } else {
                            fprintf(stderr, "[TRANSPORT] WS upgrade rejected: %s\n", response);
                            return false;
                        }
                    }
                }
            }
            usleep(100);
        }
    }

    /**
     * Send subscription message via SSL/IPC
     */
    bool send_subscription_via_ipc(const char* msg) {
        fprintf(stderr, "[TRANSPORT] Sending subscription: %.60s...\n", msg);
        fflush(stderr);

        size_t msg_len = strlen(msg);

        // Build WebSocket text frame
        uint8_t ws_frame[4096];
        size_t frame_len = 0;

        // Build frame header (masked client frame)
        ws_frame[0] = 0x81;  // FIN + TEXT opcode
        uint8_t mask_key[4];
        generate_mask_key(mask_key);

        if (msg_len <= 125) {
            ws_frame[1] = 0x80 | static_cast<uint8_t>(msg_len);  // MASK + length
            frame_len = 2;
        } else if (msg_len <= 65535) {
            ws_frame[1] = 0x80 | 126;
            ws_frame[2] = static_cast<uint8_t>(msg_len >> 8);
            ws_frame[3] = static_cast<uint8_t>(msg_len & 0xFF);
            frame_len = 4;
        } else {
            fprintf(stderr, "[TRANSPORT] Subscription too long\n");
            return false;
        }

        // Add mask key
        memcpy(ws_frame + frame_len, mask_key, 4);
        frame_len += 4;

        // Add masked payload
        for (size_t i = 0; i < msg_len; i++) {
            ws_frame[frame_len + i] = msg[i] ^ mask_key[i % 4];
        }
        frame_len += msg_len;

        // Send via SSL
        ssize_t written = ssl_policy_.write(ws_frame, frame_len);
        if (written != static_cast<ssize_t>(frame_len)) {
            fprintf(stderr, "[TRANSPORT] Failed to write subscription\n");
            return false;
        }

        // Send encrypted data
        if (!tls_handshake_send()) {
            fprintf(stderr, "[TRANSPORT] Failed to send subscription\n");
            return false;
        }

        fprintf(stderr, "[TRANSPORT] Subscription sent (%zu bytes)\n", frame_len);
        fflush(stderr);
        return true;
    }

    // Helper: Generate WebSocket key
    void generate_websocket_key(char* key) {
        uint8_t bytes[16];
        for (int i = 0; i < 16; i++) {
            bytes[i] = rdtsc() & 0xFF;
        }

        static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0, j = 0; i < 15; i += 3, j += 4) {
            uint32_t n = (bytes[i] << 16) | (bytes[i+1] << 8) | bytes[i+2];
            key[j] = b64[(n >> 18) & 63];
            key[j+1] = b64[(n >> 12) & 63];
            key[j+2] = b64[(n >> 6) & 63];
            key[j+3] = b64[n & 63];
        }
        uint32_t n = bytes[15] << 16;
        key[20] = b64[(n >> 18) & 63];
        key[21] = b64[(n >> 12) & 63];
        key[22] = '=';
        key[23] = '=';
        key[24] = '\0';
    }

    // ========================================================================
    // General Helpers
    // ========================================================================

    void reset_timestamps() {
        has_pending_timestamps_ = false;
        first_nic_timestamp_ns_ = 0;
        first_raw_frame_poll_cycle_ = 0;
        latest_nic_timestamp_ns_ = 0;
        latest_raw_frame_poll_cycle_ = 0;
    }

    // Accessors
    SSLPolicy& ssl_policy() { return ssl_policy_; }
    const SSLPolicy& ssl_policy() const { return ssl_policy_; }

    // State
    uint8_t* umem_area_ = nullptr;
    uint32_t frame_size_ = 0;
    SSLPolicy ssl_policy_;  // SSL policy with memory BIOs

    // Ring pointers (each with proper element type)
    RawInboxCons* raw_inbox_cons_ = nullptr;
    RawOutboxProd* raw_outbox_prod_ = nullptr;
    AckOutboxProd* ack_outbox_prod_ = nullptr;
    PongOutboxProd* pong_outbox_prod_ = nullptr;
    MsgOutboxCons* msg_outbox_cons_ = nullptr;
    MsgMetadataProd* msg_metadata_prod_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;
    MsgInbox* msg_inbox_ = nullptr;
    TCPStateShm* tcp_state_ = nullptr;

    // Timestamp tracking
    bool has_pending_timestamps_ = false;
    uint64_t first_nic_timestamp_ns_ = 0;
    uint64_t first_raw_frame_poll_cycle_ = 0;
    uint64_t latest_nic_timestamp_ns_ = 0;
    uint64_t latest_raw_frame_poll_cycle_ = 0;

    // ACK state
    uint32_t packets_since_ack_ = 0;
    uint64_t last_ack_cycle_ = 0;

    // Retransmit state - separate queues for MSG and PONG frames
    RetransmitQueue retransmit_queue_;       // MSG frames
    RetransmitQueue pong_retransmit_queue_;  // PONG frames
    uint64_t rto_cycles_ = 0;  // Calculated from TSC frequency in init()

    // IP identification counter for outgoing packets
    uint16_t ip_id_ = 0;

    // Userspace TCP stack for building/parsing packets (fork-first handshake)
    userspace_stack::UserspaceStack stack_;
    userspace_stack::TCPParams tcp_params_;
};

}  // namespace websocket::pipeline
