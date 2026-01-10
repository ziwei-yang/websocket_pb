# Pipeline Process 1: Transport (Core 4)

**Related Documents**:
- [Architecture Overview](pipeline_architecture.md)
- [XDP Poll Process (Core 2)](pipeline_0_nic.md)
- [WebSocket Process (Core 6)](pipeline_2_ws.md)
- [AppClient Process (Core 8)](pipeline_3_app.md)

---

## Overview

Transport Process handles the **full ETH/IP/TCP stack** and **SSL/TLS encryption/decryption**. All protocol parsing/building happens here - decoupled from NIC layer.

**Key Responsibilities**:
1. **Fork-first handshake**: Performs TCP/TLS/WS handshake via IPC rings (new)
2. TCP retransmission (highest priority)
3. TX: Encrypt outbound WS messages → build TCP packets → RAW_OUTBOX
4. RX: Parse TCP packets → decrypt via SSL → write to MSG_INBOX
5. Adaptive ACK batching
6. PONG encryption for WebSocket ping responses

**Fork-First Architecture**: In the fork-first approach, Transport is forked BEFORE any network activity.
Transport waits for XDP Poll to signal `xdp_ready`, then performs TCP/TLS/WS handshake via IPC rings,
sends subscription, and finally signals `ws_ready` before entering the main loop.

---

## Code Reuse

```cpp
// Disruptor IPC (from 01_shared_headers/disruptor/)
#include <disruptor/disruptor.hpp>        // ring_buffer, sequencer, event_processor

// TCP/IP Stack
#include <stack/userspace_stack.hpp>      // UserspaceStack
#include <stack/tcp/tcp_state.hpp>        // TCPState, TCPParams, TCPParseResult, TCP_FLAG_*
#include <stack/tcp/tcp_retransmit.hpp>   // ZeroCopyRetransmitQueue, RetransmitSegmentRef
#include <stack/ip/checksum.hpp>          // ip_checksum(), tcp_checksum()

// SSL/TLS Policy (policy-based design)
#include <policy/ssl.hpp>                     // OpenSSLPolicy, LibreSSLPolicy, WolfSSLPolicy
#include <policy/userspace_transport_bio.hpp> // UserspaceTransportBIO - bridges SSL to userspace TCP

// WebSocket & Timing
#include <core/http.hpp>                  // build_websocket_header_zerocopy(), build_pong_frame()
#include <core/timing.hpp>                // rdtsc(), rdtscp()
```

---

## SSL Policy Design

**Design Decision**: SSL/TLS operations are policy-based to support multiple SSL libraries (OpenSSL, LibreSSL, WolfSSL) and transport modes (BSD socket, userspace TCP).

### Existing SSL Policies

All SSL implementations are in `src/policy/ssl.hpp`:

| Policy | Library | Features |
|--------|---------|----------|
| `OpenSSLPolicy` | OpenSSL | kTLS support (Linux), industry standard |
| `LibreSSLPolicy` | LibreSSL | macOS default, OpenSSL-compatible |
| `WolfSSLPolicy` | WolfSSL | Lightweight, embedded-friendly |
| `NoSSLPolicy` | None | Pass-through for unencrypted transports |

### SSLPolicyConcept Interface

All SSL policies implement this interface:
```cpp
struct SSLPolicy {
    void init();                                  // Initialize SSL context
    void handshake(int fd);                       // BSD socket handshake
    void handshake_userspace_transport(T* tp);    // Userspace TCP handshake
    ssize_t read(void* buf, size_t len);          // Decrypt and read
    ssize_t write(const void* buf, size_t len);   // Encrypt and write
    size_t pending() const;                       // Bytes buffered in SSL
    bool ktls_enabled() const;                    // kTLS status
    int get_fd() const;                           // Underlying socket fd
    void shutdown();                              // Close SSL session
    void cleanup();                               // Full cleanup
};
```

### Userspace Transport BIO

For XDP/AF_XDP mode, SSL operates over userspace TCP via `UserspaceTransportBIO` (`src/policy/userspace_transport_bio.hpp`):

```
SSL_read()  → bio_read()  → transport.recv() → TCP stream data from userspace stack
SSL_write() → bio_write() → transport.send() → TCP stream data to userspace stack
```

**TransportPolicy requirements**:
```cpp
struct TransportPolicy {
    ssize_t send(const void* buf, size_t len);  // Send TCP stream data
    ssize_t recv(void* buf, size_t len);        // Receive TCP stream data
    void poll();                                 // Poll for network events
};
```

### Transport Process SSL Usage

Transport Process uses SSL policy for TLS encryption/decryption:

```cpp
template<typename SSLPolicy = OpenSSLPolicy>
class TransportProcess {
    SSLPolicy ssl_;

    void init_ssl(XDPUserspaceTransport* transport) {
        ssl_.init();
        ssl_.handshake_userspace_transport(transport);
    }

    // Use ssl_.read() and ssl_.write() in main loop
    // (already shown in ssl_read_to_msg_inbox() and send_encrypted_packet())
};
```

### WolfSSL Native I/O (No BIO)

WolfSSL uses native I/O callbacks instead of BIO abstraction:
```cpp
wolfSSL_CTX_SetIORecv(ctx_, WolfSSLUserspaceIO<TransportPolicy>::recv_cb);
wolfSSL_CTX_SetIOSend(ctx_, WolfSSLUserspaceIO<TransportPolicy>::send_cb);
wolfSSL_SetIOReadCtx(ssl_, transport);
wolfSSL_SetIOWriteCtx(ssl_, transport);
```

This avoids the need for `OPENSSL_EXTRA` compile flag and is more lightweight.

---

## Class Definition (Fork-First Architecture)

```cpp
// Protocol header sizes (from stack)
constexpr size_t ETH_HEADER_LEN = 14;
constexpr size_t IP_HEADER_LEN = 20;
constexpr size_t TCP_HEADER_LEN = 20;  // Minimum, can be up to 60 with options
constexpr size_t TLS_RECORD_MAX_SIZE = 16384 + 256;  // 16KB + overhead for TLS record

template<typename SSLPolicy = WolfSSLPolicy>
class TransportProcess {
    // Stack instance (initialized in init_with_handshake)
    userspace_stack::UserspaceStack stack_;
    ZeroCopyRetransmitQueue retransmit_queue_;       // MSG frame retransmit queue
    ZeroCopyRetransmitQueue pong_retransmit_queue_;  // PONG frame retransmit queue (separate)

    // SSL/TLS policy (created and owned in fork-first architecture)
    SSLPolicy ssl_policy_;

    // For WolfSSL: Native I/O callbacks (no BIO)
    // For OpenSSL: Memory BIO pair below
#ifdef USE_WOLFSSL
    // WolfSSL uses native I/O callbacks via ssl_policy_
#else
    BIO* bio_in_;   // Memory BIO: Transport writes encrypted RX data here
    BIO* bio_out_;  // Memory BIO: SSL writes encrypted TX data here
#endif

    // Shared state (includes TCP state and TX frame allocation)
    // See pipeline_data.hpp for WebsocketStateShm definition
    WebsocketStateShm* tcp_state_;    // Note: TCPStateShm is alias for WebsocketStateShm
    uint8_t* umem_;                   // Pointer to UMEM buffer

    // Timestamp tracking state for SSL_read batches
    uint64_t first_nic_ts_ = 0;
    uint64_t first_poll_cycle_ = 0;
    uint64_t first_raw_poll_cycle_ = 0;    // Transport rdtscp of first packet
    uint64_t latest_nic_ts_ = 0;
    uint64_t latest_poll_cycle_ = 0;
    uint64_t latest_raw_poll_cycle_ = 0;
    bool has_pending_timestamps_ = false;

    // XDP interface (for frame access)
    XDPTransport& xdp_;               // Reference to XDP transport
    // Note: TxFrameState is merged into WebsocketStateShm.tx_frame
    // Access via: tcp_state_->tx_frame.ack_alloc_pos, etc.

    // DESIGN DECISION: Buffer Full = Abort
    // All TX frame pool exhaustion (ACK, PONG, MSG) triggers std::abort().
    // This is intentional for HFT systems:
    //   1. A full buffer indicates system misconfiguration (buffer too small)
    //   2. Or indicates a process is too slow (critical performance issue)
    //   3. Graceful degradation would hide latency problems
    //   4. Crashing immediately allows detection and correction
    // Exception: Window probes skip (not abort) when ACK pool full, since
    //            probes are periodic and will retry automatically.

    // TCP connection state (for FIN handling)
    // TCPState enum values:
    //   ESTABLISHED - Normal data transfer state (initial after handshake)
    //   CLOSE_WAIT  - Peer sent FIN, we ACKed, waiting for our FIN
    //   LAST_ACK    - We sent FIN, waiting for peer's ACK
    //   FIN_WAIT_1  - We sent FIN, waiting for peer's FIN or ACK
    //   FIN_WAIT_2  - We sent FIN and got ACK, waiting for peer's FIN
    //   TIME_WAIT   - Both FINs exchanged, waiting for lingering packets
    //   CLOSED      - Connection fully closed
    TCPState connection_state_ = TCPState::ESTABLISHED;  // Renamed from tcp_state_ to avoid collision

    // Ring buffer producers/consumers
    RawInboxConsumer& raw_inbox_consumer_;
    RawOutboxProducer& raw_outbox_producer_;
    AckOutboxProducer& ack_outbox_producer_;
    PongOutboxProducer& pong_outbox_producer_;
    MsgMetadataProducer& msg_metadata_producer_;
    MsgOutboxConsumer& msg_outbox_consumer_;
    PongsConsumer& pongs_consumer_;

    // MSG_INBOX byte stream ring
    MsgInbox& msg_inbox_;

    // TCP parameters (initialized from handshake, updated during connection)
    userspace_stack::TCPParams tcp_params_;

    // Initialization (called after fork, before run()):
    // void init(TCPStateShm* tcp_state_shm, TxFrameState* tx_state, ...) {
    //     tcp_params_.snd_nxt = tcp_state_shm->initial_seq + 1;  // After SYN
    //     tcp_params_.rcv_nxt = tcp_state_shm->peer_initial_seq + 1;  // After SYN-ACK
    //     peer_recv_window_ = tcp_state_shm->peer_recv_window;
    //     peer_window_scale_ = tcp_state_shm->peer_window_scale;
    //     send_una_ = tcp_state_shm->initial_seq + 1;
    //     // ... other initialization
    // }

    // State from handshake (stored in shared memory)
    uint32_t peer_recv_window_;       // From SYN-ACK
    uint8_t  peer_window_scale_;      // From SYN-ACK TCP options
    uint32_t send_una_;               // Oldest unacked TX sequence

    // Adaptive ACK state (TSC-based timing for busy-polling - no syscalls)
    uint32_t pending_ack_seq_ = 0;
    uint32_t pkts_since_last_ack_ = 0;
    uint64_t last_ack_tsc_ = 0;
    uint64_t tsc_freq_hz_;                 // From shared memory (calibrated during handshake)

    // NOTE: tsc_freq_hz_ is loaded from TCPStateShm during init(), not calibrated locally.
    // Parent process calibrates once during handshake and stores in shared memory.
    // This avoids 10ms calibration delay in each forked child process.
    // See pipeline_handshake.md TCPStateShm::tsc_freq_hz for calibration code.

    static constexpr uint32_t ACK_BATCH_THRESHOLD = 8;
    static constexpr uint64_t ACK_TIMEOUT_US = 100;
    static constexpr uint32_t RTO_MS = 200;       // Retransmission timeout

    // TLS sizing
    static constexpr size_t TLS13_OVERHEAD = 5 + 16;  // Record header + AEAD tag
    static constexpr size_t MAX_TLS_PLAINTEXT = TCP_MSS - TLS13_OVERHEAD;

public:
    // ========================================================================
    // init_with_handshake() - Fork-first: Performs complete handshake via IPC
    // Called in Transport child process after fork
    // ========================================================================
    bool init_with_handshake(void* umem_area, uint32_t frame_size,
                              const char* target_host, uint16_t target_port,
                              const char* target_path, const char* subscription,
                              TCPStateShm* tcp_state,
                              RawInboxCons* raw_inbox_cons,
                              RawOutboxProd* raw_outbox_prod,
                              AckOutboxProd* ack_outbox_prod,
                              PongOutboxProd* pong_outbox_prod,
                              MsgInbox* msg_inbox, ...);

    void run();
    void cleanup();

private:
    // Handshake helpers (fork-first)
    bool perform_tcp_handshake_via_ipc(const char* target_host, uint16_t target_port);
    bool perform_tls_handshake_via_ipc(const char* target_host);
    bool perform_websocket_upgrade_via_ipc(const char* target_host, const char* target_path);
    bool send_subscription_via_ipc(const char* subscription_json);
};
```

---

## init_with_handshake() Implementation (Fork-First)

In fork-first architecture, Transport performs TCP/TLS/WS handshake via IPC rings
after XDP Poll has created the XSK socket.

```cpp
template<typename SSLPolicy>
bool TransportProcess<SSLPolicy>::init_with_handshake(
        void* umem_area, uint32_t frame_size,
        const char* target_host, uint16_t target_port,
        const char* target_path, const char* subscription,
        TCPStateShm* tcp_state, ...) {

    umem_ = static_cast<uint8_t*>(umem_area);
    tcp_state_ = tcp_state;

    // Store IPC ring pointers (created by parent before fork)
    raw_inbox_consumer_ = raw_inbox_cons;
    raw_outbox_producer_ = raw_outbox_prod;
    ack_outbox_producer_ = ack_outbox_prod;
    pong_outbox_producer_ = pong_outbox_prod;
    msg_inbox_ = msg_inbox;
    // ... store other ring pointers

    // Load TSC frequency from shared memory (calibrated once in parent)
    tsc_freq_hz_ = tcp_state_->tsc_freq_hz;

    // 1. Wait for XDP Poll to signal xdp_ready (XSK socket created)
    printf("[TRANSPORT] Waiting for XDP Poll to create XSK socket...\n");
    if (!tcp_state_->wait_for_handshake_xdp_ready(30000000)) {  // 30s timeout
        fprintf(stderr, "[TRANSPORT] ERROR: XDP Poll timeout\n");
        return false;
    }
    printf("[TRANSPORT] XDP Poll ready, starting handshake\n");

    // 2. Perform TCP 3-way handshake via IPC rings
    if (!perform_tcp_handshake_via_ipc(target_host, target_port)) {
        fprintf(stderr, "[TRANSPORT] ERROR: TCP handshake failed\n");
        return false;
    }
    tcp_state_->handshake_stage.tcp_ready.store(1, std::memory_order_release);
    printf("[TRANSPORT] TCP handshake complete\n");

    // 3. Perform TLS handshake via IPC rings
    if (!perform_tls_handshake_via_ipc(target_host)) {
        fprintf(stderr, "[TRANSPORT] ERROR: TLS handshake failed\n");
        return false;
    }
    tcp_state_->handshake_stage.tls_ready.store(1, std::memory_order_release);
    printf("[TRANSPORT] TLS handshake complete\n");

    // 4. Perform WebSocket upgrade via IPC rings
    if (!perform_websocket_upgrade_via_ipc(target_host, target_path)) {
        fprintf(stderr, "[TRANSPORT] ERROR: WebSocket upgrade failed\n");
        return false;
    }
    printf("[TRANSPORT] WebSocket upgrade complete\n");

    // 5. Send subscription message via IPC rings
    if (subscription && strlen(subscription) > 0) {
        if (!send_subscription_via_ipc(subscription)) {
            fprintf(stderr, "[TRANSPORT] ERROR: Subscription send failed\n");
            return false;
        }
        printf("[TRANSPORT] Subscription sent\n");
    }

    // 6. Store TCP state for other processes
    tcp_state_->initial_seq = tcp_params_.initial_seq;
    tcp_state_->peer_initial_seq = tcp_params_.peer_initial_seq;
    tcp_state_->peer_recv_window = peer_recv_window_;
    tcp_state_->peer_window_scale = peer_window_scale_;
    tcp_state_->local_ip = stack_.local_ip();
    tcp_state_->peer_ip = stack_.peer_ip();
    tcp_state_->local_port = stack_.local_port();
    tcp_state_->peer_port = stack_.peer_port();
    memcpy(tcp_state_->local_mac, stack_.local_mac(), 6);
    memcpy(tcp_state_->peer_mac, stack_.peer_mac(), 6);

    // 7. Signal WebSocket ready (handshake complete)
    tcp_state_->set_handshake_ws_ready();
    printf("[TRANSPORT] Handshake complete, signaling ws_ready\n");

    return true;
}
```

---

## Main Loop

```cpp
void TransportProcess::run() {
    // Fork-first: use is_running() helper with ProcessId enum
    while (tcp_state_->is_running(PROC_TRANSPORT)) {
        bool data_moved = false;  // Track if any data was sent or received this round

        // 0. HIGHEST PRIORITY: TCP Retransmission
        check_retransmit();

        // 1. TX: MSG_OUTBOX → SSL_write → RAW_OUTBOX
        // NOTE: No pending write handling needed - memory BIOs never return SSL_ERROR_WANT_WRITE

        // Check peer receive window before sending
        uint32_t bytes_in_flight = tcp_params_.snd_nxt - send_una_;
        uint32_t effective_window = peer_recv_window_ << peer_window_scale_;
        uint32_t available = (effective_window > bytes_in_flight)
            ? effective_window - bytes_in_flight : 0;

        // Consume MSG_OUTBOX using process_manually (MsgOutboxEvent = 2KB events)
        if (available > 0) {
            msg_outbox_consumer_.process_manually(
                [&](MsgOutboxEvent& event, int64_t seq) -> bool {
                    if (available == 0) return false;

                    if (event.msg_type == MSG_TYPE_WS_CLOSE) {
                        // Handle close signal from WebSocket process
                        send_ws_close_frame(event.data[0] << 8 | event.data[1]);
                        send_fin();
                        tcp_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
                        return false;
                    }

                    // ZERO-COPY TX: Build WS header into header_room, then single SSL_write
                    // RFC 6455 client masking uses [0,0,0,0] mask (XOR is no-op, avoids masking payload)
                    // MsgOutboxEvent layout: [header_room(14B)][data(2030B)][metadata]
                    // Header is RIGHT-ALIGNED in header_room so [header+data] is contiguous

                    // Calculate header length first to know where to write
                    size_t header_len;
                    if (event.data_len < 126) {
                        header_len = 6;  // 2 + 4 (mask)
                    } else if (event.data_len <= 0xFFFF) {
                        header_len = 8;  // 2 + 2 + 4 (mask)
                    } else {
                        header_len = 14; // 2 + 8 + 4 (mask)
                    }

                    // Right-align header in header_room (so header ends at byte 14)
                    uint8_t* header_start = event.header_room + 14 - header_len;
                    build_websocket_header_zerocopy(header_start, event.data_len, event.opcode);

                    // Single SSL_write: header + payload contiguous for single TLS record
                    int n = SSL_write(ssl_, header_start, header_len + event.data_len);
                    if (n <= 0) return false;

                    // Drain encrypted data from bio_out_ → TCP packets → RAW_OUTBOX
                    size_t encrypted_bytes_sent = send_encrypted_packet();
                    available -= encrypted_bytes_sent;
                    data_moved = true;  // We sent data
                    return true;
                });
            msg_outbox_consumer_.commit_manually();
        }

        // 2. RX: RAW_INBOX → parse → SSL_read → MSG_INBOX - uses process_manually
        size_t rx_count = 0;
        raw_inbox_consumer_.process_manually(
            [&](UMEMFrameDescriptor& desc, int64_t seq) -> bool {
                // Track timestamps for latency analysis (rdtscp from core/timing.hpp)
                uint64_t raw_poll_cycle = rdtscp();

                // Track first and latest timestamps for this SSL_read batch
                if (!has_pending_timestamps_) {
                    first_nic_ts_ = desc.nic_timestamp_ns;
                    first_poll_cycle_ = desc.nic_frame_poll_cycle;
                    first_raw_poll_cycle_ = raw_poll_cycle;  // Transport timestamp of first packet
                    has_pending_timestamps_ = true;
                }
                latest_nic_ts_ = desc.nic_timestamp_ns;
                latest_poll_cycle_ = desc.nic_frame_poll_cycle;
                latest_raw_poll_cycle_ = raw_poll_cycle;

                uint8_t* frame = umem_ + desc.umem_addr;
                TCPParseResult tcp = stack_.parse_tcp(frame, desc.frame_len);

                // Update peer window from ACK
                if (tcp.flags & TCP_FLAG_ACK) {
                    peer_recv_window_ = tcp.window;
                    send_una_ = tcp.ack;  // Update oldest unacked sequence

                    // Process ACK for MSG frames (cumulative - advances acked_pos)
                    // NOTE: ack_received() maps TCP seq (uint32_t) → frame alloc position (uint64_t)
                    // tcp.ack is the TCP ACK sequence number from peer
                    // Returns highest frame position that's been fully ACKed
                    uint64_t msg_acked_pos = retransmit_queue_.ack_received(tcp.ack);
                    set_msg_acked_pos(msg_acked_pos);

                    // Process ACK for PONG frames (separate queue, same seq→pos mapping)
                    uint64_t pong_acked_pos = pong_retransmit_queue_.ack_received(tcp.ack);
                    set_pong_acked_pos(pong_acked_pos);
                }

                // Handle FIN (proper TCP state machine)
                if (tcp.flags & TCP_FLAG_FIN) {
                    // FIN consumes 1 sequence number
                    tcp_params_.rcv_nxt++;

                    // NOTE: No drain_pending_tx() - see "drain_pending_tx() - REMOVED" section
                    // For HFT, fast reconnection is more important than ensuring pending TX delivery

                    // Send FIN-ACK (ACKs the peer's FIN)
                    send_fin_ack();

                    // Enter CLOSE-WAIT state
                    tcp_state_ = TCPState::CLOSE_WAIT;

                    // Send our own FIN to initiate close from our side
                    send_fin();
                    tcp_state_ = TCPState::LAST_ACK;

                    // NOTE: Don't set is_running=false here. Continue processing to receive
                    // the final ACK for our FIN. The main loop will handle LAST_ACK state.
                    //
                    // KNOWN LIMITATION: FIN Handling Data Loss Risk
                    // ==============================================
                    // This simplified FIN handling may result in data loss if:
                    //   1. We have in-flight data not yet ACKed by peer
                    //   2. Peer's FIN races with our data
                    //
                    // WHY THIS IS ACCEPTABLE FOR HFT:
                    //   1. Binance servers gracefully close after CLOSE frame exchange,
                    //      so all data should be ACKed before FIN in normal operation
                    //   2. Connection close is rare (server maintenance, network issues)
                    //   3. Reconnection will restore state - no persistent data loss
                    //   4. Adding send_una_ == snd_nxt wait would complicate close path
                    //      for minimal benefit in production
                    //
                    // For stricter handling, consider:
                    //   - Wait for retransmit queue to drain before sending our FIN
                    //   - Track send_una_ == snd_nxt before closing
                    //   - Implement TIME_WAIT state for lingering packets
                    //
                    return true;  // Continue to receive final ACK
                }

                // Handle final ACK in LAST_ACK state (for our FIN)
                if (tcp_state_ == TCPState::LAST_ACK && (tcp.flags & TCP_FLAG_ACK)) {
                    // Peer acknowledged our FIN - connection fully closed
                    tcp_state_ = TCPState::CLOSED;
                    tcp_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
                    return false;  // Now safe to stop
                }

                // Handle RST
                if (tcp.flags & TCP_FLAG_RST) {
                    tcp_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
                    return false;  // Stop processing
                }

                // Process payload (uses seq_lt helper for wrap-around safe comparison)
                //
                // OUT-OF-ORDER PACKET LIMITATION (DESIGN DECISION)
                // ==================================================
                // This implementation does NOT buffer out-of-order packets. When a packet
                // arrives with seq > rcv_nxt (gap in sequence), we:
                //   1. Send duplicate ACK to trigger fast retransmit on sender
                //   2. DISCARD the out-of-order packet (do not buffer it)
                //   3. Wait for sender to retransmit the missing data
                //
                // WHY THIS IS ACCEPTABLE FOR HFT:
                //   1. Low-latency networks have rare packet loss (<0.01%)
                //   2. Most "out-of-order" is actually reordering within RTT, which resolves quickly
                //   3. Buffering requires memory management and adds latency to in-order path
                //   4. For persistent packet loss, reconnection is the HFT recovery strategy
                //
                // TRADE-OFF: If packet N is lost and packet N+1 arrives first, both must be
                // retransmitted by sender (N+1 is discarded here). This adds RTT latency.
                // For HFT with reliable networks, this is acceptable vs. buffering complexity.
                //
                if (tcp.payload_len > 0) {
                    if (tcp.seq == tcp_params_.rcv_nxt) {
                        // In-order packet
                        tcp_params_.rcv_nxt += tcp.payload_len;
                        pending_ack_seq_ = tcp_params_.rcv_nxt;
                        pkts_since_last_ack_++;
                        BIO_write(bio_in_, frame + tcp.payload_offset, tcp.payload_len);
                    } else if (seq_lt(tcp.seq, tcp_params_.rcv_nxt)) {
                        // Retransmit of already-received data (ignore, but ACK)
                    } else {
                        // Out-of-order (tcp.seq > rcv_nxt): send dup ACK, DISCARD packet
                        // See "OUT-OF-ORDER PACKET LIMITATION" comment above
                        send_dup_ack();
                    }
                }

                // Mark frame as consumed for XDP Poll to reclaim
                // NOTE: This is set AFTER we've finished reading the frame data
                desc.consumed = 1;

                rx_count++;
                return true;  // Continue processing
            });
        raw_inbox_consumer_.commit_manually();
        if (rx_count > 0) {
            data_moved = true;  // We received data

            // SSL_read → MSG_INBOX (only if we received TCP data with payload)
            //
            // OPTIMIZATION: Only call ssl_read_to_msg_inbox() when rx_count > 0.
            // If no new TCP packets arrived, bio_in_ has no new encrypted data,
            // so SSL_read() would immediately return SSL_ERROR_WANT_READ.
            // Calling it unconditionally wastes cycles on the hot path.
            //
            // EDGE CASE: Partial TLS records spanning multiple TCP packets are handled
            // correctly because we only call ssl_read_to_msg_inbox() when NEW data
            // arrives. Previous partial data in bio_in_ is preserved until the final
            // TCP packet completes the TLS record.
            //
            ssl_read_to_msg_inbox();
        }

        // 3. Adaptive ACK (TSC-based timing - no syscalls in hot path)
        check_adaptive_ack();

        // 4. (idle) PONG encryption - only process when no data sent/received
        //
        // DESIGN DECISION: PONGs processed only during idle
        // ===================================================
        // PONGs are lower priority than data messages. Processing them during idle
        // ensures data path latency is not affected by PONG handling.
        //
        // TRADE-OFF: If connection is constantly receiving data, PONGs are starved.
        // RFC 6455 requires PONG responses to PINGs, so peer may close connection
        // for failing to respond.
        //
        // WHY THIS IS ACCEPTABLE FOR HFT:
        // 1. Exchange data streams are the priority - PONG delay doesn't affect trading
        // 2. Most exchanges have generous PING timeout (30-60s)
        // 3. If data flow is so high that PONGs are never processed, we have other
        //    problems (likely can't keep up with market data anyway)
        // 4. A few missed PONGs during burst traffic is acceptable
        //
        // ALTERNATIVE: Process PONGs unconditionally or with timeout (e.g., once per
        // 100ms regardless of data flow). Not implemented to keep hot path minimal.
        //
        if (!data_moved) {
            pongs_consumer_.process_manually(
                [&](PongFrameAligned& pong, int64_t seq) -> bool {
                    uint8_t ws_frame[131];  // 6-byte header + 125-byte max payload
                    size_t ws_len = build_ws_pong_frame(ws_frame, pong.pong.payload,
                                                         pong.pong.payload_len);
                    SSL_write(ssl_, ws_frame, ws_len);
                    send_encrypted_pong();
                    return true;
                });
            pongs_consumer_.commit_manually();
        }
    }
}
```

---

## SSL_read to MSG_INBOX

```cpp
// Helper: SSL_read decrypted data → MSG_INBOX byte stream
// IMPORTANT: Publish metadata FIRST, then write data (ensures consumer sees valid offsets)
void TransportProcess::ssl_read_to_msg_inbox() {
    // Loop while there's decrypted data in SSL buffer OR encrypted data in BIO
    // NOTE: SSL_pending() returns buffered decrypted data. BIO_ctrl_pending() returns
    // encrypted data waiting to be decrypted. We need to call SSL_read() to trigger
    // decryption, so we loop while either has data. SSL_read() will return WANT_READ
    // when bio_in_ is empty and there's no more decrypted data.
    while (true) {
        size_t linear_space = msg_inbox_.linear_space_to_wrap();

        if (linear_space < TLS_RECORD_MAX_SIZE) {
            // SAFETY CHECK: Verify AppClient has consumed past the wrap point
            // If we wrap, we'll overwrite from position 0. AppClient must not be reading there.
            //
            // ATOMICITY: We read app_consumed once and use that snapshot. The race is benign:
            // - If AppClient advances after our read, we're more conservative (safe)
            // - If AppClient was behind our snapshot, dirty_flag handles it
            uint32_t app_consumed = msg_inbox_.get_app_consumed();
            uint32_t write_pos = msg_inbox_.write_offset();

            // Check if AppClient is behind using circular buffer distance
            // Use modular arithmetic: (write_pos - app_consumed) handles wrap-around correctly
            // because unsigned subtraction wraps around, giving the correct forward distance.
            //
            // Threshold: 50% of buffer size - if AppClient is more than half a buffer behind,
            // it's falling behind and data may be overwritten before it's consumed.
            constexpr uint32_t BEHIND_THRESHOLD = MSG_INBOX_SIZE / 2;
            uint32_t distance = (write_pos - app_consumed) % MSG_INBOX_SIZE;
            if (distance > BEHIND_THRESHOLD) {
                // AppClient is more than 50% behind - set dirty_flag for metrics/debugging
                //
                // DESIGN DECISION: Continue writing instead of aborting
                // This allows the system to operate without AppClient process, or with a
                // slow AppClient. The dirty_flag signals data loss for metrics/debugging.
                // User can choose whether to use AppClient process at all.
                // If AppClient is critical, user code can check dirty_flag and take action.
                msg_inbox_.dirty_flag.store(1, std::memory_order_release);
                // NOTE: We continue and overwrite - AppClient will see corrupted data
                // for this region until it catches up past the wrap point.
            }

            msg_inbox_.set_wrap_flag();
            msg_inbox_.reset_to_head();
            linear_space = msg_inbox_.linear_space_to_wrap();
        }

        uint8_t* ptr = msg_inbox_.write_ptr();
        int n = SSL_read(ssl_, ptr, linear_space);
        if (n > 0) {
            // Capture SSL_read completion timestamp
            uint64_t ssl_read_cycle = rdtscp();

            // Step 1: Publish metadata FIRST (so consumer knows data location)
            // FATAL if ring full - consumer is not keeping up
            int64_t meta_seq = msg_metadata_producer_.try_claim();
            if (meta_seq < 0) std::abort();  // MSG_METADATA_INBOX full

            auto& meta = msg_metadata_producer_[meta_seq];
            meta.first_nic_timestamp_ns = first_nic_ts_;
            meta.first_nic_frame_poll_cycle = first_poll_cycle_;
            meta.first_raw_frame_poll_cycle = first_raw_poll_cycle_;
            meta.latest_nic_timestamp_ns = latest_nic_ts_;
            meta.latest_nic_frame_poll_cycle = latest_poll_cycle_;
            meta.latest_raw_frame_poll_cycle = latest_raw_poll_cycle_;
            meta.ssl_read_cycle = ssl_read_cycle;
            meta.msg_inbox_offset = msg_inbox_.write_offset();
            meta.decrypted_len = n;
            msg_metadata_producer_.publish(meta_seq);

            // Step 2: Advance write position (data already in buffer from SSL_read)
            msg_inbox_.advance_write(n);

            // Reset timestamp state for next SSL_read batch
            has_pending_timestamps_ = false;
        } else {
            int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ) break;
            handle_ssl_error(n);
        }
    }
}
```

---

## TCP Retransmission (Highest Priority)

```cpp
// Check Retransmission Timeout (RTO) - runs FIRST because lost packets must be recovered
// NOTE: We must update TCP ACK number before retransmit (reflects current rcv_nxt)
void TransportProcess::check_retransmit() {
    uint64_t rto_tsc = RTO_MS * tsc_freq_hz_ / 1000;  // Convert RTO to TSC cycles

    // Check MSG retransmits
    auto to_retransmit = retransmit_queue_.get_retransmit_refs(rto_tsc);
    for (auto* ref : to_retransmit) {
        retransmit_frame(ref, FRAME_TYPE_MSG, raw_outbox_producer_);
        retransmit_queue_.mark_retransmitted(ref->seq);

        if (retransmit_queue_.has_failed_segment()) {
            tcp_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
            return;
        }
    }

    // Check PONG retransmits (separate queue, same logic)
    auto pong_to_retransmit = pong_retransmit_queue_.get_retransmit_refs(rto_tsc);
    for (auto* ref : pong_to_retransmit) {
        retransmit_frame(ref, FRAME_TYPE_PONG, pong_outbox_producer_);
        pong_retransmit_queue_.mark_retransmitted(ref->seq);

        if (pong_retransmit_queue_.has_failed_segment()) {
            tcp_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
            return;
        }
    }
}

// Helper: Retransmit a single frame to the appropriate outbox
template<typename Producer>
void TransportProcess::retransmit_frame(RetransmitSegmentRef* ref, uint8_t frame_type, Producer& producer) {
    // Claim outbox slot - FATAL if full during retransmit
    int64_t seq = producer.try_claim();
    if (seq < 0) std::abort();  // Outbox full during retransmit

    // Update TCP ACK field in existing frame (reflects current rcv_nxt)
    // This also recalculates the TCP checksum since ACK field changed
    uint8_t* frame = xdp_.get_frame_ptr(ref->frame_idx);
    stack_.update_ack_and_checksum(frame, ref->frame_len, tcp_params_.rcv_nxt);

    // Frame already contains valid TCP packet with payload
    auto& desc = producer[seq];
    desc.umem_addr = xdp_.frame_idx_to_addr(ref->frame_idx);
    desc.frame_len = ref->frame_len;  // Already includes ETH+IP+TCP headers
    desc.frame_type = frame_type;
    producer.publish(seq);
}
```

---

## Send Encrypted Packet (Zero-Copy TX)

```cpp
// Returns total plaintext bytes sent (for TCP window tracking)
size_t TransportProcess::send_encrypted_packet() {
    size_t total_plaintext_sent = 0;
    while (BIO_ctrl_pending(bio_out_) > 0) {
        // Check how much encrypted data is pending before allocating
        size_t pending = BIO_ctrl_pending(bio_out_);
        if (pending == 0) break;

        // BOUNDS CHECK: Verify BOTH retransmit queue and frame pool have space
        // NOTE: These checks are coordinated to prevent inconsistent state:
        //   1. Check retransmit queue first (tracks in-flight packets for retransmit)
        //   2. Check frame pool second (tracks UMEM frame availability)
        // Both must have space before proceeding. If either is full, apply backpressure.
        //
        // RATIONALE: Retransmit queue can be smaller than frame pool because:
        //   - Each queue entry is 40 bytes, frames are ~2KB
        //   - Memory is cheaper than latency from queue scans
        //   - Retransmit queue full indicates network congestion, not misconfiguration
        //
        if (retransmit_queue_.size() >= MSG_FRAMES) {
            // Retransmit queue full - backpressure: stop sending until ACKs arrive
            // bio_out_ will buffer remaining data; SSL_write will still succeed
            break;
        }

        // Allocate TX frame from MSG pool (position-based allocation)
        // Uses atomic fetch_add on msg_alloc_pos, checks against release_pos for availability
        uint64_t alloc_pos = tcp_state_->tx_frame.msg_alloc_pos.load(std::memory_order_relaxed);
        uint64_t release_pos = tcp_state_->tx_frame.msg_release_pos.load(std::memory_order_acquire);

        // Check if pool is full (alloc has wrapped around to release)
        if (alloc_pos - release_pos >= MSG_FRAMES) {
            // Frame pool exhausted - apply same backpressure as retransmit queue
            // NOTE: This should rarely happen if retransmit queue check passed,
            // since both are sized to MSG_FRAMES. If it does, it indicates a bug
            // in ACK processing (frames not being released after ACK).
            break;  // Backpressure instead of abort
        }

        // FRAME INDEX DERIVATION: position→frame_idx (Transport allocation)
        // =================================================================
        // Transport allocates frames by incrementing alloc_pos. To get the
        // actual UMEM frame index, we use:
        //   frame_idx = POOL_BASE + (alloc_pos % POOL_SIZE)
        //
        // This is different from XDP Poll's addr→frame_idx derivation:
        //   frame_idx = addr / FRAME_SIZE  (used when comp_ring returns addresses)
        //
        // These are independent derivations for different purposes:
        //   - Transport uses position for sequential allocation within pool
        //   - XDP Poll uses address for pool identification from comp_ring
        //
        // The position→frame_idx formula ensures sequential allocation within the pool,
        // wrapping around when alloc_pos exceeds MSG_FRAMES.
        uint32_t frame_idx = RX_FRAMES + ACK_FRAMES + PONG_FRAMES + static_cast<uint32_t>(alloc_pos % MSG_FRAMES);
        tcp_state_->tx_frame.msg_alloc_pos.fetch_add(1, std::memory_order_release);

        uint8_t* buffer = xdp_.get_frame_ptr(frame_idx);

        // Read encrypted data directly into UMEM frame (after TCP header)
        uint8_t* payload_ptr = buffer + ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN;
        int encrypted_len = BIO_read(bio_out_, payload_ptr, MAX_TLS_PLAINTEXT + TLS13_OVERHEAD);
        if (encrypted_len <= 0) {
            // Can't easily "free" with position-based allocation
            // This shouldn't happen since we checked BIO_ctrl_pending
            break;
        }

        // Build TCP packet header using stack
        size_t frame_len = stack_.build_data(buffer, FRAME_SIZE, tcp_params_,
                                              payload_ptr, encrypted_len);

        // Add reference to retransmit queue (ZERO-COPY: just store frame_idx)
        // NOTE: Pass alloc_pos (value BEFORE fetch_add) for position-based ACK tracking
        //       Pass encrypted_len as payload_len for seq_end calculation
        retransmit_queue_.add_ref(alloc_pos, frame_idx, tcp_params_.snd_nxt,
                                  static_cast<uint16_t>(encrypted_len),
                                  static_cast<uint16_t>(frame_len), TCP_FLAG_ACK | TCP_FLAG_PSH);

        // Update send sequence
        tcp_params_.snd_nxt += encrypted_len;

        // Publish to RAW_OUTBOX - FATAL if full
        int64_t seq = raw_outbox_producer_.try_claim();
        if (seq < 0) std::abort();  // RAW_OUTBOX full

        auto& desc = raw_outbox_producer_[seq];
        desc.umem_addr = xdp_.frame_idx_to_addr(frame_idx);
        desc.frame_len = static_cast<uint16_t>(frame_len);
        desc.frame_type = FRAME_TYPE_MSG;
        raw_outbox_producer_.publish(seq);

        // Track plaintext bytes (encrypted_len - TLS overhead approximation)
        total_plaintext_sent += (encrypted_len > TLS13_OVERHEAD)
            ? (encrypted_len - TLS13_OVERHEAD) : encrypted_len;
    }
    return total_plaintext_sent;
}
```

---

## Adaptive ACK

```cpp
// Helper: Adaptive ACK logic
void TransportProcess::check_adaptive_ack() {
    uint64_t now_tsc = rdtsc();
    uint64_t elapsed_us = (now_tsc - last_ack_tsc_) * 1000000 / tsc_freq_hz_;
    bool should_ack = (pkts_since_last_ack_ >= ACK_BATCH_THRESHOLD) ||
                      (elapsed_us >= ACK_TIMEOUT_US && pkts_since_last_ack_ > 0);
    if (should_ack) {
        send_ack();
        pkts_since_last_ack_ = 0;
        last_ack_tsc_ = now_tsc;
    }
}
```

---

## ACK and Control Frame Helpers

### send_ack()
```cpp
void TransportProcess::send_ack() {
    // Allocate ACK_TX UMEM frame (position-based allocation)
    uint64_t alloc_pos = tcp_state_->tx_frame.ack_alloc_pos.load(std::memory_order_relaxed);
    uint64_t release_pos = tcp_state_->tx_frame.ack_release_pos.load(std::memory_order_acquire);

    if (alloc_pos - release_pos >= ACK_FRAMES) {
        std::abort();  // ACK frame pool exhausted
    }

    uint32_t frame_idx = RX_FRAMES + static_cast<uint32_t>(alloc_pos % ACK_FRAMES);
    tcp_state_->tx_frame.ack_alloc_pos.fetch_add(1, std::memory_order_release);

    uint8_t* buffer = xdp_.get_frame_ptr(frame_idx);

    // Build ACK packet using stack (uses tcp_params_.rcv_nxt as ACK number)
    size_t frame_len = stack_.build_ack(buffer, FRAME_SIZE, tcp_params_);

    // Publish to ACK_OUTBOX - FATAL if full
    int64_t seq = ack_outbox_producer_.try_claim();
    if (seq < 0) std::abort();  // ACK_OUTBOX full

    auto& desc = ack_outbox_producer_[seq];
    desc.umem_addr = xdp_.frame_idx_to_addr(frame_idx);
    desc.frame_len = static_cast<uint16_t>(frame_len);
    desc.frame_type = FRAME_TYPE_ACK;
    ack_outbox_producer_.publish(seq);
}
```

### send_dup_ack()
```cpp
void TransportProcess::send_dup_ack() {
    // Duplicate ACK is same as regular ACK, but sent immediately for out-of-order packets
    // This triggers fast retransmit on sender after 3 dup ACKs
    send_ack();
}
```

### send_fin_ack()
```cpp
// FIN-ACK uses ACK pool (no retransmit support)
//
// DESIGN DECISION: No FIN Retransmit for HFT
// ==========================================
// Unlike standard TCP implementations, we do NOT retransmit FIN/FIN-ACK:
//
// 1. **Fast reconnection priority**: For HFT, we want to close quickly and reconnect.
//    Waiting for FIN retransmit adds latency to the reconnection path.
//
// 2. **Peer timeout handles lost FIN**: If our FIN is lost, peer will eventually
//    timeout and close their side. This is acceptable for HFT where reconnection
//    is the recovery strategy anyway.
//
// 3. **Simplifies close path**: No need to track FIN in retransmit queue, wait for
//    ACK, or handle FIN retransmit timeout. Just send and move on.
//
// 4. **Connection state is transient**: HFT connections are recreated frequently.
//    A "stuck" close state on peer side is resolved by reconnection.
//
void TransportProcess::send_fin_ack() {
    // Allocate ACK_TX UMEM frame (position-based allocation, no retransmit)
    uint64_t alloc_pos = tcp_state_->tx_frame.ack_alloc_pos.load(std::memory_order_relaxed);
    uint64_t release_pos = tcp_state_->tx_frame.ack_release_pos.load(std::memory_order_acquire);

    if (alloc_pos - release_pos >= ACK_FRAMES) {
        return;  // Skip if no frames available - connection closing anyway
    }

    uint32_t frame_idx = RX_FRAMES + static_cast<uint32_t>(alloc_pos % ACK_FRAMES);
    tcp_state_->tx_frame.ack_alloc_pos.fetch_add(1, std::memory_order_release);

    uint8_t* buffer = xdp_.get_frame_ptr(frame_idx);
    size_t frame_len = stack_.build_fin_ack(buffer, FRAME_SIZE, tcp_params_);

    // NOTE: No retransmit queue entry - fire and forget for HFT

    // FIN consumes 1 sequence number
    tcp_params_.snd_nxt++;

    int64_t seq = ack_outbox_producer_.try_claim();
    if (seq < 0) return;  // Skip if outbox full - connection closing anyway

    auto& desc = ack_outbox_producer_[seq];
    desc.umem_addr = xdp_.frame_idx_to_addr(frame_idx);
    desc.frame_len = static_cast<uint16_t>(frame_len);
    desc.frame_type = FRAME_TYPE_ACK;
    ack_outbox_producer_.publish(seq);
}
```

### send_fin()
```cpp
// FIN frame uses ACK pool (no retransmit support)
// See send_fin_ack() for rationale on no FIN retransmit for HFT
void TransportProcess::send_fin() {
    // Allocate ACK_TX UMEM frame (position-based allocation, no retransmit)
    uint64_t alloc_pos = tcp_state_->tx_frame.ack_alloc_pos.load(std::memory_order_relaxed);
    uint64_t release_pos = tcp_state_->tx_frame.ack_release_pos.load(std::memory_order_acquire);

    if (alloc_pos - release_pos >= ACK_FRAMES) {
        return;  // Skip if no frames available - connection closing anyway
    }

    uint32_t frame_idx = RX_FRAMES + static_cast<uint32_t>(alloc_pos % ACK_FRAMES);
    tcp_state_->tx_frame.ack_alloc_pos.fetch_add(1, std::memory_order_release);

    uint8_t* buffer = xdp_.get_frame_ptr(frame_idx);
    size_t frame_len = stack_.build_fin(buffer, FRAME_SIZE, tcp_params_);

    // NOTE: No retransmit queue entry - fire and forget for HFT

    // FIN consumes 1 sequence number
    tcp_params_.snd_nxt++;

    int64_t seq = ack_outbox_producer_.try_claim();
    if (seq < 0) return;  // Skip if outbox full - connection closing anyway

    auto& desc = ack_outbox_producer_[seq];
    desc.umem_addr = xdp_.frame_idx_to_addr(frame_idx);
    desc.frame_len = static_cast<uint16_t>(frame_len);
    desc.frame_type = FRAME_TYPE_ACK;
    ack_outbox_producer_.publish(seq);
}
```

---

## WebSocket Frame Helpers

### send_ws_close_frame()
```cpp
void TransportProcess::send_ws_close_frame(uint16_t close_code) {
    uint8_t ws_frame[8];  // 2-byte header + 4-byte mask + 2-byte code
    size_t ws_len = build_ws_close_frame(ws_frame, close_code);
    SSL_write(ssl_, ws_frame, ws_len);
    send_encrypted_packet();
}
```

### build_ws_close_frame()
```cpp
size_t TransportProcess::build_ws_close_frame(uint8_t* frame, uint16_t close_code) {
    frame[0] = 0x88;  // FIN=1, opcode=0x08 (close)
    frame[1] = 0x82;  // MASK=1, payload_len=2
    frame[2] = 0; frame[3] = 0; frame[4] = 0; frame[5] = 0;  // Mask key [0,0,0,0]
    frame[6] = (close_code >> 8) & 0xFF;  // Close code big-endian
    frame[7] = close_code & 0xFF;
    return 8;
}
```

### build_ws_pong_frame()
```cpp
size_t TransportProcess::build_ws_pong_frame(uint8_t* frame, const uint8_t* payload, uint8_t payload_len) {
    size_t pos = 0;
    frame[pos++] = 0x8A;  // FIN=1, opcode=0x0A (pong)
    frame[pos++] = 0x80 | payload_len;  // MASK=1, payload_len (max 125)
    frame[pos++] = 0; frame[pos++] = 0; frame[pos++] = 0; frame[pos++] = 0;  // Mask [0,0,0,0]
    memcpy(frame + pos, payload, payload_len);  // No XOR needed with [0,0,0,0] mask
    return pos + payload_len;
}
```

### send_encrypted_pong()
```cpp
// PONGs use dedicated PONG pool and PONG_OUTBOX with retransmit support.
// Rationale:
//   - PONGs are control frames, but they consume TCP sequence numbers
//   - PONGs must be retransmittable to prevent TCP sequence gaps
//   - PONG pool is pre-allocated for this purpose (separate from MSG pool)
//   - Using dedicated pool avoids holes in sequential MSG allocation
//
// TCP ACK tracking: PONGs are added to pong_retransmit_queue_:
//   - If PONG is lost, it will be retransmitted like MSG frames
//   - XDP Poll releases PONG frames only after TCP ACK received
//   - Uses separate pong_acked[] flags in TxFrameState
void TransportProcess::send_encrypted_pong() {
    while (BIO_ctrl_pending(bio_out_) > 0) {
        size_t pending = BIO_ctrl_pending(bio_out_);
        if (pending == 0) break;

        // BOUNDS CHECK: Verify PONG retransmit queue has space
        if (pong_retransmit_queue_.size() >= PONG_FRAMES) {
            std::abort();  // PONG retransmit queue full
        }

        // Allocate PONG_TX UMEM frame (position-based allocation)
        uint64_t alloc_pos = tcp_state_->tx_frame.pong_alloc_pos.load(std::memory_order_relaxed);
        uint64_t release_pos = tcp_state_->tx_frame.pong_release_pos.load(std::memory_order_acquire);

        if (alloc_pos - release_pos >= PONG_FRAMES) {
            std::abort();  // PONG frame pool exhausted
        }

        uint32_t frame_idx = RX_FRAMES + ACK_FRAMES + static_cast<uint32_t>(alloc_pos % PONG_FRAMES);
        tcp_state_->tx_frame.pong_alloc_pos.fetch_add(1, std::memory_order_release);

        uint8_t* buffer = xdp_.get_frame_ptr(frame_idx);
        uint8_t* payload_ptr = buffer + ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN;
        int encrypted_len = BIO_read(bio_out_, payload_ptr, 256);
        if (encrypted_len <= 0) {
            // This shouldn't happen since we checked BIO_ctrl_pending
            break;
        }

        size_t frame_len = stack_.build_data(buffer, FRAME_SIZE, tcp_params_,
                                              payload_ptr, encrypted_len);

        // Add to PONG retransmit queue (separate from MSG retransmit queue)
        // NOTE: Use TCP_FLAG_ACK only (no PSH). PSH is for urgent application data,
        // PONGs are control frames that don't need special push semantics.
        // Pass alloc_pos (value BEFORE fetch_add) for position-based ACK tracking
        // Pass encrypted_len as payload_len for seq_end calculation
        pong_retransmit_queue_.add_ref(alloc_pos, frame_idx, tcp_params_.snd_nxt,
                                        static_cast<uint16_t>(encrypted_len),
                                        static_cast<uint16_t>(frame_len), TCP_FLAG_ACK);

        // Update TCP sequence number (PONGs consume sequence space)
        tcp_params_.snd_nxt += encrypted_len;

        // Publish to PONG_OUTBOX - FATAL if full
        int64_t seq = pong_outbox_producer_.try_claim();
        if (seq < 0) std::abort();  // PONG_OUTBOX full

        auto& desc = pong_outbox_producer_[seq];
        desc.umem_addr = xdp_.frame_idx_to_addr(frame_idx);
        desc.frame_len = static_cast<uint16_t>(frame_len);
        desc.frame_type = FRAME_TYPE_PONG;
        pong_outbox_producer_.publish(seq);
    }
}
```

---

## SSL Error Handling

```cpp
void TransportProcess::handle_ssl_error(int ret) {
    int err = SSL_get_error(ssl_, ret);
    if (err == SSL_ERROR_ZERO_RETURN) {
        // Peer closed TLS connection
        tcp_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
    } else if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
        // Fatal error
        tcp_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
    }
    // SSL_ERROR_WANT_READ is handled by caller
}
```

---

## Helpers

### Zero Receive Window (NOT IMPLEMENTED)

**DESIGN DECISION: No Window Probe Support**

Zero receive window (peer advertises window=0) is **not handled** in this library.

**Rationale for HFT**:
1. **Zero-window indicates misconfiguration**: In HFT scenarios, exchange connections are sized for expected throughput. If peer advertises window=0, it indicates:
   - Peer cannot keep up with data rate (fundamental problem)
   - Network/server misconfiguration
   - Peer is overloaded and should be reconnected anyway

2. **Reconnection is the recovery strategy**: For HFT, a stalled connection due to zero-window should trigger reconnection rather than waiting indefinitely with probes.

3. **Complexity vs. benefit**: Proper window probe implementation requires:
   - Retransmit support for probe bytes (consumes sequence space)
   - Timer management for probe intervals
   - Edge case handling for probe loss

   This complexity is not justified for a scenario that indicates system misconfiguration.

**Behavior**: If peer advertises window=0, the connection will stall. User should configure appropriate timeouts and use reconnection strategy.

---

### drain_pending_tx() - REMOVED

**DESIGN DECISION: No TX Drain on FIN**

The `drain_pending_tx()` function has been **removed**.

**Rationale for HFT**:
1. **Fast reconnection priority**: When receiving FIN or initiating close, HFT applications need fast reconnection rather than ensuring all pending messages are sent.

2. **Message ordering not guaranteed anyway**: If connection is closing, pending messages may not be received/processed by peer before connection terminates.

3. **Simplifies close path**: Removing drain logic simplifies FIN handling:
   - Receive FIN → send FIN-ACK → prepare for reconnection
   - Initiate close → send FIN → prepare for reconnection

**Behavior**: On connection close, pending MSG_OUTBOX entries are discarded. User code should handle reconnection and message replay if needed.

---

### set_msg_acked_pos()
```cpp
// Set MSG acked position when TCP ACK received (cumulative ACK)
// NOTE: TCP ACKs are cumulative - simply advance the acked position
void TransportProcess::set_msg_acked_pos(uint64_t acked_pos) {
    tcp_state_->tx_frame.msg_acked_pos.store(acked_pos, std::memory_order_release);
}
```

### set_pong_acked_pos()
```cpp
// Set PONG acked position when TCP ACK received (cumulative ACK)
// NOTE: TCP ACKs are cumulative - simply advance the acked position
void TransportProcess::set_pong_acked_pos(uint64_t acked_pos) {
    tcp_state_->tx_frame.pong_acked_pos.store(acked_pos, std::memory_order_release);
}
```

---

## Zero-Copy Retransmit Queue

The retransmit queue tracks TCP sequence → frame allocation position mapping. This is essential for
position-based TX frame release: when a TCP ACK arrives, we need to know which frame positions
can be marked as acked.

### Capacity Planning

The retransmit queue capacity is bounded by `MSG_FRAMES` (or `PONG_FRAMES` for PONG queue).
The queue size represents in-flight data that hasn't been ACKed yet.

**Sizing Formula**: `queue_size = bandwidth_bytes_per_sec × RTT_sec / frame_payload_size`

**Example** (typical HFT scenario):
- Link bandwidth: 100 Mbps = 12.5 MB/s
- RTT: 10ms (typical for same-datacenter exchange connection)
- In-flight data: 12.5 MB/s × 0.01s = 125 KB
- Frame payload size: ~2 KB (TCP_MSS - TLS overhead)
- Required frames: 125 KB / 2 KB = ~63 frames

**Default Configuration**:
- `MSG_FRAMES = TOTAL_UMEM_FRAMES / 4 = 1024` (with 4096 total frames)
- This provides ~16x headroom for the 100Mbps/10ms example
- Accommodates burst scenarios and varied message sizes

**Tuning**: If you see backpressure (retransmit queue full), consider:
1. Increasing `TOTAL_UMEM_FRAMES` in Makefile
2. Reducing application send rate
3. Investigating network issues causing high RTT or packet loss

**TCP Sequence → Frame Position Mapping**:
1. Transport allocates frame at `msg_alloc_pos`, builds packet with seq range `[snd_nxt, snd_nxt + payload_len)`
2. Retransmit queue tracks `{alloc_pos, seq_start, seq_end}` for each in-flight frame
3. On TCP ACK, queue returns highest `alloc_pos + 1` where `seq_end <= ack_seq`
4. Transport stores result in `msg_acked_pos.store()`
5. XDP Poll releases all frames where `release_pos < acked_pos`

```cpp
// Each frame slot tracks its TCP sequence range for ACK → position mapping
struct alignas(64) RetransmitSegmentRef {
    uint64_t alloc_pos;           // [0:7]   Frame allocation position (for acked_pos calculation)
    uint64_t send_tsc;            // [8:15]  Send time (rdtsc) - set on add_ref(), updated on retransmit
    uint32_t frame_idx;           // [16:19] UMEM frame index (for retransmit access)
    uint32_t seq_start;           // [20:23] TCP sequence number at frame start
    uint32_t seq_end;             // [24:27] TCP sequence number at frame end (seq_start + payload_len)
    uint16_t frame_len;           // [28:29] TOTAL frame length (ETH+IP+TCP+payload)
    uint8_t  flags;               // [30]    TCP flags (SYN/FIN consume 1 seq byte each)
    uint8_t  retransmit_count;    // [31]    Number of retransmissions
    uint8_t  reserved[32];        // [32:63] Padding to cache line
};  // 64 bytes (cache-line aligned, no padding holes)

class ZeroCopyRetransmitQueue {
private:
    std::deque<RetransmitSegmentRef> queue_;
    uint64_t last_acked_pos_ = 0;  // Track highest acked FRAME POSITION (not TCP seq)

public:
    // Add frame reference for potential retransmit (NO memcpy)
    //
    // Parameters:
    //   alloc_pos: Frame allocation position (for acked_pos calculation on TCP ACK)
    //              This is the UMEM pool position, NOT the TCP sequence number.
    //   frame_idx: UMEM frame index (for retransmit access)
    //   seq: TCP sequence number at start of payload (snd_nxt BEFORE sending)
    //   payload_len: TCP payload length in bytes (encrypted_len from SSL_write)
    //                Used to compute seq_end = seq + payload_len
    //                NOTE: This is the TLS record size, NOT plaintext size
    //   frame_len: TOTAL Ethernet frame length (ETH+IP+TCP+payload)
    //   flags: TCP flags (SYN/FIN consume 1 seq byte each per RFC 793)
    //
    // IMPORTANT: Captures rdtscp() as send_tsc for RTO timing
    //
    // MAPPING: This queue maps TCP sequence numbers → frame allocation positions.
    // When TCP ACK arrives with ack_seq (uint32_t), we find all frames where
    // seq_end <= ack_seq and return the highest alloc_pos + 1. Transport then
    // stores this in msg_acked_pos (uint64_t) for XDP Poll to release frames.
    bool add_ref(uint64_t alloc_pos, uint32_t frame_idx, uint32_t seq,
                 uint16_t payload_len, uint16_t frame_len, uint8_t flags) {
        RetransmitSegmentRef ref;
        ref.alloc_pos = alloc_pos;
        ref.frame_idx = frame_idx;
        ref.seq_start = seq;
        // SYN and FIN consume 1 sequence byte each (RFC 793)
        ref.seq_end = seq + payload_len;
        if (flags & TCP_FLAG_SYN) ref.seq_end++;
        if (flags & TCP_FLAG_FIN) ref.seq_end++;
        ref.frame_len = frame_len;
        ref.flags = flags;
        ref.retransmit_count = 0;
        ref.send_tsc = rdtscp();  // Capture send time for RTO calculation
        queue_.push_back(ref);
        return true;
    }

    // Process ACK, return highest acked frame position + 1
    // IMPORTANT: Returns position for msg_acked_pos / pong_acked_pos update
    // TCP ACKs are cumulative: ACK=X means all bytes with seq < X have been received
    uint64_t ack_received(uint32_t ack_seq) {
        // Remove all segments where seq_end <= ack_seq (fully ACKed)
        while (!queue_.empty()) {
            const auto& ref = queue_.front();
            // seq_leq handles TCP sequence wrap-around
            if (seq_leq(ref.seq_end, ack_seq)) {
                // This frame is fully ACKed, update highest position
                last_acked_pos_ = std::max(last_acked_pos_, ref.alloc_pos + 1);
                queue_.pop_front();
            } else {
                break;  // Remaining frames not yet ACKed
            }
        }
        return last_acked_pos_;
    }

    // Get segments needing retransmission (by RTO timeout)
    // Returns refs where: rdtscp() - ref.send_tsc > rto_cycles
    std::vector<RetransmitSegmentRef*> get_retransmit_refs(uint64_t rto_cycles);

    // Mark segment as retransmitted (updates send_tsc to current rdtscp)
    void mark_retransmitted(uint32_t seq) {
        for (auto& ref : queue_) {
            if (ref.seq_start == seq) {
                ref.send_tsc = rdtscp();  // Reset RTO timer
                ref.retransmit_count++;
                break;
            }
        }
    }

    // Check if any segment exceeded max retransmits
    bool has_failed_segment() const;

    // Get current queue size for bounds checking
    size_t size() const { return queue_.size(); }
};

// TCP sequence number comparison (handles wrap-around)
// Returns true if a < b in TCP sequence space
inline bool seq_lt(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) < 0;
}

// Returns true if a <= b in TCP sequence space
inline bool seq_leq(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b) <= 0;
}
```

**Reference**: Actual implementation in `src/stack/tcp/tcp_retransmit.hpp` uses similar pattern
with `remove_acked()` returning frame indices. The pipeline extends this to track allocation
positions for the position-based release mechanism.

---

## Ring Buffer Interactions

| Ring | Role | API |
|------|------|-----|
| RAW_INBOX | Consumer | `process_manually()` + `commit_manually()` |
| RAW_OUTBOX | Producer | `try_claim()` + `publish()` |
| ACK_OUTBOX | Producer | `try_claim()` + `publish()` |
| PONG_OUTBOX | Producer | `try_claim()` + `publish()` |
| MSG_METADATA_INBOX | Producer | `try_claim()` + `publish()` |
| MSG_OUTBOX | Consumer | `process_manually()` + `commit_manually()` |
| PONGS | Consumer | `process_manually()` + `commit_manually()` |

---

## Critical Error Handling

| Condition | Action |
|-----------|--------|
| RAW_OUTBOX full | `std::abort()` - Frame in retransmit queue, must be sent |
| ACK_OUTBOX full | `std::abort()` - ACK must be sent |
| PONG_OUTBOX full | `std::abort()` - PONG must be sent |
| MSG_METADATA_INBOX full | `std::abort()` - WebSocket not keeping up |
| TX frame allocator empty | `std::abort()` - Out of TX frames |
| Too many retransmits | Set `tcp_state_->running[PROC_TRANSPORT].flag = 0` - Connection failed |
