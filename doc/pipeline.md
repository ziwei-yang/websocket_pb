# Pipeline WebSocket Library Implementation Plan

## Overview

Multi-process pipeline architecture for ultra-low-latency WebSocket using AF_XDP zero-copy transport. Each process pinned to dedicated CPU core with busy-polling.

**Source Location**: All new files in `./src/pipeline/`

**Compile-time Configuration**:
```cpp
// Passed from Makefile via -D flags (discovered at build time)
#ifndef PATH_MTU
#define PATH_MTU 1500  // Default, overridden by Makefile discovery
#endif

constexpr size_t TOTAL_UMEM_FRAMES = 4096;  // Configurable power of 2
constexpr size_t FRAME_SIZE = 4096;          // 4KB per frame
constexpr size_t RX_FRAMES = TOTAL_UMEM_FRAMES / 2;         // 50% for RX
constexpr size_t ACK_FRAMES = TOTAL_UMEM_FRAMES / 8;        // 12.5% for ACK
constexpr size_t PONG_FRAMES = TOTAL_UMEM_FRAMES / 8;       // 12.5% for PONG
constexpr size_t MSG_FRAMES = TOTAL_UMEM_FRAMES / 4;        // 25% for MSG

constexpr size_t TCP_MSS = PATH_MTU - 40;   // MTU - IP(20) - TCP(20)
static_assert(FRAME_SIZE >= PATH_MTU + 14); // 14 = ETH header
```

**Makefile MTU Discovery**:
```makefile
# Discover path MTU to target host at build time
TARGET_HOST ?= exchange.example.com
PATH_MTU := $(shell ping -c 1 -M do -s 1472 $(TARGET_HOST) 2>/dev/null && echo 1500 || echo 1400)
CXXFLAGS += -DPATH_MTU=$(PATH_MTU)
```

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                      N I C                                              │
└───────────────────────────────────────┬─────────────────────────────────────────────────┘
                                        │
            ┌───────────────────────────┴───────────────────────────┐
            │ XDP rx_ring                              XDP tx_ring  │
            │     │                                         ▲       │
            └─────┼─────────────────────────────────────────┼───────┘
                  │                                         │
┌─────────────────┼─────────────────────────────────────────┼─────────────────────────────┐
│                 ▼                                         │                             │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐│
│  │                      UMEM_BUFFER (TOTAL_UMEM_FRAMES × FRAME_SIZE)                  ││
│  ├────────────────────┬───────────────┬───────────────┬───────────────────────────────┤│
│  │  RX (0..RX-1)      │ ACK TX        │ PONG TX       │ MSG TX                        ││
│  │  for incoming      │ for TCP ACKs  │ encrypted     │ for WS messages               ││
│  │  packets           │               │ WS PONGs      │                               ││
│  └────────────────────┴───────────────┴───────────────┴───────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────────────┘
                  │                                         ▲
                  ▼                                         │
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           XDP POLL PROCESS (Core 0)                                     │
│  Loop:                                                                                  │
│    1. Batch collect: RAW_OUTBOX + ACK_OUTBOX + PONG_OUTBOX → tx_batch                  │
│    2. Single submit: xsk_ring_prod__submit(tx_batch) + sendto() kick                   │
│    3. rx_ring → RAW_INBOX (do not release UMEM yet)                                    │
│    4. (idle) track RAW_INBOX consumer → release consumed UMEM → fill_ring              │
│    5. (idle) comp_ring → derive pool from addr → reclaim TX UMEM                       │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                  │ RAW_INBOX              ▲ RAW_OUTBOX, ACK_OUTBOX, PONG_OUTBOX
                  ▼                        │
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         TRANSPORT PROCESS (Core 1)                                      │
│  State: peer_recv_window_, window_scale_, expected_seq_, pending_ack_seq_              │
│  Loop:                                                                                  │
│    0. TCP Retransmit: check RTO → retransmit via RAW_OUTBOX (highest priority)         │
│    1. TX: MSG_OUTBOX → respect peer_recv_window_ → SSL_write() → RAW_OUTBOX            │
│       - Handle SSL_ERROR_WANT_WRITE (buffer pending data)                              │
│       - Limit TLS record to TCP_MSS - TLS_OVERHEAD for single-segment alignment        │
│    2. RX: RAW_INBOX → parse TCP → update peer_recv_window_ → SSL BIO → SSL_read()     │
│       - Handle FIN/RST → signal shutdown                                               │
│       - Out-of-order → send dup ACK                                                    │
│       - Write to MSG_INBOX with wrap-flag if linear space < TLS record size           │
│    3. Adaptive ACK: Send when pkts >= 8 OR timeout >= 100us                            │
│    4. PONG: PONGS → SSL_write() → PONG_OUTBOX                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                  │ MSG_INBOX              ▲ MSG_OUTBOX, PONGS
                  ▼                        │
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          WEBSOCKET PROCESS (Core 2)                                     │
│  State: parse_pos_, consume_pos_, pending_frame_header_                                │
│  Loop:                                                                                  │
│    1. Read MSG_INBOX (handle wrap-flag: read from buffer head)                         │
│    2. Parse complete WS frames only (track partial frame state)                        │
│    3. Push complete frames to WS_FRAME_INFO_RING                                       │
│    4. On PING: build plaintext PONG → PONGS                                            │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                  │ WS_FRAME_INFO_RING
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          APPCLIENT PROCESS (Core 3)                                     │
│  Loop:                                                                                  │
│    1. Consume WS_FRAME_INFO_RING → on_message(payload, len, opcode)                    │
│    2. Mark MSG_INBOX consumed (advance app_consumed_pos)                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. UMEM Partitioning

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           UMEM_BUFFER Layout (configurable)                             │
├────────────────────────┬──────────────┬──────────────┬──────────────────────────────────┤
│     RX Frames          │   ACK TX     │  PONG TX     │         MSG TX                   │
│     [0, RX-1]          │ [RX, RX+ACK) │[RX+ACK, ...)│       [RX+ACK+PONG, END)         │
│     50% of pool        │   12.5%      │   12.5%      │         25%                      │
├────────────────────────┼──────────────┼──────────────┼──────────────────────────────────┤
│ Owner: XDP Poll        │  Transport   │  Transport   │       Transport                  │
│ Managed: fill_ring     │  circular    │  circular    │       circular                   │
└────────────────────────┴──────────────┴──────────────┴──────────────────────────────────┘
```

**Note**: All sizes are compile-time configurable. HFT users should size based on their traffic patterns.

---

## 3. Ring Buffers

| Ring Name | Producer → Consumer | Element Type | Contents |
|-----------|---------------------|--------------|----------|
| RAW_INBOX | XDP Poll → Transport | UMEMFrameDescriptor | RX packet descriptors |
| RAW_OUTBOX | Transport → XDP Poll | UMEMFrameDescriptor | Encrypted TX + retransmit |
| ACK_OUTBOX | Transport → XDP Poll | UMEMFrameDescriptor | TCP ACK frames |
| PONG_OUTBOX | Transport → XDP Poll | UMEMFrameDescriptor | Encrypted WS PONG frames |
| MSG_INBOX | Transport → WebSocket | Byte stream | Decrypted TLS data |
| MSG_OUTBOX | AppClient → Transport | Byte stream | Plaintext WS data to encrypt |
| PONGS | WebSocket → Transport | PongFrame | Plaintext WS PONG payloads |
| WS_FRAME_INFO_RING | WebSocket → AppClient | WSFrameInfo | Parsed WS frame metadata |

---

## 4. Data Structures

### 4.1 UMEMFrameDescriptor (32 bytes)

```cpp
struct alignas(32) UMEMFrameDescriptor {
    uint64_t umem_addr;           // UMEM frame address
    uint16_t frame_len;           // Total frame length
    uint16_t payload_offset;      // Offset to payload from frame start
    uint16_t payload_len;         // Payload length
    uint16_t reserved1;
    uint32_t tcp_seq;             // TCP sequence number
    uint32_t tcp_ack;             // TCP acknowledgment number
    uint64_t hw_timestamp_ns : 48;
    uint64_t tcp_flags : 8;
    uint64_t frame_type : 8;      // RX=0, ACK=1, PONG=2, MSG=3
};
```

### 4.2 WSFrameInfo (16 bytes)

```cpp
struct alignas(16) WSFrameInfo {
    uint32_t msg_inbox_offset;    // Offset in MSG_INBOX
    uint32_t payload_len;
    uint64_t parse_cycle : 48;    // rdtscp when parsed
    uint64_t opcode : 8;          // 0x01=text, 0x02=binary, 0x09=ping, 0x0A=pong
    uint64_t is_final : 1;
    uint64_t reserved : 7;
};
```

### 4.3 PongFrame

```cpp
struct PongFrame {
    uint8_t payload[125];         // Max PONG payload per RFC 6455
    uint8_t payload_len;
};
```

### 4.4 MSG_INBOX Header (per write region)

```cpp
struct MsgInboxRegion {
    uint16_t data_len;            // Length of TLS decrypted data
    uint8_t  wrap_flag;           // 1 = consumer should read from buffer head next
    uint8_t  reserved;
    uint8_t  data[];              // Decrypted payload
};
```

---

## 5. Process Main Loops

### 5.1 XDP Poll Process

```cpp
while (running_) {
    bool data_moved = false;
    uint32_t tx_batch_count = 0;
    uint32_t tx_batch_idx;

    // Reserve TX ring space for batch
    xsk_ring_prod__reserve(&tx_ring_, TX_BATCH_SIZE, &tx_batch_idx);

    // 1. Batch collect from all outboxes
    while (tx_batch_count < TX_BATCH_SIZE && raw_outbox_.pop(&desc)) {
        xsk_ring_prod__tx_desc(&tx_ring_, tx_batch_idx + tx_batch_count++) = desc;
        data_moved = true;
    }
    while (tx_batch_count < TX_BATCH_SIZE && ack_outbox_.pop(&desc)) {
        xsk_ring_prod__tx_desc(&tx_ring_, tx_batch_idx + tx_batch_count++) = desc;
        data_moved = true;
    }
    while (tx_batch_count < TX_BATCH_SIZE && pong_outbox_.pop(&desc)) {
        xsk_ring_prod__tx_desc(&tx_ring_, tx_batch_idx + tx_batch_count++) = desc;
        data_moved = true;
    }

    // 2. Single submit + kick
    if (tx_batch_count > 0) {
        xsk_ring_prod__submit(&tx_ring_, tx_batch_count);
        sendto(xsk_fd_, NULL, 0, MSG_DONTWAIT, NULL, 0);
    }

    // 3. RX: rx_ring → RAW_INBOX
    uint32_t nb_pkts = xsk_ring_cons__peek(&rx_ring_, RX_BATCH, &idx);
    for (uint32_t i = 0; i < nb_pkts; i++) {
        raw_inbox_.push(build_descriptor(rx_ring_[idx + i]));
    }
    if (nb_pkts > 0) {
        xsk_ring_cons__release(&rx_ring_, nb_pkts);
        data_moved = true;
    }

    // 4. (idle) Reclaim consumed RX UMEM → fill_ring
    if (!data_moved) {
        uint64_t consumer_pos = raw_inbox_.consumer_pos();
        while (last_released_ < consumer_pos) {
            refill_frame_to_fill_ring(raw_inbox_.peek_at(last_released_++).umem_addr);
        }
    }

    // 5. (idle) comp_ring → reclaim TX UMEM by address range
    if (!data_moved) {
        uint32_t n = xsk_ring_cons__peek(&comp_ring_, BATCH, &idx);
        for (uint32_t i = 0; i < n; i++) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&comp_ring_, idx + i);
            uint32_t frame_idx = addr / FRAME_SIZE;
            // Derive pool from address range and return to appropriate allocator
            return_frame_to_pool(frame_idx);
        }
        xsk_ring_cons__release(&comp_ring_, n);
    }
}
```

### 5.2 Transport Process

```cpp
// State from handshake (stored in shared memory)
uint32_t peer_recv_window_;       // From SYN-ACK
uint8_t  peer_window_scale_;      // From SYN-ACK TCP options
uint32_t expected_seq_;           // Next expected RX sequence
uint32_t send_una_;               // Oldest unacked TX sequence
uint32_t send_next_;              // Next TX sequence

// Adaptive ACK state
uint32_t pending_ack_seq_ = 0;
uint32_t pkts_since_last_ack_ = 0;
uint64_t last_ack_time_us_ = 0;
constexpr uint32_t ACK_BATCH_THRESHOLD = 8;
constexpr uint64_t ACK_TIMEOUT_US = 100;

// TLS sizing (TCP_MSS defined in pipeline_config.hpp from PATH_MTU)
constexpr size_t TLS13_OVERHEAD = 5 + 16;  // Record header + AEAD tag
constexpr size_t MAX_TLS_PLAINTEXT = TCP_MSS - TLS13_OVERHEAD;

// Pending SSL_write state
const uint8_t* pending_write_buf_ = nullptr;
size_t pending_write_len_ = 0;

while (running_) {
    uint64_t now_us = get_time_us();

    // 0. HIGHEST PRIORITY: TCP Retransmission
    check_retransmit();

    // 1. TX: MSG_OUTBOX → SSL_write → RAW_OUTBOX
    // Handle pending partial write first
    if (pending_write_len_ > 0) {
        int n = SSL_write(ssl_, pending_write_buf_, pending_write_len_);
        if (n > 0) {
            pending_write_buf_ += n;
            pending_write_len_ -= n;
        } else if (SSL_get_error(ssl_, n) != SSL_ERROR_WANT_WRITE) {
            handle_ssl_error(n);
        }
    }

    // Check peer receive window before sending
    uint32_t bytes_in_flight = send_next_ - send_una_;
    uint32_t effective_window = peer_recv_window_ << peer_window_scale_;
    uint32_t available = (effective_window > bytes_in_flight)
        ? effective_window - bytes_in_flight : 0;

    while (pending_write_len_ == 0 && available > 0 && msg_outbox_.readable() > 0) {
        size_t chunk = std::min({msg_outbox_.readable(), MAX_TLS_PLAINTEXT, (size_t)available});
        uint8_t* data = msg_outbox_.read_ptr();

        int n = SSL_write(ssl_, data, chunk);
        if (n > 0) {
            msg_outbox_.advance_read(n);
            // Build TCP packet, add to retransmit queue, push to RAW_OUTBOX
            send_encrypted_packet(n);
            available -= n;
        } else {
            int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_WRITE) {
                pending_write_buf_ = data;
                pending_write_len_ = chunk;
            }
            break;
        }
    }

    // 2. RX: RAW_INBOX → parse → SSL_read → MSG_INBOX
    while (raw_inbox_.pop(&desc)) {
        uint8_t* frame = umem_ + desc.umem_addr;
        TcpParseResult tcp = parse_tcp_packet(frame, desc.frame_len);

        // Update peer window from ACK
        if (tcp.flags & TCP_FLAG_ACK) {
            peer_recv_window_ = tcp.window;  // Will be shifted by window_scale_
            retransmit_queue_.ack_received(tcp.ack);
        }

        // Handle FIN
        if (tcp.flags & TCP_FLAG_FIN) {
            send_fin_ack();
            running_.store(false);
            continue;
        }

        // Handle RST
        if (tcp.flags & TCP_FLAG_RST) {
            running_.store(false);
            continue;
        }

        // Process payload
        if (tcp.payload_len > 0) {
            if (tcp.seq == expected_seq_) {
                expected_seq_ += tcp.payload_len;
                pending_ack_seq_ = expected_seq_;
                pkts_since_last_ack_++;

                // Write to SSL BIO
                BIO_write(bio_in_, frame + tcp.payload_offset, tcp.payload_len);
            } else {
                // Out-of-order: send dup ACK immediately
                send_dup_ack(pending_ack_seq_);
            }
        }
    }

    // SSL_read → MSG_INBOX
    while (SSL_pending(ssl_) > 0 || BIO_ctrl_pending(bio_in_) > 0) {
        // Check linear space to wrap point
        size_t linear_space = msg_inbox_.linear_space_to_wrap();

        if (linear_space < TLS_RECORD_MAX_SIZE) {
            // Set wrap flag so consumer knows to read from head next
            msg_inbox_.set_wrap_flag();
            msg_inbox_.reset_to_head();
            linear_space = msg_inbox_.linear_space_to_wrap();
        }

        uint8_t* ptr = msg_inbox_.write_ptr();
        int n = SSL_read(ssl_, ptr, linear_space);
        if (n > 0) {
            msg_inbox_.advance_write(n);
        } else {
            int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ) break;
            handle_ssl_error(n);
        }
    }

    // 3. Adaptive ACK
    bool should_ack = (pkts_since_last_ack_ >= ACK_BATCH_THRESHOLD) ||
                      ((now_us - last_ack_time_us_) >= ACK_TIMEOUT_US && pkts_since_last_ack_ > 0);
    if (should_ack) {
        send_ack(pending_ack_seq_);
        pkts_since_last_ack_ = 0;
        last_ack_time_us_ = now_us;
    }

    // 4. PONG encryption
    PongFrame pong;
    while (pongs_.pop(&pong)) {
        uint8_t ws_frame[127];
        size_t ws_len = build_ws_pong_frame(ws_frame, pong.payload, pong.payload_len);
        SSL_write(ssl_, ws_frame, ws_len);
        send_encrypted_pong();
    }
}
```

### 5.3 WebSocket Process

```cpp
// Partial frame state
struct PendingFrame {
    uint8_t header[14];      // Max WS header size
    uint8_t header_len;      // Bytes of header received
    uint8_t header_needed;   // Total header bytes needed (2-14)
    uint64_t payload_len;    // Payload length from header
    uint64_t payload_read;   // Payload bytes already processed
    uint8_t opcode;
    bool has_pending;
};
PendingFrame pending_ = {};

while (running_) {
    // Handle wrap flag from Transport
    if (msg_inbox_.check_and_clear_wrap_flag()) {
        msg_inbox_.reset_read_to_head();
    }

    size_t available = msg_inbox_.readable();
    if (available == 0) continue;

    const uint8_t* data = msg_inbox_.read_ptr();
    size_t offset = 0;
    size_t consumed = 0;

    while (offset < available) {
        WSParseResult result;

        if (pending_.has_pending) {
            // Continue parsing pending frame
            result = continue_parse_ws_frame(data + offset, available - offset, &pending_);
        } else {
            // Start new frame
            result = parse_ws_frame(data + offset, available - offset, &pending_);
        }

        if (result.status == WS_NEED_MORE_DATA) {
            // Partial frame - save state and wait
            break;
        }

        if (result.status == WS_FRAME_COMPLETE) {
            if (pending_.opcode == WS_OPCODE_PING) {
                // Build PONG with same payload
                PongFrame pong;
                pong.payload_len = std::min(pending_.payload_len, (uint64_t)125);
                memcpy(pong.payload, data + offset + result.payload_offset, pong.payload_len);
                pongs_.push(pong);
            } else if (pending_.opcode == WS_OPCODE_TEXT || pending_.opcode == WS_OPCODE_BINARY) {
                // Push frame info for AppClient
                WSFrameInfo info = {
                    .msg_inbox_offset = msg_inbox_.current_offset() + offset + result.payload_offset,
                    .payload_len = (uint32_t)pending_.payload_len,
                    .parse_cycle = rdtscp(),
                    .opcode = pending_.opcode,
                    .is_final = result.is_final,
                };
                ws_frame_ring_.push(info);
            }

            offset += result.total_consumed;
            consumed = offset;
            pending_.has_pending = false;
        }
    }

    // Only advance past fully consumed frames
    if (consumed > 0) {
        msg_inbox_.advance_read(consumed);
    }
}
```

### 5.4 AppClient Process

```cpp
while (running_) {
    WSFrameInfo info;
    while (ws_frame_ring_.pop(&info)) {
        const uint8_t* payload = msg_inbox_.data_at(info.msg_inbox_offset);
        on_message(payload, info.payload_len, info.opcode);
    }

    // Advance consumption position
    msg_inbox_.set_app_consumed(current_pos_);
}
```

---

## 6. Handshake Phase (Setup)

Before forking into 4 processes, a single process performs:

```
1. Create shared memory regions (UMEM, all ring buffers, tcp_state)
2. Initialize XDP socket + UMEM
3. TCP handshake (SYN → SYN-ACK → ACK)
   - Capture window_scale from SYN-ACK options → tcp_state_shm->window_scale
   - Capture initial window → tcp_state_shm->peer_recv_window
4. TLS handshake (ClientHello → ... → Finished)
5. WebSocket handshake (HTTP Upgrade)
6. Connection ESTABLISHED
7. Fork 4 processes, each pins to dedicated core
```

---

## 7. Shared Memory Layout

```
/dev/shm/pipeline/
├── umem.dat              # UMEM buffer
├── raw_inbox.shm         # RAW_INBOX ring
├── raw_outbox.shm        # RAW_OUTBOX ring
├── ack_outbox.shm        # ACK_OUTBOX ring
├── pong_outbox.shm       # PONG_OUTBOX ring
├── msg_inbox.shm         # MSG_INBOX byte stream + wrap flags
├── msg_outbox.shm        # MSG_OUTBOX byte stream
├── pongs.shm             # PONGS ring
├── ws_frame_info.shm     # WS_FRAME_INFO_RING
└── tcp_state.shm         # TCP state: window_scale, peer_window, running flag, etc.
```

---

## 8. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Batch TX submission** | Single `xsk_ring_prod__submit()` per loop reduces syscall overhead |
| **Adaptive ACK** | ACK after 8 pkts OR 100us - balances throughput vs latency |
| **PONG via Transport** | Ensures TLS encryption - WebSocket only builds plaintext |
| **Wrap flag in MSG_INBOX** | Avoids WS frame spanning wrap point - consumer reads from head |
| **Partial WS frame tracking** | Parser maintains state across SSL_read() boundaries |
| **comp_ring → pool mapping** | Derive pool from address range, no metadata needed |
| **Window scale from handshake** | Captured in setup phase, stored in shared memory |

---

## 9. File Structure

```
src/pipeline/
├── pipeline_config.hpp      # Constants, static_asserts, UMEM ranges
├── umem_desc.hpp            # UMEMFrameDescriptor
├── ring_buffers.hpp         # All ring buffer types
├── msg_inbox.hpp            # MSG_INBOX with wrap flag support
├── ws_parser.hpp            # WebSocket parser with partial frame support
├── xdp_poll_process.hpp     # XDP Poll process
├── transport_process.hpp    # Transport process
├── websocket_process.hpp    # WebSocket process
├── app_client.hpp           # AppClient base class
└── pipeline_manager.hpp     # Orchestration, shared memory setup, fork
```

---

## 10. Implementation Phases

### Phase 1: Core Infrastructure
- [ ] `pipeline_config.hpp` - UMEM layout, compile-time sizing
- [ ] `ring_buffers.hpp` - SPSC ring implementations
- [ ] `msg_inbox.hpp` - Byte stream with wrap flag

### Phase 2: Data Structures
- [ ] `umem_desc.hpp` - UMEMFrameDescriptor
- [ ] `ws_parser.hpp` - Stateful WS parser

### Phase 3: Processes
- [ ] `xdp_poll_process.hpp` - Batch TX, comp_ring pool mapping
- [ ] `transport_process.hpp` - SSL, window tracking, FIN/RST
- [ ] `websocket_process.hpp` - Partial frame handling
- [ ] `app_client.hpp` - Consumer interface

### Phase 4: Integration
- [ ] `pipeline_manager.hpp` - Setup, handshake, fork
- [ ] End-to-end testing

---

## 11. Summary of Addressed Issues

| Issue | Solution |
|-------|----------|
| PONG bypasses TLS | Routes through Transport for encryption |
| TCP retransmission | Uses existing RetransmitQueue |
| Batch TX | Single xsk_ring_prod__submit() per loop |
| Adaptive ACK | 8 packets OR 100us timeout |
| TCP window tracking | peer_recv_window_ updated from ACKs |
| TLS/TCP alignment | Limit TLS record to TCP_MSS - overhead |
| comp_ring pool mapping | Derive from address range |
| WS frame spans TLS records | Stateful parser tracks partial frames |
| MSG_INBOX wrap | Wrap flag tells consumer to read from head |
| SSL_write partial | Buffer and retry on WANT_WRITE |
| TCP FIN/RST | Detect and signal shutdown via running_ flag |
| Window scale | Captured from SYN-ACK in handshake phase |
| Multi-connection | Single connection per pipeline; N pipelines for N connections |
| Path MTU | Discovered in Makefile, passed as -DPATH_MTU compile flag |

---

## 12. Additional Considerations

### 12.1 WebSocket CLOSE Frame Handling

**Problem**: Server may send WS CLOSE frame to initiate shutdown.

**Solution**: WebSocket process writes a special CLOSE message to MSG_OUTBOX to notify Transport:

```cpp
// In WebSocket Process
if (pending_.opcode == WS_OPCODE_CLOSE) {
    // Extract close code (optional first 2 bytes)
    uint16_t close_code = (payload_len >= 2)
        ? (payload[0] << 8) | payload[1] : 1005;

    // Write special CLOSE message to MSG_OUTBOX
    // Transport will detect this and handle connection close
    MsgOutboxHeader hdr = {
        .type = MSG_TYPE_WS_CLOSE,
        .close_code = close_code,
    };
    msg_outbox_.write(&hdr, sizeof(hdr));
}

// In Transport Process
if (msg_outbox_hdr.type == MSG_TYPE_WS_CLOSE) {
    // Send WS CLOSE response frame
    send_ws_close_frame(msg_outbox_hdr.close_code);
    // Initiate TCP FIN
    send_fin();
    running_.store(false, std::memory_order_release);
}
```

### 12.2 Client-to-Server Masking

**Requirement**: RFC 6455 mandates that client-to-server frames MUST be masked.

**Solution**: Transport wraps payload with WS frame header + mask. Mask key is always `[0,0,0,0]` (XOR with zero = no transformation, but frame is technically masked per spec).

```cpp
// In Transport, when consuming MSG_OUTBOX
constexpr uint8_t ZERO_MASK[4] = {0, 0, 0, 0};

// Build WS frame: opcode | length | mask_key=[0,0,0,0] | payload (unchanged)
build_ws_client_frame(opcode, payload, len, ZERO_MASK, ws_frame);
SSL_write(ssl_, ws_frame, ws_frame_len);
```

### 12.3 MSG_INBOX Overwrite Handling

**Scenario**: If WebSocket/AppClient falls behind, Transport's write_pos may overtake read_pos.

**Solution**: Transport continues writing and marks the overwritten region as "read dirty":

```cpp
// In Transport, before SSL_read
if (write_pos_ > read_pos_ + MSG_INBOX_SIZE) {
    // Consumer is too far behind - mark dirty
    msg_inbox_.set_read_dirty();
}

// Write anyway - HFT assumes consumer keeps up
uint8_t* ptr = msg_inbox_.write_ptr();
int n = SSL_read(ssl_, ptr, available);
if (n > 0) {
    msg_inbox_.advance_write(n);
}

// In WebSocket Process - check dirty flag
if (msg_inbox_.check_and_clear_dirty()) {
    // Data was overwritten - reset read position to current write position
    // Log warning, some messages were lost
    msg_inbox_.reset_read_to_write();
}
```

### 12.4 TLS Session Resumption

**Implementation**: Store TLS 1.3 session ticket after initial handshake for fast reconnection:

```cpp
// During initial handshake (Setup Phase)
SSL_set_session_id_context(ssl_, session_id, session_id_len);

// After handshake completes, store session ticket
SSL_SESSION* session = SSL_get1_session(ssl_);
save_session_ticket(session);  // Persist to shared memory or file

// On reconnection
SSL_SESSION* saved_session = load_session_ticket();
if (saved_session) {
    SSL_set_session(ssl_, saved_session);
    // Attempt 0-RTT if using TLS 1.3 early data
}
```

**Benefits**:
- Reduces handshake latency from 2-RTT to 1-RTT (session resumption)
- Optional 0-RTT for even faster reconnect (with replay considerations)

---

## 13. Multi-Connection Support (XDP/DPDK Mode)

**Scope**: Current plan is **single-connection per pipeline**. For N connections, deploy N pipeline instances.

### 13.1 Connection Isolation Strategy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                    NIC                                       │
│           RX queues: 0, 1, 2, ... N-1 (RSS or Flow Director)                │
└───────────┬───────────┬───────────┬─────────────────────────────────────────┘
            │           │           │
     ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
     │ Pipeline 0  │ │ Pipeline 1  │ │ Pipeline N  │
     │ Cores 0-3   │ │ Cores 4-7   │ │ Cores ...   │
     │ Connection A│ │ Connection B│ │ Connection N│
     └─────────────┘ └─────────────┘ └─────────────┘
```

### 13.2 Flow Steering

Each connection steered to dedicated NIC RX queue via:

```cpp
// Using ethtool ntuple filters (Intel NICs)
// Steer src_ip:src_port + dst_ip:dst_port → queue N
system("ethtool -N eth0 flow-type tcp4 src-ip 10.0.0.1 dst-port 443 action 0");

// Or XDP BPF map for dynamic steering
struct bpf_map_def SEC("maps") conn_to_queue = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flow_key),   // {src_ip, dst_ip, src_port, dst_port}
    .value_size = sizeof(uint32_t),         // queue_id
    .max_entries = MAX_CONNECTIONS,
};
```

### 13.3 UMEM Isolation

Each pipeline has its own UMEM region (no sharing between connections):

```cpp
// In pipeline_manager.hpp
for (int i = 0; i < num_connections; i++) {
    PipelineConfig cfg = {
        .queue_id = i,
        .umem_offset = i * UMEM_SIZE_PER_CONNECTION,
        .core_base = i * 4,  // 4 cores per pipeline
    };
    pipelines_[i] = std::make_unique<Pipeline>(cfg);
}
```

### 13.4 Shared Memory Naming

Each connection uses unique shared memory paths:

```
/dev/shm/pipeline_0/    # Connection 0
/dev/shm/pipeline_1/    # Connection 1
/dev/shm/pipeline_N/    # Connection N
```

### 13.5 Resource Requirements

| Connections | CPU Cores | Memory (UMEM) |
|-------------|-----------|---------------|
| 1           | 4         | 16 MB         |
| 4           | 16        | 64 MB         |
| 8           | 32        | 128 MB        |

**Note**: Current HFT deployments typically use 1-4 connections to exchanges. The single-connection-per-pipeline model is intentional for isolation and simplicity.

---

## 14. HFT Design Notes

| Assumption | Rationale |
|------------|-----------|
| UMEM sizes adequate | HFT traffic is predictable; sizes are compile-time configurable |
| No OOO reorder buffer | Low-loss datacenter network; rely on dup ACK + retransmit |
| Busy-polling | Each process on dedicated core, no context switches |
| Fast consumer | WebSocket/AppClient keeps up with Transport writes |
| Single connection per pipeline | Isolation, simplicity, dedicated resources |
| MTU discovered at build time | Path MTU via Makefile task, passed as -DPATH_MTU |
