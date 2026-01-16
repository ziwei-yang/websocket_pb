# Pipeline WebSocket Library - Architecture

## Overview

Multi-process pipeline architecture for ultra-low-latency WebSocket using AF_XDP zero-copy transport. Each process pinned to dedicated CPU core with busy-polling.

**Source Location**: All new files in `./src/pipeline/`

**Related Documents**:
- [Handshake Phase (Setup)](pipeline_handshake.md)
- [XDP Poll Process (Core 2)](pipeline_0_nic.md)
- [Transport Process (Core 4)](pipeline_1_trans.md)
- [WebSocket Process (Core 6)](pipeline_2_ws.md)
- [AppClient Process (Core 8)](pipeline_3_app.md)

> **Note**: File prefixes (0/1/2/3) are process indices. Core assignments (2/4/6/8) are runtime arguments and will be configurable.

**Key Design Decisions**:
- IPC Backend: hftshm+disruptor IPC mode for all fixed-size event rings
- UMEM Frame Size: Computed in Makefile as `((PATH_MTU + 94 + 1023) / 1024) * 1024`, passed as -DFRAME_SIZE
  - MTU 1500 → FRAME_SIZE = 2048 bytes
  - MTU 9000 (jumbo) → FRAME_SIZE = 10240 bytes
- MTU: Mandatory Makefile argument (compilation fails if not provided)
- Process Model: 4 separate processes via fork()
- **Full-Buffer Abort**: The entire application aborts on any full-buffer condition. This is intentional - a full buffer indicates misconfiguration (buffer too small or consumer too slow). The system is designed for deterministic latency, not graceful degradation.
- **comp_ring FIFO Assumption**: The design assumes XDP comp_ring returns frames in submission order (FIFO). This is the typical behavior of NIC DMA completion.
  - **If violated for ACK frames**: `ack_release_pos` advances past an unreleased frame, creating a "leaked" slot. The slot becomes reusable after counter wrap-around (~2^64 allocations). Practically harmless but wastes one frame slot.
  - **If violated for MSG/PONG frames**: No immediate impact - these use ACK-based release via `acked_pos`, not comp_ring order. However, debug assertions will abort to signal the unexpected NIC behavior.
  - **Detection**: In debug builds (`DEBUG`), assertions verify ordering and abort with diagnostics. If encountered in production, it indicates a NIC driver bug - contact driver vendor.
  - **Tested NICs**: igc (Intel I225), Mellanox ConnectX - all return completions in FIFO order.
- **Mandatory Processes**: XDP Poll, Transport, and WebSocket are **mandatory**. AppClient is **optional** (can be omitted if user handles WS frames directly in WebSocket callbacks).
  - If WebSocket is slow, MSG_METADATA_INBOX fills up → Transport aborts on `try_claim()` failure
  - Same design decision: abort on buffer full applies to MSG_METADATA_INBOX (WebSocket too slow)

**Compile-time Configuration**:
```cpp
// Passed from Makefile via -D flags
#ifndef PATH_MTU
#error "PATH_MTU must be defined. Use: make PATH_MTU=1500"
#endif

#ifndef FRAME_SIZE
#error "FRAME_SIZE must be defined. Makefile calculates: ((PATH_MTU + 94 + 1023) / 1024) * 1024"
#endif

// Validate at compile time
static_assert(FRAME_SIZE >= PATH_MTU + 94, "FRAME_SIZE must fit PATH_MTU + headers");
static_assert(FRAME_SIZE % 1024 == 0, "FRAME_SIZE must be 1KB aligned");

constexpr size_t TOTAL_UMEM_FRAMES = 65536;  // 16x larger for high throughput

// UMEM partition fractions (1/2 + 1/8 + 1/8 + 1/4 = 1)
constexpr size_t RX_FRAMES   = TOTAL_UMEM_FRAMES / 2;     // 32768 for RX
constexpr size_t ACK_FRAMES  = TOTAL_UMEM_FRAMES / 8;     // 8192 for TCP ACKs
constexpr size_t PONG_FRAMES = TOTAL_UMEM_FRAMES / 8;     // 8192 for encrypted WS PONGs
constexpr size_t MSG_FRAMES  = TOTAL_UMEM_FRAMES / 4;     // 16384 for WS messages

constexpr size_t TCP_MSS = PATH_MTU - 40;   // MTU - IP(20) - TCP(20)

// MSG_INBOX size (64MB byte stream ring buffer - 16x larger)
constexpr size_t MSG_INBOX_SIZE = 64 * 1024 * 1024;  // 64MB

// TX pool size for frame ACK tracking (ACK + PONG + MSG pools)
constexpr size_t TX_POOL_SIZE = ACK_FRAMES + PONG_FRAMES + MSG_FRAMES;

// Batch sizes for XDP Poll
constexpr uint32_t RX_BATCH = 32;
constexpr uint32_t TX_BATCH_SIZE = 32;
constexpr uint32_t COMP_BATCH = 32;  // Completion ring batch size

// Trickle frame size (cache-line aligned, actual packet is 43 bytes)
constexpr size_t TRICKLE_FRAME_SIZE = 64;

// Frame type constants (used in UMEMFrameDescriptor.frame_type)
// See Section 3.1 for FrameType enum definition
enum FrameType : uint8_t {
    FRAME_TYPE_RX   = 0,  // RX frames [0, RX_FRAMES) - incoming packets
    FRAME_TYPE_ACK  = 1,  // ACK frames - pure TCP ACK (no payload, immediate release)
    FRAME_TYPE_PONG = 2,  // PONG frames - WebSocket PONG (ACK-based release)
    FRAME_TYPE_MSG  = 3,  // MSG frames - data messages (ACK-based release)
};

// Ring buffer sizes (power of 2, 16x larger for high throughput)
constexpr size_t RAW_INBOX_SIZE = 32768;
constexpr size_t RAW_OUTBOX_SIZE = 32768;
constexpr size_t ACK_OUTBOX_SIZE = 8192;
constexpr size_t PONG_OUTBOX_SIZE = 1024;
constexpr size_t MSG_METADATA_SIZE = 65536;
constexpr size_t WS_FRAME_INFO_SIZE = 65536;
constexpr size_t PONGS_SIZE = 1024;
constexpr size_t MSG_OUTBOX_SIZE = 8192;
```

---

## 1. Architecture Diagram

**Disruptor IPC Mode API** (NO push() - use sequencer with IPC constructor):
- **Key IPC Requirements**:
  1. `atomic_sequence<true>` (external pointer mode - points to shared memory)
  2. `sequencer(buffer_size, cursor_ptr, published_ptr, region)` IPC constructor
  3. `external_storage_policy` for ring buffer (data in shared memory)
- **Producers**: `int64_t seq = sequencer.try_claim();` → **ABORT if seq < 0** (buffer full = misconfiguration) → write `ring_buffer[seq]` → `sequencer.publish(seq);`
- **Manual Consumers** (XDP Poll, Transport, WebSocket on MSG_INBOX): `process_manually<Lambda>()` + `commit_manually()`
- **Auto Consumers** (WebSocket on MSG_METADATA_INBOX, AppClient): `disruptor::event_processor.run()` (blocking call with `on_event()` handler)
- **Design Decision**: Always use `try_claim()`, never blocking `claim()`. Abort process on full buffer - indicates misconfiguration (buffer too small or consumer too slow).

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
│  ┌────────────────────────────────────────────────────────────────────────────────┬───┐│
│  │          UMEM_BUFFER (TOTAL_UMEM_FRAMES × FRAME_SIZE)    │TRK││
│  ├────────────────────┬───────────────┬───────────────┬──────────────────────────┼───┤│
│  │  RX (0..N/2-1)     │ ACK TX        │ PONG TX       │ MSG TX                   │64B││
│  │  1/2 of pool       │ 1/8 of pool   │ 1/8 of pool   │ 1/4 of pool              │   ││
│  │  for incoming      │ for TCP ACKs  │ encrypted     │ for WS messages          │   ││
│  │  packets           │               │ WS PONGs      │                          │   ││
│  └────────────────────┴───────────────┴───────────────┴──────────────────────────┴───┘│
└─────────────────────────────────────────────────────────────────────────────────────────┘
                  │                                         ▲
                  ▼                                         │
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                 XDP POLL PROCESS (Core 2) - Thin, Replaceable with DPDK                 │
│  *** NO ETH/IP/TCP parsing - only raw frame moving ***                                  │
│  API: process_manually<Lambda> for consumers (commit after TX submit)                   │
│       sequencer.try_claim() + ring_buffer[seq] + sequencer.publish(seq) for producers  │
│  Loop:                                                                                  │
│    1. submit_tx_batch(): process_manually on outboxes → submit → commit after submit   │
│    2. process_rx(): rx_ring → RAW_INBOX via try_claim() + publish()                    │
│    3. (always) send_trickle() every 8 iterations via AF_PACKET socket                  │
│    4. (idle: !data_moved) process_completions(): comp_ring → derive pool → handle      │
│    5. (idle: !data_moved) release_acked_tx_frames(): advance PONG/MSG release_pos      │
│    6. (idle: !data_moved) reclaim_rx_frames(): consumer seq → fill_ring                │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                  │ RAW_INBOX              ▲ RAW_OUTBOX, ACK_OUTBOX, PONG_OUTBOX
                  ▼                        │
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                   TRANSPORT PROCESS (Core 4) - Full ETH/IP/TCP Stack                    │
│  *** All protocol parsing/building happens here - decoupled from NIC layer ***         │
│  API: process_manually<Lambda> + commit_manually() for consumers                        │
│       sequencer.try_claim() + ring_buffer[seq] + sequencer.publish(seq) for producers  │
│  State: peer_recv_window_, peer_window_scale_, tcp_params_.rcv_nxt, pending_ack_seq_   │
│  Loop:                                                                                  │
│    0. TCP Retransmit: check RTO → retransmit via RAW_OUTBOX (highest priority)         │
│    1. TX: process_manually on MSG_OUTBOX → SSL_write() → RAW_OUTBOX via try_claim()    │
│       - Memory BIO: SSL_ERROR_WANT_WRITE never occurs (auto-grow buffers)              │
│       - Limit TLS record to TCP_MSS - TLS_OVERHEAD for single-segment alignment        │
│    2. RX: process_manually on RAW_INBOX → parse ETH/IP/TCP → SSL BIO → SSL_read()      │
│       - Handle FIN/RST → signal shutdown                                               │
│       - Out-of-order → send immediate dup ACK for fast retransmit (N4)                 │
│       - Write to MSG_INBOX with wrap-flag if linear space < TLS record size           │
│    3. Adaptive ACK: Send when pkts >= 8 OR timeout >= 100us                            │
│    4. PONG: process_manually on PONGS → SSL_write() → PONG_OUTBOX via try_claim_batch()│
└─────────────────────────────────────────────────────────────────────────────────────────┘
                  │ MSG_METADATA_INBOX + MSG_INBOX    ▲ MSG_OUTBOX, PONGS
                  ▼                                   │
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          WEBSOCKET PROCESS (Core 6)                                     │
│  API: event_processor.run() on MSG_METADATA_INBOX (auto-consumer)                       │
│       Reads MSG_INBOX at offset from consumed MsgMetadata events                        │
│       sequencer.try_claim() + ring_buffer[seq] + sequencer.publish(seq) for producers   │
│  State: partial_frame_start_seq_, first_packet_metadata_, pending_frame_                │
│         frame_accumulated_metadata_[256] - per-frame SSL_read metadata (N5)             │
│  on_event() handler (called by event_processor.run on MSG_METADATA_INBOX):              │
│    1. Consume MsgMetadata → accumulate in frame_accumulated_metadata_[] (N5)            │
│    2. Read decrypted data from MSG_INBOX at msg_inbox_offset (direct read, no consumer) │
│    3. Parse WS frames via ws_parser.hpp (partial frames track first_packet_metadata_)   │
│    4. Publish WSFrameInfo with full timestamp chain to WS_FRAME_INFO_RING               │
│    5. On PING: try_claim() + publish() plaintext PONG → PONGS                          │
│    6. On CLOSE: try_claim() + publish() to MSG_OUTBOX (MSG_TYPE_WS_CLOSE)              │
└─────────────────────────────────────────────────────────────────────────────────────────┘
                  │ WS_FRAME_INFO_RING (with full timestamp chain)
                  ▼
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          APPCLIENT PROCESS (Core 8)                                     │
│  API: event_processor.run() - blocking call, on_event() handler (CRTP pattern)         │
│  on_event():                                                                            │
│    1. Receive WSFrameInfo → on_message(payload, len, opcode) via CRTP dispatch         │
│    2. Mark MSG_INBOX consumed (advance app_consumed_pos) at end_of_batch               │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Dataflow Summary

**RX Path** (NIC → AppClient):
```
NIC rx_ring
    │ (raw Ethernet frames)
    ▼
XDP Poll (Core 2)
    │ UMEMFrameDescriptor {umem_addr, nic_timestamp_ns, nic_frame_poll_cycle, frame_len}
    ▼ RAW_INBOX
Transport (Core 4)
    │ parse ETH/IP/TCP → SSL_read() → decrypted WS data
    │ MsgMetadata {first/latest timestamps, msg_inbox_offset, decrypted_len}
    ▼ MSG_METADATA_INBOX + MSG_INBOX (byte stream)
WebSocket (Core 6)
    │ parse WS frames via ws_parser.hpp
    │ WSFrameInfo {msg_inbox_offset, payload_len, full timestamp chain}
    ▼ WS_FRAME_INFO_RING
AppClient (Core 8)
    │ on_message(payload, len, opcode) via CRTP
    ▼ User application code
```

**TX Path** (AppClient → NIC):
```
AppClient (Core 8)
    │ MsgOutboxEvent {header_room, data, data_len, opcode, msg_type}
    ▼ MSG_OUTBOX
Transport (Core 4)
    │ build_ws_header() → SSL_write() → build TCP packet
    │ UMEMFrameDescriptor {umem_addr, frame_len, frame_type=MSG}
    ▼ RAW_OUTBOX
XDP Poll (Core 2)
    │ batch submit to tx_ring
    ▼
NIC tx_ring
```

**PONG Path** (WebSocket → NIC):
```
WebSocket (Core 6)
    │ Receives PING frame from server during WS parsing
    │ Extracts payload (up to 125 bytes per RFC 6455)
    │ Publishes plaintext PONG: PongFrameAligned {payload, payload_len}
    ▼ PONGS ring (plaintext, 64 entries)
Transport (Core 4)
    │ process_manually() on PONGS ring during idle time (!data_moved)
    │ SSL_write(pong_payload) → encrypts to bio_out_
    │ BIO_ctrl_pending() → read encrypted TLS record
    │ Allocates frame from PONG_FRAMES pool (position-based)
    │ Builds TCP packet with encrypted TLS payload
    │ UMEMFrameDescriptor {umem_addr, frame_len, frame_type=PONG}
    ▼ PONG_OUTBOX ring (encrypted, 64 entries)
XDP Poll (Core 2)
    │ process_manually() on PONG_OUTBOX during batch collect
    │ Submits to XDP tx_ring
    ▼
NIC tx_ring → Network

NOTE: PONG processing is intentionally done during idle time in Transport.
Under sustained high load (!data_moved is rarely true), PONGs may be delayed.
This is acceptable for HFT because:
  1. HFT workloads are typically bursty, not sustained high load
  2. If we're never idle, we're overloaded and should shed load anyway
  3. Ping timeouts (typically 30-60s) are long enough to tolerate occasional delays
```

**ACK Path** (Transport → NIC):
```
Transport (Core 4)
    │ Adaptive ACK (pkts >= 8 OR timeout >= 100µs)
    │ UMEMFrameDescriptor {umem_addr, frame_len, frame_type=ACK}
    ▼ ACK_OUTBOX
XDP Poll (Core 2)
    ▼
NIC tx_ring
```

---

## 2. File Structure

```
src/pipeline/
├── pipeline_config.hpp      # Constants, UMEM layout, static_asserts, MTU validation
├── pipeline_data.hpp        # UMEMFrameDescriptor, WSFrameInfo, PongFrame, MsgOutboxEvent
├── msg_inbox.hpp            # MSG_INBOX: Byte-stream ring with wrap-flag handling
├── ws_parser.hpp            # Stateful WebSocket parser with partial frame tracking
├── 01_xdp_poll_process.hpp  # XDP Poll process main loop
├── 02_transport_process.hpp # Transport process (SSL, TCP, retransmit)
├── 03_websocket_process.hpp # WebSocket process (frame parsing)
├── 04_app_client.hpp        # AppClient base class
└── pipeline_manager.hpp     # Orchestration, shared memory setup, fork

src/xdp/bpf/
└── exchange_filter.bpf.c    # BPF program for XDP filtering (DO NOT MODIFY - reuse as-is)

test/integration/
└── binance_pipeline.cpp     # Integration test for full pipeline

# NOTE: No ring_buffers.hpp needed - use disruptor library directly from 01_shared_headers/disruptor/
# All fixed-size event rings use disruptor::ring_buffer + disruptor::sequencer with IPC constructors
```

---

## 3. Data Structures

### 3.1 UMEMFrameDescriptor (32 bytes, 32-byte aligned)

**Design Note**: XDP Poll Process is a thin, fast data mover between NIC and shared memory.
It does NOT parse ETH/IP/TCP - all protocol stack work is done by Transport Process.
This separation enables future replacement with DPDK poll process.

**Timestamp Recording**: XDP Poll captures NIC HW timestamp and poll cycle for full RX latency tracking.

```cpp
// Frame type enum defined in Section 2 (pipeline_config.hpp constants)
// Values: FRAME_TYPE_RX=0, FRAME_TYPE_ACK=1, FRAME_TYPE_PONG=2, FRAME_TYPE_MSG=3
// Used for pool derivation from comp_ring address and frame routing

// Descriptor with timestamps - XDP Poll captures NIC timestamp and poll cycle
struct alignas(32) UMEMFrameDescriptor {
    uint64_t umem_addr;           // [0:7]   UMEM frame base address
    uint64_t nic_timestamp_ns;    // [8:15]  NIC HW timestamp (from BPF metadata)
    uint64_t nic_frame_poll_cycle;// [16:23] XDP Poll rdtscp when frame received
    uint16_t frame_len;           // [24:25] Total frame length (ETH+IP+TCP+payload)
    uint8_t  frame_type;          // [26]    FrameType enum for pool identification
    uint8_t  consumed;            // [27]    Set by Transport after SSL_read consumes frame
    uint8_t  reserved[4];         // [28:31] Padding for alignment
};
static_assert(sizeof(UMEMFrameDescriptor) == 32);

// RX Frame Consumption Flow:
// 1. XDP Poll: rx_ring → RAW_INBOX, sets consumed=0
// 2. Transport: reads frame, SSL_read() decrypts, sets consumed=1
// 3. XDP Poll: checks RAW_INBOX[refill_pos].consumed==1, releases to fill_ring
// 4. XDP Poll aborts if no RX frame available (consumer too slow = misconfiguration)
```

### 3.2 WSFrameInfo (128 bytes, 2 cache-lines)

**Timestamp Recording**: Carries full timestamp chain from NIC to WebSocket parse for latency analysis.

```cpp
struct alignas(64) WSFrameInfo {
    // Message location (16 bytes)
    uint32_t msg_inbox_offset;           // [0:3]   Payload offset in MSG_INBOX
    uint32_t payload_len;                // [4:7]   Payload length
    uint32_t frame_total_len;            // [8:11]  Total WS frame size (header + payload)
    uint8_t  opcode;                     // [12]    WS opcode
    uint8_t  is_final : 1;               // [13.0]  FIN bit
    uint8_t  is_fragmented : 1;          // [13.1]  True if from fragmented message (payloads non-contiguous)
    uint8_t  reserved : 6;               // [13.2-7]
    uint8_t  padding[2];                 // [14:15]

    // First packet timestamps (24 bytes)
    uint64_t first_byte_ts;              // [16:23] NIC timestamp when first byte arrived
    uint64_t first_nic_frame_poll_cycle; // [24:31] First packet XDP Poll rdtscp

    // Latest packet timestamps (32 bytes)
    uint64_t last_byte_ts;               // [32:39] NIC timestamp when frame completed
    uint64_t latest_nic_frame_poll_cycle;// [40:47] Latest packet XDP Poll rdtscp
    uint64_t latest_raw_frame_poll_cycle;// [48:55] Latest packet Transport rdtscp

    // SSL/WS timing (16 bytes)
    uint64_t ssl_read_cycle;             // [56:63] Transport SSL_read rdtscp

    // --- Cache line 2 ---
    uint64_t ws_parse_cycle;             // [64:71] WebSocket parse rdtscp
    uint8_t  padding2[56];               // [72:127] Padding to 128 bytes
};
static_assert(sizeof(WSFrameInfo) == 128);  // 2 cache-lines
```

### 3.3 PongFrame (128 bytes, cache-aligned)

```cpp
struct PongFrame {
    uint8_t payload[125];         // [0:124] Max PONG payload per RFC 6455
    uint8_t payload_len;          // [125]   Actual payload length (0-125)
};
static_assert(sizeof(PongFrame) == 126);

struct alignas(128) PongFrameAligned {
    PongFrame pong;               // [0:125]
    uint8_t padding[2];           // [126:127] Padding to 128 bytes
};
static_assert(sizeof(PongFrameAligned) == 128);
```

### 3.4 MsgOutboxEvent (2048 bytes, 2KB aligned)

**Design Note**: Header room is placed BEFORE data to enable single contiguous SSL_write.
The WS header (6-14 bytes) is written right-aligned into header_room, then header+data
forms a contiguous buffer for a single TLS record.

```cpp
// Outbound WS message event - max 2KB per message
// Layout enables single SSL_write: header is right-aligned in header_room,
// then [header+data] is contiguous for single TLS record
struct alignas(2048) MsgOutboxEvent {
    uint8_t  header_room[14];     // [0:13]   Space for WS header (6-14 bytes, right-aligned)
    uint8_t  data[2030];          // [14:2043] Message payload
    uint16_t data_len;            // [2044:2045] Actual message length (0-2030)
    uint8_t  opcode;              // [2046]   WS opcode (0x01=text, 0x02=binary)
    uint8_t  msg_type;            // [2047]   MSG_TYPE_DATA=0, MSG_TYPE_WS_CLOSE=1
};
static_assert(sizeof(MsgOutboxEvent) == 2048);

// Special message types
constexpr uint8_t MSG_TYPE_DATA = 0;
constexpr uint8_t MSG_TYPE_WS_CLOSE = 1;

// Usage in Transport (single TLS record):
// size_t header_len = build_websocket_header_zerocopy(
//     event.header_room + 14 - actual_header_len,  // Right-align header
//     event.data_len, event.opcode);
// uint8_t* contiguous_start = event.header_room + 14 - header_len;
// SSL_write(ssl_, contiguous_start, header_len + event.data_len);
```

### 3.5 MsgInbox (shared memory byte stream buffer)

**Purpose**: Circular byte buffer for decrypted TLS data. Transport writes, WebSocket reads, AppClient tracks consumption.

**Design Decision - No Backpressure on MSG_INBOX**:
- `dirty_flag` signals when Transport overwrites unread data, but does NOT prevent writing
- Transport continues writing even if AppClient falls behind (no abort)
- This allows AppClient process to be **optional** - user decides whether to use it
- If user needs AppClient, they must ensure it keeps up with Transport
- `dirty_flag` is for metrics/debugging only, not flow control

```cpp
// Complete MsgInbox structure (in shared memory)
struct MsgInbox {
    // Data buffer (4MB default)
    alignas(64) uint8_t data[MSG_INBOX_SIZE];

    // Control section (cache-line aligned atomics)
    alignas(64) std::atomic<uint32_t> write_pos;         // Transport writes here
    alignas(64) std::atomic<uint32_t> app_consumed_pos;  // AppClient consumption marker
    alignas(64) std::atomic<uint8_t> wrap_flag;          // Set when Transport wraps to head
    alignas(64) std::atomic<uint8_t> dirty_flag;         // Set if write_pos passes app_consumed_pos
                                                          // NOTE: No backpressure - Transport continues writing
                                                          // AppClient is OPTIONAL; dirty_flag is for metrics only
                                                          // User decides whether to use AppClient process

    // === Read helpers (WebSocket, AppClient) ===
    const uint8_t* data_at(uint32_t offset) const {
        return &data[offset % MSG_INBOX_SIZE];
    }

    uint32_t get_app_consumed() const {
        return app_consumed_pos.load(std::memory_order_acquire);
    }

    void set_app_consumed(uint32_t pos) {
        app_consumed_pos.store(pos, std::memory_order_release);
    }

    // === Write helpers (Transport only) ===
    uint32_t write_offset() const {
        return write_pos.load(std::memory_order_relaxed);
    }

    uint8_t* write_ptr() {
        return &data[write_offset() % MSG_INBOX_SIZE];
    }

    void advance_write(uint32_t len) {
        uint32_t new_pos = (write_offset() + len) % MSG_INBOX_SIZE;
        write_pos.store(new_pos, std::memory_order_release);
    }

    // Returns contiguous space before wrap point
    size_t linear_space_to_wrap() const {
        uint32_t pos = write_offset();
        return MSG_INBOX_SIZE - (pos % MSG_INBOX_SIZE);
    }

    void set_wrap_flag() {
        wrap_flag.store(1, std::memory_order_release);
    }

    void reset_to_head() {
        write_pos.store(0, std::memory_order_release);
    }
};

// NOTE ON wrap_flag: This flag exists for DEBUGGING/METRICS only, not for correctness.
//
// WebSocket process does NOT read wrap_flag because it receives exact offsets via
// MsgMetadata.msg_inbox_offset from MSG_METADATA_INBOX ring buffer. The wrap is
// transparent to WebSocket - it simply reads at the offset provided.
//
// The wrap_flag is useful for:
//   1. Debugging: Detect when wrap occurs
//   2. Metrics: Count wrap events to size buffer appropriately
//   3. Diagnostics: If wrap_flag is set but no data at offset 0, indicates producer stall
//
// If wrap_flag is removed, the pipeline still works correctly.
```

### 3.5.1 TxFrameState (merged into ConnStateShm)

**Note**: The `TxFrameState` struct has been **merged into `ConnStateShm.tx_frame`** in the implementation (`src/pipeline/pipeline_data.hpp`). This document shows the conceptual structure for reference.

**Purpose**: Shared state between Transport (allocator) and XDP Poll (releaser) for position-based TX frame allocation with ACK-based release.

**Design Note**: Use simple position tracking with `pong_acked_pos` and `msg_acked_pos`. Transport advances the acked position when TCP ACK is received; XDP Poll releases frames up to the acked position.

**Access Pattern**:
```cpp
// Access via ConnStateShm
conn_state_->tx_frame.ack_alloc_pos.load(...)
conn_state_->tx_frame.msg_release_pos.fetch_add(1, ...)
```

**Conceptual Structure**:
```cpp
// Part of ConnStateShm - see pipeline_data.hpp for full definition
alignas(CACHE_LINE_SIZE) struct {
    // ACK pool (position-based, immediate release after comp_ring - no retransmit needed)
    std::atomic<uint64_t> ack_alloc_pos;       // Transport increments
    std::atomic<uint64_t> ack_release_pos;     // XDP Poll increments

    // PONG pool (position-based with ACK-based release)
    std::atomic<uint64_t> pong_alloc_pos;      // Transport increments
    std::atomic<uint64_t> pong_release_pos;    // XDP Poll increments (after ACK)
    std::atomic<uint64_t> pong_acked_pos;      // Transport sets when TCP ACK received

    // MSG pool (position-based with ACK-based release)
    std::atomic<uint64_t> msg_alloc_pos;       // Transport increments
    std::atomic<uint64_t> msg_release_pos;     // XDP Poll increments (after ACK)
    std::atomic<uint64_t> msg_acked_pos;       // Transport sets when TCP ACK received
} tx_frame;

// NOTE: Implementation uses uint64_t for position counters.
// This eliminates wrap-around concerns entirely (~584 years at 1M allocs/sec).
// The slight memory overhead (8 bytes vs 4 bytes per counter) is negligible
// compared to the safety benefit of never dealing with wrap-around logic.
```

**Initialization Values** (set during handshake, before fork):
All position counters start at 0.

**Key Invariants** (must hold at all times after initialization):
For each pool (ACK, PONG, MSG):

  INVARIANT 1: `release_pos <= acked_pos <= alloc_pos`
  - XDP Poll cannot release beyond what Transport has ACKed
  - Transport cannot ACK beyond what has been allocated

  INVARIANT 2: `alloc_pos - release_pos <= POOL_SIZE`
  - Number of in-flight frames never exceeds pool capacity
  - Transport checks this BEFORE allocating; aborts if violated

  INVARIANT 3: For PONG/MSG pools: `acked_pos >= release_pos`
  - Cannot release more than ACKed (release_pos chases acked_pos)

// ============================================================================
// Position-Based Flow
// ============================================================================
// Allocation flow (Transport):
//   1. Check: alloc_pos - release_pos < POOL_SIZE
//   2. frame_idx = BASE + (alloc_pos % POOL_SIZE)
//   3. alloc_pos.fetch_add(1)
//
// ACK flow (Transport) - cumulative ACK advances acked_pos:
//   msg_acked_pos.store(new_acked_pos, memory_order_release)
//
// Release flow (XDP Poll):
//   1. Load: acked_pos = msg_acked_pos.load(memory_order_acquire)
//   2. While: release_pos < acked_pos
//      - release_pos++ (frame now available for reuse)

// Debug assertions (add to main loops for validation):
//   assert(release_pos <= acked_pos);
//   assert(acked_pos <= alloc_pos);
//   assert(alloc_pos - release_pos <= POOL_SIZE);
```

### 3.6 MsgMetadata (64 bytes, cache-line aligned)

**Purpose**: Metadata for each SSL_read message, written to MSG_METADATA_INBOX before writing data to MSG_INBOX. Carries full timestamp chain from XDP Poll through Transport.

```cpp
// Metadata for each SSL_read message - written to MSG_METADATA_INBOX
struct alignas(64) MsgMetadata {
    // First packet timestamps (oldest in SSL_read batch)
    uint64_t first_nic_timestamp_ns;       // [0:7]   NIC HW timestamp of first packet
    uint64_t first_nic_frame_poll_cycle;   // [8:15]  XDP Poll rdtscp of first packet

    // Latest packet timestamps (newest in SSL_read batch)
    uint64_t latest_nic_timestamp_ns;      // [16:23] NIC HW timestamp of latest packet
    uint64_t latest_nic_frame_poll_cycle;  // [24:31] XDP Poll rdtscp of latest packet
    uint64_t latest_raw_frame_poll_cycle;  // [32:39] Transport rdtscp of latest packet

    // SSL timing
    uint64_t ssl_read_cycle;               // [40:47] Transport rdtscp after SSL_read()

    // Message location in MSG_INBOX
    uint32_t msg_inbox_offset;             // [48:51] Start offset in MSG_INBOX
    uint32_t decrypted_len;                // [52:55] Decrypted message length

    uint8_t _pad[8];                       // [56:63] Padding to 64 bytes
};
static_assert(sizeof(MsgMetadata) == 64);  // Cache-line aligned
```

---

## 4. Ring Buffers

**IPC Mode API Summary** (NO push() - use sequencer with IPC constructor):
- **IPC Setup Requirements**:
  1. `atomic_sequence<true>` (external pointer mode - points to shared memory)
  2. `sequencer(buffer_size, cursor_ptr, published_ptr, region)` IPC constructor
  3. `external_storage_policy` for ring buffer (data in shared memory)
- **Producers**: `int64_t seq = sequencer.try_claim();` → if (seq >= 0) `ring_buffer[seq] = event;` → `sequencer.publish(seq);`
- **Manual Consumers** (XDP Poll, Transport, WebSocket on MSG_INBOX): `process_manually<Lambda>()` → `commit_manually()`
- **Auto Consumers** (WebSocket on MSG_METADATA_INBOX, AppClient): `disruptor::event_processor.run()` with `on_event()` handler

| Ring Name | Producer → Consumer | Element Type | Size | Producer API | Consumer API |
|-----------|---------------------|--------------|------|--------------|--------------|
| RAW_INBOX | XDP Poll → Transport | UMEMFrameDescriptor (32B) | 32768 | try_claim() + publish() | process_manually |
| RAW_OUTBOX | Transport → XDP Poll | UMEMFrameDescriptor (32B) | 32768 | try_claim() + publish() | process_manually |
| ACK_OUTBOX | Transport → XDP Poll | UMEMFrameDescriptor (32B) | 8192 | try_claim() + publish() | process_manually |
| PONG_OUTBOX | Transport → XDP Poll | UMEMFrameDescriptor (32B) | 1024 | try_claim_batch() + publish_batch() | process_manually |
| **MSG_METADATA_INBOX** | **Transport → WebSocket** | **MsgMetadata (64B)** | **65536** | **try_claim() + publish()** | **event_processor.run** |
| WS_FRAME_INFO_RING | WebSocket → AppClient | WSFrameInfo (128B) | 65536 | try_claim() + publish() | event_processor.run |
| PONGS | WebSocket → Transport | PongFrameAligned (128B) | 1024 | try_claim() + publish() | process_manually |
| MSG_INBOX | Transport → WebSocket | Byte stream | 64MB | Custom write_ptr | process_manually |
| MSG_OUTBOX | AppClient → Transport | MsgOutboxEvent (2KB) | 8192 | try_claim() + publish() | process_manually |

---

## 4.1 Memory Ordering Model

This section documents the memory ordering semantics used throughout the pipeline.

### Producer-Consumer Pattern (Ring Buffers)

All ring buffers use acquire-release semantics:
- **Producer**: Writes data first, then `publish(seq)` uses `release` ordering
- **Consumer**: `process_manually()` / `event_processor.run()` uses `acquire` on sequence read

This ensures the consumer sees all data written by the producer before the sequence number was published.

### Position Counter Pattern (ConnStateShm.tx_frame)

The position-based frame allocation uses:
- **Writer** (e.g., Transport increments `alloc_pos`): `fetch_add(1, release)`
- **Reader** (e.g., XDP Poll reads `acked_pos`): `load(acquire)`

```cpp
// Transport (writer): allocates frame, then publishes
frame = allocate_at(alloc_pos);
build_packet(frame);
conn_state_->tx_frame.msg_alloc_pos.fetch_add(1, memory_order_release);  // Release: data visible

// XDP Poll (reader): reads acked position
uint32_t acked = conn_state_->tx_frame.msg_acked_pos.load(memory_order_acquire);  // Acquire
// Now safe to assume frames up to acked-1 are ACKed
```

### Flag Pattern (Running Flag, Dirty Flag)

Single-writer flags use:
- **Writer**: `store(value, release)`
- **Reader**: `load(acquire)`

```cpp
// Writer (parent process)
conn_state_->running.store(false, memory_order_release);

// Reader (child process)
if (!conn_state_->running.load(memory_order_acquire)) {
    // Safe to see all writes before running was set false
    shutdown();
}
```

### Relaxed Ordering (Local-Only Reads)

Use `relaxed` only for reads where the value is advisory and doesn't guard other data:
- `write_pos.load(relaxed)` - when writer reads its own position (single-writer)
- Loop iteration counters

### Summary Table

| Variable | Writer | Reader | Notes |
|----------|--------|--------|-------|
| Ring buffer sequence | `release` | `acquire` | Standard disruptor pattern |
| `alloc_pos` | `release` | `acquire` | Guards frame data |
| `acked_pos` | `release` | `acquire` | Guards frame reuse |
| `release_pos` | `release` | N/A | XDP Poll only writer/reader |
| `running` flag | `release` | `acquire` | Shutdown coordination |
| `dirty_flag` | `release` | `acquire` | AppClient fallback signal |
| `write_pos` (self-read) | N/A | `relaxed` | Single-writer reads own value |

---

## 5. UMEM Partitioning

```
UMEM_BUFFER (TOTAL_UMEM_FRAMES × FRAME_SIZE)
├── RX Frames      [0, N/2)                   1/2 (50%)  - incoming packets
├── ACK TX Frames  [N/2, N/2 + N/8)           1/8 (12.5%) - TCP ACKs
├── PONG TX Frames [N/2 + N/8, N/2 + N/4)     1/8 (12.5%) - encrypted WS PONGs
└── MSG TX Frames  [N/2 + N/4, N)             1/4 (25%)  - WS messages
```

**Trickle Frame**: Pre-built 43-byte UDP packet stored in process memory (not UMEM). Used by XDP Poll to trigger igc driver NAPI polling for TX completion stall workaround. Sent via separate AF_PACKET socket.

**Trickle TX Path**: Trickle is sent via separate AF_PACKET raw socket (not XDP tx_ring):
- Trickle packet built in process memory during init (43-byte self-addressed UDP)
- Sent via `::send(trickle_fd_, ...)` on AF_PACKET socket bound to interface
- Simpler implementation, avoids UMEM frame allocation complexity
- Trickle packets bypass XDP entirely, triggering kernel NAPI for TX completion

Pool derivation from comp_ring (TX frames only):
```
if (addr >= RX_POOL_END && addr < ACK_POOL_END) → ACK pool (immediate release)
else if (addr < PONG_POOL_END) → PONG pool (release when acked)
else if (addr < MSG_POOL_END) → MSG pool (release when acked)
else → should never happen (abort)
```

---

## 5.1 TX Frame Lifecycle States

**Purpose**: Define explicit states for TX frames to prevent race conditions between comp_ring completion and TCP ACK-based release.

```cpp
// TX Frame Lifecycle States
enum class TxFrameLifecycle : uint8_t {
    FREE = 0,           // Available for allocation
    BUILDING = 1,       // Being filled by Transport
    IN_OUTBOX = 2,      // Published to outbox ring, waiting for XDP Poll
    SENT_TO_NIC = 3,    // Submitted to NIC tx_ring
    COMPLETED = 4,      // comp_ring returned (NIC sent to wire)
    ACKED = 5,          // TCP ACK received - safe to release
};
```

**State Transitions**:
```
┌─────────────────────────────────────────────────────────────────────┐
│                        TX Frame Lifecycle                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   FREE ──────► BUILDING ──────► IN_OUTBOX ──────► SENT_TO_NIC      │
│     ▲         (Transport)      (Transport)       (XDP Poll)        │
│     │                                                 │             │
│     │                                                 ▼             │
│     │                                            COMPLETED          │
│     │                                           (comp_ring)         │
│     │                                                 │             │
│     │                                                 ▼             │
│     └───────────────── ACKED ◄────────────────────────┘             │
│                     (Transport                                      │
│                      marks ACK)                                     │
│                                                                     │
│   Retransmit path:                                                  │
│   SENT_TO_NIC ──(RTO expires)──► re-submit to tx_ring               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.1.1 TX Frame Layout for Retransmit

**Key Design**: TCP headers are **outside** the TLS record, allowing header updates without re-encryption.

```
TX Frame Layout (PONG/MSG frames):
┌────────────────────────────────────────────────────────────────────┐
│  Ethernet Header (14 bytes)                                         │
│  - dst_mac, src_mac, ethertype                                      │
├────────────────────────────────────────────────────────────────────┤
│  IP Header (20 bytes)                                               │
│  - version, ihl, tos, total_len, id, flags, ttl, protocol          │
│  - src_ip, dst_ip, checksum (MUTABLE on retransmit: id, checksum)  │
├────────────────────────────────────────────────────────────────────┤
│  TCP Header (20-60 bytes)                                           │
│  - src_port, dst_port                                               │
│  - seq_num (MUTABLE on retransmit - same value, revalidate)        │
│  - ack_num (MUTABLE - update to latest rcv_nxt)                    │
│  - flags, window, checksum, urgent                                  │
│  - options (if any)                                                 │
├────────────────────────────────────────────────────────────────────┤
│  TLS Record (IMMUTABLE - encrypted payload)                         │
│  - content_type, version, length                                    │
│  - encrypted data (WS frame inside)                                 │
│  - MAC tag                                                          │
└────────────────────────────────────────────────────────────────────┘

Retransmit procedure:
1. Frame already built with TLS record (from original SSL_write)
2. On RTO timeout, update TCP header fields:
   - ack_num = current rcv_nxt (peer may have sent more data)
   - Recompute TCP checksum
   - Recompute IP checksum (if IP id changed)
3. Re-submit same frame to tx_ring (no re-encryption needed)
```

**Critical Safety Rule**: XDP Poll MUST NOT release a frame from comp_ring if it has not been ACKed by Transport. The frame index from comp_ring must be <= acked position, otherwise abort.

**Ownership**:
- **Transport**: FREE → BUILDING → IN_OUTBOX, COMPLETED → ACKED (marks acked[] flag)
- **XDP Poll**: IN_OUTBOX → SENT_TO_NIC → COMPLETED (via comp_ring), ACKED → FREE (releases)

---

## 6. Full RX Path Timestamp Recording

**Goal**: Capture full latency breakdown from NIC RX to application, with per-stage CPU cycle timestamps.

### Timestamp Flow

```
NIC (hw_timestamp)
  ↓
XDP Poll (nic_frame_poll_cycle)
  ↓ RAW_INBOX
Transport (raw_frame_poll_cycle, ssl_read_cycle)
  ↓ MSG_METADATA_INBOX + MSG_INBOX
WebSocket (ws_parse_cycle)
  ↓ WS_FRAME_INFO_RING
AppClient
```

### Timestamp Semantics

Timestamps are reset after each SSL_read that returns data. This means:
- `first_nic_timestamp_ns` / `first_nic_frame_poll_cycle`: Oldest packet in the current SSL_read batch
- `latest_*`: Newest packet in the current SSL_read batch
- If a TLS record spans multiple SSL_read calls, each call gets timestamps from its own batch of packets
- This is a pragmatic trade-off: precise per-TLS-record tracking would require complex state management

**Fragmented WS Frames**: For WebSocket frames spanning multiple TLS records:
- `first_*` timestamps: From the MsgMetadata of the **first** TLS record containing frame start
- `latest_*` timestamps: From the MsgMetadata of the **last** TLS record containing frame end
- WebSocket process tracks `first_packet_metadata_` when frame header is parsed, updates `latest_*` from each subsequent MsgMetadata until frame is complete

### BPF Metadata Layout for NIC Timestamps

The XDP BPF program must store the NIC hardware timestamp in metadata space before the packet data:

```
┌─────────────────────────────────────────────────────────────┐
│                    UMEM Frame Layout                         │
├─────────────────────────────────────────────────────────────┤
│ [addr - 8]    uint64_t nic_timestamp_ns  (NIC HW timestamp) │
│ [addr]        Ethernet frame starts here                    │
│               (rx_desc->addr points here)                   │
└─────────────────────────────────────────────────────────────┘
```

**BPF Program Requirements**:
1. Call `bpf_xdp_adjust_meta(ctx, -8)` to reserve 8 bytes before packet
2. Use `bpf_ktime_get_tai_ns()` or NIC-specific HW timestamp helper
3. Store timestamp at `data_meta` pointer (8 bytes before `data`)

---

## 7. Handshake Phase (Fork-First Architecture)

**Detailed Documentation**: [pipeline_handshake.md](pipeline_handshake.md)

The pipeline uses a **fork-first architecture** where all processes are forked BEFORE any network activity. This eliminates XSK socket inheritance issues.

```
1. Create shared memory regions (UMEM, all ring buffers, conn_state)
   - shm_open() + mmap() for each shared memory file
   - Initialize ring buffer producer/consumer indices to 0

2. Create IPC rings for inter-process communication
   - Using hftshm dual-segment layout (.hdr + .dat files)
   - All rings created before fork()

3. Store target config in shared memory
   - target_host, target_port, target_path
   - subscription_json, bpf_path, interface_name
   - Transport child reads these to perform handshake

4. Calibrate TSC frequency (once in parent)
   - Stored in conn_state_shm->tsc_freq_hz
   - All child processes use this value (avoids recalibration)

5. Fork ALL processes BEFORE any network activity
   - XDP Poll:     fork() → sched_setaffinity(core 2)
   - Transport:    fork() → sched_setaffinity(core 4)
   - WebSocket:    fork() → sched_setaffinity(core 6)
   - Parent (AppClient): sched_setaffinity(core 8)

6. XDP Poll child: Create XSK socket fresh (no inheritance)
   - Create UMEM from shared memory area
   - Load and attach BPF program
   - Create XSK socket directly in child process
   - Register XSK in BPF xsks_map
   - Signal xdp_ready flag
   - Enter main loop

7. Transport child: Perform handshake via IPC rings
   - Wait for xdp_ready from XDP Poll
   - TCP handshake (SYN → SYN-ACK → ACK) via IPC rings
   - TLS handshake via IPC rings (WolfSSL native I/O callbacks)
   - WebSocket upgrade via IPC rings
   - Send subscription message via IPC rings
   - Signal ws_ready flag
   - Enter main loop

8. Parent (AppClient): Wait for handshake, run main loop
   - Wait for ws_ready with timeout (60s)
   - Enter user application loop
```

**FORK-FIRST BENEFITS**:
- No XSK socket inheritance issues (rx=0 bug eliminated)
- Each process owns its resources completely
- Clean separation of concerns (XDP Poll owns socket, Transport owns SSL)
- BPF/XSK mapping works correctly (created in same process that uses it)

**PROCESS OWNERSHIP**:
- `XSK socket/UMEM`: Created and owned by XDP Poll child
- `SSL/TLS context`: Created and owned by Transport child
- `Shared memory`: Created by parent, accessible to all via mmap
- `IPC rings`: Created by parent, used for inter-process communication

---

## 8. Shared Memory Layout

**HFTSHM Configuration**: TOML config is generated at compile-time from these constants. Do NOT manually create or edit TOML files.

```
/dev/shm/pipeline/
├── umem.dat               # UMEM buffer (single file)
├── raw_inbox              # RAW_INBOX ring (.hdr/.dat dual-segment)
│   ├── .hdr               #   Header: producer/consumer sequences
│   └── .dat               #   Data: 32B descriptors with timestamps
│                          #   NOTE: XDP Poll reads Transport's consumer sequence from .hdr
│                          #         to know when RX frames can be recycled to fill_ring
├── raw_outbox             # RAW_OUTBOX ring (.hdr/.dat, 32B descriptors)
├── ack_outbox             # ACK_OUTBOX ring (.hdr/.dat, 32B descriptors)
├── pong_outbox            # PONG_OUTBOX ring (.hdr/.dat, 32B descriptors)
├── msg_inbox.dat          # MSG_INBOX byte stream (single file, not ring buffer)
├── msg_metadata           # MSG_METADATA_INBOX ring (.hdr/.dat, 64B metadata)
├── msg_outbox             # MSG_OUTBOX ring (.hdr/.dat, 2KB events)
├── pongs                  # PONGS ring (.hdr/.dat, 128B aligned)
├── ws_frame_info          # WS_FRAME_INFO ring (.hdr/.dat, 128B with timestamps)
├── conn_state.dat          # TCP state (single file)
└── tx_frame_state.dat     # TX frame state (single file)
```

**Note**: Ring buffers use HFTSHM dual-segment layout:
- `.hdr`: Control data (magic, version, producer cursor/published, consumer sequences)
- `.dat`: Ring buffer data (power of 2 size)

---

## 9. Makefile Changes

```makefile
# MTU must be provided (fail if not)
ifndef PATH_MTU
$(error PATH_MTU is required. Usage: make PATH_MTU=1500)
endif

# Calculate FRAME_SIZE: round up (PATH_MTU + 94) to next 1KB boundary
# 94 = ETH(14) + IP(20) + TCP(60 max options)
# Examples:
#   PATH_MTU=1500 → 1500+94=1594 → round up to 2048
#   PATH_MTU=9000 → 9000+94=9094 → round up to 10240
FRAME_SIZE := $(shell echo $$(( (($(PATH_MTU) + 94 + 1023) / 1024) * 1024 )))

CXXFLAGS += -DPATH_MTU=$(PATH_MTU)
CXXFLAGS += -DFRAME_SIZE=$(FRAME_SIZE)
```

---

## 10. Implementation Phases

### Phase 1: Core Infrastructure & Data Structures

**Goal**: Establish shared memory layout and all data types.

| File | Description | Dependencies |
|------|-------------|--------------|
| `pipeline_config.hpp` | Constants, UMEM layout, compile-time sizing, FRAME_SIZE validation | None |
| `pipeline_data.hpp` | UMEMFrameDescriptor, WSFrameInfo, PongFrame, MsgOutboxEvent, MsgMetadata | pipeline_config.hpp |
| `msg_inbox.hpp` | MSG_INBOX byte-stream ring with wrap-flag handling | pipeline_config.hpp |
| `ws_parser.hpp` | Stateful WS parser with partial frame tracking (PartialWebSocketFrame) | core/http.hpp |

**Deliverable**: All data structures compile and pass static_assert checks.

---

### Phase 2: Process Implementations

**Goal**: Implement each process as a standalone class with testable interfaces.

| File | Description | Dependencies |
|------|-------------|--------------|
| `01_xdp_poll_process.hpp` | XDP Poll: batch RX/TX, comp_ring pool mapping, fill_ring management | pipeline_data.hpp, xdp/ |
| `02_transport_process.hpp` | Transport: SSL BIO, TCP state, ACK coalescing, retransmit queue | pipeline_data.hpp, stack/, policy/ |
| `03_websocket_process.hpp` | WebSocket: event_processor consumer, frame dispatch, PING/PONG/CLOSE | pipeline_data.hpp, ws_parser.hpp |
| `04_app_client.hpp` | AppClient: CRTP handler base, MSG_INBOX consumption tracking | pipeline_data.hpp |

**Deliverable**: Each process class compiles independently with mock ring buffers.

---

### Phase 3: Pipeline Manager & Orchestration

**Goal**: Implement shared memory setup, handshake sequence, and process forking.

| File | Description | Dependencies |
|------|-------------|--------------|
| `pipeline_manager.hpp` | Shared memory creation, disruptor IPC setup, TCP/TLS/WS handshake, fork + CPU pinning | All above |

**Deliverable**: Pipeline can establish connection and fork 4 processes.

---

### Phase 4: Integration Testing

**Goal**: Verify end-to-end pipeline with real exchange connection.

| File | Description | Dependencies |
|------|-------------|--------------|
| `test/integration/binance_pipeline.cpp` | Full pipeline integration test connecting to Binance stream | All pipeline headers |

**Test Requirements**:
1. Connect to `stream.binance.com` via pipeline
2. Subscribe to a ticker stream (e.g., `btcusdt@trade`)
3. Receive at least 10 WebSocket messages
4. Verify timestamp chain integrity (all timestamps non-zero, monotonically increasing)
5. Measure and report end-to-end latency (NIC → AppClient)
6. Graceful shutdown on SIGINT
7. Verify no memory leaks (UMEM frames all returned)

**Build & Run**:
```bash
# Build
make binance_pipeline USE_WOLFSSL=1

# Run on CPU core 2 (requires sudo for XDP)
sudo taskset -c 2 ./build/binance_pipeline enp108s0
```

See [Section 15: Integration Testing](#15-integration-testing) for detailed pre-test setup and execution steps.

---

### Phase 5: Performance Validation

**Goal**: Benchmark latency and throughput under realistic conditions.

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| NIC → AppClient P50 | < 5 µs | Timestamp chain in WSFrameInfo |
| NIC → AppClient P99 | < 15 µs | Timestamp chain in WSFrameInfo |
| Message throughput | > 100K msg/s | Sustained for 60s |
| CPU usage per core | < 100% (no backlog) | /proc/stat monitoring |

**Benchmark Command**:
```bash
sudo ./build/binance_pipeline --interface enp108s0 --benchmark --duration 60
```

---

## 11. Code Reuse

### 11.1 TCP/IP Stack (`src/stack/`)

| Component | Source File | Key Functions/Types |
|-----------|-------------|---------------------|
| **Stack Entry** | `src/stack/userspace_stack.hpp` | `UserspaceStack::build_syn()`, `build_ack()`, `build_data()`, `build_fin()`, `build_fin_ack()`, `build_probe()`, `parse_tcp()`, `update_ack_and_checksum()` |
| **TCP Packet** | `src/stack/tcp/tcp_packet.hpp` | `TCPPacket::build()` - builds ETH+IP+TCP+payload frame<br>`TCPPacket::parse()` - returns `TCPParseResult` with zero-copy payload pointer |
| **TCP State** | `src/stack/tcp/conn_state.hpp` | `TCPState` enum, `TCPParams`, `TCPParseResult`, `TCPProcessResult`<br>`TCP_FLAG_*` constants, `seq_lt/gt/le/ge()` helpers |
| **Retransmit** | `src/stack/tcp/tcp_retransmit.hpp` | `ZeroCopyRetransmitQueue::add_ref()`, `remove_acked()`, `get_retransmit_refs()`<br>`RetransmitSegmentRef` (40 bytes - stores alloc_pos, frame_idx, seq range, not data) |
| **Receive Buffer** | `src/stack/tcp/tcp_retransmit.hpp` | `ZeroCopyReceiveBuffer::push_frame()`, `read()`, `get_last_read_stats()` |
| **IP Layer** | `src/stack/ip/ip_layer.hpp` | `IPLayer::build_packet()`, `parse_packet()`<br>`ip_to_string()`, `string_to_ip()` |
| **Checksum** | `src/stack/ip/checksum.hpp` | `ip_checksum()`, `tcp_checksum()`, `verify_ip_checksum()`, `verify_tcp_checksum()` |
| **Ethernet** | `src/stack/mac/ethernet.hpp` | `EthernetHeader`, `MACLayer::build_frame()`, `parse_frame()` |
| **ARP** | `src/stack/mac/arp.hpp` | `ARP::resolve_gateway()` - resolves gateway MAC from /proc/net/arp |

### 11.2 WebSocket (`src/core/http.hpp`)

| Function | Signature | Description |
|----------|-----------|-------------|
| `parse_websocket_frame` | `bool parse_websocket_frame(const uint8_t* data, size_t len, WebSocketFrame& out)` | Parse WS header, returns zero-copy payload pointer |
| `unmask_payload` | `void unmask_payload(uint8_t* payload, size_t len, const uint8_t mask_key[4])` | In-place XOR unmasking |
| `build_websocket_header_zerocopy` | `size_t build_websocket_header_zerocopy(uint8_t* header, size_t payload_len, uint8_t opcode)` | Header only, uses mask [0,0,0,0] |
| `build_pong_frame` | `size_t build_pong_frame(const uint8_t* payload, size_t len, uint8_t* out, const uint8_t mask[4])` | Build PONG response |
| `build_close_frame` | `size_t build_close_frame(uint16_t code, const uint8_t* reason, size_t len, uint8_t* out, const uint8_t mask[4])` | Build CLOSE frame |

### 11.3 XDP/UMEM (`src/xdp/`) - REUSE AS-IS

All XDP components are **production-tested** and should be reused directly without modification.

| Component | Source File | Key Functions/Types | Status |
|-----------|-------------|---------------------|--------|
| **XDP Frame** | `src/xdp/xdp_frame.hpp` | `XDPFrame`, `xdp_user_metadata` (8-byte NIC timestamp) | ✅ Reuse |
| **BPF Loader** | `src/xdp/bpf_loader.hpp` | `BPFLoader`, `BPFStats`, `BPFStat` enum | ✅ Reuse |
| **XDP Transport** | `src/xdp/xdp_transport.hpp` | `XDPTransport`, `XDPConfig` | ✅ Reuse |
| **BPF Program** | `src/xdp/bpf/exchange_filter.bpf.c` | `exchange_packet_filter` | ✅ Reuse |

> **Details**: See [XDP Poll Process (pipeline_0_nic.md)](pipeline_0_nic.md) for BPF metadata layout, UMEM frame handling, and trickle packet workaround. Source files contain complete API documentation.

**Key Points**:
- **Frame Pool Split**: RX pool (50%) for FILL/RX rings, TX pool (50%) for sequential allocation
- **XDP Metadata**: 8-byte `xdp_user_metadata.rx_timestamp_ns` at `[data - 8]` from BPF kfunc
- **igc Workaround**: RX trickle (500Hz UDP) triggers NAPI for TX completion in zero-copy mode
- **Requirements**: Kernel 6.3+ for timestamp kfunc, 6.5+ for igc HW timestamps

### 11.4 SSL/TLS (`src/policy/`)

| Component | Source File | Key Functions/Types |
|-----------|-------------|---------------------|
| **SSL Policies** | `src/policy/ssl.hpp` | `OpenSSLPolicy`, `LibreSSLPolicy`, `WolfSSLPolicy`, `NoSSLPolicy`<br>Zero-copy RX: `append_encrypted_view()` (ring buffer of UMEM pointers), `clear_encrypted_view()` (reconnect only)<br>Zero-copy TX: `set_encrypted_output()`, `encrypted_output_len()`, `clear_encrypted_output()`<br>I/O: `read()`, `write()`, `init_zero_copy_bio()` |

**Note**: Transport Process does NOT use `userspace_transport_bio.hpp`. Instead, it uses a zero-copy view/output buffer model:
- **RX**: UMEM frame pointers are appended via `append_encrypted_view()` → SSL reads from scattered views
- **TX**: Output buffer is set via `set_encrypted_output()` → SSL writes directly to UMEM frames

### 11.5 Timing (`src/core/timing.hpp`)

| Function | Description |
|----------|-------------|
| `rdtsc()` | Read TSC with lfence serialization (before measurement) |
| `rdtscp()` | Read TSC with serialization after (end of transaction) |

### 11.6 Disruptor IPC (`01_shared_headers/disruptor/`)

**NOTE**: All fixed-size event rings use the disruptor library directly - no wrapper needed.

| Component | Source File | Usage |
|-----------|-------------|-------|
| Ring Buffer | `src/core/ring_buffer.hpp` | `ring_buffer<T, SIZE, external_storage_policy>` for shared memory data |
| Sequencer | `src/core/sequencer.hpp` | `sequencer(size, cursor_ptr, published_ptr, region)` IPC constructor |
| Event Processor | `src/core/event_processor.hpp` | `event_processor.run()` with `on_event()` handler |
| Sequence Barrier | `src/core/sequence_barrier.hpp` | Consumer synchronization point |
| Shared Region | `src/ipc/shared_region.hpp` | `shared_region` for mmap-backed shared memory |
| Policy Bundles | `src/policy_bundles.hpp` | Pre-configured policy combinations |

**Include Path**:
```cpp
#include <disruptor/disruptor.hpp>  // Main header from 01_shared_headers/disruptor/src/

// IPC mode usage example:
using namespace disruptor;

// Ring buffer with external storage (shared memory)
ring_buffer<UMEMFrameDescriptor, 1024, storage_policies::external_storage> raw_inbox_ring(umem_ptr);

// Sequencer with IPC constructor (cursor/published in shared memory)
sequencer<sequence_policies::local_atomic_sequence,
          memory_ordering_policies::acquire_release,
          claim_policies::single_producer_claim_policy>
    raw_inbox_sequencer(1024, cursor_ptr, published_ptr, region);

// Producer pattern (ALWAYS use try_claim, abort on full):
int64_t seq = raw_inbox_sequencer.try_claim();
if (seq < 0) {
    // Buffer full = misconfiguration, abort process
    std::abort();
}
raw_inbox_ring[seq] = descriptor;
raw_inbox_sequencer.publish(seq);

// Auto-consumer pattern (WebSocket, AppClient):
event_processor<MsgMetadata, policy_bundles::single_producer_lowest_latency> processor(
    ring_buffer, barrier, handler);
processor.run();  // Blocking - calls handler.on_event() for each event

// Cross-process consumer progress reading (XDP Poll reads Transport's RAW_INBOX progress):
// Use shared_region API - do NOT hold raw pointer to consumer sequence
disruptor::ipc::shared_region raw_inbox_region("raw_inbox");
int64_t consumer_progress = raw_inbox_region.consumer_sequence(0)->load(std::memory_order_acquire);
int64_t producer_published = raw_inbox_region.producer_published()->load(std::memory_order_acquire);
int64_t lag = producer_published - consumer_progress;
```

### 11.6.1 shared_region Memory Layout

Each disruptor ring buffer in IPC mode uses a shared memory region with this layout:

```
shared_region memory layout (used by hftshm):
┌──────────────────────────────────────────────────────────────┐
│ [0x00-0x3F]  cursor (atomic<int64_t>)  [64 bytes, aligned]   │
│              Producer claimed position                        │
├──────────────────────────────────────────────────────────────┤
│ [0x40-0x7F]  published (atomic<int64_t>) [64 bytes, aligned] │
│              Published sequence (visible to consumers)        │
├──────────────────────────────────────────────────────────────┤
│ [0x80-0xBF]  consumer_sequences[] [64 bytes, aligned]        │
│              Gating sequences for flow control                │
├──────────────────────────────────────────────────────────────┤
│ [0xC0+]      ring buffer data                                │
│              Element storage (external_storage_policy)        │
│              Size = ring_size × sizeof(element)               │
└──────────────────────────────────────────────────────────────┘

Total size = control_overhead + (ring_size × element_size)
           = 192 bytes + (ring_size × sizeof(T))
```

**Size calculation**:
```cpp
template<typename T>
constexpr size_t calculate_size(size_t ring_size) {
    constexpr size_t control_overhead = 192;  // 3 cache lines
    return control_overhead + (ring_size * sizeof(T));
}
```

**HFTSHM Dual-Segment Layout** (from `hftshm_plan.md`):
```
Header (.hdr) - e.g., /dev/shm/hft/pipeline/raw_inbox.hdr
├── metadata (64 bytes): magic, version, buffer_size, index_mask, offsets
├── producer section (128 bytes): cursor, published, metrics
└── consumer sections (128 bytes each): sequence, metrics

Data (.dat) - e.g., /dev/shm/hft/pipeline/raw_inbox.dat
└── ring buffer data (buffer_size bytes, power of 2)
```

---

## 12. Edge Cases Addressed

| Issue | Solution |
|-------|----------|
| WS frame spans SSL_read | `WSParser::PendingFrame` tracks partial header/payload |
| MSG_INBOX wrap point | `wrap_flag` signals consumer; Transport resets write to head |
| SSL_write with memory BIO | Never returns `SSL_ERROR_WANT_WRITE` - memory BIOs auto-grow |
| TCP FIN/RST | Transport checks tcp_flags, sets running_=false |
| TCP retransmission | Zero-copy: highest priority, re-submit existing frames |
| comp_ring pool mapping | Derive from address range (RX/TX pools) |
| Window scale | Captured from SYN-ACK options during handshake |
| Client-to-server masking | Use [0,0,0,0] mask key (XOR=no-op) |
| TLS record sizing | Limit to TCP_MSS - TLS_OVERHEAD |
| Consumer falls behind | dirty_flag in MsgInbox |
| WS CLOSE handling | WebSocket writes MSG_TYPE_WS_CLOSE to MSG_OUTBOX |
| PONG via Transport | WebSocket builds plaintext → Transport encrypts |

---

## 13. Error Recovery Strategy

### 13.1 Process Death Detection
Each process writes heartbeat to shared memory:
```cpp
struct ProcessHeartbeat {
    std::atomic<uint64_t> last_tsc;
    std::atomic<uint32_t> pid;
    std::atomic<uint8_t>  state;  // INIT=0, RUNNING=1, SHUTDOWN=2, DEAD=3
};
```

**NOTE: Not yet implemented.** The ProcessHeartbeat struct is defined, but pipeline processes
do not currently write heartbeats. See [Phase 6: Health Monitoring](#phase-6-health-monitoring) for implementation TODO.

### 13.2 Graceful Shutdown
On SIGTERM/SIGINT: set running_=false, wait for processes to drain, cleanup shared memory.

### 13.3 Reconnection Strategy
On connection loss: signal processes to stop, wait for exit, cleanup, exponential backoff reconnect.

### 13.4 Partial Failure Recovery
| Failed Process | Severity | Recovery Action |
|----------------|----------|-----------------|
| XDP Poll | **Fatal** | Full pipeline restart |
| Transport | **Fatal** | Full pipeline restart |
| WebSocket | Medium | Restart if needed |
| AppClient | Low | Restart AppClient only |

---

## 14. Future Work (TODO)

### Phase 5: Shutdown Coordination
- [ ] Define shutdown states per process: RUNNING → DRAINING → STOPPED
- [ ] Implement coordinated shutdown sequence:
  1. Signal `running_ = false` to all processes
  2. XDP Poll: Stop accepting new RX, drain pending TX
  3. Transport: Drain SSL buffers, send TCP FIN
  4. WebSocket: Drain pending frames
  5. AppClient: Process remaining messages
- [ ] Add shutdown timeout (5s default) with forced termination
- [ ] Implement graceful reconnection (cleanup shared memory, restart handshake)
- [ ] **drain_pending_tx() on outbound close**: When AppClient sends WS_CLOSE via MSG_OUTBOX, Transport currently calls `send_ws_close_frame()` + `send_fin()` without draining MSG_OUTBOX first. Outbound messages could be lost. For HFT this is acceptable (reconnect handles it), but document this trade-off.
- [ ] **SIGTERM-based shutdown**: Parent process sends SIGTERM to all child processes. Each process installs signal handler that calls `event_processor.halt()` to break out of blocking `run()` loops (WebSocket, AppClient).

### Phase 6: Health Monitoring
- [ ] Add per-process heartbeat in shared memory:
  ```cpp
  struct ProcessHealth {
      std::atomic<uint64_t> heartbeat_tsc;
      std::atomic<uint32_t> frames_processed;
      std::atomic<uint32_t> ring_high_watermark;
  };
  ```
- [ ] Track ring buffer fill levels (p50, p99 over 1-second window)
- [ ] Track per-stage latency histograms (via timestamp chain)
- [ ] Add retransmit rate monitoring
- [ ] Implement health check thread in pipeline_manager
- [ ] Export metrics via shared memory for external monitoring

### Phase 7: Optional Enhancements
- [ ] **WebSocket read position tracking**: Add optional `ws_read_pos` in MsgInbox for backpressure from WebSocket to Transport (prevents data corruption vs just signaling)
- [ ] **UMEM frame state debugging**: Add debug mode that tracks frame lifecycle transitions to catch double-free, use-after-free, leak conditions during development
- [ ] **MSG_INBOX high-water mark monitoring**: Track how close Transport `write_pos` gets to `app_consumed_pos`, alert/metric before overwrite occurs
- [ ] **Per-pool fill_ring**: Consider separate fill mechanism if RX frames get stuck in Transport (slow SSL_read), to prevent fill_ring starvation
- [ ] **Backpressure metrics**: Track how often backpressure conditions occur (retransmit queue full, ring buffer high watermarks) for production monitoring
- [ ] **Pool utilization metrics**: Track TX frame pool usage for capacity planning:
  - `msg_alloc_pos - msg_release_pos` → MSG frames currently in flight
  - `pong_alloc_pos - pong_release_pos` → PONG frames currently in flight
  - High-water marks over time windows for sizing validation
- [ ] **SSL session resumption**: Store session tickets/IDs during TLS handshake for faster reconnection. On reconnect, attempt session resumption before full handshake.
- [ ] **TCP sequence number wraparound documentation**: Document that `seq_lt()`/`seq_le()` helpers handle 32-bit wraparound correctly (after ~4GB of data transfer).
- [ ] **Parent process health monitoring**: Parent currently just `waitpid()` on children. Add periodic health checks (heartbeat monitoring) in parent process.
- [ ] **Child process unexpected death handling**: Currently parent does nothing if a child dies unexpectedly. Add detection and coordinated shutdown of remaining children.
- [ ] **Latency breakdown calculation helper**: Add `calculate_latency(WSFrameInfo, app_recv_cycle, tsc_freq_hz)` helper that returns per-stage breakdown (NIC→XDP, XDP→Transport, SSL decrypt, WS parse, WS→App).
- [ ] **Ring buffer high-water mark metrics**: Add optional tracking of `max_fill_level` and `full_abort_count` per ring buffer for capacity planning.
- [ ] **Connection timeout monitoring**: Add optional dead connection detection (no RX packets for configurable timeout, e.g., 120s) to trigger reconnection.
- [ ] **Gateway/netmask configuration**: Transport currently assumes gateway is `.1` of local subnet and netmask is `/24`. Should read gateway IP and netmask from `ConnStateShm` or config, populated by parent process (e.g., from system routing table or user config).

### Design Decisions: Implemented (Gap Analysis)

The following features were identified in gap analysis and implemented:

| Feature | Component | Description |
|---------|-----------|-------------|
| **Trickle via XDP tx_ring (N1)** | XDP Poll | Trickle frame built in UMEM, sent via XDP tx_ring instead of separate raw socket. Unified TX path, lower latency. |
| **Duplicate ACK for fast retransmit (N4)** | Transport | Send immediate duplicate ACK on out-of-order segments. Enables sender's fast retransmit (3 dup ACKs). Recovery time critical for HFT even if OOO is rare. |
| **Per-frame metadata accumulation (N5)** | WebSocket | `frame_accumulated_metadata_[]` array preserves all SSL_read metadata until WS frame completes. Enables detailed per-frame latency profiling. |
| **WSFrameInfo timestamp field naming (N6)** | WebSocket | Renamed `first_nic_timestamp_ns` → `first_byte_ts`, `latest_nic_timestamp_ns` → `last_byte_ts` for semantic clarity. |
| **data_moved flag optimization (N7)** | XDP Poll | Track if RX/TX data moved each iteration. Idle-time work (frame reclaim) only runs when no data moved. |
| **Separate PONG retransmit queue (Session 1)** | Transport | `pong_retransmit_queue_` for proper TCP reliability of PONG frames, separate from MSG retransmit. |
| **SSL Policy template pattern (Session 1)** | Transport | SSL policies abstract TLS operations with zero-copy interface: `append_encrypted_view()` (1024-slot ring buffer), `read()`, `write()`, `set_encrypted_output()`, `encrypted_output_len()`. |
| **process_manually + commit_manually (Session 1)** | WebSocket | Native disruptor batching pattern. Deferred commit reduces atomic operations per event. |
| **Unified TX template (Session 2)** | Transport | `process_outbound<TxType>()` template handles MSG and PONG identically. Uses `if constexpr` for zero-overhead type selection. Single source of truth for: encrypt → build headers → add to retransmit queue. |

### Design Decisions: Not Implemented (with Rationale)

The following features were considered but NOT implemented, with documented rationale:

| Feature | Rationale |
|---------|-----------|
| **TCP_CORK / Nagle-style batching** | HFT requires immediate transmission. Batching small writes adds latency. Single TLS record per TCP segment is optimal for our use case. |
| **FIN/TCP close state machine** | For HFT simplicity, no FIN handling is implemented. On any disconnect, reconnect is the recovery strategy regardless of close type. RST provides immediate resource cleanup without TIME_WAIT delay. Exchange connections are long-lived (hours/days), and proper TCP close semantics add complexity without benefit. |
| **Peer receive window tracking** | Rare in HFT scenario. We receive far more than we send (market data >> orders). Exchange servers have massive receive buffers and never zero-window HFT clients. If exchange is overloaded, reconnect is the strategy anyway. |
| **Graceful PONG timeout handling** | PONGs use unified `process_outbound<TxType::PONG>()` template (same code path as MSG). Batch-processed during idle time. HFT workloads are bursty, so idle time is common. Sustained high load indicates overload - system should fail fast rather than degrade. |
| **TIME_WAIT state for TCP close** | Reconnection handles cleanup. Lingering TIME_WAIT packets are rare and harmless - kernel handles them. Added complexity not justified for HFT. |
| **Out-of-order comp_ring handling** | Position-based allocator assumes FIFO. All tested NICs (igc, Mellanox) return completions in order. Debug assertions catch violations. Fix at driver level if encountered. |
| **Retransmit queue separate from frame pool** | Retransmit entries are 64 bytes, frames are ~2KB. Could save memory by decoupling, but added complexity not justified for typical HFT memory budgets. |
| **BPF program hot-reload** | Exchange IPs/ports are configured at startup. Runtime changes require restart. For HFT, connection parameters are static per trading session. |
| **Multi-connection support** | Single connection per pipeline instance. Multiple connections require multiple pipeline instances. Keeps design simple and deterministic for HFT. |
| **TLS certificate validation** | Certificate validation disabled (`SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL)`). Exchange endpoints are known/trusted. Validation adds ~1ms latency to handshake. |
| **Zero-window persist timeout** | No timeout - if peer window stays zero, connection stalls. For HFT, zero-window indicates peer overload; reconnection is the recovery strategy. |
| **FIN-ACK retransmission** | After sending FIN, Transport exits immediately and prepares for reconnection. Lost FIN-ACK is handled by peer's timeout. Simplifies close handling for HFT. |
| **Runtime MTU validation** | FRAME_SIZE is compile-time constant from PATH_MTU. Runtime MTU changes not supported. HFT deployments have fixed network configuration. |
| **TCP fragmentation for large TX messages** | MSG_OUTBOX events must fit in single TCP segment (~1973 bytes with 2KB frames). Transport aborts on oversized messages. HFT messages are small; fragmentation adds latency and complexity. |
| **Subscription response verification** | Subscription messages are sent but responses are not validated by this library. AppClient MUST implement subscription confirmation handling if needed. |
| **Fragmented message assembly in WebSocket** | Fragment payloads are scattered in MSG_INBOX with headers between them. This library signals `is_fragmented=true` but does NOT assemble fragments into contiguous buffer. AppClient MUST implement `FragmentAssemblingClient` pattern if fragmented messages are expected. For HFT, prefer servers that send single-frame messages. |

---

## 15. Integration Testing

**Test File**: `test/integration/binance_pipeline.cpp` | **Target**: `make binance_pipeline USE_WOLFSSL=1`

### 15.1 Requirements

| Requirement | Value |
|-------------|-------|
| Interface | `enp108s0` |
| XDP Mode | Zero-copy (`XDP_ZEROCOPY \| SO_BUSY_POLL`) |
| bpftool | `~/Proj/bpftool/linux-6.14/tools/bpf/bpftool/bpftool` |
| Network Safety | Never overwrite VPN routes; `enp108s0` must have lower priority |

### 15.2 Pre-Test Setup

```bash
# 1. Update /etc/hosts (Binance IPs have high churn)
BINANCE_IP=$(nslookup stream.binance.com | grep -A1 'Name:' | tail -1 | awk '{print $2}')
sudo sed -i '/stream.binance.com/d' /etc/hosts && sudo bash -c "echo '$BINANCE_IP stream.binance.com' >> /etc/hosts"

# 2. Sync NIC clock & prepare XDP
./scripts/nic_local_clock_sync.sh
./scripts/xdp_prepare.sh enp108s0 && ./scripts/xdp_filter.sh enp108s0

# 3. Add route (lower priority than VPN)
sudo ip route add $BINANCE_IP via $(ip route | grep enp108s0 | grep -v default | awk '{print $3}' | head -1) dev enp108s0 metric 100
```

### 15.3 Build & Run

```bash
make binance_pipeline USE_WOLFSSL=1
sudo taskset -c 2 ./build/binance_pipeline enp108s0  # Even cores for HT isolation
```

### 15.4 Success Criteria

| Criterion | Expected |
|-----------|----------|
| Connection | TCP + TLS + WS handshake complete |
| Messages | ≥10 WebSocket frames |
| Latency | NIC → AppClient: P50 < 5µs, P99 < 15µs |
| Shutdown | SIGINT triggers clean exit; all UMEM frames returned |

### 15.5 Cleanup

```bash
sudo ip route del $BINANCE_IP && sudo ip link set dev enp108s0 xdp off
```

---

## 16. Review Notes & Known Issues

### 16.1 Inconsistencies Fixed

| Issue | Location | Resolution |
|-------|----------|------------|
| Core numbering (0,1,2,3 vs 2,4,6,8) | Architecture diagram, Handshake | Updated to use even cores (2,4,6,8) for HT isolation |
| WebSocket state variables | Diagram line 138 | Updated to match pipeline_2_ws.md: `partial_frame_start_seq_`, `first_packet_metadata_`, `pending_frame_` |
| Missing CRTP mention | AppClient box | Added "CRTP pattern" to AppClient description |
| PongFrame padding math | Section 3.3 | Added `static_assert(sizeof(PongFrame) == 126)` |

### 16.2 Logic Issues to Address in Implementation

| Issue | Severity | Description | Mitigation |
|-------|----------|-------------|------------|
| **Timestamp reset on SSL_read boundary** | Low | If TLS record spans multiple SSL_reads, "first" timestamps are from last SSL_read's batch, not true first packet | Documented as trade-off in Section 6; precise tracking requires per-TLS-record state |
| **UMEM frame leak on abort** | Low | If process aborts before comp_ring returns frame, UMEM frame is leaked until restart | Acceptable for HFT - restart on any error |
| **MSG_INBOX flow control** | Medium | No backpressure from AppClient to Transport - if AppClient is slow, Transport overwrites unread data | dirty_flag signals but doesn't prevent overwrite; Transport continues (AppClient optional) |

**NOTE**: "MSG_INBOX wrap with partial WS frame" was previously listed as an issue but is NOT a problem. Transport guarantees each SSL_read output is contiguous by checking `linear_space >= TLS_RECORD_MAX_SIZE` before each SSL_read. If insufficient space before wrap, Transport resets to head first. See `pipeline_2_ws.md` Partial Frame Handling section.

### 16.3 Potential Improvements (Future)

| Improvement | Priority | Description |
|-------------|----------|-------------|
| **Congestion window tracking** | Medium | Only track `peer_recv_window_`; could add `cwnd_` and `ssthresh_` for full TCP congestion control |
| **FIN handling with in-flight data** | Low | Current FIN handling may lose unacked data if peer's FIN races with our data; documented in pipeline_1_trans.md |

### 16.4 Design Decisions Rationale

| Decision | Rationale |
|----------|-----------|
| **Even cores (2,4,6,8)** | Avoid HyperThreading siblings; dedicated physical cores |
| **Full-buffer abort** | Deterministic latency > graceful degradation; misconfiguration should crash |
| **[0,0,0,0] WS mask** | XOR with zero is no-op; avoids masking payload while meeting RFC 6455 |
| **No thread safety** | Single-thread design for HFT; no mutex/atomic overhead |
| **Memory BIO for SSL** | Never blocks on SSL_ERROR_WANT_WRITE; auto-grow buffers |
| **comp_ring FIFO assumption** | NIC returns TX frames in submission order; position-based release depends on this; if violated, system aborts (considered NIC/driver bug) |
| **Sequential ACK frame release** | Position-based allocation assumes sequential release; comp_ring FIFO + cumulative ACK ensures correctness; large UMEM tolerates temporary slot gaps |
| **MSG_INBOX dirty_flag on overwrite** | AppClient process is optional; Transport continues on overwrite and sets dirty_flag; user decides whether to use AppClient |
| **Always try_claim(), never claim()** | Non-blocking producer pattern; abort on full buffer indicates misconfiguration |
