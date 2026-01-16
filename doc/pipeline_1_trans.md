# Pipeline Process 1: Transport (Core 4)

**Related Documents**:
- [Architecture Overview](pipeline_architecture.md)
- [XDP Poll Process (Core 2)](pipeline_0_nic.md)
- [WebSocket Process (Core 6)](pipeline_2_ws.md)
- [AppClient Process (Core 8)](pipeline_3_app.md)

---

## Overview

Transport Process handles the **pure TCP/IP stack** and **SSL/TLS encryption/decryption**. It is a **protocol-agnostic byte stream transport** - no application protocol parsing/building happens here.

**Key Responsibilities**:
1. **Fork-first handshake**: Performs TCP handshake + TLS handshake (if SSL policy enabled) via IPC rings
2. TCP retransmission (highest priority)
3. TX: Encrypt outbound byte stream → build TCP packets → RAW_OUTBOX
4. RX: Parse TCP packets → decrypt via SSL → write to MSG_INBOX
5. Adaptive ACK batching

**What Transport Does NOT Do** (handled by upstream processes like WebSocket Process):
- Application protocol handshakes (WebSocket upgrade, HTTP, etc.)
- Protocol frame parsing/building (WebSocket frames, etc.)
- Application-level PING/PONG handling
- Message framing or opcodes
- Subscription messages

**SSL Policy Configuration**:
- With `WolfSSLPolicy`/`OpenSSLPolicy`/`LibreSSLPolicy`: Transport performs both TCP and TLS handshake
- With `NoSSLPolicy`: Transport performs only TCP handshake (plain TCP, no encryption)

**Fork-First Architecture**: In the fork-first approach, Transport is forked BEFORE any network activity.
Transport waits for XDP Poll to signal `xdp_ready`, then performs TCP/TLS handshake via IPC rings,
and finally signals `tls_ready` before entering the main loop. Upper protocol handshakes (e.g., WebSocket upgrade)
are performed by the appropriate upstream process (e.g., WebSocket Process) via MSG_OUTBOX/MSG_INBOX.

---

## Transport Process Workflow

### System Context: Where Transport Fits

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          PIPELINE SYSTEM OVERVIEW                               │
└─────────────────────────────────────────────────────────────────────────────────┘

     ┌─────────────┐      ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
     │   NIC       │      │  XDP Poll   │      │  TRANSPORT  │      │  Upstream   │
     │  (HW)       │ ───▶ │  (Core 2)   │ ───▶ │  (Core 4)   │ ───▶ │  (Core 6+)  │
     │             │      │             │      │             │      │             │
     │ • HW tstamp │      │ • AF_XDP    │      │ • TCP/IP    │      │ • WS Parse  │
     │ • Ethernet  │      │ • UMEM mgmt │      │ • SSL/TLS   │      │ • App logic │
     └─────────────┘      └─────────────┘      └─────────────┘      └─────────────┘
           │                    │                    │                    │
           │                    │                    │                    │
     WIRE LAYER          FRAME LAYER           STREAM LAYER         MESSAGE LAYER
   (physical bits)     (raw Ethernet)      (encrypted bytes)     (app protocols)
```

### Transport Process Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      TRANSPORT PROCESS LIFECYCLE                                │
└─────────────────────────────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                            PHASE 1: INITIALIZATION                           │
  └──────────────────────────────────────────────────────────────────────────────┘

    Parent Process                         Transport (after fork)
    ──────────────                         ─────────────────────
         │                                        │
         │  fork()                                │
         ├───────────────────────────────────────▶│
         │                                        │
         │                                        ▼
         │                              ┌─────────────────────┐
         │                              │ Wait for XDP ready  │
         │                              │ (xdp_ready flag)    │
         │                              └──────────┬──────────┘
         │                                         │
         │                                         ▼
         │                              ┌─────────────────────┐
         │                              │ TCP 3-way handshake │
         │                              │ via IPC rings       │
         │                              │ (SYN → SYN-ACK → ACK)
         │                              └──────────┬──────────┘
         │                                         │
         │                                         ▼
         │                              ┌─────────────────────┐
         │                              │ TLS handshake       │
         │                              │ via IPC rings       │
         │                              │ (ClientHello →...)  │
         │                              └──────────┬──────────┘
         │                                         │
         │                                         ▼
         │                              ┌─────────────────────┐
         │                              │ Signal tls_ready    │
         │                              │ Store TCP state     │
         │                              └──────────┬──────────┘
         │                                         │
         │                                         ▼
         │                              ┌─────────────────────┐
         │                              │ Enter Main Loop     │
         │                              └─────────────────────┘


  ┌──────────────────────────────────────────────────────────────────────────────┐
  │                             PHASE 2: MAIN LOOP                               │
  └──────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────────────┐
                              │ while(is_running()) │◀─────────────────────────┐
                              └──────────┬──────────┘                          │
                                         │                                     │
         ┌───────────────────────────────┼───────────────────────────────┐     │
         │                               │                               │     │
         ▼                               ▼                               ▼     │
  ┌─────────────┐               ┌─────────────┐               ┌─────────────┐  │
  │ 0. RETRANS  │               │ 1. TX PATH  │               │ 2. RX PATH  │  │
  │ (priority)  │               │             │               │             │  │
  └──────┬──────┘               └──────┬──────┘               └──────┬──────┘  │
         │                             │                             │         │
         ▼                             ▼                             ▼         │
  Check RTO for              MSG_OUTBOX consume           RAW_INBOX consume    │
  unACKed frames             → SSL_write()                → TCP parse          │
         │                   → Build TCP pkt              → Process ACK        │
         │                   → RAW_OUTBOX                 → Feed SSL BIO       │
         │                             │                  → SSL_read()         │
         │                             │                  → MSG_INBOX          │
         │                             │                             │         │
         └─────────────────────────────┴─────────────────────────────┘         │
                                       │                                       │
         ┌─────────────────────────────┴─────────────────────────────┐         │
         │                                                           │         │
         ▼                                                           ▼         │
  ┌─────────────┐                                             ┌─────────────┐  │
  │ 3. ADAPTIVE │                                             │ 4. IDLE     │  │
  │    ACK      │                                             │    WORK     │  │
  └──────┬──────┘                                             └──────┬──────┘  │
         │                                                           │         │
         ▼                                                           ▼         │
  Send ACK if:                                                Process PONGS    │
  • 8+ pkts OR                                                (low priority)   │
  • 100µs timeout                                                    │         │
         │                                                           │         │
         └───────────────────────────────────────────────────────────┴─────────┘
```

### TX Path Detail (Outbound Data Flow)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           TX PATH: Encrypt & Send                               │
│                    (MSG_OUTBOX → SSL → TCP → RAW_OUTBOX)                        │
└─────────────────────────────────────────────────────────────────────────────────┘

  Upstream Process                    Transport Process                    XDP Poll
  ─────────────────                   ─────────────────                    ────────

  ┌─────────────────┐
  │ Application     │
  │ builds message  │
  │ (pre-framed)    │
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐     produce      ┌─────────────────┐
  │   MSG_OUTBOX    │ ───────────────▶ │   MSG_OUTBOX    │
  │   (IPC Ring)    │                  │   Consumer      │
  └─────────────────┘                  └────────┬────────┘
                                                │
                                                │ process_manually()
                                                ▼
                                       ┌─────────────────┐
                                       │ Check TCP       │
                                       │ receive window  │
                                       │ (flow control)  │
                                       └────────┬────────┘
                                                │
                                                │ if window available
                                                ▼
                                       ┌─────────────────┐
                                       │  SSL_write()    │
                                       │                 │
                                       │ Plaintext ──▶   │
                                       │    TLS record   │
                                       └────────┬────────┘
                                                │
                                                │ encrypted data in bio_out_
                                                ▼
                                       ┌─────────────────┐
                                       │ BIO_read()      │
                                       │ → UMEM frame    │
                                       │ (zero-copy)     │
                                       └────────┬────────┘
                                                │
                                                ▼
                                       ┌─────────────────┐
                                       │ Build TCP pkt   │
                                       │ ETH+IP+TCP hdr  │
                                       │ + encrypted     │
                                       │   payload       │
                                       └────────┬────────┘
                                                │
                                                ▼
                                       ┌─────────────────┐
                                       │ Add to          │
                                       │ retransmit queue│
                                       │ (msg or pong)   │
                                       └────────┬────────┘
                                                │
                                                ▼
                                       ┌─────────────────┐     consume     ┌────────────────┐
                                       │  RAW_OUTBOX     │ ──────────────▶ │  XDP Poll      │
                                       │  Producer       │                 │  TX submit     │
                                       └─────────────────┘                 └────────────────┘
                                                                                   │
                                                                                   ▼
                                                                           ┌────────────────┐
                                                                           │  NIC TX ring   │
                                                                           │  (to wire)     │
                                                                           └────────────────┘
```

### RX Path Detail (Inbound Data Flow)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           RX PATH: Receive & Decrypt                            │
│                    (RAW_INBOX → TCP → SSL → MSG_INBOX)                          │
└─────────────────────────────────────────────────────────────────────────────────┘

      NIC                         XDP Poll                      Transport Process
      ───                         ────────                      ─────────────────

  ┌────────────────┐
  │ Packet arrives │
  │ (HW timestamp) │
  └───────┬────────┘
          │
          ▼
  ┌────────────────┐     poll      ┌─────────────────┐
  │  NIC RX ring   │ ────────────▶ │ XDP Poll        │
  │  (from wire)   │               │ read HW tstamp  │
  └────────────────┘               └────────┬────────┘
                                            │
                                            │ rdtscp() - poll timestamp
                                            ▼
                                   ┌─────────────────┐     produce     ┌─────────────────┐
                                   │  RAW_INBOX      │ ──────────────▶ │  RAW_INBOX      │
                                   │  Producer       │                 │  Consumer       │
                                   └─────────────────┘                 └────────┬────────┘
                                                                                │
                                                                                │ process_manually()
                                                                                ▼
                                                                       ┌─────────────────┐
                                                                       │ rdtscp()        │
                                                                       │ (transport ts)  │
                                                                       └────────┬────────┘
                                                                                │
                                                                                ▼
                                                                       ┌─────────────────┐
                                                                       │ TCP Parse       │
                                                                       │ • seq, ack      │
                                                                       │ • flags         │
                                                                       │ • window        │
                                                                       └────────┬────────┘
                                                                                │
                                          ┌─────────────────────────────────────┼──────────────────┐
                                          │                                     │                  │
                                          ▼                                     ▼                  ▼
                                 ┌─────────────────┐                   ┌─────────────┐    ┌─────────────┐
                                 │ Has ACK flag?   │                   │ Has payload?│    │ seq check   │
                                 │                 │                   │             │    │             │
                                 │ Update window   │                   │ In-order?   │    │ Out-of-order│
                                 │ Update send_una │                   └──────┬──────┘    │ → dup ACK   │
                                 │ ACK retransmit  │                          │           └─────────────┘
                                 │ queue entries   │                          │
                                 └─────────────────┘                          ▼
                                                                       ┌─────────────────┐
                                                                       │ Feed encrypted  │
                                                                       │ data to bio_in_ │
                                                                       └────────┬────────┘
                                                                                │
                                                                                ▼
                                                                       ┌─────────────────┐
                                                                       │  SSL_read()     │
                                                                       │                 │
                                                                       │ TLS record ──▶  │
                                                                       │    Plaintext    │
                                                                       └────────┬────────┘
                                                                                │
                                                                                │ rdtscp() - SSL read complete
                                                                                ▼
                                                                       ┌─────────────────┐
                                                                       │ MSG_METADATA    │
                                                                       │ Producer        │
                                                                       │ (timestamps)    │
                                                                       └────────┬────────┘
                                                                                │
                                                                                ▼
  ┌─────────────────┐     consume      ┌─────────────────┐
  │ Upstream        │ ◀─────────────── │  MSG_INBOX      │
  │ Process         │                  │  (byte stream)  │
  └─────────────────┘                  └─────────────────┘
```

### TCP Retransmission Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          TCP RETRANSMISSION FLOW                                │
│                    (Highest Priority in Main Loop)                              │
└─────────────────────────────────────────────────────────────────────────────────┘

                              NORMAL TX FLOW
                              ──────────────
                                    │
                                    ▼
                           ┌─────────────────┐
                           │ SSL_write()     │
                           │ → TCP packet    │
                           └────────┬────────┘
                                    │
          ┌─────────────────────────┴─────────────────────────┐
          │                                                   │
          ▼                                                   ▼
  ┌─────────────────┐                               ┌─────────────────┐
  │ RAW_OUTBOX      │                               │ Retransmit      │
  │ (to XDP Poll)   │                               │ Queue           │
  └─────────────────┘                               │                 │
                                                    │ RetransmitRef:  │
                                                    │ • alloc_pos     │
                                                    │ • frame_idx     │
                                                    │ • seq_start/end │
                                                    │ • send_tsc      │
                                                    └────────┬────────┘
                                                             │
  ┌──────────────────────────────────────────────────────────┘
  │
  │   RETRANSMIT CHECK (interval-based: when idle OR every 1024 loops)
  │   ─────────────────
  │
  ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                                                                 │
  │   for each segment in retransmit_queue:                         │
  │                                                                 │
  │     now_tsc = rdtscp()                                          │
  │     elapsed = now_tsc - segment.send_tsc                        │
  │                                                                 │
  │     if elapsed > RTO_CYCLES (200ms):                            │
  │       ┌─────────────────────────────────────────────────────┐   │
  │       │ 1. Update TCP ACK field (current rcv_nxt)           │   │
  │       │ 2. Recalculate TCP checksum                         │   │
  │       │ 3. Re-publish to RAW_OUTBOX                         │   │
  │       │ 4. Update send_tsc = now_tsc                        │   │
  │       │ 5. Increment retransmit_count                       │   │
  │       └─────────────────────────────────────────────────────┘   │
  │                                                                 │
  │     if segment.retransmit_count > MAX_RETRIES:                  │
  │       → Set is_running = false (connection failed)              │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘

  ACK RECEIVED FLOW
  ─────────────────

  ┌─────────────────┐
  │ TCP packet with │
  │ ACK flag        │
  └────────┬────────┘
           │
           ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │                                                                 │
  │   ack_seq = tcp.ack   (peer's ACK number)                       │
  │                                                                 │
  │   for each segment in retransmit_queue:                         │
  │     if segment.seq_end <= ack_seq:                              │
  │       ┌─────────────────────────────────────────────────────┐   │
  │       │ Remove from queue                                   │   │
  │       │ Update msg_acked_pos (for XDP Poll frame release)   │   │
  │       └─────────────────────────────────────────────────────┘   │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
           │
           ▼
  ┌─────────────────┐         ┌─────────────────┐
  │ XDP Poll reads  │ ──────▶ │ Release UMEM    │
  │ msg_acked_pos   │         │ frames for      │
  └─────────────────┘         │ reuse           │
                              └─────────────────┘
```

### Timestamp Flow (Latency Tracking)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          TIMESTAMP PROPAGATION                                  │
│              (For end-to-end latency measurement)                               │
└─────────────────────────────────────────────────────────────────────────────────┘

  NIC              XDP Poll           Transport          Upstream         Application
  ───              ────────           ─────────          ────────         ───────────
   │                  │                   │                  │                 │
   │ HW timestamp     │                   │                  │                 │
   │ (nic_ts_ns)      │                   │                  │                 │
   ├─────────────────▶│                   │                  │                 │
   │                  │                   │                  │                 │
   │                  │ rdtscp()          │                  │                 │
   │                  │ (poll_cycle)      │                  │                 │
   │                  ├──────────────────▶│                  │                 │
   │                  │                   │                  │                 │
   │                  │                   │ rdtscp()         │                 │
   │                  │                   │ (raw_poll_cycle) │                 │
   │                  │                   │                  │                 │
   │                  │                   │ SSL_read() done  │                 │
   │                  │                   │ rdtscp()         │                 │
   │                  │                   │ (ssl_read_cycle) │                 │
   │                  │                   │                  │                 │
   │                  │                   │                  │                 │
   │                  │                   │ MSG_METADATA:    │                 │
   │                  │                   │ ┌─────────────┐  │                 │
   │                  │                   │ │nic_ts_ns   │──┼────────────────▶│
   │                  │                   │ │poll_cycle  │  │                 │
   │                  │                   │ │raw_cycle   │  │                 │
   │                  │                   │ │ssl_cycle   │  │                 │
   │                  │                   │ │offset, len │  │                 │
   │                  │                   │ └─────────────┘  │                 │
   │                  │                   │                  │                 │
   │                  │                   │                  │   rdtscp()      │
   │                  │                   │                  │   (app_cycle)   │
   │                  │                   │                  │        │        │
   │                  │                   │                  │        ▼        │
   │                  │                   │                  │  ┌───────────┐  │
   │                  │                   │                  │  │ Latency   │  │
   │                  │                   │                  │  │ Breakdown │  │
   │                  │                   │                  │  └───────────┘  │

  Latency Breakdown:
  ─────────────────
  • NIC → XDP Poll:     poll_cycle - nic_ts_ns (HW to SW)
  • XDP → Transport:    raw_poll_cycle - poll_cycle
  • Transport decrypt:  ssl_read_cycle - raw_poll_cycle
  • Transport → App:    app_cycle - ssl_read_cycle
```

## Ring Buffer Summary

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      TRANSPORT PROCESS RING INTERACTIONS                        │
│              (Protocol-agnostic: upstream can be WS/HTTP/custom)                │
└─────────────────────────────────────────────────────────────────────────────────┘

  CONSUMES (Input):                              PRODUCES (Output):
  ═════════════════                              ══════════════════

  ┌─────────────────┐                            ┌─────────────────┐
  │ RAW_INBOX       │                            │ RAW_OUTBOX      │
  │ UMEMFrameDesc   │  ──── TCP packets ────▶   │ UMEMFrameDesc   │
  │ (from XDP Poll) │       encrypted            │ (to XDP Poll)   │
  └─────────────────┘                            └─────────────────┘

  ┌─────────────────┐                            ┌─────────────────┐
  │ MSG_OUTBOX      │                            │ ACK_OUTBOX      │
  │ MsgOutboxEvent  │  ──── byte stream ────▶   │ UMEMFrameDesc   │
  │ (from upstream) │       to encrypt           │ (to XDP Poll)   │
  └─────────────────┘                            └─────────────────┘

  ┌─────────────────┐                            ┌─────────────────┐
  │ PONGS           │                            │ PONG_OUTBOX     │
  │ PongFrameAligned│  ─ ctrl frame data ──▶   │ UMEMFrameDesc   │
  │ (from upstream) │                            │ (to XDP Poll)   │
  └─────────────────┘                            └─────────────────┘

                                                 ┌─────────────────┐
                                                 │ MSG_INBOX       │
                        ◀──── decrypted ────    │ (byte stream)   │
                              bytes              │ (to upstream)   │
                                                 └─────────────────┘

                                                 ┌─────────────────┐
                                                 │ MSG_METADATA    │
                        ◀──── timestamps ────   │ MsgMetadata     │
                                                 │ (to upstream)   │
                                                 └─────────────────┘
```

---

## UMEM Memory Layout

```
UMEM (contiguous shared memory, mmap'd):
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Total: 65536 frames                             │
├─────────────────────┬──────────────┬──────────────┬────────────────┬────────┤
│    RX Pool (1/2)    │  ACK (1/8)   │  PONG (1/8)  │   MSG (1/4)    │Trickle │
│     32768 frames    │ 8192 frames  │ 8192 frames  │  16384 frames  │  64B   │
│   idx: 0-32767      │ 32768-40959  │ 40960-49151  │ 49152-65535    │        │
└─────────────────────┴──────────────┴──────────────┴────────────────┴────────┘

Frame address: umem_area_addr = frame_idx * FRAME_SIZE
Frame pointer: frame_ptr = umem_area_area_ + umem_area_addr
```

### Single UMEM Frame Structure (FRAME_SIZE = 2048 bytes)

```
FRAME_SIZE = ((PATH_MTU + 94 + 1023) / 1024) * 1024 = 2048 bytes

┌──────────────────────────────────────────────────────────────────┐
│                        2048 bytes (one frame)                     │
├────────────┬──────────┬────────────────┬─────────────────────────┤
│ Ethernet   │   IP     │     TCP        │        Payload          │
│   14B      │  20B     │   20-60B       │      up to ~1954B       │
├────────────┴──────────┴────────────────┴─────────────────────────┤
│ offset: 0      14          34              54-94                  │
└──────────────────────────────────────────────────────────────────┘

Header offsets (TCP without options):
  ETH_HEADER_LEN  = 14
  IP_HEADER_LEN   = 20
  TCP_HEADER_LEN  = 20 (min), 60 (max with options)
  TOTAL_HEADER    = 54 (min), 94 (max)
  PAYLOAD_OFFSET  = 54 (after ETH+IP+TCP headers)
```

### DESIGN DECISION: Zero-Copy Everywhere

**Principle**: Always do zero-copy if possible. Never copy data that's already in the right place.

**TX Path Zero-Copy Flow**:
```
                                    UMEM Frame
                    ┌───────────────────────────────────────────┐
                    │ [  headers  ][      payload area        ] │
                    │ offset 0-53   offset 54+                  │
                    └───────────────────────────────────────────┘
                           ▲              ▲
                           │              │
Step 1: Set output buffer ────────────────┘ (point to payload area)
        ssl_policy_.set_encrypted_output(frame + 54, capacity)

Step 2: SSL_write encrypts directly ──────┘ (encrypts into payload area)
        ssl_policy_.write(plaintext, len)
        encrypted_len = ssl_policy_.encrypted_output_len()
        ssl_policy_.clear_encrypted_output()

Step 3: Build headers in-place ───────────┘ (prepend to existing payload)
        build_headers(frame, encrypted_len)
        - Writes ETH header at offset 0
        - Writes IP header at offset 14
        - Writes TCP header at offset 34
        - Payload already at offset 54 (NO COPY!)
```

**Implementation**:
- `ssl_policy_.set_encrypted_output()` points to UMEM at `frame + HEADER_LEN`
- `ssl_policy_.write()` encrypts directly into that buffer
- `ssl_policy_.encrypted_output_len()` returns actual encrypted size
- `TCPPacket::build_headers()` builds ETH/IP/TCP headers in-place, payload untouched
- **NO memcpy for payload** - data written once, sent directly to NIC

**Fixed TCP Header Length (20 bytes)**:

The zero-copy TX path (`process_outbound<TxType>()` and `prepare_encrypted_packet()`) assumes a fixed 20-byte
TCP header with no options. This allows the hardcoded offset 54 (ETH 14 + IP 20 + TCP 20) to be
used for payload placement.

- **Data packets**: Always use `TCP_FLAG_PSH | TCP_FLAG_ACK` with 20-byte TCP header
- **SYN packets**: Use `TCPPacket::build()` (not zero-copy) which supports 24-byte header with MSS option
- **No TCP timestamp/SACK options**: HFT systems typically disable these for latency reasons

If TCP options were needed on data packets, the payload offset would vary and zero-copy would
require dynamic offset calculation. Current design trades flexibility for simplicity and speed.

**Why This Matters for HFT**:
1. **Cache efficiency**: Data stays in L1/L2 cache, no cache pollution from copies
2. **Latency**: Eliminate ~100-500ns per packet from avoided memcpy
3. **Bandwidth**: Reduce memory bus utilization
4. **Predictability**: Fewer operations = less jitter

**Ring Buffer Publishing Pattern**:

Always use `try_claim()` + fill in-place + `publish(seq)` pattern for ring buffer publishing:
```cpp
// CORRECT: Zero-copy pattern
int64_t seq = producer->try_claim();
if (seq < 0) { /* handle full */ }
auto& slot = (*producer)[seq];
slot.field1 = value1;  // Write directly to ring buffer slot
slot.field2 = value2;
producer->publish(seq);

// WRONG: try_publish() copies from stack - DO NOT USE
MyStruct local;
local.field1 = value1;
local.field2 = value2;
producer->try_publish(local);  // Copies local → ring buffer (breaks zero-copy!)
```

**Why `try_publish()` is forbidden**:
- `try_publish(obj)` copies from stack object to ring buffer slot
- This adds unnecessary memcpy on every publish
- The 3-step pattern writes directly to the ring buffer slot (zero-copy)
- Consistent pattern across all producers (metadata, ACK, raw frames, etc.)

---

## Code Reuse

```cpp
// Disruptor IPC (from 01_shared_headers/disruptor/)
#include <disruptor/disruptor.hpp>        // ring_buffer, sequencer, event_processor

// TCP/IP Stack
#include <stack/userspace_stack.hpp>      // UserspaceStack
#include <stack/tcp/conn_state.hpp>        // TCPState, TCPParams, TCPParseResult, TCP_FLAG_*
#include <stack/tcp/tcp_retransmit.hpp>   // ZeroCopyRetransmitQueue, RetransmitSegmentRef
#include <stack/ip/checksum.hpp>          // ip_checksum(), tcp_checksum()

// SSL/TLS Policy (policy-based design)
#include <policy/ssl.hpp>                     // OpenSSLPolicy, LibreSSLPolicy, WolfSSLPolicy

// Timing
#include <core/timing.hpp>                // rdtsc(), rdtscp()
```

**Note**: Transport does NOT include any WebSocket or HTTP headers (`ws_parser.hpp`, `http.hpp`).
WebSocket frame parsing/building is handled by WebSocket Process (see `pipeline_2_ws.md`).

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
| `NoSSLPolicy` | None | Pass-through for plain TCP (no encryption) |

### NoSSLPolicy for Plain TCP

For scenarios where TLS encryption is not required (e.g., internal networks, testing, or protocols that don't use TLS), use `NoSSLPolicy`:

```cpp
// Plain TCP transport (no TLS encryption)
template<>
class TransportProcess<NoSSLPolicy> {
    NoSSLPolicy ssl_policy_;  // Pass-through - no encryption overhead

    // ... same interface as encrypted transport
};

// Usage:
// - SimulatorTransport with pre-recorded (already decrypted) data
// - Internal network connections where TLS overhead is unnecessary
// - Testing/debugging without encryption complexity
// - WebSocket over plain TCP (ws:// instead of wss://)
```

**NoSSLPolicy Behavior**:
- `init()`: No-op (no SSL context needed)
- `handshake()`: No-op (no TLS handshake)
- `read()/write()`: Direct pass-through to underlying transport
- `pending()`: Always returns 0 (no SSL buffering)
- `ktls_enabled()`: Always returns false

**When to Use NoSSLPolicy**:
1. **SimulatorTransport**: Replaying pre-recorded market data that's already decrypted
2. **Internal Services**: Backend-to-backend communication on trusted networks
3. **Testing**: Simplify debugging by removing encryption layer
4. **Performance Benchmarks**: Isolate transport performance from TLS overhead

**Security Warning**: Only use `NoSSLPolicy` in trusted environments. Production exchange connections require TLS encryption.

### SSLPolicyConcept Interface

All SSL policies implement this interface:
```cpp
struct SSLPolicy {
    // Lifecycle
    void init();                                  // Initialize SSL context
    void init_zero_copy_bio();                    // Initialize zero-copy BIO mode
    void handshake(int fd);                       // BSD socket handshake
    void handshake_userspace_transport(T* tp);    // Userspace TCP handshake
    void shutdown();                              // Close SSL session
    void cleanup();                               // Full cleanup

    // Read/Write (decrypted data)
    ssize_t read(void* buf, size_t len);          // Decrypt and read
    ssize_t write(const void* buf, size_t len);   // Encrypt and write
    size_t pending() const;                       // Bytes buffered in SSL

    // Zero-copy RX: encrypted data input (1024-slot ring buffer, no copy)
    int append_encrypted_view(const uint8_t* data, size_t len);  // Returns -1 on overflow
    void clear_encrypted_view();                  // Reset ring buffer (reconnect only)

    // Zero-copy TX: encrypted data output (direct write to UMEM)
    void set_encrypted_output(uint8_t* buf, size_t len);  // Point to UMEM
    size_t encrypted_output_len() const;          // Bytes written to output
    void clear_encrypted_output();                // Done with current output

    // Status
    bool ktls_enabled() const;                    // kTLS status
    int get_fd() const;                           // Underlying socket fd
};
```

### DESIGN DECISION: Zero-Copy SSL I/O

**Principle**: Eliminate intermediate buffer copies. SSL reads/writes directly from/to UMEM frames.

**RX Path (Zero-Copy with Ring Buffer)**:
```
UMEM frames (TCP payloads from batch)
    ↓
append_encrypted_view(payload_ptr, len)  ← No copy, stores pointer in 1024-slot ring buffer
    ↓                                       Returns -1 if buffer full (abort on overflow)
ssl_policy_.read(msg_inbox_->write_ptr(), len)  ← Decrypt from ring buffer into MSG_INBOX
    ↓                                              Ring buffer auto-cycles (tail advances)
[No clear_encrypted_view() needed]  ← Only called on reconnection/shutdown
```

**Ring Buffer Semantics**:
- 1024 ViewSegment slots (pointer + length pairs)
- Head: write position (producer), Tail: read position (consumer)
- `head == tail` means buffer is empty
- `head - tail >= 1024` means buffer is full (returns -1)
- Auto-cycles: read advances tail, no explicit clear needed

**TX Path (Zero-Copy)**:
```
set_encrypted_output(umem_area_frame + 54, capacity)  ← Point to UMEM payload area
    ↓
ssl_policy_.write(plaintext, len)  ← Encrypt directly into UMEM
    ↓
encrypted_output_len()  ← Get actual encrypted size
    ↓
clear_encrypted_output()
```

**Implementation by Policy**:
- **OpenSSL/LibreSSL**: Custom BIO type that reads from/writes to external pointers
- **WolfSSL**: Custom I/O callbacks (wolfSSL_SetIORecv/Send) using external pointers
- **NoSSL**: Direct pointer storage (no encryption, trivial implementation)

**Benefits**:
- Eliminates 2+ memcpy per RX message, 2+ memcpy per TX message
- Reduces cache pollution
- Lower latency for both RX and TX paths

### Zero-Copy SSL I/O Model

Transport Process does NOT use `userspace_transport_bio.hpp`. Instead, it uses a zero-copy view/output buffer model that avoids memory copies between UMEM and SSL:

```
RX Path (UMEM → SSL → MSG_INBOX):
  UMEM frames → append_encrypted_view() → SSL_read() → MSG_INBOX (zero-copy)
                (ring buffer of UMEM      (decrypts from  (writes directly
                 frame pointers)           scattered views) to byte stream)

TX Path (MSG_OUTBOX → SSL → UMEM):
  MSG_OUTBOX → set_encrypted_output() → SSL_write() → UMEM frame (zero-copy)
               (sets output buffer to    (encrypts directly
                UMEM frame payload area)  into UMEM)
```

**SSL Policy Zero-Copy API**:
```cpp
// RX: Append encrypted data view (points to UMEM, no copy)
int append_encrypted_view(const uint8_t* data, size_t len);  // Returns -1 on overflow

// TX: Set output buffer before SSL_write (writes directly to UMEM)
void set_encrypted_output(uint8_t* buf, size_t capacity);
size_t encrypted_output_len() const;  // Get bytes written
void clear_encrypted_output();        // Reset for next frame
```

### Transport Process SSL Usage

Transport Process uses SSL policy for TLS encryption/decryption:

```cpp
template<typename SSLPolicy = WolfSSLPolicy>
class TransportProcess {
    SSLPolicy ssl_policy_;

    void init_with_handshake(...) {
        ssl_policy_.init_zero_copy_bio();  // Initialize zero-copy BIO
        // TCP handshake via IPC rings
        // TLS handshake via IPC rings (uses append_encrypted_view / set_encrypted_output)
    }

    // RX: ssl_read_to_msg_inbox() uses ssl_policy_.read()
    // TX: process_outbound() uses ssl_policy_.set_encrypted_output() + ssl_policy_.write()
};
```

### WolfSSL Native I/O (No BIO)

WolfSSL uses native I/O callbacks instead of BIO abstraction:
```cpp
wolfSSL_CTX_SetIORecv(ctx_, WolfSSLUserspaceIO<TransportPolicy>::recv_cb);
wolfSSL_CTX_SetIOSend(ctx_, WolfSSLUserspaceIO<TransportPolicy>::send_cb);
wolfSSL_SetIOReadCtx(ssl_policy_.ssl_, transport);
wolfSSL_SetIOWriteCtx(ssl_policy_.ssl_, transport);
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
    ZeroCopyRetransmitQueue msg_retransmit_queue_;   // MSG frame retransmit queue
    ZeroCopyRetransmitQueue pong_retransmit_queue_;  // PONG frame retransmit queue (separate)

    // SSL/TLS policy (created and owned in fork-first architecture)
    SSLPolicy ssl_policy_;

    // Memory BIO pointers for SSL I/O (OpenSSL/LibreSSL only)
    // - OpenSSL/LibreSSL: Use memory BIOs for userspace transport
    // - WolfSSL: Uses native I/O callbacks, no BIO needed
    // - NoSSL: Pass-through, no SSL at all
    //
    // Use type traits to conditionally include BIO pointers at compile time
    // void* avoids OpenSSL header dependency; cast to BIO* when needed
    static constexpr bool needs_bio_ = !std::is_same_v<SSLPolicy, WolfSSLPolicy> &&
                                       !std::is_same_v<SSLPolicy, NoSSLPolicy>;
    [[no_unique_address]] std::conditional_t<needs_bio_, void*, std::monostate> bio_in_{};
    [[no_unique_address]] std::conditional_t<needs_bio_, void*, std::monostate> bio_out_{};

    // Shared state (includes TCP state and TX frame allocation)
    // See pipeline_data.hpp for ConnStateShm definition
    ConnStateShm* conn_state_;
    uint8_t* umem_area_area_;                   // Pointer to UMEM buffer

    // Timestamp tracking state for SSL_read batches
    // Tracks both first and latest timestamps for latency analysis:
    //   - first_*: First packet in batch (useful for batch start timing)
    //   - latest_*: Last packet in batch (useful for batch end timing)
    uint64_t first_nic_timestamp_ns_ = 0;
    uint64_t first_nic_frame_poll_cycle_ = 0;   // XDP Poll rdtscp of first packet
    uint64_t first_raw_frame_poll_cycle_ = 0;   // Transport rdtscp of first packet
    uint64_t latest_nic_timestamp_ns_ = 0;
    uint64_t latest_nic_frame_poll_cycle_ = 0;  // XDP Poll rdtscp of latest packet
    uint64_t latest_raw_frame_poll_cycle_ = 0;  // Transport rdtscp of latest packet
    bool has_pending_timestamps_ = false;

    // UMEM access (raw pointer, no XDP wrapper needed)
    // Frame access via: umem_area_ + frame_idx_to_addr(frame_idx, frame_size_)
    uint32_t frame_size_ = 0;              // UMEM frame size
    // Note: TxFrameState is merged into ConnStateShm.tx_frame
    // Access via: conn_state_->tx_frame.ack_alloc_pos, etc.

    // DESIGN DECISION: Buffer Full = Abort
    // All TX frame pool exhaustion (ACK, PONG, MSG) triggers std::abort().
    // This is intentional for HFT systems:
    //   1. A full buffer indicates system misconfiguration (buffer too small)
    //   2. Or indicates a process is too slow (critical performance issue)
    //   3. Graceful degradation would hide latency problems
    //   4. Crashing immediately allows detection and correction
    //
    // DESIGN DECISION: Abort When Things Don't Look Right
    // Any inconsistent state or unexpected failure in the main loop triggers std::abort().
    // Examples:
    //   - pending() > 0 but encrypted_output_len() returns 0
    //   - SSL_write() returns <= 0 (should not happen with zero-copy BIO)
    //   - TCPPacket::build() returns 0 (invalid params or buffer too small)
    //   - Retransmit queue full (should never happen with proper sizing)
    // Rationale: In HFT, silent failures or degraded operation is worse than crashing.
    // A crash exposes the problem immediately for investigation and fix.

    // NOTE: FIN/RST handling is NOT implemented.
    // HFT uses reconnect strategy for all connection terminations.
    // See "Future Improvements" section for details if implementation is needed.

    // Ring buffer producers/consumers
    RawInboxCons* raw_inbox_cons_ = nullptr;
    RawOutboxProd* raw_outbox_prod_ = nullptr;
    AckOutboxProd* ack_outbox_prod_ = nullptr;
    PongOutboxProd* pong_outbox_prod_ = nullptr;
    MsgMetadataProd* msg_metadata_prod_ = nullptr;
    MsgOutboxCons* msg_outbox_cons_ = nullptr;
    PongsCons* pongs_cons_ = nullptr;

    // MSG_INBOX byte stream ring
    MsgInbox* msg_inbox_ = nullptr;

    // TCP parameters (initialized from handshake, updated during connection)
    userspace_stack::TCPParams tcp_params_;

    // Initialization (called after fork, before run()):
    // void init(ConnStateShm* conn_state_shm, TxFrameState* tx_state, ...) {
    //     tcp_params_.snd_nxt = conn_state_shm->initial_seq + 1;  // After SYN
    //     tcp_params_.rcv_nxt = conn_state_shm->peer_initial_seq + 1;  // After SYN-ACK
    //     // TCP state stored directly in conn_state_shm
    //     // ... other initialization
    // }

    // State from handshake (stored in shared memory via conn_state_->)
    // peer_recv_window, window_scale, snd_una accessed via conn_state_->

    // Adaptive ACK state (TSC-based timing for busy-polling - no syscalls)
    uint32_t packets_since_ack_ = 0;
    uint64_t last_ack_cycle_ = 0;
    uint64_t ack_timeout_cycles_ = 0;  // Pre-calculated from ACK_TIMEOUT_US * tsc_freq_hz
    uint64_t rto_cycles_ = 0;          // Pre-calculated from RTO_MS * tsc_freq_hz
    // NOTE: Cycle thresholds are calculated once in init() from conn_state_->tsc_freq_hz.
    // TSC frequency is calibrated once in parent process and stored in shared memory.

    static constexpr uint32_t ACK_PACKET_THRESHOLD = 8;
    static constexpr uint64_t ACK_TIMEOUT_US = 100;
    static constexpr uint32_t RTO_MS = 200;       // Retransmission timeout
    static constexpr uint32_t RETRANSMIT_CHECK_INTERVAL = 1024;  // Check retransmit every N loops

    // TLS sizing
    static constexpr size_t TLS13_OVERHEAD = 5 + 16;  // Record header + AEAD tag
    static constexpr size_t MAX_TLS_PLAINTEXT = TCP_MSS - TLS13_OVERHEAD;

public:
    // ========================================================================
    // init_with_handshake() - Fork-first: Performs TCP + TLS handshake via IPC
    // Called in Transport child process after fork
    // NOTE: Only TCP/TLS handshake - no application protocol (WebSocket, HTTP, etc.)
    // ========================================================================
    bool init_with_handshake(void* umem_area_area, uint32_t frame_size,
                              const char* target_host, uint16_t target_port,
                              ConnStateShm* conn_state,
                              RawInboxCons* raw_inbox_cons,
                              RawOutboxProd* raw_outbox_prod,
                              AckOutboxProd* ack_outbox_prod,
                              PongOutboxProd* pong_outbox_prod,
                              MsgMetadataProd* msg_metadata_prod,
                              PongsCons* pongs_cons,
                              MsgOutboxCons* msg_outbox_cons,
                              MsgInbox* msg_inbox);

    void run();
    void cleanup();

private:
    // Handshake helpers (fork-first) - Transport only does TCP/TLS
    // NOTE: Application protocol handshakes (WebSocket, HTTP, etc.) are handled
    //       by upstream processes via MSG_OUTBOX/MSG_INBOX after tls_ready
    bool perform_tcp_handshake_via_ipc(const char* target_host, uint16_t target_port);
    bool perform_tls_handshake_via_ipc(const char* target_host);
};
```

---

## init_with_handshake() Implementation (Fork-First)

In fork-first architecture, Transport performs **TCP/TLS handshake only** via IPC rings
after XDP Poll has created the XSK socket.

**Note**: Transport is protocol-agnostic. Higher-level protocol handshakes (WebSocket upgrade,
HTTP handshake, etc.) are handled by the appropriate Process (e.g., WebSocket Process).

```cpp
template<typename SSLPolicy>
bool TransportProcess<SSLPolicy>::init_with_handshake(
        void* umem_area_area, uint32_t frame_size,
        const char* target_host, uint16_t target_port,
        ConnStateShm* conn_state, ...) {

    umem_area_ = static_cast<uint8_t*>(umem_area_area);
    conn_state_ = conn_state;

    // Store IPC ring pointers (created by parent before fork)
    raw_inbox_cons_ = raw_inbox_cons;
    raw_outbox_prod_ = raw_outbox_prod;
    ack_outbox_prod_ = ack_outbox_prod;
    pong_outbox_prod_ = pong_outbox_prod;
    msg_inbox_ = msg_inbox;
    // ... store other ring pointers

    // Load TSC frequency from shared memory (calibrated once in parent)
    // TSC frequency available via conn_state_->tsc_freq_hz

    // 1. Wait for XDP Poll to signal xdp_ready (XSK socket created)
    printf("[TRANSPORT] Waiting for XDP Poll to create XSK socket...\n");
    if (!conn_state_->wait_for_handshake_xdp_ready(30000000)) {  // 30s timeout
        fprintf(stderr, "[TRANSPORT] ERROR: XDP Poll timeout\n");
        return false;
    }
    printf("[TRANSPORT] XDP Poll ready, starting handshake\n");

    // 2. Perform TCP 3-way handshake via IPC rings
    if (!perform_tcp_handshake_via_ipc(target_host, target_port)) {
        fprintf(stderr, "[TRANSPORT] ERROR: TCP handshake failed\n");
        return false;
    }
    conn_state_->handshake_stage.tcp_ready.store(1, std::memory_order_release);
    printf("[TRANSPORT] TCP handshake complete\n");

    // 3. Perform TLS handshake via IPC rings (skip if using NoSSLPolicy)
    if (!perform_tls_handshake_via_ipc(target_host)) {
        fprintf(stderr, "[TRANSPORT] ERROR: TLS handshake failed\n");
        return false;
    }
    conn_state_->handshake_stage.tls_ready.store(1, std::memory_order_release);
    printf("[TRANSPORT] TLS handshake complete\n");

    // 4. Store TCP state for other processes
    conn_state_->initial_seq = tcp_params_.initial_seq;
    conn_state_->peer_initial_seq = tcp_params_.peer_initial_seq;
    // peer_recv_window and window_scale already stored in conn_state_ during handshake
    conn_state_->local_ip = stack_.local_ip();
    conn_state_->peer_ip = stack_.peer_ip();
    conn_state_->local_port = stack_.local_port();
    conn_state_->peer_port = stack_.peer_port();
    memcpy(conn_state_->local_mac, stack_.local_mac(), 6);
    memcpy(conn_state_->peer_mac, stack_.peer_mac(), 6);

    // 5. Signal transport ready (TCP/TLS handshake complete)
    // NOTE: Higher-level protocols (WebSocket, etc.) do their own handshake via MSG_OUTBOX/MSG_INBOX
    conn_state_->set_handshake_tls_ready();
    printf("[TRANSPORT] TCP/TLS handshake complete, signaling tls_ready\n");

    return true;
}
```

---

## Main Loop

```cpp
void TransportProcess::run() {
    uint32_t loops_since_retransmit_check = 0;

    // Fork-first: use is_running() helper with ProcessId enum
    while (conn_state_->is_running(PROC_TRANSPORT)) {
        bool data_moved = false;  // Track if any data was sent or received this round

        // 1. TX: MSG_OUTBOX → SSL_write → RAW_OUTBOX
        // NOTE: No pending write handling needed - memory BIOs never return SSL_ERROR_WANT_WRITE
        //
        // DESIGN DECISION: No TCP Window Checking
        // ========================================
        // We do NOT check peer's receive window before sending. Rationale:
        //   1. HFT scenario: Exchange connections are well-provisioned, window exhaustion is rare
        //   2. Simplicity: Avoid tracking bytes_in_flight and effective_window
        //   3. Rely on retransmit: If peer's buffer fills, packets get dropped and retransmitted
        //   4. Low latency priority: Window checking adds branches to hot path
        // If window exhaustion becomes an issue, it indicates network/server misconfiguration.

        // Unified TX processing via template - handles MSG and PONG identically
        // Uses process_outbound<TxType::MSG>() which:
        //   1. Claims ALL available RAW_OUTBOX slots upfront
        //   2. Encrypts each MSG_OUTBOX event into UMEM (zero-copy)
        //   3. Builds ETH/IP/TCP headers in-place
        //   4. Adds to msg_retransmit_queue_ for TCP reliability
        //   5. Publishes in TX_BATCH_SIZE chunks
        //
        // CONSTRAINT: Each MSG_OUTBOX event must fit in a single TCP segment.
        //             Max plaintext size = FRAME_SIZE - 54 (headers) - 21 (TLS overhead)
        //             With 2KB frames: max ~1973 bytes. Larger events trigger abort().
        //
        if (process_outbound<TxType::MSG>() > 0) {
            data_moved = true;
        }

        // 2. RX: RAW_INBOX → parse → SSL_read → MSG_INBOX - uses process_manually
        size_t rx_count = 0;
        bool out_of_order = false;
        raw_inbox_cons_->process_manually(
            [&](UMEMFrameDescriptor& desc, int64_t seq) -> bool {
                // Track timestamps for latency analysis (rdtscp from core/timing.hpp)
                uint64_t raw_poll_cycle = rdtscp();

                // Track first and latest timestamps for this SSL_read batch
                if (!has_pending_timestamps_) {
                    first_nic_timestamp_ns_ = desc.nic_timestamp_ns;
                    first_nic_frame_poll_cycle_ = desc.nic_frame_poll_cycle;  // XDP Poll timestamp
                    first_raw_frame_poll_cycle_ = raw_poll_cycle;  // Transport timestamp of first packet
                    has_pending_timestamps_ = true;
                }
                latest_nic_timestamp_ns_ = desc.nic_timestamp_ns;
                latest_nic_frame_poll_cycle_ = desc.nic_frame_poll_cycle;  // XDP Poll timestamp
                latest_raw_frame_poll_cycle_ = raw_poll_cycle;  // Transport timestamp of latest packet

                uint8_t* frame = umem_area_ + desc.umem_area_addr;
                TCPParseResult tcp = stack_.parse_tcp(frame, desc.frame_len);

                // Update peer window from ACK
                if (tcp.flags & TCP_FLAG_ACK) {
                    conn_state_->peer_recv_window = tcp.window;
                    conn_state_->snd_una = tcp.ack;  // Update oldest unacked sequence

                    // Process ACK for MSG frames (cumulative - advances acked_pos)
                    // NOTE: ack_up_to() maps TCP seq (uint32_t) → frame alloc position (uint64_t)
                    // tcp.ack is the TCP ACK sequence number from peer
                    // Returns highest frame position that's been fully ACKed
                    uint64_t msg_acked_pos = msg_retransmit_queue_.ack_up_to(tcp.ack);
                    conn_state_->tx_frame.msg_acked_pos.store(msg_acked_pos, std::memory_order_release);

                    // Process ACK for PONG frames (separate queue, same seq→pos mapping)
                    uint64_t pong_acked_pos = pong_retransmit_queue_.ack_up_to(tcp.ack);
                    conn_state_->tx_frame.pong_acked_pos.store(pong_acked_pos, std::memory_order_release);
                }

                // FIN/RST Handling: NOT IMPLEMENTED
                // ==================================
                // HFT uses reconnect strategy for all connection terminations.
                // FIN/RST handling adds complexity without latency benefit.
                // If peer sends FIN or RST, the connection will eventually timeout
                // or fail, triggering reconnection which is the recovery strategy anyway.
                //
                // See "Future Improvements" section for details if implementation is needed.

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
                        // In-order packet: append to encrypted view ring buffer (zero-copy)
                        tcp_params_.rcv_nxt += tcp.payload_len;
                        packets_since_ack_++;
                        if (ssl_policy_.append_encrypted_view(frame + tcp.payload_offset, tcp.payload_len) != 0) {
                            fprintf(stderr, "[FATAL] SSL view ring buffer overflow\n");
                            std::abort();
                        }
                    } else if (seq_lt(tcp.seq, tcp_params_.rcv_nxt)) {
                        // Retransmit of already-received data (ignore, but ACK)
                    } else {
                        // Out-of-order (tcp.seq > rcv_nxt): set flag, DISCARD packet
                        // See "OUT-OF-ORDER PACKET LIMITATION" comment above
                        out_of_order = true;
                    }
                }

                // Mark frame as consumed for XDP Poll to reclaim
                // NOTE: This is set AFTER we've finished reading the frame data
                desc.consumed = 1;

                rx_count++;
                return true;  // Continue processing
            });
        raw_inbox_cons_->commit_manually();

        if (rx_count > 0) {
            ssl_read_to_msg_inbox();
        }

        // Out of order - send duplicate ACK for fast retransmit (after batch processing)
        if (out_of_order) {
            send_ack();
        }

        // 3. Adaptive ACK (TSC-based timing - no syscalls in hot path)
        check_and_send_ack();

        // 4. (idle) PONG encryption - process ALL pending PONGs when no data sent/received
        //
        // DESIGN DECISION: PONGs processed in batch during idle
        // =====================================================
        // PONGs are lower priority than data messages. Processing them during idle
        // ensures data path latency is not affected by PONG handling.
        //
        // NOTE: PONGS ring contains pre-framed PONG data from WebSocket Process.
        //       Transport just encrypts and sends - no WebSocket frame building here.
        //
        // Uses unified process_outbound<TxType>() template (same as MSG path):
        //   1. Claim ALL available PONG_OUTBOX slots upfront
        //   2. Process ALL pending PONGs in one pass
        //   3. Publish in TX_BATCH_SIZE chunks
        //
        // WHY BATCH ALL PONGS:
        // 1. Multiple PINGs may arrive during data bursts - process all when idle
        // 2. Batching reduces per-PONG overhead (one claim vs. N claims)
        // 3. Unified template ensures consistent behavior for MSG and PONG
        //
        if (!data_moved) {
            process_outbound<TxType::PONG>();  // Process ALL pending PONGs
        }

        // 5. Retransmit check (interval-based, not every loop)
        //
        // DESIGN DECISION: Retransmit Check Interval
        // ===========================================
        // Retransmit check is skipped when data is flowing (data_moved == true),
        // checked only every RETRANSMIT_CHECK_INTERVAL (1024) loops or when idle.
        //
        // Rationale:
        //   1. If data_moved == true, network is healthy and packets are flowing
        //   2. Retransmit queue is likely empty or being ACKed normally
        //   3. Skipping saves ~50-200ns per busy loop (avoids queue iteration)
        //   4. RTO is 200ms; 1024 loops at ~100ns = ~100us, negligible vs RTO
        //   5. Simple loop counter avoids rdtsc() overhead
        //
        loops_since_retransmit_check++;
        if (!data_moved || loops_since_retransmit_check >= RETRANSMIT_CHECK_INTERVAL) {
            process_retransmit();
            loops_since_retransmit_check = 0;
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
        size_t linear_space = msg_inbox_->linear_space_to_wrap();

        if (linear_space < TLS_RECORD_MAX_SIZE) {
            // SAFETY CHECK: Verify AppClient has consumed past the wrap point
            // If we wrap, we'll overwrite from position 0. AppClient must not be reading there.
            //
            // ATOMICITY: We read app_consumed once and use that snapshot. The race is benign:
            // - If AppClient advances after our read, we're more conservative (safe)
            // - If AppClient was behind our snapshot, dirty_flag handles it
            uint32_t app_consumed = msg_inbox_->get_app_consumed();
            uint32_t write_pos = msg_inbox_->current_write_pos();

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
                msg_inbox_->set_dirty();
                // NOTE: We continue and overwrite - AppClient will see corrupted data
                // for this region until it catches up past the wrap point.
            }

            msg_inbox_->set_wrap_flag();
            msg_inbox_->reset_to_head();
            linear_space = msg_inbox_->linear_space_to_wrap();
        }

        uint8_t* ptr = msg_inbox_->write_ptr();
        ssize_t n = ssl_policy_.read(ptr, linear_space);
        if (n > 0) {
            // Capture SSL_read completion timestamp
            uint64_t ssl_read_cycle = rdtscp();

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
            meta.msg_inbox_offset = msg_inbox_->current_write_pos();
            meta.decrypted_len = n;
            msg_metadata_prod_->publish(meta_seq);

            // Step 2: Advance write position (data already in buffer from SSL_read)
            msg_inbox_->advance_write(n);

            // Reset timestamp state for next SSL_read batch
            has_pending_timestamps_ = false;
        } else {
            int err = ssl_policy_.get_error(n);
            if (err == SSL_ERROR_WANT_READ) break;
            handle_ssl_error(n);
        }
    }

    // Note: Ring buffer auto-cycles, no need to clear_encrypted_view() here
    // clear_encrypted_view() is only called on reconnection/shutdown
}
```

---

## TCP Retransmission (Interval-Based Check)

**Scheduling**: Retransmit check runs when idle (`!data_moved`) OR every `RETRANSMIT_CHECK_INTERVAL` (1024) loops.
This optimization saves ~50-200ns per busy loop by skipping queue iteration when network is healthy.

Retransmit processing uses the same batch publishing pattern as `process_outbound<TxType>()`:
1. First pass: Check for FATAL (max retries exceeded) and count retransmittable segments
2. Claim batch of slots upfront with `try_claim_batch()`
3. Second pass: Rebuild headers and write descriptors to claimed slots
4. Publish in TX_BATCH_SIZE chunks

### ZeroCopyRetransmitQueue API

| Method | Signature | Purpose |
|--------|-----------|---------|
| `push()` | `bool push(const RetransmitSegmentRef& ref)` | Add segment to queue |
| `for_each_expired()` | `template<typename F> size_t for_each_expired(uint64_t now_tsc, uint64_t rto_cycles, F&& callback)` | Iterate all expired segments via lambda (zero allocation) |
| `mark_retransmitted()` | `void mark_retransmitted(uint32_t seq_start, uint64_t now_tsc)` | Update send time + increment count for specific segment |
| `ack_up_to()` | `uint64_t ack_up_to(uint32_t ack_seq)` | Remove ACKed segments, return highest alloc_pos |

### Retransmit Flow

```
process_retransmit()
    │
    ├─► process_retransmit_queue(msg_retransmit_queue_, FRAME_TYPE_MSG, ...)
    │       │
    │       │  First pass (counting):
    │       ├─► for_each_expired(): Check retransmit_count < MAX_RETRANSMITS
    │       │   └─► If any segment maxed out: set has_fatal, shutdown
    │       │
    │       │  Second pass (processing each expired segment):
    │       ├─► rebuild_tcp_header_for_retransmit(&seg)
    │       │       ├─► Update TCP ACK to current rcv_nxt
    │       │       ├─► Update IP ID (fresh)
    │       │       ├─► Recalculate TCP checksum
    │       │       └─► Recalculate IP checksum
    │       ├─► Write descriptor to claimed slot
    │       ├─► mark_retransmitted(seq_start, now_tsc)
    │       ├─► publish_batch() in TX_BATCH_SIZE chunks
    │       └─► Return true to continue, false if RAW_OUTBOX full
    │
    └─► process_retransmit_queue(pong_retransmit_queue_, ...) [same logic]
```

### TCP Header Rebuild on Retransmit

When retransmitting, the original frame's TCP header may have a stale ACK number.
`rebuild_tcp_header_for_retransmit()` updates:

| Field | Update |
|-------|--------|
| TCP `ack_seq` | Current `conn_state_->rcv_nxt` |
| IP `id` | Fresh `ip_id_++` |
| TCP `check` | Recalculated (ACK changed) |
| IP `check` | Recalculated (ID changed) |

**Why rebuild?** Original ACK was captured at send time (T0). By retransmit time (T0+RTO),
we may have received more data. Fresh ACK prevents peer from unnecessary retransmits.

```cpp
void process_retransmit() {
    uint64_t now_tsc = rdtsc();
    process_retransmit_queue(msg_retransmit_queue_, FRAME_TYPE_MSG, "MSG", now_tsc);
    process_retransmit_queue(pong_retransmit_queue_, FRAME_TYPE_PONG, "PONG", now_tsc);
}

void process_retransmit_queue(ZeroCopyRetransmitQueue& queue, uint8_t frame_type,
                              const char* name, uint64_t now_tsc) {
    if (queue.empty()) return;

    // First pass: Check for FATAL and count retransmittable segments
    size_t expired_count = 0;
    bool has_fatal = false;
    queue.for_each_expired(now_tsc, rto_cycles_,
        [&](RetransmitSegmentRef& seg) -> bool {
            if (seg.retransmit_count >= ZeroCopyRetransmitQueue::MAX_RETRANSMITS) {
                fprintf(stderr, "[TRANSPORT] FATAL: %s segment seq=%u exceeded max retransmits\n",
                        name, seg.seq_start);
                has_fatal = true;
                return false;
            }
            expired_count++;
            return true;
        });

    if (has_fatal) {
        conn_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
        return;
    }
    if (expired_count == 0) return;

    // Claim batch of slots for retransmits
    auto batch_ctx = raw_outbox_prod_->try_claim_batch(expired_count);
    if (batch_ctx.count == 0) return;

    uint32_t slot_idx = 0;
    int64_t batch_start = batch_ctx.start;
    int64_t publish_lo = batch_start;

    // Second pass: Process expired segments
    queue.for_each_expired(now_tsc, rto_cycles_,
        [&](RetransmitSegmentRef& seg) -> bool {
            if (slot_idx >= batch_ctx.count) return false;

            // Rebuild TCP header with current ACK number
            rebuild_tcp_header_for_retransmit(&seg);

            // Write descriptor to pre-claimed slot
            UMEMFrameDescriptor& desc = (*raw_outbox_prod_)[batch_start + slot_idx];
            desc.umem_area_addr = static_cast<uint64_t>(seg.frame_idx) * frame_size_;
            desc.frame_len = seg.frame_len;
            desc.frame_type = frame_type;
            desc.consumed = 0;

            queue.mark_retransmitted(seg.seq_start, now_tsc);
            slot_idx++;

            // Publish chunk when reaching TX_BATCH_SIZE
            if (slot_idx % TX_BATCH_SIZE == 0) {
                raw_outbox_prod_->publish_batch(publish_lo, batch_start + slot_idx - 1);
                publish_lo = batch_start + slot_idx;
            }
            return true;
        });

    // Publish remaining
    if (slot_idx > 0 && slot_idx % TX_BATCH_SIZE != 0) {
        raw_outbox_prod_->publish_batch(publish_lo, batch_start + slot_idx - 1);
    }
}

// Rebuild TCP header with current ACK number before retransmit
void rebuild_tcp_header_for_retransmit(RetransmitSegmentRef* seg) {
    uint8_t* frame = umem_area_area_ + (seg->frame_idx * frame_size_);
    auto params = build_tcp_params();

    auto* ip_hdr = reinterpret_cast<IPv4Header*>(frame + ETH_HEADER_LEN);
    auto* tcp_hdr = reinterpret_cast<TCPHeader*>(frame + ETH_HEADER_LEN + IP_HEADER_LEN);

    // Update TCP ACK to current rcv_nxt
    tcp_hdr->ack_seq = htonl(params.rcv_nxt);

    // Update IP ID (fresh ID avoids middlebox issues)
    ip_hdr->id = htons(ip_id_++);

    // Recalculate checksums
    size_t payload_len = seg->seq_end - seg->seq_start;
    tcp_hdr->check = 0;
    tcp_hdr->check = htons(tcp_checksum(params.local_ip, params.remote_ip,
        tcp_hdr, TCP_HEADER_MIN_LEN, frame + ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_MIN_LEN, payload_len));
    ip_hdr->check = 0;
    ip_hdr->check = htons(ip_checksum(ip_hdr));
}
```

---

## Prepare Encrypted Packet (Zero-Copy TX)

```cpp
// Build ETH/IP/TCP headers and add to retransmit queue
// Zero-copy: SSL writes encrypted data directly into UMEM frame, headers built in-place
//
// @param frame_idx       Pre-allocated frame index (encrypted payload already written)
// @param encrypted_len   Length of encrypted payload already written to frame
// @param alloc_pos       Atomic alloc position for this frame type (msg or pong)
// @param rtx_queue       Retransmit queue for this frame type
//
// @return {umem_area_addr, frame_len} - caller writes descriptor to output ring
//
// DESIGN: This function does NOT write descriptors - caller handles that
//         (allows different descriptor types for MSG vs PONG)
std::pair<uint64_t, uint16_t> TransportProcess::prepare_encrypted_packet(
        uint32_t frame_idx,
        size_t encrypted_len,
        std::atomic<uint64_t>& alloc_pos,
        ZeroCopyRetransmitQueue& rtx_queue) {
    // HFT DESIGN DECISION: Abort on buffer full
    if (rtx_queue.size() >= ZeroCopyRetransmitQueue::MAX_SEGMENTS) {
        std::abort();  // Retransmit queue full - increase MAX_SEGMENTS
    }

    // ZERO-COPY: Encrypted payload already written to UMEM by SSL_write
    // Just need to build headers in-place (no payload copy)
    constexpr size_t HEADER_LEN = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_MIN_LEN;
    uint64_t umem_area_addr = frame_idx_to_addr(frame_idx, frame_size_);
    uint8_t* frame = umem_area_area_ + umem_area_addr;

    // Build ETH/IP/TCP headers in-place (payload already at offset 54)
    auto params = build_tcp_params();
    uint32_t seq_start = params.snd_nxt;

    size_t frame_len = TCPPacket::build_headers(
        frame, frame_size_, params,
        TCP_FLAG_PSH | TCP_FLAG_ACK,
        encrypted_len,
        conn_state_->local_mac, conn_state_->remote_mac,
        ip_id_++);
    if (frame_len == 0) {
        std::abort();  // build_headers() returned 0
    }

    uint32_t seq_end = seq_start + encrypted_len;

    // Update snd_nxt BEFORE adding to retransmit queue
    conn_state_->snd_nxt = seq_end;

    // Add to retransmit queue (parameterized - works for MSG or PONG)
    uint64_t alloc_pos_val = alloc_pos.load(std::memory_order_relaxed);
    uint64_t now_tsc = rdtsc();

    RetransmitSegmentRef ref;
    ref.alloc_pos = alloc_pos_val;
    ref.send_tsc = now_tsc;
    ref.frame_idx = frame_idx;
    ref.seq_start = seq_start;
    ref.seq_end = seq_end;
    ref.frame_len = static_cast<uint16_t>(frame_len);
    ref.flags = TCP_FLAG_PSH | TCP_FLAG_ACK;
    ref.retransmit_count = 0;

    if (!rtx_queue.push(ref)) {
        std::abort();  // Retransmit queue push failed
    }

    return {umem_area_addr, static_cast<uint16_t>(frame_len)};
}
```

---

## Adaptive ACK

```cpp
// Helper: Adaptive ACK logic
void TransportProcess::check_and_send_ack() {
    if (packets_since_ack_ == 0) return;

    // Check packet threshold
    if (packets_since_ack_ >= ACK_PACKET_THRESHOLD) {
        send_ack();
        return;
    }

    // Check timeout (pre-calculated ack_timeout_cycles_)
    uint64_t now = rdtsc();
    if (now - last_ack_cycle_ >= ack_timeout_cycles_) {
        send_ack();
    }
}

void TransportProcess::send_ack() {
    // ... send ACK logic ...
    packets_since_ack_ = 0;
    last_ack_cycle_ = rdtsc();
}
```

---

## ACK and Control Frame Helpers

### send_ack()
```cpp
void TransportProcess::send_ack() {
    // Allocate ACK_TX UMEM frame (position-based allocation)
    uint64_t alloc_pos = conn_state_->tx_frame.ack_alloc_pos.load(std::memory_order_relaxed);
    uint64_t release_pos = conn_state_->tx_frame.ack_release_pos.load(std::memory_order_acquire);

    if (alloc_pos - release_pos >= ACK_FRAMES) {
        std::abort();  // ACK frame pool exhausted
    }

    uint32_t frame_idx = RX_FRAMES + static_cast<uint32_t>(alloc_pos % ACK_FRAMES);
    conn_state_->tx_frame.ack_alloc_pos.fetch_add(1, std::memory_order_release);

    uint8_t* buffer = xdp_.get_frame_ptr(frame_idx);

    // Build ACK packet using stack (uses tcp_params_.rcv_nxt as ACK number)
    size_t frame_len = stack_.build_ack(buffer, FRAME_SIZE, tcp_params_);

    // Publish to ACK_OUTBOX - FATAL if full
    int64_t seq = ack_outbox_prod_->try_claim();
    if (seq < 0) std::abort();  // ACK_OUTBOX full

    auto& desc = (*ack_outbox_prod_)[seq];
    desc.umem_area_addr = xdp_.frame_idx_to_addr(frame_idx);
    desc.frame_len = static_cast<uint16_t>(frame_len);
    desc.frame_type = FRAME_TYPE_ACK;
    ack_outbox_prod_->publish(seq);
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

// NOTE: send_fin_ack() and send_fin() are NOT implemented.
// FIN/RST handling uses reconnect strategy for HFT - see "Design Decisions: Not Implemented" in architecture doc.

---

## Unified TX Template: process_outbound\<TxType\>()

Both MSG and PONG TX paths share identical logic: encrypt → build headers → add to retransmit queue.
A unified template eliminates code duplication while maintaining zero runtime overhead via `if constexpr`.

**Why separate MSG and PONG pools?**
- Control frames are low-priority but still consume TCP sequence numbers
- Separate pool prevents control frames from creating holes in MSG allocation
- Allows independent backpressure handling for control vs. data frames
- Each pool has its own retransmit queue (`msg_retransmit_queue_`, `pong_retransmit_queue_`)

### TxType Selection

| TxType | Consumer | Producer | Frame Pool | Retransmit Queue | Descriptor |
|--------|----------|----------|------------|------------------|------------|
| `MSG` | `msg_outbox_cons_` | `raw_outbox_prod_` | `allocate_msg_frame()` | `msg_retransmit_queue_` | `UMEMFrameDescriptor` |
| `PONG` | `pongs_cons_` | `pong_outbox_prod_` | `allocate_pong_frame()` | `pong_retransmit_queue_` | `UMEMFrameDescriptor` |

> **Note:** All outbox rings (RAW_OUTBOX, ACK_OUTBOX, PONG_OUTBOX) use `UMEMFrameDescriptor` for type unification with XDPPollProcess. The `frame_type` field distinguishes between ACK, PONG, and MSG frames.

### Template Implementation

```cpp
// TX types for unified template
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
    auto& alloc_pos = [this]() -> std::atomic<uint64_t>& {
        if constexpr (Type == TxType::MSG) return conn_state_->tx_frame.msg_alloc_pos;
        else return conn_state_->tx_frame.pong_alloc_pos;
    }();
    auto& rtx_queue = [this]() -> ZeroCopyRetransmitQueue& {
        if constexpr (Type == TxType::MSG) return msg_retransmit_queue_;
        else return pong_retransmit_queue_;
    }();
    constexpr const char* type_name = (Type == TxType::MSG) ? "MSG" : "PONG";

    size_t available = consumer.available();
    if (available == 0) return 0;

    // BATCHING STRATEGY:
    // 1. Claim ALL available output slots upfront with try_claim_batch(N)
    // 2. Build packets directly into pre-claimed UMEM frames
    // 3. Publish in TX_BATCH_SIZE chunks via publish_batch(lo, hi)
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
            const uint8_t* data_ptr = event.data;
            uint32_t data_len = event.data_len;

            // ZERO-COPY TX: Allocate frame FIRST (need UMEM address for output buffer)
            uint32_t frame_idx;
            if constexpr (Type == TxType::MSG) {
                frame_idx = allocate_msg_frame();
            } else {
                frame_idx = allocate_pong_frame();
            }
            if (frame_idx == UINT32_MAX) {
                fprintf(stderr, "[TRANSPORT] FATAL: %s frame pool exhausted\n", type_name);
                std::abort();
            }

            // Set output buffer to UMEM payload area BEFORE SSL_write
            constexpr size_t HEADER_LEN = ETH_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_MIN_LEN;
            uint64_t umem_area_addr = frame_idx_to_addr(frame_idx, frame_size_);
            uint8_t* frame = umem_area_area_ + umem_area_addr;
            uint8_t* payload_ptr = frame + HEADER_LEN;
            size_t payload_capacity = frame_size_ - HEADER_LEN;

            // Validate message fits in single TCP segment (no fragmentation support)
            size_t max_plaintext = payload_capacity - TLS_OVERHEAD;
            if (data_len > max_plaintext) {
                fprintf(stderr, "[FATAL] %s event too large: %u > %zu bytes\n",
                        type_name, data_len, max_plaintext);
                std::abort();
            }

            ssl_policy_.set_encrypted_output(payload_ptr, payload_capacity);

            ssize_t ret = ssl_policy_.write(data_ptr, data_len);
            if (ret <= 0) {
                fprintf(stderr, "[TRANSPORT] FATAL: SSL_write failed for %s\n", type_name);
                ssl_policy_.clear_encrypted_output();
                std::abort();
            }

            size_t encrypted_len = ssl_policy_.encrypted_output_len();
            if (encrypted_len == 0) {
                fprintf(stderr, "[TRANSPORT] FATAL: encrypted_output_len() == 0 for %s\n", type_name);
                std::abort();
            }
            ssl_policy_.clear_encrypted_output();

            // Build headers + add to retransmit queue
            auto [umem_area_addr_ret, frame_len] = prepare_encrypted_packet(
                frame_idx, encrypted_len, alloc_pos, rtx_queue);

            // Write descriptor to output ring (different descriptor types)
            int64_t out_seq = batch_start + slot_idx;
            if constexpr (Type == TxType::MSG) {
                UMEMFrameDescriptor& desc = producer[out_seq];
                desc.umem_addr = umem_addr_ret;
                desc.frame_len = frame_len;
                desc.frame_type = FRAME_TYPE_MSG;
                desc.nic_frame_poll_cycle = rdtsc();
                desc.consumed = 0;
            } else {
                // PONG uses same descriptor type for XDPPollProcess compatibility
                UMEMFrameDescriptor& desc = producer[out_seq];
                desc.umem_addr = umem_addr_ret;
                desc.frame_len = frame_len;
                desc.frame_type = FRAME_TYPE_PONG;
                desc.nic_timestamp_ns = 0;
                desc.nic_frame_poll_cycle = 0;
                desc.consumed = 0;
            }
            slot_idx++;

            // Publish chunk when reaching TX_BATCH_SIZE
            if (slot_idx % TX_BATCH_SIZE == 0) {
                int64_t publish_hi = batch_start + slot_idx - 1;
                producer.publish_batch(publish_lo, publish_hi);
                publish_lo = publish_hi + 1;
            }
            return true;
        });
    consumer.commit_manually();

    // Publish any remaining packets
    if (slot_idx > 0 && slot_idx % TX_BATCH_SIZE != 0) {
        producer.publish_batch(publish_lo, batch_start + slot_idx - 1);
    }
    return slot_idx;
}
```

### Usage

```cpp
// In main loop:
if (process_outbound<TxType::MSG>() > 0) {
    data_moved = true;
}

// When idle (no data moved):
if (!data_moved) {
    process_outbound<TxType::PONG>();
}
```

### Error Handling (Unified)

All TX errors abort immediately - no partial state:

| Error | Action |
|-------|--------|
| Output ring full | `std::abort()` |
| Frame pool exhausted | `std::abort()` |
| Message too large (> ~1973 bytes) | `std::abort()` |
| SSL_write failure | `std::abort()` |
| encrypted_output_len() == 0 | `std::abort()` |

---

## SSL Error Handling

```cpp
void TransportProcess::handle_ssl_error(int ret) {
    int err = ssl_policy_.get_error(ret);
    if (err == SSL_ERROR_ZERO_RETURN) {
        // Peer closed TLS connection
        conn_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
    } else if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
        // Fatal error
        conn_state_->running[PROC_TRANSPORT].flag.store(0, std::memory_order_release);
    }
    // SSL_ERROR_WANT_READ is handled by caller
}
```

---

## Frame Allocation Helpers

### allocate_msg_frame()

Allocates a frame from the MSG pool using atomic fetch_add with rollback pattern.

```cpp
uint32_t allocate_msg_frame() {
    // Atomically reserve a slot (fetch_add first for thread-safety)
    uint32_t pos = conn_state_->tx_frame.msg_alloc_pos.fetch_add(1, std::memory_order_relaxed);
    uint32_t rel = conn_state_->tx_frame.msg_release_pos.load(std::memory_order_acquire);

    // Check if pool is full (alloc has wrapped around to release)
    if (pos - rel >= MSG_FRAMES) {
        // Pool exhausted - rollback the allocation
        conn_state_->tx_frame.msg_alloc_pos.fetch_sub(1, std::memory_order_relaxed);
        return UINT32_MAX;  // Indicates allocation failure
    }

    // FRAME INDEX DERIVATION: position → frame_idx
    // Transport allocates frames sequentially within the MSG pool.
    // frame_idx = POOL_BASE + (position % POOL_SIZE)
    return MSG_POOL_START + (pos % MSG_FRAMES);
}
```

**Pattern: Add-Check-Rollback**
- `fetch_add(1)` atomically reserves a slot
- Check if slot is valid (within pool capacity)
- `fetch_sub(1)` rolls back if invalid

This pattern is safer than Load-Check-Add because the atomic increment prevents race conditions where two callers could reserve the same slot.

### allocate_ack_frame() / allocate_pong_frame()

Same pattern as `allocate_msg_frame()`, but for ACK and PONG pools:

```cpp
uint32_t allocate_ack_frame() {
    uint32_t pos = conn_state_->tx_frame.ack_alloc_pos.fetch_add(1, std::memory_order_relaxed);
    // ... same pattern, returns RX_FRAMES + (pos % ACK_FRAMES)
}

uint32_t allocate_pong_frame() {
    uint32_t pos = conn_state_->tx_frame.pong_alloc_pos.fetch_add(1, std::memory_order_relaxed);
    // ... same pattern, returns RX_FRAMES + ACK_FRAMES + (pos % PONG_FRAMES)
}
```

---

## Other Helpers

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
    conn_state_->tx_frame.msg_acked_pos.store(acked_pos, std::memory_order_release);
}
```

### set_pong_acked_pos()
```cpp
// Set PONG acked position when TCP ACK received (cumulative ACK)
// NOTE: TCP ACKs are cumulative - simply advance the acked position
void TransportProcess::set_pong_acked_pos(uint64_t acked_pos) {
    conn_state_->tx_frame.pong_acked_pos.store(acked_pos, std::memory_order_release);
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

// ZeroCopyRetransmitQueue - Fixed-size circular array (no heap allocation)
// "ZeroCopy" emphasizes we store references (frame indices), not data copies
class ZeroCopyRetransmitQueue {
public:
    static constexpr size_t MAX_SEGMENTS = MSG_FRAMES;  // Match TX frame pool size
    static constexpr uint8_t MAX_RETRANSMITS = 5;       // Connection dead after this many retries
private:
    RetransmitSegmentRef segments_[MAX_SEGMENTS];       // Fixed-size circular buffer
    size_t head_ = 0;                                   // Pop from here
    size_t tail_ = 0;                                   // Push to here
    size_t count_ = 0;                                  // Current number of entries
    uint64_t last_acked_pos_ = 0;                       // Track highest acked FRAME POSITION

public:
    // Add frame reference for potential retransmit (NO memcpy of payload)
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
    //
    // Returns false if queue is full (should abort - indicates misconfiguration)
    bool push(uint64_t alloc_pos, uint32_t frame_idx, uint32_t seq,
              uint16_t payload_len, uint16_t frame_len, uint8_t flags) {
        size_t next_tail = (tail_ + 1) % MAX_SEGMENTS;
        if (next_tail == head_) {
            return false;  // Queue full
        }
        RetransmitSegmentRef& ref = segments_[tail_];
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
        tail_ = next_tail;
        count_++;
        return true;
    }

    // Process cumulative ACK: Remove all segments with seq_end <= ack_seq
    // Returns the highest alloc_pos that was ACKed (for frame release)
    // TCP ACKs are cumulative: ACK=X means all bytes with seq < X have been received
    uint64_t ack_up_to(uint32_t ack_seq) {
        while (head_ != tail_) {
            RetransmitSegmentRef& seg = segments_[head_];
            // TCP sequence comparison with wraparound
            int32_t diff = static_cast<int32_t>(ack_seq - seg.seq_end);
            if (diff >= 0) {
                // This segment is fully ACKed
                if (seg.alloc_pos + 1 > last_acked_pos_) {
                    last_acked_pos_ = seg.alloc_pos + 1;
                }
                head_ = (head_ + 1) % MAX_SEGMENTS;
                count_--;
            } else {
                break;  // This segment not fully ACKed, stop here
            }
        }
        return last_acked_pos_;
    }

    // Iterate ALL expired segments via lambda callback (zero allocation)
    // Lambda signature: bool(RetransmitSegmentRef& seg) - return false to stop iteration
    // Returns number of segments processed
    template<typename Func>
    size_t for_each_expired(uint64_t now_tsc, uint64_t rto_cycles, Func&& callback) {
        if (head_ == tail_) return 0;

        size_t processed = 0;
        size_t idx = head_;
        size_t remaining = count_;

        while (remaining > 0) {
            RetransmitSegmentRef& seg = segments_[idx];
            if (now_tsc - seg.send_tsc >= rto_cycles) {
                if (!callback(seg)) break;  // Callback requested stop
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

    bool empty() const { return head_ == tail_; }
    size_t size() const { return count_; }
    void clear() { head_ = 0; tail_ = 0; count_ = 0; }
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

**Reference**: Both implementations now use fixed-size circular arrays (no `std::deque`):
- `src/stack/tcp/tcp_retransmit.hpp`: Simpler API with `add_ref()`, `remove_acked()` returning count
- `src/pipeline/transport_process.hpp`: Extended API with `push()`, `ack_up_to()` tracking allocation positions for the position-based release mechanism

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
| MSG_METADATA_INBOX full | `std::abort()` - Upstream process not keeping up |
| TX frame allocator empty | `std::abort()` - Out of TX frames |
| Too many retransmits | Set `conn_state_->running[PROC_TRANSPORT].flag = 0` - Connection failed |

---

## Future Improvements (TODO)

### FIN/RST Handling

**Current Status**: FIN/RST handling is **intentionally not implemented** in `transport_process.hpp`.

**Known Limitation**:
- Peer's FIN or RST packets are ignored
- No graceful TCP close handshake (FIN → FIN-ACK → ACK)
- Connection termination relies on process shutdown or reconnection

**Rationale for HFT**:
- Fast reconnection is prioritized over graceful close
- When connection fails, HFT apps need to reconnect immediately
- Handling FIN/RST adds complexity without latency benefit
- Process termination cleans up all resources anyway
- Connection close events are rare (server maintenance, network issues)
- Reconnection will restore state - no persistent data loss

**If FIN/RST handling is needed**, implement:
1. TCPState enum: ESTABLISHED, CLOSE_WAIT, LAST_ACK, FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT, CLOSED
2. FIN handling: rcv_nxt++, send FIN-ACK, transition to CLOSE_WAIT, send our FIN, transition to LAST_ACK
3. RST handling: immediately set is_running=false and stop processing
4. LAST_ACK state: wait for peer's ACK of our FIN before fully closing

---

## Key Design Decisions Summary

This section consolidates the key design decisions made for Transport Process, with rationale for HFT requirements.

### 1. Circular Array vs std::deque for Retransmit Queue

**Decision**: Use fixed-size circular array (`ZeroCopyRetransmitQueue`) instead of `std::deque`.

**Rationale**:
- **No heap allocation**: Circular array is stack-allocated, avoiding malloc/free latency spikes
- **Cache locality**: Contiguous memory layout improves cache performance
- **Predictable memory**: Fixed size prevents memory fragmentation
- **HFT requirement**: Deterministic latency is critical; dynamic allocation introduces jitter

### 2. process_manually() vs try_consume() Ring API

**Decision**: Use `process_manually()` + `commit_manually()` (disruptor pattern) in main loop instead of `try_consume()`.

**Rationale**:
- **Batched commits**: Single atomic operation to commit multiple consumed items
- **Reduced atomics**: `try_consume()` does atomic per item; `commit_manually()` batches
- **Disruptor pattern**: Industry-proven for high-throughput message passing
- **Exception**: Handshake code still uses `try_consume()` (one packet at a time, not latency-critical)

### 3. Raw UMEM Pointer vs XDP Interface Wrapper

**Decision**: Use raw `umem_area_` pointer + `frame_size_` instead of `XDPTransport&` reference.

**Rationale**:
- **Simplicity**: Transport only needs to read/write frame data, not manage XDP sockets
- **Decoupling**: Transport doesn't depend on XDP implementation details
- **Minimal interface**: `frame_idx_to_addr(idx, frame_size_)` is all that's needed
- **Cross-process**: UMEM is shared memory; pointer works after fork

### 4. No FIN/RST Handling

**Decision**: Intentionally skip TCP FIN/RST state machine implementation.

**Rationale**:
- **Reconnect strategy**: HFT apps reconnect immediately on any failure
- **Rare events**: Connection close is infrequent (server maintenance, network issues)
- **No data loss**: Reconnection restores state; no persistent impact
- **Complexity avoided**: TCP close state machine adds code without latency benefit

### 5. SSL Policy Abstraction with Explicit BIO Members

**Decision**: Use `SSLPolicy` template parameter for abstraction, but expose `bio_in_`/`bio_out_` members for OpenSSL/LibreSSL.

**Rationale**:
- **Library flexibility**: Policy pattern supports OpenSSL, LibreSSL, WolfSSL, NoSSL
- **Visibility**: Explicit BIO pointers make memory BIO flow clear in class definition
- **Debugging**: Easier to inspect BIO state during development
- **Conditional**: BIO members only present for libraries that use them (not WolfSSL)

### 6. First and Latest Timestamp Tracking

**Decision**: Track both `first_raw_poll_cycle_` and `latest_raw_poll_cycle_` for Transport timestamps.

**Rationale**:
- **Batch analysis**: First and latest timestamps enable batch timing analysis
- **Latency breakdown**: First packet timing useful for understanding batch start
- **Consistency**: Matches first/latest pattern used for NIC and XDP Poll timestamps

### 7. Lambda-Based Retransmit Iteration

**Decision**: Use `for_each_expired()` with lambda callback instead of returning `std::vector<RetransmitSegmentRef*>`.

**Rationale**:
- **Zero allocation**: Lambda iterates in-place with no heap allocation
- **HFT hot path**: Retransmit check runs every loop iteration; must be allocation-free
- **Early termination**: Lambda can return false to stop iteration (e.g., RAW_OUTBOX full)
- **Flexibility**: Caller decides what to do with each segment without intermediate collection

### 8. TCP Header Rebuild on Retransmit

**Decision**: Rebuild TCP ACK field and checksums at retransmit time with `rebuild_tcp_header_for_retransmit()`.

**Rationale**:
- **Fresh ACK**: Original ACK was captured at send time (T0). By retransmit time (T0+RTO), we may have received more data. Fresh ACK prevents peer from unnecessary retransmits.
- **Fresh IP ID**: Avoids potential middlebox/firewall duplicate detection issues
- **Minimal overhead**: Only updates ACK (4 bytes), IP ID (2 bytes), and recalculates checksums
- **Alternative rejected**: Storing `rcv_nxt` snapshot in `RetransmitSegmentRef` would still use stale ACK if peer sends more data after original send

### 9. Two-Pass Retransmit Processing

**Decision**: Use two passes in `process_retransmit_queue()`: first count expired segments, then process them.

**Rationale**:
- **Exact batch claim**: Know exact number of slots needed before claiming
- **FATAL check first**: If any segment has maxed retries, shutdown before claiming any slots (avoids leaked claimed-but-not-published slots)
- **Consistency**: Same pattern as `process_outbound<TxType>()` for batch publishing
- **Trade-off accepted**: Double iteration is O(2n) but n is typically small (few expired segments)
