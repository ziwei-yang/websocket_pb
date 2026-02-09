# Dual A/B Connection Architecture

## Overview

The pipeline supports running two independent TCP+TLS+WS connections (A and B) to the same exchange endpoint through a single NIC RX queue. Both connections share one `DisruptorPacketIO` instance and one XDP socket. Incoming packets are demultiplexed by TCP destination port.

Enabled at compile time with `-DENABLE_AB`, gated by `EnableAB` template parameter. When disabled, only connection 0 exists and all AB-specific code compiles away via `if constexpr`.

```
                         NIC (single RX queue)
                              |
                    XDP Poll (Core 2)
                    RAW_INBOX ring
                              |
                   Transport (Core 4)
                   PacketTransportAB<DisruptorPacketIO>
                      /              \
                 conn A              conn B
              (owns PIO)         (shares PIO)
              local_port=X       local_port=Y
                  |                   |
            MSG_INBOX[0]         MSG_INBOX[1]
            MSG_METADATA[0]      MSG_METADATA[1]
                  |                   |
                   WebSocket (Core 6)
                      /              \
                 ws_phase_[0]     ws_phase_[1]
                 parse_state_[0] parse_state_[1]
                      \              /
                     WS_FRAME_INFO ring
                           |
                     AppClient (parent)
```

## Compile-Time Gating

```cpp
// Template parameter on both processes
template<..., bool EnableAB = false, ...>
struct TransportProcess { ... };

template<..., bool EnableAB = false, ...>
struct WebSocketProcess { ... };

// Array sizing
static constexpr size_t NUM_CONN = EnableAB ? 2 : 1;
MsgInbox* msg_inbox_[NUM_CONN]{};
SSLPolicy ssl_[NUM_CONN]{};
```

Build: `make ... ENABLE_AB=1` adds `-DENABLE_AB` to CXXFLAGS.

## Transport Layer: PacketTransportAB

**File:** `src/policy/transport_ab.hpp`

`PacketTransportAB<PacketIO>` wraps two `PacketTransport<PacketIO>` instances.

### PIO Ownership

```
PacketTransportAB
  ├── a: PacketTransport  ← owns real PIO (init_with_pio_config)
  └── b: PacketTransport  ← shares a's PIO via pointer (set_shared_pio)
```

Connection A owns the `DisruptorPacketIO` (creates XDP socket, maps UMEM). Connection B gets a pointer to A's PIO. Both read from the same RAW_INBOX and write to the same RAW_OUTBOX.

### Initialization

```cpp
void init_with_pio_config(const ConfigT& config) {
    a.init_with_pio_config(config);       // Full PIO init
    b.set_shared_pio(a.get_packet_io());  // Share A's PIO
    b.init_stack_only(config);            // TCP stack only, no PIO

    // Override poll() on both to use demuxed version
    a.set_poll_override(demux_poll, this);
    b.set_poll_override(demux_poll, this);
}
```

### The Shared PIO Problem and poll_override Solution

When two `PacketTransport` share one PIO, calling `poll_rx_and_process()` on either one processes ALL frames from RAW_INBOX but only matches one connection's `local_port`. The other connection's frames get silently dropped.

**Solution:** `poll_override_` function pointer in `PacketTransport`. When set, all calls to `poll()` — including those inside `recv()` and `wait()` (used during TLS handshake) — route through the AB wrapper's demuxed poll.

```cpp
// transport.hpp
size_t poll() {
    if (poll_override_) {
        return poll_override_(poll_override_ctx_);  // → PacketTransportAB::poll()
    }
    // ... normal single-connection poll
}
```

### Demuxed Poll

`PacketTransportAB::poll()` reads all RX frames, inspects the TCP destination port at byte offset 36, and routes to the correct connection:

```cpp
size_t poll() {
    a.get_packet_io()->poll_wait();
    size_t n = a.get_packet_io()->process_rx_frames(SIZE_MAX,
        [this](uint32_t idx, PacketFrameDescriptor& desc) {
            uint8_t* pkt = (uint8_t*)desc.frame_ptr;

            // TCP dest port at ETH(14) + IP(20) + TCP_SRC(2) = offset 36
            uint16_t dst_port = ntohs(*(uint16_t*)(pkt + 36));

            if (dst_port == a.tcp_params().local_port)
                a.process_rx_frame(idx, desc);
            else if (dst_port == b.tcp_params().local_port)
                b.process_rx_frame(idx, desc);
            else
                drop(desc);  // Neither connection
        });

    a.check_retransmit();
    if (b.is_connected()) b.check_retransmit();
    return n;
}
```

Each connection has a different random `local_port` generated at connect time. The server responds to each connection's port, so demuxing by TCP dest port cleanly separates the two streams.

## Transport Process with EnableAB

**File:** `src/pipeline/10_tcp_ssl_process.hpp`

### Transport Type Selection

```cpp
using TransportType = std::conditional_t<EnableAB,
    PacketTransportAB<DisruptorPacketIO>,
    PacketTransport<DisruptorPacketIO>>;
```

### Per-Connection Resources

```cpp
static constexpr size_t NUM_CONN = EnableAB ? 2 : 1;

MsgInbox*        msg_inbox_[NUM_CONN]{};
MsgMetadataProd* msg_metadata_prod_[NUM_CONN]{};
SSLPolicy        ssl_[NUM_CONN]{};
ReconnectCtx     reconn_[NUM_CONN]{};
```

Each connection gets its own:
- `MsgInbox` (shared memory buffer for decrypted bytes)
- `MsgMetadata` producer (ring for metadata events)
- `SSLPolicy` instance (independent wolfSSL session)
- `ReconnectCtx` (state machine phase)

### get_transport Helper

```cpp
auto& get_transport(uint8_t ci) {
    if constexpr (EnableAB) {
        return transport_.transport(ci);  // Returns a or b
    } else {
        return transport_;                // Single connection
    }
}
```

### Connection Sequence (Non-Reconnect)

```
init():
    transport_.init_with_pio_config(config)   // PIO + demux setup
    transport_.start_connect(0, host, port)   // A: DNS → SYN
    blocking wait for handshake_complete(0)
    transport_.set_connected(0)
    ssl_[0].init()                                                // returns int
    ssl_[0].handshake_userspace_transport(&transport_.a, host)    // returns int
    extract TLS keys → direct AES-CTR decrypt

    transport_.start_connect(1, host, port)   // B: DNS → SYN
    blocking wait for handshake_complete(1)    // demuxed poll keeps A alive
    transport_.set_connected(1)
    ssl_[1].init()                                                // returns int
    ssl_[1].handshake_userspace_transport(&transport_.b, host)    // returns int
    extract TLS keys → direct AES-CTR decrypt
```

During B's TCP+TLS handshake, the demuxed `poll()` keeps processing A's data packets and retransmits. This is critical — without demuxed poll, A's packets would be dropped while B is connecting.

### Main Loop

```cpp
while (running_) {
    transport_.poll();             // Single demuxed poll for BOTH connections

    for (uint8_t ci = 0; ci < NUM_CONN; ci++) {
        // State machine dispatch per connection
        switch (reconn_[ci].phase) {
            ACTIVE:          process_ssl_read_for_conn(ci, timing);
            TCP_CONNECTING:  step_tcp_connect(ci);
            TLS_HANDSHAKING: step_tls_handshake(ci);
            TLS_READY:       process_ssl_read_wolfssl(ci, timing);
            WAITING_RETRY:   if (!should_backoff(ci))
                                 start_reconnect_from_tcp(ci);
        }
    }

    process_msg_outbox();         // WS → Transport (upgrade requests, etc.)
    process_low_prio_outbox();    // PONGs, client PINGs
}
```

One `poll()` call services both connections' RX. Then each connection's state machine runs independently. An SSL read failure on B does not affect A.

### Data Publishing (per-connection)

Each connection publishes to its own `MsgInbox[ci]` + `MsgMetadata[ci]`:

```cpp
int32_t process_ssl_read_for_conn(uint8_t ci, timing_record_t& timing) {
    auto& conn = get_transport(ci);
    auto* inbox = msg_inbox_[ci];
    auto* meta_prod = msg_metadata_prod_[ci];

    // Read decrypted data into connection's inbox
    ssize_t read_len = conn.ssl_read_by_chunk(inbox->write_ptr(), ...);

    // Publish metadata event to connection's metadata ring
    publish_metadata(meta_prod, write_offset, len, timing, tls_boundary);
}
```

### Outbound Routing

`MSG_OUTBOX` and `PONGS` carry a `connection_id` field. Transport reads it to route to the correct SSL session:

```cpp
int32_t process_msg_outbox() {
    MsgOutboxEvent evt;
    while (msg_outbox_cons_->try_consume(evt)) {
        uint8_t ci = EnableAB ? evt.connection_id : 0;
        ssl_[ci].write(evt.data, evt.data_len);
    }
}
```

## WebSocket Process with EnableAB

**File:** `src/pipeline/20_ws_process.hpp`

### Per-Connection State

```cpp
static constexpr size_t NUM_CONN = EnableAB ? 2 : 1;

MsgInbox*            msg_inbox_[NUM_CONN]{};
MsgMetadataCons*     msg_metadata_cons_[NUM_CONN]{};
PerConnParseState    parse_state_[NUM_CONN]{};
PartialWebSocketFrame pending_frame_[NUM_CONN]{};
bool                 has_pending_frame_[NUM_CONN]{};
WsConnPhase          ws_phase_[NUM_CONN]{};
```

Each connection has independent:
- WS frame parser state (can be mid-frame on one, starting a new frame on the other)
- HTTP response accumulator (for handshake)
- Connection phase (ACTIVE/DISCONNECTED/WS_UPGRADE_SENT)

### Main Loop: Consuming Both Connections

```cpp
void run() {
    while (running) {
        // Always consume conn A metadata
        int32_t processed = msg_metadata_cons_[0]->process_manually(
            [this](MsgMetadata& meta, int64_t seq, bool eob) {
                on_event(0, meta, seq, eob);
                return true;
            }, MAX_ACCUMULATED_METADATA);
        if (processed > 0) msg_metadata_cons_[0]->commit_manually();

        if constexpr (EnableAB) {
            // Always consume conn B metadata
            int32_t processed_b = msg_metadata_cons_[1]->process_manually(
                [this](MsgMetadata& meta, int64_t seq, bool eob) {
                    on_event(1, meta, seq, eob);
                    return true;
                }, MAX_ACCUMULATED_METADATA);
            if (processed_b > 0) msg_metadata_cons_[1]->commit_manually();
        }

        // Ping/pong for all connections
        for (size_t ci = 0; ci < NUM_CONN; ci++) {
            if (has_pending_ping_[ci])
                flush_pending_pong(ci);
        }
        maybe_send_client_ping();  // Watchdog on conn 0
    }
}
```

Both metadata rings are consumed every iteration. No connection's ring backs up even if the other is disconnecting or reconnecting.

### Event Dispatch (ci-aware)

```cpp
void on_event(uint8_t ci, MsgMetadata& meta, ...) {
    auto event_type = static_cast<MetaEventType>(meta.event_type);

    if (event_type == TCP_DISCONNECTED)  → on_tcp_disconnected(ci);
    if (event_type == TLS_CONNECTED)     → on_tls_connected(ci);

    if (ws_phase_[ci] == DISCONNECTED)   → return;  // drain stale
    if (ws_phase_[ci] == WS_UPGRADE_SENT)→ on_http_response_data(ci, meta);

    // ACTIVE: normal WS frame parsing
    on_ws_data(ci, meta);
}
```

Each connection's events are dispatched independently. Connection A can be parsing WS frames while B is accumulating HTTP upgrade response.

### Outbound Messages: connection_id Tagging

All outbound messages include a `connection_id` so Transport routes to the correct SSL session:

```cpp
void send_http_upgrade_request(uint8_t ci) {
    auto& event = (*msg_outbox_prod_)[seq];
    memcpy(event.data, request_buf, request_len);
    event.connection_id = ci;           // Tag with connection ID
    msg_outbox_prod_->publish(seq);
}

void flush_pending_pong(uint8_t ci) {
    auto& pong = (*pongs_prod_)[pong_seq];
    pong.connection_id = ci;            // Tag with connection ID
    pongs_prod_->publish(pong_seq);
}
```

### Watchdog: conn 0 Only

The dual-condition watchdog (server PING missing + client PONG missing) monitors connection 0 only:

```cpp
void maybe_send_client_ping() {
    constexpr uint8_t watchdog_ci = 0;   // Always conn 0
    // ... send PING on conn 0, check PONG replies
}
```

If the watchdog detects conn 0 is dead, it sets `reconnect_request[0]` in shared memory. Connection 1 is not monitored by the watchdog — it relies on TCP-level failure detection in Transport.

### WSFrameInfo: connection_id for AppClient

Each `WSFrameInfo` published to AppClient carries `connection_id`:

```cpp
info.connection_id = ci;  // 0=A, 1=B
```

AppClient can use this to deduplicate messages or prefer one connection over the other.

## IPC Ring Layout (AB mode)

```
Shared Memory Layout:
  MSG_INBOX[0]       ← Transport writes conn A decrypted bytes
  MSG_INBOX[1]       ← Transport writes conn B decrypted bytes
  MSG_METADATA[0]    ← Transport publishes conn A metadata events
  MSG_METADATA[1]    ← Transport publishes conn B metadata events
  MSG_OUTBOX         ← WS publishes (shared, connection_id field routes)
  PONGS              ← WS publishes (shared, connection_id field routes)
  WS_FRAME_INFO      ← WS publishes (shared, connection_id field tags)
  ConnStateShm       ← Shared atomics for handshake/reconnect signaling
```

`MSG_INBOX` and `MSG_METADATA` are per-connection (separate rings, separate producers/consumers). `MSG_OUTBOX`, `PONGS`, and `WS_FRAME_INFO` are shared rings with a `connection_id` field for routing/tagging.

## Summary

| Aspect | Single Connection | Dual A/B |
|--------|------------------|----------|
| Transport type | `PacketTransport<PIO>` | `PacketTransportAB<PIO>` |
| PIO instances | 1 (owned) | 1 (A owns, B shares pointer) |
| RX demux | Direct `poll_rx_and_process()` | Demuxed by TCP dest port |
| `poll()` calls | 1 per loop | 1 per loop (demuxed for both) |
| SSL sessions | 1 | 2 (independent wolfSSL) |
| MSG_INBOX/METADATA | 1 ring each | 2 rings each (per-connection) |
| WS parse state | 1 | 2 (independent per-connection) |
| Watchdog | conn 0 | conn 0 only |
| Build flag | (default) | `-DENABLE_AB` |
