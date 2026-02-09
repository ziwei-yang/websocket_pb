# Auto-Reconnect Architecture

## Overview

When `-DENABLE_RECONNECT` is set, both Transport and WebSocket processes use non-blocking state machines to handle initial connection and reconnection through the same code path. The surviving connection never stalls during a reconnect cycle.

Gated by `AutoReconnect` template parameter. When disabled, connections use blocking handshake and any failure is fatal.

## Design Principles

1. **Transport is protocol-agnostic** -- handles TCP+TLS only, notifies WS of state changes via events
2. **WS owns all WS-level logic** -- HTTP upgrade, subscription, watchdog
3. **Non-blocking state machines** in both processes -- surviving connection processes normally in the same loop iteration
4. **Unified connect/reconnect** -- initial connection uses the same state machine as reconnection, tested from first boot

## Inter-Process Communication

### Events: Transport to WS (via MSG_METADATA ring)

Transport publishes control events on the existing `MSG_METADATA[ci]` ring by setting `event_type`:

```cpp
enum class MetaEventType : uint8_t {
    DATA = 0,               // Normal SSL-decrypted data (default)
    TCP_DISCONNECTED = 1,   // Connection ci died
    TLS_CONNECTED = 2,      // TLS handshake complete, ready for HTTP upgrade
};

struct MsgMetadata {
    // ... timestamps, offsets ...
    uint8_t event_type;     // MetaEventType
};
```

WS always consumes metadata for ALL connections. Control events have `decrypted_len == 0` and trigger state transitions.

### Signals: WS to Transport (via ConnStateShm atomics)

```cpp
// In ConnStateShm (shared memory between all processes)
struct {
    std::atomic<bool> reconnect_request[2];   // WS -> Transport: "please reconnect ci"
    std::atomic<bool> ws_handshake_done[2];   // WS -> Transport: "switch to direct decrypt"
} conn_reconnect;
```

| Signal | Writer | Reader | Meaning |
|--------|--------|--------|---------|
| `reconnect_request[ci]` | WS | Transport | WS detected failure (watchdog/CLOSE), requests reconnect |
| `ws_handshake_done[ci]` | WS | Transport | HTTP 101 + subscription done, extract TLS keys |

### Data: WS to Transport (via MSG_OUTBOX ring)

WS sends HTTP upgrade requests and subscription messages through the `MSG_OUTBOX` ring. Transport reads and forwards via `ssl_[ci].write()`.

## State Machines

### Transport: ConnPhase (per-connection)

**File:** `src/pipeline/10_tcp_ssl_process.hpp`

```
               ACTIVE
              /      \
   failure   /        \  ws_handshake_done[ci]
  detected  /          \ extract TLS keys
           v            \
    +--------------+     \
    |TCP_CONNECTING|      |
    | (SYN sent)   |      |
    +------+-------+      |
           |               |
    SYN-ACK received       |
           |               |
    +------+--------+      |
    |TLS_HANDSHAKING|      |
    | (wolfSSL      |      |
    |  step calls)  |      |
    +------+--------+      |
           |               |
    TLS complete           |
    publish TLS_CONNECTED  |
           |               |
    +------+-----+         |
    | TLS_READY  |---------+
    | (wolfSSL   |
    |  read mode)|
    +------------+

  On error at any reconnect phase:

    +---------------+     backoff elapsed
    | WAITING_RETRY |──────────────────► start_reconnect_from_tcp(ci)
    | (exp backoff) |                     → TCP_CONNECTING (or WAITING_RETRY again)
    +---------------+
          ^
          |  SYN alloc fail, TLS init fail, timeout
          +--- from TCP_CONNECTING, TLS_HANDSHAKING, start_reconnect
```

```cpp
enum class ConnPhase : uint8_t {
    ACTIVE = 0,          // Direct AES-CTR decrypt -> msg_metadata
    TCP_CONNECTING,      // SYN sent, waiting for SYN-ACK
    TLS_HANDSHAKING,     // wolfSSL_connect() in progress (non-blocking steps)
    TLS_READY,           // TLS done, reading via wolfSSL for WS handshake
    WAITING_RETRY,       // Error occurred, waiting for backoff before retry
};

struct ReconnectCtx {
    ConnPhase phase = ConnPhase::TCP_CONNECTING;
    uint32_t attempts = 0;
    uint64_t phase_start_cycle = 0;
    uint64_t last_attempt_cycle = 0;
};
ReconnectCtx reconn_[NUM_CONN];
```

### WebSocket: WsConnPhase (per-connection)

**File:** `src/pipeline/20_ws_process.hpp`

```
    DISCONNECTED
         |
    TLS_CONNECTED event
    send HTTP upgrade
         |
    WS_UPGRADE_SENT
    (accumulate HTTP)
         |
    HTTP 101 received
    send subscription
    signal ws_handshake_done
         |
       ACTIVE
    (WS frame parsing)
         |
    TCP_DISCONNECTED event
         |
    DISCONNECTED  (cycle repeats)
```

```cpp
enum class WsConnPhase : uint8_t {
    ACTIVE = 0,
    DISCONNECTED,
    WS_UPGRADE_SENT,
};
WsConnPhase ws_phase_[NUM_CONN];
```

## Three Reconnection Triggers

### 1. TCP-level failure (Transport detects)

Transport's `PacketTransport` sets `reconnect_needed_` when it receives TCP RST, FIN, or retransmit exhaustion.

```
transport.hpp:
  process_tcp() detects RST/FIN → reconnect_needed_ = true

10_tcp_ssl_process.hpp:385-389:
  if (reconn_[ci].phase == ACTIVE && conn.needs_reconnect()) {
      conn.clear_reconnect_flag();
      start_reconnect(ci);
  }
```

### 2. WS watchdog timeout (WS detects)

Dual-condition: server PING missing AND 3 consecutive client PINGs unanswered.

```
20_ws_process.hpp:1370-1391:
  if (server_ping_missing_ && server_pong_missing_) {
      conn_state_->set_reconnect_request(watchdog_ci);   // WS -> Transport
      reset_watchdog_state();
  }

10_tcp_ssl_process.hpp:378-381:
  if (reconn_[ci].phase == ACTIVE && conn_state_->get_reconnect_request(ci)) {
      conn_state_->clear_reconnect_request(ci);
      start_reconnect(ci);
  }
```

### 3. WS CLOSE frame (WS detects)

Server sends a WebSocket CLOSE frame.

```
20_ws_process.hpp:1288-1292:
  if constexpr (AutoReconnect) {
      conn_state_->set_reconnect_request(ci);  // WS -> Transport
  }
```

## Full Reconnection Sequence

```
 Transport (Core 4)                ConnStateShm              WS (Core 6)
      |                            (shared mem)                   |
      |                                 |                         |
 --- Failure Detected ----------------------------------------------------------
      |                                 |                         |
  start_reconnect(ci)                   |                         |
  |  publish_control_event(ci,          |                         |
  |    TCP_DISCONNECTED)  ─────────────►|──── MSG_METADATA ──────►|
  |                                     |                  on_tcp_disconnected(ci)
  |  ssl_[ci].shutdown()                |                  |  ws_phase = DISCONNECTED
  |  transport.reset_for_reconnect()    |                  |  reset parse state
  |  rc = initiate_reconnect()          |                  |  pause watchdog (if ci==0)
  |    (cached IP → new port → SYN)     |                  |  drain stale DATA events
  |  phase = (rc==0) ? TCP_CONNECTING   |                         |
  |                  : WAITING_RETRY    |                         |
  |                                     |                         |
 --- TCP Handshake -------------------------------------------------------------
      |                                 |                         |
  step_tcp_connect(ci)                  |                         |
  |  poll() processes SYN-ACK           |                         |
  |  set_connected()                    |                         |
  |  if (ssl_[ci].init() != 0 ||       |                         |
  |      ssl_[ci].prepare_handshake()   |                         |
  |      != 0) → WAITING_RETRY         |                         |
  |  else → phase = TLS_HANDSHAKING    |                         |
      |                                 |                         |
 --- TLS Handshake -------------------------------------------------------------
      |                                 |                         |
  step_tls_handshake(ci)                |                         |
  |  (multiple iterations of            |                         |
  |   ssl_[ci].step_handshake())        |                         |
  |  publish_control_event(ci,          |                         |
  |    TLS_CONNECTED) ─────────────────►|──── MSG_METADATA ──────►|
  |  phase = TLS_READY                  |                  on_tls_connected(ci)
  |                                     |                  |  send_http_upgrade(ci)
  |                                     |                  |    via MSG_OUTBOX ──►|
 --- WS Handshake --------------------------------------------------------------
      |                                 |                         |
  process_ssl_read_wolfssl(ci)          |                  ws_phase = WS_UPGRADE_SENT
  |  reads via wolfSSL                  |                         |
  |  publishes DATA events ────────────►|──── MSG_METADATA ──────►|
  |                                     |                  on_http_response_data(ci)
  process_msg_outbox()                  |                  |  accumulate HTTP bytes
  |  reads HTTP upgrade from ◄──────────|◄── MSG_OUTBOX ──┘      |
  |  MSG_OUTBOX, sends via              |                         |
  |  ssl_[ci].write()                   |                         |
  |                                     |                  HTTP 101 complete:
  |                                     |                  |  validate_http_upgrade()
  |                                     |                  |  send_subscription(ci)
  |                                 ┌───|◄─────────────────|
  |                                 |ws_handshake_done[ci] |  ws_phase = ACTIVE
  |                                 |= true                |  reset watchdog (if ci==0)
  |                                 └───|                  |  signal ws_ready (startup)
      |                                 |                         |
 --- Switch to Fast Path -------------------------------------------------------
      |                                 |                         |
  switch_to_direct_decrypt(ci)          |                         |
  |  ssl_[ci].extract_record_keys()     |                  Normal WS frame parsing
  |  conn.set_tls_record_keys()         |                  Watchdog active (ci==0)
  |  conn.stop_rx_trickle_thread()      |                         |
  |  reconn_[ci].reset()                |                         |
  |  phase = ACTIVE                     |                         |
      |                                 |                         |
  Direct AES-CTR decrypt ──────────────►|──── MSG_METADATA ──────►|
  (bypass wolfSSL, hot path)            |                  on_ws_data(ci)
```

## Transport Process Code Paths

### start_reconnect(ci)

`10_tcp_ssl_process.hpp:578-602`

Called when any trigger detects failure. Publishes `TCP_DISCONNECTED` event, tears down SSL, resets TCP, sends SYN. On SYN allocation failure, enters `WAITING_RETRY` instead of crashing.

```cpp
void start_reconnect(uint8_t ci) {
    publish_control_event(ci, MetaEventType::TCP_DISCONNECTED);
    ssl_[ci].shutdown();

    int rc;
    if constexpr (EnableAB) {
        rc = transport_.start_reconnect(ci);   // returns 0 or -1
    } else {
        transport_.reset_for_reconnect();
        rc = transport_.initiate_reconnect();   // returns 0 or -1
    }

    reconn_[ci].phase = (rc == 0) ? ConnPhase::TCP_CONNECTING : ConnPhase::WAITING_RETRY;
    reconn_[ci].phase_start_cycle = rdtsc();
    reconn_[ci].attempts++;
    reconn_[ci].last_attempt_cycle = rdtsc();
}
```

### step_tcp_connect(ci)

`10_tcp_ssl_process.hpp:604-641`

Non-blocking: checks `handshake_complete()` each iteration. On success, prepares TLS (checking return codes). On TLS init failure, enters `WAITING_RETRY`. On timeout (5s), restarts with backoff.

```cpp
void step_tcp_connect(uint8_t ci) {
    if (conn.handshake_complete()) {
        conn.set_connected();

        // Prepare TLS — check return codes (no exceptions)
        if (ssl_[ci].init() != 0 ||
            ssl_[ci].prepare_handshake(&conn, hostname) != 0) {
            fprintf(stderr, "[RECONNECT] TLS init failed for conn %u, restarting\n", ci);
            if (should_backoff(ci)) {
                reconn_[ci].phase = ConnPhase::WAITING_RETRY;
                return;
            }
            start_reconnect_from_tcp(ci);
            return;
        }
        phase = TLS_HANDSHAKING;
        return;
    }
    if (elapsed > 5s) {
        if (should_backoff(ci)) return;
        start_reconnect_from_tcp(ci);
    }
}
```

### step_tls_handshake(ci)

`10_tcp_ssl_process.hpp:620-663`

Calls `ssl_[ci].step_handshake()` once per loop iteration. Returns `IN_PROGRESS`, `SUCCESS`, or `ERROR`.

```cpp
void step_tls_handshake(uint8_t ci) {
    auto result = ssl_[ci].step_handshake();  // Single wolfSSL_connect() call

    if (result == SUCCESS) {
        publish_control_event(ci, MetaEventType::TLS_CONNECTED);
        phase = TLS_READY;
    } else if (result == ERROR || timeout(5s)) {
        start_reconnect_from_tcp(ci);  // Restart from TCP
    }
    // IN_PROGRESS: do nothing, retry next iteration
}
```

### TLS_READY phase

`10_tcp_ssl_process.hpp:401-408`

Reads via wolfSSL (not direct decrypt) and publishes DATA events. Checks `ws_handshake_done[ci]` each iteration.

```cpp
case ConnPhase::TLS_READY:
    process_ssl_read_wolfssl(ci, timing);   // wolfSSL read → msg_metadata
    if (conn_state_->get_ws_handshake_done(ci)) {
        conn_state_->clear_ws_handshake_done(ci);
        switch_to_direct_decrypt(ci);       // Extract keys → ACTIVE
    }
    break;
```

### switch_to_direct_decrypt(ci)

`10_tcp_ssl_process.hpp:670-689`

Extracts TLS record keys from wolfSSL session, enables direct AES-CTR decryption (bypasses wolfSSL for the hot data path), resets reconnect context.

```cpp
void switch_to_direct_decrypt(uint8_t ci) {
    TLSRecordKeys tls_keys;
    if (ssl_[ci].extract_record_keys(tls_keys)) {
        conn.set_tls_record_keys(tls_keys);     // Enable direct AES-CTR
    }
    conn.stop_rx_trickle_thread();
    conn.reset_hw_timestamps();
    reconn_[ci].reset();                          // phase → ACTIVE, attempts → 0
}
```

### start_reconnect_from_tcp(ci)

`10_tcp_ssl_process.hpp:717-729`

Lightweight restart: shuts down SSL, sends new SYN (no TCP_DISCONNECTED event — WS is already DISCONNECTED). Used by timeout paths and `WAITING_RETRY` recovery.

```cpp
void start_reconnect_from_tcp(uint8_t ci) {
    ssl_[ci].shutdown();
    int rc;
    if constexpr (EnableAB) {
        rc = transport_.start_reconnect(ci);
    } else {
        transport_.reset_for_reconnect();
        rc = transport_.initiate_reconnect();
    }
    reconn_[ci].phase = (rc == 0) ? ConnPhase::TCP_CONNECTING : ConnPhase::WAITING_RETRY;
    reconn_[ci].phase_start_cycle = rdtsc();
    reconn_[ci].last_attempt_cycle = rdtsc();
}
```

### Transport Main Loop

`10_tcp_ssl_process.hpp:353-453`

```cpp
while (running_) {
    transport_.poll();           // Demuxed RX for ALL connections (always runs)
    process_msg_outbox();        // High-priority WS→Transport messages

    for (uint8_t ci = 0; ci < NUM_CONN; ci++) {
        // Check WS-initiated reconnect request
        if (phase == ACTIVE && conn_state_->get_reconnect_request(ci)) {
            start_reconnect(ci);
        }
        // Check transport-level TCP failure
        if (phase == ACTIVE && transport(ci).needs_reconnect()) {
            start_reconnect(ci);
        }

        switch (reconn_[ci].phase) {
            TCP_CONNECTING:   step_tcp_connect(ci);
            TLS_HANDSHAKING:  step_tls_handshake(ci);
            TLS_READY:        process_ssl_read_wolfssl(ci);
                              check ws_handshake_done → switch_to_direct_decrypt
            WAITING_RETRY:    if (!should_backoff(ci))
                                  start_reconnect_from_tcp(ci);
            ACTIVE:           process_ssl_read_for_conn(ci);
        }
    }

    process_low_prio_outbox();   // PONGs, client PINGs
}
```

## WebSocket Process Code Paths

### Event Dispatcher

`20_ws_process.hpp:732-769`

All metadata is consumed every iteration for every connection. The dispatcher routes based on `event_type` and `ws_phase_[ci]`:

```cpp
void on_event(uint8_t ci, MsgMetadata& meta, ...) {
    auto event_type = static_cast<MetaEventType>(meta.event_type);

    // Control events
    if (event_type == TCP_DISCONNECTED) { on_tcp_disconnected(ci); return; }
    if (event_type == TLS_CONNECTED)    { on_tls_connected(ci);    return; }

    // Data events — routed by connection phase
    if (ws_phase_[ci] == DISCONNECTED)    return;              // drain stale
    if (ws_phase_[ci] == WS_UPGRADE_SENT) { on_http_response_data(ci, meta); return; }

    on_ws_data(ci, meta);   // ACTIVE: normal WS frame parsing
}
```

### on_tcp_disconnected(ci)

`20_ws_process.hpp:775-795`

Resets all per-connection state. Pauses watchdog when conn 0 disconnects.

```cpp
void on_tcp_disconnected(uint8_t ci) {
    ws_phase_[ci] = WsConnPhase::DISCONNECTED;
    parse_state_[ci] = PerConnParseState{};
    has_pending_frame_[ci] = false;
    pending_frame_[ci].clear();
    has_pending_ping_[ci] = false;
    reset_accumulator(ci);
    reset_fragment_state(ci);
    http_response_[ci].clear();

    if (ci == 0) reset_watchdog_state();
}
```

### on_tls_connected(ci)

`20_ws_process.hpp:797-806`

Sends HTTP upgrade request via `MSG_OUTBOX` and transitions to `WS_UPGRADE_SENT`.

```cpp
void on_tls_connected(uint8_t ci) {
    send_http_upgrade_request(ci);
    ws_phase_[ci] = WsConnPhase::WS_UPGRADE_SENT;
    http_response_[ci].clear();
}
```

### on_http_response_data(ci, meta)

`20_ws_process.hpp:808-879`

Non-blocking HTTP response accumulation. Replaces the old blocking `recv_http_upgrade_response()`.

```cpp
void on_http_response_data(uint8_t ci, MsgMetadata& meta) {
    // Append decrypted bytes to HTTP response buffer
    auto& resp = http_response_[ci];
    memcpy(resp.buffer + resp.accumulated, data, len);
    resp.accumulated += len;

    if (!resp.try_complete()) return;     // Need more data (\r\n\r\n not found)

    if (!validate_http_upgrade_response(resp.buffer, resp.accumulated)) {
        // HTTP upgrade failed — request full reconnect
        ws_phase_[ci] = DISCONNECTED;
        conn_state_->set_reconnect_request(ci);
        return;
    }

    // Success: send subscription, signal Transport, go ACTIVE
    send_subscription_message(ci);
    conn_state_->set_ws_handshake_done(ci);    // → Transport extracts TLS keys
    ws_phase_[ci] = WsConnPhase::ACTIVE;

    if (ci == 0) reset_watchdog_state();       // Resume watchdog

    // Signal ws_ready when ALL connections reach ACTIVE (startup only)
    if (!ws_ready_signaled_ && all_connections_active())
        conn_state_->set_handshake_ws_ready();
}
```

### handle_close(ci) — CLOSE frame triggers reconnect

`20_ws_process.hpp:1288-1292`

```cpp
if constexpr (AutoReconnect) {
    conn_state_->set_reconnect_request(ci);
} else {
    conn_state_->shutdown_all();     // Fatal in non-reconnect mode
}
```

### Watchdog triggers reconnect

`20_ws_process.hpp:1384-1386`

```cpp
if constexpr (AutoReconnect) {
    conn_state_->set_reconnect_request(watchdog_ci);
    reset_watchdog_state();
}
```

## Startup Flow (Same State Machine)

Initial connection uses the exact same code path as reconnection:

```
TransportProcess::init():
    for each conn ci:
        transport.initiate_connect(host, port)   // DNS + SYN
        reconn_[ci].phase = TCP_CONNECTING

TransportProcess::run():
    // All connections start in TCP_CONNECTING
    // Same state machine handles: SYN-ACK → TLS → TLS_CONNECTED event → TLS_READY

WebSocketProcess::init():
    for each conn ci:
        ws_phase_[ci] = WsConnPhase::DISCONNECTED

WebSocketProcess::run():
    // All connections start DISCONNECTED
    // Consumes metadata, waits for TLS_CONNECTED → HTTP upgrade → subscribe → ACTIVE
```

This means reconnection logic is tested from the very first connection attempt.

## Backoff Strategy

`10_tcp_ssl_process.hpp:735-742`

Exponential backoff between retry cycles, applied when TCP connect or TLS handshake times out, or when SYN allocation / TLS init fails:

```
Attempt 1:  1s     (1000ms << 0)
Attempt 2:  2s     (1000ms << 1)
Attempt 3:  4s     (1000ms << 2)
Attempt 4:  8s     (1000ms << 3)
Attempt 5:  16s    (1000ms << 4)
Attempt 6+: 30s    (capped at RECONNECT_BACKOFF_MAX_MS)
```

Reset to 0 when connection reaches ACTIVE (`reconn_[ci].reset()`).

```cpp
bool should_backoff(uint8_t ci) {
    uint32_t backoff_ms = RECONNECT_BACKOFF_BASE_MS << min(attempts - 1, 4u);
    if (backoff_ms > RECONNECT_BACKOFF_MAX_MS) backoff_ms = RECONNECT_BACKOFF_MAX_MS;
    uint64_t backoff_cycles = backoff_ms * (tsc_freq_hz_ / 1000);
    return (rdtsc() - reconn_[ci].last_attempt_cycle < backoff_cycles);
}
```

## TLS_READY Phase: Why wolfSSL Before Direct Decrypt

After TLS handshake completes, Transport cannot immediately use direct AES-CTR decryption because:

1. Direct decrypt requires extracting TLS session keys from wolfSSL internals
2. Extracting keys must happen AFTER all wolfSSL I/O is done (HTTP upgrade goes through wolfSSL)
3. WS needs to complete its HTTP upgrade + subscription through wolfSSL first

So `TLS_READY` is a transitional phase:
- Transport reads via `ssl_[ci].read()` (wolfSSL) instead of direct decrypt
- Transport writes via `ssl_[ci].write()` for outbound MSG_OUTBOX data
- When WS signals `ws_handshake_done[ci]`, Transport extracts keys and switches to direct AES-CTR

## Non-Blocking Guarantee

The surviving connection never stalls because:

1. **Transport**: `poll()` always runs for ALL connections (demuxed). The reconnecting connection's state machine runs in the same loop iteration — just a different `switch` branch.

2. **WebSocket**: Metadata is always consumed for ALL connections. `DISCONNECTED` phase drains stale data (prevents ring backup). `WS_UPGRADE_SENT` accumulates HTTP response. The active connection's `on_ws_data()` runs in the same iteration.

3. **No blocking calls**: `step_tcp_connect()` checks `handshake_complete()` and returns. `step_tls_handshake()` calls `wolfSSL_connect()` once and returns. `on_http_response_data()` accumulates bytes and returns. Nothing blocks.

## Summary Table

| Phase | Transport ConnPhase | Transport Action | WS WsConnPhase | WS Action |
|-------|-------------------|------------------|----------------|-----------|
| Failure | ACTIVE → start_reconnect | Publish TCP_DISCONNECTED, SYN | ACTIVE → DISCONNECTED | Reset parse, pause watchdog |
| SYN fail | → WAITING_RETRY | Backoff timer | DISCONNECTED | Drain stale data |
| TCP | TCP_CONNECTING | Check handshake_complete() | DISCONNECTED | Drain stale data |
| TLS init fail | → WAITING_RETRY | Backoff timer | DISCONNECTED | Drain stale data |
| TLS | TLS_HANDSHAKING | step_handshake() | DISCONNECTED | Drain stale data |
| TLS done | → TLS_READY | Publish TLS_CONNECTED | → WS_UPGRADE_SENT | Send HTTP upgrade |
| WS handshake | TLS_READY | wolfSSL read/write, publish DATA | WS_UPGRADE_SENT | Accumulate HTTP 101 |
| WS done | Check ws_handshake_done | Extract keys → ACTIVE | → ACTIVE | Signal ws_handshake_done |
| Normal | ACTIVE | Direct AES-CTR decrypt | ACTIVE | Parse WS frames |

## Error Handling: Return Codes Instead of Exceptions

All error paths reachable from `run()` use C-style return codes (`0` = success, `-1` = failure) instead of C++ exceptions. This ensures failures trigger retry with exponential backoff instead of crashing the pipeline.

### Converted Functions

| Function | File | Old | New | Error Response |
|----------|------|-----|-----|----------------|
| `SSLPolicy::init()` | `ssl.hpp` | `void` (threw) | `int` (returns -1) | `fprintf(stderr, ...)` |
| `SSLPolicy::prepare_handshake()` | `ssl.hpp` | `void` (threw) | `int` (returns -1) | `fprintf(stderr, ...)` |
| `SSLPolicy::handshake_userspace_transport()` | `ssl.hpp` | `void` (threw) | `int` (returns -1) | `fprintf(stderr, ...)` |
| `PacketTransport::initiate_reconnect()` | `transport.hpp` | `void` (threw) | `int` (returns -1) | `fprintf(stderr, ...)` |
| `PacketTransportAB::start_reconnect()` | `transport_ab.hpp` | `void` (threw) | `int` (returns -1) | `fprintf(stderr, ...)` |

All SSL policies (WolfSSL, OpenSSL, LibreSSL, NoSSL) implement the same `int` return type for `init()`, `prepare_handshake()`, and `handshake_userspace_transport()`.

### Callers in `run()` (non-blocking reconnect path)

- `start_reconnect()` / `start_reconnect_from_tcp()`: Check `initiate_reconnect()` return → `WAITING_RETRY` on failure
- `step_tcp_connect()`: Check `init()` and `prepare_handshake()` return → `WAITING_RETRY` on failure

### Callers in blocking init path

The blocking `connect_and_handshake()` function (pre-`run()`) checks return codes and returns `false` on failure:

```cpp
if (ssl_[ci].init() != 0) return false;
if (ssl_[ci].handshake_userspace_transport(&conn, hostname) != 0) return false;
```

### Remaining Exceptions

All remaining `throw` statements (48 total) are in pre-run blocking functions only (BSD socket connect, blocking TLS handshake, PIO initialization). None are reachable from the `run()` loop. The test binary no longer wraps `transport.run()` in a `try/catch`.
