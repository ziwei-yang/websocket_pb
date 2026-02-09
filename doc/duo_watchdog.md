# RTT-Based Connection Preference via PING/PONG

## Context

With per-connection watchdog now implemented (each conn sends 1 PING/sec, tracks PONG), RTT is already computed in `handle_pong()` but only logged — not stored. There's no mechanism for WS process to tell Transport which connection is faster. Transport processes connections in fixed order (ci=0, ci=1) regardless of latency. The goal: WS process measures RTT per-connection, determines which is faster, and signals Transport so it can process the preferred connection first.

## Design

**RTT measurement** — Use TSC cycles (not wall-clock). Add `ping_send_cycle` to `WatchdogState` to track when each PING was sent. On PONG receipt, compute `rtt_cycles = now - ping_send_cycle`. If next PING fires before PONG arrives, set `rtt_cycles = UINT64_MAX` (unresponsive).

**Preference signal** — Add `std::atomic<uint8_t> preferred_conn_id` to `ConnStateShm`. WS process writes it. Transport reads it.

**Transport optimization** — Read `preferred_conn_id` once per loop iteration. Process that connection's SSL reads first in the per-connection loop. Also call `transport_.set_active(preferred)` to update `PacketTransportAB::active_conn_id`.

## Changes

### 1. `WatchdogState` — add RTT fields (`20_ws_process.hpp`)

```cpp
struct WatchdogState {
    // ... existing fields ...

    // RTT measurement
    uint64_t ping_send_cycle = 0;          // TSC when last client PING was sent (0 = no PING in flight)
    uint64_t rtt_cycles = UINT64_MAX;      // Latest RTT (MAX = unknown/unresponsive)
};
```

### 2. `handle_pong()` — store RTT on PONG receipt (`20_ws_process.hpp`)

After existing `wd_[ci].last_pong_recv_cycle = rdtscp();`, add:

```cpp
if (w.ping_send_cycle > 0) {
    w.rtt_cycles = w.last_pong_recv_cycle - w.ping_send_cycle;
    w.ping_send_cycle = 0;  // Mark answered
    if constexpr (EnableAB) update_preferred_connection();
}
```

### 3. `maybe_send_client_ping()` — detect unanswered PING, update RTT (`20_ws_process.hpp`)

Before sending a new PING, check if previous PONG is missing:

```cpp
// Right before "Send client PING" section:
if (w.ping_send_cycle > 0) {
    // Previous PING unanswered — set RTT to MAX
    w.rtt_cycles = UINT64_MAX;
    if constexpr (EnableAB) update_preferred_connection();
}

// After publishing PING frame:
w.ping_send_cycle = rdtscp();
```

### 4. Add `update_preferred_connection()` (`20_ws_process.hpp`)

New private method. Compares RTTs across connections, writes preferred to shared memory. Only called when `EnableAB`.

```cpp
void update_preferred_connection() {
    uint8_t preferred = 0;
    if (wd_[1].rtt_cycles < wd_[0].rtt_cycles) {
        preferred = 1;
    }
    // Equal RTT → keep conn 0 (stable default, avoids flapping)
    uint8_t current = conn_state_->get_preferred_conn_id();
    if (preferred != current) {
        conn_state_->set_preferred_conn_id(preferred);
        // Log change with RTT values
        struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
        uint64_t tsc_freq = conn_state_->tsc_freq_hz;
        auto rtt_us = [&](uint8_t ci) -> uint64_t {
            return (wd_[ci].rtt_cycles == UINT64_MAX) ? 999999
                 : (wd_[ci].rtt_cycles * 1000000ULL) / tsc_freq;
        };
        fprintf(stderr, "[%ld.%06ld] [WS-RTT] Preferred conn: %u -> %u "
                "(A=%luus B=%luus)\n",
                _ts.tv_sec, _ts.tv_nsec / 1000, current, preferred,
                (unsigned long)rtt_us(0), (unsigned long)rtt_us(1));
    }
}
```

### 5. `ConnStateShm` — add `preferred_conn_id` (`pipeline_data.hpp`)

Add to the `conn_reconnect` section (same WS→Transport signaling category):

```cpp
alignas(CACHE_LINE_SIZE) struct {
    std::atomic<bool> reconnect_request[2];
    std::atomic<bool> ws_handshake_done[2];
    std::atomic<uint8_t> preferred_conn_id{0};   // WS → Transport: faster connection
    uint8_t _pad[59];                             // was [60], reduced by 1
} conn_reconnect;
```

Add accessors (following existing pattern at ~line 765):

```cpp
uint8_t get_preferred_conn_id() const {
    return conn_reconnect.preferred_conn_id.load(std::memory_order_relaxed);
}
void set_preferred_conn_id(uint8_t ci) {
    conn_reconnect.preferred_conn_id.store(ci, std::memory_order_relaxed);
}
```

### 6. `TransportProcess::run()` — process preferred connection first (`10_tcp_ssl_process.hpp`)

Replace the per-connection loop (lines 375-448):

```cpp
// ── Per-connection processing (preferred first) ──
uint8_t conn_order[NUM_CONN];
if constexpr (EnableAB) {
    uint8_t pref = conn_state_->get_preferred_conn_id();
    conn_order[0] = pref;
    conn_order[1] = pref ^ 1;
    transport_.set_active(pref);
} else {
    conn_order[0] = 0;
}

for (uint8_t idx = 0; idx < NUM_CONN; idx++) {
    uint8_t ci = conn_order[idx];
    // ... existing per-connection body unchanged, just 'ci' now comes from conn_order ...
}
```

The body of the loop stays the same — only the iteration order changes. The profiling op slot mapping (`ci == 0 ? 2 : 4`) stays tied to the connection ID, not the iteration index.

## Files Modified

| File | Change |
|------|--------|
| `src/pipeline/20_ws_process.hpp` | WatchdogState RTT fields, handle_pong RTT store, maybe_send_client_ping unanswered detection, update_preferred_connection() |
| `src/pipeline/pipeline_data.hpp` | `preferred_conn_id` atomic + accessors in ConnStateShm |
| `src/pipeline/10_tcp_ssl_process.hpp` | Reorder per-connection loop by preferred_conn_id, set_active() |

## Verification

1. Build: `make build-test-pipeline-websocket_binance XDP_INTERFACE=enp108s0 USE_WOLFSSL=1 ENABLE_AB=1 ENABLE_RECONNECT=1` — compile clean
2. Run: verify `[WS-PONG]` logs show RTT for both connections
3. Verify `[WS-RTT] Preferred conn:` log appears when one connection is faster
4. Kill/delay one connection → verify preferred switches to the surviving connection (RTT=999999us for dead one)
