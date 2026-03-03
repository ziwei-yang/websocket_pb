# High-Performance WebSocket Client Library

A policy-based C++20 WebSocket client library optimized for low-latency, high-frequency trading environments.

## Key Features

- **Policy-Based Design**: Compile-time selection of SSL, transport, event loop, and buffer policies
- **Zero-Copy Architecture**: Ring buffer with virtual memory mirroring for efficient data handling
- **Shared Memory IPC**: SPSC ring buffer for inter-process communication (hft-shm compatible)
- **Hardware Timestamping**: NIC-level packet timestamps for precise latency measurement
- **XDP/AF_XDP Transport**: Kernel bypass with userspace TCP/IP stack for ultra-low latency
- **Multi-Platform**: Linux (epoll, io_uring, XDP) and macOS (kqueue)
- **SSL Flexibility**: OpenSSL, LibreSSL, or WolfSSL support
- **WebSocket Fragment Support**: Full RFC 6455 fragmented message reassembly (HftShm mode)

## Pipeline Architecture

The HFT pipeline composes **transport**, **WS processing mode**, **SSL**, and **connection topology**
at compile time via C++20 concepts and `if constexpr` — no virtual functions, no runtime dispatch.

### Pipeline Composition Overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         PIPELINE LAUNCHER                                  │
│                                                                            │
│  WebSocketPipeline<Traits>              BSDWebSocketPipeline<Traits>       │
│  (XDP zero-copy userspace TCP)          (kernel BSD socket stack)          │
│                                                                            │
│  PipelineTraitsConcept                  BSDPipelineTraitsConcept           │
│    SSLPolicy                              SSLPolicy                        │
│    AppHandler                             AppHandler                       │
│    UpgradeCustomizer                      UpgradeCustomizer                │
│    ENABLE_AB                              ENABLE_AB                        │
│    AUTO_RECONNECT                         AUTO_RECONNECT                   │
│    PROFILING                              PROFILING                        │
│    TRICKLE_ENABLED                        IOPolicy           (BSD only)    │
│    INLINE_WS                              SSLThreadingPolicy (BSD only)    │
│    WS_FRAME_INFO_RING                     INLINE_WS                        │
└────────────────────────────────────────────────────────────────────────────┘
```

### Process Topologies (4 configurations)

```
═════════════════════════════════════════════════════════════════════════════
 CONFIG 1: XDP + Dedicated WS (3 processes)         INLINE_WS=false
═════════════════════════════════════════════════════════════════════════════

  ┌──────────────┐ RAW_INBOX  ┌──────────────────┐ MSG_METADATA ┌──────────────┐
  │ XDP Poll     │───────────▶│ Transport        │─────────────▶│ WebSocket    │
  │ (core 2)     │◀───────────│ (core 4)         │◀─────────────│ (core 6)     │
  │              │ RAW_OUTBOX │                  │    PONGS     │              │
  │ AF_XDP sock  │            │ PacketTransport  │              │ WSCore       │
  │ BPF filter   │            │ + SSLPolicy      │              │ + AppHandler │
  │ HW timestamp │            │ + TCP state      │              │ + Upgrade    │
  └──────────────┘            └──────────────────┘              └──────┬───────┘
       fork 1                       fork 2                       fork 3│
                                                                       │
                                                       WS_FRAME_INFO   │
  ┌───────────────────────────────────────────────────────────────────┐│
  │ Parent Process                                                    │◀┘
  │ consume WSFrameInfo ring  ──▶  MSG_OUTBOX  ──▶  Transport         │
  └───────────────────────────────────────────────────────────────────┘


═════════════════════════════════════════════════════════════════════════════
 CONFIG 2: XDP + InlineWS (2 processes)             INLINE_WS=true
═════════════════════════════════════════════════════════════════════════════

  ┌──────────────┐ RAW_INBOX  ┌────────────────────────────────────┐
  │ XDP Poll     │───────────▶│ Transport + WSCore (inline)        │
  │ (core 2)     │◀───────────│ (core 4)                           │
  │              │ RAW_OUTBOX │                                    │
  │ AF_XDP sock  │            │ PacketTransport<DisruptorPIO>      │
  │ BPF filter   │            │   └─ SSLPolicy                     │
  └──────────────┘            │   └─ WSCore<DirectTXSink>          │
       fork 1                 │       └─ AppHandler (inline)       │
                              └─────────────────┬──────────────────┘
                                          fork 2│ WS_FRAME_INFO
                                                │ (or AppHandler handles all)
  ┌────────────────────────────────────────────┐│
  │ Parent Process                             │◀┘
  │ consume WSFrameInfo (optional)             │
  └────────────────────────────────────────────┘


═════════════════════════════════════════════════════════════════════════════
 CONFIG 3: BSD + Dedicated WS (2 processes)         INLINE_WS=false
═════════════════════════════════════════════════════════════════════════════

  ┌──────────────────────────────┐ MSG_METADATA  ┌──────────────────┐
  │ BSD Transport                │──────────────▶│ WebSocket        │
  │ (kernel TCP + SSLPolicy)     │◀──────────────│                  │
  │                              │    PONGS      │ WSCore           │
  │ SSLThreadingPolicy:          │               │ + AppHandler     │
  │   SingleThreadSSL  (1 thr)   │               │ + Upgrade        │
  │   InlineSSL        (2 thr)   │               └────────┬─────────┘
  │   DedicatedSSL     (3 thr)   │                  fork 2│
  └──────────────────────────────┘                        │ WS_FRAME_INFO
       fork 1                                             │
  ┌──────────────────────────────────────────────────────┐│
  │ Parent Process                                       │◀┘
  │ consume WSFrameInfo ring                             │
  └──────────────────────────────────────────────────────┘


═════════════════════════════════════════════════════════════════════════════
 CONFIG 4: BSD + InlineWS (1 child process)         INLINE_WS=true
═════════════════════════════════════════════════════════════════════════════

  ┌────────────────────────────────────────────┐
  │ BSD Transport + WSCore (inline)            │
  │                                            │
  │ BSDSocketTransport<EventPolicy>            │
  │   └─ SSLPolicy (OpenSSL/WolfSSL)           │
  │   └─ WSCore<DirectTXSink>                  │
  │       └─ AppHandler (decode SBE inline)    │
  └─────────────────────┬──────────────────────┘
                  fork 1│ WS_FRAME_INFO (optional)
                        │
  ┌────────────────────┐│
  │ Parent Process     │◀┘
  └────────────────────┘
```

### IPC Ring Types Between Processes

All rings use **hftshm disruptor** (lock-free SPMC with `shared_region` mmap).

| Ring | Direction | Event Type | Purpose |
|------|-----------|------------|---------|
| `RAW_INBOX` | XDP Poll → Transport | `PacketFrameDescriptor` | RX Ethernet/IP/TCP frames with NIC timestamps |
| `RAW_OUTBOX` | Transport → XDP Poll | `PacketFrameDescriptor` | TX packets (ACK, data, SYN) |
| `MSG_METADATA_A` | Transport → WS (conn 0) | `MsgMetadata` | SSL-decrypted chunk location + timestamps |
| `MSG_METADATA_B` | Transport → WS (conn 1) | `MsgMetadata` | Same for conn B (EnableAB only) |
| `PONGS` | WS → Transport | `PongFrameAligned` | PONG frames to send back |
| `MSG_OUTBOX` | Parent → Transport | `MsgOutboxEvent` | Client-initiated WS frames |
| `WS_FRAME_INFO` | WS/InlineWS → Parent | `WSFrameInfo` | Parsed frame + full timestamp chain |
| `MKT_EVENT` | AppHandler → external | `MktEvent` | Standalone ring, persistent across restarts |

### Dual A/B Connection Mode (`ENABLE_AB=true`)

```
                       ┌─────────────────────────────┐
                       │     DNS Probe (8+ IPs)      │
                       │ 54.238.13.49   (67ms RTT)   │
                       │ 52.69.21.200   (69ms RTT)   │
                       │ 54.199.0.6     (70ms RTT)   │
                       │ ...                         │
                       └──────┬─────────┬────────────┘
                         best │         │ 2nd best
                              ▼         ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ Transport (shared PIO, demuxed by TCP dest port)                 │
  │                                                                  │
  │ +----- Conn A ----------+  +----- Conn B ----------+             │
  │ | PacketTransport[0]    |  | PacketTransport[1]    |             │
  │ | IP: 54.238.13.49      |  | IP: 52.69.21.200      |             │
  │ | TCP state machine     |  | TCP state machine     |             │
  │ | SSLPolicy[0]          |  | SSLPolicy[1]          |             │
  │ +----------+------------+  +----------+------------+             │
  │            | MSG_METADATA_A           | MSG_METADATA_B           │
  └────────────┼──────────────────────────┼──────────────────────────┘
               ▼                          ▼
  ┌──────────────────────────────────────────────────────────────────┐
  │ WSCore                                                           │
  │                                                                  │
  │ Two independent watchdog layers:                                 │
  │                                                                  │
  │ 1. Per-connection PING/PONG watchdog (maybe_send_client_ping)    │
  │    - Sends client PING every 1s per connection                   │
  │    - Learns server's PING interval from first 5 samples          │
  │    - Before interval learned: reconnect if PONG missing          │
  │      > 5s (DEFAULT_PONG_TIMEOUT_MS)                              │
  │    - After interval learned: reconnect if BOTH                   │
  │      server PONG missing > learned_interval AND                  │
  │      server PING missing > 1.5x learned_interval                 │
  │    - Reconnects the SINGLE dead connection independently         │
  │                                                                  │
  │ 2. Dual-dead watchdog (check_dual_dead, EnableAB only)           │
  │    - Only fires when BOTH connections are ACTIVE                 │
  │    - Checks last_data_cycle_[0] and last_data_cycle_[1]          │
  │    - If BOTH silent > dual_dead_threshold_ms (default 3s):       │
  │      reconnect BOTH connections simultaneously                   │
  │    - Catches correlated failures (exchange-wide outage,          │
  │      network partition) that per-conn watchdog is too slow       │
  │      to detect individually                                      │
  │                                                                  │
  │ Active conn selection: lowest-latency conn gets                  │
  │ is_active_conn flag, downstream only processes active conn       │
  └───────────────────────────────┬──────────────────────────────────┘
                                  │
                                  ▼
  ┌────────────────────────────────────────────┐
  │ MktEvent Ring (persistent /dev/shm)        │
  │ Only published when ENABLE_AB=true         │
  │ Survives pipeline restart                  │
  │                                            │
  │ External consumers:                        │
  │   mkt_viewer (TUI)                         │
  │   mkt_event_reader (CLI)                   │
  └────────────────────────────────────────────┘
```

### Template Composition Decision Tree

```
START
  │
  ├─ Need AF_XDP zero-copy? ──YES──▶ WebSocketPipeline<Traits>
  │                                    ├─ INLINE_WS=false → 3 processes (XDP + Transport + WS)
  │                                    └─ INLINE_WS=true  → 2 processes (XDP + Transport+WS)
  │
  └─ Kernel TCP (portable)? ──YES──▶ BSDWebSocketPipeline<Traits>
                                       ├─ INLINE_WS=false → 2 processes (Transport + WS)
                                       └─ INLINE_WS=true  → 1 process  (Transport+WS)

  INLINE_WS=true requires AUTO_RECONNECT=true

  SSLPolicy:     WolfSSLPolicy │ OpenSSLPolicy │ LibreSSLPolicy
  SSLThreading:  SingleThreadSSL │ InlineSSL │ DedicatedSSL  (BSD only)
  IOPolicy:      EpollPolicy (Linux) │ KqueuePolicy (macOS)  (BSD only)

  AppHandler:
  ├─ NullAppHandler (enabled=false) → WSFrameInfo ring always created
  └─ Custom (enabled=true) → inline decode, optional WSFrameInfo ring

  ENABLE_AB:
  ├─ false → 1 connection, no MktEvent ring
  └─ true  → 2 connections, dual watchdog, MktEvent ring, IP pool reconnect
```

### Composition Axes Summary

| Axis | Options | Controlled By |
|------|---------|---------------|
| **Transport** | XDP zero-copy / BSD socket | Pipeline class choice |
| **WS Mode** | Dedicated process / InlineWS | `INLINE_WS` |
| **SSL** | WolfSSL / OpenSSL / LibreSSL | `SSLPolicy` typedef |
| **SSL Threading** (BSD) | SingleThread / Inline / Dedicated | `SSLThreadingPolicy` typedef |
| **IO** (BSD) | Epoll / Kqueue / Select | `IOPolicy` typedef |
| **Connections** | Single / Dual A/B | `ENABLE_AB` |
| **Reconnect** | None / Auto with IP pool | `AUTO_RECONNECT` |
| **Profiling** | Off / Cycle sampling | `PROFILING` |
| **Trickle** (XDP) | Off / Periodic padding frames | `TRICKLE_ENABLED` |
| **App Handler** | NullAppHandler / Custom inline decoder | `AppHandler` typedef |
| **Upgrade** | No custom headers / Custom HTTP headers | `UpgradeCustomizer` typedef |
| **Frame Ring** | Auto / Force enabled | `WS_FRAME_INFO_RING` |

### Real Test Examples

| Test | Pipeline | Transport | WS Mode | SSL | AB | Processes | Use Case |
|------|----------|-----------|---------|-----|----|-----------|----------|
| **20** | XDP | PacketTransport | Dedicated | WolfSSL | optional | 3 | Raw XDP latency benchmark |
| **25** | BSD | BSDSocket | Dedicated | OpenSSL | yes | 2 | SBE 2-thread with InlineSSL |
| **28** | BSD | BSDSocket | **InlineWS** | OpenSSL | yes | **1** | SBE production (lowest overhead) |
| **29** | XDP | PacketTransport | **InlineWS** | WolfSSL | yes | **2** | SBE ultra-low-latency production |

#### Test 28: BSD InlineWS (1 child process, SBE decode inline)

```cpp
struct SBEAppHandler {
    static constexpr bool enabled = true;
    IPCRingProducer<MktEvent>* mkt_event_prod = nullptr;
    void on_ws_frame(uint8_t ci, uint8_t opcode,
                     const uint8_t* payload, uint32_t len, WSFrameInfo& info);
};

struct BinanceSBEInlineTraits : DefaultBSDPipelineConfig {
    using SSLPolicy          = OpenSSLPolicy;
    using SSLThreadingPolicy = InlineSSL;
    using AppHandler         = SBEAppHandler;          // decode SBE inline
    using UpgradeCustomizer  = BinanceUpgradeCustomizer; // X-MBX-APIKEY header
    static constexpr bool ENABLE_AB        = true;     // dual A/B connections
    static constexpr bool AUTO_RECONNECT   = true;     // required for InlineWS
    static constexpr bool INLINE_WS        = true;     // 1-process mode
};
// Result: 1 child process, SBE decoded at WS frame level, MktEvent ring for external consumers
```

#### Test 29: XDP InlineWS (2 processes, SBE + MktEvent)

```cpp
struct BinanceSBEXDPInlineTraits : DefaultPipelineConfig {
    using SSLPolicy         = WolfSSLPolicy;
    using AppHandler        = SBEAppHandler;
    using UpgradeCustomizer = BinanceUpgradeCustomizer;
    static constexpr int XDP_POLL_CORE  = 2;
    static constexpr int TRANSPORT_CORE = 4;
    static constexpr bool ENABLE_AB       = true;
    static constexpr bool AUTO_RECONNECT  = true;      // required for InlineWS
    static constexpr bool INLINE_WS       = true;      // 2-process mode
};
// Result: 2 processes (XDP Poll + Transport+WS), userspace TCP, NIC HW timestamps
```

#### Test 20: XDP Standard (3 processes, raw frame output)

```cpp
struct BinanceTraits : DefaultPipelineConfig {
    using SSLPolicy  = WolfSSLPolicy;
    using AppHandler = NullAppHandler;                  // no inline decode
    static constexpr int XDP_POLL_CORE    = 2;
    static constexpr int TRANSPORT_CORE   = 4;
    static constexpr int WEBSOCKET_CORE   = 6;
    static constexpr bool ENABLE_AB       = true;
    static constexpr bool AUTO_RECONNECT  = true;
    static constexpr bool PROFILING       = true;       // cycle sampling enabled
};
// Result: 3 processes, WSFrameInfo ring consumed by parent, profiling dumps
```

### Timestamp Chain (NIC to Application)

Six-stage latency measurement from NIC hardware to user callback:

```
NIC HW RX              BPF entry           Transport poll       SSL_read start
    │                      │                     │                    │
    ▼                      ▼                     ▼                    ▼
 first_byte_ts    first_bpf_entry_ns     first_poll_cycle    first_ssl_read_start
 (NIC PHC clock)  (CLOCK_MONOTONIC)      (rdtsc)             (rdtsc)
                                                                     │
                                                              SSL_read end
                                                                     │
                                                                     ▼
                                                          ssl_last_op_cycle
                                                              (rdtscp)
                                                                     │
                                                              WS frame parse
                                                                     │
                                                                     ▼
                                                          ws_parse_cycle / ws_last_op_cycle
                                                              (rdtscp)
```

### File Locations

| Component | File |
|-----------|------|
| Pipeline Config | `src/pipeline/pipeline_config.hpp` |
| Pipeline Data | `src/pipeline/pipeline_data.hpp` |
| XDP Pipeline | `src/pipeline/websocket_pipeline.hpp` |
| BSD Pipeline | `src/pipeline/bsd_websocket_pipeline.hpp` |
| XDP Poll | `src/pipeline/00_xdp_poll_process.hpp` |
| XDP Transport | `src/pipeline/10_tcp_ssl_process.hpp` |
| BSD Transport | `src/pipeline/11_bsd_tcp_ssl_process.hpp` |
| WS Process | `src/pipeline/20_ws_process.hpp` |
| WS Core | `src/pipeline/21_ws_core.hpp` |
| MktEvent | `src/msg/mkt_event.hpp` |
| Stream Decoder | `src/msg/stream_decoder.hpp` |

---

## Performance

- Sub-microsecond event notification latency
- Zero-copy message processing via circular buffers
- Optional kernel TLS offload (kTLS)
- XDP zero-copy kernel bypass mode
- CPU core pinning support for consistent performance

## Quick Start

```bash
# Build with default configuration
make

# Run WebSocket example
make run-example

# Run all tests
make test

# Run benchmarks
make benchmark-binance
```

## Platform-Specific Builds

```bash
# Linux: io_uring + WolfSSL (default)
make

# Linux: epoll + OpenSSL
USE_IOURING=0 make

# Linux: XDP kernel bypass + OpenSSL
USE_XDP=1 USE_OPENSSL=1 make

# Linux: HftShm shared memory + WolfSSL
USE_HFTSHM=1 USE_WOLFSSL=1 make

# Linux: select + OpenSSL (maximum compatibility)
USE_OPENSSL=1 USE_SELECT=1 make

# macOS: kqueue + LibreSSL (default)
make
```

## Requirements

**Linux:**
- GCC 10+ or Clang 10+ with C++20 support
- libssl-dev (OpenSSL) or libwolfssl-dev
- liburing-dev (optional, for io_uring)
- Linux kernel 5.4+ (for XDP zero-copy, kTLS)
- libbpf-dev, libxdp-dev (optional, for XDP transport)

**macOS:**
- Xcode 12+ with C++20 support
- LibreSSL (via Homebrew: `brew install libressl`)

## Source Structure

```
src/
├── websocket.hpp              # Main WebSocketClient template
├── ws_policies.hpp            # Policy type definitions & C++20 concepts
├── ws_configs.hpp             # Pre-configured client types
├── ringbuffer.hpp             # Unified buffer implementations
├── rx_ringbuffer_consumer.hpp # Standalone shared memory consumer
├── core/
│   ├── http.hpp               # WebSocket frame parsing/building
│   └── timing.hpp             # RDTSC/hardware timestamp utilities
├── policy/
│   ├── ssl.hpp                # OpenSSL/LibreSSL/WolfSSL policies
│   ├── event.hpp              # Epoll/IoUring/Kqueue/Select policies
│   ├── transport.hpp          # BSD socket transport
│   ├── simulator_transport.hpp    # Traffic replay transport
│   └── userspace_transport_bio.hpp # OpenSSL BIO for XDP
├── transport/
│   └── bsd_socket.hpp         # BSD socket wrapper
├── pipeline/                  # HFT multi-process pipeline
│   ├── pipeline_config.hpp    # Traits concepts & defaults
│   ├── pipeline_data.hpp      # IPC data structures
│   ├── websocket_pipeline.hpp # XDP pipeline launcher
│   ├── bsd_websocket_pipeline.hpp # BSD pipeline launcher
│   ├── 00_xdp_poll_process.hpp    # AF_XDP poll process
│   ├── 10_tcp_ssl_process.hpp     # XDP transport process
│   ├── 11_bsd_tcp_ssl_process.hpp # BSD transport process
│   ├── 20_ws_process.hpp          # WebSocket process
│   ├── 21_ws_core.hpp             # WS frame parser + watchdog
│   └── msg_inbox.hpp              # Per-connection byte stream buffer
├── msg/
│   ├── mkt_event.hpp          # MktEvent struct (book/trade/status)
│   └── stream_decoder.hpp     # SBE decode policy
├── xdp/                       # AF_XDP kernel bypass
│   ├── xdp_transport.hpp      # XDP transport policy
│   ├── xdp_frame.hpp          # Zero-copy frame handling
│   └── bpf_loader.hpp         # eBPF program loader
├── net/
│   └── ip_probe.hpp           # DNS probe + RTT ranking
└── stack/                     # Userspace TCP/IP (for XDP)
    ├── userspace_stack.hpp
    ├── tcp/                   # TCP state machine, retransmit
    ├── ip/                    # IP layer, checksum
    └── mac/                   # Ethernet, ARP

tools/
├── mkt_viewer.cpp             # TUI market data viewer
└── mkt_event_reader.cpp       # CLI ring consumer

test/pipeline/
├── 20_websocket_binance.cpp           # XDP 3-process
├── 250_binance_sbe_bsdsocket_2thread.cpp  # BSD 2-process
├── 253_binance_sbe_bsdsocket_inline_ws.cpp # BSD InlineWS
├── 261_binance_sbe_xdp_inline_ws.cpp     # XDP InlineWS
├── 262_binance_sbe_dpdk_inline_ws.cpp     # DPDK InlineWS
├── 263_binance_sbe_dpdk_packetio_inline_ws.cpp # DPDK DirectIO InlineWS
└── 264_binance_sbe_xdp_packetio_inline_ws.cpp  # XDP DirectIO InlineWS
```

## Policy Reference

### SSL Policies (`policy/ssl.hpp`)
| Policy | Description | kTLS Support |
|--------|-------------|--------------|
| `OpenSSLPolicy` | Industry standard, widely deployed | Yes (Linux 4.17+) |
| `LibreSSLPolicy` | macOS/BSD default, OpenSSL-compatible | No |
| `WolfSSLPolicy` | Lightweight, optimized for embedded | No |
| `NoSSLPolicy` | No encryption (for simulator/testing) | N/A |

### Transport Policies (`policy/transport.hpp`)
| Policy | Description | Use Case |
|--------|-------------|----------|
| `BSDSocketTransport<EventPolicy>` | Kernel TCP/IP stack | Standard deployments |
| `XDPUserspaceTransport` | AF_XDP zero-copy + userspace TCP/IP | Ultra-low latency HFT |
| `SimulatorTransport` | Replay recorded traffic from file | Testing, benchmarking |

### Event Policies (`policy/event.hpp`)
| Policy | Platform | Description |
|--------|----------|-------------|
| `EpollPolicy` | Linux | Edge-triggered, O(1), sub-us latency |
| `IoUringPolicy` | Linux 5.1+ | Async I/O, reduced syscalls |
| `KqueuePolicy` | macOS/BSD | Edge-cleared, similar to epoll |
| `SelectPolicy` | All | Maximum compatibility fallback |

## Shared Memory IPC

For inter-process communication, use `ShmWebSocketClient` with a separate `RXRingBufferConsumer`:

### Producer Process (WebSocket -> Shared Memory)
```cpp
#include "ws_configs.hpp"

ShmRxBuffer::create("/dev/shm/hft/binance.rx", 2*1024*1024);
ShmWebSocketClient client("/dev/shm/hft/binance.rx");
client.connect("stream.binance.com", 443, "/stream");
client.run(nullptr);  // Data flows to shm only
```

### Consumer Process (Shared Memory -> Application)
```cpp
#include "rx_ringbuffer_consumer.hpp"

RXRingBufferConsumer consumer;
consumer.init("/dev/shm/hft/binance.rx");
consumer.set_on_messages([](const BatchInfo& batch, const MessageInfo* msgs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        process(msgs[i].payload, msgs[i].len);
    }
});
consumer.run();  // Busy-poll for lowest latency
```

## Traffic Recording & Replay

### Recording Traffic (DEBUG builds)
```cpp
PrivateWebSocketClient client;
client.enable_debug_traffic("debug_traffic.dat");
client.connect("stream.binance.com", 443, "/ws/btcusdt@trade");
client.run([](auto* msgs, size_t n, auto& timing) { /* ... */ });
```

### Replaying Traffic
```cpp
SimulatorReplayClient client;
client.transport().open_file("debug_traffic.dat");
client.set_message_callback([](const MessageInfo* msgs, size_t n, const timing_record_t&) {
    for (size_t i = 0; i < n; i++) process(msgs[i].payload, msgs[i].len);
    return true;
});
client.connect("", 0, "");
client.run(nullptr);
```

## Design Decisions

This library is optimized for **single-threaded HFT environments**:
- No TLS certificate verification (performance > MITM protection)
- Static masking key (no cryptographic security needed)
- Assumes trusted endpoints and controlled network environment

**Not suitable for**: Multi-threaded applications, untrusted endpoints, general-purpose WebSocket needs.

## License

See LICENSE file for details.
