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

## Examples

```cpp
#include "websocket.hpp"
#include "ws_configs.hpp"

// Use pre-configured policy combination
using WS = DefaultWebSocketClient;

WS client;
client.connect("stream.binance.com", 443, "/ws/btcusdt@trade");

client.run([](const uint8_t* data, size_t len, const timing_record_t& timing) {
    // Process message with zero-copy access
    // timing contains hardware timestamps and latency breakdown
});
```

## Architecture

### Source Structure (~7,400 lines of code)
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
├── xdp/                       # AF_XDP kernel bypass
│   ├── xdp_transport.hpp      # XDP transport policy
│   ├── xdp_frame.hpp          # Zero-copy frame handling
│   └── bpf_loader.hpp         # eBPF program loader
└── stack/                     # Userspace TCP/IP (for XDP)
    ├── userspace_stack.hpp
    ├── tcp/                   # TCP state machine, retransmit
    │   ├── tcp_state.hpp
    │   ├── tcp_packet.hpp
    │   └── tcp_retransmit.hpp
    ├── ip/                    # IP layer, checksum
    │   ├── ip_layer.hpp
    │   └── checksum.hpp
    └── mac/                   # Ethernet, ARP
        ├── ethernet.hpp
        └── arp.hpp
```

### Policy-Based Design

The library uses compile-time policy composition for maximum flexibility and zero runtime overhead.

#### SSL Policies (`policy/ssl.hpp`)
| Policy | Description | kTLS Support |
|--------|-------------|--------------|
| `OpenSSLPolicy` | Industry standard, widely deployed | Yes (Linux 4.17+) |
| `LibreSSLPolicy` | macOS/BSD default, OpenSSL-compatible | No |
| `WolfSSLPolicy` | Lightweight, optimized for embedded | No |
| `NoSSLPolicy` | No encryption (for simulator/testing) | N/A |

#### Transport Policies (`policy/transport.hpp`)
| Policy | Description | Use Case |
|--------|-------------|----------|
| `BSDSocketTransport<EventPolicy>` | Kernel TCP/IP stack | Standard deployments |
| `XDPUserspaceTransport` | AF_XDP zero-copy + userspace TCP/IP | Ultra-low latency HFT |
| `SimulatorTransport` | Replay recorded traffic from file | Testing, benchmarking |

#### Event Policies (`policy/event.hpp`)
| Policy | Platform | Description |
|--------|----------|-------------|
| `EpollPolicy` | Linux | Edge-triggered, O(1), sub-μs latency |
| `IoUringPolicy` | Linux 5.1+ | Async I/O, reduced syscalls |
| `KqueuePolicy` | macOS/BSD | Edge-cleared, similar to epoll |
| `SelectPolicy` | All | Maximum compatibility fallback |

#### Buffer Policies (`ringbuffer.hpp`)
| Policy | Description | on_messages callback |
|--------|-------------|---------------------|
| `RingBuffer<Capacity>` | Private memory with virtual mirroring | Enabled |
| `ShmRxBuffer` | Runtime path-based shared memory (producer) | Disabled |
| `ShmTxBuffer` | Runtime path-based shared memory (consumer) | Disabled |
| `NullBuffer` | No-op buffer (disable TX) | N/A |

All buffer types use the same batch format: `[ShmBatchHeader][ssl_data][ShmFrameDesc[]]`

### Timing Instrumentation
Six-stage latency measurement:
1. Hardware NIC RX timestamp (SO_TIMESTAMPING or XDP metadata)
2. Event loop wake (RDTSC)
3. SSL_read start
4. SSL_read end
5. Frame parsing complete
6. User callback entry

## Shared Memory IPC

For inter-process communication, use `ShmWebSocketClient` with a separate `RXRingBufferConsumer`:

### Producer Process (WebSocket → Shared Memory)
```cpp
#include "ws_configs.hpp"

// Create shared memory files (one-time setup)
ShmRxBuffer::create("/dev/shm/hft/binance.rx", 2*1024*1024);

// Producer writes to shared memory (callback disabled)
ShmWebSocketClient client("/dev/shm/hft/binance.rx");
client.connect("stream.binance.com", 443, "/stream");
client.run(nullptr);  // Data flows to shm only
```

### Consumer Process (Shared Memory → Application)
```cpp
#include "rx_ringbuffer_consumer.hpp"

RXRingBufferConsumer consumer;
consumer.init("/dev/shm/hft/binance.rx");

consumer.set_on_messages([](const BatchInfo& batch, const MessageInfo* msgs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        const char* payload = reinterpret_cast<const char*>(msgs[i].payload);
        process(payload, msgs[i].len);
    }
});

consumer.run();  // Busy-poll for lowest latency
```

### hft-shm Integration
For use with [hft-shm](https://github.com/hft-shm):
```bash
# Initialize shared memory segments
hft-shm init --config ~/hft.toml

# Run producer/consumer test
./build/binance_txrx -m ws_client     # Terminal 1: WebSocket → shm
./build/binance_txrx -m rx_consumer   # Terminal 2: shm → stdout
```

## Traffic Recording & Replay

The library supports recording live traffic and replaying it for testing/benchmarking.

### Recording Traffic (DEBUG builds)
```cpp
#include "ws_configs.hpp"

PrivateWebSocketClient client;
client.enable_debug_traffic("debug_traffic.dat");  // Start recording
client.connect("stream.binance.com", 443, "/ws/btcusdt@trade");
client.run([](auto* msgs, size_t n, auto& timing) { /* ... */ });
// Traffic saved to debug_traffic.dat
```

### Replaying Traffic
```cpp
#include "ws_configs.hpp"

SimulatorReplayClient client;
client.transport().open_file("debug_traffic.dat");
client.set_message_callback([](const MessageInfo* msgs, size_t n, const timing_record_t&) {
    for (size_t i = 0; i < n; i++) {
        process(msgs[i].payload, msgs[i].len);
    }
    return true;
});
client.connect("", 0, "");  // Dummy connect (no real connection)
client.run(nullptr);        // Process all recorded traffic
```

Traffic file format (32-byte header + payload per record):
- `SSLR` magic: RX record (received data)
- `SSLT` magic: TX record (sent data, skipped during replay)

## Testing

```bash
# Unit tests
make test-ringbuffer       # Ring buffer tests
make test-shm-ringbuffer   # Shared memory ring buffer tests
make test-event            # Event policy tests
make test-bug-fixes        # Bug fix verification

# Integration tests
make test-binance          # Binance WebSocket test

# Shared memory IPC tests (requires hft-shm)
hft-shm init --config ~/hft.toml
make test-binance-shm      # Build binance_txrx
./build/binance_txrx -m ws_client     # Producer mode (default)
./build/binance_txrx -m rx_consumer   # Consumer mode

# Benchmarks
make benchmark-binance     # Latency benchmark
```

## Documentation

- `doc/known_issues.md` - Known issues and bug tracking
- `doc/BUGFIX_SUMMARY.md` - Detailed bug fix documentation
- See `make help` for all build targets

## Design Decisions

This library is optimized for **single-threaded HFT environments**:
- No TLS certificate verification (performance > MITM protection)
- Static masking key (no cryptographic security needed)
- Assumes trusted endpoints and controlled network environment

**Not suitable for**: Multi-threaded applications, untrusted endpoints, general-purpose WebSocket needs.

## License

See LICENSE file for details.

## Status

**Production Ready** - Policy-based architecture with ~7,400 lines of code.

Features:
- Unified `ringbuffer.hpp` with private and shared memory modes
- WebSocket fragment reassembly support
- XDP/AF_XDP transport with userspace TCP/IP stack (kernel bypass)
- Shared memory IPC with hft-shm compatibility
- SimulatorTransport for traffic recording and replay
- C++20 required

Recent changes:
- Added SimulatorTransport policy for traffic replay testing
- Unified RingBuffer and ShmRingBuffer into dual-mode support
- Frame misalignment fix in `try_read_on_timeout()` leftover handling

Open issues: See `doc/known_issues.md`
