# High-Performance WebSocket Client Library

A policy-based C++17 WebSocket client library optimized for low-latency, high-frequency trading environments.

## Key Features

- **Policy-Based Design**: Compile-time selection of SSL, event loop, and buffer implementations
- **Zero-Copy Architecture**: Ring buffer with virtual memory mirroring for efficient data handling
- **Hardware Timestamping**: NIC-level packet timestamps for precise latency measurement
- **Multi-Platform**: Linux (epoll, io_uring) and macOS (kqueue)
- **SSL Flexibility**: OpenSSL, LibreSSL, or WolfSSL support
- **Production-Ready**: Comprehensive bug fixes and unit test coverage

## Performance

- Sub-microsecond event notification latency
- Zero-copy message processing
- Optional kernel TLS offload (kTLS)
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

# Linux: select + OpenSSL (maximum compatibility)
USE_OPENSSL=1 USE_SELECT=1 make

# macOS: kqueue + LibreSSL (default)
make
```

## Requirements

**Linux:**
- GCC 7+ or Clang 6+ with C++17 support
- libssl-dev (OpenSSL) or libwolfssl-dev
- liburing-dev (optional, for io_uring)
- Linux kernel 4.17+ (for kTLS support)

**macOS:**
- Xcode with C++17 support
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

### Policy-Based Design
- **SSL Policy**: OpenSSLPolicy, LibreSSLPolicy, WolfSSLPolicy
- **Event Policy**: EpollPolicy, IoUringPolicy, KqueuePolicy, SelectPolicy
- **Buffer Policy**: RingBuffer (configurable size: 64KB - 16MB)

### Timing Instrumentation
Six-stage latency measurement:
1. Hardware NIC RX timestamp
2. Event loop wake (RDTSC)
3. SSL_read start
4. SSL_read end
5. Frame parsing complete
6. User callback entry

## Testing

```bash
# Unit tests
make test-ringbuffer    # Ring buffer tests
make test-event         # Event policy tests
make test-bug-fixes     # Bug fix verification

# Integration tests
make test-binance       # Binance WebSocket test

# Benchmarks
make benchmark-binance  # Latency benchmark
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

**Production Ready** - 12 critical bugs fixed, 29/29 unit tests passing, comprehensive test coverage.

Open issues: 5 low-severity code quality improvements (see `doc/known_issues.md`)
