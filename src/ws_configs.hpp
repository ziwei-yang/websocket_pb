// ws_configs.hpp
// Pre-configured WebSocket client instantiations using policy-based design
//
// Template parameters:
//   - SSLPolicy: OpenSSLPolicy, LibreSSLPolicy, WolfSSLPolicy, NoSSLPolicy
//   - TransportPolicy: BSDSocketTransport<EventPolicy> or XDPUserspaceTransport
//   - RxBufferPolicy: RingBuffer<size>
//   - TxBufferPolicy: RingBuffer<size>
//
#pragma once

#include "websocket.hpp"
#include "ringbuffer.hpp"

// Unified event policy (epoll, kqueue, select)
#include "policy/event.hpp"

// Unified SSL policy (OpenSSL, LibreSSL, WolfSSL)
#include "policy/ssl.hpp"

// Transport policy (BSD sockets + event, XDP)
#include "policy/transport.hpp"

// ============================================================================
// Configuration 1: Linux Default (Optimized for HFT)
// ============================================================================
// Best for: Linux production high-frequency trading (HFT) systems
//
// Policy composition (io_uring mode - default):
//   - SSLPolicy: WolfSSLPolicy (optimized for io_uring)
//   - EventPolicy: EpollPolicy (edge-triggered, low latency)
//   - RxBufferPolicy: RingBuffer<32MB> (large receive buffer for market data bursts)
//   - TxBufferPolicy: RingBuffer<2MB> (small transmit buffer for order commands)
//
// Policy composition (epoll mode - USE_IOURING=0):
//   - SSLPolicy: OpenSSLPolicy (with automatic kTLS support)
//   - EventPolicy: EpollPolicy (edge-triggered, low latency)
//   - RxBufferPolicy: RingBuffer<32MB>
//   - TxBufferPolicy: RingBuffer<2MB>
//
// HFT-optimized buffer sizing rationale:
//   - RX: 32MB handles high-volume market data bursts without drops
//     * Typical HFT scenario: streaming orderbook updates, trades, quotes
//     * Prevents message loss during microsecond-scale processing delays
//     * Accommodates exchange reconnection/recovery message backlogs
//   - TX: 2MB sufficient for order commands and status updates
//     * HFT sends orders infrequently compared to receiving market data
//     * Typical order messages: 100-500 bytes each
//     * 2MB = ~4,000-20,000 pending orders (excessive headroom)
//
// Performance characteristics:
//   - io_uring for true async I/O (when ENABLE_IO_URING is defined)
//   - Falls back to epoll + OpenSSL when io_uring disabled
//   - Sub-microsecond latency for message processing
//   - Zero memory allocations in hot path
//   - Zero-copy ring buffer operations
//   - Asymmetric buffer design minimizes cache pollution

#ifdef __linux__

// Determine SSL Policy
#ifdef HAVE_WOLFSSL
    using DefaultSSLPolicy = WolfSSLPolicy;
#elif defined(USE_LIBRESSL)
    using DefaultSSLPolicy = LibreSSLPolicy;
#else
    using DefaultSSLPolicy = OpenSSLPolicy;
#endif

// Determine Event Policy
#ifdef USE_SELECT
    using DefaultEventPolicy = SelectPolicy;
#elif defined(ENABLE_IO_URING)
    // io_uring doesn't use traditional event policy - still use epoll as fallback
    using DefaultEventPolicy = EpollPolicy;
#else
    using DefaultEventPolicy = EpollPolicy;
#endif

// Default Transport Policy: XDP zero-copy when USE_XDP, otherwise BSD socket
#ifdef USE_XDP
// XDP zero-copy mode: AF_XDP + userspace TCP/IP (kernel bypass)
using DefaultTransportPolicy = websocket::transport::XDPUserspaceTransport;
#else
// BSD socket + event loop (kernel TCP/IP stack)
using DefaultTransportPolicy = websocket::transport::BSDSocketTransport<DefaultEventPolicy>;
#endif

using LinuxOptimized = WebSocketClient<
    DefaultSSLPolicy,
    DefaultTransportPolicy,        // Transport now wraps event policy
    RingBuffer<32 * 1024 * 1024>,  // 32MB RX buffer (HFT: high-volume market data ingestion)
    RingBuffer<2 * 1024 * 1024>    // 2MB TX buffer (HFT: low-volume order commands)
>;

#endif

// ============================================================================
// Configuration 2: macOS/BSD Default (LibreSSL + kqueue, HFT-optimized)
// ============================================================================
// Best for: macOS/BSD development and high-frequency trading systems
//
// Policy composition:
//   - SSLPolicy: LibreSSLPolicy (preferred on macOS/BSD)
//   - EventPolicy: KqueuePolicy (edge-cleared, similar to epoll)
//   - RxBufferPolicy: RingBuffer<32MB> (HFT: high-volume market data)
//   - TxBufferPolicy: RingBuffer<2MB> (HFT: low-volume order commands)
//
// HFT-optimized buffer sizing (same as Linux):
//   - RX: 32MB handles market data bursts without message loss
//   - TX: 2MB sufficient for order flow (asymmetric usage pattern)
//
// Performance characteristics:
//   - kqueue for efficient event notification
//   - Standard user-space TLS (kTLS is Linux-only)
//   - Zero-copy ring buffer operations
//   - Asymmetric buffers reduce memory footprint

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
// macOS/BSD Transport Policy: BSD socket + kqueue
using MacOSTransportPolicy = websocket::transport::BSDSocketTransport<KqueuePolicy>;

#ifdef USE_LIBRESSL
using MacOSDefault = WebSocketClient<
    LibreSSLPolicy,
    MacOSTransportPolicy,
    RingBuffer<32 * 1024 * 1024>,  // 32MB RX buffer (HFT: market data ingestion)
    RingBuffer<2 * 1024 * 1024>    // 2MB TX buffer (HFT: order commands)
>;
#else
// Fallback to OpenSSL if LibreSSL not available
using MacOSDefault = WebSocketClient<
    OpenSSLPolicy,
    MacOSTransportPolicy,
    RingBuffer<32 * 1024 * 1024>,  // 32MB RX buffer (HFT: market data ingestion)
    RingBuffer<2 * 1024 * 1024>    // 2MB TX buffer (HFT: order commands)
>;
#endif
#endif

// ============================================================================
// Configuration 4: Low Memory (4MB buffers)
// ============================================================================
// Use when memory is constrained but still need good performance

#ifdef __linux__
using LowMemory = WebSocketClient<
    DefaultSSLPolicy,
    DefaultTransportPolicy,
    RingBuffer<4 * 1024 * 1024>,  // 4MB RX buffer
    RingBuffer<4 * 1024 * 1024>   // 4MB TX buffer
>;
#endif

// ============================================================================
// Configuration 5: High Throughput (16MB buffers)
// ============================================================================
// For extremely high message rates or large messages

#ifdef __linux__
using HighThroughput = WebSocketClient<
    DefaultSSLPolicy,
    DefaultTransportPolicy,
    RingBuffer<16 * 1024 * 1024>,  // 16MB RX buffer
    RingBuffer<16 * 1024 * 1024>   // 16MB TX buffer
>;
#endif

// ============================================================================
// Configuration 6: Asymmetric Buffers (Large RX, Small TX)
// ============================================================================
// Common pattern: receive lots of market data, send few commands

#ifdef __linux__
using AsymmetricBuffers = WebSocketClient<
    DefaultSSLPolicy,
    DefaultTransportPolicy,
    RingBuffer<16 * 1024 * 1024>,  // 16MB RX buffer (market data)
    RingBuffer<1 * 1024 * 1024>    // 1MB TX buffer (commands)
>;
#endif

// ============================================================================
// Type aliases for convenience
// ============================================================================

// Default configuration for current platform
#ifdef __linux__
    using DefaultWebSocket = LinuxOptimized;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    using DefaultWebSocket = MacOSDefault;
#else
    #error "Unsupported platform"
#endif

// Portable configuration (works on all platforms)
using PortableWebSocket = DefaultWebSocket;

// ============================================================================
// Configuration 7: DPDK WebSocket (Ultra-Low Latency)
// ============================================================================
// Best for: Ultra-low latency HFT with dedicated NICs and CPU cores
//
// Policy composition:
//   - TransportPolicy: DPDKTransport (userspace TCP stack)
//   - SSLPolicy: DPDKSSLPolicy (OpenSSL with custom BIO)
//   - EventPolicy: DPDKEventPolicy (polling-based, no syscalls)
//   - RxBufferPolicy: RingBuffer<32MB> (HFT market data)
//   - TxBufferPolicy: RingBuffer<2MB> (HFT orders)
//
// Requirements:
//   - DPDK installed (dpdk, dpdk-dev packages)
//   - NIC bound to DPDK (dpdk-devbind.py)
//   - Huge pages configured (2MB pages)
//   - Dedicated CPU core for polling
//
// Performance characteristics:
//   - Sub-50 μs latency (NIC→callback)
//   - Zero syscalls (pure userspace)
//   - 100% CPU on polling core
//   - Hardware timestamping support
//   - No kernel bypass overhead
//
// Build:
//   USE_DPDK=1 make clean all
//
// NOTE: This is an advanced configuration requiring DPDK setup.
//       See doc/DPDK_SETUP.md for installation instructions.

#ifdef USE_DPDK
#include "dpdk/ssl/dpdk_ssl_policy.hpp"
#include "dpdk/dpdk_event.hpp"

// Note: DPDK WebSocket integration is work-in-progress
// Full integration requires Phase 4 (HTTP/WebSocket framing) completion
// For now, this serves as a template for future DPDK configs
//
// using DPDKWebSocket = WebSocketClient<
//     websocket::dpdk::ssl::DPDKSSLPolicy,
//     DPDKEventPolicy,
//     RingBuffer<32 * 1024 * 1024>,  // 32MB RX (market data)
//     RingBuffer<2 * 1024 * 1024>    // 2MB TX (orders)
// >;

#endif // USE_DPDK

// ============================================================================
// XDP Zero-Copy Configuration (AF_XDP + Userspace TCP)
// ============================================================================
// Best for: Ultra-low latency HFT with kernel bypass
//
// Policy composition:
//   - TransportPolicy: XDPUserspaceTransport (AF_XDP + userspace TCP/IP)
//   - SSLPolicy: OpenSSLPolicy (via UserspaceTransportBIO)
//   - RxBufferPolicy: RingBuffer<32MB>
//   - TxBufferPolicy: RingBuffer<2MB>
//
// Performance characteristics:
//   - ~1-5us latency (vs ~10-50us for BSD sockets)
//   - Zero-copy from NIC to userspace via UMEM
//   - Busy-polling (100% CPU, lowest latency)
//
// Requirements:
//   - NIC with XDP driver support
//   - CAP_NET_ADMIN capability (sudo)
//   - NIC queue set to 1 (scripts/nic_queue_num_switch.sh)
//
// Build:
//   USE_XDP=1 USE_OPENSSL=1 make

#ifdef USE_XDP
using XDPTransportPolicy = websocket::transport::XDPUserspaceTransport;

using XDPWebSocket = WebSocketClient<
    DefaultSSLPolicy,
    XDPTransportPolicy,
    RingBuffer<32 * 1024 * 1024>,  // 32MB RX buffer (HFT: market data)
    RingBuffer<2 * 1024 * 1024>    // 2MB TX buffer (HFT: orders)
>;
#endif

// ============================================================================
// Transport Type Traits (Re-exported for convenience)
// ============================================================================
// Use these traits to check transport type at compile-time:
//
//   if constexpr (is_fd_based_transport_v<MyTransport>) {
//       // BSD socket specific code
//   } else {
//       // Userspace transport specific code
//   }

using websocket::traits::is_fd_based_transport;
using websocket::traits::is_fd_based_transport_v;

// ============================================================================
// C++20 Concepts (Re-exported for convenience)
// ============================================================================
#if __cplusplus >= 202002L
using websocket::transport::TransportPolicyConcept;
using websocket::transport::FdBasedTransportConcept;
using websocket::transport::UserspaceTransportConcept;

// Compile-time validation of default transport
#ifdef USE_XDP
static_assert(UserspaceTransportConcept<DefaultTransportPolicy>,
              "DefaultTransportPolicy (XDP) must conform to UserspaceTransportConcept");
#else
static_assert(FdBasedTransportConcept<DefaultTransportPolicy>,
              "DefaultTransportPolicy (BSD) must conform to FdBasedTransportConcept");
#endif

#endif // C++20

// ============================================================================
// Custom Configuration Example
// ============================================================================
// You can create your own custom configuration:
//
// using MyCustomClient = WebSocketClient<
//     OpenSSLPolicy,
//     websocket::transport::BSDSocketTransport<EpollPolicy>,
//     RingBuffer<2 * 1024 * 1024>,  // 2MB RX
//     RingBuffer<512 * 1024>        // 512KB TX
// >;
//
// For XDP zero-copy:
//
// using MyXDPClient = WebSocketClient<
//     OpenSSLPolicy,
//     websocket::transport::XDPUserspaceTransport,
//     RingBuffer<32 * 1024 * 1024>,
//     RingBuffer<2 * 1024 * 1024>
// >;

// ============================================================================
// Configuration: Runtime Shared Memory (Always Enabled)
// ============================================================================
// Uses ShmRingBuffer for runtime path-based shared memory RX buffers.
// No compile flags required - always available.
//
// Producer pattern:
//   1. Create shared memory files once:
//      ShmRxBuffer::create("/tmp/binance_rx", 2*1024*1024);  // Creates .hdr + .dat
//   2. Producer attaches and writes data:
//      ShmWebSocketClient client("/tmp/binance_rx");
//      client.connect(...);
//      client.run(nullptr);  // on_messages callback DISABLED (data flows to shm)
//
// Consumer pattern (separate process):
//   RXRingBufferConsumer consumer;
//   consumer.init("/tmp/binance_rx");  // Opens .hdr + .dat
//   consumer.set_on_messages([](const MessageInfo* msgs, size_t n) { ... });
//   consumer.run();  // Busy-poll
//
// Performance characteristics:
//   - Zero-copy from SSL → shared memory → consumer
//   - Uses hftshm::metadata format for compatibility
//   - SPSC (single producer, single consumer) lock-free

#ifdef __linux__
#include "rx_ringbuffer_consumer.hpp"

// WebSocket client with shared memory RX (runtime path)
// Constructor takes shmem path, on_messages callback is DISABLED
using ShmWebSocketClient = WebSocketClient<
    DefaultSSLPolicy,
    DefaultTransportPolicy,
    ShmRxBuffer,                    // Runtime shm RX (path via constructor)
    RingBuffer<2 * 1024 * 1024>     // 2MB private TX
>;

// Default private buffer client (2MB RX/TX)
// on_messages callback is ENABLED - use for direct message processing
using PrivateWebSocketClient = WebSocketClient<
    DefaultSSLPolicy,
    DefaultTransportPolicy,
    RingBuffer<2 * 1024 * 1024>,    // 2MB private RX
    RingBuffer<2 * 1024 * 1024>     // 2MB private TX
>;

#endif // __linux__

// ============================================================================
// Configuration: hft-shm Shared Memory Buffers (Legacy - USE_HFTSHM)
// ============================================================================
// Enable with: USE_HFTSHM=1 USE_WOLFSSL=1 make
//
// Uses hft-shm managed shared memory for RX/TX buffers, enabling:
//   - RX: WebSocketClient writes to shm, external consumers read market data
//   - TX: External producers write commands to shm, WebSocketClient sends
//
// Policy composition:
//   - SSLPolicy: WolfSSLPolicy (optimized TLS)
//   - TransportPolicy: BSDSocketTransport<EpollPolicy> (not XDP during dev)
//   - RxBufferPolicy: HftShmRxBuffer (producer role, writes to shm)
//   - TxBufferPolicy: HftShmTxBuffer (consumer role, reads from shm)
//
// Requirements:
//   - hft-shm CLI installed and in PATH
//   - Segments created: hft-shm init --config conf/test.toml
//   - Segment type must be "ringbuffer"
//
// Build:
//   USE_HFTSHM=1 USE_WOLFSSL=1 make

#ifdef USE_HFTSHM
// HftShmRingBuffer is now in ringbuffer.hpp (already included at top)

// Shared memory configuration for Binance market data
// Uses BSDSocketTransport + WolfSSL (not XDP) for development
using BinanceShmClient = WebSocketClient<
    WolfSSLPolicy,                                          // WolfSSL for TLS
    websocket::transport::BSDSocketTransport<EpollPolicy>,  // BSD sockets (not XDP)
    HftShmRxBuffer<"zwy.mktdata.binance.raw.rx">,           // RX = Producer
    HftShmTxBuffer<"zwy.mktdata.binance.raw.tx">            // TX = Consumer
>;

// Mixed: RX to shared memory, TX private
// Useful when you only need to publish market data to other processes
using BinanceRxShmClient = WebSocketClient<
    WolfSSLPolicy,
    websocket::transport::BSDSocketTransport<EpollPolicy>,
    HftShmRxBuffer<"zwy.mktdata.binance.raw.rx">,
    RingBuffer<2 * 1024 * 1024>                             // 2MB private TX
>;

// Test configuration (uses test.* segments)
using TestShmClient = WebSocketClient<
    WolfSSLPolicy,
    websocket::transport::BSDSocketTransport<EpollPolicy>,
    HftShmRxBuffer<"test.mktdata.binance.raw.rx">,
    HftShmTxBuffer<"test.mktdata.binance.raw.tx">
>;

#endif // USE_HFTSHM
