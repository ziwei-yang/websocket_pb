// ws_configs.hpp
// Pre-configured WebSocket client instantiations using 4-policy design
#pragma once

#include "websocket.hpp"
#include "core/ringbuffer.hpp"

// Unified event policy (epoll, kqueue, select)
#include "policy/event.hpp"

// Unified SSL policy (OpenSSL, LibreSSL, WolfSSL)
#include "policy/ssl.hpp"

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

using LinuxOptimized = WebSocketClient<
    DefaultSSLPolicy,
    DefaultEventPolicy,
    RingBuffer<32 * 1024 * 1024>,  // 32MB RX buffer (HFT: high-volume market data ingestion)
    RingBuffer<2 * 1024 * 1024>    // 2MB TX buffer (HFT: low-volume order commands)
>;

#endif

// ============================================================================
// Configuration 2: WolfSSL (Alternative SSL) - DISABLED
// ============================================================================
// Best for: Applications requiring WolfSSL
//
// Note: WolfSSLPolicy is not currently implemented
// Uncomment when WolfSSL policy is added
//
// #ifdef __linux__
// using WolfSSLConfig = WebSocketClient<
//     WolfSSLPolicy,
//     EpollPolicy,
//     RingBuffer<8192 * 1024>,
//     RingBuffer<8192 * 1024>
// >;
// #endif

// ============================================================================
// Configuration 3: macOS/BSD Default (LibreSSL + kqueue, HFT-optimized)
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
#ifdef USE_LIBRESSL
using MacOSDefault = WebSocketClient<
    LibreSSLPolicy,
    KqueuePolicy,
    RingBuffer<32 * 1024 * 1024>,  // 32MB RX buffer (HFT: market data ingestion)
    RingBuffer<2 * 1024 * 1024>    // 2MB TX buffer (HFT: order commands)
>;
#else
// Fallback to OpenSSL if LibreSSL not available
using MacOSDefault = WebSocketClient<
    OpenSSLPolicy,
    KqueuePolicy,
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
    DefaultEventPolicy,
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
    DefaultEventPolicy,
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
    DefaultEventPolicy,
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
// Custom Configuration Example
// ============================================================================
// You can create your own custom configuration:
//
// using MyCustomClient = WebSocketClient<
//     OpenSSLPolicy,
//     EpollPolicy,
//     RingBuffer<2 * 1024 * 1024>,  // 2MB RX
//     RingBuffer<512 * 1024>         // 512KB TX
// >;
