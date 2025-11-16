// examples/policy_demo.cpp
// Demonstrates the flexibility of policy-based design with different configurations
#include "../src/ws_configs.hpp"
#include <cstdio>
#include <cstdlib>

// Example: Using different configurations based on requirements

void example_default_config() {
    printf("\n=== Example 1: Default Configuration ===\n");

    // DefaultWebSocket automatically selects the best config for your platform
    // Linux: epoll + OpenSSL + kTLS
    // macOS: kqueue + OpenSSL
    DefaultWebSocket client;

    printf("Configuration: DefaultWebSocket\n");
    printf("  - Automatically optimized for platform\n");
    printf("  - 8MB RX/TX buffers\n");
    printf("  - kTLS enabled on Linux (if available)\n");
}

void example_low_memory() {
    printf("\n=== Example 2: Low Memory Configuration ===\n");

#ifdef __linux__
    // Use smaller buffers when memory is constrained
    LowMemory client;

    printf("Configuration: LowMemory\n");
    printf("  - 4MB RX/TX buffers (half of default)\n");
    printf("  - Same performance characteristics\n");
    printf("  - Better for embedded systems\n");
#else
    printf("LowMemory configuration only available on Linux\n");
#endif
}

void example_high_throughput() {
    printf("\n=== Example 3: High Throughput Configuration ===\n");

#ifdef __linux__
    // Use larger buffers for high message rates
    HighThroughput client;

    printf("Configuration: HighThroughput\n");
    printf("  - 16MB RX/TX buffers (double default)\n");
    printf("  - Handles burst traffic better\n");
    printf("  - Reduces buffer overruns\n");
#else
    printf("HighThroughput configuration only available on Linux\n");
#endif
}

void example_asymmetric() {
    printf("\n=== Example 4: Asymmetric Buffers ===\n");

#ifdef __linux__
    // Large RX buffer for market data, small TX for commands
    AsymmetricBuffers client;

    printf("Configuration: AsymmetricBuffers\n");
    printf("  - 16MB RX buffer (receive market data)\n");
    printf("  - 1MB TX buffer (send commands)\n");
    printf("  - Optimized for typical HFT pattern\n");
#else
    printf("AsymmetricBuffers configuration only available on Linux\n");
#endif
}

void example_custom() {
    printf("\n=== Example 5: Custom Configuration ===\n");

#ifdef __linux__
    // Create completely custom configuration
    using CustomClient = WebSocketClient<
        BSDSocketPolicy,
        OpenSSLPolicy,
        EpollPolicy,
        KTLSTransport,
        RingBuffer<2 * 1024 * 1024>,  // 2MB RX
        RingBuffer<512 * 1024>         // 512KB TX
    >;

    CustomClient client;

    printf("Configuration: Custom\n");
    printf("  - Custom buffer sizes: 2MB RX, 512KB TX\n");
    printf("  - Mix and match any policies\n");
    printf("  - Full control over behavior\n");
#else
    printf("Custom configuration example only shown on Linux\n");
#endif
}

void example_explicit_policies() {
    printf("\n=== Example 6: Explicit Policy Specification ===\n");

#ifdef __linux__
    // Explicitly specify all 6 policies
    using ExplicitClient = WebSocketClient<
        BSDSocketPolicy,           // Socket: BSD socket.h API
        OpenSSLPolicy,             // SSL: OpenSSL with kTLS support
        EpollPolicy,               // Event: epoll edge-triggered
        KTLSTransport,             // Transport: kernel TLS offload
        RingBuffer<8192 * 1024>,   // RX Buffer: 8MB
        RingBuffer<8192 * 1024>    // TX Buffer: 8MB
    >;

    ExplicitClient client;

    printf("Configuration: Explicit\n");
    printf("  All 6 policy dimensions specified:\n");
    printf("    1. SocketPolicy: BSDSocketPolicy\n");
    printf("    2. SSLPolicy: OpenSSLPolicy\n");
    printf("    3. EventPolicy: EpollPolicy\n");
    printf("    4. TransportPolicy: KTLSTransport\n");
    printf("    5. RxBufferPolicy: RingBuffer<8MB>\n");
    printf("    6. TxBufferPolicy: RingBuffer<8MB>\n");
#else
    printf("Explicit configuration example only shown on Linux\n");
#endif
}

int main() {
    printf("========================================\n");
    printf("WebSocket Policy-Based Design Demo\n");
    printf("========================================\n");
    printf("\nThis demo shows how policies can be combined\n");
    printf("to create optimized configurations for different use cases.\n");

    // Show all configuration examples
    example_default_config();
    example_low_memory();
    example_high_throughput();
    example_asymmetric();
    example_custom();
    example_explicit_policies();

    printf("\n========================================\n");
    printf("Key Benefits of Policy-Based Design:\n");
    printf("========================================\n");
    printf("1. Zero runtime overhead (compile-time dispatch)\n");
    printf("2. Mix and match policies freely\n");
    printf("3. Type-safe configurations\n");
    printf("4. Single codebase for all variants\n");
    printf("5. Easy to add new policies\n");
    printf("6. Exponential combinations from linear policies\n");

    printf("\n========================================\n");
    printf("Your Configurations:\n");
    printf("========================================\n");
    printf("Config 1: socket.h + OpenSSL + kTLS + epoll\n");
    printf("  = LinuxOptimized\n");
    printf("\nConfig 2: io_uring + WolfSSL\n");
    printf("  = IoUringWolfSSL (experimental)\n");
    printf("\nConfig 3: macOS + LibreSSL + kqueue\n");
    printf("  = MacOSDefault\n");

    return 0;
}
