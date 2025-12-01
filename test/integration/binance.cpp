// test/integration/binance.cpp
// Integration test: Connect to Binance WebSocket and print first 20 messages
// URL: wss://stream.binance.com:443/stream?streams=btcusdt@trade&timeUnit=MICROSECOND
// Includes high-resolution timing from NIC to application callback
//
// Build modes:
//   BSD sockets:  make test_binance
//   XDP mode:     USE_XDP=1 make test_binance
//
// Usage:
//   BSD sockets:  ./build/test_binance
//   XDP mode:     sudo ./build/test_binance <interface> [bpf_obj]
//                 sudo ./build/test_binance enp108s0

#include "../../src/ws_configs.hpp"
#include "../../src/core/timing.hpp"
#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <vector>
#include <string>
#include <netdb.h>
#include <arpa/inet.h>

// Global message counter
std::atomic<int> message_count{0};
constexpr int MAX_MESSAGES = 20;

// Global client pointer for signal handling
DefaultWebSocket* g_client = nullptr;

// TSC frequency for timing conversion
uint64_t g_tsc_freq_hz = 0;

void on_message(const uint8_t* data, size_t len, const timing_record_t& timing) {
    // ┌─────────────────────────────────────────────────────┐
    // │ STAGE 6: Callback entry - record both timestamps   │
    // └─────────────────────────────────────────────────────┘
    uint64_t stage6_cycle = rdtscp();                           // For TSC deltas
    uint64_t stage6_monotonic_ns = get_monotonic_timestamp_ns();  // For CLOCK_MONOTONIC delta

    int current_count = message_count.fetch_add(1) + 1;

    printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║ Message %d/%d - %zu bytes                                        \n",
           current_count, MAX_MESSAGES, len);
    printf("╚════════════════════════════════════════════════════════════════════╝\n");

    // Display message content (truncated if too long)
    printf("\n📩 Payload:\n");
    printf("----------------------------------------\n");
    if (len > 500) {
        printf("%.*s...[truncated]\n", 500, data);
    } else {
        printf("%.*s\n", static_cast<int>(len), data);
    }
    printf("----------------------------------------\n");

    // Display detailed timing breakdown
    printf("\n⏱️  Latency Breakdown (CPU cycles → microseconds):\n");
    printf("══════════════════════════════════════════════════════════════════\n");
    print_timing_record(timing, g_tsc_freq_hz);

    // Calculate and display Stage 6 deltas
    printf("\n  [Stage 6] Callback:     %lu cycles", stage6_cycle);
    if (g_tsc_freq_hz > 0 && stage6_cycle > 0 && timing.frame_parsed_cycle > 0) {
        uint64_t delta = stage6_cycle - timing.frame_parsed_cycle;
        printf(" → Δ%.3f μs from Stage 5\n", cycles_to_ns(delta, g_tsc_freq_hz) / 1000.0);
    } else {
        printf("\n");
    }

    // Calculate Stage 1→2 if hardware timestamps available
    if (timing.hw_timestamp_count > 0 && timing.hw_timestamp_latest_ns > 0 && timing.event_cycle > 0) {
        // Calculate Stage 2 time in CLOCK_MONOTONIC domain:
        // stage2_time = stage6_time - (stage6_cycle - stage2_cycle) / cpu_freq
        uint64_t stage2_to_stage6_ns = cycles_to_ns(stage6_cycle - timing.event_cycle, g_tsc_freq_hz);
        uint64_t stage2_monotonic_ns = stage6_monotonic_ns - stage2_to_stage6_ns;

#ifdef USE_XDP
        // XDP mode: hw_timestamp_latest_ns is in CLOCK_REALTIME domain (NIC PHC synced to system time)
        // Convert from CLOCK_REALTIME to CLOCK_MONOTONIC for proper comparison
        struct timespec ts_real;
        clock_gettime(CLOCK_REALTIME, &ts_real);
        uint64_t realtime_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;
        // hw_ts_monotonic = hw_ts_realtime - realtime_now + monotonic_now
        int64_t hw_timestamp_mono_ns = (int64_t)timing.hw_timestamp_latest_ns -
                                       (int64_t)realtime_now_ns + (int64_t)stage6_monotonic_ns;
        int64_t stage1_to_stage2_ns = (int64_t)stage2_monotonic_ns - hw_timestamp_mono_ns;
#else
        // BSD socket mode: drain_hw_timestamps() already converts to CLOCK_MONOTONIC
        int64_t stage1_to_stage2_ns = stage2_monotonic_ns - timing.hw_timestamp_latest_ns;
#endif
        printf("\n  [Stage 1→2] NIC→Event:  %.3f μs (%u packet%s timestamped%s)\n",
               stage1_to_stage2_ns / 1000.0,
               timing.hw_timestamp_count,
               timing.hw_timestamp_count > 1 ? "s" : "",
               timing.hw_timestamp_count > 1 ? " - QUEUE BUILDUP!" : "");
    } else {
        printf("\n  [Stage 1→2] NIC→Event:  N/A (hardware timestamps not available)\n");
    }

    // Total latency
    if (g_tsc_freq_hz > 0 && stage6_cycle > 0 && timing.event_cycle > 0) {
        uint64_t total_cycles = stage6_cycle - timing.event_cycle;
        printf("  [Total] Event→Callback: %.3f μs\n",
               cycles_to_ns(total_cycles, g_tsc_freq_hz) / 1000.0);
    }

    printf("══════════════════════════════════════════════════════════════════\n");

    // Exit after receiving MAX_MESSAGES
    if (current_count >= MAX_MESSAGES) {
        printf("\n✅ Received %d messages. Test complete!\n", MAX_MESSAGES);
        if (g_client) {
            g_client->disconnect();
        }
    }
}

// Resolve hostname to IP addresses (for XDP BPF filter)
#ifdef USE_XDP
std::vector<std::string> resolve_hostname(const char* hostname) {
    std::vector<std::string> ips;

    struct addrinfo hints = {};
    struct addrinfo* result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(hostname, nullptr, &hints, &result);
    if (ret != 0 || !result) {
        if (result) freeaddrinfo(result);
        return ips;
    }

    for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            auto* addr = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            ips.push_back(ip_str);
        }
    }

    freeaddrinfo(result);
    return ips;
}
#endif

int main(int argc, char** argv) {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
#ifdef USE_XDP
    printf("║   Binance WebSocket Test with Timing (AF_XDP Zero-Copy Mode)      ║\n");
#else
    printf("║        Binance WebSocket Integration Test with Timing             ║\n");
#endif
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");
    printf("Target: wss://stream.binance.com:443\n");
    printf("Stream: btcusdt@trade with MICROSECOND timeUnit\n");
    printf("Goal: Receive first %d messages with latency breakdown\n\n", MAX_MESSAGES);

#ifdef USE_XDP
    // XDP mode requires interface argument
    const char* interface = "enp108s0";  // Default interface
    const char* bpf_obj = "src/xdp/bpf/exchange_filter.bpf.o";  // Default BPF object

    if (argc > 1) {
        interface = argv[1];
    }
    if (argc > 2) {
        bpf_obj = argv[2];
    }

    printf("🔧 XDP Mode Configuration:\n");
    printf("   Interface: %s\n", interface);
    printf("   BPF Object: %s\n\n", bpf_obj);
#else
    (void)argc;
    (void)argv;
#endif

    try {
        // Calibrate TSC frequency
        printf("⏱️  Calibrating CPU TSC frequency...\n");
        g_tsc_freq_hz = calibrate_tsc_freq();
        printf("✅ TSC frequency: %.2f GHz\n\n", g_tsc_freq_hz / 1e9);

        // Create WebSocket client with default configuration
        DefaultWebSocket client;
        g_client = &client;

#ifdef USE_XDP
        // XDP mode: Initialize transport before connect
        printf("🔌 Resolving stream.binance.com for BPF filter...\n");
        auto binance_ips = resolve_hostname("stream.binance.com");
        if (binance_ips.empty()) {
            throw std::runtime_error("Failed to resolve stream.binance.com");
        }
        printf("   Found %zu IP(s)\n", binance_ips.size());

        // Initialize XDP with resolved IPs
        client.init_xdp(interface, bpf_obj, binance_ips, 443);
        printf("\n");
#endif

        // Connect to Binance WebSocket
        printf("🔌 Connecting to stream.binance.com:443...\n");
        client.connect("stream.binance.com", 443, "/stream?streams=btcusdt@trade&timeUnit=MICROSECOND");

        printf("✅ Connected successfully!\n");
        printf("📡 Waiting for messages with timing instrumentation...\n");
        printf("    Measuring latency at 6 stages from network to callback\n\n");

        // Run event loop (will exit when disconnect() is called)
        client.run(on_message);

        printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
        printf("║ Test Complete - Statistics                                        ║\n");
        printf("╚════════════════════════════════════════════════════════════════════╝\n");
        printf("   Total messages received: %d\n", message_count.load());
        printf("   TSC frequency: %.2f GHz\n", g_tsc_freq_hz / 1e9);
        printf("   Connection status: Closed\n\n");

        return 0;

    } catch (const std::exception& e) {
        fprintf(stderr, "\n❌ Error: %s\n", e.what());
        return 1;
    }
}
