// test/integration/binance.cpp
// Integration test: Connect to Binance WebSocket and print first 20 messages
// URL: wss://stream.binance.com:443/stream?streams=btcusdt@trade&timeUnit=MICROSECOND
// Includes high-resolution timing from NIC to application callback

#include "../../src/ws_configs.hpp"
#include "../../src/core/timing.hpp"
#include <cstdio>
#include <cstdlib>
#include <atomic>

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
        int64_t stage1_to_stage2_ns = stage2_monotonic_ns - timing.hw_timestamp_latest_ns;
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

int main() {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║        Binance WebSocket Integration Test with Timing             ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");
    printf("Target: wss://stream.binance.com:443\n");
    printf("Stream: btcusdt@trade with MICROSECOND timeUnit\n");
    printf("Goal: Receive first %d messages with latency breakdown\n\n", MAX_MESSAGES);

    try {
        // Calibrate TSC frequency
        printf("⏱️  Calibrating CPU TSC frequency...\n");
        g_tsc_freq_hz = calibrate_tsc_freq();
        printf("✅ TSC frequency: %.2f GHz\n\n", g_tsc_freq_hz / 1e9);

        // Create WebSocket client with default configuration
        DefaultWebSocket client;
        g_client = &client;

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
