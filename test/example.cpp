// test/example.cpp
// Minimal example: Connect to Binance WebSocket and print messages with timing

#include "../src/ws_configs.hpp"
#include "../src/core/timing.hpp"
#include <cstdio>
#include <csignal>
#include <atomic>

// Global flag for graceful shutdown
std::atomic<bool> running{true};

// Global client pointer for signal handling
DefaultWebSocket* g_client = nullptr;

// TSC frequency for timing conversion
uint64_t g_tsc_freq_hz = 0;

// Message counter
std::atomic<uint64_t> message_count{0};

// Signal handler for Ctrl+C
void signal_handler(int signal) {
    if (signal == SIGINT) {
        printf("\n[SIGNAL] Caught SIGINT, shutting down...\n");
        running = false;
        if (g_client) {
            g_client->disconnect();
        }
    }
}

// Message callback - prints received messages with timing
void on_message(const uint8_t* data, size_t len, const timing_record_t& timing) {
    // Stage 6: Record callback entry
    uint64_t stage6_cycle = rdtscp();
    uint64_t stage6_monotonic_ns = get_monotonic_timestamp_ns();

    uint64_t msg_num = message_count.fetch_add(1) + 1;

    // Print message content
    printf("\n[Message #%lu] %zu bytes: %.*s\n",
           msg_num, len, static_cast<int>(len), data);

    // Calculate and display timing breakdown
    printf("Latency breakdown:\n");

    // Stage 1→2: NIC to Event Loop (if hardware timestamp available)
    if (timing.hw_timestamp_ns > 0 && timing.event_cycle > 0 && g_tsc_freq_hz > 0) {
        // Convert stage 2 cycle to CLOCK_MONOTONIC
        uint64_t stage2_to_stage6_ns = cycles_to_ns(stage6_cycle - timing.event_cycle, g_tsc_freq_hz);
        uint64_t stage2_monotonic_ns = stage6_monotonic_ns - stage2_to_stage6_ns;
        int64_t stage1_to_2_ns = stage2_monotonic_ns - timing.hw_timestamp_ns;
        printf("  [1→2] NIC→Event:       %7.3f μs\n", stage1_to_2_ns / 1000.0);
    }

    // Stage 2→3: Event Loop to SSL_read start
    if (g_tsc_freq_hz > 0 && timing.recv_start_cycle > 0 && timing.event_cycle > 0) {
        uint64_t delta_ns = cycles_to_ns(timing.recv_start_cycle - timing.event_cycle, g_tsc_freq_hz);
        printf("  [2→3] Event→SSL start: %7.3f μs\n", delta_ns / 1000.0);
    }

    // Stage 3→4: SSL_read duration (decryption)
    if (g_tsc_freq_hz > 0 && timing.recv_end_cycle > 0 && timing.recv_start_cycle > 0) {
        uint64_t delta_ns = cycles_to_ns(timing.recv_end_cycle - timing.recv_start_cycle, g_tsc_freq_hz);
        printf("  [3→4] SSL decryption:  %7.3f μs\n", delta_ns / 1000.0);
    }

    // Stage 4→5: WebSocket frame parsing
    if (g_tsc_freq_hz > 0 && timing.frame_parsed_cycle > 0 && timing.recv_end_cycle > 0) {
        uint64_t delta_ns = cycles_to_ns(timing.frame_parsed_cycle - timing.recv_end_cycle, g_tsc_freq_hz);
        printf("  [4→5] Frame parsing:   %7.3f μs\n", delta_ns / 1000.0);
    }

    // Stage 5→6: Frame to callback
    if (g_tsc_freq_hz > 0 && stage6_cycle > 0 && timing.frame_parsed_cycle > 0) {
        uint64_t delta_ns = cycles_to_ns(stage6_cycle - timing.frame_parsed_cycle, g_tsc_freq_hz);
        printf("  [5→6] Frame→Callback:  %7.3f μs\n", delta_ns / 1000.0);
    }

    // Total: Event Loop to Callback
    if (g_tsc_freq_hz > 0 && stage6_cycle > 0 && timing.event_cycle > 0) {
        uint64_t total_ns = cycles_to_ns(stage6_cycle - timing.event_cycle, g_tsc_freq_hz);
        printf("  [Total] Event→Callback:%7.3f μs\n", total_ns / 1000.0);
    }

    // Optional: Exit after first message (for quick test)
    // running = false;
    // if (g_client) {
    //     g_client->disconnect();
    // }
}

int main() {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║         Minimal WebSocket Example with Timing                 ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");

    // Setup signal handler
    signal(SIGINT, signal_handler);

    // Calibrate TSC frequency for accurate timing
    printf("Calibrating CPU timestamp counter...\n");
    g_tsc_freq_hz = calibrate_tsc_freq();
    if (g_tsc_freq_hz > 0) {
        printf("TSC frequency: %.2f GHz\n\n", g_tsc_freq_hz / 1e9);
    } else {
        printf("Warning: TSC calibration failed, timing may be inaccurate\n\n");
    }

    try {
        // Create WebSocket client
        DefaultWebSocket client;
        g_client = &client;

        printf("Connecting to Binance WebSocket...\n");

        // Connect to Binance
        client.connect("stream.binance.com", 443, "/stream?streams=btcusdt@trade");

        printf("Connected! Receiving BTC/USDT trades (press Ctrl+C to exit)...\n");
        printf("Latency breakdown will be shown for each message.\n\n");

        // Run event loop (will block until disconnected or signal)
        client.run(on_message);

        printf("\n════════════════════════════════════════════════════════════════\n");
        printf("Disconnected.\n");
        printf("Total messages received: %lu\n", message_count.load());
        printf("════════════════════════════════════════════════════════════════\n");

    } catch (const std::exception& e) {
        fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }

    return 0;
}
