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

// Global message counter
std::atomic<int> message_count{0};
constexpr int MAX_MESSAGES = 20;

// Global client pointer for signal handling
DefaultWebSocket* g_client = nullptr;

// TSC frequency for timing conversion
uint64_t g_tsc_freq_hz = 0;

// Pre-calculated timing for each message
struct MessageTiming {
    uint64_t parse_cycle;
    uint64_t callback_cycle;
    double stage5_to_6_us;      // Parse → Callback
    double stage1_to_2_us;      // NIC → Event (if available)
    double total_us;            // Event → Callback
    bool hw_ts_available;
};

bool on_messages(const MessageInfo* msgs, size_t count, const timing_record_t& timing) {
    // Stage 6: Callback entry - capture immediately
    uint64_t stage6_cycle = rdtscp();
    uint64_t stage6_monotonic_ns = get_monotonic_timestamp_ns();

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 1: Calculate all timing (no I/O)
    // ═══════════════════════════════════════════════════════════════════

    // Pre-calculate shared timing values
    double stage2_to_3_us = 0, stage3_to_4_us = 0;
    double stage1_to_2_us = 0;
    bool hw_ts_available = false;

    if (g_tsc_freq_hz > 0) {
        // Non-XDP: no separate event loop cycle, so stage 2->3 is always 0
        // (recv_start_cycle is our earliest reference point)
        (void)stage2_to_3_us;
        if (timing.recv_end_cycle > timing.recv_start_cycle) {
            stage3_to_4_us = cycles_to_ns(timing.recv_end_cycle - timing.recv_start_cycle, g_tsc_freq_hz) / 1000.0;
        }

        // Stage 1→2 calculation (shared for batch)
        if (timing.hw_timestamp_count > 0 && timing.hw_timestamp_latest_ns > 0 && timing.recv_start_cycle > 0) {
            hw_ts_available = true;
            uint64_t stage2_to_stage6_ns = cycles_to_ns(stage6_cycle - timing.recv_start_cycle, g_tsc_freq_hz);
            uint64_t stage2_monotonic_ns = stage6_monotonic_ns - stage2_to_stage6_ns;
#ifdef USE_XDP
            struct timespec ts_real;
            clock_gettime(CLOCK_REALTIME, &ts_real);
            uint64_t realtime_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;
            int64_t hw_timestamp_mono_ns = (int64_t)timing.hw_timestamp_latest_ns -
                                           (int64_t)realtime_now_ns + (int64_t)stage6_monotonic_ns;
            stage1_to_2_us = ((int64_t)stage2_monotonic_ns - hw_timestamp_mono_ns) / 1000.0;
#else
            stage1_to_2_us = ((int64_t)stage2_monotonic_ns - (int64_t)timing.hw_timestamp_latest_ns) / 1000.0;
#endif
        }
    }

    // Calculate per-message timing
    static MessageTiming msg_timings[256];  // Max batch size
    size_t process_count = (count > 256) ? 256 : count;

    for (size_t i = 0; i < process_count; i++) {
        const MessageInfo& msg = msgs[i];
        MessageTiming& mt = msg_timings[i];

        mt.parse_cycle = msg.parse_cycle;
        mt.callback_cycle = stage6_cycle;
        mt.hw_ts_available = hw_ts_available;
        mt.stage1_to_2_us = stage1_to_2_us;

        if (g_tsc_freq_hz > 0 && stage6_cycle > 0 && msg.parse_cycle > 0) {
            mt.stage5_to_6_us = cycles_to_ns(stage6_cycle - msg.parse_cycle, g_tsc_freq_hz) / 1000.0;
        } else {
            mt.stage5_to_6_us = 0;
        }

        if (g_tsc_freq_hz > 0 && stage6_cycle > 0 && timing.recv_start_cycle > 0) {
            mt.total_us = cycles_to_ns(stage6_cycle - timing.recv_start_cycle, g_tsc_freq_hz) / 1000.0;
        } else {
            mt.total_us = 0;
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // PHASE 2: Print all messages and stats
    // ═══════════════════════════════════════════════════════════════════

#ifdef USE_XDP
    // RX polled stats from timing record (captured before reset in websocket.hpp)
    printf("\n[RX polled: %lu bytes, %u pkts]",
           timing.hw_timestamp_byte_count, timing.hw_timestamp_count);

    // Consumed stats (packets consumed via recv() for SSL)
    uint32_t ssl_pkt_count = 0;
    if (g_client) {
        auto& transport = g_client->transport();
        ssl_pkt_count = transport.get_recv_packet_count();
        transport.reset_recv_stats();
    }

    // Display SSL_read stats using consumed packet count
    printf("\n┌─ SSL_read: %zd bytes → %zu frame%s, %u pkt%s ─┐\n",
           timing.ssl_read_bytes,
           count, count > 1 ? "s" : "",
           ssl_pkt_count, ssl_pkt_count != 1 ? "s" : "");
#else
    (void)g_client;  // Suppress unused warning in non-XDP mode

    // Display SSL_read stats using hw_timestamp_count from timing record
    printf("\n┌─ SSL_read: %zd bytes → %zu frame%s, %u pkt%s ─┐\n",
           timing.ssl_read_bytes,
           count, count > 1 ? "s" : "",
           timing.hw_timestamp_count, timing.hw_timestamp_count != 1 ? "s" : "");
#endif

    // Print per-message: header + payload
    bool should_exit = false;
    for (size_t i = 0; i < process_count; i++) {
        const MessageInfo& msg = msgs[i];
        int current_count = message_count.fetch_add(1) + 1;

        // Header
        printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
        if (count > 1) {
            printf("║ Message %d/%d - %zu bytes [%zu/%zu in batch]\n",
                   current_count, MAX_MESSAGES, msg.len, i + 1, count);
        } else {
            printf("║ Message %d/%d - %zu bytes\n",
                   current_count, MAX_MESSAGES, msg.len);
        }
        printf("╚════════════════════════════════════════════════════════════════════╝\n");

        // Payload
        printf("\n📩 Payload:\n");
        printf("────────────────────────────────────────────────────────────────────\n");
        if (msg.len > 500) {
            printf("%.*s...[truncated]\n", 500, msg.payload);
        } else {
            printf("%.*s\n", static_cast<int>(msg.len), msg.payload);
        }

        if (current_count >= MAX_MESSAGES) {
            should_exit = true;
        }
    }

    // Print once per batch: Latency breakdown (shared timing for all messages)
    const MessageTiming& mt = msg_timings[0];
    printf("\n⏱️  Latency Breakdown:\n");
    printf("────────────────────────────────────────────────────────────────────\n");
    if (mt.hw_ts_available) {
        printf("  [1→2] NIC → Event:     %7.3f μs  (%u pkt%s)\n",
               mt.stage1_to_2_us, timing.hw_timestamp_count,
               timing.hw_timestamp_count > 1 ? "s" : "");
    } else {
        printf("  [1→2] NIC → Event:         N/A    (no HW timestamp)\n");
    }
    printf("  [2→3] Event → Recv:    %7.3f μs\n", stage2_to_3_us);
    printf("  [3→4] SSL decrypt:     %7.3f μs\n", stage3_to_4_us);
    printf("  [5→6] Parse → Callback:%7.3f μs\n", mt.stage5_to_6_us);
    printf("  ─────────────────────────────────\n");
    printf("  [2→6] Event → Callback:%7.3f μs\n", mt.total_us);
    printf("════════════════════════════════════════════════════════════════════\n");

    // Exit after receiving MAX_MESSAGES
    if (should_exit) {
        printf("\n✅ Received %d messages. Test complete!\n", MAX_MESSAGES);
        if (g_client) {
            g_client->disconnect();
        }
        return false;  // Signal to stop the run() loop
    }
    return true;  // Continue receiving
}


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
        // XDP mode: Initialize transport before connect (resolves DNS internally)
        client.init_xdp(interface, bpf_obj, "stream.binance.com", 443);
        printf("\n");
#endif

        // Connect to Binance WebSocket
        printf("🔌 Connecting to stream.binance.com:443...\n");
        client.connect("stream.binance.com", 443, "/stream?streams=btcusdt@trade&timeUnit=MICROSECOND");

        printf("✅ Connected successfully!\n");
        printf("📡 Waiting for messages with timing instrumentation...\n");
        printf("    Measuring latency at 6 stages from network to callback\n\n");

        // Run event loop (will exit when disconnect() is called)
        client.run(on_messages);

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
