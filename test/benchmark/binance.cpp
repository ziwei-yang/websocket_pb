// test/benchmark/binance.cpp
// Benchmark test: Statistical analysis of WebSocket latency from Binance
// URL: wss://stream.binance.com:443/stream?streams=btcusdt@trade&timeUnit=MICROSECOND
//
// Methodology:
//   1. Warmup: 100 messages (discard)
//   2. Benchmark: 300 messages (collect statistics)
//   3. Analyze: Min/Max/Mean/Median/P90/P95/P99 for all 6 stages
//
// Build modes:
//   BSD sockets:  make benchmark-binance
//   XDP mode:     USE_XDP=1 USE_OPENSSL=1 make benchmark-binance
//
// Usage:
//   BSD sockets:  ./build/benchmark_binance [warmup_count] [benchmark_count]
//   XDP mode:     sudo ./build/benchmark_binance <interface> [warmup_count] [benchmark_count]
//                 sudo ./build/benchmark_binance enp40s0 50 150

#include "../../src/ws_configs.hpp"
#include "../../src/core/timing.hpp"
#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <vector>
#include <algorithm>
#include <cmath>
#include <string>

// Configuration (adjustable via command line or defaults)
constexpr int DEFAULT_WARMUP_COUNT = 100;
constexpr int DEFAULT_BENCHMARK_COUNT = 300;

int WARMUP_COUNT = DEFAULT_WARMUP_COUNT;
int BENCHMARK_COUNT = DEFAULT_BENCHMARK_COUNT;
int TOTAL_COUNT = WARMUP_COUNT + BENCHMARK_COUNT;

// Global state
std::atomic<int> message_count{0};
DefaultWebSocket* g_client = nullptr;
uint64_t g_tsc_freq_hz = 0;

// Latency data storage
struct LatencyData {
    double stage1_to_stage2_us;  // NIC RX → Event loop
    double stage2_to_stage3_us;  // Event loop → Recv start
    double stage3_to_stage4_us;  // SSL decryption
    double stage4_to_stage5_us;  // WebSocket parsing
    double stage5_to_stage6_us;  // Callback invocation
    double total_us;             // Stage 2 → Stage 6
    double end_to_end_us;        // Stage 1 → Stage 6
};

std::vector<LatencyData> latency_samples;

// Statistics structure
struct Stats {
    double min;
    double max;
    double mean;
    double median;
    double stddev;
    double p90;
    double p95;
    double p99;
};

// Calculate statistics from vector of values
Stats calculate_stats(std::vector<double> values) {
    if (values.empty()) {
        return {0, 0, 0, 0, 0, 0, 0, 0};
    }

    std::sort(values.begin(), values.end());

    Stats stats;
    stats.min = values.front();
    stats.max = values.back();

    // Mean
    double sum = 0;
    for (double v : values) {
        sum += v;
    }
    stats.mean = sum / values.size();

    // Standard deviation
    double variance = 0;
    for (double v : values) {
        double diff = v - stats.mean;
        variance += diff * diff;
    }
    stats.stddev = std::sqrt(variance / values.size());

    // Percentiles
    auto percentile = [&](double p) -> double {
        size_t idx = static_cast<size_t>(p * values.size());
        if (idx >= values.size()) idx = values.size() - 1;
        return values[idx];
    };

    stats.median = percentile(0.50);
    stats.p90 = percentile(0.90);
    stats.p95 = percentile(0.95);
    stats.p99 = percentile(0.99);

    return stats;
}

// Print statistics table
void print_stats_table(const char* stage_name, const Stats& stats) {
    printf("  %-25s %9.2f %9.2f %9.2f %9.2f %9.2f %9.2f %9.2f %9.2f\n",
           stage_name,
           stats.min,
           stats.max,
           stats.mean,
           stats.median,
           stats.stddev,
           stats.p90,
           stats.p95,
           stats.p99);
}

// Batch message callback
bool on_messages(const MessageInfo* msgs, size_t count, const timing_record_t& timing) {
    // ┌─────────────────────────────────────────────────────┐
    // │ STAGE 6: Callback entry - record both timestamps   │
    // └─────────────────────────────────────────────────────┘
    uint64_t stage6_cycle = rdtscp();                      // For Stage 2→6 delta (TSC)
    uint64_t stage6_monotonic_ns = get_monotonic_timestamp_ns();  // For Stage 1→6 delta (CLOCK_MONOTONIC)

    // Pre-calculate shared timing values (batch-level)
    double stage2_to_3_us = 0, stage3_to_4_us = 0;
    double stage1_to_2_us = 0;
    bool hw_ts_available = false;

    if (g_tsc_freq_hz > 0) {
        // Stage 2 → Stage 3: Event loop to recv start
        // Non-XDP: no separate event loop cycle, so this is always 0
        // (recv_start_cycle is our earliest reference point)

        // Stage 3 → Stage 4: SSL decryption
        if (timing.recv_end_cycle > timing.recv_start_cycle) {
            stage3_to_4_us = cycles_to_ns(timing.recv_end_cycle - timing.recv_start_cycle, g_tsc_freq_hz) / 1000.0;
        }

        // Stage 1 → Stage 2: NIC RX to recv start
        if (timing.hw_timestamp_count > 0 && timing.hw_timestamp_latest_ns > 0 && timing.recv_start_cycle > 0) {
            hw_ts_available = true;
            uint64_t stage2_to_stage6_ns = cycles_to_ns(stage6_cycle - timing.recv_start_cycle, g_tsc_freq_hz);
            uint64_t stage2_monotonic_ns = stage6_monotonic_ns - stage2_to_stage6_ns;

#ifdef USE_XDP
            // XDP mode: hw_timestamp is CLOCK_REALTIME, convert to CLOCK_MONOTONIC
            struct timespec ts_real;
            clock_gettime(CLOCK_REALTIME, &ts_real);
            uint64_t realtime_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;
            int64_t hw_timestamp_mono_ns = (int64_t)timing.hw_timestamp_latest_ns -
                                           (int64_t)realtime_now_ns + (int64_t)stage6_monotonic_ns;
            stage1_to_2_us = ((int64_t)stage2_monotonic_ns - hw_timestamp_mono_ns) / 1000.0;
#else
            // BSD socket mode: hw_timestamp is already CLOCK_MONOTONIC
            int64_t delta_ns = stage2_monotonic_ns - timing.hw_timestamp_latest_ns;
            stage1_to_2_us = delta_ns / 1000.0;
#endif
        }
    }

    // Process each message in batch
    bool should_exit = false;
    for (size_t i = 0; i < count; i++) {
        const MessageInfo& msg = msgs[i];
        int current_count = message_count.fetch_add(1) + 1;

        // Progress indicator (warmup phase only)
        if (current_count <= WARMUP_COUNT) {
            if (current_count % 10 == 0) {
                printf("\r[WARMUP] %d/%d messages...", current_count, WARMUP_COUNT);
                fflush(stdout);
            }
            if (current_count == WARMUP_COUNT) {
                printf("\r[WARMUP] Complete! Collected %d messages    \n", WARMUP_COUNT);
                printf("[BENCHMARK] Starting data collection...\n");
            }
            continue;  // Skip warmup messages
        }

        // Calculate latencies for this message
        LatencyData latency;

        // Use shared batch timing for stages 1-4
        latency.stage1_to_stage2_us = hw_ts_available ? stage1_to_2_us : 0;
        latency.stage2_to_stage3_us = stage2_to_3_us;
        latency.stage3_to_stage4_us = stage3_to_4_us;

        // Stage 4 → Stage 5: WebSocket parsing (use per-message parse_cycle)
        if (msg.parse_cycle > 0 && timing.recv_end_cycle > 0) {
            uint64_t delta_cycles = msg.parse_cycle - timing.recv_end_cycle;
            latency.stage4_to_stage5_us = cycles_to_ns(delta_cycles, g_tsc_freq_hz) / 1000.0;
        } else {
            latency.stage4_to_stage5_us = 0;
        }

        // Stage 5 → Stage 6: Callback invocation (use per-message parse_cycle)
        if (stage6_cycle > 0 && msg.parse_cycle > 0) {
            uint64_t delta_cycles = stage6_cycle - msg.parse_cycle;
            latency.stage5_to_stage6_us = cycles_to_ns(delta_cycles, g_tsc_freq_hz) / 1000.0;
        } else {
            latency.stage5_to_stage6_us = 0;
        }

        // Total (Recv Start → Stage 6)
        if (stage6_cycle > 0 && timing.recv_start_cycle > 0) {
            uint64_t delta_cycles = stage6_cycle - timing.recv_start_cycle;
            latency.total_us = cycles_to_ns(delta_cycles, g_tsc_freq_hz) / 1000.0;
        } else {
            latency.total_us = 0;
        }

        // End-to-end (Stage 1 → Stage 6)
        if (hw_ts_available) {
#ifdef USE_XDP
            // XDP mode: convert hw_timestamp from CLOCK_REALTIME to CLOCK_MONOTONIC
            struct timespec ts_real;
            clock_gettime(CLOCK_REALTIME, &ts_real);
            uint64_t realtime_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;
            int64_t hw_timestamp_mono_ns = (int64_t)timing.hw_timestamp_latest_ns -
                                           (int64_t)realtime_now_ns + (int64_t)stage6_monotonic_ns;
            int64_t delta_ns = stage6_monotonic_ns - hw_timestamp_mono_ns;
            latency.end_to_end_us = delta_ns / 1000.0;
#else
            // BSD socket mode: hw_timestamp is CLOCK_MONOTONIC
            int64_t delta_ns = stage6_monotonic_ns - timing.hw_timestamp_latest_ns;
            latency.end_to_end_us = delta_ns / 1000.0;
#endif
        } else {
            latency.end_to_end_us = latency.total_us;
        }

        // Store latency data
        latency_samples.push_back(latency);

        // Check if benchmark is complete
        if (current_count >= TOTAL_COUNT) {
            should_exit = true;
        }
    }

    // Exit after benchmark is complete
    if (should_exit) {
        printf("\n[BENCHMARK] Complete! Collected %zu samples    \n", latency_samples.size());
        printf("[BENCHMARK] Disconnecting...\n\n");
        if (g_client) {
            g_client->disconnect();
        }
        return false;  // Signal to stop the run() loop
    }
    return true;  // Continue receiving
}

// Print results
void print_results() {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║              Benchmark Results - Latency Statistics               ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    printf("Configuration:\n");
    printf("  Warmup messages:    %d\n", WARMUP_COUNT);
    printf("  Benchmark messages: %d\n", BENCHMARK_COUNT);
    printf("  TSC frequency:      %.2f GHz\n", g_tsc_freq_hz / 1e9);
    printf("  Samples collected:  %zu\n", latency_samples.size());

    // Policy and buffer configuration
    if (g_client) {
        printf("\nPolicy Configuration:\n");

        // SSL/TLS policy
        printf("  TLS Policy:         %s", DefaultWebSocket::SSLPolicy::name());
        if (g_client->ktls_enabled()) {
            printf(" (kTLS enabled)\n");
        } else {
            printf(" (user-space)\n");
        }

        // IO Backend and Transport Policy
#ifdef USE_XDP
        printf("  IO Backend:         SO_BUSY_POLL\n");
        printf("  Transport Policy:   AF_XDP zero-copy + Userspace TCP/IP stack\n");
#elif defined(ENABLE_IO_URING)
        printf("  IO Backend:         io_uring (async I/O)\n");
        printf("  Transport Policy:   BSDSocket + %s\n", DefaultWebSocket::TransportPolicy::event_policy_name());
#else
        printf("  IO Backend:         EventPolicy-based I/O\n");
        printf("  Transport Policy:   BSDSocket + %s\n", DefaultWebSocket::TransportPolicy::event_policy_name());
#endif

        // Ringbuffer configuration
        printf("  RX Buffer:          ");
        printf("size=%zu KB", g_client->get_rx_buffer().capacity() / 1024);
        printf(", mmap=%s", g_client->get_rx_buffer().is_mmap() ? "yes" : "no");
        printf(", mirrored=%s\n", g_client->get_rx_buffer().is_mirrored() ? "yes" : "no");

        printf("  TX Buffer:          ");
        printf("size=%zu KB", g_client->get_tx_buffer().capacity() / 1024);
        printf(", mmap=%s", g_client->get_tx_buffer().is_mmap() ? "yes" : "no");
        printf(", mirrored=%s\n", g_client->get_tx_buffer().is_mirrored() ? "yes" : "no");
    }
    printf("\n");

    if (latency_samples.empty()) {
        printf("❌ No samples collected!\n");
        return;
    }

    // Extract data for each stage
    std::vector<double> stage1_to_2, stage2_to_3, stage3_to_4, stage4_to_5, stage5_to_6, total, end_to_end;

    for (const auto& sample : latency_samples) {
        if (sample.stage1_to_stage2_us > 0) stage1_to_2.push_back(sample.stage1_to_stage2_us);
        if (sample.stage2_to_stage3_us > 0) stage2_to_3.push_back(sample.stage2_to_stage3_us);
        if (sample.stage3_to_stage4_us > 0) stage3_to_4.push_back(sample.stage3_to_stage4_us);
        if (sample.stage4_to_stage5_us > 0) stage4_to_5.push_back(sample.stage4_to_stage5_us);
        if (sample.stage5_to_stage6_us > 0) stage5_to_6.push_back(sample.stage5_to_stage6_us);
        if (sample.total_us > 0) total.push_back(sample.total_us);
        if (sample.end_to_end_us > 0) end_to_end.push_back(sample.end_to_end_us);
    }

    // Calculate statistics
    Stats stats_1_to_2 = calculate_stats(stage1_to_2);
    Stats stats_2_to_3 = calculate_stats(stage2_to_3);
    Stats stats_3_to_4 = calculate_stats(stage3_to_4);
    Stats stats_4_to_5 = calculate_stats(stage4_to_5);
    Stats stats_5_to_6 = calculate_stats(stage5_to_6);
    Stats stats_total = calculate_stats(total);
    Stats stats_e2e = calculate_stats(end_to_end);

    // Print table header
    printf("All values in microseconds (μs)\n\n");
    printf("  %-25s %9s %9s %9s %9s %9s %9s %9s %9s\n",
           "Stage", "Min", "Max", "Mean", "Median", "StdDev", "P90", "P95", "P99");
    printf("  ──────────────────────────────────────────────────────────────────────────────────────────────────\n");

    // Print statistics for each stage
    print_stats_table("Stage 1->2 (NIC->App)", stats_1_to_2);
    print_stats_table("Stage 2->3 (Event)", stats_2_to_3);
    print_stats_table("Stage 3->4 (SSL)", stats_3_to_4);
    print_stats_table("Stage 4->5 (Parse)", stats_4_to_5);
    print_stats_table("Stage 5->6 (Callback)", stats_5_to_6);
    printf("  --------------------------------------------------------------------------------------------------------\n");
    print_stats_table("Total (Stage 2->6)", stats_total);
    print_stats_table("End-to-End (1->6)", stats_e2e);

    printf("\n");

    // Print latency breakdown
    printf("Latency Breakdown (Mean):\n");
    printf("  +---------------------------------------------------------------------+\n");

    double total_mean = stats_1_to_2.mean + stats_total.mean;
    auto print_bar = [&](const char* name, double value, double pct) {
        int bar_len = static_cast<int>(pct / 2);  // Scale to 50 chars max
        printf("  | %-20s %8.2f us [%3.0f%%] ", name, value, pct);
        for (int i = 0; i < bar_len; i++) printf("#");
        printf("\n");
    };

    if (total_mean > 0) {
        print_bar("NIC->Event (1->2)", stats_1_to_2.mean, (stats_1_to_2.mean / total_mean) * 100);
        print_bar("Event loop (2->3)", stats_2_to_3.mean, (stats_2_to_3.mean / total_mean) * 100);
        print_bar("SSL decrypt (3->4)", stats_3_to_4.mean, (stats_3_to_4.mean / total_mean) * 100);
        print_bar("WS parse (4->5)", stats_4_to_5.mean, (stats_4_to_5.mean / total_mean) * 100);
        print_bar("Callback (5->6)", stats_5_to_6.mean, (stats_5_to_6.mean / total_mean) * 100);
    }

    printf("  +---------------------------------------------------------------------+\n");
    printf("  Total: %.2f us\n\n", total_mean);

    // Key insights
    printf("Key Insights:\n");
    printf("  • SSL decryption accounts for %.1f%% of application latency (Stage 2→6)\n",
           (stats_3_to_4.mean / stats_total.mean) * 100);
    printf("  • NIC→Application latency (Stage 1→2): %.2f μs (includes kernel + epoll)\n",
           stats_1_to_2.mean);
    printf("  • Application processing (Stage 2→6): %.2f μs\n", stats_total.mean);
    printf("  • WebSocket parsing overhead: %.2f μs (%.1f%% of total)\n",
           stats_4_to_5.mean, (stats_4_to_5.mean / stats_total.mean) * 100);
    printf("  • 99th percentile end-to-end: %.2f μs\n", stats_e2e.p99);
    printf("\n");

    // Jitter analysis
    printf("Jitter Analysis:\n");
    printf("  • Stage 1→2 jitter (P99-P50): %.2f μs\n", stats_1_to_2.p99 - stats_1_to_2.median);
    printf("  • SSL decrypt jitter (P99-P50): %.2f μs\n", stats_3_to_4.p99 - stats_3_to_4.median);
    printf("  • Total jitter (P99-P50): %.2f μs\n", stats_total.p99 - stats_total.median);
    printf("  • Coefficient of variation: %.1f%%\n", (stats_total.stddev / stats_total.mean) * 100);
    printf("\n");
}

int main(int argc, char* argv[]) {
#ifdef USE_XDP
    // XDP mode: interface [bpf_obj] [warmup] [benchmark]
    const char* interface = "enp108s0";
    const char* bpf_obj = "src/xdp/bpf/exchange_filter.bpf.o";

    if (argc >= 2) {
        interface = argv[1];
    }
    if (argc >= 3) {
        // Check if second arg is a number (warmup) or string (bpf_obj)
        if (argv[2][0] >= '0' && argv[2][0] <= '9') {
            WARMUP_COUNT = atoi(argv[2]);
            if (WARMUP_COUNT < 0) WARMUP_COUNT = DEFAULT_WARMUP_COUNT;
        } else {
            bpf_obj = argv[2];
        }
    }
    if (argc >= 4) {
        // Could be warmup or benchmark
        if (argv[3][0] >= '0' && argv[3][0] <= '9') {
            if (argc >= 3 && argv[2][0] >= '0' && argv[2][0] <= '9') {
                // argv[2] was warmup, argv[3] is benchmark
                BENCHMARK_COUNT = atoi(argv[3]);
            } else {
                // argv[2] was bpf_obj, argv[3] is warmup
                WARMUP_COUNT = atoi(argv[3]);
            }
        }
    }
    if (argc >= 5) {
        BENCHMARK_COUNT = atoi(argv[4]);
        if (BENCHMARK_COUNT < 1) BENCHMARK_COUNT = DEFAULT_BENCHMARK_COUNT;
    }
#else
    // BSD socket mode: [warmup] [benchmark]
    if (argc >= 2) {
        WARMUP_COUNT = atoi(argv[1]);
        if (WARMUP_COUNT < 0) WARMUP_COUNT = DEFAULT_WARMUP_COUNT;
    }
    if (argc >= 3) {
        BENCHMARK_COUNT = atoi(argv[2]);
        if (BENCHMARK_COUNT < 1) BENCHMARK_COUNT = DEFAULT_BENCHMARK_COUNT;
    }
#endif
    TOTAL_COUNT = WARMUP_COUNT + BENCHMARK_COUNT;

    printf("╔════════════════════════════════════════════════════════════════════╗\n");
#ifdef USE_XDP
    printf("║   Binance WebSocket Latency Benchmark (AF_XDP Zero-Copy Mode)     ║\n");
#else
    printf("║           Binance WebSocket Latency Benchmark Test                ║\n");
#endif
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");
    printf("Target: wss://stream.binance.com:443\n");
    printf("Stream: btcusdt@trade with MICROSECOND timeUnit\n");
    printf("Methodology:\n");
    printf("  1. Warmup:    %d messages (discard)\n", WARMUP_COUNT);
    printf("  2. Benchmark: %d messages (collect statistics)\n", BENCHMARK_COUNT);
    printf("  3. Analyze:   Min/Max/Mean/Median/P90/P95/P99\n");

#ifdef USE_XDP
    printf("\nUsage: sudo %s <interface> [bpf_obj] [warmup] [benchmark]\n", argv[0]);
    printf("Example: sudo %s enp108s0 100 300\n\n", argv[0]);
    printf("🔧 XDP Mode Configuration:\n");
    printf("   Interface: %s\n", interface);
    printf("   BPF Object: %s\n\n", bpf_obj);
#else
    printf("\nUsage: %s [warmup_count] [benchmark_count]\n", argv[0]);
    printf("Example: %s 20 100  (20 warmup, 100 benchmark)\n\n", argv[0]);
#endif

    try {
        // Calibrate TSC frequency
        printf("⏱️  Calibrating CPU TSC frequency...\n");
        g_tsc_freq_hz = calibrate_tsc_freq();
        printf("✅ TSC frequency: %.2f GHz\n\n", g_tsc_freq_hz / 1e9);

        // Reserve space for samples
        latency_samples.reserve(BENCHMARK_COUNT);

        // Create WebSocket client
        DefaultWebSocket client;
        g_client = &client;

#ifdef USE_XDP
        // XDP mode: Initialize transport before connect (resolves DNS internally)
        client.transport().init(interface, bpf_obj, "stream.binance.com", 443);
        printf("\n");
#endif

        // Connect to Binance
        printf("🔌 Connecting to stream.binance.com:443...\n");
        client.connect("stream.binance.com", 443, "/stream?streams=btcusdt@trade&timeUnit=MICROSECOND");

        printf("✅ Connected successfully!\n");
        printf("📡 Starting benchmark...\n\n");

        // Run event loop with batch callback
        client.run(on_messages);

        // Check if we collected enough samples
        if (latency_samples.size() < static_cast<size_t>(BENCHMARK_COUNT)) {
            printf("\n⚠️  Warning: Only collected %zu samples out of %d expected\n",
                   latency_samples.size(), BENCHMARK_COUNT);
            printf("   Connection may have closed prematurely\n");
            printf("   Total messages received: %d\n\n", message_count.load());
        }

        // Print results
        print_results();

        return 0;

    } catch (const std::exception& e) {
        fprintf(stderr, "\n❌ Error: %s\n", e.what());
        fprintf(stderr, "Messages received before error: %d\n", message_count.load());
        return 1;
    }
}
