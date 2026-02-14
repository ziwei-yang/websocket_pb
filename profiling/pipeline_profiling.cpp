// profiling/xdp_poll.cpp
// Analysis tool for XDP Poll profiling data
// Reads binary profiling file and generates statistics and histograms
//
// Usage: ./xdp_poll <profiling_file.bin> [cpu_freq_ghz]
// Example: ./xdp_poll /tmp/xdp_poll_profiling_1682770.bin 3.5

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <vector>
#include <map>
#include <set>
#include <string>

// ANSI color codes for terminal output
namespace Color {
    constexpr const char* Reset     = "\033[0m";
    constexpr const char* Bold      = "\033[1m";
    constexpr const char* Dim       = "\033[2m";
    // Foreground colors
    constexpr const char* Red       = "\033[31m";
    constexpr const char* Green     = "\033[32m";
    constexpr const char* Yellow    = "\033[33m";
    constexpr const char* Blue      = "\033[34m";
    constexpr const char* Magenta   = "\033[35m";
    constexpr const char* Cyan      = "\033[36m";
    constexpr const char* White     = "\033[37m";
    // Bold + color combos
    constexpr const char* BoldRed   = "\033[1;31m";
    constexpr const char* BoldGreen = "\033[1;32m";
    constexpr const char* BoldYellow= "\033[1;33m";
    constexpr const char* BoldCyan  = "\033[1;36m";
    constexpr const char* BoldWhite = "\033[1;37m";
}

// CycleSample structure (must match pipeline_data.hpp)
struct CycleSample {
    static constexpr size_t N = 6;
    uint64_t packet_nic_ns;         // NIC hardware timestamp (ns) of oldest RX packet
    uint64_t nic_poll_cycle;        // XDP Poll rdtsc when packet retrieved from NIC
    uint64_t transport_poll_cycle;  // Transport rdtsc when packet processed (0 for XDP Poll)
    int32_t op_details[N];
    int32_t op_cycles[N];
    int16_t noop_ct[N];

    // Compute total loop cycles from sum of op_cycles
    uint64_t total_op_cycles() const {
        uint64_t sum = 0;
        for (size_t i = 0; i < N; ++i) {
            sum += static_cast<uint64_t>(op_cycles[i]);
        }
        return sum;
    }
};
static_assert(sizeof(CycleSample) == 88, "CycleSample must be 88 bytes");

// NicLatencySample structure (must match pipeline_data.hpp)
struct NicLatencySample {
    uint64_t nic_realtime_ns;         // HW timestamp from NIC (ns) - PHC (synced to CLOCK_REALTIME)
    uint64_t packet_bpf_timestamp_ns; // BPF entry bpf_ktime_get_ns() - CLOCK_MONOTONIC
    uint64_t poll_cycle;              // TSC cycle when XDP Poll retrieved packet
    uint64_t poll_timestamp_ns;       // XDP Poll clock_gettime(CLOCK_MONOTONIC)
    uint64_t poll_realtime_ns;        // XDP Poll clock_gettime(CLOCK_REALTIME) - matches NIC PHC
};
static_assert(sizeof(NicLatencySample) == 40, "NicLatencySample must be 40 bytes");

// Operation names for XDP Poll process
static const char* XDP_POLL_OP_NAMES[CycleSample::N] = {
    "TX Submit",           // 0: submit_tx_batch() - count of TX frames
    "RX Process",          // 1: process_rx() - count of RX frames
    "Trickle",             // 2: send_trickle() - triggered (0/1)
    "Completions",         // 3: process_completions() - count
    "Release+Reserve",     // 4: release_acked_tx_frames() + proactive_reserve_tx() - reserved count
    "Reclaim RX"           // 5: reclaim_rx_frames() - count
};

// Operation names for Transport process
static const char* TRANSPORT_OP_NAMES[CycleSample::N] = {
    "Poll",                // 0: transport_.poll() - always 0
    "MSG Outbox",          // 1: process_msg_outbox() - messages sent
    "SSL Read",            // 2: process_ssl_read() - bytes read
    "Low-Prio TX",         // 3: process_low_prio_outbox() - messages sent (IDLE only)
    "(reserved)",          // 4: unused
    "(reserved)"           // 5: unused
};

// Operation names for WebSocket process
static const char* WS_PROCESS_OP_NAMES[CycleSample::N] = {
    "WS Process",          // 0: process_manually + commit (conn A / single)
    "Ping/Pong",           // 1: flush_pending_pong + maybe_send_client_ping
    "WS Process B",        // 2: process_manually + commit (conn B, EnableAB only)
    "(reserved)",          // 3: unused
    "(reserved)",          // 4: unused
    "(reserved)"           // 5: unused
};

// Current operation names (set based on file type)
static const char** OP_NAMES = XDP_POLL_OP_NAMES;

// Global CPU frequency for cycle-to-ns conversion
static double g_cpu_freq_ghz = 3.5;  // Default 3.5 GHz

// Global cycle-to-absolute-time calibration
// cycle_epoch_ns = wall_clock_ns - cycles_to_ns(rdtsc_at_calibration)
static int64_t g_cycle_epoch_ns = 0;

// Convert cycles to nanoseconds (relative)
inline double cycles_to_ns(double cycles) {
    return cycles / g_cpu_freq_ghz;
}

// Convert cycles to absolute nanoseconds (wall clock time)
inline int64_t cycles_to_abs_ns(uint64_t cycles) {
    return g_cycle_epoch_ns + static_cast<int64_t>(cycles_to_ns(static_cast<double>(cycles)));
}

// Calibrate cycle counter to wall clock time using NIC latency data
// NIC latency samples have both nic_realtime_ns (wall clock) and poll_cycle (CPU cycles)
// for the same event, allowing us to compute the epoch offset
inline void calibrate_cycle_epoch_from_nic_data(uint64_t nic_realtime_ns, uint64_t poll_cycle) {
    // epoch = nic_realtime_ns - cycles_to_ns(poll_cycle)
    g_cycle_epoch_ns = static_cast<int64_t>(nic_realtime_ns) -
                       static_cast<int64_t>(cycles_to_ns(static_cast<double>(poll_cycle)));
}

// Statistics structure
struct Stats {
    uint64_t count = 0;
    double sum = 0;
    double sum_sq = 0;
    int64_t min_val = 0;
    int64_t max_val = 0;
    std::vector<int64_t> values;  // For percentile calculation

    void add(int64_t v) {
        if (count == 0) {
            min_val = v;
            max_val = v;
        } else {
            min_val = std::min(min_val, v);
            max_val = std::max(max_val, v);
        }
        count++;
        sum += v;
        sum_sq += static_cast<double>(v) * v;
        values.push_back(v);
    }

    double mean() const { return count > 0 ? sum / count : 0; }

    double stddev() const {
        if (count < 2) return 0;
        double variance = (sum_sq - (sum * sum / count)) / (count - 1);
        return variance > 0 ? std::sqrt(variance) : 0;
    }

    int64_t percentile(double p) {
        if (values.empty()) return 0;
        std::sort(values.begin(), values.end());
        size_t idx = static_cast<size_t>(p * values.size() / 100.0);
        if (idx >= values.size()) idx = values.size() - 1;
        return values[idx];
    }
};

// Histogram with predefined ns buckets
struct Histogram {
    // Predefined bucket boundaries in ns
    static constexpr double BUCKET_BOUNDS[] = {
        10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 50000
    };
    static constexpr size_t NUM_BUCKETS = sizeof(BUCKET_BOUNDS) / sizeof(BUCKET_BOUNDS[0]) + 1;

    uint64_t bucket_counts[NUM_BUCKETS] = {0};
    uint64_t total_count = 0;

    Histogram(int64_t = 0) {}  // Ignore bucket_size parameter for compatibility

    void add(int64_t cycles) {
        double ns = cycles_to_ns(cycles);
        size_t bucket_idx = NUM_BUCKETS - 1;  // Default to last bucket (overflow)
        for (size_t i = 0; i < NUM_BUCKETS - 1; ++i) {
            if (ns < BUCKET_BOUNDS[i]) {
                bucket_idx = i;
                break;
            }
        }
        bucket_counts[bucket_idx]++;
        total_count++;
    }

    void print(const char* title, int bar_width = 40) const {
        if (total_count == 0) {
            printf("  (no data)\n");
            return;
        }

        uint64_t max_count = 0;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            max_count = std::max(max_count, bucket_counts[i]);
        }

        printf("\n%s%s%s:\n", Color::Bold, title, Color::Reset);

        // Find first and last non-zero buckets to skip empty trailing/leading rows
        size_t first_nonzero = 0;
        size_t last_nonzero = NUM_BUCKETS - 1;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            if (bucket_counts[i] > 0) {
                first_nonzero = i;
                break;
            }
        }
        for (size_t i = NUM_BUCKETS; i > 0; --i) {
            if (bucket_counts[i - 1] > 0) {
                last_nonzero = i - 1;
                break;
            }
        }

        for (size_t i = first_nonzero; i <= last_nonzero; ++i) {
            // Format bucket label with fixed width - all in same unit for alignment
            char label[14];
            if (i == 0) {
                double hi = BUCKET_BOUNDS[0];
                snprintf(label, sizeof(label), "     < %4.0fns", hi);
            } else if (i == NUM_BUCKETS - 1) {
                double lo = BUCKET_BOUNDS[NUM_BUCKETS - 2];
                snprintf(label, sizeof(label), "  %5.0fns +  ", lo);
            } else {
                double lo = BUCKET_BOUNDS[i - 1];
                double hi = BUCKET_BOUNDS[i];
                snprintf(label, sizeof(label), "%5.0f-%5.0fns", lo, hi);
            }

            // Calculate bar length and percentage
            int bar_len = max_count > 0 ? static_cast<int>(bucket_counts[i] * bar_width / max_count) : 0;
            double pct = total_count > 0 ? 100.0 * bucket_counts[i] / total_count : 0;

            // Build bar string using Unicode full block character with color
            std::string bar;
            bar += Color::Cyan;
            for (int j = 0; j < bar_len; ++j) {
                bar += "█";
            }
            bar += Color::Reset;
            // Pad with spaces to bar_width
            for (int j = bar_len; j < bar_width; ++j) {
                bar += " ";
            }

            // Print row
            printf("    %s%13s%s |%s| %7lu (%s%5.1f%%%s)\n",
                   Color::Dim, label, Color::Reset,
                   bar.c_str(),
                   bucket_counts[i],
                   Color::Magenta, pct, Color::Reset);
        }
    }

    // Print two histograms side by side with stats
    // per_unit_stats is optional - if provided, shows ns/item stats for active side
    static void print_side_by_side_with_stats(const char* title,
                                   const Histogram& left_hist, const char* left_label, Stats& left_stats,
                                   const Histogram& right_hist, const char* right_label, Stats& right_stats,
                                   Stats* per_unit_stats = nullptr,
                                   int bar_width = 20) {
        printf("\n%s%s%s:\n", Color::Bold, title, Color::Reset);

        // Print stats for both sides
        printf("    %s%-40s%s   %s%-40s%s\n",
               Color::BoldGreen, left_label, Color::Reset,
               Color::Dim, right_label, Color::Reset);
        printf("    Avg:%s%7.1f%s Min:%s%7.1f%s Max:%s%8.1f%s       Avg:%7.1f Min:%7.1f Max:%8.1f\n",
               Color::White, cycles_to_ns(left_stats.mean()), Color::Reset,
               Color::Green, cycles_to_ns(left_stats.min_val), Color::Reset,
               Color::Red, cycles_to_ns(left_stats.max_val), Color::Reset,
               cycles_to_ns(right_stats.mean()),
               cycles_to_ns(right_stats.min_val),
               cycles_to_ns(right_stats.max_val));
        printf("    P50:%s%7.1f%s P90:%7.1f P99:%s%8.1f%s       P50:%7.1f P90:%7.1f P99:%8.1f\n",
               Color::BoldYellow, cycles_to_ns(left_stats.percentile(50)), Color::Reset,
               cycles_to_ns(left_stats.percentile(90)),
               Color::BoldRed, cycles_to_ns(left_stats.percentile(99)), Color::Reset,
               cycles_to_ns(right_stats.percentile(50)),
               cycles_to_ns(right_stats.percentile(90)),
               cycles_to_ns(right_stats.percentile(99)));

        // Print per-unit stats if provided (for active side only)
        if (per_unit_stats && per_unit_stats->count > 0) {
            printf("    ns/item: Avg:%s%6.1f%s Min:%s%6.1f%s Max:%s%6.1f%s P50:%s%6.1f%s P99:%s%6.1f%s\n",
                   Color::White, per_unit_stats->mean() / 100.0, Color::Reset,
                   Color::Green, per_unit_stats->min_val / 100.0, Color::Reset,
                   Color::Red, per_unit_stats->max_val / 100.0, Color::Reset,
                   Color::Yellow, per_unit_stats->percentile(50) / 100.0, Color::Reset,
                   Color::BoldRed, per_unit_stats->percentile(99) / 100.0, Color::Reset);
        }

        // Find range of non-zero buckets across both histograms
        size_t first_nonzero = NUM_BUCKETS;
        size_t last_nonzero = 0;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            if (left_hist.bucket_counts[i] > 0 || right_hist.bucket_counts[i] > 0) {
                if (i < first_nonzero) first_nonzero = i;
                if (i > last_nonzero) last_nonzero = i;
            }
        }
        if (first_nonzero > last_nonzero) return;  // Both empty

        // Find max counts for scaling
        uint64_t left_max = 0, right_max = 0;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            left_max = std::max(left_max, left_hist.bucket_counts[i]);
            right_max = std::max(right_max, right_hist.bucket_counts[i]);
        }

        for (size_t i = first_nonzero; i <= last_nonzero; ++i) {
            // Format bucket label
            char label[14];
            if (i == 0) {
                snprintf(label, sizeof(label), "     < %4.0fns", BUCKET_BOUNDS[0]);
            } else if (i == NUM_BUCKETS - 1) {
                snprintf(label, sizeof(label), "  %5.0fns +  ", BUCKET_BOUNDS[NUM_BUCKETS - 2]);
            } else {
                snprintf(label, sizeof(label), "%5.0f-%5.0fns", BUCKET_BOUNDS[i - 1], BUCKET_BOUNDS[i]);
            }

            // Left bar (green for active)
            int left_bar_len = left_max > 0 ? static_cast<int>(left_hist.bucket_counts[i] * bar_width / left_max) : 0;
            double left_pct = left_hist.total_count > 0 ? 100.0 * left_hist.bucket_counts[i] / left_hist.total_count : 0;
            std::string left_bar;
            left_bar += Color::Green;
            for (int j = 0; j < left_bar_len; ++j) left_bar += "█";
            left_bar += Color::Reset;
            for (int j = left_bar_len; j < bar_width; ++j) left_bar += " ";

            // Right bar (dim for idle)
            int right_bar_len = right_max > 0 ? static_cast<int>(right_hist.bucket_counts[i] * bar_width / right_max) : 0;
            double right_pct = right_hist.total_count > 0 ? 100.0 * right_hist.bucket_counts[i] / right_hist.total_count : 0;
            std::string right_bar;
            right_bar += Color::Dim;
            for (int j = 0; j < right_bar_len; ++j) right_bar += "█";
            right_bar += Color::Reset;
            for (int j = right_bar_len; j < bar_width; ++j) right_bar += " ";

            printf("    %s%13s%s |%s| %6lu (%s%5.1f%%%s)   |%s| %7lu (%5.1f%%)\n",
                   Color::Dim, label, Color::Reset,
                   left_bar.c_str(), left_hist.bucket_counts[i], Color::Magenta, left_pct, Color::Reset,
                   right_bar.c_str(), right_hist.bucket_counts[i], right_pct);
        }
    }
};

void print_stats(const char* name, Stats& stats) {
    printf("\n=== %s ===\n", name);
    printf("  Count:    %lu\n", stats.count);
    printf("  Mean:     %10.2f cycles  (%7.2f ns)\n", stats.mean(), cycles_to_ns(stats.mean()));
    printf("  StdDev:   %10.2f cycles  (%7.2f ns)\n", stats.stddev(), cycles_to_ns(stats.stddev()));
    printf("  Min:      %10ld cycles  (%7.2f ns)\n", stats.min_val, cycles_to_ns(stats.min_val));
    printf("  Max:      %10ld cycles  (%7.2f ns)\n", stats.max_val, cycles_to_ns(stats.max_val));
    printf("  P50:      %10ld cycles  (%7.2f ns)\n", stats.percentile(50), cycles_to_ns(stats.percentile(50)));
    printf("  P90:      %10ld cycles  (%7.2f ns)\n", stats.percentile(90), cycles_to_ns(stats.percentile(90)));
    printf("  P99:      %10ld cycles  (%7.2f ns)\n", stats.percentile(99), cycles_to_ns(stats.percentile(99)));
    printf("  P99.9:    %10ld cycles  (%7.2f ns)\n", stats.percentile(99.9), cycles_to_ns(stats.percentile(99.9)));
}

void print_stats_table(const char* title, Stats& all_stats, Stats& data_moved_stats, Stats& idle_stats) {
    printf("\n%s\n", title);
    printf("%-10s %12s %12s %12s\n", "Metric", "All", "Data-Moved", "Idle");
    printf("%-10s %12s %12s %12s\n", "----------", "------------", "------------", "------------");
    printf("%-10s %12lu %12lu %12lu\n", "Count",
           all_stats.count, data_moved_stats.count, idle_stats.count);
    printf("%-10s %12.2f %12.2f %12.2f\n", "Mean(ns)",
           cycles_to_ns(all_stats.mean()),
           cycles_to_ns(data_moved_stats.mean()),
           cycles_to_ns(idle_stats.mean()));
    printf("%-10s %12.2f %12.2f %12.2f\n", "StdDev(ns)",
           cycles_to_ns(all_stats.stddev()),
           cycles_to_ns(data_moved_stats.stddev()),
           cycles_to_ns(idle_stats.stddev()));
    printf("%-10s %12.2f %12.2f %12.2f\n", "Min(ns)",
           cycles_to_ns(all_stats.min_val),
           cycles_to_ns(data_moved_stats.min_val),
           cycles_to_ns(idle_stats.min_val));
    printf("%-10s %12.2f %12.2f %12.2f\n", "Max(ns)",
           cycles_to_ns(all_stats.max_val),
           cycles_to_ns(data_moved_stats.max_val),
           cycles_to_ns(idle_stats.max_val));
    printf("%-10s %12.2f %12.2f %12.2f\n", "P50(ns)",
           cycles_to_ns(all_stats.percentile(50)),
           cycles_to_ns(data_moved_stats.percentile(50)),
           cycles_to_ns(idle_stats.percentile(50)));
    printf("%-10s %12.2f %12.2f %12.2f\n", "P90(ns)",
           cycles_to_ns(all_stats.percentile(90)),
           cycles_to_ns(data_moved_stats.percentile(90)),
           cycles_to_ns(idle_stats.percentile(90)));
    printf("%-10s %12.2f %12.2f %12.2f\n", "P99(ns)",
           cycles_to_ns(all_stats.percentile(99)),
           cycles_to_ns(data_moved_stats.percentile(99)),
           cycles_to_ns(idle_stats.percentile(99)));
    printf("%-10s %12.2f %12.2f %12.2f\n", "P99.9(ns)",
           cycles_to_ns(all_stats.percentile(99.9)),
           cycles_to_ns(data_moved_stats.percentile(99.9)),
           cycles_to_ns(idle_stats.percentile(99.9)));
}

// Auto-scaling histogram that detects data range and creates appropriate buckets
struct AutoScaleLatencyHistogram {
    std::vector<double> values;

    void add(double ns) {
        values.push_back(ns);
    }

    void print(const char* title, int bar_width = 40) const {
        if (values.empty()) {
            printf("  (no data)\n");
            return;
        }

        // Find min and max
        double min_val = values[0];
        double max_val = values[0];
        for (double v : values) {
            min_val = std::min(min_val, v);
            max_val = std::max(max_val, v);
        }

        // Determine scale and bucket boundaries based on data range
        double range = max_val - min_val;
        if (range < 1.0) range = 1.0;  // Avoid division by zero

        // Choose appropriate bucket boundaries based on data range
        std::vector<double> bounds;
        double base = min_val;

        // Determine scale: ns, us, or ms
        const char* unit = "ns";
        double unit_div = 1.0;
        if (max_val >= 1'000'000) {  // ms range
            unit = "ms";
            unit_div = 1'000'000.0;
        } else if (max_val >= 1000) {  // us range
            unit = "us";
            unit_div = 1000.0;
        }

        // Create ~10 buckets with nice round numbers
        double step;
        double nice_steps[] = {1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000};
        double target_step = range / 10.0;

        // Find the nicest step size
        step = nice_steps[0];
        for (double ns : nice_steps) {
            if (ns * unit_div >= target_step) {
                step = ns * unit_div;
                break;
            }
            step = ns * unit_div;
        }

        // Round base down to step boundary
        base = std::floor(min_val / step) * step;

        // Create bucket boundaries
        for (double b = base; b <= max_val + step; b += step) {
            bounds.push_back(b);
            if (bounds.size() >= 15) break;  // Limit bucket count
        }

        // Count values in each bucket
        std::vector<uint64_t> bucket_counts(bounds.size() + 1, 0);
        for (double v : values) {
            size_t idx = bounds.size();  // Overflow bucket
            for (size_t i = 0; i < bounds.size(); ++i) {
                if (v < bounds[i]) {
                    idx = i;
                    break;
                }
            }
            bucket_counts[idx]++;
        }

        // Find max count for bar scaling
        uint64_t max_count = 0;
        for (uint64_t c : bucket_counts) {
            max_count = std::max(max_count, c);
        }

        printf("\n%s%s%s:\n", Color::Bold, title, Color::Reset);

        // Find first and last non-zero buckets
        size_t first_nonzero = 0;
        size_t last_nonzero = bucket_counts.size() - 1;
        for (size_t i = 0; i < bucket_counts.size(); ++i) {
            if (bucket_counts[i] > 0) {
                first_nonzero = i;
                break;
            }
        }
        for (size_t i = bucket_counts.size(); i > 0; --i) {
            if (bucket_counts[i - 1] > 0) {
                last_nonzero = i - 1;
                break;
            }
        }

        // Print buckets
        for (size_t i = first_nonzero; i <= last_nonzero; ++i) {
            char label[20];
            if (i == 0) {
                snprintf(label, sizeof(label), "   < %.1f%s", bounds[0] / unit_div, unit);
            } else if (i >= bounds.size()) {
                snprintf(label, sizeof(label), "  >= %.1f%s", bounds.back() / unit_div, unit);
            } else {
                double lo = bounds[i - 1];
                double hi = bounds[i];
                snprintf(label, sizeof(label), "%6.1f~%6.1f%s", lo / unit_div, hi / unit_div, unit);
            }

            int bar_len = max_count > 0 ? static_cast<int>(bucket_counts[i] * bar_width / max_count) : 0;
            double pct = values.size() > 0 ? 100.0 * bucket_counts[i] / values.size() : 0;

            std::string bar;
            bar += Color::Yellow;
            for (int j = 0; j < bar_len; ++j) bar += "█";
            bar += Color::Reset;
            for (int j = bar_len; j < bar_width; ++j) bar += " ";

            printf("    %s%14s%s |%s| %7lu (%s%5.1f%%%s)\n",
                   Color::Dim, label, Color::Reset,
                   bar.c_str(), bucket_counts[i],
                   Color::Magenta, pct, Color::Reset);
        }
    }
};

// Histogram with predefined ns buckets for NIC latency jitter (signed values)
struct NicLatencyHistogram {
    // Bucket boundaries in ns (actual jitter values, can be negative)
    // Fine granularity in the middle (-5us to +5us), coarser at edges
    static constexpr double BUCKET_BOUNDS[] = {
        -20000, -10000, -5000, -3000, -2000, -1000, -500, 0, 500, 1000, 2000, 3000, 5000, 10000, 20000, 50000
    };
    static constexpr size_t NUM_BUCKETS = sizeof(BUCKET_BOUNDS) / sizeof(BUCKET_BOUNDS[0]) + 1;

    uint64_t bucket_counts[NUM_BUCKETS] = {0};
    uint64_t total_count = 0;

    void add(double ns) {
        size_t bucket_idx = NUM_BUCKETS - 1;  // Default to last bucket (overflow)
        for (size_t i = 0; i < NUM_BUCKETS - 1; ++i) {
            if (ns < BUCKET_BOUNDS[i]) {
                bucket_idx = i;
                break;
            }
        }
        bucket_counts[bucket_idx]++;
        total_count++;
    }

    void print(const char* title, int bar_width = 40) const {
        if (total_count == 0) {
            printf("  (no data)\n");
            return;
        }

        uint64_t max_count = 0;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            max_count = std::max(max_count, bucket_counts[i]);
        }

        printf("\n%s%s%s:\n", Color::Bold, title, Color::Reset);

        // Find first and last non-zero buckets
        size_t first_nonzero = 0;
        size_t last_nonzero = NUM_BUCKETS - 1;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            if (bucket_counts[i] > 0) {
                first_nonzero = i;
                break;
            }
        }
        for (size_t i = NUM_BUCKETS; i > 0; --i) {
            if (bucket_counts[i - 1] > 0) {
                last_nonzero = i - 1;
                break;
            }
        }

        for (size_t i = first_nonzero; i <= last_nonzero; ++i) {
            // Format bucket label (show ns for small values, us for large)
            char label[18];
            if (i == 0) {
                double hi = BUCKET_BOUNDS[0];
                snprintf(label, sizeof(label), "    < %+.0fus", hi / 1000);
            } else if (i == NUM_BUCKETS - 1) {
                double lo = BUCKET_BOUNDS[NUM_BUCKETS - 2];
                snprintf(label, sizeof(label), "   %+.0fus +  ", lo / 1000);
            } else {
                double lo = BUCKET_BOUNDS[i - 1];
                double hi = BUCKET_BOUNDS[i];
                // Use ns for values < 1000ns, us otherwise
                if (std::abs(hi) < 1000 && std::abs(lo) < 1000) {
                    snprintf(label, sizeof(label), "%+5.0f~%+5.0fns", lo, hi);
                } else if (std::abs(lo) < 1000) {
                    snprintf(label, sizeof(label), "%+5.0fns~%+.0fus", lo, hi / 1000);
                } else {
                    snprintf(label, sizeof(label), "%+5.0f~%+5.0fus", lo / 1000, hi / 1000);
                }
            }

            // Calculate bar length and percentage
            int bar_len = max_count > 0 ? static_cast<int>(bucket_counts[i] * bar_width / max_count) : 0;
            double pct = total_count > 0 ? 100.0 * bucket_counts[i] / total_count : 0;

            // Build bar string with color (yellow for jitter)
            std::string bar;
            bar += Color::Yellow;
            for (int j = 0; j < bar_len; ++j) {
                bar += "█";
            }
            bar += Color::Reset;
            for (int j = bar_len; j < bar_width; ++j) {
                bar += " ";
            }

            printf("    %s%14s%s |%s| %7lu (%s%5.1f%%%s)\n",
                   Color::Dim, label, Color::Reset,
                   bar.c_str(), bucket_counts[i],
                   Color::Magenta, pct, Color::Reset);
        }
    }
};

// Analyze NIC latency profiling file
int analyze_nic_latency(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file '%s': %s\n", filename, strerror(errno));
        return 1;
    }

    // Read header
    uint32_t total_count, sample_count;
    if (fread(&total_count, sizeof(uint32_t), 1, f) != 1 ||
        fread(&sample_count, sizeof(uint32_t), 1, f) != 1) {
        fprintf(stderr, "Error: Failed to read header\n");
        fclose(f);
        return 1;
    }

    printf("%s========================================%s\n", Color::Dim, Color::Reset);
    printf("%sNIC->XDP Latency Profiling Analysis%s\n", Color::BoldYellow, Color::Reset);
    printf("%s========================================%s\n", Color::Dim, Color::Reset);
    printf("File: %s%s%s\n", Color::Dim, filename, Color::Reset);
    printf("CPU Frequency: %s%.3f GHz%s\n", Color::Cyan, g_cpu_freq_ghz, Color::Reset);
    printf("Total RX packets: %s%u%s\n", Color::BoldWhite, total_count, Color::Reset);
    printf("Samples in file:  %s%u%s\n", Color::BoldWhite, sample_count, Color::Reset);
    printf("Sample size:      %zu bytes\n", sizeof(NicLatencySample));

    if (sample_count == 0) {
        printf("No samples to analyze.\n");
        fclose(f);
        return 0;
    }

    // Read all samples
    std::vector<NicLatencySample> samples(sample_count);
    size_t read_count = fread(samples.data(), sizeof(NicLatencySample), sample_count, f);
    fclose(f);

    if (read_count != sample_count) {
        fprintf(stderr, "Warning: Expected %u samples, read %zu\n", sample_count, read_count);
        samples.resize(read_count);
    }

    // ========== UNWRAP NIC TIMESTAMPS (handle 32-bit counter overflow) ==========
    // Intel I225/I226 NIC (igc driver) uses 32-bit PHC counter that wraps every ~3.29 seconds
    // The wrap period is 2^32 - 1e9 = 3,294,967,296 ns (empirically determined)
    // Detect wrap-around and add compensation to get monotonic timestamps
    constexpr int64_t WRAP_DETECT = -3'000'000'000LL; // Detect backward jump > 3 seconds
    constexpr uint64_t WRAP_PERIOD = 3'294'967'296ULL; // Actual wrap period for igc NIC
    uint64_t wrap_count = 0;
    uint64_t prev_nic_ts = 0;

    for (auto& sample : samples) {
        if (sample.nic_realtime_ns == 0) continue;

        if (prev_nic_ts > 0) {
            int64_t delta = static_cast<int64_t>(sample.nic_realtime_ns) - static_cast<int64_t>(prev_nic_ts);
            // Detect wrap: timestamp jumped backward by ~3.29 seconds
            if (delta < WRAP_DETECT) {
                wrap_count++;
            }
        }
        prev_nic_ts = sample.nic_realtime_ns;
        // Apply wrap compensation
        sample.nic_realtime_ns += wrap_count * WRAP_PERIOD;
    }

    if (wrap_count > 0) {
        printf("\n%sNote: Detected %lu NIC timestamp wrap-around(s) (32-bit PHC counter)%s\n",
               Color::Yellow, wrap_count, Color::Reset);
    }

    // Track invalid samples
    uint64_t zero_nic_ts_count = 0;
    uint64_t jitter_outlier_count = 0;

    // ========== BPF->XDP LATENCY (ACCURATE - SAME CLOCK DOMAIN) ==========
    // BPF->XDP Latency = poll_timestamp_ns - packet_bpf_timestamp_ns
    // Both use kernel CLOCK_MONOTONIC, so this is accurate without calibration
    Stats bpf_latency_stats;
    NicLatencyHistogram bpf_latency_hist;
    uint64_t bpf_latency_outlier_count = 0;

    for (const auto& sample : samples) {
        if (sample.packet_bpf_timestamp_ns == 0 || sample.poll_timestamp_ns == 0) continue;

        int64_t latency = static_cast<int64_t>(sample.poll_timestamp_ns) -
                          static_cast<int64_t>(sample.packet_bpf_timestamp_ns);

        // Skip outliers (negative or > 10ms - actual latency should be sub-millisecond)
        if (latency < 0 || latency > 10'000'000) {
            bpf_latency_outlier_count++;
            continue;
        }

        bpf_latency_stats.add(latency);
        bpf_latency_hist.add(static_cast<double>(latency));
    }

    // Print BPF->XDP latency statistics
    printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
    printf("%sBPF->XDP_poll LATENCY (ACCURATE - same clock)%s\n", Color::BoldGreen, Color::Reset);
    printf("%s========================================%s\n", Color::Dim, Color::Reset);

    if (bpf_latency_stats.count > 0) {
        printf("Samples: %s%lu%s  Outliers: %lu\n", Color::BoldWhite, bpf_latency_stats.count, Color::Reset, bpf_latency_outlier_count);
        printf("  Min:      %s%ld ns%s (%.3f us)\n", Color::Green, bpf_latency_stats.min_val, Color::Reset,
               bpf_latency_stats.min_val / 1000.0);
        printf("  Max:      %s%ld ns%s (%.3f us)\n", Color::Red, bpf_latency_stats.max_val, Color::Reset,
               bpf_latency_stats.max_val / 1000.0);
        printf("  Avg:      %.2f ns (%.3f us)\n", bpf_latency_stats.mean(), bpf_latency_stats.mean() / 1000.0);
        printf("  StdDev:   %.2f ns\n", bpf_latency_stats.stddev());
        printf("  P50:      %s%ld ns%s (%.3f us)\n", Color::BoldYellow, bpf_latency_stats.percentile(50), Color::Reset,
               bpf_latency_stats.percentile(50) / 1000.0);
        printf("  P99:      %s%ld ns%s (%.3f us)\n", Color::BoldRed, bpf_latency_stats.percentile(99), Color::Reset,
               bpf_latency_stats.percentile(99) / 1000.0);
        bpf_latency_hist.print("BPF->XDP_poll Latency Distribution");
    } else {
        printf("No valid BPF->XDP latency data.\n");
    }

    // ========== NIC->BPF->XDP_poll BREAKDOWN ==========
    // Calculate NIC->BPF latency using baseline subtraction method:
    // 1. raw_diff = BPF_timestamp - NIC_timestamp = epoch_offset + processing_latency
    // 2. baseline = min(raw_diff) = epoch_offset + min_latency
    // 3. latency = raw_diff - baseline = latency variation above minimum
    //
    // Note: When clocks are PTP-synced via phc2sys, both CLOCK_MONOTONIC and PHC
    // share the same underlying tick source, so raw_diff is constant (no variation).
    // In this case, NIC->BPF latency cannot be measured - it's absorbed into the epoch offset.

    std::vector<int64_t> nic_bpf_raw_diffs;
    for (const auto& sample : samples) {
        if (sample.nic_realtime_ns == 0 || sample.packet_bpf_timestamp_ns == 0) continue;
        int64_t diff = static_cast<int64_t>(sample.packet_bpf_timestamp_ns) -
                       static_cast<int64_t>(sample.nic_realtime_ns);
        nic_bpf_raw_diffs.push_back(diff);
    }

    printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
    printf("%sNIC->BPF->XDP_poll BREAKDOWN%s\n", Color::BoldCyan, Color::Reset);
    printf("%s========================================%s\n", Color::Dim, Color::Reset);

    if (!nic_bpf_raw_diffs.empty()) {
        // Find baseline (minimum raw difference)
        int64_t baseline = *std::min_element(nic_bpf_raw_diffs.begin(), nic_bpf_raw_diffs.end());
        int64_t max_diff = *std::max_element(nic_bpf_raw_diffs.begin(), nic_bpf_raw_diffs.end());
        int64_t spread = max_diff - baseline;

        // Count unique values to detect perfect PTP sync
        std::set<int64_t> unique_diffs(nic_bpf_raw_diffs.begin(), nic_bpf_raw_diffs.end());

        printf("%s[NIC -> BPF]%s:\n", Color::Yellow, Color::Reset);
        printf("  Samples:      %s%zu%s\n", Color::BoldWhite, nic_bpf_raw_diffs.size(), Color::Reset);
        printf("  Epoch offset: %.6f sec (BPF - NIC baseline)\n", baseline / 1e9);

        if (unique_diffs.size() == 1) {
            // Perfect PTP sync - all timestamps have same offset
            printf("\n  %s*** PTP SYNCHRONIZED - NIC->BPF latency not measurable ***%s\n",
                   Color::BoldGreen, Color::Reset);
            printf("  %sWhen phc2sys syncs PHC to system clock, both timestamps%s\n", Color::Dim, Color::Reset);
            printf("  %sderive from the same tick source. The actual NIC->BPF%s\n", Color::Dim, Color::Reset);
            printf("  %sprocessing time is absorbed into the constant epoch offset.%s\n", Color::Dim, Color::Reset);
            printf("\n  Measured variation: %s0 ns%s (all %zu samples identical)\n",
                   Color::BoldGreen, Color::Reset, nic_bpf_raw_diffs.size());
        } else if (spread < 1000) {
            // Very low variation - clocks nearly synchronized
            printf("\n  %s*** Clocks nearly synchronized ***%s\n", Color::BoldGreen, Color::Reset);
            printf("  Variation:    %s%ld ns%s (spread across %zu unique values)\n",
                   Color::Green, spread, Color::Reset, unique_diffs.size());
        } else {
            // Clocks not synchronized - can measure actual latency variation
            Stats nic_to_bpf_stats;
            for (int64_t diff : nic_bpf_raw_diffs) {
                int64_t latency = diff - baseline;
                if (latency >= 0 && latency < 100'000'000) {  // < 100ms sanity check
                    nic_to_bpf_stats.add(latency);
                }
            }

            if (nic_to_bpf_stats.count > 0) {
                printf("\n  NIC->BPF Latency (above minimum):\n");
                printf("    Min:      %s%ld ns%s (%.2f us)\n", Color::Green, nic_to_bpf_stats.min_val, Color::Reset,
                       nic_to_bpf_stats.min_val / 1000.0);
                printf("    Avg:      %.1f ns (%.2f us)\n", nic_to_bpf_stats.mean(), nic_to_bpf_stats.mean() / 1000.0);
                printf("    P50:      %s%ld ns%s (%.2f us)\n", Color::BoldYellow, nic_to_bpf_stats.percentile(50), Color::Reset,
                       nic_to_bpf_stats.percentile(50) / 1000.0);
                printf("    P99:      %s%ld ns%s (%.2f us)\n", Color::BoldRed, nic_to_bpf_stats.percentile(99), Color::Reset,
                       nic_to_bpf_stats.percentile(99) / 1000.0);
                printf("    Max:      %s%ld ns%s (%.2f us)\n", Color::Red, nic_to_bpf_stats.max_val, Color::Reset,
                       nic_to_bpf_stats.max_val / 1000.0);
            }
        }

        printf("\n%s[BPF -> XDP_poll]%s (accurate, same clock):\n", Color::Green, Color::Reset);
        printf("  Avg:      %.1f ns (%.2f us)\n", bpf_latency_stats.mean(), bpf_latency_stats.mean() / 1000.0);
        printf("  P50:      %ld ns (%.2f us)\n", bpf_latency_stats.percentile(50), bpf_latency_stats.percentile(50) / 1000.0);
        printf("  P99:      %ld ns (%.2f us)\n", bpf_latency_stats.percentile(99), bpf_latency_stats.percentile(99) / 1000.0);

        printf("\n%s[TOTAL: NIC -> XDP_poll]%s:\n", Color::BoldWhite, Color::Reset);
        printf("  %s= BPF->XDP_poll (NIC->BPF not measurable with PTP sync)%s\n", Color::Dim, Color::Reset);
        printf("  Avg:      %.1f ns (%.2f us)\n", bpf_latency_stats.mean(), bpf_latency_stats.mean() / 1000.0);
        printf("  P50:      %s%ld ns%s (%.2f us)\n", Color::BoldYellow, bpf_latency_stats.percentile(50), Color::Reset,
               bpf_latency_stats.percentile(50) / 1000.0);
        printf("  P99:      %s%ld ns%s (%.2f us)\n", Color::BoldRed, bpf_latency_stats.percentile(99), Color::Reset,
               bpf_latency_stats.percentile(99) / 1000.0);

        // Show time span for reference
        if (samples.size() >= 2) {
            uint64_t first_nic = 0, last_nic = 0;
            for (const auto& s : samples) {
                if (s.nic_realtime_ns > 0) {
                    if (first_nic == 0) first_nic = s.nic_realtime_ns;
                    last_nic = s.nic_realtime_ns;
                }
            }
            if (last_nic > first_nic) {
                double time_span_ms = (last_nic - first_nic) / 1'000'000.0;
                printf("\n  %sTime span:%s %.1f ms\n", Color::Dim, Color::Reset, time_span_ms);
            }
        }
    }

    // ========== NIC->XDP_poll LATENCY (SAME CLOCK DOMAIN - ACCURATE!) ==========
    // Both nic_realtime_ns (PHC via phc2sys) and poll_realtime_ns (CLOCK_REALTIME) are synced
    // This gives us the TRUE latency from NIC RX to XDP poll retrieval
    {
        printf("\n%s=======================================%s\n", Color::Dim, Color::Reset);
        printf("%s[NIC -> XDP_poll] LATENCY (SAME CLOCK DOMAIN)%s\n", Color::BoldGreen, Color::Reset);
        printf("%s=======================================%s\n", Color::Dim, Color::Reset);
        printf("  %sBoth timestamps use CLOCK_REALTIME domain (PHC synced via phc2sys)%s\n",
               Color::Dim, Color::Reset);

        Stats nic_to_xdp_stats;
        NicLatencyHistogram nic_to_xdp_hist;
        uint64_t outlier_count = 0;
        int64_t first_latency = 0;
        bool first_set = false;

        for (const auto& sample : samples) {
            if (sample.nic_realtime_ns == 0 || sample.poll_realtime_ns == 0) continue;

            // Direct comparison - same clock domain!
            int64_t latency = static_cast<int64_t>(sample.poll_realtime_ns) -
                              static_cast<int64_t>(sample.nic_realtime_ns);

            // Store first latency for epoch offset analysis
            if (!first_set) {
                first_latency = latency;
                first_set = true;
            }

            // Check for reasonable latency (should be positive and < 1 second)
            // Large values indicate epoch mismatch between PHC and CLOCK_REALTIME
            if (latency < 0 || latency > 1'000'000'000) {
                outlier_count++;
                continue;
            }

            nic_to_xdp_stats.add(latency);
            nic_to_xdp_hist.add(latency);
        }

        if (nic_to_xdp_stats.count == 0) {
            printf("\n  %sNo valid NIC->XDP_poll samples%s\n", Color::BoldYellow, Color::Reset);
            if (outlier_count > 0) {
                printf("  %s(All %lu samples had epoch mismatch - PHC not synced to CLOCK_REALTIME?)%s\n",
                       Color::Dim, outlier_count, Color::Reset);
                printf("  First sample: poll_realtime - nic_realtime = %ld ns (%.3f sec)\n",
                       first_latency, first_latency / 1e9);
            }
        } else {
            printf("\n  Samples: %s%lu%s  (outliers: %lu)\n",
                   Color::BoldWhite, nic_to_xdp_stats.count, Color::Reset, outlier_count);

            printf("\n  %sLatency Statistics:%s\n", Color::BoldWhite, Color::Reset);
            printf("  Min:      %s%ld ns%s (%.2f us)\n", Color::Green, nic_to_xdp_stats.min_val, Color::Reset,
                   nic_to_xdp_stats.min_val / 1000.0);
            printf("  Avg:      %.1f ns (%.2f us)\n", nic_to_xdp_stats.mean(), nic_to_xdp_stats.mean() / 1000.0);
            printf("  P50:      %s%ld ns%s (%.2f us)\n", Color::BoldYellow, nic_to_xdp_stats.percentile(50), Color::Reset,
                   nic_to_xdp_stats.percentile(50) / 1000.0);
            printf("  P99:      %s%ld ns%s (%.2f us)\n", Color::BoldRed, nic_to_xdp_stats.percentile(99), Color::Reset,
                   nic_to_xdp_stats.percentile(99) / 1000.0);
            printf("  Max:      %s%ld ns%s (%.2f us)\n", Color::Red, nic_to_xdp_stats.max_val, Color::Reset,
                   nic_to_xdp_stats.max_val / 1000.0);
            printf("  Jitter:   %.1f ns (stddev)\n", nic_to_xdp_stats.stddev());

            // Print histogram
            printf("\n  %sHistogram:%s\n", Color::BoldWhite, Color::Reset);
            nic_to_xdp_hist.print("  ");
        }
    }

    // Calibrate cycle epoch using first valid sample (for legacy NIC->XDP analysis below)
    for (const auto& sample : samples) {
        if (sample.nic_realtime_ns > 0) {
            calibrate_cycle_epoch_from_nic_data(sample.nic_realtime_ns, sample.poll_cycle);
            break;
        }
    }

    // ========== NIC->XDP LATENCY (CLOCK DRIFT - different clock domains) ==========
    // NIC->XDP Latency = cycles_to_abs_ns(poll_cycle) - nic_realtime_ns
    // Note: NIC PHC and CPU TSC are different clocks, so this shows clock drift
    Stats latency_stats;
    NicLatencyHistogram latency_hist;
    uint64_t latency_outlier_count = 0;

    for (const auto& sample : samples) {
        if (sample.nic_realtime_ns == 0) continue;

        int64_t latency = static_cast<int64_t>(cycles_to_ns(sample.poll_cycle)) -
                          static_cast<int64_t>(sample.nic_realtime_ns);

        // Skip outliers (negative or > 100ms)
        if (latency < 0 || latency > 100'000'000) {
            latency_outlier_count++;
            continue;
        }

        latency_stats.add(latency);
        latency_hist.add(static_cast<double>(latency));
    }

    // Print NIC->XDP latency statistics (with clock drift caveat)
    printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
    printf("%sNIC->XDP LATENCY (clock drift - different clocks)%s\n", Color::BoldYellow, Color::Reset);
    printf("%s========================================%s\n", Color::Dim, Color::Reset);

    if (latency_stats.count > 0) {
        printf("Samples: %s%lu%s  Outliers: %lu\n", Color::BoldWhite, latency_stats.count, Color::Reset, latency_outlier_count);
        printf("  Min:      %s%ld ns%s (%.3f us)\n", Color::Green, latency_stats.min_val, Color::Reset,
               latency_stats.min_val / 1000.0);
        printf("  Max:      %s%ld ns%s (%.3f us)\n", Color::Red, latency_stats.max_val, Color::Reset,
               latency_stats.max_val / 1000.0);
        printf("  Avg:      %.2f ns (%.3f us)\n", latency_stats.mean(), latency_stats.mean() / 1000.0);
        printf("  StdDev:   %.2f ns\n", latency_stats.stddev());
        printf("  P50:      %s%ld ns%s (%.3f us)\n", Color::BoldYellow, latency_stats.percentile(50), Color::Reset,
               latency_stats.percentile(50) / 1000.0);
        printf("  P99:      %s%ld ns%s (%.3f us)\n", Color::BoldRed, latency_stats.percentile(99), Color::Reset,
               latency_stats.percentile(99) / 1000.0);
        printf("%sNote: Shows clock drift between NIC PHC and CPU TSC, not actual latency%s\n", Color::Dim, Color::Reset);
        latency_hist.print("NIC->XDP (Clock Drift) Distribution");
    } else {
        printf("No valid NIC->XDP latency data.\n");
    }

    // ========== JITTER (differential analysis) ==========
    // Jitter measures how much latency varies between consecutive packets
    // jitter = poll_delta - nic_delta
    Stats jitter_stats;
    NicLatencyHistogram jitter_hist;

    NicLatencySample prev_sample = {};
    bool have_prev = false;

    for (const auto& sample : samples) {
        if (sample.nic_realtime_ns == 0) {
            zero_nic_ts_count++;
            continue;
        }

        if (!have_prev) {
            prev_sample = sample;
            have_prev = true;
            continue;
        }

        // Compute deltas
        int64_t nic_delta = static_cast<int64_t>(sample.nic_realtime_ns) -
                            static_cast<int64_t>(prev_sample.nic_realtime_ns);
        double poll_delta = (sample.poll_cycle - prev_sample.poll_cycle) / g_cpu_freq_ghz;
        double jitter = poll_delta - nic_delta;

        // Skip outliers (> 1ms jitter indicates clock issue or gap in data)
        if (jitter < -1'000'000 || jitter > 1'000'000) {
            jitter_outlier_count++;
            prev_sample = sample;
            continue;
        }

        jitter_stats.add(static_cast<int64_t>(jitter));
        jitter_hist.add(jitter);

        prev_sample = sample;
    }

    // Print summary
    printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
    printf("%sSUMMARY%s\n", Color::BoldCyan, Color::Reset);
    printf("%s========================================%s\n", Color::Dim, Color::Reset);
    printf("Packet pairs analyzed: %s%lu%s\n", Color::BoldWhite, jitter_stats.count, Color::Reset);
    printf("Zero NIC timestamp:    %lu\n", zero_nic_ts_count);
    printf("Outliers (>1ms):       %lu\n", jitter_outlier_count);
    printf("\n%sNote:%s Jitter = poll_delta - nic_delta (between consecutive packets).\n", Color::Dim, Color::Reset);
    printf("Positive = packet took longer to reach XDP Poll than previous.\n");
    printf("Negative = packet reached XDP Poll faster than previous.\n");

    if (jitter_stats.count == 0) {
        printf("\nNo valid packet pairs to analyze.\n");
        return 0;
    }

    // Print statistics
    printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
    printf("%sNIC->XDP STATISTICS (ns)%s\n", Color::BoldCyan, Color::Reset);
    printf("%s========================================%s\n", Color::Dim, Color::Reset);
    printf("  Count:    %s%lu%s\n", Color::BoldWhite, jitter_stats.count, Color::Reset);
    printf("  Min:      %s%.2f ns%s (%.3f us)\n", Color::Green, static_cast<double>(jitter_stats.min_val), Color::Reset,
           jitter_stats.min_val / 1000.0);
    printf("  Max:      %s%.2f ns%s (%.3f us)\n", Color::Red, static_cast<double>(jitter_stats.max_val), Color::Reset,
           jitter_stats.max_val / 1000.0);
    printf("  Avg:      %.2f ns (%.3f us)\n", jitter_stats.mean(),
           jitter_stats.mean() / 1000.0);
    printf("  StdDev:   %.2f ns\n", jitter_stats.stddev());
    printf("  P50:      %s%ld ns%s (%.3f us)\n", Color::BoldYellow, jitter_stats.percentile(50), Color::Reset,
           jitter_stats.percentile(50) / 1000.0);
    printf("  P90:      %ld ns (%.3f us)\n", jitter_stats.percentile(90),
           jitter_stats.percentile(90) / 1000.0);
    printf("  P99:      %s%ld ns%s (%.3f us)\n", Color::BoldRed, jitter_stats.percentile(99), Color::Reset,
           jitter_stats.percentile(99) / 1000.0);
    printf("  P99.9:    %s%ld ns%s (%.3f us)\n", Color::BoldRed, jitter_stats.percentile(99.9), Color::Reset,
           jitter_stats.percentile(99.9) / 1000.0);

    // Print histogram
    jitter_hist.print("NIC->XDP Jitter Distribution");

    printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
    printf("Analysis complete.\n");
    printf("%s========================================%s\n", Color::Dim, Color::Reset);

    return 0;
}

// Detect CPU frequency from /proc/cpuinfo or /sys
double detect_cpu_freq_ghz() {
    // Try /sys/devices/system/cpu/cpu0/cpufreq/base_frequency first (in kHz)
    FILE* f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/base_frequency", "r");
    if (f) {
        uint64_t freq_khz;
        if (fscanf(f, "%lu", &freq_khz) == 1) {
            fclose(f);
            return freq_khz / 1000000.0;
        }
        fclose(f);
    }

    // Try /proc/cpuinfo
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            double mhz;
            if (sscanf(line, "cpu MHz : %lf", &mhz) == 1) {
                fclose(f);
                return mhz / 1000.0;
            }
        }
        fclose(f);
    }

    return 3.5;  // Default fallback
}

// Check if string is a valid PID (all digits)
bool is_pid(const char* str) {
    if (!str || !*str) return false;
    for (const char* p = str; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

// Forward declaration for XDP Poll loop analysis
int analyze_xdp_poll_loop(const char* filename);

// Analyze all profiling files for a given PID
int analyze_by_pid(const char* pid_str) {
    char xdp_poll_file[256];
    char nic_latency_file[256];
    char transport_file[256];
    char ws_process_file[256];

    snprintf(xdp_poll_file, sizeof(xdp_poll_file), "/tmp/xdp_poll_profiling_%s.bin", pid_str);
    snprintf(nic_latency_file, sizeof(nic_latency_file), "/tmp/nic_latency_profiling_%s.bin", pid_str);
    snprintf(transport_file, sizeof(transport_file), "/tmp/transport_profiling_%s.bin", pid_str);
    snprintf(ws_process_file, sizeof(ws_process_file), "/tmp/ws_process_profiling_%s.bin", pid_str);

    int result = 0;
    bool found_any = false;

    // First: Read NIC latency file to calibrate cycle-to-absolute-time conversion
    // This must happen before Transport analysis which needs the calibration
    FILE* f = fopen(nic_latency_file, "rb");
    if (f) {
        // Read first sample to get calibration data
        uint32_t total_count, sample_count;
        if (fread(&total_count, sizeof(uint32_t), 1, f) == 1 &&
            fread(&sample_count, sizeof(uint32_t), 1, f) == 1 && sample_count > 0) {
            NicLatencySample first_sample;
            if (fread(&first_sample, sizeof(NicLatencySample), 1, f) == 1 &&
                first_sample.nic_realtime_ns > 0) {
                calibrate_cycle_epoch_from_nic_data(first_sample.nic_realtime_ns, first_sample.poll_cycle);
            }
        }
        fclose(f);
    }

    // Try to analyze XDP Poll profiling
    f = fopen(xdp_poll_file, "rb");
    if (f) {
        fclose(f);
        found_any = true;
        printf("\n");
        printf("%s############################################################%s\n", Color::BoldCyan, Color::Reset);
        printf("%s##                XDP POLL LOOP PROFILING                 ##%s\n", Color::BoldCyan, Color::Reset);
        printf("%s############################################################%s\n", Color::BoldCyan, Color::Reset);
        analyze_xdp_poll_loop(xdp_poll_file);
    }

    // Try to analyze Transport profiling
    f = fopen(transport_file, "rb");
    if (f) {
        fclose(f);
        found_any = true;
        printf("\n");
        printf("%s############################################################%s\n", Color::BoldGreen, Color::Reset);
        printf("%s##               TRANSPORT LOOP PROFILING                 ##%s\n", Color::BoldGreen, Color::Reset);
        printf("%s############################################################%s\n", Color::BoldGreen, Color::Reset);
        analyze_xdp_poll_loop(transport_file);
    }

    // Try to analyze WebSocket process profiling
    f = fopen(ws_process_file, "rb");
    if (f) {
        fclose(f);
        found_any = true;
        printf("\n");
        printf("%s############################################################%s\n", Color::BoldYellow, Color::Reset);
        printf("%s##             WEBSOCKET PROCESS LOOP PROFILING            ##%s\n", Color::BoldYellow, Color::Reset);
        printf("%s############################################################%s\n", Color::BoldYellow, Color::Reset);
        analyze_xdp_poll_loop(ws_process_file);
    }

    // Analyze NIC latency
    f = fopen(nic_latency_file, "rb");
    if (f) {
        fclose(f);
        found_any = true;
        printf("\n");
        printf("%s############################################################%s\n", Color::BoldYellow, Color::Reset);
        printf("%s##               NIC->XDP LATENCY PROFILING               ##%s\n", Color::BoldYellow, Color::Reset);
        printf("%s############################################################%s\n", Color::BoldYellow, Color::Reset);
        result = analyze_nic_latency(nic_latency_file);
    }

    if (!found_any) {
        printf("No profiling files found for PID %s\n", pid_str);
        printf("Expected files:\n");
        printf("  %s\n", xdp_poll_file);
        printf("  %s\n", transport_file);
        printf("  %s\n", ws_process_file);
        printf("  %s\n", nic_latency_file);
        return 1;
    }

    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <PID | profiling_file.bin> [cpu_freq_ghz]\n", argv[0]);
        fprintf(stderr, "\nModes:\n");
        fprintf(stderr, "  PID mode:  %s 12345       - Analyze all files for PID 12345\n", argv[0]);
        fprintf(stderr, "  File mode: %s file.bin   - Analyze single file\n", argv[0]);
        fprintf(stderr, "\nSupported file types:\n");
        fprintf(stderr, "  xdp_poll_profiling_*.bin    - XDP Poll loop profiling\n");
        fprintf(stderr, "  transport_profiling_*.bin   - Transport loop profiling\n");
        fprintf(stderr, "  ws_process_profiling_*.bin  - WebSocket process loop profiling\n");
        fprintf(stderr, "  nic_latency_profiling_*.bin - NIC->XDP latency per packet\n");
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  %s 2047333\n", argv[0]);
        fprintf(stderr, "  %s /tmp/xdp_poll_profiling_2047333.bin 3.5\n", argv[0]);
        return 1;
    }

    const char* arg1 = argv[1];

    // Get CPU frequency
    if (argc >= 3) {
        g_cpu_freq_ghz = atof(argv[2]);
    } else {
        g_cpu_freq_ghz = detect_cpu_freq_ghz();
    }

    // Check if arg1 is a PID
    if (is_pid(arg1)) {
        return analyze_by_pid(arg1);
    }

    const char* filename = arg1;

    // Check if this is a NIC latency file
    if (strstr(filename, "nic_latency") != nullptr) {
        return analyze_nic_latency(filename);
    }

    // Otherwise, analyze as XDP Poll / Transport / WebSocket loop profiling
    return analyze_xdp_poll_loop(filename);
}

// Analyze XDP Poll or Transport loop profiling file
int analyze_xdp_poll_loop(const char* filename) {
    // Set operation names based on file type
    if (strstr(filename, "transport") != nullptr) {
        OP_NAMES = TRANSPORT_OP_NAMES;
    } else if (strstr(filename, "ws_process") != nullptr) {
        OP_NAMES = WS_PROCESS_OP_NAMES;
    } else {
        OP_NAMES = XDP_POLL_OP_NAMES;
    }

    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file '%s': %s\n", filename, strerror(errno));
        return 1;
    }

    // Read header
    uint32_t total_count, sample_count;
    if (fread(&total_count, sizeof(uint32_t), 1, f) != 1 ||
        fread(&sample_count, sizeof(uint32_t), 1, f) != 1) {
        fprintf(stderr, "Error: Failed to read header\n");
        fclose(f);
        return 1;
    }

    bool is_transport_local = (OP_NAMES == TRANSPORT_OP_NAMES);
    bool is_ws_process = (OP_NAMES == WS_PROCESS_OP_NAMES);
    const char* process_name = is_transport_local ? "Transport" : is_ws_process ? "WebSocket" : "XDP Poll";

    const char* header_color = is_transport_local ? Color::BoldGreen : is_ws_process ? Color::BoldYellow : Color::BoldCyan;
    printf("%s========================================%s\n", Color::Dim, Color::Reset);
    printf("%s%s Profiling Analysis%s\n", header_color, process_name, Color::Reset);
    printf("%s========================================%s\n", Color::Dim, Color::Reset);
    printf("File: %s%s%s\n", Color::Dim, filename, Color::Reset);
    printf("CPU Frequency: %s%.3f GHz%s\n", Color::Cyan, g_cpu_freq_ghz, Color::Reset);
    printf("Total iterations: %s%u%s\n", Color::BoldWhite, total_count, Color::Reset);
    printf("Samples in file:  %s%u%s\n", Color::BoldWhite, sample_count, Color::Reset);
    printf("Sample size:      %zu bytes\n", sizeof(CycleSample));

    if (sample_count == 0) {
        printf("No samples to analyze.\n");
        fclose(f);
        return 0;
    }

    // Read all samples
    std::vector<CycleSample> samples(sample_count);
    size_t read_count = fread(samples.data(), sizeof(CycleSample), sample_count, f);
    fclose(f);

    if (read_count != sample_count) {
        fprintf(stderr, "Warning: Expected %u samples, read %zu\n", sample_count, read_count);
        samples.resize(read_count);
    }

    // Calibrate cycle epoch using first valid CycleSample with NIC timestamp
    // This allows converting TSC cycles to absolute wall-clock nanoseconds
    for (const auto& sample : samples) {
        if (sample.packet_nic_ns > 0 && sample.nic_poll_cycle > 0) {
            calibrate_cycle_epoch_from_nic_data(sample.packet_nic_ns, sample.nic_poll_cycle);
            break;
        }
    }

    // NIC->XDP Latency Analysis (FIRST - most important metric)
    // Measures time from NIC receiving packet to XDP Poll retrieving it
    // Formula: cycles_to_abs_ns(nic_poll_cycle) - packet_nic_ns
    // Split by time quartiles to visualize clock drift
    {
        printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
        printf("%sNIC->XDP STATISTICS (ns) - Time Quartile Analysis%s\n", header_color, Color::Reset);
        printf("%s========================================%s\n", Color::Dim, Color::Reset);

        // Collect valid samples with their timestamps and latencies
        struct TimedLatency {
            uint64_t nic_realtime_ns;
            int64_t latency_ns;
        };
        std::vector<TimedLatency> timed_latencies;
        uint64_t outlier_count = 0;

        for (const auto& sample : samples) {
            if (sample.packet_nic_ns > 0 && sample.nic_poll_cycle > 0) {
                int64_t latency = cycles_to_abs_ns(sample.nic_poll_cycle) -
                                  static_cast<int64_t>(sample.packet_nic_ns);

                // Skip outliers (negative or > 100ms latency)
                if (latency < 0 || latency > 100'000'000) {
                    outlier_count++;
                    continue;
                }

                timed_latencies.push_back({sample.packet_nic_ns, latency});
            }
        }

        if (timed_latencies.empty()) {
            printf("No valid NIC->XDP latency data.\n");
        } else {
            // Sort by NIC timestamp (oldest to newest)
            std::sort(timed_latencies.begin(), timed_latencies.end(),
                      [](const TimedLatency& a, const TimedLatency& b) {
                          return a.nic_realtime_ns < b.nic_realtime_ns;
                      });

            // Overall stats
            Stats overall_stats;
            for (const auto& tl : timed_latencies) {
                overall_stats.add(tl.latency_ns);
            }

            // Time range info
            uint64_t time_span_ns = timed_latencies.back().nic_realtime_ns - timed_latencies.front().nic_realtime_ns;
            double time_span_ms = time_span_ns / 1'000'000.0;

            printf("Total Samples: %s%zu%s  Outliers: %lu  Time Span: %.1f ms\n",
                   Color::BoldWhite, timed_latencies.size(), Color::Reset, outlier_count, time_span_ms);
            printf("Overall: Min:%s%.0f%s  Avg:%.0f  P50:%s%ld%s  P99:%s%ld%s  Max:%s%.0f%s ns\n",
                   Color::Green, static_cast<double>(overall_stats.min_val), Color::Reset,
                   overall_stats.mean(),
                   Color::BoldYellow, overall_stats.percentile(50), Color::Reset,
                   Color::BoldRed, overall_stats.percentile(99), Color::Reset,
                   Color::Red, static_cast<double>(overall_stats.max_val), Color::Reset);

            // ========== XY Chart: First 50 samples latency over time ==========
            size_t chart_samples = std::min(timed_latencies.size(), size_t(50));
            if (chart_samples > 0) {
                printf("\n%sFirst %zu Samples - Latency vs Time (ns):%s\n", Color::BoldCyan, chart_samples, Color::Reset);

                // Find min/max for Y-axis scaling
                int64_t y_min = timed_latencies[0].latency_ns;
                int64_t y_max = timed_latencies[0].latency_ns;
                for (size_t i = 0; i < chart_samples; i++) {
                    y_min = std::min(y_min, timed_latencies[i].latency_ns);
                    y_max = std::max(y_max, timed_latencies[i].latency_ns);
                }
                // Add some padding
                int64_t y_range = y_max - y_min;
                if (y_range == 0) y_range = 1;

                // Chart dimensions
                constexpr int CHART_HEIGHT = 36;
                constexpr int CHART_WIDTH = 60;

                // Build 2D chart buffer (space = empty, * = data point)
                std::vector<std::string> chart(CHART_HEIGHT + 1, std::string(CHART_WIDTH, ' '));

                // Track first 3 samples' row positions for labeling
                std::map<int, std::vector<int64_t>> first3_labels;  // row -> list of latency_ns
                for (size_t i = 0; i < std::min(chart_samples, size_t(3)); i++) {
                    int row = static_cast<int>(
                        ((timed_latencies[i].latency_ns - y_min) * CHART_HEIGHT) / y_range);
                    first3_labels[row].push_back(timed_latencies[i].latency_ns);
                }

                // Place all markers
                for (size_t i = 0; i < chart_samples; i++) {
                    int col = static_cast<int>((i * (CHART_WIDTH - 1)) / (chart_samples - 1));
                    int row = static_cast<int>(
                        ((timed_latencies[i].latency_ns - y_min) * CHART_HEIGHT) / y_range);
                    if (col >= 0 && col < CHART_WIDTH && row >= 0 && row <= CHART_HEIGHT) {
                        chart[row][col] = '*';
                    }
                }

                // Draw chart (top to bottom)
                for (int row = CHART_HEIGHT; row >= 0; row--) {
                    int64_t y_val = y_min + (y_range * row) / CHART_HEIGHT;
                    printf("  %10ld |", y_val);
                    // Print row with colored markers
                    for (int col = 0; col < CHART_WIDTH; col++) {
                        if (chart[row][col] == '*') {
                            printf("%s*%s", Color::Yellow, Color::Reset);
                        } else {
                            printf(" ");
                        }
                    }
                    // Print label for first 3 samples
                    if (first3_labels.count(row)) {
                        printf(" %s<-", Color::Cyan);
                        for (size_t i = 0; i < first3_labels[row].size(); i++) {
                            if (i > 0) printf(",");
                            printf(" %ld", first3_labels[row][i]);
                        }
                        printf(" ns%s", Color::Reset);
                    }
                    printf("\n");
                }

                // X-axis
                printf("  %10s +", "");
                for (int i = 0; i < CHART_WIDTH; i++) printf("-");
                printf("\n");

                // X-axis labels (sample indices)
                printf("  %10s  ", "");
                int label_spacing = CHART_WIDTH / 4;
                for (int i = 0; i <= 4; i++) {
                    size_t sample_idx = (i * (chart_samples - 1)) / 4;
                    printf("%-*zu", label_spacing, sample_idx);
                }
                printf("\n");
                printf("  %10s  %s(sample index)%s\n", "", Color::Dim, Color::Reset);

                // Print table of first 20 samples
                printf("\n  %sIndex    Time(ms)      Latency(ns)%s\n", Color::Dim, Color::Reset);
                for (size_t i = 0; i < chart_samples; i++) {
                    double time_ms = (timed_latencies[i].nic_realtime_ns - timed_latencies.front().nic_realtime_ns) / 1'000'000.0;
                    printf("  %5zu    %8.2f    %12ld\n", i, time_ms, timed_latencies[i].latency_ns);
                }
            }

            // Split into 4 quartiles by time
            size_t n = timed_latencies.size();
            size_t q1_end = n / 4;
            size_t q2_end = n / 2;
            size_t q3_end = (3 * n) / 4;

            const char* quartile_names[] = {"Q1 (0-25%)", "Q2 (25-50%)", "Q3 (50-75%)", "Q4 (75-100%)"};
            size_t quartile_ranges[][2] = {{0, q1_end}, {q1_end, q2_end}, {q2_end, q3_end}, {q3_end, n}};

            // Helper lambda to print histogram in ns
            auto print_ns_histogram = [](const std::vector<int64_t>& values, const char* title) {
                if (values.empty()) return;

                // Find min/max
                int64_t min_val = values[0], max_val = values[0];
                for (int64_t v : values) {
                    min_val = std::min(min_val, v);
                    max_val = std::max(max_val, v);
                }

                // Create ~8 buckets
                int64_t range = max_val - min_val;
                if (range == 0) range = 1;
                int64_t bucket_size = (range + 7) / 8;
                if (bucket_size == 0) bucket_size = 1;

                // Round bucket_size to nice number
                int64_t nice_sizes[] = {100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000};
                for (int64_t ns : nice_sizes) {
                    if (ns >= bucket_size) {
                        bucket_size = ns;
                        break;
                    }
                }

                // Round min down to bucket boundary
                int64_t base = (min_val / bucket_size) * bucket_size;

                // Count buckets
                std::vector<std::pair<int64_t, uint64_t>> buckets;
                for (int64_t b = base; b <= max_val; b += bucket_size) {
                    uint64_t count = 0;
                    for (int64_t v : values) {
                        if (v >= b && v < b + bucket_size) count++;
                    }
                    if (count > 0 || !buckets.empty()) {
                        buckets.push_back({b, count});
                    }
                }

                // Find max count for bar scaling
                uint64_t max_count = 0;
                for (const auto& [b, c] : buckets) max_count = std::max(max_count, c);

                printf("\n%s%s%s:\n", Color::Bold, title, Color::Reset);
                constexpr int BAR_WIDTH = 40;
                for (const auto& [b, count] : buckets) {
                    int bar_len = max_count > 0 ? static_cast<int>(count * BAR_WIDTH / max_count) : 0;
                    double pct = values.size() > 0 ? 100.0 * count / values.size() : 0;

                    printf("    %s%10ld~%10ld ns%s |%s", Color::Dim, b, b + bucket_size, Color::Reset, Color::Yellow);
                    for (int j = 0; j < bar_len; j++) printf("█");
                    printf("%s", Color::Reset);
                    for (int j = bar_len; j < BAR_WIDTH; j++) printf(" ");
                    printf("| %5lu (%s%5.1f%%%s)\n", count, Color::Magenta, pct, Color::Reset);
                }
            };

            for (int q = 0; q < 4; q++) {
                size_t start = quartile_ranges[q][0];
                size_t end = quartile_ranges[q][1];
                if (start >= end) continue;

                Stats q_stats;
                std::vector<int64_t> q_values;

                for (size_t i = start; i < end; i++) {
                    q_stats.add(timed_latencies[i].latency_ns);
                    q_values.push_back(timed_latencies[i].latency_ns);
                }

                // Time range for this quartile
                double q_start_ms = (timed_latencies[start].nic_realtime_ns - timed_latencies.front().nic_realtime_ns) / 1'000'000.0;
                double q_end_ms = (timed_latencies[end-1].nic_realtime_ns - timed_latencies.front().nic_realtime_ns) / 1'000'000.0;

                printf("\n%s[%s]%s (T+%.1f ~ T+%.1f ms, n=%zu)\n",
                       Color::BoldCyan, quartile_names[q], Color::Reset,
                       q_start_ms, q_end_ms, end - start);
                printf("  Min:%s%.0f%s  Avg:%.0f  P50:%s%ld%s  P99:%s%ld%s  Max:%s%.0f%s ns\n",
                       Color::Green, static_cast<double>(q_stats.min_val), Color::Reset,
                       q_stats.mean(),
                       Color::BoldYellow, q_stats.percentile(50), Color::Reset,
                       Color::BoldRed, q_stats.percentile(99), Color::Reset,
                       Color::Red, static_cast<double>(q_stats.max_val), Color::Reset);
                print_ns_histogram(q_values, quartile_names[q]);
            }

            // Drift summary: compare Q1 avg vs Q4 avg
            if (n >= 4) {
                Stats q1_stats, q4_stats;
                for (size_t i = 0; i < q1_end; i++) q1_stats.add(timed_latencies[i].latency_ns);
                for (size_t i = q3_end; i < n; i++) q4_stats.add(timed_latencies[i].latency_ns);

                double drift_ns = q4_stats.mean() - q1_stats.mean();
                double drift_rate_ns_per_ms = drift_ns / time_span_ms;
                printf("\n%sDrift Analysis:%s Q1_avg=%.0f ns, Q4_avg=%.0f ns, Drift=%.0f ns over %.1f ms (%.2f ns/ms)\n",
                       Color::BoldYellow, Color::Reset,
                       q1_stats.mean(), q4_stats.mean(), drift_ns, time_span_ms, drift_rate_ns_per_ms);
            }
        }
    }

    // Statistics collectors
    Stats total_cycles_stats;
    Stats op_cycles_stats[CycleSample::N];
    Stats op_details_stats[CycleSample::N];

    // Separate stats for data_moved vs no_data_moved iterations
    Stats total_cycles_data_moved;
    Stats total_cycles_idle;

    // Per-operation stats for data_moved iterations only
    Stats op_cycles_data_moved_stats[CycleSample::N];
    Stats op_details_data_moved_stats[CycleSample::N];

    // Per-operation stats for idle iterations only
    Stats op_cycles_idle_stats[CycleSample::N];
    Stats op_details_idle_stats[CycleSample::N];

    // Histograms
    Histogram total_cycles_hist(500);        // 500 cycle buckets
    Histogram total_cycles_data_moved_hist(500);
    Histogram total_cycles_idle_hist(500);
    Histogram op_cycles_hist[CycleSample::N] = {
        Histogram(100), Histogram(100), Histogram(50),
        Histogram(50), Histogram(50), Histogram(50)
    };
    // Histograms for data_moved iterations only
    Histogram op_cycles_data_moved_hist[CycleSample::N] = {
        Histogram(100), Histogram(100), Histogram(50),
        Histogram(50), Histogram(50), Histogram(50)
    };
    // Histograms for idle iterations only
    Histogram op_cycles_idle_hist[CycleSample::N] = {
        Histogram(100), Histogram(100), Histogram(50),
        Histogram(50), Histogram(50), Histogram(50)
    };
    // Histograms for samples where op_details[i] != 0 (active for that specific op)
    Histogram op_cycles_active_hist[CycleSample::N] = {
        Histogram(100), Histogram(100), Histogram(50),
        Histogram(50), Histogram(50), Histogram(50)
    };
    // Histograms for samples where op_details[i] == 0 (inactive for that specific op)
    Histogram op_cycles_inactive_hist[CycleSample::N] = {
        Histogram(100), Histogram(100), Histogram(50),
        Histogram(50), Histogram(50), Histogram(50)
    };
    // Stats for active/inactive per-operation
    Stats op_cycles_active_stats[CycleSample::N];
    Stats op_cycles_inactive_stats[CycleSample::N];
    // Per-unit cost stats (ns per item, stored as fixed-point * 100)
    Stats op_per_unit_stats[CycleSample::N];
    // Track count and min/max of op_details for active samples (within data-moved iterations)
    uint64_t op_active_in_dm_count[CycleSample::N] = {0};  // Active within data-moved
    int32_t op_active_min[CycleSample::N];
    int32_t op_active_max[CycleSample::N];
    for (size_t i = 0; i < CycleSample::N; ++i) {
        op_active_min[i] = INT32_MAX;
        op_active_max[i] = INT32_MIN;
    }

    // Event latency stats (Transport only: IPC latency = transport_poll_cycle - nic_poll_cycle)
    Stats event_latency_stats;
    Histogram event_latency_hist;
    bool is_transport = (OP_NAMES == TRANSPORT_OP_NAMES);

    // Total latency stats (sum of op_cycles for data-moved samples)
    Stats total_latency_stats;
    AutoScaleLatencyHistogram total_latency_hist;

    // Process samples
    uint64_t data_moved_count = 0;
    uint64_t idle_count = 0;

    for (const auto& sample : samples) {
        // Total loop cycles = sum of op_cycles (for both XDP Poll and Transport)
        uint64_t total_cycles = sample.total_op_cycles();
        total_cycles_stats.add(static_cast<int64_t>(total_cycles));
        total_cycles_hist.add(static_cast<int64_t>(total_cycles));

        // Determine if data was moved
        // XDP Poll: TX submitted (op 0) or RX received (op 1)
        // Transport: any op produced work — poll (op 0), msg outbox (op 1),
        //            SSL read (op 2), or low-prio outbox (op 3)
        // WebSocket: metadata consumed on conn A (op 0) or conn B (op 2, EnableAB)
        bool data_moved;
        if (is_transport)
            data_moved = (sample.op_details[0] > 0) || (sample.op_details[1] > 0) ||
                         (sample.op_details[2] > 0) || (sample.op_details[3] > 0);
        else if (is_ws_process)
            data_moved = (sample.op_details[0] > 0) || (sample.op_details[2] > 0);
        else
            data_moved = (sample.op_details[0] > 0) || (sample.op_details[1] > 0);

        if (data_moved) {
            data_moved_count++;
            total_cycles_data_moved.add(static_cast<int64_t>(total_cycles));
            total_cycles_data_moved_hist.add(static_cast<int64_t>(total_cycles));

            // Per-operation stats for data_moved iterations
            for (size_t i = 0; i < CycleSample::N; ++i) {
                op_cycles_data_moved_stats[i].add(sample.op_cycles[i]);
                op_details_data_moved_stats[i].add(sample.op_details[i]);
                op_cycles_data_moved_hist[i].add(sample.op_cycles[i]);

                // Track active count within data-moved iterations
                if (sample.op_details[i] != 0) {
                    op_active_in_dm_count[i]++;
                }
            }

            // Total latency: sum of op_cycles from first to last active op
            int last_active = -1;
            for (int i = CycleSample::N - 1; i >= 0; --i) {
                if (sample.op_cycles[i] != 0) { last_active = i; break; }
            }
            if (last_active >= 0) {
                int64_t sum_cycles = 0;
                for (int i = 0; i <= last_active; ++i)
                    sum_cycles += sample.op_cycles[i];
                double lat_ns = cycles_to_ns(static_cast<double>(sum_cycles));
                total_latency_stats.add(static_cast<int64_t>(lat_ns));
                total_latency_hist.add(lat_ns);
            }
        } else {
            idle_count++;
            total_cycles_idle.add(static_cast<int64_t>(total_cycles));
            total_cycles_idle_hist.add(static_cast<int64_t>(total_cycles));

            // Per-operation stats and histograms for idle iterations
            for (size_t i = 0; i < CycleSample::N; ++i) {
                op_cycles_idle_stats[i].add(sample.op_cycles[i]);
                op_details_idle_stats[i].add(sample.op_details[i]);
                op_cycles_idle_hist[i].add(sample.op_cycles[i]);
            }
        }

        // Per-operation stats (all iterations)
        for (size_t i = 0; i < CycleSample::N; ++i) {
            op_cycles_stats[i].add(sample.op_cycles[i]);
            op_details_stats[i].add(sample.op_details[i]);
            op_cycles_hist[i].add(sample.op_cycles[i]);

            // Track active samples (op_details[i] != 0) vs inactive (op_details[i] == 0)
            if (sample.op_details[i] != 0) {
                op_cycles_active_hist[i].add(sample.op_cycles[i]);
                op_cycles_active_stats[i].add(sample.op_cycles[i]);
                op_active_min[i] = std::min(op_active_min[i], sample.op_details[i]);
                op_active_max[i] = std::max(op_active_max[i], sample.op_details[i]);
                // Collect per-unit cost (ns per item, stored as fixed-point * 100)
                double ns_per_unit = cycles_to_ns(sample.op_cycles[i]) / sample.op_details[i];
                op_per_unit_stats[i].add(static_cast<int64_t>(ns_per_unit * 100));
            } else {
                op_cycles_inactive_hist[i].add(sample.op_cycles[i]);
                op_cycles_inactive_stats[i].add(sample.op_cycles[i]);
            }
        }

        // Collect event latency stats (Transport only: IPC latency)
        if (is_transport && sample.nic_poll_cycle > 0 && sample.transport_poll_cycle > 0) {
            // IPC latency = transport_poll_cycle - nic_poll_cycle (in cycles)
            int64_t ipc_latency_cycles = static_cast<int64_t>(sample.transport_poll_cycle - sample.nic_poll_cycle);
            int64_t latency_ns = static_cast<int64_t>(cycles_to_ns(ipc_latency_cycles));
            event_latency_stats.add(latency_ns);
            event_latency_hist.add(ipc_latency_cycles);
        }
    }

    // Compute cycle breakdown percentages from DATA-MOVED samples only
    // (idle rdtscp overhead is ~equal across all ops, drowns out real work)
    double dm_total_mean = total_cycles_data_moved.count > 0 ? total_cycles_data_moved.mean() : 0;
    double op_pct[CycleSample::N];
    double accounted = 0;
    for (size_t i = 0; i < CycleSample::N; ++i) {
        double op_mean = op_cycles_data_moved_stats[i].count > 0 ? op_cycles_data_moved_stats[i].mean() : 0;
        op_pct[i] = dm_total_mean > 0 ? 100.0 * op_mean / dm_total_mean : 0;
        accounted += op_mean;
    }
    double overhead_pct = dm_total_mean > 0 ? 100.0 * (dm_total_mean - accounted) / dm_total_mean : 0;

    // Event latency analysis for Transport (IPC latency)
    if (is_transport && event_latency_stats.count > 0) {
        printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
        printf("%sEVENT POLL LATENCY (XDP->Transport IPC)%s\n", Color::BoldGreen, Color::Reset);
        printf("%s========================================%s\n", Color::Dim, Color::Reset);
        printf("Samples: %s%lu%s (%s%.1f%%%s)  ", Color::BoldWhite, event_latency_stats.count, Color::Reset,
               Color::Magenta, 100.0 * event_latency_stats.count / samples.size(), Color::Reset);
        printf("Min:%s%ld%s  Avg:%.0f  P50:%s%ld%s  P99:%s%ld%s  Max:%s%ld%s ns\n",
               Color::Green, event_latency_stats.min_val, Color::Reset,
               event_latency_stats.mean(),
               Color::BoldYellow, event_latency_stats.percentile(50), Color::Reset,
               Color::BoldRed, event_latency_stats.percentile(99), Color::Reset,
               Color::Red, event_latency_stats.max_val, Color::Reset);
        event_latency_hist.print("IPC Latency Distribution");
    }

    // Print histograms with stats - side by side (Active vs Idle)
    printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
    printf("%sHISTOGRAMS (Active vs Idle)%s\n", Color::BoldWhite, Color::Reset);
    printf("%s========================================%s\n", Color::Dim, Color::Reset);

    // Total loop: use data-moved vs idle
    {
        char dm_label[64];
        char idle_label[64];
        char title[128];
        double dm_pct = samples.size() > 0 ? 100.0 * data_moved_count / samples.size() : 0;
        double idle_pct = samples.size() > 0 ? 100.0 * idle_count / samples.size() : 0;
        // Use enough decimal places to show at least one non-zero digit
        if (dm_pct > 0 && dm_pct < 0.1) {
            snprintf(dm_label, sizeof(dm_label), "%.3f%% Data-Moved", dm_pct);
        } else if (dm_pct > 0 && dm_pct < 1.0) {
            snprintf(dm_label, sizeof(dm_label), "%.2f%% Data-Moved", dm_pct);
        } else {
            snprintf(dm_label, sizeof(dm_label), "%.1f%% Data-Moved", dm_pct);
        }
        if (idle_pct > 0 && idle_pct < 0.1) {
            snprintf(idle_label, sizeof(idle_label), "%.3f%% Idle", idle_pct);
        } else if (idle_pct > 0 && idle_pct < 1.0) {
            snprintf(idle_label, sizeof(idle_label), "%.2f%% Idle", idle_pct);
        } else {
            snprintf(idle_label, sizeof(idle_label), "%.1f%% Idle", idle_pct);
        }
        snprintf(title, sizeof(title), "Total Loop Cycles (overhead: %.1f%%)", overhead_pct);
        Histogram::print_side_by_side_with_stats(title,
                                      total_cycles_data_moved_hist, dm_label, total_cycles_data_moved,
                                      total_cycles_idle_hist, idle_label, total_cycles_idle,
                                      nullptr);
    }

    // Per-operation: use op_details[i] != 0 as "active" vs op_details[i] == 0 as "inactive"
    // Percentage is calculated within data-moved iterations only
    for (size_t i = 0; i < CycleSample::N; ++i) {
        char title[128];
        char active_label[64];
        char inactive_label[64];

        // Percentage of active within data-moved iterations
        double active_pct_in_dm = data_moved_count > 0 ? 100.0 * op_active_in_dm_count[i] / data_moved_count : 0;

        if (op_active_in_dm_count[i] > 0) {
            // Show percentage (in data-moved) and Operations [min~max] range
            if (op_active_min[i] == op_active_max[i]) {
                snprintf(active_label, sizeof(active_label), "%.1f%% Ops[%d] in DM",
                         active_pct_in_dm, op_active_min[i]);
            } else {
                snprintf(active_label, sizeof(active_label), "%.1f%% Ops[%d~%d] in DM",
                         active_pct_in_dm, op_active_min[i], op_active_max[i]);
            }
        } else {
            snprintf(active_label, sizeof(active_label), "0%% in DM");
        }
        snprintf(inactive_label, sizeof(inactive_label), "Inactive");

        // Include cycle breakdown percentage in title
        snprintf(title, sizeof(title), "%s (%.1f%%)", OP_NAMES[i], op_pct[i]);
        // Pass per-unit stats for operations where it makes sense (op_details > 1 possible)
        Stats* per_unit = (op_per_unit_stats[i].count > 0) ? &op_per_unit_stats[i] : nullptr;
        Histogram::print_side_by_side_with_stats(title,
                                      op_cycles_active_hist[i], active_label, op_cycles_active_stats[i],
                                      op_cycles_inactive_hist[i], inactive_label, op_cycles_inactive_stats[i],
                                      per_unit);
    }

    // Per-op IDLE summary: recorded idle count vs cumulative noop_ct
    printf("\n  IDLE summary per step:\n");
    int16_t last_noop_ct[CycleSample::N] = {};
    if (!samples.empty()) {
        for (size_t i = 0; i < CycleSample::N; ++i)
            last_noop_ct[i] = samples.back().noop_ct[i];
    }
    for (size_t i = 0; i < CycleSample::N; ++i) {
        printf("    %s: recorded=%lu  implied_total=%d%s\n",
               OP_NAMES[i],
               op_cycles_inactive_stats[i].count,
               last_noop_ct[i],
               last_noop_ct[i] >= 10000 ? " (suppressed)" : "");
    }

    // Total processing latency histogram (all process types)
    if (total_latency_stats.count > 0) {
        printf("\n");
        const char* label = is_ws_process  ? "Total Processing Latency (ns) — WS"
                          : is_transport   ? "Total Processing Latency (ns) — Transport"
                          :                  "Total Processing Latency (ns) — XDP Poll";
        printf("%s========================================%s\n", Color::Dim, Color::Reset);
        printf("%s%s%s\n", Color::BoldYellow, label, Color::Reset);
        printf("%s========================================%s\n", Color::Dim, Color::Reset);
        total_latency_hist.print(label);
    }

    // NIC->XDP_poll->Transport Latency Analysis (for Transport only)
    // Two segments:
    //   1. NIC->XDP_poll: cycles_to_abs_ns(nic_poll_cycle) - packet_nic_ns
    //   2. XDP_poll->Transport: cycles_to_ns(transport_poll_cycle - nic_poll_cycle)
    if (is_transport) {
        printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
        printf("%sNIC->XDP_poll->Transport STATISTICS (ns)%s\n", Color::BoldGreen, Color::Reset);
        printf("%s========================================%s\n", Color::Dim, Color::Reset);

        // Segment 1: NIC->XDP_poll
        Stats nic_to_xdp_stats;
        AutoScaleLatencyHistogram nic_to_xdp_hist;
        uint64_t nic_to_xdp_outliers = 0;

        // Segment 2: XDP_poll->Transport
        Stats xdp_to_transport_stats;
        AutoScaleLatencyHistogram xdp_to_transport_hist;
        uint64_t xdp_to_transport_outliers = 0;

        // Diagnostic counters
        uint64_t zero_nic_ns_count = 0;
        uint64_t zero_xdp_cycle_count = 0;
        uint64_t zero_transport_cycle_count = 0;
        uint64_t valid_samples = 0;

        for (const auto& sample : samples) {
            // Count diagnostic cases
            if (sample.packet_nic_ns == 0) zero_nic_ns_count++;
            if (sample.nic_poll_cycle == 0) zero_xdp_cycle_count++;
            if (sample.transport_poll_cycle == 0) zero_transport_cycle_count++;

            // Need all three fields for full pipeline analysis
            if (sample.packet_nic_ns > 0 && sample.nic_poll_cycle > 0 && sample.transport_poll_cycle > 0) {
                valid_samples++;

                // Segment 1: NIC->XDP_poll
                int64_t nic_to_xdp = cycles_to_abs_ns(sample.nic_poll_cycle) -
                                    static_cast<int64_t>(sample.packet_nic_ns);
                if (nic_to_xdp >= 0 && nic_to_xdp <= 100'000'000) {
                    nic_to_xdp_stats.add(nic_to_xdp);
                    nic_to_xdp_hist.add(static_cast<double>(nic_to_xdp));
                } else {
                    nic_to_xdp_outliers++;
                }

                // Segment 2: XDP_poll->Transport (both are TSC cycles, just convert difference)
                int64_t xdp_to_transport = static_cast<int64_t>(
                    cycles_to_ns(static_cast<double>(sample.transport_poll_cycle - sample.nic_poll_cycle)));
                if (xdp_to_transport >= 0 && xdp_to_transport <= 100'000'000) {
                    xdp_to_transport_stats.add(xdp_to_transport);
                    xdp_to_transport_hist.add(static_cast<double>(xdp_to_transport));
                } else {
                    xdp_to_transport_outliers++;
                }
            }
        }

        // Print Segment 1: NIC->XDP_poll
        printf("\n%s[Segment 1] NIC -> XDP_poll%s\n", Color::BoldCyan, Color::Reset);
        if (nic_to_xdp_stats.count > 0) {
            printf("Samples: %s%lu%s  Outliers: %lu  ", Color::BoldWhite, nic_to_xdp_stats.count, Color::Reset, nic_to_xdp_outliers);
            printf("Min:%s%.0f%s  Avg:%.0f  P50:%s%ld%s  P99:%s%ld%s  Max:%s%.0f%s ns\n",
                   Color::Green, static_cast<double>(nic_to_xdp_stats.min_val), Color::Reset,
                   nic_to_xdp_stats.mean(),
                   Color::BoldYellow, nic_to_xdp_stats.percentile(50), Color::Reset,
                   Color::BoldRed, nic_to_xdp_stats.percentile(99), Color::Reset,
                   Color::Red, static_cast<double>(nic_to_xdp_stats.max_val), Color::Reset);
            nic_to_xdp_hist.print("NIC->XDP_poll Latency Distribution");
        } else {
            printf("No valid NIC->XDP_poll latency data.\n");
        }

        // Print Segment 2: XDP_poll->Transport
        printf("\n%s[Segment 2] XDP_poll -> Transport%s\n", Color::BoldCyan, Color::Reset);
        if (xdp_to_transport_stats.count > 0) {
            printf("Samples: %s%lu%s  Outliers: %lu  ", Color::BoldWhite, xdp_to_transport_stats.count, Color::Reset, xdp_to_transport_outliers);
            printf("Min:%s%.0f%s  Avg:%.0f  P50:%s%ld%s  P99:%s%ld%s  Max:%s%.0f%s ns\n",
                   Color::Green, static_cast<double>(xdp_to_transport_stats.min_val), Color::Reset,
                   xdp_to_transport_stats.mean(),
                   Color::BoldYellow, xdp_to_transport_stats.percentile(50), Color::Reset,
                   Color::BoldRed, xdp_to_transport_stats.percentile(99), Color::Reset,
                   Color::Red, static_cast<double>(xdp_to_transport_stats.max_val), Color::Reset);
            xdp_to_transport_hist.print("XDP_poll->Transport Latency Distribution");
        } else {
            printf("No valid XDP_poll->Transport latency data.\n");
        }

        // Diagnostics if no valid data
        if (valid_samples == 0) {
            printf("\n%sDiagnostics:%s\n", Color::BoldYellow, Color::Reset);
            printf("  Total samples:              %zu\n", samples.size());
            printf("  packet_nic_ns == 0:         %lu\n", zero_nic_ns_count);
            printf("  nic_poll_cycle == 0:        %lu\n", zero_xdp_cycle_count);
            printf("  transport_poll_cycle == 0:  %lu\n", zero_transport_cycle_count);

            // Print first 10 samples with non-zero data for debugging
            printf("\n%sFirst 10 samples with any non-zero field:%s\n", Color::Dim, Color::Reset);
            int printed = 0;
            for (size_t i = 0; i < samples.size() && printed < 10; i++) {
                const auto& s = samples[i];
                if (s.packet_nic_ns > 0 || s.nic_poll_cycle > 0 || s.transport_poll_cycle > 0) {
                    printf("  [%zu] packet_nic_ns=%lu  nic_poll_cycle=%lu  transport_poll_cycle=%lu\n",
                           i, s.packet_nic_ns, s.nic_poll_cycle, s.transport_poll_cycle);
                    printed++;
                }
            }
            if (printed == 0) {
                printf("  (all samples have all three fields == 0)\n");
            }
        }
    }

    printf("\n%s========================================%s\n", Color::Dim, Color::Reset);
    printf("Analysis complete.\n");
    printf("%s========================================%s\n", Color::Dim, Color::Reset);

    return 0;
}
