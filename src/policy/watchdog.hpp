// policy/watchdog.hpp
// Watchdog policies for WebSocket connection liveness detection
//
// Two policies:
//   FixedWatchdogPolicy<Ms>  — fixed timeout, no learning (multi-conn: kill in 1s)
//   SelfLearnWatchdogPolicy  — learns server PING interval, dual condition
//
// Selection: FixedWatchdogPolicy<1000> for MaxConn > 1, SelfLearnWatchdogPolicy for single
#pragma once

#include <climits>
#include <cstdint>
#include <cstdio>
#include <algorithm>

namespace websocket::policy {

// ============================================================================
// FixedWatchdogPolicy — fixed PONG timeout, no server PING learning
// ============================================================================

template<uint64_t TimeoutMs>
struct FixedWatchdogPolicy {
    uint64_t last_pong_recv_cycle = 0;
    uint64_t last_client_ping_cycle = 0;

    void on_pong(uint64_t cycle)                    { last_pong_recv_cycle = cycle; }
    void on_server_ping(uint64_t, uint64_t)         {}  // ignored
    void reset(uint64_t now)                        { last_pong_recv_cycle = now; last_client_ping_cycle = 0; }

    bool check_alert(uint64_t now_cycle, uint64_t tsc_freq) const {
        if (last_pong_recv_cycle == 0) return false;
        return (now_cycle - last_pong_recv_cycle) > (TimeoutMs * tsc_freq) / 1000;
    }

    uint64_t timeout_display_ms() const             { return TimeoutMs; }
    uint64_t server_ping_display_ms() const         { return 0; }
};

// ============================================================================
// SelfLearnWatchdogPolicy — learns server PING interval, dual-condition alert
// ============================================================================

struct SelfLearnWatchdogPolicy {
    static constexpr uint64_t DEFAULT_TIMEOUT_MS = 5000;
    static constexpr uint32_t PING_LEARN_SAMPLES = 5;

    uint64_t last_pong_recv_cycle = 0;
    uint64_t last_client_ping_cycle = 0;
    uint64_t server_ping_cycles[PING_LEARN_SAMPLES]{};
    uint32_t server_ping_count = 0;
    uint64_t learned_interval_cycles = 0;
    uint64_t learned_interval_ms = 0;
    uint64_t last_server_ping_cycle = 0;

    void on_pong(uint64_t cycle) { last_pong_recv_cycle = cycle; }

    void on_server_ping(uint64_t now_cycle, uint64_t tsc_freq) {
        last_server_ping_cycle = now_cycle;

        uint32_t idx = server_ping_count;
        if (idx < PING_LEARN_SAMPLES) {
            server_ping_cycles[idx] = now_cycle;
        }
        server_ping_count++;

        if (server_ping_count >= 2) {
            uint32_t n = std::min(server_ping_count, PING_LEARN_SAMPLES);
            uint64_t total_delta = server_ping_cycles[n - 1] - server_ping_cycles[0];
            uint64_t avg_delta = total_delta / (n - 1);

            uint64_t avg_ms = (avg_delta * 1000ULL) / tsc_freq;

            // Reject bogus intervals < 1s (frame parse desync can produce fake PINGs)
            if (avg_ms < 1000) {
                server_ping_count = 0;
                learned_interval_cycles = 0;
                learned_interval_ms = 0;
            } else {
                learned_interval_cycles = avg_delta;
                learned_interval_ms = ((avg_ms + 50) / 100) * 100;
            }
        }
    }

    void reset(uint64_t now) {
        server_ping_count = 0;
        last_server_ping_cycle = now;
        last_client_ping_cycle = 0;
        last_pong_recv_cycle = now;
    }

    bool check_alert(uint64_t now_cycle, uint64_t tsc_freq) const {
        if (last_pong_recv_cycle == 0) return false;

        bool interval_learned = (server_ping_count >= 2 && learned_interval_cycles > 0);
        uint64_t pong_timeout_cycles = interval_learned
            ? learned_interval_cycles
            : (DEFAULT_TIMEOUT_MS * tsc_freq) / 1000;

        uint64_t since_last_pong = now_cycle - last_pong_recv_cycle;
        bool server_pong_missing = (since_last_pong > pong_timeout_cycles);

        bool server_ping_missing = false;
        if (interval_learned && last_server_ping_cycle > 0) {
            uint64_t since_last_ping = now_cycle - last_server_ping_cycle;
            uint64_t threshold = learned_interval_cycles + (learned_interval_cycles / 2);
            server_ping_missing = (since_last_ping > threshold);
        }

        return interval_learned
            ? (server_pong_missing && server_ping_missing)
            : server_pong_missing;
    }

    uint64_t timeout_display_ms() const {
        bool interval_learned = (server_ping_count >= 2 && learned_interval_cycles > 0);
        return interval_learned ? learned_interval_ms : DEFAULT_TIMEOUT_MS;
    }

    uint64_t server_ping_display_ms() const {
        bool interval_learned = (server_ping_count >= 2 && learned_interval_cycles > 0);
        return interval_learned ? (learned_interval_ms * 3 / 2) : 0;
    }
};

// ============================================================================
// LatencyTracker — per-connection EMA of server latency (nanoseconds)
// ============================================================================

struct LatencyTracker {
    int64_t ema_ns = 0;
    int64_t last_sample_ns = 0;
    uint32_t sample_count = 0;

    static constexpr uint32_t WARMUP_SAMPLES = 8;
    static constexpr int32_t EMA_SHIFT = 3;  // alpha = 1/8

    bool on_sample(int64_t latency_ns) {
        if (latency_ns <= 0) return false;
        last_sample_ns = latency_ns;
        if (sample_count < WARMUP_SAMPLES) {
            ema_ns = (ema_ns * (int64_t)sample_count + latency_ns) / (int64_t)(sample_count + 1);
        } else {
            ema_ns = ema_ns - (ema_ns >> EMA_SHIFT) + (latency_ns >> EMA_SHIFT);
        }
        sample_count++;
        return true;
    }
    void reset() { ema_ns = 0; last_sample_ns = 0; sample_count = 0; }
    bool is_warmed_up() const { return sample_count >= WARMUP_SAMPLES; }

    static constexpr uint32_t OUTLIER_MIN_SAMPLES = 64;
    bool is_outlier_eligible() const { return sample_count >= OUTLIER_MIN_SAMPLES; }

    int64_t ema_ms() const { return ema_ns / 1'000'000; }
};

// ============================================================================
// detect_latency_outlier — cross-connection latency comparison
//
// Outlier criteria (all must hold):
//   1. Connection EMA > OutlierRatio × minimum EMA across eligible connections
//   2. Absolute delta > OutlierAbsDeltaNs
//   3. At least 2 connections outlier-eligible (≥OUTLIER_MIN_SAMPLES each)
//   Ineligible trackers are skipped (not compared, not blocking)
// ============================================================================

struct LatencyOutlierResult {
    int8_t outlier_ci = -1;        // -1 = no outlier
    int64_t min_ema_ns = 0;
    int64_t outlier_ema_ns = 0;
};

template<int64_t OutlierRatio = 2, int64_t OutlierAbsDeltaNs = 50'000'000LL>
inline LatencyOutlierResult detect_latency_outlier(
        const LatencyTracker* trackers, uint8_t n_active) {
    LatencyOutlierResult r{};
    if (n_active < 2) return r;
    uint8_t n_eligible = 0;
    for (uint8_t i = 0; i < n_active; ++i)
        if (trackers[i].is_outlier_eligible()) n_eligible++;
    if (n_eligible < 2) return r;
    int64_t min_ema = INT64_MAX;
    for (uint8_t i = 0; i < n_active; ++i)
        if (trackers[i].is_outlier_eligible() && trackers[i].ema_ns < min_ema)
            min_ema = trackers[i].ema_ns;
    r.min_ema_ns = min_ema;
    if (min_ema <= 0) return r;
    int64_t worst = 0;
    for (uint8_t i = 0; i < n_active; ++i) {
        if (!trackers[i].is_outlier_eligible()) continue;
        int64_t ema = trackers[i].ema_ns;
        if (ema > OutlierRatio * min_ema && (ema - min_ema) > OutlierAbsDeltaNs && ema > worst) {
            worst = ema; r.outlier_ci = (int8_t)i;
        }
    }
    r.outlier_ema_ns = worst;
    return r;
}

}  // namespace websocket::policy
