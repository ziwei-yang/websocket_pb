// policy/watchdog.hpp
// Watchdog policies for WebSocket connection liveness detection
//
// Two policies:
//   FixedWatchdogPolicy<Ms>  — fixed timeout, no learning (multi-conn: kill in 1s)
//   SelfLearnWatchdogPolicy  — learns server PING interval, dual condition
//
// Selection: FixedWatchdogPolicy<1000> for MaxConn > 1, SelfLearnWatchdogPolicy for single
#pragma once

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

}  // namespace websocket::policy
