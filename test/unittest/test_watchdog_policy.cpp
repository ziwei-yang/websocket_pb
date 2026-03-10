// test/unittest/test_watchdog_policy.cpp
// Unit tests for WatchdogPolicy types (FixedWatchdogPolicy, SelfLearnWatchdogPolicy)

#include "../../src/policy/watchdog.hpp"
#include <iostream>
#include <cassert>

int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) \
    std::cout << "Testing " << name << "... "; \
    try {

#define END_TEST \
        std::cout << "\u2705 PASS" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "\u274C FAIL: " << e.what() << std::endl; \
        tests_failed++; \
    }

#define ASSERT(condition, msg) \
    if (!(condition)) throw std::runtime_error(msg);

// Simulated TSC frequency: 3 GHz
static constexpr uint64_t TSC_FREQ = 3'000'000'000ULL;

// Helper: cycles for given milliseconds at TSC_FREQ
static constexpr uint64_t ms_to_cycles(uint64_t ms) {
    return (ms * TSC_FREQ) / 1000;
}

// ============================================================================
// FixedWatchdogPolicy<1000> Tests
// ============================================================================

using Fixed1s = websocket::policy::FixedWatchdogPolicy<1000>;

void test_fixed_no_data_yet() {
    TEST("Fixed: check_alert false when last_pong_recv_cycle == 0")
        Fixed1s w{};
        ASSERT(!w.check_alert(ms_to_cycles(5000), TSC_FREQ),
               "Should not alert when no PONG received yet");
    END_TEST
}

void test_fixed_fresh_pong() {
    TEST("Fixed: check_alert false when pong is fresh (< 1s)")
        Fixed1s w{};
        uint64_t now = ms_to_cycles(10000);
        w.on_pong(now);
        // 500ms later
        ASSERT(!w.check_alert(now + ms_to_cycles(500), TSC_FREQ),
               "Should not alert when pong is 500ms old");
    END_TEST
}

void test_fixed_stale_pong() {
    TEST("Fixed: check_alert true when pong is stale (> 1s)")
        Fixed1s w{};
        uint64_t now = ms_to_cycles(10000);
        w.on_pong(now);
        // 1500ms later
        ASSERT(w.check_alert(now + ms_to_cycles(1500), TSC_FREQ),
               "Should alert when pong is 1500ms old");
    END_TEST
}

void test_fixed_on_pong_updates() {
    TEST("Fixed: on_pong updates cycle, makes check_alert false")
        Fixed1s w{};
        uint64_t t0 = ms_to_cycles(10000);
        w.on_pong(t0);
        // 1500ms: stale
        uint64_t t1 = t0 + ms_to_cycles(1500);
        ASSERT(w.check_alert(t1, TSC_FREQ), "Should alert before refresh");
        // Refresh pong
        w.on_pong(t1);
        ASSERT(!w.check_alert(t1 + ms_to_cycles(500), TSC_FREQ),
               "Should not alert after refresh");
    END_TEST
}

void test_fixed_reset() {
    TEST("Fixed: reset clears state, check_alert false after reset")
        Fixed1s w{};
        uint64_t t0 = ms_to_cycles(10000);
        w.on_pong(t0);
        w.last_client_ping_cycle = t0;
        // Make stale
        ASSERT(w.check_alert(t0 + ms_to_cycles(2000), TSC_FREQ), "Should alert before reset");
        // Reset
        uint64_t t1 = t0 + ms_to_cycles(2000);
        w.reset(t1);
        ASSERT(!w.check_alert(t1 + ms_to_cycles(500), TSC_FREQ),
               "Should not alert after reset");
        ASSERT(w.last_client_ping_cycle == 0, "last_client_ping_cycle should be 0 after reset");
    END_TEST
}

void test_fixed_on_server_ping_noop() {
    TEST("Fixed: on_server_ping is no-op (no crash)")
        Fixed1s w{};
        w.on_server_ping(ms_to_cycles(1000), TSC_FREQ);
        w.on_server_ping(ms_to_cycles(2000), TSC_FREQ);
        // Should not crash, state unchanged
        ASSERT(w.last_pong_recv_cycle == 0, "PONG cycle should remain 0");
    END_TEST
}

void test_fixed_timeout_display() {
    TEST("Fixed: timeout_display_ms returns template parameter")
        Fixed1s w{};
        ASSERT(w.timeout_display_ms() == 1000, "Should be 1000");
        ASSERT(w.server_ping_display_ms() == 0, "Should be 0");

        websocket::policy::FixedWatchdogPolicy<500> w2{};
        ASSERT(w2.timeout_display_ms() == 500, "Should be 500");
    END_TEST
}

void test_fixed_exact_boundary() {
    TEST("Fixed: check_alert at exact boundary (not >) is false")
        Fixed1s w{};
        uint64_t t0 = ms_to_cycles(10000);
        w.on_pong(t0);
        // Exactly at 1s boundary
        ASSERT(!w.check_alert(t0 + ms_to_cycles(1000), TSC_FREQ),
               "Should not alert at exact boundary (requires >)");
        // 1ms over
        ASSERT(w.check_alert(t0 + ms_to_cycles(1001), TSC_FREQ),
               "Should alert 1ms past boundary");
    END_TEST
}

// ============================================================================
// SelfLearnWatchdogPolicy Tests
// ============================================================================

using SelfLearn = websocket::policy::SelfLearnWatchdogPolicy;

void test_selflearn_prelearn_default_timeout() {
    TEST("SelfLearn: pre-learning uses DEFAULT_TIMEOUT_MS (5s)")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        w.on_pong(t0);
        // 4s: should not alert
        ASSERT(!w.check_alert(t0 + ms_to_cycles(4000), TSC_FREQ),
               "Should not alert at 4s (pre-learning default 5s)");
        // 6s: should alert (PONG only, no server PING tracking)
        ASSERT(w.check_alert(t0 + ms_to_cycles(6000), TSC_FREQ),
               "Should alert at 6s (pre-learning)");
    END_TEST
}

void test_selflearn_prelearn_pong_timeout() {
    TEST("SelfLearn: pre-learning fires on PONG timeout alone")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        w.on_pong(t0);
        // No server pings at all — should alert on PONG timeout alone
        ASSERT(w.check_alert(t0 + ms_to_cycles(5001), TSC_FREQ),
               "Should alert on PONG timeout alone (pre-learning)");
    END_TEST
}

void test_selflearn_postlearn_dual_condition() {
    TEST("SelfLearn: post-learning requires BOTH pong AND ping missing")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        // Feed 3 server PINGs 3s apart → learned interval ~3s
        w.on_server_ping(t0, TSC_FREQ);
        w.on_server_ping(t0 + ms_to_cycles(3000), TSC_FREQ);
        w.on_server_ping(t0 + ms_to_cycles(6000), TSC_FREQ);
        ASSERT(w.learned_interval_cycles > 0, "Should have learned interval");

        // Set PONG baseline at t0+6s
        w.on_pong(t0 + ms_to_cycles(6000));

        // 4s later: PONG is stale (> 3s interval) but server PING was recent at t0+6s
        // Server PING threshold = 3s * 1.5 = 4.5s. At +4s since last ping, not missing yet.
        uint64_t check_time = t0 + ms_to_cycles(10000);
        ASSERT(!w.check_alert(check_time, TSC_FREQ),
               "Should NOT alert when only PONG missing but server PING recent");
    END_TEST
}

void test_selflearn_postlearn_pong_missing_ping_recent() {
    TEST("SelfLearn: post-learning doesn't fire if only pong missing but ping recent")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        // Learn 3s interval
        w.on_server_ping(t0, TSC_FREQ);
        w.on_server_ping(t0 + ms_to_cycles(3000), TSC_FREQ);

        // PONG baseline at t0
        w.on_pong(t0);

        // At t0 + 4s: PONG stale (> 3s), but last server ping was at t0+3s
        // which is only 1s ago → server ping NOT missing
        ASSERT(!w.check_alert(t0 + ms_to_cycles(4000), TSC_FREQ),
               "Should NOT alert: PONG stale but server PING recent");
    END_TEST
}

void test_selflearn_postlearn_both_missing() {
    TEST("SelfLearn: post-learning fires when both pong AND ping missing")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        // Learn 3s interval
        w.on_server_ping(t0, TSC_FREQ);
        w.on_server_ping(t0 + ms_to_cycles(3000), TSC_FREQ);

        // PONG baseline at t0
        w.on_pong(t0);

        // At t0 + 8s: PONG stale (8s > 3s) AND server ping at t0+3s is 5s ago (> 4.5s threshold)
        ASSERT(w.check_alert(t0 + ms_to_cycles(8000), TSC_FREQ),
               "Should alert: both PONG and server PING missing");
    END_TEST
}

void test_selflearn_interval_learning() {
    TEST("SelfLearn: on_server_ping computes learned_interval_cycles correctly")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        // Feed 3 pings 2s apart
        w.on_server_ping(t0, TSC_FREQ);
        ASSERT(w.learned_interval_cycles == 0, "No interval after 1 sample");

        w.on_server_ping(t0 + ms_to_cycles(2000), TSC_FREQ);
        ASSERT(w.learned_interval_cycles == ms_to_cycles(2000),
               "Interval should be 2s after 2 samples");

        w.on_server_ping(t0 + ms_to_cycles(4000), TSC_FREQ);
        // avg = (4000ms - 0ms) / 2 = 2000ms
        ASSERT(w.learned_interval_cycles == ms_to_cycles(2000),
               "Interval should still be 2s after 3 samples");
        ASSERT(w.learned_interval_ms == 2000,
               "learned_interval_ms should be 2000");
    END_TEST
}

void test_selflearn_bogus_interval() {
    TEST("SelfLearn: on_server_ping rejects bogus intervals < 1s")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        // Feed pings 500ms apart — should reject
        w.on_server_ping(t0, TSC_FREQ);
        w.on_server_ping(t0 + ms_to_cycles(500), TSC_FREQ);
        ASSERT(w.server_ping_count == 0, "Count should reset on bogus interval");
        ASSERT(w.learned_interval_cycles == 0, "Interval should reset on bogus");
        ASSERT(w.learned_interval_ms == 0, "Interval ms should reset on bogus");
    END_TEST
}

void test_selflearn_reset() {
    TEST("SelfLearn: reset clears state")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        // Build up state
        w.on_server_ping(t0, TSC_FREQ);
        w.on_server_ping(t0 + ms_to_cycles(3000), TSC_FREQ);
        w.on_pong(t0 + ms_to_cycles(3000));
        w.last_client_ping_cycle = t0 + ms_to_cycles(3000);

        uint64_t t1 = t0 + ms_to_cycles(5000);
        w.reset(t1);

        ASSERT(w.server_ping_count == 0, "server_ping_count should be 0");
        ASSERT(w.last_client_ping_cycle == 0, "last_client_ping_cycle should be 0");
        ASSERT(w.last_pong_recv_cycle == t1, "last_pong_recv_cycle should be reset time");
        ASSERT(w.last_server_ping_cycle == t1, "last_server_ping_cycle should be reset time");

        // After reset, should not alert within default timeout
        ASSERT(!w.check_alert(t1 + ms_to_cycles(1000), TSC_FREQ),
               "Should not alert 1s after reset");
    END_TEST
}

void test_selflearn_no_data_yet() {
    TEST("SelfLearn: check_alert false when last_pong_recv_cycle == 0")
        SelfLearn w{};
        ASSERT(!w.check_alert(ms_to_cycles(10000), TSC_FREQ),
               "Should not alert when no PONG received yet");
    END_TEST
}

void test_selflearn_display_methods() {
    TEST("SelfLearn: timeout_display_ms and server_ping_display_ms")
        SelfLearn w{};
        // Pre-learning
        ASSERT(w.timeout_display_ms() == 5000, "Pre-learning timeout should be 5000");
        ASSERT(w.server_ping_display_ms() == 0, "Pre-learning server ping should be 0");

        // Learn 3s interval
        uint64_t t0 = ms_to_cycles(10000);
        w.on_server_ping(t0, TSC_FREQ);
        w.on_server_ping(t0 + ms_to_cycles(3000), TSC_FREQ);

        // Post-learning
        ASSERT(w.timeout_display_ms() == 3000, "Post-learning timeout should be 3000");
        ASSERT(w.server_ping_display_ms() == 4500, "Post-learning server ping threshold should be 4500");
    END_TEST
}

void test_selflearn_learn_then_reset_preserves_nothing() {
    TEST("SelfLearn: reset after learning preserves nothing")
        SelfLearn w{};
        uint64_t t0 = ms_to_cycles(10000);
        w.on_server_ping(t0, TSC_FREQ);
        w.on_server_ping(t0 + ms_to_cycles(3000), TSC_FREQ);
        ASSERT(w.learned_interval_cycles > 0, "Should have learned");

        w.reset(t0 + ms_to_cycles(5000));
        ASSERT(w.server_ping_count == 0, "Count should be 0 after reset");
        // Note: learned_interval_cycles is NOT cleared by reset (preserves learned knowledge)
        // The dual-condition check still uses server_ping_count >= 2 to decide
        // so with count=0, it falls back to pre-learning mode
        ASSERT(w.timeout_display_ms() == 5000,
               "Should fall back to default timeout after reset");
    END_TEST
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Watchdog Policy Unit Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << "\n--- FixedWatchdogPolicy<1000> Tests ---" << std::endl;
    test_fixed_no_data_yet();
    test_fixed_fresh_pong();
    test_fixed_stale_pong();
    test_fixed_on_pong_updates();
    test_fixed_reset();
    test_fixed_on_server_ping_noop();
    test_fixed_timeout_display();
    test_fixed_exact_boundary();

    std::cout << "\n--- SelfLearnWatchdogPolicy Tests ---" << std::endl;
    test_selflearn_no_data_yet();
    test_selflearn_prelearn_default_timeout();
    test_selflearn_prelearn_pong_timeout();
    test_selflearn_postlearn_dual_condition();
    test_selflearn_postlearn_pong_missing_ping_recent();
    test_selflearn_postlearn_both_missing();
    test_selflearn_interval_learning();
    test_selflearn_bogus_interval();
    test_selflearn_reset();
    test_selflearn_display_methods();
    test_selflearn_learn_then_reset_preserves_nothing();

    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
