// test/unittest/test_retransmit_queue.cpp
// Unit tests for ZeroCopyRetransmitQueue new APIs:
//   - for_each_expired() - lambda-based iteration
//   - mark_retransmitted(seq, now_tsc) - new signature
//   - MAX_RETRANSMITS constant

#include "../../src/stack/tcp/tcp_retransmit.hpp"
#include <iostream>
#include <cassert>
#include <vector>

using namespace userspace_stack;

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

// ============================================================================
// Test: MAX_RETRANSMITS constant
// ============================================================================
void test_max_retransmits_constant() {
    TEST("MAX_RETRANSMITS constant exists and has expected value")
        ASSERT(ZeroCopyRetransmitQueue::MAX_RETRANSMITS == 5,
               "MAX_RETRANSMITS should be 5");
    END_TEST
}

// ============================================================================
// Test: for_each_expired() - basic iteration
// ============================================================================
void test_for_each_expired_basic() {
    TEST("for_each_expired: iterates all expired segments")
        ZeroCopyRetransmitQueue queue;
        // Use a fake TSC frequency (1 MHz = 1 cycle per microsecond)
        queue.init(1000000, 100);  // 100ms RTO

        // Add 3 segments with old send_cycle (expired)
        // Note: We can't easily set send_cycle directly, so we'll use add_ref
        // and then manually check via for_each_expired with a very large now_tsc

        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);
        queue.add_ref(1050, TCP_FLAG_ACK, 1, 100, 50);
        queue.add_ref(1100, TCP_FLAG_ACK, 2, 100, 50);

        ASSERT(queue.size() == 3, "Queue should have 3 segments");

        // All segments should be expired if we use a very large now_tsc
        // RTO cycles = 100ms * 1MHz = 100,000 cycles
        uint64_t rto_cycles = 100000;
        uint64_t now_tsc = UINT64_MAX;  // Ensure all are expired

        std::vector<uint32_t> found_seqs;
        size_t count = queue.for_each_expired(now_tsc, rto_cycles,
            [&](RetransmitSegmentRef& seg) -> bool {
                found_seqs.push_back(seg.seq);
                return true;  // Continue
            });

        ASSERT(count == 3, "Should process 3 expired segments");
        ASSERT(found_seqs.size() == 3, "Lambda called 3 times");
        ASSERT(found_seqs[0] == 1000, "First segment seq");
        ASSERT(found_seqs[1] == 1050, "Second segment seq");
        ASSERT(found_seqs[2] == 1100, "Third segment seq");
    END_TEST
}

// ============================================================================
// Test: for_each_expired() - early termination
// ============================================================================
void test_for_each_expired_early_termination() {
    TEST("for_each_expired: stops when lambda returns false")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);
        queue.add_ref(1050, TCP_FLAG_ACK, 1, 100, 50);
        queue.add_ref(1100, TCP_FLAG_ACK, 2, 100, 50);

        uint64_t rto_cycles = 100000;
        uint64_t now_tsc = UINT64_MAX;

        int call_count = 0;
        size_t count = queue.for_each_expired(now_tsc, rto_cycles,
            [&](RetransmitSegmentRef& seg) -> bool {
                call_count++;
                return call_count < 2;  // Return false on 2nd call (stops iteration)
            });

        // Note: count only includes segments where callback returned true (1)
        // call_count includes the call that returned false (2)
        ASSERT(count == 1, "Should process 1 segment (only counts successful callbacks)");
        ASSERT(call_count == 2, "Lambda called exactly 2 times before stopping");
    END_TEST
}

// ============================================================================
// Test: for_each_expired() - no expired segments
// ============================================================================
void test_for_each_expired_none_expired() {
    TEST("for_each_expired: returns 0 when no segments expired")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);
        queue.add_ref(1050, TCP_FLAG_ACK, 1, 100, 50);

        // Use mark_retransmitted to set send_cycle to a known recent time
        // Then use now_tsc that's less than RTO cycles away
        uint64_t recent_time = 1000000000ULL;  // Base time
        queue.mark_retransmitted(1000, recent_time);
        queue.mark_retransmitted(1050, recent_time);

        // rto_cycles = 100000
        // now_tsc - send_cycle < rto_cycles means NOT expired
        // now_tsc = recent_time + 50 (only 50 cycles elapsed, < 100000)
        uint64_t rto_cycles = 100000;
        uint64_t now_tsc = recent_time + 50;

        int call_count = 0;
        size_t count = queue.for_each_expired(now_tsc, rto_cycles,
            [&](RetransmitSegmentRef&) -> bool {
                call_count++;
                return true;
            });

        ASSERT(count == 0, "Should process 0 expired segments");
        ASSERT(call_count == 0, "Lambda never called");
    END_TEST
}

// ============================================================================
// Test: for_each_expired() - empty queue
// ============================================================================
void test_for_each_expired_empty_queue() {
    TEST("for_each_expired: handles empty queue")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        ASSERT(queue.empty(), "Queue should be empty");

        int call_count = 0;
        size_t count = queue.for_each_expired(UINT64_MAX, 100000,
            [&](RetransmitSegmentRef& seg) -> bool {
                call_count++;
                return true;
            });

        ASSERT(count == 0, "Should process 0 segments");
        ASSERT(call_count == 0, "Lambda never called for empty queue");
    END_TEST
}

// ============================================================================
// Test: mark_retransmitted() - new signature with seq and now_tsc
// ============================================================================
void test_mark_retransmitted_new_signature() {
    TEST("mark_retransmitted: updates specific segment by seq")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);
        queue.add_ref(1050, TCP_FLAG_ACK, 1, 100, 50);
        queue.add_ref(1100, TCP_FLAG_ACK, 2, 100, 50);

        // Mark middle segment as retransmitted
        uint64_t mark_time = 999999999;
        queue.mark_retransmitted(1050, mark_time);

        // Verify via for_each_expired
        uint64_t rto_cycles = 100000;
        bool found_marked = false;
        queue.for_each_expired(UINT64_MAX, rto_cycles,
            [&](RetransmitSegmentRef& seg) -> bool {
                if (seg.seq == 1050) {
                    found_marked = true;
                    ASSERT(seg.retransmit_count == 1, "Retransmit count should be 1");
                    ASSERT(seg.send_cycle == mark_time, "send_cycle should be updated");
                }
                return true;
            });

        ASSERT(found_marked, "Should find the marked segment");
    END_TEST
}

// ============================================================================
// Test: mark_retransmitted() - increments count on multiple calls
// ============================================================================
void test_mark_retransmitted_increments_count() {
    TEST("mark_retransmitted: increments retransmit_count on each call")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);

        // Mark same segment multiple times
        queue.mark_retransmitted(1000, 100);
        queue.mark_retransmitted(1000, 200);
        queue.mark_retransmitted(1000, 300);

        // Verify count
        bool found = false;
        queue.for_each_expired(UINT64_MAX, 1,
            [&](RetransmitSegmentRef& seg) -> bool {
                if (seg.seq == 1000) {
                    found = true;
                    ASSERT(seg.retransmit_count == 3, "Retransmit count should be 3");
                    ASSERT(seg.send_cycle == 300, "send_cycle should be last mark time");
                }
                return true;
            });

        ASSERT(found, "Should find the segment");
    END_TEST
}

// ============================================================================
// Test: mark_retransmitted() - non-existent seq (no-op)
// ============================================================================
void test_mark_retransmitted_nonexistent_seq() {
    TEST("mark_retransmitted: no-op for non-existent seq")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);

        // Try to mark non-existent sequence
        queue.mark_retransmitted(9999, 100);

        // Verify original segment unchanged
        queue.for_each_expired(UINT64_MAX, 1,
            [&](RetransmitSegmentRef& seg) -> bool {
                ASSERT(seg.retransmit_count == 0, "Retransmit count should be unchanged");
                return true;
            });
    END_TEST
}

// ============================================================================
// Test: has_failed_segment() with MAX_RETRANSMITS
// ============================================================================
void test_has_failed_segment() {
    TEST("has_failed_segment: detects segment exceeding MAX_RETRANSMITS")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);

        ASSERT(!queue.has_failed_segment(), "No failed segment initially");

        // Mark MAX_RETRANSMITS times
        for (int i = 0; i < ZeroCopyRetransmitQueue::MAX_RETRANSMITS; i++) {
            ASSERT(!queue.has_failed_segment(), "Should not fail before MAX_RETRANSMITS");
            queue.mark_retransmitted(1000, i * 100);
        }

        ASSERT(queue.has_failed_segment(), "Should detect failed segment after MAX_RETRANSMITS");
    END_TEST
}

// ============================================================================
// Test: for_each_expired() - modify segment in callback
// ============================================================================
void test_for_each_expired_modify_segment() {
    TEST("for_each_expired: can modify segment via reference")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);
        queue.add_ref(1050, TCP_FLAG_ACK, 1, 100, 50);

        // Increment retransmit_count via callback
        queue.for_each_expired(UINT64_MAX, 1,
            [](RetransmitSegmentRef& seg) -> bool {
                seg.retransmit_count++;
                return true;
            });

        // Verify modifications
        std::vector<uint8_t> counts;
        queue.for_each_expired(UINT64_MAX, 1,
            [&](RetransmitSegmentRef& seg) -> bool {
                counts.push_back(seg.retransmit_count);
                return true;
            });

        ASSERT(counts.size() == 2, "Should have 2 segments");
        ASSERT(counts[0] == 1, "First segment count incremented");
        ASSERT(counts[1] == 1, "Second segment count incremented");
    END_TEST
}

// ============================================================================
// Test: for_each_expired() - partial expiration
// ============================================================================
void test_for_each_expired_partial() {
    TEST("for_each_expired: only processes expired segments")
        ZeroCopyRetransmitQueue queue;
        queue.init(1000000, 100);

        // Add segments
        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);
        queue.add_ref(1050, TCP_FLAG_ACK, 1, 100, 50);
        queue.add_ref(1100, TCP_FLAG_ACK, 2, 100, 50);

        // Mark first segment with very old time
        queue.mark_retransmitted(1000, 0);  // send_cycle = 0, very old

        // Use now_tsc that only makes the first segment expired
        // First segment: send_cycle=0, now_tsc=200000, diff=200000 >= rto_cycles(100000) -> expired
        // Other segments: send_cycle~rdtsc(), now_tsc=200000, diff might be < rto_cycles
        // Actually, since add_ref uses rdtsc(), we can't easily control this
        // Let's use a different approach: mark segments at different times

        // Reset queue
        queue.clear();
        queue.add_ref(1000, TCP_FLAG_ACK, 0, 100, 50);
        queue.add_ref(1050, TCP_FLAG_ACK, 1, 100, 50);

        // Mark first as old (send_cycle = 0)
        queue.mark_retransmitted(1000, 0);

        // Mark second as recent (send_cycle = 100000000000)
        queue.mark_retransmitted(1050, 100000000000ULL);

        // Now with rto_cycles = 100000 and now_tsc = 200000:
        // First: 200000 - 0 = 200000 >= 100000 -> expired
        // Second: 200000 - 100000000000 = negative (underflow, but treated as huge) -> not expired
        // Actually, underflow would give a very large positive number, which would be >= rto_cycles
        // Let's use a safer approach

        // Use now_tsc = 100000000001, rto_cycles = 100
        // First: 100000000001 - 0 = 100000000001 >= 100 -> expired
        // Second: 100000000001 - 100000000000 = 1 < 100 -> NOT expired

        std::vector<uint32_t> found_seqs;
        size_t count = queue.for_each_expired(100000000001ULL, 100,
            [&](RetransmitSegmentRef& seg) -> bool {
                found_seqs.push_back(seg.seq);
                return true;
            });

        ASSERT(count == 1, "Should only process 1 expired segment");
        ASSERT(found_seqs.size() == 1, "Lambda called once");
        ASSERT(found_seqs[0] == 1000, "Only first segment should be expired");
    END_TEST
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557" << std::endl;
    std::cout << "\u2551   ZeroCopyRetransmitQueue New API Tests     \u2551" << std::endl;
    std::cout << "\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D" << std::endl;
    std::cout << std::endl;

    // Run tests
    test_max_retransmits_constant();
    test_for_each_expired_basic();
    test_for_each_expired_early_termination();
    test_for_each_expired_none_expired();
    test_for_each_expired_empty_queue();
    test_mark_retransmitted_new_signature();
    test_mark_retransmitted_increments_count();
    test_mark_retransmitted_nonexistent_seq();
    test_has_failed_segment();
    test_for_each_expired_modify_segment();
    test_for_each_expired_partial();

    // Summary
    std::cout << std::endl;
    std::cout << "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550" << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;
    std::cout << "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
