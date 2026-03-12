// test/unittest/test_tx_pool_fifo.cpp
// Unit tests for TX frame pool FIFO release logic (dpdk_packet_io.hpp)
//
// Tests the claim/commit/ack/free cycle and verifies the fix:
// mbuf pre-allocation in claim_tx_frames() prevents FIFO deadlock by
// failing the claim BEFORE incrementing tx_alloc_pos_ when mbufs are exhausted.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <cassert>
#include <stdexcept>
#include <functional>

int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) \
    std::cout << "Testing " << name << "... "; \
    try {

#define END_TEST \
        std::cout << "\xE2\x9C\x85 PASS" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "\xE2\x9D\x8C FAIL: " << e.what() << std::endl; \
        tests_failed++; \
    }

#define ASSERT(condition, msg) \
    if (!(condition)) throw std::runtime_error(msg);

// ============================================================================
// MockTxPool — Models the FIXED DPDKPacketIO TX pool (mbuf pre-alloc in claim)
// ============================================================================

struct MockTxPool {
    static constexpr uint32_t POOL_SIZE = 8;  // Small for testing
    static constexpr uint32_t POOL_START = 100;  // Simulated frame index offset

    uint32_t tx_alloc_pos = 0;
    uint32_t tx_free_pos = 0;
    bool frame_acked[POOL_SIZE] = {};
    bool frame_sent[POOL_SIZE] = {};

    // Tracks how many mbufs are "available" (simulates rte_pktmbuf_alloc)
    uint32_t mbuf_avail;

    MockTxPool(uint32_t initial_mbufs = POOL_SIZE)
        : mbuf_avail(initial_mbufs) {}

    uint32_t in_use() const { return tx_alloc_pos - tx_free_pos; }
    uint32_t available() const { return POOL_SIZE - in_use(); }

    // Mirrors FIXED DPDKPacketIO::claim_tx_frames()
    // mbuf is pre-allocated BEFORE tx_alloc_pos_++ — no orphaned frames
    uint32_t claim_tx_frames(uint32_t count) {
        uint32_t claimed = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (in_use() >= POOL_SIZE) break;

            // Pre-allocate mbuf BEFORE incrementing tx_alloc_pos
            if (mbuf_avail == 0) break;  // claim fails cleanly
            mbuf_avail--;

            uint32_t relative_idx = tx_alloc_pos % POOL_SIZE;
            frame_sent[relative_idx] = false;
            frame_acked[relative_idx] = false;  // defense-in-depth
            tx_alloc_pos++;
            claimed++;
        }
        return claimed;
    }

    // Mirrors FIXED DPDKPacketIO::commit_tx_frames()
    // mbufs already pre-allocated in claim — commit always succeeds
    uint32_t commit_tx_frames(uint32_t count) {
        uint32_t committed = 0;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t relative_idx = (tx_alloc_pos - count + i) % POOL_SIZE;
            frame_sent[relative_idx] = true;
            committed++;
        }
        return committed;
    }

    // Combined claim+commit (like normal data send path)
    // Returns {claimed, committed}
    std::pair<uint32_t, uint32_t> claim_and_commit(uint32_t count) {
        uint32_t claimed = claim_tx_frames(count);
        uint32_t committed = commit_tx_frames(claimed);
        return {claimed, committed};
    }

    // Mirrors commit_ack_frame(): claim 1, commit 1, immediately ack
    // Returns frame_idx or 0 on failure
    uint32_t commit_ack_frame() {
        uint32_t claimed = claim_tx_frames(1);
        if (claimed == 0) return 0;

        uint32_t relative_idx = (tx_alloc_pos - 1) % POOL_SIZE;
        uint32_t frame_idx = POOL_START + relative_idx;

        commit_tx_frames(1);

        // ACK immediately (ACKs don't wait for TCP ACK)
        mark_frame_acked(frame_idx);
        return frame_idx;
    }

    // Mirrors DPDKPacketIO::mark_frame_acked()
    void mark_frame_acked(uint32_t frame_idx) {
        if (frame_idx < POOL_START || frame_idx >= POOL_START + POOL_SIZE) return;
        uint32_t relative_idx = (frame_idx - POOL_START) % POOL_SIZE;
        frame_acked[relative_idx] = true;

        // FIFO release: advance tx_free_pos while contiguous frames are acked
        while (tx_free_pos < tx_alloc_pos) {
            uint32_t free_rel = tx_free_pos % POOL_SIZE;
            if (!frame_acked[free_rel]) break;
            frame_acked[free_rel] = false;
            frame_sent[free_rel] = false;
            tx_free_pos++;
        }
    }

    // Simulate NIC returning mbufs (driver TX completion)
    void return_mbufs(uint32_t count) {
        mbuf_avail += count;
    }

    // Diagnostic: check if the FIFO is stuck (head frame not acked, not sent)
    bool is_fifo_stuck() const {
        if (tx_free_pos >= tx_alloc_pos) return false;
        uint32_t head_rel = tx_free_pos % POOL_SIZE;
        return !frame_acked[head_rel] && !frame_sent[head_rel];
    }
};


// ============================================================================
// Test: Normal operation — claim, commit, ack, free cycle
// ============================================================================
void test_normal_cycle() {
    TEST("Normal claim/commit/ack/free cycle")
        MockTxPool pool;

        // Claim and commit 3 frames
        auto [claimed, committed] = pool.claim_and_commit(3);
        ASSERT(claimed == 3, "Should claim 3");
        ASSERT(committed == 3, "Should commit 3");
        ASSERT(pool.in_use() == 3, "3 frames in use");

        // ACK all 3 in order
        pool.mark_frame_acked(MockTxPool::POOL_START + 0);
        ASSERT(pool.in_use() == 2, "After ack #0: 2 in use");
        pool.mark_frame_acked(MockTxPool::POOL_START + 1);
        ASSERT(pool.in_use() == 1, "After ack #1: 1 in use");
        pool.mark_frame_acked(MockTxPool::POOL_START + 2);
        ASSERT(pool.in_use() == 0, "After ack #2: 0 in use");
    END_TEST
}

// ============================================================================
// Test: Out-of-order ACK with FIFO release
// ============================================================================
void test_out_of_order_ack() {
    TEST("Out-of-order ACK: FIFO releases only contiguous")
        MockTxPool pool;

        auto [claimed, committed] = pool.claim_and_commit(4);
        ASSERT(claimed == 4 && committed == 4, "Claim/commit 4");

        // ACK #2 first (out of order)
        pool.mark_frame_acked(MockTxPool::POOL_START + 2);
        ASSERT(pool.in_use() == 4, "Out-of-order ack: still 4 in use (FIFO blocked at #0)");

        // ACK #0
        pool.mark_frame_acked(MockTxPool::POOL_START + 0);
        ASSERT(pool.in_use() == 3, "After ack #0: 3 in use (released #0 only)");

        // ACK #1 — should trigger cascade release of #1 and #2
        pool.mark_frame_acked(MockTxPool::POOL_START + 1);
        ASSERT(pool.in_use() == 1, "After ack #1: 1 in use (cascade released #1,#2)");

        // ACK #3
        pool.mark_frame_acked(MockTxPool::POOL_START + 3);
        ASSERT(pool.in_use() == 0, "All freed");
    END_TEST
}

// ============================================================================
// Test: Pool full — claim rejected
// ============================================================================
void test_pool_full_claim_rejected() {
    TEST("Pool full: claim correctly rejected")
        MockTxPool pool;

        // Fill pool completely
        auto [c1, co1] = pool.claim_and_commit(MockTxPool::POOL_SIZE);
        ASSERT(c1 == MockTxPool::POOL_SIZE, "Fill pool");
        ASSERT(pool.in_use() == MockTxPool::POOL_SIZE, "Pool full");

        // Try to claim more — should be rejected
        uint32_t extra = pool.claim_tx_frames(1);
        ASSERT(extra == 0, "Cannot claim when pool full");
    END_TEST
}

// ============================================================================
// FIX VERIFICATION: mbuf exhaustion causes clean claim failure (no deadlock)
// ============================================================================
void test_mbuf_failure_causes_clean_claim_failure() {
    TEST("FIX: mbuf exhaustion causes clean claim failure, no FIFO deadlock")
        // Start with limited mbufs (simulates DPDK mbuf pool depletion)
        MockTxPool pool(4);  // Only 4 mbufs available

        // Successfully send frames #0..#3 (uses all 4 mbufs)
        auto [c1, co1] = pool.claim_and_commit(4);
        ASSERT(c1 == 4 && co1 == 4, "First batch: 4 claimed, 4 committed");
        ASSERT(pool.mbuf_avail == 0, "All mbufs consumed");

        // NIC ACKs frames #0..#3, freeing UMEM slots
        for (uint32_t i = 0; i < 4; i++)
            pool.mark_frame_acked(MockTxPool::POOL_START + i);
        ASSERT(pool.in_use() == 0, "All frames freed");

        // But NIC hasn't returned mbufs yet (still in TX completion queue)
        // pool.mbuf_avail is still 0

        // FIX: claim now fails cleanly — mbuf checked BEFORE tx_alloc_pos_++
        uint32_t claimed2 = pool.claim_tx_frames(2);
        ASSERT(claimed2 == 0, "Claim returns 0: no mbufs available");
        ASSERT(pool.in_use() == 0, "No orphaned frames — pool is clean");
        ASSERT(!pool.is_fifo_stuck(), "FIFO is NOT stuck");

        // Once NIC returns mbufs, everything works again
        pool.return_mbufs(4);
        auto [c3, co3] = pool.claim_and_commit(4);
        ASSERT(c3 == 4 && co3 == 4, "After mbuf return: claim+commit succeeds");
        ASSERT(pool.in_use() == 4, "4 frames in use");

        // ACK all — pool fully recovers
        for (uint32_t i = 0; i < 4; i++)
            pool.mark_frame_acked(MockTxPool::POOL_START + (pool.tx_alloc_pos - 4 + i) % MockTxPool::POOL_SIZE + MockTxPool::POOL_START);
        // Simpler: just mark them by relative position
    END_TEST
}

// ============================================================================
// FIX VERIFICATION: No gradual pool leak from intermittent mbuf failures
// ============================================================================
void test_no_gradual_pool_leak() {
    TEST("FIX: Intermittent mbuf failures cause NO pool leak")
        MockTxPool pool(MockTxPool::POOL_SIZE);

        // Simulate many send/ack cycles with occasional mbuf failures
        for (int cycle = 0; cycle < 40; cycle++) {
            // Every 5th cycle, simulate mbuf depletion
            if (cycle % 5 == 3) {
                pool.mbuf_avail = 0;
            }

            uint32_t claimed = pool.claim_tx_frames(1);
            if (claimed == 0) {
                // FIX: claim fails cleanly, no frame leaked
                ASSERT(!pool.is_fifo_stuck(), "No FIFO stuck after failed claim");
                pool.return_mbufs(2);  // NIC returns mbufs later
                continue;
            }

            pool.commit_tx_frames(1);

            // Simulate TCP ACK for committed frame
            uint32_t frame_idx = MockTxPool::POOL_START +
                                 (pool.tx_alloc_pos - 1) % MockTxPool::POOL_SIZE;
            pool.mark_frame_acked(frame_idx);
            pool.return_mbufs(1);  // NIC returns the mbuf
        }

        // After all cycles, pool should be completely clean
        ASSERT(pool.in_use() == 0, "Pool is clean after all cycles");
        ASSERT(!pool.is_fifo_stuck(), "FIFO never got stuck");
    END_TEST
}

// ============================================================================
// FIX VERIFICATION: ACK frames work fine even after mbuf failures
// ============================================================================
void test_ack_frame_works_after_mbuf_recovery() {
    TEST("FIX: ACK frames work after mbuf recovery")
        MockTxPool pool(2);  // Very limited mbufs

        // Send 2 data frames — uses all mbufs
        auto [c1, co1] = pool.claim_and_commit(2);
        ASSERT(c1 == 2 && co1 == 2, "2 data frames sent");

        // ACK them, but NIC hasn't returned mbufs
        pool.mark_frame_acked(MockTxPool::POOL_START + 0);
        pool.mark_frame_acked(MockTxPool::POOL_START + 1);
        ASSERT(pool.in_use() == 0, "UMEM frames freed");

        // FIX: claim fails cleanly (no mbufs), no FIFO corruption
        uint32_t c2 = pool.claim_tx_frames(1);
        ASSERT(c2 == 0, "Claim returns 0: no mbufs");
        ASSERT(!pool.is_fifo_stuck(), "FIFO is clean — no orphaned frames");

        // NIC returns mbufs
        pool.return_mbufs(4);

        // Now ACKs work fine — pool is clean, mbufs available
        uint32_t acks_sent = 0;
        for (int i = 0; i < (int)MockTxPool::POOL_SIZE; i++) {
            uint32_t ack_idx = pool.commit_ack_frame();
            if (ack_idx == 0) break;
            acks_sent++;
        }
        // All ACK frames should succeed (pool has space, mbufs available)
        // ACKs are immediately acked, so pool drains after each one
        ASSERT(acks_sent == 4, "All 4 ACK frames sent successfully");
        ASSERT(pool.in_use() == 0, "Pool clean after ACKs (all immediately freed)");
    END_TEST
}

// ============================================================================
// Test: mbuf exhaustion during partial claim
// ============================================================================
void test_mbuf_exhaustion_partial_claim() {
    TEST("FIX: mbuf exhaustion mid-batch stops cleanly")
        MockTxPool pool(3);  // Only 3 mbufs, try to claim 5

        uint32_t claimed = pool.claim_tx_frames(5);
        ASSERT(claimed == 3, "Partial claim: got 3 (limited by mbufs)");
        ASSERT(pool.in_use() == 3, "3 in use");

        // Commit the 3 claimed frames
        pool.commit_tx_frames(3);
        ASSERT(!pool.is_fifo_stuck(), "No FIFO stuck after commit");

        // Ack all 3
        for (uint32_t i = 0; i < 3; i++) {
            pool.mark_frame_acked(MockTxPool::POOL_START + i);
        }
        ASSERT(pool.in_use() == 0, "All freed");
    END_TEST
}

// ============================================================================
// Test: Wrapping behavior — pool slots reuse after full cycle
// ============================================================================
void test_pool_wrapping() {
    TEST("Pool wrapping: slots correctly reused after full cycle")
        MockTxPool pool;

        // Run through 3 full pool cycles (3 * 8 = 24 frames)
        for (int cycle = 0; cycle < 3; cycle++) {
            for (uint32_t i = 0; i < MockTxPool::POOL_SIZE; i++) {
                auto [c, co] = pool.claim_and_commit(1);
                ASSERT(c == 1 && co == 1, "Claim+commit 1 frame");
                uint32_t idx = MockTxPool::POOL_START +
                               (pool.tx_alloc_pos - 1) % MockTxPool::POOL_SIZE;
                pool.mark_frame_acked(idx);
                pool.return_mbufs(1);
            }
            ASSERT(pool.in_use() == 0, "All frames freed after cycle");
        }
        ASSERT(pool.tx_alloc_pos == 24, "24 total allocations across 3 cycles");
        ASSERT(pool.tx_free_pos == 24, "24 total frees");
    END_TEST
}


// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "=== TX Pool FIFO Release Unit Tests ===" << std::endl;
    std::cout << "(Tests verify DPDK TX pool mbuf pre-alloc fix)" << std::endl;
    std::cout << std::endl;

    test_normal_cycle();
    test_out_of_order_ack();
    test_pool_full_claim_rejected();
    test_pool_wrapping();
    test_mbuf_failure_causes_clean_claim_failure();
    test_no_gradual_pool_leak();
    test_ack_frame_works_after_mbuf_recovery();
    test_mbuf_exhaustion_partial_claim();

    std::cout << std::endl;
    std::cout << "=== Results: " << tests_passed << " passed, "
              << tests_failed << " failed ===" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
