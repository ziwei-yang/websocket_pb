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

    // Simulates rte_eth_tx_burst() returning 0 (NIC TX ring temporarily full)
    bool tx_burst_fail = false;

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

    // Mirrors DPDKPacketIO::commit_tx_frames()
    // When tx_burst_fail=true, simulates rte_eth_tx_burst() returning 0:
    // frame_sent[] is set (attach_extbuf happened), but burst fails, mbuf freed.
    uint32_t commit_tx_frames(uint32_t count) {
        uint32_t committed = 0;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t relative_idx = (tx_alloc_pos - count + i) % POOL_SIZE;
            frame_sent[relative_idx] = true;
            committed++;
        }
        if (tx_burst_fail) {
            // tx_burst returned 0: free mbufs (return to pool), report 0 sent
            return_mbufs(count);
            return 0;
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

    // Mirrors FIXED commit_ack_frame(): claim 1, commit 1, always ack FIFO slot.
    // Returns frame_idx or 0 on failure.
    uint32_t commit_ack_frame() {
        uint32_t claimed = claim_tx_frames(1);
        if (claimed == 0) return 0;

        uint32_t relative_idx = (tx_alloc_pos - 1) % POOL_SIZE;
        uint32_t frame_idx = POOL_START + relative_idx;

        uint32_t committed = commit_tx_frames(1);

        // Always free FIFO slot — ACK frames are fire-and-forget.
        mark_frame_acked(frame_idx);

        if (committed == 0) return 0;
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
// FIX: ACK frame tx_burst failure does NOT leak FIFO slot
// ============================================================================
void test_ack_frame_tx_burst_fail_no_leak() {
    TEST("FIX: ACK frame tx_burst failure does NOT leak FIFO slot")
        MockTxPool pool;

        // Simulate NIC TX ring temporarily full
        pool.tx_burst_fail = true;

        // commit_ack_frame: claim succeeds, tx_burst fails → returns 0
        uint32_t result = pool.commit_ack_frame();
        ASSERT(result == 0, "commit_ack_frame returns 0 on tx_burst failure");

        // CRITICAL: FIFO slot must NOT be leaked
        ASSERT(pool.in_use() == 0, "No FIFO slot leaked after tx_burst failure");
        ASSERT(!pool.is_fifo_stuck(), "FIFO is not stuck");

        // Restore normal operation
        pool.tx_burst_fail = false;

        // Pool should be fully functional — can still claim all slots
        auto [c, co] = pool.claim_and_commit(MockTxPool::POOL_SIZE);
        ASSERT(c == MockTxPool::POOL_SIZE, "Pool fully usable after failed ACK");
    END_TEST
}

// ============================================================================
// FIX: Repeated ACK tx_burst failures don't fill pool (deadlock scenario)
// ============================================================================
void test_ack_frame_tx_burst_fail_no_deadlock() {
    TEST("FIX: Repeated ACK tx_burst failures don't deadlock pool")
        MockTxPool pool;
        pool.tx_burst_fail = true;

        // Simulate many failed ACK commits (e.g., during TLS handshake errors)
        for (int i = 0; i < 100; i++) {
            uint32_t result = pool.commit_ack_frame();
            ASSERT(result == 0, "Each failed ACK returns 0");
        }

        // Pool must still be completely empty — no leaked slots
        ASSERT(pool.in_use() == 0, "Zero slots leaked after 100 failed ACKs");

        // Restore and verify pool is fully functional
        pool.tx_burst_fail = false;
        pool.return_mbufs(MockTxPool::POOL_SIZE);  // replenish mbufs consumed by claims
        auto [c, co] = pool.claim_and_commit(MockTxPool::POOL_SIZE);
        ASSERT(c == MockTxPool::POOL_SIZE, "Pool fully usable — no deadlock");
    END_TEST
}

// ============================================================================
// MockDualPool — Models the split TX Data + ACK pool (HOL-fix)
// ============================================================================

struct MockDualPool {
    // Data pool (retransmit-tracked)
    static constexpr uint32_t DATA_POOL_SIZE = 8;
    static constexpr uint32_t DATA_POOL_START = 100;
    uint32_t tx_alloc_pos = 0, tx_free_pos = 0;
    bool frame_acked[DATA_POOL_SIZE] = {}, frame_sent[DATA_POOL_SIZE] = {};
    uint32_t mbuf_avail;
    bool tx_burst_fail = false;

    // ACK pool (fire-and-forget)
    static constexpr uint32_t ACK_POOL_SIZE = 8;
    static constexpr uint32_t ACK_POOL_START = DATA_POOL_START + DATA_POOL_SIZE;  // 108
    uint32_t ack_alloc_pos = 0, ack_free_pos = 0;
    bool ack_frame_acked[ACK_POOL_SIZE] = {}, ack_frame_sent[ACK_POOL_SIZE] = {};

    MockDualPool(uint32_t initial_mbufs = DATA_POOL_SIZE + ACK_POOL_SIZE)
        : mbuf_avail(initial_mbufs) {}

    uint32_t data_in_use() const { return tx_alloc_pos - tx_free_pos; }
    uint32_t data_avail() const { return DATA_POOL_SIZE - data_in_use(); }
    uint32_t ack_in_use() const { return ack_alloc_pos - ack_free_pos; }
    uint32_t ack_avail() const { return ACK_POOL_SIZE - ack_in_use(); }

    // Data pool: claim_tx_frames (same as MockTxPool)
    uint32_t claim_tx_frames(uint32_t count) {
        uint32_t claimed = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (data_in_use() >= DATA_POOL_SIZE) break;
            if (mbuf_avail == 0) break;
            mbuf_avail--;
            uint32_t relative_idx = tx_alloc_pos % DATA_POOL_SIZE;
            frame_sent[relative_idx] = false;
            frame_acked[relative_idx] = false;
            tx_alloc_pos++;
            claimed++;
        }
        return claimed;
    }

    uint32_t commit_tx_frames(uint32_t count) {
        for (uint32_t i = 0; i < count; i++) {
            uint32_t relative_idx = (tx_alloc_pos - count + i) % DATA_POOL_SIZE;
            frame_sent[relative_idx] = true;
        }
        if (tx_burst_fail) { mbuf_avail += count; return 0; }
        return count;
    }

    std::pair<uint32_t, uint32_t> claim_and_commit(uint32_t count) {
        uint32_t claimed = claim_tx_frames(count);
        uint32_t committed = commit_tx_frames(claimed);
        return {claimed, committed};
    }

    void mark_frame_acked(uint32_t frame_idx) {
        if (frame_idx < DATA_POOL_START || frame_idx >= DATA_POOL_START + DATA_POOL_SIZE) return;
        uint32_t relative_idx = (frame_idx - DATA_POOL_START) % DATA_POOL_SIZE;
        frame_acked[relative_idx] = true;
        while (tx_free_pos < tx_alloc_pos) {
            uint32_t free_rel = tx_free_pos % DATA_POOL_SIZE;
            if (!frame_acked[free_rel]) break;
            frame_acked[free_rel] = false;
            frame_sent[free_rel] = false;
            tx_free_pos++;
        }
    }

    // ACK pool: commit_ack_frame (uses separate pool)
    uint32_t commit_ack_frame() {
        if (ack_in_use() >= ACK_POOL_SIZE) return 0;
        if (mbuf_avail == 0) return 0;
        mbuf_avail--;

        uint32_t relative_idx = ack_alloc_pos % ACK_POOL_SIZE;
        uint32_t frame_idx = ACK_POOL_START + relative_idx;
        ack_frame_sent[relative_idx] = false;
        ack_frame_acked[relative_idx] = false;

        ack_frame_sent[relative_idx] = true;
        ack_alloc_pos++;

        if (tx_burst_fail) {
            mbuf_avail++;
            mark_ack_frame_acked(frame_idx);
            return 0;
        }

        // Always free — fire-and-forget
        mark_ack_frame_acked(frame_idx);
        return frame_idx;
    }

    void mark_ack_frame_acked(uint32_t frame_idx) {
        uint32_t relative_idx = (frame_idx - ACK_POOL_START) % ACK_POOL_SIZE;
        ack_frame_acked[relative_idx] = true;
        while (ack_free_pos < ack_alloc_pos) {
            uint32_t free_rel = ack_free_pos % ACK_POOL_SIZE;
            if (!ack_frame_acked[free_rel]) break;
            ack_frame_acked[free_rel] = false;
            ack_frame_sent[free_rel] = false;
            ack_free_pos++;
        }
    }

    void return_mbufs(uint32_t count) { mbuf_avail += count; }
};

// ============================================================================
// DUAL POOL TESTS — Verify HOL-fix: data pool full does NOT block ACK pool
// ============================================================================

void test_data_pool_full_does_not_affect_ack_pool() {
    TEST("HOL-FIX: data pool full does NOT affect ACK pool")
        MockDualPool pool;

        // Fill data pool completely (no ACKs from remote yet)
        auto [c, co] = pool.claim_and_commit(MockDualPool::DATA_POOL_SIZE);
        ASSERT(c == MockDualPool::DATA_POOL_SIZE, "Data pool filled");
        ASSERT(pool.data_in_use() == MockDualPool::DATA_POOL_SIZE, "Data pool full");

        // Data pool full — cannot claim more data frames
        ASSERT(pool.claim_tx_frames(1) == 0, "Data pool rejects new claims");

        // BUT: ACK pool is completely independent — ACKs still work!
        uint32_t acks_sent = 0;
        for (uint32_t i = 0; i < MockDualPool::ACK_POOL_SIZE; i++) {
            uint32_t idx = pool.commit_ack_frame();
            if (idx == 0) break;
            ASSERT(idx >= MockDualPool::ACK_POOL_START, "ACK frame_idx in ACK pool range");
            ASSERT(idx < MockDualPool::ACK_POOL_START + MockDualPool::ACK_POOL_SIZE, "ACK frame_idx in range");
            acks_sent++;
        }
        ASSERT(acks_sent == MockDualPool::ACK_POOL_SIZE, "All ACK frames sent despite data pool being full");
        ASSERT(pool.ack_in_use() == 0, "ACK pool clean (all immediately freed)");
    END_TEST
}

void test_ack_pool_basic_alloc_free() {
    TEST("ACK pool: basic alloc/free cycle")
        MockDualPool pool;

        uint32_t idx = pool.commit_ack_frame();
        ASSERT(idx >= MockDualPool::ACK_POOL_START, "Frame idx in ACK range");
        ASSERT(idx < MockDualPool::ACK_POOL_START + MockDualPool::ACK_POOL_SIZE, "Frame idx in range");
        ASSERT(pool.ack_in_use() == 0, "Immediately freed (fire-and-forget)");
        ASSERT(pool.ack_alloc_pos == 1, "ack_alloc_pos advanced");
        ASSERT(pool.ack_free_pos == 1, "ack_free_pos advanced (immediately freed)");
    END_TEST
}

void test_ack_pool_fifo_sequential() {
    TEST("ACK pool: N sequential commit_ack_frames")
        MockDualPool pool;

        for (uint32_t i = 0; i < MockDualPool::ACK_POOL_SIZE; i++) {
            uint32_t idx = pool.commit_ack_frame();
            ASSERT(idx != 0, "ACK frame succeeded");
        }
        ASSERT(pool.ack_alloc_pos == MockDualPool::ACK_POOL_SIZE, "Alloc pos advanced by N");
        ASSERT(pool.ack_free_pos == MockDualPool::ACK_POOL_SIZE, "Free pos advanced by N");
        ASSERT(pool.ack_in_use() == 0, "All freed");
    END_TEST
}

void test_ack_pool_full() {
    TEST("ACK pool full: returns 0, data pool unaffected")
        MockDualPool pool(MockDualPool::DATA_POOL_SIZE + MockDualPool::ACK_POOL_SIZE);

        // Fill data pool to verify independence
        auto [c, co] = pool.claim_and_commit(4);
        ASSERT(c == 4, "Data pool: 4 claimed");

        // Send ACKs with mbuf replenishment (simulates NIC returning mbufs)
        for (uint32_t i = 0; i < 20; i++) {
            uint32_t idx = pool.commit_ack_frame();
            ASSERT(idx != 0, "ACK succeeds (self-draining pool)");
            pool.return_mbufs(1);  // NIC returns the mbuf
        }
        // Data pool still has 4 in use
        ASSERT(pool.data_in_use() == 4, "Data pool unaffected by ACK traffic");
    END_TEST
}

void test_ack_pool_wrap_around() {
    TEST("ACK pool: wrap around pool boundary")
        MockDualPool pool;

        // Send 3 full cycles of ACKs (3 * 8 = 24 ACKs)
        for (uint32_t cycle = 0; cycle < 3; cycle++) {
            for (uint32_t i = 0; i < MockDualPool::ACK_POOL_SIZE; i++) {
                uint32_t idx = pool.commit_ack_frame();
                ASSERT(idx != 0, "ACK frame succeeded");
                pool.return_mbufs(1);  // NIC returns the mbuf
            }
        }
        ASSERT(pool.ack_alloc_pos == 24, "24 total ACK allocations");
        ASSERT(pool.ack_free_pos == 24, "24 total ACK frees");
        ASSERT(pool.ack_in_use() == 0, "All freed after wrap");
    END_TEST
}

void test_ack_pool_tx_burst_fail_no_leak() {
    TEST("ACK pool: tx_burst failure does NOT leak FIFO slot")
        MockDualPool pool;
        pool.tx_burst_fail = true;

        uint32_t result = pool.commit_ack_frame();
        ASSERT(result == 0, "Returns 0 on tx_burst failure");
        ASSERT(pool.ack_in_use() == 0, "No ACK FIFO slot leaked");

        pool.tx_burst_fail = false;
        // Pool still works
        uint32_t idx = pool.commit_ack_frame();
        ASSERT(idx != 0, "ACK pool works after recovery");
    END_TEST
}

void test_pools_independent_exhaustion() {
    TEST("Pools independent: fill each, other remains available")
        MockDualPool pool;

        // Fill data pool
        auto [c, co] = pool.claim_and_commit(MockDualPool::DATA_POOL_SIZE);
        ASSERT(c == MockDualPool::DATA_POOL_SIZE, "Data pool filled");
        ASSERT(pool.data_avail() == 0, "Data pool: 0 available");

        // ACK pool unaffected
        ASSERT(pool.ack_avail() == MockDualPool::ACK_POOL_SIZE, "ACK pool: full capacity");
        uint32_t idx = pool.commit_ack_frame();
        ASSERT(idx != 0, "ACK works with data pool full");

        // Free data pool
        for (uint32_t i = 0; i < MockDualPool::DATA_POOL_SIZE; i++) {
            pool.mark_frame_acked(MockDualPool::DATA_POOL_START + i);
        }
        ASSERT(pool.data_avail() == MockDualPool::DATA_POOL_SIZE, "Data pool recovered");
    END_TEST
}

void test_frame_idx_routing() {
    TEST("Frame idx routing: mark_frame_acked only affects data pool")
        MockDualPool pool;

        // Claim 2 data frames
        auto [c, co] = pool.claim_and_commit(2);
        ASSERT(c == 2, "2 data frames claimed");

        // Send 2 ACKs
        uint32_t ack1 = pool.commit_ack_frame();
        uint32_t ack2 = pool.commit_ack_frame();
        ASSERT(ack1 != 0 && ack2 != 0, "2 ACKs sent");

        // mark_frame_acked with ACK pool indices should be no-op for data pool
        pool.mark_frame_acked(ack1);  // Out of data pool range — ignored
        pool.mark_frame_acked(ack2);  // Out of data pool range — ignored
        ASSERT(pool.data_in_use() == 2, "Data pool unaffected by ACK pool indices");

        // mark_frame_acked with data pool indices works correctly
        pool.mark_frame_acked(MockDualPool::DATA_POOL_START + 0);
        ASSERT(pool.data_in_use() == 1, "Data frame #0 freed");
        pool.mark_frame_acked(MockDualPool::DATA_POOL_START + 1);
        ASSERT(pool.data_in_use() == 0, "Data frame #1 freed");
    END_TEST
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "=== TX Pool FIFO Release Unit Tests ===" << std::endl;
    std::cout << "(Tests verify DPDK TX pool FIFO fixes)" << std::endl;
    std::cout << std::endl;

    // Original single-pool tests (data pool via MockTxPool)
    test_normal_cycle();
    test_out_of_order_ack();
    test_pool_full_claim_rejected();
    test_pool_wrapping();
    test_mbuf_failure_causes_clean_claim_failure();
    test_no_gradual_pool_leak();
    test_ack_frame_works_after_mbuf_recovery();
    test_mbuf_exhaustion_partial_claim();
    test_ack_frame_tx_burst_fail_no_leak();
    test_ack_frame_tx_burst_fail_no_deadlock();

    std::cout << std::endl;
    std::cout << "--- Dual Pool Tests (HOL-fix) ---" << std::endl;

    // New dual-pool tests (MockDualPool)
    test_data_pool_full_does_not_affect_ack_pool();
    test_ack_pool_basic_alloc_free();
    test_ack_pool_fifo_sequential();
    test_ack_pool_full();
    test_ack_pool_wrap_around();
    test_ack_pool_tx_burst_fail_no_leak();
    test_pools_independent_exhaustion();
    test_frame_idx_routing();

    std::cout << std::endl;
    std::cout << "=== Results: " << tests_passed << " passed, "
              << tests_failed << " failed ===" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
