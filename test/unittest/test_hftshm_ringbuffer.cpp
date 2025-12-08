// test/unittest/test_hftshm_ringbuffer.cpp
// Unit tests for HftShmRingBuffer policy
//
// Prerequisites:
//   1. hft-shm CLI installed and in PATH
//   2. Test segments created: hft-shm init --config conf/test.toml
//
// Build: USE_HFTSHM=1 USE_WOLFSSL=1 make test-hftshm
//
#include "../../src/core/hftshm_ringbuffer.hpp"
#include <cassert>
#include <cstring>
#include <cstdio>

int main() {
    printf("=== HftShmRingBuffer Tests ===\n");

    // Test RX buffer (producer role)
    printf("\n[1] Testing RX buffer (producer)...\n");
    try {
        HftShmRxBuffer<"test.mktdata.binance.raw.rx"> rx;
        rx.init();

        // Verify interface matches RingBuffer
        assert(rx.is_mmap() == true);
        assert(rx.is_mirrored() == false);
        printf("  capacity: %zu bytes\n", rx.capacity());
        printf("  is_mmap: %s, is_mirrored: %s\n",
               rx.is_mmap() ? "true" : "false",
               rx.is_mirrored() ? "true" : "false");

        // Verify capacity is power of 2 (index_mask = capacity - 1)
        size_t cap = rx.capacity();
        assert((cap & (cap - 1)) == 0 && "capacity must be power of 2");

        // Test write region
        size_t avail = 0;
        uint8_t* ptr = rx.next_write_region(&avail);
        assert(ptr != nullptr);
        printf("  writable: %zu bytes\n", avail);

        // Write test data
        const char* msg = "HftShmRingBuffer test message";
        size_t len = strlen(msg);
        assert(avail >= len);
        memcpy(ptr, msg, len);
        rx.commit_write(len);
        printf("  wrote: %zu bytes\n", len);

        printf("  [PASS] RX buffer tests\n");

    } catch (const std::runtime_error& e) {
        printf("  [SKIP] RX buffer not available: %s\n", e.what());
        printf("  Hint: Run 'hft-shm init --config conf/test.toml' first\n");
    }

    // Test TX buffer (consumer role)
    printf("\n[2] Testing TX buffer (consumer)...\n");
    try {
        HftShmTxBuffer<"test.mktdata.binance.raw.tx"> tx;
        tx.init();

        // Verify interface matches RingBuffer
        assert(tx.is_mmap() == true);
        assert(tx.is_mirrored() == false);
        printf("  capacity: %zu bytes\n", tx.capacity());

        // Verify capacity is power of 2
        size_t cap = tx.capacity();
        assert((cap & (cap - 1)) == 0 && "capacity must be power of 2");

        // Check readable (may be 0 if no external producer)
        size_t readable = tx.readable();
        printf("  readable: %zu bytes\n", readable);

        if (readable > 0) {
            size_t avail = 0;
            const uint8_t* ptr = tx.next_read_region(&avail);
            assert(ptr != nullptr);
            printf("  read region: %zu bytes available\n", avail);
            tx.commit_read(avail);
        }

        printf("  [PASS] TX buffer tests\n");

    } catch (const std::runtime_error& e) {
        printf("  [SKIP] TX buffer not available: %s\n", e.what());
        printf("  Hint: Run 'hft-shm init --config conf/test.toml' first\n");
    }

    printf("\n=== HftShmRingBuffer Tests Complete ===\n");
    return 0;
}
