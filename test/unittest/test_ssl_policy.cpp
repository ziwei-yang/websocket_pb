// test/unittest/test_ssl_policy.cpp
// Unit tests for zero-copy SSL policy APIs
//
// Tests the new zero-copy API added to all SSL policies:
//   RX: append_encrypted_view(), clear_encrypted_view()
//   TX: set_encrypted_output(), encrypted_output_len(), clear_encrypted_output()
//   Init: init_zero_copy_bio()

#include "../../src/policy/ssl.hpp"
#include <iostream>
#include <cassert>
#include <cstring>
#include <vector>

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
// NoSSLPolicy Tests (always available, no SSL library required)
// ============================================================================

void test_nossl_init_zero_copy_bio() {
    TEST("NoSSLPolicy::init_zero_copy_bio()")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();  // Should not throw
        // NoSSL doesn't need any initialization, just verify it doesn't crash
    END_TEST
}

void test_nossl_append_encrypted_view() {
    TEST("NoSSLPolicy::append_encrypted_view()")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        // Set up test data
        const uint8_t test_data[] = "Hello, World!";
        size_t test_len = sizeof(test_data) - 1;  // Exclude null terminator

        // Append encrypted view
        policy.append_encrypted_view(test_data, test_len);

        // Read from view via read() - NoSSL passes through directly
        uint8_t read_buf[32];
        ssize_t ret = policy.read(read_buf, sizeof(read_buf));
        ASSERT(ret == static_cast<ssize_t>(test_len), "Should read all data");
        ASSERT(memcmp(read_buf, test_data, test_len) == 0, "Data should match");
    END_TEST
}

void test_nossl_clear_encrypted_view() {
    TEST("NoSSLPolicy::clear_encrypted_view()")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        const uint8_t test_data[] = "Test data";
        policy.append_encrypted_view(test_data, sizeof(test_data) - 1);

        // Read some data
        uint8_t buf[4];
        policy.read(buf, 4);

        // Clear the view (reset ring buffer)
        policy.clear_encrypted_view();

        // Reading should now fail (ring buffer empty)
        ssize_t ret = policy.read(buf, sizeof(buf));
        ASSERT(ret == -1, "Read should fail after clear");
    END_TEST
}

void test_nossl_set_encrypted_output() {
    TEST("NoSSLPolicy::set_encrypted_output()")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        // Set up output buffer
        uint8_t out_buf[64];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));

        // Initially no data written
        ASSERT(policy.encrypted_output_len() == 0, "Initial output len should be 0");

        // Write some data - NoSSL passes through directly
        const char* test_data = "Hello, Output!";
        size_t test_len = strlen(test_data);
        ssize_t ret = policy.write(test_data, test_len);

        ASSERT(ret == static_cast<ssize_t>(test_len), "Should write all data");
        ASSERT(policy.encrypted_output_len() == test_len, "Output len should match");
        ASSERT(memcmp(out_buf, test_data, test_len) == 0, "Output data should match");
    END_TEST
}

void test_nossl_encrypted_output_len() {
    TEST("NoSSLPolicy::encrypted_output_len()")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        uint8_t out_buf[128];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));

        // Write multiple chunks
        policy.write("First", 5);
        ASSERT(policy.encrypted_output_len() == 5, "Should be 5 after first write");

        policy.write("Second", 6);
        ASSERT(policy.encrypted_output_len() == 11, "Should be 11 after second write");

        policy.write("Third", 5);
        ASSERT(policy.encrypted_output_len() == 16, "Should be 16 after third write");

        // Verify accumulated data
        ASSERT(memcmp(out_buf, "FirstSecondThird", 16) == 0, "Accumulated data should match");
    END_TEST
}

void test_nossl_clear_encrypted_output() {
    TEST("NoSSLPolicy::clear_encrypted_output()")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        uint8_t out_buf[64];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));

        // Write some data
        policy.write("Test", 4);
        ASSERT(policy.encrypted_output_len() == 4, "Should have 4 bytes");

        // Clear the output
        policy.clear_encrypted_output();
        ASSERT(policy.encrypted_output_len() == 0, "Output len should be 0 after clear");

        // Writing should now fail (no output buffer set)
        ssize_t ret = policy.write("More", 4);
        ASSERT(ret == -1, "Write should fail after clear");
    END_TEST
}

void test_nossl_output_capacity_limit() {
    TEST("NoSSLPolicy output buffer capacity limit")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        // Small buffer
        uint8_t small_buf[8];
        policy.set_encrypted_output(small_buf, sizeof(small_buf));

        // Write up to capacity
        ssize_t ret = policy.write("12345678", 8);
        ASSERT(ret == 8, "Should write full capacity");
        ASSERT(policy.encrypted_output_len() == 8, "Should be at capacity");

        // Writing more should fail
        ret = policy.write("X", 1);
        ASSERT(ret == -1, "Write should fail when buffer full");
    END_TEST
}

void test_nossl_partial_read() {
    TEST("NoSSLPolicy partial view read")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        const uint8_t test_data[] = "0123456789ABCDEF";
        policy.append_encrypted_view(test_data, 16);

        // Read in chunks
        uint8_t buf[4];

        ssize_t ret = policy.read(buf, 4);
        ASSERT(ret == 4, "Should read 4 bytes");
        ASSERT(memcmp(buf, "0123", 4) == 0, "First chunk should match");

        ret = policy.read(buf, 4);
        ASSERT(ret == 4, "Should read 4 more bytes");
        ASSERT(memcmp(buf, "4567", 4) == 0, "Second chunk should match");

        ret = policy.read(buf, 4);
        ASSERT(ret == 4, "Should read 4 more bytes");

        ret = policy.read(buf, 4);
        ASSERT(ret == 4, "Should read final 4 bytes");

        // No more data
        ret = policy.read(buf, 4);
        ASSERT(ret == -1, "Should fail when view exhausted");
    END_TEST
}

void test_nossl_rx_tx_independent() {
    TEST("NoSSLPolicy RX and TX are independent")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        // Set up both RX view and TX output
        const uint8_t rx_data[] = "RX Input Data";
        uint8_t tx_buf[32];

        policy.append_encrypted_view(rx_data, sizeof(rx_data) - 1);
        policy.set_encrypted_output(tx_buf, sizeof(tx_buf));

        // Write to TX
        policy.write("TX Output", 9);
        ASSERT(policy.encrypted_output_len() == 9, "TX should have 9 bytes");

        // Read from RX - should be independent
        uint8_t read_buf[32];
        ssize_t ret = policy.read(read_buf, sizeof(read_buf));
        ASSERT(ret == 13, "RX should read 13 bytes");

        // TX should be unaffected
        ASSERT(policy.encrypted_output_len() == 9, "TX should still have 9 bytes");

        // Clear RX, TX should be unaffected
        policy.clear_encrypted_view();
        ASSERT(policy.encrypted_output_len() == 9, "TX should still have 9 bytes after RX clear");

        // Clear TX, verify TX is cleared
        policy.clear_encrypted_output();
        ASSERT(policy.encrypted_output_len() == 0, "TX len should be 0");
    END_TEST
}

void test_nossl_multiple_views() {
    TEST("NoSSLPolicy multiple views accumulate in ring buffer")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        // Append multiple views (simulating multiple packets)
        const uint8_t data1[] = "First";
        const uint8_t data2[] = "Second";
        const uint8_t data3[] = "Third";

        policy.append_encrypted_view(data1, 5);
        policy.append_encrypted_view(data2, 6);
        policy.append_encrypted_view(data3, 5);

        // Read all data - should span multiple views
        uint8_t buf[32];
        size_t total_read = 0;

        ssize_t ret = policy.read(buf, sizeof(buf));
        ASSERT(ret > 0, "Should read data");
        total_read += ret;

        // Try reading more
        if (ret < 16) {
            ret = policy.read(buf + total_read, sizeof(buf) - total_read);
            if (ret > 0) total_read += ret;
        }
        if (total_read < 16) {
            ret = policy.read(buf + total_read, sizeof(buf) - total_read);
            if (ret > 0) total_read += ret;
        }

        ASSERT(total_read == 16, "Should read all 16 bytes total");
        ASSERT(memcmp(buf, "FirstSecondThird", 16) == 0, "Data should be in order");
    END_TEST
}

void test_nossl_ring_buffer_cycling() {
    TEST("NoSSLPolicy ring buffer cycles correctly")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        // Test that we can add and consume multiple times without clearing
        for (int round = 0; round < 3; round++) {
            const uint8_t data[] = "RoundData";
            policy.append_encrypted_view(data, 9);

            uint8_t buf[16];
            ssize_t ret = policy.read(buf, sizeof(buf));
            ASSERT(ret == 9, "Should read 9 bytes in each round");
            ASSERT(memcmp(buf, "RoundData", 9) == 0, "Data should match in each round");
        }
        // Ring buffer should auto-cycle without clear_encrypted_view()
    END_TEST
}

void test_nossl_ring_buffer_overflow() {
    TEST("NoSSLPolicy ring buffer overflow returns -1")
        NoSSLPolicy policy;
        policy.init_zero_copy_bio();

        // Fill ring buffer to capacity (1024 slots)
        const uint8_t data[] = "X";
        int ret;
        for (size_t i = 0; i < websocket::ssl::VIEW_RING_SIZE; i++) {
            ret = policy.append_encrypted_view(data, 1);
            ASSERT(ret == 0, "Should succeed until full");
        }

        // Next append should fail
        ret = policy.append_encrypted_view(data, 1);
        ASSERT(ret == -1, "Should return -1 when ring buffer is full");

        // Consume one entry, then append should succeed again
        uint8_t buf[1];
        policy.read(buf, 1);
        ret = policy.append_encrypted_view(data, 1);
        ASSERT(ret == 0, "Should succeed after consuming one entry");
    END_TEST
}

// ============================================================================
// WolfSSL Policy Tests (if available)
// ============================================================================

#ifdef SSL_POLICY_WOLFSSL

void test_wolfssl_init_zero_copy_bio() {
    TEST("WolfSSLPolicy::init_zero_copy_bio()")
        WolfSSLPolicy policy;
        policy.init_zero_copy_bio();
        // Verify SSL object was created
        ASSERT(policy.ssl_ != nullptr, "SSL object should be created");
    END_TEST
}

void test_wolfssl_append_encrypted_view() {
    TEST("WolfSSLPolicy::append_encrypted_view()")
        WolfSSLPolicy policy;
        policy.init_zero_copy_bio();

        const uint8_t test_data[] = "Encrypted TLS data";
        policy.append_encrypted_view(test_data, sizeof(test_data) - 1);
        // Note: Can't actually read without valid TLS record, just verify API works
    END_TEST
}

void test_wolfssl_clear_encrypted_view() {
    TEST("WolfSSLPolicy::clear_encrypted_view()")
        WolfSSLPolicy policy;
        policy.init_zero_copy_bio();

        const uint8_t test_data[] = "Test";
        policy.append_encrypted_view(test_data, 4);
        policy.clear_encrypted_view();
        // Ring buffer should be reset
    END_TEST
}

void test_wolfssl_set_encrypted_output() {
    TEST("WolfSSLPolicy::set_encrypted_output()")
        WolfSSLPolicy policy;
        policy.init_zero_copy_bio();

        uint8_t out_buf[1024];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));

        ASSERT(policy.encrypted_output_len() == 0, "Initial output len should be 0");
        // Note: SSL_write would encrypt data, but we can't test without handshake
    END_TEST
}

void test_wolfssl_clear_encrypted_output() {
    TEST("WolfSSLPolicy::clear_encrypted_output()")
        WolfSSLPolicy policy;
        policy.init_zero_copy_bio();

        uint8_t out_buf[64];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));
        policy.clear_encrypted_output();

        ASSERT(policy.encrypted_output_len() == 0, "Output len should be 0 after clear");
    END_TEST
}

#endif // SSL_POLICY_WOLFSSL

// ============================================================================
// OpenSSL Policy Tests (if available)
// ============================================================================

#ifdef SSL_POLICY_OPENSSL

void test_openssl_init_zero_copy_bio() {
    TEST("OpenSSLPolicy::init_zero_copy_bio()")
        OpenSSLPolicy policy;
        policy.init_zero_copy_bio();
        ASSERT(policy.ssl_ != nullptr, "SSL object should be created");
    END_TEST
}

void test_openssl_append_encrypted_view() {
    TEST("OpenSSLPolicy::append_encrypted_view()")
        OpenSSLPolicy policy;
        policy.init_zero_copy_bio();

        const uint8_t test_data[] = "Encrypted data";
        policy.append_encrypted_view(test_data, sizeof(test_data) - 1);
        // API should work without error
    END_TEST
}

void test_openssl_clear_encrypted_view() {
    TEST("OpenSSLPolicy::clear_encrypted_view()")
        OpenSSLPolicy policy;
        policy.init_zero_copy_bio();

        const uint8_t test_data[] = "Test";
        policy.append_encrypted_view(test_data, 4);
        policy.clear_encrypted_view();
        // Ring buffer should be reset
    END_TEST
}

void test_openssl_set_encrypted_output() {
    TEST("OpenSSLPolicy::set_encrypted_output()")
        OpenSSLPolicy policy;
        policy.init_zero_copy_bio();

        uint8_t out_buf[1024];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));
        ASSERT(policy.encrypted_output_len() == 0, "Initial output len should be 0");
    END_TEST
}

void test_openssl_clear_encrypted_output() {
    TEST("OpenSSLPolicy::clear_encrypted_output()")
        OpenSSLPolicy policy;
        policy.init_zero_copy_bio();

        uint8_t out_buf[64];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));
        policy.clear_encrypted_output();
        ASSERT(policy.encrypted_output_len() == 0, "Output len should be 0 after clear");
    END_TEST
}

#endif // SSL_POLICY_OPENSSL

// ============================================================================
// LibreSSL Policy Tests (if available)
// ============================================================================

#ifdef SSL_POLICY_LIBRESSL

void test_libressl_init_zero_copy_bio() {
    TEST("LibreSSLPolicy::init_zero_copy_bio()")
        LibreSSLPolicy policy;
        policy.init_zero_copy_bio();
        ASSERT(policy.ssl_ != nullptr, "SSL object should be created");
    END_TEST
}

void test_libressl_append_encrypted_view() {
    TEST("LibreSSLPolicy::append_encrypted_view()")
        LibreSSLPolicy policy;
        policy.init_zero_copy_bio();

        const uint8_t test_data[] = "Encrypted data";
        policy.append_encrypted_view(test_data, sizeof(test_data) - 1);
        // API should work without error
    END_TEST
}

void test_libressl_clear_encrypted_view() {
    TEST("LibreSSLPolicy::clear_encrypted_view()")
        LibreSSLPolicy policy;
        policy.init_zero_copy_bio();

        const uint8_t test_data[] = "Test";
        policy.append_encrypted_view(test_data, 4);
        policy.clear_encrypted_view();
        // Ring buffer should be reset
    END_TEST
}

void test_libressl_set_encrypted_output() {
    TEST("LibreSSLPolicy::set_encrypted_output()")
        LibreSSLPolicy policy;
        policy.init_zero_copy_bio();

        uint8_t out_buf[1024];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));
        ASSERT(policy.encrypted_output_len() == 0, "Initial output len should be 0");
    END_TEST
}

void test_libressl_clear_encrypted_output() {
    TEST("LibreSSLPolicy::clear_encrypted_output()")
        LibreSSLPolicy policy;
        policy.init_zero_copy_bio();

        uint8_t out_buf[64];
        policy.set_encrypted_output(out_buf, sizeof(out_buf));
        policy.clear_encrypted_output();
        ASSERT(policy.encrypted_output_len() == 0, "Output len should be 0 after clear");
    END_TEST
}

#endif // SSL_POLICY_LIBRESSL

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SSL Policy Zero-Copy API Unit Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    // NoSSLPolicy tests (always available)
    std::cout << "\n--- NoSSLPolicy Tests ---" << std::endl;
    test_nossl_init_zero_copy_bio();
    test_nossl_append_encrypted_view();
    test_nossl_clear_encrypted_view();
    test_nossl_set_encrypted_output();
    test_nossl_encrypted_output_len();
    test_nossl_clear_encrypted_output();
    test_nossl_output_capacity_limit();
    test_nossl_partial_read();
    test_nossl_rx_tx_independent();
    test_nossl_multiple_views();
    test_nossl_ring_buffer_cycling();
    test_nossl_ring_buffer_overflow();

#ifdef SSL_POLICY_WOLFSSL
    std::cout << "\n--- WolfSSLPolicy Tests ---" << std::endl;
    test_wolfssl_init_zero_copy_bio();
    test_wolfssl_append_encrypted_view();
    test_wolfssl_clear_encrypted_view();
    test_wolfssl_set_encrypted_output();
    test_wolfssl_clear_encrypted_output();
#else
    std::cout << "\n--- WolfSSLPolicy Tests SKIPPED (not compiled) ---" << std::endl;
#endif

#ifdef SSL_POLICY_OPENSSL
    std::cout << "\n--- OpenSSLPolicy Tests ---" << std::endl;
    test_openssl_init_zero_copy_bio();
    test_openssl_append_encrypted_view();
    test_openssl_clear_encrypted_view();
    test_openssl_set_encrypted_output();
    test_openssl_clear_encrypted_output();
#else
    std::cout << "\n--- OpenSSLPolicy Tests SKIPPED (not compiled) ---" << std::endl;
#endif

#ifdef SSL_POLICY_LIBRESSL
    std::cout << "\n--- LibreSSLPolicy Tests ---" << std::endl;
    test_libressl_init_zero_copy_bio();
    test_libressl_append_encrypted_view();
    test_libressl_clear_encrypted_view();
    test_libressl_set_encrypted_output();
    test_libressl_clear_encrypted_output();
#else
    std::cout << "\n--- LibreSSLPolicy Tests SKIPPED (not compiled) ---" << std::endl;
#endif

    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
