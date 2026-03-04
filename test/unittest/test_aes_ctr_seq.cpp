// test/unittest/test_aes_ctr_seq.cpp
// Unit test: Reproduce AES-CTR seq_num=0 bug
//
// switch_to_direct_decrypt() calls set_tls_record_keys() which hardcodes
// tls_seq_num_=0. It never calls set_tls_seq_num(get_server_record_count()).
// TLS 1.3 nonce = IV XOR seq_num. Wrong seq -> wrong nonce -> AES-CTR
// decryption produces garbage -> WS parser sees random opcodes.

#include "../../src/core/aes_ctr.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    printf("Testing: %s ... ", name); \
    fflush(stdout);

#define PASS() \
    printf("PASS\n"); \
    tests_passed++;

#define FAIL(msg) \
    printf("FAIL: %s\n", msg); \
    tests_failed++;

using namespace websocket::crypto;

// =============================================================================
// Test 1: Nonce derivation differs with different seq_num (sanity)
// =============================================================================
void test_nonce_differs_with_seq() {
    TEST("nonce derivation differs with different seq_num");

    uint8_t iv[12] = {0xA0,0xB1,0xC2,0xD3,0xE4,0xF5,0x06,0x17,0x28,0x39,0x4A,0x5B};
    uint8_t nonce0[12], nonce5[12];

    derive_nonce_tls13(iv, 0, nonce0);
    derive_nonce_tls13(iv, 5, nonce5);

    if (memcmp(nonce0, nonce5, 12) != 0) {
        PASS();
    } else {
        FAIL("nonce with seq=0 should differ from nonce with seq=5");
    }
}

// =============================================================================
// Test 2: Decrypt with correct seq_num recovers plaintext (sanity)
// =============================================================================
void test_decrypt_correct_seq() {
    TEST("decrypt with correct seq_num recovers plaintext");

    // AES-128 key
    uint8_t raw_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    uint8_t iv[12] = {0xA0,0xB1,0xC2,0xD3,0xE4,0xF5,0x06,0x17,0x28,0x39,0x4A,0x5B};

    // Expand keys
    TLSRecordKeys keys{};
    memcpy(keys.key, raw_key, 16);
    memcpy(keys.iv, iv, 12);
    keys.key_len = 16;
    keys.is_tls13 = true;
    expand_keys(keys);

    // Plaintext: 48 bytes
    alignas(16) uint8_t plaintext[48];
    memcpy(plaintext, "{\"result\":null,\"id\":1}__padding_", 32);
    memcpy(plaintext + 32, "____more_padding____", 16);
    // Ensure we know exactly what plaintext is (pad remainder)
    // Already filled 48 bytes above

    // Derive nonce at seq=5
    uint8_t nonce5[12];
    derive_nonce_tls13(iv, 5, nonce5);

    // Encrypt: plaintext -> ciphertext using AES-CTR at counter=2
    alignas(16) uint8_t ciphertext[48];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                             nonce5, 2, plaintext, ciphertext, 48);

    // Decrypt: ciphertext -> result using same nonce (seq=5)
    alignas(16) uint8_t result[48];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                             nonce5, 2, ciphertext, result, 48);

    if (memcmp(result, plaintext, 48) == 0) {
        PASS();
    } else {
        FAIL("decryption with correct seq_num should recover plaintext");
    }
}

// =============================================================================
// Test 3: Wrong seq_num produces different output (regression)
// =============================================================================
void test_decrypt_wrong_seq_fails() {
    TEST("wrong seq_num produces different output (regression)");

    // AES-128 key (same as test 2)
    uint8_t raw_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    uint8_t iv[12] = {0xA0,0xB1,0xC2,0xD3,0xE4,0xF5,0x06,0x17,0x28,0x39,0x4A,0x5B};

    TLSRecordKeys keys{};
    memcpy(keys.key, raw_key, 16);
    memcpy(keys.iv, iv, 12);
    keys.key_len = 16;
    keys.is_tls13 = true;
    expand_keys(keys);

    // Plaintext: 48 bytes
    alignas(16) uint8_t plaintext[48];
    memcpy(plaintext, "{\"result\":null,\"id\":1}__padding_", 32);
    memcpy(plaintext + 32, "____more_padding____", 16);

    // Encrypt at seq=5
    uint8_t nonce5[12];
    derive_nonce_tls13(iv, 5, nonce5);

    alignas(16) uint8_t ciphertext[48];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                             nonce5, 2, plaintext, ciphertext, 48);

    // Decrypt with seq=0 (what set_tls_record_keys() hardcodes)
    uint8_t nonce0[12];
    derive_nonce_tls13(iv, 0, nonce0);

    alignas(16) uint8_t result[48];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                             nonce0, 2, ciphertext, result, 48);

    // Wrong seq must produce different (garbage) output - nonce matters
    if (memcmp(result, plaintext, 48) != 0) {
        PASS();
    } else {
        FAIL("wrong seq_num should produce different output (nonce must matter)");
    }
}

// =============================================================================
// Main
// =============================================================================
int main() {
    printf("================================================================\n");
    printf("  AES-CTR seq_num=0 Bug Regression Test\n");
    printf("================================================================\n\n");
    printf("Bug: switch_to_direct_decrypt() hardcodes tls_seq_num_=0\n");
    printf("     TLS 1.3 nonce = IV XOR seq_num\n");
    printf("     Wrong seq -> wrong nonce -> decryption garbage\n\n");

    test_nonce_differs_with_seq();
    test_decrypt_correct_seq();
    test_decrypt_wrong_seq_fails();

    printf("\n================================================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("================================================================\n");

    return tests_failed > 0 ? 1 : 0;
}
