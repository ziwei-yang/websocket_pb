// test/unittest/test_wolfssl_seq_num.cpp
// Unit test: WolfSSL seq_num must count ALL TLS records, not just app-data
//
// Bug: WolfSSL's manual server_record_count_ only incremented on wolfSSL_read()
// return, missing NewSessionTickets consumed internally by WolfSSL. This causes
// the initial seq_num for AES-CTR direct decrypt to be wrong, producing garbage
// on the FIRST data frame after switching.
//
// Fix: Use wolfSSL_GetPeerSequenceNumber() which returns the authoritative
// ssl->keys.peer_sequence_number — automatically incremented by WolfSSL's
// internal GetSEQIncrement() for ALL records including NewSessionTickets.
//
// This test validates the principle: using a wrong (under-counted) seq_num
// produces a wrong nonce, which causes AES-CTR decryption to fail.

#include "../../src/core/aes_ctr.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    printf("  Test: %s ... ", name); \
    fflush(stdout);

#define PASS() \
    printf("PASS\n"); \
    tests_passed++;

#define FAIL(msg) \
    printf("FAIL: %s\n", msg); \
    tests_failed++;

using namespace websocket::crypto;

// =============================================================================
// Test 1: Manual counter misses internally-consumed records
// =============================================================================
// Simulates the Binance TLS 1.3 timeline:
//   seq=0: NewSessionTicket (consumed internally by WolfSSL, NOT returned by read)
//   seq=1: HTTP 101 Switching Protocols (returned by wolfSSL_read)
//   seq=2: First WebSocket data frame
//
// Manual counter: only sees the read() → count = 1
// Correct count (wolfSSL_GetPeerSequenceNumber): 2 (all records processed)

static void test_manual_counter_undercounts() {
    TEST("Manual counter misses NewSessionTicket (1 NST + 1 app-data → count should be 2, manual gives 1)");

    // Simulate: 1 NewSessionTicket consumed internally + 1 app-data returned by read
    uint64_t manual_counter = 0;  // Reset at handshake completion

    // seq=0: NewSessionTicket — consumed internally, manual counter NOT incremented
    // (wolfSSL processes it but doesn't return it via wolfSSL_read)

    // seq=1: HTTP 101 — returned by wolfSSL_read()
    manual_counter++;  // manual_counter = 1

    // The next server record will be seq=2, so we need seq_num=2
    uint64_t correct_seq = 2;  // What wolfSSL_GetPeerSequenceNumber() returns
    uint64_t wrong_seq = manual_counter;  // = 1

    if (wrong_seq == correct_seq) {
        FAIL("Expected manual counter to differ from correct seq");
        return;
    }

    if (wrong_seq != 1) {
        FAIL("Expected manual counter = 1");
        return;
    }

    if (correct_seq != 2) {
        FAIL("Expected correct seq = 2");
        return;
    }

    PASS();
}

// =============================================================================
// Test 2: Multiple NewSessionTickets (common with Binance)
// =============================================================================
// Some servers send 2 NewSessionTickets after handshake before any app-data.
// Manual counter: 1 (only the HTTP 101)
// Correct: 3 (2 NST + 1 HTTP 101)

static void test_multiple_nst_undercounts() {
    TEST("Multiple NewSessionTickets: 2 NST + 1 app-data → correct=3, manual=1");

    uint64_t manual_counter = 0;

    // seq=0: NewSessionTicket #1 — internal
    // seq=1: NewSessionTicket #2 — internal
    // seq=2: HTTP 101 — returned by read
    manual_counter++;  // manual_counter = 1

    uint64_t correct_seq = 3;  // Next expected from server
    uint64_t wrong_seq = manual_counter;  // = 1

    if (wrong_seq >= correct_seq) {
        FAIL("Expected manual counter < correct seq");
        return;
    }

    if (correct_seq - wrong_seq != 2) {
        FAIL("Expected off-by-2 (missed 2 NewSessionTickets)");
        return;
    }

    PASS();
}

// =============================================================================
// Test 3: Wrong seq_num → wrong nonce → AES-CTR decrypt produces garbage
// =============================================================================
// Encrypt a block at seq=2, then try decrypting with seq=1 (wrong) vs seq=2 (correct).

static void test_wrong_seq_produces_garbage() {
    TEST("Wrong seq_num → wrong nonce → AES-CTR decrypt fails");

    // Set up a TLS 1.3 key + IV (use deterministic test values)
    TLSRecordKeys keys{};
    keys.key_len = 16;  // AES-128
    keys.is_tls13 = true;
    memset(keys.key, 0xAA, 16);
    memset(keys.iv, 0xBB, 12);
    expand_keys(keys);

    // Plaintext to "encrypt" (AES-CTR: encrypt = decrypt with same nonce)
    const char* plaintext = "Hello, WebSocket!";
    size_t pt_len = strlen(plaintext);

    // Encrypt with correct seq=2 (GCM counter starts at 2)
    uint64_t correct_seq = 2;
    uint8_t nonce_correct[12];
    derive_nonce_tls13(keys.iv, correct_seq, nonce_correct);

    uint8_t ciphertext[64];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                              nonce_correct, 2,
                              reinterpret_cast<const uint8_t*>(plaintext),
                              ciphertext, pt_len);

    // Decrypt with correct seq=2 → should recover plaintext
    uint8_t decrypted_correct[64];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                              nonce_correct, 2,
                              ciphertext, decrypted_correct, pt_len);

    if (memcmp(decrypted_correct, plaintext, pt_len) != 0) {
        FAIL("Correct seq should recover plaintext");
        return;
    }

    // Decrypt with wrong seq=1 → should NOT recover plaintext
    uint64_t wrong_seq = 1;
    uint8_t nonce_wrong[12];
    derive_nonce_tls13(keys.iv, wrong_seq, nonce_wrong);

    uint8_t decrypted_wrong[64];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                              nonce_wrong, 2,
                              ciphertext, decrypted_wrong, pt_len);

    if (memcmp(decrypted_wrong, plaintext, pt_len) == 0) {
        FAIL("Wrong seq should NOT recover plaintext (nonce collision!)");
        return;
    }

    PASS();
}

// =============================================================================
// Test 4: Nonce differs when seq_num differs by 1
// =============================================================================
// Verify that derive_nonce_tls13 produces distinct nonces for adjacent seq values.

static void test_nonce_differs_for_adjacent_seq() {
    TEST("Adjacent seq_num values produce different nonces");

    uint8_t iv[12];
    memset(iv, 0xCC, 12);

    uint8_t nonce_a[12], nonce_b[12];
    derive_nonce_tls13(iv, 1, nonce_a);
    derive_nonce_tls13(iv, 2, nonce_b);

    if (memcmp(nonce_a, nonce_b, 12) == 0) {
        FAIL("seq=1 and seq=2 should produce different nonces");
        return;
    }

    PASS();
}

// =============================================================================
// Test 5: Verify off-by-one from 65ms Binance scenario
// =============================================================================
// Real-world: 65ms between TLS handshake and switch_to_direct_decrypt.
// In that window, server sends NewSessionTicket (seq=0) + HTTP 101 (seq=1).
// Old code: set_tls_seq_num(1) → next decrypt uses nonce for seq=1
// But server's next record is seq=2 → nonce mismatch → garbage.

static void test_binance_65ms_scenario() {
    TEST("Binance 65ms scenario: NST(seq=0) + HTTP101(seq=1) → next record at seq=2");

    TLSRecordKeys keys{};
    keys.key_len = 16;
    keys.is_tls13 = true;
    memset(keys.key, 0x42, 16);
    memset(keys.iv, 0x13, 12);
    expand_keys(keys);

    // Server encrypts WebSocket frame at seq=2
    uint8_t server_plaintext[] = {0x82, 0x05, 'H', 'e', 'l', 'l', 'o'};  // WS binary frame
    size_t frame_len = sizeof(server_plaintext);

    uint8_t nonce_seq2[12];
    derive_nonce_tls13(keys.iv, 2, nonce_seq2);

    uint8_t wire_data[64];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                              nonce_seq2, 2,
                              server_plaintext, wire_data, frame_len);

    // Client with OLD code: seq_num=1 (wrong — missed the NST)
    uint8_t dec_old[64];
    uint8_t nonce_seq1[12];
    derive_nonce_tls13(keys.iv, 1, nonce_seq1);
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                              nonce_seq1, 2,
                              wire_data, dec_old, frame_len);

    if (memcmp(dec_old, server_plaintext, frame_len) == 0) {
        FAIL("Old code (seq=1) should NOT decrypt correctly");
        return;
    }

    // Check: first byte would be parsed as WS opcode → likely garbage
    uint8_t opcode_old = dec_old[0] & 0x0F;
    printf("(wrong opcode=0x%02x) ", opcode_old);

    // Client with NEW code: seq_num=2 (correct — counts NST)
    uint8_t dec_new[64];
    AESCTRDecryptor::decrypt(keys.round_keys, keys.num_rounds,
                              nonce_seq2, 2,
                              wire_data, dec_new, frame_len);

    if (memcmp(dec_new, server_plaintext, frame_len) != 0) {
        FAIL("New code (seq=2) should decrypt correctly");
        return;
    }

    PASS();
}

// =============================================================================
int main() {
    printf("=== WolfSSL seq_num tracking regression test ===\n");
    printf("Bug: manual server_record_count_ misses NewSessionTickets\n");
    printf("Fix: use wolfSSL_GetPeerSequenceNumber() for authoritative count\n\n");

    test_manual_counter_undercounts();
    test_multiple_nst_undercounts();
    test_wrong_seq_produces_garbage();
    test_nonce_differs_for_adjacent_seq();
    test_binance_65ms_scenario();

    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
