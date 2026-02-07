// src/core/aes_ctr.hpp
// AES-CTR Decryptor for Direct TLS Record Decryption (AES-NI)
//
// Provides:
//   - TLSRecordKeys: Pre-expanded AES round keys + IV for a TLS connection
//   - AESCTRDecryptor: Static decrypt() using AES-NI intrinsics
//   - Nonce derivation for TLS 1.2 (explicit nonce) and TLS 1.3 (XOR with seq)
//
// Skips GHASH tag verification for minimum latency. Decrypts AES-GCM
// ciphertext by running AES-CTR on the payload (GCM = CTR + GHASH).
//
// Performance: 8-block pipelined loop saturates AES-NI at ~1 block/cycle.

#pragma once

#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include <wmmintrin.h>

namespace websocket {
namespace crypto {

// ============================================================================
// TLS Record Keys
// ============================================================================

struct TLSRecordKeys {
    uint8_t  key[32];          // AES key (16 for AES-128, 32 for AES-256)
    uint8_t  iv[12];           // 12-byte base IV (implicit IV for TLS 1.2, or TLS 1.3 IV)
    uint8_t  key_len;          // 16 or 32
    bool     is_tls13;
    __m128i  round_keys[15];   // Pre-expanded (11 for AES-128, 15 for AES-256)
    uint8_t  num_rounds;       // 10 (AES-128) or 14 (AES-256)
};

// ============================================================================
// AES Key Expansion (AES-NI)
// ============================================================================

namespace detail {

inline __m128i aes128_key_assist(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

inline void aes128_key_expansion(const uint8_t* raw_key, __m128i* round_keys) {
    round_keys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw_key));
    round_keys[1]  = aes128_key_assist(round_keys[0],  _mm_aeskeygenassist_si128(round_keys[0],  0x01));
    round_keys[2]  = aes128_key_assist(round_keys[1],  _mm_aeskeygenassist_si128(round_keys[1],  0x02));
    round_keys[3]  = aes128_key_assist(round_keys[2],  _mm_aeskeygenassist_si128(round_keys[2],  0x04));
    round_keys[4]  = aes128_key_assist(round_keys[3],  _mm_aeskeygenassist_si128(round_keys[3],  0x08));
    round_keys[5]  = aes128_key_assist(round_keys[4],  _mm_aeskeygenassist_si128(round_keys[4],  0x10));
    round_keys[6]  = aes128_key_assist(round_keys[5],  _mm_aeskeygenassist_si128(round_keys[5],  0x20));
    round_keys[7]  = aes128_key_assist(round_keys[6],  _mm_aeskeygenassist_si128(round_keys[6],  0x40));
    round_keys[8]  = aes128_key_assist(round_keys[7],  _mm_aeskeygenassist_si128(round_keys[7],  0x80));
    round_keys[9]  = aes128_key_assist(round_keys[8],  _mm_aeskeygenassist_si128(round_keys[8],  0x1B));
    round_keys[10] = aes128_key_assist(round_keys[9],  _mm_aeskeygenassist_si128(round_keys[9],  0x36));
}

inline __m128i aes256_key_assist_1(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

inline __m128i aes256_key_assist_2(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(keygened, 0x00), 0xAA);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

inline void aes256_key_expansion(const uint8_t* raw_key, __m128i* round_keys) {
    round_keys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw_key));
    round_keys[1] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(raw_key + 16));

    round_keys[2]  = aes256_key_assist_1(round_keys[0],  _mm_aeskeygenassist_si128(round_keys[1],  0x01));
    round_keys[3]  = aes256_key_assist_2(round_keys[1],  round_keys[2]);
    round_keys[4]  = aes256_key_assist_1(round_keys[2],  _mm_aeskeygenassist_si128(round_keys[3],  0x02));
    round_keys[5]  = aes256_key_assist_2(round_keys[3],  round_keys[4]);
    round_keys[6]  = aes256_key_assist_1(round_keys[4],  _mm_aeskeygenassist_si128(round_keys[5],  0x04));
    round_keys[7]  = aes256_key_assist_2(round_keys[5],  round_keys[6]);
    round_keys[8]  = aes256_key_assist_1(round_keys[6],  _mm_aeskeygenassist_si128(round_keys[7],  0x08));
    round_keys[9]  = aes256_key_assist_2(round_keys[7],  round_keys[8]);
    round_keys[10] = aes256_key_assist_1(round_keys[8],  _mm_aeskeygenassist_si128(round_keys[9],  0x10));
    round_keys[11] = aes256_key_assist_2(round_keys[9],  round_keys[10]);
    round_keys[12] = aes256_key_assist_1(round_keys[10], _mm_aeskeygenassist_si128(round_keys[11], 0x20));
    round_keys[13] = aes256_key_assist_2(round_keys[11], round_keys[12]);
    round_keys[14] = aes256_key_assist_1(round_keys[12], _mm_aeskeygenassist_si128(round_keys[13], 0x40));
}

} // namespace detail

// Expand raw key into round keys. Call once per connection.
inline bool expand_keys(TLSRecordKeys& keys) {
    if (keys.key_len == 16) {
        detail::aes128_key_expansion(keys.key, keys.round_keys);
        keys.num_rounds = 10;
        return true;
    } else if (keys.key_len == 32) {
        detail::aes256_key_expansion(keys.key, keys.round_keys);
        keys.num_rounds = 14;
        return true;
    }
    return false;
}

// ============================================================================
// Nonce Derivation
// ============================================================================

// TLS 1.3: nonce = iv XOR pad_left_64(seq_num, 12)
inline void derive_nonce_tls13(const uint8_t iv[12], uint64_t seq_num, uint8_t nonce[12]) {
    // Copy IV
    std::memcpy(nonce, iv, 12);
    // XOR seq_num into last 8 bytes (big-endian, padded left with zeros)
    uint8_t seq_be[8];
    seq_be[0] = static_cast<uint8_t>(seq_num >> 56);
    seq_be[1] = static_cast<uint8_t>(seq_num >> 48);
    seq_be[2] = static_cast<uint8_t>(seq_num >> 40);
    seq_be[3] = static_cast<uint8_t>(seq_num >> 32);
    seq_be[4] = static_cast<uint8_t>(seq_num >> 24);
    seq_be[5] = static_cast<uint8_t>(seq_num >> 16);
    seq_be[6] = static_cast<uint8_t>(seq_num >> 8);
    seq_be[7] = static_cast<uint8_t>(seq_num);
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] ^= seq_be[i];
    }
}

// TLS 1.2: nonce = implicit_iv(4B) || explicit_nonce(8B from record)
inline void derive_nonce_tls12(const uint8_t iv[4], const uint8_t explicit_nonce[8], uint8_t nonce[12]) {
    std::memcpy(nonce, iv, 4);
    std::memcpy(nonce + 4, explicit_nonce, 8);
}

// ============================================================================
// AES-CTR Decryptor (AES-NI)
// ============================================================================
//
// GCM counter starts at 2 (counter=1 is reserved for tag encryption).
// Counter block layout: [nonce(12 bytes) || counter_be32(4 bytes)]

struct AESCTRDecryptor {

    // Build a 128-bit counter block from nonce + counter value
    static inline __m128i make_counter_block(const uint8_t nonce[12], uint32_t counter) {
        alignas(16) uint8_t cb[16];
        std::memcpy(cb, nonce, 12);
        cb[12] = static_cast<uint8_t>(counter >> 24);
        cb[13] = static_cast<uint8_t>(counter >> 16);
        cb[14] = static_cast<uint8_t>(counter >> 8);
        cb[15] = static_cast<uint8_t>(counter);
        return _mm_load_si128(reinterpret_cast<const __m128i*>(cb));
    }

    // Increment the big-endian counter in a counter block by 1
    static inline __m128i increment_counter(__m128i cb) {
        // Extract last 4 bytes (big-endian counter), increment, put back
        alignas(16) uint8_t buf[16];
        _mm_store_si128(reinterpret_cast<__m128i*>(buf), cb);
        uint32_t ctr = (static_cast<uint32_t>(buf[12]) << 24) |
                       (static_cast<uint32_t>(buf[13]) << 16) |
                       (static_cast<uint32_t>(buf[14]) << 8)  |
                       (static_cast<uint32_t>(buf[15]));
        ctr++;
        buf[12] = static_cast<uint8_t>(ctr >> 24);
        buf[13] = static_cast<uint8_t>(ctr >> 16);
        buf[14] = static_cast<uint8_t>(ctr >> 8);
        buf[15] = static_cast<uint8_t>(ctr);
        return _mm_load_si128(reinterpret_cast<const __m128i*>(buf));
    }

    // AES encrypt a single block (for keystream generation)
    static inline __m128i aes_encrypt_block(__m128i block, const __m128i* round_keys, uint8_t num_rounds) {
        block = _mm_xor_si128(block, round_keys[0]);
        for (uint8_t i = 1; i < num_rounds; i++) {
            block = _mm_aesenc_si128(block, round_keys[i]);
        }
        return _mm_aesenclast_si128(block, round_keys[num_rounds]);
    }

    // Decrypt ciphertext in-place or to output buffer using AES-CTR mode.
    // counter_start: starting GCM counter value (typically 2 for payload)
    // Returns the counter value after decryption (for continued decryption).
    static uint32_t decrypt(const __m128i* round_keys, uint8_t num_rounds,
                            const uint8_t nonce[12], uint32_t counter_start,
                            const uint8_t* ciphertext, uint8_t* plaintext,
                            size_t len) {
        uint32_t counter = counter_start;
        size_t offset = 0;

        // Tier 1: 8-block pipelined (128 bytes) - saturates AES-NI pipeline
        while (offset + 128 <= len) {
            __m128i cb0 = make_counter_block(nonce, counter);
            __m128i cb1 = make_counter_block(nonce, counter + 1);
            __m128i cb2 = make_counter_block(nonce, counter + 2);
            __m128i cb3 = make_counter_block(nonce, counter + 3);
            __m128i cb4 = make_counter_block(nonce, counter + 4);
            __m128i cb5 = make_counter_block(nonce, counter + 5);
            __m128i cb6 = make_counter_block(nonce, counter + 6);
            __m128i cb7 = make_counter_block(nonce, counter + 7);

            // Round 0: XOR with round key 0
            cb0 = _mm_xor_si128(cb0, round_keys[0]);
            cb1 = _mm_xor_si128(cb1, round_keys[0]);
            cb2 = _mm_xor_si128(cb2, round_keys[0]);
            cb3 = _mm_xor_si128(cb3, round_keys[0]);
            cb4 = _mm_xor_si128(cb4, round_keys[0]);
            cb5 = _mm_xor_si128(cb5, round_keys[0]);
            cb6 = _mm_xor_si128(cb6, round_keys[0]);
            cb7 = _mm_xor_si128(cb7, round_keys[0]);

            // Rounds 1..num_rounds-1
            for (uint8_t r = 1; r < num_rounds; r++) {
                cb0 = _mm_aesenc_si128(cb0, round_keys[r]);
                cb1 = _mm_aesenc_si128(cb1, round_keys[r]);
                cb2 = _mm_aesenc_si128(cb2, round_keys[r]);
                cb3 = _mm_aesenc_si128(cb3, round_keys[r]);
                cb4 = _mm_aesenc_si128(cb4, round_keys[r]);
                cb5 = _mm_aesenc_si128(cb5, round_keys[r]);
                cb6 = _mm_aesenc_si128(cb6, round_keys[r]);
                cb7 = _mm_aesenc_si128(cb7, round_keys[r]);
            }

            // Final round
            cb0 = _mm_aesenclast_si128(cb0, round_keys[num_rounds]);
            cb1 = _mm_aesenclast_si128(cb1, round_keys[num_rounds]);
            cb2 = _mm_aesenclast_si128(cb2, round_keys[num_rounds]);
            cb3 = _mm_aesenclast_si128(cb3, round_keys[num_rounds]);
            cb4 = _mm_aesenclast_si128(cb4, round_keys[num_rounds]);
            cb5 = _mm_aesenclast_si128(cb5, round_keys[num_rounds]);
            cb6 = _mm_aesenclast_si128(cb6, round_keys[num_rounds]);
            cb7 = _mm_aesenclast_si128(cb7, round_keys[num_rounds]);

            // XOR keystream with ciphertext
            const __m128i* ct = reinterpret_cast<const __m128i*>(ciphertext + offset);
            __m128i* pt = reinterpret_cast<__m128i*>(plaintext + offset);

            _mm_storeu_si128(pt + 0, _mm_xor_si128(cb0, _mm_loadu_si128(ct + 0)));
            _mm_storeu_si128(pt + 1, _mm_xor_si128(cb1, _mm_loadu_si128(ct + 1)));
            _mm_storeu_si128(pt + 2, _mm_xor_si128(cb2, _mm_loadu_si128(ct + 2)));
            _mm_storeu_si128(pt + 3, _mm_xor_si128(cb3, _mm_loadu_si128(ct + 3)));
            _mm_storeu_si128(pt + 4, _mm_xor_si128(cb4, _mm_loadu_si128(ct + 4)));
            _mm_storeu_si128(pt + 5, _mm_xor_si128(cb5, _mm_loadu_si128(ct + 5)));
            _mm_storeu_si128(pt + 6, _mm_xor_si128(cb6, _mm_loadu_si128(ct + 6)));
            _mm_storeu_si128(pt + 7, _mm_xor_si128(cb7, _mm_loadu_si128(ct + 7)));

            counter += 8;
            offset += 128;
        }

        // Tier 2: Single-block (16 bytes) - remaining full blocks
        while (offset + 16 <= len) {
            __m128i cb = make_counter_block(nonce, counter);
            __m128i ks = aes_encrypt_block(cb, round_keys, num_rounds);
            __m128i ct = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ciphertext + offset));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(plaintext + offset),
                             _mm_xor_si128(ks, ct));
            counter++;
            offset += 16;
        }

        // Tier 3: Partial block - final bytes at record end
        if (offset < len) {
            __m128i cb = make_counter_block(nonce, counter);
            __m128i ks = aes_encrypt_block(cb, round_keys, num_rounds);
            alignas(16) uint8_t ks_bytes[16];
            _mm_store_si128(reinterpret_cast<__m128i*>(ks_bytes), ks);
            for (size_t i = offset; i < len; i++) {
                plaintext[i] = ciphertext[i] ^ ks_bytes[i - offset];
            }
            counter++;
        }

        return counter;
    }
};

} // namespace crypto
} // namespace websocket
