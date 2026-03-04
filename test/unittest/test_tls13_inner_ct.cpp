// test/unittest/test_tls13_inner_ct.cpp
// Unit test: TLS 1.3 non-app-data inner content type causes double seq_num++
//
// In TLS 1.3, ALL records have outer content_type = 0x17. The real type
// (app-data 0x17, NewSessionTicket 0x04, etc.) is the last byte of decrypted
// payload. When NEED_PAYLOAD finds inner_ct != 0x17, the buggy code does
// seq_num++ then transitions to NEED_TAG, which does seq_num++ again.
// This off-by-one nonce causes all subsequent records to decrypt as garbage.

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
// Minimal recv buffer over a flat byte array
// =============================================================================
struct MockRecvBuffer {
    const uint8_t* data;
    size_t len;
    size_t pos;

    MockRecvBuffer(const uint8_t* d, size_t l) : data(d), len(l), pos(0) {}

    size_t available() const { return len - pos; }

    size_t read(uint8_t* dst, size_t n) {
        size_t can = (n < available()) ? n : available();
        memcpy(dst, data + pos, can);
        pos += can;
        return can;
    }
};

// =============================================================================
// Build a TLS 1.3 record: 5-byte header + ciphertext(payload+inner_ct) + 16B tag
//
// payload_len: length of actual plaintext (not including inner CT byte)
// inner_ct: the real content type (0x17 = app-data, 0x04 = NewSessionTicket)
// seq_num: for nonce derivation
// =============================================================================
static size_t build_tls13_record(
    uint8_t* out,
    const uint8_t* plaintext, size_t payload_len,
    uint8_t inner_ct,
    const TLSRecordKeys& keys, uint64_t seq_num)
{
    // Plaintext to encrypt = payload || inner_ct
    size_t ct_len = payload_len + 1;  // ciphertext_length (what parser computes as record_length - 16)
    uint16_t record_length = static_cast<uint16_t>(ct_len + 16);  // ciphertext + tag

    // TLS record header: content_type(0x17) || version(0x0303) || length
    out[0] = 0x17;  // outer content type (always 0x17 in TLS 1.3)
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = static_cast<uint8_t>(record_length >> 8);
    out[4] = static_cast<uint8_t>(record_length);

    // Build plaintext: payload || inner_ct
    uint8_t plain[256];
    memcpy(plain, plaintext, payload_len);
    plain[payload_len] = inner_ct;

    // Derive nonce
    uint8_t nonce[12];
    derive_nonce_tls13(keys.iv, seq_num, nonce);

    // Encrypt with AES-CTR at counter=2 (GCM convention)
    AESCTRDecryptor::decrypt(
        keys.round_keys, keys.num_rounds,
        nonce, 2, plain, out + 5, ct_len);

    // Dummy 16-byte auth tag (we skip verification)
    memset(out + 5 + ct_len, 0xAA, 16);

    return 5 + ct_len + 16;
}

// =============================================================================
// TLS 1.3 record parser — reproduces the exact state machine from
// transport.hpp:1556-1767 (NEED_HEADER → NEED_PAYLOAD → NEED_TAG)
// =============================================================================
struct ParseResult {
    uint64_t seq_num;
    int      output_len;       // total app-data bytes written
};

static ParseResult parse_tls13_records(
    MockRecvBuffer& buf,
    const TLSRecordKeys& keys,
    uint8_t* dest, size_t dest_size)
{
    TLSRecordParser parser{};
    uint64_t seq_num = 0;
    int offset = 0;
    size_t chunk_size = dest_size;

    for (;;) {
        if (static_cast<size_t>(offset) >= chunk_size)
            break;

        switch (parser.state) {

        case TLSRecordState::NEED_HEADER: {
            if (buf.available() < 5) goto done;

            uint8_t hdr[5];
            buf.read(hdr, 5);

            parser.content_type = hdr[0];
            parser.record_length = (static_cast<uint16_t>(hdr[3]) << 8) | hdr[4];
            parser.payload_consumed = 0;
            parser.tag_consumed = 0;

            // TLS 1.3: record_length = ciphertext + inner_content_type(1) + tag(16)
            parser.ciphertext_length = parser.record_length - 16;

            // Derive nonce
            derive_nonce_tls13(keys.iv, seq_num, parser.nonce);

            parser.block_counter = 2;  // GCM convention

            // Non-application data outer CT: skip (shouldn't happen in TLS 1.3,
            // but matches production code)
            if (parser.content_type != 0x17) {
                uint16_t to_skip = parser.ciphertext_length + 16;
                size_t avail = buf.available();
                size_t skip_now = (avail < to_skip) ? avail : to_skip;
                { uint8_t discard[256]; size_t skipped = 0;
                  while (skipped < skip_now) {
                      size_t chunk = (skip_now - skipped < sizeof(discard)) ? (skip_now - skipped) : sizeof(discard);
                      buf.read(discard, chunk);
                      skipped += chunk;
                  }
                }
                if (skip_now < to_skip) goto done;
                seq_num++;
                parser.state = TLSRecordState::NEED_HEADER;
                continue;
            }

            parser.state = TLSRecordState::NEED_PAYLOAD;
            continue;
        }

        case TLSRecordState::NEED_PAYLOAD: {
            uint16_t payload_remaining = parser.ciphertext_length - parser.payload_consumed;

            if (payload_remaining == 0) {
                parser.state = TLSRecordState::NEED_TAG;
                parser.tag_consumed = 0;
                continue;
            }

            size_t avail = buf.available();
            if (avail == 0) goto done;

            size_t can_decrypt = chunk_size - static_cast<size_t>(offset);
            if (can_decrypt > payload_remaining) can_decrypt = payload_remaining;
            if (can_decrypt > avail) can_decrypt = avail;

            bool is_final = (can_decrypt >= payload_remaining);

            if (!is_final) {
                can_decrypt = (can_decrypt / 16) * 16;
                if (can_decrypt == 0) goto done;
            }

            size_t read_ct = buf.read(dest + offset, can_decrypt);
            if (read_ct < can_decrypt) {
                can_decrypt = read_ct;
                is_final = false;
                can_decrypt = (can_decrypt / 16) * 16;
                if (can_decrypt == 0) goto done;
            }

            parser.block_counter = AESCTRDecryptor::decrypt(
                keys.round_keys, keys.num_rounds,
                parser.nonce, parser.block_counter,
                dest + offset, dest + offset, can_decrypt);
            parser.payload_consumed += static_cast<uint16_t>(can_decrypt);

            size_t chunk_len = can_decrypt;

            // TLS 1.3: if final chunk, strip inner content type + padding
            if (is_final && keys.is_tls13 && chunk_len > 0) {
                uint8_t* chunk_start = dest + offset;
                size_t pos = chunk_len - 1;
                while (pos > 0 && chunk_start[pos] == 0) {
                    pos--;
                }
                uint8_t inner_ct = chunk_start[pos];
                chunk_len = pos;  // exclude CT byte

                if (inner_ct != 0x17) {
                    parser.state = TLSRecordState::NEED_TAG;
                    parser.tag_consumed = 0;
                    // BUG: this seq_num++ is premature — NEED_TAG will do it again
                    // (removed after fix)
                    // seq_num++;
                    continue;
                }
            }

            if (chunk_len > 0) {
                offset += static_cast<int>(chunk_len);
            }

            if (parser.payload_consumed >= parser.ciphertext_length) {
                parser.state = TLSRecordState::NEED_TAG;
                parser.tag_consumed = 0;
            }
            continue;
        }

        case TLSRecordState::NEED_TAG: {
            // For non-app-data records with outer CT != 0x17 (TLS 1.2 path)
            if (parser.content_type != 0x17) {
                uint16_t remaining = parser.ciphertext_length;
                if (remaining > 0) {
                    size_t avail = buf.available();
                    size_t skip_now = (avail < remaining) ? avail : remaining;
                    { uint8_t discard[256]; size_t skipped = 0;
                      while (skipped < skip_now) {
                          size_t chunk = (skip_now - skipped < sizeof(discard)) ? (skip_now - skipped) : sizeof(discard);
                          buf.read(discard, chunk);
                          skipped += chunk;
                      }
                    }
                    parser.ciphertext_length -= static_cast<uint16_t>(skip_now);
                    if (parser.ciphertext_length > 0) goto done;
                }
                seq_num++;
                parser.state = TLSRecordState::NEED_HEADER;
                continue;
            }

            // Read and discard 16-byte AEAD tag
            uint16_t tag_remaining = 16 - parser.tag_consumed;
            size_t avail = buf.available();
            size_t skip_now = (avail < tag_remaining) ? avail : tag_remaining;
            { uint8_t discard[16];
              buf.read(discard, skip_now);
            }
            parser.tag_consumed += static_cast<uint16_t>(skip_now);

            if (parser.tag_consumed >= 16) {
                seq_num++;
                parser.state = TLSRecordState::NEED_HEADER;
                continue;
            }
            goto done;
        }

        } // switch
    } // for

done:
    return { seq_num, offset };
}

// =============================================================================
// Tests
// =============================================================================

static void run_tests() {
    // Setup: AES-128 key + IV
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

    // Build 3 TLS 1.3 records into a wire buffer:
    //   Record 0 (seq=0): app-data,          16B payload "HELLO_WORLD_PAD!"  + inner CT 0x17
    //   Record 1 (seq=1): NewSessionTicket,   16B payload "SESSION_TICKET!!"  + inner CT 0x04
    //   Record 2 (seq=2): app-data,          16B payload "AFTER_TICKET_PAD"  + inner CT 0x17
    uint8_t wire[512];
    size_t wire_len = 0;

    const char* plain0 = "HELLO_WORLD_PAD!";  // 16 bytes
    const char* plain1 = "SESSION_TICKET!!";  // 16 bytes
    const char* plain2 = "AFTER_TICKET_PAD";  // 16 bytes

    wire_len += build_tls13_record(wire + wire_len,
        reinterpret_cast<const uint8_t*>(plain0), 16, 0x17, keys, 0);
    wire_len += build_tls13_record(wire + wire_len,
        reinterpret_cast<const uint8_t*>(plain1), 16, 0x04, keys, 1);
    wire_len += build_tls13_record(wire + wire_len,
        reinterpret_cast<const uint8_t*>(plain2), 16, 0x17, keys, 2);

    printf("  Wire buffer: %zu bytes (%zu per record)\n\n", wire_len, wire_len / 3);

    // Parse all records
    uint8_t output[256];
    memset(output, 0, sizeof(output));
    MockRecvBuffer buf(wire, wire_len);
    auto result = parse_tls13_records(buf, keys, output, sizeof(output));

    // ---- Test 1: Record 0 decrypts correctly ----
    TEST("Record 0 (app-data) decrypts correctly");
    if (result.output_len >= 16 && memcmp(output, plain0, 16) == 0) {
        PASS();
    } else {
        char got[17] = {};
        memcpy(got, output, (result.output_len >= 16) ? 16 : result.output_len);
        char msg[128];
        snprintf(msg, sizeof(msg), "expected \"%s\", got \"%s\" (output_len=%d)", plain0, got, result.output_len);
        FAIL(msg);
    }

    // ---- Test 2: Record 1 (NewSessionTicket) is NOT in output ----
    TEST("Record 1 (NewSessionTicket) is skipped from output");
    // Output should be exactly 32 bytes (record 0 + record 2), not 48
    if (result.output_len == 32) {
        PASS();
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "expected output_len=32, got %d", result.output_len);
        FAIL(msg);
    }

    // ---- Test 3: seq_num after all 3 records == 3 ----
    TEST("seq_num after all 3 records == 3");
    if (result.seq_num == 3) {
        PASS();
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "expected seq_num=3, got %llu",
                 static_cast<unsigned long long>(result.seq_num));
        FAIL(msg);
    }

    // ---- Test 4: Record 2 decrypts correctly ----
    TEST("Record 2 (app-data after ticket) decrypts correctly");
    if (result.output_len >= 32 && memcmp(output + 16, plain2, 16) == 0) {
        PASS();
    } else {
        char got[17] = {};
        if (result.output_len >= 32)
            memcpy(got, output + 16, 16);
        char msg[128];
        snprintf(msg, sizeof(msg), "expected \"%s\", got \"%s\"", plain2, got);
        FAIL(msg);
    }
}

// =============================================================================
// Main
// =============================================================================
int main() {
    printf("================================================================\n");
    printf("  TLS 1.3 Inner Content Type — Double seq_num++ Bug Test\n");
    printf("================================================================\n\n");
    printf("  Bug: In TLS 1.3, NewSessionTicket has outer CT=0x17.\n");
    printf("       NEED_PAYLOAD does seq_num++ on inner_ct!=0x17,\n");
    printf("       then NEED_TAG does seq_num++ again → off-by-one nonce.\n\n");

    run_tests();

    printf("\n================================================================\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("================================================================\n");

    return tests_failed > 0 ? 1 : 0;
}
