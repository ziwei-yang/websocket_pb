// test/unittest/test_ws_parser.cpp
// Unit tests for pipeline/ws_parser.hpp - WebSocket frame partial parsing

#include "../../src/pipeline/ws_parser.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace websocket::pipeline;

void test_calculate_header_len() {
    printf("Testing calculate_header_len()...\n");

    // Small payload (< 126), no mask
    assert(calculate_header_len(0x81, 0x05) == 2);  // 5 bytes payload

    // Small payload, with mask
    assert(calculate_header_len(0x81, 0x85) == 6);  // 5 bytes payload + mask

    // Medium payload (126), no mask
    assert(calculate_header_len(0x81, 0x7E) == 4);  // 16-bit length

    // Medium payload, with mask
    assert(calculate_header_len(0x81, 0xFE) == 8);  // 16-bit length + mask

    // Large payload (127), no mask
    assert(calculate_header_len(0x81, 0x7F) == 10);  // 64-bit length

    // Large payload, with mask
    assert(calculate_header_len(0x81, 0xFF) == 14);  // 64-bit length + mask

    printf("  PASS calculate_header_len()\n");
}

void test_start_parse_frame_complete() {
    printf("Testing start_parse_frame() with complete frame...\n");

    // Complete TEXT frame: FIN=1, opcode=TEXT, no mask, payload="Hello"
    uint8_t frame[] = {
        0x81,  // FIN + opcode 0x01 (TEXT)
        0x05,  // Not masked + length 5
        'H', 'e', 'l', 'l', 'o'
    };

    PartialWebSocketFrame pf;
    size_t consumed = start_parse_frame(pf, frame, sizeof(frame));

    assert(consumed == 2);  // Only header consumed
    assert(pf.header_complete == true);
    assert(pf.opcode == 0x01);
    assert(pf.fin == true);
    assert(pf.masked == false);
    assert(pf.payload_len == 5);
    assert(pf.expected_header_len == 2);

    printf("  PASS start_parse_frame() complete frame\n");
}

void test_start_parse_frame_partial_1_byte() {
    printf("Testing start_parse_frame() with only 1 byte...\n");

    uint8_t frame[] = {0x81};  // Only first byte

    PartialWebSocketFrame pf;
    size_t consumed = start_parse_frame(pf, frame, 1);

    assert(consumed == 1);
    assert(pf.header_complete == false);
    assert(pf.header_bytes_received == 1);
    assert(pf.header_buf[0] == 0x81);

    printf("  PASS start_parse_frame() 1 byte\n");
}

void test_start_parse_frame_partial_header() {
    printf("Testing start_parse_frame() with partial extended header...\n");

    // Frame with 16-bit length (126), only 3 bytes provided
    uint8_t frame[] = {0x81, 0x7E, 0x01};  // Need 4 bytes for header

    PartialWebSocketFrame pf;
    size_t consumed = start_parse_frame(pf, frame, 3);

    assert(consumed == 3);
    assert(pf.header_complete == false);
    assert(pf.header_bytes_received == 3);
    assert(pf.expected_header_len == 4);  // 2 base + 2 extended length

    printf("  PASS start_parse_frame() partial header\n");
}

void test_continue_partial_frame_complete_header_from_1_byte() {
    printf("Testing continue_partial_frame() completing header from 1 byte...\n");

    // Start with 1 byte
    uint8_t byte0[] = {0x81};
    PartialWebSocketFrame pf;
    start_parse_frame(pf, byte0, 1);
    assert(pf.header_bytes_received == 1);
    assert(pf.header_complete == false);

    // Continue with rest of header + payload
    uint8_t rest[] = {0x05, 'H', 'e', 'l', 'l', 'o'};
    size_t consumed = continue_partial_frame(pf, rest, sizeof(rest));

    assert(consumed == 1);  // Only 1 more byte needed for header
    assert(pf.header_complete == true);
    assert(pf.opcode == 0x01);
    assert(pf.fin == true);
    assert(pf.payload_len == 5);

    printf("  PASS continue_partial_frame() from 1 byte\n");
}

void test_continue_partial_frame_extended_length() {
    printf("Testing continue_partial_frame() with 16-bit extended length...\n");

    // Frame with 16-bit length = 300 bytes
    uint8_t header_part1[] = {0x81, 0x7E};  // Need extended length
    PartialWebSocketFrame pf;
    start_parse_frame(pf, header_part1, 2);
    assert(pf.header_complete == false);
    assert(pf.expected_header_len == 4);

    // Continue with extended length bytes
    uint8_t header_part2[] = {0x01, 0x2C};  // 300 in big-endian
    size_t consumed = continue_partial_frame(pf, header_part2, 2);

    assert(consumed == 2);
    assert(pf.header_complete == true);
    assert(pf.payload_len == 300);

    printf("  PASS continue_partial_frame() extended length\n");
}

void test_continue_partial_frame_64bit_length() {
    printf("Testing continue_partial_frame() with 64-bit extended length...\n");

    // Frame with 64-bit length
    uint8_t header[] = {
        0x82,  // FIN + opcode 0x02 (BINARY)
        0x7F,  // 64-bit length indicator
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00  // 65536 bytes
    };

    PartialWebSocketFrame pf;
    size_t consumed = start_parse_frame(pf, header, sizeof(header));

    assert(consumed == 10);
    assert(pf.header_complete == true);
    assert(pf.opcode == 0x02);
    assert(pf.payload_len == 65536);
    assert(pf.expected_header_len == 10);

    printf("  PASS continue_partial_frame() 64-bit length\n");
}

void test_continue_partial_frame_masked() {
    printf("Testing continue_partial_frame() with masked frame...\n");

    // Masked frame (client-to-server style)
    uint8_t header[] = {
        0x81,  // FIN + TEXT
        0x85,  // Masked + length 5
        0x12, 0x34, 0x56, 0x78  // Mask key
    };

    PartialWebSocketFrame pf;
    size_t consumed = start_parse_frame(pf, header, sizeof(header));

    assert(consumed == 6);
    assert(pf.header_complete == true);
    assert(pf.masked == true);
    assert(pf.payload_len == 5);
    assert(pf.mask_key[0] == 0x12);
    assert(pf.mask_key[1] == 0x34);
    assert(pf.mask_key[2] == 0x56);
    assert(pf.mask_key[3] == 0x78);

    printf("  PASS continue_partial_frame() masked\n");
}

void test_continue_partial_frame_byte_by_byte() {
    printf("Testing continue_partial_frame() byte by byte...\n");

    // Complete header sent byte by byte
    uint8_t header[] = {0x89, 0x00};  // PING with 0 payload

    PartialWebSocketFrame pf;

    // First byte
    size_t c1 = start_parse_frame(pf, &header[0], 1);
    assert(c1 == 1);
    assert(pf.header_complete == false);
    assert(pf.header_bytes_received == 1);

    // Second byte
    size_t c2 = continue_partial_frame(pf, &header[1], 1);
    assert(c2 == 1);
    assert(pf.header_complete == true);
    assert(pf.opcode == 0x09);  // PING
    assert(pf.payload_len == 0);

    printf("  PASS continue_partial_frame() byte by byte\n");
}

void test_continue_partial_frame_extended_byte_by_byte() {
    printf("Testing continue_partial_frame() extended length byte by byte...\n");

    // 16-bit extended length header
    uint8_t header[] = {0x81, 0x7E, 0x00, 0x80};  // 128 bytes payload

    PartialWebSocketFrame pf;

    // Byte 1
    start_parse_frame(pf, &header[0], 1);
    assert(pf.header_bytes_received == 1);

    // Byte 2 - now we know expected length
    continue_partial_frame(pf, &header[1], 1);
    assert(pf.header_bytes_received == 2);
    assert(pf.expected_header_len == 4);
    assert(pf.header_complete == false);

    // Byte 3
    continue_partial_frame(pf, &header[2], 1);
    assert(pf.header_bytes_received == 3);
    assert(pf.header_complete == false);

    // Byte 4 - header complete
    continue_partial_frame(pf, &header[3], 1);
    assert(pf.header_bytes_received == 4);
    assert(pf.header_complete == true);
    assert(pf.payload_len == 128);

    printf("  PASS continue_partial_frame() extended byte by byte\n");
}

void test_parse_completed_header_all_opcodes() {
    printf("Testing parse_completed_header() for all opcodes...\n");

    // CONTINUATION (0x00)
    {
        PartialWebSocketFrame pf;
        uint8_t frame[] = {0x00, 0x00};
        start_parse_frame(pf, frame, 2);
        assert(pf.opcode == 0x00);
        assert(pf.fin == false);
    }

    // TEXT (0x01)
    {
        PartialWebSocketFrame pf;
        uint8_t frame[] = {0x81, 0x00};
        start_parse_frame(pf, frame, 2);
        assert(pf.opcode == 0x01);
        assert(pf.fin == true);
    }

    // BINARY (0x02)
    {
        PartialWebSocketFrame pf;
        uint8_t frame[] = {0x82, 0x00};
        start_parse_frame(pf, frame, 2);
        assert(pf.opcode == 0x02);
    }

    // CLOSE (0x08)
    {
        PartialWebSocketFrame pf;
        uint8_t frame[] = {0x88, 0x02, 0x03, 0xE8};  // Close with code 1000
        start_parse_frame(pf, frame, 2);
        assert(pf.opcode == 0x08);
        assert(pf.payload_len == 2);
    }

    // PING (0x09)
    {
        PartialWebSocketFrame pf;
        uint8_t frame[] = {0x89, 0x04, 'p', 'i', 'n', 'g'};
        start_parse_frame(pf, frame, 2);
        assert(pf.opcode == 0x09);
    }

    // PONG (0x0A)
    {
        PartialWebSocketFrame pf;
        uint8_t frame[] = {0x8A, 0x00};
        start_parse_frame(pf, frame, 2);
        assert(pf.opcode == 0x0A);
    }

    printf("  PASS parse_completed_header() all opcodes\n");
}

void test_frame_is_complete() {
    printf("Testing PartialWebSocketFrame::is_complete()...\n");

    PartialWebSocketFrame pf;
    uint8_t frame[] = {0x81, 0x05};  // 5 byte payload

    start_parse_frame(pf, frame, 2);

    assert(pf.is_complete() == false);  // Header complete, but no payload received
    assert(pf.payload_remaining() == 5);

    // Simulate receiving payload
    pf.payload_bytes_received = 3;
    assert(pf.is_complete() == false);
    assert(pf.payload_remaining() == 2);

    pf.payload_bytes_received = 5;
    assert(pf.is_complete() == true);
    assert(pf.payload_remaining() == 0);

    printf("  PASS is_complete()\n");
}

void test_build_ws_header() {
    printf("Testing build_ws_header()...\n");

    // Small payload, no mask
    {
        uint8_t header[14];
        size_t len = build_ws_header(header, 0x01, 50, true, false, nullptr);
        assert(len == 2);
        assert(header[0] == 0x81);  // FIN + TEXT
        assert(header[1] == 50);    // Length
    }

    // Small payload, with mask
    {
        uint8_t header[14];
        uint8_t mask[4] = {0x11, 0x22, 0x33, 0x44};
        size_t len = build_ws_header(header, 0x01, 50, true, true, mask);
        assert(len == 6);
        assert(header[0] == 0x81);
        assert(header[1] == 0xB2);  // 0x80 | 50
        assert(header[2] == 0x11);
        assert(header[3] == 0x22);
        assert(header[4] == 0x33);
        assert(header[5] == 0x44);
    }

    // Medium payload (16-bit)
    {
        uint8_t header[14];
        size_t len = build_ws_header(header, 0x02, 1000, true, false, nullptr);
        assert(len == 4);
        assert(header[0] == 0x82);  // FIN + BINARY
        assert(header[1] == 126);   // Extended 16-bit
        assert(header[2] == 0x03);  // 1000 >> 8
        assert(header[3] == 0xE8);  // 1000 & 0xFF
    }

    // Large payload (64-bit)
    {
        uint8_t header[14];
        size_t len = build_ws_header(header, 0x02, 100000, true, false, nullptr);
        assert(len == 10);
        assert(header[0] == 0x82);
        assert(header[1] == 127);  // Extended 64-bit
    }

    // FIN=0 (fragmented)
    {
        uint8_t header[14];
        size_t len = build_ws_header(header, 0x01, 10, false, false, nullptr);
        assert(len == 2);
        assert(header[0] == 0x01);  // No FIN + TEXT
    }

    printf("  PASS build_ws_header()\n");
}

void test_unmask_payload() {
    printf("Testing unmask_payload()...\n");

    // Test unmasking
    uint8_t payload[] = {'H' ^ 0x12, 'e' ^ 0x34, 'l' ^ 0x56, 'l' ^ 0x78, 'o' ^ 0x12};
    uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};

    unmask_payload(payload, 5, mask);

    assert(payload[0] == 'H');
    assert(payload[1] == 'e');
    assert(payload[2] == 'l');
    assert(payload[3] == 'l');
    assert(payload[4] == 'o');

    printf("  PASS unmask_payload()\n");
}

void test_zero_length_input() {
    printf("Testing zero-length input handling...\n");

    PartialWebSocketFrame pf;

    // start_parse_frame with 0 bytes
    size_t consumed = start_parse_frame(pf, nullptr, 0);
    assert(consumed == 0);

    // continue_partial_frame with 0 bytes
    pf.header_bytes_received = 1;
    pf.header_buf[0] = 0x81;
    consumed = continue_partial_frame(pf, nullptr, 0);
    assert(consumed == 0);

    printf("  PASS zero-length input\n");
}

int main() {
    printf("\n========================================\n");
    printf("  WebSocket Parser Unit Tests\n");
    printf("========================================\n\n");

    test_calculate_header_len();
    test_start_parse_frame_complete();
    test_start_parse_frame_partial_1_byte();
    test_start_parse_frame_partial_header();
    test_continue_partial_frame_complete_header_from_1_byte();
    test_continue_partial_frame_extended_length();
    test_continue_partial_frame_64bit_length();
    test_continue_partial_frame_masked();
    test_continue_partial_frame_byte_by_byte();
    test_continue_partial_frame_extended_byte_by_byte();
    test_parse_completed_header_all_opcodes();
    test_frame_is_complete();
    test_build_ws_header();
    test_unmask_payload();
    test_zero_length_input();

    printf("\n========================================\n");
    printf("  All ws_parser tests PASSED!\n");
    printf("========================================\n\n");

    return 0;
}
