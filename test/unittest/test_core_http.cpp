// test/unittest/test_core_http.cpp
// Unit tests for core/http.hpp - WebSocket frame parsing and building

#include "../../src/core/http.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>

using namespace websocket::http;

void test_generate_websocket_key() {
    printf("Testing generate_websocket_key()...\n");

    std::string key1 = generate_websocket_key();
    std::string key2 = generate_websocket_key();

    // Keys should be 24 characters
    assert(key1.size() == 24);
    assert(key2.size() == 24);

    // Keys should be different (random)
    assert(key1 != key2);

    printf("  ✅ generate_websocket_key() works\n");
}

void test_is_valid_header() {
    printf("Testing is_valid_header()...\n");

    // Valid headers
    assert(is_valid_header("Content-Type", "application/json"));
    assert(is_valid_header("Authorization", "Bearer token123"));

    // Invalid: CRLF injection
    assert(!is_valid_header("X-Test\r\n", "value"));
    assert(!is_valid_header("X-Test", "value\r\nX-Injected: evil"));
    assert(!is_valid_header("X-Test\n", "value"));

    // Invalid: empty key
    assert(!is_valid_header("", "value"));

    printf("  ✅ is_valid_header() works\n");
}

void test_build_pong_frame() {
    printf("Testing build_pong_frame()...\n");

    // Test 1: Empty payload
    {
        uint8_t pong[256];
        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
        size_t len = build_pong_frame(nullptr, 0, pong, mask);

        assert(len == 6);  // Header (2) + mask (4) + payload (0)
        assert(pong[0] == 0x8A);  // FIN + opcode 0x0A
        assert(pong[1] == 0x80);  // Masked + length 0
    }

    // Test 2: Small payload
    {
        uint8_t payload[] = {'p', 'i', 'n', 'g'};
        uint8_t pong[256];
        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
        size_t len = build_pong_frame(payload, 4, pong, mask);

        assert(len == 10);  // Header (2) + mask (4) + payload (4)
        assert(pong[0] == 0x8A);  // FIN + opcode 0x0A
        assert(pong[1] == 0x84);  // Masked + length 4

        // Verify masking
        for (size_t i = 0; i < 4; i++) {
            assert(pong[6 + i] == (payload[i] ^ mask[i % 4]));
        }
    }

    // Test 3: Truncation (> 125 bytes)
    {
        uint8_t payload[200];
        memset(payload, 'A', sizeof(payload));
        uint8_t pong[256];
        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
        size_t len = build_pong_frame(payload, 200, pong, mask);

        assert(len == 131);  // Header (2) + mask (4) + payload (125, truncated)
        assert(pong[1] == 0xFD);  // Masked + length 125
    }

    printf("  ✅ build_pong_frame() works\n");
}

void test_parse_websocket_frame() {
    printf("Testing parse_websocket_frame()...\n");

    // Test 1: Simple TEXT frame (small payload)
    {
        uint8_t frame[] = {
            0x81,  // FIN + opcode 0x01 (TEXT)
            0x05,  // Not masked + length 5
            'H', 'e', 'l', 'l', 'o'
        };

        WebSocketFrame parsed;
        bool success = parse_websocket_frame(frame, sizeof(frame), parsed);

        assert(success);
        assert(parsed.fin == true);
        assert(parsed.opcode == 0x01);
        assert(parsed.masked == false);
        assert(parsed.payload_len == 5);
        assert(parsed.header_len == 2);
        assert(memcmp(parsed.payload, "Hello", 5) == 0);
    }

    // Test 2: PING frame with masking
    {
        uint8_t frame[] = {
            0x89,  // FIN + opcode 0x09 (PING)
            0x84,  // Masked + length 4
            0x12, 0x34, 0x56, 0x78,  // Masking key
            'p' ^ 0x12, 'i' ^ 0x34, 'n' ^ 0x56, 'g' ^ 0x78  // Masked payload
        };

        WebSocketFrame parsed;
        bool success = parse_websocket_frame(frame, sizeof(frame), parsed);

        assert(success);
        assert(parsed.fin == true);
        assert(parsed.opcode == 0x09);
        assert(parsed.masked == true);
        assert(parsed.payload_len == 4);
        assert(parsed.header_len == 6);  // 2 + 4 (masking key)
    }

    // Test 3: Extended payload length (126)
    {
        uint8_t frame[] = {
            0x81,  // FIN + opcode 0x01 (TEXT)
            126,   // Extended length (16-bit)
            0x00, 0x80,  // Length = 128
            // ... payload would follow
        };

        WebSocketFrame parsed;
        bool success = parse_websocket_frame(frame, 4, parsed);  // No payload yet

        assert(!success);  // Should fail - incomplete frame
    }

    // Test 4: Incomplete frame
    {
        uint8_t frame[] = {0x81};  // Only 1 byte

        WebSocketFrame parsed;
        bool success = parse_websocket_frame(frame, 1, parsed);

        assert(!success);  // Need at least 2 bytes
    }

    printf("  ✅ parse_websocket_frame() works\n");
}

void test_build_websocket_upgrade_request() {
    printf("Testing build_websocket_upgrade_request()...\n");

    std::vector<std::pair<std::string, std::string>> headers = {
        {"User-Agent", "TestClient/1.0"},
        {"X-Custom", "value"}
    };

    char request[4096];
    size_t len = build_websocket_upgrade_request("example.com", "/chat",
                                                   headers, request, sizeof(request));

    assert(len > 0);
    assert(len < sizeof(request));

    // Convert to string for easier checking
    std::string req_str(request, len);

    // Verify required headers
    assert(req_str.find("GET /chat HTTP/1.1") != std::string::npos);
    assert(req_str.find("Host: example.com") != std::string::npos);
    assert(req_str.find("Upgrade: websocket") != std::string::npos);
    assert(req_str.find("Connection: Upgrade") != std::string::npos);
    assert(req_str.find("Sec-WebSocket-Key: ") != std::string::npos);
    assert(req_str.find("Sec-WebSocket-Version: 13") != std::string::npos);

    // Verify custom headers
    assert(req_str.find("User-Agent: TestClient/1.0") != std::string::npos);
    assert(req_str.find("X-Custom: value") != std::string::npos);

    // Verify ends with \r\n\r\n
    assert(req_str.substr(req_str.size() - 4) == "\r\n\r\n");

    printf("  ✅ build_websocket_upgrade_request() works\n");
}

void test_validate_http_upgrade_response() {
    printf("Testing validate_http_upgrade_response()...\n");

    // Valid response
    const char* valid = "HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n\r\n";
    assert(validate_http_upgrade_response(
        reinterpret_cast<const uint8_t*>(valid), strlen(valid)));

    // Invalid: 200 OK
    const char* invalid = "HTTP/1.1 200 OK\r\n\r\n";
    assert(!validate_http_upgrade_response(
        reinterpret_cast<const uint8_t*>(invalid), strlen(invalid)));

    // Too short
    const char* too_short = "HTTP";
    assert(!validate_http_upgrade_response(
        reinterpret_cast<const uint8_t*>(too_short), strlen(too_short)));

    printf("  ✅ validate_http_upgrade_response() works\n");
}

void test_build_text_frame() {
    printf("Testing build_text_frame()...\n");

    const char* text = "Hello, World!";
    uint8_t frame[256];
    uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};

    size_t len = build_text_frame(reinterpret_cast<const uint8_t*>(text),
                                    strlen(text), frame, sizeof(frame), mask);

    assert(len == 2 + 4 + strlen(text));  // Header + mask + payload
    assert(frame[0] == 0x81);  // FIN + opcode 0x01 (TEXT)
    assert(frame[1] == (0x80 | strlen(text)));  // Masked + length

    // Verify masking key
    assert(memcmp(frame + 2, mask, 4) == 0);

    // Verify masked payload
    for (size_t i = 0; i < strlen(text); i++) {
        assert(frame[6 + i] == (text[i] ^ mask[i % 4]));
    }

    printf("  ✅ build_text_frame() works\n");
}

void test_build_close_frame() {
    printf("Testing build_close_frame()...\n");

    const char* reason = "Goodbye";
    uint8_t frame[256];
    uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};

    size_t len = build_close_frame(1000,  // Normal closure
                                     reinterpret_cast<const uint8_t*>(reason),
                                     strlen(reason), frame, mask);

    assert(len == 2 + 4 + 2 + strlen(reason));  // Header + mask + status + reason
    assert(frame[0] == 0x88);  // FIN + opcode 0x08 (CLOSE)
    assert(frame[1] == (0x80 | (2 + strlen(reason))));  // Masked + payload length

    printf("  ✅ build_close_frame() works\n");
}

int main() {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║        core/http.hpp Unit Tests                                   ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    test_generate_websocket_key();
    test_is_valid_header();
    test_build_pong_frame();
    test_parse_websocket_frame();
    test_build_websocket_upgrade_request();
    test_validate_http_upgrade_response();
    test_build_text_frame();
    test_build_close_frame();

    printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║ All tests passed! ✅                                              ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n");

    return 0;
}
