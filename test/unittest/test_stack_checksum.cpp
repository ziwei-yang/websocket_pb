// test/unittest/test_stack_checksum.cpp
// Unit tests for IP/TCP checksum calculation

#include "../../src/stack/ip/checksum.hpp"
#include <iostream>
#include <cstring>
#include <cassert>
#include <arpa/inet.h>

using namespace userspace_stack;

// Test counter
int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) \
    std::cout << "Testing " << name << "... "; \
    try {

#define END_TEST \
        std::cout << "✅ PASS" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "❌ FAIL: " << e.what() << std::endl; \
        tests_failed++; \
    }

#define ASSERT(condition, msg) \
    if (!(condition)) throw std::runtime_error(msg);

// Test IP checksum calculation
void test_ip_checksum() {
    TEST("IP header checksum")
        // Create a simple IP header
        uint8_t ip_header[20] = {
            0x45, 0x00,  // Version, IHL, TOS
            0x00, 0x3c,  // Total length (60 bytes)
            0x1c, 0x46,  // Identification
            0x40, 0x00,  // Flags, Fragment offset
            0x40, 0x06,  // TTL, Protocol (TCP)
            0x00, 0x00,  // Checksum (will be calculated)
            0xc0, 0xa8, 0x01, 0x64,  // Source IP: 192.168.1.100
            0xc0, 0xa8, 0x01, 0x01   // Dest IP: 192.168.1.1
        };

        // Calculate checksum
        uint16_t checksum = ip_checksum(ip_header);

        // Checksum should be non-zero
        ASSERT(checksum != 0, "Checksum should be non-zero");

        // Insert checksum into header
        ip_header[10] = (checksum >> 8) & 0xFF;
        ip_header[11] = checksum & 0xFF;

        // Verify checksum (should be 0 when computed over header with checksum)
        ASSERT(verify_ip_checksum(ip_header) == 0, "Checksum verification failed");
    END_TEST
}

// Test internet checksum with known values
void test_internet_checksum() {
    TEST("Internet checksum (RFC 1071 example)")
        // RFC 1071 example: checksum of [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]
        uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
        uint16_t checksum = internet_checksum(data, sizeof(data));

        // The checksum should be 0x220d (one's complement)
        ASSERT(checksum == 0x220d, "Internet checksum mismatch");
    END_TEST
}

// Test TCP checksum calculation
void test_tcp_checksum() {
    TEST("TCP checksum with pseudo-header")
        // Create a simple TCP header (SYN packet)
        uint8_t tcp_header[20] = {
            0x04, 0xd2,  // Source port: 1234
            0x01, 0xbb,  // Dest port: 443
            0x00, 0x00, 0x00, 0x01,  // Sequence number
            0x00, 0x00, 0x00, 0x00,  // ACK number
            0x50, 0x02,  // Data offset (5 * 4 = 20 bytes), Flags (SYN)
            0xff, 0xff,  // Window size
            0x00, 0x00,  // Checksum (will be calculated)
            0x00, 0x00   // Urgent pointer
        };

        // Source/Dest IP addresses (network byte order)
        uint32_t src_ip = htonl(0xC0A80164);  // 192.168.1.100
        uint32_t dst_ip = htonl(0xC0A80101);  // 192.168.1.1

        // Calculate TCP checksum
        uint16_t checksum = tcp_checksum(src_ip, dst_ip, tcp_header, 20, nullptr, 0);

        // Checksum should be non-zero
        ASSERT(checksum != 0, "TCP checksum should be non-zero");

        // Insert checksum
        tcp_header[16] = (checksum >> 8) & 0xFF;
        tcp_header[17] = checksum & 0xFF;

        // Verify checksum
        ASSERT(verify_tcp_checksum(src_ip, dst_ip, tcp_header, 20, nullptr, 0) == 0,
               "TCP checksum verification failed");
    END_TEST
}

// Test TCP checksum with data
void test_tcp_checksum_with_data() {
    TEST("TCP checksum with payload")
        uint8_t tcp_header[20] = {
            0x04, 0xd2,  // Source port: 1234
            0x01, 0xbb,  // Dest port: 443
            0x00, 0x00, 0x00, 0x01,  // Sequence number
            0x00, 0x00, 0x00, 0x00,  // ACK number
            0x50, 0x18,  // Data offset, Flags (PSH, ACK)
            0xff, 0xff,  // Window size
            0x00, 0x00,  // Checksum
            0x00, 0x00   // Urgent pointer
        };

        const char* data = "Hello, World!";
        size_t data_len = strlen(data);

        uint32_t src_ip = htonl(0xC0A80164);
        uint32_t dst_ip = htonl(0xC0A80101);

        // Calculate checksum
        uint16_t checksum = tcp_checksum(src_ip, dst_ip, tcp_header, 20,
                                        data, data_len);

        ASSERT(checksum != 0, "TCP checksum with data should be non-zero");

        // Insert checksum
        tcp_header[16] = (checksum >> 8) & 0xFF;
        tcp_header[17] = checksum & 0xFF;

        // Verify
        ASSERT(verify_tcp_checksum(src_ip, dst_ip, tcp_header, 20, data, data_len) == 0,
               "TCP checksum with data verification failed");
    END_TEST
}

// Test checksum with odd length data
void test_checksum_odd_length() {
    TEST("Checksum with odd-length data")
        uint8_t data[] = {0x00, 0x01, 0x02};  // 3 bytes (odd)
        uint16_t checksum = internet_checksum(data, sizeof(data));

        ASSERT(checksum != 0, "Checksum of odd-length data should be non-zero");
    END_TEST
}

// Test checksum is commutative (order doesn't matter for sum)
void test_checksum_properties() {
    TEST("Checksum mathematical properties")
        uint8_t data1[] = {0x12, 0x34, 0x56, 0x78};
        uint8_t data2[] = {0x56, 0x78, 0x12, 0x34};

        uint16_t sum1 = internet_checksum(data1, sizeof(data1));
        uint16_t sum2 = internet_checksum(data2, sizeof(data2));

        // Checksums should be equal (sum is commutative)
        ASSERT(sum1 == sum2, "Checksum should be commutative");
    END_TEST
}

int main() {
    std::cout << "╔════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   Userspace Stack: Checksum Unit Tests        ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;

    // Run tests
    test_internet_checksum();
    test_ip_checksum();
    test_tcp_checksum();
    test_tcp_checksum_with_data();
    test_checksum_odd_length();
    test_checksum_properties();

    // Summary
    std::cout << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
