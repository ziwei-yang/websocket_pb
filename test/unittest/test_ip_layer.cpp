// test/unittest/test_ip_layer.cpp
// Unit tests for IP layer helpers (no network required)

#include "../../src/stack/ip/ip_layer.hpp"
#include <iostream>
#include <cassert>

using namespace userspace_stack;

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

// Test IP string to uint32_t conversion
void test_string_to_ip() {
    TEST("IP string to uint32_t conversion")
        uint32_t ip1 = IPLayer::string_to_ip("192.168.1.100");
        ASSERT(ip1 == 0xC0A80164, "192.168.1.100 = 0xC0A80164");

        uint32_t ip2 = IPLayer::string_to_ip("127.0.0.1");
        ASSERT(ip2 == 0x7F000001, "127.0.0.1 = 0x7F000001");

        uint32_t ip3 = IPLayer::string_to_ip("255.255.255.255");
        ASSERT(ip3 == 0xFFFFFFFF, "255.255.255.255 = 0xFFFFFFFF");

        uint32_t ip4 = IPLayer::string_to_ip("0.0.0.0");
        ASSERT(ip4 == 0x00000000, "0.0.0.0 = 0x00000000");
    END_TEST
}

// Test uint32_t to IP string conversion
void test_ip_to_string() {
    TEST("uint32_t to IP string conversion")
        std::string str1 = IPLayer::ip_to_string(0xC0A80164);
        ASSERT(str1 == "192.168.1.100", "0xC0A80164 = 192.168.1.100");

        std::string str2 = IPLayer::ip_to_string(0x7F000001);
        ASSERT(str2 == "127.0.0.1", "0x7F000001 = 127.0.0.1");

        std::string str3 = IPLayer::ip_to_string(0xFFFFFFFF);
        ASSERT(str3 == "255.255.255.255", "0xFFFFFFFF = 255.255.255.255");

        std::string str4 = IPLayer::ip_to_string(0x00000000);
        ASSERT(str4 == "0.0.0.0", "0x00000000 = 0.0.0.0");
    END_TEST
}

// Test round-trip conversion
void test_ip_conversion_roundtrip() {
    TEST("IP conversion round-trip")
        const char* test_ips[] = {
            "192.168.1.100",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "1.2.3.4"
        };

        for (const char* ip_str : test_ips) {
            uint32_t ip = IPLayer::string_to_ip(ip_str);
            std::string back = IPLayer::ip_to_string(ip);
            ASSERT(back == ip_str, std::string("Round-trip failed for ") + ip_str);
        }
    END_TEST
}

// Test invalid IP string handling
void test_invalid_ip_string() {
    TEST("Invalid IP string handling")
        bool exception_thrown = false;
        try {
            IPLayer::string_to_ip("invalid.ip.address");
        } catch (const std::runtime_error&) {
            exception_thrown = true;
        }
        ASSERT(exception_thrown, "Should throw on invalid IP");

        exception_thrown = false;
        try {
            IPLayer::string_to_ip("999.999.999.999");
        } catch (const std::runtime_error&) {
            exception_thrown = true;
        }
        ASSERT(exception_thrown, "Should throw on out-of-range IP");
    END_TEST
}

// Test subnet checking (if implemented)
void test_subnet_check() {
    TEST("Subnet checking")
        // This test assumes we have a simple subnet check
        // Local IP: 192.168.1.100
        // Netmask: 255.255.255.0 (0xFFFFFF00)

        uint32_t local_ip = 0xC0A80164;    // 192.168.1.100
        uint32_t netmask = 0xFFFFFF00;     // 255.255.255.0

        // Same subnet
        uint32_t ip1 = 0xC0A80101;         // 192.168.1.1
        ASSERT((ip1 & netmask) == (local_ip & netmask), "192.168.1.1 in same subnet");

        // Different subnet
        uint32_t ip2 = 0xC0A80201;         // 192.168.2.1
        ASSERT((ip2 & netmask) != (local_ip & netmask), "192.168.2.1 in different subnet");
    END_TEST
}

// Test IPv4 header structure size
void test_ipv4_header_size() {
    TEST("IPv4 header structure size")
        // IPv4 header should be exactly 20 bytes (no padding)
        ASSERT(sizeof(IPv4Header) == 20, "IPv4Header should be 20 bytes");
    END_TEST
}

// Test IP protocol constants
void test_ip_protocol_constants() {
    TEST("IP protocol constants")
        ASSERT(IP_PROTO_ICMP == 1, "ICMP protocol number");
        ASSERT(IP_PROTO_TCP == 6, "TCP protocol number");
        ASSERT(IP_PROTO_UDP == 17, "UDP protocol number");
        ASSERT(IP_VERSION == 4, "IP version");
        ASSERT(IP_HEADER_LEN == 20, "IP header length");
    END_TEST
}

int main() {
    std::cout << "╔════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   Userspace Stack: IP Layer Unit Tests        ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;

    // Run tests
    test_string_to_ip();
    test_ip_to_string();
    test_ip_conversion_roundtrip();
    test_invalid_ip_string();
    test_subnet_check();
    test_ipv4_header_size();
    test_ip_protocol_constants();

    // Summary
    std::cout << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;
    std::cout << "Tests passed: " << tests_passed << std::endl;
    std::cout << "Tests failed: " << tests_failed << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
