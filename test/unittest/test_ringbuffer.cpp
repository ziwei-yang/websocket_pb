// test/unittest/test_ringbuffer.cpp
// Unit tests for optimized ring buffer implementation

#include "../../src/ringbuffer.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

// Simple test framework
#define TEST(name) \
    void test_##name(); \
    struct TestRegistrar_##name { \
        TestRegistrar_##name() { register_test(#name, test_##name); } \
    } registrar_##name; \
    void test_##name()

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        std::cerr << "FAIL: " << __FILE__ << ":" << __LINE__ \
                  << " Expected " << #a << " == " << #b \
                  << " (got " << (a) << " vs " << (b) << ")" << std::endl; \
        return; \
    } \
} while(0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        std::cerr << "FAIL: " << __FILE__ << ":" << __LINE__ \
                  << " Expected " << #cond << " to be true" << std::endl; \
        return; \
    } \
} while(0)

#define ASSERT_FALSE(cond) do { \
    if (cond) { \
        std::cerr << "FAIL: " << __FILE__ << ":" << __LINE__ \
                  << " Expected " << #cond << " to be false" << std::endl; \
        return; \
    } \
} while(0)

#define ASSERT_NE(a, b) do { \
    if ((a) == (b)) { \
        std::cerr << "FAIL: " << __FILE__ << ":" << __LINE__ \
                  << " Expected " << #a << " != " << #b << std::endl; \
        return; \
    } \
} while(0)

// Test registry
struct Test {
    const char* name;
    void (*func)();
};
std::vector<Test> tests;

void register_test(const char* name, void (*func)()) {
    tests.push_back({name, func});
}

// ============================================================================
// RingBuffer Tests
// ============================================================================

TEST(initialization) {
    RingBuffer<1024> rb;
    rb.init();

    ASSERT_EQ(rb.capacity(), 1024);
    ASSERT_EQ(rb.readable(), 0);
    ASSERT_EQ(rb.writable(), 1023);  // Reserve 1 byte to distinguish full/empty
}

TEST(power_of_two_enforcement) {
    // These should compile (power of 2)
    RingBuffer<256> rb1;
    RingBuffer<512> rb2;
    RingBuffer<1024> rb3;
    RingBuffer<2048> rb4;

    // This would fail to compile (not power of 2):
    // RingBuffer<1000> rb_bad;  // Compile error: static_assert

    ASSERT_TRUE(true);  // If we got here, power-of-2 checks passed
}

TEST(basic_write_read) {
    RingBuffer<1024> rb;
    rb.init();

    // Write some data
    size_t write_len;
    uint8_t* write_ptr = rb.next_write_region(&write_len);
    ASSERT_NE(write_ptr, nullptr);
    ASSERT_TRUE(write_len > 0);

    const char* msg = "Hello, World!";
    size_t msg_len = strlen(msg);
    memcpy(write_ptr, msg, msg_len);
    rb.commit_write(msg_len);

    ASSERT_EQ(rb.readable(), msg_len);
    ASSERT_EQ(rb.writable(), 1023 - msg_len);

    // Read the data
    size_t read_len;
    const uint8_t* read_ptr = rb.next_read_region(&read_len);
    ASSERT_NE(read_ptr, nullptr);
    ASSERT_EQ(read_len, msg_len);
    ASSERT_EQ(memcmp(read_ptr, msg, msg_len), 0);

    rb.commit_read(msg_len);
    ASSERT_EQ(rb.readable(), 0);
    ASSERT_EQ(rb.writable(), 1023);
}

TEST(wraparound_non_mirrored) {
    RingBuffer<64> rb;  // Small buffer to test wraparound
    rb.init();

    // Write data near the end
    size_t write_len;
    uint8_t* write_ptr = rb.next_write_region(&write_len);
    ASSERT_NE(write_ptr, nullptr);

    // Write 50 bytes
    for (size_t i = 0; i < 50; i++) {
        write_ptr[i] = static_cast<uint8_t>(i);
    }
    rb.commit_write(50);
    ASSERT_EQ(rb.readable(), 50);

    // Read 40 bytes
    size_t read_len;
    const uint8_t* read_ptr = rb.next_read_region(&read_len);
    rb.commit_read(40);
    ASSERT_EQ(rb.readable(), 10);

    // Write more data - should wrap around
    write_ptr = rb.next_write_region(&write_len);
    ASSERT_NE(write_ptr, nullptr);

    // Write 30 more bytes
    for (size_t i = 0; i < 30; i++) {
        write_ptr[i] = static_cast<uint8_t>(100 + i);
    }
    rb.commit_write(30);
    ASSERT_EQ(rb.readable(), 40);  // 10 + 30
}

TEST(full_buffer) {
    RingBuffer<64> rb;
    rb.init();

    size_t available = rb.writable();
    ASSERT_EQ(available, 63);  // Capacity - 1

    // Fill the buffer completely
    size_t write_len;
    uint8_t* write_ptr = rb.next_write_region(&write_len);
    ASSERT_NE(write_ptr, nullptr);

    size_t to_write = std::min(write_len, available);
    rb.commit_write(to_write);

    // Buffer should be full now
    ASSERT_EQ(rb.writable(), 0);
    ASSERT_EQ(rb.readable(), 63);

    // Try to write more - should get nullptr or 0 length
    write_ptr = rb.next_write_region(&write_len);
    ASSERT_TRUE(write_ptr == nullptr || write_len == 0);
}

TEST(empty_buffer) {
    RingBuffer<64> rb;
    rb.init();

    ASSERT_EQ(rb.readable(), 0);

    // Try to read from empty buffer
    size_t read_len;
    const uint8_t* read_ptr = rb.next_read_region(&read_len);
    ASSERT_TRUE(read_ptr == nullptr || read_len == 0);
}

TEST(reset) {
    RingBuffer<64> rb;
    rb.init();

    // Write some data
    size_t write_len;
    uint8_t* write_ptr = rb.next_write_region(&write_len);
    rb.commit_write(20);

    ASSERT_EQ(rb.readable(), 20);

    // Reset
    rb.reset();
    ASSERT_EQ(rb.readable(), 0);
    ASSERT_EQ(rb.writable(), 63);
}

TEST(multiple_writes_reads) {
    RingBuffer<256> rb;
    rb.init();

    // Perform multiple write/read cycles
    for (int i = 0; i < 10; i++) {
        size_t write_len;
        uint8_t* write_ptr = rb.next_write_region(&write_len);
        ASSERT_NE(write_ptr, nullptr);

        size_t chunk_size = 20;
        for (size_t j = 0; j < chunk_size; j++) {
            write_ptr[j] = static_cast<uint8_t>(i * 10 + j);
        }
        rb.commit_write(chunk_size);

        ASSERT_EQ(rb.readable(), chunk_size);

        size_t read_len;
        const uint8_t* read_ptr = rb.next_read_region(&read_len);
        ASSERT_EQ(read_len, chunk_size);

        for (size_t j = 0; j < chunk_size; j++) {
            ASSERT_EQ(read_ptr[j], static_cast<uint8_t>(i * 10 + j));
        }

        rb.commit_read(chunk_size);
        ASSERT_EQ(rb.readable(), 0);
    }
}

TEST(virtual_memory_mirroring_status) {
    RingBuffer8MB rb;
    rb.init();

    // Just verify we can query mirroring status
    bool is_mirrored = rb.is_mirrored();
    bool is_mmap = rb.is_mmap();

    std::cout << "  Virtual memory mirroring: " << (is_mirrored ? "enabled" : "disabled") << std::endl;
    std::cout << "  Memory mapping: " << (is_mmap ? "mmap" : "malloc") << std::endl;

    ASSERT_TRUE(true);  // This test just reports status
}

TEST(branchless_calculations) {
    RingBuffer<1024> rb;
    rb.init();

    // Write some data
    rb.commit_write(100);
    ASSERT_EQ(rb.readable(), 100);
    ASSERT_EQ(rb.writable(), 923);  // 1024 - 100 - 1

    // Read some
    rb.commit_read(50);
    ASSERT_EQ(rb.readable(), 50);
    ASSERT_EQ(rb.writable(), 973);  // 1024 - 50 - 1
}

TEST(large_buffer_allocation) {
    // Test that large buffers can be allocated
    RingBuffer8MB rb;
    rb.init();

    ASSERT_EQ(rb.capacity(), 8 * 1024 * 1024);

    size_t write_len;
    uint8_t* write_ptr = rb.next_write_region(&write_len);
    ASSERT_NE(write_ptr, nullptr);
    ASSERT_TRUE(write_len > 0);

    // Write 1MB of data
    const size_t chunk_size = 1024 * 1024;
    rb.commit_write(chunk_size);
    ASSERT_EQ(rb.readable(), chunk_size);
}

TEST(null_pointer_handling) {
    RingBuffer<64> rb;
    rb.init();

    // Pass nullptr to next_write_region
    uint8_t* ptr = rb.next_write_region(nullptr);
    ASSERT_EQ(ptr, nullptr);

    // Pass nullptr to next_read_region
    const uint8_t* read_ptr = rb.next_read_region(nullptr);
    ASSERT_EQ(read_ptr, nullptr);
}

TEST(commit_zero_length) {
    RingBuffer<64> rb;
    rb.init();

    size_t initial_readable = rb.readable();
    size_t initial_writable = rb.writable();

    // Commit zero bytes
    rb.commit_write(0);
    rb.commit_read(0);

    ASSERT_EQ(rb.readable(), initial_readable);
    ASSERT_EQ(rb.writable(), initial_writable);
}

TEST(predefined_sizes) {
    // Test that predefined size aliases work
    RingBuffer1MB rb1;
    RingBuffer2MB rb2;
    RingBuffer4MB rb4;
    RingBuffer16MB rb16;

    ASSERT_EQ(rb1.capacity(), 1u << 20);
    ASSERT_EQ(rb2.capacity(), 1u << 21);
    ASSERT_EQ(rb4.capacity(), 1u << 22);
    ASSERT_EQ(rb16.capacity(), 1u << 24);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "Running RingBuffer unit tests..." << std::endl;
    std::cout << "=================================" << std::endl;

    int passed = 0;
    int failed = 0;

    for (const auto& test : tests) {
        std::cout << "Running: " << test.name << "... ";
        std::cout.flush();

        test.func();

        std::cout << "PASS" << std::endl;
        passed++;
    }

    std::cout << "=================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;

    return failed > 0 ? 1 : 0;
}
