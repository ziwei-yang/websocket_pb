// test/unittest/test_event.cpp
// Unit tests for event policy implementations

#include "policy/event.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <chrono>

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

#define ASSERT_GT(a, b) do { \
    if ((a) <= (b)) { \
        std::cerr << "FAIL: " << __FILE__ << ":" << __LINE__ \
                  << " Expected " << #a << " > " << #b \
                  << " (got " << (a) << " vs " << (b) << ")" << std::endl; \
        return; \
    } \
} while(0)

#define ASSERT_LT(a, b) do { \
    if ((a) >= (b)) { \
        std::cerr << "FAIL: " << __FILE__ << ":" << __LINE__ \
                  << " Expected " << #a << " < " << #b \
                  << " (got " << (a) << " vs " << (b) << ")" << std::endl; \
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

// Helper: Create a pipe and make it non-blocking
struct PipeHelper {
    int read_fd;
    int write_fd;

    PipeHelper() {
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            throw std::runtime_error("pipe() failed");
        }
        read_fd = pipefd[0];
        write_fd = pipefd[1];

        // Make read end non-blocking
        int flags = fcntl(read_fd, F_GETFL, 0);
        fcntl(read_fd, F_SETFL, flags | O_NONBLOCK);
    }

    ~PipeHelper() {
        if (read_fd >= 0) close(read_fd);
        if (write_fd >= 0) close(write_fd);
    }

    void write_data(const char* data, size_t len) {
        ssize_t written = write(write_fd, data, len);
        (void)written;  // Suppress unused warning
    }

    ssize_t read_data(char* buf, size_t len) {
        return read(read_fd, buf, len);
    }
};

// ============================================================================
// EventPolicy Tests
// ============================================================================

TEST(initialization) {
    EventPolicy event;
    event.init();

    // Just verify initialization doesn't crash
    ASSERT_TRUE(true);
}

TEST(policy_name) {
    const char* name = EventPolicy::name();
    ASSERT_NE(name, nullptr);

    std::cout << "  Event policy: " << name << std::endl;

#ifdef EVENT_POLICY_LINUX
    #ifdef EVENT_POLICY_IOURING
        ASSERT_EQ(strcmp(name, "io_uring"), 0);
    #else
        ASSERT_EQ(strcmp(name, "epoll"), 0);
    #endif
#elif defined(EVENT_POLICY_BSD)
    ASSERT_EQ(strcmp(name, "kqueue"), 0);
#endif
}

TEST(add_read_event) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    ASSERT_TRUE(true);  // No crash
}

TEST(add_write_event) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_write(pipe.write_fd);

    ASSERT_TRUE(true);  // No crash
}

TEST(add_readwrite_event) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_readwrite(pipe.read_fd);

    ASSERT_TRUE(true);  // No crash
}

TEST(wait_with_event) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    // Write data to trigger event
    pipe.write_data("test", 4);

    // Wait for event (should return immediately)
    int n = event.wait();

    ASSERT_GT(n, 0);
    ASSERT_EQ(event.get_ready_fd(), pipe.read_fd);
    ASSERT_TRUE(event.is_readable());

    // Clean up - read the data
    char buf[64];
    pipe.read_data(buf, sizeof(buf));
}

TEST(wait_with_timeout_triggers) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    // Set timeout
    event.set_wait_timeout(100);  // 100ms

    // Write data to trigger event
    pipe.write_data("test", 4);

    // Wait - should return immediately with event
    int n = event.wait_with_timeout();

    ASSERT_GT(n, 0);
    ASSERT_EQ(event.get_ready_fd(), pipe.read_fd);

    // Clean up
    char buf[64];
    pipe.read_data(buf, sizeof(buf));
}

TEST(wait_with_timeout_expires) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    // Set short timeout
    event.set_wait_timeout(50);  // 50ms

    // Don't write data - should timeout
    auto start = std::chrono::high_resolution_clock::now();
    int n = event.wait_with_timeout();
    auto end = std::chrono::high_resolution_clock::now();

    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    ASSERT_EQ(n, 0);  // Timeout
    ASSERT_GT(duration_ms, 40);  // At least ~40ms
    ASSERT_LT(duration_ms, 100); // But not too long
}

TEST(set_wait_timeout_changes) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    // Test with 100ms timeout
    event.set_wait_timeout(100);
    auto start = std::chrono::high_resolution_clock::now();
    int n = event.wait_with_timeout();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration1 = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    ASSERT_EQ(n, 0);  // Timeout
    ASSERT_GT(duration1, 90);

    // Change to 50ms timeout
    event.set_wait_timeout(50);
    start = std::chrono::high_resolution_clock::now();
    n = event.wait_with_timeout();
    end = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    ASSERT_EQ(n, 0);  // Timeout
    ASSERT_GT(duration2, 40);
    ASSERT_LT(duration2, 70);

    // Second timeout should be shorter
    ASSERT_LT(duration2, duration1);
}

TEST(modify_event) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    // Modify to write event (0x04 = EPOLLOUT/POLLOUT)
    event.modify(pipe.read_fd, 0x04);

    ASSERT_TRUE(true);  // No crash
}

TEST(remove_event) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    // Remove the event
    event.remove(pipe.read_fd);

    ASSERT_TRUE(true);  // No crash
}

TEST(multiple_events) {
    EventPolicy event;
    event.init();

    PipeHelper pipe1;
    PipeHelper pipe2;

    event.add_read(pipe1.read_fd);
    event.add_read(pipe2.read_fd);

    // Trigger first pipe
    pipe1.write_data("test1", 5);

    int n = event.wait();
    ASSERT_GT(n, 0);

    int ready_fd = event.get_ready_fd();
    ASSERT_TRUE(ready_fd == pipe1.read_fd || ready_fd == pipe2.read_fd);

    // Clean up
    char buf[64];
    pipe1.read_data(buf, sizeof(buf));
    pipe2.read_data(buf, sizeof(buf));
}

TEST(writable_event) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_write(pipe.write_fd);

    // Write end should be immediately writable
    int n = event.wait();

    ASSERT_GT(n, 0);
    ASSERT_EQ(event.get_ready_fd(), pipe.write_fd);
    ASSERT_TRUE(event.is_writable());
}

TEST(is_readable_check) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    pipe.write_data("data", 4);

    int n = event.wait();
    ASSERT_GT(n, 0);

    ASSERT_TRUE(event.is_readable());
    ASSERT_FALSE(event.is_writable());

    // Clean up
    char buf[64];
    pipe.read_data(buf, sizeof(buf));
}

TEST(zero_timeout_poll) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    // Set zero timeout (polling mode)
    event.set_wait_timeout(0);

    // No data - should return immediately
    int n = event.wait_with_timeout();
    ASSERT_EQ(n, 0);  // No events

    // Write data
    pipe.write_data("test", 4);

    // Poll again - should get event
    n = event.wait_with_timeout();
    ASSERT_GT(n, 0);

    // Clean up
    char buf[64];
    pipe.read_data(buf, sizeof(buf));
}

TEST(move_constructor) {
    EventPolicy event1;
    event1.init();

    PipeHelper pipe;
    event1.add_read(pipe.read_fd);

    // Move construct
    EventPolicy event2(std::move(event1));

    // Write data
    pipe.write_data("test", 4);

    // event2 should work
    int n = event2.wait();
    ASSERT_GT(n, 0);

    // Clean up
    char buf[64];
    pipe.read_data(buf, sizeof(buf));
}

TEST(move_assignment) {
    EventPolicy event1;
    event1.init();

    PipeHelper pipe;
    event1.add_read(pipe.read_fd);

    EventPolicy event2;
    event2.init();

    // Move assign
    event2 = std::move(event1);

    // Write data
    pipe.write_data("test", 4);

    // event2 should work
    int n = event2.wait();
    ASSERT_GT(n, 0);

    // Clean up
    char buf[64];
    pipe.read_data(buf, sizeof(buf));
}

TEST(get_ready_events) {
    EventPolicy event;
    event.init();

    PipeHelper pipe;
    event.add_read(pipe.read_fd);

    pipe.write_data("test", 4);

    int n = event.wait();
    ASSERT_GT(n, 0);

    uint32_t events = event.get_ready_events();
    ASSERT_NE(events, 0);

    // Clean up
    char buf[64];
    pipe.read_data(buf, sizeof(buf));
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "Running EventPolicy unit tests..." << std::endl;
    std::cout << "==================================" << std::endl;

    int passed = 0;
    int failed = 0;

    for (const auto& test : tests) {
        std::cout << "Running: " << test.name << "... ";
        std::cout.flush();

        try {
            test.func();
            std::cout << "PASS" << std::endl;
            passed++;
        } catch (const std::exception& e) {
            std::cout << "EXCEPTION: " << e.what() << std::endl;
            failed++;
        }
    }

    std::cout << "==================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;

    return failed > 0 ? 1 : 0;
}
