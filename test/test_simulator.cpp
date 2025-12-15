// test/test_simulator.cpp
// WebSocket traffic simulator using ACTUAL process_frames() code
//
// Build: make test-simulator
// Usage: ./build/test_simulator [debug_traffic.dat]
//
// This replays recorded SSL traffic through the real WebSocket frame parser
// to detect parsing bugs, frame misalignment, and other issues.
//
// Key difference from traffic_simulator.cpp:
// - Uses actual process_frames() from websocket.hpp (with SIMULATOR_MODE guards)
// - Same parsing logic as production code
// - Zero runtime overhead in production builds

// SIMULATOR_MODE is defined via -DSIMULATOR_MODE in Makefile
#include "../src/websocket.hpp"

// Minimal policy stubs for simulator mode
// These are never used because SIMULATOR_MODE skips their initialization
struct NoOpSSL {
    void init() {}
    ssize_t read(void*, size_t) { return 0; }
    ssize_t write(const void*, size_t) { return 0; }
    int pending() { return 0; }
};

struct NoOpTransport {
    void init() {}
    void connect(const char*, uint16_t) {}
    int wait() { return 0; }
    int get_fd() { return -1; }
};

struct NoOpBuffer {
    static constexpr bool is_hftshm = false;
    static constexpr bool is_shm_ringbuffer = false;

    void init() {}
    void init(const char*) {}
    uint8_t* data() { return nullptr; }
    uint8_t* buffer_base() { return nullptr; }
    size_t capacity() { return 0; }
    size_t buffer_capacity() { return 0; }
    size_t writable() { return 0; }
    void commit_write(size_t) {}
    void reset() {}
};

using SimClient = WebSocketClient<NoOpSSL, NoOpTransport, NoOpBuffer, NoOpBuffer>;

int main(int argc, char* argv[]) {
    const char* file = argc > 1 ? argv[1] : "debug_traffic.dat";

    printf("=== WebSocket Traffic Simulator (using ACTUAL process_frames) ===\n");
    printf("Input: %s\n\n", file);

    SimClient client;

    // Set up message callback to count and optionally display messages
    uint64_t callback_count = 0;
    client.set_message_callback([&callback_count](const MessageInfo* msgs, size_t count, const timing_record_t&) {
        for (size_t i = 0; i < count; i++) {
            callback_count++;
            // Show first few bytes of each message for verification
            if (msgs[i].len > 0 && msgs[i].payload != nullptr) {
                size_t show_len = std::min(msgs[i].len, size_t(60));
                printf("[MSG#%lu] op=%02x len=%zu: %.*s%s\n",
                       callback_count, msgs[i].opcode, msgs[i].len,
                       (int)show_len, reinterpret_cast<const char*>(msgs[i].payload),
                       msgs[i].len > 60 ? "..." : "");
            }
        }
        return true;
    });

    // Run the simulator
    bool success = client.run_simulator(file);

    printf("\n=== Callback Statistics ===\n");
    printf("Messages received via callback: %lu\n", callback_count);

    return success ? 0 : 1;
}
