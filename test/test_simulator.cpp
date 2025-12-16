// test/test_simulator.cpp
// WebSocket traffic simulator - replays debug_traffic.dat through real frame parser
//
// Build: make test-simulator
// Usage: ./build/test_simulator [debug_traffic.dat]
//
// Replays recorded SSL traffic through the actual WebSocket frame parser
// to detect parsing bugs, frame misalignment, and other issues.

#include "../src/ws_configs.hpp"
#include <cstdio>
#include <algorithm>

int main(int argc, char* argv[]) {
    const char* file = argc > 1 ? argv[1] : "debug_traffic.dat";

    printf("=== WebSocket Traffic Simulator ===\n");
    printf("Input: %s\n\n", file);

    // Use pre-configured SimulatorReplayClient from ws_configs.hpp
    SimulatorReplayClient client;

    // Open traffic file
    if (!client.transport().open_file(file)) {
        fprintf(stderr, "Failed to open traffic file: %s\n", file);
        fprintf(stderr, "\nTo create a traffic file:\n");
        fprintf(stderr, "  1. Build with DEBUG: make DEBUG=1\n");
        fprintf(stderr, "  2. Run client (records to debug_traffic.dat)\n");
        return 1;
    }

    // Set up message callback to count and display messages
    uint64_t callback_count = 0;
    uint64_t total_bytes = 0;
    client.set_message_callback([&](const MessageInfo* msgs, size_t count, const timing_record_t&) {
        for (size_t i = 0; i < count; i++) {
            callback_count++;
            total_bytes += msgs[i].len;
            // Show first few bytes of each message for verification
            if (callback_count <= 10 && msgs[i].len > 0 && msgs[i].payload != nullptr) {
                size_t show_len = std::min(msgs[i].len, size_t(60));
                printf("[MSG#%lu] op=%02x len=%zu: %.*s%s\n",
                       callback_count, msgs[i].opcode, msgs[i].len,
                       (int)show_len, reinterpret_cast<const char*>(msgs[i].payload),
                       msgs[i].len > 60 ? "..." : "");
                fflush(stdout);
            }
        }
        return true;
    });

    // Connect and run (SimulatorTransport handles connect as no-op)
    client.connect("", 0, "");
    client.run(nullptr);

    printf("\n=== Replay Statistics ===\n");
    printf("Messages:  %lu\n", callback_count);
    printf("Bytes:     %lu\n", total_bytes);
    printf("RX count:  %lu\n", client.transport().rx_count());
    printf("TX count:  %lu\n", client.transport().tx_count());

    return 0;
}
