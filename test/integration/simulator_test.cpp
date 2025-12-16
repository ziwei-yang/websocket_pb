// test/integration/simulator_test.cpp
// Simulator Replay Test - replays recorded traffic from debug_traffic.dat
//
// Build: make test-simulator
// Prerequisites: A debug_traffic.dat file recorded with enable_debug_traffic()
//
// Usage:
//   ./build/simulator_test [traffic_file]  # Default: debug_traffic.dat
//
// Example workflow:
//   1. Run with DEBUG build: ./build/binance_txrx (records to debug_traffic.dat)
//   2. Run simulator: ./build/simulator_test
//

#include "../../src/ws_configs.hpp"
#include <cstdio>
#include <cstring>

int main(int argc, char* argv[]) {
    const char* traffic_file = "debug_traffic.dat";
    if (argc > 1) {
        traffic_file = argv[1];
    }

    printf("=== Simulator Replay Test ===\n");
    printf("Traffic file: %s\n\n", traffic_file);

    // Create simulator replay client
    SimulatorReplayClient client;

    // Open traffic file
    if (!client.transport().open_file(traffic_file)) {
        fprintf(stderr, "Failed to open traffic file: %s\n", traffic_file);
        fprintf(stderr, "\nTo create a traffic file:\n");
        fprintf(stderr, "  1. Build with DEBUG: make DEBUG=1\n");
        fprintf(stderr, "  2. Run client with enable_debug_traffic() called\n");
        fprintf(stderr, "  3. Traffic is recorded to debug_traffic.dat\n");
        return 1;
    }

    // Stats
    size_t total_messages = 0;
    size_t total_batches = 0;
    size_t total_bytes = 0;

    // Set message callback
    client.set_message_callback([&](const MessageInfo* msgs, size_t count, const timing_record_t&) -> bool {
        total_batches++;
        for (size_t i = 0; i < count; i++) {
            total_messages++;
            total_bytes += msgs[i].len;

            // Print first few messages
            if (total_messages <= 5) {
                printf("Message %zu: opcode=%d len=%zu\n", total_messages, msgs[i].opcode, (size_t)msgs[i].len);
                if (msgs[i].len > 0 && msgs[i].len < 200) {
                    printf("  Payload: %.*s\n", (int)msgs[i].len, (const char*)msgs[i].payload);
                } else if (msgs[i].len >= 200) {
                    printf("  Payload (truncated): %.100s...\n", (const char*)msgs[i].payload);
                }
            }
        }
        return true;  // Continue processing
    });

    // "Connect" - just sets connected state (no real connection)
    client.connect("", 0, "");

    printf("Starting replay...\n\n");

    // Run the replay - processes all recorded traffic
    client.run(nullptr);

    printf("\n=== Replay Complete ===\n");
    printf("Batches:  %zu\n", total_batches);
    printf("Messages: %zu\n", total_messages);
    printf("Bytes:    %zu\n", total_bytes);
    printf("RX count: %lu\n", client.transport().rx_count());
    printf("TX count: %lu\n", client.transport().tx_count());

    return 0;
}
