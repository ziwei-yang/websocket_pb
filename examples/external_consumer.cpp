// examples/external_consumer.cpp
// Minimal example for external process to consume WebSocket RX shared memory
//
// This demonstrates how to use the exported headers from an external project
// that only has access to the websocket_txrx headers (not the full websocket_pb library).
//
// Prerequisites:
//   - hft-shm init --config ~/hft.toml (creates shared memory files)
//   - A WebSocket producer writing to the RX buffer (e.g., binance_txrx -m ws_client)
//
// Build (standalone):
//   g++ -std=c++20 -O2 \
//       -I../export/headers \
//       -I~/Proj/01_shared_headers \
//       external_consumer.cpp \
//       -o external_consumer
//
// Usage:
//   ./external_consumer                                          # Default path
//   ./external_consumer /dev/shm/hft/custom.mktdata.binance.raw.rx  # Custom path
//

#include <websocket_txrx/rx_consumer.hpp>
#include <cstdio>
#include <csignal>
#include <unistd.h>

// Default shared memory path (hft-shm segment: test.mktdata.binance.raw.rx)
static const char* DEFAULT_RX_SHM_PATH = "/dev/shm/hft/test.mktdata.binance.raw.rx";

volatile bool running = true;

void signal_handler(int) {
    printf("\nShutting down...\n");
    running = false;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    const char* rx_path = (argc > 1) ? argv[1] : DEFAULT_RX_SHM_PATH;

    printf("=== External RX Consumer Example ===\n");
    printf("Path: %s\n\n", rx_path);

    RXRingBufferConsumer consumer;

    try {
        consumer.init(rx_path);
        printf("Connected to shared memory!\n\n");
    } catch (const std::exception& e) {
        printf("Failed to init consumer: %s\n", e.what());
        printf("Make sure hft-shm is initialized and producer is running.\n");
        return 1;
    }

    int total_batches = 0;
    int total_messages = 0;

    // Set message callback
    consumer.set_on_messages([&](const ShmBatchHeader* hdr, const ShmMessageInfo* msgs) {
        // Handle connection status events (empty batches)
        if (hdr->is_status_only()) {
            if (hdr->is_connected()) {
                printf("[STATUS] Connection established (reconnect=%d)\n",
                       hdr->is_reconnect_enabled());
                // TODO: If you need to send subscription messages,
                // write them to the TX shared memory buffer here
            } else {
                printf("[STATUS] Disconnected\n");
            }
            return;
        }

        total_batches++;

        // Print batch info
        printf("Batch[%d] frames=%u text=%d cpucycle=%lu\n",
               total_batches, hdr->frame_count, hdr->is_text(), hdr->cpucycle);

        // Process each message in the batch
        for (uint16_t i = 0; i < hdr->frame_count; i++) {
            total_messages++;

            // Resolve payload pointer from offset
            const uint8_t* payload = consumer.resolve_payload(msgs[i]);
            int32_t len = msgs[i].len;

            // Print payload (truncated for readability)
            if (len > 100) {
                // Print first 60 chars + "..." + last 30 chars
                printf("  [%d] len=%d: %.60s ... %.*s\n",
                       i, len, payload, 30, payload + len - 30);
            } else if (len > 0) {
                printf("  [%d] len=%d: %.*s\n", i, len, len, payload);
            } else {
                printf("  [%d] len=%d: (empty)\n", i, len);
            }
        }
        printf("\n");
    });

    printf("Polling for messages... (Ctrl+C to stop)\n\n");

    // Poll loop with periodic stats
    int poll_count = 0;
    while (running) {
        consumer.poll();

        // Print buffer stats every ~2 seconds (2000 polls at 1ms interval)
        if (++poll_count >= 2000) {
            poll_count = 0;
            printf("--- Stats: batches=%d messages=%d buffer: %.1fKB/%.1fKB ---\n",
                   total_batches, total_messages,
                   consumer.current_read_pos() / 1024.0,
                   consumer.capacity() / 1024.0);
        }

        usleep(1000);  // 1ms poll interval
    }

    printf("\nStopped: %d batches, %d messages\n", total_batches, total_messages);
    return 0;
}
