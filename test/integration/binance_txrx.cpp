// test/integration/binance_txrx.cpp
// WebSocket producer and shared memory consumer - can run as separate processes
//
// Build: make test-binance-shm
// Prerequisites: hft-shm init --config ~/hft.toml (creates shared memory files)
//
// Usage:
//   ./build/binance_txrx -m ws_client    # Producer: WebSocket → shm (default)
//   ./build/binance_txrx -m rx_consumer  # Consumer: shm → stdout
//
// Run both in separate terminals for true IPC testing.

#include "../../src/ws_configs.hpp"
#include "../../src/ringbuffer.hpp"
#include "../../src/rx_ringbuffer_consumer.hpp"
#include <csignal>
#include <cstdio>
#include <cstring>
#include <unistd.h>

// Shared memory path (hft-shm segment: test.mktdata.binance.raw.rx)
static const char* RX_SHM_PATH = "/dev/shm/hft/test.mktdata.binance.raw.rx";

volatile bool running = true;
void signal_handler(int) {
    printf("\nShutting down...\n");
    running = false;
}

// ============================================================================
// Consumer Mode: Read from RX shm using RXRingBufferConsumer
// ============================================================================
int run_consumer() {
    printf("[Consumer] Starting RX buffer reader...\n");
    printf("[Consumer] Path: %s\n\n", RX_SHM_PATH);

    RXRingBufferConsumer consumer;

    try {
        consumer.init(RX_SHM_PATH);
        printf("[Consumer] Connected!\n\n");
    } catch (const std::exception& e) {
        printf("[Consumer] Failed: %s\n", e.what());
        return 1;
    }

    int total_batches = 0;
    int total_messages = 0;

    // Set message callback - invoked for each batch of frames
    consumer.set_on_messages([&](const BatchInfo& batch, const MessageInfo* msgs, size_t n) {
        total_batches++;

        // Print batch header with sizes: Batch[N] Frames X [HDR Y][Data Z][TAIL W]
        printf("Batch[%d] Frames %u [HDR %zu][Data %zu][TAIL %zu]\n",
               total_batches, batch.frame_count,
               batch.hdr_size, batch.data_size, batch.tail_size);

        for (size_t i = 0; i < n; i++) {
            const char* payload = reinterpret_cast<const char*>(msgs[i].payload);
            uint32_t len = msgs[i].len;
            uint8_t opcode = msgs[i].opcode;

            total_messages++;

            // Print payload (truncated for readability)
            if (len > 80) {
                printf("    [%d] op=%d len=%u: %.60s .... %.20s\n",
                       total_messages, opcode, len,
                       payload, payload + len - 20);
            } else {
                printf("    [%d] op=%d len=%u: %.*s\n",
                       total_messages, opcode, len,
                       (int)len, payload);
            }
        }
    });

    // Poll loop with stats printing
    int poll_count = 0;
    while (running) {
        consumer.poll();

        // Print buffer stats every ~1 second (1000 polls at 1ms interval)
        if (++poll_count >= 1000) {
            poll_count = 0;
            // RX(capacity) write: X read: Y
            printf("RX(%zuKB) write: %.1fKB read: %.1fKB\n",
                   consumer.capacity() / 1024,
                   consumer.current_write_pos() / 1024.0,
                   consumer.current_read_pos() / 1024.0);
        }

        usleep(1000);  // 1ms poll interval
    }

    printf("[Consumer] Stopped: batch %d msg %d\n", total_batches, total_messages);
    return 0;
}

// ============================================================================
// Producer Mode: WebSocket client writes to RX shm
// ============================================================================

// Subscription message for Binance streams
static const char* g_subscribe = R"({"method":"SUBSCRIBE","params":["btcusdt@aggTrade","btcusdt@depth@100ms","btcusdt@depth@250ms","btcusdt@depth"],"id":1})";

int run_producer() {
    printf("[Producer] Starting WebSocket client...\n");
    printf("[Producer] Path: %s\n\n", RX_SHM_PATH);

    // Use ShmWebSocketClient with runtime path
    ShmWebSocketClient client(RX_SHM_PATH);

    // Set stop flag for graceful Ctrl+C handling
    client.set_stop_flag(&running);

    // Set on_connect callback to populate subscription messages
    client.set_on_connect([](char (*msgs)[512], size_t& count) {
        strcpy(msgs[0], g_subscribe);
        count = 1;
    });

    // Set on_close handler
    client.set_on_close([]() -> bool {
        printf("[Producer] Connection closed, will reconnect...\n");
        return false;  // Don't reconnect
    });

    printf("[Producer] Connecting to Binance...\n");
    try {
        client.connect("stream.binance.com", 443, "/stream");
        printf("[Producer] Connected!\n\n");
    } catch (const std::exception& e) {
        printf("[Producer] Failed: %s\n", e.what());
        return 1;
    }

    client.set_wait_timeout(100);

    printf("[Producer] Running event loop... (Ctrl+C to stop)\n\n");

    // Run without callback - data goes to RX shm
    client.run(nullptr);

    printf("[Producer] Stopped\n");
    return 0;
}

// ============================================================================
// Main: Parse arguments and run selected mode
// ============================================================================
void print_usage(const char* prog) {
    printf("Usage: %s [-m mode]\n", prog);
    printf("\n");
    printf("Modes:\n");
    printf("  ws_client   - WebSocket producer: Binance → shm (default)\n");
    printf("  rx_consumer - Shared memory consumer: shm → stdout\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                  # Run producer (default)\n", prog);
    printf("  %s -m ws_client     # Run producer\n", prog);
    printf("  %s -m rx_consumer   # Run consumer\n", prog);
    printf("\n");
    printf("For IPC testing, run producer and consumer in separate terminals.\n");
    printf("\n");
    printf("Prerequisites: hft-shm init --config ~/hft.toml\n");
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Default mode
    const char* mode = "ws_client";

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            mode = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            printf("Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    printf("=== Binance TX/RX via Shared Memory ===\n");
    printf("Mode: %s\n\n", mode);

    int result;
    if (strcmp(mode, "ws_client") == 0) {
        result = run_producer();
    } else if (strcmp(mode, "rx_consumer") == 0) {
        result = run_consumer();
    } else {
        printf("Unknown mode: %s\n", mode);
        print_usage(argv[0]);
        return 1;
    }

    printf("\n=== Done ===\n");
    return result;
}
