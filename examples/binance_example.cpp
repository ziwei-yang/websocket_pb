// examples/binance_example.cpp
// Example: Connect to Binance WebSocket and receive market data
#include "../src/ws_configs.hpp"
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <ctime>

// Global flag for graceful shutdown
volatile bool running = true;

void signal_handler(int signum) {
    printf("\n📊 Received signal %d, shutting down...\n", signum);
    running = false;
}

// Simple JSON parser to extract trade price (for demonstration)
double extract_price(const uint8_t* json, size_t len) {
    // Look for "p":"123.45" pattern
    const char* str = reinterpret_cast<const char*>(json);
    const char* price_key = strstr(str, "\"p\":\"");

    if (price_key) {
        price_key += 5;  // Skip past "p":"
        return atof(price_key);
    }

    return 0.0;
}

int main() {
    // Install signal handler for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("🚀 WebSocket Policy-Based Design Example\n");
    printf("==========================================\n");

    // Display configuration being used
    #ifdef __linux__
        printf("📦 Configuration: LinuxOptimized\n");
        printf("   - Socket: BSD socket API\n");
        printf("   - SSL: OpenSSL with kTLS support\n");
        printf("   - Event: epoll (edge-triggered)\n");
        printf("   - Buffer: 8MB ring buffer\n");
    #elif defined(__APPLE__)
        printf("📦 Configuration: MacOSDefault\n");
        printf("   - Socket: BSD socket API\n");
        printf("   - SSL: OpenSSL\n");
        printf("   - Event: kqueue\n");
        printf("   - Buffer: 8MB ring buffer\n");
    #endif
    printf("\n");

    try {
        // Instantiate WebSocket client with default configuration
        DefaultWebSocket client;

        // Connect to Binance WebSocket
        printf("🔌 Connecting to Binance WebSocket...\n");
        client.connect(
            "stream.binance.com",
            443,
            "/stream?streams=btcusdt@trade"
        );

        printf("✅ Connected! Receiving market data...\n\n");

        // Message counter and timing
        uint64_t msg_count = 0;
        time_t start_time = time(nullptr);
        double last_price = 0.0;

        // Run event loop with message callback
        client.run([&](const uint8_t* data, size_t len, const timing_record_t& timing) {
            // Zero-copy access to message data
            // timing parameter contains latency information (ignored in this example)
            (void)timing;  // Suppress unused parameter warning
            msg_count++;

            // Extract price from JSON (simple parsing)
            double price = extract_price(data, len);

            if (price > 0.0 && price != last_price) {
                printf("💰 BTC/USDT: $%.2f  (msg #%lu)\n", price, msg_count);
                last_price = price;
            }

            // Display raw JSON every 100 messages
            if (msg_count % 100 == 0) {
                time_t elapsed = time(nullptr) - start_time;
                double msg_per_sec = (double)msg_count / elapsed;

                printf("\n📈 Statistics:\n");
                printf("   Messages: %lu\n", msg_count);
                printf("   Elapsed: %ld seconds\n", elapsed);
                printf("   Rate: %.2f msg/sec\n", msg_per_sec);
                printf("\n");
            }

            // Stop after receiving 1000 messages (for demo)
            if (msg_count >= 1000) {
                running = false;
            }

            if (!running) {
                // Trigger disconnect
                throw std::runtime_error("User requested shutdown");
            }
        });

        // Final statistics
        time_t total_time = time(nullptr) - start_time;
        printf("\n📊 Final Statistics:\n");
        printf("   Total messages: %lu\n", msg_count);
        printf("   Total time: %ld seconds\n", total_time);
        printf("   Average rate: %.2f msg/sec\n", (double)msg_count / total_time);

    } catch (const std::exception& e) {
        printf("\n❌ Error: %s\n", e.what());
        return 1;
    }

    printf("\n✅ Disconnected gracefully\n");
    return 0;
}
