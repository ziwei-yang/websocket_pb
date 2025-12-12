// test/integration/binance_txrx.cpp
// Single executable - spawns consumer thread, main thread runs producer
//
// Build: USE_HFTSHM=1 USE_WOLFSSL=1 make test-binance-shm
// Prerequisites: hft-shm init --config test/shmem.toml
//
// Batch format in RX buffer (cache-line aligned, zero-copy design):
//   [ShmBatchHeader (CLS bytes)][raw_ssl_data padded (N*CLS)][ShmFrameDesc[] padded (M*CLS)]
// Consumer reads header, then uses frame descriptors to locate payloads.

#include "../../src/ws_configs.hpp"
#include "../../src/core/hftshm_ringbuffer.hpp"
#include <csignal>
#include <cstdio>
#include <cstring>
#include <thread>
#include <unistd.h>

volatile bool running = true;
void signal_handler(int) {
    printf("\nShutting down...\n");
    running = false;
}

#ifdef USE_HFTSHM

// Consumer thread: Read from RX shm, parse ShmBatchHeader entries
// Uses circular buffer access - data may wrap around buffer boundary
void consumer_thread() {
    printf("[Consumer] Starting RX buffer reader (circular mode)...\n");

    // Use Consumer role to READ from the RX buffer segment
    HftShmRingBuffer<"test.mktdata.binance.raw.rx", HftShmBufferRole::Consumer> rx;

    try {
        rx.init();
        printf("[Consumer] Connected to: test.mktdata.binance.raw.rx\n\n");
    } catch (const std::exception& e) {
        printf("[Consumer] Failed: %s\n", e.what());
        return;
    }

    int total_batches = 0;
    int total_messages = 0;
    size_t total_bytes = 0;

    while (running) {
        usleep(1000000);  // 1000ms poll interval

        // Print RX buffer stats
        size_t available = rx.readable();
        printf("RX(%zuKB) write: %.1fKB read: %.1fKB\n",
               rx.buffer_capacity() / 1024,
               rx.current_write_pos() / 1024.0,
               rx.current_read_pos() / 1024.0);

        if (available == 0) continue;

        // Get circular buffer info
        const uint8_t* buffer = rx.buffer_base();
        size_t capacity = rx.buffer_capacity();
        size_t read_pos = rx.current_read_pos();

        size_t offset = 0;  // Logical offset from read_pos
        size_t last_valid_offset = 0;
        int loop_count = 0;

        while (offset + sizeof(ShmBatchHeader) <= available) {
            // Read header from circular buffer
            ShmBatchHeader hdr;
            circular_read(buffer, capacity, (read_pos + offset) % capacity,
                          reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr));

            ++loop_count;  // Track iteration count

            // Validate batch header - stop process on failure for debugging
            // Valid ranges:
            // - ssl_data_len_in_CLS: 1-16384 (64B to 1MB of SSL data)
            // - frame_count: 1-255 (uint8_t, non-zero)
            const char* reject_reason = nullptr;
            if (hdr.ssl_data_len_in_CLS == 0) {
                reject_reason = "ssl_data_len_in_CLS=0 (no data)";
            } else if (hdr.frame_count == 0) {
                reject_reason = "frame_count=0 (no frames)";
            } else if (hdr.ssl_data_len_in_CLS > 16384) {
                reject_reason = "ssl_data_len_in_CLS>16384 (>1MB, likely corrupt)";
            } else if (hdr.frame_count > 255) {
                reject_reason = "frame_count>255 (exceeds uint8_t max)";
            }

            if (reject_reason) {
                printf("\n[CONSUMER REJECT] %s\n", reject_reason);
                printf("  Buffer state: capacity=%zuKB, write=%.1fKB, read=%.1fKB, available=%zu\n",
                       capacity / 1024, rx.current_write_pos() / 1024.0,
                       rx.current_read_pos() / 1024.0, available);
                printf("  Position: read_pos=%zu, offset=%zu, physical_pos=%zu\n",
                       read_pos, offset, (read_pos + offset) % capacity);
                printf("  Header: ssl_data_len_in_CLS=%u (%zuKB), frame_count=%u\n",
                       hdr.ssl_data_len_in_CLS, cls_to_bytes(hdr.ssl_data_len_in_CLS) / 1024,
                       hdr.frame_count);
                printf("  Stats so far: batches=%d, messages=%d, bytes=%zu\n",
                       total_batches, total_messages, total_bytes);
                printf("  Loop iteration: %d\n", loop_count);
                printf("\n[FATAL] Stopping process for debugging. Shared memory preserved.\n");
                printf("  Inspect with: hft-shm dump test.mktdata.binance.raw.rx\n\n");
                running = false;  // Stop producer thread too
                break;
            }

            // Calculate batch size (embedded descriptors in header, overflow after SSL data)
            size_t padded_ssl_len = cls_to_bytes(hdr.ssl_data_len_in_CLS);
            size_t overflow_size = overflow_descs_size(hdr.frame_count);
            size_t batch_size = sizeof(ShmBatchHeader) + padded_ssl_len + overflow_size;

            // Sanity check - stop on failure
            if (batch_size < sizeof(ShmBatchHeader) || batch_size > capacity) {
                printf("\n[CONSUMER REJECT] Invalid batch_size=%zu\n", batch_size);
                printf("  Constraints: sizeof(ShmBatchHeader)=%zu, capacity=%zu\n",
                       sizeof(ShmBatchHeader), capacity);
                printf("  Header: ssl_data_len_in_CLS=%u, frame_count=%u\n",
                       hdr.ssl_data_len_in_CLS, hdr.frame_count);
                printf("  Computed: padded_ssl=%zu, overflow=%zu\n",
                       padded_ssl_len, overflow_size);
                printf("  Position: read_pos=%zu, offset=%zu\n", read_pos, offset);
                printf("\n[FATAL] Stopping process for debugging.\n\n");
                running = false;
                break;
            }

            if (offset + batch_size > available) {
                break;  // Incomplete batch - wait for more data
            }

            total_batches++;

            // Print batch details
            printf("Batch[%d] Frames %u [HDR %zu][Data %zu][TAIL %zu]\n",
                   total_batches, hdr.frame_count,
                   sizeof(ShmBatchHeader), padded_ssl_len, overflow_size);

            // Read frame descriptors - first from embedded[], then overflow if needed
            ShmFrameDesc descs[255];  // Match MAX_FRAMES in websocket.hpp
            uint8_t embedded_count = std::min(hdr.frame_count, static_cast<uint8_t>(EMBEDDED_FRAMES));
            uint8_t overflow_count = overflow_frame_count(hdr.frame_count);

            // Copy embedded descriptors from header (already read via circular_read)
            memcpy(descs, hdr.embedded, embedded_count * sizeof(ShmFrameDesc));

            // Read overflow descriptors if any
            if (overflow_count > 0) {
                size_t overflow_pos = (read_pos + offset + sizeof(ShmBatchHeader) + padded_ssl_len) % capacity;
                circular_read(buffer, capacity, overflow_pos,
                              reinterpret_cast<uint8_t*>(descs + EMBEDDED_FRAMES),
                              overflow_count * sizeof(ShmFrameDesc));
            }

            // Process each frame
            size_t ssl_data_pos = (read_pos + offset + sizeof(ShmBatchHeader)) % capacity;
            for (uint16_t i = 0; i < hdr.frame_count; i++) {
                uint32_t payload_start = descs[i].payload_start;
                uint32_t len = descs[i].payload_len;

                // Bounds check (ssl_data_len_in_CLS * CLS gives max possible range)
                if (payload_start + len > padded_ssl_len) {
                    printf("\n[CONSUMER REJECT] Frame bounds error\n");
                    printf("  Frame %d/%u: payload_start=%u, len=%u, end=%u\n",
                           i, hdr.frame_count, payload_start, len, payload_start + len);
                    printf("  Constraint: padded_ssl_len=%zu (max valid offset)\n", padded_ssl_len);
                    printf("  Batch: ssl_data_len_in_CLS=%u, frame_count=%u\n",
                           hdr.ssl_data_len_in_CLS, hdr.frame_count);
                    printf("  Position: read_pos=%zu, offset=%zu\n", read_pos, offset);
                    printf("\n[FATAL] Stopping process for debugging.\n\n");
                    running = false;
                    break;
                }

                // Get payload from circular buffer (zero-copy, no temp buffer)
                size_t payload_pos = (ssl_data_pos + payload_start) % capacity;
                size_t to_end = capacity - payload_pos;

                const char* part1 = reinterpret_cast<const char*>(buffer + payload_pos);
                size_t part1_len = (len <= to_end) ? len : to_end;

                if (len <= to_end) {
                    // No wrap - single contiguous region
                    if (len > 80) {
                        printf("    [%d] op=%d len=%u: %.60s .... %.20s\n",
                               total_messages + 1, descs[i].opcode, len,
                               part1, part1 + len - 20);
                    } else {
                        printf("    [%d] op=%d len=%u: %.*s\n",
                               total_messages + 1, descs[i].opcode, len,
                               (int)len, part1);
                    }
                } else {
                    // Wrapped - print two parts directly, no buffer copy
                    const char* part2 = reinterpret_cast<const char*>(buffer);
                    size_t part2_len = len - to_end;

                    if (len > 80) {
                        // Show first 60 chars (may span both parts) + last 20 chars
                        if (part1_len >= 60) {
                            // First 60 chars all in part1
                            printf("    [%d] op=%d len=%u: %.60s .... ",
                                   total_messages + 1, descs[i].opcode, len, part1);
                        } else {
                            // First 60 chars spans both parts
                            printf("    [%d] op=%d len=%u: %.*s%.*s .... ",
                                   total_messages + 1, descs[i].opcode, len,
                                   (int)part1_len, part1,
                                   (int)(60 - part1_len), part2);
                        }
                        // Last 20 chars (always in part2 since payload is long)
                        if (part2_len >= 20) {
                            printf("%.20s\n", part2 + part2_len - 20);
                        } else {
                            printf("%.*s%.*s\n",
                                   (int)(20 - part2_len), part1 + part1_len - (20 - part2_len),
                                   (int)part2_len, part2);
                        }
                    } else {
                        // Short payload - print both parts
                        printf("    [%d] op=%d len=%u: %.*s%.*s\n",
                               total_messages + 1, descs[i].opcode, len,
                               (int)part1_len, part1,
                               (int)part2_len, part2);
                    }
                }
                total_messages++;
            }

            // Check if frame loop was aborted due to error
            if (!running) break;

            offset += batch_size;
            last_valid_offset = offset;
        }

        // Commit what we parsed
        if (last_valid_offset > 0) {
            rx.commit_read(last_valid_offset);
            total_bytes += last_valid_offset;
        }

        // Print stats every ~1 second
        static int print_counter = 0;
        if (++print_counter >= 1000) {
            print_counter = 0;
            printf("[Stats] batch %d msg %d bytes %zu, RX: Write(%.3fKB) Read(%.3fKB)\n",
                   total_batches, total_messages, total_bytes,
                   rx.current_write_pos() / 1024.0, rx.current_read_pos() / 1024.0);
        }
    }
    printf("[Consumer] Stopped: batch %d msg %d bytes %zu\n",
           total_batches, total_messages, total_bytes);
}

// Subscription message for Binance streams
static const char* g_subscribe = R"({"method":"SUBSCRIBE","params":["btcusdt@aggTrade","btcusdt@depth@100ms","btcusdt@depth@250ms","btcusdt@depth"],"id":1})";

// Producer: WebSocketClient connects to Binance, writes to RX shm
int run_producer() {
    TestShmClient client;

    // Set stop flag for graceful Ctrl+C handling
    client.set_stop_flag(&running);

    // Set on_connect callback to populate subscription messages
    // Called after connect() and after each reconnect
    client.set_on_connect([](char (*msgs)[512], size_t& count) {
        strcpy(msgs[0], g_subscribe);
        count = 1;
    });

    // Set on_close handler for automatic reconnection
    client.set_on_close([]() -> bool {
        printf("[Producer] Connection closed, will reconnect...\n");
        return false;  // Stop reconnect
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

    // Run without callback - data goes to RX shm with ShmMsgHeader format
    client.run(nullptr);

    return 0;
}

#endif // USE_HFTSHM

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("=== Binance TX/RX via HftShm ===\n\n");

#ifdef USE_HFTSHM
    // Spawn consumer thread first
    std::thread consumer(consumer_thread);

    // Give consumer time to initialize
    usleep(100000);  // 100ms

    // Main thread runs producer
    int result = run_producer();

    // Wait for consumer to finish
    running = false;
    consumer.join();

    printf("\n=== Test Complete ===\n");
    return result;
#else
    printf("ERROR: USE_HFTSHM not defined!\n");
    printf("Build with: USE_HFTSHM=1 USE_WOLFSSL=1 make test-binance-shm\n");
    return 1;
#endif
}
