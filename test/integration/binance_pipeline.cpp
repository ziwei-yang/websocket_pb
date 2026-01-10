// test/integration/binance_pipeline.cpp
// Integration test for AF_XDP WebSocket pipeline
// Connects to Binance stream and receives market data
//
// Usage: sudo taskset -c 8 ./build/binance_pipeline [interface]
//
// Before running:
// 1. ./scripts/xdp_prepare.sh $interface
// 2. Update /etc/hosts with latest DNS for stream.binance.com
// 3. ./scripts/nic_local_clock_sync.sh (non-AWS)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <unistd.h>

#ifdef USE_XDP
#include "../../src/pipeline/pipeline.hpp"
#include "../../src/xdp/xdp_transport.hpp"
#endif

using namespace websocket::pipeline;

// ============================================================================
// Signal handling is done by the pipeline itself via detail::install_signal_handlers()
// All processes (parent + children) share tcp_state_->running which is set to 0 on signal
// ============================================================================

// ============================================================================
// BinanceTestHandler - User handler implementation
// ============================================================================

#ifdef USE_XDP

class BinanceTestHandler : public AppClientHandler<BinanceTestHandler,
                                                    MsgOutboxRing,
                                                    WSFrameInfoRing> {
public:
    using Base = AppClientHandler<BinanceTestHandler, MsgOutboxRing, WSFrameInfoRing>;

    // Message counter
    uint64_t message_count_ = 0;
    uint64_t total_bytes_ = 0;
    uint64_t start_time_ns_ = 0;

    // Called for each contiguous WebSocket message
    void on_message(const uint8_t* payload, uint32_t len, uint8_t opcode) {
        message_count_++;
        total_bytes_ += len;

        // Print all messages (for testing)
        printf("[MSG #%lu] opcode=%u len=%u\n", message_count_, opcode, len);

        if (opcode == WS_OP_TEXT && len < 300) {
            printf("  %.300s\n", reinterpret_cast<const char*>(payload));
        }

        // Stats every 100 messages
        if (message_count_ % 100 == 0) {
            print_stats();
        }
    }

    // Called when payload wraps around MSG_INBOX boundary (rare)
    void on_message_wrapped(const uint8_t* seg1, uint32_t len1,
                            const uint8_t* seg2, uint32_t len2, uint8_t opcode) {
        message_count_++;
        total_bytes_ += len1 + len2;

        printf("[MSG-WRAPPED #%lu] opcode=%u len=%u+%u\n",
               message_count_, opcode, len1, len2);
    }

    // Called for fragmented messages
    void on_fragmented_message(const WSFrameInfo& info) {
        message_count_++;

        printf("[MSG-FRAGMENTED #%lu] opcode=%u total_len=%u\n",
               message_count_, info.opcode, info.frame_total_len);
    }

    void print_stats() {
        uint64_t now = get_monotonic_timestamp_ns();
        if (start_time_ns_ == 0) {
            start_time_ns_ = now;
            return;
        }

        double elapsed_s = (now - start_time_ns_) / 1e9;
        double msg_rate = message_count_ / elapsed_s;
        double byte_rate = total_bytes_ / elapsed_s / 1024;

        printf("\n=== Stats ===\n");
        printf("Messages:    %lu\n", message_count_);
        printf("Total bytes: %lu\n", total_bytes_);
        printf("Elapsed:     %.2f s\n", elapsed_s);
        printf("Msg rate:    %.1f msg/s\n", msg_rate);
        printf("Data rate:   %.2f KB/s\n", byte_rate);
        printf("=============\n\n");
    }
};

#endif  // USE_XDP

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
#ifndef USE_XDP
    fprintf(stderr, "Error: Build with USE_XDP=1\n");
    return 1;
#else

    // Parse arguments
    const char* interface = "enp108s0";
    if (argc > 1) {
        interface = argv[1];
    }

    printf("=== Binance Pipeline Integration Test ===\n");
    printf("Interface: %s\n", interface);
    printf("Target:    stream.binance.com:443/stream\n");
    printf("\n");

    // Signal handlers are installed by pipeline.start() via detail::install_signal_handlers()

    // Configure pipeline
    WebSocketConfig config;
    config.interface = interface;
    config.host = "stream.binance.com";
    config.port = 443;
    config.path = "/stream";
    config.cpu_cores[0] = 2;  // XDP Poll
    config.cpu_cores[1] = 4;  // Transport
    config.cpu_cores[2] = 6;  // WebSocket
    config.cpu_cores[3] = 8;  // AppClient

    // Create pipeline
    WebSocketClientPipeline pipeline;

    // Setup (TCP + TLS + WS handshake)
    printf("[MAIN] Setting up pipeline...\n");
    if (!pipeline.setup(config)) {
        fprintf(stderr, "[MAIN] Pipeline setup failed\n");
        return 1;
    }

    // Subscribe to streams - multiple high-traffic pairs
    const char* subscribe_msg = R"({"method":"SUBSCRIBE","params":["btcusdt@aggTrade","ethusdt@aggTrade","solusdt@aggTrade","xrpusdt@aggTrade","dogeusdt@aggTrade","btcusdt@trade","ethusdt@trade","btcusdt@depth@100ms"],"id":1})";

    printf("[MAIN] Subscribing to streams...\n");
    if (!pipeline.subscribe(subscribe_msg)) {
        fprintf(stderr, "[MAIN] Subscription failed\n");
        pipeline.cleanup();
        return 1;
    }

    // Instead of multi-process pipeline (which has stub processes),
    // do single-process SSL_read loop to verify message reception
    printf("[MAIN] Starting single-process message loop (Ctrl+C to stop)...\n");
    printf("\n");

    // Set running flag (normally done by fork_processes)
    pipeline.manager().tcp_state()->running.store(1, std::memory_order_release);

    // Install signal handler for parent process
    detail::install_signal_handlers(pipeline.manager().tcp_state());

    BinanceTestHandler handler;
    handler.start_time_ns_ = get_monotonic_timestamp_ns();

    // Get SSL and BIO handles
    PL_SSL* ssl = pipeline.manager().ssl();
    PL_BIO* bio_in = pipeline.manager().bio_in();
    auto& xdp_transport = pipeline.manager().xdp_transport();

    uint8_t net_buf[8192];
    uint8_t ssl_buf[8192];
    uint8_t ws_buf[65536];
    size_t ws_buf_len = 0;

    uint64_t last_recv_time = get_monotonic_timestamp_ns();
    uint64_t total_raw_bytes = 0;
    uint64_t last_status_time = last_recv_time;

    while (pipeline.manager().tcp_state()->running.load(std::memory_order_acquire)) {
        // Step 1: Receive from XDP transport and feed to SSL BIO
        // Always try to read existing data from recv_buffer, not just when new packets arrive
        xdp_transport.set_wait_timeout(100);  // 100ms timeout
        xdp_transport.wait();  // Triggers poll and processes RX ring

        // Read ALL available data from recv_buffer and feed to BIO
        // Must loop because poll_rx_and_process() may add multiple frames
        ssize_t recv_len;
        int recv_count = 0;
        do {
            recv_len = xdp_transport.recv(net_buf, sizeof(net_buf));
            if (recv_len > 0) {
                PL_BIO_write(bio_in, net_buf, recv_len);
                total_raw_bytes += recv_len;
                last_recv_time = get_monotonic_timestamp_ns();
                recv_count++;
            } else if (recv_len < 0 && errno != EAGAIN) {
                printf("[DEBUG] recv returned %zd, errno=%d\n", recv_len, errno);
            }
        } while (recv_len > 0 && recv_count < 100);  // Limit iterations to prevent starvation

        // Periodic status (every 10 seconds)
        uint64_t now = get_monotonic_timestamp_ns();
        if (now - last_status_time > 10000000000ULL) {
            double idle_s = (now - last_recv_time) / 1e9;
            printf("[STATUS] raw=%lu msgs=%lu idle=%.1fs\n",
                   total_raw_bytes, handler.message_count_, idle_s);
            last_status_time = now;
        }

        // Step 2: Read decrypted data from SSL
        int ret = PL_SSL_read(ssl, ssl_buf, sizeof(ssl_buf));
        if (ret > 0) {
            // Accumulate in WS buffer
            if (ws_buf_len + ret <= sizeof(ws_buf)) {
                memcpy(ws_buf + ws_buf_len, ssl_buf, ret);
                ws_buf_len += ret;
            }

            // Parse WebSocket frames
            size_t consumed = 0;
            while (consumed < ws_buf_len) {
                uint8_t* frame = ws_buf + consumed;
                size_t remaining = ws_buf_len - consumed;

                if (remaining < 2) break;

                // Parse WS header
                bool fin = (frame[0] & 0x80) != 0;
                uint8_t opcode = frame[0] & 0x0F;
                bool masked = (frame[1] & 0x80) != 0;
                uint64_t payload_len = frame[1] & 0x7F;
                size_t header_len = 2;

                if (payload_len == 126) {
                    if (remaining < 4) break;
                    payload_len = (frame[2] << 8) | frame[3];
                    header_len = 4;
                } else if (payload_len == 127) {
                    if (remaining < 10) break;
                    payload_len = 0;
                    for (int i = 0; i < 8; i++) {
                        payload_len = (payload_len << 8) | frame[2 + i];
                    }
                    header_len = 10;
                }

                if (masked) header_len += 4;

                size_t frame_len = header_len + payload_len;
                if (remaining < frame_len) break;

                const uint8_t* payload = frame + header_len;

                // Handle different frame types
                if (opcode == 0x09) {
                    // PING - respond with PONG
                    printf("[WS] Received PING, sending PONG...\n");
                    uint8_t pong_frame[128];
                    size_t pong_len = 0;

                    // Build masked PONG frame (client must mask)
                    pong_frame[pong_len++] = 0x8A;  // FIN + PONG opcode
                    if (payload_len < 126) {
                        pong_frame[pong_len++] = 0x80 | payload_len;  // Masked + length
                    } else {
                        pong_frame[pong_len++] = 0x80 | 126;
                        pong_frame[pong_len++] = (payload_len >> 8) & 0xFF;
                        pong_frame[pong_len++] = payload_len & 0xFF;
                    }

                    // Add mask key (random)
                    uint32_t mask_key = 0x12345678;
                    memcpy(pong_frame + pong_len, &mask_key, 4);
                    pong_len += 4;

                    // Copy and mask payload
                    for (size_t i = 0; i < payload_len && pong_len < sizeof(pong_frame); i++) {
                        pong_frame[pong_len++] = payload[i] ^ ((mask_key >> ((i % 4) * 8)) & 0xFF);
                    }

                    // Send via SSL
                    int written = PL_SSL_write(ssl, pong_frame, pong_len);
                    if (written > 0) {
                        // Flush SSL output to BIO
                        PL_BIO* bio_out = pipeline.manager().bio_out();
                        char out_buf[4096];
                        int pending;
                        while ((pending = PL_BIO_read(bio_out, out_buf, sizeof(out_buf))) > 0) {
                            xdp_transport.send(reinterpret_cast<uint8_t*>(out_buf), pending);
                        }
                        printf("[WS] PONG sent (%zu bytes)\n", pong_len);
                    }
                } else if (opcode == 0x08) {
                    // CLOSE frame
                    printf("[WS] Received CLOSE frame\n");
                    pipeline.manager().tcp_state()->running.store(0, std::memory_order_release);
                } else if (fin && (opcode == 0x01 || opcode == 0x02)) {
                    // TEXT or BINARY
                    handler.on_message(payload, payload_len, opcode);
                }

                consumed += frame_len;
            }

            // Shift remaining data
            if (consumed > 0 && consumed < ws_buf_len) {
                memmove(ws_buf, ws_buf + consumed, ws_buf_len - consumed);
            }
            ws_buf_len -= consumed;
        } else {
            int err = PL_SSL_get_error(ssl, ret);
            if (err != PL_SSL_ERROR_WANT_READ && err != PL_SSL_ERROR_WANT_WRITE) {
                printf("[MAIN] SSL error: %d\n", err);
                break;
            }
        }
    }

    // Cleanup
    printf("\n[MAIN] Cleaning up...\n");
    handler.print_stats();
    pipeline.cleanup();

    printf("[MAIN] Done\n");
    return 0;

#endif  // USE_XDP
}
