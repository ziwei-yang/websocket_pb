// test/integration/xdp_binance.cpp
// XDP + Userspace TCP + SSL + WebSocket Integration Test
//
// Policy-Based Design Architecture:
//   Application → TransportPolicy (XDPUserspaceTransport) → SSLPolicy → WebSocket
//
// This test validates complete kernel bypass using:
//   - AF_XDP zero-copy mode (XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP)
//   - Native driver mode (XDP_FLAGS_DRV_MODE)
//   - Userspace TCP/IP stack (complete kernel bypass)
//   - SSL/TLS over userspace TCP
//   - WebSocket protocol
//   - 6-stage latency breakdown with NIC hardware timestamps
//
// Target: wss://stream.binance.com:443/stream?streams=btcusdt@trade
//
// Polling Mode:
//   Uses userspace busy-polling with SO_BUSY_POLL for lowest latency.
//
// Zero-Copy TX Completion Workaround:
//   The igc driver (Intel I225/I226) has a TX completion stall bug in zero-copy
//   mode. TX completions only happen during NAPI poll which requires RX traffic.
//   XDPTransport uses an RX trickle thread (self-ping at 500 Hz) to keep NAPI
//   polling active.
//
// Requirements:
//   - Root or CAP_NET_RAW + CAP_BPF
//   - XDP-capable NIC (e.g., Intel I225/I226 with igc driver)
//   - Compile with USE_XDP=1 USE_OPENSSL=1
//   - Run ./scripts/xdp_prepare.sh <interface> before testing

#include "../../src/policy/transport.hpp"
#include "../../src/policy/ssl.hpp"
#include "../../src/core/http.hpp"
#include "../../src/core/timing.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <unistd.h>
#include <vector>
#include <netdb.h>
#include <arpa/inet.h>

using namespace websocket::transport;
using namespace websocket::ssl;
using namespace websocket::http;

// Test configuration
constexpr const char* BINANCE_HOST = "stream.binance.com";
constexpr uint16_t BINANCE_PORT = 443;
constexpr const char* BINANCE_PATH = "/stream?streams=btcusdt@trade";

// Global test state
std::atomic<bool> test_complete{false};
std::atomic<int> message_count{0};
constexpr int MAX_MESSAGES = 20;

// TSC frequency for timing conversion
uint64_t g_tsc_freq_hz = 0;

/**
 * Resolve hostname to list of IP addresses
 */
std::vector<std::string> resolve_hostname(const char* hostname) {
    std::vector<std::string> ips;

    struct addrinfo hints = {};
    struct addrinfo* result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(hostname, nullptr, &hints, &result);
    if (ret != 0 || !result) {
        if (result) freeaddrinfo(result);
        return ips;
    }

    for (struct addrinfo* p = result; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            auto* addr = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            ips.push_back(ip_str);
        }
    }

    freeaddrinfo(result);
    return ips;
}

/**
 * Main test: XDP + Userspace TCP + SSL + WebSocket
 */
int main(int argc, char** argv) {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║    XDP Userspace TCP + SSL + WebSocket (Policy-Based Design)      ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");
    printf("Target: wss://%s:%u%s\n", BINANCE_HOST, BINANCE_PORT, BINANCE_PATH);
    printf("Architecture: XDP (native driver) + Userspace TCP/IP + OpenSSL\n\n");

    // Parse command line args
    // Usage: ./test_xdp_binance_integration [interface]
    const char* interface = "enp108s0";

    for (int i = 1; i < argc; i++) {
        // Silently ignore deprecated --napi-timer and --user-poll flags
        if (strcmp(argv[i], "--napi-timer") == 0 || strcmp(argv[i], "-t") == 0 ||
            strcmp(argv[i], "--user-poll") == 0 || strcmp(argv[i], "-u") == 0) {
            continue;
        }
        interface = argv[i];
    }

    printf("Polling Mode: Userspace SO_BUSY_POLL\n");
    printf("Interface: %s\n\n", interface);

    try {
        // ═══════════════════════════════════════════════════════════════════════
        // TSC Calibration (for timing measurements)
        // ═══════════════════════════════════════════════════════════════════════
        printf("⏱️  Calibrating CPU TSC frequency...\n");
        g_tsc_freq_hz = calibrate_tsc_freq();
        printf("✅ TSC frequency: %.2f GHz\n\n", g_tsc_freq_hz / 1e9);

        // ═══════════════════════════════════════════════════════════════════════
        // Phase 1: Transport Initialization (XDP + Userspace TCP)
        // ═══════════════════════════════════════════════════════════════════════
        printf("📦 Phase 1: XDP + Userspace TCP Initialization\n");
        printf("─────────────────────────────────────────────────────────────────\n");

        XDPUserspaceTransport transport;
        transport.init(interface, "src/xdp/bpf/exchange_filter.bpf.o");

        // Configure BPF filter for Binance
        printf("  Resolving Binance IPs...\n");
        auto binance_ips = resolve_hostname(BINANCE_HOST);
        printf("  Found %zu IP(s): ", binance_ips.size());
        for (size_t i = 0; i < binance_ips.size(); i++) {
            printf("%s%s", binance_ips[i].c_str(), (i < binance_ips.size() - 1) ? ", " : "\n");
            transport.add_exchange_ip(binance_ips[i].c_str());
        }
        transport.add_exchange_port(BINANCE_PORT);
        printf("  ✅ BPF filter configured\n");

        // Verify XDP driver mode
        printf("\n  ╔══════════════════════════════════════════════════════════════╗\n");
        printf("  ║             XDP MODE VERIFICATION                           ║\n");
        printf("  ╚══════════════════════════════════════════════════════════════╝\n");
        printf("  Interface:  %s\n", transport.get_interface());
        printf("  Queue:      %u\n", transport.get_queue_id());
        printf("  XDP Mode:   %s\n", transport.get_xdp_mode());
        printf("  BPF Filter: %s\n", transport.is_bpf_enabled() ? "✅ ENABLED" : "❌ DISABLED");
        printf("  ╚══════════════════════════════════════════════════════════════╝\n\n");

        // ═══════════════════════════════════════════════════════════════════════
        // Phase 2: TCP Connection (Userspace 3-Way Handshake)
        // ═══════════════════════════════════════════════════════════════════════
        printf("📡 Phase 2: Userspace TCP Connection\n");
        printf("─────────────────────────────────────────────────────────────────\n");

        transport.connect(BINANCE_HOST, BINANCE_PORT);

        // ═══════════════════════════════════════════════════════════════════════
        // Phase 3: SSL/TLS Handshake (Policy-Based!)
        // ═══════════════════════════════════════════════════════════════════════
        printf("🔒 Phase 3: SSL/TLS Handshake\n");
        printf("─────────────────────────────────────────────────────────────────\n");

        OpenSSLPolicy ssl;
        ssl.init();

        printf("  Performing TLS handshake over userspace TCP...\n");
        // ✨ CLEAN POLICY-BASED DESIGN - One line!
        ssl.handshake_userspace_transport(&transport);

        // ═══════════════════════════════════════════════════════════════════════
        // Phase 4: HTTP WebSocket Upgrade
        // ═══════════════════════════════════════════════════════════════════════
        printf("🌐 Phase 4: HTTP WebSocket Upgrade\n");
        printf("─────────────────────────────────────────────────────────────────\n");

        // Build upgrade request
        std::vector<std::pair<std::string, std::string>> headers;
        char upgrade_req[2048];
        size_t req_len = build_websocket_upgrade_request(
            BINANCE_HOST, BINANCE_PATH, headers, upgrade_req, sizeof(upgrade_req)
        );

        printf("  Sending HTTP upgrade request (%zu bytes)...\n", req_len);

        // Send upgrade request with polling
        size_t total_sent = 0;
        while (total_sent < req_len) {
            transport.poll();
            ssize_t sent = ssl.write(upgrade_req + total_sent, req_len - total_sent);
            if (sent > 0) {
                total_sent += sent;
            } else if (sent < 0 && errno != EAGAIN) {
                throw std::runtime_error("Failed to send upgrade request");
            }
            usleep(1000);
        }
        printf("  ✅ Upgrade request sent\n");

        // Receive upgrade response
        printf("  Waiting for HTTP 101 response...\n");
        uint8_t response_buf[4096];
        bool response_validated = false;
        int poll_attempts = 0;
        int max_attempts = 1000;

        while (poll_attempts < max_attempts && !response_validated) {
            transport.poll();
            ssize_t received = ssl.read(response_buf, sizeof(response_buf));

            if (received > 0) {
                if (validate_http_upgrade_response(response_buf, received)) {
                    printf("  ✅ HTTP 101 Switching Protocols validated\n\n");
                    response_validated = true;
                    break;
                }
            } else if (received < 0 && errno != EAGAIN) {
                throw std::runtime_error("SSL read error");
            }

            usleep(1000);
            poll_attempts++;
        }

        if (!response_validated) {
            throw std::runtime_error("Failed to receive valid HTTP upgrade response");
        }

        // ═══════════════════════════════════════════════════════════════════════
        // Phase 5: WebSocket Message Streaming
        // ═══════════════════════════════════════════════════════════════════════
        printf("💬 Phase 5: WebSocket Message Streaming\n");
        printf("─────────────────────────────────────────────────────────────────\n\n");

        // Reset stats before message streaming
        // (clear any stale timestamps from handshake/upgrade phases)
        transport.reset_hw_timestamps();  // Legacy per-iteration tracking
        transport.reset_recv_stats();      // New per-frame cumulative tracking

        uint8_t frame_buffer[65536];
        size_t buffer_offset = 0;
        int ping_count = 0;
        int pong_sent = 0;

        // Timing record for each message
        timing_record_t timing;
        memset(&timing, 0, sizeof(timing));

        while (message_count < MAX_MESSAGES) {
            // Stage 2: Event loop start
            timing.event_cycle = rdtsc();

            // Poll transport first (handles TX completions, etc.)
            transport.poll();

            // Stage 3: Before SSL read
            timing.recv_start_cycle = rdtsc();

            // Read more data from SSL
            // This internally calls transport.recv() via BIO, which records HW timestamps
            ssize_t read_len = ssl.read(frame_buffer + buffer_offset,
                                         sizeof(frame_buffer) - buffer_offset);

            // Stage 4: After SSL read
            timing.recv_end_cycle = rdtscp();

            // NOTE: Don't capture/reset stats here - we need to accumulate across multiple
            // ssl.read() calls until we have complete frames to process. Stats are captured
            // and reset only when we print batch results (after parsing complete frames).

            if (read_len > 0) {
                buffer_offset += read_len;

                // ============================================================
                // Phase 1: Parse all complete frames in buffer
                // ============================================================
                struct ParsedFrame {
                    WebSocketFrame frame;
                    size_t total_size;
                    uint64_t parse_cycle;
                };
                std::vector<ParsedFrame> text_frames;
                std::vector<ParsedFrame> control_frames;  // PING, CLOSE, etc.

                size_t consumed = 0;
                while (consumed < buffer_offset) {
                    WebSocketFrame frame;
                    if (!parse_websocket_frame(frame_buffer + consumed,
                                                 buffer_offset - consumed, frame)) {
                        break;  // Incomplete frame
                    }

                    uint64_t parse_cycle = rdtscp();
                    size_t total_frame_size = frame.header_len + frame.payload_len;

                    if (frame.opcode == 0x01) {  // TEXT
                        text_frames.push_back({frame, total_frame_size, parse_cycle});
                    } else {
                        control_frames.push_back({frame, total_frame_size, parse_cycle});
                    }

                    consumed += total_frame_size;
                }

                // ============================================================
                // Phase 2: Print batch summary for TEXT frames
                // ============================================================
                if (!text_frames.empty()) {
                    // NOW capture stats - we have complete frames to process
                    // This accumulates all packets processed since last reset (across ssl.read() calls)
                    timing.hw_timestamp_count = transport.get_recv_packet_count();
                    if (timing.hw_timestamp_count > 0) {
                        timing.hw_timestamp_oldest_ns = transport.get_recv_oldest_timestamp();
                        timing.hw_timestamp_latest_ns = transport.get_recv_latest_timestamp();
                    } else {
                        timing.hw_timestamp_oldest_ns = 0;
                        timing.hw_timestamp_latest_ns = 0;
                    }
                    // Reset for next batch (after capturing)
                    transport.reset_recv_stats();

                    size_t total_payload = 0;
                    for (const auto& pf : text_frames) {
                        total_payload += pf.frame.payload_len;
                    }

                    // Show legacy per-iteration stats (bytes/packets polled since last reset)
                    uint64_t polled_bytes = transport.get_hw_timestamp_byte_count();
                    uint32_t polled_packets = transport.get_hw_timestamp_count();
                    printf("\n  [RX polled: %lu bytes, %u packets]\n", polled_bytes, polled_packets);
                    transport.reset_hw_timestamps();  // Reset for next batch

                    printf("  ┌─ SSL_read: %zd bytes → %zu frame%s, %u packet%s ─┐\n",
                           read_len,
                           text_frames.size(),
                           text_frames.size() > 1 ? "s" : "",
                           timing.hw_timestamp_count,
                           timing.hw_timestamp_count != 1 ? "s" : "");

                    // Print each frame's details
                    for (size_t i = 0; i < text_frames.size(); i++) {
                        const auto& pf = text_frames[i];
                        uint64_t stage6_cycle = rdtscp();

                        // Update timing record for this frame
                        timing.frame_parsed_cycle = pf.parse_cycle;
                        timing.payload_len = pf.frame.payload_len;
                        timing.opcode = pf.frame.opcode;

                        printf("\n  ╔════════════════════════════════════════════════════════════╗\n");
                        if (text_frames.size() > 1) {
                            printf("  ║ Message #%d (%lu bytes) [%zu/%zu in batch]                 \n",
                                   message_count.load() + 1, pf.frame.payload_len, i + 1, text_frames.size());
                        } else {
                            printf("  ║ Message #%d (%lu bytes)                                    \n",
                                   message_count.load() + 1, pf.frame.payload_len);
                        }
                        printf("  ╚════════════════════════════════════════════════════════════╝\n");
                        printf("  📨 Data: %.100s%s\n",
                               pf.frame.payload,
                               pf.frame.payload_len > 100 ? "..." : "");

                        // Display timing breakdown
                        printf("\n  ⏱️  Latency Breakdown (6 Stages):\n");
                        printf("  ────────────────────────────────────────────────────────────\n");

                        // Stage 1: Hardware timestamp from NIC
                        if (timing.hw_timestamp_latest_ns > 0) {
                            struct timespec ts_real, ts_mono;
                            clock_gettime(CLOCK_REALTIME, &ts_real);
                            clock_gettime(CLOCK_MONOTONIC, &ts_mono);
                            uint64_t realtime_now_ns = (uint64_t)ts_real.tv_sec * 1000000000ULL + ts_real.tv_nsec;
                            uint64_t monotonic_now_ns = (uint64_t)ts_mono.tv_sec * 1000000000ULL + ts_mono.tv_nsec;

                            int64_t hw_ts_mono_ns = (int64_t)timing.hw_timestamp_latest_ns -
                                                    (int64_t)realtime_now_ns + (int64_t)monotonic_now_ns;

                            printf("    [Stage 1] NIC HW timestamp: %.6f s (converted to MONOTONIC)\n",
                                   hw_ts_mono_ns / 1e9);

                            uint64_t stage2_to_6_ns = cycles_to_ns(stage6_cycle - timing.event_cycle, g_tsc_freq_hz);
                            int64_t stage2_mono_ns = (int64_t)monotonic_now_ns - (int64_t)stage2_to_6_ns;
                            int64_t stage1_to_2_ns = stage2_mono_ns - hw_ts_mono_ns;
                            printf("    [Stage 1→2] NIC→Event:      %.3f μs\n",
                                   stage1_to_2_ns / 1000.0);
                        } else {
                            printf("    [Stage 1] NIC HW timestamp: N/A (not available)\n");
                        }

                        if (timing.recv_start_cycle > timing.event_cycle) {
                            uint64_t delta = timing.recv_start_cycle - timing.event_cycle;
                            printf("    [Stage 2→3] Event→Recv:     %.3f μs\n",
                                   cycles_to_ns(delta, g_tsc_freq_hz) / 1000.0);
                        }

                        if (timing.recv_end_cycle > timing.recv_start_cycle) {
                            uint64_t delta = timing.recv_end_cycle - timing.recv_start_cycle;
                            printf("    [Stage 3→4] SSL decrypt:    %.3f μs\n",
                                   cycles_to_ns(delta, g_tsc_freq_hz) / 1000.0);
                        }

                        if (timing.frame_parsed_cycle > timing.recv_end_cycle) {
                            uint64_t delta = timing.frame_parsed_cycle - timing.recv_end_cycle;
                            printf("    [Stage 4→5] WS parse:       %.3f μs\n",
                                   cycles_to_ns(delta, g_tsc_freq_hz) / 1000.0);
                        }

                        if (stage6_cycle > timing.frame_parsed_cycle) {
                            uint64_t delta = stage6_cycle - timing.frame_parsed_cycle;
                            printf("    [Stage 5→6] To callback:    %.3f μs\n",
                                   cycles_to_ns(delta, g_tsc_freq_hz) / 1000.0);
                        }

                        if (stage6_cycle > timing.event_cycle) {
                            uint64_t total = stage6_cycle - timing.event_cycle;
                            printf("    ────────────────────────────────────────────────────────\n");
                            printf("    [Total]     Event→Callback: %.3f μs\n",
                                   cycles_to_ns(total, g_tsc_freq_hz) / 1000.0);
                        }

                        printf("  ────────────────────────────────────────────────────────────\n");

                        message_count++;
                    }
                }

                // ============================================================
                // Phase 3: Handle control frames (PING, CLOSE, etc.)
                // ============================================================
                for (const auto& pf : control_frames) {
                    if (pf.frame.opcode == 0x09) {  // PING
                        printf("  🏓 PING received - sending PONG\n");
                        ping_count++;

                        uint8_t pong_buffer[256];
                        uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
                        size_t pong_len = build_pong_frame(pf.frame.payload, pf.frame.payload_len,
                                                            pong_buffer, mask);

                        // Send PONG with polling
                        size_t pong_total = 0;
                        while (pong_total < pong_len) {
                            transport.poll();
                            ssize_t pong_sent_bytes = ssl.write(pong_buffer + pong_total,
                                                                  pong_len - pong_total);
                            if (pong_sent_bytes > 0) {
                                pong_total += pong_sent_bytes;
                            }
                            usleep(100);
                        }
                        pong_sent++;

                    } else if (pf.frame.opcode == 0x08) {  // CLOSE
                        printf("  🚪 CLOSE frame received\n");
                        test_complete = true;
                        break;
                    }
                }

                // Shift remaining data to front of buffer
                if (consumed > 0 && consumed < buffer_offset) {
                    memmove(frame_buffer, frame_buffer + consumed, buffer_offset - consumed);
                    buffer_offset -= consumed;
                } else if (consumed == buffer_offset) {
                    buffer_offset = 0;
                }

                if (test_complete) break;

            } else if (read_len < 0 && errno != EAGAIN) {
                throw std::runtime_error("SSL read error during streaming");
            }

            // Pure busy-poll for lowest latency (no usleep)
        }

        printf("\n");
        printf("─────────────────────────────────────────────────────────────────\n");
        printf("  ✅ WebSocket streaming complete\n");
        printf("     Messages: %d\n", message_count.load());
        printf("     PINGs: %d, PONGs: %d\n", ping_count, pong_sent);
        printf("\n");

        // Display BPF statistics
        printf("📊 BPF Packet Statistics\n");
        printf("─────────────────────────────────────────────────────────────────\n");
        transport.print_bpf_stats();
        printf("\n");

        // ═══════════════════════════════════════════════════════════════════════
        // Cleanup
        // ═══════════════════════════════════════════════════════════════════════
        printf("🧹 Cleanup\n");
        printf("─────────────────────────────────────────────────────────────────\n");
        ssl.shutdown();
        transport.close();
        printf("  ✅ Cleanup complete\n\n");

        // ═══════════════════════════════════════════════════════════════════════
        // Test Summary
        // ═══════════════════════════════════════════════════════════════════════
        printf("╔════════════════════════════════════════════════════════════════════╗\n");
        printf("║                      TEST PASSED ✅                                ║\n");
        printf("╚════════════════════════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("All phases completed successfully:\n");
        printf("  ✅ XDP + Userspace TCP initialization\n");
        printf("  ✅ Userspace TCP 3-way handshake\n");
        printf("  ✅ SSL/TLS handshake over userspace TCP (policy-based)\n");
        printf("  ✅ HTTP WebSocket upgrade\n");
        printf("  ✅ WebSocket message streaming\n");
        printf("\n");
        printf("🎉 Complete kernel bypass achieved!\n");
        printf("   XDP (native driver) + Userspace TCP/IP + SSL/TLS\n");
        printf("\n");
        printf("✨ Clean policy-based design demonstrated:\n");
        printf("   ssl.handshake_userspace_transport(&transport);\n");
        printf("\n");

        return 0;

    } catch (const std::exception& e) {
        printf("\n");
        printf("╔════════════════════════════════════════════════════════════════════╗\n");
        printf("║                      TEST FAILED ❌                                ║\n");
        printf("╚════════════════════════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("Error: %s\n\n", e.what());

        printf("Common issues:\n");
        printf("  - Permission denied: Run with sudo\n");
        printf("  - Interface not found: Specify correct interface (e.g., ./xdp_binance enp108s0)\n");
        printf("  - XDP not supported: Ensure NIC supports XDP native mode\n");
        printf("  - Gateway not reachable: Check network configuration\n");
        printf("\n");

        return 1;
    }
}
