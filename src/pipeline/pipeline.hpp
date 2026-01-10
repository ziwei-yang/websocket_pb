// pipeline/pipeline.hpp
// WebSocketClientPipeline - User-facing facade for pipeline setup and management
// Single header to include for using the pipeline
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <functional>

// pipeline_data.hpp must be included first as it includes disruptor headers
// before pipeline_config.hpp to avoid macro conflicts
#include "pipeline_data.hpp"
#include "msg_inbox.hpp"
#include "ws_parser.hpp"
#include "app_client.hpp"
#include "handshake_manager.hpp"

#ifdef USE_XDP
#include "../xdp/xdp_transport.hpp"
#endif

namespace websocket::pipeline {

// ============================================================================
// WebSocketConfig - User configuration
// ============================================================================

struct WebSocketConfig {
    const char* interface = "enp108s0";
    const char* host = "stream.binance.com";
    uint16_t port = 443;
    const char* path = "/stream";
    const char* bpf_path = "src/xdp/bpf/exchange_filter.bpf.o";
    int cpu_cores[4] = {2, 4, 6, 8};  // XDP Poll, Transport, WebSocket, AppClient
};

// ============================================================================
// WebSocketClientPipeline - Main pipeline facade
//
// Template parameter:
//   Handler - User-defined handler class derived from AppClientHandler<Handler, ...>
//
// Usage:
//   class MyHandler : public AppClientHandler<MyHandler, ...> { ... };
//
//   WebSocketConfig config;
//   config.interface = "enp108s0";
//   config.host = "stream.binance.com";
//
//   WebSocketClientPipeline<MyHandler> pipeline;
//   pipeline.setup(config);
//   pipeline.subscribe(R"({"method":"SUBSCRIBE",...})");
//   pipeline.start();  // Blocks until shutdown
//   pipeline.cleanup();
// ============================================================================

#ifdef USE_XDP
template<typename Handler>
class WebSocketClientPipeline {
public:
    using Manager = HandshakeManager;

    // ========================================================================
    // Setup
    // ========================================================================

    bool setup(const WebSocketConfig& config) {
        config_ = config;

        // Convert to manager config
        typename Manager::Config mgr_config;
        mgr_config.interface = config.interface;
        mgr_config.host = config.host;
        mgr_config.port = config.port;
        mgr_config.path = config.path;
        mgr_config.bpf_path = config.bpf_path;
        memcpy(mgr_config.cpu_cores, config.cpu_cores, sizeof(config.cpu_cores));

        // Initialize manager
        if (!manager_.init(mgr_config)) {
            fprintf(stderr, "[PIPELINE] Manager init failed\n");
            return false;
        }

        // Initialize XDP
        if (!manager_.init_xdp()) {
            fprintf(stderr, "[PIPELINE] XDP init failed\n");
            return false;
        }

        // TCP handshake
        if (!manager_.tcp_handshake()) {
            fprintf(stderr, "[PIPELINE] TCP handshake failed\n");
            return false;
        }

        // TLS handshake
        if (!manager_.tls_handshake()) {
            fprintf(stderr, "[PIPELINE] TLS handshake failed\n");
            return false;
        }

        // WebSocket upgrade
        if (!manager_.websocket_upgrade()) {
            fprintf(stderr, "[PIPELINE] WebSocket upgrade failed\n");
            return false;
        }

        printf("[PIPELINE] Setup complete\n");
        return true;
    }

    // ========================================================================
    // Subscription
    // ========================================================================

    bool subscribe(const char* msg) {
        subscriptions_.push_back(msg);
        return manager_.send_subscription(msg);
    }

    bool subscribe(const std::string& msg) {
        return subscribe(msg.c_str());
    }

    // ========================================================================
    // Start (Blocking) - Multi-process pipeline with ring consumption
    // ========================================================================

    void start() {
        // Fork child processes (XDP Poll, Transport, WebSocket)
        manager_.fork_processes();

        printf("[APP-CLIENT] Started on core %d\n", config_.cpu_cores[3]);

        // Open IPC rings for AppClient process
        // AppClient consumes: WS_FRAME_INFO
        // AppClient produces: MSG_OUTBOX
        try {
            disruptor::ipc::shared_region ws_frame_info_region(
                manager_.get_ws_frame_info_ring_name());
            disruptor::ipc::shared_region msg_outbox_region(
                manager_.get_msg_outbox_ring_name());

            // Create adapters
            IPCRingConsumer<WSFrameInfo> ws_frame_info_cons(ws_frame_info_region);
            IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(msg_outbox_region);

            // Initialize handler with rings and shared state
            handler_.init(manager_.msg_inbox(), &ws_frame_info_cons,
                         &msg_outbox_prod, manager_.tcp_state());

            printf("[APP-CLIENT] Running main loop\n");

            // Mark ourselves as ready
            manager_.tcp_state()->set_ready(PROC_APPCLIENT);

            // AppClient uses manual polling in a busy loop
            WSFrameInfo frame_info;
            bool end_of_batch;
            while (manager_.tcp_state()->is_running(PROC_APPCLIENT)) {
                if (ws_frame_info_cons.try_consume(frame_info, &end_of_batch)) {
                    handler_.on_event(frame_info, ws_frame_info_cons.sequence(), end_of_batch);
                } else {
                    __builtin_ia32_pause();  // CPU hint for spin-wait
                }
            }

        } catch (const std::exception& e) {
            fprintf(stderr, "[APP-CLIENT] Exception: %s\n", e.what());
        }

        printf("[APP-CLIENT] Exiting\n");

        // Wait for children to exit
        manager_.wait_for_children();
    }

    // Overload for passing external handler reference (backwards compatibility)
    void start(Handler& handler) {
        handler_ = handler;  // Copy/move to internal handler
        start();
    }

    // ========================================================================
    // Shutdown
    // ========================================================================

    void shutdown() {
        manager_.shutdown();
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    void cleanup() {
        manager_.cleanup();
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    Manager& manager() { return manager_; }
    const WebSocketConfig& config() const { return config_; }
    Handler& handler() { return handler_; }
    const Handler& handler() const { return handler_; }

private:
    WebSocketConfig config_;
    Manager manager_;
    Handler handler_;
    std::vector<std::string> subscriptions_;
    // Note: Ring buffers are now IPC-based via hftshm shared memory
    // No local ring buffer members needed - each process opens shared regions
};

// Note: WebSocketClientPipeline is now a class template.
// Usage: WebSocketClientPipeline<MyHandler> pipeline;
// The old non-template DefaultPipeline alias has been removed.
#endif  // USE_XDP

}  // namespace websocket::pipeline
