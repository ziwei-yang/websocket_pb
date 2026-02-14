// pipeline/bsd_websocket_pipeline.hpp
// BSDWebSocketPipeline<Traits> — single-call launcher for BSD socket transport pipeline
//
// Centralizes IP probe, IPC ring management, shared memory allocation,
// and fork logic for BSD socket transport (2-thread InlineSSL or 3-thread DedicatedSSL).
//
// Unlike WebSocketPipeline (XDP), this launcher:
//   - No XDP/UMEM/BPF (uses kernel TCP stack)
//   - 2 processes (Transport + WebSocket), not 3
//   - macOS-compatible (/tmp/hft/ instead of /dev/shm/hft/)
//
// Usage:
//   struct MyTraits : DefaultBSDPipelineConfig {
//       using SSLPolicy          = OpenSSLPolicy;
//       using AppHandler         = NullAppHandler;
//       using IOPolicy           = DefaultBlockingIO;
//       using SSLThreadingPolicy = InlineSSL;
//       static constexpr int TRANSPORT_CORE = -1;
//       static constexpr int WEBSOCKET_CORE = -1;
//       static constexpr const char* WSS_HOST = "stream.binance.com";
//       static constexpr uint16_t WSS_PORT = 443;
//       static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade";
//       static constexpr bool ENABLE_AB = true;
//       static constexpr bool AUTO_RECONNECT = true;
//   };
//   BSDWebSocketPipeline<MyTraits> pipeline;
//   pipeline.setup();
//   pipeline.start();
//   // ... consume ws_frame_info ...
//   pipeline.shutdown();
//
// C++20, policy-based design
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <atomic>
#include <chrono>
#include <concepts>
#include <memory>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <csignal>

#include "pipeline_data.hpp"
#include "pipeline_config.hpp"
#include "11_bsd_tcp_ssl_process.hpp"
#include "20_ws_process.hpp"
#include "msg_inbox.hpp"
#include "../net/ip_probe.hpp"

namespace websocket::pipeline {

// ============================================================================
// BSDPipelineTraits Concept
// ============================================================================

template<typename T>
concept BSDPipelineTraitsConcept = requires {
    typename T::SSLPolicy;
    typename T::AppHandler;
    requires AppHandlerConcept<typename T::AppHandler>;
    typename T::UpgradeCustomizer;
    requires UpgradeCustomizerConcept<typename T::UpgradeCustomizer>;
    typename T::IOPolicy;
    typename T::SSLThreadingPolicy;

    { T::TRANSPORT_CORE } -> std::convertible_to<int>;
    { T::WEBSOCKET_CORE } -> std::convertible_to<int>;

    { T::WSS_HOST } -> std::convertible_to<const char*>;
    { T::WSS_PORT } -> std::convertible_to<uint16_t>;
    { T::WSS_PATH } -> std::convertible_to<const char*>;

    { T::ENABLE_AB }              -> std::convertible_to<bool>;
    { T::AUTO_RECONNECT }         -> std::convertible_to<bool>;
    { T::PROFILING }              -> std::convertible_to<bool>;

    { T::PROBE_COUNT }            -> std::convertible_to<uint32_t>;
    { T::PROBE_TIMEOUT_MS }       -> std::convertible_to<uint32_t>;
    { T::DUAL_DEAD_THRESHOLD_MS } -> std::convertible_to<uint64_t>;
};

// ============================================================================
// DefaultBSDPipelineConfig
// ============================================================================

struct DefaultBSDPipelineConfig {
    using IOPolicy           = DefaultBlockingIO;
    using SSLThreadingPolicy = InlineSSL;
    using AppHandler         = NullAppHandler;
    using UpgradeCustomizer  = NullUpgradeCustomizer;

    static constexpr int TRANSPORT_CORE = -1;  // No pinning (macOS)
    static constexpr int WEBSOCKET_CORE = -1;

    static constexpr bool ENABLE_AB        = false;
    static constexpr bool AUTO_RECONNECT   = false;
    static constexpr bool PROFILING        = false;

    static constexpr uint32_t PROBE_COUNT            = 3;
    static constexpr uint32_t PROBE_TIMEOUT_MS       = 200;
    static constexpr uint64_t DUAL_DEAD_THRESHOLD_MS = 3000;
};

// ============================================================================
// BSDIPCRingManager — macOS-compatible IPC ring file manager
// ============================================================================

class BSDIPCRingManager {
public:
    explicit BSDIPCRingManager(const char* prefix) {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string(prefix) + "_" + timestamp;
    }

    ~BSDIPCRingManager() { cleanup(); }

    BSDIPCRingManager(const BSDIPCRingManager&) = delete;
    BSDIPCRingManager& operator=(const BSDIPCRingManager&) = delete;

    bool create_ring(const char* name, size_t buffer_size, size_t event_size, uint8_t max_consumers = 1) {
        std::string base_path = std::string(shm_base()) + "/" + ipc_ring_dir_ + "/" + name;
        std::string hdr_path = base_path + ".hdr";
        std::string dat_path = base_path + ".dat";

        uint32_t producer_offset = hftshm::default_producer_offset();
        uint32_t consumer_0_offset = hftshm::default_consumer_0_offset();
        uint32_t header_size = hftshm::header_segment_size(max_consumers);

        int hdr_fd = open(hdr_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (hdr_fd < 0) {
            fprintf(stderr, "[IPC] Failed to create header: %s\n", hdr_path.c_str());
            return false;
        }
        if (ftruncate(hdr_fd, header_size) < 0) { close(hdr_fd); return false; }
        void* hdr_ptr = mmap(nullptr, header_size, PROT_READ | PROT_WRITE, MAP_SHARED, hdr_fd, 0);
        close(hdr_fd);
        if (hdr_ptr == MAP_FAILED) return false;

        hftshm::metadata_init(hdr_ptr, max_consumers, event_size, buffer_size,
                              producer_offset, consumer_0_offset, header_size);

        auto* cursor = reinterpret_cast<std::atomic<int64_t>*>(
            static_cast<char*>(hdr_ptr) + producer_offset);
        auto* published = reinterpret_cast<std::atomic<int64_t>*>(
            static_cast<char*>(hdr_ptr) + producer_offset + hftshm::CACHE_LINE);
        cursor->store(-1, std::memory_order_relaxed);
        published->store(-1, std::memory_order_relaxed);

        for (uint8_t i = 0; i < max_consumers; ++i) {
            auto* cons_seq = reinterpret_cast<std::atomic<int64_t>*>(
                static_cast<char*>(hdr_ptr) + consumer_0_offset + i * 2 * hftshm::CACHE_LINE);
            cons_seq->store(-1, std::memory_order_relaxed);
        }

        munmap(hdr_ptr, header_size);

        int dat_fd = open(dat_path.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0644);
        if (dat_fd < 0) {
            fprintf(stderr, "[IPC] Failed to create data: %s\n", dat_path.c_str());
            unlink(hdr_path.c_str());
            return false;
        }
        if (ftruncate(dat_fd, buffer_size) < 0) {
            close(dat_fd);
            unlink(hdr_path.c_str());
            return false;
        }
        void* dat_ptr = mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, dat_fd, 0);
        close(dat_fd);
        if (dat_ptr == MAP_FAILED) { unlink(hdr_path.c_str()); return false; }
        memset(dat_ptr, 0, buffer_size);
        munmap(dat_ptr, buffer_size);

        return true;
    }

    template<bool EnableAB, bool HasAppHandler>
    bool create_all_rings() {
        mkdir(shm_base(), 0755);
        std::string full_dir = std::string(shm_base()) + "/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "[IPC] Failed to create directory: %s\n", full_dir.c_str());
            return false;
        }

        // Transport <-> WebSocket rings (no raw_inbox/raw_outbox for BSD)
        if (!create_ring("msg_outbox", MSG_OUTBOX_SIZE * sizeof(MsgOutboxEvent),
                         sizeof(MsgOutboxEvent), 1)) return false;
        if (!create_ring("msg_metadata_a", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                         sizeof(MsgMetadata), 1)) return false;
        if constexpr (EnableAB) {
            if (!create_ring("msg_metadata_b", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                             sizeof(MsgMetadata), 1)) return false;
        }
        if (!create_ring("pongs", PONGS_SIZE * sizeof(PongFrameAligned),
                         sizeof(PongFrameAligned), 1)) return false;

        // WebSocket -> Parent ring (skip when AppHandler replaces it)
        if constexpr (!HasAppHandler) {
            if (!create_ring("ws_frame_info", WS_FRAME_INFO_SIZE * sizeof(WSFrameInfo),
                             sizeof(WSFrameInfo), 1)) return false;
        }

        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;
        std::string base = std::string(shm_base()) + "/" + ipc_ring_dir_;
        const char* ring_names[] = {
            "msg_outbox", "msg_metadata_a", "msg_metadata_b", "pongs", "ws_frame_info"
        };
        for (const char* name : ring_names) {
            unlink((base + "/" + name + ".hdr").c_str());
            unlink((base + "/" + name + ".dat").c_str());
        }
        rmdir(base.c_str());
    }

    std::string get_ring_name(const char* ring) const {
        return ipc_ring_dir_ + "/" + ring;
    }

private:
    static const char* shm_base() {
#ifdef __APPLE__
        return "/tmp/hft";
#else
        return "/dev/shm/hft";
#endif
    }

    std::string ipc_ring_dir_;
};

// ============================================================================
// TSC calibration helper (shared with XDP pipeline)
// ============================================================================

namespace bsd_pipeline_helpers {

inline uint64_t get_monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

inline double calibrate_tsc_ghz() {
    uint64_t start_tsc = rdtsc();
    uint64_t start_ns = get_monotonic_ns();
    usleep(100000);  // 100ms
    uint64_t end_tsc = rdtsc();
    uint64_t end_ns = get_monotonic_ns();
    double ghz = static_cast<double>(end_tsc - start_tsc) / static_cast<double>(end_ns - start_ns);
    printf("[TSC] Calibrated: %.3f GHz\n", ghz);
    return ghz;
}

#ifdef __linux__
inline void pin_to_cpu(int core) {
    if (core < 0) return;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        fprintf(stderr, "[CPU] WARNING: Failed to pin to core %d: %s\n", core, strerror(errno));
        return;
    }
    struct sched_param param = {};
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) {
        fprintf(stderr, "[CPU] WARNING: Failed to set SCHED_FIFO on core %d: %s\n", core, strerror(errno));
    }
    fprintf(stderr, "[CPU] Pinned to core %d\n", core);
}
#else
inline void pin_to_cpu(int /*core*/) {
    // CPU pinning not supported on macOS
}
#endif

}  // namespace bsd_pipeline_helpers

// ============================================================================
// BSDWebSocketPipeline<Traits>
// ============================================================================

template<BSDPipelineTraitsConcept Traits>
class BSDWebSocketPipeline {
public:
    static constexpr bool EnableAB       = Traits::ENABLE_AB;
    static constexpr bool AutoReconnect  = Traits::AUTO_RECONNECT;
    static constexpr bool Prof           = Traits::PROFILING;
    static constexpr size_t NUM_CONN     = EnableAB ? 2 : 1;
    static constexpr bool HasAppHandler  = Traits::AppHandler::enabled;

    using SSLPolicyType      = typename Traits::SSLPolicy;
    using IOPolicyType       = typename Traits::IOPolicy;
    using SSLThreadingType   = typename Traits::SSLThreadingPolicy;
    using AppHandlerType     = typename Traits::AppHandler;
    using UpgradeCustomizerType = typename Traits::UpgradeCustomizer;

    using BSDTransportType = BSDSocketTransportProcess<
        SSLPolicyType,
        IOPolicyType,
        SSLThreadingType,
        IPCRingConsumer<MsgOutboxEvent>,
        IPCRingProducer<MsgMetadata>,
        IPCRingConsumer<PongFrameAligned>,
        EnableAB, AutoReconnect>;

    using WebSocketType = WebSocketProcess<
        IPCRingConsumer<MsgMetadata>,
        IPCRingProducer<WSFrameInfo>,
        IPCRingProducer<PongFrameAligned>,
        IPCRingProducer<MsgOutboxEvent>,
        EnableAB, AutoReconnect, Prof,
        AppHandlerType,
        UpgradeCustomizerType>;

    BSDWebSocketPipeline() : ipc_manager_("bsd_ws_pipeline") {}
    ~BSDWebSocketPipeline() { shutdown(); }

    BSDWebSocketPipeline(const BSDWebSocketPipeline&) = delete;
    BSDWebSocketPipeline& operator=(const BSDWebSocketPipeline&) = delete;

    // ========================================================================
    // Lifecycle
    // ========================================================================

    bool setup() {
        printf("\n=== Setting up BSD WebSocket Pipeline ===\n");
        printf("SSL:        %s\n", SSLPolicyType::name());
        printf("Threading:  %s\n", SSLThreadingType::has_ssl_thread ? "3-thread (DedicatedSSL)" : "2-thread (InlineSSL)");

        // IP Probe: resolve all IPs, measure RTT, rank
        {
            websocket::net::ProbeConfig probe_cfg;
            probe_cfg.port        = Traits::WSS_PORT;
            probe_cfg.probe_count = Traits::PROBE_COUNT;
            probe_cfg.timeout_ms  = Traits::PROBE_TIMEOUT_MS;
            probe_cfg.family      = AF_INET;

            // detect_probe_interface is Linux-only (/proc/net/route);
            // on macOS, probe without interface binding
#ifdef __linux__
            probe_iface_ = websocket::net::detect_probe_interface(nullptr);
            if (!probe_iface_.empty()) {
                probe_cfg.bind_interface = probe_iface_.c_str();
            }
#endif

            probe_result_ = websocket::net::probe(Traits::WSS_HOST, probe_cfg);
            websocket::net::print_probe_result(probe_result_);

            if (!probe_result_.ok()) {
                fprintf(stderr, "FAIL: IP probe for %s: %s (%s)\n",
                        Traits::WSS_HOST, websocket::net::probe_status_str(probe_result_.status),
                        probe_result_.error);
                return false;
            }

            websocket::net::IpSelector selector;
            if (selector.build(probe_result_) != 0) {
                fprintf(stderr, "FAIL: No reachable IPs for %s\n", Traits::WSS_HOST);
                return false;
            }

            if constexpr (EnableAB) {
                const websocket::net::ProbeEntry* ip_a = nullptr;
                const websocket::net::ProbeEntry* ip_b = nullptr;
                if (selector.assign_dual(ip_a, ip_b)) {
                    conn_target_ip_[0] = ip_a->ipv4_net();
                    conn_target_ip_[1] = ip_b->ipv4_net();
                } else {
                    conn_target_ip_[0] = conn_target_ip_[1] = ip_a->ipv4_net();
                }
                printf("Target: conn0=%s (%ldus), conn1=%s (%ldus)\n",
                       ip_a->ip_str, ip_a->rtt_us,
                       ip_b ? ip_b->ip_str : ip_a->ip_str,
                       ip_b ? ip_b->rtt_us : ip_a->rtt_us);
            } else {
                const auto* ip = selector.fastest();
                conn_target_ip_[0] = conn_target_ip_[1] = ip->ipv4_net();
                printf("Target: %s (%ldus)\n", ip->ip_str, ip->rtt_us);
            }
        }
        printf("Host:       %s:%u\n", Traits::WSS_HOST, Traits::WSS_PORT);
        printf("Path:       %s\n\n", Traits::WSS_PATH);

        // TSC calibration
        tsc_freq_ghz_ = bsd_pipeline_helpers::calibrate_tsc_ghz();

        // Create IPC rings
        if (!ipc_manager_.template create_all_rings<EnableAB, HasAppHandler>()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        // Allocate MsgInbox per connection (shared memory for cross-process access)
        for (size_t i = 0; i < NUM_CONN; i++) {
            msg_inbox_[i] = static_cast<MsgInbox*>(
                mmap(nullptr, sizeof(MsgInbox), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0));
            if (msg_inbox_[i] == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate MsgInbox[%zu]\n", i);
                return false;
            }
            msg_inbox_[i]->init();
        }

        // Allocate ConnStateShm
        conn_state_ = static_cast<ConnStateShm*>(
            mmap(nullptr, sizeof(ConnStateShm), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0));
        if (conn_state_ == MAP_FAILED) {
            fprintf(stderr, "FAIL: Cannot allocate ConnStateShm\n");
            return false;
        }
        conn_state_->init();

        // Populate shared state
        strncpy(conn_state_->target_host, Traits::WSS_HOST, sizeof(conn_state_->target_host) - 1);
        conn_state_->target_port = Traits::WSS_PORT;
        strncpy(conn_state_->target_path, Traits::WSS_PATH, sizeof(conn_state_->target_path) - 1);
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(tsc_freq_ghz_ * 1e9);

        // IP probe target IPs
        conn_state_->conn_target_ip[0] = conn_target_ip_[0];
        conn_state_->conn_target_ip[1] = conn_target_ip_[1];

        // Populate exchange_ips[] from DNS probe for reconnect pool
        {
            uint8_t count = 0;
            for (const auto& e : probe_result_.entries) {
                if (e.family == AF_INET && count < ConnStateShm::MAX_EXCHANGE_IPS) {
                    conn_state_->exchange_ips[count++] = e.ipv4_net();
                }
            }
            conn_state_->exchange_ip_count = count;
        }
        if constexpr (EnableAB) {
            conn_state_->dual_dead_threshold_ms = Traits::DUAL_DEAD_THRESHOLD_MS;
        }

        // Open shared regions
        try {
            msg_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_outbox"));
            msg_metadata_region_[0] = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata_a"));
            if constexpr (EnableAB) {
                msg_metadata_region_[1] = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata_b"));
            }
            pongs_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pongs"));
            if constexpr (!HasAppHandler) {
                ws_frame_info_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("ws_frame_info"));
            }
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
            return false;
        }

        printf("=== BSD Pipeline Setup Complete ===\n\n");
        return true;
    }

    bool start() {
        // Flush before fork to prevent duplicate buffered output
        fflush(stdout);

        // Fork Transport process
        transport_pid_ = fork();
        if (transport_pid_ < 0) { fprintf(stderr, "FAIL: fork() for Transport\n"); return false; }
        if (transport_pid_ == 0) { run_transport_process(); _exit(0); }
        printf("[PIPELINE] Forked BSD Transport (PID %d, %s, %s)\n",
               transport_pid_, SSLPolicyType::name(),
               SSLThreadingType::has_ssl_thread ? "3-thread" : "2-thread");

        // Wait for TLS ready
        auto start = std::chrono::steady_clock::now();
        while (!conn_state_->is_handshake_tls_ready()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed > 15000) { fprintf(stderr, "FAIL: TLS handshake timeout\n"); return false; }
            if (!conn_state_->is_running(PROC_TRANSPORT)) {
                fprintf(stderr, "FAIL: Transport exited during TLS handshake\n"); return false;
            }
            usleep(1000);
        }
        printf("[PIPELINE] TLS handshake complete\n");

        // Flush before fork
        fflush(stdout);

        // Fork WebSocket process
        websocket_pid_ = fork();
        if (websocket_pid_ < 0) { fprintf(stderr, "FAIL: fork() for WebSocket\n"); return false; }
        if (websocket_pid_ == 0) { run_websocket_process(); _exit(0); }
        printf("[PIPELINE] Forked WebSocket (PID %d)\n", websocket_pid_);

        // Wait for WS ready
        if (!conn_state_->wait_for_handshake_ws_ready(30000000)) {
            fprintf(stderr, "FAIL: WebSocket handshake timeout\n");
            return false;
        }
        printf("[PIPELINE] All processes ready\n");
        return true;
    }

    void shutdown() {
        if (conn_state_) conn_state_->shutdown_all();

        auto reap = [](pid_t& pid, const char* name) {
            if (pid <= 0) return;
            kill(pid, SIGTERM);
            auto t0 = std::chrono::steady_clock::now();
            while (true) {
                int st;
                pid_t ret = waitpid(pid, &st, WNOHANG);
                if (ret == pid || ret < 0) break;
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();
                if (ms > 2000) { kill(pid, SIGKILL); waitpid(pid, nullptr, 0); break; }
                usleep(1000);
            }
            pid = 0;
        };
        reap(transport_pid_, "Transport");
        reap(websocket_pid_, "WebSocket");

        // Cleanup shared regions
        delete msg_outbox_region_; msg_outbox_region_ = nullptr;
        for (size_t i = 0; i < NUM_CONN; i++) {
            delete msg_metadata_region_[i]; msg_metadata_region_[i] = nullptr;
        }
        delete pongs_region_; pongs_region_ = nullptr;
        delete ws_frame_info_region_; ws_frame_info_region_ = nullptr;

        if (conn_state_ && conn_state_ != MAP_FAILED) {
            munmap(conn_state_, sizeof(ConnStateShm)); conn_state_ = nullptr;
        }
        for (size_t i = 0; i < NUM_CONN; i++) {
            if (msg_inbox_[i] && msg_inbox_[i] != MAP_FAILED) {
                munmap(msg_inbox_[i], sizeof(MsgInbox)); msg_inbox_[i] = nullptr;
            }
        }
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    ConnStateShm* conn_state() { return conn_state_; }
    MsgInbox* msg_inbox(uint8_t ci) { return msg_inbox_[ci]; }
    double tsc_freq_ghz() const { return tsc_freq_ghz_; }

    disruptor::ipc::shared_region* ws_frame_info_region() {
        static_assert(!HasAppHandler, "No WSFrameInfo ring when AppHandler is active");
        return ws_frame_info_region_;
    }

    disruptor::ipc::shared_region* msg_metadata_region(uint8_t ci) { return msg_metadata_region_[ci]; }
    disruptor::ipc::shared_region* msg_outbox_region() { return msg_outbox_region_; }
    disruptor::ipc::shared_region* pongs_region() { return pongs_region_; }

    AppHandlerType& app_handler() { return app_handler_; }

    void set_subscription_json(const char* json) {
        strncpy(conn_state_->subscription_json, json, sizeof(conn_state_->subscription_json) - 1);
    }

private:
    // ========================================================================
    // Child process entry points
    // ========================================================================

    void run_transport_process() {
        bsd_pipeline_helpers::pin_to_cpu(Traits::TRANSPORT_CORE);

        IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(*msg_outbox_region_);
        IPCRingProducer<MsgMetadata> msg_metadata_prod_a(*msg_metadata_region_[0]);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);

        // Conn B metadata producer must outlive transport.run() — declared here
        // so it stays alive for the entire function scope (not scoped inside
        // the if-constexpr block which would create a dangling pointer).
        std::unique_ptr<IPCRingProducer<MsgMetadata>> msg_metadata_prod_b_holder;
        if constexpr (EnableAB) {
            msg_metadata_prod_b_holder = std::make_unique<IPCRingProducer<MsgMetadata>>(
                *msg_metadata_region_[1]);
        }

        BSDTransportType transport;

        if constexpr (EnableAB) {
            bool ok = transport.init(Traits::WSS_HOST, Traits::WSS_PORT,
                                     &msg_outbox_cons, &msg_metadata_prod_a, &pongs_cons,
                                     msg_inbox_[0], conn_state_,
                                     msg_inbox_[1], msg_metadata_prod_b_holder.get());
            if (!ok) { conn_state_->shutdown_all(); return; }
        } else {
            bool ok = transport.init(Traits::WSS_HOST, Traits::WSS_PORT,
                                     &msg_outbox_cons, &msg_metadata_prod_a, &pongs_cons,
                                     msg_inbox_[0], conn_state_);
            if (!ok) { conn_state_->shutdown_all(); return; }
        }

        transport.run();
    }

    void run_websocket_process() {
        bsd_pipeline_helpers::pin_to_cpu(Traits::WEBSOCKET_CORE);

        IPCRingConsumer<MsgMetadata> msg_metadata_cons_a(*msg_metadata_region_[0]);
        IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(*msg_outbox_region_);
        IPCRingProducer<PongFrameAligned> pongs_prod(*pongs_region_);

        // Conn B metadata consumer must outlive ws_process.run() — declared here
        // so it stays alive for the entire function scope (not scoped inside
        // the if-constexpr block which would create a dangling pointer).
        std::unique_ptr<IPCRingConsumer<MsgMetadata>> msg_metadata_cons_b_holder;
        if constexpr (EnableAB) {
            msg_metadata_cons_b_holder = std::make_unique<IPCRingConsumer<MsgMetadata>>(
                *msg_metadata_region_[1]);
        }

        // WSFrameInfo producer — created always, only wired when !HasAppHandler
        struct WSFrameInfoProdHelper {
            IPCRingProducer<WSFrameInfo>* prod_ = nullptr;
            std::unique_ptr<IPCRingProducer<WSFrameInfo>> owned_;

            explicit WSFrameInfoProdHelper(disruptor::ipc::shared_region* region) {
                if constexpr (!HasAppHandler) {
                    if (region) {
                        owned_ = std::make_unique<IPCRingProducer<WSFrameInfo>>(*region);
                        prod_ = owned_.get();
                    }
                }
            }
            IPCRingProducer<WSFrameInfo>* get() { return prod_; }
        };
        WSFrameInfoProdHelper ws_frame_info_prod_holder(ws_frame_info_region_);

        WebSocketType ws_process;
        ws_process.app_handler() = app_handler_;

        if constexpr (EnableAB) {
            bool ok = ws_process.init(msg_inbox_[0], &msg_metadata_cons_a,
                ws_frame_info_prod_holder.get(), &pongs_prod, &msg_outbox_prod,
                conn_state_, msg_inbox_[1], msg_metadata_cons_b_holder.get());
            if (!ok) { conn_state_->shutdown_all(); return; }
        } else {
            bool ok = ws_process.init(msg_inbox_[0], &msg_metadata_cons_a,
                ws_frame_info_prod_holder.get(), &pongs_prod, &msg_outbox_prod,
                conn_state_);
            if (!ok) { conn_state_->shutdown_all(); return; }
        }

        ws_process.run_with_handshake();
    }

    // ========================================================================
    // Member Variables
    // ========================================================================

    double tsc_freq_ghz_ = 0.0;
    uint32_t conn_target_ip_[NUM_CONN]{};
    std::string probe_iface_;
    websocket::net::ProbeResult probe_result_;

    BSDIPCRingManager ipc_manager_;

    MsgInbox* msg_inbox_[NUM_CONN]{};
    ConnStateShm* conn_state_ = nullptr;

    disruptor::ipc::shared_region* msg_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_metadata_region_[NUM_CONN]{};
    disruptor::ipc::shared_region* pongs_region_ = nullptr;
    disruptor::ipc::shared_region* ws_frame_info_region_ = nullptr;

    pid_t transport_pid_ = 0;
    pid_t websocket_pid_ = 0;

    [[no_unique_address]] AppHandlerType app_handler_{};
};

}  // namespace websocket::pipeline
