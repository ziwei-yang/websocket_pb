// pipeline/websocket_pipeline.hpp
// WebSocketPipeline<Traits> — single-call launcher for the full XDP→Transport→WebSocket pipeline
//
// Centralizes ALL customizable parameters in a PipelineTraits concept,
// extracts IPCRingManager, network helpers, and fork logic from test binaries.
//
// Usage:
//   struct MyTraits : DefaultPipelineConfig {
//       using SSLPolicy  = WolfSSLPolicy;
//       using AppHandler = NullAppHandler;
//       static constexpr int XDP_POLL_CORE = 2;
//       static constexpr int TRANSPORT_CORE = 4;
//       static constexpr int WEBSOCKET_CORE = 6;
//       static constexpr const char* WSS_HOST = "stream.binance.com";
//       static constexpr uint16_t WSS_PORT = 443;
//       static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade";
//   };
//   WebSocketPipeline<MyTraits> pipeline;
//   pipeline.setup(interface, bpf_path);
//   pipeline.start();
//   // ... consume ws_frame_info or AppHandler handles inline ...
//   pipeline.shutdown();
//
// C++20, policy-based design, single-thread HFT focus
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
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <csignal>

#include "pipeline_data.hpp"
#include "pipeline_config.hpp"
#include "00_xdp_poll_process.hpp"
#include "10_tcp_ssl_process.hpp"
#include "20_ws_process.hpp"
#include "21_ws_core.hpp"
#include "msg_inbox.hpp"
#include "../core/http.hpp"
#include "../net/ip_probe.hpp"

namespace websocket::pipeline {

using websocket::xdp::PacketFrameDescriptor;

// ============================================================================
// PipelineTraits Concept — defines what a Traits struct must provide
// ============================================================================

template<typename T>
concept PipelineTraitsConcept = requires {
    // ── Type policies (required, no default) ──
    typename T::SSLPolicy;
    typename T::AppHandler;
    requires AppHandlerConcept<typename T::AppHandler>;
    typename T::UpgradeCustomizer;
    requires UpgradeCustomizerConcept<typename T::UpgradeCustomizer>;

    // ── CPU core assignments (required, no default) ──
    { T::XDP_POLL_CORE }    -> std::convertible_to<int>;
    { T::TRANSPORT_CORE }   -> std::convertible_to<int>;
    { T::WEBSOCKET_CORE }   -> std::convertible_to<int>;

    // ── Target endpoint (required, no default) ──
    { T::WSS_HOST }  -> std::convertible_to<const char*>;
    { T::WSS_PORT }  -> std::convertible_to<uint16_t>;
    { T::WSS_PATH }  -> std::convertible_to<const char*>;

    // ── Feature toggles ──
    { T::ENABLE_AB }        -> std::convertible_to<bool>;
    { T::AUTO_RECONNECT }   -> std::convertible_to<bool>;
    { T::PROFILING }        -> std::convertible_to<bool>;
    { T::TRICKLE_ENABLED }  -> std::convertible_to<bool>;

    // ── IP Probe settings ──
    { T::PROBE_COUNT }             -> std::convertible_to<uint32_t>;
    { T::PROBE_TIMEOUT_MS }        -> std::convertible_to<uint32_t>;
    { T::DUAL_DEAD_THRESHOLD_MS }  -> std::convertible_to<uint64_t>;

    // ── InlineWS toggle ──
    { T::INLINE_WS }              -> std::convertible_to<bool>;
};

// ============================================================================
// DefaultPipelineConfig — sensible defaults; users inherit and override
// ============================================================================

struct DefaultPipelineConfig {
    // ── Default type policies ──
    using UpgradeCustomizer = NullUpgradeCustomizer;

    // ── Feature toggles ──
    static constexpr bool ENABLE_AB        = false;
    static constexpr bool AUTO_RECONNECT   = false;
    static constexpr bool PROFILING        = false;
    static constexpr bool TRICKLE_ENABLED  = true;

    // ── IP Probe settings ──
    static constexpr uint32_t PROBE_COUNT            = 3;
    static constexpr uint32_t PROBE_TIMEOUT_MS       = 200;
    static constexpr uint64_t DUAL_DEAD_THRESHOLD_MS = 3000;  // 3s

    // ── InlineWS ──
    static constexpr bool INLINE_WS = false;
};

// ============================================================================
// Network Helpers (extracted from test binaries)
// ============================================================================

namespace pipeline_helpers {

inline bool get_interface_mac(const char* interface, uint8_t* mac_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return false; }
    close(fd);
    memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

inline bool get_interface_ip(const char* interface, std::string& ip_out) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return false; }
    close(fd);
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    ip_out = inet_ntoa(addr->sin_addr);
    return true;
}

inline bool get_default_gateway(const char* interface, std::string& gateway_out) {
    FILE* fp = fopen("/proc/net/route", "r");
    if (!fp) return false;
    char line[256];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return false; }
    while (fgets(line, sizeof(line), fp)) {
        char iface[32];
        unsigned int dest, gateway, flags;
        if (sscanf(line, "%31s %x %x %x", iface, &dest, &gateway, &flags) >= 4) {
            if (strcmp(iface, interface) == 0 && dest == 0 && gateway != 0) {
                struct in_addr addr;
                addr.s_addr = gateway;
                gateway_out = inet_ntoa(addr);
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}

inline bool get_gateway_mac(const char* interface, const char* gateway_ip, uint8_t* mac_out) {
    FILE* fp = fopen("/proc/net/arp", "r");
    if (!fp) return false;
    char line[256];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return false; }
    while (fgets(line, sizeof(line), fp)) {
        char ip[64], hw_type[16], flags[16], mac_str[32], mask[16], dev[32];
        if (sscanf(line, "%63s %15s %15s %31s %15s %31s",
                   ip, hw_type, flags, mac_str, mask, dev) == 6) {
            if (strcmp(ip, gateway_ip) == 0 && strcmp(dev, interface) == 0) {
                unsigned int m[6];
                if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++) mac_out[i] = (uint8_t)m[i];
                    fclose(fp);
                    return true;
                }
            }
        }
    }
    fclose(fp);
    return false;
}

inline std::string resolve_hostname(const char* hostname) {
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname, nullptr, &hints, &res) != 0 || !res) {
        fprintf(stderr, "FAIL: Cannot resolve %s\n", hostname);
        return "";
    }
    auto* addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
    freeaddrinfo(res);
    printf("Resolved %s -> %s\n", hostname, ip_str);
    return ip_str;
}

inline void pin_to_cpu(int core) {
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

}  // namespace pipeline_helpers

// ============================================================================
// IPCRingManager — creates IPC ring files in /dev/shm/hft/
// ============================================================================

class IPCRingManager {
public:
    explicit IPCRingManager(const char* prefix) {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string(prefix) + "_" + timestamp;
    }

    ~IPCRingManager() { cleanup(); }

    // Non-copyable
    IPCRingManager(const IPCRingManager&) = delete;
    IPCRingManager& operator=(const IPCRingManager&) = delete;

    bool create_ring(const char* name, size_t buffer_size, size_t event_size, uint8_t max_consumers = 1) {
        std::string base_path = std::string("/dev/shm/hft/") + ipc_ring_dir_ + "/" + name;
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

    template<bool EnableAB, bool HasAppHandler, bool IsInlineWS = false>
    bool create_all_rings() {
        mkdir("/dev/shm/hft", 0755);
        std::string full_dir = "/dev/shm/hft/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "[IPC] Failed to create directory: %s\n", full_dir.c_str());
            return false;
        }

        // XDP Poll <-> Transport rings (always needed)
        if (!create_ring("raw_inbox", RAW_INBOX_SIZE * sizeof(PacketFrameDescriptor),
                         sizeof(PacketFrameDescriptor), 1)) return false;
        if (!create_ring("raw_outbox", RAW_OUTBOX_SIZE * sizeof(PacketFrameDescriptor),
                         sizeof(PacketFrameDescriptor), 1)) return false;

        // MSG_OUTBOX: always created (parent may send custom WS frames at runtime)
        if (!create_ring("msg_outbox", MSG_OUTBOX_SIZE * sizeof(MsgOutboxEvent),
                         sizeof(MsgOutboxEvent), 1)) return false;

        // Transport <-> WebSocket IPC rings (skip in InlineWS mode — no WS process)
        if constexpr (!IsInlineWS) {
            if (!create_ring("msg_metadata_a", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                             sizeof(MsgMetadata), 1)) return false;
            if constexpr (EnableAB) {
                if (!create_ring("msg_metadata_b", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                                 sizeof(MsgMetadata), 1)) return false;
            }
            if (!create_ring("pongs", PONGS_SIZE * sizeof(PongFrameAligned),
                             sizeof(PongFrameAligned), 1)) return false;
        }

        // WebSocket <-> Parent ring (skip when AppHandler replaces it)
        if constexpr (!HasAppHandler) {
            if (!create_ring("ws_frame_info", WS_FRAME_INFO_SIZE * sizeof(WSFrameInfo),
                             sizeof(WSFrameInfo), 1)) return false;
        }

        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;
        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = {
            "raw_inbox", "raw_outbox",
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
    std::string ipc_ring_dir_;
};

// ============================================================================
// WebSocketPipeline<Traits> — concept-constrained pipeline launcher
// ============================================================================

template<PipelineTraitsConcept Traits>
class WebSocketPipeline {
public:
    // ── Derived constants ──
    static constexpr bool EnableAB       = Traits::ENABLE_AB;
    static constexpr bool AutoReconnect  = Traits::AUTO_RECONNECT;
    static constexpr bool Prof           = Traits::PROFILING;
    static constexpr bool InlineWS       = Traits::INLINE_WS;
    static constexpr size_t NUM_CONN     = EnableAB ? 2 : 1;
    static constexpr bool HasAppHandler  = Traits::AppHandler::enabled;

    // InlineWS requires AutoReconnect
    static_assert(!InlineWS || AutoReconnect,
                  "INLINE_WS requires AUTO_RECONNECT=true");

    // ── Process type aliases ──
    using SSLPolicyType = typename Traits::SSLPolicy;
    using AppHandlerType = typename Traits::AppHandler;
    using UpgradeCustomizerType = typename Traits::UpgradeCustomizer;

    using XDPPollType = XDPPollProcess<
        IPCRingProducer<PacketFrameDescriptor>,
        IPCRingConsumer<PacketFrameDescriptor>,
        Traits::TRICKLE_ENABLED,
        Prof>;

    // --- IPC mode types (non-InlineWS) ---
    using TransportType = TransportProcess<
        SSLPolicyType,
        IPCRingProducer<MsgMetadata>,
        IPCRingConsumer<PongFrameAligned>,
        EnableAB, AutoReconnect, Prof>;

    using WebSocketType = WebSocketProcess<
        IPCRingConsumer<MsgMetadata>,
        IPCRingProducer<WSFrameInfo>,
        IPCRingProducer<PongFrameAligned>,
        IPCRingProducer<MsgOutboxEvent>,
        EnableAB, AutoReconnect, Prof,
        AppHandlerType,
        UpgradeCustomizerType>;

    // --- Inline mode types (InlineWS) ---
    using InlineWSCoreType = WSCore<
        DirectTXSink<SSLPolicyType, EnableAB>,
        IPCRingProducer<WSFrameInfo>,
        EnableAB, AutoReconnect, Prof,
        AppHandlerType,
        UpgradeCustomizerType>;

    using InlineTransportType = TransportProcess<
        SSLPolicyType,
        NullRingAdapter,
        NullRingAdapter,
        EnableAB, AutoReconnect, Prof,
        InlineWSCoreType>;

    // ========================================================================
    // Lifecycle
    // ========================================================================

    WebSocketPipeline() : ipc_manager_("websocket_pipeline") {}

    ~WebSocketPipeline() { shutdown(); }

    // Non-copyable
    WebSocketPipeline(const WebSocketPipeline&) = delete;
    WebSocketPipeline& operator=(const WebSocketPipeline&) = delete;

    bool setup(const char* interface, const char* bpf_path) {
        interface_ = interface;
        bpf_path_ = bpf_path;

        printf("\n=== Setting up WebSocket Pipeline%s ===\n", InlineWS ? " (InlineWS)" : "");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);
        if constexpr (InlineWS) {
            printf("Mode:        InlineWS (transport + WS in single process, 2-process total)\n");
        }

        // IP Probe: resolve all IPs, measure RTT, rank
        {
            websocket::net::ProbeConfig probe_cfg;
            probe_cfg.port        = Traits::WSS_PORT;
            probe_cfg.probe_count = Traits::PROBE_COUNT;
            probe_cfg.timeout_ms  = Traits::PROBE_TIMEOUT_MS;
            probe_cfg.family      = AF_INET;  // Pipeline is IPv4 only (BPF filter)

            // Detect non-XDP probe interface
            probe_iface_ = websocket::net::detect_probe_interface(interface_);
            if (!probe_iface_.empty()) {
                probe_cfg.bind_interface = probe_iface_.c_str();
            }

            probe_result_ = websocket::net::probe(Traits::WSS_HOST, probe_cfg);
            websocket::net::print_probe_result(probe_result_);

            if (!probe_result_.ok()) {
                fprintf(stderr, "FAIL: IP probe for %s: %s (%s)\n",
                        Traits::WSS_HOST, websocket::net::probe_status_str(probe_result_.status),
                        probe_result_.error);
                return false;
            }

            // Build selector with latency filtering
            websocket::net::IpSelector selector;
            if (selector.build(probe_result_) != 0) {
                fprintf(stderr, "FAIL: No reachable IPs for %s\n", Traits::WSS_HOST);
                return false;
            }

            // Assign per-connection IPs
            if constexpr (EnableAB) {
                const websocket::net::ProbeEntry* ip_a = nullptr;
                const websocket::net::ProbeEntry* ip_b = nullptr;
                if (selector.assign_dual(ip_a, ip_b)) {
                    conn_target_ip_[0] = ip_a->ipv4_net();
                    conn_target_ip_[1] = ip_b->ipv4_net();
                } else {
                    // Single IP available — both connections use it
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
            wss_target_ip_ = probe_result_.entries[0].ip_str;
        }
        printf("Path:        %s\n\n", Traits::WSS_PATH);

        tsc_freq_ghz_ = pipeline_helpers::calibrate_tsc_ghz();

        // Get interface MAC
        if (!pipeline_helpers::get_interface_mac(interface_, local_mac_)) {
            fprintf(stderr, "FAIL: Cannot get MAC address for %s\n", interface_);
            return false;
        }
        printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_mac_[0], local_mac_[1], local_mac_[2],
               local_mac_[3], local_mac_[4], local_mac_[5]);

        // Get interface IP
        if (!pipeline_helpers::get_interface_ip(interface_, local_ip_)) {
            fprintf(stderr, "FAIL: Cannot get IP address for %s\n", interface_);
            return false;
        }
        printf("Local IP:  %s\n", local_ip_.c_str());

        // Get gateway
        if (!pipeline_helpers::get_default_gateway(interface_, gateway_ip_)) {
            fprintf(stderr, "FAIL: Cannot get gateway for %s\n", interface_);
            return false;
        }
        printf("Gateway:   %s\n", gateway_ip_.c_str());

        // Ping gateway to populate ARP cache
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s >/dev/null 2>&1", gateway_ip_.c_str());
        [[maybe_unused]] int ping_ret = system(cmd);

        if (!pipeline_helpers::get_gateway_mac(interface_, gateway_ip_.c_str(), gateway_mac_)) {
            fprintf(stderr, "FAIL: Cannot get gateway MAC for %s\n", gateway_ip_.c_str());
            return false;
        }
        printf("Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               gateway_mac_[0], gateway_mac_[1], gateway_mac_[2],
               gateway_mac_[3], gateway_mac_[4], gateway_mac_[5]);

        // Create IPC rings (InlineWS skips transport↔WS rings)
        if (!ipc_manager_.template create_all_rings<EnableAB, HasAppHandler, InlineWS>()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        // Allocate UMEM
        umem_size_ = UMEM_TOTAL_SIZE;
        umem_area_ = mmap(nullptr, umem_size_, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (umem_area_ == MAP_FAILED) {
            printf("WARN: Huge pages not available, using regular pages\n");
            umem_area_ = mmap(nullptr, umem_size_, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            if (umem_area_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate UMEM\n");
                return false;
            }
        }
        printf("UMEM: %p (%zu bytes)\n", umem_area_, umem_size_);

        // Allocate MsgInbox per connection
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
        strncpy(conn_state_->bpf_path, bpf_path_, sizeof(conn_state_->bpf_path) - 1);
        strncpy(conn_state_->interface_name, interface_, sizeof(conn_state_->interface_name) - 1);

        struct in_addr addr;
        inet_aton(local_ip_.c_str(), &addr);
        conn_state_->local_ip = addr.s_addr;
        memcpy(conn_state_->local_mac, local_mac_, 6);
        memcpy(conn_state_->remote_mac, gateway_mac_, 6);
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(tsc_freq_ghz_ * 1e9);

        // IP probe target IPs and interface
        conn_state_->conn_target_ip[0] = conn_target_ip_[0];
        conn_state_->conn_target_ip[1] = conn_target_ip_[1];
        strncpy(conn_state_->probe_interface, probe_iface_.c_str(),
                sizeof(conn_state_->probe_interface) - 1);

        // Populate exchange_ips[] from DNS probe for BPF filter + reconnect pool
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

        // Allocate ProfilingShm
        if constexpr (Prof) {
            profiling_ = static_cast<ProfilingShm*>(
                mmap(nullptr, sizeof(ProfilingShm), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0));
            if (profiling_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate ProfilingShm\n");
                return false;
            }
            profiling_->init();
        }

        // Open shared regions
        try {
            raw_inbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_inbox"));
            raw_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_outbox"));
            // MSG_OUTBOX always opened (parent may send custom WS frames)
            msg_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_outbox"));
            if constexpr (!InlineWS) {
                msg_metadata_region_[0] = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata_a"));
                if constexpr (EnableAB) {
                    msg_metadata_region_[1] = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata_b"));
                }
                pongs_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pongs"));
            }
            if constexpr (!HasAppHandler) {
                ws_frame_info_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("ws_frame_info"));
            }
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
            return false;
        }

        printf("=== Pipeline Setup Complete ===\n\n");
        return true;
    }

    bool start() {
        // Fork XDP Poll process
        xdp_pid_ = fork();
        if (xdp_pid_ < 0) { fprintf(stderr, "FAIL: fork() for XDP Poll\n"); return false; }
        if (xdp_pid_ == 0) { run_xdp_poll_process(); _exit(0); }
        printf("[PIPELINE] Forked XDP Poll (PID %d, core %d)\n", xdp_pid_, Traits::XDP_POLL_CORE);

        // Wait for XDP ready
        if (!conn_state_->wait_for_handshake_xdp_ready(10000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for XDP Poll ready\n");
            return false;
        }

        // Flush before fork
        fflush(stdout);

        if constexpr (InlineWS) {
            // InlineWS: single Transport+WS child process (2 total with XDP Poll)
            transport_pid_ = fork();
            if (transport_pid_ < 0) { fprintf(stderr, "FAIL: fork() for InlineWS Transport\n"); return false; }
            if (transport_pid_ == 0) { run_inline_transport_process(); _exit(0); }
            printf("[PIPELINE] Forked InlineWS Transport (PID %d, core %d, %s)\n",
                   transport_pid_, Traits::TRANSPORT_CORE, SSLPolicyType::name());

            // Wait for WS ready (transport handles TLS + WS handshake internally)
            if (!conn_state_->wait_for_handshake_ws_ready(30000000)) {
                fprintf(stderr, "FAIL: InlineWS handshake timeout\n");
                return false;
            }
            printf("[PIPELINE] InlineWS transport ready (2 processes, MSG_OUTBOX for client sends)\n");
        } else {
            // Standard 3-process mode: XDP Poll + Transport + WS
            transport_pid_ = fork();
            if (transport_pid_ < 0) { fprintf(stderr, "FAIL: fork() for Transport\n"); return false; }
            if (transport_pid_ == 0) { run_transport_process(); _exit(0); }
            printf("[PIPELINE] Forked Transport (PID %d, core %d, %s)\n",
                   transport_pid_, Traits::TRANSPORT_CORE, SSLPolicyType::name());

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

            // Flush before fork
            fflush(stdout);

            // Fork WebSocket process
            websocket_pid_ = fork();
            if (websocket_pid_ < 0) { fprintf(stderr, "FAIL: fork() for WebSocket\n"); return false; }
            if (websocket_pid_ == 0) { run_websocket_process(); _exit(0); }
            printf("[PIPELINE] Forked WebSocket (PID %d, core %d)\n",
                   websocket_pid_, Traits::WEBSOCKET_CORE);

            // Wait for WS ready
            if (!conn_state_->wait_for_handshake_ws_ready(30000000)) {
                fprintf(stderr, "FAIL: WebSocket handshake timeout\n");
                return false;
            }
            printf("[PIPELINE] All processes ready\n");
        }
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
        reap(xdp_pid_, "XDP-Poll");
        reap(transport_pid_, "Transport");
        if constexpr (!InlineWS) {
            reap(websocket_pid_, "WebSocket");
        }

        // Cleanup shared regions
        delete raw_inbox_region_; raw_inbox_region_ = nullptr;
        delete raw_outbox_region_; raw_outbox_region_ = nullptr;
        delete msg_outbox_region_; msg_outbox_region_ = nullptr;
        if constexpr (!InlineWS) {
            for (size_t i = 0; i < NUM_CONN; i++) {
                delete msg_metadata_region_[i]; msg_metadata_region_[i] = nullptr;
            }
            delete pongs_region_; pongs_region_ = nullptr;
        }
        delete ws_frame_info_region_; ws_frame_info_region_ = nullptr;

        if (conn_state_ && conn_state_ != MAP_FAILED) {
            munmap(conn_state_, sizeof(ConnStateShm)); conn_state_ = nullptr;
        }
        for (size_t i = 0; i < NUM_CONN; i++) {
            if (msg_inbox_[i] && msg_inbox_[i] != MAP_FAILED) {
                munmap(msg_inbox_[i], sizeof(MsgInbox)); msg_inbox_[i] = nullptr;
            }
        }
        if constexpr (Prof) {
            if (profiling_ && profiling_ != MAP_FAILED) {
                munmap(profiling_, sizeof(ProfilingShm)); profiling_ = nullptr;
            }
        }
        if (umem_area_ && umem_area_ != MAP_FAILED) {
            munmap(umem_area_, umem_size_); umem_area_ = nullptr;
        }
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    ConnStateShm* conn_state() { return conn_state_; }
    MsgInbox* msg_inbox(uint8_t ci) { return msg_inbox_[ci]; }
    ProfilingShm* profiling() { return profiling_; }
    double tsc_freq_ghz() const { return tsc_freq_ghz_; }
    const std::string& local_ip() const { return local_ip_; }
    const std::string& wss_target_ip() const { return wss_target_ip_; }

    // WSFrameInfo region — only available when !HasAppHandler
    disruptor::ipc::shared_region* ws_frame_info_region() {
        static_assert(!HasAppHandler, "No WSFrameInfo ring when AppHandler is active");
        return ws_frame_info_region_;
    }

    // Ring regions for monitoring
    disruptor::ipc::shared_region* msg_metadata_region(uint8_t ci) { return msg_metadata_region_[ci]; }
    disruptor::ipc::shared_region* msg_outbox_region() { return msg_outbox_region_; }
    disruptor::ipc::shared_region* pongs_region() { return pongs_region_; }

    // Pre-fork handler config
    AppHandlerType& app_handler() { return app_handler_; }

    // IPC ring manager (for ring name access, e.g. subscription_json)
    void set_subscription_json(const char* json) {
        strncpy(conn_state_->subscription_json, json, sizeof(conn_state_->subscription_json) - 1);
    }

    void save_profiling_data() {
        if constexpr (!Prof) return;
        if (!profiling_) return;

        pid_t pid = getpid();
        auto save_buffer = [pid](const CycleSampleBuffer& buf, const char* name) {
            char filename[256];
            snprintf(filename, sizeof(filename), "/tmp/%s_profiling_%d.bin", name, pid);
            FILE* f = fopen(filename, "wb");
            if (!f) { fprintf(stderr, "[PROFILING] Failed to create %s\n", filename); return; }
            uint32_t committed = buf.write_idx;
            uint32_t count = std::min(committed, CycleSampleBuffer::SAMPLE_COUNT);
            uint32_t start_idx = (committed > CycleSampleBuffer::SAMPLE_COUNT)
                ? (committed & CycleSampleBuffer::MASK) : 0;
            fwrite(&buf.total_count, sizeof(uint32_t), 1, f);
            fwrite(&count, sizeof(uint32_t), 1, f);
            for (uint32_t i = 0; i < count; ++i) {
                uint32_t idx = (start_idx + i) & CycleSampleBuffer::MASK;
                fwrite(&buf.samples[idx], sizeof(CycleSample), 1, f);
            }
            fclose(f);
            printf("[PROFILING] %s saved to %s (%u samples, %u total)\n", name, filename, count, buf.total_count);
        };
        save_buffer(profiling_->xdp_poll, "xdp_poll");
        save_buffer(profiling_->transport, "transport");
        save_buffer(profiling_->ws_process, "ws_process");

        // NIC latency
        {
            char filename[256];
            snprintf(filename, sizeof(filename), "/tmp/nic_latency_profiling_%d.bin", pid);
            FILE* f = fopen(filename, "wb");
            if (!f) return;
            const auto& buf = profiling_->nic_latency;
            uint32_t count = std::min(buf.total_count, NicLatencyBuffer::SAMPLE_COUNT);
            uint32_t start_idx = (buf.total_count > NicLatencyBuffer::SAMPLE_COUNT)
                ? (buf.write_idx & NicLatencyBuffer::MASK) : 0;
            fwrite(&buf.total_count, sizeof(uint32_t), 1, f);
            fwrite(&count, sizeof(uint32_t), 1, f);
            for (uint32_t i = 0; i < count; ++i) {
                uint32_t idx = (start_idx + i) & NicLatencyBuffer::MASK;
                fwrite(&buf.samples[idx], sizeof(NicLatencySample), 1, f);
            }
            fclose(f);
            printf("[PROFILING] nic_latency saved to %s (%u samples, %u total)\n", filename, count, buf.total_count);
        }
    }

private:
    // ========================================================================
    // Child process entry points
    // ========================================================================

    void run_xdp_poll_process() {
        pipeline_helpers::pin_to_cpu(Traits::XDP_POLL_CORE);

        IPCRingProducer<PacketFrameDescriptor> raw_inbox_prod(*raw_inbox_region_);
        IPCRingConsumer<PacketFrameDescriptor> raw_outbox_cons(*raw_outbox_region_);
        XDPPollType xdp_poll(interface_);

        if constexpr (Prof) {
            xdp_poll.set_profiling_data(&profiling_->xdp_poll);
            xdp_poll.set_nic_latency_data(&profiling_->nic_latency);
        }

        bool ok = xdp_poll.init(umem_area_, umem_size_, bpf_path_,
                                &raw_inbox_prod, &raw_outbox_cons, conn_state_);
        if (!ok) { conn_state_->shutdown_all(); return; }

        auto* bpf = xdp_poll.get_bpf_loader();
        if (bpf) {
            bpf->set_local_ip(local_ip_.c_str());
            // Add ALL resolved IPs to BPF filter (not just the primary target)
            for (const auto& e : probe_result_.entries) {
                if (e.family == AF_INET) {
                    bpf->add_exchange_ip(e.ip_str);
                }
            }
            bpf->add_exchange_port(Traits::WSS_PORT);
        }

        xdp_poll.run();
        xdp_poll.cleanup();
    }

    void run_transport_process() {
        pipeline_helpers::pin_to_cpu(Traits::TRANSPORT_CORE);

        IPCRingConsumer<PacketFrameDescriptor> raw_inbox_cons(*raw_inbox_region_);
        IPCRingProducer<PacketFrameDescriptor> raw_outbox_prod(*raw_outbox_region_);
        IPCRingProducer<MsgMetadata> msg_metadata_prod_a(*msg_metadata_region_[0]);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);
        IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(*msg_outbox_region_);

        char url[512];
        snprintf(url, sizeof(url), "wss://%s:%u%s",
                 Traits::WSS_HOST, Traits::WSS_PORT, Traits::WSS_PATH);

        if constexpr (EnableAB) {
            IPCRingProducer<MsgMetadata> msg_metadata_prod_b(*msg_metadata_region_[1]);
            TransportType transport(url, umem_area_, FRAME_SIZE,
                &raw_inbox_cons, &raw_outbox_prod,
                msg_inbox_[0], &msg_metadata_prod_a, &pongs_cons,
                conn_state_, &msg_outbox_cons,
                msg_inbox_[1], &msg_metadata_prod_b);
            if constexpr (Prof) transport.set_profiling_data(&profiling_->transport);
            if (!transport.init()) { conn_state_->shutdown_all(); return; }
            transport.run();
            transport.cleanup();
        } else {
            TransportType transport(url, umem_area_, FRAME_SIZE,
                &raw_inbox_cons, &raw_outbox_prod,
                msg_inbox_[0], &msg_metadata_prod_a, &pongs_cons,
                conn_state_, &msg_outbox_cons);
            if constexpr (Prof) transport.set_profiling_data(&profiling_->transport);
            if (!transport.init()) { conn_state_->shutdown_all(); return; }
            transport.run();
            transport.cleanup();
        }
    }

    void run_websocket_process() {
        pipeline_helpers::pin_to_cpu(Traits::WEBSOCKET_CORE);

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

        // WSFrameInfo producer — created always (template param requires the type),
        // but only wired to the ring when !HasAppHandler
        WSFrameInfoProdHelper ws_frame_info_prod_holder(ws_frame_info_region_);

        WebSocketType ws_process;
        ws_process.app_handler() = app_handler_;

        if constexpr (Prof) ws_process.set_profiling_data(&profiling_->ws_process);

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

    void run_inline_transport_process() {
        static_assert(InlineWS, "run_inline_transport_process() only valid when INLINE_WS=true");
        pipeline_helpers::pin_to_cpu(Traits::TRANSPORT_CORE);

        IPCRingConsumer<PacketFrameDescriptor> raw_inbox_cons(*raw_inbox_region_);
        IPCRingProducer<PacketFrameDescriptor> raw_outbox_prod(*raw_outbox_region_);
        IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(*msg_outbox_region_);

        // WSFrameInfo producer — transport → parent
        std::unique_ptr<IPCRingProducer<WSFrameInfo>> ws_frame_info_prod_holder;
        if constexpr (!HasAppHandler) {
            ws_frame_info_prod_holder = std::make_unique<IPCRingProducer<WSFrameInfo>>(
                *ws_frame_info_region_);
        }

        char url[512];
        snprintf(url, sizeof(url), "wss://%s:%u%s",
                 Traits::WSS_HOST, Traits::WSS_PORT, Traits::WSS_PATH);

        // InlineTransportType: MsgMetadataProd=NullRingAdapter, LowPrioCons=NullRingAdapter
        // MsgOutboxCons is real (parent sends), WSProcessor=InlineWSCoreType
        InlineTransportType transport(url, umem_area_, FRAME_SIZE,
            &raw_inbox_cons, &raw_outbox_prod,
            msg_inbox_[0], nullptr, nullptr,
            conn_state_, &msg_outbox_cons,
            EnableAB ? msg_inbox_[1] : nullptr, nullptr);
        transport.inline_app_handler() = app_handler_;

        if constexpr (Prof) transport.set_profiling_data(&profiling_->transport);
        if (!transport.init()) { conn_state_->shutdown_all(); return; }

        // Wire WSCore to msg_inbox, ws_frame_info_prod, DirectTXSink
        if constexpr (EnableAB) {
            transport.init_inline(ws_frame_info_prod_holder.get(), conn_state_,
                                  msg_inbox_[0], msg_inbox_[1]);
        } else {
            transport.init_inline(ws_frame_info_prod_holder.get(), conn_state_,
                                  msg_inbox_[0]);
        }

        transport.run();
        transport.cleanup();
    }

    // Helper to conditionally create WSFrameInfo producer
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

    // ========================================================================
    // Member Variables
    // ========================================================================

    const char* interface_ = nullptr;
    const char* bpf_path_ = nullptr;
    std::string wss_target_ip_;
    std::string local_ip_;
    std::string gateway_ip_;
    std::string probe_iface_;
    double tsc_freq_ghz_ = 0.0;
    uint32_t conn_target_ip_[NUM_CONN]{};
    websocket::net::ProbeResult probe_result_;

    IPCRingManager ipc_manager_;

    void* umem_area_ = nullptr;
    size_t umem_size_ = 0;
    uint8_t local_mac_[6] = {};
    uint8_t gateway_mac_[6] = {};

    MsgInbox* msg_inbox_[NUM_CONN]{};
    ConnStateShm* conn_state_ = nullptr;
    ProfilingShm* profiling_ = nullptr;

    disruptor::ipc::shared_region* raw_inbox_region_ = nullptr;
    disruptor::ipc::shared_region* raw_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_metadata_region_[NUM_CONN]{};
    disruptor::ipc::shared_region* pongs_region_ = nullptr;
    disruptor::ipc::shared_region* ws_frame_info_region_ = nullptr;

    pid_t xdp_pid_ = 0;
    pid_t transport_pid_ = 0;
    pid_t websocket_pid_ = 0;

    [[no_unique_address]] AppHandlerType app_handler_{};
};

}  // namespace websocket::pipeline
