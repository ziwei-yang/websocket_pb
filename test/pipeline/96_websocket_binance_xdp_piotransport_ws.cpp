// test/pipeline/96_websocket_binance.cpp
// Test XDP Poll + PIO Transport + WebSocket Process against Binance WSS stream
//
// Architecture (3 child processes):
//   - Child 1 (Core 2): XDPPollProcess - XDP kernel interface
//   - Child 2 (Core 4): PIOTransportProcess - TCP + SSL via DisruptorPacketIO
//   - Child 3 (Core 6): WebSocketProcess - WS frame parsing
//   - Parent: Consumes WS_FRAME_INFO, prints latency
//
// Data Flow:
//   XDP Poll (Core 2)           PIO Transport (Core 4)      WebSocket (Core 6)
//   ┌────────────────┐          ┌─────────────────────┐     ┌─────────────────┐
//   │ XDP → RAW_INBOX ──────────→ DisruptorPacketIO   │     │                 │
//   │                │          │      ↓              │     │                 │
//   │ XDP ← RAW_OUTBOX ◄─────────────PacketTransport  │     │                 │
//   │                │          │      ↓              │     │                 │
//   └────────────────┘          │  TCP + SSL         │     │                 │
//          │                    │      ↓              │     │                 │
//          └─── Shared UMEM ────│ MSG_INBOX ─────────────────→ WS Parse      │
//                               │ MSG_METADATA ──────────────→              │
//                               │              ◄─────────────── PONGS       │
//                               └─────────────────────┘     │ WS_FRAME_INFO ──→ Parent
//                                                           └─────────────────┘
//
// Usage: ./test_pipeline_96_websocket_binance <interface> <bpf_path> [--timeout <ms>]
//
// Build: ./scripts/build_xdp.sh 96_websocket_binance.cpp
//
// Options:
//   --timeout <ms>   Stream timeout in milliseconds (default: 5000)
//                    If <= 0, run forever and display every message received

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>

#ifdef USE_XDP

#define DEBUG 0
#define DEBUG_IPC 0

// pipeline_data.hpp must be included FIRST as it includes disruptor headers
// before pipeline_config.hpp to avoid CACHE_LINE_SIZE macro conflict
#include "../../src/pipeline/pipeline_data.hpp"
#include "../../src/pipeline/00_xdp_poll_process.hpp"
#include "../../src/pipeline/10_tcp_ssl_process.hpp"
#include "../../src/pipeline/20_ws_process.hpp"
#include "../../src/pipeline/msg_inbox.hpp"
#include "../../src/core/http.hpp"
#include "../../src/policy/ssl.hpp"

using namespace websocket::pipeline;
using namespace websocket::ssl;
using websocket::xdp::PacketFrameDescriptor;

// Select SSL policy based on compile-time flags
#if defined(USE_OPENSSL)
using SSLPolicyType = OpenSSLPolicy;
#elif defined(USE_WOLFSSL)
using SSLPolicyType = WolfSSLPolicy;
#else
#error "Must define USE_OPENSSL or USE_WOLFSSL"
#endif

// ============================================================================
// Configuration
// ============================================================================

namespace {

// CPU core assignments (3 processes)
constexpr int XDP_POLL_CPU_CORE = 2;     // XDP Poll process
constexpr int PIO_TRANSPORT_CPU_CORE = 4; // PIO Transport process
constexpr int WEBSOCKET_CPU_CORE = 6;     // WebSocket parsing process

// Test parameters
constexpr int DEFAULT_STREAM_DURATION_MS = 5000;
constexpr int FINAL_DRAIN_MS = 2000;
constexpr int MIN_EXPECTED_TRADES = 10;

// Runtime timeout
int g_timeout_ms = DEFAULT_STREAM_DURATION_MS;

// WebSocket target
static constexpr const char* WSS_HOST = "stream.binance.com";
static constexpr uint16_t WSS_PORT = 443;
static constexpr const char* WSS_PATH = "/stream?streams=btcusdt@trade";

// Global shutdown flag and connection state pointer for signal handler
std::atomic<bool> g_shutdown{false};
ConnStateShm* g_conn_state = nullptr;

void signal_handler(int sig) {
    g_shutdown.store(true, std::memory_order_release);
    if (g_conn_state) {
        g_conn_state->shutdown_all();
    }
    fprintf(stderr, "\n[SIGNAL] Received signal %d, initiating graceful shutdown...\n", sig);
}

// Pin current process to specified CPU core with SCHED_FIFO priority
void pin_to_cpu(int core) {
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

uint64_t get_monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}

// TSC frequency calibration
double g_tsc_freq_ghz = 0.0;

void calibrate_tsc() {
    uint64_t start_tsc = rdtsc();
    uint64_t start_ns = get_monotonic_ns();
    usleep(100000);  // 100ms
    uint64_t end_tsc = rdtsc();
    uint64_t end_ns = get_monotonic_ns();

    uint64_t elapsed_tsc = end_tsc - start_tsc;
    uint64_t elapsed_ns = end_ns - start_ns;
    g_tsc_freq_ghz = static_cast<double>(elapsed_tsc) / static_cast<double>(elapsed_ns);
    printf("[TSC] Calibrated: %.3f GHz\n", g_tsc_freq_ghz);
}

// Validate Binance trade JSON
bool is_valid_trade_json(const char* data, size_t len) {
    std::string_view sv(data, len);
    if (sv.find("\"stream\"") == std::string_view::npos) return false;
    if (sv.find("btcusdt@trade") == std::string_view::npos) return false;
    if (sv.find("\"data\"") == std::string_view::npos) return false;
    if (sv.find("\"e\":\"trade\"") == std::string_view::npos) return false;
    return true;
}

// Parse "E" field (event timestamp) from Binance JSON
uint64_t parse_event_time(const uint8_t* payload, size_t len) {
    const char* e_pos = (const char*)memmem(payload, len, "\"E\":", 4);
    if (e_pos) {
        return strtoull(e_pos + 4, nullptr, 10);
    }
    return 0;
}

// ============================================================================
// Frame Recording (NIC-to-message latency)
// ============================================================================

static constexpr size_t MAX_FRAME_RECORDS = 65536;

void dump_frame_records(const WSFrameInfo* records, size_t count, const char* tag) {
    if (count == 0) return;
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s_frame_records_%d.bin", tag, getpid());
    FILE* f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "Failed to create %s\n", path); return; }
    uint32_t n = static_cast<uint32_t>(count);
    uint32_t sz = static_cast<uint32_t>(sizeof(WSFrameInfo));
    fwrite(&n, 4, 1, f);
    fwrite(&sz, 4, 1, f);
    fwrite(records, sizeof(WSFrameInfo), count, f);
    fclose(f);
    printf("[FRAME-RECORDS] Saved %u records to %s\n", n, path);
}

}  // namespace

// ============================================================================
// IPC Ring Creation
// ============================================================================

class IPCRingManager {
public:
    IPCRingManager() {
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string("websocket_96_test_") + timestamp;
    }

    ~IPCRingManager() {
        cleanup();
    }

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
        if (ftruncate(hdr_fd, header_size) < 0) {
            close(hdr_fd);
            return false;
        }
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
        if (dat_ptr == MAP_FAILED) {
            unlink(hdr_path.c_str());
            return false;
        }
        memset(dat_ptr, 0, buffer_size);
        munmap(dat_ptr, buffer_size);

        return true;
    }

    bool create_all_rings() {
        mkdir("/dev/shm/hft", 0755);
        std::string full_dir = "/dev/shm/hft/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "[IPC] Failed to create directory: %s\n", full_dir.c_str());
            return false;
        }

        // XDP Poll <-> PIO Transport rings (unified RAW_OUTBOX for all TX)
        if (!create_ring("raw_inbox", RAW_INBOX_SIZE * sizeof(PacketFrameDescriptor),
                         sizeof(PacketFrameDescriptor), 1)) return false;
        if (!create_ring("raw_outbox", RAW_OUTBOX_SIZE * sizeof(PacketFrameDescriptor),
                         sizeof(PacketFrameDescriptor), 1)) return false;

        // PIO Transport <-> WebSocket rings
        if (!create_ring("msg_outbox", MSG_OUTBOX_SIZE * sizeof(MsgOutboxEvent),
                         sizeof(MsgOutboxEvent), 1)) return false;
        if (!create_ring("msg_metadata", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                         sizeof(MsgMetadata), 1)) return false;
        if (!create_ring("pongs", PONGS_SIZE * sizeof(PongFrameAligned),
                         sizeof(PongFrameAligned), 1)) return false;

        // WebSocket <-> Parent ring
        if (!create_ring("ws_frame_info", WS_FRAME_INFO_SIZE * sizeof(WSFrameInfo),
                         sizeof(WSFrameInfo), 1)) return false;

        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup() {
        if (ipc_ring_dir_.empty()) return;

        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = {
            "raw_inbox", "raw_outbox",
            "msg_outbox", "msg_metadata", "pongs", "ws_frame_info"
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
// Type Aliases
// ============================================================================

// XDP Poll Process type
using XDPPollType = XDPPollProcess<
    IPCRingProducer<PacketFrameDescriptor>,
    IPCRingConsumer<PacketFrameDescriptor>,
    true,   // TrickleEnabled
    false>; // Profiling

// Transport Process type (with profiling enabled)
using TransportType = TransportProcess<
    SSLPolicyType,
    IPCRingProducer<MsgMetadata>,
    IPCRingConsumer<PongFrameAligned>,
    true>;  // Profiling

// WebSocket Process type
using WebSocketType = WebSocketProcess<
    IPCRingConsumer<MsgMetadata>,
    IPCRingProducer<WSFrameInfo>,
    IPCRingProducer<PongFrameAligned>,
    IPCRingProducer<MsgOutboxEvent>>;

// ============================================================================
// Test Class
// ============================================================================

class WebSocket96Test {
public:
    WebSocket96Test(const char* interface, const char* bpf_path)
        : interface_(interface), bpf_path_(bpf_path) {}

    bool setup() {
        printf("\n=== Setting up WebSocket 96 Test (3-Process Architecture) ===\n");
        printf("Interface:   %s\n", interface_);
        printf("BPF Path:    %s\n", bpf_path_);
        printf("Target:      %s:%u\n", WSS_HOST, WSS_PORT);
        printf("Path:        %s\n\n", WSS_PATH);

        calibrate_tsc();

        // Create IPC rings
        if (!ipc_manager_.create_all_rings()) {
            fprintf(stderr, "FAIL: Cannot create IPC rings\n");
            return false;
        }

        // Allocate UMEM (shared between XDP Poll and PIO Transport)
        umem_area_ = mmap(nullptr, UMEM_TOTAL_SIZE,
                          PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB,
                          -1, 0);
        if (umem_area_ == MAP_FAILED) {
            // Fall back to regular pages
            umem_area_ = mmap(nullptr, UMEM_TOTAL_SIZE,
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS,
                              -1, 0);
            if (umem_area_ == MAP_FAILED) {
                fprintf(stderr, "FAIL: Cannot allocate UMEM\n");
                return false;
            }
            printf("[UMEM] Allocated %zu bytes (regular pages)\n", UMEM_TOTAL_SIZE);
        } else {
            printf("[UMEM] Allocated %zu bytes (huge pages)\n", UMEM_TOTAL_SIZE);
        }

        // Allocate MsgInbox (shared)
        msg_inbox_ = static_cast<MsgInbox*>(
            mmap(nullptr, sizeof(MsgInbox),
                 PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS,
                 -1, 0));
        if (msg_inbox_ == MAP_FAILED) {
            fprintf(stderr, "FAIL: Cannot allocate MsgInbox\n");
            return false;
        }
        msg_inbox_->init();
        printf("MsgInbox: %p\n", msg_inbox_);

        // Allocate ConnStateShm (shared)
        conn_state_ = static_cast<ConnStateShm*>(
            mmap(nullptr, sizeof(ConnStateShm),
                 PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS,
                 -1, 0));
        if (conn_state_ == MAP_FAILED) {
            fprintf(stderr, "FAIL: Cannot allocate ConnStateShm\n");
            return false;
        }
        conn_state_->init();

        // Set target configuration
        strncpy(conn_state_->target_host, WSS_HOST, sizeof(conn_state_->target_host) - 1);
        conn_state_->target_port = WSS_PORT;
        strncpy(conn_state_->target_path, WSS_PATH, sizeof(conn_state_->target_path) - 1);
        strncpy(conn_state_->bpf_path, bpf_path_, sizeof(conn_state_->bpf_path) - 1);
        strncpy(conn_state_->interface_name, interface_, sizeof(conn_state_->interface_name) - 1);

        // Set TSC frequency
        conn_state_->tsc_freq_hz = static_cast<uint64_t>(g_tsc_freq_ghz * 1e9);

        // Resolve DNS and store exchange IPs for XDP Poll to configure BPF filter
        printf("[DNS] Resolving %s...\n", WSS_HOST);
        if (!resolve_and_store_exchange_ips(WSS_HOST)) {
            fprintf(stderr, "FAIL: Cannot resolve %s\n", WSS_HOST);
            return false;
        }

        printf("ConnStateShm: %p\n", conn_state_);

        // Open shared regions
        try {
            raw_inbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_inbox"));
            raw_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("raw_outbox"));
            msg_outbox_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_outbox"));
            msg_metadata_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("msg_metadata"));
            pongs_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("pongs"));
            ws_frame_info_region_ = new disruptor::ipc::shared_region(ipc_manager_.get_ring_name("ws_frame_info"));
        } catch (const std::exception& e) {
            fprintf(stderr, "FAIL: Cannot open shared regions: %s\n", e.what());
            return false;
        }

        printf("=== Setup Complete ===\n\n");
        return true;
    }

    void teardown() {
        printf("\n=== Teardown ===\n");

        if (conn_state_) conn_state_->shutdown_all();
        g_shutdown.store(true);

        // Wait for child processes
        if (xdp_poll_pid_ > 0) {
            kill(xdp_poll_pid_, SIGTERM);
            waitpid(xdp_poll_pid_, nullptr, 0);
        }
        if (transport_pid_ > 0) {
            kill(transport_pid_, SIGTERM);
            waitpid(transport_pid_, nullptr, 0);
        }
        if (websocket_pid_ > 0) {
            kill(websocket_pid_, SIGTERM);
            waitpid(websocket_pid_, nullptr, 0);
        }

        // Cleanup shared regions
        delete raw_inbox_region_;
        delete raw_outbox_region_;
        delete msg_outbox_region_;
        delete msg_metadata_region_;
        delete pongs_region_;
        delete ws_frame_info_region_;

        if (conn_state_ && conn_state_ != MAP_FAILED) {
            munmap(conn_state_, sizeof(ConnStateShm));
        }
        if (msg_inbox_ && msg_inbox_ != MAP_FAILED) {
            munmap(msg_inbox_, sizeof(MsgInbox));
        }
        if (umem_area_ && umem_area_ != MAP_FAILED) {
            munmap(umem_area_, UMEM_TOTAL_SIZE);
        }

        printf("=== Teardown Complete ===\n");
    }

    bool fork_processes() {
        // Build URL
        char url[512];
        snprintf(url, sizeof(url), "wss://%s:%u%s", WSS_HOST, WSS_PORT, WSS_PATH);

        // Fork XDP Poll process (Core 2) - must be first to initialize XDP
        xdp_poll_pid_ = fork();
        if (xdp_poll_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for XDP Poll failed\n");
            return false;
        }

        if (xdp_poll_pid_ == 0) {
            // Child: XDP Poll process
            run_xdp_poll_process();
            _exit(0);
        }

        printf("[PARENT] Forked XDP Poll process (PID %d) on core %d\n",
               xdp_poll_pid_, XDP_POLL_CPU_CORE);

        // Wait for XDP to be ready
        printf("[PARENT] Waiting for XDP to be ready...\n");
        if (!conn_state_->wait_for_handshake_xdp_ready(10000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for XDP ready\n");
            return false;
        }
        printf("[PARENT] XDP ready\n");

        // Fork PIO Transport process (Core 4)
        transport_pid_ = fork();
        if (transport_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for PIO Transport failed\n");
            return false;
        }

        if (transport_pid_ == 0) {
            // Child: PIO Transport process
            run_transport_process(url);
            _exit(0);
        }

        printf("[PARENT] Forked PIO Transport process (PID %d) on core %d\n",
               transport_pid_, PIO_TRANSPORT_CPU_CORE);

        // Wait for TLS handshake to complete
        printf("[PARENT] Waiting for TLS handshake (%s)...\n", SSLPolicyType::name());
        if (!conn_state_->wait_for_handshake_tls_ready(15000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for TLS handshake\n");
            return false;
        }
        printf("[PARENT] TLS handshake complete\n");

        // Fork WebSocket process (Core 6)
        websocket_pid_ = fork();
        if (websocket_pid_ < 0) {
            fprintf(stderr, "FAIL: fork() for WebSocket failed\n");
            return false;
        }

        if (websocket_pid_ == 0) {
            // Child: WebSocket process
            run_websocket_process();
            _exit(0);
        }

        printf("[PARENT] Forked WebSocket process (PID %d) on core %d\n",
               websocket_pid_, WEBSOCKET_CPU_CORE);

        // Wait for WebSocket handshake to complete
        printf("[PARENT] Waiting for WebSocket handshake...\n");
        if (!conn_state_->wait_for_handshake_ws_ready(30000000)) {
            fprintf(stderr, "FAIL: Timeout waiting for WebSocket handshake\n");
            return false;
        }
        printf("[PARENT] WebSocket handshake complete\n");

        return true;
    }

    bool run_stream_test() {
        bool run_forever = (g_timeout_ms <= 0);

        if (run_forever) {
            printf("\n--- WSS Stream Test (FOREVER MODE - Ctrl+C to stop) ---\n");
        } else {
            printf("\n--- WSS Stream Test (%dms, expect %d+ trades) ---\n",
                   g_timeout_ms, MIN_EXPECTED_TRADES);
        }

        // Create consumer for WS_FRAME_INFO ring
        IPCRingConsumer<WSFrameInfo> ws_frame_cons(*ws_frame_info_region_);

        // Tracking metrics
        uint64_t total_frames = 0;
        uint64_t text_frames = 0;
        uint64_t binary_frames = 0;
        uint64_t ping_frames = 0;
        uint64_t pong_frames = 0;
        uint64_t close_frames = 0;
        uint64_t valid_trades = 0;
        int64_t last_sequence = -1;
        bool sequence_error = false;

        // Frame recording for latency analysis
        std::vector<WSFrameInfo> frame_records;
        frame_records.reserve(MAX_FRAME_RECORDS);
        uint64_t tsc_freq = conn_state_->tsc_freq_hz;

        uint64_t prev_publish_mono_ns = 0;
        uint64_t prev_latest_poll_cycle = 0;

        auto start_time = std::chrono::steady_clock::now();
        auto stream_end = start_time + std::chrono::milliseconds(g_timeout_ms);

        printf("[WSS] Starting stream reception...\n");

        // Main streaming loop
        while (run_forever || std::chrono::steady_clock::now() < stream_end) {
            if (g_shutdown.load(std::memory_order_acquire)) {
                printf("[WSS] Shutdown signal received\n");
                break;
            }

            if (!conn_state_->is_running(PROC_WEBSOCKET)) {
                fprintf(stderr, "[WSS] WebSocket process exited during streaming\n");
                break;
            }

            // Process WS_FRAME_INFO events
            WSFrameInfo frame;
            bool end_of_batch;
            while (ws_frame_cons.try_consume(frame, &end_of_batch)) {
                total_frames++;
                frame.print_timeline(tsc_freq, prev_publish_mono_ns, prev_latest_poll_cycle);
                prev_publish_mono_ns = frame.ssl_read_end_mono_ns(tsc_freq);
                prev_latest_poll_cycle = frame.latest_poll_cycle;

                if (frame_records.size() < MAX_FRAME_RECORDS) {
                    frame_records.push_back(frame);
                }

                // Verify sequence ordering
                int64_t current_seq = ws_frame_cons.sequence();
                if (last_sequence != -1 && current_seq != last_sequence + 1) {
                    fprintf(stderr, "WARN: Out-of-order frame! Expected %ld, got %ld\n",
                            last_sequence + 1, current_seq);
                    sequence_error = true;
                }
                last_sequence = current_seq;

                // Count by opcode (no per-frame printing)
                switch (frame.opcode) {
                    case 0x01:  // TEXT
                        text_frames++;
                        if (frame.payload_len > 0) {
                            const uint8_t* payload = msg_inbox_->data_at(frame.msg_inbox_offset);
                            if (is_valid_trade_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                                valid_trades++;
                            }
                        }
                        break;

                    case 0x02:  // BINARY
                        binary_frames++;
                        break;

                    case 0x09:  // PING
                        ping_frames++;
                        break;

                    case 0x0A:  // PONG
                        pong_frames++;
                        break;

                    case 0x08:  // CLOSE
                        close_frames++;
                        break;

                    default:
                        break;
                }
            }

            __builtin_ia32_pause();
        }

        // Final drain
        if (!run_forever) {
            printf("[WSS] Final %dms drain...\n", FINAL_DRAIN_MS);
            auto drain_start = std::chrono::steady_clock::now();

            while (true) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - drain_start).count();
                if (elapsed_ms >= FINAL_DRAIN_MS) break;

                WSFrameInfo frame;
                while (ws_frame_cons.try_consume(frame)) {
                    total_frames++;
                    frame.print_timeline(tsc_freq, prev_publish_mono_ns, prev_latest_poll_cycle);
                    prev_publish_mono_ns = frame.ssl_read_end_mono_ns(tsc_freq);
                    prev_latest_poll_cycle = frame.latest_poll_cycle;
                    if (frame_records.size() < MAX_FRAME_RECORDS) {
                        frame_records.push_back(frame);
                    }
                    if (frame.opcode == 0x01) {
                        text_frames++;
                        if (frame.payload_len > 0) {
                            const uint8_t* payload = msg_inbox_->data_at(frame.msg_inbox_offset);
                            if (is_valid_trade_json(reinterpret_cast<const char*>(payload), frame.payload_len)) {
                                valid_trades++;
                            }
                        }
                    }
                }
                usleep(1000);
            }
        }

        auto actual_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start_time).count();

        printf("\n=== Test Results ===\n");
        printf("  Duration:        %ld ms\n", actual_duration);
        printf("  Total frames:    %lu\n", total_frames);
        printf("  TEXT frames:     %lu\n", text_frames);
        printf("  BINARY frames:   %lu\n", binary_frames);
        printf("  PING frames:     %lu\n", ping_frames);
        printf("  PONG frames:     %lu\n", pong_frames);
        printf("  CLOSE frames:    %lu\n", close_frames);
        printf("  Valid trades:    %lu\n", valid_trades);
        printf("  Sequence errors: %s\n", sequence_error ? "YES" : "none");

        // --- NIC-to-message latency stats (qualifying: 1-pkt, 1-ssl, TEXT, >=100B) ---
        {
            std::vector<double> msg_latencies_us;
            for (const auto& r : frame_records) {
                if (r.opcode == 0x01 &&
                    !r.is_fragmented() &&
                    r.ssl_read_ct == 1 &&
                    r.nic_packet_ct == 1 &&
                    r.first_poll_cycle > 0 &&
                    r.ws_frame_publish_cycle > r.first_poll_cycle &&
                    r.payload_len >= 100) {
                    uint64_t lat_ns = cycles_to_ns(
                        r.ws_frame_publish_cycle - r.first_poll_cycle, tsc_freq);
                    msg_latencies_us.push_back(static_cast<double>(lat_ns) / 1000.0);
                }
            }
            if (!msg_latencies_us.empty()) {
                std::sort(msg_latencies_us.begin(), msg_latencies_us.end());
                size_t n = msg_latencies_us.size();
                auto pctile = [&](double p) -> double {
                    return msg_latencies_us[static_cast<size_t>(p / 100.0 * (n - 1))];
                };
                double sum = 0;
                for (double v : msg_latencies_us) sum += v;
                printf("\n=== NIC-to-Message Latency (poll->publish, 1-pkt 1-ssl TEXT) (N=%zu) ===\n", n);
                printf("  Min:    %.2f us\n", msg_latencies_us.front());
                printf("  P50:    %.2f us\n", pctile(50));
                printf("  P90:    %.2f us\n", pctile(90));
                printf("  P99:    %.2f us\n", pctile(99));
                printf("  Max:    %.2f us\n", msg_latencies_us.back());
                printf("  Mean:   %.2f us\n", sum / n);
            } else {
                printf("\n=== NIC-to-Message Latency: No qualifying samples ===\n");
            }
        }

        // Dump all frame records to binary file
        dump_frame_records(frame_records.data(), frame_records.size(), "binance_96");

        // Verify ring buffer status
        printf("\n--- Ring Buffer Status ---\n");

        int64_t ws_frame_prod = ws_frame_info_region_->producer_published()->load(std::memory_order_acquire);
        int64_t ws_frame_cons_seq = ws_frame_cons.sequence();
        bool ws_frame_caught_up = ws_frame_cons_seq >= ws_frame_prod;
        printf("  WS_FRAME_INFO producer: %ld, consumer: %ld\n", ws_frame_prod, ws_frame_cons_seq);
        printf("  Consumer caught up: %s\n", ws_frame_caught_up ? "yes" : "NO - FAIL");

        int64_t meta_prod = msg_metadata_region_->producer_published()->load(std::memory_order_acquire);
        int64_t meta_cons = msg_metadata_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        printf("  MSG_METADATA producer: %ld, consumer: %ld\n", meta_prod, meta_cons);

        int64_t raw_inbox_prod = raw_inbox_region_->producer_published()->load(std::memory_order_acquire);
        int64_t raw_inbox_cons = raw_inbox_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        printf("  RAW_INBOX producer: %ld, consumer: %ld\n", raw_inbox_prod, raw_inbox_cons);

        int64_t raw_outbox_prod = raw_outbox_region_->producer_published()->load(std::memory_order_acquire);
        int64_t raw_outbox_cons = raw_outbox_region_->consumer_sequence(0)->load(std::memory_order_acquire);
        printf("  RAW_OUTBOX producer: %ld, consumer: %ld\n", raw_outbox_prod, raw_outbox_cons);

        printf("====================\n");
        fflush(stdout);

        // Signal children to stop and wait
        conn_state_->shutdown_all();
        if (xdp_poll_pid_ > 0) waitpid(xdp_poll_pid_, nullptr, 0);
        if (transport_pid_ > 0) waitpid(transport_pid_, nullptr, 0);
        if (websocket_pid_ > 0) waitpid(websocket_pid_, nullptr, 0);
        xdp_poll_pid_ = 0;
        transport_pid_ = 0;
        websocket_pid_ = 0;

        // Failure conditions
        if (run_forever) {
            printf("\nFOREVER MODE: Received %lu trades over %ld ms\n",
                   valid_trades, actual_duration);
            printf("PASS: Forever mode completed (terminated by signal)\n");
            return true;
        }

        if (total_frames == 0) {
            printf("\nFAIL: No WebSocket frames received\n");
            return false;
        }

        if (valid_trades < static_cast<uint64_t>(MIN_EXPECTED_TRADES)) {
            printf("\nFAIL: Only %lu trades received (expected %d+)\n",
                   valid_trades, MIN_EXPECTED_TRADES);
            return false;
        }

        if (!ws_frame_caught_up) {
            printf("\nFAIL: WS_FRAME_INFO consumer did not catch up\n");
            return false;
        }

        if (sequence_error) {
            printf("\nFAIL: Out-of-order frame delivery detected\n");
            return false;
        }

        printf("\nPASS: WebSocket pipeline working, received %lu trades in %ld ms\n",
               valid_trades, actual_duration);
        return true;
    }

    ConnStateShm* get_conn_state() const { return conn_state_; }

private:
    // XDP Poll child process
    void run_xdp_poll_process() {
        pin_to_cpu(XDP_POLL_CPU_CORE);

        // Create ring adapters
        IPCRingProducer<PacketFrameDescriptor> raw_inbox_prod(*raw_inbox_region_);
        IPCRingConsumer<PacketFrameDescriptor> raw_outbox_cons(*raw_outbox_region_);

        XDPPollType xdp_poll(interface_);

        if (!xdp_poll.init(umem_area_, UMEM_TOTAL_SIZE,
                           bpf_path_,
                           &raw_inbox_prod,
                           &raw_outbox_cons,
                           conn_state_)) {
            fprintf(stderr, "[XDP-POLL] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        printf("[XDP-POLL] Initialized, running main loop\n");
        xdp_poll.run();
        xdp_poll.cleanup();
    }

    // PIO Transport child process
    void run_transport_process(const char* url) {
        pin_to_cpu(PIO_TRANSPORT_CPU_CORE);

        // Create ring adapters
        IPCRingConsumer<PacketFrameDescriptor> raw_inbox_cons(*raw_inbox_region_);
        IPCRingProducer<PacketFrameDescriptor> raw_outbox_prod(*raw_outbox_region_);
        IPCRingProducer<MsgMetadata> msg_metadata_prod(*msg_metadata_region_);
        IPCRingConsumer<PongFrameAligned> pongs_cons(*pongs_region_);

        TransportType transport(
            url,
            umem_area_,
            FRAME_SIZE,
            &raw_inbox_cons,
            &raw_outbox_prod,
            msg_inbox_,
            &msg_metadata_prod,
            &pongs_cons,
            conn_state_);

        if (!transport.init()) {
            fprintf(stderr, "[TRANSPORT] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        transport.run();
        transport.cleanup();
    }

    // WebSocket child process
    void run_websocket_process() {
        pin_to_cpu(WEBSOCKET_CPU_CORE);

        // Create ring adapters
        IPCRingConsumer<MsgMetadata> msg_metadata_cons(*msg_metadata_region_);
        IPCRingProducer<WSFrameInfo> ws_frame_info_prod(*ws_frame_info_region_);
        IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(*msg_outbox_region_);
        IPCRingProducer<PongFrameAligned> pongs_prod(*pongs_region_);

        WebSocketType ws_process;

        bool ok = ws_process.init(
            msg_inbox_,
            &msg_metadata_cons,
            &ws_frame_info_prod,
            &pongs_prod,
            &msg_outbox_prod,
            conn_state_);

        if (!ok) {
            fprintf(stderr, "[WS-PROCESS] init() failed\n");
            conn_state_->shutdown_all();
            return;
        }

        // Wait for WS ready (PIO Transport handles the HTTP upgrade)
        printf("[WS-PROCESS] Waiting for WS ready from PIO Transport...\n");
        while (!conn_state_->is_handshake_ws_ready()) {
            if (!conn_state_->is_running(PROC_WEBSOCKET)) {
                fprintf(stderr, "[WS-PROCESS] Shutdown during WS ready wait\n");
                return;
            }
            __builtin_ia32_pause();
        }
        printf("[WS-PROCESS] WS ready, starting frame parsing\n");

        // Skip handshake - PIO Transport already did HTTP upgrade
        // Go straight to main loop for WS frame parsing
        ws_process.run();
    }

    // Resolve hostname and store IPs in ConnStateShm for XDP Poll
    bool resolve_and_store_exchange_ips(const char* hostname) {
        struct addrinfo hints = {};
        struct addrinfo* result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        int ret = getaddrinfo(hostname, nullptr, &hints, &result);
        if (ret != 0 || !result) {
            if (result) freeaddrinfo(result);
            return false;
        }

        uint8_t count = 0;
        for (struct addrinfo* p = result; p != nullptr && count < ConnStateShm::MAX_EXCHANGE_IPS; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                auto* addr = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
                conn_state_->exchange_ips[count] = addr->sin_addr.s_addr;  // Already network byte order

                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
                printf("[DNS] Resolved IP %u: %s\n", count, ip_str);

                count++;
            }
        }

        conn_state_->exchange_ip_count = count;
        freeaddrinfo(result);

        printf("[DNS] Total IPs resolved: %u\n", count);
        return count > 0;
    }

    const char* interface_;
    const char* bpf_path_;

    IPCRingManager ipc_manager_;

    void* umem_area_ = nullptr;
    MsgInbox* msg_inbox_ = nullptr;
    ConnStateShm* conn_state_ = nullptr;

    disruptor::ipc::shared_region* raw_inbox_region_ = nullptr;
    disruptor::ipc::shared_region* raw_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_outbox_region_ = nullptr;
    disruptor::ipc::shared_region* msg_metadata_region_ = nullptr;
    disruptor::ipc::shared_region* pongs_region_ = nullptr;
    disruptor::ipc::shared_region* ws_frame_info_region_ = nullptr;

    pid_t xdp_poll_pid_ = 0;
    pid_t transport_pid_ = 0;
    pid_t websocket_pid_ = 0;
};

// ============================================================================
// Main
// ============================================================================

void parse_args(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            g_timeout_ms = atoi(argv[i + 1]);
            printf("[ARGS] Timeout set to %d ms%s\n",
                   g_timeout_ms, g_timeout_ms <= 0 ? " (FOREVER MODE)" : "");
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <interface> <bpf_path> [--timeout <ms>]\n", argv[0]);
        fprintf(stderr, "NOTE: Do NOT run directly. Use: ./scripts/build_xdp.sh 96_websocket_binance.cpp\n");
        fprintf(stderr, "\nOptions:\n");
        fprintf(stderr, "  --timeout <ms>   Stream timeout (default: %d, <= 0 = forever)\n", DEFAULT_STREAM_DURATION_MS);
        fprintf(stderr, "\nArchitecture (3 processes):\n");
        fprintf(stderr, "  - XDP Poll (core %d): XDP kernel interface\n", XDP_POLL_CPU_CORE);
        fprintf(stderr, "  - PIO Transport (core %d): TCP + SSL via IPC\n", PIO_TRANSPORT_CPU_CORE);
        fprintf(stderr, "  - WebSocket (core %d): WS frame parsing\n", WEBSOCKET_CPU_CORE);
        return 1;
    }

    const char* interface = argv[1];
    const char* bpf_path = argv[2];

    parse_args(argc, argv);

    if (geteuid() == 0) {
        fprintf(stderr, "ERROR: Do NOT run as root! Use: ./scripts/build_xdp.sh 96_websocket_binance.cpp\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("==============================================\n");
    printf("  WebSocket 96 Test (XDP + PIO + WS)          \n");
    printf("==============================================\n");
    printf("  Interface:  %s\n", interface);
    printf("  Target:     %s:%u (WSS)\n", WSS_HOST, WSS_PORT);
    printf("  Path:       %s\n", WSS_PATH);
    printf("  SSL:        %s\n", SSLPolicyType::name());
    printf("  Processes:  XDP Poll (core %d)\n", XDP_POLL_CPU_CORE);
    printf("              PIO Transport (core %d)\n", PIO_TRANSPORT_CPU_CORE);
    printf("              WebSocket (core %d)\n", WEBSOCKET_CPU_CORE);
    if (g_timeout_ms <= 0) {
        printf("  Timeout:    FOREVER (Ctrl+C to stop)\n");
    } else {
        printf("  Timeout:    %d ms\n", g_timeout_ms);
    }
    printf("==============================================\n\n");

    WebSocket96Test test(interface, bpf_path);

    if (!test.setup()) {
        fprintf(stderr, "\nFATAL: Setup failed\n");
        return 1;
    }

    g_conn_state = test.get_conn_state();

    if (!test.fork_processes()) {
        fprintf(stderr, "\nFATAL: Failed to fork processes\n");
        test.teardown();
        return 1;
    }

    usleep(500000);  // 500ms stabilization

    int result = 0;
    if (!test.run_stream_test()) {
        result = 1;
    }

    test.teardown();

    printf("\n==============================================\n");
    if (result == 0) {
        printf("  TEST PASSED\n");
    } else {
        printf("  TEST FAILED\n");
    }
    printf("==============================================\n");

    return result;
}

#else  // !USE_XDP

int main() {
    fprintf(stderr, "Error: Build with USE_XDP=1 USE_WOLFSSL=1\n");
    fprintf(stderr, "Example: ./scripts/build_xdp.sh 96_websocket_binance.cpp\n");
    return 1;
}

#endif  // USE_XDP
