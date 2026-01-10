// pipeline/handshake_manager.hpp
// Handshake Manager - TCP/TLS/WS handshake and process orchestration
// Manages shared memory, XDP init, and fork processes
// C++20, policy-based design, single-thread HFT focus
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <string>

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "pipeline_config.hpp"
#include "pipeline_data.hpp"
#include "msg_inbox.hpp"
#include "../core/timing.hpp"

// SSL includes (OpenSSL or WolfSSL compatibility)
#if defined(WOLFSSL_USER_SETTINGS) || defined(HAVE_WOLFSSL)
    #define PIPELINE_USE_WOLFSSL 1
    #include <wolfssl/options.h>
    #include <wolfssl/ssl.h>
    // Type aliases for WolfSSL (use native wolfSSL types, NO BIO support)
    using PL_SSL_CTX = WOLFSSL_CTX;
    using PL_SSL = WOLFSSL;
    #define PL_SSL_CTX_new wolfSSL_CTX_new
    #define PL_SSL_CTX_free wolfSSL_CTX_free
    #define PL_TLS_client_method wolfTLSv1_2_client_method
    #define PL_SSL_new wolfSSL_new
    #define PL_SSL_free wolfSSL_free
    #define PL_SSL_set_connect_state wolfSSL_set_connect_state
    #define PL_SSL_do_handshake wolfSSL_connect
    #define PL_SSL_get_error wolfSSL_get_error
    #define PL_SSL_ERROR_WANT_READ WOLFSSL_ERROR_WANT_READ
    #define PL_SSL_ERROR_WANT_WRITE WOLFSSL_ERROR_WANT_WRITE
    #define PL_SSL_read wolfSSL_read
    #define PL_SSL_write wolfSSL_write
    #define PL_SSL_get_cipher wolfSSL_get_cipher
    #define PL_SSL_shutdown wolfSSL_shutdown
#else
    #include <openssl/ssl.h>
    #include <openssl/bio.h>
    #include <openssl/err.h>
    // Type aliases for OpenSSL
    using PL_SSL_CTX = SSL_CTX;
    using PL_SSL = SSL;
    using PL_BIO = BIO;
    #define PL_SSL_CTX_new SSL_CTX_new
    #define PL_SSL_CTX_free SSL_CTX_free
    #define PL_TLS_client_method TLS_client_method
    #define PL_SSL_new SSL_new
    #define PL_SSL_free SSL_free
    #define PL_SSL_set_tlsext_host_name SSL_set_tlsext_host_name
    #define PL_SSL_set_connect_state SSL_set_connect_state
    #define PL_SSL_do_handshake SSL_do_handshake
    #define PL_SSL_get_error SSL_get_error
    #define PL_SSL_ERROR_WANT_READ SSL_ERROR_WANT_READ
    #define PL_SSL_ERROR_WANT_WRITE SSL_ERROR_WANT_WRITE
    #define PL_SSL_read SSL_read
    #define PL_SSL_write SSL_write
    #define PL_SSL_get_cipher SSL_get_cipher
    #define PL_SSL_shutdown SSL_shutdown
    #define PL_BIO_new BIO_new
    #define PL_BIO_s_mem BIO_s_mem
    #define PL_BIO_read BIO_read
    #define PL_BIO_write BIO_write
    #define PL_BIO_ctrl_pending BIO_ctrl_pending
    #define PL_ERR_print_errors_fp ERR_print_errors_fp
#endif

// Use existing XDPUserspaceTransport from policy/transport.hpp
#ifdef USE_XDP
#include "../policy/transport.hpp"
// Process headers - now integrated with IPC rings
#include "xdp_poll_process.hpp"
#include "transport_process.hpp"
#include "websocket_process.hpp"
#endif

namespace websocket::pipeline {

// Forward declaration for XDP transport type (used by WolfSSL callbacks)
#ifdef USE_XDP
namespace xdp_io_detail {
    // Forward declaration - actual type defined in transport.hpp
    using XDPTransportType = websocket::transport::XDPUserspaceTransport;
}
#endif

// ============================================================================
// WolfSSL Native I/O Callbacks (used instead of BIO for WolfSSL builds)
// ============================================================================

#if defined(PIPELINE_USE_WOLFSSL) && defined(USE_XDP)
namespace detail {
    // Receive callback - called by WolfSSL when it needs data
    // ctx is a pointer to XDPUserspaceTransport
    inline int wolfssl_recv_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
        (void)ssl;
        auto* transport = static_cast<xdp_io_detail::XDPTransportType*>(ctx);
        if (!transport) return WOLFSSL_CBIO_ERR_GENERAL;

        // Poll for data with short timeout
        transport->set_wait_timeout(100);  // 100ms
        int ready = transport->wait();
        if (ready <= 0) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }

        ssize_t result = transport->recv(buf, sz);
        if (result > 0) {
            return static_cast<int>(result);
        } else if (result == 0) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return WOLFSSL_CBIO_ERR_WANT_READ;
            }
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    // Send callback - called by WolfSSL when it needs to write data
    // ctx is a pointer to XDPUserspaceTransport
    inline int wolfssl_send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
        (void)ssl;
        auto* transport = static_cast<xdp_io_detail::XDPTransportType*>(ctx);
        if (!transport) return WOLFSSL_CBIO_ERR_GENERAL;

        ssize_t result = transport->send(buf, sz);
        if (result > 0) {
            return static_cast<int>(result);
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
            }
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }
}  // namespace detail
#endif  // PIPELINE_USE_WOLFSSL && USE_XDP

// ============================================================================
// Signal Handling for Pipeline Processes
// Each process (parent and children) installs this handler after fork
// ============================================================================

namespace detail {
    // Global pointer to shared state for signal handler access
    inline std::atomic<WebsocketStateShm*> g_ws_state{nullptr};

    inline void pipeline_signal_handler(int sig) {
        (void)sig;
        WebsocketStateShm* state = g_ws_state.load(std::memory_order_acquire);
        if (state) {
            state->shutdown_all();  // Sets all 4 per-process running flags to 0
        }
        printf("\n[SIGNAL] Caught signal, shutting down...\n");
    }

    inline void install_signal_handlers(WebsocketStateShm* ws_state) {
        g_ws_state.store(ws_state, std::memory_order_release);

        struct sigaction sa = {};
        sa.sa_handler = pipeline_signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        sigaction(SIGQUIT, &sa, nullptr);
    }
}  // namespace detail

// ============================================================================
// HandshakeManager - Orchestrates connection setup and process management
//
// FORK-FIRST ARCHITECTURE:
// This manager now implements a fork-first approach where:
// 1. Parent creates shared memory (UMEM, ring buffers, state structures)
// 2. Parent stores target config in shared memory
// 3. Parent forks ALL child processes BEFORE any network activity
// 4. XDP Poll child creates XSK socket fresh (no inheritance issues)
// 5. Transport child performs TCP/TLS/WS handshake via IPC rings
// 6. Parent waits for handshake completion, then runs AppClient loop
//
// This eliminates XSK socket inheritance issues across fork() that caused
// rx=0 packets in the previous architecture.
// ============================================================================

#ifdef USE_XDP
struct HandshakeManager {
    // ========================================================================
    // Configuration
    // ========================================================================

    struct Config {
        const char* interface;
        const char* host;
        uint16_t port;
        const char* path;
        int cpu_cores[4];  // XDP Poll, Transport, WebSocket, AppClient
        const char* bpf_path;
        const char* subscription;  // JSON subscription message
    };

    // ========================================================================
    // Initialization (Fork-First Architecture)
    // ========================================================================

    bool init(const Config& config) {
        config_ = config;

        // Create shared memory directory
        mkdir(shm_paths::PIPELINE_DIR, 0755);

        // Create UMEM
        if (!create_umem()) {
            fprintf(stderr, "[HANDSHAKE] Failed to create UMEM\n");
            return false;
        }

        // Create state structures
        if (!create_state_shm()) {
            fprintf(stderr, "[HANDSHAKE] Failed to create state SHM\n");
            return false;
        }

        // Create MSG_INBOX
        if (!create_msg_inbox()) {
            fprintf(stderr, "[HANDSHAKE] Failed to create MSG_INBOX\n");
            return false;
        }

        // Get network info
        if (!get_network_info()) {
            fprintf(stderr, "[HANDSHAKE] Failed to get network info\n");
            return false;
        }

        // Copy local network info to shared state (Transport needs this for handshake)
        tcp_state_->local_ip = local_ip_;
        memcpy(tcp_state_->local_mac, local_mac_, 6);

        // Initialize TSC frequency
        tcp_state_->tsc_freq_hz = calibrate_tsc_freq();
        printf("[HANDSHAKE] TSC freq: %lu Hz\n", tcp_state_->tsc_freq_hz);

        // Create IPC rings for inter-process communication
        if (!create_ipc_rings()) {
            fprintf(stderr, "[HANDSHAKE] Failed to create IPC rings\n");
            return false;
        }

        // Store target config in shared memory for child processes
        // Transport will read this to perform handshake
        strncpy(tcp_state_->target_host, config.host, sizeof(tcp_state_->target_host) - 1);
        tcp_state_->target_port = config.port;
        strncpy(tcp_state_->target_path, config.path, sizeof(tcp_state_->target_path) - 1);
        strncpy(tcp_state_->bpf_path, config.bpf_path, sizeof(tcp_state_->bpf_path) - 1);
        strncpy(tcp_state_->interface_name, config.interface, sizeof(tcp_state_->interface_name) - 1);
        if (config.subscription) {
            strncpy(tcp_state_->subscription_json, config.subscription, sizeof(tcp_state_->subscription_json) - 1);
        }

        printf("[HANDSHAKE] Shared memory initialized (fork-first mode)\n");
        printf("[HANDSHAKE] Target: %s:%u%s\n", config.host, config.port, config.path);
        return true;
    }

    // ========================================================================
    // DEPRECATED: These methods are no longer used in fork-first architecture
    // Handshake is now performed by Transport process after fork
    // ========================================================================

    [[deprecated("Fork-first: XDP Poll creates XSK directly")]]
    bool init_xdp() {
        fprintf(stderr, "[HANDSHAKE] DEPRECATED: init_xdp() - XDP Poll creates XSK directly\n");
        return true;
    }

    [[deprecated("Fork-first: Transport performs TCP handshake")]]
    bool tcp_handshake() {
        fprintf(stderr, "[HANDSHAKE] DEPRECATED: tcp_handshake() - Transport handles this\n");
        return true;
    }

    [[deprecated("Fork-first: Transport performs TLS handshake")]]
    bool tls_handshake() {
        fprintf(stderr, "[HANDSHAKE] DEPRECATED: tls_handshake() - Transport handles this\n");
        return true;
    }

    [[deprecated("Fork-first: Transport performs WebSocket upgrade")]]
    bool websocket_upgrade() {
        fprintf(stderr, "[HANDSHAKE] DEPRECATED: websocket_upgrade() - Transport handles this\n");
        return true;
    }

    [[deprecated("Fork-first: Transport sends subscription")]]
    bool send_subscription(const char* msg) {
        // Store in shared memory for Transport to send
        if (msg) {
            strncpy(tcp_state_->subscription_json, msg, sizeof(tcp_state_->subscription_json) - 1);
        }
        return true;
    }

    // ========================================================================
    // Process Management (Fork-First Architecture)
    // Fork ALL processes BEFORE any network activity
    // ========================================================================

    void fork_processes() {
        printf("[FORK] Fork-first architecture: forking ALL processes before handshake\n");

        // Initialize all running flags to 1
        for (int i = 0; i < PROC_COUNT; ++i) {
            tcp_state_->running[i].flag.store(1, std::memory_order_release);
        }

        // Fork XDP Poll process FIRST
        // XDP Poll will create XSK socket fresh (no inheritance)
        pid_t xdp_pid = fork();
        if (xdp_pid == 0) {
            detail::install_signal_handlers(tcp_state_);
            pin_to_core(config_.cpu_cores[0]);
            run_xdp_poll_fresh();  // New: creates XSK from scratch
            exit(0);
        }
        child_pids_[0] = xdp_pid;

        // Fork Transport process
        // Transport will wait for XDP Poll, then perform TCP/TLS/WS handshake
        pid_t transport_pid = fork();
        if (transport_pid == 0) {
            detail::install_signal_handlers(tcp_state_);
            pin_to_core(config_.cpu_cores[1]);
            run_transport_with_handshake();  // New: performs handshake
            exit(0);
        }
        child_pids_[1] = transport_pid;

        // Fork WebSocket process
        // WebSocket will wait for handshake completion
        pid_t ws_pid = fork();
        if (ws_pid == 0) {
            detail::install_signal_handlers(tcp_state_);
            pin_to_core(config_.cpu_cores[2]);
            run_websocket();
            exit(0);
        }
        child_pids_[2] = ws_pid;

        // Parent (AppClient) - install signal handlers
        detail::install_signal_handlers(tcp_state_);
        pin_to_core(config_.cpu_cores[3]);

        printf("[FORK] Forked processes (fork-first): XDP=%d Transport=%d WS=%d\n",
               xdp_pid, transport_pid, ws_pid);

        // Parent waits for handshake completion
        printf("[FORK] Waiting for handshake completion...\n");
        if (!tcp_state_->wait_for_handshake_ws_ready(60000000)) {  // 60s timeout
            fprintf(stderr, "[FORK] ERROR: Handshake timeout or process died\n");
            shutdown();
            return;
        }
        printf("[FORK] Handshake complete, all processes ready\n");
    }

    void wait_for_children() {
        for (int i = 0; i < 3; i++) {
            if (child_pids_[i] > 0) {
                waitpid(child_pids_[i], nullptr, 0);
            }
        }
    }

    void shutdown() {
        tcp_state_->shutdown_all();  // Sets all 4 per-process running flags to 0

        for (int i = 0; i < 3; i++) {
            if (child_pids_[i] > 0) {
                kill(child_pids_[i], SIGTERM);
            }
        }
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    void cleanup() {
        // NOTE: In fork-first architecture, SSL and XDP are owned by child processes
        // Parent only cleans up shared memory

        // Unmap shared memory
        if (umem_area_) {
            munmap(umem_area_, UMEM_TOTAL_SIZE);
            umem_area_ = nullptr;
        }
        if (tcp_state_) {
            munmap(tcp_state_, sizeof(TCPStateShm));
            tcp_state_ = nullptr;
        }
        if (msg_inbox_) {
            munmap(msg_inbox_, sizeof(MsgInbox));
            msg_inbox_ = nullptr;
        }

        // Remove shared memory files
        unlink(shm_paths::UMEM);
        unlink(shm_paths::TCP_STATE);
        unlink(shm_paths::MSG_INBOX);

        // Cleanup IPC ring files
        cleanup_ipc_rings();
    }

    // Accessors
    TCPStateShm* tcp_state() { return tcp_state_; }
    MsgInbox* msg_inbox() { return msg_inbox_; }
    uint8_t* umem_area() { return umem_area_; }

private:
    // ========================================================================
    // Shared Memory Creation
    // ========================================================================

    bool create_umem() {
        int fd = open(shm_paths::UMEM, O_CREAT | O_RDWR, 0644);
        if (fd < 0) return false;

        if (ftruncate(fd, UMEM_TOTAL_SIZE) < 0) {
            close(fd);
            return false;
        }

        umem_area_ = static_cast<uint8_t*>(mmap(nullptr, UMEM_TOTAL_SIZE,
                                                 PROT_READ | PROT_WRITE,
                                                 MAP_SHARED, fd, 0));
        close(fd);

        if (umem_area_ == MAP_FAILED) {
            umem_area_ = nullptr;
            return false;
        }

        memset(umem_area_, 0, UMEM_TOTAL_SIZE);
        return true;
    }

    bool create_state_shm() {
        // TCP state
        int fd = open(shm_paths::TCP_STATE, O_CREAT | O_RDWR, 0644);
        if (fd < 0) return false;
        ftruncate(fd, sizeof(TCPStateShm));
        tcp_state_ = static_cast<TCPStateShm*>(mmap(nullptr, sizeof(TCPStateShm),
                                                     PROT_READ | PROT_WRITE,
                                                     MAP_SHARED, fd, 0));
        close(fd);
        if (tcp_state_ == MAP_FAILED) return false;
        tcp_state_->init();

        return true;
    }

    bool create_msg_inbox() {
        int fd = open(shm_paths::MSG_INBOX, O_CREAT | O_RDWR, 0644);
        if (fd < 0) return false;
        ftruncate(fd, sizeof(MsgInbox));
        msg_inbox_ = static_cast<MsgInbox*>(mmap(nullptr, sizeof(MsgInbox),
                                                  PROT_READ | PROT_WRITE,
                                                  MAP_SHARED, fd, 0));
        close(fd);
        if (msg_inbox_ == MAP_FAILED) return false;
        msg_inbox_->init();
        return true;
    }

    // ========================================================================
    // Network Info
    // ========================================================================

    bool get_network_info() {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return false;

        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, config_.interface, IFNAMSIZ - 1);

        // Get IP
        if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
            close(fd);
            return false;
        }
        local_ip_ = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr;

        // Get MAC
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            close(fd);
            return false;
        }
        memcpy(local_mac_, ifr.ifr_hwaddr.sa_data, 6);

        close(fd);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_ip_, ip_str, sizeof(ip_str));
        printf("[HANDSHAKE] Local: %s (%02x:%02x:%02x:%02x:%02x:%02x)\n",
               ip_str, local_mac_[0], local_mac_[1], local_mac_[2],
               local_mac_[3], local_mac_[4], local_mac_[5]);

        return true;
    }

    // ========================================================================
    // SSL Helpers (OpenSSL BIO-based only, WolfSSL uses native I/O callbacks)
    // ========================================================================

#ifndef PIPELINE_USE_WOLFSSL
    void send_pending_ssl_data() {
        uint8_t buf[4096];
        int pending;

        while ((pending = PL_BIO_ctrl_pending(bio_out_)) > 0) {
            int ret = PL_BIO_read(bio_out_, buf, sizeof(buf));
            if (ret > 0) {
                xdp_transport_.send(buf, ret);
            }
        }
    }

    bool receive_ssl_data() {
        // Poll for data with timeout
        xdp_transport_.set_wait_timeout(1000);  // 1 second
        int ready = xdp_transport_.wait();
        if (ready <= 0) {
            return false;
        }

        uint8_t buf[4096];
        ssize_t ret = xdp_transport_.recv(buf, sizeof(buf));
        if (ret > 0) {
            PL_BIO_write(bio_in_, buf, ret);
            return true;
        }
        return false;
    }
#endif  // !PIPELINE_USE_WOLFSSL

    // ========================================================================
    // CPU Pinning
    // ========================================================================

    void pin_to_core(int core) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core, &cpuset);
        sched_setaffinity(0, sizeof(cpuset), &cpuset);

        struct sched_param param = {};
        param.sched_priority = sched_get_priority_max(SCHED_FIFO);
        sched_setscheduler(0, SCHED_FIFO, &param);

        printf("[PROCESS] Pinned to core %d\n", core);
    }

    // ========================================================================
    // Process Run Functions - Fork-First Architecture
    // ========================================================================

    // ========================================================================
    // run_xdp_poll_fresh() - Creates XSK socket from scratch (no inheritance)
    // This is the fork-first approach: XDP Poll creates its own XSK socket
    // ========================================================================

    void run_xdp_poll_fresh() {
        fprintf(stderr, "[XDP-POLL] Started on core %d (fresh XSK)\n", config_.cpu_cores[0]);
        fflush(stderr);

        // Open IPC rings for XDP Poll process
        try {
            disruptor::ipc::shared_region raw_inbox_region(get_raw_inbox_ring_name());
            disruptor::ipc::shared_region raw_outbox_region(get_raw_outbox_ring_name());
            disruptor::ipc::shared_region ack_outbox_region(get_ack_outbox_ring_name());
            disruptor::ipc::shared_region pong_outbox_region(get_pong_outbox_ring_name());

            // Create adapters
            IPCRingProducer<UMEMFrameDescriptor> raw_inbox_prod(raw_inbox_region);
            IPCRingConsumer<UMEMFrameDescriptor> raw_outbox_cons(raw_outbox_region);
            IPCRingConsumer<AckDescriptor> ack_outbox_cons(ack_outbox_region);
            IPCRingConsumer<PongDescriptor> pong_outbox_cons(pong_outbox_region);

            // Create XDPPollProcess instance
            using XDPProc = XDPPollProcess<
                IPCRingProducer<UMEMFrameDescriptor>,
                IPCRingConsumer<UMEMFrameDescriptor>,
                IPCRingConsumer<AckDescriptor>,
                IPCRingConsumer<PongDescriptor>>;
            XDPProc xdp_proc;

            // Configure
            typename XDPProc::Config cfg;
            cfg.interface = tcp_state_->interface_name;
            cfg.queue_id = 0;
            cfg.frame_size = FRAME_SIZE;
            cfg.zero_copy = true;

            // Initialize fresh - creates XSK socket from scratch
            // Uses shared UMEM area (mapped via shm file)
            if (!xdp_proc.init_fresh(umem_area_, UMEM_TOTAL_SIZE, cfg,
                                     tcp_state_->bpf_path,
                                     &raw_inbox_prod, &raw_outbox_cons,
                                     &ack_outbox_cons, &pong_outbox_cons,
                                     tcp_state_)) {
                fprintf(stderr, "[XDP-POLL] Failed to initialize XDPPollProcess (fresh)\n");
                return;
            }

            // Signal XDP ready (XSK socket created, BPF attached)
            tcp_state_->set_handshake_xdp_ready();
            fprintf(stderr, "[XDP-POLL] XSK socket created, signaling ready\n");
            fflush(stderr);

            // Run main loop
            fprintf(stderr, "[XDP-POLL] Running main loop\n");
            fflush(stderr);
            xdp_proc.run();
            xdp_proc.cleanup();

        } catch (const std::exception& e) {
            fprintf(stderr, "[XDP-POLL] Exception: %s\n", e.what());
            fflush(stderr);
        }

        fprintf(stderr, "[XDP-POLL] Exiting\n");
        fflush(stderr);
    }

    // ========================================================================
    // run_transport_with_handshake() - Performs TCP/TLS/WS handshake via IPC
    // This is the fork-first approach: Transport performs all handshake
    // ========================================================================

    void run_transport_with_handshake() {
        fprintf(stderr, "[TRANSPORT] Started on core %d (handshake mode)\n", config_.cpu_cores[1]);
        fflush(stderr);

        // Wait for XDP Poll to be ready (XSK socket created)
        fprintf(stderr, "[TRANSPORT] Waiting for XDP Poll to create XSK socket...\n");
        fflush(stderr);
        if (!tcp_state_->wait_for_handshake_xdp_ready(30000000)) {  // 30s timeout
            fprintf(stderr, "[TRANSPORT] ERROR: XDP Poll not ready\n");
            return;
        }
        fprintf(stderr, "[TRANSPORT] XDP Poll ready, starting handshake\n");
        fflush(stderr);

        // Open IPC rings for Transport process
        try {
            disruptor::ipc::shared_region raw_inbox_region(get_raw_inbox_ring_name());
            disruptor::ipc::shared_region raw_outbox_region(get_raw_outbox_ring_name());
            disruptor::ipc::shared_region ack_outbox_region(get_ack_outbox_ring_name());
            disruptor::ipc::shared_region pong_outbox_region(get_pong_outbox_ring_name());
            disruptor::ipc::shared_region msg_metadata_region(get_msg_metadata_ring_name());
            disruptor::ipc::shared_region msg_outbox_region(get_msg_outbox_ring_name());
            disruptor::ipc::shared_region pongs_region(get_pongs_ring_name());

            // Create adapters
            IPCRingConsumer<UMEMFrameDescriptor> raw_inbox_cons(raw_inbox_region);
            IPCRingProducer<UMEMFrameDescriptor> raw_outbox_prod(raw_outbox_region);
            IPCRingProducer<AckDescriptor> ack_outbox_prod(ack_outbox_region);
            IPCRingProducer<PongDescriptor> pong_outbox_prod(pong_outbox_region);
            IPCRingProducer<MsgMetadata> msg_metadata_prod(msg_metadata_region);
            IPCRingConsumer<MsgOutboxEvent> msg_outbox_cons(msg_outbox_region);
            IPCRingConsumer<PongFrameAligned> pongs_cons(pongs_region);

            // Create TransportProcess instance
            using TransProc = TransportProcess<PipelineSSLPolicy,
                IPCRingConsumer<UMEMFrameDescriptor>,
                IPCRingProducer<UMEMFrameDescriptor>,
                IPCRingProducer<AckDescriptor>,
                IPCRingProducer<PongDescriptor>,
                IPCRingConsumer<MsgOutboxEvent>,
                IPCRingProducer<MsgMetadata>,
                IPCRingConsumer<PongFrameAligned>>;
            TransProc trans_proc;

            // Initialize with handshake - performs TCP/TLS/WS handshake
            if (!trans_proc.init_with_handshake(
                    umem_area_, FRAME_SIZE,
                    tcp_state_->target_host,
                    tcp_state_->target_port,
                    tcp_state_->target_path,
                    tcp_state_->subscription_json,
                    &raw_inbox_cons, &raw_outbox_prod,
                    &ack_outbox_prod, &pong_outbox_prod,
                    &msg_outbox_cons, &msg_metadata_prod,
                    &pongs_cons, msg_inbox_,
                    tcp_state_)) {
                fprintf(stderr, "[TRANSPORT] Handshake failed\n");
                return;
            }

            // Signal WebSocket ready (handshake complete)
            tcp_state_->set_handshake_ws_ready();
            fprintf(stderr, "[TRANSPORT] Handshake complete, signaling ready\n");
            fflush(stderr);

            // Run main loop
            fprintf(stderr, "[TRANSPORT] Running main loop\n");
            fflush(stderr);
            trans_proc.run();

        } catch (const std::exception& e) {
            fprintf(stderr, "[TRANSPORT] Exception: %s\n", e.what());
            fflush(stderr);
        }

        fprintf(stderr, "[TRANSPORT] Exiting\n");
        fflush(stderr);
    }

    // ========================================================================
    // LEGACY: Old run functions (kept for reference, will be removed)
    // ========================================================================

    [[deprecated("Use run_xdp_poll_fresh() instead")]]
    void run_xdp_poll() {
        // Redirect to fresh implementation
        run_xdp_poll_fresh();
    }

    [[deprecated("Use run_transport_with_handshake() instead")]]
    void run_transport() {
        // Redirect to handshake implementation
        run_transport_with_handshake();
    }

    void run_websocket() {
        printf("[WS] Started on core %d\n", config_.cpu_cores[2]);

        // Open IPC rings for WebSocket process
        // WebSocket consumes: MSG_METADATA
        // WebSocket produces: WS_FRAME_INFO, PONGS, MSG_OUTBOX (for CLOSE)
        try {
            disruptor::ipc::shared_region msg_metadata_region(get_msg_metadata_ring_name());
            disruptor::ipc::shared_region ws_frame_info_region(get_ws_frame_info_ring_name());
            disruptor::ipc::shared_region pongs_region(get_pongs_ring_name());
            disruptor::ipc::shared_region msg_outbox_region(get_msg_outbox_ring_name());

            // Create adapters
            IPCRingConsumer<MsgMetadata> msg_metadata_cons(msg_metadata_region);
            IPCRingProducer<WSFrameInfo> ws_frame_info_prod(ws_frame_info_region);
            IPCRingProducer<PongFrameAligned> pongs_prod(pongs_region);
            IPCRingProducer<MsgOutboxEvent> msg_outbox_prod(msg_outbox_region);

            // Create WebSocketProcess instance with all ring types explicitly specified
            using WSProc = WebSocketProcess<
                IPCRingConsumer<MsgMetadata>,      // msg_metadata
                IPCRingProducer<WSFrameInfo>,      // ws_frame_info
                IPCRingProducer<PongFrameAligned>, // pongs
                IPCRingProducer<MsgOutboxEvent>>;  // msg_outbox
            WSProc ws_proc;

            // Initialize
            if (!ws_proc.init(msg_inbox_,
                              &msg_metadata_cons, &ws_frame_info_prod,
                              &pongs_prod, &msg_outbox_prod,
                              tcp_state_)) {
                fprintf(stderr, "[WS] Failed to initialize WebSocketProcess\n");
                return;
            }

            // Run WebSocketProcess main loop
            // Uses process_manually + commit_manually pattern for batching (Gap 10, 11, 16)
            ws_proc.run();

        } catch (const std::exception& e) {
            fprintf(stderr, "[WS] Exception: %s\n", e.what());
        }

        printf("[WS] Exiting\n");
    }

    // State
    Config config_;

    // NOTE: In fork-first architecture, XDP transport and SSL are created
    // in child processes (XDP Poll and Transport respectively), not in parent.
    // These are kept as placeholders for potential future use.

    // Shared memory (created by parent, used by all processes after fork)
    uint8_t* umem_area_ = nullptr;
    TCPStateShm* tcp_state_ = nullptr;
    MsgInbox* msg_inbox_ = nullptr;

    // Network info (for logging)
    uint32_t local_ip_ = 0;
    uint8_t local_mac_[6] = {};

    // Child processes
    pid_t child_pids_[3] = {};

    // IPC ring directory name (timestamped)
    std::string ipc_ring_dir_;

    // ========================================================================
    // IPC Ring Creation
    // Creates hftshm-compatible ring files (.hdr + .dat) in /dev/shm/hft/
    // Called in init() before fork() so all processes can access rings
    // ========================================================================

    bool create_ipc_ring(const char* name, size_t buffer_size, size_t event_size, uint8_t max_consumers) {
        std::string base_path = std::string("/dev/shm/hft/") + ipc_ring_dir_ + "/" + name;
        std::string hdr_path = base_path + ".hdr";
        std::string dat_path = base_path + ".dat";

        // Calculate header size (metadata + producer + consumers)
        uint32_t producer_offset = hftshm::default_producer_offset();
        uint32_t consumer_0_offset = hftshm::default_consumer_0_offset();
        uint32_t header_size = hftshm::header_segment_size(max_consumers);

        // Create and initialize header file
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

        // Initialize metadata
        hftshm::metadata_init(hdr_ptr, max_consumers, event_size, buffer_size,
                              producer_offset, consumer_0_offset, header_size);

        // Initialize producer sequences to -1 (disruptor convention)
        auto* meta = static_cast<hftshm::metadata*>(hdr_ptr);
        auto* cursor = reinterpret_cast<std::atomic<int64_t>*>(
            static_cast<char*>(hdr_ptr) + meta->producer_offset);
        auto* published = reinterpret_cast<std::atomic<int64_t>*>(
            static_cast<char*>(hdr_ptr) + meta->producer_offset + hftshm::CACHE_LINE);
        cursor->store(-1, std::memory_order_relaxed);
        published->store(-1, std::memory_order_relaxed);

        // Initialize consumer sequences to -1
        for (uint8_t i = 0; i < max_consumers; i++) {
            auto* cons_seq = reinterpret_cast<std::atomic<int64_t>*>(
                static_cast<char*>(hdr_ptr) + hftshm::consumer_offset(meta, i));
            cons_seq->store(-1, std::memory_order_relaxed);
        }

        munmap(hdr_ptr, header_size);

        // Create data file
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

        // Zero-initialize data
        void* dat_ptr = mmap(nullptr, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, dat_fd, 0);
        close(dat_fd);
        if (dat_ptr == MAP_FAILED) {
            unlink(hdr_path.c_str());
            return false;
        }
        memset(dat_ptr, 0, buffer_size);
        munmap(dat_ptr, buffer_size);

        printf("[IPC] Created ring: %s (buf=%zu, event=%zu)\n", name, buffer_size, event_size);
        return true;
    }

    bool create_ipc_rings() {
        // Generate timestamped directory name
        time_t now = time(nullptr);
        struct tm* tm_info = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", tm_info);
        ipc_ring_dir_ = std::string("ws_pipeline_") + timestamp;

        // Create directories
        mkdir("/dev/shm/hft", 0755);
        std::string full_dir = "/dev/shm/hft/" + ipc_ring_dir_;
        if (mkdir(full_dir.c_str(), 0755) < 0 && errno != EEXIST) {
            fprintf(stderr, "[IPC] Failed to create directory: %s\n", full_dir.c_str());
            return false;
        }

        // Create all rings
        // XDP Poll → Transport
        if (!create_ipc_ring("raw_inbox", RAW_INBOX_SIZE * sizeof(UMEMFrameDescriptor),
                             sizeof(UMEMFrameDescriptor), 1)) return false;

        // Transport → XDP Poll
        if (!create_ipc_ring("raw_outbox", RAW_OUTBOX_SIZE * sizeof(UMEMFrameDescriptor),
                             sizeof(UMEMFrameDescriptor), 1)) return false;

        // ACK frames: Transport → XDP Poll
        if (!create_ipc_ring("ack_outbox", ACK_OUTBOX_SIZE * sizeof(AckDescriptor),
                             sizeof(AckDescriptor), 1)) return false;

        // PONG frames: Transport → XDP Poll
        if (!create_ipc_ring("pong_outbox", PONG_OUTBOX_SIZE * sizeof(PongDescriptor),
                             sizeof(PongDescriptor), 1)) return false;

        // Transport → WebSocket
        if (!create_ipc_ring("msg_metadata", MSG_METADATA_SIZE * sizeof(MsgMetadata),
                             sizeof(MsgMetadata), 1)) return false;

        // WebSocket → AppClient
        if (!create_ipc_ring("ws_frame_info", WS_FRAME_INFO_SIZE * sizeof(WSFrameInfo),
                             sizeof(WSFrameInfo), 1)) return false;

        // AppClient → Transport
        if (!create_ipc_ring("msg_outbox", MSG_OUTBOX_SIZE * sizeof(MsgOutboxEvent),
                             sizeof(MsgOutboxEvent), 1)) return false;

        // WebSocket → Transport (PONG payloads)
        if (!create_ipc_ring("pongs", PONGS_SIZE * sizeof(PongFrameAligned),
                             sizeof(PongFrameAligned), 1)) return false;

        printf("[IPC] Created all ring files in %s\n", full_dir.c_str());
        return true;
    }

    void cleanup_ipc_rings() {
        if (ipc_ring_dir_.empty()) return;

        std::string base = "/dev/shm/hft/" + ipc_ring_dir_;
        const char* ring_names[] = {
            "raw_inbox", "raw_outbox", "ack_outbox", "pong_outbox",
            "msg_metadata", "ws_frame_info", "msg_outbox", "pongs"
        };

        for (const char* name : ring_names) {
            unlink((base + "/" + name + ".hdr").c_str());
            unlink((base + "/" + name + ".dat").c_str());
        }
        rmdir(base.c_str());
        printf("[IPC] Cleaned up ring files\n");
    }

public:
    // Ring name accessors (used by processes after fork)
    std::string get_ring_name(const char* ring) const {
        return ipc_ring_dir_ + "/" + ring;
    }
    std::string get_raw_inbox_ring_name() const { return get_ring_name("raw_inbox"); }
    std::string get_raw_outbox_ring_name() const { return get_ring_name("raw_outbox"); }
    std::string get_ack_outbox_ring_name() const { return get_ring_name("ack_outbox"); }
    std::string get_pong_outbox_ring_name() const { return get_ring_name("pong_outbox"); }
    std::string get_msg_metadata_ring_name() const { return get_ring_name("msg_metadata"); }
    std::string get_ws_frame_info_ring_name() const { return get_ring_name("ws_frame_info"); }
    std::string get_msg_outbox_ring_name() const { return get_ring_name("msg_outbox"); }
    std::string get_pongs_ring_name() const { return get_ring_name("pongs"); }
};
#else
// Stub when USE_XDP is not defined
struct HandshakeManager {
    struct Config {
        const char* interface;
        const char* host;
        uint16_t port;
        const char* path;
        int cpu_cores[4];
        const char* bpf_path;
    };
    bool init(const Config&) { return false; }
    bool init_xdp() { return false; }
    bool tcp_handshake() { return false; }
    bool tls_handshake() { return false; }
    bool websocket_upgrade() { return false; }
    bool send_subscription(const char*) { return false; }
    void fork_processes() {}
    void wait_for_children() {}
    void shutdown() {}
    void cleanup() {}
    SSL* ssl() { return nullptr; }
    TCPStateShm* tcp_state() { return nullptr; }
    MsgInbox* msg_inbox() { return nullptr; }
};
#endif  // USE_XDP

}  // namespace websocket::pipeline
