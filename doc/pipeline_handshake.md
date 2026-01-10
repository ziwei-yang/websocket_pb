# Pipeline Handshake Phase (Setup)

**Related Documents**:
- [Architecture Overview](pipeline_architecture.md)
- [XDP Poll Process (Core 2)](pipeline_0_nic.md)
- [Transport Process (Core 4)](pipeline_1_trans.md)
- [WebSocket Process (Core 6)](pipeline_2_ws.md)
- [AppClient Process (Core 8)](pipeline_3_app.md)

---

## Overview

The pipeline uses a **fork-first architecture** where all processes are forked BEFORE any network activity. This eliminates XSK socket inheritance issues that caused `rx=0` packets in the previous single-process handshake approach.

**Key Responsibilities**:
1. Create shared memory regions (UMEM, ring buffers, TCP state)
2. Create IPC rings for inter-process communication
3. Store target config (host, port, path, subscription) in shared memory
4. Fork ALL processes (XDP Poll, Transport, WebSocket)
5. XDP Poll: Creates XSK socket fresh (no inheritance)
6. Transport: Performs TCP/TLS/WS handshake via IPC rings
7. Parent waits for handshake completion, then runs AppClient

### Fork-First Architecture Flow

```
Parent (HandshakeManager):
  create_shared_memory() → create_ipc_rings() → store_target_config() → fork()
        ↓                                                                ↓
XDP Poll (child):                                               Transport (child):
  create_xsk() → register_bpf()                                   wait_for_xdp_ready()
  populate_fill() → set_xdp_ready()                                      ↓
        ↓                                                    tcp_handshake() → tls_handshake()
  run_main_loop()                                            ws_upgrade() → send_subscription()
                                                             set_ws_ready() → run_main_loop()
```

**Why Fork-First?**
- XSK socket inheritance across `fork()` doesn't work reliably
- BPF/XSK mapping may not correctly transfer to child process
- Creating XSK fresh in child avoids all inheritance issues

---

## Code Reuse

```cpp
// XDP/UMEM (from src/xdp/ - reuse as-is)
#include <xdp/xdp_transport.hpp>       // XDPTransport, XDPConfig
#include <xdp/bpf_loader.hpp>          // BPFLoader

// TCP/IP Stack (from src/stack/)
#include <stack/userspace_stack.hpp>   // UserspaceStack
#include <stack/tcp/tcp_state.hpp>     // TCPState, TCPParams
#include <stack/mac/arp.hpp>           // ARP::resolve_gateway()

// SSL/TLS Policy (from src/policy/)
#include <policy/ssl.hpp>                     // WolfSSLPolicy, OpenSSLPolicy
#include <policy/userspace_transport_bio.hpp> // UserspaceTransportBIO

// WebSocket (from src/core/)
#include <core/http.hpp>               // build_websocket_upgrade_request()

// Disruptor IPC (from 01_shared_headers/disruptor/)
#include <disruptor/disruptor.hpp>     // ring_buffer, sequencer, shared_region

// Pipeline data structures
#include <pipeline/pipeline_config.hpp>
#include <pipeline/pipeline_data.hpp>
```

---

## Shared Memory Layout

```cpp
// Shared memory file paths
// NOTE: Using HFTSHM dual-segment layout (.hdr for control, .dat for data)
// This follows the disruptor IPC mode pattern from 01_shared_headers/disruptor/
namespace shm_paths {
    // UMEM buffer (single file, not dual-segment)
    constexpr const char* UMEM           = "/dev/shm/pipeline/umem.dat";

    // Ring buffers use HFTSHM dual-segment layout:
    //   .hdr: metadata (magic, version, buffer_size), producer (cursor, published), consumer (sequence)
    //   .dat: ring buffer data (power of 2 size)
    // Base paths (append .hdr or .dat as needed)
    constexpr const char* RAW_INBOX      = "/dev/shm/pipeline/raw_inbox";       // .hdr/.dat
    constexpr const char* RAW_OUTBOX     = "/dev/shm/pipeline/raw_outbox";      // .hdr/.dat
    constexpr const char* ACK_OUTBOX     = "/dev/shm/pipeline/ack_outbox";      // .hdr/.dat
    constexpr const char* PONG_OUTBOX    = "/dev/shm/pipeline/pong_outbox";     // .hdr/.dat
    constexpr const char* MSG_METADATA   = "/dev/shm/pipeline/msg_metadata";    // .hdr/.dat
    constexpr const char* MSG_OUTBOX     = "/dev/shm/pipeline/msg_outbox";      // .hdr/.dat
    constexpr const char* PONGS          = "/dev/shm/pipeline/pongs";           // .hdr/.dat
    constexpr const char* WS_FRAME_INFO  = "/dev/shm/pipeline/ws_frame_info";   // .hdr/.dat

    // MSG_INBOX is a byte stream buffer (single file, not ring buffer)
    constexpr const char* MSG_INBOX      = "/dev/shm/pipeline/msg_inbox.dat";

    // State structures (single files)
    constexpr const char* TCP_STATE      = "/dev/shm/pipeline/tcp_state.dat";
    constexpr const char* TX_FRAME_STATE = "/dev/shm/pipeline/tx_frame_state.dat";
}
```

---

## WebsocketStateShm (Shared Pipeline State)

The canonical shared state struct is `WebsocketStateShm` defined in `src/pipeline/pipeline_data.hpp`.
This struct consolidates all shared state including:

- Per-process running flags (cache-line padded)
- Per-process ready flags (for startup synchronization)
- Handshake stage flags (fork-first architecture)
- Target URL and config
- TCP connection state
- TX frame allocation counters (merged from TxFrameState)

**Note**: `TCPStateShm` is a type alias for backwards compatibility:
```cpp
using TCPStateShm = WebsocketStateShm;
```

### Process Index Enum

Defined in `pipeline_data.hpp`:
```cpp
enum ProcessId : uint8_t {
    PROC_XDP_POLL   = 0,
    PROC_TRANSPORT  = 1,
    PROC_WEBSOCKET  = 2,
    PROC_APPCLIENT  = 3,
    PROC_COUNT      = 4
};
```

### Key Helper Methods

```cpp
// Check if process should continue running
bool is_running(ProcessId proc) const {
    return running[proc].flag.load(std::memory_order_acquire) != 0;
}

// Shutdown all processes
void shutdown_all() {
    for (int i = 0; i < PROC_COUNT; ++i) {
        running[i].flag.store(0, std::memory_order_release);
    }
}

// Handshake synchronization
void set_handshake_xdp_ready();
void set_handshake_ws_ready();
bool wait_for_handshake_xdp_ready(uint64_t timeout_us) const;
bool wait_for_handshake_ws_ready(uint64_t timeout_us) const;
```

### TX Frame State (Merged)

TX frame allocation is now part of `WebsocketStateShm.tx_frame`:
```cpp
alignas(CACHE_LINE_SIZE) struct {
    // ACK pool (Transport allocates, XDP Poll releases)
    std::atomic<uint32_t> ack_alloc_pos;
    std::atomic<uint32_t> ack_release_pos;

    // PONG pool (Transport allocates, XDP Poll releases after ACK)
    std::atomic<uint32_t> pong_alloc_pos;
    std::atomic<uint32_t> pong_release_pos;
    std::atomic<uint32_t> pong_acked_pos;

    // MSG pool (Transport allocates, XDP Poll releases after ACK)
    std::atomic<uint32_t> msg_alloc_pos;
    std::atomic<uint32_t> msg_release_pos;
    std::atomic<uint32_t> msg_acked_pos;
} tx_frame;
```

**Initialization** (set during handshake, before fork):
- All position counters start at 0
- See `pipeline_data.hpp` for full struct definition and invariants

---

## Handshake Manager Class (Fork-First Architecture)

```cpp
// HandshakeManager - Orchestrates fork-first connection setup
// IMPORTANT: Handshake now happens in CHILD processes, not parent
// Template parameter: SSLPolicy (WolfSSLPolicy, OpenSSLPolicy, etc.)
template<typename SSLPolicy = WolfSSLPolicy>
struct HandshakeManager {
    struct Config {
        const char* interface;        // Network interface (e.g., "enp108s0")
        const char* host;             // Target hostname
        uint16_t port;                // Target port (e.g., 443)
        const char* path;             // WebSocket path (e.g., "/ws")
        int cpu_cores[4];             // XDP Poll, Transport, WebSocket, AppClient
        const char* bpf_path;         // Path to BPF program
        const char* subscription;     // JSON subscription message (sent by Transport child)
    };

private:
    Config config_;

    // Shared memory (created by parent, used by all processes after fork)
    // NOTE: In fork-first architecture, XDP transport and SSL are created
    // in child processes (XDP Poll and Transport respectively), not in parent.
    uint8_t* umem_area_ = nullptr;
    WebsocketStateShm* tcp_state_ = nullptr;  // Using WebsocketStateShm (TCPStateShm is alias)
    MsgInbox* msg_inbox_ = nullptr;

    // Network info (for logging)
    uint32_t local_ip_ = 0;
    uint8_t local_mac_[6] = {};

    // Child process PIDs
    pid_t child_pids_[3] = {};  // XDP, Transport, WebSocket

    // IPC ring directory (timestamped)
    std::string ipc_ring_dir_;

public:
    // ========================================================================
    // Initialization (Fork-First Architecture)
    // ========================================================================

    bool init(const Config& config) {
        config_ = config;

        // 1. Create shared memory directory and files
        create_umem();
        create_state_shm();
        create_msg_inbox();

        // 2. Get local network info
        get_network_info();

        // 3. Calibrate TSC frequency (once in parent)
        tcp_state_->tsc_freq_hz = calibrate_tsc_freq();

        // 4. Create IPC rings
        create_ipc_rings();

        // 5. Store target config in shared memory for Transport child
        strncpy(tcp_state_->target_host, config.host, sizeof(tcp_state_->target_host) - 1);
        tcp_state_->target_port = config.port;
        strncpy(tcp_state_->target_path, config.path, sizeof(tcp_state_->target_path) - 1);
        strncpy(tcp_state_->bpf_path, config.bpf_path, sizeof(tcp_state_->bpf_path) - 1);
        strncpy(tcp_state_->interface_name, config.interface, sizeof(tcp_state_->interface_name) - 1);
        // Subscription stored in shared memory - Transport child will send it after WS upgrade
        if (config.subscription) {
            strncpy(tcp_state_->subscription_json, config.subscription,
                    sizeof(tcp_state_->subscription_json) - 1);
        }

        return true;
    }

    // ========================================================================
    // Process Management (Fork-First)
    // ========================================================================

    void fork_processes() {
        // Initialize all running flags
        for (int i = 0; i < PROC_COUNT; ++i) {
            tcp_state_->running[i].flag.store(1, std::memory_order_release);
        }

        // Fork XDP Poll FIRST (creates XSK socket fresh)
        pid_t xdp_pid = fork();
        if (xdp_pid == 0) {
            install_signal_handlers(tcp_state_);
            pin_to_core(config_.cpu_cores[PROC_XDP_POLL]);
            run_xdp_poll_fresh();  // Creates XSK from scratch
            exit(0);
        }
        child_pids_[0] = xdp_pid;

        // Fork Transport (waits for XDP, performs handshake, sends subscription)
        pid_t transport_pid = fork();
        if (transport_pid == 0) {
            install_signal_handlers(tcp_state_);
            pin_to_core(config_.cpu_cores[PROC_TRANSPORT]);
            run_transport_with_handshake();  // Performs TCP/TLS/WS + subscription
            exit(0);
        }
        child_pids_[1] = transport_pid;

        // Fork WebSocket
        pid_t ws_pid = fork();
        if (ws_pid == 0) {
            install_signal_handlers(tcp_state_);
            pin_to_core(config_.cpu_cores[PROC_WEBSOCKET]);
            run_websocket();
            exit(0);
        }
        child_pids_[2] = ws_pid;

        // Parent: wait for handshake completion
        install_signal_handlers(tcp_state_);
        pin_to_core(config_.cpu_cores[PROC_APPCLIENT]);
        tcp_state_->wait_for_handshake_ws_ready(60000000);  // 60s timeout
    }

private:
    // ========================================================================
    // Child Process Run Functions (Fork-First)
    // ========================================================================

    void run_xdp_poll_fresh();           // Creates XSK socket, signals xdp_ready
    void run_transport_with_handshake(); // Performs TCP/TLS/WS handshake + subscription
    void run_websocket();                // Parses WS frames
};
```

**Note**: All handshake logic (TCP, TLS, WebSocket upgrade, subscription) is performed by
the Transport child process via `run_transport_with_handshake()`. See
[Transport IPC Handshake Implementation](#transport-ipc-handshake-implementation) for details.

---

## Step 1: Create Shared Memory

```cpp
bool HandshakeManager::create_shared_memory() {
    // Create pipeline directory
    mkdir("/dev/shm/pipeline", 0755);

    // 1. UMEM buffer (hugepages preferred)
    // Include TRICKLE_FRAME_SIZE (64 bytes) for the RX trickle packet at end of UMEM
    // See pipeline_0_nic.md for trickle_frame_addr_ usage
    //
    // TRICKLE FRAME INITIALIZATION:
    // The trickle frame is a pre-built 43-byte self-addressed UDP packet stored at
    // the end of UMEM (address = TOTAL_UMEM_FRAMES * FRAME_SIZE). It is NOT part of
    // any RX/TX pool. XDP Poll uses this to trigger NAPI processing on igc driver.
    // After mmap, build the trickle packet once:
    //   uint8_t* trickle_ptr = umem_ptr_ + TOTAL_UMEM_FRAMES * FRAME_SIZE;
    //   build_trickle_packet(trickle_ptr, local_mac, local_ip);  // 43-byte UDP packet
    //
    size_t umem_size = TOTAL_UMEM_FRAMES * FRAME_SIZE + TRICKLE_FRAME_SIZE;
    int umem_fd = shm_open(shm_paths::UMEM, O_CREAT | O_RDWR, 0666);
    ftruncate(umem_fd, umem_size);
    umem_ptr_ = mmap(nullptr, umem_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_HUGETLB, umem_fd, 0);
    if (umem_ptr_ == MAP_FAILED) {
        // Fallback to regular pages
        umem_ptr_ = mmap(nullptr, umem_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED, umem_fd, 0);
    }
    close(umem_fd);

    // 2. TCP state
    int tcp_fd = shm_open(shm_paths::TCP_STATE, O_CREAT | O_RDWR, 0666);
    ftruncate(tcp_fd, sizeof(TCPStateShm));
    tcp_state_ = static_cast<TCPStateShm*>(
        mmap(nullptr, sizeof(TCPStateShm), PROT_READ | PROT_WRITE, MAP_SHARED, tcp_fd, 0));
    close(tcp_fd);
    memset(tcp_state_, 0, sizeof(TCPStateShm));

    // Calibrate TSC frequency once (takes ~10ms) and store in shared memory
    // All forked child processes will use this value instead of re-calibrating
    tcp_state_->tsc_freq_hz = calibrate_tsc();

    // 3. TX frame state
    int tx_fd = shm_open(shm_paths::TX_FRAME_STATE, O_CREAT | O_RDWR, 0666);
    ftruncate(tx_fd, sizeof(TxFrameState));
    tx_state_ = static_cast<TxFrameState*>(
        mmap(nullptr, sizeof(TxFrameState), PROT_READ | PROT_WRITE, MAP_SHARED, tx_fd, 0));
    close(tx_fd);
    memset(tx_state_, 0, sizeof(TxFrameState));

    // 4. Ring buffer shared regions (using disruptor IPC)
    // Each region contains: cursor, published sequence, gating sequences, data buffer

    // RAW_INBOX: 2048 × 32B = 64KB + control
    raw_inbox_region_.create(shm_paths::RAW_INBOX,
        disruptor::shared_region::calculate_size<UMEMFrameDescriptor>(RAW_INBOX_SIZE));

    // RAW_OUTBOX: 2048 × 32B = 64KB + control
    raw_outbox_region_.create(shm_paths::RAW_OUTBOX,
        disruptor::shared_region::calculate_size<UMEMFrameDescriptor>(RAW_OUTBOX_SIZE));

    // ACK_OUTBOX: 512 × 32B = 16KB + control
    ack_outbox_region_.create(shm_paths::ACK_OUTBOX,
        disruptor::shared_region::calculate_size<UMEMFrameDescriptor>(ACK_OUTBOX_SIZE));

    // PONG_OUTBOX: 64 × 32B = 2KB + control
    pong_outbox_region_.create(shm_paths::PONG_OUTBOX,
        disruptor::shared_region::calculate_size<UMEMFrameDescriptor>(PONG_OUTBOX_SIZE));

    // MSG_INBOX: 4MB byte stream + control
    msg_inbox_region_.create(shm_paths::MSG_INBOX,
        sizeof(MsgInbox));

    // MSG_METADATA_INBOX: 4096 × 64B = 256KB + control
    msg_metadata_region_.create(shm_paths::MSG_METADATA,
        disruptor::shared_region::calculate_size<MsgMetadata>(MSG_METADATA_SIZE));

    // MSG_OUTBOX: 512 × 2KB = 1MB + control
    msg_outbox_region_.create(shm_paths::MSG_OUTBOX,
        disruptor::shared_region::calculate_size<MsgOutboxEvent>(MSG_OUTBOX_SIZE));

    // PONGS: 64 × 128B = 8KB + control
    pongs_region_.create(shm_paths::PONGS,
        disruptor::shared_region::calculate_size<PongFrameAligned>(PONGS_SIZE));

    // WS_FRAME_INFO: 4096 × 128B = 512KB + control
    ws_frame_info_region_.create(shm_paths::WS_FRAME_INFO,
        disruptor::shared_region::calculate_size<WSFrameInfo>(WS_FRAME_INFO_SIZE));

    return true;
}
```

---

## Terminology: UMEMFrameDescriptor

Pipeline processes use `UMEMFrameDescriptor` in ring buffers for IPC:

```cpp
// UMEMFrameDescriptor: Ring buffer entry for IPC between processes
// Contains UMEM address (not pointer) and metadata for routing
struct UMEMFrameDescriptor {
    uint64_t umem_addr;        // Offset into UMEM buffer
    uint16_t frame_len;        // Actual frame length
    uint8_t  frame_type;       // FRAME_TYPE_ACK/PONG/MSG
    // ... timestamps, etc.
};
```

---

## Legacy Handshake Methods (Removed)

**Note**: The following legacy methods have been removed from the fork-first architecture:
- `HandshakeManager::init_xdp()` - XDP Poll child creates XSK directly
- `HandshakeManager::tcp_handshake()` - Transport child performs via IPC
- `HandshakeManager::tls_handshake()` - Transport child performs via IPC
- `HandshakeManager::websocket_upgrade()` - Transport child performs via IPC
- `HandshakeManager::send_subscriptions()` - Transport child sends after WS upgrade

All handshake logic is now in `TransportProcess::init_with_handshake()`.
See [Transport IPC Handshake Implementation](#transport-ipc-handshake-implementation) for details.

---

## Step 2: Fork Processes (Fork-First Architecture)

In fork-first architecture, ALL processes are forked BEFORE any network activity.
XDP Poll creates the XSK socket fresh, and Transport performs handshake via IPC rings.

```cpp
void HandshakeManager::fork_processes() {
    // Initialize all per-process running flags
    for (int i = 0; i < PROC_COUNT; ++i) {
        tcp_state_->running[i].flag.store(1, std::memory_order_release);
    }


    // Fork XDP Poll FIRST (creates XSK socket fresh)
    pid_t xdp_pid = fork();
    if (xdp_pid == 0) {
        install_signal_handlers(tcp_state_);
        pin_to_core(config_.cpu_cores[PROC_XDP_POLL]);
        run_xdp_poll_fresh();  // Creates XSK from scratch
        exit(0);
    }
    child_pids_[0] = xdp_pid;

    // Fork Transport (waits for XDP, performs handshake, sends subscription)
    pid_t transport_pid = fork();
    if (transport_pid == 0) {
        install_signal_handlers(tcp_state_);
        pin_to_core(config_.cpu_cores[PROC_TRANSPORT]);
        run_transport_with_handshake();  // Performs TCP/TLS/WS + subscription
        exit(0);
    }
    child_pids_[1] = transport_pid;

    // Fork WebSocket
    pid_t ws_pid = fork();
    if (ws_pid == 0) {
        install_signal_handlers(tcp_state_);
        pin_to_core(config_.cpu_cores[PROC_WEBSOCKET]);
        run_websocket();
        exit(0);
    }
    child_pids_[2] = ws_pid;

    // Parent: wait for handshake completion
    install_signal_handlers(tcp_state_);
    pin_to_core(config_.cpu_cores[PROC_APPCLIENT]);

    // Wait for handshake completion (with timeout)
    if (!tcp_state_->wait_for_handshake_ws_ready(60000000)) {  // 60s
        fprintf(stderr, "[FORK] ERROR: Handshake timeout\n");
        shutdown();
        return;
    }
    printf("[FORK] Handshake complete, all processes ready\n");

    // Parent now runs AppClient loop (user code)
}

// Shutdown: Signal all processes via per-process running flags
void HandshakeManager::shutdown() {
    tcp_state_->shutdown_all();  // Sets all running flags to 0

    // Send SIGTERM to child processes
    for (int i = 0; i < 3; i++) {  // Only 3 children, parent is AppClient
        if (child_pids_[i] > 0) {
            kill(child_pids_[i], SIGTERM);
        }
    }
}
```

### CPU Pinning Helper

```cpp
void pin_to_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    int result = sched_setaffinity(0, sizeof(cpuset), &cpuset);
    if (result != 0) {
        perror("sched_setaffinity");
        exit(1);
    }

    // Also set scheduler priority (optional)
    struct sched_param param;
    param.sched_priority = 99;
    sched_setscheduler(0, SCHED_FIFO, &param);
}
```

---

## Fork Safety

**Critical**: After fork(), each process inherits all file descriptors and memory mappings but must only use resources appropriate to its role.

| Resource | XDP Poll | Transport | WebSocket | AppClient |
|----------|----------|-----------|-----------|-----------|
| XDP socket fd | **YES** | No | No | No |
| SSL* / BIO* | No | **YES** | No | No |
| UMEM buffer | Read/Write | Read/Write | Read-only | Read-only |
| Shared memory | Read/Write | Read/Write | Read/Write | Read/Write |
| Ring buffers | Per role | Per role | Per role | Per role |

**Process Isolation**:
```cpp
// After fork in XDP Poll process:
// - Close SSL resources (not needed)
// - ssl_ destructor not called in child

// After fork in Transport process:
// - XDP socket fd is inherited but not used directly
// - Access UMEM via shared memory pointer

// After fork in WebSocket process:
// - Read-only access to MSG_INBOX
// - No SSL or XDP socket access

// After fork in AppClient process:
// - Read-only access to MSG_INBOX
// - Write to MSG_OUTBOX only
```

---

## Reconnection Support

In fork-first architecture, reconnection requires terminating and restarting all child processes:

```cpp
// Reconnection in fork-first architecture
void HandshakeManager::reconnect() {
    // 1. Signal all processes to shutdown
    tcp_state_->shutdown_all();

    // 2. Wait for children to exit
    for (int i = 0; i < 3; i++) {
        if (child_pids_[i] > 0) {
            waitpid(child_pids_[i], nullptr, 0);
        }
    }

    // 3. Reset shared state
    tcp_state_->init();

    // 4. Re-fork all processes (handshake will be performed by Transport)
    fork_processes();
}
```

**Note**: Reconnection triggers a full restart of the pipeline. The Transport child will
perform a fresh TCP/TLS/WS handshake and resend subscriptions.

---

## Transport Type Trait Dispatch

**Reference**: Pattern from `src/websocket.hpp` lines 97-121

Compile-time dispatch for transport types enables zero-overhead abstraction:

```cpp
namespace websocket::traits {

// Primary template: Default to userspace transport (XDP, DPDK)
template<typename T, typename = void>
struct is_fd_based_transport : std::false_type {};

// Specialization: BSD socket transports have get_fd() returning int
template<typename T>
struct is_fd_based_transport<T,
    std::enable_if_t<std::is_same_v<decltype(std::declval<T>().get_fd()), int>>>
    : std::true_type {};

template<typename T>
inline constexpr bool is_fd_based_transport_v = is_fd_based_transport<T>::value;

} // namespace websocket::traits

// Usage in handshake (compile-time dispatch)
template<typename TransportPolicy>
void perform_ssl_handshake(TransportPolicy& transport, SSLPolicy& ssl) {
    constexpr bool is_fd_based = websocket::traits::is_fd_based_transport_v<TransportPolicy>;

    if constexpr (is_fd_based) {
        // BSD socket: use fd-based handshake (supports kTLS)
        int fd = transport.get_fd();
        ssl.handshake(fd);
    } else {
        // XDP/Userspace: use userspace transport BIO
        ssl.handshake_userspace_transport(&transport);
    }
}
```

---

## Dead Connection Detection

**Reference**: Pattern from `src/websocket.hpp` lines 1629-1631

Detect stale connections during handshake with timeout tracking:

```cpp
// Handshake timeout configuration
static constexpr int HANDSHAKE_TIMEOUT_SEC = 10;
static constexpr int TCP_SYN_RETRIES = 3;
static constexpr int TLS_HANDSHAKE_TIMEOUT_SEC = 5;

// Track consecutive timeouts
struct TimeoutTracker {
    int consecutive_timeouts = 0;
    static constexpr int MAX_CONSECUTIVE = 60;  // 60 seconds max

    bool check_timeout(int wait_result) {
        if (wait_result <= 0) {
            consecutive_timeouts++;
            if (consecutive_timeouts >= MAX_CONSECUTIVE) {
                return true;  // Dead connection
            }
        } else {
            consecutive_timeouts = 0;  // Reset on activity
        }
        return false;
    }
};
```

---

## Complete Handshake Flow (Fork-First Architecture)

```cpp
// Fork-first architecture: Handshake happens AFTER fork in Transport child

bool HandshakeManager::init(const Config& config) {
    config_ = config;

    // Step 1: Create all shared memory
    create_umem();
    create_state_shm();
    create_msg_inbox();

    // Step 2: Get network info
    get_network_info();

    // Step 3: Calibrate TSC frequency (once in parent)
    tcp_state_->tsc_freq_hz = calibrate_tsc_freq();

    // Step 4: Create IPC rings
    create_ipc_rings();

    // Step 5: Store target config in shared memory
    strncpy(tcp_state_->target_host, config.host, sizeof(tcp_state_->target_host) - 1);
    tcp_state_->target_port = config.port;
    strncpy(tcp_state_->target_path, config.path, sizeof(tcp_state_->target_path) - 1);
    strncpy(tcp_state_->bpf_path, config.bpf_path, sizeof(tcp_state_->bpf_path) - 1);
    strncpy(tcp_state_->interface_name, config.interface,
            sizeof(tcp_state_->interface_name) - 1);
    if (config.subscription) {
        strncpy(tcp_state_->subscription_json, config.subscription,
                sizeof(tcp_state_->subscription_json) - 1);
    }

    return true;
}

// Handshake happens in Transport child process (see run_transport_with_handshake)
// Parent calls fork_processes() which:
//   1. Forks XDP Poll (creates XSK fresh, signals xdp_ready)
//   2. Forks Transport (waits for XDP, performs TCP/TLS/WS, signals ws_ready)
//   3. Forks WebSocket
//   4. Parent waits for ws_ready, then runs AppClient

// Transport child handshake flow:
// 1. Wait for XDP Poll to signal xdp_ready (XSK socket created)
// 2. Perform TCP 3-way handshake via IPC rings
// 3. Perform TLS handshake via IPC rings
// 4. Perform WebSocket upgrade via IPC rings
// 5. Send subscription message via IPC rings
// 6. Signal ws_ready
// 7. Enter main loop
```

---

## Transport IPC Handshake Implementation

The Transport process performs the complete handshake via IPC rings using direct packet construction.
This is implemented in `TransportProcess::init_with_handshake()` and its helper methods.

### Direct IPC Approach (Implemented)

Instead of reusing `XDPUserspaceTransport` (which owns its own XSK socket), the Transport process
uses `UserspaceStack` directly to build/parse TCP packets and exchanges them via IPC rings:

```cpp
// TransportProcess handshake via IPC (from transport_process.hpp)

bool init_with_handshake(...) {
    // Initialize UserspaceStack for packet building/parsing
    stack_.init(local_ip_str, gateway_ip_str, netmask_str, tcp_state_->local_mac);

    // TCP handshake via IPC
    if (!perform_tcp_handshake_via_ipc(target_host, target_port)) return false;

    // TLS handshake via IPC
    if (!perform_tls_handshake_via_ipc(target_host)) return false;

    // WebSocket upgrade via IPC
    if (!perform_websocket_upgrade_via_ipc(target_host, target_path)) return false;

    // Subscription via IPC
    if (!send_subscription_via_ipc(subscription)) return false;

    tcp_state_->set_handshake_ws_ready();
    return true;
}
```

### TCP Handshake via IPC

```cpp
bool perform_tcp_handshake_via_ipc(const char* target_host, uint16_t target_port) {
    // 1. Resolve hostname to IP
    struct addrinfo hints = {}, *res = nullptr;
    hints.ai_family = AF_INET;
    getaddrinfo(target_host, nullptr, &hints, &res);
    uint32_t remote_ip = ntohl(((sockaddr_in*)res->ai_addr)->sin_addr.s_addr);

    // 2. Initialize TCP params
    tcp_params_.remote_ip = remote_ip;
    tcp_params_.remote_port = target_port;
    tcp_params_.local_port = UserspaceStack::generate_port();
    tcp_params_.snd_nxt = UserspaceStack::generate_isn();

    // 3. Build and send SYN via RAW_OUTBOX
    uint32_t syn_frame_idx = allocate_msg_frame();
    uint8_t* syn_buffer = umem_area_ + frame_idx_to_addr(syn_frame_idx, frame_size_);
    size_t syn_len = stack_.build_syn(syn_buffer, frame_size_, tcp_params_);

    UMEMFrameDescriptor syn_desc{...};
    raw_outbox_prod_->try_publish(syn_desc);
    tcp_params_.snd_nxt++;  // SYN consumes 1 seq

    // 4. Wait for SYN-ACK via RAW_INBOX
    while (!got_synack) {
        UMEMFrameDescriptor rx_desc;
        if (raw_inbox_cons_->try_consume(rx_desc)) {
            auto parsed = stack_.parse_tcp(frame, rx_desc.frame_len, ...);
            if (parsed.valid && (parsed.flags & TCP_FLAG_SYN) && (parsed.flags & TCP_FLAG_ACK)) {
                tcp_params_.rcv_nxt = parsed.seq + 1;
                tcp_params_.snd_una = parsed.ack;
                got_synack = true;
            }
        }
    }

    // 5. Send ACK via ACK_OUTBOX
    uint32_t ack_frame_idx = allocate_ack_frame();
    size_t ack_len = stack_.build_ack(ack_buffer, frame_size_, tcp_params_);
    ack_outbox_prod_->try_publish(ack_desc);

    return true;  // TCP ESTABLISHED
}
```

### TLS Handshake via IPC

```cpp
bool perform_tls_handshake_via_ipc(const char* target_host) {
    // 1. Initialize SSL policy (creates context and SSL object)
    ssl_policy_.init();
    wolfSSL_UseSNI(ssl_policy_.ssl(), WOLFSSL_SNI_HOST_NAME, target_host, strlen(target_host));

    // 2. Non-blocking handshake loop
    while (!handshake_complete) {
        int ret = wolfSSL_connect(ssl_policy_.ssl());
        if (ret == WOLFSSL_SUCCESS) {
            handshake_complete = true;
            break;
        }

        int err = wolfSSL_get_error(ssl_policy_.ssl(), ret);
        if (err == WOLFSSL_ERROR_WANT_READ) {
            tls_handshake_recv();  // Receive via RAW_INBOX, feed to SSL
        } else if (err == WOLFSSL_ERROR_WANT_WRITE) {
            tls_handshake_send();  // Get from SSL, send via RAW_OUTBOX
        }

        tls_handshake_send();  // Always flush pending outbound
    }
    return true;
}

bool tls_handshake_send() {
    // Get encrypted data from SSL policy
    size_t pending = ssl_policy_.encrypted_pending();
    if (pending == 0) return false;

    uint8_t encrypted[4096];
    ssize_t ret = ssl_policy_.get_encrypted(encrypted, sizeof(encrypted));

    // Build TCP data packet and send via RAW_OUTBOX
    size_t frame_len = stack_.build_data(frame, frame_size_, tcp_params_, encrypted, ret);
    raw_outbox_prod_->try_publish(desc);
    tcp_params_.snd_nxt += ret;
    return true;
}

bool tls_handshake_recv() {
    // Consume from RAW_INBOX
    UMEMFrameDescriptor rx_desc;
    if (!raw_inbox_cons_->try_consume(rx_desc)) return false;

    auto parsed = stack_.parse_tcp(frame, rx_desc.frame_len, ...);
    if (parsed.payload_len > 0) {
        tcp_params_.rcv_nxt += parsed.payload_len;
        ssl_policy_.feed_encrypted(parsed.payload, parsed.payload_len);
        send_ack_during_handshake();
    }
    return true;
}
```

### WebSocket Upgrade via IPC

```cpp
bool perform_websocket_upgrade_via_ipc(const char* target_host, const char* target_path) {
    // Build HTTP upgrade request
    char request[1024];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n", target_path, target_host, ws_key);

    // Send via SSL
    ssl_policy_.write(request, req_len);
    tls_handshake_send();

    // Wait for 101 response
    while (true) {
        if (tls_handshake_recv()) {
            ssize_t ret = ssl_policy_.read(response + response_len, ...);
            if (ret > 0 && strstr(response, "101")) {
                return true;  // WebSocket upgraded
            }
        }
    }
}
```

### Key Design Decisions

1. **Direct IPC vs XDPUserspaceTransport**: The Transport process uses `UserspaceStack` directly
   instead of `XDPUserspaceTransport` because:
   - `XDPUserspaceTransport` owns its own XSK socket
   - In fork-first, XDP Poll owns the XSK socket
   - Transport must use IPC rings for all network I/O

2. **Frame Allocation**: During handshake, Transport uses the same frame allocation pools
   as the main loop (ACK frames for ACKs, MSG frames for data).

3. **Blocking Handshake**: The handshake uses polling loops with `usleep()` instead of
   busy-polling since latency is not critical during connection setup.

4. **SSL Policy**: Uses `PipelineSSLPolicy` with memory buffers (`feed_encrypted()` /
   `get_encrypted()`) rather than file descriptor-based I/O.

---

## Helper Functions

### Found in Codebase

| Function | Location | Signature |
|----------|----------|-----------|
| `resolve_hostname` | `src/policy/transport.hpp:649` | `static std::vector<std::string> resolve_hostname(const char* hostname)` |
| `ip_to_string` | `src/stack/ip/ip_layer.hpp:226` | `static std::string ip_to_string(uint32_t ip_host_order)` |
| `ip_to_string` | `src/stack/userspace_stack.hpp:231` | `static std::string ip_to_string(uint32_t ip)` (wrapper) |

### Need Implementation

These helpers are used in handshake code but not yet implemented:

| Function | Description | Suggested Location |
|----------|-------------|-------------------|
| `get_interface_ip` | Get IPv4 address of NIC interface | `src/stack/utils.hpp` |
| `get_interface_mac` | Get MAC address of NIC interface | `src/stack/utils.hpp` |
| `get_default_gateway` | Get default gateway IP for interface | `src/stack/utils.hpp` |
| `get_time_ns` | Get current time in nanoseconds | `src/core/timing.hpp` |
| `base64_encode` | Base64 encode bytes to string | `src/core/http.hpp` |
| `fill_random` | Fill buffer with random bytes | `src/core/utils.hpp` |
| `SHA1` | Compute SHA-1 hash (for WS accept key) | Use SSL library (OpenSSL/WolfSSL) |

**Implementation Notes**:
- `get_interface_ip`: Use `ioctl(SIOCGIFADDR)` on Linux
- `get_interface_mac`: Use `ioctl(SIOCGIFHWADDR)` on Linux
- `get_default_gateway`: Parse `/proc/net/route` or use `netlink` socket
- `SHA1`: Use `SHA1()` from OpenSSL or `wc_Sha()` from WolfSSL

---

## Usage Example (Fork-First Architecture)

```cpp
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // Configure the pipeline
    HandshakeManager<WolfSSLPolicy>::Config config;
    config.interface = argv[1];
    config.host = "stream.binance.com";
    config.port = 443;
    config.path = "/ws";
    config.bpf_path = "build/exchange_filter.bpf.o";
    config.cpu_cores[PROC_XDP_POLL] = 2;
    config.cpu_cores[PROC_TRANSPORT] = 4;
    config.cpu_cores[PROC_WEBSOCKET] = 6;
    config.cpu_cores[PROC_APPCLIENT] = 8;

    // Subscription is stored in shared memory and sent by Transport child after WS upgrade
    config.subscription = R"({"method":"SUBSCRIBE","params":["btcusdt@trade"],"id":1})";

    HandshakeManager<WolfSSLPolicy> manager;

    // Initialize shared memory and store config (NO network activity yet)
    if (!manager.init(config)) {
        fprintf(stderr, "Initialization failed\n");
        return 1;
    }

    printf("Shared memory created, forking processes...\n");

    // Fork all processes - handshake performed by Transport child via IPC
    // This call blocks until handshake completes (or timeout)
    manager.fork_processes();

    // Parent is now AppClient - run user code
    // ... (user main loop using msg_inbox, ws_frame_info, etc.)

    // Cleanup on exit
    manager.cleanup();

    return 0;
}
```

**Key Points**:
1. Subscription JSON is passed via `config.subscription`, NOT called separately
2. `init()` only creates shared memory - no network I/O
3. `fork_processes()` forks children AND waits for handshake completion
4. Transport child performs TCP/TLS/WS handshake and sends subscription
5. Parent becomes AppClient after handshake completes

---

## Error Handling

| Stage | Error | Action |
|-------|-------|--------|
| Shared memory creation | shm_open/mmap fails | Return false, log error |
| XDP init | BPF load fails | Return false, check kernel version |
| XDP init | Zero-copy not supported | Return false, check NIC driver |
| TCP handshake | SYN-ACK timeout | Retry 3x with backoff |
| TCP handshake | RST received | Return false, log reason |
| TLS handshake | SSL_connect fails | Return false, log SSL error |
| TLS handshake | Certificate validation | Configure in SSL policy |
| WS upgrade | Non-101 response | Return false, log HTTP status |
| WS upgrade | Invalid accept key | Return false, potential MITM |
| Fork | fork() fails | Abort, system resource issue |
| CPU pinning | sched_setaffinity fails | Continue with warning |

---

## Cleanup

```cpp
void HandshakeManager::cleanup() {
    // Unlink shared memory files
    shm_unlink(shm_paths::UMEM);
    shm_unlink(shm_paths::RAW_INBOX);
    shm_unlink(shm_paths::RAW_OUTBOX);
    shm_unlink(shm_paths::ACK_OUTBOX);
    shm_unlink(shm_paths::PONG_OUTBOX);
    shm_unlink(shm_paths::MSG_INBOX);
    shm_unlink(shm_paths::MSG_METADATA);
    shm_unlink(shm_paths::MSG_OUTBOX);
    shm_unlink(shm_paths::PONGS);
    shm_unlink(shm_paths::WS_FRAME_INFO);
    shm_unlink(shm_paths::TCP_STATE);
    shm_unlink(shm_paths::TX_FRAME_STATE);

    // Remove pipeline directory
    rmdir("/dev/shm/pipeline");

    // Close XDP socket
    xdp_.close();

    // Cleanup SSL
    ssl_.cleanup();
}
```
