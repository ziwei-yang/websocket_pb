// policy/simulator_transport.hpp
// Simulator Transport Policy - Replay recorded traffic for testing
//
// This transport reads from recorded traffic files (created by BSDSocketTransport
// with enable_recording() in DEBUG builds) and replays them as if they came
// from a real network connection.
//
// Traffic file format (32-byte header + payload):
//   Header:
//     0-3:   Magic ("SSLR" for RX, "SSLT" for TX)
//     4-11:  timestamp_ns (uint64_t)
//     12-15: ssl_bytes (uint32_t)
//     16-19: accumulated_before (uint32_t) - only for RX
//     20-31: reserved
//
// Usage:
//   using SimulatorClient = WebSocketClient<NoSSLPolicy, SimulatorTransport, ...>;
//   SimulatorClient client;
//   client.get_transport().open_file("debug_traffic.dat");
//   client.run([](const MessageInfo* msgs, size_t n) { ... });
//
#pragma once

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <type_traits>

// Debug printing - enable with -DDEBUG
#ifdef DEBUG
#define DEBUG_PRINT(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)
#else
#define DEBUG_PRINT(...) ((void)0)
#endif

namespace websocket {
namespace transport {

/**
 * Simulator Transport Policy (Replay-Only)
 *
 * Reads recorded traffic from file and replays it as network data.
 * No real network connection - used for testing and benchmarking.
 *
 * Recording is handled by real transports (BSDSocketTransport) via
 * enable_recording() - this transport only replays.
 */
struct SimulatorTransport {
    SimulatorTransport() = default;

    ~SimulatorTransport() {
        close_file();
    }

    // Prevent copying
    SimulatorTransport(const SimulatorTransport&) = delete;
    SimulatorTransport& operator=(const SimulatorTransport&) = delete;

    // Allow moving
    SimulatorTransport(SimulatorTransport&& other) noexcept
        : fp_(other.fp_)
        , rx_count_(other.rx_count_)
        , tx_count_(other.tx_count_)
        , connected_(other.connected_)
        , timeout_ms_(other.timeout_ms_)
        , pending_rx_bytes_(other.pending_rx_bytes_)
    {
        other.fp_ = nullptr;
        other.rx_count_ = 0;
        other.tx_count_ = 0;
        other.connected_ = false;
        other.pending_rx_bytes_ = 0;
    }

    SimulatorTransport& operator=(SimulatorTransport&& other) noexcept {
        if (this != &other) {
            close_file();
            fp_ = other.fp_;
            rx_count_ = other.rx_count_;
            tx_count_ = other.tx_count_;
            connected_ = other.connected_;
            timeout_ms_ = other.timeout_ms_;
            pending_rx_bytes_ = other.pending_rx_bytes_;
            other.fp_ = nullptr;
            other.rx_count_ = 0;
            other.tx_count_ = 0;
            other.connected_ = false;
            other.pending_rx_bytes_ = 0;
        }
        return *this;
    }

    // ============================================================================
    // TransportPolicy Interface
    // ============================================================================

    void init() {
        // No-op for simulator
    }

    void connect(const char* host, uint16_t port) {
        (void)host;
        (void)port;
        // No real connection - just set connected state
        connected_ = true;
    }

    /**
     * Send data (TX) - log and skip
     *
     * In replay mode, we don't actually send data. We can optionally
     * verify against recorded TX records.
     */
    ssize_t send(const void* buf, size_t len) {
        (void)buf;
        tx_count_++;
        return static_cast<ssize_t>(len);  // Pretend we sent it
    }

    /**
     * Receive data (RX) - read from recorded traffic file
     *
     * Reads next RX record from file. Skips TX records.
     * Returns -1 with errno=EAGAIN when no more data available.
     */
    ssize_t recv(void* buf, size_t len) {
        if (!fp_) {
            errno = ENOTCONN;
            return -1;
        }

        // If we have pending bytes from previous read, continue reading them
        if (pending_rx_bytes_ > 0) {
            size_t to_read = (len < pending_rx_bytes_) ? len : pending_rx_bytes_;
            size_t read = fread(buf, 1, to_read, fp_);
            if (read == 0) {
                // EOF or error - no more data
                connected_ = false;
                errno = EAGAIN;
                return -1;
            }
            pending_rx_bytes_ -= read;
            return static_cast<ssize_t>(read);
        }

        // Read next record header
        while (true) {
            uint8_t header[32];
            size_t hdr_read = fread(header, 1, 32, fp_);
            if (hdr_read < 32) {
                // EOF - no more records
                connected_ = false;
                errno = EAGAIN;
                return -1;
            }

            // Check magic
            if (memcmp(header, "SSLR", 4) == 0) {
                // RX record - read payload
                uint32_t ssl_bytes;
                memcpy(&ssl_bytes, header + 12, 4);

                if (ssl_bytes == 0) {
                    // Empty record, continue to next
                    continue;
                }

                rx_count_++;

                // Read payload (up to len bytes)
                size_t to_read = (len < ssl_bytes) ? len : ssl_bytes;
                size_t read = fread(buf, 1, to_read, fp_);
                if (read == 0) {
                    connected_ = false;
                    errno = EAGAIN;
                    return -1;
                }

                // Track remaining bytes for next recv() call
                pending_rx_bytes_ = ssl_bytes - read;

                // Skip remaining payload if we didn't read it all but have
                // no pending_rx_bytes_ tracking (shouldn't happen with above logic)

                return static_cast<ssize_t>(read);
            } else if (memcmp(header, "SSLT", 4) == 0) {
                // TX record - skip payload and continue
                uint32_t ssl_bytes;
                memcpy(&ssl_bytes, header + 12, 4);
                if (ssl_bytes > 0) {
                    fseek(fp_, ssl_bytes, SEEK_CUR);
                }
                // Continue to next record
            } else {
                // Unknown magic - file may be corrupt
                fprintf(stderr, "[SimulatorTransport] Unknown magic: %c%c%c%c at position %ld\n",
                        header[0], header[1], header[2], header[3],
                        ftell(fp_) - 32);
                connected_ = false;
                errno = EINVAL;
                return -1;
            }
        }
    }

    void close() {
        close_file();
        connected_ = false;
    }

    bool is_connected() const {
        return connected_;
    }

    void set_wait_timeout(int timeout_ms) {
        timeout_ms_ = timeout_ms;
    }

    /**
     * Wait for data availability
     *
     * In simulator, returns immediately if more data in file.
     * Returns 0 (timeout) if no more data.
     *
     * IMPORTANT: Sets connected_ = false when no file or EOF to ensure
     * event loop exits even if is_replay_mode detection fails.
     */
    int wait() {
        if (!fp_) {
            DEBUG_PRINT("[SimulatorTransport::wait] fp_ is nullptr - call open_file() first!\n");
            connected_ = false;  // Force disconnection to exit event loop
            return 0;  // File not opened
        }
        if (feof(fp_)) {
            DEBUG_PRINT("[SimulatorTransport::wait] EOF reached after %lu RX records\n", rx_count_);
            connected_ = false;  // Force disconnection to exit event loop
            return 0;  // End of file
        }
        return 1;  // Data available
    }

    int get_fd() const {
        return -1;  // No file descriptor for simulator
    }

    // BSD socket compatibility (no-ops for simulator)
    void start_event_loop() {
        // No-op - simulator doesn't use event loop
    }

    int get_ready_fd() const {
        return get_fd();  // Always returns -1
    }

    bool is_error() const {
        return !fp_;  // Error if file not opened
    }

    void* get_transport_ptr() {
        return this;
    }

    bool supports_ktls() const {
        return false;  // Simulator doesn't support kTLS
    }

    // Userspace transport interface stubs (no real hardware timestamps in replay)
    void poll() {}  // No-op for simulator
    uint32_t get_hw_timestamp_count() const { return 0; }
    uint64_t get_oldest_rx_hw_timestamp() const { return 0; }
    uint64_t get_latest_rx_hw_timestamp() const { return 0; }
    uint64_t get_hw_timestamp_byte_count() const { return 0; }
    void reset_hw_timestamps() {}

    // ============================================================================
    // File Operations
    // ============================================================================

    /**
     * Open recorded traffic file for replay
     */
    bool open_file(const char* path) {
        close_file();
        fp_ = fopen(path, "rb");
        if (!fp_) {
            return false;
        }
        rx_count_ = 0;
        tx_count_ = 0;
        pending_rx_bytes_ = 0;
        return true;
    }

    void close_file() {
        if (fp_) {
            fclose(fp_);
            fp_ = nullptr;
        }
        pending_rx_bytes_ = 0;
    }

    bool has_more_data() const {
        return fp_ && !feof(fp_);
    }

    // ============================================================================
    // Recording No-ops (Simulator is replay-only)
    // ============================================================================

    void enable_recording(const char* /*path*/) {
        // No-op - simulator doesn't record
    }

    void disable_recording() {
        // No-op
    }

    void write_record(uint8_t* /*buffer*/, size_t /*pos*/, ssize_t /*n*/,
                      size_t /*capacity*/, size_t /*data_written*/) {
        // No-op - simulator doesn't record
    }

    void write_tx_record(const uint8_t* /*data*/, size_t /*len*/) {
        // No-op - simulator doesn't record
    }

    // ============================================================================
    // Replay Statistics
    // ============================================================================

    uint64_t rx_count() const { return rx_count_; }
    uint64_t tx_count() const { return tx_count_; }

private:
    FILE* fp_ = nullptr;
    uint64_t rx_count_ = 0;
    uint64_t tx_count_ = 0;
    bool connected_ = false;
    int timeout_ms_ = 100;
    size_t pending_rx_bytes_ = 0;  // Remaining bytes from current RX record
};

// ============================================================================
// Type Traits for Transport Detection
// ============================================================================

template<typename T>
struct is_simulator_transport : std::false_type {};

template<>
struct is_simulator_transport<SimulatorTransport> : std::true_type {};

template<typename T>
inline constexpr bool is_simulator_transport_v = is_simulator_transport<T>::value;

} // namespace transport
} // namespace websocket
