// policy/ssl.hpp
// Unified SSL/TLS Policy - supports OpenSSL, LibreSSL, WolfSSL
//
// This header provides SSL/TLS implementations for different libraries:
//   - OpenSSLPolicy: OpenSSL with optional kTLS (Linux)
//   - LibreSSLPolicy: LibreSSL (macOS default, no kTLS)
//   - WolfSSLPolicy: WolfSSL (lightweight, no kTLS)
//
// All policies conform to the SSLPolicyConcept interface:
//   - void init()
//   - void handshake(int fd)                              // BSD socket mode
//   - void handshake_userspace_transport(TransportPolicy*) // Userspace TCP mode
//   - ssize_t read(void* buf, size_t len)
//   - ssize_t write(const void* buf, size_t len)
//   - bool ktls_enabled() const
//   - int get_fd() const
//   - void shutdown()
//
// Zero-copy API (pipeline mode):
//   - void init_zero_copy_bio()                           // Initialize zero-copy BIO mode
//   - void set_encrypted_view(const uint8_t*, size_t)     // RX: point to UMEM encrypted data
//   - size_t encrypted_view_consumed() const              // RX: bytes consumed from view
//   - void clear_encrypted_view()                         // RX: done with current view
//   - void set_encrypted_output(uint8_t*, size_t)         // TX: point to UMEM output buffer
//   - size_t encrypted_output_len() const                 // TX: bytes written to output
//   - void clear_encrypted_output()                       // TX: done with current output
//
// Userspace Transport Mode (XDP):
//   When using XDPUserspaceTransport (AF_XDP zero-copy mode), SSL operates over
//   a custom BIO that bridges OpenSSL to the userspace TCP/IP stack. The handshake
//   is done via handshake_userspace_transport(&transport) which:
//     1. Creates a custom BIO using UserspaceTransportBIO
//     2. Polls the transport for TX completion (critical for igc driver)
//     3. Performs non-blocking handshake with retry loop
//   Note: kTLS is not available for userspace transports (no kernel socket).
//
// Namespace: websocket::ssl

#pragma once

#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>  // usleep() for DPDK handshake polling
#include <string>
#include <vector>

#include "../pipeline/pipeline_config.hpp"  // NIC_MTU, PIPELINE_TCP_MSS, MAX_TLS_RECORD_PAYLOAD
#include "../core/aes_ctr.hpp"              // TLSRecordKeys for extract_record_keys()

// ============================================================================
// Library Detection and Headers
// ============================================================================

// Include ALL SSL library headers (they'll compile conditionally based on which is selected)
// Note: WolfSSL and OpenSSL are mutually exclusive, but LibreSSL is OpenSSL-compatible

#if defined(WOLFSSL_USER_SETTINGS) || defined(HAVE_WOLFSSL)
    // WolfSSL selected
    #define SSL_POLICY_WOLFSSL 1
    #include <wolfssl/options.h>
    #include <wolfssl/ssl.h>
#else
    // OpenSSL or LibreSSL (they're API-compatible)
    #define SSL_POLICY_OPENSSL 1
    #define SSL_POLICY_LIBRESSL 1
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/bio.h>
    #include <openssl/kdf.h>
    #include <openssl/evp.h>
#endif

// Forward declaration for userspace transport BIO
#include "userspace_transport_bio.hpp"

namespace websocket {
namespace ssl {

// ============================================================================
// Zero-Copy View Ring Buffer (shared by all policies)
// ============================================================================

/**
 * ViewSegment - A single pointer+length view into encrypted data
 * Used to accumulate multiple packet views before SSL decryption
 */
struct ViewSegment {
    const uint8_t* data = nullptr;
    size_t len = 0;
};

// Ring buffer constants (power of 2 for fast modulo)
inline constexpr size_t VIEW_RING_SIZE = 1024;
inline constexpr size_t VIEW_RING_MASK = VIEW_RING_SIZE - 1;

// ============================================================================
// OpenSSL Policy (with optional kTLS support)
// ============================================================================

#ifdef SSL_POLICY_OPENSSL

/**
 * OpenSSLPolicy - OpenSSL implementation with optional kernel TLS (kTLS)
 *
 * Features:
 *   - TLS 1.2+ support
 *   - Kernel TLS offload on Linux (if available)
 *   - Zero-copy encryption/decryption with kTLS
 *   - Industry standard, widely used
 *
 * kTLS Benefits (Linux 4.17+):
 *   - 5-10% lower CPU usage
 *   - Reduced memory copies
 *   - Better throughput for large messages
 *
 * Thread safety: Not thread-safe (designed for single connection per instance)
 */
struct OpenSSLPolicy {
    OpenSSLPolicy() : ctx_(nullptr), ssl_(nullptr), ktls_enabled_(false), bio_method_(nullptr) {}

    ~OpenSSLPolicy() {
        cleanup();  // Full cleanup including ctx_
    }

    // Prevent copying
    OpenSSLPolicy(const OpenSSLPolicy&) = delete;
    OpenSSLPolicy& operator=(const OpenSSLPolicy&) = delete;

    // Allow moving
    OpenSSLPolicy(OpenSSLPolicy&& other) noexcept
        : ctx_(other.ctx_)
        , ssl_(other.ssl_)
        , ktls_enabled_(other.ktls_enabled_)
    {
        other.ctx_ = nullptr;
        other.ssl_ = nullptr;
        other.ktls_enabled_ = false;
    }

    OpenSSLPolicy& operator=(OpenSSLPolicy&& other) noexcept {
        if (this != &other) {
            shutdown();
            ctx_ = other.ctx_;
            ssl_ = other.ssl_;
            ktls_enabled_ = other.ktls_enabled_;
            other.ctx_ = nullptr;
            other.ssl_ = nullptr;
            other.ktls_enabled_ = false;
        }
        return *this;
    }

    /**
     * Initialize SSL context
     *
     * @return 0 on success, -1 on failure
     */
    int init() {
        // Initialize OpenSSL library (OpenSSL 1.1.0+ does this automatically)
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        #endif

        // Create TLS client method
        const SSL_METHOD* method = TLS_client_method();
        ctx_ = SSL_CTX_new(method);

        if (!ctx_) {
            fprintf(stderr, "[TLS] SSL_CTX_new() failed\n");
            return -1;
        }

        // Set TLS version range: 1.2 minimum, 1.3 maximum
        // TLS 1.3 ClientHello can be ~1540 bytes, exceeding MTU. The Hybrid Approach
        // handles this via TCP segmentation in tls_handshake_send_from_buffer().
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);

        // Disable session tickets (reduces ClientHello size slightly)
        // NOTE: Removed SSL_OP_NO_TICKET to allow empty session_ticket extension like Python
        // SSL_CTX_set_options(ctx_, SSL_OP_NO_TICKET);

        // =================================================================
        // Match Python ClientHello exactly for Binance compatibility
        // =================================================================

        // 1. Add ClientHello padding to 512 bytes (matches Python)
        SSL_CTX_set_options(ctx_, SSL_OP_TLSEXT_PADDING);

        // 1b. Enable secure renegotiation to add SCSV cipher (0x00ff)
        // This ensures TLS_EMPTY_RENEGOTIATION_INFO_SCSV is in cipher list
        // Clear any options that might prevent SCSV from being added
        SSL_CTX_clear_options(ctx_, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_CTX_clear_options(ctx_, SSL_OP_NO_RENEGOTIATION);
#endif

        // 2. Set supported groups to match Python (10 groups)
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        if (SSL_CTX_set1_groups_list(ctx_,
            "X25519:P-256:X448:P-521:P-384:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192") != 1) {
            fprintf(stderr, "[TLS] Warning: Failed to set supported groups\n");
        }
#endif

        // 2b. EC point formats are automatically determined by OpenSSL based on curves
        // Python sends 3 formats (uncompressed, ansiX962_compressed_prime/char2)
        // OpenSSL typically sends only uncompressed, which is fine for TLS 1.3
        // TLS 1.3 mandates uncompressed format only (RFC 8446 Section 4.2.8.2)
        // For TLS 1.2 with Python fingerprint match, this is a minor difference

        // 3. Set signature algorithms to match Python exactly (20 algorithms, 40 bytes)
        // Order from Python PCAP: ECDSA→EdDSA→RSA-PSS-PSS→RSA-PSS-RSAE→RSA-PKCS1→Legacy→DSA
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
        SSL_CTX_set1_sigalgs_list(ctx_,
            // ECDSA with SHA-2 (04 03, 05 03, 06 03)
            "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:"
            // EdDSA curves (08 07, 08 08)
            "ed25519:ed448:"
            // RSA-PSS with PSS padding (08 09, 08 0a, 08 0b)
            "rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:"
            // RSA-PSS with RSAE padding (08 04, 08 05, 08 06)
            "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:"
            // RSA PKCS#1 v1.5 (04 01, 05 01, 06 01)
            "RSA+SHA256:RSA+SHA384:RSA+SHA512:"
            // Legacy SHA-1 (03 03, 03 01)
            "ECDSA+SHA1:RSA+SHA1:"
            // DSA variants (03 02, 04 02, 05 02, 06 02)
            "DSA+SHA1:DSA+SHA256:DSA+SHA384:DSA+SHA512");
#endif

        // 4. Set TLS 1.3 ciphersuites - Python order: AES-256 FIRST
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
        SSL_CTX_set_ciphersuites(ctx_,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
#endif

        // 5. Set TLS 1.2 ciphers - Python order (31 total ciphers)
        SSL_CTX_set_cipher_list(ctx_,
            // ECDHE + AES-GCM (highest priority)
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES256-GCM-SHA384:"
            // ECDHE + ChaCha20
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "DHE-RSA-CHACHA20-POLY1305:"
            // ECDHE + AES-128-GCM
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "DHE-RSA-AES128-GCM-SHA256:"
            // ECDHE + AES-CBC-SHA384/SHA256
            "ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:"
            "DHE-RSA-AES256-SHA256:"
            "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:"
            "DHE-RSA-AES128-SHA256:"
            // ECDHE + AES-CBC-SHA (legacy)
            "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:"
            "DHE-RSA-AES256-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:"
            "DHE-RSA-AES128-SHA:"
            // RSA-only fallbacks
            "AES256-GCM-SHA384:AES128-GCM-SHA256:"
            "AES256-SHA256:AES128-SHA256:"
            "AES256-SHA:AES128-SHA");

        // Limit TLS record size to fit in single TCP segment (Hybrid Approach for MTU)
        // MAX_TLS_RECORD_PAYLOAD = PIPELINE_TCP_MSS - TLS13_OVERHEAD (from pipeline_config.hpp)
        // This is derived from NIC_MTU which is a compile-time argument
        SSL_CTX_set_max_send_fragment(ctx_, pipeline::MAX_TLS_RECORD_PAYLOAD);

        // Disable verification for simplicity (HFT optimization)
        // In production, you should verify certificates!
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);

        #ifdef __linux__
        #ifdef ENABLE_KTLS
        // Enable kTLS (kernel TLS offload) when requested
        // Note: kTLS prevents access to socket-level timestamps
        SSL_CTX_set_options(ctx_, SSL_OP_ENABLE_KTLS);
        #else
        // Disable kTLS to allow hardware timestamp retrieval
        // kTLS (kernel TLS) prevents access to socket-level timestamps
        // SSL_CTX_set_options(ctx_, SSL_OP_ENABLE_KTLS);  // DISABLED for timestamp access
        #endif
        #endif

        // Register keylog callback for TLS key extraction (ssl_read_by_chunk)
        SSL_CTX_set_keylog_callback(ctx_, keylog_callback);

        // Register msg_callback for TLS record counting (seq_num tracking)
        SSL_CTX_set_msg_callback(ctx_, record_count_callback);
        return 0;
    }

    uint64_t get_server_record_count() const { return server_record_count_; }

    /**
     * Perform TLS handshake
     *
     * @param fd Socket file descriptor
     * @throws std::runtime_error if handshake fails
     */
    void handshake(int fd) {
        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            if (init() != 0) throw std::runtime_error("OpenSSL init() failed");
        }

        keylog_lines_.clear();

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            if (init() != 0) throw std::runtime_error("SSL init() failed");
            ssl_ = SSL_new(ctx_);
        }

        if (!ssl_) {
            throw std::runtime_error("SSL_new() failed");
        }

        // Store policy pointer in SSL ex_data for keylog callback
        SSL_set_ex_data(ssl_, get_ex_data_index(), this);

        // Associate socket with SSL object
        if (SSL_set_fd(ssl_, fd) != 1) {
            throw std::runtime_error("SSL_set_fd() failed");
        }

        // Perform TLS handshake (blocking)
        int ret = SSL_connect(ssl_);
        if (ret != 1) {
            int err = SSL_get_error(ssl_, ret);
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            throw std::runtime_error(std::string("SSL_connect() failed: ") + err_buf);
        }

        // Log negotiated TLS version and cipher
        const char* version = SSL_get_version(ssl_);
        const char* cipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl_));
        fprintf(stderr, "[TLS] Handshake SUCCESS (BSD socket)\n");
        fprintf(stderr, "[TLS]   Version: %s\n", version ? version : "unknown");
        fprintf(stderr, "[TLS]   Cipher:  %s\n", cipher ? cipher : "unknown");

        #if defined(__linux__) && !defined(USE_LIBRESSL) && !defined(HAVE_WOLFSSL)
        // Check if kTLS was successfully activated (OpenSSL only)
        BIO* wbio = SSL_get_wbio(ssl_);
        BIO* rbio = SSL_get_rbio(ssl_);

        if (wbio && BIO_get_ktls_send(wbio)) {
            ktls_enabled_ = true;
        }

        // For receive-side kTLS (requires kernel 4.17+)
        if (rbio && BIO_get_ktls_recv(rbio)) {
            // Both send and receive kTLS enabled
        }
        #endif

        // Reset server record counter — only count post-handshake records
        server_record_count_ = 0;
    }

    /**
     * Perform TLS handshake over userspace transport
     *
     * Works with any transport policy implementing send/recv/poll interface.
     * Example: XDPUserspaceTransport, or any custom userspace TCP stack.
     *
     * @param transport Transport policy instance
     * @param hostname  Optional hostname for SNI (Server Name Indication)
     * @return 0 on success, -1 on failure
     */
    template<typename TransportPolicy>
    int handshake_userspace_transport(TransportPolicy* transport, const char* hostname = nullptr) {
        if (!transport) {
            fprintf(stderr, "[TLS] Transport is null in handshake_userspace_transport\n");
            return -1;
        }

        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            if (init() != 0) return -1;
        }

        keylog_lines_.clear();

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            if (init() != 0) return -1;
            ssl_ = SSL_new(ctx_);
        }

        if (!ssl_) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            fprintf(stderr, "[TLS] SSL_new() failed: %s\n", err_buf);
            return -1;
        }

        // Store policy pointer in SSL ex_data for keylog callback
        SSL_set_ex_data(ssl_, get_ex_data_index(), this);

        // Set SNI hostname for virtual hosting
        if (hostname) {
            SSL_set_tlsext_host_name(ssl_, hostname);
        }

        // Create custom BIO for userspace transport
        bio_method_ = websocket::policy::UserspaceTransportBIO<TransportPolicy>::create_bio_method();
        if (!bio_method_) {
            SSL_free(ssl_);
            ssl_ = nullptr;
            fprintf(stderr, "[TLS] Failed to create userspace transport BIO method\n");
            return -1;
        }

        BIO* bio = websocket::policy::UserspaceTransportBIO<TransportPolicy>::create_bio(bio_method_, transport);
        if (!bio) {
            SSL_free(ssl_);
            ssl_ = nullptr;
            fprintf(stderr, "[TLS] Failed to create userspace transport BIO\n");
            return -1;
        }

        // Associate BIO with SSL object
        SSL_set_bio(ssl_, bio, bio);

        // Set client mode for handshake
        SSL_set_connect_state(ssl_);

        // Perform TLS handshake (non-blocking, polling-based)
        int max_retries = 1000;
        int retries = 0;

        while (retries < max_retries) {
            // Poll transport before handshake attempt
            transport->poll();

            int ret = SSL_do_handshake(ssl_);

            if (ret == 1) {
                // Handshake successful - stop trickle thread, switch to inline trickle
                transport->stop_rx_trickle_thread();
                ktls_enabled_ = false;

                // Log negotiated TLS version and cipher
                const char* version = SSL_get_version(ssl_);
                const char* cipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl_));
                fprintf(stderr, "[TLS] Handshake SUCCESS\n");
                fprintf(stderr, "[TLS]   Version: %s\n", version ? version : "unknown");
                fprintf(stderr, "[TLS]   Cipher:  %s\n", cipher ? cipher : "unknown");

                // Reset server record counter — only count post-handshake records
                server_record_count_ = 0;
                return 0;
            }

            int err = SSL_get_error(ssl_, ret);

            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block, poll and retry
                transport->poll();
                usleep(1000);  // 1ms
                retries++;
                continue;
            }

            // SSL_ERROR_SYSCALL with errno=0 or EAGAIN should be retried
            if (err == SSL_ERROR_SYSCALL) {
                if (errno == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
                    transport->poll();
                    usleep(1000);  // 1ms
                    retries++;
                    continue;
                }
            }

            // Fatal error
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            fprintf(stderr, "[TLS] SSL handshake failed: %s\n", err_buf);
            SSL_free(ssl_);
            ssl_ = nullptr;
            return -1;
        }

        fprintf(stderr, "[TLS] SSL handshake timeout\n");
        SSL_free(ssl_);
        ssl_ = nullptr;
        return -1;
    }

    // Non-blocking handshake stubs (OpenSSL: delegate to blocking for now)
    enum class HandshakeResult : uint8_t { IN_PROGRESS = 0, SUCCESS = 1, ERROR = 2 };
    template<typename TransportPolicy>
    int prepare_handshake(TransportPolicy* transport, const char* hostname) {
        return handshake_userspace_transport(transport, hostname);
    }
    HandshakeResult step_handshake() { return HandshakeResult::SUCCESS; }

    /**
     * Read decrypted data from SSL connection
     *
     * @param buf Buffer to store data
     * @param len Buffer size
     * @return Number of bytes read, 0 on connection close, -1 on error/would-block
     */
    ssize_t read(void* buf, size_t len) {
        if (!ssl_) return -1;

        int n = SSL_read(ssl_, buf, len);

        if (n > 0) {
            return n;  // Success
        } else if (n == 0) {
            return 0;  // Connection closed
        } else {
            int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block (non-blocking socket)
                errno = EAGAIN;  // Set errno for caller
                return -1;
            }

            // Fatal SSL error
            errno = EIO;
            return -1;
        }
    }

    /**
     * Write encrypted data to SSL connection
     *
     * @param buf Data to write
     * @param len Data length
     * @return Number of bytes written, -1 on error/would-block
     */
    ssize_t write(const void* buf, size_t len) {
        if (!ssl_) return -1;

        int n = SSL_write(ssl_, buf, len);

        if (n > 0) {
            return n;  // Success
        } else {
            int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block (non-blocking socket)
                errno = EAGAIN;  // Set errno for caller
                return -1;
            }

            // Fatal SSL error
            errno = EIO;
            return -1;
        }
    }

    /**
     * Check bytes available in SSL read buffer
     * @return Number of bytes buffered in SSL (not yet returned to app)
     */
    size_t pending() const {
        if (!ssl_) return 0;
        return static_cast<size_t>(SSL_pending(ssl_));
    }

    /**
     * Check if kernel TLS is enabled
     *
     * @return true if kTLS is active, false otherwise
     */
    bool ktls_enabled() const {
        return ktls_enabled_;
    }

    /**
     * Get underlying socket file descriptor
     *
     * @return File descriptor, -1 if not set
     */
    int get_fd() const {
        if (!ssl_) return -1;
        return SSL_get_fd(ssl_);
    }

    // ========================================================================
    // Zero-Copy BIO Methods (for pipeline operation)
    // ========================================================================

    /**
     * Initialize zero-copy BIO for decoupled network I/O
     * SSL reads from external pointer (RX) and writes to external pointer (TX)
     */
    void init_zero_copy_bio() {
        if (!ctx_) {
            if (init() != 0) throw std::runtime_error("SSL init() failed");
        }

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            throw std::runtime_error("SSL_new() failed");
        }

        // Create zero-copy BIO method if not already created
        if (!zc_bio_method_) {
            // Use SOURCE_SINK type with unique index (required for proper BIO lifecycle)
            zc_bio_method_ = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "zero-copy");
            if (!zc_bio_method_) {
                SSL_free(ssl_);
                ssl_ = nullptr;
                throw std::runtime_error("BIO_meth_new() failed");
            }
            BIO_meth_set_read(zc_bio_method_, zc_bio_read);
            BIO_meth_set_write(zc_bio_method_, zc_bio_write);
            BIO_meth_set_ctrl(zc_bio_method_, zc_bio_ctrl);
            BIO_meth_set_create(zc_bio_method_, zc_bio_create);
            BIO_meth_set_destroy(zc_bio_method_, zc_bio_destroy);
        }

        // Create BIO instances with this policy as context
        BIO* bio_in = BIO_new(zc_bio_method_);
        BIO* bio_out = BIO_new(zc_bio_method_);
        if (!bio_in || !bio_out) {
            if (bio_in) BIO_free(bio_in);
            if (bio_out) BIO_free(bio_out);
            SSL_free(ssl_);
            ssl_ = nullptr;
            throw std::runtime_error("BIO_new() failed");
        }

        // Store policy pointer in BIO data for callbacks
        BIO_set_data(bio_in, this);
        BIO_set_data(bio_out, this);
        BIO_set_init(bio_in, 1);
        BIO_set_init(bio_out, 1);

        // Attach BIOs to SSL (SSL takes ownership)
        SSL_set_bio(ssl_, bio_in, bio_out);

        // Set client mode
        SSL_set_connect_state(ssl_);
    }

    // ------------------------------------------------------------------------
    // Zero-copy RX API: encrypted data input (pointer view, no copy)
    // ------------------------------------------------------------------------

    /**
     * Append encrypted data view (points to UMEM, no copy)
     * Views accumulate in ring buffer, SSL_read consumes from tail
     * @return 0 on success, -1 if ring buffer is full
     */
    int append_encrypted_view(const uint8_t* data, size_t len) {
        if (len == 0) return 0;  // Empty view is a no-op
        // Check if ring buffer is full (head caught up to tail)
        if (in_view_head_ - in_view_tail_ >= VIEW_RING_SIZE) {
            return -1;  // Ring buffer full
        }
        in_views_[in_view_head_ & VIEW_RING_MASK].data = data;
        in_views_[in_view_head_ & VIEW_RING_MASK].len = len;
        in_view_head_++;
        return 0;
    }

    /**
     * Clear encrypted views (only called on reconnection)
     * Resets ring buffer state
     */
    void clear_encrypted_view() {
        in_view_head_ = 0;
        in_view_tail_ = 0;
        in_view_pos_ = 0;
    }

    /**
     * Get the number of view segments that have been fully consumed by SSL.
     * Used to safely release UMEM frames.
     */
    size_t view_segments_consumed() const {
        return in_view_tail_;
    }

    /**
     * Check if there are any partially consumed view segments.
     */
    bool has_partial_view() const {
        return in_view_pos_ > 0;
    }

    // ------------------------------------------------------------------------
    // Zero-copy TX API: encrypted data output (direct write to UMEM)
    // ------------------------------------------------------------------------

    /**
     * Set encrypted output buffer (points to UMEM payload area)
     * SSL_write will encrypt directly into this buffer
     */
    void set_encrypted_output(uint8_t* buf, size_t capacity) {
        out_buf_ = buf;
        out_buf_capacity_ = capacity;
        out_buf_len_ = 0;
    }

    /**
     * Get bytes written to encrypted output buffer
     */
    size_t encrypted_output_len() const {
        return out_buf_len_;
    }

    // Reset output length without clearing buffer pointer (for handshake loops)
    void reset_encrypted_output_len() {
        out_buf_len_ = 0;
    }

    /**
     * Clear encrypted output buffer (done with current packet)
     */
    void clear_encrypted_output() {
        out_buf_ = nullptr;
        out_buf_capacity_ = 0;
        out_buf_len_ = 0;
    }

    // ------------------------------------------------------------------------

    /**
     * Perform TLS handshake step (for zero-copy BIO mode)
     * Call repeatedly until returns true (handshake complete)
     *
     * @return true if handshake complete, false if need more data
     */
    bool do_handshake_step() {
        if (!ssl_) return false;
        int ret = SSL_do_handshake(ssl_);
        if (ret == 1) return true;  // Complete

        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return false;  // Need more data
        }

        // Fatal error
        return false;
    }

    /**
     * Check if handshake is complete
     */
    bool is_handshake_complete() const {
        return ssl_ && SSL_is_init_finished(ssl_);
    }

    // ========================================================================
    // TLS Key Extraction (for ssl_read_by_chunk)
    // ========================================================================

    /**
     * Extract server record keys for direct AES-CTR decryption.
     * Must be called after handshake completes.
     * Returns true if keys were extracted (AES-GCM cipher), false otherwise.
     */
    bool extract_record_keys(websocket::crypto::TLSRecordKeys& keys) {
        if (!ssl_ || !SSL_is_init_finished(ssl_)) return false;

        // Determine TLS version
        int version = SSL_version(ssl_);
        bool is_tls13 = (version == TLS1_3_VERSION);

        // Check cipher is AES-GCM
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_);
        if (!cipher) return false;

        const char* cipher_name = SSL_CIPHER_get_name(cipher);
        if (!cipher_name) return false;

        // Determine key length from cipher name
        uint8_t key_len = 0;
        if (strstr(cipher_name, "AES128") || strstr(cipher_name, "AES_128")) {
            key_len = 16;
        } else if (strstr(cipher_name, "AES256") || strstr(cipher_name, "AES_256")) {
            key_len = 32;
        } else {
            // Not AES-GCM (e.g., ChaCha20)
            return false;
        }

        // Also verify it's GCM
        if (!strstr(cipher_name, "GCM")) {
            return false;
        }

        keys.key_len = key_len;
        keys.is_tls13 = is_tls13;

        // Parse keylog lines to find the server traffic secret
        if (is_tls13) {
            return extract_tls13_keys(keys);
        } else {
            return extract_tls12_keys(keys);
        }
    }

    // ========================================================================

    /**
     * Shutdown SSL connection (keeps ctx_ for reconnection)
     * Full cleanup happens in destructor
     */
    void shutdown() {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        // Clear zero-copy state
        clear_encrypted_view();
        clear_encrypted_output();
        keylog_lines_.clear();
        // Note: ctx_, bio_method_, zc_bio_method_ kept for reconnection, freed in destructor
        ktls_enabled_ = false;
    }

    /**
     * Full cleanup - called by destructor
     */
    void cleanup() {
        shutdown();  // Free ssl_ first

        if (bio_method_) {
            BIO_meth_free(bio_method_);
            bio_method_ = nullptr;
        }

        if (zc_bio_method_) {
            BIO_meth_free(zc_bio_method_);
            zc_bio_method_ = nullptr;
        }

        if (ctx_) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

    /**
     * Get SSL implementation name
     */
    static constexpr const char* name() {
        return "OpenSSL";
    }

private:
    // Zero-copy BIO callbacks (read from ring buffer, write to out_buf_)
    static int zc_bio_read(BIO* bio, char* buf, int len) {
        auto* self = static_cast<OpenSSLPolicy*>(BIO_get_data(bio));
        if (!self || self->in_view_tail_ == self->in_view_head_) {
            BIO_set_retry_read(bio);
            return -1;  // WANT_READ - ring buffer empty
        }

        size_t total_copied = 0;
        while (total_copied < static_cast<size_t>(len) &&
               self->in_view_tail_ != self->in_view_head_) {

            const auto& seg = self->in_views_[self->in_view_tail_ & VIEW_RING_MASK];
            size_t avail = seg.len - self->in_view_pos_;
            size_t to_copy = (static_cast<size_t>(len) - total_copied < avail)
                           ? (static_cast<size_t>(len) - total_copied) : avail;

            memcpy(buf + total_copied, seg.data + self->in_view_pos_, to_copy);
            total_copied += to_copy;
            self->in_view_pos_ += to_copy;

            // Move to next segment if current is exhausted
            if (self->in_view_pos_ >= seg.len) {
                self->in_view_tail_++;
                self->in_view_pos_ = 0;
            }
        }

        if (total_copied == 0) {
            BIO_set_retry_read(bio);
            return -1;  // WANT_READ
        }
        return static_cast<int>(total_copied);
    }

    static int zc_bio_write(BIO* bio, const char* buf, int len) {
        auto* self = static_cast<OpenSSLPolicy*>(BIO_get_data(bio));
        if (!self || !self->out_buf_) {
            BIO_set_retry_write(bio);
            return -1;  // WANT_WRITE
        }

        size_t space = self->out_buf_capacity_ - self->out_buf_len_;
        if (space == 0) {
            BIO_set_retry_write(bio);
            return -1;  // WANT_WRITE
        }

        size_t to_copy = (static_cast<size_t>(len) < space) ? static_cast<size_t>(len) : space;
        memcpy(self->out_buf_ + self->out_buf_len_, buf, to_copy);
        self->out_buf_len_ += to_copy;
        return static_cast<int>(to_copy);
    }

    static long zc_bio_ctrl(BIO* bio, int cmd, long num, void* ptr) {
        (void)num; (void)ptr;
        auto* self = static_cast<OpenSSLPolicy*>(BIO_get_data(bio));
        switch (cmd) {
            case BIO_CTRL_FLUSH:
                return 1;  // Success
            case BIO_CTRL_PENDING:
                // Return bytes available to read in view ring
                if (self && self->in_view_tail_ != self->in_view_head_) {
                    size_t pending = 0;
                    size_t tail = self->in_view_tail_;
                    size_t head = self->in_view_head_;
                    // Sum all segments from tail to head
                    for (size_t i = tail; i != head; i++) {
                        pending += self->in_views_[i & VIEW_RING_MASK].len;
                    }
                    // Subtract already-consumed portion of current segment
                    if (tail != head) {
                        pending -= self->in_view_pos_;
                    }
                    return static_cast<long>(pending);
                }
                return 0;
            case BIO_CTRL_WPENDING:
                return 0;
            default:
                return 0;
        }
    }

    static int zc_bio_create(BIO* bio) {
        if (!bio) return 0;
        BIO_set_init(bio, 0);
        BIO_set_data(bio, nullptr);
        return 1;
    }

    static int zc_bio_destroy(BIO* bio) {
        if (!bio) return 0;
        BIO_set_init(bio, 0);
        BIO_set_data(bio, nullptr);
        return 1;
    }

    // ========================================================================
    // Keylog callback and key extraction helpers
    // ========================================================================

    static int get_ex_data_index() {
        static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
        return idx;
    }

    static void keylog_callback(const SSL* ssl, const char* line) {
        auto* self = static_cast<OpenSSLPolicy*>(SSL_get_ex_data(ssl, get_ex_data_index()));
        if (self && line) {
            self->keylog_lines_.emplace_back(line);
        }
    }

    static void record_count_callback(int write_p, int version, int content_type,
                                       const void* buf, size_t len, SSL* ssl, void* arg) {
        (void)version; (void)content_type; (void)buf; (void)len; (void)arg;
        if (write_p == 0) {  // 0 = read (server->client)
            auto* self = static_cast<OpenSSLPolicy*>(SSL_get_ex_data(ssl, get_ex_data_index()));
            if (self) self->server_record_count_++;
        }
    }

    // Parse hex string into bytes. Returns number of bytes written.
    static size_t hex_to_bytes(const char* hex, uint8_t* out, size_t max_out) {
        size_t len = strlen(hex);
        size_t bytes = len / 2;
        if (bytes > max_out) bytes = max_out;
        for (size_t i = 0; i < bytes; i++) {
            unsigned int val;
            if (sscanf(hex + i * 2, "%02x", &val) != 1) return i;
            out[i] = static_cast<uint8_t>(val);
        }
        return bytes;
    }

    // TLS 1.3: Find SERVER_TRAFFIC_SECRET_0 in keylog, derive key + IV via HKDF
    bool extract_tls13_keys(websocket::crypto::TLSRecordKeys& keys) {
        // Get client random to match keylog line
        uint8_t client_random[32];
        SSL_get_client_random(ssl_, client_random, 32);

        // Format client random as hex for matching
        char client_random_hex[65];
        for (int i = 0; i < 32; i++) {
            sprintf(client_random_hex + i * 2, "%02x", client_random[i]);
        }
        client_random_hex[64] = '\0';

        // Find SERVER_TRAFFIC_SECRET_0 line
        std::string server_secret_hex;
        for (const auto& line : keylog_lines_) {
            if (line.find("SERVER_TRAFFIC_SECRET_0") == 0) {
                // Format: "SERVER_TRAFFIC_SECRET_0 <client_random_hex> <secret_hex>"
                // Find the secret (third field)
                size_t first_space = line.find(' ');
                if (first_space == std::string::npos) continue;
                size_t second_space = line.find(' ', first_space + 1);
                if (second_space == std::string::npos) continue;
                server_secret_hex = line.substr(second_space + 1);
                break;
            }
        }

        if (server_secret_hex.empty()) return false;

        // Parse secret
        uint8_t secret[48];  // SHA-256 = 32 bytes, SHA-384 = 48 bytes
        size_t secret_len = hex_to_bytes(server_secret_hex.c_str(), secret, sizeof(secret));
        if (secret_len == 0) return false;

        // Determine hash algorithm from cipher
        const EVP_MD* md = (keys.key_len == 32) ? EVP_sha384() : EVP_sha256();

        // HKDF-Expand-Label(secret, "key", "", key_len)
        if (!hkdf_expand_label(md, secret, secret_len, "key", keys.key, keys.key_len)) {
            return false;
        }

        // HKDF-Expand-Label(secret, "iv", "", 12)
        if (!hkdf_expand_label(md, secret, secret_len, "iv", keys.iv, 12)) {
            return false;
        }

        return true;
    }

    // TLS 1.2: Find CLIENT_RANDOM line, derive keys from master secret
    bool extract_tls12_keys(websocket::crypto::TLSRecordKeys& keys) {
        // Get client random
        uint8_t client_random[32];
        SSL_get_client_random(ssl_, client_random, 32);

        char client_random_hex[65];
        for (int i = 0; i < 32; i++) {
            sprintf(client_random_hex + i * 2, "%02x", client_random[i]);
        }
        client_random_hex[64] = '\0';

        // Find CLIENT_RANDOM line
        std::string master_secret_hex;
        for (const auto& line : keylog_lines_) {
            if (line.find("CLIENT_RANDOM") == 0) {
                size_t first_space = line.find(' ');
                if (first_space == std::string::npos) continue;
                size_t second_space = line.find(' ', first_space + 1);
                if (second_space == std::string::npos) continue;

                // Verify client random matches
                std::string line_random = line.substr(first_space + 1, second_space - first_space - 1);
                // Case-insensitive compare
                bool match = (line_random.size() == 64);
                if (match) {
                    for (size_t i = 0; i < 64; i++) {
                        if (tolower(line_random[i]) != tolower(client_random_hex[i])) {
                            match = false;
                            break;
                        }
                    }
                }
                if (match) {
                    master_secret_hex = line.substr(second_space + 1);
                    break;
                }
            }
        }

        if (master_secret_hex.empty()) return false;

        uint8_t master_secret[48];
        size_t ms_len = hex_to_bytes(master_secret_hex.c_str(), master_secret, 48);
        if (ms_len != 48) return false;

        // TLS 1.2 key expansion: PRF(master_secret, "key expansion", server_random + client_random)
        uint8_t server_random[32];
        SSL_get_server_random(ssl_, server_random, 32);

        // key_block = PRF(master_secret, "key expansion", server_random || client_random)
        // For AES-GCM: client_write_key(key_len) + server_write_key(key_len) + client_write_IV(4) + server_write_IV(4)
        size_t key_block_len = 2 * keys.key_len + 2 * 4;  // AES-GCM uses 4-byte implicit IV
        uint8_t key_block[104];  // Max: 2*32 + 2*4 = 72

        // Use TLS PRF via EVP_PKEY_derive
        uint8_t seed[64];
        memcpy(seed, server_random, 32);
        memcpy(seed + 32, client_random, 32);

        if (!tls12_prf(EVP_sha256(), master_secret, 48,
                       "key expansion", seed, 64,
                       key_block, key_block_len)) {
            // Try SHA-384 for AES-256
            if (keys.key_len == 32) {
                if (!tls12_prf(EVP_sha384(), master_secret, 48,
                               "key expansion", seed, 64,
                               key_block, key_block_len)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Extract server_write_key and server_write_IV
        // Layout: client_key(key_len) | server_key(key_len) | client_iv(4) | server_iv(4)
        memcpy(keys.key, key_block + keys.key_len, keys.key_len);   // server_write_key
        memcpy(keys.iv, key_block + 2 * keys.key_len + 4, 4);      // server_write_IV (4 bytes implicit)

        return true;
    }

public:
    // TLS 1.3 HKDF-Expand-Label (public: shared with LibreSSLPolicy)
    static bool hkdf_expand_label(const EVP_MD* md,
                                   const uint8_t* secret, size_t secret_len,
                                   const char* label,
                                   uint8_t* out, size_t out_len) {
        // Build HkdfLabel structure:
        //   uint16 length = out_len
        //   opaque label<7..255> = "tls13 " + label
        //   opaque context<0..255> = ""
        std::string full_label = std::string("tls13 ") + label;

        uint8_t hkdf_label[256];
        size_t pos = 0;
        hkdf_label[pos++] = static_cast<uint8_t>(out_len >> 8);
        hkdf_label[pos++] = static_cast<uint8_t>(out_len);
        hkdf_label[pos++] = static_cast<uint8_t>(full_label.size());
        memcpy(hkdf_label + pos, full_label.data(), full_label.size());
        pos += full_label.size();
        hkdf_label[pos++] = 0;  // Empty context

        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!pctx) return false;

        bool ok = false;
        size_t actual_len = out_len;
        if (EVP_PKEY_derive_init(pctx) > 0 &&
            EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0 &&
            EVP_PKEY_CTX_set_hkdf_md(pctx, md) > 0 &&
            EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, static_cast<int>(secret_len)) > 0 &&
            EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label, static_cast<int>(pos)) > 0 &&
            EVP_PKEY_derive(pctx, out, &actual_len) > 0) {
            ok = (actual_len == out_len);
        }

        EVP_PKEY_CTX_free(pctx);
        return ok;
    }

    // TLS 1.2 PRF (P_SHA256 or P_SHA384)
    static bool tls12_prf(const EVP_MD* md,
                           const uint8_t* secret, size_t secret_len,
                           const char* label,
                           const uint8_t* seed, size_t seed_len,
                           uint8_t* out, size_t out_len) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, nullptr);
        if (!pctx) return false;

        bool ok = false;
        size_t actual_len = out_len;
        if (EVP_PKEY_derive_init(pctx) > 0 &&
            EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) > 0 &&
            EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret, static_cast<int>(secret_len)) > 0 &&
            EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, reinterpret_cast<const unsigned char*>(label), static_cast<int>(strlen(label))) > 0 &&
            EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, static_cast<int>(seed_len)) > 0 &&
            EVP_PKEY_derive(pctx, out, &actual_len) > 0) {
            ok = (actual_len == out_len);
        }

        EVP_PKEY_CTX_free(pctx);
        return ok;
    }

public:
    SSL_CTX* ctx_;
    SSL* ssl_;
    bool ktls_enabled_;
    BIO_METHOD* bio_method_;      // For userspace transport BIO
    BIO_METHOD* zc_bio_method_ = nullptr;  // For zero-copy BIO

    // Zero-copy RX state (ring buffer of UMEM encrypted data views)
    ViewSegment in_views_[VIEW_RING_SIZE];
    size_t in_view_head_ = 0;   // Write position (producer)
    size_t in_view_tail_ = 0;   // Read position (consumer)
    size_t in_view_pos_ = 0;    // Position within current segment

    // Zero-copy TX state (pointer to UMEM output buffer)
    uint8_t* out_buf_ = nullptr;
    size_t out_buf_capacity_ = 0;
    size_t out_buf_len_ = 0;

    // Keylog lines captured during handshake (for key extraction)
    std::vector<std::string> keylog_lines_;

    // Server record counter (post-handshake, for TLS 1.3 seq_num tracking)
    uint64_t server_record_count_ = 0;
};

#endif // SSL_POLICY_OPENSSL

// ============================================================================
// LibreSSL Policy (macOS default, no kTLS)
// ============================================================================

#ifdef SSL_POLICY_LIBRESSL

/**
 * LibreSSLPolicy - LibreSSL implementation (OpenSSL fork)
 *
 * Features:
 *   - TLS 1.2+ support
 *   - Default SSL library on macOS
 *   - No kTLS support (LibreSSL doesn't support it)
 *   - API-compatible with OpenSSL
 *
 * Note: LibreSSL is a security-focused fork of OpenSSL, commonly
 *       used on BSD systems and macOS. It does not support kTLS.
 *
 * Thread safety: Not thread-safe (designed for single connection per instance)
 */
struct LibreSSLPolicy {
    LibreSSLPolicy() : ctx_(nullptr), ssl_(nullptr), bio_method_(nullptr) {}

    ~LibreSSLPolicy() {
        cleanup();  // Full cleanup including ctx_
    }

    // Prevent copying
    LibreSSLPolicy(const LibreSSLPolicy&) = delete;
    LibreSSLPolicy& operator=(const LibreSSLPolicy&) = delete;

    // Allow moving
    LibreSSLPolicy(LibreSSLPolicy&& other) noexcept
        : ctx_(other.ctx_)
        , ssl_(other.ssl_)
        , bio_method_(other.bio_method_)
    {
        other.ctx_ = nullptr;
        other.ssl_ = nullptr;
        other.bio_method_ = nullptr;
    }

    LibreSSLPolicy& operator=(LibreSSLPolicy&& other) noexcept {
        if (this != &other) {
            shutdown();
            ctx_ = other.ctx_;
            ssl_ = other.ssl_;
            bio_method_ = other.bio_method_;
            other.ctx_ = nullptr;
            other.ssl_ = nullptr;
            other.bio_method_ = nullptr;
        }
        return *this;
    }

    /**
     * Initialize SSL context
     *
     * @return 0 on success, -1 on failure
     */
    int init() {
        // Initialize LibreSSL library
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        #endif

        // Create TLS client method
        const SSL_METHOD* method = TLS_client_method();
        ctx_ = SSL_CTX_new(method);

        if (!ctx_) {
            fprintf(stderr, "[TLS] SSL_CTX_new() failed\n");
            return -1;
        }

        // Set TLS version range: 1.2 minimum, 1.3 maximum
        // TLS 1.3 ClientHello can be ~1540 bytes, exceeding MTU. The Hybrid Approach
        // handles this via TCP segmentation in tls_handshake_send_from_buffer().
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx_, TLS1_3_VERSION);

        // Disable session tickets (reduces ClientHello size slightly)
        SSL_CTX_set_options(ctx_, SSL_OP_NO_TICKET);

        // Limit TLS record size to fit in single TCP segment (Hybrid Approach for MTU)
        // MAX_TLS_RECORD_PAYLOAD = PIPELINE_TCP_MSS - TLS13_OVERHEAD (from pipeline_config.hpp)
        // This is derived from NIC_MTU which is a compile-time argument
        SSL_CTX_set_max_send_fragment(ctx_, pipeline::MAX_TLS_RECORD_PAYLOAD);

        // Disable verification for simplicity
        // In production, you should verify certificates!
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);

        // Register keylog callback for TLS key extraction (ssl_read_by_chunk)
        SSL_CTX_set_keylog_callback(ctx_, libressl_keylog_callback);

        // Register msg_callback for TLS record counting (seq_num tracking)
        SSL_CTX_set_msg_callback(ctx_, libressl_record_count_callback);
        return 0;
    }

    uint64_t get_server_record_count() const { return server_record_count_; }

    /**
     * Perform TLS handshake
     *
     * @param fd Socket file descriptor
     * @throws std::runtime_error if handshake fails
     */
    void handshake(int fd) {
        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            if (init() != 0) throw std::runtime_error("LibreSSL init() failed");
        }

        keylog_lines_.clear();

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            if (init() != 0) throw std::runtime_error("SSL init() failed");
            ssl_ = SSL_new(ctx_);
        }

        if (!ssl_) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            throw std::runtime_error(std::string("SSL_new() failed: ") + err_buf);
        }

        // Store policy pointer in SSL ex_data for keylog callback
        SSL_set_ex_data(ssl_, libressl_get_ex_data_index(), this);

        // Associate socket with SSL object
        if (SSL_set_fd(ssl_, fd) != 1) {
            throw std::runtime_error("SSL_set_fd() failed");
        }

        // Perform TLS handshake (blocking)
        int ret = SSL_connect(ssl_);
        if (ret != 1) {
            int err = SSL_get_error(ssl_, ret);
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            throw std::runtime_error(std::string("SSL_connect() failed: ") + err_buf);
        }

        // Log negotiated TLS version and cipher
        const char* version = SSL_get_version(ssl_);
        const char* cipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl_));
        fprintf(stderr, "[TLS] Handshake SUCCESS (BSD socket)\n");
        fprintf(stderr, "[TLS]   Version: %s\n", version ? version : "unknown");
        fprintf(stderr, "[TLS]   Cipher:  %s\n", cipher ? cipher : "unknown");

        // Reset server record counter — only count post-handshake records
        server_record_count_ = 0;
    }

    /**
     * Perform TLS handshake over userspace transport
     *
     * Works with any transport policy implementing send/recv/poll interface.
     * Example: XDPUserspaceTransport, or any custom userspace TCP stack.
     *
     * @param transport Transport policy instance
     * @param hostname  Optional hostname for SNI (Server Name Indication)
     * @return 0 on success, -1 on failure
     */
    template<typename TransportPolicy>
    int handshake_userspace_transport(TransportPolicy* transport, const char* hostname = nullptr) {
        if (!transport) {
            fprintf(stderr, "[TLS] Transport is null in handshake_userspace_transport\n");
            return -1;
        }

        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            if (init() != 0) return -1;
        }

        keylog_lines_.clear();

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            if (init() != 0) return -1;
            ssl_ = SSL_new(ctx_);
        }

        if (!ssl_) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            fprintf(stderr, "[TLS] SSL_new() failed: %s\n", err_buf);
            return -1;
        }

        // Store policy pointer in SSL ex_data for keylog callback
        SSL_set_ex_data(ssl_, libressl_get_ex_data_index(), this);

        // Set SNI hostname for virtual hosting
        if (hostname) {
            SSL_set_tlsext_host_name(ssl_, hostname);
        }

        // Create custom BIO for userspace transport
        bio_method_ = websocket::policy::UserspaceTransportBIO<TransportPolicy>::create_bio_method();
        if (!bio_method_) {
            SSL_free(ssl_);
            ssl_ = nullptr;
            fprintf(stderr, "[TLS] Failed to create userspace transport BIO method\n");
            return -1;
        }

        BIO* bio = websocket::policy::UserspaceTransportBIO<TransportPolicy>::create_bio(bio_method_, transport);
        if (!bio) {
            SSL_free(ssl_);
            ssl_ = nullptr;
            fprintf(stderr, "[TLS] Failed to create userspace transport BIO\n");
            return -1;
        }

        // Associate BIO with SSL object
        SSL_set_bio(ssl_, bio, bio);

        // Set client mode for handshake
        SSL_set_connect_state(ssl_);

        // Perform TLS handshake (non-blocking, polling-based)
        int max_retries = 1000;
        int retries = 0;

        while (retries < max_retries) {
            // Poll transport before handshake attempt
            transport->poll();

            int ret = SSL_do_handshake(ssl_);

            if (ret == 1) {
                // Handshake successful
                // Log negotiated TLS version and cipher
                const char* version = SSL_get_version(ssl_);
                const char* cipher = SSL_CIPHER_get_name(SSL_get_current_cipher(ssl_));
                fprintf(stderr, "[TLS] Handshake SUCCESS\n");
                fprintf(stderr, "[TLS]   Version: %s\n", version ? version : "unknown");
                fprintf(stderr, "[TLS]   Cipher:  %s\n", cipher ? cipher : "unknown");

                // Reset server record counter — only count post-handshake records
                server_record_count_ = 0;
                return 0;
            }

            int err = SSL_get_error(ssl_, ret);

            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block, poll and retry
                transport->poll();
                usleep(1000);  // 1ms
                retries++;
                continue;
            }

            // SSL_ERROR_SYSCALL with errno=0 or EAGAIN should be retried
            if (err == SSL_ERROR_SYSCALL) {
                if (errno == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
                    transport->poll();
                    usleep(1000);  // 1ms
                    retries++;
                    continue;
                }
            }

            // Fatal error
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            fprintf(stderr, "[TLS] SSL handshake failed: %s\n", err_buf);
            SSL_free(ssl_);
            ssl_ = nullptr;
            return -1;
        }

        fprintf(stderr, "[TLS] SSL handshake timeout\n");
        SSL_free(ssl_);
        ssl_ = nullptr;
        return -1;
    }

    // Non-blocking handshake stubs (LibreSSL: delegate to blocking for now)
    enum class HandshakeResult : uint8_t { IN_PROGRESS = 0, SUCCESS = 1, ERROR = 2 };
    template<typename TransportPolicy>
    int prepare_handshake(TransportPolicy* transport, const char* hostname) {
        return handshake_userspace_transport(transport, hostname);
    }
    HandshakeResult step_handshake() { return HandshakeResult::SUCCESS; }

    /**
     * Read decrypted data from SSL connection
     *
     * @param buf Buffer to store data
     * @param len Buffer size
     * @return Number of bytes read, 0 on connection close, -1 on error/would-block
     */
    ssize_t read(void* buf, size_t len) {
        if (!ssl_) return -1;

        int n = SSL_read(ssl_, buf, len);

        if (n > 0) {
            return n;  // Success
        } else if (n == 0) {
            return 0;  // Connection closed
        } else {
            int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block (non-blocking socket)
                errno = EAGAIN;  // Set errno for caller
                return -1;
            }

            // Fatal SSL error
            errno = EIO;
            return -1;
        }
    }

    /**
     * Write encrypted data to SSL connection
     *
     * @param buf Data to write
     * @param len Data length
     * @return Number of bytes written, -1 on error/would-block
     */
    ssize_t write(const void* buf, size_t len) {
        if (!ssl_) return -1;

        int n = SSL_write(ssl_, buf, len);

        if (n > 0) {
            return n;  // Success
        } else {
            int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block (non-blocking socket)
                errno = EAGAIN;  // Set errno for caller
                return -1;
            }

            // Fatal SSL error
            errno = EIO;
            return -1;
        }
    }

    /**
     * Check bytes available in SSL read buffer
     * @return Number of bytes buffered in SSL (not yet returned to app)
     */
    size_t pending() const {
        if (!ssl_) return 0;
        return static_cast<size_t>(SSL_pending(ssl_));
    }

    /**
     * Check if kernel TLS is enabled
     *
     * @return false (LibreSSL doesn't support kTLS)
     */
    bool ktls_enabled() const {
        return false;  // LibreSSL doesn't support kTLS
    }

    /**
     * Get underlying socket file descriptor
     *
     * @return File descriptor, -1 if not set
     */
    int get_fd() const {
        if (!ssl_) return -1;
        return SSL_get_fd(ssl_);
    }

    // ========================================================================
    // Zero-Copy BIO Methods (for pipeline operation)
    // ========================================================================

    /**
     * Initialize zero-copy BIO for decoupled network I/O
     * SSL reads from external pointer (RX) and writes to external pointer (TX)
     */
    void init_zero_copy_bio() {
        if (!ctx_) {
            if (init() != 0) throw std::runtime_error("SSL init() failed");
        }

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            throw std::runtime_error("SSL_new() failed");
        }

        // Create zero-copy BIO method if not already created
        if (!zc_bio_method_) {
            // Use SOURCE_SINK type with unique index (required for proper BIO lifecycle)
            zc_bio_method_ = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "zero-copy");
            if (!zc_bio_method_) {
                SSL_free(ssl_);
                ssl_ = nullptr;
                throw std::runtime_error("BIO_meth_new() failed");
            }
            BIO_meth_set_read(zc_bio_method_, zc_bio_read);
            BIO_meth_set_write(zc_bio_method_, zc_bio_write);
            BIO_meth_set_ctrl(zc_bio_method_, zc_bio_ctrl);
            BIO_meth_set_create(zc_bio_method_, zc_bio_create);
            BIO_meth_set_destroy(zc_bio_method_, zc_bio_destroy);
        }

        // Create BIO instances with this policy as context
        BIO* bio_in = BIO_new(zc_bio_method_);
        BIO* bio_out = BIO_new(zc_bio_method_);
        if (!bio_in || !bio_out) {
            if (bio_in) BIO_free(bio_in);
            if (bio_out) BIO_free(bio_out);
            SSL_free(ssl_);
            ssl_ = nullptr;
            throw std::runtime_error("BIO_new() failed");
        }

        // Store policy pointer in BIO data for callbacks
        BIO_set_data(bio_in, this);
        BIO_set_data(bio_out, this);
        BIO_set_init(bio_in, 1);
        BIO_set_init(bio_out, 1);

        // Attach BIOs to SSL (SSL takes ownership)
        SSL_set_bio(ssl_, bio_in, bio_out);

        // Set client mode
        SSL_set_connect_state(ssl_);
    }

    // ------------------------------------------------------------------------
    // Zero-copy RX API: encrypted data input (ring buffer, no copy)
    // ------------------------------------------------------------------------

    int append_encrypted_view(const uint8_t* data, size_t len) {
        if (len == 0) return 0;
        if (in_view_head_ - in_view_tail_ >= VIEW_RING_SIZE) {
            return -1;  // Ring buffer full
        }
        in_views_[in_view_head_ & VIEW_RING_MASK].data = data;
        in_views_[in_view_head_ & VIEW_RING_MASK].len = len;
        in_view_head_++;
        return 0;
    }

    void clear_encrypted_view() {
        in_view_head_ = 0;
        in_view_tail_ = 0;
        in_view_pos_ = 0;
    }

    /**
     * Get the number of view segments that have been fully consumed by SSL.
     * Used to safely release UMEM frames.
     */
    size_t view_segments_consumed() const {
        return in_view_tail_;
    }

    /**
     * Check if there are any partially consumed view segments.
     */
    bool has_partial_view() const {
        return in_view_pos_ > 0;
    }

    // ------------------------------------------------------------------------
    // Zero-copy TX API: encrypted data output (direct write to UMEM)
    // ------------------------------------------------------------------------

    void set_encrypted_output(uint8_t* buf, size_t capacity) {
        out_buf_ = buf;
        out_buf_capacity_ = capacity;
        out_buf_len_ = 0;
    }

    size_t encrypted_output_len() const {
        return out_buf_len_;
    }

    // Reset output length without clearing buffer pointer (for handshake loops)
    void reset_encrypted_output_len() {
        out_buf_len_ = 0;
    }

    void clear_encrypted_output() {
        out_buf_ = nullptr;
        out_buf_capacity_ = 0;
        out_buf_len_ = 0;
    }

    // ------------------------------------------------------------------------

    bool do_handshake_step() {
        if (!ssl_) return false;
        int ret = SSL_do_handshake(ssl_);
        if (ret == 1) return true;

        int err = SSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return false;
        }
        return false;
    }

    bool is_handshake_complete() const {
        return ssl_ && SSL_is_init_finished(ssl_);
    }

    // ========================================================================
    // TLS Key Extraction (for ssl_read_by_chunk)
    // ========================================================================

    /**
     * Extract server record keys for direct AES-CTR decryption.
     * Uses same keylog callback approach as OpenSSLPolicy.
     * Returns true if keys were extracted (AES-GCM cipher), false otherwise.
     */
    bool extract_record_keys(websocket::crypto::TLSRecordKeys& keys) {
        if (!ssl_ || !SSL_is_init_finished(ssl_)) return false;

        int version = SSL_version(ssl_);
        bool is_tls13 = (version == TLS1_3_VERSION);

        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl_);
        if (!cipher) return false;

        const char* cipher_name = SSL_CIPHER_get_name(cipher);
        if (!cipher_name) return false;

        uint8_t key_len = 0;
        if (strstr(cipher_name, "AES128") || strstr(cipher_name, "AES_128")) {
            key_len = 16;
        } else if (strstr(cipher_name, "AES256") || strstr(cipher_name, "AES_256")) {
            key_len = 32;
        } else {
            return false;  // Not AES-GCM
        }

        if (!strstr(cipher_name, "GCM")) return false;

        keys.key_len = key_len;
        keys.is_tls13 = is_tls13;

        if (is_tls13) {
            return libressl_extract_tls13_keys(keys);
        } else {
            return libressl_extract_tls12_keys(keys);
        }
    }

    // ========================================================================

    void shutdown() {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        clear_encrypted_view();
        clear_encrypted_output();
        keylog_lines_.clear();
    }

    void cleanup() {
        shutdown();

        if (bio_method_) {
            BIO_meth_free(bio_method_);
            bio_method_ = nullptr;
        }

        if (zc_bio_method_) {
            BIO_meth_free(zc_bio_method_);
            zc_bio_method_ = nullptr;
        }

        if (ctx_) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

    static constexpr const char* name() {
        return "LibreSSL";
    }

private:
    // Zero-copy BIO callbacks (read from ring buffer)
    static int zc_bio_read(BIO* bio, char* buf, int len) {
        auto* self = static_cast<LibreSSLPolicy*>(BIO_get_data(bio));
        if (!self || self->in_view_tail_ == self->in_view_head_) {
            BIO_set_retry_read(bio);
            return -1;
        }

        size_t total_copied = 0;
        while (total_copied < static_cast<size_t>(len) &&
               self->in_view_tail_ != self->in_view_head_) {

            const auto& seg = self->in_views_[self->in_view_tail_ & VIEW_RING_MASK];
            size_t avail = seg.len - self->in_view_pos_;
            size_t to_copy = (static_cast<size_t>(len) - total_copied < avail)
                           ? (static_cast<size_t>(len) - total_copied) : avail;

            memcpy(buf + total_copied, seg.data + self->in_view_pos_, to_copy);
            total_copied += to_copy;
            self->in_view_pos_ += to_copy;

            if (self->in_view_pos_ >= seg.len) {
                self->in_view_tail_++;
                self->in_view_pos_ = 0;
            }
        }

        if (total_copied == 0) {
            BIO_set_retry_read(bio);
            return -1;
        }
        return static_cast<int>(total_copied);
    }

    static int zc_bio_write(BIO* bio, const char* buf, int len) {
        auto* self = static_cast<LibreSSLPolicy*>(BIO_get_data(bio));
        if (!self || !self->out_buf_) {
            BIO_set_retry_write(bio);
            return -1;
        }

        size_t space = self->out_buf_capacity_ - self->out_buf_len_;
        if (space == 0) {
            BIO_set_retry_write(bio);
            return -1;
        }

        size_t to_copy = (static_cast<size_t>(len) < space) ? static_cast<size_t>(len) : space;
        memcpy(self->out_buf_ + self->out_buf_len_, buf, to_copy);
        self->out_buf_len_ += to_copy;
        return static_cast<int>(to_copy);
    }

    static long zc_bio_ctrl(BIO* bio, int cmd, long num, void* ptr) {
        (void)num; (void)ptr;
        auto* self = static_cast<LibreSSLPolicy*>(BIO_get_data(bio));
        switch (cmd) {
            case BIO_CTRL_FLUSH: return 1;
            case BIO_CTRL_PENDING:
                // Return bytes available to read in view ring
                if (self && self->in_view_tail_ != self->in_view_head_) {
                    size_t pending = 0;
                    size_t tail = self->in_view_tail_;
                    size_t head = self->in_view_head_;
                    for (size_t i = tail; i != head; i++) {
                        pending += self->in_views_[i & VIEW_RING_MASK].len;
                    }
                    if (tail != head) {
                        pending -= self->in_view_pos_;
                    }
                    return static_cast<long>(pending);
                }
                return 0;
            case BIO_CTRL_WPENDING: return 0;
            default: return 0;
        }
    }

    static int zc_bio_create(BIO* bio) {
        if (!bio) return 0;
        BIO_set_init(bio, 0);
        BIO_set_data(bio, nullptr);
        return 1;
    }

    static int zc_bio_destroy(BIO* bio) {
        if (!bio) return 0;
        BIO_set_init(bio, 0);
        BIO_set_data(bio, nullptr);
        return 1;
    }

    // ========================================================================
    // Keylog callback and key extraction helpers
    // ========================================================================

    static int libressl_get_ex_data_index() {
        static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
        return idx;
    }

    static void libressl_keylog_callback(const SSL* ssl, const char* line) {
        auto* self = static_cast<LibreSSLPolicy*>(SSL_get_ex_data(ssl, libressl_get_ex_data_index()));
        if (self && line) {
            self->keylog_lines_.emplace_back(line);
        }
    }

    static void libressl_record_count_callback(int write_p, int version, int content_type,
                                                const void* buf, size_t len, SSL* ssl, void* arg) {
        (void)version; (void)content_type; (void)buf; (void)len; (void)arg;
        if (write_p == 0) {  // 0 = read (server->client)
            auto* self = static_cast<LibreSSLPolicy*>(SSL_get_ex_data(ssl, libressl_get_ex_data_index()));
            if (self) self->server_record_count_++;
        }
    }

    static size_t libressl_hex_to_bytes(const char* hex, uint8_t* out, size_t max_out) {
        size_t len = strlen(hex);
        size_t bytes = len / 2;
        if (bytes > max_out) bytes = max_out;
        for (size_t i = 0; i < bytes; i++) {
            unsigned int val;
            if (sscanf(hex + i * 2, "%02x", &val) != 1) return i;
            out[i] = static_cast<uint8_t>(val);
        }
        return bytes;
    }

    // TLS 1.3 key extraction (same approach as OpenSSL)
    bool libressl_extract_tls13_keys(websocket::crypto::TLSRecordKeys& keys) {
        uint8_t client_random[32];
        SSL_get_client_random(ssl_, client_random, 32);

        std::string server_secret_hex;
        for (const auto& line : keylog_lines_) {
            if (line.find("SERVER_TRAFFIC_SECRET_0") == 0) {
                size_t first_space = line.find(' ');
                if (first_space == std::string::npos) continue;
                size_t second_space = line.find(' ', first_space + 1);
                if (second_space == std::string::npos) continue;
                server_secret_hex = line.substr(second_space + 1);
                break;
            }
        }

        if (server_secret_hex.empty()) return false;

        uint8_t secret[48];
        size_t secret_len = libressl_hex_to_bytes(server_secret_hex.c_str(), secret, sizeof(secret));
        if (secret_len == 0) return false;

        const EVP_MD* md = (keys.key_len == 32) ? EVP_sha384() : EVP_sha256();

        // Use OpenSSL-compatible HKDF (shared implementation from OpenSSLPolicy)
        if (!OpenSSLPolicy::hkdf_expand_label(md, secret, secret_len, "key", keys.key, keys.key_len)) {
            return false;
        }
        if (!OpenSSLPolicy::hkdf_expand_label(md, secret, secret_len, "iv", keys.iv, 12)) {
            return false;
        }

        return true;
    }

    // TLS 1.2 key extraction
    bool libressl_extract_tls12_keys(websocket::crypto::TLSRecordKeys& keys) {
        uint8_t client_random[32];
        SSL_get_client_random(ssl_, client_random, 32);

        char client_random_hex[65];
        for (int i = 0; i < 32; i++) {
            sprintf(client_random_hex + i * 2, "%02x", client_random[i]);
        }
        client_random_hex[64] = '\0';

        std::string master_secret_hex;
        for (const auto& line : keylog_lines_) {
            if (line.find("CLIENT_RANDOM") == 0) {
                size_t first_space = line.find(' ');
                if (first_space == std::string::npos) continue;
                size_t second_space = line.find(' ', first_space + 1);
                if (second_space == std::string::npos) continue;
                std::string line_random = line.substr(first_space + 1, second_space - first_space - 1);
                bool match = (line_random.size() == 64);
                if (match) {
                    for (size_t i = 0; i < 64; i++) {
                        if (tolower(line_random[i]) != tolower(client_random_hex[i])) {
                            match = false;
                            break;
                        }
                    }
                }
                if (match) {
                    master_secret_hex = line.substr(second_space + 1);
                    break;
                }
            }
        }

        if (master_secret_hex.empty()) return false;

        uint8_t master_secret[48];
        size_t ms_len = libressl_hex_to_bytes(master_secret_hex.c_str(), master_secret, 48);
        if (ms_len != 48) return false;

        uint8_t server_random[32];
        SSL_get_server_random(ssl_, server_random, 32);

        size_t key_block_len = 2 * keys.key_len + 2 * 4;
        uint8_t key_block[104];
        uint8_t seed[64];
        memcpy(seed, server_random, 32);
        memcpy(seed + 32, client_random, 32);

        if (!OpenSSLPolicy::tls12_prf(EVP_sha256(), master_secret, 48,
                                       "key expansion", seed, 64,
                                       key_block, key_block_len)) {
            if (keys.key_len == 32) {
                if (!OpenSSLPolicy::tls12_prf(EVP_sha384(), master_secret, 48,
                                               "key expansion", seed, 64,
                                               key_block, key_block_len)) {
                    return false;
                }
            } else {
                return false;
            }
        }

        memcpy(keys.key, key_block + keys.key_len, keys.key_len);
        memcpy(keys.iv, key_block + 2 * keys.key_len + 4, 4);

        return true;
    }

public:
    SSL_CTX* ctx_;
    SSL* ssl_;
    BIO_METHOD* bio_method_;      // For userspace transport BIO
    BIO_METHOD* zc_bio_method_ = nullptr;  // For zero-copy BIO

    // Zero-copy RX state (ring buffer)
    ViewSegment in_views_[VIEW_RING_SIZE];
    size_t in_view_head_ = 0;
    size_t in_view_tail_ = 0;
    size_t in_view_pos_ = 0;

    // Zero-copy TX state
    uint8_t* out_buf_ = nullptr;
    size_t out_buf_capacity_ = 0;
    size_t out_buf_len_ = 0;

    // Keylog lines captured during handshake
    std::vector<std::string> keylog_lines_;

    // Server record counter (post-handshake, for TLS 1.3 seq_num tracking)
    uint64_t server_record_count_ = 0;
};

#endif // SSL_POLICY_LIBRESSL

// ============================================================================
// WolfSSL Policy (Lightweight, embedded-friendly)
// ============================================================================

#ifdef SSL_POLICY_WOLFSSL

/**
 * WolfSSLUserspaceIO - Native I/O callbacks for userspace transports
 *
 * WolfSSL's native I/O callback mechanism (no BIO/OPENSSL_EXTRA required).
 * Template parameter: TransportPolicy with send/recv interface.
 */
template<typename TransportPolicy>
struct WolfSSLUserspaceIO {
    /**
     * Receive callback - called by WolfSSL when it needs to read data
     */
    static int recv_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
        (void)ssl;
        auto* transport = static_cast<TransportPolicy*>(ctx);
        if (!transport) return WOLFSSL_CBIO_ERR_GENERAL;

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

    /**
     * Send callback - called by WolfSSL when it needs to write data
     */
    static int send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
        (void)ssl;
        auto* transport = static_cast<TransportPolicy*>(ctx);
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
};

/**
 * WolfSSLPolicy - WolfSSL implementation
 *
 * Features:
 *   - Lightweight SSL/TLS library
 *   - Optimized for embedded systems
 *   - Small code footprint
 *   - No kTLS support
 *   - Good performance for constrained environments
 *
 * Thread safety: Not thread-safe (designed for single connection per instance)
 */
struct WolfSSLPolicy {
    WolfSSLPolicy() : ctx_(nullptr), ssl_(nullptr) {}

    ~WolfSSLPolicy() {
        cleanup();  // Full cleanup including ctx_
    }

    // Prevent copying
    WolfSSLPolicy(const WolfSSLPolicy&) = delete;
    WolfSSLPolicy& operator=(const WolfSSLPolicy&) = delete;

    // Allow moving
    WolfSSLPolicy(WolfSSLPolicy&& other) noexcept
        : ctx_(other.ctx_)
        , ssl_(other.ssl_)
    {
        other.ctx_ = nullptr;
        other.ssl_ = nullptr;
    }

    WolfSSLPolicy& operator=(WolfSSLPolicy&& other) noexcept {
        if (this != &other) {
            shutdown();
            ctx_ = other.ctx_;
            ssl_ = other.ssl_;
            other.ctx_ = nullptr;
            other.ssl_ = nullptr;
        }
        return *this;
    }

    /**
     * Initialize WolfSSL context
     *
     * @return 0 on success, -1 on failure
     */
    int init() {
        wolfSSL_Init();

        // Create flexible TLS client method (supports TLS 1.2 and 1.3)
        // TLS 1.3 ClientHello is handled by TCP segmentation in tls_handshake_send_from_buffer()
        WOLFSSL_METHOD* method = wolfSSLv23_client_method();
        if (!method) {
            fprintf(stderr, "[TLS] wolfSSLv23_client_method() failed\n");
            return -1;
        }

        ctx_ = wolfSSL_CTX_new(method);
        if (!ctx_) {
            fprintf(stderr, "[TLS] wolfSSL_CTX_new() failed\n");
            return -1;
        }

        // Set minimum TLS version to 1.2
        wolfSSL_CTX_SetMinVersion(ctx_, WOLFSSL_TLSV1_2);

        // Set cipher preference: AES-128-GCM first (fastest on Intel with AES-NI)
        // WolfSSL uses a unified cipher list for TLS 1.2 and 1.3
        // TLS 1.3 ciphers: TLS13-AES128-GCM-SHA256, TLS13-AES256-GCM-SHA384, TLS13-CHACHA20-POLY1305-SHA256
        // TLS 1.2 ciphers: ECDHE-RSA-AES128-GCM-SHA256, etc.
        int ret = wolfSSL_CTX_set_cipher_list(ctx_,
            "TLS13-AES128-GCM-SHA256:TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305-SHA256");
        if (ret != WOLFSSL_SUCCESS) {
            fprintf(stderr, "[TLS] Warning: Failed to set cipher preference\n");
        }

        // Disable verification (HFT optimization - verify in production!)
        wolfSSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);

        fprintf(stderr, "[TLS] WolfSSL initialized with AES-128-GCM preferred\n");
        return 0;
    }

    uint64_t get_server_record_count() const { return server_record_count_; }

    /**
     * Perform TLS handshake
     *
     * @param fd Socket file descriptor
     * @throws std::runtime_error if handshake fails
     */
    void handshake(int fd) {
        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            if (init() != 0) throw std::runtime_error("wolfSSL init() failed");
        }

        ssl_ = wolfSSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                wolfSSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            if (init() != 0) throw std::runtime_error("wolfSSL init() failed");
            ssl_ = wolfSSL_new(ctx_);
        }

        if (!ssl_) {
            throw std::runtime_error("wolfSSL_new() failed");
        }

        // Associate socket with SSL object
        int ret = wolfSSL_set_fd(ssl_, fd);
        if (ret != SSL_SUCCESS) {
            throw std::runtime_error("wolfSSL_set_fd() failed");
        }

        // Perform TLS handshake (blocking)
        ret = wolfSSL_connect(ssl_);
        if (ret != SSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl_, ret);
            char err_buf[256];
            wolfSSL_ERR_error_string(err, err_buf);
            throw std::runtime_error(std::string("wolfSSL_connect() failed: ") + err_buf);
        }

        // Log cipher details
        const char* cipher_name = wolfSSL_get_cipher(ssl_);
        const char* tls_version = wolfSSL_get_version(ssl_);

        fprintf(stderr, "[TLS] Handshake SUCCESS (BSD socket)\n");
        fprintf(stderr, "[TLS]   Version: %s\n", tls_version ? tls_version : "unknown");
        fprintf(stderr, "[TLS]   Cipher:  %s\n", cipher_name ? cipher_name : "unknown");

        // Reset server record counter — only count post-handshake records
        server_record_count_ = 0;
    }

    /**
     * Perform TLS handshake over userspace transport
     *
     * Works with any transport policy implementing send/recv/poll interface.
     * Example: XDPUserspaceTransport, or any custom userspace TCP stack.
     *
     * @param transport Transport policy instance
     * @return 0 on success, -1 on failure
     */
    template<typename TransportPolicy>
    int handshake_userspace_transport(TransportPolicy* transport, const char* hostname = nullptr) {
        if (!transport) {
            fprintf(stderr, "[TLS] Transport is null in handshake_userspace_transport\n");
            return -1;
        }

        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            if (init() != 0) return -1;
        }

        // Register native I/O callbacks BEFORE creating SSL object
        // This avoids the need for OPENSSL_EXTRA/BIO compatibility layer
        wolfSSL_CTX_SetIORecv(ctx_, WolfSSLUserspaceIO<TransportPolicy>::recv_cb);
        wolfSSL_CTX_SetIOSend(ctx_, WolfSSLUserspaceIO<TransportPolicy>::send_cb);

        ssl_ = wolfSSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                wolfSSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            if (init() != 0) return -1;
            // Re-register callbacks on new context
            wolfSSL_CTX_SetIORecv(ctx_, WolfSSLUserspaceIO<TransportPolicy>::recv_cb);
            wolfSSL_CTX_SetIOSend(ctx_, WolfSSLUserspaceIO<TransportPolicy>::send_cb);
            ssl_ = wolfSSL_new(ctx_);
        }

        if (!ssl_) {
            fprintf(stderr, "[TLS] wolfSSL_new() failed in handshake_userspace_transport\n");
            return -1;
        }

        // Set SNI hostname for virtual hosting
        if (hostname) {
            wolfSSL_UseSNI(ssl_, WOLFSSL_SNI_HOST_NAME, hostname, (unsigned short)strlen(hostname));
        }

        // Set transport as the I/O context for this SSL session
        wolfSSL_SetIOReadCtx(ssl_, transport);
        wolfSSL_SetIOWriteCtx(ssl_, transport);

        // Perform TLS handshake (non-blocking, polling-based)
        int max_retries = 1000;
        int retries = 0;

        while (retries < max_retries) {
            // Poll transport before handshake attempt
            transport->poll();

            int ret = wolfSSL_connect(ssl_);

            if (ret == SSL_SUCCESS) {
                // Handshake successful - log cipher details
                const char* cipher_name = wolfSSL_get_cipher(ssl_);
                const char* tls_version = wolfSSL_get_version(ssl_);

                fprintf(stderr, "[TLS] Handshake SUCCESS\n");
                fprintf(stderr, "[TLS]   Version: %s\n", tls_version ? tls_version : "unknown");
                fprintf(stderr, "[TLS]   Cipher:  %s\n", cipher_name ? cipher_name : "unknown");

                // Stop trickle thread, switch to inline trickle
                transport->stop_rx_trickle_thread();
                // Reset server record counter — only count post-handshake records
                server_record_count_ = 0;
                return 0;
            }

            int err = wolfSSL_get_error(ssl_, ret);

            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block, poll and retry
                transport->poll();
                usleep(1000);  // 1ms
                retries++;
                continue;
            }

            // SSL_ERROR_SYSCALL with errno=0 or EAGAIN should be retried
            if (err == SSL_ERROR_SYSCALL) {
                if (errno == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
                    transport->poll();
                    usleep(1000);  // 1ms
                    retries++;
                    continue;
                }
            }

            // Fatal error
            char err_buf[256];
            wolfSSL_ERR_error_string(err, err_buf);
            fprintf(stderr, "[TLS] SSL handshake failed: %s\n", err_buf);
            wolfSSL_free(ssl_);
            ssl_ = nullptr;
            return -1;
        }

        fprintf(stderr, "[TLS] SSL handshake timeout\n");
        wolfSSL_free(ssl_);
        ssl_ = nullptr;
        return -1;
    }

    // ========================================================================
    // Non-blocking TLS Handshake (for state-machine-based reconnect)
    // ========================================================================

    enum class HandshakeResult : uint8_t {
        IN_PROGRESS = 0,
        SUCCESS = 1,
        ERROR = 2,
    };

    /**
     * One-time setup: create SSL object, set SNI, set I/O context.
     * Call once before calling step_handshake() in a loop.
     *
     * @return 0 on success, -1 on failure
     */
    template<typename TransportPolicy>
    int prepare_handshake(TransportPolicy* transport, const char* hostname) {
        if (!transport) {
            fprintf(stderr, "[TLS] Transport is null in prepare_handshake\n");
            return -1;
        }

        // If ctx_ is null, initialize
        if (!ctx_) {
            if (init() != 0) return -1;
        }

        // Register native I/O callbacks
        wolfSSL_CTX_SetIORecv(ctx_, WolfSSLUserspaceIO<TransportPolicy>::recv_cb);
        wolfSSL_CTX_SetIOSend(ctx_, WolfSSLUserspaceIO<TransportPolicy>::send_cb);

        ssl_ = wolfSSL_new(ctx_);
        if (!ssl_) {
            if (ctx_) { wolfSSL_CTX_free(ctx_); ctx_ = nullptr; }
            if (init() != 0) return -1;
            wolfSSL_CTX_SetIORecv(ctx_, WolfSSLUserspaceIO<TransportPolicy>::recv_cb);
            wolfSSL_CTX_SetIOSend(ctx_, WolfSSLUserspaceIO<TransportPolicy>::send_cb);
            ssl_ = wolfSSL_new(ctx_);
        }
        if (!ssl_) {
            fprintf(stderr, "[TLS] wolfSSL_new() failed in prepare_handshake\n");
            return -1;
        }

        if (hostname) {
            wolfSSL_UseSNI(ssl_, WOLFSSL_SNI_HOST_NAME, hostname, (unsigned short)strlen(hostname));
        }

        wolfSSL_SetIOReadCtx(ssl_, transport);
        wolfSSL_SetIOWriteCtx(ssl_, transport);
        return 0;
    }

    /**
     * Perform one step of the TLS handshake (single wolfSSL_connect() call).
     * Returns IN_PROGRESS if not done, SUCCESS when handshake complete,
     * ERROR on fatal failure.
     *
     * Caller must call transport->poll() before each call.
     */
    HandshakeResult step_handshake() {
        if (!ssl_) return HandshakeResult::ERROR;

        int ret = wolfSSL_connect(ssl_);

        if (ret == SSL_SUCCESS) {
            const char* cipher_name = wolfSSL_get_cipher(ssl_);
            const char* tls_version = wolfSSL_get_version(ssl_);
            fprintf(stderr, "[TLS] Handshake SUCCESS (non-blocking)\n");
            fprintf(stderr, "[TLS]   Version: %s\n", tls_version ? tls_version : "unknown");
            fprintf(stderr, "[TLS]   Cipher:  %s\n", cipher_name ? cipher_name : "unknown");
            server_record_count_ = 0;
            return HandshakeResult::SUCCESS;
        }

        int err = wolfSSL_get_error(ssl_, ret);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return HandshakeResult::IN_PROGRESS;
        }

        if (err == SSL_ERROR_SYSCALL) {
            if (errno == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
                return HandshakeResult::IN_PROGRESS;
            }
        }

        // Fatal error
        char err_buf[256];
        wolfSSL_ERR_error_string(err, err_buf);
        fprintf(stderr, "[TLS] step_handshake() fatal error: %s\n", err_buf);
        wolfSSL_free(ssl_);
        ssl_ = nullptr;
        return HandshakeResult::ERROR;
    }

    /**
     * Read decrypted data from SSL connection
     *
     * @param buf Buffer to store data
     * @param len Buffer size
     * @return Number of bytes read, 0 on connection close, -1 on error/would-block
     */
    ssize_t read(void* buf, size_t len) {
        if (!ssl_) return -1;

        int n = wolfSSL_read(ssl_, buf, len);

        if (n > 0) {
            server_record_count_++;  // Track records for seq_num
            return n;  // Success
        } else if (n == 0) {
            return 0;  // Connection closed
        } else {
            int err = wolfSSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block (non-blocking socket)
                errno = EAGAIN;  // Set errno for caller
                return -1;
            }

            // Fatal SSL error
            errno = EIO;
            return -1;
        }
    }

    /**
     * Write encrypted data to SSL connection
     *
     * @param buf Data to write
     * @param len Data length
     * @return Number of bytes written, -1 on error/would-block
     */
    ssize_t write(const void* buf, size_t len) {
        if (!ssl_) return -1;

        int n = wolfSSL_write(ssl_, buf, len);

        if (n > 0) {
            return n;  // Success
        } else {
            int err = wolfSSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // Would block (non-blocking socket)
                errno = EAGAIN;  // Set errno for caller
                return -1;
            }

            // Fatal SSL error
            errno = EIO;
            return -1;
        }
    }

    /**
     * Check bytes available in SSL read buffer
     * @return Number of bytes buffered in SSL (not yet returned to app)
     */
    size_t pending() const {
        if (!ssl_) return 0;
        return static_cast<size_t>(wolfSSL_pending(ssl_));
    }

    /**
     * Check if kernel TLS is enabled
     *
     * @return false (WolfSSL doesn't support kTLS)
     */
    bool ktls_enabled() const {
        return false;  // WolfSSL doesn't support kTLS
    }

    /**
     * Get underlying socket file descriptor
     *
     * @return File descriptor, -1 if not set
     */
    int get_fd() const {
        if (!ssl_) return -1;
        return wolfSSL_get_fd(ssl_);
    }

    // ========================================================================
    // TLS Key Extraction (for ssl_read_by_chunk)
    // ========================================================================

    /**
     * Extract server record keys for direct AES-CTR decryption.
     * WolfSSL provides direct access to key material via wolfSSL_get_keys().
     * Returns true if keys were extracted (AES-GCM cipher), false otherwise.
     */
    bool extract_record_keys(websocket::crypto::TLSRecordKeys& keys) {
        if (!ssl_ || !wolfSSL_is_init_finished(ssl_)) return false;

        // Check cipher is AES-GCM
        const char* cipher_name = wolfSSL_get_cipher(ssl_);
        if (!cipher_name) return false;

        uint8_t key_len = 0;
        if (strstr(cipher_name, "AES128") || strstr(cipher_name, "AES_128") ||
            strstr(cipher_name, "AES-128")) {
            key_len = 16;
        } else if (strstr(cipher_name, "AES256") || strstr(cipher_name, "AES_256") ||
                   strstr(cipher_name, "AES-256")) {
            key_len = 32;
        } else {
            return false;  // Not AES
        }

        if (!strstr(cipher_name, "GCM")) return false;

        // Determine TLS version
        const char* version_str = wolfSSL_get_version(ssl_);
        bool is_tls13 = version_str && strstr(version_str, "TLSv1.3");

        keys.key_len = key_len;
        keys.is_tls13 = is_tls13;

        // Use wolfSSL_get_keys() to access key material directly
        // Requires wolfSSL built with OPENSSL_EXTRA
        unsigned int suite_len = 0, key_sz = 0, iv_sz = 0;
        unsigned char* ms = nullptr;
        unsigned char* sr = nullptr;
        unsigned char* cr = nullptr;

#ifdef OPENSSL_EXTRA
        int ret = wolfSSL_get_keys(ssl_, &ms, &suite_len, &sr, &key_sz, &cr, &iv_sz);
#else
        int ret = -1;  // wolfSSL_get_keys not available without OPENSSL_EXTRA
#endif
        if (ret != 0 || !ms) {
            // wolfSSL_get_keys not available or failed
            return false;
        }

        // For TLS 1.3, wolfSSL_get_keys returns traffic secrets
        // For TLS 1.2, it returns the key material directly
        if (is_tls13) {
            // In TLS 1.3, we need the server traffic key and IV
            // wolfSSL stores these internally after handshake
            // With --enable-opensslall, we can access them
            // The key material pointers from wolfSSL_get_keys in TLS 1.3 mode
            // contain the derived keys directly
            if (key_sz >= key_len && iv_sz >= 12) {
                // sr points to server write key, cr points to server write IV
                memcpy(keys.key, sr, key_len);
                memcpy(keys.iv, cr, 12);
                return true;
            }
            return false;
        } else {
            // TLS 1.2: key material from PRF expansion
            // Layout depends on WolfSSL internals
            if (key_sz >= key_len && iv_sz >= 4) {
                memcpy(keys.key, sr, key_len);
                memcpy(keys.iv, cr, 4);  // 4-byte implicit IV for TLS 1.2 AES-GCM
                return true;
            }
            return false;
        }
    }

    // ========================================================================
    // Zero-Copy Methods (for pipeline operation)
    // WolfSSL uses I/O callbacks that read from/write to external pointers
    // ========================================================================

    /**
     * Initialize zero-copy mode for decoupled network I/O
     * SSL reads from external pointer (RX) and writes to external pointer (TX)
     */
    void init_zero_copy_bio() {
        if (!ctx_) {
            if (init() != 0) throw std::runtime_error("SSL init() failed");
        }

        // Register zero-copy I/O callbacks
        wolfSSL_CTX_SetIORecv(ctx_, zc_recv_cb);
        wolfSSL_CTX_SetIOSend(ctx_, zc_send_cb);

        ssl_ = wolfSSL_new(ctx_);
        if (!ssl_) {
            throw std::runtime_error("wolfSSL_new() failed");
        }

        // Set this object as the I/O context
        wolfSSL_SetIOReadCtx(ssl_, this);
        wolfSSL_SetIOWriteCtx(ssl_, this);
    }

    // ------------------------------------------------------------------------
    // Zero-copy RX API: encrypted data input (ring buffer, no copy)
    // ------------------------------------------------------------------------

    int append_encrypted_view(const uint8_t* data, size_t len) {
        if (len == 0) return 0;
        if (in_view_head_ - in_view_tail_ >= VIEW_RING_SIZE) {
            return -1;  // Ring buffer full
        }
        in_views_[in_view_head_ & VIEW_RING_MASK].data = data;
        in_views_[in_view_head_ & VIEW_RING_MASK].len = len;
        in_view_head_++;
        return 0;
    }

    void clear_encrypted_view() {
        in_view_head_ = 0;
        in_view_tail_ = 0;
        in_view_pos_ = 0;
    }

    /**
     * Get the number of view segments that have been fully consumed by SSL.
     * Used to safely release UMEM frames - only commit frames whose data
     * has been completely read by SSL.
     */
    size_t view_segments_consumed() const {
        return in_view_tail_;
    }

    /**
     * Check if there are any partially consumed view segments.
     * If in_view_pos_ > 0, the current tail segment is partially consumed.
     */
    bool has_partial_view() const {
        return in_view_pos_ > 0;
    }

    // ------------------------------------------------------------------------
    // Zero-copy TX API: encrypted data output (direct write to UMEM)
    // ------------------------------------------------------------------------

    void set_encrypted_output(uint8_t* buf, size_t capacity) {
        out_buf_ = buf;
        out_buf_capacity_ = capacity;
        out_buf_len_ = 0;
    }

    size_t encrypted_output_len() const {
        return out_buf_len_;
    }

    // Reset output length without clearing buffer pointer (for handshake loops)
    void reset_encrypted_output_len() {
        out_buf_len_ = 0;
    }

    void clear_encrypted_output() {
        out_buf_ = nullptr;
        out_buf_capacity_ = 0;
        out_buf_len_ = 0;
    }

    // ------------------------------------------------------------------------

    bool do_handshake_step() {
        if (!ssl_) return false;
        int ret = wolfSSL_connect(ssl_);
        if (ret == SSL_SUCCESS) return true;

        int err = wolfSSL_get_error(ssl_, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return false;
        }
        return false;
    }

    bool is_handshake_complete() const {
        return ssl_ && wolfSSL_is_init_finished(ssl_);
    }

    // ========================================================================

    void shutdown() {
        if (ssl_) {
            wolfSSL_shutdown(ssl_);
            wolfSSL_free(ssl_);
            ssl_ = nullptr;
        }
        clear_encrypted_view();
        clear_encrypted_output();
    }

    void cleanup() {
        shutdown();

        if (ctx_) {
            wolfSSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }

        wolfSSL_Cleanup();
    }

    static constexpr const char* name() {
        return "WolfSSL";
    }

private:
    // Zero-copy I/O callbacks for WolfSSL
    static int zc_recv_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
        (void)ssl;
        auto* self = static_cast<WolfSSLPolicy*>(ctx);
        if (self->in_view_tail_ == self->in_view_head_) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }

        size_t total_copied = 0;
        while (total_copied < static_cast<size_t>(sz) &&
               self->in_view_tail_ != self->in_view_head_) {

            const auto& seg = self->in_views_[self->in_view_tail_ & VIEW_RING_MASK];

            if (!seg.data || seg.len == 0) {
                self->in_view_tail_++;
                self->in_view_pos_ = 0;
                continue;
            }

            size_t avail = seg.len - self->in_view_pos_;
            size_t to_copy = (static_cast<size_t>(sz) - total_copied < avail)
                           ? (static_cast<size_t>(sz) - total_copied) : avail;

            memcpy(buf + total_copied, seg.data + self->in_view_pos_, to_copy);
            total_copied += to_copy;
            self->in_view_pos_ += to_copy;

            if (self->in_view_pos_ >= seg.len) {
                self->in_view_tail_++;
                self->in_view_pos_ = 0;
            }
        }

        if (total_copied == 0) {
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        return static_cast<int>(total_copied);
    }

    static int zc_send_cb(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
        (void)ssl;
        auto* self = static_cast<WolfSSLPolicy*>(ctx);
        if (!self->out_buf_) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }

        size_t space = self->out_buf_capacity_ - self->out_buf_len_;
        if (space == 0) {
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }

        size_t to_copy = (static_cast<size_t>(sz) < space) ? static_cast<size_t>(sz) : space;
        memcpy(self->out_buf_ + self->out_buf_len_, buf, to_copy);
        self->out_buf_len_ += to_copy;
        return static_cast<int>(to_copy);
    }

public:
    WOLFSSL_CTX* ctx_;
    WOLFSSL* ssl_;

    // Server record counter (post-handshake, for TLS 1.3 seq_num tracking)
    uint64_t server_record_count_ = 0;

private:
    // Zero-copy RX state (ring buffer)
    ViewSegment in_views_[VIEW_RING_SIZE];
    size_t in_view_head_ = 0;
    size_t in_view_tail_ = 0;
    size_t in_view_pos_ = 0;

    // Zero-copy TX state (pointer to UMEM output buffer)
    uint8_t* out_buf_ = nullptr;
    size_t out_buf_capacity_ = 0;
    size_t out_buf_len_ = 0;
};

#endif // SSL_POLICY_WOLFSSL

} // namespace ssl
} // namespace websocket

// ============================================================================
// Backward-Compatible Type Aliases (Global Scope)
// ============================================================================

// Always provide all three policy type names
// When a library is not available, alias it to a working implementation

#ifdef SSL_POLICY_OPENSSL
using OpenSSLPolicy = websocket::ssl::OpenSSLPolicy;
#endif

#ifdef SSL_POLICY_LIBRESSL
using LibreSSLPolicy = websocket::ssl::LibreSSLPolicy;
#endif

#ifdef SSL_POLICY_WOLFSSL
using WolfSSLPolicy = websocket::ssl::WolfSSLPolicy;
#endif

// Provide fallback type aliases for non-compiled policies
// When used in ws_configs.hpp conditionals, they need to exist as types

#if !defined(SSL_POLICY_OPENSSL)
// Dummy OpenSSL/LibreSSL types when not available (WolfSSL build)
namespace websocket { namespace ssl {
    struct OpenSSLPolicy {};  // Empty stub - will fail if instantiated
    struct LibreSSLPolicy {}; // Empty stub - will fail if instantiated
}}
using OpenSSLPolicy = websocket::ssl::OpenSSLPolicy;
using LibreSSLPolicy = websocket::ssl::LibreSSLPolicy;
#endif

#if !defined(SSL_POLICY_WOLFSSL)
// Dummy WolfSSL type when not available (OpenSSL/LibreSSL build)
namespace websocket { namespace ssl {
    struct WolfSSLPolicy {};  // Empty stub - will fail if instantiated
}}
using WolfSSLPolicy = websocket::ssl::WolfSSLPolicy;
#endif

// ============================================================================
// NoSSLPolicy - Pass-through (no encryption)
// ============================================================================
// For use with SimulatorTransport where data is already decrypted in recordings
namespace websocket { namespace ssl {

/**
 * NoSSLPolicy - Pass-through policy for unencrypted transports
 *
 * Used with SimulatorTransport where data is already decrypted.
 * All reads/writes are passed directly to the transport layer.
 * For memory BIO mode, data passes through without encryption.
 */
struct NoSSLPolicy {
    NoSSLPolicy() = default;
    ~NoSSLPolicy() = default;

    // Prevent copying
    NoSSLPolicy(const NoSSLPolicy&) = delete;
    NoSSLPolicy& operator=(const NoSSLPolicy&) = delete;

    // Allow moving
    NoSSLPolicy(NoSSLPolicy&&) noexcept = default;
    NoSSLPolicy& operator=(NoSSLPolicy&&) noexcept = default;

    int init() {
        // No SSL context needed
        return 0;
    }

    // BSD socket handshake (no-op for NoSSL)
    void handshake(int fd) {
        (void)fd;
        // No handshake needed
    }

    // Userspace transport handshake - store transport pointer
    template<typename TransportPolicy>
    void handshake_userspace_transport(TransportPolicy* transport, const char* hostname = nullptr) {
        transport_ = static_cast<void*>(transport);
        recv_fn_ = [](void* tp, void* buf, size_t len) -> ssize_t {
            return static_cast<TransportPolicy*>(tp)->recv(buf, len);
        };
        send_fn_ = [](void* tp, const void* buf, size_t len) -> ssize_t {
            return static_cast<TransportPolicy*>(tp)->send(buf, len);
        };
    }

    ssize_t read(void* buf, size_t len) {
        // Zero-copy mode: read from ring buffer (no decryption - pass through)
        if (in_view_tail_ != in_view_head_) {
            size_t total_copied = 0;
            while (total_copied < len && in_view_tail_ != in_view_head_) {
                const auto& seg = in_views_[in_view_tail_ & VIEW_RING_MASK];
                size_t avail = seg.len - in_view_pos_;
                size_t to_copy = (len - total_copied < avail)
                               ? (len - total_copied) : avail;

                memcpy(static_cast<uint8_t*>(buf) + total_copied,
                       seg.data + in_view_pos_, to_copy);
                total_copied += to_copy;
                in_view_pos_ += to_copy;

                if (in_view_pos_ >= seg.len) {
                    in_view_tail_++;
                    in_view_pos_ = 0;
                }
            }
            if (total_copied == 0) {
                errno = EAGAIN;
                return -1;
            }
            return static_cast<ssize_t>(total_copied);
        }

        // Transport mode: read from transport
        if (!transport_ || !recv_fn_) {
            errno = EAGAIN;
            return -1;
        }
        return recv_fn_(transport_, buf, len);
    }

    ssize_t write(const void* buf, size_t len) {
        // Zero-copy mode: write to output buffer (no encryption - pass through)
        if (out_buf_) {
            size_t space = out_buf_capacity_ - out_buf_len_;
            size_t to_copy = (len < space) ? len : space;
            if (to_copy == 0) {
                errno = EAGAIN;
                return -1;
            }
            memcpy(out_buf_ + out_buf_len_, buf, to_copy);
            out_buf_len_ += to_copy;
            return static_cast<ssize_t>(to_copy);
        }

        // Transport mode: write to transport
        if (!transport_ || !send_fn_) {
            errno = ENOTCONN;
            return -1;
        }
        return send_fn_(transport_, buf, len);
    }

    bool ktls_enabled() const { return false; }
    int get_fd() const { return -1; }
    size_t pending() const { return (in_view_tail_ != in_view_head_) ? 1 : 0; }  // Non-zero if data available

    // No encryption - key extraction not applicable
    bool extract_record_keys(websocket::crypto::TLSRecordKeys&) { return false; }
    uint64_t get_server_record_count() const { return 0; }

    // Non-blocking handshake stubs (NoSSL: immediate success)
    enum class HandshakeResult : uint8_t { IN_PROGRESS = 0, SUCCESS = 1, ERROR = 2 };
    template<typename TransportPolicy>
    int prepare_handshake(TransportPolicy* transport, const char* hostname) {
        handshake_userspace_transport(transport, hostname);
        return 0;
    }
    HandshakeResult step_handshake() { return HandshakeResult::SUCCESS; }

    // ========================================================================
    // Zero-Copy Methods (for pipeline operation)
    // NoSSL: pass-through without encryption
    // ========================================================================

    /**
     * Initialize zero-copy mode for decoupled network I/O
     * For NoSSL, this just enables pointer mode (no encryption)
     */
    void init_zero_copy_bio() {
        // NoSSL doesn't need any initialization - just enable pointer mode
    }

    // ------------------------------------------------------------------------
    // Zero-copy RX API: data input (ring buffer, no copy)
    // ------------------------------------------------------------------------

    int append_encrypted_view(const uint8_t* data, size_t len) {
        if (len == 0) return 0;
        if (in_view_head_ - in_view_tail_ >= VIEW_RING_SIZE) {
            return -1;  // Ring buffer full
        }
        in_views_[in_view_head_ & VIEW_RING_MASK].data = data;
        in_views_[in_view_head_ & VIEW_RING_MASK].len = len;
        in_view_head_++;
        return 0;
    }

    void clear_encrypted_view() {
        in_view_head_ = 0;
        in_view_tail_ = 0;
        in_view_pos_ = 0;
    }

    /**
     * Get the number of view segments that have been fully consumed.
     * Used to safely release UMEM frames.
     */
    size_t view_segments_consumed() const {
        return in_view_tail_;
    }

    /**
     * Check if there are any partially consumed view segments.
     */
    bool has_partial_view() const {
        return in_view_pos_ > 0;
    }

    // ------------------------------------------------------------------------
    // Zero-copy TX API: data output (direct write)
    // ------------------------------------------------------------------------

    void set_encrypted_output(uint8_t* buf, size_t capacity) {
        out_buf_ = buf;
        out_buf_capacity_ = capacity;
        out_buf_len_ = 0;
    }

    size_t encrypted_output_len() const {
        return out_buf_len_;
    }

    void clear_encrypted_output() {
        out_buf_ = nullptr;
        out_buf_capacity_ = 0;
        out_buf_len_ = 0;
    }

    // ------------------------------------------------------------------------

    bool do_handshake_step() {
        return true;  // No handshake needed
    }

    bool is_handshake_complete() const {
        return true;
    }

    // ========================================================================

    void shutdown() {
        transport_ = nullptr;
        clear_encrypted_view();
        clear_encrypted_output();
    }

    void cleanup() {
        shutdown();
    }

private:
    void* transport_ = nullptr;
    ssize_t (*recv_fn_)(void*, void*, size_t) = nullptr;
    ssize_t (*send_fn_)(void*, const void*, size_t) = nullptr;

    // Zero-copy RX state (ring buffer)
    ViewSegment in_views_[VIEW_RING_SIZE];
    size_t in_view_head_ = 0;
    size_t in_view_tail_ = 0;
    size_t in_view_pos_ = 0;

    // Zero-copy TX state
    uint8_t* out_buf_ = nullptr;
    size_t out_buf_capacity_ = 0;
    size_t out_buf_len_ = 0;
};

}}  // namespace websocket::ssl

using NoSSLPolicy = websocket::ssl::NoSSLPolicy;

// ============================================================================
// SSL Policy Concepts (C++20)
// ============================================================================

#if __cplusplus >= 202002L
#include <concepts>

/**
 * SSLPolicyConcept - Defines required interface for SSL policies
 *
 * All SSL policies must provide:
 *   - init() - Initialize SSL context
 *   - handshake(fd) - Perform TLS handshake
 *   - read(buf, len) - Read decrypted data
 *   - write(buf, len) - Write encrypted data
 *   - ktls_enabled() - Check if kTLS is active
 *   - get_fd() - Get underlying file descriptor
 *   - shutdown() - Cleanup SSL connection
 *
 * Zero-copy API (pipeline mode):
 *   - init_zero_copy_bio() - Initialize zero-copy BIO mode
 *   - append_encrypted_view(ptr, len) - RX: append UMEM encrypted data to ring buffer (returns -1 if full)
 *   - clear_encrypted_view() - RX: reset ring buffer (only on reconnection)
 *   - set_encrypted_output(ptr, len) - TX: point to UMEM output buffer
 *   - encrypted_output_len() - TX: bytes written to output
 *   - clear_encrypted_output() - TX: done with current output
 */
template<typename T>
concept SSLPolicyConcept = requires(T ssl, int fd, void* buf, const uint8_t* cptr, uint8_t* ptr, size_t len) {
    // Basic interface
    { ssl.init() } -> std::convertible_to<int>;
    { ssl.handshake(fd) } -> std::same_as<void>;
    { ssl.read(buf, len) } -> std::convertible_to<ssize_t>;
    { ssl.write(buf, len) } -> std::convertible_to<ssize_t>;
    { ssl.ktls_enabled() } -> std::convertible_to<bool>;
    { ssl.get_fd() } -> std::convertible_to<int>;
    { ssl.shutdown() } -> std::same_as<void>;

    // Zero-copy API
    { ssl.init_zero_copy_bio() } -> std::same_as<void>;
    { ssl.append_encrypted_view(cptr, len) } -> std::convertible_to<int>;  // Returns -1 if ring buffer full
    { ssl.clear_encrypted_view() } -> std::same_as<void>;
    { ssl.set_encrypted_output(ptr, len) } -> std::same_as<void>;
    { ssl.encrypted_output_len() } -> std::convertible_to<size_t>;
    { ssl.clear_encrypted_output() } -> std::same_as<void>;
};

// Verify our policies conform to the concept
#ifdef SSL_POLICY_OPENSSL
static_assert(SSLPolicyConcept<websocket::ssl::OpenSSLPolicy>);
static_assert(SSLPolicyConcept<OpenSSLPolicy>);
#endif

#ifdef SSL_POLICY_LIBRESSL
static_assert(SSLPolicyConcept<websocket::ssl::LibreSSLPolicy>);
static_assert(SSLPolicyConcept<LibreSSLPolicy>);
#endif

#ifdef SSL_POLICY_WOLFSSL
static_assert(SSLPolicyConcept<websocket::ssl::WolfSSLPolicy>);
static_assert(SSLPolicyConcept<WolfSSLPolicy>);
#endif

#endif // C++20
