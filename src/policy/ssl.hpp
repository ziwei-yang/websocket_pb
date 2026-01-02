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
#include <unistd.h>  // usleep() for DPDK handshake polling

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
#endif

// Forward declaration for userspace transport BIO
#include "userspace_transport_bio.hpp"

namespace websocket {
namespace ssl {

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
     * @throws std::runtime_error if initialization fails
     */
    void init() {
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
            throw std::runtime_error("SSL_CTX_new() failed");
        }

        // Set minimum TLS version to 1.2 for security and kTLS compatibility
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);

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
    }

    /**
     * Perform TLS handshake
     *
     * @param fd Socket file descriptor
     * @throws std::runtime_error if handshake fails
     */
    void handshake(int fd) {
        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            init();
        }

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            init();
            ssl_ = SSL_new(ctx_);
        }

        if (!ssl_) {
            throw std::runtime_error("SSL_new() failed");
        }

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
    }

    /**
     * Perform TLS handshake over userspace transport
     *
     * Works with any transport policy implementing send/recv/poll interface.
     * Example: XDPUserspaceTransport, or any custom userspace TCP stack.
     *
     * @param transport Transport policy instance
     * @throws std::runtime_error on handshake failure
     */
    template<typename TransportPolicy>
    void handshake_userspace_transport(TransportPolicy* transport) {
        if (!transport) {
            throw std::runtime_error("Transport is null");
        }

        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            init();
        }

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            init();
            ssl_ = SSL_new(ctx_);
        }

        if (!ssl_) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            throw std::runtime_error(std::string("SSL_new() failed: ") + err_buf);
        }

        // Create custom BIO for userspace transport
        bio_method_ = websocket::policy::UserspaceTransportBIO<TransportPolicy>::create_bio_method();
        if (!bio_method_) {
            SSL_free(ssl_);
            throw std::runtime_error("Failed to create userspace transport BIO method");
        }

        BIO* bio = websocket::policy::UserspaceTransportBIO<TransportPolicy>::create_bio(bio_method_, transport);
        if (!bio) {
            SSL_free(ssl_);
            throw std::runtime_error("Failed to create userspace transport BIO");
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
                printf("[SSL] Handshake complete (userspace transport)\n");
                return;
            }

            int err = SSL_get_error(ssl_, ret);
            if (retries < 5 || retries % 100 == 0) {
                printf("[SSL-DEBUG] Handshake attempt #%d: ret=%d, err=%d (%s), errno=%d\n",
                       retries, ret, err,
                       err == SSL_ERROR_WANT_READ ? "WANT_READ" :
                       err == SSL_ERROR_WANT_WRITE ? "WANT_WRITE" :
                       err == SSL_ERROR_SYSCALL ? "SYSCALL" :
                       err == SSL_ERROR_SSL ? "SSL" : "OTHER",
                       errno);
            }

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
            printf("[SSL-ERROR] Fatal error after %d retries: %s\n", retries, err_buf);
            SSL_free(ssl_);
            ssl_ = nullptr;
            throw std::runtime_error(std::string("SSL handshake failed: ") + err_buf);
        }

        SSL_free(ssl_);
        ssl_ = nullptr;
        throw std::runtime_error("SSL handshake timeout");
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

            // Fatal SSL error - log and set errno
            unsigned long err_code = ERR_get_error();
            if (err_code != 0) {
                char err_buf[256];
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                printf("[SSL ERROR] SSL_read failed: %s (ssl_err=%d)\n", err_buf, err);
            } else {
                printf("[SSL ERROR] SSL_read failed: ssl_error=%d\n", err);
            }

            errno = EIO;  // Fatal error
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

            // Fatal SSL error - log and set errno
            unsigned long err_code = ERR_get_error();
            if (err_code != 0) {
                char err_buf[256];
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                printf("[SSL ERROR] SSL_write failed: %s (ssl_err=%d)\n", err_buf, err);
            } else {
                printf("[SSL ERROR] SSL_write failed: ssl_error=%d\n", err);
            }

            errno = EIO;  // Fatal error
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
        // Note: ctx_ and bio_method_ kept for reconnection, freed in destructor
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

    SSL_CTX* ctx_;
    SSL* ssl_;
    bool ktls_enabled_;
    BIO_METHOD* bio_method_;  // For userspace transport BIO
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
     * @throws std::runtime_error if initialization fails
     */
    void init() {
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
            throw std::runtime_error("SSL_CTX_new() failed");
        }

        // Set minimum TLS version to 1.2 for security
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);

        // Disable verification for simplicity
        // In production, you should verify certificates!
        SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    }

    /**
     * Perform TLS handshake
     *
     * @param fd Socket file descriptor
     * @throws std::runtime_error if handshake fails
     */
    void handshake(int fd) {
        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            init();
        }

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            init();
            ssl_ = SSL_new(ctx_);
        }

        if (!ssl_) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            throw std::runtime_error(std::string("SSL_new() failed: ") + err_buf);
        }

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
    }

    /**
     * Perform TLS handshake over userspace transport
     *
     * Works with any transport policy implementing send/recv/poll interface.
     * Example: XDPUserspaceTransport, or any custom userspace TCP stack.
     *
     * @param transport Transport policy instance
     * @throws std::runtime_error on handshake failure
     */
    template<typename TransportPolicy>
    void handshake_userspace_transport(TransportPolicy* transport) {
        if (!transport) {
            throw std::runtime_error("Transport is null");
        }

        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            init();
        }

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                SSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            init();
            ssl_ = SSL_new(ctx_);
        }

        if (!ssl_) {
            unsigned long err = ERR_get_error();
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            throw std::runtime_error(std::string("SSL_new() failed: ") + err_buf);
        }

        // Create custom BIO for userspace transport
        bio_method_ = websocket::policy::UserspaceTransportBIO<TransportPolicy>::create_bio_method();
        if (!bio_method_) {
            SSL_free(ssl_);
            throw std::runtime_error("Failed to create userspace transport BIO method");
        }

        BIO* bio = websocket::policy::UserspaceTransportBIO<TransportPolicy>::create_bio(bio_method_, transport);
        if (!bio) {
            SSL_free(ssl_);
            throw std::runtime_error("Failed to create userspace transport BIO");
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
                printf("[SSL] Handshake complete (userspace transport)\n");
                return;
            }

            int err = SSL_get_error(ssl_, ret);
            if (retries < 5 || retries % 100 == 0) {
                printf("[SSL-DEBUG] Handshake attempt #%d: ret=%d, err=%d (%s), errno=%d\n",
                       retries, ret, err,
                       err == SSL_ERROR_WANT_READ ? "WANT_READ" :
                       err == SSL_ERROR_WANT_WRITE ? "WANT_WRITE" :
                       err == SSL_ERROR_SYSCALL ? "SYSCALL" :
                       err == SSL_ERROR_SSL ? "SSL" : "OTHER",
                       errno);
            }

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
            printf("[SSL-ERROR] Fatal error after %d retries: %s\n", retries, err_buf);
            SSL_free(ssl_);
            ssl_ = nullptr;
            throw std::runtime_error(std::string("SSL handshake failed: ") + err_buf);
        }

        SSL_free(ssl_);
        ssl_ = nullptr;
        throw std::runtime_error("SSL handshake timeout");
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

            // Fatal SSL error - log and set errno
            unsigned long err_code = ERR_get_error();
            if (err_code != 0) {
                char err_buf[256];
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                printf("[SSL ERROR] SSL_read failed: %s (ssl_err=%d)\n", err_buf, err);
            } else {
                printf("[SSL ERROR] SSL_read failed: ssl_error=%d\n", err);
            }

            errno = EIO;  // Fatal error
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

            // Fatal SSL error - log and set errno
            unsigned long err_code = ERR_get_error();
            if (err_code != 0) {
                char err_buf[256];
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                printf("[SSL ERROR] SSL_write failed: %s (ssl_err=%d)\n", err_buf, err);
            } else {
                printf("[SSL ERROR] SSL_write failed: ssl_error=%d\n", err);
            }

            errno = EIO;  // Fatal error
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
        // Note: ctx_ and bio_method_ kept for reconnection, freed in destructor
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

        if (ctx_) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

    /**
     * Get SSL implementation name
     */
    static constexpr const char* name() {
        return "LibreSSL";
    }

    SSL_CTX* ctx_;
    SSL* ssl_;
    BIO_METHOD* bio_method_;  // For userspace transport BIO
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
     * @throws std::runtime_error if initialization fails
     */
    void init() {
        // Initialize WolfSSL library
        wolfSSL_Init();

        // Create TLS 1.2 client method
        WOLFSSL_METHOD* method = wolfTLSv1_2_client_method();
        ctx_ = wolfSSL_CTX_new(method);

        if (!ctx_) {
            throw std::runtime_error("wolfSSL_CTX_new() failed");
        }

        // Disable verification for simplicity (HFT optimization)
        // In production, you should verify certificates!
        wolfSSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
    }

    /**
     * Perform TLS handshake
     *
     * @param fd Socket file descriptor
     * @throws std::runtime_error if handshake fails
     */
    void handshake(int fd) {
        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            init();
        }

        ssl_ = wolfSSL_new(ctx_);
        if (!ssl_) {
            // ctx_ might be stale after reconnect, try reinitializing
            if (ctx_) {
                wolfSSL_CTX_free(ctx_);
                ctx_ = nullptr;
            }
            init();
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
    }

    /**
     * Perform TLS handshake over userspace transport
     *
     * Works with any transport policy implementing send/recv/poll interface.
     * Example: XDPUserspaceTransport, or any custom userspace TCP stack.
     *
     * @param transport Transport policy instance
     * @throws std::runtime_error on handshake failure
     */
    template<typename TransportPolicy>
    void handshake_userspace_transport(TransportPolicy* transport) {
        if (!transport) {
            throw std::runtime_error("Transport is null");
        }

        // If ctx_ is null, initialize (first connection or after full cleanup)
        if (!ctx_) {
            init();
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
            init();
            // Re-register callbacks on new context
            wolfSSL_CTX_SetIORecv(ctx_, WolfSSLUserspaceIO<TransportPolicy>::recv_cb);
            wolfSSL_CTX_SetIOSend(ctx_, WolfSSLUserspaceIO<TransportPolicy>::send_cb);
            ssl_ = wolfSSL_new(ctx_);
        }

        if (!ssl_) {
            throw std::runtime_error("wolfSSL_new() failed");
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
                // Handshake successful - stop trickle thread, switch to inline trickle
                transport->stop_rx_trickle_thread();
                printf("[SSL] Handshake complete (userspace transport)\n");
                return;
            }

            int err = wolfSSL_get_error(ssl_, ret);
            if (retries < 5 || retries % 100 == 0) {
                printf("[SSL-DEBUG] Handshake attempt #%d: ret=%d, err=%d (%s), errno=%d\n",
                       retries, ret, err,
                       err == SSL_ERROR_WANT_READ ? "WANT_READ" :
                       err == SSL_ERROR_WANT_WRITE ? "WANT_WRITE" :
                       err == SSL_ERROR_SYSCALL ? "SYSCALL" :
                       err == SSL_ERROR_SSL ? "SSL" : "OTHER",
                       errno);
            }

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
            printf("[SSL-ERROR] Fatal error after %d retries: %s\n", retries, err_buf);
            wolfSSL_free(ssl_);
            ssl_ = nullptr;
            throw std::runtime_error(std::string("SSL handshake failed: ") + err_buf);
        }

        wolfSSL_free(ssl_);
        ssl_ = nullptr;
        throw std::runtime_error("SSL handshake timeout");
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

            // Fatal SSL error - log and set errno
            char err_buf[256];
            wolfSSL_ERR_error_string(err, err_buf);
            printf("[SSL ERROR] wolfSSL_read failed: %s (err=%d)\n", err_buf, err);

            errno = EIO;  // Fatal error
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

            // Fatal SSL error - log and set errno
            char err_buf[256];
            wolfSSL_ERR_error_string(err, err_buf);
            printf("[SSL ERROR] wolfSSL_write failed: %s (err=%d)\n", err_buf, err);

            errno = EIO;  // Fatal error
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

    /**
     * Shutdown SSL connection (keeps ctx_ for reconnection)
     * Full cleanup happens in destructor
     */
    void shutdown() {
        if (ssl_) {
            wolfSSL_shutdown(ssl_);
            wolfSSL_free(ssl_);
            ssl_ = nullptr;
        }
        // Note: ctx_ is kept for reconnection, freed in destructor
    }

    /**
     * Full cleanup - called by destructor
     */
    void cleanup() {
        shutdown();  // Free ssl_ first

        if (ctx_) {
            wolfSSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }

        wolfSSL_Cleanup();
    }

    /**
     * Get SSL implementation name
     */
    static constexpr const char* name() {
        return "WolfSSL";
    }

    WOLFSSL_CTX* ctx_;
    WOLFSSL* ssl_;
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

    void init() {
        // No SSL context needed
    }

    // BSD socket handshake (no-op for NoSSL)
    void handshake(int fd) {
        (void)fd;
        // No handshake needed
    }

    // Userspace transport handshake - store transport pointer
    template<typename TransportPolicy>
    void handshake_userspace_transport(TransportPolicy* transport) {
        transport_ = static_cast<void*>(transport);
        recv_fn_ = [](void* tp, void* buf, size_t len) -> ssize_t {
            return static_cast<TransportPolicy*>(tp)->recv(buf, len);
        };
        send_fn_ = [](void* tp, const void* buf, size_t len) -> ssize_t {
            return static_cast<TransportPolicy*>(tp)->send(buf, len);
        };
    }

    ssize_t read(void* buf, size_t len) {
        if (!transport_ || !recv_fn_) {
            errno = ENOTCONN;
            return -1;
        }
        return recv_fn_(transport_, buf, len);
    }

    ssize_t write(const void* buf, size_t len) {
        if (!transport_ || !send_fn_) {
            errno = ENOTCONN;
            return -1;
        }
        return send_fn_(transport_, buf, len);
    }

    bool ktls_enabled() const { return false; }
    int get_fd() const { return -1; }
    int pending() const { return 0; }  // No SSL buffering
    void shutdown() { transport_ = nullptr; }
    void cleanup() { transport_ = nullptr; }

private:
    void* transport_ = nullptr;
    ssize_t (*recv_fn_)(void*, void*, size_t) = nullptr;
    ssize_t (*send_fn_)(void*, const void*, size_t) = nullptr;
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
 */
template<typename T>
concept SSLPolicyConcept = requires(T ssl, int fd, void* buf, size_t len) {
    { ssl.init() } -> std::same_as<void>;
    { ssl.handshake(fd) } -> std::same_as<void>;
    { ssl.read(buf, len) } -> std::convertible_to<ssize_t>;
    { ssl.write(buf, len) } -> std::convertible_to<ssize_t>;
    { ssl.ktls_enabled() } -> std::convertible_to<bool>;
    { ssl.get_fd() } -> std::convertible_to<int>;
    { ssl.shutdown() } -> std::same_as<void>;
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
