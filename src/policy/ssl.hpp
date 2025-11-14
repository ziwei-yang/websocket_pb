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
//   - void handshake(int fd)
//   - ssize_t read(void* buf, size_t len)
//   - ssize_t write(const void* buf, size_t len)
//   - bool ktls_enabled() const
//   - int get_fd() const
//   - void shutdown()
//
// Namespace: websocket::ssl

#pragma once

#include <stdexcept>
#include <cstdio>
#include <cstring>

// ============================================================================
// Library Detection
// ============================================================================

// Determine which SSL library is available
#if defined(WOLFSSL_USER_SETTINGS) || defined(HAVE_WOLFSSL)
    #define SSL_POLICY_WOLFSSL 1
    #include <wolfssl/options.h>
    #include <wolfssl/ssl.h>
#elif defined(LIBRESSL_VERSION_NUMBER)
    #define SSL_POLICY_LIBRESSL 1
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/bio.h>
#else
    // Default to OpenSSL
    #define SSL_POLICY_OPENSSL 1
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/bio.h>
#endif

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
    OpenSSLPolicy() : ctx_(nullptr), ssl_(nullptr), ktls_enabled_(false) {}

    ~OpenSSLPolicy() {
        shutdown();
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
        // Disable kTLS to allow hardware timestamp retrieval
        // kTLS (kernel TLS) prevents access to socket-level timestamps
        // SSL_CTX_set_options(ctx_, SSL_OP_ENABLE_KTLS);  // DISABLED for timestamp access
        #endif
    }

    /**
     * Perform TLS handshake
     *
     * @param fd Socket file descriptor
     * @throws std::runtime_error if handshake fails
     */
    void handshake(int fd) {
        ssl_ = SSL_new(ctx_);
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

        #ifdef __linux__
        // Check if kTLS was successfully activated
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
                return -1;
            }
            return -1;  // Error
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
                return -1;
            }
            return -1;  // Error
        }
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
     * Shutdown SSL connection and free resources
     */
    void shutdown() {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }

        if (ctx_) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }

        ktls_enabled_ = false;
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
    LibreSSLPolicy() : ctx_(nullptr), ssl_(nullptr) {}

    ~LibreSSLPolicy() {
        shutdown();
    }

    // Prevent copying
    LibreSSLPolicy(const LibreSSLPolicy&) = delete;
    LibreSSLPolicy& operator=(const LibreSSLPolicy&) = delete;

    // Allow moving
    LibreSSLPolicy(LibreSSLPolicy&& other) noexcept
        : ctx_(other.ctx_)
        , ssl_(other.ssl_)
    {
        other.ctx_ = nullptr;
        other.ssl_ = nullptr;
    }

    LibreSSLPolicy& operator=(LibreSSLPolicy&& other) noexcept {
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
        ssl_ = SSL_new(ctx_);
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
                return -1;
            }
            return -1;  // Error
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
                return -1;
            }
            return -1;  // Error
        }
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
     * Shutdown SSL connection and free resources
     */
    void shutdown() {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
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
};

#endif // SSL_POLICY_LIBRESSL

// ============================================================================
// WolfSSL Policy (Lightweight, embedded-friendly)
// ============================================================================

#ifdef SSL_POLICY_WOLFSSL

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
        shutdown();
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
        ssl_ = wolfSSL_new(ctx_);
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
                return -1;
            }
            return -1;  // Error
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
                return -1;
            }
            return -1;  // Error
        }
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
     * Shutdown SSL connection and free resources
     */
    void shutdown() {
        if (ssl_) {
            wolfSSL_shutdown(ssl_);
            wolfSSL_free(ssl_);
            ssl_ = nullptr;
        }

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

#ifdef SSL_POLICY_OPENSSL
using OpenSSLPolicy = websocket::ssl::OpenSSLPolicy;
#endif

#ifdef SSL_POLICY_LIBRESSL
using LibreSSLPolicy = websocket::ssl::LibreSSLPolicy;
#endif

#ifdef SSL_POLICY_WOLFSSL
using WolfSSLPolicy = websocket::ssl::WolfSSLPolicy;
#endif

// ============================================================================
// Default SSL Policy Selection
// ============================================================================

#if defined(SSL_POLICY_OPENSSL)
    // OpenSSL (default)
    using DefaultSSLPolicy = websocket::ssl::OpenSSLPolicy;
    using SSLPolicy = websocket::ssl::OpenSSLPolicy;
#elif defined(SSL_POLICY_LIBRESSL)
    // LibreSSL (macOS, BSD)
    using DefaultSSLPolicy = websocket::ssl::LibreSSLPolicy;
    using SSLPolicy = websocket::ssl::LibreSSLPolicy;
#elif defined(SSL_POLICY_WOLFSSL)
    // WolfSSL (embedded, lightweight)
    using DefaultSSLPolicy = websocket::ssl::WolfSSLPolicy;
    using SSLPolicy = websocket::ssl::WolfSSLPolicy;
#endif

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

static_assert(SSLPolicyConcept<SSLPolicy>);
static_assert(SSLPolicyConcept<DefaultSSLPolicy>);

#endif // C++20

// ============================================================================
// Usage Examples
// ============================================================================

/*

// Example 1: Using platform-default SSL policy
SSLPolicy ssl;
ssl.init();
ssl.handshake(sockfd);

char buf[4096];
ssize_t n = ssl.read(buf, sizeof(buf));
if (n > 0) {
    // Process decrypted data
}

// Example 2: Explicit policy selection
websocket::ssl::OpenSSLPolicy openssl;
openssl.init();
openssl.handshake(sockfd);

if (openssl.ktls_enabled()) {
    // Using kernel TLS for better performance!
}

// Example 3: Policy-based template
template <typename SSLPolicy>
class SecureWebSocketClient {
    SSLPolicy ssl_;
public:
    void connect(int fd) {
        ssl_.init();
        ssl_.handshake(fd);
    }

    ssize_t receive(void* buf, size_t len) {
        return ssl_.read(buf, len);
    }

    ssize_t send(const void* buf, size_t len) {
        return ssl_.write(buf, len);
    }
};

// Instantiate with different policies
SecureWebSocketClient<websocket::ssl::OpenSSLPolicy> openssl_client;
SecureWebSocketClient<websocket::ssl::LibreSSLPolicy> libressl_client;
SecureWebSocketClient<websocket::ssl::WolfSSLPolicy> wolfssl_client;

// Example 4: Check kTLS support
SSLPolicy ssl;
ssl.init();
ssl.handshake(sockfd);

if (ssl.ktls_enabled()) {
    std::cout << "Using kernel TLS for zero-copy encryption!" << std::endl;
} else {
    std::cout << "Using userspace TLS" << std::endl;
}

*/
