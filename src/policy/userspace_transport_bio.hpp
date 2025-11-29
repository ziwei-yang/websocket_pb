// policy/userspace_transport_bio.hpp
// Generic BIO for userspace transport policies
//
// This BIO bridges OpenSSL with transport policies that implement
// userspace TCP/IP stacks (e.g., XDPUserspaceTransport).
//
// Calls the transport policy's send/recv methods which return TCP stream data.
//
// Architecture:
//   SSL_read()  → bio_read()  → transport.recv() → TCP stream data
//   SSL_write() → bio_write() → transport.send() → TCP stream data
//
// Compatible with any TransportPolicy that provides:
//   - ssize_t send(const void* buf, size_t len)
//   - ssize_t recv(void* buf, size_t len)
//   - void poll() (optional, for non-blocking I/O)

#pragma once

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <errno.h>

namespace websocket {
namespace policy {

/**
 * UserspaceTransportBIO - Generic BIO for userspace transport policies
 *
 * Template parameter: TransportPolicy with send/recv interface
 *
 * This BIO enables SSL/TLS to operate over userspace TCP/IP stacks
 * by calling the transport policy's send/recv methods.
 */
template<typename TransportPolicy>
class UserspaceTransportBIO {
public:
    /**
     * Create BIO method for userspace transport
     *
     * @return BIO_METHOD pointer, or nullptr on failure
     */
    static BIO_METHOD* create_bio_method() {
        BIO_METHOD* bio_method = BIO_meth_new(
            BIO_TYPE_SOURCE_SINK | BIO_get_new_index(),
            "userspace_transport_bio"
        );
        if (!bio_method) {
            return nullptr;
        }

        BIO_meth_set_write(bio_method, bio_write);
        BIO_meth_set_read(bio_method, bio_read);
        BIO_meth_set_puts(bio_method, bio_puts);
        BIO_meth_set_gets(bio_method, nullptr);
        BIO_meth_set_ctrl(bio_method, bio_ctrl);
        BIO_meth_set_create(bio_method, bio_create);
        BIO_meth_set_destroy(bio_method, bio_destroy);

        return bio_method;
    }

    /**
     * Create BIO instance for userspace transport
     *
     * @param method BIO method created by create_bio_method()
     * @param transport Transport policy instance
     * @return BIO pointer, or nullptr on failure
     */
    static BIO* create_bio(BIO_METHOD* method, TransportPolicy* transport) {
        if (!method || !transport) {
            return nullptr;
        }

        BIO* bio = BIO_new(method);
        if (!bio) {
            return nullptr;
        }

        BIO_set_data(bio, transport);
        BIO_set_init(bio, 1);

        return bio;
    }

private:
    /**
     * Write data via transport policy
     *
     * @param bio BIO instance
     * @param buf Data to write
     * @param len Data length
     * @return Number of bytes written, or -1 on error
     */
    static int bio_write(BIO* bio, const char* buf, int len) {
        if (!bio || !buf || len <= 0) {
            return -1;
        }

        auto* transport = static_cast<TransportPolicy*>(BIO_get_data(bio));
        if (!transport) {
            return -1;
        }

        ssize_t result = transport->send(buf, len);
        if (result < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                BIO_set_retry_write(bio);
            }
            return -1;
        }

        BIO_clear_retry_flags(bio);
        return static_cast<int>(result);
    }

    /**
     * Read data from transport policy
     *
     * @param bio BIO instance
     * @param buf Buffer to store data
     * @param len Buffer size
     * @return Number of bytes read, or -1 on error, 0 on EOF
     */
    static int bio_read(BIO* bio, char* buf, int len) {
        if (!bio || !buf || len <= 0) {
            return -1;
        }

        auto* transport = static_cast<TransportPolicy*>(BIO_get_data(bio));
        if (!transport) {
            return -1;
        }

        ssize_t result = transport->recv(buf, len);
        if (result < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                BIO_set_retry_read(bio);
            }
            return -1;
        }

        if (result == 0) {
            return 0;  // Connection closed
        }

        BIO_clear_retry_flags(bio);
        return static_cast<int>(result);
    }

    /**
     * Write string to BIO
     *
     * @param bio BIO instance
     * @param str String to write
     * @return Number of bytes written, or -1 on error
     */
    static int bio_puts(BIO* bio, const char* str) {
        if (!bio || !str) {
            return -1;
        }
        return bio_write(bio, str, strlen(str));
    }

    /**
     * BIO control operations
     *
     * @param bio BIO instance
     * @param cmd Control command
     * @param num Numeric argument
     * @param ptr Pointer argument
     * @return Command-specific return value
     */
    static long bio_ctrl(BIO* bio, int cmd, long num, void* ptr) {
        (void)num;
        (void)ptr;

        if (!bio) {
            return 0;
        }

        switch (cmd) {
            case BIO_CTRL_FLUSH:
                return 1;

            case BIO_CTRL_GET_CLOSE:
                return BIO_get_shutdown(bio);

            case BIO_CTRL_SET_CLOSE:
                BIO_set_shutdown(bio, static_cast<int>(num));
                return 1;

            default:
                return 0;
        }
    }

    /**
     * Create BIO instance
     *
     * @param bio BIO instance
     * @return 1 on success, 0 on failure
     */
    static int bio_create(BIO* bio) {
        if (!bio) {
            return 0;
        }

        BIO_set_init(bio, 0);
        BIO_set_data(bio, nullptr);
        BIO_clear_flags(bio, ~0);

        return 1;
    }

    /**
     * Destroy BIO instance
     *
     * @param bio BIO instance
     * @return 1 on success, 0 on failure
     */
    static int bio_destroy(BIO* bio) {
        if (!bio) {
            return 0;
        }

        BIO_set_init(bio, 0);
        BIO_set_data(bio, nullptr);

        return 1;
    }
};

} // namespace policy
} // namespace websocket
