// xdp/xdp_bio.hpp
// Custom OpenSSL BIO for XDP transport with zero-copy frame API
//
// This BIO implementation bridges OpenSSL with XDPTransport, enabling
// SSL/TLS encryption/decryption to operate directly on UMEM frames
// without intermediate buffer copies.
//
// Architecture:
//   SSL_read()  → bio_read()  → peek_rx_frame() → read from frame->data (UMEM)
//   SSL_write() → bio_write() → get_tx_frame()  → write to frame->data (UMEM)
//
// Zero-copy semantics:
//   - RX: NIC DMAs to UMEM → SSL decrypts in place
//   - TX: SSL encrypts to UMEM → NIC DMAs from UMEM
//   - No intermediate user buffers
//
// Similar to DPDK_BIO but uses XDPFrame API instead of mbufs.

#pragma once

#ifdef USE_XDP

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <errno.h>
#include "xdp_transport.hpp"
#include "xdp_frame.hpp"

namespace websocket {
namespace xdp {

/**
 * XDP_BIO - Custom OpenSSL BIO for XDP transport with zero-copy
 *
 * Manages frame references and implements OpenSSL BIO callbacks to
 * enable SSL operations directly on UMEM frames.
 *
 * Key features:
 *   - Zero-copy: SSL reads/writes directly from/to UMEM
 *   - Frame management: Handles frame acquisition and release
 *   - Multi-frame support: SSL records can span multiple frames
 *   - Non-blocking: Proper retry signaling for async operation
 */
class XDP_BIO {
public:
    /**
     * BIO state for managing frame references
     *
     * Tracks current RX/TX frames and offsets within frames.
     * This allows SSL records to span multiple frames seamlessly.
     */
    struct BIOState {
        XDPTransport* transport;        // XDP transport instance
        XDPFrame* current_rx_frame;     // Currently held RX frame
        XDPFrame* current_tx_frame;     // Currently held TX frame
        uint32_t rx_offset;             // Read offset in current RX frame
        uint32_t tx_offset;             // Write offset in current TX frame

        BIOState(XDPTransport* t)
            : transport(t)
            , current_rx_frame(nullptr)
            , current_tx_frame(nullptr)
            , rx_offset(0)
            , tx_offset(0)
        {}

        ~BIOState() {
            // Release any held frames on destruction
            if (current_rx_frame && transport) {
                transport->release_rx_frame(current_rx_frame);
            }
            if (current_tx_frame && transport) {
                // Submit partial TX frame if it has data
                if (tx_offset > 0) {
                    current_tx_frame->set_length(tx_offset);
                    transport->send_frame(current_tx_frame, tx_offset);
                }
            }
        }
    };

    /**
     * Create BIO method for XDP transport
     *
     * @return BIO_METHOD pointer, or nullptr on failure
     */
    static BIO_METHOD* create_bio_method() {
        BIO_METHOD* bio_method = BIO_meth_new(
            BIO_TYPE_SOURCE_SINK | BIO_get_new_index(),
            "xdp_bio"
        );
        if (!bio_method) {
            return nullptr;
        }

        BIO_meth_set_write(bio_method, bio_write);
        BIO_meth_set_read(bio_method, bio_read);
        BIO_meth_set_puts(bio_method, bio_puts);
        BIO_meth_set_gets(bio_method, nullptr);  // Not implemented
        BIO_meth_set_ctrl(bio_method, bio_ctrl);
        BIO_meth_set_create(bio_method, bio_create);
        BIO_meth_set_destroy(bio_method, bio_destroy);

        return bio_method;
    }

    /**
     * Create BIO instance for XDP transport
     *
     * @param method BIO method created by create_bio_method()
     * @param transport XDP transport instance
     * @return BIO pointer, or nullptr on failure
     */
    static BIO* create_bio(BIO_METHOD* method, XDPTransport* transport) {
        if (!method || !transport) {
            return nullptr;
        }

        BIO* bio = BIO_new(method);
        if (!bio) {
            return nullptr;
        }

        // Allocate and initialize BIO state
        BIOState* state = new BIOState(transport);
        BIO_set_data(bio, state);
        BIO_set_init(bio, 1);

        return bio;
    }

private:
    /**
     * Write data to XDP transport (SSL → UMEM)
     *
     * Called by SSL_write() to send encrypted data to the network.
     * Writes directly to UMEM frame(s), acquiring new frames as needed.
     *
     * @param bio BIO instance
     * @param buf Data to write
     * @param len Data length
     * @return Number of bytes written, or -1 on error/would-block
     */
    static int bio_write(BIO* bio, const char* buf, int len) {
        if (!bio || !buf || len <= 0) {
            return -1;
        }

        BIOState* state = static_cast<BIOState*>(BIO_get_data(bio));
        if (!state || !state->transport) {
            return -1;
        }

        int total_written = 0;

        while (total_written < len) {
            // Try to get TX frame if we don't have one
            if (!state->current_tx_frame) {
                state->current_tx_frame = state->transport->get_tx_frame();
                if (!state->current_tx_frame) {
                    // No frames available
                    if (total_written > 0) {
                        // Partial write succeeded
                        BIO_clear_retry_flags(bio);
                        return total_written;
                    }
                    // Would block
                    BIO_set_retry_write(bio);
                    errno = EAGAIN;
                    return -1;
                }
                state->tx_offset = 0;
            }

            XDPFrame* frame = state->current_tx_frame;

            // Calculate available space in frame
            uint32_t available = frame->capacity - state->tx_offset;
            if (available == 0) {
                // Frame full - submit and get new frame
                frame->set_length(state->tx_offset);
                ssize_t result = state->transport->send_frame(frame, state->tx_offset);

                state->current_tx_frame = nullptr;
                state->tx_offset = 0;

                if (result < 0) {
                    // Send failed
                    if (total_written > 0) {
                        BIO_clear_retry_flags(bio);
                        return total_written;
                    }
                    BIO_set_retry_write(bio);
                    return -1;
                }

                // Continue with next frame
                continue;
            }

            // Write to frame (zero-copy - direct UMEM write)
            int remaining = len - total_written;
            uint32_t to_write = (remaining < (int)available) ? remaining : available;
            memcpy(frame->data + state->tx_offset, buf + total_written, to_write);
            state->tx_offset += to_write;
            total_written += to_write;
        }

        BIO_clear_retry_flags(bio);
        return total_written;
    }

    /**
     * Read data from XDP transport (UMEM → SSL)
     *
     * Called by SSL_read() to receive encrypted data from the network.
     * Reads directly from UMEM frame(s), acquiring new frames as needed.
     *
     * @param bio BIO instance
     * @param buf Buffer to store data
     * @param len Buffer size
     * @return Number of bytes read, or -1 on error/would-block, 0 on EOF
     */
    static int bio_read(BIO* bio, char* buf, int len) {
        if (!bio || !buf || len <= 0) {
            return -1;
        }

        BIOState* state = static_cast<BIOState*>(BIO_get_data(bio));
        if (!state || !state->transport) {
            return -1;
        }

        int total_read = 0;

        while (total_read < len) {
            // Try to peek RX frame if we don't have one
            if (!state->current_rx_frame) {
                state->current_rx_frame = state->transport->peek_rx_frame();
                if (!state->current_rx_frame) {
                    // No frames available
                    if (total_read > 0) {
                        // Partial read succeeded
                        BIO_clear_retry_flags(bio);
                        return total_read;
                    }
                    // Would block
                    BIO_set_retry_read(bio);
                    errno = EAGAIN;
                    return -1;
                }
                state->rx_offset = 0;
            }

            XDPFrame* frame = state->current_rx_frame;

            // Calculate remaining data in frame
            uint32_t remaining = frame->len - state->rx_offset;
            if (remaining == 0) {
                // Frame consumed - release and try next frame
                state->transport->release_rx_frame(frame);
                state->current_rx_frame = nullptr;
                state->rx_offset = 0;

                // Continue to next frame
                continue;
            }

            // Read from frame (zero-copy - direct UMEM read)
            int to_read_requested = len - total_read;
            uint32_t to_read = (to_read_requested < (int)remaining) ? to_read_requested : remaining;
            memcpy(buf + total_read, frame->data + state->rx_offset, to_read);
            state->rx_offset += to_read;
            total_read += to_read;

            // If frame fully consumed, release it immediately
            if (state->rx_offset >= frame->len) {
                state->transport->release_rx_frame(frame);
                state->current_rx_frame = nullptr;
                state->rx_offset = 0;
            }
        }

        BIO_clear_retry_flags(bio);
        return total_read;
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
     * Handles flush, shutdown, and other control commands.
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

        BIOState* state = static_cast<BIOState*>(BIO_get_data(bio));
        if (!state) {
            return 0;
        }

        switch (cmd) {
            case BIO_CTRL_FLUSH:
                // Flush any pending TX frame
                if (state->current_tx_frame && state->tx_offset > 0) {
                    state->current_tx_frame->set_length(state->tx_offset);
                    ssize_t result = state->transport->send_frame(
                        state->current_tx_frame,
                        state->tx_offset
                    );
                    state->current_tx_frame = nullptr;
                    state->tx_offset = 0;

                    return (result >= 0) ? 1 : 0;
                }
                return 1;

            case BIO_CTRL_GET_CLOSE:
                return BIO_get_shutdown(bio);

            case BIO_CTRL_SET_CLOSE:
                BIO_set_shutdown(bio, static_cast<int>(num));
                return 1;

            case BIO_CTRL_PENDING:
                // Return number of bytes available to read
                if (state->current_rx_frame) {
                    return state->current_rx_frame->len - state->rx_offset;
                }
                return 0;

            case BIO_CTRL_WPENDING:
                // Return number of bytes pending write
                if (state->current_tx_frame) {
                    return state->tx_offset;
                }
                return 0;

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
     * Releases any held frames and frees BIO state.
     *
     * @param bio BIO instance
     * @return 1 on success, 0 on failure
     */
    static int bio_destroy(BIO* bio) {
        if (!bio) {
            return 0;
        }

        BIOState* state = static_cast<BIOState*>(BIO_get_data(bio));
        if (state) {
            // BIOState destructor handles frame cleanup
            delete state;
        }

        BIO_set_init(bio, 0);
        BIO_set_data(bio, nullptr);

        return 1;
    }
};

} // namespace xdp
} // namespace websocket

#endif // USE_XDP
