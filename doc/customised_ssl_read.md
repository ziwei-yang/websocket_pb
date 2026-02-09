# Fast Progressive SSL_read

## Problem

The standard `SSL_read()` call in every poll iteration is wasteful when no
complete TLS record has arrived. Each failed call that returns `WANT_READ` still
pays the cost of function dispatch, internal state checks, and a BIO read
attempt. In an HFT busy-poll loop running millions of iterations per second,
these empty calls accumulate significant overhead.

Current hot path (`10_tcp_ssl_process.hpp`):

```cpp
// Called every iteration regardless of encrypted data availability
ssize_t read_len = ssl_.read(msg_inbox_->write_ptr(), linear_space);
```

When the underlying BIO or I/O callback has no data, the library still:
1. Enters the record-layer state machine
2. Attempts to read the 5-byte record header from the BIO
3. Gets `WANT_READ` from the BIO callback
4. Propagates `SSL_ERROR_WANT_READ` back to the caller

This is 100-300ns of wasted work per iteration on typical hardware.

## TLS Record Structure

All three libraries process the same wire format. Understanding it is the
foundation of progressive reading.

```
+------+----------+--------+------------------+-----+
|  CT  | Version  | Length |     Payload      | Tag |
+------+----------+--------+------------------+-----+
  1B      2B         2B       variable          16B   (AES-GCM)
```

- **CT** (Content Type): 0x17 = Application Data, 0x15 = Alert, 0x16 = Handshake, 0x14 = CCS
- **Version**: 0x0303 (TLS 1.2 on the wire, even for TLS 1.3 records)
- **Length**: Big-endian uint16, size of Payload + Tag (max 16384 + 256 = 16640)
- **Tag**: 16 bytes for AES-128-GCM / AES-256-GCM (the AEAD authentication tag)

Constants from `pipeline_config.hpp`:

```cpp
constexpr size_t TLS_RECORD_HEADER = 5;     // CT(1) + Version(2) + Length(2)
constexpr size_t TLS_MAC_SIZE = 16;          // AES-GCM tag
constexpr size_t TLS13_OVERHEAD = 21;        // Header(5) + Tag(16)
```

For TLS 1.3, the actual content type is encrypted inside the payload (the outer
CT is always 0x17). The `Length` field includes the AEAD tag and the inner
content type byte.

## Solution: Fast Progressive SSL_read

The technique has three phases that replace the single blind `SSL_read()` call:

### Phase 1: Pre-check Encrypted Data Availability

Before calling `SSL_read()`, inspect the ring buffer (or BIO) to determine
if enough encrypted bytes have accumulated. This avoids entering the SSL
state machine when the answer is guaranteed to be `WANT_READ`.

```cpp
// Peek at ring buffer to check available encrypted bytes
size_t enc_avail = encrypted_bytes_available();  // ring buffer occupancy
if (enc_avail < TLS_RECORD_HEADER) {
    return 0;  // Not even a header present, skip SSL_read entirely
}
```

### Phase 2: Record-Aware Gating

Parse the TLS record header from the ring buffer to determine the full
record size. Only call `SSL_read()` when the complete record is present.

```cpp
// Peek at TLS record header (non-consuming, zero-copy from ring buffer)
const uint8_t* hdr = peek_encrypted(TLS_RECORD_HEADER);
uint16_t record_len = (hdr[3] << 8) | hdr[4];   // big-endian Length field
size_t total_needed = TLS_RECORD_HEADER + record_len;

if (enc_avail < total_needed) {
    return 0;  // Partial record, wait for remaining bytes
}

// Complete record present -- SSL_read will succeed without WANT_READ
timing.recv_start_cycle = rdtsc();
ssize_t read_len = ssl_.read(buf, buf_len);
timing.recv_end_cycle = rdtscp();
```

### Phase 3: Drain Loop

After a successful `SSL_read()`, the library may have buffered additional
decrypted plaintext internally (e.g., if multiple TLS records arrived in a
burst and the BIO consumed them all during the first `SSL_read()`). Drain
all available data before returning.

```cpp
ssize_t total = read_len;
while (ssl_.pending() > 0) {
    ssize_t more = ssl_.read(buf + total, buf_len - total);
    if (more <= 0) break;
    total += more;
}
```

## Library-Specific Implementation Details

### WolfSSL

WolfSSL uses native I/O callbacks rather than BIOs. The ring buffer
occupancy is directly accessible from the callback context.

**Key APIs:**

| Function | Purpose |
|---|---|
| `wolfSSL_pending(ssl)` | Bytes of already-decrypted plaintext buffered internally |
| `wolfSSL_peek(ssl, buf, len)` | Read decrypted data without consuming it |
| `wolfSSL_CTX_SetIORecv(ctx, cb)` | Register custom receive callback |
| `wolfSSL_SetIOReadCtx(ssl, ptr)` | Set callback context (ring buffer pointer) |

**Internal flow** (`src/internal.c`):

```
wolfSSL_read()
  -> ReceiveData()
    -> GetInputData()       // calls recv callback to fill ssl->buffers.inputBuffer
    -> ProcessReply()       // parse record header, decrypt
```

`GetInputData()` calls the registered `recv_cb` and returns
`WOLFSSL_CBIO_ERR_WANT_READ` if no data is available.

**Progressive implementation with WolfSSL:**

The pre-check inspects the ring buffer directly since the `WolfSSLPolicy`
owns both the ring buffer state and is the I/O callback context:

```cpp
// WolfSSLPolicy member: check ring buffer before SSL_read
size_t encrypted_bytes_available() const {
    size_t avail = 0;
    for (size_t i = in_view_tail_; i != in_view_head_; i++) {
        avail += in_views_[i & VIEW_RING_MASK].len;
    }
    if (in_view_tail_ != in_view_head_) {
        avail -= in_view_pos_;  // subtract consumed portion of current segment
    }
    return avail;
}

// Peek at first N bytes across ring buffer segments (non-consuming)
bool peek_encrypted(uint8_t* out, size_t n) const {
    size_t copied = 0;
    size_t tail = in_view_tail_;
    size_t pos = in_view_pos_;
    while (copied < n && tail != in_view_head_) {
        const auto& seg = in_views_[tail & VIEW_RING_MASK];
        size_t avail = seg.len - pos;
        size_t to_copy = std::min(n - copied, avail);
        memcpy(out + copied, seg.data + pos, to_copy);
        copied += to_copy;
        pos += to_copy;
        if (pos >= seg.len) { tail++; pos = 0; }
    }
    return copied == n;
}
```

The drain loop uses `wolfSSL_pending()`:

```cpp
ssize_t total = wolfSSL_read(ssl_, buf, len);
if (total > 0) {
    while (wolfSSL_pending(ssl_) > 0) {
        ssize_t more = wolfSSL_read(ssl_, buf + total, len - total);
        if (more <= 0) break;
        total += more;
    }
}
```

**WolfSSL-specific notes:**

- WolfSSL's internal input buffer (`ssl->buffers.inputBuffer`) is
  dynamically sized. When `WOLFSSL_SMALL_STACK` is defined, it starts
  small and grows. For HFT, pre-allocate with `wolfSSL_SetIOBuffers()` if
  available, or build with `LARGE_STATIC_BUFFERS`.
- `wolfSSL_peek()` internally calls `ReceiveData()` with a peek flag,
  which means it still enters the record layer. Use the ring buffer peek
  (above) instead for the pre-check -- it avoids all library overhead.
- WolfSSL does not have an equivalent of OpenSSL's `SSL_has_pending()`.
  Use `wolfSSL_pending()` which returns only fully decrypted bytes.

---

### OpenSSL

OpenSSL uses custom BIOs. The zero-copy BIO already implements
`BIO_CTRL_PENDING` which reports ring buffer occupancy.

**Key APIs:**

| Function | Purpose |
|---|---|
| `SSL_pending(ssl)` | Bytes of decrypted plaintext buffered internally |
| `SSL_has_pending(ssl)` | Any unprocessed data exists, including partial records (1.1.0+) |
| `SSL_peek(ssl, buf, len)` | Read decrypted data without consuming it |
| `BIO_ctrl_pending(bio)` | Bytes available in BIO (triggers `BIO_CTRL_PENDING` callback) |
| `SSL_set_read_ahead(ssl, 1)` | Enable read-ahead: read more from BIO than strictly needed |

**Internal flow** (`ssl/record/rec_layer_s3.c`):

```
SSL_read()
  -> ssl3_read_bytes()
    -> ssl3_get_record()
      -> BIO_read(rbio, ...)     // reads header (5 bytes)
      -> BIO_read(rbio, ...)     // reads payload (Length bytes)
      -> decrypt in place
```

**Progressive implementation with OpenSSL:**

The pre-check uses `BIO_ctrl_pending()` on the read BIO, which calls the
existing `zc_bio_ctrl` handler with `BIO_CTRL_PENDING`:

```cpp
// Pre-check: query BIO for available encrypted bytes
BIO* rbio = SSL_get_rbio(ssl_);
size_t enc_avail = BIO_ctrl_pending(rbio);
if (enc_avail < TLS_RECORD_HEADER) {
    return 0;  // skip SSL_read
}
```

For record-aware gating, peek at the ring buffer directly (the BIO data
pointer gives access to the policy object):

```cpp
// OpenSSLPolicy member
uint16_t peek_tls_record_length() const {
    uint8_t hdr[TLS_RECORD_HEADER];
    if (!peek_encrypted(hdr, TLS_RECORD_HEADER)) return 0;
    return (static_cast<uint16_t>(hdr[3]) << 8) | hdr[4];
}
```

The drain loop uses both `SSL_pending()` and `SSL_has_pending()`:

```cpp
ssize_t total = SSL_read(ssl_, buf, len);
if (total > 0) {
    // SSL_has_pending() catches records that SSL consumed from BIO
    // but hasn't decrypted yet (read-ahead mode)
    while (SSL_pending(ssl_) > 0 || SSL_has_pending(ssl_)) {
        ssize_t more = SSL_read(ssl_, buf + total, len - total);
        if (more <= 0) break;
        total += more;
    }
}
```

**OpenSSL-specific notes:**

- `SSL_set_read_ahead(ssl, 1)` makes OpenSSL read as much as possible
  from the BIO in one go, which can pull multiple TLS records into its
  internal buffer. This pairs well with the drain loop -- one BIO read
  satisfies multiple SSL_read calls.
- `SSL_has_pending()` (OpenSSL 1.1.0+) returns true if there's *any*
  buffered data, including partial records that haven't been decrypted yet.
  `SSL_pending()` only counts fully decrypted bytes. The drain loop should
  check both.
- The existing `zc_bio_ctrl` handler for `BIO_CTRL_PENDING` already sums
  all ring buffer segments. This makes `BIO_ctrl_pending()` zero-overhead
  for the pre-check -- no syscall, just a ring buffer walk.

---

### LibreSSL 3.5+

LibreSSL uses the same BIO API as OpenSSL. The zero-copy BIO implementation
is identical. LibreSSL 3.5+ is the minimum version for reliable TLS 1.3
support and modern BIO method APIs.

**Key APIs:**

| Function | Purpose |
|---|---|
| `SSL_pending(ssl)` | Bytes of decrypted plaintext buffered internally |
| `SSL_peek(ssl, buf, len)` | Read decrypted data without consuming it |
| `BIO_ctrl_pending(bio)` | Bytes available in BIO (triggers `BIO_CTRL_PENDING` callback) |
| `BIO_meth_new()` | Create custom BIO method (available since LibreSSL 2.8) |

**Differences from OpenSSL:**

| Feature | OpenSSL | LibreSSL 3.5+ |
|---|---|---|
| `SSL_has_pending()` | Available (1.1.0+) | **Not available** |
| `SSL_set_read_ahead()` | Works, aggressive BIO reads | Exists but may behave differently |
| `SSL_read_ex()` | Available (1.1.1+) | **Not available** (added ~3.8.x) |
| `BIO_meth_set_read_ex()` | Available (1.1.1+) | **Not available** |
| Custom BIO (`BIO_meth_*`) | Full support | Full support (since 2.8) |
| TLS 1.3 records | Full support | Full support (since 3.3, stable in 3.5+) |

**Progressive implementation with LibreSSL:**

Identical to OpenSSL except the drain loop cannot use `SSL_has_pending()`:

```cpp
ssize_t total = SSL_read(ssl_, buf, len);
if (total > 0) {
    // No SSL_has_pending() in LibreSSL -- use SSL_pending() only
    while (SSL_pending(ssl_) > 0) {
        ssize_t more = SSL_read(ssl_, buf + total, len - total);
        if (more <= 0) break;
        total += more;
    }
}
```

Because `SSL_has_pending()` is not available, LibreSSL may leave a partial
record undrained if read-ahead pulled it into the internal buffer. In
practice this is rare: with `MAX_TLS_RECORD_PAYLOAD` set to fit a single
TCP segment, TLS records almost always arrive as complete records within
one packet.

**LibreSSL 3.5+ specific notes:**

- LibreSSL 3.5 significantly improved TLS 1.3 record processing stability.
  Earlier versions (3.3, 3.4) had edge cases with record reassembly that
  could cause spurious `SSL_ERROR_WANT_READ` even with complete records
  in the BIO.
- The `BIO_meth_*` API has been available since LibreSSL 2.8 (2018) and is
  stable. Custom BIO methods work identically to OpenSSL.
- LibreSSL does not support `SSL_set_read_ahead()` in a meaningful way for
  custom BIOs. The library reads exactly what it needs from the BIO and no
  more. This means the drain loop relies entirely on multiple TLS records
  being present in the ring buffer, not on read-ahead pulling them into
  the SSL internal buffer.

## Unified Progressive SSL_read

The following template works across all three libraries. It is parameterised
on the SSL policy type and compiles with no overhead for the pre-check
(the ring buffer walk is inline).

```cpp
template<typename SSLPolicy>
int32_t process_ssl_read_progressive(SSLPolicy& ssl, MsgInbox* inbox,
                                     timing_record_t& timing) {
    // Phase 1: Pre-check encrypted data availability
    size_t enc_avail = ssl.encrypted_bytes_available();
    if (enc_avail < TLS_RECORD_HEADER) {
        return 0;
    }

    // Phase 2: Record-aware gating
    uint8_t hdr[TLS_RECORD_HEADER];
    if (!ssl.peek_encrypted(hdr, TLS_RECORD_HEADER)) {
        return 0;
    }
    uint16_t record_payload_len = (static_cast<uint16_t>(hdr[3]) << 8) | hdr[4];
    size_t total_needed = TLS_RECORD_HEADER + record_payload_len;

    if (enc_avail < total_needed) {
        return 0;  // partial record
    }

    // Phase 3: SSL_read -- guaranteed to succeed (no WANT_READ)
    uint32_t write_pos = inbox->current_write_pos();
    uint32_t linear_space = MSG_INBOX_SIZE - write_pos;
    if (linear_space > 16384) linear_space = 16384;

    timing.recv_start_cycle = rdtsc();
    ssize_t total = ssl.read(inbox->write_ptr(), linear_space);
    timing.recv_end_cycle = rdtscp();

    if (total <= 0) {
        return (total < 0 && errno != EAGAIN) ? -1 : 0;
    }

    // Phase 4: Drain loop -- consume any additional buffered plaintext
    while (ssl.pending() > 0) {
        uint32_t remaining = linear_space - static_cast<uint32_t>(total);
        if (remaining == 0) break;
        ssize_t more = ssl.read(
            static_cast<uint8_t*>(inbox->write_ptr()) + total, remaining);
        if (more <= 0) break;
        total += more;
    }

    inbox->advance_write(static_cast<uint32_t>(total));
    return static_cast<int32_t>(total);
}
```

## Required Policy Additions

Each SSL policy (`WolfSSLPolicy`, `OpenSSLPolicy`, `LibreSSLPolicy`) needs
two new methods to support progressive reads. These are implemented
identically since all three use the same `ViewSegment` ring buffer:

```cpp
// Add to each policy struct:

size_t encrypted_bytes_available() const {
    size_t avail = 0;
    size_t tail = in_view_tail_;
    size_t pos = in_view_pos_;
    while (tail != in_view_head_) {
        avail += in_views_[tail & VIEW_RING_MASK].len;
        tail++;
    }
    if (in_view_tail_ != in_view_head_) {
        avail -= in_view_pos_;
    }
    return avail;
}

bool peek_encrypted(uint8_t* out, size_t n) const {
    size_t copied = 0;
    size_t tail = in_view_tail_;
    size_t pos = in_view_pos_;
    while (copied < n && tail != in_view_head_) {
        const auto& seg = in_views_[tail & VIEW_RING_MASK];
        size_t avail = seg.len - pos;
        size_t to_copy = (n - copied < avail) ? (n - copied) : avail;
        __builtin_memcpy(out + copied, seg.data + pos, to_copy);
        copied += to_copy;
        pos += to_copy;
        if (pos >= seg.len) { tail++; pos = 0; }
    }
    return copied == n;
}
```

These two methods are pure reads of the ring buffer with no side effects.
They do not advance `in_view_tail_` or `in_view_pos_`.

## Performance Characteristics

| Metric | Standard SSL_read | Progressive SSL_read |
|---|---|---|
| Wasted iterations (WANT_READ) | ~95% of poll loops | 0% (gated by pre-check) |
| Cost per empty iteration | 100-300ns (library overhead) | <10ns (ring buffer size check) |
| Burst handling | 1 record per SSL_read call | All buffered records drained |
| Ring buffer peek overhead | N/A | 5-byte memcpy + 2 comparisons |

The pre-check is branch-predicted as "not taken" in steady state since
data arrives in bursts separated by idle periods. The record-aware gate
is only evaluated when encrypted data is present, which is the case where
SSL_read would succeed anyway.

## Edge Cases

**Fragmented TLS records across TCP segments**: A single TLS record can
span multiple TCP segments (packets). The ring buffer accumulates views
from multiple packets. The record-aware gate correctly handles this by
comparing total available bytes against the record length from the header.

**Multiple TLS records in a single TCP segment**: Common when the server
batches small messages. The first SSL_read decrypts the first record, and
the drain loop with `pending()` handles subsequent records that the library
consumed from the BIO during the first read.

**TLS 1.3 inner content type**: The outer record header always shows
CT=0x17 (Application Data) for TLS 1.3. The progressive approach only
needs the outer header for gating -- the inner content type is handled
by the library during decryption and does not affect the pre-check.

**Renegotiation / KeyUpdate**: TLS 1.3 uses KeyUpdate messages (CT=0x17
in the outer header, with an inner handshake content type). These are
transparent to the progressive approach since the outer header length
field still correctly indicates the record size. The library handles
key rotation internally during `SSL_read()`.

---

## Direct AES-CTR Decryption (`ssl_read_by_chunk`)

### Overview

`ssl_read_by_chunk()` bypasses `SSL_read()` entirely for application data
records, performing AES-CTR decryption directly via AES-NI intrinsics.
This eliminates all SSL library overhead (state machine, GHASH
verification, BIO dispatch) from the hot path.

GCM is CTR mode + GHASH authentication. By skipping GHASH tag
verification, the decryption reduces to pure AES-CTR XOR operations
on the ciphertext payload.

### Architecture

```
ssl_read_by_chunk(dest, chunk_size, callback)
    │
    ├── TLS Record Parser (state machine in TLSRecordParser)
    │   ├── NEED_HEADER:  peek 5B header, derive nonce, skip non-0x17 records
    │   ├── NEED_PAYLOAD: decrypt available blocks via AES-CTR, call callback
    │   └── NEED_TAG:     skip 16B AEAD tag (not verified)
    │
    ├── AESCTRDecryptor (src/core/aes_ctr.hpp)
    │   ├── 8-block pipelined loop (128B) — saturates AES-NI
    │   ├── Single-block loop (16B)
    │   └── Partial block (final bytes)
    │
    └── ZeroCopyReceiveBuffer peek()/skip()
        └── Non-destructive read + deferred frame release
```

### Key Extraction

Keys are extracted once after TLS handshake via `ssl_policy.extract_record_keys()`:

| Library | Method |
|---|---|
| WolfSSL | `wolfSSL_get_keys()` — direct access to internal key material |
| OpenSSL | `SSL_CTX_set_keylog_callback()` + HKDF-Expand-Label for TLS 1.3 |
| LibreSSL 3.5+ | Same keylog callback as OpenSSL |
| NoSSL | Returns false (no encryption) |

The extracted `TLSRecordKeys` struct contains the AES key, 12-byte IV,
and pre-expanded AES round keys (computed once per connection).

### Nonce Derivation

- **TLS 1.3**: `nonce[i] = iv[i] XOR pad_left_64(seq_num, 12)[i]`
- **TLS 1.2**: `nonce = implicit_iv(4B) || explicit_nonce(8B from record)`

### Chunked Callback

```cpp
transport_.ssl_read_by_chunk(dest, chunk_size,
    [&](const uint8_t* data, size_t len) {
        // Process decrypted chunk immediately
    });
```

The callback fires for each chunk as soon as complete AES blocks (16
bytes) arrive. When available ciphertext < `chunk_size` but >= 16 bytes,
decrypts what's available rather than waiting for a full chunk.

### Files

| File | Purpose |
|---|---|
| `src/core/aes_ctr.hpp` | AES-CTR decryptor, TLSRecordKeys, nonce derivation |
| `src/stack/tcp/tcp_retransmit.hpp` | `peek()` and `skip()` on ZeroCopyReceiveBuffer |
| `src/policy/transport.hpp` | `ssl_read_by_chunk()`, TLSRecordParser state machine |
| `src/policy/ssl.hpp` | `extract_record_keys()` on each SSL policy |

### Edge Cases

| Case | Handling |
|---|---|
| Fragmented record across TCP segments | State machine persists in `tls_parser_`; resumes on next call |
| Available < 16 bytes mid-record | Return, wait for next packet to bring more data |
| Non-AES-GCM cipher (ChaCha20) | `extract_record_keys()` returns false; caller falls back to `ssl_.read()` |
| TLS 1.3 KeyUpdate | Inner content type != 0x17; detected after final chunk, not passed to callback |
| TLS 1.2 explicit nonce split | Handled in NEED_HEADER state; waits for 8 bytes after header consumed |
| Non-application-data records | Skipped entirely (seq_num still incremented) |
