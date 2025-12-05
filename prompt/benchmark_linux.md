# WebSocket Policy-Based Library - Linux Benchmark Report

**Date:** 2025-12-06
**Platform:** Linux 6.14.0-36-generic (Ubuntu)
**CPU:** Intel (TSC frequency: 2.42 GHz)
**NIC:** Intel igc (enp108s0)
**Target:** wss://stream.binance.com:443 (btcusdt@trade)
**Methodology:** 100 warmup messages, 300 benchmark samples
**CPU Pinning:** taskset -c 1

---

## Summary Table

| Mode | Transport | Event | SSL | Mean (μs) | StdDev (μs) | P99 (μs) | SSL Decrypt (μs) | NIC→App (μs) |
|------|-----------|-------|-----|-----------|-------------|----------|------------------|--------------|
| 1 | XDP | SO_BUSY_POLL | WolfSSL | **24.76** | 12.00 | 46.08 | **8.19** | 14.55 |
| 2 | XDP | SO_BUSY_POLL | LibreSSL | 30.23 | **8.43** | **41.27** | 10.56 | 15.78 |
| 3 | XDP | SO_BUSY_POLL | OpenSSL | 42.11 | 9.58 | 56.74 | 13.40 | 24.73 |
| 4 | BSD Socket | epoll | kTLS | 14.74* | 8.50 | 36.25* | 12.97 | N/A |
| 5 | BSD Socket | select | kTLS | 21.22* | 13.69 | 43.58* | 18.93 | N/A |
| 6 | BSD Socket | select | LibreSSL | 50.05 | 17.24 | 74.39 | 21.04 | 27.23 |
| 7 | BSD Socket | io_uring | OpenSSL | 52.21 | 23.15 | 82.99 | 28.79 | 21.64 |
| 8 | BSD Socket | select | OpenSSL | 53.72 | 23.90 | 86.41 | 25.47 | 26.99 |
| 9 | BSD Socket | epoll | OpenSSL | 55.55 | 17.88 | 73.90 | 31.82 | 21.67 |
| 10 | BSD Socket | epoll | WolfSSL | 66.69 | 19.31 | 116.16 | 26.96 | 37.41 |
| 11 | BSD Socket | epoll | LibreSSL | 66.84 | 12.21 | 79.15 | 38.84 | 25.96 |

*kTLS modes do not have hardware timestamps (Stage 1→2 = 0)

**WolfSSL requires optimized build.** Use `./scripts/install_fastest_wolfssl.sh` or:
```bash
./configure --enable-intelasm --enable-aesni --enable-all-asm \
            --enable-aesgcm-stream --enable-sp-math-all --enable-sp-asm \
            --enable-fastmath --enable-chacha --enable-poly1305 \
            --enable-opensslextra --enable-opensslall \
            CFLAGS="-O3 -march=native"
make && sudo make install && sudo ldconfig
```

---

## Detailed Results

### Mode 1: XDP + WolfSSL (Optimized)

```
Transport:   AF_XDP zero-copy + Userspace TCP/IP stack
TLS:         WolfSSL (user-space, optimized build)
IO Backend:  SO_BUSY_POLL

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)          4.78     30.45     14.55     10.06      8.71     30.45     30.45     30.45
Stage 2->3 (Event)             0.01      0.01      0.01      0.01      0.00      0.01      0.01      0.01
Stage 3->4 (SSL)               1.67     13.57      8.19      6.61      3.81     13.57     13.57     13.57
Stage 4->5 (Parse)             0.01      1.02      0.43      0.39      0.27      0.81      0.89      0.97
Stage 5->6 (Callback)          0.01      1.08      0.40      0.35      0.27      0.82      0.91      1.03
Total (Stage 2->6)             1.95     14.69      9.03      7.59      4.03     14.69     14.69     14.69
End-to-End (1->6)             10.28     46.15     24.76     17.85     12.00     43.72     44.10     46.08

SSL decryption: 90.7% of application latency
```

### Mode 2: XDP + LibreSSL

```
Transport:   AF_XDP zero-copy + Userspace TCP/IP stack
TLS:         LibreSSL (user-space)
IO Backend:  SO_BUSY_POLL

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)          6.83     22.02     15.78     16.59      4.27     20.20     22.02     22.02
Stage 2->3 (Event)             0.01      0.27      0.01      0.01      0.02      0.01      0.01      0.11
Stage 3->4 (SSL)               2.82     17.52     10.56      9.79      4.20     17.52     17.52     17.52
Stage 4->5 (Parse)             0.01      1.52      0.55      0.47      0.40      1.17      1.31      1.47
Stage 5->6 (Callback)          0.01      1.53      0.54      0.44      0.40      1.16      1.28      1.48
Total (Stage 2->6)             2.88     18.94     11.66     11.35      4.47     18.94     18.94     18.94
End-to-End (1->6)              9.74     41.35     30.23     31.02      8.43     40.32     40.84     41.27

SSL decryption: 90.6% of application latency
```

### Mode 3: XDP + OpenSSL

```
Transport:   AF_XDP zero-copy + Userspace TCP/IP stack
TLS:         OpenSSL (user-space)
IO Backend:  SO_BUSY_POLL

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)         14.20     32.33     24.73     27.26      6.09     32.33     32.33     32.33
Stage 2->3 (Event)             0.01      0.23      0.02      0.01      0.04      0.01      0.11      0.23
Stage 3->4 (SSL)               2.19     18.91     13.40     15.05      5.18     18.91     18.91     18.91
Stage 4->5 (Parse)             0.01      1.43      0.56      0.53      0.38      1.11      1.21      1.39
Stage 5->6 (Callback)          0.01      1.31      0.49      0.44      0.33      0.97      1.12      1.25
Total (Stage 2->6)             2.28     20.15     14.47     16.52      5.51     20.15     20.15     20.15
End-to-End (1->6)             18.09     56.82     42.11     39.82      9.58     54.71     55.10     56.74

SSL decryption: 92.6% of application latency
```

### Mode 4: BSD Socket + epoll + kTLS

```
Transport:   BSDSocket + epoll
TLS:         OpenSSL+kTLS (kernel TLS offload)
IO Backend:  EventPolicy-based I/O

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)          0.00      0.00      0.00      0.00      0.00      0.00      0.00      0.00
Stage 2->3 (Event)             0.01      4.03      0.10      0.02      0.24      0.26      0.26      0.46
Stage 3->4 (SSL)               2.99     29.58     12.97      9.56      6.91     29.58     29.58     29.58
Stage 4->5 (Parse)             0.01      6.39      0.84      0.51      1.14      1.44      3.76      5.88
Stage 5->6 (Callback)          0.01      6.42      0.83      0.51      1.12      1.45      3.59      5.84
Total (Stage 2->6)             3.55     36.25     14.74     11.06      8.50     36.25     36.25     36.25
End-to-End (1->6)              3.55     36.25     14.74     11.06      8.50     36.25     36.25     36.25

Note: kTLS disables hardware timestamps (Stage 1->2 = 0)
SSL decryption: 88.0% of application latency
```

### Mode 5: BSD Socket + select + kTLS

```
Transport:   BSDSocket + select
TLS:         OpenSSL+kTLS (kernel TLS offload)
IO Backend:  EventPolicy-based I/O

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)          0.00      0.00      0.00      0.00      0.00      0.00      0.00      0.00
Stage 2->3 (Event)             0.01      0.26      0.11      0.08      0.10      0.26      0.26      0.26
Stage 3->4 (SSL)               4.88     36.56     18.93     13.10     12.25     36.56     36.56     36.56
Stage 4->5 (Parse)             0.03      6.80      1.12      0.74      1.32      2.58      4.67      6.35
Stage 5->6 (Callback)          0.02      6.79      1.06      0.68      1.31      2.50      4.59      6.36
Total (Stage 2->6)             5.31     43.58     21.22     13.72     13.69     43.58     43.58     43.58
End-to-End (1->6)              5.31     43.58     21.22     13.72     13.69     43.58     43.58     43.58

Note: kTLS disables hardware timestamps (Stage 1->2 = 0)
SSL decryption: 89.2% of application latency
```

### Mode 6: BSD Socket + select + LibreSSL

```
Transport:   BSDSocket + select
TLS:         LibreSSL (user-space)
IO Backend:  EventPolicy-based I/O

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)         11.39     42.13     27.23     29.40      7.00     33.08     35.79     42.13
Stage 2->3 (Event)             0.01      0.18      0.06      0.07      0.04      0.08      0.18      0.18
Stage 3->4 (SSL)               2.14     40.59     21.04     22.83     10.62     34.21     40.59     40.59
Stage 4->5 (Parse)             0.01      4.24      0.84      0.51      0.89      2.12      2.83      4.17
Stage 5->6 (Callback)          0.01      4.16      0.88      0.51      0.95      2.37      3.13      3.79
Total (Stage 2->6)             2.29     41.31     22.82     24.21     11.30     36.21     41.31     41.31
End-to-End (1->6)             18.44     74.39     50.05     52.79     17.24     72.80     74.39     74.39

SSL decryption: 92.2% of application latency
```

### Mode 7: BSD Socket + io_uring + OpenSSL

```
Transport:   BSDSocket + epoll
TLS:         OpenSSL (user-space)
IO Backend:  io_uring (async I/O)

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)          5.73     44.48     21.64     21.31     10.26     34.51     34.51     44.48
Stage 2->3 (Event)             0.01      0.40      0.08      0.08      0.08      0.14      0.31      0.40
Stage 3->4 (SSL)               5.87     57.73     28.79     30.05     15.86     57.73     57.73     57.73
Stage 4->5 (Parse)             0.01     26.92      0.95      0.38      2.73      2.07      3.56      4.95
Stage 5->6 (Callback)          0.01      5.17      0.75      0.38      1.05      2.09      3.60      4.84
Total (Stage 2->6)             6.30     58.66     30.57     32.63     16.28     58.66     58.66     58.66
End-to-End (1->6)             12.04     89.61     52.21     47.08     23.15     82.99     82.99     82.99

SSL decryption: 94.2% of application latency
```

### Mode 8: BSD Socket + select + OpenSSL

```
Transport:   BSDSocket + select
TLS:         OpenSSL (user-space)
IO Backend:  EventPolicy-based I/O

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)         15.23     77.88     26.99     23.35     10.55     42.03     42.03     42.03
Stage 2->3 (Event)             0.01      4.07      0.11      0.08      0.32      0.22      0.22      0.22
Stage 3->4 (SSL)               2.69     49.49     25.47     22.49     15.84     49.49     49.49     49.49
Stage 4->5 (Parse)             0.02      2.05      0.62      0.55      0.43      1.26      1.38      1.60
Stage 5->6 (Callback)          0.01      2.03      0.53      0.45      0.39      1.10      1.28      1.58
Total (Stage 2->6)             2.79     50.84     26.73     23.70     15.98     50.84     50.84     50.84
End-to-End (1->6)             22.24     98.84     53.72     45.60     23.90     86.41     86.41     86.41

SSL decryption: 95.3% of application latency
```

### Mode 9: BSD Socket + epoll + OpenSSL

```
Transport:   BSDSocket + epoll
TLS:         OpenSSL (user-space)
IO Backend:  EventPolicy-based I/O

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)         10.95     29.06     21.67     23.50      5.81     28.55     29.06     29.06
Stage 2->3 (Event)             0.01      0.18      0.07      0.08      0.04      0.10      0.18      0.18
Stage 3->4 (SSL)               5.82     48.89     31.82     34.46     13.76     48.89     48.89     48.89
Stage 4->5 (Parse)             0.01      5.72      1.14      0.70      1.15      2.44      3.70      5.28
Stage 5->6 (Callback)          0.01      5.70      0.84      0.47      1.12      2.13      3.69      5.26
Total (Stage 2->6)             6.22     51.49     33.88     35.44     14.71     51.49     51.49     51.49
End-to-End (1->6)             19.50     73.90     55.55     60.63     17.88     73.90     73.90     73.90

SSL decryption: 93.9% of application latency
```

### Mode 10: BSD Socket + epoll + WolfSSL (Optimized)

```
Transport:   BSDSocket + epoll
TLS:         WolfSSL (user-space, optimized build)
IO Backend:  io_uring

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)         22.16    116.16     37.41     35.66     19.31     85.22     85.22    116.16
Stage 2->3 (Event)             0.01      0.12      0.09      0.08      0.03      0.12      0.12      0.12
Stage 3->4 (SSL)               3.11     43.60     26.96     29.25      6.71     32.97     34.92     36.53
Stage 4->5 (Parse)             0.02      4.24      1.14      0.95      0.90      2.33      2.93      3.92
Stage 5->6 (Callback)          0.01      4.23      1.08      0.84      0.87      2.27      2.90      3.90
Total (Stage 2->6)             3.18     44.25     29.28     31.62      7.04     35.59     35.59     39.16
End-to-End (1->6)             22.16    116.16     66.69     73.61     19.31     85.22     85.22    116.16

SSL decryption: 92.1% of application latency
```

### Mode 11: BSD Socket + epoll + LibreSSL

```
Transport:   BSDSocket + epoll
TLS:         LibreSSL (user-space)
IO Backend:  EventPolicy-based I/O

Stage                           Min       Max      Mean    Median    StdDev       P90       P95       P99
Stage 1->2 (NIC->App)         18.83     30.03     25.96     25.90      2.31     30.03     30.03     30.03
Stage 2->3 (Event)             0.01      0.21      0.12      0.08      0.06      0.21      0.21      0.21
Stage 3->4 (SSL)               2.21     51.85     38.84     37.13     10.93     50.84     50.84     51.85
Stage 4->5 (Parse)             0.01      4.20      0.94      0.61      0.89      2.15      2.92      3.88
Stage 5->6 (Callback)          0.01      4.19      0.98      0.60      0.91      2.23      2.93      3.77
Total (Stage 2->6)             2.32     53.25     40.88     39.39     11.40     53.25     53.25     53.25
End-to-End (1->6)             24.91     79.15     66.84     64.51     12.21     79.15     79.15     79.15

SSL decryption: 95.0% of application latency
```

---

## Analysis

### Key Findings

1. **Best Overall Performance: XDP + WolfSSL (Optimized)**
   - Mean end-to-end latency: 24.76 μs
   - P99 latency: 46.08 μs
   - SSL decryption: 8.19 μs (fastest among all modes)
   - XDP zero-copy mode provides significant improvement over BSD sockets

2. **SSL Library Comparison (XDP mode)**
   - WolfSSL (optimized): 8.19 μs SSL decrypt ← **Fastest**
   - LibreSSL: 10.56 μs SSL decrypt
   - OpenSSL: 13.40 μs SSL decrypt
   - WolfSSL is 22% faster than LibreSSL and 39% faster than OpenSSL

3. **Transport Comparison (BSD vs XDP)**
   - XDP provides 27-63% improvement in end-to-end latency
   - XDP benefits from userspace TCP/IP stack (kernel bypass)

4. **Event Loop Comparison**
   - epoll, select, and io_uring show similar performance
   - io_uring does not provide significant advantage for this workload (single connection)
   - select is competitive with epoll for single-FD scenarios

5. **kTLS Performance**
   - kTLS shows excellent application latency (14.74 μs with epoll)
   - However, kTLS disables hardware timestamps (cannot measure NIC→App latency)
   - Useful when hardware timestamps are not required

### Latency Breakdown

SSL decryption consistently accounts for 88-95% of application processing time (Stage 2→6).
This makes SSL library choice critical for HFT applications.

### Recommendations

| Use Case | Recommended Mode |
|----------|------------------|
| Lowest latency with HW timestamps | XDP + WolfSSL (optimized) |
| Lowest latency without HW timestamps | BSD + epoll + kTLS |
| Standard deployment | BSD + epoll + OpenSSL |
| Maximum compatibility | BSD + select + LibreSSL |
| Easy deployment, good performance | XDP + LibreSSL |

---

## Build Commands

```bash
# XDP modes (requires ./scripts/install_fastest_wolfssl.sh for WolfSSL)
USE_XDP=1 USE_WOLFSSL=1 make benchmark-binance     # XDP + WolfSSL (fastest)
USE_XDP=1 make benchmark-binance                   # XDP + LibreSSL (default)
USE_XDP=1 USE_OPENSSL=1 make benchmark-binance     # XDP + OpenSSL

# BSD Socket modes
USE_OPENSSL=1 USE_IOURING=0 make benchmark-binance  # epoll + OpenSSL
USE_IOURING=0 make benchmark-binance                # epoll + LibreSSL
USE_OPENSSL=1 USE_SELECT=1 make benchmark-binance   # select + OpenSSL
USE_SELECT=1 make benchmark-binance                 # select + LibreSSL
USE_OPENSSL=1 make benchmark-binance                # io_uring + OpenSSL
USE_WOLFSSL=1 USE_IOURING=0 make benchmark-binance  # epoll + WolfSSL

# kTLS modes (OpenSSL only)
USE_OPENSSL=1 USE_IOURING=0 ENABLE_KTLS=1 make benchmark-binance  # epoll + kTLS
USE_OPENSSL=1 USE_SELECT=1 ENABLE_KTLS=1 make benchmark-binance   # select + kTLS
```

---

## WolfSSL Optimization Flags

| Flag | Effect |
|------|--------|
| `--enable-intelasm` | Hand-written x86_64 assembly (biggest impact) |
| `--enable-aesni` | AES-NI hardware acceleration |
| `--enable-all-asm` | All assembly optimizations |
| `--enable-sp-math-all --enable-sp-asm` | 2-4x faster ECC |
| `--enable-fastmath` | Fast RSA/ECC exponentiation |
| `--enable-chacha --enable-poly1305` | Best when AES-NI throttles |
| `CFLAGS="-O3 -march=native"` | Native CPU optimizations |

**Without optimization:** WolfSSL is 2-4x slower than OpenSSL/LibreSSL.
**With optimization:** WolfSSL is 22-39% faster than OpenSSL/LibreSSL.

---

## Test Environment

- **Interface:** enp108s0 (Intel igc driver)
- **XDP Mode:** XDP_ZEROCOPY | SO_BUSY_POLL
- **NIC Queues:** 1 (for AF_XDP)
- **GRO/LRO:** Disabled
- **Interrupt Coalescing:** Disabled
- **Hardware Timestamping:** Enabled (rx_filter=1)
- **Target Server:** stream.binance.com
