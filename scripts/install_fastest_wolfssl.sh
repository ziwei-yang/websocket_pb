#!/bin/bash
# install_fastest_wolfssl.sh - Build and install WolfSSL with maximum performance
#
# Performance flags explanation:
# | Flag                                   | Why                                            |
# |----------------------------------------|------------------------------------------------|
# | --enable-intelasm                      | THIS is the big one - enables hand-written ASM |
# | --enable-aesni                         | Uses AES-NI hardware instructions              |
# | --enable-all-asm                       | Enable all applicable assembly accelerations   |
# | --enable-sp-math-all + --enable-sp-asm | 2x-4x faster ECC with Single Precision math    |
# | --enable-fastmath                      | RSA/ECC exponentiation speed                   |
# | --enable-aesgcm-stream                 | Streaming AES-GCM for TLS                      |
# | --enable-chacha --enable-poly1305      | Best when AES-NI throttles                     |
# | --enable-opensslextra --enable-opensslall | OpenSSL compatibility layer                 |
# | CFLAGS=-O3 -march=native               | Forces usage of VAES/ADX if available          |
#
# Future flags (WolfSSL 5.7+):
# | --enable-vaes                          | Vector AES (VAES > AES-NI)                     |
# | --enable-vpclmulqdq                    | Fastest AES-GCM                                |
# | --enable-sha-ni                        | SHA-NI hardware acceleration                   |
#

set -e

WOLFSSL_VERSION="${WOLFSSL_VERSION:-5.7.6-stable}"
BUILD_DIR="${BUILD_DIR:-/tmp/wolfssl-opt}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"

echo "=== WolfSSL Optimized Build Script ==="
echo "Version: $WOLFSSL_VERSION"
echo "Build dir: $BUILD_DIR"
echo "Install prefix: $INSTALL_PREFIX"
echo ""

# Check CPU features
echo "=== CPU Features ==="
if grep -q aes /proc/cpuinfo 2>/dev/null; then
    echo "  AES-NI: supported"
else
    echo "  AES-NI: NOT supported"
fi
if grep -q avx2 /proc/cpuinfo 2>/dev/null; then
    echo "  AVX2: supported"
else
    echo "  AVX2: NOT supported"
fi
if grep -q vaes /proc/cpuinfo 2>/dev/null; then
    echo "  VAES: supported"
else
    echo "  VAES: NOT supported (or older CPU)"
fi
if grep -q sha_ni /proc/cpuinfo 2>/dev/null; then
    echo "  SHA-NI: supported"
else
    echo "  SHA-NI: NOT supported (or older CPU)"
fi
echo ""

# Download WolfSSL if not already present
if [ ! -d "$BUILD_DIR" ]; then
    echo "=== Downloading WolfSSL $WOLFSSL_VERSION ==="
    mkdir -p "$BUILD_DIR"
    cd /tmp
    if [ ! -f "wolfssl-${WOLFSSL_VERSION}.tar.gz" ]; then
        wget -q "https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL_VERSION}.tar.gz" \
            -O "wolfssl-${WOLFSSL_VERSION}.tar.gz" || {
            echo "Download failed, trying alternate URL..."
            wget -q "https://github.com/wolfSSL/wolfssl/archive/refs/tags/${WOLFSSL_VERSION}.tar.gz" \
                -O "wolfssl-${WOLFSSL_VERSION}.tar.gz"
        }
    fi
    tar xzf "wolfssl-${WOLFSSL_VERSION}.tar.gz" -C "$BUILD_DIR" --strip-components=1
fi

cd "$BUILD_DIR"

# Run autoreconf if needed
if [ ! -f configure ] || [ configure.ac -nt configure ]; then
    echo "=== Running autoreconf ==="
    autoreconf -fi
fi

# Configure with all performance flags
echo "=== Configuring WolfSSL with performance flags ==="

# Base flags that work on all versions
CONFIGURE_FLAGS=(
    --enable-intelasm
    --enable-aesni
    --enable-all-asm
    --enable-aesgcm-stream
    --enable-sp-math-all
    --enable-sp-asm
    --enable-fastmath
    --enable-chacha
    --enable-poly1305
    --enable-opensslextra
    --enable-opensslall
    --enable-intelrand
    --prefix="$INSTALL_PREFIX"
)

# Try newer flags if available (WolfSSL 5.7+)
EXTRA_FLAGS=""
if ./configure --help 2>/dev/null | grep -q -- "--enable-vaes"; then
    EXTRA_FLAGS="$EXTRA_FLAGS --enable-vaes"
    echo "  Adding --enable-vaes (VAES support detected)"
fi
if ./configure --help 2>/dev/null | grep -q -- "--enable-vpclmulqdq"; then
    EXTRA_FLAGS="$EXTRA_FLAGS --enable-vpclmulqdq"
    echo "  Adding --enable-vpclmulqdq (VPCLMULQDQ support detected)"
fi
if ./configure --help 2>/dev/null | grep -q -- "--enable-sha-ni"; then
    EXTRA_FLAGS="$EXTRA_FLAGS --enable-sha-ni"
    echo "  Adding --enable-sha-ni (SHA-NI support detected)"
fi

./configure "${CONFIGURE_FLAGS[@]}" $EXTRA_FLAGS CFLAGS="-O3 -march=native -w"

# Build
echo ""
echo "=== Building WolfSSL ==="
make -j$(nproc) clean 2>/dev/null || true
make -j$(nproc)

# Install
echo ""
echo "=== Installing WolfSSL ==="
sudo make install
sudo ldconfig

# Verify installation
echo ""
echo "=== Verifying Installation ==="
if [ -f "$INSTALL_PREFIX/lib/libwolfssl.so" ]; then
    echo "  Library: $INSTALL_PREFIX/lib/libwolfssl.so"
    ls -la "$INSTALL_PREFIX/lib/libwolfssl.so"*
else
    echo "  ERROR: Library not found!"
    exit 1
fi

if [ -f "$INSTALL_PREFIX/include/wolfssl/ssl.h" ]; then
    echo "  Headers: $INSTALL_PREFIX/include/wolfssl/"
else
    echo "  ERROR: Headers not found!"
    exit 1
fi

echo ""
echo "=== WolfSSL Installation Complete ==="
echo ""
echo "To use with this project:"
echo "  USE_WOLFSSL=1 make clean all"
echo ""
echo "To benchmark:"
echo "  USE_WOLFSSL=1 make benchmark-binance"
echo ""
