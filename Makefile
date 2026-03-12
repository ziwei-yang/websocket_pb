# Makefile for WebSocket Policy-Based Library
# Supports: Linux (epoll, io_uring) and macOS (kqueue)

CXX := g++
CXXFLAGS := -std=c++20 -O3 -march=native -Wall -Wextra -I./src -I../01_shared_headers
LDFLAGS :=

# Debug mode - enables verbose debug prints
ifdef DEBUG
    CXXFLAGS += -DDEBUG
endif

# Multi-connection mode (MAX_CONN=N, default 1)
ifdef MAX_CONN
    CXXFLAGS += -DMAX_CONN=$(MAX_CONN)
endif

# Auto-reconnect mode
ifdef ENABLE_RECONNECT
    CXXFLAGS += -DENABLE_RECONNECT
endif

# Build directory
BUILD_DIR := ./build
TEST_DIR := ./test/unittest
INTEGRATION_DIR := ./test/integration

# Detect platform
UNAME_S := $(shell uname -s)

# ============================================================================
# Platform-specific settings
# ============================================================================

ifeq ($(UNAME_S),Linux)
    # Linux configuration
    CXXFLAGS += -D__linux__

    # Check for available libraries
    HAS_IOURING := $(shell echo "int main(){}" | gcc -x c - -luring -o /dev/null 2>/dev/null && echo 1 || echo 0)

    # ============================================================================
    # Custom SSL Library Paths (~/Proj/)
    # ============================================================================
    CUSTOM_LIBRESSL_DIR := $(HOME)/Proj/libressl/install
    CUSTOM_OPENSSL_DIR := $(HOME)/Proj/openssl/install
    CUSTOM_WOLFSSL_DIR := $(HOME)/Proj/wolfssl/install

    # SSL Policy Selection - Always use custom libraries from ~/Proj/
    ifdef USE_WOLFSSL
        ifeq ($(wildcard $(CUSTOM_WOLFSSL_DIR)/include/wolfssl),)
            $(error WolfSSL not found at $(CUSTOM_WOLFSSL_DIR). Please build and install WolfSSL to ~/Proj/wolfssl/install/)
        endif
        CXXFLAGS += -DUSE_WOLFSSL -DHAVE_WOLFSSL -I$(CUSTOM_WOLFSSL_DIR)/include
        LDFLAGS += -L$(CUSTOM_WOLFSSL_DIR)/lib -Wl,-rpath,$(CUSTOM_WOLFSSL_DIR)/lib -lwolfssl
        SSL_INFO := WolfSSL ($(CUSTOM_WOLFSSL_DIR))
    else ifdef USE_OPENSSL
        ifeq ($(wildcard $(CUSTOM_OPENSSL_DIR)/include/openssl),)
            $(error OpenSSL not found at $(CUSTOM_OPENSSL_DIR). Please build and install OpenSSL to ~/Proj/openssl/install/)
        endif
        CXXFLAGS += -DUSE_OPENSSL -I$(CUSTOM_OPENSSL_DIR)/include
        LDFLAGS += -L$(CUSTOM_OPENSSL_DIR)/lib64 -Wl,-rpath,$(CUSTOM_OPENSSL_DIR)/lib64 -lssl -lcrypto
        SSL_INFO := OpenSSL ($(CUSTOM_OPENSSL_DIR))
    else
        # Default: LibreSSL
        ifeq ($(wildcard $(CUSTOM_LIBRESSL_DIR)/include/openssl),)
            $(error LibreSSL not found at $(CUSTOM_LIBRESSL_DIR). Please build and install LibreSSL to ~/Proj/libressl/install/)
        endif
        CXXFLAGS += -DUSE_LIBRESSL -I$(CUSTOM_LIBRESSL_DIR)/include
        LDFLAGS += -L$(CUSTOM_LIBRESSL_DIR)/lib -Wl,-rpath,$(CUSTOM_LIBRESSL_DIR)/lib -lssl -lcrypto
        SSL_INFO := LibreSSL ($(CUSTOM_LIBRESSL_DIR))
    endif

    # kTLS Support (Linux only, OpenSSL only)
    ifdef ENABLE_KTLS
        CXXFLAGS += -DENABLE_KTLS
        SSL_INFO := $(SSL_INFO)+kTLS
    endif

    # HftShm Shared Memory Support
    ifdef USE_HFTSHM
        CXXFLAGS += -DUSE_HFTSHM -std=c++20
        $(info Building with HftShm shared memory buffer support)
    endif

    # IO Backend Selection
    ifdef USE_SELECT
        CXXFLAGS += -DUSE_SELECT
        IO_INFO := select
    else ifneq ($(USE_IOURING),0)
        # Try io_uring
        ifeq ($(HAS_IOURING),1)
            CXXFLAGS += -DENABLE_IO_URING
            LDFLAGS += -luring
            IO_INFO := io_uring
        else
            IO_INFO := epoll (iouring not available)
        endif
    else
        IO_INFO := epoll
    endif

    # Transport Layer Selection
    # Note: These are mutually exclusive - only one can be active at a time

    # Auto-enable USE_XDP if XDP_INTERFACE is provided (but not when USE_DPDK is set)
    ifdef XDP_INTERFACE
        ifndef USE_DPDK
            USE_XDP := 1
        endif
    endif

    # DPDK Support (Linux only)
    ifdef USE_DPDK
        ifdef USE_XDP
            $(error Cannot use both USE_DPDK=1 and USE_XDP=1 simultaneously)
        endif
        ifdef USE_SOCKET
            $(error Cannot use both USE_DPDK=1 and USE_SOCKET=1 simultaneously)
        endif
        HAS_LIBDPDK := $(shell pkg-config --exists libdpdk && echo 1 || echo 0)
        ifeq ($(HAS_LIBDPDK),1)
            CXXFLAGS += -DUSE_DPDK $(shell pkg-config --cflags libdpdk)
            LDFLAGS += $(shell pkg-config --libs libdpdk)
            TRANSPORT_INFO := DPDK (PMD)
            ifndef DPDK_INTERFACE
                DPDK_INTERFACE := enp108s0
            endif
            CXXFLAGS += -DDPDK_INTERFACE='"$(DPDK_INTERFACE)"'
            $(info DPDK Interface: $(DPDK_INTERFACE))
            ifndef NIC_MTU
                NIC_MTU := $(shell cat /sys/class/net/$(DPDK_INTERFACE)/mtu 2>/dev/null || echo 1500)
            endif
            CXXFLAGS += -DNIC_MTU=$(NIC_MTU)
            $(info DPDK MTU: $(NIC_MTU))
            $(info Building with DPDK support enabled)
        else
            $(error DPDK requested but libdpdk not found. Install dpdk-dev or check PKG_CONFIG_PATH)
        endif
    # XDP Support (Linux only)
    else ifdef USE_XDP
        ifdef USE_SOCKET
            $(error Cannot use both USE_XDP=1 and USE_SOCKET=1 simultaneously)
        endif
        # Check if libbpf and libxdp are installed
        HAS_LIBBPF := $(shell pkg-config --exists libbpf && echo 1 || echo 0)
        HAS_LIBXDP := $(shell pkg-config --exists libxdp && echo 1 || echo 0)
        ifeq ($(HAS_LIBBPF)$(HAS_LIBXDP),11)
            CXXFLAGS += -DUSE_XDP $(shell pkg-config --cflags libbpf libxdp)
            LDFLAGS += $(shell pkg-config --libs libbpf libxdp) -lbpf -lxdp
            TRANSPORT_INFO := XDP (AF_XDP)
            # XDP Compile-time configuration
            # XDP_INTERFACE is required; MTU and HEADROOM are auto-detected
            # Example: make XDP_INTERFACE=enp40s0 build/benchmark_binance
            ifndef XDP_INTERFACE
                $(error XDP_INTERFACE is required. Usage: make XDP_INTERFACE=<interface>)
            endif
            ifdef XDP_INTERFACE
                CXXFLAGS += -DXDP_INTERFACE='"$(XDP_INTERFACE)"'
                $(info XDP Interface: $(XDP_INTERFACE))
                # Auto-detect NIC_MTU from interface if not specified
                ifndef NIC_MTU
                    NIC_MTU := $(shell cat /sys/class/net/$(XDP_INTERFACE)/mtu 2>/dev/null)
                    ifeq ($(NIC_MTU),)
                        $(error Failed to detect MTU for $(XDP_INTERFACE). Specify NIC_MTU manually.)
                    endif
                    $(info XDP MTU: $(NIC_MTU) (auto-detected))
                endif
                # Auto-detect headroom based on driver if not specified
                # Driver-specific defaults: mlx5/igc/i40e/ice/ixgbe=256 (XDP metadata), others=0
                ifndef XDP_HEADROOM
                    XDP_DRIVER := $(shell basename $$(readlink /sys/class/net/$(XDP_INTERFACE)/device/driver 2>/dev/null) 2>/dev/null)
                    ifneq (,$(filter $(XDP_DRIVER),mlx5_core igc i40e ice ixgbe))
                        XDP_HEADROOM := 256
                    else
                        XDP_HEADROOM := 0
                    endif
                    $(info XDP Headroom: $(XDP_HEADROOM) (auto-detected, driver=$(XDP_DRIVER)))
                endif
            endif
            ifdef XDP_HEADROOM
                CXXFLAGS += -DXDP_HEADROOM=$(XDP_HEADROOM)
                ifndef XDP_INTERFACE
                    $(info XDP Headroom: $(XDP_HEADROOM))
                endif
            endif
            # NIC_MTU is required - auto-detected from interface or must be specified
            ifndef NIC_MTU
                $(error NIC_MTU is required. Specify XDP_INTERFACE for auto-detection or NIC_MTU=<value>)
            endif
            CXXFLAGS += -DNIC_MTU=$(NIC_MTU)
            $(info Building with XDP support enabled)
        else
            $(error XDP requested but dependencies not found. Install libbpf-dev and libxdp-dev)
        endif
    # BSD Sockets (default or explicit)
    else
        TRANSPORT_INFO := BSD sockets
        # NIC_MTU is required for TCP MSS calculations
        ifndef NIC_MTU
            $(error NIC_MTU is required. Usage: make NIC_MTU=1500)
        endif
        CXXFLAGS += -DNIC_MTU=$(NIC_MTU)
        ifdef USE_SOCKET
            $(info Building with BSD sockets (explicit USE_SOCKET=1))
        endif
    endif

    $(info Building with $(SSL_INFO) + $(IO_INFO) + $(TRANSPORT_INFO))

else ifeq ($(UNAME_S),Darwin)
    # macOS configuration
    CXXFLAGS += -D__APPLE__

    # Custom SSL libraries in ~/Proj/ (WolfSSL default for lowest jitter)
    WOLFSSL_PREFIX := $(HOME)/Proj/wolfssl
    OPENSSL_PREFIX := $(HOME)/Proj/openssl
    LIBRESSL_PREFIX := $(HOME)/Proj/libressl/install

    # SSL Policy Selection (WolfSSL default - best P99 latency and jitter)
    ifdef USE_LIBRESSL
        CXXFLAGS += -I$(LIBRESSL_PREFIX)/include -DUSE_LIBRESSL
        LDFLAGS += -L$(LIBRESSL_PREFIX)/lib -lssl -lcrypto
        SSL_INFO := LibreSSL
    else ifdef USE_OPENSSL
        CXXFLAGS += -I$(OPENSSL_PREFIX)/include -DUSE_OPENSSL
        LDFLAGS += -L$(OPENSSL_PREFIX) -lssl -lcrypto
        SSL_INFO := OpenSSL
    else
        # Default: WolfSSL (lowest P99=52μs, jitter=3μs)
        CXXFLAGS += -I$(WOLFSSL_PREFIX) -DHAVE_WOLFSSL
        LDFLAGS += -L$(WOLFSSL_PREFIX)/src/.libs -lwolfssl
        SSL_INFO := WolfSSL
    endif

    # IO Backend Selection (select default - lower jitter than kqueue)
    ifdef USE_KQUEUE
        CXXFLAGS += -DUSE_KQUEUE
        IO_INFO := kqueue
    else
        IO_INFO := select
    endif

    # NIC_MTU is required for TCP MSS calculations
    ifndef NIC_MTU
        $(error NIC_MTU is required. Usage: make NIC_MTU=1500)
    endif
    CXXFLAGS += -DNIC_MTU=$(NIC_MTU)

    $(info Building for macOS with $(IO_INFO) + $(SSL_INFO))
else
    $(error Unsupported platform: $(UNAME_S))
endif

# ============================================================================
# Targets
# ============================================================================

# Source files
EXAMPLE_SRC := examples/binance_example.cpp

# Test source files
TEST_RINGBUFFER_SRC := $(TEST_DIR)/test_ringbuffer.cpp
TEST_EVENT_SRC := $(TEST_DIR)/test_event.cpp
TEST_BUG_FIXES_SRC := $(TEST_DIR)/test_bug_fixes.cpp
TEST_NEW_BUG_FIXES_SRC := $(TEST_DIR)/test_new_bug_fixes.cpp
TEST_HFTSHM_SRC := $(TEST_DIR)/test_hftshm_ringbuffer.cpp
TEST_SHM_RINGBUFFER_SRC := $(TEST_DIR)/test_shm_ringbuffer.cpp

# XDP test source files
TEST_XDP_TRANSPORT_SRC := $(TEST_DIR)/test_xdp_transport.cpp
TEST_XDP_FRAME_SRC := $(TEST_DIR)/test_xdp_frame.cpp
TEST_XDP_SEND_RECV_SRC := $(TEST_DIR)/test_xdp_send_recv.cpp

# Userspace TCP/IP stack test source files
TEST_CORE_HTTP_SRC := $(TEST_DIR)/test_core_http.cpp
TEST_IP_LAYER_SRC := $(TEST_DIR)/test_ip_layer.cpp
TEST_IP_OPTIMIZATIONS_SRC := $(TEST_DIR)/test_ip_optimizations.cpp
TEST_STACK_CHECKSUM_SRC := $(TEST_DIR)/test_stack_checksum.cpp
TEST_TCP_STATE_SRC := $(TEST_DIR)/test_tcp_state.cpp
TEST_RETRANSMIT_QUEUE_SRC := $(TEST_DIR)/test_retransmit_queue.cpp
TEST_SSL_POLICY_SRC := $(TEST_DIR)/test_ssl_policy.cpp
TEST_WS_PARSER_SRC := $(TEST_DIR)/test_ws_parser.cpp
TEST_SBE_DECODER_SRC := $(TEST_DIR)/msg_binance_sbe/test_sbe_decoder.cpp
TEST_SBE_HANDLER_SRC := $(TEST_DIR)/msg_binance_sbe/test_sbe_handler.cpp
TEST_USDM_JSON_SRC := $(TEST_DIR)/msg_binance_usdm/test_usdm_json_parser.cpp
TEST_USDM_JSON_BENCH_SRC := $(TEST_DIR)/msg_binance_usdm/test_usdm_json_bench.cpp
TEST_ORDERBOOK_SRC := $(TEST_DIR)/test_orderbook.cpp
TEST_MKT_VIEWER_DEDUP_SRC := $(TEST_DIR)/test_mkt_viewer_dedup.cpp
TEST_MKT_EVENT_BITFIELDS_SRC := $(TEST_DIR)/test_mkt_event_bitfields.cpp
TEST_WATCHDOG_POLICY_SRC := $(TEST_DIR)/test_watchdog_policy.cpp
TEST_TX_POOL_FIFO_SRC := $(TEST_DIR)/test_tx_pool_fifo.cpp

# Integration test source files
TEST_BINANCE_SRC := $(INTEGRATION_DIR)/binance.cpp
TEST_XDP_BINANCE_SRC := $(INTEGRATION_DIR)/xdp_binance.cpp

# Benchmark source files
BENCHMARK_DIR := ./test/benchmark
BENCHMARK_BINANCE_SRC := $(BENCHMARK_DIR)/binance.cpp

# Binary output
EXAMPLE_BIN := $(BUILD_DIR)/ws_example
TEST_RINGBUFFER_BIN := $(BUILD_DIR)/test_ringbuffer
TEST_EVENT_BIN := $(BUILD_DIR)/test_event
TEST_BUG_FIXES_BIN := $(BUILD_DIR)/test_bug_fixes
TEST_NEW_BUG_FIXES_BIN := $(BUILD_DIR)/test_new_bug_fixes
TEST_HFTSHM_BIN := $(BUILD_DIR)/test_hftshm_ringbuffer
TEST_SHM_RINGBUFFER_BIN := $(BUILD_DIR)/test_shm_ringbuffer
TEST_BINANCE_BIN := $(BUILD_DIR)/test_binance_integration
BENCHMARK_BINANCE_BIN := $(BUILD_DIR)/benchmark_binance

# XDP test binaries
TEST_XDP_TRANSPORT_BIN := $(BUILD_DIR)/test_xdp_transport
TEST_XDP_FRAME_BIN := $(BUILD_DIR)/test_xdp_frame
TEST_XDP_SEND_RECV_BIN := $(BUILD_DIR)/test_xdp_send_recv
TEST_XDP_BINANCE_BIN := $(BUILD_DIR)/test_xdp_binance_integration

# Userspace TCP/IP stack test binaries
TEST_CORE_HTTP_BIN := $(BUILD_DIR)/test_core_http
TEST_IP_LAYER_BIN := $(BUILD_DIR)/test_ip_layer
TEST_IP_OPTIMIZATIONS_BIN := $(BUILD_DIR)/test_ip_optimizations
TEST_STACK_CHECKSUM_BIN := $(BUILD_DIR)/test_stack_checksum
TEST_TCP_STATE_BIN := $(BUILD_DIR)/test_tcp_state
TEST_RETRANSMIT_QUEUE_BIN := $(BUILD_DIR)/test_retransmit_queue
TEST_SSL_POLICY_BIN := $(BUILD_DIR)/test_ssl_policy
TEST_WS_PARSER_BIN := $(BUILD_DIR)/test_ws_parser
TEST_SBE_DECODER_BIN := $(BUILD_DIR)/test_sbe_decoder
TEST_SBE_HANDLER_BIN := $(BUILD_DIR)/test_sbe_handler
TEST_USDM_JSON_BIN := $(BUILD_DIR)/test_usdm_json_parser
TEST_USDM_JSON_BENCH_BIN := $(BUILD_DIR)/test_usdm_json_bench
TEST_ORDERBOOK_BIN := $(BUILD_DIR)/test_orderbook
TEST_MKT_VIEWER_DEDUP_BIN := $(BUILD_DIR)/test_mkt_viewer_dedup
TEST_MKT_EVENT_BITFIELDS_BIN := $(BUILD_DIR)/test_mkt_event_bitfields
TEST_WATCHDOG_POLICY_BIN := $(BUILD_DIR)/test_watchdog_policy
TEST_TX_POOL_FIFO_BIN := $(BUILD_DIR)/test_tx_pool_fifo
TEST_AES_CTR_SEQ_SRC := $(TEST_DIR)/test_aes_ctr_seq.cpp
TEST_AES_CTR_SEQ_BIN := $(BUILD_DIR)/test_aes_ctr_seq
TEST_TLS13_INNER_CT_SRC := $(TEST_DIR)/test_tls13_inner_ct.cpp
TEST_TLS13_INNER_CT_BIN := $(BUILD_DIR)/test_tls13_inner_ct
TEST_WOLFSSL_SEQ_SRC := $(TEST_DIR)/test_wolfssl_seq_num.cpp
TEST_WOLFSSL_SEQ_BIN := $(BUILD_DIR)/test_wolfssl_seq_num
TEST_LAST_BYTE_TS_SRC := $(TEST_DIR)/test_last_byte_ts.cpp
TEST_LAST_BYTE_TS_BIN := $(BUILD_DIR)/test_last_byte_ts

.PHONY: all clean clean-bpf run help test test-ringbuffer test-shm-ringbuffer test-event test-bug-fixes test-new-bug-fixes test-aes-ctr-seq test-tls13-inner-ct test-wolfssl-seq-num test-last-byte-ts test-binance benchmark-binance test-xdp-transport test-xdp-frame test-xdp-send-recv test-xdp-binance test-core-http test-ip-layer test-ip-optimizations test-stack-checksum test-tcp-state test-retransmit-queue test-ssl-policy test-ws-parser test-sbe-decoder test-sbe-handler test-usdm-json-parser test-orderbook test-mkt-viewer-dedup test-mkt-event-bitfields test-hftshm bpf check-ktls release debug epoll build-pipeline-binance test-pipeline-binance build-test-pipeline-xdp-poll test-pipeline-xdp-poll build-test-pipeline-xdp-poll-tcp test-pipeline-xdp-poll-tcp build-test-pipeline-transport-tcp test-pipeline-transport-tcp build-test-pipeline-transport-http test-pipeline-transport-http build-test-pipeline-transport_wss test-pipeline-transport-wss build-test-pipeline-bsd-transport-tcp test-pipeline-bsd-transport-tcp build-test-pipeline-bsd-transport test-pipeline-bsd-transport build-test-pipeline-websocket_binance_bsdsocket_2thread test-pipeline-websocket-binance-bsdsocket-2thread build-test-pipeline-websocket_binance_bsdsocket_3thread test-pipeline-websocket-binance-bsdsocket-3thread build-test-pipeline-252_binance_sbe_bsdsocket_1thread test-pipeline-252-binance-sbe-bsdsocket-1thread build-test-pipeline-250_binance_sbe_bsdsocket_2thread test-pipeline-250-binance-sbe-bsdsocket-2thread build-test-pipeline-251_binance_sbe_bsdsocket_3thread test-pipeline-251-binance-sbe-bsdsocket-3thread build-test-pipeline-253_binance_sbe_bsdsocket_inline_ws test-pipeline-253-binance-sbe-bsdsocket-inline-ws build-test-pipeline-261_binance_sbe_xdp_inline_ws test-pipeline-261-binance-sbe-xdp-inline-ws build-test-pipeline-262_binance_sbe_dpdk_inline_ws build-test-pipeline-263_binance_sbe_dpdk_packetio_inline_ws build-test-pipeline-264_binance_sbe_xdp_packetio_inline_ws bench-usdm-json-parser

all: $(EXAMPLE_BIN)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# SSL backend sentinel — forces rebuild when SSL backend changes between
# USE_OPENSSL, USE_WOLFSSL, USE_LIBRESSL.  The sentinel file records the
# backend name; if it differs from the current invocation the file is
# rewritten, which makes every binary that depends on it out-of-date.
ifdef USE_WOLFSSL
    SSL_BACKEND_NAME := wolfssl
else ifdef USE_OPENSSL
    SSL_BACKEND_NAME := openssl
else ifdef USE_LIBRESSL
    SSL_BACKEND_NAME := libressl
else
    SSL_BACKEND_NAME := none
endif

SSL_BACKEND_SENTINEL := $(BUILD_DIR)/.ssl_backend

$(SSL_BACKEND_SENTINEL): FORCE | $(BUILD_DIR)
	@echo "$(SSL_BACKEND_NAME)" | cmp -s - $@ || echo "$(SSL_BACKEND_NAME)" > $@

FORCE:

# Build example
$(EXAMPLE_BIN): $(EXAMPLE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling example..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✅ Build complete: $@"

# Build ringbuffer tests
$(TEST_RINGBUFFER_BIN): $(TEST_RINGBUFFER_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling ringbuffer unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "✅ Test build complete: $@"

# Build event policy tests
$(TEST_EVENT_BIN): $(TEST_EVENT_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling event policy unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "✅ Test build complete: $@"

# Run example
run: $(EXAMPLE_BIN)
	@echo "🚀 Running WebSocket example..."
	./$(EXAMPLE_BIN)

# Run ringbuffer tests
test-ringbuffer: $(TEST_RINGBUFFER_BIN)
	@echo "🧪 Running ringbuffer unit tests..."
	./$(TEST_RINGBUFFER_BIN)

# Build shm-ringbuffer tests
$(TEST_SHM_RINGBUFFER_BIN): $(TEST_SHM_RINGBUFFER_SRC) src/ringbuffer.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling shm-ringbuffer unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run shm-ringbuffer tests
test-shm-ringbuffer: $(TEST_SHM_RINGBUFFER_BIN)
	@echo "🧪 Running shm-ringbuffer unit tests..."
	./$(TEST_SHM_RINGBUFFER_BIN)

# Run event policy tests
test-event: $(TEST_EVENT_BIN)
	@echo "🧪 Running event policy unit tests..."
	./$(TEST_EVENT_BIN)

# Build bug fixes verification tests
$(TEST_BUG_FIXES_BIN): $(TEST_BUG_FIXES_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling bug fixes unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "✅ Test build complete: $@"

# Run bug fixes verification tests
test-bug-fixes: $(TEST_BUG_FIXES_BIN)
	@echo "🧪 Running bug fixes verification tests..."
	./$(TEST_BUG_FIXES_BIN)

# Build new bug fixes verification tests
$(TEST_NEW_BUG_FIXES_BIN): $(TEST_NEW_BUG_FIXES_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling new bug fixes unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "✅ Test build complete: $@"

# Run new bug fixes verification tests
test-new-bug-fixes: $(TEST_NEW_BUG_FIXES_BIN)
	@echo "🧪 Running new bug fixes verification tests..."
	./$(TEST_NEW_BUG_FIXES_BIN)

# AES-CTR sequence number regression test
$(TEST_AES_CTR_SEQ_BIN): $(TEST_AES_CTR_SEQ_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling AES-CTR seq_num regression test..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

test-aes-ctr-seq: $(TEST_AES_CTR_SEQ_BIN)
	@echo "🧪 Running AES-CTR seq_num regression test..."
	./$(TEST_AES_CTR_SEQ_BIN)

# TLS 1.3 inner content type double seq_num++ regression test
$(TEST_TLS13_INNER_CT_BIN): $(TEST_TLS13_INNER_CT_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling TLS 1.3 inner content type test..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

test-tls13-inner-ct: $(TEST_TLS13_INNER_CT_BIN)
	@echo "🧪 Running TLS 1.3 inner content type test..."
	./$(TEST_TLS13_INNER_CT_BIN)

# WolfSSL seq_num tracking regression test (wrong initial seq_num)
$(TEST_WOLFSSL_SEQ_BIN): $(TEST_WOLFSSL_SEQ_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling WolfSSL seq_num regression test..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

test-wolfssl-seq-num: $(TEST_WOLFSSL_SEQ_BIN)
	@echo "🧪 Running WolfSSL seq_num regression test..."
	./$(TEST_WOLFSSL_SEQ_BIN)

# last_byte_ts=0 partial-frame timestamp regression test
$(TEST_LAST_BYTE_TS_BIN): $(TEST_LAST_BYTE_TS_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling last_byte_ts partial-frame timestamp test..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

test-last-byte-ts: $(TEST_LAST_BYTE_TS_BIN)
	@echo "🧪 Running last_byte_ts partial-frame timestamp test..."
	./$(TEST_LAST_BYTE_TS_BIN)

# Build Binance integration test
$(TEST_BINANCE_BIN): $(TEST_BINANCE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling Binance integration test..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✅ Integration test build complete: $@"

# Run Binance integration test
test-binance: $(TEST_BINANCE_BIN)
	@echo "🧪 Running Binance WebSocket integration test..."
	@echo "📡 Connecting to wss://stream.binance.com:443..."
	./$(TEST_BINANCE_BIN)

# Build Binance benchmark
$(BENCHMARK_BINANCE_BIN): $(BENCHMARK_BINANCE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling Binance latency benchmark..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✅ Benchmark build complete: $@"

# Build Binance benchmark only (no auto-run, for sudo usage)
build-benchmark-binance: $(BENCHMARK_BINANCE_BIN)

# Run Binance benchmark (builds and runs - requires sudo for XDP)
benchmark-binance: $(BENCHMARK_BINANCE_BIN)
	@echo "📊 Running Binance WebSocket latency benchmark..."
	@echo "📡 Warmup: 100 messages, Benchmark: 300 messages"
	./$(BENCHMARK_BINANCE_BIN)

# ============================================================================
# XDP Integration Tests
# ============================================================================

# Build XDP Binance integration test
$(TEST_XDP_BINANCE_BIN): $(TEST_XDP_BINANCE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling XDP Binance integration test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Test build complete: $@"
else
	@echo "❌ Error: XDP not enabled. Build with USE_XDP=1"
	@exit 1
endif

# Run XDP Binance integration test
test-xdp-binance: $(TEST_XDP_BINANCE_BIN)
	@echo "🧪 Running XDP Binance integration test..."
	@echo "⚠️  NOTE: This test requires:"
	@echo "    - libbpf-dev and libxdp-dev installed"
	@echo "    - Huge pages configured (sudo sh -c 'echo 256 > /proc/sys/vm/nr_hugepages')"
	@echo "    - Run as root or with CAP_NET_RAW + CAP_BPF"
	@echo "    - Network interface that supports XDP"
	@echo ""
	sudo ./$(TEST_XDP_BINANCE_BIN)

# Build XDP transport tests
$(TEST_XDP_TRANSPORT_BIN): $(TEST_XDP_TRANSPORT_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling XDP transport unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run XDP transport tests
test-xdp-transport: $(TEST_XDP_TRANSPORT_BIN)
	@echo "🧪 Running XDP transport unit tests..."
	./$(TEST_XDP_TRANSPORT_BIN)

# Build XDP frame tests
$(TEST_XDP_FRAME_BIN): $(TEST_XDP_FRAME_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling XDP frame unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run XDP frame tests
test-xdp-frame: $(TEST_XDP_FRAME_BIN)
	@echo "🧪 Running XDP frame unit tests..."
	./$(TEST_XDP_FRAME_BIN)

# Build XDP send/recv tests
$(TEST_XDP_SEND_RECV_BIN): $(TEST_XDP_SEND_RECV_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling XDP send/recv unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run XDP send/recv tests
test-xdp-send-recv: $(TEST_XDP_SEND_RECV_BIN)
	@echo "🧪 Running XDP send/recv unit tests..."
	./$(TEST_XDP_SEND_RECV_BIN)

# ============================================================================
# Userspace TCP/IP Stack Unit Tests
# ============================================================================

# Build core HTTP tests
$(TEST_CORE_HTTP_BIN): $(TEST_CORE_HTTP_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling core HTTP unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run core HTTP tests
test-core-http: $(TEST_CORE_HTTP_BIN)
	@echo "🧪 Running core HTTP unit tests..."
	./$(TEST_CORE_HTTP_BIN)

# Build IP layer tests
$(TEST_IP_LAYER_BIN): $(TEST_IP_LAYER_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling IP layer unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run IP layer tests
test-ip-layer: $(TEST_IP_LAYER_BIN)
	@echo "🧪 Running IP layer unit tests..."
	./$(TEST_IP_LAYER_BIN)

# Build IP optimizations tests
$(TEST_IP_OPTIMIZATIONS_BIN): $(TEST_IP_OPTIMIZATIONS_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling IP optimizations unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run IP optimizations tests
test-ip-optimizations: $(TEST_IP_OPTIMIZATIONS_BIN)
	@echo "🧪 Running IP optimizations unit tests..."
	./$(TEST_IP_OPTIMIZATIONS_BIN)

# Build stack checksum tests
$(TEST_STACK_CHECKSUM_BIN): $(TEST_STACK_CHECKSUM_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling stack checksum unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run stack checksum tests
test-stack-checksum: $(TEST_STACK_CHECKSUM_BIN)
	@echo "🧪 Running stack checksum unit tests..."
	./$(TEST_STACK_CHECKSUM_BIN)

# Build TCP state tests
$(TEST_TCP_STATE_BIN): $(TEST_TCP_STATE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling TCP state unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run TCP state tests
test-tcp-state: $(TEST_TCP_STATE_BIN)
	@echo "🧪 Running TCP state unit tests..."
	./$(TEST_TCP_STATE_BIN)

# Build retransmit queue tests
$(TEST_RETRANSMIT_QUEUE_BIN): $(TEST_RETRANSMIT_QUEUE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling retransmit queue unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run retransmit queue tests
test-retransmit-queue: $(TEST_RETRANSMIT_QUEUE_BIN)
	@echo "🧪 Running retransmit queue unit tests..."
	./$(TEST_RETRANSMIT_QUEUE_BIN)

# Build SSL policy tests
$(TEST_SSL_POLICY_BIN): $(TEST_SSL_POLICY_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling SSL policy unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Test build complete: $@"

# Run SSL policy tests
test-ssl-policy: $(TEST_SSL_POLICY_BIN)
	@echo "🧪 Running SSL policy unit tests..."
	./$(TEST_SSL_POLICY_BIN)

# Build watchdog policy tests
$(TEST_WATCHDOG_POLICY_BIN): $(TEST_WATCHDOG_POLICY_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling watchdog policy unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run watchdog policy tests
test-watchdog-policy: $(TEST_WATCHDOG_POLICY_BIN)
	@echo "🧪 Running watchdog policy unit tests..."
	./$(TEST_WATCHDOG_POLICY_BIN)

# Build TX pool FIFO tests
$(TEST_TX_POOL_FIFO_BIN): $(TEST_TX_POOL_FIFO_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling TX pool FIFO unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run TX pool FIFO tests
test-tx-pool-fifo: $(TEST_TX_POOL_FIFO_BIN)
	@echo "🧪 Running TX pool FIFO unit tests..."
	./$(TEST_TX_POOL_FIFO_BIN)

# Build WS parser tests
$(TEST_WS_PARSER_BIN): $(TEST_WS_PARSER_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling WS parser unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run WS parser tests
test-ws-parser: $(TEST_WS_PARSER_BIN)
	@echo "🧪 Running WS parser unit tests..."
	./$(TEST_WS_PARSER_BIN)

# Build SBE decoder tests
$(TEST_SBE_DECODER_BIN): $(TEST_SBE_DECODER_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling SBE decoder unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run SBE decoder tests
test-sbe-decoder: $(TEST_SBE_DECODER_BIN)
	@echo "🧪 Running SBE decoder unit tests..."
	./$(TEST_SBE_DECODER_BIN)

# Build SBE handler tests
$(TEST_SBE_HANDLER_BIN): $(TEST_SBE_HANDLER_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling SBE handler unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run SBE handler tests
test-sbe-handler: $(TEST_SBE_HANDLER_BIN)
	@echo "🧪 Running SBE handler unit tests..."
	./$(TEST_SBE_HANDLER_BIN)

# Build USDM JSON parser tests
$(TEST_USDM_JSON_BIN): $(TEST_USDM_JSON_SRC) src/msg/01_binance_usdm_json.hpp src/msg/03_binance_usdm_simdjson.hpp src/msg/market_conf.hpp $(BUILD_DIR)/simdjson.o | $(BUILD_DIR)
	@echo "🔨 Compiling USDM JSON parser unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $< $(BUILD_DIR)/simdjson.o
	@echo "✅ Test build complete: $@"

# Run USDM JSON parser tests
test-usdm-json-parser: $(TEST_USDM_JSON_BIN)
	@echo "🧪 Running USDM JSON parser unit tests..."
	./$(TEST_USDM_JSON_BIN)

# Build simdjson vendor object (C++17)
$(BUILD_DIR)/simdjson.o: src/vendor/simdjson.cpp src/vendor/simdjson.h | $(BUILD_DIR)
	$(CXX) -std=c++17 -O3 -march=native -c -o $@ $<

# Build USDM JSON benchmark (custom vs simdjson)
$(TEST_USDM_JSON_BENCH_BIN): $(TEST_USDM_JSON_BENCH_SRC) $(BUILD_DIR)/simdjson.o \
		src/msg/01_binance_usdm_json.hpp src/msg/03_binance_usdm_simdjson.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling USDM JSON parse benchmark..."
	$(CXX) $(CXXFLAGS) -o $@ $< $(BUILD_DIR)/simdjson.o
	@echo "✅ Benchmark build complete: $@"

# Run USDM JSON parse benchmark
bench-usdm-json-parser: $(TEST_USDM_JSON_BENCH_BIN)
	@echo "🧪 Running USDM JSON parse benchmark..."
	./$(TEST_USDM_JSON_BENCH_BIN)

# Build OrderBook tests
$(TEST_ORDERBOOK_BIN): $(TEST_ORDERBOOK_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling OrderBook unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run OrderBook tests
test-orderbook: $(TEST_ORDERBOOK_BIN)
	@echo "🧪 Running OrderBook unit tests..."
	./$(TEST_ORDERBOOK_BIN)

# Build mkt_viewer dedup tests
$(TEST_MKT_VIEWER_DEDUP_BIN): $(TEST_MKT_VIEWER_DEDUP_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling mkt_viewer dedup unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run mkt_viewer dedup tests
test-mkt-viewer-dedup: $(TEST_MKT_VIEWER_DEDUP_BIN)
	@echo "🧪 Running mkt_viewer dedup unit tests..."
	./$(TEST_MKT_VIEWER_DEDUP_BIN)

# Build MktEvent bitfield tests
$(TEST_MKT_EVENT_BITFIELDS_BIN): $(TEST_MKT_EVENT_BITFIELDS_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling MktEvent bitfield unit tests..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ Test build complete: $@"

# Run MktEvent bitfield tests
test-mkt-event-bitfields: $(TEST_MKT_EVENT_BITFIELDS_BIN)
	@echo "🧪 Running MktEvent bitfield unit tests..."
	./$(TEST_MKT_EVENT_BITFIELDS_BIN)

# ============================================================================
# Pipeline Integration Tests (Multi-Process AF_XDP WebSocket)
# ============================================================================

# Common pipeline headers - all pipeline tests depend on these
# When any header changes, affected tests will be rebuilt
PIPELINE_HEADERS := \
    src/pipeline/00_xdp_poll_process.hpp \
    src/pipeline/01_dpdk_poll_process.hpp \
    src/pipeline/10_tcp_ssl_process.hpp \
    src/pipeline/11_bsd_tcp_ssl_process.hpp \
    src/pipeline/20_ws_process.hpp \
    src/pipeline/21_ws_core.hpp \
    src/pipeline/98_xdp_tcp_ssl_process.hpp \
    src/pipeline/99_xdp_tcp_ssl_ws_process.hpp \
    src/pipeline/websocket_pipeline.hpp \
    src/pipeline/bsd_websocket_pipeline.hpp \
    src/pipeline/pipeline_data.hpp \
    src/pipeline/pipeline_config.hpp \
    src/pipeline/msg_inbox.hpp \
    src/pipeline/disruptor_packet_io.hpp \
    src/pipeline/dpdk_packet_io.hpp \
    src/net/ip_probe.hpp \
    src/stack/userspace_stack.hpp \
    src/xdp/xdp_packet_io.hpp \
    src/policy/ssl.hpp \
    src/core/timing.hpp

# ============================================================================
# XDP Poll Segregated Test (Wire Loopback)
# ============================================================================

PIPELINE_XDP_POLL_SRC := test/pipeline/00_xdp_poll.cpp
PIPELINE_XDP_POLL_BIN := $(BUILD_DIR)/test_pipeline_xdp_poll

# Build XDP Poll test
$(PIPELINE_XDP_POLL_BIN): $(PIPELINE_XDP_POLL_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling XDP Poll segregated test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ XDP Poll test build complete: $@"
else
	@echo "❌ Error: XDP Poll test requires USE_XDP=1"
	@exit 1
endif

# Build-only target for XDP Poll test
build-test-pipeline-xdp-poll: $(PIPELINE_XDP_POLL_BIN)

# Run XDP Poll segregated test (requires sudo access and wire loopback)
# Uses scripts/test_pipeline_xdp_poll.sh for safe setup/teardown
# NOTE: Script uses sudo internally, do not invoke with sudo
test-pipeline-xdp-poll: $(PIPELINE_XDP_POLL_BIN) bpf
	@echo "🧪 Running XDP Poll segregated test via script..."
	./scripts/test_pipeline_xdp_poll.sh $(XDP_INTERFACE)

# ============================================================================
# XDP Poll ICMP Ping Test
# ============================================================================

PIPELINE_XDP_POLL_PING_SRC := test/pipeline/00_xdp_poll_ping.cpp
PIPELINE_XDP_POLL_PING_BIN := $(BUILD_DIR)/test_pipeline_xdp_poll_ping

# Build XDP Poll Ping test
$(PIPELINE_XDP_POLL_PING_BIN): $(PIPELINE_XDP_POLL_PING_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling XDP Poll ICMP Ping test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ XDP Poll Ping test build complete: $@"
else
	@echo "❌ Error: XDP Poll Ping test requires USE_XDP=1"
	@exit 1
endif

# Build-only target for XDP Poll Ping test
build-test-pipeline-xdp-poll-ping: $(PIPELINE_XDP_POLL_PING_BIN)

# ============================================================================
# XDP Poll TCP Test (Echo Server)
# ============================================================================

PIPELINE_XDP_POLL_TCP_SRC := test/pipeline/01_xdp_poll_tcp.cpp
PIPELINE_XDP_POLL_TCP_BIN := $(BUILD_DIR)/test_pipeline_xdp_poll_tcp

# Build XDP Poll TCP test
$(PIPELINE_XDP_POLL_TCP_BIN): $(PIPELINE_XDP_POLL_TCP_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling XDP Poll TCP test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ XDP Poll TCP test build complete: $@"
else
	@echo "❌ Error: XDP Poll TCP test requires USE_XDP=1"
	@exit 1
endif

# Build-only target for XDP Poll TCP test
build-test-pipeline-xdp-poll-tcp: $(PIPELINE_XDP_POLL_TCP_BIN)

# Run XDP Poll TCP test (requires echo server at 39.162.79.171:12345)
# Uses scripts/test_pipeline_xdp_poll.sh with test file argument
# NOTE: Script uses sudo internally, do not invoke with sudo
test-pipeline-xdp-poll-tcp: $(PIPELINE_XDP_POLL_TCP_BIN) bpf
	@echo "🧪 Running XDP Poll TCP test via script..."
	./scripts/test_pipeline_xdp_poll.sh $(XDP_INTERFACE) 01_xdp_poll_tcp.cpp

# ============================================================================
# XDPPacketIO TCP Test (Single-Process: PacketTransport<XDPPacketIO>)
# Tests single-process AF_XDP path with plain TCP echo server
# ============================================================================

PIPELINE_XDP_PACKETIO_TCP_SRC := test/pipeline/02_xdp_packetio_tcp.cpp
PIPELINE_XDP_PACKETIO_TCP_BIN := $(BUILD_DIR)/test_pipeline_02_xdp_packetio_tcp

# Build XDPPacketIO TCP test
$(PIPELINE_XDP_PACKETIO_TCP_BIN): $(PIPELINE_XDP_PACKETIO_TCP_SRC) $(PIPELINE_HEADERS) src/xdp/xdp_packet_io.hpp src/policy/transport.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling XDPPacketIO TCP test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ XDPPacketIO TCP test build complete: $@"
else
	@echo "❌ Error: XDPPacketIO TCP test requires USE_XDP=1"
	@exit 1
endif

# Build-only target for XDPPacketIO TCP test
build-test-pipeline-02_xdp_packetio_tcp: $(PIPELINE_XDP_PACKETIO_TCP_BIN)

# Run XDPPacketIO TCP test (requires echo server)
# NOTE: Script uses sudo internally, do not invoke with sudo
test-pipeline-02-xdp-packetio-tcp: $(PIPELINE_XDP_PACKETIO_TCP_BIN) bpf
	@echo "🧪 Running XDPPacketIO TCP test via script..."
	./scripts/build_xdp.sh 02_xdp_packetio_tcp.cpp

# ============================================================================
# DisruptorPacketIO TCP Test (2-Process: XDP Poll + PacketTransport<DisruptorPacketIO>)
# ============================================================================

PIPELINE_DISRUPTOR_PACKETIO_TCP_SRC := test/pipeline/03_disruptor_packetio_tcp.cpp
PIPELINE_DISRUPTOR_PACKETIO_TCP_BIN := $(BUILD_DIR)/test_pipeline_03_disruptor_packetio_tcp

$(PIPELINE_DISRUPTOR_PACKETIO_TCP_BIN): $(PIPELINE_DISRUPTOR_PACKETIO_TCP_SRC) $(PIPELINE_HEADERS) \
    src/pipeline/disruptor_packet_io.hpp src/pipeline/00_xdp_poll_process.hpp src/policy/transport.hpp | $(BUILD_DIR)
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
endif

build-test-pipeline-03_disruptor_packetio_tcp: $(PIPELINE_DISRUPTOR_PACKETIO_TCP_BIN)

test-pipeline-03-disruptor-packetio-tcp: $(PIPELINE_DISRUPTOR_PACKETIO_TCP_BIN) bpf
	./scripts/build_xdp.sh 03_disruptor_packetio_tcp.cpp

# ============================================================================
# DPDK Poll ICMP Ping Test (DPDKPollProcess standalone test)
# ============================================================================

PIPELINE_DPDK_POLL_PING_SRC := test/pipeline/04_dpdk_poll_ping.cpp
PIPELINE_DPDK_POLL_PING_BIN := $(BUILD_DIR)/test_pipeline_04_dpdk_poll_ping

$(PIPELINE_DPDK_POLL_PING_BIN): $(PIPELINE_DPDK_POLL_PING_SRC) $(PIPELINE_HEADERS) \
    src/pipeline/01_dpdk_poll_process.hpp | $(BUILD_DIR)
ifdef USE_DPDK
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ DPDK Poll Ping test build complete: $@"
else
	@echo "❌ Error: DPDK Poll Ping test requires USE_DPDK=1"
	@exit 1
endif

build-test-pipeline-04_dpdk_poll_ping: $(PIPELINE_DPDK_POLL_PING_BIN)

# ============================================================================
# DPDK DisruptorPacketIO TCP Test (2-Process: DPDK Poll + PacketTransport<DisruptorPacketIO>)
# ============================================================================

PIPELINE_DPDK_DISRUPTOR_TCP_SRC := test/pipeline/05_dpdk_disruptor_packetio_tcp.cpp
PIPELINE_DPDK_DISRUPTOR_TCP_BIN := $(BUILD_DIR)/test_pipeline_05_dpdk_disruptor_packetio_tcp

$(PIPELINE_DPDK_DISRUPTOR_TCP_BIN): $(PIPELINE_DPDK_DISRUPTOR_TCP_SRC) $(PIPELINE_HEADERS) \
    src/pipeline/disruptor_packet_io.hpp src/pipeline/01_dpdk_poll_process.hpp src/policy/transport.hpp | $(BUILD_DIR)
ifdef USE_DPDK
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ DPDK DisruptorPacketIO TCP test build complete: $@"
else
	@echo "❌ Error: DPDK DisruptorPacketIO TCP test requires USE_DPDK=1"
	@exit 1
endif

build-test-pipeline-05_dpdk_disruptor_packetio_tcp: $(PIPELINE_DPDK_DISRUPTOR_TCP_BIN)

# ============================================================================
# DPDK PacketIO TCP Test (Single-Process: PacketTransport<DPDKPacketIO>)
# ============================================================================

PIPELINE_DPDK_PACKETIO_TCP_SRC := test/pipeline/06_dpdk_packetio_tcp.cpp
PIPELINE_DPDK_PACKETIO_TCP_BIN := $(BUILD_DIR)/test_pipeline_06_dpdk_packetio_tcp

$(PIPELINE_DPDK_PACKETIO_TCP_BIN): $(PIPELINE_DPDK_PACKETIO_TCP_SRC) $(PIPELINE_HEADERS) \
    src/pipeline/dpdk_packet_io.hpp src/policy/transport.hpp | $(BUILD_DIR)
ifdef USE_DPDK
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ DPDK PacketIO TCP test build complete: $@"
else
	@echo "❌ Error: DPDK PacketIO TCP test requires USE_DPDK=1"
	@exit 1
endif

build-test-pipeline-06_dpdk_packetio_tcp: $(PIPELINE_DPDK_PACKETIO_TCP_BIN)

# ============================================================================
# Transport TCP Test (NoSSLPolicy with forked XDP Poll + Transport)
# ============================================================================

PIPELINE_TRANSPORT_TCP_SRC := test/pipeline/10_transport_tcp.cpp
PIPELINE_TRANSPORT_TCP_BIN := $(BUILD_DIR)/test_pipeline_transport_tcp

# Build Transport TCP test
$(PIPELINE_TRANSPORT_TCP_BIN): $(PIPELINE_TRANSPORT_TCP_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling Transport TCP test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Transport TCP test build complete: $@"
else
	@echo "❌ Error: Transport TCP test requires USE_XDP=1"
	@exit 1
endif

# Build-only target for Transport TCP test
build-test-pipeline-transport-tcp: $(PIPELINE_TRANSPORT_TCP_BIN)

# Run Transport TCP test (requires echo server at 139.162.79.171:12345)
# Uses scripts/test_xdp.sh - the verified XDP test runner
# NOTE: Script uses sudo internally, do not invoke with sudo
test-pipeline-transport-tcp: $(PIPELINE_TRANSPORT_TCP_BIN) bpf
	@echo "🧪 Running Transport TCP test via script..."
	./scripts/test_xdp.sh 10_transport_tcp.cpp

# ============================================================================
# Transport HTTP Test (NoSSLPolicy with forked XDP Poll + Transport)
# Tests plain HTTP against ipinfo.io:80
# ============================================================================

PIPELINE_TRANSPORT_HTTP_SRC := test/pipeline/11_transport_http.cpp
PIPELINE_TRANSPORT_HTTP_BIN := $(BUILD_DIR)/test_pipeline_transport_http

# Build Transport HTTP test
$(PIPELINE_TRANSPORT_HTTP_BIN): $(PIPELINE_TRANSPORT_HTTP_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling Transport HTTP test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Transport HTTP test build complete: $@"
else
	@echo "❌ Error: Transport HTTP test requires USE_XDP=1"
	@exit 1
endif

# Build-only target for Transport HTTP test
build-test-pipeline-transport-http: $(PIPELINE_TRANSPORT_HTTP_BIN)

# Run Transport HTTP test (connects to ipinfo.io:80)
# Uses scripts/test_xdp.sh - the verified XDP test runner
# NOTE: Script uses sudo internally, do not invoke with sudo
test-pipeline-transport-http: $(PIPELINE_TRANSPORT_HTTP_BIN) bpf
	@echo "🧪 Running Transport HTTP test via script..."
	./scripts/test_xdp.sh 11_transport_http.cpp

# ============================================================================
# Transport HTTPS WolfSSL Test (WolfSSLPolicy with forked XDP Poll + Transport)
# Tests HTTPS against www.gnu.org:443
# ============================================================================

PIPELINE_TRANSPORT_HTTPS_WOLFSSL_SRC := test/pipeline/12_transport_https_wolfssl.cpp
PIPELINE_TRANSPORT_HTTPS_WOLFSSL_BIN := $(BUILD_DIR)/test_pipeline_transport_https_wolfssl

# Build Transport HTTPS WolfSSL test
$(PIPELINE_TRANSPORT_HTTPS_WOLFSSL_BIN): $(PIPELINE_TRANSPORT_HTTPS_WOLFSSL_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling Transport HTTPS WolfSSL test..."
ifdef USE_XDP
ifdef USE_WOLFSSL
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Transport HTTPS WolfSSL test build complete: $@"
else
	@echo "❌ Error: Transport HTTPS WolfSSL test requires USE_WOLFSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: Transport HTTPS WolfSSL test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-transport_https_wolfssl: $(PIPELINE_TRANSPORT_HTTPS_WOLFSSL_BIN)

test-pipeline-transport-https-wolfssl: $(PIPELINE_TRANSPORT_HTTPS_WOLFSSL_BIN) bpf
	@echo "🧪 Running Transport HTTPS WolfSSL test via script..."
	./scripts/test_xdp.sh 12_transport_https_wolfssl.cpp

# ============================================================================
# Transport HTTPS OpenSSL Test (OpenSSLPolicy with forked XDP Poll + Transport)
# Tests HTTPS against www.gnu.org:443
# ============================================================================

PIPELINE_TRANSPORT_HTTPS_OPENSSL_SRC := test/pipeline/13_transport_https_openssl.cpp
PIPELINE_TRANSPORT_HTTPS_OPENSSL_BIN := $(BUILD_DIR)/test_pipeline_transport_https_openssl

$(PIPELINE_TRANSPORT_HTTPS_OPENSSL_BIN): $(PIPELINE_TRANSPORT_HTTPS_OPENSSL_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling Transport HTTPS OpenSSL test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Transport HTTPS OpenSSL test build complete: $@"
else
	@echo "❌ Error: Transport HTTPS OpenSSL test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-transport_https_openssl: $(PIPELINE_TRANSPORT_HTTPS_OPENSSL_BIN)

test-pipeline-transport-https-openssl: $(PIPELINE_TRANSPORT_HTTPS_OPENSSL_BIN) bpf
	@echo "🧪 Running Transport HTTPS OpenSSL test via script..."
	./scripts/test_xdp.sh 13_transport_https_openssl.cpp

# ============================================================================
# Transport HTTPS LibreSSL Test (LibreSSLPolicy with forked XDP Poll + Transport)
# Tests HTTPS against www.gnu.org:443
# ============================================================================

PIPELINE_TRANSPORT_HTTPS_LIBRESSL_SRC := test/pipeline/14_transport_https_libressl.cpp
PIPELINE_TRANSPORT_HTTPS_LIBRESSL_BIN := $(BUILD_DIR)/test_pipeline_transport_https_libressl

$(PIPELINE_TRANSPORT_HTTPS_LIBRESSL_BIN): $(PIPELINE_TRANSPORT_HTTPS_LIBRESSL_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling Transport HTTPS LibreSSL test..."
ifdef USE_XDP
ifdef USE_LIBRESSL
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Transport HTTPS LibreSSL test build complete: $@"
else
	@echo "❌ Error: Transport HTTPS LibreSSL test requires USE_LIBRESSL=1"
	@exit 1
endif
else
	@echo "❌ Error: Transport HTTPS LibreSSL test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-transport_https_libressl: $(PIPELINE_TRANSPORT_HTTPS_LIBRESSL_BIN)

test-pipeline-transport-https-libressl: $(PIPELINE_TRANSPORT_HTTPS_LIBRESSL_BIN) bpf
	@echo "🧪 Running Transport HTTPS LibreSSL test via script..."
	./scripts/test_xdp.sh 14_transport_https_libressl.cpp

# ============================================================================
# Transport WSS Test (WebSocket Secure with WolfSSL against Binance)
# Tests WSS streaming against stream.binance.com:443
# ============================================================================

PIPELINE_TRANSPORT_WSS_SRC := test/pipeline/15_transport_wss.cpp
PIPELINE_TRANSPORT_WSS_BIN := $(BUILD_DIR)/test_pipeline_transport_wss

$(PIPELINE_TRANSPORT_WSS_BIN): $(PIPELINE_TRANSPORT_WSS_SRC) $(PIPELINE_HEADERS) $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling Transport WSS test..."
ifdef USE_XDP
ifdef USE_WOLFSSL
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Transport WSS test build complete: $@"
else
	@echo "❌ Error: Transport WSS test requires USE_WOLFSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: Transport WSS test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-transport_wss: $(PIPELINE_TRANSPORT_WSS_BIN)

test-pipeline-transport-wss: $(PIPELINE_TRANSPORT_WSS_BIN) bpf
	@echo "🧪 Running Transport WSS test via script..."
	./scripts/test_xdp.sh 15_transport_wss.cpp

# ============================================================================
# WebSocket Binance Test (WebSocketProcess with Binance WSS stream)
# Tests full pipeline: XDP Poll + Transport + WebSocket processes
# ============================================================================

PIPELINE_WEBSOCKET_BINANCE_SRC := test/pipeline/20_websocket_binance.cpp
PIPELINE_WEBSOCKET_BINANCE_BIN := $(BUILD_DIR)/test_pipeline_websocket_binance

$(PIPELINE_WEBSOCKET_BINANCE_BIN): $(PIPELINE_WEBSOCKET_BINANCE_SRC) $(PIPELINE_HEADERS) $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling WebSocket Binance test..."
ifneq (,$(or $(USE_XDP),$(USE_DPDK)))
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ WebSocket Binance test build complete: $@"
else
	@echo "❌ Error: WebSocket Binance test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: WebSocket Binance test requires USE_XDP=1 or USE_DPDK=1"
	@exit 1
endif

build-test-pipeline-websocket_binance: $(PIPELINE_WEBSOCKET_BINANCE_BIN)

test-pipeline-websocket-binance: $(PIPELINE_WEBSOCKET_BINANCE_BIN) bpf
	@echo "🧪 Running WebSocket Binance test via script..."
	./scripts/test_xdp.sh 20_websocket_binance.cpp

# ============================================================================
# Binance SBE Binary Protocol Test (WebSocketProcess with SBE binary stream)
# Tests full pipeline with SBE binary decoding via AppHandler
# ============================================================================

PIPELINE_BINANCE_SBE_SRC := test/pipeline/24_binance_sbe_xdp.cpp
PIPELINE_BINANCE_SBE_BIN := $(BUILD_DIR)/test_pipeline_binance_sbe_xdp

$(PIPELINE_BINANCE_SBE_BIN): $(PIPELINE_BINANCE_SBE_SRC) $(PIPELINE_HEADERS) src/msg/00_binance_spot_sbe.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling Binance SBE test..."
ifdef USE_XDP
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Binance SBE test build complete: $@"
else
	@echo "❌ Error: Binance SBE test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: Binance SBE test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-binance_sbe_xdp: $(PIPELINE_BINANCE_SBE_BIN)

test-pipeline-binance-sbe: $(PIPELINE_BINANCE_SBE_BIN) bpf
	@echo "🧪 Running Binance SBE test via script..."
	./scripts/test_xdp.sh 24_binance_sbe_xdp.cpp

# ============================================================================
# DPDK Binance SBE InlineWS Binary Protocol Test
# ============================================================================

PIPELINE_DPDK_BINANCE_SBE_SRC := test/pipeline/262_binance_sbe_dpdk_inline_ws.cpp
PIPELINE_DPDK_BINANCE_SBE_BIN := $(BUILD_DIR)/test_pipeline_262_binance_sbe_dpdk_inline_ws

$(PIPELINE_DPDK_BINANCE_SBE_BIN): $(PIPELINE_DPDK_BINANCE_SBE_SRC) $(PIPELINE_HEADERS) src/msg/00_binance_spot_sbe.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling DPDK Binance SBE InlineWS test..."
ifdef USE_DPDK
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ DPDK Binance SBE InlineWS test build complete: $@"
else
	@echo "❌ Error: DPDK Binance SBE InlineWS test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: DPDK Binance SBE InlineWS test requires USE_DPDK=1"
	@exit 1
endif

build-test-pipeline-262_binance_sbe_dpdk_inline_ws: $(PIPELINE_DPDK_BINANCE_SBE_BIN)

# ============================================================================
# DPDK DirectIO Binance SBE InlineWS Test (no poll process, DPDKPacketIO in transport)
# ============================================================================

PIPELINE_DPDK_DIRECTIO_SBE_SRC := test/pipeline/263_binance_sbe_dpdk_packetio_inline_ws.cpp
PIPELINE_DPDK_DIRECTIO_SBE_BIN := $(BUILD_DIR)/test_pipeline_263_binance_sbe_dpdk_packetio_inline_ws

$(PIPELINE_DPDK_DIRECTIO_SBE_BIN): $(PIPELINE_DPDK_DIRECTIO_SBE_SRC) $(PIPELINE_HEADERS) src/msg/00_binance_spot_sbe.hpp | $(BUILD_DIR)
	@echo "Compiling DPDK DirectIO Binance SBE InlineWS test..."
ifdef USE_DPDK
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "DPDK DirectIO Binance SBE InlineWS test build complete: $@"
else
	@echo "Error: DPDK DirectIO SBE InlineWS test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "Error: DPDK DirectIO SBE InlineWS test requires USE_DPDK=1"
	@exit 1
endif

build-test-pipeline-263_binance_sbe_dpdk_packetio_inline_ws: $(PIPELINE_DPDK_DIRECTIO_SBE_BIN)

# ============================================================================
# XDP DirectIO Binance SBE InlineWS Test (no poll process, XDPPacketIO in transport)
# ============================================================================

PIPELINE_XDP_DIRECTIO_SBE_SRC := test/pipeline/264_binance_sbe_xdp_packetio_inline_ws.cpp
PIPELINE_XDP_DIRECTIO_SBE_BIN := $(BUILD_DIR)/test_pipeline_264_binance_sbe_xdp_packetio_inline_ws

$(PIPELINE_XDP_DIRECTIO_SBE_BIN): $(PIPELINE_XDP_DIRECTIO_SBE_SRC) $(PIPELINE_HEADERS) src/msg/00_binance_spot_sbe.hpp | $(BUILD_DIR)
	@echo "Compiling XDP DirectIO Binance SBE InlineWS test..."
ifdef USE_XDP
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "XDP DirectIO Binance SBE InlineWS test build complete: $@"
else
	@echo "Error: XDP DirectIO SBE InlineWS test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "Error: XDP DirectIO SBE InlineWS test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-264_binance_sbe_xdp_packetio_inline_ws: $(PIPELINE_XDP_DIRECTIO_SBE_BIN)

# ============================================================================
# DPDK DirectIO Binance USDM JSON InlineWS Test (DPDKPacketIO, simdjson parser)
# ============================================================================

PIPELINE_DPDK_DIRECTIO_USDM_SRC := test/pipeline/270_binance_usdm_dpdk_packetio_inline_ws.cpp
PIPELINE_DPDK_DIRECTIO_USDM_BIN := $(BUILD_DIR)/test_pipeline_270_binance_usdm_dpdk_packetio_inline_ws

$(PIPELINE_DPDK_DIRECTIO_USDM_BIN): $(PIPELINE_DPDK_DIRECTIO_USDM_SRC) $(PIPELINE_HEADERS) src/msg/03_binance_usdm_simdjson.hpp $(BUILD_DIR)/simdjson.o | $(BUILD_DIR)
	@echo "Compiling DPDK DirectIO Binance USDM JSON InlineWS test..."
ifdef USE_DPDK
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(BUILD_DIR)/simdjson.o $(LDFLAGS)
	@echo "DPDK DirectIO USDM JSON InlineWS test build complete: $@"
else
	@echo "Error: DPDK DirectIO USDM test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "Error: DPDK DirectIO USDM test requires USE_DPDK=1"
	@exit 1
endif

build-test-pipeline-270_binance_usdm_dpdk_packetio_inline_ws: $(PIPELINE_DPDK_DIRECTIO_USDM_BIN)

# ============================================================================
# DPDK DirectIO Binance USDM 2-URL Split InlineWS Test (public + market endpoints)
# ============================================================================

PIPELINE_DPDK_DIRECTIO_USDM_2URL_SRC := test/pipeline/271_binance_usdm_2url_dpdk_packetio_inline_ws.cpp
PIPELINE_DPDK_DIRECTIO_USDM_2URL_BIN := $(BUILD_DIR)/test_pipeline_271_binance_usdm_2url_dpdk_packetio_inline_ws

$(PIPELINE_DPDK_DIRECTIO_USDM_2URL_BIN): $(PIPELINE_DPDK_DIRECTIO_USDM_2URL_SRC) $(PIPELINE_HEADERS) src/msg/03_binance_usdm_simdjson.hpp $(BUILD_DIR)/simdjson.o | $(BUILD_DIR)
	@echo "Compiling DPDK DirectIO Binance USDM 2-URL InlineWS test..."
ifdef USE_DPDK
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(BUILD_DIR)/simdjson.o $(LDFLAGS)
	@echo "DPDK DirectIO USDM 2-URL InlineWS test build complete: $@"
else
	@echo "Error: DPDK DirectIO USDM 2-URL test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "Error: DPDK DirectIO USDM 2-URL test requires USE_DPDK=1"
	@exit 1
endif

build-test-pipeline-271_binance_usdm_2url_dpdk_packetio_inline_ws: $(PIPELINE_DPDK_DIRECTIO_USDM_2URL_BIN)

# ============================================================================
# WebSocket OKX Test (WebSocketProcess with OKX WSS stream)
# Tests full pipeline: XDP Poll + Transport + WebSocket processes
# ============================================================================

PIPELINE_WEBSOCKET_OKX_SRC := test/pipeline/21_websocket_okx.cpp
PIPELINE_WEBSOCKET_OKX_BIN := $(BUILD_DIR)/test_pipeline_websocket_okx

$(PIPELINE_WEBSOCKET_OKX_BIN): $(PIPELINE_WEBSOCKET_OKX_SRC) $(PIPELINE_HEADERS) $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling WebSocket OKX test..."
ifdef USE_XDP
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ WebSocket OKX test build complete: $@"
else
	@echo "❌ Error: WebSocket OKX test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: WebSocket OKX test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-websocket_okx: $(PIPELINE_WEBSOCKET_OKX_BIN)

test-pipeline-websocket-okx: $(PIPELINE_WEBSOCKET_OKX_BIN) bpf
	@echo "🧪 Running WebSocket OKX test via script..."
	./scripts/test_xdp.sh 21_websocket_okx.cpp

# ============================================================================
# BSD Socket WebSocket Binance Test - 2-thread InlineSSL (test22)
# Uses kernel TCP via BSD sockets instead of XDP
# ============================================================================

PIPELINE_BSD_WS_BINANCE_2T_SRC := test/pipeline/22_websocket_binance_bsdsocket_2thread.cpp
PIPELINE_BSD_WS_BINANCE_2T_BIN := $(BUILD_DIR)/test_pipeline_websocket_binance_bsdsocket_2thread

$(PIPELINE_BSD_WS_BINANCE_2T_BIN): $(PIPELINE_BSD_WS_BINANCE_2T_SRC) $(PIPELINE_HEADERS) src/pipeline/11_bsd_tcp_ssl_process.hpp src/pipeline/bsd_websocket_pipeline.hpp src/net/ip_probe.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Socket WebSocket Binance 2-thread test..."
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL),$(USE_LIBRESSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ BSD Socket WebSocket Binance 2-thread test build complete: $@"
else
	@echo "❌ Error: BSD Socket WebSocket Binance test requires USE_WOLFSSL=1, USE_OPENSSL=1, or USE_LIBRESSL=1"
	@exit 1
endif

build-test-pipeline-websocket_binance_bsdsocket_2thread: $(PIPELINE_BSD_WS_BINANCE_2T_BIN)

# Default timeout for streaming test
TIMEOUT ?= 5000

test-pipeline-websocket-binance-bsdsocket-2thread: $(PIPELINE_BSD_WS_BINANCE_2T_BIN)
	@echo "🧪 Running BSD Socket WebSocket Binance 2-thread test..."
ifeq ($(UNAME_S),Darwin)
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./$(PIPELINE_BSD_WS_BINANCE_2T_BIN) --timeout $(TIMEOUT)
else
	./$(PIPELINE_BSD_WS_BINANCE_2T_BIN) --timeout $(TIMEOUT)
endif

# ============================================================================
# BSD Socket WebSocket Binance Test - 3-thread DedicatedSSL (test23)
# Uses kernel TCP via BSD sockets with separate SSL thread
# ============================================================================

PIPELINE_BSD_WS_BINANCE_3T_SRC := test/pipeline/23_websocket_binance_bsdsocket_3thread.cpp
PIPELINE_BSD_WS_BINANCE_3T_BIN := $(BUILD_DIR)/test_pipeline_websocket_binance_bsdsocket_3thread

$(PIPELINE_BSD_WS_BINANCE_3T_BIN): $(PIPELINE_BSD_WS_BINANCE_3T_SRC) $(PIPELINE_HEADERS) src/pipeline/11_bsd_tcp_ssl_process.hpp src/pipeline/bsd_websocket_pipeline.hpp src/net/ip_probe.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Socket WebSocket Binance 3-thread test..."
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL),$(USE_LIBRESSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ BSD Socket WebSocket Binance 3-thread test build complete: $@"
else
	@echo "❌ Error: BSD Socket WebSocket Binance test requires USE_WOLFSSL=1, USE_OPENSSL=1, or USE_LIBRESSL=1"
	@exit 1
endif

build-test-pipeline-websocket_binance_bsdsocket_3thread: $(PIPELINE_BSD_WS_BINANCE_3T_BIN)

test-pipeline-websocket-binance-bsdsocket-3thread: $(PIPELINE_BSD_WS_BINANCE_3T_BIN)
	@echo "🧪 Running BSD Socket WebSocket Binance 3-thread test..."
ifeq ($(UNAME_S),Darwin)
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./$(PIPELINE_BSD_WS_BINANCE_3T_BIN) --timeout $(TIMEOUT)
else
	./$(PIPELINE_BSD_WS_BINANCE_3T_BIN) --timeout $(TIMEOUT)
endif

# ============================================================================
# BSD Socket Binance SBE Test - 1-thread SingleThreadSSL (test252)
# Uses kernel TCP via BSD sockets with single-thread RX+TX loop + SBE binary protocol
# ============================================================================

PIPELINE_BSD_SBE_BINANCE_1T_SRC := test/pipeline/252_binance_sbe_bsdsocket_1thread.cpp
PIPELINE_BSD_SBE_BINANCE_1T_BIN := $(BUILD_DIR)/test_pipeline_252_binance_sbe_bsdsocket_1thread

$(PIPELINE_BSD_SBE_BINANCE_1T_BIN): $(PIPELINE_BSD_SBE_BINANCE_1T_SRC) $(PIPELINE_HEADERS) src/pipeline/11_bsd_tcp_ssl_process.hpp src/pipeline/bsd_websocket_pipeline.hpp src/net/ip_probe.hpp src/msg/00_binance_spot_sbe.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Socket Binance SBE 1-thread test..."
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL),$(USE_LIBRESSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ BSD Socket Binance SBE 1-thread test build complete: $@"
else
	@echo "❌ Error: BSD Socket Binance SBE test requires USE_WOLFSSL=1, USE_OPENSSL=1, or USE_LIBRESSL=1"
	@exit 1
endif

build-test-pipeline-252_binance_sbe_bsdsocket_1thread: $(PIPELINE_BSD_SBE_BINANCE_1T_BIN)

test-pipeline-252-binance-sbe-bsdsocket-1thread: $(PIPELINE_BSD_SBE_BINANCE_1T_BIN)
	@echo "🧪 Running BSD Socket Binance SBE 1-thread test..."
ifeq ($(UNAME_S),Darwin)
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./$(PIPELINE_BSD_SBE_BINANCE_1T_BIN) --timeout $(TIMEOUT)
else
	./$(PIPELINE_BSD_SBE_BINANCE_1T_BIN) --timeout $(TIMEOUT)
endif

# ============================================================================
# BSD Socket Binance SBE Test - 2-thread InlineSSL (test250)
# Uses kernel TCP via BSD sockets with SBE binary protocol
# ============================================================================

PIPELINE_BSD_SBE_BINANCE_2T_SRC := test/pipeline/250_binance_sbe_bsdsocket_2thread.cpp
PIPELINE_BSD_SBE_BINANCE_2T_BIN := $(BUILD_DIR)/test_pipeline_250_binance_sbe_bsdsocket_2thread

$(PIPELINE_BSD_SBE_BINANCE_2T_BIN): $(PIPELINE_BSD_SBE_BINANCE_2T_SRC) $(PIPELINE_HEADERS) src/pipeline/11_bsd_tcp_ssl_process.hpp src/pipeline/bsd_websocket_pipeline.hpp src/net/ip_probe.hpp src/msg/00_binance_spot_sbe.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Socket Binance SBE 2-thread test..."
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL),$(USE_LIBRESSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ BSD Socket Binance SBE 2-thread test build complete: $@"
else
	@echo "❌ Error: BSD Socket Binance SBE test requires USE_WOLFSSL=1, USE_OPENSSL=1, or USE_LIBRESSL=1"
	@exit 1
endif

build-test-pipeline-250_binance_sbe_bsdsocket_2thread: $(PIPELINE_BSD_SBE_BINANCE_2T_BIN)

test-pipeline-250-binance-sbe-bsdsocket-2thread: $(PIPELINE_BSD_SBE_BINANCE_2T_BIN)
	@echo "🧪 Running BSD Socket Binance SBE 2-thread test..."
ifeq ($(UNAME_S),Darwin)
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./$(PIPELINE_BSD_SBE_BINANCE_2T_BIN) --timeout $(TIMEOUT)
else
	./$(PIPELINE_BSD_SBE_BINANCE_2T_BIN) --timeout $(TIMEOUT)
endif

# ============================================================================
# BSD Socket Binance SBE Test - 3-thread DedicatedSSL (test251)
# Uses kernel TCP via BSD sockets with separate SSL thread + SBE binary protocol
# ============================================================================

PIPELINE_BSD_SBE_BINANCE_3T_SRC := test/pipeline/251_binance_sbe_bsdsocket_3thread.cpp
PIPELINE_BSD_SBE_BINANCE_3T_BIN := $(BUILD_DIR)/test_pipeline_251_binance_sbe_bsdsocket_3thread

$(PIPELINE_BSD_SBE_BINANCE_3T_BIN): $(PIPELINE_BSD_SBE_BINANCE_3T_SRC) $(PIPELINE_HEADERS) src/pipeline/11_bsd_tcp_ssl_process.hpp src/pipeline/bsd_websocket_pipeline.hpp src/net/ip_probe.hpp src/msg/00_binance_spot_sbe.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Socket Binance SBE 3-thread test..."
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL),$(USE_LIBRESSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ BSD Socket Binance SBE 3-thread test build complete: $@"
else
	@echo "❌ Error: BSD Socket Binance SBE test requires USE_WOLFSSL=1, USE_OPENSSL=1, or USE_LIBRESSL=1"
	@exit 1
endif

build-test-pipeline-251_binance_sbe_bsdsocket_3thread: $(PIPELINE_BSD_SBE_BINANCE_3T_BIN)

test-pipeline-251-binance-sbe-bsdsocket-3thread: $(PIPELINE_BSD_SBE_BINANCE_3T_BIN)
	@echo "🧪 Running BSD Socket Binance SBE 3-thread test..."
ifeq ($(UNAME_S),Darwin)
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./$(PIPELINE_BSD_SBE_BINANCE_3T_BIN) --timeout $(TIMEOUT)
else
	./$(PIPELINE_BSD_SBE_BINANCE_3T_BIN) --timeout $(TIMEOUT)
endif

# ============================================================================
# BSD Socket Binance SBE Test - InlineWS (test253)
# Transport + WS in single process — no IPC rings between transport and WS
# ============================================================================

PIPELINE_BSD_SBE_BINANCE_INLINE_SRC := test/pipeline/253_binance_sbe_bsdsocket_inline_ws.cpp
PIPELINE_BSD_SBE_BINANCE_INLINE_BIN := $(BUILD_DIR)/test_pipeline_253_binance_sbe_bsdsocket_inline_ws

$(PIPELINE_BSD_SBE_BINANCE_INLINE_BIN): $(PIPELINE_BSD_SBE_BINANCE_INLINE_SRC) $(PIPELINE_HEADERS) src/pipeline/11_bsd_tcp_ssl_process.hpp src/pipeline/21_ws_core.hpp src/pipeline/bsd_websocket_pipeline.hpp src/net/ip_probe.hpp src/msg/00_binance_spot_sbe.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Socket Binance SBE InlineWS test..."
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL),$(USE_LIBRESSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ BSD Socket Binance SBE InlineWS test build complete: $@"
else
	@echo "❌ Error: BSD Socket Binance SBE test requires USE_WOLFSSL=1, USE_OPENSSL=1, or USE_LIBRESSL=1"
	@exit 1
endif

build-test-pipeline-253_binance_sbe_bsdsocket_inline_ws: $(PIPELINE_BSD_SBE_BINANCE_INLINE_BIN)

test-pipeline-253-binance-sbe-bsdsocket-inline-ws: $(PIPELINE_BSD_SBE_BINANCE_INLINE_BIN)
	@echo "🧪 Running BSD Socket Binance SBE InlineWS test..."
ifeq ($(UNAME_S),Darwin)
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./$(PIPELINE_BSD_SBE_BINANCE_INLINE_BIN) --timeout $(TIMEOUT)
else
	./$(PIPELINE_BSD_SBE_BINANCE_INLINE_BIN) --timeout $(TIMEOUT)
endif

# ============================================================================
# Binance SBE XDP InlineWS Test (Transport + WS in single process, XDP)
# 2 processes total: XDP Poll + InlineWS Transport
# ============================================================================

PIPELINE_XDP_SBE_INLINE_SRC := test/pipeline/261_binance_sbe_xdp_inline_ws.cpp
PIPELINE_XDP_SBE_INLINE_BIN := $(BUILD_DIR)/test_pipeline_261_binance_sbe_xdp_inline_ws

$(PIPELINE_XDP_SBE_INLINE_BIN): $(PIPELINE_XDP_SBE_INLINE_SRC) $(PIPELINE_HEADERS) src/pipeline/21_ws_core.hpp src/msg/00_binance_spot_sbe.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling XDP Binance SBE InlineWS test..."
ifdef USE_XDP
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ XDP Binance SBE InlineWS test build complete: $@"
else
	@echo "❌ Error: XDP Binance SBE InlineWS test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: XDP Binance SBE InlineWS test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-261_binance_sbe_xdp_inline_ws: $(PIPELINE_XDP_SBE_INLINE_BIN)

test-pipeline-261-binance-sbe-xdp-inline-ws: $(PIPELINE_XDP_SBE_INLINE_BIN) bpf
	@echo "🧪 Running XDP Binance SBE InlineWS test via script..."
	./scripts/test_xdp.sh 261_binance_sbe_xdp_inline_ws.cpp

# ============================================================================
# MktEvent Ring Reader Tool
# Standalone utility to read and print MktEvent shared memory ring
# ============================================================================

MKT_EVENT_READER_SRC := tools/mkt_event_reader.cpp
MKT_EVENT_READER_BIN := $(BUILD_DIR)/mkt_event_reader

$(MKT_EVENT_READER_BIN): $(MKT_EVENT_READER_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling MktEvent reader..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ MktEvent reader build complete: $@"

build-mkt-event-reader: $(MKT_EVENT_READER_BIN)

# ============================================================================
# MktEvent Full-Screen Viewer Tool
# Live TUI: orderbook + trades + event log from MktEvent shared memory ring
# ============================================================================

MKT_VIEWER_SRC := tools/mkt_viewer.cpp
MKT_VIEWER_BIN := $(BUILD_DIR)/mkt_viewer

$(MKT_VIEWER_BIN): $(MKT_VIEWER_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling MktEvent viewer..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ MktEvent viewer build complete: $@"

build-mkt-viewer: $(MKT_VIEWER_BIN)

# ============================================================================
# MktEvent Sampling Tool
# Captures WSFrameInfo + raw payloads + MktEvents for offline verification
# ============================================================================

MKT_SAMPLING_SRC := tools/mkt_sampling.cpp
MKT_SAMPLING_BIN := $(BUILD_DIR)/mkt_sampling

$(MKT_SAMPLING_BIN): $(MKT_SAMPLING_SRC) $(PIPELINE_HEADERS) | $(BUILD_DIR)
	@echo "🔨 Compiling MktEvent sampler..."
	$(CXX) $(CXXFLAGS) -o $@ $<
	@echo "✅ MktEvent sampler build complete: $@"

build-mkt-sampling: $(MKT_SAMPLING_BIN)

# ============================================================================
# Unified XDP+TCP+SSL+WS Pipeline Test (Single-Process)
# Tests unified pipeline: all layers in one process, outputs to IPC rings
# ============================================================================

PIPELINE_UNIFIED_BINANCE_SRC := test/pipeline/99_websocket_binance_1_proc.cpp
PIPELINE_UNIFIED_BINANCE_BIN := $(BUILD_DIR)/test_pipeline_99_websocket_binance

$(PIPELINE_UNIFIED_BINANCE_BIN): $(PIPELINE_UNIFIED_BINANCE_SRC) $(PIPELINE_HEADERS) src/pipeline/99_xdp_tcp_ssl_ws_process.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling Unified XDP+TCP+SSL+WS Pipeline test..."
ifdef USE_XDP
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Unified Pipeline test build complete: $@"
else
	@echo "❌ Error: Unified Pipeline test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: Unified Pipeline test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-unified_binance: $(PIPELINE_UNIFIED_BINANCE_BIN)

test-pipeline-unified-binance: $(PIPELINE_UNIFIED_BINANCE_BIN) bpf
	@echo "🧪 Running Unified Pipeline Binance test via script..."
	./scripts/test_xdp.sh 99_websocket_binance.cpp

# ============================================================================
# UnifiedSSL + WebSocket Pipeline Test (98_*)
# Two processes: UnifiedSSL (XDP+TCP+SSL) + WebSocket (frame parsing)
# ============================================================================

PIPELINE_98_BINANCE_SRC := test/pipeline/98_websocket_binance_piotransport_ws.cpp
PIPELINE_98_BINANCE_BIN := $(BUILD_DIR)/test_pipeline_98_websocket_binance

$(PIPELINE_98_BINANCE_BIN): $(PIPELINE_98_BINANCE_SRC) $(PIPELINE_HEADERS) src/pipeline/98_xdp_tcp_ssl_process.hpp src/pipeline/20_ws_process.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling UnifiedSSL + WebSocket Pipeline test (98_*)..."
ifdef USE_XDP
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ UnifiedSSL + WebSocket Pipeline test build complete: $@"
else
	@echo "❌ Error: 98_* test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: 98_* test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-98_websocket_binance: $(PIPELINE_98_BINANCE_BIN)

test-pipeline-98-binance: $(PIPELINE_98_BINANCE_BIN) bpf
	@echo "🧪 Running UnifiedSSL + WebSocket Pipeline test via script..."
	./scripts/test_xdp.sh 98_websocket_binance.cpp

# ============================================================================
# 96_websocket_binance - Three-Process Pipeline Test (XDP Poll + PIO Transport + WebSocket)
# Three processes: XDP Poll + PIO Transport (TCP+SSL via DisruptorPacketIO) + WebSocket
# ============================================================================

PIPELINE_96_BINANCE_SRC := test/pipeline/96_websocket_binance_xdp_piotransport_ws.cpp
PIPELINE_96_BINANCE_BIN := $(BUILD_DIR)/test_pipeline_96_websocket_binance

$(PIPELINE_96_BINANCE_BIN): $(PIPELINE_96_BINANCE_SRC) $(PIPELINE_HEADERS) src/pipeline/00_xdp_poll_process.hpp src/pipeline/10_tcp_ssl_process.hpp src/pipeline/disruptor_packet_io.hpp src/pipeline/20_ws_process.hpp $(SSL_BACKEND_SENTINEL) | $(BUILD_DIR)
	@echo "🔨 Compiling XDP Poll + PIO Transport + WebSocket Pipeline test (96_*)..."
ifdef USE_XDP
ifneq (,$(or $(USE_WOLFSSL),$(USE_OPENSSL)))
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ XDP Poll + PIO Transport + WebSocket Pipeline test build complete: $@"
else
	@echo "❌ Error: 96_* test requires USE_WOLFSSL=1 or USE_OPENSSL=1"
	@exit 1
endif
else
	@echo "❌ Error: 96_* test requires USE_XDP=1"
	@exit 1
endif

build-test-pipeline-96_websocket_binance: $(PIPELINE_96_BINANCE_BIN)

test-pipeline-96-binance: $(PIPELINE_96_BINANCE_BIN) bpf
	@echo "🧪 Running XDP Poll + PIO Transport + WebSocket Pipeline test via script..."
	./scripts/test_xdp.sh 96_websocket_binance.cpp

# ============================================================================
# BSD Socket Transport SSL Tests (separate by SSL library)
# Tests 2-thread (InlineSSL) and 3-thread (DedicatedSSL) modes
# ============================================================================

# SSL library paths for explicit linking
ifeq ($(UNAME_S),Darwin)
    WOLFSSL_INC := -I$(HOME)/Proj/wolfssl
    WOLFSSL_LIB := -L$(HOME)/Proj/wolfssl/src/.libs -Wl,-rpath,$(HOME)/Proj/wolfssl/src/.libs -lwolfssl
    OPENSSL_INC := -I$(HOME)/Proj/openssl/include
    OPENSSL_LIB := -L$(HOME)/Proj/openssl -Wl,-rpath,$(HOME)/Proj/openssl -lssl -lcrypto
    LIBRESSL_INC := -I$(HOME)/Proj/libressl/install/include
    LIBRESSL_LIB := -L$(HOME)/Proj/libressl/install/lib -Wl,-rpath,$(HOME)/Proj/libressl/install/lib -lssl -lcrypto
else
    WOLFSSL_INC := -I$(HOME)/Proj/wolfssl/install/include
    WOLFSSL_LIB := -L$(HOME)/Proj/wolfssl/install/lib -Wl,-rpath,$(HOME)/Proj/wolfssl/install/lib -lwolfssl
    OPENSSL_INC := -I$(HOME)/Proj/openssl/install/include
    OPENSSL_LIB := -L$(HOME)/Proj/openssl/install/lib64 -Wl,-rpath,$(HOME)/Proj/openssl/install/lib64 -lssl -lcrypto
    LIBRESSL_INC := -I$(HOME)/Proj/libressl/install/include
    LIBRESSL_LIB := -L$(HOME)/Proj/libressl/install/lib -Wl,-rpath,$(HOME)/Proj/libressl/install/lib -lssl -lcrypto
endif

# Base CXXFLAGS without SSL-specific flags
BASE_CXXFLAGS := -std=c++20 -O3 -march=native -Wall -Wextra -I./src -I../01_shared_headers -DNIC_MTU=$(NIC_MTU)
ifeq ($(UNAME_S),Darwin)
    BASE_CXXFLAGS += -D__APPLE__
else
    BASE_CXXFLAGS += -D__linux__
endif

# --- OpenSSL Test ---
PIPELINE_BSD_OPENSSL_SRC := test/pipeline/112_bsd_transport_openssl.cpp
PIPELINE_BSD_OPENSSL_BIN := $(BUILD_DIR)/test_pipeline_bsd_transport_openssl

$(PIPELINE_BSD_OPENSSL_BIN): $(PIPELINE_BSD_OPENSSL_SRC) src/pipeline/11_bsd_tcp_ssl_process.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Transport OpenSSL test..."
	$(CXX) $(BASE_CXXFLAGS) $(OPENSSL_INC) -o $@ $< $(OPENSSL_LIB)
	@echo "✅ BSD Transport OpenSSL test build complete: $@"

build-test-pipeline-bsd-transport-openssl: $(PIPELINE_BSD_OPENSSL_BIN)

# Usage: make test-pipeline-bsd-transport-openssl           # Test both 2-thread + 3-thread
#        make test-pipeline-bsd-transport-openssl MODE=2thread  # 2-thread InlineSSL only
#        make test-pipeline-bsd-transport-openssl MODE=3thread  # 3-thread DedicatedSSL only
test-pipeline-bsd-transport-openssl: $(PIPELINE_BSD_OPENSSL_BIN)
	@echo "🧪 Running BSD Transport OpenSSL test..."
	./$(PIPELINE_BSD_OPENSSL_BIN) $(MODE)

# --- WolfSSL Test ---
PIPELINE_BSD_WOLFSSL_SRC := test/pipeline/112_bsd_transport_wolfssl.cpp
PIPELINE_BSD_WOLFSSL_BIN := $(BUILD_DIR)/test_pipeline_bsd_transport_wolfssl

$(PIPELINE_BSD_WOLFSSL_BIN): $(PIPELINE_BSD_WOLFSSL_SRC) src/pipeline/11_bsd_tcp_ssl_process.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Transport WolfSSL test..."
	$(CXX) $(BASE_CXXFLAGS) $(WOLFSSL_INC) -DHAVE_WOLFSSL -o $@ $< $(WOLFSSL_LIB)
	@echo "✅ BSD Transport WolfSSL test build complete: $@"

build-test-pipeline-bsd-transport-wolfssl: $(PIPELINE_BSD_WOLFSSL_BIN)

test-pipeline-bsd-transport-wolfssl: $(PIPELINE_BSD_WOLFSSL_BIN)
	@echo "🧪 Running BSD Transport WolfSSL test..."
ifeq ($(UNAME_S),Darwin)
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./$(PIPELINE_BSD_WOLFSSL_BIN) $(MODE)
else
	./$(PIPELINE_BSD_WOLFSSL_BIN) $(MODE)
endif

# --- LibreSSL Test ---
PIPELINE_BSD_LIBRESSL_SRC := test/pipeline/112_bsd_transport_libressl.cpp
PIPELINE_BSD_LIBRESSL_BIN := $(BUILD_DIR)/test_pipeline_bsd_transport_libressl

$(PIPELINE_BSD_LIBRESSL_BIN): $(PIPELINE_BSD_LIBRESSL_SRC) src/pipeline/11_bsd_tcp_ssl_process.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Transport LibreSSL test..."
	$(CXX) $(BASE_CXXFLAGS) $(LIBRESSL_INC) -DUSE_LIBRESSL -o $@ $< $(LIBRESSL_LIB)
	@echo "✅ BSD Transport LibreSSL test build complete: $@"

build-test-pipeline-bsd-transport-libressl: $(PIPELINE_BSD_LIBRESSL_BIN)

test-pipeline-bsd-transport-libressl: $(PIPELINE_BSD_LIBRESSL_BIN)
	@echo "🧪 Running BSD Transport LibreSSL test..."
	./$(PIPELINE_BSD_LIBRESSL_BIN) $(MODE)

# ============================================================================
# BSD Socket Transport TCP Test (NoSSLPolicy, no XDP required)
# ============================================================================

PIPELINE_BSD_TRANSPORT_TCP_SRC := test/pipeline/110_bsd_transport_tcp.cpp
PIPELINE_BSD_TRANSPORT_TCP_BIN := $(BUILD_DIR)/test_pipeline_bsd_transport_tcp

# Build BSD Transport TCP test (no USE_XDP required - uses kernel TCP)
$(PIPELINE_BSD_TRANSPORT_TCP_BIN): $(PIPELINE_BSD_TRANSPORT_TCP_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling BSD Transport TCP test..."
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ BSD Transport TCP test build complete: $@"

# Build-only target for BSD Transport TCP test
build-test-pipeline-bsd-transport-tcp: $(PIPELINE_BSD_TRANSPORT_TCP_BIN)

# Run BSD Transport TCP test with localhost echo server (default)
# No XDP/BPF required - uses standard BSD sockets with kernel TCP
# Usage: make test-pipeline-bsd-transport-tcp              # localhost echo (default)
#        make test-pipeline-bsd-transport-tcp ECHO_TARGET=139.162.79.171:12345  # remote
ECHO_TARGET ?= localhost
test-pipeline-bsd-transport-tcp: $(PIPELINE_BSD_TRANSPORT_TCP_BIN)
	@echo "🧪 Running BSD Transport TCP test ($(ECHO_TARGET))..."
	./$(PIPELINE_BSD_TRANSPORT_TCP_BIN) $(subst :, ,$(ECHO_TARGET))

# ============================================================================
# BSD Socket Transport io_uring Test (Option E - Linux only)
# ============================================================================

PIPELINE_BSD_IOURING_SRC := test/pipeline/111_bsd_transport_iouring.cpp
PIPELINE_BSD_IOURING_BIN := $(BUILD_DIR)/test_pipeline_bsd_transport_iouring

# Build io_uring Transport test (Linux only, requires liburing)
$(PIPELINE_BSD_IOURING_BIN): $(PIPELINE_BSD_IOURING_SRC) | $(BUILD_DIR)
ifeq ($(OS),Linux)
	@echo "🔨 Compiling io_uring Transport test (Option E)..."
	$(CXX) -std=c++20 -O3 -march=native -Wall -Wextra $(INCLUDES) -o $@ $< -luring -lpthread
	@echo "✅ io_uring Transport test build complete: $@"
else
	@echo "⚠️  io_uring Transport test is Linux-only (skipping on $(OS))"
endif

# Build-only target for io_uring Transport test
build-test-pipeline-bsd-transport-iouring: $(PIPELINE_BSD_IOURING_BIN)

# Run io_uring Transport test with localhost echo server (default)
# Requires: Linux 5.1+ with io_uring support, liburing
# Usage: make test-pipeline-bsd-transport-iouring
#        make test-pipeline-bsd-transport-iouring ECHO_TARGET=139.162.79.171:12345
test-pipeline-bsd-transport-iouring: $(PIPELINE_BSD_IOURING_BIN)
ifeq ($(OS),Linux)
	@echo "🧪 Running io_uring Transport test ($(ECHO_TARGET))..."
	./$(PIPELINE_BSD_IOURING_BIN) $(subst :, ,$(ECHO_TARGET))
else
	@echo "⚠️  io_uring Transport test is Linux-only (skipping on $(OS))"
endif

# ============================================================================
# Unified BSD Socket Transport Test (all configurations)
# ============================================================================

PIPELINE_BSD_UNIFIED_SRC := test/pipeline/113_bsd_transport.cpp
PIPELINE_BSD_UNIFIED_BIN := $(BUILD_DIR)/test_pipeline_bsd_transport

# Build unified BSD Transport test (tests all configurations)
$(PIPELINE_BSD_UNIFIED_BIN): $(PIPELINE_BSD_UNIFIED_SRC) src/pipeline/11_bsd_tcp_ssl_process.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling unified BSD Transport test..."
ifeq ($(UNAME_S),Linux)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS) -luring
else
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
endif
	@echo "✅ Unified BSD Transport test build complete: $@"

# Build-only target
build-test-pipeline-bsd-transport: $(PIPELINE_BSD_UNIFIED_BIN)

# Run unified BSD Transport test
# Usage: make test-pipeline-bsd-transport              # Test all configs
#        make test-pipeline-bsd-transport MODE=2thread  # 2-thread only
#        make test-pipeline-bsd-transport MODE=iouring  # io_uring only (Linux)
MODE ?=
test-pipeline-bsd-transport: $(PIPELINE_BSD_UNIFIED_BIN)
	@echo "🧪 Running unified BSD Transport test..."
ifeq ($(UNAME_S),Darwin)
	OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ./$(PIPELINE_BSD_UNIFIED_BIN) $(MODE)
else
	./$(PIPELINE_BSD_UNIFIED_BIN) $(MODE)
endif

# ============================================================================
# HftShm RingBuffer Tests (requires hft-shm CLI)
# ============================================================================

# Build HftShm ringbuffer tests
$(TEST_HFTSHM_BIN): $(TEST_HFTSHM_SRC) src/ringbuffer.hpp | $(BUILD_DIR)
	@echo "🔨 Compiling HftShm ringbuffer unit tests..."
	$(CXX) -std=c++20 -O3 -march=native -Wall -Wextra -I./src -DUSE_HFTSHM -o $@ $<
	@echo "✅ Test build complete: $@"

# Run HftShm ringbuffer tests
# Uses test/shmem.toml by default, override with HFT_SHM_CONFIG env var
HFT_SHM_CONFIG ?= $(CURDIR)/test/shmem.toml

test-hftshm: $(TEST_HFTSHM_BIN)
	@echo "🧪 Running HftShm ringbuffer unit tests..."
	@echo "📋 Prerequisites:"
	@echo "    - hft-shm CLI installed and in PATH"
	@echo "    - Test segments created: hft-shm init --config test/shmem.toml"
	@echo ""
	HFT_SHM_CONFIG="$(HFT_SHM_CONFIG)" ./$(TEST_HFTSHM_BIN)

# ============================================================================
# Binance TX/RX Integration Test (Shared Memory)
# ============================================================================
# Single executable - spawns consumer thread, main thread runs producer
#   - Producer: ShmWebSocketClient writes to RX shm (runtime path)
#   - Consumer: RXRingBufferConsumer reads from RX shm
#
# Prerequisites: hft-shm init --config ~/hft.toml (creates shared memory files)

BINANCE_TXRX_SRC := test/integration/binance_txrx.cpp
BINANCE_TXRX_BIN := $(BUILD_DIR)/binance_txrx

# Build Binance TX/RX test (C++17, no USE_HFTSHM required)
$(BINANCE_TXRX_BIN): $(BINANCE_TXRX_SRC) $(HEADERS) src/ringbuffer.hpp | $(BUILD_DIR)
	@echo "Building Binance TX/RX integration test..."
	$(CXX) $(CXX_STD) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

# Build-only target
test-binance-shm: $(BINANCE_TXRX_BIN)
	@echo "Built: $(BINANCE_TXRX_BIN)"
	@echo ""
	@echo "Usage: ./build/binance_txrx"
	@echo "Prerequisites: hft-shm init --config ~/hft.toml"

# ============================================================================
# Traffic Simulator - Replay debug_traffic.dat through frame parser
# ============================================================================
TRAFFIC_SIM_SRC := test/traffic_simulator.cpp
TRAFFIC_SIM_BIN := $(BUILD_DIR)/traffic_simulator

$(TRAFFIC_SIM_BIN): $(TRAFFIC_SIM_SRC) | $(BUILD_DIR)
	@echo "Building traffic simulator..."
	$(CXX) $(CXXFLAGS) -I./src -I../01_shared_headers -o $@ $<
	@echo "Built: $@"

test-traffic-sim: $(TRAFFIC_SIM_BIN)
	@echo ""
	@echo "Usage: ./build/traffic_simulator [debug_traffic.dat]"
	@echo "Replays recorded SSL traffic through frame parser to detect issues"

# ============================================================================
# WebSocket Simulator - Replay debug_traffic.dat through real frame parser
# Uses SimulatorReplayClient (SimulatorTransport + NoSSLPolicy)
# ============================================================================

SIMULATOR_SRC := test/test_simulator.cpp
SIMULATOR_BIN := $(BUILD_DIR)/test_simulator

$(SIMULATOR_BIN): $(SIMULATOR_SRC) src/ws_configs.hpp src/websocket.hpp src/ringbuffer.hpp src/policy/simulator_transport.hpp | $(BUILD_DIR)
	@echo "Building WebSocket simulator..."
	$(CXX) $(CXXFLAGS) -I./src -I../01_shared_headers -o $@ $<
	@echo "Built: $@"

test-simulator: $(SIMULATOR_BIN)
	@echo ""
	@echo "Usage: ./build/test_simulator [debug_traffic.dat]"
	@echo "Replays recorded traffic through WebSocket frame parser"

# ============================================================================
# Unified Test Target - Run All Unit Tests
# ============================================================================

test: test-ringbuffer test-event test-bug-fixes test-new-bug-fixes test-aes-ctr-seq test-tls13-inner-ct test-wolfssl-seq-num test-last-byte-ts test-xdp-transport test-xdp-frame test-xdp-send-recv test-core-http test-ip-layer test-ip-optimizations test-stack-checksum test-tcp-state test-retransmit-queue test-ssl-policy test-watchdog-policy test-tx-pool-fifo test-ws-parser test-sbe-decoder test-sbe-handler test-usdm-json-parser test-orderbook test-mkt-viewer-dedup test-mkt-event-bitfields
	@echo ""
	@echo "╔════════════════════════════════════════════════════════════════════╗"
	@echo "║                    ALL UNIT TESTS COMPLETED                        ║"
	@echo "╚════════════════════════════════════════════════════════════════════╝"

# ============================================================================
# BPF (eBPF) Program Compilation
# ============================================================================

BPF_SRC := src/xdp/bpf/exchange_filter.bpf.c
BPF_OBJ := src/xdp/bpf/exchange_filter.bpf.o
CLANG := clang
BPFTOOL := bpftool

# Compile BPF program to object file
$(BPF_OBJ): $(BPF_SRC)
	@echo "🔨 Compiling eBPF program..."
	@$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_x86_64 \
		-I/usr/include/bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c $< -o $@
	@echo "✅ BPF object created: $@"

# Target to build BPF program (can be called explicitly)
bpf: $(BPF_OBJ)

# Clean BPF objects
clean-bpf:
	rm -f $(BPF_OBJ)

# Clean build artifacts
clean: clean-bpf
	rm -rf $(BUILD_DIR)
	@echo "🧹 Cleaned build artifacts"

# ============================================================================
# Variant builds
# ============================================================================

# Build with epoll + LibreSSL (Linux only, io_uring is default)
epoll:
	@echo "🔧 Building epoll + LibreSSL variant..."
	$(MAKE) all USE_IOURING=0

# Build optimized for production
release: CXXFLAGS += -DNDEBUG -flto
release: all
	@echo "✅ Release build complete"

# Build with debug symbols
debug: CXXFLAGS := -std=c++20 -g -O0 -Wall -Wextra -I./src
debug: all
	@echo "🐛 Debug build complete"

# ============================================================================
# Additional checks
# ============================================================================

# Check if kTLS is available (Linux only)
check-ktls:
ifeq ($(UNAME_S),Linux)
	@echo "🔍 Checking kTLS support..."
	@lsmod | grep -q tls && echo "✅ kTLS kernel module loaded" || echo "❌ kTLS module not loaded (run: sudo modprobe tls)"
	@uname -r | awk -F. '{ if ($$1 >= 5 || ($$1 == 4 && $$2 >= 17)) print "✅ Kernel version supports kTLS"; else print "❌ Kernel too old for kTLS (need 4.17+)" }'
else
	@echo "⚠️  kTLS is only available on Linux"
endif

# ============================================================================
# Help
# ============================================================================

help:
	@echo "WebSocket Policy-Based Library - Makefile"
	@echo "=========================================="
	@echo ""
	@echo "Build Targets:"
	@echo "  make              - Build main example (build/ws_example)"
	@echo "  make run          - Build and run WebSocket example"
	@echo "  make bpf          - Compile eBPF program for XDP"
	@echo "  make release      - Build optimized release version"
	@echo "  make debug        - Build with debug symbols"
	@echo "  make epoll        - Build with epoll (no io_uring)"
	@echo "  make clean        - Remove build artifacts"
	@echo ""
	@echo "Unit Tests:"
	@echo "  make test               - Run ALL unit tests"
	@echo "  make test-ringbuffer    - Test ring buffer implementation"
	@echo "  make test-shm-ringbuffer - Test shared memory ring buffer"
	@echo "  make test-event         - Test event policies (epoll/kqueue/select)"
	@echo "  make test-bug-fixes     - Verify bug fixes #1-10"
	@echo "  make test-new-bug-fixes - Verify bug fixes #11-20"
	@echo "  make test-xdp-transport - Test XDP transport layer"
	@echo "  make test-xdp-frame     - Test XDP frame handling"
	@echo "  make test-xdp-send-recv - Test XDP send/receive operations"
	@echo "  make test-core-http     - Test HTTP parsing for WebSocket"
	@echo "  make test-ip-layer      - Test userspace IP layer"
	@echo "  make test-ip-optimizations - Test IP layer optimizations"
	@echo "  make test-stack-checksum - Test TCP/IP checksum calculations"
	@echo "  make test-tcp-state     - Test TCP state machine"
	@echo "  make test-ssl-policy    - Test SSL policy zero-copy API"
	@echo "  make test-ws-parser     - Test WebSocket frame parser"
	@echo "  make test-hftshm        - Test HftShmRingBuffer (requires hft-shm CLI)"
	@echo ""
	@echo "Integration Tests:"
	@echo "  make test-binance       - BSD socket test with Binance (20 msgs)"
	@echo "  make test-xdp-binance   - XDP zero-copy test with Binance (requires sudo)"
	@echo "  make test-pipeline-xdp-poll - XDP Poll segregated test (wire loopback, sudo)"
	@echo "  make test-pipeline-transport-http - Plain HTTP test against ipinfo.io:80"
	@echo ""
	@echo "Benchmark:"
	@echo "  make benchmark-binance  - Latency benchmark (100 warmup, 300 samples)"
	@echo ""
	@echo "Diagnostics:"
	@echo "  make check-ktls   - Check if kTLS is available (Linux)"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  USE_IOURING=0     - Disable io_uring, use epoll (Linux only)"
	@echo "  USE_OPENSSL=1     - Use OpenSSL instead of LibreSSL"
	@echo "  USE_WOLFSSL=1     - Use WolfSSL instead of LibreSSL"
	@echo "  USE_XDP=1         - Enable XDP support (Linux only, requires libbpf/libxdp)"
	@echo "  USE_HFTSHM=1      - Enable hft-shm shared memory buffer support"
	@echo "  CXX=clang++       - Use Clang compiler"
	@echo ""
	@echo "Quick start:"
	@echo "  make run                          # Run WebSocket example"
	@echo "  USE_OPENSSL=1 make test-binance   # BSD socket test"
	@echo "  USE_XDP=1 USE_OPENSSL=1 make test-xdp-binance  # XDP test"
