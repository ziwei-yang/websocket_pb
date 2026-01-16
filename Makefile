# Makefile for WebSocket Policy-Based Library
# Supports: Linux (epoll, io_uring) and macOS (kqueue)

CXX := g++
CXXFLAGS := -std=c++20 -O3 -march=native -Wall -Wextra -I./src -I../01_shared_headers
LDFLAGS :=

# Debug mode - enables verbose debug prints
ifdef DEBUG
    CXXFLAGS += -DDEBUG
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
        CXXFLAGS += -DHAVE_WOLFSSL -I$(CUSTOM_WOLFSSL_DIR)/include
        LDFLAGS += -L$(CUSTOM_WOLFSSL_DIR)/lib -Wl,-rpath,$(CUSTOM_WOLFSSL_DIR)/lib -lwolfssl
        SSL_INFO := WolfSSL ($(CUSTOM_WOLFSSL_DIR))
    else ifdef USE_OPENSSL
        ifeq ($(wildcard $(CUSTOM_OPENSSL_DIR)/include/openssl),)
            $(error OpenSSL not found at $(CUSTOM_OPENSSL_DIR). Please build and install OpenSSL to ~/Proj/openssl/install/)
        endif
        CXXFLAGS += -I$(CUSTOM_OPENSSL_DIR)/include
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

    # Auto-enable USE_XDP if XDP_INTERFACE is provided
    ifdef XDP_INTERFACE
        USE_XDP := 1
    endif

    # XDP Support (Linux only)
    ifdef USE_XDP
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
                # Auto-detect MTU from interface if not specified
                ifndef XDP_MTU
                    XDP_MTU := $(shell cat /sys/class/net/$(XDP_INTERFACE)/mtu 2>/dev/null || echo 1500)
                    $(info XDP MTU: $(XDP_MTU) (auto-detected))
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
            ifdef XDP_MTU
                CXXFLAGS += -DXDP_MTU=$(XDP_MTU)
                ifndef XDP_INTERFACE
                    $(info XDP MTU: $(XDP_MTU))
                endif
            endif
            $(info Building with XDP support enabled)
        else
            $(error XDP requested but dependencies not found. Install libbpf-dev and libxdp-dev)
        endif
    # BSD Sockets (default or explicit)
    else
        TRANSPORT_INFO := BSD sockets
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

.PHONY: all clean clean-bpf run help test test-ringbuffer test-shm-ringbuffer test-event test-bug-fixes test-new-bug-fixes test-binance benchmark-binance test-xdp-transport test-xdp-frame test-xdp-send-recv test-xdp-binance test-core-http test-ip-layer test-ip-optimizations test-stack-checksum test-tcp-state test-retransmit-queue test-ssl-policy test-hftshm bpf check-ktls release debug epoll build-pipeline-binance test-pipeline-binance build-test-pipeline-xdp-poll test-pipeline-xdp-poll build-test-pipeline-xdp-poll-tcp test-pipeline-xdp-poll-tcp build-test-pipeline-transport-tcp test-pipeline-transport-tcp

all: $(EXAMPLE_BIN)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

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

# ============================================================================
# Pipeline Integration Tests (Multi-Process AF_XDP WebSocket)
# ============================================================================

# Pipeline source and binary
PIPELINE_BINANCE_SRC := $(INTEGRATION_DIR)/binance_pipeline.cpp
PIPELINE_BINANCE_BIN := $(BUILD_DIR)/binance_pipeline

# Build pipeline Binance integration test
$(PIPELINE_BINANCE_BIN): $(PIPELINE_BINANCE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling Pipeline Binance integration test..."
ifdef USE_XDP
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Pipeline build complete: $@"
else
	@echo "❌ Error: Pipeline requires USE_XDP=1"
	@exit 1
endif

# Build-only target for pipeline
build-pipeline-binance: $(PIPELINE_BINANCE_BIN)

# Run pipeline Binance test (with full XDP preparation)
test-pipeline-binance: $(PIPELINE_BINANCE_BIN)
	@echo "🧪 Running Pipeline integration test via script..."
	sudo ./scripts/xdp_pipeline_integration.sh $(XDP_INTERFACE) 45

# ============================================================================
# XDP Poll Segregated Test (Wire Loopback)
# ============================================================================

PIPELINE_XDP_POLL_SRC := test/pipeline/00_xdp_poll.cpp
PIPELINE_XDP_POLL_BIN := $(BUILD_DIR)/test_pipeline_xdp_poll

# Build XDP Poll test
$(PIPELINE_XDP_POLL_BIN): $(PIPELINE_XDP_POLL_SRC) | $(BUILD_DIR)
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
$(PIPELINE_XDP_POLL_PING_BIN): $(PIPELINE_XDP_POLL_PING_SRC) | $(BUILD_DIR)
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
$(PIPELINE_XDP_POLL_TCP_BIN): $(PIPELINE_XDP_POLL_TCP_SRC) | $(BUILD_DIR)
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
# Transport TCP Test (NoSSLPolicy with forked XDP Poll + Transport)
# ============================================================================

PIPELINE_TRANSPORT_TCP_SRC := test/pipeline/10_transport_tcp.cpp
PIPELINE_TRANSPORT_TCP_BIN := $(BUILD_DIR)/test_pipeline_transport_tcp

# Build Transport TCP test
$(PIPELINE_TRANSPORT_TCP_BIN): $(PIPELINE_TRANSPORT_TCP_SRC) | $(BUILD_DIR)
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

test: test-ringbuffer test-event test-bug-fixes test-new-bug-fixes test-xdp-transport test-xdp-frame test-xdp-send-recv test-core-http test-ip-layer test-ip-optimizations test-stack-checksum test-tcp-state test-retransmit-queue test-ssl-policy
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
	@echo "  make test-hftshm        - Test HftShmRingBuffer (requires hft-shm CLI)"
	@echo ""
	@echo "Integration Tests:"
	@echo "  make test-binance       - BSD socket test with Binance (20 msgs)"
	@echo "  make test-xdp-binance   - XDP zero-copy test with Binance (requires sudo)"
	@echo "  make test-pipeline-binance - Multi-process pipeline test (requires sudo)"
	@echo "  make test-pipeline-xdp-poll - XDP Poll segregated test (wire loopback, sudo)"
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
