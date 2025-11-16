# Makefile for WebSocket Policy-Based Library
# Supports: Linux (epoll, io_uring) and macOS (kqueue)

CXX := g++
CXXFLAGS := -std=c++17 -O3 -march=native -Wall -Wextra -I./src
LDFLAGS :=

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
    HAS_WOLFSSL := $(shell echo "int main(){}" | gcc -x c - -lwolfssl -o /dev/null 2>/dev/null && echo 1 || echo 0)

    # SSL Policy Selection
    ifdef USE_WOLFSSL
        CXXFLAGS += -DHAVE_WOLFSSL
        LDFLAGS += -lwolfssl
        SSL_INFO := WolfSSL
    else ifdef USE_LIBRESSL
        CXXFLAGS += -DUSE_LIBRESSL
        LDFLAGS += -lssl -lcrypto
        SSL_INFO := LibreSSL
    else ifdef USE_OPENSSL
        LDFLAGS += -lssl -lcrypto
        SSL_INFO := OpenSSL
    else
        # Default: Try io_uring + WolfSSL, fall back to OpenSSL
        ifneq ($(USE_IOURING),0)
            ifeq ($(HAS_WOLFSSL),1)
                CXXFLAGS += -DHAVE_WOLFSSL
                LDFLAGS += -lwolfssl
                SSL_INFO := WolfSSL
            else
                LDFLAGS += -lssl -lcrypto
                SSL_INFO := OpenSSL
            endif
        else
            LDFLAGS += -lssl -lcrypto
            SSL_INFO := OpenSSL
        endif
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

    $(info Building with $(SSL_INFO) + $(IO_INFO))

else ifeq ($(UNAME_S),Darwin)
    # macOS configuration
    CXXFLAGS += -D__APPLE__

    # Check for Homebrew LibreSSL (preferred) or fall back to OpenSSL
    HOMEBREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /usr/local)
    LIBRESSL_PREFIX := $(shell brew --prefix libressl 2>/dev/null)

    ifneq ($(LIBRESSL_PREFIX),)
        # LibreSSL found (preferred)
        CXXFLAGS += -I$(LIBRESSL_PREFIX)/include -DUSE_LIBRESSL
        LDFLAGS += -L$(LIBRESSL_PREFIX)/lib -lssl -lcrypto
        $(info Building for macOS with kqueue + LibreSSL (default))
    else
        # Fall back to OpenSSL
        OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || echo $(HOMEBREW_PREFIX)/opt/openssl)
        CXXFLAGS += -I$(OPENSSL_PREFIX)/include
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
        $(info Building for macOS with kqueue + OpenSSL (LibreSSL not found))
    endif
else
    $(error Unsupported platform: $(UNAME_S))
endif

# ============================================================================
# Targets
# ============================================================================

# Source files
EXAMPLE_SRC := examples/binance_example.cpp
IO_ECHO_SRC := examples/io_echo_server.cpp

# Test source files
TEST_RINGBUFFER_SRC := $(TEST_DIR)/test_ringbuffer.cpp
TEST_EVENT_SRC := $(TEST_DIR)/test_event.cpp
TEST_BUG_FIXES_SRC := $(TEST_DIR)/test_bug_fixes.cpp
TEST_NEW_BUG_FIXES_SRC := $(TEST_DIR)/test_new_bug_fixes.cpp

# Integration test source files
TEST_BINANCE_SRC := $(INTEGRATION_DIR)/binance.cpp

# Minimal example source file
EXAMPLE_MINIMAL_SRC := test/example.cpp

# Benchmark source files
BENCHMARK_DIR := ./test/benchmark
BENCHMARK_BINANCE_SRC := $(BENCHMARK_DIR)/binance.cpp

# Diagnostic tools
CHECK_HW_TIMESTAMP_SRC := test/check_hw_timestamp.cpp
TEST_NIC_TIMESTAMP_SRC := test/test_nic_timestamp.cpp
TEST_NIC_TIMESTAMP_SIMPLE_SRC := test/test_nic_timestamp_simple.cpp

# Binary output
EXAMPLE_BIN := $(BUILD_DIR)/ws_example
IO_ECHO_BIN := $(BUILD_DIR)/io_echo_server
TEST_RINGBUFFER_BIN := $(BUILD_DIR)/test_ringbuffer
TEST_EVENT_BIN := $(BUILD_DIR)/test_event
TEST_BUG_FIXES_BIN := $(BUILD_DIR)/test_bug_fixes
TEST_NEW_BUG_FIXES_BIN := $(BUILD_DIR)/test_new_bug_fixes
TEST_BINANCE_BIN := $(BUILD_DIR)/test_binance_integration
EXAMPLE_MINIMAL_BIN := $(BUILD_DIR)/example
BENCHMARK_BINANCE_BIN := $(BUILD_DIR)/benchmark_binance
CHECK_HW_TIMESTAMP_BIN := $(BUILD_DIR)/check_hw_timestamp
TEST_NIC_TIMESTAMP_BIN := $(BUILD_DIR)/test_nic_timestamp
TEST_NIC_TIMESTAMP_SIMPLE_BIN := $(BUILD_DIR)/test_timestamp_simple

.PHONY: all clean run run-echo help test test-ringbuffer test-event test-bug-fixes test-new-bug-fixes test-integration test-binance example run-example benchmark-binance check-hw-timestamp test-nic-timestamp test-timestamp-simple

all: $(EXAMPLE_BIN) $(IO_ECHO_BIN)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Build example
$(EXAMPLE_BIN): $(EXAMPLE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling example..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✅ Build complete: $@"

# Build I/O echo server example
$(IO_ECHO_BIN): $(IO_ECHO_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling I/O echo server..."
	$(CXX) $(CXXFLAGS) -o $@ $^
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

# Run I/O echo server
run-echo: $(IO_ECHO_BIN)
	@echo "🚀 Running I/O echo server on port 8080..."
	@echo "Test with: nc localhost 8080"
	./$(IO_ECHO_BIN)

# Run ringbuffer tests
test-ringbuffer: $(TEST_RINGBUFFER_BIN)
	@echo "🧪 Running ringbuffer unit tests..."
	./$(TEST_RINGBUFFER_BIN)

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

# Build minimal example
$(EXAMPLE_MINIMAL_BIN): $(EXAMPLE_MINIMAL_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling minimal example..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✅ Example build complete: $@"

# Build and run minimal example
example: $(EXAMPLE_MINIMAL_BIN)
	@echo "Building minimal example..."

run-example: $(EXAMPLE_MINIMAL_BIN)
	@echo "🚀 Running minimal WebSocket example..."
	@echo "📡 Connecting to wss://stream.binance.com:443..."
	./$(EXAMPLE_MINIMAL_BIN)

# Build Binance benchmark
$(BENCHMARK_BINANCE_BIN): $(BENCHMARK_BINANCE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling Binance latency benchmark..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✅ Benchmark build complete: $@"

# Run Binance benchmark
benchmark-binance: $(BENCHMARK_BINANCE_BIN)
	@echo "📊 Running Binance WebSocket latency benchmark..."
	@echo "📡 Warmup: 100 messages, Benchmark: 300 messages"
	./$(BENCHMARK_BINANCE_BIN)

# Build hardware timestamp checker
$(CHECK_HW_TIMESTAMP_BIN): $(CHECK_HW_TIMESTAMP_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling hardware timestamp diagnostic tool..."
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "✅ Diagnostic tool build complete: $@"

# Run hardware timestamp checker
check-hw-timestamp: $(CHECK_HW_TIMESTAMP_BIN)
	@echo "🔍 Checking hardware timestamping capabilities..."
	./$(CHECK_HW_TIMESTAMP_BIN)

# Build NIC timestamp test
$(TEST_NIC_TIMESTAMP_BIN): $(TEST_NIC_TIMESTAMP_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling NIC timestamp test..."
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "✅ Test build complete: $@"

# Run NIC timestamp test
test-nic-timestamp: $(TEST_NIC_TIMESTAMP_BIN)
	@echo "⚡ Testing hardware NIC timestamping..."
	@echo "   NOTE: Requires root/sudo for hardware timestamps"
	@echo "   Usage: sudo ./$(TEST_NIC_TIMESTAMP_BIN) <interface> [port]"
	@echo ""
	@echo "   Example:"
	@echo "     sudo ./$(TEST_NIC_TIMESTAMP_BIN) eth0 8888"
	@echo ""
	@echo "   Then send test packets:"
	@echo "     echo 'test' | nc -u localhost 8888"

# Build simple timestamp test (no root required)
$(TEST_NIC_TIMESTAMP_SIMPLE_BIN): $(TEST_NIC_TIMESTAMP_SIMPLE_SRC) | $(BUILD_DIR)
	@echo "🔨 Compiling simple timestamp test..."
	$(CXX) $(CXXFLAGS) -o $@ $^
	@echo "✅ Test build complete: $@"

# Run simple timestamp test
test-timestamp-simple: $(TEST_NIC_TIMESTAMP_SIMPLE_BIN)
	@echo "⚡ Simple software timestamp test (no root required)"
	@echo "   Usage: ./$(TEST_NIC_TIMESTAMP_SIMPLE_BIN) [port]"
	@echo ""
	@echo "   Example:"
	@echo "     Terminal 1: ./$(TEST_NIC_TIMESTAMP_SIMPLE_BIN) 8888"
	@echo "     Terminal 2: echo 'test' | nc -u localhost 8888"

# Run all integration tests
test-integration: test-binance
	@echo "✅ All integration tests completed"

# Run all tests (unit + integration)
test: test-ringbuffer test-event test-bug-fixes test-new-bug-fixes
	@echo "✅ All unit tests completed"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	@echo "🧹 Cleaned build artifacts"

# ============================================================================
# Variant builds
# ============================================================================

# Build with epoll + OpenSSL (Linux only, io_uring is default)
epoll:
	@echo "🔧 Building epoll + OpenSSL variant..."
	$(MAKE) all USE_IOURING=0

# Build optimized for production
release: CXXFLAGS += -DNDEBUG -flto
release: all
	@echo "✅ Release build complete"

# Build with debug symbols
debug: CXXFLAGS := -std=c++17 -g -O0 -Wall -Wextra -I./src
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
	@echo "Targets:"
	@echo "  make              - Build all examples"
	@echo "  make run          - Build and run WebSocket example"
	@echo "  make run-echo     - Build and run I/O echo server (port 8080)"
	@echo "  make test         - Build and run all unit tests"
	@echo "  make test-ringbuffer - Build and run ringbuffer unit tests"
	@echo "  make test-event   - Build and run event policy unit tests"
	@echo "  make test-binance - Build and run Binance integration test (first 20 msgs)"
	@echo "  make test-integration - Build and run all integration tests"
	@echo "  make check-hw-timestamp - Check hardware timestamping capabilities"
	@echo "  make test-nic-timestamp - Build NIC timestamp test (requires sudo to run)"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make release      - Build optimized release version"
	@echo "  make debug        - Build with debug symbols"
	@echo "  make check-ktls   - Check if kTLS is available (Linux)"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Platform-specific default configurations:"
	@echo "  Linux   : io_uring + WolfSSL (use USE_IOURING=0 for epoll + OpenSSL)"
	@echo "  macOS   : kqueue + LibreSSL (falls back to OpenSSL if LibreSSL not found)"
	@echo ""
	@echo "Output directory:"
	@echo "  ./build/          - All binaries and test executables"
	@echo ""
	@echo "Examples:"
	@echo "  ./build/ws_example       - WebSocket client example"
	@echo "  ./build/io_echo_server   - Async I/O echo server"
	@echo ""
	@echo "Environment variables:"
	@echo "  USE_IOURING=0     - Disable io_uring, use epoll + OpenSSL (Linux only)"
	@echo "  CXX=clang++       - Use Clang compiler"
	@echo ""
	@echo "Quick start:"
	@echo "  make run-echo                # Start echo server"
	@echo "  make test                    # Run all tests"
	@echo "  CXX=clang++ make             # Build with Clang"
	@echo "  USE_IOURING=0 make           # Use epoll instead of io_uring (Linux)"
