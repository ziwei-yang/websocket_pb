// examples/io_echo_server.cpp
// Simple echo server demonstrating IOBackend usage
//
// This example shows:
// - Creating a listening socket
// - Accepting connections asynchronously
// - Reading data asynchronously
// - Writing data asynchronously (echo)
// - Clean shutdown

#include "policy/iobackend.hpp"
#include <iostream>
#include <unordered_set>
#include <cstring>
#include <csignal>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

// Import types from iobackend namespace
using websocket::iobackend::Socket;
using websocket::iobackend::IOResult;
using websocket::iobackend::AcceptHandler;
using websocket::iobackend::IOHandler;

// Global I/O backend instance for signal handler
IOBackend* g_io = nullptr;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        std::cout << "\nShutting down..." << std::endl;
        if (g_io) {
            g_io->stop();
        }
    }
}

// Helper: Create non-blocking listening socket
int create_listening_socket(uint16_t port) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return -1;
    }

    // Set SO_REUSEADDR
    int optval = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Bind
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return -1;
    }

    // Listen
    if (listen(listen_fd, 128) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    // Make non-blocking
    int flags = fcntl(listen_fd, F_GETFL, 0);
    fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);

    return listen_fd;
}

// Connection tracking (now just FD set, buffers are internal to IOBackend)
std::unordered_set<Socket> connections;

// Forward declaration
void start_read(IOBackend& io, Socket client_fd);

// Write completion handler
void on_write_complete(IOBackend& io, Socket fd, std::size_t bytes, IOResult result) {
    if (result != IOResult::SUCCESS) {
        std::cerr << "Write error on fd " << fd << std::endl;
        io.close(fd);
        connections.erase(fd);
        return;
    }

    std::cout << "Echoed " << bytes << " bytes to fd " << fd << std::endl;

    // Continue reading
    start_read(io, fd);
}

// Read completion handler
void on_read_complete(IOBackend& io, Socket fd, std::size_t bytes, IOResult result) {
    if (connections.find(fd) == connections.end()) {
        io.close(fd);
        return;
    }

    if (result == IOResult::CLOSED || bytes == 0) {
        std::cout << "Connection closed by peer: fd " << fd << std::endl;
        io.close(fd);
        connections.erase(fd);
        return;
    }

    if (result != IOResult::SUCCESS) {
        std::cerr << "Read error on fd " << fd << std::endl;
        io.close(fd);
        connections.erase(fd);
        return;
    }

    std::cout << "Read " << bytes << " bytes from fd " << fd << std::endl;

    // Get RX RingBuffer and read data from it
    auto* rx_buf = io.get_rx_buffer(fd);
    if (!rx_buf) {
        io.close(fd);
        connections.erase(fd);
        return;
    }

    // Get data from RX buffer
    size_t available = 0;
    const uint8_t* data = rx_buf->next_read_region(&available);

    if (available > 0 && data) {
        // Echo back the data
        io.async_write(fd, data, available,
            [&io, fd, rx_buf, available](Socket s, std::size_t written, IOResult res) {
                // Commit read from RX buffer after successful write
                if (res == IOResult::SUCCESS) {
                    rx_buf->commit_read(available);
                }
                on_write_complete(io, s, written, res);
            });
    } else {
        // Continue reading
        start_read(io, fd);
    }
}

// Start asynchronous read
void start_read(IOBackend& io, Socket client_fd) {
    if (connections.find(client_fd) == connections.end()) {
        return;
    }

    io.async_read(client_fd,
        [&io, client_fd](Socket fd, std::size_t bytes, IOResult result) {
            on_read_complete(io, fd, bytes, result);
        });
}

// Accept handler
void on_accept(IOBackend& io, Socket listen_fd, Socket client_fd,
               struct sockaddr_storage addr, IOResult result) {
    if (result != IOResult::SUCCESS) {
        std::cerr << "Accept error" << std::endl;
        return;
    }

    // Get client address
    struct sockaddr_in* addr_in = reinterpret_cast<struct sockaddr_in*>(&addr);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, sizeof(client_ip));
    uint16_t client_port = ntohs(addr_in->sin_port);

    std::cout << "Accepted connection from " << client_ip << ":" << client_port
              << " (fd " << client_fd << ")" << std::endl;

    // Track connection
    connections.insert(client_fd);

    // Start reading
    start_read(io, client_fd);

    // Continue accepting
    io.async_accept(listen_fd,
        [&io, listen_fd](Socket fd, struct sockaddr_storage a, IOResult r) {
            on_accept(io, listen_fd, fd, a, r);
        });
}

int main(int argc, char* argv[]) {
    uint16_t port = 8080;
    if (argc > 1) {
        port = static_cast<uint16_t>(atoi(argv[1]));
    }

    std::cout << "Echo Server Example" << std::endl;
    std::cout << "===================" << std::endl;
    std::cout << "Platform: " << EventPolicy::name() << std::endl;
    std::cout << std::endl;

    // Create I/O backend
    IOBackend io;
    g_io = &io;

    // Set timeout
    io.set_timeout(1000);  // 1 second

    // Initialize
    if (!io.init()) {
        std::cerr << "Failed to initialize I/O backend" << std::endl;
        return 1;
    }

    // Create listening socket
    int listen_fd = create_listening_socket(port);
    if (listen_fd < 0) {
        std::cerr << "Failed to create listening socket" << std::endl;
        return 1;
    }

    std::cout << "Listening on port " << port << "..." << std::endl;
    std::cout << "Test with: nc localhost " << port << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    std::cout << std::endl;

    // Register signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Add to I/O loop
    if (!io.add_listen_socket(listen_fd)) {
        std::cerr << "Failed to add listening socket" << std::endl;
        close(listen_fd);
        return 1;
    }

    // Start accepting connections
    io.async_accept(listen_fd,
        [&io, listen_fd](Socket fd, struct sockaddr_storage addr, IOResult result) {
            on_accept(io, listen_fd, fd, addr, result);
        });

    // Run event loop (blocks until stop() is called or no connections)
    io.run();

    // Cleanup
    std::cout << "Cleaning up..." << std::endl;
    close(listen_fd);

    for (auto fd : connections) {
        io.close(fd);
    }
    connections.clear();

    std::cout << "Shutdown complete" << std::endl;
    return 0;
}
