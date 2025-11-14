// test/test_nic_timestamp_simple.cpp
// Simple hardware NIC timestamping test - doesn't require root
// Binds to all interfaces instead of specific one

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/net_tstamp.h>
#include <errno.h>

void print_usage(const char* prog) {
    printf("Usage: %s [port]\n", prog);
    printf("Example: %s 8888\n", prog);
    printf("\nThis version doesn't require root (no interface binding)\n");
}

int enable_socket_timestamping(int sockfd) {
    // Request software timestamps (always works, no root needed)
    int flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;

    printf("🔧 Enabling software timestamping on socket...\n");

    if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
        perror("setsockopt SO_TIMESTAMPING");
        printf("❌ Failed to enable timestamping\n");
        return -1;
    }

    printf("✅ Software timestamping enabled (flags: 0x%x)\n", flags);
    printf("   This provides kernel-level timestamps with ~100-1000ns precision\n\n");
    return 0;
}

int main(int argc, char** argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 8888;

    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║        Simple Software Timestamping Test (No Root Required)       ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    printf("UDP Port: %d\n", port);
    printf("Binding to all interfaces (0.0.0.0:%d)\n\n", port);

    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Bind to port (all interfaces)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }
    printf("✅ Socket bound to port %d\n\n", port);

    // Enable timestamping
    if (enable_socket_timestamping(sockfd) < 0) {
        close(sockfd);
        return 1;
    }

    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║ Ready to receive UDP packets with software timestamps             ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    printf("📡 Listening on 0.0.0.0:%d\n\n", port);
    printf("To send test packets from another terminal:\n");
    printf("  echo \"test\" | nc -u localhost %d\n", port);
    printf("  or\n");
    printf("  for i in {{1..5}}; do echo \"packet $i\" | nc -u localhost %d; sleep 0.5; done\n\n", port);
    printf("Press Ctrl+C to stop.\n\n");

    // Receive loop
    char buffer[2048];
    char control[512];
    int pkt_count = 0;

    while (true) {
        struct sockaddr_in src_addr;
        struct msghdr msg;
        struct iovec iov;

        memset(&msg, 0, sizeof(msg));
        memset(control, 0, sizeof(control));

        iov.iov_base = buffer;
        iov.iov_len = sizeof(buffer);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_name = &src_addr;
        msg.msg_namelen = sizeof(src_addr);
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);

        ssize_t n = recvmsg(sockfd, &msg, 0);

        if (n > 0) {
            pkt_count++;
            buffer[n] = '\0';

            printf("═══════════════════════════════════════════════════════════════════\n");
            printf("📦 Received packet #%d (%zd bytes) from %s:%d\n",
                   pkt_count, n,
                   inet_ntoa(src_addr.sin_addr),
                   ntohs(src_addr.sin_port));
            printf("   Data: %.*s\n", (int)n, buffer);

            // Extract timestamps from ancillary data
            printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
            printf("║ Packet #%d Timestamps\n", pkt_count);
            printf("╚════════════════════════════════════════════════════════════════════╝\n");

            bool found_timestamp = false;
            struct timespec rcv_timestamp = {0, 0};

            for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != nullptr;
                 cmsg = CMSG_NXTHDR(&msg, cmsg)) {

                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                    // SO_TIMESTAMPING returns 3 timestamps
                    struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);

                    // Index 0: Software timestamp
                    // Index 1: Deprecated
                    // Index 2: Hardware timestamp (if available)
                    struct timespec sw_ts = ts[0];
                    struct timespec hw_ts = ts[2];

                    if (sw_ts.tv_sec > 0 || sw_ts.tv_nsec > 0) {
                        uint64_t sw_ns = (uint64_t)sw_ts.tv_sec * 1000000000ULL + sw_ts.tv_nsec;
                        printf("  📅 Software timestamp: %ld.%09ld s (%lu ns)\n",
                               sw_ts.tv_sec, sw_ts.tv_nsec, sw_ns);
                        rcv_timestamp = sw_ts;
                        found_timestamp = true;
                    }

                    if (hw_ts.tv_sec > 0 || hw_ts.tv_nsec > 0) {
                        uint64_t hw_ns = (uint64_t)hw_ts.tv_sec * 1000000000ULL + hw_ts.tv_nsec;
                        printf("  ⚡ Hardware timestamp: %ld.%09ld s (%lu ns)\n",
                               hw_ts.tv_sec, hw_ts.tv_nsec, hw_ns);
                        found_timestamp = true;

                        if (sw_ts.tv_sec > 0 || sw_ts.tv_nsec > 0) {
                            int64_t delta_ns = ((int64_t)sw_ts.tv_sec - hw_ts.tv_sec) * 1000000000LL +
                                              ((int64_t)sw_ts.tv_nsec - hw_ts.tv_nsec);
                            printf("  ⏱️  SW - HW Delta:     %ld ns (%.3f μs)\n",
                                   delta_ns, delta_ns / 1000.0);
                        }
                    }
                }

                // Also check for SO_TIMESTAMP (simpler, single timestamp)
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMP) {
                    struct timeval* tv = (struct timeval*)CMSG_DATA(cmsg);
                    printf("  🕐 SO_TIMESTAMP: %ld.%06ld s\n", tv->tv_sec, tv->tv_usec);
                    found_timestamp = true;
                }
            }

            if (!found_timestamp) {
                printf("  ⚠️  No timestamps found in ancillary data\n");
                printf("      This might indicate SO_TIMESTAMPING wasn't set correctly\n");
            } else {
                // Show human-readable time
                if (rcv_timestamp.tv_sec > 0) {
                    time_t t = rcv_timestamp.tv_sec;
                    struct tm* tm_info = localtime(&t);
                    char time_str[64];
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                    printf("\n  🕐 Wall clock time: %s.%09ld\n", time_str, rcv_timestamp.tv_nsec);
                    printf("  💡 Timestamp precision: ~%ld ns (kernel software timestamp)\n",
                           rcv_timestamp.tv_nsec % 1000);
                }
            }

            printf("═══════════════════════════════════════════════════════════════════\n\n");
        }
    }

    close(sockfd);
    return 0;
}
