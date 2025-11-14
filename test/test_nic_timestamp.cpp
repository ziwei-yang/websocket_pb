// test/test_nic_timestamp.cpp
// Demonstrates hardware NIC timestamping on a raw UDP socket
// NOTE: Does NOT work through SSL/TLS (see docs/NIC_TIMESTAMPING.md)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/errqueue.h>
#include <errno.h>

void print_usage(const char* prog) {
    printf("Usage: %s <interface> [port]\n", prog);
    printf("Example: sudo %s eth0 8888\n", prog);
    printf("\nNOTE: Requires root/sudo for hardware timestamping\n");
}

int enable_interface_hw_timestamp(const char* iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct hwtstamp_config hwconfig;
    memset(&hwconfig, 0, sizeof(hwconfig));

    // Enable hardware timestamps for all RX packets
    hwconfig.tx_type = HWTSTAMP_TX_OFF;
    hwconfig.rx_filter = HWTSTAMP_FILTER_ALL;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_data = (char*)&hwconfig;

    if (ioctl(sock, SIOCSHWTSTAMP, &ifr) < 0) {
        int err = errno;
        close(sock);

        if (err == EPERM) {
            fprintf(stderr, "❌ Permission denied. Run with sudo.\n");
        } else if (err == EOPNOTSUPP) {
            fprintf(stderr, "❌ Interface %s does not support hardware timestamping.\n", iface);
            fprintf(stderr, "   Check with: ethtool -T %s\n", iface);
        } else {
            fprintf(stderr, "❌ Failed to enable hardware timestamping: %s\n", strerror(err));
        }
        return -1;
    }

    close(sock);
    printf("✅ Hardware timestamping enabled on %s\n", iface);
    return 0;
}

int enable_socket_timestamping(int sockfd) {
    // Request hardware + software timestamps
    int flags = SOF_TIMESTAMPING_RX_HARDWARE |   // Hardware RX timestamp
                SOF_TIMESTAMPING_RX_SOFTWARE |   // Software fallback
                SOF_TIMESTAMPING_RAW_HARDWARE |  // Raw hardware clock
                SOF_TIMESTAMPING_SOFTWARE;       // Software timestamp

    printf("Attempting to enable: HW_RX | SW_RX | RAW_HW | SW timestamps\n");

    if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
        // Try software-only fallback
        printf("⚠️  Hardware timestamping failed, trying software-only...\n");
        flags = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;

        if (setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
            perror("setsockopt SO_TIMESTAMPING");
            return -1;
        }
        printf("✅ Software-only timestamping enabled\n");
        return 0;
    }

    printf("✅ Socket timestamping configured (hardware + software)\n");
    printf("   Flags: 0x%x\n", flags);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char* iface = argv[1];
    int port = (argc > 2) ? atoi(argv[2]) : 8888;

    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║        Hardware NIC Timestamping Test                             ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    printf("Interface: %s\n", iface);
    printf("UDP Port:  %d\n\n", port);

    // Check if running as root
    if (geteuid() != 0) {
        fprintf(stderr, "⚠️  WARNING: Not running as root. Hardware timestamping may fail.\n");
        fprintf(stderr, "   Try: sudo %s %s %d\n\n", argv[0], iface, port);
    }

    // Enable hardware timestamping on interface
    printf("🔧 Step 1: Enabling hardware timestamping on interface...\n");
    if (enable_interface_hw_timestamp(iface) < 0) {
        fprintf(stderr, "\n⚠️  Continuing with software timestamps only...\n\n");
    }

    // Create UDP socket
    printf("\n🔧 Step 2: Creating UDP socket...\n");
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // Bind to specific interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
        perror("setsockopt SO_BINDTODEVICE");
        fprintf(stderr, "⚠️  Failed to bind to %s (requires root)\n", iface);
    } else {
        printf("✅ Socket bound to interface %s\n", iface);
    }

    // Bind to port
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
    printf("✅ Socket bound to port %d\n", port);

    // Enable timestamping on socket
    printf("\n🔧 Step 3: Enabling timestamping on socket...\n");
    if (enable_socket_timestamping(sockfd) < 0) {
        close(sockfd);
        return 1;
    }

    printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║ Ready to receive UDP packets with hardware timestamps             ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    printf("📡 Listening on %s:%d\n\n", iface, port);
    printf("To send test packets from another terminal:\n");
    printf("  echo \"test\" | nc -u localhost %d\n", port);
    printf("  or\n");
    printf("  echo \"test\" | socat - UDP:localhost:%d\n\n", port);
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
            printf("   Data: %s\n", buffer);

            // Extract timestamps from ancillary data
            printf("\n╔════════════════════════════════════════════════════════════════════╗\n");
            printf("║ Packet #%d Timestamps                                            \n", pkt_count);
            printf("╚════════════════════════════════════════════════════════════════════╝\n");

            bool found_timestamp = false;
            for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
                 cmsg != nullptr;
                 cmsg = CMSG_NXTHDR(&msg, cmsg)) {

                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING) {
                    // SO_TIMESTAMPING returns 3 timestamps
                    struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);

                    struct timespec sw_ts = ts[0];  // Software timestamp
                    struct timespec hw_ts = ts[2];  // Hardware timestamp

                    // Software timestamp
                    if (sw_ts.tv_sec > 0 || sw_ts.tv_nsec > 0) {
                        uint64_t sw_ns = (uint64_t)sw_ts.tv_sec * 1000000000ULL + sw_ts.tv_nsec;
                        printf("  📅 Software timestamp: %ld.%09ld s (%lu ns)\n",
                               sw_ts.tv_sec, sw_ts.tv_nsec, sw_ns);
                        found_timestamp = true;
                    }

                    // Hardware timestamp
                    if (hw_ts.tv_sec > 0 || hw_ts.tv_nsec > 0) {
                        uint64_t hw_ns = (uint64_t)hw_ts.tv_sec * 1000000000ULL + hw_ts.tv_nsec;
                        printf("  ⚡ Hardware timestamp: %ld.%09ld s (%lu ns)\n",
                               hw_ts.tv_sec, hw_ts.tv_nsec, hw_ns);
                        found_timestamp = true;

                        // Calculate delta
                        if (sw_ts.tv_sec > 0 || sw_ts.tv_nsec > 0) {
                            int64_t delta_ns = ((int64_t)sw_ts.tv_sec - hw_ts.tv_sec) * 1000000000LL +
                                              ((int64_t)sw_ts.tv_nsec - hw_ts.tv_nsec);
                            printf("  ⏱️  SW - HW Delta:     %ld ns (%.3f μs)\n",
                                   delta_ns, delta_ns / 1000.0);
                        }
                    } else if (found_timestamp) {
                        printf("  ⚠️  Hardware timestamp: Not available (NIC doesn't support it)\n");
                    }
                }
            }

            if (!found_timestamp) {
                printf("  ⚠️  No timestamps found in ancillary data\n");
                printf("      This may indicate:\n");
                printf("      - SO_TIMESTAMPING not enabled correctly\n");
                printf("      - NIC doesn't support timestamping\n");
                printf("      - Virtual/cloud environment\n");
            }

            printf("═══════════════════════════════════════════════════════════════════\n\n");
        }
    }

    close(sockfd);
    return 0;
}
