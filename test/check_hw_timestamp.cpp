// test/check_hw_timestamp.cpp
// Diagnostic tool to check hardware timestamping capabilities

#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>

void check_interface_capabilities(const char* iface_name) {
    printf("Checking hardware timestamping for interface: %s\n", iface_name);
    printf("═══════════════════════════════════════════════════════════\n");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    struct ethtool_ts_info ts_info;
    memset(&ts_info, 0, sizeof(ts_info));
    ts_info.cmd = ETHTOOL_GET_TS_INFO;
    ifr.ifr_data = (char*)&ts_info;

    if (ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
        perror("ioctl(SIOCETHTOOL)");
        printf("❌ Hardware timestamping not supported or requires root access\n");
        printf("   Try: sudo ./build/check_hw_timestamp\n\n");
        close(sock);
        return;
    }

    printf("✅ Hardware timestamping query successful\n\n");

    printf("SO_TIMESTAMPING capabilities:\n");
    printf("  SOF_TIMESTAMPING_TX_HARDWARE:   %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_TX_HARDWARE) ? "✅ Yes" : "❌ No");
    printf("  SOF_TIMESTAMPING_RX_HARDWARE:   %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_RX_HARDWARE) ? "✅ Yes" : "❌ No");
    printf("  SOF_TIMESTAMPING_RAW_HARDWARE:  %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_RAW_HARDWARE) ? "✅ Yes" : "❌ No");
    printf("  SOF_TIMESTAMPING_TX_SOFTWARE:   %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_TX_SOFTWARE) ? "✅ Yes" : "❌ No");
    printf("  SOF_TIMESTAMPING_RX_SOFTWARE:   %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE) ? "✅ Yes" : "❌ No");
    printf("  SOF_TIMESTAMPING_SOFTWARE:      %s\n",
           (ts_info.so_timestamping & SOF_TIMESTAMPING_SOFTWARE) ? "✅ Yes" : "❌ No");

    printf("\nHardware clock sources:\n");
    if (ts_info.phc_index >= 0) {
        printf("  PHC index: %d (/dev/ptp%d)\n", ts_info.phc_index, ts_info.phc_index);
        printf("  ✅ PTP Hardware Clock available\n");
    } else {
        printf("  ❌ No PTP Hardware Clock\n");
    }

    printf("\nSupported TX timestamp types:\n");
    if (ts_info.tx_types == 0) {
        printf("  ❌ None\n");
    } else {
        if (ts_info.tx_types & (1 << HWTSTAMP_TX_ON))
            printf("  ✅ HWTSTAMP_TX_ON\n");
        if (ts_info.tx_types & (1 << HWTSTAMP_TX_OFF))
            printf("  ✅ HWTSTAMP_TX_OFF\n");
    }

    printf("\nSupported RX filter types:\n");
    if (ts_info.rx_filters == 0) {
        printf("  ❌ None\n");
    } else {
        if (ts_info.rx_filters & (1 << HWTSTAMP_FILTER_NONE))
            printf("  ✅ HWTSTAMP_FILTER_NONE\n");
        if (ts_info.rx_filters & (1 << HWTSTAMP_FILTER_ALL))
            printf("  ✅ HWTSTAMP_FILTER_ALL (timestamps all packets)\n");
        if (ts_info.rx_filters & (1 << HWTSTAMP_FILTER_SOME))
            printf("  ✅ HWTSTAMP_FILTER_SOME\n");
        if (ts_info.rx_filters & (1 << HWTSTAMP_FILTER_PTP_V1_L4_EVENT))
            printf("  ✅ HWTSTAMP_FILTER_PTP_V1_L4_EVENT\n");
        if (ts_info.rx_filters & (1 << HWTSTAMP_FILTER_PTP_V2_L4_EVENT))
            printf("  ✅ HWTSTAMP_FILTER_PTP_V2_L4_EVENT\n");
    }

    printf("\n");

    // Summary
    bool hw_rx_supported = ts_info.so_timestamping & SOF_TIMESTAMPING_RX_HARDWARE;
    bool sw_rx_supported = ts_info.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE;

    printf("Summary for %s:\n", iface_name);
    if (hw_rx_supported) {
        printf("  ✅ Hardware RX timestamping: SUPPORTED\n");
        printf("  💡 To enable: ethtool -K %s rx-timestamping on\n", iface_name);
    } else if (sw_rx_supported) {
        printf("  ⚠️  Only software timestamping available (still useful!)\n");
        printf("  💡 Provides kernel-level timestamps with ~1-10μs precision\n");
    } else {
        printf("  ❌ No timestamping support on this interface\n");
    }

    close(sock);
    printf("\n");
}

int main(int argc, char** argv) {
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║    Hardware Timestamping Capability Checker                       ║\n");
    printf("╚════════════════════════════════════════════════════════════════════╝\n\n");

    if (argc > 1) {
        // Check specific interface
        for (int i = 1; i < argc; i++) {
            check_interface_capabilities(argv[i]);
        }
    } else {
        // Check common interfaces
        printf("Checking common network interfaces...\n");
        printf("(Use: %s <interface> to check specific interface)\n\n", argv[0]);

        const char* common_ifaces[] = {
            "eth0", "eth1", "ens33", "ens160", "enp0s3",
            "eno1", "wlan0", "lo", nullptr
        };

        for (int i = 0; common_ifaces[i] != nullptr; i++) {
            // Check if interface exists
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock >= 0) {
                struct ifreq ifr;
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, common_ifaces[i], IFNAMSIZ - 1);

                if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                    check_interface_capabilities(common_ifaces[i]);
                }
                close(sock);
            }
        }
    }

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("Note: Some features may require root/sudo access\n");
    printf("      Software timestamps are typically sufficient for most\n");
    printf("      HFT applications (~1-10μs precision)\n");
    printf("═══════════════════════════════════════════════════════════════\n");

    return 0;
}
