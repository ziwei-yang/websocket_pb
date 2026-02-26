#!/bin/bash
# Bind/unbind a NIC to vfio-pci for DPDK usage
# Usage: ./scripts/dpdk_bind.sh [interface] [--unbind]
#
# Prerequisite: IOMMU enabled in BIOS and kernel (intel_iommu=on or amd_iommu=on)
# Management: use enp109s0 or wlp0s20f3 when enp108s0 is bound to vfio-pci

set -e

IFACE=${1:-enp108s0}
ACTION=${2:-bind}

# Resolve PCI address from interface name
if [ -L "/sys/class/net/$IFACE/device" ]; then
    PCI=$(basename $(readlink /sys/class/net/$IFACE/device))
else
    # Interface might already be unbound — try common PCI address
    echo "Interface $IFACE not found in sysfs. Provide PCI address directly or bind back first."
    echo "Usage: $0 <interface> [--unbind]"
    echo "       $0 <pci_addr> --unbind    (e.g., 0000:6c:00.0)"
    PCI=$IFACE
fi

if [ "$ACTION" = "--unbind" ]; then
    # Detect original driver
    ORIG_DRIVER=$(basename $(readlink /sys/bus/pci/devices/$PCI/driver 2>/dev/null) 2>/dev/null || true)
    if [ "$ORIG_DRIVER" = "vfio-pci" ]; then
        echo "Unbinding $PCI from vfio-pci, rebinding to igc..."
        sudo dpdk-devbind.py --bind=igc $PCI
        rm -f /tmp/dpdk_pci_${IFACE} /tmp/dpdk_ip_${IFACE} /tmp/dpdk_mac_${IFACE} /tmp/dpdk_netmask_${IFACE} /tmp/dpdk_gw_${IFACE} /tmp/dpdk_gw_mac_${IFACE} 2>/dev/null
    else
        echo "$PCI is bound to $ORIG_DRIVER (not vfio-pci), nothing to do"
    fi
    dpdk-devbind.py --status
    exit 0
fi

# Check IOMMU
if ! dmesg 2>/dev/null | grep -qi "iommu"; then
    echo "WARNING: IOMMU may not be enabled. Check: dmesg | grep -i iommu"
    echo "         Boot with intel_iommu=on iommu=pt (Intel) or amd_iommu=on (AMD)"
fi

echo "Binding $IFACE ($PCI) to vfio-pci..."

# Cache NIC config before bind (sysfs/ioctl disappear after bind)
echo "$PCI" > /tmp/dpdk_pci_${IFACE}
LOCAL_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
LOCAL_MAC=$(cat /sys/class/net/"$IFACE"/address 2>/dev/null)
NETMASK=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet [\d.]+/\K[\d]+' | head -1)
if [ -n "$LOCAL_IP" ]; then
    echo "$LOCAL_IP" > /tmp/dpdk_ip_${IFACE}
    echo "Cached IP: $LOCAL_IP"
fi
if [ -n "$LOCAL_MAC" ]; then
    echo "$LOCAL_MAC" > /tmp/dpdk_mac_${IFACE}
    echo "Cached MAC: $LOCAL_MAC"
fi
if [ -n "$NETMASK" ]; then
    echo "$NETMASK" > /tmp/dpdk_netmask_${IFACE}
fi

# Cache gateway IP and MAC (needed by websocket_pipeline for DPDK mode)
GATEWAY_IP=$(ip route show dev "$IFACE" 2>/dev/null | awk '/default/ {print $3}' | head -1)
if [ -z "$GATEWAY_IP" ]; then
    # Try any default route (interface may share gateway with management NIC)
    GATEWAY_IP=$(ip route show default 2>/dev/null | awk '/via/ {print $3}' | head -1)
fi
if [ -n "$GATEWAY_IP" ]; then
    echo "$GATEWAY_IP" > /tmp/dpdk_gw_${IFACE}
    echo "Cached gateway IP: $GATEWAY_IP"
    # Ping gateway to ensure ARP entry exists, then cache gateway MAC
    ping -c 1 -W 1 "$GATEWAY_IP" >/dev/null 2>&1 || true
    GW_MAC=$(awk -v ip="$GATEWAY_IP" '$1 == ip {print $4}' /proc/net/arp | head -1)
    if [ -n "$GW_MAC" ] && [ "$GW_MAC" != "00:00:00:00:00:00" ]; then
        echo "$GW_MAC" > /tmp/dpdk_gw_mac_${IFACE}
        echo "Cached gateway MAC: $GW_MAC"
    fi
fi

# Load vfio-pci module
sudo modprobe vfio-pci

# Bring interface down (dpdk-devbind.py refuses active interfaces)
sudo ip link set "$IFACE" down 2>/dev/null || true

# Bind
sudo dpdk-devbind.py --bind=vfio-pci $PCI

echo "Done. Status:"
dpdk-devbind.py --status

echo ""
echo "To unbind: $0 $PCI --unbind"
echo "Management interfaces: enp109s0, wlp0s20f3"
