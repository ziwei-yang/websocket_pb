#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <interface>" >&2
    exit 1
fi

IFACE="$1"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }

need_cmd ethtool
need_cmd ip

echo "=== Interface: $IFACE ==="
ip link show "$IFACE" || { echo "Interface not found: $IFACE" >&2; exit 1; }

echo
echo "=== CPU governor / scaling (per-cpu) ==="
if command -v cpupower >/dev/null 2>&1; then
    cpupower frequency-info | head -n 20 || true
else
    for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
        gov=$(cat "$cpu/cpufreq/scaling_governor" 2>/dev/null || echo "n/a")
        cur=$(cat "$cpu/cpufreq/scaling_cur_freq" 2>/dev/null || echo "n/a")
        echo "$(basename "$cpu"): governor=$gov freq=$cur kHz"
    done | head -n 8
fi

echo
echo "=== Driver / firmware (ethtool -i) ==="
if sudo ethtool -i "$IFACE"; then :; else echo "(failed)"; fi

echo
echo "=== Coalescing (ethtool -c) ==="
if sudo ethtool -c "$IFACE"; then :; else echo "(failed)"; fi

echo
echo "=== Offloads (ethtool -k) ==="
if sudo ethtool -k "$IFACE"; then :; else echo "(failed)"; fi

echo
echo "=== Ring parameters (ethtool -g) ==="
if sudo ethtool -g "$IFACE"; then :; else echo "(failed)"; fi

echo
echo "=== Channels / RSS queues (ethtool -l) ==="
if sudo ethtool -l "$IFACE"; then :; else echo "(failed)"; fi

echo
echo "=== RSS indirection table (ethtool -x) ==="
if sudo ethtool -x "$IFACE"; then :; else echo "(failed or not supported)"; fi

echo
echo "=== Timestamp capabilities (ethtool -T) ==="
if sudo ethtool -T "$IFACE"; then :; else echo "(failed)"; fi

echo
echo "=== Private flags (ethtool --show-priv-flags) ==="
if sudo ethtool --show-priv-flags "$IFACE"; then :; else echo "(not supported)"; fi

if command -v hwstamp_ctl >/dev/null 2>&1; then
    echo
    echo "=== Current hwstamp_ctl profile ==="
    if sudo hwstamp_ctl -i "$IFACE"; then :; else echo "(hwstamp_ctl failed)"; fi
fi

echo
echo "=== Interrupts for $IFACE (grep /proc/interrupts) ==="
if grep -i "$IFACE" /proc/interrupts; then
    echo
    echo "--- IRQ affinity masks (smp_affinity) ---"
    while read -r irq _rest; do
        irq_num="${irq%:}"
        if [[ -f "/proc/irq/${irq_num}/smp_affinity" ]]; then
            mask=$(cat "/proc/irq/${irq_num}/smp_affinity")
            echo "IRQ $irq_num affinity: $mask"
        fi
    done < <(grep -i "$IFACE" /proc/interrupts)
else
    echo "(no interrupts found for $IFACE)"
fi

echo
echo "=== irqbalance status ==="
if systemctl is-active --quiet irqbalance 2>/dev/null; then
    echo "irqbalance: active"
else
    echo "irqbalance: inactive"
fi

echo
echo "=== Busy poll sysctls ==="
for key in net.core.busy_read net.core.busy_poll net.core.netdev_budget net.core.netdev_budget_usecs; do
    val=$(cat /proc/sys/${key//./\/} 2>/dev/null || echo "n/a")
    echo "$key = $val"
done

echo
echo "=== C-state limit (intel_idle/processor) ==="
if [[ -f /sys/module/intel_idle/parameters/max_cstate ]]; then
    echo "intel_idle max_cstate=$(cat /sys/module/intel_idle/parameters/max_cstate)"
fi
if [[ -f /sys/module/processor/parameters/max_cstate ]]; then
    echo "processor max_cstate=$(cat /sys/module/processor/parameters/max_cstate)"
fi

echo
echo "=== NUMA locality (lspci -vv) ==="
if command -v lspci >/dev/null 2>&1; then
    PCIDEV=$(ethtool -i "$IFACE" 2>/dev/null | awk '/bus-info/ {print $2}')
    if [[ -n "$PCIDEV" ]]; then
        lspci -s "$PCIDEV" -vv | grep -iE "NUMA|LnkSta|LnkCap" || true
    fi
fi
