#!/usr/bin/env bash
# local_clock_sync.sh - Sync system clock (CPU) to NIC hardware clock (PHC)
# For systems without PTP infrastructure, keeps NIC clock synchronized with system time

set -euo pipefail

# Default configuration
DEFAULT_PHC="${PHC_DEVICE:-/dev/ptp0}"
PID_DIR="${SYNC_PID_DIR:-/tmp/local_clock_sync}"
LOG_DIR="${SYNC_LOG_DIR:-/var/log}"
SYNC_LOG="${SYNC_LOG:-$LOG_DIR/phc2sys-local.log}"
PID_FILE="$PID_DIR/phc2sys.pid"

# phc2sys options: -O 0 (no offset), -m (print messages)
read -r -a PHC2SYS_OPTS <<< "${PHC2SYS_OPTS:--O 0 -m}"

usage() {
    cat <<EOF
Usage: sudo ./scripts/local_clock_sync.sh <command> [ptp_device]

Commands:
  start [ptp]   Start background sync: CLOCK_REALTIME (CPU) → PHC (NIC)
  stop          Stop background phc2sys daemon
  restart [ptp] Restart sync daemon (stop + start)
  status        Show sync status and current offset
  diagnose      Run diagnostics to troubleshoot sync issues
  once [ptp]    Run a one-shot sync (for testing)
  help          Show this message

Description:
  Synchronizes NIC hardware clock (PHC) FROM system clock (CPU).
  Use this when you have NTP/chrony keeping system time accurate,
  and want the NIC hardware timestamps to match system time.

  Direction: System Clock → NIC Hardware Clock
  Tool used: phc2sys (from linuxptp package)

Examples:
  sudo ./scripts/local_clock_sync.sh start
  sudo ./scripts/local_clock_sync.sh status
  sudo ./scripts/local_clock_sync.sh once /dev/ptp1

Environment overrides:
  PHC_DEVICE       (default: /dev/ptp0)
  PHC2SYS_OPTS     (default: "-O 0 -m")
  SYNC_LOG_DIR, SYNC_LOG, SYNC_PID_DIR

Prerequisites:
  - linuxptp package installed (provides phc2sys)
  - NIC with hardware timestamping support
  - Root privileges (sudo)
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

need_priv_helper() {
    if [[ $EUID -eq 0 ]]; then
        echo ""
        return
    fi
    if command -v sudo >/dev/null 2>&1; then
        echo "sudo"
        return
    fi
    if command -v doas >/dev/null 2>&1; then
        echo "doas"
        return
    fi
    die "This script requires root privileges; install sudo/doas or run as root"
}

with_priv() {
    local helper
    helper="$(need_priv_helper)"
    if [[ -n "$helper" ]]; then
        "$helper" "$@"
    else
        "$@"
    fi
}

ensure_linuxptp() {
    if command -v phc2sys >/dev/null 2>&1; then
        return 0
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        echo "[warn] phc2sys not found and apt-get unavailable; install linuxptp manually." >&2
        return 1
    fi

    echo "[deps] Installing linuxptp package..."
    if with_priv apt-get update >/dev/null && with_priv apt-get -y install linuxptp; then
        command -v phc2sys >/dev/null 2>&1
    else
        echo "[warn] Failed to install linuxptp automatically." >&2
        return 1
    fi
}

phc_exists() {
    [[ -e "$1" ]]
}

# Get network interface name from PHC device
# Usage: get_interface_from_phc "/dev/ptp0"
# Returns: interface name (e.g., "enp108s0") or empty string
get_interface_from_phc() {
    local phc_device="$1"

    # Extract PHC index from device path (e.g., /dev/ptp0 -> 0)
    local phc_index=""
    if [[ "$phc_device" =~ /dev/ptp([0-9]+) ]]; then
        phc_index="${BASH_REMATCH[1]}"
    else
        return 1
    fi

    # Method 1: Try via /sys/class/ptp/ptpX/device/net/
    if [[ -d "/sys/class/ptp/ptp${phc_index}/device/net" ]]; then
        local iface=$(ls "/sys/class/ptp/ptp${phc_index}/device/net/" 2>/dev/null | head -n 1)
        if [[ -n "$iface" ]]; then
            echo "$iface"
            return 0
        fi
    fi

    # Method 2: Try via /sys/class/net/*/phc_index (older kernels)
    for iface in $(ls /sys/class/net/ 2>/dev/null | grep -v lo); do
        if [[ -f "/sys/class/net/$iface/phc_index" ]]; then
            local iface_phc_index=$(cat "/sys/class/net/$iface/phc_index" 2>/dev/null || echo "-1")
            if [[ "$iface_phc_index" == "$phc_index" ]]; then
                echo "$iface"
                return 0
            fi
        fi
    done

    return 1
}

is_running() {
    local pid_file="$1"
    [[ -f "$pid_file" ]] || return 1
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    [[ -n "$pid" && -d "/proc/$pid" ]]
}

start_sync() {
    local phc="$1"

    if ! ensure_linuxptp; then
        die "Cannot start sync without phc2sys (linuxptp package)"
    fi

    mkdir -p "$PID_DIR" "$(dirname "$SYNC_LOG")"

    if is_running "$PID_FILE"; then
        echo "[info] Sync already running (PID $(cat "$PID_FILE"))."
        echo "       Use 'status' to check or 'stop' to terminate."
        return
    fi

    echo "[start] phc2sys -s CLOCK_REALTIME -c $phc ${PHC2SYS_OPTS[*]}"
    echo "        Direction: System Clock (CPU) → $phc (NIC)"
    echo "        Log: $SYNC_LOG"

    # Start phc2sys in background, syncing system clock TO hardware clock
    nohup phc2sys -s CLOCK_REALTIME -c "$phc" "${PHC2SYS_OPTS[@]}" >>"$SYNC_LOG" 2>&1 &
    echo $! >"$PID_FILE"

    sleep 1
    if is_running "$PID_FILE"; then
        echo "[info] Sync daemon started successfully (PID $(cat "$PID_FILE"))"
    else
        echo "[error] Sync daemon failed to start. Check $SYNC_LOG" >&2
        rm -f "$PID_FILE"
        return 1
    fi
}

stop_sync() {
    if ! is_running "$PID_FILE"; then
        echo "[info] Sync daemon not running."
        return
    fi

    local pid
    pid="$(cat "$PID_FILE")"
    echo "[stop] Stopping sync daemon (PID $pid)"

    if kill "$pid" 2>/dev/null; then
        rm -f "$PID_FILE"
        echo "[info] Sync daemon stopped successfully"
    else
        echo "[warn] Failed to stop PID $pid (already dead?)" >&2
        rm -f "$PID_FILE"
    fi
}

restart_sync() {
    local phc="$1"

    echo "[restart] Restarting clock sync daemon..."
    echo ""

    # Stop the daemon
    stop_sync

    # Wait a moment to ensure clean shutdown
    sleep 1

    # Start the daemon
    start_sync "$phc"

    echo ""
    echo "[info] Restart complete. Check status with:"
    echo "       sudo $0 status"
}

show_status() {
    local phc="$1"

    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║             Local Clock Sync Status & Metrics                     ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""

    # Daemon status
    local daemon_status="Stopped"
    local daemon_pid=""
    if is_running "$PID_FILE"; then
        daemon_pid="$(cat "$PID_FILE")"
        daemon_status="Running (PID $daemon_pid)"
    fi

    # Get network interface name
    local iface_name=$(get_interface_from_phc "$phc")

    echo "Daemon Status:  $daemon_status"
    echo "PHC Device:     $phc"
    if [[ -n "$iface_name" ]]; then
        echo "Interface:      $iface_name"
    fi
    echo "Direction:      CLOCK_REALTIME (CPU) → PHC (NIC)"
    if [[ -n "$daemon_pid" ]]; then
        echo "Log File:       $SYNC_LOG"
    fi
    echo ""

    # Get clock offset from phc2sys
    if ! command -v phc2sys >/dev/null 2>&1; then
        echo "⚠️  phc2sys not available (install linuxptp)"
        return
    fi

    if ! phc_exists "$phc"; then
        echo "⚠️  PHC device $phc not found"
        echo ""
        echo "Available PTP devices:"
        ls -la /dev/ptp* 2>/dev/null || echo "  (none found)"
        return
    fi

    # Get current offset from log file (if daemon running) or run phc2sys
    local offset_ns=0
    local offset_output=""
    local sync_state=""

    if is_running "$PID_FILE" && [[ -f "$SYNC_LOG" ]]; then
        # Daemon is running - read from log file
        offset_output=$(tail -n 1 "$SYNC_LOG" 2>/dev/null)
    else
        # No daemon - try to run phc2sys directly (requires sudo)
        offset_output=$(timeout 2 phc2sys -s CLOCK_REALTIME -c "$phc" -O 0 -m 2>&1 | grep "sys offset" | head -n 1)
    fi

    # Parse offset from output: "phc2sys[...]: /dev/ptp0 sys offset -28669 s2 freq ..."
    if [[ "$offset_output" =~ sys\ offset\ +(-?[0-9]+) ]]; then
        offset_ns="${BASH_REMATCH[1]}"
    fi

    # Extract sync state (s0, s1, s2)
    if [[ "$offset_output" =~ \ s([0-2]) ]]; then
        sync_state="${BASH_REMATCH[1]}"
    fi

    # Calculate absolute value for comparisons
    local abs_offset=${offset_ns#-}

    # Convert to microseconds for display (with error handling)
    local offset_us="0.000"
    if command -v awk >/dev/null 2>&1; then
        offset_us=$(awk "BEGIN {printf \"%.3f\", $offset_ns / 1000.0}" 2>/dev/null || echo "0.000")
    else
        # Fallback: use bash arithmetic (less precise)
        offset_us=$(( offset_ns / 1000 )).$(( (abs_offset % 1000) ))
    fi

    # Determine status based on offset
    local status_emoji=""
    local status_text=""
    if [[ $abs_offset -lt 100 ]]; then
        status_emoji="✅"
        status_text="Excellent"
    elif [[ $abs_offset -lt 1000 ]]; then
        status_emoji="✅"
        status_text="Good"
    elif [[ $abs_offset -lt 10000 ]]; then
        status_emoji="⚠️ "
        status_text="Fair"
    else
        status_emoji="❌"
        status_text="Poor"
    fi

    # Print metrics table
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                      Clock Sync Metrics                            ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
    printf "  %-28s %-15s %-15s\n" "| Metric" "| Value" "| Status" || echo "  | Metric | Value | Status"
    printf "  %-28s %-15s %-15s\n" "|---------------------------" "|---------------" "|---------------" || echo "  |---------------------------|---------------|---------------"
    printf "  %-28s %-15s %s %s\n" "| Clock offset (CPU↔NIC)" "| ${offset_ns} ns" "| ${status_emoji}" "${status_text}" || echo "  | Clock offset: ${offset_ns} ns | ${status_text}"
    printf "  %-28s %-15s %s %s\n" "| Clock offset (μs)" "| ${offset_us} μs" "|" "" || echo "  | Clock offset: ${offset_us} μs"

    # Show sync state
    if [[ -n "$sync_state" ]]; then
        local state_text="Unknown"
        case "$sync_state" in
            0) state_text="Unlocked" ;;
            1) state_text="Locked" ;;
            2) state_text="Holdover" ;;
            *) state_text="Unknown (s$sync_state)" ;;
        esac
        printf "  %-28s %-15s %-15s\n" "| Sync state" "| $state_text" "|" || echo "  | Sync state: $state_text"
    fi
    echo ""

    # Check if offset is converging
    local is_converging=false
    if is_running "$PID_FILE" && [[ -f "$SYNC_LOG" ]]; then
        local first_offset last_offset
        first_offset=$(tail -n 5 "$SYNC_LOG" 2>/dev/null | grep "sys offset" | head -n 1 | grep -oP 'offset\s+\K-?\d+' || echo "$abs_offset")
        last_offset="$abs_offset"
        local first_abs=${first_offset#-}
        if [[ $first_abs -gt $abs_offset ]]; then
            is_converging=true
        fi
    fi

    # Quality assessment
    echo "Quality Assessment:"
    if [[ $abs_offset -lt 100 ]]; then
        echo "  ${status_emoji} Clock synchronization is excellent (< 100 ns)"
        echo "  Suitable for: High-frequency trading, precision timestamping"
        echo "  Status: Optimal - no action needed"
    elif [[ $abs_offset -lt 1000 ]]; then
        echo "  ${status_emoji} Clock synchronization is good (< 1 μs)"
        echo "  Suitable for: Most trading applications, accurate timestamping"
        echo "  Status: Good - no action needed"
    elif [[ $abs_offset -lt 10000 ]]; then
        echo "  ${status_emoji} Clock synchronization is fair (< 10 μs)"
        echo "  Suitable for: General trading, may affect sub-microsecond accuracy"
        echo ""
        echo "  Recommendations:"
        echo "    • Monitor for a few minutes to see if it improves"
        echo "    • Check system load: top, htop"
        echo "    • Verify no high CPU usage on sync daemon"
    else
        echo "  ${status_emoji} Clock synchronization needs improvement (≥ 10 μs)"
        echo "  Impact: Timestamps may have significant inaccuracy"
        echo ""
        if [[ "$is_converging" == "true" ]]; then
            echo "  ✅ Status: Offset is converging (improving)"
            echo "  Action: Wait 2-5 minutes for sync to stabilize"
            echo ""
            echo "  Check again with:"
            echo "    sudo $0 status"
        else
            echo "  ⚠️  Status: Offset not improving or stable at poor value"
            echo ""
            echo "  Troubleshooting steps:"
            if [[ -n "$iface_name" ]]; then
                echo "    1. Verify NIC hardware timestamp support:"
                echo "       sudo ethtool -T $iface_name | grep hardware-"
            else
                echo "    1. Find your network interface and check timestamp support:"
                echo "       ip link show"
                echo "       sudo ethtool -T <interface-name> | grep hardware-"
            fi
            echo ""
            echo "    2. Run full diagnostics:"
            echo "       sudo $0 diagnose"
            echo ""
            echo "    3. Review recent log for errors:"
            echo "       sudo tail -20 $SYNC_LOG"
            echo ""
            echo "    4. Restart sync daemon:"
            echo "       sudo $0 restart"
            echo ""
            echo "    5. Check system performance:"
            echo "       top -bn1 | head -20"
        fi
    fi
    echo ""

    # Recent sync history if daemon is running
    if is_running "$PID_FILE" && [[ -f "$SYNC_LOG" ]]; then
        echo "Recent Sync History (last 5 samples):"
        tail -n 5 "$SYNC_LOG" 2>/dev/null | grep "sys offset" | while read -r line; do
            if [[ "$line" =~ offset\ +(-?[0-9]+) ]]; then
                hist_offset="${BASH_REMATCH[1]}"
                hist_us=$(awk "BEGIN {printf \"%.2f\", $hist_offset / 1000.0}" 2>/dev/null || echo "N/A")
                echo "  Offset: ${hist_offset} ns (${hist_us} μs)"
            fi
        done
        echo ""
    fi
}


run_once() {
    local phc="$1"

    if ! ensure_linuxptp; then
        die "Cannot run sync without phc2sys (linuxptp package)"
    fi

    echo "[sync] One-shot sync: CLOCK_REALTIME (CPU) → $phc (NIC)"
    echo ""

    phc2sys -s CLOCK_REALTIME -c "$phc" -O 0 -m
}

run_diagnostics() {
    local phc="$1"
    local iface_name=$(get_interface_from_phc "$phc")

    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                Clock Sync Diagnostics Report                      ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""

    # 1. Check daemon status
    echo "1. Sync Daemon Status:"
    if is_running "$PID_FILE"; then
        echo "   ✅ Running (PID $(cat "$PID_FILE"))"
        echo "   Log: $SYNC_LOG"
    else
        echo "   ❌ Not running"
        echo "   Action: Start with: sudo $0 start"
    fi
    echo ""

    # 2. Check PHC device and interface mapping
    echo "2. PHC Device & Interface:"
    if phc_exists "$phc"; then
        echo "   ✅ PHC device found: $phc"
        ls -l "$phc" 2>/dev/null | sed 's/^/      /' || true
        if [[ -n "$iface_name" ]]; then
            echo "   ✅ Mapped to interface: $iface_name"
        else
            echo "   ⚠️  Could not map to network interface"
        fi
    else
        echo "   ❌ PHC device not found: $phc"
        echo "   Available PTP devices:"
        ls -la /dev/ptp* 2>/dev/null | sed 's/^/      /' || echo "     (none found)"
        echo ""
        echo "   This usually means:"
        echo "     • NIC doesn't support hardware timestamping"
        echo "     • Kernel module not loaded"
        echo "     • Wrong device path"
    fi
    echo ""

    # 3. Check NIC hardware timestamp support (focus on detected interface first)
    echo "3. NIC Hardware Timestamp Support:"
    local found_interface=false

    # Check the detected interface first
    if [[ -n "$iface_name" ]]; then
        echo "   Target Interface: $iface_name"
        if command -v ethtool >/dev/null 2>&1; then
            echo ""
            echo "   Timestamp Capabilities (ethtool -T $iface_name):"
            local ethtool_output=$(ethtool -T "$iface_name" 2>&1)
            if echo "$ethtool_output" | grep -q "hardware-transmit\|hardware-receive\|hardware-raw-clock"; then
                echo "$ethtool_output" | grep -E "hardware-" | sed 's/^/      /'
                found_interface=true
                echo ""
                echo "   ✅ Hardware timestamping is supported"
            else
                echo "      $ethtool_output" | head -3 | sed 's/^/      /'
                echo ""
                echo "   ❌ Hardware timestamping NOT supported on $iface_name"
            fi
        fi
    fi

    # List all other interfaces with hardware timestamp support
    echo ""
    echo "   All interfaces with PTP support:"
    local other_found=false

    # Check via /sys/class/ptp/ (most reliable)
    for ptp_dev in /sys/class/ptp/ptp*; do
        if [[ -d "$ptp_dev/device/net" ]]; then
            local ptp_iface=$(ls "$ptp_dev/device/net/" 2>/dev/null | head -n 1)
            local ptp_num=$(basename "$ptp_dev" | sed 's/ptp//')
            if [[ -n "$ptp_iface" ]]; then
                echo "      • $ptp_iface (PHC: /dev/ptp$ptp_num)"
                other_found=true
            fi
        fi
    done

    # Fallback: check via /sys/class/net/*/phc_index (older kernels)
    if [[ "$other_found" == "false" ]]; then
        for iface in $(ls /sys/class/net/ 2>/dev/null | grep -v lo); do
            if [[ -f "/sys/class/net/$iface/phc_index" ]]; then
                local phc_idx=$(cat "/sys/class/net/$iface/phc_index" 2>/dev/null)
                if [[ "$phc_idx" != "-1" && -n "$phc_idx" ]]; then
                    echo "      • $iface (PHC index: $phc_idx)"
                    other_found=true
                fi
            fi
        done
    fi

    if [[ "$other_found" == "false" && "$found_interface" == "false" ]]; then
        echo "      (none found)"
        echo ""
        echo "   Common causes:"
        echo "     • NIC doesn't support PTP/hardware timestamps"
        echo "     • Driver not loaded or configured"
        echo "     • Virtual machine (VM NICs typically don't support HW timestamps)"
    fi
    echo ""

    # 4. Check for time sync conflicts
    echo "4. Time Synchronization Conflicts:"
    local conflicts=false
    if systemctl is-active chronyd >/dev/null 2>&1; then
        echo "   ⚠️  chronyd is running (may conflict with phc2sys)"
        conflicts=true
    fi
    if systemctl is-active ntpd >/dev/null 2>&1; then
        echo "   ⚠️  ntpd is running (may conflict with phc2sys)"
        conflicts=true
    fi
    if [[ "$conflicts" == "false" ]]; then
        echo "   ✅ No conflicting time services detected"
    else
        echo ""
        echo "   Note: System time sync (chrony/ntp) is fine for keeping CPU clock"
        echo "         accurate. phc2sys syncs NIC←CPU, not CPU←network."
    fi
    echo ""

    # 5. Check system performance
    echo "5. System Performance:"
    local loadavg=$(cat /proc/loadavg 2>/dev/null | awk '{print $1, $2, $3}')
    echo "   Load average: $loadavg"

    local phc2sys_cpu=""
    if is_running "$PID_FILE"; then
        phc2sys_cpu=$(ps aux | grep "[p]hc2sys" | head -n 1 | awk '{print $3}')
        if [[ -n "$phc2sys_cpu" ]]; then
            echo "   phc2sys CPU usage: ${phc2sys_cpu}%"

            # Check if CPU usage is high (only if bc is available)
            if command -v bc >/dev/null 2>&1; then
                local is_high=$(echo "$phc2sys_cpu > 5.0" | bc -l 2>/dev/null || echo 0)
                if [[ "$is_high" == "1" ]]; then
                    echo "   ⚠️  High CPU usage - may affect sync accuracy"
                fi
            fi
        fi
    fi
    echo ""

    # 6. Check recent sync quality
    echo "6. Recent Sync Quality (last 10 samples):"
    if [[ -f "$SYNC_LOG" ]]; then
        tail -n 10 "$SYNC_LOG" 2>/dev/null | grep "sys offset" | while read -r line; do
            if [[ "$line" =~ offset\ +(-?[0-9]+) ]]; then
                local off="${BASH_REMATCH[1]}"
                local off_abs=${off#-}
                local quality="❌ Poor"
                [[ $off_abs -lt 10000 ]] && quality="⚠️  Fair"
                [[ $off_abs -lt 1000 ]] && quality="✅ Good"
                [[ $off_abs -lt 100 ]] && quality="✅ Excellent"
                echo "   $quality: ${off} ns ($(awk "BEGIN {printf \"%.2f\", $off / 1000.0}" 2>/dev/null || echo "?") μs)"
            fi
        done
    else
        echo "   No log file found: $SYNC_LOG"
    fi
    echo ""

    # 7. Recommendations
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║                        Recommendations                             ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""

    if ! is_running "$PID_FILE"; then
        echo "  → Start sync daemon:"
        echo "    sudo $0 start"
    elif [[ "$found_interface" == "false" ]]; then
        echo "  → Your NIC may not support hardware timestamps"
        echo "    This sync tool requires PTP-capable hardware"
        echo "    Check your NIC specifications for PTP support"
    else
        echo "  → Monitor sync status:"
        echo "    sudo $0 status"
        echo ""
        echo "  → If offset is not improving:"
        echo "    sudo $0 restart"
    fi
    echo ""
}

# Main execution
main() {
    local cmd="${1:-help}"
    local phc_dev="${2:-$DEFAULT_PHC}"

    case "$cmd" in
        start)
            phc_exists "$phc_dev" || die "PHC device $phc_dev not found. Try: ls -la /dev/ptp*"
            start_sync "$phc_dev"
            ;;
        stop)
            stop_sync
            ;;
        restart)
            phc_exists "$phc_dev" || die "PHC device $phc_dev not found. Try: ls -la /dev/ptp*"
            restart_sync "$phc_dev"
            ;;
        status)
            show_status "$phc_dev"
            ;;
        diagnose)
            run_diagnostics "$phc_dev"
            ;;
        once)
            phc_exists "$phc_dev" || die "PHC device $phc_dev not found. Try: ls -la /dev/ptp*"
            run_once "$phc_dev"
            ;;
        help|-h|--help|"")
            usage
            ;;
        *)
            die "Unknown command '$cmd' (try 'help')"
            ;;
    esac
}

main "$@"
