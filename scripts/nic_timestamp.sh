#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER_BIN="$ROOT_DIR/build/check_hw_timestamp"
DEFAULT_TX_MODE="${HWSTAMP_TX_MODE:-1}"   # 1 = enable TX timestamps
DEFAULT_RX_FILTER="${HWSTAMP_RX_FILTER:-1}" # 1 = timestamp all RX packets (see hwstamp_ctl -h)

usage() {
    cat <<'EOF'
Usage: nic_timestamp.sh <command> [options]

Commands:
  status  <iface>   Show NIC driver features (ethtool -k/-T) and current hwstamp_ctl profile
  verify  <iface>   Build + run the hardware timestamp diagnostic tool
  enable  <iface>   Install linuxptp if needed, then run: sudo hwstamp_ctl -i <iface> -t 1 -r 1
  disable <iface>   Disable NIC hardware timestamps via: sudo hwstamp_ctl -i <iface> -t 0 -r 0
  help              Print this message

Examples:
  ./scripts/nic_timestamp.sh status eth0
  sudo ./scripts/nic_timestamp.sh enable enp108s0
  ./scripts/nic_timestamp.sh verify eno1

Environment overrides:
  HWSTAMP_TX_MODE   (default 1) hwstamp_ctl -t value
  HWSTAMP_RX_FILTER (default 1) hwstamp_ctl -r value (1=all packets)
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found in PATH"
}

need_iface() {
    [[ -n "${1:-}" ]] || die "Interface name is required (see --help)"
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
    die "This action requires root; install sudo/doas or re-run as root"
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

ensure_checker() {
    if [[ -x "$CHECKER_BIN" ]]; then
        return
    fi
    require_cmd make
    echo "[build] Compiling hardware timestamp diagnostic tool..."
    (cd "$ROOT_DIR" && make check-hw-timestamp >/dev/null)
    if [[ ! -x "$CHECKER_BIN" ]]; then
        die "Failed to build $CHECKER_BIN"
    fi
}

ensure_hwstamp_ctl() {
    if command -v hwstamp_ctl >/dev/null 2>&1; then
        return 0
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        echo "[warn] hwstamp_ctl not found and apt-get unavailable; install linuxptp manually." >&2
        return 1
    fi

    echo "[deps] Installing linuxptp via: sudo apt-get install linuxptp"
    if with_priv apt-get -y install linuxptp; then
        command -v hwstamp_ctl >/dev/null 2>&1
    else
        echo "[warn] Failed to install linuxptp automatically." >&2
        return 1
    fi
}

show_status() {
    local iface="$1"
    require_cmd ethtool
    echo "=== Feature state for $iface (sudo ethtool -k $iface) ==="
    if ! with_priv ethtool -k "$iface" | grep -i timestamp; then
        echo "No timestamp-related features reported by ethtool -k"
    fi
    echo
    echo "=== Timestamp capabilities (sudo ethtool -T $iface) ==="
    with_priv ethtool -T "$iface"

    if command -v hwstamp_ctl >/dev/null 2>&1; then
        echo
        echo "=== Active hwstamp configuration (sudo hwstamp_ctl -i $iface) ==="
        if ! with_priv hwstamp_ctl -i "$iface"; then
            echo "(hwstamp_ctl reported an error; is the interface up?)"
        fi
    fi
}

run_checker() {
    local iface="$1"
    ensure_checker
    echo
    echo "=== Running hardware timestamp diagnostic ==="
    "$CHECKER_BIN" "$iface"
}

configure_hwstamp() {
    local iface="$1"
    local tx_mode="$2"
    local rx_filter="$3"

    if ! ensure_hwstamp_ctl; then
        return 1
    fi

    echo "Applying hardware timestamp settings via: sudo hwstamp_ctl -i $iface -t $tx_mode -r $rx_filter"
    if with_priv hwstamp_ctl -i "$iface" -t "$tx_mode" -r "$rx_filter"; then
        echo
        with_priv hwstamp_ctl -i "$iface"
        echo
        return 0
    fi

    echo "[warn] hwstamp_ctl configuration failed on $iface" >&2
    return 1
}

toggle_features() {
    local iface="$1"
    local tx_mode="$2"
    local rx_filter="$3"

    if configure_hwstamp "$iface" "$tx_mode" "$rx_filter"; then
        show_status "$iface"
        return
    fi

    require_cmd ethtool
    local fallback_mode
    fallback_mode=$([[ "$tx_mode" == "0" && "$rx_filter" == "0" ]] && echo "off" || echo "on")
    echo "Falling back to ethtool -K (sudo ethtool -K $iface rx-timestamping $fallback_mode tx-timestamping $fallback_mode)"
    if ! with_priv ethtool -K "$iface" rx-timestamping "$fallback_mode" tx-timestamping "$fallback_mode"; then
        die "Failed to configure timestamping on $iface (hwstamp_ctl and ethtool -K both failed)"
    fi
    echo
    show_status "$iface"
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        status)
            need_iface "${2:-}"
            show_status "$2"
            ;;
        verify)
            need_iface "${2:-}"
            show_status "$2"
            run_checker "$2"
            ;;
        enable)
            need_iface "${2:-}"
            toggle_features "$2" "$DEFAULT_TX_MODE" "$DEFAULT_RX_FILTER"
            ;;
        disable)
            need_iface "${2:-}"
            toggle_features "$2" 0 0
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
