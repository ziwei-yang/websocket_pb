#!/usr/bin/env python3
"""
TCP Options Probe - Detect remote server TCP option support

Probes a remote server to detect which TCP options it supports by analyzing
the SYN-ACK response. Requires root/CAP_NET_RAW for raw socket access.

Usage:
    sudo ./tcp_options_probe.py                        # Probe all default targets
    sudo ./tcp_options_probe.py <host> <port>          # Probe specific target
    sudo ./tcp_options_probe.py stream.binance.com 443
    sudo ./tcp_options_probe.py --list                 # List default targets

Options detected:
    - MSS (Maximum Segment Size) - RFC 879
    - Window Scaling - RFC 7323
    - SACK Permitted - RFC 2018
    - TCP Timestamps - RFC 7323 (includes PAWS)
    - TCP Fast Open (TFO) - RFC 7413
    - Multipath TCP (MPTCP) - RFC 8684
    - ECN (Explicit Congestion Notification) - RFC 3168

Requirements:
    - Python 3.8+
    - Root privileges or CAP_NET_RAW capability
    - No external dependencies (uses raw sockets)

Author: TCP Options Probe Tool
"""

import argparse
import socket
import struct
import random
import time
import sys
import os
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Any
from enum import IntEnum


# =============================================================================
# TCP Option Kinds (IANA assigned)
# =============================================================================

# =============================================================================
# Default Targets
# =============================================================================

DEFAULT_TARGETS = [
    ("google.com", 443, "Google (reference)"),
    ("cloudflare.com", 443, "Cloudflare CDN"),
    ("stream.binance.com", 443, "Binance WebSocket"),
    ("ws.okx.com", 8443, "OKX WebSocket"),
]


class TCPOptionKind(IntEnum):
    EOL = 0           # End of Option List
    NOP = 1           # No-Operation
    MSS = 2           # Maximum Segment Size
    WS = 3            # Window Scale
    SACK_PERM = 4     # SACK Permitted
    SACK = 5          # SACK blocks
    TIMESTAMP = 8     # Timestamps
    TFO = 34          # TCP Fast Open Cookie
    MPTCP = 30        # Multipath TCP
    TCP_AO = 29       # TCP Authentication Option
    UTO = 28          # User Timeout Option

    # Experimental
    EXP1 = 253        # RFC 4727 experimental
    EXP2 = 254        # RFC 4727 experimental


# =============================================================================
# TCP Flags
# =============================================================================

class TCPFlags(IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40  # ECN-Echo
    CWR = 0x80  # Congestion Window Reduced
    NS = 0x100  # ECN Nonce Sum (in reserved bits)


# =============================================================================
# Parsed TCP Options
# =============================================================================

@dataclass
class ParsedTCPOptions:
    """Container for parsed TCP options from SYN-ACK."""
    # MSS
    mss: Optional[int] = None

    # Window Scaling (RFC 7323)
    window_scale: Optional[int] = None

    # SACK (RFC 2018)
    sack_permitted: bool = False

    # Timestamps (RFC 7323)
    timestamp_enabled: bool = False
    ts_val: Optional[int] = None
    ts_ecr: Optional[int] = None

    # TCP Fast Open (RFC 7413)
    tfo_enabled: bool = False
    tfo_cookie: Optional[bytes] = None

    # Multipath TCP (RFC 8684)
    mptcp_enabled: bool = False
    mptcp_version: Optional[int] = None
    mptcp_flags: Optional[int] = None
    mptcp_key: Optional[bytes] = None

    # ECN (RFC 3168) - detected from flags, not options
    ecn_capable: bool = False

    # TCP-AO (RFC 5925)
    tcp_ao_enabled: bool = False

    # User Timeout (RFC 5482)
    uto_enabled: bool = False
    uto_timeout: Optional[int] = None

    # Raw option bytes for unknown options
    unknown_options: List[Tuple[int, bytes]] = field(default_factory=list)


# =============================================================================
# Checksum Calculation
# =============================================================================

def checksum(data: bytes) -> int:
    """Calculate Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'

    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w

    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)

    return ~s & 0xFFFF


def tcp_checksum(src_ip: str, dst_ip: str, tcp_segment: bytes) -> int:
    """Calculate TCP checksum with pseudo-header."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    # Pseudo header: src_ip, dst_ip, zero, protocol, tcp_length
    pseudo = struct.pack('!4s4sBBH', src, dst, 0, socket.IPPROTO_TCP, len(tcp_segment))
    return checksum(pseudo + tcp_segment)


# =============================================================================
# TCP Option Building
# =============================================================================

def build_tcp_options_for_probe() -> bytes:
    """
    Build TCP options to include in SYN packet for probing.
    We include all options we want to detect support for.
    """
    options = bytearray()

    # MSS (Kind=2, Len=4): Request 1460 (typical for Ethernet)
    options += struct.pack('!BBH', TCPOptionKind.MSS, 4, 1460)

    # SACK Permitted (Kind=4, Len=2)
    options += struct.pack('!BB', TCPOptionKind.SACK_PERM, 2)

    # Timestamps (Kind=8, Len=10): TSval=current_time, TSecr=0
    ts_val = int(time.time() * 1000) & 0xFFFFFFFF
    options += struct.pack('!BBII', TCPOptionKind.TIMESTAMP, 10, ts_val, 0)

    # NOP for alignment
    options += struct.pack('!B', TCPOptionKind.NOP)

    # Window Scale (Kind=3, Len=3): Scale factor 7 (128x)
    options += struct.pack('!BBB', TCPOptionKind.WS, 3, 7)

    # TCP Fast Open (Kind=34, Len=2): Empty cookie request
    # Note: TFO cookie request is just the option with no cookie
    options += struct.pack('!BB', TCPOptionKind.TFO, 2)

    # MPTCP (Kind=30): MP_CAPABLE subtype
    # Subtype 0 = MP_CAPABLE, version 1, flags
    # Format: Kind(1) + Len(1) + Subtype|Version(1) + Flags(1) + Key(8)
    mptcp_key = random.getrandbits(64)
    options += struct.pack('!BBBBQ', TCPOptionKind.MPTCP, 12,
                          (0 << 4) | 1,  # subtype=0 (MP_CAPABLE), version=1
                          0x81,          # flags: H=1 (HMAC-SHA256), checksum required
                          mptcp_key)

    # Pad to 4-byte boundary
    while len(options) % 4:
        options += struct.pack('!B', TCPOptionKind.NOP)

    return bytes(options)


def build_tcp_options_minimal() -> bytes:
    """Build minimal TCP options (just MSS, SACK, TS, WS) for compatibility."""
    options = bytearray()

    # MSS
    options += struct.pack('!BBH', TCPOptionKind.MSS, 4, 1460)

    # SACK Permitted
    options += struct.pack('!BB', TCPOptionKind.SACK_PERM, 2)

    # Timestamps
    ts_val = int(time.time() * 1000) & 0xFFFFFFFF
    options += struct.pack('!BBII', TCPOptionKind.TIMESTAMP, 10, ts_val, 0)

    # NOP + Window Scale
    options += struct.pack('!B', TCPOptionKind.NOP)
    options += struct.pack('!BBB', TCPOptionKind.WS, 3, 7)

    return bytes(options)


# =============================================================================
# TCP Packet Building
# =============================================================================

def build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq_num: int, options: bytes, ecn: bool = False) -> bytes:
    """Build a TCP SYN packet with specified options."""

    # TCP header without checksum
    data_offset = (5 + len(options) // 4) << 4  # 5 = 20 bytes base header / 4
    flags = TCPFlags.SYN
    if ecn:
        flags |= TCPFlags.ECE | TCPFlags.CWR

    # Base TCP header (20 bytes)
    tcp_header = struct.pack('!HHIIBBHHH',
        src_port,           # Source port
        dst_port,           # Destination port
        seq_num,            # Sequence number
        0,                  # Acknowledgment number
        data_offset,        # Data offset (header length)
        flags,              # Flags
        65535,              # Window size
        0,                  # Checksum (placeholder)
        0                   # Urgent pointer
    )

    # Add options
    tcp_segment = tcp_header + options

    # Calculate checksum
    chksum = tcp_checksum(src_ip, dst_ip, tcp_segment)

    # Rebuild with checksum
    tcp_header = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq_num, 0, data_offset, flags, 65535, chksum, 0
    )

    return tcp_header + options


def build_rst_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     seq_num: int) -> bytes:
    """Build a TCP RST packet to cleanly close the probing connection."""

    data_offset = 5 << 4  # 20 bytes, no options
    flags = TCPFlags.RST | TCPFlags.ACK

    tcp_header = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq_num, 0, data_offset, flags, 0, 0, 0
    )

    chksum = tcp_checksum(src_ip, dst_ip, tcp_header)

    tcp_header = struct.pack('!HHIIBBHHH',
        src_port, dst_port, seq_num, 0, data_offset, flags, 0, chksum, 0
    )

    return tcp_header


# =============================================================================
# TCP Option Parsing
# =============================================================================

def parse_tcp_options(options_bytes: bytes, flags: int) -> ParsedTCPOptions:
    """Parse TCP options from SYN-ACK response."""
    result = ParsedTCPOptions()

    # Check ECN from flags
    if flags & TCPFlags.ECE:
        result.ecn_capable = True

    i = 0
    while i < len(options_bytes):
        kind = options_bytes[i]

        # EOL - End of options
        if kind == TCPOptionKind.EOL:
            break

        # NOP - Skip
        if kind == TCPOptionKind.NOP:
            i += 1
            continue

        # All other options have length byte
        if i + 1 >= len(options_bytes):
            break

        length = options_bytes[i + 1]
        if length < 2 or i + length > len(options_bytes):
            break

        option_data = options_bytes[i + 2:i + length]

        # MSS
        if kind == TCPOptionKind.MSS and length == 4:
            result.mss = struct.unpack('!H', option_data)[0]

        # Window Scale
        elif kind == TCPOptionKind.WS and length == 3:
            result.window_scale = option_data[0]

        # SACK Permitted
        elif kind == TCPOptionKind.SACK_PERM and length == 2:
            result.sack_permitted = True

        # Timestamps
        elif kind == TCPOptionKind.TIMESTAMP and length == 10:
            result.timestamp_enabled = True
            result.ts_val, result.ts_ecr = struct.unpack('!II', option_data)

        # TCP Fast Open
        elif kind == TCPOptionKind.TFO:
            result.tfo_enabled = True
            if length > 2:
                result.tfo_cookie = option_data

        # Multipath TCP
        elif kind == TCPOptionKind.MPTCP:
            result.mptcp_enabled = True
            if len(option_data) >= 1:
                subtype_version = option_data[0]
                result.mptcp_version = subtype_version & 0x0F
                if len(option_data) >= 2:
                    result.mptcp_flags = option_data[1]
                if len(option_data) >= 10:
                    result.mptcp_key = option_data[2:10]

        # TCP-AO
        elif kind == TCPOptionKind.TCP_AO:
            result.tcp_ao_enabled = True

        # User Timeout
        elif kind == TCPOptionKind.UTO and length >= 4:
            result.uto_enabled = True
            granularity_timeout = struct.unpack('!H', option_data[:2])[0]
            granularity = (granularity_timeout >> 15) & 1
            timeout = granularity_timeout & 0x7FFF
            result.uto_timeout = timeout * (60 if granularity else 1)  # minutes or seconds

        # Unknown option
        else:
            result.unknown_options.append((kind, option_data))

        i += length

    return result


# =============================================================================
# Network Probing
# =============================================================================

def get_local_ip(target_ip: str) -> str:
    """Get local IP address that would be used to reach target."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((target_ip, 80))
        return s.getsockname()[0]


def resolve_host(host: str) -> str:
    """Resolve hostname to IP address."""
    return socket.gethostbyname(host)


def probe_tcp_options(host: str, port: int, timeout: float = 5.0,
                      use_ecn: bool = True, verbose: bool = False) -> Optional[ParsedTCPOptions]:
    """
    Probe a remote server for TCP option support.

    Sends a SYN packet with various TCP options and analyzes the SYN-ACK response.

    Args:
        host: Target hostname or IP
        port: Target port
        timeout: Response timeout in seconds
        use_ecn: Whether to set ECN flags in SYN
        verbose: Print debug information

    Returns:
        ParsedTCPOptions if successful, None on failure
    """
    # Resolve host
    try:
        dst_ip = resolve_host(host)
    except socket.gaierror as e:
        print(f"Failed to resolve {host}: {e}", file=sys.stderr)
        return None

    # Get local IP
    src_ip = get_local_ip(dst_ip)
    src_port = random.randint(40000, 60000)
    seq_num = random.randint(0, 0xFFFFFFFF)

    if verbose:
        print(f"Probing {host} ({dst_ip}:{port})")
        print(f"Local: {src_ip}:{src_port}, SEQ={seq_num}")

    # Build SYN packet with all options
    options = build_tcp_options_for_probe()
    syn_packet = build_syn_packet(src_ip, dst_ip, src_port, port, seq_num, options, ecn=use_ecn)

    # Create raw socket
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)  # Kernel builds IP header
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
    except PermissionError:
        print("Error: Raw socket requires root privileges or CAP_NET_RAW", file=sys.stderr)
        print("Run with: sudo ./tcp_options_probe.py ...", file=sys.stderr)
        return None

    try:
        # Send SYN
        send_sock.sendto(syn_packet, (dst_ip, 0))
        if verbose:
            print(f"Sent SYN ({len(syn_packet)} bytes)")

        # Wait for SYN-ACK
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = recv_sock.recvfrom(65535)
            except socket.timeout:
                print("Timeout waiting for SYN-ACK", file=sys.stderr)
                return None

            # Parse IP header to get to TCP
            ip_header_len = (data[0] & 0x0F) * 4
            tcp_data = data[ip_header_len:]

            if len(tcp_data) < 20:
                continue

            # Parse TCP header
            (recv_src_port, recv_dst_port, recv_seq, recv_ack,
             data_offset_flags, flags, window, _, _) = struct.unpack('!HHIIBBHHH', tcp_data[:20])

            # Check if this is our SYN-ACK
            if recv_src_port != port or recv_dst_port != src_port:
                continue

            if not (flags & TCPFlags.SYN and flags & TCPFlags.ACK):
                if flags & TCPFlags.RST:
                    print(f"Connection refused (RST)", file=sys.stderr)
                    return None
                continue

            if verbose:
                print(f"Received SYN-ACK from {addr[0]}:{recv_src_port}")
                print(f"  SEQ={recv_seq}, ACK={recv_ack}, Flags=0x{flags:02x}, Window={window}")

            # Parse TCP options
            tcp_header_len = (data_offset_flags >> 4) * 4
            if tcp_header_len > 20:
                options_bytes = tcp_data[20:tcp_header_len]
                result = parse_tcp_options(options_bytes, flags)

                # Send RST to clean up (ignore errors - kernel may handle this)
                try:
                    rst_packet = build_rst_packet(src_ip, dst_ip, src_port, port, seq_num + 1)
                    send_sock.sendto(rst_packet, (dst_ip, 0))
                except Exception:
                    pass  # RST is optional cleanup

                return result
            else:
                # No options in response
                return ParsedTCPOptions(ecn_capable=(flags & TCPFlags.ECE) != 0)

        print("Timeout waiting for SYN-ACK", file=sys.stderr)
        return None

    finally:
        send_sock.close()
        recv_sock.close()


# =============================================================================
# ECN Probe (separate test)
# =============================================================================

def probe_ecn_support(host: str, port: int, timeout: float = 5.0,
                      verbose: bool = False) -> Optional[bool]:
    """
    Specifically probe for ECN support by sending SYN with ECE+CWR flags.

    If server responds with ECE flag set, it supports ECN.
    """
    try:
        dst_ip = resolve_host(host)
    except socket.gaierror:
        return None

    src_ip = get_local_ip(dst_ip)
    src_port = random.randint(40000, 60000)
    seq_num = random.randint(0, 0xFFFFFFFF)

    options = build_tcp_options_minimal()
    syn_packet = build_syn_packet(src_ip, dst_ip, src_port, port, seq_num, options, ecn=True)

    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)
    except PermissionError:
        return None

    try:
        send_sock.sendto(syn_packet, (dst_ip, 0))

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, _ = recv_sock.recvfrom(65535)
            except socket.timeout:
                return None

            ip_header_len = (data[0] & 0x0F) * 4
            tcp_data = data[ip_header_len:]

            if len(tcp_data) < 20:
                continue

            recv_src_port, recv_dst_port = struct.unpack('!HH', tcp_data[:4])
            if recv_src_port != port or recv_dst_port != src_port:
                continue

            flags = tcp_data[13]
            if flags & TCPFlags.SYN and flags & TCPFlags.ACK:
                # Send RST (ignore errors - kernel may handle this)
                try:
                    rst = build_rst_packet(src_ip, dst_ip, src_port, port, seq_num + 1)
                    send_sock.sendto(rst, (dst_ip, 0))
                except Exception:
                    pass
                return (flags & TCPFlags.ECE) != 0

            if flags & TCPFlags.RST:
                return None

        return None
    finally:
        send_sock.close()
        recv_sock.close()


# =============================================================================
# Report Generation
# =============================================================================

def print_report(host: str, port: int, options: ParsedTCPOptions, ecn_result: Optional[bool]):
    """Print a formatted report of detected TCP options."""

    print()
    print("=" * 70)
    print(f"  TCP OPTIONS PROBE REPORT")
    print(f"  Target: {host}:{port}")
    print("=" * 70)
    print()

    # Table header
    print(f"{'Option':<25} {'Status':<12} {'Details'}")
    print("-" * 70)

    # MSS
    if options.mss:
        print(f"{'MSS':<25} {'SUPPORTED':<12} {options.mss} bytes")
    else:
        print(f"{'MSS':<25} {'NOT SET':<12} Server did not specify MSS")

    # Window Scaling
    if options.window_scale is not None:
        max_window = 65535 << options.window_scale
        print(f"{'Window Scaling':<25} {'SUPPORTED':<12} Scale={options.window_scale} (max window={max_window:,} bytes)")
    else:
        print(f"{'Window Scaling':<25} {'DISABLED':<12} Limited to 64KB window")

    # SACK
    if options.sack_permitted:
        print(f"{'SACK Permitted':<25} {'SUPPORTED':<12} Selective acknowledgment enabled")
    else:
        print(f"{'SACK Permitted':<25} {'DISABLED':<12} Only cumulative ACKs")

    # Timestamps
    if options.timestamp_enabled:
        print(f"{'TCP Timestamps':<25} {'SUPPORTED':<12} TSval={options.ts_val}, TSecr={options.ts_ecr}")
        print(f"{'  -> PAWS':<25} {'ENABLED':<12} Protection Against Wrapped Sequences")
        print(f"{'  -> RTTM':<25} {'ENABLED':<12} Round-Trip Time Measurement")
    else:
        print(f"{'TCP Timestamps':<25} {'DISABLED':<12} No PAWS/RTTM support")

    # ECN
    if ecn_result is True:
        print(f"{'ECN':<25} {'SUPPORTED':<12} Explicit Congestion Notification")
    elif ecn_result is False:
        print(f"{'ECN':<25} {'DISABLED':<12} Server did not echo ECE flag")
    else:
        print(f"{'ECN':<25} {'UNKNOWN':<12} Could not determine ECN support")

    # TCP Fast Open
    if options.tfo_enabled:
        if options.tfo_cookie:
            cookie_hex = options.tfo_cookie.hex()
            print(f"{'TCP Fast Open':<25} {'SUPPORTED':<12} Cookie={cookie_hex}")
        else:
            print(f"{'TCP Fast Open':<25} {'SUPPORTED':<12} No cookie provided")
    else:
        print(f"{'TCP Fast Open':<25} {'DISABLED':<12} No TFO support detected")

    # MPTCP
    if options.mptcp_enabled:
        ver = f"v{options.mptcp_version}" if options.mptcp_version else "?"
        flags = f"flags=0x{options.mptcp_flags:02x}" if options.mptcp_flags else ""
        print(f"{'Multipath TCP':<25} {'SUPPORTED':<12} {ver} {flags}")
    else:
        print(f"{'Multipath TCP':<25} {'DISABLED':<12} No MPTCP support")

    # TCP-AO
    if options.tcp_ao_enabled:
        print(f"{'TCP-AO':<25} {'SUPPORTED':<12} TCP Authentication Option")
    else:
        print(f"{'TCP-AO':<25} {'NOT SEEN':<12} (rarely used)")

    # UTO
    if options.uto_enabled:
        print(f"{'User Timeout':<25} {'SUPPORTED':<12} Timeout={options.uto_timeout}s")
    else:
        print(f"{'User Timeout':<25} {'NOT SEEN':<12} (rarely used)")

    # Unknown options
    if options.unknown_options:
        print()
        print("Unknown/Other Options:")
        for kind, data in options.unknown_options:
            print(f"  Kind={kind}, Data={data.hex() if data else '(empty)'}")

    print()
    print("-" * 70)

    # Summary
    print()
    print("SUMMARY:")
    print()

    supported = []
    if options.mss:
        supported.append("MSS")
    if options.window_scale is not None:
        supported.append("Window Scaling")
    if options.sack_permitted:
        supported.append("SACK")
    if options.timestamp_enabled:
        supported.append("Timestamps/PAWS")
    if ecn_result:
        supported.append("ECN")
    if options.tfo_enabled:
        supported.append("TFO")
    if options.mptcp_enabled:
        supported.append("MPTCP")

    if supported:
        print(f"  Supported: {', '.join(supported)}")

    not_supported = []
    if options.window_scale is None:
        not_supported.append("Window Scaling")
    if not options.sack_permitted:
        not_supported.append("SACK")
    if not options.timestamp_enabled:
        not_supported.append("Timestamps")
    if ecn_result is False:
        not_supported.append("ECN")
    if not options.tfo_enabled:
        not_supported.append("TFO")
    if not options.mptcp_enabled:
        not_supported.append("MPTCP")

    if not_supported:
        print(f"  Not Supported: {', '.join(not_supported)}")

    # Recommendations
    print()
    print("RECOMMENDATIONS FOR LOW-LATENCY:")
    print()

    if not options.timestamp_enabled:
        print("  [!] Timestamps disabled - RTT estimation will be less accurate")

    if not options.sack_permitted:
        print("  [!] SACK disabled - Loss recovery will be slower (go-back-N)")

    if options.window_scale is None:
        print("  [!] Window Scaling disabled - Throughput limited on high-BDP links")

    if ecn_result is False:
        print("  [i] ECN disabled - Congestion will cause packet drops instead of marking")

    if not options.tfo_enabled:
        print("  [i] TFO disabled - Connection setup requires full 3-way handshake")

    if (options.timestamp_enabled and options.sack_permitted and
        options.window_scale is not None):
        print("  [+] Core latency options (TS, SACK, WS) are all supported")

    print()


# =============================================================================
# Multi-target Summary
# =============================================================================

def print_summary_table(results: List[Tuple[str, int, str, Optional[ParsedTCPOptions], Optional[bool]]]):
    """Print a summary table of all probed targets."""

    print()
    print("=" * 100)
    print("  TCP OPTIONS COMPARISON TABLE")
    print("=" * 100)
    print()

    # Header
    print(f"{'Target':<35} {'MSS':>5} {'WS':>4} {'SACK':>5} {'TS':>4} {'ECN':>4} {'TFO':>4} {'MPTCP':>6}")
    print("-" * 100)

    for host, port, desc, options, ecn in results:
        target = f"{host}:{port}"
        if len(target) > 33:
            target = target[:30] + "..."

        if options is None:
            print(f"{target:<35} {'FAILED - could not probe':^63}")
            continue

        mss = str(options.mss) if options.mss else "-"
        ws = str(options.window_scale) if options.window_scale is not None else "-"
        sack = "Yes" if options.sack_permitted else "No"
        ts = "Yes" if options.timestamp_enabled else "No"
        ecn_str = "Yes" if ecn else ("No" if ecn is False else "?")
        tfo = "Yes" if options.tfo_enabled else "No"
        mptcp = "Yes" if options.mptcp_enabled else "No"

        print(f"{target:<35} {mss:>5} {ws:>4} {sack:>5} {ts:>4} {ecn_str:>4} {tfo:>4} {mptcp:>6}")

    print("-" * 100)
    print()

    # Legend
    print("Legend:")
    print("  MSS    = Maximum Segment Size (bytes)")
    print("  WS     = Window Scale factor (max window = 65535 << WS)")
    print("  SACK   = Selective Acknowledgment (RFC 2018)")
    print("  TS     = TCP Timestamps / PAWS / RTTM (RFC 7323)")
    print("  ECN    = Explicit Congestion Notification (RFC 3168)")
    print("  TFO    = TCP Fast Open (RFC 7413) - saves 1 RTT on connect")
    print("  MPTCP  = Multipath TCP (RFC 8684)")
    print()


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Probe remote server for TCP option support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  sudo %(prog)s                            # Probe all default targets
  sudo %(prog)s --list                     # List default targets
  sudo %(prog)s stream.binance.com 443     # Probe specific target
  sudo %(prog)s -v google.com 443          # Verbose mode
  sudo %(prog)s --timeout 10 slow.com 80   # Custom timeout

Default Targets:
  - google.com:443         (reference)
  - cloudflare.com:443     (CDN)
  - stream.binance.com:443 (crypto exchange)
  - ws.okx.com:8443        (crypto exchange)

Options Detected:
  - MSS (Maximum Segment Size)
  - Window Scaling (RFC 7323)
  - SACK Permitted (RFC 2018)
  - TCP Timestamps (RFC 7323)
  - TCP Fast Open (RFC 7413)
  - Multipath TCP (RFC 8684)
  - ECN (RFC 3168)
        '''
    )
    parser.add_argument('host', nargs='?', help='Target hostname or IP address')
    parser.add_argument('port', nargs='?', type=int, help='Target port')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                        help='Timeout in seconds (default: 5.0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    parser.add_argument('--no-ecn-probe', action='store_true',
                        help='Skip separate ECN probe')
    parser.add_argument('--list', action='store_true',
                        help='List default targets and exit')
    parser.add_argument('--table', action='store_true',
                        help='Output as comparison table (for multiple targets)')

    args = parser.parse_args()

    # List default targets
    if args.list:
        print("Default targets:")
        for host, port, desc in DEFAULT_TARGETS:
            print(f"  {host}:{port:<5}  - {desc}")
        sys.exit(0)

    # Check if running as root
    if os.geteuid() != 0:
        print("Warning: This tool requires root privileges for raw sockets.", file=sys.stderr)
        print("Run with: sudo ./tcp_options_probe.py ...", file=sys.stderr)
        print()

    # Determine targets
    if args.host and args.port:
        # Single target specified
        targets = [(args.host, args.port, "user-specified")]
    elif args.host and not args.port:
        print("Error: Port is required when specifying a host", file=sys.stderr)
        sys.exit(1)
    else:
        # No target specified - use defaults
        targets = DEFAULT_TARGETS
        print(f"Probing {len(targets)} default targets...")
        print()

    # Probe all targets
    results = []
    for host, port, desc in targets:
        print(f"Probing {host}:{port} ({desc})...", end=" ", flush=True)

        options = probe_tcp_options(host, port, args.timeout,
                                    use_ecn=True, verbose=args.verbose)

        if options is None:
            print("FAILED")
            results.append((host, port, desc, None, None))
            continue

        # ECN probe
        ecn_result = None
        if not args.no_ecn_probe:
            ecn_result = probe_ecn_support(host, port, args.timeout, args.verbose)
            if ecn_result is None:
                ecn_result = options.ecn_capable

        print("OK")
        results.append((host, port, desc, options, ecn_result))

    # Output results
    if len(targets) == 1 and not args.table:
        # Single target - detailed report
        host, port, desc, options, ecn = results[0]
        if options:
            print_report(host, port, options, ecn)
        else:
            print(f"\nFailed to probe {host}:{port}", file=sys.stderr)
            sys.exit(1)
    else:
        # Multiple targets - summary table
        print_summary_table(results)

        # Also print detailed reports if verbose
        if args.verbose:
            for host, port, desc, options, ecn in results:
                if options:
                    print_report(host, port, options, ecn)


if __name__ == '__main__':
    main()
