#!/usr/bin/env python3
"""
Fastest IP Probe - Exchange Endpoint Latency Measurement

Measures TCP SYN-ACK RTT and TLS handshake latency to all IPs
a hostname resolves to. Identifies the fastest endpoint for
low-latency trading connections.

Bypasses /etc/hosts by querying DNS servers directly (8.8.8.8, 1.1.1.1).

Usage:
    ./tools/fastest_ip_probe.py                           # Probe stream.binance.com
    ./tools/fastest_ip_probe.py --host ws.okx.com         # Probe OKX
    ./tools/fastest_ip_probe.py --host ws.okx.com --port 8443
    ./tools/fastest_ip_probe.py --continuous              # Monitor continuously
    ./tools/fastest_ip_probe.py --json                    # JSON output
    ./tools/fastest_ip_probe.py --fastest-only            # Output only fastest IP (for scripts)
"""

import argparse
import socket
import ssl
import time
import json
import sys
import subprocess
import statistics
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import dnspython for direct DNS queries (bypasses /etc/hosts)
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


@dataclass
class ProbeResult:
    ip: str
    tcp_rtt_us: float           # TCP SYN-ACK RTT in microseconds
    tcp_rtt_min_us: float       # Min RTT across samples
    tcp_rtt_max_us: float       # Max RTT across samples
    tcp_rtt_stddev_us: float    # Standard deviation
    tls_handshake_us: float     # Full TLS handshake time
    success_rate: float         # Fraction of successful probes
    samples: int                # Number of samples taken
    error: Optional[str] = None


@dataclass
class ProbeConfig:
    host: str = "stream.binance.com"
    port: int = 443
    samples: int = 10
    timeout_s: float = 2.0
    delay_between_ms: int = 50
    parallel: bool = True
    measure_tls: bool = True


def resolve_host_dns(host: str, dns_servers: List[str] = None) -> List[str]:
    """
    Resolve hostname to all A records using direct DNS queries.
    Bypasses /etc/hosts to get real DNS responses with all IPs.
    """
    if dns_servers is None:
        dns_servers = ["8.8.8.8", "1.1.1.1"]  # Google, Cloudflare

    all_ips = set()

    # Method 1: Use dnspython if available (best)
    if HAS_DNSPYTHON:
        for server in dns_servers:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [server]
                resolver.lifetime = 5.0
                answers = resolver.resolve(host, 'A')
                for rdata in answers:
                    all_ips.add(str(rdata))
            except Exception as e:
                print(f"DNS query to {server} failed: {e}", file=sys.stderr)
        if all_ips:
            return sorted(all_ips)

    # Method 2: Use dig command (fallback)
    for server in dns_servers:
        try:
            result = subprocess.run(
                ["dig", "+short", f"@{server}", host, "A"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    line = line.strip()
                    # Filter valid IPv4 addresses (dig may return CNAMEs)
                    if line and all(c.isdigit() or c == '.' for c in line):
                        all_ips.add(line)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"dig @{server} failed: {e}", file=sys.stderr)

    if all_ips:
        return sorted(all_ips)

    # Method 3: Fall back to system resolver (may be limited by /etc/hosts)
    print("Warning: Using system resolver (may be limited by /etc/hosts)", file=sys.stderr)
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return sorted(set(ips))
    except socket.gaierror as e:
        print(f"DNS resolution failed for {host}: {e}", file=sys.stderr)
        return []


def resolve_host(host: str) -> List[str]:
    """Resolve hostname - wrapper for backwards compatibility."""
    return resolve_host_dns(host)


def measure_tcp_rtt(ip: str, port: int, timeout_s: float) -> Tuple[float, Optional[str]]:
    """
    Measure TCP connection RTT (SYN -> SYN-ACK).
    Returns (rtt_us, error_string).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        start = time.perf_counter_ns()
        sock.connect((ip, port))
        end = time.perf_counter_ns()
        rtt_us = (end - start) / 1000.0
        return rtt_us, None
    except socket.timeout:
        return -1, "timeout"
    except ConnectionRefusedError:
        return -1, "refused"
    except OSError as e:
        return -1, str(e)
    finally:
        sock.close()


def measure_tls_handshake(ip: str, port: int, host: str, timeout_s: float) -> Tuple[float, Optional[str]]:
    """
    Measure full TLS handshake time (TCP + TLS negotiation).
    Returns (handshake_us, error_string).
    """
    context = ssl.create_default_context()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        start = time.perf_counter_ns()
        sock.connect((ip, port))
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        end = time.perf_counter_ns()
        handshake_us = (end - start) / 1000.0
        ssl_sock.close()
        return handshake_us, None
    except socket.timeout:
        return -1, "timeout"
    except ssl.SSLError as e:
        return -1, f"ssl:{e.reason}"
    except OSError as e:
        return -1, str(e)
    finally:
        try:
            sock.close()
        except:
            pass


def probe_ip(ip: str, config: ProbeConfig) -> ProbeResult:
    """Run multiple probe samples against a single IP."""
    tcp_rtts = []
    tls_times = []
    errors = []

    for i in range(config.samples):
        # TCP RTT measurement
        rtt, err = measure_tcp_rtt(ip, config.port, config.timeout_s)
        if err:
            errors.append(err)
        else:
            tcp_rtts.append(rtt)

        # Small delay between probes
        if i < config.samples - 1:
            time.sleep(config.delay_between_ms / 1000.0)

    # TLS handshake measurement (fewer samples, it's slower)
    if config.measure_tls and tcp_rtts:
        for _ in range(min(3, config.samples)):
            tls_time, err = measure_tls_handshake(ip, config.port, config.host, config.timeout_s)
            if not err:
                tls_times.append(tls_time)
            time.sleep(config.delay_between_ms / 1000.0)

    # Compute statistics
    if tcp_rtts:
        return ProbeResult(
            ip=ip,
            tcp_rtt_us=statistics.median(tcp_rtts),
            tcp_rtt_min_us=min(tcp_rtts),
            tcp_rtt_max_us=max(tcp_rtts),
            tcp_rtt_stddev_us=statistics.stdev(tcp_rtts) if len(tcp_rtts) > 1 else 0,
            tls_handshake_us=statistics.median(tls_times) if tls_times else -1,
            success_rate=len(tcp_rtts) / config.samples,
            samples=len(tcp_rtts),
        )
    else:
        return ProbeResult(
            ip=ip,
            tcp_rtt_us=float('inf'),
            tcp_rtt_min_us=float('inf'),
            tcp_rtt_max_us=float('inf'),
            tcp_rtt_stddev_us=0,
            tls_handshake_us=-1,
            success_rate=0,
            samples=0,
            error=errors[0] if errors else "unknown",
        )


def probe_all_ips(ips: List[str], config: ProbeConfig) -> List[ProbeResult]:
    """Probe all IPs, optionally in parallel."""
    results = []

    if config.parallel and len(ips) > 1:
        with ThreadPoolExecutor(max_workers=min(len(ips), 8)) as executor:
            futures = {executor.submit(probe_ip, ip, config): ip for ip in ips}
            for future in as_completed(futures):
                results.append(future.result())
    else:
        for ip in ips:
            results.append(probe_ip(ip, config))

    # Sort by median TCP RTT
    results.sort(key=lambda r: r.tcp_rtt_us)
    return results


def format_table(results: List[ProbeResult], host: str) -> str:
    """Format results as ASCII table."""
    lines = []
    lines.append(f"\n{'='*78}")
    lines.append(f"  Latency Probe: {host}")
    lines.append(f"  {len(results)} IPs found, sorted by TCP RTT (fastest first)")
    lines.append(f"{'='*78}")
    lines.append("")
    lines.append(f"{'IP':>18}  {'TCP RTT':>10}  {'min':>8}  {'max':>8}  {'stddev':>8}  {'TLS':>10}  {'OK':>5}")
    lines.append(f"{'-'*18}  {'-'*10}  {'-'*8}  {'-'*8}  {'-'*8}  {'-'*10}  {'-'*5}")

    for r in results:
        if r.error:
            lines.append(f"{r.ip:>18}  {'FAILED':>10}  {'-':>8}  {'-':>8}  {'-':>8}  {'-':>10}  {r.error:>5}")
        else:
            tls_str = f"{r.tls_handshake_us:>7.0f} us" if r.tls_handshake_us > 0 else "-"
            lines.append(
                f"{r.ip:>18}  {r.tcp_rtt_us:>7.0f} us  "
                f"{r.tcp_rtt_min_us:>5.0f} us  {r.tcp_rtt_max_us:>5.0f} us  "
                f"{r.tcp_rtt_stddev_us:>5.0f} us  {tls_str:>10}  "
                f"{r.success_rate*100:>4.0f}%"
            )

    if results and not results[0].error:
        best = results[0]
        lines.append("")
        lines.append(f"{'='*78}")
        lines.append(f"  FASTEST: {best.ip}  ({best.tcp_rtt_us:.0f} us TCP RTT)")
        lines.append("")
        lines.append(f"  To pin this IP:")
        lines.append(f"    echo '{best.ip} {host}' | sudo tee -a /etc/hosts")
        lines.append("")
        lines.append(f"  Or use in code with SNI:")
        lines.append(f"    connect(\"{best.ip}\", 443);")
        lines.append(f"    ssl_set_sni(\"{host}\");")
        lines.append(f"{'='*78}")

    return "\n".join(lines)


def format_json(results: List[ProbeResult], host: str) -> str:
    """Format results as JSON."""
    output = {
        "host": host,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": [asdict(r) for r in results],
        "fastest_ip": results[0].ip if results and not results[0].error else None,
    }
    return json.dumps(output, indent=2)


def run_continuous(config: ProbeConfig, interval_s: int, json_output: bool,
                   dns_servers: List[str] = None):
    """Continuously probe and report."""
    print(f"Continuous monitoring of {config.host} (Ctrl+C to stop)", file=sys.stderr)
    print(f"Probe interval: {interval_s}s, Samples per probe: {config.samples}", file=sys.stderr)

    best_ip_history = {}

    try:
        while True:
            ips = resolve_host_dns(config.host, dns_servers)
            if not ips:
                print(f"[{time.strftime('%H:%M:%S')}] No IPs resolved", file=sys.stderr)
                time.sleep(interval_s)
                continue

            results = probe_all_ips(ips, config)

            if json_output:
                print(format_json(results, config.host))
            else:
                # Compact continuous output
                ts = time.strftime('%H:%M:%S')
                best = results[0] if results else None
                if best and not best.error:
                    # Track if best IP changed
                    marker = ""
                    if best.ip in best_ip_history:
                        if best_ip_history.get("_last") != best.ip:
                            marker = " [NEW BEST]"
                    best_ip_history[best.ip] = best_ip_history.get(best.ip, 0) + 1
                    best_ip_history["_last"] = best.ip

                    print(f"[{ts}] {len(ips)} IPs | BEST: {best.ip:>15} "
                          f"TCP={best.tcp_rtt_us:>6.0f}us (min={best.tcp_rtt_min_us:.0f}) "
                          f"TLS={best.tls_handshake_us:>7.0f}us{marker}")
                else:
                    print(f"[{ts}] {len(ips)} IPs | All probes failed")

            time.sleep(interval_s)

    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        if best_ip_history:
            print("\nBest IP frequency:", file=sys.stderr)
            for ip, count in sorted(best_ip_history.items(), key=lambda x: -x[1] if x[0] != "_last" else 0):
                if ip != "_last":
                    print(f"  {ip}: {count} times", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Probe latency to exchange WebSocket endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                              # Probe stream.binance.com
    %(prog)s --host ws.okx.com --port 8443
    %(prog)s --continuous --interval 30   # Monitor every 30s
    %(prog)s --json                       # JSON output for scripting
    %(prog)s --samples 20                 # More samples for accuracy
    %(prog)s --dns 8.8.8.8,1.1.1.1        # Use specific DNS servers
"""
    )
    parser.add_argument("--host", default="stream.binance.com",
                        help="Hostname to probe (default: stream.binance.com)")
    parser.add_argument("--port", type=int, default=443,
                        help="Port to probe (default: 443)")
    parser.add_argument("--samples", type=int, default=10,
                        help="Number of probe samples per IP (default: 10)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Connection timeout in seconds (default: 2.0)")
    parser.add_argument("--dns", type=str, default="8.8.8.8,1.1.1.1",
                        help="DNS servers to query (comma-separated, default: 8.8.8.8,1.1.1.1)")
    parser.add_argument("--no-tls", action="store_true",
                        help="Skip TLS handshake measurement")
    parser.add_argument("--sequential", action="store_true",
                        help="Probe IPs sequentially (default: parallel)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--fastest-only", action="store_true",
                        help="Output only the fastest IP (for scripts)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress progress messages (implies --fastest-only)")
    parser.add_argument("--continuous", action="store_true",
                        help="Continuously monitor (Ctrl+C to stop)")
    parser.add_argument("--interval", type=int, default=60,
                        help="Probe interval for continuous mode (default: 60s)")

    args = parser.parse_args()

    # Parse DNS servers
    dns_servers = [s.strip() for s in args.dns.split(',') if s.strip()]

    config = ProbeConfig(
        host=args.host,
        port=args.port,
        samples=args.samples,
        timeout_s=args.timeout,
        parallel=not args.sequential,
        measure_tls=not args.no_tls,
    )

    # --quiet implies --fastest-only
    fastest_only = args.fastest_only or args.quiet
    quiet = args.quiet

    if args.continuous:
        run_continuous(config, args.interval, args.json, dns_servers)
    else:
        # One-shot probe
        if not quiet:
            print(f"Resolving {config.host} via DNS ({', '.join(dns_servers)})...", file=sys.stderr)
        ips = resolve_host_dns(config.host, dns_servers)

        if not ips:
            if not quiet:
                print(f"ERROR: No IPs resolved for {config.host}", file=sys.stderr)
            sys.exit(1)

        if not quiet:
            print(f"Found {len(ips)} IPs, probing ({config.samples} samples each)...",
                  file=sys.stderr)

        results = probe_all_ips(ips, config)

        if not results or results[0].error:
            if not quiet:
                print(f"ERROR: All probes failed", file=sys.stderr)
            sys.exit(1)

        if fastest_only:
            # Output just the fastest IP (for shell script integration)
            print(results[0].ip)
        elif args.json:
            print(format_json(results, config.host))
        else:
            print(format_table(results, config.host))


if __name__ == "__main__":
    main()
