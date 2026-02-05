#!/usr/bin/env python3
"""Analyze frame_records binary dumps: stage-by-stage latency breakdown."""

import argparse
import struct
import sys
import math
from pathlib import Path
from collections import defaultdict

# --- WSFrameInfo parsing (128 bytes) ---
HEADER_STRUCT = struct.Struct('<II')  # record_count, record_size
FRAME_STRUCT = struct.Struct('<II BBBB HH 10Q II 3Q')  # 128 bytes

FIELD_NAMES = [
    'msg_inbox_offset', 'payload_len',
    'opcode', 'is_fin', 'is_fragmented', 'is_last_fragment',
    'ssl_read_ct', 'nic_packet_ct',
    'first_byte_ts', 'last_byte_ts',
    'first_bpf_entry_ns', 'latest_bpf_entry_ns',
    'first_poll_cycle', 'latest_poll_cycle',
    'first_ssl_read_start', 'publish_time_ts',
    'ssl_last_op_cycle', 'latest_ssl_read_end',
    'ssl_read_batch_num', 'ssl_read_total_bytes', 'ws_last_op_cycle',
    'ws_parse_cycle', 'ws_frame_publish_cycle',
]


def read_frame_records(path):
    """Return (records: list[dict], record_count, record_size)."""
    data = Path(path).read_bytes()
    if len(data) < HEADER_STRUCT.size:
        print(f"Error: file too small ({len(data)} bytes)", file=sys.stderr)
        sys.exit(1)

    record_count, record_size = HEADER_STRUCT.unpack_from(data, 0)

    if record_size != FRAME_STRUCT.size:
        print(f"Error: record_size={record_size}, expected {FRAME_STRUCT.size}",
              file=sys.stderr)
        sys.exit(1)

    expected = HEADER_STRUCT.size + record_count * record_size
    if len(data) < expected:
        print(f"Error: file truncated ({len(data)} < {expected} bytes)",
              file=sys.stderr)
        sys.exit(1)

    records = []
    offset = HEADER_STRUCT.size
    for _ in range(record_count):
        vals = FRAME_STRUCT.unpack_from(data, offset)
        records.append(dict(zip(FIELD_NAMES, vals)))
        offset += record_size

    return records, record_count, record_size


def get_tsc_freq_hz():
    """Auto-detect TSC frequency from multiple kernel/sysfs sources."""
    # 1. sysfs base_frequency (most reliable on modern Intel)
    try:
        with open('/sys/devices/system/cpu/cpu0/cpufreq/base_frequency') as f:
            khz = int(f.read().strip())
            return khz * 1000
    except (OSError, ValueError):
        pass

    # 2. /proc/cpuinfo "model name" line with "@ X.XXGHz"
    try:
        with open('/proc/cpuinfo') as f:
            for line in f:
                if line.startswith('model name'):
                    idx = line.find('@')
                    if idx != -1:
                        rest = line[idx + 1:].strip()
                        for token in rest.split():
                            token_lower = token.lower()
                            if 'ghz' in token_lower:
                                ghz = float(token_lower.replace('ghz', ''))
                                return int(ghz * 1e9)
                    break  # only need first core
    except (OSError, ValueError):
        pass

    return None


# --- Histogram (reused from analyze_ws_latency.py) ---
BLOCKS = " ▏▎▍▌▋▊▉█"  # 9 chars: 0/8 through 8/8


def bar_str(fraction, width):
    """Render a fractional-width bar using unicode block chars."""
    full = int(fraction * width)
    remainder = (fraction * width) - full
    idx = int(remainder * 8)
    return "█" * full + (BLOCKS[idx] if idx > 0 or full == 0 else "")


def _nice_step(raw):
    """Round raw bin width up to a clean 1/2/5 × 10^k step."""
    if raw <= 0:
        return 1.0
    exp = math.floor(math.log10(raw))
    mag = 10 ** exp
    normed = raw / mag  # in [1, 10)
    if normed <= 1.0:
        nice = 1.0
    elif normed <= 2.0:
        nice = 2.0
    elif normed <= 5.0:
        nice = 5.0
    else:
        nice = 10.0
    return nice * mag


def _fmt_decimals(step):
    """Return number of decimal places needed to distinguish bin edges."""
    if step >= 1.0:
        return 0
    return max(1, -math.floor(math.log10(step)) + 1)


def print_histogram(values, title, unit="us", bar_width=44):
    """Print histogram with unicode block bars."""
    if not values:
        print(f"\n{title}: NO DATA\n")
        return

    values = sorted(values)
    n = len(values)
    p50 = values[int(n * 0.50)]
    p90 = values[int(n * 0.90)]
    p99 = values[min(int(n * 0.99), n - 1)]
    mn, mx = values[0], values[-1]

    print(f"\n {title} ({unit})")
    # Extra precision for tight scales (based on median, not max)
    vfmt = '.3f' if p50 < 0.5 else '.2f' if p50 < 6.0 else '.1f'
    print(f" n={n}  min={mn:{vfmt}}  p50={p50:{vfmt}}  p90={p90:{vfmt}}  p99={p99:{vfmt}}  max={mx:{vfmt}}")
    print(f" {'─' * 68}")

    # Focus on the dense region up to ~p99
    p99_val = values[min(int(n * 0.99), n - 1)]
    focus_max = p99_val * 1.1
    if focus_max <= mn:
        focus_max = mx

    # Pick a clean bin width targeting ~20 bins in the focus region
    # Fixed bins for tight scales based on median: 0.1us (<0.5us), 0.5us (<3us)
    if p50 < 0.5:
        step = 0.1
    elif p50 < 6.0:
        step = 0.5
    else:
        raw_step = (focus_max - mn) / 20
        step = _nice_step(raw_step)

    # Align bin start to a multiple of step at or below mn
    bin_start = math.floor(mn / step) * step

    # Build bins: linear bins covering [bin_start, cutoff), plus one overflow
    cutoff = bin_start
    while cutoff < focus_max:
        cutoff += step
    num_bins = round((cutoff - bin_start) / step)

    bins = [0] * num_bins
    overflow = 0
    for v in values:
        if v >= cutoff:
            overflow += 1
        else:
            idx = int((v - bin_start) / step)
            idx = max(0, min(idx, num_bins - 1))
            bins[idx] += 1

    # Find max count for bar scaling
    max_count = max(max(bins), overflow) if overflow else max(bins)
    if max_count == 0:
        max_count = 1

    dec = _fmt_decimals(step)

    # Print bins (skip empty bins)
    for i in range(num_bins):
        count = bins[i]
        if count == 0:
            continue
        lo = bin_start + i * step
        hi = lo + step
        label = f" {lo:7.{dec}f} - {hi:<7.{dec}f}"
        frac = count / max_count
        bar = bar_str(frac, bar_width)
        pct_val = count / n * 100
        print(f" {label}▏{bar:<{bar_width}s} {count:5d} {pct_val:5.1f}%")

    # Overflow bin
    if overflow > 0:
        label = f"    >{cutoff:<7.{dec}f}    "
        frac = overflow / max_count
        bar = bar_str(frac, bar_width)
        pct_val = overflow / n * 100
        print(f" {label}▏{bar:<{bar_width}s} {overflow:5d} {pct_val:5.1f}%")

    print()


# --- Percentile helper ---
def pct(sorted_vals, p):
    """Return percentile value from sorted list. p in [0, 100]."""
    if not sorted_vals:
        return 0.0
    idx = p / 100.0 * (len(sorted_vals) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


# --- Stage definitions ---
STAGES = [
    ("Poll → SSL Read Start",      'first_ssl_read_start', 'first_poll_cycle'),
    ("SSL Read (decrypt)",          'latest_ssl_read_end',   'first_ssl_read_start'),
    ("SSL Read End → WS Parse",    'ws_parse_cycle',       'latest_ssl_read_end'),
    ("WS Parse → Frame Publish",   'ws_frame_publish_cycle', 'ws_parse_cycle'),
    ("Full: Poll → WS Parse",      'ws_parse_cycle',       'first_poll_cycle'),
    ("Full: Poll → Frame Publish", 'ws_frame_publish_cycle', 'first_poll_cycle'),
]


def main():
    parser = argparse.ArgumentParser(
        description='Analyze frame_records binary dumps: stage-by-stage latency breakdown.')
    parser.add_argument('bin_file', help='Path to *_frame_records_*.bin file')
    parser.add_argument('--min-payload', type=int, default=160,
                        help='Minimum payload_len (default: 160)')
    parser.add_argument('--max-payload', type=int, default=200,
                        help='Maximum payload_len (default: 200)')
    args = parser.parse_args()

    # --- TSC frequency ---
    tsc_freq = get_tsc_freq_hz()
    if tsc_freq is None:
        print("Error: could not auto-detect TSC frequency from sysfs or /proc/cpuinfo.",
              file=sys.stderr)
        sys.exit(1)

    tsc_to_us = 1e6 / tsc_freq  # multiply cycles by this to get µs

    # --- Read records ---
    records, record_count, record_size = read_frame_records(args.bin_file)

    print(f"Loaded {record_count} records from {args.bin_file}")
    print(f"  record_size = {record_size} bytes")
    print(f"  tsc_freq    = {tsc_freq / 1e9:.3f} GHz")

    # --- Filter ---
    qualifying = []
    for r in records:
        if r['opcode'] != 0x01:
            continue
        if r['is_fragmented']:
            continue
        if r['ssl_read_ct'] != 1:
            continue
        if r['nic_packet_ct'] != 1:
            continue
        if not (args.min_payload <= r['payload_len'] <= args.max_payload):
            continue
        if not (args.min_payload <= r['ssl_read_total_bytes'] <= args.max_payload):
            continue
        # All TSC timestamps > 0 and monotonically ordered
        tsc_chain = [
            r['first_poll_cycle'],
            r['first_ssl_read_start'],
            r['latest_ssl_read_end'],
            r['ws_parse_cycle'],
            r['ws_frame_publish_cycle'],
        ]
        if any(t == 0 for t in tsc_chain):
            continue
        if not all(a < b for a, b in zip(tsc_chain, tsc_chain[1:])):
            continue
        qualifying.append(r)

    print(f"\nFilter: payload_len in [{args.min_payload}, {args.max_payload}], "
          f"ssl_read_total_bytes in [{args.min_payload}, {args.max_payload}], "
          f"TEXT, 1-pkt, 1-ssl, not fragmented")
    print(f"  Qualifying: {len(qualifying)} / {record_count} records")

    if not qualifying:
        print("\nNo qualifying records. Try widening --min-payload / --max-payload.")
        return

    # --- Compute stage latencies (µs) ---
    stage_values = [[] for _ in STAGES]
    for r in qualifying:
        for i, (label, end_field, start_field) in enumerate(STAGES):
            cycles = r[end_field] - r[start_field]
            stage_values[i].append(cycles * tsc_to_us)

    # Sort for percentile computation
    for sv in stage_values:
        sv.sort()

    # --- Percentile summary table ---
    n = len(qualifying)
    percentiles = [('Min', 0), ('P50', 50), ('P90', 90), ('P95', 95),
                   ('P99', 99), ('P99.9', 99.9), ('Max', 100)]

    print(f"\n Stage Latency Summary (us)          N={n}")
    print(f" {'─' * 80}")
    header = f" {'':30s}"
    for plabel, _ in percentiles:
        header += f" {plabel:>6s}"
    header += f" {'Mean':>6s}"
    print(header)

    for i, (label, _, _) in enumerate(STAGES):
        sv = stage_values[i]
        p50_val = pct(sv, 50)
        vfmt = '6.3f' if p50_val < 0.5 else '6.2f' if p50_val < 6.0 else '6.1f'
        line = f" {i + 1}. {label:27s}"
        for _, p in percentiles:
            val = pct(sv, p)
            line += f" {val:{vfmt}}"
        mean = sum(sv) / len(sv)
        line += f" {mean:{vfmt}}"
        print(line)

    # --- Per-stage histograms ---
    for i, (label, _, _) in enumerate(STAGES):
        print_histogram(stage_values[i], f"{i + 1}. {label}")

    # --- WS Polling Latency: busy vs idle split ---
    busy_wait = []   # ring wait time (us) for busy records
    idle_stage3 = [] # SSL Read End → WS Parse (us) for idle records
    busy_stage3 = [] # SSL Read End → WS Parse (us) for busy records
    for r in qualifying:
        last_op = r['ws_last_op_cycle']
        ssl_end = r['latest_ssl_read_end']
        s3_us = (r['ws_parse_cycle'] - ssl_end) * tsc_to_us
        if last_op > ssl_end:
            busy_wait.append((last_op - ssl_end) * tsc_to_us)
            busy_stage3.append(s3_us)
        else:
            idle_stage3.append(s3_us)

    n_busy = len(busy_wait)
    n_idle = len(idle_stage3)
    n_total = n_busy + n_idle

    print(f"\n WS Polling Latency Analysis")
    print(f" {'─' * 68}")
    if n_total == 0:
        print(" No records with ws_last_op_cycle data.")
    else:
        # Records with ws_last_op_cycle == 0 are pre-first-op; count separately
        n_no_op = sum(1 for r in qualifying if r['ws_last_op_cycle'] == 0)
        if n_no_op > 0:
            print(f" Note: {n_no_op} records have ws_last_op_cycle=0 (first frame, no prior op)")
        print(f" Busy: {n_busy}/{n_total} ({n_busy / n_total * 100:.1f}%)  "
              f"Idle: {n_idle}/{n_total} ({n_idle / n_total * 100:.1f}%)")
        print(f"   Busy = ws_last_op_cycle > latest_ssl_read_end (data waited in ring)")
        print(f"   Idle = ws_last_op_cycle <= latest_ssl_read_end (WS was waiting)")

        if n_busy > 0:
            busy_wait.sort()
            percentiles_bw = [('Min', 0), ('P50', 50), ('P90', 90), ('P95', 95),
                              ('P99', 99), ('Max', 100)]
            bw_p50 = pct(busy_wait, 50)
            vfmt = '7.4f' if bw_p50 < 0.5 else '7.3f' if bw_p50 < 6.0 else '7.2f'
            print(f"\n Ring Wait Time (busy records only, us)  N={n_busy}")
            print(f" {'─' * 68}")
            header = f" {'':20s}"
            for plabel, _ in percentiles_bw:
                header += f" {plabel:>7s}"
            print(header)
            line = f" {'Ring Wait':20s}"
            for _, p in percentiles_bw:
                val = pct(busy_wait, p)
                line += f" {val:{vfmt}}"
            print(line)

            print_histogram(busy_wait, "Ring Wait Time (busy)", unit="us")

        if n_busy > 0 or n_idle > 0:
            print_histogram(busy_stage3, "SSL Read End → WS Parse (busy)", unit="us")
            print_histogram(idle_stage3, "SSL Read End → WS Parse (idle)", unit="us")

    # --- Process Lateness Analysis ---
    # Detect model: if ssl_last_op_cycle == ws_last_op_cycle for most records → single-process
    n_same = sum(1 for r in qualifying
                 if r['ssl_last_op_cycle'] == r['ws_last_op_cycle'] and r['ssl_last_op_cycle'] > 0)
    n_with_ssl_op = sum(1 for r in qualifying if r['ssl_last_op_cycle'] > 0)
    is_single_process = (n_with_ssl_op > 0 and n_same / n_with_ssl_op > 0.9)

    print(f"\n Process Lateness Analysis")
    print(f" {'─' * 68}")
    if n_with_ssl_op == 0:
        print(" No records with ssl_last_op_cycle data.")
    else:
        model = "single-process" if is_single_process else "multi-process"
        print(f" Detected model: {model} (ssl==ws: {n_same}/{n_with_ssl_op})")

        # to_time(cycle) = first_bpf_entry_ns + (cycle - first_poll_cycle) * ns_per_cycle
        ns_per_cycle = 1e9 / tsc_freq

        def compute_late_us(records, name, cycle_field, ref='bpf'):
            """Compute lateness values in us. ref='bpf' uses to_time-bpf, ref='ssl_end' uses TSC diff."""
            vals = []
            for r in records:
                cyc = r[cycle_field]
                if cyc == 0:
                    continue
                if ref == 'bpf':
                    if r['first_poll_cycle'] == 0 or r['first_bpf_entry_ns'] == 0:
                        continue
                    late_ns = (cyc - r['first_poll_cycle']) * ns_per_cycle
                    vals.append(late_ns / 1000.0)
                elif ref == 'ssl_end':
                    ssl_end = r['latest_ssl_read_end']
                    if ssl_end == 0:
                        continue
                    late_ns = (cyc - ssl_end) * ns_per_cycle
                    vals.append(late_ns / 1000.0)
            return vals

        def print_late_table(name, vals):
            if not vals:
                print(f"\n {name}: NO DATA")
                return
            vals_sorted = sorted(vals)
            n_v = len(vals_sorted)
            n_late = sum(1 for v in vals_sorted if v > 0)
            n_idle = n_v - n_late
            mean = sum(vals_sorted) / n_v
            print(f"\n {name}  N={n_v}")
            print(f" {'─' * 68}")
            ptiles = [('Min', 0), ('P50', 50), ('P90', 90), ('P95', 95),
                      ('P99', 99), ('Max', 100)]
            p50_val = pct(vals_sorted, 50)
            vfmt = '7.3f' if abs(p50_val) < 0.5 else '7.2f' if abs(p50_val) < 6.0 else '7.1f'
            header = f" {'':12s}"
            for plabel, _ in ptiles:
                header += f" {plabel:>7s}"
            header += f" {'Mean':>7s}"
            print(header)
            line = f" {'Lateness':12s}"
            for _, p in ptiles:
                val = pct(vals_sorted, p)
                line += f" {val:{vfmt}}"
            line += f" {mean:{vfmt}}"
            print(line)
            print(f" Late: {n_late}/{n_v} ({n_late / n_v * 100:.1f}%) — process was busy when pkt arrived")
            print(f" Idle: {n_idle}/{n_v} ({n_idle / n_v * 100:.1f}%) — process was waiting")

        # main_late = (ws_last_op_cycle - first_poll_cycle) in us
        main_vals = [v for v in compute_late_us(qualifying, 'main_late', 'ws_last_op_cycle', ref='bpf') if v >= 0]
        print_late_table("main_late (us) — main loop lateness", main_vals)
        print_histogram(main_vals, "main_late", unit="us")

        # ssl_late = (ssl_last_op_cycle - first_poll_cycle) in us
        ssl_vals = [v for v in compute_late_us(qualifying, 'ssl_late', 'ssl_last_op_cycle', ref='bpf') if v >= 0]
        print_late_table("ssl_late (us) — transport process lateness", ssl_vals)
        print_histogram(ssl_vals, "ssl_late", unit="us")

        # ws_late = (ws_last_op_cycle - latest_ssl_read_end) in us
        ws_vals = [v for v in compute_late_us(qualifying, 'ws_late', 'ws_last_op_cycle', ref='ssl_end') if v >= 0]
        print_late_table("ws_late (us) — WS process lateness", ws_vals)
        print_histogram(ws_vals, "ws_late", unit="us")

    # --- Print qualifying samples (timeline format, skip ws_late) ---
    idle_samples = [r for r in qualifying
                    if r['ws_last_op_cycle'] <= r['latest_ssl_read_end']]
    late_count = len(qualifying) - len(idle_samples)
    print(f"\n Qualifying Samples ({len(idle_samples)} idle, {late_count} ws_late skipped)")
    print(f" {'─' * 100}")
    for r in idle_samples:
        now = r['ws_frame_publish_cycle']
        def us_ago(cycle):
            return (now - cycle) * tsc_to_us if cycle > 0 and now > cycle else 0.0

        def fmt_range(us_first, us_last):
            larger = max(us_first, us_last)
            if larger < 1000.0:
                return f"{us_first:6.1f}", f"{us_last:6.1f}us"
            else:
                return f"{us_first / 1000.0:6.2f}", f"{us_last / 1000.0:6.2f}ms"

        def fmt(us):
            if us < 1000.0:
                return f"{us:6.1f}us"
            else:
                return f"{us / 1000.0:6.2f}ms"

        p0, p1 = fmt_range(us_ago(r['first_poll_cycle']), us_ago(r['latest_poll_cycle']))
        s0, s1 = fmt_range(us_ago(r['first_ssl_read_start']), us_ago(r['latest_ssl_read_end']))
        sz = f"{r['payload_len']}/{r['ssl_read_total_bytes']}B"
        parse = fmt(us_ago(r['ws_parse_cycle']))
        total = fmt(us_ago(r['first_poll_cycle']))
        batch = r['ssl_read_batch_num']

        print(f" | poll {r['nic_packet_ct']:2d} pkt {p0} ~ {p1:>8s} "
              f"| ssl {r['ssl_read_ct']:2d} x {sz:<10s} {s0} ~ {s1:>8s} "
              f"| parse {batch:03d} {parse:>8s} "
              f"| total {total:>8s} |")


if __name__ == "__main__":
    main()
