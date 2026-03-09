#!/usr/bin/env python3
"""
Detect multi-connection same-SEQ interleave from timeline logs.

Usage:
    python3 tools/find_same_seq_interleave.py ./log/271*.log
    python3 tools/find_same_seq_interleave.py --examples ./log/271*.log
    python3 tools/find_same_seq_interleave.py --examples --top 5 ./log/271*.log
    python3 tools/find_same_seq_interleave.py --verbose --top 20 ./log/271*.log

Modes:
    (default)    Summary statistics: how many seqs had interleave opportunities
    --examples   Find and display concrete examples of multi-connection WSFrame
                 packet interleaving (packets from different conns for the same
                 seq arriving interleaved in time)
    --verbose    Show detailed per-event listing for top interleave opportunities
"""

import re
import argparse
from collections import defaultdict, Counter

# Strip ANSI escape sequences
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Timeline log line pattern (after stripping ANSI):
#   <conn_hex> <gap>| nic ... | <N> pkt <pkt#> ... | ssl ... | WS ... |<X?> <count?> <type> @ ... | +<lat> | #<seq> <arrow?>
LINE_RE = re.compile(
    r'^([0-9a-f])\s+'           # conn_id (single hex char)
    r'.*\|\s*'                  # skip to event section
    r'(X?)\s*'                  # X flag (discarded)
    r'(\d*)\s*'                 # entry count (may be empty for discarded)
    r'(Dp|D1|D2|OB|Td|Mp|Lq)'  # event type
    r'\s+@\s*'                  # @ separator
    r'([\d.]+\w+)'             # arrival time
    r'.*\|\s*'                  # skip to latency
    r'\+(\d+\w+)'              # latency
    r'\s*\|\s*'                 # separator
    r'#(\d+)'                   # sequence number
    r'\s*(<?-?)'                # arrow (<- = final published)
)

# Extract WS frame count from the WS section: "WS <N> <time>"
WS_FRAME_RE = re.compile(r'\| WS\s+(\d+)\s')


def parse_log(filepath):
    """Parse a timeline log file and return depth events grouped by seq."""
    seqs = defaultdict(list)

    with open(filepath, 'r', errors='replace') as f:
        for lineno, raw_line in enumerate(f, 1):
            line = ANSI_RE.sub('', raw_line).rstrip()
            m = LINE_RE.match(line)
            if not m:
                continue

            event_type = m.group(4)
            if event_type not in ('Dp', 'D1', 'D2'):
                continue

            conn_id = m.group(1)
            x_flag = m.group(2) == 'X'
            count_str = m.group(3)
            entry_count = int(count_str) if count_str else 0

            # Extract WS frame number (tells us which packet of the WS message)
            ws_m = WS_FRAME_RE.search(line)
            ws_frame_n = int(ws_m.group(1)) if ws_m else 0

            seqs[int(m.group(7))].append({
                'conn': conn_id,
                'x': x_flag,
                'count': entry_count,
                'type': event_type,
                'arrival': m.group(5),
                'latency': m.group(6),
                'published': not x_flag and entry_count > 0,
                'final': m.group(8) == '<-',
                'ws_frame': ws_frame_n,
                'lineno': lineno,
            })

    return seqs


def analyze_interleave(seqs):
    """Analyze seq groups for interleave opportunities."""
    results = []

    for seq, events in sorted(seqs.items()):
        by_conn = defaultdict(list)
        for ev in events:
            by_conn[ev['conn']].append(ev)

        if len(by_conn) < 2:
            continue

        publishers = []
        loser_conns = []

        for conn_id, conn_events in by_conn.items():
            is_publisher = any(e['published'] for e in conn_events)
            if is_publisher:
                total_entries = max((e['count'] for e in conn_events), default=0)
                publishers.append({
                    'conn': conn_id,
                    'packets': len(conn_events),
                    'total': total_entries,
                    'has_final': any(e['final'] for e in conn_events),
                })
            else:
                loser_conns.append({
                    'conn': conn_id,
                    'packets': len(conn_events),
                    'events': conn_events,
                })

        if not publishers:
            continue

        publishers.sort(key=lambda p: (p['has_final'], p['total']), reverse=True)
        primary = publishers[0]

        any_multi_publisher = any(p['packets'] > 1 for p in publishers)
        multi_flush_losers = [l for l in loser_conns if l['packets'] > 1]

        # Compute interleave score: number of connection switches in timeline order
        conn_order = [e['conn'] for e in events]
        switches = sum(1 for i in range(1, len(conn_order))
                       if conn_order[i] != conn_order[i-1])

        results.append({
            'seq': seq,
            'winner': primary['conn'],
            'winner_packets': primary['packets'],
            'winner_total': primary['total'],
            'publishers': publishers,
            'losers': loser_conns,
            'multi_flush_losers': multi_flush_losers,
            'interleave_opportunity': any_multi_publisher and len(multi_flush_losers) > 0,
            'total_conns': len(by_conn),
            'switches': switches,
            'events': events,
        })

    return results


def find_interleave_examples(results, top_n=5):
    """Find examples where a depth SEQ is split across multiple TCP packets
    (ws#1, ws#2, ws#3, ...) and packets from different connections arrive
    interleaved in time.

    Criteria:
    - At least 2 connections each have ws_frame >= 2 (multi-packet WS frame)
    - Packets from different connections are interleaved in arrival order
    - Manageable size for display (6-40 lines)
    """
    candidates = []

    for r in results:
        events = r['events']
        n = len(events)
        if n < 6 or n > 40:
            continue

        # Count connections with multi-packet delivery (ws_frame >= 2)
        by_conn = defaultdict(list)
        for ev in events:
            by_conn[ev['conn']].append(ev)

        multi_pkt_conns = []
        for conn_id, evts in by_conn.items():
            max_ws = max(e['ws_frame'] for e in evts)
            if max_ws >= 2:
                multi_pkt_conns.append((conn_id, max_ws, len(evts)))

        if len(multi_pkt_conns) < 2:
            continue

        # Check for true interleaving (not sequential per-connection)
        conn_order = [e['conn'] for e in events]
        switches = r['switches']
        unique_conns = len(set(conn_order))
        min_switches = unique_conns - 1
        if switches <= min_switches:
            continue

        # Filter: the first connection to arrive (first ws#1 in timeline)
        # must NOT be the final winner — shows that initial pkt doesn't
        # always determine winner
        first_conn = events[0]['conn']
        winner_conn = None
        for ev in events:
            if ev['final']:
                winner_conn = ev['conn']
                break
        if winner_conn is None:
            continue
        if first_conn == winner_conn:
            continue  # first mover won — not interesting

        # Score: prefer more multi-pkt connections, higher switch ratio,
        # and moderate sizes (not too small, not too large)
        switch_ratio = switches / max(n - 1, 1)
        multi_pkt_count = len(multi_pkt_conns)
        score = multi_pkt_count * 10 + switch_ratio * 5 - abs(n - 15) * 0.1

        candidates.append((score, r, multi_pkt_conns))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [(c[1], c[2]) for c in candidates[:top_n]]


def print_example(r, multi_pkt_info, index):
    """Print a single interleave example with annotation."""
    events = r['events']
    conn_order = [e['conn'] for e in events]
    pub_conns = {p['conn'] for p in r['publishers']}

    # Build per-connection ws_frame progression
    by_conn = defaultdict(list)
    for ev in events:
        by_conn[ev['conn']].append(ev)

    print(f"\n{'='*90}")
    print(f"  Example {index}: SEQ #{r['seq']}")
    print(f"  Lines {events[0]['lineno']}-{events[-1]['lineno']}  "
          f"({len(events)} timeline entries, {len(set(conn_order))} conns, "
          f"{r['switches']} conn-switches)")

    # Show multi-packet connections with their ws# range and entry progression
    print(f"  Multi-packet connections (WS frame split across TCP segments):")
    for conn_id, max_ws, n_lines in sorted(multi_pkt_info,
                                            key=lambda x: x[1], reverse=True):
        evts = by_conn[conn_id]
        counts = [e['count'] for e in evts if e['count']]
        final = any(e['final'] for e in evts)
        x_count = sum(1 for e in evts if e['x'])
        status = '<- WINNER' if final else f'{x_count}X' if x_count else 'pub'
        entry_str = '→'.join(str(c) for c in counts) if counts else '(all X)'
        print(f"    conn {conn_id}: {n_lines} pkts (ws#1..#{max_ws})  "
              f"entries: {entry_str}  [{status}]")

    if r['losers']:
        single_pkt_losers = [l for l in r['losers']
                             if l['packets'] == 1]
        if single_pkt_losers:
            ids = ', '.join(l['conn'] for l in single_pkt_losers)
            print(f"  Single-packet losers (all X): {ids}")
    print(f"{'='*90}")

    # Print events with clear status indicators
    prev_conn = None
    for ev in events:
        if ev['final']:
            flag = '<-'
        elif ev['x']:
            flag = ' X'
        else:
            flag = '  '

        cnt = f"{ev['count']:>4}" if ev['count'] else '    '

        # Highlight connection switches with "|"
        switch = ' |' if prev_conn is not None and ev['conn'] != prev_conn else '  '
        prev_conn = ev['conn']

        role = 'pub' if ev['conn'] in pub_conns else 'dup'

        print(f"  L{ev['lineno']:>7} {flag} {switch} conn={ev['conn']} "
              f"{cnt} {ev['type']}  ws#{ev['ws_frame']:<2}  "
              f"arr={ev['arrival']:>8s}  lat={ev['latency']:>5s}  [{role}]")

    # Compact arrival order
    print(f"\n  Arrival order: {'→'.join(conn_order)}")
    print()


def print_summary(results, verbose=False, top_n=10):
    """Print analysis summary."""
    total_seqs = len(results)
    interleave_opps = [r for r in results if r['interleave_opportunity']]
    multi_pkt_winners = [r for r in results if r['winner_packets'] > 1]

    print("=" * 72)
    print("  Multi-Connection Same-SEQ Interleave Analysis")
    print("=" * 72)
    print()
    print(f"  Total depth delta seqs with 2+ connections:  {total_seqs}")
    print(f"  Winner used multi-packet (multi-flush):      {len(multi_pkt_winners)}")
    print(f"  Interleave opportunities (loser also multi): {len(interleave_opps)}")
    print()

    if not interleave_opps and not verbose:
        print("  No interleave opportunities found.")
        print("  (All depth deltas fit in single packet, or losers had single packet)")
        if multi_pkt_winners:
            print(f"\n  Note: {len(multi_pkt_winners)} seqs had multi-packet winners but")
            print(f"  all losers had single-packet delivery (no interleave benefit).")
        return

    # Connection participation stats
    conn_counts = defaultdict(lambda: {'published': 0, 'discarded': 0, 'total': 0})
    for r in results:
        for p in r['publishers']:
            conn_counts[p['conn']]['published'] += 1
            conn_counts[p['conn']]['total'] += 1
        for l in r['losers']:
            conn_counts[l['conn']]['discarded'] += 1
            conn_counts[l['conn']]['total'] += 1

    print("  Per-connection stats:")
    print(f"  {'conn':>4}  {'published':>9}  {'discarded':>9}  {'total':>6}")
    for conn_id in sorted(conn_counts.keys()):
        c = conn_counts[conn_id]
        print(f"  {conn_id:>4}  {c['published']:>9}  {c['discarded']:>9}  {c['total']:>6}")
    print()

    # Top interleave opportunities by winner entry count
    display = interleave_opps if interleave_opps else multi_pkt_winners
    display_sorted = sorted(display, key=lambda r: r['winner_total'], reverse=True)
    display_label = "interleave opportunities" if interleave_opps else "multi-packet winners"

    show_n = min(top_n, len(display_sorted))
    print(f"  Top {show_n} {display_label} (by entry count):")
    print(f"  {'seq':>20}  {'winner':>6}  {'pkts':>4}  {'entries':>7}  "
          f"{'losers':>6}  {'loser_pkts':>10}")
    print(f"  {'':->20}  {'':->6}  {'':->4}  {'':->7}  {'':->6}  {'':->10}")

    for r in display_sorted[:show_n]:
        loser_pkt_str = ','.join(f"{l['conn']}:{l['packets']}"
                                 for l in r['losers'][:4])
        if len(r['losers']) > 4:
            loser_pkt_str += f"...+{len(r['losers'])-4}"
        print(f"  #{r['seq']:<19}  {r['winner']:>6}  {r['winner_packets']:>4}  "
              f"{r['winner_total']:>7}  {r['total_conns']-1:>6}  {loser_pkt_str}")

    if verbose:
        print()
        print("=" * 72)
        print("  Detailed event listing")
        print("=" * 72)
        for r in display_sorted[:show_n]:
            pub_str = ', '.join(f"{p['conn']}:{p['total']}"
                                for p in r['publishers'])
            print(f"\n  SEQ #{r['seq']}  publishers=[{pub_str}]  "
                  f"losers={len(r['losers'])}")
            for ev in r['events']:
                if ev['final']:
                    flag = '<-'
                elif ev['x']:
                    flag = 'X '
                elif ev['published']:
                    flag = '  '
                else:
                    flag = '  '
                cnt = f"{ev['count']:>4}" if ev['count'] else '    '
                print(f"    {flag} conn={ev['conn']}  {cnt} {ev['type']}  "
                      f"arrival={ev['arrival']:>8}  lat={ev['latency']:>5}  "
                      f"line={ev['lineno']}")


def main():
    parser = argparse.ArgumentParser(
        description='Detect multi-connection same-SEQ interleave '
                    'from timeline logs')
    parser.add_argument('logfile', nargs='+',
                        help='Timeline log file(s) to analyze')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed per-event listing')
    parser.add_argument('-e', '--examples', action='store_true',
                        help='Find and display concrete examples of '
                             'multi-connection WSFrame packet interleaving')
    parser.add_argument('-t', '--top', type=int, default=10,
                        help='Show top N results (default: 10)')
    args = parser.parse_args()

    for filepath in args.logfile:
        print(f"\n  Analyzing: {filepath}")
        try:
            seqs = parse_log(filepath)
        except FileNotFoundError:
            print(f"  ERROR: File not found: {filepath}")
            continue

        depth_seqs = {s: evts for s, evts in seqs.items()
                      if any(e['type'] in ('Dp', 'D1', 'D2') for e in evts)}

        results = analyze_interleave(depth_seqs)
        print_summary(results, verbose=args.verbose, top_n=args.top)

        if args.examples:
            examples = find_interleave_examples(results, top_n=args.top)
            if examples:
                print()
                print("=" * 90)
                print("  Multi-Connection WSFrame Packet Interleave Examples")
                print("  SEQ split into multiple TCP packets, different conns'")
                print("  packets arrive interleaved in time")
                print("=" * 90)
                for i, (ex, multi_info) in enumerate(examples, 1):
                    print_example(ex, multi_info, i)
            else:
                print("\n  No interleaved packet examples found "
                      "(all seqs had sequential per-connection delivery)")

        print()


if __name__ == '__main__':
    main()
