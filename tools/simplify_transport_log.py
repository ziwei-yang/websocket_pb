#!/usr/bin/env python3
"""
Simplify XDP Transport Process logs into readable packet flow.

Usage: ./simplify_transport_log.py <log_file> [output_file]

Converts verbose transport_process.hpp debug output into a simplified view:
  --> PKT n       : Server sends data packet (PKT ID = TCP sequence order)
  <-- ACK n       : Simple ACK, received PKT 0 to n
  <-- SACK n, [a,b) : SACK with cumulative n, OOO range [a,b)
"""
import re
import sys

def simplify_log(input_file, output_file=None):
    with open(input_file, 'r') as f:
        lines = f.readlines()

    output = []
    output.append("=" * 80)
    output.append("XDP PACKET FLOW - Simplified View")
    output.append("=" * 80)
    output.append("")
    output.append("Legend:")
    output.append("  --> PKT n       : Server sends data packet (PKT ID = TCP sequence order)")
    output.append("  <-- ACK n       : Simple ACK, received PKT 0 to n")
    output.append("  <-- SACK n, [a,b) OOOBuffer=x,y : SACK with cumulative n, OOO range [a,b)")
    output.append("")
    output.append("-" * 80)

    # First pass: collect all RX packets
    packets = []
    seen_seqs = set()  # Track unique seqs for deduplication
    for line in lines:
        m = re.search(r'\[TRANSPORT-RX\].*umem_id=(\d+).*seq=(\d+).*len=(\d+).*slot=(\d+)', line)
        if m:
            umem_id, seq, length, slot = m.groups()
            is_dup = int(seq) in seen_seqs
            seen_seqs.add(int(seq))
            packets.append({
                'umem_id': umem_id,
                'seq': int(seq),
                'len': int(length),
                'slot': slot,
                'end_seq': int(seq) + int(length),
                'is_dup': is_dup  # Mark retransmits
            })

    # Sort UNIQUE packets by seq to assign real packet IDs (exclude retransmits)
    unique_packets = [p for p in packets if not p['is_dup']]
    sorted_packets = sorted(unique_packets, key=lambda p: p['seq'])
    seq_to_pkt_id = {}
    for i, p in enumerate(sorted_packets):
        seq_to_pkt_id[p['seq']] = i
        p['pkt_id'] = i

    def seq_to_pkt(seq):
        for p in sorted_packets:
            if p['end_seq'] == seq:
                return p['pkt_id']
        for i, p in enumerate(sorted_packets):
            if p['seq'] > seq:
                return i - 1 if i > 0 else None
        return len(sorted_packets) - 1 if sorted_packets else None

    def seq_range_to_pkt_range(sack_start, sack_end):
        start_pkt = None
        end_pkt = None
        for p in sorted_packets:
            if p['seq'] >= sack_start and p['seq'] < sack_end:
                if start_pkt is None:
                    start_pkt = p['pkt_id']
                end_pkt = p['pkt_id'] + 1
        return start_pkt, end_pkt

    # Second pass: generate output
    arrival_idx = 0
    current_pkt_id = None
    last_ooo_buffer = ""

    for i, line in enumerate(lines):
        # RX packet
        m = re.search(r'\[TRANSPORT-RX\].*umem_id=(\d+).*seq=(\d+).*len=(\d+).*slot=(\d+)', line)
        if m:
            umem_id, seq, length, slot = m.groups()
            real_pkt_id = seq_to_pkt_id.get(int(seq), -1)
            current_pkt_id = real_pkt_id
            output.append(f"--> PKT {real_pkt_id:3d}      seq={seq} len={length}  (umem={umem_id}, slot={slot}, arrived #{arrival_idx})")
            arrival_idx += 1
            continue

        if 'TCP IN-ORDER' in line:
            m = re.search(r'rcv_nxt:.*-> (\d+)', line)
            if m:
                output.append(f"                 [IN-ORDER] rcv_nxt -> {m.group(1)}")
            continue

        if 'TCP GAP!' in line:
            m = re.search(r'expected_seq=(\d+).*got_seq=(\d+).*gap=(\d+)', line)
            if m:
                output.append(f"                 [GAP!] expected={m.group(1)} got={m.group(2)} (missing {m.group(3)} bytes)")
            continue

        if 'OOO BUFFERED' in line:
            m = re.search(r'ooo_count=(\d+)', line)
            if m:
                output.append(f"                 [BUFFERED] ooo_count={m.group(1)}")
            continue

        if 'OOO DELIVER' in line:
            m = re.search(r'len=(\d+)', line)
            if m:
                output.append(f"                 [RECOVER] delivered {m.group(1)} bytes")
            continue

        # Capture OOO-BUFFER dump for use in SACK line
        if '[OOO-BUFFER]' in line:
            m = re.search(r'count=(\d+) segments:(.*)', line)
            if m:
                count = m.group(1)
                segs_str = m.group(2).strip()
                # Parse segments: [seq=X len=Y ext=Z]
                seg_seqs = re.findall(r'seq=(\d+)', segs_str)
                ooo_pkt_ids = []
                for s in seg_seqs:
                    pkt_id = seq_to_pkt_id.get(int(s), None)
                    if pkt_id is not None:
                        ooo_pkt_ids.append(str(pkt_id))
                last_ooo_buffer = ','.join(ooo_pkt_ids) if ooo_pkt_ids else "?"
            continue

        # TX ACK (not SACK)
        if '[TRANSPORT-TX] ACK' in line and 'SACK' not in line:
            m = re.search(r'rcv_nxt=(\d+)', line)
            if m:
                ack_pkt = seq_to_pkt(int(m.group(1)))
                if ack_pkt is not None:
                    output.append(f"<-- ACK {ack_pkt:3d}      ack={m.group(1)}")
            continue

        # TX SACK ACK - parse ALL blocks from new format
        if '[TRANSPORT-TX] SACK ACK' in line:
            m = re.search(r'rcv_nxt=(\d+).*blocks=(\d+)(.*)', line)
            if m:
                rcv, blocks, rest = m.groups()
                ack_pkt = seq_to_pkt(int(rcv))

                # Parse all SACK blocks: [start-end] [start-end] ...
                sack_ranges = re.findall(r'\[(\d+)-(\d+)\]', rest)
                pkt_ranges = []
                for sack_start, sack_end in sack_ranges:
                    start_pkt, end_pkt = seq_range_to_pkt_range(int(sack_start), int(sack_end))
                    if start_pkt is not None:
                        pkt_ranges.append(f"[{start_pkt},{end_pkt})")

                sack_str = ','.join(pkt_ranges) if pkt_ranges else "[?]"
                ack_str = ack_pkt if ack_pkt is not None else "?"
                output.append(f"<-- SACK {ack_str:3}, {sack_str} ack={rcv} blocks={blocks} OOOBuffer={last_ooo_buffer}")
            continue

        if 'TCP FULL DUP' in line:
            output.append(f"                 [DUP] duplicate/retransmit")
            continue

    result = '\n'.join(output)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(result + '\n')
        print(f"Written to {output_file}")
    else:
        print(result)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    simplify_log(input_file, output_file)
