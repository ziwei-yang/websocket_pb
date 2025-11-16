#!/usr/bin/env python3
"""Analyze batch benchmark results - comprehensive statistical analysis"""

import sys
import statistics
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_batch.py <timestamps_file>")
        sys.exit(1)
    
    timestamps_file = sys.argv[1]
    
    with open(timestamps_file, 'r') as f:
        timestamps = [line.strip() for line in f if line.strip()]
    
    if not timestamps:
        print("No timestamps found!")
        sys.exit(1)
    
    n_runs = len(timestamps)
    print(f"\n{'='*80}")
    print(f"BATCH ANALYSIS: {n_runs} Runs")
    print(f"{'='*80}\n")
    
    # Extract data from all runs
    data = {}  # {(ssl, io): [values...]}
    
    for i, ts in enumerate(timestamps, 1):
        filepath = f"./benchmark_results/policy_benchmark_report_{ts}.txt"
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            for line in content.split('\n'):
                if line.startswith('|') and any(ssl in line for ssl in ['OpenSSL', 'WolfSSL', 'LibreSSL']):
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 7:
                        ssl = parts[1].strip()
                        io = parts[2].strip()
                        mean_str = parts[5].strip()
                        
                        if ssl and io and mean_str and mean_str != 'Mean (μs)':
                            try:
                                mean_val = float(mean_str)
                                key = (ssl, io)
                                if key not in data:
                                    data[key] = []
                                data[key].append(mean_val)
                            except ValueError:
                                pass
        except FileNotFoundError:
            print(f"Warning: Report {filepath} not found")
    
    # Calculate and display statistics
    print("Configuration            │  N  │  Mean  │ StdDev │  Min   │  Max   │  CV%   │ Median")
    print("─" * 90)
    
    results = []
    for (ssl, io), values in sorted(data.items()):
        if values:
            n = len(values)
            mean_val = statistics.mean(values)
            stddev = statistics.stdev(values) if len(values) > 1 else 0
            min_val = min(values)
            max_val = max(values)
            median = statistics.median(values)
            cv = (stddev / mean_val * 100) if mean_val > 0 else 0
            
            print(f"{ssl:<10} + {io:<12} │ {n:3d} │ {mean_val:6.2f} │ {stddev:6.2f} │ {min_val:6.2f} │ {max_val:6.2f} │ {cv:5.1f}% │ {median:6.2f}")
            results.append((ssl, io, mean_val, stddev, cv, n))
    
    print("\n" + "="*80)
    print("RANKING (by mean latency)")
    print("="*80 + "\n")
    
    for i, (ssl, io, mean_val, stddev, cv, n) in enumerate(sorted(results, key=lambda x: x[2]), 1):
        medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i:2d}."
        print(f"{medal} {ssl:<10} + {io:<12} : {mean_val:6.2f} μs (±{stddev:5.2f}, CV={cv:4.1f}%, n={n})")
    
    print()

if __name__ == "__main__":
    main()
