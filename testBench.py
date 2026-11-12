#!/usr/bin/env python3
"""Benchmark the analyzer's file-replay throughput.

The packet count is read from the analyzer's own summary line
("Packets received by callback"), so there is nothing to type and it cannot
disagree with what was actually processed.

Timed runs send output to /dev/null so we measure parsing + flow tracking,
not terminal rendering. The best (fastest) of N runs is reported to reduce
noise from other programs using the CPU.

Usage:   python3 testBench.py <analyzer> <file.pcap> [runs]
Example: python3 testBench.py ./analyzer testData.pcap
"""
import re, subprocess, sys, time

if len(sys.argv) < 3:
    sys.exit(__doc__)

analyzer = sys.argv[1]
pcap     = sys.argv[2]
runs     = int(sys.argv[3]) if len(sys.argv) > 3 else 5

# Untimed first run: gets the packet count and warms the file cache.
first = subprocess.run([analyzer, "-r", pcap], capture_output=True, text=True)
if first.returncode != 0:
    sys.exit(f"analyzer failed (exit {first.returncode}):\n{first.stderr or first.stdout}")

m = re.search(r"Packets received by callback\s*:\s*(\d+)", first.stdout)
if not m:
    sys.exit("could not find 'Packets received by callback' in the analyzer output")
packets = int(m.group(1))
if packets == 0:
    sys.exit("analyzer processed 0 packets; nothing to benchmark")
print(f"file: {pcap}  ({packets:,} packets)\n")

best = float("inf")
for i in range(runs):
    t0 = time.perf_counter()
    subprocess.run([analyzer, "-r", pcap], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dt = time.perf_counter() - t0
    best = min(best, dt)
    print(f"  run {i+1}: {dt:.3f} s  ({packets/dt:,.0f} packets/sec)")

print(f"\nbest wall time : {best:.3f} s for {packets:,} packets")
print(f"throughput     : {packets/best:,.0f} packets/sec")
