# Network Traffic Analyzer

A command-line packet analyzer written in C on top of libpcap. It captures live traffic or replays saved `.pcap` files, decodes packets layer by layer, tracks connections, and measures TCP handshake round-trip time.

Built to learn how packet capture and protocol decoding work below the level of the usual tools. It runs on Linux and macOS.

## What it does

- **Captures** live from a network interface or reads a saved `.pcap` file, with an optional BPF filter (for example `tcp port 443`).
- **Decodes** Ethernet and BSD/macOS loopback frames, then IPv4 and IPv6, then TCP, UDP, ICMP and ICMPv6. Headers are read straight from the raw bytes, with bounds checks against the captured length.
- **Tracks connections** in a fixed-size hash table: packet and byte counts per source/destination pair.
- **Measures handshake RTT** by matching each SYN with its SYN-ACK.
- **Reports** the top connections by bytes (`-n N`, default 10) and packet counters at the end of a run, with kernel drop counts for live captures. An optional `-s N` prints a snapshot every N seconds of capture time. Live runs on a terminal show a one-line status (elapsed time, packets, flows, drops) on stderr.
- **Shuts down cleanly** on Ctrl+C.

## Build

Requires a C compiler and libpcap.

```bash
# macOS: libpcap ships with the system
make

# Debian/Ubuntu
sudo apt install libpcap-dev
make
```

## Usage

```
./analyzer [-i interface | -r file.pcap] [-f "bpf filter"] [-c count] [-s seconds] [-n top]
./analyzer -l
```

| Option | Meaning |
|---|---|
| `-i` | capture live on this interface (default: first available) |
| `-r` | read packets from a saved pcap file instead |
| `-f` | BPF filter expression, e.g. `"tcp port 443"` |
| `-c` | stop after this many packets (default: no limit) |
| `-s` | print a connection snapshot every N seconds (default: off) |
| `-n` | number of connections to list, ranked by bytes (default: 10) |
| `-l` | list capture interfaces and exit |
| `-h` | show help |

Live capture needs root, because the OS only lets privileged users read raw packets. Replaying a file does not.

```bash
./analyzer -l                                    # list interfaces
sudo ./analyzer -i en0 -f "tcp port 443"         # live, filtered
sudo ./analyzer -i en0 -s 5                      # live, snapshot every 5 s
sudo ./analyzer -i en0 > capture.log             # live, events saved to a file (status line stays on screen)
sudo tcpdump -i en0 -c 500 -w test.pcap          # save a capture...
./analyzer -r test.pcap                          # ...and analyze it, no sudo
```

### Example output

Replaying a small sample capture:

```
Reading from file: sample.pcap
Processing file...
[RTT] 10.0.0.1:5000 -> 93.184.216.34:443 : 12.00 ms
[RTT] [2001:db8::1]:6000 -> [2001:db8:abcd:ef01:2345:6789:abcd:ef01]:80 : 25.00 ms
[ICMP] 10.0.0.1 -> 8.8.8.8 (42 bytes)

=== Top 5 of 5 connections by bytes ===
Connection                              Packets        Bytes
----------                              -------        -----
10.0.0.1:5000 -> 93.184.216.34:443          115         6210
10.0.0.1:5353 -> 8.8.8.8:53                   1           62
93.184.216.34:443 -> 10.0.0.1:5000            1           54
...

=== Capture Summary ===
Packets received by callback : 120
Decoded (IPv4/IPv6)          : 120
TCP/UDP packets tracked      : 119
```

For a live capture the summary also shows the kernel's received and dropped counts.

## Design

```
main.c      option parsing, wiring
capture.c   libpcap setup (live / file), BPF filter, signal handling, counters, reports
decoder.c   raw bytes -> PacketInfo (Ethernet / loopback -> IPv4 / IPv6 -> TCP / UDP / ICMP)
tracker.c   connection table: fixed 4096-slot hash table, linear probing, top-N by bytes, no dynamic allocation
metrics.c   SYN / SYN-ACK matching for handshake RTT
```

## Benchmark

File-replay throughput, single-threaded, 1,000,000 synthetic packets (a mix of TCP with handshakes and UDP, spread over 1,500 flows), output sent to `/dev/null`:

| Machine | Result (best of 5) | Range across runs |
|---|---|---|
| MacBook Air | **1.68 million packets/sec** | 1.60M – 1.68M |

This measures how fast the parsing and connection tracking code runs. It is not live wire speed, which the network card and the OS limit. To reproduce:

```bash
python3 make_pcapTestData.py 1000000 testData.pcap
python3 testBench.py ./analyzer testData.pcap
```

## Known limitations

- **Connections are directional.** `A→B` and `B→A` are separate table entries, and the key does not include the protocol.
- **No expiry.** Table entries are never removed. When all 4096 slots fill, new connections are dropped with a message. The pending-SYN list (1024 entries) has no expiry either, so unanswered SYNs eventually stop RTT measurement.
- **IPv6 extension headers are not followed.** Packets that use them show as protocol `???`.
- **Snapshots fire when a packet arrives.** On a silent network, nothing prints until the next packet.
