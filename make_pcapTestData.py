#!/usr/bin/env python3
"""Generate a large pcap of synthetic Ethernet/IPv4 traffic for benchmarking.
Dependency-free (pure stdlib). Checksums are left zero: the analyzer reads
header fields, it does not validate checksums, so this does not affect parsing.

Usage: python3 make_pcap.py <num_packets> <output.pcap>
"""
import struct, sys, random

def ipv4_hdr(src, dst, proto, payload_len):
    ver_ihl = (4 << 4) | 5          # IPv4, 20-byte header
    total = 20 + payload_len
    return struct.pack("!BBHHHBBH4s4s",
                       ver_ihl, 0, total, 0, 0, 64, proto, 0, src, dst)

def tcp_hdr(sport, dport, flags):
    off = (5 << 4)                  # 20-byte TCP header, no options
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, off, flags, 65535, 0, 0)

def udp_hdr(sport, dport, payload_len):
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0)

def main():
    n = int(sys.argv[1]); out = sys.argv[2]
    random.seed(42)
    FLOWS = 1500                     # distinct connections (×2 dirs < 4096 table slots)
    flows = []
    for i in range(FLOWS):
        src = struct.pack("!4B", 10, random.randint(0,255), random.randint(0,255), random.randint(1,254))
        dst = struct.pack("!4B", 93, 184, random.randint(0,255), random.randint(1,254))
        sport = random.randint(1024, 65000); dport = random.choice([80, 443, 53])
        proto = 6 if dport != 53 else 17
        flows.append((src, dst, sport, dport, proto))
    SYN, SYNACK, ACK = 0x02, 0x12, 0x10
    eth = struct.pack("!6B6BH", 2,0,0,0,0,1, 2,0,0,0,0,2, 0x0800)  # dummy MACs, IPv4
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))  # LINKTYPE_ETHERNET
        ts = 1_600_000_000
        for i in range(n):
            src, dst, sport, dport, proto = flows[i % FLOWS]
            if proto == 6:
                # cycle SYN -> SYN-ACK -> ACK so RTT logic and flags get exercised
                phase = i % 8
                if phase == 0:   l4 = tcp_hdr(sport, dport, SYN);    s,d = (src,dst)
                elif phase == 1: l4 = tcp_hdr(dport, sport, SYNACK); s,d = (dst,src)
                else:            l4 = tcp_hdr(sport, dport, ACK);    s,d = (src,dst)
                payload = b"\x00" * (random.randint(0, 200) if phase > 1 else 0)
                ip = ipv4_hdr(s, d, 6, len(l4) + len(payload))
            else:
                payload = b"\x00" * random.randint(20, 120)
                l4 = udp_hdr(sport, dport, len(payload)); s,d = (src,dst)
                ip = ipv4_hdr(s, d, 17, len(l4) + len(payload))
            pkt = eth + ip + l4 + payload
            ts_us = (i * 10) % 1_000_000
            if i and ts_us == 0: ts += 1
            f.write(struct.pack("<IIII", ts, ts_us, len(pkt), len(pkt)))
            f.write(pkt)
    print(f"wrote {n} packets to {out}")

if __name__ == "__main__":
    main()
