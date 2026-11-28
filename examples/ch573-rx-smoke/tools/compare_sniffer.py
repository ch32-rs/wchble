#!/usr/bin/env python3
"""Compare CH573 rx-smoke frames with an nRF Sniffer pcap, byte for byte.

Usage:
  compare_sniffer.py rx.log capture.pcap [--show N]

rx.log is the defmt output: a `state=2 … len=N` line followed by a `buf [..]`
line. The pcap is the Nordic DLT 272 format written by `nrfutil ble-sniffer
sniff`; each record carries the on-air PDU after the advertising access
address, so the PDU is located by searching for it.

The sniffer's per-record CRC flag is not used as ground truth: the same PDU is
broadcast many times and pcap timestamps do not align with the board clock, so
this capture cannot attribute a flag to a specific board reception. CRC status
is checked by the controlled CH585 known-answer test instead (see README).
"""
import argparse
import re
import struct

AA = bytes.fromhex("d6be898e")
MAX_LEGACY_LEN = 37


def read_rx(path):
    """Return [pdu] from `state=2 len=N` + `buf [...]` pairs."""
    frames, pending = [], None
    for line in open(path, errors="replace"):
        m = re.search(r"state=2 .*?len=(\d+)", line)
        if m:
            pending = int(m.group(1))
            continue
        m = re.search(r"buf \[([0-9, ]+)\]", line)
        if m and pending is not None:
            length, pending = pending, None
            raw = [int(x) for x in m.group(1).split(",")]
            if 0 < length <= MAX_LEGACY_LEN and len(raw) >= 2 + length:
                frames.append(bytes(raw[:2 + length]))
    return frames


def read_pcap(path):
    data = open(path, "rb").read()
    if data[:4] == bytes.fromhex("d4c3b2a1"):
        endian = "<"
    elif data[:4] == bytes.fromhex("a1b2c3d4"):
        endian = ">"
    else:
        raise SystemExit("expected a classic pcap file")
    pdus, off = set(), 24
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > len(data) - off:
            break
        pkt = data[off:off + incl]
        off += incl
        i = pkt.find(AA)
        if i < 0:
            continue
        pdu = pkt[i + len(AA):]
        if len(pdu) < 2 + pdu[1]:
            continue
        pdus.add(pdu[:2 + pdu[1]])
    return pdus


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("pcap")
    ap.add_argument("--show", type=int, default=5)
    args = ap.parse_args()

    rx = read_rx(args.log)
    captured = read_pcap(args.pcap)
    matched = [f for f in rx if f in captured]
    addrs = {f[2:8] for f in matched}
    print(f"rx frames={len(rx)} sniffer unique PDUs={len(captured)}")
    print(f"byte-exact={len(matched)}/{len(rx)} unique AdvA={len(addrs)}")
    for f in matched[: args.show]:
        print(f"match {f.hex(' ')}")


if __name__ == "__main__":
    main()
