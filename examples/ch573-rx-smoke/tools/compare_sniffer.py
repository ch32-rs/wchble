#!/usr/bin/env python3
"""Compare CH573 rx-smoke frames with an nRF Sniffer pcap, byte for byte.

Usage:
  compare_sniffer.py rx.log capture.pcap [--show N]

rx.log is the defmt output: a `state=2 … len=N … crc=…` line followed by a
`buf [..]` line. The pcap is the Nordic DLT 272 format written by
`nrfutil ble-sniffer sniff`; each record carries the on-air PDU after the
advertising access address, so the PDU is located by searching for it. The
Nordic flag byte (offset 8) bit0 is the sniffer's CRC-ok verdict, so the
script also reports how the board's `crc=` field agrees with it.
"""
import argparse
import re
import struct

AA = bytes.fromhex("d6be898e")
MAX_LEGACY_LEN = 37


def read_rx(path):
    """Return [(pdu, crc_ok)] from `state=2 len=N … crc=…` + `buf [...]`."""
    frames, pending = [], None
    for line in open(path, errors="replace"):
        m = re.search(r"state=2 .*?len=(\d+) .*?crc=(true|false)", line)
        if m:
            pending = (int(m.group(1)), m.group(2) == "true")
            continue
        m = re.search(r"buf \[([0-9, ]+)\]", line)
        if m and pending is not None:
            length, crc_ok = pending
            raw = [int(x) for x in m.group(1).split(",")]
            if 0 < length <= MAX_LEGACY_LEN and len(raw) >= 2 + length:
                frames.append((bytes(raw[:2 + length]), crc_ok))
            pending = None
    return frames


def read_pcap(path):
    data = open(path, "rb").read()
    if data[:4] == bytes.fromhex("d4c3b2a1"):
        endian = "<"
    elif data[:4] == bytes.fromhex("a1b2c3d4"):
        endian = ">"
    else:
        raise SystemExit("expected a classic pcap file")
    pdus, off = [], 24
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
        # Nordic DLT 272: byte 8 is the flag byte, bit0 = CRC ok.
        pdus.append((pdu[:2 + pdu[1]], bool(pkt[8] & 1)))
    return pdus


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("pcap")
    ap.add_argument("--show", type=int, default=5)
    args = ap.parse_args()

    rx = read_rx(args.log)
    captured = read_pcap(args.pcap)
    by_pdu = {}
    for pdu, crc_ok in captured:
        by_pdu.setdefault(pdu, crc_ok)
    matched = [(f, ours) for f, ours in rx if f in by_pdu]
    addrs = {f[2:8] for f, _ in matched}
    print(f"rx frames={len(rx)} sniffer records={len(captured)} unique={len(by_pdu)}")
    print(f"byte-exact={len(matched)}/{len(rx)} unique AdvA={len(addrs)}")
    agree = sum(1 for f, ours in matched if ours == by_pdu[f])
    print(f"crc agree={agree}/{len(matched)} (sniffer flags) ")
    for f, ours in matched[:args.show]:
        print(f"match {f.hex(' ')} ours={ours} sniffer={by_pdu[f]}")
    for f, ours in matched:
        if ours != by_pdu[f]:
            print(f"MISMATCH {f.hex(' ')} ours={ours} sniffer={by_pdu[f]}")


if __name__ == "__main__":
    main()
