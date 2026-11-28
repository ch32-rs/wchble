#!/usr/bin/env python3
"""Pair CH573 rx-smoke receptions with nRF Sniffer records, event by event.

Usage:
  compare_rssi_crc.py rx.log capture.pcap --seq-off 22 [--adv-a C1:FF:EE:00:00:02]

The source PDU must carry a per-event counter (`ch585-rf-smoke --features
adv-seq`, manufacturer AD `05 ff ff ff seq_lo seq_hi`). The sniffer and the
board both see a subset of the same air events, so `(seq, channel)` is the
pairing key.

Board side is the defmt log: a `state=2 ... len=N rssi=R crc=B ...` line
followed by the `buf [...]` dump. Sniffer side is a Nordic DLT 272 pcap
(protocol v3): 17 metadata bytes before the AA, flags at AA-9 (bit0 = CRC OK),
channel at AA-8, RSSI magnitude at AA-7.

Reports the CH573-RSSI minus sniffer-RSSI distribution and the CRC confusion
matrix (including "sniffer accepts, board rejects").
"""
import argparse
import re
import statistics
import struct
from collections import defaultdict

AA = bytes.fromhex("d6be898e")
META = 17
MAX_LEGACY_LEN = 37


def read_board(path, seq_off):
    """Return {(seq, ch): record} and trait-accessor mismatch counts."""
    out = {}
    pending = None
    mismatches = {"rssi": 0, "crc": 0, "checked": 0}
    rx = re.compile(
        r"ch(\d+) state=2 .*?len=(\d+) rssi=(-?\d+) crc=(true|false)"
        r"(?: .*?trssi=(-?\d+) tcrc=(true|false))?"
    )
    for line in open(path, errors="replace"):
        m = rx.search(line)
        if m:
            pending = {
                "ch": int(m.group(1)),
                "len": int(m.group(2)),
                "rssi": int(m.group(3)),
                "crc": m.group(4) == "true",
                "trssi": int(m.group(5)) if m.group(5) is not None else None,
                "tcrc": (m.group(6) == "true") if m.group(6) is not None else None,
            }
            continue
        m = re.search(r"buf \[([0-9, ]+)\]", line)
        if m and pending is not None:
            rec, pending = pending, None
            raw = [int(x) for x in m.group(1).split(",")]
            n = 2 + rec["len"]
            if not (0 < rec["len"] <= MAX_LEGACY_LEN and len(raw) >= n):
                continue
            if rec["trssi"] is not None:
                mismatches["checked"] += 1
                mismatches["rssi"] += rec["trssi"] != rec["rssi"]
                mismatches["crc"] += rec["tcrc"] != rec["crc"]
            pdu = bytes(raw[:n])
            if seq_off is None:
                key = pdu
            else:
                if seq_off + 2 > len(pdu):
                    continue
                key = (pdu[seq_off] | pdu[seq_off + 1] << 8, rec["ch"])
            out[key] = {"pdu": pdu, "rssi": rec["rssi"], "crc": rec["crc"]}
    return out, mismatches


def read_pcap(path, seq_off, adv_a):
    """Return {(seq, ch): record}, keeping the first duplicate per event."""
    data = open(path, "rb").read()
    endian = "<" if data[:4] == bytes.fromhex("d4c3b2a1") else ">"
    if data[:4] not in (bytes.fromhex("d4c3b2a1"), bytes.fromhex("a1b2c3d4")):
        raise SystemExit("expected a classic pcap file")
    out, dup = {}, 0
    off = 24
    while off + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > len(data) - off:
            break
        pkt = data[off:off + incl]
        off += incl
        i = pkt.find(AA)
        if i < META or i + 6 > len(pkt):
            continue
        pdu = pkt[i + 4:]
        if len(pdu) < 2 + pdu[1] or pdu[1] > MAX_LEGACY_LEN:
            continue
        pdu = pdu[:2 + pdu[1]]
        if adv_a is not None and pdu[2:8] not in (adv_a, adv_a[::-1]):
            continue
        if seq_off is None:
            key = pdu
        else:
            if seq_off + 2 > len(pdu):
                continue
            key = (pdu[seq_off] | pdu[seq_off + 1] << 8, pkt[i - 8])
        rec = {
            "pdu": pdu,
            "rssi": -pkt[i - 7],
            "crc": bool(pkt[i - 9] & 1),
        }
        if key in out:
            dup += 1
            continue
        out[key] = rec
    return out, dup


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("pcap")
    ap.add_argument("--seq-off", type=int,
                    help="byte offset of the u16 event counter in the PDU")
    ap.add_argument("--adv-a", help="only this six-byte AdvA, e.g. C1:FF:EE:00:00:02")
    args = ap.parse_args()

    adv_a = bytes(int(x, 16) for x in args.adv_a.split(":")) if args.adv_a else None
    board, mism = read_board(args.log, args.seq_off)
    sniffer, dup = read_pcap(args.pcap, args.seq_off, adv_a)

    print(f"board receptions={len(board)} sniffer records={len(sniffer)} "
          f"(duplicates skipped={dup})")
    if mism["checked"]:
        print(f"Radio::rssi/crc_ok vs Done: checked={mism['checked']} "
              f"rssi_mismatch={mism['rssi']} crc_mismatch={mism['crc']}")
    if args.seq_off is None:
        print("no --seq-off: key is the whole PDU, so repeated events collapse; "
              "per-event pairing is unavailable")

    paired = sorted(set(board) & set(sniffer))
    board_only = len(board) - len(paired)
    sniffer_only = len(sniffer) - len(paired)
    print(f"paired events={len(paired)} board-only={board_only} "
          f"sniffer-only={sniffer_only}")

    # CRC confusion, on paired events only.
    cm = defaultdict(int)
    for k in paired:
        b, s = board[k]["crc"], sniffer[k]["crc"]
        cm[("board_ok" if b else "board_bad", "sniffer_ok" if s else "sniffer_bad")] += 1
    print("\nCRC (paired):")
    for (b, s), n in sorted(cm.items()):
        print(f"  {b:9s} / {s:11s} {n}")
    key = cm.get(("board_bad", "sniffer_ok"), 0)
    print(f"  sniffer accepts, board rejects: {key}")

    # RSSI delta distribution, paired events.
    deltas = [board[k]["rssi"] - sniffer[k]["rssi"] for k in paired]
    if deltas:
        mean = statistics.fmean(deltas)
        sd = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
        lo, hi = min(deltas), max(deltas)
        med = statistics.median(deltas)
        print(f"\nRSSI delta (board - sniffer), n={len(deltas)}: "
              f"median={med:+.1f} mean={mean:+.2f} sd={sd:.2f} "
              f"range={lo:+d}..{hi:+d} dB")
        by_ch = defaultdict(list)
        for k in paired:
            by_ch[k[1] if isinstance(k, tuple) else 0].append(
                board[k]["rssi"] - sniffer[k]["rssi"]
            )
        for ch, ds in sorted(by_ch.items()):
            if len(ds) >= 2:
                print(f"  ch{ch}: n={len(ds)} median={statistics.median(ds):+.1f} "
                      f"mean={statistics.fmean(ds):+.2f} sd={statistics.pstdev(ds):.2f}")
        # Linear fit to see whether the offset is additive.
        xs = [sniffer[k]["rssi"] for k in paired]
        ys = [board[k]["rssi"] for k in paired]
        mx, my = statistics.fmean(xs), statistics.fmean(ys)
        den = sum((x - mx) ** 2 for x in xs)
        if den:
            slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den
            print(f"  board vs sniffer fit: board = {slope:.2f} * sniffer "
                  f"+ {my - slope * mx:+.2f} dB")
        print(f"  sniffer RSSI range {min(xs)}..{max(xs)} dBm, "
              f"board RSSI range {min(ys)}..{max(ys)} dBm")


if __name__ == "__main__":
    main()
