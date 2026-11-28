#!/usr/bin/env python3
"""Compare a ch573-observer RTT log with an nRF Sniffer capture.

Usage:
  compare_observer.py --board-log rtt.log --pcap capture.pcap

The capture must span the whole board run (start the sniffer first, stop it
after the board has parked). Counts are compared per AdvA. Duty cycle: each
channel gets a 15 ms window every ~64 ms round (~24% per channel); summed over
the three channels the radio is listening ~71% of wall time. A board/sniffer
ratio far below either number is the receive deficit, not just missed gaps.
This is not a per-frame identity or loss-rate measurement; the sniffer also
drops records.
"""
import argparse
import re
import statistics
import struct
import sys
from collections import Counter, defaultdict

AA = bytes.fromhex("d6be898e")
MAX_LEGACY_LEN = 37
PKT = re.compile(
    r"pkt ch(\d+) t=(\d+) len=(\d+) rssi=(-?\d+) a=\[([\d, ]+)\]"
)
SUMMARY = re.compile(
    r"obs t=(\d+) rounds=(\d+) win=(\d+) arm_err=(\d+) irq=(\d+)"
)


def read_pcap(path):
    data = open(path, "rb").read()
    if data[:4] == bytes.fromhex("d4c3b2a1"):
        endian = "<"
    elif data[:4] == bytes.fromhex("a1b2c3d4"):
        endian = ">"
    else:
        raise SystemExit("expected a classic pcap file")
    frames, off = [], 24
    while off + 16 <= len(data):
        ts_s, ts_us, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > len(data) - off:
            break
        pkt = data[off:off + incl]
        off += incl
        i = pkt.find(AA)
        if i < 12 or i + 4 + 2 > len(pkt):
            continue
        pdu = pkt[i + 4:]
        if len(pdu) < 2 + pdu[1] or pdu[1] > MAX_LEGACY_LEN:
            continue
        frames.append(
            {
                "type": pdu[0] & 0x0F,
                "pdu": pdu[: 2 + pdu[1]],
                "channel": pkt[i - 8],
                "rssi": -pkt[i - 7],
            }
        )
    return frames


# Header low nibble of the PDUs whose payload starts with an AdvA:
# ADV_IND(0), ADV_DIRECT_IND(1), ADV_NONCONN_IND(2), SCAN_RSP(4),
# ADV_SCAN_IND(6). SCAN_REQ(3) starts with ScanA and CONNECT_IND(5) with
# InitA, so they must not enter the advertiser table.
ADV_A_TYPES = (0, 1, 2, 4, 6)


def sniffer_addr(frame):
    if frame["type"] in ADV_A_TYPES:
        return bytes(frame["pdu"][2:8])
    return None


def board_addr(text):
    return bytes(int(x) for x in text.split(","))


def fmt(addr):
    return ":".join(f"{b:02X}" for b in addr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--board-log", required=True)
    ap.add_argument("--pcap", required=True)
    args = ap.parse_args()

    board = defaultdict(list)
    last_summary = None
    for line in open(args.board_log, errors="replace"):
        m = PKT.search(line)
        if m:
            ch, t, ln, rssi, addr = m.groups()
            board[board_addr(addr)].append(
                {"channel": int(ch), "t": int(t), "len": int(ln), "rssi": int(rssi)}
            )
            continue
        m = SUMMARY.search(line)
        if m:
            last_summary = m.groups()

    frames = [f for f in read_pcap(args.pcap) if sniffer_addr(f) is not None]
    sniffer = defaultdict(list)
    for f in frames:
        sniffer[sniffer_addr(f)].append(f)

    print(f"board AdvA packets={sum(len(v) for v in board.values())} "
          f"advertisers={len(board)}")
    if last_summary:
        t, rounds, windows, arm_err, irq = last_summary
        print(f"board last summary t={t}s rounds={rounds} windows={windows} "
              f"arm_err={arm_err} irq={irq}")
    print(f"sniffer legacy-adv={len(frames)} advertisers={len(sniffer)} "
          f"channels={dict(sorted(Counter(f['channel'] for f in frames).items()))}")
    print()

    print(f"{'AdvA':<18} {'chans':<10} {'board':>6} {'sniffer':>8} {'b/s %':>7} "
          f"{'board rssi':>10} {'sniffer rssi':>12}")
    all_addrs = sorted(set(board) | set(sniffer),
                       key=lambda a: -len(sniffer.get(a, [])))
    for a in all_addrs:
        b, s = board.get(a, []), sniffer.get(a, [])
        chans = "".join(str(c) for c in sorted({x["channel"] for x in b}))
        br = f"{statistics.median(x['rssi'] for x in b):.0f}" if b else "-"
        sr = f"{statistics.median(x['rssi'] for x in s):.0f}" if s else "-"
        ratio = f"{100 * len(b) / len(s):.3f}" if s else "-"
        print(f"{fmt(a):<18} {chans:<10} {len(b):>6} {len(s):>8} {ratio:>7} "
              f"{br:>10} {sr:>12}")

    missing = set(sniffer) - set(board)
    print()
    print(f"sniffer-only AdvAs={len(missing)} board-only AdvAs="
          f"{len(set(board) - set(sniffer))}")
    if missing:
        print("  (expected for devices whose events the 15 ms windows miss)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
