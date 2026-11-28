#!/usr/bin/env python3
"""Cross-check a CH573 <-> CH585 RX run in both directions.

Inputs are the plain-text logs of the two boards:
  * `ch573-rx-smoke` over RTT (`ch38 state=2 len=17 ...` + `buf [66, 17, ...]`)
  * `ch585-rf-smoke` RAM log (`rx loop hit len=17 crc=true` + `rx buf 42 11 ...`),
    or its `PEER` tally dump, which survives the RAM log wrapping.

Each side's own advertisement is built into both firmwares, so the opposite
side must see it byte-for-byte.
"""

import argparse
import re
import sys

WCH573 = bytes.fromhex("4211c1ffee0000730201060709776368353733")
WCH585 = bytes.fromhex("42110200 00eeffc1 020106 0709 776368353835".replace(" ", ""))

BUF_RE = re.compile(r"buf \[([0-9, ]*)\]")
HIT_RE = re.compile(r"len=(\d+)(?: rssi=-?\d+)?")
HEX_RE = re.compile(r"rx buf ((?:[0-9a-f]{2} )*[0-9a-f]{2})")
CH573_LINE_RE = re.compile(r"ch\d+ state=(\d+) len=(\d+)")


def read_ch573(path):
    """Yield (len, frame) for every state=2 line plus the buf line after it."""
    frames = []
    pending = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = CH573_LINE_RE.search(line)
            if m:
                state, length = int(m.group(1)), int(m.group(2))
                pending = (state, length)
                continue
            m = BUF_RE.search(line)
            if m and pending:
                state, length = pending
                if state == 2:
                    raw = bytes(int(b) for b in m.group(1).split(",") if b.strip())
                    frames.append((length, raw[: 2 + length]))
                pending = None
    return frames


def read_ch585(path):
    """Yield (len, crc_ok, frame) for every `rx loop hit`/`rx listen hit`."""
    frames = []
    pending = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            m = HIT_RE.search(line)
            if ("rx loop hit" in line or "rx listen hit" in line) and m:
                pending = (int(m.group(1)), "crc=true" in line)
                continue
            m = HEX_RE.search(line)
            if m and pending:
                length, crc_ok = pending
                raw = bytes.fromhex(m.group(1))
                frames.append((length, crc_ok, raw[: 2 + length]))
                pending = None
    return frames


def read_peer(path):
    """Parse a `probe-rs read --chip CH585 b32 <PEER> 8` dump.

    Layout: u32 byte-exact count, len, crc, crc failures, then the frame.
    """
    words = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.search(r": ((?:[0-9a-f]{8} ?)+)", line)
            if m:
                words += [int(w, 16) for w in m.group(1).split()]
    raw = b"".join(w.to_bytes(4, "little") for w in words)
    if len(raw) < 8:
        sys.exit(f"no PEER words in {path}")
    length = raw[4]
    return int.from_bytes(raw[:4], "little"), raw[5], raw[6], raw[8 : 8 + 2 + length]


def adva(frame):
    return frame[2:8].hex() if len(frame) >= 8 else "?"


def report(name, frames, expected):
    exact = [f for f in frames if f[-1] == expected]
    print(f"{name}: frames={len(frames)} exact={len(exact)}/{len(frames)}")
    advas = sorted({adva(f[-1]) for f in exact})
    print(f"  exact AdvAs: {', '.join(advas) if advas else '-'}")
    bad_crc = sum(1 for f in frames if len(f) == 3 and not f[1])
    if len(frames) and len(frames[0]) == 3:
        print(f"  crc=false frames: {bad_crc}")
    for f in frames:
        if f[-1] == expected:
            continue
        print(f"  other len={f[0]} adva={adva(f[-1])} {f[-1].hex()}")
    return len(exact)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ch573-log", required=True, help="RTT log from ch573-rx-smoke")
    ap.add_argument("--ch585-log", help="RAM log from ch585-rf-smoke")
    ap.add_argument("--ch585-peer", help="probe-rs dump of the PEER tally")
    args = ap.parse_args()
    if not args.ch585_log and not args.ch585_peer:
        ap.error("one of --ch585-log / --ch585-peer is required")

    ch573 = read_ch573(args.ch573_log)
    n_a = report("ch573 rx (expects wch585)", ch573, WCH585)

    if args.ch585_peer:
        count, crc, crc_fail, frame = read_peer(args.ch585_peer)
        print(
            f"ch585 peer: exact={count} crc_last={bool(crc)} crc_fail={crc_fail}"
            f" frame={frame.hex()}"
        )
        ok_b = count > 0 and crc_fail == 0 and frame == WCH573
    else:
        ch585 = read_ch585(args.ch585_log)
        ok_b = report("ch585 rx (expects wch573)", ch585, WCH573) > 0

    ok = n_a > 0 and ok_b
    print(f"PASS? {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
