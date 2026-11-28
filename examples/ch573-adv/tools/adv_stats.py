#!/usr/bin/env python3
"""Summarise an nRF Sniffer capture of legacy advertising.

Usage:
  adv_stats.py capture.pcap [--addr C1:FF:EE:00:00:73]

Checks the three things a broadcaster must show on air:

* same AdvA **same channel** intervals (the advertising interval plus
  advDelay, 20–30 ms for the example),
* intra-event channel-switch gaps (37 → 38 → 39, target ≪ 10 ms),
* a type/AdvA/channel histogram and the AD payload of the target.

Caveats: timestamps come from the sniffer host. A dropped frame turns one
interval into an integer multiple and host scheduling jitters by tens of µs,
so read the median/percentiles, not the maximum. nRF DLT 272 keeps the
channel/RSSI in the 17 metadata bytes before the access address.
"""
import argparse
import statistics
import struct
import sys
from collections import Counter, defaultdict

AA = bytes.fromhex("d6be898e")
MAX_LEGACY_LEN = 37


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
        if i < 9 or i + 4 + 2 > len(pkt):
            continue
        pdu = pkt[i + 4:]
        if len(pdu) < 2 + pdu[1] or pdu[1] > MAX_LEGACY_LEN:
            continue
        frames.append(
            {
                "t_us": ts_s * 1_000_000 + ts_us,
                "type": pdu[0] & 0x0F,
                "txadd": bool(pdu[0] & 0x40),
                "pdu": pdu[: 2 + pdu[1]],
                "channel": pkt[i - 8],
                "rssi": -pkt[i - 12],
            }
        )
    return frames


def adv_addr(frame):
    """AdvA/InitA/ScanA for the types that carry one first."""
    if frame["type"] in (0, 1, 2, 3):
        return frame["pdu"][2:8]
    return None


def fmt_addr(a):
    # Air order, as written by `AdvState::build_adv_ind`.
    return ":".join(f"{b:02X}" for b in a)


def parse_addr(text):
    parts = [int(x, 16) for x in text.split(":")]
    if len(parts) != 6:
        raise SystemExit("expected a 6-byte address")
    return bytes(parts)


def ad_structures(pdu):
    out, i = [], 8
    while i + 1 < len(pdu):
        ln = pdu[i]
        if ln == 0 or i + 1 + ln > len(pdu):
            break
        out.append(pdu[i + 1 : i + 1 + ln])
        i += 1 + ln
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--addr", help="only this AdvA, e.g. C1:FF:EE:00:00:73")
    args = ap.parse_args()

    frames = read_pcap(args.pcap)
    wanted = parse_addr(args.addr) if args.addr else None
    adv = [f for f in frames if adv_addr(f) is not None]
    groups = defaultdict(list)
    for f in adv:
        groups[adv_addr(f)].append(f)

    print(f"records={len(frames)} legacy-adv={len(adv)} advertisers={len(groups)}")
    print("type histogram:", dict(sorted(Counter(f["type"] for f in adv).items())))
    print("channel histogram:", dict(sorted(Counter(f["channel"] for f in adv).items())))

    for addr, group in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        if wanted is not None and addr != wanted:
            continue
        if wanted is None and len(group) < 10:
            continue
        group.sort(key=lambda f: f["t_us"])
        print(f"\nAdvA {fmt_addr(addr)} txadd={group[0]['txadd']} frames={len(group)} "
              f"rssi={statistics.median(f['rssi'] for f in group):.0f} dBm")

        # Consecutive occurrences *on the same channel*, so a sniffer that
        # misses the 37/38 slots still yields an interval sample.
        same = defaultdict(list)
        last_on_channel = {}
        intra = []
        glitches = 0
        for prev, cur in zip(group, group[1:]):
            dt = cur["t_us"] - prev["t_us"]
            if dt <= 0 or dt > 5_000_000:
                glitches += 1
                continue
            if cur["channel"] != prev["channel"] and dt < 10_000:
                intra.append((prev["channel"], cur["channel"], dt))
        for f in group:
            prev = last_on_channel.get(f["channel"])
            if prev is not None and 0 < f["t_us"] - prev < 5_000_000:
                same[f["channel"]].append(f["t_us"] - prev)
            last_on_channel[f["channel"]] = f["t_us"]
        if glitches:
            print(f"  dropped {glitches} non-monotonic/gapped timestamp pairs")
        for ch, deltas in sorted(same.items()):
            # The sniffer occasionally emits the same PDU twice; a same-channel
            # delta far below the interval is a duplicate, not an event.
            deltas_ms = sorted(d / 1000 for d in deltas if d >= 5_000)
            if not deltas_ms:
                continue
            med = statistics.median(deltas_ms)
            in_band = sum(19.5 <= d <= 30.5 for d in deltas_ms)
            print(f"  ch{ch} same-channel n={len(deltas_ms)} "
                  f"median={med:.2f} ms min={deltas_ms[0]:.2f} "
                  f"20-30ms={in_band}/{len(deltas_ms)}")
        if intra:
            gaps = sorted(dt / 1000 for _, _, dt in intra)
            order = Counter((a, b) for a, b, _ in intra)
            print(f"  intra-event gaps n={len(gaps)} median={statistics.median(gaps):.2f} ms "
                  f"max={gaps[-1]:.2f} ms order={dict(order)}")
        ads = Counter(bytes(a) for f in group for a in ad_structures(f["pdu"]))
        for ad, count in ads.most_common():
            print(f"  AD[{count}] {ad.hex(' ')}")

    if wanted is not None and not any(a == wanted for a in groups):
        print(f"\n{wanted.hex()} not captured", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
