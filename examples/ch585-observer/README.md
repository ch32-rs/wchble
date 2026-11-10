# CH585 O1 passive Observer

Finite, receive-only Observer for legacy BLE advertising channels. It listens
on 37/38/39 with one RX window per channel, records counters and bounded raw
samples, and **never transmits**: no `SCAN_REQ`, no connection request, no data
PDU. It is the O1 deliverable in
[`local-docs/ch585-ble-role-roadmap.md`](../../local-docs/ch585-ble-role-roadmap.md)
and the natural basis for O2 (active scan).

This is a bring-up example, not a BLE conformance claim. It does not prove
all-channel continuous coverage, loss rate, air IFS, or calibrated RSSI.
Between windows the radio is shut down, the channel is switched, and the DMA
buffer is parsed, so packets in those gaps are missed.

## Behaviour

- Default finite run: **30 s**. The image then stops the RF engine, records
  final status, and parks.
- Channel plan: 37 → 38 → 39, 15 ms RX window per channel. A 15 ms window keeps
  the LLE `WINDOW` count below bit 15; the field width above `0x7FFF` is not
  established for CH585.
- One packet per arm. On address capture (`CLKCAP`) the window reloads to a
  full-PDU budget; after `RX_DONE` the window ends.
- After every window the radio is explicitly stopped (`shut`, `CMD & 3 == 0`
  within 100 µs), fenced, and only then is the DMA buffer read or reused. A
  stop that is not acknowledged parks with stage `0xee`; the DMA buffer stays
  quarantined. This is the same experimental policy as P2/P3, not a general
  `Radio::rx_basic` DMA-lifetime guarantee.
- `PDU_SCAN_REQ_SEEN` / `PDU_CONNECT_IND_SEEN` count **received** packets from
  other devices; this image has no TX call at all.

## Test-only controlled-source selector

`--features target-src` builds a matching selector for one known source:

- local name `wch585-obs-src`, or
- manufacturer data `0xFFFF` + `O1` + version `0x0001` (`ffff4f310001`).

A match increments a monotonic counter and fills a 4-row ring; ordinary
ambient advertisements never enter that ring. The default build has no target
selector and no `MATCH` ring.

`tools/advertise.swift` is the matching Mac source: a `CBPeripheralManager`
that advertises that name and manufacturer data for a bounded time. It is a
test instrument; CoreBluetooth does not expose the advertising interval or
guarantee which AD structures land in `ADV_IND`.

Observed on macOS 15 with the nRF Sniffer: the Mac `ADV_IND` carries Flags,
Tx Power Level and the complete local name, but **not** the manufacturer data
(`CBAdvertisementDataManufacturerDataKey` is ignored for advertising on macOS).
The exact local name is therefore the acceptance identifier; manufacturer data
is recorded when a source supplies it but is not a gate. macOS also does not
deliver its own advertisements to a local scanner, so the source-side check is
the sniffer capture, not `scan_ch585.swift`.

## Observation contract

`STATS: [u32; 48]` (see `src/main.rs` for the authoritative indices):

| Index | Meaning |
| --- | --- |
| 0, 1 | magic `0x4f313538`, version 1 |
| 2 | stage: 1 init, 2 running, 3 finished, 0xe1 init fail, 0xee stop fail |
| 3 | run duration in µs |
| 4, 5 | window half-µs (30000), embedded run seconds |
| 6 | armed windows |
| 7 | arm / channel errors |
| 8, 9 | completions, window timeouts |
| 10, 11 | address captures, captured-but-not-complete |
| 12, 13 | CRC-ok completions, CRC errors |
| 14 | CRC-ok but unparsable/long PDU |
| 15, 16 | acknowledged stops, stop failures |
| 17..19 | completions per channel 37/38/39 |
| 20..22 | CRC-ok per channel 37/38/39 |
| 23..31 | PDU counts: ADV_IND, ADV_DIRECT_IND, ADV_NONCONN_IND, SCAN_RSP, ADV_SCAN_IND, ADV_EXT_IND, SCAN_REQ seen, CONNECT_IND seen, other |
| 32 | advertisements carrying a local name |
| 33, 36 | controlled-source matches, match-ring writes |
| 34, 35 | sample writes, sample ring overflow |
| 37..39 | last channel, last payload length, last raw RSSI |
| 40..43 | last LLE/BB status, final `CMD`, final `MODE` |
| 44, 45 | clock Hz, target-src selector present |

`SAMPLE` holds the last 32 CRC-valid PDUs in 13-word rows: timestamp,
metadata word (channel, length, CRC, PDU type, AD presence, valid bit), raw
RSSI, then 40 raw bytes of `[header, length, payload..]`. `MATCH` uses the same
row layout for up to 4 controlled-source matches.

`RUN_SECONDS_SYM` and `TARGET_SRC` are file-backed ELF symbols so the runner
can reject a mismatched image before touching the probe.

RSSI is the raw `BB.RSSICFO` field. It is **uncalibrated** and is not reported
in dBm.

## Build and run

Run commands from this directory so the target/linker configuration applies.

```sh
cargo build --release --features target-src
(cd ../ch585-rf-smoke && cargo build --release)
python3 tools/test_run.py
python3 tools/run.py --out /absolute/new/evidence-directory
```

`tools/run.py`:

1. archives and hashes the ELF, checks symbols and the embedded `RUN_SECONDS`
   / `TARGET_SRC` values, and compiles `advertise.swift`;
2. starts the Mac advertiser and waits for its `advertising` event;
3. flashes with the single-session `tools/ch585-preflight` helper (fixed probe
   `1a86:8010:F93D8F067E10`), waits `RUN_SECONDS + 3`, and only then reads
   `STATS`/`SAMPLE`/`MATCH` with `probe-rs`;
4. stops the advertiser, waits 5 s, and repeats the same image with no source
   (the negative control must show zero matches);
5. restores `ch585-rf-smoke` and requires exact-name macOS discovery of
   `wch585`.

`--no-advertiser` runs only the negative control. No probe access happens
during either finite run. A failed positive gate is preserved in
`result.json`; do not retry it away.

## Validation status (2026-11-10)

Two positive rounds and two negative rounds with the same `target-src` image
(SHA-256 `326f0dc82f72934f6214aa13d9336732f98481be7024d439fba526d65ccb8eec`)
passed on the fixed CH585:

- positive: 332 and 327 controlled-source matches over 30 s; CRC-valid
  advertisements 2180 and 2404; 0 arm errors and 0 unacknowledged stops; all
  three channels represented in the match ring;
- negative (same image, no controlled source): 0 matches while still receiving
  2080 and 1906 CRC-valid ambient advertisements;
- both rounds finished at stage 3 with `CMD=0` and `MODE=0x30000`, and restored
  `ch585-rf-smoke` with exact-name macOS discovery.

The raw matched PDU equals the sniffer-captured Mac advertisement
(`00 1c b5 45 b0 f3 89 c8 02 01 1a 02 0a 0c 0f 09 "wch585-obs-src"`). These
results do not cover continuous all-channel listening, loss rate, air IFS, or
calibrated RSSI, and they do not change any P2-P5 acceptance conclusion.
Research notes and raw records remain local under
`local-docs/research/ch585-observer-results.md`.

## Capability boundaries

- Legacy 1M advertising-channel PDUs only; no extended advertising, no scan
  response solicitation, no scanning state machine beyond the fixed rotation.
- No `SCAN_REQ`, no `CONNECT_IND`, no GATT, no encryption.
- Not a statement about receiver sensitivity, coverage, or missing-packet rate.
- CRC-valid/timed-out ambient traffic is expected input, not controlled
  injection evidence.
