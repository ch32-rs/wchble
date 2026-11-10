# CH585 O2 active scanner

Finite legacy active scanner. It listens on advertising channels 37/38/39,
answers scannable advertisements (`ADV_IND`, `ADV_SCAN_IND`) with a `SCAN_REQ`,
and records the `SCAN_RSP` received in the immediately following window. It is
the O2 deliverable in
[`local-docs/ch585-ble-role-roadmap.md`](../../local-docs/ch585-ble-role-roadmap.md)
and builds on the O1 passive Observer.

This is a bring-up example, not a BLE conformance claim. It does not prove air
IFS, all-channel continuous coverage, loss rate, or calibrated RSSI. The
114 µs constant is a **software offset** from the polled `RX_DONE` to the
`tx_basic` deadline; it is not the 150 µs air `T_IFS` and the actual air start
is later than that software deadline. The value was calibrated against the
Android source on 2026-11-10 (112–118 µs accepted about a third of requests,
120 µs was mostly ignored).

## Behaviour

- Default finite run: **30 s**. The image then stops the RF engine, records
  final status, and parks.
- Channel plan: 37 → 38 → 39, 15 ms RX window per channel. A 15 ms window keeps
  the LLE `WINDOW` count below bit 15; the field width above `0x7FFF` is not
  established for CH585.
- One advertisement per arm. On address capture (`CLKCAP`) the window reloads
  to a full-PDU budget; after `RX_DONE` the window ends.
- After every window the radio is explicitly stopped (`shut`, `CMD & 3 == 0`
  within 100 µs), fenced, and only then is the DMA buffer read or reused. A
  stop that is not acknowledged parks with stage `0xee`; DMA stays quarantined.
- Scanner address: static random `C1:FF:EE:00:00:31` (TxAdd=1). The `SCAN_REQ`
  is built from the received advertisement: ScanA = our address, AdvA = the
  advertiser's address, RxAdd = the advertisement's AdvA address type.
- TX path per candidate:
  1. `stop()` + fence, parse the advertisement, build `SCAN_REQ`;
  2. `deadline = rx_done + 114 µs`, `tx_basic(..., Some(deadline))` with a
     4-byte-aligned DMA buffer;
  3. after `TX_DONE`, clear BB `IRQSTAT` and arm a separate RX buffer for 2 ms
     on the same channel; `rx_basic` force-stops the still-engaged TX command;
  4. after the response window, `stop()` + fence, then read the response DMA.
- A response is accepted only when CRC is valid, the PDU type is `SCAN_RSP`,
  AdvA equals the requested advertiser, and (in `target-src` builds) the AD
  data carries the response marker. Type, AdvA and marker rejects are counted
  separately from CRC errors.
- `PDU_SCAN_RSP_SEEN` also counts responses observed while scanning ordinary
  advertising windows; those are not accepted unless they follow our request.

### RAM-resident fast path

The polled `RX_DONE` leaves only the transaction budget before the request must
be on air. On CH585, running the same classification from flash took ~170 µs
after `RX_DONE` (parse ~4 µs, marker/type and counter work ~84 µs, ring write
~63 µs). The example therefore runs `classify_adv` from the RAM-copied
`.highcode` section (requires the `qingke-rt` `highcode` feature) and defers
all STATS and ring writes until after `TX_DONE`. Entry-to-deadline margin was
23 µs in the validated runs; changing this arrangement invalidates the 114 µs
calibration.

## Controlled source and test selector

`--features target-src` builds a matching selector for one known source:

- advertisement manufacturer data `0xFFFF` + `O2ADV` + `0x01`;
- scan response manufacturer data `0xFFFF` + `O2RSP` + `0x01`.

The default build answers **any** scannable advertisement and does not require
the response marker. The runner only accepts the `target-src` image.

`tools/android-advertiser/` is the controlled source: a small Android app that
advertises with `AdvertisingSetParameters.Builder` (`setLegacyMode(true)`,
`setConnectable(false)`, `setPrimaryPhy(LE_1M)`) for a bounded time, with JSON
events on logcat tag `WCHBLE`. Modes (`--es mode`):

| Mode | PDU | ADV data | Scan response |
| --- | --- | --- | --- |
| `scannable` | `ADV_SCAN_IND` | `O2ADV` marker | `O2RSP` marker |
| `non-scannable` | `ADV_NONCONN_IND` | `O2ADV` marker | none |
| `wrong-marker` | `ADV_SCAN_IND` | `O2ADX` marker | `O2RSP` marker |

Build and install:

```sh
tools/android-advertiser/build.sh
adb install -g -r tools/android-advertiser/build/wchble-o2adv.apk
```

The debug keystore and APK live under `build/` and are not committed.

## Observation contract

`STATS: [u32; 64]` (see `src/main.rs` for authoritative indices):

| Index | Meaning |
| --- | --- |
| 0, 1 | magic `0x4f323538`, version 1 |
| 2 | stage: 1 init, 2 running, 3 finished, 0xe1 init fail, 0xee stop fail |
| 3 | run duration in µs |
| 4, 5 | window half-µs (30000), embedded run seconds |
| 6, 7 | armed windows, arm/channel errors |
| 8, 9 | completions, timeouts |
| 10, 11 | CRC-ok completions, CRC errors |
| 12, 13 | CRC-ok but unparsable/long PDU, parsed PDUs |
| 14..21 | ADV_IND, ADV_SCAN_IND, ADV_NONCONN_IND, ADV_DIRECT_IND, SCAN_RSP seen, SCAN_REQ seen, CONNECT_IND seen, other/extended |
| 22..25 | `O2ADV` advertisements, of which scannable, of which non-connectable; `O2ADX` wrong-marker advertisements |
| 26..29 | SCAN_REQ attempts, sent, late, build/transmit errors |
| 30, 31 | response windows armed, response arm errors |
| 32, 33 | response completions, response timeouts |
| 34, 35 | response CRC ok, response CRC err |
| 36..39 | response accepted, reject type, reject AdvA, reject marker |
| 40 | stop failures |
| 41..43 | completions per channel 37/38/39 |
| 44, 45 | last advertisement length, last response length |
| 46, 47 | last advertisement RSSI, last response RSSI (raw, uncalibrated) |
| 48, 49 | last/max `tx_basic` entry − `RX_DONE` |
| 50, 51 | last/max `tx_basic` return − `RX_DONE` |
| 52, 53 | last/min software deadline margin |
| 54, 55 | last/max TX_DONE → response-arm entry |
| 56 | last response latency (response `RX_DONE` − TX_DONE) |
| 57, 58 | final `CMD`, final `MODE` |
| 59, 60 | clock Hz, target-src selector present |
| 61 | `SCAN_REQ` software offset (114) |
| 62, 63 | advertisement marker channel mask, accepted response channel mask |

Invariants (checked by the runner and `tools/test_run.py`):

`6 == 8 + 9`; `8 == 10 + 11`; `10 == 12 + 13`; `13 == 14 + … + 21`;
`22 == 23 + 24`; `26 == 27 + 28 + 29`; `26 == 23` in `target-src` builds;
`27 == 30 + 31`; `30 == 32 + 33`; `32 == 34 + 35`; `34 == 36 + 37 + 38 + 39`;
`41 + 42 + 43 == 8`; `stage == 3`; `final CMD & 3 == 0`;
`final MODE == 0x30000`; `stop_failures == 0`.

`ADV_RING` holds the last 4 answered advertisements and `RSP_RING` the last 4
accepted responses, in 13-word rows: timestamp, metadata (channel, length, CRC,
PDU type, AD presence, valid bit), raw RSSI, then 40 raw bytes of
`[header, length, payload..]`.

`RUN_SECONDS_SYM`, `TARGET_SRC`, `SCAN_REQ_OFFSET` and `SCAN_ADDR_SYM` are
file-backed ELF symbols; the runner rejects a mismatched image before touching
the probe.

## Build and run

Run commands from this directory so the target/linker configuration applies.

```sh
cargo build --release --features target-src
(cd ../ch585-rf-smoke && cargo build --release)
python3 tools/test_run.py
python3 tools/run.py --out /absolute/new/evidence-directory
```

`tools/run.py`:

1. archives and hashes the ELF, checks the exported symbols, embedded
   `RUN_SECONDS` / `TARGET_SRC` / 114 µs offset / scan address, and the markers;
2. builds the APK if missing, installs it, grants the advertising permissions;
3. for each phase: starts (or force-stops) the Android source and waits for its
   `advertising` event, then flashes with the single-session
   `tools/ch585-preflight` helper (fixed probe `1a86:8010:F93D8F067E10`), waits
   `RUN_SECONDS + 3`, stops the app, and only then reads `STATS`/rings with
   `probe-rs`;
4. phases: two positive `scannable` rounds, `negative-nonconn`,
   `negative-marker`, `negative-nosource` (ambient traffic must prove the
   receiver was alive);
5. restores `ch585-rf-smoke` and requires exact-name macOS discovery of
   `wch585`.

No probe access happens during any finite run. A failed gate is preserved in
`result.json`; do not retry it away. `--skip-negative-*` and
`--positive-rounds` exist for bring-up only.

## Validation status (2026-11-10)

One full round on the fixed CH585 with a CPH2411 (Android 15) source, ELF
SHA-256 `49d186f8974d76686c6299fa96115290814ae92863d3ac64ef3b696e482d21ec`:

- positive 1: 293 marked scannable advertisements, 293 `SCAN_REQ` sent, 0 late,
  116 response-window completions, 86 accepted responses, 0 rejected by AdvA
  or marker, channels 37/38/39 covered in both directions;
- positive 2: 299 sent, 0 late, 122 completions, 88 accepted;
- negative `non-scannable`: 525 `ADV_NONCONN_IND` with the same marker, 0 scan
  requests;
- negative `wrong-marker`: 489 scannable advertisements with `O2ADX`, 0
  expected marker and 0 scan requests;
- negative no source: 0 markers/requests while 1935 CRC-valid ambient packets
  still proved receiver liveness;
- every phase ended at stage 3, `CMD=0`, `MODE=0x30000`, 0 stop failures;
  `ch585-rf-smoke` was restored with exact-name macOS discovery.

The last captured response latency was 356 µs from our `TX_DONE` to the
response `RX_DONE`; the 26-byte `SCAN_RSP` on air plus 150 µs `T_IFS` explains
it. That is a consistency observation, not a calibrated air-IFS measurement.
Evidence and the offset-calibration runs remain local under
`local-docs/research/ch585-active-scanner-results.md`.

`tools/scan_markers.swift` is a Mac-side sanity scanner: it shows that the
Android source exposes both the advertisement and scan-response markers to
CoreBluetooth, independent of this board.

## Capability boundaries

- Legacy 1M advertising-channel PDUs only; no extended advertising, no
  periodic advertising, no connection.
- One advertisement per RX window; no scan-request retry or scan state machine
  beyond the fixed rotation.
- The 114 µs constant is a software deadline offset calibrated against one
  Android source; it is not an air-IFS measurement and may differ for other
  controllers.
- Not a statement about receiver sensitivity, coverage, or missing-packet rate.
- RSSI is the raw BB field and is not reported in dBm.
