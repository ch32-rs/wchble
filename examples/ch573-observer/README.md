# CH573 passive Observer (P3a)

Finite, receive-only legacy-advertising observer for the CH573 backend. It
hops 37 → 38 → 39 with one RX window per channel, parses each captured PDU
with `wchble::ll::scan`, and logs counters plus every captured frame over
defmt/RTT. The image contains **no TX call**: no `SCAN_REQ`, no connection
request, no data PDU. (`init()` still runs the calibration path, including
TXCtune, which is not an advertisement.)

This is a bring-up example, not a conformance claim. It does not establish
continuous all-channel coverage, loss rate, air IFS, or calibrated RSSI:
between windows the engine is shut down, the channel is switched, and the
buffer is parsed, so frames in those gaps are missed.

## Behaviour

- Finite run: **30 s** default; build with `CH573_OBS_RUN_S=<seconds>`. The
  image stops the engine, prints a final summary and the advertiser table,
  then parks.
- Window: **15 ms** per channel (`WINDOW_HALF_US = 30_000`), the same bound as
  the CH585 observer — it keeps the LLE `WINDOW` count below bit 15, whose
  width above `0x7FFF` is not established.
- Completion comes from the real LLE/BB interrupt (`install_ble_irq`, PFIC
  slots 2/3); `rx_isr_take()` is polled, with a host-side timeout that only
  guards a lost event (`stale=`).
- After every result the engine is shut down (`radio.shut()`) before the DMA
  buffer is read or reused, with a 5 ms settle.
- Telemetry is RTT only; there is no `STATS` RAM record. Two liveness words
  exist for manual diagnosis — `OBS_ALIVE` (rounds completed) and
  `BOOT_STAGE` (last boot milestone, 1..7) — but a `probe-rs read` halts the
  core, so use them only to tell a stuck core from a stalled RTT session,
  never during an acceptance run. Find their addresses with
  `nm <elf> | grep -E 'OBS_ALIVE|BOOT_STAGE'`.

## Accounting

| Field | Meaning |
| --- | --- |
| `win` | windows armed |
| `arm_err` / `stale` | `rx_basic`/`set_channel` failed / host wait expired without an ISR result |
| `done` | `RxPoll::Done` results |
| `crc_err` | `Done` with `BB+0x38` bit5 clear — the vendor `ble_ll_chkcrc` predicate |
| `mismatch` | buffer no longer matches the published length (a second frame landed in the same window after `Done`) |
| `bad_len` | CRC-ok, length > 37 or buffer mismatch not caught by the byte check |
| `named` / `mfr` | parsable PDUs with a local name / manufacturer data |
| `pdu ind/dir/nonconn/scan_req/scan_rsp/conn/scan_ind/ext/rfuv` | PDU types received |
| `rssi_hist` | 10 dB buckets from −120 dBm; the driver's `RxPoll::Done.rssi` |
| `adv` rows | per-AdvA first-seen name, capture count, last RSSI (bounded 24 rows) |

RSSI is the driver's `RxPoll::Done.rssi` (`BB+0x30 >> 15` sign-extended). A
paired verification matched it to the vendor `ll_scan_rx` byte in 82/82
sampled `Done`, so the field is read correctly; the absolute values are not
calibrated against a reference receiver.

## Known limits

- One published packet per window: `Done` does not abort the window, so a
  later frame inside the same 15 ms could overwrite the bytes the ISR
  published. `mismatch` counts the cases the header/length check catches.
- Duplicate detections are possible at window boundaries, and the log has no
  receive timestamps yet; comparisons with a sniffer are per-device counts,
  not per-frame identity.
- **Receive deficit vs a simultaneous sniffer** (2026-11-28, see below): the
  board hears ~1% of what an nRF Sniffer logs, and its RSSI reads 20–45 dB
  below the sniffer's median for the same advertisers. Per channel the board
  listens 15 ms of every ~64 ms round (~24%; ~71% of wall time summed over the
  three channels), so it should capture far more than it does. Window length is
  not the cause (`win_dt_us` shows the armed window really is ~15 ms and
  `rx_basic` returns in microseconds), and the RSSI field is read the way the
  vendor `ll_scan_rx` reads it, so the level difference itself is the open
  question (antenna/placement vs RX gain). Tracked with the CH573 RSSI/CRC
  verification, not fixed here.
- `early=` and `to_dt_us` cover Timeout results only; `late=` (> 30 ms
  arm→result) covers every result path. Early windows are ~15–20%.
- A **stalled `probe-rs run` session** is a probe failure, not a firmware hang.
  In some sessions the flash completes (`Finished in …`) yet no RTT output
  appears at all — not even `boot`. The same ELF then boots and finishes its
  full run on a later attempt: in this session's batches one image both
  succeeded (2/3, 2/4, and 20/20 for the pre-instrumentation build) and stayed
  silent (0/20 in a batch whose sessions were torn down with SIGKILL). An
  earlier run also stopped right after `sysclk`; that half-log was not
  reproduced in the later batches and is kept as an observation only.
  `disable_debug_module: could not clear sw-breakpoint state:
  DtmOperationFailed` is common around a stalled session, but it also appears
  when a session ends normally, so it is not a signature by itself. An earlier
  revision of this file called the stall an "ISR/arming race"; that was wrong.
  Follow-up debug sessions in that state report a bogus PC, `mcause=2` at a
  legal instruction, and scrambled CodeFlash read-back — the CH5xx flash
  algorithm documents that a halted debug read of CodeFlash returns a
  scrambled placeholder — so none of that is firmware evidence. Workaround:
  re-run the same ELF; if repeated re-runs stay silent, `probe-rs reset` or
  re-plug the WCH-LinkE. Firmware side was hardened anyway: `ble_clock_on`
  and `apply_tx_power` now run their SAFE_ACCESS windows with `mstatus.MIE`
  masked, matching `ch585`.

## Acceptance (2026-11-28, probe `5CED…`)

600 s run, ELF `03c000a4…67c`, nRF Sniffer capture spanning the run
(`nrfutil ble-sniffer sniff --only-advertising`, port `/dev/cu.usbmodem21201`):

| Counter | Value |
| --- | --- |
| rounds / windows | 9844 / 29,533 |
| `done` / `crc_ok` / `crc_err` | 683 / 367 / 316 |
| `stale` / `arm_err` | 822 / 0 |
| parsed per channel 37/38/39 | 213 / 59 / 95 |
| `adv_seen` / `named` / `mfr` | 20 / 176 / 267 |
| `bad_len` / `mismatch` | 0 / 0 |
| PDU types | ADV_IND 101, ADV_NONCONN_IND 197, SCAN_REQ 59, SCAN_RSP 10 |
| `win_dt_us` min/avg/max | 1079 / 14,526 / 71,829 |
| early / late windows | 5553 / 277 |
| RSSI histogram | 314 in −100..−90, 27 in −90..−80, 20 in −80..−70, 6 in −70..−60 dBm |

The sniffer logged 77,119 AdvA-bearing records (~128/s, 2684 AdvAs) in the
same window; per-device board/sniffer ratios were 0.07–1.2%, and board RSSI
was 20–45 dB below the sniffer median — the deficit listed above. The
channel 37 skew is a real source, not a bug: the CH585 board next to this one
was left advertising in adv-ch37-only mode (AdvA `02:00:00:EE:FF:C1`, name
`wch585`). The sniffer logged 16,651 of its frames on ch37; the observer
caught 149 (0.9%), at −96 dBm against the sniffer's −58 — the cleanest
deficit datum, because the channel and the transmitter are known.

`named=` and the `adv` table still track the ambient population, so the
observer is usable for presence/counting at short range, but its counts are
not a loss-rate or rate measurement.

Post-fix check (same day, ELF `accb4e75…51`, after the SAFE_ACCESS masking
change and the guarded panic handler): `rf init ok`, 470 rounds / 1410 windows
in 30 s, `arm_err=0`, counters in line with the numbers above.

`tools/compare_observer.py --board-log rtt.log --pcap capture.pcap` prints the
per-AdvA table (board vs sniffer counts, channels, RSSI medians). Start the
sniffer first and stop it after the board parks so the capture spans the run.


## Build / flash

```bash
cd examples/ch573-observer
cargo build --release
probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2 --scan-region ram \
  target/riscv32imac-unknown-none-elf/release/ch573-observer
```

Do **not** flash with the CH585 preflight probe (`F93D8F067E10`).

SRAM is `@0x20003800..0x20008000` and the DMA engine keeps only the low 14
bits of a pointer, so the buffers live in `.dma_buffer` at `0x20004c00+`
(`build.rs` asserts the `0x2000_4000` floor and the `0x400` reservation).

`probe-rs run` occasionally attaches RTT late and shows only the boot lines.
Before suspecting a firmware stall, check that `obs t=` lines are advancing.
