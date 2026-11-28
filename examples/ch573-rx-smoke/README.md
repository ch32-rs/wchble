# CH573 RX smoke (single-window ADV RX)

On-target RX path for the CH573 backend:

1. Apply DevInit + `DMA_DevInit`, then arm one RX window per channel
   (`ch37/38/39`, 10 ms each = 20,000 half-µs) with `rx_basic`.
2. Service the window from the **real LLE interrupt** (PFIC IRQ 21, routed
   through fast-interrupt slot 2); `rx_poll` remains as the `USE_ISR = false`
   fallback.
3. Print `len`, `rssi`, `crc` and `valid` (`crc && len <= 37`) plus the first
   48 bytes of the DMA buffer over defmt.
4. Answer each valid `Done` with one ADV and report the RX-done → TX-kick
   turnaround.

`SDIPrint` is a no-op on CH573 in ch5xx-hal, so this example uses **defmt/RTT**.

## RX buffer layout

The hardware writes into the pointer at **`DMA+0x18`** (not `+0x14`):

```
[hdr][len][payload …][pad]
[status u16][rssi i8]   @ off = (len + 5) & 0x1fc
```

There is no RSSI prefix in BLE mode. The window only DMAs when the BB payload
event (`BB+0x38` bit6) is serviced and `LLE+0x60` is reloaded; `rx_poll` /
`ble_isr` do that.

## Interrupt setup (why VTF)

`install_ble_irq()` copies what the vendor library does at init:
`PFIC_FastINT2CFG(21, …)` for LLE and `PFIC_FastINT3CFG(20, …)` for BB
(`core_riscv.h` marks slots 2/3 "occupied if use BLE"). The entry lives in
`.highcode`, so the binary **must enable ch5xx-hal's `highcode` feature** (as
this example's `Cargo.toml` does) — the fast-interrupt path does no hardware
register stacking, and the entry saves `ra`/`t0..t6`/`a0..a7` itself.

Enabling IRQ 21 through the plain vector table instead re-enters forever: the
PFIC pending bit latches while masked, and it is not clearable from software.

When the window ends (`LLE+0x60 == 0`) the LLE line stays asserted by engine
state (`LLE+0x08` bit14) until the engine stops, so `ble_isr` masks both BLE
lines on `Done`/`Timeout`; the caller unmasks before the next window.

## Hard constraint

CH573 SRAM is `@0x20003800..0x20008000`; the DMA engine keeps the low 14 bits
of a pointer, so buffers must live in `@0x20004000..0x20008000`. This example
pins them in `.dma_buffer` at `0x20004c00+`. Do **not** flash with the CH585
preflight probe (`F93D8F067E10`).

## Build / flash

```bash
cd examples/ch573-rx-smoke
cargo build --release
probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2 --scan-region ram \
  target/riscv32imac-unknown-none-elf/release/ch573-rx-smoke
```

## RX→TX turnaround (`turn=`)

With `MEASURE_RX_TX`, every `Done` that passes `valid` is answered with one
`wch573` ADV on ch37;
`turn=` is the SysTick delta from the RX-done ISR timestamp to the TX bit9
kick in µs (`0` = TX failed before the kick, `0xffff` = no kick seen).
The number includes this example's own register dump and `set_channel`, so it
is an upper bound for the driver path.

Build with `CH573_RX_NO_TX=1` for a passive receiver (no answer ADV), e.g. for
the RSSI/CRC comparison against a sniffer.

26 s run, ELF `6c29b94d…`:

| RX window at `Done` | n | µs |
| --- | --- | --- |
| ended (`LLE+0x60 == 0`) | 41 | 378–380 (p50 379) |
| still counting | 29 | 7180–7338 (p50 7203) |

The LLE only raises the TX arm event after the RX window has expired;
`engine_stop()` ahead of the TX arm does not cut the remaining count short.
T_IFS is 150 µs, so a real SCAN_RSP/connected turnaround needs an RX abort
at `Done` and a shorter arm path — this example only records the current
number.

## Acceptance (2026-11-27, probe `5CED…`)

Transmitter: `examples/ch585-rf-smoke` (ADV_NONCONN_IND, name `wch585`).
26 s ISR run: **70 `Done`, 13 of them the exact `wch585` frame**, 403 window
timeouts and 41 waits that saw no event; `isr=` delta 0–4 per window (no
storm). ELF SHA256 `6c29b94d…ad6f3ebc2`. All 70 `Done` also produced a TX
kick; macOS CoreBluetooth saw the `wch573` ADV that answers them (9
observations, RSSI −43…−47 dBm), so the RX and TX ISR paths run together.
Earlier polling run for comparison: 13/13 exact.

```
ch38 state=2 len=17 rssi=-99 crc=false valid=false timeout=false trssi=-99 tcrc=false cnt=0 isr=1 bb38=246f lle08=100000
buf [66, 17, 2, 0, 0, 238, 255, 193, 2, 1, 6, 7, 9, 119, 99, 104, 53, 56, 53, …]
```

= `42 11 02 00 00 EE FF C1 02 01 06 07 09 77 63 68 35 38 35` — the CH585 frame.

### Independent receiver (nRF Sniffer)

`tools/compare_sniffer.py` compares the log with a pcap written by
`nrfutil ble-sniffer sniff` (Nordic DLT 272), byte for byte only — the pcap
cannot attribute per-record CRC flags to a specific board reception, so CRC
status is checked by the known-answer test below. 35 s run, ELF `a2d639bc…`:
8215 records, CH573 `Done` 76 (67 with a legal length), **28 byte-exact**
across 7 AdvAs — CH585 plus 6 surrounding third-party devices (Apple
Continuity and similar). The same capture holds 60 of our own `wch573`
advertisements. Two frames differed from the sniffer by one bit and 9 `Done`
had impossible lengths (53/61/102/114/164/224…).

### CRC status (`crc=`, `valid=`)

`RxPoll::Done` carries `crc_ok`, sampled from `BB+0x38` bit5 after `RX_DONE`
is seen. This is exactly the vendor predicate, not a software threshold:
`ble_ll_chkcrc` (`ip.o`, `.highcode+0xd8`, LIB V2.20) loads `BB+0x38`,
shifts right 5, masks bit0 and returns 1 when it is set (CRC error) before
reading any payload byte. Following the vendor's
whole-word `~mask` writes on this register (the timer clear is `~0x2`), the
handler only clears the bits it consumes (`!payload`, or `!payload & ~crc`)
and never writes a stale snapshot over a bit that asserts later. Whole-register
write-zero-to-clear is not documented; the clear style matches the EVT, and
the known-answer test is the board-side check for the payload/CRC bits. Arming
a window masks the lines with the vendor `PFIC_DisableIRQ` sequence (including
`fence.i`), drops a re-pended PFIC entry and clears the software flags and
per-frame BB bits.

The CRC evidence is a controlled known-answer transmission; it bounds the gate
but does not establish per-event truth, because air errors and collisions can
still change any received frame. The CH585 with `--features crc-test` sends
`crcgood` with the advertising CRC init; `--features crc-test-bad` sends
`crcbad!` with the init flipped by one bit. ELF `dc13a3e3…`, 40 s per run,
frames selected by the local-name bytes (frames whose name was corrupted are
not counted):

| Run | name-matched `Done` | RSSI | reported `crc=true` |
| --- | --- | --- | --- |
| all `crcgood` (correct init) | 13 | −58…−99 dBm | 2 — flag is live |
| all `crcbad!` (wrong init) | 14 | −56…−99 dBm | **0** |

None of the 14 name-matched `Done` selected during the wrong-init run was
reported good, including two at −56 dBm. In the correct-init run 2 of the 13
name-matched `Done` carry `crc=true`; that is an observed ratio, not an
estimated pass rate for valid frames, because a valid frame can also fail on
air and the two runs do not share a ground truth per event. Any sensitivity
cost cannot be separated from air loss with this method. The buffer holds no
CRC bytes to re-check in software (`(len+5)&0x1fc` is `[status u16][rssi][x]`).

The stale-flag fix also removed the old "Done with an all-`0xAA` buffer"
artefacts; the post-gate runs carry data in every `Done`.

Not exercised by the evidence above; needs targeted board tests before P3a:
timer/timeout interleaving (`Done` does not abort the window, so a later
frame can overwrite the buffer the ISR is about to publish), several frames
inside one window, re-arming while an old window is still active, and
priority nesting with other PFIC lines. Accepted for now on the strength of
the call contract above (thread-context arming, masked lines on `Busy`) and
the observed runs: the correct-init KAT exercised the timeout path (166
`timeout` / 30 `Armed` alongside 13 `Done`) without a false `Done`. Name
matching is offline selection only — the driver publishes every `Done` and
this example answers on `crc_ok && len <= 37`; the wrong-init run also had
5 non-name ambient `valid=true` `Done`, so these runs do not establish the
gate for arbitrary frames.

RSSI is the DMA byte at `((len + 5) & 0x1fc) + 2`, read by vendor
`ble_ll_chkcrc` and copied straight into the scan-report `rssi` as a signed
byte by `ll_scan_rx` / `ll_scan_add_advertising_to_report`. The board pins the
register field: across 768 logged `Done` lines (pre-existing runs, 2026-11-28)
`rssi` equals `(BB+0x30 >> 15) as u8 as i8` in 759 cases; the 9 exceptions
are stale `BB+0x30` samples (the log reads it after the ISR, and it can hold a
later frame). So the field is `bits[22:15]`, sign-extended, with no calibration
subtraction — the same `>> 15` cnlohr's iSLER uses. Vendor `BLE_ReadRssi` in
`bb.o` shifts by 12 instead and does **not** reproduce the received byte; treat
it as an unrelated/legacy helper, not the packet-RSSI formula. The example logs
`Radio::rssi()` / `Radio::crc_ok()` as `trssi=` / `tcrc=`; both return the last
completed packet and track `state=2` lines exactly.

`probe-rs run` occasionally attaches RTT late and shows only the boot lines —
re-run the same ELF before suspecting a firmware hang.

### RSSI/CRC cross-check vs the nRF Sniffer

Controlled source: `examples/ch585-rf-smoke --features adv-ch37` with
`CH585_RF_SMOKE_TX_POWER=<dBm>` (CH585 stops at +4). `adv-seq` embeds a 16-bit
counter in a manufacturer AD (`05 ff ff ff seq_lo seq_hi`) and `adv-ch37`
broadcasts it on ch37 every 20 ms, so board and sniffer can be joined event by
event. Build this example with `CH573_RX_NO_TX=1` as the passive receiver:

```bash
cd examples/ch585-rf-smoke
CH585_RF_SMOKE_TX_POWER=0 cargo build --release --features adv-ch37
probe-rs download --probe 1a86:8010:F93D8F067E10 --chip CH585 --protocol jtag \
  --verify --start target/riscv32imc-unknown-none-elf/release/ch585-rf-smoke

cd ../ch573-rx-smoke
CH573_RX_NO_TX=1 cargo build --release
probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2 --scan-region ram \
  target/riscv32imac-unknown-none-elf/release/ch573-rx-smoke > rtt.log 2>&1 &
nrfutil ble-sniffer sniff --port /dev/cu.usbmodem21201 --only-advertising \
  --output-pcap-file cap.pcap
python3 tools/compare_rssi_crc.py rtt.log cap.pcap --seq-off 23 \
  --adv-a C1:FF:EE:00:00:02
```

The counter sits at PDU offset 23; the CH585 random AdvA is
`C1:FF:EE:00:00:02`. The sniffer's per-record CRC-OK flag is bit0 of the
metadata byte 9 before the AA (byte 8 is the channel, byte 10 the RSSI
magnitude); this was cross-checked against `crcgood`/`crcbad!` captures.

### CH573 ↔ CH585 interop (both directions)

Run `ch585-rf-smoke` (probe `F93D…`) and this example (probe `5CED…`) at the
same time: the CH585 advertises `wch585` on 37/38/39 and listens on ch37; this
example receives and answers each valid `Done` with one `wch573` frame.
Pre-CRC-gate 90 s run, 2026-11-28:

| Direction | Result |
| --- | --- |
| CH585 → CH573 | 26 frames with the CH585 AdvA, **25 byte-exact** `wch585`; 1 differs in one bit |
| CH573 → CH585 | CH585 `PEER` tally: **30/30 byte-exact** `wch573`, 0 CRC failures |

Post-gate regression, 40 s, ELF `dc13a3e3…` / `172f5567…` (`--features peer-rx`):
33 `Done`, **7 byte-exact** `wch585`; CH585 `PEER` **2/2 byte-exact**
`wch573`, 0 CRC failures. `compare_peer.py` reports `PASS? True`.

The CH585 side counts matching frames in a static `PEER` record (read it with
`probe-rs read --chip CH585 b32 <PEER> 8`) because its RAM log wraps in
seconds. Cross-check both sides with
`tools/compare_peer.py --ch573-log <rtt.log> --ch585-peer <peer-dump>` (or
`--ch585-log <ram.log>` when the matching hit is still in the log); details in
`local-docs/results/ch573-ch585-bidir-20261128.md`.

The empty `Done` lines and the impossible lengths are the stale-flag and
missing-gate defects this stage fixes; the post-gate run has no empty `Done`.
The pre-gate one-bit error is not attributed to them — the remaining mismatch
traffic is CRC-gated or ambient, and frame association under dense traffic is
still open (see the interleaving list above).
