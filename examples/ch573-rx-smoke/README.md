# CH573 RX smoke (single-window ADV RX)

On-target RX path for the CH573 backend:

1. Apply DevInit + `DMA_DevInit`, then arm one RX window per channel
   (`ch37/38/39`, 20 ms each) with `rx_basic`.
2. Service the window from the **real LLE interrupt** (PFIC IRQ 21, routed
   through fast-interrupt slot 2); `rx_poll` remains as the `USE_ISR = false`
   fallback.
3. Print `len`, `rssi` and the first 48 bytes of the DMA buffer over defmt.
4. Answer each `Done` with one ADV and report the RX-done → TX-kick
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

With `MEASURE_RX_TX`, every `Done` is answered with one `wch573` ADV on ch37;
`turn=` is the SysTick delta from the RX-done ISR timestamp to the TX bit9
kick in µs (`0` = TX failed before the kick, `0xffff` = no kick seen).
The number includes this example's own register dump and `set_channel`, so it
is an upper bound for the driver path.

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
ch38 state=2 len=17 rssi=-99 cnt=0 isr=1 bb38=246f lle08=100000
buf [66, 17, 2, 0, 0, 238, 255, 193, 2, 1, 6, 7, 9, 119, 99, 104, 53, 56, 53, …]
```

= `42 11 02 00 00 EE FF C1 02 01 06 07 09 77 63 68 35 38 35` — the CH585 frame.

### Independent receiver (nRF Sniffer)

`tools/compare_sniffer.py` compares the log with a pcap written by
`nrfutil ble-sniffer sniff` (Nordic DLT 272). 35 s run, ELF `a2d639bc…`:
8215 records, CH573 `Done` 76 (67 with a legal length), **28 byte-exact**
across 7 AdvAs — CH585 plus 6 surrounding third-party devices (Apple
Continuity and similar). The same capture holds 60 of our own `wch573`
advertisements. Two frames differed from the sniffer by one bit and 9 `Done`
had impossible lengths (53/61/102/114/164/224…).

Not yet:

- **CRC status** — `BB+0x38` bit5 reads set even with no PDU in the polling
  context, so `RxPoll::Done` omits it. The sniffer run above shows the cost:
  bad frames (one-bit errors, garbage lengths) are reported as received.
- RSSI is read from the status word (`(len+5)&0x1fc + 2`); cnlohr's iSLER
  reads `BB+0x30 >> 15` for CH571/573 — worth cross-checking later.

`probe-rs run` occasionally attaches RTT late and shows only the boot lines —
re-run the same ELF before suspecting a firmware hang.

### CH573 ↔ CH585 interop (both directions)

Run `ch585-rf-smoke` (probe `F93D…`) and this example (probe `5CED…`) at the
same time: the CH585 advertises `wch585` on 37/38/39 and listens on ch37; this
example receives and answers each `Done` with one `wch573` frame. 90 s run,
2026-11-28:

| Direction | Result |
| --- | --- |
| CH585 → CH573 | 26 frames with the CH585 AdvA, **25 byte-exact** `wch585`; 1 differs in one bit |
| CH573 → CH585 | CH585 `PEER` tally: **30/30 byte-exact** `wch573`, 0 CRC failures |

The CH585 side counts matching frames in a static `PEER` record (read it with
`probe-rs read --chip CH585 b32 <PEER> 8`) because its RAM log wraps in
seconds. Cross-check both sides with
`tools/compare_peer.py --ch573-log <rtt.log> --ch585-peer <peer-dump>` (or
`--ch585-log <ram.log>` when the matching hit is still in the log); details in
`local-docs/results/ch573-ch585-bidir-20261128.md`.

The 1 one-bit error and the 102 empty / 7 impossible-length `Done` lines are
the same CRC-gating gap the nRF comparison exposed.
