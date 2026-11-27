# CH573 RX smoke (single-window ADV RX)

On-target RX path for the CH573 backend:

1. Apply DevInit + `DMA_DevInit`, then arm one RX window per channel
   (`ch37/38/39`, 20 ms each) with `rx_basic`.
2. Service the window from the **real LLE interrupt** (PFIC IRQ 21, routed
   through fast-interrupt slot 2); `rx_poll` remains as the `USE_ISR = false`
   fallback.
3. Print `len`, `rssi` and the first 48 bytes of the DMA buffer over defmt.

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

## Acceptance (2026-11-27, probe `5CED…`)

Transmitter: `examples/ch585-rf-smoke` (ADV_NONCONN_IND, name `wch585`).
30 s ISR run: **107 `Done`, 26 of them the exact `wch585` frame**, 503 window
timeouts; `isr=` delta was 1–3 per window (no storm). ELF SHA256
`898fcce0…fde038c3`. Earlier polling run for comparison: 13/13 exact.

```
ch38 state=2 len=17 rssi=-99 cnt=0 isr=1 bb38=246f lle08=100000
buf [66, 17, 2, 0, 0, 238, 255, 193, 2, 1, 6, 7, 9, 119, 99, 104, 53, 56, 53, …]
```

= `42 11 02 00 00 EE FF C1 02 01 06 07 09 77 63 68 35 38 35` — the CH585 frame.

Not yet:

- **CRC status** — `BB+0x38` bit5 reads set even with no PDU in the polling
  context, so `RxPoll::Done` omits it.
- RSSI is read from the status word (`(len+5)&0x1fc + 2`); cnlohr's iSLER
  reads `BB+0x30 >> 15` for CH571/573 — worth cross-checking later.
- RXFilter determinism (occasional spurious timeouts).

`probe-rs run` occasionally attaches RTT late and shows only the boot lines —
re-run the same ELF before suspecting a firmware hang.
