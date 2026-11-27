# CH573 RX smoke (single-window ADV RX)

On-target RX path for the CH573 backend:

1. Apply DevInit + `DMA_DevInit`, then arm one RX window per channel
   (`ch37/38/39`, 20 ms each) with `rx_basic`.
2. Service the window with `rx_poll` (mirrors `BB_IRQLibHandler` +
   `LLE_IRQLibHandler`) until `Done` / `Timeout`.
3. Print `len`, `rssi` and the first 48 bytes of the DMA buffer over defmt.

`SDIPrint` is a no-op on CH573 in ch5xx-hal, so this example uses **defmt/RTT**.

## RX buffer layout

The hardware writes into the pointer at **`DMA+0x18`** (not `+0x14`):

```
[hdr][len][payload …][pad]
[status u16][rssi i8]   @ off = (len + 5) & 0x1fc
```

There is no RSSI prefix in BLE mode. The window only DMAs when the BB payload
event (`BB+0x38` bit6) is serviced and `LLE+0x60` is reloaded; `rx_poll`
does that.

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

Transmitter: `examples/ch585-rf-smoke` (ADV_NONCONN_IND, name `wch585`,
ELF SHA256 `8b2ab81a…a7ac708`). In a 20 s run CH573 completed 13 frames and
all 13 were byte-exact:

```
ch38 state=2 len=17 rssi=-91 … bb38=246f lle08=100000
buf [66, 17, 2, 0, 0, 238, 255, 193, 2, 1, 6, 7, 9, 119, 99, 104, 53, 56, 53, …]
```

= `42 11 02 00 00 EE FF C1 02 01 06 07 09 77 63 68 35 38 35` — matches the
CH585 frame exactly. ELF SHA256 of this example: `752801c8…1c3afb`.

Not yet:

- **CRC status** — `BB+0x38` bit5 reads set even with no PDU in the polling
  context, so `RxPoll::Done` omits it.
- **Real LLE/BB PFIC IRQ** — `ble_isr`/`rx_isr_take` and the `BLEB`/`BLEL`
  handlers are scaffolding only; `USE_ISR` stays `false`. Measured with a
  self-disabling counting handler: BLEL is entered **1000 times inside one
  20 ms window** while the engine is armed, yet `LLE+0x08` low 16 bits are 0
  on the first entry (only the non-writable bit 20 stays set) and `unpend()`
  does not stop it. Enabling **only BLEB** keeps the main loop alive but then
  every window times out with `cnt=0`, so RX completion still needs the LLE
  side. Details and next probes in `local-docs/ch573-rx-isr-spec.md`.

Register facts measured on silicon: `LLE+0x08` is plain R/W (write `~0`,
read `~0`), bit 20 (`0x100000`) is not writable and must not be relied on for
the interrupt line; `BB+0x38` ignores software writes.

`probe-rs run` occasionally attaches RTT late and shows only the boot lines —
re-run the same ELF before suspecting a firmware hang.
