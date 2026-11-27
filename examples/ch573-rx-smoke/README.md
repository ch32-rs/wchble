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
ELF SHA256 `8b2ab81a…a7ac708`). CH573 received 5 byte-exact frames in 25 s:

```
ch38 state=2 len=17 rssi=-92 … bb38=246f
buf [66, 17, 2, 0, 0, 238, 255, 193, 2, 1, 6, 7, 9, 119, 99, 104, 53, 56, 53, …]
```

= `42 11 02 00 00 EE FF C1 02 01 06 07 09 77 63 68 35 38 35` — matches the
CH585 frame exactly. ELF SHA256 of this example: `f6d3ae60…5308f3`.

Not yet: CRC status (`BB+0x38` bit5 reads set even with no PDU in the polling
context) and the real LLE/BB PFIC IRQ. See `local-docs/ch573-rx-isr-spec.md`.
