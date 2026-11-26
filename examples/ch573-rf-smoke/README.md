# CH573 RF smoke (DevInit readback)

First on-target gate for the CH573 backend: apply absolute LLE/BB/RFEND
DevInit stores and dump the live registers over **defmt/RTT**. TX/RX are
still `Unsupported`.

`SDIPrint` is a no-op on CH573 in ch5xx-hal (CH592-only), so this example
uses RTT like the HAL CH573 flash smoke.

## Hard constraint

CH573 SRAM is only `@0x20003800..0x20008000` (18 KiB). The smoke prints the
RX DMA address; it must fall in that window. Do **not** flash this image with
the CH585 preflight probe (`F93D8F067E10`).

## Build / flash

```bash
cd examples/ch573-rf-smoke
cargo run --release
# or:
probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2 \
  target/riscv32imac-unknown-none-elf/release/ch573-rf-smoke
```

Success markers (RTT):

- `rf init ok`
- `dma …` inside `@0x20003800..`
- `LLE …` / `RFEND …` / `BB …` matching the EVT tables

## Silicon readback (2026-11-26, probe `5CED…`)

```
boot
sysclk=60000000
dma 20003844 len=272
rf init ok
LLE 0c=c303 14=50 1c=a 2c=3c 3c=3c 44=50 4c=a 58=f6 74=0 78=0 7c=0
RFEND 28=480 0c=1111 90=400000
BB 00=a7 34=152
park (tx/rx still Unsupported)
```

Absolute DevInit stores match EVT. `LLE+0x7c` did **not** retain the RX DMA
pointer after write — BUFPTR offset still UNCERTAIN for TX/RX bring-up.
