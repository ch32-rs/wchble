# CH573 RF smoke (DMA probe + ADV TX)

On-target gate for the CH573 backend after DevInit:

1. Apply LLE/BB/RFEND DevInit + `DMA_DevInit` enables + BLE clock on.
2. **Probe** `LLE+0x70/74/78/7c` vs `DMA+0x10/14/18/1c` stickiness.
3. ADV_NONCONN_IND TX on **37 / 38 / 39** (local name `wch573`).
4. `adv loop` for a macOS CoreBluetooth scanner.

`SDIPrint` is a no-op on CH573 in ch5xx-hal (CH592-only), so this example
uses **defmt/RTT**.

## Hard constraint

CH573 SRAM is only `@0x20003800..0x20008000` (18 KiB), and the DMA engine
keeps just the low 14 bits of a pointer, so it only reaches
`0x20004000..0x20008000`. Buffer pointers are programmed on the **DMA block**
at `0x4000C000` (`+0x10` TX / `+0x18` RX; see `examples/ch573-rx-smoke`) as
**16-bit offsets from
`0x20000000`** (e.g. `0x20004c20` → `0x4c20`). This example pins its buffers
in `.dma_buffer` at `0x20004c00`. LLE `+0x78/+0x7c` do **not** stick. Do
**not** flash this image with the CH585 preflight probe (`F93D8F067E10`).

## Build / flash

```bash
cd examples/ch573-rf-smoke
cargo run --release
# or:
probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2 --scan-region ram \
  target/riscv32imac-unknown-none-elf/release/ch573-rf-smoke
```

Success markers (RTT):

- `rf init ok`
- `dma-probe … stick=1`
- `tx ch{37,38,39} ok` (board-side; see On-air)
- `adv loop`

## On-air (macOS)

```bash
swift examples/ch573-rf-smoke/tools/scan_ch573.swift wch573 20
```

Exit 0 if the local name is seen. Do not treat board-only `tx … ok` as PASS.

## Silicon status (2026-11-27, probe `5CED…`)

**PASS**

- Absolute LLE/BB/RFEND DevInit markers match EVT.
- DMA probe: LLE 70/74/78/7c ignore writes; DMA 10/14/18/1c stick as 16-bit
  SRAM offsets.
- `LLE+0x08` is a **plain R/W status word, not W1C**: clear flags with
  read-modify-write (`write(v & !bits)`). Writing `0xffff` to "clear" sets
  every flag and hides the TX-start event.
- TX must be kicked from the LLE **TX-start event (bit9 `0x200`)** exactly
  like `LLE_IRQLibHandler`: `LLE+0x60=0x190`, `BB+0x2c=(v&~3)|2`,
  `BB+0x00|=0x1000_0000`. A blind kick after arming produces no air traffic.
- **VCO tune works** only under `LLE MODE=0x5d (CAL)` (`BLE_RegInit` order):
  `TUNE_CO` bit25/26 assert in ~2 ms. Without CAL the tune silently no-ops.
- Registers reconciled to EVT disasm: `RFEND_DevInit` RMW masks (earlier
  `lui` misread, fields off by 4 bits), ADV `RXCFG18` bit25/`0x18`,
  `CRC_AA_CFG=0x1f`, FREQMODE clear[1:0], `FECTRL` only bit17 for RF-on
  (wider `0x0033_0000` is a CH585 constant).

**Earlier failure, now fixed.** The baseband kick used to fire blindly while
the IRQ flags were destroyed by `write(LLESTAT, 0xffff)`; the BB therefore
started outside the LLE TX window and nothing reached the air. Clearing flags
with RMW and kicking on bit9 fixes it — same image, no RFEND replay hack:

- nRF sniffer pcap: `d6be898e 42 11 c1ffee000073 020106 0709 "wch573"`.
- macOS CoreBluetooth: `scan_ch573.swift wch573 25` → 37 observations,
  RSSI ≈ −40..−49 dBm (exit 0).

Calibration note: `RFEND_RXFilter`/`RFEND_RXAdc` run in CAL mode after TXCtune.
`RFEND_RXFilter` now replays the vendor order, including the second `CFG0C`
bit4 set after the settle; the boot log reports `rx filter ok=… code=…`
(`CFG50[4:0]`) and `RFEND 50=… 9c=…`. RX calibration does not gate TX.

## On-air (nRF sniffer)

`--follow-by-name wch573` never resolves before the first advertisement, so
scan raw traffic and search the capture for the AdvA bytes `c1 ff ee 00 00 73`
(or the payload string `wch573`).

Byte-exact check (2026-11-27, nRF Sniffer via
`~/.nrfutil/bin/nrfutil ble-sniffer sniff --port … --output-pcap-file …`):
25 s run, 8162 PDUs captured, **79 of 79 `wch573` PDUs equal**
`42 11 c1 ff ee 00 00 73 02 01 06 07 09 77 63 68 35 37 33`, and the board
logged `tx ch37/38/39 ok` twice. The same image also passes the macOS scan
(`scan_ch573.swift wch573`, 37 observations earlier).

## Out of scope (follow-ups)

- RX hit path lives in `examples/ch573-rx-smoke` (`rx_basic` here is arm-only).
- `.dma_buffer` placement (currently `RAM_END - 0x3400`).
