# CH32V208 RF verify smoke

On-target Phase 2 verification for `wchble`'s V208 RF path.

## What it does

1. Bring up SYSCLK = 96 MHz from the on-board 32 MHz HSE (`/4 × 12`)
2. Enable BLE AHB clock + HSE load trim (HAL boundary)
3. Start a free-running SysTick µs clock (`InstantUs`)
4. `Ch32v208Radio::new` → `init`
5. Dump / check sticky DevInit markers (`LLE+0x14/1c/2c/3c`, `RFEND+0x28`, `BB+0x34`)
6. Multi-channel ADV_IND TX on **37 / 38 / 39**
7. RX listen on ch37 (poll `IRQSTAT` / `WINDOW`; hit or timeout both pass)
8. SoftRunner Phase B: build ADV_IND from AdvState and TX on mapped channels

SDI markers: `rf init ok`, `regs ok`, `tx ch{37,38,39} ok`, `rx armed` +
`rx timeout|rx hit|rx poll deadline`, `soft adv len N`, `soft tx chN ok`,
`smoke done`.

Verified 2026-11-08 on `CH32V208WBU6` (`wlink -d 1a86:8010:2FC48F06B4A8`):
init + DevInit dump + TX 37/38/39 + RX hit + SoftRunner TX 37/38/39 +
`smoke done` at HCLK 96 MHz. Note: `RFEND+0x28` may read `0x1480` after cal
(low 12 bits still `0x480`).

## Build / flash

```bash
cd examples/ch32v208-rf-smoke
cargo build --release
# With several WCH-Links attached, pin the V208 probe by serial:
wlink -d 1a86:8010:<SERIAL> flash --enable-sdi-print \
  target/riscv32imac-unknown-none-elf/release/ch32v208-rf-smoke
# Then read SDI on that probe's cu.usbmodem… port (wlink --watch-serial
# may open another probe's serial when multiple links are present).
```

Requires a sibling checkout of [`ch32-hal`](https://github.com/ch32-rs/ch32-hal)
at `../../../ch32-hal` and `wlink` on `PATH`. The example enables the
`controller` feature so SoftRunner / AdvState are linked.

RX DMA is wrapped in `#[repr(align(4))]` — plain `StaticCell<[u8; N]>` can
place the payload at an odd address and fail `Ch32v208Radio::new`.

## Sniffer check

With a BLE sniffer / nRF Connect nearby, look for ADV_IND on channels 37/38/39
with local names `wchble` (direct TX) and `softadv` (SoftRunner PDU) while the
burst runs.
