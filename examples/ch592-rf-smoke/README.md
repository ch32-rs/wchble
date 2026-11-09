# CH592 RF verify smoke

On-target verification for `wchble`'s CH592 (CH59x) RF path.

## What it does

1. Bring up SYSCLK 60 MHz from the on-board HSE (`ch5xx-hal` `rcc`)
2. Start a free-running SysTick µs clock (`InstantUs`)
3. `Ch592Radio::new` → `init` (`LLE_DevInit → RFEND_DevInit → TXCtune →
   BB_DevInit`)
4. Dump DevInit markers (`LLE+0x06/14/2c/3c/50/54/0c`, `RFEND+0x28/44`,
   `BB+0x00/10/2c/34/38`)
5. Multi-channel ADV_IND TX on **37 / 38 / 39**
6. Two RX arming rounds on ch38 (arm-clear / timeout still proves the path)
7. Loop: ADV_IND on 37/38/39 + the vendor `RF_PHY` reference frame on ch39,
   with a periodic RX check on ch37

SDI markers: `rf init ok`, `LLE …` / `RFEND …` / `BB …`, `tx ch{37,38,39} ok`,
`rx listen hit|arm-clear`, `adv loop`, `rx loop hit len=N crc=true`.

Verified 2026-11-08 on `1a86:8010:F93D8F067E10` (SDI
`/dev/cu.usbmodemF93D8F067E102`): init + TX 37/38/39 + RX hits with `crc=true`.
A CH32V208 reference receiver decodes the CH592 ADV_IND (`crc=true`) and macOS
CoreBluetooth sees the local name `wch592` at ≈ −43 dBm.

Two CH592-specific traps this example guards: `TX_DONE` at window expiry is not
radiation (verify with the second receiver), and the `IRQSTAT` W1C is gated by
`LLE+0x0C` bit 17.

## Build / flash

```bash
cd examples/ch592-rf-smoke
cargo build --release
wlink -d 1a86:8010:<SERIAL> flash --enable-sdi-print \
  target/riscv32imc-unknown-none-elf/release/ch592-rf-smoke
```

Requires a sibling checkout of
[`ch5xx-hal`](https://github.com/ch32-rs/ch5xx-hal) at `../../../ch5xx-hal` and
`wlink` on `PATH`. `wlink --watch-serial` may open another attached probe's
serial; pin the probe with `-d` for flashing and read SDI on its own
`cu.usbmodem…` port.
