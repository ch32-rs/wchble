# CH32V208 RF smoke

On-target bring-up firmware for `wchble`'s V208 RF path.

## What it does

1. Enable BLE AHB clock + HSE load trim (HAL boundary)
2. Start a free-running SysTick µs clock (`InstantUs`)
3. `Ch32v208Radio::new` → `init` → `set_channel(37)`
4. Burst eight ADV_IND PDUs (`tx_basic`) with name `wchble`

SDI print markers: `rf init ok`, `tx ch37 ok #N`, `smoke done`.

## Build / flash

```bash
cd examples/ch32v208-rf-smoke
cargo build --release
cargo run --release          # wlink flash + SDI serial
```

Requires a sibling checkout of [`ch32-hal`](https://github.com/ch32-rs/ch32-hal)
at `../../../ch32-hal` and `wlink` on `PATH`.

## Sniffer check

With a BLE sniffer / nRF Connect nearby, look for ADV_IND on channel 37
with local name `wchble` while the burst runs.
