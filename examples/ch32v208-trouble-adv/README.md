# CH32V208 Trouble ADV

Embassy + SoftRunner + Trouble Host join: Host-driven legacy ADV_IND on air.

## What it does

1. 96 MHz SYSCLK from 32 MHz HSE (`/4 × 12`)
2. BLE AHB + HSE trim, radio init (same as RF smoke)
3. `wchble::hci::new()` SoftController + SoftRunner
4. Trouble 0.8 Host `Peripheral::advertise`
5. Interleaved SoftRunner HCI pump + `tx_basic` while adv enabled

SDI markers: `rf init ok`, `hci host up`, `adv enable`, `tx ch{37,38,39}`,
`trouble adv running`.

## Build / flash

```bash
cd examples/ch32v208-trouble-adv
cargo build --release
wlink -d 1a86:8010:<SERIAL> flash --enable-sdi-print \
  target/riscv32imac-unknown-none-elf/release/ch32v208-trouble-adv
```

Requires sibling [`ch32-hal`](https://github.com/ch32-rs/ch32-hal) at
`../../../ch32-hal`.

### `trouble-host` pin

crates.io `trouble-host` 0.8.0 still depends on `bt-hci` 0.10, while `wchble`
uses 0.11. This example expects a sibling checkout of
[`embassy-rs/trouble`](https://github.com/embassy-rs/trouble) at
`../../../trouble` (i.e. next to `wchble` / `ch32-hal`). Override
`trouble-host.path` in `Cargo.toml` if your clone lives elsewhere.

## Sniffer

Look for ADV_IND named `wchble` on channels 37/38/39. SCAN_RSP / connections
are out of scope for this cut.
