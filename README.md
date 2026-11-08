# wchble

Embassy-style Bluetooth Low Energy layer for WCH MCUs, consumed by
[`ch32-hal`](https://github.com/ch32-rs/ch32-hal) and
[`ch5xx-hal`](https://github.com/ch32-rs/ch5xx-hal) — not a standalone firmware
crate.

HALs own clocks, NVIC, Embassy executor, and board bring-up. This crate owns
the radio → soft PHY → link layer → soft HCI path that Trouble Host drives,
mirroring how Embassy splits [`bt-hci`](https://github.com/embassy-rs/bt-hci) +
[`trouble`](https://github.com/embassy-rs/trouble) from chip HALs.

```text
Trouble Host          (in HAL examples / apps)
    ↕  bt-hci (in-process soft HCI)
wchble::hci
    ↕
wchble::ll            # Rust link layer
    ↕
wchble::phy           # soft IFS / WFR
    ↕
wchble::rf            # pure Rust MMIO radio HAL
    ↕
ch32-hal / ch5xx-hal  # RCC BLE clock, HSE trim, IRQ install, time
```

RF backends (cfg-per-family under `src/rf/family/`):

| Feature | Status |
| --- | --- |
| `ch32v208` | DevInit/cal + channel/shut/tx_basic/rx_basic/ISR (open `wch_rf`); HAL smoke next |
| `ch572` | CH5xx map + unique new-table constants (`0x64` / `0x16000F`); MMIO TBD |
| `ch583` | Bases + closed-disasm “old tables” (≈V208); MMIO apply TBD |
| `ch585` | Bases + closed-disasm “new tables” / `nCO2522`; MMIO apply TBD |
| `ch592` | CH59x EVT v1.7 disasm: `0x6E` LLE pair, `BB+0x38=0xFF`, TX DMA `+0x78`; MMIO apply TBD |
| `ch595` | Near-CH585 tables without `nCO2522` (`0x84` highs); MMIO TBD |

Uncertain fields are tagged `UNCERTAIN` / `Certainty::*` for silicon debug — see
[`docs/research/bringup-debug.md`](docs/research/bringup-debug.md).

> **Read [`docs/pitfalls.md`](docs/pitfalls.md) before touching RF/LL/HCI.**
> The sticky W1C `TX_DONE` bug, DMA alignment, and AdvA seeding all fail as
> "success with nothing on air".

This repository used to wrap closed WCH `.a` BLE libraries via bindgen. That
path is gone; the open register-level work continues from the CH32V208 NimBLE
RF bring-up (`wch_rf`).

## Workspace

| Path | Role |
| --- | --- |
| `src/rf` | L0 radio HAL |
| `src/phy` | L1 schedule / IFS / WFR |
| `src/ll` | L2 link layer |
| `src/hci` | L3 soft HCI (`bt-hci` Controller) |
| `docs/architecture.md` | Layer diagram + HAL boundary |
| `docs/pitfalls.md` | Bring-up invariants / false-green traps |
| `docs/research` | Family init research notes |
| `examples/` | Flashable V208 RF smoke + Trouble ADV examples |

On-target bring-up examples live in this repo while the HAL integration is in
flight; production firmware still belongs in the HAL repos.

## Features

```bash
# Radio / family only (HAL RF bring-up)
cargo check --features ch32v208

# Soft HCI + LL surface for Trouble
cargo check --features ch32v208,controller,phy
```

Enable **at most one** chip feature (`ch32v208`, `ch572`, `ch583`, `ch585`,
`ch592`, `ch595`).

## HAL integration sketch

```rust,ignore
// inside ch32-hal / application after BLE AHB clock + HSE trim (IRQs still off):
use wchble::hci::{self, SoftRunner};
use wchble::rf::family::ch32v208::Ch32v208Radio;
use wchble::rf::txrx::RX_DMA_MIN;
use wchble::rf::Radio;

static RX: StaticCell<[u8; RX_DMA_MIN]> = StaticCell::new();
let mut radio = Ch32v208Radio::new(RX.init([0; RX_DMA_MIN]))?;
radio.init(&hal_clock)?; // LLE → RFEND → BB → cal; HAL enables NVIC after

let controller = hci::new(); // ExternalController<HciTransport, 4>
let mut soft = SoftRunner::new();
// soft.set_bd_addr([...]);

// join Trouble's runner with SoftRunner::run — SoftRunner must reply
// Command Complete or Host exec hangs waiting on the in-process channel.
// let stack = trouble_host::new(controller, &mut resources);
```

On-target smoke (RF only, before Trouble) remains a HAL-side example:
`set_channel(37)` + `tx_basic` ADV_IND with BB/LLE IRQs wired — see
[`docs/research/bringup-debug.md`](docs/research/bringup-debug.md).

## Status

**Soft HCI Phase B verified on air** (2026-11-08): `hci::new()` is
`bt_hci::ExternalController` over bounded embassy channels; `SoftRunner`
answers Reset / ReadBdAddr / event masks / LE buffer size / legacy adv cmds.
[`examples/ch32v208-trouble-adv`](examples/ch32v208-trouble-adv) joins
SoftRunner with a Trouble Host and advertises ADV_IND on 37/38/39; macOS
CoreBluetooth sees `wchble` (`RSSI ≈ -54`) via
`examples/ch32v208-trouble-adv/tools/scan_wchble.swift`. Next: SCAN_RSP /
connections (Phase C).

Tracked in [`docs/progress.md`](docs/progress.md). Phased gates:
[`docs/research/path-b-soft-hci-trouble.md`](docs/research/path-b-soft-hci-trouble.md).

## License

Apache-2.0. See `LICENSE-APACHE`.
