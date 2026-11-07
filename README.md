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
| `ch32v208` | Bases + open-driver DevInit markers; MMIO apply next |
| `ch572` | CH5xx map + unique new-table constants (`0x64` / `0x16000F`); MMIO TBD |
| `ch583` | Bases + closed-disasm “old tables” (≈V208); MMIO apply TBD |
| `ch585` | Bases + closed-disasm “new tables” / `nCO2522`; MMIO apply TBD |
| `ch595` | Near-CH585 tables without `nCO2522` (`0x84` highs); MMIO TBD |

Uncertain fields are tagged `UNCERTAIN` / `Certainty::*` for silicon debug — see
[`docs/research/bringup-debug.md`](docs/research/bringup-debug.md).

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
| `docs/research` | Family init research notes |

Firmware examples live in the HAL repos once integration lands — not here.

## Features

```bash
# Radio / family only (HAL RF bring-up)
cargo check --features ch32v208

# Soft HCI + LL surface for Trouble
cargo check --features ch32v208,controller,phy
```

Enable **at most one** chip feature (`ch32v208`, `ch572`, `ch583`, `ch585`, `ch595`).

## HAL integration sketch

```rust,ignore
// inside ch32-hal / application after BLE AHB clock + HSE trim + NVIC:
use wchble::hci::SoftController;
use wchble::rf::Radio;
use wchble::time::InstantUs;

let mut ctl = SoftController::new();
ctl.radio.init(&hal_clock)?;
// later: impl bt_hci::controller::Controller for SoftController
// let stack = trouble_host::new(ctl, &mut resources);
```

## Status

**Scaffold complete** (2026-11-07): open Path B crate, family stubs with DevInit
markers for `ch32v208` / `ch572` / `ch583` / `ch585` / `ch595`, research +
bring-up debug docs. RF MMIO apply, TX/RX, and `bt-hci` Controller impl are next.

Tracked in [`docs/progress.md`](docs/progress.md). Phased gates:
[`docs/research/path-b-soft-hci-trouble.md`](docs/research/path-b-soft-hci-trouble.md).

## License

Apache-2.0. See `LICENSE-APACHE`.
