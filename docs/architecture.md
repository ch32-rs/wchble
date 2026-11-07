# Architecture

`wchble` is an Embassy-style BLE compatibility layer. It is **not** a
standalone firmware package: `ch32-hal` / `ch5xx-hal` apps own clocks, NVIC,
linker scripts, and the Embassy executor; this crate supplies RF → soft HCI.

```text
┌─────────────────────────────────────────┐
│  Trouble Host (GATT / ATT / L2CAP)      │  HAL examples / apps
└──────────────────▲──────────────────────┘
                   │ bt-hci Controller traits
┌──────────────────┴──────────────────────┐
│  wchble::hci  SoftController + queues   │  feature: controller
└──────────────────▲──────────────────────┘
                   │ HCI cmds / events / ACL
┌──────────────────┴──────────────────────┐
│  wchble::ll   adv / conn / acl / ctrl   │  feature: controller
└──────────────────▲──────────────────────┘
                   │ RadioPlan / PDUs
┌──────────────────┴──────────────────────┐
│  wchble::phy  T_IFS / WFR / schedule    │  feature: phy
└──────────────────▲──────────────────────┘
                   │ channel / phy / tx_basic / rx_basic
┌──────────────────┴──────────────────────┐
│  wchble::rf   Radio + family MMIO       │  feature: ch32v208 (…)
│    regs / analog / txrx / isr / family  │
└──────────────────▲──────────────────────┘
                   │ InstantUs + IRQ entry
┌──────────────────┴──────────────────────┐
│  ch32-hal / ch5xx-hal                   │
│  RCC BLE clock, HSE trim, NVIC, time    │
└─────────────────────────────────────────┘
```

## Module map

| Module | Layer | Owns | Must not own |
| --- | --- | --- | --- |
| `rf` | L0 | MMIO, init/cal tables, TX/RX primitives, ISR dispatch | HCI, GATT, adv policy, RCC/NVIC |
| `phy` | L1 | WFR extend, soft T_IFS, PDU↔radio mapping | HCI parsing |
| `ll` | L2 | legacy adv, conn SM, ACL, LL control PDUs | GATT/ATT |
| `hci` | L3 | `bt-hci` traits, cmd/event/ACL queues | register bit soup |
| HAL / apps | L4 | Trouble host, clocks, IRQs, flash/RAM | stack logic |

## Chip selection

Enable **at most one** of `ch32v208`, `ch572`, `ch583`, `ch585`, `ch595`. Bases
and DevInit tables live under `src/rf/family/<chip>.rs` (cfg-per-family modules).

Shared across families: register **offsets** / bit names in `rf::regs`, the
`Radio` trait, and soft PHY/LL/HCI. **Not** shared: absolute bases, IRQ
numbers, LLE/BB/RFEND immediates, VCO bands, WaitTune.

Research buckets (porting order, not crate layout):

1. **CH32V208-class** — open `wch_rf` golden path
2. **CH583-class** — CH5xx map, DevInit ≈ V208 (rebase + audit)
3. **CH572 / CH585 / CH595-class** — CH5xx map, **per-chip** new tables;
   CH585 adds `nCO2522`; CH572 has unique LLE/BB immediates; CH595 ≈ CH585
   without the 4th VCO band

Each family module exports `LLE_DEV_INIT` / `BB_DEV_INIT` / `RFEND_INIT` with
[`Certainty`](../src/rf/family/tables.rs) tags. Silicon probe order:
[`research/bringup-debug.md`](research/bringup-debug.md).

### CH32V208 (do not confuse TOP with BB)

| Block | Base |
| --- | --- |
| TOP | `0x40024000` |
| BB | `0x40024100` |
| LLE | `0x40024200` |
| AES | `0x40024300` |
| RFEND | `0x40025000` |
| MISC | `0x40022000` |
| IRQ | BB=63, LLE=64 |

### CH5xx (`ch572` / `ch583` / `ch585` / `ch595`)

| Block | Base |
| --- | --- |
| BB | `0x4000C100` |
| LLE | `0x4000C200` |
| AES | `0x4000C300` |
| RFEND | `0x4000D000` |
| IRQ | BLEB=20, BLEL=21 |

Relative spacing from **BB** is shared: LLE `+0x100`, AES `+0x200`, RFEND `+0xF00`.
DevInit / WaitTune / VCO remain **per-chip** — do not share one table across these
features.

## HAL boundary

| Concern | Owner |
| --- | --- |
| `RCC` BLE/CRC AHB clock | HAL |
| HSE load trim (`OSC->HSE_CAL_CTRL`) | HAL |
| `NVIC` BB/LLE enable + priorities | HAL (vectors call into `wchble::rf` ISR hooks) |
| Embassy time / `InstantUs` impl | HAL |
| LLE/BB/RFEND DevInit + calibration | `wchble::rf` |
| Soft HCI + Trouble Host | `wchble::hci` + app |

## Bring-up phases

See [`research/path-b-soft-hci-trouble.md`](research/path-b-soft-hci-trouble.md):

- **A** — soft HCI typechecks with Trouble; Reset / Read BD_ADDR stubs
- **B** — legacy advertising visible on air
- **C** — BAS peripheral via Trouble (in a HAL example)
- **D** — additional chip families
