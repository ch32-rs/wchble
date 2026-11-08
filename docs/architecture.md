# Architecture

`wchble` is an Embassy-style BLE compatibility layer. It is **not** a
standalone firmware package: `ch32-hal` / `ch5xx-hal` apps own clocks, NVIC,
linker scripts, and the Embassy executor; this crate supplies RF → soft HCI.

> **Before changing RF/LL/HCI code, read [`docs/pitfalls.md`](pitfalls.md).**
> It lists the invariants that silently produce "TX ok" with nothing on air
> (sticky W1C `TX_DONE`, DMA alignment, AdvA seeding, quiet TX path).

```text
┌─────────────────────────────────────────┐
│  Trouble Host (GATT / ATT / L2CAP)      │  HAL examples / apps
└──────────────────▲──────────────────────┘
                   │ bt-hci Controller traits
┌──────────────────┴──────────────────────┐
│  wchble::hci  ExternalController + SoftRunner │  feature: controller
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
| `hci` | L3 | `ExternalController` transport + SoftRunner cmds | register bit soup |
| HAL / apps | L4 | Trouble host, clocks, IRQs, flash/RAM | stack logic |

### Multi-family rules (L0)

`Radio` and above are family-agnostic. Below `Radio`, split three ways:

| Bucket | May share | Must stay per-chip |
| --- | --- | --- |
| Pure helpers | channel→MHz, cal interpolation math, HCI queues | — |
| Orchestration | init order LLE→RFEND→BB→cal; TX/RX stage names | literal mode words, DMA ptr offsets, synth path |
| Family module | cfg-selected `family/<chip>.rs` + DevInit tables | RFEND RMW soup, band codes, BB power pack |

**Do not** copy V208 `tx_basic` into CH585 with three constants changed — DMA
(`+0x70/+0x74` vs `+0x78/+0x7c`), LLE mode bank, and synth programming diverge.
Optional generation helpers (e.g. CH5xx bases/IRQ only) are fine; one backend for
all CH5xx is not. See [`research/ch58x-hal-ble-reuse.md`](research/ch58x-hal-ble-reuse.md).

Shared L0 modules today: `regs` (offset *names*), `analog` (wait_tune / nibble),
`timing` (pure formulas; V208 TX window helpers are clearly named `v208_*`).

## Chip selection

Enable **at most one** of `ch32v208`, `ch572`, `ch583`, `ch585`, `ch592`,
`ch595`. Bases and DevInit tables live under `src/rf/family/<chip>.rs`
(cfg-per-family modules).

Shared across families: register **offsets** / bit names in `rf::regs`, the
`Radio` trait, and soft PHY/LL/HCI. **Not** shared: absolute bases, IRQ
numbers, LLE/BB/RFEND immediates, VCO bands, WaitTune.

Research buckets (porting order, not crate layout):

1. **CH32V208-class** — open `wch_rf` golden path
2. **CH583-class** — CH5xx map, DevInit ≈ V208 (rebase + audit)
3. **CH572 / CH585 / CH592 / CH595-class** — CH5xx map, **per-chip** new
   tables; CH585 adds `nCO2522`; CH572 has unique LLE/BB immediates; CH592
   uses the `0x6E` LLE pair and TX DMA `+0x78`; CH595 ≈ CH585 without the 4th
   VCO band

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

### CH5xx (`ch572` / `ch583` / `ch585` / `ch592` / `ch595`)

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
| RX DMA scratch (`≥272` B, 4-byte aligned) | HAL / app → `Ch32v208Radio::new` |
| LLE/BB/RFEND DevInit + calibration | `wchble::rf` |
| Soft HCI + Trouble Host | `wchble::hci` + app |

### `Radio::init` precondition (V208)

Before `radio.init(&clock)` the HAL must:

1. Enable BLE AHB clock (`RCC_AHBPeriph_BLE_CRC` class).
2. Apply HSE load trim.
3. Keep BB/LLE IRQs **disabled** (this crate clears IRQSTAT; HAL enables NVIC after).
4. Provide a working `InstantUs` (WaitTune / filter polls use it).

Construct the radio with a `'static` RX DMA buffer. The LLE reads `RXBUFPTR`
as a word address, so use [`DmaBuf`](../src/rf/txrx.rs) (a plain
`StaticCell<[u8; N]>` can land at +1 and `new` rejects it):

```rust,ignore
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
static RX: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
let radio = wchble::rf::family::ch32v208::Ch32v208Radio::new(
    &mut RX.init(DmaBuf::zeroed()).0,
)?;
// Or, for HAL code that picks the backend by feature:
// let radio = wchble::rf::new_radio_with_dma(&mut RX.init(DmaBuf::zeroed()).0)?;
```

## Bring-up phases

See [`research/path-b-soft-hci-trouble.md`](research/path-b-soft-hci-trouble.md):

- **A** — soft HCI typechecks with Trouble; Reset / Read BD_ADDR — **done**
  (`hci::new` + `SoftRunner`; join SoftRunner with Trouble runner in HAL apps)
- **B** — legacy advertising visible on air — **verified** on V208 (macOS
  CoreBluetooth sees `wchble`; see `examples/ch32v208-trouble-adv`)
- **C** — BAS peripheral via Trouble (in a HAL example)
- **D** — additional chip families
