# Silicon bring-up / debug checklist

Use this when a board hangs, never TX/RX-completes, or calibration times out.
Constants live in `src/rf/family/{ch32v208,ch572,ch583,ch585,ch595}.rs` as
`LLE_DEV_INIT` / `BB_DEV_INIT` / `RFEND_INIT` with a
[`Certainty`](../../src/rf/family/tables.rs) tag.

Legend in code comments: **UNCERTAIN** = probe on hardware before trusting.

## 0. Always confirm platform first (HAL)

| Check | V208 | CH572 / CH583 / CH585 / CH595 |
| --- | --- | --- |
| BLE AHB / sleep clock enabled before any BB/LLE/RFEND access | `RCC_AHBPeriph_BLE_CRC` | CH5xx sleep/clk BLE bits |
| HSE pad trim | `OSC->HSE_CAL_CTRL` | `HSECFG_Capacitance(...)` |
| NVIC vectors installed | IRQ 63 / 64 | IRQ 20 / 21 |
| Timebase for WaitTune / TX deadline | 1 MHz-class `InstantUs` | same |

If clock is gated, calibration polls never see ready bits — looks like “RF dead”.

## 1. After `LLE_DevInit` — dump these

Read back via probe-rs / debugger (prefer RAM history on sticky cores):

| Offset | CH572 | CH583 | CH585 | CH595 | Fail hint |
| --- | --- | --- | --- | --- | --- |
| `LLE+0x14` | `0x64` | `0x8C` | `0x8C` | `0x84` | wrong table / wrong base |
| `LLE+0x1C` | `0x6E` | `0x76` | `0x76` | `0x76` | |
| `LLE+0x2C` | `0x64` | **`0x3C`** | **`0x6C`** | **`0x6C`** | swapped chip table |
| `LLE+0x3C` | `0x64` | **`0x3C`** | **`0x6C`** | **`0x6C`** | same |
| `LLE+0x0C` | **`0x16000F`** | **`0xF00F`** | **`0x1F000F`** | **`0x1F000F`** | guard/IRQ mask wrong |
| `LLE+0x08` | `0xFFFFFFFF` | `0xFFFF` | `0xFFFFFFFF` | `0xFFFFFFFF` | |
| `LLE+0x54` | (untouched) | (untouched) | `0` | (untouched) | |

**UNCERTAIN:** RX buffer pointer (`+0x74` vs `+0x7C` path). If RX never completes
but TX does, dump these and the DMA/buffer address you programmed.

## 2. After `RFEND_DevInit` / Reset

| Check | CH572 | CH583 | CH585 | CH595 |
| --- | --- | --- | --- | --- |
| `RFEND_Reset` pulse `+0x0C=0x1101` | no | yes (V208-class) | **no** | no |
| `RFEND+0x28` | `0x480` | `0x480` | `0x480` | `0x480` |
| Rest of DevInit | RMW UNCERTAIN | long RMW UNCERTAIN | short RMW UNCERTAIN | RMW UNCERTAIN |

If `+0x28` is not `0x480`, you are not hitting RFEND (base wrong or clock off).

## 3. After `BB_DevInit`

| Offset | CH572 | CH583 | CH585 | CH595 |
| --- | --- | --- | --- | --- |
| `BB+0x34` | **`0x14`** | **`0x1D0` (464)** | **`0x50` (80)** | **`0x50`** |
| `BB+0x20` | UNCERTAIN | `0x90083` | UNCERTAIN (not in DevInit) | UNCERTAIN |
| `BB+0x38` | — | (later `0xF0` class on V208) | DevInit `0x3FF` | — |
| `BB+0x3C` | — | — | `0x2020C` | — |
| `BB+0` bit23 | UNCERTAIN | set | set | UNCERTAIN |
| `BB+0` bit28 | UNCERTAIN | set | UNCERTAIN | UNCERTAIN |

Swapping any of these tables (especially CH583↔CH585 or CH572↔anyone) is the
usual “cal hangs / weird RSSI” footgun.

## 4. Calibration / WaitTune

| Item | CH572 | CH583 | CH585 | CH595 | Debug |
| --- | --- | --- | --- | --- | --- |
| WaitTune `LLE+0x64` | **8000** | **6000** | **8000** | **8000** | dump `+0x64` + `RFEND+0x90` on timeout |
| Ready bits `RFEND+0x90` | 25+26 class | same | same | same | both must assert |
| VCO bands | 3 | 3 | 3 + **2522** | 3 | only CH585 needs 4th band |

**UNCERTAIN:** exact TXCtune loop / interpolation (large closed functions). Log
per-band success/fail if you port incrementally.

## 5. First TX/RX (runtime — mostly UNCERTAIN on CH58x)

Proven on **V208 open** only today:

| Item | V208 open | CH583 | CH585 |
| --- | --- | --- | --- |
| `LLE+0` cmd RX/TX/stop | 1 / 2 / `\|8` | UNCERTAIN (likely same IP) | UNCERTAIN |
| `LLE+0x50` mode TX/RX/cal | `0x5A` / `0x59` / `0x5D` | UNCERTAIN | UNCERTAIN |
| `BB+0` PHY bits | 1M `0x1000`, 2M `0`, coded `0x2000` (+S2 `0x4000`) | UNCERTAIN | headers stress 1M/2M |
| Soft IFS vs auto sequencer | soft preferred | product choice | RFIP helpers exist |

Bring-up order recommendation: get **adv TX on 1M** with V208-like mode words,
capture `LLE+0x08` IRQSTAT + `BB+0` on success/fail, then adjust.

## 6. Feature / module map

| Cargo feature | Module | Tables |
| --- | --- | --- |
| `ch32v208` | `family::ch32v208` | open `wch_rf` (port in progress) |
| `ch572` | `family::ch572` | unique new-table set; MMIO apply TBD |
| `ch583` | `family::ch583` | old tables recorded; MMIO apply TBD |
| `ch585` | `family::ch585` | new tables + `nCO2522`; MMIO apply TBD |
| `ch595` | `family::ch595` | near-CH585 without 2522; MMIO apply TBD |

Never enable two chip features. Never paste one chip’s immediates into another
(CH583↔CH585 and CH572↔anyone are especially sharp edges).
