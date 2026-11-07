# Silicon bring-up / debug checklist

Use this when a board hangs, never TX/RX-completes, or calibration times out.
Constants live in `src/rf/family/{ch32v208,ch583,ch585}.rs` as `LLE_DEV_INIT` /
`BB_DEV_INIT` / `RFEND_INIT` with a [`Certainty`](../../src/rf/family/tables.rs)
tag.

Legend in code comments: **UNCERTAIN** = probe on hardware before trusting.

## 0. Always confirm platform first (HAL)

| Check | V208 | CH583 / CH585 |
| --- | --- | --- |
| BLE AHB / sleep clock enabled before any BB/LLE/RFEND access | `RCC_AHBPeriph_BLE_CRC` | CH5xx sleep/clk BLE bits |
| HSE pad trim | `OSC->HSE_CAL_CTRL` | `HSECFG_Capacitance(...)` |
| NVIC vectors installed | IRQ 63 / 64 | IRQ 20 / 21 |
| Timebase for WaitTune / TX deadline | 1 MHz-class `InstantUs` | same |

If clock is gated, calibration polls never see ready bits — looks like “RF dead”.

## 1. After `LLE_DevInit` — dump these

Read back via probe-rs / debugger (prefer RAM history on sticky cores):

| Offset | CH583 expect | CH585 expect | Fail hint |
| --- | --- | --- | --- |
| `LLE+0x14` | `0x8C` | `0x8C` | wrong table / wrong base |
| `LLE+0x1C` | `0x76` | `0x76` | |
| `LLE+0x2C` | **`0x3C`** | **`0x6C`** | used the other chip’s table |
| `LLE+0x3C` | **`0x3C`** | **`0x6C`** | same |
| `LLE+0x0C` | **`0xF00F`** | **`0x1F000F`** | guard/IRQ mask wrong |
| `LLE+0x08` | `0xFFFF` | `0xFFFFFFFF` | |
| `LLE+0x54` | (untouched) | `0` | |

**UNCERTAIN:** RX buffer pointer (`+0x74` vs `+0x7C` path). If RX never completes
but TX does, dump these and the DMA/buffer address you programmed.

## 2. After `RFEND_DevInit` / Reset

| Check | CH583 | CH585 |
| --- | --- | --- |
| `RFEND_Reset` pulse `+0x0C=0x1101` | yes (closed + V208-class) | **no symbol** — skip |
| `RFEND+0x28` | `0x480` | `0x480` |
| Rest of DevInit | long RMW — **UNCERTAIN transcription** | short RMW — **UNCERTAIN transcription** |

If `+0x28` is not `0x480`, you are not hitting RFEND (base wrong or clock off).

## 3. After `BB_DevInit`

| Offset | CH583 expect | CH585 expect |
| --- | --- | --- |
| `BB+0x34` | **`0x1D0` (464)** | **`0x50` (80)** |
| `BB+0x20` | `0x90083` | **UNCERTAIN** (not in DevInit) |
| `BB+0x38` | (later `0xF0` clear class on V208) | DevInit `0x3FF` |
| `BB+0x3C` | — | `0x2020C` |
| `BB+0` bit23 | set | set |
| `BB+0` bit28 | set | **UNCERTAIN** (not seen in DevInit) |

Swapping CH583/CH585 here is the usual “cal hangs / weird RSSI” footgun.

## 4. Calibration / WaitTune

| Item | CH583 | CH585 | Debug |
| --- | --- | --- | --- |
| WaitTune load into `LLE+0x64` | **6000** | **8000** | if timeout always fires, dump `+0x64` + `RFEND+0x90` |
| Ready bits `RFEND+0x90` | bits 25+26 class | same | both must assert |
| VCO bands | 2401/2440/2480 | + **2522** | CH585 missing 4th band → edge channels |

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
| `ch583` | `family::ch583` | old tables recorded; MMIO apply TBD |
| `ch585` | `family::ch585` | new tables recorded; MMIO apply TBD |

Never enable two chip features. Never paste CH585 immediates into CH583 (or
the reverse).
