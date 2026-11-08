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

If `+0x28` low 12 bits are not `0x480`, you are not hitting RFEND (base wrong or
clock off). On V208 after cal, silicon may read `0x1480` (sticky high bit over
the DevInit value) — still counts as a hit.

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

## 5. First TX/RX (runtime)

V208 open path is **ported** in `family::ch32v208` (`set_channel` / `shut` /
`tx_basic` / `rx_basic` / `lle_isr` / `bb_isr`). CH5xx still UNCERTAIN:

| Item | V208 (`wchble`) | CH583 | CH585 (rusted-ch5 ref) |
| --- | --- | --- | --- |
| `LLE+0` cmd RX/TX/stop | 1 / 2 / `\|8` | UNCERTAIN | same class |
| `LLE+0x50` mode TX/RX/cal | `0x5A` / `0x59` / `0x5D` | UNCERTAIN | `0x0003_0258` / `_0158` / `_0558` |
| DMA TX/RX ptr | `+0x70` / `+0x74` | UNCERTAIN | `+0x78` / `+0x7c` |
| `BB+0` PHY bits | 1M `0x1000`, 2M `0`, coded `0x2000` (+S2 `0x4000`) | UNCERTAIN | bit7 2M selector |

### HAL smoke (V208)

Flashable firmware: [`examples/ch32v208-rf-smoke`](../../examples/ch32v208-rf-smoke)
(`cargo run --release` with wlink on a CH32V208). Sketch of what it does:

```rust,ignore
// after BLE AHB + HSE trim; IRQs still off; InstantUs live:
let mut radio = Ch32v208Radio::new(RX.init([0; RX_DMA_MIN]))?;
radio.init(&clock)?;
// enable NVIC 63/64 → radio.bb_isr() / radio.lle_isr()
radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
radio.set_channel(37)?;
// ADV_IND hdr/len/payload…
radio.tx_basic(&clock, &frame, 0, None)?;
```

Soft HCI Phase A (no air yet):

```rust,ignore
let controller = wchble::hci::new();
let mut soft = wchble::hci::SoftRunner::new();
// join(soft.run(), trouble_runner.run())
```

On TX timeout: dump `LLE+0x08`, `LLE+0x50`, `LLE+0x64`, `BB+0`, `RFEND+0x08/+0x2c`.

## 6. Feature / module map

| Cargo feature | Module | Tables |
| --- | --- | --- |
| `ch32v208` | `family::ch32v208` | open `wch_rf` init+runtime |
| `ch572` | `family::ch572` | unique new-table set; MMIO apply TBD |
| `ch583` | `family::ch583` | old tables recorded; MMIO apply TBD |
| `ch585` | `family::ch585` | new tables + `nCO2522`; MMIO apply TBD |
| `ch595` | `family::ch595` | near-CH585 without 2522; MMIO apply TBD |

Never enable two chip features. Never paste one chip’s immediates into another
(CH583↔CH585 and CH572↔anyone are especially sharp edges).
