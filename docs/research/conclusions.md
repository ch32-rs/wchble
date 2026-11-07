# Conclusions — CH32V208 NimBLE vs CH585EVT BLE core init

## Verdict

**Most of the BLE controller IP is the same family; a small set of core-init details are not.**

Hypothesis from the request (“mostly the same, a little core init may differ”) is confirmed by the closed CH585 objects:

- Same block decomposition and naming: BB / LLE / AES / RFEND, `BLE_IPCoreInit`, `*_DevInit`, `BLE_RegInit`, `RFEND_TXCtune/TXFtune/RXFilter/RXAdc`.
- Same relative MMIO spacing and calibration pipeline shape.
- **Different** absolute bases, IRQ numbers, and several DevInit / WaitTune / VCO-table constants.

So: reusable as a **mental model and bring-up checklist**, not as a binary register dump to paste onto CH585.

## What is the same (portable knowledge)

1. **IP core bring-up order**  
   Assign bases → `LLE_DevInit` → `RFEND_DevInit` → `BB_DevInit` → calibration envelope.

2. **Calibration algorithm shape**  
   Guard/mask clear → force 1M/RX-ish BB envelope → RF on → `LLE` cal mode →  
   `TXCtune` (multi-band CO/GA) → `TXFtune` → `RXFilter` → `RXAdc` → cleanup.

3. **WaitTune completion rule**  
   Success on RFEND status bits 25 **and/or** bit-test style on 25/26, with LLE window expiry as vendor fallback — not “both ready bits hard-required”.

4. **Shared magic that already matched**  
   - `RFEND+0x28 = 0x480` in DevInit  
   - `RFEND+4 \|= 0x100` for TXFtune  
   - RF-on bit class around `RFEND+8` (`0x330000` / clear `0xffcd/ceffff`)  
   - Public symbol surface for RF role / RFIP / PHY mode

5. **NimBLE-side software architecture** from `ch32v208-nimble`  
   Cputime before RF; basic TX/RX + soft IFS; PHY callback model — still the right host/controller split once a CH585 HAL exists.

## What differs (must re-verify / rewrite for CH585)

### Hard blockers if you naively reuse V208 MMIO

| Area | V208 | CH585 |
| --- | --- | --- |
| BB/LLE/AES/RFEND bases | `0x40024xxx` / `0x40025000` | `0x4000Cxxx` / `0x4000D000` |
| BB / LLE IRQ | 63 / 64 | 20 / 21 |
| BLE clock gate API | `RCC_AHBPeriph_BLE_CRC` | CH58x sleep/clk + lib |
| HSE trim API | `OSC->HSE_CAL_CTRL` | `HSECFG_Capacitance` |
| Default SYSCLK | 96 MHz class | 62.4 MHz example |

### Core init table deltas (high signal)

1. **`LLE_DevInit` timeout table**  
   V208 `{0x8C,0x6C,0x8C,0x3C,0x8C,0x3C,0x8C,0x6C}`  
   CH585 `{0x8C,0x76,0x8C,0x6C,0x8C,0x6C,0x8C,0x76}`  
   Guard/mask `+0x0C`: V208 `0xF00F` vs CH585 `0x1F000F`.

2. **`BB_DevInit` constants**  
   Especially `BB+0x34`: V208 `464` vs CH585 `80`, plus CH585-only writes (`+0x3C=0x2020C`, `+0x10` low bits, DevInit IRQSTAT `0x3FF`).

3. **RFEND DevInit body**  
   Shares `+0x28=0x480`, but the rest of the bit soup and reset strategy diverge (V208 explicit `0x1101` reset pulse; CH585 short sequence + delay loop).

4. **VCO calibration coverage**  
   CH585 adds **`nCO2522` / `nGA2522`** (four sample points). WaitTune window is **8000** half-µs vs V208 **6000**.

5. **Stack / OS packaging**  
   CH585EVT path is TMOS + closed `BLE_LibInit`. V208 path is FreeRTOS + Apache NimBLE with open PHY. That is not an RF-register delta, but it changes IRQ ownership, sleep, and periodic cal scheduling.

## Implications for a CH585 open NimBLE port

**Reuse from `ch32v208-nimble`:**

- Overall driver layering (`wch_rf` primitives → `ble_phy` → NimBLE LL)
- Bring-up checklist (clock → cputime → IP clock → DevInits → cal → enable IRQs)
- Debug methodology (serial logs; avoid halt-the-core probes during air traffic)
- Soft-IFS / basic-mode strategy as a starting point

**Do not reuse unchanged:**

- All base addresses and IRQ numbers in `wch_rf.h`
- `lle_dev_init` / `bb_dev_init` literal tables
- Full `wch_rf_analog.c` DevInit + TXCtune (need CH585 re-transcript, including 2522 MHz band)
- HSE/RCC bring-up snippets

**Recommended next verification steps on hardware:**

1. Dump `gptr*` after stock EVT `BLE_LibInit` (confirm `0x4000C100/C200/C300/D000` live).
2. Diff MMIO before/after `BLE_IPCoreInit` and after first `BLE_RegInit` on CH585.
3. Re-lift `RFEND_TXCtune` band codes and nibble writers from `rfend.o` (or live trace).
4. Confirm runtime TX/RX words (`LLE+0x50`, `BB` PHY bits, CRC/RSSI locations) against a known-good ADV air capture — do not assume V208 coded-PHY paths exist identically.

## Short answer

Yes: **the stacks share the same BLE IP family and most of the init *story*.**  
No: **you cannot treat CH585 core init as identical to the CH32V208 open driver.** The differences are concentrated exactly where suspected — base map, IRQ, and a handful of DevInit / calibration constants — and those are enough to break bring-up if ignored.

## Addendum: CH572 / CH583 / CH595 (2026-11-04)

From EVT libs in `~/Downloads` — details in [family-comparison.md](family-comparison.md):

- **Not the same as V208 map.** All four CH5xx parts use `0x4000C100/C200/C300/D000` and IRQ 20/21.
- **Not identical to each other either.** Shared window + symbols; per-SoC `LLE_DevInit` / `BB_DevInit` / WaitTune / VCO tables.
- **CH583 ≈ V208 table literals** (CFG34=`464`, BB `0x800000`/`0x10000000`, mask `0xF00F`, WaitTune `6000`, 3-band, has `RFEND_Reset`).
- **CH585** is the outlier with **`nCO2522`** and WaitTune `8000`.
- **CH572 / CH595** sit in the “new tables” bucket with CH585-like WaitTune `8000`, but without the 2522 band; their LLE/BB constants still need their own HAL tables.
