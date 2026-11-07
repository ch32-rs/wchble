# CH57x / CH58x / CH59x BLE IP family comparison

Date: 2026-11-04  
Sources: EVT zips in `~/Downloads` (`CH572EVT`, `CH583EVT`, `CH585EVT`, `CH595EVT`), objects carved into `wchble/_evt_probe/objs_*` and `wchble/_ch585_objs`.

No CH57xEVT beyond 572, and no CH59x beyond 595, were present in Downloads. Datasheets for CH573/CH587 exist without matching EVT zips here.

## Executive summary

| Question | Answer |
| --- | --- |
| Same as CH32V208? | **No** for MMIO/IRQ. V208 uses `0x40024xxx`; all probed CH57/58/59 use `0x4000Cxxx`. |
| Same as each other? | **Same map window and symbol names; DevInit tables are per-SoC.** |
| Closest to V208 open driver tables? | **CH583** (BB `464`, `\|0x800000`/`\|0x10000000`, LLE mask `0xF00F`, WaitTune `6000`, 3-band VCO, has `RFEND_Reset`). |
| CH585 special? | Yes: **4th VCO band `nCO2522`**, WaitTune `8000`, LLE/BB constants diverge from both V208 and CH583. |

## Memory map / IRQ (all CH57/58/59 probed)

| Chip | SFR BLE window | `BLE_IPCoreInit` bases | BB / LLE IRQ |
| --- | --- | --- | --- |
| CH572 | `+C000H..D3FFH` | BB `0x4000C100`, LLE `0x4000C200`, AES `0x4000C300`, RFEND `0x4000D000` | 20 / 21 |
| CH583 | `+C000H..D3FFH` | same | 20 / 21 |
| CH585 | `+C000H..DFFFH` (wider comment) | same | 20 / 21 |
| CH595 | `+C000H..D3FFH` | same | 20 / 21 |
| **CH32V208** | (different chip family) | BB `0x40024100` … RFEND `0x40025000` | 63 / 64 |

Relative spacing BB→LLE `+0x100`, →AES `+0x200`, →RFEND `+0xF00` is shared across **all** of the above, including V208.

## Core init constants

### `LLE_DevInit` timeout / mask

| Offset | V208 open | CH572 | CH583 | CH585 | CH595 |
| --- | --- | --- | --- | --- | --- |
| `+0x14` | `0x8C` | `0x64` | `0x8C` | `0x8C` | `0x84` |
| `+0x1C` | `0x6C` | `0x6E` | `0x76` | `0x76` | `0x76` |
| `+0x24` | `0x8C` | `0x64` | `0x8C` | `0x8C` | `0x84` |
| `+0x2C` | `0x3C` | `0x64` | `0x3C` | `0x6C` | `0x6C` |
| `+0x34` | `0x8C` | `0x64` | `0x8C` | `0x8C` | `0x84` |
| `+0x3C` | `0x3C` | `0x64` | `0x3C` | `0x6C` | `0x6C` |
| `+0x44` | `0x8C` | `0x64` | `0x8C` | `0x8C` | `0x84` |
| `+0x4C` | `0x6C` | `0x6E` | `0x76` | `0x76` | `0x76` |
| `+0x08` clear | `0xFFFF` | `0xFFFFFFFF` | `0xFFFF` | `0xFFFFFFFF` | `0xFFFFFFFF` |
| `+0x0C` mask | `0xF00F` | `0x16000F` | `0xF00F` | `0x1F000F` | `0x1F000F` |

CH583 is the only CH5xx row that keeps V208’s `0x3C` pair and `0xF00F` mask.

### `BB_DevInit` highlights

| Item | V208 open | CH572 | CH583 | CH585 | CH595 |
| --- | --- | --- | --- | --- | --- |
| `BB+0x34` | `464` (`0x1D0`) | `0x14` | `0x1D0` | `0x50` | `0x50` |
| `BB+0` bit23 / bit28 style | `\|0x800000`, `\|0x10000000` | not same immediates | **same immediates present** | different packing | different |
| `BB+0x20` | `0x90083` | other | `0x90083` | not DevInit | other |
| object size | (source) | 80 B | 180 B | 198 B | 138 B |

### RFEND / calibration

| Item | V208 open | CH572 | CH583 | CH585 | CH595 |
| --- | --- | --- | --- | --- | --- |
| VCO bands | 2401/2440/2480 | 3 | 3 | **3 + 2522** | 3 |
| WaitTune window (half-µs) | 6000 | 8000 | **6000** | 8000 | 8000 |
| `RFEND_Reset` symbol | yes (open `rf_reset`) | no in nm list | **yes** | no | no |
| `RFEND_DevInit` size | (source ~150B table) | 168 | **378** | 152 | 176 |
| `RFEND_TXCtune` size | (source loop) | 3216 | 3388 | 1966 | 3436 |

## Stack packaging notes

| Chip | Closed lib in EVT | Notes |
| --- | --- | --- |
| CH572 | `libCH572BLE_PERI.a` (+ separate `libCH57xRF.a`) | Peripheral-oriented; still has full `BLE_IPCoreInit` / `*_DevInit` |
| CH583 | `libCH58xBLE.a` (+ ROM hex variants) | Closest register tables to V208 RE |
| CH585 | `libCH58xBLE.a` / `_PERI.a` + ROM | Same lib naming as CH583, **different** object contents |
| CH595 | `libCH59xBLE.a` | Same map; LLE/BB closer to CH585 than to CH583 |

Public API naming (`BLE_LibInit`, `BLE_RegInit`, `RF_RoleInit`, TMOS) is shared across the CH57/58/59 EVT style. That does **not** imply identical MMIO constants.

## Practical grouping

Think in three buckets when porting an open controller:

1. **CH32V208-class** — bases `0x40024xxx`, IRQ 63/64, tables as in `ch32v208-nimble`.
2. **CH583-class (CH5xx “old tables”)** — bases `0x4000Cxxx`, IRQ 20/21, DevInit/WaitTune **very close to V208 literals** (still need rebase + re-audit `RFEND_DevInit` body).
3. **CH572 / CH585 / CH595-class (CH5xx “new tables”)** — same `0x4000Cxxx` window, but **per-chip** LLE/BB/WaitTune/VCO; CH585 uniquely adds 2522 MHz band.

“CH57/59 same as CH585?” → **same address window, not the same init tables.**  
“Anyone same as V208?” → **CH583 tables ≈ V208; map still CH5xx.**

## Artifacts

- Extracted libs: `wchble/_evt_probe/{CH572,CH583,CH595}/`
- Per-chip objects: `wchble/_evt_probe/objs_{CH572,CH583,CH585,CH595}/`
- Method mirrors `research-process.md` (ar carve + RV32 const/store recovery).
