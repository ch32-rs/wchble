# CH58x BLE reuse — CH583 vs CH585 (and CH587)

Date: 2026-11-07  
Sources: carved objects under `/tmp/wchble-notes-*/_evt_probe/objs_{CH583,CH585}/`,
EVT headers (`CH58xBLE_LIB.h`, `CH583SFR.h`, `CH585SFR.h`), datasheet
`CH587DS1.PDF`. No CH587EVT in Downloads.

## Bottom line

| Question | Answer |
| --- | --- |
| Same BLE IP *map* across CH58x? | **Yes** — BB `0x4000C100`, LLE `+0x100`, AES `+0x200`, RFEND `0x4000D000`, IRQ 20/21 |
| Same DevInit / cal *tables*? | **No** — CH583 ≠ CH585 |
| Can one `family/ch58x.rs` serve both? | **No** — keep `ch583` and `ch585` separate modules |
| What *is* reusable above RF? | Soft HCI / LL / PHY / `rf::regs` offsets / `Radio` trait |
| Closest open-driver tables? | **CH583 ≈ V208**; CH585 is the divergent “new tables” part |
| CH587? | Datasheet has BLE 5.4; **no EVT here** → tables unknown |

Marketing / lib naming is misleading: both ship `libCH58xBLE.a` and
`CH58xBLE_LIB.h`, but the **object contents differ**.

## Shared (safe to assume family-common)

| Item | CH583 | CH585 |
| --- | --- | --- |
| SFR BLE window comment | `+C000H..D3FFH` | `+C000H..DFFFH` (wider comment; bases still same) |
| BB / LLE / AES / RFEND bases | `0x4000C100` / `C200` / `C300` / `D000` | same |
| Relative spacing | +0x100 / +0x200 / +0xF00 | same |
| IRQ | BLEB=20, BLEL=21 | same |
| Core symbols | `BLE_IPCoreInit`, `LLE_DevInit`, `BB_DevInit`, `RFEND_*`, `BLE_RegInit` | same names |
| Bring-up order | LLE → RFEND → BB → TXCtune → TXFtune → RXFilter → RXAdc | same |
| `RFEND+0x28 = 0x480` | yes | yes |
| Ready poll bits on `RFEND+0x90` | bits 25+26 class | same class (`bexti` 0x19/0x1a) |

For `wchble`: one CH5xx **map** helper (bases + IRQ) is fine; **tables are not**.

## Not shared (must be per-SoC)

### Object footprint

| Object | CH583 | CH585 |
| --- | --- | --- |
| `lle.o` | 4364 B | 2108 B |
| `bb.o` | 3312 B | 3396 B |
| `rfend.o` | 11132 B | 9056 B |
| `ip.o` | 19108 B | 21860 B |
| Extra | — | `rf_ip.o` (10504 B) with `RFIP_*` |

### `LLE_DevInit` (re-disassembled)

| Offset | CH583 | CH585 | V208 open |
| --- | --- | --- | --- |
| `+0x14` | `0x8C` | `0x8C` | `0x8C` |
| `+0x1C` | `0x76` | `0x76` | `0x6C` |
| `+0x24` | `0x8C` | `0x8C` | `0x8C` |
| `+0x2C` | **`0x3C`** | **`0x6C`** | `0x3C` |
| `+0x34` | `0x8C` | `0x8C` | `0x8C` |
| `+0x3C` | **`0x3C`** | **`0x6C`** | `0x3C` |
| `+0x44` | `0x8C` | `0x8C` | `0x8C` |
| `+0x4C` | `0x76` | `0x76` | `0x6C` |
| `+0x08` clear | `0xFFFF` (`lui 0x10; addi -1`) | `0xFFFFFFFF` | `0xFFFF` |
| `+0x0C` mask | **`0xF00F`** | **`0x1F000F`** | `0xF00F` |
| `+0x54` | — | `0` | — |
| `+0x74` RX ptr | yes (reloc) | uses `+0x7C` path | V208 `+0x74` |
| PFIC unmask in LLE | yes (`0xE000E000`) | no (in BB path) | HAL/NVIC |

CH583 keeps the V208-style `0x3C` pair and `0xF00F` guard mask. CH585 does not.

### `BB_DevInit` highlights

| Item | CH583 | CH585 | V208 open |
| --- | --- | --- | --- |
| `BB+0` bit23 / bit28 style | `\|= 0x800000`, `\|= 0x10000000` | `bseti` bit23 only in this path | same as CH583 |
| `BB+0x34` | **`0x1D0` (464)** | **`0x50` (80)** | `464` |
| `BB+0x20` | `0x90083` | not written here | `0x90083` |
| `BB+0x38` | — | `0x3FF` | post-cal `0xF0` in open init |
| `BB+0x3C` | — | `0x2020C` | — |
| `BB+0x10` low nibble | — | force `0xE` | — |

### RFEND / calibration

| Item | CH583 | CH585 |
| --- | --- | --- |
| `RFEND_Reset` | **present** (calls into DevInit) | **absent** |
| `RFEND_DevInit` size | `0x17a` (~378 B) | `0x98` (152 B) |
| VCO BSS | `nCO2401/2440/2480` | those **+ `nCO2522`** |
| `RFEND_TXCtune` size | `0xd3c` (~3388 B) | `0x7ae` (~1966 B) |
| `WaitTune` window (LLE+0x64) | **6000** (`0x1770`) | **8000** (`0x1f40`) |
| `RFEND_SetSensitivity` | real body | effectively stub (`ret`-sized) |

## Public C API vs RF tables

Both EVT trees brand the closed stack as **CH58x** (`CH58xBLE_LIB.h`,
`libCH58xBLE.a`). That means:

- Host/TMOS-facing symbol *names* look related.
- It does **not** mean RF DevInit immediates are interchangeable.
- CH585 adds a larger RFIP surface (`rf_ip.o`: `RFIP_RegInit`,
  `RFIP_SetTx` / `SetRx`, `RFIP_Calibration`, …) that CH583’s carved RF
  objects do not expose the same way.

For Path B we do **not** wrap that closed API; we only care that the
underlying IP map is shared and the tables are not.

## CH587 / other CH58*

| Part | In Downloads | BLE? | Tables |
| --- | --- | --- | --- |
| CH583 | EVT + DS | yes | extracted — “old tables” |
| CH585 | EVT + DS | yes | extracted — “new tables” + `nCO2522` |
| CH587 | DS only | yes (BLE 5.4 / 1M+2M per DS) | **unknown** until EVT objs |
| CH582/584/… | not present | — | — |

Until a CH587EVT `libCH58xBLE.a` (or equivalent) is carved, do **not**
alias CH587 to either CH583 or CH585.

## Implication for `wchble`

```text
Reusable across CH58x (+ V208 above RF):
  hci / ll / phy / rf::regs offsets / Radio trait / bring-up order

Per chip module (cfg feature):
  bases+IRQ (CH5xx shared constants OK to duplicate or tiny helper)
  LLE_DevInit table
  BB_DevInit table
  RFEND_DevInit (+ Reset if present)
  WaitTune constant
  TXCtune band list (3 vs 4)
```

Recommended feature modules (already the locked layout):

- `ch32v208` — open golden path
- `ch583` — CH5xx map + near-V208 tables (scaffold when needed)
- `ch585` — CH5xx map + new tables / `nCO2522` (stub bases done)

Do **not** invent a single `ch58x` backend that switches on runtime chip id
for DevInit — wrong table bricks RF bring-up. HALs already select one chip
feature at compile time (`ch5xx-hal`’s `ch583` / `ch585`); mirror that.
