# Init diff table — CH32V208 open driver vs CH585 `libCH58xBLE.a`

Values for V208 come from `/Users/mono/Repos/ch32v208-nimble/drivers/wch_ble/`.  
Values for CH585 come from disassembly of extracted `libCH58xBLE.a` objects in `_ch585_objs/`.

Legend: **same** = treat as family-shared; **diff** = must change for a CH585 port; **unk** = not fully proven this pass.

## Memory map / IRQ

| Item | V208 | CH585 | Verdict |
| --- | --- | --- | --- |
| BB base | `0x40024100` | `0x4000C100` | **diff** |
| LLE base | `0x40024200` | `0x4000C200` | **diff** |
| AES base | `0x40024300` | `0x4000C300` | **diff** |
| RFEND base | `0x40025000` | `0x4000D000` | **diff** |
| BB→LLE spacing | `+0x100` | `+0x100` | **same** |
| BB→AES spacing | `+0x200` | `+0x200` | **same** |
| BB→RFEND spacing | `+0xF00` | `+0xF00` | **same** |
| BB IRQ | 63 | 20 (`BLEB`) | **diff** |
| LLE IRQ | 64 | 21 (`BLEL`) | **diff** |

## Bring-up order

| Step | V208 open | CH585 closed | Verdict |
| --- | --- | --- | --- |
| CPU clock | HSE PLL 72/96/144 | HSE PLL 62.4 (default example) | **diff** (platform) |
| HSE pad trim | `OSC->HSE_CAL_CTRL` | `HSECFG_Capacitance(18p)` | **diff** API, same intent |
| BLE clock enable | `RCC_AHBPeriph_BLE_CRC` | sleep/clk bits + lib | **diff** |
| Cputime before RF | required (TIM3) | TMOS/SysTick inside lib | **diff** plumbing |
| IP core order | LLE → RFEND → BB → cal | `BLE_IPCoreInit` same names/order | **same** |
| Periodic cal | `wch_rf_recalibrate` | TMOS → `BLE_RegInit` | **same** idea |

## `LLE_DevInit`

| Offset | V208 | CH585 | Verdict |
| --- | --- | --- | --- |
| `+0x14` | `0x8C` | `0x8C` | **same** |
| `+0x1C` | `0x6C` | `0x76` | **diff** |
| `+0x24` | `0x8C` | `0x8C` | **same** |
| `+0x2C` | `0x3C` | `0x6C` | **diff** |
| `+0x34` | `0x8C` | `0x8C` | **same** |
| `+0x3C` | `0x3C` | `0x6C` | **diff** |
| `+0x44` | `0x8C` | `0x8C` | **same** |
| `+0x4C` | `0x6C` | `0x76` | **diff** |
| `+0x08` clear | `0xFFFF` | `0xFFFFFFFF` | **diff** (width) |
| `+0x0C` mask/guard | `0xF00F` | `0x1F000F` | **diff** |
| `+0x54` | — | `0` | **diff** / CH585-only |
| RX DMA prog | `+0x74` = buffer addr | store involving `+0x7C` path | **unk/diff** |

## `BB_DevInit`

| Item | V208 | CH585 | Verdict |
| --- | --- | --- | --- |
| `BB+0` init bits | `\|=0x800000`, `\|=0x10000000` | RMW around bit23 path | **unk/diff** |
| `BB+0x34` | `464` | `80` | **diff** |
| `BB+0x2C` power | enum 9 in bits[30:25] | cfg-driven packing | **diff** details |
| `BB+0x20` | `0x90083` | not same DevInit write | **diff** placement |
| `BB+0x38` | post-init `0xF0` | DevInit `0x3FF` | **diff** |
| `BB+0x3C` | — | `0x2020C` | **diff** / CH585-only |
| `BB+0x10` | — | low nibble → `0xE` | **diff** / CH585-only |

## RFEND analog

| Item | V208 | CH585 | Verdict |
| --- | --- | --- | --- |
| `RFEND+0x28 = 0x480` | yes | yes | **same** |
| Reset pulse `+0x0C=0x1101` | yes (`rf_reset`) | not in short DevInit | **diff** |
| Rest of DevInit bit soup | long table in `wch_rf_analog.c` | shorter divergent table | **diff** |
| VCO bands | 2401 / 2440 / 2480 | + **2522** (`nCO2522`) | **diff** |
| WaitTune window | 6000 half-µs | 8000 half-µs | **diff** |
| Ready bits | `RF+0x90` bits 25+26 | same two bits | **same** |
| TXFtune `+4 \|= 0x100` | yes | yes | **same** |
| RXFilter / RXAdc shape | yes | yes | **same** |
| Cal envelope `RF+8` on/off | `0x330000` / `0xffcdffff` | same class (`0xffceffff` seen) | **same**/minor |
| `LLE+0x50` cal mode | `0x5D` | used in cal envelope | **same** class |

## CH592 deviations (verified on silicon 2026-11-08)

CH592 uses the CH5xx window but its BLE-stack runtime is **not** the V208 one
(see `ch592-baseline.md`):

| Item | V208 | CH592 | Verdict |
| --- | --- | --- | --- |
| TX / RX DMA pointer | `LLE+0x70` / `LLE+0x74` | `LLE+0x78` / `LLE+0x7C` | **diff** |
| TX / RX mode word `LLE+0x50` | `0x5A` / `0x59` | `0x30258` / `0x30158` | **diff** |
| Idle / post-init `LLE+0x50` | — | `0x30` / `0x30000` | **diff** |
| CRC enable `LLE+0x04` bit0 | clear | set | **diff polarity** |
| Arm-clear bit in `IRQSTAT` | `0x2000` | `0x20000` | **diff** |
| W1C guard `LLE+0x0C` | bits 12..16 | **bit 17** (`!CLEAR_ARM`) | **diff** |
| Channel select | BB channel table | `BB+0[6:0]` + `BB+0x5C[8:0]`, no `RFEND+0x44` | **diff** |
| RFEND analog `+0x3C` | table | RMW `0x5000` into bits 12..15 | **diff** |
| RFEND analog `+0x30` | table | `\|= 0x7000` | **diff** |
| TX window | open table | 1M `16*(len+10)+316` half-µs | **diff** |

Lesson: an `OK` TX completion is not proof of radiation — CH592 reported
`TX_DONE` exactly at window expiry while the analog front end was misconfigured.
Always verify with a second receiver.

Lesson (CH585, 2026-11-09): vendor disassembly RMWs read `w & ~field | value`,
but `regs::rmw(base, off, clear, set)` computes `v & !clear | set`. Passing the
vendor's AND mask as `clear` inverts the update. Three such sites
(`RFEND+0x3C`, `RFEND+0x5C`, `BB+0x2C`) silently destroyed the analog config and
broke VCO calibration (all bands returned the same code, VCOTAB stayed zero)
while `TX_DONE` still fired. Convert `w & M | v` to `clear = !M`.

## TX/RX runtime (recovered from the CH585 objects)

Recovered 2026-11-09 from `ip.o` (`RFIP_SetTx` / `RFIP_SetRx` /
`BLE_SetPHYTxMode` / `BLE_SetPHYRxMode` / `phy_status_clear` /
`ble_ll_hw_api_shut`), `ll_advertise.o` (`ll_advertise_tx`) and
`ll_scan.o` (`LL_ScanSetRF`). Implemented in `src/rf/family/ch585.rs`.

| Item | V208 open (proven) | CH585 closed | Verdict |
| --- | --- | --- | --- |
| Engine cmd `LLE+0` | RX=1, TX=2, stop `\|8` | same (`RFIP_SetTx/Rx`, `ble_ll_hw_api_shut`) | **same** |
| Mode word `LLE+0x50` | TX=`0x5A`, RX=`0x59` | TX=`0x30258`, RX=`0x30158`, INIT=`0x30558`, POST=`0x30000` | **diff** |
| PHY bits in `BB+0` | 1M=`0x1000`, 2M=`0` | bit7: 2M set, 1M clear | **diff** |
| LLE halfword `+0x06` | — | `2` from `LLE_DevInit`/`RFIP_SetRx` | **diff** |
| TX DMA ptr | `+0x70` | `+0x78` | **diff** |
| RX DMA ptr | `+0x74` | `+0x7C` | **diff** |
| TX trigger | BB bit23 then `CMD=2` | `BB+0 \|= 0x00800000`, `BB+0x2C &= ~3`, `LLE+0 = 2` | **diff** |
| TX window | open table | `2*((len<<3)+adj+0xEE)` 1M / `2*((len<<2)+adj+0xCA)` 2M | **same** as `v208_tx_window_half_us` with `adj=0` |
| RX window reload | open table | `16*(len+5)+0x3C` 1M / `8*(len+5)+0x3C` 2M | **same** as `v208_rx_capture_reload_half_us` |
| TX completion | `IRQSTAT` bit1 | soft flags from `IRQSTAT` bits 3\|1 (`ll_tx_wait_finish` also waits `LLE+0x64`) | **same shape** |
| RX completion | `IRQSTAT` bit0 | `IRQSTAT` bits 0\|2 | **same shape** |
| Arm-clear | `0x2000`, guard bit13 | `0x20000`, guard bit17 of `LLE+0x0C` | **diff** |
| CRC enable | opposite polarity | `LLE+0x04` bit0 set | **diff** |
| Channel select | BB channel table | `BB+0[6:0]` + `BB+0x5C[8:0]`, no `RFEND+0x44` | **diff** |
| Soft IFS vs auto sequencer | soft IFS preferred | lib supports auto/basic LLE modes | product choice |

Silicon verification (2026-11-09, `examples/ch585-rf-smoke`): the `0x6C` LLE
DevInit pair, `LLE+0x06 = 2` and `LLE+0x54 = 0` read back as tabulated; RX
reported packets with `crc=true`, and macOS saw `wch585`. `BB+0x38 = 0x3FF`
is a W1C initialization write, not a readback assertion. Calibration tables
were populated and broadly resembled the vendor capture, but some words
differed. The early elapsed-time log used reversed subtraction and did not
measure air-interface timing.

