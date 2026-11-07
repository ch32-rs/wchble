# Research process — V208 NimBLE vs CH585EVT BLE init

Date: 2026-11-04  
Scope: core RF/BB/LLE/RFEND bring-up (not host/GATT/TMOS vs NimBLE end-to-end)

## 1. Sources

### CH32V208 (open)

- Tree: `/Users/mono/Repos/ch32v208-nimble`
- Driver: `drivers/wch_ble/{wch_rf.h,wch_rf.c,wch_rf_analog.c,ble_hw_wch.c,ble_phy_wch.c}`
- Bring-up notes: `docs/radio-2026-10-29.md`, `docs/bringup-2026-10-29.md`, `docs/clock-rates.md`
- Origin: register sequences reverse-engineered from WCH `libwchble.a` / `wchble_linked.elf`, reimplemented without TMOS / closed stack

### CH585 (closed EVT)

- Tree: `/Users/mono/WCH/CH585EVT`
- Examples: `EXAM/BLE/Peripheral`, `EXAM/BLE/RF_Basic_Tx`, `EXAM/BLE/HAL/MCU.c`
- Headers: `EXAM/BLE/LIB/{CH58xBLE_LIB.h,CH58xBLE_ROM.h,wchrf.h}`, `EXAM/SRC/StdPeriphDriver/inc/CH585SFR.h`
- Closed objects extracted from `EXAM/BLE/LIB/libCH58xBLE.a` into `wchble/_ch585_objs/`:
  - `bb.o`, `lle.o`, `ip.o`, `rfend.o`, `rf_ip.o`, `aes.o`
- Note: this archive uses trailing-slash member names (`bb.o/`); macOS `ar x` fails, so members were carved with a small Python ar parser.

## 2. Method

1. Map public bring-up call graphs from both sides (example `main` / NimBLE port).
2. Confirm CH585 SFR does **not** publish BB/LLE/RFEND register structs; only IRQ IDs and BLE clock/power bits.
3. `nm` the CH585 static library for RF init symbols; extract the defining objects.
4. Disassemble / const-prop `BLE_IPCoreInit`, `LLE_DevInit`, `BB_DevInit`, `RFEND_*`, `RFIP_*` for:
   - absolute base addresses written into `gptrBBReg` / `gptrLLEReg` / `gptrRFENDReg` / `gptrAESReg`
   - DevInit store tables
   - WaitTune window and ready-bit tests
   - TXCtune sample-band BSS symbols
5. Diff against the open V208 driver tables in `wch_rf.c` / `wch_rf_analog.c`.

No live CH585 RF MMIO capture was done in this pass; CH585 numbers below are from the closed objects + headers/examples.

## 3. Software call graphs

### CH585EVT Peripheral / RF_Basic_Tx (visible C)

```
main
  PWR_DCDCCfg?                      # optional
  HSECFG_Capacitance(HSECap_18p)
  SetSysClock(SYSCLK_FREQ)          # default CLK_SOURCE_HSE_PLL_62_4MHz
  UART debug?
  CH58x_BLEInit()                   # HAL/MCU.c
    SysTick config; PFIC BLEL prio
    g_LLE_IRQLibHandlerLocation = LLE_IRQLibHandler
    fill bleConfig_t (MEM/SNV/MAC/cbs)
    BLE_LibInit(&cfg)               # inside libCH58xBLE.a → opaque
  HAL_Init()
    TMOS_ProcessEventRegister
    HAL_TimeInit / Sleep / LED / KEY
    schedule HAL_REG_INIT_EVENT → BLE_RegInit() periodically
  GAPRole_PeripheralInit / RFRole_Init
  while (1) TMOS_SystemProcess()
```

Opaque inside `BLE_LibInit` (from `ip.o` / `rf_ip.o` symbols and call edges):

```
BLE_LibInit
  … TMOS / heap / host wiring …
  BLE_IPCoreInit
    gptrAESReg  = 0x4000C300
    gptrLLEReg  = 0x4000C200
    gptrRFENDReg= 0x4000D000
    gptrBBReg   = 0x4000C100
    LLE_DevInit / RFEND_DevInit / BB_DevInit   # same names as V208 RE
    NVIC/PFIC enables for BLEB/BLEL
  BLE_RegInit / RFIP_Calibration envelope
    RFEND_TXCtune → RFEND_TXFtune → RFEND_RXFilter → RFEND_RXAdc
```

`RFIP_RegInit` repeats the same four base assignments (used by proprietary RF / DTM paths).

### CH32V208 NimBLE (open)

```
SystemInit (HSE/PLL 72/96/144)
main → FreeRTOS app task → app_ble_start
  nimble_port_init
    hal_timer (TIM3 @ 1 MHz) + os_cputime_init     # before RF
    wch_ble_hw_init
      RCC_AHBPeriph_BLE_CRC enable
      OSC->HSE_CAL_CTRL trim
      wch_rf_init
        lle_dev_init
        wch_rf_analog_dev_init   # RFEND_DevInit(+Reset)
        bb_dev_init
        wch_rf_analog_init       # TXCtune→TXFtune→RXFilter→RXAdc
        enable BB_IRQn / LLE_IRQn
      ble_phy_init
    ble_ll_init / host tasks
```

## 4. Address map evidence

### V208 (open macros)

| Block | Base |
| --- | --- |
| BLE top | `0x40024000` |
| BB | `0x40024100` |
| LLE | `0x40024200` |
| AES | `0x40024300` |
| RFEND | `0x40025000` |
| misc / OSC | `0x40022000` |

IRQ: `BB_IRQn=63`, `LLE_IRQn=64` (CH32V20x SDK).

### CH585 (`BLE_IPCoreInit` / `RFIP_RegInit` immediates)

| Block | Base |
| --- | --- |
| BB | `0x4000C100` |
| LLE | `0x4000C200` |
| AES | `0x4000C300` |
| RFEND | `0x4000D000` |

SFR map comment in `CH585SFR.h`: BLE region `+C000H..DFFFH`.  
IRQ: `BLEB_IRQn=20`, `BLEL_IRQn=21`.

Relative layout is the same family pattern:

- BB + `0x100` → LLE
- BB + `0x200` → AES
- BB + `0xF00` → RFEND

Only the **APB/AHB window base** moved.

## 5. Extracted CH585 DevInit highlights

### `LLE_DevInit` (`lle.o`, 74 bytes)

Stores via `gptrLLEReg`:

| Offset | CH585 value | V208 open value |
| --- | --- | --- |
| `+0x14` | `0x8C` | `0x8C` |
| `+0x1C` | `0x76` | `0x6C` |
| `+0x24` | `0x8C` | `0x8C` |
| `+0x2C` | `0x6C` | `0x3C` |
| `+0x34` | `0x8C` | `0x8C` |
| `+0x3C` | `0x6C` | `0x3C` |
| `+0x44` | `0x8C` | `0x8C` |
| `+0x4C` | `0x76` | `0x6C` |
| `+0x54` | `0` | (not in V208 LLE_DevInit) |
| `+0x08` | `0xFFFFFFFF` | `0xFFFF` |
| `+0x0C` | `0x001F000F` | `0x0000F00F` |

Also RMW on `+0x04` and a store to `+0x7C` (RX buffer / lib-private pointer wiring; needs fuller reloc-aware decode before treating as portable).

### `BB_DevInit` (`bb.o`, 198 bytes)

Notable differences vs V208 open `bb_dev_init`:

| Item | CH585 | V208 open |
| --- | --- | --- |
| `BB+0x34` | `0x50` (80) | `464` (`0x1D0`) |
| `BB+0x38` | written `0x3FF` during DevInit | cleared to `0xF0` after cal in `wch_rf_init` |
| `BB+0x3C` | `0x2020C` | not in V208 DevInit |
| `BB+0x10` | low bits forced to `0xE` (RMW) | not in V208 DevInit |
| `BB+0x2C` | power enum from `ble` cfg, different packing path | enum 9 << 25 over `0x80010EC8` |
| `BB+0` | bit23-oriented RMW | `\|= 0x00800000` then `\|= 0x10000000` |

CH585 `BB_DevInit` also touches PFIC (`0xE000E000`) to unmask BLE vectors.

### `RFEND_DevInit` (`rfend.o`, 152 bytes)

- Starts with `RFEND+0x28 = 0x480` — **same constant** as V208.
- Remaining bit soup diverges (CH585 sequence is shorter; no separate `RFEND_Reset` pulse `0x1101` as in V208 `wch_rf_analog.c`).
- Ends with a ~100-iteration delay loop.

### Calibration symbols (`rfend.o`)

| Symbol | CH585 | V208 open |
| --- | --- | --- |
| `nCO2401/2440/2480` + GA | present | present (3-band) |
| `nCO2522` / `nGA2522` | **present** | **absent** |
| `RFEND_TXCtune` size | 1966 B | transcribed ~3-band loop |
| `RFEND_WaitTune` window | `LLE+0x64 = 0x1F40` (8000 half-µs = 4.0 ms) | `6000` half-µs = 3.0 ms |
| ready test | bits 25 and 26 of `RFEND+0x90` (srli 25/26) | mask `0x06000000` (same two bits) |
| `RFEND_TXFtune` | `RFEND+4 \|= 0x100` | same |
| `RFEND_RXAdc` | pulse on `+0x58/+0x08/+0x0C/+0x04` | same shape |

`BLE_RegInit` / `RFIP_Calibration` envelope in CH585 still does:

1. force BB PHY/DIR for cal
2. `RFEND+8 \|= 0x330000`-class RF-on bits
3. `LLE+0x50` cal mode
4. TXCtune → TXFtune → RXFilter → RXAdc
5. cleanup with `RFEND+8 &= 0xffceffff`-class mask

That matches the V208 `wch_rf_analog_init` structure.

## 6. Platform / clock prerequisites

| Topic | CH585EVT examples | V208 NimBLE |
| --- | --- | --- |
| HSE load | `HSECFG_Capacitance(HSECap_18p)` before `SetSysClock` | `OSC->HSE_CAL_CTRL` bitfields in `wch_rf_init` |
| SYSCLK default | HSE PLL **62.4 MHz** | HSE PLL **96 MHz** (also 72/144) |
| BLE clock gate | `RB_SLP_CLK_BLE` / lib-internal; not the V208 `RCC_AHBPeriph_BLE_CRC` bit recipe | explicit `RCC_AHBPeriphClockCmd(RCC_AHBPeriph_BLE_CRC)` |
| 32 kHz | `CLK_OSC32K` default internal RC; LSI calibration callback | LSI forced off in `main`; no TMOS RTC path |
| Periodic RF cal | TMOS `BLE_RegInit` every `BLE_CALIBRATION_PERIOD` (default 120 s) | `wch_rf_recalibrate()` when LLE idle |
| Timebase for cal polls | lib / SysTick / TMOS | TIM3 `os_cputime` @ 1 MHz **must** precede RF init |

## 7. What stayed opaque

- Full CH585 `RFEND_TXCtune` band-code immediates and 4th-band interpolation (object is large; BSS proves 2522 MHz sample exists).
- Exact CH585 TX/RX arming mode words (`LLE+0x50` values) and RX demod magic groups — not fully re-derived this pass; public headers still expose `LLE_MODE_PHY_1M/2M` and RFIP APIs.
- Whether CH585 coded-PHY BB bits match V208 (V208 open driver has extensive coded support; CH585 public `LLE_MODE_PHY_*` macros in the header only document 1M/2M).

## 8. Artifacts kept here

- `_ch585_objs/*.o` — extracted from `libCH58xBLE.a` for offline diffing (not redistributable as a product; local research copy).
