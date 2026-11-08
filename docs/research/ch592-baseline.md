# CH592 baseline (CH59x EVT v1.7)

Date: 2026-11-08

`openwch/ch592` EVT v1.7 (`a46e008`) is the reference for the CH591/CH592
family. The BLE controller ships as closed `EVT/EXAM/BLE/LIB/LIBCH59xBLE.a`;
objects were carved into `/tmp/ch592-objs` with the MounRiver GCC 15
`riscv32-wch-elf-*` binutils. This note records what is proven from that
binary, what is still missing, and why CH592 must not alias CH585/CH595.

## Confirmed map

`BLE_IPCoreInit` writes the register base pointers:

| Block | Base |
| --- | --- |
| BB | `0x4000_C100` |
| LLE | `0x4000_C200` |
| AES | `0x4000_C300` |
| RFEND | `0x4000_D000` |
| IRQ | BB `20`, LLE `21` |

Same CH5xx window as CH572/583/585/595; **not** the V208 `0x40024xxx` window.

## DevInit evidence

### `LLE_DevInit` (`lle.o`)

Stores `0x14/0x24/0x34/0x44 = 0x84`, `0x1C/0x4C = 0x76`, and
**`0x2C/0x3C = 0x6E`**, then `+0x08 = 0xFFFFFFFF`, `+0x0C = 0x001F000F`.
The `0x2C/0x3C` pair is `0x6E`, not CH585's carved `0x6C`; do not copy the
CH585 table file.

The `0x84` vs `0x8C` choice is runtime-configurable: the lib loads the signed
byte `ble+0x14` and takes `0x8C` if negative. `BLE_LibInit` memsets the 64-byte
`ble` block and defaults `ble+0x14 = 21`, so a stock SDK build takes the `0x84`
path. The same byte's upper bits gate `RFEND+0x48` bit31.

Other `LLE_DevInit` writes not yet modelled by `LleDevInit`:

- halfword `LLE+0x06 = 0x78`
- `LLE+0x54`: read, OR `0x8000_0000`, write, then write `0x14`
- `LLE+0x7C`: pointer from the lib config block

### `BB_DevInit` (`bb.o`)

- `BB+0 |= 0x0080_0000` (bit23)
- `BB+0x38 = 0xFF`
- `BB+0x34 = 0x50`
- `BB+0x2C |= 0x8000_0000`, then config-byte fields
- `BB+0x3C = 0x0002_020C` (one config branch uses `0x0002_0210`)
- `BB+0x10`: low six bits = `0x0E`
- PFIC enable for IRQ 20 (HAL responsibility)

### `RFEND_DevInit` / calibration (`rfend.o`)

Starts at `RFEND+0x28 = 0x480`, then a dense RMW block (`+0x3C`, `+0x54 = 9`,
`+0x30`, `+0x4C`, `+0x5C`, conditional `+0x48` bit31). No `RFEND_Reset` symbol.
`RFEND_WaitTune` loads `LLE+0x64 = 8000`. `RFEND_TXCtuneSet` uses three bands
(2401/2440/2480); there is no `nCO2522` symbol.

## Runtime evidence (`rf_ip.o`)

`RFIP_SetTx` / `RFIP_SetRx` show the CH592 TX/RX path differs from V208:

| Item | CH592 |
| --- | --- |
| TX DMA pointer | `LLE+0x78` (V208 open: `+0x70`) |
| LLE mode word | `0x0003_0258` (TX); CH585-class bank |
| TX window / IFS halfword | `LLE+0x06 = 0x28`, then `0x78` before start |
| RFEND front end | `RFEND+0x08 \|= 0x0033_0000` |
| Completion clear | `LLE+0x08 = 0x0002_0000` — **not** V208 `0x2000` |
| Start TX | `LLE+0 = 2`; force-stop bit3 when idle bits are set |
| Channel | `RFIP_DevSetChannel`, cached in `gRFIPPara` |

This is enough to conclude **feasible** with a dedicated CH5xx runtime, but a
V208-style `tx_basic`/`rx_basic` cannot be reused unchanged.

## Current state in `wchble`

- `src/rf/family/ch592.rs`: bases, IRQs, LLE/BB/RFEND tables with
  `Certainty::FromClosedDisasm`, and the macro-generated stub backend.
- Feature `ch592` compiles (alone and with `controller,phy`).
- No MMIO apply, calibration, or TX/RX runtime yet; the stub returns
  `Error::Unsupported`.

## Next steps (hardware)

1. Free a CH59x probe (a `probe-rs run --chip CH592 ... pwm_diag` session
   currently holds the board).
2. Add `init`: `LLE_DevInit → RFEND_DevInit → BB_DevInit → cal` plus the
   unmodelled field writes above.
3. Port `RFIP_Calibration` / `RFEND_WaitTune` / `RFEND_TXCtune` (3 bands).
4. Port `RFIP_SetTx`/`RFIP_SetRx` with `LLE+0x78/+0x7C`, mode
   `0x0003_0258`, and the `0x20000` clear-arm bit; validate with a V208-style
   RF smoke firmware.
5. Only then wire SoftRunner/Trouble; keep V208 as the regression gate.

Until step 4 passes, treat CH592 as a **reserved family**, not a working
backend.
