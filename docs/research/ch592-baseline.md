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

Other `LLE_DevInit` writes, now modelled in `ch592.rs`:

- halfword `LLE+0x06 = 0x78`
- `LLE+0x54`: read, OR `0x8000_0000`, write, then write `0x14`
- `LLE+0x7C`: RX DMA pointer (`rx_basic` programs it from the aligned scratch)

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

## Runtime evidence (`rf_ip.o`, `ll_advertise.o`, `bb.o`)

The BLE-stack path (`ll_advertise_tx` / `LL_ScanSetRF` / `BLE_SetPHYTxMode`)
differs from the standalone-RF `RFIP_*` path in `rf_ip.o`:

| Item | BLE stack (TX / RX) | `RFIP_SetTx` / `RFIP_SetRx` |
| --- | --- | --- |
| TX DMA pointer | `LLE+0x78` (V208 open: `+0x70`) | same |
| RX DMA pointer | `LLE+0x7C` | same |
| Mode word `LLE+0x50` | TX `0x0003_0258`, RX `0x0003_0158`, idle `0x30`, post-init `0x30000` | same bank |
| Pre-arm window | `LLE+0x64 = 0x78`, spin until 0 | `RFIP_SetRx` writes `LLE+0x06 = 4` |
| TX window | 1M `16*(len+10)+316` half-µs; 2M `8*(len+11)+316` | — |
| CRC enable | `LLE+0x04 \|= 1` (**opposite polarity from V208 open**) | same |
| Channel | `BB+0[6:0]` (high bits kept), `BB+0x5C[8:0]` | `RFIP_DevSetChannel` also programs `RFEND+0x44` fractional synth |
| RF on | `RFEND+0x08 \|= 0x0033_0000` | same |
| Completion clear | `LLE+0x08 = 0x0002_0000` — **not** V208 `0x2000` | same |
| Start TX / RX | `LLE+0 = 2` / `1`; force-stop bit3 when idle bits are set | same |

The **BLE** path never writes `RFEND+0x44`: it clears `RFEND+0x2C` bit1
(fractional-synth enable) and selects the carrier through `BB+0[6:0]` alone.
Only `RFIP_DevSetChannel` enables the fractional synth.

### W1C guard bit (`LLE+0x0C` bit 17)

`BLE_SetPHYTxMode` clears bit 17 of `LLE+0x0C` around the `IRQSTAT` write and
restores it afterwards. Bit 17 shadows `IRQSTAT`'s `CLEAR_ARM` bit: **writing
`IRQSTAT` while guard bit 17 is set is silently dropped**. Reusing V208's
numeric mask (`0xfffe_0fff`, bits 12..16) instead of `!CLEAR_ARM` leaves the W1C
effective-nothing and the next `tx_basic` sees a stale `LLE+0x00` command and
returns `Busy`.

### `RFEND_DevInit` analog fields

Two RMW values were mis-recovered from `lui`/`addi` pairs:

- `RFEND+0x3C`: the value is a **4-bit field at bits 12..15** (`0x0000_5000`),
  not bit 16 (`0x0005_0000`).
- `RFEND+0x30`: `|= 0x0000_7000` (bits 12..14), not `|= 0x7`.

Both sit in the RF analog configuration. Before the fix the front end never
tuned: `TXCtune` CO/GA read back constant (`30/127` for every band) and TX
completed exactly at window expiry because the radio never keyed. After the
fix `TXCtune` reads differ per band (`2401=36/57 2440=30/55 2480=24/52`) and
ADV_IND is decoded by a second receiver.

## Hardware status (2026-11-08)

Verified on `1a86:8010:F93D8F067E10` (SDI `/dev/cu.usbmodemF93D8F067E102`):

- `rf init ok`; DevInit markers read back (`LLE 06=78 14=8c 2c=6e 3c=6e
  0c=1f000f`, `BB 34=50`).
- `tx ch{37,38,39} ok`; a CH32V208 reference receiver decodes the ADV_IND with
  `crc=true`, and macOS CoreBluetooth reports `wch592` at RSSI ≈ −43 dBm.
- The vendor `RF_PHY` reference frame (`01 02 .. 00`, AA `0x71764129`,
  CRC `0x555555`, ch 39) is decoded by the V208 at ≈ −52…−76 dBm.
- RX: the CH592 decodes ADV_IND from the V208 transmitter and from nearby
  third-party advertisers with `crc=true` (bits 0/2 of `LLE+0x08`).

Caveat: macOS CoreBluetooth reports a sparse advertiser sporadically (scan
window vs. interval). Absence from one short scan is not evidence; use a second
WCH receiver (`crc` bit) or a dense test interval for proof.

## Next steps

1. Wire SoftRunner → `tx_basic` for CH592 (the RF layer now matches V208
   semantics; `examples/ch592-rf-smoke` is the board gate).
2. Auto-ack / `auto_arm_rx` / IFS turnaround (SCAN_RSP, connections).
3. Recover the per-chip TX-power table (`BB+0x2C[30:25]` enum, `RFEND+0x04`
   `TXFTUNE` pulse) and 2M / Coded PHY windows.

