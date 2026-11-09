# Progress

Last updated: 2026-11-09

## Done

- Replaced closed-lib bindgen crates (`ch32v20x-ble` / `ch57x-ble` / `ch58x-ble` /
  `ch59x-ble` / old `wchble` facade) with a single `wchble` Path B crate.
- Module layout: `rf` / `phy` / `ll` / `hci` / `time`; HAL-extension framing
  (consumed by `ch32-hal` / `ch5xx-hal`, no in-repo firmware/linker).
- Chip features + `Backend`:
  - `ch32v208` — DevInit + cal + **channel / shut / tx_basic / rx_basic / ISR**
    (open `wch_rf`)
  - `ch572` — CH5xx map + unique new-table set (`0x64` / `0x16000F` / BB `0x14`)
  - `ch583` — CH5xx map + closed-disasm “old tables” (≈V208)
  - `ch585` — CH58x EVT disasm: `0x6C` LLE pair / `BB+0x38=0x3FF` /
    3-band interpolation + measured 2522 band; **DevInit + cal + channel /
    shut / tx_basic / rx_basic on air**, gate `examples/ch585-rf-smoke`
    (see the CH585 entry below)
  - `ch592` — CH59x EVT v1.7 disasm: `0x6E` LLE pair / `BB+0x38=0xFF` /
    TX DMA `+0x78` / clear-arm `0x20000`; **DevInit + cal + channel / shut /
    tx_basic / rx_basic on air** (see the CH592 entry below)
  - `ch595` — CH5xx map + near-CH585 tables without `nCO2522` (`0x84` highs)
- Shared table shapes + `Certainty` tags in `src/rf/family/tables.rs`.
- Soft HCI Phase A: `bt-hci` 0.11 `ExternalController` + bounded embassy
  channels (`hci::transport`) + `SoftRunner` Phase A cmd set (Reset /
  ReadBdAddr / masks / LE buffer / legacy adv stubs). Host unit tests cover CC path.
- Soft HCI Phase B (state): `AdvState` stores AdvData/ScanRsp/channel map;
  SoftRunner helpers `build_adv_pdu` / `adv_channels` / `adv_interval_us`;
  host unit test `le_set_adv_data_builds_pdu`.
- **Board gate (V208)** — `examples/ch32v208-rf-smoke` flashed on
  `CH32V208WBU6` (`1a86:8010:2FC48F06B4A8`); SDI confirmed
  `rf init ok` + eight `tx ch37 ok` + `smoke done` at HCLK 96 MHz
  (32 MHz HSE /4 ×12). Fixes needed on the way: 4-byte-aligned RX DMA
  wrapper (plain `StaticCell<[u8;N]>` landed at +1), non-blocking
  `try_println`, and PLL clock instead of default 8 MHz HSI.
- **Phase 2 RF verify (V208)** — same probe; SDI confirmed DevInit dump
  (LLE `14/1c/2c/3c` + BB `34` match; RFEND `28=0x1480` has sticky high
  bit over DevInit `0x480`), TX on **37/38/39**, RX arm + live `rx hit`,
  SoftRunner ADV_IND → `tx_basic` on all three channels, `smoke done`.

- Thin MMIO helpers (`regs::{read,write,rmw}`) + RFEND/AES offset map +
  `rf::timing` pure helpers.
- Research notes under `docs/research/` (incl. `ch58x-reuse.md`,
  `ch58x-hal-ble-reuse.md`, `bringup-debug.md`); architecture + HAL boundary in
  `docs/architecture.md`.
- **`docs/pitfalls.md`** — consolidated bring-up invariants and false-green
  traps (W1C completions, DMA alignment, AdvA seeding, quiet TX, probe-rs).
- **Cleanup pass (2026-11-08)** — shared `rf::txrx::DmaBuf` replaces four local
  `#[repr(align(4))]` wrappers; the TX bounce buffer is a radio field instead
  of a per-call stack object; CH5xx stub backends are macro-generated;
  one-hot `family` cfg is single-source; own-address assignment is centralized
  (`sync_adv_addr`). Corrected the AdvA note: the pinned Trouble *does* send
  HCI 0x2005 after Reset. Re-verified on
  `1a86:8010:2FC48F06B4A8`: SDI `tx0` ≈ 258 µs on 37/38/39 and macOS
  CoreBluetooth `FOUND wchble rssi=-46`.
- `cargo check` clean for each single chip feature (+ `controller,phy`),
  including `riscv32imac-unknown-none-elf` for `ch32v208`.

- **Trouble join (V208)** — `examples/ch32v208-trouble-adv` Embassy app joins
  SoftRunner HCI pump + Trouble Host runner + AdvRadio TX; SDI confirmed
  `rf init ok` / `hci host up` / `adv enable` / `tx ongoing` /
  `trouble adv running` on the same probe. Uses a local `embassy-rs/trouble`
  checkout (crates.io 0.8.0 still pins bt-hci 0.10; main is 0.11).
- **AdvA / random address** — the pinned Trouble `ControlRunner::run` already
  sends HCI `LE Set Random Address` (0x2005) after `Reset` when
  `StackBuilder::set_random_address` was used. `SoftRunner::set_random_addr`
  remains as a HAL fallback (re-applied across Reset); the example wires one
  `RAND_ADDR` into both sides and uses a valid static-random MSB (`0xC1`).
  Unit test `set_random_addr_survives_reset` covers the Reset path.
- **Quiet TX path** — `controller_task` prints nothing per channel/per burst
  (SDI on the TX path stretches the adv interval; `try_println` only on
  `adv enable` / first burst / one-shot PDU dump).
- **Nimble reference baseline** — sibling `ch32v208-nimble` built locally with
  the MounRiver GCC 15 toolchain
  (`/Applications/MounRiver Studio 2.app/.../RISC-V Embedded GCC15`) and a
  sibling `apache/mynewt-nimble` checkout; needed
  `MYNEWT_VAL_BLE_SM_MIN_KEY_SIZE (7)` in its `syscfg_overrides.h` for current
  upstream NimBLE. This is the known-good on-air reference for macOS
  `tools/macos-ble` scans, not our firmware.
- **CH592 feasibility (2026-11-08)** — `openwch/ch592` EVT v1.7 (`a46e008`)
  and `LIBCH59xBLE.a` carved; bases/IRQs confirmed; LLE `0x6E` pair,
  `BB+0x38=0xFF`, TX DMA `+0x78`, clear-arm `0x20000` recorded. `ch592`
  feature + stub backend compile; details in
  `docs/research/ch592-baseline.md`. On-air bring-up pending a free CH59x
  probe (a `probe-rs ... pwm_diag` session currently holds the board).
- **CH592 backend on air (2026-11-08)** — `src/rf/family/ch592.rs` now applies
  `LLE_DevInit → RFEND_DevInit → RFEND_TXCtune → BB_DevInit` and implements
  `channel / shut / tx_basic / rx_basic` for the BLE-stack path. Board gate
  `examples/ch592-rf-smoke` on `1a86:8010:F93D8F067E10`:
  `rf init ok` / `tx ch{37,38,39} ok` / `rx loop hit … crc=true` / `adv loop`.
  Independent proof: a CH32V208 reference receiver decodes the CH592 ADV_IND
  with `crc=true`, macOS CoreBluetooth sees `wch592` at ≈ −43 dBm, and the
  CH592 decodes the V208 (and third-party) ADV_IND with `crc=true`.
  Two bugs cost the session:
  - `IRQSTAT` W1C is gated by `LLE+0x0C` **bit 17** (clear it around the write;
    V208's bits 12..16 mask is wrong and made `tx_basic` see a stale `Busy`).
  - `RFEND_DevInit` transcription: `RFEND+0x3C` is a 4-bit field at bits 12..15
    (`0x5000`) and `RFEND+0x30 |= 0x7000`; the earlier recovery (`0x0005_0000`)
    left the analog front end off (TX "completed" at window expiry, TXCtune
    constant per band). Details in `docs/research/ch592-baseline.md`.
    Committed 2026-11-09 on branch `ch592-rf-bringup`.

- **CH585 backend landed (2026-11-09)** — `src/rf/family/ch585.rs` is no longer
  a stub: `LLE_DevInit` (`0x6C` pair, `+0x04 &= 0xFFFF_FFE1`, halfword `+0x06 =
  2`, `+0x54 = 0`), the CH585 `RFEND_DevInit` RMW block, `BB_DevInit`
  (`BB+0x38 = 0x3FF`, `BB+0x3C = 0x0002_020C`), 4-band `TXCtune`
  (`bf/e8/d4/fc`, the 2522 sample measured but unused for interpolation),
  `RXFilter` arming `TUNE` bit 12, and the `channel / shut / tx_basic /
  rx_basic` runtime recovered from `RFIP_SetTx/SetRx`, `ll_advertise_tx`,
  `LL_ScanSetRF` and `ll_tx/rx_wait_finish`. Board gate
  `examples/ch585-rf-smoke` carries its own RAM console because `ch5xx-hal`'s
  `SDIPrint` is still CH592-only and the LinkE does not drain the CH585 debug
  window.
  **Verified on air 2026-11-09**: LLE readback included `06=2 / 2c=6c /
  3c=6c / 54=0`; RX decoded nearby packets with `crc=true` and macOS
  CoreBluetooth saw `wch585` at −44 dBm. The BB `0x38=0x3ff` value is a W1C
  write, not a readback assertion. Calibration tables were populated and
  broadly resembled the vendor capture, but some words differed. The earlier
  TX elapsed-time log subtracted backwards and does not establish airtime.
  The chip must be **power-cycled after flashing** (`wlink set-power
  disable3v3/enable3v3`) — the LinkE's post-flash reset leaves the BLE block
  idle. `rf::new_radio_with_dma` now treats `ch585` like
  `ch32v208`/`ch592` (RX DMA scratch required). V208 + CH592 builds and host
  tests unchanged.
- **CH585 DevInit mask semantics** — the last blocker before on-air was three
  `rmw` calls that passed the vendor's AND masks (`0xF8FFFFFF`, `0x81FFFFFF`)
  where `regs::rmw(base, off, clear, set)` expects a *clear* mask, inverting
  the intended field update on `RFEND+0x3C`, `RFEND+0x5C` and `BB+0x2C`. VCO
  tuning then produced identical per-band codes and a zero VCOTAB. Corrected
  to clear masks (`0x0700_0000`, `0x7e00_0000`) and documented in
  `docs/research/init-diff-table.md`.

- **TX DMA alignment (V208)** — the LLE reads `TXBUFPTR` as a DMA word
  address. The open driver in `ch32v208-nimble` always passes a
  `__attribute__((aligned(4)))` TX buffer (`g_ble_phy_tx_buf`), while our
  examples passed a stack `[u8; 40]` whose alignment is not guaranteed (the RX
  DMA already needed an aligned wrapper for the same reason).
  `Ch32v208Radio::tx_basic` now bounces unaligned frames through an internal
  `#[repr(align(4))]` buffer before programming `TXBUFPTR`. (Hardening; the
  actual visibility root cause was the sticky `TX_DONE` bit below.)

## Solved: macOS visibility (2026-11-08)

Root cause: LLE `IRQSTAT` (`LLE+0x08`) is W1C and `TX_DONE` (bit1) is sticky.
`tx_basic` only cleared the window with `CLEAR_ARM` (0x2000) and then polled
`TX_DONE`, so from the second transmission on it saw the **previous** packet's
completion and returned `Ok` without transmitting. Only the very first packet
(real airtime ~262 µs) ever reached the air; all later "TX ok" results were
false positives. Confirmed by first-burst timing: `ch37 us=262` vs
`ch38 us=12`.

Fix: clear the sticky bits explicitly (`IRQSTAT = TX_DONE` / `RX_DONE`) before
arming in `tx_basic` / `rx_basic`, and acknowledge `TX_DONE` after consuming it.

**Read [`docs/pitfalls.md`](pitfalls.md) before touching RF/LL/HCI** — it
collects this false-green class (sticky W1C bits, DMA alignment, AdvA seeding,
quiet TX path, probe-rs halting the core) with detection heuristics.

Verified on `1a86:8010:2FC48F06B4A8`:
- TX counters: 374 bursts / 1122 `tx_basic` successes, all three channels.
- macOS CoreBluetooth: `seen name=wchble rssi=-54`, `FOUND wchble`
  (`examples/ch32v208-trouble-adv/tools/scan_wchble.swift`).

The same class of bug cannot affect the NimBLE reference (its LLE ISR clears
`TX_DONE`), but the freshly built `ch32v208-nimble` still stops advertising
after ~7 events in this RF environment; that observation is kept in
`docs/research/nimble-baseline.md` and is no longer blocking.

## Not done (next)

1. Auto-ack / `auto_arm_rx` / IFS turnaround (needed for SCAN_RSP / conn events).
2. Soft HCI + Trouble BAS peripheral (Phase C) — accept connection + GATT.
3. SoftRunner → `tx_basic` on CH585/CH592, then auto-ack/IFS for the other
   CH5xx parts. (The CH585 silicon gate is **done**: init, DevInit markers,
   `tx ch37/38/39`, RX `crc=true`, and `wch585` seen by macOS.)
4. Remaining CH5xx (CH572/CH583/CH595) still have tables only; apply
   DevInit/cal + runtime per chip (do not share the CH585 table).
5. **TODO: CH587** — DS mentions BLE 5.4; no CH587EVT / carved `libCH58xBLE`
   here yet (may still be unpublished by WCH). Do **not** alias to CH583/CH585.
   Other CH57/58 without carved libs stay out of tree.
6. Pin `trouble-host` to a published bt-hci 0.11 release once crates.io catches up.

## Path B phases (from research)

| Phase | Goal | Status |
| --- | --- | --- |
| scaffold | crate + docs + family stubs | **done** |
| rf-init | V208 DevInit + cal MMIO | **done** |
| rf-runtime | V208 channel/shut/tx/rx/ISR | **done** |
| A | soft HCI typechecks with Trouble | **done** + on-device Host init verified |
| B | legacy adv on air | **verified** — `wchble` ADV_IND seen by macOS CoreBluetooth (after the W1C `TX_DONE` fix) |
| C | BAS via Trouble in a HAL example | not started |
| D | more chip packs | CH592 + CH585 RF layers **done + on air**; CH572/583/595 tables recorded, apply TBD |
