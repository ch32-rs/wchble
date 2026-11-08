# Progress

Last updated: 2026-11-08

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
  - `ch585` — CH5xx map + “new tables” / `nCO2522` / WaitTune 8000
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
- `cargo check` clean for each single chip feature (+ `controller,phy`),
  including `riscv32imac-unknown-none-elf` for `ch32v208`.

- **Trouble join (V208)** — `examples/ch32v208-trouble-adv` Embassy app joins
  SoftRunner HCI pump + Trouble Host runner + AdvRadio TX; SDI confirmed
  `rf init ok` / `hci host up` / `adv enable` / `tx ch{37,38,39}` /
  `trouble adv running` on the same probe. Uses a local `embassy-rs/trouble`
  checkout (crates.io 0.8.0 still pins bt-hci 0.10; main is 0.11).

## Not done (next)

1. Auto-ack / `auto_arm_rx` / IFS turnaround (needed for SCAN_RSP / conn events).
2. Soft HCI + Trouble BAS peripheral (Phase C) — accept connection + GATT.
3. Apply DevInit/cal + runtime on CH5xx (tables recorded; CH585 use rusted-ch5
   as RF reference, not V208 open).
4. **TODO: CH587** — DS mentions BLE 5.4; no CH587EVT / carved `libCH58xBLE`
   here yet (may still be unpublished by WCH). Do **not** alias to CH583/CH585.
   Other CH57/58 without carved libs stay out of tree.
5. Pin `trouble-host` to a published bt-hci 0.11 release once crates.io catches up.

## Path B phases (from research)

| Phase | Goal | Status |
| --- | --- | --- |
| scaffold | crate + docs + family stubs | **done** |
| rf-init | V208 DevInit + cal MMIO | **done** |
| rf-runtime | V208 channel/shut/tx/rx/ISR | **done** |
| A | soft HCI typechecks with Trouble | **done** + on-device Host init verified |
| B | legacy adv on air | **verified** Host-driven ADV via Trouble + SoftRunner |
| C | BAS via Trouble in a HAL example | not started |
| D | more chip packs | CH572/583/585/595 tables recorded; apply TBD |
