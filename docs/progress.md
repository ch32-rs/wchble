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

- Thin MMIO helpers (`regs::{read,write,rmw}`) + RFEND/AES offset map +
  `rf::timing` pure helpers.
- Research notes under `docs/research/` (incl. `ch58x-reuse.md`,
  `ch58x-hal-ble-reuse.md`, `bringup-debug.md`); architecture + HAL boundary in
  `docs/architecture.md`.
- `cargo check` clean for each single chip feature (+ `controller,phy`),
  including `riscv32imac-unknown-none-elf` for `ch32v208`.

## Not done (next)

1. **HAL on-target smoke** — HAL-side example (kept out of this tree for now):
   clock + HSE trim + `InstantUs` + `Ch32v208Radio::new` → `init` →
   `set_channel(37)` → `tx_basic` ADV_IND; wire `lle_isr` / `bb_isr`
   (+ `note_anchor_us`). Sketch in `docs/research/bringup-debug.md`.
2. **Phase B** — `SoftRunner` drives real legacy adv TX on 37/38/39 via RF
   runtime (store AdvData / ScanRsp; schedule `tx_basic`).
3. Auto-ack / `auto_arm_rx` / IFS turnaround (needed for SCAN_RSP / conn events).
4. Apply DevInit/cal + runtime on CH5xx (tables recorded; CH585 use rusted-ch5
   as RF reference, not V208 open).
5. **TODO: CH587** — DS mentions BLE 5.4; no CH587EVT / carved `libCH58xBLE`
   here yet (may still be unpublished by WCH). Do **not** alias to CH583/CH585.
   Other CH57/58 without carved libs stay out of tree.

## Path B phases (from research)

| Phase | Goal | Status |
| --- | --- | --- |
| scaffold | crate + docs + family stubs | **done** |
| rf-init | V208 DevInit + cal MMIO | **done** |
| rf-runtime | V208 channel/shut/tx/rx/ISR | **done** |
| A | soft HCI typechecks with Trouble | **done** (`ExternalController` + SoftRunner) |
| B | legacy adv on air | SoftRunner stores params; RF schedule TBD |
| C | BAS via Trouble in a HAL example | not started |
| D | more chip packs | CH572/583/585/595 tables recorded; apply TBD |
