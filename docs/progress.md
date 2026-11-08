# Progress

Last updated: 2026-11-07

## Done

- Replaced closed-lib bindgen crates (`ch32v20x-ble` / `ch57x-ble` / `ch58x-ble` /
  `ch59x-ble` / old `wchble` facade) with a single `wchble` Path B crate.
- Module layout: `rf` / `phy` / `ll` / `hci` / `time`; HAL-extension framing
  (consumed by `ch32-hal` / `ch5xx-hal`, no in-repo firmware/linker).
- Chip features + `Backend`:
  - `ch32v208` — bases + **MMIO DevInit apply + full calibration** (open `wch_rf`)
  - `ch572` — CH5xx map + unique new-table set (`0x64` / `0x16000F` / BB `0x14`)
  - `ch583` — CH5xx map + closed-disasm “old tables” (≈V208)
  - `ch585` — CH5xx map + “new tables” / `nCO2522` / WaitTune 8000
  - `ch595` — CH5xx map + near-CH585 tables without `nCO2522` (`0x84` highs)
- Shared table shapes + `Certainty` tags in `src/rf/family/tables.rs`.
- Thin MMIO helpers (`regs::{read,write,rmw}`) + RFEND/AES offset map.
- Research notes under `docs/research/` (incl. `ch58x-reuse.md`,
  `bringup-debug.md`); architecture + HAL boundary in `docs/architecture.md`.
- `cargo check` clean for each single chip feature (+ `controller,phy`),
  including `riscv32imac-unknown-none-elf` for `ch32v208`.

## Not done (next)

1. **TX/RX runtime (V208)** — `tx_basic` / `rx_basic` / `shut` / channel MMIO +
   `lle_isr` / `bb_isr` from open `wch_rf.c`.
2. **Soft HCI Phase A** — real `bt-hci` `Controller` + CmdSync/Async stubs so
   Trouble typechecks (state shell exists; traits not implemented).
3. **HAL integration** — examples live in `ch32-hal` / `ch5xx-hal`, not here
   (provide `StaticCell` RX DMA ≥272 B into `Ch32v208Radio::new`).
4. Apply DevInit/cal on CH5xx families (tables recorded; MMIO TBD).
5. **TODO: CH587** — DS mentions BLE 5.4; no CH587EVT / carved `libCH58xBLE`
   here yet (may still be unpublished by WCH). Do **not** alias to CH583/CH585.
   Other CH57/58 without carved libs stay out of tree.

## Path B phases (from research)

| Phase | Goal | Status |
| --- | --- | --- |
| scaffold | crate + docs + family stubs | **done** |
| rf-init | V208 DevInit + cal MMIO | **done** (TX/RX next) |
| A | soft HCI typechecks with Trouble | not started |
| B | legacy adv on air | not started |
| C | BAS via Trouble in a HAL example | not started |
| D | more chip packs | CH572/583/585/595 tables recorded; apply TBD |
