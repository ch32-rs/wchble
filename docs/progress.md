# Progress

Last updated: 2026-11-07

## Done

- Replaced closed-lib bindgen crates (`ch32v20x-ble` / `ch57x-ble` / `ch58x-ble` /
  `ch59x-ble` / old `wchble` facade) with a single `wchble` Path B crate.
- Module layout: `rf` / `phy` / `ll` / `hci` / `time`; HAL-extension framing
  (consumed by `ch32-hal` / `ch5xx-hal`, no in-repo firmware/linker).
- Chip features + `Backend`:
  - `ch32v208` — correct bases (TOP≠BB), open-driver DevInit markers
  - `ch572` — CH5xx map + unique new-table set (`0x64` / `0x16000F` / BB `0x14`)
  - `ch583` — CH5xx map + closed-disasm “old tables” (≈V208)
  - `ch585` — CH5xx map + “new tables” / `nCO2522` / WaitTune 8000
  - `ch595` — CH5xx map + near-CH585 tables without `nCO2522` (`0x84` highs)
- Shared table shapes + `Certainty` tags in `src/rf/family/tables.rs`.
- Research notes under `docs/research/` (incl. `ch58x-reuse.md`,
  `bringup-debug.md`); architecture + HAL boundary in `docs/architecture.md`.
- `cargo check` clean for each single chip feature (+ `controller,phy`).

## Not done (next)

1. **RF MMIO apply** — write `LLE_DEV_INIT` / `BB_DEV_INIT` / `RFEND_*` to
   hardware; port V208 sequences from open `wch_rf{,_analog}.c` first.
2. **TX/RX runtime** — `tx_basic` / `rx_basic` / ISR (mode words still
   UNCERTAIN on CH58x; proven on V208 open only).
3. **Soft HCI Phase A** — real `bt-hci` `Controller` + CmdSync/Async stubs so
   Trouble typechecks (state shell exists; traits not implemented).
4. **HAL integration** — examples live in `ch32-hal` / `ch5xx-hal`, not here.
5. **TODO: CH587** — DS mentions BLE 5.4; no CH587EVT / carved `libCH58xBLE`
   here yet (may still be unpublished by WCH). Do **not** alias to CH583/CH585.
   Other CH57/58 without carved libs stay out of tree.

## Path B phases (from research)

| Phase | Goal | Status |
| --- | --- | --- |
| scaffold | crate + docs + family stubs | **done** |
| A | soft HCI typechecks with Trouble | not started |
| B | legacy adv on air | not started |
| C | BAS via Trouble in a HAL example | not started |
| D | more chip packs | CH572/583/585/595 tables recorded; apply TBD |
