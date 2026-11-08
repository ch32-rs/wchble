# wchble — CH32V208 NimBLE vs CH585EVT RF/BB bring-up

Compare the open CH32V208 NimBLE radio driver (`~/Repos/ch32v208-nimble`) with the closed CH585EVT BLE stack (`~/WCH/CH585EVT/EXAM/BLE`), focusing on **core RF / BB / LLE / RFEND initialization**.

## Documents

| File | Content |
| --- | --- |
| [research-process.md](research-process.md) | V208 vs CH585 sources, method, call graphs, evidence |
| [conclusions.md](conclusions.md) | V208 vs CH585 same-vs-different + porting implications |
| [init-diff-table.md](init-diff-table.md) | Register-level init table (V208 open vs CH585) |
| [family-comparison.md](family-comparison.md) | CH572 / CH583 / CH585 / CH595 cross-family matrix |
| [ch592-baseline.md](ch592-baseline.md) | CH592 (CH59x EVT v1.7): runtime recovery + on-air status |
| [ch58x-reuse.md](ch58x-reuse.md) | CH583 vs CH585: shared map, **not** shared DevInit tables |
| [bringup-debug.md](bringup-debug.md) | On-silicon dump checklist; marks UNCERTAIN fields |
| [path-b-soft-hci-trouble.md](path-b-soft-hci-trouble.md) | Path B: Rust LL + soft HCI → Trouble (refined plan) |
| [upstream-disasm/notes.md](upstream-disasm/notes.md) | Preserved notes from old `ch32v20x-ble/disasm` |
| [../architecture.md](../architecture.md) | Repo layer / HAL boundary / module map |
| [../progress.md](../progress.md) | Scaffold / Path B phase progress |

## Bottom line

The BLE IP **looks like the same family**: same block roles (BB / LLE / AES / RFEND), same relative spacing, same public symbol names (`BLE_IPCoreInit`, `LLE_DevInit`, `BB_DevInit`, `RFEND_*`, `BLE_RegInit`), and the same calibration pipeline shape (TXCtune → TXFtune → RXFilter → RXAdc).

The **core init is not copy-paste portable**.

- **CH32V208** uses bases `0x40024xxx` / IRQ 63–64.
- **CH572 / CH583 / CH585 / CH595** all use bases `0x4000Cxxx` / IRQ 20–21.
- Within CH57/58/59, **DevInit tables still differ per SoC**. CH583 is closest to the V208 open-driver literals; CH585 adds a 4th VCO band (`nCO2522`) and diverges further.

Do **not** reuse `ch32v208-nimble/drivers/wch_ble/` on any CH5xx part without re-basing MMIO and re-auditing that chip’s `*_DevInit` / `RFEND_*` objects.

**Status (2026-11-09):** CH592 is the first CH5xx part fully brought up on air
from this evidence — DevInit, calibration, TX and RX in
`src/rf/family/ch592.rs`, gate `examples/ch592-rf-smoke`; see
[ch592-baseline.md](ch592-baseline.md).
