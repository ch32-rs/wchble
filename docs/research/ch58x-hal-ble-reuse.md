# rusted-ch5/ch58x-hal BLE reuse audit

Date: 2026-11-08  
Clone: `/tmp/wchble-research/ch58x-hal` (`git clone --depth 1 https://github.com/rusted-ch5/ch58x-hal`)  
Cross-check: our `docs/research/{ch58x-reuse,family-comparison,conclusions}.md` + open V208 `wch_rf_analog.c`.

## Bottom line

| Question | Answer |
| --- | --- |
| Is their BLE “usable” today? | **As a library reference / design sample — yes. As proven on-air firmware — no.** |
| Can we vendor their crate into `wchble`? | **Not as a drop-in.** CH585-only RF path; different product shape (custom Peripheral LL + HCI queues vs our Path B soft HCI → Trouble). |
| Worth deep borrowing? | **Yes** — CH585 RF runtime details, HCI transport pattern, portable cal arithmetic, acceptance-gate docs. |
| Safe to copy into V208? | **No** for MMIO/mode words/DMA offsets. V208 stays on open `wch_rf`. |

Their own docs are explicit (`docs/ble-status.md`): host tests + `riscv32imc` library build only; **no** Rust firmware RF acceptance. Scope is legacy ADV + one plaintext Peripheral link (27 B ACL, CSA#1, LLCP); no encryption, Central, DLE, or extended advertising.

License: MIT OR Apache-2.0. BLE packages are Git-only (`publish = false`).

## Layout (what exists)

```text
ch58x-hal (HAL: clocks/GPIO/UART/DataFlash + BLE ownership token)
├── crates/ble-controller   # portable protocol core, no MMIO (~4.2k LOC)
│   advertising / channel / crc / whitening / phy
│   rf_calibration (pure 3-point table builder)
│   link_layer + llcp + hci validation
└── crates/ch58x-ble        # CH585 backend (~3.3k LOC)
    controller.rs           # bt-hci ExternalController + embassy Channel transport
    link_layer.rs           # Peripheral runner / scheduling
    radio.rs                # BB/LLE/RFEND TX·RX·ISR (~1050 LOC)
    rf_frontend.rs          # DevInit + TXCtune/Ftune/RXFilter/RXAdc (~270 LOC)
```

Ownership chain they document:

```text
HAL Peripherals.BLE
  ├─ ControllerToken → HciTransport / ExternalController → Trouble Host
  └─ RadioToken      → link_layer::Runner → radio / rf_frontend
```

## What to borrow (ranked)

### 1. CH585 RF runtime facts (when we MMIO-apply `ch585`)

These are the highest-value deltas vs our current **table-only** `src/rf/family/ch585.rs` stub.

| Item | Their code | Our prior note | Action |
| --- | --- | --- | --- |
| Bases / IRQ | BB `0x4000_C100`, LLE `+0x100`, RFEND `0x4000_D000`, BLEB=20 | match | keep |
| WaitTune | `LLE+0x64 = 0x1F40` (8000) | match | keep |
| No `RFEND_Reset` | DevInit starts at `+0x28=0x480` | match | keep |
| Band clear | `(CFG38 & 0xfffe00ff) \| tune` | we fixed V208 to same mask | reuse constant |
| TXCtune bands | `0xbf00 / 0xe800 / 0xd400 / 0xfc00` (+2522) | we knew 4th band exists; **codes differ from V208 `bf/e7/d3`** | record CH585 codes |
| DMA pointers | **TX `LLE+0x78`, RX `LLE+0x7c`** | we flagged “+0x7C path vs V208 +0x74” as UNCERTAIN | **treat as confirmed for CH585** |
| LLE mode bank | `IDLE 0x0003_0000`, `CAL 0x0003_0558`, `RX 0x0003_0158`, `TX 0x0003_0258` | our V208 words are `0x5a/0x59/0x5d` | **do not share mode words across families** |
| BB mode field | bits[9:8]: IDLE `0x100`, ACTIVE `0x200` | not in our V208 open path the same way | CH585-only |
| Channel / synth | `RFEND+0x2c \|= 2`; program `RFEND+0x44` fractional (kHz, RX −1 MHz) | missing from our stub | port with CH585 MMIO |
| TX power | AUTOCFG-ish pack with code **`0x15` = 0 dBm**; RFEND `+0x5c` profile 1 | V208 open uses enum **9** | per-family |
| IFS / PHY timing | `tx_1m_countdown`, `rx_1m_capture_countdown`, transition `0x18e`, RX→TX timing `0x76` | not yet in `wchble` | steal pure formulas into `txrx` / family helpers |
| Capture IRQ | BLEB bit6 W1C ack **before** trusting LLE completion; disable IRQ during polled scan RX | future ISR work | adopt ordering |
| Shut path | clear LLE mode bits, CMD `\|= 0x08`, BB→IDLE, `FECTRL &= 0xffcd_ffff` | same shut mask as V208 open | shared constant OK |

**RFEND DevInit soup is not V208.** Their `initialize_baseline` RMW set (CFG3C/30/48/4C/5C, no 0x1101 reset pulse) must stay a CH585 table — do not reuse the V208 `rf_dev_init_rmw` literal port.

### 2. Portable calibration arithmetic

`ble-controller::rf_calibration::build_table` is a clean, tested 3-point nibble packer (13 words / VCOTAB+GA). Same math as open V208 / our `nibble_write` loops.

Borrow ideas:

- Keep measurement + MMIO in the family backend; put **pure** interpolation in a shared `wchble` module (or copy the algorithm under our license headers).
- Their CH585 path **measures** 2522 then **drops** it from `build_table` (still 3-point). Decide explicitly whether CH585 should use a 4-point interpolator or keep 3-point + discard — do not silently inherit the drop.

### 3. Soft HCI / Trouble integration shape

Useful for our Path B Phase A even though RF backends differ:

- `bt_hci::controller::ExternalController<HciTransport, N>` over a **bounded** embassy `Channel` (H2C depth 1, C2H depth 2) — back-pressure instead of unbounded queues.
- Split Host-facing token vs Radio-facing token so HAL cannot double-bind BLE IRQs.
- Command Complete / Status / ACL helpers as thin byte builders (`controller.rs`).
- Explicit “Host must drain events or RF deadlines slip” contract (`docs/ble-integration.md`).

We should **not** adopt their full in-controller Peripheral LL (`link_layer.rs` ~1.2k + portable ~2.2k) as the long-term architecture: Path B wants Trouble Host above a soft HCI controller. Their LLCP / outstanding-owner / instant / widening logic is still a strong **checklist** when we implement connection events under HCI.

### 4. Process / docs patterns

Worth mirroring in `wchble`:

- Phased evidence table (host tests ≠ RF acceptance).
- Independent peer contract (`ble-peer-contract.md`) for Nordic Central gates.
- Pure modules host-tested via `cases/ble-pure.rs` path includes (DMA policy, PHY timing, RX status) — same idea as keeping cal math off-target-testable.

## What not to copy

| Item | Why |
| --- | --- |
| V208 MMIO / mode words from this tree | CH585-only; different LLE mode bank, DMA offsets, synth, DevInit |
| `static mut` TX/RX/RESPONSE DMA banks | We already require caller `StaticCell` / `'static mut [u8]` |
| Spin-loop calibration polls as primary timeout | Prefer `InstantUs` + LLE window (open-driver style); spin is OK as inner hint |
| Claiming RF acceptance from their README | They disclaim it; so should we |
| CH582 comments as CH583/V208 truth | Mixed generation notes inside `radio.rs`; verify per family |

## Discrepancies to resolve before CH585 MMIO apply

1. **LLE timeout stores `+0x2c` / `+0x3c`:** our carved `libCH58xBLE` path records **`0x6c`**; their RF-basic-derived init writes **`0x6e`**. Same for whether DevInit clears `LLE+0x04` low5 + halfword `+0x06=1` (they do; our table has `crc_aa_cfg_clear_mask` but not the `+0x06` u16 write). Prefer silicon / which archive is authoritative before freezing tables.
2. **Band codes:** V208 open `0xbf / 0xe7 / 0xd3`; CH585 tree `0xbf / 0xe8 / 0xd4` (+ `0xfc` for 2522). Treat as family-specific immediates.
3. **Fourth VCO band:** measured then unused in table builder — confirm intended CH585 behavior from closed `RFEND_TXCtune` size / BSS (`nCO2522`).
4. **BB `+0x34`:** our carve `0x50`; their init path emphasizes `bb_interrupt_enable.write(0x50)` and does not obviously write CFG34 the V208 way — re-read BB_DevInit against both archives.

## Suggested `wchble` follow-ups

1. **Now (docs/tables only):** annotate `ch585.rs` with DMA `+0x78/+0x7c`, LLE mode bank constants, band codes, synth note, and the `0x6c` vs `0x6e` open question; link this file from `ch58x-reuse.md`.
2. **After V208 TX/RX:** when applying CH585 MMIO, port `rf_frontend` + TX/RX sequencing from this tree as the primary CH585 reference (not V208 open), still gated behind our `Radio` trait / HAL clock+NVIC boundary.
3. **HCI Phase A:** skim their `HciTransport` + `ExternalController` wiring as a template for `wchble::hci::SoftController` ↔ Trouble; keep LL in Trouble, not a second Peripheral runner unless we deliberately fork Path B.
4. **Shared pure cal:** extract 3-point `build_table` (with tests) so V208 and CH585 backends share math; backends own measurements + MMIO.

## Evidence commands (local clone)

```sh
# already cloned:
# /tmp/wchble-research/ch58x-hal

rg -n "LLE_MODE_|0x78|0x7c|0x1f40|fffe00ff|0xfc00" \
  /tmp/wchble-research/ch58x-hal/crates/ch58x-ble/src

# their claimed checks (needs network/toolchains):
# cases/check-ble.sh
```
