# Bring-up pitfalls (read before touching RF/LL/HCI)

These are the traps that have actually cost bring-up time. Each one produces a
**false green**: counters/logs say "ok" while nothing works on air. Treat them
as invariants, not suggestions.

## 1. LLE `IRQSTAT` is W1C — clear sticky completion bits explicitly

`LLE+0x08` is write-1-to-clear. `CLEAR_ARM` (0x2000) clears the window/arm
state but **does not clear `TX_DONE` (bit1) or `RX_DONE` (bit0)**.

**Symptom (2026-11-08, cost: whole session):** macOS never saw the advertiser
even though `tx_basic` returned `Ok` thousands of times and SDI printed
`tx ongoing`. Only the first packet ever reached the air.

**Mechanism:** `tx_basic` polled `TX_DONE` after arming. From the second call
on, the previous packet's sticky bit was still set, so the poll returned
"complete" almost immediately and no transmission happened.

**Rules:**
- Before arming TX: `IRQSTAT = TX_DONE` (and `RX_DONE` when arming RX), then
  `IRQSTAT = CLEAR_ARM`.
- After consuming a completion: write the same bit again (W1C acknowledge).
- Never treat `Ok` from a polled-basic TX as proof of airtime. **Time it:** a
  1M frame is hundreds of µs (19-byte ADV_IND ≈ 262 µs on V208); a stale-bit
  return is ~10 µs.
- If the HAL enables the LLE ISR, the ISR and `tx_basic` must agree on who
  consumes `TX_DONE`; otherwise the poll can race the ISR and time out.

## 2. TX and RX DMA buffers must be 4-byte aligned

The LLE reads `TXBUFPTR` / `RXBUFPTR` as DMA word addresses. The open
`ch32v208-nimble` driver only ever passes `__attribute__((aligned(4)))` buffers
(`g_ble_phy_tx_buf`); our RX path already failed when a `StaticCell<[u8; N]>`
landed at +1.

**Rules:**
- RX scratch: wrap in `#[repr(align(4))]` (as the examples do), and
  `Ch32v208Radio::new` rejects misaligned buffers.
- TX: `tx_basic` bounces unaligned caller frames through an internal aligned
  buffer. Prefer declaring aligned PDU buffers in apps anyway (avoids the
  copy), but never rely on stack alignment.

## 3. Own address: HCI `0x2005` is the real path — the HAL seed is a fallback

The pinned Trouble checkout **does** send `LE Set Random Address` (0x2005):
`ControlRunner::run` issues `Reset` and then 0x2005 for the address given to
`StackBuilder::set_random_address` (`host/src/host.rs`, and advertising
commands are gated on host init finishing). So `SoftRunner::set_random_addr`
is not required for this Host; it exists for Hosts that never send 0x2005 and
for HALs that want an address before Host init.

**Rules:**
- If you seed, pass the same bytes to `SoftRunner::set_random_addr(bytes)` and
  `Address::random(bytes)`. SoftRunner re-applies a seed after `Reset`; a
  0x2005 that arrives later wins.
- Investigate a wrong AdvA by checking the actual 0x2005 command/bytes, not by
  adding another seed path.
- The address must be valid: for a **static random** address the most
  significant octet's bits 7..6 must be `11` (e.g. `0xC1`). Invalid random
  addresses are dropped by macOS/iOS scanners.
- HCI/AdvA is little-endian: `[0x42, 0x00, 0x00, 0xEE, 0xFF, 0xC1]` has MSB
  `0xC1`.

## 4. Do not print from the TX hot path

SDI / RTT / logging on the advertising path stretches the interval enough that
scanners miss packets. A single `try_println` per channel or per burst is
already too much.

**Rules:** print state transitions only (`adv enable`, first burst, one-shot
PDU dump). Use RAM counters + `probe-rs read` for ongoing telemetry.

## 5. `probe-rs read` halts the core

Any memory read stops the RISC-V core (and therefore BLE deadlines). Two
consecutive identical counter snapshots mean "halted between reads", **not**
"firmware stalled".

**Rules:**
- Take one snapshot after the measurement window, then reset the board.
- `probe-rs reset` / `probe-rs read` may leave the target halted; use
  `wlink reset` (or a probe-rs `run`) when the firmware must be executing.
- Never leave a probe attached while judging on-air behavior; same lesson as
  the NimBLE project's RTT warning.

## 6. macOS caches names per identity

CoreBluetooth may keep reporting an old `kCBAdvDataLocalName` for the same
identity address after reflashing.

**Rules:** match a stable secondary signal too (manufacturer bytes, service
UUID, or the CoreBluetooth `id`). An empty name match is not proof the board is
absent from an unfiltered scan.

## 7. `Ok` from `tx_basic` is not `tx on air`

Basic-mode TX completion only means the LLE engine finished its programmed
window. It says nothing about CRC, whitening, channel, PA enable, or antenna.
Validate on air (second receiver / macOS scan) before declaring PF/LL work done.

**Signature seen on CH592 (2026-11-08):** `TX_DONE` arrived *exactly* at the
programmed window expiry (254/254 µs, 302/302, 366/366, 406/406) and the
calibration readback was identical for every band. That means the radio never
keyed — the analog front end was off. Compare TX duration against the window
formula: a real 1M packet finishes a few µs before the window, and TXCtune
CO/GA must differ per band. See `research/ch592-baseline.md`.

## 8. CH5xx tables are not transferable

Bases, IRQ numbers, DevInit, WaitTune, VCO and RFEND offsets are per chip.
Never paste V208 immediates into CH583/CH585/CH572, and never enable two chip
features at once.

## 9. CH592 W1C is gated by `LLE+0x0C` bit 17

`BLE_SetPHYTxMode` clears bit 17 of the guard register `LLE+0x0C` around every
`IRQSTAT` write. The bit shadows `IRQSTAT`'s `CLEAR_ARM` position; while it is
set the W1C is **silently dropped**.

**Symptom:** after the first TX, every `tx_basic` sees `LLE+0x00` still holding
`2` and returns `Busy`; clearing `IRQSTAT` appears to do nothing.

**Rule:** the guard-clear mask is `!CLEAR_ARM` (`0xfffd_ffff`), never V208's
numeric bits 12..16 (`0xfffe_0fff`). Keep the guard read/restore, with
`fence.i` between the guard write and the `IRQSTAT` write.

## 10. DevInit values recovered from `lui`/`addi` pairs are field shifts

Disassembly like `lui a3, 5` is not the value `5`; it is `0x5000` (bits
12..15), and `lui a3, 0xffff1; addi -1` is a **mask**, not a value. Two CH592
RFEND analog fields were lost this way and silently disabled the radio:

- `RFEND+0x3C`: RMW set `0x0000_5000` (bits 12..15), not `0x0005_0000`.
- `RFEND+0x30`: RMW OR `0x0000_7000` (bits 12..14), not `0x7`.

**Rule:** when recovering a store, decode the full `lui`+`addi`/`ori` immediate
and log the resulting 32-bit word (and its bit positions) next to the register;
then verify the effect with the calibration readback on silicon.

## 11. macOS reports a sparse advertiser sporadically

CoreBluetooth's scan window vs. an advertiser's interval can produce zero
reports from a device that is provably on air. Absence in one short scan is not
evidence — confirm with a second receiver's `crc` bit, or re-scan at a dense
test interval. Conversely, a single `seen name=…` does not prove the production
interval works.

## 12. Do not advertise scan/connect support that the firmware does not provide

**Symptom (CH585, 2026-11-09):** iPhone nRF Connect saw the smoke-test
advertiser, but Android nRF Connect did not, even though it could see other
BLE devices and had no scan filters. Changing the random address to a static
random address did not help. With the same static address, name and loop,
changing the PDU from `ADV_IND` to `ADV_NONCONN_IND` made it visible on that
Android phone. The latter remains visible on macOS as well.

**Likely mechanism, not yet confirmed on that phone:** `ADV_IND` declares a
connectable, scannable advertiser, but the smoke firmware only transmits; it
does not receive a `SCAN_REQ` and send `SCAN_RSP`, or accept a connection.
Some active-scanning implementations may wait for a scan response before
reporting an advertisement to the application. For example, one version of
[Android's scan reassembler](https://chromium.googlesource.com/aosp/platform/packages/modules/Bluetooth/+/d7e980b0bc8754f7bd2eb24b6810044b76083be6/system/gd/hci/le_scanning_reassembler.cc)
caches a scannable advertisement while awaiting its response under certain
configurations. Its behavior is version- and configuration-dependent; no HCI
snoop or air trace was captured from the affected phone, so this does not prove
its exact failure path. A missed response can have other causes too.

**Rules:**
- For a TX-only smoke test, use `ADV_NONCONN_IND` (with TxAdd matching the
  address type); do not claim scan or connection support.
- Use `ADV_IND` only when the intended implementation handles scan requests
  and connection events. An on-air advertisement alone is not proof of either.
- When scanners disagree, compare PDU types with the address, payload and
  timing held constant. Use an air capture or Android HCI snoop to distinguish
  a missing `SCAN_RSP` from scan-window, filtering or other issues.
