# CH585 C1 central (LE 1M initiator + GATT client)

This finite example is the CH585 **central** counterpart to the P3/P4
peripherals. It scans with the real soft HCI, selects one controlled peripheral
by local name, initiates a legacy LE 1M connection, runs a real Trouble
`GattClient` service discovery / read / write / read-back, disconnects, and
repeats three times. It is a prototype for single-link central operation, not a
qualified BLE controller.

The advertised name is exactly `wch585-c1`. The controlled sources are
`tools/peripheral.swift` (macOS CoreBluetooth, bring-up) and
`tools/android-gatt/` (`BluetoothGattServer` + `BluetoothLeAdvertiser`, formal
acceptance).

**Test-only link parameters.** The connection uses the constant access address
`0x12345678` and CRCInit `0x00555555`, channel map = all 37 channels, hop 5,
SCA 0, `WinSize=8`, `WinOffset=0`. They are exported as ELF symbols (`AA`,
`CRC_INIT`, `WIN_SPEC`, `CONNECT_OFFSET`) and checked by the runner before it
touches the probe. This example does not use a CSRNG and must not be treated as
an interoperable production configuration.

## CONNECT_IND is hardware-timed

The initiator follows the vendor controller path, not a software deadline.
When the scan window receives the target advertisement, the prepared 36-byte
CONNECT_IND is armed inside the link-layer engine while it is still in its RX
window (`Ch585Radio::initiate_tx` mirrors `LL_InitiateSetRF` +
`ll_initiate_tx`): store the TX buffer, set the BB `START_TX` bit, clear
`AUTOCFG[1:0]`, and wait for the RX side to finish. The LLE performs the RX→TX
transition and starts the packet at hardware T_IFS. There is no `MODE=TX` write
and no software deadline, so the `CONNECT_OFFSET` metadata is `0`.
The arm code and `set_phy_tx_mode` run from `.highcode` RAM.

Observed on air (Mac and Android): advertisement end → CONNECT_IND completion
≈ 500–501 µs (36-byte PDU), arm 2 µs after RX_DONE, first-event RX 243–244 µs
after the scheduled anchor. The first event anchor is
`CONNECT_IND end + 1.25 ms + WinSize/2 × 0.625 ms` (window centre).

**This is not a measurement of air IFS.** The counters show the LLE accepted
and completed the packets; they do not prove 150 µs spacing or conformance.
Independent over-the-air instrumentation is still required.

## GATT test

Per connection the host discovers service `00001000-b0cd-11ec-871f-d45ddf138840`,
resolves characteristic `00001001-...` as `Characteristic<u32>`, reads the
initial value `0x0000002A`, writes `0x0000002B`, and reads it back. The expected
value is tracked across cycles because the peer keeps its characteristic value
after a disconnect.

Android's `BluetoothGattServer` does **not** synthesize the Client
Characteristic Configuration descriptor for a `PROPERTY_NOTIFY` characteristic;
the app publishes `0x2902` explicitly. Without it a spec-following client that
resolves `cccd_handle` during discovery fails with NotFound even though read and
write would work.

## Build

The firmware is built from this directory so the target/linker configuration
applies. The tools do not build firmware.

```sh
cd examples/ch585-central
cargo build --release                 # 60 s run
cargo build --release --features short-run   # 25 s run
cargo build --release --features bogus-peer  # nonexistent-peer negative image
```

All builds share `target/riscv32imc-unknown-none-elf/release/ch585-central`.
The `bogus-peer` image has a different `BOGUS_PEER` symbol value; copy it aside
before rebuilding the default image and pass it with `--bogus-elf`.

## Run

```sh
# Mac bring-up, positive phase
python3 -I tools/run.py --source mac --phase positive \
    --out local-docs/research/experiments/c1-mac

# Android formal acceptance: all five phases
python3 -I tools/run.py --source android --phase all \
    --elf  target/riscv32imc-unknown-none-elf/release/ch585-central \
    --bogus-elf target/riscv32imc-unknown-none-elf/release/ch585-central-bogus \
    --out local-docs/research/experiments/c1-android
```

The runner checks the image identity (name, AA, CRCInit, service UUID, run
length, bogus flag), flashes through the single-session
`tools/ch585-preflight`, never reads the probe before `RUN_SECONDS + 5`, and
restores `ch585-rf-smoke` afterwards, requiring macOS to discover `wch585`.

Phases: `positive` (3 connect/GATT/disconnect cycles, both sides checked),
`negative-nosource`, `negative-wrong-name`, `negative-no-service`, and
`negative-bogus-peer` (initiator timeout, no CONNECT_IND, Host receives
`0x3e`).

## Validation status

**2026-11-11 (Mac bring-up).** `c1-mac-run-04` passed: 3 CONNECT_IND attempts
sent with 0 late/0 error, 3 connections and disconnects, 6 reads and 3 writes,
final `CMD=0`, `MODE=0x30000`, stage 9, clean 60 s run. An earlier short run
(`c1-mac-03`) froze after the connection phase and is preserved as an
unexplained anomaly; the later 25 s and 60 s runs completed and parked
normally, and the panic-location recorder was added afterwards.

**2026-11-11 (Android formal acceptance).** `c1-android-accept-02` passed all
five phases plus smoke recovery on CPH2411 (Android 15). Positive: 85 scan
arms, 3 target reports, 3/3 attempts sent, 54 connection events, 3 first-event
RX, 6 GATT reads, 3 writes, 0 bridge errors. The first acceptance attempt
(`c1-android-accept-01`) failed the positive phase because of the missing
Android CCCD; the failure and its ATT-level evidence (`c1-android-diag-01/02`)
are preserved.

**2026-11-11 (regressions).** The P3 connect-only run (`c1-regress-p3-01`)
completed one 37-event connection with a clean terminate and idle RF; the P4
Trouble GATT run (`c1-regress-p4-01`) completed one GATT cycle over 62 accepted
events. Both restored smoke and macOS discovered `wch585`.

Not delivered here: encryption/pairing/SMP, CSA#2, DLE, 2M/Coded, extended or
periodic advertising, multiple simultaneous links, notification acceptance,
production randomness, throughput/power, and calibrated air IFS.
