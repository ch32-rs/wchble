# CH585 HID-over-GATT keyboard (X4b)

A standard HOGP keyboard (service `0x1812`) on the real Trouble Host. The RF
pump, HCI bridge and DataFlash bond store are copied from
`examples/ch585-trouble-gatt` so the HID example cannot change the P4/P5/S2/S3
acceptance fixture; only `src/host.rs` differs. Reports are only emitted on an
encrypted link (LE Secure Connections Just Works) and reuse the S3 stored bond
across reboots.

This example has passed only what is recorded in
`local-docs/research/ch585-hid-results.md`. iOS is not a HOGP host and is out of
scope; Android is a manual system-HID check.

## Build

```sh
cd examples/ch585-hid-keyboard
cargo build --release --features secure              # acceptance image, RUN_SECONDS=60
cargo build --release --features secure,long-run     # 360 s manual window
cargo build --release                                # plain link, HID table only
```

`--locked` reproduces the pinned Trouble (`3aa6fd27…`, `bt-hci` 0.11) and
`uuid` 1.17.0 dependency graph. Do not regenerate the lockfile for normal
builds.

The report tick needs `embassy-time`; the bare driver in `src/time_driver.rs` is
installed in every build, not only `secure` (the only deviation from the copied
`main.rs`). `embassy-time-driver` is therefore a direct, non-optional
dependency.

## GATT contract

| Service | Characteristic | UUID | Properties | Value |
| --- | --- | --- | --- | --- |
| GAP | Device Name / Appearance | `2A00` / `2A01` | Read | `wch585-hid` / `0x03C1` |
| DIS | Manufacturer / Model / FW | `2A29` / `2A24` / `2A26` | Read | `wchble` / `ch585-hid-keyboard` / `x4b-0.1` |
| HID | HID Information | `2A4A` | Read | `11 01 00 01` |
| HID | Report Map | `2A4B` | Read | 63-byte boot keyboard map |
| HID | HID Control Point | `2A4C` | Write Without Response | `0x00`/`0x01` recorded |
| HID | Protocol Mode | `2A4E` | Read + Write Without Response | `1` report, `0` boot |
| HID | Report (keyboard input) | `2A4D` | Read + Notify, `2908=[0,1]` | 8 bytes |
| HID | Report (LED output) | `2A4D` | Read + Write + Write Without Response, `2908=[0,2]` | 1 byte |
| HID | Boot Keyboard Input | `2A22` | Read + Notify | 8 bytes |
| HID | Boot Keyboard Output | `2A32` | Read + Write | 1 byte |
| vendor | Bond control | `00001a01-…` | Write | `DEL!` / `WIPE` / `FALT` |

The 63-byte report map is the vendor `HID_Keyboard` map
(`CH585EVT/EXAM/BLE/HID_Keyboard/Profile/hidkbdservice.c`): 8 modifier bits, one
reserved byte, five LED bits plus padding, six key bytes. There is no boot
keyboard control point: `0x2A34` is Glucose Measurement Context, not HID.

Under `secure`, every HID value/CCCD write requires encryption. The two
`0x2908` Report Reference descriptors stay `Allowed`: they carry no secret and
a HOGP host may read them while bonding. The attribute table capacity is 64
(`AttributeTable` and `AttributeServer` const generics must match; `push`
panics at the first poll on overflow).

Advertising data: Flags, complete 16-bit service list `0x1812`, Appearance
(`0x19`), complete local name. Android only reliably receives `ADV_IND`, so the
name and service UUID are in the advertising data itself. Static random address
`C1:FF:EE:00:00:17`, fixed across boots so the S3 bond store can answer the
peer's stored LTK.

## Reports

Once the input report CCCD is written, a one-second tick sends the fixed cycle
`a` down, release, `b`, release, `c`, release, `d`, release. The sequence resets
at every subscription rising edge, so a client always sees the cycle from its
first report. In boot protocol the same eight-byte reports go to `0x2A22`;
values written to either LED output characteristic are recorded. Reports are
never sent while the link is unencrypted.

`HID_STATS[16]` (symbol, read over SWD) carries: `magic`, `version`,
`reports_sent` (report protocol), `notify_errors`, `subscription_edges`,
`led_writes`, `led_value`, `control_point_writes`, `control_point_last`,
`protocol_mode`, `protocol_mode_writes`, `boot_input_sent`,
`report_map_reads`, `hid_info_reads`, `blocked_unencrypted` (diagnostic),
`last_error`.

`HOST_STATS[16]` is the Host's control-plane view: `phase`, `connections`,
`disconnects`, `security` (1 requested, 2 paired, 3 encrypted, 4 failed),
`errors`, `last_error`, `advertise_attempts`.

## Acceptance

The runner flashes the secure image through the single-session preflight helper,
runs a macOS CoreBluetooth client, waits for the embedded `RUN_SECONDS` plus the
cleanup margin, reads the counters, and always restores the smoke image.
It never probes while RF may be running.

```sh
# First hardware step: discovery only (no pairing, no reports).
python3 examples/ch585-hid-keyboard/tools/hid_run.py \
  --out local-docs/results/x4b-discover-<unique> --discover-only

# Full macOS acceptance.
python3 examples/ch585-hid-keyboard/tools/hid_run.py \
  --out local-docs/results/x4b-macos-<unique>
```

The macOS client asserts the HID Information, the exact 63-byte Report Map,
Protocol Mode `1`, the two `0x2908` values, the first eight report bytes, the
LED write, both Control Point values, boot protocol reports and the return to
report protocol. The pairing dialog must be accepted; the runner starts
`tools/hid_pair_click.py`, which clicks only the affirmative Bluetooth button.

Offline gates before any hardware session:

```sh
cargo test --manifest-path tests/hid-host/Cargo.toml --locked
python3 -m unittest discover -s examples/ch585-hid-keyboard/tools -p 'test_*.py'
swiftc -typecheck examples/ch585-hid-keyboard/tools/hid_host.swift
```

### Android manual check

1. Flash the `secure,long-run` image through the preflight helper (360 s).
2. Advanced Bluetooth settings → pair with `wch585-hid`; the Just Works dialog
   on this ROM needs one user tap.
3. Open a text field and watch `abcd…` typed once per second.
4. Evidence: `adb shell dumpsys input` shows a new HID keyboard input device,
   `adb exec-out screencap -p` captures the typed text, and the firmware
   counters are read after the run. `getevent` may be restricted on retail
   builds; that is recorded, not treated as a failure.
5. Wait out the 360 s budget, then restore the smoke image.

Android system HOGP cannot be scripted; it does not replace the macOS
byte-level assertions.

## Known gaps

- iOS is not a HOGP host (MFi required); out of scope, like S2.
- Consumer-control and mouse reports are not implemented.
- Sniffer capture shows SMP/start-encryption gates only; ATT values after
  encryption cannot be decoded without adding the dumped LTK to the sniffer.
- The copied example pump (~2100 lines) is duplicated; L0 is the planned
  place to extract it. Tracked in `BACKLOG.md`.
- Encryption-required HID Information/Report Map reads may need to be relaxed
  to `Allowed` if a specific Android HID host fails before bonding; reports
  themselves stay encrypted.
