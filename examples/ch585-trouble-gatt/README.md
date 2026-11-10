# CH585 Trouble GATT peripheral (P4)

This example combines the CH585 polling radio/LL with the real `trouble-host`
GATT server. It is not the P3 hand-written ATT responder. Two separate five-cycle
macOS GATT runs passed with nominal HSE/PLL timing and the RX completion fix
(2026-11-10); this is not Android/iPhone acceptance, sustained stability, or air
compliance. Open defects and acceptance gaps are tracked in the repository
[`BACKLOG.md`](../../BACKLOG.md).

The local Trouble checkout at `../../../trouble/host` must be at
`3aa6fd27b89cd5fc35f5c9b4f0c7f66795a14f70` (the `bt-hci` 0.11 revision).
Only `peripheral`, `gatt`, `default-packet-pool` and
`default-packet-pool-mtu-27` are enabled. No derive macros, executor, or HAL
Embassy/SysTick time driver are enabled. The build and RAM-copy linker fragment
are inherited from the P3 peripheral example.

Keep this executable's `Cargo.lock` under version control and archive it with
build artifacts. It pins the transitive `uuid` dependency to `1.17.0`, matching
the existing Trouble advertising example and the repository's Rust 1.88
toolchain. A newly resolved `uuid` 1.29.2 requires Rust 1.89 and does not build
with Rust 1.88. Reproduce the dependency graph with
`cargo build --release --locked`; do not delete or regenerate the lockfile as
part of normal builds.
If intentionally recreating it, run `cargo update -p uuid --precise 1.17.0`
before building. The local Trouble checkout revision above must also match.

## Validation status

The first manual phone check passed on 2026-11-10. In one directly flashed
360-second window the user reported all five requested operations completed on
Android and a later iOS attempt also succeeded: read, Write Request/readback,
numbered notifications, a write/read with notifications disabled, and
disconnect/reconnect persistence. Firmware recorded four accepted connections
and disconnects, six reads, five writes, five queued notifications, final value
`0xAAAAAAAA`, no Host/bridge/RF-stop/TX/RX/supervision error, a clean 360.000021 s
finish and smoke restoration/discovery. Both platforms share that window's
counters, so platform attribution is the user's separate UI report, not captured
peer evidence. This is one manual session per platform, not three isolated
acceptance rounds each, and its 103 missed events plus 554 retries/duplicates are
retained rather than hidden. Sustained reliability and calibrated air timing
remain unverified.

**Preflight fix (2026-11-10).** The installed `probe-rs read` resumes CPU
execution after each access, so the old separate stop/idle reads could let smoke
rearm RF; an unrelated phone launch was refused before download (CMD
acknowledgements 0 then 2). `tools/ch585-preflight` now performs halt, engine
shutdown, two zero acknowledgements, verified download and start in one retained
session, and refuses to download on any nonzero or missing acknowledgement. The
runners use it for test and recovery flashes. The previously successful direct
phone window did not use this helper.

With the helper, two new three-cycle macOS acceptance runs passed. Each recorded
exactly three accepted connections and normal terminations, fifteen reads,
thirty-nine writes, thirty checked notifications, final value 110, Host
back-to-advertising phase, and no Host/bridge/RF-stop/error counters. One run had
172 data RX/TX with zero missed events or retries; the other 171 each, also zero.
Both finished the 25-second budget and restored/discovered smoke. Retained
failures: the preceding attempt had a fourth connection and final connected phase
while a phone was still present (counts therefore mismatched), and the next
attempt hit a transient download failure before the test image was written.
Neither is reclassified as a pass.

Two subsequent isolated five-cycle Mac runs each completed twenty-five reads,
sixty-five writes, fifty verified notifications, five normal disconnects and
return to advertising. The latest run finished its client sequence in 11.756 s,
with 287 data RX/TX, 1 miss in 286 events, zero supervision/TX/RX/stop/Host/bridge
errors or poll overruns, and maximum observed Host/HCI poll 987 us. Both firmware
budgets and smoke restoration/discovery passed. Capture remained incomplete in
both runs (despite clean capture-process exits), so their combined capture gates
are FAIL, not reclassified by their functional successes.

After correcting the receive deadline, the initial three-cycle Mac regression
completed fifteen reads, thirty-nine writes, thirty checked notifications and
three normal terminations in 6.209 s total client time. Misses dropped to 1/172
events (171 data RX/TX), without TX late/error, supervision expiration, Host/bridge
error or poll overrun. The two fully captured links each have 57 central and
57 peripheral packets, eliminating the prior alternating-event pattern.
Firmware finished its 25-second budget and smoke recovery/discovery passed.

The prior nominal-rate-only regression completed three Mac discovery/read/write/notify/
unsubscribe/disconnect/reconnect cycles: fifteen reads, thirty-nine writes,
thirty checked notifications, three normal terminations, and return to
advertising after each disconnect. Firmware confirmed 62,400,000 Hz, 173 data
RX/TX, 171 missed events out of 344, no supervision expiration, TX late/error,
RX/stop/Host/bridge error or poll overrun. Maximum observed Host/HCI poll was
987 us; the 25-second budget and smoke restoration/discovery passed. Missed events
remain visible, not hidden as zero-loss or stability acceptance.

The earlier single controlled macOS cycle completed discovery, five reads, thirteen writes,
ten checked notifications (101–110), unsubscribe, final readback 110, and expected
disconnect. Firmware recorded 65 data RX/TX, three missed events, normal terminate
0x13, no supervision expiration, TX late/error, RF stop error, Host/bridge error,
or Host poll overrun. Maximum observed Host/HCI poll was 985 us; the finite
25-second run ended safely and smoke restoration/discovery passed. This is an
observed maximum from one run, not a worst-case execution bound.

Two earlier attempts failed during automatic discovery and are retained as
failures. The final fix keeps Host polling outside the existing 2 ms guard and
uses a tight RF-only wait to the unchanged RX prepare deadline, rather than
repeated outer-loop snapshots that can overshoot it. Channel setup is also done
early, as in P3. Trace kind 8 records RX arm entry/return times outside the
RX-to-TX response deadline.

The original single-cycle run's optional capture did **not** follow data channels:
its only CONNECT was CRC-bad, and capture needed forced shutdown. Those records
remain unchanged. A new nominal-rate three-cycle capture separately passed valid
CONNECT/bidirectional data/ATT/notifications for every cycle and clean SIGINT
exit0, with finite-run smoke recovery. The capture wrapper explicitly uses a
100 ms serial read timeout; this is not a capture duration or a calibrated air
timing measurement. No TERM/KILL fallback was needed in that run.

The later RX correction separates the latest preamble start (`rx_end_us`) from
full reception (`rx_complete_end_us`). Both initial hardware WINDOW and software
no-capture timeout allow the longest 27-byte LE1M PDU (296 us) to finish; earlier
finite/supervision/terminate/event limits remain authoritative. This is not a
larger SCA/clock-error budget or an assumed exact CLKCAP latency. Model tests
reproduce the old alternating-event misses and cover late starts/time wrap.

That correction's physical run passed all three functional cycles and captured
two complete 1:1 links, but missed one CONNECT and needed SIGTERM during cleanup.
Its combined capture result therefore remains FAIL, despite the firmware result
passing. The earlier all-three capture/clean-stop pass does not establish reliable
whole-run capture or shutdown. Android/iPhone P4, long-run P4 and calibrated IFS
acceptance remain unverified.

## P5 services

On top of the P4 value characteristic, the same image exposes:

- Device Information Service `180A`: Manufacturer Name `2A29` = `wchble`,
  Model Number `2A24` = `ch585-trouble-gatt`, Firmware Revision `2A26` = `p5-0.1`
  (all read-only).
- Nordic UART Service `6E400001-B5A3-F393-E0A9-E50E24DCCA9E`:
  - RX `6E400002-...` (Write): accepts up to 64 bytes in RAM; at MTU 23 the
    client can send at most 20 bytes per Write Request.
  - TX `6E400003-...` (Notify): each accepted RX write is echoed once as a TX
    notification with the same bytes.

The echo is driven only by writes; there is no periodic traffic or UART
flow-control protocol. `HOST_STATS[12..14]` record UART writes, echo
notifications queued, and the last accepted byte count. Standard reads and the
UART pipe stay in the Host/application layer; the radio hot path is unchanged.
ATT MTU remains 23, and the default packet pool stays at 27-byte chunks.

Validation: the native fixture discovers and reads all three DIS fields, then
subscribes to TX, writes `hi` to RX and requires exactly one matching echo
notification (alongside the existing P4 lifecycle). A three-cycle macOS run read
three DIS fields per cycle and echoed `p5-1`..`p5-3`; firmware recorded three
connections/terminations, zero missed events, retries, supervision, TX/RX/stop,
Host or bridge errors, and smoke restoration/discovery passed. Three earlier
client attempts failed on Swift-side discovery/callback ordering before a clean
run; they are retained in the local experiment records. MTU exchange, long data,
and sustained UART throughput remain unverified.

A separate macOS client wrote the six-byte UTF-8 sequence for "中文"
(`e4 b8 ad e6 96 87`) to RX with TX notifications enabled. The write was
acknowledged, exactly one matching six-byte echo arrived, the link stayed up for
three further seconds and then disconnected normally; firmware recorded one UART
write/notification of length six, one normal termination and zero supervision or
TX errors. The native fixture asserts the same six-byte echo. This confirms the
firmware path, not the Android behavior below.

Phone results (2026-11-10, user-reported; no captured peer evidence): on iPhone,
DIS reads, subscription and UART echo all succeeded after the address change.
On Android, reading DIS and enabling notifications worked, but writing the same
six Chinese bytes to `6E400002` disconnected the link. A dedicated window showed
seven UART writes/notifications, one normal termination and three supervision
timeouts with no Host error. The same bytes pass on macOS, so the current working
assumption is an Android/central- or link-specific problem, not a proven
firmware defect; attribution stays open pending an ATT-level capture of that
Android session.

## GATT contract

- Complete local name: `wch585-p4`.
- Static random address: `C1:FF:EE:00:00:15` (changed from `...:14` when the P5
  service database was added, because iOS caches a peer's GATT layout by address).
- GAP service `1800`: Device Name `2A00` and Appearance `2A01` (unknown, zero).
- GATT service `1801`.
- Custom service: `00001000-b0cd-11ec-871f-d45ddf138840`.
- Value characteristic: `00001001-b0cd-11ec-871f-d45ddf138840`.
- Value properties: Read, Write (with response), Notify; CCCD managed by Trouble.
- Value encoding: exactly four bytes, unsigned 32-bit little-endian, initially 0.

The client writes sequence number `n`; readback and each subscribed notification
contain the same `n`, not an independently generated counter. The payload is
four bytes, below the 20-byte ATT payload budget at MTU 23. With notifications
disabled, writes and reads continue normally. Disconnection returns to
advertising; the characteristic value persists for the life of the host future.
The client should enable notifications anew after reconnecting.

The UUID text constants and the corresponding ATT little-endian `Uuid` constants
are exported by `src/host.rs`; clients should use the text form above rather than
formatting the constructor's raw byte array in forward order.

## Host integration and diagnostics

`host::run(controller, &stats)` is one persistent future. Main owns a local
`HostStats`, pins the future once, and polls it only outside radio deadlines.
The host joins Trouble's runner with the advertising/GATT application; no host
poll is allowed to re-enter RF handling. Fatal host/application errors record the
stage and then remain pending instead of spinning inside `poll()`.

`HostStats::word(index)` exposes these single-threaded `Cell` values for archival
by the radio main loop; out-of-range indices return zero.

| Word | Meaning |
| --- | --- |
| 0 | Phase: 0 unpolled, 1 starting, 2 advertising, 3 connected, 255 fatal |
| 1 | Accepted connections |
| 2 | Observed disconnections |
| 3 | Reads of the custom value |
| 4 | Accepted writes to the custom value |
| 5 | Notifications queued by Trouble, not central acknowledgements |
| 6 | Last custom value written |
| 7 | Errors |
| 8 | Last error stage |
| 9 | Other GATT events, including discovery and CCCD access |
| 10 | Current connection's notification subscription (0/1) |
| 11 | Advertising attempts |
| 12 | UART RX writes accepted |
| 13 | UART TX echo notifications queued |
| 14 | Byte length of the last UART write |

Error stages: 1 runner exit, 2 advertising-data encode, 3 scan-response encode,
4 advertise, 5 accept, 6 attribute-server attachment, 7 GATT accept, 8 value
readback, 9 notify, 10 connection-parameter rejection. Stages 9 and 10 are
non-fatal; other stages park the failing task. A malformed/rejected ATT request
that Trouble successfully answers is not itself a host error.

The exported `STATS[64]` retains the P3 radio counters, with P4 magic
`0x50343538`; word 31 is RX backpressure (not automatically a fatal error).
Words 61–63 record the maximum single Host/HCI poll duration in microseconds,
poll deadline overruns, and bridge invariant errors. `HOST_STATS[16]` snapshots
the fifteen Host counters above, followed by one reserved zero word. A 2 ms
pre-poll guard is not a preemptible execution budget; actual poll duration and
wireless deadlines must still be checked on hardware.

The current source converts SysTick HCLK ticks with the nominal HSE/PLL frequency
from `hal::rcc::clocks().sysclk` (62.4 MHz here). The HAL delay estimate uses an
internal low-speed RC reference and is not the preferred rate for a crystal/PLL
clock. Separate conversion/window tests reproduce the approximately 1755 ppm
error seen with the old rate. The earlier successful single cycle used the old
rate; the separate three-cycle regression above validates the functional change.
It does not retroactively alter archived images, reclassify earlier failures, or
validate calibrated clock/IFS compliance.

## Build and validate

Build from this directory with `cargo build --release --locked`. The default
image has a finite 25-second RF budget; `--features long-run` selects 360 seconds.
The runner checks `RUN_SECONDS` in the exact archived ELF before touching hardware.

Run the native real-Trouble fixture **from the repository root**, avoiding this
example's embedded target configuration:

```sh
cargo test --locked --manifest-path tests/trouble-host/Cargo.toml
python3 examples/ch585-trouble-gatt/tools/test_run.py
swiftc -typecheck examples/ch585-trouble-gatt/tools/central.swift
swiftc -typecheck examples/ch585-trouble-gatt/tools/p5_uart.swift
```

`tools/p5_uart.swift` is the manual P5 client: for each cycle it reads the three
Device Information fields, subscribes to UART TX, writes `p5-<cycle>` to RX and
requires exactly one matching echo notification before unsubscribing and
disconnecting. It is intentionally separate from the P4 acceptance runner.

The native fixture covers service/characteristic/CCCD discovery, read/write and
readback, notifications 101–110, more than five real ACL credit cycles, disconnect
with an unacknowledged packet, same-handle reconnect, and subscription reset. It
runs the actual `host::run` and soft HCI bridge, not the radio or a physical client.

On macOS, one controlled physical GATT cycle can be run from the repository root:

```sh
python3 examples/ch585-trouble-gatt/tools/run.py \
  --out local-docs/research/experiments/ch585-p4-unique-run \
  --run-seconds 25 --cycles 1 --timeout 20
```

Use a new output directory for every attempt. This command flashes the fixed
probe `1a86:8010:F93D8F067E10`, archives both ELF images and their hashes, runs the
CoreBluetooth client, waits the complete finite budget plus three seconds before
probe reads, and finally restores smoke and checks exact-name `wch585` discovery.
A failed run is retained, not automatically retried. The client discovers the
custom service and characteristic, performs three write/readback pairs, subscribes
and checks ten numbered notifications, unsubscribes, reads back 110, and waits for
its expected disconnect. No phone client should run concurrently.

The runner does not start the optional nRF Sniffer itself. `tools/capture.py`
wraps the same safe runner with capture of `C1:FF:EE:00:00:15 random`. Confirm the
sniffer's USB serial and current port before using it; the following paths are
local installed-tool examples, not fresh-machine installation instructions:

```sh
python3 examples/ch585-trouble-gatt/tools/capture.py \
  --sniffer /tmp/wchble-nrfutil-state-20261109/bin/nrfutil-ble-sniffer \
  --nrfutil-home /tmp/wchble-nrfutil-state-20261109 \
  --sniffer-port /dev/cu.usbmodem21301 \
  --sniffer-serial 8D4391AA608D9EE4 --serial-timeout-ms 100 \
  --out local-docs/research/experiments/ch585-p4-unique-capture \
  --run-seconds 25 --cycles 3 --timeout 20
```

The experimental wrapper flag `--follow-by-name` keeps scanning until `wch585-p4`
appears after flashing, instead of sending an address-follow request while the
board is still smoke. Name mode enables scan-response following because the
local name is in SCAN_RSP; analysis still requires the fixed target address and
actual connection/data packets. Scan startup is not declared connection success.
The first physical name-mode comparison did not follow all links and failed its
capture gate; it is not a proven repair or the default mode.

`--serial-timeout-ms` controls serial reads, not the capture duration. Capture
startup and shutdown are bounded; loss of capture never shortens the firmware's
safe budget/recovery sequence. The outer `capture-result.json` reports functional,
capture and shutdown gates separately; the original `run/result.json` remains the
independent client/firmware/recovery result. Capture requires a CRC-valid target
CONNECT for every requested cycle, both CRC-valid data directions, actual ATT
reads/writes and the notification sequence. An advertisement or CRC-bad CONNECT
is not connection-following success. SIGTERM/SIGKILL shutdown fallback is retained
as unclean, never silently promoted to a pass. Offline helper tests:
`python3 examples/ch585-trouble-gatt/tools/test_capture.py`.

Build/native success, macOS GATT acceptance, Android/iPhone acceptance, sustained
reliability, and calibrated air timing are separate validation claims.

## Separate phone acceptance

Use a dedicated finite phone-only firmware window, not a concurrent Mac central.
The normal runner above always starts the Mac client; do not use it as a phone
launcher. A separately built `long-run` image provides a 360-second budget, but
still requires the same deferred probe collection and smoke recovery policy.
Test Android and iPhone in separate windows so the observed peer has unambiguous
platform attribution. Neither platform is accepted just because its UI connects.

For each of three connect/discover/read/write/disconnect/reconnect rounds in
nRF Connect, select `wch585-p4` and the custom service/characteristic above:

1. Read the four-byte value; it may retain the previous connection's last value.
2. Send a **Write Request (with response)** of hex `01 00 00 00`; read back the
   same bytes. Do not select Write Command or assume a text/decimal encoding.
3. Enable notifications, then write u32LE sequence values 101–110 (`65 00 00 00`
   through `6e 00 00 00`), checking exactly one matching notification per write.
4. Disable notifications, write another four-byte value and read it back; no
   notification should arrive while disabled.
5. Disconnect explicitly, reconnect and verify the value persists and CCCD
   subscription starts disabled. Enable notifications again only when requested.

Keep the phone operation log/platform separate from captured address attribution.
A timeout before discovery, repeated LL control exchange, missing ATT response,
wrong value and notification failure are different outcomes and must not be
collapsed into one generic GATT failure. No automatic retries should erase a
failed round.
