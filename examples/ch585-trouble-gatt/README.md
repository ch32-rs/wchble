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
`default-packet-pool-mtu-128` are enabled. A 27-byte pool cannot reassemble the
65-byte P-256 public key that LE Secure Connections exchanges, so the secure
build needs the larger pool; the non-secure build shares it. No derive macros,
executor, or HAL Embassy/SysTick time driver are enabled. The build and RAM-copy
linker fragment are inherited from the P3 peripheral example.

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
Android. A separate manual iOS observation with the third-party nRF Connect
client (P4/P5 image, not the S2 secure image) also reported success: read,
Write Request/readback,
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
The link starts at ATT MTU 23; a client may exchange MTU up to 124 (the
128-byte packet pool limit, see X4 below). The UART echo still accepts at most
20 bytes per Write Request at MTU 23 because it does not split writes.

Validation: the native fixture discovers and reads all three DIS fields, then
subscribes to TX, writes `hi` to RX and requires exactly one matching echo
notification (alongside the existing P4 lifecycle). A three-cycle macOS run read
three DIS fields per cycle and echoed `p5-1`..`p5-3`; firmware recorded three
connections/terminations, zero missed events, retries, supervision, TX/RX/stop,
Host or bridge errors, and smoke restoration/discovery passed. Three earlier
client attempts failed on Swift-side discovery/callback ordering before a clean
run; they are retained in the local experiment records. MTU exchange and long
data are covered by the X4 round below; sustained UART throughput remains
unverified.

A separate macOS client wrote the six-byte UTF-8 sequence for "中文"
(`e4 b8 ad e6 96 87`) to RX with TX notifications enabled. The write was
acknowledged, exactly one matching six-byte echo arrived, the link stayed up for
three further seconds and then disconnected normally; firmware recorded one UART
write/notification of length six, one normal termination and zero supervision or
TX errors. The native fixture asserts the same six-byte echo. This confirms the
firmware path, not the Android behavior below.

Phone results (2026-11-10, user-reported; no captured peer evidence): on iPhone,
DIS reads, subscription and UART echo all succeeded after the address change.
On Android, reading DIS and enabling notifications worked, but any write to
`6E400002` (`hello` or the same six Chinese bytes) disconnected the link. An
address-followed sniffer capture reproduced this on two Android links: the
firmware accepted each write and queued the echo, but the Android central never
acknowledged the echo notification at link layer (its NESN never changed) and
stopped sending new packets. The peripheral retransmitted the identical,
well-formed notification once per 30 ms event for 4.95 s until the Android
requested 5 s supervision timeout expired. The short ATT Write Response was
acknowledged; only the longer UART notification was not. The two iPhone links in
that window performed discovery only, so an OS-specific cause is not yet proven;
the same echo passes on macOS and in the native fixture.

## X4: ATT MTU, long data and queue pressure

The vendor service `00001000-...` adds three fixtures on top of the P4/P5
characteristics, all with the same access level as the value characteristic
(`EncryptionRequired` in the `secure` build, open otherwise):

- Bulk `00001005-...`: Read + Write, 200-byte value. The server fills it with a
  fixed pattern (`index * 7 + 3`); a client overwrite is verified against the
  frozen copy inside the Host poll.
- Burst `00001006-...`: Read + Notify, 121 bytes (`MTU - 3` at MTU 124, so each
  notification is one full ATT PDU).
- X4 control `00001007-...`: Write, 4 bytes. Writing `BST!` queues twelve
  back-to-back burst notifications in the same Host poll with
  `try_notify_raw`; the application never blocks, waits, or retries.

`X4_STATS[16]` (exported symbol) records magic `0x58340001`, version, the
negotiated MTU, bulk read/write counters, the stored length and checksum, the
read-back comparison result, and burst attempts/queued/queue-full counts. The
acceptance criteria live in `tools/secure_run.py` (`att` mode): MTU above 23,
`ReadBlobReq/Rsp` and `PrepareWriteReq/Rsp` + `ExecuteWriteReq/Rsp` on air, a
200-byte read-back match, at least one queued and one queue-full burst
notification, and the usual security/clean-stop checks.

The packet pool is 128 bytes (`default-packet-pool-mtu-128`), so the server
cannot promise more than MTU 124. A 200-byte attribute therefore needs Read Blob
for the read and Prepare/Execute queued writes for the write; both are counted
by `SEC_OPCODES`, so platform behaviour is proven on air rather than inferred
from the app.

Android result (CPH2411, 2026-11-13): MTU 124, `ReadReq` 2 + `ReadBlobReq` 2,
`PrepareWriteReq` 2 + `ExecuteWriteReq` 1, 200-byte write read back identical,
and a 12-attempt burst that queued 7 notifications and hit a full queue 5 times;
the app received all 7 × 121 bytes. Firmware reported no refused PDU. Details
and the earlier failed rounds are in
[`local-docs/research/ch585-x4-att-results.md`](../../local-docs/research/ch585-x4-att-results.md)
(local experiment records).

That investigation found a real link-layer defect: an Android Central sends
28-octet encrypted PDUs (24 plaintext + MIC) even without DLE, and the LL used
to refuse anything above the legacy 27-octet size. A refused PDU was not
acknowledged at all, so the peer retransmitted until supervision timeout. The
fix is `ll::enc::MAX_ENCRYPTED` (27 plaintext + MIC) as the one ceiling used by
`ll::acl`, `ll::conn`, `ll::central` and the firmware receive gate. The gate
also stores the first refused PDU header/length in `SEC_DIAG[63]`
(`1 | header << 8 | len << 16`); the `att` gate fails the run if any sample
appears.

## X1: CSA #2 and bidirectional DLE

The controller advertises `LE Data Length Extension` and `CSA #2` (and
`Encryption` in the `secure` build) from startup; 2M/Coded stay unset because
the PHY switch is not implemented. Advertising PDUs and CONNECT_IND carry
ChSel, and the link uses CSA #2 only when both sides set it. The same
algorithm runs in the central example; both are checked against the Core
sample vectors in `src/ll/conn.rs`.

DLE is fully bidirectional: `LE Read Buffer Size` reports 251 octets and five
credits, the LL splits each Host ACL packet at the negotiated on-air size
(27 octets until the peer answers), and only the last fragment returns the HCI
credit. `LL_LENGTH_REQ/RSP` fields are payload octets (Core 5.4 Vol 6 Part B
4.5.10), so the controller advertises 247 and adds the 4-octet MIC on air; the
peer's declared payload is likewise accepted plus MIC (an Android Central that
advertises 128 sends 132 octets once encrypted). Encryption runs per fragment.
Receive windows and the software no-capture timeout scale
with `rx_complete_allowance_us()`, and the pre-negotiation receive limit stays
31 octets so the observed 28-octet Android PDU is still valid.

`X1_STATS[24]` (exported symbol, magic `0x58310001`) records the negotiated
algorithm, event counter, both ChSel bits, `LL_LENGTH_REQ/RSP` counts in both
directions, effective TX/RX octets and times, largest TX/RX PDU, >27 counts,
Host fragments and segmented Host packets, PDUs sent/received, whether the
peer feature set is known, and `last_error`. `secure_run.py` validates it on
every run; `--require-dle` additionally demands a feature exchange, at least
one PDU above 27 octets in each direction, and at least one segmented Host
packet. Host buffer credits are still 5 per direction.

## GATT contract

- Complete local name: `wch585-p4`.
- Static random address: `C1:FF:EE:00:00:18` (changed from `...:16` for X4,
  because iOS caches a peer's GATT layout by address and a stale bond/cache
  must not be reused).
  Since S3 the address is fixed across boots so a peer can reuse its bond (see
  S3 below); only a GATT database change moves it.
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

## S2: LE Secure Connections (feature `secure`)

`--features secure` enables `trouble-host/security` (RustCrypto AES-128,
CMAC, P-256) and adds the controller side of the peripheral start-encryption
procedure. It is a separate finite-run acceptance image; the default build is
the P4/P5 image.

What the image does differently:

- Seeds the controller DRBG and a separate Host RNG stream from measured ADC
  temperature noise, and refuses to advertise when the health check fails.
- Advertises LE Encryption with the legacy HCI ACL buffer of 27 plaintext
  octets; encryption adds the 4-octet MIC for a 31-octet on-air payload. A
  peer without DLE can legitimately send 28-octet encrypted PDUs (see X4).
- Owns `LL_ENC_REQ`/`LL_ENC_RSP`, the Host's `LE LTK Request` reply, the
  plaintext `LL_START_ENC_REQ`, and the encrypted `LL_START_ENC_RSP`. All
  AES-CCM runs outside the connection event: TX is encrypted before the
  event, RX is decrypted after it. The CH585 AES block shares registers with
  the RF IP, so the engine reloads the key before every CCM operation.
- Uses a fixed static random address (`C1:FF:EE:00:00:18`,
  `host::RANDOM_ADDRESS`) so a peer can find the bond it saved on an earlier
  boot. S2 rotated the address because it had no bond store; X4 moved it again
  because the GATT database changed. A phone that bonded an older address must
  forget it once.
- Exposes `SECURE_STATS[16]` (ENC_REQ/RSP, LTK request/reply, START_ENC
  request/response, encrypted TX/RX, active, MIC failures, errors, entropy
  flags) and `SEC_DIAG` with the packed ACL ring, the last HCI commands and
  command responses, and word 63 = the first refused data PDU
  (`1 | header << 8 | len << 16`, zero when none was refused).

Acceptance (Just Works, no MITM protection): the phone must report
`BOND_BONDED` and then complete an encrypted read/write/read-back; the Host
`SECURITY` state must be `Encrypted`; and a passive capture must contain the
SMP exchange, `ENC_REQ`/`ENC_RSP`/`START_ENC_REQ`, and no decodable ATT PDU
after the encryption start. Connecting without encryption is not acceptance.

`tools/secure_run.py` drives the Android client (`tools/android-pair`) and
takes `--mode pair|reconnect|delete|wipe|fault|att` plus `--reject` (expect the
reconnect to be refused). `tools/secure_capture.py` wraps it with the sniffer;
its `--mode` also gates the pcap (reconnect/fault forbid new SMP frames,
delete/reject require `LL_REJECT_IND`). The capture wrapper starts the sniffer
only after the probe flash (so the firmware is already advertising) and
follows the fixed address; `--follow-by-name` alone races the sniffer's
one-shot name lookup. Both runners flash with the single-session preflight
helper and restore the smoke image in a `finally`.

Android 15 (CPH2411) passed this matrix on 2026-11-12. The iOS round has not
been attempted and is tracked in the backlog: this repository has no iOS
client, and the test iPhone (registered with the Mac as `mono@iphone`, not
bonded to this firmware) is offline. The iOS acceptance client is nRF Connect,
already installed on that phone and used for the P5 manual checks. S2 is
accepted on the Android evidence only; do not describe the iOS support as
verified.

## S3: bond persistence (feature `secure`)

The secure image keeps its bonds across resets and power loss.

- `wchble::storage::DualCopyStore` writes the bond list to one of two
  DataFlash pages (`0x7E00`, `0x7F00`). Each copy has a 24-byte header with a
  payload CRC32, header CRC32 and wrap-safe sequence number; the previous copy
  stays valid until the new one has been read back. Deletion writes a
  zero-length tombstone (higher sequence) before erasing the old page.
- Sequential payload version 2 starts with the local random address and its
  kind. A store written by an image advertising a different identity is read
  and ignored (`BOND_STATS.load_result = 4`, `records_loaded = 0`) instead of
  being served to the peer, which used to end pairing in `DHKeyCheck`. The old
  version is not migrated; the first boot after this change starts empty.
- A second dual-copy store (`0x7C00`, `0x7D00`) keeps each bonded peer's raw
  `ClientAttTable` under the same local identity. The Host applies it after
  `with_attribute_server` (before that call `set_client_att_table` is a silent
  no-op) and snapshots after an accepted CCCD write or on disconnect. `DEL!`
  and `WIPE` clear both stores, one flash operation per flush call.
  `CATT_STATS[16]` reports load/restore/snapshot/save outcomes; a table whose
  bytes do not read back unchanged is counted invalid and not applied.
- The CH585 backend (`Ch585DataFlash`) uses the DataFlash command path
  (`0x81` erase, `0x02` program, `0x0B` read) from `.highcode` RAM with
  interrupts masked; the safe-access window is only a few system clocks.
  DataFlash is not memory-mapped: `ch585-preflight --dump-dataflash` reads it
  through the target's `ch5xx-data-flash` algorithm, never `probe-rs read`.
- The Host restores bonds before advertising and answers the controller's LTK
  request from the bond table. A new bond is saved from `PairingComplete` in
  the idle path, deferred while the next RX prepare is within the measured
  save time plus 2 ms (never below 8 ms), and forced on disconnect, with no
  session, or at the end of the run. The value characteristic requires
  encryption; night-time reads no longer rely on the peer.
- `BOND_STATS[32]` and `BOND_ECHO[16]` expose load/save/clear counters, the
  winner slot/sequence, the key the Host used and the local identity the
  record was written under, so the runner can compare the DataFlash dump with
  the live session. `CATT_STATS[16]` covers the client ATT store.
- A test-only control characteristic (`00001002-b0cd-11ec-871f-d45ddf138840`)
  takes `DEL!` (remove + tombstone), `WIPE` (erase both slots) and `FALT`
  (truncate the next save; needs `--features bond-fault`). It is deliberately
  unauthenticated so a peer can clear a stale bond it cannot use, so it only
  exists in images built with the non-default `accept-control` feature
  (`--features secure,accept-control`; `bond-fault` implies it). A `secure`
  product image does not expose it. `DEL!`/`WIPE` also discard any bond
  snapshot queued before the command, so a deferred save cannot recreate a
  deleted bond.

Measured on hardware: a save takes about 22 ms and erasing both pages about
35 ms; boot reads take 25-39 us for an empty store, 121-128 us for a valid
record and about 1.2 ms when one slot must be rejected. Android 15 evidence is
in `local-docs/research/ch585-s3-results.md`: reset and real unplug both
resumed the stored key without pairing, deletion produced
`LL_REJECT_IND(0x06)` and a later pairing wrote a new record, and a truncated
save fell back to the previous copy.

`tools/bond_accept.py PHASE --out DIR` runs one phase per invocation
(`wipe`, `pair`, `reconnect`, `delete`, `repair`, `fault`, `powercycle`) with
the phone app in `--es mode`. `--dataflash-addr/--att-addr` select the bond and
client ATT stores for the dump; `reconnect` requires the stored client ATT
table to be applied. The acceptance image is built with
`--features secure,accept-control` (`bond-fault` for the `fault` phase). `pair` and `fault` keep the image in flash so
`reconnect`/`powercycle` are a reset or a real power cycle without a download;
every other exit restores and scans the smoke image. The `delete` phase expects
the operator to forget the bond on the phone before `repair`.

## Build and validate

Build from this directory with `cargo build --release --locked`. The default
image has a finite 25-second RF budget; `--features long-run` selects 360 seconds.
The runner checks `RUN_SECONDS` in the exact archived ELF before touching hardware.

`--features conn-params-30` / `conn-params-48` are test-only builds used to
separate phone-controller behavior from connection-interval effects. Once per
connection, on the first GATT write, they send an L2CAP Connection Parameter
Update Request for 30 ms or 48.75 ms and record the send result in host stats
word 15. They never change the default image. The radio `STATS[45]`
(`last_interval`) is the CONNECT_IND interval, not the current one; confirm a
later update from the air cadence or a dedicated counter.

Run the native real-Trouble fixture **from the repository root**, avoiding this
example's embedded target configuration:

```sh
cargo test --locked --manifest-path tests/trouble-host/Cargo.toml
python3 examples/ch585-trouble-gatt/tools/test_run.py
python3 examples/ch585-trouble-gatt/tools/test_capture.py
python3 examples/ch585-trouble-gatt/tools/test_bond_accept.py
python3 examples/ch585-trouble-gatt/tools/test_secure_run.py
python3 examples/ch585-trouble-gatt/tools/test_secure_att.py
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

The secure image uses the same output path as the default build, so rebuild
with the feature right before the run (`tools/secure_run.py` refuses an ELF
without the crypto backend):

```sh
cargo build --release --features secure
python3 tools/secure_capture.py \
  --out local-docs/results/s2-run-<unique> \
  --sniffer /tmp/wchble-nrfutil-state-20261109/bin/nrfutil-ble-sniffer \
  --nrfutil-home /tmp/wchble-nrfutil-state-20261109 \
  --sniffer-port /dev/cu.usbmodem21301 --follow-by-name \
  --run-seconds 60 --timeout 50 --full-logcat
```

The pairing dialog on Android needs one manual confirmation; the runner taps
it and records the action. Use a new output directory for every attempt.

The X4 MTU/long-data round uses the `att` mode of the same runner (from the
example directory, after `cargo build --release --features secure`):

```sh
python3 -I tools/secure_run.py --mode att --run-seconds 60 --timeout 55 \
  --out local-docs/results/x4-att-<unique>
```

It requires a bonded peer, negotiates MTU, drives the 200-byte read/write and
the `BST!` burst, and fails on a malformed transcript, a missing air opcode,
`burst_queue_full=0`, or any refused-PDU sample in `SEC_DIAG[63]`.

The runner does not start the optional nRF Sniffer itself. `tools/capture.py`
wraps the same safe runner with capture of `C1:FF:EE:00:00:18 random`. Confirm the
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
