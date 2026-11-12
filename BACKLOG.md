# CH585 BLE bring-up backlog

Updated 2026-11-12. These are open defects, evidence gaps and acceptance work,
not features implicitly promised by the current example. Keep functional,
capture, recovery, platform and compliance results separate. Do not retry away
failures or retroactively change archived results.

## Current baseline

- P2 scannable advertising has independent on-air validation.
- P3 connect/hold/disconnect passed ten 10-second cycles and a finite 360-second
  run. After the nominal-clock and RX-completion fixes, a separate three-cycle
  3-second-hold regression passed with smoke restoration/discovery.
- P4 uses the real Trouble Host, bounded single-connection HCI/ACL bridge and
  actual LL-ACK-based credits. The native real-Host lifecycle fixture passes.
- Two isolated P4 macOS runs each passed five complete discovery/read/write/
  notify/unsubscribe/disconnect/reconnect cycles: 25 reads, 65 writes and 50
  independently checked notifications per run. Finite RF finish and smoke
  restoration/discovery passed. Neither run passed its whole-run capture gate.
- C1 central (`examples/ch585-central`) passed two isolated macOS positive runs
  and three isolated Android positive runs (CPH2411, Android 15), plus the
  Android five-phase runner (positive, three negatives, bogus peer) and a
  `peer-vanish` phase. CONNECT_IND is hardware-timed by the LLE;
  `CONNECT_OFFSET` is 0. P3 and P4 one-cycle regressions passed afterwards.

See [`examples/ch585-trouble-gatt/README.md`](examples/ch585-trouble-gatt/README.md)
for the GATT contract, test commands, counters and detailed validation boundaries.
Raw captures and experiment records remain local; they are not required to build.

## Resolved: safe pre-flash stop

- [x] **Single-session preflight (`tools/ch585-preflight`).** Standalone
  `probe-rs read` resumes all cores, so the old separate stop/idle reads could
  rearm RF. The helper halts once, performs engine shutdown, requires two zero
  CMD acknowledgements, then verifies the download and starts the image; any
  nonzero/missing acknowledgement refuses the download. Test and recovery
  flashes use it. Built against the pinned sibling probe-rs checkout because the
  published 0.32.0 target list predates CH585.
- [x] **Re-validated on hardware:** smoke flash/start/discovery, then two clean
  three-cycle macOS P4 acceptance runs (three connections, fifteen reads,
  thirty-nine writes, thirty notifications, zero missed/retry/supervision/bridge
  errors, smoke recovery). The earlier refusal and direct-flash phone window
  remain archived as separate attempts.
- [ ] **Supervision-timeout recovery is still untested.** The Mac central never
  withholds LL acknowledgements, so the planned phone walk-away/disconnect case
  remains open.

## Priority: independent phone acceptance

- [x] **First manual Android check (2026-11-10):** the user reports all five
  requested operations succeeded in a directly flashed 360-second window. Board
  counters show four accepted connections/disconnects, six reads, five writes,
  five queued notifications, `0xAAAAAAAA` final value and no Host/RF error.
- [x] **First manual iPhone check (2026-11-10):** the user separately reports a
  successful iOS attempt. It shares the same window's counters, so attribution
  rests on the user's UI observations rather than captured peer evidence.
- [x] **Multi-round acceptance via controlled Mac central (2026-11-10).** By
  project decision, repeated rounds use the scripted Mac client instead of
  repeated manual phone operation. Two clean three-cycle runs passed every
  read/write/notification/unsubscribe/disconnect/reconnect step with zero missed
  events or retries. This does not replace the separate one-round platform smoke
  checks above.
- [ ] **Optional deeper per-platform rounds:** if a platform-specific defect is
  suspected, repeat three isolated phone rounds with ten notifications each and
  no competing central. Not required by the current Mac-centered acceptance plan.
- [ ] **Classify any phone connection/discovery failure from evidence.** An
  uncontrolled phone attempt saw services but did not complete the intended
  workflow. This is neither acceptance nor proof of interference. Retain the
  phone operation log and platform separately from peer-address attribution;
  distinguish LL ACK/control stalls, missing ATT responses and UI symptoms.

Acceptance requires the phone's received values, not just Host notification
queue counters or a connected UI. Use a dedicated 360-second firmware window;
never use the automated Mac runner as a phone launcher. No runtime probe access;
collect after the complete finite budget plus margin, then restore smoke and
confirm exact-name discovery. A capture failure must not erase an independent
functional result or shorten the safe wait.

## Priority: reliable sniffer evidence

- [ ] **Whole-run connection following remains intermittent.** One three-cycle
  run captured all three valid CONNECTs, both data directions and ATT/notification
  sequences. A later three-cycle run captured only two complete links. Two newer
  five-cycle runs passed GATT but captured zero target CONNECTs, or one CRC-valid
  CONNECT with no data, respectively. Name-follow with scan-response following
  is an experimental comparison, not a proven repair.
- [ ] **Orderly sniffer shutdown is not consistently established.** Some runs
  exit cleanly on SIGINT; others require TERM/KILL. Keep bounded cleanup and
  report forced shutdown as unclean, even when the firmware/client passes.

Acceptance: for every requested connection in a controlled run, record a
CRC-valid target CONNECT, bidirectional CRC-valid data, the actual ATT exchange
and received notification sequence; stop cleanly within the SIGINT budget.
Startup/configuration logs alone are not proof of following. Do not weaken
capture checks, trim malformed PCAP tails, or blindly repeat until a pass.

## P5 service expansion gaps

- [x] **Device Information + UART echo v1:** standard DIS reads and a Nordic
  UART-style write/notify echo run in the Host/application layer. Native fixture
  and a three-cycle macOS run pass.
- [ ] **ATT MTU negotiation and long data:** the image still fixes MTU 23 and a
  27-byte packet pool. MTU exchange, longer writes, L2CAP fragmentation and
  reads across multiple ACL packets are unimplemented/unvalidated.
- [ ] **UART flow and throughput stress:** bursts beyond the Host credit window,
  backpressure with large payloads, and sustained bidirectional throughput are
  not tested. The current echo accepts at most 20 bytes per write at MTU 23.
- [ ] **Certain phone models: BLE link stability (2026-11-10):** some Android
  models lose bursts of peripheral PDUs and can drop the link. The visible
  symptom is the UART echo test: writing `hello` or UTF-8 "中文" to `6E400002`
  with TX notifications enabled disconnects on the affected phones. An
  address-followed sniffer capture reproduced it on two Android links (30 ms
  interval, 5 s supervision): the firmware accepted each write and queued the
  echo, but the Android central never acknowledged the echo notification at LL
  level (its NESN never changed) and stopped sending new packets. The
  peripheral retransmitted the identical, well-formed notification PDU (~165
  times over 4.95 s) until supervision timeout. The short Write Response was
  acknowledged; only the longer UART notification was not. The two iPhone links
  in that window performed discovery only, so OS specificity is not proven. The
  same echo passes on macOS and in the native fixture. Evidence:
  `local-docs/research/experiments/ch585-p5-android-capture-3/`.

  Follow-up (2026-11-10): the failing links all settled at 30 ms while the
  working CPH2411 used 48.75 ms, so a test feature was added to request a fixed
  interval over L2CAP (`conn-params-30`/`conn-params-48`, not in default
  builds). CPH2411 accepted the 30 ms request, and ten writes at 30 ms all
  echoed with zero retries; **the interval hypothesis is rejected**. At the
  same RSSI (-51 dBm) the failing phones lose bursts of eight to twelve
  peripheral PDUs even during discovery, while CPH2411 loses none, so the
  remaining question is the failing controllers' receive behavior and
  controller-to-host delivery. An HCI snoop bugreport for the failing PJZ110
  was generated on-device (file under
  `/data/user_de/0/com.android.shell/files/bugreports/`) but not yet pulled.
  Next: pull it, and capture a failing phone on the sniffer together with the
  enhanced probe (phone-side RSSI, repeated writes). Do not treat this as a
  firmware defect or an accepted phone behavior until one of those runs
  explains it. Evidence: `local-docs/research/experiments/ch585-app-conn30-*/`.

## Sustained radio/Host reliability

- [ ] **P4 sustained connection and long-run traffic:** short five-cycle runs do
  not establish multi-minute stability. Validate a finite long-run image with
  measured client hold/traffic duration, firmware timing, supervision/late/error
  counters, reconnect and safe recovery. Building a 360-second image is not
  on-device long-run acceptance.
- [ ] **P3 historical 120-second joint failure:** the Mac hold completed, but
  firmware duration and a later extra connection failed acceptance. Clock and
  RX fixes need a new controlled long-hold regression; they do not change the
  historical failure to a pass.
- [ ] **Historical phone LL-control/ACK stalls:** the earlier P3 mixed-platform
  window included repeated feature-control exchanges and supervision timeouts.
  Recheck only if reproduced in an isolated current-image window; do not assign
  captured peer addresses to a phone OS by operation order or assume GATT alone
  explains the symptom.

## Timing, resources and observability

- [ ] **Calibrated air timing/compliance:** nominal 62.4 MHz HSE/PLL conversion
  fixes the RC-reference scaling error, but does not calibrate oscillator error,
  RF-start latency or 150 us IFS. CPU RX_DONE/command timestamps and sniffer packet
  deltas are not a calibrated compliance result. Retain current deadline and
  SCA limits; do not fit arbitrary delays/ppm just to pass.
- [ ] **Host scheduling bounds and stack headroom:** the observed maximum poll
  of 987 us is not a WCET proof. The 2 ms guard cannot preempt `Future::poll`.
  Measure runtime stack high-water and loaded-path poll/prepare overruns before
  claiming robust scheduling/resource margin.
- [ ] **Physical-run queue/credit diagnostics:** native fixtures cover real
  five-slot credit recycling, backpressure, disconnect and stale-tag isolation.
  Add bounded queue high-water/credit-ledger observations for physical stress
  runs; current packet/Host counters do not provide these metrics.

## Reproducible builds and regression coverage

- [ ] **Sibling checkout provenance:** P4 requires the documented local Trouble
  revision (bt-hci 0.11) and executable lockfile. Document/reproduce matching HAL
  and Trouble checkouts on a fresh machine; the same registry version name is
  not a compatible substitute. Do not silently resolve new dependencies.
- [ ] **Original V208 example locked-build drift:** its sibling HAL metadata
  changed a metapac path dependency to a pinned Git source. An isolated adjusted
  copy built successfully, but the original example's locked build remains an
  unresolved reproducibility gap. Repair and validate deliberately, without
  unrelated lockfile regeneration or claiming the original command passed.

## C1 central gaps

- [ ] **Repeated but short rounds:** two macOS and three Android positive runs
  (three cycles each) passed, but this is not multi-minute stability. Longer
  holds and repeated phone rounds keep late/retry/supervision counters under
  observation.
- [ ] **Unexplained short-run freeze (2026-11-11):** one 25-second Mac run
  stopped updating firmware counters after the connection phase while the Mac
  logged three GATT cycles. Not reproduced in five later runs. A panic-location
  recorder now writes `STATS[63]`/`STATS[59]`; no diagnosis exists yet.
- [ ] **On-air supervision timeout:** the `peer-vanish` phase (adapter off,
  first ATT read held) ended through an Android `LL_TERMINATE_IND`
  (`remote_term=1`, `supervision=0`). No controlled peer goes silent without
  terminating, so supervision expiry is covered only by unit tests. Record the
  mechanism rather than relabelling the result.
- [ ] **Test-only link constants:** AA `0x12345678` and CRCInit `0x00555555` are
  fixed for the test sources. Production operation needs a real access-address
  and CRC policy, not a claim that this configuration is interoperable.
- [ ] **Android CCCD requirement:** `BluetoothGattServer` does not synthesize
  `0x2902` for a NOTIFY characteristic; the test source publishes it. Verify
  any future Android-based acceptance source does the same instead of treating
  the first failure as a controller defect.

## Security gaps (S2/S3)

- [ ] **iOS round never started (backlogged 2026-11-12 by project decision).**
  No iOS client exists in this repository and none was ever installed on the
  phone; the devicectl entry `mono@iphone` is a Mac development registration,
  not a bond. The intended client is the nRF Connect install already used for
  the P5 manual checks. Requires, on a live iPhone: Just Works pairing
  (system dialog), `dumpsys`-equivalent bond evidence or app-level bond state,
  an encrypted read/write, and a capture with no plaintext ATT. Do not claim
  cross-platform LESC support until this closes.
- [ ] **Android evidence is one green run.** Run53 (2026-11-12) is the only
  clean end-to-end record: bonded, encrypted read/write with every ATT status
  0, `SECURE_STATS` encryption counters, and a capture with ciphertext after
  `START_ENC_RSP`. It does not establish repeatability across boots, per-model
  behaviour, MTU above 23, or an encrypted notification path.
- [x] **Bond store (S3, 2026-11-12).** Two DataFlash pages, 24-byte header with
  payload/header CRC32 and a wrap-safe sequence, a zero-length tombstone for
  deletion, and the whole engine sequence in `.highcode` RAM with interrupts
  masked. The address is now fixed (`C1:FF:EE:00:00:16`) so a peer can find the
  key it stored on an earlier boot. Hardware evidence: probe reset and a real
  USB unplug/replug reconnect encrypted with `pairs_complete=0` and
  `save_attempts=0`; deletion produced `LL_REJECT_IND(0x06)` with
  `start_req=0`, then a fresh pairing wrote a new record; a truncated save left
  the older copy valid and the reboot loaded it (`winner_seq` unchanged). See
  [S3 results](local-docs/research/ch585-s3-results.md).
- [ ] **Air capture of the post-delete rejection.** Android re-pairs within the
  same app run after the peripheral rejects the stale key (`BONDED→BONDING→
  BONDED`), so the sniffer's first followed link shows the new pairing, not the
  `REJECT_IND`. The rejection is proven by firmware counters
  (`last_error=0x06`, `start_req=0`) and the phone's ATT 0x85, not on air.
- [ ] **Multi-bond and resolving list.** The store holds up to four records per
  slot and keeps the IRK field, but only one peer, one record and no RPA
  resolution were exercised on hardware. Capacity and IRK round-trip are
  host-tested only. A full table also has no admission policy: Trouble's
  `add_bond` returns `OutOfMemory` before `PairingComplete`, so a fifth peer
  fails at DHKeyCheck until a slot is freed. Define eviction/admission before
  insertion rather than evicting a trusted peer on an arbitrary attempt.
- [ ] **Bond write scheduling and durability policy.** A save takes ~22 ms; the
  deferral guard is `max(observed + 2 ms, 8 ms)`, so at intervals <= 24 ms
  nothing is persisted while connected (only on disconnect), and `WIPE`'s
  ~35 ms erase raises the guard for the rest of the boot. A cap at
  `interval/2` cannot make a 22 ms synchronous flash operation fit a 7.5 ms
  budget; the policy needs an explicit scheduling/durability decision.
- [ ] **Store hardening from the S3 review.** `erase_all()` erases slot 0
  before slot 1 (unlike the tombstone-first `clear()`); `new()` + `save()`
  without `load()` can resurrect an older higher-sequence record; `load()`
  computes the payload CRC through the caller buffer, aborts on one slot's
  read error instead of trying the other, and treats a version mismatch as
  empty; `save()` reads back only the 24-byte header, not the payload. Fix
  together with a mock flash that completes but corrupts a payload byte.
- [ ] **Bonded CCCD persistence.** `PersistedBond` does not store client ATT
  state, so a bonded peer's CCCD subscription disappears on reboot (Core 5.4
  Vol 3 Part G §3.3.3.3). The pinned Host exposes
  `get/set_client_att_table`; without this, #7's HID keyboard can resume
  encryption after reboot with notifications still disabled.
- [ ] **Bond record security at rest.** The LTK is stored in plain DataFlash;
  SWD/probe reads it. Acceptable for bring-up, not claimed as tamper-resistant
  (security spec §2).

## X4b HID (encrypted-link keyboard)

- [ ] **Android system-HID round not yet executed.** This is the only host
  round that exercises the real `0x1812` subscription and reports; it needs one
  Just Works confirmation tap and a focused text field. Firmware counters,
  `dumpsys input` and a screenshot are the evidence. The 60 s macOS runs do not
  replace it.
- [ ] **macOS cannot audit HID bytes.** CoreBluetooth filters `0x1812` from
  third-party discovery (Apple Accessory Design Guidelines, GATT Server
  section) and bluetoothd checks an unsigned CLI in with
  `fProgrammaticPairing 0`, so no pairing dialog or encrypted access is
  possible. The diagnostic mirror and client support a bonded host, but that
  path was never exercised on macOS.
- [ ] **Only a keyboard Report Map is implemented.** Consumer-control and mouse
  collections, output reports beyond the LED byte, and multiple Report IDs are
  absent.
- [ ] **Encrypted ATT is not decodable in captures.** The sniffer sees SMP and
  LL encryption but cannot read reports without the stored LTK; the
  `--sc-ltk-key` path was not wired into the runner.
- [ ] **The example duplicates the ~2100-line P4/P5 pump.** Extraction belongs
  to L0; the copied example is a validation artefact, not a second driver.

## Explicitly outside this milestone

Pairing/encryption, multiple connections, DLE, 2M, CSA2, long attributes and
product profiles are not implemented or accepted by the current peripheral or
central examples. They are future scope decisions, not compatibility claims.
