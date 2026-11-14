# CH585 BLE bring-up backlog

Updated 2026-11-13. These are open defects, evidence gaps and acceptance work,
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

## Issue #9 audit follow-ups (2026-11-14)

- [ ] **A1 — async RX/TX DMA lifetime.** `rx_basic` (and the TX fast path) keep
  a raw DMA pointer after returning. Needs an interface spec before code: either
  `unsafe` with a completion contract, or a leak-safe ownership token. Deferred
  by decision on 2026-11-14; refactor once the spec exists.
- [x] **B2 — pending security work has no connection epoch.** A queued LTK reply
  survived disconnect and was returned for the next connection with handle 1.
  `SoftRunner` now stores both requests with the bridge epoch and drops them on
  disconnect/reset; a repeated Enable Encryption is no longer blocked by a stale
  entry.
- [ ] **B3 — Instant boundaries.** `validate_instant(0, 32767)` accepts a
  past Instant and rejects a legal same-instant update; applying a current-instant
  update needs immediate re-anchoring, not just a predicate change.
- [ ] **B4 — CRC-failed packet vs establishment/supervision.** Core §4.5 lets any
  received data-channel packet establish the link (and §4.5.5 uses the first
  received packet as the Peripheral anchor) even on a CRC error, while payload
  acceptance and supervision refresh need a valid packet. The current Central RX
  path conflates the two and drops the anchor of a CRC-failed packet.
- [ ] **B5 — Central supervision timer at connection-update instants.** The timer
  should restart at the instant/transmit window; it currently keeps the old base.
- [ ] **B6 — scan/filter policy application.** Filter_Duplicates, basic filtered
  policy 1 (with an accept list) and directed-ADV target filtering are accepted
  but not applied; initiator policy 1 ignores Peer_Address.
- [ ] **B7 — HCI state restrictions.** Set Random Address / Set Scan Parameters
  are accepted while scanning or advertising; they must return Command Disallowed.
- [ ] **B8 — Own address selection per procedure.** A public-address Create
  Connection can be initiated with the default zero/random address.
- [ ] **B9 — HCI command-response contracts.** Create Connection Cancel without a
  pending initiation returns Command Status instead of Command Complete; Host
  Number Of Completed Packets answers with Command Complete in an idle state.
- [ ] **TX timeout quiescence / hardware ownership single-instance audit** and
  the advertising `advDelay` distribution check — need evidence first.

A2 (TX frame extent) and B1 (lifecycle slot reserve) are fixed in PR #10. B2,
the store hardening and the bond-identity/CCCD work below are fixed on the
`ch585-bond-session-correctness` branch.

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
- [x] **ATT MTU negotiation and long data (2026-11-13).** The 60 s secure
  image now negotiates MTU 124 (128-byte packet pool), answers a 200-byte read
  with Read + Read Blob and a 200-byte write with Prepare/Execute; the Android
  app read back the identical pattern and the air opcode counters prove both
  paths. The same round exercised notification-queue pressure (12 attempts, 7
  queued, 5 queue-full). Evidence:
  `local-docs/results/x4-att-5-rx31/`, summary in
  [X4 results](local-docs/research/ch585-x4-att-results.md).
- [x] **Encrypted PDUs above the legacy 27 octets (2026-11-13).** An Android
  Central without DLE sent 28-octet encrypted data PDUs (24 plaintext + MIC);
  the LL refused them at four hardcoded 27-byte limits and, because the refusal
  happened before any TX, never acknowledged them. The peer retransmitted until
  the 5 s supervision timeout killed the link. The ceiling is now
  `ll::enc::MAX_ENCRYPTED` (27 plaintext + MIC) everywhere, and a refused PDU
  is recorded in `SEC_DIAG[63]`; the X4 runner fails on any such sample.
  Evidence: `local-docs/results/x4-att-3-badpdu/` (`0x001c1201` = header
  `0x12`, length 28), `x4-att-4-rx31/`, `x4-att-5-rx31/`.
- [ ] **X1 acceptance: CSA #2 and bidirectional DLE (implementation 2026-11-13).**
  The controller negotiates CSA #2 from the ADV/CONNECT_IND ChSel bits (Core
  sample vectors in unit tests). DLE advertises 251-octet buffers from startup,
  segments every Host ACL packet at the negotiated on-air size, keeps the HCI
  tag only on the final fragment, and scales receive windows with
  `rx_complete_allowance_us()`. `LL_LENGTH_*` octets are payload octets, so the
  controller advertises 247 under its 251-octet air ceiling and accepts the
  peer's payload plus MIC; effective limits stay 27 TX / 31 RX until the peer
  answers, then min(local, peer). Offline: 168 library tests, both Host
  fixtures, all examples build. Hardware (`att --require-dle`): algorithm 2
  with both ChSel bits, effective TX 251 / RX 132, 132-octet PDUs both ways,
  App `att_mtu_long_burst_ok`, no refused PDU. Regressions after the change:
  S2 fresh-bond `encrypted_read_write_ok`, X4b payload and app rounds green.
  Still to record: a keyed capture of `LL_LENGTH_REQ/RSP` (they are encrypted
  after `START_ENC_RSP`). 2M/Coded remain unadvertised.
- [ ] **X1b: 2M/Coded PHY.** Both feature bits stay 0 because the PHY switch and
  its timing are not implemented. Claim either only after a measured air
  comparison against a controlled peer.
- [ ] **Burst drops are silent by design.** `try_notify_raw` returns
  `OutOfMemory` when the 8-deep notification queue is full; the X4 fixture
  counts it and moves on rather than waiting or retrying. This proves the
  pressure path but is not a flow-control policy; a profile needing lossless
  notification must add credit/backpressure semantics at the application layer.
- [ ] **Long writes depend on the peer's queued-write implementation.** The
  Android result relies on AOSP splitting a `WRITE_TYPE_DEFAULT` value larger
  than MTU-3 into Prepare/Execute writes. Other stacks may truncate or fail
  instead; the acceptance evidence is for CPH2411/AOSP only.
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
- [ ] **Bond records are keyed only by the peer identity.** A record stores the
  peer identity and IRK but not the local advertised identity, and DataFlash
  survives reflashes. A record written by an image that advertised a different
  address (the secure build once rotated the low octet from entropy) is loaded
  and offered to the same phone, so a fresh pairing fails at DHKeyCheck
  (`SMP_DHKEY_CHK_FAIL`, phone reports `BOND_REJECTED`) until the store is
  wiped. Observed 2026-11-14: the `...16` image loaded a record left by an
  earlier rotating-address boot (`records_loaded=1`), and `--mode wipe` cleared
  it (`load_result=0`, both slots `0xFFFFFFFF`) before a clean pairing
  (`pairs_complete=1`, `save_ok=1`). Test images sharing one board and one
  phone hit this repeatedly; wipe before a fresh-pair round and decide whether
  records should carry the local identity.
- [ ] **Bond write scheduling and durability policy.** A save takes ~22 ms; the
  deferral guard is `max(observed + 2 ms, 8 ms)`, so at intervals <= 24 ms
  nothing is persisted while connected (only on disconnect), and `WIPE`'s
  ~35 ms erase raises the guard for the rest of the boot. A cap at
  `interval/2` cannot make a 22 ms synchronous flash operation fit a 7.5 ms
  budget; the policy needs an explicit scheduling/durability decision.
- [x] **Store hardening from the S3 review.** `erase_all()` writes a tombstone
  before erasing and keeps the tombstone page until the old page is gone;
  `save()` seeds the sequence from slot headers when `load()` never ran;
  `load()` streams the payload CRC through a bounded scratch and keeps trying
  the other slot after one read error; `save()` reads the whole payload back.
  Covered by the mock flash's read-failure and payload-corruption injection.
- [x] **Bonded CCCD persistence.** Both secure examples now keep the raw
  `ClientAttTable` per peer in a second dual-copy store
  (`0x7C00`/`0x7D00`), keyed by the resolved peer identity and the local
  identity that wrote it, and apply it right after `with_attribute_server`
  (Core 5.4 Vol 3 Part G §3.3.3.3). A bonded peer resumes its subscriptions
  across a reboot without writing the CCCD again. Snapshots happen after an
  accepted CCCD write and on disconnect; the disconnect snapshot never creates
  a first record, so a peer that never subscribed costs no flash write. `DEL!`
  and `WIPE` clear both stores. The restore read-back proves the stored bytes
  landed on the same handles, not that those handles still host the same
  characteristics; see the GATT database fingerprint item below.
- [ ] **GATT database fingerprint for client ATT records.** Restore compares
  the read-back table byte for byte. A layout change that moves or resizes a
  CCCD, or changes a subscription value, is detected and rolled back, but a
  build that keeps the same handles and values under different characteristic
  UUIDs is byte-identical and can enable a notification through a handle that
  now belongs to another characteristic. Store the Core GATT database hash
  (`AttributeTable::hash()`: AES-CMAC over declaration handles and UUIDs) next
  to each client ATT record, bump the client ATT payload format, and refuse a
  record whose hash differs before `set_client_att_table` applies anything.
  Needs a hardware round: firmware layout change plus same-handle CCCD rename.
- [ ] **Shared bond-store and session module (after #7).** `bond.rs` in
  `examples/ch585-hid-keyboard` is a copy of the S3 example's file, and its
  `host.rs`/`main.rs` duplicate the secure session and control-characteristic
  handling. The unauthenticated `DEL!/WIPE/FALT` exposure, the delete/wipe race
  and the CCM ordering guard therefore each have two copies to fix. Extract the
  bond store (and ideally the session pump) once both examples' acceptance is
  stable; keep the per-example policy out of the shared layer.
- [ ] **Bond record security at rest.** The LTK is stored in plain DataFlash;
  SWD/probe reads it. Acceptable for bring-up, not claimed as tamper-resistant
  (security spec §2).

## X4b HID (encrypted-link keyboard)

- [x] **Android system-HID round executed (2026-11-12).** With the 360 s
  image, the pair helper plus the system HID host produced `reports_sent=354`,
  `subscription_edges=1`, `HOST security=3`, `SECURE active=1` and a
  `wch585-hid` keyboard in `dumpsys input` (`local-docs/results/x4b-android-1/`).
  Human-visible typing was not observed; the helper app's own summary is
  `timeout` because it targets the P5 vendor service.
- [x] **App-level HID recognition on Android (2026-11-12).** The helper app's
  `hid` mode discovers `0x1812` (8 characteristics, two `0x2A4D` reports),
  records the platform gate (`SecurityException: Need BLUETOOTH PRIVILEGED
  permission` on the first read) and then observes the OS input device
  (`input_device`: sources `0x101`, keyboard type 2) in `InputManager` and
  `dumpsys input` (`local-docs/results/x4b-android-5/`). Driven by
  `tools/android_hid_run.py --expect app`.
- [ ] **Stock Android blocks third-party HID-service GATT access.** Unprivileged
  clients cannot read or subscribe to `0x1812`; byte-level HOGP assertions must
  come from the system HID host (or a privileged/system app). Recorded, not
  worked around.
- [x] **A bonded Android host with a cached layout does not resubscribe.** After
  a first discovery, the system HID host keeps the cached service layout and
  never writes the report CCCD again, so a same-bond run showed
  `subscription_edges=0`. The firmware now restores the stored client ATT table
  itself, so reports flow without a new CCCD write; `android_hid_run.py
  --expect restored` gates that phase on `CATT_STATS.restored` plus sent
  reports (hardware run pending).
- [ ] **The Android HID host needs an explicit connect trigger.** A bonded peer
  gets no background connection after a reboot, and an adapter cycle did not
  bring the HID host back. Tapping the paired keyboard in Bluetooth Settings
  is deterministic; the runner automates it with `--settings-connect`
  (`uiautomator` bounds, ROM-localised labels avoided).
- [x] **Bond store is keyed by peer address only.** Reusing the store from an
  image with a different local identity made SMP fail: the phone had no bond
  for the new address while the Host still returned the old LTK. The bond and
  client ATT payloads now start with the local identity; a foreign record is
  ignored (`load_result=foreign`) and left in place rather than erased.
- [ ] **LESC key agreement can starve the RF pump past the peer's supervision
  timeout (2026-11-14).** On the macOS gate run the firmware answered the
  protected CCCD write with Insufficient Encryption (0x0F) after 3.8 s; the
  client then saw the link die with "connection has timed out unexpectedly".
  Firmware: `supervision=1`, `host_poll_overrun=2`, `max_host_poll_us=1222635`,
  `missed=5`, and `Host security=0` because the 10 s Security Request had not
  fired yet (`local-docs/results/x4b-macos-review2-20261114/`). The 1.22 s
  block is the documented non-preemptible LESC key agreement; the pump cannot
  transmit while it runs, so a peer that starts pairing right after a 0x0F can
  drop the link even though the example steps over its own missed events.
  A repeat with the first protected access held past the 10 s Security Request
  recorded SMP `PairingRequest`/`PairingResponse`/`PairingFailed` with one
  1.22 s poll and `supervision=0` (`x4b-macos-review3-20261114`), so the
  failure depends on when the peer's pairing lands relative to the connection
  events. Android's pairing survived the same build. Fix direction: move key
  agreement off the pump's critical path (precompute, or a preemptible crypto
  task), or guarantee the peer pairs before the first protected access.
- [ ] **macOS `bond_wipe.swift` stalls on the HID control image.** On
  2026-11-14 the helper connected, received `didConnect`, and then sent no ATT
  or SMP traffic at all for 19.5 s; the firmware TRACE shows only its own
  `LL_VERSION_IND`/`LL_FEATURE_REQ` before the 20 s supervision drop
  (`x1-hid-review-7`/`x1-hid-review-9`). The phone-driven `DEL!`/`WIPE` write is
  the working path; pinning the host-side cause needs a macOS HCI/packet log.
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

Multiple connections, 2M/Coded PHY and product profiles beyond HOGP are not
implemented or accepted by the current peripheral or central examples. DLE and
CSA #2 have since moved out of this list (X1 implementation above; its hardware
round is still open). They are future scope decisions, not compatibility
claims. Pairing/encryption (S2/S3) and long attributes (X4a) moved out earlier
with the evidence above.
