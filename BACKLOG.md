# CH585 BLE bring-up backlog

Updated 2026-11-19. These are open defects, evidence gaps and acceptance work,
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

- [x] **A1 — async RX/TX DMA lifetime.** `rx_basic` (and the TX fast path) keep
  a raw DMA pointer after returning. Implemented on `ch585-a1-dma-lifetime` as
  `unsafe` + completion-contract variant (spec:
  `local-docs/research/ch585-a1-dma-lifetime-spec.md`): TX force-stops the LLE
  on timeout before returning, RX force-stops a still-armed window, waits for
  the LLE to report idle, and fails closed with `Error::Busy` before
  re-pointing, and every call site carries the contract. Offline: 201 lib tests
  per chip feature, host fixtures 7/1/1, 12 examples build. Hardware on the
  final images: P2 PASS (`adv=1053/1053`, restore scan), P3 PASS, P4/S2
  wipe/pair/reconnect PASS (`pairs_complete=1 save_ok=1`,
  `load_result=1 records_loaded=1`), C1 PASS on the same-image recheck (the
  first C1 run lost one CONNECT_IND and then hit a supervision timeout with
  unchanged timing counters, and is filed as RF loss, not a regression). The
  ownership-token variant stays the follow-up for X3/X5 or an interrupt-driven
  RX. Review follow-up: the TX contract now separates `Late` (no transfer
  started) from stop-before-return, and the RX arm path commits `rx_armed` only
  after `RXBUFPTR` names the buffer (P2/P3/C1 rerun on the final images).
- [x] **B2 — pending security work has no connection epoch.** A queued LTK reply
  survived disconnect and was returned for the next connection with handle 1.
  `SoftRunner` now stores both requests with the bridge epoch and drops them on
  disconnect/reset; a repeated Enable Encryption is no longer blocked by a stale
  entry.
- [x] **B3 — Instant boundaries.** `validate_instant` now treats only a modulo
  distance of at least `0x7fff` as past; distance zero is legal (§5.1.1) and is
  applied by the receiving event in both roles: the channel map updates CSA and
  the stored map, a connection update applies interval/latency/timeout only
  (WinOffset/WinSize do not apply) and keeps the packet as the new anchor.
  Tests: `instant_distance_32767_is_past_and_zero_is_legal`,
  `same_instant_update_uses_the_packet_as_anchor`,
  `same_instant_channel_map_applies_now` and the central-role
  `past_instant_is_rejected_but_same_instant_applies`.
- [x] **B4 — CRC-failed packet vs establishment/supervision.** Core §4.5 lets any
  received data-channel packet establish the link (and §4.5.5 uses the first
  received packet as the Peripheral anchor) even on a CRC error, while payload
  acceptance and supervision refresh need a valid packet. Both roles now
  follow that: `CentralConnection::on_rx` and
  `PeripheralConnection::on_rx_anchor_crc` establish on any AA match without
  refreshing supervision, and only a valid packet moves the supervision base.
  Tests: `crc_error_establishes_without_refreshing_supervision`,
  `crc_error_after_the_establishment_deadline_is_rejected`,
  `crc_error_first_packet_sets_the_anchor_without_refreshing_supervision`,
  `crc_error_does_not_move_an_existing_anchor`. CRC-error packets keep the
  header Length for anchor estimation and get a response (retransmit or Empty)
  exactly once; two consecutive CRC errors close the event (§4.5.1/§4.5.6),
  and the next RX window is recomputed after a successful response. Offline
  review R1/R2 PASS. The example-level CRC-only lifecycle fixture (including
  `bridge.connected` backpressure) is the first X3.2a deliverable.
  Current-tree hardware (2026-11-17): P3 (`e6d88ba9…`, 6 clean client rounds
  incl. `x3-n1-p3-repro1..5`), C1 (`3f3fae94…`), GATT reconnect
  (`105a6e9e…`) and fresh pairing (`7ade1071…`) pass with clean RF counters
  (`tx_late=0` on P3/C1). One P3 round (`x3-n1-p3b`) failed to finish
  (stage 2, runtime 0) and is retained as an unexplained observation. CRC-first
  establishment and the two-CRC-error event close are not yet fixed-point
  tested on air; HID encrypted reports are not verified.
- [x] **B5 — supervision timer at connection-update instants.** The timer now
  restarts at the instant's transmit window (`next_event`), but a deadline that
  was already reached before the instant is not extended by the new timeout;
  a deadline that falls between the instant and the offset window resets at the
  window instead of expiring during the wait. Tests:
  `update_instant_restarts_supervision_at_the_new_anchor`,
  `update_instant_cannot_extend_a_deadline_reached_while_waiting`,
  `update_window_resets_a_deadline_that_falls_before_the_window` (both roles).
  Current-tree P3/C1/reconnect/fresh-pair rounds pass, but none exercised a
  connection-update instant across the old deadline; air fixed-point evidence
  for the instant boundary is still pending.
- [ ] **B6 — scan/filter policy application.** Filter_Duplicates and
  directed-ADV target filtering are still accepted but not applied, and
  initiator policy 1 still ignores Peer_Address. Unimplemented accept-list
  policies no longer silently pass: Set Scan Parameters with policy ≠ 0 and
  LE Create Connection with initiator policy ≠ 0 now return `0x12` (S4b).
  Tests: `scan_filter_policies_are_rejected`,
  `create_connection_rejects_invalid_parameters`.
- [x] **B7 — HCI state restrictions.** Set Random Address now returns Command
  Disallowed while advertising, scanning or initiating (§7.8.4), and Set Scan
  Parameters while scanning (§7.8.10). Test:
  `scan_state_rejects_address_and_scan_parameter_changes` (and
  `random_address_is_rejected_while_initiating`).
- [x] **B8 — Own address selection per procedure.** `SoftRunner::initiator_addr`
  selects the initiator address from the request's Own_Address_Type, not from
  advertising state, and a random own address without an initialized random
  address returns Command Disallowed (§7.8.12). `finish_reset` restores the
  public BD_ADDR too. Tests:
  `public_own_address_survives_reset_and_selects_initiator_addr`,
  `random_own_address_requires_an_initialized_random_address`.
- [x] **B9 — HCI command-response contracts.** Create Connection Cancel without a
  pending initiation now returns Command Complete/Command Disallowed (§7.8.13);
  Host Number Of Completed Packets validates its handle list (malformed →
  Command Complete/Invalid Parameters) and generates no event for unknown
  handles (§7.3.40). Tests: `cancel_without_pending_is_command_complete`,
  `completed_packets_ignores_unknown_connection`.

B3/B7/B8/B9 are offline-verified on `ch585-b3-b9-hci-correctness` (210 lib
tests per chip feature, `tests/{secure,trouble,hid}-host`) and built into all
12 examples. Hardware on freshly rebuilt images: P3 PASS (`cae2eb91…`), C1
PASS (`5d004331…`, re-run against merged ch5xx-hal main after the HCI review
fix; the earlier `e889b449…` predates it) and P4 PASS after the late-TX fix
below (`85fc661a…`, `tx_late=0`, no retries, GATT cycle counters complete).
- [x] **B10 — Host→Controller queue has no enqueue epoch.** A Host command still
  in the one-slot `HOST_TO_CONTROLLER` channel when the link drops is parsed
  after reconnect and attributed to the new connection (`pending_input` reads
  the epoch on dequeue). `c40c008` stamped the packet at enqueue, but adding a
  field to `Packet` broke first pairing on hardware, so it was removed. Fixed
  without growing `Packet`: the channel item is `HostPacket { packet, scope }`,
  `Transport::write` binds `LinkKey { slot, generation }` at the producer, and
  the consumer never re-stamps. Stale ACL data is dropped; stale
  connection-scoped commands (0x0406/0x2019/0x201a/0x201b/0x2022) are answered
  with the correct response shape (`0x02`) instead of being applied. Tests:
  `stale_ltk_reply_is_answered_not_applied_after_handle_reuse`,
  `stale_disconnect_and_set_data_length_keep_their_response_shape`. Stale
  0x201a/0x201b replies now echo the handle as §4.5 requires.
  Hardware fresh pairing on the current tree PASS (`7ade1071…`,
  `secure,accept-control` opt-z+ICF, 2026-11-17): both sides cleared
  (`load_result=0`, phone unpair verified), `pairs_complete=1`, `save_ok=1`,
  six handshake counters = 1, encrypted TX/RX = 9/15, MIC/errors = 0
  (`local-docs/results/x3-n1-pair-20261117`). This is the fresh-pairing
  regression, not a fixed-point test of stale epoch injection.
- [x] **Peripheral Host connection report skipped after a late first response.**
  Found while validating the batch above. Both secure peripheral examples
  (`ch585-trouble-gatt`, `ch585-hid-keyboard`) reported LE Connection Complete
  only when the *first* received PDU's response was transmitted inside its
  window. When that TX returned `Late`, `on_rx_anchor` had already set
  `established`, so the report was never sent: the Host stayed in advertising,
  every ACL PDU was refused for backpressure, and the peer reached supervision
  timeout with no HCI error logged. Both now call one `report_connection`
  helper whenever `bridge.is_connected()` is false — after a successful
  response and also on the `Late` path, before any ACL data reaches the Host.
  Offline: `tests/trouble-host`; hardware: P4 trouble-gatt (Host connected and
  completed the GATT cycle).
- [x] **Peripheral late TX under live Host traffic (X1 DLE regression).**
  Introduced by the X1 DLE work, not by A1: bisect with three images shows
  `cd9a186` (11-12) `tx_late=0`, `b2db898` (pre-A1) `tx_late=35`, and the
  same pre-A1 image plus probes reproduces it. Two paths moved from
  `.highcode`-backed work into flash inside the peer's response window:
  `queue_next_host_fragment` (1124 B, queueing measured up to 103 us) and the
  LL_LENGTH_REQ handling (`ControlState::on_pdu` 52 us + `apply_data_length`
  55 us; the first request consumed 86 us and entered TX at 119 us against the
  120 us start deadline). Fixes: `.highcode` on `queue_next_host_fragment`,
  `apply_data_length`, and `ControlState::on_pdu`; control procedures without
  an Instant (0x08/0x09/0x0c/0x14/0x15) deferred to the post-event idle gap
  (`DeferredControl` / `service_control`, guarded so it never displaces a
  reply the encryption procedure or `service_dle` owns) because their reply
  may leave one event later. Result 35 -> 3 -> 1 -> 0.
  The review round showed how marginal the cold path was: a helper extraction
  rerolled code placement and the first LL_FEATURE_REQ then entered TX at
  95 us (late again), which is why the deferral now covers all Instant-free
  control procedures rather than DLE alone.
  Hardware: P4 `85fc661a…` PASS (`tx_late=0`, 61/61 data, no retries) and HID
  secure `6360c65b…` PASS. Evidence:
  `local-docs/results/diag-p4-*`, `review-p4-*`, `diag-hid-deferred`,
  `review-hid-*`.
  `max_host_poll_us≈1.2…2.16 ms` sits near the 2 ms poll guard on HID while
  its overrun counter stays 0-1 (the guard measures the gap, the counter
  counts an actual reserved-RX collision).
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
  after `START_ENC_RSP`). 2M/Coded stay unadvertised in that build.
- [ ] **X1b: 2M/Coded PHY (2M peripheral subset, 2026-11-19).** `--features
  secure,x1b-2m` sets the LE 2M feature bit and runs
  `LL_PHY_REQ`/`RSP`/`UPDATE_IND` on one peripheral link. Both initiators passed
  N=1 on hardware (`x1b-2m-att-20261119f`, `x1b-2m-peer-20261119d`): LE Read PHY
  2/2, encrypted ATT MTU 124 reads/writes/notifications at 2M, `bad_crc=0`,
  `supervision=0`. Still open: 1M-only peer fallback (offline only), Coded PHY
  (request path and air timing), and Central-side PHY, so `pp`/`cp` builds keep
  both bits clear. Evidence and boundaries:
  `local-docs/results/x1b-2m-20261119.md`.
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

## X3 dual-link open items (2026-11-18)

The PP/CP subsets are closed in `local-docs/results/x3-6-closeout.md`. These
remain open and must not be read as verified:
- [ ] **`pp+secure` (two encrypted links).** The feature combination builds
  (flash 310,126 B, RAM 44,308 B) but has no hardware round; PP acceptance is
  plaintext only.
- [ ] **CP reverse connect order (peripheral first, then central).** Starting
  the phone after the Mac link failed: the fixture advertises about 11 s after
  boot while the app's scan budget is about 10 s and a live link leaves roughly
  2.8 % scan duty. Needs a longer scan budget or a denser background policy.
- [ ] **CP Create Connection Cancel with a live link.** The command gate and
  initiator teardown are covered offline; hardware only exercised the
  no-target scan timeout.
- [ ] **CP inbound existing-bond reconnect (X3.5c).**
- [ ] **Total ACL credits per connection.** X3.3 stays a limited HCI subset;
  the end-to-end credit total is not accepted.
- [ ] **HID encrypted report.** The unencrypted refusal gate passes; encrypted
  reports remain NOT VERIFIED.
- [ ] **Concurrent new pairing.** Pairing while two links are live is rejected
  at SMP with Pairing Failed 0x05 by design; a multi-link pairing path has no
  acceptance evidence.
- [ ] **Host poll budget in security windows.** The HID 60 s refusal-gate run
  recorded `max_host_poll_us=562,467` with `host_poll_overrun=1`; the gate
  passed, but the Host poll budget inside pairing/security windows is not
  verified.
- [ ] **Fresh-bond Gate 0.** Clearing the phone bond needs a manual Unpair
  (Settings → gear → Unpair); the merged engine has no fresh-bond run yet.
- [ ] **CC (two DUT centrals) and MultiCentPeri.** Outside the verified scope.

## X2a extended advertising open items (2026-11-20)

The advertiser subset is closed in `local-docs/results/x2a-ext-adv-20261120.md`.
The advertiser subset is closed in `local-docs/results/x2a-ext-adv-20261120.md`.
X2a-3 coexistence passed N=1 on `ch585-x2a-3-coex`
(`local-docs/results/x2a-3-coex-20261121.md`): a complete Mac GATT cycle with
`TX_LATE=0` while extended advertising ran against the live link (`aux_skip=11`
admission skips, Android byte-exact marker). The first three rounds' failure was
a build-recipe artifact, not firmware logic: opt-z+`--icf=all` breaks the pp
RX→TX response deadline. **2026-11-21 follow-up: the recipe split itself is
closed** — opt-3 pairing no longer fails on the shared-link engine, so
opt-z+ICF is retired project-wide and every example builds plain release
(`local-docs/results/single-recipe-20261121.md`, clean round
`s4-redissect-opt3-pair2-20261121`). Remaining open items:
- [x] **Per-role build-recipe enforcement — resolved by retirement.** No
  per-role profiles remain to enforce; keep `TX_LATE=0` as the on-target gate
  and add the offline `.highcode` nm ownership check (design doc L0b in
  `local-docs/ch585-build-recipe-hardening.md`) if a static preflight is
  wanted.
- [ ] **OTA slot size under the single recipe.** opt-3 without ICF is larger
  than the already-overflowing opt-z+icf images (secure,privacy,rpa-fast
  `.text` ≈ 306 KiB vs the 221,184 B slot); X6b size closure now needs
  feature-dieting or link-section work, and any future OTA-only opt-z
  override must be recorded as a size-driven choice, not timing.
- [ ] **Coex branch shared-path changes.** Three un-cfg'd pp_loop edits
  (`ADV_EXIT_US` 160→1000, `ADV_SCHEDULE_LEAD_US`, `Decision::Skipped` clearing
  `adv_work`) change plain-pp behavior; confirm or cfg-gate before merge.
- [ ] **2M nRF Connect manual corroboration.** The 2M round is backed by the
  APK `secondary_phy=2` plus firmware `last_aux_phy=2`; no second-face manual
  capture was taken.
- [ ] **`scan_req_rx` observation.** The feature bit promises no AUX_SCAN_REQ
  answer by design; scanner retry behavior was not separately captured.
- [ ] **Periodic advertising, SYNC_ADV/SYNC_SCAN and PAwR** are untouched X2
  scope.

## Explicitly outside this milestone

Multiple connections, Coded PHY and product profiles beyond HOGP are not
implemented or accepted by the current peripheral or central examples. DLE and
CSA #2 have since moved out of this list (X1 implementation above; its hardware
round is still open); LE 2M moved out for the single peripheral link only (X1b
subset above). They are future scope decisions, not compatibility claims.
Pairing/encryption (S2/S3) and long attributes (X4a) moved out earlier with the
evidence above.
