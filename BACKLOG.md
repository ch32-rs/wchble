# CH585 BLE bring-up backlog

Updated 2026-11-10. These are open defects, evidence gaps and acceptance work,
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
- [ ] **Android six-byte UART write disconnect (2026-11-10):** the user reports
  that writing UTF-8 "中文" (`e4 b8 ad e6 96 87`) to `6E400002` with TX
  notifications enabled drops the Android link. The dedicated firmware window
  recorded seven UART writes/notifications, one normal termination and three
  supervision timeouts with no Host error. The identical sequence passes on
  macOS (write ack, one matching six-byte echo, link held three seconds, normal
  disconnect) and in the native fixture. Not reproduced, not explained; open
  pending an ATT-level capture of the Android session. Do not record it as
  either a firmware or an Android defect yet.

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

## Explicitly outside this milestone

Pairing/encryption, multiple connections, Central role, DLE, 2M, CSA2, long
attributes and product profiles are not implemented or accepted by this P4
milestone. They are future scope decisions, not compatibility claims.
