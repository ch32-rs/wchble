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

## Priority: safe pre-flash stop reliability

- [ ] **Further physical launches are blocked by the preflight CLI sequence.**
  The first P4 phone-only attempt refused to flash: CMD was 2 before shut, then
  0 and 2 at the required acknowledgements. No P4 test image ran and no phone
  result was obtained. Independent final smoke restoration and exact-name
  discovery passed; the board is smoke, not ready for phone GATT. The same
  attempt's sniffer needed SIGTERM and remains unclean.
- [ ] **Retain one halted probe session through shut, acknowledgements and
  verified download/start.** Installed `probe-rs` 0.32.0
  (`b580f1a0b96c1880871c30892343287b1aed716f`) unconditionally resumes all cores
  after `read`. Consequently every separate preflight read, including the first
  zero acknowledgement, lets smoke run and rearm RF. Even two sampled zeros do
  not establish uninterrupted CPU/RF ownership. The current read/write CLI has
  no keep-halted option. Separate debug REPL invocations are not a safe substitute:
  startup resumes Request-halted cores before processing `break`, and the REPL
  lacks generic MMIO writes. Do not rerun the current physical launch sequence
  or bypass acknowledgements; implement a bounded single-session helper first.

Acceptance: with the fixed probe selector, establish halted CPU/RF ownership
through the complete pre-flash sequence, retain both zero idle acknowledgements
and failure refusal, then perform a new archived phone-only launch with real
successful-flash readiness. Preserve the failed attempt separately; smoke
recovery is not successful phone-image installation. Historical client/firmware
functional results remain separate from this newly identified preflight gap.

## Priority: independent phone acceptance

- [ ] **Android P4:** complete at least three isolated connect/discover/read/
  Write Request/readback/notify/unsubscribe/disconnect/reconnect rounds. Verify
  ten numbered notifications, value persistence and cleared CCCD on reconnect.
- [ ] **iPhone P4:** repeat the same acceptance in its own finite window, with
  no Android or macOS central competing for the single connection.
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
