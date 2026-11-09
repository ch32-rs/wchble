# CH585: from RF smoke to a BLE peripheral connection

Research snapshot: 2026-11-09. This is a design and evidence report, not an
implementation or a claim that `wchble` supports CH585 connections. The goal
is the existing Path B: open RF → PHY → LL → software HCI → Trouble Host.
Changes must preserve the existing V208 and CH592 paths and be checked on their
respective hardware when shared behavior changes.

## Conclusions and evidence levels

- **Observed on hardware:** CH585 basic TX and RX work on air in the smoke
  example. iPhone could see its original TX-only `ADV_IND`; an Android phone
  could see the experimental `ADV_NONCONN_IND` after it could not see the
  original advertisement. See [pitfalls §12](../pitfalls.md#12-do-not-advertise-scanconnect-support-that-the-firmware-does-not-provide).
  This proves neither scan response nor connection behavior.
- **Vendor implementation evidence:** the CH585 EVT library contains legacy
  advertisement, scan-request and connection-request processing. Its paths
  involve software at transition points; this is not proof of autonomous
  request validation or of the timing achieved by our implementation.
- **Independent V208 evidence:** `ch32v208-nimble` recorded CRC-valid
  `SCAN_REQ` reception and short macOS connections with GATT discovery and
  read/write. That is a valuable real-time baseline, **not** evidence that the
  CH585 register map or delays are interchangeable with V208.
- **Not yet demonstrated in `wchble` on CH585:** a scan response, a received
  `CONNECT_IND`, an accurate connection anchor, 150 µs RX→TX turnaround,
  connection-event tracking, ACL data, or a Trouble GATT connection.

Recommendation: measure and validate CH585 scan-response turnaround first,
then implement a minimal single-peripheral connection, and finally connect it
to Trouble over HCI. Do not treat an async executor timer or a successful
`tx_basic` return as evidence of an on-air deadline.

## Existing implementation and gaps

`examples/ch585-rf-smoke/src/main.rs` directly operates the radio; it is not a
Trouble/SoftRunner integration. During the Android investigation, its
advertising address and PDU type were changed to static-random and
non-connectable/non-scannable. Preserve the distinction between this current
smoke test and the earlier `ADV_IND` smoke build.

`src/rf/family/ch585.rs` provides init/calibration, channel and AA/CRC setup,
basic TX/RX and ISR hooks. `rx_basic` arms DMA and returns before completion:
the caller must keep the aligned receive buffer alive, stable and exclusively
owned until completion or shutdown. The current smoke test polls completion;
it does not implement an immediate post-advertising RX/response exchange.
`tx_basic` blocks while polling and is not a proven IFS scheduler. HAL-owned IRQ
routing and the timestamp supplied to the radio callbacks also require audit.

`src/hci/runner.rs` provides command and advertising-state scaffolding; scan
response data is stored but not sent. The existing Trouble-on-air integration
is V208-only (`examples/ch32v208-trouble-adv/src/main.rs`) and uses cooperative
polling, blocking TX and millisecond-scale async sleeps; it does not arm RX
for requests and is not a connection scheduler.

`src/ll/conn.rs`, `src/ll/acl.rs` and `src/ll/ctrl.rs` are scaffolds, not a
connection implementation. In particular, host-to-controller ACL packets are
currently discarded by `src/hci/runner.rs`, despite the reported LE buffer
size and credits. Connection/disconnection events, ACL delivery, completed
packet accounting, LL sequence/acknowledgement, retransmission, supervision,
channel scheduling and required control procedures are missing. Capabilities
and credits must describe real implementation and owned buffers, not placeholders.

## Timing constraints

### Advertising exchange

An active scanner can send a `SCAN_REQ` after a scannable advertisement; the
advertiser must receive and validate it and, when applicable, transmit
`SCAN_RSP` on the same channel. Legacy LE exchanges use an inter-frame space of
150 µs. This is an **air-interface interval**, not an instruction to delay
150 µs after entering an interrupt. IRQ latency, packet completion and
validation, DMA setup, radio turnaround and RF startup all consume budget.
Prepare data ahead of time and measure the actual interval and jitter under
load. Do not infer it from the programmed delay or register values.

### Connection establishment and subsequent events

For legacy `CONNECT_IND`, the first transmit window starts at the end of the
request plus `1.25 ms + WinOffset × 1.25 ms`; `WinSize` gives its width in
1.25 ms units. The peripheral must switch to the requested access address,
CRC and data channels and listen in the window. Subsequent receive windows
follow the anchor and interval, widened for clock uncertainty. See Bluetooth
Core Link Layer §4.5.3 and §4.2.4 in the references below.

The central transmits first in a connection event; the peripheral must respond
within the applicable inter-frame spacing. Packet sequence and acknowledgement
bits, retries, event termination and supervision must be handled across events.
Receiving `CONNECT_IND` alone is not proof that a usable connection was
established; verify actual first and later data-channel exchanges.

A CPU-read timestamp is not automatically the end of a packet. Establish the
BB/LLE capture reference and measure IRQ/trigger latency and jitter on silicon.
Do not steal an Embassy-owned timer or make a normal async task responsible
for a hard radio deadline. Avoid logging, allocation and waiting on a full HCI
queue in IRQ/deadline paths. Avoid having an ISR and a blocking poll both
consume the same W1C completion bit.

## Baselines and what they prove

### CH585 EVT

The local vendor archive is `~/WCH/CH585EVT/EXAM/BLE/LIB/libCH58xBLE.a`.
In carved `ll_advertise.o`, `.highcode.ll_adv_legacy_ind_tx_process` contains
calls to set RX PHY, register `ll_adv_legacy_rx_process`, and continue through
`ll_tx_wait_finish`. In `.text.ll_adv_legacy_rx_process`, the observed path
checks CRC, packet type and address; the type-5 branch calls
`ll_advertise_to_connection_state`, while the scan path calls
`ll_advertise_generated_scan_rsp` and continues TX. These are section-relative
disassembly observations, not measured air timing. Some vendor compressed
instructions were not decoded by the inspected tool; audit the complete
sequence and relocations before relying on individual register semantics.

The public `CH58xBLE_LIB.h` documents scan-request notifications and behavior
after scan response, but is not a timing guarantee. CH585's recovered LLE
initialization is in `src/rf/family/ch585.rs`; values such as `0x76` are
register contents, **not** a measured microsecond response time. Keep CH585,
CH592 and V208 register maps and W1C guards separate.

### Proven V208 path

`~/Repos/ch32v208-nimble/docs/radio-2026-10-29.md` records received valid
scan requests, receive-window/anchor debugging and three short macOS
connection/GATT test runs. Its experimental hardware auto RX→TX sequence
previously stuck the sequencer and caused IRQ re-entry; it was withdrawn. Its
address-match handling extends the receive window to avoid truncating a full
connection request. The same document notes the capture point and packet start
were estimated, not instrument-level timing proof.

`~/Repos/ch32v208-nimble/docs/android-interop-2026-10-30.md` records Android
interop and response-delay tuning. The current
`drivers/wch_ble/ble_phy_wch.c` contains a software response-delay setting and
short-packet correction. Neither that delay nor historical tuning values may
be copied as CH585 air-timing constants.

### CH58x independent implementation

The separately researched `ch58x-hal` reference is not our sibling
`ch5xx-hal`. Its `ch58x-ble` radio and LL sources contain a proposed CH58x
transition sequence, pre-staged response DMA, first-window scheduling and
window widening. Its recorded acceptance is host tests/library build, not a
CH585 on-air connection; see [ch58x-hal-ble-reuse.md](ch58x-hal-ble-reuse.md).
One RX transition countdown appears as `0x18e` in code and `0x196` in a
comment. Resolve this against vendor code and measurements instead of copying
either value. The research checkout was under `/tmp/wchble-research/ch58x-hal`
and is an ephemeral reference, not a repository dependency.

### Trouble, Embassy and SoftDevice

Trouble is the Host, not the controller: it expects HCI events and working ACL
transport. The local Trouble nRF52 example uses the proprietary Nordic
SoftDevice Controller/MPSL with reserved RADIO/TIMER/RTC and high-priority IRQ
handlers. This is a useful separation of deadline-sensitive controller work
from async Host work, not a Nordic controller implementation portable to WCH.
Local NimBLE's `nimble/controller/src/ble_ll_sched.c` is an open scheduler
reference for radio reservations, conflict handling and early receive windows.

Trouble derives ACL fragment size and credits from LE Read Buffer Size and
restores credits from Number Of Completed Packets. Implement real bounded
buffer ownership and both directions of ACL transport, including disconnect
cleanup. HCI ACL fragmentation and on-air LL fragmentation/retransmission are
separate concerns. Critical radio code must not await an Embassy HCI channel.

## Proposed staged hardware gates

1. **Positive control and measurement.** On the same CH585 board and Android
   phone, run the vendor Peripheral firmware and verify discovery, connection
   and a GATT operation. Capture the advertising channels and connection
   traffic, plus GPIO/timer points for BB capture, RX completion, ISR entry
   and TX trigger where possible. Restore the user's test firmware afterward.
2. **Scan response only.** Pre-stage a response and implement advertising →
   RX → validated `SCAN_REQ` → same-channel `SCAN_RSP`. Independently capture
   the air interval and jitter, including under interrupt and Host load; test
   repeatedly with Android and iPhone. Do not label this as connection support.
3. **Connection-request reception.** Receive complete CRC-valid `CONNECT_IND`,
   check target address and parameters, parse AA/CRC, window, interval,
   channel map, hop and clock information. Unit-test parsing and bounds; map
   the captured timestamp to packet end with measured error.
4. **Minimal single peripheral LL.** Schedule first and later windows and data
   channels; implement empty-PDU response, SN/NESN, acknowledgement,
   retransmission, required LL control procedures, disconnect and supervision.
   Initially constrain scope to LE 1M and an unencrypted single connection;
   report unsupported capabilities honestly. Verify first and sustained
   data-channel events before declaring a usable connection.
5. **HCI and Trouble.** Implement LE connection/disconnection events, bidirectional
   ACL, buffer/credit accounting and queue saturation handling. Connect Trouble
   and validate GATT discovery and read/write, disconnect/reconnect and timeout.
6. **Regression and robustness.** Run host tests for parsers, state transitions,
   scheduling/widening and credits. Test CH585 across phone types, connection
   intervals and interrupt load over time. Build and on-device regress V208 and
   CH592 for any shared changes; do not assume their hardware paths are equivalent.

## Open questions before implementation

- Which CH585 LLE/BB status bits correspond to TX→RX and RX→TX, including
  failure paths and guarded W1C behavior? What is automatic versus ISR-serviced?
- What are the physical meanings and units of the vendor countdown values?
- What are RX capture reference, radio-ready latency, ISR jitter and measured
  air T_IFS under realistic load? Can an interrupt-driven software path meet it,
  or is a carefully validated hardware-assisted sequence required?
- Which timer/capture resources can the HAL reserve without conflicting with
  Embassy? How are DMA ownership and queue backpressure expressed safely?
- Which LL control procedures and HCI commands does the actual phone/Host
  exercise for the chosen minimal capability set?

## References

- [Bluetooth Core 6.1, LE Link Layer](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-61/out/en/low-energy-controller/link-layer-specification.html)
- [Bluetooth LE Primer](https://www.bluetooth.com/bluetooth-le-primer/)
- [Trouble: Rust BLE Host](https://github.com/embassy-rs/trouble)
- [Embassy nRF SoftDevice: timing and interrupt constraints](https://github.com/embassy-rs/nrf-softdevice/blob/master/README.md)
- [Nordic SoftDevice Controller scheduling](https://github.com/nrfconnect/sdk-nrfxlib/blob/main/softdevice_controller/doc/scheduling.rst)
- [Apache NimBLE connection controller](https://github.com/apache/mynewt-nimble/blob/master/nimble/controller/src/ble_ll_conn.c)
