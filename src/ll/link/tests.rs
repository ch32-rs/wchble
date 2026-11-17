//! Lifecycle fixtures for the shared Peripheral session engine.
//!
//! A scripted [`FakeRadio`] feeds frames into the production event path, a
//! self-advancing clock keeps the RF waits finite, and [`RecHost`] records the
//! Host-visible order so close/publish/re-arm invariants are asserted on the
//! real code rather than a test copy.

extern crate std;

use core::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

use super::*;
use crate::ll::conn::ConnectParams;
use crate::rf::{Radio, RfCallback, RxState};

/// Self-advancing microsecond clock: every read moves time forward.
#[derive(Clone)]
pub(crate) struct FakeClock {
    now: Rc<Cell<u32>>,
    tick: u32,
}

impl FakeClock {
    pub(crate) fn new(start: u32) -> Self {
        Self {
            now: Rc::new(Cell::new(start)),
            tick: 1,
        }
    }
    pub(crate) fn advance(&self, us: u32) {
        self.now.set(self.now.get().wrapping_add(us));
    }
    pub(crate) fn now(&self) -> u32 {
        self.now.get()
    }
    pub(crate) fn handle(&self) -> Rc<Cell<u32>> {
        self.now.clone()
    }
}

impl InstantUs for FakeClock {
    fn now_us(&self) -> u32 {
        let v = self.now.get();
        self.now.set(v.wrapping_add(self.tick));
        v
    }
    fn delay_us(&self, us: u32) {
        self.now.set(self.now.get().wrapping_add(us));
    }
}

#[derive(Clone)]
pub(crate) struct Window {
    frame: Option<Vec<u8>>,
    crc_ok: bool,
    /// Extra time before RX completion, modelling a late-starting packet.
    done_delay_us: u32,
}

pub(crate) struct FakeRadio {
    clock: FakeClock,
    windows: VecDeque<Window>,
    sent: Vec<Vec<u8>>,
    /// Next transmit returns `Error::Late` without going on air.
    late: bool,
    /// Next transmit returns this error, with the engine stopped, once.
    tx_error: Option<crate::Error>,
    /// Report a capture that never completes, to exercise the capture timeout.
    stall_capture: bool,
    stop_ok: bool,
    stops: Rc<Cell<u32>>,
    channel: u8,
    armed: Option<Window>,
    /// RX completion time the engine will read as `end` (clock + 150 us).
    last_end: Option<u32>,
    /// RX window widths requested by the engine, in half microseconds.
    windows_armed: Vec<u32>,
    /// TX start deadlines passed to `tx_basic`.
    tx_deadlines: Vec<Option<u32>>,
    /// Clock at each `rx_basic` entry (the event's RX arm times).
    rx_entries: Vec<u32>,
}

impl FakeRadio {
    pub(crate) fn new(clock: &FakeClock, stops: Rc<Cell<u32>>) -> Self {
        Self {
            clock: clock.clone(),
            windows: VecDeque::new(),
            sent: Vec::new(),
            late: false,
            tx_error: None,
            stall_capture: false,
            stop_ok: true,
            stops,
            channel: 0,
            armed: None,
            last_end: None,
            windows_armed: Vec::new(),
            tx_deadlines: Vec::new(),
            rx_entries: Vec::new(),
        }
    }
    pub(crate) fn push(&mut self, window: Window) {
        self.windows.push_back(window);
    }
    pub(crate) fn frame(frame: Vec<u8>) -> Window {
        Window {
            frame: Some(frame),
            crc_ok: true,
            done_delay_us: 0,
        }
    }
    pub(crate) fn bad_frame(frame: Vec<u8>) -> Window {
        Window {
            frame: Some(frame),
            crc_ok: false,
            done_delay_us: 0,
        }
    }
    pub(crate) fn missed() -> Window {
        Window {
            frame: None,
            crc_ok: true,
            done_delay_us: 0,
        }
    }
}

impl Radio for FakeRadio {
    fn init<T: InstantUs>(&mut self, _clock: &T) -> crate::Result<()> {
        Ok(())
    }
    fn recalibrate<T: InstantUs>(&mut self, _clock: &T) -> crate::Result<()> {
        Ok(())
    }
    fn shut(&mut self) {}
    fn set_channel(&mut self, channel: crate::rf::Channel) -> crate::Result<()> {
        self.channel = channel;
        Ok(())
    }
    fn channel(&self) -> crate::rf::Channel {
        self.channel
    }
    fn set_aa_crc(&mut self, _access_address: u32, _crc_init: u32) {}
    fn set_phy(&mut self, _tx: crate::rf::PhyMode, _rx: crate::rf::PhyMode) {}
    fn set_whiten_disabled(&mut self, _disabled: bool) {}
    fn set_encrypt(&mut self, _enabled: bool) {}
    fn set_callback(&mut self, _cb: Option<RfCallback>) {}
    unsafe fn tx_basic<T: InstantUs>(
        &mut self,
        _clock: &T,
        frame: &[u8],
        _timeout_half_us: u32,
        _start_cputime: Option<u32>,
    ) -> crate::Result<()> {
        self.tx_deadlines.push(_start_cputime);
        if let Some(error) = self.tx_error.take() {
            return Err(error);
        }
        if self.late {
            self.late = false;
            return Err(crate::Error::Late);
        }
        self.sent.push(frame.to_vec());
        self.clock.advance(80 + 8 * frame.len() as u32);
        Ok(())
    }
    unsafe fn rx_basic<T: InstantUs>(
        &mut self,
        _clock: &T,
        rxbuf: &mut [u8],
        window_half_us: u32,
    ) -> crate::Result<()> {
        self.windows_armed.push(window_half_us);
        self.rx_entries.push(self.clock.now());
        let window = self.windows.pop_front().unwrap_or_else(FakeRadio::missed);
        if let Some(frame) = &window.frame {
            rxbuf[..frame.len()].copy_from_slice(frame);
        }
        self.armed = Some(window);
        Ok(())
    }
    fn rssi(&self) -> i8 {
        0
    }
    fn crc_ok(&self) -> bool {
        true
    }
}

impl LinkRadio for FakeRadio {
    fn clear_rx_status(&mut self) {
        self.armed = None;
    }
    fn rx_state(&mut self) -> RxState {
        if self.stall_capture {
            return RxState {
                done: false,
                crc_ok: true,
                captured: true,
            };
        }
        match &self.armed {
            Some(w) if w.frame.is_some() => {
                // `receive` reads the clock once more after this returns.
                let delay = 150 + w.done_delay_us;
                self.last_end = Some(self.clock.now().wrapping_add(delay));
                self.clock.advance(delay);
                RxState {
                    done: true,
                    crc_ok: w.crc_ok,
                    captured: true,
                }
            }
            _ => RxState::default(),
        }
    }
    fn note_capture(&mut self, _now_us: u32) {}
    fn stop<T: InstantUs>(&mut self, _clock: &T) -> bool {
        self.stops.set(self.stops.get() + 1);
        self.stop_ok
    }
}

struct RecHost {
    stats: [u32; 64],
    features: [u8; 8],
    sec: [u32; 16],
    log: Vec<&'static str>,
    connections: u32,
    closes: Vec<u8>,
    connected: bool,
    reject_connection: bool,
    adv_enabled: bool,
    stops_at_close: Option<u32>,
    stops: Rc<Cell<u32>>,
    clock: Option<Rc<Cell<u32>>>,
    acl_rx: Vec<(u8, Vec<u8>)>,
    diag_rx: Vec<(u8, Vec<u8>, bool)>,
    acl_tx: VecDeque<TxAcl>,
    acked: Vec<TxTag>,
    acl_reply_calls: Vec<(u8, Vec<u8>)>,
    acl_replies: VecDeque<Option<AclReply>>,
    payload_limit: usize,
    capture_timeout: Option<u32>,
    rearm: Option<u32>,
    feature_request_allowed: bool,
    establishment_limit: Option<u16>,
    can_receive: bool,
    skipped: u32,
    rx_frames: Vec<usize>,
    idle_gaps: u32,
    after_close: u32,
    resets: u32,
    radio_requests: VecDeque<RadioRequest>,
    x1: Option<X1Snapshot>,
}

impl RecHost {
    fn new(stops: Rc<Cell<u32>>) -> Self {
        Self {
            stats: [0; 64],
            features: crate::ll::ctrl::feature_bits(&[
                crate::ll::ctrl::FEATURE_LE_DATA_LENGTH_EXTENSION,
                crate::ll::ctrl::FEATURE_LE_CSA2,
            ]),
            sec: [0; 16],
            log: Vec::new(),
            connections: 0,
            closes: Vec::new(),
            connected: false,
            reject_connection: false,
            adv_enabled: true,
            stops_at_close: None,
            stops,
            clock: None,
            acl_rx: Vec::new(),
            diag_rx: Vec::new(),
            acl_tx: VecDeque::new(),
            acked: Vec::new(),
            acl_reply_calls: Vec::new(),
            acl_replies: VecDeque::new(),
            payload_limit: MAX_ENCRYPTED,
            capture_timeout: None,
            rearm: None,
            feature_request_allowed: true,
            establishment_limit: None,
            can_receive: true,
            skipped: 0,
            rx_frames: Vec::new(),
            idle_gaps: 0,
            after_close: 0,
            resets: 0,
            radio_requests: VecDeque::new(),
            x1: None,
        }
    }
}

impl LinkHost for RecHost {
    type Aes = crate::crypto::aes::Aes128;

    fn local_features(&self) -> [u8; 8] {
        self.features
    }
    fn new_aes(&mut self, key: &[u8; 16]) -> Self::Aes {
        crate::crypto::aes::Aes128::new(key)
    }

    fn stat_inc(&mut self, slot: usize) {
        self.stats[slot] = self.stats[slot].wrapping_add(1);
    }
    fn stat_put(&mut self, slot: usize, value: u32) {
        self.stats[slot] = value;
    }
    fn stat_get(&self, slot: usize) -> u32 {
        self.stats[slot]
    }
    fn sec_inc(&mut self, slot: usize) {
        self.sec[slot] = self.sec[slot].wrapping_add(1);
    }
    fn sec_put(&mut self, slot: usize, value: u32) {
        self.sec[slot] = value;
    }

    fn trace(
        &mut self,
        _now_us: u32,
        _kind: u32,
        _event: u16,
        _channel: u8,
        _header: u8,
        _len: u8,
        _a: u32,
        _b: u32,
    ) {
    }

    fn diag_acl_raw(&mut self, llid: u8, payload: &[u8], ciphertext: bool) {
        self.diag_rx.push((llid, payload.to_vec(), ciphertext));
    }
    fn diag_acl_plain(&mut self, llid: u8, payload: &[u8]) {
        self.diag_rx.push((llid, payload.to_vec(), false));
    }
    fn diag_control_opcode(&mut self, _opcode: u8) {}
    fn note_bad_pdu(&mut self, _header: u8, _len: usize) {
        self.log.push("bad_pdu");
    }
    fn note_rx_frame(&mut self, len: usize) {
        self.rx_frames.push(len);
    }
    fn note_rx_oversize(&mut self) {
        self.log.push("oversize");
    }
    fn note_start_req_queued(&mut self) {}
    fn note_start_rsp_queued(&mut self) {}
    fn diag_skipped_event(&mut self) {
        self.skipped += 1;
    }

    fn can_receive_acl(&mut self, _llid: u8, _len: usize) -> bool {
        self.can_receive
    }
    fn receive_acl(&mut self, llid: u8, payload: &[u8]) -> bool {
        if !self.can_receive {
            return false;
        }
        self.acl_rx.push((llid, payload.to_vec()));
        true
    }
    fn take_tx_acl(&mut self) -> Option<TxAcl> {
        self.acl_tx.pop_front()
    }
    fn ack_tx(&mut self, tag: TxTag) -> bool {
        self.acked.push(tag);
        true
    }

    fn acl_reply(&mut self, llid: u8, payload: &[u8]) -> Option<AclReply> {
        self.acl_reply_calls.push((llid, payload.to_vec()));
        self.acl_replies.pop_front().unwrap_or(None)
    }
    fn rx_payload_limit(&self) -> usize {
        self.payload_limit
    }
    fn rx_capture_timeout_us(&self) -> Option<u32> {
        self.capture_timeout
    }
    fn rx_rearm_window_us(&self) -> Option<u32> {
        self.rearm
    }
    fn allows_feature_request(&self) -> bool {
        self.feature_request_allowed
    }
    fn establishment_event_limit(&self) -> Option<u16> {
        self.establishment_limit
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
    fn publish_connection(&mut self, _info: &mut ConnectionInfo) -> bool {
        if self.reject_connection {
            self.log.push("publish_refused");
            return false;
        }
        self.connected = true;
        self.connections += 1;
        self.log.push("connect");
        true
    }
    fn disable_adv(&mut self) {
        if self.adv_enabled {
            self.adv_enabled = false;
            self.log.push("adv_off");
        }
    }
    fn connection_closed(&mut self, reason: u8) {
        self.closes.push(reason);
        self.stops_at_close = Some(self.stops.get());
        // The real bridge drops the event when no link was ever published.
        if self.connected {
            self.connected = false;
            self.log.push("disconnect");
        }
    }
    fn encryption_change(&mut self, _handle: u16, _status: u8, _enabled: u8) {}
    fn connection_updated(&mut self, _interval: u16, _latency: u16, _timeout: u16) -> bool {
        true
    }
    fn data_length_change(&mut self, _a: u16, _b: u16, _c: u16, _d: u16) -> bool {
        true
    }

    fn take_ltk_reply(&mut self) -> Option<LtkReply> {
        None
    }
    fn push_ltk_request(&mut self, _rand: [u8; 8], _ediv: u16) -> bool {
        true
    }
    fn take_data_length_request(&mut self) -> Option<(u16, u16)> {
        None
    }

    fn publish_x1(&mut self, snapshot: &X1Snapshot) {
        self.x1 = Some(*snapshot);
    }

    fn idle_gap(&mut self, _deadline: u32, until: u32) {
        self.idle_gaps += 1;
        if let Some(clock) = &self.clock {
            clock.set(until);
        }
    }
    fn after_close(&mut self) {
        self.after_close += 1;
    }
    fn on_reset(&mut self) {
        self.resets += 1;
        self.log.push("reset");
    }
    fn on_disconnect_request(&mut self, _reason: u8) {}
    fn pre_iteration(&mut self) {}
    fn take_radio_request(&mut self) -> Option<RadioRequest> {
        self.radio_requests.pop_front()
    }
}

pub(crate) fn connect_pdu() -> [u8; 36] {
    let mut pdu = [0; 36];
    pdu[0] = 0x85;
    pdu[1] = 34;
    pdu[2..8].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
    pdu[8..14].copy_from_slice(&[0xc0; 6]);
    pdu[14..18].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    pdu[18..21].copy_from_slice(&[0x55, 0x55, 0x55]);
    pdu[21] = 2;
    pdu[24..26].copy_from_slice(&24u16.to_le_bytes());
    pdu[28..30].copy_from_slice(&200u16.to_le_bytes());
    pdu[30..35].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x1f]);
    pdu[35] = 5;
    pdu
}

pub(crate) fn params() -> ConnectParams {
    ConnectParams::parse(&connect_pdu(), true, [0xc0; 6], true).unwrap()
}

pub(crate) const CONNECT_END: u32 = 1_000;
/// Run budget far enough out to avoid the wrap-sensitive `earlier` path.
pub(crate) const FINISH: u32 = 120_000_000;

struct Harness {
    clock: FakeClock,
    radio: FakeRadio,
    host: RecHost,
    session: Session<crate::crypto::aes::Aes128>,
    rx: DmaBuf<RX_DMA_MIN>,
    tx: DmaBuf<MAX_PDU>,
}

impl Harness {
    fn new() -> Self {
        Self::new_at(0)
    }

    fn new_at(start: u32) -> Self {
        let clock = FakeClock::new(start);
        let stops = Rc::new(Cell::new(0));
        let radio = FakeRadio::new(&clock, stops.clone());
        let mut host = RecHost::new(stops);
        host.clock = Some(clock.now.clone());
        let session = Session::new(
            params(),
            false,
            start.wrapping_add(CONNECT_END),
            start,
            [0x11; 12],
            host.local_features(),
        );
        Self {
            clock,
            radio,
            host,
            session,
            rx: DmaBuf::zeroed(),
            tx: DmaBuf::zeroed(),
        }
    }

    fn event(&mut self, finish: u32) -> EventEnd {
        connection_event(
            &mut self.radio,
            &self.clock,
            &mut self.rx,
            &mut self.tx,
            &mut self.session,
            &mut self.host,
            finish,
        )
    }

    fn step(&mut self, finish: u32) -> Control {
        step(
            &mut self.session,
            &mut self.host,
            &mut self.radio,
            &self.clock,
            &mut self.rx,
            &mut self.tx,
            finish,
        )
    }
}

/// An empty LL PDU (LLID 1, length 0).
fn empty_pdu() -> Vec<u8> {
    std::vec![0x01, 0x00]
}

/// A CRC-bad frame with a readable header/length only.
pub(crate) fn bad_crc_frame(header: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = std::vec![header, payload.len() as u8];
    frame.extend_from_slice(payload);
    frame
}

fn close_reason(end: EventEnd) -> Option<u8> {
    match end {
        EventEnd::Close(reason) => Some(reason),
        _ => None,
    }
}

#[test]
fn crc_only_establishes_then_supervision_closes_once_in_order() {
    let mut h = Harness::new();
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    // Matching AA establishes the link and the Host learns about it once.
    assert_eq!(h.host.connections, 1);
    assert!(h.host.connected);
    assert_eq!(h.radio.sent.len(), 1, "one response to the first bad CRC");
    assert_eq!(h.host.log, std::vec!["connect"]);

    let mut control = Control::Continue;
    for _ in 0..200 {
        control = h.step(FINISH);
        if matches!(control, Control::Closed(_)) {
            break;
        }
        h.radio.push(FakeRadio::missed());
    }
    assert_eq!(control, Control::Closed(0x08), "supervision timeout");
    assert_eq!(h.host.connections, 1, "published exactly once");
    assert_eq!(h.host.closes, std::vec![0x08]);

    // The shared close stops the radio before it publishes the disconnect.
    let stops = h.host.stops_at_close.unwrap();
    assert!(stops >= 1);
    assert_eq!(h.host.log, std::vec!["connect", "adv_off", "disconnect"]);

    // The engine never re-enables advertising by itself. The example only
    // schedules a re-advertise after the Host saw the disconnect.
    let before = h.host.stops.get();
    assert!(!h.host.adv_enabled);
    let _ = before;
    h.host.adv_enabled = true;
    assert!(h.host.adv_enabled);
    assert_eq!(h.host.connections, 1);
}

#[test]
fn two_bad_crc_frames_close_the_event_after_one_response() {
    let mut h = Harness::new();
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent.len(), 1, "second bad CRC gets no response");
    assert_eq!(h.host.connections, 1);
    assert_eq!(h.host.closes.len(), 0, "the event ends, the link stays");
}

#[test]
fn bad_good_bad_keeps_the_link_and_answers_each_bad_run() {
    let mut h = Harness::new();
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    h.radio.push(FakeRadio::frame(empty_pdu()));
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    // One answer per run of bad frames; the valid PDU in between resets the
    // consecutive-CRC counter without closing the event.
    assert_eq!(h.radio.sent.len(), 3);
    assert_eq!(h.host.connections, 1);
    assert!(h.session.established());
}

/// First event start after one CRC-bad packet whose header declares `air_len`.
fn first_bad_crc_event_start(air_len: u8) -> u32 {
    let mut h = Harness::new();
    h.radio.push(FakeRadio::bad_frame(std::vec![0x21, air_len]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert!(h.session.established());
    // `note_rx_frame` reports the header-inclusive length the header declares.
    assert_eq!(h.host.rx_frames, std::vec![usize::from(air_len) + 2]);
    h.session.event_start_us()
}

#[test]
fn crc_error_anchor_uses_the_header_length_not_the_captured_bytes() {
    // A 2-byte capture declaring 252 moves the anchor 250 payload bytes
    // earlier; using the captured length would make both runs identical.
    let long = first_bad_crc_event_start(252);
    let short = first_bad_crc_event_start(2);
    assert_eq!(
        short.wrapping_sub(long),
        8 * 250,
        "a longer declared packet anchors earlier"
    );
}

#[test]
fn bad_crc_is_not_acknowledged_and_the_valid_retransmission_is() {
    let mut h = Harness::new();
    h.radio.push(FakeRadio::bad_frame(std::vec![0x21, 252]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    let end = h.radio.last_end.expect("RX completion recorded");
    assert_eq!(h.host.stats[8], 1, "CRC error counted");
    assert_eq!(h.host.stats[9], 0, "bad CRC is not an oversize PDU");
    assert!(h.host.log.iter().all(|s| *s != "oversize"));
    assert_eq!(h.radio.sent.len(), 1);
    assert_eq!(
        (h.radio.sent[0][0] >> 2) & 1,
        0,
        "a CRC-bad PDU is not acknowledged"
    );
    assert_eq!(
        h.radio.tx_deadlines[0],
        Some(end.wrapping_add(120)),
        "TX carries the response deadline"
    );

    // The peer retransmits the same SN with a valid CRC: now it is accepted.
    h.radio.push(FakeRadio::frame(empty_pdu()));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent.len(), 2);
    assert_eq!(
        (h.radio.sent[1][0] >> 2) & 1,
        1,
        "the valid retransmission is acknowledged"
    );
    assert_eq!(h.host.connections, 1, "still one link");
}

#[test]
fn oversize_crc_ok_frame_is_refused_and_never_establishes() {
    let mut h = Harness::new();
    // Length 252 exceeds the 251-octet encrypted maximum.
    let mut frame = std::vec![0x01, 252];
    frame.extend_from_slice(&[0u8; 252]);
    h.radio.push(FakeRadio::frame(frame));
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert!(!h.session.established());
    assert_eq!(h.host.log.iter().filter(|s| **s == "oversize").count(), 1);
    assert_eq!(h.host.stats[9], 1);
    assert_eq!(h.radio.sent.len(), 0);

    // Establishment was never possible: six intervals after the connect.
    let mut reason = None;
    for _ in 0..200 {
        if let Some(r) = close_reason(h.event(FINISH)) {
            reason = Some(r);
            break;
        }
        h.radio.push(FakeRadio::missed());
    }
    assert_eq!(reason, Some(0x3e), "connection failed, not supervision");
    assert_eq!(h.host.connections, 0);
}

#[test]
fn late_response_still_publishes_and_delivers_the_received_fragment() {
    let mut h = Harness::new();
    // LLID 2 (start), L2CAP payload of 4 octets, CRC valid.
    h.radio.push(FakeRadio::frame(std::vec![
        0x02, 0x04, 0xaa, 0xbb, 0xcc, 0xdd
    ]));
    h.radio.late = true;
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert!(h.host.connected, "the link is reported despite Late");
    assert_eq!(h.host.acl_rx.len(), 1, "received fragment is not lost");
    assert_eq!(h.host.acl_rx[0].0, 2);
    assert_eq!(h.host.stats[19], 1, "Late counted");

    // The Late answer does not stall the outer loop: later events still run.
    let events = h.host.stats[16];
    let start = h.session.event_start_us();
    for _ in 0..3 {
        h.radio.push(FakeRadio::missed());
        assert_eq!(h.step(FINISH), Control::Continue);
    }
    assert!(h.host.stats[16] > events, "an event ran after Late");
    assert!(
        h.session.event_start_us().wrapping_sub(start) >= 24 * 1250,
        "the next event start moved on"
    );
    assert_eq!(h.host.acl_rx.len(), 1, "the fragment is delivered once");
    assert_eq!(h.host.stats[24], 0, "no duplicate accepted");
    assert!(
        h.radio.windows_armed.iter().all(|w| *w <= 24 * 1250 * 2),
        "RX windows stay inside the event interval"
    );
}

#[test]
fn late_answer_to_the_first_bad_crc_still_publishes_the_link() {
    let mut h = Harness::new();
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    h.radio.late = true;
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert!(h.session.established());
    assert_eq!(h.host.connections, 1, "published despite the Late answer");
    assert_eq!(h.radio.sent.len(), 0, "the Late answer never went on air");
    assert_eq!(h.host.stats[19], 1, "Late counted");
    assert_eq!(h.host.stats[8], 1, "the CRC error is still recorded");

    // The outer loop keeps advancing the event anchor.
    let start = h.session.event_start_us();
    for _ in 0..3 {
        h.radio.push(FakeRadio::missed());
        assert_eq!(h.step(FINISH), Control::Continue);
    }
    assert!(h.session.event_start_us().wrapping_sub(start) >= 24 * 1250);
    assert_eq!(h.host.connections, 1, "still one link");
}

#[test]
fn first_publish_backpressure_closes_with_bridge_error() {
    let mut h = Harness::new();
    h.host.reject_connection = true;
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Close(0x1f));
    assert_eq!(h.host.connections, 0);
    assert_eq!(h.host.closes.len(), 0, "the caller owns the close");
    assert!(h.host.log.iter().all(|s| *s != "disconnect"));
    // The example's close path then runs the shared stop-first close.
    let stops = h.host.stops.get();
    h.radio.push(FakeRadio::missed());
    assert!(close_session(
        &mut h.host,
        &mut h.radio,
        &h.clock,
        &h.session,
        0x1f
    ));
    assert_eq!(h.host.closes, std::vec![0x1f]);
    assert_eq!(h.host.stops.get(), stops + 1, "radio stopped once");
    assert!(
        h.host.log.iter().all(|s| *s != "disconnect"),
        "a link that never published produces no disconnect event"
    );
    assert_eq!(h.host.stats[63], 1);
    assert_eq!(h.host.after_close, 1);
}

#[test]
fn rf_stop_without_confirmation_does_not_close_or_rearm() {
    let mut h = Harness::new();
    // Force a close path: the peer never answers and supervision expires.
    // Advertising was already taken down by the link.
    h.host.adv_enabled = false;
    h.clock.advance(200_000);
    h.radio.stop_ok = false;
    assert_eq!(h.step(FINISH), Control::StopTimeout);
    assert_eq!(
        h.host.closes.len(),
        0,
        "no disconnect on an unconfirmed stop"
    );
    assert!(!h.host.adv_enabled);
    assert_eq!(h.host.after_close, 0);

    // A later attempt with a confirmed stop closes exactly once.
    h.radio.stop_ok = true;
    assert_eq!(h.step(FINISH), Control::Closed(0x3e));
    assert_eq!(h.host.closes, std::vec![0x3e]);
    assert_eq!(h.host.after_close, 1);
}

#[test]
fn step_skips_missed_events_and_reset_does_not_publish_a_disconnect() {
    let mut h = Harness::new();
    // Three intervals behind: the catch-up path runs before the next event.
    h.clock.advance(90_000);
    assert_eq!(h.step(FINISH), Control::Continue);
    assert!(h.host.skipped >= 1);
    assert!(h.host.idle_gaps <= 1);

    h.host.radio_requests.push_back(RadioRequest::Reset);
    assert_eq!(h.step(FINISH), Control::Reset);
    assert_eq!(h.host.resets, 1);
    assert_eq!(h.host.closes.len(), 0, "Reset is not a disconnect event");
}

#[test]
fn reconnect_uses_a_fresh_session_after_close() {
    let mut h = Harness::new();
    h.clock.advance(200_000);
    assert_eq!(h.step(FINISH), Control::Closed(0x3e));
    assert_eq!(h.host.closes.len(), 1);

    // A second CONNECT_IND builds a new Session; the Host is re-armed only
    // through its own disconnect handling (adv_enabled), never by the engine.
    let now = h.clock.now();
    h.session = Session::new(
        params(),
        false,
        now.wrapping_add(CONNECT_END),
        now,
        [0x22; 12],
        h.host.local_features(),
    );
    h.host.adv_enabled = true;
    h.host.log.clear();
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    let mut control = Control::Continue;
    for _ in 0..10 {
        control = h.step(FINISH);
        if h.host.connections == 1 {
            break;
        }
    }
    assert_eq!(control, Control::Continue);
    assert_eq!(h.host.connections, 1);
    assert!(!h.host.adv_enabled, "the new link stops advertising again");
    assert_eq!(h.host.closes.len(), 1);
}

#[test]
fn microsecond_clock_wrap_keeps_the_close_ordered() {
    let clock = FakeClock::new(0xffff_0000);
    let stops = Rc::new(Cell::new(0));
    let mut radio = FakeRadio::new(&clock, stops.clone());
    let mut host = RecHost::new(stops);
    let mut session = Session::new(
        params(),
        false,
        0xffff_0100,
        0xffff_0000,
        [0x33; 12],
        host.local_features(),
    );
    let mut rx = DmaBuf::zeroed();
    let mut tx = DmaBuf::zeroed();
    radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    let end = connection_event(
        &mut radio,
        &clock,
        &mut rx,
        &mut tx,
        &mut session,
        &mut host,
        FINISH,
    );
    assert_eq!(end, EventEnd::Continue);
    assert_eq!(host.connections, 1);

    // Wrap past FINISH into a supervision timeout.
    let mut reason = None;
    for _ in 0..200 {
        radio.push(FakeRadio::missed());
        if let EventEnd::Close(r) = connection_event(
            &mut radio,
            &clock,
            &mut rx,
            &mut tx,
            &mut session,
            &mut host,
            FINISH,
        ) {
            reason = Some(r);
            break;
        }
    }
    assert_eq!(reason, Some(0x08));
    assert!(close_session(&mut host, &mut radio, &clock, &session, 0x08));
    assert_eq!(host.closes, std::vec![0x08]);
}

#[test]
fn receive_reports_two_accessible_bytes_for_a_large_crc_bad_header() {
    for air_len in [252u8, 255] {
        let mut h = Harness::new();
        h.radio.push(FakeRadio::bad_frame(std::vec![0x21, air_len]));
        let mut arm = [0; 2];
        let result = receive(
            &mut h.radio,
            &h.clock,
            &mut h.host,
            &mut h.rx,
            CONNECT_END + 10_000,
            FINISH,
            64,
            &mut arm,
        );
        match result {
            RxResult::Packet(packet) => {
                assert_eq!(packet.len, 2, "only the header is accessible");
                assert_eq!(
                    packet.air_len, air_len,
                    "the declared length is kept for the anchor"
                );
                assert!(!packet.crc_ok);
            }
            _ => panic!("expected a CRC-bad packet for air_len {air_len}"),
        }
        assert!(h.host.acl_rx.is_empty(), "nothing is delivered");
        assert_eq!(h.host.rx_frames, std::vec![usize::from(air_len) + 2]);
    }
}

/// First CRC-bad completion is late enough that the old `until` has passed
/// when the next arm is attempted; only the response-updated one still arms.
fn narrow_window_case(start: u32) -> (u32, std::vec::Vec<u32>, usize) {
    // Enough to push the next arm past the original deadline; the refreshed
    // one still leaves room because it is based on the response time.
    const DELAY: u32 = 2800;
    let mut h = Harness::new_at(start);
    let old_until = h.session.conn.rx_complete_end_us();
    h.radio.push(Window {
        frame: Some(std::vec![0x21, 0]),
        crc_ok: false,
        done_delay_us: DELAY,
    });
    h.radio.push(FakeRadio::bad_frame(std::vec![0x21, 0]));
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    (old_until, h.radio.rx_entries.clone(), h.radio.sent.len())
}

#[test]
fn refreshed_until_accepts_the_second_bad_crc_after_a_late_first_completion() {
    for start in [0u32, 0xffff_fe00] {
        let (old_until, entries, sent) = narrow_window_case(start);
        assert_eq!(entries.len(), 2, "the second packet is armed and consumed");
        assert!(
            entries[1].wrapping_sub(old_until) < 0x8000_0000,
            "the second arm happens at or after the original deadline"
        );
        assert_eq!(
            sent, 1,
            "the second consecutive CRC-bad packet is not answered"
        );
    }
}

fn queued_data_acl(tag: TxTag) -> TxAcl {
    let mut bytes = [0u8; 251];
    bytes[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    TxAcl {
        tag,
        llid: 2,
        len: 4,
        bytes,
    }
}

/// Header with the given peer NESN/SN for an empty PDU.
fn empty_with(nesn: bool, sn: bool) -> Vec<u8> {
    let mut header = 0x01;
    if nesn {
        header |= 0x04;
    }
    if sn {
        header |= 0x08;
    }
    std::vec![header, 0x00]
}

#[test]
fn bad_crc_retransmits_the_outstanding_pdu_and_acks_only_once() {
    let mut h = Harness::new();
    let tag = crate::hci::connection::test_tag(1, 7);
    h.host.acl_tx.push_back(queued_data_acl(tag));

    // Peer accepts our data PDU but does not acknowledge it yet.
    h.radio.push(FakeRadio::frame(empty_with(false, false)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent.len(), 1);
    let first = h.radio.sent[0].clone();
    assert_eq!(first[0] & 3, 2, "a data PDU was sent");
    assert_eq!(&first[2..6], &[0xde, 0xad, 0xbe, 0xef]);
    assert!(h.host.acked.is_empty(), "not acknowledged yet");

    // A CRC-bad peer PDU whose NESN=1 would acknowledge ours if wrongly
    // trusted: the answer is the same PDU, byte for byte, with the same SN.
    h.radio.push(FakeRadio::bad_frame(std::vec![0x05, 0x00]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent.len(), 2);
    assert_eq!(
        h.radio.sent[1], first,
        "retransmission keeps payload and SN"
    );
    assert_eq!(h.host.stats[25], 1, "retransmission counted");
    assert!(h.host.acked.is_empty(), "a CRC error is not an ACK");

    // The peer's next PDU acknowledges the PDU exactly once.
    h.radio.push(FakeRadio::frame(empty_with(true, true)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.acked, std::vec![tag]);
    assert_eq!(h.host.stats[25], 1, "no new retransmission");

    // A later ACK cannot settle the same buffer again.
    h.radio.push(FakeRadio::frame(empty_with(true, false)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.acked, std::vec![tag]);
}

#[test]
fn late_response_retransmits_the_outstanding_pdu_and_acks_only_once() {
    let mut h = Harness::new();
    let tag = crate::hci::connection::test_tag(1, 9);
    h.host.acl_tx.push_back(queued_data_acl(tag));

    h.radio.push(FakeRadio::frame(empty_with(false, false)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    let first = h.radio.sent[0].clone();
    assert!(h.host.acked.is_empty());

    // The response is Late: nothing goes on air and the tag stays owned; the
    // peer PDU does not acknowledge it (NESN=0).
    h.radio.late = true;
    h.radio.push(FakeRadio::frame(empty_with(false, true)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent.len(), 1, "Late response never reached the air");
    assert_eq!(h.host.stats[19], 1);
    assert!(h.host.acked.is_empty(), "Late is not an ACK");

    // A Late response returns without advancing the event, so the outer loop
    // first re-runs the same (now expired) window and then moves on.
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent.len(), 1, "the expired window sends nothing");

    // The peer retransmits its SN because it never saw our ACK: our PDU is
    // retransmitted unchanged in the next event.
    h.radio.push(FakeRadio::frame(empty_with(false, true)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent.len(), 2);
    let again = &h.radio.sent[1];
    assert_eq!(again[0] & 0x0b, first[0] & 0x0b, "same LLID and SN");
    assert_eq!(&again[2..], &first[2..], "identical payload bytes");
    assert!(h.host.acked.is_empty());

    // The peer's next new PDU acknowledges once.
    h.radio.push(FakeRadio::frame(empty_with(true, false)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.acked, std::vec![tag]);

    h.radio.push(FakeRadio::frame(empty_with(true, true)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.acked, std::vec![tag]);
}

#[test]
fn feature_request_exchange_replies_after_the_empty_ack() {
    let mut h = Harness::new();
    // Central LL_FEATURE_REQ: LLID 3, NESN 0, SN 0.
    let mut req = std::vec![0x03, 9];
    req.extend_from_slice(&[0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
    h.radio.push(FakeRadio::frame(req));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent[0], std::vec![0x05, 0x00], "empty ack first");

    super::service_control(&mut h.host, &mut h.session, h.clock.now_us());

    // The central accepted our PDU: its next empty PDU is SN 1, NESN 1.
    h.radio.push(FakeRadio::frame(std::vec![0x0d, 0x00]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    let mut rsp = std::vec![0x0b, 9, 0x09]; // LLID 3, NESN 0, SN 1
    rsp.extend_from_slice(&h.host.local_features());
    assert_eq!(h.radio.sent[1], rsp);

    // Unacknowledged: the same PDU goes out byte for byte.
    h.radio.push(FakeRadio::frame(std::vec![0x0d, 0x00]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent[2], rsp);

    // The central accepted our RSP: our next PDU acknowledges SN 0, NESN 0.
    h.radio.push(FakeRadio::frame(std::vec![0x01, 0x00]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent[3], std::vec![0x05, 0x00]);
}

#[test]
fn host_reply_is_selected_in_the_same_event_and_retransmitted_verbatim() {
    let mut h = Harness::new();
    h.host
        .acl_replies
        .push_back(Some(AclReply::new(2, &[0x11, 0x22]).unwrap()));

    // Central ATT request: LLID 2, SN 0, NESN 0.
    h.radio
        .push(FakeRadio::frame(std::vec![0x02, 2, 0xaa, 0xbb]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(
        h.host.acl_reply_calls,
        std::vec![(2, std::vec![0xaa, 0xbb])]
    );
    assert_eq!(h.radio.sent.len(), 1, "reply chosen in the same event");
    // LLID 2, SN 0, NESN 1.
    assert_eq!(h.radio.sent[0], std::vec![0x06, 2, 0x11, 0x22]);

    // The same SN is a duplicate: no second Host call, same bytes retransmit.
    h.radio
        .push(FakeRadio::frame(std::vec![0x02, 2, 0xaa, 0xbb]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(
        h.host.acl_reply_calls.len(),
        1,
        "duplicate is not delivered"
    );
    assert_eq!(h.radio.sent[1], h.radio.sent[0]);

    // The Central acknowledges SN 0 and advances to SN 1.
    h.radio.push(FakeRadio::frame(empty_with(true, true)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.radio.sent[2].len(), 2, "an empty PDU");
    assert_eq!(h.radio.sent[2][0] & 3, 1);
    assert_eq!(h.radio.sent[2][1], 0);
}

#[test]
fn a_pending_control_reply_defers_the_acl_reply_to_the_next_event() {
    let mut h = Harness::new();
    h.session.pending_control = Some(DataPdu::new(3, &[0x07, 0xff]).unwrap());
    h.host
        .acl_replies
        .push_back(Some(AclReply::new(2, &[0x44]).unwrap()));

    h.radio
        .push(FakeRadio::frame(std::vec![0x02, 2, 0xaa, 0xbb]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(
        &h.radio.sent[0][2..],
        &[0x07, 0xff],
        "control owns the event"
    );
    assert!(
        h.session.pending_acl_reply.is_some(),
        "the request is held, not lost"
    );

    // The Central acknowledges the control PDU; the held reply goes out.
    h.radio.push(FakeRadio::frame(empty_with(true, true)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(&h.radio.sent[1][2..], &[0x44], "reply after contention");
    assert!(h.session.pending_acl_reply.is_none());
    assert_eq!(h.host.acl_reply_calls.len(), 1, "the Host ran once");
}

#[test]
fn an_occupied_reply_slot_backpressures_a_new_request_without_acking_it() {
    let mut h = Harness::new();
    h.session.pending_acl_reply = Some(AclReply::new(2, &[0x33]).unwrap());

    h.radio
        .push(FakeRadio::frame(std::vec![0x02, 2, 0xaa, 0xbb]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.acl_reply_calls.len(), 0, "not accepted");
    assert_eq!(h.host.stats[31], 1, "rx backpressure counted");
    assert_eq!(&h.radio.sent[0][2..], &[0x33], "only the held reply");
    // NESN 0: the rejected request was not acknowledged.
    assert_eq!(h.radio.sent[0][0] & 4, 0);
}

#[test]
fn a_termination_reply_uses_the_single_termination_state_machine() {
    let mut h = Harness::new();
    h.host
        .acl_replies
        .push_back(Some(AclReply::terminate(0x13)));

    // A non-empty continuation fragment: LLID 1, SN 0.
    h.radio.push(FakeRadio::frame(std::vec![0x01, 1, 0xaa]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(
        h.radio.sent[0],
        std::vec![0x07, 2, 2, 0x13],
        "one LL_TERMINATE_IND, LLID 3/NESN 1/SN 0"
    );
    assert!(h.session.pending_acl_reply.is_none(), "no second owner");

    // The Central acknowledges it: the link closes with the Host's reason.
    h.radio.push(FakeRadio::frame(empty_with(true, true)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Close(0x13));
    assert_eq!(h.host.stats[28], 1, "terminated ack counted");
    assert_eq!(h.host.stats[25], 0, "no retransmission on the ACK");
}

#[test]
fn the_host_payload_cap_rejects_28_bytes_and_accepts_27() {
    let mut h = Harness::new();
    h.host.payload_limit = 27;

    let mut frame = std::vec![0x02, 28];
    frame.extend_from_slice(&[0u8; 28]);
    h.radio.push(FakeRadio::frame(frame));
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.stats[9], 1, "oversize counted once");
    assert_eq!(h.radio.sent.len(), 0, "nothing answered, no ACK");

    // 27 octets is the boundary the Host accepts.
    h.host
        .acl_replies
        .push_back(Some(AclReply::new(2, &[0x55]).unwrap()));
    let mut frame = std::vec![0x02, 27];
    frame.extend_from_slice(&[0x55; 27]);
    h.radio.push(FakeRadio::frame(frame));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.stats[9], 1, "27 bytes is not oversize");
    assert_eq!(h.host.acl_reply_calls.len(), 1);
    assert_eq!(&h.radio.sent[0][2..], &[0x55]);
}

#[test]
fn host_capture_timeout_bounds_a_stalled_completion() {
    fn elapsed(capture: Option<u32>) -> u32 {
        let mut h = Harness::new();
        h.host.capture_timeout = capture;
        h.radio.stall_capture = true;
        h.radio.push(FakeRadio::frame(empty_pdu()));
        let start = h.clock.now();
        assert_eq!(h.event(FINISH), EventEnd::Continue);
        h.clock.now().wrapping_sub(start)
    }
    let default = elapsed(None);
    let configured = elapsed(Some(700));
    let delta = configured.wrapping_sub(default);
    // The engine default is `allowance + 64`; only the wait differs here.
    assert!((280..=340).contains(&delta), "delta was {delta}");
}

#[test]
fn host_rearm_window_sets_the_post_exchange_until() {
    let mut h = Harness::new();
    h.host.rearm = Some(500);
    h.radio.push(FakeRadio::frame(empty_pdu()));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert!(h.radio.windows_armed.len() >= 2, "a second window is armed");
    let window = h.radio.windows_armed[1];
    assert!((980..=1000).contains(&window), "window was {window}");
}

#[test]
fn encryption_requests_take_the_unsupported_path_without_the_feature_bit() {
    let mut h = Harness::new();
    assert_eq!(h.session.pending_enc_req, None);

    // LL_ENC_REQ (0x03) is a valid 23-octet control PDU.
    let mut req = std::vec![0x03, 23];
    req.extend_from_slice(&[0x03; 23]);
    h.radio.push(FakeRadio::frame(req));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(&h.radio.sent[0][2..], &[0x07, 0x03], "LL_UNKNOWN_RSP");
    assert!(h.session.pending_enc_req.is_none());
    assert_eq!(h.host.sec[2], 0, "no ENC_REQ statistics");

    // LL_START_ENC_REQ (0x05) is answered the same way.
    h.radio.push(FakeRadio::frame(std::vec![0x0f, 1, 0x05]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(&h.radio.sent[1][2..], &[0x07, 0x05], "LL_UNKNOWN_RSP");
    assert_eq!(h.host.sec[6], 0, "no START_ENC statistics");
}

#[test]
fn encryption_requests_are_hoisted_when_the_feature_bit_is_set() {
    let mut h = Harness::new();
    let features = crate::ll::ctrl::feature_bits(&[
        crate::ll::ctrl::FEATURE_LE_ENCRYPTION,
        crate::ll::ctrl::FEATURE_LE_DATA_LENGTH_EXTENSION,
        crate::ll::ctrl::FEATURE_LE_CSA2,
    ]);
    h.host.features = features;
    h.session = Session::new(params(), false, CONNECT_END, 0, [0x11; 12], features);

    let mut req = std::vec![0x03, 23];
    req.extend_from_slice(&[0x03; 23]);
    h.radio.push(FakeRadio::frame(req));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert!(h.session.pending_enc_req.is_some(), "hoisted for AES");
    assert_eq!(h.radio.sent[0], std::vec![0x05, 0x00], "empty ack");
    assert_eq!(h.host.sec[2], 1, "ENC_REQ counted");
}

#[test]
fn feature_request_suppression_keeps_the_control_queue_empty() {
    fn pending_after(allowed: bool) -> bool {
        let mut h = Harness::new();
        h.host.feature_request_allowed = allowed;
        h.radio.push(FakeRadio::frame(empty_pdu()));
        h.radio.push(FakeRadio::missed());
        assert_eq!(h.event(FINISH), EventEnd::Continue);
        assert!(h.session.established());
        // Settle our empty reply so the link is idle.
        let _ = h.session.link.on_rx(0x0d, &[], true, true);
        assert!(!h.session.link.has_outstanding());
        super::service_dle(&mut h.host, &mut h.session);
        h.session.pending_control.is_some()
    }
    assert!(pending_after(true), "the default still starts the exchange");
    assert!(!pending_after(false), "suppressed for this Host");
}

#[test]
fn a_remote_terminate_drops_a_held_reply_and_closes() {
    let mut h = Harness::new();
    h.session.pending_acl_reply = Some(AclReply::new(2, &[0x66]).unwrap());

    // LL_TERMINATE_IND (0x02) from the Central: LLID 3, SN 0.
    h.radio
        .push(FakeRadio::frame(std::vec![0x03, 2, 0x02, 0x13]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Close(0x13));
    assert_eq!(h.radio.sent.len(), 1, "only the acknowledge PDU");
    assert_eq!(h.radio.sent[0][0] & 3, 1, "empty PDU, not the reply");
    assert!(h.session.pending_acl_reply.is_none());
}

#[test]
fn establishment_limit_closes_at_the_configured_event_and_counts_once() {
    let mut h = Harness::new();
    h.host.establishment_limit = Some(6);
    let mut control = Control::Continue;
    for _ in 0..40 {
        if h.session.event_counter() == 6 {
            break;
        }
        control = h.step(FINISH);
        assert_eq!(control, Control::Continue);
    }
    assert_eq!(h.session.event_counter(), 6);
    assert_eq!(h.host.stats[30], 0, "events below the limit are allowed");
    let mut control = Control::Continue;
    for _ in 0..8 {
        control = h.step(FINISH);
        if control != Control::Continue {
            break;
        }
    }
    assert_eq!(control, Control::Closed(0x3e));
    assert_eq!(h.host.stats[30], 1, "counted once");
    assert_eq!(h.host.closes, std::vec![0x3e]);
    assert_eq!(h.host.stats[37], 0x3e, "close reason recorded");
}

#[test]
fn establishment_limit_catches_up_without_arming_a_forbidden_event() {
    let mut h = Harness::new();
    h.host.establishment_limit = Some(6);
    for _ in 0..40 {
        if h.session.event_counter() == 5 {
            break;
        }
        assert_eq!(h.step(FINISH), Control::Continue);
    }
    assert_eq!(h.session.event_counter(), 5);
    let arms = h.radio.windows_armed.len();

    // One delayed step skips events past the limit via the catch-up loop.
    h.clock.advance(35_000);
    assert_eq!(h.step(FINISH), Control::Continue);
    assert_eq!(h.radio.windows_armed.len(), arms, "no RX armed");
    assert_eq!(h.host.stats[30], 0);

    assert_eq!(h.step(FINISH), Control::Closed(0x3e));
    assert_eq!(h.host.stats[30], 1);
}

#[test]
fn an_established_link_never_trips_the_establishment_limit() {
    let mut h = Harness::new();
    h.host.establishment_limit = Some(6);
    h.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert!(h.session.established());
    for _ in 0..10 {
        h.step(FINISH);
    }
    assert!(h.session.event_counter() >= 6);
    assert_eq!(h.host.stats[30], 0);
    assert!(h.host.closes.is_empty());
}

#[test]
fn the_run_budget_wins_over_the_establishment_limit() {
    let mut h = Harness::new();
    h.host.establishment_limit = Some(6);
    for _ in 0..40 {
        if h.session.event_counter() == 6 {
            break;
        }
        assert_eq!(h.step(FINISH), Control::Continue);
    }
    let now = h.clock.now();
    assert_eq!(h.step(now), Control::Finish);
    assert_eq!(h.host.stats[30], 0, "no establishment failure counted");
    assert!(h.host.closes.is_empty());
}

#[test]
fn establishment_limit_does_not_publish_when_the_stop_fails() {
    let mut h = Harness::new();
    h.host.establishment_limit = Some(6);
    for _ in 0..40 {
        if h.session.event_counter() == 6 {
            break;
        }
        assert_eq!(h.step(FINISH), Control::Continue);
    }
    h.radio.stop_ok = false;
    let mut control = Control::Continue;
    for _ in 0..8 {
        control = h.step(FINISH);
        if control != Control::Continue {
            break;
        }
    }
    assert_eq!(control, Control::StopTimeout);
    assert_eq!(h.host.stats[30], 1);
    assert!(h.host.closes.is_empty(), "no disconnect published");
    assert!(h.host.after_close == 0);
}

#[test]
fn an_encryption_capable_session_never_captures_acl_replies() {
    let mut h = Harness::new();
    let features = crate::ll::ctrl::feature_bits(&[
        crate::ll::ctrl::FEATURE_LE_ENCRYPTION,
        crate::ll::ctrl::FEATURE_LE_DATA_LENGTH_EXTENSION,
        crate::ll::ctrl::FEATURE_LE_CSA2,
    ]);
    h.host.features = features;
    h.session = Session::new(params(), false, CONNECT_END, 0, [0x11; 12], features);
    h.host
        .acl_replies
        .push_back(Some(AclReply::new(2, &[0x77]).unwrap()));

    h.radio
        .push(FakeRadio::frame(std::vec![0x02, 2, 0xaa, 0xbb]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.acl_reply_calls.len(), 0, "hook not consulted");
    assert!(h.session.pending_acl_reply.is_none());
}

#[test]
fn a_non_late_tx_error_keeps_the_reply_for_retransmission() {
    let mut h = Harness::new();
    h.host
        .acl_replies
        .push_back(Some(AclReply::new(2, &[0x88]).unwrap()));
    h.radio.tx_error = Some(crate::Error::Timeout);

    // A failed response ends the event early; do not queue another window.
    h.radio
        .push(FakeRadio::frame(std::vec![0x02, 2, 0xaa, 0xbb]));
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(h.host.stats[20], 1, "tx_err counted");
    assert_eq!(h.host.stats[19], 0, "not Late");
    assert_eq!(h.radio.sent.len(), 0, "nothing went on air");
    assert!(h.session.link.has_outstanding());

    // The peer's next PDU does not acknowledge it: the reply retransmits.
    h.radio.push(FakeRadio::frame(empty_with(false, true)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert_eq!(&h.radio.sent[0][2..], &[0x88]);
    assert_eq!(h.host.acl_reply_calls.len(), 1, "business ran once");

    h.radio.push(FakeRadio::frame(empty_with(true, false)));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    // The acknowledged reply advanced our SN: the response is a fresh PDU.
    assert_eq!(h.radio.sent[1][0] & 8, 8, "SN advanced after the ACK");
    assert_eq!(h.host.stats[25], 1, "retransmitted exactly once");
}

#[test]
fn maximum_length_frames_never_reach_the_host() {
    for len in [251usize, 252, 255] {
        let mut h = Harness::new();
        h.host
            .acl_replies
            .push_back(Some(AclReply::new(2, &[0x01]).unwrap()));
        let mut frame = std::vec![0x02, len as u8];
        frame.extend_from_slice(&[0xaa; 255][..len]);
        h.radio.push(FakeRadio::frame(frame));
        assert_eq!(h.event(FINISH), EventEnd::Continue, "len {len}");
        assert_eq!(h.host.acl_reply_calls.len(), 0, "len {len}");
        assert_eq!(h.host.stats[9], 1, "len {len} counted invalid");
    }
}

#[test]
fn a_crc_bad_maximum_length_header_only_establishes() {
    let mut h = Harness::new();
    h.radio.push(FakeRadio::bad_frame(std::vec![0x01, 255]));
    h.radio.push(FakeRadio::missed());
    assert_eq!(h.event(FINISH), EventEnd::Continue);
    assert!(h.session.established());
    assert_eq!(h.host.stats[8], 1, "crc error counted");
    assert_eq!(h.host.stats[9], 0, "not an invalid PDU");
}
