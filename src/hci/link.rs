//! SoftRunner bridge for the shared Peripheral session engine.
//!
//! [`RunnerHost`] owns the real SoftRunner wiring (ACL, lifecycle, DLE, LTK,
//! radio requests); the example supplies only its executor and diagnostics
//! through [`LinkExtras`]. This keeps one connection lifecycle implementation
//! for every HCI-backed Peripheral example.

use crate::crypto::engine::AesEngine;
use crate::hci::connection::{ConnectionBridge, ConnectionInfo, RadioRequest, TxAcl, TxTag};
use crate::hci::runner::LtkReply;
use crate::hci::transport::LinkKey;
use crate::hci::SoftRunner;
use crate::ll::link::{LinkHost, X1Snapshot};

/// AES engine constructible from a session key.
pub trait AesFromKey: AesEngine {
    fn from_key(key: &[u8; 16]) -> Self;
}

/// Example-side hooks: executor pumping, persistence, diagnostics.
///
/// Hooks that manipulate the Host take `soft` explicitly: the runner is owned
/// by [`RunnerHost`], not by the extras.
pub trait LinkExtras {
    type Aes: AesFromKey;

    fn local_features(&self) -> [u8; 8];

    fn stat_inc(&mut self, slot: usize);
    fn stat_put(&mut self, slot: usize, value: u32);
    fn stat_get(&self, slot: usize) -> u32;
    fn sec_inc(&mut self, slot: usize);
    fn sec_put(&mut self, slot: usize, value: u32);
    fn sec_error(&mut self, reason: u8) {
        self.sec_inc(12);
        self.sec_put(15, u32::from(reason));
    }

    #[allow(clippy::too_many_arguments)]
    fn trace(
        &mut self,
        now_us: u32,
        kind: u32,
        event: u16,
        channel: u8,
        header: u8,
        len: u8,
        a: u32,
        b: u32,
    );

    fn diag_acl_raw(&mut self, llid: u8, payload: &[u8], ciphertext: bool);
    fn diag_acl_tx(&mut self, _llid: u8, _payload: &[u8]) {}
    fn diag_acl_plain(&mut self, llid: u8, payload: &[u8]);
    fn diag_control_opcode(&mut self, opcode: u8);
    fn note_bad_pdu(&mut self, header: u8, len: usize);
    fn note_rx_frame(&mut self, len: usize);
    fn note_rx_oversize(&mut self);
    fn note_start_req_queued(&mut self);
    fn note_start_rsp_queued(&mut self);
    fn diag_skipped_event(&mut self);

    /// Fill `peer_rpa`/`peer_identity` before the bridge publishes the link.
    fn resolve_peer(&mut self, _soft: &mut SoftRunner, _info: &mut ConnectionInfo) {}
    /// The bridge accepted the link (privacy bookkeeping, for example).
    fn published_connection(&mut self, _soft: &mut SoftRunner) {}

    fn publish_x1(&mut self, snapshot: &X1Snapshot);

    fn idle_gap(&mut self, soft: &mut SoftRunner, deadline: u32, until: u32);
    fn after_close(&mut self, soft: &mut SoftRunner);
    fn on_disconnect_request(&mut self, reason: u8);
    fn pre_iteration(&mut self);
}

/// [`LinkHost`] over the real `SoftRunner` plus example extras.
pub struct RunnerHost<'a, X: LinkExtras> {
    soft: &'a mut SoftRunner,
    extras: X,
    slot: u8,
    /// Full identity this host operates on. A slot rebuild (close, Reset)
    /// changes it, so a host kept across the rebuild goes stale instead of
    /// acting on the new link.
    key: LinkKey,
}

impl<'a, X: LinkExtras> RunnerHost<'a, X> {
    /// Slot 0, the N=1 wiring every existing example uses.
    pub fn new(soft: &'a mut SoftRunner, extras: X) -> Self {
        Self::for_slot(0, soft, extras)
    }

    /// Bind this host to one transport slot and the identity that slot holds
    /// now; a later publish within this host's life rebinds it to the new key.
    pub fn for_slot(slot: u8, soft: &'a mut SoftRunner, extras: X) -> Self {
        assert!(usize::from(slot) < crate::hci::transport::MAX_LINKS);
        let key = soft.bridge_slot(slot).link_key();
        Self {
            soft,
            extras,
            slot,
            key,
        }
    }

    /// Pin an explicit identity, for an owner that stored the key when the
    /// session was published.
    pub fn for_link(key: LinkKey, soft: &'a mut SoftRunner, extras: X) -> Self {
        assert!(usize::from(key.slot) < crate::hci::transport::MAX_LINKS);
        Self {
            soft,
            extras,
            slot: key.slot,
            key,
        }
    }

    fn bridge(&self) -> &ConnectionBridge {
        self.soft.bridge_slot(self.slot)
    }

    fn bridge_mut(&mut self) -> &mut ConnectionBridge {
        self.soft.bridge_slot_mut(self.slot)
    }

    /// Handle of this slot's live link, if the pinned key still matches.
    fn live_handle(&self) -> Option<u16> {
        if self.live() {
            self.bridge().handle()
        } else {
            None
        }
    }

    /// Identity this host was constructed for.
    pub fn key(&self) -> LinkKey {
        self.key
    }

    /// True while the slot still holds the identity this host was built for.
    fn live(&self) -> bool {
        self.bridge().link_key() == self.key
    }
}

impl<X: LinkExtras> LinkHost for RunnerHost<'_, X> {
    type Aes = X::Aes;

    fn local_features(&self) -> [u8; 8] {
        self.extras.local_features()
    }

    fn new_aes(&mut self, key: &[u8; 16]) -> X::Aes {
        X::Aes::from_key(key)
    }
    fn fill_random(&mut self, out: &mut [u8]) {
        self.soft.fill_random(out);
    }

    fn stat_inc(&mut self, slot: usize) {
        self.extras.stat_inc(slot);
    }
    fn stat_put(&mut self, slot: usize, value: u32) {
        self.extras.stat_put(slot, value);
    }
    fn stat_get(&self, slot: usize) -> u32 {
        self.extras.stat_get(slot)
    }
    fn sec_inc(&mut self, slot: usize) {
        self.extras.sec_inc(slot);
    }
    fn sec_put(&mut self, slot: usize, value: u32) {
        self.extras.sec_put(slot, value);
    }
    fn sec_error(&mut self, reason: u8) {
        self.extras.sec_error(reason);
    }

    fn trace(
        &mut self,
        now_us: u32,
        kind: u32,
        event: u16,
        channel: u8,
        header: u8,
        len: u8,
        a: u32,
        b: u32,
    ) {
        self.extras
            .trace(now_us, kind, event, channel, header, len, a, b);
    }

    fn diag_acl_raw(&mut self, llid: u8, payload: &[u8], ciphertext: bool) {
        self.extras.diag_acl_raw(llid, payload, ciphertext);
    }
    fn diag_acl_tx(&mut self, llid: u8, payload: &[u8]) {
        self.extras.diag_acl_tx(llid, payload);
    }
    fn diag_acl_plain(&mut self, llid: u8, payload: &[u8]) {
        self.extras.diag_acl_plain(llid, payload);
    }
    fn diag_control_opcode(&mut self, opcode: u8) {
        self.extras.diag_control_opcode(opcode);
    }
    fn note_bad_pdu(&mut self, header: u8, len: usize) {
        self.extras.note_bad_pdu(header, len);
    }
    fn note_rx_frame(&mut self, len: usize) {
        self.extras.note_rx_frame(len);
    }
    fn note_rx_oversize(&mut self) {
        self.extras.note_rx_oversize();
    }
    fn note_start_req_queued(&mut self) {
        self.extras.note_start_req_queued();
    }
    fn note_start_rsp_queued(&mut self) {
        self.extras.note_start_rsp_queued();
    }
    fn diag_skipped_event(&mut self) {
        self.extras.diag_skipped_event();
    }

    fn can_receive_acl(&mut self, llid: u8, len: usize) -> bool {
        self.live() && self.bridge().can_receive_acl(llid, len)
    }
    fn receive_acl(&mut self, llid: u8, payload: &[u8]) -> bool {
        self.live() && self.bridge_mut().receive_acl(llid, payload).is_ok()
    }
    fn take_tx_acl(&mut self) -> Option<TxAcl> {
        if !self.live() {
            return None;
        }
        self.bridge_mut().take_tx_acl()
    }
    fn has_tx_acl(&self) -> bool {
        self.live() && self.bridge().has_tx_acl()
    }
    fn ack_tx(&mut self, tag: TxTag) -> bool {
        self.live() && self.bridge_mut().ack_tx(tag)
    }

    fn is_connected(&self) -> bool {
        self.live() && self.bridge().is_connected()
    }
    fn publish_connection(&mut self, info: &mut ConnectionInfo) -> bool {
        // One HCI label per live link: the engine reports one connection per
        // slot, and two slots must not publish the same handle.
        info.handle = 1 + u16::from(self.slot);
        self.extras.resolve_peer(self.soft, info);
        if self.bridge_mut().connected(*info).is_err() {
            return false;
        }
        // The successful publish is the one rebinding point; every later call
        // must still match this exact generation.
        self.key = self.bridge().link_key();
        self.extras.published_connection(self.soft);
        true
    }
    fn disable_adv(&mut self) {
        self.soft.ll.adv.enabled = false;
    }
    fn connection_closed(&mut self, reason: u8) {
        let key = self.key();
        self.soft.connection_closed_on(key, reason);
    }
    fn local_handle(&self) -> Option<u16> {
        self.live_handle()
    }
    fn encryption_change(&mut self, handle: u16, status: u8, enabled: u8) {
        // Never route by handle alone: the same handle may live in the other
        // slot or in a later generation.
        if self.live() && self.bridge().handle() == Some(handle) {
            let _ = self.soft.encryption_change(handle, status, enabled);
        }
    }
    fn connection_updated(&mut self, interval: u16, latency: u16, timeout: u16) -> bool {
        self.live()
            && self
                .bridge_mut()
                .connection_updated(interval, latency, timeout)
                .is_ok()
    }
    fn data_length_change(
        &mut self,
        tx_octets: u16,
        tx_time: u16,
        rx_octets: u16,
        rx_time: u16,
    ) -> bool {
        self.live()
            && self
                .bridge_mut()
                .data_length_change(tx_octets, tx_time, rx_octets, rx_time)
                .is_ok()
    }

    fn take_ltk_reply(&mut self) -> Option<LtkReply> {
        if !self.live() {
            return None;
        }
        let key = self.key;
        self.soft.take_ltk_reply_for(key)
    }
    fn take_encryption_request(&mut self) -> Option<crate::hci::runner::EnableEncryption> {
        if !self.live() {
            return None;
        }
        self.soft.take_encryption_request_on(self.slot)
    }
    fn take_connection_update(&mut self) -> Option<(u16, u16, u16, u16)> {
        if !self.live() {
            return None;
        }
        self.bridge_mut().take_connection_update()
    }
    fn push_ltk_request(&mut self, rand: [u8; 8], ediv: u16) -> bool {
        if !self.live() {
            return false;
        }
        let Some(handle) = self.bridge().handle() else {
            return false;
        };
        self.soft.push_ltk_request_on(handle, rand, ediv)
    }
    fn take_data_length_request(&mut self) -> Option<(u16, u16)> {
        if !self.live() {
            return None;
        }
        self.bridge_mut().take_data_length_request()
    }
    fn take_phy_request(&mut self) -> Option<(u8, u8)> {
        if !self.live() {
            return None;
        }
        self.bridge_mut().take_phy_request()
    }
    fn phy_update_complete(&mut self, status: u8, tx: u8, rx: u8) {
        if !self.live() {
            return;
        }
        let handle = self.bridge().handle();
        if let Some(handle) = handle {
            let _ = self.soft.phy_update_complete_on(handle, status, tx, rx);
        }
    }

    fn publish_x1(&mut self, snapshot: &X1Snapshot) {
        self.extras.publish_x1(snapshot);
    }

    fn idle_gap(&mut self, deadline: u32, until: u32) {
        self.extras.idle_gap(self.soft, deadline, until);
    }
    fn after_close(&mut self) {
        self.extras.after_close(self.soft);
    }
    fn on_reset(&mut self) {
        if self.live() {
            self.bridge_mut().reset_finished();
        }
    }
    fn on_disconnect_request(&mut self, reason: u8) {
        self.extras.on_disconnect_request(reason);
    }
    fn pre_iteration(&mut self) {
        self.extras.pre_iteration();
    }
    fn take_radio_request(&mut self) -> Option<RadioRequest> {
        if !self.live() {
            return None;
        }
        self.bridge_mut().take_radio_request()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::hci::transport;
    use crate::ll::link::tests::{
        bad_crc_frame, params, FakeClock, FakeRadio, CONNECT_END, FINISH,
    };
    use crate::ll::link::{self, Control, EventEnd, Session, X1Snapshot};
    use crate::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};

    struct Counters {
        stats: [u32; 64],
        sec: [u32; 16],
    }

    /// Minimal extras: stats plus a clock advanced by the idle gap.
    struct X {
        counters: Rc<core::cell::RefCell<Counters>>,
        now: Rc<Cell<u32>>,
        closes: Rc<Cell<u32>>,
    }

    impl LinkExtras for X {
        type Aes = crate::crypto::aes::Aes128;

        fn local_features(&self) -> [u8; 8] {
            crate::ll::ctrl::feature_bits(&[
                crate::ll::ctrl::FEATURE_LE_DATA_LENGTH_EXTENSION,
                crate::ll::ctrl::FEATURE_LE_CSA2,
            ])
        }

        fn stat_inc(&mut self, slot: usize) {
            let mut c = self.counters.borrow_mut();
            c.stats[slot] = c.stats[slot].wrapping_add(1);
        }
        fn stat_put(&mut self, slot: usize, value: u32) {
            self.counters.borrow_mut().stats[slot] = value;
        }
        fn stat_get(&self, slot: usize) -> u32 {
            self.counters.borrow().stats[slot]
        }
        fn sec_inc(&mut self, slot: usize) {
            let mut c = self.counters.borrow_mut();
            c.sec[slot] = c.sec[slot].wrapping_add(1);
        }
        fn sec_put(&mut self, slot: usize, value: u32) {
            self.counters.borrow_mut().sec[slot] = value;
        }
        fn trace(&mut self, _a: u32, _b: u32, _c: u16, _d: u8, _e: u8, _f: u8, _g: u32, _h: u32) {}
        fn diag_acl_raw(&mut self, _llid: u8, _payload: &[u8], _ciphertext: bool) {}
        fn diag_acl_plain(&mut self, _llid: u8, _payload: &[u8]) {}
        fn diag_control_opcode(&mut self, _opcode: u8) {}
        fn note_bad_pdu(&mut self, _header: u8, _len: usize) {}
        fn note_rx_frame(&mut self, _len: usize) {}
        fn note_rx_oversize(&mut self) {}
        fn note_start_req_queued(&mut self) {}
        fn note_start_rsp_queued(&mut self) {}
        fn diag_skipped_event(&mut self) {}
        fn publish_x1(&mut self, _snapshot: &X1Snapshot) {}
        fn idle_gap(&mut self, _soft: &mut SoftRunner, _deadline: u32, until: u32) {
            self.now.set(until);
        }
        fn after_close(&mut self, _soft: &mut SoftRunner) {
            self.closes.set(self.closes.get() + 1);
        }
        fn on_disconnect_request(&mut self, _reason: u8) {}
        fn pre_iteration(&mut self) {}
    }

    /// Every test here touches the global channels and link table.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        let guard = crate::hci::test_lock::lock();
        transport::drain_channels_for_test();
        guard
    }

    struct Bench {
        clock: FakeClock,
        radio: FakeRadio,
        soft: SoftRunner,
        counters: Rc<core::cell::RefCell<Counters>>,
        now: Rc<Cell<u32>>,
        closes: Rc<Cell<u32>>,
        rx: DmaBuf<RX_DMA_MIN>,
        tx: DmaBuf<MAX_PDU>,
        session: Session<crate::crypto::aes::Aes128>,
    }

    impl Bench {
        fn new() -> Self {
            let clock = FakeClock::new(0);
            let stops = Rc::new(Cell::new(0));
            let radio = FakeRadio::new(&clock, stops);
            let counters = Rc::new(core::cell::RefCell::new(Counters {
                stats: [0; 64],
                sec: [0; 16],
            }));
            let now = clock.handle();
            let closes = Rc::new(Cell::new(0));
            let mut soft = SoftRunner::new();
            let extras = X {
                counters: counters.clone(),
                now: clock.handle(),
                closes: closes.clone(),
            };
            let host = RunnerHost::new(&mut soft, extras);
            let session = Session::new(
                params(),
                false,
                CONNECT_END,
                0,
                [0x44; 12],
                host.local_features(),
            );
            Self {
                clock,
                radio,
                soft,
                counters,
                now,
                closes,
                rx: DmaBuf::zeroed(),
                tx: DmaBuf::zeroed(),
                session,
            }
        }

        fn extras(&self) -> X {
            X {
                counters: self.counters.clone(),
                now: self.now.clone(),
                closes: self.closes.clone(),
            }
        }

        fn event(&mut self) -> EventEnd {
            let extras = self.extras();
            let mut host = RunnerHost::new(&mut self.soft, extras);
            link::connection_event(
                &mut self.radio,
                &self.clock,
                &mut self.rx,
                &mut self.tx,
                &mut self.session,
                &mut host,
                FINISH,
            )
        }

        fn stat(&self, slot: usize) -> u32 {
            self.counters.borrow().stats[slot]
        }
    }

    #[test]
    fn real_runner_publishes_the_link_and_stops_advertising() {
        let _serial = serial();
        let mut b = Bench::new();
        b.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
        assert_eq!(b.event(), EventEnd::Continue);
        assert!(b.soft.bridge.is_connected());
        assert_eq!(b.stat(16), 1, "one event ran");
    }

    #[test]
    fn close_through_the_runner_clears_the_bridge_once() {
        let _serial = serial();
        let mut b = Bench::new();
        b.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
        assert_eq!(b.event(), EventEnd::Continue);
        let epoch = b.soft.bridge.epoch();

        let extras = b.extras();
        let mut host = RunnerHost::new(&mut b.soft, extras);
        assert!(link::close_session(
            &mut host,
            &mut b.radio,
            &b.clock,
            &b.session,
            0x08
        ));
        drop(host);
        assert!(!b.soft.bridge.is_connected());
        assert_ne!(b.soft.bridge.epoch(), epoch, "close bumps the link epoch");
        assert_eq!(b.closes.get(), 1);
        assert_eq!(b.stat(37), 0x08, "close reason recorded");
    }

    #[test]
    fn full_acl_queue_reports_backpressure_without_closing() {
        let _serial = serial();
        let mut b = Bench::new();
        b.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
        assert_eq!(b.event(), EventEnd::Continue);

        // Fill the bridge's five RX slots from the Host side.
        // The bridge holds five RX slots.
        for _ in 0..5 {
            b.soft
                .bridge
                .receive_acl(2, &[0xaa, 0xbb, 0xcc, 0xdd])
                .unwrap();
        }
        assert!(!b.soft.bridge.can_receive_acl(2, 4));

        // A fresh start fragment cannot be accepted while the queue is full.
        b.radio.push(FakeRadio::frame(std::vec![
            0x02, 0x04, 0x01, 0x02, 0x03, 0x04
        ]));
        assert_eq!(b.event(), EventEnd::Continue);
        assert!(b.stat(31) >= 1, "RX backpressure counted");
        assert!(b.soft.bridge.is_connected());
    }

    #[test]
    fn reset_through_the_runner_keeps_the_link_identity_until_close() {
        let _serial = serial();
        let mut b = Bench::new();
        b.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
        assert_eq!(b.event(), EventEnd::Continue);
        let epoch = b.soft.bridge.epoch();

        // Queue a Host Reset; `step` stops the radio and calls reset_finished.
        b.soft.bridge.request_reset();
        let extras = b.extras();
        let mut host = RunnerHost::new(&mut b.soft, extras);
        assert_eq!(
            link::step(
                &mut b.session,
                &mut host,
                &mut b.radio,
                &b.clock,
                &mut b.rx,
                &mut b.tx,
                FINISH
            ),
            Control::Reset
        );
        drop(host);
        assert_ne!(b.soft.bridge.epoch(), epoch);
        assert_eq!(b.closes.get(), 0, "Reset is not a disconnect event");
    }

    /// (event code, handle, reason) for the lifecycle packets a Host reads.
    fn event_kind(packet: &crate::hci::transport::Packet) -> (u8, u16, u8) {
        let payload = packet.payload();
        match payload[0] {
            0x3e => (0x3e, u16::from_le_bytes([payload[4], payload[5]]), 0),
            0x05 => (
                0x05,
                u16::from_le_bytes([payload[3], payload[4]]),
                payload[5],
            ),
            code => (code, 0, 0),
        }
    }

    fn read_events() -> std::vec::Vec<(u8, u16, u8)> {
        let mut out = std::vec::Vec::new();
        while let Some(packet) = transport::try_receive_controller_packet() {
            out.push(event_kind(&packet));
        }
        out
    }

    fn new_session(clock: &FakeClock) -> Session<crate::crypto::aes::Aes128> {
        let now = clock.now();
        Session::new(
            params(),
            false,
            now.wrapping_add(CONNECT_END),
            now,
            [0x44; 12],
            crate::ll::ctrl::feature_bits(&[
                crate::ll::ctrl::FEATURE_LE_DATA_LENGTH_EXTENSION,
                crate::ll::ctrl::FEATURE_LE_CSA2,
            ]),
        )
    }

    fn connect(
        soft: &mut SoftRunner,
        radio: &mut FakeRadio,
        clock: &FakeClock,
        rx: &mut DmaBuf<RX_DMA_MIN>,
        tx: &mut DmaBuf<MAX_PDU>,
        counters: &Rc<core::cell::RefCell<Counters>>,
        now: &Rc<Cell<u32>>,
        closes: &Rc<Cell<u32>>,
    ) -> Session<crate::crypto::aes::Aes128> {
        let mut session = new_session(clock);
        radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
        let extras = X {
            counters: counters.clone(),
            now: now.clone(),
            closes: closes.clone(),
        };
        let mut host = RunnerHost::new(soft, extras);
        assert_eq!(
            link::connection_event(radio, clock, rx, tx, &mut session, &mut host, FINISH),
            EventEnd::Continue
        );
        session
    }

    /// The Host stalls, so the event slots fill; the next publish fails with
    /// 0x1f without emitting a bogus disconnect, and draining recovers.
    #[test]
    fn stalled_host_backpressure_fails_publish_cleanly_and_recovers() {
        let _serial = serial();
        let clock = FakeClock::new(0);
        let stops = Rc::new(Cell::new(0));
        let mut radio = FakeRadio::new(&clock, stops);
        let mut soft = SoftRunner::new();
        let counters = Rc::new(core::cell::RefCell::new(Counters {
            stats: [0; 64],
            sec: [0; 16],
        }));
        let now = clock.handle();
        let closes = Rc::new(Cell::new(0));
        let mut rx = DmaBuf::zeroed();
        let mut tx = DmaBuf::zeroed();

        // Two links move four events into the transport channel (capacity 4).
        for _ in 0..2 {
            let session = connect(
                &mut soft, &mut radio, &clock, &mut rx, &mut tx, &counters, &now, &closes,
            );
            let extras = X {
                counters: counters.clone(),
                now: now.clone(),
                closes: closes.clone(),
            };
            let mut host = RunnerHost::new(&mut soft, extras);
            assert!(link::close_session(
                &mut host, &mut radio, &clock, &session, 0x13
            ));
            drop(host);
            assert!(soft.pump_once(), "connection event moved to the channel");
            assert!(soft.pump_once(), "disconnection event moved to the channel");
        }
        assert_eq!(closes.get(), 2);

        // Eight more links fill the 16 bridge slots while the channel is full.
        // (Two lifecycle events per link; the last one leaves zero free.)
        for _ in 0..8 {
            let session = connect(
                &mut soft, &mut radio, &clock, &mut rx, &mut tx, &counters, &now, &closes,
            );
            let extras = X {
                counters: counters.clone(),
                now: now.clone(),
                closes: closes.clone(),
            };
            let mut host = RunnerHost::new(&mut soft, extras);
            assert!(link::close_session(
                &mut host, &mut radio, &clock, &session, 0x13
            ));
            drop(host);
            assert!(!soft.pump_once(), "the channel is full");
        }

        // The next publish cannot reserve lifecycle storage.
        let mut session = new_session(&clock);
        radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
        let extras = X {
            counters: counters.clone(),
            now: now.clone(),
            closes: closes.clone(),
        };
        let mut host = RunnerHost::new(&mut soft, extras);
        assert_eq!(
            link::connection_event(
                &mut radio,
                &clock,
                &mut rx,
                &mut tx,
                &mut session,
                &mut host,
                FINISH
            ),
            EventEnd::Close(0x1f),
            "bridge Full ends the attempt"
        );
        drop(host);
        assert!(!soft.bridge.is_connected());
        let extras = X {
            counters: counters.clone(),
            now: now.clone(),
            closes: closes.clone(),
        };
        let mut host = RunnerHost::new(&mut soft, extras);
        assert!(link::close_session(
            &mut host, &mut radio, &clock, &session, 0x1f
        ));
        drop(host);
        assert_eq!(
            closes.get(),
            11,
            "the failed attempt still closes the radio side"
        );

        // Draining the channel yields every lifecycle event once, in order.
        let first = read_events();
        assert_eq!(
            first,
            std::vec![
                (0x3e, 0x0001, 0),
                (0x05, 0x0001, 0x13),
                (0x3e, 0x0001, 0),
                (0x05, 0x0001, 0x13)
            ]
        );

        // Flush the sixteen events the stalled Host left in the bridge.
        let mut second = std::vec::Vec::new();
        while second.len() < 16 {
            assert!(soft.pump_once(), "queued lifecycle event flushed");
            second.extend(read_events());
        }
        let expected: std::vec::Vec<(u8, u16, u8)> = (0..8)
            .flat_map(|_| [(0x3e, 0x0001, 0), (0x05, 0x0001, 0x13)])
            .collect();
        assert_eq!(second, expected, "the failed publish produced no event");

        // With the slots drained a new link publishes normally.
        let session = connect(
            &mut soft, &mut radio, &clock, &mut rx, &mut tx, &counters, &now, &closes,
        );
        assert!(soft.bridge.is_connected(), "recovered after draining");
        let extras = X {
            counters: counters.clone(),
            now: now.clone(),
            closes: closes.clone(),
        };
        let mut host = RunnerHost::new(&mut soft, extras);
        assert!(link::close_session(
            &mut host, &mut radio, &clock, &session, 0x08
        ));
        drop(host);
        assert!(soft.pump_once());
        assert!(soft.pump_once());
        assert_eq!(
            read_events(),
            std::vec![(0x3e, 0x0001, 0), (0x05, 0x0001, 0x08)]
        );
        assert_eq!(closes.get(), 12);
    }

    /// Two live links must not publish the same HCI handle: the transport
    /// routes ACL data by it, so slot 1 gets its own label.
    #[test]
    fn two_slots_publish_distinct_handles() {
        let _serial = serial();
        let mut soft = SoftRunner::new();
        let counters = Rc::new(core::cell::RefCell::new(Counters {
            stats: [0; 64],
            sec: [0; 16],
        }));
        let now = Rc::new(Cell::new(0u32));
        let closes = Rc::new(Cell::new(0));
        for slot in 0..2u8 {
            let extras = X {
                counters: counters.clone(),
                now: now.clone(),
                closes: closes.clone(),
            };
            let mut host = RunnerHost::for_slot(slot, &mut soft, extras);
            let mut info = info_on(1);
            assert!(host.publish_connection(&mut info), "slot {slot} publishes");
            assert_eq!(info.handle, 1 + u16::from(slot));
            assert_eq!(host.bridge().handle(), Some(info.handle));
        }
    }

    fn info_on(handle: u16) -> ConnectionInfo {
        ConnectionInfo {
            handle,
            role: crate::ll::Role::Peripheral,
            peer_address_type: 1,
            peer_address: [1, 2, 3, 4, 5, 0xc6],
            interval: 24,
            latency: 0,
            supervision_timeout: 200,
            master_clock_accuracy: 0,
            peer_rpa: None,
            local_rpa: None,
            peer_identity: None,
        }
    }

    fn acl_packet(handle: u16, data: &[u8]) -> crate::hci::transport::Packet {
        let mut packet =
            crate::hci::transport::Packet::empty(bt_hci::transport::PacketKind::AclData);
        packet.bytes[..2].copy_from_slice(&handle.to_le_bytes());
        packet.bytes[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        packet.bytes[4..4 + data.len()].copy_from_slice(data);
        packet.len = data.len() + 4;
        packet
    }

    #[test]
    fn encryption_change_cannot_cross_slots() {
        let _serial = serial();
        let mut b = Bench::new();
        b.soft.bridge_slot_mut(0).connected(info_on(1)).unwrap();
        b.soft.bridge_slot_mut(1).connected(info_on(5)).unwrap();
        while b.soft.pump_once() {
            while transport::try_receive_controller_packet().is_some() {}
        }
        while transport::try_receive_controller_packet().is_some() {}

        let extras = b.extras();
        let mut host = RunnerHost::new(&mut b.soft, extras);
        host.encryption_change(5, 0, 1);
        drop(host);
        assert!(
            transport::try_receive_controller_packet().is_none(),
            "slot 0's host must not report slot 1's encryption"
        );

        // The controller API still routes by handle for the slot's owner.
        assert!(b.soft.encryption_change(5, 0, 1));
        assert!(b.soft.pump_once());
        let event = transport::try_receive_controller_packet().unwrap();
        assert_eq!(event.payload()[0], 0x08);
        assert_eq!(&event.payload()[3..5], &[5, 0]);
    }

    #[test]
    fn a_stale_runner_host_cannot_touch_the_rebuilt_link() {
        let _serial = serial();
        let mut b = Bench::new();
        b.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
        assert_eq!(b.event(), EventEnd::Continue);
        let old = b.soft.bridge.link_key();

        // The slot reopens with the same handle but a new identity.
        b.soft.bridge.disconnected(0x13);
        b.soft.bridge.connected(info_on(1)).unwrap();
        let new = b.soft.bridge.link_key();
        assert_ne!(old, new);
        while transport::try_receive_controller_packet().is_some() {}
        b.soft.bridge.enqueue_tx(&acl_packet(1, &[7])).unwrap();

        let extras = b.extras();
        let mut stale = RunnerHost::for_link(old, &mut b.soft, extras);
        assert!(!stale.is_connected());
        stale.encryption_change(1, 0, 1);
        stale.connection_closed(0x13);
        assert!(!stale.push_ltk_request([0; 8], 0));
        drop(stale);

        assert!(b.soft.bridge.is_connected(), "the stale close is a no-op");
        assert_eq!(b.soft.bridge.link_key(), new);
        assert!(transport::try_receive_controller_packet().is_none());
    }

    #[test]
    fn a_stale_host_cannot_drain_the_new_links_acl() {
        let _serial = serial();
        let mut b = Bench::new();
        b.radio.push(FakeRadio::bad_frame(bad_crc_frame(0x01, &[])));
        assert_eq!(b.event(), EventEnd::Continue);
        let old = b.soft.bridge.link_key();
        b.soft.bridge.disconnected(0x13);
        b.soft.bridge.connected(info_on(1)).unwrap();
        while transport::try_receive_controller_packet().is_some() {}
        b.soft.bridge.enqueue_tx(&acl_packet(1, &[7])).unwrap();

        let extras = b.extras();
        let mut stale = RunnerHost::for_link(old, &mut b.soft, extras);
        assert!(stale.take_tx_acl().is_none(), "stale host drains nothing");
        drop(stale);
        assert!(
            b.soft.bridge.take_tx_acl().is_some(),
            "the new link keeps it"
        );
    }
}
