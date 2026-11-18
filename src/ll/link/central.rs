//! Central-role link engine for the shared scheduler (X3.5).
//!
//! The Peripheral engine carries the start-encryption procedure; CP keeps the
//! outbound link plaintext, so this engine only runs the event, ACL, control
//! and DLE paths. It reuses the same [`LinkHost`], radio and stat contract and
//! must be driven by [`LinkTable`], which owns event advancement.
//!
//! [`LinkTable`]: crate::ll::sched::LinkTable

use crate::hci::connection::{ConnectionInfo, RadioRequest, TxAcl, TxTag};
use crate::ll::acl::{DataPdu, LinkSequence, RxStatus};
use crate::ll::central::CentralConnection;
use crate::ll::conn::{time_reached, ConnError, ConnectParams};
use crate::ll::ctrl::{termination_reason, ControlAction, ControlState, FEATURE_LE_ENCRYPTION};
use crate::ll::enc::MAX_ENCRYPTED;
use crate::ll::sched::{CloseCause, Expiry, LinkWindow, ScheduledLink, ARM_LEAD_US, EVENT_TAIL_US};
use crate::ll::Role;
use crate::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use crate::rf::LinkRadio;
use crate::time::InstantUs;

use super::{
    earlier, reached, receive, Control, EventEnd, LinkHost, RxResult, LOCAL_VERSION, STAT_ACCEPTED,
    STAT_BRIDGE_FAIL, STAT_CHANNEL, STAT_CLOSE_REASON, STAT_CONNECT_FAIL, STAT_CONTROL_RX,
    STAT_DUPLICATE, STAT_EMPTY_EVENTS, STAT_EVENTS, STAT_EVENT_NO, STAT_FIRST_ANCHOR,
    STAT_FIRST_ANCHOR_US, STAT_INVALID_PDU, STAT_LAST_CONTROL, STAT_LAST_HEADER, STAT_LAST_LEN,
    STAT_MAX_CONNECTION_US, STAT_RETRANSMIT, STAT_RX_BACKPRESSURE, STAT_RX_PDUS, STAT_SUPERVISION,
    STAT_TERMINATED_ACK, STAT_TERMINATION_EXPIRED, STAT_TX_ERR, STAT_TX_LATE, STAT_TX_OK,
};

/// Response window after our event packet, as in the single-link example.
const RESPONSE_WINDOW_US: u32 = 2_000;

/// The table dispatches this long before the event so the flash-resident
/// `step` (Host snapshot, DLE service, channel/AA restore) finishes before
/// the TX start at `event_start - ARM_LEAD_US`; measured pre-TX work is
/// ~150-190 us.
pub const PREPARE_LEAD_US: u32 = 500;

/// Host ACL packet split across LL PDUs; only the last fragment owns the tag.
struct PendingHost {
    acl: TxAcl,
    offset: usize,
}

/// One Central-role connection on the shared scheduler contract.
pub struct CentralLink {
    pub conn: CentralConnection,
    link: LinkSequence,
    control: ControlState,
    pending_control: Option<DataPdu>,
    pending_host: Option<PendingHost>,
    acl_tag: Option<TxTag>,
    terminating: Option<u8>,
    terminate_requested: Option<u8>,
    /// Last `(tx, tx_time, rx, rx_time)` exported as LE Data Length Change.
    dl_reported: Option<(u16, u16, u16, u16)>,
    began: u32,
    complete_sent: bool,
    event_served: bool,
}

impl CentralLink {
    /// `params` must have passed `validate`; `local_features` must not claim
    /// LE Encryption, because this engine never runs the start procedure.
    pub fn new(
        params: ConnectParams,
        connect_ind_end_us: u32,
        now: u32,
        local_features: [u8; 8],
    ) -> Self {
        let mut control = ControlState::new();
        // No AES path exists here: advertising the feature bit would make a
        // peer start an encryption procedure this engine cannot finish.
        debug_assert_eq!(
            local_features[0] & (1 << FEATURE_LE_ENCRYPTION),
            0,
            "CentralLink cannot drive encryption"
        );
        control.local_features = local_features;
        Self {
            conn: CentralConnection::new(params, connect_ind_end_us)
                .with_first_event_bias_us(u32::from(params.win_size) * 625),
            link: LinkSequence::new(),
            control,
            pending_control: None,
            pending_host: None,
            acl_tag: None,
            terminating: None,
            terminate_requested: None,
            dl_reported: None,
            began: now,
            complete_sent: false,
            event_served: false,
        }
    }

    /// True once if the last [`step`] ran a connection event body.
    pub fn take_event_served(&mut self) -> bool {
        core::mem::take(&mut self.event_served)
    }

    fn expiration<H: LinkHost>(&mut self, host: &mut H, now: u32) -> Option<u8> {
        if self.control.termination_expired(now) {
            host.stat_inc(STAT_TERMINATION_EXPIRED);
            return Some(0x08);
        }
        if self.conn.supervision_expired(now) {
            let established = self.conn.established();
            host.stat_inc(if established {
                STAT_SUPERVISION
            } else {
                STAT_CONNECT_FAIL
            });
            return Some(if established { 0x08 } else { 0x3e });
        }
        None
    }

    fn request_terminate(&mut self, reason: u8, now: u32) {
        self.terminate_requested.get_or_insert(reason);
        self.control
            .start_termination(now, self.conn.params.timeout);
    }

    /// Hard deadline of the next event, with the cause the table reports.
    fn event_deadline(&self) -> (u32, CloseCause) {
        let supervision = self.conn.supervision_deadline_us();
        match self.control.termination_deadline_us() {
            Some(termination) if !time_reached(supervision, termination) => {
                (termination, CloseCause::Termination)
            }
            _ if self.conn.established() => (supervision, CloseCause::SupervisionTimeout),
            _ => (supervision, CloseCause::EstablishmentTimeout),
        }
    }

    /// Copy negotiated DLE limits into the link, the RX window and the Host.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    fn apply_data_length<H: LinkHost>(&mut self, host: &mut H) {
        let tx = self.control.data_length.tx_octets(false);
        let rx = self.control.data_length.rx_octets(false);
        self.link.set_max_payloads(tx, rx);
        self.conn.set_rx_max_payload(rx);
        let data = &self.control.data_length;
        let reported = (
            data.tx_payload(),
            data.tx_time_us(),
            data.rx_payload(),
            data.rx_time_us(),
        );
        if data.negotiated()
            && self.dl_reported != Some(reported)
            && host.data_length_change(reported.0, reported.1, reported.2, reported.3)
        {
            self.dl_reported = Some(reported);
        }
    }

    /// True while no control exchange or queued Host data owns the link.
    fn link_idle(&self) -> bool {
        self.pending_control.is_none()
            && self.pending_host.is_none()
            && self.terminate_requested.is_none()
            && self.terminating.is_none()
            && !self.link.has_outstanding()
    }
}

impl ScheduledLink for CentralLink {
    fn window(&self) -> LinkWindow {
        let air = self.conn.rx_complete_allowance_us();
        let (deadline_us, deadline_cause) = self.event_deadline();
        LinkWindow {
            prepare_us: self.conn.event_start_us().wrapping_sub(PREPARE_LEAD_US),
            latest_start_us: self.conn.event_start_us(),
            // Our packet plus one reply of the same size, then the tail.
            reservation_end_us: self
                .conn
                .event_start_us()
                .wrapping_add(air)
                .wrapping_add(air)
                .wrapping_add(EVENT_TAIL_US),
            min_service_us: air + 80 + EVENT_TAIL_US,
            deadline_us,
            deadline_cause,
            deadline_reason: deadline_cause.default_reason(),
            channel: self.conn.channel(),
            priority: 0,
            event: self.conn.event_counter(),
        }
    }

    fn advance_one(&mut self) -> Result<(), ConnError> {
        self.conn.next_event()
    }

    fn expiry(&self, now: u32) -> Option<Expiry> {
        let (at_us, cause) = self.event_deadline();
        time_reached(now, at_us).then_some(Expiry {
            at_us,
            cause,
            reason: cause.default_reason(),
        })
    }
}

/// Queue the next LL fragment of the Host ACL packet. Returns false when
/// nothing was queued.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
fn queue_next_host_fragment<H: LinkHost>(host: &mut H, l: &mut CentralLink) -> bool {
    if l.pending_host.is_none() {
        let Some(acl) = host.take_tx_acl() else {
            return false;
        };
        if acl.len == 0 {
            let _ = host.ack_tx(acl.tag);
            return false;
        }
        l.pending_host = Some(PendingHost { acl, offset: 0 });
    }
    let max_fragment = usize::from(l.link.tx_max_payload());
    let done = {
        let host_packet = l.pending_host.as_mut().expect("pending host packet");
        let remaining = host_packet.acl.len - host_packet.offset;
        let n = remaining.min(max_fragment);
        // Only the first fragment carries the Host LLID; the rest continue it.
        let llid = if host_packet.offset == 0 {
            host_packet.acl.llid
        } else {
            1
        };
        let start = host_packet.offset;
        let end = start + n;
        l.link
            .queue(llid, &host_packet.acl.bytes[start..end])
            .expect("fragment fits the LL PDU");
        host_packet.offset = end;
        (end == host_packet.acl.len).then_some(host_packet.acl.tag)
    };
    if let Some(tag) = done {
        l.pending_host = None;
        l.acl_tag = Some(tag);
    }
    true
}

/// Ask for DLE once features are known and the link is otherwise idle.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
fn service_dle<H: LinkHost>(host: &mut H, l: &mut CentralLink) -> Option<u8> {
    if !l.conn.established() || !l.link_idle() {
        return None;
    }
    if let Some((octets, time)) = host.take_data_length_request() {
        l.control.data_length.set_local_tx(octets, time);
        let pdu = l.control.length_request();
        l.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).expect("length request"));
        return None;
    }
    if l.control.data_length.requested() {
        return None;
    }
    if let Some(pdu) = l.control.request_length_if_supported() {
        l.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).expect("length request"));
    } else if host.allows_feature_request() {
        if let Some(pdu) = l.control.feature_request(false) {
            l.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).expect("feature request"));
        }
    }
    None
}

/// Publish LE Connection Complete (role Central) once.
fn report_connection<H: LinkHost>(host: &mut H, l: &mut CentralLink) -> Option<u8> {
    if l.complete_sent {
        return None;
    }
    l.complete_sent = true;
    let p = l.conn.params;
    let mut info = ConnectionInfo {
        handle: 1,
        role: Role::Central,
        peer_address_type: u8::from(p.peer_random),
        peer_address: p.peer_addr,
        interval: p.interval,
        latency: p.latency,
        supervision_timeout: p.timeout,
        master_clock_accuracy: p.sca,
        peer_rpa: None,
        local_rpa: None,
        peer_identity: None,
    };
    if !host.publish_connection(&mut info) {
        host.stat_inc(STAT_BRIDGE_FAIL);
        return Some(0x1f);
    }
    None
}

fn close<H: LinkHost, R: LinkRadio, C: InstantUs>(
    host: &mut H,
    radio: &mut R,
    clock: &C,
    l: &CentralLink,
    reason: u8,
) -> bool {
    if !radio.stop(clock) {
        return false;
    }
    let duration = clock.now_us().wrapping_sub(l.began);
    if duration > host.stat_get(STAT_MAX_CONNECTION_US) {
        host.stat_put(STAT_MAX_CONNECTION_US, duration);
    }
    host.stat_put(STAT_CLOSE_REASON, u32::from(reason));
    host.trace(
        clock.now_us(),
        6,
        l.conn.event_counter(),
        l.conn.channel(),
        0,
        0,
        u32::from(reason),
        duration,
    );
    host.connection_closed(reason);
    host.after_close();
    true
}

/// One outer-loop iteration for a Central link: deferred services, the idle
/// gap, one connection event and the shared close. The table advances the
/// event counter after the dispatch.
#[allow(clippy::too_many_arguments)]
pub fn step<H: LinkHost, R: LinkRadio, C: InstantUs>(
    l: &mut CentralLink,
    host: &mut H,
    radio: &mut R,
    clock: &C,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    finish: u32,
) -> Control {
    host.pre_iteration();
    l.event_served = false;
    if reached(clock.now_us(), finish) {
        return Control::Finish;
    }
    if let Some(request) = host.take_radio_request() {
        match request {
            RadioRequest::Reset => {
                if !radio.stop(clock) {
                    return Control::StopTimeout;
                }
                host.on_reset();
                return Control::Reset;
            }
            RadioRequest::Disconnect { reason } => {
                host.on_disconnect_request(reason);
                l.request_terminate(reason, clock.now_us());
            }
        }
    }
    let mut reason = l.expiration(host, clock.now_us());
    let prepare = l.conn.event_start_us().wrapping_sub(ARM_LEAD_US);
    let mut serviced = false;
    if reason.is_none() && !reached(clock.now_us().wrapping_add(4000), prepare) {
        serviced = true;
        reason = service_dle(host, l);
    }
    // The channel plan moves every event; program it before the RF arming
    // allowance, and restore our AA after any background advertising.
    if reason.is_none() && radio.channel() != l.conn.channel() {
        radio
            .set_channel(l.conn.channel())
            .expect("channel map is valid");
    }
    if reason.is_none() {
        radio.set_aa_crc(l.conn.params.access_addr, l.conn.params.crc_init);
    }
    if reason.is_none() && !reached(clock.now_us().wrapping_add(2000), prepare) {
        let mut until = earlier(prepare, earlier(finish, l.conn.supervision_deadline_us()));
        if let Some(end) = l.control.termination_deadline_us() {
            until = earlier(until, end);
        }
        host.idle_gap(prepare, until);
        return Control::Continue;
    }
    if reason.is_none() {
        reason = match connection_event(radio, clock, rx, tx, l, host, finish) {
            EventEnd::Continue => {
                l.event_served = true;
                None
            }
            EventEnd::Close(reason) => {
                l.event_served = true;
                Some(reason)
            }
            EventEnd::Stopped => return Control::StopTimeout,
        };
        // A scheduler dispatches `step` at the arm boundary, so the 4 ms
        // pre-event pass may never run; catch up in the long gap after it.
        if !serviced && reason.is_none() {
            reason = service_dle(host, l);
        }
    }
    if let Some(reason) = reason {
        if !close(host, radio, clock, l, reason) {
            return Control::StopTimeout;
        }
        return Control::Closed(reason);
    }
    Control::Continue
}

/// Run one connection event. Returns a close reason when the link ends.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn connection_event<H: LinkHost, R: LinkRadio, C: InstantUs>(
    radio: &mut R,
    clock: &C,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    l: &mut CentralLink,
    host: &mut H,
    finish: u32,
) -> EventEnd {
    if let Some(reason) = l.expiration(host, clock.now_us()) {
        return EventEnd::Close(reason);
    }
    let event = l.conn.event_counter();
    let channel = l.conn.channel();
    host.stat_put(STAT_EVENT_NO, u32::from(event));
    host.stat_put(STAT_CHANNEL, u32::from(channel));
    host.stat_inc(STAT_EVENTS);
    let event_start = l.conn.event_start_us();
    let event_limit = event_start
        .wrapping_add(u32::from(l.conn.params.interval) * 1250)
        .wrapping_sub(600);
    let mut expires = earlier(
        event_limit,
        earlier(finish, l.conn.supervision_deadline_us()),
    );
    if let Some(end) = l.control.termination_deadline_us() {
        expires = earlier(expires, end);
    }
    // The table dispatches at `prepare_us`; *tx_basic* is the late authority
    // (it rejects a start more than 10 us in the past), so it is not re-checked.
    let deadline = event_start.wrapping_sub(ARM_LEAD_US);
    radio.set_channel(channel).expect("channel map is valid");

    let retry = l.link.has_outstanding();
    if !retry {
        if let Some(pdu) = l.pending_control.take() {
            l.link.queue(3, pdu.payload()).expect("control PDU fits");
        } else if let Some(reason) = l.terminate_requested.take() {
            l.link.queue(3, &[2, reason]).expect("terminate PDU");
            l.terminating = Some(reason);
        } else if !queue_next_host_fragment(host, l) {
            l.link.queue(1, &[]).expect("empty PDU");
        }
    }
    let pdu = l.link.tx_pdu();
    let frame = pdu.as_bytes();
    tx.0[..frame.len()].copy_from_slice(frame);
    // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or stops the
    // engine on a failed send; `tx` outlives the call.
    let sent = unsafe { radio.tx_basic(clock, &tx.0[..frame.len()], 0, Some(deadline)) };
    let tx_return = clock.now_us();
    host.trace(
        tx_return,
        1,
        event,
        channel,
        tx.0[0],
        tx.0[1],
        tx_return.wrapping_sub(deadline),
        frame.len() as u32,
    );
    match &sent {
        Ok(()) => {
            host.stat_inc(STAT_TX_OK);
            if retry {
                host.stat_inc(STAT_RETRANSMIT);
            }
        }
        Err(crate::Error::Late) => host.stat_inc(STAT_TX_LATE),
        Err(_) => host.stat_inc(STAT_TX_ERR),
    }
    if sent.is_err() {
        let _ = radio.stop(clock);
        return match l.expiration(host, clock.now_us()) {
            Some(reason) => EventEnd::Close(reason),
            None => EventEnd::Continue,
        };
    }

    // TX_DONE leaves the LLE command engaged; `rx_basic` force-stops it.
    let capture_us = l.conn.rx_complete_allowance_us() + 64;
    let rx_until = earlier(tx_return.wrapping_add(RESPONSE_WINDOW_US), event_limit);
    let rx_expires = earlier(rx_until.wrapping_add(capture_us), expires);
    let mut arm_times = [0; 2];
    let packet = match receive(
        radio,
        clock,
        host,
        rx,
        rx_until,
        rx_expires,
        capture_us,
        &mut arm_times,
    ) {
        RxResult::Packet(packet) => packet,
        RxResult::Missed => {
            host.stat_inc(STAT_EMPTY_EVENTS);
            host.trace(
                clock.now_us(),
                5,
                event,
                channel,
                0,
                0,
                event_start,
                event_limit,
            );
            return match l.expiration(host, clock.now_us()) {
                Some(reason) => EventEnd::Close(reason),
                None => EventEnd::Continue,
            };
        }
        RxResult::Stopped => return EventEnd::Stopped,
    };
    let first = !l.conn.established();
    let payload_len = packet.len.saturating_sub(2) as u8;
    // Any packet with a matching access address establishes the link, even
    // with a CRC error; only a valid packet refreshes supervision.
    if !l
        .conn
        .on_rx(packet.end, payload_len, packet.crc_ok && packet.len >= 2)
    {
        return match l.expiration(host, packet.end) {
            Some(reason) => EventEnd::Close(reason),
            None => EventEnd::Close(0x08),
        };
    }
    if first {
        host.stat_inc(STAT_FIRST_ANCHOR);
        if host.stat_get(STAT_FIRST_ANCHOR_US) == 0 {
            host.stat_put(STAT_FIRST_ANCHOR_US, event_start);
        }
    }
    // Publish after the time-critical work; a CRC-error first packet is still
    // a real link and the Host must learn about it.
    if let Some(reason) = report_connection(host, l) {
        return EventEnd::Close(reason);
    }
    if !packet.crc_ok || packet.len < 2 {
        return EventEnd::Continue;
    }
    let header = rx.0[0];
    let payload = &rx.0[2..packet.len];
    if payload.len() > host.rx_payload_limit().min(MAX_ENCRYPTED) {
        host.note_bad_pdu(header, payload.len());
        host.stat_inc(STAT_INVALID_PDU);
        return EventEnd::Continue;
    }
    let llid = header & 3;
    let capacity = match llid {
        1 if payload.is_empty() => true,
        1 | 2 => host.can_receive_acl(llid, payload.len()),
        3 => l.pending_control.is_none() && l.terminate_requested.is_none(),
        _ => false,
    };
    let outcome = l.link.on_rx(header, payload, true, capacity);
    if outcome.status == RxStatus::Invalid {
        host.note_bad_pdu(header, payload.len());
        host.stat_inc(STAT_INVALID_PDU);
        return EventEnd::Continue;
    }
    host.stat_inc(STAT_RX_PDUS);
    host.stat_put(STAT_LAST_HEADER, u32::from(header));
    host.stat_put(STAT_LAST_LEN, payload.len() as u32);
    let acknowledged_acl = if outcome.tx_acked {
        l.acl_tag.take()
    } else {
        None
    };
    if outcome.tx_acked {
        if let Some(reason) = l.terminating {
            // The peer's only packet acknowledges our LL_TERMINATE_IND.
            host.stat_inc(STAT_TERMINATED_ACK);
            let _ = radio.stop(clock);
            return EventEnd::Close(reason);
        }
    }
    let mut remote_terminate = None;
    match outcome.status {
        RxStatus::Accepted => {
            host.stat_inc(STAT_ACCEPTED);
            if matches!(llid, 1 | 2) {
                host.diag_acl_raw(llid, payload, false);
            }
            match llid {
                1 if payload.is_empty() => {}
                2 => {
                    if !host.receive_acl(llid, payload) {
                        host.stat_inc(STAT_BRIDGE_FAIL);
                        return EventEnd::Close(0x1f);
                    }
                }
                3 => {
                    host.stat_inc(STAT_CONTROL_RX);
                    host.stat_put(STAT_LAST_CONTROL, u32::from(payload[0]));
                    host.diag_control_opcode(payload[0]);
                    match l.control.on_pdu(&mut l.conn, payload, LOCAL_VERSION) {
                        Ok(action) => {
                            l.apply_data_length(host);
                            match action {
                                ControlAction::Reply(reply) => {
                                    l.pending_control = Some(
                                        DataPdu::new(3, reply.as_bytes()).expect("control reply"),
                                    );
                                }
                                ControlAction::Terminate(reason) => {
                                    remote_terminate = Some(reason);
                                }
                                ControlAction::None => {}
                            }
                        }
                        Err(error) => l.request_terminate(termination_reason(error), packet.end),
                    }
                }
                _ => host.note_bad_pdu(header, payload.len()),
            }
        }
        RxStatus::Duplicate => host.stat_inc(STAT_DUPLICATE),
        RxStatus::Backpressure => host.stat_inc(STAT_RX_BACKPRESSURE),
        RxStatus::Invalid => {}
    }
    if let Some(tag) = acknowledged_acl {
        if !host.ack_tx(tag) {
            host.stat_inc(STAT_BRIDGE_FAIL);
            return EventEnd::Close(0x1f);
        }
    }
    if let Some(reason) = remote_terminate {
        // Acknowledge the peer's terminate with an empty PDU before leaving.
        l.link.queue(1, &[]).expect("empty PDU");
        let ack = l.link.tx_pdu();
        let frame = ack.as_bytes();
        tx.0[..frame.len()].copy_from_slice(frame);
        // SAFETY: the frame is a caller buffer that outlives the call;
        // `tx_basic` either completes or reports the failure.
        if unsafe {
            radio.tx_basic(
                clock,
                &tx.0[..frame.len()],
                0,
                Some(clock.now_us().wrapping_add(120)),
            )
        }
        .is_ok()
        {
            host.stat_inc(STAT_TX_OK);
        }
        let _ = radio.stop(clock);
        return EventEnd::Close(reason);
    }
    match l.expiration(host, clock.now_us()) {
        Some(reason) => EventEnd::Close(reason),
        None => EventEnd::Continue,
    }
}
