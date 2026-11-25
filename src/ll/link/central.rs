//! Central-role link engine (X3.5), driven by [`LinkTable`] for advancement.
//!
//! [`LinkTable`]: crate::ll::sched::LinkTable

use crate::crypto::engine::AesEngine;
use crate::crypto::BLE_MIC_LEN;
use crate::hci::connection::{ConnectionInfo, RadioRequest, TxAcl, TxTag};
use crate::hci::runner::EnableEncryption;
use crate::ll::acl::{DataPdu, LinkSequence, RxStatus};
use crate::ll::central::CentralConnection;
use crate::ll::conn::{time_reached, ConnError, ConnectParams, ConnectionUpdate};
use crate::ll::ctrl::{
    termination_reason, ControlAction, ControlPdu, ControlState, FEATURE_LE_ENCRYPTION,
};
use crate::ll::enc::{
    CentralStage, CentralStart, EncError, Encryption, MAX_ENCRYPTED, MAX_PLAINTEXT,
};
use crate::ll::sched::{CloseCause, Expiry, LinkWindow, ScheduledLink, ARM_LEAD_US, EVENT_TAIL_US};
use crate::ll::Role;
use crate::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use crate::rf::LinkRadio;
use crate::time::InstantUs;

use super::{
    earlier, reached, receive, Control, DeferredRx, EncTx, EventEnd, LinkHost, RxResult,
    LOCAL_VERSION, SEC_ACTIVE, SEC_ENCRYPTED_RX, SEC_ENCRYPTED_TX, SEC_ENC_REQ, SEC_ENC_RSP,
    SEC_LTK_REPLY, SEC_LTK_REQUEST, SEC_MIC_FAILURE, SEC_PREPARED, SEC_START_REQ, SEC_START_RSP,
    STAT_ACCEPTED, STAT_BRIDGE_FAIL, STAT_CHANNEL, STAT_CLOSE_REASON, STAT_CONNECT_FAIL,
    STAT_CONTROL_RX, STAT_DUPLICATE, STAT_EMPTY_EVENTS, STAT_EVENTS, STAT_EVENT_NO,
    STAT_FIRST_ANCHOR, STAT_FIRST_ANCHOR_US, STAT_INVALID_PDU, STAT_LAST_CONTROL, STAT_LAST_HEADER,
    STAT_LAST_LEN, STAT_MAX_CONNECTION_US, STAT_RETRANSMIT, STAT_RX_BACKPRESSURE, STAT_RX_PDUS,
    STAT_SUPERVISION, STAT_TERMINATED_ACK, STAT_TERMINATION_EXPIRED, STAT_TX_ERR, STAT_TX_LATE,
    STAT_TX_OK,
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
pub struct CentralLink<E: AesEngine> {
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
    start: CentralStart,
    enc: Option<Encryption<E>>,
    /// Peer PDUs carry the MIC from this point on.
    rx_encrypted: bool,
    /// Set when the precomputed encrypted LL_START_ENC_RSP is queued; RX
    /// decryption is armed only after that PDU is on air.
    arm_rx_on_send: bool,
    /// Encrypted PDU prepared outside the event.
    pending_enc_tx: Option<EncTx>,
    /// Ciphertext received last event; decrypted in the next gap.
    deferred_rx: Option<DeferredRx>,
    /// HCI Encryption Change to report: `(status, enabled)`.
    enc_change: Option<(u8, u8)>,
    /// A Host Enable Encryption request that arrived while TX was busy.
    pending_enable: Option<EnableEncryption>,
    /// The Peripheral's LL_ENC_RSP arrived; the service asks for the LTK.
    enc_rsp_seen: bool,
    /// The Peripheral's plaintext LL_START_ENC_REQ arrived; the service
    /// releases the precomputed response.
    start_req_seen: bool,
    /// `SKDm || IVm` drawn when the procedure starts.
    enc_random: [u8; 12],
    /// `(instant, interval, latency, timeout)` reported once the update lands.
    update_report: Option<(u16, u16, u16, u16)>,
    /// Host update not yet armed; armed only when its IND is queued.
    update_request: Option<(u16, u16, u16, u16)>,
}

impl<E: AesEngine> CentralLink<E> {
    /// `params` must have passed `validate`. With the LE Encryption feature
    /// bit set the engine runs the initiator-side start procedure; without it
    /// a Host Enable Encryption request is failed with `0x11`.
    pub fn new(
        params: ConnectParams,
        connect_ind_end_us: u32,
        now: u32,
        local_features: [u8; 8],
    ) -> Self {
        let mut control = ControlState::new();
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
            start: CentralStart::new(),
            enc: None,
            rx_encrypted: false,
            arm_rx_on_send: false,
            pending_enc_tx: None,
            deferred_rx: None,
            enc_change: None,
            pending_enable: None,
            enc_rsp_seen: false,
            start_req_seen: false,
            enc_random: [0; 12],
            update_report: None,
            update_request: None,
        }
    }

    fn enc_supported(&self) -> bool {
        self.control.local_features[0] & (1 << FEATURE_LE_ENCRYPTION) != 0
    }

    /// Both sides encrypted and the precomputed response acknowledged.
    fn enc_active(&self) -> bool {
        self.start.is_active()
    }

    /// True once the link's own start procedure completed.
    pub fn encrypted(&self) -> bool {
        self.start.is_active()
    }

    /// Drop a start procedure that never completed so a termination PDU can
    /// leave in plaintext. An active session keeps its cipher.
    fn abandon_unfinished_encryption(&mut self) {
        if self.start.owns_link() {
            self.start.abort();
            self.enc = None;
            self.pending_enc_tx = None;
            self.deferred_rx = None;
            self.rx_encrypted = false;
            self.arm_rx_on_send = false;
            self.pending_host = None;
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
        let tx = self.control.data_length.tx_octets(self.enc_active());
        let rx = self.control.data_length.rx_octets(self.rx_encrypted);
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

    /// True while no control exchange, queued Host data or start procedure
    /// owns the link.
    fn link_idle(&self) -> bool {
        self.pending_control.is_none()
            && self.pending_host.is_none()
            && self.terminate_requested.is_none()
            && self.terminating.is_none()
            && self.pending_enc_tx.is_none()
            && self.deferred_rx.is_none()
            && !self.start.owns_link()
            && !self.link.has_outstanding()
    }
}

impl<E: AesEngine> ScheduledLink for CentralLink<E> {
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
fn queue_next_host_fragment<E: AesEngine, H: LinkHost>(
    host: &mut H,
    l: &mut CentralLink<E>,
) -> bool {
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
fn service_dle<E: AesEngine, H: LinkHost>(host: &mut H, l: &mut CentralLink<E>) -> Option<u8> {
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
fn report_connection<E: AesEngine, H: LinkHost>(
    host: &mut H,
    l: &mut CentralLink<E>,
) -> Option<u8> {
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

/// Encrypt and stage one PDU for the next event. Returns a termination reason
/// when the cipher refused a block.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
fn prefetch_encrypted<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    l: &mut CentralLink<E>,
) -> Option<u8> {
    if !l.enc_active() || l.pending_enc_tx.is_some() || l.link.has_outstanding() {
        return None;
    }
    let Some(enc) = l.enc.as_mut() else {
        return None;
    };
    let mut out = [0u8; MAX_ENCRYPTED];
    let staged = if let Some(reason) = l.terminate_requested.take() {
        enc.encrypt(3, &[2, reason], &mut out)
            .map(|len| (3, len, None, Some(reason)))
    } else if let Some(pdu) = l.pending_control.take() {
        enc.encrypt(3, pdu.payload(), &mut out)
            .map(|len| (3, len, None, None))
    } else if let Some((bytes, len)) = stage_update(
        host,
        &mut l.conn,
        &mut l.update_request,
        &mut l.update_report,
        // A staged PDU leaves this event in the pre-event pass; after the
        // event body it waits for the next one.
        if l.event_served { 7 } else { 6 },
    ) {
        enc.encrypt(3, &bytes[..len], &mut out)
            .map(|len| (3, len, None, None))
    } else {
        if l.pending_host.is_none() {
            let Some(acl) = host.take_tx_acl() else {
                return None;
            };
            if acl.len == 0 {
                let _ = host.ack_tx(acl.tag);
                return None;
            }
            l.pending_host = Some(PendingHost { acl, offset: 0 });
        }
        // The on-air ceiling already includes the MIC.
        let max_fragment = usize::from(l.link.tx_max_payload()).saturating_sub(BLE_MIC_LEN);
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
        match enc.encrypt(llid, &host_packet.acl.bytes[start..end], &mut out) {
            Ok(len) => {
                host_packet.offset = end;
                let tag = (end == host_packet.acl.len).then_some(host_packet.acl.tag);
                if tag.is_some() {
                    l.pending_host = None;
                }
                Ok((llid, len, tag, None))
            }
            Err(error) => Err(error),
        }
    };
    let (llid, len, tag, terminate) = match staged {
        Ok(staged) => staged,
        Err(_) => {
            host.sec_error(0x1e);
            return Some(0x1e);
        }
    };
    let mut bytes = [0u8; MAX_ENCRYPTED];
    bytes[..len].copy_from_slice(&out[..len]);
    l.pending_enc_tx = Some(EncTx {
        llid,
        bytes,
        len: len as u8,
        tag,
        terminate,
    });
    host.sec_inc(SEC_ENCRYPTED_TX);
    None
}

/// Decrypt the PDU deferred by the last event and dispatch it. MIC failure
/// terminates with 0x3d.
fn finish_deferred<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    l: &mut CentralLink<E>,
    now: u32,
) -> Option<u8> {
    let rx = l.deferred_rx.take()?;
    let mut plain = [0u8; MAX_PLAINTEXT];
    let decrypted = {
        let Some(enc) = l.enc.as_mut() else {
            return Some(0x1e);
        };
        enc.decrypt(rx.header, &rx.payload[..usize::from(rx.len)], &mut plain)
    };
    let len = match decrypted {
        Ok(len) => len,
        Err(EncError::MicFailure) => {
            host.sec_inc(SEC_MIC_FAILURE);
            host.sec_error(0x3d);
            return Some(0x3d);
        }
        Err(_) => {
            host.sec_error(0x1e);
            return Some(0x1e);
        }
    };
    host.sec_inc(SEC_ENCRYPTED_RX);
    let llid = rx.header & 3;
    let payload = &plain[..len];
    if llid == 3 {
        if !l.enc_active() {
            // The link's first ciphertext must be the Peripheral's RSP.
            if payload == ControlPdu::start_enc_rsp().as_bytes()
                && l.start.stage() == CentralStage::WaitingRsp
            {
                if l.start.on_peer_rsp().is_ok() {
                    host.sec_inc(SEC_ACTIVE);
                    l.enc_change = Some((0, 1));
                    l.apply_data_length(host);
                }
                return None;
            }
            host.sec_error(0x1e);
            return Some(0x1e);
        }
        host.stat_put(STAT_LAST_CONTROL, u32::from(payload[0]));
        host.diag_control_opcode(payload[0]);
        match l.control.on_pdu(&mut l.conn, payload, LOCAL_VERSION) {
            Ok(action) => {
                l.apply_data_length(host);
                match action {
                    ControlAction::Reply(reply) => {
                        l.pending_control =
                            Some(DataPdu::new(3, reply.as_bytes()).expect("control reply"));
                    }
                    ControlAction::Terminate(reason) => l.request_terminate(reason, now),
                    ControlAction::None => {}
                }
            }
            Err(error) => l.request_terminate(termination_reason(error), now),
        }
    } else if llid == 2 || !payload.is_empty() {
        if !host.receive_acl(llid, payload) {
            host.stat_inc(STAT_BRIDGE_FAIL);
            return Some(0x1f);
        }
    }
    None
}

/// Everything the start procedure needs outside the event: HCI reports, the
/// Host's LTK answer and precomputed ciphertext.
fn service_security<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    l: &mut CentralLink<E>,
    now: u32,
) -> Option<u8> {
    let decrypted = finish_deferred(host, l, now);
    if decrypted.is_some() {
        report_enc_change(host, l);
        return decrypted;
    }
    // The Peripheral's LL_ENC_RSP arrived: ask the Host for the LTK.
    if l.enc_rsp_seen && l.enc.is_none() {
        l.enc_rsp_seen = false;
        let (rand, ediv) = l.start.rand_ediv();
        if host.push_ltk_request(rand, ediv) {
            host.sec_inc(SEC_LTK_REQUEST);
        } else {
            host.sec_error(0x1e);
            l.start.abort();
            l.enc_change = Some((0x1e, 0));
            l.request_terminate(0x1e, now);
        }
    }
    if l.start.stage() == CentralStage::AwaitingKey && l.enc.is_none() {
        if let Some(reply) = host.take_ltk_reply() {
            match reply {
                crate::hci::runner::LtkReply::Key(ltk) => {
                    host.sec_inc(SEC_LTK_REPLY);
                    match l.start.session(&ltk) {
                        Ok(session) => {
                            let engine = host.new_aes(session.key());
                            let mut enc =
                                Encryption::new(session, crate::ll::enc::EncRole::Central, engine);
                            if l.start.prepare_start_rsp(&mut enc).is_ok() {
                                l.enc = Some(enc);
                                host.sec_inc(SEC_PREPARED);
                            } else {
                                host.sec_error(0x1e);
                                l.start.abort();
                                l.enc_change = Some((0x1e, 0));
                                l.request_terminate(0x1e, now);
                            }
                        }
                        Err(_) => {
                            host.sec_error(0x1e);
                            l.start.abort();
                            l.enc_change = Some((0x1e, 0));
                            l.request_terminate(0x1e, now);
                        }
                    }
                }
                crate::hci::runner::LtkReply::Rejected => {
                    // Core 5.4 Vol 6 Part B §5.1.4: no key means no link.
                    host.sec_error(0x06);
                    l.start.abort();
                    l.enc_change = Some((0x06, 0));
                    l.request_terminate(0x06, now);
                }
            }
        }
    }
    // A Host started the procedure.
    if l.pending_enable.is_none() {
        l.pending_enable = host.take_encryption_request();
    }
    if let Some(request) = l.pending_enable {
        if !l.complete_sent {
            l.pending_enable = None;
            l.enc_change = Some((0x0c, 0));
        } else if l.enc_active() {
            // Already encrypted with the Host's key; pause/resume is not
            // implemented, so report the link as encrypted.
            l.pending_enable = None;
            l.enc_change = Some((0, 1));
        } else if !l.enc_supported() {
            l.pending_enable = None;
            l.enc_change = Some((0x11, 0));
        } else if l.start.is_idle() && l.link_idle() {
            l.pending_enable = None;
            host.fill_random(&mut l.enc_random);
            let mut skdm = [0; 8];
            skdm.copy_from_slice(&l.enc_random[..8]);
            let mut ivm = [0; 4];
            ivm.copy_from_slice(&l.enc_random[8..]);
            match l.start.begin(request.rand, request.ediv, skdm, ivm) {
                Ok(pdu) => {
                    l.link.queue(3, pdu.as_bytes()).expect("LL_ENC_REQ fits");
                    host.sec_inc(SEC_ENC_REQ);
                }
                Err(_) => {
                    host.sec_error(0x1e);
                    l.enc_change = Some((0x1e, 0));
                    l.request_terminate(0x1e, now);
                }
            }
        }
    }
    // The Peripheral's plaintext LL_START_ENC_REQ releases the response.
    if l.start.is_idle() {
        l.start_req_seen = false;
    }
    if l.start_req_seen && l.start.stage() == CentralStage::Prepared {
        l.start_req_seen = false;
        match l.start.on_start_enc_req() {
            Ok(bytes) => {
                let len = bytes.len();
                let mut buf = [0u8; MAX_ENCRYPTED];
                buf[..len].copy_from_slice(bytes);
                l.pending_enc_tx = Some(EncTx {
                    llid: 3,
                    bytes: buf,
                    len: len as u8,
                    tag: None,
                    terminate: None,
                });
                l.arm_rx_on_send = true;
                host.sec_inc(SEC_START_RSP);
            }
            Err(_) => {
                host.sec_error(0x1e);
                l.start.abort();
                l.enc_change = Some((0x1e, 0));
                l.request_terminate(0x1e, now);
            }
        }
    }
    report_enc_change(host, l);
    if l.enc_active() {
        return prefetch_encrypted(host, l);
    }
    None
}

/// Accept a Host `LE Connection Update` and report it once the instant passed.
///
/// The instant is not stamped here: the PDU may leave in a later event on an
/// encrypted link, so [`stage_update`] arms the procedure when it is queued.
fn service_update<E: AesEngine, H: LinkHost<Aes = E>>(host: &mut H, l: &mut CentralLink<E>) {
    if let Some((instant, interval, latency, timeout)) = l.update_report {
        // The complete event names the parameters the link now uses.
        if l.conn.event_counter().wrapping_sub(instant) < 0x8000
            && host.connection_updated(interval, latency, timeout)
        {
            l.update_report = None;
        }
    }
    if !l.conn.established() || l.update_report.is_some() || l.update_request.is_some() {
        return;
    }
    l.update_request = host.take_connection_update();
}

/// Arm the Host's update for an event that will carry its IND. `margin` counts
/// from the current event to the stamped instant (6 = sent in this event).
fn stage_update<H: LinkHost>(
    host: &mut H,
    conn: &mut CentralConnection,
    request: &mut Option<(u16, u16, u16, u16)>,
    report: &mut Option<(u16, u16, u16, u16)>,
    margin: u16,
) -> Option<([u8; 12], usize)> {
    let (min, max, latency, timeout) = request.take()?;
    // Prefer the low end of the Host's band; the HCI layer already validated
    // the range, so a failing schedule is a collision the link cannot have.
    let interval = min.max(0x0006).min(max);
    let instant = conn.event_counter().wrapping_add(margin);
    let update = ConnectionUpdate {
        win_size: 1,
        win_offset: 0,
        interval,
        latency,
        timeout,
        instant,
    };
    let mut bytes = [0u8; 12];
    let pdu = ControlPdu::connection_update(&update);
    let len = pdu.as_bytes().len();
    bytes[..len].copy_from_slice(pdu.as_bytes());
    match conn.schedule_update(update) {
        Ok(()) => {
            *report = Some((instant, interval, latency, timeout));
            Some((bytes, len))
        }
        Err(_) => {
            host.stat_inc(STAT_INVALID_PDU);
            let p = conn.params;
            let _ = host.connection_updated(p.interval, p.latency, p.timeout);
            None
        }
    }
}

/// Send a queued HCI Encryption Change; report after every state transition so
/// a failure and its reason leave in the same pass.
fn report_enc_change<E: AesEngine, H: LinkHost<Aes = E>>(host: &mut H, l: &mut CentralLink<E>) {
    if let Some((status, enabled)) = l.enc_change {
        if let Some(handle) = host.local_handle() {
            host.encryption_change(handle, status, enabled);
            l.enc_change = None;
        }
    }
}

fn close<E: AesEngine, H: LinkHost, R: LinkRadio, C: InstantUs>(
    host: &mut H,
    radio: &mut R,
    clock: &C,
    l: &CentralLink<E>,
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
pub fn step<E: AesEngine, H: LinkHost<Aes = E>, R: LinkRadio, C: InstantUs>(
    l: &mut CentralLink<E>,
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
                l.abandon_unfinished_encryption();
                l.request_terminate(reason, clock.now_us());
            }
        }
    }
    let mut reason = l.expiration(host, clock.now_us());
    let prepare = l.conn.event_start_us().wrapping_sub(ARM_LEAD_US);
    let mut serviced = false;
    if reason.is_none() && !reached(clock.now_us().wrapping_add(4000), prepare) {
        serviced = true;
        reason = service_security(host, l, clock.now_us());
        if reason.is_none() {
            service_update(host, l);
            reason = service_dle(host, l);
        }
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
            reason = service_security(host, l, clock.now_us());
            if reason.is_none() {
                service_update(host, l);
                reason = service_dle(host, l);
            }
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
pub fn connection_event<E: AesEngine, H: LinkHost<Aes = E>, R: LinkRadio, C: InstantUs>(
    radio: &mut R,
    clock: &C,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    l: &mut CentralLink<E>,
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
        if let Some(tx) = l.pending_enc_tx.take() {
            // Prepared outside the event: an encrypted response or PDU.
            l.link
                .queue(tx.llid, &tx.bytes[..usize::from(tx.len)])
                .expect("prepared PDU fits");
            l.acl_tag = tx.tag;
            if let Some(reason) = tx.terminate {
                l.terminating = Some(reason);
            }
        } else if l.start.owns_link() || l.enc_active() {
            // The start procedure owns the link; with encryption active only
            // an empty PDU may share an event that has nothing prepared.
            l.link.queue(1, &[]).expect("empty PDU");
        } else if let Some(pdu) = l.pending_control.take() {
            l.link.queue(3, pdu.payload()).expect("control PDU fits");
        } else if let Some(reason) = l.terminate_requested.take() {
            l.link.queue(3, &[2, reason]).expect("terminate PDU");
            l.terminating = Some(reason);
        } else if let Some((bytes, len)) = stage_update(
            host,
            &mut l.conn,
            &mut l.update_request,
            &mut l.update_report,
            6,
        ) {
            l.link.queue(3, &bytes[..len]).expect("control PDU fits");
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
    if l.arm_rx_on_send {
        // Our encrypted LL_START_ENC_RSP is on air: the peer's next PDU is
        // its encrypted response. RX stays off until exactly this point.
        l.arm_rx_on_send = false;
        l.rx_encrypted = true;
        if let Some(enc) = l.enc.as_mut() {
            enc.enable_rx();
        }
        l.apply_data_length(host);
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
    // After our encrypted LL_START_ENC_RSP the peer's PDUs carry the MIC;
    // empty PDUs are never encrypted.
    let ciphertext = l.rx_encrypted && !(llid == 1 && payload.is_empty());
    let capacity = if ciphertext {
        l.deferred_rx.is_none()
            && match llid {
                // The bridge stores plaintext: reserve without the MIC.
                1 | 2 => host.can_receive_acl(llid, payload.len().saturating_sub(BLE_MIC_LEN)),
                3 => true,
                _ => false,
            }
    } else {
        match llid {
            1 if payload.is_empty() => true,
            1 | 2 => host.can_receive_acl(llid, payload.len()),
            3 => l.pending_control.is_none() && l.terminate_requested.is_none(),
            _ => false,
        }
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
                host.diag_acl_raw(llid, payload, ciphertext);
            }
            if ciphertext {
                // AES-CCM cannot fit in the response window; hold the PDU and
                // decrypt it after the event.
                let mut copy = [0u8; MAX_ENCRYPTED];
                copy[..payload.len()].copy_from_slice(payload);
                l.deferred_rx = Some(DeferredRx {
                    header,
                    payload: copy,
                    len: payload.len() as u8,
                    end: packet.end,
                });
            } else {
                match llid {
                    1 if payload.is_empty() => {}
                    1 | 2 => {
                        if !host.receive_acl(llid, payload) {
                            host.stat_inc(STAT_BRIDGE_FAIL);
                            return EventEnd::Close(0x1f);
                        }
                    }
                    3 => {
                        host.stat_inc(STAT_CONTROL_RX);
                        host.stat_put(STAT_LAST_CONTROL, u32::from(payload[0]));
                        host.diag_control_opcode(payload[0]);
                        match payload[0] {
                            // The Peripheral's contributions; the LTK request
                            // is HCI work and waits for the gap.
                            0x04 if l.start.stage() == CentralStage::AwaitingRsp => {
                                if l.start.on_enc_rsp(payload).is_ok() {
                                    l.enc_rsp_seen = true;
                                    host.sec_inc(SEC_ENC_RSP);
                                } else {
                                    host.sec_error(0x1e);
                                    l.start.abort();
                                    l.enc_change = Some((0x1e, 0));
                                    l.request_terminate(0x1e, packet.end);
                                }
                            }
                            // The Peripheral may send this before our Host
                            // answers the LTK request; hold it for the prepare.
                            0x05 if matches!(
                                l.start.stage(),
                                CentralStage::AwaitingKey | CentralStage::Prepared
                            ) =>
                            {
                                l.start_req_seen = true;
                                host.sec_inc(SEC_START_REQ);
                            }
                            0x0d | 0x11 if l.start.owns_link() => {
                                let reason = if payload[0] == 0x0d {
                                    payload.get(1).copied()
                                } else {
                                    payload.get(2).copied()
                                };
                                match reason {
                                    Some(reason) => {
                                        // Core §5.1.4: the peer refused the key.
                                        // Report and let its TERMINATE_IND end
                                        // the link.
                                        host.sec_error(reason);
                                        l.start.abort();
                                        l.enc = None;
                                        l.rx_encrypted = false;
                                        l.enc_change = Some((reason, 0));
                                    }
                                    None => host.note_bad_pdu(header, payload.len()),
                                }
                            }
                            _ => match l.control.on_pdu(&mut l.conn, payload, LOCAL_VERSION) {
                                Ok(action) => {
                                    l.apply_data_length(host);
                                    match action {
                                        ControlAction::Reply(reply) => {
                                            l.pending_control = Some(
                                                DataPdu::new(3, reply.as_bytes())
                                                    .expect("control reply"),
                                            );
                                        }
                                        ControlAction::Terminate(reason) => {
                                            remote_terminate = Some(reason);
                                        }
                                        ControlAction::None => {}
                                    }
                                }
                                Err(error) => {
                                    l.request_terminate(termination_reason(error), packet.end)
                                }
                            },
                        }
                    }
                    _ => host.note_bad_pdu(header, payload.len()),
                }
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
