//! Shared Peripheral session engine (single link, N=1).
//!
//! Owns the connection-event loop, CRC/anchor handling, ACL segmentation and
//! the start-encryption/DLE orchestration that the GATT and HID examples used
//! to duplicate. Hardware access is limited to [`LinkRadio`]; Host side effects
//! go through [`LinkHost`], so the same path runs on hardware and on the host
//! fixtures.
//!
//! Production behaviour is intentionally identical to the former example
//! copies: the event window, deferred AES work and close ordering are kept.

use crate::crypto::engine::AesEngine;
use crate::crypto::BLE_MIC_LEN;
use crate::hci::connection::{ConnectionInfo, RadioRequest, TxAcl, TxTag};
use crate::hci::runner::LtkReply;
use crate::ll::acl::{DataPdu, LinkSequence, RxStatus};
use crate::ll::conn::{ChannelSelectionAlgorithm, ConnError, ConnectParams, PeripheralConnection};
use crate::ll::ctrl::{
    termination_reason, ControlAction, ControlPdu, ControlState, EncReq, LocalVersion,
    FEATURE_LE_ENCRYPTION,
};
use crate::ll::dle::LL_LEGACY_PAYLOAD;
use crate::ll::enc::{
    EncError, EncRole, Encryption, PeripheralStart, StartStage, MAX_ENCRYPTED, MAX_PLAINTEXT,
};
use crate::ll::sched::{CloseCause, Expiry, LinkWindow, ScheduledLink, ARM_LEAD_US, EVENT_TAIL_US};
use crate::ll::Role;
use crate::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use crate::rf::{LinkRadio, PhyMode};
use crate::time::InstantUs;

/// `LL_VERSION_IND` this controller reports.
pub const LOCAL_VERSION: LocalVersion = LocalVersion {
    version: 0x0d,
    company_id: 0xffff,
    subversion: 1,
};

/// A same-event reply for an accepted ACL fragment.
///
/// Bypasses the Host TX queue, so it is limited to a legacy 27-octet payload;
/// once queued the link sequence owns its SN, ACK and retransmission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AclReply {
    llid: u8,
    len: u8,
    bytes: [u8; LL_LEGACY_PAYLOAD as usize],
}

impl AclReply {
    /// `None` unless this is LLID 2 data or the `[2, reason]` termination PDU.
    /// Other control replies stay with the engine's `ControlState`.
    pub fn new(llid: u8, payload: &[u8]) -> Option<Self> {
        let allowed = match llid {
            2 => !payload.is_empty(),
            3 => payload.len() == 2 && payload[0] == 2,
            _ => false,
        };
        if !allowed || payload.len() > LL_LEGACY_PAYLOAD as usize {
            return None;
        }
        let mut bytes = [0u8; LL_LEGACY_PAYLOAD as usize];
        bytes[..payload.len()].copy_from_slice(payload);
        Some(Self {
            llid,
            len: payload.len() as u8,
            bytes,
        })
    }

    pub fn llid(&self) -> u8 {
        self.llid
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Our local `LL_TERMINATE_IND` reply.
    pub fn terminate(reason: u8) -> Self {
        Self::new(3, &[2, reason]).expect("terminate reply is a two-byte control PDU")
    }
}

// STATS slots the shared engine owns. The example keeps the same layout; the
// numbers are part of the acceptance tooling.
const STAT_RX_ARM: usize = 6;
const STAT_RX_DONE: usize = 7;
const STAT_CRC_ERR: usize = 8;
const STAT_INVALID_PDU: usize = 9;
const STAT_FIRST_ANCHOR: usize = 15;
const STAT_EVENTS: usize = 16;
const STAT_RX_PDUS: usize = 17;
const STAT_TX_OK: usize = 18;
const STAT_TX_LATE: usize = 19;
const STAT_TX_ERR: usize = 20;
const STAT_RX_ARM_ERR: usize = 21;
const STAT_EMPTY_EVENTS: usize = 23;
const STAT_DUPLICATE: usize = 24;
const STAT_RETRANSMIT: usize = 25;
const STAT_CONTROL_RX: usize = 26;
const STAT_UNKNOWN_RSP: usize = 27;
const STAT_TERMINATED_ACK: usize = 28;
const STAT_SUPERVISION: usize = 29;
const STAT_CONNECT_FAIL: usize = 30;
const STAT_RX_BACKPRESSURE: usize = 31;
const STAT_FIRST_ANCHOR_US: usize = 36;
const STAT_CLOSE_REASON: usize = 37;
const STAT_LAST_CONTROL: usize = 38;
const STAT_ACCEPTED: usize = 41;
const STAT_LAST_HEADER: usize = 42;
const STAT_LAST_LEN: usize = 43;
const STAT_MAX_CONNECTION_US: usize = 44;
const STAT_EVENT_NO: usize = 51;
const STAT_CHANNEL: usize = 52;
const STAT_RX_COMPLETE_LATENCY: usize = 54;
const STAT_RX_HANDLE_LATENCY: usize = 55;
const STAT_TX_PRE_LATENCY: usize = 56;
const STAT_TX_POST_LATENCY: usize = 57;
const STAT_SEQUENCE_US: usize = 58;
const STAT_HANDLED_US: usize = 59;
const STAT_TERMINATION_EXPIRED: usize = 60;
const STAT_BRIDGE_FAIL: usize = 63;

/// SECURE_STATS slots (S2 evidence layout).
const SEC_ENC_REQ: usize = 2;
const SEC_ENC_RSP: usize = 3;
const SEC_LTK_REQUEST: usize = 4;
const SEC_LTK_REPLY: usize = 5;
const SEC_START_REQ: usize = 6;
const SEC_START_RSP: usize = 7;
const SEC_ENCRYPTED_TX: usize = 8;
const SEC_ENCRYPTED_RX: usize = 9;
const SEC_ACTIVE: usize = 10;
const SEC_MIC_FAILURE: usize = 11;
const SEC_ERRORS: usize = 12;
const SEC_PREPARED: usize = 13;
const SEC_LAST_ERROR: usize = 15;

/// Host/executor surface the shared engine drives. Implementations must be
/// cheap: every method runs inside or next to a connection event.
pub trait LinkHost {
    /// AES block engine (the CH585 hardware engine on hardware).
    type Aes: AesEngine;

    fn local_features(&self) -> [u8; 8];
    fn new_aes(&mut self, key: &[u8; 16]) -> Self::Aes;

    fn stat_inc(&mut self, slot: usize);
    fn stat_put(&mut self, slot: usize, value: u32);
    fn stat_get(&self, slot: usize) -> u32;
    fn sec_inc(&mut self, slot: usize);
    fn sec_put(&mut self, slot: usize, value: u32);
    fn sec_error(&mut self, reason: u8) {
        self.sec_inc(SEC_ERRORS);
        self.sec_put(SEC_LAST_ERROR, u32::from(reason));
    }
    /// Timestamped trace row; `now_us` is sampled by the engine.
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

    /// Raw received ACL fragment. `ciphertext` is set when not yet decrypted.
    fn diag_acl_raw(&mut self, llid: u8, payload: &[u8], ciphertext: bool);
    /// Host ACL fragment about to be sent, before encryption.
    fn diag_acl_tx(&mut self, _llid: u8, _payload: &[u8]) {}
    fn diag_acl_plain(&mut self, llid: u8, payload: &[u8]);
    fn diag_control_opcode(&mut self, opcode: u8);
    fn note_bad_pdu(&mut self, header: u8, len: usize);
    fn note_rx_frame(&mut self, len: usize);
    fn note_rx_oversize(&mut self);
    fn note_start_req_queued(&mut self);
    fn note_start_rsp_queued(&mut self);
    fn diag_skipped_event(&mut self);

    fn can_receive_acl(&mut self, llid: u8, len: usize) -> bool;
    /// Returns false when the bridge refuses the fragment.
    fn receive_acl(&mut self, llid: u8, payload: &[u8]) -> bool;
    fn take_tx_acl(&mut self) -> Option<TxAcl>;
    fn ack_tx(&mut self, tag: TxTag) -> bool;

    fn is_connected(&self) -> bool;
    /// Publish LE Connection Complete; the host may fill the RPA/identity
    /// fields and resolve the peer here. False means the bridge refused it.
    fn publish_connection(&mut self, info: &mut ConnectionInfo) -> bool;
    fn disable_adv(&mut self);
    fn connection_closed(&mut self, reason: u8);
    /// HCI handle of the live link, when this host fronts one.
    fn local_handle(&self) -> Option<u16> {
        None
    }
    fn encryption_change(&mut self, handle: u16, status: u8, enabled: u8);
    fn connection_updated(&mut self, interval: u16, latency: u16, timeout: u16) -> bool;
    fn data_length_change(
        &mut self,
        tx_octets: u16,
        tx_time: u16,
        rx_octets: u16,
        rx_time: u16,
    ) -> bool;

    fn take_ltk_reply(&mut self) -> Option<LtkReply>;
    fn push_ltk_request(&mut self, rand: [u8; 8], ediv: u16) -> bool;
    fn take_data_length_request(&mut self) -> Option<(u16, u16)>;

    /// Host `LE Set PHY` preference masks (1M bit0, 2M bit1).
    fn take_phy_request(&mut self) -> Option<(u8, u8)> {
        None
    }
    /// Report one PHY completion: status, TX PHY code, RX PHY code.
    fn phy_update_complete(&mut self, _status: u8, _tx: u8, _rx: u8) {}

    fn publish_x1(&mut self, snapshot: &X1Snapshot);

    /// Run the Host executor (and example-side persistence) before the next RX
    /// prepare. `deadline` is that prepare time; `until` is the earliest bound.
    fn idle_gap(&mut self, deadline: u32, until: u32);
    /// Called after `connection_closed`, still in the close path.
    fn after_close(&mut self);
    fn on_reset(&mut self);
    fn on_disconnect_request(&mut self, reason: u8);
    /// Per-iteration hook before anything else (example time-driver advance).
    fn pre_iteration(&mut self);
    fn take_radio_request(&mut self) -> Option<RadioRequest>;

    /// Reply for an accepted, non-empty, plaintext LLID 1/2 fragment. Only
    /// consulted by sessions that do not advertise LE Encryption; called once
    /// per new fragment and held across events if the window is owned.
    /// `None` (the default) keeps the Host TX queue only.
    fn acl_reply(&mut self, _llid: u8, _payload: &[u8]) -> Option<AclReply> {
        None
    }
    /// Largest ACL payload the Host accepts; never widens the engine buffer.
    fn rx_payload_limit(&self) -> usize {
        MAX_ENCRYPTED
    }
    /// Capture-to-completion timeout; `None` keeps the engine's allowance.
    fn rx_capture_timeout_us(&self) -> Option<u32> {
        None
    }
    /// Post-exchange receive window; `None` keeps the engine's allowance.
    fn rx_rearm_window_us(&self) -> Option<u32> {
        None
    }
    /// Whether this Peripheral may start the feature exchange itself.
    fn allows_feature_request(&self) -> bool {
        true
    }
    /// Close with 0x3e when this many events pass without a first anchor.
    /// `None` (the default) keeps supervision as the only bound.
    fn establishment_event_limit(&self) -> Option<u16> {
        None
    }
}

/// CSA #2 / DLE observations published once per event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X1Snapshot {
    pub algorithm: u8,
    pub event_counter: u16,
    pub adv_chsel: bool,
    pub init_chsel: bool,
    pub length_req_rx: u32,
    pub length_rsp_rx: u32,
    pub length_req_tx: u32,
    pub length_rsp_tx: u32,
    pub tx_octets: u16,
    pub rx_octets: u16,
    pub tx_time: u16,
    pub rx_time: u16,
    pub max_tx_pdu: u16,
    pub max_rx_pdu: u16,
    pub rx_over_27: u32,
    pub tx_over_27: u32,
    pub host_packets_segmented: u32,
    pub host_fragments: u32,
    pub tx_pdus: u32,
    pub rx_pdus: u32,
    pub feature_exchange: bool,
    pub last_error: u32,
    /// Current PHY codes (1 = 1M, 2 = 2M) and the PHY procedure counters.
    pub phy_tx: u8,
    pub phy_rx: u8,
    pub phy_req_tx: u32,
    pub phy_req_rx: u32,
    pub phy_rsp_tx: u32,
    pub phy_rsp_rx: u32,
    pub phy_update_rx: u32,
    pub phy_changes: u32,
    pub phy_invalid: u32,
    /// Last `LL_PHY_UPDATE_IND` fields and the local counter at parse time.
    pub phy_ind: (u8, u8),
    pub phy_ind_instant: u16,
    pub phy_ind_counter: u16,
}

/// One received frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Received {
    pub len: usize,
    /// Header Length field: the on-air payload length to assume even when the
    /// CRC failed, used only for anchor estimation.
    pub air_len: u8,
    pub end: u32,
    pub crc_ok: bool,
}

/// Receive outcome. `Stopped` means the RF engine did not confirm idle; the
/// link must not be closed or re-armed on that path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxResult {
    Packet(Received),
    Missed,
    Stopped,
}

/// Transmit outcome, same stop-confirmation semantics as [`RxResult`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxResult {
    Sent,
    NotSent,
    Stopped,
}

/// End of one connection event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventEnd {
    Continue,
    Close(u8),
    Stopped,
}

/// Result of [`step`]: what the example's outer loop should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// The step ran (event and/or idle gap); loop again.
    Continue,
    /// The shared close ran (RF stopped, Host notified); clear the session.
    Closed(u8),
    /// Reset was processed; clear the session without a disconnect event.
    Reset,
    /// The run budget expired; leave the loop and park.
    Finish,
    /// The RF engine did not confirm idle; do not close, clear or re-arm.
    StopTimeout,
}

/// An encrypted PDU prepared before the connection event.
struct EncTx {
    llid: u8,
    bytes: [u8; MAX_ENCRYPTED],
    len: u8,
    tag: Option<TxTag>,
    terminate: Option<u8>,
}

/// Host ACL packet being split across LL PDUs.
struct PendingHost {
    acl: TxAcl,
    offset: usize,
    /// Only the last fragment owns the HCI tag (and returns the credit).
    fragments: u32,
}

/// An LL control PDU whose parsing does not depend on the event Instant.
struct DeferredControl {
    len: u8,
    bytes: [u8; 27],
}

/// A received encrypted PDU held until AES can run outside the IFS window.
struct DeferredRx {
    header: u8,
    payload: [u8; MAX_ENCRYPTED],
    len: u8,
    end: u32,
}

/// Control PDUs that carry no Instant and may be answered one event later.
fn deferrable_control(opcode: u8) -> bool {
    matches!(opcode, 0x08 | 0x09 | 0x0c | 0x14 | 0x15 | 0x16 | 0x17)
}

fn reached(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) as i32 >= 0
}

fn earlier(a: u32, b: u32) -> u32 {
    if reached(a, b) {
        b
    } else {
        a
    }
}

fn phy_code(phy: PhyMode) -> u8 {
    match phy {
        PhyMode::Rate2m => 2,
        _ => 1,
    }
}

/// Only builds that advertise LE Encryption may run the hoisted procedure.
/// Otherwise the PDUs take `ControlState`'s unsupported path.
fn encryption_supported<E: AesEngine>(s: &Session<E>) -> bool {
    s.control.local_features[0] & (1 << FEATURE_LE_ENCRYPTION) != 0
}

/// Peripheral link state. The engine owns everything the RF loop mutates; the
/// example only creates it and inspects the negotiated parameters.
/// Who advances the connection event counter after a served event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvanceOwner {
    /// The engine advances inside [`connection_event`]/[`step`] (P3, HID).
    SelfRun,
    /// A [`SessionLink`] in the scheduler table advances via
    /// [`ScheduledLink::advance_one`]; the engine must not.
    Table,
}

/// Scheduler adapter that owns one [`Session`] inside [`LinkTable`].
///
/// [`LinkTable`]: crate::ll::sched::LinkTable
pub struct SessionLink<E: AesEngine> {
    pub session: Session<E>,
}

impl<E: AesEngine> SessionLink<E> {
    pub fn new(mut session: Session<E>) -> Self {
        session.set_advance_owner(AdvanceOwner::Table);
        Self { session }
    }
}

impl<E: AesEngine> ScheduledLink for SessionLink<E> {
    fn window(&self) -> LinkWindow {
        let conn = &self.session.conn;
        // One bounded exchange: RX the largest accepted PDU, then TX one frame
        // of the same size. `step` is handed `hard_end_us` as its budget, so
        // the event cannot outlive this reservation.
        let air = conn.rx_complete_allowance_us();
        let (deadline_us, deadline_cause) = self.session.event_deadline();
        LinkWindow {
            prepare_us: conn.rx_start_us().wrapping_sub(ARM_LEAD_US),
            latest_start_us: conn.event_start_us(),
            reservation_end_us: conn
                .rx_complete_end_us()
                .wrapping_add(air)
                .wrapping_add(EVENT_TAIL_US),
            min_service_us: air + 80 + EVENT_TAIL_US,
            deadline_us,
            deadline_cause,
            deadline_reason: deadline_cause.default_reason(),
            channel: conn.channel(),
            priority: 0,
            event: conn.event_counter(),
        }
    }

    fn advance_one(&mut self) -> Result<(), ConnError> {
        self.session.conn.next_event()?;
        self.session.report_update_instant();
        Ok(())
    }

    fn expiry(&self, now: u32) -> Option<Expiry> {
        let (at_us, cause) = self.session.event_deadline();
        super::conn::time_reached(now, at_us).then_some(Expiry {
            at_us,
            cause,
            reason: cause.default_reason(),
        })
    }
}

pub struct Session<E: AesEngine> {
    conn: PeripheralConnection,
    link: LinkSequence,
    control: ControlState,
    pending_control: Option<DataPdu>,
    /// Same-event reply captured from `LinkHost::acl_reply`.
    pending_acl_reply: Option<AclReply>,
    acl_tag: Option<TxTag>,
    terminating: Option<u8>,
    /// End the link once the control PDU in `pending_control` is acknowledged.
    terminate_after_control: Option<u8>,
    terminate_requested: Option<u8>,
    update_instant: Option<u16>,
    update_report: Option<(u16, u16, u16)>,
    began: u32,
    start: PeripheralStart,
    enc: Option<Encryption<E>>,
    enc_active: bool,
    rx_encrypted: bool,
    enc_rsp_queued: bool,
    enc_rsp_sent: bool,
    pending_start_rsp: Option<EncTx>,
    enc_change_pending: bool,
    pending_enc_control: Option<EncTx>,
    pending_enc_acl: Option<EncTx>,
    pending_host: Option<PendingHost>,
    /// X1 telemetry: (our ADV ChSel, the CONNECT_IND ChSel).
    chsel: (bool, bool),
    max_tx_pdu: u16,
    max_rx_pdu: u16,
    tx_over_27: u32,
    rx_over_27: u32,
    tx_pdus: u32,
    rx_pdus: u32,
    host_fragments: u32,
    host_packets_segmented: u32,
    length_req_tx: u32,
    length_rsp_tx: u32,
    length_req_rx: u32,
    length_rsp_rx: u32,
    x1_last_error: u32,
    dl_reported: Option<(u16, u16, u16, u16)>,
    deferred_rx: Option<DeferredRx>,
    deferred_control: Option<DeferredControl>,
    enc_rsp_random: [u8; 12],
    enc_rsp_payload: [u8; 13],
    pending_enc_req: Option<[u8; 23]>,
    enc_rsp_at: u32,
    pending_ltk: Option<([u8; 8], u16)>,
    own_rpa: Option<[u8; 6]>,
    /// Who advances the connection event counter after a served event.
    advance_owner: AdvanceOwner,
    /// The last `step` ran a connection event body.
    event_served: bool,
    /// This link already stopped the advertising that formed it.
    adv_stopped: bool,
}

impl<E: AesEngine> Session<E> {
    pub fn new(
        params: ConnectParams,
        advertiser_chsel: bool,
        end: u32,
        now: u32,
        enc_rsp_random: [u8; 12],
        local_features: [u8; 8],
    ) -> Self {
        let initiator_chsel = params.chsel;
        let mut control = ControlState::new();
        control.local_features = local_features;
        let mut enc_rsp_payload = [0u8; 13];
        enc_rsp_payload[0] = 0x04;
        enc_rsp_payload[1..].copy_from_slice(&enc_rsp_random);
        Self {
            conn: PeripheralConnection::new(params, end, advertiser_chsel),
            link: LinkSequence::new(),
            control,
            pending_control: None,
            pending_acl_reply: None,
            acl_tag: None,
            terminating: None,
            terminate_after_control: None,
            terminate_requested: None,
            update_instant: None,
            update_report: None,
            began: now,
            start: PeripheralStart::new(),
            enc: None,
            enc_active: false,
            rx_encrypted: false,
            enc_rsp_queued: false,
            enc_rsp_sent: false,
            pending_start_rsp: None,
            enc_change_pending: false,
            pending_enc_control: None,
            pending_enc_acl: None,
            pending_host: None,
            chsel: (advertiser_chsel, initiator_chsel),
            max_tx_pdu: 0,
            max_rx_pdu: 0,
            tx_over_27: 0,
            rx_over_27: 0,
            tx_pdus: 0,
            rx_pdus: 0,
            host_fragments: 0,
            host_packets_segmented: 0,
            length_req_tx: 0,
            length_rsp_tx: 0,
            length_req_rx: 0,
            length_rsp_rx: 0,
            x1_last_error: 0,
            dl_reported: None,
            deferred_rx: None,
            deferred_control: None,
            enc_rsp_random,
            enc_rsp_payload,
            pending_enc_req: None,
            enc_rsp_at: 0,
            pending_ltk: None,
            own_rpa: None,
            advance_owner: AdvanceOwner::SelfRun,
            event_served: false,
            adv_stopped: false,
        }
    }

    /// Hand event advancement to the scheduler table (`ll::sched`).
    pub fn set_advance_owner(&mut self, owner: AdvanceOwner) {
        self.advance_owner = owner;
    }

    /// True when the last [`step`] ran a connection event body.
    pub fn take_event_served(&mut self) -> bool {
        core::mem::take(&mut self.event_served)
    }

    /// Publish a queued Connection Update once its instant has passed.
    fn report_update_instant(&mut self) {
        if self.update_instant == Some(self.conn.event_counter()) {
            self.update_instant = None;
            self.update_report = Some((
                self.conn.params.interval,
                self.conn.params.latency,
                self.conn.params.timeout,
            ));
        }
    }

    /// Hard deadline of the next event, with the cause the table reports.
    fn event_deadline(&self) -> (u32, CloseCause) {
        let supervision = self.conn.supervision_deadline_us();
        match self.control.termination_deadline_us() {
            Some(termination) if !super::conn::time_reached(supervision, termination) => {
                (termination, CloseCause::Termination)
            }
            _ if self.conn.established() => (supervision, CloseCause::SupervisionTimeout),
            _ => (supervision, CloseCause::EstablishmentTimeout),
        }
    }

    /// Local RPA snapshot this connection was established with.
    pub fn set_own_rpa(&mut self, address: [u8; 6]) {
        self.own_rpa = Some(address);
    }

    /// Seed TX preference from the Host's `LE Set Data Length` suggestion.
    pub fn set_suggested_data_length(&mut self, octets: u16, time: u16) {
        self.control.data_length.set_suggested_tx(octets, time);
    }

    pub fn event_start_us(&self) -> u32 {
        self.conn.event_start_us()
    }

    pub fn event_counter(&self) -> u16 {
        self.conn.event_counter()
    }

    pub fn channel(&self) -> u8 {
        self.conn.channel()
    }

    pub fn established(&self) -> bool {
        self.conn.established()
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

    pub fn request_terminate<H: LinkHost>(&mut self, host: &mut H, reason: u8, now: u32) {
        let _ = host;
        self.terminate_requested.get_or_insert(reason);
        self.control
            .start_termination(now, self.conn.params.timeout);
    }

    /// Copy negotiated DLE limits into the link, the RX window and the Host.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    fn apply_data_length<H: LinkHost>(&mut self, host: &mut H) {
        let tx = self.control.data_length.tx_octets(self.enc_active);
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
        if data.negotiated() && self.dl_reported != Some(reported) {
            if host.data_length_change(reported.0, reported.1, reported.2, reported.3) {
                self.dl_reported = Some(reported);
            }
        }
    }

    /// True while no encryption exchange or queued PDU owns the link.
    fn encryption_idle(&self) -> bool {
        matches!(self.start.stage(), StartStage::Idle | StartStage::Active)
            && !self.enc_rsp_queued
            && !self.enc_change_pending
            && self.pending_control.is_none()
            && self.pending_enc_control.is_none()
            && self.pending_enc_acl.is_none()
            && self.pending_start_rsp.is_none()
    }

    fn x1_snapshot(&self) -> X1Snapshot {
        let data_length = &self.control.data_length;
        X1Snapshot {
            algorithm: match self.conn.channel_selection_algorithm() {
                ChannelSelectionAlgorithm::Csa2 => 2,
                _ => 1,
            },
            event_counter: self.conn.event_counter(),
            adv_chsel: self.chsel.0,
            init_chsel: self.chsel.1,
            length_req_rx: self.length_req_rx,
            length_rsp_rx: self.length_rsp_rx,
            length_req_tx: self.length_req_tx,
            length_rsp_tx: self.length_rsp_tx,
            tx_octets: data_length.tx_octets(self.enc_active),
            rx_octets: data_length.rx_octets(self.rx_encrypted),
            tx_time: data_length.tx_time_us(),
            rx_time: data_length.rx_time_us(),
            max_tx_pdu: self.max_tx_pdu,
            max_rx_pdu: self.max_rx_pdu,
            rx_over_27: self.rx_over_27,
            tx_over_27: self.tx_over_27,
            host_packets_segmented: self.host_packets_segmented,
            host_fragments: self.host_fragments,
            tx_pdus: self.tx_pdus,
            rx_pdus: self.rx_pdus,
            feature_exchange: self.control.peer_features.is_some() || data_length.negotiated(),
            last_error: self.x1_last_error,
            phy_tx: phy_code(self.conn.tx_phy()),
            phy_rx: phy_code(self.conn.rx_phy()),
            phy_req_tx: self.control.phy_req_tx,
            phy_req_rx: self.control.phy_req_rx,
            phy_rsp_tx: self.control.phy_rsp_tx,
            phy_rsp_rx: self.control.phy_rsp_rx,
            phy_update_rx: self.control.phy_update_rx,
            phy_changes: self.control.phy_changes,
            phy_invalid: self.control.phy_invalid,
            phy_ind: self.control.phy_ind,
            phy_ind_instant: self.control.phy_ind_instant,
            phy_ind_counter: self.control.phy_ind_counter,
        }
    }
}

/// Arm RX and wait for this exchange's frame.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn receive<H: LinkHost, R: LinkRadio, C: InstantUs>(
    radio: &mut R,
    clock: &C,
    host: &mut H,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    until: u32,
    expires: u32,
    capture_timeout_us: u32,
    arm_times: &mut [u32; 2],
) -> RxResult {
    radio.clear_rx_status();
    let now = clock.now_us();
    *arm_times = [now, 0];
    if reached(now, until) || reached(now, expires) {
        return RxResult::Missed;
    }
    // `until` allows packet completion, not just its latest preamble start.
    let window = until.wrapping_sub(now).saturating_mul(2);
    // SAFETY: `rx` is a static DMA buffer and every path below stops the
    // engine before returning, so no window outlives this call.
    if unsafe { radio.rx_basic(clock, &mut rx.0, window) }.is_err() {
        host.stat_inc(STAT_RX_ARM_ERR);
        return if radio.stop(clock) {
            RxResult::Missed
        } else {
            RxResult::Stopped
        };
    }
    arm_times[1] = clock.now_us();
    host.stat_inc(STAT_RX_ARM);
    let mut capture = None;
    let (end, crc_ok) = loop {
        let status = radio.rx_state();
        let now = clock.now_us();
        if reached(now, expires) {
            return if radio.stop(clock) {
                RxResult::Missed
            } else {
                RxResult::Stopped
            };
        }
        if status.done {
            break (now, status.crc_ok);
        }
        if capture.is_none() && status.captured {
            radio.note_capture(now);
            capture = Some(now);
        }
        let expired = match capture {
            Some(at) => now.wrapping_sub(at) >= capture_timeout_us,
            None => reached(now, until),
        };
        if expired {
            return if radio.stop(clock) {
                RxResult::Missed
            } else {
                RxResult::Stopped
            };
        }
    };
    if !radio.stop(clock) {
        return RxResult::Stopped;
    }
    host.stat_put(STAT_RX_COMPLETE_LATENCY, clock.now_us().wrapping_sub(end));
    host.stat_inc(STAT_RX_DONE);
    let len = usize::from(rx.0[1]) + 2;
    let air_len = rx.0[1];
    host.note_rx_frame(len);
    if len > MAX_ENCRYPTED + 2 {
        if !crc_ok {
            // Matching AA still establishes the link (§4.5); the payload is
            // unusable but the header Length is what the anchor must assume.
            host.stat_inc(STAT_CRC_ERR);
            return RxResult::Packet(Received {
                len: 2,
                air_len,
                end,
                crc_ok,
            });
        }
        host.note_rx_oversize();
        host.stat_inc(STAT_INVALID_PDU);
        return RxResult::Missed;
    }
    host.stat_put(STAT_RX_HANDLE_LATENCY, clock.now_us().wrapping_sub(end));
    if !crc_ok {
        host.stat_inc(STAT_CRC_ERR);
    }
    RxResult::Packet(Received {
        len,
        air_len,
        end,
        crc_ok,
    })
}

/// Transmit one frame and stop the engine.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
#[inline(never)]
pub fn transmit<H: LinkHost, R: LinkRadio, C: InstantUs>(
    radio: &mut R,
    clock: &C,
    host: &mut H,
    frame: &[u8],
    end: u32,
) -> TxResult {
    host.stat_put(STAT_TX_PRE_LATENCY, clock.now_us().wrapping_sub(end));
    // Preserve the P3 command deadline; it is not calibrated air IFS.
    // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or stops
    // the engine on a failed send; `frame` only has to live for the call.
    let result = unsafe { radio.tx_basic(clock, frame, 0, Some(end.wrapping_add(120))) };
    host.stat_put(STAT_TX_POST_LATENCY, clock.now_us().wrapping_sub(end));
    match result {
        Ok(()) => host.stat_inc(STAT_TX_OK),
        Err(crate::Error::Late) => host.stat_inc(STAT_TX_LATE),
        Err(_) => host.stat_inc(STAT_TX_ERR),
    }
    if !radio.stop(clock) {
        return TxResult::Stopped;
    }
    if result.is_ok() {
        TxResult::Sent
    } else {
        TxResult::NotSent
    }
}

/// Report LE Connection Complete once, after the event's time-critical work.
fn report_connection<H: LinkHost, E: AesEngine>(host: &mut H, s: &Session<E>) -> Option<u8> {
    if host.is_connected() {
        return None;
    }
    let p = s.conn.params;
    let mut info = ConnectionInfo {
        handle: 1,
        role: Role::Peripheral,
        peer_address_type: u8::from(p.peer_random),
        peer_address: p.peer_addr,
        interval: p.interval,
        latency: p.latency,
        supervision_timeout: p.timeout,
        master_clock_accuracy: p.sca,
        peer_rpa: None,
        local_rpa: s.own_rpa,
        peer_identity: None,
    };
    if !host.publish_connection(&mut info) {
        host.stat_inc(STAT_BRIDGE_FAIL);
        return Some(0x1f);
    }
    None
}

/// Run one connection event.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub fn connection_event<E: AesEngine, H: LinkHost<Aes = E>, R: LinkRadio, C: InstantUs>(
    radio: &mut R,
    clock: &C,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    s: &mut Session<E>,
    host: &mut H,
    finish: u32,
) -> EventEnd {
    if let Some(reason) = s.expiration(host, clock.now_us()) {
        return EventEnd::Close(reason);
    }
    // The Instant may have fired while advancing here or in the scheduler;
    // report it once, before this event's RX is armed.
    if let Some((tx, rx)) = s.conn.take_phy_applied() {
        s.control.on_phy_applied();
        host.phy_update_complete(0, phy_code(tx), phy_code(rx));
    }
    radio.set_phy(s.conn.tx_phy(), s.conn.rx_phy());
    // The caller's catch-up can cross the limit inside one step, so the check
    // lives here, before any RX is armed.
    if !s.conn.established() {
        if let Some(limit) = host.establishment_event_limit() {
            if s.conn.event_counter() >= limit {
                if reached(clock.now_us(), finish) {
                    // The finite run budget ends first; no event is armed.
                    return EventEnd::Continue;
                }
                host.stat_inc(STAT_CONNECT_FAIL);
                return EventEnd::Close(0x3e);
            }
        }
    }
    let event = s.conn.event_counter();
    let channel = s.conn.channel();
    host.stat_put(STAT_EVENT_NO, u32::from(event));
    host.stat_put(STAT_CHANNEL, u32::from(channel));
    host.stat_inc(STAT_EVENTS);
    let event_limit = s
        .conn
        .event_start_us()
        .wrapping_add(u32::from(s.conn.params.interval) * 1250)
        .wrapping_sub(600);
    let mut expires = earlier(
        event_limit,
        earlier(finish, s.conn.supervision_deadline_us()),
    );
    if let Some(end) = s.control.termination_deadline_us() {
        expires = earlier(expires, end);
    }
    // Once inside the Host guard, stay in this tight RF wait like P3.
    let prepare = s.conn.rx_start_us().wrapping_sub(100);
    while !reached(clock.now_us(), prepare) {
        let now = clock.now_us();
        if reached(now, expires) {
            return match s.expiration(host, now) {
                Some(reason) => EventEnd::Close(reason),
                None => EventEnd::Continue,
            };
        }
    }
    if let Some(reason) = s.expiration(host, clock.now_us()) {
        return EventEnd::Close(reason);
    }
    let mut until = s.conn.rx_complete_end_us();
    let mut any_rx = false;
    let mut consecutive_crc = 0u8;
    for _ in 0..32 {
        if reached(clock.now_us(), finish) || reached(clock.now_us(), event_limit) {
            break;
        }
        let first_exchange = !any_rx;
        let mut arm_times = [0; 2];
        let capture_us = host
            .rx_capture_timeout_us()
            .unwrap_or_else(|| s.conn.rx_complete_allowance_us() + 64);
        let packet = match receive(
            radio,
            clock,
            host,
            rx,
            until,
            expires,
            capture_us,
            &mut arm_times,
        ) {
            RxResult::Packet(packet) => packet,
            RxResult::Missed => {
                if first_exchange {
                    host.trace(
                        clock.now_us(),
                        8,
                        event,
                        channel,
                        0,
                        0,
                        arm_times[0],
                        arm_times[1],
                    );
                }
                break;
            }
            RxResult::Stopped => return EventEnd::Stopped,
        };
        let header = rx.0[0];
        let payload = &rx.0[2..packet.len];
        let llid = header & 3;
        if !packet.crc_ok {
            consecutive_crc = consecutive_crc.saturating_add(1);
            // A matching access address establishes the link and fixes the
            // first anchor even with a CRC error; the header Length is the
            // only airtime fact available (§4.5.1).
            let first = !s.conn.established();
            if !s.conn.on_rx_anchor_crc(packet.end, packet.air_len) {
                return match s.expiration(host, packet.end) {
                    Some(reason) => EventEnd::Close(reason),
                    None => EventEnd::Close(0x08),
                };
            }
            if first {
                host.stat_inc(STAT_FIRST_ANCHOR);
                if host.stat_get(STAT_FIRST_ANCHOR_US) == 0 {
                    host.stat_put(STAT_FIRST_ANCHOR_US, packet.end);
                }
            }
            any_rx = true;
            // §4.5.6: a second consecutive CRC error closes the event without
            // another response.
            if consecutive_crc >= 2 {
                break;
            }
            // §4.5.1: answer the first CRC-error packet with a retransmission
            // or an Empty PDU; the corrupt packet does not advance the SN.
            let retry = s.link.has_outstanding();
            let pdu = s.link.tx_pdu();
            let frame = pdu.as_bytes();
            tx.0[..frame.len()].copy_from_slice(frame);
            let sent = match transmit(radio, clock, host, &tx.0[..frame.len()], packet.end) {
                TxResult::Sent => true,
                TxResult::NotSent => false,
                TxResult::Stopped => return EventEnd::Stopped,
            };
            if sent {
                note_tx_pdu(s, frame.len() - 2);
            }
            if retry {
                host.stat_inc(STAT_RETRANSMIT);
            }
            // Publish after the time-critical response. A CRC-error first
            // packet is still a real link, and without this the Host never
            // learns it ended.
            if let Some(reason) = report_connection(host, s) {
                return EventEnd::Close(reason);
            }
            if !sent {
                return EventEnd::Continue;
            }
            let rearm = host
                .rx_rearm_window_us()
                .unwrap_or_else(|| s.conn.rx_complete_allowance_us() + 64);
            until = earlier(clock.now_us().wrapping_add(rearm), event_limit);
            continue;
        }
        consecutive_crc = 0;
        // The Host may narrow the payload cap; the engine buffer is the limit.
        if payload.len() > host.rx_payload_limit().min(MAX_ENCRYPTED) {
            host.note_bad_pdu(header, payload.len());
            host.stat_inc(STAT_INVALID_PDU);
            break;
        }
        note_rx_pdu(s, payload.len());
        // After our plaintext LL_START_ENC_REQ, the Central's next non-empty
        // PDU is its encrypted LL_START_ENC_RSP; empty PDUs stay plaintext.
        let ciphertext = s.rx_encrypted && !(llid == 1 && payload.is_empty());
        let capacity = if ciphertext {
            // The bridge stores plaintext, so reserve room for the fragment
            // without the MIC, not for the on-air ciphertext.
            let plain_len = payload.len().saturating_sub(BLE_MIC_LEN);
            s.deferred_rx.is_none()
                && match llid {
                    1 | 2 => s.pending_acl_reply.is_none() && host.can_receive_acl(llid, plain_len),
                    3 => true,
                    _ => false,
                }
        } else {
            match llid {
                1 if payload.is_empty() => true,
                1 | 2 => s.pending_acl_reply.is_none() && host.can_receive_acl(llid, payload.len()),
                3 => {
                    s.pending_control.is_none()
                        && s.terminate_requested.is_none()
                        && s.update_report.is_none()
                }
                _ => false,
            }
        };
        let outcome = s.link.on_rx(header, payload, true, capacity);
        if outcome.status == RxStatus::Invalid {
            host.note_bad_pdu(header, payload.len());
            host.stat_inc(STAT_INVALID_PDU);
            break;
        }
        let acknowledged_acl = if outcome.tx_acked {
            s.acl_tag.take()
        } else {
            None
        };
        if outcome.tx_acked {
            if let Some(reason) = s.terminating {
                host.stat_inc(STAT_TERMINATED_ACK);
                return EventEnd::Close(reason);
            }
        }
        let sequence_us = clock.now_us().wrapping_sub(packet.end);
        let first = !s.conn.established();
        if !s.conn.on_rx_anchor(packet.end, payload.len() as u8) {
            return match s.expiration(host, packet.end) {
                Some(reason) => EventEnd::Close(reason),
                None => EventEnd::Close(0x08),
            };
        }
        if first {
            host.stat_inc(STAT_FIRST_ANCHOR);
            if host.stat_get(STAT_FIRST_ANCHOR_US) == 0 {
                host.stat_put(STAT_FIRST_ANCHOR_US, packet.end);
            }
        }
        any_rx = true;
        host.stat_inc(STAT_RX_PDUS);
        host.stat_put(STAT_LAST_HEADER, u32::from(header));
        host.stat_put(STAT_LAST_LEN, payload.len() as u32);
        let mut remote_terminate = None;
        let mut deliver_acl = false;
        match outcome.status {
            RxStatus::Accepted => {
                host.stat_inc(STAT_ACCEPTED);
                // Ciphertext has no readable L2CAP/ATT header; the deferred
                // path counts those opcodes after decryption instead.
                if matches!(llid, 1 | 2) {
                    host.diag_acl_raw(llid, payload, ciphertext);
                }
                if ciphertext {
                    // AES-CCM cannot fit in the 150 us response window; hold
                    // the PDU and decrypt it after the event.
                    let mut copy = [0u8; MAX_ENCRYPTED];
                    copy[..payload.len()].copy_from_slice(payload);
                    s.deferred_rx = Some(DeferredRx {
                        header,
                        payload: copy,
                        len: payload.len() as u8,
                        end: packet.end,
                    });
                } else if llid == 3 {
                    host.stat_inc(STAT_CONTROL_RX);
                    host.stat_put(STAT_LAST_CONTROL, u32::from(payload[0]));
                    match payload[0] {
                        0x03 if encryption_supported(s) && s.start.stage() == StartStage::Idle => {
                            // Hand the request over for parsing once the event
                            // is over. This event answers with an empty PDU;
                            // the response leaves two events later, as macOS
                            // does.
                            s.enc_rsp_at = packet
                                .end
                                .wrapping_add(u32::from(s.conn.params.interval) * 1250 * 3 / 2);
                            if payload.len() == 23 {
                                let mut req = [0u8; 23];
                                req.copy_from_slice(payload);
                                s.pending_enc_req = Some(req);
                                host.sec_inc(SEC_ENC_REQ);
                            } else {
                                s.enc_rsp_at = 0;
                                host.sec_error(0x1e);
                                s.request_terminate(host, 0x1e, packet.end);
                            }
                        }
                        0x05 if encryption_supported(s) => {
                            // Core §5.1.3.1 has the Peripheral send this PDU;
                            // a Central that sends one is only counted.
                            host.sec_inc(SEC_START_REQ);
                        }
                        _ => {
                            host.diag_control_opcode(payload[0]);
                            note_control_rx(s, payload);
                            // These procedures have no Instant and tolerate a
                            // reply one event later, so parse them in the
                            // post-event idle gap rather than inside the
                            // window.
                            if deferrable_control(payload[0])
                                && s.deferred_control.is_none()
                                && payload.len() <= 27
                            {
                                let mut bytes = [0u8; 27];
                                bytes[..payload.len()].copy_from_slice(payload);
                                s.deferred_control = Some(DeferredControl {
                                    len: payload.len() as u8,
                                    bytes,
                                });
                            } else {
                                match s.control.on_pdu(&mut s.conn, payload, LOCAL_VERSION) {
                                    Ok(action) => {
                                        // DLE takes effect once the request or
                                        // response has been received.
                                        s.apply_data_length(host);
                                        match action {
                                            ControlAction::Reply(pdu) => {
                                                if pdu.as_bytes().first() == Some(&7) {
                                                    host.stat_inc(STAT_UNKNOWN_RSP);
                                                }
                                                if pdu.as_bytes().first() == Some(&0x15) {
                                                    s.length_rsp_tx += 1;
                                                }
                                                s.pending_control =
                                                    Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                                            }
                                            ControlAction::Terminate(reason) => {
                                                // A closing link must not send
                                                // a business reply it still holds.
                                                s.pending_acl_reply = None;
                                                remote_terminate = Some(reason)
                                            }
                                            ControlAction::None => {
                                                if payload[0] == 0 && payload.len() == 12 {
                                                    s.update_instant = Some(u16::from_le_bytes([
                                                        payload[10],
                                                        payload[11],
                                                    ]));
                                                }
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        if matches!(payload.first(), Some(0x14) | Some(0x15)) {
                                            s.x1_last_error = 0x1e;
                                        }
                                        s.request_terminate(
                                            host,
                                            termination_reason(error),
                                            packet.end,
                                        );
                                    }
                                }
                            }
                        }
                    }
                } else {
                    deliver_acl = !(llid == 1 && payload.is_empty());
                }
            }
            RxStatus::Duplicate => host.stat_inc(STAT_DUPLICATE),
            RxStatus::Backpressure => host.stat_inc(STAT_RX_BACKPRESSURE),
            RxStatus::Invalid => unreachable!(),
        }
        // Captured only for a newly accepted fragment, so duplicates and
        // retransmissions never re-run the Host. A termination reply keeps
        // its single owner: the existing termination state machine. Sessions
        // that advertise LE Encryption keep the procedure's TX ownership.
        if deliver_acl && !encryption_supported(s) {
            match host.acl_reply(llid, payload) {
                Some(reply) if reply.llid() == 3 => {
                    s.request_terminate(host, reply.payload()[1], packet.end);
                }
                Some(reply) => s.pending_acl_reply = Some(reply),
                None => {}
            }
        }
        expires = earlier(
            event_limit,
            earlier(finish, s.conn.supervision_deadline_us()),
        );
        if let Some(end) = s.control.termination_deadline_us() {
            expires = earlier(expires, end);
        }
        let handled_us = clock.now_us().wrapping_sub(packet.end);
        let retry = s.link.has_outstanding();
        if !retry {
            if s.enc_active {
                // Every new PDU was encrypted before the event; the IFS budget
                // only covers copying it into the link layer.
                if let Some(tx) = s
                    .pending_enc_control
                    .take()
                    .or_else(|| s.pending_enc_acl.take())
                {
                    s.link
                        .queue(tx.llid, &tx.bytes[..usize::from(tx.len)])
                        .unwrap();
                    s.acl_tag = tx.tag;
                    if tx.terminate.is_some() {
                        s.terminating = tx.terminate;
                    }
                    host.sec_inc(SEC_ENCRYPTED_TX);
                }
            } else if let Some(tx) = s.pending_start_rsp.take() {
                // The Central's encrypted LL_START_ENC_RSP was the previous
                // event's PDU: answer with our precomputed encrypted response.
                s.link
                    .queue(tx.llid, &tx.bytes[..usize::from(tx.len)])
                    .unwrap();
                s.acl_tag = tx.tag;
                s.enc_active = true;
                s.enc_change_pending = true;
                // TX grows by the MIC now that our PDUs are encrypted.
                s.apply_data_length(host);
                host.sec_inc(SEC_START_RSP);
                host.sec_inc(SEC_ENCRYPTED_TX);
                host.sec_inc(SEC_ACTIVE);
                host.note_start_rsp_queued();
            } else if s.rx_encrypted {
                // LL_START_ENC_REQ is outstanding: only Empty PDUs may share
                // this window until the Central's encrypted response.
            } else if s.enc_rsp_queued {
                // The prebuilt LL_ENC_RSP owns this event.
                let pdu = s.pending_control.take().unwrap();
                s.link.queue(3, pdu.payload()).unwrap();
                s.enc_rsp_queued = false;
                s.enc_rsp_sent = true;
                if let Some(reason) = s.terminate_after_control.take() {
                    s.terminating = Some(reason);
                }
            } else if s.enc_rsp_sent && s.start.stage() == StartStage::Prepared {
                // Core 5.4 Vol 6 Part B §5.1.3.1: the Peripheral sends the
                // plaintext LL_START_ENC_REQ and starts RX decryption.
                let (start, enc) = (&mut s.start, &mut s.enc);
                match start.start_enc_req(enc.as_mut().unwrap()) {
                    Ok(pdu) => {
                        s.link.queue(3, pdu.as_bytes()).unwrap();
                        s.rx_encrypted = true;
                        // The Central's PDUs carry the MIC from here on.
                        s.apply_data_length(host);
                        host.sec_inc(SEC_START_REQ);
                        host.note_start_req_queued();
                    }
                    Err(_) => {
                        host.sec_error(0x1e);
                        s.request_terminate(host, 0x1e, packet.end);
                    }
                }
            } else if let Some(reason) = s.terminate_requested.take() {
                s.link.queue(3, &[2, reason]).unwrap();
                s.terminating = Some(reason);
            } else if let Some(pdu) = s.pending_control.take() {
                // Ordinary control replies wait for the encryption procedure
                // to finish; only Empty/TERMINATE PDUs may share that window.
                s.link.queue(3, pdu.payload()).unwrap();
                if let Some(reason) = s.terminate_after_control.take() {
                    s.terminating = Some(reason);
                }
            } else if let Some(reply) = s.pending_acl_reply.take() {
                // No higher-priority control or retransmission this event.
                s.link.queue(reply.llid(), reply.payload()).unwrap();
            } else if s.enc_rsp_at == 0 || reached(clock.now_us(), s.enc_rsp_at) {
                // The encryption procedure owns the link until it ends: no ACL
                // data may share the event with LL_ENC_REQ/LL_ENC_RSP.
                queue_next_host_fragment(host, s);
            }
        }
        let pdu = s.link.tx_pdu();
        let frame = pdu.as_bytes();
        tx.0[..frame.len()].copy_from_slice(frame);
        let sent = match transmit(radio, clock, host, &tx.0[..frame.len()], packet.end) {
            TxResult::Sent => true,
            TxResult::NotSent => false,
            TxResult::Stopped => return EventEnd::Stopped,
        };
        if sent {
            note_tx_pdu(s, frame.len() - 2);
        }
        host.stat_put(STAT_SEQUENCE_US, sequence_us);
        host.stat_put(STAT_HANDLED_US, handled_us);
        if retry {
            host.stat_inc(STAT_RETRANSMIT);
        }
        host.trace(
            clock.now_us(),
            3,
            event,
            channel,
            header,
            payload.len() as u8,
            packet.end,
            u32::from(pdu.header()),
        );
        if first_exchange {
            host.trace(
                clock.now_us(),
                8,
                event,
                channel,
                0,
                0,
                arm_times[0],
                arm_times[1],
            );
        }
        if !sent {
            // A late command means nothing went on air. That is a missed
            // event, not a failed link: the PDU stays queued and is
            // retransmitted in the next event.
            //
            // The received PDU, however, was already acknowledged in the LL
            // sequence and the peer will never send it again: dropping it
            // loses a fragment of a multi-PDU L2CAP frame. Deliver it even
            // though the response is late.
            if let Some(reason) = report_connection(host, s) {
                return EventEnd::Close(reason);
            }
            if deliver_acl && !host.receive_acl(llid, payload) {
                host.stat_inc(STAT_BRIDGE_FAIL);
                return EventEnd::Close(0x1f);
            }
            return EventEnd::Continue;
        }
        // Serialize HCI output only after the time-critical radio response.
        if let Some(reason) = report_connection(host, s) {
            return EventEnd::Close(reason);
        }
        if let Some(tag) = acknowledged_acl {
            if !host.ack_tx(tag) {
                host.stat_inc(STAT_BRIDGE_FAIL);
                return EventEnd::Close(0x1f);
            }
        }
        if deliver_acl && !host.receive_acl(llid, payload) {
            host.stat_inc(STAT_BRIDGE_FAIL);
            return EventEnd::Close(0x1f);
        }
        if let Some(reason) = remote_terminate {
            host.stat_inc(STAT_TERMINATED_ACK);
            return EventEnd::Close(reason);
        }
        let rearm = host
            .rx_rearm_window_us()
            .unwrap_or_else(|| s.conn.rx_complete_allowance_us() + 64);
        until = earlier(clock.now_us().wrapping_add(rearm), event_limit);
    }
    if !any_rx {
        host.stat_inc(STAT_EMPTY_EVENTS);
        host.trace(
            clock.now_us(),
            5,
            event,
            channel,
            0,
            0,
            s.conn.rx_start_us(),
            s.conn.rx_end_us(),
        );
    }
    // The scheduler table owns advancement in `AdvanceOwner::Table` mode and
    // runs the same update-instant bookkeeping in `advance_one`.
    if s.advance_owner == AdvanceOwner::SelfRun {
        if s.conn.next_event().is_err() {
            return EventEnd::Close(0x28);
        }
        s.report_update_instant();
    }
    match s.expiration(host, clock.now_us()) {
        Some(reason) => EventEnd::Close(reason),
        None => EventEnd::Continue,
    }
}

/// Queue the next plaintext LL fragment of the Host ACL packet.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
fn queue_next_host_fragment<H: LinkHost, E: AesEngine>(host: &mut H, s: &mut Session<E>) {
    if s.pending_host.is_none() {
        let Some(acl) = host.take_tx_acl() else {
            return;
        };
        if acl.len == 0 {
            let _ = host.ack_tx(acl.tag);
            return;
        }
        host.diag_acl_tx(acl.llid, &acl.bytes[..acl.len]);
        s.pending_host = Some(PendingHost {
            acl,
            offset: 0,
            fragments: 0,
        });
    }
    let max = usize::from(s.link.tx_max_payload());
    let done = {
        let host_pdu = s.pending_host.as_mut().unwrap();
        let remaining = host_pdu.acl.len - host_pdu.offset;
        let n = remaining.min(max);
        let llid = if host_pdu.offset == 0 {
            host_pdu.acl.llid
        } else {
            1
        };
        let start = host_pdu.offset;
        let end = start + n;
        s.link.queue(llid, &host_pdu.acl.bytes[start..end]).unwrap();
        host_pdu.offset = end;
        host_pdu.fragments += 1;
        s.host_fragments += 1;
        if end == host_pdu.acl.len {
            Some((host_pdu.acl.tag, host_pdu.fragments))
        } else {
            None
        }
    };
    if let Some((tag, fragments)) = done {
        if fragments > 1 {
            s.host_packets_segmented += 1;
        }
        s.pending_host = None;
        s.acl_tag = Some(tag);
    }
}

/// Count DLE opcodes seen in a received LL control PDU.
fn note_control_rx<E: AesEngine>(s: &mut Session<E>, payload: &[u8]) {
    match payload.first() {
        Some(0x14) => s.length_req_rx += 1,
        Some(0x15) => s.length_rsp_rx += 1,
        // The peer rejected our LL_LENGTH_REQ.
        Some(0x07) if payload.len() >= 2 && matches!(payload[1], 0x14 | 0x15) => {
            if s.x1_last_error == 0 {
                s.x1_last_error = 0x14;
            }
        }
        _ => {}
    }
}

fn note_tx_pdu<E: AesEngine>(s: &mut Session<E>, len: usize) {
    let len = len as u16;
    s.tx_pdus += 1;
    s.max_tx_pdu = s.max_tx_pdu.max(len);
    if len > LL_LEGACY_PAYLOAD {
        s.tx_over_27 += 1;
    }
}

fn note_rx_pdu<E: AesEngine>(s: &mut Session<E>, len: usize) {
    let len = len as u16;
    s.rx_pdus += 1;
    s.max_rx_pdu = s.max_rx_pdu.max(len);
    if len > LL_LEGACY_PAYLOAD {
        s.rx_over_27 += 1;
    }
}

/// Turn the Host's LTK answer into a session cipher and precompute the
/// encrypted START_ENC_RSP. Runs outside the radio event.
pub fn service_encryption<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    s: &mut Session<E>,
) -> Option<u8> {
    if s.enc.is_some() || s.start.stage() != StartStage::AwaitingKey {
        return None;
    }
    let reply = host.take_ltk_reply()?;
    let ltk = match reply {
        LtkReply::Key(ltk) => ltk,
        LtkReply::Rejected => {
            // Core 5.4 Vol 6 Part B §5.1.4: a negative reply becomes
            // LL_REJECT_IND with 0x06 and the link ends.
            host.sec_error(0x06);
            s.start.abort();
            s.enc_rsp_at = 0;
            s.enc_rsp_queued = false;
            s.pending_control =
                Some(DataPdu::new(3, ControlPdu::reject_ind(0x06).as_bytes()).expect("fits"));
            // End the link only once this PDU is queued and acknowledged.
            s.terminate_after_control = Some(0x06);
            return None;
        }
    };
    host.sec_inc(SEC_LTK_REPLY);
    let session = match s.start.session(&ltk) {
        Ok(session) => session,
        Err(_) => {
            host.sec_error(0x1e);
            return Some(0x1e);
        }
    };
    let engine = host.new_aes(session.key());
    let mut enc = Encryption::new(session, EncRole::Peripheral, engine);
    if s.start.prepare_start_rsp(&mut enc).is_err() {
        host.sec_error(0x1e);
        return Some(0x1e);
    }
    s.enc = Some(enc);
    host.sec_inc(SEC_PREPARED);
    None
}

/// Parse a DLE control PDU outside the response window, then queue its reply.
pub fn service_control<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    s: &mut Session<E>,
    now: u32,
) -> Option<u8> {
    // Never displace a reply the encryption procedure already owns.
    if s.pending_control.is_some() {
        return None;
    }
    let Some(deferred) = s.deferred_control.take() else {
        return None;
    };
    let payload = &deferred.bytes[..usize::from(deferred.len)];
    match s.control.on_pdu(&mut s.conn, payload, LOCAL_VERSION) {
        Ok(action) => {
            // DLE takes effect once the request or response has been received.
            s.apply_data_length(host);
            match action {
                ControlAction::Reply(pdu) => {
                    if pdu.as_bytes().first() == Some(&0x15) {
                        s.length_rsp_tx += 1;
                    }
                    s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                }
                ControlAction::Terminate(reason) => return Some(reason),
                ControlAction::None => {}
            }
        }
        Err(error) => {
            s.x1_last_error = 0x1e;
            s.request_terminate(host, termination_reason(error), now);
        }
    }
    None
}

/// Start DLE from the peripheral side once features are known.
pub fn service_dle<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    s: &mut Session<E>,
) -> Option<u8> {
    // `service_control` may have left a deferred reply in `pending_control`;
    // it owns the next event's TX slot.
    if !s.conn.established()
        || s.link.has_outstanding()
        || s.pending_control.is_some()
        || !s.encryption_idle()
    {
        return None;
    }
    let requested = host.take_data_length_request();
    if let Some((octets, time)) = requested {
        s.control.data_length.set_local_tx(octets, time);
        let pdu = s.control.length_request();
        s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
        s.length_req_tx += 1;
        return None;
    }
    if !s.control.data_length.requested() {
        if let Some(pdu) = s.control.request_length_if_supported() {
            s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
            s.length_req_tx += 1;
            return None;
        }
        if host.allows_feature_request() {
            if let Some(pdu) = s.control.feature_request(true) {
                s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
            }
        }
    }
    None
}

/// Start a Host-requested PHY update once the link can carry a control PDU.
pub fn service_phy<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    s: &mut Session<E>,
) -> Option<u8> {
    // An empty response keeps `has_outstanding` true after every event of a
    // live link, so only a queued control PDU blocks a new request. The TX
    // selector sends it once the peer acknowledges our last packet.
    if !s.conn.established() || s.pending_control.is_some() || !s.encryption_idle() {
        return None;
    }
    // A request that arrives while a procedure is live cannot be queued: the
    // HCI layer should have returned Command Disallowed, but if it did not,
    // end it as a collision instead of silently starting it later.
    if s.control.phy_busy() {
        if host.take_phy_request().is_some() {
            host.phy_update_complete(0x2a, phy_code(s.conn.tx_phy()), phy_code(s.conn.rx_phy()));
        }
        return None;
    }
    if !s.control.phy_supported() {
        // No advertised 2M bit: end the request instead of leaving it queued
        // forever behind a procedure that can never start.
        if host.take_phy_request().is_some() {
            host.phy_update_complete(0x1f, phy_code(s.conn.tx_phy()), phy_code(s.conn.rx_phy()));
        }
        return None;
    }
    let (tx, rx) = host.take_phy_request()?;
    if let Some(pdu) = s.control.start_phy_request(tx, rx) {
        s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
    }
    None
}

/// Report a PHY completion that is not tied to an Instant (collision).
fn service_phy_report<E: AesEngine, H: LinkHost<Aes = E>>(host: &mut H, s: &mut Session<E>) {
    if let Some(status) = s.control.take_phy_status() {
        host.phy_update_complete(status, phy_code(s.conn.tx_phy()), phy_code(s.conn.rx_phy()));
    }
}

/// Produce at most one prepared ciphertext PDU before the next event.
pub fn prefetch_encrypted<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    s: &mut Session<E>,
) -> Option<u8> {
    if !s.enc_active || s.pending_enc_control.is_some() || s.pending_enc_acl.is_some() {
        return None;
    }
    let enc = s.enc.as_mut()?;
    {
        let mut out = [0u8; MAX_ENCRYPTED];
        let prepared = if let Some(reason) = s.terminate_requested.take() {
            Some((enc.encrypt(3, &[2, reason], &mut out), Some(reason)))
        } else if let Some(pdu) = s.pending_control.take() {
            Some((enc.encrypt(3, pdu.payload(), &mut out), None))
        } else {
            None
        };
        if let Some((result, terminate)) = prepared {
            match result {
                Ok(len) => {
                    s.pending_enc_control = Some(EncTx {
                        llid: 3,
                        bytes: out,
                        len: len as u8,
                        tag: None,
                        terminate,
                    });
                }
                Err(_) => {
                    host.sec_error(0x1e);
                    return Some(0x1e);
                }
            }
        }
    }
    if s.pending_enc_control.is_none() && s.pending_enc_acl.is_none() {
        if s.pending_host.is_none() {
            if let Some(acl) = host.take_tx_acl() {
                if acl.len == 0 {
                    let _ = host.ack_tx(acl.tag);
                } else {
                    host.diag_acl_tx(acl.llid, &acl.bytes[..acl.len]);
                    s.pending_host = Some(PendingHost {
                        acl,
                        offset: 0,
                        fragments: 0,
                    });
                }
            }
        }
        // The MIC lives inside the negotiated on-air limit.
        let max_plain = usize::from(s.link.tx_max_payload()).saturating_sub(BLE_MIC_LEN);
        let prepared = if let Some(host_pdu) = s.pending_host.as_mut() {
            let remaining = host_pdu.acl.len - host_pdu.offset;
            let n = remaining.min(max_plain);
            let llid = if host_pdu.offset == 0 {
                host_pdu.acl.llid
            } else {
                1
            };
            let start = host_pdu.offset;
            let end = start + n;
            let mut out = [0u8; MAX_ENCRYPTED];
            match enc.encrypt(llid, &host_pdu.acl.bytes[start..end], &mut out) {
                Ok(len) => Some((
                    llid,
                    out,
                    len,
                    if end == host_pdu.acl.len {
                        Some(host_pdu.acl.tag)
                    } else {
                        None
                    },
                    end,
                    host_pdu.fragments + 1,
                )),
                Err(_) => {
                    host.sec_error(0x1e);
                    return Some(0x1e);
                }
            }
        } else {
            None
        };
        if let Some((llid, out, len, tag, offset, fragments)) = prepared {
            s.pending_enc_acl = Some(EncTx {
                llid,
                bytes: out,
                len: len as u8,
                tag,
                terminate: None,
            });
            if let Some(host_pdu) = s.pending_host.as_mut() {
                host_pdu.offset = offset;
                host_pdu.fragments = fragments;
            }
            s.host_fragments += 1;
            if tag.is_some() {
                if fragments > 1 {
                    s.host_packets_segmented += 1;
                }
                s.pending_host = None;
            }
        }
    }
    None
}

/// Decrypt the PDU deferred by the last event and dispatch it. MIC failure
/// terminates the link with reason 0x3d, per Core 5.4 Vol 6 Part E.
pub fn finish_deferred<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    s: &mut Session<E>,
) -> Option<u8> {
    let rx = s.deferred_rx.take()?;
    let mut plain = [0u8; MAX_PLAINTEXT];
    let payload = &rx.payload[..usize::from(rx.len)];
    let len = {
        let enc = s.enc.as_mut()?;
        match enc.decrypt(rx.header, payload, &mut plain) {
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
        }
    };
    host.sec_inc(SEC_ENCRYPTED_RX);
    let llid = rx.header & 3;
    if !s.enc_active {
        // The link's first encrypted PDU must be the Central's START_ENC_RSP;
        // our own encrypted response is queued for the next event.
        if llid == 3 && len == 1 && plain[0] == 0x06 {
            match s.start.on_start_enc_rsp() {
                Ok(bytes) => {
                    let mut out = [0u8; MAX_ENCRYPTED];
                    out[..bytes.len()].copy_from_slice(bytes);
                    s.pending_start_rsp = Some(EncTx {
                        llid: 3,
                        bytes: out,
                        len: bytes.len() as u8,
                        tag: None,
                        terminate: None,
                    });
                    return None;
                }
                Err(_) => {
                    host.sec_error(0x1e);
                    return Some(0x1e);
                }
            }
        }
        host.sec_error(0x1e);
        return Some(0x1e);
    }
    match llid {
        3 => {
            host.stat_put(STAT_LAST_CONTROL, u32::from(plain[0]));
            host.diag_control_opcode(plain[0]);
            note_control_rx(s, &plain);
            match s.control.on_pdu(&mut s.conn, &plain[..len], LOCAL_VERSION) {
                Ok(action) => {
                    // DLE takes effect once the request or response has been
                    // received.
                    s.apply_data_length(host);
                    match action {
                        ControlAction::Reply(pdu) => {
                            if pdu.as_bytes().first() == Some(&7) {
                                host.stat_inc(STAT_UNKNOWN_RSP);
                            }
                            if pdu.as_bytes().first() == Some(&0x15) {
                                s.length_rsp_tx += 1;
                            }
                            s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                        }
                        ControlAction::Terminate(reason) => {
                            s.request_terminate(host, reason, rx.end)
                        }
                        ControlAction::None => {
                            if plain[0] == 0 && len == 12 {
                                s.update_instant = Some(u16::from_le_bytes([plain[10], plain[11]]));
                            }
                        }
                    }
                }
                Err(error) => {
                    if matches!(plain.first(), Some(0x14) | Some(0x15)) {
                        s.x1_last_error = 0x1e;
                    }
                    s.request_terminate(host, termination_reason(error), rx.end)
                }
            }
            None
        }
        1 | 2 => {
            // Count ATT/SMP opcodes from the decrypted start fragment.
            host.diag_acl_plain(llid, &plain[..len]);
            if !host.receive_acl(llid, &plain[..len]) {
                host.stat_inc(STAT_BRIDGE_FAIL);
                Some(0x1f)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Stop the RF engine, notify the Host and finish the close bookkeeping.
///
/// Returns false when the engine did not confirm idle: the caller must not
/// publish a disconnect, clear the session or re-arm the radio then.
pub fn close_session<E: AesEngine, H: LinkHost<Aes = E>, R: LinkRadio, C: InstantUs>(
    host: &mut H,
    radio: &mut R,
    clock: &C,
    s: &Session<E>,
    reason: u8,
) -> bool {
    if !radio.stop(clock) {
        return false;
    }
    let duration = clock.now_us().wrapping_sub(s.began);
    if duration > host.stat_get(STAT_MAX_CONNECTION_US) {
        host.stat_put(STAT_MAX_CONNECTION_US, duration);
    }
    host.stat_put(STAT_CLOSE_REASON, u32::from(reason));
    host.trace(
        clock.now_us(),
        6,
        s.conn.event_counter(),
        s.conn.channel(),
        0,
        0,
        u32::from(reason),
        duration,
    );
    host.connection_closed(reason);
    host.after_close();
    true
}

/// Everything that only queues work for the next event: encryption setup,
/// deferred control replies, DLE and prebuilt ciphertext.
fn service_pending<E: AesEngine, H: LinkHost<Aes = E>>(
    host: &mut H,
    s: &mut Session<E>,
    now: u32,
) -> Option<u8> {
    let mut reason = service_encryption(host, s);
    if reason.is_none() {
        reason = service_control(host, s, now);
    }
    // After `service_control`: a deferred 0x16 that collided with our own
    // request must report 0x2A in the same tick.
    service_phy_report(host, s);
    if reason.is_none() {
        reason = service_dle(host, s);
    }
    if reason.is_none() {
        reason = service_phy(host, s);
    }
    if reason.is_none() {
        reason = prefetch_encrypted(host, s);
    }
    reason
}

/// One outer-loop iteration while a session is active.
///
/// Covers the missed-event catch-up, deferred services, the idle gap, the
/// connection event and the shared close. On [`Control::Closed`] the caller
/// drops the session, resets its re-advertise timer and must let the Host
/// re-enable advertising through its own disconnect path.
#[allow(clippy::too_many_arguments)]
pub fn step<E: AesEngine, H: LinkHost<Aes = E>, R: LinkRadio, C: InstantUs>(
    s: &mut Session<E>,
    host: &mut H,
    radio: &mut R,
    clock: &C,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    finish: u32,
) -> Control {
    host.pre_iteration();
    s.event_served = false;
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
                s.request_terminate(host, reason, clock.now_us());
            }
        }
    }
    let mut reason = s.expiration(host, clock.now_us());
    let mut prepare = s.conn.rx_start_us().wrapping_sub(100);
    // A Host poll is non-preemptible, and LESC key agreement blocks the
    // executor for more than a second. Step over missed events instead of
    // transmitting into a window that already closed.
    // Table mode never advances here: a late window reaches the owner as
    // `Decision::Skipped` and `advance_one` steps the counter exactly once.
    while s.advance_owner == AdvanceOwner::SelfRun
        && reached(clock.now_us().wrapping_sub(2_000), prepare)
    {
        if s.conn.next_event().is_err() {
            break;
        }
        host.diag_skipped_event();
        prepare = s.conn.rx_start_us().wrapping_sub(100);
        if reason.is_none() {
            reason = s.expiration(host, clock.now_us());
        }
    }
    // AES-CCM runs only while at least 3 ms remain before RX arming.
    if let Some(req) = s.pending_enc_req.take() {
        let random = s.enc_rsp_random;
        let mut skds = [0u8; 8];
        skds.copy_from_slice(&random[..8]);
        let mut ivs = [0u8; 4];
        ivs.copy_from_slice(&random[8..]);
        match s.start.on_enc_req(&req, skds, ivs) {
            Ok(_) => {
                let parsed = EncReq::parse(&req).unwrap();
                s.pending_ltk = Some((parsed.rand, parsed.ediv));
            }
            Err(_) => {
                host.sec_error(0x1e);
                s.request_terminate(host, 0x1e, clock.now_us());
            }
        }
    }
    if s.enc_rsp_at != 0
        && s.start.stage() != StartStage::Idle
        && reached(clock.now_us(), s.enc_rsp_at)
    {
        s.enc_rsp_at = 0;
        s.pending_control = Some(DataPdu::new(3, &s.enc_rsp_payload).unwrap());
        s.enc_rsp_queued = true;
        host.sec_inc(SEC_ENC_RSP);
    }
    if let Some((rand, ediv)) = s.pending_ltk.take() {
        if host.push_ltk_request(rand, ediv) {
            host.sec_inc(SEC_LTK_REQUEST);
        } else {
            host.sec_error(0x1e);
            s.request_terminate(host, 0x1e, clock.now_us());
        }
    }
    let mut serviced = false;
    if reason.is_none() && !reached(clock.now_us().wrapping_add(4000), prepare) {
        serviced = true;
        reason = service_pending(host, s, clock.now_us());
    }
    if let Some((interval, latency, timeout)) = s.update_report {
        if host.connection_updated(interval, latency, timeout) {
            s.update_report = None;
        }
    }
    // Configure the channel before waiting for RX prepare, not inside the
    // final 100 us RF arming allowance.
    if reason.is_none() && radio.channel() != s.conn.channel() {
        radio.set_channel(s.conn.channel()).unwrap();
    }
    // Advertising between events reprograms the AA/CRC; restore ours before
    // arming, or every later event is heard on the wrong access address.
    if reason.is_none() {
        radio.set_aa_crc(s.conn.params.access_addr, s.conn.params.crc_init);
    }
    if reason.is_none() && !reached(clock.now_us().wrapping_add(2000), prepare) {
        let mut until = earlier(prepare, earlier(finish, s.conn.supervision_deadline_us()));
        if let Some(end) = s.control.termination_deadline_us() {
            until = earlier(until, end);
        }
        host.idle_gap(prepare, until);
        return Control::Continue;
    }
    if reason.is_none() {
        reason = match connection_event(radio, clock, rx, tx, s, host, finish) {
            EventEnd::Continue => {
                s.event_served = true;
                None
            }
            EventEnd::Close(reason) => {
                s.event_served = true;
                Some(reason)
            }
            EventEnd::Stopped => return Control::StopTimeout,
        };
        if s.conn.established() && !s.adv_stopped {
            // Stop the advertising that formed this link once. A Host that
            // keeps a second advertising instance alive re-arms it after the
            // connection; disarming every event would silence that slot.
            s.adv_stopped = true;
            host.disable_adv();
        }
        if reason.is_none() {
            reason = finish_deferred(host, s);
        }
        // A scheduler dispatches `step` once, at the arm boundary, so the
        // 4 ms pre-event pass never runs there. Catch up in the long gap
        // after the event; these services only queue work for the next one.
        if !serviced && reason.is_none() {
            reason = service_pending(host, s, clock.now_us());
        }
        host.publish_x1(&s.x1_snapshot());
        if s.enc_change_pending {
            // Our encrypted START_ENC_RSP is on air: tell the Host the link is
            // encrypted. HCI work stays outside the event.
            s.enc_change_pending = false;
            if let Some(handle) = host.local_handle() {
                host.encryption_change(handle, 0, 1);
            }
        }
    }
    if let Some(reason) = reason {
        if !close_session(host, radio, clock, s, reason) {
            return Control::StopTimeout;
        }
        return Control::Closed(reason);
    }
    Control::Continue
}

pub mod central;
pub mod cp;

#[cfg(test)]
pub(crate) mod tests;
