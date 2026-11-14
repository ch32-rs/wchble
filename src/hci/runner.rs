//! Soft HCI command/ACL pump and bounded single-connection bridge.
//!
//! A cooperative RF owner calls [`SoftRunner::pump_once`] only while idle and
//! synchronizes connection lifecycle through [`SoftRunner::bridge`]. LL radio
//! timing, retransmission and sequence numbers remain outside this module.

use bt_hci::transport::PacketKind;

use crate::crypto::Aes128;
use crate::ll::dle::{LL_LEGACY_PAYLOAD, LL_LEGACY_TIME_US, LL_MAX_PLAINTEXT, LL_MAX_TIME_US};
use crate::ll::{scan, LinkLayer};
use crate::rand::ChaCha20Drbg;

use super::connection::{event_packet, BridgeError, ConnectionBridge};
use super::transport::{self, Packet};

/// HCI success.
const HCI_SUCCESS: u8 = 0x00;
/// Unknown HCI command.
const HCI_UNKNOWN_COMMAND: u8 = 0x01;
/// Invalid HCI command parameters.
const HCI_INVALID_PARAMETERS: u8 = 0x12;
/// Command disallowed.
const HCI_COMMAND_DISALLOWED: u8 = 0x0c;
/// Unknown connection identifier.
const HCI_UNKNOWN_CONNECTION: u8 = 0x02;

/// ACL data packet length reported by `LE Read Buffer Size`: the DLE maximum.
const ACL_DATA_PACKET_LENGTH: u16 = super::connection::ACL_DATA_PACKET_LENGTH as u16;
/// Number of ACL credits advertised to the Host.
const ACL_CREDITS: u8 = super::connection::ACL_CREDITS as u8;

/// Wire-valid ranges for the TX_Octets/TX_Time fields of `LE Set Data Length`
/// and `LE Write Suggested Default Data Length` (Core HCI §7.8.33/§7.8.35):
/// the Host may ask for 27..=251 octets and 328..=17040 us regardless of what
/// this controller implements; the LL negotiation then applies our own limit.
const HCI_MIN_TX_OCTETS: u16 = 27;
const HCI_MAX_TX_OCTETS: u16 = 251;
const HCI_MIN_TX_TIME: u16 = 328;
const HCI_MAX_TX_TIME: u16 = 17040;

/// Default public BD_ADDR placeholder (HAL / OTP can override later).
const DEFAULT_BD_ADDR: [u8; 6] = [0x00, 0x00, 0x00, 0xc1, 0xff, 0xee];

/// Passive-scan configuration accepted from `LE Set Scan Parameters`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanState {
    pub enabled: bool,
    pub active: bool,
    /// HCI units of 0.625 ms.
    pub interval_slots: u16,
    pub window_slots: u16,
    pub filter_duplicates: bool,
}

/// Pending `LE Create Connection` request, consumed by the RF owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnRequest {
    pub peer_addr: [u8; 6],
    pub peer_random: bool,
    pub own_random: bool,
    /// HCI units of 0.625 ms.
    pub scan_interval_slots: u16,
    pub scan_window_slots: u16,
    /// HCI units of 1.25 ms.
    pub interval_min: u16,
    pub interval_max: u16,
    pub latency: u16,
    /// HCI units of 10 ms.
    pub timeout: u16,
    pub min_ce: u16,
    pub max_ce: u16,
}

/// `LE Enable Encryption` request waiting for the RF owner to run the LL
/// start-encryption procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnableEncryption {
    pub handle: u16,
    /// Random number from the Host (zeros for LE Secure Connections).
    pub rand: [u8; 8],
    /// Encrypted diversifier (zero for LE Secure Connections).
    pub ediv: u16,
    pub ltk: [u8; 16],
}

/// Host answer to an `LE LTK Request` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LtkReply {
    Key([u8; 16]),
    Rejected,
}

/// Drains Host→Controller packets and emits Command Complete / Status.
#[derive(Debug)]
pub struct SoftRunner {
    pub ll: LinkLayer,
    pub bridge: ConnectionBridge,
    scan: ScanState,
    pending_connect: Option<CreateConnRequest>,
    adv_reports_dropped: u32,
    pending_reply: Option<Packet>,
    pending_input: Option<(Packet, u32)>,
    reset_pending: bool,
    event_mask: u64,
    le_event_mask: u64,
    bd_addr: [u8; 6],
    /// Address from `LE Set Random Address` / HAL seed; `None` = public BD_ADDR.
    random_addr: Option<[u8; 6]>,
    /// DRBG backing `HCI_LE_Rand` and LL random values.
    drbg: ChaCha20Drbg,
    /// True once a HAL supplied a measured entropy seed.
    entropy_seeded: bool,
    /// Pending `LE Enable Encryption` for the RF owner (Central role), tagged
    /// with the connection epoch that created it.
    pending_encryption: Option<(u32, EnableEncryption)>,
    /// Host answer waiting for the RF owner (Peripheral role), tagged with the
    /// connection epoch that requested it.
    ltk_reply: Option<(u32, LtkReply)>,
    /// LE features advertised both through HCI and LL_FEATURE_RSP.
    le_features: [u8; 8],
    /// Host's `LE Write Suggested Default Data Length` values.
    suggested_tx_octets: u16,
    suggested_tx_time: u16,
    /// True once the Host explicitly set the suggestion; until then the
    /// controller keeps its own larger default for new connections.
    suggested_tx_explicit: bool,
    /// Most recent command that answered with a non-success status:
    /// `(opcode << 8) | status`, for firmware-side diagnostics.
    last_command_failure: Option<u32>,
    /// Newest eight commands, each `(opcode << 8) | status`; the firmware
    /// dumps this to explain a Host that stopped on an HCI error.
    command_log: [u32; 8],
    command_log_len: u32,
    /// Newest eight command responses actually handed to the Host, packed as
    /// `0xE0_0000 | opcode << 8 | status` (Complete) or
    /// `0xF0_0000 | opcode << 8 | status` (Status), with a separate counter so
    /// a dropped or overwritten reply can be told apart from a logged one.
    sent_log: [u32; 8],
    sent_log_len: u32,
}

impl Default for SoftRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftRunner {
    pub fn new() -> Self {
        Self {
            ll: LinkLayer::new(),
            bridge: ConnectionBridge::new(),
            scan: ScanState::default(),
            pending_connect: None,
            adv_reports_dropped: 0,
            pending_reply: None,
            pending_input: None,
            reset_pending: false,
            event_mask: u64::MAX,
            le_event_mask: 0x1f,
            bd_addr: DEFAULT_BD_ADDR,
            random_addr: None,
            drbg: ChaCha20Drbg::from_seed(&[0u8; 32]),
            entropy_seeded: false,
            pending_encryption: None,
            ltk_reply: None,
            le_features: [0; 8],
            suggested_tx_octets: LL_LEGACY_PAYLOAD,
            suggested_tx_time: LL_LEGACY_TIME_US,
            suggested_tx_explicit: false,
            last_command_failure: None,
            command_log: [0; 8],
            command_log_len: 0,
            sent_log: [0; 8],
            sent_log_len: 0,
        }
    }

    /// Opcode and status of the most recent failed HCI command, packed as
    /// `(opcode << 8) | status`.
    pub fn last_command_failure(&self) -> Option<u32> {
        self.last_command_failure
    }

    /// The newest eight commands as `(opcode << 8) | status`, oldest first.
    pub fn command_log(&self) -> [u32; 8] {
        let mut out = [0u32; 8];
        if self.command_log_len < 8 {
            out[..self.command_log_len as usize]
                .copy_from_slice(&self.command_log[..self.command_log_len as usize]);
        } else {
            let start = (self.command_log_len % 8) as usize;
            for i in 0..8 {
                out[i] = self.command_log[(start + i) % 8];
            }
        }
        out
    }

    /// The newest eight command responses handed to the Host, oldest first.
    /// Each is `0xE000_0000 | opcode << 8 | status` for Command Complete and
    /// `0xF000_0000 | opcode << 8 | status` for Command Status.
    pub fn sent_log(&self) -> [u32; 8] {
        let mut out = [0u32; 8];
        if self.sent_log_len < 8 {
            out[..self.sent_log_len as usize]
                .copy_from_slice(&self.sent_log[..self.sent_log_len as usize]);
        } else {
            let start = (self.sent_log_len % 8) as usize;
            for i in 0..8 {
                out[i] = self.sent_log[(start + i) % 8];
            }
        }
        out
    }

    /// Number of commands the runner has answered so far.
    pub fn command_log_len(&self) -> u32 {
        self.command_log_len
    }

    /// Number of command responses handed to the Host so far.
    pub fn sent_log_len(&self) -> u32 {
        self.sent_log_len
    }

    fn log_sent(&mut self, packet: &transport::Packet) {
        let (tag, opcode, status) = match packet.bytes[0] {
            0x0e if packet.len >= 6 => (
                0xE000_0000,
                u16::from_le_bytes([packet.bytes[3], packet.bytes[4]]),
                packet.bytes[5],
            ),
            0x0f if packet.len >= 5 => (
                0xF000_0000,
                u16::from_le_bytes([packet.bytes[3], packet.bytes[4]]),
                packet.bytes[2],
            ),
            _ => return,
        };
        let index = (self.sent_log_len % 8) as usize;
        self.sent_log[index] = tag | (u32::from(opcode) << 8) | u32::from(status);
        self.sent_log_len = self.sent_log_len.wrapping_add(1);
    }

    fn log_command(&mut self, opcode: u16, status: u8) {
        let index = (self.command_log_len % 8) as usize;
        self.command_log[index] = (u32::from(opcode) << 8) | u32::from(status);
        self.command_log_len = self.command_log_len.wrapping_add(1);
        if status != HCI_SUCCESS {
            self.last_command_failure = Some(self.command_log[index]);
        }
    }

    /// Install a 32-byte entropy seed collected by the HAL / series code.
    ///
    /// Returns `false` if `seed` equals the current key (a HAL that failed to
    /// collect fresh entropy must not silently "reseed"). The controller still
    /// answers `HCI_LE_Rand` before this is called, but with a publicly
    /// deterministic stream; [`Self::entropy_seeded`] lets firmware refuse to
    /// claim a secure connection in that state.
    pub fn set_entropy_seed(&mut self, seed: &[u8; 32]) -> bool {
        let installed = self.drbg.reseed(seed);
        if installed {
            self.entropy_seeded = true;
        }
        installed
    }

    /// Whether a measured entropy seed has been installed.
    pub fn entropy_seeded(&self) -> bool {
        self.entropy_seeded
    }

    /// Advertise the LE feature set implemented by this controller build.
    ///
    /// Both `LE Read Local Supported Features` and the LL feature response use
    /// this value. The default is all zero (P3/P4); a build that drives the
    /// start-encryption procedure must set bit 0.
    pub fn set_le_features(&mut self, features: [u8; 8]) {
        self.le_features = features;
    }

    pub fn le_features(&self) -> [u8; 8] {
        self.le_features
    }

    /// Suggested default TX data length last written by the Host.
    pub fn suggested_data_length(&self) -> (u16, u16) {
        (self.suggested_tx_octets, self.suggested_tx_time)
    }

    /// The Host's suggestion, but only once it actually set one. New
    /// connections seed their TX preference from this; the controller's own
    /// default stays in force until then.
    pub fn suggested_data_length_explicit(&self) -> Option<(u16, u16)> {
        self.suggested_tx_explicit
            .then_some((self.suggested_tx_octets, self.suggested_tx_time))
    }

    /// Take a Host `LE Set Data Length` request (`TX_Octets`, `TX_Time`).
    pub fn take_data_length_request(&mut self) -> Option<(u16, u16)> {
        self.bridge.take_data_length_request()
    }

    /// A 32-bit random value for LL use (access address / CRCInit).
    pub fn rand_u32(&mut self) -> u32 {
        self.drbg.next_u32()
    }

    /// Fill `out` from the DRBG for LL_ENC_REQ SKDm/IVm and similar values.
    pub fn fill_random(&mut self, out: &mut [u8]) {
        self.drbg.fill(out);
    }

    /// Take the pending `LE Enable Encryption` request (Central role).
    ///
    /// A request queued on an earlier connection is discarded: every link uses
    /// handle 1, so without the epoch check the RF owner would start encryption
    /// on the new link with the old key material.
    pub fn take_encryption_request(&mut self) -> Option<EnableEncryption> {
        let (epoch, request) = self.pending_encryption.take()?;
        (epoch == self.bridge.epoch()).then_some(request)
    }

    /// Take the Host's answer to an `LE LTK Request` (Peripheral role).
    pub fn take_ltk_reply(&mut self) -> Option<LtkReply> {
        let (epoch, reply) = self.ltk_reply.take()?;
        (epoch == self.bridge.epoch()).then_some(reply)
    }

    /// Drop encryption state when the link is gone or Reset is processed.
    pub fn clear_encryption(&mut self) {
        self.pending_encryption = None;
        self.ltk_reply = None;
    }

    /// Emit `LE LTK Request` for the connected handle. Returns false when the
    /// Host has not enabled the event or the queue is full; the RF owner must
    /// then reject `LL_ENC_REQ` instead of starting encryption.
    pub fn push_ltk_request(&mut self, rand: [u8; 8], ediv: u16) -> bool {
        let Some(handle) = self.bridge.handle() else {
            return false;
        };
        self.bridge.ltk_request(handle, rand, ediv).is_ok()
    }

    /// Report the outcome of the start-encryption procedure.
    ///
    /// `enabled` is the HCI Encryption_Enabled value: 0x00 off, 0x01 on.
    /// Returns false if the handle is gone or the event queue is full.
    pub fn encryption_change(&mut self, handle: u16, status: u8, enabled: u8) -> bool {
        self.bridge
            .encryption_change(handle, status, enabled)
            .is_ok()
    }

    /// Override the public address returned by `Read BD_ADDR`.
    pub fn set_bd_addr(&mut self, addr: [u8; 6]) {
        self.bd_addr = addr;
        if !self.ll.adv.random_addr {
            self.ll.adv.own_addr = addr;
        }
    }

    /// Seed the LE random address used as AdvA when advertising with
    /// Own_Address_Type = Random.
    ///
    /// This is a HAL fallback, not a substitute for HCI: the pinned Trouble
    /// (`ControlRunner::run`) sends `Reset` followed by `LE Set Random Address`
    /// whenever `StackBuilder::set_random_address` was used. Hosts that omit
    /// 0x2005 (or HALs that want an address before Host init) can seed here;
    /// the value is re-applied when `Reset` rebuilds the link layer.
    pub fn set_random_addr(&mut self, addr: [u8; 6]) {
        self.random_addr = Some(addr);
        self.sync_adv_addr();
    }

    /// Point `AdvState` at the selected own address (random if one was set,
    /// otherwise the public BD_ADDR).
    fn sync_adv_addr(&mut self) {
        match self.random_addr {
            Some(addr) => {
                self.ll.adv.own_addr = addr;
                self.ll.adv.random_addr = true;
            }
            None => {
                self.ll.adv.own_addr = self.bd_addr;
                self.ll.adv.random_addr = false;
            }
        }
    }

    /// True while Host has advertising enabled.
    pub fn adv_enabled(&self) -> bool {
        self.ll.adv.enabled
    }

    /// Advertising interval in microseconds (from HCI slots).
    pub fn adv_interval_us(&self) -> u32 {
        self.ll.adv.interval_us()
    }

    /// Channels selected by the current advertising channel map.
    pub fn adv_channels(&self) -> impl Iterator<Item = u8> + '_ {
        self.ll.adv.channels()
    }

    /// Build the current ADV_IND PDU when advertising is enabled.
    pub fn build_adv_pdu(&self, out: &mut [u8]) -> Option<usize> {
        self.ll.adv.build_adv_ind(out)
    }

    pub fn scan_state(&self) -> ScanState {
        self.scan
    }

    pub fn pending_connect(&self) -> Option<CreateConnRequest> {
        self.pending_connect
    }

    /// The RF owner calls this once it has resolved the pending request
    /// (success or initiator timeout) so a later cancel is rejected.
    pub fn clear_pending_connect(&mut self) {
        self.pending_connect = None;
    }

    /// Currently selected own address and whether it is random.
    pub fn own_addr(&self) -> ([u8; 6], bool) {
        (self.ll.adv.own_addr, self.ll.adv.random_addr)
    }

    pub fn adv_reports_dropped(&self) -> u32 {
        self.adv_reports_dropped
    }

    /// Queue one HCI Advertising Report for a CRC-valid legacy PDU.
    /// Returns false when scan is disabled, the type is not reportable, or
    /// the event queue is full. Scan reports are droppable diagnostics.
    pub fn push_adv_report(&mut self, pdu: &scan::Pdu<'_>, rssi: i8) -> bool {
        if !self.scan.enabled || !self.bridge.le_event_enabled(2) {
            return false;
        }
        let event_type = match pdu.pdu_type() {
            scan::PduType::AdvInd => 0x00,
            scan::PduType::AdvDirectInd => 0x01,
            scan::PduType::AdvScanInd => 0x02,
            scan::PduType::AdvNonconnInd => 0x03,
            scan::PduType::ScanRsp => 0x04,
            _ => return false,
        };
        let adv_a = match pdu.adv_a() {
            Some(addr) => *addr,
            None => return false,
        };
        // Advertising Report Data excludes AdvA; ADV_DIRECT_IND carries none.
        let data: &[u8] = match pdu.pdu_type() {
            scan::PduType::AdvInd
            | scan::PduType::AdvScanInd
            | scan::PduType::AdvNonconnInd
            | scan::PduType::ScanRsp => pdu.payload().get(6..).unwrap_or(&[]),
            _ => &[],
        };
        let mut parameters = [0u8; 2 + 10 + scan::MAX_LEGACY_ADV_PAYLOAD];
        parameters[0] = 0x02; // LE Advertising Report
        parameters[1] = 1; // one report
        parameters[2] = event_type;
        parameters[3] = u8::from(pdu.tx_add());
        parameters[4..10].copy_from_slice(&adv_a);
        parameters[10] = data.len() as u8;
        parameters[11..11 + data.len()].copy_from_slice(data);
        parameters[11 + data.len()] = rssi as u8;
        let len = 12 + data.len();
        if !self
            .bridge
            .try_push_event(event_packet(0x3e, &parameters[..len]))
        {
            self.adv_reports_dropped = self.adv_reports_dropped.wrapping_add(1);
            return false;
        }
        true
    }

    /// Bounded, non-blocking idle-time pump. It never borrows the RF owner
    /// across an await, and retains owned input/output packets under backpressure.
    pub fn pump_once(&mut self) -> bool {
        let mut progressed = false;
        if self.reset_pending && self.bridge.take_reset_done() {
            self.finish_reset();
            progressed = true;
        }
        if let Some(reply) = self.pending_reply {
            if transport::try_send_controller_packet(reply).is_err() {
                return progressed;
            }
            self.log_sent(&reply);
            self.pending_reply = None;
            return true;
        }
        if self.reset_pending {
            return progressed;
        }
        // One output at most, with lifecycle events ahead of ACL data.
        if self.bridge.flush_one() {
            return true;
        }
        let input = self
            .pending_input
            .take()
            .filter(|(_, epoch)| *epoch == self.bridge.epoch());
        let Some((packet, epoch)) = input.or_else(|| {
            transport::try_receive_host_packet().map(|packet| (packet, self.bridge.epoch()))
        }) else {
            return progressed;
        };
        match packet.kind {
            PacketKind::Cmd => self.handle_command(packet.payload()),
            PacketKind::AclData => {
                if self.bridge.enqueue_tx(&packet) == Err(BridgeError::Full) {
                    self.pending_input = Some((packet, epoch));
                    return progressed;
                }
            }
            _ => {}
        }
        if let Some(reply) = self.pending_reply {
            if transport::try_send_controller_packet(reply).is_ok() {
                self.log_sent(&reply);
                self.pending_reply = None;
            }
        }
        true
    }

    /// Compatibility entry point for existing cooperative async callers.
    pub async fn poll_once(&mut self) -> bool {
        self.pump_once()
    }

    /// Legacy advertising-only async service. Connected RF applications use
    /// pump_once at idle boundaries instead of holding this future across RF.
    pub async fn serve_one(&mut self) {
        loop {
            let progressed = self.pump_once();
            if self.pending_reply.is_some() || self.bridge.has_output() {
                transport::wait_for_output_space().await;
            } else if progressed {
                return;
            } else {
                transport::wait_for_host_packet().await;
            }
        }
    }

    pub async fn run(&mut self) -> ! {
        loop {
            self.serve_one().await;
        }
    }

    fn finish_reset(&mut self) {
        self.reset_pending = false;
        self.pending_input = None;
        self.event_mask = u64::MAX;
        self.le_event_mask = 0x1f;
        self.bridge.set_masks(self.event_mask, self.le_event_mask);
        // ChSel is a controller capability configured by the RF owner, not
        // HCI state. The Host sends Reset before advertising; losing it here
        // silently downgrades every link to CSA #1.
        let adv_chsel = self.ll.adv.chsel;
        self.ll = LinkLayer::new();
        self.ll.adv.chsel = adv_chsel;
        self.scan = ScanState::default();
        self.pending_connect = None;
        self.clear_encryption();
        self.suggested_tx_octets = LL_LEGACY_PAYLOAD;
        self.suggested_tx_time = LL_LEGACY_TIME_US;
        self.suggested_tx_explicit = false;
        if self.random_addr.is_some() {
            self.sync_adv_addr();
        }
        self.pending_reply = Some(transport::command_complete_packet(0x0c03, HCI_SUCCESS, &[]));
    }

    fn handle_command(&mut self, bytes: &[u8]) {
        if bytes.len() < 3 || bytes.len() != 3 + usize::from(bytes[2]) {
            return;
        }
        let opcode = u16::from_le_bytes([bytes[0], bytes[1]]);
        let params = &bytes[3..];

        // Async commands answer with Command Status, not Complete.
        match opcode {
            0x0406 => {
                let status = if params.len() != 3
                    || !matches!(params[2], 0x05 | 0x13 | 0x14 | 0x15 | 0x1a | 0x29 | 0x3b)
                {
                    HCI_INVALID_PARAMETERS
                } else {
                    self.bridge
                        .request_disconnect(u16::from_le_bytes([params[0], params[1]]), params[2])
                };
                self.log_command(opcode, status);
                self.pending_reply = Some(transport::command_status_packet(opcode, status));
                return;
            }
            0x200d => {
                let status = self.create_connection(params);
                self.log_command(opcode, status);
                self.pending_reply = Some(transport::command_status_packet(opcode, status));
                return;
            }
            0x2013 => {
                self.log_command(opcode, HCI_COMMAND_DISALLOWED);
                self.pending_reply = Some(transport::command_status_packet(
                    opcode,
                    HCI_COMMAND_DISALLOWED,
                ));
                return;
            }
            0x2019 => {
                let status = self.enable_encryption(params);
                self.log_command(opcode, status);
                self.pending_reply = Some(transport::command_status_packet(opcode, status));
                return;
            }
            0x0c03 if params.is_empty() => {
                if self.bridge.is_connected() || self.ll.adv.enabled {
                    self.reset_pending = true;
                    self.bridge.request_reset();
                } else {
                    self.bridge.request_reset();
                    self.bridge.reset_finished();
                    self.bridge.take_reset_done();
                    self.finish_reset();
                }
                return;
            }
            _ => {}
        }

        // Own the address while the command handler mutates advertising state.
        let bd_addr = self.bd_addr;

        let result: Result<&[u8], u8> = match opcode {
            // Set Event Mask / LE Set Event Mask
            0x0c01 | 0x2001 if params.len() == 8 => {
                let mask = u64::from_le_bytes(params.try_into().unwrap());
                if opcode == 0x0c01 {
                    self.event_mask = mask;
                } else {
                    self.le_event_mask = mask;
                }
                self.bridge.set_masks(self.event_mask, self.le_event_mask);
                Ok(&[][..])
            }
            // Set Event Mask Page 2
            0x0c63 if params.len() == 8 => Ok(&[][..]),
            // Set Controller To Host Flow Control — only "off" accepted.
            0x0c31 if params == [0] => Ok(&[][..]),
            0x0c31 => Err(HCI_INVALID_PARAMETERS),
            // Host Buffer Size — accept and ignore (no C→H flow control).
            0x0c33 if params.len() == 7 => Ok(&[][..]),
            // Host Number Of Completed Packets — accept empty work.
            0x0c35 => Ok(&[][..]),
            // Read BD_ADDR
            0x1009 if params.is_empty() => Ok(&bd_addr[..]),
            // Read RSSI — no connection; disallowed until Phase C.
            0x1405 => Err(HCI_COMMAND_DISALLOWED),
            // LE Read Buffer Size (v1)
            0x2002 if params.is_empty() => {
                let [lo, hi] = ACL_DATA_PACKET_LENGTH.to_le_bytes();
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    HCI_SUCCESS,
                    &[lo, hi, ACL_CREDITS],
                ));
                return;
            }
            // Features implemented by this controller build (bit 0 = LE
            // Encryption when the RF owner drives the start procedure).
            0x2003 if params.is_empty() => {
                let features = self.le_features;
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    HCI_SUCCESS,
                    &features,
                ));
                return;
            }
            // LE Set Data Length: the RF owner performs LL_LENGTH_REQ.
            0x2022 if params.len() == 6 => {
                let handle = u16::from_le_bytes([params[0], params[1]]);
                let octets = u16::from_le_bytes([params[2], params[3]]);
                let time = u16::from_le_bytes([params[4], params[5]]);
                let status = if !(HCI_MIN_TX_OCTETS..=HCI_MAX_TX_OCTETS).contains(&octets)
                    || !(HCI_MIN_TX_TIME..=HCI_MAX_TX_TIME).contains(&time)
                {
                    HCI_INVALID_PARAMETERS
                } else {
                    self.bridge.request_data_length(handle, octets, time)
                };
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    status,
                    &[params[0], params[1]],
                ));
                return;
            }
            // LE Read Suggested Default Data Length.
            0x2023 if params.is_empty() => {
                let octets = self.suggested_tx_octets.to_le_bytes();
                let time = self.suggested_tx_time.to_le_bytes();
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    HCI_SUCCESS,
                    &[octets[0], octets[1], time[0], time[1]],
                ));
                return;
            }
            // LE Write Suggested Default Data Length.
            0x2024 if params.len() == 4 => {
                let octets = u16::from_le_bytes([params[0], params[1]]);
                let time = u16::from_le_bytes([params[2], params[3]]);
                let status = if (HCI_MIN_TX_OCTETS..=HCI_MAX_TX_OCTETS).contains(&octets)
                    && (HCI_MIN_TX_TIME..=HCI_MAX_TX_TIME).contains(&time)
                {
                    self.suggested_tx_octets = octets;
                    self.suggested_tx_time = time;
                    self.suggested_tx_explicit = true;
                    HCI_SUCCESS
                } else {
                    HCI_INVALID_PARAMETERS
                };
                self.pending_reply = Some(transport::command_complete_packet(opcode, status, &[]));
                return;
            }
            // LE Read Maximum Data Length. The fields are payload octets, so
            // the 251-octet air ceiling minus the MIC is what we can grant.
            0x202f if params.is_empty() => {
                let octets = LL_MAX_PLAINTEXT.to_le_bytes();
                let time = LL_MAX_TIME_US.to_le_bytes();
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    HCI_SUCCESS,
                    &[
                        octets[0], octets[1], time[0], time[1], octets[0], octets[1], time[0],
                        time[1],
                    ],
                ));
                return;
            }
            // LE Read Buffer Size v2: no ISO buffers.
            0x2060 if params.is_empty() => {
                let [lo, hi] = ACL_DATA_PACKET_LENGTH.to_le_bytes();
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    HCI_SUCCESS,
                    &[lo, hi, ACL_CREDITS, 0, 0, 0],
                ));
                return;
            }
            // LE Set Random Address
            0x2005 if params.len() == 6 => {
                if self.ll.adv.enabled {
                    Err(HCI_COMMAND_DISALLOWED)
                } else {
                    self.set_random_addr(params.try_into().unwrap());
                    Ok(&[][..])
                }
            }
            // LE Set Advertising Parameters (store interval / channel map only).
            0x2006 if params.len() == 15 => self.set_adv_params(params),
            // LE Set Advertising Data
            0x2008 if params.len() == 32 => {
                if self.ll.adv.enabled {
                    Err(HCI_COMMAND_DISALLOWED)
                } else if self.ll.adv.set_adv_data(params[0], &params[1..]) {
                    Ok(&[][..])
                } else {
                    Err(HCI_INVALID_PARAMETERS)
                }
            }
            // LE Set Scan Response Data
            0x2009 if params.len() == 32 => {
                if self.ll.adv.enabled {
                    Err(HCI_COMMAND_DISALLOWED)
                } else if self.ll.adv.set_scan_rsp(params[0], &params[1..]) {
                    Ok(&[][..])
                } else {
                    Err(HCI_INVALID_PARAMETERS)
                }
            }
            // LE Set Advertise Enable
            0x200a if params.len() == 1 && params[0] <= 1 => {
                let enable = params[0] != 0;
                if enable {
                    // Resolve AdvA right before use; 0x2005 normally did this
                    // already, but Hosts may skip it.
                    self.sync_adv_addr();
                }
                self.ll.adv.enabled = enable;
                Ok(&[][..])
            }
            // LE Set Scan Parameters — passive only.
            0x200b if params.len() == 7 => self.set_scan_params(params),
            // LE Set Scan Enable
            0x200c if params.len() == 2 && params.iter().all(|value| *value <= 1) => {
                let enable = params[0] != 0;
                if enable && (self.bridge.is_connected() || self.pending_connect.is_some()) {
                    self.reply_status(opcode, HCI_COMMAND_DISALLOWED);
                    return;
                }
                if enable {
                    self.sync_adv_addr();
                }
                self.scan.enabled = enable;
                self.scan.filter_duplicates = params[1] != 0;
                Ok(&[][..])
            }
            // LE Create Connection Cancel
            0x200e if params.is_empty() => {
                if self.pending_connect.take().is_none() {
                    self.reply_status(opcode, HCI_COMMAND_DISALLOWED);
                    return;
                }
                let _ = self.bridge.connection_failed(0x02);
                Ok(&[][..])
            }
            // Filter Accept List size / clear / add — report empty list.
            0x200f if params.is_empty() => Ok(&[0][..]),
            0x2010 if params.is_empty() => Ok(&[][..]),
            0x2011 => Err(HCI_COMMAND_DISALLOWED),
            // Resolving list and privacy: accepted but not implemented.
            //
            // The controller never generates or resolves RPAs yet (S4), and
            // the examples use a static random address. Trouble's `security`
            // feature still issues the full startup sync, so answer success
            // while keeping the list logically empty. HCI commands:
            // 0x2027 add, 0x2028 remove, 0x2029 clear, 0x202A read size,
            // 0x202D address resolution enable, 0x202E RPA timeout,
            // 0x204E privacy mode.
            0x2027 if params.len() == 39 => Ok(&[][..]),
            0x2028 if params.len() == 7 => Ok(&[][..]),
            0x2029 if params.is_empty() => Ok(&[][..]),
            0x202a if params.is_empty() => Ok(&[0][..]),
            0x202d if params.len() == 1 && params[0] <= 1 => Ok(&[][..]),
            0x202e if params.len() == 2 => Ok(&[][..]),
            0x204e if params.len() == 8 => Ok(&[][..]),
            0x2027 | 0x2028 | 0x202d | 0x202e | 0x204e => Err(HCI_INVALID_PARAMETERS),
            // LE Encrypt — one AES-128 block, software engine (Host utility;
            // not on the connection timing path).
            0x2017 if params.len() == 32 => {
                // HCI carries 128-bit values least-significant-octet first,
                // while the AES block is big-endian: reverse in, reverse out.
                let mut key = [0u8; 16];
                key.copy_from_slice(&params[..16]);
                key.reverse();
                let mut block = [0u8; 16];
                block.copy_from_slice(&params[16..32]);
                block.reverse();
                Aes128::new(&key).encrypt_block(&mut block);
                block.reverse();
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    HCI_SUCCESS,
                    &block,
                ));
                return;
            }
            0x2017 => Err(HCI_INVALID_PARAMETERS),
            // LE LTK Request Reply / Negative Reply (Peripheral role). Both
            // return the connection handle in the Command Complete parameters
            // (Core 5.4 Vol 4 Part E §7.8.25/26); a Host that cannot decode it
            // reports `Invalid HCI Command Parameters` even on success.
            0x201a if params.len() == 18 => {
                if self.bridge.handle() != Some(le16_from(params)) {
                    Err(HCI_UNKNOWN_CONNECTION)
                } else {
                    let mut ltk = [0u8; 16];
                    ltk.copy_from_slice(&params[2..18]);
                    self.ltk_reply = Some((self.bridge.epoch(), LtkReply::Key(ltk)));
                    Ok(&params[..2])
                }
            }
            0x201a => Err(HCI_INVALID_PARAMETERS),
            0x201b if params.len() == 2 => {
                if self.bridge.handle() != Some(le16_from(params)) {
                    Err(HCI_UNKNOWN_CONNECTION)
                } else {
                    self.ltk_reply = Some((self.bridge.epoch(), LtkReply::Rejected));
                    Ok(&params[..2])
                }
            }
            0x201b => Err(HCI_INVALID_PARAMETERS),
            // LE Rand — DRBG output; the HAL seeds it from measured entropy.
            0x2018 if params.is_empty() => {
                let mut rand = [0u8; 8];
                self.drbg.fill(&mut rand);
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    HCI_SUCCESS,
                    &rand,
                ));
                return;
            }
            // LE Set Ext Advertising / Scan Enable — legacy-only controller.
            0x2039 | 0x2042 => Err(HCI_COMMAND_DISALLOWED),
            _ => Err(HCI_UNKNOWN_COMMAND),
        };

        let status = match &result {
            Ok(_) => HCI_SUCCESS,
            Err(status) => *status,
        };
        self.log_command(opcode, status);
        self.pending_reply = Some(match result {
            Ok(return_data) => transport::command_complete_packet(opcode, HCI_SUCCESS, return_data),
            Err(status) => transport::command_complete_packet(opcode, status, &[]),
        });
    }

    fn set_adv_params(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        if self.ll.adv.enabled {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        let min = u16::from_le_bytes([params[0], params[1]]);
        let max = u16::from_le_bytes([params[2], params[3]]);
        if !(0x20..=0x4000).contains(&min) || !(min..=0x4000).contains(&max) {
            return Err(HCI_INVALID_PARAMETERS);
        }
        // ADV_IND + random own address + channel map only — match rusted-ch5 checks.
        if params[4] != 0
            || params[5] != 1
            || params[14] != 0
            || params[13] == 0
            || params[13] & !7 != 0
        {
            return Err(HCI_INVALID_PARAMETERS);
        }
        self.ll.adv.interval_slots = min;
        self.ll.adv.channel_map = params[13];
        Ok(&[])
    }

    fn reply_status(&mut self, opcode: u16, status: u8) {
        self.pending_reply = Some(transport::command_status_packet(opcode, status));
    }

    fn set_scan_params(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        let scan_type = params[0];
        let interval = u16::from_le_bytes([params[1], params[2]]);
        let window = u16::from_le_bytes([params[3], params[4]]);
        if scan_type > 1
            || !(0x0004..=0x4000).contains(&interval)
            || !(0x0004..=0x4000).contains(&window)
            || window > interval
            || params[5] > 1
            || params[6] > 3
        {
            return Err(HCI_INVALID_PARAMETERS);
        }
        if scan_type == 1 {
            // Active scanning needs SCAN_REQ pacing that this probe does not
            // implement; reject it rather than silently scanning passively.
            return Err(HCI_INVALID_PARAMETERS);
        }
        self.scan.active = false;
        self.scan.interval_slots = interval;
        self.scan.window_slots = window;
        Ok(&[])
    }

    fn create_connection(&mut self, params: &[u8]) -> u8 {
        if params.len() != 25 {
            return HCI_INVALID_PARAMETERS;
        }
        if self.bridge.is_connected() || self.pending_connect.is_some() {
            return HCI_COMMAND_DISALLOWED;
        }
        let le16 = |index: usize| u16::from_le_bytes([params[index], params[index + 1]]);
        let scan_interval = le16(0);
        let scan_window = le16(2);
        let filter_policy = params[4];
        let peer_kind = params[5];
        let own_kind = params[12];
        let interval_min = le16(13);
        let interval_max = le16(15);
        let latency = le16(17);
        let timeout = le16(19);
        if filter_policy > 1
            || peer_kind > 1
            || own_kind > 1
            || !(0x0004..=0x4000).contains(&scan_interval)
            || !(0x0004..=0x4000).contains(&scan_window)
            || scan_window > scan_interval
            || !(0x0006..=0x0c80).contains(&interval_min)
            || interval_max < interval_min
            || interval_max > 0x0c80
            || latency > 499
            || !(0x000a..=0x0c80).contains(&timeout)
            || u32::from(timeout) * 10_000
                <= 2 * u32::from(latency + 1) * u32::from(interval_max) * 1250
        {
            return HCI_INVALID_PARAMETERS;
        }
        let mut peer_addr = [0; 6];
        peer_addr.copy_from_slice(&params[6..12]);
        self.pending_connect = Some(CreateConnRequest {
            peer_addr,
            peer_random: peer_kind == 1,
            own_random: own_kind == 1,
            scan_interval_slots: scan_interval,
            scan_window_slots: scan_window,
            interval_min,
            interval_max,
            latency,
            timeout,
            min_ce: le16(21),
            max_ce: le16(23),
        });
        // Initiating replaces scanning on the radio owner.
        self.scan.enabled = false;
        HCI_SUCCESS
    }

    fn enable_encryption(&mut self, params: &[u8]) -> u8 {
        // Connection_Handle 2 + Random_Number 8 + Encrypted_Diversifier 2 +
        // Long_Term_Key 16 = 28 octets (Core 5.4 Vol 4 Part E §7.8.24).
        if params.len() != 28 {
            return HCI_INVALID_PARAMETERS;
        }
        let handle = le16_from(params);
        if self.bridge.handle() != Some(handle) || self.bridge.is_disconnecting() {
            return HCI_UNKNOWN_CONNECTION;
        }
        // Only the Central starts encryption; a Peripheral waits for
        // LL_ENC_REQ and raises LE LTK Request instead.
        if self.bridge.role() != Some(crate::ll::Role::Central) {
            return HCI_COMMAND_DISALLOWED;
        }
        // A request left over from an earlier connection must not block this
        // one; overwrite it with the current epoch.
        if self
            .pending_encryption
            .is_some_and(|(epoch, _)| epoch == self.bridge.epoch())
        {
            return HCI_COMMAND_DISALLOWED;
        }
        let mut rand = [0u8; 8];
        rand.copy_from_slice(&params[2..10]);
        let mut ltk = [0u8; 16];
        ltk.copy_from_slice(&params[12..28]);
        self.pending_encryption = Some((
            self.bridge.epoch(),
            EnableEncryption {
                handle,
                rand,
                ediv: u16::from_le_bytes([params[10], params[11]]),
                ltk,
            },
        ));
        HCI_SUCCESS
    }
}

fn le16_from(params: &[u8]) -> u16 {
    u16::from_le_bytes([params[0], params[1]])
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use bt_hci::transport::PacketKind;
    use std::sync::{Mutex, OnceLock};

    /// Global HCI channels are shared; serialize tests that touch them.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn inject_cmd(opcode: u16, params: &[u8]) {
        let mut bytes = [0u8; transport::HCI_PACKET_CAPACITY];
        bytes[0..2].copy_from_slice(&opcode.to_le_bytes());
        bytes[2] = params.len() as u8;
        bytes[3..3 + params.len()].copy_from_slice(params);
        let packet = Packet::from_bytes(PacketKind::Cmd, &bytes[..3 + params.len()]).unwrap();
        transport::try_send_host_packet(packet).unwrap();
    }

    fn expect_command_complete(opcode: u16, status: u8, return_data: &[u8]) {
        let packet = transport::try_receive_controller_packet().expect("missing CC");
        assert_eq!(packet.kind, PacketKind::Event);
        let payload = packet.payload();
        assert_eq!(payload[0], 0x0e);
        assert_eq!(payload[1] as usize, 4 + return_data.len());
        assert_eq!(payload[2], 1);
        assert_eq!(u16::from_le_bytes([payload[3], payload[4]]), opcode);
        assert_eq!(payload[5], status);
        assert_eq!(&payload[6..6 + return_data.len()], return_data);
    }

    #[test]
    fn set_random_addr_survives_reset() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let addr = [0x42, 0x00, 0x00, 0xEE, 0xFF, 0xC1];
        runner.set_random_addr(addr);

        pollster::block_on(async {
            inject_cmd(0x0c03, &[]);
            runner.serve_one().await;
            expect_command_complete(0x0c03, HCI_SUCCESS, &[]);
        });

        assert_eq!(runner.ll.adv.own_addr, addr);
        assert!(runner.ll.adv.random_addr);
    }

    #[test]
    fn reset_and_read_bd_addr_roundtrip() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_bd_addr([1, 2, 3, 4, 5, 6]);

        pollster::block_on(async {
            inject_cmd(0x0c03, &[]);
            runner.serve_one().await;
            expect_command_complete(0x0c03, HCI_SUCCESS, &[]);

            inject_cmd(0x1009, &[]);
            runner.serve_one().await;
            expect_command_complete(0x1009, HCI_SUCCESS, &[1, 2, 3, 4, 5, 6]);
        });
    }

    #[test]
    fn reset_keeps_configured_advertising_chsel() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.ll.adv.chsel = true;
        runner.finish_reset();
        // The Host resets the controller before it advertises. ChSel is a
        // controller capability, so Reset must not silently select CSA #1.
        assert!(runner.ll.adv.chsel);
        transport::drain_channels_for_test();
    }

    #[test]
    fn le_set_adv_data_builds_pdu() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            // Random address + params + AdvData + enable.
            inject_cmd(0x2005, &[0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x01]);
            runner.serve_one().await;
            expect_command_complete(0x2005, HCI_SUCCESS, &[]);

            let mut params = [0u8; 15];
            params[0..2].copy_from_slice(&0x00a0u16.to_le_bytes()); // 100 ms
            params[2..4].copy_from_slice(&0x00a0u16.to_le_bytes());
            params[4] = 0; // ADV_IND
            params[5] = 1; // random own
            params[13] = 0x07; // 37/38/39
            inject_cmd(0x2006, &params);
            runner.serve_one().await;
            expect_command_complete(0x2006, HCI_SUCCESS, &[]);

            let mut adv = [0u8; 32];
            adv[0] = 3;
            adv[1..4].copy_from_slice(&[0x02, 0x01, 0x06]);
            inject_cmd(0x2008, &adv);
            runner.serve_one().await;
            expect_command_complete(0x2008, HCI_SUCCESS, &[]);

            inject_cmd(0x200a, &[1]);
            runner.serve_one().await;
            expect_command_complete(0x200a, HCI_SUCCESS, &[]);

            assert!(runner.adv_enabled());
            let mut chs = [0u8; 3];
            let mut n = 0;
            for ch in runner.adv_channels() {
                chs[n] = ch;
                n += 1;
            }
            assert_eq!(&chs[..n], &[37, 38, 39]);
            let mut pdu = [0u8; 40];
            let n = runner.build_adv_pdu(&mut pdu).unwrap();
            assert_eq!(n, 2 + 6 + 3);
            assert_eq!(pdu[0], 0x40);
            assert_eq!(&pdu[2..8], &[0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x01]);
            assert_eq!(&pdu[8..11], &[0x02, 0x01, 0x06]);
        });
    }

    fn connection_info() -> super::super::connection::ConnectionInfo {
        super::super::connection::ConnectionInfo {
            handle: 1,
            role: crate::ll::Role::Peripheral,
            peer_address_type: 1,
            peer_address: [1, 2, 3, 4, 5, 0xc6],
            interval: 24,
            latency: 0,
            supervision_timeout: 200,
            master_clock_accuracy: 0,
        }
    }

    fn acl(handle: u16, pb: u16, data: &[u8]) -> Packet {
        let mut packet = Packet::empty(PacketKind::AclData);
        packet.bytes[..2].copy_from_slice(&(handle | (pb << 12)).to_le_bytes());
        packet.bytes[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        packet.bytes[4..4 + data.len()].copy_from_slice(data);
        packet.len = data.len() + 4;
        packet
    }

    fn open(runner: &mut SoftRunner) {
        runner.bridge.connected(connection_info()).unwrap();
        assert!(runner.pump_once());
        let event = transport::try_receive_controller_packet().unwrap();
        assert_eq!(&event.payload()[..3], &[0x3e, 19, 1]);
        assert_eq!(&event.payload()[4..8], &[1, 0, 1, 1]);
    }

    #[test]
    fn acl_five_real_slots_and_more_than_five_credit_cycles() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        for cycle in 0..4 {
            for n in 0..5 {
                runner
                    .bridge
                    .enqueue_tx(&acl(1, n % 2, &[cycle as u8; 251]))
                    .unwrap();
            }
            assert_eq!(
                runner.bridge.enqueue_tx(&acl(1, 0, &[0])),
                Err(BridgeError::Full)
            );
            let mut tags = [None; 5];
            for (n, tag) in tags.iter_mut().enumerate() {
                let tx = runner.bridge.take_tx_acl().unwrap();
                assert_eq!(tx.llid, if n % 2 == 0 { 2 } else { 1 });
                assert_eq!(tx.len, 251);
                assert_eq!(&tx.bytes[..tx.len], &[cycle as u8; 251]);
                *tag = Some(tx.tag);
            }
            assert!(runner.bridge.take_tx_acl().is_none());
            assert_eq!(
                runner.bridge.enqueue_tx(&acl(1, 0, &[0])),
                Err(BridgeError::Full)
            );
            assert!(transport::try_receive_controller_packet().is_none());
            for tag in tags.into_iter().flatten() {
                assert!(runner.bridge.ack_tx(tag));
                assert!(!runner.bridge.ack_tx(tag));
            }
            assert!(runner.pump_once());
            assert_eq!(
                transport::try_receive_controller_packet()
                    .unwrap()
                    .payload(),
                &[0x13, 5, 1, 1, 0, 5, 0]
            );
            assert!(!runner.pump_once());
        }
    }

    #[test]
    fn acl_validates_handle_pb_bc_and_the_251_byte_limit() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        assert_eq!(
            runner.bridge.enqueue_tx(&acl(1, 0, &[1])),
            Err(BridgeError::NotConnected)
        );
        open(&mut runner);
        for packet in [
            acl(2, 0, &[1]),
            acl(1, 2, &[1]),
            acl(1, 3, &[1]),
            acl(0x4001, 0, &[1]),
        ] {
            assert_eq!(
                runner.bridge.enqueue_tx(&packet),
                Err(BridgeError::InvalidPacket)
            );
        }
        // A claimed 252-octet payload cannot fit one HCI packet at all.
        let mut oversized = acl(1, 0, &[1; 251]);
        oversized.bytes[2..4].copy_from_slice(&252u16.to_le_bytes());
        assert_eq!(
            runner.bridge.enqueue_tx(&oversized),
            Err(BridgeError::InvalidPacket)
        );
        let mut truncated = acl(1, 0, &[1, 2]);
        truncated.len -= 1;
        assert_eq!(
            runner.bridge.enqueue_tx(&truncated),
            Err(BridgeError::InvalidPacket)
        );
        assert!(runner.bridge.enqueue_tx(&acl(1, 0, &[1; 251])).is_ok());
    }

    #[test]
    fn host_reads_buffer_size_and_features() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_le_features([1, 0, 0, 0, 0, 0, 0, 0]);

        pollster::block_on(async {
            inject_cmd(0x2002, &[]);
            runner.serve_one().await;
            expect_command_complete(0x2002, HCI_SUCCESS, &[0xfb, 0, ACL_CREDITS]);

            inject_cmd(0x2003, &[]);
            runner.serve_one().await;
            expect_command_complete(0x2003, HCI_SUCCESS, &[1, 0, 0, 0, 0, 0, 0, 0]);
        });
    }

    #[test]
    fn dle_commands_report_the_maximum_and_store_the_suggestion() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            inject_cmd(0x202f, &[]);
            runner.serve_one().await;
            expect_command_complete(
                0x202f,
                HCI_SUCCESS,
                &[0xf7, 0, 0x48, 0x08, 0xf7, 0, 0x48, 0x08],
            );

            inject_cmd(0x2060, &[]);
            runner.serve_one().await;
            expect_command_complete(0x2060, HCI_SUCCESS, &[0xfb, 0, ACL_CREDITS, 0, 0, 0]);

            inject_cmd(0x2023, &[]);
            runner.serve_one().await;
            expect_command_complete(0x2023, HCI_SUCCESS, &[27, 0, 0x48, 0x01]);

            assert_eq!(runner.suggested_data_length_explicit(), None);
            inject_cmd(0x2024, &[0xf7, 0, 0x48, 0x08]);
            runner.serve_one().await;
            expect_command_complete(0x2024, HCI_SUCCESS, &[]);
            assert_eq!(runner.suggested_data_length(), (247, 2120));
            assert_eq!(runner.suggested_data_length_explicit(), Some((247, 2120)));

            // 251 octets / 2120 us is wire-valid even though this controller
            // negotiates 247: the suggestion is stored and clamped when a
            // session applies it.
            inject_cmd(0x2024, &[0xfb, 0, 0x48, 0x08]);
            runner.serve_one().await;
            expect_command_complete(0x2024, HCI_SUCCESS, &[]);
            assert_eq!(runner.suggested_data_length_explicit(), Some((251, 2120)));
            assert_eq!(runner.suggested_data_length(), (251, 2120));
            // Outside the wire-valid range is still rejected.
            inject_cmd(0x2024, &[0x1a, 0, 0x48, 0x08]);
            runner.serve_one().await;
            expect_command_complete(0x2024, HCI_INVALID_PARAMETERS, &[]);
            assert_eq!(runner.suggested_data_length(), (251, 2120));
            inject_cmd(0x2024, &[0xfb, 0, 0x47, 0x01]);
            runner.serve_one().await;
            expect_command_complete(0x2024, HCI_INVALID_PARAMETERS, &[]);
        });
    }

    #[test]
    fn le_set_data_length_queues_a_request_for_a_live_handle() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);

        pollster::block_on(async {
            inject_cmd(0x2022, &[1, 0, 0xf7, 0, 0x48, 0x08]);
            runner.serve_one().await;
            expect_command_complete(0x2022, HCI_SUCCESS, &[1, 0]);
            assert_eq!(runner.take_data_length_request(), Some((247, 2120)));
            assert_eq!(runner.take_data_length_request(), None);

            // Unknown handle.
            inject_cmd(0x2022, &[0xfe, 0x0f, 0xf7, 0, 0x48, 0x08]);
            runner.serve_one().await;
            expect_command_complete(0x2022, HCI_UNKNOWN_CONNECTION, &[0xfe, 0x0f]);

            // Out-of-range octets.
            inject_cmd(0x2022, &[1, 0, 0x1a, 0, 0x48, 0x08]);
            runner.serve_one().await;
            expect_command_complete(0x2022, HCI_INVALID_PARAMETERS, &[1, 0]);
            assert_eq!(runner.take_data_length_request(), None);
        });
    }

    #[test]
    fn privacy_commands_are_accepted_without_a_resolving_list() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            for (opcode, params) in [
                (0x202d, &[1u8][..]),
                (0x2029, &[][..]),
                (0x2027, &[0u8; 39][..]),
                (0x2028, &[0u8; 7][..]),
                (0x202e, &[0x10, 0x00][..]),
                (0x204e, &[0u8; 8][..]),
            ] {
                inject_cmd(opcode, params);
                runner.serve_one().await;
                expect_command_complete(opcode, HCI_SUCCESS, &[]);
            }
            inject_cmd(0x202a, &[]);
            runner.serve_one().await;
            expect_command_complete(0x202a, HCI_SUCCESS, &[0]);

            inject_cmd(0x202d, &[2]);
            runner.serve_one().await;
            expect_command_complete(0x202d, HCI_INVALID_PARAMETERS, &[]);
        });
    }

    #[test]
    fn rx_backpressure_pb_mapping_and_empty_control_packets() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.bridge.connected(connection_info()).unwrap();
        assert!(!runner.bridge.can_receive_acl(3, 1));
        assert!(!runner.bridge.can_receive_acl(2, 252));
        assert_eq!(
            runner.bridge.receive_acl(3, &[0]),
            Err(BridgeError::InvalidPacket)
        );
        for n in 0..5 {
            assert!(runner.bridge.can_receive_acl(2, 27));
            runner
                .bridge
                .receive_acl(if n == 0 { 2 } else { 1 }, &[n; 27])
                .unwrap();
        }
        assert!(!runner.bridge.can_receive_acl(2, 1));
        assert_eq!(runner.bridge.receive_acl(2, &[9]), Err(BridgeError::Full));
        assert!(runner.bridge.can_receive_acl(1, 0));
        runner.bridge.receive_acl(1, &[]).unwrap();
        assert!(runner.pump_once());
        assert_eq!(
            &transport::try_receive_controller_packet()
                .unwrap()
                .payload()[..3],
            &[0x3e, 19, 1]
        );
        for n in 0..5 {
            assert!(runner.pump_once());
            let packet = transport::try_receive_controller_packet().unwrap();
            assert_eq!(packet.kind, PacketKind::AclData);
            assert_eq!(packet.bytes[1] >> 4, if n == 0 { 2 } else { 1 });
            assert_eq!(&packet.payload()[4..], &[n; 27]);
        }
        assert!(!runner.pump_once()); // No ACL/credits for empty or control.
    }

    #[test]
    fn transport_full_retains_lifecycle_acl_and_command_reply() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        for _ in 0..4 {
            transport::try_send_controller_packet(transport::command_complete_packet(
                0x1009,
                0,
                &[],
            ))
            .unwrap();
        }
        inject_cmd(0x2003, &[]);
        assert!(runner.pump_once());
        runner.bridge.connected(connection_info()).unwrap();
        runner.bridge.receive_acl(2, &[7]).unwrap();
        assert!(!runner.pump_once());
        for _ in 0..4 {
            transport::try_receive_controller_packet().unwrap();
        }
        assert!(runner.pump_once());
        expect_command_complete(0x2003, 0, &[0; 8]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet().unwrap().bytes[0],
            0x3e
        );
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet().unwrap().kind,
            PacketKind::AclData
        );
    }

    #[test]
    fn disconnect_status_precedes_completion_and_old_epoch_cannot_ack() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        runner.bridge.enqueue_tx(&acl(1, 0, &[1])).unwrap();
        let old = runner.bridge.take_tx_acl().unwrap().tag;
        inject_cmd(0x0406, &[2, 0, 0x13]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 2, 1, 6, 4]
        );
        assert!(runner.bridge.take_radio_request().is_none());
        inject_cmd(0x0406, &[1, 0, 0x13]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0, 1, 6, 4]
        );
        assert_eq!(
            runner.bridge.take_radio_request(),
            Some(super::super::connection::RadioRequest::Disconnect { reason: 0x13 })
        );
        assert!(!runner.pump_once()); // Completion waits for actual RF teardown.
        runner.bridge.disconnected(0x16);
        runner.bridge.connected(connection_info()).unwrap();
        assert!(!runner.bridge.ack_tx(old));
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[5, 4, 0, 1, 0, 0x16]
        );
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet().unwrap().bytes[0],
            0x3e
        );
        assert!(!runner.pump_once());
    }

    #[test]
    fn connected_reset_waits_for_rf_and_preserves_next_command() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        runner.bridge.enqueue_tx(&acl(1, 0, &[1])).unwrap();
        let old = runner.bridge.take_tx_acl().unwrap().tag;
        runner.bridge.receive_acl(2, &[9]).unwrap();
        // RX may be published first; Reset must remove it before reusing handle.
        assert!(runner.pump_once());
        inject_cmd(0x0c03, &[]);
        assert!(runner.pump_once());
        assert_eq!(
            runner.bridge.take_radio_request(),
            Some(super::super::connection::RadioRequest::Reset)
        );
        inject_cmd(0x1009, &[]);
        assert!(!runner.pump_once());
        runner.bridge.reset_finished();
        assert!(transport::try_receive_controller_packet().is_none());
        assert!(runner.pump_once());
        expect_command_complete(0x0c03, 0, &[]);
        assert!(runner.pump_once());
        expect_command_complete(0x1009, 0, &DEFAULT_BD_ADDR);
        assert!(!runner.bridge.ack_tx(old));
        assert!(!runner.bridge.is_connected());
        open(&mut runner);
        assert!(!runner.pump_once());
    }

    #[test]
    fn data_length_change_reports_the_negotiated_values() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        // The default mask enables subevents 1..=5; a Host that wants Data
        // Length Change sets bit 6.
        runner.bridge.set_masks(u64::MAX, 0x1f | (1 << 6));
        runner
            .bridge
            .data_length_change(247, 2120, 132, 1120)
            .unwrap();
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x3e, 11, 7, 1, 0, 0xf7, 0, 0x48, 0x08, 0x84, 0, 0x60, 0x04]
        );
        // Masked-off subevent is dropped.
        runner.bridge.set_masks(u64::MAX, 0x1f & !(1 << 6));
        runner
            .bridge
            .data_length_change(247, 2120, 247, 2120)
            .unwrap();
        assert!(!runner.pump_once());
    }

    #[test]
    fn update_mask_and_lifecycle_slots_remain_bounded() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        runner.bridge.connection_updated(30, 1, 300).unwrap();
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x3e, 10, 3, 0, 1, 0, 30, 0, 1, 0, 44, 1]
        );
        inject_cmd(0x2001, &[0; 8]);
        assert!(runner.pump_once());
        expect_command_complete(0x2001, 0, &[]);
        runner.bridge.connection_updated(32, 0, 300).unwrap();
        assert!(!runner.pump_once());
        runner.bridge.set_masks(u64::MAX, 0x1f);
        for _ in 0..15 {
            runner.bridge.connection_updated(32, 0, 300).unwrap();
        }
        assert_eq!(
            runner.bridge.connection_updated(32, 0, 300),
            Err(BridgeError::Full)
        );
        runner.bridge.disconnected(0x08); // Reserved slot, even with fifteen updates.
        assert!(!runner.bridge.is_connected());
        assert_eq!(
            runner.bridge.connected(connection_info()),
            Err(BridgeError::Full)
        );
        for _ in 0..15 {
            assert!(runner.pump_once());
            assert_eq!(
                transport::try_receive_controller_packet().unwrap().bytes[0],
                0x3e
            );
        }
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet().unwrap().bytes[0],
            5
        );
    }

    #[test]
    fn stale_full_input_cannot_cross_handle_reuse() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        for _ in 0..5 {
            runner.bridge.enqueue_tx(&acl(1, 0, &[1])).unwrap();
        }
        transport::try_send_host_packet(acl(1, 0, &[99])).unwrap();
        assert!(!runner.pump_once());
        runner.bridge.disconnected(0x13);
        runner.bridge.connected(connection_info()).unwrap();
        for _ in 0..2 {
            assert!(runner.pump_once());
            transport::try_receive_controller_packet().unwrap();
        }
        runner.pump_once();
        assert!(runner.bridge.take_tx_acl().is_none());
    }

    #[test]
    fn le_read_buffer_size() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            inject_cmd(0x2002, &[]);
            runner.serve_one().await;
            expect_command_complete(
                0x2002,
                HCI_SUCCESS,
                &[
                    ACL_DATA_PACKET_LENGTH as u8,
                    (ACL_DATA_PACKET_LENGTH >> 8) as u8,
                    ACL_CREDITS,
                ],
            );
        });
    }

    fn expect_command_status(opcode: u16, status: u8) {
        let packet = transport::try_receive_controller_packet().expect("missing CS");
        assert_eq!(packet.kind, PacketKind::Event);
        let payload = packet.payload();
        assert_eq!(payload[0], 0x0f);
        assert_eq!(payload[1], 4);
        assert_eq!(payload[2], status);
        assert_eq!(payload[3], 1);
        assert_eq!(u16::from_le_bytes([payload[4], payload[5]]), opcode);
    }

    fn scan_params() -> [u8; 7] {
        // Passive, 30 ms interval, 15 ms window, random own address, no filter.
        [0, 0x30, 0x00, 0x18, 0x00, 1, 0]
    }

    fn create_params(peer: [u8; 6]) -> [u8; 25] {
        let mut params = [0u8; 25];
        params[0..2].copy_from_slice(&0x0030u16.to_le_bytes());
        params[2..4].copy_from_slice(&0x0018u16.to_le_bytes());
        params[5] = 1;
        params[6..12].copy_from_slice(&peer);
        params[12] = 1;
        params[13..15].copy_from_slice(&24u16.to_le_bytes());
        params[15..17].copy_from_slice(&24u16.to_le_bytes());
        params[19..21].copy_from_slice(&200u16.to_le_bytes());
        params
    }

    #[test]
    fn scan_reports_exclude_adv_a_and_encode_rssi() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_random_addr([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x21]);

        pollster::block_on(async {
            inject_cmd(0x200b, &scan_params());
            runner.serve_one().await;
            expect_command_complete(0x200b, HCI_SUCCESS, &[]);

            inject_cmd(0x200c, &[1, 0]);
            runner.serve_one().await;
            expect_command_complete(0x200c, HCI_SUCCESS, &[]);
        });
        assert!(runner.scan_state().enabled);

        // ADV_IND with AdvA 06:05:04:03:02:01 and one local-name AD field.
        let mut dma = [0u8; 2 + 6 + 11];
        dma[0] = 0x00; // ADV_IND, public TxAdd
        dma[1] = 17;
        dma[2..8].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        dma[8] = 10;
        dma[9] = 0x09;
        dma[10..19].copy_from_slice(b"wch585-c1");
        let pdu = scan::Pdu::parse(&dma, true).unwrap();
        assert!(runner.push_adv_report(&pdu, -42));

        assert!(runner.pump_once());
        let packet = transport::try_receive_controller_packet().unwrap();
        let payload = packet.payload();
        assert_eq!(payload[0], 0x3e);
        assert_eq!(payload[2], 0x02);
        assert_eq!(payload[3], 1);
        assert_eq!(payload[4], 0x00); // ADV_IND
        assert_eq!(payload[5], 0); // public address
        assert_eq!(&payload[6..12], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(payload[12], 11); // AdvA removed
        assert_eq!(&payload[13..24], &dma[8..19]);
        assert_eq!(payload[24], (-42i8) as u8);
    }

    #[test]
    fn create_connection_status_and_cancel_failure_event() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_random_addr([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x21]);
        let peer = [1, 2, 3, 4, 5, 6];

        pollster::block_on(async {
            inject_cmd(0x200d, &create_params(peer));
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_SUCCESS);
        });
        let request = runner.pending_connect().unwrap();
        assert_eq!(request.peer_addr, peer);
        assert!(request.peer_random && request.own_random);
        assert_eq!(
            runner.own_addr(),
            ([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x21], true)
        );

        pollster::block_on(async {
            inject_cmd(0x200e, &[]);
            runner.serve_one().await;
            expect_command_complete(0x200e, HCI_SUCCESS, &[]);
        });
        assert!(runner.pending_connect().is_none());
        // `serve_one` already flushed the failure event after the command reply.
        let event = transport::try_receive_controller_packet().unwrap();
        let payload = event.payload();
        assert_eq!(payload[0], 0x3e);
        assert_eq!(payload[2], 0x01); // LE Connection Complete
        assert_eq!(payload[3], 0x02); // Unknown Connection Identifier
    }

    #[test]
    fn create_connection_rejects_invalid_parameters() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            let mut params = create_params([1, 2, 3, 4, 5, 6]);
            params[4] = 2; // filter policy
            inject_cmd(0x200d, &params);
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_INVALID_PARAMETERS);
            assert!(runner.pending_connect().is_none());

            let mut params = create_params([1, 2, 3, 4, 5, 6]);
            params[19] = 0x06; // 60 ms is not above 2 x interval
            inject_cmd(0x200d, &params);
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_INVALID_PARAMETERS);
        });
    }

    fn le_rand_once(runner: &mut SoftRunner) -> [u8; 8] {
        transport::drain_channels_for_test();
        inject_cmd(0x2018, &[]);
        pollster::block_on(runner.serve_one());
        let packet = transport::try_receive_controller_packet().expect("missing LE Rand CC");
        let payload = packet.payload();
        assert_eq!(payload[0], 0x0e);
        assert_eq!(payload[2], 1);
        assert_eq!(u16::from_le_bytes([payload[3], payload[4]]), 0x2018);
        assert_eq!(payload[5], HCI_SUCCESS);
        let mut out = [0u8; 8];
        out.copy_from_slice(&payload[6..14]);
        out
    }

    #[test]
    fn le_rand_advances_and_tracks_seed() {
        let _guard = test_lock();
        let mut runner = SoftRunner::new();
        assert!(!runner.entropy_seeded());

        let first = le_rand_once(&mut runner);
        let second = le_rand_once(&mut runner);
        assert_ne!(first, second);
        assert_ne!(first, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        let seed = [0x42u8; 32];
        assert!(runner.set_entropy_seed(&seed));
        assert!(runner.entropy_seeded());
        let seeded = le_rand_once(&mut runner);
        let expected = crate::rand::chacha20_block(&seed, 0, &[0u8; 12]);
        assert_eq!(seeded, expected[..8]);

        // Re-installing the same seed is rejected and does not rewind.
        assert!(!runner.set_entropy_seed(&seed));
        assert_ne!(le_rand_once(&mut runner), seeded);
    }

    #[test]
    fn le_encrypt_matches_fips_197() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        // HCI sends 128-bit values least-significant-octet first, so the FIPS
        // key 000102..0f and plaintext 001122..ff travel reversed.
        let mut params = [0u8; 32];
        for i in 0..16 {
            params[i] = 15 - i as u8;
            params[16 + i] = 0xff - (i as u8) * 0x11;
        }

        pollster::block_on(async {
            inject_cmd(0x2017, &params);
            runner.serve_one().await;
            // AES(000102..0f, 001122..ff) = 69c4e0d8..b4c55a, returned reversed.
            expect_command_complete(
                0x2017,
                HCI_SUCCESS,
                &[
                    0x5a, 0xc5, 0xb4, 0x70, 0x80, 0xb7, 0xcd, 0xd8, 0x30, 0x04, 0x7b, 0x6a, 0xd8,
                    0xe0, 0xc4, 0x69,
                ],
            );
        });
    }

    #[test]
    fn le_encrypt_matches_the_core_session_key_sample() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        // Core 5.4 Vol 6 Part C: SK = AES(LTK, SKD) with SKD = r ||
        // (diversifier || 0). Both inputs and the result are in HCI wire order.
        let mut params = [0u8; 32];
        params[..16].copy_from_slice(&[
            0xbf, 0x01, 0xfb, 0x9d, 0x4e, 0xf3, 0xbc, 0x36, 0xd8, 0x74, 0xf5, 0x39, 0x41, 0x38,
            0x68, 0x4c,
        ]);
        params[16..].copy_from_slice(&[
            0x13, 0x02, 0xf1, 0xe0, 0xdf, 0xce, 0xbd, 0xac, 0x79, 0x68, 0x57, 0x46, 0x35, 0x24,
            0x13, 0x02,
        ]);

        pollster::block_on(async {
            inject_cmd(0x2017, &params);
            runner.serve_one().await;
            expect_command_complete(
                0x2017,
                HCI_SUCCESS,
                &[
                    0x66, 0xc6, 0xc2, 0x27, 0x8e, 0x3b, 0x8e, 0x05, 0x3e, 0x7e, 0xa3, 0x26, 0x52,
                    0x1b, 0xad, 0x99,
                ],
            );
        });
    }

    #[test]
    fn le_encrypt_rejects_a_wrong_parameter_length() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            inject_cmd(0x2017, &[0u8; 31]);
            runner.serve_one().await;
            expect_command_complete(0x2017, HCI_INVALID_PARAMETERS, &[]);
            inject_cmd(0x2017, &[0u8; 33]);
            runner.serve_one().await;
            expect_command_complete(0x2017, HCI_INVALID_PARAMETERS, &[]);
        });
    }

    #[test]
    fn enable_encryption_waits_for_radio_owner_and_validates_state() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        // Encryption is a Central procedure; the Peripheral path is LTK Request.
        let mut info = connection_info();
        info.role = crate::ll::Role::Central;
        runner.bridge.connected(info).unwrap();
        assert!(runner.pump_once());
        transport::try_receive_controller_packet().unwrap();

        let mut params = [0u8; 28];
        params[0..2].copy_from_slice(&1u16.to_le_bytes());
        params[2..10].copy_from_slice(&[0xa0; 8]);
        params[10..12].copy_from_slice(&0x1234u16.to_le_bytes());
        params[12..28].copy_from_slice(&[0x5a; 16]);

        pollster::block_on(async {
            inject_cmd(0x2019, &params);
            runner.serve_one().await;
            expect_command_status(0x2019, HCI_SUCCESS);

            // A second request before the RF owner consumes the first.
            inject_cmd(0x2019, &params);
            runner.serve_one().await;
            expect_command_status(0x2019, HCI_COMMAND_DISALLOWED);

            // Unknown handle.
            let mut bad = params;
            bad[0] = 2;
            inject_cmd(0x2019, &bad);
            runner.serve_one().await;
            expect_command_status(0x2019, HCI_UNKNOWN_CONNECTION);

            // Short and long parameters are rejected before any state changes.
            inject_cmd(0x2019, &params[..27]);
            runner.serve_one().await;
            expect_command_status(0x2019, HCI_INVALID_PARAMETERS);
            let mut long = [0u8; 29];
            long[..28].copy_from_slice(&params);
            inject_cmd(0x2019, &long);
            runner.serve_one().await;
            expect_command_status(0x2019, HCI_INVALID_PARAMETERS);
        });

        let request = runner.take_encryption_request().unwrap();
        assert_eq!(request.handle, 1);
        assert_eq!(request.rand, [0xa0; 8]);
        assert_eq!(request.ediv, 0x1234);
        assert_eq!(request.ltk, [0x5a; 16]);
        assert!(runner.take_encryption_request().is_none());
    }

    #[test]
    fn enable_encryption_is_disallowed_in_the_peripheral_role() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);

        let mut params = [0u8; 28];
        params[0..2].copy_from_slice(&1u16.to_le_bytes());

        pollster::block_on(async {
            inject_cmd(0x2019, &params);
            runner.serve_one().await;
            expect_command_status(0x2019, HCI_COMMAND_DISALLOWED);
        });
        assert!(runner.take_encryption_request().is_none());
    }

    #[test]
    fn ltk_reply_commands_reach_the_radio_owner() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);

        let mut params = [0u8; 18];
        params[0..2].copy_from_slice(&1u16.to_le_bytes());
        params[2..18].copy_from_slice(&[0x33; 16]);

        pollster::block_on(async {
            inject_cmd(0x201a, &params);
            runner.serve_one().await;
            // bt-hci parses the Command Complete return parameters as a
            // `ConnHandle`; empty parameters become
            // `Error::INVALID_HCI_PARAMETERS` even though the status is 0.
            let echoed = [1u8, 0];
            expect_command_complete(0x201a, HCI_SUCCESS, &echoed);
            use bt_hci::FromHciBytes as _;
            let (handle, rest) =
                bt_hci::param::ConnHandle::from_hci_bytes(&echoed).expect("conn handle");
            assert_eq!(handle.raw(), 1);
            assert!(rest.is_empty());
            assert_eq!(runner.take_ltk_reply(), Some(LtkReply::Key([0x33; 16])));

            inject_cmd(0x201b, &[1, 0]);
            runner.serve_one().await;
            expect_command_complete(0x201b, HCI_SUCCESS, &echoed);
            assert_eq!(runner.take_ltk_reply(), Some(LtkReply::Rejected));

            let mut bad = params;
            bad[0] = 2;
            inject_cmd(0x201a, &bad);
            runner.serve_one().await;
            expect_command_complete(0x201a, HCI_UNKNOWN_CONNECTION, &[]);

            inject_cmd(0x201b, &[2, 0]);
            runner.serve_one().await;
            expect_command_complete(0x201b, HCI_UNKNOWN_CONNECTION, &[]);
        });
    }

    /// Drain every queued controller event, including the lifecycle pair a
    /// disconnect/reconnect produces, so the next command sees an idle channel.
    fn drain_controller(runner: &mut SoftRunner) {
        while runner.pump_once() {
            while transport::try_receive_controller_packet().is_some() {}
        }
        while transport::try_receive_controller_packet().is_some() {}
    }

    #[test]
    fn ltk_reply_does_not_survive_disconnect_and_reconnect() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);

        let mut params = [0u8; 18];
        params[0..2].copy_from_slice(&1u16.to_le_bytes());
        params[2..18].copy_from_slice(&[0x33; 16]);

        pollster::block_on(async {
            inject_cmd(0x201a, &params);
            runner.serve_one().await;
            expect_command_complete(0x201a, HCI_SUCCESS, &[1, 0]);
        });

        // The reply was queued for the first link; every link uses handle 1, so
        // the epoch is the only thing that can reject it after a reconnect.
        runner.bridge.disconnected(0x13);
        runner.bridge.connected(connection_info()).unwrap();
        drain_controller(&mut runner);
        assert!(runner.take_ltk_reply().is_none());

        // A fresh reply on the new link still reaches the RF owner.
        pollster::block_on(async {
            inject_cmd(0x201a, &params);
            runner.serve_one().await;
            expect_command_complete(0x201a, HCI_SUCCESS, &[1, 0]);
        });
        assert_eq!(runner.take_ltk_reply(), Some(LtkReply::Key([0x33; 16])));
    }

    #[test]
    fn enable_encryption_does_not_survive_disconnect_and_reconnect() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        let mut info = connection_info();
        info.role = crate::ll::Role::Central;
        runner.bridge.connected(info).unwrap();
        drain_controller(&mut runner);

        let mut params = [0u8; 28];
        params[0..2].copy_from_slice(&1u16.to_le_bytes());
        params[12..28].copy_from_slice(&[0x5a; 16]);

        pollster::block_on(async {
            inject_cmd(0x2019, &params);
            runner.serve_one().await;
            expect_command_status(0x2019, HCI_SUCCESS);
        });

        runner.bridge.disconnected(0x13);
        runner.bridge.connected(info).unwrap();
        drain_controller(&mut runner);
        assert!(runner.take_encryption_request().is_none());

        // A stale entry must not make the new link look busy.
        pollster::block_on(async {
            inject_cmd(0x2019, &params);
            runner.serve_one().await;
            expect_command_status(0x2019, HCI_SUCCESS);
        });
        assert_eq!(
            runner.take_encryption_request(),
            Some(EnableEncryption {
                handle: 1,
                rand: [0; 8],
                ediv: 0,
                ltk: [0x5a; 16],
            })
        );
    }

    #[test]
    fn security_events_keep_the_disconnect_slot() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        // Fill the event queue down to the lifecycle reserve.
        while runner.bridge.connection_updated(30, 1, 300).is_ok() {}
        // Only the reserved disconnect slot is left; security events must not
        // take it.
        assert_eq!(runner.bridge.encryption_change(1, 0, 1), Err(BridgeError::Full));
        assert_eq!(
            runner.bridge.ltk_request(1, [0; 8], 0),
            Err(BridgeError::Full)
        );
        // Disconnection still finds its slot instead of panicking, and the
        // queued event survives the full queue intact.
        runner.bridge.disconnected(0x13);
        assert!(!runner.bridge.is_connected());
        let mut disconnect = None;
        while runner.pump_once() {
            while let Some(packet) = transport::try_receive_controller_packet() {
                let payload = packet.payload();
                if payload.first() == Some(&0x05) {
                    disconnect = Some(payload[1..].to_vec());
                }
            }
        }
        while let Some(packet) = transport::try_receive_controller_packet() {
            let payload = packet.payload();
            if payload.first() == Some(&0x05) {
                disconnect = Some(payload[1..].to_vec());
            }
        }
        // [code 0x05][param len 4][status 0][handle 1][reason 0x13]
        assert_eq!(disconnect.as_deref(), Some(&[4, 0, 1, 0, 0x13][..]));
    }

    #[test]
    fn ltk_request_and_encryption_change_events() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);

        assert!(runner.push_ltk_request([0xa5; 8], 0xbeef));
        assert!(runner.pump_once());
        let event = transport::try_receive_controller_packet().unwrap();
        assert_eq!(
            event.payload(),
            &[0x3e, 13, 5, 1, 0, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xef, 0xbe,]
        );

        assert!(runner.encryption_change(1, 0, 1));
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x08, 4, 0, 1, 0, 1]
        );
    }

    #[test]
    fn ltk_request_is_refused_when_the_host_disabled_the_event() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        runner.bridge.set_masks(u64::MAX, 0);
        assert!(!runner.push_ltk_request([0; 8], 0));
        // Encryption Change is a normal event; a disabled mask is not an error.
        assert!(runner.encryption_change(1, 0, 1));
    }

    #[test]
    fn connection_complete_reports_central_role_and_clock_accuracy() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let mut info = connection_info();
        info.role = crate::ll::Role::Central;
        info.master_clock_accuracy = 3;
        runner.bridge.connected(info).unwrap();
        assert!(runner.pump_once());
        let event = transport::try_receive_controller_packet().unwrap();
        let payload = event.payload();
        assert_eq!(payload[0], 0x3e);
        assert_eq!(payload[2], 0x01);
        assert_eq!(payload[6], 0); // Central (parameters[4])
        assert_eq!(payload[20], 3); // master clock accuracy (parameters[18])
    }
}
