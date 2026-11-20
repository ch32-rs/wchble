//! Soft HCI command/ACL pump and its fixed two-slot connection bridges.
//!
//! A cooperative RF owner calls [`SoftRunner::pump_once`] only while idle and
//! synchronizes connection lifecycle through [`SoftRunner::bridge`] (slot 0)
//! and [`SoftRunner::link_bridge`]. LL radio timing, retransmission and
//! sequence numbers remain outside this module.

use bt_hci::transport::PacketKind;

use crate::crypto::Aes128;
use crate::ll::dle::{LL_LEGACY_PAYLOAD, LL_LEGACY_TIME_US, LL_MAX_PLAINTEXT, LL_MAX_TIME_US};
use crate::ll::privacy::{
    is_resolvable, Poll, Privacy, PrivacyStats, ResolvingEntry, MAX_FILTER_ACCEPT_LIST,
    MAX_RESOLVING_LIST,
};
use crate::ll::{scan, LinkLayer};
use crate::rand::ChaCha20Drbg;

use super::connection::{event_packet, BridgeError, ConnectionBridge};
use super::transport::{self, HostPacket, LinkKey, Packet, PacketScope, MAX_LINKS};

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
/// Memory capacity exceeded (resolving or filter accept list full).
const HCI_MEMORY_CAPACITY_EXCEEDED: u8 = 0x07;
/// Unsupported Feature or Parameter Value.
const HCI_UNSUPPORTED_FEATURE: u8 = 0x11;

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

/// `adv_own_addr_type` before `LE Set Advertising Parameters` sets it.
const OWN_ADDR_UNSET: u8 = 0xff;

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
    /// Slot 0. Kept as a named field so N=1 callers keep their wiring.
    pub bridge: ConnectionBridge,
    /// Slot 1, used by the second link. Idle until a session publishes into it.
    slot1: ConnectionBridge,
    /// Next slot to poll for output, so neither link starves the other.
    flush_slot: u8,
    scan: ScanState,
    pending_connect: Option<CreateConnRequest>,
    adv_reports_dropped: u32,
    pending_reply: Option<Packet>,
    /// Input held under backpressure per slot, with the scope stamped at the
    /// producer so a blocked link cannot occupy the shared input path.
    pending_input: [Option<HostPacket>; MAX_LINKS],
    reset_pending: bool,
    /// The RF owner confirmed the radio is physically idle for a Reset that
    /// had only advertising/scanning (no link to stop).
    reset_radio_ack: bool,
    event_mask: u64,
    le_event_mask: u64,
    bd_addr: [u8; 6],
    /// Address from `LE Set Random Address` / HAL seed; `None` = public BD_ADDR.
    random_addr: Option<[u8; 6]>,
    /// Own address type selected by `LE Set Advertising Parameters`.
    adv_own_addr_type: u8,
    /// Local RPA, peer resolution and filter accept list.
    privacy: Privacy,
    /// DRBG backing `HCI_LE_Rand` and LL random values.
    drbg: ChaCha20Drbg,
    /// True once a HAL supplied a measured entropy seed.
    entropy_seeded: bool,
    /// Pending `LE Enable Encryption` per slot (Central role), tagged with the
    /// link identity that created it.
    pending_encryption: [Option<(LinkKey, EnableEncryption)>; MAX_LINKS],
    /// Host answer per slot (Peripheral role), tagged with the link identity
    /// that requested it.
    ltk_reply: [Option<(LinkKey, LtkReply)>; MAX_LINKS],
    /// LE features advertised both through HCI and LL_FEATURE_RSP.
    le_features: [u8; 8],
    /// `LE Set Default PHY` preferences for future connections (masks).
    default_phy: (u8, u8),
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
            slot1: ConnectionBridge::for_slot(1),
            flush_slot: 0,
            scan: ScanState::default(),
            pending_connect: None,
            adv_reports_dropped: 0,
            pending_reply: None,
            pending_input: [None; MAX_LINKS],
            reset_pending: false,
            reset_radio_ack: true,
            event_mask: u64::MAX,
            le_event_mask: 0x1f,
            bd_addr: DEFAULT_BD_ADDR,
            random_addr: None,
            adv_own_addr_type: OWN_ADDR_UNSET,
            privacy: Privacy::new(),
            drbg: ChaCha20Drbg::from_seed(&[0u8; 32]),
            entropy_seeded: false,
            pending_encryption: [None; MAX_LINKS],
            ltk_reply: [None; MAX_LINKS],
            le_features: [0; 8],
            default_phy: (0x03, 0x03),
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

    /// Bridge for `slot`, or `None` when the slot is out of range. Slots are
    /// fixed; only their links come and go.
    pub fn link_bridge(&self, slot: u8) -> Option<&ConnectionBridge> {
        match slot {
            0 => Some(&self.bridge),
            1 => Some(&self.slot1),
            _ => None,
        }
    }

    pub fn link_bridge_mut(&mut self, slot: u8) -> Option<&mut ConnectionBridge> {
        match slot {
            0 => Some(&mut self.bridge),
            1 => Some(&mut self.slot1),
            _ => None,
        }
    }

    /// Internal accessors: callers only pass slots from a `LinkKey`.
    pub(crate) fn bridge_slot(&self, slot: u8) -> &ConnectionBridge {
        match slot {
            1 => &self.slot1,
            _ => &self.bridge,
        }
    }

    pub(crate) fn bridge_slot_mut(&mut self, slot: u8) -> &mut ConnectionBridge {
        match slot {
            1 => &mut self.slot1,
            _ => &mut self.bridge,
        }
    }

    fn links(&self) -> [&ConnectionBridge; 2] {
        [&self.bridge, &self.slot1]
    }

    fn links_mut(&mut self) -> [&mut ConnectionBridge; 2] {
        [&mut self.bridge, &mut self.slot1]
    }

    /// Live link for `handle`, if any. Handles are shared by both slots.
    pub(crate) fn live_key(&self, handle: u16) -> Option<LinkKey> {
        self.links()
            .into_iter()
            .find(|bridge| bridge.handle() == Some(handle))
            .map(ConnectionBridge::link_key)
    }

    /// True while `key` still names a connected link.
    fn link_live(&self, key: LinkKey) -> bool {
        self.links()
            .into_iter()
            .any(|bridge| bridge.is_connected() && bridge.link_key() == key)
    }

    fn link_key_mut(&mut self, key: LinkKey) -> Option<&mut ConnectionBridge> {
        self.links_mut()
            .into_iter()
            .find(|bridge| bridge.is_connected() && bridge.link_key() == key)
    }

    fn any_connected(&self) -> bool {
        self.links().into_iter().any(ConnectionBridge::is_connected)
    }

    /// Every slot already holds a link. A single live link must not block the
    /// other role's scanning or initiating (X3.5 CP), so those commands ask
    /// this instead of [`any_connected`].
    fn all_links_connected(&self) -> bool {
        self.links().into_iter().all(ConnectionBridge::is_connected)
    }

    /// Acknowledge Reset only when every slot has finished retiring its link
    /// and the RF owner has confirmed the physical stop when one was needed.
    fn take_reset_done(&mut self) -> bool {
        // Do not consume the bridges' completion flags until the RF owner has
        // confirmed the stop, or the one-shot flag would be lost.
        if !self.reset_radio_ack {
            return false;
        }
        let mut done = false;
        let mut pending = false;
        for bridge in self.links_mut() {
            done |= bridge.take_reset_done();
            pending |= bridge.is_resetting();
        }
        done && !pending
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

    /// `LE Set Default PHY` preferences (TX/RX masks) stored for later links.
    pub fn default_phy(&self) -> (u8, u8) {
        self.default_phy
    }

    /// Report a completed PHY procedure for `handle`, including peer-initiated
    /// ones. A stale handle is dropped with the link it belonged to.
    pub fn phy_update_complete_on(&mut self, handle: u16, status: u8, tx: u8, rx: u8) -> bool {
        match self.live_key(handle) {
            Some(key) => self
                .bridge_slot_mut(key.slot)
                .phy_update_complete(status, tx, rx)
                .is_ok(),
            None => false,
        }
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

    /// Take slot 0's Host `LE Set Data Length` request (`TX_Octets`,
    /// `TX_Time`). The N=1 wiring; a dual-link owner uses
    /// [`Self::take_data_length_request_on`].
    pub fn take_data_length_request(&mut self) -> Option<(u16, u16)> {
        self.bridge.take_data_length_request()
    }

    /// Take `slot`'s DLE request, leaving any other link's untouched.
    pub fn take_data_length_request_on(&mut self, slot: u8) -> Option<(u16, u16)> {
        if usize::from(slot) >= MAX_LINKS {
            return None;
        }
        self.bridge_slot_mut(slot).take_data_length_request()
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
    /// Tied to slot 0, the N=1 wiring; a multi-link owner uses
    /// [`Self::take_encryption_request_on`]. A request queued on an earlier
    /// connection is discarded: handles are reused, so without the full
    /// link-key check the RF owner could start encryption on the new link with
    /// the old key material.
    pub fn take_encryption_request(&mut self) -> Option<EnableEncryption> {
        self.take_encryption_request_on(0)
    }

    /// Take the request queued by `slot`, leaving the other link's untouched.
    pub fn take_encryption_request_on(&mut self, slot: u8) -> Option<EnableEncryption> {
        let (key, request) = self.pending_encryption.get_mut(usize::from(slot))?.take()?;
        self.link_live(key).then_some(request)
    }

    /// Take the Host's answer to an `LE LTK Request` (Peripheral role), slot 0
    /// only so a dual-link owner cannot consume the other link's answer.
    pub fn take_ltk_reply(&mut self) -> Option<LtkReply> {
        self.take_ltk_reply_on(0)
    }

    /// Take slot `slot`'s pending LTK answer.
    pub fn take_ltk_reply_on(&mut self, slot: u8) -> Option<LtkReply> {
        let (key, reply) = self.ltk_reply.get_mut(usize::from(slot))?.take()?;
        self.link_live(key).then_some(reply)
    }

    /// Take the answer for one specific link, leaving any other link's reply
    /// untouched.
    pub(crate) fn take_ltk_reply_for(&mut self, key: LinkKey) -> Option<LtkReply> {
        if !self.link_live(key) {
            return None;
        }
        let entry = self.ltk_reply.get_mut(usize::from(key.slot))?;
        let (tagged, reply) = entry.take()?;
        if tagged == key {
            return Some(reply);
        }
        *entry = Some((tagged, reply));
        None
    }

    /// Drop encryption state when the link is gone or Reset is processed.
    pub fn clear_encryption(&mut self) {
        self.pending_encryption = [None; MAX_LINKS];
        self.ltk_reply = [None; MAX_LINKS];
    }

    /// Drop only `key`'s security state; another link's pending reply survives.
    pub(crate) fn clear_encryption_for(&mut self, key: LinkKey) {
        let slot = usize::from(key.slot);
        if self
            .pending_encryption
            .get(slot)
            .is_some_and(|entry| entry.is_some_and(|(tagged, _)| tagged == key))
        {
            self.pending_encryption[slot] = None;
        }
        if self
            .ltk_reply
            .get(slot)
            .is_some_and(|entry| entry.is_some_and(|(tagged, _)| tagged == key))
        {
            self.ltk_reply[slot] = None;
        }
    }

    /// N=1 close entry: closes slot 0 only, and drops only that link's key
    /// material. A dual-link owner must use [`Self::connection_closed_on`]
    /// so this legacy call cannot retire the other link.
    pub fn connection_closed(&mut self, reason: u8) {
        let key = self.bridge.link_key();
        if self.bridge.is_connected() {
            self.bridge.disconnected(reason);
        }
        self.clear_encryption_for(key);
    }

    /// Close the link `key` names. A stale key (the slot already retired and
    /// reopened) is a no-op, even when the handle matches the new link.
    /// Close one slot from the RF owner after a scheduler-level retirement
    /// (supervision expiry, invalid window) that bypassed the link engine.
    pub fn close_link_slot(&mut self, slot: u8, reason: u8) {
        let Some(bridge) = self.link_bridge(slot) else {
            return;
        };
        let key = bridge.link_key();
        self.connection_closed_on(key, reason);
    }

    pub(crate) fn connection_closed_on(&mut self, key: LinkKey, reason: u8) {
        if let Some(bridge) = self.link_key_mut(key) {
            bridge.disconnected(reason);
        }
        self.clear_encryption_for(key);
    }

    /// Emit `LE LTK Request` for slot 0's connected handle. Returns false when
    /// the Host has not enabled the event or the queue is full; the RF owner
    /// must then reject `LL_ENC_REQ` instead of starting encryption.
    pub fn push_ltk_request(&mut self, rand: [u8; 8], ediv: u16) -> bool {
        let Some(handle) = self.bridge.handle() else {
            return false;
        };
        self.bridge.ltk_request(handle, rand, ediv).is_ok()
    }

    /// Emit `LE LTK Request` for `handle` only.
    pub(crate) fn push_ltk_request_on(&mut self, handle: u16, rand: [u8; 8], ediv: u16) -> bool {
        match self.live_key(handle) {
            Some(key) => self
                .bridge_slot_mut(key.slot)
                .ltk_request(handle, rand, ediv)
                .is_ok(),
            None => false,
        }
    }

    /// Report the outcome of the start-encryption procedure.
    ///
    /// `enabled` is the HCI Encryption_Enabled value: 0x00 off, 0x01 on.
    /// Returns false if the handle is gone or the event queue is full.
    pub fn encryption_change(&mut self, handle: u16, status: u8, enabled: u8) -> bool {
        match self.live_key(handle) {
            Some(key) => self
                .bridge_slot_mut(key.slot)
                .encryption_change(handle, status, enabled)
                .is_ok(),
            None => false,
        }
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
        self.sync_adv_addr(false);
    }

    /// Selects the local address for the requested own address type
    /// (Core 5.4 Vol 4 Part E §7.8.5).
    fn sync_adv_addr(&mut self, for_adv: bool) {
        let own_type = self.adv_own_addr_type;
        let mut fallback = false;
        let mut uses_rpa = false;
        let (address, random) = match own_type {
            0 => (self.bd_addr, false),
            1 => (self.random_addr.unwrap_or([0; 6]), true),
            2 | 3 => match self.ensure_local_rpa() {
                Some(rpa) => {
                    uses_rpa = true;
                    (rpa, true)
                }
                None => {
                    fallback = true;
                    if own_type == 2 || self.random_addr.is_none() {
                        (self.bd_addr, false)
                    } else {
                        (self.random_addr.unwrap_or([0; 6]), true)
                    }
                }
            },
            // Before the Host sets parameters: random if one was seeded.
            _ => match self.random_addr {
                Some(addr) => (addr, true),
                None => (self.bd_addr, false),
            },
        };
        self.ll.adv.own_addr = address;
        self.ll.adv.random_addr = random;
        if for_adv {
            self.privacy.note_adv_address(uses_rpa, fallback);
        }
    }

    /// Generates the first local RPA if the selected own type needs one.
    fn ensure_local_rpa(&mut self) -> Option<[u8; 6]> {
        if !matches!(self.adv_own_addr_type, 2 | 3) {
            return None;
        }
        for _ in 0..4 {
            let mut random = [0u8; 3];
            self.drbg.fill(&mut random);
            if let Some(rpa) = self.privacy.ensure_rpa(random) {
                return Some(rpa);
            }
        }
        None
    }

    /// True when `LE Set Advertising Enable` can resolve an address.
    fn adv_address_available(&mut self) -> bool {
        match self.adv_own_addr_type {
            0 | 2 => true,
            1 => self.random_addr.is_some(),
            3 => self.random_addr.is_some() || self.ensure_local_rpa().is_some(),
            _ => true,
        }
    }

    /// Confirm the RF owner physically stopped advertising/scanning after a
    /// Reset. Without it a Reset issued with no live link would complete while
    /// the radio still transmits.
    pub fn reset_radio_stopped(&mut self) {
        if self.reset_pending {
            self.reset_radio_ack = true;
        }
    }

    /// Advertising, scanning or initiating.
    fn roles_active(&self) -> bool {
        self.ll.adv.enabled || self.scan.enabled || self.pending_connect.is_some()
    }

    /// RL edits are only blocked while resolution is enabled (HCI §7.8.38–40).
    fn resolving_edits_blocked(&self) -> bool {
        self.privacy.enabled() && self.roles_active()
    }

    fn add_resolving_entry(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        if self.resolving_edits_blocked() {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        let mut address = [0u8; 6];
        address.copy_from_slice(&params[1..7]);
        let mut peer_irk = [0u8; 16];
        peer_irk.copy_from_slice(&params[7..23]);
        let mut local_irk = [0u8; 16];
        local_irk.copy_from_slice(&params[23..39]);
        let privacy_mode = self
            .privacy
            .entry(params[0], address)
            .map_or(0, |entry| entry.privacy_mode);
        let entry = ResolvingEntry {
            peer_kind: params[0],
            peer_address: address,
            peer_irk,
            local_irk,
            privacy_mode,
        };
        match self.privacy.add(entry) {
            Ok(()) => {
                self.sync_adv_addr(false);
                Ok(&[][..])
            }
            Err(crate::ll::privacy::PrivacyError::NoSpace) => Err(HCI_MEMORY_CAPACITY_EXCEEDED),
            Err(_) => Err(HCI_INVALID_PARAMETERS),
        }
    }

    fn remove_resolving_entry(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        if self.resolving_edits_blocked() {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        let mut address = [0u8; 6];
        address.copy_from_slice(&params[1..7]);
        match self.privacy.remove(params[0], address) {
            Ok(()) => {
                self.sync_adv_addr(false);
                Ok(&[][..])
            }
            Err(crate::ll::privacy::PrivacyError::NotFound) => Err(HCI_UNKNOWN_CONNECTION),
            Err(_) => Err(HCI_INVALID_PARAMETERS),
        }
    }

    fn clear_resolving_list(&mut self) -> Result<&'static [u8], u8> {
        if self.resolving_edits_blocked() {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        self.privacy.clear();
        self.sync_adv_addr(false);
        Ok(&[][..])
    }

    fn set_resolution_enable(&mut self, enable: bool) -> Result<&'static [u8], u8> {
        if self.roles_active() {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        self.privacy.set_enabled(enable);
        Ok(&[][..])
    }

    fn set_rpa_timeout(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        // Units are seconds, 1..=0x0E10 (Core 5.4 Vol 4 Part E §7.8.45).
        let seconds = u16::from_le_bytes([params[0], params[1]]);
        if !(1..=0x0e10).contains(&seconds) {
            return Err(HCI_INVALID_PARAMETERS);
        }
        self.privacy.set_timeout_us(u32::from(seconds) * 1_000_000);
        Ok(&[][..])
    }

    fn set_privacy_mode(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        let mut address = [0u8; 6];
        address.copy_from_slice(&params[1..7]);
        match self.privacy.set_mode(params[0], address, params[7]) {
            Ok(()) => Ok(&[][..]),
            Err(crate::ll::privacy::PrivacyError::NotFound) => Err(HCI_UNKNOWN_CONNECTION),
            Err(_) => Err(HCI_INVALID_PARAMETERS),
        }
    }

    /// Scan and initiator filter policies are rejected, so only an active
    /// filtered advertisement can pin the accept list.
    fn fal_busy(&self) -> bool {
        self.ll.adv.enabled && self.privacy.filter_policy() != 0
    }

    fn clear_filter_accept_list(&mut self) -> Result<&'static [u8], u8> {
        if self.fal_busy() {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        self.privacy.fal_clear();
        Ok(&[][..])
    }

    fn add_filter_accept(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        if self.fal_busy() {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        let mut address = [0u8; 6];
        address.copy_from_slice(&params[1..7]);
        match self.privacy.fal_add(params[0], address) {
            Ok(_) => Ok(&[][..]),
            Err(crate::ll::privacy::PrivacyError::NoSpace) => Err(HCI_MEMORY_CAPACITY_EXCEEDED),
            Err(_) => Err(HCI_INVALID_PARAMETERS),
        }
    }

    fn remove_filter_accept(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        if self.fal_busy() {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        let mut address = [0u8; 6];
        address.copy_from_slice(&params[1..7]);
        match self.privacy.fal_remove(params[0], address) {
            Ok(_) => Ok(&[][..]),
            Err(crate::ll::privacy::PrivacyError::NotFound) => Err(HCI_UNKNOWN_CONNECTION),
            Err(_) => Err(HCI_INVALID_PARAMETERS),
        }
    }

    /// RF event boundary: stamp the first RPA and rotate when due.
    pub fn poll_privacy(&mut self, now_us: u32) -> bool {
        let mut generated = false;
        for _ in 0..4 {
            let mut random = [0u8; 3];
            self.drbg.fill(&mut random);
            match self.privacy.poll(now_us, random) {
                Poll::Generated => {
                    generated = true;
                    break;
                }
                Poll::Idle => break,
                Poll::InvalidRandom => {}
            }
        }
        if generated {
            self.sync_adv_addr(self.ll.adv.enabled);
        }
        generated
    }

    pub fn local_rpa(&self) -> Option<[u8; 6]> {
        self.privacy.local_rpa()
    }

    /// One CONNECT_IND: policy 0 accepts and defers, policy 2 decides here.
    pub fn admit_connection(&mut self, address: [u8; 6], random: bool) -> bool {
        self.privacy.admit(address, random)
    }

    /// SCAN_REQ gate: a Network-mode peer may not scan us at its identity
    /// address (Core 5.4 Vol 6 Part B §6.2.1).
    pub fn scan_request_allowed(&self, address: [u8; 6], random: bool) -> bool {
        if random && is_resolvable(address) {
            return true;
        }
        !self.privacy.blocks_identity(u8::from(random), address)
    }

    /// Idle path: resolve the address recorded by `admit_connection`.
    pub fn resolve_pending_peer(&mut self) -> Option<(u8, [u8; 6])> {
        self.privacy.resolve_pending()
    }

    pub fn clear_pending_peer(&mut self) {
        self.privacy.clear_pending();
    }

    /// Diagnostic resolution that also counts against `PrivacyStats`.
    pub fn resolve_peer(&mut self, address: [u8; 6], random: bool) -> Option<(u8, [u8; 6])> {
        self.privacy.resolve_peer(address, random)
    }

    pub fn privacy_stats(&self) -> PrivacyStats {
        self.privacy.stats()
    }

    /// True when this identity and peer IRK are loaded in the controller.
    pub fn privacy_has_peer(&self, kind: u8, address: [u8; 6], peer_irk: &[u8; 16]) -> bool {
        self.privacy.has_peer(kind, address, peer_irk)
    }

    pub fn privacy_list_generation(&self) -> u32 {
        self.privacy.list_generation()
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

    /// Currently selected own address and whether it is random (advertising).
    pub fn own_addr(&self) -> ([u8; 6], bool) {
        (self.ll.adv.own_addr, self.ll.adv.random_addr)
    }

    /// Own address for a pending create-connection request, selected by the
    /// request's Own_Address_Type rather than by advertising state
    /// (Core 5.4 Vol 4 Part E §7.8.12).
    pub fn initiator_addr(&self, request: &CreateConnRequest) -> ([u8; 6], bool) {
        if request.own_random {
            // `create_connection` rejects this selection without a random
            // address, so the fallback is unreachable in practice.
            (self.random_addr.unwrap_or([0; 6]), true)
        } else {
            (self.bd_addr, false)
        }
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
    ///
    /// Each call moves at most one output and one input, so an always-busy
    /// link cannot starve the other one's input or output.
    pub fn pump_once(&mut self) -> bool {
        let mut progressed = false;
        if self.reset_pending && self.take_reset_done() {
            self.finish_reset();
            progressed = true;
        }
        if let Some(reply) = self.pending_reply {
            if transport::try_send_controller_packet(reply).is_err() {
                return progressed;
            }
            self.log_sent(&reply);
            self.pending_reply = None;
            progressed = true;
        }
        if self.reset_pending {
            return progressed;
        }
        // One output at most, alternating slots so neither link starves.
        for offset in 0..2 {
            let slot = (self.flush_slot + offset) % 2;
            if self.bridge_slot_mut(slot).flush_one() {
                self.flush_slot = (slot + 1) % 2;
                progressed = true;
                break;
            }
        }
        if self.dispatch_input() {
            progressed = true;
        }
        if let Some(reply) = self.pending_reply {
            if transport::try_send_controller_packet(reply).is_ok() {
                self.log_sent(&reply);
                self.pending_reply = None;
                progressed = true;
            }
        }
        progressed
    }

    /// Move one Host packet in, retrying held packets before taking new ones.
    /// A full link keeps its packet in `pending_input` without blocking the
    /// other slot.
    fn dispatch_input(&mut self) -> bool {
        for slot in 0..MAX_LINKS {
            let Some(host) = self.pending_input[slot].take() else {
                continue;
            };
            if !self.scope_current(host.scope) {
                if host.packet.kind == PacketKind::Cmd {
                    self.reject_stale_command(&host.packet);
                }
                return true;
            }
            match self.try_dispatch(host) {
                Ok(()) => return true,
                Err(host) => {
                    self.pending_input[slot] = Some(host);
                }
            }
        }
        let Some(host) = transport::try_receive_host_packet() else {
            return false;
        };
        // Keep producer order: with one channel slot, pushing the packet back
        // is lossless and the held ACL is retried on the next pump.
        if let PacketScope::Connection { key, .. } = host.scope {
            if self
                .pending_input
                .get(usize::from(key.slot))
                .is_some_and(Option::is_some)
            {
                let _ = transport::try_send_host_packet_scoped(host.packet, host.scope);
                return false;
            }
        }
        if !self.scope_current(host.scope) {
            // The producer-time link no longer exists. ACL is dropped; a
            // command the Host is awaiting still gets its unknown-connection
            // response so its command credit is not lost.
            if host.packet.kind == PacketKind::Cmd {
                self.reject_stale_command(&host.packet);
            }
            return true;
        }
        match self.try_dispatch(host) {
            Ok(()) => true,
            Err(host) => {
                let slot = match host.scope {
                    PacketScope::Connection { key, .. } => usize::from(key.slot),
                    PacketScope::Global => 0,
                };
                self.pending_input[slot] = Some(host);
                false
            }
        }
    }

    /// Apply one Host packet. `Err` means the link's TX queue is full and the
    /// caller must hold the packet.
    fn try_dispatch(&mut self, host: HostPacket) -> Result<(), HostPacket> {
        match host.packet.kind {
            PacketKind::Cmd => {
                self.handle_command(host.packet.payload());
                Ok(())
            }
            PacketKind::AclData => {
                let slot = match host.scope {
                    PacketScope::Connection { key, .. } => key.slot,
                    PacketScope::Global => 0,
                };
                match self.bridge_slot_mut(slot).enqueue_tx(&host.packet) {
                    Ok(()) | Err(BridgeError::InvalidPacket | BridgeError::NotConnected) => Ok(()),
                    Err(BridgeError::Full) => Err(host),
                    Err(_) => Ok(()),
                }
            }
            _ => Ok(()),
        }
    }

    /// True while `scope` still names the live connection. A global command
    /// is never invalidated by a link change.
    fn scope_current(&self, scope: PacketScope) -> bool {
        match scope {
            PacketScope::Global => true,
            PacketScope::Connection { handle, key } => {
                key.generation != 0 && self.live_key(handle) == Some(key)
            }
        }
    }

    /// Answer a command whose producer-time link is gone. The response class
    /// follows the command: status events for asynchronous commands.
    fn reject_stale_command(&mut self, packet: &Packet) {
        let payload = packet.payload();
        if payload.len() < 2 {
            return;
        }
        let opcode = u16::from_le_bytes([payload[0], payload[1]]);
        let reply = match opcode {
            0x0406 | 0x2019 | 0x2032 => {
                transport::command_status_packet(opcode, HCI_UNKNOWN_CONNECTION)
            }
            0x201a | 0x201b | 0x2022 | 0x2030 => error_command_complete(
                opcode,
                HCI_UNKNOWN_CONNECTION,
                payload.get(3..).unwrap_or(&[]),
            ),
            _ => return,
        };
        self.log_command(opcode, HCI_UNKNOWN_CONNECTION);
        self.pending_reply = Some(reply);
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
            let has_output = self.links().into_iter().any(ConnectionBridge::has_output);
            if self.pending_reply.is_some() || has_output {
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
        self.reset_radio_ack = true;
        self.pending_input = [None; MAX_LINKS];
        self.flush_slot = 0;
        self.event_mask = u64::MAX;
        self.le_event_mask = 0x1f;
        let (event_mask, le_event_mask) = (self.event_mask, self.le_event_mask);
        for bridge in self.links_mut() {
            bridge.set_masks(event_mask, le_event_mask);
        }
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
        self.default_phy = (0x03, 0x03);
        // Revert to the documented defaults: empty resolving and filter accept
        // lists, resolution disabled, 900 s timeout.
        self.adv_own_addr_type = OWN_ADDR_UNSET;
        self.privacy = Privacy::new();
        // `LinkLayer::new` resets AdvA to a zero random address; restore the
        // selected own address even when only a public BD_ADDR is known.
        self.sync_adv_addr(false);
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
                    let handle = u16::from_le_bytes([params[0], params[1]]);
                    self.live_key(handle)
                        .map(|key| {
                            self.bridge_slot_mut(key.slot)
                                .request_disconnect(handle, params[2])
                        })
                        .unwrap_or(HCI_UNKNOWN_CONNECTION)
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
            // LE Set PHY: async; the LL procedure answers with
            // LE PHY Update Complete.
            0x2032 => {
                let status = if params.len() == 7 {
                    self.set_phy_command(params)
                } else {
                    HCI_INVALID_PARAMETERS
                };
                self.log_command(opcode, status);
                self.pending_reply = Some(transport::command_status_packet(opcode, status));
                return;
            }
            0x0c03 if params.is_empty() => {
                if self.any_connected() {
                    self.reset_pending = true;
                    // Idle slots retire now; only the active link waits for
                    // the RF owner to stop using its buffers.
                    for bridge in self.links_mut() {
                        bridge.request_reset();
                        if !bridge.is_connected() {
                            bridge.reset_finished();
                        }
                    }
                } else if self.roles_active() {
                    // Advertising/scanning has no link to ack the stop, so the
                    // RF owner must confirm it before Reset completes. Slot 0
                    // keeps the request visible; the other slot retires now.
                    self.reset_pending = true;
                    self.reset_radio_ack = false;
                    self.bridge.request_reset();
                    self.slot1.request_reset();
                    self.slot1.reset_finished();
                } else {
                    for bridge in self.links_mut() {
                        bridge.request_reset();
                        bridge.reset_finished();
                        bridge.take_reset_done();
                    }
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
                let (event_mask, le_event_mask) = (self.event_mask, self.le_event_mask);
                for bridge in self.links_mut() {
                    bridge.set_masks(event_mask, le_event_mask);
                }
                Ok(&[][..])
            }
            // Set Event Mask Page 2
            0x0c63 if params.len() == 8 => Ok(&[][..]),
            // Set Controller To Host Flow Control — only "off" accepted.
            0x0c31 if params == [0] => Ok(&[][..]),
            0x0c31 => Err(HCI_INVALID_PARAMETERS),
            // Host Buffer Size — accept and ignore (no C→H flow control).
            0x0c33 if params.len() == 7 => Ok(&[][..]),
            // Host Number Of Completed Packets — no C→H flow control, so a
            // well-formed list never gets an event, whatever handles it names
            // (Core 5.4 Vol 4 Part E §7.3.40). Only an invalid parameter list
            // returns Command Complete; Number_Of_Handles is 0…255, so an
            // empty list is well-formed too.
            0x0c35 => {
                let handles = usize::from(params.first().copied().unwrap_or(0));
                let malformed = params.is_empty() || params.len() != 1 + 4 * handles;
                self.log_command(
                    opcode,
                    if malformed {
                        HCI_INVALID_PARAMETERS
                    } else {
                        HCI_SUCCESS
                    },
                );
                if malformed {
                    self.pending_reply = Some(transport::command_complete_packet(
                        opcode,
                        HCI_INVALID_PARAMETERS,
                        &[],
                    ));
                }
                return;
            }
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
            // LE Read PHY
            0x2030 if params.len() == 2 => {
                let handle = le16_from(params);
                let codes = self.live_key(handle).map(|key| {
                    let (tx, rx) = self.bridge_slot(key.slot).phy_codes();
                    (tx, rx)
                });
                let reply = match codes {
                    Some((tx, rx)) => transport::command_complete_packet(
                        opcode,
                        HCI_SUCCESS,
                        &[params[0], params[1], tx, rx],
                    ),
                    None => error_command_complete(opcode, HCI_UNKNOWN_CONNECTION, params),
                };
                let status = if codes.is_some() {
                    HCI_SUCCESS
                } else {
                    HCI_UNKNOWN_CONNECTION
                };
                self.log_command(opcode, status);
                self.pending_reply = Some(reply);
                return;
            }
            // LE Set Default PHY
            0x2031 if params.len() == 3 => {
                let status = self.set_default_phy_command(params[0], params[1], params[2]);
                self.log_command(opcode, status);
                self.pending_reply = Some(transport::command_complete_packet(opcode, status, &[]));
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
                    self.live_key(handle)
                        .map(|key| {
                            self.bridge_slot_mut(key.slot)
                                .request_data_length(handle, octets, time)
                        })
                        .unwrap_or(HCI_UNKNOWN_CONNECTION)
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
            // LE Set Random Address — disallowed while advertising, scanning
            // or initiating (Core 5.4 Vol 4 Part E §7.8.4).
            0x2005 if params.len() == 6 => {
                if self.ll.adv.enabled || self.scan.enabled || self.pending_connect.is_some() {
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
                if enable && !self.adv_address_available() {
                    Err(HCI_INVALID_PARAMETERS)
                } else {
                    if enable {
                        // Resolve AdvA right before use; 0x2005 normally did
                        // this already, but Hosts may skip it.
                        self.sync_adv_addr(true);
                    }
                    self.ll.adv.enabled = enable;
                    Ok(&[][..])
                }
            }
            // LE Set Scan Parameters — passive only; disallowed while scanning
            // (Core 5.4 Vol 4 Part E §7.8.10).
            0x200b if params.len() == 7 => {
                if self.scan.enabled {
                    Err(HCI_COMMAND_DISALLOWED)
                } else {
                    self.set_scan_params(params)
                }
            }
            // LE Set Scan Enable. Enabled scanning is refused only when no
            // free slot or initiator is left; the RF owner schedules the
            // window in its gaps.
            0x200c if params.len() == 2 && params.iter().all(|value| *value <= 1) => {
                let enable = params[0] != 0;
                if enable && (self.all_links_connected() || self.pending_connect.is_some()) {
                    Err(HCI_COMMAND_DISALLOWED)
                } else {
                    if enable {
                        self.sync_adv_addr(false);
                    }
                    self.scan.enabled = enable;
                    self.scan.filter_duplicates = params[1] != 0;
                    Ok(&[][..])
                }
            }
            // LE Create Connection Cancel — no pending initiation is a
            // synchronous Command Complete with Command Disallowed
            // (Core 5.4 Vol 4 Part E §7.8.13), not Command Status.
            0x200e if params.is_empty() => {
                if self.pending_connect.take().is_none() {
                    self.log_command(opcode, HCI_COMMAND_DISALLOWED);
                    self.pending_reply = Some(transport::command_complete_packet(
                        opcode,
                        HCI_COMMAND_DISALLOWED,
                        &[],
                    ));
                    return;
                }
                let _ = self.bridge.connection_failed(0x02);
                Ok(&[][..])
            }
            // Filter Accept List: size / clear / add / remove. Only the
            // connect filter (policy 2) uses it (S4b).
            0x200f if params.is_empty() => Ok(&[MAX_FILTER_ACCEPT_LIST as u8][..]),
            0x2010 if params.is_empty() => self.clear_filter_accept_list(),
            0x2011 if params.len() == 7 => self.add_filter_accept(params),
            0x2012 if params.len() == 7 => self.remove_filter_accept(params),
            0x200f | 0x2010 | 0x2011 | 0x2012 => Err(HCI_INVALID_PARAMETERS),
            // Resolving list (Core 5.4 Vol 4 Part E §7.8.38-40): add, remove,
            // clear, read size. Changes are disallowed while a role is active.
            0x2027 if params.len() == 39 => self.add_resolving_entry(params),
            0x2028 if params.len() == 7 => self.remove_resolving_entry(params),
            0x2029 if params.is_empty() => self.clear_resolving_list(),
            0x202a if params.is_empty() => Ok(&[MAX_RESOLVING_LIST as u8][..]),
            // Address resolution enable / RPA timeout / privacy mode.
            0x202d if params.len() == 1 && params[0] <= 1 => {
                self.set_resolution_enable(params[0] != 0)
            }
            0x202e if params.len() == 2 => self.set_rpa_timeout(params),
            0x204e if params.len() == 8 => self.set_privacy_mode(params),
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
            0x201a if params.len() == 18 => match self.live_key(le16_from(params)) {
                Some(key) => {
                    let mut ltk = [0u8; 16];
                    ltk.copy_from_slice(&params[2..18]);
                    self.ltk_reply[usize::from(key.slot)] = Some((key, LtkReply::Key(ltk)));
                    Ok(&params[..2])
                }
                None => Err(HCI_UNKNOWN_CONNECTION),
            },
            0x201a => Err(HCI_INVALID_PARAMETERS),
            0x201b if params.len() == 2 => match self.live_key(le16_from(params)) {
                Some(key) => {
                    self.ltk_reply[usize::from(key.slot)] = Some((key, LtkReply::Rejected));
                    Ok(&params[..2])
                }
                None => Err(HCI_UNKNOWN_CONNECTION),
            },
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
            Err(status) => error_command_complete(opcode, status, params),
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
        // ADV_IND, own address type 0..=3, channel map, and only the filter
        // policies we implement: 0 (unfiltered) and 2 (connect filter).
        if params[4] != 0
            || params[5] > 3
            || params[14] > 3
            || params[14] == 1
            || params[14] == 3
            || params[13] == 0
            || params[13] & !7 != 0
        {
            return Err(HCI_INVALID_PARAMETERS);
        }
        self.ll.adv.interval_slots = min;
        self.ll.adv.channel_map = params[13];
        self.privacy.set_filter_policy(params[14]);
        self.adv_own_addr_type = params[5];
        self.privacy.set_own_addr_type(params[5]);
        self.sync_adv_addr(false);
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
            // Scanning filter policies 1..=3 are not implemented; rejecting
            // them beats silently scanning unfiltered.
            || params[6] != 0
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
        // Only a full link set or an initiator already in flight refuses a
        // new connection; one live link must not block the other role.
        if self.all_links_connected() || self.pending_connect.is_some() {
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
        // Initiator filter policy 1 is not implemented.
        if filter_policy != 0
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
        if own_kind == 1 && self.random_addr.is_none() {
            // §7.8.12: Random own address requires an initialized random
            // address; otherwise the command is disallowed.
            return HCI_COMMAND_DISALLOWED;
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

    fn set_default_phy_command(&mut self, all_phys: u8, tx: u8, rx: u8) -> u8 {
        if all_phys & !0x03 != 0 {
            return HCI_INVALID_PARAMETERS;
        }
        let no_tx = all_phys & 0x01 != 0;
        let no_rx = all_phys & 0x02 != 0;
        // Only LE 1M and LE 2M are implemented; zero or Coded is unsupported.
        if !no_tx && (tx == 0 || tx & !0x03 != 0) {
            return HCI_UNSUPPORTED_FEATURE;
        }
        if !no_rx && (rx == 0 || rx & !0x03 != 0) {
            return HCI_UNSUPPORTED_FEATURE;
        }
        if !no_tx {
            self.default_phy.0 = tx;
        }
        if !no_rx {
            self.default_phy.1 = rx;
        }
        HCI_SUCCESS
    }

    /// `LE Set PHY` parameters: handle(2), all_phys, tx_phys, rx_phys,
    /// phy_options(2). The LL owner performs the procedure.
    fn set_phy_command(&mut self, params: &[u8]) -> u8 {
        // Without the advertised LE 2M bit the LL procedure cannot run; fail
        // here instead of accepting a request that would never complete.
        if self.le_features[1] & 1 == 0 {
            return HCI_UNSUPPORTED_FEATURE;
        }
        let handle = le16_from(params);
        let all_phys = params[2];
        let options = le16_from(&params[5..]);
        if all_phys & !0x03 != 0 {
            return HCI_INVALID_PARAMETERS;
        }
        // Phy_Options is a Coded coding preference; Core 5.4 7.8.49 allows
        // it even without Coded in the masks. Only reserved bits fail.
        if options & !0x03 != 0 {
            return HCI_INVALID_PARAMETERS;
        }
        let no_tx = all_phys & 0x01 != 0;
        let no_rx = all_phys & 0x02 != 0;
        if no_tx && no_rx {
            // Nothing to negotiate: report the current PHYs immediately.
            return self
                .live_key(handle)
                .map(|key| self.bridge_slot_mut(key.slot).complete_phy_now(handle))
                .unwrap_or(HCI_UNKNOWN_CONNECTION);
        }
        // "No preference" covers every supported PHY (Core 5.4 7.8.49): Set
        // PHY overrides the Set Default PHY masks, so they do not apply.
        let tx = if no_tx { 0x03 } else { params[3] };
        let rx = if no_rx { 0x03 } else { params[4] };
        if tx == 0 || tx & !0x03 != 0 || rx == 0 || rx & !0x03 != 0 {
            return HCI_UNSUPPORTED_FEATURE;
        }
        self.live_key(handle)
            .map(|key| self.bridge_slot_mut(key.slot).request_phy(handle, tx, rx))
            .unwrap_or(HCI_UNKNOWN_CONNECTION)
    }

    fn enable_encryption(&mut self, params: &[u8]) -> u8 {
        // Connection_Handle 2 + Random_Number 8 + Encrypted_Diversifier 2 +
        // Long_Term_Key 16 = 28 octets (Core 5.4 Vol 4 Part E §7.8.24).
        if params.len() != 28 {
            return HCI_INVALID_PARAMETERS;
        }
        let handle = le16_from(params);
        let Some(key) = self.live_key(handle) else {
            return HCI_UNKNOWN_CONNECTION;
        };
        let bridge = self.bridge_slot(key.slot);
        if bridge.is_disconnecting() {
            return HCI_UNKNOWN_CONNECTION;
        }
        // Only the Central starts encryption; a Peripheral waits for
        // LL_ENC_REQ and raises LE LTK Request instead.
        if bridge.role() != Some(crate::ll::Role::Central) {
            return HCI_COMMAND_DISALLOWED;
        }
        // A request already queued for this link must not be silently
        // replaced; a stale one from an earlier generation is overwritten.
        let slot = usize::from(key.slot);
        if self.pending_encryption[slot].is_some_and(|(tagged, _)| tagged == key) {
            return HCI_COMMAND_DISALLOWED;
        }
        let mut rand = [0u8; 8];
        rand.copy_from_slice(&params[2..10]);
        let mut ltk = [0u8; 16];
        ltk.copy_from_slice(&params[12..28]);
        self.pending_encryption[slot] = Some((
            key,
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

/// Error Command Complete for a command whose return parameters start with a
/// connection handle. §4.5 requires that handle to be echoed on errors too.
fn error_command_complete(opcode: u16, status: u8, params: &[u8]) -> Packet {
    let echo: &[u8] = if matches!(opcode, 0x201a | 0x201b | 0x2022 | 0x2030) && params.len() >= 2 {
        &params[..2]
    } else {
        &[]
    };
    transport::command_complete_packet(opcode, status, echo)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use bt_hci::transport::PacketKind;

    /// Global HCI channels are shared; serialize tests that touch them.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::hci::test_lock::lock()
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
            peer_rpa: None,
            local_rpa: None,
            peer_identity: None,
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
    fn data_length_requests_are_taken_per_link() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);

        inject_cmd(0x2022, &[1, 0, 0xf7, 0, 0x48, 0x08]);
        assert!(runner.pump_once());
        expect_command_complete(0x2022, HCI_SUCCESS, &[1, 0]);
        inject_cmd(0x2022, &[2, 0, 0xfa, 0, 0x40, 0x06]);
        assert!(runner.pump_once());
        expect_command_complete(0x2022, HCI_SUCCESS, &[2, 0]);

        // Each link keeps its own request; the N=1 entry is slot 0 only.
        assert_eq!(runner.take_data_length_request_on(1), Some((250, 1600)));
        assert_eq!(runner.take_data_length_request(), Some((247, 2120)));
        assert_eq!(runner.take_data_length_request_on(1), None);
        assert_eq!(runner.take_data_length_request_on(5), None);
    }

    #[test]
    fn resolving_list_commands_track_real_entries() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        let mut add = [0u8; 39];
        add[1..7].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        add[7..23].fill(0x11);
        add[23..39].fill(0x22);

        pollster::block_on(async {
            inject_cmd(0x202a, &[]);
            runner.serve_one().await;
            expect_command_complete(0x202a, HCI_SUCCESS, &[8]);

            inject_cmd(0x2027, &add);
            runner.serve_one().await;
            expect_command_complete(0x2027, HCI_SUCCESS, &[]);
            assert_eq!(runner.privacy_stats().list_len, 1);

            // Same four parameters: idempotent.
            inject_cmd(0x2027, &add);
            runner.serve_one().await;
            expect_command_complete(0x2027, HCI_SUCCESS, &[]);
            assert_eq!(runner.privacy_stats().list_len, 1);

            let mut mode = [0u8; 8];
            mode[1..7].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
            mode[7] = 1;
            inject_cmd(0x204e, &mode);
            runner.serve_one().await;
            expect_command_complete(0x204e, HCI_SUCCESS, &[]);
            mode[7] = 2;
            inject_cmd(0x204e, &mode);
            runner.serve_one().await;
            expect_command_complete(0x204e, HCI_INVALID_PARAMETERS, &[]);
            mode[1] = 9;
            mode[7] = 0;
            inject_cmd(0x204e, &mode);
            runner.serve_one().await;
            expect_command_complete(0x204e, HCI_UNKNOWN_CONNECTION, &[]);

            // RPA timeout is in seconds: 16 is the minimum, 0 is invalid.
            inject_cmd(0x202e, &[0x10, 0x00]);
            runner.serve_one().await;
            expect_command_complete(0x202e, HCI_SUCCESS, &[]);
            inject_cmd(0x202e, &[0, 0]);
            runner.serve_one().await;
            expect_command_complete(0x202e, HCI_INVALID_PARAMETERS, &[]);

            let mut remove = [0u8; 7];
            remove[1..7].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
            inject_cmd(0x2028, &remove);
            runner.serve_one().await;
            expect_command_complete(0x2028, HCI_SUCCESS, &[]);
            inject_cmd(0x2028, &remove);
            runner.serve_one().await;
            expect_command_complete(0x2028, HCI_UNKNOWN_CONNECTION, &[]);

            inject_cmd(0x202d, &[1]);
            runner.serve_one().await;
            expect_command_complete(0x202d, HCI_SUCCESS, &[]);
            inject_cmd(0x202d, &[2]);
            runner.serve_one().await;
            expect_command_complete(0x202d, HCI_INVALID_PARAMETERS, &[]);
        });
    }

    #[test]
    fn reset_clears_privacy_state() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        let mut add = [0u8; 39];
        add[1..7].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        add[7..23].fill(0x11);
        add[23..39].fill(0x22);
        let fal = [0, 7, 8, 9, 10, 11, 12];

        pollster::block_on(async {
            for (opcode, params) in [(0x2027, &add[..]), (0x202d, &[1u8][..]), (0x2011, &fal[..])] {
                inject_cmd(opcode, params);
                runner.serve_one().await;
                expect_command_complete(opcode, HCI_SUCCESS, &[]);
            }
            let before = runner.privacy_stats();
            assert_eq!(before.list_len, 1);
            assert_ne!(
                before.flags & crate::ll::privacy::flags::RESOLUTION_ENABLED,
                0
            );
            assert_ne!(before.flags & crate::ll::privacy::flags::FAL_NONEMPTY, 0);

            inject_cmd(0x0c03, &[]);
            runner.serve_one().await;
            expect_command_complete(0x0c03, HCI_SUCCESS, &[]);

            let after = runner.privacy_stats();
            assert_eq!(after.list_len, 0);
            assert_eq!(
                after.flags
                    & (crate::ll::privacy::flags::RESOLUTION_ENABLED
                        | crate::ll::privacy::flags::FAL_NONEMPTY),
                0
            );
        });
    }

    #[test]
    fn close_drops_link_state_but_reset_clears_global_configuration() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let fal = [0, 7, 8, 9, 10, 11, 12];

        pollster::block_on(async {
            inject_cmd(0x2011, &fal);
            runner.serve_one().await;
            expect_command_complete(0x2011, HCI_SUCCESS, &[]);
            open(&mut runner);
            let mut ltk = [0u8; 18];
            ltk[0..2].copy_from_slice(&1u16.to_le_bytes());
            ltk[2..].fill(0x33);
            inject_cmd(0x201a, &ltk);
            runner.serve_one().await;
            expect_command_complete(0x201a, HCI_SUCCESS, &[1, 0]);
            runner.bridge.enqueue_tx(&acl(1, 0, &[1])).unwrap();

            runner.connection_closed(0x13);
            assert!(!runner.bridge.is_connected());
            assert!(runner.take_ltk_reply().is_none());
            // Global configuration survives a link close.
            assert_ne!(
                runner.privacy_stats().flags & crate::ll::privacy::flags::FAL_NONEMPTY,
                0
            );
            // The closed link's queued ACL must not reach a new link.
            runner.bridge.connected(connection_info()).unwrap();
            assert!(runner.bridge.take_tx_acl().is_none());
            runner.connection_closed(0x14);

            // Flush the close events before the reset reply.
            while runner.pump_once() {}
            while transport::try_receive_controller_packet().is_some() {}
            inject_cmd(0x0c03, &[]);
            runner.serve_one().await;
            expect_command_complete(0x0c03, HCI_SUCCESS, &[]);
            assert_eq!(
                runner.privacy_stats().flags & crate::ll::privacy::flags::FAL_NONEMPTY,
                0
            );
        });
    }

    #[test]
    fn resolving_list_edits_are_disallowed_while_active() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        pollster::block_on(async {
            inject_cmd(0x202d, &[1]);
            runner.serve_one().await;
            expect_command_complete(0x202d, HCI_SUCCESS, &[]);
            runner.ll.adv.enabled = true;
            for (opcode, params) in [
                (0x2027, &[0u8; 39][..]),
                (0x2028, &[0u8; 7][..]),
                (0x2029, &[][..]),
                (0x202d, &[0u8][..]),
            ] {
                inject_cmd(opcode, params);
                runner.serve_one().await;
                expect_command_complete(opcode, HCI_COMMAND_DISALLOWED, &[]);
            }
        });
    }

    #[test]
    fn resolving_list_edits_are_allowed_while_resolution_is_off() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.ll.adv.enabled = true;

        let mut add = [0u8; 39];
        add[1..7].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        add[7..23].fill(0x11);
        add[23..39].fill(0x22);

        pollster::block_on(async {
            inject_cmd(0x2027, &add);
            runner.serve_one().await;
            expect_command_complete(0x2027, HCI_SUCCESS, &[]);
            assert_eq!(runner.privacy_stats().list_len, 1);

            inject_cmd(0x2029, &[]);
            runner.serve_one().await;
            expect_command_complete(0x2029, HCI_SUCCESS, &[]);
            assert_eq!(runner.privacy_stats().list_len, 0);
        });
    }

    #[test]
    fn scan_request_from_a_network_mode_identity_is_ignored() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        let mut add = [0u8; 39];
        add[1..7].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        add[7..23].fill(0x11);
        add[23..39].fill(0x22);

        pollster::block_on(async {
            inject_cmd(0x2027, &add);
            runner.serve_one().await;
            expect_command_complete(0x2027, HCI_SUCCESS, &[]);

            assert!(!runner.scan_request_allowed([1, 2, 3, 4, 5, 6], false));
            assert!(runner.scan_request_allowed([9; 6], false));
            assert!(runner.scan_request_allowed([1, 2, 3, 4, 5, 0x46], true));
        });
    }

    #[test]
    fn first_advertising_frame_is_the_local_rpa() {
        // Spec §16.2.11: the offline hard proof is the PDU the RF owner sends,
        // not a sniffer capture. Own type 2 must already advertise an RPA in
        // the very first frame, with no identity-address frame in between.
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        // The Host seeds the local IRK through the default resolving-list entry
        // (zero peer identity), exactly like Trouble's full sync.
        let mut add = [0u8; 39];
        add[23..39].fill(0x22);

        let mut params = [0u8; 15];
        params[0..4].copy_from_slice(&[0x20, 0x00, 0x20, 0x00]);
        params[5] = 2;
        params[13] = 0x07;
        let mut adv = [0u8; 32];
        adv[0] = 3;
        adv[1..4].copy_from_slice(&[0x02, 0x01, 0x06]);

        pollster::block_on(async {
            inject_cmd(0x2027, &add);
            runner.serve_one().await;
            expect_command_complete(0x2027, HCI_SUCCESS, &[]);

            inject_cmd(0x2006, &params);
            runner.serve_one().await;
            expect_command_complete(0x2006, HCI_SUCCESS, &[]);
            inject_cmd(0x2008, &adv);
            runner.serve_one().await;
            expect_command_complete(0x2008, HCI_SUCCESS, &[]);
            inject_cmd(0x200a, &[1]);
            runner.serve_one().await;
            expect_command_complete(0x200a, HCI_SUCCESS, &[]);

            let rpa = runner.local_rpa().expect("own type 2 needs a local RPA");
            let mut pdu = [0u8; 40];
            let n = runner.build_adv_pdu(&mut pdu).unwrap();
            assert_eq!(n, 2 + 6 + 3);
            assert_eq!(pdu[0], 0x40);
            assert_eq!(&pdu[2..8], &rpa);
            assert_eq!(rpa[5] & 0xc0, 0x40, "prand top bits must be 01");
            assert_eq!(&pdu[8..11], &[0x02, 0x01, 0x06]);

            let stats = runner.privacy_stats();
            assert_eq!(stats.generations, 1);
            assert!(stats.flags & crate::ll::privacy::flags::ADV_USES_RPA != 0);
            assert_eq!(
                stats.flags & crate::ll::privacy::flags::IDENTITY_FALLBACK,
                0
            );
        });
    }

    #[test]
    fn filter_accept_list_commands_report_real_status() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let mut member = [0u8; 7];
        member[1..7].copy_from_slice(&[7, 7, 7, 7, 7, 7]);

        pollster::block_on(async {
            inject_cmd(0x200f, &[]);
            runner.serve_one().await;
            expect_command_complete(0x200f, HCI_SUCCESS, &[8]);

            inject_cmd(0x2011, &member);
            runner.serve_one().await;
            expect_command_complete(0x2011, HCI_SUCCESS, &[]);
            // Adding an existing member is not an error.
            inject_cmd(0x2011, &member);
            runner.serve_one().await;
            expect_command_complete(0x2011, HCI_SUCCESS, &[]);

            inject_cmd(0x2012, &member);
            runner.serve_one().await;
            expect_command_complete(0x2012, HCI_SUCCESS, &[]);
            inject_cmd(0x2012, &member);
            runner.serve_one().await;
            expect_command_complete(0x2012, HCI_UNKNOWN_CONNECTION, &[]);

            inject_cmd(0x2011, &member);
            runner.serve_one().await;
            expect_command_complete(0x2011, HCI_SUCCESS, &[]);
            inject_cmd(0x2010, &[]);
            runner.serve_one().await;
            expect_command_complete(0x2010, HCI_SUCCESS, &[]);
        });
    }
    #[test]
    fn filter_accept_list_rejects_bad_lengths_identities_and_overflow() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            for (opcode, params) in [
                (0x200f, &[0u8][..]),
                (0x2010, &[0u8][..]),
                (0x2011, &[0u8; 6][..]),
                (0x2012, &[0u8; 8][..]),
            ] {
                inject_cmd(opcode, params);
                runner.serve_one().await;
                expect_command_complete(opcode, HCI_INVALID_PARAMETERS, &[]);
            }

            // Identity kinds 0 and 1 only; a random identity must be static.
            inject_cmd(0x2011, &[2, 1, 2, 3, 4, 5, 6]);
            runner.serve_one().await;
            expect_command_complete(0x2011, HCI_INVALID_PARAMETERS, &[]);
            inject_cmd(0x2011, &[1, 1, 2, 3, 4, 5, 0x40]);
            runner.serve_one().await;
            expect_command_complete(0x2011, HCI_INVALID_PARAMETERS, &[]);
            inject_cmd(0x2012, &[1, 1, 2, 3, 4, 5, 0x40]);
            runner.serve_one().await;
            expect_command_complete(0x2012, HCI_INVALID_PARAMETERS, &[]);

            for n in 0..8u8 {
                inject_cmd(0x2011, &[0, n, 0, 0, 0, 0, 0]);
                runner.serve_one().await;
                expect_command_complete(0x2011, HCI_SUCCESS, &[]);
            }
            inject_cmd(0x2011, &[0, 9, 0, 0, 0, 0, 0]);
            runner.serve_one().await;
            expect_command_complete(0x2011, HCI_MEMORY_CAPACITY_EXCEEDED, &[]);
        });
    }

    #[test]
    fn advertising_filter_policy_accepts_only_zero_and_two() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let mut params = [0u8; 15];
        params[0..2].copy_from_slice(&0x00a0u16.to_le_bytes());
        params[2..4].copy_from_slice(&0x00a0u16.to_le_bytes());
        params[13] = 0x07;

        pollster::block_on(async {
            for policy in [0u8, 2] {
                params[14] = policy;
                inject_cmd(0x2006, &params);
                runner.serve_one().await;
                expect_command_complete(0x2006, HCI_SUCCESS, &[]);
                assert_eq!(runner.privacy.filter_policy(), policy);
            }
            for policy in [1u8, 3, 4] {
                params[14] = policy;
                inject_cmd(0x2006, &params);
                runner.serve_one().await;
                expect_command_complete(0x2006, HCI_INVALID_PARAMETERS, &[]);
                // A rejected policy must not disturb the stored one.
                assert_eq!(runner.privacy.filter_policy(), 2);
            }
        });
    }

    #[test]
    fn fal_edits_are_disallowed_only_during_filtered_advertising() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let member = [0, 1, 2, 3, 4, 5, 0];
        let mut params = [0u8; 15];
        params[0..2].copy_from_slice(&0x00a0u16.to_le_bytes());
        params[2..4].copy_from_slice(&0x00a0u16.to_le_bytes());
        params[13] = 0x07;

        pollster::block_on(async {
            params[14] = 0; // unfiltered advertising does not pin the list
            inject_cmd(0x2006, &params);
            runner.serve_one().await;
            expect_command_complete(0x2006, HCI_SUCCESS, &[]);
            inject_cmd(0x200a, &[1]);
            runner.serve_one().await;
            expect_command_complete(0x200a, HCI_SUCCESS, &[]);
            inject_cmd(0x2011, &member);
            runner.serve_one().await;
            expect_command_complete(0x2011, HCI_SUCCESS, &[]);
            inject_cmd(0x200a, &[0]);
            runner.serve_one().await;
            expect_command_complete(0x200a, HCI_SUCCESS, &[]);

            params[14] = 2;
            inject_cmd(0x2006, &params);
            runner.serve_one().await;
            expect_command_complete(0x2006, HCI_SUCCESS, &[]);
            inject_cmd(0x200a, &[1]);
            runner.serve_one().await;
            expect_command_complete(0x200a, HCI_SUCCESS, &[]);

            for (opcode, bytes) in [
                (0x2010, &[][..]),
                (0x2011, &member[..]),
                (0x2012, &member[..]),
            ] {
                inject_cmd(opcode, bytes);
                runner.serve_one().await;
                expect_command_complete(opcode, HCI_COMMAND_DISALLOWED, &[]);
            }
            // The size is still readable while advertising.
            inject_cmd(0x200f, &[]);
            runner.serve_one().await;
            expect_command_complete(0x200f, HCI_SUCCESS, &[8]);

            inject_cmd(0x200a, &[0]);
            runner.serve_one().await;
            expect_command_complete(0x200a, HCI_SUCCESS, &[]);
            inject_cmd(0x2010, &[]);
            runner.serve_one().await;
            expect_command_complete(0x2010, HCI_SUCCESS, &[]);
        });
    }

    #[test]
    fn scan_filter_policies_are_rejected() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let mut params = scan_params();

        pollster::block_on(async {
            for policy in 1u8..=3 {
                params[6] = policy;
                inject_cmd(0x200b, &params);
                runner.serve_one().await;
                expect_command_complete(0x200b, HCI_INVALID_PARAMETERS, &[]);
            }
            params[6] = 0;
            inject_cmd(0x200b, &params);
            runner.serve_one().await;
            expect_command_complete(0x200b, HCI_SUCCESS, &[]);
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
        // The same pump completes Reset and dispatches the command queued
        // behind it; both replies are now in the channel.
        assert!(runner.pump_once());
        expect_command_complete(0x0c03, 0, &[]);
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
    fn le_set_phy_queues_one_procedure_and_reports_completion() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_le_features(crate::ll::ctrl::feature_bits(&[
            crate::ll::ctrl::FEATURE_LE_2M_PHY,
        ]));
        open(&mut runner);
        runner.bridge.set_masks(u64::MAX, 0x1f | (1 << 11));
        // handle 1, all_phys 0, TX 2M, RX 2M, options 0.
        inject_cmd(0x2032, &[1, 0, 0, 0x02, 0x02, 0, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0, 1, 0x32, 0x20]
        );
        assert_eq!(runner.bridge.take_phy_request(), Some((2, 2)));
        // A second command cannot overwrite the live procedure.
        inject_cmd(0x2032, &[1, 0, 0, 0x02, 0x02, 0, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0x0c, 1, 0x32, 0x20]
        );
        assert_eq!(runner.bridge.take_phy_request(), None);
        // The LL owner completes it; LE Read PHY reports the new codes.
        assert!(runner.phy_update_complete_on(1, 0, 2, 2));
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x3e, 6, 0x0c, 0, 1, 0, 2, 2]
        );
        inject_cmd(0x2030, &[1, 0]);
        assert!(runner.pump_once());
        expect_command_complete(0x2030, 0, &[1, 0, 2, 2]);
        // The procedure is done, so another request is accepted.
        inject_cmd(0x2032, &[1, 0, 0, 0x01, 0x01, 0, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0, 1, 0x32, 0x20]
        );
    }

    #[test]
    fn le_set_phy_requires_the_2m_feature_bit() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        inject_cmd(0x2032, &[1, 0, 0, 0x02, 0x02, 0, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0x11, 1, 0x32, 0x20]
        );
        assert_eq!(runner.bridge.take_phy_request(), None);
    }

    #[test]
    fn le_phy_commands_validate_masks_and_the_handle() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_le_features(crate::ll::ctrl::feature_bits(&[
            crate::ll::ctrl::FEATURE_LE_2M_PHY,
        ]));
        open(&mut runner);
        runner.bridge.set_masks(u64::MAX, 0x1f | (1 << 11));

        // Unknown handle: Read PHY echoes it, Set PHY reports 0x02.
        inject_cmd(0x2030, &[9, 0]);
        assert!(runner.pump_once());
        expect_command_complete(0x2030, 0x02, &[9, 0]);
        inject_cmd(0x2032, &[9, 0, 0, 0x02, 0x02, 0, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0x02, 1, 0x32, 0x20]
        );
        // Coded PHY in the mask is unsupported (Core 5.4 7.8.49: 0x11).
        inject_cmd(0x2032, &[1, 0, 0, 0x04, 0x02, 0, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0x11, 1, 0x32, 0x20]
        );
        // A Coded coding preference is legal even without Coded in the masks
        // (Core 5.4 7.8.49); reserved option bits are invalid parameters.
        inject_cmd(0x2032, &[1, 0, 0, 0x02, 0x02, 0x01, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0, 1, 0x32, 0x20]
        );
        assert_eq!(runner.bridge.take_phy_request(), Some((2, 2)));
        // End that procedure before the next command; its event is masked.
        runner.bridge.set_masks(u64::MAX, 0x7ff & !(1 << 11));
        runner.bridge.phy_update_complete(0, 2, 2).unwrap();
        inject_cmd(0x2032, &[1, 0, 0, 0x02, 0x02, 0x04, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0x12, 1, 0x32, 0x20]
        );
        // Set Default PHY: a zero mask without "no preference" is unsupported.
        inject_cmd(0x2031, &[0, 0, 0x02]);
        assert!(runner.pump_once());
        expect_command_complete(0x2031, 0x11, &[]);
        // A 2M default must not leak into a Set PHY "no preference"
        // direction: that covers every PHY the controller supports.
        inject_cmd(0x2031, &[0, 0x02, 0x02]);
        assert!(runner.pump_once());
        expect_command_complete(0x2031, 0, &[]);
        inject_cmd(0x2032, &[1, 0, 0x01, 0, 0x02, 0, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0, 1, 0x32, 0x20]
        );
        assert_eq!(runner.bridge.take_phy_request(), Some((0x03, 0x02)));
        runner.bridge.set_masks(u64::MAX, 0x7ff & !(1 << 11));
        runner.bridge.phy_update_complete(0, 2, 2).unwrap();

        // Both directions "no preference": no procedure, current PHYs reported.
        inject_cmd(0x2032, &[1, 0, 0x03, 0, 0, 0, 0]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0, 1, 0x32, 0x20]
        );
        assert_eq!(runner.bridge.take_phy_request(), None);
        // The completion event was masked off, so it is not queued.
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

    fn scoped_cmd(opcode: u16, params: &[u8], key: transport::LinkKey) -> Packet {
        let mut bytes = [0u8; transport::HCI_PACKET_CAPACITY];
        bytes[0..2].copy_from_slice(&opcode.to_le_bytes());
        bytes[2] = params.len() as u8;
        bytes[3..3 + params.len()].copy_from_slice(params);
        let packet = Packet::from_bytes(PacketKind::Cmd, &bytes[..3 + params.len()]).unwrap();
        transport::try_send_host_packet_scoped(
            packet,
            transport::PacketScope::Connection { handle: 1, key },
        )
        .unwrap();
        packet
    }

    fn reopen_with_a_new_generation(runner: &mut SoftRunner) -> transport::LinkKey {
        let old = runner.bridge.link_key();
        runner.bridge.disconnected(0x13);
        assert!(runner.pump_once());
        transport::try_receive_controller_packet().unwrap();
        runner.bridge.connected(connection_info()).unwrap();
        assert!(runner.pump_once());
        transport::try_receive_controller_packet().unwrap();
        assert_ne!(old, runner.bridge.link_key());
        old
    }

    #[test]
    fn stale_ltk_reply_is_answered_not_applied_after_handle_reuse() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        let old = reopen_with_a_new_generation(&mut runner);

        let mut params = [0u8; 18];
        params[0..2].copy_from_slice(&1u16.to_le_bytes());
        params[2..18].copy_from_slice(&[0x5a; 16]);
        scoped_cmd(0x201a, &params, old);
        assert!(runner.pump_once());
        // §4.5: the handle follows Status even on an error response.
        expect_command_complete(0x201a, HCI_UNKNOWN_CONNECTION, &[1, 0]);
        assert!(runner.ltk_reply.iter().all(Option::is_none));
    }

    #[test]
    fn stale_disconnect_and_set_data_length_keep_their_response_shape() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        let old = reopen_with_a_new_generation(&mut runner);

        scoped_cmd(0x0406, &[1, 0, 0x13], old);
        assert!(runner.pump_once());
        expect_command_status(0x0406, HCI_UNKNOWN_CONNECTION);
        assert!(runner.bridge.take_radio_request().is_none());

        scoped_cmd(0x2022, &[1, 0, 0xf7, 0, 0x48, 0x08], old);
        assert!(runner.pump_once());
        expect_command_complete(0x2022, HCI_UNKNOWN_CONNECTION, &[1, 0]);
        assert!(runner.bridge.take_data_length_request().is_none());
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
        assert_eq!(
            runner.initiator_addr(&request),
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
    fn cancel_without_pending_is_command_complete() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            inject_cmd(0x200e, &[]);
            runner.serve_one().await;
            expect_command_complete(0x200e, HCI_COMMAND_DISALLOWED, &[]);
        });
    }

    #[test]
    fn one_connected_link_still_allows_scanning_and_initiating() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_random_addr([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x21]);
        runner.bridge.connected(connection_info()).unwrap();
        drain_controller(&mut runner);

        pollster::block_on(async {
            inject_cmd(0x200c, &[1, 0]);
            runner.serve_one().await;
            expect_command_complete(0x200c, HCI_SUCCESS, &[]);
            assert!(runner.scan_state().enabled);

            inject_cmd(0x200d, &create_params([1, 2, 3, 4, 5, 6]));
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_SUCCESS);
        });
        assert!(runner.pending_connect().is_some());
    }

    #[test]
    fn a_full_link_set_refuses_scanning_and_initiating() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_random_addr([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x21]);
        connect_two(&mut runner);

        pollster::block_on(async {
            inject_cmd(0x200c, &[1, 0]);
            runner.serve_one().await;
            expect_command_complete(0x200c, HCI_COMMAND_DISALLOWED, &[]);
            assert!(!runner.scan_state().enabled);

            inject_cmd(0x200d, &create_params([1, 2, 3, 4, 5, 6]));
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_COMMAND_DISALLOWED);
        });
        assert!(runner.pending_connect().is_none());
    }

    #[test]
    fn scan_state_rejects_address_and_scan_parameter_changes() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_random_addr([0x21, 0x00, 0x00, 0xEE, 0xFF, 0xC1]);

        pollster::block_on(async {
            inject_cmd(0x200b, &scan_params());
            runner.serve_one().await;
            expect_command_complete(0x200b, HCI_SUCCESS, &[]);

            inject_cmd(0x200c, &[1, 0]);
            runner.serve_one().await;
            expect_command_complete(0x200c, HCI_SUCCESS, &[]);

            // While scanning: neither the scan parameters nor the random
            // address may change (§7.8.4, §7.8.10).
            inject_cmd(0x200b, &scan_params());
            runner.serve_one().await;
            expect_command_complete(0x200b, HCI_COMMAND_DISALLOWED, &[]);

            inject_cmd(0x2005, &[0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x22]);
            runner.serve_one().await;
            expect_command_complete(0x2005, HCI_COMMAND_DISALLOWED, &[]);
        });
    }

    #[test]
    fn random_address_is_rejected_while_initiating() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_random_addr([0x21, 0x00, 0x00, 0xEE, 0xFF, 0xC1]);

        pollster::block_on(async {
            inject_cmd(0x200d, &create_params([1, 2, 3, 4, 5, 6]));
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_SUCCESS);

            inject_cmd(0x2005, &[0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x22]);
            runner.serve_one().await;
            expect_command_complete(0x2005, HCI_COMMAND_DISALLOWED, &[]);
        });
    }

    #[test]
    fn public_own_address_survives_reset_and_selects_initiator_addr() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let public = [9, 8, 7, 6, 5, 4];
        runner.set_bd_addr(public);

        pollster::block_on(async {
            inject_cmd(0x0c03, &[]);
            runner.serve_one().await;
            expect_command_complete(0x0c03, HCI_SUCCESS, &[]);
        });
        assert_eq!(runner.own_addr(), (public, false));

        let mut params = create_params([1, 2, 3, 4, 5, 6]);
        params[12] = 0; // Own_Address_Type = Public
        pollster::block_on(async {
            inject_cmd(0x200d, &params);
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_SUCCESS);
        });
        let request = runner.pending_connect().unwrap();
        assert!(!request.own_random);
        assert_eq!(runner.initiator_addr(&request), (public, false));
    }

    #[test]
    fn random_own_address_requires_an_initialized_random_address() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            // `create_params` selects Own_Address_Type = Random (1).
            inject_cmd(0x200d, &create_params([1, 2, 3, 4, 5, 6]));
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_COMMAND_DISALLOWED);
        });
        assert!(runner.pending_connect().is_none());
    }

    #[test]
    fn completed_packets_is_silent_unless_malformed() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        // Well-formed, but no connection exists: no event at all.
        inject_cmd(0x0c35, &[1, 0x01, 0x00, 0x00, 0x00]);
        assert!(runner.pump_once());
        assert!(transport::try_receive_controller_packet().is_none());

        // Connected, and the handle matches: still no event on success, so
        // the Host cannot mistake the reply for a completed command.
        runner.bridge.connected(connection_info()).unwrap();
        assert!(runner.pump_once()); // flush the queued LE Connection Complete
        transport::drain_channels_for_test();
        inject_cmd(0x0c35, &[1, 0x01, 0x00, 0x00, 0x00]);
        assert!(runner.pump_once());
        assert!(transport::try_receive_controller_packet().is_none());

        // An empty list is well-formed (Number_Of_Handles is 0…255).
        inject_cmd(0x0c35, &[0]);
        assert!(runner.pump_once());
        assert!(transport::try_receive_controller_packet().is_none());

        // A malformed parameter list still gets an error response.
        inject_cmd(0x0c35, &[2, 0x01, 0x00, 0x00, 0x00]);
        assert!(runner.pump_once());
        expect_command_complete(0x0c35, HCI_INVALID_PARAMETERS, &[]);
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
            expect_command_complete(0x201a, HCI_UNKNOWN_CONNECTION, &[2, 0]);

            inject_cmd(0x201b, &[2, 0]);
            runner.serve_one().await;
            expect_command_complete(0x201b, HCI_UNKNOWN_CONNECTION, &[2, 0]);
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
        assert_eq!(
            runner.bridge.encryption_change(1, 0, 1),
            Err(BridgeError::Full)
        );
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

    fn info_h(handle: u16) -> super::super::connection::ConnectionInfo {
        super::super::connection::ConnectionInfo {
            handle,
            ..connection_info()
        }
    }

    fn connect_two(runner: &mut SoftRunner) {
        runner.bridge_slot_mut(0).connected(info_h(1)).unwrap();
        runner.bridge_slot_mut(1).connected(info_h(2)).unwrap();
        drain_controller(runner);
    }

    #[test]
    fn two_slots_share_the_handle_namespace_but_keep_separate_tags() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.bridge_slot_mut(0).connected(info_h(1)).unwrap();
        assert_eq!(
            runner.bridge_slot_mut(1).connected(info_h(1)),
            Err(BridgeError::InvalidPacket)
        );
        runner.bridge_slot_mut(1).connected(info_h(2)).unwrap();
        drain_controller(&mut runner);

        runner
            .bridge_slot_mut(0)
            .enqueue_tx(&acl(1, 0, &[0x11]))
            .unwrap();
        runner
            .bridge_slot_mut(1)
            .enqueue_tx(&acl(2, 0, &[0x22]))
            .unwrap();
        let t0 = runner.bridge_slot_mut(0).take_tx_acl().unwrap().tag;
        let t1 = runner.bridge_slot_mut(1).take_tx_acl().unwrap().tag;
        assert!(!runner.bridge_slot_mut(1).ack_tx(t0));
        assert!(!runner.bridge_slot_mut(0).ack_tx(t1));
        assert!(runner.bridge_slot_mut(0).ack_tx(t0));
        assert!(runner.bridge_slot_mut(1).ack_tx(t1));
    }

    #[test]
    fn closing_one_link_keeps_the_other_links_state() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        runner
            .bridge_slot_mut(0)
            .enqueue_tx(&acl(1, 0, &[1]))
            .unwrap();
        runner
            .bridge_slot_mut(1)
            .enqueue_tx(&acl(2, 0, &[2]))
            .unwrap();
        let t1 = runner.bridge_slot_mut(1).take_tx_acl().unwrap().tag;
        assert!(runner.push_ltk_request_on(2, [7; 8], 0));

        // Host answers slot 1's LTK request.
        let mut cmd = [0u8; 21];
        cmd[0..2].copy_from_slice(&0x201au16.to_le_bytes());
        cmd[2] = 18;
        cmd[3..5].copy_from_slice(&2u16.to_le_bytes());
        cmd[5..21].copy_from_slice(&[0x44; 16]);
        runner.handle_command(&cmd);

        let key0 = runner.bridge_slot(0).link_key();
        let key1 = runner.bridge_slot(1).link_key();
        runner.connection_closed_on(key0, 0x13);

        assert!(!runner.bridge_slot(0).is_connected());
        assert!(runner.bridge_slot(1).is_connected());
        assert!(runner.bridge_slot_mut(1).ack_tx(t1));
        assert_eq!(
            runner.take_ltk_reply_for(key1),
            Some(LtkReply::Key([0x44; 16]))
        );
    }

    #[test]
    fn a_stale_close_does_not_touch_a_reused_handle() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.bridge_slot_mut(0).connected(info_h(1)).unwrap();
        let old = runner.bridge_slot(0).link_key();
        runner.connection_closed_on(old, 0x13);

        runner.bridge_slot_mut(0).connected(info_h(1)).unwrap();
        runner
            .bridge_slot_mut(0)
            .enqueue_tx(&acl(1, 0, &[9]))
            .unwrap();
        runner.connection_closed_on(old, 0x13);

        assert!(runner.bridge_slot(0).is_connected());
        assert!(runner.bridge_slot_mut(0).take_tx_acl().is_some());
    }

    #[test]
    fn pump_alternates_between_filled_links() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        runner.bridge_slot_mut(0).receive_acl(2, &[0xaa]).unwrap();
        runner.bridge_slot_mut(1).receive_acl(2, &[0xbb]).unwrap();

        let mut seen = [0u16; 2];
        for entry in &mut seen {
            assert!(runner.pump_once());
            let packet = transport::try_receive_controller_packet().unwrap();
            *entry = u16::from_le_bytes([packet.payload()[0], packet.payload()[1]]) & 0x0fff;
        }
        seen.sort_unstable();
        assert_eq!(seen, [1, 2]);
    }

    #[test]
    fn a_blocked_link_does_not_block_the_other_links_output() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        for _ in 0..5 {
            runner
                .bridge_slot_mut(0)
                .enqueue_tx(&acl(1, 0, &[1]))
                .unwrap();
        }
        transport::try_send_host_packet(acl(1, 0, &[9])).unwrap();
        // The sixth ACL cannot enter: it is held instead of being dropped.
        assert!(!runner.pump_once());
        assert!(runner.pending_input[0].is_some());

        // The blocked link must not stop the other link's queued response.
        runner.bridge_slot_mut(1).receive_acl(2, &[7]).unwrap();
        assert!(runner.pump_once());
        let packet = transport::try_receive_controller_packet().unwrap();
        let handle = u16::from_le_bytes([packet.payload()[0], packet.payload()[1]]) & 0x0fff;
        assert_eq!(handle, 2);
        assert!(runner.pending_input[0].is_some());
    }

    #[test]
    fn a_full_link_does_not_starve_the_other() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        while runner
            .bridge_slot_mut(0)
            .connection_updated(30, 1, 300)
            .is_ok()
        {}
        runner
            .bridge_slot_mut(1)
            .connection_updated(30, 1, 300)
            .unwrap();

        let mut handles = [0u16; 4];
        for handle in &mut handles {
            assert!(runner.pump_once());
            let packet = transport::try_receive_controller_packet().unwrap();
            *handle = u16::from_le_bytes([packet.payload()[4], packet.payload()[5]]);
        }
        // Slot 1's single event reaches the Host after one slot-0 event, not
        // after slot 0's whole backlog.
        assert_eq!(handles[..2], [1, 2]);
    }

    #[test]
    fn reset_is_global_across_both_slots() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        runner
            .bridge_slot_mut(0)
            .enqueue_tx(&acl(1, 0, &[1]))
            .unwrap();
        runner
            .bridge_slot_mut(1)
            .enqueue_tx(&acl(2, 0, &[2]))
            .unwrap();
        let t0 = runner.bridge_slot_mut(0).take_tx_acl().unwrap().tag;
        let t1 = runner.bridge_slot_mut(1).take_tx_acl().unwrap().tag;

        inject_cmd(0x0c03, &[]);
        assert!(runner.pump_once());
        runner.bridge_slot_mut(0).reset_finished();
        // Slot 1 has not stopped yet, so no Command Complete is allowed.
        assert!(!runner.pump_once());
        assert!(transport::try_receive_controller_packet().is_none());
        runner.bridge_slot_mut(1).reset_finished();
        assert!(runner.pump_once());
        expect_command_complete(0x0c03, 0, &[]);

        assert!(!runner.bridge_slot(0).is_connected());
        assert!(!runner.bridge_slot(1).is_connected());
        assert!(!runner.bridge_slot_mut(0).ack_tx(t0));
        assert!(!runner.bridge_slot_mut(1).ack_tx(t1));
        assert!(transport::published_key(1).is_none());
        assert!(transport::published_key(2).is_none());
    }

    #[test]
    fn a_handle_cannot_reopen_elsewhere_before_its_lifecycle_event_is_delivered() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.bridge_slot_mut(0).connected(info_h(1)).unwrap();
        // Deliver the Connection Complete so only the disconnect is pending.
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload()[0],
            0x3e
        );

        runner.bridge_slot_mut(0).disconnected(0x13);
        // Slot rotation starts at slot 1: reusing the handle now would hand
        // the Host a second connect before the promised disconnect.
        runner.flush_slot = 1;
        assert_eq!(
            runner.bridge_slot_mut(1).connected(info_h(1)),
            Err(BridgeError::HandleRetiring)
        );
        assert!(runner.bridge_slot(1).handle().is_none());

        assert!(runner.pump_once());
        let disconnect = transport::try_receive_controller_packet().unwrap();
        assert_eq!(disconnect.payload()[0], 0x05);
        assert_eq!(&disconnect.payload()[3..5], &[1, 0]);

        runner.bridge_slot_mut(1).connected(info_h(1)).unwrap();
        assert!(runner.pump_once());
        let connect = transport::try_receive_controller_packet().unwrap();
        assert_eq!(connect.payload()[0], 0x3e);
        assert_eq!(&connect.payload()[4..6], &[1, 0]);
    }

    #[test]
    fn a_handle_cannot_reopen_elsewhere_while_old_link_events_are_queued() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        // No Disconnection Complete is promised, so only the DLE event remains
        // queued and it alone must delay the cross-slot reopen.
        runner
            .bridge_slot_mut(0)
            .set_masks(u64::MAX & !(1u64 << 4), 0x1f);
        runner.bridge_slot_mut(0).connected(info_h(1)).unwrap();
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload()[0],
            0x3e
        );

        runner
            .bridge_slot_mut(0)
            .set_masks(u64::MAX & !(1u64 << 4), 0x1f | (1 << 6));
        runner
            .bridge_slot_mut(0)
            .data_length_change(27, 328, 27, 328)
            .unwrap();
        runner.bridge_slot_mut(0).disconnected(0x13);
        assert_eq!(
            runner.bridge_slot_mut(1).connected(info_h(1)),
            Err(BridgeError::HandleRetiring)
        );

        assert!(runner.pump_once());
        let stale = transport::try_receive_controller_packet().unwrap();
        assert_eq!(stale.payload()[0], 0x3e, "the old DLE event is delivered");
        runner.bridge_slot_mut(1).connected(info_h(1)).unwrap();
    }

    #[test]
    fn reconnecting_in_the_same_slot_keeps_its_events_in_order() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.bridge_slot_mut(0).connected(info_h(1)).unwrap();
        runner.bridge_slot_mut(0).disconnected(0x13);
        // Same-slot reuse is safe: one FIFO queue orders both events.
        runner.bridge_slot_mut(0).connected(info_h(1)).unwrap();

        let mut kinds = std::vec::Vec::new();
        while runner.pump_once() {
            while let Some(packet) = transport::try_receive_controller_packet() {
                kinds.push(packet.payload()[0]);
            }
        }
        while let Some(packet) = transport::try_receive_controller_packet() {
            kinds.push(packet.payload()[0]);
        }
        assert_eq!(kinds, std::vec![0x3e, 0x05, 0x3e]);
    }

    #[test]
    fn security_pending_is_per_link_and_survives_the_other_close() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        let k0 = runner.bridge_slot(0).link_key();
        let k1 = runner.bridge_slot(1).link_key();

        // The Host answers the LTK request on both links.
        let mut params = [0u8; 18];
        params[0..2].copy_from_slice(&1u16.to_le_bytes());
        params[2..18].copy_from_slice(&[0x11; 16]);
        inject_cmd(0x201a, &params);
        assert!(runner.pump_once());
        expect_command_complete(0x201a, 0, &[1, 0]);
        params[0..2].copy_from_slice(&2u16.to_le_bytes());
        params[2..18].copy_from_slice(&[0x22; 16]);
        inject_cmd(0x201a, &params);
        assert!(runner.pump_once());
        expect_command_complete(0x201a, 0, &[2, 0]);

        // Each accessor sees one link only, and exactly once.
        assert_eq!(
            runner.take_ltk_reply(),
            Some(LtkReply::Key([0x11; 16])),
            "slot-0 accessor"
        );
        assert_eq!(
            runner.take_ltk_reply_for(k1),
            Some(LtkReply::Key([0x22; 16]))
        );
        assert_eq!(runner.take_ltk_reply_for(k1), None);
        assert!(runner.take_ltk_reply().is_none());

        // Queue again, then close link 0: link 1's answer must survive.
        inject_cmd(0x201a, &params);
        assert!(runner.pump_once());
        params[0..2].copy_from_slice(&1u16.to_le_bytes());
        params[2..18].copy_from_slice(&[0x11; 16]);
        inject_cmd(0x201a, &params);
        assert!(runner.pump_once());
        runner.connection_closed_on(k0, 0x13);
        assert_eq!(
            runner.take_ltk_reply_for(k0),
            None,
            "closing link 0 clears it"
        );
        assert_eq!(
            runner.take_ltk_reply_for(k1),
            Some(LtkReply::Key([0x22; 16])),
            "link 1's answer survives"
        );
        assert!(runner.take_ltk_reply().is_none());
    }

    #[test]
    fn the_n1_close_entry_cannot_retire_the_other_link() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        let k1 = runner.bridge_slot(1).link_key();

        // Both links queue an LTK answer through the real command path.
        let mut params = [0u8; 18];
        for (handle, byte) in [(1u16, 0x11u8), (2, 0x22)] {
            params[0..2].copy_from_slice(&handle.to_le_bytes());
            params[2..18].copy_from_slice(&[byte; 16]);
            inject_cmd(0x201a, &params);
            assert!(runner.pump_once());
            expect_command_complete(0x201a, 0, &[handle as u8, 0]);
        }

        // The N=1 entry acts on slot 0 only.
        runner.connection_closed(0x13);
        assert!(!runner.bridge_slot(0).is_connected());
        assert!(runner.bridge_slot(1).is_connected());
        assert_eq!(
            runner.take_ltk_reply_for(k1),
            Some(LtkReply::Key([0x22; 16])),
            "slot 1's answer survives the legacy close"
        );

        // Calling it again while slot 0 is idle is a no-op for slot 1.
        runner.connection_closed(0x13);
        assert!(runner.bridge_slot(1).is_connected());
    }

    #[test]
    fn encryption_requests_are_queued_per_link() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        for (slot, handle) in [(0u8, 1u16), (1, 2)] {
            let info = super::super::connection::ConnectionInfo {
                role: crate::ll::Role::Central,
                ..info_h(handle)
            };
            runner.bridge_slot_mut(slot).connected(info).unwrap();
        }
        drain_controller(&mut runner);

        for handle in [1u16, 2] {
            let mut params = [0u8; 28];
            params[0..2].copy_from_slice(&handle.to_le_bytes());
            params[2..10].copy_from_slice(&[handle as u8; 8]);
            params[10..12].copy_from_slice(&0u16.to_le_bytes());
            params[12..28].copy_from_slice(&[handle as u8 + 0x30; 16]);
            inject_cmd(0x2019, &params);
            assert!(runner.pump_once());
            expect_command_status(0x2019, HCI_SUCCESS);
        }

        // Taking one link's request leaves the other in place.
        assert_eq!(
            runner
                .take_encryption_request_on(1)
                .map(|request| request.handle),
            Some(2)
        );
        assert!(runner.take_encryption_request_on(1).is_none());
        assert_eq!(
            runner
                .take_encryption_request()
                .map(|request| request.handle),
            Some(1),
            "slot-0 accessor"
        );
        assert!(runner.take_encryption_request_on(0).is_none());
    }

    #[test]
    fn close_link_slot_retires_only_that_links_security_work() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        for (slot, handle) in [(0u8, 1u16), (1, 2)] {
            let info = super::super::connection::ConnectionInfo {
                role: crate::ll::Role::Central,
                ..info_h(handle)
            };
            runner.bridge_slot_mut(slot).connected(info).unwrap();
        }
        drain_controller(&mut runner);
        for handle in [1u16, 2] {
            let mut params = [0u8; 28];
            params[0..2].copy_from_slice(&handle.to_le_bytes());
            params[2..10].copy_from_slice(&[handle as u8; 8]);
            params[10..12].copy_from_slice(&0u16.to_le_bytes());
            params[12..28].copy_from_slice(&[handle as u8 + 0x30; 16]);
            inject_cmd(0x2019, &params);
            assert!(runner.pump_once());
            expect_command_status(0x2019, HCI_SUCCESS);
        }

        // The RF owner retires slot 1 after a scheduler-level close.
        runner.close_link_slot(1, 0x08);
        assert!(!runner.bridge_slot(1).is_connected());
        assert!(runner.take_encryption_request_on(1).is_none());
        assert!(runner.bridge_slot(0).is_connected());
        assert!(
            runner.take_encryption_request_on(0).is_some(),
            "the other link keeps its queued request"
        );
    }

    #[test]
    fn a_busy_output_does_not_starve_input() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        // Keep slot 0's output queue non-empty for the whole window.
        for _ in 0..8 {
            let _ = runner.bridge_slot_mut(0).connection_updated(24, 0, 200);
        }
        inject_cmd(0x1009, &[]);

        let mut answered = false;
        for _ in 0..16 {
            runner.pump_once();
            while let Some(packet) = transport::try_receive_controller_packet() {
                let payload = packet.payload();
                if payload[0] == 0x0e && u16::from_le_bytes([payload[3], payload[4]]) == 0x1009 {
                    answered = true;
                }
            }
        }
        assert!(answered, "input starved behind continuous output");
    }

    #[test]
    fn a_full_link_does_not_hold_the_shared_input() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        connect_two(&mut runner);
        for _ in 0..5 {
            runner
                .bridge_slot_mut(0)
                .enqueue_tx(&acl(1, 0, &[1]))
                .unwrap();
        }
        transport::try_send_host_packet(acl(1, 0, &[9])).unwrap();
        assert!(!runner.pump_once());
        assert!(runner.pending_input[0].is_some());

        // A command queued behind the held ACL is still answered.
        inject_cmd(0x1009, &[]);
        let mut answered = false;
        for _ in 0..8 {
            runner.pump_once();
            while let Some(packet) = transport::try_receive_controller_packet() {
                let payload = packet.payload();
                if payload[0] == 0x0e && u16::from_le_bytes([payload[3], payload[4]]) == 0x1009 {
                    answered = true;
                }
            }
        }
        assert!(answered, "the blocked link wedged the shared input");
        assert!(
            runner.pending_input[0].is_some(),
            "the held ACL is not dropped"
        );
    }

    #[test]
    fn reset_while_only_a_background_role_runs_waits_for_the_radio() {
        let _guard = test_lock();
        for scanning in [false, true] {
            transport::drain_channels_for_test();
            let mut runner = SoftRunner::new();
            if scanning {
                runner.scan.enabled = true;
            } else {
                runner.ll.adv.enabled = true;
            }
            inject_cmd(0x0c03, &[]);
            assert!(runner.pump_once());
            assert_eq!(
                runner.bridge.take_radio_request(),
                Some(super::super::connection::RadioRequest::Reset),
                "the owner still gets the stop request"
            );

            // No Command Complete while the radio may still transmit.
            assert!(!runner.pump_once());
            assert!(transport::try_receive_controller_packet().is_none());

            runner.reset_radio_stopped();
            assert!(!runner.pump_once(), "the slot must retire as well");
            runner.bridge.reset_finished();
            assert!(runner.pump_once());
            expect_command_complete(0x0c03, 0, &[]);
            assert!(!runner.adv_enabled());
            assert!(!runner.scan.enabled);
        }
    }
}
