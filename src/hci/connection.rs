//! Bounded single-connection HCI state. The radio/LL owner calls this bridge
//! only outside its timing-critical exchange; no method waits on the Host.

use bt_hci::transport::PacketKind;

use crate::ll::Role;

use super::transport::{self, LinkKey, Packet};

/// The transport slot this single bridge owns until X3 assigns slots per link.
const LINK_SLOT: u8 = 0;

/// Maximum Host ACL payload advertised through `LE Read Buffer Size`: the
/// DLE on-air maximum of 251 octets. The Host may still hand over smaller
/// packets, and the LL fragments them to the negotiated on-air length.
pub const ACL_DATA_PACKET_LENGTH: usize = 251;
pub const ACL_CREDITS: usize = 5;
/// Scan reports share this queue with lifecycle events. Two slots stay
/// reserved for Connection/Disconnection Complete.
const EVENT_CAPACITY: usize = 16;
const LIFECYCLE_RESERVE: usize = 2;
const RX_CAPACITY: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    pub handle: u16,
    pub role: Role,
    pub peer_address_type: u8,
    pub peer_address: [u8; 6],
    pub interval: u16,
    pub latency: u16,
    pub supervision_timeout: u16,
    /// Master clock accuracy (SCA) reported in LE Connection Complete.
    pub master_clock_accuracy: u8,
    /// RPA received in CONNECT_IND; set even when it was not resolved.
    pub peer_rpa: Option<[u8; 6]>,
    /// Local RPA snapshot for this connection.
    pub local_rpa: Option<[u8; 6]>,
    /// Identity `(kind, address)` when the controller resolved the peer.
    pub peer_identity: Option<(u8, [u8; 6])>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    NotConnected,
    InvalidPacket,
    Full,
    AlreadyConnected,
    /// The Host has not enabled the event required to continue.
    Disabled,
}

/// An opaque identity for an actual Host ACL buffer, not an LL sequence number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTag {
    epoch: u32,
    serial: u32,
}

/// Test-only identity for fixtures that supply their own TX buffer.
#[cfg(test)]
pub(crate) fn test_tag(epoch: u32, serial: u32) -> TxTag {
    TxTag { epoch, serial }
}

#[derive(Clone, Copy, Debug)]
pub struct TxAcl {
    pub tag: TxTag,
    pub llid: u8,
    pub len: usize,
    pub bytes: [u8; ACL_DATA_PACKET_LENGTH],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadioRequest {
    Disconnect { reason: u8 },
    Reset,
}

#[derive(Clone, Copy, Debug)]
struct TxSlot {
    acl: TxAcl,
    in_flight: bool,
}

/// Enhanced Connection Complete (v1) subevent.
const ENHANCED_CONNECTION_COMPLETE: u8 = 0x0a;
/// Legacy Connection Complete subevent.
const CONNECTION_COMPLETE: u8 = 0x01;

/// Picks the connection-complete event the Host enabled; Enhanced wins.
fn connection_event_slot_for(mask: u64, event_enabled: bool) -> Option<u8> {
    if !event_enabled {
        return None;
    }
    if mask & (1u64 << (ENHANCED_CONNECTION_COMPLETE - 1)) != 0 {
        Some(ENHANCED_CONNECTION_COMPLETE)
    } else if mask & (1u64 << (CONNECTION_COMPLETE - 1)) != 0 {
        Some(CONNECTION_COMPLETE)
    } else {
        None
    }
}

/// Encodes a Connection Complete / Enhanced event body (without the HCI
/// header). `None` means the attempt failed and every field is zero.
///
/// Enhanced layout (Core 5.4 Vol 4 Part E §7.7.65.10): peer address, local RPA,
/// peer RPA, then the timing fields.
fn connection_event(
    info: Option<&ConnectionInfo>,
    status: u8,
    enhanced: bool,
) -> ([u8; 31], usize) {
    let mut parameters = [0u8; 31];
    let len = if enhanced { 31 } else { 19 };
    parameters[0] = if enhanced {
        ENHANCED_CONNECTION_COMPLETE
    } else {
        CONNECTION_COMPLETE
    };
    parameters[1] = status;
    let Some(info) = info else {
        return (parameters, len);
    };
    parameters[2..4].copy_from_slice(&info.handle.to_le_bytes());
    parameters[4] = match info.role {
        Role::Central => 0,
        Role::Peripheral => 1,
        _ => return (parameters, len),
    };
    parameters[5] = info.peer_address_type;
    parameters[6..12].copy_from_slice(&info.peer_address);
    if !enhanced {
        parameters[12..14].copy_from_slice(&info.interval.to_le_bytes());
        parameters[14..16].copy_from_slice(&info.latency.to_le_bytes());
        parameters[16..18].copy_from_slice(&info.supervision_timeout.to_le_bytes());
        parameters[18] = info.master_clock_accuracy;
        return (parameters, len);
    }
    if let Some(rpa) = info.local_rpa {
        parameters[12..18].copy_from_slice(&rpa);
    }
    // Peer_RPA is valid only together with a resolved identity address.
    if let (Some((kind, address)), Some(rpa)) = (info.peer_identity, info.peer_rpa) {
        if kind <= 1 {
            parameters[5] = if kind == 0 { 2 } else { 3 };
            parameters[6..12].copy_from_slice(&address);
            parameters[18..24].copy_from_slice(&rpa);
        }
    }
    parameters[24..26].copy_from_slice(&info.interval.to_le_bytes());
    parameters[26..28].copy_from_slice(&info.latency.to_le_bytes());
    parameters[28..30].copy_from_slice(&info.supervision_timeout.to_le_bytes());
    parameters[30] = info.master_clock_accuracy;
    (parameters, len)
}

#[derive(Debug)]
pub struct ConnectionBridge {
    info: Option<ConnectionInfo>,
    epoch: u32,
    serial: u32,
    tx: [Option<TxSlot>; ACL_CREDITS],
    rx: [Option<Packet>; RX_CAPACITY],
    events: [Option<Packet>; EVENT_CAPACITY],
    completed: u16,
    radio_request: Option<RadioRequest>,
    disconnecting: bool,
    resetting: bool,
    reset_done: bool,
    event_mask: u64,
    le_event_mask: u64,
    /// Pending Host `LE Set Data Length` (`TX_Octets`, `TX_Time`) for the RF
    /// owner to negotiate on the link.
    data_length_request: Option<(u16, u16)>,
}

impl Default for ConnectionBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionBridge {
    pub const fn new() -> Self {
        Self {
            info: None,
            epoch: 0,
            serial: 0,
            tx: [None; ACL_CREDITS],
            rx: [None; RX_CAPACITY],
            events: [None; EVENT_CAPACITY],
            completed: 0,
            radio_request: None,
            disconnecting: false,
            resetting: false,
            reset_done: false,
            event_mask: u64::MAX,
            le_event_mask: 0x1f,
            data_length_request: None,
        }
    }

    /// Queue a Host `LE Set Data Length` request for the RF owner. Returns an
    /// HCI status: 0x00 accepted, 0x02 unknown connection, 0x0c disallowed.
    pub(crate) fn request_data_length(&mut self, handle: u16, tx_octets: u16, tx_time: u16) -> u8 {
        if self.handle() != Some(handle) {
            return 0x02;
        }
        if self.disconnecting || self.resetting || self.info.is_none() {
            return 0x0c;
        }
        self.data_length_request = Some((tx_octets, tx_time));
        0
    }

    /// Take the pending data-length request; the RF owner applies it once the
    /// link is idle enough to send `LL_LENGTH_REQ`.
    pub fn take_data_length_request(&mut self) -> Option<(u16, u16)> {
        self.data_length_request.take()
    }

    pub fn is_connected(&self) -> bool {
        self.info.is_some()
    }

    pub fn handle(&self) -> Option<u16> {
        self.info.map(|info| info.handle)
    }

    pub fn role(&self) -> Option<Role> {
        self.info.map(|info| info.role)
    }

    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
    }

    pub(crate) fn link_key(&self) -> LinkKey {
        LinkKey {
            slot: LINK_SLOT,
            generation: self.epoch,
        }
    }

    /// Reserve lifecycle storage before the LL accepts a new connection.
    pub fn connected(&mut self, info: ConnectionInfo) -> Result<(), BridgeError> {
        if self.info.is_some() || self.resetting {
            return Err(BridgeError::AlreadyConnected);
        }
        if info.handle > 0x0eff
            || info.peer_address_type > 1
            || !matches!(info.role, Role::Central | Role::Peripheral)
            || info.master_clock_accuracy > 7
        {
            return Err(BridgeError::InvalidPacket);
        }
        if self.events.iter().filter(|slot| slot.is_none()).count() < 2 {
            return Err(BridgeError::Full);
        }
        self.epoch = self.epoch.wrapping_add(1);
        self.info = Some(info);
        self.disconnecting = false;
        transport::set_link(LINK_SLOT, Some((info.handle, self.link_key())));
        if let Some(subevent) = self.connection_event_slot() {
            let (parameters, len) =
                connection_event(Some(&info), 0, subevent == ENHANCED_CONNECTION_COMPLETE);
            self.push_event(event_packet(0x3e, &parameters[..len]));
        }
        Ok(())
    }

    /// Report a connection attempt that never produced a link. The Host uses
    /// this to release the pending create-connection command (for example
    /// after a cancel or an initiator timeout).
    pub fn connection_failed(&mut self, status: u8) -> Result<(), BridgeError> {
        if self.info.is_some() || self.resetting {
            return Err(BridgeError::AlreadyConnected);
        }
        let Some(subevent) = self.connection_event_slot() else {
            return Ok(());
        };
        if self.events.iter().filter(|slot| slot.is_none()).count() < 2 {
            return Err(BridgeError::Full);
        }
        // Failure/cancel follows the same event choice: a Host that enabled
        // only the Enhanced event must still learn that the attempt ended.
        let (parameters, len) =
            connection_event(None, status, subevent == ENHANCED_CONNECTION_COMPLETE);
        self.push_event(event_packet(0x3e, &parameters[..len]));
        Ok(())
    }

    /// Close this link only: its TX/RX data, completions, DLE request and
    /// published identity. Event masks, addresses, lists and features stay.
    /// Called only once the radio has stopped using this connection's buffers.
    pub fn disconnected(&mut self, reason: u8) {
        let Some(info) = self.info.take() else {
            return;
        };
        self.clear_data();
        transport::set_link(LINK_SLOT, None);
        self.radio_request = None;
        self.disconnecting = false;
        if !self.resetting && self.event_enabled(0x05) {
            let [lo, hi] = info.handle.to_le_bytes();
            self.push_event(event_packet(0x05, &[0, lo, hi, reason]));
        }
    }

    pub fn connection_updated(
        &mut self,
        interval: u16,
        latency: u16,
        timeout: u16,
    ) -> Result<(), BridgeError> {
        let info = self.info.as_mut().ok_or(BridgeError::NotConnected)?;
        info.interval = interval;
        info.latency = latency;
        info.supervision_timeout = timeout;
        let handle = info.handle;
        if !self.le_event_enabled(3) {
            return Ok(());
        }
        // Keep one slot reserved for Disconnection Complete.
        if self.events.iter().filter(|slot| slot.is_none()).count() < 2 {
            return Err(BridgeError::Full);
        }
        let mut parameters = [0; 10];
        parameters[0] = 3;
        parameters[2..4].copy_from_slice(&handle.to_le_bytes());
        parameters[4..6].copy_from_slice(&interval.to_le_bytes());
        parameters[6..8].copy_from_slice(&latency.to_le_bytes());
        parameters[8..10].copy_from_slice(&timeout.to_le_bytes());
        self.push_event(event_packet(0x3e, &parameters));
        Ok(())
    }

    /// Emit `LE Data Length Change` (LE Meta subevent 0x07) for the
    /// connected handle. The octet values are payload octets, MIC excluded.
    /// The controller generates this whenever the effective data length
    /// changes as a result of DLE (Core 5.4 Vol 4 Part E 7.7.65.7).
    pub fn data_length_change(
        &mut self,
        max_tx_octets: u16,
        max_tx_time: u16,
        max_rx_octets: u16,
        max_rx_time: u16,
    ) -> Result<(), BridgeError> {
        let info = self.info.as_ref().ok_or(BridgeError::NotConnected)?;
        if self.resetting {
            return Err(BridgeError::NotConnected);
        }
        if !self.le_event_enabled(7) {
            return Ok(());
        }
        let handle = info.handle;
        // Keep one slot reserved for Disconnection Complete.
        if self.events.iter().filter(|slot| slot.is_none()).count() < 2 {
            return Err(BridgeError::Full);
        }
        let mut parameters = [0; 11];
        parameters[0] = 0x07;
        parameters[1..3].copy_from_slice(&handle.to_le_bytes());
        parameters[3..5].copy_from_slice(&max_tx_octets.to_le_bytes());
        parameters[5..7].copy_from_slice(&max_tx_time.to_le_bytes());
        parameters[7..9].copy_from_slice(&max_rx_octets.to_le_bytes());
        parameters[9..11].copy_from_slice(&max_rx_time.to_le_bytes());
        self.push_event(event_packet(0x3e, &parameters));
        Ok(())
    }

    /// Emit `Encryption Change` for the connected handle.
    ///
    /// `enabled` is the HCI Encryption_Enabled value (0x00 off, 0x01 on).
    /// Returns `Full` when no event slot is free so the caller can retry on a
    /// later pump rather than overwrite a lifecycle event.
    pub fn encryption_change(
        &mut self,
        handle: u16,
        status: u8,
        enabled: u8,
    ) -> Result<(), BridgeError> {
        if self.handle() != Some(handle) || self.resetting {
            return Err(BridgeError::NotConnected);
        }
        if !self.event_enabled(0x08) {
            return Ok(());
        }
        // Keep the lifecycle reserve: Disconnection Complete must always find
        // a slot, and `disconnected()` queues it without a capacity check.
        if self.events.iter().filter(|slot| slot.is_none()).count() < LIFECYCLE_RESERVE {
            return Err(BridgeError::Full);
        }
        let [lo, hi] = handle.to_le_bytes();
        self.push_event(event_packet(0x08, &[status, lo, hi, enabled]));
        Ok(())
    }

    /// Emit `LE LTK Request` for the connected handle. The controller cannot
    /// continue the start-encryption procedure until the Host answers, so a
    /// disabled event mask or full queue is reported as an error.
    pub fn ltk_request(
        &mut self,
        handle: u16,
        rand: [u8; 8],
        ediv: u16,
    ) -> Result<(), BridgeError> {
        if self.handle() != Some(handle) || self.resetting {
            return Err(BridgeError::NotConnected);
        }
        if !self.le_event_enabled(5) {
            return Err(BridgeError::Disabled);
        }
        // Keep the lifecycle reserve (see `encryption_change`).
        if self.events.iter().filter(|slot| slot.is_none()).count() < LIFECYCLE_RESERVE {
            return Err(BridgeError::Full);
        }
        let [lo, hi] = handle.to_le_bytes();
        let [elo, ehi] = ediv.to_le_bytes();
        let mut parameters = [0u8; 13];
        parameters[0] = 0x05; // LE LTK Request
        parameters[1] = lo;
        parameters[2] = hi;
        parameters[3..11].copy_from_slice(&rand);
        parameters[11] = elo;
        parameters[12] = ehi;
        self.push_event(event_packet(0x3e, &parameters));
        Ok(())
    }

    /// True while a Host disconnect or Reset is in flight.
    pub(crate) fn is_disconnecting(&self) -> bool {
        self.disconnecting || self.resetting
    }

    /// Check this before advancing NESN for a new, CRC-valid data PDU. The
    /// caller must not interleave another producer between this and receive_acl.
    pub fn can_receive_acl(&self, llid: u8, len: usize) -> bool {
        self.info.is_some()
            && !self.disconnecting
            && !self.resetting
            && matches!(llid, 1 | 2)
            && len <= ACL_DATA_PACKET_LENGTH
            && (llid == 1 && len == 0 || self.rx.iter().any(Option::is_none))
    }

    pub fn receive_acl(&mut self, llid: u8, payload: &[u8]) -> Result<(), BridgeError> {
        let info = self.info.ok_or(BridgeError::NotConnected)?;
        // Do not rely on the destination buffer happening to be large enough:
        // a 4-octet ACL header plus payload must fit one HCI packet.
        if !matches!(llid, 1 | 2)
            || payload.len() > ACL_DATA_PACKET_LENGTH
            || 4 + payload.len() > transport::HCI_PACKET_CAPACITY
        {
            return Err(BridgeError::InvalidPacket);
        }
        if !self.can_receive_acl(llid, payload.len()) {
            return Err(BridgeError::Full);
        }
        if llid == 1 && payload.is_empty() {
            return Ok(()); // LL empty ACK is not Host ACL.
        }
        let mut packet = Packet::empty(PacketKind::AclData);
        let pb = if llid == 2 { 2 } else { 1 }; // Trouble expects FirstFlushable.
        packet.bytes[..2].copy_from_slice(&(info.handle | (pb << 12)).to_le_bytes());
        packet.bytes[2..4].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        packet.bytes[4..4 + payload.len()].copy_from_slice(payload);
        packet.len = 4 + payload.len();
        *self.rx.iter_mut().find(|slot| slot.is_none()).unwrap() = Some(packet);
        Ok(())
    }

    /// Moving a packet to LL does not release its HCI credit. The caller owns
    /// retransmission and must retain this tag until the LL acknowledges it.
    pub fn take_tx_acl(&mut self) -> Option<TxAcl> {
        if self.disconnecting || self.resetting {
            return None;
        }
        let slot = self
            .tx
            .iter_mut()
            .flatten()
            .filter(|slot| !slot.in_flight)
            .min_by_key(|slot| slot.acl.tag.serial)?;
        slot.in_flight = true;
        Some(slot.acl)
    }

    /// Only the first acknowledgement of a live, in-flight ACL tag returns a
    /// credit. Empty/control PDUs have no TxTag and cannot call this by accident.
    pub fn ack_tx(&mut self, tag: TxTag) -> bool {
        if tag.epoch != self.epoch || self.resetting {
            return false;
        }
        let Some(slot) = self.tx.iter_mut().find(|slot| {
            slot.as_ref()
                .is_some_and(|slot| slot.in_flight && slot.acl.tag == tag)
        }) else {
            return false;
        };
        *slot = None;
        self.completed += 1;
        true
    }

    pub fn take_radio_request(&mut self) -> Option<RadioRequest> {
        self.radio_request.take()
    }

    /// Acknowledge Reset only after all RF activity (including advertising) is
    /// stopped. The runner then emits Command Complete and resumes command input.
    pub fn reset_finished(&mut self) {
        if !self.resetting {
            return;
        }
        self.info = None;
        self.clear_data();
        transport::set_link(LINK_SLOT, None);
        self.events = [None; EVENT_CAPACITY];
        self.radio_request = None;
        self.disconnecting = false;
        self.resetting = false;
        self.reset_done = true;
    }

    pub(crate) fn set_masks(&mut self, event_mask: u64, le_event_mask: u64) {
        self.event_mask = event_mask;
        self.le_event_mask = le_event_mask;
    }

    pub(crate) fn request_disconnect(&mut self, handle: u16, reason: u8) -> u8 {
        if self.handle() != Some(handle) {
            return 0x02; // Unknown Connection Identifier
        }
        if self.disconnecting || self.resetting {
            return 0x0c;
        }
        self.disconnecting = true;
        self.radio_request = Some(RadioRequest::Disconnect { reason });
        0
    }

    pub(crate) fn request_reset(&mut self) {
        self.resetting = true;
        self.radio_request = Some(RadioRequest::Reset);
    }

    pub(crate) fn take_reset_done(&mut self) -> bool {
        core::mem::take(&mut self.reset_done)
    }

    pub(crate) fn enqueue_tx(&mut self, packet: &Packet) -> Result<(), BridgeError> {
        let info = self.info.ok_or(BridgeError::NotConnected)?;
        let bytes = packet.payload();
        if bytes.len() < 4 {
            return Err(BridgeError::InvalidPacket);
        }
        let flags = u16::from_le_bytes([bytes[0], bytes[1]]);
        let len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let pb = (flags >> 12) & 3;
        if flags & 0x0fff != info.handle
            || flags & 0xc000 != 0
            || !matches!(pb, 0 | 1)
            || len > ACL_DATA_PACKET_LENGTH
            || bytes.len() != len + 4
        {
            return Err(BridgeError::InvalidPacket);
        }
        if self.disconnecting || self.resetting {
            return Err(BridgeError::NotConnected);
        }
        let slot = self
            .tx
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(BridgeError::Full)?;
        self.serial = self.serial.wrapping_add(1);
        let mut acl = TxAcl {
            tag: TxTag {
                epoch: self.epoch,
                serial: self.serial,
            },
            llid: if pb == 0 { 2 } else { 1 },
            len,
            bytes: [0; ACL_DATA_PACKET_LENGTH],
        };
        acl.bytes[..len].copy_from_slice(&bytes[4..]);
        *slot = Some(TxSlot {
            acl,
            in_flight: false,
        });
        Ok(())
    }

    pub(crate) fn has_output(&self) -> bool {
        self.events[0].is_some() || self.completed != 0 || self.rx[0].is_some()
    }

    pub(crate) fn flush_one(&mut self) -> bool {
        // Lifecycle events always precede ACL, including a newly opened link.
        if let Some(packet) = self.events[0] {
            if transport::try_send_controller_packet(packet).is_err() {
                return false;
            }
            shift(&mut self.events);
            return true;
        }
        if self.completed != 0 {
            if let Some(handle) = self.handle() {
                let [lo, hi] = handle.to_le_bytes();
                let [count_lo, count_hi] = self.completed.to_le_bytes();
                let packet = event_packet(0x13, &[1, lo, hi, count_lo, count_hi]);
                if transport::try_send_controller_packet(packet).is_err() {
                    return false;
                }
                self.completed = 0;
                return true;
            }
        }
        if let Some(packet) = self.rx[0] {
            if transport::try_send_controller_packet(packet).is_err() {
                return false;
            }
            shift(&mut self.rx);
            return true;
        }
        false
    }

    fn clear_data(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.tx = [None; ACL_CREDITS];
        self.rx = [None; RX_CAPACITY];
        self.completed = 0;
        self.data_length_request = None;
        transport::discard_connection_data();
    }

    fn event_enabled(&self, code: u8) -> bool {
        self.event_mask & (1u64 << (code - 1)) != 0
    }

    pub(crate) fn le_event_enabled(&self, subevent: u8) -> bool {
        self.event_enabled(0x3e) && self.le_event_mask & (1u64 << (subevent - 1)) != 0
    }

    fn connection_event_slot(&self) -> Option<u8> {
        connection_event_slot_for(self.le_event_mask, self.event_enabled(0x3e))
    }

    fn push_event(&mut self, packet: Packet) {
        *self
            .events
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("reserved lifecycle slot") = Some(packet);
    }

    /// Best-effort event for droppable diagnostics such as scan reports.
    /// Keeps `LIFECYCLE_RESERVE` slots free so a connect/disconnect event can
    /// always be queued.
    pub(crate) fn try_push_event(&mut self, packet: Packet) -> bool {
        let free = self.events.iter().filter(|slot| slot.is_none()).count();
        if free <= LIFECYCLE_RESERVE {
            return false;
        }
        self.push_event(packet);
        true
    }
}

fn shift<const N: usize>(queue: &mut [Option<Packet>; N]) {
    queue.rotate_left(1);
    queue[N - 1] = None;
}

pub(crate) fn event_packet(code: u8, parameters: &[u8]) -> Packet {
    let mut packet = Packet::empty(PacketKind::Event);
    packet.bytes[0] = code;
    packet.bytes[1] = parameters.len() as u8;
    packet.bytes[2..2 + parameters.len()].copy_from_slice(parameters);
    packet.len = 2 + parameters.len();
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    const RPA: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const IDENTITY: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0xc0];
    const LOCAL_RPA: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x4f];

    fn info() -> ConnectionInfo {
        ConnectionInfo {
            handle: 0x0041,
            role: Role::Peripheral,
            peer_address_type: 1,
            peer_address: RPA,
            interval: 24,
            latency: 0,
            supervision_timeout: 200,
            master_clock_accuracy: 1,
            peer_rpa: Some(RPA),
            local_rpa: Some(LOCAL_RPA),
            peer_identity: Some((1, IDENTITY)),
        }
    }

    #[test]
    fn enhanced_wins_over_legacy() {
        assert_eq!(connection_event_slot_for(0x201, true), Some(0x0a));
        assert_eq!(connection_event_slot_for(0x001, true), Some(0x01));
        assert_eq!(connection_event_slot_for(0x200, true), Some(0x0a));
        assert_eq!(connection_event_slot_for(0x002, true), None);
        assert_eq!(connection_event_slot_for(0x201, false), None);
    }

    #[test]
    fn enhanced_event_encodes_resolved_identity() {
        let (p, len) = connection_event(Some(&info()), 0, true);
        assert_eq!(len, 31);
        assert_eq!(p[0], 0x0a);
        assert_eq!(p[1], 0);
        assert_eq!(&p[2..4], &[0x41, 0x00]);
        assert_eq!(p[4], 1);
        assert_eq!(p[5], 3); // random identity
        assert_eq!(&p[6..12], &IDENTITY);
        assert_eq!(&p[12..18], &LOCAL_RPA);
        assert_eq!(&p[18..24], &RPA);
        assert_eq!(&p[24..26], &[24, 0]);
        assert_eq!(p[30], 1);
    }

    #[test]
    fn enhanced_event_keeps_unresolved_rpa_visible() {
        let mut info = info();
        info.peer_identity = None;
        let (p, len) = connection_event(Some(&info), 0, true);
        assert_eq!(len, 31);
        assert_eq!(p[5], 1);
        assert_eq!(&p[6..12], &RPA);
        assert_eq!(&p[12..18], &LOCAL_RPA);
        assert_eq!(&p[18..24], &[0; 6]);
    }

    #[test]
    fn identity_without_rpa_is_not_reported_as_resolved() {
        let mut info = info();
        info.peer_rpa = None;
        let (p, _) = connection_event(Some(&info), 0, true);
        assert_eq!(p[5], 1);
        assert_eq!(&p[6..12], &RPA);
        assert_eq!(&p[18..24], &[0; 6]);
    }

    #[test]
    fn public_identity_becomes_type_two() {
        let mut info = info();
        info.peer_identity = Some((0, [0x10, 0x20, 0x30, 0x40, 0x50, 0x60]));
        let (p, _) = connection_event(Some(&info), 0, true);
        assert_eq!(p[5], 2);
        assert_eq!(&p[6..12], &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    }

    #[test]
    fn legacy_event_ignores_privacy_fields() {
        let (p, len) = connection_event(Some(&info()), 0, false);
        assert_eq!(len, 19);
        assert_eq!(p[0], 0x01);
        assert_eq!(p[5], 1);
        assert_eq!(&p[6..12], &RPA);
    }

    #[test]
    fn enhanced_event_parses_with_the_hci_crate() {
        use bt_hci::event::le::LeEnhancedConnectionComplete;
        use bt_hci::FromHciBytes;

        let (parameters, _) = connection_event(Some(&info()), 0, true);
        let event =
            LeEnhancedConnectionComplete::from_hci_bytes_complete(&parameters[1..]).unwrap();
        assert!(event.status.to_result().is_ok());
        assert_eq!(event.handle.raw(), 0x0041);
        assert_eq!(event.role, bt_hci::param::LeConnRole::Peripheral);
        assert_eq!(event.peer_addr_kind.as_raw(), 3);
        assert_eq!(event.peer_addr.raw(), IDENTITY);
        assert_eq!(event.local_resolvable_private_addr.raw(), LOCAL_RPA);
        assert_eq!(event.peer_resolvable_private_addr.raw(), RPA);
        assert_eq!(event.conn_interval.as_micros(), 24 * 1_250);
        assert_eq!(event.peripheral_latency, 0);
        assert_eq!(event.supervision_timeout.as_micros(), 200 * 10_000);
    }

    #[test]
    fn failure_uses_the_same_event_and_clears_fields() {
        let (p, len) = connection_event(None, 0x02, true);
        assert_eq!(len, 31);
        assert_eq!(p[0], 0x0a);
        assert_eq!(p[1], 0x02);
        assert!(p[2..].iter().all(|byte| *byte == 0));
        let (p, len) = connection_event(None, 0x02, false);
        assert_eq!(len, 19);
        assert_eq!(p[0], 0x01);
        assert!(p[2..].iter().all(|byte| *byte == 0));
    }
}
