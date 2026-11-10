//! Bounded single-connection HCI state. The radio/LL owner calls this bridge
//! only outside its timing-critical exchange; no method waits on the Host.

use bt_hci::transport::PacketKind;

use crate::ll::Role;

use super::transport::{self, Packet};

pub const ACL_DATA_PACKET_LENGTH: usize = 27;
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeError {
    NotConnected,
    InvalidPacket,
    Full,
    AlreadyConnected,
}

/// An opaque identity for an actual Host ACL buffer, not an LL sequence number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxTag {
    epoch: u32,
    serial: u32,
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
        }
    }

    pub fn is_connected(&self) -> bool {
        self.info.is_some()
    }

    pub fn handle(&self) -> Option<u16> {
        self.info.map(|info| info.handle)
    }

    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
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
        if self.le_event_enabled(1) {
            let mut parameters = [0; 19];
            parameters[0] = 1; // LE Connection Complete
            parameters[2..4].copy_from_slice(&info.handle.to_le_bytes());
            parameters[4] = match info.role {
                Role::Central => 0,
                Role::Peripheral => 1,
                _ => unreachable!("role checked above"),
            };
            parameters[5] = info.peer_address_type;
            parameters[6..12].copy_from_slice(&info.peer_address);
            parameters[12..14].copy_from_slice(&info.interval.to_le_bytes());
            parameters[14..16].copy_from_slice(&info.latency.to_le_bytes());
            parameters[16..18].copy_from_slice(&info.supervision_timeout.to_le_bytes());
            parameters[18] = info.master_clock_accuracy;
            self.push_event(event_packet(0x3e, &parameters));
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
        if !self.le_event_enabled(1) {
            return Ok(());
        }
        if self.events.iter().filter(|slot| slot.is_none()).count() < 2 {
            return Err(BridgeError::Full);
        }
        let mut parameters = [0; 19];
        parameters[0] = 1; // LE Connection Complete
        parameters[1] = status;
        self.push_event(event_packet(0x3e, &parameters));
        Ok(())
    }

    /// Called only once the radio has stopped using this connection's buffers.
    pub fn disconnected(&mut self, reason: u8) {
        let Some(info) = self.info.take() else {
            return;
        };
        self.clear_data();
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
        if !matches!(llid, 1 | 2) || payload.len() > ACL_DATA_PACKET_LENGTH {
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
        transport::discard_connection_data();
    }

    fn event_enabled(&self, code: u8) -> bool {
        self.event_mask & (1u64 << (code - 1)) != 0
    }

    pub(crate) fn le_event_enabled(&self, subevent: u8) -> bool {
        self.event_enabled(0x3e) && self.le_event_mask & (1u64 << (subevent - 1)) != 0
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
