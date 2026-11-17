//! In-process HCI transport for [`bt_hci::controller::ExternalController`].
//!
//! Pattern mirrors rusted-ch5 `ch58x-ble`: Host↔Controller packets move through
//! bounded `embassy_sync::channel::Channel`s (no UART). The paired
//! [`crate::hci::runner::SoftRunner`] must be polled or Trouble's `exec` hangs
//! waiting for Command Complete.

use core::cell::Cell;
use core::convert::Infallible;

use bt_hci::transport::{
    PacketKind, PacketToController, PacketToHost, Transport as TransportTrait,
};
use bt_hci::{FromHciBytesError, ReadHciError};
use critical_section::Mutex as CsMutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

/// Bytes reserved for one HCI packet on this soft transport: the four-octet
/// ACL header plus the 251-octet DLE maximum. This is also the largest packet
/// `Packet::from_bytes` accepts, so no ACL frame can silently truncate.
pub const HCI_PACKET_CAPACITY: usize = 255;

const HOST_TO_CONTROLLER_CAPACITY: usize = 1;
const CONTROLLER_TO_HOST_CAPACITY: usize = 4;

/// Link slots the transport can attribute packets to. X3 first ships two.
pub const MAX_LINKS: usize = 2;

/// Identity of a link slot. The HCI handle is a protocol label, not identity:
/// a reused handle gets a new generation. Generation zero is never live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkKey {
    pub slot: u8,
    pub generation: u32,
}

/// Where an inbound Host packet belongs. `Global` commands survive link
/// changes; connection-scoped packets are validated against the producer-time
/// key and are never re-stamped on dequeue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketScope {
    Global,
    Connection { handle: u16, key: LinkKey },
}

#[derive(Clone, Copy, Debug)]
pub struct HostPacket {
    pub packet: Packet,
    pub scope: PacketScope,
}

/// Links currently published for producer-side packet classification.
type LinkTable = [Option<(u16, LinkKey)>; MAX_LINKS];

static LINKS: CsMutex<Cell<LinkTable>> = CsMutex::new(Cell::new([None; MAX_LINKS]));

static HOST_TO_CONTROLLER: Channel<
    CriticalSectionRawMutex,
    HostPacket,
    HOST_TO_CONTROLLER_CAPACITY,
> = Channel::new();
static CONTROLLER_TO_HOST: Channel<CriticalSectionRawMutex, Packet, CONTROLLER_TO_HOST_CAPACITY> =
    Channel::new();

/// Publish or retire the link occupying `slot`. Called by the link owner when
/// a connection is accepted or released, never by the packet consumer.
pub(crate) fn set_link(slot: u8, link: Option<(u16, LinkKey)>) {
    let slot = usize::from(slot);
    if slot >= MAX_LINKS {
        return;
    }
    critical_section::with(|cs| {
        let mut links = LINKS.borrow(cs).get();
        links[slot] = link.map(|(handle, key)| {
            (
                handle,
                LinkKey {
                    slot: slot as u8,
                    ..key
                },
            )
        });
        LINKS.borrow(cs).set(links);
    });
}

fn published_key(handle: u16) -> Option<LinkKey> {
    critical_section::with(|cs| {
        LINKS
            .borrow(cs)
            .get()
            .iter()
            .flatten()
            .find(|(published, _)| *published == handle)
            .map(|(_, key)| *key)
    })
}

/// HCI commands whose first parameter is a connection handle.
fn connection_command(opcode: u16) -> bool {
    matches!(opcode, 0x0406 | 0x2019 | 0x201a | 0x201b | 0x2022)
}

/// Attach the producer-time link identity. A packet naming an unpublished
/// handle keeps generation zero and is rejected when it is dequeued.
fn classify(packet: &Packet) -> PacketScope {
    let handle = match packet.kind {
        PacketKind::AclData if packet.len >= 2 => {
            Some(u16::from_le_bytes([packet.bytes[0], packet.bytes[1]]) & 0x0fff)
        }
        PacketKind::Cmd if packet.len >= 5 => {
            let opcode = u16::from_le_bytes([packet.bytes[0], packet.bytes[1]]);
            connection_command(opcode)
                .then(|| u16::from_le_bytes([packet.bytes[3], packet.bytes[4]]))
        }
        _ => None,
    };
    match handle {
        None => PacketScope::Global,
        Some(handle) => PacketScope::Connection {
            handle,
            key: published_key(handle).unwrap_or(LinkKey {
                slot: u8::MAX,
                generation: 0,
            }),
        },
    }
}

/// Owned HCI packet stored in the static channels.
#[derive(Clone, Copy, Debug)]
pub struct Packet {
    pub kind: PacketKind,
    pub len: usize,
    pub bytes: [u8; HCI_PACKET_CAPACITY],
}

impl Packet {
    pub const fn empty(kind: PacketKind) -> Self {
        Self {
            kind,
            len: 0,
            bytes: [0; HCI_PACKET_CAPACITY],
        }
    }

    pub fn from_bytes(kind: PacketKind, data: &[u8]) -> Result<Self, Error> {
        if data.len() > HCI_PACKET_CAPACITY {
            return Err(Error::PacketTooLarge);
        }
        let mut packet = Self::empty(kind);
        packet.bytes[..data.len()].copy_from_slice(data);
        packet.len = data.len();
        Ok(packet)
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Soft-transport errors surfaced through `bt-hci`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    PacketTooLarge,
    MalformedPacket,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PacketTooLarge => f.write_str("HCI packet too large"),
            Self::MalformedPacket => f.write_str("malformed HCI packet"),
        }
    }
}

impl core::error::Error for Error {}

impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::PacketTooLarge => embedded_io::ErrorKind::OutOfMemory,
            Self::MalformedPacket => embedded_io::ErrorKind::InvalidData,
        }
    }
}

impl From<FromHciBytesError> for Error {
    fn from(_: FromHciBytesError) -> Self {
        Self::MalformedPacket
    }
}

impl From<ReadHciError<Infallible>> for Error {
    fn from(_: ReadHciError<Infallible>) -> Self {
        Self::MalformedPacket
    }
}

/// Packet transport used by `bt-hci`'s command dispatcher.
#[derive(Debug, Default)]
pub struct HciTransport {
    _private: (),
}

impl HciTransport {
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

impl embedded_io::ErrorType for HciTransport {
    type Error = Error;
}

impl TransportTrait for HciTransport {
    async fn read<'a, P: PacketToHost<'a>>(&self, output: &'a mut [u8]) -> Result<P, Self::Error> {
        let packet = CONTROLLER_TO_HOST.receive().await;

        if packet.len > output.len() {
            return Err(Error::PacketTooLarge);
        }
        let mut input = &packet.bytes[..packet.len];
        let parsed = P::read_hci(packet.kind, &mut input, output)?;
        if !input.is_empty() {
            return Err(Error::MalformedPacket);
        }
        Ok(parsed)
    }

    async fn write<T: PacketToController>(&self, value: &T) -> Result<(), Self::Error> {
        if value.size() > HCI_PACKET_CAPACITY {
            return Err(Error::PacketTooLarge);
        }
        let mut packet = Packet::empty(T::KIND);
        let size = value.size();
        let mut destination = &mut packet.bytes[..size];
        value
            .write_hci(&mut destination)
            .map_err(|_| Error::PacketTooLarge)?;
        packet.len = size;

        // Bind the link identity here, at the producer, so a packet queued
        // across a disconnect cannot be attributed to a later connection.
        HOST_TO_CONTROLLER
            .send(HostPacket {
                packet,
                scope: classify(&packet),
            })
            .await;
        Ok(())
    }
}

/// Drain one Host→Controller packet (async).
pub async fn receive_host_packet() -> HostPacket {
    HOST_TO_CONTROLLER.receive().await
}

/// Non-blocking Host→Controller poll (tests / cooperative pump).
pub fn try_receive_host_packet() -> Option<HostPacket> {
    HOST_TO_CONTROLLER.try_receive().ok()
}

/// Push a Host→Controller packet without going through `Transport::write`.
///
/// For cooperative pumps and diagnostics that have no async Host; production
/// Hosts use [`HciTransport`] through `bt-hci`.
pub fn try_send_host_packet(packet: Packet) -> Result<(), Error> {
    try_send_host_packet_scoped(packet, classify(&packet))
}

/// Test hook: inject a packet with an explicit producer-time scope. Crate-only
/// so real Hosts cannot choose a scope; they go through [`HciTransport`].
pub(crate) fn try_send_host_packet_scoped(packet: Packet, scope: PacketScope) -> Result<(), Error> {
    HOST_TO_CONTROLLER
        .try_send(HostPacket { packet, scope })
        .map_err(|_| Error::PacketTooLarge)
}

/// Push a Controller→Host packet (returns the channel send future).
pub fn send_controller_packet(packet: Packet) -> impl core::future::Future<Output = ()> {
    CONTROLLER_TO_HOST.send(packet)
}

/// Non-blocking Controller→Host push (tests).
pub fn try_send_controller_packet(packet: Packet) -> Result<(), Error> {
    CONTROLLER_TO_HOST
        .try_send(packet)
        .map_err(|_| Error::PacketTooLarge)
}

/// Non-blocking Controller→Host poll (cooperative pumps and diagnostics).
pub fn try_receive_controller_packet() -> Option<Packet> {
    CONTROLLER_TO_HOST.try_receive().ok()
}

/// Emit a raw HCI event (`event_code` + parameters).
pub async fn event(event_code: u8, parameters: &[u8]) -> Result<(), Error> {
    if parameters.len() > HCI_PACKET_CAPACITY.saturating_sub(2) {
        return Err(Error::PacketTooLarge);
    }
    let mut packet = Packet::empty(PacketKind::Event);
    packet.bytes[0] = event_code;
    packet.bytes[1] = parameters.len() as u8;
    packet.bytes[2..2 + parameters.len()].copy_from_slice(parameters);
    packet.len = 2 + parameters.len();
    send_controller_packet(packet).await;
    Ok(())
}

/// HCI Command Complete (event 0x0e).
pub async fn command_complete(opcode: u16, status: u8, return_data: &[u8]) {
    send_controller_packet(command_complete_packet(opcode, status, return_data)).await;
}

/// HCI Command Status (event 0x0f) — used for async cmds we still stub.
pub async fn command_status(opcode: u16, status: u8) {
    send_controller_packet(command_status_packet(opcode, status)).await;
}

/// Remove obsolete connection data without discarding command replies or a
/// subsequent Host command. Called only by the single cooperative RF/HCI owner.
pub(crate) fn discard_connection_data() {
    let mut retained = [None; CONTROLLER_TO_HOST_CAPACITY];
    let mut count = 0;
    while let Ok(packet) = CONTROLLER_TO_HOST.try_receive() {
        if packet.kind == PacketKind::AclData
            || (packet.kind == PacketKind::Event && packet.payload().first() == Some(&0x13))
        {
            continue;
        }
        retained[count] = Some(packet);
        count += 1;
    }
    for packet in retained.into_iter().flatten() {
        let _ = CONTROLLER_TO_HOST.try_send(packet);
    }
    // Connection-scoped commands keep their producer-time scope, so they are
    // answered as stale instead of being applied to the next link.
    if let Ok(host) = HOST_TO_CONTROLLER.try_receive() {
        if host.packet.kind != PacketKind::AclData {
            let _ = HOST_TO_CONTROLLER.try_send(host);
        }
    }
}

pub(crate) async fn wait_for_host_packet() {
    core::future::poll_fn(|cx| HOST_TO_CONTROLLER.poll_ready_to_receive(cx)).await
}

pub(crate) async fn wait_for_output_space() {
    core::future::poll_fn(|cx| CONTROLLER_TO_HOST.poll_ready_to_send(cx)).await
}

pub(crate) fn command_complete_packet(opcode: u16, status: u8, data: &[u8]) -> Packet {
    let mut packet = Packet::empty(PacketKind::Event);
    packet.bytes[0] = 0x0e;
    packet.bytes[1] = (4 + data.len()) as u8;
    packet.bytes[2] = 1;
    packet.bytes[3..5].copy_from_slice(&opcode.to_le_bytes());
    packet.bytes[5] = status;
    packet.bytes[6..6 + data.len()].copy_from_slice(data);
    packet.len = 6 + data.len();
    packet
}

pub(crate) fn command_status_packet(opcode: u16, status: u8) -> Packet {
    super::connection::event_packet(0x0f, &[status, 1, opcode as u8, (opcode >> 8) as u8])
}

/// Test helper: drop any residual channel and link state between unit tests.
#[cfg(test)]
pub fn drain_channels_for_test() {
    while HOST_TO_CONTROLLER.try_receive().is_ok() {}
    while CONTROLLER_TO_HOST.try_receive().is_ok() {}
    critical_section::with(|cs| LINKS.borrow(cs).set([None; MAX_LINKS]));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_maximum_packet_fits_without_truncation() {
        // Four-octet ACL header plus the 251-octet DLE maximum is exactly one
        // HCI packet, and one byte more must be rejected rather than clipped.
        assert_eq!(HCI_PACKET_CAPACITY, 4 + 251);
        assert_eq!(
            HCI_PACKET_CAPACITY,
            crate::hci::connection::ACL_DATA_PACKET_LENGTH + 4
        );
        let max = [0x5au8; HCI_PACKET_CAPACITY];
        let packet = Packet::from_bytes(PacketKind::AclData, &max).unwrap();
        assert_eq!(packet.payload(), &max);
        assert_eq!(
            Packet::from_bytes(PacketKind::AclData, &[0; HCI_PACKET_CAPACITY + 1]).err(),
            Some(Error::PacketTooLarge)
        );
    }
}
