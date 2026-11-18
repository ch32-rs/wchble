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

/// Controller→Host entry. ACL and completed-packets are attributed to the link
/// that produced them; command replies and lifecycle events are global.
#[derive(Clone, Copy, Debug)]
pub struct ControllerPacket {
    pub packet: Packet,
    pub scope: PacketScope,
}

/// Links currently published for producer-side packet classification.
type LinkTable = [Option<(u16, LinkKey)>; MAX_LINKS];

static LINKS: CsMutex<Cell<LinkTable>> = CsMutex::new(Cell::new([None; MAX_LINKS]));

/// Handles with link-scoped events still queued in a slot (lifecycle, LTK
/// request, encryption, update, DLE). A handle may reopen on another slot only
/// after every such event reached the Host, or a stale one could be applied to
/// the new link.
const PENDING_HANDLES: usize = 4;
type LifecycleTable = (
    [[Option<(u16, u8)>; PENDING_HANDLES]; MAX_LINKS],
    [bool; MAX_LINKS],
);
static PENDING_EVENTS: CsMutex<Cell<LifecycleTable>> = CsMutex::new(Cell::new((
    [[None; PENDING_HANDLES]; MAX_LINKS],
    [false; MAX_LINKS],
)));

static HOST_TO_CONTROLLER: Channel<
    CriticalSectionRawMutex,
    HostPacket,
    HOST_TO_CONTROLLER_CAPACITY,
> = Channel::new();
static CONTROLLER_TO_HOST: Channel<
    CriticalSectionRawMutex,
    ControllerPacket,
    CONTROLLER_TO_HOST_CAPACITY,
> = Channel::new();

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

pub(crate) fn published_key(handle: u16) -> Option<LinkKey> {
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

/// Remember a queued link event for `handle` in `slot`.
pub(crate) fn note_link_event(slot: u8, handle: u16) {
    let slot = usize::from(slot);
    if slot >= MAX_LINKS {
        return;
    }
    critical_section::with(|cs| {
        let (mut table, mut saturated) = PENDING_EVENTS.borrow(cs).get();
        if let Some(entry) = table[slot]
            .iter_mut()
            .flatten()
            .find(|(queued, _)| *queued == handle)
        {
            entry.1 = entry.1.saturating_add(1);
        } else if let Some(entry) = table[slot].iter_mut().find(|entry| entry.is_none()) {
            *entry = Some((handle, 1));
        } else {
            // Without a free entry the slot cannot prove which handles are
            // still queued; block cross-slot reuse until its ring is empty.
            saturated[slot] = true;
        }
        PENDING_EVENTS.borrow(cs).set((table, saturated));
    });
}

/// The Host has been handed one link event for `handle` in `slot`.
pub(crate) fn release_link_event(slot: u8, handle: u16) {
    let slot = usize::from(slot);
    if slot >= MAX_LINKS {
        return;
    }
    critical_section::with(|cs| {
        let (mut table, saturated) = PENDING_EVENTS.borrow(cs).get();
        let mut cleared = None;
        for (index, entry) in table[slot].iter_mut().enumerate() {
            if let Some((queued, count)) = entry {
                if *queued == handle {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        cleared = Some(index);
                    }
                    break;
                }
            }
        }
        if let Some(index) = cleared {
            table[slot][index] = None;
        }
        PENDING_EVENTS.borrow(cs).set((table, saturated));
    });
}

/// The slot's event ring is empty (or was cleared by Reset), so no link event
/// from it can still reach the Host.
pub(crate) fn clear_link_events(slot: u8) {
    let slot = usize::from(slot);
    if slot >= MAX_LINKS {
        return;
    }
    critical_section::with(|cs| {
        let (mut table, mut saturated) = PENDING_EVENTS.borrow(cs).get();
        table[slot] = [None; PENDING_HANDLES];
        saturated[slot] = false;
        PENDING_EVENTS.borrow(cs).set((table, saturated));
    });
}

/// True when opening `handle` on `slot` now could reach the Host before a
/// link event another slot has queued for the same handle.
pub(crate) fn link_event_pending_elsewhere(slot: u8, handle: u16) -> bool {
    let slot = usize::from(slot);
    critical_section::with(|cs| {
        let (table, saturated) = PENDING_EVENTS.borrow(cs).get();
        (0..MAX_LINKS).any(|other| {
            other != slot
                && (saturated[other] || table[other].iter().flatten().any(|(h, _)| *h == handle))
        })
    })
}

/// HCI commands whose first parameter is a connection handle.
fn connection_command(opcode: u16) -> bool {
    matches!(opcode, 0x0406 | 0x2019 | 0x201a | 0x201b | 0x2022)
}

/// Controller→Host scope. Only ACL and completed-packets belong to a link;
/// events (including lifecycle) stay global so a close cannot swallow a
/// promised Connection/Disconnection Complete.
fn classify_controller(packet: &Packet) -> PacketScope {
    let handle = match packet.kind {
        PacketKind::AclData if packet.len >= 2 => {
            Some(u16::from_le_bytes([packet.bytes[0], packet.bytes[1]]) & 0x0fff)
        }
        PacketKind::Event => {
            // A multi-handle completion has no single owner; the discard path
            // rewrites it entry by entry instead.
            let mut handles = completed_handles(packet);
            match (handles.next(), handles.next()) {
                (Some(handle), None) => Some(handle),
                _ => None,
            }
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
        let packet = CONTROLLER_TO_HOST.receive().await.packet;

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
    let scope = classify_controller(&packet);
    CONTROLLER_TO_HOST.send(ControllerPacket { packet, scope })
}

/// Non-blocking Controller→Host push (tests).
pub fn try_send_controller_packet(packet: Packet) -> Result<(), Error> {
    let scope = classify_controller(&packet);
    CONTROLLER_TO_HOST
        .try_send(ControllerPacket { packet, scope })
        .map_err(|_| Error::PacketTooLarge)
}

/// Non-blocking Controller→Host poll (cooperative pumps and diagnostics).
pub fn try_receive_controller_packet() -> Option<Packet> {
    CONTROLLER_TO_HOST
        .try_receive()
        .ok()
        .map(|entry| entry.packet)
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

fn acl_handle(packet: &Packet) -> Option<u16> {
    (packet.kind == PacketKind::AclData && packet.len >= 2)
        .then(|| u16::from_le_bytes([packet.bytes[0], packet.bytes[1]]) & 0x0fff)
}

/// Handles named by a `Number Of Completed Packets` event (0x13).
struct CompletedHandles<'a> {
    packet: Option<&'a Packet>,
    index: usize,
}

fn completed_handles(packet: &Packet) -> CompletedHandles<'_> {
    let valid = packet.kind == PacketKind::Event
        && packet.len >= 3
        && packet.bytes[0] == 0x13
        && packet.len >= 3 + 4 * usize::from(packet.bytes[2]);
    CompletedHandles {
        packet: valid.then_some(packet),
        index: 0,
    }
}

impl Iterator for CompletedHandles<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        let packet = self.packet?;
        if self.index >= usize::from(packet.bytes[2]) {
            return None;
        }
        let at = 3 + 4 * self.index;
        self.index += 1;
        Some(u16::from_le_bytes([packet.bytes[at], packet.bytes[at + 1]]) & 0x0fff)
    }
}

/// Drop one handle's entry from a completed-packets event, rewriting the list.
/// Returns `None` when no entry remains.
fn remove_completed_handle(mut packet: Packet, handle: u16) -> Option<Packet> {
    if completed_handles(&packet).next().is_none() {
        return Some(packet);
    }
    let count = usize::from(packet.bytes[2]);
    let mut kept = 0usize;
    for index in 0..count {
        let at = 3 + 4 * index;
        let named = u16::from_le_bytes([packet.bytes[at], packet.bytes[at + 1]]) & 0x0fff;
        if named == handle {
            continue;
        }
        let dest = 3 + 4 * kept;
        let entry = [
            packet.bytes[at],
            packet.bytes[at + 1],
            packet.bytes[at + 2],
            packet.bytes[at + 3],
        ];
        packet.bytes[dest..dest + 4].copy_from_slice(&entry);
        kept += 1;
    }
    if kept == 0 {
        return None;
    }
    packet.bytes[2] = kept as u8;
    packet.bytes[1] = (1 + 4 * kept) as u8;
    packet.len = 3 + 4 * kept;
    Some(packet)
}

/// Remove only the closing link's data without discarding command replies,
/// promised lifecycle events or other links' packets. `key` is the identity
/// that was live before this close, so a reused handle cannot be affected.
pub(crate) fn discard_connection_data(handle: u16, key: LinkKey) {
    retain_output(|entry| {
        if matches!(entry.scope, PacketScope::Connection { handle: scoped, key: tagged }
            if scoped == handle && tagged == key)
        {
            return None;
        }
        if acl_handle(&entry.packet) == Some(handle) {
            return None;
        }
        let packet = remove_completed_handle(entry.packet, handle)?;
        Some(ControllerPacket {
            packet,
            scope: entry.scope,
        })
    });
    // Connection-scoped commands keep their producer-time scope, so they are
    // answered as stale instead of being applied to the next link.
    if let Ok(host) = HOST_TO_CONTROLLER.try_receive() {
        if acl_handle(&host.packet) != Some(handle) {
            let _ = HOST_TO_CONTROLLER.try_send(host);
        }
    }
}

/// Reset-only cleanup: every link and its pending data are retired.
pub(crate) fn discard_all_connection_data() {
    retain_output(|entry| {
        (entry.packet.kind != PacketKind::AclData
            && completed_handles(&entry.packet).next().is_none())
        .then_some(entry)
    });
    if let Ok(host) = HOST_TO_CONTROLLER.try_receive() {
        if host.packet.kind != PacketKind::AclData {
            let _ = HOST_TO_CONTROLLER.try_send(host);
        }
    }
}

fn retain_output(mut rewrite: impl FnMut(ControllerPacket) -> Option<ControllerPacket>) {
    let mut retained = [None; CONTROLLER_TO_HOST_CAPACITY];
    let mut count = 0;
    while let Ok(entry) = CONTROLLER_TO_HOST.try_receive() {
        if let Some(entry) = rewrite(entry) {
            retained[count] = Some(entry);
            count += 1;
        }
    }
    for entry in retained.into_iter().flatten() {
        let _ = CONTROLLER_TO_HOST.try_send(entry);
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
    critical_section::with(|cs| {
        LINKS.borrow(cs).set([None; MAX_LINKS]);
        PENDING_EVENTS
            .borrow(cs)
            .set(([[None; PENDING_HANDLES]; MAX_LINKS], [false; MAX_LINKS]));
    });
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

    fn acl(handle: u16, byte: u8) -> Packet {
        Packet::from_bytes(
            PacketKind::AclData,
            &[handle as u8, (handle >> 8) as u8, 1, 0, byte],
        )
        .unwrap()
    }

    fn completed(handle: u16) -> Packet {
        super::super::connection::event_packet(0x13, &[1, handle as u8, (handle >> 8) as u8, 1, 0])
    }

    fn completed_multi(entries: &[(u16, u16)]) -> Packet {
        let mut parameters = [0u8; 1 + 8];
        parameters[0] = entries.len() as u8;
        for (index, (handle, count)) in entries.iter().enumerate() {
            parameters[1 + 4 * index..3 + 4 * index].copy_from_slice(&handle.to_le_bytes());
            parameters[3 + 4 * index..5 + 4 * index].copy_from_slice(&count.to_le_bytes());
        }
        super::super::connection::event_packet(0x13, &parameters[..1 + 4 * entries.len()])
    }

    fn disconnect_complete() -> Packet {
        super::super::connection::event_packet(0x05, &[0, 1, 0, 0x13])
    }

    fn connection_complete() -> Packet {
        super::super::connection::event_packet(0x3e, &[0x01; 19])
    }

    #[test]
    fn scoped_discard_keeps_the_other_link() {
        let _guard = crate::hci::test_lock::lock();
        drain_channels_for_test();
        let key = LinkKey {
            slot: 0,
            generation: 3,
        };
        set_link(0, Some((1, key)));
        set_link(
            1,
            Some((
                2,
                LinkKey {
                    slot: 1,
                    generation: 3,
                },
            )),
        );
        try_send_controller_packet(acl(1, 0xaa)).unwrap();
        try_send_controller_packet(acl(2, 0xbb)).unwrap();
        try_send_controller_packet(completed(1)).unwrap();
        try_send_controller_packet(completed(2)).unwrap();
        try_send_host_packet(acl(2, 0xcc)).unwrap();

        discard_connection_data(1, key);

        let first = try_receive_controller_packet().unwrap();
        let second = try_receive_controller_packet().unwrap();
        assert!(try_receive_controller_packet().is_none());
        assert_eq!(first.payload(), &[2, 0, 1, 0, 0xbb]);
        assert_eq!(second.payload()[..5], [0x13, 5, 1, 2, 0]);

        let host = try_receive_host_packet().unwrap();
        assert_eq!(host.packet.payload()[..2], [2, 0]);
        assert!(try_receive_host_packet().is_none());
    }

    #[test]
    fn aggregated_completed_packets_keep_the_other_links_entries() {
        let _guard = crate::hci::test_lock::lock();
        drain_channels_for_test();
        let key = LinkKey {
            slot: 0,
            generation: 4,
        };
        set_link(0, Some((1, key)));
        set_link(
            1,
            Some((
                2,
                LinkKey {
                    slot: 1,
                    generation: 4,
                },
            )),
        );
        try_send_controller_packet(completed_multi(&[(1, 2), (2, 3)])).unwrap();
        // Promised lifecycle events survive the close.
        try_send_controller_packet(disconnect_complete()).unwrap();
        try_send_controller_packet(connection_complete()).unwrap();

        discard_connection_data(1, key);

        let completion = try_receive_controller_packet().unwrap();
        assert_eq!(completion.payload(), &[0x13, 5, 1, 2, 0, 3, 0]);
        let disconnect = try_receive_controller_packet().unwrap();
        assert_eq!(disconnect.payload()[..2], [0x05, 4]);
        let connect = try_receive_controller_packet().unwrap();
        assert_eq!(connect.payload()[0], 0x3e);
        assert!(try_receive_controller_packet().is_none());
    }

    #[test]
    fn reset_discard_drops_link_data_but_keeps_command_replies() {
        let _guard = crate::hci::test_lock::lock();
        drain_channels_for_test();
        try_send_controller_packet(acl(1, 0xaa)).unwrap();
        try_send_controller_packet(completed(1)).unwrap();
        try_send_controller_packet(command_complete_packet(0x0c03, 0, &[])).unwrap();
        try_send_host_packet(acl(1, 0xcc)).unwrap();

        discard_all_connection_data();

        let kept = try_receive_controller_packet().unwrap();
        assert!(try_receive_controller_packet().is_none());
        assert_eq!(kept.payload()[..5], [0x0e, 4, 1, 0x03, 0x0c]);
        assert!(try_receive_host_packet().is_none());
    }
}
