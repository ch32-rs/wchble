//! Command reply and TO_HOST packet queues for the soft HCI.

/// HCI packet kinds Troubles expects from a controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HostPacket {
    Event,
    Acl,
}

/// Placeholder command-complete / status reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CmdReply {
    pub opcode: u16,
    pub status: u8,
}

/// Tiny fixed-capacity queue shell (no heap).
#[derive(Debug, Default)]
pub struct PacketQueue {
    pub pending_events: usize,
    pub pending_acl: usize,
}

impl PacketQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_event(&mut self) {
        self.pending_events = self.pending_events.saturating_add(1);
    }

    pub fn push_acl(&mut self) {
        self.pending_acl = self.pending_acl.saturating_add(1);
    }
}
