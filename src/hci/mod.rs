//! Soft HCI facade for Trouble (`bt-hci` Controller traits).

pub mod controller;
pub mod queue;

pub use controller::SoftController;
pub use queue::{CmdReply, HostPacket, PacketQueue};
