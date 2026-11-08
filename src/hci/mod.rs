//! Soft HCI facade for Trouble (`bt-hci` Controller traits).
//!
//! Phase A shape (rusted-ch5 pattern):
//! - [`SoftController`] = `ExternalController<HciTransport, N>` for the Host
//! - [`SoftRunner`] drains Host→Controller cmds and emits Command Complete
//!
//! HAL apps must `join` Trouble's runner with [`SoftRunner::run`].

pub mod controller;
pub mod queue;
pub mod runner;
pub mod transport;

pub use controller::{new, SoftController};
pub use queue::{CmdReply, HostPacket, PacketQueue};
pub use runner::SoftRunner;
pub use transport::{Error as TransportError, HciTransport};
