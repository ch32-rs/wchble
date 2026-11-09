//! Soft HCI facade for Trouble (`bt-hci` Controller traits).
//!
//! - [`SoftController`] = `ExternalController<HciTransport, N>` for the Host.
//! - [`SoftRunner`] pumps commands, ACL and connection lifecycle without blocking.
//!
//! Connected RF applications poll [`SoftRunner::pump_once`] at radio idle
//! boundaries. Advertising-only async applications can use [`SoftRunner::run`].

pub mod connection;
pub mod controller;
pub mod queue;
pub mod runner;
pub mod transport;

pub use connection::{BridgeError, ConnectionBridge, ConnectionInfo, RadioRequest, TxAcl, TxTag};
pub use controller::{new, SoftController};
pub use queue::{CmdReply, HostPacket, PacketQueue};
pub use runner::SoftRunner;
pub use transport::{Error as TransportError, HciTransport};
