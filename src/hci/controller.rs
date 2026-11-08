//! Soft HCI controller shell implementing the Path B boundary.
//!
//! Consumed by `ch32-hal` / `ch5xx-hal` apps that plug this type into
//! `trouble_host::new`. Full `bt-hci::controller::Controller` (+ CmdSync/Async)
//! wiring lands once LL advertising/connection paths exist. This stub keeps the
//! `controller` feature compiling and holds the LL + queue state Trouble will drive.

use crate::ll::LinkLayer;
use crate::rf::{Backend, Radio};
use crate::Result;

use super::queue::PacketQueue;

/// Soft HCI controller: Trouble Host ↔ queues ↔ [`LinkLayer`] ↔ [`Radio`].
pub struct SoftController<R: Radio = Backend> {
    pub radio: R,
    pub ll: LinkLayer,
    pub queue: PacketQueue,
}

impl SoftController<Backend> {
    /// Build a controller with the feature-selected radio backend.
    ///
    /// Unavailable for `ch32v208` — that backend needs an RX DMA buffer; use
    /// [`SoftController::with_radio`] with [`crate::rf::family::ch32v208::Ch32v208Radio::new`].
    #[cfg(not(feature = "ch32v208"))]
    pub fn new() -> Self {
        Self {
            radio: crate::rf::new_radio(),
            ll: LinkLayer::new(),
            queue: PacketQueue::new(),
        }
    }
}

#[cfg(not(feature = "ch32v208"))]
impl Default for SoftController<Backend> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Radio> SoftController<R> {
    /// Construct around an explicit radio backend (tests / alternate chips).
    pub fn with_radio(radio: R) -> Self {
        Self {
            radio,
            ll: LinkLayer::new(),
            queue: PacketQueue::new(),
        }
    }

    /// Reset controller state (HCI Reset stub).
    pub fn reset(&mut self) -> Result<()> {
        self.ll = LinkLayer::new();
        self.queue = PacketQueue::new();
        self.radio.shut();
        Ok(())
    }
}
