//! BB / LLE interrupt dispatch hooks.

use super::{RfCallback, RfEvent};

/// Shared ISR context mutated from interrupt handlers.
#[derive(Debug, Default)]
pub struct IsrState {
    pub callback: Option<RfCallback>,
    pub last_event: Option<RfEvent>,
    pub last_status: u32,
}

impl IsrState {
    /// Record and optionally forward an RF event.
    pub fn dispatch(&mut self, event: RfEvent, status: u32) {
        self.last_event = Some(event);
        self.last_status = status;
        if let Some(cb) = self.callback {
            cb(event, status);
        }
    }
}
