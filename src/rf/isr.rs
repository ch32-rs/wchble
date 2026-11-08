//! BB / LLE interrupt dispatch hooks.

use super::{RfCallback, RfEvent};

/// Shared ISR context mutated from interrupt handlers.
#[derive(Debug, Default)]
pub struct IsrState {
    pub callback: Option<RfCallback>,
    pub last_event: Option<RfEvent>,
    pub last_status: u32,
    /// Last RX CRC-ok sticky (set in LLE ISR on RX_DONE).
    pub rx_crc_ok: bool,
    /// Engine armed for a basic RX window.
    pub rx_armed: bool,
    /// Address match / clock-capture seen for the in-flight RX.
    pub rx_captured: bool,
    /// `os_cputime`-style µs stamp from BB clock-capture.
    pub last_anchor_us: u32,
    /// PDU length byte of the last completed RX (`rxbuf[1]`).
    pub last_rx_len: u8,
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

    pub fn clear_rx_flags(&mut self) {
        self.rx_armed = false;
        self.rx_captured = false;
    }
}
