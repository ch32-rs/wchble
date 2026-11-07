//! Connection state machine shell.

/// Connection handle / timing placeholders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnState {
    pub handle: Option<u16>,
    pub interval_slots: u16,
    pub latency: u16,
    pub timeout_slots: u16,
}

impl Default for ConnState {
    fn default() -> Self {
        Self {
            handle: None,
            interval_slots: 24,
            latency: 0,
            timeout_slots: 200,
        }
    }
}
