//! Legacy advertising state.

/// Advertising enable / parameters held by the LL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdvState {
    pub enabled: bool,
    pub interval_slots: u16,
    pub channel_map: u8,
}

impl Default for AdvState {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_slots: 0x0020, // ~20 ms
            channel_map: 0x07,      // 37/38/39
        }
    }
}
