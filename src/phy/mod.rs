//! Soft PHY policy — IFS, WFR extension, PDU ↔ radio mapping.
//!
//! Enabled with the `phy` feature. Keeps timing policy out of [`crate::rf`].

use crate::rf::{Channel, PhyMode};

/// Inter-frame space in microseconds (LE 1M default 150 µs).
pub const T_IFS_US: u32 = 150;

/// Soft window-widen request computed from drift / sleep clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Widen {
    pub us: u32,
}

/// Map a host PDU + timing request onto radio parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RadioPlan {
    pub channel: Channel,
    pub phy_tx: PhyMode,
    pub phy_rx: PhyMode,
    pub window_half_us: u32,
    pub timeout_half_us: u32,
}

/// Placeholder planner — filled when LL scheduling lands.
pub fn plan_rx(channel: Channel, phy: PhyMode, window_us: u32, widen: Widen) -> RadioPlan {
    let window = window_us.saturating_add(widen.us);
    RadioPlan {
        channel,
        phy_tx: phy,
        phy_rx: phy,
        window_half_us: window.saturating_mul(2),
        timeout_half_us: window.saturating_mul(2),
    }
}
