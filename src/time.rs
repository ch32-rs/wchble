//! Timebase adapter used by RF calibration polls and PHY scheduling.
//!
//! Firmware should install a 1 MHz (or otherwise documented) monotonic before
//! calling [`crate::rf`] init. The scaffold keeps a tiny trait so Embassy and
//! bare-metal ports can plug different counters.

/// Free-running microsecond time source.
pub trait InstantUs {
    /// Current tick in microseconds (wrapping).
    fn now_us(&self) -> u32;

    /// Busy-wait at least `us` microseconds.
    fn delay_us(&self, us: u32);
}

/// No-op clock for host-side unit tests / typecheck without hardware.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullClock;

impl InstantUs for NullClock {
    fn now_us(&self) -> u32 {
        0
    }

    fn delay_us(&self, _us: u32) {}
}
