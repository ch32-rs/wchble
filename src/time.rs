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

/// Extend a polled 32-bit free-running counter without relying on a high register.
///
/// One owner must sample more often than once per hardware rollover. This cannot
/// recover whole rollovers missed while the owner sleeps or is preempted.
#[derive(Debug, Clone, Copy)]
pub struct ExtendingTicks {
    last: u32,
    elapsed: u64,
}

impl ExtendingTicks {
    pub fn new(raw: u32) -> Self {
        Self {
            last: raw,
            elapsed: 0,
        }
    }

    pub fn sample(&mut self, raw: u32) -> u64 {
        self.elapsed = self
            .elapsed
            .wrapping_add(u64::from(raw.wrapping_sub(self.last)));
        self.last = raw;
        self.elapsed
    }
}

/// Fixed-point conversion of a wide free-running tick counter to wrapping µs.
///
/// Compute the rate once, outside radio deadlines. Rounding loses less than one
/// microsecond per 2^32 input ticks; unlike dividing the low word first, this
/// stays continuous across the hardware counter's low-word rollover.
#[derive(Debug, Clone, Copy)]
pub struct TickRate {
    micros_q32: u64,
}

impl TickRate {
    pub fn new(hz: u32) -> Option<Self> {
        if hz == 0 {
            return None;
        }
        Some(Self {
            micros_q32: (1_000_000u64 << 32) / u64::from(hz),
        })
    }

    pub fn micros(&self, ticks: u64) -> u32 {
        (ticks.wrapping_mul(self.micros_q32) >> 32) as u32
    }
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

#[cfg(test)]
mod tests {
    use super::{ExtendingTicks, TickRate};

    #[test]
    fn polled_low_word_extends_across_repeated_hardware_rollovers() {
        // Model the actual CH585 counter: only the low word advances. The
        // software samples far more often than the ~69 s hardware rollover.
        let hz = 62_513_320u64;
        let origin = u64::from(u32::MAX) - hz / 2;
        let mut counter = ExtendingTicks::new(origin as u32);
        let rate = TickRate::new(hz as u32).unwrap();
        for millis in 0..=360_000u64 {
            let elapsed = hz * millis / 1000;
            let extended = counter.sample(origin.wrapping_add(elapsed) as u32);
            assert_eq!(extended, elapsed);
            assert!((millis as u32 * 1000).wrapping_sub(rate.micros(extended)) <= 6);
        }
    }

    #[test]
    fn hse_nominal_rate_avoids_rc_reference_scaling_error() {
        let nominal = TickRate::new(62_400_000).unwrap();
        let rc_referenced = TickRate::new(62_509_688).unwrap();
        for (ticks, exact_us, rc_us) in [
            (1_872_000, 30_000, 29_947),
            (7_488_000, 120_000, 119_789),
            (7_488_000_000, 120_000_000, 119_789_431),
        ] {
            assert!(exact_us - nominal.micros(ticks) <= 2);
            assert_eq!(rc_referenced.micros(ticks), rc_us);
        }
    }

    #[test]
    fn wide_ticks_are_continuous_across_low_word_rollover() {
        let rate = TickRate::new(60_000_000).unwrap();
        let before = rate.micros((1u64 << 32) - 600);
        let after = rate.micros((1u64 << 32) + 600);
        assert!((19..=21).contains(&after.wrapping_sub(before)));
        assert!(TickRate::new(0).is_none());
    }

    #[test]
    fn fractional_clock_rate_and_microsecond_rollover() {
        for hz in [59_999_123u32, 60_000_000, 60_012_345] {
            let rate = TickRate::new(hz).unwrap();
            for seconds in [1u64, 72, 120, 360] {
                let ticks = u64::from(hz) * seconds;
                let exact = seconds as u32 * 1_000_000;
                assert!(exact.wrapping_sub(rate.micros(ticks)) <= 6);
            }
            let middle = (1u64 << 32) * u64::from(hz) / 1_000_000;
            let step = u64::from(hz) / 1_000;
            let elapsed = rate
                .micros(middle + step)
                .wrapping_sub(rate.micros(middle - step));
            assert!((1998..=2001).contains(&elapsed));
        }
    }
}
