//! Minimal embassy-time driver for the cooperative Host poll.
//!
//! Trouble's SMP uses `embassy_time::Timer` for pairing timeouts. This
//! firmware never sleeps: the main loop polls the Host frequently and the
//! radio events last at most one connection interval. The driver therefore
//! publishes a monotonically advanced microsecond timestamp each time the
//! loop reaches a poll boundary and treats `schedule_wake` as a no-op; a timer
//! fires on the next poll after its deadline (sub-millisecond in practice).
//!
//! Ticks are microseconds (`embassy-time/tick-hz-1_000_000`). The finite run
//! budget is far below the 32-bit wrap (71 minutes).

use core::task::Waker;

use portable_atomic::{AtomicU64, Ordering};

use embassy_time_driver::Driver;

static NOW_US: AtomicU64 = AtomicU64::new(0);

/// Publish `now_us`; later polls only ever move forward.
pub fn advance(now_us: u32) {
    let now = u64::from(now_us);
    if now > NOW_US.load(Ordering::Relaxed) {
        NOW_US.store(now, Ordering::Relaxed);
    }
}

struct SoftDriver;

impl Driver for SoftDriver {
    fn now(&self) -> u64 {
        NOW_US.load(Ordering::Relaxed)
    }

    fn schedule_wake(&self, _at: u64, _waker: &Waker) {
        // The main loop polls the Host on a fixed cadence; no alarm is used.
    }
}

embassy_time_driver::time_driver_impl!(static DRIVER: SoftDriver = SoftDriver);
