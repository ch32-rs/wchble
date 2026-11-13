//! `embassy-crypto` RNG driver for Trouble's SMP.
//!
//! The controller owns one ChaCha20 DRBG for LL randomness; the Host needs a
//! second, independent stream for SMP (private keys, pairing random). The
//! second stream is seeded from the first DRBG after it consumes the measured
//! entropy seed, so both streams start from the same physical noise without
//! sharing keystream.
//!
//! This firmware is single-core and single-threaded: only the pinned Host
//! future calls `fill_bytes`, never from an interrupt, so an `UnsafeCell` is
//! enough. A call before seeding parks instead of returning predictable bytes.

use core::cell::UnsafeCell;

use wchble::rand::ChaCha20Drbg;

struct Cell(UnsafeCell<Option<ChaCha20Drbg>>);
// Safety: single-core firmware; the driver is only called from the one thread
// that polls the Host future, and `seed` runs before the stack is started.
unsafe impl Sync for Cell {}

static RNG: Cell = Cell(UnsafeCell::new(None));

/// Install a 32-byte seed taken from the controller DRBG.
pub fn seed(seed: &[u8; 32]) {
    unsafe {
        *RNG.0.get() = Some(ChaCha20Drbg::from_seed(seed));
    }
}

pub fn seeded() -> bool {
    unsafe { (*RNG.0.get()).is_some() }
}

struct Driver;

impl embassy_crypto::driver::Rng for Driver {
    fn fill_bytes(buf: &mut [u8]) {
        unsafe {
            match (*RNG.0.get()).as_mut() {
                Some(rng) => rng.fill(buf),
                None => panic!("crypto RNG used before seeding"),
            }
        }
    }
}

embassy_crypto::rng_impl!(Driver);
