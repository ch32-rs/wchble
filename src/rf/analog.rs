//! RFEND DevInit + calibration helpers (TXCtune / TXFtune / RXFilter / RXAdc).
//!
//! Concrete register sequences are chip-family tables under [`crate::rf::family`].
//! Shared poll / nibble helpers below match open `wch_rf_analog.c`.

use crate::rf::regs::{self, lle, rfend};
use crate::time::InstantUs;
use crate::{Error, Result};

/// CPU-side fallback when LLE WaitTune / filter windows never complete (µs).
pub const CAL_TIMEOUT_US: u32 = 10_000;

/// Analog bring-up hooks implemented per family.
pub trait AnalogInit {
    fn rfend_dev_init<T: InstantUs>(&mut self, clock: &T) -> Result<()>;
    fn calibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()>;
}

/// Short settle used by RXFilter (open `settle`: 2 µs).
#[inline]
pub fn settle<T: InstantUs>(clock: &T) {
    clock.delay_us(2);
}

/// Instruction fence used around LLE guard clear/restore on QingKe.
#[inline]
pub fn fence_i() {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!("fence.i", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        // Host / docs typecheck only — no I-cache to flush.
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Open `tune_div`: RISC-V DIV returns -1 for a zero divisor.
#[inline]
pub fn tune_div(numerator: i32, denominator: i32) -> i32 {
    if denominator == 0 {
        -1
    } else {
        numerator / denominator
    }
}

/// Pack a 4-bit nibble into the RFEND VCO / GA tables (`nibble_write`).
///
/// # Safety
/// `rfend_base + table_base` must be valid RFEND MMIO.
#[inline]
pub unsafe fn nibble_write(rfend_base: usize, table_base: usize, index: usize, value: i32) {
    let off = table_base + (index / 8) * 4;
    let shift = (index % 8) * 4;
    let mask = 0xfu32 << shift;
    let packed = ((value as u32) & 0xf) << shift;
    regs::rmw(rfend_base, off, mask, packed);
}

/// `RFEND_WaitTune`: succeed when both ready bits assert **or** the LLE window
/// counts to zero; hard-fail only after [`CAL_TIMEOUT_US`] with neither.
///
/// # Safety
/// `lle_base` / `rfend_base` must be the live BLE IP bases with clock enabled.
pub unsafe fn wait_tune<T: InstantUs>(
    clock: &T,
    lle_base: usize,
    rfend_base: usize,
    wait_tune_half_us: u32,
) -> Result<()> {
    regs::write(lle_base, lle::WINDOW, wait_tune_half_us);
    let started = clock.now_us();
    loop {
        let now = clock.now_us();
        let st = regs::read(rfend_base, rfend::TUNE_CO);
        let window = regs::read(lle_base, lle::WINDOW);
        if (st & rfend::TUNE_READY) == rfend::TUNE_READY {
            return Ok(());
        }
        if window == 0 {
            // Open driver treats window expiry as soft success for that band.
            return Ok(());
        }
        if now.wrapping_sub(started) >= CAL_TIMEOUT_US {
            return Err(Error::Timeout);
        }
    }
}
