//! Per-SoC bases, IRQ numbers, and DevInit / radio backends.
//!
//! Layout: **one module per chip feature**. Shared register *offsets* live in
//! [`crate::rf::regs`]; table shapes / certainty tags in [`tables`].
//!
//! HAL crates enable exactly one chip feature; [`crate::rf::Backend`] aliases
//! that module's radio type.

pub mod tables;

#[cfg(all(feature = "ch32v208", not(feature = "ch583"), not(feature = "ch585")))]
pub mod ch32v208;

#[cfg(all(feature = "ch583", not(feature = "ch32v208"), not(feature = "ch585")))]
pub mod ch583;

#[cfg(all(feature = "ch585", not(feature = "ch32v208"), not(feature = "ch583")))]
pub mod ch585;
