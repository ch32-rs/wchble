#![no_std]
#![allow(async_fn_in_trait)]

//! Open WCH BLE controller building blocks for `ch32-hal` / `ch5xx-hal`.
//!
//! This crate is an Embassy-style Bluetooth compatibility layer: HALs own
//! clocks, NVIC, and Embassy executor wiring; `wchble` owns RF → PHY → LL →
//! soft HCI (`bt-hci`) for Trouble Host.
//!
//! Layers (bottom → top):
//! - [`rf`] — MMIO radio HAL
//! - [`phy`] — soft IFS / WFR policy
//! - [`ll`] — link layer state machines
//! - [`hci`] — soft HCI for Trouble (`controller` feature)

#[cfg(any(
    all(feature = "ch32v208", feature = "ch572"),
    all(feature = "ch32v208", feature = "ch583"),
    all(feature = "ch32v208", feature = "ch585"),
    all(feature = "ch32v208", feature = "ch592"),
    all(feature = "ch32v208", feature = "ch595"),
    all(feature = "ch572", feature = "ch583"),
    all(feature = "ch572", feature = "ch585"),
    all(feature = "ch572", feature = "ch592"),
    all(feature = "ch572", feature = "ch595"),
    all(feature = "ch583", feature = "ch585"),
    all(feature = "ch583", feature = "ch592"),
    all(feature = "ch583", feature = "ch595"),
    all(feature = "ch585", feature = "ch592"),
    all(feature = "ch585", feature = "ch595"),
    all(feature = "ch592", feature = "ch595"),
))]
compile_error!(
    "enable at most one chip feature (`ch32v208`, `ch572`, `ch583`, `ch585`, `ch592`, or `ch595`)"
);

pub mod rf;
pub mod storage;
pub mod time;

#[cfg(feature = "phy")]
pub mod phy;

#[cfg(feature = "controller")]
pub mod crypto;

#[cfg(feature = "controller")]
pub mod rand;

#[cfg(feature = "controller")]
pub mod ll;

#[cfg(feature = "controller")]
pub mod hci;

/// Crate-level result alias used by radio bring-up helpers.
pub type Result<T> = core::result::Result<T, Error>;

/// Minimal error type for scaffold / bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// Feature or chip backend not enabled / not yet ported.
    Unsupported,
    /// Hardware / calibration timed out.
    Timeout,
    /// Invalid argument or state.
    InvalidState,
    /// Busy (engine active).
    Busy,
    /// Scheduled TX start missed its absolute deadline (open `wch_rf_tx_basic` −2).
    Late,
}
