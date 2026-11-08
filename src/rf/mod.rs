//! L0 radio HAL — MMIO, init/cal, basic TX/RX, ISR hooks.
//!
//! Chip-specific bases and DevInit tables live under [`family`].

pub mod analog;
pub mod family;
pub mod isr;
pub mod regs;
pub mod timing;
pub mod txrx;

use crate::{Error, Result};
use crate::time::InstantUs;

/// BLE channel index 0..=39.
pub type Channel = u8;

/// Radio completion / progress events delivered from ISR context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RfEvent {
    TxDone,
    RxStart,
    RxDone,
    RxTimeout,
    HwErr,
}

/// Callback invoked from BB/LLE ISR paths.
pub type RfCallback = fn(RfEvent, u32);

/// PHY mode indices aligned with NimBLE `ble_phy.h` / `wch_rf_phy_mode_set`.
///
/// Discriminants matter: RFCTRL bit mapping keys off these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum PhyMode {
    /// LE Coded S=2 (500 kbps). NimBLE `BLE_PHY_MODE_CODED_500KBPS`.
    RateCodedS2 = 0,
    /// LE 1M.
    Rate1m = 1,
    /// LE 2M.
    Rate2m = 2,
    /// LE Coded S=8 (125 kbps). NimBLE `BLE_PHY_MODE_CODED_125KBPS`.
    RateCodedS8 = 3,
}

/// Chip-agnostic radio surface. Implementations are selected by chip features.
pub trait Radio {
    /// Bring up BB/LLE/RFEND and run initial calibration.
    fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()>;

    /// Periodic RF calibration when the engine is idle.
    fn recalibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()>;

    /// Force radio idle / shutdown envelope.
    fn shut(&mut self);

    fn set_channel(&mut self, channel: Channel) -> Result<()>;
    fn channel(&self) -> Channel;

    fn set_aa_crc(&mut self, access_address: u32, crc_init: u32);
    fn set_phy(&mut self, tx: PhyMode, rx: PhyMode);
    fn set_whiten_disabled(&mut self, disabled: bool);
    fn set_encrypt(&mut self, enabled: bool);

    fn set_callback(&mut self, cb: Option<RfCallback>);

    /// Blocking/basic TX; `start_cputime` is an optional absolute µs deadline base.
    fn tx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        frame: &[u8],
        timeout_half_us: u32,
        start_cputime: Option<u32>,
    ) -> Result<()>;

    /// Arm RX for `window_half_us`; completion via callback / ISR.
    fn rx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        rxbuf: &mut [u8],
        window_half_us: u32,
    ) -> Result<()>;

    fn rssi(&self) -> i8;
    fn crc_ok(&self) -> bool;
}

/// Placeholder backend when no chip feature is selected.
#[derive(Debug, Default)]
pub struct UnselectedRadio;

impl Radio for UnselectedRadio {
    fn init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn recalibrate<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn shut(&mut self) {}

    fn set_channel(&mut self, _channel: Channel) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn channel(&self) -> Channel {
        0xff
    }

    fn set_aa_crc(&mut self, _access_address: u32, _crc_init: u32) {}
    fn set_phy(&mut self, _tx: PhyMode, _rx: PhyMode) {}
    fn set_whiten_disabled(&mut self, _disabled: bool) {}
    fn set_encrypt(&mut self, _enabled: bool) {}
    fn set_callback(&mut self, _cb: Option<RfCallback>) {}

    fn tx_basic<T: InstantUs>(
        &mut self,
        _clock: &T,
        _frame: &[u8],
        _timeout_half_us: u32,
        _start_cputime: Option<u32>,
    ) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn rx_basic<T: InstantUs>(
        &mut self,
        _clock: &T,
        _rxbuf: &mut [u8],
        _window_half_us: u32,
    ) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn rssi(&self) -> i8 {
        0
    }

    fn crc_ok(&self) -> bool {
        false
    }
}

/// Active radio type for the enabled chip feature.
///
/// Exactly one chip feature may be enabled (`lib.rs` rejects combinations), so
/// each alias is gated on its own feature and a single fallback covers "none".
#[cfg(feature = "ch32v208")]
pub type Backend = family::ch32v208::Ch32v208Radio;

#[cfg(feature = "ch572")]
pub type Backend = family::ch572::Ch572Radio;

#[cfg(feature = "ch583")]
pub type Backend = family::ch583::Ch583Radio;

#[cfg(feature = "ch585")]
pub type Backend = family::ch585::Ch585Radio;

#[cfg(feature = "ch592")]
pub type Backend = family::ch592::Ch592Radio;

#[cfg(feature = "ch595")]
pub type Backend = family::ch595::Ch595Radio;

#[cfg(not(any(
    feature = "ch32v208",
    feature = "ch572",
    feature = "ch583",
    feature = "ch585",
    feature = "ch592",
    feature = "ch595",
)))]
pub type Backend = UnselectedRadio;

/// Construct the feature-selected radio backend when it implements [`Default`].
///
/// CH32V208 needs a DMA RX scratch — use [`new_radio_with_dma`] for it.
#[cfg(not(feature = "ch32v208"))]
pub fn new_radio() -> Backend {
    Backend::default()
}

/// Construct the feature-selected backend with an explicit RX DMA scratch.
///
/// The LLE DMAs through `RXBUFPTR`, so the buffer must be 4-byte aligned (see
/// [`txrx::DmaBuf`]); stub backends ignore it until their MMIO path lands.
pub fn new_radio_with_dma(rx_dma: &'static mut [u8]) -> Result<Backend> {
    backend_new(rx_dma)
}

#[cfg(feature = "ch32v208")]
fn backend_new(rx_dma: &'static mut [u8]) -> Result<Backend> {
    Backend::new(rx_dma)
}

#[cfg(not(feature = "ch32v208"))]
fn backend_new(_rx_dma: &'static mut [u8]) -> Result<Backend> {
    Ok(Backend::default())
}
