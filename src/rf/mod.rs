//! L0 radio HAL — MMIO, init/cal, basic TX/RX, ISR hooks.
//!
//! Chip-specific bases and DevInit tables live under [`family`].

pub mod analog;
pub mod family;
pub mod isr;
pub mod regs;
pub mod timing;
pub mod txrx;

use crate::time::InstantUs;
use crate::{Error, Result};

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
    ///
    /// # Safety
    ///
    /// The LLE DMAs `frame` while the transmission is in flight, so the
    /// caller must keep it valid and unmodified for the whole call.
    ///
    /// - `Ok`: the DMA has completed.
    /// - `Err(Late)`: no transmission was started; there is no DMA in
    ///   flight, but `TXBUFPTR` may still name `frame` until the next call.
    /// - Any other error: the implementation requests an engine stop and
    ///   waits a bounded time (debug-asserted) for the LLE to report idle
    ///   before returning. A controller that does not idle within that
    ///   bound is already unusable; the call still returns.
    ///
    /// Once the call returns, the borrow may end.
    unsafe fn tx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        frame: &[u8],
        timeout_half_us: u32,
        start_cputime: Option<u32>,
    ) -> Result<()>;

    /// Arm RX for `window_half_us`; completion via callback / ISR.
    ///
    /// # Safety
    ///
    /// The LLE DMAs into `rxbuf` after this call returns. The caller must keep
    /// `rxbuf` valid and exclusively owned until the window has completed (the
    /// ISR observes `RX_DONE`/`CLEAR_ARM`) or the engine has been shut down.
    ///
    /// Re-arming while a window is still armed is allowed only while the old
    /// buffer is still live: the implementation force-stops the old window,
    /// waits for the LLE to report idle, and only then points `RXBUFPTR` at
    /// the new buffer. If the engine does not idle within the bound it
    /// returns `Err(Busy)` without touching `RXBUFPTR`, so the old buffer's
    /// obligation is unchanged.
    unsafe fn rx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        rxbuf: &mut [u8],
        window_half_us: u32,
    ) -> Result<()>;

    fn rssi(&self) -> i8;
    fn crc_ok(&self) -> bool;
}

/// Receive state a connection-event loop polls between RX arming and capture.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RxState {
    /// LLE reports RX done or a cleared arm.
    pub done: bool,
    /// BB reports no CRC error for the completed packet.
    pub crc_ok: bool,
    /// A clock capture was latched for this window.
    pub captured: bool,
}

/// Raw receive progress and bounded stop confirmation for the shared link
/// loop. [`Radio`] only arms a window; the loop also needs these primitives so
/// it can run against a fake backend as well as the CH58x/CH59x hardware.
pub trait LinkRadio: Radio {
    /// Clear the BB receive status latch before arming a window.
    fn clear_rx_status(&mut self);
    /// Current receive state for the polling loop.
    fn rx_state(&mut self) -> RxState;
    /// Latch the capture instant and reload the window (once per window).
    fn note_capture(&mut self, now_us: u32);
    /// Shut the engine down and wait, bounded, until it reports idle.
    /// `false` means the engine did not confirm idle.
    fn stop<T: InstantUs>(&mut self, clock: &T) -> bool;
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

    unsafe fn tx_basic<T: InstantUs>(
        &mut self,
        _clock: &T,
        _frame: &[u8],
        _timeout_half_us: u32,
        _start_cputime: Option<u32>,
    ) -> Result<()> {
        Err(Error::Unsupported)
    }

    unsafe fn rx_basic<T: InstantUs>(
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

#[cfg(feature = "ch573")]
pub type Backend = family::ch573::Ch573Radio;

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
    feature = "ch573",
    feature = "ch583",
    feature = "ch585",
    feature = "ch592",
    feature = "ch595",
)))]
pub type Backend = UnselectedRadio;

/// Construct the feature-selected radio backend when it implements [`Default`].
///
/// CH32V208 / CH585 / CH592 / CH573 need a DMA RX scratch — use [`new_radio_with_dma`].
#[cfg(not(any(
    feature = "ch32v208",
    feature = "ch585",
    feature = "ch592",
    feature = "ch573"
)))]
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

#[cfg(any(
    feature = "ch32v208",
    feature = "ch585",
    feature = "ch592",
    feature = "ch573"
))]
fn backend_new(rx_dma: &'static mut [u8]) -> Result<Backend> {
    Backend::new(rx_dma)
}

#[cfg(not(any(
    feature = "ch32v208",
    feature = "ch585",
    feature = "ch592",
    feature = "ch573"
)))]
fn backend_new(_rx_dma: &'static mut [u8]) -> Result<Backend> {
    Ok(Backend::default())
}
