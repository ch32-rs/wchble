//! Per-SoC bases, IRQ numbers, and DevInit / radio backends.
//!
//! Layout: **one module per chip feature**. Shared register *offsets* live in
//! [`crate::rf::regs`]; table shapes / certainty tags in [`tables`].
//!
//! HAL crates enable exactly one chip feature; [`crate::rf::Backend`] aliases
//! that module's radio type.

pub mod tables;

/// Generate the bookkeeping-only backend for a chip whose MMIO path is not
/// ported yet.
///
/// The chip module supplies its own bases / DevInit tables / IRQ constants and
/// invokes `stub_radio!(ChXxxRadio);`. Every stub shares the same behaviour, so
/// a `Radio` trait change only needs one edit here.
#[allow(unused_macros)]
macro_rules! stub_radio {
    ($name:ident) => {
        #[doc = concat!("Stub ", stringify!($name), " radio — known tables recorded; MMIO apply comes later.")]
        #[derive(Debug)]
        pub struct $name {
            channel: Channel,
            phy_tx: PhyMode,
            phy_rx: PhyMode,
            whiten_disabled: bool,
            encrypt: bool,
            access_address: u32,
            crc_init: u32,
            isr: IsrState,
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    channel: 0xff,
                    phy_tx: PhyMode::Rate1m,
                    phy_rx: PhyMode::Rate1m,
                    whiten_disabled: false,
                    encrypt: false,
                    access_address: 0x8e89_bed6,
                    crc_init: 0x55_5555,
                    isr: IsrState::default(),
                }
            }
        }

        impl AnalogInit for $name {
            fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
                // Tables recorded; MMIO apply not ported — see bringup-debug.md.
                let _ = &RFEND_INIT;
                Err(Error::Unsupported)
            }

            fn calibrate<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
                let _ = RFEND_INIT.wait_tune_half_us;
                Err(Error::Unsupported)
            }
        }

        impl Radio for $name {
            fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
                // Order: LLE_DevInit → RFEND_DevInit → BB_DevInit → cal.
                // HAL: BLE clock / HSE capacitance / NVIC 20/21.
                let _ = (clock, &LLE_DEV_INIT, &BB_DEV_INIT, IRQ_BB, IRQ_LLE);
                Err(Error::Unsupported)
            }

            fn recalibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
                self.calibrate(clock)
            }

            fn shut(&mut self) {}

            fn set_channel(&mut self, channel: Channel) -> Result<()> {
                if channel > 39 {
                    return Err(Error::InvalidState);
                }
                self.channel = channel;
                Ok(())
            }

            fn channel(&self) -> Channel {
                self.channel
            }

            fn set_aa_crc(&mut self, access_address: u32, crc_init: u32) {
                self.access_address = access_address;
                self.crc_init = crc_init;
            }

            fn set_phy(&mut self, tx: PhyMode, rx: PhyMode) {
                self.phy_tx = tx;
                self.phy_rx = rx;
            }

            fn set_whiten_disabled(&mut self, disabled: bool) {
                self.whiten_disabled = disabled;
            }

            fn set_encrypt(&mut self, enabled: bool) {
                self.encrypt = enabled;
            }

            fn set_callback(&mut self, cb: Option<RfCallback>) {
                self.isr.callback = cb;
            }

            fn tx_basic<T: InstantUs>(
                &mut self,
                _clock: &T,
                frame: &[u8],
                _timeout_half_us: u32,
                _start_cputime: Option<u32>,
            ) -> Result<()> {
                if frame.len() < 2 {
                    return Err(Error::InvalidState);
                }
                // UNCERTAIN: LLE mode words / TX path not proven on this chip.
                Err(Error::Unsupported)
            }

            fn rx_basic<T: InstantUs>(
                &mut self,
                _clock: &T,
                rxbuf: &mut [u8],
                _window_half_us: u32,
            ) -> Result<()> {
                if rxbuf.is_empty() {
                    return Err(Error::InvalidState);
                }
                Err(Error::Unsupported)
            }

            fn rssi(&self) -> i8 {
                0
            }

            fn crc_ok(&self) -> bool {
                false
            }
        }
    };
}


// One feature per module. Multi-chip builds are rejected by the `compile_error!`
// in `lib.rs`, so the modules do not repeat `not(feature = ...)` guards.
#[cfg(feature = "ch32v208")]
pub mod ch32v208;

#[cfg(feature = "ch572")]
pub mod ch572;

#[cfg(feature = "ch583")]
pub mod ch583;

#[cfg(feature = "ch585")]
pub mod ch585;

#[cfg(feature = "ch595")]
pub mod ch595;
