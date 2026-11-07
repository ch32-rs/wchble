//! CH32V208 BLE IP bases and stub radio backend.
//!
//! Absolute map (from open `wch_rf.h` / `docs/research/init-diff-table.md`):
//! - TOP   `0x4002_4000`
//! - BB    `0x4002_4100`
//! - LLE   `0x4002_4200`
//! - AES   `0x4002_4300`
//! - RFEND `0x4002_5000`
//! - MISC  `0x4002_2000`
//! - IRQs BB=63, LLE=64
//!
//! Relative from BB: LLE +0x100, AES +0x200, RFEND +0xF00.
//!
//! Table constants below are from the **open** `wch_rf` driver (VerifiedFromOpen).
//! Full RFEND DevInit bit soup still ports from `wch_rf_analog.c`.

use crate::rf::analog::AnalogInit;
use crate::rf::family::tables::{
    BbDevInit, Certainty, LleDevInit, RegInit, RfendInit,
};
use crate::rf::isr::IsrState;
use crate::rf::{Channel, PhyMode, Radio, RfCallback};
use crate::time::InstantUs;
use crate::{Error, Result};

use Certainty::Unverified;
use Certainty::VerifiedFromOpen as Open;

/// BLE IP top-level base (not the BB block).
pub const TOP_BASE: usize = 0x4002_4000;
/// Baseband register block base.
pub const BB_BASE: usize = 0x4002_4100;
/// Link-layer engine base (BB + 0x100).
pub const LLE_BASE: usize = 0x4002_4200;
/// AES engine base (BB + 0x200).
pub const AES_BASE: usize = 0x4002_4300;
/// RF frontend / analog base (BB + 0xF00).
pub const RFEND_BASE: usize = 0x4002_5000;
/// Misc / OSC-adjacent BLE region used by CTE and related bits.
pub const MISC_BASE: usize = 0x4002_2000;

/// BB interrupt number (`BB_IRQn`).
pub const IRQ_BB: u8 = 63;
/// LLE interrupt number (`LLE_IRQn`).
pub const IRQ_LLE: u8 = 64;

/// `LLE_DevInit` stores from open `wch_rf.c` / research table.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x8c, Open),
        RegInit::new(0x1c, 0x6c, Open),
        RegInit::new(0x24, 0x8c, Open),
        RegInit::new(0x2c, 0x3c, Open),
        RegInit::new(0x34, 0x8c, Open),
        RegInit::new(0x3c, 0x3c, Open),
        RegInit::new(0x44, 0x8c, Open),
        RegInit::new(0x4c, 0x6c, Open),
        RegInit::new(0x08, 0xffff, Open),
        RegInit::new(0x0c, 0xf00f, Open),
    ],
    crc_aa_cfg_clear_mask: None,
};

/// `BB_DevInit` highlights from open `wch_rf.c`.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x1d0, Open), // 464
    cfg20: Some(RegInit::new(0x20, 0x90083, Open)),
    irqstat: None, // open init clears to 0xF0 after cal — see wch_rf_init
    cfg3c: None,
    set_bit23: true,
    set_bit28: true,
    certainty: Open,
};

/// RFEND reset / WaitTune / VCO from open `wch_rf_analog.c`.
///
/// UNCERTAIN until full analog port: complete DevInit RMW list after +0x28.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: Some(RegInit::new(0x0c, 0x1101, Open)),
    dev_init_0x28: RegInit::new(0x28, 0x480, Open),
    wait_tune_half_us: RegInit::new(0x64, 6000, Open),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Open,
};

/// Stub CH32V208 radio — MMIO sequences land in the RF port phase.
#[derive(Debug)]
pub struct Ch32v208Radio {
    channel: Channel,
    phy_tx: PhyMode,
    phy_rx: PhyMode,
    whiten_disabled: bool,
    encrypt: bool,
    access_address: u32,
    crc_init: u32,
    isr: IsrState,
}

impl Default for Ch32v208Radio {
    fn default() -> Self {
        Self {
            // 0xFF = unset until set_channel (matches wch_rf).
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

impl AnalogInit for Ch32v208Radio {
    fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        // Known markers in RFEND_INIT; full bit soup still TODO from wch_rf_analog.c.
        let _ = (RFEND_INIT, Unverified);
        Err(Error::Unsupported)
    }

    fn calibrate<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        // TODO: TXCtune / TXFtune / RXFilter / RXAdc (WaitTune=6000).
        let _ = RFEND_INIT.wait_tune_half_us;
        Err(Error::Unsupported)
    }
}

impl Radio for Ch32v208Radio {
    fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        // Golden wch_rf_init order:
        //   1. AHB BLE clock enable (HAL / RCC — not owned here)
        //   2. HSE load trim (HAL / OSC)
        //   3. LLE_DevInit
        //   4. RFEND_DevInit
        //   5. BB_DevInit
        //   6. TXCtune → TXFtune → RXFilter → RXAdc
        //   7. NVIC BB/LLE enable (HAL)
        // Steps 1/2/7 stay in ch32-hal; 3–6 are the RF port.
        let _ = (clock, &LLE_DEV_INIT, &BB_DEV_INIT, IRQ_BB, IRQ_LLE);
        Err(Error::Unsupported)
    }

    fn recalibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        self.calibrate(clock)
    }

    fn shut(&mut self) {
        // TODO: assert RFCTRL.SHUT / force LLE stop (wch_rf_shut)
    }

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
        // Frame is [hdr][len][payload…]; need at least the two header bytes.
        if frame.len() < 2 {
            return Err(Error::InvalidState);
        }
        // TODO: program TXBUFPTR / LLE mode / RFCTRL trigger
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
        // TODO: arm RX window
        Err(Error::Unsupported)
    }

    fn rssi(&self) -> i8 {
        0
    }

    fn crc_ok(&self) -> bool {
        false
    }
}
