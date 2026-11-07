//! CH583 BLE IP bases, known DevInit tables, and stub radio backend.
//!
//! Map (from `BLE_IPCoreInit` immediates + SFR):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21
//!
//! Tables are the CH5xx **"old tables"** bucket — closest to open V208 among
//! CH57/58/59. See `docs/research/{family-comparison,ch58x-reuse}.md` and
//! `docs/research/bringup-debug.md` for silicon probe points.
//!
//! Certainty legend on table constants:
//! - [`Certainty::FromClosedDisasm`] — recovered from `objs_CH583`; not yet
//!   exercised on our hardware.
//! - [`Certainty::Unverified`] — shape known, value or side-effects unclear.

use crate::rf::analog::AnalogInit;
use crate::rf::family::tables::{
    BbDevInit, Certainty, LleDevInit, RegInit, RfendInit,
};
use crate::rf::isr::IsrState;
use crate::rf::{Channel, PhyMode, Radio, RfCallback};
use crate::time::InstantUs;
use crate::{Error, Result};

/// Baseband register block base.
pub const BB_BASE: usize = 0x4000_C100;
/// Link-layer engine base (BB + 0x100).
pub const LLE_BASE: usize = 0x4000_C200;
/// AES engine base (BB + 0x200).
pub const AES_BASE: usize = 0x4000_C300;
/// RF frontend / analog base (BB + 0xF00).
pub const RFEND_BASE: usize = 0x4000_D000;

/// BB interrupt number (`BLEB_IRQn`).
pub const IRQ_BB: u8 = 20;
/// LLE interrupt number (`BLEL_IRQn`).
pub const IRQ_LLE: u8 = 21;

use Certainty::FromClosedDisasm as Disasm;
use Certainty::Unverified;

/// `LLE_DevInit` absolute stores (disasm of `objs_CH583/lle.o`).
///
/// UNCERTAIN on silicon:
/// - Relocated store to `LLE+0x74` (RX buffer pointer) — needs live buffer addr.
/// - PFIC unmask at end of closed `LLE_DevInit` must stay in **HAL**, not here.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x8c, Disasm),
        RegInit::new(0x1c, 0x76, Disasm), // V208 open uses 0x6C — probe turnaround
        RegInit::new(0x24, 0x8c, Disasm),
        RegInit::new(0x2c, 0x3c, Disasm),
        RegInit::new(0x34, 0x8c, Disasm),
        RegInit::new(0x3c, 0x3c, Disasm),
        RegInit::new(0x44, 0x8c, Disasm),
        RegInit::new(0x4c, 0x76, Disasm), // V208 open uses 0x6C
        RegInit::new(0x08, 0xffff, Disasm),
        RegInit::new(0x0c, 0xf00f, Disasm),
    ],
    // Closed body does RMW on +0x04 (`andi -0x1f`); exact intent UNCERTAIN.
    crc_aa_cfg_clear_mask: Some(0xffff_ffe0),
};

/// `BB_DevInit` highlights (`objs_CH583/bb.o`).
///
/// UNCERTAIN on silicon:
/// - Power packing into `BB+0x2C` (reads a config byte at runtime).
/// - SYS writes around `0x40001040` / `0x40001022` in closed body — platform?
/// - PFIC unmask (IRQ 20) belongs in HAL.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x1d0, Disasm), // 464 — matches V208 open
    cfg20: Some(RegInit::new(0x20, 0x90083, Disasm)),
    irqstat: None,
    cfg3c: None,
    set_bit23: true,
    set_bit28: true,
    certainty: Disasm,
};

/// RFEND reset / WaitTune / VCO markers.
///
/// UNCERTAIN on silicon:
/// - Full `RFEND_DevInit` bit soup after `+0x28=0x480` (long sequence, not yet
///   transcribed into a store list).
/// - `TXCtune` band interpolation math (3-band; large function).
/// - Whether WaitTune countdown is hardware-decrement of `LLE+0x64` (assumed).
pub const RFEND_INIT: RfendInit = RfendInit {
    // Pulse `RFEND+0x0C = 0x1101` (same immediate class as V208 open `rf_reset`).
    reset_pulse: Some(RegInit::new(0x0c, 0x1101, Disasm)),
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    wait_tune_half_us: RegInit::new(0x64, 6000, Disasm), // loaded via LLE base
    vco_mhz: &[2401, 2440, 2480],
    certainty: Disasm,
};

/// Stub CH583 radio — applies known tables once MMIO helpers land.
#[derive(Debug)]
pub struct Ch583Radio {
    channel: Channel,
    phy_tx: PhyMode,
    phy_rx: PhyMode,
    whiten_disabled: bool,
    encrypt: bool,
    access_address: u32,
    crc_init: u32,
    isr: IsrState,
}

impl Default for Ch583Radio {
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

impl AnalogInit for Ch583Radio {
    fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        // Known: Reset pulse 0x1101, then +0x28=0x480, then long bit soup.
        // UNCERTAIN: remainder of DevInit RMW list — see bringup-debug.md.
        let _ = (RFEND_INIT, Unverified);
        Err(Error::Unsupported)
    }

    fn calibrate<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        // Known: WaitTune=6000, VCO bands 2401/2440/2480, has RFEND_Reset.
        // UNCERTAIN: TXCtune loop body / ready-bit timeout policy.
        let _ = RFEND_INIT.wait_tune_half_us;
        Err(Error::Unsupported)
    }
}

impl Radio for Ch583Radio {
    fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        // Order: LLE_DevInit → RFEND_DevInit → BB_DevInit → cal.
        // HAL must: BLE AHB/sleep clock, HSE capacitance, NVIC 20/21.
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
        // UNCERTAIN: LLE+0x50 mode words / RFCTRL trigger path not re-proven on CH583.
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
