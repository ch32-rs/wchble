//! CH595 BLE IP bases, known DevInit tables, and stub radio backend.
//!
//! Map (from `BLE_IPCoreInit` / SFR — same CH5xx window as CH572/583/585):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21
//!
//! Tables sit near CH585 ("new tables"): LLE `0x6C` pair + mask `0x1F000F`,
//! BB+0x34=`0x50`, WaitTune 8000 — but **no** 4th VCO band `nCO2522`, and LLE
//! timeout highs are `0x84` (not CH585's `0x8C`). See
//! `docs/research/family-comparison.md`.

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

/// `LLE_DevInit` absolute stores (`objs_CH595/lle.o`).
///
/// UNCERTAIN on silicon:
/// - High timeouts `0x84` vs CH585 `0x8C` — confirm readback before copying 585.
/// - RX pointer / `+0x04` RMW path not fully transcribed.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x84, Disasm), // CH585 uses 0x8C
        RegInit::new(0x1c, 0x76, Disasm),
        RegInit::new(0x24, 0x84, Disasm),
        RegInit::new(0x2c, 0x6c, Disasm), // same class as CH585
        RegInit::new(0x34, 0x84, Disasm),
        RegInit::new(0x3c, 0x6c, Disasm),
        RegInit::new(0x44, 0x84, Disasm),
        RegInit::new(0x4c, 0x76, Disasm),
        RegInit::new(0x08, 0xffff_ffff, Disasm),
        RegInit::new(0x0c, 0x001f_000f, Disasm), // same as CH585
    ],
    crc_aa_cfg_clear_mask: Some(0xffff_ffe0),
};

/// `BB_DevInit` highlights (`objs_CH595/bb.o`).
///
/// UNCERTAIN on silicon:
/// - `BB+0` bit packing marked "different" vs V208/CH583 in research — not the
///   same recovered immediates; do not assume bit23/bit28 until dump.
/// - No `BB+0x20 = 0x90083` recovered here.
/// - CH585-only extras (`+0x38`/`+0x3C`) were **not** listed for CH595.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x50, Disasm), // 80 — same as CH585
    cfg20: None,
    irqstat: None,
    cfg3c: None,
    set_bit23: false, // UNCERTAIN — packing differs from V208/CH583
    set_bit28: false, // UNCERTAIN
    certainty: Disasm,
};

/// RFEND WaitTune / VCO markers (no `RFEND_Reset` symbol on CH595).
///
/// UNCERTAIN on silicon:
/// - Full `RFEND_DevInit` RMW list after `+0x28=0x480` (~176 B object).
/// - `TXCtune` (~3436 B) — 3-band only; do **not** add CH585's 2522.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    wait_tune_half_us: RegInit::new(0x64, 8000, Disasm),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Disasm,
};

/// Stub CH595 radio — known tables recorded; MMIO apply comes later.
#[derive(Debug)]
pub struct Ch595Radio {
    channel: Channel,
    phy_tx: PhyMode,
    phy_rx: PhyMode,
    whiten_disabled: bool,
    encrypt: bool,
    access_address: u32,
    crc_init: u32,
    isr: IsrState,
}

impl Default for Ch595Radio {
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

impl AnalogInit for Ch595Radio {
    fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        // Known: +0x28=0x480; no RFEND_Reset.
        // UNCERTAIN: remainder of DevInit — see bringup-debug.md.
        let _ = (RFEND_INIT, Unverified);
        Err(Error::Unsupported)
    }

    fn calibrate<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        // Known: WaitTune=8000, VCO 2401/2440/2480 (no 2522).
        let _ = RFEND_INIT.wait_tune_half_us;
        Err(Error::Unsupported)
    }
}

impl Radio for Ch595Radio {
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
        // UNCERTAIN: LLE mode words / TX path not re-proven on CH595.
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
