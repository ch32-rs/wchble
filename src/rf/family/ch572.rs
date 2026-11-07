//! CH572 BLE IP bases, known DevInit tables, and stub radio backend.
//!
//! Map (from `BLE_IPCoreInit` / SFR — same CH5xx window as CH583/585/595):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21
//!
//! Tables are CH5xx **"new tables"** but **not** a copy of CH585: LLE timeouts
//! are mostly `0x64`, mask `0x16000F`, BB+0x34=`0x14`, WaitTune 8000, 3-band VCO
//! (no `nCO2522`). See `docs/research/family-comparison.md`.

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

/// `LLE_DevInit` absolute stores (`objs_CH572/lle.o`).
///
/// UNCERTAIN on silicon:
/// - Entire timeout set differs from CH583/CH585/CH595 — confirm readback.
/// - Mask `0x16000F` is unique among probed parts (others use `0xF00F` / `0x1F000F`).
/// - RX pointer / `+0x04` RMW path not fully transcribed.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x64, Disasm),
        RegInit::new(0x1c, 0x6e, Disasm),
        RegInit::new(0x24, 0x64, Disasm),
        RegInit::new(0x2c, 0x64, Disasm),
        RegInit::new(0x34, 0x64, Disasm),
        RegInit::new(0x3c, 0x64, Disasm),
        RegInit::new(0x44, 0x64, Disasm),
        RegInit::new(0x4c, 0x6e, Disasm),
        RegInit::new(0x08, 0xffff_ffff, Disasm),
        RegInit::new(0x0c, 0x0016_000f, Disasm), // unique vs CH585 0x1F000F
    ],
    // Closed bodies typically RMW `LLE+0x04`; exact CH572 mask UNCERTAIN.
    crc_aa_cfg_clear_mask: Some(0xffff_ffe0),
};

/// `BB_DevInit` highlights (`objs_CH572/bb.o`, ~80 B — smallest among probed).
///
/// UNCERTAIN on silicon:
/// - `BB+0` bit23 / bit28 packing differs from V208/CH583 immediates — not
///   recorded as the same `|= 0x800000` / `|= 0x10000000` style.
/// - No `BB+0x20 = 0x90083` recovered in this DevInit.
/// - PFIC unmask belongs in HAL.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x14, Disasm), // 20 — not 464 / not 0x50
    cfg20: None,
    irqstat: None,
    cfg3c: None,
    set_bit23: false, // UNCERTAIN — packing not same as V208/CH583
    set_bit28: false, // UNCERTAIN
    certainty: Disasm,
};

/// RFEND WaitTune / VCO markers (no `RFEND_Reset` symbol on CH572).
///
/// UNCERTAIN on silicon:
/// - Full `RFEND_DevInit` RMW list after `+0x28=0x480` (~168 B object).
/// - `TXCtune` body (~3216 B) — 3-band only.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    wait_tune_half_us: RegInit::new(0x64, 8000, Disasm),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Disasm,
};

/// Stub CH572 radio — known tables recorded; MMIO apply comes later.
#[derive(Debug)]
pub struct Ch572Radio {
    channel: Channel,
    phy_tx: PhyMode,
    phy_rx: PhyMode,
    whiten_disabled: bool,
    encrypt: bool,
    access_address: u32,
    crc_init: u32,
    isr: IsrState,
}

impl Default for Ch572Radio {
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

impl AnalogInit for Ch572Radio {
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

impl Radio for Ch572Radio {
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
        // UNCERTAIN: LLE mode words / TX path not re-proven on CH572.
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
