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

stub_radio!(Ch583Radio);
