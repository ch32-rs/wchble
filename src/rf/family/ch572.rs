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

stub_radio!(Ch572Radio);
