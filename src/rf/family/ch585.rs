//! CH585 BLE IP bases, known DevInit tables, and stub radio backend.
//!
//! Map (from `BLE_IPCoreInit` / SFR):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21
//!
//! Tables are the CH5xx **"new tables"** bucket (not V208, not CH583).
//! Unique: 4th VCO band `nCO2522`, WaitTune 8000, no `RFEND_Reset`.
//! See `docs/research/{family-comparison,ch58x-reuse,bringup-debug}.md`.
//!
//! External Rust CH585 RF reference (`rusted-ch5/ch58x-hal` crates/ch58x-ble):
//! DMA TX/RX at `LLE+0x78/+0x7c` (not V208 `+0x70/+0x74`); LLE mode bank
//! `0x0003_0x58` class; TXCtune codes `bf/e8/d4/fc`; fractional synth via
//! `RFEND+0x44`. Full audit: `docs/research/ch58x-hal-ble-reuse.md`.
//! Do **not** reuse V208 open mode words / DevInit soup here.

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

/// `LLE_DevInit` absolute stores (`objs_CH585/lle.o`).
///
/// UNCERTAIN on silicon:
/// - `+0x2c`/`+0x3c`: carved lib says `0x6c`; rusted-ch5 RF-basic path uses `0x6e`.
/// - RMW on `LLE+0x04` (`andi -0x1f`) + halfword `+0x06 = 1` (present in rusted-ch5).
/// - Effect of `LLE+0x54 = 0` (CH585-only in this DevInit).
/// - DMA: rusted-ch5 programs TX `+0x78` / RX `+0x7c` (vs V208 `+0x70/+0x74`).
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x8c, Disasm),
        RegInit::new(0x1c, 0x76, Disasm),
        RegInit::new(0x24, 0x8c, Disasm),
        RegInit::new(0x2c, 0x6c, Disasm), // vs rusted-ch5 0x6e — resolve on silicon
        RegInit::new(0x34, 0x8c, Disasm),
        RegInit::new(0x3c, 0x6c, Disasm), // vs rusted-ch5 0x6e — resolve on silicon
        RegInit::new(0x44, 0x8c, Disasm),
        RegInit::new(0x4c, 0x76, Disasm),
        RegInit::new(0x54, 0x00, Disasm), // CH585-only
        RegInit::new(0x08, 0xffff_ffff, Disasm),
        RegInit::new(0x0c, 0x001f_000f, Disasm), // differs from CH583 0xF00F
    ],
    crc_aa_cfg_clear_mask: Some(0xffff_ffe0),
};

/// `BB_DevInit` highlights (`objs_CH585/bb.o`).
///
/// UNCERTAIN on silicon:
/// - No `BB+0x20 = 0x90083` in this DevInit (unlike CH583/V208) — needed later?
/// - Runtime power packing via `gptrRFENDReg+0x5C` branches.
/// - `BB+0` only `bseti` bit23 observed here; bit28 path unclear.
/// - PFIC unmask belongs in HAL.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x50, Disasm), // 80 — not 464
    cfg20: None,
    irqstat: Some(RegInit::new(0x38, 0x3ff, Disasm)),
    cfg3c: Some(RegInit::new(0x3c, 0x2_020c, Disasm)),
    set_bit23: true,
    set_bit28: false, // not observed in this DevInit path — UNCERTAIN if needed elsewhere
    certainty: Disasm,
};

/// RFEND WaitTune / VCO markers (no `RFEND_Reset` symbol on CH585).
///
/// UNCERTAIN on silicon:
/// - Full `RFEND_DevInit` RMW list after `+0x28=0x480` (short but dense).
/// - `TXCtune` 4-band interpolation with `nCO2522`.
/// - `RFEND_SetSensitivity` is effectively empty in the carved object — rely on
///   defaults or missing feature?
/// - Coded-PHY BB bits: public `LLE_MODE_PHY_*` headers emphasize 1M/2M.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    wait_tune_half_us: RegInit::new(0x64, 8000, Disasm),
    vco_mhz: &[2401, 2440, 2480, 2522],
    certainty: Disasm,
};

stub_radio!(Ch585Radio);
