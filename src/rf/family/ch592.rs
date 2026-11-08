//! CH592 (CH59x) BLE IP bases, DevInit tables, and stub backend.
//!
//! Source: `openwch/ch592` EVT v1.7 (`EVT/EXAM/BLE/LIB/LIBCH59xBLE.a`), carved
//! objects under `/tmp/ch592-objs` (`lle.o`, `bb.o`, `rfend.o`, `ip.o`,
//! `rf_ip.o`, `tmos.o`).
//!
//! Map (confirmed in `BLE_IPCoreInit`):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21
//!
//! **CH592 is not a CH585/CH595 alias.** `LLE_DevInit` writes the `0x6E` pair
//! at `+0x2C/+0x3C` (CH585 carved: `0x6C`) and defaults its timeout high byte
//! to `0x84` (CH585: `0x8C`). `BB_DevInit` writes `BB+0x38 = 0xFF` (CH585:
//! `0x3FF`). Runtime also differs: TX DMA is `LLE+0x78`, and the completion
//! clear-arm bit is `0x20000`, not V208's `0x2000`.
//!
//! Do **not** reuse V208 open-path mode words or the CH585 table file here.
//!
//! See `docs/research/ch592-baseline.md` for the raw disassembly evidence.

use crate::rf::analog::AnalogInit;
use crate::rf::family::tables::{BbDevInit, Certainty, LleDevInit, RegInit, RfendInit};
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

/// `LLE_DevInit` absolute stores (`lle.o`).
///
/// `BLE_LibInit` memsets the 64-byte `ble` config block and defaults
/// `ble+0x14` to 21, so the negative-config branch (`0x8C`) is not taken by a
/// stock SDK build; `+0x14/+0x24/+0x34/+0x44` = `0x84`.
///
/// Not represented by [`LleDevInit`]: the halfword `LLE+0x06 = 0x78`, the
/// `LLE+0x54` write sequence (`|= 0x8000_0000`, then `= 0x14`), and the
/// `LLE+0x7C` scratch pointer copied from the lib's config block. Add these
/// when applying MMIO.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x84, Disasm),
        RegInit::new(0x1c, 0x76, Disasm),
        RegInit::new(0x24, 0x84, Disasm),
        RegInit::new(0x2c, 0x6e, Disasm), // CH585 carved says 0x6c — do not copy
        RegInit::new(0x34, 0x84, Disasm),
        RegInit::new(0x3c, 0x6e, Disasm),
        RegInit::new(0x44, 0x84, Disasm),
        RegInit::new(0x4c, 0x76, Disasm),
        RegInit::new(0x54, 0x14, Disasm),
        RegInit::new(0x08, 0xffff_ffff, Disasm),
        RegInit::new(0x0c, 0x001f_000f, Disasm),
    ],
    // CH592 does not do the CH585 `LLE+0x04 &= -0x1f` RMW.
    crc_aa_cfg_clear_mask: None,
};

/// `BB_DevInit` highlights (`bb.o`).
///
/// Also written but not represented by [`BbDevInit`]: `BB+0x2C |= 0x8000_0000`
/// plus config-byte fields, `BB+0x10` low six bits = `0x0E`, and the PFIC
/// enable for IRQ 20 (HAL responsibility).
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x50, Disasm),
    cfg20: None,
    irqstat: Some(RegInit::new(0x38, 0xff, Disasm)),
    cfg3c: Some(RegInit::new(0x3c, 0x2_020c, Disasm)),
    set_bit23: true,
    set_bit28: false,
    certainty: Disasm,
};

/// RFEND / WaitTune / VCO markers (`rfend.o`).
///
/// `RFEND_DevInit` starts with `+0x28 = 0x480` and a dense RMW block
/// (`+0x3C`, `+0x54 = 9`, `+0x30`, `+0x4C`, `+0x5C`, conditional `+0x48`
/// bit31) that is not yet modelled. No `RFEND_Reset` symbol exists on CH592.
/// `RFEND_WaitTune` loads `LLE+0x64 = 8000`; TXCtune has three bands.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    wait_tune_half_us: RegInit::new(0x64, 8000, Disasm),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Disasm,
};

stub_radio!(Ch592Radio);
