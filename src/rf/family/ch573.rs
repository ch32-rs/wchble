//! CH573 BLE IP bases and WIP stub radio backend.
//!
//! WIP: draft-PR placeholder while DevInit tables are lifted from
//! `CH573EVT/.../libCH57xBLE.a` and the MMIO path is brought up.
//!
//! Map (same CH5xx window as CH583/585/592):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21 (PAC / vector table)
//!
//! Hard constraint: SRAM is only `0x2000_3800..0x2000_8000` (18 KiB). DMA
//! buffers must land in that window — the low `0x2000_0000` map used by
//! CH572/CH585 is illegal on this die.

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

/// Inclusive SRAM window used by LLE DMA on this die.
pub const SRAM_START: usize = 0x2000_3800;
/// Exclusive end of the SRAM window.
pub const SRAM_END: usize = 0x2000_8000;

use Certainty::Unverified as Unverified;

/// Placeholder until EVT `LLE_DevInit` is transcribed.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[],
    crc_aa_cfg_clear_mask: None,
};

/// Placeholder until EVT `BB_DevInit` is transcribed.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0, Unverified),
    cfg20: None,
    irqstat: None,
    cfg3c: None,
    set_bit23: false,
    set_bit28: false,
    certainty: Unverified,
};

/// Placeholder until EVT `RFEND_*` markers are transcribed.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0, Unverified),
    wait_tune_half_us: RegInit::new(0x64, 0, Unverified),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Unverified,
};

stub_radio!(Ch573Radio);
