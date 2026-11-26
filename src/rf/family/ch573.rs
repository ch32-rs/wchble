//! CH573 BLE IP bases, DevInit tables from EVT, and stub radio backend.
//!
//! Tables recovered from `CH573EVT/EXAM/BLE/LIB/libCH57xBLE.a`
//! (`lle.o` / `bb.o` / `rfend.o`). MMIO apply / `ch58x_common` wiring is next.
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
use crate::rf::family::caps::FamilyCaps;
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

use Certainty::FromClosedDisasm as Disasm;

/// `LLE_DevInit` absolute stores (`lle.o`).
///
/// Differs from CH583 old tables: timeouts `0x50`/`0x0A`, mask `0xC303`,
/// and an extra `+0x58 = 0xF6`. No `+0x08` clear observed in this body.
/// UNCERTAIN on silicon: PFIC unmask at the end belongs in the HAL.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x50, Disasm),
        RegInit::new(0x1c, 0x0a, Disasm),
        RegInit::new(0x24, 0x8c, Disasm),
        RegInit::new(0x2c, 0x3c, Disasm),
        RegInit::new(0x34, 0x8c, Disasm),
        RegInit::new(0x3c, 0x3c, Disasm),
        RegInit::new(0x44, 0x50, Disasm),
        RegInit::new(0x4c, 0x0a, Disasm),
        RegInit::new(0x58, 0xf6, Disasm),
        RegInit::new(0x0c, 0x0000_c303, Disasm),
    ],
    crc_aa_cfg_clear_mask: None,
};

/// `BB_DevInit` highlights (`bb.o`).
///
/// `BB+0x34 = 0x152` (not CH583/V208 `0x1D0`). `BB+0` packing mixes a
/// config byte with `0x0100_8000`; not the V208 `bit23`/`bit28` immediates.
/// SYS `0x40001040` SAFE_ACCESS poke stays outside this table.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x152, Disasm),
    cfg20: None,
    irqstat: None,
    cfg3c: None,
    set_bit23: false,
    set_bit28: false,
    certainty: Disasm,
};

/// RFEND markers (`rfend.o`).
///
/// `RFEND_Reset` exists but is a multi-step `+0x0C` bit bang, not a single
/// `0x1101` store. `RFEND_WaitTune` busy-waits a software countdown
/// (`0x249F2`) while polling `RFEND+0x90` — it does **not** load `LLE+0x64`.
/// TXCtune is a large 3-pass calibrate; keep the usual 3-band markers.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    // Software poll iterations in `RFEND_WaitTune`, not an LLE+0x64 store.
    wait_tune_half_us: RegInit::new(0x64, 0x0002_49f2, Disasm),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Disasm,
};

/// Hypothesize the CH585/CH592 BUFPTR class until silicon says otherwise.
pub const CAPS: FamilyCaps = FamilyCaps {
    bb_base: BB_BASE,
    lle_base: LLE_BASE,
    aes_base: AES_BASE,
    rfend_base: RFEND_BASE,
    irq_bb: IRQ_BB,
    irq_lle: IRQ_LLE,
    tx_bufptr_off: 0x78,
    rx_bufptr_off: 0x7c,
    sram_start: SRAM_START,
    sram_end: SRAM_END,
    vco_mhz: RFEND_INIT.vco_mhz,
    wait_tune_half_us: RFEND_INIT.wait_tune_half_us.value,
};

stub_radio!(Ch573Radio);
