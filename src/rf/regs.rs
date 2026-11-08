//! Register offsets and bitfields shared across WCH BLE IP family layouts.
//!
//! Absolute bases differ by chip; see [`crate::rf::family`]. Offsets below match
//! the CH32V208 open driver / CH5xx relative map (BB +0x100 LLE, +0x200 AES,
//! +0xF00 RFEND).

/// Read a 32-bit MMIO register at `base + off`.
///
/// # Safety
/// `base + off` must be a valid, aligned peripheral address for this chip.
#[inline(always)]
pub unsafe fn read(base: usize, off: usize) -> u32 {
    core::ptr::read_volatile((base + off) as *const u32)
}

/// Write a 32-bit MMIO register at `base + off`.
///
/// # Safety
/// `base + off` must be a valid, aligned peripheral address for this chip.
#[inline(always)]
pub unsafe fn write(base: usize, off: usize, val: u32) {
    core::ptr::write_volatile((base + off) as *mut u32, val);
}

/// Write a 16-bit MMIO register at `base + off`.
///
/// Used by CH5xx LLE (`LLE+0x06` command halfword is narrower than the word
/// registers around it).
///
/// # Safety
/// `base + off` must be a valid, 2-byte-aligned peripheral address for this chip.
#[inline(always)]
pub unsafe fn write_u16(base: usize, off: usize, val: u16) {
    core::ptr::write_volatile((base + off) as *mut u16, val);
}

/// Write an 8-bit MMIO register at `base + off`.
///
/// # Safety
/// `base + off` must be a valid peripheral byte address for this chip.
#[inline(always)]
pub unsafe fn write_u8(base: usize, off: usize, val: u8) {
    core::ptr::write_volatile((base + off) as *mut u8, val);
}

/// Read-modify-write: `reg = (reg & !clear) | set`.
///
/// # Safety
/// Same as [`read`] / [`write`].
#[inline(always)]
pub unsafe fn rmw(base: usize, off: usize, clear: u32, set: u32) {
    let v = read(base, off);
    write(base, off, (v & !clear) | set);
}

/// Byte offsets from BB base.
pub mod bb {
    pub const RFCTRL: usize = 0x00;
    pub const CRCINIT: usize = 0x04;
    pub const ACCESSADDR: usize = 0x08;
    pub const RXCFG10: usize = 0x10;
    pub const RXCFG14: usize = 0x14;
    pub const RXCFG18: usize = 0x18;
    pub const RXCFG20: usize = 0x20;
    pub const RXCFG24: usize = 0x24;
    pub const RXCFG28: usize = 0x28;
    pub const AUTOCFG: usize = 0x2c;
    pub const RSSICFO: usize = 0x30;
    pub const CFG34: usize = 0x34;
    pub const IRQSTAT: usize = 0x38;
}

/// BB AUTOCFG (`BB+0x2C`) fields.
pub mod autocfg {
    pub const ARM_MASK: u32 = 0x0000_0003;
    pub const ARM_RX: u32 = 0x0000_0001;
    /// Mask applied after packing power into bits[30:25] (open `bb_dev_init`).
    pub const CFG_MASK: u32 = 0x81ff_ffff;
    pub const CFG_SHIFT: u32 = 25;
    /// Vendor TX power enum for 0 dBm.
    pub const TX_POWER_0DBM: u32 = 9;
    /// Low bits OR'd into AUTOCFG before power pack (`0x80010EC8`).
    pub const INIT_LO: u32 = 0x8001_0ec8;
}

/// BB IRQSTAT bits / clear values.
pub mod bb_irq {
    pub const CLKCAP: u32 = 0x40;
    pub const CLKCAP_CLR: u32 = 0x60;
    /// CRC-fail sticky observed with RX_DONE (open `wch_rf_lle_isr`).
    pub const CRC_ERR: u32 = 0x20;
    /// Post-init clear written by open `wch_rf_init`.
    pub const POST_INIT_CLR: u32 = 0xf0;
    /// Timer flags acknowledged at end of open `wch_rf_bb_isr`.
    pub const TIMER_ACK: u32 = 0x90;
}

/// BB RSSICFO (`BB+0x30`) field extracts.
pub mod rssi {
    pub const SHIFT: u32 = 15;
}

/// Byte offsets from LLE base.
pub mod lle {
    pub const CMD: usize = 0x00;
    pub const CRC_AA_CFG: usize = 0x04;
    pub const IRQSTAT: usize = 0x08;
    pub const GUARD: usize = 0x0c;
    pub const TIMEOUT: usize = 0x14;
    pub const TURNAROUND: usize = 0x1c;
    pub const INIT24: usize = 0x24;
    pub const INIT2C: usize = 0x2c;
    pub const INIT34: usize = 0x34;
    pub const INIT3C: usize = 0x3c;
    pub const INIT44: usize = 0x44;
    pub const INIT4C: usize = 0x4c;
    pub const MODE: usize = 0x50;
    pub const WINDOW: usize = 0x64;
    pub const TICK: usize = 0x68;
    pub const CALLOAD: usize = 0x6c;
    pub const TXBUFPTR: usize = 0x70;
    pub const RXBUFPTR: usize = 0x74;
}

/// LLE IRQSTAT bits.
pub mod lle_irq {
    pub const RX_DONE: u32 = 0x0000_0001;
    pub const TX_DONE: u32 = 0x0000_0002;
    pub const CLEAR_ARM: u32 = 0x0000_2000;
    pub const TICK_CLR: u32 = 0x0000_4000;
}

/// Common RFCTRL bits (BB+0).
pub mod rfctrl {
    pub const CH_MASK: u32 = 0x3f;
    pub const WHITEN_OFF: u32 = 1 << 6;
    pub const SHUT: u32 = 1 << 7;
    pub const DIR_RX: u32 = 1 << 8;
    pub const DIR_MASK: u32 = 0x180;
    /// bits[13:12] PHY select.
    pub const PHY_MASK: u32 = 0x3000;
    pub const PHY_1M: u32 = 0x1000;
    pub const PHY_2M: u32 = 0x0000;
    pub const PHY_CODED: u32 = 0x2000;
    /// bit14: S=2 TX coding (used with PHY_CODED).
    pub const PHY_S2: u32 = 0x4000;
    /// bits[15:14] — clear before programming a new PHY (matches wch_rf).
    pub const CODING_MASK: u32 = 0xc000;
    pub const TX_TRIG: u32 = 0x0080_0000;
    /// BB_DevInit sets bit28.
    pub const INIT_BIT28: u32 = 0x1000_0000;
}

/// Open V208 RX demod register groups (`BLE_SetPHYRxMode`).
pub mod rxcfg {
    pub const CFG20_1M2M: u32 = 0x0009_0083;
    pub const CFG14_1M2M: u32 = 0x0810_1901;
    pub const CFG18_1M2M: u32 = 0x0003_1624;
    pub const CFG28_1M2M: u32 = 0x28be;
    pub const CFG24_1M2M: u32 = 0x0100_6310;
    pub const CFG10_1M2M: u32 = 0x0032_22d0;
    pub const CFG10_1M2M_DTM: u32 = 0x003f_a2ce;

    pub const CFG20_CODED: u32 = 0x0009_0086;
    pub const CFG14_CODED: u32 = 0x0830_1ff1;
    pub const CFG18_CODED: u32 = 0x0003_1619;
    pub const CFG28_CODED: u32 = 0x0000_28de;
    pub const CFG24_CODED: u32 = 0x0100_6310;
    /// Open header `0x034A4DF` (zero-extended).
    pub const CFG10_CODED: u32 = 0x0034_a4df;
    /// Open header `0x03FA4DF`.
    pub const CFG10_CODED_DTM: u32 = 0x003f_a4df;
}

/// LLE command bits.
pub mod lle_cmd {
    pub const START_RX: u32 = 1;
    pub const START_TX: u32 = 2;
    pub const BUSY_MASK: u32 = 3;
    pub const FORCE_STOP: u32 = 8;
}

/// Vendor mode words written to LLE+0x50 on CH32V208-class IP.
///
/// Note: open header historically names some of these `TIMEOUT_*`, but the C
/// runtime writes them to **MODE (+0x50)**, not TIMEOUT (+0x14).
pub mod lle_mode {
    pub const BASE: u32 = 0x58;
    pub const TX: u32 = 0x5a;
    pub const RX: u32 = 0x59;
    pub const CAL: u32 = 0x5d;
    pub const CCM: u32 = 0x20;
    pub const CCM_ARMED: u32 = 0x80;
    pub const DIR_MASK: u32 = 0x07;
}

/// Byte offsets / bits from RFEND base (needed by DevInit + calibration).
pub mod rfend {
    pub const TUNE: usize = 0x04;
    pub const FECTRL: usize = 0x08;
    pub const CFG0C: usize = 0x0c;
    pub const CFG28: usize = 0x28;
    pub const FREQMODE: usize = 0x2c;
    pub const CFG30: usize = 0x30;
    pub const CFG38: usize = 0x38;
    pub const CFG3C: usize = 0x3c;
    pub const SYNTH: usize = 0x44;
    pub const CFG48: usize = 0x48;
    pub const CFG4C: usize = 0x4c;
    pub const CFG50: usize = 0x50;
    pub const CFG54: usize = 0x54;
    pub const CFG58: usize = 0x58;
    pub const CFG5C: usize = 0x5c;
    pub const TUNE_CO: usize = 0x90;
    pub const TUNE_GA: usize = 0x94;
    pub const FILTMEAS: usize = 0x9c;
    pub const VCOTAB: usize = 0xa0;
    pub const VCOTAB_GA: usize = 0xc8;

    pub const TUNE_TRIG: u32 = 0x0000_0001;
    pub const TUNE_FILT: u32 = 0x0000_0010;
    pub const TUNE_TXFTUNE: u32 = 0x0000_0100;
    pub const TUNE_RXADC: u32 = 0x0001_0000;

    pub const FECTRL_RF_ON: u32 = 0x0033_0000;
    pub const FECTRL_RXFILT: u32 = 0x0020_0000;
    pub const FECTRL_RXADC: u32 = 0x0001_0000;
    /// `&=` mask used on shutdown / cal cleanup.
    pub const FECTRL_SHUT_MASK: u32 = 0xffcd_ffff;

    pub const CFG0C_FILT_TOGGLE: u32 = 0x10;
    pub const CFG0C_RXADC: u32 = 0x100;
    pub const CFG0C_RESET: u32 = 0x1101;

    pub const CFG28_INIT: u32 = 0x480;

    pub const FREQMODE_EN: u32 = 0x2;

    pub const BANDCODE_MASK: u32 = 0xfffe_00ff;
    pub const BANDCODE_SHIFT: u32 = 8;

    pub const TUNE_CO_MASK: u32 = 0x3f;
    pub const TUNE_GA_SHIFT: u32 = 10;
    pub const TUNE_GA_MASK: u32 = 0x7f;
    /// Both ready bits on `TUNE_CO` (bits 25+26).
    pub const TUNE_READY: u32 = 0x0600_0000;

    pub const FILTMEAS_RDY: u32 = 0x100;
    pub const FILTMEAS_MASK: u32 = 0x1f;
    pub const CFG50_FILT_EN: u32 = 0x1_0000;
}

/// AES block offsets (for a later HCI Encrypt cut).
pub mod aes {
    pub const CTRL: usize = 0x00;
    pub const STATUS: usize = 0x04;
    pub const CNT_LO: usize = 0x08;
    pub const CNT_HI: usize = 0x0c;
    pub const IV_LO: usize = 0x10;
    pub const IV_HI: usize = 0x14;
    pub const BLOCK0: usize = 0x18;
    pub const KEY0: usize = 0x28;

    pub const CTRL_RESET: u32 = 0x100;
    pub const CTRL_START: u32 = 0x1;
    pub const STATUS_BUSY: u32 = 0x1;
}
