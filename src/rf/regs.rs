//! Register offsets and bitfields shared across WCH BLE IP family layouts.
//!
//! Absolute bases differ by chip; see [`crate::rf::family`]. Offsets below match
//! the CH32V208 open driver / CH5xx relative map (BB +0x100 LLE, +0x200 AES,
//! +0xF00 RFEND).

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
    pub const TXBUFPTR: usize = 0x70;
    pub const RXBUFPTR: usize = 0x74;
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
}

/// LLE command bits.
pub mod lle_cmd {
    pub const START_RX: u32 = 1;
    pub const START_TX: u32 = 2;
    pub const BUSY_MASK: u32 = 3;
    pub const FORCE_STOP: u32 = 8;
}

/// Vendor mode words written to LLE+0x50 on CH32V208-class IP.
pub mod lle_mode {
    pub const TX: u32 = 0x5a;
    pub const RX: u32 = 0x59;
    pub const CAL: u32 = 0x5d;
}
