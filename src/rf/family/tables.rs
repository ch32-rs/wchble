//! DevInit / calibration table shapes shared by family backends.
//!
//! Values come from closed-lib disassembly or the open V208 driver. Every field
//! that is not yet proven on hardware should carry [`Certainty::Unverified`] so
//! bring-up logs / docs can highlight what to probe first.

/// How much we trust a constant before silicon confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Certainty {
    /// Matches open V208 driver *and* closed-lib immediate (or open-only golden).
    VerifiedFromOpen,
    /// Recovered from closed-lib disassembly; not yet run on our board.
    FromClosedDisasm,
    /// Inferred / partial; expect to change during bring-up.
    Unverified,
}

/// One MMIO store recovered from `*_DevInit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegInit {
    pub offset: u16,
    pub value: u32,
    pub certainty: Certainty,
}

impl RegInit {
    pub const fn new(offset: u16, value: u32, certainty: Certainty) -> Self {
        Self {
            offset,
            value,
            certainty,
        }
    }
}

/// Apply absolute `*(base + off) = val` stores from a DevInit table.
///
/// # Safety
/// `base` must be the correct block base for this chip; callers are responsible
/// for the HAL having already enabled the BLE AHB clock.
#[inline]
pub unsafe fn apply_stores(base: usize, stores: &[RegInit]) {
    for s in stores {
        crate::rf::regs::write(base, s.offset as usize, s.value);
    }
}

/// LLE timeout / mask block written by `LLE_DevInit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LleDevInit {
    /// Absolute stores of the form `*(lle + off) = val` (not RMW).
    pub stores: &'static [RegInit],
    /// Optional RMW on `LLE+0x04` (clear low bits). `None` if not observed.
    pub crc_aa_cfg_clear_mask: Option<u32>,
}

/// BB DevInit highlights we care about for first bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BbDevInit {
    pub cfg34: RegInit,
    /// Optional `BB+0x20` magic (V208/CH583).
    pub cfg20: Option<RegInit>,
    /// Optional post/pre IRQSTAT write (`BB+0x38`).
    pub irqstat: Option<RegInit>,
    /// Optional CH585-only `BB+0x3C`.
    pub cfg3c: Option<RegInit>,
    /// Set bit23 (`0x800000`) on `BB+0` during DevInit?
    pub set_bit23: bool,
    /// Set bit28 (`0x10000000`) on `BB+0` during DevInit?
    pub set_bit28: bool,
    pub certainty: Certainty,
}

/// RFEND reset / DevInit / WaitTune envelope markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfendInit {
    /// `RFEND+0x0C` pulse value if `RFEND_Reset` exists (V208/CH583: `0x1101`).
    pub reset_pulse: Option<RegInit>,
    /// First DevInit store seen on all parts: `RFEND+0x28 = 0x480`.
    pub dev_init_0x28: RegInit,
    /// Half-µs window loaded into `LLE+0x64` by `RFEND_WaitTune`.
    pub wait_tune_half_us: RegInit,
    /// VCO calibration sample frequencies in MHz (e.g. 2401/2440/2480[/2522]).
    pub vco_mhz: &'static [u16],
    pub certainty: Certainty,
}
