//! Per-family RF constants that used to be copy-pasted across backends.
//!
//! Keep this RF-scoped. LL/HCI capability gating can grow a sibling type later
//! without pulling chip names into those layers.

/// L0 constants shared by bring-up and DMA placement checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyCaps {
    pub bb_base: usize,
    pub lle_base: usize,
    pub aes_base: usize,
    pub rfend_base: usize,
    pub irq_bb: u8,
    pub irq_lle: u8,
    /// Base for [`Self::tx_bufptr_off`] / [`Self::rx_bufptr_off`].
    ///
    /// CH585/592/V208: same as `lle_base`. CH573: separate DMA block at
    /// `0x4000_C000` (not LLE-relative).
    pub bufptr_base: usize,
    /// TX buffer pointer register offset from [`Self::bufptr_base`].
    pub tx_bufptr_off: usize,
    /// RX buffer pointer register offset from [`Self::bufptr_base`].
    pub rx_bufptr_off: usize,
    /// Inclusive start of the SRAM window LLE DMA may use.
    pub sram_start: usize,
    /// Exclusive end of the SRAM window.
    pub sram_end: usize,
    pub vco_mhz: &'static [u16],
    pub wait_tune_half_us: u32,
}

impl FamilyCaps {
    /// True when `[ptr, ptr+len)` lies entirely inside this die's SRAM window.
    #[inline]
    pub const fn contains_dma(self, ptr: usize, len: usize) -> bool {
        match ptr.checked_add(len) {
            Some(end) => ptr >= self.sram_start && end <= self.sram_end,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FamilyCaps;

    const CH573: FamilyCaps = FamilyCaps {
        bb_base: 0,
        lle_base: 0,
        aes_base: 0,
        rfend_base: 0,
        irq_bb: 0,
        irq_lle: 0,
        bufptr_base: 0x4000_c000,
        tx_bufptr_off: 0x10,
        rx_bufptr_off: 0x14,
        sram_start: 0x2000_3800,
        sram_end: 0x2000_8000,
        vco_mhz: &[],
        wait_tune_half_us: 0,
    };

    #[test]
    fn ch573_rejects_low_sram_window() {
        assert!(!CH573.contains_dma(0x2000_0000, 272));
        assert!(CH573.contains_dma(0x2000_3800, 272));
        assert!(!CH573.contains_dma(0x2000_7f00, 0x200));
    }
}
