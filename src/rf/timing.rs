//! Pure BLE RF timing / channel helpers (no MMIO).
//!
//! Frequency mapping is Core-spec and shared across families. TX window formulas
//! below are the **CH32V208 open `wch_rf`** versions — CH585 uses a different
//! countdown encoding; do not call these from a CH5xx `FamilyHw` blindly.

use crate::rf::PhyMode;

/// Carrier frequency in kHz for BLE channel `0..=39`.
#[inline]
pub const fn freq_for_channel_khz(channel: u8) -> u32 {
    if channel <= 36 {
        let base = if channel <= 10 { 2404u32 } else { 2406 };
        (base + 2 * channel as u32) * 1000
    } else {
        match channel {
            37 => 2_402_000,
            38 => 2_426_000,
            39 => 2_480_000,
            _ => 2_402_000,
        }
    }
}

/// Low-side LO injection bookkeeping (kHz) used by open V208 channel mode.
#[inline]
pub const fn lo_inject_khz(phy: PhyMode) -> u16 {
    match phy {
        PhyMode::Rate2m => 2000,
        _ => 1000, // 1M + both coded codings
    }
}

/// Open `BLE_SetPHYTxMode` LLE+0x64 TX busy window (half-µs) for V208.
///
/// `payload_len` is the PDU length byte (`frame[1]`), not including the 2-byte
/// header.
#[inline]
pub const fn v208_tx_window_half_us(phy: PhyMode, payload_len: u8) -> u32 {
    let len = payload_len as u32;
    match phy {
        PhyMode::Rate2m => 8 * (len + 11) + 316,
        PhyMode::RateCodedS8 => 128 * (len + 2) + 1564,
        PhyMode::RateCodedS2 => 32 * (len + 2) + 1240,
        PhyMode::Rate1m => 16 * (len + 10) + 316,
    }
}

/// Post-address-capture RX reload window (half-µs) from open `wch_rf_bb_isr`.
#[inline]
pub const fn v208_rx_capture_reload_half_us(phy: PhyMode) -> u32 {
    match phy {
        PhyMode::Rate2m => 8 * (255 + 5) + 60,
        PhyMode::RateCodedS2 | PhyMode::RateCodedS8 => (255 + 4) * 128 + 868,
        PhyMode::Rate1m => 16 * (255 + 5) + 60,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertising_and_data_channels() {
        assert_eq!(freq_for_channel_khz(37), 2_402_000);
        assert_eq!(freq_for_channel_khz(38), 2_426_000);
        assert_eq!(freq_for_channel_khz(39), 2_480_000);
        assert_eq!(freq_for_channel_khz(0), 2_404_000);
        assert_eq!(freq_for_channel_khz(10), 2_424_000);
        assert_eq!(freq_for_channel_khz(11), 2_428_000);
    }

    #[test]
    fn v208_1m_tx_window_matches_open_vector() {
        // payload 31 → 16*(41)+316 = 972
        assert_eq!(v208_tx_window_half_us(PhyMode::Rate1m, 31), 972);
    }
}
