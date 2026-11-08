//! TX/RX helpers shared by family backends.

/// Half-microsecond unit used by LLE timeout / window registers.
pub type HalfUs = u32;

/// Convert microseconds to LLE half-µs ticks.
#[inline]
pub fn us_to_half(us: u32) -> HalfUs {
    us.saturating_mul(2)
}

/// Convert LLE half-µs ticks to microseconds (truncating).
#[inline]
pub fn half_to_us(half: HalfUs) -> u32 {
    half / 2
}

/// Max PDU bytes accepted by basic TX/RX helpers (excluding AA/CRC).
pub const MAX_PDU: usize = 257;

/// Minimum RX DMA scratch length required by open `wch_rf` (`WCH_RF_RX_BUFFER_SIZE`).
pub const RX_DMA_MIN: usize = 272;
