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

/// 4-byte-aligned scratch buffer for LLE DMA (`TXBUFPTR` / `RXBUFPTR`).
///
/// The LLE reads DMA pointers as word addresses, so every buffer programmed
/// into it must be word-aligned. Keep one of these instead of a plain array
/// (or letting a `&mut [u8]` land at an arbitrary offset).
#[repr(align(4))]
#[derive(Clone, Copy, Debug)]
pub struct DmaBuf<const N: usize>(pub [u8; N]);

impl<const N: usize> DmaBuf<N> {
    pub const fn zeroed() -> Self {
        Self([0; N])
    }
}
