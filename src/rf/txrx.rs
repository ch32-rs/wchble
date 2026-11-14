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

/// True when `frame` is a complete LE PDU: a header octet, a length octet and
/// exactly that many payload octets. The LLE is programmed with `frame[1]` and
/// DMAs the header-implied extent, so a shorter slice makes it read stale or
/// out-of-bounds memory and a longer one hides caller mistakes. Advertising,
/// scan and data PDUs all share this layout.
pub fn tx_frame_valid(frame: &[u8]) -> bool {
    frame.len() >= 2 && frame.len() == 2 + usize::from(frame[1])
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_frame_extent_matches_the_length_octet() {
        let mut frame = [0x02u8; 2 + 255];
        for payload in [0usize, 27, 251, 255] {
            frame[1] = payload as u8;
            assert!(tx_frame_valid(&frame[..2 + payload]), "payload={payload}");
        }
        // Too short for the declared payload: the DMA would read past it.
        assert!(!tx_frame_valid(&[0x02, 255, 0, 0]));
        // One octet missing, one octet extra.
        assert!(!tx_frame_valid(&[0x02, 1]));
        assert!(!tx_frame_valid(&[0x02, 1, 0, 0]));
        // Header only.
        assert!(!tx_frame_valid(&[0x02]));
        assert!(!tx_frame_valid(&[]));
    }
}
