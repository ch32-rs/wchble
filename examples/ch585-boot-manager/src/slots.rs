//! Slot header validation. Only the 32 B header is read at boot: the engine
//! read path is not reliable for long images (ch585-ota-spec §3.3).

use ch5xx_hal::flash::{Blocking, CodeFlash};
use wchble::ota::{HeaderError, ImageHeader};

/// Slot bases and the shared slot length (216 KiB).
pub const SLOT_BASES: [u32; 2] = [0x0000_4000, 0x0003_A000];
pub const SLOT_LEN: u32 = wchble::ota::MAX_IMAGE_LEN;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SlotState {
    Valid = 0,
    Read = 1,
    BadMagic = 2,
    BadFormat = 3,
    BadLength = 4,
    BadSequence = 5,
    BadHeaderCrc = 6,
    BadImageCrc = 7,
}

fn state_of(error: HeaderError) -> SlotState {
    match error {
        HeaderError::BadMagic => SlotState::BadMagic,
        HeaderError::BadFormat => SlotState::BadFormat,
        HeaderError::BadLength => SlotState::BadLength,
        HeaderError::BadSequence => SlotState::BadSequence,
        HeaderError::BadHeaderCrc => SlotState::BadHeaderCrc,
        HeaderError::BadImageCrc => SlotState::BadImageCrc,
    }
}

/// Read and parse the 32 B header at `base`.
pub fn read_header(
    code: &mut CodeFlash<'_, '_, Blocking>,
    base: u32,
) -> (SlotState, Option<ImageHeader>) {
    let mut raw = [0u8; 32];
    if code.blocking_read(base, &mut raw).is_err() {
        return (SlotState::Read, None);
    }
    match ImageHeader::parse(&raw) {
        Ok(header) if header.image_len <= SLOT_LEN => (SlotState::Valid, Some(header)),
        Ok(_) => (SlotState::BadLength, None),
        Err(error) => (state_of(error), None),
    }
}
