//! OTA image header and boot metadata codecs, shared with `tools/ota_image.py`.

use crate::storage::crc32;

/// Slot header size; the app entry starts right after it.
pub const IMAGE_HEADER_LEN: usize = 32;
/// Entry offset inside a slot (`ORIGIN(FLASH)` of a slot image).
pub const ENTRY_OFFSET: u32 = IMAGE_HEADER_LEN as u32;
/// "CH5X" little-endian.
pub const IMAGE_MAGIC: u32 = 0x5835_4843;
pub const HEADER_FORMAT: u16 = 1;
pub const IMAGE_FORMAT: u16 = 1;
/// Largest image a 216 KiB slot accepts.
pub const MAX_IMAGE_LEN: u32 = 0x36_000;
/// Host stamped the image; runtime trust comes from the metadata good mark.
pub const FLAG_HOST_VERIFIED: u32 = 1 << 0;
pub const FLAG_DEBUG: u32 = 1 << 1;

pub const SLOT_A: u8 = 0;
pub const SLOT_B: u8 = 1;
pub const NO_SLOT: u8 = 0xFF;
/// Attempts before a slot is written off as failed.
pub const MAX_ATTEMPTS: u8 = 2;
/// Metadata flags bit0: the last decision was a rollback.
pub const META_FLAG_ROLLBACK: u8 = 1 << 0;

pub const METADATA_MAGIC: u32 = 0x4D41_544F;
pub const METADATA_VERSION: u16 = 1;
pub const METADATA_LEN: usize = 32;
/// DataFlash page offsets (relative to the region) for the dual copy.
pub const METADATA_SLOTS: [u32; 2] = [0x0000, 0x0100];

/// Why a header failed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    BadMagic,
    BadFormat,
    BadLength,
    BadSequence,
    BadHeaderCrc,
    BadImageCrc,
}

/// The 32 B slot header. CRC fields are recomputed, never trusted on input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageHeader {
    pub image_len: u32,
    pub image_crc32: u32,
    pub sequence: u32,
    pub flags: u32,
}

impl ImageHeader {
    /// Header bytes with both CRC fields zeroed (the image-CRC input form).
    pub fn raw_zeroed(&self) -> [u8; IMAGE_HEADER_LEN] {
        let mut raw = [0u8; IMAGE_HEADER_LEN];
        raw[0..4].copy_from_slice(&IMAGE_MAGIC.to_le_bytes());
        raw[4..6].copy_from_slice(&HEADER_FORMAT.to_le_bytes());
        raw[6..8].copy_from_slice(&IMAGE_FORMAT.to_le_bytes());
        raw[8..12].copy_from_slice(&self.image_len.to_le_bytes());
        raw[16..20].copy_from_slice(&self.sequence.to_le_bytes());
        raw[20..24].copy_from_slice(&self.flags.to_le_bytes());
        raw
    }

    /// In-memory form of a flat image with a stamped header.
    pub fn stamp(image: &mut [u8], sequence: u32, flags: u32) -> Result<(), HeaderError> {
        let len = u32::try_from(image.len()).map_err(|_| HeaderError::BadLength)?;
        if len <= IMAGE_HEADER_LEN as u32 || len > MAX_IMAGE_LEN {
            return Err(HeaderError::BadLength);
        }
        if sequence == 0 {
            return Err(HeaderError::BadSequence);
        }
        let header = ImageHeader {
            image_len: len,
            image_crc32: 0,
            sequence,
            flags,
        };
        image[..IMAGE_HEADER_LEN].copy_from_slice(&header.raw_zeroed());
        let image_crc = crc32(&image[..len as usize]);
        image[12..16].copy_from_slice(&image_crc.to_le_bytes());
        let header_crc = crc32(&image[..24]);
        image[24..28].copy_from_slice(&header_crc.to_le_bytes());
        Ok(())
    }

    /// Validate magic/formats/length/sequence/header CRC. The image CRC is
    /// checked separately because it streams the whole slot.
    pub fn parse(raw: &[u8; IMAGE_HEADER_LEN]) -> Result<Self, HeaderError> {
        if u32::from_le_bytes(raw[0..4].try_into().unwrap()) != IMAGE_MAGIC {
            return Err(HeaderError::BadMagic);
        }
        if u16::from_le_bytes(raw[4..6].try_into().unwrap()) != HEADER_FORMAT
            || u16::from_le_bytes(raw[6..8].try_into().unwrap()) != IMAGE_FORMAT
        {
            return Err(HeaderError::BadFormat);
        }
        let header = ImageHeader {
            image_len: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
            image_crc32: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
            sequence: u32::from_le_bytes(raw[16..20].try_into().unwrap()),
            flags: u32::from_le_bytes(raw[20..24].try_into().unwrap()),
        };
        if header.image_len <= IMAGE_HEADER_LEN as u32 || header.image_len > MAX_IMAGE_LEN {
            return Err(HeaderError::BadLength);
        }
        if header.sequence == 0 {
            return Err(HeaderError::BadSequence);
        }
        let header_crc = u32::from_le_bytes(raw[24..28].try_into().unwrap());
        if header_crc != crc32(&raw[..24]) {
            return Err(HeaderError::BadHeaderCrc);
        }
        // The tail is outside the header CRC; both codecs require it zero.
        if raw[28..32] != [0; 4] {
            return Err(HeaderError::BadFormat);
        }
        Ok(header)
    }

    /// The expected image CRC over `raw_zeroed() || body`.
    pub fn stream_check(&self, streamed: u32) -> Result<(), HeaderError> {
        if streamed == self.image_crc32 {
            Ok(())
        } else {
            Err(HeaderError::BadImageCrc)
        }
    }
}

/// Boot metadata payload (32 B) stored in a `DualCopyStore` page pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub candidate_slot: u8,
    pub attempts_done: u8,
    pub flags: u8,
    pub active_slot: u8,
    pub candidate_seq: u32,
    pub good_seq: u32,
    pub failed_seq_a: u32,
    pub failed_seq_b: u32,
}

impl Default for Metadata {
    fn default() -> Self {
        Metadata {
            candidate_slot: NO_SLOT,
            attempts_done: 0,
            flags: 0,
            active_slot: NO_SLOT,
            candidate_seq: 0,
            good_seq: 0,
            failed_seq_a: 0,
            failed_seq_b: 0,
        }
    }
}

impl Metadata {
    pub fn encode(&self) -> [u8; METADATA_LEN] {
        let mut raw = [0u8; METADATA_LEN];
        raw[0..4].copy_from_slice(&METADATA_MAGIC.to_le_bytes());
        raw[4..6].copy_from_slice(&METADATA_VERSION.to_le_bytes());
        raw[6] = self.candidate_slot;
        raw[7] = self.attempts_done;
        raw[8] = self.flags;
        raw[9] = self.active_slot;
        raw[12..16].copy_from_slice(&self.candidate_seq.to_le_bytes());
        raw[16..20].copy_from_slice(&self.good_seq.to_le_bytes());
        raw[20..24].copy_from_slice(&self.failed_seq_a.to_le_bytes());
        raw[24..28].copy_from_slice(&self.failed_seq_b.to_le_bytes());
        let crc = crc32(&raw[..28]);
        raw[28..32].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    pub fn decode(raw: &[u8; METADATA_LEN]) -> Option<Self> {
        if u32::from_le_bytes(raw[0..4].try_into().ok()?) != METADATA_MAGIC {
            return None;
        }
        if u16::from_le_bytes(raw[4..6].try_into().ok()?) != METADATA_VERSION {
            return None;
        }
        let crc = u32::from_le_bytes(raw[28..32].try_into().ok()?);
        if crc != crc32(&raw[..28]) {
            return None;
        }
        Some(Metadata {
            candidate_slot: raw[6],
            attempts_done: raw[7],
            flags: raw[8],
            active_slot: raw[9],
            candidate_seq: u32::from_le_bytes(raw[12..16].try_into().ok()?),
            good_seq: u32::from_le_bytes(raw[16..20].try_into().ok()?),
            failed_seq_a: u32::from_le_bytes(raw[20..24].try_into().ok()?),
            failed_seq_b: u32::from_le_bytes(raw[24..28].try_into().ok()?),
        })
    }

    pub fn is_good(&self, slot: u8, seq: u32) -> bool {
        seq != 0 && self.active_slot == slot && self.good_seq == seq
    }

    pub fn is_failed(&self, slot: u8, seq: u32) -> bool {
        seq != 0
            && match slot {
                SLOT_A => self.failed_seq_a == seq,
                SLOT_B => self.failed_seq_b == seq,
                _ => false,
            }
    }

    fn failed_mut(&mut self, slot: u8) -> Option<&mut u32> {
        match slot {
            SLOT_A => Some(&mut self.failed_seq_a),
            SLOT_B => Some(&mut self.failed_seq_b),
            _ => None,
        }
    }
}

/// What the boot manager does after validating both slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootAction {
    Boot {
        slot: u8,
        sequence: u32,
        attempts_done: u8,
        rollback: bool,
    },
    Park(ParkReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParkReason {
    NoValidSlot,
    AllFailed,
    MetadataWriteFailed,
}

/// A decision plus the metadata to persist, when it changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub action: BootAction,
    pub persist: Option<Metadata>,
}

/// Pick the slot to boot. `valid`/`seq` come from header validation.
pub fn select(meta: Option<Metadata>, valid: [bool; 2], seq: [u32; 2]) -> Decision {
    let original = meta.unwrap_or_default();
    let mut meta = original;
    let mut rollback = false;

    // Resume the recorded candidate until its attempts run out.
    if let Some(slot) = slot_index(meta.candidate_slot) {
        let i = slot as usize;
        let pending = valid[i]
            && seq[i] != 0
            && meta.candidate_seq == seq[i]
            && !meta.is_good(slot, seq[i])
            && !meta.is_failed(slot, seq[i]);
        if pending {
            if meta.attempts_done < MAX_ATTEMPTS {
                meta.attempts_done += 1;
                meta.flags = 0;
                return Decision {
                    action: BootAction::Boot {
                        slot,
                        sequence: seq[i],
                        attempts_done: meta.attempts_done,
                        rollback: false,
                    },
                    persist: (meta != original).then_some(meta),
                };
            }
            // Exhausted: mark this sequence failed and fall through.
            if let Some(failed) = meta.failed_mut(slot) {
                *failed = seq[i];
            }
            meta.candidate_slot = NO_SLOT;
            meta.candidate_seq = 0;
            meta.attempts_done = 0;
            meta.flags = META_FLAG_ROLLBACK;
            rollback = true;
        }
    }

    // Fresh selection: highest valid, non-failed sequence; good wins ties.
    let mut best: Option<u8> = None;
    for slot in [SLOT_A, SLOT_B] {
        let i = slot as usize;
        if !valid[i] || seq[i] == 0 || meta.is_failed(slot, seq[i]) {
            continue;
        }
        best = match best {
            None => Some(slot),
            Some(current) => {
                let ci = current as usize;
                let newer = seq[i].wrapping_sub(seq[ci]) < 0x8000_0000 && seq[i] != seq[ci];
                let tie_good = seq[i] == seq[ci]
                    && meta.is_good(slot, seq[i])
                    && !meta.is_good(current, seq[ci]);
                if newer || tie_good {
                    Some(slot)
                } else {
                    Some(current)
                }
            }
        };
    }

    let Some(slot) = best else {
        let any_valid = valid.iter().any(|v| *v);
        meta.candidate_slot = NO_SLOT;
        meta.candidate_seq = 0;
        meta.attempts_done = 0;
        let action = if any_valid {
            BootAction::Park(ParkReason::AllFailed)
        } else {
            BootAction::Park(ParkReason::NoValidSlot)
        };
        return Decision {
            action,
            persist: (meta != original).then_some(meta),
        };
    };

    let i = slot as usize;
    let good = meta.is_good(slot, seq[i]);
    meta.candidate_slot = slot;
    meta.candidate_seq = seq[i];
    meta.attempts_done = if good { 0 } else { 1 };
    meta.flags = if rollback { META_FLAG_ROLLBACK } else { 0 };
    Decision {
        action: BootAction::Boot {
            slot,
            sequence: seq[i],
            attempts_done: meta.attempts_done,
            rollback,
        },
        persist: (meta != original).then_some(meta),
    }
}

/// What an app writes once it is healthy: good mark plus cleared markers.
pub fn on_good(meta: Option<Metadata>, slot: u8, seq: u32) -> Metadata {
    let mut meta = meta.unwrap_or_default();
    meta.active_slot = slot;
    meta.candidate_slot = slot;
    meta.candidate_seq = seq;
    meta.attempts_done = 0;
    meta.good_seq = seq;
    meta.flags = 0;
    if let Some(failed) = meta.failed_mut(slot) {
        *failed = 0;
    }
    meta
}

fn slot_index(slot: u8) -> Option<u8> {
    match slot {
        SLOT_A | SLOT_B => Some(slot),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
