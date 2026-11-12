//! Power-safe persistence of small blobs in two flash slots.
//!
//! Bond storage (S3) needs three properties the radio path must not lose:
//! a write that is interrupted by a power cut leaves the previous copy
//! readable, a deleted copy cannot come back, and a corrupt page is detected
//! instead of decoded. [`DualCopyStore`] gets all three from alternating
//! pages, a sequence number and a CRC32 over header and payload.
//!
//! The module is chip-agnostic: it only needs a [`FlashRegion`]. Platform
//! layers provide the erase/program/read primitives (CH585 uses its DataFlash
//! engine), and [`bond`] encodes an RTOS-independent bond record. Nothing here
//! depends on a Host stack.

pub mod bond;

/// Size of the record header in front of every payload.
pub const HEADER_LEN: usize = 24;

/// Header magic. ASCII "BND3" read as a little-endian word.
const MAGIC: u32 = 0x3344_4e42;

/// Format revision written by this module.
const FORMAT_VERSION: u16 = 1;

/// Record flags: the stored payload is a zero-length tombstone.
const FLAG_TOMBSTONE: u16 = 1 << 0;

/// Platform flash failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum FlashError {
    /// Address or length lies outside the region.
    OutOfRange,
    /// The engine reported a failure or stayed busy.
    Busy,
    /// A bounded wait expired.
    Timeout,
    /// Read-back after a program did not match.
    Verify,
}

/// Storage-level failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StoreError {
    /// The platform region failed.
    Flash(FlashError),
    /// The payload does not fit in one slot.
    PayloadTooLarge { len: usize, max: usize },
    /// The caller's buffer is smaller than the stored payload.
    BufferTooSmall { len: usize, needed: usize },
    /// A test build truncated the write on purpose.
    Injected,
    /// A payload decoded cleanly but is not a valid bond list.
    BadFormat,
}

impl From<FlashError> for StoreError {
    fn from(error: FlashError) -> Self {
        StoreError::Flash(error)
    }
}

/// Erase/program/read primitives for one flash region.
pub trait FlashRegion {
    /// Erase granularity.
    fn page_size(&self) -> usize;
    /// Read `out.len()` bytes at `offset` (relative to the region).
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), FlashError>;
    /// Erase the page containing `offset`.
    fn erase(&mut self, offset: u32) -> Result<(), FlashError>;
    /// Program `data` at `offset`; flash must already be erased.
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError>;
}

/// Reflected CRC32 (IEEE 802.3), bitwise to keep the code small.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[derive(Debug, Clone, Copy)]
struct Header {
    flags: u16,
    seq: u32,
    payload_len: u16,
    payload_crc: u32,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut raw = [0u8; HEADER_LEN];
        raw[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        raw[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        raw[6..8].copy_from_slice(&self.flags.to_le_bytes());
        raw[8..12].copy_from_slice(&self.seq.to_le_bytes());
        raw[12..14].copy_from_slice(&self.payload_len.to_le_bytes());
        raw[14..16].copy_from_slice(&0u16.to_le_bytes());
        raw[16..20].copy_from_slice(&self.payload_crc.to_le_bytes());
        let header_crc = crc32(&raw[..20]);
        raw[20..24].copy_from_slice(&header_crc.to_le_bytes());
        raw
    }

    fn decode(raw: &[u8; HEADER_LEN]) -> Option<Self> {
        if u32::from_le_bytes(raw[0..4].try_into().ok()?) != MAGIC {
            return None;
        }
        if u16::from_le_bytes(raw[4..6].try_into().ok()?) != FORMAT_VERSION {
            return None;
        }
        let header_crc = u32::from_le_bytes(raw[20..24].try_into().ok()?);
        if header_crc != crc32(&raw[..20]) {
            return None;
        }
        Some(Header {
            flags: u16::from_le_bytes(raw[6..8].try_into().ok()?),
            seq: u32::from_le_bytes(raw[8..12].try_into().ok()?),
            payload_len: u16::from_le_bytes(raw[12..14].try_into().ok()?),
            payload_crc: u32::from_le_bytes(raw[16..20].try_into().ok()?),
        })
    }

    fn is_tombstone(&self) -> bool {
        self.flags & FLAG_TOMBSTONE != 0 || self.payload_len == 0
    }
}

/// Sequence comparison that survives a 32-bit wrap.
fn seq_after(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) < 0x8000_0000
}

/// Two-slot store: every save goes to the slot that is not the current one.
pub struct DualCopyStore<R: FlashRegion> {
    region: R,
    slots: [u32; 2],
    active: Option<usize>,
    seq: u32,
}

impl<R: FlashRegion> DualCopyStore<R> {
    /// Build a store over two slot offsets in `region`.
    pub fn new(region: R, slots: [u32; 2]) -> Self {
        Self {
            region,
            slots,
            active: None,
            seq: 0,
        }
    }

    /// Sequence number of the record currently in use (0 when none).
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// Slot index holding the current record, if any.
    pub fn active_slot(&self) -> Option<usize> {
        self.active
    }

    /// Borrow the underlying region.
    pub fn region(&mut self) -> &mut R {
        &mut self.region
    }

    fn max_payload(&self) -> usize {
        self.region.page_size() - HEADER_LEN
    }

    fn read_header(&mut self, slot: usize) -> Result<Option<Header>, StoreError> {
        let offset = self.slots[slot];
        let mut raw = [0u8; HEADER_LEN];
        self.region.read(offset, &mut raw)?;
        Ok(Header::decode(&raw))
    }

    fn payload_crc_ok(
        &mut self,
        slot: usize,
        header: &Header,
        scratch: &mut [u8],
    ) -> Result<bool, StoreError> {
        let len = header.payload_len as usize;
        if len == 0 {
            return Ok(header.payload_crc == 0);
        }
        if scratch.len() < len {
            return Err(StoreError::BufferTooSmall {
                len,
                needed: len,
            });
        }
        self.region
            .read(self.slots[slot] + HEADER_LEN as u32, &mut scratch[..len])?;
        Ok(crc32(&scratch[..len]) == header.payload_crc)
    }

    /// Load the newest valid record into `out`.
    ///
    /// Returns the payload length, or `None` when both slots are empty or the
    /// newest record is a tombstone. A page with a bad header or payload CRC is
    /// treated as absent, so an interrupted save falls back to the older copy.
    pub fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, StoreError> {
        let mut best: Option<(usize, Header)> = None;
        for slot in 0..2 {
            let Some(header) = self.read_header(slot)? else {
                continue;
            };
            if header.payload_len as usize > self.max_payload() {
                continue;
            }
            if !self.payload_crc_ok(slot, &header, out)? {
                continue;
            }
            if best.is_none_or(|(_, current)| seq_after(header.seq, current.seq)) {
                best = Some((slot, header));
            }
        }
        match best {
            None => {
                self.active = None;
                self.seq = 0;
                Ok(None)
            }
            Some((slot, header)) => {
                self.active = Some(slot);
                self.seq = header.seq;
                if header.is_tombstone() {
                    return Ok(None);
                }
                let len = header.payload_len as usize;
                if out.len() < len {
                    return Err(StoreError::BufferTooSmall {
                        len,
                        needed: len,
                    });
                }
                self.region
                    .read(self.slots[slot] + HEADER_LEN as u32, &mut out[..len])?;
                Ok(Some(len))
            }
        }
    }

    fn write_record(&mut self, slot: usize, seq: u32, payload: &[u8]) -> Result<(), StoreError> {
        let offset = self.slots[slot];
        self.region.erase(offset)?;
        let header = Header {
            flags: if payload.is_empty() { FLAG_TOMBSTONE } else { 0 },
            seq,
            payload_len: payload.len() as u16,
            payload_crc: crc32(payload),
        };
        let raw = header.encode();
        self.region.program(offset, &raw)?;
        if !payload.is_empty() {
            self.region
                .program(offset + HEADER_LEN as u32, payload)?;
        }
        let mut check = [0u8; HEADER_LEN];
        self.region.read(offset, &mut check)?;
        if check != raw {
            return Err(StoreError::Flash(FlashError::Verify));
        }
        Ok(())
    }

    /// Write `payload` to the inactive slot and make it current.
    ///
    /// The previous copy stays intact until the new one has been read back, so
    /// a power cut at any point leaves either the old or the new record.
    pub fn save(&mut self, payload: &[u8]) -> Result<(), StoreError> {
        if payload.len() > self.max_payload() {
            return Err(StoreError::PayloadTooLarge {
                len: payload.len(),
                max: self.max_payload(),
            });
        }
        let target = match self.active {
            Some(active) => 1 - active,
            None => 0,
        };
        let seq = self.seq.wrapping_add(1);
        self.write_record(target, seq, payload)?;
        self.active = Some(target);
        self.seq = seq;
        Ok(())
    }

    /// Test-only: erase the target slot, program only part of the record and
    /// report an injected failure, modelling a power cut during the save.
    #[cfg(feature = "storage-fault")]
    pub fn save_with_fault(&mut self, payload: &[u8], prefix: usize) -> Result<(), StoreError> {
        if payload.len() > self.max_payload() {
            return Err(StoreError::PayloadTooLarge {
                len: payload.len(),
                max: self.max_payload(),
            });
        }
        let target = match self.active {
            Some(active) => 1 - active,
            None => 0,
        };
        let seq = self.seq.wrapping_add(1);
        let offset = self.slots[target];
        self.region.erase(offset)?;
        let header = Header {
            flags: 0,
            seq,
            payload_len: payload.len() as u16,
            payload_crc: crc32(payload),
        };
        self.region.program(offset, &header.encode())?;
        let prefix = prefix.min(payload.len());
        if prefix != 0 {
            self.region
                .program(offset + HEADER_LEN as u32, &payload[..prefix])?;
        }
        Err(StoreError::Injected)
    }

    /// Delete the stored record with a tombstone.
    ///
    /// The zero-length tombstone is written first and the old page is erased
    /// only afterwards, so a power cut during deletion leaves the bond, never a
    /// half-restored one.
    pub fn clear(&mut self) -> Result<(), StoreError> {
        let target = match self.active {
            Some(active) => 1 - active,
            None => 0,
        };
        let seq = self.seq.wrapping_add(1);
        self.write_record(target, seq, &[])?;
        if let Some(previous) = self.active {
            // Best effort: the tombstone already wins on sequence order.
            let _ = self.region.erase(self.slots[previous]);
        }
        self.active = Some(target);
        self.seq = seq;
        Ok(())
    }

    /// Erase both slots (test setup).
    pub fn erase_all(&mut self) -> Result<(), StoreError> {
        for slot in 0..2 {
            self.region.erase(self.slots[slot])?;
        }
        self.active = None;
        self.seq = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 256;

    struct FakeFlash {
        data: [u8; PAGE * 2],
        fail_erase: Option<usize>,
        programs: u32,
    }

    impl FakeFlash {
        fn new() -> Self {
            Self {
                data: [0xFF; PAGE * 2],
                fail_erase: None,
                programs: 0,
            }
        }
    }

    impl FlashRegion for FakeFlash {
        fn page_size(&self) -> usize {
            PAGE
        }

        fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), FlashError> {
            let start = offset as usize;
            let end = start + out.len();
            if end > self.data.len() {
                return Err(FlashError::OutOfRange);
            }
            out.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn erase(&mut self, offset: u32) -> Result<(), FlashError> {
            let page = offset as usize / PAGE;
            if self.fail_erase == Some(page) {
                return Err(FlashError::Busy);
            }
            let start = page * PAGE;
            self.data[start..start + PAGE].fill(0xFF);
            Ok(())
        }

        fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError> {
            self.programs += 1;
            let start = offset as usize;
            let end = start + data.len();
            if end > self.data.len() {
                return Err(FlashError::OutOfRange);
            }
            for (slot, byte) in self.data[start..end].iter_mut().zip(data) {
                *slot &= *byte;
            }
            Ok(())
        }
    }

    fn store() -> DualCopyStore<FakeFlash> {
        DualCopyStore::new(FakeFlash::new(), [0, PAGE as u32])
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn erased_store_is_empty() {
        let mut store = store();
        let mut out = [0u8; 64];
        assert_eq!(store.load(&mut out), Ok(None));
        assert_eq!(store.active_slot(), None);
    }

    #[test]
    fn save_load_round_trip() {
        let mut store = store();
        assert_eq!(store.save(b"hello bond"), Ok(()));
        let mut out = [0u8; 64];
        assert_eq!(store.load(&mut out), Ok(Some(10)));
        assert_eq!(&out[..10], b"hello bond");
        assert_eq!(store.seq(), 1);
    }

    #[test]
    fn alternating_slots_newest_wins() {
        let mut store = store();
        store.save(b"one").unwrap();
        let first = store.active_slot().unwrap();
        store.save(b"two").unwrap();
        assert_ne!(store.active_slot().unwrap(), first);
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"two");
    }

    #[test]
    fn corrupt_newest_payload_falls_back() {
        let mut store = store();
        store.save(b"old").unwrap();
        store.save(b"new").unwrap();
        let newest = store.active_slot().unwrap();
        let offset = newest * PAGE + HEADER_LEN + 1;
        store.region.data[offset] ^= 0x40;
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"old");
    }

    #[test]
    fn corrupt_newest_header_ignores_slot() {
        let mut store = store();
        store.save(b"old").unwrap();
        store.save(b"new").unwrap();
        let newest = store.active_slot().unwrap();
        store.region.data[newest * PAGE + 8] ^= 0x01;
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"old");
    }

    #[test]
    fn version_mismatch_is_ignored() {
        let mut store = store();
        store.save(b"data").unwrap();
        let slot = store.active_slot().unwrap();
        store.region.data[slot * PAGE + 4] = 2;
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(None));
    }

    #[test]
    fn interrupted_save_keeps_previous_record() {
        let mut store = store();
        store.save(b"old").unwrap();
        let target = match store.active_slot() {
            Some(0) => 1,
            _ => 0,
        };
        store.region.erase((target * PAGE) as u32).unwrap();
        // Header is valid but the payload stops early.
        let header = Header {
            flags: 0,
            seq: 2,
            payload_len: 8,
            payload_crc: crc32(b"new-data"),
        };
        store.region.program((target * PAGE) as u32, &header.encode()).unwrap();
        store
            .region
            .program((target * PAGE + HEADER_LEN) as u32, b"new")
            .unwrap();
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"old");
    }

    #[cfg(feature = "storage-fault")]
    #[test]
    fn injected_fault_keeps_previous_record() {
        let mut store = store();
        store.save(b"old").unwrap();
        let seq = store.seq();
        assert_eq!(store.save_with_fault(b"new-data", 3), Err(StoreError::Injected));
        assert_eq!(store.seq(), seq);
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"old");
    }

    #[test]
    fn clear_is_power_safe() {
        let mut store = store();
        store.save(b"bond").unwrap();
        store.clear().unwrap();
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(None));
        store.save(b"again").unwrap();
        assert_eq!(store.load(&mut out), Ok(Some(5)));
        assert_eq!(&out[..5], b"again");
    }

    #[test]
    fn oversized_payload_rejected_without_writes() {
        let mut store = store();
        let big = [0xAAu8; PAGE];
        assert_eq!(
            store.save(&big),
            Err(StoreError::PayloadTooLarge {
                len: PAGE,
                max: PAGE - HEADER_LEN
            })
        );
        assert_eq!(store.region.programs, 0);
    }

    #[test]
    fn small_buffer_reports_needed_length() {
        let mut store = store();
        store.save(b"0123456789").unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            store.load(&mut out),
            Err(StoreError::BufferTooSmall { len: 10, needed: 10 })
        );
    }

    #[test]
    fn sequence_wrap_keeps_newest() {
        let mut store = store();
        store.seq = u32::MAX - 1;
        store.save(b"before").unwrap();
        store.save(b"after").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(Some(5)));
        assert_eq!(&out[..5], b"after");
    }

    #[test]
    fn erase_failure_propagates() {
        let mut store = store();
        store.region.fail_erase = Some(0);
        assert_eq!(
            store.save(b"x"),
            Err(StoreError::Flash(FlashError::Busy))
        );
        assert_eq!(store.active_slot(), None);
    }
}
