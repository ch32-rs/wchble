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
pub mod client_att;

/// Size of the record header in front of every payload.
pub const HEADER_LEN: usize = 24;

/// Header magic. ASCII "BND3" read as a little-endian word.
const MAGIC: u32 = 0x3344_4e42;

/// Format revision written by this module. Version 2 adds the local identity
/// to the bond and client-ATT payloads; version-1 slots are ignored once.
const FORMAT_VERSION: u16 = 2;

/// Record flags: the stored payload is a zero-length tombstone.
const FLAG_TOMBSTONE: u16 = 1 << 0;

/// Encoded local identity length: kind byte plus six address bytes.
pub const LOCAL_IDENTITY_LEN: usize = 7;

/// Local advertised identity stored with every bond and client-ATT payload.
///
/// A record written by an image that advertised a different address is ignored,
/// because the peer paired with that other identity and its LTK must not be
/// offered by this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LocalIdentity {
    /// 0 public, 1 random.
    pub address_kind: u8,
    /// Display order (most significant byte first), as `Address::to_bytes()`.
    pub address: [u8; 6],
}

impl LocalIdentity {
    pub const fn new(address_kind: u8, address: [u8; 6]) -> Self {
        Self {
            address_kind,
            address,
        }
    }

    /// Build from an HCI random address in little-endian wire order.
    pub fn random(hci_address: [u8; 6]) -> Self {
        let mut address = hci_address;
        address.reverse();
        Self::new(1, address)
    }

    pub fn encode(&self) -> [u8; LOCAL_IDENTITY_LEN] {
        let mut out = [0u8; LOCAL_IDENTITY_LEN];
        out[0] = self.address_kind;
        out[1..].copy_from_slice(&self.address);
        out
    }

    pub fn decode(input: &[u8]) -> Option<Self> {
        if input.len() < LOCAL_IDENTITY_LEN {
            return None;
        }
        Some(Self {
            address_kind: input[0],
            address: input[1..LOCAL_IDENTITY_LEN].try_into().ok()?,
        })
    }
}

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
    !crc32_update(0xFFFF_FFFF, data)
}

/// Continue a reflected CRC32; the caller passes the un-inverted state.
fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    crc
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

    /// Compare the stored payload CRC without borrowing the caller's buffer.
    ///
    /// The read is chunked so a caller with a tiny `out` slice, or a payload
    /// larger than any stack scratch, still gets CRC validation of both slots.
    fn payload_crc_ok(&mut self, slot: usize, header: &Header) -> Result<bool, StoreError> {
        const CHUNK: usize = 32;
        let len = header.payload_len as usize;
        if len == 0 {
            return Ok(header.payload_crc == 0);
        }
        let mut crc = 0xFFFF_FFFFu32;
        let mut scratch = [0u8; CHUNK];
        let base = self.slots[slot] + HEADER_LEN as u32;
        let mut offset = 0usize;
        while offset < len {
            let count = (len - offset).min(CHUNK);
            self.region
                .read(base + offset as u32, &mut scratch[..count])?;
            crc = crc32_update(crc, &scratch[..count]);
            offset += count;
        }
        Ok(!crc == header.payload_crc)
    }

    /// Find the newest slot whose header and payload CRC are valid.
    ///
    /// A read failure on one slot is remembered but does not abandon the other
    /// slot; it is only returned when neither slot yielded a valid record.
    fn scan(&mut self) -> Result<Option<(usize, Header)>, StoreError> {
        let mut best: Option<(usize, Header)> = None;
        let mut first_error = None;
        for slot in 0..2 {
            let header = match self.read_header(slot) {
                Ok(Some(header)) => header,
                Ok(None) => continue,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            if header.payload_len as usize > self.max_payload() {
                continue;
            }
            match self.payload_crc_ok(slot, &header) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            }
            if best.is_none_or(|(_, current)| seq_after(header.seq, current.seq)) {
                best = Some((slot, header));
            }
        }
        match best {
            Some(entry) => Ok(Some(entry)),
            None => match first_error {
                Some(error) => Err(error),
                None => Ok(None),
            },
        }
    }

    /// Load the newest valid record into `out`.
    ///
    /// Returns the payload length, or `None` when both slots are empty or the
    /// newest record is a tombstone. A page with a bad header or payload CRC is
    /// treated as absent, so an interrupted save falls back to the older copy.
    pub fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, StoreError> {
        match self.scan()? {
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
        if !payload.is_empty() {
            const CHUNK: usize = 32;
            let mut scratch = [0u8; CHUNK];
            let base = offset + HEADER_LEN as u32;
            let mut done = 0usize;
            while done < payload.len() {
                let count = (payload.len() - done).min(CHUNK);
                self.region
                    .read(base + done as u32, &mut scratch[..count])?;
                if scratch[..count] != payload[done..done + count] {
                    return Err(StoreError::Flash(FlashError::Verify));
                }
                done += count;
            }
        }
        Ok(())
    }

    /// Discover the on-flash sequence before a write when the caller did not
    /// call [`load`](Self::load) first.
    ///
    /// Without this, `new() + save()` writes sequence 1 and an older slot with
    /// sequence 5 wins on the next load. The next write must not erase the only
    /// valid copy: when the newest header carries a corrupt payload and the
    /// other slot is still valid, `active` is the valid slot, so the write goes
    /// into the corrupt one. The sequence is always taken from the newest
    /// readable header, valid or not, so a corrupt record is never resurrected
    /// over.
    ///
    /// If no slot proved valid and a header read failed, refuse to write blind:
    /// the unreadable slot may hold the only good copy, and `save` erases its
    /// target before programming.
    fn locate(&mut self) -> Result<(), StoreError> {
        if self.active.is_some() || self.seq != 0 {
            return Ok(());
        }
        let mut newest: Option<(usize, Header)> = None;
        let mut newest_valid: Option<(usize, Header)> = None;
        let mut first_error = None;
        for slot in 0..2 {
            let header = match self.read_header(slot) {
                Ok(Some(header)) => header,
                Ok(None) => continue,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            if newest.is_none_or(|(_, current)| seq_after(header.seq, current.seq)) {
                newest = Some((slot, header));
            }
            if header.payload_len as usize <= self.max_payload() {
                match self.payload_crc_ok(slot, &header) {
                    Ok(true) => {
                        if newest_valid
                            .is_none_or(|(_, current)| seq_after(header.seq, current.seq))
                        {
                            newest_valid = Some((slot, header));
                        }
                    }
                    Ok(false) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }
        let seq = newest.map_or(0, |(_, header)| header.seq);
        if let Some((slot, _)) = newest_valid {
            self.active = Some(slot);
            self.seq = seq;
            return Ok(());
        }
        // No slot proved valid. A failed header read may hide the only good
        // copy, so refuse to pick a write target instead of erasing it blind.
        if let Some(error) = first_error {
            return Err(error);
        }
        match newest {
            Some((slot, _)) => {
                self.active = Some(slot);
                self.seq = seq;
                Ok(())
            }
            None => Ok(()),
        }
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
        self.locate()?;
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
        self.locate()?;
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
        self.locate()?;
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
    ///
    /// A tombstone is written first; the old record's page is erased next and
    /// the tombstone page last. If power is lost during the wipe, the tombstone
    /// still wins on sequence order, so no record can reappear.
    pub fn erase_all(&mut self) -> Result<(), StoreError> {
        self.locate()?;
        let previous = self.active;
        let target = match previous {
            Some(active) => 1 - active,
            None => 0,
        };
        let seq = self.seq.wrapping_add(1);
        self.write_record(target, seq, &[])?;
        let mut first_error = None;
        if let Some(previous) = previous {
            if let Err(error) = self.region.erase(self.slots[previous]) {
                first_error = Some(error);
            }
        }
        // Keep the tombstone intact when the old copy could not be erased.
        if first_error.is_none() {
            if let Err(error) = self.region.erase(self.slots[target]) {
                first_error = Some(error);
            }
        }
        self.active = None;
        self.seq = 0;
        match first_error {
            Some(error) => Err(StoreError::Flash(error)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 256;

    struct FakeFlash {
        data: [u8; PAGE * 2],
        fail_erase: Option<usize>,
        fail_read: Option<usize>,
        fail_read_all: bool,
        corrupt_next_payload: bool,
        programs: u32,
    }

    impl FakeFlash {
        fn new() -> Self {
            Self {
                data: [0xFF; PAGE * 2],
                fail_erase: None,
                fail_read: None,
                fail_read_all: false,
                corrupt_next_payload: false,
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
            if self.fail_read_all || self.fail_read == Some(start / PAGE) {
                return Err(FlashError::Busy);
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
            // Model a cell that programs but reads back wrong. Only payload
            // writes consume the flag, so the header stays valid.
            if self.corrupt_next_payload && start % PAGE >= HEADER_LEN && !data.is_empty() {
                self.data[end - 1] ^= 0x01;
                self.corrupt_next_payload = false;
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
    fn save_without_load_does_not_erase_the_only_valid_copy() {
        let mut store = store();
        store.save(b"old").unwrap();
        store.save(b"new").unwrap();
        let newest = store.active_slot().unwrap();
        // The newest header stays valid; only its payload is damaged.
        store.region.data[newest * PAGE + HEADER_LEN + 1] ^= 0x40;

        // A fresh store that never calls `load()` must write into the damaged
        // slot, not erase the older valid copy.
        let mut next = DualCopyStore::new(store.region, [0, PAGE as u32]);
        next.save(b"next").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(next.load(&mut out), Ok(Some(4)));
        assert_eq!(&out[..4], b"next");

        // The previous record still backs up the new one.
        let current = next.active_slot().unwrap();
        next.region.data[current * PAGE + HEADER_LEN + 2] ^= 0x80;
        assert_eq!(next.load(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"old");
    }

    #[test]
    fn failed_save_without_load_keeps_the_only_valid_copy() {
        let mut store = store();
        store.save(b"old").unwrap();
        store.save(b"new").unwrap();
        let newest = store.active_slot().unwrap();
        store.region.data[newest * PAGE + HEADER_LEN + 1] ^= 0x40;

        let mut next = DualCopyStore::new(store.region, [0, PAGE as u32]);
        next.region.corrupt_next_payload = true;
        assert!(next.save(b"next").is_err());
        let mut out = [0u8; 16];
        assert_eq!(next.load(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"old");
    }

    #[test]
    fn unreadable_header_blocks_a_blind_save() {
        let mut store = store();
        store.save(b"old").unwrap();
        store.save(b"new").unwrap();
        let newest = store.active_slot().unwrap();
        // The newest header stays readable but its payload is damaged, so no
        // slot validates; the older slot still holds the only good record.
        store.region.data[newest * PAGE + HEADER_LEN + 1] ^= 0x40;

        let mut next = DualCopyStore::new(store.region, [0, PAGE as u32]);
        // Slot 0's header cannot be read, so `locate` must not pick slot 1 as
        // the write target: `save` erases the target first.
        next.region.fail_read = Some(0);
        next.region.corrupt_next_payload = true;
        let before = next.region.data;
        assert!(next.save(b"next").is_err());
        assert_eq!(next.region.data, before);

        // Once the header is readable again the old record is still there.
        next.region.fail_read = None;
        let mut out = [0u8; 16];
        assert_eq!(next.load(&mut out), Ok(Some(3)));
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
        store.region.data[slot * PAGE + 4] = 3;
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

    #[test]
    fn load_falls_back_when_newest_slot_read_fails() {
        let mut store = store();
        store.save(b"old").unwrap();
        store.save(b"new").unwrap();
        let newest = store.active_slot().unwrap();
        store.region.fail_read = Some(newest);
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(Some(3)));
        assert_eq!(&out[..3], b"old");
        store.region.fail_read = None;
    }

    #[test]
    fn load_returns_io_when_both_slots_fail() {
        let mut store = store();
        store.save(b"bond").unwrap();
        store.region.fail_read_all = true;
        let mut out = [0u8; 16];
        assert_eq!(
            store.load(&mut out),
            Err(StoreError::Flash(FlashError::Busy))
        );
    }

    #[test]
    fn save_verifies_the_payload_read_back() {
        let mut store = store();
        store.region.corrupt_next_payload = true;
        assert_eq!(
            store.save(b"payload"),
            Err(StoreError::Flash(FlashError::Verify))
        );
        assert_eq!(store.active_slot(), None);
        assert_eq!(store.seq(), 0);
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(None));
    }

    /// A caller that writes without loading must still write above whatever the
    /// two slots already hold.
    fn copy_store(source: &DualCopyStore<FakeFlash>) -> DualCopyStore<FakeFlash> {
        let mut region = FakeFlash::new();
        region.data.copy_from_slice(&source.region.data);
        DualCopyStore::new(region, [0, PAGE as u32])
    }

    #[test]
    fn save_without_load_seeds_the_stored_sequence() {
        let mut source = store();
        source.save(b"one").unwrap();
        source.save(b"two").unwrap();
        let mut fresh = copy_store(&source);
        fresh.save(b"three").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(fresh.load(&mut out), Ok(Some(5)));
        assert_eq!(&out[..5], b"three");
    }

    #[test]
    fn clear_without_load_does_not_resurrect_an_older_record() {
        let mut source = store();
        source.save(b"one").unwrap();
        source.save(b"two").unwrap();
        let mut fresh = copy_store(&source);
        fresh.clear().unwrap();
        let mut out = [0u8; 16];
        assert_eq!(fresh.load(&mut out), Ok(None));
    }

    #[test]
    fn erase_all_survives_an_erase_failure() {
        let mut store = store();
        store.save(b"bond").unwrap();
        let active = store.active_slot().unwrap();
        // The old record's page cannot be erased, so the tombstone must stay.
        store.region.fail_erase = Some(active);
        assert_eq!(
            store.erase_all(),
            Err(StoreError::Flash(FlashError::Busy))
        );
        store.region.fail_erase = None;
        let mut out = [0u8; 16];
        assert_eq!(store.load(&mut out), Ok(None));
    }

    #[test]
    fn crc_covers_payloads_larger_than_the_scratch_chunk() {
        let mut store = store();
        let mut old = [0u8; 100];
        let mut new = [0u8; 100];
        old.fill(0x11);
        new.fill(0x22);
        store.save(&old).unwrap();
        store.save(&new).unwrap();
        let newest = store.active_slot().unwrap();
        store.region.data[newest * PAGE + HEADER_LEN + 50] ^= 0x01;
        let mut out = [0u8; 100];
        assert_eq!(store.load(&mut out), Ok(Some(100)));
        assert_eq!(out, old);
    }
}
