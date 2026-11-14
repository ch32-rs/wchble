//! Bond records stored by [`DualCopyStore`](super::DualCopyStore).
//!
//! The wire format is independent of the Host stack: callers convert their
//! `BondInformation` into [`PersistedBond`] and back. A record carries only
//! what the link layer needs to answer a later encryption request, plus the
//! peer identity used to find it again after a reboot.
//!
//! The list is prefixed by the local advertised identity ([`LocalIdentity`]).
//! A slot written under another address is ignored rather than served to the
//! peer, which would fail at DHKeyCheck.

use super::{LocalIdentity, StoreError, LOCAL_IDENTITY_LEN};

/// Bonds a single slot holds. A record is 52 bytes; four records plus the
/// count and identity prefix still fit the 232-byte slot payload.
pub const MAX_BONDS: usize = 4;

/// Encoded size of one bond.
pub const RECORD_LEN: usize = 52;

/// Header before the records: local identity plus count.
pub const HEADER_LEN: usize = LOCAL_IDENTITY_LEN + 1;

/// Largest payload [`encode_bonds`] can produce.
pub const MAX_PAYLOAD: usize = HEADER_LEN + MAX_BONDS * RECORD_LEN;

const FLAG_HAS_IRK: u8 = 1 << 0;
const FLAG_BONDED: u8 = 1 << 1;

/// A bond in the form the storage layer understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PersistedBond {
    /// Long-term key, little-endian as written by the Host.
    pub ltk: [u8; 16],
    /// Peer identity address in Bluetooth order (most significant byte first).
    pub address: [u8; 6],
    /// Address kind: 0 public, 1 random.
    pub address_kind: u8,
    /// Identity resolving key, if the peer distributed one.
    pub irk: Option<[u8; 16]>,
    /// Whether the peer asked to keep the key after disconnect.
    pub is_bonded: bool,
    /// Host security level at pairing time.
    pub security_level: u8,
    /// Legacy pairing EDIV (zero without the legacy feature).
    pub ediv: u16,
    /// Legacy pairing random (zero without the legacy feature).
    pub rand: [u8; 8],
    /// Encryption key length in bytes.
    pub key_len: u8,
}

impl PersistedBond {
    /// Zeroed record.
    pub const fn empty() -> Self {
        Self {
            ltk: [0; 16],
            address: [0; 6],
            address_kind: 0,
            irk: None,
            is_bonded: false,
            security_level: 0,
            ediv: 0,
            rand: [0; 8],
            key_len: 16,
        }
    }

    fn encode(&self, out: &mut [u8]) {
        out[0..16].copy_from_slice(&self.ltk);
        out[16..22].copy_from_slice(&self.address);
        out[22] = self.address_kind;
        let mut flags = 0u8;
        if self.irk.is_some() {
            flags |= FLAG_HAS_IRK;
        }
        if self.is_bonded {
            flags |= FLAG_BONDED;
        }
        out[23] = flags;
        out[24..40].copy_from_slice(&self.irk.unwrap_or([0; 16]));
        out[40] = self.security_level;
        out[41..43].copy_from_slice(&self.ediv.to_le_bytes());
        out[43..51].copy_from_slice(&self.rand);
        out[51] = self.key_len;
    }

    fn decode(input: &[u8]) -> Self {
        let flags = input[23];
        let mut irk = [0u8; 16];
        irk.copy_from_slice(&input[24..40]);
        Self {
            ltk: input[0..16].try_into().expect("fixed length"),
            address: input[16..22].try_into().expect("fixed length"),
            address_kind: input[22],
            irk: (flags & FLAG_HAS_IRK != 0).then_some(irk),
            is_bonded: flags & FLAG_BONDED != 0,
            security_level: input[40],
            ediv: u16::from_le_bytes([input[41], input[42]]),
            rand: input[43..51].try_into().expect("fixed length"),
            key_len: input[51],
        }
    }
}

/// Encode a bond list; returns the payload length.
pub fn encode_bonds(
    local: &LocalIdentity,
    bonds: &[PersistedBond],
    out: &mut [u8],
) -> Result<usize, StoreError> {
    let len = HEADER_LEN + bonds.len() * RECORD_LEN;
    if bonds.len() > MAX_BONDS || out.len() < len {
        return Err(StoreError::PayloadTooLarge {
            len,
            max: MAX_PAYLOAD,
        });
    }
    out[..LOCAL_IDENTITY_LEN].copy_from_slice(&local.encode());
    out[LOCAL_IDENTITY_LEN] = bonds.len() as u8;
    for (index, bond) in bonds.iter().enumerate() {
        let start = HEADER_LEN + index * RECORD_LEN;
        bond.encode(&mut out[start..start + RECORD_LEN]);
    }
    Ok(len)
}

/// Decode a bond list; returns the number of records written to `out`.
///
/// `Ok(None)` means the payload is well formed but was written under a
/// different local identity; the caller must not serve those bonds and must
/// not erase the slot.
pub fn decode_bonds(
    input: &[u8],
    local: &LocalIdentity,
    out: &mut [PersistedBond],
) -> Result<Option<usize>, StoreError> {
    let stored = LocalIdentity::decode(input).ok_or(StoreError::BadFormat)?;
    if stored != *local {
        return Ok(None);
    }
    if input.len() < HEADER_LEN {
        return Err(StoreError::BadFormat);
    }
    let count = input[LOCAL_IDENTITY_LEN] as usize;
    if count > MAX_BONDS
        || count > out.len()
        || input.len() < HEADER_LEN + count * RECORD_LEN
    {
        return Err(StoreError::BadFormat);
    }
    for (index, slot) in out[..count].iter_mut().enumerate() {
        let start = HEADER_LEN + index * RECORD_LEN;
        *slot = PersistedBond::decode(&input[start..start + RECORD_LEN]);
    }
    Ok(Some(count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(key: u8) -> PersistedBond {
        PersistedBond {
            ltk: [key; 16],
            address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, key],
            address_kind: 0,
            irk: None,
            is_bonded: true,
            security_level: 2,
            ediv: 0,
            rand: [0; 8],
            key_len: 16,
        }
    }

    fn local() -> LocalIdentity {
        LocalIdentity::random([0x21, 0x00, 0x00, 0xee, 0xff, 0xc1])
    }

    #[test]
    fn round_trip_without_irk() {
        let bonds = [sample(1), sample(2)];
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_bonds(&local(), &bonds, &mut payload).unwrap();
        assert_eq!(len, HEADER_LEN + 2 * RECORD_LEN);

        let mut decoded = [PersistedBond::empty(); MAX_BONDS];
        let count = decode_bonds(&payload[..len], &local(), &mut decoded).unwrap();
        assert_eq!(count, Some(2));
        assert_eq!(&decoded[..2], &bonds);
    }

    #[test]
    fn round_trip_with_irk() {
        let mut bond = sample(3);
        bond.irk = Some([0x5A; 16]);
        bond.is_bonded = false;
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_bonds(&local(), &[bond], &mut payload).unwrap();
        let mut decoded = [PersistedBond::empty(); MAX_BONDS];
        assert_eq!(decode_bonds(&payload[..len], &local(), &mut decoded), Ok(Some(1)));
        assert_eq!(decoded[0], bond);
    }

    #[test]
    fn maximum_capacity_fits_one_slot() {
        let bonds = [sample(1), sample(2), sample(3), sample(4)];
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_bonds(&local(), &bonds, &mut payload).unwrap();
        assert_eq!(len, MAX_PAYLOAD);
        assert!(MAX_PAYLOAD <= 256 - super::super::HEADER_LEN);
    }

    #[test]
    fn foreign_local_identity_is_ignored() {
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_bonds(&local(), &[sample(1)], &mut payload).unwrap();
        let other = LocalIdentity::random([0x18, 0x00, 0x00, 0xee, 0xff, 0xc1]);
        let mut decoded = [PersistedBond::empty(); MAX_BONDS];
        assert_eq!(decode_bonds(&payload[..len], &other, &mut decoded), Ok(None));
    }

    #[test]
    fn identity_only_payload_is_rejected_not_read() {
        // Exactly the local identity: the count byte is missing. This used to
        // index past the end after the identity matched.
        let local = local();
        let input = local.encode();
        let mut decoded = [PersistedBond::empty(); MAX_BONDS];
        assert_eq!(
            decode_bonds(&input, &local, &mut decoded),
            Err(StoreError::BadFormat)
        );
    }

    #[test]
    fn too_many_bonds_rejected() {
        let bonds = [sample(1); MAX_BONDS + 1];
        let mut payload = [0u8; MAX_PAYLOAD + RECORD_LEN];
        assert!(encode_bonds(&local(), &bonds, &mut payload).is_err());
    }

    #[test]
    fn truncated_payload_rejected() {
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_bonds(&local(), &[sample(1), sample(2)], &mut payload).unwrap();
        let mut decoded = [PersistedBond::empty(); MAX_BONDS];
        assert_eq!(
            decode_bonds(&payload[..len - 1], &local(), &mut decoded),
            Err(StoreError::BadFormat)
        );
        assert_eq!(
            decode_bonds(&[], &local(), &mut decoded),
            Err(StoreError::BadFormat)
        );
    }

    #[test]
    fn count_beyond_caller_buffer_rejected() {
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_bonds(&local(), &[sample(1), sample(2)], &mut payload).unwrap();
        let mut decoded = [PersistedBond::empty(); 1];
        assert_eq!(
            decode_bonds(&payload[..len], &local(), &mut decoded),
            Err(StoreError::BadFormat)
        );
    }
}
