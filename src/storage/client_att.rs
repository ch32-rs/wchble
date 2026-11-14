//! Per-peer client ATT state (CCCD subscriptions and client-specific writes).
//!
//! Trouble keeps this table in RAM and preserves it across a bonded disconnect,
//! but not across a reboot. The raw serialization is Host-specific, so this
//! module only stores opaque bytes, keyed by the resolved peer identity and the
//! local identity that was advertised when the state was written.
//!
//! The payload is `[local identity 7][count 1][record]` where each record is
//! `[peer kind 1][peer address 6][raw length 1][raw bytes]`.

use super::{LocalIdentity, StoreError, LOCAL_IDENTITY_LEN};

/// Client ATT tables one slot holds.
pub const MAX_CLIENT_ATT: usize = 3;

/// Largest raw table the pinned Host can produce (`CLIENT_ATT_TABLE_SIZE`).
pub const RAW_MAX: usize = 64;

/// Fixed bytes before one record's raw table.
pub const RECORD_OVERHEAD: usize = 8;

/// Header before the records: local identity plus count.
pub const HEADER_LEN: usize = LOCAL_IDENTITY_LEN + 1;

/// Largest payload [`encode_client_att`] can produce.
pub const MAX_PAYLOAD: usize = HEADER_LEN + MAX_CLIENT_ATT * (RECORD_OVERHEAD + RAW_MAX);

/// One peer's opaque client ATT table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientAttRecord {
    /// 0 public, 1 random.
    pub address_kind: u8,
    /// Peer identity address in display order, as `Address::to_bytes()`.
    pub address: [u8; 6],
    /// Number of valid bytes in `raw`.
    pub raw_len: u8,
    /// Raw `ClientAttTable::raw()` bytes.
    pub raw: [u8; RAW_MAX],
}

impl ClientAttRecord {
    pub const fn empty() -> Self {
        Self {
            address_kind: 0,
            address: [0; 6],
            raw_len: 0,
            raw: [0; RAW_MAX],
        }
    }

    /// Copy a raw Host table into the record; false when it is too large.
    pub fn set_raw(&mut self, raw: &[u8]) -> bool {
        if raw.len() > RAW_MAX {
            return false;
        }
        self.raw = [0; RAW_MAX];
        self.raw[..raw.len()].copy_from_slice(raw);
        self.raw_len = raw.len() as u8;
        true
    }
}

/// Encode the client ATT list; returns the payload length.
pub fn encode_client_att(
    local: &LocalIdentity,
    records: &[ClientAttRecord],
    out: &mut [u8],
) -> Result<usize, StoreError> {
    if records.len() > MAX_CLIENT_ATT {
        return Err(StoreError::PayloadTooLarge {
            len: records.len(),
            max: MAX_CLIENT_ATT,
        });
    }
    let len = HEADER_LEN
        + records
            .iter()
            .map(|record| RECORD_OVERHEAD + record.raw_len as usize)
            .sum::<usize>();
    if len > out.len() || len > MAX_PAYLOAD {
        return Err(StoreError::PayloadTooLarge {
            len,
            max: MAX_PAYLOAD,
        });
    }
    out[..LOCAL_IDENTITY_LEN].copy_from_slice(&local.encode());
    out[LOCAL_IDENTITY_LEN] = records.len() as u8;
    let mut offset = HEADER_LEN;
    for record in records {
        let raw_len = record.raw_len as usize;
        if raw_len > RAW_MAX {
            return Err(StoreError::BadFormat);
        }
        out[offset] = record.address_kind;
        out[offset + 1..offset + 7].copy_from_slice(&record.address);
        out[offset + 7] = record.raw_len;
        out[offset + RECORD_OVERHEAD..offset + RECORD_OVERHEAD + raw_len]
            .copy_from_slice(&record.raw[..raw_len]);
        offset += RECORD_OVERHEAD + raw_len;
    }
    Ok(len)
}

/// Decode a client ATT list; returns the number of records written to `out`.
///
/// `Ok(None)` means the payload was written under a different local identity;
/// the caller must leave the Host's default (empty) table in place.
pub fn decode_client_att(
    input: &[u8],
    local: &LocalIdentity,
    out: &mut [ClientAttRecord],
) -> Result<Option<usize>, StoreError> {
    let stored = LocalIdentity::decode(input).ok_or(StoreError::BadFormat)?;
    if stored != *local {
        return Ok(None);
    }
    if input.len() < HEADER_LEN {
        return Err(StoreError::BadFormat);
    }
    let count = input[LOCAL_IDENTITY_LEN] as usize;
    if count > MAX_CLIENT_ATT || count > out.len() {
        return Err(StoreError::BadFormat);
    }
    let mut offset = HEADER_LEN;
    for slot in out[..count].iter_mut() {
        if input.len() < offset + RECORD_OVERHEAD {
            return Err(StoreError::BadFormat);
        }
        let raw_len = input[offset + 7] as usize;
        if raw_len > RAW_MAX || input.len() < offset + RECORD_OVERHEAD + raw_len {
            return Err(StoreError::BadFormat);
        }
        let mut record = ClientAttRecord {
            address_kind: input[offset],
            address: input[offset + 1..offset + 7].try_into().expect("fixed length"),
            raw_len: raw_len as u8,
            raw: [0; RAW_MAX],
        };
        record.raw[..raw_len]
            .copy_from_slice(&input[offset + RECORD_OVERHEAD..offset + RECORD_OVERHEAD + raw_len]);
        *slot = record;
        offset += RECORD_OVERHEAD + raw_len;
    }
    Ok(Some(count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> LocalIdentity {
        LocalIdentity::random([0x21, 0x00, 0x00, 0xee, 0xff, 0xc1])
    }

    fn record(key: u8, raw: &[u8]) -> ClientAttRecord {
        let mut record = ClientAttRecord {
            address_kind: 1,
            address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, key],
            ..ClientAttRecord::empty()
        };
        assert!(record.set_raw(raw));
        record
    }

    #[test]
    fn round_trip() {
        let records = [record(1, &[0, 0, 0, 0]), record(2, &[1, 2, 3])];
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_client_att(&local(), &records, &mut payload).unwrap();
        let mut decoded = [ClientAttRecord::empty(); MAX_CLIENT_ATT];
        assert_eq!(
            decode_client_att(&payload[..len], &local(), &mut decoded),
            Ok(Some(2))
        );
        assert_eq!(&decoded[..2], &records);
    }

    #[test]
    fn foreign_local_identity_is_ignored() {
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_client_att(&local(), &[record(1, &[0; 4])], &mut payload).unwrap();
        let other = LocalIdentity::random([0x18, 0x00, 0x00, 0xee, 0xff, 0xc1]);
        let mut decoded = [ClientAttRecord::empty(); MAX_CLIENT_ATT];
        assert_eq!(
            decode_client_att(&payload[..len], &other, &mut decoded),
            Ok(None)
        );
    }

    #[test]
    fn maximum_capacity_fits_one_slot() {
        let records = [
            record(1, &[0x11; RAW_MAX]),
            record(2, &[0x22; RAW_MAX]),
            record(3, &[0x33; RAW_MAX]),
        ];
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_client_att(&local(), &records, &mut payload).unwrap();
        assert_eq!(len, MAX_PAYLOAD);
        assert!(MAX_PAYLOAD <= 256 - super::super::HEADER_LEN);
    }

    #[test]
    fn identity_only_payload_is_rejected_not_read() {
        // Exactly the local identity: the count byte is missing. This used to
        // index past the end after the identity matched.
        let local = local();
        let input = local.encode();
        let mut decoded = [ClientAttRecord::empty(); MAX_CLIENT_ATT];
        assert_eq!(
            decode_client_att(&input, &local, &mut decoded),
            Err(StoreError::BadFormat)
        );
    }

    #[test]
    fn oversized_raw_table_is_rejected() {
        let mut record = ClientAttRecord::empty();
        assert!(!record.set_raw(&[0u8; RAW_MAX + 1]));
    }

    #[test]
    fn too_many_records_rejected() {
        let records = [record(1, &[]); MAX_CLIENT_ATT + 1];
        let mut payload = [0u8; MAX_PAYLOAD];
        assert!(encode_client_att(&local(), &records, &mut payload).is_err());
    }

    #[test]
    fn truncated_payload_rejected() {
        let records = [record(1, &[1, 2, 3, 4])];
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_client_att(&local(), &records, &mut payload).unwrap();
        let mut decoded = [ClientAttRecord::empty(); MAX_CLIENT_ATT];
        assert_eq!(
            decode_client_att(&payload[..len - 1], &local(), &mut decoded),
            Err(StoreError::BadFormat)
        );
        assert_eq!(
            decode_client_att(&[], &local(), &mut decoded),
            Err(StoreError::BadFormat)
        );
    }

    #[test]
    fn count_beyond_caller_buffer_rejected() {
        let records = [record(1, &[0; 2]), record(2, &[0; 2])];
        let mut payload = [0u8; MAX_PAYLOAD];
        let len = encode_client_att(&local(), &records, &mut payload).unwrap();
        let mut decoded = [ClientAttRecord::empty(); 1];
        assert_eq!(
            decode_client_att(&payload[..len], &local(), &mut decoded),
            Err(StoreError::BadFormat)
        );
    }
}
