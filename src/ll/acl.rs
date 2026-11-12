//! Fixed-size legacy data PDUs and one-outstanding-packet SN/NESN handling.

/// Direction of an ACL fragment relative to the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AclDir {
    ToHost,
    FromHost,
}

/// Minimal ACL fragment descriptor (no ownership of bytes yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AclFragment {
    pub handle: u16,
    pub dir: AclDir,
    pub len: u16,
}

/// Largest on-air data-PDU payload this layer can store: the DLE maximum of
/// 251 octets, MIC included. The effective per-link limit is smaller until
/// DLE completes; [`LinkSequence::set_max_payloads`] applies it.
pub const MAX_LEGACY_PAYLOAD: usize = crate::ll::enc::MAX_ENCRYPTED;

use super::dle::{LL_DEFAULT_RX_PAYLOAD, LL_LEGACY_PAYLOAD, LL_MAX_PAYLOAD};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    Busy,
    Length,
    Llid,
}

/// Two-byte data-channel header followed by the legacy payload, no CRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct DataPdu {
    bytes: [u8; MAX_LEGACY_PAYLOAD + 2],
}

impl DataPdu {
    pub fn new(llid: u8, payload: &[u8]) -> Result<Self, TxError> {
        if payload.len() > MAX_LEGACY_PAYLOAD {
            return Err(TxError::Length);
        }
        if !(1..=3).contains(&llid) || (llid != 1 && payload.is_empty()) {
            return Err(TxError::Llid);
        }
        let mut pdu = Self {
            bytes: [0; MAX_LEGACY_PAYLOAD + 2],
        };
        pdu.bytes[0] = llid;
        pdu.bytes[1] = payload.len() as u8;
        pdu.bytes[2..payload.len() + 2].copy_from_slice(payload);
        Ok(pdu)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.bytes[1]) + 2]
    }

    pub fn payload(&self) -> &[u8] {
        &self.as_bytes()[2..]
    }
    pub fn llid(&self) -> u8 {
        self.bytes[0] & 3
    }
    pub fn header(&self) -> u8 {
        self.bytes[0]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxStatus {
    Invalid,
    Duplicate,
    Backpressure,
    Accepted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxOutcome {
    pub status: RxStatus,
    pub tx_acked: bool,
}

/// Reliable transport for data and controls alike. A queued PDU, including an
/// empty PDU, remains outstanding until a CRC-valid peer NESN acknowledges it.
#[derive(Debug, Clone)]
pub struct LinkSequence {
    expected_rx_sn: bool,
    tx_sn: bool,
    outstanding: Option<DataPdu>,
    transmitted: bool,
    tx_max_payload: u16,
    rx_max_payload: u16,
}

impl Default for LinkSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkSequence {
    pub const fn new() -> Self {
        Self {
            expected_rx_sn: false,
            tx_sn: false,
            outstanding: None,
            transmitted: false,
            tx_max_payload: LL_LEGACY_PAYLOAD,
            rx_max_payload: LL_DEFAULT_RX_PAYLOAD,
        }
    }

    /// Apply the negotiated on-air limits (MIC included). Values are clamped
    /// to the legacy minimum and the DLE maximum.
    pub fn set_max_payloads(&mut self, tx: u16, rx: u16) {
        self.tx_max_payload = tx.clamp(LL_LEGACY_PAYLOAD, LL_MAX_PAYLOAD);
        self.rx_max_payload = rx.clamp(LL_LEGACY_PAYLOAD, LL_MAX_PAYLOAD);
    }

    pub fn tx_max_payload(&self) -> u16 {
        self.tx_max_payload
    }

    pub fn rx_max_payload(&self) -> u16 {
        self.rx_max_payload
    }

    pub fn expected_rx_sn(&self) -> bool {
        self.expected_rx_sn
    }
    pub fn tx_sn(&self) -> bool {
        self.tx_sn
    }
    pub fn has_outstanding(&self) -> bool {
        self.outstanding.is_some()
    }

    pub fn queue(&mut self, llid: u8, payload: &[u8]) -> Result<(), TxError> {
        if self.outstanding.is_some() {
            return Err(TxError::Busy);
        }
        if payload.len() > usize::from(self.tx_max_payload) {
            return Err(TxError::Length);
        }
        self.outstanding = Some(DataPdu::new(llid, payload)?);
        self.transmitted = false;
        Ok(())
    }

    /// Prepare a transmission, automatically creating an empty continuation
    /// when idle. Invoke only when committing this PDU to a radio transmission:
    /// this marks it as sent. The SN and payload survive all retries; NESN is
    /// refreshed to acknowledge the newest accepted peer packet.
    pub fn tx_pdu(&mut self) -> DataPdu {
        let pdu = self.outstanding.get_or_insert(DataPdu {
            bytes: [0; MAX_LEGACY_PAYLOAD + 2],
        });
        if pdu.bytes[0] & 3 == 0 {
            pdu.bytes[0] = 1;
        }
        pdu.bytes[0] =
            (pdu.bytes[0] & 3) | (u8::from(self.expected_rx_sn) << 2) | (u8::from(self.tx_sn) << 3);
        self.transmitted = true;
        *pdu
    }

    /// Process only a fully received PDU whose declared length matches
    /// `payload.len()`. `accept` means storage/handler capacity was reserved.
    /// On backpressure the peer's packet is not acknowledged, but its NESN
    /// can still acknowledge our outstanding packet. Duplicates are never
    /// delivered twice. The caller delivers payload only on `Accepted`.
    /// Header RFU bits 6 and 7 are ignored. CP=1 (a third CTEInfo header byte)
    /// is not supported by this two-byte-header legacy path.
    pub fn on_rx(&mut self, header: u8, payload: &[u8], crc_ok: bool, accept: bool) -> RxOutcome {
        let llid = header & 3;
        if !crc_ok
            || header & 0x20 != 0 // CP=1 requires a third header byte; not supported.
            || llid == 0
            || (llid != 1 && payload.is_empty())
            || payload.len() > MAX_LEGACY_PAYLOAD
            || payload.len() > usize::from(self.rx_max_payload)
        {
            return RxOutcome {
                status: RxStatus::Invalid,
                tx_acked: false,
            };
        }
        let peer_nesn = header & 4 != 0;
        let tx_acked = self.outstanding.is_some() && self.transmitted && peer_nesn != self.tx_sn;
        if tx_acked {
            self.outstanding = None;
            self.transmitted = false;
            self.tx_sn = !self.tx_sn;
        }
        let status = if (header & 8 != 0) != self.expected_rx_sn {
            RxStatus::Duplicate
        } else if !accept {
            RxStatus::Backpressure
        } else {
            self.expected_rx_sn = !self.expected_rx_sn;
            RxStatus::Accepted
        };
        RxOutcome { status, tx_acked }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdu_bounds_and_llid() {
        // One header + length octet and the largest payload, rounded up to
        // the four-octet alignment the radio DMA expects.
        assert_eq!(
            core::mem::size_of::<DataPdu>(),
            (MAX_LEGACY_PAYLOAD + 2 + 3) / 4 * 4
        );
        assert_eq!(core::mem::align_of::<DataPdu>(), 4);
        assert_eq!(DataPdu::new(1, &[]).unwrap().as_bytes(), &[1, 0]);
        assert_eq!(
            DataPdu::new(2, &[1; MAX_LEGACY_PAYLOAD])
                .unwrap()
                .as_bytes()
                .len(),
            MAX_LEGACY_PAYLOAD + 2
        );
        assert_eq!(
            DataPdu::new(2, &[1; MAX_LEGACY_PAYLOAD + 1]),
            Err(TxError::Length)
        );
        assert_eq!(DataPdu::new(0, &[1]), Err(TxError::Llid));
        assert_eq!(DataPdu::new(3, &[]), Err(TxError::Llid));
        assert_eq!(DataPdu::new(2, &[]), Err(TxError::Llid));
    }

    #[test]
    fn one_acl_fragment_of_encrypted_plaintext_is_accepted() {
        // 24 plaintext octets plus the MIC is the on-air size an Android
        // Central uses for L2CAP fragments without DLE; refusing it stalls
        // the link because the peer retransmits an unacknowledged PDU.
        let encrypted = 24 + crate::crypto::BLE_MIC_LEN;
        assert!(encrypted > 27, "the legacy limit would have refused this");
        let mut link = LinkSequence::new();
        assert_eq!(
            link.on_rx(0x02, &[1; 24 + crate::crypto::BLE_MIC_LEN][..], true, true)
                .status,
            RxStatus::Accepted
        );
        let mut link = LinkSequence::new();
        assert_eq!(
            link.on_rx(0x02, &[1; MAX_LEGACY_PAYLOAD + 1][..], true, true).status,
            RxStatus::Invalid
        );
    }

    #[test]
    fn negotiated_limits_gate_tx_storage_and_rx_acceptance() {
        let mut link = LinkSequence::new();
        assert_eq!(link.tx_max_payload(), 27);
        assert_eq!(link.rx_max_payload(), 31);
        assert_eq!(link.queue(2, &[1; 28]), Err(TxError::Length));
        assert_eq!(
            link.on_rx(2, &[1; 32], true, true).status,
            RxStatus::Invalid
        );

        link.set_max_payloads(251, 251);
        assert_eq!(link.tx_max_payload(), 251);
        assert_eq!(
            link.on_rx(2, &[1; 251], true, true).status,
            RxStatus::Accepted
        );
        assert_eq!(
            link.on_rx(2, &[1; 252], true, true).status,
            RxStatus::Invalid
        );
        assert_eq!(link.queue(2, &[1; 252]), Err(TxError::Length));
        assert!(link.queue(2, &[1; 251]).is_ok());
        // Clamping protects the buffers from caller mistakes.
        link.set_max_payloads(0, u16::MAX);
        assert_eq!(link.tx_max_payload(), 27);
        assert_eq!(link.rx_max_payload(), 251);
    }

    #[test]
    fn retry_preserves_payload_sn_and_updates_nesn() {
        let mut link = LinkSequence::new();
        link.queue(2, &[1, 2, 3]).unwrap();
        let first = link.tx_pdu();
        assert_eq!(first.header(), 2);
        assert_eq!(link.tx_pdu(), first);
        let rx = link.on_rx(1, &[], true, true);
        assert_eq!(
            rx,
            RxOutcome {
                status: RxStatus::Accepted,
                tx_acked: false
            }
        );
        let retry = link.tx_pdu();
        assert_eq!(retry.header(), 6);
        assert_eq!(retry.payload(), first.payload());
        assert!(!link.tx_sn());
        assert_eq!(link.queue(3, &[0x07, 0x14]), Err(TxError::Busy));
        let rx = link.on_rx(0x0d, &[], true, true);
        assert_eq!(
            rx,
            RxOutcome {
                status: RxStatus::Accepted,
                tx_acked: true
            }
        );
        assert!(link.tx_sn());
        assert!(!link.has_outstanding());
        link.queue(3, &[0x07, 0x14]).unwrap();
        assert_eq!(link.tx_pdu().header(), 0x0b);
    }

    #[test]
    fn duplicate_can_ack_without_redelivery() {
        let mut link = LinkSequence::new();
        assert_eq!(link.on_rx(1, &[7], true, true).status, RxStatus::Accepted);
        link.queue(2, &[8]).unwrap();
        link.tx_pdu();
        let duplicate = link.on_rx(5, &[7], true, true);
        assert_eq!(
            duplicate,
            RxOutcome {
                status: RxStatus::Duplicate,
                tx_acked: true
            }
        );
        assert!(link.expected_rx_sn());
        assert!(link.tx_sn());
        assert_eq!(link.on_rx(5, &[7], true, true).status, RxStatus::Duplicate);
        assert!(link.tx_sn());
    }

    #[test]
    fn full_rx_buffer_does_not_ack_new_payload_but_processes_peer_ack() {
        let mut link = LinkSequence::new();
        link.tx_pdu();
        let full = link.on_rx(5, &[7], true, false);
        assert_eq!(
            full,
            RxOutcome {
                status: RxStatus::Backpressure,
                tx_acked: true
            }
        );
        assert!(!link.expected_rx_sn());
        assert!(link.tx_sn());
        assert_eq!(link.on_rx(5, &[7], true, true).status, RxStatus::Accepted);
        assert!(link.expected_rx_sn());
    }

    #[test]
    fn empty_packets_are_outstanding_and_retried() {
        let mut link = LinkSequence::new();
        let empty = link.tx_pdu();
        assert_eq!(empty.as_bytes(), &[1, 0]);
        assert!(link.has_outstanding());
        assert_eq!(link.queue(3, &[2, 0x13]), Err(TxError::Busy));
        assert_eq!(link.tx_pdu(), empty);
        assert!(link.on_rx(5, &[], true, true).tx_acked);
        link.queue(3, &[2, 0x13]).unwrap();
        assert_eq!(link.tx_pdu().payload(), &[2, 0x13]);
    }

    #[test]
    fn received_header_rfu_bits_are_ignored() {
        let mut link = LinkSequence::new();
        assert_eq!(link.on_rx(0xc1, &[], true, true).status, RxStatus::Accepted);
        assert_eq!(link.tx_pdu().header(), 5);
        assert_eq!(
            link.on_rx(0xcd, &[], true, true),
            RxOutcome {
                status: RxStatus::Accepted,
                tx_acked: true,
            }
        );
        assert!(link.tx_sn());
        assert!(!link.expected_rx_sn());
    }

    #[test]
    fn corrupt_invalid_and_unsent_packets_do_not_change_sequence() {
        let mut link = LinkSequence::new();
        link.queue(2, &[8]).unwrap();
        assert!(!link.on_rx(5, &[], true, true).tx_acked); // Queued, not sent.
        assert!(!link.tx_sn());
        link.tx_pdu();
        for (header, payload, crc) in [
            (5, &[][..], false),
            (4, &[1][..], true),
            (0x25, &[1][..], true),
            (7, &[][..], true),
            (5, &[1; MAX_LEGACY_PAYLOAD + 1][..], true),
        ] {
            assert_eq!(
                link.on_rx(header, payload, crc, true),
                RxOutcome {
                    status: RxStatus::Invalid,
                    tx_acked: false
                }
            );
        }
        assert!(link.has_outstanding());
        assert!(!link.tx_sn());
        assert!(link.expected_rx_sn()); // Only the first valid incoming empty was accepted.
    }
}
