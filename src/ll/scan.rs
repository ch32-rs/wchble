//! Passive-scan receive helpers: legacy advertising PDU and AD parsing.
//!
//! Everything here is pure and allocation-free. It expects the raw LLE DMA
//! layout used by the examples: `[header, length, payload..]`, with the access
//! address and CRC already stripped by the radio backend.

/// Maximum payload of a legacy advertising-channel PDU (Core Vol 6 Part B).
pub const MAX_LEGACY_ADV_PAYLOAD: usize = 37;

/// Legacy advertising-channel PDU types (`header[3:0]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PduType {
    AdvInd,
    AdvDirectInd,
    AdvNonconnInd,
    ScanReq,
    ScanRsp,
    ConnectInd,
    AdvScanInd,
    AdvExtInd,
    /// RFU / extended types not decoded here; carries the low nibble.
    Unknown(u8),
}

impl PduType {
    /// Decode the PDU type from the first header byte.
    pub const fn from_header(header: u8) -> Self {
        match header & 0x0f {
            0x00 => Self::AdvInd,
            0x01 => Self::AdvDirectInd,
            0x02 => Self::AdvNonconnInd,
            0x03 => Self::ScanReq,
            0x04 => Self::ScanRsp,
            0x05 => Self::ConnectInd,
            0x06 => Self::AdvScanInd,
            0x07 => Self::AdvExtInd,
            other => Self::Unknown(other),
        }
    }

    /// Header low nibble for this type.
    pub const fn code(self) -> u8 {
        match self {
            Self::AdvInd => 0x00,
            Self::AdvDirectInd => 0x01,
            Self::AdvNonconnInd => 0x02,
            Self::ScanReq => 0x03,
            Self::ScanRsp => 0x04,
            Self::ConnectInd => 0x05,
            Self::AdvScanInd => 0x06,
            Self::AdvExtInd => 0x07,
            Self::Unknown(code) => code,
        }
    }

    /// Types that carry an AdvA at the start of the payload.
    pub const fn has_adv_a(self) -> bool {
        matches!(
            self,
            Self::AdvInd
                | Self::AdvDirectInd
                | Self::AdvNonconnInd
                | Self::AdvScanInd
                | Self::ScanRsp
        )
    }
}

/// One received legacy advertising PDU.
#[derive(Debug, Clone, Copy)]
pub struct Pdu<'a> {
    header: u8,
    payload: &'a [u8],
}

impl<'a> Pdu<'a> {
    /// Parse the DMA buffer after a completed RX.
    ///
    /// `dma` is `[header, length, payload..]`. Returns `None` on CRC failure,
    /// a length above the legacy maximum, or a truncated buffer.
    pub fn parse(dma: &'a [u8], crc_ok: bool) -> Option<Self> {
        if !crc_ok || dma.len() < 2 {
            return None;
        }
        let len = usize::from(dma[1]);
        if len > MAX_LEGACY_ADV_PAYLOAD || len + 2 > dma.len() {
            return None;
        }
        Some(Self {
            header: dma[0],
            payload: &dma[2..2 + len],
        })
    }

    pub fn header(&self) -> u8 {
        self.header
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub fn pdu_type(&self) -> PduType {
        PduType::from_header(self.header)
    }

    /// TxAdd: transmitter address is random.
    pub fn tx_add(&self) -> bool {
        self.header & 0x40 != 0
    }

    /// RxAdd: the addressed receiver uses a random address.
    pub fn rx_add(&self) -> bool {
        self.header & 0x80 != 0
    }

    /// ChSel bit (legacy: RFU, kept for reporting only).
    pub fn chsel(&self) -> bool {
        self.header & 0x20 != 0
    }

    /// Advertiser address for types that begin with AdvA.
    pub fn adv_a(&self) -> Option<&'a [u8; 6]> {
        if !self.pdu_type().has_adv_a() {
            return None;
        }
        self.payload.get(..6).and_then(|bytes| bytes.try_into().ok())
    }

    /// Addressed peer address: TargetA for ADV_DIRECT_IND, AdvA for SCAN_REQ
    /// and CONNECT_IND (the advertiser being addressed).
    pub fn target_a(&self) -> Option<&'a [u8; 6]> {
        let start = match self.pdu_type() {
            PduType::AdvDirectInd | PduType::ScanReq | PduType::ConnectInd => 6,
            _ => return None,
        };
        self.payload
            .get(start..start + 6)
            .and_then(|bytes| bytes.try_into().ok())
    }

    /// AD structures carried by this PDU, if any.
    pub fn ad_structures(&self) -> AdStructures<'a> {
        let start = match self.pdu_type() {
            PduType::AdvInd | PduType::AdvNonconnInd | PduType::AdvScanInd => 6,
            PduType::ScanRsp => 6,
            _ => return AdStructures { remaining: &[] },
        };
        AdStructures {
            remaining: self.payload.get(start..).unwrap_or(&[]),
        }
    }

    /// First complete (`0x09`) or shortened (`0x08`) local name.
    pub fn local_name(&self) -> Option<&'a [u8]> {
        self.ad_structures()
            .find(|ad| ad.ad_type == 0x08 || ad.ad_type == 0x09)
            .map(|ad| ad.data)
    }

    /// First manufacturer-specific data element, including the company ID.
    pub fn manufacturer_data(&self) -> Option<&'a [u8]> {
        self.ad_structures()
            .find(|ad| ad.ad_type == 0xff)
            .map(|ad| ad.data)
    }
}

/// One AD structure: `[length, type, data..]` with `length = 1 + data.len()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdStructure<'a> {
    pub ad_type: u8,
    pub data: &'a [u8],
}

/// Iterator over AD structures that stops safely at a zero terminator or a
/// truncated element.
#[derive(Debug, Clone, Copy)]
pub struct AdStructures<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for AdStructures<'a> {
    type Item = AdStructure<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let len = *self.remaining.first()? as usize;
        if len == 0 {
            // Zero-length element terminates the AD data.
            self.remaining = &[];
            return None;
        }
        if self.remaining.len() < 1 + len {
            // Truncated element: stop without yielding partial data.
            self.remaining = &[];
            return None;
        }
        let ad_type = self.remaining[1];
        let data = &self.remaining[2..1 + len];
        self.remaining = &self.remaining[1 + len..];
        Some(AdStructure { ad_type, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adv_ind(payload: &[u8]) -> [u8; 64] {
        let mut dma = [0u8; 64];
        dma[0] = 0x00;
        dma[1] = payload.len() as u8;
        dma[2..2 + payload.len()].copy_from_slice(payload);
        dma
    }

    fn with_header(header: u8, payload: &[u8]) -> [u8; 64] {
        let mut dma = adv_ind(payload);
        dma[0] = header;
        dma
    }

    #[test]
    fn pdu_types_decode_low_nibble_and_preserve_unknown() {
        for (header, expected) in [
            (0x00, PduType::AdvInd),
            (0x01, PduType::AdvDirectInd),
            (0x02, PduType::AdvNonconnInd),
            (0x03, PduType::ScanReq),
            (0x04, PduType::ScanRsp),
            (0x05, PduType::ConnectInd),
            (0x06, PduType::AdvScanInd),
            (0x07, PduType::AdvExtInd),
            (0x08, PduType::Unknown(0x08)),
            (0x0f, PduType::Unknown(0x0f)),
            (0xff, PduType::Unknown(0x0f)),
        ] {
            assert_eq!(PduType::from_header(header), expected);
            assert_eq!(PduType::from_header(header).code(), header & 0x0f);
        }
    }

    #[test]
    fn adv_a_types() {
        for ty in [
            PduType::AdvInd,
            PduType::AdvDirectInd,
            PduType::AdvNonconnInd,
            PduType::AdvScanInd,
            PduType::ScanRsp,
        ] {
            assert!(ty.has_adv_a(), "{ty:?}");
        }
        for ty in [
            PduType::ScanReq,
            PduType::ConnectInd,
            PduType::AdvExtInd,
            PduType::Unknown(0x0a),
        ] {
            assert!(!ty.has_adv_a(), "{ty:?}");
        }
    }

    #[test]
    fn parse_validates_crc_length_and_bounds() {
        let dma = adv_ind(&[0xaa; 10]);
        assert!(Pdu::parse(&dma, true).is_some());
        assert!(Pdu::parse(&dma, false).is_none());
        assert!(Pdu::parse(&dma[..1], true).is_none());

        let mut bad = dma;
        bad[1] = 38;
        assert!(Pdu::parse(&bad, true).is_none());

        let mut bad = dma;
        bad[1] = 10;
        assert!(Pdu::parse(&bad[..11], true).is_none());
        assert!(Pdu::parse(&bad[..12], true).is_some());
    }

    #[test]
    fn adv_ind_payload_address_and_ad_fields() {
        let payload = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // AdvA
            0x02, 0x01, 0x06, // flags (len 2: type + 1 byte)
            0x05, 0xff, 0xff, 0xff, 0x4f, 0x01, // manufacturer (len 5 = type + 4)
            0x05, 0x09, b'h', b'e', b'l', b'l', // name (len 5 = type + 4)
        ];
        let dma = adv_ind(&payload);
        let pdu = Pdu::parse(&dma, true).unwrap();
        assert_eq!(pdu.pdu_type(), PduType::AdvInd);
        assert_eq!(pdu.adv_a(), Some(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        assert_eq!(pdu.target_a(), None);
        assert_eq!(pdu.local_name(), Some(&b"hell"[..]));
        assert_eq!(pdu.manufacturer_data(), Some(&[0xff, 0xff, 0x4f, 0x01][..]));
        let mut ads = [AdStructure {
            ad_type: 0,
            data: &[],
        }; 3];
        for (slot, ad) in ads.iter_mut().zip(pdu.ad_structures()) {
            *slot = ad;
        }
        assert_eq!(ads[0].ad_type, 0x01);
        assert_eq!(ads[0].data, &[0x06]);
        assert_eq!(ads[1].ad_type, 0xff);
        assert_eq!(ads[2].ad_type, 0x09);
    }

    #[test]
    fn truncated_and_zero_terminated_ad_data_stops_safely() {
        // Zero-length terminator ends the list.
        let mut payload = [0u8; 6 + 6];
        payload[6] = 0x02;
        payload[7] = 0x01;
        payload[8] = 0x06;
        payload[9] = 0x00;
        payload[10] = 0x02;
        payload[11] = 0x01;
        let dma = adv_ind(&payload);
        let pdu = Pdu::parse(&dma, true).unwrap();
        assert_eq!(pdu.ad_structures().count(), 1);

        // A length that runs past the payload yields nothing partial.
        let mut payload = [0u8; 6 + 4];
        payload[6] = 0x09;
        payload[7] = 0x09;
        payload[8] = b'a';
        payload[9] = b'b';
        let dma = adv_ind(&payload);
        let pdu = Pdu::parse(&dma, true).unwrap();
        assert_eq!(pdu.local_name(), None);
        assert_eq!(pdu.ad_structures().count(), 0);
    }

    #[test]
    fn scan_req_and_connect_ind_addresses() {
        let mut payload = [0u8; 34];
        payload[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        payload[6..12].copy_from_slice(&[7, 8, 9, 10, 11, 12]);
        let dma = with_header(0x05, &payload);
        let pdu = Pdu::parse(&dma, true).unwrap();
        assert_eq!(pdu.pdu_type(), PduType::ConnectInd);
        assert_eq!(pdu.adv_a(), None);
        assert_eq!(pdu.target_a(), Some(&[7, 8, 9, 10, 11, 12]));
        assert_eq!(pdu.ad_structures().count(), 0);

        let mut payload = [0u8; 12];
        payload[..6].copy_from_slice(&[9, 9, 9, 9, 9, 9]);
        payload[6..12].copy_from_slice(&[0x15, 0, 0, 0xee, 0xff, 0xc1]);
        let dma = with_header(0x43, &payload);
        let pdu = Pdu::parse(&dma, true).unwrap();
        assert_eq!(pdu.pdu_type(), PduType::ScanReq);
        assert!(pdu.tx_add());
        assert_eq!(pdu.target_a(), Some(&[0x15, 0, 0, 0xee, 0xff, 0xc1]));
    }

    #[test]
    fn scan_rsp_and_adv_scan_ind_carry_ad_after_adv_a() {
        for ty in [0x04u8, 0x06] {
            let mut payload = [0u8; 6 + 11];
            payload[..6].copy_from_slice(&[0xc1, 0xff, 0xee, 0, 1, 2]);
            payload[6] = 0x0a;
            payload[7] = 0x09;
            payload[8..17].copy_from_slice(b"wch585-ob");
            let dma = with_header(ty, &payload);
            let pdu = Pdu::parse(&dma, true).unwrap();
            assert_eq!(pdu.adv_a(), Some(&[0xc1, 0xff, 0xee, 0, 1, 2]));
            assert_eq!(pdu.local_name(), Some(&b"wch585-ob"[..]));
        }
    }

    #[test]
    fn header_flag_bits() {
        let dma = with_header(0xe0, &[0u8; 6]);
        let pdu = Pdu::parse(&dma, true).unwrap();
        assert!(pdu.tx_add());
        assert!(pdu.rx_add());
        assert!(pdu.chsel());
        let dma = with_header(0x10, &[0u8; 6]);
        let pdu = Pdu::parse(&dma, true).unwrap();
        assert!(!pdu.tx_add());
        assert!(!pdu.rx_add());
        assert!(!pdu.chsel());
    }

    #[test]
    fn direct_ind_has_no_ad_data() {
        let mut payload = [0u8; 12];
        payload[..6].copy_from_slice(&[1, 1, 1, 1, 1, 1]);
        payload[6..].copy_from_slice(&[2, 2, 2, 2, 2, 2]);
        let dma = with_header(0x01, &payload);
        let pdu = Pdu::parse(&dma, true).unwrap();
        assert_eq!(pdu.adv_a(), Some(&[1, 1, 1, 1, 1, 1]));
        assert_eq!(pdu.target_a(), Some(&[2, 2, 2, 2, 2, 2]));
        assert_eq!(pdu.ad_structures().count(), 0);
        assert_eq!(pdu.local_name(), None);
    }
}
