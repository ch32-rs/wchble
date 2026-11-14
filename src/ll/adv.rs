//! Legacy advertising state and pure advertising PDU helpers.

/// Max HCI advertising / scan-response data payload (Core Vol 4 Part E).
pub const ADV_DATA_MAX: usize = 31;

/// Advertising enable / parameters / payloads held by the LL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AdvState {
    pub enabled: bool,
    /// Advertising interval in 0.625 ms slots (HCI `Advertising_Interval_Min`).
    pub interval_slots: u16,
    /// Bit0=ch37, bit1=ch38, bit2=ch39.
    pub channel_map: u8,
    /// Own address used as AdvA (`TxAdd=random` when [`Self::random_addr`]).
    pub own_addr: [u8; 6],
    pub random_addr: bool,
    /// Set ChSel in ADV_IND/ADV_SCAN_IND: this advertiser supports CSA #2.
    /// A connection uses CSA #2 only if the initiator's CONNECT_IND says so
    /// too. SCAN_RSP has no ChSel bit (RFU) and always leaves it clear.
    pub chsel: bool,
    pub data_len: u8,
    pub data: [u8; ADV_DATA_MAX],
    pub scan_rsp_len: u8,
    pub scan_rsp: [u8; ADV_DATA_MAX],
}

impl Default for AdvState {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_slots: 0x0020, // ~20 ms
            channel_map: 0x07,      // 37/38/39
            own_addr: [0; 6],
            random_addr: true,
            chsel: false,
            data_len: 0,
            data: [0; ADV_DATA_MAX],
            scan_rsp_len: 0,
            scan_rsp: [0; ADV_DATA_MAX],
        }
    }
}

impl AdvState {
    /// Advertising channels selected by [`Self::channel_map`] (BLE indices).
    pub fn channels(&self) -> impl Iterator<Item = u8> + '_ {
        [37u8, 38, 39]
            .into_iter()
            .enumerate()
            .filter_map(|(bit, ch)| ((self.channel_map >> bit) & 1 != 0).then_some(ch))
    }

    /// Interval converted to microseconds.
    pub fn interval_us(&self) -> u32 {
        u32::from(self.interval_slots) * 625
    }

    /// Store HCI `LE Set Advertising Data` payload (`len` + bytes).
    pub fn set_adv_data(&mut self, len: u8, bytes: &[u8]) -> bool {
        let n = usize::from(len);
        if n > ADV_DATA_MAX || bytes.len() < n {
            return false;
        }
        self.data[..n].copy_from_slice(&bytes[..n]);
        self.data_len = len;
        true
    }

    /// Store HCI `LE Set Scan Response Data` payload (`len` + bytes).
    pub fn set_scan_rsp(&mut self, len: u8, bytes: &[u8]) -> bool {
        let n = usize::from(len);
        if n > ADV_DATA_MAX || bytes.len() < n {
            return false;
        }
        self.scan_rsp[..n].copy_from_slice(&bytes[..n]);
        self.scan_rsp_len = len;
        true
    }

    /// Build a legacy ADV_SCAN_IND PDU (header + AdvA + advertising data).
    ///
    /// Returns `None` if advertising is disabled, the stored length is invalid,
    /// or the output is too small. No bytes are written on failure.
    pub fn build_adv_scan_ind(&self, out: &mut [u8]) -> Option<usize> {
        self.build_scannable_pdu(out, 0x06, self.data_len, &self.data, self.chsel)
    }

    /// Build a legacy SCAN_RSP PDU (header + AdvA + scan response data).
    ///
    /// Returns `None` under the same conditions as [`Self::build_adv_scan_ind`].
    pub fn build_scan_rsp(&self, out: &mut [u8]) -> Option<usize> {
        self.build_scannable_pdu(out, 0x04, self.scan_rsp_len, &self.scan_rsp, false)
    }

    fn build_scannable_pdu(
        &self,
        out: &mut [u8],
        pdu_type: u8,
        data_len: u8,
        data: &[u8; ADV_DATA_MAX],
        chsel: bool,
    ) -> Option<usize> {
        let n = usize::from(data_len);
        let total = 8 + n;
        if !self.enabled || n > ADV_DATA_MAX || out.len() < total {
            return None;
        }
        out[0] = pdu_type | if self.random_addr { 0x40 } else { 0 } | if chsel { 0x20 } else { 0 };
        out[1] = (6 + n) as u8;
        out[2..8].copy_from_slice(&self.own_addr);
        out[8..total].copy_from_slice(&data[..n]);
        Some(total)
    }

    /// Check a received legacy SCAN_REQ addressed to this advertiser.
    ///
    /// `pdu` is exactly the two-byte header and twelve-byte payload, without
    /// access address or CRC; `crc_ok` is the receiver's CRC result. Scanner
    /// address and TxAdd may have either value. RFU header bits are ignored.
    /// This only validates the packet, independently of advertising enable state.
    pub fn validate_scan_req(&self, pdu: &[u8], crc_ok: bool) -> bool {
        crc_ok
            && pdu.len() == 14
            && pdu[0] & 0x0f == 0x03
            && pdu[1] == 12
            && (pdu[0] & 0x80 != 0) == self.random_addr
            && pdu[8..14] == self.own_addr
    }

    /// Build a legacy ADV_IND PDU into `out` (header + AdvA + AD).
    ///
    /// Returns `None` when advertising is disabled or `out` is too small.
    pub fn build_adv_ind(&self, out: &mut [u8]) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        let ad_len = usize::from(self.data_len);
        let payload_len = 6 + ad_len;
        let total = 2 + payload_len;
        if out.len() < total || payload_len > 37 {
            return None;
        }
        // PDU header: ADV_IND (0), TxAdd = random if own is random, ChSel.
        out[0] = if self.random_addr { 0x40 } else { 0x00 } | if self.chsel { 0x20 } else { 0 };
        out[1] = payload_len as u8;
        out[2..8].copy_from_slice(&self.own_addr);
        if ad_len != 0 {
            out[8..8 + ad_len].copy_from_slice(&self.data[..ad_len]);
        }
        Some(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scannable_builders_encode_lengths_addresses_and_distinct_data() {
        for random in [false, true] {
            for len in [0, 1, 31] {
                let mut adv = AdvState::default();
                adv.enabled = true;
                adv.random_addr = random;
                adv.own_addr = [1, 2, 3, 4, 5, 6];
                assert!(adv.set_adv_data(len, &[0xa5; 31]));
                assert!(adv.set_scan_rsp(len, &[0x5a; 31]));
                for (build, kind, value) in [
                    (
                        AdvState::build_adv_scan_ind as fn(&AdvState, &mut [u8]) -> Option<usize>,
                        0x06,
                        0xa5,
                    ),
                    (AdvState::build_scan_rsp, 0x04, 0x5a),
                ] {
                    let mut out = [0xcc; 40];
                    let total = build(&adv, &mut out).unwrap();
                    assert_eq!(total, 8 + usize::from(len));
                    assert_eq!(out[0], kind | if random { 0x40 } else { 0 });
                    assert_eq!(out[1], 6 + len);
                    assert_eq!(&out[2..8], &adv.own_addr);
                    assert!(out[8..total].iter().all(|&b| b == value));
                    assert!(out[total..].iter().all(|&b| b == 0xcc));
                    assert_eq!(build(&adv, &mut out[..total]), Some(total));
                }
            }
        }
    }

    #[test]
    fn scannable_builders_reject_bad_bounds_without_writing() {
        let mut adv = AdvState::default();
        for build in [
            AdvState::build_adv_scan_ind as fn(&AdvState, &mut [u8]) -> Option<usize>,
            AdvState::build_scan_rsp,
        ] {
            let mut out = [0xcc; 40];
            assert_eq!(build(&adv, &mut out), None);
            assert_eq!(out, [0xcc; 40]);
            adv.enabled = true;
            for size in 0..8 {
                assert_eq!(build(&adv, &mut out[..size]), None);
                assert_eq!(out, [0xcc; 40]);
            }
            adv.data_len = 31;
            adv.scan_rsp_len = 31;
            assert_eq!(build(&adv, &mut out[..38]), None);
            assert_eq!(out, [0xcc; 40]);
            for invalid in [32, 255] {
                adv.data_len = invalid;
                adv.scan_rsp_len = invalid;
                assert_eq!(build(&adv, &mut out), None);
                assert_eq!(out, [0xcc; 40]);
            }
            adv = AdvState::default();
        }
    }

    #[test]
    fn scan_req_checks_crc_type_exact_lengths_address_and_rxadd() {
        let mut adv = AdvState::default();
        adv.own_addr = [1, 2, 3, 4, 5, 6];
        let mut req = [0u8; 15];
        req[0] = 0x83;
        req[1] = 12;
        req[2..8].copy_from_slice(&[9, 8, 7, 6, 5, 4]);
        req[8..14].copy_from_slice(&adv.own_addr);
        assert!(adv.validate_scan_req(&req[..14], true));
        assert!(!adv.validate_scan_req(&req[..14], false));
        for len in 0..14 {
            assert!(!adv.validate_scan_req(&req[..len], true));
        }
        assert!(!adv.validate_scan_req(&req, true));
        for kind in 0..16 {
            req[0] = 0x80 | kind;
            assert_eq!(adv.validate_scan_req(&req[..14], true), kind == 3);
        }
        req[0] = 0x83;
        for len in 0..=255 {
            req[1] = len;
            assert_eq!(adv.validate_scan_req(&req[..14], true), len == 12);
        }
        req[1] = 12;
        for i in 8..14 {
            req[i] ^= 1;
            assert!(!adv.validate_scan_req(&req[..14], true));
            req[i] ^= 1;
        }
        for random in [false, true] {
            adv.random_addr = random;
            for rxadd in [false, true] {
                for txadd in [false, true] {
                    req[0] = 0x03 | if rxadd { 0x80 } else { 0 } | if txadd { 0x40 } else { 0 };
                    assert_eq!(adv.validate_scan_req(&req[..14], true), rxadd == random);
                }
            }
        }
        // RFU bits do not affect reception.
        req[0] = 0xb3;
        assert!(adv.validate_scan_req(&req[..14], true));
    }

    #[test]
    fn channels_follow_map_bits() {
        let mut adv = AdvState::default();
        adv.channel_map = 0b101; // 37 + 39
        let mut chs = [0u8; 3];
        let mut n = 0;
        for ch in adv.channels() {
            chs[n] = ch;
            n += 1;
        }
        assert_eq!(&chs[..n], &[37, 39]);
    }

    #[test]
    fn build_adv_ind_includes_addr_and_data() {
        let mut adv = AdvState::default();
        adv.enabled = true;
        adv.own_addr = [0xC1, 0xFF, 0xEE, 0, 0, 1];
        assert!(adv.set_adv_data(3, &[0x02, 0x01, 0x06]));
        let mut out = [0u8; 32];
        let n = adv.build_adv_ind(&mut out).unwrap();
        assert_eq!(n, 2 + 6 + 3);
        assert_eq!(out[0], 0x40);
        assert_eq!(out[1], 9);
        assert_eq!(&out[2..8], &adv.own_addr);
        assert_eq!(&out[8..11], &[0x02, 0x01, 0x06]);
    }

    #[test]
    fn chsel_is_set_on_scannable_advertising_but_not_scan_rsp() {
        for random in [false, true] {
            for chsel in [false, true] {
                let mut adv = AdvState::default();
                adv.enabled = true;
                adv.random_addr = random;
                adv.chsel = chsel;
                assert!(adv.set_adv_data(1, &[0x02]));
                assert!(adv.set_scan_rsp(1, &[0x02]));
                let mut out = [0u8; 16];
                adv.build_adv_ind(&mut out).unwrap();
                assert_eq!(out[0] & 0x20 != 0, chsel);
                assert_eq!(out[0] & 0x40 != 0, random);
                adv.build_adv_scan_ind(&mut out).unwrap();
                assert_eq!(out[0] & 0x0f, 0x06);
                assert_eq!(out[0] & 0x20 != 0, chsel);
                adv.build_scan_rsp(&mut out).unwrap();
                assert_eq!(out[0] & 0x0f, 0x04);
                assert_eq!(out[0] & 0x20, 0);
            }
        }
    }
}
