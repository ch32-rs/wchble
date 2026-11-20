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

/// Max advertising data in one AUX_ADV_IND:
/// `AdvData = Length − (ExtHdrLen + 1)`, Length ≤ 255, ExtHdr = flags + AdvA + ADI.
pub const EXT_ADV_DATA_MAX: usize = 245;

/// AuxPtr offset from the primary packet start to the AUX packet start, in
/// 30 µs units (Core Vol 6 Part B 2.3.4.5).
pub const AUX_OFFSET_UNITS: u16 = 600 / 30;

/// One extended advertising set (X2a: non-connectable, non-scannable, handle 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ExtAdvState {
    /// Set by Set Ext Adv Params; enable and builders refuse otherwise.
    pub configured: bool,
    pub enabled: bool,
    /// Fixed interval in 0.625 ms slots (HCI max when min != max).
    pub interval_slots: u16,
    /// Bit0=ch37, bit1=ch38, bit2=ch39 (primary map).
    pub channel_map: u8,
    pub own_addr: [u8; 6],
    pub random_addr: bool,
    /// Advertising Set ID placed in the ADI SID field (0–15).
    pub adv_sid: u8,
    /// Advertising Data ID; the HCI layer rolls it randomly on data change.
    pub did: u16,
    /// Secondary PHY mask (HCI semantics): bit0=1M, bit1=2M.
    pub aux_phy: u8,
    pub data_len: usize,
    pub data: [u8; EXT_ADV_DATA_MAX],
    /// Duration in 10 ms units from Set Ext Adv Enable; 0 = unlimited.
    pub duration_10ms: u16,
    /// Max extended advertising events; 0 = no cap.
    pub max_events: u8,
    /// Completed extended advertising events since enable.
    pub events_done: u32,
    /// Enable timestamp in µs for the duration check.
    pub enabled_at_us: u32,
}

impl Default for ExtAdvState {
    fn default() -> Self {
        Self {
            configured: false,
            enabled: false,
            interval_slots: 0x0100, // 160 ms
            channel_map: 0x07,
            own_addr: [0; 6],
            random_addr: true,
            adv_sid: 0,
            did: 0,
            aux_phy: 0x01,
            data_len: 0,
            data: [0; EXT_ADV_DATA_MAX],
            duration_10ms: 0,
            max_events: 0,
            events_done: 0,
            enabled_at_us: 0,
        }
    }
}

/// Set Ext Adv Data operation (Core Vol 4 Part E 7.8.54).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataOp {
    Intermediate,
    First,
    Last,
    Complete,
}

/// Data assembly failure for the HCI layer to map onto a status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataError {
    /// Combined length exceeds `EXT_ADV_DATA_MAX` (Memory Capacity Exceeded).
    Capacity,
}

impl ExtAdvState {
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

    /// Assemble advertising data for the four data operations (7.8.54).
    ///
    /// First/Complete discard existing data; Intermediate/Last append.
    pub fn append_adv_data(&mut self, op: DataOp, bytes: &[u8]) -> Result<(), DataError> {
        let base = match op {
            DataOp::First | DataOp::Complete => 0,
            DataOp::Intermediate | DataOp::Last => self.data_len,
        };
        let total = base + bytes.len();
        if total > EXT_ADV_DATA_MAX {
            return Err(DataError::Capacity);
        }
        self.data[base..total].copy_from_slice(bytes);
        self.data_len = total;
        Ok(())
    }

    /// ADI field bytes: DID in the low 12 bits, SID in the high 4 (Fig 2.18).
    fn adi(&self) -> [u8; 2] {
        (((self.adv_sid as u16) << 12) | (self.did & 0x0fff)).to_le_bytes()
    }

    /// AuxPtr field bytes for the given auxiliary channel: Channel Index,
    /// CA=0, Units=0 (30 µs), offset 600 µs, AUX PHY per Table 2.14.
    fn aux_ptr(&self, aux_channel: u8) -> [u8; 3] {
        // Table 2.14 values: 0b000 = LE 1M, 0b001 = LE 2M.
        let phy = if self.aux_phy & 0x02 != 0 { 1u32 } else { 0 };
        let bits = u32::from(aux_channel)
            | (0 << 6)
            | (0 << 7)
            | (u32::from(AUX_OFFSET_UNITS) << 8)
            | (phy << 21);
        bits.to_le_bytes()[..3].try_into().unwrap()
    }

    /// Secondary channel for the given advertising round (controller's choice).
    pub fn aux_channel(round: u32) -> u8 {
        (round.wrapping_mul(7) % 37) as u8
    }

    /// PDU Length field of the AUX_ADV_IND: Extended Header Length byte +
    /// ExtHdr(9) + data.
    pub fn aux_payload_len(&self) -> usize {
        10 + self.data_len
    }

    /// AUX_ADV_IND air time at the configured secondary PHY.
    pub fn aux_air_us(&self) -> u32 {
        let n = self.aux_payload_len();
        if self.aux_phy & 0x02 != 0 {
            44 + 4 * n as u32
        } else {
            80 + 8 * n as u32
        }
    }

    /// One extended advertising round: primary packet start to AUX end plus
    /// the caller's radio-exit cost.
    pub fn round_span_us(&self, exit_us: u32) -> u32 {
        u32::from(AUX_OFFSET_UNITS) * 30 + self.aux_air_us() + exit_us
    }

    /// Build the primary ADV_EXT_IND (ADI + AuxPtr, no AdvA) for `aux_channel`.
    ///
    /// Returns `None` when disabled or `out` is too small.
    pub fn build_adv_ext_ind(&self, out: &mut [u8], aux_channel: u8) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        if out.len() < 9 {
            return None;
        }
        // Header: ADV_EXT_IND (0b0111), TxAdd; payload: ExtHdrLen byte + 6.
        out[0] = 0x07 | if self.random_addr { 0x40 } else { 0 };
        out[1] = 7;
        out[2] = 0x06; // AdvMode 00b, Extended Header Length 6.
        out[3] = 0x18; // Flags: ADI | AuxPtr.
        out[4..6].copy_from_slice(&self.adi());
        out[6..9].copy_from_slice(&self.aux_ptr(aux_channel));
        Some(9)
    }

    /// Build the secondary AUX_ADV_IND (AdvA + ADI + advertising data).
    ///
    /// Returns `None` when disabled or `out` is too small.
    pub fn build_aux_adv_ind(&self, out: &mut [u8]) -> Option<usize> {
        if !self.enabled {
            return None;
        }
        let payload_len = self.aux_payload_len();
        let total = 2 + payload_len;
        if out.len() < total || payload_len > 255 {
            return None;
        }
        out[0] = 0x07 | if self.random_addr { 0x40 } else { 0 };
        out[1] = payload_len as u8;
        out[2] = 0x09; // AdvMode 00b, Extended Header Length 9.
        out[3] = 0x09; // Flags: AdvA | ADI.
        out[4..10].copy_from_slice(&self.own_addr);
        out[10..12].copy_from_slice(&self.adi());
        out[12..total].copy_from_slice(&self.data[..self.data_len]);
        Some(total)
    }

    /// Record one completed extended advertising event; true when the set
    /// terminates (duration elapsed or the event cap was reached).
    pub fn round_done(&mut self, now_us: u32) -> bool {
        if !self.enabled {
            return false;
        }
        self.events_done += 1;
        if self.max_events != 0 && self.events_done >= u32::from(self.max_events) {
            return true;
        }
        if self.duration_10ms != 0 {
            let elapsed = now_us.wrapping_sub(self.enabled_at_us);
            if elapsed >= u32::from(self.duration_10ms) * 10_000 {
                return true;
            }
        }
        false
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

    fn ext() -> ExtAdvState {
        let mut s = ExtAdvState::default();
        s.configured = true;
        s.enabled = true;
        s.own_addr = [0xC1, 0xFF, 0xEE, 0, 0, 0x2A];
        s.random_addr = true;
        s.adv_sid = 1;
        s.did = 0x123;
        s
    }

    #[test]
    fn adv_ext_ind_carries_only_adi_and_auxptr() {
        for (aux_phy, phy_bits) in [(0x01u8, 0u32), (0x02, 1)] {
            let mut s = ext();
            s.aux_phy = aux_phy;
            let mut out = [0xcc; 16];
            let n = s.build_adv_ext_ind(&mut out, 25).unwrap();
            assert_eq!(n, 9, "17 octets on air: 136 us at 1M");
            assert_eq!(out[0], 0x47, "ADV_EXT_IND with TxAdd");
            assert_eq!(out[1], 7);
            assert_eq!(out[2], 0x06, "AdvMode 00b, ExtHdrLen 6");
            assert_eq!(out[3], 0x18, "flags ADI|AuxPtr");
            // ADI: SID in the high nibble, DID in the low 12 bits.
            assert_eq!(&out[4..6], &[0x23, 0x11]);
            // AuxPtr LE bytes: ch 25 | CA/units 0 | offset 20<<8 | PHY<<21.
            assert_eq!(&out[6..9], &[0x19, 0x14, (phy_bits << 5) as u8]);
            assert!(out[9..].iter().all(|&b| b == 0xcc), "no more bytes");
            assert_eq!(s.build_adv_ext_ind(&mut out[..8], 25), None);
        }
    }

    #[test]
    fn aux_adv_ind_carries_adva_adi_and_data() {
        let mut s = ext();
        s.append_adv_data(DataOp::Complete, &[0xA5; 200]).unwrap();
        let mut out = [0u8; 256];
        let n = s.build_aux_adv_ind(&mut out).unwrap();
        assert_eq!(n, 2 + 10 + 200);
        assert_eq!(out[0], 0x47);
        assert_eq!(out[1], 210);
        assert_eq!(out[2], 0x09, "AdvMode 00b, ExtHdrLen 9");
        assert_eq!(out[3], 0x09, "flags AdvA|ADI");
        assert_eq!(&out[4..10], &s.own_addr);
        assert_eq!(&out[10..12], &[0x23, 0x11]);
        assert!(out[12..n].iter().all(|&b| b == 0xA5));
        // 245 octets of data is the single-AUX ceiling.
        s.append_adv_data(DataOp::Complete, &[0x5A; 245]).unwrap();
        let mut big = [0u8; 257];
        assert_eq!(s.build_aux_adv_ind(&mut big).unwrap(), 257);
    }

    #[test]
    fn adi_packs_did_low_and_sid_high() {
        let mut s = ext();
        s.adv_sid = 1;
        s.did = 0;
        let mut out = [0u8; 16];
        s.build_adv_ext_ind(&mut out, 0).unwrap();
        assert_eq!(&out[4..6], &[0x00, 0x10]);
        s.did = 0x0FFF;
        s.build_adv_ext_ind(&mut out, 0).unwrap();
        assert_eq!(&out[4..6], &[0xFF, 0x1F]);
    }

    #[test]
    fn aux_offset_reserves_the_mafs_margin() {
        // Core 2.3.4.5: AuxOffset >= primary air time (136 us) + T_MAFS (300 us).
        assert!(u32::from(AUX_OFFSET_UNITS) * 30 >= 136 + 300);
        // All data sizes fit the 13-bit AuxPtr field.
        assert!(u32::from(AUX_OFFSET_UNITS) < (1 << 13));
    }

    #[test]
    fn data_operations_assemble_into_one_buffer() {
        let mut s = ext();
        s.append_adv_data(DataOp::First, &[1, 2, 3]).unwrap();
        s.append_adv_data(DataOp::Intermediate, &[4, 5]).unwrap();
        s.append_adv_data(DataOp::Last, &[6]).unwrap();
        assert_eq!(s.data_len, 6);
        assert_eq!(&s.data[..6], &[1, 2, 3, 4, 5, 6]);
        // First discards the previous assembly.
        s.append_adv_data(DataOp::First, &[9]).unwrap();
        assert_eq!(s.data_len, 1);
        s.append_adv_data(DataOp::Intermediate, &[0xB5; 245])
            .unwrap_err();
        assert_eq!(s.data_len, 1, "overflow leaves the buffer intact");
        s.append_adv_data(DataOp::Complete, &[0; 245]).unwrap();
        assert_eq!(s.data_len, 245);
        s.append_adv_data(DataOp::Intermediate, &[0]).unwrap_err();
    }

    #[test]
    fn aux_air_and_span_follow_the_configured_phy() {
        let mut s = ext();
        s.append_adv_data(DataOp::Complete, &[0; 128]).unwrap();
        assert_eq!(s.aux_air_us(), 80 + 8 * 138);
        assert_eq!(s.round_span_us(160), 600 + 1184 + 160);
        s.aux_phy = 0x02;
        assert_eq!(s.aux_air_us(), 44 + 4 * 138);
        s.append_adv_data(DataOp::Complete, &[0; 245]).unwrap();
        assert_eq!(s.aux_air_us(), 44 + 4 * 255);
        s.aux_phy = 0x01;
        assert_eq!(s.aux_air_us(), 80 + 8 * 255);
        assert_eq!(s.round_span_us(160), 600 + 2120 + 160);
    }

    #[test]
    fn aux_channels_rotate_over_the_data_channels() {
        let mut seen = [false; 37];
        for round in 0..37 {
            let ch = ExtAdvState::aux_channel(round);
            assert!(ch < 37);
            seen[usize::from(ch)] = true;
        }
        assert!(seen.iter().all(|&s| s), "7 is invertible mod 37");
    }

    #[test]
    fn round_done_terminates_on_events_and_duration() {
        let mut s = ext();
        s.max_events = 3;
        assert!(!s.round_done(0));
        assert!(!s.round_done(0));
        assert!(s.round_done(0));
        assert_eq!(s.events_done, 3);
        // Duration: 2 x 10 ms counted from the enable instant.
        s.max_events = 0;
        s.duration_10ms = 2;
        s.enabled_at_us = 1_000;
        assert!(!s.round_done(1_000 + 19_999));
        assert!(s.round_done(1_000 + 20_000));
        // Unlimited set never terminates.
        s.duration_10ms = 0;
        s.enabled_at_us = 0;
        for _ in 0..1000 {
            assert!(!s.round_done(u32::MAX / 2));
        }
    }

    #[test]
    fn disabled_state_builds_nothing() {
        let mut s = ExtAdvState::default();
        let mut out = [0u8; 256];
        assert_eq!(s.build_adv_ext_ind(&mut out, 0), None);
        assert_eq!(s.build_aux_adv_ind(&mut out), None);
        assert!(!s.round_done(0));
    }
}
