//! Legacy advertising state + ADV_IND PDU builder.

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
        // PDU header: ADV_IND (0), TxAdd = random if own is random.
        out[0] = if self.random_addr { 0x40 } else { 0x00 };
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
}
