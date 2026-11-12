//! LE Data Length Extension: negotiated per-direction limits and Host ACL
//! segmentation (Core 5.4, Vol 6, Part B, 4.5.10 and 2.4.2.21).

use crate::crypto::BLE_MIC_LEN;

/// Largest LL Data PDU payload on air, MIC included. The one-octet length
/// field would allow 255, but the specification caps DLE at 251 octets.
pub const LL_MAX_PAYLOAD: u16 = 251;
/// Largest plaintext carried in one encrypted LL PDU.
pub const LL_MAX_PLAINTEXT: u16 = LL_MAX_PAYLOAD - BLE_MIC_LEN as u16;
/// Legacy on-air data PDU payload, MIC included.
pub const LL_LEGACY_PAYLOAD: u16 = 27;
/// Legacy on-air plaintext payload of an encrypted PDU.
pub const LL_LEGACY_PLAINTEXT: u16 = LL_LEGACY_PAYLOAD - BLE_MIC_LEN as u16;
/// Receive ceiling before DLE: one 24-octet Host fragment plus MIC, the size
/// Android Centrals were observed sending without negotiating.
pub const LL_DEFAULT_RX_PAYLOAD: u16 = 31;
/// `MaxRxTime`/`MaxTxTime` suggested by the specification for 251 octets.
/// The value is informational here; the radio timing uses `air_time_us`.
pub const LL_MAX_TIME_US: u16 = 2120;
/// `MaxRxTime`/`MaxTxTime` suggested for the legacy 27-octet PDU.
pub const LL_LEGACY_TIME_US: u16 = 328;

/// On-air time of one LE 1M data PDU: preamble, access address, header,
/// payload and CRC. Not an IFS or scheduling claim.
pub const fn air_time_us(octets: u16) -> u16 {
    80 + octets * 8
}

/// The four fields of `LL_LENGTH_REQ`/`LL_LENGTH_RSP` in wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct LengthParams {
    pub max_rx_octets: u16,
    pub max_rx_time: u16,
    pub max_tx_octets: u16,
    pub max_tx_time: u16,
}

impl LengthParams {
    /// Prefer a requested size but keep every field inside the valid DLE
    /// ranges. Every request or response we send goes through this.
    pub const fn clamped(self) -> Self {
        Self {
            max_rx_octets: clamp(self.max_rx_octets, LL_LEGACY_PAYLOAD, LL_MAX_PAYLOAD),
            max_rx_time: clamp(
                self.max_rx_time,
                air_time_us(LL_LEGACY_PAYLOAD),
                LL_MAX_TIME_US,
            ),
            max_tx_octets: clamp(self.max_tx_octets, LL_LEGACY_PAYLOAD, LL_MAX_PAYLOAD),
            max_tx_time: clamp(
                self.max_tx_time,
                air_time_us(LL_LEGACY_PAYLOAD),
                LL_MAX_TIME_US,
            ),
        }
    }

    /// Parse the eight payload octets (opcode excluded).
    pub fn from_octets(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        Some(Self {
            max_rx_octets: u16::from_le_bytes([bytes[0], bytes[1]]),
            max_rx_time: u16::from_le_bytes([bytes[2], bytes[3]]),
            max_tx_octets: u16::from_le_bytes([bytes[4], bytes[5]]),
            max_tx_time: u16::from_le_bytes([bytes[6], bytes[7]]),
        })
    }

    pub fn to_octets(self) -> [u8; 8] {
        let mut out = [0; 8];
        out[0..2].copy_from_slice(&self.max_rx_octets.to_le_bytes());
        out[2..4].copy_from_slice(&self.max_rx_time.to_le_bytes());
        out[4..6].copy_from_slice(&self.max_tx_octets.to_le_bytes());
        out[6..8].copy_from_slice(&self.max_tx_time.to_le_bytes());
        out
    }
}

const fn clamp(value: u16, min: u16, max: u16) -> u16 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Per-direction DLE state for one link.
///
/// The peer's request and response fields are the same shape: `MaxRxOctets`
/// is what that peer can receive, so it caps our TX; `MaxTxOctets` is what it
/// will send, so it caps our RX. Before any exchange the legacy defaults stay
/// in force (27 on air, 31 for receive compatibility) and are never widened
/// merely because a request was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DataLength {
    local_octets: u16,
    local_time: u16,
    peer_rx_octets: Option<u16>,
    peer_tx_octets: Option<u16>,
    requested: bool,
}

impl Default for DataLength {
    fn default() -> Self {
        Self::new()
    }
}

impl DataLength {
    pub const fn new() -> Self {
        Self {
            local_octets: LL_MAX_PAYLOAD,
            local_time: LL_MAX_TIME_US,
            peer_rx_octets: None,
            peer_tx_octets: None,
            requested: false,
        }
    }

    /// Local limits advertised in a request or response.
    pub const fn local_params(&self) -> LengthParams {
        LengthParams {
            max_rx_octets: self.local_octets,
            max_rx_time: self.local_time,
            max_tx_octets: self.local_octets,
            max_tx_time: self.local_time,
        }
    }

    /// Apply the Host's `LE Set Data Length` request.
    pub fn set_local(&mut self, octets: u16, time: u16) {
        self.local_octets = clamp(octets, LL_LEGACY_PAYLOAD, LL_MAX_PAYLOAD);
        self.local_time = clamp(time, air_time_us(LL_LEGACY_PAYLOAD), LL_MAX_TIME_US);
    }

    pub fn mark_requested(&mut self) {
        self.requested = true;
    }

    pub fn requested(&self) -> bool {
        self.requested
    }

    pub fn negotiated(&self) -> bool {
        self.peer_rx_octets.is_some() || self.peer_tx_octets.is_some()
    }

    /// Store a peer `LL_LENGTH_REQ` and return our response. A request and a
    /// response carry identical fields, so both use this.
    pub fn on_peer_length(&mut self, peer: LengthParams) -> LengthParams {
        let peer = peer.clamped();
        self.peer_rx_octets = Some(peer.max_rx_octets);
        self.peer_tx_octets = Some(peer.max_tx_octets);
        self.local_params()
    }

    /// Effective on-air TX payload, MIC included. 27 until the peer reports
    /// what it can receive.
    pub fn tx_octets(&self) -> u16 {
        match self.peer_rx_octets {
            Some(peer) => self.local_octets.min(peer),
            None => LL_LEGACY_PAYLOAD,
        }
    }

    /// Effective on-air RX payload, MIC included. 31 until the peer reports
    /// what it will send, which keeps the observed 28-octet Android PDU valid.
    pub fn rx_octets(&self) -> u16 {
        match self.peer_tx_octets {
            Some(peer) => self.local_octets.min(peer),
            None => LL_DEFAULT_RX_PAYLOAD,
        }
    }

    /// Largest Host ACL fragment that fits one LL PDU. Encryption adds the MIC
    /// inside the negotiated on-air limit.
    pub fn tx_plaintext(&self, encrypted: bool) -> usize {
        let mic = if encrypted { BLE_MIC_LEN as u16 } else { 0 };
        usize::from(self.tx_octets().saturating_sub(mic).max(1))
    }
}

/// One LL data PDU produced from a Host ACL packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFragment<'a> {
    /// LLID 2 for the first fragment of a start packet, 1 for continuations.
    pub llid: u8,
    pub data: &'a [u8],
}

/// Split a Host ACL payload into LL fragments no larger than `max_fragment`.
///
/// `first_llid` is 2 when the Host packet starts an L2CAP PDU (HCI PB=0) and
/// 1 when it continues one (PB=1). Only the first fragment may use LLID 2;
/// every later fragment is a continuation. An empty Host packet yields no
/// fragments; the caller can acknowledge its tag immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAclFragmenter<'a> {
    payload: &'a [u8],
    offset: usize,
    max_fragment: usize,
    first_llid: u8,
}

impl<'a> HostAclFragmenter<'a> {
    pub fn new(payload: &'a [u8], max_fragment: usize, first_llid: u8) -> Self {
        Self {
            payload,
            offset: 0,
            max_fragment: max_fragment.max(1),
            first_llid: if first_llid == 2 { 2 } else { 1 },
        }
    }

    pub fn is_done(&self) -> bool {
        self.offset >= self.payload.len()
    }

    pub fn remaining(&self) -> usize {
        self.payload.len().saturating_sub(self.offset)
    }

    pub fn next_fragment(&mut self) -> Option<HostFragment<'a>> {
        if self.is_done() {
            return None;
        }
        let end = (self.offset + self.max_fragment).min(self.payload.len());
        let llid = if self.offset == 0 { self.first_llid } else { 1 };
        let data = &self.payload[self.offset..end];
        self.offset = end;
        Some(HostFragment { llid, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_params_round_trip_and_clamp() {
        let params = LengthParams {
            max_rx_octets: 251,
            max_rx_time: 2120,
            max_tx_octets: 27,
            max_tx_time: 328,
        };
        assert_eq!(LengthParams::from_octets(&params.to_octets()), Some(params));
        assert_eq!(LengthParams::from_octets(&[0; 7]), None);
        let clamped = LengthParams {
            max_rx_octets: 1000,
            max_rx_time: 1,
            max_tx_octets: 5,
            max_tx_time: 60000,
        }
        .clamped();
        assert_eq!(clamped.max_rx_octets, 251);
        assert_eq!(clamped.max_rx_time, air_time_us(27));
        assert_eq!(clamped.max_tx_octets, 27);
        assert_eq!(clamped.max_tx_time, 2120);
    }

    #[test]
    fn defaults_stay_legacy_until_the_peer_answers() {
        let mut dle = DataLength::new();
        assert_eq!(dle.tx_octets(), 27);
        assert_eq!(dle.rx_octets(), 31);
        assert!(!dle.negotiated());
        dle.mark_requested();
        assert!(dle.requested());
        // Sending a request must not widen anything by itself.
        assert_eq!(dle.tx_octets(), 27);
        let rsp = dle.on_peer_length(LengthParams {
            max_rx_octets: 251,
            max_rx_time: 2120,
            max_tx_octets: 251,
            max_tx_time: 2120,
        });
        assert!(dle.negotiated());
        assert_eq!(rsp.max_rx_octets, 251);
        assert_eq!(dle.tx_octets(), 251);
        assert_eq!(dle.rx_octets(), 251);
        assert_eq!(dle.tx_plaintext(true), 247);
        assert_eq!(dle.tx_plaintext(false), 251);
    }

    #[test]
    fn effective_limits_take_the_smaller_side() {
        let mut dle = DataLength::new();
        dle.set_local(251, 2120);
        dle.on_peer_length(LengthParams {
            max_rx_octets: 65,
            max_rx_time: 848,
            max_tx_octets: 100,
            max_tx_time: 1120,
        });
        assert_eq!(dle.tx_octets(), 65);
        assert_eq!(dle.rx_octets(), 100);
        dle.set_local(27, 328);
        assert_eq!(dle.tx_octets(), 27);
        assert_eq!(dle.rx_octets(), 27);
    }

    #[test]
    fn host_acl_fragmenter_boundaries_and_llid_sequence() {
        let data = [0x5au8; 741];
        for (len, expected) in [
            (0usize, &[][..]),
            (1, &[1][..]),
            (23, &[23][..]),
            (27, &[27][..]),
            (247, &[247][..]),
            (251, &[247, 4][..]),
            (494, &[247, 247][..]),
            (741, &[247, 247, 247][..]),
        ] {
            let mut fragments = HostAclFragmenter::new(&data[..len], 247, 2);
            let mut sizes = [0usize; 4];
            let mut count = 0;
            let mut first_llid = None;
            while let Some(fragment) = fragments.next_fragment() {
                if count == 0 {
                    first_llid = Some(fragment.llid);
                } else {
                    assert_eq!(fragment.llid, 1);
                }
                sizes[count] = fragment.data.len();
                count += 1;
                assert!(fragment.data.iter().all(|b| *b == 0x5a));
            }
            assert_eq!(&sizes[..count], expected, "len={len}");
            assert_eq!(first_llid, expected.first().map(|_| 2));
            assert!(fragments.is_done());
            assert_eq!(fragments.remaining(), 0);
            assert_eq!(fragments.next_fragment(), None);
        }
        // A continuation Host packet never uses LLID 2.
        let data = [1u8; 30];
        let mut fragments = HostAclFragmenter::new(&data, 16, 1);
        assert_eq!(fragments.next_fragment().unwrap().llid, 1);
        assert_eq!(fragments.next_fragment().unwrap().llid, 1);
        assert!(fragments.next_fragment().is_none());
    }
}
