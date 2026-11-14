//! LE Data Length Extension: negotiated per-direction limits and Host ACL
//! segmentation (Core 5.4, Vol 6, Part B, 4.5.10 and 2.4.2.21).

use crate::crypto::BLE_MIC_LEN;

/// Largest payload field an `LL_LENGTH_REQ`/`LL_LENGTH_RSP` may carry
/// (Core 5.4, Vol 6, Part B, §4.5.10). The MIC is a separate on-air field,
/// so an encrypted PDU may reach 255 octets on air; this controller keeps
/// its air ceiling at 251 and therefore advertises `LL_MAX_PLAINTEXT`.
pub const LL_MAX_PAYLOAD: u16 = 251;
/// Largest payload this controller receives or sends inside one LL PDU:
/// 251 on air minus the MIC, which is what we put in the octet fields.
pub const LL_MAX_PLAINTEXT: u16 = LL_MAX_PAYLOAD - BLE_MIC_LEN as u16;
/// Legacy payload of a data PDU, MIC excluded.
pub const LL_LEGACY_PAYLOAD: u16 = 27;
/// On-air receive ceiling before DLE: one 24-octet Host fragment plus MIC,
/// the size Android Centrals were observed sending without negotiating. This
/// is an air limit, so it is used as-is on encrypted and plaintext links.
pub const LL_DEFAULT_RX_PAYLOAD: u16 = 31;
/// `MaxRxTime`/`MaxTxTime` suggested by the specification for 251 octets.
/// The value is informational here; the radio timing uses `air_time_us`.
pub const LL_MAX_TIME_US: u16 = 2120;
/// `MaxRxTime`/`MaxTxTime` floor (Core 5.4 Vol 6 Part B 4.5.10: 0x0148 =
/// 328 us) and the value suggested for the legacy 27-octet PDU.
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
            max_rx_time: clamp(self.max_rx_time, LL_LEGACY_TIME_US, LL_MAX_TIME_US),
            max_tx_octets: clamp(self.max_tx_octets, LL_LEGACY_PAYLOAD, LL_MAX_PAYLOAD),
            max_tx_time: clamp(self.max_tx_time, LL_LEGACY_TIME_US, LL_MAX_TIME_US),
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

/// MIC octets added on air by encryption, separate from the payload count.
const fn mic_octets(encrypted: bool) -> u16 {
    if encrypted {
        BLE_MIC_LEN as u16
    } else {
        0
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
/// Every octet field counts payload octets, MIC excluded (§4.5.10); the MIC
/// is added on top when a PDU is encrypted on air. The peer's request and
/// response fields are the same shape: `MaxRxOctets` is what that peer can
/// receive, so it caps our TX; `MaxTxOctets` is what it will send, so it caps
/// our RX. Before any exchange the legacy defaults stay in force (27 payload,
/// 31 on air for receive compatibility) and are never widened merely because
/// a request was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DataLength {
    /// This controller's own receive limits. The Host's `LE Set Data Length`
    /// never changes them.
    local_rx_octets: u16,
    local_rx_time: u16,
    /// This controller's transmit preference, seeded by the Host's suggested
    /// default and overridden by `LE Set Data Length` for one connection.
    local_tx_octets: u16,
    local_tx_time: u16,
    peer_rx_octets: Option<u16>,
    peer_rx_time: Option<u16>,
    peer_tx_octets: Option<u16>,
    peer_tx_time: Option<u16>,
    requested: bool,
    /// This side sent `LL_LENGTH_REQ` and a response may be applied.
    awaiting_rsp: bool,
}

impl Default for DataLength {
    fn default() -> Self {
        Self::new()
    }
}

impl DataLength {
    pub const fn new() -> Self {
        Self {
            local_rx_octets: LL_MAX_PLAINTEXT,
            local_rx_time: LL_MAX_TIME_US,
            local_tx_octets: LL_MAX_PLAINTEXT,
            local_tx_time: LL_MAX_TIME_US,
            peer_rx_octets: None,
            peer_rx_time: None,
            peer_tx_octets: None,
            peer_tx_time: None,
            requested: false,
            awaiting_rsp: false,
        }
    }

    /// Local limits advertised in a request or response: this controller's
    /// receive capability and its transmit preference.
    pub const fn local_params(&self) -> LengthParams {
        LengthParams {
            max_rx_octets: self.local_rx_octets,
            max_rx_time: self.local_rx_time,
            max_tx_octets: self.local_tx_octets,
            max_tx_time: self.local_tx_time,
        }
    }

    /// Apply the Host's `LE Set Data Length` request. It only sets this
    /// controller's TX preference; the receive limit is a local capability.
    /// The advertised value is a payload count, so a request for 251 is
    /// granted as 247: the MIC must still fit inside the 251-octet air
    /// ceiling.
    pub fn set_local_tx(&mut self, octets: u16, time: u16) {
        self.local_tx_octets = clamp(octets, LL_LEGACY_PAYLOAD, LL_MAX_PLAINTEXT);
        self.local_tx_time = clamp(time, LL_LEGACY_TIME_US, LL_MAX_TIME_US);
    }

    /// Seed the TX preference from `LE Write Suggested Default Data Length`.
    /// It applies to new connections until an explicit `LE Set Data Length`
    /// overrides it for the current one.
    pub fn set_suggested_tx(&mut self, octets: u16, time: u16) {
        self.set_local_tx(octets, time);
    }

    /// Record that a length exchange happened in either direction, so the
    /// controller does not start a second one.
    pub fn mark_requested(&mut self) {
        self.requested = true;
    }

    /// Record that this side transmitted `LL_LENGTH_REQ`; only then may an
    /// incoming `LL_LENGTH_RSP` move the negotiated limits.
    pub fn mark_sent_request(&mut self) {
        self.requested = true;
        self.awaiting_rsp = true;
    }

    /// A response to our request arrived, or the procedure will not complete.
    pub fn clear_awaiting_rsp(&mut self) {
        self.awaiting_rsp = false;
    }

    pub fn awaiting_rsp(&self) -> bool {
        self.awaiting_rsp
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
        self.peer_rx_time = Some(peer.max_rx_time);
        self.peer_tx_octets = Some(peer.max_tx_octets);
        self.peer_tx_time = Some(peer.max_tx_time);
        self.local_params()
    }

    /// Effective TX payload, MIC excluded. 27 until the peer reports what it
    /// can receive.
    pub fn tx_payload(&self) -> u16 {
        match self.peer_rx_octets {
            Some(peer) => self.local_tx_octets.min(peer),
            None => LL_LEGACY_PAYLOAD,
        }
    }

    /// Effective RX payload, MIC excluded.
    pub fn rx_payload(&self) -> u16 {
        match self.peer_tx_octets {
            Some(peer) => self.local_rx_octets.min(peer),
            None => LL_LEGACY_PAYLOAD,
        }
    }

    /// Effective TX payload on air: the negotiated payload plus the MIC when
    /// the link is encrypted.
    pub fn tx_octets(&self, encrypted: bool) -> u16 {
        self.tx_payload() + mic_octets(encrypted)
    }

    /// Effective RX ceiling on air. 31 until the peer reports what it will
    /// send, which keeps the observed 28-octet Android PDU valid.
    pub fn rx_octets(&self, encrypted: bool) -> u16 {
        match self.peer_tx_octets {
            Some(_) => self.rx_payload() + mic_octets(encrypted),
            None => LL_DEFAULT_RX_PAYLOAD,
        }
    }

    /// Effective on-air TX time, MIC included. The peer's `MaxRxTime` caps
    /// our `MaxTxTime`; 328 µs is the legacy default.
    pub fn tx_time_us(&self) -> u16 {
        match self.peer_rx_time {
            Some(peer) => self.local_tx_time.min(peer),
            None => LL_LEGACY_TIME_US,
        }
    }

    /// Effective on-air RX time. The peer's `MaxTxTime` caps our `MaxRxTime`;
    /// the default covers the 31-octet pre-negotiation receive window.
    pub fn rx_time_us(&self) -> u16 {
        match self.peer_tx_time {
            Some(peer) => self.local_rx_time.min(peer),
            None => air_time_us(LL_DEFAULT_RX_PAYLOAD),
        }
    }

    /// Largest Host ACL fragment that fits one LL PDU.
    pub fn tx_plaintext(&self) -> usize {
        usize::from(self.tx_payload().max(1))
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
        assert_eq!(clamped.max_rx_time, LL_LEGACY_TIME_US);
        assert_eq!(clamped.max_tx_octets, 27);
        assert_eq!(clamped.max_tx_time, 2120);
    }

    #[test]
    fn defaults_stay_legacy_until_the_peer_answers() {
        let mut dle = DataLength::new();
        assert_eq!(dle.tx_octets(false), 27);
        assert_eq!(dle.tx_octets(true), 31);
        assert_eq!(dle.rx_octets(false), 31);
        assert_eq!(dle.rx_octets(true), 31);
        assert!(!dle.negotiated());
        dle.mark_requested();
        assert!(dle.requested());
        // Sending a request must not widen anything by itself.
        assert_eq!(dle.tx_payload(), 27);
        let rsp = dle.on_peer_length(LengthParams {
            max_rx_octets: 251,
            max_rx_time: 2120,
            max_tx_octets: 251,
            max_tx_time: 2120,
        });
        assert!(dle.negotiated());
        // The local advertisement is a payload count: 251 on air minus MIC.
        assert_eq!(rsp.max_rx_octets, 247);
        assert_eq!(rsp.max_tx_octets, 247);
        assert_eq!(dle.tx_payload(), 247);
        assert_eq!(dle.rx_payload(), 247);
        assert_eq!(dle.tx_octets(false), 247);
        assert_eq!(dle.tx_octets(true), 251);
        assert_eq!(dle.rx_octets(false), 247);
        assert_eq!(dle.rx_octets(true), 251);
        assert_eq!(dle.tx_plaintext(), 247);
    }

    #[test]
    fn encrypted_peer_payload_keeps_its_mic_on_air() {
        // An Android Central that declared 128 payload octets sends 132
        // octets on air once the link is encrypted.
        let mut dle = DataLength::new();
        dle.on_peer_length(LengthParams {
            max_rx_octets: 251,
            max_rx_time: 2120,
            max_tx_octets: 128,
            max_tx_time: 1120,
        });
        assert_eq!(dle.rx_payload(), 128);
        assert_eq!(dle.rx_octets(true), 132);
        assert_eq!(dle.rx_octets(false), 128);
        assert_eq!(dle.tx_octets(true), 251);
    }

    #[test]
    fn effective_limits_take_the_smaller_side() {
        let mut dle = DataLength::new();
        dle.set_local_tx(251, 2120);
        dle.on_peer_length(LengthParams {
            max_rx_octets: 65,
            max_rx_time: 848,
            max_tx_octets: 100,
            max_tx_time: 1120,
        });
        assert_eq!(dle.tx_octets(false), 65);
        assert_eq!(dle.rx_octets(false), 100);
        assert_eq!(dle.tx_time_us(), 848);
        assert_eq!(dle.rx_time_us(), 1120);
        // `LE Set Data Length` is a TX-only preference: it must not shrink
        // the receive limit the peer already negotiated.
        dle.set_local_tx(27, 328);
        assert_eq!(dle.tx_octets(false), 27);
        assert_eq!(dle.rx_octets(false), 100);
        assert_eq!(dle.tx_time_us(), 328);
        assert_eq!(dle.rx_time_us(), 1120);
        assert_eq!(dle.local_params().max_rx_octets, 247);
        assert_eq!(dle.local_params().max_tx_octets, 27);
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
