//! Pure legacy LE 1M peripheral connection timing and channel selection.

/// Connection handle / timing placeholders retained for the HCI scaffold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnState {
    pub handle: Option<u16>,
    pub interval_slots: u16,
    pub latency: u16,
    pub timeout_slots: u16,
}

impl Default for ConnState {
    fn default() -> Self {
        Self {
            handle: None,
            interval_slots: 24,
            latency: 0,
            timeout_slots: 200,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnError {
    Crc,
    Length,
    Header,
    Address,
    AccessAddress,
    ChannelMap,
    Parameters,
    InstantPassed,
    ProcedureCollision,
}

/// CONNECT_IND parameters. Time units are 1.25 ms, except timeout (10 ms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectParams {
    pub peer_addr: [u8; 6],
    pub peer_random: bool,
    pub access_addr: u32,
    pub crc_init: u32,
    pub win_size: u8,
    pub win_offset: u16,
    pub interval: u16,
    pub latency: u16,
    pub timeout: u16,
    pub channel_map: [u8; 5],
    pub hop: u8,
    pub sca: u8,
}

impl ConnectParams {
    /// Parse a complete advertising PDU (two header bytes, 34 payload bytes,
    /// no CRC). This peripheral advertises ChSel=0 and supports only CSA #1.
    /// RFU header bits are ignored. A CSA #2-capable initiator is allowed to
    /// send ChSel=1 even though our ADV_IND had ChSel=0 (Core 5.4, 2.3.3.1);
    /// selection still remains CSA #1 for this advertiser.
    pub fn parse(
        pdu: &[u8],
        crc_ok: bool,
        own_addr: [u8; 6],
        random_addr: bool,
    ) -> Result<Self, ConnError> {
        if !crc_ok {
            return Err(ConnError::Crc);
        }
        if pdu.len() != 36 {
            return Err(ConnError::Length);
        }
        if pdu[1] != 34 || pdu[0] & 0x0f != 0x05 {
            return Err(ConnError::Header);
        }
        if pdu[8..14] != own_addr || (pdu[0] & 0x80 != 0) != random_addr {
            return Err(ConnError::Address);
        }
        let mut peer_addr = [0; 6];
        peer_addr.copy_from_slice(&pdu[2..8]);
        let mut channel_map = [0; 5];
        channel_map.copy_from_slice(&pdu[30..35]);
        channel_map[4] &= 0x1f; // Bits 37..39 are RFU on the wire.
        let params = Self {
            peer_addr,
            peer_random: pdu[0] & 0x40 != 0,
            access_addr: u32::from_le_bytes(pdu[14..18].try_into().unwrap()),
            crc_init: u32::from_le_bytes([pdu[18], pdu[19], pdu[20], 0]),
            win_size: pdu[21],
            win_offset: le16(&pdu[22..]),
            interval: le16(&pdu[24..]),
            latency: le16(&pdu[26..]),
            timeout: le16(&pdu[28..]),
            channel_map,
            hop: pdu[35] & 0x1f,
            sca: pdu[35] >> 5,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn validate(&self) -> Result<(), ConnError> {
        if !valid_access_address(self.access_addr) {
            return Err(ConnError::AccessAddress);
        }
        validate_channel_map(self.channel_map)?;
        validate_timing(
            self.win_size,
            self.win_offset,
            self.interval,
            self.latency,
            self.timeout,
        )?;
        if !(5..=16).contains(&self.hop) || self.sca > 7 || self.crc_init > 0xff_ffff {
            return Err(ConnError::Parameters);
        }
        Ok(())
    }

    /// Build a complete legacy CONNECT_IND PDU: two header bytes plus 34
    /// payload bytes, without access address or CRC.
    ///
    /// `init_addr`/`init_random` are the initiator address (InitA) and its
    /// TxAdd; `self.peer_addr`/`self.peer_random` are the advertiser address
    /// (AdvA) and its TxAdd, which becomes RxAdd on the wire. The caller owns
    /// the access address and CRC configuration for transmission.
    pub fn build_connect_ind(
        &self,
        out: &mut [u8],
        init_addr: [u8; 6],
        init_random: bool,
    ) -> Option<usize> {
        const LEN: usize = 36;
        if out.len() < LEN {
            return None;
        }
        self.validate().ok()?;
        // The transmit window must fit inside the first connection interval.
        if u32::from(self.win_offset) + u32::from(self.win_size) > u32::from(self.interval) {
            return None;
        }
        out[0] = 0x05
            | if init_random { 0x40 } else { 0 }
            | if self.peer_random { 0x80 } else { 0 };
        out[1] = 34;
        out[2..8].copy_from_slice(&init_addr);
        out[8..14].copy_from_slice(&self.peer_addr);
        out[14..18].copy_from_slice(&self.access_addr.to_le_bytes());
        out[18..21].copy_from_slice(&self.crc_init.to_le_bytes()[..3]);
        out[21] = self.win_size;
        out[22..24].copy_from_slice(&self.win_offset.to_le_bytes());
        out[24..26].copy_from_slice(&self.interval.to_le_bytes());
        out[26..28].copy_from_slice(&self.latency.to_le_bytes());
        out[28..30].copy_from_slice(&self.timeout.to_le_bytes());
        out[30..35].copy_from_slice(&self.channel_map);
        out[35] = self.hop | (self.sca << 5);
        Some(LEN)
    }
}

/// Timing hooks shared by peripheral and central link objects. `ControlState`
/// uses them to defer channel-map and connection-parameter changes to an
/// instant without knowing which role owns the link.
pub trait LinkTiming {
    fn event_counter(&self) -> u16;
    fn schedule_channel_map(&mut self, map: [u8; 5], instant: u16) -> Result<(), ConnError>;
    fn schedule_update(&mut self, update: ConnectionUpdate) -> Result<(), ConnError>;
}

pub(crate) fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

/// Core 5.4, Vol 6, Part B, 2.1.2: uncoded LE 1M data access address.
/// The extra constraints for LE Coded PHY are deliberately not applied.
pub fn valid_access_address(aa: u32) -> bool {
    if (aa ^ 0x8e89_bed6).count_ones() <= 1 {
        return false;
    }
    let bytes = aa.to_le_bytes();
    if bytes.iter().all(|b| *b == bytes[0]) {
        return false;
    }
    let mut transitions = 0;
    let mut upper_transitions = 0;
    let mut run = 1;
    for bit in 1..32 {
        if (aa >> bit) & 1 == (aa >> (bit - 1)) & 1 {
            run += 1;
            if run > 6 {
                return false;
            }
        } else {
            run = 1;
            transitions += 1;
            if bit >= 27 {
                upper_transitions += 1;
            }
        }
    }
    transitions <= 24 && upper_transitions >= 2
}

pub fn validate_channel_map(map: [u8; 5]) -> Result<(), ConnError> {
    if map[4] & 0xe0 != 0 || map.iter().map(|b| b.count_ones()).sum::<u32>() < 2 {
        Err(ConnError::ChannelMap)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_timing(
    win_size: u8,
    win_offset: u16,
    interval: u16,
    latency: u16,
    timeout: u16,
) -> Result<(), ConnError> {
    // The transmit window is at most 10 ms and less than one interval.
    if !(6..=3200).contains(&interval)
        || latency > 499
        || !(10..=3200).contains(&timeout)
        || win_size == 0
        || u16::from(win_size) > 8.min(interval.saturating_sub(1))
        || win_offset > interval
        || u32::from(timeout) * 10_000 <= (u32::from(latency) + 1) * u32::from(interval) * 2500
    {
        Err(ConnError::Parameters)
    } else {
        Ok(())
    }
}

/// CSA #1. The first event advances from unmapped channel zero by `hop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Csa1 {
    map: [u8; 5],
    hop: u8,
    unmapped: u8,
}

impl Csa1 {
    pub fn new(map: [u8; 5], hop: u8) -> Result<Self, ConnError> {
        validate_channel_map(map)?;
        if !(5..=16).contains(&hop) {
            return Err(ConnError::Parameters);
        }
        Ok(Self {
            map,
            hop,
            unmapped: 0,
        })
    }

    pub fn set_map(&mut self, map: [u8; 5]) -> Result<(), ConnError> {
        validate_channel_map(map)?;
        self.map = map;
        Ok(())
    }

    /// Call once for every connection event, including missed events.
    pub fn next_channel(&mut self) -> u8 {
        self.unmapped = (self.unmapped + self.hop) % 37;
        if self.map[usize::from(self.unmapped / 8)] & (1 << (self.unmapped % 8)) != 0 {
            return self.unmapped;
        }
        let used = self.map.iter().map(|b| b.count_ones()).sum::<u32>() as u8;
        let mut index = self.unmapped % used;
        for channel in 0..37 {
            if self.map[usize::from(channel / 8)] & (1 << (channel % 8)) != 0 {
                if index == 0 {
                    return channel;
                }
                index -= 1;
            }
        }
        unreachable!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionUpdate {
    pub win_size: u8,
    pub win_offset: u16,
    pub interval: u16,
    pub latency: u16,
    pub timeout: u16,
    pub instant: u16,
}

impl ConnectionUpdate {
    pub fn validate(&self) -> Result<(), ConnError> {
        validate_timing(
            self.win_size,
            self.win_offset,
            self.interval,
            self.latency,
            self.timeout,
        )
    }
}

/// `now` is at or after `deadline`, for distances below 2^31 microseconds.
pub fn time_reached(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) as i32 >= 0
}

pub fn validate_instant(current: u16, instant: u16) -> Result<(), ConnError> {
    let distance = instant.wrapping_sub(current);
    if distance == 0 || distance >= 0x8000 {
        Err(ConnError::InstantPassed)
    } else {
        Ok(())
    }
}

/// One peripheral link, independent of radio registers and packet buffers.
/// All timestamps are wrapping microseconds. Call `next_event` even on a miss.
#[derive(Debug, Clone)]
pub struct PeripheralConnection {
    pub params: ConnectParams,
    csa: Csa1,
    channel: u8,
    event_counter: u16,
    event_start_us: u32,
    window_width_us: u32,
    supervision_base_us: u32,
    last_anchor_us: u32,
    anchor_seen: bool,
    established: bool,
    pending_map: Option<(u16, [u8; 5])>,
    pending_update: Option<ConnectionUpdate>,
}

impl PeripheralConnection {
    /// `params` must have passed `parse` or `validate`.
    pub fn new(params: ConnectParams, connect_end_us: u32) -> Self {
        let mut csa = Csa1::new(params.channel_map, params.hop).expect("validated CONNECT_IND");
        let channel = csa.next_channel();
        Self {
            params,
            csa,
            channel,
            event_counter: 0,
            event_start_us: connect_end_us.wrapping_add(1250 + u32::from(params.win_offset) * 1250),
            window_width_us: u32::from(params.win_size) * 1250,
            supervision_base_us: connect_end_us,
            last_anchor_us: connect_end_us,
            anchor_seen: false,
            established: false,
            pending_map: None,
            pending_update: None,
        }
    }

    pub fn channel(&self) -> u8 {
        self.channel
    }
    pub fn event_counter(&self) -> u16 {
        self.event_counter
    }
    pub fn established(&self) -> bool {
        self.established
    }

    /// Predicted window left edge, not a measured anchor before reception.
    pub fn event_start_us(&self) -> u32 {
        self.event_start_us
    }

    fn widening_us(&self) -> u32 {
        const CENTRAL_PPM: [u32; 8] = [500, 250, 150, 100, 75, 50, 30, 20];
        // Conservative local clock accuracy: 500 ppm. Include timestamp jitter.
        let elapsed = self.event_start_us.wrapping_sub(self.last_anchor_us);
        let ppm = 500 + CENTRAL_PPM[usize::from(self.params.sca)];
        let widening = ((u64::from(elapsed) * u64::from(ppm)).div_ceil(1_000_000)) as u32;
        (widening + 16).min(u32::from(self.params.interval) * 625 - 150)
    }

    pub fn rx_start_us(&self) -> u32 {
        self.event_start_us.wrapping_sub(self.widening_us())
    }

    /// End of the possible packet-start window. The radio must allow a packet
    /// starting before this deadline to finish (up to 328 us for a 31-octet
    /// encrypted legacy payload).
    pub fn rx_end_us(&self) -> u32 {
        self.event_start_us
            .wrapping_add(self.window_width_us + self.widening_us())
    }

    /// Allow the latest-starting legacy LE 1M packet to finish: 80 us overhead
    /// plus the largest on-air payload (31 octets with the 4-octet MIC).
    /// Address match cannot occur before the 40 us preamble/AA reception; its
    /// exact hardware flag latency is not assumed.
    /// Use this for the initial hardware window and software no-capture timeout,
    /// while still honoring earlier finite, supervision and event deadlines.
    pub fn rx_complete_end_us(&self) -> u32 {
        self.rx_end_us()
            .wrapping_add(80 + super::enc::MAX_ENCRYPTED as u32 * 8)
    }

    /// Until the first valid data PDU, establishment is bounded by six
    /// connection intervals. Afterwards use the negotiated supervision timer.
    pub fn supervision_deadline_us(&self) -> u32 {
        let timeout_us = if self.established {
            u32::from(self.params.timeout) * 10_000
        } else {
            u32::from(self.params.interval) * 1250 * 6
        };
        self.supervision_base_us.wrapping_add(timeout_us)
    }

    pub fn supervision_expired(&self, now_us: u32) -> bool {
        time_reached(now_us, self.supervision_deadline_us())
    }

    /// Call only for a valid, CRC-correct data-channel packet. `rx_done_us`
    /// must denote the on-air end, with backend interrupt latency removed.
    /// A later packet in the same event refreshes supervision, not the anchor.
    /// Returns false for an invalid length or a link that already expired.
    pub fn on_rx_anchor(&mut self, rx_done_us: u32, payload_len: u8) -> bool {
        if usize::from(payload_len) > super::enc::MAX_ENCRYPTED
            || self.supervision_expired(rx_done_us)
        {
            return false;
        }
        self.supervision_base_us = rx_done_us;
        self.established = true;
        if !self.anchor_seen {
            // Preamble + AA + header + payload + CRC on LE 1M.
            let anchor = rx_done_us.wrapping_sub(80 + u32::from(payload_len) * 8);
            self.event_start_us = anchor;
            self.last_anchor_us = anchor;
            self.window_width_us = 0;
            self.anchor_seen = true;
        }
        true
    }

    pub fn schedule_channel_map(&mut self, map: [u8; 5], instant: u16) -> Result<(), ConnError> {
        validate_channel_map(map)?;
        validate_instant(self.event_counter, instant)?;
        if self.pending_map.is_some() {
            return Err(ConnError::ProcedureCollision);
        }
        self.pending_map = Some((instant, map));
        Ok(())
    }

    pub fn schedule_update(&mut self, update: ConnectionUpdate) -> Result<(), ConnError> {
        update.validate()?;
        validate_instant(self.event_counter, update.instant)?;
        if self.pending_update.is_some() {
            return Err(ConnError::ProcedureCollision);
        }
        self.pending_update = Some(update);
        Ok(())
    }

    pub fn next_event(&mut self) -> Result<(), ConnError> {
        self.event_start_us = self
            .event_start_us
            .wrapping_add(u32::from(self.params.interval) * 1250);
        self.event_counter = self.event_counter.wrapping_add(1);
        self.anchor_seen = false;
        if let Some((instant, map)) = self.pending_map {
            if instant == self.event_counter {
                self.csa.set_map(map)?;
                self.params.channel_map = map;
                self.pending_map = None;
            }
        }
        if let Some(update) = self.pending_update {
            if update.instant == self.event_counter {
                let old_deadline = self.supervision_deadline_us();
                // Offset is relative to this event's anchor on the old schedule.
                self.event_start_us = self
                    .event_start_us
                    .wrapping_add(u32::from(update.win_offset) * 1250);
                self.window_width_us = u32::from(update.win_size) * 1250;
                self.params.win_size = update.win_size;
                self.params.win_offset = update.win_offset;
                self.params.interval = update.interval;
                self.params.latency = update.latency;
                self.params.timeout = update.timeout;
                // Restart at the update window only if the old link can live
                // until then. next_event plans ahead: a future instant must not
                // erase a supervision deadline occurring during the wait.
                self.supervision_base_us = if time_reached(self.event_start_us, old_deadline) {
                    old_deadline.wrapping_sub(u32::from(self.params.timeout) * 10_000)
                } else {
                    self.event_start_us
                };
                self.pending_update = None;
            }
        }
        self.channel = self.csa.next_channel();
        Ok(())
    }
}

impl LinkTiming for PeripheralConnection {
    fn event_counter(&self) -> u16 {
        self.event_counter
    }

    fn schedule_channel_map(&mut self, map: [u8; 5], instant: u16) -> Result<(), ConnError> {
        PeripheralConnection::schedule_channel_map(self, map, instant)
    }

    fn schedule_update(&mut self, update: ConnectionUpdate) -> Result<(), ConnError> {
        PeripheralConnection::schedule_update(self, update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn connect_pdu() -> [u8; 36] {
        let mut pdu = [0; 36];
        pdu[0] = 0x85;
        pdu[1] = 34;
        pdu[2..8].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        pdu[8..14].copy_from_slice(&[0xc0; 6]);
        pdu[14..18].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        pdu[18..21].copy_from_slice(&[0x55, 0x55, 0x55]);
        pdu[21] = 2;
        pdu[24..26].copy_from_slice(&24u16.to_le_bytes());
        pdu[28..30].copy_from_slice(&200u16.to_le_bytes());
        pdu[30..35].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x1f]);
        pdu[35] = 5;
        pdu
    }

    fn params() -> ConnectParams {
        ConnectParams::parse(&connect_pdu(), true, [0xc0; 6], true).unwrap()
    }

    #[test]
    fn connect_ind_builder_round_trips_all_address_types() {
        for peer_random in [false, true] {
            for init_random in [false, true] {
                let mut expected = params();
                expected.peer_random = peer_random;
                expected.win_size = 2;
                expected.win_offset = 3;
                let init_addr = [9, 8, 7, 6, 5, 4];
                let mut out = [0xaa; 36];
                assert_eq!(
                    expected.build_connect_ind(&mut out, init_addr, init_random),
                    Some(36)
                );
                assert_eq!(out[0] & 0x40 != 0, init_random);
                assert_eq!(out[0] & 0x80 != 0, peer_random);
                assert_eq!(&out[2..8], &init_addr);
                // From the advertiser's perspective, parse sees InitA as the
                // peer; every other field must round-trip unchanged.
                let parsed =
                    ConnectParams::parse(&out, true, expected.peer_addr, peer_random).unwrap();
                assert_eq!(parsed.peer_addr, init_addr);
                assert_eq!(parsed.peer_random, init_random);
                let mut expected_peer_view = expected;
                expected_peer_view.peer_addr = init_addr;
                expected_peer_view.peer_random = init_random;
                assert_eq!(parsed, expected_peer_view);
            }
        }
    }

    #[test]
    fn connect_ind_builder_rejects_short_buffers_and_window_overflow() {
        let params = params();
        let mut short = [0x5a; 35];
        assert_eq!(
            params.build_connect_ind(&mut short, [0; 6], false),
            None
        );
        assert!(short.iter().all(|byte| *byte == 0x5a));

        let mut overflow = params;
        overflow.win_size = 8;
        overflow.win_offset = 20; // 20 + 8 exceeds the 24-slot interval.
        let mut out = [0; 36];
        assert_eq!(overflow.build_connect_ind(&mut out, [0; 6], false), None);
    }

    #[test]
    fn hse_rate_keeps_the_next_anchor_in_the_declared_window() {
        use crate::time::TickRate;

        // A 62.4 MHz HSE/PLL counter: anchor at 10 ms, then a 30 ms interval.
        // No oscillator drift or IRQ latency is needed to reproduce the error
        // from substituting an RC-referenced rate for the crystal clock.
        for (hz, inside_window) in [(62_400_000, true), (62_509_688, false)] {
            let rate = TickRate::new(hz).unwrap();
            let mut conn = PeripheralConnection::new(params(), 0);
            let first_anchor_ticks = 624_000;
            let empty_airtime_ticks = 4_992;
            assert!(conn.on_rx_anchor(rate.micros(first_anchor_ticks + empty_airtime_ticks), 0));
            conn.next_event().unwrap();
            let next_anchor = rate.micros(first_anchor_ticks + 1_872_000);
            let inside = time_reached(next_anchor, conn.rx_start_us())
                && time_reached(conn.rx_end_us(), next_anchor);
            assert_eq!(inside, inside_window, "rate={hz}");
            if !inside {
                assert!(!time_reached(next_anchor, conn.rx_start_us()));
            }
        }
    }

    #[test]
    fn latest_starting_packet_can_match_and_complete_across_time_wrap() {
        for origin in [0u32, u32::MAX - 5_000] {
            let mut p = params();
            p.sca = 1;
            let mut conn = PeripheralConnection::new(p, origin);
            let anchor = origin.wrapping_add(2_500);
            assert!(conn.on_rx_anchor(anchor.wrapping_add(80), 0));
            conn.next_event().unwrap();
            let latest = conn.rx_end_us();
            for start in [latest.wrapping_sub(1), latest] {
                let address_match = start.wrapping_add(40);
                let full_packet = start.wrapping_add(80 + 27 * 8);
                assert!(time_reached(address_match, latest));
                assert!(time_reached(conn.rx_complete_end_us(), address_match));
                assert!(time_reached(conn.rx_complete_end_us(), full_packet));
            }
            // Completion allowance must not revive an expired link.
            assert!(!conn.on_rx_anchor(conn.supervision_deadline_us(), 27));
        }
    }

    #[test]
    fn receive_ceiling_covers_the_encrypted_legacy_payload() {
        // 27 plaintext octets plus the 4-octet MIC is the largest legacy PDU.
        let mut conn = PeripheralConnection::new(params(), 0);
        assert!(conn.on_rx_anchor(2_500, 31));
        assert_eq!(conn.event_start_us(), 2_500 - (80 + 31 * 8));
        let mut conn = PeripheralConnection::new(params(), 0);
        assert!(!conn.on_rx_anchor(2_500, 32));
    }

    #[test]
    fn packet_start_cutoff_reproduces_alternating_misses_but_completion_does_not() {
        for completion_allowance in [false, true] {
            let mut p = params();
            p.sca = 1;
            let mut conn = PeripheralConnection::new(p, 0);
            let first_anchor = 2_500u32;
            assert!(conn.on_rx_anchor(first_anchor + 80, 0));
            for event in 1..=8 {
                conn.next_event().unwrap();
                let anchor = first_anchor + event * 30_000;
                let cutoff = if completion_allowance {
                    conn.rx_complete_end_us()
                } else {
                    conn.rx_end_us()
                };
                let captured = time_reached(cutoff, anchor + 40);
                assert_eq!(captured, completion_allowance || event % 2 == 0);
                if captured {
                    assert!(conn.on_rx_anchor(anchor + 80, 0));
                }
            }
        }
    }

    #[test]
    fn parse_addresses_and_crc_init_zero() {
        let mut pdu = connect_pdu();
        pdu[18..21].fill(0);
        let p = ConnectParams::parse(&pdu, true, [0xc0; 6], true).unwrap();
        assert_eq!(p.crc_init, 0);
        assert_eq!(p.peer_addr, [1, 2, 3, 4, 5, 6]);
        assert!(!p.peer_random);
        assert_eq!(p.interval, 24);
        assert_eq!(
            ConnectParams::parse(&pdu, true, [0xc0; 6], false),
            Err(ConnError::Address)
        );
        assert_eq!(
            ConnectParams::parse(&pdu, true, [0xc1; 6], true),
            Err(ConnError::Address)
        );
        assert_eq!(
            ConnectParams::parse(&pdu, false, [0xc0; 6], true),
            Err(ConnError::Crc)
        );
    }

    #[test]
    fn parser_ignores_rfu_and_initiator_chsel_when_advertiser_uses_csa1() {
        for bits in [0, 0x10, 0x20, 0x30] {
            let mut pdu = connect_pdu();
            pdu[0] |= bits;
            let p = ConnectParams::parse(&pdu, true, [0xc0; 6], true).unwrap();
            let c = PeripheralConnection::new(p, 0);
            assert_eq!(c.channel(), 5);
        }
    }

    #[test]
    fn received_map_rfu_bits_do_not_count_as_channels() {
        let mut pdu = connect_pdu();
        pdu[30..35].copy_from_slice(&[3, 0, 0, 0, 0xe0]);
        let p = ConnectParams::parse(&pdu, true, [0xc0; 6], true).unwrap();
        assert_eq!(p.channel_map, [3, 0, 0, 0, 0]);
        for low_bits in [0, 1] {
            pdu[30] = low_bits;
            assert_eq!(
                ConnectParams::parse(&pdu, true, [0xc0; 6], true),
                Err(ConnError::ChannelMap)
            );
        }
    }

    #[test]
    fn parser_rejects_truncation_headers_and_invalid_fields() {
        let pdu = connect_pdu();
        for len in 0..36 {
            assert_eq!(
                ConnectParams::parse(&pdu[..len], true, [0xc0; 6], true),
                Err(ConnError::Length)
            );
        }
        let mut long = [0; 37];
        long[..36].copy_from_slice(&pdu);
        assert_eq!(
            ConnectParams::parse(&long, true, [0xc0; 6], true),
            Err(ConnError::Length)
        );
        for (index, value) in [
            (0, 0x84),
            (0, 0x86),
            (1, 33),
            (21, 0),
            (21, 9),
            (24, 5),
            (35, 4),
            (35, 17),
        ] {
            let mut bad = pdu;
            bad[index] = value;
            assert!(
                ConnectParams::parse(&bad, true, [0xc0; 6], true).is_err(),
                "index={index} value={value}"
            );
        }
    }

    #[test]
    fn timing_boundaries_and_timeout_strict_inequality() {
        assert_eq!(validate_timing(5, 6, 6, 0, 10), Ok(()));
        assert!(validate_timing(6, 0, 6, 0, 10).is_err());
        assert_eq!(validate_timing(8, 3200, 3200, 0, 3200), Ok(()));
        assert!(validate_timing(1, 25, 24, 0, 200).is_err());
        assert!(validate_timing(1, 0, 24, 500, 3200).is_err());
        assert!(validate_timing(1, 0, 24, 0, 9).is_err());
        assert!(validate_timing(1, 0, 24, 0, 3201).is_err());
        assert!(validate_timing(1, 0, 40, 0, 10).is_err());
        assert_eq!(validate_timing(1, 0, 40, 0, 11), Ok(()));
        assert!(validate_timing(1, 0, 3200, 499, 3200).is_err());
    }

    #[test]
    fn access_address_le1m_constraints() {
        assert!(valid_access_address(0x1234_5678));
        assert!(valid_access_address(0x1234_1234)); // Repeated halves are not repeated bytes.
        for aa in [
            0,
            u32::MAX,
            0x8e89_bed6,
            0xaaaa_aaaa,
            0x1212_1212,
            0x0102_0304,
            0x3fff_5678,
        ] {
            assert!(!valid_access_address(aa), "aa={aa:08x}");
        }
        for bit in 0..32 {
            assert!(!valid_access_address(0x8e89_bed6 ^ (1 << bit)));
        }
    }

    #[test]
    fn csa1_first_hop_modulo_and_sparse_remap() {
        let mut all = Csa1::new([0xff, 0xff, 0xff, 0xff, 0x1f], 5).unwrap();
        for index in 1..=74 {
            assert_eq!(all.next_channel(), (index * 5 % 37) as u8);
        }
        let mut sparse = Csa1::new([1, 0, 0, 0, 0x10], 5).unwrap();
        assert_eq!(sparse.next_channel(), 36); // 5 % 2 = 1 -> channel 36.
        assert_eq!(sparse.next_channel(), 0);
        assert!(Csa1::new([1, 0, 0, 0, 0], 5).is_err());
        assert!(Csa1::new([3, 0, 0, 0, 0x20], 5).is_err());
    }

    #[test]
    fn first_window_anchor_and_missed_events() {
        let mut p = params();
        p.win_offset = 3;
        let mut c = PeripheralConnection::new(p, 1000);
        assert_eq!(c.event_start_us(), 6000);
        assert!(c.rx_start_us() < 6000);
        assert!(c.rx_end_us() >= 8500);
        assert!(!c.established());
        c.on_rx_anchor(7000 + 80, 0);
        assert_eq!(c.event_start_us(), 7000);
        assert!(c.established());
        c.on_rx_anchor(8000 + 80, 0);
        assert_eq!(c.event_start_us(), 7000); // Second packet is not an anchor.
        c.next_event().unwrap();
        assert_eq!(c.event_start_us(), 37_000);
        assert_eq!(c.channel(), 10);
        let width = c.rx_end_us().wrapping_sub(c.rx_start_us());
        c.next_event().unwrap(); // No RX: CSA and time still advance, widening grows.
        assert_eq!(c.channel(), 15);
        assert!(c.rx_end_us().wrapping_sub(c.rx_start_us()) > width);
    }

    #[test]
    fn supervision_and_time_wrap() {
        let start = u32::MAX - 2000;
        let mut c = PeripheralConnection::new(params(), start);
        assert!(!c.supervision_expired(start.wrapping_add(179_999)));
        assert!(c.supervision_expired(start.wrapping_add(180_000)));
        c.on_rx_anchor(start.wrapping_add(5000), 27);
        assert_eq!(c.event_start_us(), start.wrapping_add(5000 - 296));
        assert!(!c.supervision_expired(start.wrapping_add(2_004_999)));
        assert!(c.supervision_expired(start.wrapping_add(2_005_000)));
        c.next_event().unwrap();
        assert_eq!(c.event_start_us(), start.wrapping_add(5000 - 296 + 30_000));
    }

    #[test]
    fn update_restarts_supervision_at_new_window() {
        let mut c = PeripheralConnection::new(params(), 0);
        c.on_rx_anchor(1330, 0);
        c.schedule_update(ConnectionUpdate {
            win_size: 1,
            win_offset: 1,
            interval: 24,
            latency: 0,
            timeout: 10,
            instant: 3,
        })
        .unwrap();
        for _ in 0..3 {
            c.next_event().unwrap();
        }
        let instant_us = c.event_start_us();
        assert_eq!(instant_us, 92_500);
        assert!(!c.supervision_expired(instant_us + 99_999));
        assert!(c.supervision_expired(instant_us + 100_000));
    }

    #[test]
    fn a_late_packet_cannot_revive_supervision_after_event_wait() {
        let mut p = params();
        p.timeout = 10;
        let mut c = PeripheralConnection::new(p, 0);
        assert!(c.on_rx_anchor(1330, 0));
        assert_eq!(c.supervision_deadline_us(), 101_330);
        for _ in 0..4 {
            c.next_event().unwrap();
        }
        assert!(c.supervision_expired(121_330));
        assert!(!c.on_rx_anchor(121_330, 0));
        assert_eq!(c.supervision_deadline_us(), 101_330);
    }

    #[test]
    fn planning_an_update_instant_cannot_hide_an_earlier_timeout() {
        let mut p = params();
        p.timeout = 10;
        let mut c = PeripheralConnection::new(p, 0);
        assert!(c.on_rx_anchor(1330, 0));
        c.schedule_update(ConnectionUpdate {
            win_size: 1,
            win_offset: 0,
            interval: 24,
            latency: 0,
            timeout: 20,
            instant: 6,
        })
        .unwrap();
        for end in [31_330, 61_330] {
            c.next_event().unwrap();
            assert!(c.on_rx_anchor(end, 0));
        }
        for _ in 0..4 {
            c.next_event().unwrap();
        }
        assert_eq!(c.event_counter(), 6);
        assert_eq!(c.event_start_us(), 181_250);
        assert_eq!(c.supervision_deadline_us(), 161_330);
        assert!(!c.supervision_expired(151_330));
        assert!(c.supervision_expired(161_330));
        assert!(!c.on_rx_anchor(181_330, 0));
    }

    #[test]
    fn map_and_connection_update_at_wrapping_instant() {
        let mut c = PeripheralConnection::new(params(), 0);
        c.event_counter = 0xfffe;
        assert_eq!(validate_instant(0xfffe, 1), Ok(()));
        assert_eq!(validate_instant(1, 0xfffe), Err(ConnError::InstantPassed));
        assert_eq!(validate_instant(1, 1), Err(ConnError::InstantPassed));
        c.schedule_channel_map([1, 0, 0, 0, 0x10], 0).unwrap();
        let update = ConnectionUpdate {
            win_size: 1,
            win_offset: 2,
            interval: 40,
            latency: 0,
            timeout: 200,
            instant: 0,
        };
        c.schedule_update(update).unwrap();
        assert_eq!(
            c.schedule_update(update),
            Err(ConnError::ProcedureCollision)
        );
        c.next_event().unwrap();
        assert_eq!(c.event_counter(), 0xffff);
        assert_eq!(c.channel(), 10);
        c.next_event().unwrap();
        assert_eq!(c.event_counter(), 0);
        assert_eq!(c.channel(), 36);
        assert_eq!(c.event_start_us(), 1250 + 60_000 + 2500);
        assert_eq!(c.params.interval, 40);
        c.next_event().unwrap();
        assert_eq!(c.event_start_us(), 1250 + 60_000 + 2500 + 50_000);
    }
}
