//! Pure legacy LE 1M central connection timing and channel selection.
//!
//! The central owns the connection schedule: it transmits the first packet of
//! every event at `event_start_us` and then listens for the peer. Unlike the
//! peripheral object, a received packet never moves the anchor; it only
//! refreshes supervision and establishes the link.

use super::acl::MAX_LEGACY_PAYLOAD;
use super::conn::{
    time_reached, validate_instant, ChannelSelection, ChannelSelectionAlgorithm, ConnError,
    ConnectParams, ConnectionUpdate, LinkTiming,
};

/// One central link, independent of radio registers and packet buffers.
/// All timestamps are wrapping microseconds. Call `next_event` for every
/// interval, including missed events.
#[derive(Debug, Clone)]
pub struct CentralConnection {
    pub params: ConnectParams,
    csa: ChannelSelection,
    channel: u8,
    event_counter: u16,
    event_start_us: u32,
    connect_end_us: u32,
    supervision_base_us: u32,
    established: bool,
    pending_map: Option<(u16, [u8; 5])>,
    pending_update: Option<ConnectionUpdate>,
}

impl CentralConnection {
    /// `params` must have passed `validate`. `connect_ind_end_us` is the
    /// software estimate of the CONNECT_IND on-air end; the first event starts
    /// at `connect_ind_end_us + 1.25 ms + WinOffset * 1.25 ms`.
    pub fn new(params: ConnectParams, connect_ind_end_us: u32) -> Self {
        // `params.chsel` was already gated on the peer ADV's ChSel when the
        // CONNECT_IND was built, so it alone decides the algorithm here.
        let algorithm = if params.chsel {
            ChannelSelectionAlgorithm::Csa2
        } else {
            ChannelSelectionAlgorithm::Csa1
        };
        let mut csa = ChannelSelection::new(
            algorithm,
            params.channel_map,
            params.access_addr,
            params.hop,
        )
        .expect("validated CONNECT_IND");
        let channel = csa.next_channel(0);
        Self {
            params,
            csa,
            channel,
            event_counter: 0,
            event_start_us: connect_ind_end_us
                .wrapping_add(1250 + u32::from(params.win_offset) * 1250),
            connect_end_us: connect_ind_end_us,
            supervision_base_us: connect_ind_end_us,
            established: false,
            pending_map: None,
            pending_update: None,
        }
    }

    /// Shift the whole schedule by a fixed offset. The example uses half the
    /// first receive window during bring-up so that CONNECT_IND-end estimate
    /// error stays inside the peer's window; subsequent events inherit it.
    pub fn with_first_event_bias_us(mut self, bias_us: u32) -> Self {
        self.event_start_us = self.event_start_us.wrapping_add(bias_us);
        self
    }

    pub fn channel(&self) -> u8 {
        self.channel
    }

    pub fn channel_selection_algorithm(&self) -> ChannelSelectionAlgorithm {
        self.csa.algorithm()
    }

    pub fn event_counter(&self) -> u16 {
        self.event_counter
    }

    pub fn established(&self) -> bool {
        self.established
    }

    /// Software schedule for the next first-packet transmit. This is not an
    /// on-air measurement and must not be used as an IFS claim.
    pub fn event_start_us(&self) -> u32 {
        self.event_start_us
    }

    pub fn connect_end_us(&self) -> u32 {
        self.connect_end_us
    }

    /// Until the first valid peer packet, establishment is bounded by six
    /// connection intervals. Afterwards the negotiated supervision timer runs
    /// from the last valid reception.
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

    /// Call only for a CRC-correct data-channel packet. Returns false when the
    /// packet cannot establish or refresh the link. The anchor is deliberately
    /// unchanged; the central's own schedule defines it.
    pub fn on_rx(&mut self, rx_done_us: u32, payload_len: u8, crc_ok: bool) -> bool {
        if !crc_ok
            || usize::from(payload_len) > MAX_LEGACY_PAYLOAD
            || self.supervision_expired(rx_done_us)
        {
            return false;
        }
        self.supervision_base_us = rx_done_us;
        self.established = true;
        true
    }

    pub fn schedule_channel_map(&mut self, map: [u8; 5], instant: u16) -> Result<(), ConnError> {
        super::conn::validate_channel_map(map)?;
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
        if let Some((instant, map)) = self.pending_map {
            if instant == self.event_counter {
                self.csa.set_map(map)?;
                self.params.channel_map = map;
                self.pending_map = None;
            }
        }
        if let Some(update) = self.pending_update {
            if update.instant == self.event_counter {
                // WinOffset is relative to the anchor of the instant event.
                self.event_start_us = self
                    .event_start_us
                    .wrapping_add(u32::from(update.win_offset) * 1250);
                self.params.win_size = update.win_size;
                self.params.win_offset = update.win_offset;
                self.params.interval = update.interval;
                self.params.latency = update.latency;
                self.params.timeout = update.timeout;
                self.pending_update = None;
            }
        }
        self.channel = self.csa.next_channel(self.event_counter);
        Ok(())
    }

    /// Skip whole intervals that are already in the past. Returns the number
    /// of events skipped. Refuses an unbounded leap; supervision must expire
    /// instead of silently resynchronising a dead link.
    pub fn skip_to(&mut self, now_us: u32) -> Result<u16, ConnError> {
        let mut skipped = 0u16;
        while time_reached(now_us, self.event_start_us) {
            if skipped == 0x0fff {
                return Err(ConnError::Parameters);
            }
            self.next_event()?;
            skipped += 1;
        }
        Ok(skipped)
    }
}

impl LinkTiming for CentralConnection {
    fn event_counter(&self) -> u16 {
        self.event_counter
    }

    fn schedule_channel_map(&mut self, map: [u8; 5], instant: u16) -> Result<(), ConnError> {
        CentralConnection::schedule_channel_map(self, map, instant)
    }

    fn schedule_update(&mut self, update: ConnectionUpdate) -> Result<(), ConnError> {
        CentralConnection::schedule_update(self, update)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ConnectParams {
        ConnectParams {
            peer_addr: [1, 2, 3, 4, 5, 6],
            peer_random: true,
            chsel: false,
            access_addr: 0x1234_5678,
            crc_init: 0x0055_5555,
            win_size: 2,
            win_offset: 1,
            interval: 24,
            latency: 0,
            timeout: 200,
            channel_map: [0xff, 0xff, 0xff, 0xff, 0x1f],
            hop: 5,
            sca: 0,
        }
    }

    #[test]
    fn first_event_uses_connect_end_window_and_first_hop() {
        let conn = CentralConnection::new(params(), 1000);
        assert_eq!(conn.event_start_us(), 1000 + 1250 + 1250);
        assert_eq!(conn.channel(), 5);
        assert_eq!(conn.event_counter(), 0);
        assert_eq!(
            conn.channel_selection_algorithm(),
            ChannelSelectionAlgorithm::Csa1
        );
    }

    #[test]
    fn csa2_first_event_matches_the_peripheral() {
        let mut p = params();
        p.chsel = true;
        let mut central = CentralConnection::new(p, 1000);
        let mut peripheral = crate::ll::conn::PeripheralConnection::new(p, 1000, true);
        assert_eq!(
            central.channel_selection_algorithm(),
            ChannelSelectionAlgorithm::Csa2
        );
        assert_eq!(central.channel(), peripheral.channel());
        for _ in 0..8 {
            central.next_event().unwrap();
            peripheral.next_event().unwrap();
            assert_eq!(central.channel(), peripheral.channel());
        }
    }

    #[test]
    fn bias_shifts_the_whole_schedule() {
        let conn = CentralConnection::new(params(), 1000).with_first_event_bias_us(5000);
        assert_eq!(conn.event_start_us(), 1000 + 1250 + 1250 + 5000);
    }

    #[test]
    fn reception_establishes_without_moving_the_anchor() {
        let mut conn = CentralConnection::new(params(), 1000);
        let anchor = conn.event_start_us();
        assert!(!conn.established());
        assert!(conn.on_rx(anchor + 400, 0, true));
        assert!(conn.established());
        assert_eq!(conn.event_start_us(), anchor);
        assert!(!conn.on_rx(anchor + 500, 0, false));
        conn.next_event().unwrap();
        assert_eq!(conn.event_start_us(), anchor + 24 * 1250);
        assert_eq!(conn.channel(), 10);
    }

    #[test]
    fn supervision_uses_six_intervals_before_establishment() {
        let mut conn = CentralConnection::new(params(), 1000);
        let deadline = 1000 + 24 * 1250 * 6;
        assert_eq!(conn.supervision_deadline_us(), deadline);
        assert!(!conn.supervision_expired(deadline - 1));
        assert!(conn.supervision_expired(deadline));
        assert!(conn.on_rx(deadline - 10, 0, true));
        assert_eq!(conn.supervision_deadline_us(), deadline - 10 + 200 * 10_000);
    }

    #[test]
    fn receive_ceiling_covers_the_encrypted_legacy_payload() {
        // 27 plaintext octets plus the 4-octet MIC is the largest legacy PDU.
        let mut conn = CentralConnection::new(params(), 0);
        assert!(conn.on_rx(2_500, 31, true));
        let mut conn = CentralConnection::new(params(), 0);
        assert!(!conn.on_rx(2_500, 32, true));
    }

    #[test]
    fn map_and_update_apply_at_the_requested_instant() {
        let mut conn = CentralConnection::new(params(), 0);
        conn.schedule_channel_map([0x03, 0, 0, 0, 0], 2).unwrap();
        conn.schedule_update(ConnectionUpdate {
            win_size: 1,
            win_offset: 0,
            interval: 40,
            latency: 0,
            timeout: 400,
            instant: 2,
        })
        .unwrap();
        conn.next_event().unwrap();
        assert_eq!(conn.params.interval, 24);
        let before = conn.event_start_us();
        conn.next_event().unwrap();
        assert_eq!(conn.params.interval, 40);
        assert_eq!(conn.params.timeout, 400);
        assert_eq!(conn.event_start_us(), before + 24 * 1250);
        // The two-channel map remaps unmapped 15 to the second enabled channel.
        assert_eq!(conn.channel(), 1);
    }

    #[test]
    fn skip_to_advances_whole_intervals_and_wraps() {
        let mut conn = CentralConnection::new(params(), u32::MAX - 5_000);
        let target = conn.event_start_us().wrapping_add(24 * 1250 * 3);
        let skipped = conn.skip_to(target).unwrap();
        assert_eq!(skipped, 4);
        assert!(time_reached(conn.event_start_us(), target));
        let now = conn.event_start_us().wrapping_sub(1);
        assert_eq!(conn.skip_to(now), Ok(0));
    }

    #[test]
    fn invalid_instant_is_rejected() {
        let mut conn = CentralConnection::new(params(), 0);
        assert_eq!(
            conn.schedule_channel_map([0xff, 0xff, 0xff, 0xff, 0x1f], 0),
            Err(ConnError::InstantPassed)
        );
        assert_eq!(
            conn.schedule_channel_map([0xff, 0xff, 0xff, 0xff, 0x1f], 0xffff),
            Err(ConnError::InstantPassed)
        );
    }
}
