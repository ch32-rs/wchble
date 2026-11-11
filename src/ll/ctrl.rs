//! Minimal legacy peripheral LL control procedures.
//!
//! Encryption control PDUs are constructed and parsed here; the session key
//! and data-PDU crypto live in [`super::enc`]. The control state machine in
//! this module deliberately does not handle encryption: the Host (LTK) and the
//! radio owner must sequence those exchanges, so they are driven explicitly.

use super::conn::{le16, ConnError, ConnectionUpdate, LinkTiming};

/// Subset of LL Control opcodes used during bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum LlCtrlOpcode {
    ConnectionUpdateInd = 0x00,
    ChannelMapInd = 0x01,
    TerminateInd = 0x02,
    EncReq = 0x03,
    EncRsp = 0x04,
    StartEncReq = 0x05,
    StartEncRsp = 0x06,
    UnknownRsp = 0x07,
    FeatureReq = 0x08,
    FeatureRsp = 0x09,
    PauseEncReq = 0x0a,
    PauseEncRsp = 0x0b,
    VersionInd = 0x0c,
    RejectInd = 0x0d,
    ConnectionParamReq = 0x0f,
    ConnectionParamRsp = 0x10,
    RejectExtInd = 0x11,
}

/// Identity must be supplied by the application, not copied from a vendor
/// controller. `version` is the Bluetooth version number (0x0d for Core 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalVersion {
    pub version: u8,
    pub company_id: u16,
    pub subversion: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct ControlPdu {
    bytes: [u8; 27],
    len: u8,
}

impl ControlPdu {
    fn new(payload: &[u8]) -> Self {
        debug_assert!(payload.len() <= 27);
        let mut pdu = Self {
            bytes: [0; 27],
            len: payload.len() as u8,
        };
        pdu.bytes[..payload.len()].copy_from_slice(payload);
        pdu
    }

    pub fn terminate(reason: u8) -> Self {
        Self::new(&[LlCtrlOpcode::TerminateInd as u8, reason])
    }

    pub fn unknown(opcode: u8) -> Self {
        Self::new(&[LlCtrlOpcode::UnknownRsp as u8, opcode])
    }

    pub fn connection_update(update: &ConnectionUpdate) -> Self {
        let mut bytes = [0; 12];
        bytes[0] = LlCtrlOpcode::ConnectionUpdateInd as u8;
        bytes[1] = update.win_size;
        bytes[2..4].copy_from_slice(&update.win_offset.to_le_bytes());
        bytes[4..6].copy_from_slice(&update.interval.to_le_bytes());
        bytes[6..8].copy_from_slice(&update.latency.to_le_bytes());
        bytes[8..10].copy_from_slice(&update.timeout.to_le_bytes());
        bytes[10..12].copy_from_slice(&update.instant.to_le_bytes());
        Self::new(&bytes)
    }

    pub fn channel_map(map: [u8; 5], instant: u16) -> Self {
        let mut bytes = [0; 8];
        bytes[0] = LlCtrlOpcode::ChannelMapInd as u8;
        bytes[1..6].copy_from_slice(&map);
        bytes[6..8].copy_from_slice(&instant.to_le_bytes());
        Self::new(&bytes)
    }

    pub fn version_ind(local: LocalVersion) -> Self {
        let company = local.company_id.to_le_bytes();
        let subversion = local.subversion.to_le_bytes();
        Self::new(&[
            LlCtrlOpcode::VersionInd as u8,
            local.version,
            company[0],
            company[1],
            subversion[0],
            subversion[1],
        ])
    }

    pub fn feature_rsp(features: [u8; 8]) -> Self {
        let mut bytes = [0; 9];
        bytes[0] = LlCtrlOpcode::FeatureRsp as u8;
        bytes[1..9].copy_from_slice(&features);
        Self::new(&bytes)
    }

    /// `LL_ENC_REQ`, sent by the Central. All fields are in wire order.
    pub fn enc_req(req: &EncReq) -> Self {
        let mut bytes = [0; 23];
        bytes[0] = LlCtrlOpcode::EncReq as u8;
        bytes[1..9].copy_from_slice(&req.rand);
        bytes[9..11].copy_from_slice(&req.ediv.to_le_bytes());
        bytes[11..19].copy_from_slice(&req.skdm);
        bytes[19..23].copy_from_slice(&req.ivm);
        Self::new(&bytes)
    }

    /// `LL_ENC_RSP`, sent by the Peripheral.
    pub fn enc_rsp(rsp: &EncRsp) -> Self {
        let mut bytes = [0; 13];
        bytes[0] = LlCtrlOpcode::EncRsp as u8;
        bytes[1..9].copy_from_slice(&rsp.skds);
        bytes[9..13].copy_from_slice(&rsp.ivs);
        Self::new(&bytes)
    }

    pub fn start_enc_req() -> Self {
        Self::new(&[LlCtrlOpcode::StartEncReq as u8])
    }

    pub fn start_enc_rsp() -> Self {
        Self::new(&[LlCtrlOpcode::StartEncRsp as u8])
    }

    pub fn pause_enc_req() -> Self {
        Self::new(&[LlCtrlOpcode::PauseEncReq as u8])
    }

    pub fn pause_enc_rsp() -> Self {
        Self::new(&[LlCtrlOpcode::PauseEncRsp as u8])
    }

    pub fn reject_ind(reason: u8) -> Self {
        Self::new(&[LlCtrlOpcode::RejectInd as u8, reason])
    }

    pub fn reject_ext_ind(opcode: u8, reason: u8) -> Self {
        Self::new(&[LlCtrlOpcode::RejectExtInd as u8, opcode, reason])
    }

    /// Payload only. Queue using `LinkSequence::queue(3, pdu.as_bytes())` so
    /// controls use exactly the same acknowledgment/retry path as ACL data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// `LL_ENC_REQ` fields in wire order. `skdm` and `ivm` are the Central's
/// session-key-diversifier and IV contributions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncReq {
    pub rand: [u8; 8],
    pub ediv: u16,
    pub skdm: [u8; 8],
    pub ivm: [u8; 4],
}

impl EncReq {
    pub fn parse(payload: &[u8]) -> Result<Self, ConnError> {
        if payload.len() != 23 {
            return Err(ConnError::Length);
        }
        if payload[0] != LlCtrlOpcode::EncReq as u8 {
            return Err(ConnError::Header);
        }
        let mut rand = [0; 8];
        rand.copy_from_slice(&payload[1..9]);
        let mut skdm = [0; 8];
        skdm.copy_from_slice(&payload[11..19]);
        let mut ivm = [0; 4];
        ivm.copy_from_slice(&payload[19..23]);
        Ok(Self {
            rand,
            ediv: le16(&payload[9..]),
            skdm,
            ivm,
        })
    }
}

/// `LL_ENC_RSP` fields in wire order: the Peripheral's contributions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncRsp {
    pub skds: [u8; 8],
    pub ivs: [u8; 4],
}

impl EncRsp {
    pub fn parse(payload: &[u8]) -> Result<Self, ConnError> {
        if payload.len() != 13 {
            return Err(ConnError::Length);
        }
        if payload[0] != LlCtrlOpcode::EncRsp as u8 {
            return Err(ConnError::Header);
        }
        let mut skds = [0; 8];
        skds.copy_from_slice(&payload[1..9]);
        let mut ivs = [0; 4];
        ivs.copy_from_slice(&payload[9..13]);
        Ok(Self { skds, ivs })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlAction {
    None,
    Reply(ControlPdu),
    /// Stop only after sending the link-layer acknowledgment when possible.
    Terminate(u8),
}

#[derive(Debug, Clone, Default)]
pub struct ControlState {
    pub peer_version: Option<LocalVersion>,
    pub peer_features: Option<[u8; 8]>,
    /// Feature bits this controller build implements. Bit 0 (LE Encryption)
    /// must be set by an RF owner that drives the start-encryption procedure.
    pub local_features: [u8; 8],
    version_sent: bool,
    termination_deadline_us: Option<u32>,
}

impl ControlState {
    pub const fn new() -> Self {
        Self {
            peer_version: None,
            peer_features: None,
            local_features: [0; 8],
            version_sent: false,
            termination_deadline_us: None,
        }
    }

    /// Start when local termination is requested, even if an older PDU is still
    /// outstanding. Later received packets must not restart this deadline.
    pub fn start_termination(&mut self, now_us: u32, timeout_slots: u16) {
        self.termination_deadline_us
            .get_or_insert(now_us.wrapping_add(u32::from(timeout_slots) * 10_000));
    }

    pub fn termination_deadline_us(&self) -> Option<u32> {
        self.termination_deadline_us
    }

    pub fn termination_expired(&self, now_us: u32) -> bool {
        self.termination_deadline_us
            .is_some_and(|end| super::conn::time_reached(now_us, end))
    }

    /// Invoke once for each newly accepted LLID=3 packet, never for retries.
    /// Reserve a response slot before accepting the peer's SN. The caller must
    /// retain a reply until `LinkSequence::queue` succeeds (an empty packet may
    /// still be awaiting its acknowledgment).
    pub fn on_pdu<C: LinkTiming>(
        &mut self,
        conn: &mut C,
        payload: &[u8],
        local: LocalVersion,
    ) -> Result<ControlAction, ConnError> {
        let Some(&opcode) = payload.first() else {
            return Err(ConnError::Length);
        };
        let reply = match opcode {
            0x00 => {
                exact_len(payload, 12)?;
                conn.schedule_update(ConnectionUpdate {
                    win_size: payload[1],
                    win_offset: le16(&payload[2..]),
                    interval: le16(&payload[4..]),
                    latency: le16(&payload[6..]),
                    timeout: le16(&payload[8..]),
                    instant: le16(&payload[10..]),
                })?;
                return Ok(ControlAction::None);
            }
            0x01 => {
                exact_len(payload, 8)?;
                let mut map = [0; 5];
                map.copy_from_slice(&payload[1..6]);
                map[4] &= 0x1f; // Ignore RFU bits 37..39 on reception.
                conn.schedule_channel_map(map, le16(&payload[6..]))?;
                return Ok(ControlAction::None);
            }
            0x02 => {
                exact_len(payload, 2)?;
                return Ok(ControlAction::Terminate(payload[1]));
            }
            0x07 => {
                exact_len(payload, 2)?;
                return Ok(ControlAction::None);
            }
            0x08 | 0x09 => {
                exact_len(payload, 9)?;
                let mut features = [0; 8];
                features.copy_from_slice(&payload[1..9]);
                self.peer_features = Some(features);
                if opcode == 0x09 {
                    return Ok(ControlAction::None);
                }
                // Only the features the owner explicitly enabled. DLE, PHY
                // update, CSA #2 and optional control procedures remain
                // unadvertised. Mandatory legacy procedures need no bit.
                ControlPdu::feature_rsp(self.local_features)
            }
            0x0c => {
                exact_len(payload, 6)?;
                self.peer_version = Some(LocalVersion {
                    version: payload[1],
                    company_id: le16(&payload[2..]),
                    subversion: le16(&payload[4..]),
                });
                if self.version_sent {
                    return Ok(ControlAction::None);
                }
                self.version_sent = true;
                ControlPdu::version_ind(local)
            }
            0x0d => {
                exact_len(payload, 2)?; // LL_REJECT_IND.
                return Ok(ControlAction::None);
            }
            0x11 => {
                exact_len(payload, 3)?; // LL_REJECT_EXT_IND.
                return Ok(ControlAction::None);
            }
            // Unsupported encryption, connection parameter request, DLE, PHY,
            // and future opcodes are explicitly reported as unknown. Never
            // fake an encryption response or negotiate a larger data length.
            _ => ControlPdu::unknown(opcode),
        };
        Ok(ControlAction::Reply(reply))
    }
}

fn exact_len(payload: &[u8], len: usize) -> Result<(), ConnError> {
    if payload.len() == len {
        Ok(())
    } else {
        Err(ConnError::Length)
    }
}

/// Error reason for ending a link after an invalid mandatory procedure.
pub fn termination_reason(error: ConnError) -> u8 {
    match error {
        ConnError::InstantPassed => 0x28,
        ConnError::ProcedureCollision => 0x23,
        _ => 0x1e, // Invalid LL Parameters.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ll::acl::LinkSequence;
    use crate::ll::conn::{ConnectParams, PeripheralConnection};

    const LOCAL: LocalVersion = LocalVersion {
        version: 0x0d,
        company_id: 0xffff,
        subversion: 1,
    };

    fn connection() -> PeripheralConnection {
        PeripheralConnection::new(
            ConnectParams {
                peer_addr: [1; 6],
                peer_random: false,
                access_addr: 0x1234_5678,
                crc_init: 0,
                win_size: 1,
                win_offset: 0,
                interval: 24,
                latency: 0,
                timeout: 200,
                channel_map: [0xff, 0xff, 0xff, 0xff, 0x1f],
                hop: 5,
                sca: 0,
            },
            1000,
        )
    }

    #[test]
    fn control_pdu_is_word_aligned_without_exposing_padding() {
        assert_eq!(core::mem::size_of::<ControlPdu>(), 28);
        assert_eq!(core::mem::align_of::<ControlPdu>(), 4);
        let pdu = ControlPdu::new(&[7, 0x14]);
        assert_eq!(pdu.as_bytes(), &[7, 0x14]);
        let full = ControlPdu::new(&[0; 27]);
        assert_eq!(full.as_bytes().len(), 27);
    }

    fn reply(action: ControlAction) -> ControlPdu {
        match action {
            ControlAction::Reply(pdu) => pdu,
            _ => panic!("expected reply"),
        }
    }

    #[test]
    fn local_termination_is_not_extended_by_valid_non_acknowledging_packets() {
        let mut conn = connection();
        conn.params.timeout = 10;
        let mut ctrl = ControlState::new();
        let mut link = LinkSequence::new();
        let start = u32::MAX - 50_000;
        conn = PeripheralConnection::new(conn.params, start.wrapping_sub(1000));
        assert!(conn.on_rx_anchor(start, 0));
        ctrl.start_termination(start, 10);
        link.queue(3, &[2, 0x13]).unwrap();
        link.tx_pdu();
        for elapsed in (10_000..=1_200_000).step_by(10_000) {
            let now = start.wrapping_add(elapsed);
            ctrl.start_termination(now, 10);
            let rx = link.on_rx(1, &[], true, true);
            assert!(!rx.tx_acked);
            // Even a link whose supervision is refreshed cannot extend the
            // independent local termination deadline.
            assert!(conn.on_rx_anchor(now, 0));
            assert!(!conn.supervision_expired(now));
            assert_eq!(ctrl.termination_expired(now), elapsed >= 100_000);
        }
        assert!(link.has_outstanding());
        assert_eq!(
            ctrl.termination_deadline_us(),
            Some(start.wrapping_add(100_000))
        );
    }

    #[test]
    fn mandatory_feature_and_version_without_vendor_impersonation() {
        let mut c = connection();
        let mut ctrl = ControlState::new();
        let features = reply(
            ctrl.on_pdu(
                &mut c,
                &[8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                LOCAL,
            )
            .unwrap(),
        );
        assert_eq!(features.as_bytes(), &[9, 0, 0, 0, 0, 0, 0, 0, 0]);
        let version = reply(
            ctrl.on_pdu(&mut c, &[0x0c, 9, 0x34, 0x12, 2, 0], LOCAL)
                .unwrap(),
        );
        assert_eq!(version.as_bytes(), &[0x0c, 0x0d, 0xff, 0xff, 1, 0]);
        assert_eq!(ctrl.peer_version.unwrap().company_id, 0x1234);
        assert_eq!(
            ctrl.on_pdu(&mut c, &[0x0c, 9, 0x34, 0x12, 2, 0], LOCAL),
            Ok(ControlAction::None)
        );
        let mut link = LinkSequence::new();
        link.queue(3, version.as_bytes()).unwrap();
        let first = link.tx_pdu();
        assert_eq!(first.llid(), 3);
        assert_eq!(link.tx_pdu(), first);
    }

    #[test]
    fn local_features_are_reported_only_when_the_owner_enables_them() {
        let mut c = connection();
        let mut ctrl = ControlState::new();
        assert_eq!(
            reply(
                ctrl.on_pdu(&mut c, &[8, 1, 0, 0, 0, 0, 0, 0, 0], LOCAL)
                    .unwrap()
            )
            .as_bytes(),
            &[9, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        ctrl.local_features = [1, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            reply(
                ctrl.on_pdu(&mut c, &[8, 1, 0, 0, 0, 0, 0, 0, 0], LOCAL)
                    .unwrap()
            )
            .as_bytes(),
            &[9, 1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn unsupported_features_receive_unknown_not_fake_success() {
        let mut c = connection();
        let mut ctrl = ControlState::new();
        for opcode in [0x03, 0x0f, 0x12, 0x14, 0x16, 0xff] {
            let response = reply(ctrl.on_pdu(&mut c, &[opcode], LOCAL).unwrap());
            assert_eq!(response.as_bytes(), &[0x07, opcode]);
        }
        assert_eq!(
            ctrl.on_pdu(&mut c, &[7, 0x14], LOCAL),
            Ok(ControlAction::None)
        );
        assert_eq!(
            ctrl.on_pdu(&mut c, &[2, 0x13], LOCAL),
            Ok(ControlAction::Terminate(0x13))
        );
    }

    #[test]
    fn known_controls_require_exact_length() {
        let mut c = connection();
        let mut ctrl = ControlState::new();
        assert_eq!(ctrl.on_pdu(&mut c, &[], LOCAL), Err(ConnError::Length));
        for (opcode, len) in [
            (0, 12),
            (1, 8),
            (2, 2),
            (7, 2),
            (8, 9),
            (9, 9),
            (12, 6),
            (13, 2),
            (17, 3),
        ] {
            let mut bytes = [0; 13];
            bytes[0] = opcode;
            for actual in 1..=13 {
                if actual != len {
                    assert_eq!(
                        ctrl.on_pdu(&mut c, &bytes[..actual], LOCAL),
                        Err(ConnError::Length)
                    );
                }
            }
        }
    }

    #[test]
    fn valid_map_update_and_connection_update_are_deferred() {
        let mut c = connection();
        let mut ctrl = ControlState::new();
        assert_eq!(
            ctrl.on_pdu(&mut c, &[1, 1, 0, 0, 0, 0x10, 2, 0], LOCAL),
            Ok(ControlAction::None)
        );
        assert_eq!(
            ctrl.on_pdu(&mut c, &[0, 1, 0, 0, 40, 0, 0, 0, 200, 0, 2, 0], LOCAL),
            Ok(ControlAction::None)
        );
        assert_eq!(c.params.interval, 24);
        c.next_event().unwrap();
        assert_eq!(c.channel(), 10);
        c.next_event().unwrap();
        assert_eq!(c.channel(), 36);
        assert_eq!(c.params.interval, 40);
    }

    #[test]
    fn invalid_map_past_instant_and_invalid_timeout() {
        let mut c = connection();
        let mut ctrl = ControlState::new();
        assert_eq!(
            ctrl.on_pdu(&mut c, &[1, 1, 0, 0, 0, 0, 2, 0], LOCAL),
            Err(ConnError::ChannelMap)
        );
        assert_eq!(
            ctrl.on_pdu(&mut c, &[1, 3, 0, 0, 0, 0, 0xff, 0xff], LOCAL),
            Err(ConnError::InstantPassed)
        );
        assert_eq!(
            ctrl.on_pdu(&mut c, &[0, 1, 0, 0, 40, 0, 0, 0, 10, 0, 2, 0], LOCAL),
            Err(ConnError::Parameters)
        );
        assert_eq!(termination_reason(ConnError::InstantPassed), 0x28);
    }
}
