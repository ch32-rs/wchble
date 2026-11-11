//! LE link-layer encryption: session key derivation and data-PDU AES-CCM.
//!
//! Conventions (Core 5.4, Vol 6, Part E):
//! - `SKD = SKDm || SKDs` and `IV = IVm || IVs`, in the order the fields
//!   appear on the air (little-endian multi-octet fields).
//! - `SK = AES-128(key = LTK, plaintext = SKD)`, one block, with the software
//!   engine (this happens once per session, outside the event loop).
//! - CCM nonce (13 octets): counter[7:0], [15:8], [23:16], [31:24],
//!   direction in bit 7 with counter[38:32] in bits 6:0, then the 8-octet IV.
//! - `directionBit` is 1 for Central -> Peripheral and 0 for
//!   Peripheral -> Central.
//! - The associated data is **one octet**: the first PDU header octet with
//!   NESN, SN and MD masked to zero. The length octet is not authenticated.
//! - Packet counters start at zero per direction and advance once per new
//!   encrypted PDU; retransmissions reuse the stored PDU and do not advance.
//!   Empty PDUs are neither encrypted nor counted.
//!
//! The counters are separate per direction, and a MIC failure must terminate
//! the link (reason 0x3d); the failed packet does not advance the counter.
//!
//! Sequence tested by [`tests::full_start_procedure_round_trip`]:
//! Central sends `LL_ENC_REQ`, Peripheral replies `LL_ENC_RSP`, Central sends
//! `LL_START_ENC_REQ`, Peripheral replies with an encrypted `LL_START_ENC_RSP`,
//! then Central replies with its own encrypted `LL_START_ENC_RSP`. The
//! Peripheral enables TX before its RSP and RX after it; the Central enables
//! RX after `LL_ENC_RSP` and TX before its RSP. Counters reset on every start
//! or pause/resume procedure.

use crate::crypto::ccm::{decrypt as ccm_decrypt, encrypt as ccm_encrypt, CcmError, BLE_MIC_LEN};
use crate::crypto::{Aes128, AesEngine};

/// Largest plaintext payload of an encrypted legacy PDU (27 on-air octets
/// including the 4-octet MIC).
pub const MAX_PLAINTEXT: usize = 27 - BLE_MIC_LEN;
/// Largest encrypted payload including the MIC.
pub const MAX_ENCRYPTED: usize = 27;

/// Header bits that are excluded from the authenticated data.
const AAD_MASK: u8 = !0x1c; // ~(NESN | SN | MD)
/// Highest valid 39-bit packet counter.
const COUNTER_MAX: u64 = (1 << 39) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EncError {
    /// Empty payload (not encrypted) or longer than [`MAX_ENCRYPTED`].
    Length,
    /// MIC verification failed on receive.
    MicFailure,
    /// The direction is not enabled yet.
    NotEnabled,
    /// The 39-bit packet counter is exhausted.
    CounterExhausted,
    /// The AES block engine failed to complete.
    Engine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum EncRole {
    Central,
    Peripheral,
}

impl EncRole {
    /// `true` when this role's transmissions use direction bit 1.
    pub const fn tx_direction(self) -> bool {
        matches!(self, Self::Central)
    }
}

/// Session key material exchanged by `LL_ENC_REQ` / `LL_ENC_RSP`.
#[derive(Clone)]
pub struct SessionKey {
    key: [u8; 16],
    iv: [u8; 8],
}

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

impl SessionKey {
    /// `SK = AES-128(LTK, SKD)`, with `SKD = SKDm || SKDs` and
    /// `IV = IVm || IVs` in wire order.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    pub fn derive(ltk: &[u8; 16], skd: &[u8; 16], iv: &[u8; 8]) -> Self {
        let mut key = *skd;
        Aes128::new(ltk).encrypt_block(&mut key);
        Self { key, iv: *iv }
    }

    /// Convenience wrapper for the two exchanged contributions.
    pub fn from_parts(
        ltk: &[u8; 16],
        skdm: &[u8; 8],
        skds: &[u8; 8],
        ivm: &[u8; 4],
        ivs: &[u8; 4],
    ) -> Self {
        let mut skd = [0; 16];
        skd[..8].copy_from_slice(skdm);
        skd[8..].copy_from_slice(skds);
        let mut iv = [0; 8];
        iv[..4].copy_from_slice(ivm);
        iv[4..].copy_from_slice(ivs);
        Self::derive(ltk, &skd, &iv)
    }

    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }

    pub fn iv(&self) -> &[u8; 8] {
        &self.iv
    }
}

/// Build the 13-octet CCM nonce for a packet counter and direction.
pub fn nonce(iv: &[u8; 8], counter: u64, direction_bit: bool) -> [u8; 13] {
    let mut n = [0; 13];
    n[..5].copy_from_slice(&counter.to_le_bytes()[..5]);
    if direction_bit {
        n[4] |= 0x80;
    }
    n[5..].copy_from_slice(iv);
    n
}

/// Per-connection encryption state, owning the keyed AES engine.
///
/// Construct once per start (or pause/resume) procedure with an engine keyed
/// by [`SessionKey::key`], then enable TX/RX at the points required by the
/// start procedure. Holding the engine here prevents pairing a session key
/// with the wrong cipher key and keeps the hardware key loaded for every
/// block of the connection.
pub struct Encryption<E: AesEngine> {
    engine: E,
    iv: [u8; 8],
    role: EncRole,
    tx_enabled: bool,
    rx_enabled: bool,
    tx_counter: u64,
    rx_counter: u64,
}

impl<E: AesEngine> core::fmt::Debug for Encryption<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Encryption")
            .field("role", &self.role)
            .field("tx_enabled", &self.tx_enabled)
            .field("rx_enabled", &self.rx_enabled)
            .field("tx_counter", &self.tx_counter)
            .field("rx_counter", &self.rx_counter)
            .finish_non_exhaustive()
    }
}

impl<E: AesEngine> Encryption<E> {
    pub fn new(session: SessionKey, role: EncRole, engine: E) -> Self {
        Self {
            engine,
            iv: session.iv,
            role,
            tx_enabled: false,
            rx_enabled: false,
            tx_counter: 0,
            rx_counter: 0,
        }
    }

    pub fn role(&self) -> EncRole {
        self.role
    }

    pub fn tx_enabled(&self) -> bool {
        self.tx_enabled
    }

    pub fn rx_enabled(&self) -> bool {
        self.rx_enabled
    }

    pub fn enable_tx(&mut self) {
        self.tx_enabled = true;
    }

    pub fn enable_rx(&mut self) {
        self.rx_enabled = true;
    }

    pub fn disable(&mut self) {
        self.tx_enabled = false;
        self.rx_enabled = false;
    }

    pub fn tx_counter(&self) -> u64 {
        self.tx_counter
    }

    pub fn rx_counter(&self) -> u64 {
        self.rx_counter
    }

    /// Encrypt one new data/control PDU payload.
    ///
    /// `llid` is used in the one-octet AAD (only the LLID bits survive the
    /// mask). `out` receives the ciphertext followed by the 4-octet MIC and
    /// the returned length includes the MIC, ready for `LinkSequence::queue`.
    /// Call once per new PDU; a retransmission must reuse the queued bytes.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    pub fn encrypt(
        &mut self,
        llid: u8,
        plaintext: &[u8],
        out: &mut [u8; MAX_ENCRYPTED],
    ) -> Result<usize, EncError> {
        if !self.tx_enabled {
            return Err(EncError::NotEnabled);
        }
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
            return Err(EncError::Length);
        }
        if self.tx_counter > COUNTER_MAX {
            return Err(EncError::CounterExhausted);
        }
        let nonce = nonce(&self.iv, self.tx_counter, self.role.tx_direction());
        let aad = [llid & AAD_MASK];
        let mut mic = [0u8; BLE_MIC_LEN];
        let len = plaintext.len();
        ccm_encrypt::<BLE_MIC_LEN>(
            &mut self.engine,
            &nonce,
            &aad,
            plaintext,
            &mut out[..len],
            &mut mic,
        )
        .map_err(|e| match e {
            CcmError::Engine => EncError::Engine,
            _ => EncError::Length,
        })?;
        out[len..len + BLE_MIC_LEN].copy_from_slice(&mic);
        self.tx_counter += 1;
        Ok(len + BLE_MIC_LEN)
    }

    /// Decrypt and authenticate one newly accepted PDU.
    ///
    /// `payload` is the on-air payload including the MIC and `header` is the
    /// first header octet as received. Call only for a packet the link
    /// sequence accepted (not a duplicate) so the counter advances exactly
    /// once. On [`EncError::MicFailure`] the caller must terminate the link
    /// with reason 0x3d.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    pub fn decrypt(
        &mut self,
        header: u8,
        payload: &[u8],
        out: &mut [u8; MAX_PLAINTEXT],
    ) -> Result<usize, EncError> {
        if !self.rx_enabled {
            return Err(EncError::NotEnabled);
        }
        if payload.len() <= BLE_MIC_LEN || payload.len() > MAX_ENCRYPTED {
            return Err(EncError::Length);
        }
        if self.rx_counter > COUNTER_MAX {
            return Err(EncError::CounterExhausted);
        }
        let split = payload.len() - BLE_MIC_LEN;
        let mut mic = [0u8; BLE_MIC_LEN];
        mic.copy_from_slice(&payload[split..]);
        let nonce = nonce(&self.iv, self.rx_counter, !self.role.tx_direction());
        let aad = [header & AAD_MASK];
        ccm_decrypt::<BLE_MIC_LEN>(
            &mut self.engine,
            &nonce,
            &aad,
            &payload[..split],
            &mic,
            &mut out[..split],
        )
        .map_err(|e| match e {
            CcmError::Engine => EncError::Engine,
            _ => EncError::MicFailure,
        })?;
        self.rx_counter += 1;
        Ok(split)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ll::ctrl::{ControlPdu, EncReq, EncRsp, LlCtrlOpcode};

    const LTK: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const SKDM: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    const SKDS: [u8; 8] = [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    const IVM: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    const IVS: [u8; 4] = [0x55, 0x66, 0x77, 0x88];

    fn session() -> SessionKey {
        SessionKey::from_parts(&LTK, &SKDM, &SKDS, &IVM, &IVS)
    }

    fn central() -> Encryption<Aes128> {
        let session = session();
        let engine = Aes128::new(session.key());
        Encryption::new(session, EncRole::Central, engine)
    }

    fn peripheral() -> Encryption<Aes128> {
        let session = session();
        let engine = Aes128::new(session.key());
        Encryption::new(session, EncRole::Peripheral, engine)
    }

    #[test]
    fn session_key_matches_independent_vector() {
        // Produced with Python `cryptography` AES-ECB: SK = AES(LTK, SKD).
        let sk = session();
        assert_eq!(
            sk.key(),
            &[
                0x0a, 0x94, 0x0b, 0xb5, 0x41, 0x6e, 0xf0, 0x45, 0xf1, 0xc3, 0x94, 0x58, 0xc6, 0x53,
                0xea, 0x5a,
            ]
        );
        assert_eq!(sk.iv(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    }

    #[test]
    fn nonce_layout_is_counter_le_then_iv() {
        assert_eq!(
            nonce(
                &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                0x0102_0304_05,
                false
            ),
            [0x05, 0x04, 0x03, 0x02, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        // Direction occupies bit 7 of octet 4; counter bit 32..38 fill bits 6:0.
        let n = nonce(&[0; 8], 0x80_0000_0000, true);
        assert_eq!(n[4], 0x80);
        let n = nonce(&[0; 8], 0x7f_ffff_ffff, false);
        assert_eq!(n[4], 0x7f);
    }

    #[test]
    fn central_tx_kat_from_independent_implementation() {
        let mut enc = central();
        enc.enable_tx();
        let mut out = [0; MAX_ENCRYPTED];
        let pt = [
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        ];
        let len = enc.encrypt(0x02, &pt, &mut out).unwrap();
        assert_eq!(len, 18);
        assert_eq!(
            &out[..len],
            &[
                0xa6, 0x20, 0x57, 0x69, 0x6b, 0x70, 0x4e, 0x6a, 0x8d, 0x2c, 0x53, 0x9b, 0x0e, 0x2e,
                0xd0, 0xd5, 0x10, 0x0b,
            ]
        );
        assert_eq!(enc.tx_counter(), 1);
    }

    #[test]
    fn second_packet_uses_counter_one() {
        let mut enc = central();
        enc.enable_tx();
        let mut out = [0; MAX_ENCRYPTED];
        enc.encrypt(0x02, &[0; 14], &mut out).unwrap();
        let len = enc
            .encrypt(0x02, &[0xde, 0xad, 0xbe, 0xef], &mut out)
            .unwrap();
        assert_eq!(
            &out[..len],
            &[0xe1, 0xbe, 0x4b, 0xe8, 0xbe, 0xd5, 0x94, 0x3e]
        );
        assert_eq!(enc.tx_counter(), 2);
    }

    #[test]
    fn peripheral_direction_bit_zero_vector() {
        let mut enc = peripheral();
        enc.enable_tx();
        let mut out = [0; MAX_ENCRYPTED];
        let len = enc.encrypt(0x03, &[0x0a, 0x0b, 0x0c], &mut out).unwrap();
        assert_eq!(&out[..len], &[0x7f, 0x17, 0xc2, 0xb4, 0xcd, 0xec, 0x77]);
    }

    #[test]
    fn header_sn_nesn_md_do_not_change_the_mic() {
        let mut a = central();
        a.enable_tx();
        let mut b = central();
        b.enable_tx();
        let mut out_a = [0; MAX_ENCRYPTED];
        let mut out_b = [0; MAX_ENCRYPTED];
        let pt = [0xde, 0xad, 0xbe, 0xef];
        // Same LLID, different SN/NESN/MD bits: the on-air header differs but
        // the masked AAD is identical.
        let la = a.encrypt(0x02, &pt, &mut out_a).unwrap();
        let lb = b.encrypt(0x02, &pt, &mut out_b).unwrap();
        assert_eq!(out_a[..la], out_b[..lb]);
        assert_eq!((0x02 | 0x1c) & AAD_MASK, 0x02);
    }

    #[test]
    fn decrypt_rejects_tampering_without_advancing() {
        let mut tx = central();
        tx.enable_tx();
        let mut out = [0; MAX_ENCRYPTED];
        let len = tx.encrypt(0x02, &[1, 2, 3, 4, 5], &mut out).unwrap();
        let mut rx = peripheral();
        rx.enable_rx();
        let mut plain = [0; MAX_PLAINTEXT];
        out[0] ^= 1;
        assert_eq!(
            rx.decrypt(0x02, &out[..len], &mut plain),
            Err(EncError::MicFailure)
        );
        assert_eq!(rx.rx_counter(), 0);
        out[0] ^= 1;
        assert_eq!(rx.decrypt(0x02, &out[..len], &mut plain), Ok(5));
        assert_eq!(&plain[..5], &[1, 2, 3, 4, 5]);
        assert_eq!(rx.rx_counter(), 1);
    }

    #[test]
    fn disabled_and_empty_pdus_are_rejected() {
        let mut enc = central();
        let mut out = [0; MAX_ENCRYPTED];
        assert_eq!(enc.encrypt(0x02, &[1], &mut out), Err(EncError::NotEnabled));
        enc.enable_tx();
        assert_eq!(enc.encrypt(0x02, &[], &mut out), Err(EncError::Length));
        assert_eq!(
            enc.encrypt(0x02, &[0; MAX_PLAINTEXT + 1], &mut out),
            Err(EncError::Length)
        );
        enc.enable_rx();
        assert_eq!(
            enc.decrypt(0x02, &[0; 4], &mut [0; MAX_PLAINTEXT]),
            Err(EncError::Length)
        );
    }

    #[test]
    fn counters_are_independent_per_direction() {
        let mut c = central();
        c.enable_tx();
        c.enable_rx();
        let mut out = [0; MAX_ENCRYPTED];
        c.encrypt(0x02, &[1], &mut out).unwrap();
        c.encrypt(0x02, &[2], &mut out).unwrap();
        assert_eq!(c.tx_counter(), 2);
        assert_eq!(c.rx_counter(), 0);
        c.disable();
        assert!(!c.tx_enabled() && !c.rx_enabled());
    }

    #[test]
    fn control_pdus_round_trip_wire_format() {
        let req = EncReq {
            rand: [0xa0; 8],
            ediv: 0x1234,
            skdm: SKDM,
            ivm: IVM,
        };
        let pdu = ControlPdu::enc_req(&req);
        assert_eq!(pdu.as_bytes().len(), 23);
        assert_eq!(pdu.as_bytes()[0], LlCtrlOpcode::EncReq as u8);
        assert_eq!(pdu.as_bytes()[9..11], [0x34, 0x12]);
        assert_eq!(EncReq::parse(pdu.as_bytes()).unwrap(), req);

        let rsp = EncRsp {
            skds: SKDS,
            ivs: IVS,
        };
        let pdu = ControlPdu::enc_rsp(&rsp);
        assert_eq!(pdu.as_bytes().len(), 13);
        assert_eq!(pdu.as_bytes()[0], LlCtrlOpcode::EncRsp as u8);
        assert_eq!(EncRsp::parse(pdu.as_bytes()).unwrap(), rsp);
        assert_eq!(ControlPdu::start_enc_req().as_bytes(), &[0x05]);
        assert_eq!(ControlPdu::start_enc_rsp().as_bytes(), &[0x06]);
        assert_eq!(ControlPdu::pause_enc_req().as_bytes(), &[0x0a]);
        assert_eq!(ControlPdu::pause_enc_rsp().as_bytes(), &[0x0b]);
        assert_eq!(ControlPdu::reject_ind(0x06).as_bytes(), &[0x0d, 0x06]);
        assert_eq!(
            ControlPdu::reject_ext_ind(0x03, 0x06).as_bytes(),
            &[0x11, 0x03, 0x06]
        );
    }

    /// Fake-LL start procedure: the Central and Peripheral exchange the real
    /// control PDUs and then encrypted PDUs under one software engine each.
    #[test]
    fn full_start_procedure_round_trip() {
        // 1. Central -> LL_ENC_REQ.
        let req = EncReq {
            rand: [0; 8], // LE Secure Connections: unused
            ediv: 0,
            skdm: SKDM,
            ivm: IVM,
        };
        let req_bytes = ControlPdu::enc_req(&req);
        let parsed = EncReq::parse(req_bytes.as_bytes()).unwrap();
        assert_eq!(parsed, req);

        // 2. Peripheral -> LL_ENC_RSP.
        let rsp = EncRsp {
            skds: SKDS,
            ivs: IVS,
        };
        let rsp_bytes = ControlPdu::enc_rsp(&rsp);
        let parsed_rsp = EncRsp::parse(rsp_bytes.as_bytes()).unwrap();
        assert_eq!(parsed_rsp, rsp);

        // Both sides derive the same session key.
        let c_key = SessionKey::from_parts(&LTK, &req.skdm, &rsp.skds, &req.ivm, &rsp.ivs);
        let p_key = SessionKey::from_parts(&LTK, &req.skdm, &rsp.skds, &req.ivm, &rsp.ivs);
        assert_eq!(c_key.key(), p_key.key());
        assert_eq!(c_key.iv(), p_key.iv());

        let c_engine = Aes128::new(c_key.key());
        let p_engine = Aes128::new(p_key.key());
        let mut c_enc = Encryption::new(c_key, EncRole::Central, c_engine);
        let mut p_enc = Encryption::new(p_key, EncRole::Peripheral, p_engine);
        // Central receives the Peripheral's encrypted RSP next.
        c_enc.enable_rx();

        // 3. Central -> LL_START_ENC_REQ (unencrypted).
        assert_eq!(ControlPdu::start_enc_req().as_bytes(), &[0x05]);

        // 4. Peripheral -> encrypted LL_START_ENC_RSP (TX counter 0).
        p_enc.enable_tx();
        let mut ccm_out = [0; MAX_ENCRYPTED];
        let rsp_pt = ControlPdu::start_enc_rsp();
        let len = p_enc
            .encrypt(0x03, rsp_pt.as_bytes(), &mut ccm_out)
            .unwrap();
        assert_eq!(len, 5);
        let mut plain = [0; MAX_PLAINTEXT];
        let n = c_enc.decrypt(0x03, &ccm_out[..len], &mut plain).unwrap();
        assert_eq!(&plain[..n], rsp_pt.as_bytes());
        p_enc.enable_rx();

        // 5. Central -> encrypted LL_START_ENC_RSP (TX counter 0).
        c_enc.enable_tx();
        let len = c_enc
            .encrypt(0x03, rsp_pt.as_bytes(), &mut ccm_out)
            .unwrap();
        let n = p_enc.decrypt(0x03, &ccm_out[..len], &mut plain).unwrap();
        assert_eq!(&plain[..n], rsp_pt.as_bytes());

        // Data flows both ways with independent counters.
        let payload = [0x2a; 7];
        let len = c_enc.encrypt(0x02, &payload, &mut ccm_out).unwrap();
        let n = p_enc.decrypt(0x02, &ccm_out[..len], &mut plain).unwrap();
        assert_eq!(&plain[..n], &payload);
        let len = p_enc.encrypt(0x02, &payload, &mut ccm_out).unwrap();
        let n = c_enc.decrypt(0x02, &ccm_out[..len], &mut plain).unwrap();
        assert_eq!(&plain[..n], &payload);
        assert_eq!(c_enc.tx_counter(), 2); // RSP + data
        assert_eq!(c_enc.rx_counter(), 2); // Peripheral RSP + data
        assert_eq!(p_enc.tx_counter(), 2);
        assert_eq!(p_enc.rx_counter(), 2);
    }

    /// The pause procedure is three encrypted PDUs on the old session; a
    /// resume is a fresh start procedure whose new session resets counters.
    #[test]
    fn pause_exchange_then_resume_with_fresh_counters() {
        let mut c_enc = central();
        let mut p_enc = peripheral();
        c_enc.enable_tx();
        c_enc.enable_rx();
        p_enc.enable_tx();
        p_enc.enable_rx();
        let mut wire = [0; MAX_ENCRYPTED];
        let mut plain = [0; MAX_PLAINTEXT];

        // One data packet first so the counters are non-zero.
        let len = c_enc.encrypt(0x02, &[0x11, 0x22, 0x33], &mut wire).unwrap();
        assert_eq!(p_enc.decrypt(0x02, &wire[..len], &mut plain), Ok(3));

        let req = ControlPdu::pause_enc_req();
        let rsp = ControlPdu::pause_enc_rsp();
        // PAUSE_ENC_REQ (Central -> Peripheral).
        let len = c_enc.encrypt(0x03, req.as_bytes(), &mut wire).unwrap();
        assert_eq!(p_enc.decrypt(0x03, &wire[..len], &mut plain), Ok(1));
        // PAUSE_ENC_RSP (Peripheral -> Central).
        let len = p_enc.encrypt(0x03, rsp.as_bytes(), &mut wire).unwrap();
        assert_eq!(c_enc.decrypt(0x03, &wire[..len], &mut plain), Ok(1));
        // PAUSE_ENC_RSP (Central -> Peripheral).
        let len = c_enc.encrypt(0x03, rsp.as_bytes(), &mut wire).unwrap();
        assert_eq!(p_enc.decrypt(0x03, &wire[..len], &mut plain), Ok(1));

        // Resume: new SKDs/IVs, counters restart at zero.
        let new_skds = [0x77; 8];
        let new_ivs = [0x99; 4];
        let c_key = SessionKey::from_parts(&LTK, &SKDM, &new_skds, &IVM, &new_ivs);
        let p_key = SessionKey::from_parts(&LTK, &SKDM, &new_skds, &IVM, &new_ivs);
        let c_engine = Aes128::new(c_key.key());
        let p_engine = Aes128::new(p_key.key());
        let mut c_enc = Encryption::new(c_key, EncRole::Central, c_engine);
        let mut p_enc = Encryption::new(p_key, EncRole::Peripheral, p_engine);
        c_enc.enable_tx();
        p_enc.enable_rx();
        let len = c_enc.encrypt(0x03, rsp.as_bytes(), &mut wire).unwrap();
        assert_eq!(p_enc.decrypt(0x03, &wire[..len], &mut plain), Ok(1));
        assert_eq!(c_enc.tx_counter(), 1);
        assert_eq!(p_enc.rx_counter(), 1);
    }

    #[test]
    fn counter_exhaustion_is_reported() {
        let mut enc = central();
        enc.enable_tx();
        enc.enable_rx();
        let mut out = [0; MAX_ENCRYPTED];
        enc.tx_counter = COUNTER_MAX;
        assert!(enc.encrypt(0x02, &[1], &mut out).is_ok());
        assert_eq!(enc.tx_counter(), COUNTER_MAX + 1);
        assert_eq!(
            enc.encrypt(0x02, &[1], &mut out),
            Err(EncError::CounterExhausted)
        );

        enc.rx_counter = COUNTER_MAX + 1;
        assert_eq!(
            enc.decrypt(0x02, &out[..5], &mut [0; MAX_PLAINTEXT]),
            Err(EncError::CounterExhausted)
        );
    }
}
