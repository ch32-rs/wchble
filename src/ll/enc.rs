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
//! Sequence tested by [`tests::full_start_procedure_round_trip`] (Core 5.4
//! Vol 6 Part B §5.1.3.1): Central sends `LL_ENC_REQ`, Peripheral replies
//! `LL_ENC_RSP`, **Peripheral sends the plaintext `LL_START_ENC_REQ`**, then
//! the Central answers with the link's first encrypted PDU (its
//! `LL_START_ENC_RSP`, TX counter 0) and the Peripheral answers with its own
//! encrypted `LL_START_ENC_RSP` (TX counter 0). The Peripheral enables TX
//! before precomputing its RSP and RX when it sends `LL_START_ENC_REQ`; the
//! Central enables RX after `LL_ENC_RSP` and TX before its RSP. Counters reset
//! on every start or pause/resume procedure.

use crate::crypto::ccm::{decrypt as ccm_decrypt, encrypt as ccm_encrypt, CcmError, BLE_MIC_LEN};
use crate::crypto::{Aes128, AesEngine};

use super::ctrl::{ControlPdu, EncReq, EncRsp};

/// Largest plaintext payload of an encrypted PDU: the 251-octet air ceiling
/// minus the MIC. It also covers pre-DLE peers: an Android Central has been
/// observed sending 28-octet encrypted PDUs without negotiating. The
/// negotiated per-link limit is smaller until DLE completes; see
/// [`super::dle::DataLength`].
pub const MAX_PLAINTEXT: usize = crate::ll::dle::LL_MAX_PLAINTEXT as usize;
/// Largest encrypted payload on air, MIC included; also the ceiling that
/// bounds every `LinkSequence` receive/tx limit.
pub const MAX_ENCRYPTED: usize = crate::ll::dle::LL_MAX_PAYLOAD as usize;

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
    /// `SK = AES-128(LTK, SKD)` (Core Vol 6 Part C §1.2).
    ///
    /// The cipher works on the *values* in most-significant-octet order, while
    /// every field arrives little-endian on the air: `SKD` is
    /// `SKDs || SKDm` (Peripheral half first) with each half byte-reversed from
    /// the wire, and the Host supplies the LTK as HCI little-endian octets.
    /// `iv` is already the nonce form (`IVm || IVs`, wire octets as received).
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    pub fn derive(ltk: &[u8; 16], skd: &[u8; 16], iv: &[u8; 8]) -> Self {
        let mut key = [0u8; 16];
        for (dst, src) in key.iter_mut().zip(ltk.iter().rev()) {
            *dst = *src;
        }
        let mut session = *skd;
        Aes128::new(&key).encrypt_block(&mut session);
        Self {
            key: session,
            iv: *iv,
        }
    }

    /// Convenience wrapper for the two exchanged contributions. `skdm`, `skds`,
    /// `ivm` and `ivs` are the octets exactly as received in `LL_ENC_REQ` /
    /// `LL_ENC_RSP`.
    pub fn from_parts(
        ltk: &[u8; 16],
        skdm: &[u8; 8],
        skds: &[u8; 8],
        ivm: &[u8; 4],
        ivs: &[u8; 4],
    ) -> Self {
        let mut skd = [0; 16];
        for (dst, src) in skd[..8].iter_mut().zip(skds.iter().rev()) {
            *dst = *src;
        }
        for (dst, src) in skd[8..].iter_mut().zip(skdm.iter().rev()) {
            *dst = *src;
        }
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
        self.engine.reload();
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
        self.engine.reload();
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

/// Where the Peripheral is in the start-encryption exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StartStage {
    /// No `LL_ENC_REQ` seen yet; PDUs are plaintext.
    Idle,
    /// `LL_ENC_RSP` prepared; waiting for the Host's LTK answer.
    AwaitingKey,
    /// Encrypted `LL_START_ENC_RSP` precomputed; the Peripheral's own
    /// `LL_START_ENC_REQ` has not been sent yet.
    Prepared,
    /// `LL_START_ENC_REQ` sent and RX decryption on; waiting for the Central's
    /// encrypted `LL_START_ENC_RSP`.
    WaitingRsp,
    /// Both sides encrypted.
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StartError {
    /// A new `LL_ENC_REQ` arrived while a procedure is already running.
    NotIdle,
    /// A later step ran before its predecessor.
    NotReady,
    /// Malformed control PDU.
    Length,
    /// Not the expected opcode.
    Opcode,
    Enc(EncError),
}

impl From<EncError> for StartError {
    fn from(error: EncError) -> Self {
        Self::Enc(error)
    }
}

/// Peripheral-side start-encryption sequencing.
///
/// The RF owner supplies the Central's `LL_ENC_REQ`, its own SKDs/IVs and the
/// Host's LTK; this type enforces the order in Core 5.4 Vol 6 Part B §5.1.3.1
/// and owns the precomputed encrypted response. All AES work happens through
/// [`Encryption`], so callers can keep it off the connection-event path:
///
/// 1. [`Self::on_enc_req`] returns the plaintext `LL_ENC_RSP` to send.
/// 2. After the Host answers, build `Encryption::new(session, Peripheral, ..)`
///    and call [`Self::prepare_start_rsp`]. This enables TX and burns TX
///    counter 0.
/// 3. [`Self::start_enc_req`] sends the Peripheral's plaintext
///    `LL_START_ENC_REQ` and enables RX; the Central's answer is the link's
///    first encrypted PDU.
/// 4. After decrypting the Central's response, [`Self::on_start_enc_rsp`]
///    returns the precomputed encrypted response to send.
pub struct PeripheralStart {
    stage: StartStage,
    req: Option<EncReq>,
    skds: [u8; 8],
    ivs: [u8; 4],
    prepared: [u8; MAX_ENCRYPTED],
    prepared_len: u8,
}

impl Default for PeripheralStart {
    fn default() -> Self {
        Self::new()
    }
}

impl PeripheralStart {
    pub const fn new() -> Self {
        Self {
            stage: StartStage::Idle,
            req: None,
            skds: [0; 8],
            ivs: [0; 4],
            prepared: [0; MAX_ENCRYPTED],
            prepared_len: 0,
        }
    }

    pub fn stage(&self) -> StartStage {
        self.stage
    }

    /// Abandon the procedure, e.g. after the Host rejected the LTK. The link
    /// then answers `LL_ENC_REQ` with `LL_REJECT_IND` and ends; a later
    /// `LL_ENC_REQ` starts from [`StartStage::Idle`] again.
    pub fn abort(&mut self) {
        self.stage = StartStage::Idle;
        self.req = None;
        self.prepared_len = 0;
    }

    pub fn is_active(&self) -> bool {
        self.stage == StartStage::Active
    }

    pub fn enc_req(&self) -> Option<&EncReq> {
        self.req.as_ref()
    }

    /// Parse the Central's `LL_ENC_REQ` and produce the plaintext response.
    ///
    /// `skds` and `ivs` must come from the controller's random source. The
    /// caller sends the returned PDU and asks the Host for the LTK.
    pub fn on_enc_req(
        &mut self,
        payload: &[u8],
        skds: [u8; 8],
        ivs: [u8; 4],
    ) -> Result<ControlPdu, StartError> {
        if self.stage != StartStage::Idle {
            return Err(StartError::NotIdle);
        }
        let req = EncReq::parse(payload).map_err(|error| match error {
            super::conn::ConnError::Length => StartError::Length,
            _ => StartError::Opcode,
        })?;
        self.req = Some(req);
        self.skds = skds;
        self.ivs = ivs;
        self.stage = StartStage::AwaitingKey;
        Ok(ControlPdu::enc_rsp(&EncRsp { skds, ivs }))
    }

    /// Derive the session key from the Host's LTK and the stored exchange.
    pub fn session(&self, ltk: &[u8; 16]) -> Result<SessionKey, StartError> {
        if !matches!(self.stage, StartStage::AwaitingKey | StartStage::Prepared) {
            return Err(StartError::NotReady);
        }
        let req = self.req.as_ref().ok_or(StartError::NotReady)?;
        Ok(SessionKey::from_parts(
            ltk, &req.skdm, &self.skds, &req.ivm, &self.ivs,
        ))
    }

    /// Precompute the encrypted `LL_START_ENC_RSP` (TX counter 0).
    pub fn prepare_start_rsp<E: AesEngine>(
        &mut self,
        enc: &mut Encryption<E>,
    ) -> Result<(), StartError> {
        if self.stage != StartStage::AwaitingKey {
            return Err(StartError::NotReady);
        }
        enc.enable_tx();
        let mut out = [0; MAX_ENCRYPTED];
        // AAD is the masked PDU header first octet: LLID=3 for a control PDU.
        let len = enc.encrypt(3, ControlPdu::start_enc_rsp().as_bytes(), &mut out)?;
        self.prepared[..len].copy_from_slice(&out[..len]);
        self.prepared_len = len as u8;
        self.stage = StartStage::Prepared;
        Ok(())
    }

    /// Send the Peripheral's plaintext `LL_START_ENC_REQ` and enable RX: the
    /// Central's next non-empty PDU is its encrypted `LL_START_ENC_RSP`, the
    /// first encrypted PDU of the link (RX counter 0).
    pub fn start_enc_req<E: AesEngine>(
        &mut self,
        enc: &mut Encryption<E>,
    ) -> Result<ControlPdu, StartError> {
        if self.stage != StartStage::Prepared {
            return Err(StartError::NotReady);
        }
        enc.enable_rx();
        self.stage = StartStage::WaitingRsp;
        Ok(ControlPdu::start_enc_req())
    }

    /// Record that the Central's encrypted `LL_START_ENC_RSP` was decrypted
    /// and return the precomputed encrypted response to send.
    pub fn on_start_enc_rsp(&mut self) -> Result<&[u8], StartError> {
        if self.stage != StartStage::WaitingRsp {
            return Err(StartError::NotReady);
        }
        self.stage = StartStage::Active;
        Ok(&self.prepared[..usize::from(self.prepared_len)])
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

    /// The LTK arrives from the Host as HCI little-endian octets, while every
    /// `SKD`/`IV` field arrives little-endian on the air; Core Vol 6 Part C
    /// §1.2 works on the values most-significant-octet first for the cipher
    /// input (`SKD = SKDs || SKDm`) but on the wire octets for the nonce IV.
    #[test]
    fn session_key_matches_core_sample_data() {
        let ltk = [
            0xbf, 0x01, 0xfb, 0x9d, 0x4e, 0xf3, 0xbc, 0x36, 0xd8, 0x74, 0xf5, 0x39, 0x41, 0x38,
            0x68, 0x4c,
        ];
        let sk = SessionKey::from_parts(
            &ltk,
            &[0x13, 0x02, 0xf1, 0xe0, 0xdf, 0xce, 0xbd, 0xac],
            &[0x79, 0x68, 0x57, 0x46, 0x35, 0x24, 0x13, 0x02],
            &[0x24, 0xab, 0xdc, 0xba],
            &[0xbe, 0xba, 0xaf, 0xde],
        );
        assert_eq!(
            sk.key(),
            &[
                0x99, 0xad, 0x1b, 0x52, 0x26, 0xa3, 0x7e, 0x3e, 0x05, 0x8e, 0x3b, 0x8e, 0x27, 0xc2,
                0xc6, 0x66,
            ]
        );
        assert_eq!(sk.iv(), &[0x24, 0xab, 0xdc, 0xba, 0xbe, 0xba, 0xaf, 0xde]);
    }

    /// First encrypted PDU of each direction from the same sample data.
    #[test]
    fn start_enc_rsp_matches_core_sample_data() {
        let ltk = [
            0xbf, 0x01, 0xfb, 0x9d, 0x4e, 0xf3, 0xbc, 0x36, 0xd8, 0x74, 0xf5, 0x39, 0x41, 0x38,
            0x68, 0x4c,
        ];
        let sk = SessionKey::from_parts(
            &ltk,
            &[0x13, 0x02, 0xf1, 0xe0, 0xdf, 0xce, 0xbd, 0xac],
            &[0x79, 0x68, 0x57, 0x46, 0x35, 0x24, 0x13, 0x02],
            &[0x24, 0xab, 0xdc, 0xba],
            &[0xbe, 0xba, 0xaf, 0xde],
        );
        let mut out = [0; MAX_ENCRYPTED];

        let mut central = Encryption::new(sk.clone(), EncRole::Central, Aes128::new(sk.key()));
        central.enable_tx();
        let len = central
            .encrypt(0x03, ControlPdu::start_enc_rsp().as_bytes(), &mut out)
            .unwrap();
        assert_eq!(&out[..len], &[0x9f, 0xcd, 0xa7, 0xf4, 0x48]);

        let mut peripheral =
            Encryption::new(sk.clone(), EncRole::Peripheral, Aes128::new(sk.key()));
        peripheral.enable_tx();
        let len = peripheral
            .encrypt(0x03, ControlPdu::start_enc_rsp().as_bytes(), &mut out)
            .unwrap();
        assert_eq!(&out[..len], &[0xa3, 0x4c, 0x13, 0xa4, 0x15]);
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
                0x9c, 0x9e, 0x9f, 0x3d, 0xab, 0x75, 0x3f, 0xdb, 0xc3, 0xe6, 0x8b, 0x2e, 0xea, 0x9a,
                0x7f, 0xa9, 0x26, 0x3a,
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
            &[0xf1, 0x2a, 0xa7, 0x82, 0xd0, 0xc8, 0xff, 0x3f]
        );
        assert_eq!(enc.tx_counter(), 2);
    }

    #[test]
    fn peripheral_direction_bit_zero_vector() {
        let mut enc = peripheral();
        enc.enable_tx();
        let mut out = [0; MAX_ENCRYPTED];
        let len = enc.encrypt(0x03, &[0x0a, 0x0b, 0x0c], &mut out).unwrap();
        assert_eq!(&out[..len], &[0xf6, 0x67, 0xe6, 0x6f, 0x9f, 0xb6, 0x77]);
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
    fn one_acl_fragment_of_plaintext_round_trips() {
        // An Android Central fragments its L2CAP PDUs at 24 octets and sends
        // them encrypted without DLE: 28 octets on air. Both directions must
        // handle that size even though it exceeds the legacy 27-octet PDU.
        let mut tx = central();
        tx.enable_tx();
        let mut wire = [0; MAX_ENCRYPTED];
        let plaintext = [0xa5; 24];
        let len = tx.encrypt(0x02, &plaintext, &mut wire).unwrap();
        assert_eq!(len, 24 + BLE_MIC_LEN);
        let mut rx = peripheral();
        rx.enable_rx();
        let mut plain = [0; MAX_PLAINTEXT];
        assert_eq!(rx.decrypt(0x02, &wire[..len], &mut plain), Ok(24));
        assert_eq!(&plain[..24], &plaintext);
    }

    #[test]
    fn dle_maximum_plaintext_round_trips() {
        let mut tx = central();
        tx.enable_tx();
        let mut wire = [0; MAX_ENCRYPTED];
        let plaintext = [0x5a; MAX_PLAINTEXT];
        let len = tx.encrypt(0x02, &plaintext, &mut wire).unwrap();
        assert_eq!(len, MAX_ENCRYPTED);
        assert_eq!(len, 251);
        let mut rx = peripheral();
        rx.enable_rx();
        let mut plain = [0; MAX_PLAINTEXT];
        assert_eq!(rx.decrypt(0x02, &wire[..len], &mut plain), Ok(247));
        assert_eq!(&plain, &plaintext);
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
    fn largest_legacy_payload_round_trips_with_the_mic_on_air() {
        let mut tx = central();
        tx.enable_tx();
        let mut rx = peripheral();
        rx.enable_rx();
        let plaintext: [u8; MAX_PLAINTEXT] = core::array::from_fn(|i| i as u8);
        let mut out = [0; MAX_ENCRYPTED];
        let len = tx.encrypt(0x02, &plaintext, &mut out).unwrap();
        assert_eq!(len, MAX_ENCRYPTED);
        let mut back = [0; MAX_PLAINTEXT];
        assert_eq!(rx.decrypt(0x02, &out[..len], &mut back), Ok(MAX_PLAINTEXT));
        assert_eq!(back, plaintext);
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
    /// Core 5.4 Vol 6 Part B §5.1.3.1: the Peripheral sends the plaintext
    /// `LL_START_ENC_REQ`; the Central's `LL_START_ENC_RSP` is the first
    /// encrypted PDU of the link.
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
        let mut start = PeripheralStart::new();
        let rsp = EncRsp {
            skds: SKDS,
            ivs: IVS,
        };
        let rsp_bytes = start
            .on_enc_req(req_bytes.as_bytes(), SKDS, IVS)
            .unwrap();
        assert_eq!(rsp_bytes.as_bytes(), ControlPdu::enc_rsp(&rsp).as_bytes());
        assert_eq!(start.stage(), StartStage::AwaitingKey);

        // Both sides derive the same session key.
        let c_key = SessionKey::from_parts(&LTK, &req.skdm, &rsp.skds, &req.ivm, &rsp.ivs);
        let p_key = start.session(&LTK).unwrap();
        assert_eq!(c_key.key(), p_key.key());
        assert_eq!(c_key.iv(), p_key.iv());

        let c_engine = Aes128::new(c_key.key());
        let p_engine = Aes128::new(p_key.key());
        let mut c_enc = Encryption::new(c_key, EncRole::Central, c_engine);
        let mut p_enc = Encryption::new(p_key, EncRole::Peripheral, p_engine);
        // Central receives the Peripheral's encrypted RSP next.
        c_enc.enable_rx();

        // The Peripheral precomputes its encrypted response (TX counter 0).
        start.prepare_start_rsp(&mut p_enc).unwrap();
        assert_eq!(start.stage(), StartStage::Prepared);

        // 3. Peripheral -> LL_START_ENC_REQ (unencrypted); RX starts now.
        let pdu = start.start_enc_req(&mut p_enc).unwrap();
        assert_eq!(pdu.as_bytes(), &[0x05]);
        assert_eq!(start.stage(), StartStage::WaitingRsp);
        assert!(p_enc.rx_enabled());

        // 4. Central -> encrypted LL_START_ENC_RSP (TX counter 0).
        c_enc.enable_tx();
        let mut ccm_out = [0; MAX_ENCRYPTED];
        let rsp_pt = ControlPdu::start_enc_rsp();
        let len = c_enc
            .encrypt(0x03, rsp_pt.as_bytes(), &mut ccm_out)
            .unwrap();
        assert_eq!(len, 5);
        let mut plain = [0; MAX_PLAINTEXT];
        let n = p_enc.decrypt(0x03, &ccm_out[..len], &mut plain).unwrap();
        assert_eq!(&plain[..n], rsp_pt.as_bytes());

        // 5. Peripheral -> precomputed encrypted LL_START_ENC_RSP (TX counter 0).
        let mut prepared = [0; MAX_ENCRYPTED];
        let prepared_len = {
            let bytes = start.on_start_enc_rsp().unwrap();
            prepared[..bytes.len()].copy_from_slice(bytes);
            bytes.len()
        };
        assert_eq!(start.stage(), StartStage::Active);
        let n = c_enc
            .decrypt(0x03, &prepared[..prepared_len], &mut plain)
            .unwrap();
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

    #[test]
    fn peripheral_start_sequence_matches_central() {
        let req = EncReq {
            rand: [0; 8],
            ediv: 0,
            skdm: SKDM,
            ivm: IVM,
        };
        let mut start = PeripheralStart::new();
        let rsp = start
            .on_enc_req(ControlPdu::enc_req(&req).as_bytes(), SKDS, IVS)
            .unwrap();
        assert_eq!(
            rsp.as_bytes(),
            ControlPdu::enc_rsp(&EncRsp {
                skds: SKDS,
                ivs: IVS
            })
            .as_bytes()
        );
        assert_eq!(start.stage(), StartStage::AwaitingKey);
        assert_eq!(start.enc_req(), Some(&req));

        let c_key = SessionKey::from_parts(&LTK, &SKDM, &SKDS, &IVM, &IVS);
        let p_key = start.session(&LTK).unwrap();
        let p_engine = Aes128::new(p_key.key());
        let mut p_enc = Encryption::new(p_key, EncRole::Peripheral, p_engine);
        start.prepare_start_rsp(&mut p_enc).unwrap();
        assert_eq!(start.stage(), StartStage::Prepared);
        assert!(p_enc.tx_enabled());
        assert_eq!(p_enc.tx_counter(), 1);

        let c_engine = Aes128::new(c_key.key());
        let mut c_enc = Encryption::new(c_key, EncRole::Central, c_engine);
        c_enc.enable_rx();
        // Peripheral sends the plaintext LL_START_ENC_REQ and starts RX.
        let pdu = start.start_enc_req(&mut p_enc).unwrap();
        assert_eq!(pdu.as_bytes(), &[0x05]);
        assert_eq!(start.stage(), StartStage::WaitingRsp);
        assert!(p_enc.rx_enabled());

        // Central's encrypted response is the link's first encrypted PDU.
        c_enc.enable_tx();
        let mut ccm_out = [0; MAX_ENCRYPTED];
        let mut plain = [0; MAX_PLAINTEXT];
        let len = c_enc
            .encrypt(0x03, ControlPdu::start_enc_rsp().as_bytes(), &mut ccm_out)
            .unwrap();
        assert_eq!(p_enc.decrypt(0x03, &ccm_out[..len], &mut plain), Ok(1));
        assert_eq!(plain[0], 0x06);

        // The precomputed response is handed back for the next event.
        let mut prepared_copy = [0; MAX_ENCRYPTED];
        let prepared_len = {
            let prepared = start.on_start_enc_rsp().unwrap();
            prepared_copy[..prepared.len()].copy_from_slice(prepared);
            prepared.len()
        };
        assert_eq!(prepared_len, 5);
        assert!(start.is_active());
        assert_eq!(start.on_start_enc_rsp(), Err(StartError::NotReady));
        let n = c_enc
            .decrypt(0x03, &prepared_copy[..prepared_len], &mut plain)
            .unwrap();
        assert_eq!(&plain[..n], &[0x06]);
    }

    #[test]
    fn peripheral_start_enforces_order_and_rejects_duplicates() {
        let mut start = PeripheralStart::new();
        let req = ControlPdu::enc_req(&EncReq {
            rand: [0; 8],
            ediv: 0,
            skdm: SKDM,
            ivm: IVM,
        });
        assert_eq!(
            start.on_enc_req(&[0x03], SKDS, IVS),
            Err(StartError::Length)
        );
        assert_eq!(
            start.on_enc_req(&[0x04; 23], SKDS, IVS),
            Err(StartError::Opcode)
        );
        start.on_enc_req(req.as_bytes(), SKDS, IVS).unwrap();
        assert_eq!(
            start.on_enc_req(req.as_bytes(), SKDS, IVS),
            Err(StartError::NotIdle)
        );
        assert_eq!(start.prepare_start_rsp(&mut peripheral()), Ok(()));
        assert_eq!(
            start.start_enc_req(&mut peripheral()).unwrap().as_bytes(),
            &[0x05]
        );
        assert_eq!(start.on_start_enc_rsp().unwrap().len(), 5);
        assert!(start.is_active());
    }
}
