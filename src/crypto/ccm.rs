//! AES-CCM as used by BLE (L=2, MIC 4 octets by default).
//!
//! The implementation is parameterised over the MIC length `M` so the RFC 3610
//! known-answer vectors (M=8) exercise the same code path BLE uses (M=4).
//! BLE fixes the counter length to 2 octets (`L=2`), so messages are at most
//! 65535 octets; longer input is rejected instead of silently truncated.
//!
//! No allocations: callers provide the output slice and a fixed-size MIC.

use super::aes::Aes128;

/// BLE MIC length (Core Vol 6 Part E).
pub const BLE_MIC_LEN: usize = 4;
/// BLE nonce length (39-bit counter + direction bit + 64-bit IV).
pub const BLE_NONCE_LEN: usize = 13;
/// Counter length for BLE CCM.
pub const BLE_L: usize = 2;

const BLOCK: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcmError {
    /// `M` outside 4..=16 or odd.
    BadMicLen,
    /// Message or AAD too long for L=2.
    TooLong,
    /// Output slice shorter than the plaintext / ciphertext.
    BufferTooSmall,
    /// Authentication failed on decrypt.
    AuthFailed,
}

/// Encrypt `plaintext` under `nonce` and `aad`, writing the ciphertext to
/// `out` and the MIC to `mic`. `out.len()` must be at least `plaintext.len()`.
pub fn encrypt<const M: usize>(
    aes: &Aes128,
    nonce: &[u8; BLE_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut [u8],
    mic: &mut [u8; M],
) -> Result<(), CcmError> {
    validate::<M>(aad, plaintext, out)?;
    let (mac, s0) = mac_and_s0::<M>(aes, nonce, aad, plaintext)?;
    ctr(aes, nonce, plaintext, out);
    for i in 0..M {
        mic[i] = mac[i] ^ s0[i];
    }
    Ok(())
}

/// Decrypt `ciphertext` under `nonce` and `aad`, writing plaintext to `out`
/// and verifying `mic`. On [`CcmError::AuthFailed`] `out` contains the
/// unauthenticated plaintext and must be discarded by the caller.
pub fn decrypt<const M: usize>(
    aes: &Aes128,
    nonce: &[u8; BLE_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    mic: &[u8; M],
    out: &mut [u8],
) -> Result<(), CcmError> {
    validate::<M>(aad, ciphertext, out)?;
    // CCM authenticates the plaintext, so decrypt first, then MAC.
    ctr(aes, nonce, ciphertext, out);
    let (mut mac, s0) = mac_and_s0::<M>(aes, nonce, aad, &out[..ciphertext.len()])?;
    for i in 0..M {
        mac[i] ^= s0[i];
    }
    // Constant-time compare; a MIC mismatch is an attack signal, not a bug.
    let mut diff = 0u8;
    for i in 0..M {
        diff |= mac[i] ^ mic[i];
    }
    if diff != 0 {
        return Err(CcmError::AuthFailed);
    }
    Ok(())
}

fn validate<const M: usize>(aad: &[u8], msg: &[u8], out: &[u8]) -> Result<(), CcmError> {
    if M < 4 || M > 16 || M % 2 != 0 {
        return Err(CcmError::BadMicLen);
    }
    if msg.len() > 0xffff || aad.len() >= 0xff00 {
        return Err(CcmError::TooLong);
    }
    if out.len() < msg.len() {
        return Err(CcmError::BufferTooSmall);
    }
    Ok(())
}

/// CBC-MAC over `B0 || AAD (length-prefixed, zero padded) || msg`, plus the
/// CTR block `S0` used to mask the MAC.
fn mac_and_s0<const M: usize>(
    aes: &Aes128,
    nonce: &[u8; BLE_NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
) -> Result<([u8; BLOCK], [u8; BLOCK]), CcmError> {
    let msg_len = msg.len();
    if msg_len > 0xffff || aad.len() >= 0xff00 {
        return Err(CcmError::TooLong);
    }

    let mut mac = [0u8; BLOCK];

    // B0: flags | nonce | message length (L=2).
    let mut b = [0u8; BLOCK];
    b[0] = (if aad.is_empty() { 0 } else { 0x40 })
        | ((((M - 2) / 2) as u8) << 3)
        | ((BLE_L - 1) as u8);
    b[1..1 + BLE_NONCE_LEN].copy_from_slice(nonce);
    b[14] = (msg_len >> 8) as u8;
    b[15] = msg_len as u8;
    xor_block(&mut mac, &b);
    aes.encrypt_block(&mut mac);

    // AAD: 2-octet length prefix, then the bytes, zero padded.
    if !aad.is_empty() {
        let mut block = [0u8; BLOCK];
        block[0] = (aad.len() >> 8) as u8;
        block[1] = aad.len() as u8;
        let first = core::cmp::min(14, aad.len());
        block[2..2 + first].copy_from_slice(&aad[..first]);
        xor_block(&mut mac, &block);
        aes.encrypt_block(&mut mac);
        let mut i = first;
        while i < aad.len() {
            let n = core::cmp::min(BLOCK, aad.len() - i);
            let mut block = [0u8; BLOCK];
            block[..n].copy_from_slice(&aad[i..i + n]);
            xor_block(&mut mac, &block);
            aes.encrypt_block(&mut mac);
            i += n;
        }
    }

    // Message bytes, zero padded.
    let mut i = 0;
    while i < msg.len() {
        let n = core::cmp::min(BLOCK, msg.len() - i);
        let mut block = [0u8; BLOCK];
        block[..n].copy_from_slice(&msg[i..i + n]);
        xor_block(&mut mac, &block);
        aes.encrypt_block(&mut mac);
        i += n;
    }

    // S0 = E(K, A0), A0 = flags | nonce | 0.
    let mut a = [0u8; BLOCK];
    a[0] = (BLE_L - 1) as u8;
    a[1..1 + BLE_NONCE_LEN].copy_from_slice(nonce);
    aes.encrypt_block(&mut a);

    Ok((mac, a))
}

/// CTR mode starting at counter 1.
fn ctr(aes: &Aes128, nonce: &[u8; BLE_NONCE_LEN], input: &[u8], out: &mut [u8]) {
    let mut a = [0u8; BLOCK];
    a[0] = (BLE_L - 1) as u8;
    a[1..1 + BLE_NONCE_LEN].copy_from_slice(nonce);
    let mut counter: u16 = 0;
    let mut i = 0;
    while i < input.len() {
        counter = counter.wrapping_add(1);
        a[14] = (counter >> 8) as u8;
        a[15] = counter as u8;
        let mut s = a;
        aes.encrypt_block(&mut s);
        let n = core::cmp::min(BLOCK, input.len() - i);
        for j in 0..n {
            out[i + j] = input[i + j] ^ s[j];
        }
        i += n;
    }
}

fn xor_block(dst: &mut [u8; BLOCK], src: &[u8; BLOCK]) {
    for i in 0..BLOCK {
        dst[i] ^= src[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Aes128 {
        Aes128::new(&[
            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd,
            0xce, 0xcf,
        ])
    }

    fn nonce() -> [u8; BLE_NONCE_LEN] {
        [
            0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
        ]
    }

    fn aad() -> [u8; 8] {
        [0, 1, 2, 3, 4, 5, 6, 7]
    }

    fn plaintext() -> [u8; 23] {
        [
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        ]
    }

    #[test]
    fn rfc3610_vector_1_encrypt() {
        let expected = [
            0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9,
            0x89, 0x80, 0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84,
        ];
        let expected_mic = [0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0];
        let mut out = [0u8; 23];
        let mut mic = [0u8; 8];
        encrypt(&key(), &nonce(), &aad(), &plaintext(), &mut out, &mut mic).unwrap();
        assert_eq!(out, expected);
        assert_eq!(mic, expected_mic);
    }

    #[test]
    fn rfc3610_vector_1_decrypt() {
        let ct = [
            0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9,
            0x89, 0x80, 0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84,
        ];
        let mic = [0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0];
        let mut out = [0u8; 23];
        decrypt(&key(), &nonce(), &aad(), &ct, &mic, &mut out).unwrap();
        assert_eq!(out, plaintext());
    }

    /// Same inputs as RFC 3610 vector #1 with the BLE MIC length (4 bytes).
    /// The ciphertext is unchanged; the MIC was produced by an independent
    /// AES-CCM implementation (RFC 3610 does not publish an M=4 vector).
    #[test]
    fn ble_mic_len_kat() {
        let mut out = [0u8; 23];
        let mut mic = [0u8; BLE_MIC_LEN];
        encrypt::<BLE_MIC_LEN>(&key(), &nonce(), &aad(), &plaintext(), &mut out, &mut mic).unwrap();
        assert_eq!(
            out,
            [
                0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9,
                0x89, 0x80, 0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84,
            ]
        );
        assert_eq!(mic, [0x50, 0x19, 0x8b, 0xbc]);
    }

    #[test]
    fn empty_message_kat() {
        let mut mic = [0u8; BLE_MIC_LEN];
        encrypt::<BLE_MIC_LEN>(&key(), &[0u8; BLE_NONCE_LEN], &[], &[], &mut [], &mut mic).unwrap();
        assert_eq!(mic, [0x5a, 0xaa, 0x6f, 0xc4]);
    }

    #[test]
    fn tampered_mic_is_rejected() {
        let ct = [
            0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9,
            0x89, 0x80, 0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84,
        ];
        let mut mic = [0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0];
        mic[3] ^= 0x80;
        let mut out = [0u8; 23];
        assert_eq!(
            decrypt(&key(), &nonce(), &aad(), &ct, &mic, &mut out),
            Err(CcmError::AuthFailed)
        );
    }

    #[test]
    fn round_trip_ble_mic_len() {
        let aes = Aes128::new(&[0x11; 16]);
        let nonce = [0x42; BLE_NONCE_LEN];
        let pt = [0xab; 37];
        let mut ct = [0u8; 37];
        let mut mic = [0u8; BLE_MIC_LEN];
        emit_round_trip(&aes, &nonce, &pt, &mut ct, &mut mic);
    }

    fn emit_round_trip(
        aes: &Aes128,
        nonce: &[u8; BLE_NONCE_LEN],
        pt: &[u8; 37],
        ct: &mut [u8; 37],
        mic: &mut [u8; BLE_MIC_LEN],
    ) {
        encrypt::<BLE_MIC_LEN>(aes, nonce, &[0x03, 0x00], pt, ct, mic).unwrap();
        let mut back = [0u8; 37];
        decrypt::<BLE_MIC_LEN>(aes, nonce, &[0x03, 0x00], ct, mic, &mut back).unwrap();
        assert_eq!(&back, pt);
    }
}
