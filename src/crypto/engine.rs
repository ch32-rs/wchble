//! AES-128 block engine boundary.
//!
//! AES-CCM only ever needs forward AES blocks (CBC-MAC and CTR both encrypt),
//! so the boundary is deliberately smaller than a general cipher API. The
//! software [`Aes128`] holds its round keys; the CH585 hardware engine keeps
//! the key loaded in the peripheral and pays only the block cost per call.
//!
//! Callers construct the engine once per session key and reuse it for every
//! block of the session. Constructing a software engine expands the key
//! (~116 us on CH585); constructing the hardware engine writes the key once.

use super::aes::Aes128;

/// A block engine failed to complete. On CH585 this means the AES peripheral
/// did not clear its busy bit; the session must not use the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AesEngineError {
    Timeout,
}

pub trait AesEngine {
    /// Re-establish the loaded key before a CCM operation.
    ///
    /// Engines whose key lives in registers shared with another owner must
    /// reload it here: the CH585 AES block sits in the RF IP, and every
    /// connection event leaves it without the session key. Software engines
    /// keep their round keys and leave the default no-op.
    fn reload(&mut self) {}

    /// Encrypt one 16-byte block in place with the engine's loaded key.
    fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), AesEngineError>;
}

impl AesEngine for Aes128 {
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), AesEngineError> {
        Aes128::encrypt_block(self, block);
        Ok(())
    }
}
