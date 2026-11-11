//! Cryptographic primitives used by the controller.
//!
//! S0 provides the software AES-128 core and AES-CCM so S1 can build LE
//! encryption without depending on the unverified CH585 AES block. Everything
//! here is `no_std`, allocation-free and covered by known-answer tests.

pub mod aes;
pub mod ccm;
