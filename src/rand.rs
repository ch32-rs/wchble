//! Entropy conditioning and a ChaCha20-based DRBG.
//!
//! S0 needs two things the controller did not have: a real random source for
//! `HCI_LE_Rand` / AA / CRCInit, and an honest description of its strength.
//! This module provides the deterministic half:
//!
//! - [`EntropyPool`] conditions raw platform samples (timer jitter, ADC noise)
//!   into a 32-byte seed with one ChaCha20 block. It does not create entropy;
//!   callers must add samples from a source they have measured.
//! - [`ChaCha20Drbg`] expands that seed with the RFC 8439 ChaCha20 block
//!   function. It rekeys from an unexposed keystream block every
//!   `REKEY_BLOCKS` blocks so the generator never runs into the 32-bit
//!   counter limit.
//!
//! The DRBG is only as good as the seed. Platform code must label an unseeded
//! instance as such; `SoftRunner::set_entropy_seed` records whether a seed was
//! supplied.

/// Seed length consumed by [`ChaCha20Drbg`].
pub const SEED_LEN: usize = 32;

/// Number of raw samples the pool holds before wrapping.
pub const SAMPLE_SLOTS: usize = 32;

/// ChaCha20 block function (RFC 8439 §2.3): 64 keystream bytes for
/// `counter`/`nonce` under `key`.
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[4 * i],
            nonce[4 * i + 1],
            nonce[4 * i + 2],
            nonce[4 * i + 3],
        ]);
    }

    let initial = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].wrapping_add(initial[i]).to_le_bytes());
    }
    out
}

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

#[cfg(not(test))]
const REKEY_BLOCKS: u32 = 1 << 20;
#[cfg(test)]
const REKEY_BLOCKS: u32 = 8;

/// ChaCha20 keystream generator seeded by entropy.
#[derive(Clone)]
pub struct ChaCha20Drbg {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
}

impl core::fmt::Debug for ChaCha20Drbg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChaCha20Drbg")
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl ChaCha20Drbg {
    /// Seed with a 32-byte secret and a 12-byte nonce.
    pub fn new(seed: &[u8; SEED_LEN], nonce: &[u8; 12]) -> Self {
        Self {
            key: *seed,
            nonce: *nonce,
            counter: 0,
        }
    }

    /// Seed with a 32-byte secret and a zero nonce.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self::new(seed, &[0u8; 12])
    }

    /// Replace the key with fresh entropy. The caller must supply a seed that
    /// differs from the previous one; this method detects identical seeds so a
    /// HAL cannot silently "reseed" with the same buffer.
    pub fn reseed(&mut self, seed: &[u8; SEED_LEN]) -> bool {
        if seed == &self.key {
            return false;
        }
        self.key = *seed;
        self.nonce = [0u8; 12];
        self.counter = 0;
        true
    }

    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    fn rekey(&mut self) {
        // Consume a block that is not handed to the caller, so the next state
        // is not derivable from any published output.
        let block = chacha20_block(&self.key, self.counter, &self.nonce);
        self.key.copy_from_slice(&block[..32]);
        self.nonce.copy_from_slice(&block[32..44]);
        self.counter = 0;
    }

    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    fn next_block(&mut self) -> [u8; 64] {
        if self.counter >= REKEY_BLOCKS {
            self.rekey();
        }
        let block = chacha20_block(&self.key, self.counter, &self.nonce);
        self.counter += 1;
        block
    }

    /// Fill `out` with keystream. Bytes from a partially used block are
    /// discarded at the end of the call, so a short request advances the
    /// generator by a whole block.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(64) {
            let block = self.next_block();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }

    /// One 32-bit value for LL access addresses / CRCInit.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }
}

/// Accumulates raw platform samples and conditions them into a seed.
///
/// The mixing step is deterministic and public: it is a conditioner, not an
/// entropy source. A pool with no samples produces a fixed, public seed.
#[derive(Debug, Clone)]
pub struct EntropyPool {
    samples: [u32; SAMPLE_SLOTS],
    count: u32,
    min_sample: u32,
    max_sample: u32,
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyPool {
    pub const fn new() -> Self {
        Self {
            samples: [0; SAMPLE_SLOTS],
            count: 0,
            min_sample: u32::MAX,
            max_sample: 0,
        }
    }

    /// Absorb one raw sample. Samples wrap around the slot array, so a long
    /// run keeps mixing instead of saturating.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    pub fn add_sample(&mut self, sample: u32) {
        let i = (self.count as usize) % SAMPLE_SLOTS;
        self.samples[i] = self.samples[i].wrapping_mul(0x9e37_79b9).rotate_left(5) ^ sample;
        self.min_sample = self.min_sample.min(sample);
        self.max_sample = self.max_sample.max(sample);
        self.count = self.count.wrapping_add(1);
    }

    pub fn sample_count(&self) -> u32 {
        self.count
    }

    /// Raw range of the samples seen so far; `None` before the first sample.
    ///
    /// Health check for platforms: a stuck ADC or a dead timer collapses the
    /// range to zero (or one count) no matter how many samples are taken.
    pub fn raw_range(&self) -> Option<(u32, u32)> {
        (self.count != 0).then_some((self.min_sample, self.max_sample))
    }

    /// Condition the accumulated samples into a 32-byte seed.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    pub fn seed(&self) -> [u8; SEED_LEN] {
        // Fold all slots into the 8 key words so every sample reaches the
        // conditioner, then run one ChaCha20 block over the result.
        let mut words = [0u32; 8];
        for (i, &sample) in self.samples.iter().enumerate() {
            let lane = i & 7;
            words[lane] = words[lane]
                .wrapping_add(sample.rotate_left((i as u32) & 31))
                .wrapping_mul(0x9e37_79b9);
        }
        let mut key = [0u8; 32];
        for (i, word) in words.iter().enumerate() {
            key[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
        }
        // Domain separation keeps pool seeds distinct from raw DRBG blocks;
        // the count is mixed in so partial blocks are context-bound.
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.count.to_le_bytes());
        nonce[4..8].copy_from_slice(b"wchb");
        let block = chacha20_block(&key, 0, &nonce);
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(&block[..SEED_LEN]);
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc8439_block_kat() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce: [u8; 12] = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(
            block,
            hex64(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
                 d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            )
        );
    }

    #[test]
    fn zero_state_block() {
        let block = chacha20_block(&[0u8; 32], 0, &[0u8; 12]);
        assert_eq!(
            block,
            hex64(
                "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
                 da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
            )
        );
    }

    #[test]
    fn drbg_stream_is_block_chained() {
        let mut drbg = ChaCha20Drbg::from_seed(&[0u8; 32]);
        let mut out = [0u8; 128];
        drbg.fill(&mut out);
        let b0 = chacha20_block(&[0u8; 32], 0, &[0u8; 12]);
        let b1 = chacha20_block(&[0u8; 32], 1, &[0u8; 12]);
        assert_eq!(&out[..64], &b0);
        assert_eq!(&out[64..], &b1);
    }

    #[test]
    fn short_fill_advances_a_whole_block() {
        let mut drbg = ChaCha20Drbg::from_seed(&[7u8; 32]);
        let mut first = [0u8; 1];
        let mut second = [0u8; 1];
        drbg.fill(&mut first);
        drbg.fill(&mut second);
        let b0 = chacha20_block(&[7u8; 32], 0, &[0u8; 12]);
        let b1 = chacha20_block(&[7u8; 32], 1, &[0u8; 12]);
        assert_eq!(first[0], b0[0]);
        assert_eq!(second[0], b1[0]);
    }

    #[test]
    fn consecutive_outputs_differ() {
        let mut drbg = ChaCha20Drbg::from_seed(&[0x42; 32]);
        let a = drbg.next_u32();
        let b = drbg.next_u32();
        let c = drbg.next_u32();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn reseed_changes_stream_and_rejects_same_seed() {
        let seed = [3u8; 32];
        let mut drbg = ChaCha20Drbg::from_seed(&seed);
        let mut before = [0u8; 8];
        drbg.fill(&mut before);
        assert!(!drbg.reseed(&seed));
        let other = [4u8; 32];
        assert!(drbg.reseed(&other));
        let mut after = [0u8; 8];
        drbg.fill(&mut after);
        let mut fresh = ChaCha20Drbg::from_seed(&other);
        let mut fresh_out = [0u8; 8];
        fresh.fill(&mut fresh_out);
        assert_eq!(after, fresh_out);
        assert_ne!(before, after);
    }

    #[test]
    fn rekey_keeps_output_distinct() {
        let mut drbg = ChaCha20Drbg::from_seed(&[0x5a; 32]);
        let mut blocks = [[0u8; 64]; 20];
        for block in &mut blocks {
            drbg.fill(block);
        }
        // 20 blocks cross the (test) rekey threshold at 8; no block repeats.
        for i in 0..blocks.len() {
            for j in (i + 1)..blocks.len() {
                assert_ne!(blocks[i], blocks[j]);
            }
        }
    }

    #[test]
    fn pool_depends_on_samples() {
        let mut a = EntropyPool::new();
        let mut b = EntropyPool::new();
        for i in 0..8u32 {
            a.add_sample(0x1000 + i * 7);
            b.add_sample(0x2000 + i * 13);
        }
        assert_eq!(a.sample_count(), 8);
        assert_ne!(a.seed(), b.seed());
    }

    #[test]
    fn raw_range_tracks_samples() {
        let mut pool = EntropyPool::new();
        assert_eq!(pool.raw_range(), None);
        for sample in [7u32, 3, 9, 9] {
            pool.add_sample(sample);
        }
        assert_eq!(pool.raw_range(), Some((3, 9)));
    }

    #[test]
    fn empty_pool_seed_is_stable() {
        let pool = EntropyPool::new();
        assert_eq!(pool.seed(), EntropyPool::new().seed());
        assert_ne!(pool.seed(), [0u8; 32]);
    }

    #[test]
    fn sample_order_matters() {
        let mut a = EntropyPool::new();
        let mut b = EntropyPool::new();
        a.add_sample(1);
        a.add_sample(2);
        b.add_sample(2);
        b.add_sample(1);
        assert_ne!(a.seed(), b.seed());
    }
}
