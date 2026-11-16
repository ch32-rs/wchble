//! Resolvable Private Address generation and peer resolution.
//!
//! Byte order: addresses are on-air/little-endian (`[0]` is the LSB octet);
//! IRKs are the `to_le_bytes` form used by `bt-hci` and the bond store.
//! Feeding AES therefore needs both reversed.

use crate::crypto::aes::Aes128;

pub const MAX_RESOLVING_LIST: usize = 8;
pub const MAX_FILTER_ACCEPT_LIST: usize = 8;
/// 900 s, the default in the privacy spec.
pub const DEFAULT_TIMEOUT_US: u32 = 900_000_000;

/// `PrivacyStats::flags` bits.
pub mod flags {
    pub const RESOLUTION_ENABLED: u8 = 0x01;
    pub const LOCAL_IRK: u8 = 0x02;
    pub const ADV_USES_RPA: u8 = 0x04;
    pub const IDENTITY_FALLBACK: u8 = 0x08;
    pub const FAL_NONEMPTY: u8 = 0x10;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyError {
    InvalidKind,
    InvalidIdentity,
    NoSpace,
    NotFound,
    KeyConflict,
}

/// One resolving-list entry; keys are redacted in `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ResolvingEntry {
    pub peer_kind: u8,
    pub peer_address: [u8; 6],
    pub peer_irk: [u8; 16],
    pub local_irk: [u8; 16],
    pub privacy_mode: u8,
}

impl ResolvingEntry {
    pub const fn empty() -> Self {
        Self {
            peer_kind: 0,
            peer_address: [0; 6],
            peer_irk: [0; 16],
            local_irk: [0; 16],
            privacy_mode: 1,
        }
    }

    fn is_default(&self) -> bool {
        self.peer_kind == 0 && self.peer_address == [0; 6] && self.peer_irk == [0; 16]
    }
}

impl core::fmt::Debug for ResolvingEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResolvingEntry")
            .field("peer_kind", &self.peer_kind)
            .field("peer_address", &self.peer_address)
            .field("peer_irk", &"<redacted>")
            .field("local_irk", &"<redacted>")
            .field("privacy_mode", &self.privacy_mode)
            .finish()
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PrivacyStats {
    pub generations: u32,
    pub rotations: u32,
    pub resolve_attempts: u32,
    pub resolve_ok: u32,
    pub resolve_unresolved: u32,
    pub rejected_not_listed: u32,
    pub rejected_mode: u32,
    pub rotated_at_us: u32,
    pub rpa: [u8; 6],
    pub list_len: u8,
    pub adv_filter_policy: u8,
    pub flags: u8,
    pub last_error: u8,
    pub stamp_valid: bool,
}

impl core::fmt::Debug for Privacy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Privacy")
            .field("len", &self.len())
            .field("local_irk", &self.local_table.is_some())
            .field("rpa", &self.rpa)
            .field("enabled", &self.resolution_enabled)
            .field("fal_len", &self.fal_len)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for PrivacyStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivacyStats")
            .field("generations", &self.generations)
            .field("rotations", &self.rotations)
            .field("resolve_attempts", &self.resolve_attempts)
            .field("resolve_ok", &self.resolve_ok)
            .field("resolve_unresolved", &self.resolve_unresolved)
            .field("rejected_not_listed", &self.rejected_not_listed)
            .field("rejected_mode", &self.rejected_mode)
            .field("rotated_at_us", &self.rotated_at_us)
            .field("rpa", &self.rpa)
            .field("list_len", &self.list_len)
            .field("adv_filter_policy", &self.adv_filter_policy)
            .field("flags", &self.flags)
            .field("last_error", &self.last_error)
            .field("stamp_valid", &self.stamp_valid)
            .finish()
    }
}

/// Result of one RF-loop call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Poll {
    Idle,
    Generated,
    /// The random bytes produced an illegal prand; call again with new ones.
    InvalidRandom,
}

/// `ah(IRK, prand)`; both arguments and the result are in on-air byte order.
pub fn ah(irk: &[u8; 16], prand: [u8; 3]) -> [u8; 3] {
    ah_with(&Aes128::new(&aes_key(irk)), prand)
}

fn aes_key(irk: &[u8; 16]) -> [u8; 16] {
    let mut key = *irk;
    key.reverse();
    key
}

fn ah_with(table: &Aes128, prand: [u8; 3]) -> [u8; 3] {
    let mut block = [0u8; 16];
    block[13] = prand[2];
    block[14] = prand[1];
    block[15] = prand[0];
    table.encrypt_block(&mut block);
    [block[15], block[14], block[13]]
}

/// True when the address carries the resolvable-private `01` type bits.
pub fn is_resolvable(address: [u8; 6]) -> bool {
    address[5] & 0xc0 == 0x40
}

/// Builds a legal prand (top two bits `01`, the other 22 not all 0/all 1).
pub fn prand_from(random: [u8; 3]) -> Option<[u8; 3]> {
    let mut prand = random;
    prand[2] = (prand[2] & 0x3f) | 0x40;
    let low = prand[2] & 0x3f;
    if (prand[0] == 0 && prand[1] == 0 && low == 0)
        || (prand[0] == 0xff && prand[1] == 0xff && low == 0x3f)
    {
        None
    } else {
        Some(prand)
    }
}

/// Full 48-bit RPA from a legal prand.
pub fn rpa_from(irk: &[u8; 16], prand: [u8; 3]) -> [u8; 6] {
    let hash = ah(irk, prand);
    [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]]
}

pub struct Privacy {
    entries: [ResolvingEntry; MAX_RESOLVING_LIST],
    used: u8,
    tables: [Option<Aes128>; MAX_RESOLVING_LIST],
    local_irk: [u8; 16],
    local_table: Option<Aes128>,
    rpa: Option<[u8; 6]>,
    stamp_valid: bool,
    rotated_at_us: u32,
    timeout_us: u32,
    resolution_enabled: bool,
    own_addr_type: u8,
    adv_filter_policy: u8,
    fal: [Option<(u8, [u8; 6])>; MAX_FILTER_ACCEPT_LIST],
    fal_len: u8,
    pending: Option<([u8; 6], bool)>,
    cached_identity: Option<(u8, [u8; 6])>,
    generation: u32,
    stats: PrivacyStats,
}

impl Default for Privacy {
    fn default() -> Self {
        Self::new()
    }
}

impl Privacy {
    pub fn new() -> Self {
        Self {
            entries: [ResolvingEntry::empty(); MAX_RESOLVING_LIST],
            used: 0,
            tables: core::array::from_fn(|_| None),
            local_irk: [0; 16],
            local_table: None,
            rpa: None,
            stamp_valid: false,
            rotated_at_us: 0,
            timeout_us: DEFAULT_TIMEOUT_US,
            resolution_enabled: false,
            own_addr_type: 0,
            adv_filter_policy: 0,
            fal: [None; MAX_FILTER_ACCEPT_LIST],
            fal_len: 0,
            pending: None,
            cached_identity: None,
            generation: 0,
            stats: PrivacyStats::default(),
        }
    }

    // ---- resolving list -------------------------------------------------

    pub fn len(&self) -> u8 {
        self.used.count_ones() as u8
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    pub fn list_generation(&self) -> u32 {
        self.generation
    }

    pub fn entry(&self, kind: u8, address: [u8; 6]) -> Option<&ResolvingEntry> {
        self.find(kind, address).map(|slot| &self.entries[slot])
    }

    /// Adds or replaces one entry. Identical parameters are an idempotent hit.
    pub fn add(&mut self, entry: ResolvingEntry) -> Result<(), PrivacyError> {
        if entry.peer_kind > 1 {
            return Err(PrivacyError::InvalidKind);
        }
        if entry.peer_kind == 1 && entry.peer_address[5] & 0xc0 != 0xc0 {
            return Err(PrivacyError::InvalidIdentity);
        }
        let slot = match self.find(entry.peer_kind, entry.peer_address) {
            Some(slot) => slot,
            None => self.free_slot().ok_or(PrivacyError::NoSpace)?,
        };
        if self.prospective_local(Some(slot), Some(&entry)).is_err() {
            return Err(PrivacyError::KeyConflict);
        }
        self.entries[slot] = entry;
        self.used |= 1 << slot;
        self.tables[slot] = if entry.peer_irk == [0; 16] {
            None
        } else {
            Some(Aes128::new(&aes_key(&entry.peer_irk)))
        };
        self.mutated();
        Ok(())
    }

    pub fn remove(&mut self, kind: u8, address: [u8; 6]) -> Result<(), PrivacyError> {
        let slot = self.find(kind, address).ok_or(PrivacyError::NotFound)?;
        self.entries[slot] = ResolvingEntry::empty();
        self.tables[slot] = None;
        self.used &= !(1 << slot);
        self.mutated();
        Ok(())
    }

    pub fn clear(&mut self) {
        self.entries = [ResolvingEntry::empty(); MAX_RESOLVING_LIST];
        self.tables = core::array::from_fn(|_| None);
        self.used = 0;
        // The pending admission belongs to the connection being established,
        // not to the list: a Host that clears and rebuilds the list between
        // CONNECT_IND and its first ACL frame must still get it resolved.
        self.mutated();
    }

    /// Per-entry privacy mode; the target must already be in the list.
    pub fn set_mode(&mut self, kind: u8, address: [u8; 6], mode: u8) -> Result<(), PrivacyError> {
        if mode > 1 {
            return Err(PrivacyError::InvalidIdentity);
        }
        let slot = self.find(kind, address).ok_or(PrivacyError::NotFound)?;
        self.entries[slot].privacy_mode = mode;
        Ok(())
    }

    /// True when this exact identity and peer IRK are in the list.
    pub fn has_peer(&self, kind: u8, address: [u8; 6], peer_irk: &[u8; 16]) -> bool {
        match self.find(kind, address) {
            Some(slot) => self.entries[slot].peer_irk == *peer_irk,
            None => false,
        }
    }

    fn find(&self, kind: u8, address: [u8; 6]) -> Option<usize> {
        (0..MAX_RESOLVING_LIST).find(|&slot| {
            self.used & (1 << slot) != 0
                && self.entries[slot].peer_kind == kind
                && self.entries[slot].peer_address == address
        })
    }

    fn free_slot(&self) -> Option<usize> {
        (0..MAX_RESOLVING_LIST).find(|&slot| self.used & (1 << slot) == 0)
    }

    fn mutated(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.stats.list_len = self.len();
        self.refresh_local();
    }

    // ---- local IRK and address ------------------------------------------

    /// Default entry wins; otherwise all non-zero local IRKs must agree.
    fn prospective_local(
        &self,
        skip: Option<usize>,
        incoming: Option<&ResolvingEntry>,
    ) -> Result<[u8; 16], ()> {
        let mut default: Option<[u8; 16]> = None;
        let mut seen: Option<[u8; 16]> = None;
        let iter = (0..MAX_RESOLVING_LIST)
            .filter(|&slot| self.used & (1 << slot) != 0 && Some(slot) != skip)
            .map(|slot| &self.entries[slot])
            .chain(incoming);
        for entry in iter {
            if entry.is_default() {
                default = Some(entry.local_irk);
            }
            if entry.local_irk != [0; 16] {
                match seen {
                    Some(value) if value != entry.local_irk => return Err(()),
                    Some(_) => {}
                    None => seen = Some(entry.local_irk),
                }
            }
        }
        Ok(default.or(seen).unwrap_or([0; 16]))
    }

    fn refresh_local(&mut self) {
        let irk = match self.prospective_local(None, None) {
            Ok(value) => value,
            Err(()) => {
                self.stats.last_error = 1;
                return;
            }
        };
        let changed = irk != self.local_irk;
        self.local_irk = irk;
        self.local_table = if irk == [0; 16] {
            None
        } else {
            Some(Aes128::new(&aes_key(&irk)))
        };
        self.stats.flags &= !flags::LOCAL_IRK;
        if self.local_table.is_some() {
            self.stats.flags |= flags::LOCAL_IRK;
        }
        if changed {
            self.invalidate_rpa();
        }
    }

    pub fn local_irk(&self) -> Option<[u8; 16]> {
        if self.local_table.is_some() {
            Some(self.local_irk)
        } else {
            None
        }
    }

    fn invalidate_rpa(&mut self) {
        self.rpa = None;
        self.stamp_valid = false;
        self.rotated_at_us = 0;
        self.stats.rpa = [0; 6];
        self.stats.rotated_at_us = 0;
        self.stats.stamp_valid = false;
        self.stats.flags &= !flags::ADV_USES_RPA;
    }

    /// Generates the local RPA if there is none yet.
    pub fn ensure_rpa(&mut self, random: [u8; 3]) -> Option<[u8; 6]> {
        if self.rpa.is_none() {
            let prand = prand_from(random)?;
            self.set_rpa(prand, false);
        }
        self.rpa
    }

    fn set_rpa(&mut self, prand: [u8; 3], rotated: bool) {
        let Some(table) = self.local_table.as_ref() else {
            return;
        };
        let hash = ah_with(table, prand);
        let rpa = [hash[0], hash[1], hash[2], prand[0], prand[1], prand[2]];
        self.rpa = Some(rpa);
        self.stats.rpa = rpa;
        self.stats.generations = self.stats.generations.wrapping_add(1);
        if rotated {
            self.stats.rotations = self.stats.rotations.wrapping_add(1);
        }
        self.stamp_valid = false;
        self.stats.stamp_valid = false;
    }

    /// RF event boundary: rotate when due, otherwise stamp the first time.
    pub fn poll(&mut self, now_us: u32, random: [u8; 3]) -> Poll {
        if self.local_table.is_none() {
            return Poll::Idle;
        }
        let Some(prand) = prand_from(random) else {
            return Poll::InvalidRandom;
        };
        if self.rpa.is_none() {
            self.set_rpa(prand, false);
            return Poll::Generated;
        }
        if !self.stamp_valid {
            self.rotated_at_us = now_us;
            self.stamp_valid = true;
            self.stats.rotated_at_us = now_us;
            self.stats.stamp_valid = true;
            return Poll::Idle;
        }
        if now_us.wrapping_sub(self.rotated_at_us) >= self.timeout_us {
            self.set_rpa(prand, true);
            self.rotated_at_us = now_us;
            self.stamp_valid = true;
            self.stats.rotated_at_us = now_us;
            self.stats.stamp_valid = true;
            return Poll::Generated;
        }
        Poll::Idle
    }

    pub fn local_rpa(&self) -> Option<[u8; 6]> {
        self.rpa
    }

    pub fn timeout_us(&self) -> u32 {
        self.timeout_us
    }

    pub fn set_timeout_us(&mut self, timeout_us: u32) {
        self.timeout_us = timeout_us;
    }

    /// Called by the advertising path after it picked the local address.
    pub fn note_adv_address(&mut self, uses_rpa: bool, fallback: bool) {
        self.stats.flags &= !(flags::ADV_USES_RPA | flags::IDENTITY_FALLBACK);
        if uses_rpa {
            self.stats.flags |= flags::ADV_USES_RPA;
        }
        if fallback {
            self.stats.flags |= flags::IDENTITY_FALLBACK;
        }
    }

    pub fn set_own_addr_type(&mut self, own_addr_type: u8) {
        self.own_addr_type = own_addr_type;
    }

    pub fn own_addr_type(&self) -> u8 {
        self.own_addr_type
    }

    // ---- resolution and admission ---------------------------------------

    /// Scans entries with a non-zero peer IRK; the default entry never costs AES.
    pub fn resolve(&self, address: [u8; 6]) -> Option<(u8, [u8; 6])> {
        if !is_resolvable(address) {
            return None;
        }
        let prand = [address[3], address[4], address[5]];
        let hash = [address[0], address[1], address[2]];
        for slot in 0..MAX_RESOLVING_LIST {
            if self.used & (1 << slot) == 0 {
                continue;
            }
            let Some(table) = self.tables[slot].as_ref() else {
                continue;
            };
            if ah_with(table, prand) == hash {
                let entry = &self.entries[slot];
                return Some((entry.peer_kind, entry.peer_address));
            }
        }
        None
    }

    /// Network-mode peers may only connect or scan with an RPA from their IRK.
    pub fn blocks_identity(&self, kind: u8, address: [u8; 6]) -> bool {
        self.find(kind, address).is_some_and(|slot| {
            self.entries[slot].peer_irk != [0; 16] && self.entries[slot].privacy_mode == 0
        })
    }

    /// CONNECT_IND gate. Policy 0 accepts and defers; policy 2 decides here.
    pub fn admit(&mut self, address: [u8; 6], random: bool) -> bool {
        let rpa = random && is_resolvable(address);
        if self.adv_filter_policy != 2 {
            // FAL is not used, but a policy value we do not filter on must not
            // silently become "unfiltered" either; values 1/3 are rejected at
            // Set Advertising Parameters.
            if !rpa && self.blocks_identity(u8::from(random), address) {
                self.stats.rejected_mode = self.stats.rejected_mode.wrapping_add(1);
                self.pending = None;
                self.cached_identity = None;
                return false;
            }
            self.pending = Some((address, random));
            self.cached_identity = None;
            return true;
        }
        if rpa && !self.resolution_enabled {
            // Without resolution a listed peer cannot be matched against the FAL.
            self.stats.rejected_not_listed = self.stats.rejected_not_listed.wrapping_add(1);
            self.cached_identity = None;
            return false;
        }
        if rpa {
            self.stats.resolve_attempts = self.stats.resolve_attempts.wrapping_add(1);
        }
        let identity = if rpa {
            self.resolve(address)
        } else {
            Some((u8::from(random), address))
        };
        match identity {
            Some(identity) => {
                if rpa {
                    self.stats.resolve_ok = self.stats.resolve_ok.wrapping_add(1);
                } else if self.blocks_identity(identity.0, identity.1) {
                    self.stats.rejected_mode = self.stats.rejected_mode.wrapping_add(1);
                    self.cached_identity = None;
                    return false;
                }
                if self.fal_contains(identity.0, identity.1) {
                    self.cached_identity = Some(identity);
                    true
                } else {
                    self.stats.rejected_not_listed = self.stats.rejected_not_listed.wrapping_add(1);
                    self.cached_identity = None;
                    false
                }
            }
            None => {
                self.stats.resolve_unresolved = self.stats.resolve_unresolved.wrapping_add(1);
                self.stats.rejected_not_listed = self.stats.rejected_not_listed.wrapping_add(1);
                self.cached_identity = None;
                false
            }
        }
    }

    /// Idle-path resolution of the address recorded by `admit`.
    pub fn resolve_pending(&mut self) -> Option<(u8, [u8; 6])> {
        if self.adv_filter_policy == 2 {
            return self.cached_identity;
        }
        if !self.resolution_enabled {
            return None;
        }
        let (address, random) = self.pending?;
        if !(random && is_resolvable(address)) {
            return None;
        }
        self.stats.resolve_attempts = self.stats.resolve_attempts.wrapping_add(1);
        let identity = self.resolve(address);
        if identity.is_some() {
            self.stats.resolve_ok = self.stats.resolve_ok.wrapping_add(1);
        } else {
            self.stats.resolve_unresolved = self.stats.resolve_unresolved.wrapping_add(1);
        }
        identity
    }

    /// Diagnostic entry; counts like the admission path and follows its switch.
    pub fn resolve_peer(&mut self, address: [u8; 6], random: bool) -> Option<(u8, [u8; 6])> {
        if !self.resolution_enabled || !(random && is_resolvable(address)) {
            return None;
        }
        self.stats.resolve_attempts = self.stats.resolve_attempts.wrapping_add(1);
        let identity = self.resolve(address);
        if identity.is_some() {
            self.stats.resolve_ok = self.stats.resolve_ok.wrapping_add(1);
        } else {
            self.stats.resolve_unresolved = self.stats.resolve_unresolved.wrapping_add(1);
        }
        identity
    }

    pub fn clear_pending(&mut self) {
        self.pending = None;
        self.cached_identity = None;
    }

    // ---- address resolution switch --------------------------------------

    pub fn set_enabled(&mut self, enabled: bool) {
        self.resolution_enabled = enabled;
        if enabled {
            self.stats.flags |= flags::RESOLUTION_ENABLED;
        } else {
            self.stats.flags &= !flags::RESOLUTION_ENABLED;
        }
    }

    pub fn enabled(&self) -> bool {
        self.resolution_enabled
    }

    // ---- filter accept list ---------------------------------------------

    pub fn set_filter_policy(&mut self, policy: u8) {
        self.adv_filter_policy = policy;
        self.stats.adv_filter_policy = policy;
    }

    pub fn filter_policy(&self) -> u8 {
        self.adv_filter_policy
    }

    pub fn fal_len(&self) -> u8 {
        self.fal_len
    }

    pub fn fal_contains(&self, kind: u8, address: [u8; 6]) -> bool {
        self.fal
            .iter()
            .flatten()
            .any(|&(k, a)| k == kind && a == address)
    }

    /// Returns true when the member was newly added.
    pub fn fal_add(&mut self, kind: u8, address: [u8; 6]) -> Result<bool, PrivacyError> {
        if kind > 1 {
            return Err(PrivacyError::InvalidKind);
        }
        if kind == 1 && address[5] & 0xc0 != 0xc0 {
            return Err(PrivacyError::InvalidIdentity);
        }
        if self.fal_contains(kind, address) {
            return Ok(false);
        }
        let slot = self
            .fal
            .iter()
            .position(|entry| entry.is_none())
            .ok_or(PrivacyError::NoSpace)?;
        self.fal[slot] = Some((kind, address));
        self.fal_len += 1;
        self.stats.flags |= flags::FAL_NONEMPTY;
        Ok(true)
    }

    /// Returns true when a member was removed.
    pub fn fal_remove(&mut self, kind: u8, address: [u8; 6]) -> Result<bool, PrivacyError> {
        if kind > 1 {
            return Err(PrivacyError::InvalidKind);
        }
        let Some(slot) = self
            .fal
            .iter()
            .position(|entry| *entry == Some((kind, address)))
        else {
            return Err(PrivacyError::NotFound);
        };
        self.fal[slot] = None;
        self.fal_len -= 1;
        if self.fal_len == 0 {
            self.stats.flags &= !flags::FAL_NONEMPTY;
        }
        Ok(true)
    }

    pub fn fal_clear(&mut self) {
        self.fal = [None; MAX_FILTER_ACCEPT_LIST];
        self.fal_len = 0;
        self.stats.flags &= !flags::FAL_NONEMPTY;
    }

    // ---- observation ----------------------------------------------------

    pub fn stats(&self) -> PrivacyStats {
        let mut stats = self.stats;
        stats.list_len = self.len();
        stats.stamp_valid = self.stamp_valid;
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core 5.4 Vol 3 Part H `ah` vector: IRK ec02...7d9b, prand 708194.
    const IRK: [u8; 16] = [
        0x9b, 0x7d, 0x39, 0x0a, 0xa6, 0x10, 0x10, 0x34, 0x05, 0xad, 0xc8, 0x57, 0xa3, 0x34, 0x02,
        0xec,
    ];
    /// Trouble's own vector, cross-checked against its implementation.
    const IRK2: [u8; 16] = [
        0x4d, 0xf5, 0x3c, 0x0d, 0xc9, 0x7b, 0xd2, 0x7b, 0x46, 0x64, 0xed, 0x58, 0xc1, 0x58, 0x39,
        0x8b,
    ];

    #[test]
    fn ah_matches_core_vector() {
        assert_eq!(ah(&IRK, [0x94, 0x81, 0x70]), [0xaa, 0xfb, 0x0d]);
    }

    #[test]
    fn resolves_known_rpa() {
        let rpa = [0x92, 0xf2, 0x8f, 0x84, 0x72, 0x4f];
        assert!(is_resolvable(rpa));
        let mut p = Privacy::new();
        p.add(ResolvingEntry {
            peer_kind: 0,
            peer_address: [0x11; 6],
            peer_irk: IRK2,
            local_irk: [0; 16],
            privacy_mode: 1,
        })
        .unwrap();
        assert_eq!(p.resolve(rpa), Some((0, [0x11; 6])));
        assert_eq!(p.resolve([0x92, 0xf2, 0x8f, 0x84, 0x72, 0x4e]), None);
    }

    #[test]
    fn generated_rpa_resolves_and_has_type_bits() {
        let mut p = Privacy::new();
        p.add(ResolvingEntry {
            peer_kind: 0,
            peer_address: [0; 6],
            peer_irk: [0; 16],
            local_irk: IRK,
            privacy_mode: 1,
        })
        .unwrap();
        let rpa = p.ensure_rpa([0x11, 0x22, 0x33]).unwrap();
        assert!(is_resolvable(rpa));
        assert_eq!(p.local_irk(), Some(IRK));
        let expected = rpa_from(&IRK, [0x11, 0x22, 0x73]);
        assert_eq!(rpa, expected);

        let mut q = Privacy::new();
        q.add(ResolvingEntry {
            peer_kind: 0,
            peer_address: [1; 6],
            peer_irk: IRK,
            local_irk: [0; 16],
            privacy_mode: 1,
        })
        .unwrap();
        assert_eq!(q.resolve(rpa), Some((0, [1; 6])));
    }

    #[test]
    fn prand_rejects_all_zero_and_all_one() {
        assert!(prand_from([0x00, 0x00, 0x00]).is_none());
        assert!(prand_from([0xff, 0xff, 0xff]).is_none());
        assert_eq!(prand_from([0x00, 0x00, 0x01]), Some([0x00, 0x00, 0x41]));
        assert_eq!(prand_from([0x01, 0x00, 0x00]), Some([0x01, 0x00, 0x40]));
    }

    #[test]
    fn poll_does_nothing_without_a_local_irk() {
        let mut p = Privacy::new();
        assert_eq!(p.poll(10, [1, 2, 3]), Poll::Idle);
        assert_eq!(p.stats().generations, 0);
        assert!(p.local_rpa().is_none());
    }

    #[test]
    fn rotation_needs_a_stamp_first() {
        let mut p = Privacy::new();
        p.add(default_entry(IRK)).unwrap();
        assert_eq!(p.poll(10, [1, 2, 3]), Poll::Generated);
        assert_eq!(p.poll(20, [1, 2, 3]), Poll::Idle);
        assert_eq!(p.stats().rotated_at_us, 20);
        assert_eq!(p.poll(20 + DEFAULT_TIMEOUT_US - 1, [1, 2, 4]), Poll::Idle);
        assert_eq!(p.poll(20 + DEFAULT_TIMEOUT_US, [1, 2, 5]), Poll::Generated);
        let stats = p.stats();
        assert_eq!(stats.generations, 2);
        assert_eq!(stats.rotations, 1);
        assert_eq!(stats.rotated_at_us, 20 + DEFAULT_TIMEOUT_US);
    }

    #[test]
    fn wrapping_timer_still_rotates() {
        let mut p = Privacy::new();
        p.add(default_entry(IRK)).unwrap();
        p.set_timeout_us(1_000);
        assert_eq!(p.poll(u32::MAX - 500, [1, 2, 3]), Poll::Generated);
        assert_eq!(p.poll(u32::MAX - 400, [1, 2, 4]), Poll::Idle);
        assert_eq!(
            p.poll((u32::MAX - 400).wrapping_add(999), [1, 2, 5]),
            Poll::Idle
        );
        assert_eq!(
            p.poll((u32::MAX - 400).wrapping_add(1_000), [1, 2, 6]),
            Poll::Generated
        );
    }

    #[test]
    fn replace_and_remove_invalidate_the_rpa() {
        let mut p = Privacy::new();
        p.add(default_entry(IRK)).unwrap();
        let first = p.ensure_rpa([1, 2, 3]).unwrap();
        p.add(default_entry(IRK2)).unwrap();
        assert!(p.local_rpa().is_none());
        let second = p.ensure_rpa([1, 2, 3]).unwrap();
        assert_ne!(first, second);
        p.remove(0, [0; 6]).unwrap();
        assert!(p.local_irk().is_none());
        assert!(p.local_rpa().is_none());
    }

    #[test]
    fn local_irk_conflict_is_rejected_without_commit() {
        let mut p = Privacy::new();
        p.add(ResolvingEntry {
            peer_kind: 0,
            peer_address: [1; 6],
            peer_irk: [2; 16],
            local_irk: IRK,
            privacy_mode: 1,
        })
        .unwrap();
        let before = p.len();
        let err = p
            .add(ResolvingEntry {
                peer_kind: 0,
                peer_address: [3; 6],
                peer_irk: [4; 16],
                local_irk: IRK2,
                privacy_mode: 1,
            })
            .unwrap_err();
        assert_eq!(err, PrivacyError::KeyConflict);
        assert_eq!(p.len(), before);
    }

    #[test]
    fn default_entry_wins_but_must_agree() {
        let mut p = Privacy::new();
        p.add(ResolvingEntry {
            peer_kind: 0,
            peer_address: [1; 6],
            peer_irk: [2; 16],
            local_irk: IRK,
            privacy_mode: 1,
        })
        .unwrap();
        p.add(default_entry(IRK)).unwrap();
        assert_eq!(p.local_irk(), Some(IRK));
        assert_eq!(
            p.add(default_entry(IRK2)).unwrap_err(),
            PrivacyError::KeyConflict
        );
    }

    #[test]
    fn duplicate_identity_replaces_and_identical_is_idempotent() {
        let mut p = Privacy::new();
        let entry = ResolvingEntry {
            peer_kind: 1,
            peer_address: [0x40, 0, 0, 0, 0, 0xc1],
            peer_irk: IRK,
            local_irk: [0; 16],
            privacy_mode: 1,
        };
        p.add(entry).unwrap();
        let generation = p.list_generation();
        p.add(entry).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p.list_generation() > generation);
        let other = ResolvingEntry {
            peer_irk: IRK2,
            ..entry
        };
        p.add(other).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p.has_peer(1, entry.peer_address, &IRK2));
    }

    #[test]
    fn validates_identity_kinds() {
        let mut p = Privacy::new();
        assert_eq!(
            p.add(ResolvingEntry {
                peer_kind: 2,
                ..ResolvingEntry::empty()
            })
            .unwrap_err(),
            PrivacyError::InvalidKind
        );
        assert_eq!(
            p.add(ResolvingEntry {
                peer_kind: 1,
                peer_address: [0x40, 0, 0, 0, 0, 0x40],
                ..ResolvingEntry::empty()
            })
            .unwrap_err(),
            PrivacyError::InvalidIdentity
        );
    }

    #[test]
    fn list_capacity_is_enforced() {
        let mut p = Privacy::new();
        for i in 0..MAX_RESOLVING_LIST {
            let mut address = [0u8; 6];
            address[0] = i as u8;
            p.add(ResolvingEntry {
                peer_kind: 0,
                peer_address: address,
                peer_irk: [i as u8 + 1; 16],
                local_irk: [0; 16],
                privacy_mode: 1,
            })
            .unwrap();
        }
        assert_eq!(
            p.add(ResolvingEntry {
                peer_kind: 0,
                peer_address: [0xff; 6],
                peer_irk: [9; 16],
                local_irk: [0; 16],
                privacy_mode: 1,
            })
            .unwrap_err(),
            PrivacyError::NoSpace
        );
        assert_eq!(p.len(), MAX_RESOLVING_LIST as u8);
    }

    #[test]
    fn clear_frees_the_list_but_keeps_settings() {
        let mut p = Privacy::new();
        p.set_timeout_us(5_000);
        p.set_enabled(true);
        p.add(default_entry(IRK)).unwrap();
        p.fal_add(0, [1; 6]).unwrap();
        p.clear();
        assert!(p.is_empty());
        assert_eq!(p.local_irk(), None);
        assert_eq!(p.fal_len(), 1);
        assert_eq!(p.timeout_us(), 5_000);
        assert!(p.enabled());
    }

    #[test]
    fn policy_zero_accepts_and_defers_resolution() {
        let mut p = Privacy::new();
        p.set_enabled(true);
        p.add(ResolvingEntry {
            peer_kind: 0,
            peer_address: [1; 6],
            peer_irk: IRK,
            local_irk: [0; 16],
            privacy_mode: 1,
        })
        .unwrap();
        let rpa = rpa_from(&IRK, [0x94, 0x81, 0x70]);
        assert!(p.admit(rpa, true));
        assert_eq!(p.stats().resolve_attempts, 0);
        assert_eq!(p.resolve_pending(), Some((0, [1; 6])));
        assert_eq!(p.stats().resolve_ok, 1);
    }

    #[test]
    fn policy_two_filters_every_address_kind() {
        let mut p = Privacy::new();
        p.set_enabled(true);
        p.set_filter_policy(2);
        p.add(ResolvingEntry {
            peer_kind: 0,
            peer_address: [1; 6],
            peer_irk: IRK,
            local_irk: [0; 16],
            privacy_mode: 1,
        })
        .unwrap();
        p.fal_add(0, [1; 6]).unwrap();
        p.fal_add(0, [2; 6]).unwrap();

        // Public address not in the FAL: rejected, no AES needed.
        assert!(!p.admit([3; 6], false));
        assert_eq!(p.stats().rejected_not_listed, 1);
        assert_eq!(p.stats().resolve_attempts, 0);

        // Public address that is listed: accepted.
        assert!(p.admit([2; 6], false));

        // Resolved RPA whose identity is listed: accepted.
        let rpa = rpa_from(&IRK, [0x94, 0x81, 0x70]);
        assert!(p.admit(rpa, true));
        assert_eq!(p.resolve_pending(), Some((0, [1; 6])));

        // Unresolved RPA: rejected and counted.
        let stranger = rpa_from(&IRK2, [0x94, 0x81, 0x70]);
        assert!(!p.admit(stranger, true));
        assert_eq!(p.stats().resolve_unresolved, 1);
        assert_eq!(p.stats().rejected_not_listed, 2);
    }

    #[test]
    fn disabled_resolution_leaves_the_rpa_unresolved() {
        let mut p = Privacy::new();
        p.add(ResolvingEntry {
            peer_kind: 0,
            peer_address: [1; 6],
            peer_irk: IRK,
            local_irk: [0; 16],
            privacy_mode: 1,
        })
        .unwrap();
        let rpa = rpa_from(&IRK, [0x94, 0x81, 0x70]);
        assert!(p.admit(rpa, true));
        assert_eq!(p.resolve_pending(), None);
        assert_eq!(p.resolve_peer(rpa, true), None);
        assert_eq!(p.stats().resolve_attempts, 0);

        p.set_enabled(true);
        assert_eq!(p.resolve_pending(), Some((0, [1; 6])));
        assert_eq!(p.stats().resolve_ok, 1);
    }

    #[test]
    fn clearing_the_list_keeps_the_pending_admission() {
        let entry = ResolvingEntry {
            peer_kind: 0,
            peer_address: [1; 6],
            peer_irk: IRK,
            local_irk: [0; 16],
            privacy_mode: 1,
        };
        let mut p = Privacy::new();
        p.set_enabled(true);
        p.add(entry).unwrap();
        let rpa = rpa_from(&IRK, [0x94, 0x81, 0x70]);
        assert!(p.admit(rpa, true));

        // A Host resync clears and rebuilds the list during setup.
        p.clear();
        p.add(entry).unwrap();
        assert_eq!(p.resolve_pending(), Some((0, [1; 6])));
    }

    #[test]
    fn network_mode_rejects_the_peer_identity_address() {
        let entry = ResolvingEntry {
            peer_kind: 0,
            peer_address: [1; 6],
            peer_irk: IRK,
            local_irk: [0; 16],
            privacy_mode: 0,
        };
        let mut p = Privacy::new();
        p.set_enabled(true);
        p.add(entry).unwrap();
        assert!(!p.admit([1; 6], false));
        assert_eq!(p.stats().rejected_mode, 1);

        // The same peer using an RPA from its IRK is accepted and resolved.
        let rpa = rpa_from(&IRK, [0x94, 0x81, 0x70]);
        assert!(p.admit(rpa, true));
        assert_eq!(p.resolve_pending(), Some((0, [1; 6])));

        // Device privacy mode has no such restriction.
        p.set_mode(0, [1; 6], 1).unwrap();
        assert!(p.admit([1; 6], false));

        // Policy 2 must not let the FAL bypass the mode either.
        let mut q = Privacy::new();
        q.set_enabled(true);
        q.set_filter_policy(2);
        q.add(entry).unwrap();
        q.fal_add(0, [1; 6]).unwrap();
        assert!(!q.admit([1; 6], false));
        assert_eq!(q.stats().rejected_mode, 1);
    }

    #[test]
    fn empty_fal_with_policy_two_rejects_public() {
        let mut p = Privacy::new();
        p.set_filter_policy(2);
        assert!(!p.admit([1; 6], false));
        assert_eq!(p.stats().rejected_not_listed, 1);
    }

    #[test]
    fn static_random_is_not_resolved() {
        let mut p = Privacy::new();
        let static_addr = [0x01, 0, 0, 0, 0, 0xc0];
        assert!(p.admit(static_addr, true));
        assert_eq!(p.resolve_pending(), None);
        assert_eq!(p.stats().resolve_attempts, 0);
    }

    #[test]
    fn fal_membership_rules() {
        let mut p = Privacy::new();
        assert!(p.fal_add(0, [1; 6]).unwrap());
        assert!(!p.fal_add(0, [1; 6]).unwrap());
        assert!(p.fal_contains(0, [1; 6]));
        assert!(!p.fal_contains(1, [1; 6]));
        assert!(p.fal_remove(0, [1; 6]).unwrap());
        assert_eq!(p.fal_remove(0, [1; 6]).unwrap_err(), PrivacyError::NotFound);
        for i in 0..MAX_FILTER_ACCEPT_LIST {
            let mut address = [0u8; 6];
            address[1] = i as u8;
            p.fal_add(0, address).unwrap();
        }
        assert_eq!(p.fal_add(0, [9; 6]).unwrap_err(), PrivacyError::NoSpace);
        p.fal_clear();
        assert_eq!(p.fal_len(), 0);
        assert_eq!(p.stats().flags & flags::FAL_NONEMPTY, 0);
    }

    #[test]
    fn default_entry_never_costs_aes() {
        let mut p = Privacy::new();
        p.add(default_entry(IRK)).unwrap();
        // A default entry has a zero peer IRK, so no peer can resolve through it.
        let rpa = rpa_from(&IRK, [0x94, 0x81, 0x70]);
        assert_eq!(p.resolve(rpa), None);
        assert!(p.tables.iter().all(|table| table.is_none()));
    }

    fn default_entry(local_irk: [u8; 16]) -> ResolvingEntry {
        ResolvingEntry {
            peer_kind: 0,
            peer_address: [0; 6],
            peer_irk: [0; 16],
            local_irk,
            privacy_mode: 1,
        }
    }
}
