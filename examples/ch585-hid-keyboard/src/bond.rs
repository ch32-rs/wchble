//! Bond persistence wiring for the secure example.
//!
//! The library stores an opaque, Host-independent [`PersistedBond`] record;
//! this module converts between it and Trouble's `BondInformation`, and keeps
//! the RAM counters the runner reads back over SWD.

use core::cell::Cell;

use heapless::Vec;
use trouble_host::prelude::*;
pub use wchble::storage::bond::{PersistedBond, MAX_BONDS};

static mut SIGNALS: BondSignals = BondSignals::new();
static mut BOOT_BONDS: [PersistedBond; MAX_BONDS] = [PersistedBond::empty(); MAX_BONDS];
static mut BOOT_COUNT: usize = 0;

/// Shared request slots, reachable from both the RF owner and the Host future.
pub fn signals() -> &'static BondSignals {
    // SAFETY: single-threaded example; the Cell fields are only touched from
    // the Host poll and read by the RF loop between polls.
    unsafe { &*core::ptr::addr_of!(SIGNALS) }
}

/// Publish the bonds read from flash before the Host starts advertising.
pub fn set_boot_bonds(list: &[PersistedBond]) {
    let count = list.len().min(MAX_BONDS);
    // SAFETY: single-threaded boot; written before the Host future is polled.
    unsafe {
        let out = core::ptr::addr_of_mut!(BOOT_BONDS).cast::<PersistedBond>();
        for (index, record) in list[..count].iter().enumerate() {
            out.add(index).write_volatile(*record);
        }
        core::ptr::addr_of_mut!(BOOT_COUNT).write_volatile(count);
    }
}

/// Bonds loaded at boot, for [`crate::host::run`].
pub fn boot_bonds() -> &'static [PersistedBond] {
    // SAFETY: written once at boot before the Host is polled, then read-only.
    unsafe {
        let count = core::ptr::addr_of!(BOOT_COUNT).read_volatile();
        core::slice::from_raw_parts(core::ptr::addr_of!(BOOT_BONDS).cast(), count)
    }
}

/// Full bond list as the Host holds it.
pub type BondSnapshot = Vec<BondInformation, MAX_BONDS>;

pub const BOND_MAGIC: u32 = 0x4233_5330;
pub const BOND_ECHO_MAGIC: u32 = 0x4F48_4345;
pub const BOND_STATS_WORDS: usize = 32;
pub const BOND_ECHO_WORDS: usize = 16;

/// Load outcome reported in [`walk`] word 2.
pub const LOAD_NONE: u32 = 0;
pub const LOAD_VALID: u32 = 1;
pub const LOAD_CORRUPT: u32 = 2;
pub const LOAD_IO: u32 = 3;

pub const STAT_LOAD_RESULT: usize = 2;
pub const STAT_RECORDS_LOADED: usize = 3;
pub const STAT_WINNER_SLOT: usize = 4;
pub const STAT_WINNER_SEQ: usize = 5;
pub const STAT_SAVE_ATTEMPTS: usize = 6;
pub const STAT_SAVE_OK: usize = 7;
pub const STAT_SAVE_FAIL: usize = 8;
pub const STAT_DEFERRED: usize = 9;
pub const STAT_SAVE_ON_DISCONNECT: usize = 10;
pub const STAT_CLEAR_REQUESTS: usize = 11;
pub const STAT_CLEAR_OK: usize = 12;
pub const STAT_CLEAR_FAIL: usize = 13;
#[cfg(feature = "bond-fault")]
pub const STAT_FAULT_INJECTED: usize = 14;
pub const STAT_LAST_ERROR: usize = 15;
pub const STAT_MAX_SAVE_US: usize = 16;
pub const STAT_LAST_SAVE_US: usize = 17;
pub const STAT_BOOT_READ_US: usize = 18;
pub const STAT_PAIRS_COMPLETE: usize = 19;
pub const STAT_PAIRS_WITHOUT_BOND: usize = 20;
pub const STAT_IN_MEMORY_REMOVED: usize = 21;
pub const STAT_CONTROL_WRITES: usize = 22;
pub const STAT_MALFORMED_CONTROL_WRITES: usize = 23;
pub const STAT_ADD_BOND_OK: usize = 24;
pub const STAT_ADD_BOND_FAIL: usize = 25;

/// Marker the acceptance runner reads to refuse a `fault` phase against an
/// image built without the injection feature.
#[cfg(feature = "bond-fault")]
#[used]
#[no_mangle]
pub static BOND_FAULT_BUILD: u32 = 1;

/// Marker for the non-default bond-control characteristic, so a runner can
/// refuse `--wipe-bond` against a product-shaped image before flashing.
#[cfg(feature = "accept-control")]
#[used]
#[no_mangle]
pub static BOND_ACCEPT_CONTROL_BUILD: u32 = 1;

/// Counters and requests shared between the Host future and the RF owner.
#[no_mangle]
pub static mut BOND_STATS: [u32; BOND_STATS_WORDS] = [0; BOND_STATS_WORDS];

/// Latest bond key material, so the runner can compare the flash dump against
/// what the Host actually used without decoding the pcap.
#[no_mangle]
pub static mut BOND_ECHO: [u32; BOND_ECHO_WORDS] = [0; BOND_ECHO_WORDS];

fn word(index: usize) -> u32 {
    // SAFETY: single-threaded example; the RF loop and the Host poll never run
    // at the same time.
    unsafe { core::ptr::addr_of!(BOND_STATS).cast::<u32>().add(index).read_volatile() }
}

/// Increment a counter.
pub fn bump(index: usize) {
    let next = word(index).wrapping_add(1);
    // SAFETY: see `word`.
    unsafe {
        core::ptr::addr_of_mut!(BOND_STATS)
            .cast::<u32>()
            .add(index)
            .write_volatile(next);
    }
}

/// Set a counter or observation.
pub fn set(index: usize, value: u32) {
    // SAFETY: see `word`.
    unsafe {
        core::ptr::addr_of_mut!(BOND_STATS)
            .cast::<u32>()
            .add(index)
            .write_volatile(value);
    }
}

/// Read a counter or observation.
pub fn value(index: usize) -> u32 {
    word(index)
}

/// Highest observed value.
pub fn observe_max(index: usize, value: u32) {
    if value > word(index) {
        set(index, value);
    }
}

/// Requests set by the Host and consumed by the RF owner.
pub struct BondSignals {
    pending: Cell<Option<BondSnapshot>>,
    /// `DEL!`: remove the in-memory bonds and write a tombstone.
    pub delete: Cell<bool>,
    /// `WIPE`: erase both slots (acceptance setup).
    pub wipe: Cell<bool>,
    /// `FALT`: truncate the next save on purpose (needs `bond-fault`).
    pub fault: Cell<bool>,
}

impl BondSignals {
    pub const fn new() -> Self {
        Self {
            pending: Cell::new(None),
            delete: Cell::new(false),
            wipe: Cell::new(false),
            fault: Cell::new(false),
        }
    }

    /// Replace the snapshot that is waiting to be written.
    pub fn set_pending(&self, snapshot: BondSnapshot) {
        self.pending.replace(Some(snapshot));
    }

    pub fn take_pending(&self) -> Option<BondSnapshot> {
        self.pending.take()
    }

    /// Drop a queued snapshot. A delete/wipe must not be undone by a snapshot
    /// captured before it.
    pub fn discard_pending(&self) {
        self.pending.set(None);
    }
}

/// Convert a Host bond into the stored record.
pub fn from_bond(bond: &BondInformation) -> PersistedBond {
    let address = bond.identity.addr.to_bytes();
    let mut record = PersistedBond::empty();
    record.ltk = bond.ltk.to_le_bytes();
    record.address_kind = address[0];
    record.address.copy_from_slice(&address[1..]);
    record.irk = bond
        .identity
        .irk
        .map(|key| key.0.get().to_le_bytes());
    record.is_bonded = bond.is_bonded;
    record.security_level = match bond.security_level {
        SecurityLevel::NoEncryption => 0,
        SecurityLevel::Encrypted => 1,
        SecurityLevel::EncryptedAuthenticated => 2,
    };
    record
}

/// Rebuild a Host bond from the stored record.
pub fn to_bond(record: &PersistedBond) -> BondInformation {
    let mut address = record.address;
    address.reverse();
    let identity = Identity {
        addr: Address::new(AddrKind::new(record.address_kind), BdAddr::new(address)),
        irk: record
            .irk
            .and_then(|bytes| IdentityResolvingKey::new(u128::from_le_bytes(bytes))),
    };
    let level = match record.security_level {
        1 => SecurityLevel::Encrypted,
        2 => SecurityLevel::EncryptedAuthenticated,
        _ => SecurityLevel::NoEncryption,
    };
    BondInformation::new(
        identity,
        LongTermKey::from_le_bytes(record.ltk),
        level,
        record.is_bonded,
    )
}

/// Record the key material of the bond the Host just added, for dump checks.
pub fn echo(bond: &BondInformation) {
    let record = from_bond(bond);
    let ltk = record.ltk;
    let words = [
        BOND_ECHO_MAGIC,
        1,
        u32::from_be_bytes([record.address[0], record.address[1], record.address[2], record.address[3]]),
        (u32::from(record.address[4]) << 24)
            | (u32::from(record.address[5]) << 16)
            | (u32::from(record.address_kind) << 8)
            | u32::from(record.is_bonded),
        u32::from_le_bytes([ltk[0], ltk[1], ltk[2], ltk[3]]),
        u32::from_le_bytes([ltk[4], ltk[5], ltk[6], ltk[7]]),
        u32::from_le_bytes([ltk[8], ltk[9], ltk[10], ltk[11]]),
        u32::from_le_bytes([ltk[12], ltk[13], ltk[14], ltk[15]]),
        (u32::from(record.security_level) << 8)
            | (u32::from(record.irk.is_some()) << 16)
            | (u32::from(record.key_len) << 24),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    // SAFETY: see `word`.
    unsafe {
        let out = core::ptr::addr_of_mut!(BOND_ECHO).cast::<u32>();
        for (index, value) in words.iter().enumerate() {
            out.add(index).write_volatile(*value);
        }
    }
    bump(STAT_PAIRS_COMPLETE);
}
