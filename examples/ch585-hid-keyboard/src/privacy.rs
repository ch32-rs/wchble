//! S4 acceptance observations.
//!
//! `PRIVACY_STATS` is the only place the runner reads privacy state from; the
//! controller-owned counters come from `SoftRunner`, while timings and storage
//! facts are recorded here because the library has no clock and no store.

use wchble::hci::SoftRunner;

pub const WORDS: usize = 24;
pub const MAGIC: u32 = 0x5334_5052;

/// Example-owned bits OR-ed into word 2 above the library's `u8` flags.
pub const FLAG_IRK_UNPERSISTED: u32 = 0x20;
pub const FLAG_WRITES_BLOCKED: u32 = 0x40;
pub const FLAG_WIPE_PENDING: u32 = 0x80;
pub const FLAG_RL_NOT_READY: u32 = 0x100;
pub const FLAG_STAMP_VALID: u32 = 0x200;
/// Bonds exist but no local IRK: the peer must re-pair for privacy.
pub const FLAG_IRK_MISSING: u32 = 0x400;
/// The accept list could not be rebuilt; advertising fell back to unfiltered.
pub const FLAG_FAL_REBUILD_FAILED: u32 = 0x800;

/// Marker the acceptance runner reads to refuse a `fal` phase against an
/// image built without the feature.
#[cfg(feature = "fal-filter")]
#[used]
#[no_mangle]
pub static FAL_FILTER_BUILD: u32 = 1;

#[no_mangle]
pub static mut PRIVACY_STATS: [u32; WORDS] = [0; WORDS];

static mut FLAGS: u32 = 0;
static mut MAX_ADMIT_US: u32 = 0;
static mut MAX_RESOLVE_US: u32 = 0;
static mut STAGE: (u32, u32, u32) = (0, 0, 0);
static mut STAGE_SET: bool = false;
static mut RECONNECT: (u32, u32, u32) = (0, 0, 0);
static mut LINKS: u32 = 0;
static mut STAGE_PAIRS: u32 = 0;

pub fn set_flag(flag: u32) {
    // SAFETY: single-threaded; written from boot or the Host poll.
    unsafe {
        let flags = core::ptr::addr_of_mut!(FLAGS);
        flags.write_volatile(flags.read_volatile() | flag);
    }
}

pub fn flags() -> u32 {
    // SAFETY: see `set_flag`.
    unsafe { core::ptr::addr_of!(FLAGS).read_volatile() }
}

/// Record the cost of one admission (policy 2 resolution included).
pub fn note_admit(us: u32) {
    // SAFETY: see `set_flag`.
    unsafe {
        let slot = core::ptr::addr_of_mut!(MAX_ADMIT_US);
        if us > slot.read_volatile() {
            slot.write_volatile(us);
        }
    }
}

/// Record the cost of the deferred peer resolution.
pub fn note_resolve(us: u32) {
    // SAFETY: see `set_flag`.
    unsafe {
        let slot = core::ptr::addr_of_mut!(MAX_RESOLVE_US);
        if us > slot.read_volatile() {
            slot.write_volatile(us);
        }
    }
}

/// Snapshot the counters at the first disconnect, so the rotation window and
/// the reconnect that follow can be compared. Later disconnects (the app ends
/// the reconnected link before the finite run ends) must not move it.
pub fn snapshot(soft: &SoftRunner) {
    // SAFETY: single-threaded.
    unsafe {
        let set = core::ptr::addr_of_mut!(STAGE_SET);
        if set.read_volatile() {
            return;
        }
        set.write_volatile(true);
    }
    let stats = soft.privacy_stats();
    // Every PairingComplete increments exactly one of these, bonded or not.
    let pairs = crate::bond::value(crate::bond::STAT_PAIRS_COMPLETE)
        .wrapping_add(crate::bond::value(crate::bond::STAT_PAIRS_WITHOUT_BOND));
    // SAFETY: single-threaded.
    unsafe {
        core::ptr::addr_of_mut!(STAGE).write_volatile((
            stats.generations,
            stats.resolve_ok,
            stats.rotations,
        ));
        core::ptr::addr_of_mut!(STAGE_PAIRS).write_volatile(pairs);
    }
}

/// Close the rotation window when the second link is reported, so rotations
/// after the reconnect cannot be counted as part of it.
pub fn note_connection(soft: &SoftRunner) {
    // SAFETY: single-threaded.
    unsafe {
        let links = core::ptr::addr_of_mut!(LINKS);
        let count = links.read_volatile().wrapping_add(1);
        links.write_volatile(count);
        if count != 2 {
            return;
        }
    }
    let stats = soft.privacy_stats();
    // SAFETY: single-threaded.
    unsafe {
        core::ptr::addr_of_mut!(RECONNECT).write_volatile((
            stats.generations,
            stats.resolve_ok,
            stats.rotations,
        ));
    }
}

/// Publish the 23-word block read over SWD after a finite run.
pub fn publish(soft: &SoftRunner) {
    let stats = soft.privacy_stats();
    // SAFETY: single-threaded.
    let (stage, reconnect, max_admit, max_resolve, stage_pairs) = unsafe {
        (
            core::ptr::addr_of!(STAGE).read_volatile(),
            core::ptr::addr_of!(RECONNECT).read_volatile(),
            core::ptr::addr_of!(MAX_ADMIT_US).read_volatile(),
            core::ptr::addr_of!(MAX_RESOLVE_US).read_volatile(),
            core::ptr::addr_of!(STAGE_PAIRS).read_volatile(),
        )
    };
    let flags = flags()
        | u32::from(stats.flags)
        | if stats.stamp_valid {
            FLAG_STAMP_VALID
        } else {
            0
        };
    let irk = crate::bond::local_irk();
    let fingerprint = if irk == [0; 16] {
        0
    } else {
        let hash = wchble::ll::privacy::ah(&irk, [0; 3]);
        u32::from_le_bytes([hash[0], hash[1], hash[2], 0])
    };
    let words = [
        MAGIC,
        1,
        flags,
        stats.generations,
        stats.rotations,
        stats.resolve_attempts,
        stats.resolve_ok,
        stats.resolve_unresolved,
        stats.rejected_not_listed,
        stats.rejected_mode,
        max_admit,
        max_resolve,
        stats.rotated_at_us,
        u32::from_le_bytes([stats.rpa[0], stats.rpa[1], stats.rpa[2], stats.rpa[3]]),
        u32::from_le_bytes([stats.rpa[4], stats.rpa[5], 0, 0]),
        u32::from(stats.list_len)
            | (u32::from(stats.adv_filter_policy) << 8)
            | (u32::from(stats.last_error) << 16),
        fingerprint,
        stage.0,
        stage.1,
        stage.2,
        reconnect.0,
        reconnect.1,
        reconnect.2,
        stage_pairs,
    ];
    // SAFETY: single-threaded.
    unsafe {
        let out = core::ptr::addr_of_mut!(PRIVACY_STATS).cast::<u32>();
        for (index, word) in words.iter().enumerate() {
            out.add(index).write_volatile(*word);
        }
    }
}
