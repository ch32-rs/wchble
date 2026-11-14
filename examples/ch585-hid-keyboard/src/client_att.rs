//! Client ATT (CCCD) shadow and flash plumbing for the secure example.
//!
//! Trouble keeps a bonded peer's table in RAM across a disconnect, but not
//! across a reboot. This module keeps a per-peer shadow, restores it after the
//! Host has allocated the connection's table slot, and hands snapshots to the
//! RF owner for persistence through [`crate::bond::signals`]'s flush path.

use core::cell::Cell;

use embassy_sync::blocking_mutex::raw::RawMutex;
use heapless::Vec;
use trouble_host::prelude::*;
pub use wchble::storage::client_att::{
    decode_client_att, encode_client_att, ClientAttRecord, MAX_CLIENT_ATT, MAX_PAYLOAD,
};

static mut BOOT_RECORDS: [ClientAttRecord; MAX_CLIENT_ATT] =
    [ClientAttRecord::empty(); MAX_CLIENT_ATT];
static mut BOOT_COUNT: usize = 0;

/// Publish the records decoded from flash before the Host starts advertising.
pub fn set_boot_records(list: &[ClientAttRecord]) {
    let count = list.len().min(MAX_CLIENT_ATT);
    // SAFETY: single-threaded boot; written before the Host future is polled.
    unsafe {
        let out = core::ptr::addr_of_mut!(BOOT_RECORDS).cast::<ClientAttRecord>();
        for (index, record) in list[..count].iter().enumerate() {
            out.add(index).write_volatile(*record);
        }
        core::ptr::addr_of_mut!(BOOT_COUNT).write_volatile(count);
    }
}

/// Records loaded at boot, for [`crate::host::run`].
pub fn boot_records() -> &'static [ClientAttRecord] {
    // SAFETY: written once at boot before the Host is polled, then read-only.
    unsafe {
        let count = core::ptr::addr_of!(BOOT_COUNT).read_volatile();
        core::slice::from_raw_parts(core::ptr::addr_of!(BOOT_RECORDS).cast(), count)
    }
}

pub const CATT_MAGIC: u32 = 0x4333_4130;
pub const CATT_VERSION: u32 = 1;
pub const CATT_STATS_WORDS: usize = 16;

pub const STAT_MAGIC: usize = 0;
pub const STAT_VERSION: usize = 1;
pub const STAT_LOAD_RESULT: usize = 2;
pub const STAT_RECORDS_LOADED: usize = 3;
pub const STAT_IDENTITY_MISMATCH: usize = 4;
pub const STAT_SAVE_ATTEMPTS: usize = 5;
pub const STAT_SAVE_OK: usize = 6;
pub const STAT_SAVE_FAIL: usize = 7;
pub const STAT_SNAPSHOTS: usize = 8;
pub const STAT_RESTORE_ATTEMPTS: usize = 9;
pub const STAT_RESTORE_OK: usize = 10;
pub const STAT_RESTORE_NO_RECORD: usize = 11;
pub const STAT_RESTORE_INVALID: usize = 12;
pub const STAT_OVERFLOW: usize = 13;
pub const STAT_LAST_ERROR: usize = 14;
pub const STAT_RESERVED: usize = 15;

pub const LOAD_NONE: u32 = 0;
pub const LOAD_VALID: u32 = 1;
pub const LOAD_CORRUPT: u32 = 2;
pub const LOAD_IO: u32 = 3;
pub const LOAD_FOREIGN: u32 = 4;

#[no_mangle]
pub static mut CATT_STATS: [u32; CATT_STATS_WORDS] = [0; CATT_STATS_WORDS];

fn word(index: usize) -> u32 {
    // SAFETY: single-threaded example; the RF loop and the Host poll never run
    // at the same time.
    unsafe { core::ptr::addr_of!(CATT_STATS).cast::<u32>().add(index).read_volatile() }
}

pub fn bump(index: usize) {
    set(index, word(index).wrapping_add(1));
}

pub fn set(index: usize, value: u32) {
    // SAFETY: see `word`.
    unsafe {
        core::ptr::addr_of_mut!(CATT_STATS)
            .cast::<u32>()
            .add(index)
            .write_volatile(value);
    }
}

pub fn value(index: usize) -> u32 {
    word(index)
}

/// Per-peer tables as the Host agreed to them.
pub type ClientAttSnapshot = Vec<ClientAttRecord, MAX_CLIENT_ATT>;

/// Snapshot waiting for the RF owner to write it.
pub struct ClientAttSignals {
    pending: Cell<Option<ClientAttSnapshot>>,
    /// `DEL!`: clear the stored tables with a tombstone.
    pub delete: Cell<bool>,
    /// `WIPE`: erase both slots.
    pub wipe: Cell<bool>,
}

impl ClientAttSignals {
    pub const fn new() -> Self {
        Self {
            pending: Cell::new(None),
            delete: Cell::new(false),
            wipe: Cell::new(false),
        }
    }

    pub fn set_pending(&self, snapshot: ClientAttSnapshot) {
        self.pending.replace(Some(snapshot));
    }

    pub fn take_pending(&self) -> Option<ClientAttSnapshot> {
        self.pending.take()
    }

    pub fn discard_pending(&self) {
        self.pending.set(None);
    }
}

static mut SIGNALS: ClientAttSignals = ClientAttSignals::new();

pub fn signals() -> &'static ClientAttSignals {
    // SAFETY: single-threaded example; the Cell is only touched from the Host
    // poll and read by the RF loop between polls.
    unsafe { &*core::ptr::addr_of!(SIGNALS) }
}

pub fn shadow_from_boot() -> ClientAttSnapshot {
    let mut shadow = ClientAttSnapshot::new();
    for record in boot_records() {
        let _ = shadow.push(*record);
    }
    shadow
}

/// Split a resolved identity into the stored key.
pub fn identity_parts(identity: &Identity) -> (u8, [u8; 6]) {
    let bytes = identity.addr.to_bytes();
    (bytes[0], bytes[1..].try_into().expect("fixed length"))
}

/// Restore the stored table for this peer, if there is one.
///
/// Must run after `with_attribute_server`: before that call the Host has no
/// client-table slot for the peer and `set_client_att_table` is a silent no-op.
pub fn restore<M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CONN_MAX: usize>(
    server: &AttributeServer<'_, M, P, ATT_MAX, CONN_MAX>,
    connection: &GattConnection<'_, '_, P>,
    shadow: &[ClientAttRecord],
) {
    bump(STAT_RESTORE_ATTEMPTS);
    if !connection.raw().is_bonded_peer() {
        return;
    }
    let (kind, address) = identity_parts(&connection.raw().peer_identity());
    let Some(record) = shadow
        .iter()
        .find(|record| record.address_kind == kind && record.address == address)
    else {
        bump(STAT_RESTORE_NO_RECORD);
        return;
    };
    let raw = &record.raw[..record.raw_len as usize];
    match ClientAttTableView::try_from_raw(raw) {
        Ok(view) => {
            server.set_client_att_table(connection.raw(), &view);
            // `set_*` keys on the peer identity and silently does nothing when
            // the slot does not match; read back to tell the two apart.
            let applied = server
                .get_client_att_table(connection.raw())
                .is_some_and(|table| table.raw() == raw);
            if applied {
                bump(STAT_RESTORE_OK);
            } else {
                bump(STAT_RESTORE_INVALID);
                set(STAT_LAST_ERROR, 2);
            }
        }
        Err(_) => {
            bump(STAT_RESTORE_INVALID);
            set(STAT_LAST_ERROR, 1);
        }
    }
}

/// Copy this peer's table into the shadow and queue it for persistence.
///
/// Only called for bonded peers and only after the table changed, so a normal
/// reconnect without a CCCD write does not queue a needless flash save.
///
/// `allow_new` is false on disconnect: without a CCCD write in this session the
/// all-zero table says nothing, and recording it would write flash on every
/// clean disconnect of a bonded peer that never subscribed.
pub fn snapshot<M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CONN_MAX: usize>(
    server: &AttributeServer<'_, M, P, ATT_MAX, CONN_MAX>,
    connection: &GattConnection<'_, '_, P>,
    shadow: &mut ClientAttSnapshot,
    allow_new: bool,
) {
    if !connection.raw().is_bonded_peer() {
        return;
    }
    let Some(table) = server.get_client_att_table(connection.raw()) else {
        return;
    };
    let raw = table.raw();
    if raw.len() > wchble::storage::client_att::RAW_MAX {
        bump(STAT_OVERFLOW);
        set(STAT_LAST_ERROR, 3);
        return;
    }
    let (kind, address) = identity_parts(&connection.raw().peer_identity());
    let existing = shadow
        .iter()
        .find(|record| record.address_kind == kind && record.address == address);
    let changed = match existing {
        Some(record) => {
            let len = record.raw_len as usize;
            len != raw.len() || &record.raw[..len] != raw
        }
        None if !allow_new => return,
        None => true,
    };
    if !changed {
        return;
    }
    let mut record = ClientAttRecord {
        address_kind: kind,
        address,
        ..ClientAttRecord::empty()
    };
    if !record.set_raw(raw) {
        bump(STAT_OVERFLOW);
        set(STAT_LAST_ERROR, 4);
        return;
    }
    if let Some(slot) = shadow
        .iter_mut()
        .find(|record| record.address_kind == kind && record.address == address)
    {
        *slot = record;
    } else if shadow.push(record).is_err() {
        bump(STAT_OVERFLOW);
        set(STAT_LAST_ERROR, 5);
        return;
    }
    signals().set_pending(shadow.clone());
    bump(STAT_SNAPSHOTS);
}
