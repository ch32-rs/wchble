//! Boot evidence read back over SWD after a halt.

pub const BOOT_MAGIC: u32 = 0x544F_4F42; // "BOOT"
pub const BOOT_VERSION: u32 = 1;
pub const MAGIC_WORD: usize = 0;
pub const VERSION_WORD: usize = 1;

pub const SLOT_A_STATE: usize = 2;
pub const SLOT_B_STATE: usize = 3;
pub const SEQ_A: usize = 4;
pub const SEQ_B: usize = 5;
pub const SELECTED: usize = 6;
pub const ATTEMPTS: usize = 7;
pub const ACTION: usize = 8;
pub const META_LOAD: usize = 9;
pub const META_SAVE: usize = 10;
pub const ELAPSED_US: usize = 11;
pub const ROLLBACK: usize = 12;
pub const ACTION_BOOT: u32 = 0;
pub const ACTION_NO_VALID: u32 = 1;
pub const ACTION_ALL_FAILED: u32 = 2;
pub const ACTION_META_FAILED: u32 = 3;

// Placed in the STATS region at the bottom of RAM (boot-stats.x): the app
// that runs after the jump must never zero or overwrite this evidence.
#[link_section = ".boot_stats"]
#[no_mangle]
pub static mut BOOT_STATS: [u32; 32] = [0; 32];

/// Clear stale words from the previous boot; only known fields are written.
pub fn init() {
    // SAFETY: single-threaded, before any other writer exists.
    unsafe {
        let words = core::ptr::addr_of_mut!(BOOT_STATS).cast::<u32>();
        for index in 0..32 {
            words.add(index).write_volatile(0);
        }
    }
}

/// Complete the record; magic is written last so a reader can trust it.
pub fn complete() {
    put(VERSION_WORD, BOOT_VERSION);
    put(MAGIC_WORD, BOOT_MAGIC);
}

pub fn put(slot: usize, value: u32) {
    // SAFETY: single-threaded boot manager; only this core writes the array.
    unsafe {
        let stats = core::ptr::addr_of_mut!(BOOT_STATS).cast::<u32>();
        stats.add(slot).write_volatile(value);
    }
}
