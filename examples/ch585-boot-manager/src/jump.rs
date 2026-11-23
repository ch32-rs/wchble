//! Enter a slot. The app's `.init` (`j handle_reset`) owns all setup from
//! here: gp/sp/mtvec, the `.highcode`/`.data` copies and the bss clear.

use wchble::ota::ENTRY_OFFSET;

/// # Safety
/// `slot_base` must be a validated slot; this never returns.
#[inline(never)]
pub unsafe fn jump_to_slot(slot_base: u32) -> ! {
    let entry = (slot_base + ENTRY_OFFSET) as usize;
    unsafe {
        core::arch::asm!(
            "csrci mstatus, 8",
            "fence.i",
            "jr {entry}",
            entry = in(reg) entry,
            options(noreturn)
        );
    }
}
