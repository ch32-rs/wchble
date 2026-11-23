//! X6b boot manager: validate both OTA slots, pick one, jump (see README.md).

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use ch5xx_hal::flash::Flash;
use qingke_rt::entry;
use wchble::ota::{self, BootAction, Metadata, ParkReason};
use wchble::storage::{DualCopyStore, LoadOutcome};
use {panic_halt as _, portable_atomic as _};

mod dataflash;
mod jump;
mod slots;
mod stats;

use dataflash::HalDataFlash;
use slots::{SlotState, SLOT_BASES};

fn now_ticks() -> u32 {
    hal::pac::SYSTICK.cntl().read().cntl()
}

#[entry]
fn main() -> ! {
    let p = hal::init(hal::rcc::Config::HSE_PLL_78MHZ.into());
    let ticks_per_us = (hal::rcc::clocks().sysclk.0 / 1_000_000).max(1);
    let started = now_ticks();
    stats::init();

    let mut flash = Flash::new(p.FLASHROM);

    // Header pass first: it borrows only CodeFlash.
    let mut states = [SlotState::Read; 2];
    let mut seq = [0u32; 2];
    {
        let mut code = flash.code_flash();
        for i in 0..2 {
            let (state, header) = slots::read_header(&mut code, SLOT_BASES[i]);
            states[i] = state;
            if let Some(header) = header {
                seq[i] = header.sequence;
            }
        }
    }

    // One DataFlash borrow covers load and save; a bad record is "none".
    // meta_load: 0 blank, 1 loaded, 2 record but bad payload, 3 untrusted
    // pages, 4 read error.
    let mut load_state = 0u32;
    let mut save_state = 0u32;
    let mut store = DualCopyStore::new(HalDataFlash::new(flash.data_flash()), ota::METADATA_SLOTS);
    let mut payload = [0u8; ota::METADATA_LEN];
    let mut meta = None;
    let mut untrusted = false;
    match store.load_checked(&mut payload) {
        Ok(LoadOutcome::Record(len)) if len == ota::METADATA_LEN => {
            match Metadata::decode(payload[..ota::METADATA_LEN].try_into().unwrap()) {
                Some(record) => {
                    meta = Some(record);
                    load_state = 1;
                }
                None => {
                    load_state = 2;
                    untrusted = true;
                }
            }
        }
        Ok(LoadOutcome::Record(_)) => {
            load_state = 2;
            untrusted = true;
        }
        Ok(LoadOutcome::Empty) => {}
        Ok(LoadOutcome::Untrusted) => {
            load_state = 3;
            untrusted = true;
        }
        Err(_) => {
            load_state = 4;
            untrusted = true;
        }
    }

    // Header validation only: the engine read path is not reliable enough
    // for a full-image CRC at boot (see ch585-ota-spec §3.3). Image integrity
    // is established by the writer and carried by the metadata good mark.
    let valid = [states[0] == SlotState::Valid, states[1] == SlotState::Valid];
    // Lost metadata must not revive a failed slot, so the factory slot wins
    // until a fresh record is on flash (see ch585-ota-spec §3.3).
    let decision = if untrusted {
        ota::select_recovery(valid, seq)
    } else {
        ota::select(meta, valid, seq)
    };

    // Persist the decision; a failed save fails closed (no jump).
    if let Some(next) = decision.persist {
        match store.save(&next.encode()) {
            Ok(()) => save_state = 1,
            Err(_) => save_state = 2,
        }
    }

    stats::put(stats::SLOT_A_STATE, states[0] as u32);
    stats::put(stats::SLOT_B_STATE, states[1] as u32);
    stats::put(stats::SEQ_A, seq[0]);
    stats::put(stats::SEQ_B, seq[1]);
    stats::put(stats::META_LOAD, load_state);
    stats::put(stats::META_SAVE, save_state);
    stats::put(
        stats::ELAPSED_US,
        now_ticks().wrapping_sub(started) / ticks_per_us,
    );

    match decision.action {
        BootAction::Boot {
            slot,
            attempts_done,
            rollback,
            ..
        } if save_state != 2 => {
            stats::put(stats::SELECTED, slot as u32);
            stats::put(stats::ATTEMPTS, attempts_done as u32);
            stats::put(stats::ACTION, stats::ACTION_BOOT);
            stats::put(stats::ROLLBACK, rollback as u32);
            stats::complete();
            // SAFETY: both slots were validated above; the app owns the CPU.
            unsafe { jump::jump_to_slot(SLOT_BASES[slot as usize]) }
        }
        action => {
            let code = if save_state == 2 {
                stats::ACTION_META_FAILED
            } else {
                match action {
                    BootAction::Park(ParkReason::NoValidSlot) => stats::ACTION_NO_VALID,
                    BootAction::Park(ParkReason::AllFailed) => stats::ACTION_ALL_FAILED,
                    _ => stats::ACTION_META_FAILED,
                }
            };
            stats::put(stats::SELECTED, 0xFF);
            stats::put(stats::ACTION, code);
            stats::complete();
            loop {
                hal::pac::SYS
                    .iwdg_kr()
                    .write_value(hal::pac::sys::regs::IwdgKr(0xAAAA));
            }
        }
    }
}
