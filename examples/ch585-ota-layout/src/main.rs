//! OTA slot-A layout: the app links at 0x4000, 0x0 holds a 4-byte jump.
//!
//! The reset vector sits at 0x0, so the one image contains both the stub and
//! the app: `.boot_entry` jumps to slot A and the app's `_start` (the first
//! vector-table word) takes over. Everything else links into
//! `0x4000..0x3A000` (216 KiB), leaving `0x3A000..0x70000` as slot B; the
//! DataFlash at `0x70000` carries the OTA metadata.
//!
//! Non-secure release only: a secure build of the trouble-host examples is
//! larger than one slot, so this layout example stays on the plain image.
//! It only advertises; connection handling belongs to the app, not the layout.
//!
//! Build, flash as one ELF with the single-session preflight runner, then scan
//! for the name (commands run from the repository root):
//!
//! ```console
//! cargo build --release --target riscv32imc-unknown-none-elf
//! tools/ch585-preflight/target/release/ch585-preflight --probe <SERIAL> \
//!     --chip CH585 --protocol jtag --verify \
//!     target/riscv32imc-unknown-none-elf/release/ch585-ota-layout
//! swift examples/ch585-rf-smoke/tools/scan_ch585.swift wch585-ota 8
//! ```

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::ptr::addr_of;
use hal::rcc;
use hal::time::Hertz;
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

/// Advertising access address / CRC init (Core Vol 6 Part B).
const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;
/// Local name this image advertises; distinguishes it from the smoke image.
const NAME: &[u8] = b"wch585-ota";

// Only code outside the slot. `lui t0, 4` is slot A; keep it in sync with
// `memory.x`.
core::arch::global_asm!(
    ".section .boot_entry, \"ax\"",
    ".global _boot_entry",
    "_boot_entry:",
    "lui t0, 4",
    "jr t0",
);

/// Boot evidence for a probe read once the radio is stopped: magic, the
/// app's link base, the advertisement length and the burst count.
#[no_mangle]
static mut OTA_SLOT: [u32; 4] = [0; 4];

/// LLE DMAs through `RXBUFPTR`, so the scratch must be word-aligned.
static RX_DMA: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();

/// SysTick microseconds; the HAL owns the counter, this only reads it.
struct UsClock {
    ticks_per_us: u32,
}

impl UsClock {
    fn start() -> Self {
        let hz = hal::delay::measured_sysclk().0.max(1_000_000);
        Self {
            ticks_per_us: (hz / 1_000_000).max(1),
        }
    }
}

impl InstantUs for UsClock {
    fn now_us(&self) -> u32 {
        hal::pac::SYSTICK.cntl().read().cntl() / self.ticks_per_us
    }

    fn delay_us(&self, us: u32) {
        let start = self.now_us();
        while self.now_us().wrapping_sub(start) < us {}
    }
}

/// Legacy ADV_NONCONN_IND: header + AdvA + flags + complete local name.
fn build_adv(out: &mut [u8; 32]) -> usize {
    // Static random address C1:FF:EE:00:00:03, least-significant byte first.
    let adv_a = [0x03, 0x00, 0x00, 0xEE, 0xFF, 0xC1];
    let mut payload = [0u8; 30];
    let mut len = 0usize;
    payload[len..len + adv_a.len()].copy_from_slice(&adv_a);
    len += adv_a.len();
    payload[len..len + 3].copy_from_slice(&[2, 0x01, 0x06]);
    len += 3;
    payload[len] = (1 + NAME.len()) as u8;
    payload[len + 1] = 0x09;
    payload[len + 2..len + 2 + NAME.len()].copy_from_slice(NAME);
    len += 2 + NAME.len();

    out[0] = 0x42; // ADV_NONCONN_IND, TxAdd: the address above is random
    out[1] = len as u8;
    out[2..2 + len].copy_from_slice(&payload[..len]);
    2 + len
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    let clock = UsClock::start();

    let rx_dma = RX_DMA.init(DmaBuf::zeroed());
    let mut radio = match new_radio_with_dma(&mut rx_dma.0[..]) {
        Ok(radio) => radio,
        Err(_) => halt(),
    };
    if radio.init(&clock).is_err() {
        halt();
    }
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);

    let mut frame = [0u8; 32];
    let len = build_adv(&mut frame);
    // `_stext` is `ORIGIN(REGION_TEXT)`: 0x4000 in this layout.
    extern "C" {
        static _stext: u8;
    }
    let text_base = addr_of!(_stext) as u32;
    unsafe {
        OTA_SLOT[0] = 0x4f54_4101; // "OTA" + layout version 1
        OTA_SLOT[1] = text_base;
        OTA_SLOT[2] = len as u32;
    }

    loop {
        for channel in [37u8, 38, 39] {
            let _ = radio.set_channel(channel);
            // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or
            // stops the engine on error; `frame` lives across the call.
            let _ = unsafe { radio.tx_basic(&clock, &frame[..len], 0, None) };
            clock.delay_us(3_000);
        }
        unsafe {
            OTA_SLOT[3] = OTA_SLOT[3].wrapping_add(1);
        }
        clock.delay_us(20_000);
    }
}

/// Feed the watchdog so a reset cannot clear the observation words.
fn halt() -> ! {
    loop {
        hal::pac::SYS
            .iwdg_kr()
            .write_value(hal::pac::sys::regs::IwdgKr(0xAAAA));
    }
}
