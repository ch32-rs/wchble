//! CH32V208 on-target RF smoke — init + ADV_IND on channel 37.
//!
//! HAL owns clocks / HSE trim / timebase; `wchble` owns RF init/TX.
//! Flash with `cargo run --release` (wlink) from this directory.
//!
//! Success criteria (SDI print):
//! - `rf init ok`
//! - `tx ch37 ok` (or `tx timeout` if antenna/clock wrong — still proves MMIO path)

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use ch32_hal::pac::SYSTICK;
use ch32_hal::println;
use static_cell::StaticCell;
use wchble::rf::family::ch32v208::Ch32v208Radio;
use wchble::rf::txrx::RX_DMA_MIN;
use wchble::rf::{PhyMode, Radio};
use wchble::time::InstantUs;
use {ch32_hal as hal, panic_halt as _};

/// `RCC_AHBPeriph_BLE_CRC` — AHBPCENR bits 17/18 (BLE) + bit 6 (CRC).
const RCC_AHB_BLE_CRC: u32 = 0x0003_0040;
const RCC_AHBPCENR: *mut u32 = 0x4002_1014 as *mut u32;
/// `OSC->HSE_CAL_CTRL` (AHBPERIPH_BASE + 0x202C).
const OSC_HSE_CAL_CTRL: *mut u32 = 0x4002_202C as *mut u32;

/// Advertising access address / CRC init (Core Vol 6 Part B).
const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;

static RX_DMA: StaticCell<[u8; RX_DMA_MIN]> = StaticCell::new();

/// Free-running µs clock on SysTick (HCLK), for WaitTune / TX deadline polls.
struct UsClock {
    ticks_per_us: u32,
}

impl UsClock {
    fn start(hclk_hz: u32) -> Self {
        let ticks_per_us = (hclk_hz / 1_000_000).max(1);
        use ch32_hal::pac::systick::vals;
        SYSTICK.cntl().write_value(0);
        SYSTICK.cnth().write_value(0);
        SYSTICK.cmpl().write_value(0xffff_ffff);
        SYSTICK.ctlr().modify(|w| {
            w.set_stclk(vals::Stclk::HCLK);
            w.set_ste(true);
        });
        Self { ticks_per_us }
    }

    fn ticks(&self) -> u64 {
        let h = SYSTICK.cnth().read() as u64;
        let l = SYSTICK.cntl().read() as u64;
        (h << 32) | l
    }
}

impl InstantUs for UsClock {
    fn now_us(&self) -> u32 {
        (self.ticks() / u64::from(self.ticks_per_us)) as u32
    }

    fn delay_us(&self, us: u32) {
        let start = self.now_us();
        while self.now_us().wrapping_sub(start) < us {}
    }
}

fn enable_ble_clock_and_hse_trim() {
    unsafe {
        let ahb = read_volatile(RCC_AHBPCENR);
        write_volatile(RCC_AHBPCENR, ahb | RCC_AHB_BLE_CRC);

        // EXAM/BLE/HAL/MCU.c WCHBLE_Init — load capacitance + drive.
        let mut cal = read_volatile(OSC_HSE_CAL_CTRL);
        cal &= !(0x07 << 28);
        cal |= 0x03 << 28;
        cal |= 3 << 24;
        write_volatile(OSC_HSE_CAL_CTRL, cal);
    }
}

/// Minimal ADV_IND: header + AdvA + flags + complete local name "wchble".
fn build_adv_ind(out: &mut [u8; 32]) -> usize {
    // PDU header: ADV_IND (0x0), TxAdd=random (bit6), length follows.
    let name = b"wchble";
    let adv_a = [0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x01]; // random-static-ish
    // AD: flags (02 01 06) + complete name
    let mut payload_len = 0usize;
    let mut buf = [0u8; 30];
    buf[payload_len..payload_len + 6].copy_from_slice(&adv_a);
    payload_len += 6;
    buf[payload_len] = 2; // len
    buf[payload_len + 1] = 0x01; // flags
    buf[payload_len + 2] = 0x06;
    payload_len += 3;
    buf[payload_len] = (1 + name.len()) as u8;
    buf[payload_len + 1] = 0x09; // complete local name
    buf[payload_len + 2..payload_len + 2 + name.len()].copy_from_slice(name);
    payload_len += 2 + name.len();

    out[0] = 0x40; // ADV_IND + random TxAdd
    out[1] = payload_len as u8;
    out[2..2 + payload_len].copy_from_slice(&buf[..payload_len]);
    2 + payload_len
}

#[qingke_rt::entry]
fn main() -> ! {
    hal::debug::SDIPrint::enable();
    let _p = hal::init(Default::default());

    println!("wchble ch32v208 rf-smoke");
    println!("chip {}", hal::signature::chip_id().name());

    enable_ble_clock_and_hse_trim();

    let hclk = hal::rcc::clocks().hclk.0;
    let clock = UsClock::start(hclk);
    println!("hclk={} Hz", hclk);

    let rx = RX_DMA.init([0; RX_DMA_MIN]);
    let mut radio = match Ch32v208Radio::new(rx) {
        Ok(r) => r,
        Err(e) => {
            println!("radio new err {:?}", e);
            loop {}
        }
    };

    // IRQs stay off through init (crate clears IRQSTAT).
    match radio.init(&clock) {
        Ok(()) => println!("rf init ok"),
        Err(e) => {
            println!("rf init err {:?}", e);
            loop {}
        }
    }

    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    if let Err(e) = radio.set_channel(37) {
        println!("set_channel err {:?}", e);
        loop {}
    }

    let mut frame = [0u8; 32];
    let n = build_adv_ind(&mut frame);
    println!("adv len {}", n);

    // Burst a few ADV_IND PDUs on ch37 so a sniffer / phone nearby can see them.
    for i in 0u32..8 {
        match radio.tx_basic(&clock, &frame[..n], 0, None) {
            Ok(()) => println!("tx ch37 ok #{}", i),
            Err(e) => println!("tx ch37 err {:?} #{}", e, i),
        }
        clock.delay_us(20_000); // ~20 ms spacing
    }

    println!("smoke done");
    loop {
        clock.delay_us(1_000_000);
    }
}
