//! CH592 on-target RF verification — init, DevInit registers, ADV_IND TX, RX.
//!
//! HAL owns clocks / SysTick; `wchble` owns RF. Flash with
//! `wlink -d 1a86:8010:<SERIAL> flash --enable-sdi-print <elf>` and read the
//! SDI channel from the Link's USB serial port.
//!
//! Success markers (SDI):
//! - `rf init ok`
//! - `LLE …` / `RFEND …` / `BB …` (DevInit markers)
//! - `tx ch{37,38,39} ok`
//! - `rx listen hit|arm-clear` (arm path; a hit needs a nearby advertiser)
//! - `adv loop` (keeps ADV_IND and the RF_PHY reference frame on air)

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::fmt::Write;
use hal::debug::SDIPrint;
use hal::rcc;
use hal::time::Hertz;
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::rf::family::ch592::{Ch592Radio, BB_BASE, LLE_BASE, RFEND_BASE};
use wchble::rf::regs::{self, bb, lle, rfend};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

/// Advertising access address / CRC init (Core Vol 6 Part B).
const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;

/// LLE `IRQSTAT` bits the vendor treats as RX completion (bits 0 and 2 —
/// see `lleIrqHandler` / `ll_rx_wait_finish` in `ip.o`).
const RX_DONE: u32 = 0x1 | 0x4;
/// `IRQSTAT` bit 17: RX arm cleared / window expired.
const ARM_CLEAR: u32 = 0x2_0000;
/// BB `IRQSTAT` sticky CRC-fail latch, cleared by writing it back.
const BB_CRC_ERR: u32 = 0x20;

/// LLE DMAs through `RXBUFPTR`, so the scratch must be word-aligned.
static RX_DMA: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX_LISTEN: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();

/// Free-running µs clock on the HAL's SysTick timebase.
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

    fn ticks(&self) -> u32 {
        hal::pac::SYSTICK.cntl().read().cntl()
    }
}

impl InstantUs for UsClock {
    fn now_us(&self) -> u32 {
        self.ticks() / self.ticks_per_us
    }

    fn delay_us(&self, us: u32) {
        let start = self.now_us();
        while self.now_us().wrapping_sub(start) < us {}
    }
}

fn mmio(base: usize, off: usize) -> u32 {
    unsafe { regs::read(base, off) }
}

fn dump_regs(out: &mut SDIPrint) {
    let ctrl06 = unsafe { core::ptr::read_volatile((LLE_BASE + 0x06) as *const u16) };
    let _ = writeln!(
        out,
        "LLE 06={:x} 14={:x} 2c={:x} 3c={:x} 50={:x} 54={:x} 0c={:x}",
        ctrl06,
        mmio(LLE_BASE, 0x14),
        mmio(LLE_BASE, 0x2c),
        mmio(LLE_BASE, 0x3c),
        mmio(LLE_BASE, 0x50),
        mmio(LLE_BASE, 0x54),
        mmio(LLE_BASE, 0x0c),
    );
    let _ = writeln!(
        out,
        "RFEND 28={:x} 30={:x} 3c={:x} 44={:x}",
        mmio(RFEND_BASE, 0x28),
        mmio(RFEND_BASE, 0x30),
        mmio(RFEND_BASE, 0x3c),
        mmio(RFEND_BASE, rfend::SYNTH),
    );
    let _ = writeln!(
        out,
        "BB 00={:x} 10={:x} 2c={:x} 34={:x} 38={:x}",
        mmio(BB_BASE, 0x00),
        mmio(BB_BASE, 0x10),
        mmio(BB_BASE, 0x2c),
        mmio(BB_BASE, 0x34),
        mmio(BB_BASE, 0x38),
    );
}

/// Minimal ADV_IND: header + AdvA + flags + complete local name "wch592".
fn build_adv_ind(out: &mut [u8; 32]) -> usize {
    let name = b"wch592";
    let adv_a = [0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x01];
    let mut payload_len = 0usize;
    let mut buf = [0u8; 30];
    buf[payload_len..payload_len + 6].copy_from_slice(&adv_a);
    payload_len += 6;
    buf[payload_len] = 2;
    buf[payload_len + 1] = 0x01;
    buf[payload_len + 2] = 0x06;
    payload_len += 3;
    buf[payload_len] = (1 + name.len()) as u8;
    buf[payload_len + 1] = 0x09;
    buf[payload_len + 2..payload_len + 2 + name.len()].copy_from_slice(name);
    payload_len += 2 + name.len();

    out[0] = 0x40;
    out[1] = payload_len as u8;
    out[2..2 + payload_len].copy_from_slice(&buf[..payload_len]);
    2 + payload_len
}

fn tx_burst(radio: &mut Ch592Radio, clock: &UsClock, out: &mut SDIPrint, frame: &[u8]) {
    for &ch in &[37u8, 38, 39] {
        if let Err(e) = radio.set_channel(ch) {
            let _ = writeln!(out, "set_channel {} err {:?}", ch, e);
            continue;
        }
        for i in 0u32..2 {
            match radio.tx_basic(clock, frame, 0, None) {
                Ok(()) => {
                    let _ = writeln!(out, "tx ch{} ok #{}", ch, i);
                }
                Err(e) => {
                    let _ = writeln!(out, "tx ch{} err {:?} #{}", ch, e, i);
                    dump_regs(out);
                }
            }
            clock.delay_us(10_000);
        }
    }
}

/// Arm RX for `window_half_us` and poll `IRQSTAT` (no NVIC needed).
///
/// Returns the decoded length and CRC result when a packet completed, or
/// `None` on arm-clear / timeout (which still proves the arm path works).
fn rx_once(
    radio: &mut Ch592Radio,
    clock: &UsClock,
    rxbuf: &mut [u8],
    ch: u8,
    window_half_us: u32,
) -> Option<(usize, bool)> {
    if radio.set_channel(ch).is_err() {
        return None;
    }
    // Clear the sticky CRC-fail latch before arming so the flag read after
    // RX_DONE belongs to this packet.
    unsafe { regs::write(BB_BASE, bb::IRQSTAT, BB_CRC_ERR) };
    if radio.rx_basic(clock, rxbuf, window_half_us).is_err() {
        return None;
    }

    let started = clock.now_us();
    let mut result = None;
    loop {
        let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
        if st & RX_DONE != 0 {
            let crc_ok = mmio(BB_BASE, bb::IRQSTAT) & BB_CRC_ERR == 0;
            result = Some((usize::from(rxbuf[1]), crc_ok));
            unsafe { regs::write(LLE_BASE, lle::IRQSTAT, RX_DONE) };
            break;
        }
        if st & ARM_CLEAR != 0 || mmio(LLE_BASE, lle::WINDOW) == 0 {
            unsafe { regs::write(LLE_BASE, lle::IRQSTAT, ARM_CLEAR) };
            break;
        }
        if clock.now_us().wrapping_sub(started) > 20_000 {
            break;
        }
    }
    radio.shut();
    result
}

fn rx_listen(
    radio: &mut Ch592Radio,
    clock: &UsClock,
    out: &mut SDIPrint,
    rxbuf: &mut [u8],
    window_half_us: u32,
) {
    let _ = writeln!(out, "rx round window={}", window_half_us);
    match rx_once(radio, clock, rxbuf, 38, window_half_us) {
        Some((len, crc_ok)) => {
            let _ = writeln!(out, "rx listen hit len={} crc={}", len, crc_ok);
        }
        None => {
            let _ = writeln!(out, "rx listen arm-clear");
        }
    }
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());

    let mut out = SDIPrint;
    let _ = writeln!(
        out,
        "wchble ch592 rf-smoke sysclk={} measured={}",
        rcc::clocks().sysclk.0,
        hal::delay::measured_sysclk().0
    );

    let clock = UsClock::start();
    let rx_dma = RX_DMA.init(DmaBuf::zeroed());
    let rx_listen_buf = RX_LISTEN.init(DmaBuf::zeroed());

    let mut radio = match new_radio_with_dma(&mut rx_dma.0[..]) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(out, "radio new err {:?}", e);
            loop {}
        }
    };

    match radio.init(&clock) {
        Ok(()) => {
            let _ = writeln!(out, "rf init ok");
        }
        Err(e) => {
            let _ = writeln!(out, "rf init err {:?}", e);
            dump_regs(&mut out);
            loop {}
        }
    }

    dump_regs(&mut out);
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);

    let mut frame = [0u8; 32];
    let n = build_adv_ind(&mut frame);
    let _ = writeln!(out, "adv len {}", n);
    tx_burst(&mut radio, &clock, &mut out, &frame[..n]);
    for window_half_us in [2_000u32, 10_000] {
        rx_listen(
            &mut radio,
            &clock,
            &mut out,
            &mut rx_listen_buf.0[..],
            window_half_us,
        );
    }

    // Keep two signals on air for external observers:
    // - ADV_IND on 37/38/39 (real BLE AA/CRC) for a phone / Mac scanner;
    // - the CH592 SDK `RF_PHY` reference frame on channel 39 (AA 0x71764129 /
    //   CRC 0x555555) which a V208 reference receiver decodes.
    let _ = writeln!(out, "adv loop");
    let mut round = 0u32;
    loop {
        radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
        for &ch in &[37u8, 38, 39] {
            if radio.set_channel(ch).is_ok() {
                if let Err(e) = radio.tx_basic(&clock, &frame[..n], 0, None) {
                    let _ = writeln!(out, "adv tx ch{} err {:?}", ch, e);
                }
            }
            clock.delay_us(2_000);
        }

        radio.set_aa_crc(0x7176_4129, 0x55_5555);
        if radio.set_channel(39).is_ok() {
            let rf_frame = [0x00u8, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
            let _ = radio.tx_basic(&clock, &rf_frame, 0, None);
        }

        // Periodically prove the RX path on silicon while the loop runs.
        if round % 20 == 0 {
            radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
            if let Some((len, crc_ok)) =
                rx_once(&mut radio, &clock, &mut rx_listen_buf.0[..], 37, 10_000)
            {
                let _ = writeln!(out, "rx loop hit len={} crc={}", len, crc_ok);
            }
        }

        round = round.wrapping_add(1);
        clock.delay_us(100_000);
    }
}
