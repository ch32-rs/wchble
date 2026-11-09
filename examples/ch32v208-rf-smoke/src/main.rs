//! CH32V208 on-target RF verification — init, regs, multi-channel TX, RX listen,
//! SoftRunner ADV_IND schedule.
//!
//! HAL owns clocks / HSE trim / timebase; `wchble` owns RF + soft HCI state.
//! Flash with `wlink -d 1a86:8010:<SERIAL> flash --enable-sdi-print …`.
//!
//! Success markers (SDI):
//! - `rf init ok`
//! - `regs ok` (LLE/BB/RFEND match open DevInit)
//! - `tx ch{37,38,39} ok`
//! - `rx listen` (hit or timeout — both prove arm path)
//! - `soft adv` + `soft tx chN ok`
//! - `smoke done`

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use ch32_hal::interrupt;
use ch32_hal::pac::SYSTICK;
use ch32_hal::rcc::{
    AHBPrescaler, APBPrescaler, Config as RccConfig, HsPllSource, Hse, HseMode, LsConfig, Pll,
    PllMul, PllPreDiv, PllSource, Sysclk,
};
use ch32_hal::time::Hertz;
use ch32_hal::try_println as println;
use static_cell::StaticCell;
use wchble::hci::SoftRunner;
use wchble::rf::family::ch32v208::{self, Ch32v208Radio, BB_BASE, LLE_BASE, RFEND_BASE};
use wchble::rf::regs::{self, lle, lle_irq};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{PhyMode, Radio};
use wchble::time::InstantUs;
use {ch32_hal as _, panic_halt as _};
use ch32_hal as hal;

/// `RCC_AHBPeriph_BLE_CRC` — AHBPCENR bits 17/18 (BLE) + bit 6 (CRC).
const RCC_AHB_BLE_CRC: u32 = 0x0003_0040;
const RCC_AHBPCENR: *mut u32 = 0x4002_1014 as *mut u32;
/// `OSC->HSE_CAL_CTRL` (AHBPERIPH_BASE + 0x202C).
const OSC_HSE_CAL_CTRL: *mut u32 = 0x4002_202C as *mut u32;

/// Advertising access address / CRC init (Core Vol 6 Part B).
const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;

/// LLE DMAs through `RXBUFPTR`, so the scratch must be word-aligned.
static RX_DMA: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX_LISTEN: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();

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

fn mmio(base: usize, off: usize) -> u32 {
    unsafe { regs::read(base, off) }
}

/// Dump sticky DevInit markers for the V208 open path.
fn dump_and_check_regs() -> bool {
    let lle_14 = mmio(LLE_BASE, 0x14);
    let lle_1c = mmio(LLE_BASE, 0x1c);
    let lle_2c = mmio(LLE_BASE, 0x2c);
    let lle_3c = mmio(LLE_BASE, 0x3c);
    let lle_0c = mmio(LLE_BASE, 0x0c);
    let rfend_28 = mmio(RFEND_BASE, 0x28);
    let bb_34 = mmio(BB_BASE, 0x34);
    let bb_0 = mmio(BB_BASE, 0);

    println!(
        "LLE 14={:x} 1c={:x} 2c={:x} 3c={:x} 0c={:x}",
        lle_14, lle_1c, lle_2c, lle_3c, lle_0c
    );
    println!("RFEND 28={:x} BB 34={:x} 0={:x}", rfend_28, bb_34, bb_0);

    // Open V208 LLE_DevInit / RFEND / BB markers. RFEND+0x28 DevInit writes
    // 0x480; post-cal silicon may OR sticky high bits (observed 0x1480).
    let expect = ch32v208::LLE_DEV_INIT.stores;
    let rfend_ok =
        (rfend_28 & 0x0fff) == (ch32v208::RFEND_INIT.dev_init_0x28.value & 0x0fff);
    let ok = lle_14 == expect[0].value
        && lle_1c == expect[1].value
        && lle_2c == expect[3].value
        && lle_3c == expect[5].value
        && rfend_ok
        && bb_34 == ch32v208::BB_DEV_INIT.cfg34.value;

    if ok {
        println!("regs ok");
    } else {
        println!("regs mismatch");
    }
    ok
}

/// Minimal ADV_IND: header + AdvA + flags + complete local name "wchble".
fn build_adv_ind(out: &mut [u8; 32]) -> usize {
    let name = b"wchble";
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

fn tx_burst_on_channels(radio: &mut Ch32v208Radio, clock: &UsClock, frame: &[u8], channels: &[u8]) {
    for &ch in channels {
        if let Err(e) = radio.set_channel(ch) {
            println!("set_channel {} err {:?}", ch, e);
            continue;
        }
        for i in 0u32..2 {
            match radio.tx_basic(clock, frame, 0, None) {
                Ok(()) => println!("tx ch{} ok #{}", ch, i),
                Err(e) => println!("tx ch{} err {:?} #{}", ch, e, i),
            }
            clock.delay_us(10_000);
        }
    }
}

/// Arm RX for ~5 ms and poll IRQSTAT (no NVIC) for RX_DONE / window expiry.
fn rx_listen_poll(radio: &mut Ch32v208Radio, clock: &UsClock, rxbuf: &mut [u8]) {
    const WINDOW_HALF_US: u32 = 10_000; // 5 ms
    if let Err(e) = radio.set_channel(37) {
        println!("rx set_channel err {:?}", e);
        return;
    }
    match radio.rx_basic(clock, rxbuf, WINDOW_HALF_US) {
        Ok(()) => println!("rx armed"),
        Err(e) => {
            println!("rx arm err {:?}", e);
            return;
        }
    }

    let started = clock.now_us();
    let deadline = started.wrapping_add(8_000);
    loop {
        let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
        let window = unsafe { regs::read(LLE_BASE, lle::WINDOW) };
        if st & lle_irq::RX_DONE != 0 {
            let len = rxbuf.get(1).copied().unwrap_or(0);
            println!("rx hit len={} irq={:x}", len, st);
            unsafe {
                regs::write(LLE_BASE, lle::IRQSTAT, lle_irq::RX_DONE);
            }
            break;
        }
        if st & lle_irq::CLEAR_ARM != 0 || window == 0 {
            println!("rx timeout irq={:x} win={}", st, window);
            unsafe {
                regs::write(LLE_BASE, lle::IRQSTAT, lle_irq::CLEAR_ARM);
            }
            break;
        }
        if clock.now_us().wrapping_sub(deadline) as i32 >= 0 {
            println!("rx poll deadline irq={:x} win={}", st, window);
            break;
        }
    }
    radio.shut();
}

/// SoftRunner holds AdvData/channel map; smoke drives `tx_basic` from that PDU.
fn soft_adv_tx(radio: &mut Ch32v208Radio, clock: &UsClock) {
    let mut soft = SoftRunner::new();
    soft.set_bd_addr([0x00, 0x00, 0x00, 0xc1, 0xff, 0xee]);
    soft.set_random_addr([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x02]);
    soft.ll.adv.channel_map = 0x07;
    soft.ll.adv.interval_slots = 0x00a0; // 100 ms
    let ad = [
        0x02, 0x01, 0x06, // flags
        0x08, 0x09, b's', b'o', b'f', b't', b'a', b'd', b'v',
    ];
    soft.ll.adv.set_adv_data(ad.len() as u8, &ad);
    soft.ll.adv.enabled = true;

    let mut pdu = [0u8; 40];
    let Some(n) = soft.build_adv_pdu(&mut pdu) else {
        println!("soft adv build fail");
        return;
    };
    println!("soft adv len {}", n);

    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    for ch in soft.adv_channels() {
        if let Err(e) = radio.set_channel(ch) {
            println!("soft set_channel {} err {:?}", ch, e);
            continue;
        }
        match radio.tx_basic(clock, &pdu[..n], 0, None) {
            Ok(()) => println!("soft tx ch{} ok", ch),
            Err(e) => println!("soft tx ch{} err {:?}", ch, e),
        }
        clock.delay_us(soft.adv_interval_us().min(50_000));
    }
}

#[qingke_rt::entry]
fn main() -> ! {
    hal::debug::SDIPrint::enable();
    // CH32V208WBU6 (D8W): 32 MHz HSE → /4 * 12 = 96 MHz SYSCLK (nimble default).
    let _p = hal::init(hal::Config {
        rcc: RccConfig {
            hse: Some(Hse {
                freq: Hertz(32_000_000),
                mode: HseMode::Oscillator,
            }),
            sys: Sysclk::PLL,
            pll_src: PllSource::HSE,
            pll: Some(Pll {
                prediv: PllPreDiv::DIV4,
                mul: PllMul::MUL12,
            }),
            pllx: None,
            ahb_pre: AHBPrescaler::DIV1,
            apb1_pre: APBPrescaler::DIV2,
            apb2_pre: APBPrescaler::DIV1,
            ls: LsConfig::default(),
            hspll_src: HsPllSource::HSI,
            hspll: None,
        },
        dma_interrupt_priority: interrupt::Priority::P0,
    });

    println!("wchble ch32v208 rf-verify");
    println!("chip {}", hal::signature::chip_id().name());

    enable_ble_clock_and_hse_trim();

    let hclk = hal::rcc::clocks().hclk.0;
    let clock = UsClock::start(hclk);
    println!("hclk={} Hz", hclk);

    let rx = &mut RX_DMA.init(DmaBuf::zeroed()).0;
    let mut radio = match Ch32v208Radio::new(rx) {
        Ok(r) => r,
        Err(e) => {
            println!("radio new err {:?}", e);
            loop {}
        }
    };

    match radio.init(&clock) {
        Ok(()) => println!("rf init ok"),
        Err(e) => {
            println!("rf init err {:?}", e);
            loop {}
        }
    }

    let _ = dump_and_check_regs();

    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);

    let mut frame = [0u8; 32];
    let n = build_adv_ind(&mut frame);
    println!("adv len {}", n);

    // 1) Multi-channel TX smoke
    tx_burst_on_channels(&mut radio, &clock, &frame[..n], &[37, 38, 39]);

    // 2) RX listen (environment-dependent; timeout still validates arm path)
    let listen = &mut RX_LISTEN.init(DmaBuf::zeroed()).0;
    rx_listen_poll(&mut radio, &clock, listen);

    // 3) SoftRunner → RF adv schedule
    soft_adv_tx(&mut radio, &clock);

    println!("smoke done");
    loop {
        clock.delay_us(1_000_000);
    }
}
