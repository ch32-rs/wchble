//! CH585 bounded RX/stop register trace; see README.md for the experiment.
//! No DMA data is inspected or reused, even after shut().

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use hal::{rcc, time::Hertz};
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::ll::adv::AdvState;
use wchble::rf::family::ch585::{BB_BASE, LLE_BASE, RFEND_BASE};
use wchble::rf::regs::{self, bb, lle};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

static RX_SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX_ONCE: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static TX_ONCE: StaticCell<DmaBuf<64>> = StaticCell::new();

#[no_mangle]
static mut OBS: [u32; 20] = [0; 20];

const ROW_WORDS: usize = 12;
const ROWS: usize = 64;
#[no_mangle]
static mut TRACE: [u32; ROWS * ROW_WORDS] = [0; ROWS * ROW_WORDS];

// Features select one independent run per complete power cycle.
const PASSIVE: bool = cfg!(feature = "passive");
const EARLY_STOP: bool = cfg!(feature = "early-stop");
const OBSERVE_US: u32 = if EARLY_STOP { 500 } else { 20_000 };

fn trace(clock: &UsClock, started: u32, phase: u32, count: &mut usize) {
    if *count >= ROWS {
        record(13, 1); // overflow; later mandatory checkpoints may be missing
        return;
    }
    // Sequential, non-atomic MMIO snapshots. No DMA access, W1C or ISR here.
    let row = [
        clock.now_us().wrapping_sub(started),
        phase,
        read_reg(LLE_BASE, lle::IRQSTAT),
        read_reg(BB_BASE, bb::IRQSTAT),
        read_reg(LLE_BASE, lle::CMD),
        read_reg(LLE_BASE, lle::WINDOW),
        read_reg(LLE_BASE, lle::MODE),
        read_reg(LLE_BASE, lle::GUARD),
        read_reg(BB_BASE, bb::RFCTRL),
        read_reg(RFEND_BASE, 0x08),
        read_reg(LLE_BASE, 0x7c),
        hal::pac::SYSTICK.stk_cntl().read().cntl(),
    ];
    for (i, word) in row.into_iter().enumerate() {
        unsafe {
            core::ptr::addr_of_mut!(TRACE)
                .cast::<u32>()
                .add(*count * ROW_WORDS + i)
                .write_volatile(word);
        }
    }
    *count += 1;
    record(12, *count as u32); // publish only a complete row
}

fn record(index: usize, value: u32) {
    // OBS is separate from the radio's DMA buffers and has one CPU writer.
    unsafe {
        core::ptr::addr_of_mut!(OBS)
            .cast::<u32>()
            .add(index)
            .write_volatile(value)
    }
}

fn read_reg(base: usize, offset: usize) -> u32 {
    unsafe { regs::read(base, offset) }
}

fn snapshot(elapsed: u32) {
    record(5, read_reg(LLE_BASE, lle::IRQSTAT));
    record(6, read_reg(BB_BASE, bb::IRQSTAT));
    record(7, read_reg(LLE_BASE, lle::CMD));
    record(8, read_reg(LLE_BASE, lle::WINDOW));
    record(9, elapsed);
}

fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

struct UsClock(u32);
impl InstantUs for UsClock {
    fn now_us(&self) -> u32 {
        hal::pac::SYSTICK.stk_cntl().read().cntl() / self.0
    }
    fn delay_us(&self, us: u32) {
        let start = self.now_us();
        while self.now_us().wrapping_sub(start) < us {}
    }
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    let clock = UsClock((hal::delay::measured_sysclk().0 / 1_000_000).max(1));
    record(0, 0x5258_4f31);
    record(1, 2);
    record(14, u32::from(PASSIVE) | (u32::from(EARLY_STOP) << 1));
    record(15, 10_000);
    record(17, clock.0);
    record(18, unsafe { (0x4000_1044 as *const u8).read_volatile() }
        as u32);
    record(2, 1);
    record(10, 37);

    let scratch = RX_SCRATCH.init(DmaBuf::zeroed());
    let rx = RX_ONCE.init(DmaBuf::zeroed());
    let tx = TX_ONCE.init(DmaBuf::zeroed());
    let mut adv = AdvState {
        enabled: true,
        own_addr: [0x02, 0, 0, 0xee, 0xff, 0xc1],
        ..AdvState::default()
    };
    let data = [2, 1, 6, 7, 9, b'w', b'c', b'h', b'5', b'8', b'5'];
    if !adv.set_adv_data(data.len() as u8, &data) {
        record(2, 9);
        park();
    }
    let len = match adv.build_adv_scan_ind(&mut tx.0) {
        Some(n) => n,
        None => {
            record(2, 9);
            park();
        }
    };

    let mut radio = match new_radio_with_dma(&mut scratch.0) {
        Ok(r) => r,
        Err(_) => {
            record(2, 9);
            park();
        }
    };
    if radio.init(&clock).is_err() {
        record(2, 9);
        park();
    }
    record(2, 2);
    radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    if radio.set_channel(37).is_err() {
        record(2, 9);
        park();
    }
    clock.delay_us(2_000_000);
    // tx_basic also force-stops a stale command; do not invoke it while busy.
    if read_reg(LLE_BASE, lle::CMD) & 3 != 0 {
        snapshot(0);
        record(2, 9);
        park();
    }
    record(2, 3);
    let tx_started = clock.now_us();
    let tx_result = if PASSIVE {
        Ok(())
    } else {
        radio.tx_basic(&clock, &tx.0[..len], 0, None)
    };
    // Keep RAM instrumentation out of the TX -> RX gap. This remains the
    // blocking TX + scanner RX path, not a verified advertiser turnaround.
    let tx_returned = clock.now_us();
    let cmd = read_reg(LLE_BASE, lle::CMD);
    if tx_result.is_err() || cmd & 3 != 0 {
        record(3, if tx_result.is_ok() { 1 } else { 2 });
        record(11, cmd);
        snapshot(0);
        record(2, 9);
        park();
    }
    // Match the smoke's pre-arm CRC-latch clear; do not interpret it as CRC.
    unsafe { regs::write(BB_BASE, bb::IRQSTAT, 0x20) };
    let result = radio.rx_basic(&clock, &mut rx.0, 10_000);
    let started = clock.now_us();
    record(3, if PASSIVE { 0 } else { 1 });
    record(11, cmd);
    record(4, if result.is_ok() { 1 } else { 2 });
    record(16, started.wrapping_sub(tx_returned)); // CPU TX-return to RX-arm
    record(19, tx_returned.wrapping_sub(tx_started));

    if result.is_err() {
        snapshot(0);
        record(2, 9);
        park();
    }
    record(2, 6);

    // Keep every status/command transition and a 1-ms heartbeat. WINDOW is
    // sampled but excluded from the transition key (it counts continuously).
    // No first-bit exit: observe expiry and the explicit shut separately.
    let mut count = 0;
    let mut previous = (u32::MAX, u32::MAX, u32::MAX);
    let mut last = 0;
    loop {
        let elapsed = clock.now_us().wrapping_sub(started);
        let key = (
            read_reg(LLE_BASE, lle::IRQSTAT),
            read_reg(BB_BASE, bb::IRQSTAT),
            read_reg(LLE_BASE, lle::CMD),
        );
        if key != previous || elapsed.wrapping_sub(last) >= 1_000 {
            // Reserve four rows for mandatory before/after-stop checkpoints.
            if count < ROWS - 4 {
                trace(&clock, started, 1, &mut count);
            } else {
                record(13, 1);
            }
            previous = key;
            last = elapsed;
        }
        if elapsed >= OBSERVE_US {
            break;
        }
    }
    trace(&clock, started, 2, &mut count);
    record(2, 10); // explicit shutdown starts; not a DMA-release assertion
    radio.shut();
    trace(&clock, started, 3, &mut count);
    clock.delay_us(100);
    trace(&clock, started, 4, &mut count);
    clock.delay_us(5_000);
    trace(&clock, started, 5, &mut count);
    snapshot(clock.now_us().wrapping_sub(started));
    record(2, 11); // trace complete; all DMA storage remains quarantined
    park();
}
