//! P2: finite scannable advertiser, following ch32v208-nimble PHY event flow.
//! Dedicated CH585 registers stay in the existing RF backend. See README.md.
#![no_std]
#![no_main]

use ch5xx_hal as hal;
use hal::{rcc, time::Hertz};
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::ll::adv::AdvState;
use wchble::rf::family::ch585::{Ch585Radio, BB_BASE, LLE_BASE};
use wchble::rf::regs::{self, bb, bb_irq, lle};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

static SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static ADV: StaticCell<DmaBuf<64>> = StaticCell::new();
static RSP: StaticCell<DmaBuf<64>> = StaticCell::new();

// Single CPU writer, separate from DMA. No live probe reads during the run.
#[no_mangle]
static mut STATS: [u32; 32] = [0; 32];
#[no_mangle]
static mut LAST_REQ: DmaBuf<16> = DmaBuf::zeroed();

fn put(i: usize, v: u32) {
    unsafe {
        core::ptr::addr_of_mut!(STATS)
            .cast::<u32>()
            .add(i)
            .write_volatile(v)
    }
}
fn inc(i: usize) {
    unsafe {
        let p = core::ptr::addr_of_mut!(STATS).cast::<u32>().add(i);
        p.write_volatile(p.read_volatile().wrapping_add(1));
    }
}
fn reg(base: usize, offset: usize) -> u32 {
    unsafe { regs::read(base, offset) }
}
fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
struct Clock {
    ticks_per_us: u32,
    epoch: u32,
}
impl InstantUs for Clock {
    fn now_us(&self) -> u32 {
        hal::pac::SYSTICK
            .stk_cntl()
            .read()
            .cntl()
            .wrapping_sub(self.epoch)
            / self.ticks_per_us
    }
    fn delay_us(&self, us: u32) {
        let start = self.now_us();
        while self.now_us().wrapping_sub(start) < us {
            core::hint::spin_loop();
        }
    }
}

// Same event-close policy as ble_phy_disable()/wch_rf_shut() in the working
// V208 PHY, with an added bounded acknowledgement check on CH585. A zero
// WINDOW alone is not a stop. Buffers remain static and owned for this boot.
fn stop(radio: &mut Ch585Radio, clock: &Clock) -> bool {
    radio.shut();
    let start = clock.now_us();
    while reg(LLE_BASE, lle::CMD) & 3 != 0 {
        if clock.now_us().wrapping_sub(start) >= 100 {
            inc(14);
            put(2, 0xee);
            return false;
        }
    }
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
    inc(13);
    true
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    let clock = Clock {
        ticks_per_us: (hal::delay::measured_sysclk().0 / 1_000_000).max(1),
        epoch: hal::pac::SYSTICK.stk_cntl().read().cntl(),
    };
    put(0, 0x5032_3538);
    put(1, 1);
    put(2, 1);
    put(23, clock.ticks_per_us);
    let scratch = SCRATCH.init(DmaBuf::zeroed());
    let rx = RX.init(DmaBuf::zeroed());
    let adv_buf = ADV.init(DmaBuf::zeroed());
    let rsp_buf = RSP.init(DmaBuf::zeroed());
    let mut adv = AdvState {
        enabled: true,
        own_addr: [0x12, 0, 0, 0xee, 0xff, 0xc1],
        ..AdvState::default()
    };
    // Exact name is ONLY in SCAN_RSP, never the advertisement.
    adv.set_adv_data(3, &[2, 1, 6]);
    adv.set_scan_rsp(
        11,
        &[10, 9, b'w', b'c', b'h', b'5', b'8', b'5', b'-', b'p', b'2'],
    );
    let adv_len = adv.build_adv_scan_ind(&mut adv_buf.0).unwrap();
    let rsp_len = adv.build_scan_rsp(&mut rsp_buf.0).unwrap();
    let mut radio = new_radio_with_dma(&mut scratch.0).unwrap();
    if radio.init(&clock).is_err() {
        put(2, 0xe1);
        park();
    }
    radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    if !stop(&mut radio, &clock) {
        park();
    }
    put(2, 2);
    clock.delay_us(500_000);
    let run_start = clock.now_us();
    // Source starting point: current V208 basic-mode response uses an absolute
    // RX_DONE timestamp + 120 us deadline. This is NOT a measured CH585 IFS.
    const RESPONSE_DELAY_US: u32 = 120;
    put(24, RESPONSE_DELAY_US);
    while clock.now_us().wrapping_sub(run_start) < 8_000_000 {
        for ch in [37u8, 38, 39] {
            radio.set_channel(ch).unwrap();
            inc(3);
            put(2, 3);
            if radio
                .tx_basic(&clock, &adv_buf.0[..adv_len], 0, None)
                .is_err()
            {
                inc(5);
                if !stop(&mut radio, &clock) {
                    park();
                }
                continue;
            }
            inc(4);
            unsafe {
                regs::write(BB_BASE, bb::IRQSTAT, 0xf0);
            }
            if radio.rx_basic(&clock, &mut rx.0, 1_000).is_err() {
                inc(15);
                if !stop(&mut radio, &clock) {
                    park();
                }
                continue;
            }
            inc(6);
            put(2, 4);
            let armed = clock.now_us();
            let mut captured = false;
            let mut complete = false;
            let mut end = armed;
            let mut crc_ok = false;
            // V208 WFR: empty window ends; capture gets a full-PDU budget;
            // software watchdog closes partial frames instead of stalling LL.
            loop {
                let st = reg(LLE_BASE, lle::IRQSTAT);
                let now = clock.now_us();
                if st & 5 != 0 {
                    end = now;
                    crc_ok = reg(BB_BASE, bb::IRQSTAT) & bb_irq::CRC_ERR == 0;
                    complete = true;
                    break;
                }
                if !captured && reg(BB_BASE, bb::IRQSTAT) & bb_irq::CLKCAP != 0 {
                    radio.note_anchor_us(now);
                    radio.bb_isr();
                    captured = true;
                    inc(16);
                }
                if (!captured && now.wrapping_sub(armed) >= 600) || now.wrapping_sub(armed) >= 3_000
                {
                    break;
                }
            }
            put(20, reg(LLE_BASE, lle::IRQSTAT));
            put(21, reg(BB_BASE, bb::IRQSTAT));
            if !stop(&mut radio, &clock) {
                park();
            }
            if !complete {
                inc(7);
                if captured {
                    inc(17);
                }
                continue;
            }
            inc(8);
            if !crc_ok {
                inc(9);
                continue;
            }
            // DMA is stopped and acknowledged before CPU reads/reuses RX.
            let payload_len = rx.0[1] as usize;
            put(25, payload_len as u32);
            if payload_len != 12 || !adv.validate_scan_req(&rx.0[..14], crc_ok) {
                inc(10);
                continue;
            }
            inc(11);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    rx.0.as_ptr(),
                    core::ptr::addr_of_mut!(LAST_REQ).cast(),
                    14,
                );
            }
            put(2, 5);
            let deadline = end.wrapping_add(RESPONSE_DELAY_US);
            put(29, clock.now_us().wrapping_sub(end));
            match radio.tx_basic(&clock, &rsp_buf.0[..rsp_len], 0, Some(deadline)) {
                Ok(()) => {
                    inc(12);
                }
                Err(wchble::Error::Late) => {
                    inc(18);
                    put(28, clock.now_us().wrapping_sub(end));
                }
                Err(_) => {
                    inc(19);
                }
            }
            if !stop(&mut radio, &clock) {
                park();
            }
        }
        clock.delay_us(20_000);
    }
    if !stop(&mut radio, &clock) {
        park();
    }
    put(22, clock.now_us().wrapping_sub(run_start));
    put(26, reg(LLE_BASE, lle::CMD));
    put(27, reg(LLE_BASE, lle::MODE));
    put(2, 9);
    park();
}
