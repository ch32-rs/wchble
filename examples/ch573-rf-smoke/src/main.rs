//! CH573 on-target DevInit readback — init absolute stores, dump registers.
//!
//! TX/RX are not wired yet. Flash with the pinned CH573 probe only:
//! `probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2`.
//!
//! Success markers (defmt/RTT):
//! - `rf init ok`
//! - `dma …` inside `@0x20003800..0x20008000`
//! - `LLE …` / `RFEND …` / `BB …` DevInit markers

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use defmt::info;
use defmt_rtt as _;
use hal::rcc;
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::rf::family::ch573::{Ch573Radio, BB_BASE, CAPS, LLE_BASE, RFEND_BASE};
use wchble::rf::regs;
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

// defmt 1.2 always references `_defmt_timestamp` when any log is live.
defmt::timestamp!("{=u32}", 0u32);

static RX_DMA: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();

/// Free-running µs clock on the V3A SysTick down-counter.
struct UsClock {
    ticks_per_us: u32,
}

impl UsClock {
    fn start() -> Self {
        // Prefer the configured clock; measured_sysclk can hang if SysTick is not free.
        let hz = rcc::clocks().sysclk.0.max(1_000_000);
        Self {
            ticks_per_us: (hz / 1_000_000).max(1),
        }
    }

    fn ticks(&self) -> u32 {
        // CNTL counts down; invert so `now_us` increases.
        u32::MAX - hal::pac::SYSTICK.cntl().read().cntl()
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

fn dump_regs() {
    info!(
        "LLE 0c={=u32:x} 14={=u32:x} 1c={=u32:x} 2c={=u32:x} 3c={=u32:x} 44={=u32:x} 4c={=u32:x} 58={=u32:x} 74={=u32:x} 78={=u32:x} 7c={=u32:x}",
        mmio(LLE_BASE, 0x0c),
        mmio(LLE_BASE, 0x14),
        mmio(LLE_BASE, 0x1c),
        mmio(LLE_BASE, 0x2c),
        mmio(LLE_BASE, 0x3c),
        mmio(LLE_BASE, 0x44),
        mmio(LLE_BASE, 0x4c),
        mmio(LLE_BASE, 0x58),
        mmio(LLE_BASE, 0x74),
        mmio(LLE_BASE, 0x78),
        mmio(LLE_BASE, 0x7c),
    );
    info!(
        "RFEND 28={=u32:x} 0c={=u32:x} 90={=u32:x}",
        mmio(RFEND_BASE, 0x28),
        mmio(RFEND_BASE, 0x0c),
        mmio(RFEND_BASE, 0x90),
    );
    info!(
        "BB 00={=u32:x} 34={=u32:x}",
        mmio(BB_BASE, 0x00),
        mmio(BB_BASE, 0x34),
    );
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::PLL_60MHZ.into());
    info!("boot");
    info!("wchble ch573 rf-smoke sysclk={}", rcc::clocks().sysclk.0);

    let clock = UsClock::start();
    let rx_dma = RX_DMA.init(DmaBuf::zeroed());
    let dma_ptr = rx_dma.0.as_ptr() as usize;
    info!("dma {=usize:x} len={}", dma_ptr, rx_dma.0.len());
    if !CAPS.contains_dma(dma_ptr, rx_dma.0.len()) {
        info!(
            "dma OUT OF WINDOW expect {=usize:x}..{=usize:x}",
            CAPS.sram_start,
            CAPS.sram_end
        );
        loop {}
    }

    let mut radio: Ch573Radio = match new_radio_with_dma(&mut rx_dma.0[..]) {
        Ok(r) => r,
        Err(e) => {
            info!("radio new err {:?}", e);
            loop {}
        }
    };

    match radio.init(&clock) {
        Ok(()) => info!("rf init ok"),
        Err(e) => {
            info!("rf init err {:?}", e);
            dump_regs();
            loop {}
        }
    }

    dump_regs();
    info!("park (tx/rx still Unsupported)");
    loop {
        clock.delay_us(1_000_000);
    }
}
