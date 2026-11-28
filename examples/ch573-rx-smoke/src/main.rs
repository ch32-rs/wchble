//! CH573 RX smoke — arm a legacy-ADV RX window and dump what the DMA wrote.
//!
//! Flash with the pinned CH573 probe only:
//! `probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2 --scan-region ram`
//!
//! Success markers (defmt/RTT):
//! - `rf init ok`
//! - `state=2` lines with a plausible `len`/`rssi`
//! - `buf …` bytes matching an ADV seen by the nRF sniffer / a known
//!   transmitter (`examples/ch585-rf-smoke` broadcasts the name `wch585`).

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use defmt::info;
use defmt_rtt as _;
use hal::rcc;
use qingke_rt::entry;
use wchble::rf::family::ch573::{
    install_ble_irq, irq_entries, rx_done_ticks, rx_isr_take, tx_kick_count, tx_kick_ticks,
    Ch573Radio, RxPoll, BB_BASE, CAPS, DMA_BASE, LLE_BASE,
};
use wchble::rf::regs;
use wchble::rf::txrx::RX_DMA_MIN;
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

defmt::timestamp!("{=u32}", 0u32);

const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;

/// Serve windows from the real PFIC interrupt; `false` keeps the `rx_poll` kick.
const USE_ISR: bool = true;

/// PFIC fast-interrupt slots 2 (LLE, IRQ 21) and 3 (BB, IRQ 20).
const PFIC_BASE: usize = 0xE000_E000;

/// After a received frame, transmit one ADV and report the RX-done → TX-kick
/// turnaround (SysTick counts / `ticks_per_us`).
const MEASURE_RX_TX: bool = true;

/// Minimal ADV_NONCONN_IND carrying the local name `wch573`.
fn build_adv(out: &mut [u8]) -> usize {
    let name = b"wch573";
    let adv_a = [0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x73];
    let mut payload_len = 0usize;
    out[2..8].copy_from_slice(&adv_a);
    payload_len += 6;
    out[2 + payload_len] = 2;
    out[2 + payload_len + 1] = 0x01;
    out[2 + payload_len + 2] = 0x06;
    payload_len += 3;
    out[2 + payload_len] = (1 + name.len()) as u8;
    out[2 + payload_len + 1] = 0x09;
    out[2 + payload_len + 2..2 + payload_len + 2 + name.len()].copy_from_slice(name);
    payload_len += 2 + name.len();
    out[0] = 0x42; // ADV_NONCONN_IND | TxAdd=random
    out[1] = payload_len as u8;
    2 + payload_len
}

/// DMA-visible RX buffer placed by `build.rs`.
#[repr(align(4))]
struct DmaCell<const N: usize>(core::cell::UnsafeCell<[u8; N]>);

// SAFETY: single-threaded firmware; the buffer is only used by `main`.
unsafe impl<const N: usize> Sync for DmaCell<N> {}

impl<const N: usize> DmaCell<N> {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([0; N]))
    }
}

/// Scratch owned by the driver (DMA init seeds its pointers from it).
#[link_section = ".dma_buffer"]
static RX_SCRATCH: DmaCell<RX_DMA_MIN> = DmaCell::new();
/// Buffer handed to `rx_basic` for each window.
#[link_section = ".dma_buffer"]
static RX_BUF: DmaCell<RX_DMA_MIN> = DmaCell::new();

struct UsClock {
    ticks_per_us: u32,
}

impl UsClock {
    fn start() -> Self {
        let hz = rcc::clocks().sysclk.0.max(1_000_000);
        Self {
            ticks_per_us: (hz / 1_000_000).max(1),
        }
    }

    fn ticks(&self) -> u32 {
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

/// `LLE+0x08` is plain R/W: clear flags by writing the bits back as zero.
fn clear_lle_irq(bits: u32) {
    unsafe {
        let v = mmio(LLE_BASE, 0x08);
        regs::write(LLE_BASE, 0x08, v & !bits);
    }
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::PLL_60MHZ.into());
    info!("boot");
    info!("wchble ch573 rx-smoke sysclk={}", rcc::clocks().sysclk.0);

    let clock = UsClock::start();
    // SAFETY: single-threaded; the buffers are used only here.
    let scratch: &mut [u8] = unsafe { &mut *RX_SCRATCH.0.get() };
    let rx: &mut [u8; RX_DMA_MIN] = unsafe { &mut *RX_BUF.0.get() };
    let dma_ptr = rx.as_ptr() as usize;
    info!("dma {=usize:x}", dma_ptr);
    if !CAPS.contains_dma(dma_ptr, rx.len())
        || !CAPS.contains_dma(scratch.as_ptr() as usize, scratch.len())
    {
        info!(
            "dma OUT OF WINDOW expect {=usize:x}..{=usize:x}",
            CAPS.sram_start, CAPS.sram_end
        );
        loop {}
    }

    let mut radio: Ch573Radio = match new_radio_with_dma(scratch) {
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
            loop {}
        }
    }

    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);

    info!("rx mode={}", if USE_ISR { "isr" } else { "poll" });
    if USE_ISR {
        // SAFETY: PFIC writes only; runs with interrupts masked.
        unsafe { install_ble_irq() };
        info!(
            "vtf fibaddr={=u32:x} slot2={=u32:x} slot3={=u32:x}",
            mmio(PFIC_BASE, 0x44),
            mmio(PFIC_BASE, 0x68),
            mmio(PFIC_BASE, 0x6c)
        );
    }

    let mut round = 0u32;
    loop {
        for &ch in &[37u8, 38, 39] {
            if radio.set_channel(ch).is_err() {
                continue;
            }
            for b in rx.iter_mut() {
                *b = 0xAA;
            }
            clear_lle_irq(0xffff);

            // SAFETY: `rx` is DMA-visible and stops the engine before re-use.
            if let Err(e) = unsafe { radio.rx_basic(&clock, &mut rx[..], 20_000) } {
                info!("rx arm ch{=u8} err {:?}", ch, e);
                continue;
            }
            if round == 0 && ch == 37 {
                info!(
                    "armed lle08={=u32:x} bb38={=u32:x}",
                    mmio(LLE_BASE, 0x08),
                    mmio(BB_BASE, 0x38)
                );
            }

            // `rx_basic` unmasks the lines when `install_ble_irq` has run;
            // the ISR masks them again when the window ends.
            let isr_before = irq_entries();

            // Wait for the window: the ISR (or `rx_poll` in poll mode) serves
            // the BB reload the engine needs and reports completion.
            let start = clock.now_us();
            let (poll, waited) = loop {
                let p = if USE_ISR {
                    rx_isr_take().unwrap_or(RxPoll::Armed)
                } else {
                    unsafe { radio.rx_poll() }
                };
                if p != RxPoll::Armed {
                    break (p, false);
                }
                if clock.now_us().wrapping_sub(start) > 15_000 {
                    break (RxPoll::Armed, true);
                }
            };

            let count = mmio(LLE_BASE, 0x60);
            let dma18 = mmio(DMA_BASE, 0x18);
            let bb30 = mmio(BB_BASE, 0x30);
            let bb38 = mmio(BB_BASE, 0x38);
            let lle08 = mmio(LLE_BASE, 0x08);
            let (state, len, rssi, crc_ok) = match poll {
                RxPoll::Armed => (0u8, 0u8, 0i8, false),
                RxPoll::Timeout => (1, 0, 0, false),
                RxPoll::Done { len, rssi, crc_ok } => (2, len, rssi, crc_ok),
            };
            // A legacy advertising PDU is at most 37 bytes; anything longer is
            // a corrupted length byte even if the CRC flag says otherwise.
            let valid = state == 2 && crc_ok && len <= 37;
            let isr_delta = irq_entries().wrapping_sub(isr_before);
            let mut dump = [0u8; 48];
            dump.copy_from_slice(&rx[..48]);
            let show_buf = poll != RxPoll::Timeout || dump[0] != 0xAA || dump[1] != 0xAA;

            // RX done → TX kick, in SysTick counts (the V3A counter runs
            // down). Includes the driver's engine stop and arm sequence; the
            // TX itself runs to completion inside `tx_basic`. `turn=0xffff`
            // means the kick never ran, so the delta is stale.
            let mut turn_us = 0u32;
            if MEASURE_RX_TX && valid {
                let t_rx = rx_done_ticks();
                let kicks = tx_kick_count();
                let n = build_adv(&mut rx[..]);
                if radio.set_channel(37).is_ok() {
                    match unsafe { radio.tx_basic(&clock, &rx[..n], 0, None) } {
                        Ok(()) if tx_kick_count() != kicks => {
                            turn_us = t_rx.wrapping_sub(tx_kick_ticks())
                                / clock.ticks_per_us.max(1);
                        }
                        Ok(()) => turn_us = 0xffff,
                        Err(e) => info!("tx after rx err {:?}", e),
                    }
                }
            }

            info!(
                "ch{=u8} state={=u8} len={=u8} rssi={=i8} crc={=bool} valid={=bool} timeout={=bool} trssi={=i8} tcrc={=bool} cnt={=u32:x} isr={=u32} kick={=u32} turn={=u32} dma18={=u32:x} bb30={=u32:x} bb38={=u32:x} lle08={=u32:x}",
                ch, state, len, rssi, crc_ok, valid, waited, radio.rssi(), radio.crc_ok(), count, isr_delta, tx_kick_count(),
                turn_us, dma18, bb30, bb38, lle08
            );
            if show_buf {
                info!("buf {:?}", &dump[..]);
            }
            radio.shut();
            clock.delay_us(5_000);
        }
        round = round.wrapping_add(1);
        if round % 5 == 0 {
            info!("rx loop round={=u32}", round);
        }
    }
}
