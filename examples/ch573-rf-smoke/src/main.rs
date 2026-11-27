//! CH573 on-target RF smoke — DMA probe, DevInit dump, ADV TX, adv loop.
//!
//! Flash with the pinned CH573 probe only:
//! `probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2 --scan-region ram`.
//!
//! Success markers (defmt/RTT):
//! - `rf init ok`
//! - `dma-probe … stick=1` (DMA+0x10/14 stick; LLE 70/74/78/7c do not)
//! - `tx ch{37,38,39} ok`
//! - `adv loop` (macOS scan target local name `wch573`)

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use defmt::info;
use defmt_rtt as _;
use hal::rcc;
use qingke_rt::entry;
use wchble::rf::family::ch573::{
    install_ble_irq, Ch573Radio, BB_BASE, CAPS, DMA_BASE, LLE_BASE, RFEND_BASE,
};
use wchble::rf::regs;
use wchble::rf::txrx::RX_DMA_MIN;
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

// defmt 1.2 always references `_defmt_timestamp` when any log is live.
defmt::timestamp!("{=u32}", 0u32);

const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;

/// DMA-visible buffer placed by `build.rs`.
///
/// CH573 DMA registers keep only the low 14 bits of the address, so anything
/// below `0x2000_4000` aliases; `.dma_buffer` sits inside the reachable window.
#[repr(align(4))]
struct DmaCell<const N: usize>(core::cell::UnsafeCell<[u8; N]>);

// SAFETY: single-threaded firmware; buffers are only used by `main`.
unsafe impl<const N: usize> Sync for DmaCell<N> {}

impl<const N: usize> DmaCell<N> {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([0; N]))
    }
}

#[link_section = ".dma_buffer"]
static RX_DMA: DmaCell<RX_DMA_MIN> = DmaCell::new();
#[link_section = ".dma_buffer"]
static TX_FRAME: DmaCell<32> = DmaCell::new();

/// Free-running µs clock on the V3A SysTick down-counter.
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

fn mmio_w(base: usize, off: usize, val: u32) {
    unsafe { regs::write(base, off, val) }
}

fn dump_regs() {
    info!(
        "LLE 0c={=u32:x} 14={=u32:x} 1c={=u32:x} 2c={=u32:x} 3c={=u32:x} 44={=u32:x} 4c={=u32:x} 50={=u32:x} 58={=u32:x} 74={=u32:x} 78={=u32:x} 7c={=u32:x}",
        mmio(LLE_BASE, 0x0c),
        mmio(LLE_BASE, 0x14),
        mmio(LLE_BASE, 0x1c),
        mmio(LLE_BASE, 0x2c),
        mmio(LLE_BASE, 0x3c),
        mmio(LLE_BASE, 0x44),
        mmio(LLE_BASE, 0x4c),
        mmio(LLE_BASE, 0x50),
        mmio(LLE_BASE, 0x58),
        mmio(LLE_BASE, 0x74),
        mmio(LLE_BASE, 0x78),
        mmio(LLE_BASE, 0x7c),
    );
    info!(
        "DMA 00={=u32:x} 08={=u32:x} 0c={=u32:x} 10={=u32:x} 14={=u32:x} 18={=u32:x} 1c={=u32:x}",
        mmio(DMA_BASE, 0x00),
        mmio(DMA_BASE, 0x08),
        mmio(DMA_BASE, 0x0c),
        mmio(DMA_BASE, 0x10),
        mmio(DMA_BASE, 0x14),
        mmio(DMA_BASE, 0x18),
        mmio(DMA_BASE, 0x1c),
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

/// DMA bufptrs are 16-bit offsets from `0x2000_0000` (word-aligned).
fn dma_off(ptr: u32) -> u32 {
    ptr & 0xfffc
}

/// Write distinctive patterns; return true when DMA+0x10/14 accept offsets
/// and LLE 0x70/74/78/7c do not stick.
fn probe_bufptr(dma_ptr: u32) -> bool {
    const LLE_PAT: [(usize, u32); 4] = [
        (0x70, 0xa1a1_a1a1),
        (0x74, 0xb2b2_b2b2),
        (0x78, 0xc3c3_c3c3),
        (0x7c, 0xd4d4_d4d4),
    ];
    // Offsets inside the high SRAM window; bit15 clear, word-aligned.
    const DMA_PAT: [(usize, u32); 4] = [
        (0x10, 0x3a50),
        (0x14, 0x3b54),
        (0x18, 0x3c58),
        (0x1c, 0x3d5c),
    ];

    for &(off, pat) in &LLE_PAT {
        mmio_w(LLE_BASE, off, pat);
    }
    for &(off, pat) in &DMA_PAT {
        mmio_w(DMA_BASE, off, pat);
    }

    let mut lle_sticky = 0u32;
    for &(off, pat) in &LLE_PAT {
        let v = mmio(LLE_BASE, off);
        if v == pat {
            lle_sticky |= 1;
        }
        info!("probe LLE+{=u32:x} -> {=u32:x}", off as u32, v);
    }
    let mut dma_sticky = 0u32;
    for &(off, pat) in &DMA_PAT {
        let v = mmio(DMA_BASE, off) & 0xffff;
        if v == pat {
            dma_sticky |= 1;
        }
        info!("probe DMA+{=u32:x} -> {=u32:x}", off as u32, v);
    }

    let want = dma_off(dma_ptr);
    mmio_w(DMA_BASE, 0x10, want);
    mmio_w(DMA_BASE, 0x14, want);
    let t = mmio(DMA_BASE, 0x10) & 0xffff;
    let r = mmio(DMA_BASE, 0x14) & 0xffff;
    info!(
        "dma-probe ptr={=u32:x} off={=u32:x} tx={=u32:x} rx={=u32:x} dma_stick={=u32} lle_stick={=u32}",
        dma_ptr,
        want,
        t,
        r,
        dma_sticky,
        lle_sticky
    );
    dma_sticky != 0 && t == want && r == want && lle_sticky == 0
}

/// ADV_NONCONN_IND + AdvA + flags + complete local name "wch573".
fn build_adv(out: &mut [u8; 32]) -> usize {
    let name = b"wch573";
    let adv_a = [0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x73];
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

    // ADV_NONCONN_IND (0x02) | TxAdd=random (0x40)
    out[0] = 0x42;
    out[1] = payload_len as u8;
    out[2..2 + payload_len].copy_from_slice(&buf[..payload_len]);
    2 + payload_len
}

fn tx_burst(radio: &mut Ch573Radio, clock: &UsClock, frame: &[u8]) {
    for &ch in &[37u8, 38, 39] {
        if let Err(e) = radio.set_channel(ch) {
            info!("set_channel {=u8} err {:?}", ch, e);
            continue;
        }
        for i in 0u32..2 {
            // SAFETY: tx_basic completes or stops the engine before return.
            match unsafe { radio.tx_basic(clock, frame, 0, None) } {
                Ok(()) => {
                    info!("tx ch{=u8} ok #{=u32}", ch, i);
                    if i == 0 && ch == 37 {
                        info!(
                            "post-tx BB00={=u32:x} MODE={=u32:x} COUNT={=u32:x} GUARD={=u32:x} CMD={=u32:x} IRQ={=u32:x} FE={=u32:x} DMA10={=u32:x} BB18={=u32:x}",
                            mmio(BB_BASE, 0x00),
                            mmio(LLE_BASE, 0x50),
                            mmio(LLE_BASE, 0x60),
                            mmio(LLE_BASE, 0x0c),
                            mmio(LLE_BASE, 0x00),
                            mmio(LLE_BASE, 0x08),
                            mmio(RFEND_BASE, 0x08),
                            mmio(DMA_BASE, 0x10),
                            mmio(BB_BASE, 0x18),
                        );
                    }
                }
                Err(e) => {
                    info!("tx ch{=u8} err {:?} #{=u32}", ch, e, i);
                    dump_regs();
                }
            }
            clock.delay_us(10_000);
        }
    }
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::PLL_60MHZ.into());
    info!("boot");
    info!("wchble ch573 rf-smoke sysclk={}", rcc::clocks().sysclk.0);

    let clock = UsClock::start();
    // SAFETY: single-threaded; these buffers are used only here.
    let rx_dma: &mut [u8; RX_DMA_MIN] = unsafe { &mut *RX_DMA.0.get() };
    let tx_frame: &mut [u8; 32] = unsafe { &mut *TX_FRAME.0.get() };
    let dma_ptr = rx_dma.as_ptr() as usize;
    info!("dma {=usize:x} len={}", dma_ptr, rx_dma.len());
    if !CAPS.contains_dma(dma_ptr, rx_dma.len()) {
        info!(
            "dma OUT OF WINDOW expect {=usize:x}..{=usize:x}",
            CAPS.sram_start, CAPS.sram_end
        );
        loop {}
    }

    let mut radio: Ch573Radio = match new_radio_with_dma(&mut rx_dma[..]) {
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

    // SAFETY: PFIC VTF writes only; the entry lives in `.highcode`.
    unsafe { install_ble_irq() };
    info!("ble irq installed");

    dump_regs();

    let stick = probe_bufptr(dma_ptr as u32);
    info!("dma-probe stick={=u8}", stick as u8);
    if !stick {
        info!("dma-probe FAIL — stop before TX");
        dump_regs();
        loop {
            clock.delay_us(1_000_000);
        }
    }

    // Re-seed all four DMA pointer offsets after the probe stomped them.
    let off = (dma_ptr as u32) & 0xfffc;
    unsafe {
        regs::write(DMA_BASE, CAPS.rx_bufptr_off, off);
        regs::write(DMA_BASE, CAPS.tx_bufptr_off, off);
        regs::write(DMA_BASE, 0x18, off);
        regs::write(DMA_BASE, 0x1c, off);
    }

    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);

    let n = build_adv(tx_frame);
    info!("adv len {=usize}", n);
    tx_burst(&mut radio, &clock, &tx_frame[..n]);

    info!("adv loop");
    let mut round = 0u32;
    loop {
        radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
        for &ch in &[37u8, 38, 39] {
            if radio.set_channel(ch).is_ok() {
                if let Err(e) = unsafe { radio.tx_basic(&clock, &tx_frame[..n], 0, None) } {
                    info!("adv tx ch{=u8} err {:?}", ch, e);
                }
            }
            clock.delay_us(2_000);
        }
        if round % 50 == 0 {
            info!("adv loop round={=u32}", round);
        }
        round = round.wrapping_add(1);
        clock.delay_us(100_000);
    }
}
