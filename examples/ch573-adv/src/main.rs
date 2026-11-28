//! CH573 legacy broadcaster — ADV_IND with interval, advDelay and channel
//! rotation.
//!
//! Connection handling is intentionally absent: CONNECT_IND is not answered,
//! so the peer times out while advertising continues.

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use defmt::info;
use defmt_rtt as _;
use hal::rcc;
use qingke_rt::entry;
use wchble::ll::adv::AdvState;
use wchble::rf::family::ch573::{Ch573Radio, TxPower, CAPS};
use wchble::rf::txrx::RX_DMA_MIN;
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

// defmt 1.2 always references `_defmt_timestamp` when any log is live.
defmt::timestamp!("{=u32}", 0u32);

const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;
const OWN_ADDR: [u8; 6] = [0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x73];
const ADV_INTERVAL_SLOTS: u16 = 0x20; // 20 ms
const LOG_EVERY: u32 = 50;

/// TX power from `CH573_ADV_TX_POWER` at build time (default 0 dBm).
fn tx_power() -> (TxPower, &'static str) {
    match option_env!("CH573_ADV_TX_POWER") {
        Some("-20") => (TxPower::Minus20Dbm, "-20"),
        Some("-14") => (TxPower::Minus14Dbm, "-14"),
        Some("-8") => (TxPower::Minus8Dbm, "-8"),
        Some("-4") => (TxPower::Minus4Dbm, "-4"),
        Some("1") => (TxPower::Plus1Dbm, "+1"),
        Some("2") => (TxPower::Plus2Dbm, "+2"),
        Some("3") => (TxPower::Plus3Dbm, "+3"),
        Some("4") => (TxPower::Plus4Dbm, "+4"),
        Some("5") => (TxPower::Plus5Dbm, "+5"),
        _ => (TxPower::ZeroDbm, "0"),
    }
}

/// DMA-visible buffer placed by `build.rs` inside the CH573 14-bit window.
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

/// xorshift32 for advDelay; the spec only asks for a pseudo-random 0–10 ms.
struct Rng(u32);

impl Rng {
    fn new(seed: u32) -> Self {
        Self(if seed == 0 { 0x9e37_79b9 } else { seed })
    }

    fn next_u16(&mut self) -> u16 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        (x >> 16) as u16
    }
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::PLL_60MHZ.into());
    let clock = UsClock::start();
    info!("wchble ch573 adv sysclk={}", rcc::clocks().sysclk.0);

    // SAFETY: single-threaded; these buffers are used only here.
    let rx_dma: &mut [u8; RX_DMA_MIN] = unsafe { &mut *RX_DMA.0.get() };
    if !CAPS.contains_dma(rx_dma.as_ptr() as usize, rx_dma.len()) {
        info!("dma OUT OF WINDOW");
        loop {}
    }
    let mut radio: Ch573Radio = match new_radio_with_dma(&mut rx_dma[..]) {
        Ok(r) => r,
        Err(e) => {
            info!("radio new err {:?}", e);
            loop {}
        }
    };
    // Select the level before init: the PA tune is bound to it.
    let (power, power_label) = tx_power();
    radio.set_tx_power(power);
    match radio.init(&clock) {
        Ok(()) => info!("rf init ok"),
        Err(e) => {
            info!("rf init err {:?}", e);
            loop {}
        }
    }
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    info!("tx_power={=str} dBm code={=u8}", power_label, power.code());

    let mut adv = AdvState::default();
    adv.enabled = true;
    adv.own_addr = OWN_ADDR;
    adv.random_addr = true;
    adv.interval_slots = ADV_INTERVAL_SLOTS;
    adv.channel_map = 0x07;
    adv.chsel = false;
    let ad = [
        0x02, 0x01, 0x06, // Flags: LE General Discoverable
        0x07, 0x09, b'w', b'c', b'h', b'5', b'7', b'3',
    ];
    if !adv.set_adv_data(ad.len() as u8, &ad) {
        info!("adv data too long");
        loop {}
    }

    // SAFETY: single-threaded; the TX buffer is reused each event.
    let frame = unsafe { &mut *TX_FRAME.0.get() };
    let Some(n) = adv.build_adv_ind(&mut frame[..]) else {
        info!("ADV_IND build failed");
        loop {}
    };
    info!(
        "ADV_IND len={=usize} interval_us={=u32} channels={=usize}",
        n,
        adv.interval_us(),
        adv.channels().count()
    );
    info!("connection not implemented: CONNECT_IND is not answered");

    let mut rng = Rng::new(clock.now_us());
    let mut round = 0u32;
    loop {
        let t0 = clock.now_us();
        for ch in adv.channels() {
            if radio.set_channel(ch).is_err() {
                continue;
            }
            if let Err(e) = unsafe { radio.tx_basic(&clock, &frame[..n], 0, None) } {
                info!("tx ch{=u8} err {:?}", ch, e);
            }
        }
        let elapsed = clock.now_us().wrapping_sub(t0);
        let wait = adv.event_interval_us(rng.next_u16());
        let delay = wait.saturating_sub(elapsed);
        if delay != 0 {
            clock.delay_us(delay);
        }
        if round % LOG_EVERY == 0 {
            info!(
                "adv round={=u32} event_us={=u32} wait_us={=u32} delay_us={=u32}",
                round, elapsed, wait, delay
            );
        }
        round = round.wrapping_add(1);
    }
}
