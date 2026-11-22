//! OTA carrier image: an app linked into slot A or B (see README.md).

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::ptr::addr_of_mut;
use hal::rcc;
use hal::time::Hertz;
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::ota::{self, Metadata};
use wchble::rf::family::ch585::Ch585DataFlash;
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::storage::DualCopyStore;
#[cfg(feature = "wipe-meta")]
use wchble::storage::FlashRegion;
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

include!(concat!(env!("OUT_DIR"), "/ota_config.rs"));

/// Advertising access address / CRC init (Core Vol 6 Part B).
const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;
/// Name per slot, so the runner's scan proves which one booted.
const NAME: &[u8] = if OTA_SLOT_INDEX == 0 {
    b"wch585-ota-a"
} else {
    b"wch585-ota-b"
};

/// Lets `ota_image.py` check the stamped sequence against the build.
#[used]
#[no_mangle]
static OTA_IMAGE_SEQUENCE: u32 = OTA_SEQUENCE;

/// Slot evidence for a probe read once the radio is stopped; layout v2.
#[no_mangle]
static mut OTA_SLOT: [u32; 16] = [0; 16];

const SLOT_MAGIC: u32 = 0x4f54_4102;

fn slot_put(slot: usize, value: u32) {
    // SAFETY: single-threaded example; only this task writes the array.
    unsafe {
        addr_of_mut!(OTA_SLOT).cast::<u32>().add(slot).write(value);
    }
}

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

/// Mark this slot good. Returns (ok, elapsed_us, prev record, load_ok).
fn mark_good(clock: &UsClock) -> (u32, u32, Option<Metadata>, u32) {
    let started = clock.now_us();
    let mut store = DualCopyStore::new(Ch585DataFlash, ota::METADATA_SLOTS);
    let mut payload = [0u8; ota::METADATA_LEN];
    let mut prev = None;
    let mut load_ok = 0;
    match store.load(&mut payload) {
        Ok(Some(len)) if len == ota::METADATA_LEN => {
            prev = Metadata::decode(payload[..ota::METADATA_LEN].try_into().unwrap());
            if prev.is_some() {
                load_ok = 1;
            }
        }
        Ok(None) => {}
        _ => {}
    }

    let next = ota::on_good(prev, OTA_SLOT_INDEX, OTA_SEQUENCE);
    // Already good: skip the write so reboots do not wear the page.
    #[cfg(not(any(feature = "no-good", feature = "ota-fault-mark-good")))]
    let ok = if prev == Some(next) {
        1
    } else {
        u32::from(store.save(&next.encode()).is_ok())
    };
    #[cfg(any(feature = "no-good", feature = "ota-fault-mark-good"))]
    let ok = u32::from(prev == Some(next));
    let elapsed = clock.now_us().wrapping_sub(started);
    #[cfg(feature = "ota-fault-mark-good")]
    {
        // Truncated write: the record must be ignored and the attempt kept.
        let _ = store.save_with_fault(&next.encode(), 8);
        let _ = (ok, elapsed, prev, load_ok);
        halt();
    }
    (ok, elapsed, prev, load_ok)
}

/// Erase both metadata pages, then park; the runner resets afterwards.
#[cfg(feature = "wipe-meta")]
fn wipe_metadata() -> ! {
    let mut region = Ch585DataFlash;
    let _ = region.erase(ota::METADATA_SLOTS[0]);
    let _ = region.erase(ota::METADATA_SLOTS[1]);
    halt();
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    #[cfg(feature = "wipe-meta")]
    wipe_metadata();
    let clock = UsClock::start();

    let rx_dma = RX_DMA.init(DmaBuf::zeroed());
    let mut radio = match new_radio_with_dma(&mut rx_dma.0[..]) {
        Ok(radio) => radio,
        Err(_) => halt(),
    };
    if radio.init(&clock).is_err() {
        halt();
    }

    // The radio is idle here, so the DataFlash writes cannot miss an event.
    let (mark_good_ok, mark_good_us, prev, load_ok) = mark_good(&clock);
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);

    let mut frame = [0u8; 32];
    let len = build_adv(&mut frame);
    // `_stext` is `ORIGIN(REGION_TEXT)`: the slot base + 32.
    extern "C" {
        static _stext: u8;
    }
    let text_base = core::ptr::addr_of!(_stext) as u32;
    slot_put(0, SLOT_MAGIC);
    slot_put(1, text_base);
    slot_put(2, OTA_SLOT_INDEX as u32);
    slot_put(3, OTA_SEQUENCE);
    slot_put(4, prev.map_or(0xFF, |record| record.candidate_slot as u32));
    slot_put(5, prev.map_or(0, |record| record.attempts_done as u32));
    slot_put(6, prev.map_or(0, |record| record.good_seq));
    slot_put(7, prev.map_or(0, |record| record.flags as u32));
    slot_put(8, mark_good_ok);
    slot_put(9, mark_good_us);
    slot_put(10, load_ok);
    slot_put(12, OTA_SLOT_BASE);

    loop {
        for channel in [37u8, 38, 39] {
            let _ = radio.set_channel(channel);
            // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or
            // stops the engine on error; `frame` lives across the call.
            let _ = unsafe { radio.tx_basic(&clock, &frame[..len], 0, None) };
            clock.delay_us(3_000);
        }
        unsafe {
            let count = addr_of_mut!(OTA_SLOT).cast::<u32>().add(11);
            count.write(count.read().wrapping_add(1));
        }
        clock.delay_us(20_000);
    }
}

/// Park a failed init; feed the watchdog in case one is enabled, so it cannot
/// reboot the core in a loop.
fn halt() -> ! {
    loop {
        hal::pac::SYS
            .iwdg_kr()
            .write_value(hal::pac::sys::regs::IwdgKr(0xAAAA));
    }
}
