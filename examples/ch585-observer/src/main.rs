//! O1: finite passive Observer. Receives legacy advertising PDUs on
//! channels 37/38/39, records counters and bounded raw samples, and never
//! transmits. See README.md for the experiment and its non-claims.
#![no_std]
#![no_main]

use core::cell::Cell;

use ch5xx_hal as hal;
use hal::{rcc, time::Hertz};
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::ll::scan::{self, PduType, MAX_LEGACY_ADV_PAYLOAD};
use wchble::rf::family::ch585::{Ch585Radio, BB_BASE, LLE_BASE};
use wchble::rf::regs::{self, bb, bb_irq, lle};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use {panic_halt as _, portable_atomic as _};

const RUN_SECONDS: u32 = 30;
const CHANNELS: [u8; 3] = [37, 38, 39];
// 15 ms keeps the LLE WINDOW count below bit 15; the field width above
// 0x7FFF is not established for CH585.
const WINDOW_HALF_US: u32 = 30_000;
const WINDOW_US: u32 = 15_000;
const NO_CAPTURE_MARGIN_US: u32 = 1_000;
const POST_CAPTURE_US: u32 = 2_500;
const RX_RAW: usize = 40;
const SAMPLE_ROWS: usize = 32;
const MATCH_ROWS: usize = 4;
const ROW_WORDS: usize = 13;

// Test-only controlled source: `wchble-obs-src` plus manufacturer data
// 0xFFFF + "O1" + version 1. Never part of the default image.
#[cfg(feature = "target-src")]
const TARGET_NAME: &[u8] = b"wch585-obs-src";
#[cfg(feature = "target-src")]
const TARGET_MFR: &[u8] = &[0xff, 0xff, 0x4f, 0x31, 0x00, 0x01];

static SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();

#[no_mangle]
#[used]
pub static RUN_SECONDS_SYM: u32 = RUN_SECONDS;
#[no_mangle]
#[used]
pub static TARGET_SRC: u32 = cfg!(feature = "target-src") as u32;
#[no_mangle]
static mut STATS: [u32; 48] = [0; 48];
#[no_mangle]
static mut SAMPLE: [u32; SAMPLE_ROWS * ROW_WORDS] = [0; SAMPLE_ROWS * ROW_WORDS];
#[cfg(feature = "target-src")]
#[no_mangle]
static mut MATCH: [u32; MATCH_ROWS * ROW_WORDS] = [0; MATCH_ROWS * ROW_WORDS];

// STATS layout (README and tools/run.py must agree).
const STAGE: usize = 2;
const RUN_US: usize = 3;
const WINDOW_HALF_US_STAT: usize = 4;
const RUN_SECONDS_STAT: usize = 5;
const WINDOWS: usize = 6;
const ARM_ERRORS: usize = 7;
const COMPLETIONS: usize = 8;
const TIMEOUTS: usize = 9;
const CAPTURES: usize = 10;
const CAPTURED_NO_COMPLETE: usize = 11;
const CRC_OK: usize = 12;
const CRC_ERR: usize = 13;
const BAD_LENGTH: usize = 14;
const STOPS_OK: usize = 15;
const STOP_FAILURES: usize = 16;
const CH_COMPLETIONS: usize = 17;
const CH_CRC_OK: usize = 20;
const PDU_ADV_IND: usize = 23;
const PDU_ADV_DIRECT_IND: usize = 24;
const PDU_ADV_NONCONN_IND: usize = 25;
const PDU_SCAN_RSP: usize = 26;
const PDU_ADV_SCAN_IND: usize = 27;
const PDU_ADV_EXT_IND: usize = 28;
const PDU_SCAN_REQ_SEEN: usize = 29;
const PDU_CONNECT_IND_SEEN: usize = 30;
const PDU_OTHER: usize = 31;
const NAMED_PDUS: usize = 32;
const MATCH_COUNT: usize = 33;
const SAMPLE_COUNT: usize = 34;
const SAMPLE_OVERFLOW: usize = 35;
const MATCH_RING_COUNT: usize = 36;
const LAST_CHANNEL: usize = 37;
const LAST_LEN: usize = 38;
const LAST_RSSI_RAW: usize = 39;
const LAST_LLE_IRQSTAT: usize = 40;
const LAST_BB_IRQSTAT: usize = 41;
const FINAL_CMD: usize = 42;
const FINAL_MODE: usize = 43;
const CLOCK_HZ: usize = 44;
const TARGET_SRC_STAT: usize = 45;
const RESERVED: usize = 46;

const STAGE_INIT: u32 = 1;
const STAGE_RUNNING: u32 = 2;
const STAGE_DONE: u32 = 3;
const STAGE_INIT_FAIL: u32 = 0xe1;
const STAGE_STOP_FAIL: u32 = 0xee;

fn put(i: usize, v: u32) {
    unsafe {
        core::ptr::addr_of_mut!(STATS)
            .cast::<u32>()
            .add(i)
            .write_volatile(v)
    }
}
fn get(i: usize) -> u32 {
    unsafe {
        core::ptr::addr_of!(STATS)
            .cast::<u32>()
            .add(i)
            .read_volatile()
    }
}
fn inc(i: usize) {
    put(i, get(i).wrapping_add(1));
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
    ticks: Cell<ExtendingTicks>,
    rate: TickRate,
}
impl InstantUs for Clock {
    fn now_us(&self) -> u32 {
        // CH585 SysTick is only 32 bits. One owner samples continuously,
        // including every deadline wait below.
        let mut ticks = self.ticks.get();
        let elapsed = ticks.sample(hal::pac::SYSTICK.cntl().read().cntl());
        self.ticks.set(ticks);
        self.rate.micros(elapsed)
    }
    fn delay_us(&self, us: u32) {
        let start = self.now_us();
        while self.now_us().wrapping_sub(start) < us {
            core::hint::spin_loop();
        }
    }
}

/// Same bounded stop policy as P2/P3: shut, acknowledge CMD idle, fence.
/// DMA must not be read or reused unless this returns.
fn stop(radio: &mut Ch585Radio, clock: &Clock) -> bool {
    radio.shut();
    let start = clock.now_us();
    while reg(LLE_BASE, lle::CMD) & 3 != 0 {
        if clock.now_us().wrapping_sub(start) >= 100 {
            inc(STOP_FAILURES);
            put(STAGE, STAGE_STOP_FAIL);
            return false;
        }
    }
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
    inc(STOPS_OK);
    true
}

/// One arm/capture/stop cycle. The DMA buffer is untouched until stop.
struct Window {
    completed: bool,
    captured: bool,
    crc_ok: bool,
    rssi: u8,
    end_us: u32,
    lle_status: u32,
    bb_status: u32,
}

fn read_window(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    channel: u8,
) -> Option<Window> {
    // CRC and CLKCAP latches belong to the previous window.
    unsafe {
        regs::write(BB_BASE, bb::IRQSTAT, 0xf0);
    }
    if radio.set_channel(channel).is_err() {
        inc(ARM_ERRORS);
        return None;
    }
    if radio
        .rx_basic(clock, &mut rx.0, WINDOW_HALF_US)
        .is_err()
    {
        inc(ARM_ERRORS);
        if !stop(radio, clock) {
            park();
        }
        return None;
    }
    inc(WINDOWS);
    let armed = clock.now_us();
    let mut captured = false;
    let mut capture_at = 0;
    let mut completed = false;
    let mut end_us = armed;
    loop {
        if reg(LLE_BASE, lle::IRQSTAT) & 5 != 0 {
            completed = true;
            end_us = clock.now_us();
            break;
        }
        let now = clock.now_us();
        if !captured && reg(BB_BASE, bb::IRQSTAT) & bb_irq::CLKCAP != 0 {
            // Extend the window to a full-PDU budget for the packet that just
            // started; without this, a late capture would be cut short.
            radio.note_anchor_us(now);
            radio.bb_isr();
            captured = true;
            capture_at = now;
            inc(CAPTURES);
        }
        let expired = if captured {
            now.wrapping_sub(capture_at) >= POST_CAPTURE_US
        } else {
            now.wrapping_sub(armed) >= WINDOW_US + NO_CAPTURE_MARGIN_US
        };
        if expired {
            break;
        }
    }
    let lle_status = reg(LLE_BASE, lle::IRQSTAT);
    let bb_status = reg(BB_BASE, bb::IRQSTAT);
    let crc_ok = bb_status & bb_irq::CRC_ERR == 0;
    let rssi = radio.rssi() as u8;
    if !stop(radio, clock) {
        park();
    }
    Some(Window {
        completed,
        captured,
        crc_ok,
        rssi,
        end_us,
        lle_status,
        bb_status,
    })
}

fn meta_word(
    channel: u8,
    len: u8,
    crc_ok: bool,
    pdu_type: u8,
    mfr_present: bool,
    name_present: bool,
) -> u32 {
    u32::from(channel)
        | (u32::from(len) << 8)
        | (u32::from(crc_ok) << 16)
        | (u32::from(pdu_type) << 17)
        | (u32::from(mfr_present) << 21)
        | (u32::from(name_present) << 22)
}

unsafe fn write_row(
    rows: *mut u32,
    slot: usize,
    ticks: u32,
    meta: u32,
    rssi: u8,
    raw: &[u8],
) {
    let base = rows.add(slot * ROW_WORDS);
    let mut bytes = [0u8; 40];
    let n = raw.len().min(bytes.len());
    bytes[..n].copy_from_slice(&raw[..n]);
    base.add(0).write_volatile(ticks);
    base.add(2).write_volatile(u32::from(rssi));
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        base.add(3 + i).write_volatile(word);
    }
    // Publish the row only after everything it describes is in place.
    base.add(1).write_volatile(meta | (1 << 24));
}

fn record_sample(ticks: u32, meta: u32, rssi: u8, raw: &[u8]) {
    let count = get(SAMPLE_COUNT);
    let slot = count as usize % SAMPLE_ROWS;
    unsafe {
        write_row(
            core::ptr::addr_of_mut!(SAMPLE).cast::<u32>(),
            slot,
            ticks,
            meta,
            rssi,
            raw,
        );
    }
    put(SAMPLE_COUNT, count.wrapping_add(1));
    put(
        SAMPLE_OVERFLOW,
        count
            .saturating_add(1)
            .saturating_sub(SAMPLE_ROWS as u32),
    );
}

#[cfg(feature = "target-src")]
fn record_match(ticks: u32, meta: u32, rssi: u8, raw: &[u8]) {
    let count = get(MATCH_COUNT);
    let slot = count as usize % MATCH_ROWS;
    unsafe {
        write_row(
            core::ptr::addr_of_mut!(MATCH).cast::<u32>(),
            slot,
            ticks,
            meta,
            rssi,
            raw,
        );
    }
}

fn type_index(pdu_type: PduType) -> usize {
    match pdu_type {
        PduType::AdvInd => PDU_ADV_IND,
        PduType::AdvDirectInd => PDU_ADV_DIRECT_IND,
        PduType::AdvNonconnInd => PDU_ADV_NONCONN_IND,
        PduType::ScanRsp => PDU_SCAN_RSP,
        PduType::AdvScanInd => PDU_ADV_SCAN_IND,
        PduType::AdvExtInd => PDU_ADV_EXT_IND,
        PduType::ScanReq => PDU_SCAN_REQ_SEEN,
        PduType::ConnectInd => PDU_CONNECT_IND_SEEN,
        PduType::Unknown(_) => PDU_OTHER,
    }
}

fn classify(raw: &[u8], ticks: u32, rssi: u8, channel: u8) {
    let len = usize::from(raw[1]);
    if len > MAX_LEGACY_ADV_PAYLOAD || len + 2 > raw.len() || len + 2 > RX_RAW {
        inc(BAD_LENGTH);
        return;
    }
    let Some(pdu) = scan::Pdu::parse(&raw[..len + 2], true) else {
        inc(BAD_LENGTH);
        return;
    };
    inc(type_index(pdu.pdu_type()));
    let name_present = pdu.local_name().is_some();
    let mfr_present = pdu.manufacturer_data().is_some();
    if name_present {
        inc(NAMED_PDUS);
    }
    let meta = meta_word(
        channel,
        len as u8,
        true,
        pdu.pdu_type().code(),
        mfr_present,
        name_present,
    );
    #[cfg(feature = "target-src")]
    {
        let name_match = pdu.local_name() == Some(TARGET_NAME);
        let mfr_match = pdu.manufacturer_data() == Some(TARGET_MFR);
        if name_match || mfr_match {
            record_match(ticks, meta, rssi, &raw[..len + 2]);
            inc(MATCH_COUNT);
            inc(MATCH_RING_COUNT);
        }
    }
    record_sample(ticks, meta, rssi, &raw[..len + 2]);
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    let hz = hal::rcc::clocks().sysclk.0;
    let clock = Clock {
        ticks: Cell::new(ExtendingTicks::new(
            hal::pac::SYSTICK.cntl().read().cntl(),
        )),
        rate: TickRate::new(hz).unwrap(),
    };
    // A debug start may not clear .bss; do not inherit a previous run's rows.
    for i in 0..48 {
        put(i, 0);
    }
    for i in 0..SAMPLE_ROWS * ROW_WORDS {
        unsafe {
            core::ptr::addr_of_mut!(SAMPLE)
                .cast::<u32>()
                .add(i)
                .write_volatile(0);
        }
    }
    #[cfg(feature = "target-src")]
    for i in 0..MATCH_ROWS * ROW_WORDS {
        unsafe {
            core::ptr::addr_of_mut!(MATCH)
                .cast::<u32>()
                .add(i)
                .write_volatile(0);
        }
    }
    // Read through black_box so the file-backed symbols survive LTO and
    // linker GC; the runner uses them to reject a mismatched image offline.
    let run_seconds = *core::hint::black_box(&RUN_SECONDS_SYM);
    let target_src = *core::hint::black_box(&TARGET_SRC);
    put(0, 0x4f31_3538);
    put(1, 1);
    put(STAGE, STAGE_INIT);
    put(WINDOW_HALF_US_STAT, WINDOW_HALF_US);
    put(RUN_SECONDS_STAT, run_seconds);
    put(CLOCK_HZ, hz);
    put(TARGET_SRC_STAT, target_src);
    put(RESERVED, 0);
    put(RESERVED + 1, 0);

    let scratch = SCRATCH.init(DmaBuf::zeroed());
    let rx = RX.init(DmaBuf::zeroed());
    let mut radio = match new_radio_with_dma(&mut scratch.0) {
        Ok(radio) => radio,
        Err(_) => {
            put(STAGE, STAGE_INIT_FAIL);
            park();
        }
    };
    if radio.init(&clock).is_err() {
        put(STAGE, STAGE_INIT_FAIL);
        park();
    }
    radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    if !stop(&mut radio, &clock) {
        park();
    }
    clock.delay_us(500_000);

    put(STAGE, STAGE_RUNNING);
    let run_start = clock.now_us();
    let mut channel_index = 0usize;
    while clock.now_us().wrapping_sub(run_start) < run_seconds * 1_000_000 {
        let channel = CHANNELS[channel_index];
        put(LAST_CHANNEL, u32::from(channel));
        let window = match read_window(&mut radio, &clock, rx, channel) {
            Some(window) => window,
            None => {
                channel_index = (channel_index + 1) % CHANNELS.len();
                continue;
            }
        };
        put(LAST_LLE_IRQSTAT, window.lle_status);
        put(LAST_BB_IRQSTAT, window.bb_status);
        put(LAST_RSSI_RAW, u32::from(window.rssi));
        if !window.completed {
            inc(TIMEOUTS);
            if window.captured {
                inc(CAPTURED_NO_COMPLETE);
            }
            channel_index = (channel_index + 1) % CHANNELS.len();
            continue;
        }
        inc(COMPLETIONS);
        inc(CH_COMPLETIONS + usize::from(channel - 37));
        if !window.crc_ok {
            inc(CRC_ERR);
            channel_index = (channel_index + 1) % CHANNELS.len();
            continue;
        }
        inc(CRC_OK);
        inc(CH_CRC_OK + usize::from(channel - 37));
        put(LAST_LEN, u32::from(rx.0[1]));
        classify(&rx.0, window.end_us, window.rssi, channel);
        channel_index = (channel_index + 1) % CHANNELS.len();
    }
    if !stop(&mut radio, &clock) {
        park();
    }
    put(RUN_US, clock.now_us().wrapping_sub(run_start));
    put(FINAL_CMD, reg(LLE_BASE, lle::CMD));
    put(FINAL_MODE, reg(LLE_BASE, lle::MODE));
    put(STAGE, STAGE_DONE);
    park();
}
