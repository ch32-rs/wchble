//! O2: finite legacy active scanner. Receives advertising PDUs on channels
//! 37/38/39, answers scannable advertisements with `SCAN_REQ`, and records the
//! `SCAN_RSP` that follows. See README.md for the experiment, the software
//! timing offset, and its non-claims.
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
// Software offset from the polled RX_DONE to the `tx_basic` deadline. Not the
// 150 us air T_IFS and not an air-timing claim; the actual air start is later
// than this software deadline. Calibrated on 2026-11-10 against the Android
// source: 112..118 us accepted ~1/3 of requests, 120 us was mostly ignored,
// and the `tx_basic` pre-deadline setup makes offsets below 112 report Late.
const SCAN_REQ_START_AFTER_RX_DONE_US: u32 = 114;
// 2 ms response window, same 0x7FFF-safe reasoning as the advertising window.
const RSP_WINDOW_HALF_US: u32 = 4_000;
const RSP_WINDOW_US: u32 = 2_000;
const RSP_NO_CAPTURE_MARGIN_US: u32 = 500;
const RSP_POST_CAPTURE_US: u32 = 1_500;
// Static random scanner address, printed as C1:FF:EE:00:00:31 (TxAdd=1).
const SCAN_ADDR: [u8; 6] = [0x31, 0x00, 0x00, 0xee, 0xff, 0xc1];
const SCAN_RANDOM: bool = true;
const RX_RAW: usize = 40;
const ADV_ROWS: usize = 4;
const RSP_ROWS: usize = 4;
const ROW_WORDS: usize = 13;

// Controlled source (test only): manufacturer data 0xFFFF + "O2ADV" + 0x01 in
// the advertisement and 0xFFFF + "O2RSP" + 0x01 in the scan response. The
// wrong-marker control uses "O2ADX" in a scannable advertisement.
const MARKER_ADV: &[u8] = &[0xff, 0xff, b'O', b'2', b'A', b'D', b'V', 0x01];
const MARKER_RSP: &[u8] = &[0xff, 0xff, b'O', b'2', b'R', b'S', b'P', 0x01];
const MARKER_WRONG: &[u8] = &[0xff, 0xff, b'O', b'2', b'A', b'D', b'X', 0x01];

static SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX_ADV: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX_RSP: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static TX_REQ: StaticCell<DmaBuf<16>> = StaticCell::new();

#[no_mangle]
#[used]
pub static RUN_SECONDS_SYM: u32 = RUN_SECONDS;
#[no_mangle]
#[used]
pub static TARGET_SRC: u32 = cfg!(feature = "target-src") as u32;
#[no_mangle]
#[used]
pub static SCAN_REQ_OFFSET: u32 = SCAN_REQ_START_AFTER_RX_DONE_US;
#[no_mangle]
#[used]
pub static SCAN_ADDR_SYM: [u8; 6] = SCAN_ADDR;
#[no_mangle]
static mut STATS: [u32; 64] = [0; 64];
#[no_mangle]
static mut ADV_RING: [u32; ADV_ROWS * ROW_WORDS] = [0; ADV_ROWS * ROW_WORDS];
#[no_mangle]
static mut RSP_RING: [u32; RSP_ROWS * ROW_WORDS] = [0; RSP_ROWS * ROW_WORDS];
static mut ADV_WRITES: u32 = 0;
static mut RSP_WRITES: u32 = 0;


// STATS layout (README and tools/run.py must agree).
const STAGE: usize = 2;
const RUN_US: usize = 3;
const WINDOW_HALF_US_STAT: usize = 4;
const RUN_SECONDS_STAT: usize = 5;
const WINDOWS: usize = 6;
const ARM_ERRORS: usize = 7;
const COMPLETIONS: usize = 8;
const TIMEOUTS: usize = 9;
const CRC_OK: usize = 10;
const CRC_ERR: usize = 11;
const BAD_LENGTH: usize = 12;
const PARSED: usize = 13;
const PDU_ADV_IND: usize = 14;
const PDU_ADV_SCAN_IND: usize = 15;
const PDU_ADV_NONCONN_IND: usize = 16;
const PDU_ADV_DIRECT_IND: usize = 17;
const PDU_SCAN_RSP_SEEN: usize = 18;
const PDU_SCAN_REQ_SEEN: usize = 19;
const PDU_CONNECT_IND_SEEN: usize = 20;
const PDU_OTHER: usize = 21;
const MARKER_ADVS: usize = 22;
const MARKER_SCANNABLE: usize = 23;
const MARKER_NONCONN: usize = 24;
const MARKER_OTHER: usize = 25;
const ATTEMPTS: usize = 26;
const SENT: usize = 27;
const LATE: usize = 28;
const REQ_ERR: usize = 29;
const RSP_WINDOWS: usize = 30;
const RSP_ARM_ERRORS: usize = 31;
const RSP_COMPLETIONS: usize = 32;
const RSP_TIMEOUTS: usize = 33;
const RSP_CRC_OK: usize = 34;
const RSP_CRC_ERR: usize = 35;
const RSP_ACCEPTED: usize = 36;
const RSP_REJECT_TYPE: usize = 37;
const RSP_REJECT_ADV_A: usize = 38;
const RSP_REJECT_MARKER: usize = 39;
const STOP_FAILURES: usize = 40;
const CH_COMPLETIONS: usize = 41;
const LAST_ADV_LEN: usize = 44;
const LAST_RSP_LEN: usize = 45;
const LAST_ADV_RSSI: usize = 46;
const LAST_RSP_RSSI: usize = 47;
const LAST_TX_ENTRY: usize = 48;
const MAX_TX_ENTRY: usize = 49;
const LAST_TX_RETURN: usize = 50;
const MAX_TX_RETURN: usize = 51;
const LAST_MARGIN: usize = 52;
const MIN_MARGIN: usize = 53;
const LAST_RSP_ARM: usize = 54;
const MAX_RSP_ARM: usize = 55;
const LAST_RSP_LATENCY: usize = 56;
const FINAL_CMD: usize = 57;
const FINAL_MODE: usize = 58;
const CLOCK_HZ: usize = 59;
const TARGET_SRC_STAT: usize = 60;
const SCAN_REQ_OFFSET_STAT: usize = 61;
const ADV_CH_MASK: usize = 62;
const RSP_CH_MASK: usize = 63;

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
    true
}

/// One advertising-channel arm/capture/stop cycle. The DMA buffer is untouched
/// until stop.
struct Window {
    completed: bool,
    crc_ok: bool,
    rssi: u8,
    end_us: u32,
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
    if radio.rx_basic(clock, &mut rx.0, WINDOW_HALF_US).is_err() {
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
    let bb_status = reg(BB_BASE, bb::IRQSTAT);
    let crc_ok = bb_status & bb_irq::CRC_ERR == 0;
    let rssi = radio.rssi() as u8;
    if !stop(radio, clock) {
        park();
    }
    Some(Window {
        completed,
        crc_ok,
        rssi,
        end_us,
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

fn record_adv(ticks: u32, meta: u32, rssi: u8, raw: &[u8]) {
    let slot = unsafe { ADV_WRITES } as usize % ADV_ROWS;
    unsafe {
        write_row(
            core::ptr::addr_of_mut!(ADV_RING).cast::<u32>(),
            slot,
            ticks,
            meta,
            rssi,
            raw,
        );
        ADV_WRITES = ADV_WRITES.wrapping_add(1);
    }
}

fn record_rsp(ticks: u32, meta: u32, rssi: u8, raw: &[u8]) {
    let slot = unsafe { RSP_WRITES } as usize % RSP_ROWS;
    unsafe {
        write_row(
            core::ptr::addr_of_mut!(RSP_RING).cast::<u32>(),
            slot,
            ticks,
            meta,
            rssi,
            raw,
        );
        RSP_WRITES = RSP_WRITES.wrapping_add(1);
    }
}

fn type_index(pdu_type: PduType) -> usize {
    match pdu_type {
        PduType::AdvInd => PDU_ADV_IND,
        PduType::AdvScanInd => PDU_ADV_SCAN_IND,
        PduType::AdvNonconnInd => PDU_ADV_NONCONN_IND,
        PduType::AdvDirectInd => PDU_ADV_DIRECT_IND,
        PduType::ScanRsp => PDU_SCAN_RSP_SEEN,
        PduType::ScanReq => PDU_SCAN_REQ_SEEN,
        PduType::ConnectInd => PDU_CONNECT_IND_SEEN,
        PduType::AdvExtInd | PduType::Unknown(_) => PDU_OTHER,
    }
}

/// Result of classifying one CRC-valid advertising-channel PDU.
struct AdvClass {
    pdu_type: PduType,
    len: u8,
    mfr_present: bool,
    /// Advertisement carries the expected controlled-source marker.
    marker: bool,
    /// Advertisement carries the wrong-marker control marker.
    wrong: bool,
    /// Address and AdvA address type of a candidate this build should answer.
    candidate: Option<([u8; 6], bool)>,
}

/// Classify one CRC-valid advertising-channel PDU.
///
/// This runs between the polled `RX_DONE` and the `SCAN_REQ` deadline, so it
/// does no STATS, ring or clock work and lives in the RAM-copied `.highcode`
/// section: CH585 flash execution alone costs far more than the SCAN_REQ budget.
#[link_section = ".highcode"]
#[inline(never)]
fn classify_adv(raw: &[u8]) -> Option<AdvClass> {
    let len = usize::from(raw[1]);
    if len > MAX_LEGACY_ADV_PAYLOAD || len + 2 > raw.len() || len + 2 > RX_RAW {
        return None;
    }
    let pdu = scan::Pdu::parse(&raw[..len + 2], true)?;
    let pdu_type = pdu.pdu_type();
    let mfr = pdu.manufacturer_data();
    let marker = mfr == Some(MARKER_ADV);
    let wrong = mfr == Some(MARKER_WRONG);
    let candidate = if pdu_type.is_scannable() && (!cfg!(feature = "target-src") || marker) {
        Some((*pdu.adv_a()?, pdu.tx_add()))
    } else {
        None
    };
    Some(AdvClass {
        pdu_type,
        len: len as u8,
        mfr_present: mfr.is_some(),
        marker,
        wrong,
        candidate,
    })
}

/// Classify one CRC-valid response-window PDU against the request that preceded
/// it. Every completion lands in exactly one of accepted / type / AdvA /
/// marker.
fn classify_rsp(raw: &[u8], ticks: u32, rssi: u8, channel: u8, adv_a: [u8; 6]) {
    let len = usize::from(raw[1]);
    let parsed = if len <= MAX_LEGACY_ADV_PAYLOAD && len + 2 <= raw.len() && len + 2 <= RX_RAW {
        scan::Pdu::parse(&raw[..len + 2], true)
    } else {
        None
    };
    let Some(pdu) = parsed else {
        inc(RSP_REJECT_TYPE);
        return;
    };
    if pdu.pdu_type() != PduType::ScanRsp {
        inc(RSP_REJECT_TYPE);
        return;
    }
    if pdu.adv_a() != Some(&adv_a) {
        inc(RSP_REJECT_ADV_A);
        return;
    }
    if cfg!(feature = "target-src") && pdu.manufacturer_data() != Some(MARKER_RSP) {
        inc(RSP_REJECT_MARKER);
        return;
    }
    let meta = meta_word(
        channel,
        len as u8,
        true,
        pdu.pdu_type().code(),
        pdu.manufacturer_data().is_some(),
        false,
    );
    record_rsp(ticks, meta, rssi, &raw[..len + 2]);
    inc(RSP_ACCEPTED);
    put(RSP_CH_MASK, get(RSP_CH_MASK) | (1 << (channel - 37)));
    put(LAST_RSP_LEN, u32::from(len as u8));
    put(LAST_RSP_RSSI, u32::from(rssi));
}

/// Answer one scannable advertisement: stop already acknowledged, DMA read,
/// build SCAN_REQ, TX at a software deadline, then arm one RX window for the
/// SCAN_RSP. All DMA buffers stay quarantined behind `stop()`.
#[allow(clippy::too_many_arguments)]
fn answer(
    radio: &mut Ch585Radio,
    clock: &Clock,
    tx: &mut DmaBuf<16>,
    rx_rsp: &mut DmaBuf<RX_DMA_MIN>,
    adv_a: [u8; 6],
    adv_random: bool,
    channel: u8,
    adv_end_us: u32,
) {
    let Some(len) = scan::build_scan_req(&mut tx.0, &SCAN_ADDR, SCAN_RANDOM, &adv_a, adv_random) else {
        inc(ATTEMPTS);
        inc(REQ_ERR);
        return;
    };
    // Only the build and the tx call sit between the polled RX_DONE and the
    // deadline; all STATS bookkeeping is deferred until after TX_DONE.
    let deadline = adv_end_us.wrapping_add(SCAN_REQ_START_AFTER_RX_DONE_US);
    let entry = clock.now_us();
    let result = radio.tx_basic(clock, &tx.0[..len], 0, Some(deadline));
    let tx_done = clock.now_us();
    let entry_delta = entry.wrapping_sub(adv_end_us);
    let ret_delta = tx_done.wrapping_sub(adv_end_us);
    put(LAST_TX_ENTRY, entry_delta);
    if entry_delta > get(MAX_TX_ENTRY) {
        put(MAX_TX_ENTRY, entry_delta);
    }
    put(LAST_TX_RETURN, ret_delta);
    if ret_delta > get(MAX_TX_RETURN) {
        put(MAX_TX_RETURN, ret_delta);
    }
    let margin = deadline.wrapping_sub(entry);
    if margin < 0x8000_0000 {
        put(LAST_MARGIN, margin);
        if margin < get(MIN_MARGIN) {
            put(MIN_MARGIN, margin);
        }
    } else {
        // Already past the software deadline; tx_basic reports Late.
        put(LAST_MARGIN, 0);
        put(MIN_MARGIN, 0);
    }
    inc(ATTEMPTS);
    match result {
        Ok(()) => inc(SENT),
        Err(wchble::Error::Late) => {
            inc(LATE);
            if !stop(radio, clock) {
                park();
            }
            return;
        }
        Err(_) => {
            inc(REQ_ERR);
            if !stop(radio, clock) {
                park();
            }
            return;
        }
    }
    // TX_DONE leaves the LLE command engaged until the engine is re-armed or
    // shut; `rx_basic` performs the same force-stop as the vendor scanner, so
    // arm over it directly.
    let arm_entry = clock.now_us();
    // SCAN_RSP latches belong to the previous window, not this one.
    unsafe {
        regs::write(BB_BASE, bb::IRQSTAT, 0xf0);
    }
    if radio
        .rx_basic(clock, &mut rx_rsp.0, RSP_WINDOW_HALF_US)
        .is_err()
    {
        inc(RSP_ARM_ERRORS);
        if !stop(radio, clock) {
            park();
        }
        return;
    }
    inc(RSP_WINDOWS);
    let arm_delta = arm_entry.wrapping_sub(tx_done);
    put(LAST_RSP_ARM, arm_delta);
    if arm_delta > get(MAX_RSP_ARM) {
        put(MAX_RSP_ARM, arm_delta);
    }
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
            radio.note_anchor_us(now);
            radio.bb_isr();
            captured = true;
            capture_at = now;
        }
        let expired = if captured {
            now.wrapping_sub(capture_at) >= RSP_POST_CAPTURE_US
        } else {
            now.wrapping_sub(armed) >= RSP_WINDOW_US + RSP_NO_CAPTURE_MARGIN_US
        };
        if expired {
            break;
        }
    }
    let bb_status = reg(BB_BASE, bb::IRQSTAT);
    let crc_ok = bb_status & bb_irq::CRC_ERR == 0;
    let rssi = radio.rssi() as u8;
    if !stop(radio, clock) {
        park();
    }
    if !completed {
        inc(RSP_TIMEOUTS);
        return;
    }
    inc(RSP_COMPLETIONS);
    put(LAST_RSP_LATENCY, end_us.wrapping_sub(tx_done));
    if !crc_ok {
        inc(RSP_CRC_ERR);
        return;
    }
    inc(RSP_CRC_OK);
    classify_rsp(&rx_rsp.0, end_us, rssi, channel, adv_a);
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
    for i in 0..64 {
        put(i, 0);
    }
    for i in 0..ADV_ROWS * ROW_WORDS {
        unsafe {
            core::ptr::addr_of_mut!(ADV_RING)
                .cast::<u32>()
                .add(i)
                .write_volatile(0);
        }
    }
    for i in 0..RSP_ROWS * ROW_WORDS {
        unsafe {
            core::ptr::addr_of_mut!(RSP_RING)
                .cast::<u32>()
                .add(i)
                .write_volatile(0);
        }
    }
    unsafe {
        ADV_WRITES = 0;
        RSP_WRITES = 0;
    }
    // Read through black_box so the file-backed symbols survive LTO and
    // linker GC; the runner uses them to reject a mismatched image offline.
    let run_seconds = *core::hint::black_box(&RUN_SECONDS_SYM);
    let target_src = *core::hint::black_box(&TARGET_SRC);
    let offset = *core::hint::black_box(&SCAN_REQ_OFFSET);
    let scan_addr = *core::hint::black_box(&SCAN_ADDR_SYM);
    if scan_addr != SCAN_ADDR {
        // The runner checks this file-backed symbol too.
        put(STAGE, STAGE_INIT_FAIL);
        park();
    }
    put(0, 0x4f32_3538);
    put(1, 1);
    put(STAGE, STAGE_INIT);
    put(WINDOW_HALF_US_STAT, WINDOW_HALF_US);
    put(RUN_SECONDS_STAT, run_seconds);
    put(CLOCK_HZ, hz);
    put(TARGET_SRC_STAT, target_src);
    put(SCAN_REQ_OFFSET_STAT, offset);
    put(MIN_MARGIN, 0xffff_ffff);

    let scratch = SCRATCH.init(DmaBuf::zeroed());
    let rx_adv = RX_ADV.init(DmaBuf::zeroed());
    let rx_rsp = RX_RSP.init(DmaBuf::zeroed());
    let tx_req = TX_REQ.init(DmaBuf::zeroed());
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
        let window = match read_window(&mut radio, &clock, rx_adv, channel) {
            Some(window) => window,
            None => {
                channel_index = (channel_index + 1) % CHANNELS.len();
                continue;
            }
        };
        if !window.completed {
            inc(TIMEOUTS);
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
        let Some(class) = classify_adv(&rx_adv.0) else {
            inc(BAD_LENGTH);
            channel_index = (channel_index + 1) % CHANNELS.len();
            continue;
        };
        inc(PARSED);
        inc(type_index(class.pdu_type));
        if class.marker {
            match class.pdu_type {
                PduType::AdvInd | PduType::AdvScanInd => {
                    inc(MARKER_ADVS);
                    inc(MARKER_SCANNABLE);
                    put(ADV_CH_MASK, get(ADV_CH_MASK) | (1 << (channel - 37)));
                }
                PduType::AdvNonconnInd => {
                    inc(MARKER_ADVS);
                    inc(MARKER_NONCONN);
                }
                _ => {}
            }
        }
        if class.wrong {
            inc(MARKER_OTHER);
        }
        put(LAST_ADV_LEN, u32::from(class.len));
        put(LAST_ADV_RSSI, u32::from(window.rssi));
        if let Some((adv_a, adv_random)) = class.candidate {
            answer(
                &mut radio,
                &clock,
                tx_req,
                rx_rsp,
                adv_a,
                adv_random,
                channel,
                window.end_us,
            );
            // The ring row is written after the response exchange; rx_adv is
            // not touched by answer().
            let len = usize::from(class.len);
            let meta = meta_word(
                channel,
                class.len,
                true,
                class.pdu_type.code(),
                class.mfr_present,
                false,
            );
            record_adv(window.end_us, meta, window.rssi, &rx_adv.0[..len + 2]);
        }
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
