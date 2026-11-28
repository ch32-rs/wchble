//! CH573 passive Observer: hop 37/38/39 with one RX window per channel,
//! count what arrives, never transmit. See README.md for scope and non-claims.
//!
//! Flash with the pinned CH573 probe only:
//! `probe-rs run --chip CH573 --probe 1a86:8010:5CED8F06E1D2 --scan-region ram`

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use defmt::info;
use defmt_rtt as _;
use hal::rcc;
use qingke_rt::entry;
use wchble::ll::scan::Pdu;
use wchble::rf::family::ch573::{
    install_ble_irq, irq_entries, rx_isr_take, Ch573Radio, RxPoll, CAPS, LLE_BASE,
};
use wchble::rf::regs;
use wchble::rf::txrx::RX_DMA_MIN;
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs};
use portable_atomic as _;

/// Log where a panic happened instead of halting silently (`panic-halt`).
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    match info.location() {
        Some(l) => defmt::error!("panic {}:{}", l.file(), l.line()),
        None => defmt::error!("panic"),
    }
    loop {
        core::hint::spin_loop();
    }
}

defmt::timestamp!("{=u32}", 0u32);

const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;

const CHANNELS: [u8; 3] = [37, 38, 39];

/// 15 ms window = 30,000 half-µs. Keeps the LLE WINDOW count below bit 15;
/// the field width above `0x7FFF` is not established (same bound as the
/// CH585 observer).
const WINDOW_HALF_US: u32 = 30_000;
const WINDOW_US: u32 = 15_000;
/// Host-side wait budget over the window before the result is declared lost.
const WAIT_SLACK_US: u32 = 5_000;
/// Engine settle after `shut()` before the DMA buffer is read again.
const STOP_DELAY_US: u32 = 5_000;

/// Periodic summary cadence, in seconds of run time.
const SUMMARY_EVERY_S: u32 = 5;

const ADV_ROWS: usize = 24;
const NAME_BYTES: usize = 16;

/// Run length in seconds; `CH573_OBS_RUN_S` at build time (default 30).
fn run_seconds() -> u32 {
    parse_dec(option_env!("CH573_OBS_RUN_S")).unwrap_or(30)
}

const fn parse_dec(s: Option<&str>) -> Option<u32> {
    let s = match s {
        Some(s) => s.as_bytes(),
        None => return None,
    };
    if s.is_empty() {
        return None;
    }
    let mut v: u32 = 0;
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if !b.is_ascii_digit() {
            return None;
        }
        v = match v.checked_mul(10) {
            Some(v) => match v.checked_add((b - b'0') as u32) {
                Some(v) => v,
                None => return None,
            },
            None => return None,
        };
        i += 1;
    }
    Some(v)
}

/// DMA-visible RX buffer placed by `build.rs`.
#[repr(align(4))]
struct DmaCell<const N: usize>(core::cell::UnsafeCell<[u8; N]>);

// SAFETY: single-threaded firmware; the buffers are only used by `main`.
unsafe impl<const N: usize> Sync for DmaCell<N> {}

impl<const N: usize> DmaCell<N> {
    const fn new() -> Self {
        Self(core::cell::UnsafeCell::new([0; N]))
    }
}

/// Rounds completed; read from RAM with `probe-rs read b32` to tell a stuck
/// core from a stalled RTT session (the value keeps moving when the firmware
/// is alive and only the log stopped).
#[no_mangle]
pub static OBS_ALIVE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Boot milestone, for pinning down where a stuck boot stopped.
#[no_mangle]
pub static BOOT_STAGE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn boot(v: u32) {
    BOOT_STAGE.store(v, core::sync::atomic::Ordering::Relaxed);
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

/// Run time in µs, extended past the 32-bit SysTick wrap (71.6 s at 60 MHz).
fn elapsed_us(clock: &UsClock, ext: &mut ExtendingTicks) -> u64 {
    ext.sample(clock.ticks()) / u64::from(clock.ticks_per_us.max(1))
}

/// `LLE+0x08` is plain R/W: clear flags by writing the bits back as zero.
fn clear_lle_irq(bits: u32) {
    unsafe {
        let v = mmio(LLE_BASE, 0x08);
        regs::write(LLE_BASE, 0x08, v & !bits);
    }
}

/// One advertiser seen by this run.
struct AdvEntry {
    addr: [u8; 6],
    name: [u8; NAME_BYTES],
    name_len: u8,
    count: u32,
    last_rssi: i8,
}

impl Default for AdvEntry {
    fn default() -> Self {
        Self::empty()
    }
}

impl AdvEntry {
    const fn empty() -> Self {
        Self {
            addr: [0; 6],
            name: [0; NAME_BYTES],
            name_len: 0,
            count: 0,
            last_rssi: 0,
        }
    }
}

#[derive(Default)]
struct Counters {
    rounds: u32,
    windows: u32,
    arm_errors: u32,
    timeouts: u32,
    stale: u32,
    done: u32,
    crc_ok: u32,
    crc_err: u32,
    bad_len: u32,
    mismatch: u32,
    named: u32,
    mfr: u32,
    /// Arm → result latency in µs: min/max/sum over all windows.
    dt_min_us: u32,
    dt_max_us: u32,
    dt_sum_us: u64,
    /// Timeout-only latency bounds and end-of-window anomalies.
    timeout_min_us: u32,
    timeout_max_us: u32,
    early_timeouts: u32,
    late_results: u32,
    first_done_logged: bool,
    ch_windows: [u32; 3],
    ch_ok: [u32; 3],
    /// Header low nibble 0..=7 plus 8..=15 in one array.
    types: [u32; 16],
    /// 10 dB buckets from −120 dBm up.
    rssi_hist: [u32; 12],
    adv: [AdvEntry; ADV_ROWS],
    adv_used: usize,
}

impl Counters {
    fn note_adv(&mut self, addr: [u8; 6], rssi: i8, name: &[u8]) {
        for e in self.adv[..self.adv_used].iter_mut() {
            if e.addr == addr {
                e.count += 1;
                e.last_rssi = rssi;
                if e.name_len == 0 && !name.is_empty() {
                    let n = name.len().min(NAME_BYTES);
                    e.name[..n].copy_from_slice(&name[..n]);
                    e.name_len = n as u8;
                }
                return;
            }
        }
        if self.adv_used < ADV_ROWS {
            let mut e = AdvEntry::empty();
            e.addr = addr;
            e.count = 1;
            e.last_rssi = rssi;
            let n = name.len().min(NAME_BYTES);
            e.name[..n].copy_from_slice(&name[..n]);
            e.name_len = n as u8;
            self.adv[self.adv_used] = e;
            self.adv_used += 1;
        }
    }

    fn hist(&self, rssi: i8) -> usize {
        ((i16::from(rssi) + 120) / 10).clamp(0, 11) as usize
    }

    fn summary(&self, t_s: u32, irq: u32) {
        info!(
            "obs t={=u32} rounds={=u32} win={=u32} arm_err={=u32} irq={=u32}",
            t_s, self.rounds, self.windows, self.arm_errors, irq
        );
        info!(
            "obs done={=u32} to={=u32} stale={=u32} crc_ok={=u32} crc_err={=u32}",
            self.done, self.timeouts, self.stale, self.crc_ok, self.crc_err
        );
        info!(
            "obs bad_len={=u32} mismatch={=u32} named={=u32} mfr={=u32} adv_seen={=u32}",
            self.bad_len, self.mismatch, self.named, self.mfr, self.adv_used as u32
        );
        let avg = if self.windows > 0 {
            self.dt_sum_us / u64::from(self.windows)
        } else {
            0
        };
        info!(
            "obs win_dt_us min={=u32} avg={=u64} max={=u32}",
            self.dt_min_us, avg, self.dt_max_us
        );
        info!(
            "obs to_dt_us min={=u32} max={=u32} early={=u32} late={=u32}",
            self.timeout_min_us, self.timeout_max_us, self.early_timeouts, self.late_results
        );
        info!(
            "obs ch37 win={=u32} ok={=u32} ch38 win={=u32} ok={=u32}",
            self.ch_windows[0], self.ch_ok[0], self.ch_windows[1], self.ch_ok[1]
        );
        info!(
            "obs ch39 win={=u32} ok={=u32}",
            self.ch_windows[2], self.ch_ok[2]
        );
        info!(
            "obs pdu ind={=u32} dir={=u32} nonconn={=u32} scan_req={=u32}",
            self.types[0], self.types[1], self.types[2], self.types[3]
        );
        info!(
            "obs scan_rsp={=u32} conn={=u32} scan_ind={=u32} ext={=u32} rfuv={=u32}",
            self.types[4],
            self.types[5],
            self.types[6],
            self.types[7],
            self.types[8..].iter().sum::<u32>()
        );
        info!("obs rssi_hist(-120..0,10dB) {:?}", &self.rssi_hist[..]);
    }

    fn adv_table(&self) {
        for (i, e) in self.adv[..self.adv_used].iter().enumerate() {
            info!(
                "adv {=usize} a={:?} n={:?} cnt={=u32} rssi={=i8}",
                i,
                &e.addr[..],
                &e.name[..usize::from(e.name_len)],
                e.count,
                e.last_rssi
            );
        }
    }
}

/// Arm one window on `ch`, wait for the ISR result, stop the engine, and
/// account for whatever came back.
fn observe_channel(
    clock: &UsClock,
    radio: &mut Ch573Radio,
    rx: &mut [u8; RX_DMA_MIN],
    ch: u8,
    ci: usize,
    c: &mut Counters,
) {
    if radio.set_channel(ch).is_err() {
        c.arm_errors += 1;
        return;
    }
    for b in rx.iter_mut() {
        *b = 0xAA;
    }
    clear_lle_irq(0xffff);

    // SAFETY: `rx` is DMA-visible and the engine was stopped after the
    // previous window.
    if unsafe { radio.rx_basic(clock, &mut rx[..], WINDOW_HALF_US) }.is_err() {
        c.arm_errors += 1;
        radio.shut();
        return;
    }
    c.windows += 1;
    c.ch_windows[ci] += 1;
    let t_arm = clock.ticks();

    // The ISR produces the result; the host timeout only guards a lost event.
    let start = clock.now_us();
    let poll = loop {
        if let Some(p) = rx_isr_take() {
            break Some(p);
        }
        if clock.now_us().wrapping_sub(start) > WINDOW_US + WAIT_SLACK_US {
            break None;
        }
    };

    // Arm → result latency; on `Timeout` this is the real armed window.
    let dt_us = clock.ticks().wrapping_sub(t_arm) / clock.ticks_per_us.max(1);
    c.dt_sum_us += u64::from(dt_us);
    if c.dt_min_us == 0 || dt_us < c.dt_min_us {
        c.dt_min_us = dt_us;
    }
    if dt_us > c.dt_max_us {
        c.dt_max_us = dt_us;
    }
    if dt_us > WINDOW_US * 2 {
        c.late_results += 1;
    }

    // Stop before reading or re-using the DMA buffer.
    radio.shut();
    clock.delay_us(STOP_DELAY_US);

    let (len, rssi, crc_ok) = match poll {
        None => {
            c.stale += 1;
            return;
        }
        Some(RxPoll::Armed) | Some(RxPoll::Timeout) => {
            c.timeouts += 1;
            if c.timeout_min_us == 0 || dt_us < c.timeout_min_us {
                c.timeout_min_us = dt_us;
            }
            if dt_us > c.timeout_max_us {
                c.timeout_max_us = dt_us;
            }
            if dt_us < WINDOW_US * 3 / 4 {
                c.early_timeouts += 1;
                if c.early_timeouts <= 5 {
                    info!(
                        "win early ch{=u8} dt_us={=u32} lle60={=u32:x}",
                        ch,
                        dt_us,
                        mmio(LLE_BASE, 0x60)
                    );
                }
            }
            return;
        }
        Some(RxPoll::Done { len, rssi, crc_ok }) => (len, rssi, crc_ok),
    };
    if !c.first_done_logged {
        c.first_done_logged = true;
        info!("win first_done ch{=u8} dt_us={=u32}", ch, dt_us);
    }
    c.done += 1;
    if !crc_ok {
        c.crc_err += 1;
        return;
    }
    // A second frame can land in the same window after the ISR published the
    // first one. Only parse when the bytes still match the published length.
    if rx[0] == 0xAA || usize::from(rx[1]) != usize::from(len) {
        c.mismatch += 1;
        return;
    }
    let Some(pdu) = Pdu::parse(&rx[..], true) else {
        c.bad_len += 1;
        return;
    };

    c.crc_ok += 1;
    c.ch_ok[ci] += 1;
    c.types[usize::from(pdu.pdu_type().code() & 0x0f)] += 1;
    c.rssi_hist[c.hist(rssi)] += 1;
    let name = pdu.local_name().unwrap_or(&[]);
    // SCAN_REQ carries ScanA/TargetA, not AdvA; only AdvA rows are keyed.
    let adv_a = pdu.adv_a().copied();
    if !name.is_empty() {
        c.named += 1;
    }
    if pdu.manufacturer_data().is_some() {
        c.mfr += 1;
    }
    if let Some(addr) = adv_a {
        c.note_adv(addr, rssi, name);
    }
    let addr: &[u8] = match &adv_a {
        Some(a) => &a[..],
        None => &[],
    };

    info!(
        "pkt ch{=u8} t={=u8:x} len={=u8} rssi={=i8} a={:?}",
        ch,
        pdu.pdu_type().code(),
        len,
        rssi,
        addr
    );
}

#[entry]
fn main() -> ! {
    boot(1);
    let _p = hal::init(rcc::Config::PLL_60MHZ.into());
    boot(2);
    info!("boot");
    info!("wchble ch573 observer sysclk={}", rcc::clocks().sysclk.0);
    boot(3);

    let clock = UsClock::start();
    boot(4);
    // SAFETY: single-threaded; the buffers are used only here.
    let scratch: &mut [u8] = unsafe { &mut *RX_SCRATCH.0.get() };
    let rx: &mut [u8; RX_DMA_MIN] = unsafe { &mut *RX_BUF.0.get() };
    if !CAPS.contains_dma(scratch.as_ptr() as usize, scratch.len())
        || !CAPS.contains_dma(rx.as_ptr() as usize, rx.len())
    {
        info!(
            "dma OUT OF WINDOW expect {=usize:x}..{=usize:x}",
            CAPS.sram_start, CAPS.sram_end
        );
        loop {}
    }
    boot(5);

    let mut radio: Ch573Radio = match new_radio_with_dma(scratch) {
        Ok(r) => r,
        Err(e) => {
            info!("radio new err {:?}", e);
            loop {}
        }
    };
    boot(6);
    match radio.init(&clock) {
        Ok(()) => info!("rf init ok"),
        Err(e) => {
            info!("rf init err {:?}", e);
            loop {}
        }
    }
    boot(7);
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);

    // SAFETY: PFIC writes only; runs with interrupts masked.
    unsafe { install_ble_irq() };

    let run_s = run_seconds();
    info!(
        "obs start run_s={=u32} window_half_us={=u32} channels={:?}",
        run_s,
        WINDOW_HALF_US,
        &CHANNELS[..]
    );

    let mut c = Counters::default();
    let mut ext = ExtendingTicks::new(clock.ticks());
    let run_end_us = u64::from(run_s) * 1_000_000;
    let mut last_summary_s = 0u64;

    'run: loop {
        for (ci, &ch) in CHANNELS.iter().enumerate() {
            if elapsed_us(&clock, &mut ext) >= run_end_us {
                break 'run;
            }
            observe_channel(&clock, &mut radio, rx, ch, ci, &mut c);
        }
        c.rounds = c.rounds.wrapping_add(1);
        OBS_ALIVE.store(c.rounds, core::sync::atomic::Ordering::Relaxed);
        let t_s = elapsed_us(&clock, &mut ext) / 1_000_000;
        if t_s >= last_summary_s + u64::from(SUMMARY_EVERY_S) {
            last_summary_s = t_s;
            c.summary(t_s as u32, irq_entries());
        }
    }

    radio.shut();
    let t_s = elapsed_us(&clock, &mut ext) / 1_000_000;
    // Skip a final summary that the periodic one just printed.
    if t_s != last_summary_s {
        c.summary(t_s as u32, irq_entries());
    }
    c.adv_table();
    info!(
        "obs final run_s={=u32} elapsed_s={=u64} rounds={=u32} win={=u32} done={=u32}",
        run_s, t_s, c.rounds, c.windows, c.done
    );
    info!("obs parked");
    loop {
        clock.delay_us(1_000_000);
    }
}
