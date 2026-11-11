//! CH585 entropy measurement: timer jitter + ADC temperature noise.
//!
//! S0 must not claim a secure connection without a measured entropy source.
//! This image never starts the RF block: it runs two timing phases, conditions
//! the samples with [`EntropyPool`], seeds the controller DRBG through the soft
//! HCI path, answers two `HCI_LE_Rand` commands, and parks. With RF idle the
//! probe can read the RAM log at any time.
//!
//! Phase A repeats one fixed workload and records the SysTick delta: the
//! spread is the jitter available to the seed. Phase B records ADC temperature
//! samples and how long each conversion took.
//!
//! Console markers:
//! - `entropy start`
//! - `jitter n=… min=… max=… mean=… distinct=… zero=…`
//! - `adc n=… min=… max=… distinct=… ticks=…/…/…`
//! - `seed <16 hex chars>`
//! - `le rand 0 <16 hex chars>` / `le rand 1 …`
//! - `entropy done`

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::fmt::{self, Write};
use core::future::Future;
use core::task::{Context, Waker};
use hal::adc::{Adc, Config as AdcConfig};
use hal::rcc;
use hal::time::Hertz;
use qingke_rt::entry;
use wchble::hci::transport::{self, Packet};
use wchble::hci::SoftRunner;
use wchble::rand::EntropyPool;
use {panic_halt as _, portable_atomic as _};

/// Fixed-workload timing samples.
const JITTER_ROUNDS: usize = 1024;
/// ADC samples (also measures conversion time). Two halves in one boot show
/// whether the low-bit noise repeats or is fresh per sample. Only the first
/// 256 values are logged; all of them feed the pool.
const ADC_ROUNDS: usize = 512;
const ADC_LOG: usize = 256;

/// RAM console for `wlink`/`probe-rs` dumps (same layout as the RF smoke).
#[no_mangle]
static mut LOG: [u8; 2048] = [0; 2048];

/// Machine-readable results, read by `tools/run.py`.
///
/// 0 magic, 1 version, 2 stage, 3 jitter_rounds, 4 jitter_min, 5 jitter_max,
/// 6 jitter_distinct, 7 jitter_mean, 8 adc_samples, 9 adc_min, 10 adc_max,
/// 11 adc_distinct, 12 adc_ticks_min, 13 adc_ticks_max, 14 adc_ticks_distinct,
/// 15 seed_w0, 16 seed_w1, 17 rand0_w0, 18 rand0_w1, 19 rand1_w0,
/// 20 rand1_w1, 21 seeded, 22 rand_differs, 23 adc_errors, 24 sysclk_hz,
/// 25 jitter_zero, 26..31 reserved.
#[no_mangle]
static mut STATS: [u32; 32] = [0; 32];

const STATS_MAGIC: u32 = 0x4530_3538; // "E058"

const LOG_CAP: usize = 2048;
const LOG_TEXT: usize = LOG_CAP - 4;

struct Log;

impl fmt::Write for Log {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let base = core::ptr::addr_of_mut!(LOG).cast::<u8>();
        unsafe {
            let mut len = core::ptr::read_unaligned(base.cast::<u32>()) as usize;
            if len > LOG_TEXT || len + s.len() > LOG_TEXT {
                len = 0;
            }
            for b in s.bytes() {
                base.add(4 + len).write_volatile(b);
                len += 1;
            }
            core::ptr::write_unaligned(base.cast::<u32>(), len as u32);
        }
        Ok(())
    }
}

fn put(index: usize, value: u32) {
    let p = core::ptr::addr_of_mut!(STATS).cast::<u32>();
    unsafe { p.add(index).write_volatile(value) };
}

fn systick() -> u32 {
    hal::pac::SYSTICK.cntl().read().cntl()
}

/// Number of distinct values in `values`, saturating at `unique.len()`.
fn distinct(values: &[u32], unique: &mut [u32]) -> (u32, usize) {
    let mut count = 0;
    for &value in values {
        if unique[..count].contains(&value) {
            continue;
        }
        if count < unique.len() {
            unique[count] = value;
            count += 1;
        }
    }
    (count as u32, count)
}

/// Send one zero-parameter HCI command through the soft transport and poll
/// the runner to completion. Returns the Command Complete params after status.
fn hci_command(soft: &mut SoftRunner, opcode: u16) -> Option<[u8; 10]> {
    let mut bytes = [0u8; 3];
    bytes[..2].copy_from_slice(&opcode.to_le_bytes());
    bytes[2] = 0;
    let packet = Packet::from_bytes(bt_hci::transport::PacketKind::Cmd, &bytes).ok()?;
    transport::try_send_host_packet(packet).ok()?;

    let mut serve = core::pin::pin!(soft.serve_one());
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if serve.as_mut().poll(&mut cx).is_ready() {
            break;
        }
    }
    let reply = transport::try_receive_controller_packet()?;
    let payload = reply.payload();
    if payload.len() < 6 || payload[0] != 0x0e || payload[5] != 0 {
        return None;
    }
    let mut params = [0u8; 10];
    let n = core::cmp::min(10, payload.len() - 6);
    params[..n].copy_from_slice(&payload[6..6 + n]);
    Some(params)
}

#[entry]
fn main() -> ! {
    let p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    let mut out = Log;

    put(0, STATS_MAGIC);
    put(1, 1);
    put(2, 1);
    put(24, rcc::clocks().sysclk.0);
    let _ = writeln!(out, "entropy start sysclk={}", rcc::clocks().sysclk.0);

    let mut pool = EntropyPool::new();

    // Phase A: identical workload every round; the delta spread is jitter.
    let mut jitter = [0u32; JITTER_ROUNDS];
    let mut jitter_zero = 0u32;
    for sample in &mut jitter {
        let t0 = systick();
        for i in 0..9u32 {
            core::hint::black_box(i);
        }
        let t1 = systick();
        let delta = t1.wrapping_sub(t0);
        *sample = delta;
        if delta == 0 {
            jitter_zero += 1;
        }
        pool.add_sample(delta);
        pool.add_sample(t1);
    }
    let mut unique = [0u32; 128];
    let (jitter_distinct, _) = distinct(&jitter, &mut unique);
    let jitter_min = jitter.iter().copied().min().unwrap_or(0);
    let jitter_max = jitter.iter().copied().max().unwrap_or(0);
    let sum: u64 = jitter.iter().map(|&v| u64::from(v)).sum();
    let jitter_mean = (sum / JITTER_ROUNDS as u64) as u32;

    // Phase B: ADC temperature value plus conversion duration.
    let mut adc = Adc::new(p.ADC, AdcConfig::default());
    let mut temperature = adc.enable_temperature();
    let mut adc_errors = 0u32;
    let mut adc_values = [0u32; ADC_ROUNDS];
    let mut adc_ticks = [0u32; ADC_ROUNDS];
    let mut adc_count = 0usize;
    for _ in 0..ADC_ROUNDS {
        let t0 = systick();
        match adc.blocking_read(&mut temperature) {
            Ok(value) => {
                let t1 = systick();
                let ticks = t1.wrapping_sub(t0);
                adc_values[adc_count] = u32::from(value);
                adc_ticks[adc_count] = ticks;
                adc_count += 1;
                pool.add_sample(u32::from(value));
                pool.add_sample(ticks);
                pool.add_sample(t1);
            }
            Err(_) => adc_errors += 1,
        }
    }
    let adc_values = &adc_values[..adc_count];
    let adc_ticks = &adc_ticks[..adc_count];
    let adc_min = adc_values.iter().copied().min().unwrap_or(0);
    let adc_max = adc_values.iter().copied().max().unwrap_or(0);
    let adc_distinct = distinct(adc_values, &mut unique).0;
    let ticks_min = adc_ticks.iter().copied().min().unwrap_or(0);
    let ticks_max = adc_ticks.iter().copied().max().unwrap_or(0);
    let ticks_distinct = distinct(adc_ticks, &mut unique).0;

    put(2, 2);
    put(3, JITTER_ROUNDS as u32);
    put(4, jitter_min);
    put(5, jitter_max);
    put(6, jitter_distinct);
    put(7, jitter_mean);
    put(8, adc_count as u32);
    put(9, adc_min);
    put(10, adc_max);
    put(11, adc_distinct);
    put(12, ticks_min);
    put(13, ticks_max);
    put(14, ticks_distinct);
    put(23, adc_errors);
    put(25, jitter_zero);

    let _ = writeln!(
        out,
        "jitter n={} min={} max={} mean={} distinct={} zero={}",
        JITTER_ROUNDS, jitter_min, jitter_max, jitter_mean, jitter_distinct, jitter_zero
    );
    let _ = writeln!(
        out,
        "adc n={} min={} max={} distinct={} ticks={}/{}/{} err={}",
        adc_count, adc_min, adc_max, adc_distinct, ticks_min, ticks_max, ticks_distinct, adc_errors
    );
    // Refuse to seed from a stuck converter: enough samples, a nonzero range
    // and more than a couple of distinct low-byte values.
    let health = adc_count >= 64 && adc_max.wrapping_sub(adc_min) >= 2 && adc_distinct >= 4;
    let (raw_min, raw_max) = pool.raw_range().unwrap_or((0, 0));
    put(26, u32::from(health));
    put(27, raw_max.wrapping_sub(raw_min));
    let _ = writeln!(
        out,
        "health ok={} adc_range={} raw_range={}",
        health,
        adc_max.wrapping_sub(adc_min),
        raw_max.wrapping_sub(raw_min)
    );
    let _ = write!(out, "jitter first:");
    for value in &jitter[..8] {
        let _ = write!(out, " {}", value);
    }
    let _ = writeln!(out);
    // Full ADC sequence for offline entropy analysis (low-bit noise is where
    // any per-sample entropy would live); the log buffer has room for it.
    let _ = write!(out, "adc all:");
    for value in &adc_values[..core::cmp::min(ADC_LOG, adc_values.len())] {
        let _ = write!(out, " {}", value);
    }
    let _ = writeln!(out, " samples={}", pool.sample_count());

    let seed = pool.seed();
    put(15, u32::from_le_bytes([seed[0], seed[1], seed[2], seed[3]]));
    put(16, u32::from_le_bytes([seed[4], seed[5], seed[6], seed[7]]));
    let _ = writeln!(
        out,
        "seed {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        seed[0], seed[1], seed[2], seed[3], seed[4], seed[5], seed[6], seed[7]
    );

    let mut soft = SoftRunner::new();
    let seeded = health && soft.set_entropy_seed(&seed);
    put(2, 3);
    put(21, u32::from(seeded));
    let _ = writeln!(out, "drbg seeded={}", seeded);

    let mut rands = [[0u8; 8]; 2];
    for (index, rand) in rands.iter_mut().enumerate() {
        match hci_command(&mut soft, 0x2018) {
            Some(params) => {
                rand.copy_from_slice(&params[..8]);
                put(
                    17 + 2 * index,
                    u32::from_le_bytes([rand[0], rand[1], rand[2], rand[3]]),
                );
                put(
                    18 + 2 * index,
                    u32::from_le_bytes([rand[4], rand[5], rand[6], rand[7]]),
                );
                put(2, 4 + index as u32);
                let _ = writeln!(
                    out,
                    "le rand {} {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    index, rand[0], rand[1], rand[2], rand[3], rand[4], rand[5], rand[6], rand[7]
                );
            }
            None => {
                let _ = writeln!(out, "le rand {} failed", index);
            }
        }
    }

    put(22, u32::from(rands[0] != rands[1]));
    put(2, 9);
    let _ = writeln!(out, "entropy done");

    // RF was never initialized; park so probe reads never race a radio.
    loop {
        core::hint::spin_loop();
    }
}
