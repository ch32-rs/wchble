//! CH585 software-crypto timing benchmark.
//!
//! Measures the S0 crypto on the real core:
//! - AES-128 block encryption (chained, so it is a true dependency chain)
//! - AES-CCM encrypt/decrypt for a legacy 27-byte payload and a DLE 251-byte
//!   payload, with the 2-byte LL header as AAD and a 4-byte MIC
//! - ChaCha20 DRBG output (64 bytes)
//! - AES-128 key expansion
//!
//! The image never initializes RF, so the probe can read RAM at any time.
//! All timings are SysTick ticks; the runner converts with the reported
//! `sysclk_hz` (the HAL's measured clock, not the nominal 60 MHz).
//!
//! Console markers: `crypto bench start`, one line per phase, `crypto bench done`.

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::fmt::{self, Write};
use hal::rcc;
use hal::time::Hertz;
use qingke_rt::entry;
use wchble::crypto::aes::Aes128;
use wchble::crypto::ccm;
use wchble::rand::ChaCha20Drbg;
use {panic_halt as _, portable_atomic as _};

const AES_ITERS: u32 = 1000;
const KEY_ITERS: u32 = 1000;
const CCM27_ITERS: u32 = 500;
const CCM251_ITERS: u32 = 200;
const DRBG_ITERS: u32 = 1000;

#[no_mangle]
static mut LOG: [u8; 1024] = [0; 1024];

/// 0 magic, 1 version, 2 stage, 3 sysclk_hz,
/// 4 aes_iters, 5 aes_ticks, 6 key_iters, 7 key_ticks,
/// 8 ccm27_iters, 9 ccm27_ticks, 10 ccm251_iters, 11 ccm251_ticks,
/// 12 ccm251_dec_iters, 13 ccm251_dec_ticks, 14 drbg_iters, 15 drbg_ticks,
/// 16 aes_ticks_per_block, 17..31 reserved.
#[no_mangle]
static mut STATS: [u32; 32] = [0; 32];

const STATS_MAGIC: u32 = 0x4230_3538; // "B058"
const LOG_CAP: usize = 1024;
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

fn us(ticks: u32, hz: u32) -> u32 {
    ((u64::from(ticks) * 1_000_000) / u64::from(hz).max(1)) as u32
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    let mut out = Log;
    let hz = rcc::clocks().sysclk.0;

    put(0, STATS_MAGIC);
    put(1, 1);
    put(2, 1);
    put(3, hz);
    let _ = writeln!(out, "crypto bench start sysclk={}", hz);

    let key = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];
    let mut aes = Aes128::new(&key);

    // Key expansion.
    let t0 = systick();
    for i in 0..KEY_ITERS {
        aes = Aes128::new(core::hint::black_box(&key));
        core::hint::black_box(i);
    }
    let key_ticks = systick().wrapping_sub(t0);
    put(6, KEY_ITERS);
    put(7, key_ticks);
    let _ = writeln!(out, "key_expand n={} ticks={} us={}", KEY_ITERS, key_ticks, us(key_ticks / KEY_ITERS, hz));

    // AES-128 block, chained.
    let mut block = [0x5au8; 16];
    let t0 = systick();
    for i in 0..AES_ITERS {
        block[0] ^= i as u8;
        aes.encrypt_block(&mut block);
    }
    let aes_ticks = systick().wrapping_sub(t0);
    let aes_per = aes_ticks / AES_ITERS;
    core::hint::black_box(block);
    put(4, AES_ITERS);
    put(5, aes_ticks);
    put(16, aes_per);
    let _ = writeln!(
        out,
        "aes_block n={} ticks/block={} us/block={}",
        AES_ITERS,
        aes_per,
        us(aes_per, hz)
    );

    // AES-CCM encrypt: legacy 27-byte and DLE 251-byte payloads.
    let nonce = [0x42u8; 13];
    let aad = [0x03u8, 0x1b];
    let mut pt = [0xa5u8; 251];
    let mut ct = [0u8; 251];
    let mut mic = [0u8; 4];

    let t0 = systick();
    for i in 0..CCM27_ITERS {
        pt[0] = i as u8;
        let _ = ccm::encrypt::<4>(&aes, &nonce, &aad, &pt[..27], &mut ct[..27], &mut mic);
    }
    let ccm27_ticks = systick().wrapping_sub(t0);
    put(8, CCM27_ITERS);
    put(9, ccm27_ticks);
    let _ = writeln!(
        out,
        "ccm27 n={} ticks/op={} us/op={}",
        CCM27_ITERS,
        ccm27_ticks / CCM27_ITERS,
        us(ccm27_ticks / CCM27_ITERS, hz)
    );

    let t0 = systick();
    for i in 0..CCM251_ITERS {
        pt[0] = i as u8;
        let _ = ccm::encrypt::<4>(&aes, &nonce, &aad, &pt[..251], &mut ct[..251], &mut mic);
    }
    let ccm251_ticks = systick().wrapping_sub(t0);
    put(10, CCM251_ITERS);
    put(11, ccm251_ticks);
    let _ = writeln!(
        out,
        "ccm251 n={} ticks/op={} us/op={}",
        CCM251_ITERS,
        ccm251_ticks / CCM251_ITERS,
        us(ccm251_ticks / CCM251_ITERS, hz)
    );

    // AES-CCM decrypt of the 251-byte payload (RX cost).
    let t0 = systick();
    for _ in 0..CCM251_ITERS {
        let _ = ccm::decrypt::<4>(&aes, &nonce, &aad, &ct[..251], &mic, &mut pt[..251]);
    }
    let ccm251_dec_ticks = systick().wrapping_sub(t0);
    put(12, CCM251_ITERS);
    put(13, ccm251_dec_ticks);
    let _ = writeln!(
        out,
        "ccm251_dec n={} ticks/op={} us/op={}",
        CCM251_ITERS,
        ccm251_dec_ticks / CCM251_ITERS,
        us(ccm251_dec_ticks / CCM251_ITERS, hz)
    );

    // DRBG: 64 bytes per call.
    let mut drbg = ChaCha20Drbg::from_seed(&[0x5au8; 32]);
    let mut buf = [0u8; 64];
    let t0 = systick();
    for _ in 0..DRBG_ITERS {
        drbg.fill(&mut buf);
        core::hint::black_box(buf[0]);
    }
    let drbg_ticks = systick().wrapping_sub(t0);
    put(14, DRBG_ITERS);
    put(15, drbg_ticks);
    let _ = writeln!(
        out,
        "drbg64 n={} ticks/op={} us/op={}",
        DRBG_ITERS,
        drbg_ticks / DRBG_ITERS,
        us(drbg_ticks / DRBG_ITERS, hz)
    );

    put(2, 9);
    let _ = writeln!(out, "crypto bench done");
    loop {
        core::hint::spin_loop();
    }
}
