//! CH585 on-target RF verification — init, DevInit registers, ADV_NONCONN_IND TX, RX.
//!
//! HAL owns clocks / SysTick; `wchble` owns RF. Flash with
//! `wlink -d 1a86:8010:<SERIAL> flash <elf>` and then **power-cycle the
//! target** (`wlink -d <SERIAL> set-power disable3v3` / `enable3v3`, or replug
//! it): the Link's post-flash reset leaves the BLE block idle, so the
//! advertisement only appears after a real power cycle.
//!
//! The WCH-LinkE does not drain the debug data window on CH585 (`0xE000_0340`
//! reads `0xffff_ffff` from the probe side), so SDI print is unusable on this
//! die with the probes at hand. The example therefore mirrors its console into
//! a `#[no_mangle]` RAM buffer: the first four bytes hold the byte count, the
//! rest is UTF-8 text. Read it with `probe-rs` (`wlink dump` aliases CH585 RAM
//! reads to flash):
//!
//! ```text
//! probe-rs read --chip CH585 b32 <LOG address from nm> <words>
//! ```
//!
//! `probe-rs` leaves the core halted after it detaches, so power-cycle the
//! target again before watching it on air.
//!
//! Success markers:
//! - `rf init ok`
//! - `LLE …` / `RFEND …` / `BB …` (DevInit markers)
//! - `tx ch{37,38,39} ok`
//! - `rx listen hit|arm-clear` (arm path; a hit needs a nearby advertiser)
//! - `adv loop` (keeps ADV_NONCONN_IND and the RF_PHY reference frame on air)
//! - a macOS CoreBluetooth scan sees the local name `wch585`

#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::fmt::{self, Write};
use hal::rcc;
use hal::time::Hertz;
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::rf::family::ch585::{Ch585Radio, AES_BASE, BB_BASE, LLE_BASE, RFEND_BASE};
use wchble::rf::regs::{self, bb, lle, rfend};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, portable_atomic as _};

/// Advertising access address / CRC init (Core Vol 6 Part B).
const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;

/// LLE `IRQSTAT` bits the vendor treats as RX completion (bits 0 and 2 —
/// see `lleIrqHandler` / `ll_rx_wait_finish` in `ip.o`).
const RX_DONE: u32 = 0x1 | 0x4;
/// `IRQSTAT` bit 17: RX arm cleared / window expired.
const ARM_CLEAR: u32 = 0x2_0000;
/// BB `IRQSTAT` sticky CRC-fail latch, cleared by writing it back.
const BB_CRC_ERR: u32 = 0x20;

/// LLE DMAs through `RXBUFPTR`, so the scratch must be word-aligned.
static RX_DMA: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX_LISTEN: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();

/// RAM console for `wlink dump`.
///
/// Layout: little-endian `u32` byte count at `[0..4]`, UTF-8 text after it.
/// A message that would overflow restarts the buffer, so a dump always shows
/// the most recent, complete messages.
#[no_mangle]
static mut LOG: [u8; 2048] = [0; 2048];

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

/// Free-running µs clock on the HAL's SysTick timebase.
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

    fn ticks(&self) -> u32 {
        hal::pac::SYSTICK.cntl().read().cntl()
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

fn dump_regs(out: &mut Log) {
    let ctrl06 = unsafe { core::ptr::read_volatile((LLE_BASE + 0x06) as *const u16) };
    let _ = writeln!(
        out,
        "LLE 06={:x} 14={:x} 2c={:x} 3c={:x} 50={:x} 54={:x} 0c={:x}",
        ctrl06,
        mmio(LLE_BASE, 0x14),
        mmio(LLE_BASE, 0x2c),
        mmio(LLE_BASE, 0x3c),
        mmio(LLE_BASE, 0x50),
        mmio(LLE_BASE, 0x54),
        mmio(LLE_BASE, 0x0c),
    );
    let _ = writeln!(
        out,
        "RFEND 28={:x} 30={:x} 3c={:x} 44={:x}",
        mmio(RFEND_BASE, 0x28),
        mmio(RFEND_BASE, 0x30),
        mmio(RFEND_BASE, 0x3c),
        mmio(RFEND_BASE, rfend::SYNTH),
    );
    let _ = writeln!(
        out,
        "BB 00={:x} 10={:x} 2c={:x} 34={:x} 38={:x}",
        mmio(BB_BASE, 0x00),
        mmio(BB_BASE, 0x10),
        mmio(BB_BASE, 0x2c),
        mmio(BB_BASE, 0x34),
        mmio(BB_BASE, 0x38),
    );
}

/// Minimal ADV_NONCONN_IND: header + AdvA + flags + complete local name "wch585".
fn build_adv_nonconn_ind(out: &mut [u8; 32]) -> usize {
    let name = b"wch585";
    // Static random address C1:FF:EE:00:00:02, least-significant byte first.
    let adv_a = [0x02, 0x00, 0x00, 0xEE, 0xFF, 0xC1];
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

    // Random AdvA, non-connectable and non-scannable legacy advertising.
    out[0] = 0x42;
    out[1] = payload_len as u8;
    out[2..2 + payload_len].copy_from_slice(&buf[..payload_len]);
    2 + payload_len
}

fn tx_burst(radio: &mut Ch585Radio, clock: &UsClock, out: &mut Log, frame: &[u8]) {
    for &ch in &[37u8, 38, 39] {
        if let Err(e) = radio.set_channel(ch) {
            let _ = writeln!(out, "set_channel {} err {:?}", ch, e);
            continue;
        }
        for i in 0u32..2 {
            let t0 = clock.now_us();
            match radio.tx_basic(clock, frame, 0, None) {
                Ok(()) => {
                    let us = clock.now_us().wrapping_sub(t0);
                    let st = mmio(LLE_BASE, lle::IRQSTAT);
                    let win = mmio(LLE_BASE, lle::WINDOW);
                    let _ = writeln!(
                        out,
                        "tx ch{} ok us={} st={:x} win={:x} #{}",
                        ch, us, st, win, i
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "tx ch{} err {:?} #{}", ch, e, i);
                    dump_regs(out);
                }
            }
            clock.delay_us(10_000);
        }
    }
}

/// Arm RX for `window_half_us` and poll `IRQSTAT` (no NVIC needed).
///
/// Returns the decoded length and CRC result when a packet completed, or
/// `None` on arm-clear / timeout (which still proves the arm path works).
fn rx_once(
    radio: &mut Ch585Radio,
    clock: &UsClock,
    rxbuf: &mut [u8],
    ch: u8,
    window_half_us: u32,
) -> Option<(usize, bool)> {
    if radio.set_channel(ch).is_err() {
        return None;
    }
    // Clear the sticky CRC-fail latch before arming so the flag read after
    // RX_DONE belongs to this packet.
    unsafe { regs::write(BB_BASE, bb::IRQSTAT, BB_CRC_ERR) };
    if radio.rx_basic(clock, rxbuf, window_half_us).is_err() {
        return None;
    }

    let started = clock.now_us();
    let mut result = None;
    loop {
        let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
        if st & RX_DONE != 0 {
            let crc_ok = mmio(BB_BASE, bb::IRQSTAT) & BB_CRC_ERR == 0;
            result = Some((usize::from(rxbuf[1]), crc_ok));
            unsafe { regs::write(LLE_BASE, lle::IRQSTAT, RX_DONE) };
            break;
        }
        if st & ARM_CLEAR != 0 || mmio(LLE_BASE, lle::WINDOW) == 0 {
            unsafe { regs::write(LLE_BASE, lle::IRQSTAT, ARM_CLEAR) };
            break;
        }
        if clock.now_us().wrapping_sub(started) > 20_000 {
            break;
        }
    }
    radio.shut();
    result
}

fn rx_listen(
    radio: &mut Ch585Radio,
    clock: &UsClock,
    out: &mut Log,
    rxbuf: &mut [u8],
    window_half_us: u32,
) {
    let _ = writeln!(out, "rx round window={}", window_half_us);
    match rx_once(radio, clock, rxbuf, 38, window_half_us) {
        Some((len, crc_ok)) => {
            let _ = writeln!(out, "rx listen hit len={} crc={}", len, crc_ok);
        }
        None => {
            let _ = writeln!(out, "rx listen arm-clear");
        }
    }
}

/// Last trap state: `mcause`, `mepc`, `mtval`, `mstatus`.
///
/// Read it with `probe-rs read --chip CH585 b32 <address> 4`.
#[no_mangle]
static mut TRAP: [u32; 4] = [0; 4];

/// Bring-up hook: overrides qingke-rt's `ExceptionHandler` alias.
///
/// Records the trap CSRs into [`TRAP`] and parks; `wlink regs` cannot read the
/// GPRs on this die, but `probe-rs` reads the RAM copy.
#[no_mangle]
pub extern "C" fn ExceptionHandler() -> ! {
    let p = core::ptr::addr_of_mut!(TRAP).cast::<u32>();
    unsafe {
        core::arch::asm!(
            "csrr t1, mcause",
            "sw t1, 0(a0)",
            "csrr t1, mepc",
            "sw t1, 4(a0)",
            "csrr t1, mtval",
            "sw t1, 8(a0)",
            "csrr t1, mstatus",
            "sw t1, 12(a0)",
            "j .",
            in("a0") p,
            options(noreturn)
        )
    }
}

/// One-shot AES block KAT against the vendor `AES_DevAESEnc/Dec` sequence.
///
/// **Current status: negative.** The block is present and writable, but this
/// sequence does not produce AES output; the vendor LL uses the packet engine
/// `AES_DevPktEnc` instead. See `local-docs/research/ch585-aes-kat-results.md`.
/// Kept as a reproducible probe, not as a passing test.
///
/// The engine lives at [`AES_BASE`]. The vendor block writes `0x100` (then the
/// mode word) to `+0x00`, key to `+0x28..0x34`, input to `+0x18..0x24`, starts
/// through `+0x04` and polls `+0x04` bit 0.
#[cfg(feature = "aes-kat")]
fn le_word(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// AES-128 through the RF IP block, following the working ch32fun sequence
/// (`examples_ch5xx/aes/aes.c`): command `0x100`, mode, little-endian key and
/// data words, then `CFG |= 1` and poll `CFG` bit 0. The earlier probe used
/// big-endian words and a fixed delay, which cannot produce AES output.
#[cfg(feature = "aes-kat")]
fn aes_block(mode: u32, key: &[u8; 16], input: &[u8; 16], out: &mut [u8; 16]) -> bool {
    aes_block_step(true, true, mode, key, input, out)
}

/// One block with optional peripheral enable / mode / key loads, so repeated
/// blocks can measure where the per-block cost actually sits.
#[cfg(feature = "aes-kat")]
fn aes_block_step(
    enable: bool,
    load_key: bool,
    mode: u32,
    key: &[u8; 16],
    input: &[u8; 16],
    out: &mut [u8; 16],
) -> bool {
    unsafe {
        if enable {
            regs::write(AES_BASE, 0x00, 0x100);
            regs::write(AES_BASE, 0x00, mode);
        } else if load_key {
            regs::write(AES_BASE, 0x00, mode);
        }
        if load_key {
            for i in 0..4 {
                regs::write(AES_BASE, 0x28 + 4 * i, le_word(&key[4 * i..]));
            }
        }
        for i in 0..4 {
            regs::write(AES_BASE, 0x18 + 4 * i, le_word(&input[4 * i..]));
        }
        regs::write(AES_BASE, 0x00, regs::read(AES_BASE, 0x00) | 0x1);

        let mut spins = 0u32;
        while regs::read(AES_BASE, 0x00) & 0x1 != 0 {
            spins += 1;
            if spins > 200_000 {
                return false;
            }
            core::hint::spin_loop();
        }
        for i in 0..4 {
            let w = regs::read(AES_BASE, 0x18 + 4 * i);
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
    }
    true
}

#[cfg(feature = "aes-kat")]
fn write_hex(out: &mut Log, b: &[u8; 16]) {
    for byte in b {
        let _ = write!(out, "{:02x}", byte);
    }
}

#[cfg(feature = "aes-kat")]
fn aes_kat(out: &mut Log, clock: &UsClock) {
    let _ = writeln!(
        out,
        "aes kat start pre ctrl={:08x} st={:08x} key0={:08x}",
        mmio(AES_BASE, 0x00),
        mmio(AES_BASE, 0x04),
        mmio(AES_BASE, 0x28)
    );
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let pt = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let ct = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5,
        0x5a,
    ];
    let zero = [0u8; 16];
    let zero_ct = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];

    let mut got = [0u8; 16];
    let t0 = clock.now_us();
    if aes_block(0, &key, &pt, &mut got) {
        let dt = clock.now_us().wrapping_sub(t0);
        if got == ct {
            let _ = writeln!(out, "aes kat enc ok {}us", dt);
        } else {
            let _ = write!(out, "aes kat enc FAIL {}us got=", dt);
            write_hex(out, &got);
            let _ = writeln!(out);
        }
    } else {
        let dt = clock.now_us().wrapping_sub(t0);
        let _ = writeln!(
            out,
            "aes kat enc TIMEOUT {}us ctrl={:08x} st={:08x} o={:08x},{:08x},{:08x},{:08x}",
            dt,
            mmio(AES_BASE, 0x00),
            mmio(AES_BASE, 0x04),
            mmio(AES_BASE, 0x18),
            mmio(AES_BASE, 0x1c),
            mmio(AES_BASE, 0x20),
            mmio(AES_BASE, 0x24)
        );
    }

    if aes_block(0, &zero, &zero, &mut got) {
        if got == zero_ct {
            let _ = writeln!(out, "aes kat zero ok");
        } else {
            let _ = write!(out, "aes kat zero FAIL got=");
            write_hex(out, &got);
            let _ = writeln!(out);
        }
    } else {
        let _ = writeln!(out, "aes kat zero TIMEOUT");
    }

    if aes_block(2, &key, &ct, &mut got) {
        if got == pt {
            let _ = writeln!(out, "aes kat dec ok");
        } else {
            let _ = write!(out, "aes kat dec FAIL got=");
            write_hex(out, &got);
            let _ = writeln!(out);
        }
    } else {
        let _ = writeln!(out, "aes kat dec TIMEOUT");
    }

    // Repeated blocks: a BLE CCM operation needs several, and the per-block
    // command/key/data setup is part of the cost.
    let iters = 1000u32;
    let t0 = clock.now_us();
    for i in 0..iters {
        let mut block = pt;
        block[0] ^= i as u8;
        if !aes_block(0, &key, &block, &mut got) {
            let _ = writeln!(out, "aes kat loop TIMEOUT after {}", i);
            return;
        }
    }
    let dt = clock.now_us().wrapping_sub(t0);
    let _ = writeln!(
        out,
        "aes kat loop n={} us={} us/block={}",
        iters,
        dt,
        dt / iters
    );

    // Same loop without the 0x100 enable handshake per block.
    let t0 = clock.now_us();
    for i in 0..iters {
        let mut block = pt;
        block[0] ^= i as u8;
        if !aes_block_step(false, true, 0, &key, &block, &mut got) {
            let _ = writeln!(out, "aes kat loop-mk TIMEOUT after {}", i);
            return;
        }
    }
    let dt = clock.now_us().wrapping_sub(t0);
    let _ = writeln!(
        out,
        "aes kat loop-mode-key n={} us={} us/block={}",
        iters,
        dt,
        dt / iters
    );

    // Data + start + poll only: mode and key persist in the block.
    let t0 = clock.now_us();
    for i in 0..iters {
        let mut block = pt;
        block[0] ^= i as u8;
        if !aes_block_step(false, false, 0, &key, &block, &mut got) {
            let _ = writeln!(out, "aes kat loop-do TIMEOUT after {}", i);
            return;
        }
    }
    let dt = clock.now_us().wrapping_sub(t0);
    let _ = writeln!(
        out,
        "aes kat loop-data-only n={} us={} us/block={}",
        iters,
        dt,
        dt / iters
    );
}

#[entry]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());

    let mut out = Log;
    let _ = writeln!(
        out,
        "wchble ch585 rf-smoke sysclk={} measured={}",
        rcc::clocks().sysclk.0,
        hal::delay::measured_sysclk().0
    );

    let clock = UsClock::start();
    let rx_dma = RX_DMA.init(DmaBuf::zeroed());
    let rx_listen_buf = RX_LISTEN.init(DmaBuf::zeroed());

    let mut radio = match new_radio_with_dma(&mut rx_dma.0[..]) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(out, "radio new err {:?}", e);
            loop {}
        }
    };

    match radio.init(&clock) {
        Ok(()) => {
            let _ = writeln!(out, "rf init ok");
        }
        Err(e) => {
            let _ = writeln!(out, "rf init err {:?}", e);
            dump_regs(&mut out);
            loop {}
        }
    }

    #[cfg(feature = "aes-kat")]
    {
        // The AES block sits in the RF IP; keep its analog clock on while the
        // engine runs (no TX/RX is armed).
        unsafe {
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RF_ON);
        }
        // The vendor runs AES while the RF window is active; arm a long RX
        // window (1 s) so the block has its clock while the KAT runs.
        let _ = radio.set_channel(37);
        match radio.rx_basic(&clock, &mut rx_listen_buf.0[..], 2_000_000) {
            Ok(()) => {
                let _ = writeln!(out, "aes kat entered");
                aes_kat(&mut out, &clock);
                radio.shut();
            }
            Err(e) => {
                let _ = writeln!(out, "aes kat rx arm err {:?}", e);
            }
        }
        unsafe {
            regs::rmw(RFEND_BASE, rfend::FECTRL, rfend::FECTRL_RF_ON, 0);
        }
        // RF stays off; park so the probe read is safe.
        loop {
            core::hint::spin_loop();
        }
    }

    dump_regs(&mut out);
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);

    let mut frame = [0u8; 32];
    let n = build_adv_nonconn_ind(&mut frame);
    let _ = writeln!(out, "adv len {}", n);
    tx_burst(&mut radio, &clock, &mut out, &frame[..n]);
    for window_half_us in [2_000u32, 10_000] {
        rx_listen(
            &mut radio,
            &clock,
            &mut out,
            &mut rx_listen_buf.0[..],
            window_half_us,
        );
    }

    // Keep two signals on air for external observers:
    // - ADV_NONCONN_IND on 37/38/39 (real BLE AA/CRC) for a phone / Mac scanner;
    // - the CH585 SDK `RF_PHY` reference frame on channel 39 (AA 0x71764129 /
    //   CRC 0x555555) which a V208/CH592 reference receiver decodes.
    let _ = writeln!(out, "adv loop");
    let mut round = 0u32;
    loop {
        radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
        for &ch in &[37u8, 38, 39] {
            if radio.set_channel(ch).is_ok() {
                if let Err(e) = radio.tx_basic(&clock, &frame[..n], 0, None) {
                    let _ = writeln!(out, "adv tx ch{} err {:?}", ch, e);
                }
            }
            clock.delay_us(2_000);
        }

        radio.set_aa_crc(0x7176_4129, 0x55_5555);
        if radio.set_channel(39).is_ok() {
            let rf_frame = [0x00u8, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
            let _ = radio.tx_basic(&clock, &rf_frame, 0, None);
        }

        // Periodically prove the RX path on silicon while the loop runs.
        if round % 20 == 0 {
            radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);
            if let Some((len, crc_ok)) =
                rx_once(&mut radio, &clock, &mut rx_listen_buf.0[..], 37, 10_000)
            {
                let _ = writeln!(out, "rx loop hit len={} crc={}", len, crc_ok);
            }
        }

        round = round.wrapping_add(1);
        clock.delay_us(100_000);
    }
}
