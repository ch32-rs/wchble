//! CH582/CH583 BLE RF backend. Legacy 1M was tested on CH582M.
//! Poll-driven: service completions with [`Ch583Radio::poll`].
//!
//! The active MMIO path uses the public ch32fun iSLER CH582/CH583 sequence.
//! The recorded DevInit tables below retain their original provenance and are
//! kept as reference values. See `LICENSE-ch32fun` for the iSLER license.
//!
//! Map (from `BLE_IPCoreInit` immediates + SFR):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21
//!
//! Tables are the CH5xx **"old tables"** bucket — closest to open V208 among
//! CH57/58/59.
//!
//! Certainty legend on table constants:
//! - [`Certainty::FromClosedDisasm`] — recovered from `objs_CH583`; not yet
//!   exercised on our hardware.
//! - [`Certainty::Unverified`] — shape known, value or side-effects unclear.

use core::cell::Cell;
use critical_section::Mutex;

use crate::rf::analog::{self, AnalogInit, CAL_TIMEOUT_US};
use crate::rf::family::tables::{BbDevInit, Certainty, LleDevInit, RegInit, RfendInit};
use crate::rf::isr::IsrState;
use crate::rf::regs::{self, autocfg, bb, lle, rssi};
use crate::rf::txrx::{tx_frame_valid, HalfUs, RX_DMA_MIN};
use crate::rf::{Channel, PhyMode, Radio, RfCallback, RfEvent};
use crate::time::InstantUs;
use crate::{Error, Result};

/// Baseband register block base.
pub const BB_BASE: usize = 0x4000_C100;
/// Link-layer engine base (BB + 0x100).
pub const LLE_BASE: usize = 0x4000_C200;
/// AES engine base (BB + 0x200).
pub const AES_BASE: usize = 0x4000_C300;
/// RF frontend / analog base (BB + 0xF00).
pub const RFEND_BASE: usize = 0x4000_D000;

/// BB interrupt number (`BLEB_IRQn`).
pub const IRQ_BB: u8 = 20;
/// LLE interrupt number (`BLEL_IRQn`).
pub const IRQ_LLE: u8 = 21;

use Certainty::FromClosedDisasm as Disasm;

/// `LLE_DevInit` absolute stores (disasm of `objs_CH583/lle.o`).
///
/// UNCERTAIN on silicon:
/// - Relocated store to `LLE+0x74` (RX buffer pointer) — needs live buffer addr.
/// - PFIC unmask at end of closed `LLE_DevInit` must stay in **HAL**, not here.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x8c, Disasm),
        RegInit::new(0x1c, 0x76, Disasm), // V208 open uses 0x6C — probe turnaround
        RegInit::new(0x24, 0x8c, Disasm),
        RegInit::new(0x2c, 0x3c, Disasm),
        RegInit::new(0x34, 0x8c, Disasm),
        RegInit::new(0x3c, 0x3c, Disasm),
        RegInit::new(0x44, 0x8c, Disasm),
        RegInit::new(0x4c, 0x76, Disasm), // V208 open uses 0x6C
        RegInit::new(0x08, 0xffff, Disasm),
        RegInit::new(0x0c, 0xf00f, Disasm),
    ],
    // Closed body does RMW on +0x04 (`andi -0x1f`); exact intent UNCERTAIN.
    crc_aa_cfg_clear_mask: Some(0xffff_ffe0),
};

/// `BB_DevInit` highlights (`objs_CH583/bb.o`).
///
/// UNCERTAIN on silicon:
/// - Power packing into `BB+0x2C` (reads a config byte at runtime).
/// - SYS writes around `0x40001040` / `0x40001022` in closed body — platform?
/// - PFIC unmask (IRQ 20) belongs in HAL.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x1d0, Disasm), // 464 — matches V208 open
    cfg20: Some(RegInit::new(0x20, 0x90083, Disasm)),
    irqstat: None,
    cfg3c: None,
    set_bit23: true,
    set_bit28: true,
    certainty: Disasm,
};

/// RFEND reset / WaitTune / VCO markers.
///
/// UNCERTAIN on silicon:
/// - Full `RFEND_DevInit` bit soup after `+0x28=0x480` (long sequence, not yet
///   transcribed into a store list).
/// - `TXCtune` band interpolation math (3-band; large function).
/// - Whether WaitTune countdown is hardware-decrement of `LLE+0x64` (assumed).
pub const RFEND_INIT: RfendInit = RfendInit {
    // Pulse `RFEND+0x0C = 0x1101` (same immediate class as V208 open `rf_reset`).
    reset_pulse: Some(RegInit::new(0x0c, 0x1101, Disasm)),
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    wait_tune_half_us: RegInit::new(0x64, 6000, Disasm), // loaded via LLE base
    vco_mhz: &[2401, 2440, 2480],
    certainty: Disasm,
};

const RF1: usize = 1;
const RF2: usize = 2;
const RF3: usize = 3;
const RF10: usize = 10;
const RF11: usize = 11;
const RF_TXTUNE_CTRL: usize = 14;
const RF20: usize = 20;
const RF22: usize = 22;
const RF_TXCTUNE_CO_CTRL: usize = 36;
const RF_TXCTUNE_GA_CTRL: usize = 37;
const RF_RXTUNE: usize = 39;
const RF_TXCTUNE_CO: usize = 40;
const RF_TXCTUNE_GA: usize = 50;

const DEVMODE_TUNE: u16 = 0xdd;
const DEVMODE_TX: u16 = 0xda;
const DEVMODE_RX: u16 = 0xd9;
const TX_POWER_0_DBM: u32 = 0x12;
const TX_SETTLE_US: u32 = 100;

const CHANNEL_MAP: [u8; 40] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 0, 11, 39,
];

#[inline(always)]
unsafe fn rf_r(i: usize) -> u32 {
    regs::read(RFEND_BASE, i * 4)
}
#[inline(always)]
unsafe fn rf_w(i: usize, v: u32) {
    regs::write(RFEND_BASE, i * 4, v)
}

unsafe fn set_mode(mode: u16) {
    if mode != 0 {
        regs::write(
            BB_BASE,
            bb::RFCTRL,
            (regs::read(BB_BASE, bb::RFCTRL) & 0xffff_fe7f) | 0x0000_0100,
        );
        rf_w(RF2, rf_r(RF2) | 0x0033_0000);
    } else {
        regs::write(
            BB_BASE,
            bb::RFCTRL,
            (regs::read(BB_BASE, bb::RFCTRL) & 0xffff_fe7f) | 0x0000_0080,
        );
        rf_w(RF2, rf_r(RF2) & 0xffcd_ffff);
    }
    let m = if mode == 0 { 0x80 } else { mode as u32 };
    regs::write(LLE_BASE, lle::MODE, m);
}

/// Synthesise one channel and return `(nGA << 24) | nCO`.
unsafe fn txctune(clock: &impl InstantUs, channel: u8) -> Result<u32> {
    rf_w(RF1, rf_r(RF1) & !1);
    let map = CHANNEL_MAP[channel as usize] as u32;
    rf_w(
        RF_TXTUNE_CTRL,
        (rf_r(RF_TXTUNE_CTRL) & 0xfffe_00ff) | (0xbf00 + (map << 8)),
    );
    rf_w(RF1, rf_r(RF1) | 1);

    // iSLER's CH582/CH583 tune loop polls both ready bits in RF36.
    analog::wait_tune(clock, LLE_BASE, RFEND_BASE, 8000)?;

    let n_co = rf_r(RF_TXCTUNE_CO_CTRL) & 0x3f;
    let n_ga = (rf_r(RF_TXCTUNE_GA_CTRL) >> 10) & 0x7f;
    Ok((n_ga << 24) | n_co)
}

unsafe fn tx_tune(clock: &impl InstantUs) -> Result<()> {
    rf_w(RF1, rf_r(RF1) & 0xffff_feff);
    rf_w(RF10, rf_r(RF10) & 0xffff_efff);
    rf_w(RF11, rf_r(RF11) & 0xffff_ffef);
    rf_w(RF2, rf_r(RF2) | 0x0002_0000);
    rf_w(RF1, rf_r(RF1) | 0x10);

    // Calibrate at both band edges and near the middle, then interpolate.
    let low = txctune(clock, 37)?;
    let high = txctune(clock, 39)?;
    let middle = txctune(clock, 18)?;

    let n_co = |t: u32| t & 0x3f;
    let n_ga = |t: u32| (t >> 24) & 0x7f;

    let d_co_0140 = n_co(low).wrapping_sub(n_co(middle));
    let d_co_4080 = n_co(middle).wrapping_sub(n_co(high));
    let points: u32 = 20;
    let mut co = [0u8; 40];
    let mut f = 0;
    while f < points {
        let tune = d_co_0140.wrapping_mul(points - f) / points;
        co[f as usize] = (tune | (tune << 4)) as u8;
        f += 1;
    }
    while f < 2 * points {
        let tune = d_co_4080.wrapping_mul(f - points) / points;
        co[f as usize] = (tune | (tune << 4)) as u8;
        f += 1;
    }
    for i in 0..10 {
        let b = i * 4;
        rf_w(
            RF_TXCTUNE_CO + i,
            u32::from_le_bytes([co[b], co[b + 1], co[b + 2], co[b + 3]]),
        );
    }

    // iSLER notes this GA interpolation is not what EVT does; it is kept for
    // parity with the reference implementation (a BLE monitor reads better
    // without it, but 1M advertising works either way).
    let d_ga_0140 = n_ga(low).wrapping_sub(n_ga(middle));
    let d_ga_4080 = n_ga(middle).wrapping_sub(n_ga(high));
    let points: u32 = 6;
    let mut ga = [0u8; 12];
    let mut f = 1;
    while f < points {
        let tune = d_ga_0140.wrapping_mul(points - f) / points;
        ga[f as usize] = (tune | (tune << 4)) as u8;
        f += 1;
    }
    while f < 2 * points - 1 {
        let tune = d_ga_4080.wrapping_mul(f - points) / points;
        ga[f as usize] = (tune | (tune << 4)) as u8;
        f += 1;
    }
    for i in 0..3 {
        let b = i * 4;
        rf_w(
            RF_TXCTUNE_GA + i,
            u32::from_le_bytes([ga[b], ga[b + 1], ga[b + 2], ga[b + 3]]),
        );
    }

    rf_w(RF1, rf_r(RF1) & !0x10);
    rf_w(RF1, rf_r(RF1) & !1);
    rf_w(RF10, rf_r(RF10) | 0x1000);
    rf_w(RF11, rf_r(RF11) | 0x10);
    rf_w(
        RF_TXTUNE_CTRL,
        (rf_r(RF_TXTUNE_CTRL) & 0xffff_ffc0) | (middle & 0x3f),
    );
    rf_w(
        RF_TXTUNE_CTRL,
        (rf_r(RF_TXTUNE_CTRL) & 0x80ff_ffff) | (middle & 0x7f00_0000),
    );
    rf_w(RF1, rf_r(RF1) | 0x100);
    Ok(())
}

unsafe fn rx_tune(clock: &impl InstantUs) -> Result<()> {
    rf_w(RF20, rf_r(RF20) & 0xfffe_ffff);
    rf_w(RF2, rf_r(RF2) | 0x0020_0000);
    rf_w(RF3, (rf_r(RF3) & !0x10) | 0x10);
    rf_w(RF1, rf_r(RF1) | 0x1000);

    regs::write(LLE_BASE, lle::WINDOW, 100);
    let started = clock.now_us();
    while regs::read(LLE_BASE, lle::WINDOW) != 0 && rf_r(RF_RXTUNE) & 0x100 != 0 {
        if clock.now_us().wrapping_sub(started) >= CAL_TIMEOUT_US {
            return Err(Error::Timeout);
        }
    }

    let filter = rf_r(RF_RXTUNE) & 0x1f;
    rf_w(RF20, rf_r(RF20) | 0x0001_0000);
    rf_w(RF20, (rf_r(RF20) & !0x1f) | filter);
    rf_w(RF2, rf_r(RF2) & !0x0020_0000);

    rf_w(RF22, rf_r(RF22) & !0x0001_0000);
    rf_w(RF2, rf_r(RF2) | 0x0001_0000);
    rf_w(RF3, (rf_r(RF3) & !0x100) | 0x100);
    rf_w(RF1, (rf_r(RF1) & !0x0001_0000) | 0x0010_0000);
    Ok(())
}

unsafe fn tune(clock: &impl InstantUs) -> Result<()> {
    set_mode(DEVMODE_TUNE);
    let result = tx_tune(clock).and_then(|()| rx_tune(clock));
    set_mode(0);
    result
}

/// CH582/CH583 LLE command bits and timer offset.
mod lle583 {
    pub const RX: u32 = 1;
    pub const TX: u32 = 2;
    pub const STOP: u32 = 8;
    pub const ACTIVE: u32 = RX | TX;
    /// LLE + 0x6c loads the RX window timer (TMR2) on this family.
    pub const TMR2: usize = super::lle::CALLOAD;
}

/// CH582/CH583 LLE `IRQSTAT` flags (W1C).
mod lle583_irq {
    pub const RX_DONE: u32 = 1;
    pub const TX_DONE: u32 = 2;
    pub const TMR2_EXPIRED: u32 = 1 << 15;
    pub const RX_EVENTS: u32 = RX_DONE | TMR2_EXPIRED;
    pub const TRANSFER: u32 = RX_EVENTS | TX_DONE;
}

// The CH584/585 DMA-footer convention also matched the CH582M CRCInit
// bench test: bit 4 of the fourth byte after the PDU reports failure.
// iSLER leaves this flag unimplemented for CH582/583.
const RX_CRC_ERROR: u8 = 1 << 4;
const RX_FOOTER: usize = 4;

static RADIO_TAKEN: Mutex<Cell<bool>> = Mutex::new(Cell::new(false));

/// Polling RF backend for the CH582/CH583 1M PHY.
pub struct Ch583Radio {
    scratch: &'static mut [u8],
    // The caller keeps this live through completion or cancellation. RXBUFPTR
    // always addresses scratch.
    rx_destination: Option<*mut u8>,
    isr: IsrState,
    channel: Channel,
    access: u32,
    crc_init: u32,
    phy_tx: PhyMode,
    phy_rx: PhyMode,
    whiten_disabled: bool,
    encrypt: bool,
    initialized: bool,
}

// Soft state only; MMIO runs through fixed bases.
unsafe impl Send for Ch583Radio {}

impl Ch583Radio {
    /// Claim the BLE engine once per boot. The firmware must keep the BLE IRQ
    /// masked for polling and avoid accessing the engine through another driver.
    pub fn new(scratch: &'static mut [u8]) -> Result<Self> {
        if scratch.len() < RX_DMA_MIN || (scratch.as_ptr() as usize) & 3 != 0 {
            return Err(Error::InvalidState);
        }
        if critical_section::with(|cs| RADIO_TAKEN.borrow(cs).replace(true)) {
            return Err(Error::Busy);
        }
        Ok(Self {
            scratch,
            rx_destination: None,
            isr: IsrState::default(),
            channel: 37,
            access: 0x8e89_bed6,
            crc_init: 0x55_5555,
            phy_tx: PhyMode::Rate1m,
            phy_rx: PhyMode::Rate1m,
            whiten_disabled: false,
            encrypt: false,
            initialized: false,
        })
    }

    fn check_mode(&self, phy: PhyMode) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidState);
        }
        if phy != PhyMode::Rate1m || self.whiten_disabled || self.encrypt {
            return Err(Error::Unsupported);
        }
        Ok(())
    }

    unsafe fn configure_1m(&self) {
        rf_w(RF11, rf_r(RF11) & !2);
        regs::rmw(
            BB_BASE,
            bb::RFCTRL,
            0xf07f,
            0x1000 | u32::from(self.channel),
        );
        regs::write(BB_BASE, bb::ACCESSADDR, self.access);
        regs::write(BB_BASE, bb::CRCINIT, self.crc_init);
        regs::write(BB_BASE, bb::RXCFG10, 0x0037_22d0);
        regs::write(BB_BASE, bb::RXCFG14, 0x0810_1901);
        regs::write(BB_BASE, bb::RXCFG18, 0x0003_1624);
        regs::write(BB_BASE, bb::RXCFG20, 0x0009_0083);
        regs::write(BB_BASE, bb::RXCFG24, 0x0100_6310);
        regs::write(BB_BASE, bb::RXCFG28, 0x28be);
        regs::rmw(LLE_BASE, lle::CRC_AA_CFG, 1, 0);
    }

    fn request_idle(&self) {
        unsafe {
            set_mode(0);
            let cmd = regs::read(LLE_BASE, lle::CMD);
            if cmd & lle583::ACTIVE != 0 {
                regs::rmw(LLE_BASE, lle::MODE, 7, 0);
                regs::write(LLE_BASE, lle::CMD, cmd | lle583::STOP);
            }
            regs::write(LLE_BASE, lle583::TMR2, 0);
        }
    }

    fn wait_idle(&self, clock: &impl InstantUs) -> bool {
        let start = clock.now_us();
        loop {
            if unsafe { regs::read(LLE_BASE, lle::CMD) } & lle583::ACTIVE == 0 {
                return true;
            }
            if clock.now_us().wrapping_sub(start) >= 50 {
                return false;
            }
        }
    }

    /// Cancel any pending transfer and confirm the engine has returned idle.
    pub fn stop(&mut self, clock: &impl InstantUs) -> bool {
        if !self.initialized {
            return true;
        }
        self.request_idle();
        if !self.wait_idle(clock) {
            return false;
        }
        self.rx_destination = None;
        self.isr.rx_crc_ok = false;
        self.isr.last_rx_len = 0;
        true
    }

    /// Process one latched RX completion or timeout, and return the event.
    ///
    /// The board must leave the BLE IRQ masked when polling, or ensure only one
    /// context owns this radio and acknowledges the LLE status register.
    pub fn poll(&mut self, clock: &impl InstantUs) -> Option<RfEvent> {
        let destination = self.rx_destination?;
        let status = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
        if status & lle583_irq::RX_EVENTS == 0 {
            return None;
        }
        self.rx_destination = None;
        let done = status & lle583_irq::RX_DONE != 0;
        if done {
            unsafe { regs::rmw(BB_BASE, bb::AUTOCFG, 0, autocfg::ARM_RX) };
        }
        self.request_idle();
        let idle = self.wait_idle(clock);
        unsafe { regs::write(LLE_BASE, lle::IRQSTAT, status & lle583_irq::TRANSFER) };
        self.isr.rx_crc_ok = false;
        let event = if !idle {
            RfEvent::HwErr
        } else if !done {
            RfEvent::RxTimeout
        } else {
            dma_fence();
            let len = 2 + usize::from(self.scratch[1]);
            let footer = &self.scratch[len..len + RX_FOOTER];
            self.isr.rx_crc_ok = footer[3] & RX_CRC_ERROR == 0;
            self.isr.last_rx_len = self.scratch[1];
            // SAFETY: rx_basic requires a live disjoint buffer of at least
            // RX_DMA_MIN bytes through completion, including this copy.
            unsafe {
                core::ptr::copy_nonoverlapping(self.scratch.as_ptr(), destination, len);
            }
            RfEvent::RxDone
        };
        self.isr.dispatch(event, status);
        Some(event)
    }
}

#[inline(always)]
fn dma_fence() {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
    #[cfg(not(target_arch = "riscv32"))]
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl AnalogInit for Ch583Radio {
    fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        unsafe { rf_w(RF10, 0x480) };
        Ok(())
    }

    fn calibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        if !self.stop(clock) {
            return Err(Error::Busy);
        }
        unsafe { tune(clock) }
    }
}

impl Radio for Ch583Radio {
    fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        if self.initialized {
            return Err(Error::InvalidState);
        }
        self.rfend_dev_init(clock)?;
        unsafe {
            regs::write(LLE_BASE, lle::GUARD, 0xf00f);
            regs::write(LLE_BASE, lle::RXBUFPTR, self.scratch.as_mut_ptr() as u32);
            regs::write(LLE_BASE, lle::IRQSTAT, u32::MAX);
            regs::rmw(BB_BASE, bb::RFCTRL, 0, 0x1080_0000);
            regs::write(BB_BASE, bb::CFG34, 0x1d0);
            regs::write(
                BB_BASE,
                bb::AUTOCFG,
                (TX_POWER_0_DBM << autocfg::CFG_SHIFT) | 0x8001_0e78,
            );
            regs::write(BB_BASE, bb::RXCFG20, 0x0009_0083);
        }
        self.calibrate(clock)?;
        unsafe { regs::write(LLE_BASE, lle::IRQSTAT, u32::MAX) };
        self.initialized = true;
        Ok(())
    }

    fn recalibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        self.check_mode(PhyMode::Rate1m)?;
        self.calibrate(clock)
    }

    fn shut(&mut self) {
        if self.initialized {
            self.request_idle();
        }
        self.rx_destination = None;
        self.isr.rx_crc_ok = false;
        self.isr.last_rx_len = 0;
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        if channel > 39 {
            return Err(Error::InvalidState);
        }
        self.channel = channel;
        Ok(())
    }

    fn channel(&self) -> Channel {
        self.channel
    }

    fn set_aa_crc(&mut self, access_address: u32, crc_init: u32) {
        self.access = access_address;
        self.crc_init = crc_init & 0x00ff_ffff;
    }

    fn set_phy(&mut self, tx: PhyMode, rx: PhyMode) {
        self.phy_tx = tx;
        self.phy_rx = rx;
    }

    fn set_whiten_disabled(&mut self, disabled: bool) {
        self.whiten_disabled = disabled;
    }

    fn set_encrypt(&mut self, enabled: bool) {
        self.encrypt = enabled;
    }

    fn set_callback(&mut self, cb: Option<RfCallback>) {
        self.isr.callback = cb;
    }

    /// For scheduled TX, the caller supplies a deadline with enough lead for
    /// radio setup and settling. The CH582M RF smoke uses 180 µs of lead.
    unsafe fn tx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        frame: &[u8],
        timeout_half_us: HalfUs,
        start_cputime: Option<u32>,
    ) -> Result<()> {
        self.check_mode(self.phy_tx)?;
        if !tx_frame_valid(frame) || timeout_half_us == 0 {
            return Err(Error::InvalidState);
        }
        if !self.stop(clock) {
            return Err(Error::Busy);
        }

        self.scratch[..frame.len()].copy_from_slice(frame);
        self.configure_1m();
        regs::write(LLE_BASE, lle::IRQSTAT, lle583_irq::TRANSFER);
        regs::write(LLE_BASE, lle::TXBUFPTR, self.scratch.as_mut_ptr() as u32);
        set_mode(DEVMODE_TX);

        if let Some(start) = start_cputime {
            loop {
                let elapsed = clock.now_us().wrapping_sub(start) as i32;
                if elapsed >= 0 {
                    if elapsed > 10 {
                        self.shut();
                        return Err(Error::Late);
                    }
                    break;
                }
            }
        } else {
            clock.delay_us(TX_SETTLE_US);
        }

        let started = clock.now_us();
        dma_fence();
        regs::rmw(BB_BASE, bb::RFCTRL, 0, 0x0080_0000);
        regs::rmw(BB_BASE, bb::AUTOCFG, autocfg::ARM_MASK, 0);
        regs::write(LLE_BASE, lle::CMD, lle583::TX);
        let timeout_us = timeout_half_us.div_ceil(2);
        loop {
            let status = regs::read(LLE_BASE, lle::IRQSTAT);
            if status & lle583_irq::TX_DONE != 0 {
                regs::write(LLE_BASE, lle::IRQSTAT, lle583_irq::TX_DONE);
                if !self.stop(clock) {
                    return Err(Error::Busy);
                }
                self.isr.dispatch(RfEvent::TxDone, status);
                return Ok(());
            }
            if clock.now_us().wrapping_sub(started) >= timeout_us {
                return Err(if self.stop(clock) {
                    Error::Timeout
                } else {
                    Error::Busy
                });
            }
        }
    }

    /// Completion is serviced by [`Ch583Radio::poll`], which copies the frame
    /// into `rxbuf` and dispatches the callback.
    unsafe fn rx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        rxbuf: &mut [u8],
        window_half_us: HalfUs,
    ) -> Result<()> {
        self.check_mode(self.phy_rx)?;
        if rxbuf.len() < RX_DMA_MIN || window_half_us == 0 {
            return Err(Error::InvalidState);
        }
        if !self.stop(clock) {
            return Err(Error::Busy);
        }
        self.rx_destination = Some(rxbuf.as_mut_ptr());
        self.isr.rx_crc_ok = false;
        self.configure_1m();
        regs::write(LLE_BASE, lle::IRQSTAT, lle583_irq::TRANSFER);
        regs::write(LLE_BASE, lle::RXBUFPTR, self.scratch.as_mut_ptr() as u32);
        regs::write(LLE_BASE, lle583::TMR2, window_half_us);
        set_mode(DEVMODE_RX);
        dma_fence();
        regs::write(LLE_BASE, lle::CMD, lle583::RX);
        Ok(())
    }

    fn rssi(&self) -> i8 {
        unsafe { (regs::read(BB_BASE, bb::RSSICFO) >> rssi::SHIFT) as u8 as i8 }
    }

    fn crc_ok(&self) -> bool {
        self.isr.rx_crc_ok
    }
}
