//! CH32V208 BLE IP bases and open-driver radio backend.
//!
//! Absolute map (from open `wch_rf.h` / `docs/research/init-diff-table.md`):
//! - TOP   `0x4002_4000`
//! - BB    `0x4002_4100`
//! - LLE   `0x4002_4200`
//! - AES   `0x4002_4300`
//! - RFEND `0x4002_5000`
//! - MISC  `0x4002_2000`
//! - IRQs BB=63, LLE=64
//!
//! Relative from BB: LLE +0x100, AES +0x200, RFEND +0xF00.
//!
//! `init` / `calibrate` are a literal port of open `wch_rf{,_analog}.c`.
//! HAL must enable BLE AHB clock + HSE trim and leave BB/LLE IRQs disabled
//! before calling [`Radio::init`]. NVIC enable stays in the HAL.

use crate::rf::analog::{self, AnalogInit};
use crate::rf::family::tables::{self, BbDevInit, Certainty, LleDevInit, RegInit, RfendInit};
use crate::rf::isr::IsrState;
use crate::rf::regs::{
    self, autocfg, bb, bb_irq, lle, lle_cmd, lle_irq, lle_mode, rfctrl, rfend, rssi, rxcfg,
};
use crate::rf::timing::{self, v208_rx_capture_reload_half_us, v208_tx_window_half_us};
use crate::rf::txrx::RX_DMA_MIN;
use crate::rf::{Channel, PhyMode, Radio, RfCallback, RfEvent};
use crate::time::InstantUs;
use crate::{Error, Result};

use Certainty::VerifiedFromOpen as Open;

/// BLE IP top-level base (not the BB block).
pub const TOP_BASE: usize = 0x4002_4000;
/// Baseband register block base.
pub const BB_BASE: usize = 0x4002_4100;
/// Link-layer engine base (BB + 0x100).
pub const LLE_BASE: usize = 0x4002_4200;
/// AES engine base (BB + 0x200).
pub const AES_BASE: usize = 0x4002_4300;
/// RF frontend / analog base (BB + 0xF00).
pub const RFEND_BASE: usize = 0x4002_5000;
/// Misc / OSC-adjacent BLE region used by CTE and related bits.
pub const MISC_BASE: usize = 0x4002_2000;

/// BB interrupt number (`BB_IRQn`).
pub const IRQ_BB: u8 = 63;
/// LLE interrupt number (`LLE_IRQn`).
pub const IRQ_LLE: u8 = 64;

/// TXCtune band codes written to `RFEND+0x38[15:8]` (2401 / 2480 / 2440 order).
const TXCTUNE_BANDS: [u8; 3] = [0xbf, 0xe7, 0xd3];
/// Maps TXCtune loop index → sample slot {low, mid, high} = {0, 2, 1}.
const TXCTUNE_SAMPLE_INDEX: [usize; 3] = [0, 2, 1];

/// `LLE_DevInit` timeout baselines from open `wch_rf.c` (before RXBUFPTR).
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x8c, Open),
        RegInit::new(0x1c, 0x6c, Open),
        RegInit::new(0x24, 0x8c, Open),
        RegInit::new(0x2c, 0x3c, Open),
        RegInit::new(0x34, 0x8c, Open),
        RegInit::new(0x3c, 0x3c, Open),
        RegInit::new(0x44, 0x8c, Open),
        RegInit::new(0x4c, 0x6c, Open),
    ],
    crc_aa_cfg_clear_mask: None,
};

/// `BB_DevInit` highlights from open `wch_rf.c`.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x1d0, Open), // 464
    cfg20: Some(RegInit::new(0x20, 0x90083, Open)),
    irqstat: None, // open init clears to 0xF0 after cal — see Radio::init
    cfg3c: None,
    set_bit23: true,
    set_bit28: true,
    certainty: Open,
};

/// RFEND reset / WaitTune / VCO from open `wch_rf_analog.c`.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: Some(RegInit::new(0x0c, 0x1101, Open)),
    dev_init_0x28: RegInit::new(0x28, 0x480, Open),
    wait_tune_half_us: RegInit::new(0x64, 6000, Open),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Open,
};

/// CH32V208 radio — DevInit + calibration ported from open `wch_rf`.
#[derive(Debug)]
pub struct Ch32v208Radio {
    channel: Channel,
    phy_tx: PhyMode,
    phy_rx: PhyMode,
    whiten_disabled: bool,
    encrypt: bool,
    /// DTM demod variant (open `wch_rf_dtm_set`); affects RXCFG10 only.
    dtm: bool,
    access_address: u32,
    crc_init: u32,
    /// Last synth bookkeeping value (carrier − LO inject); channel mode does not
    /// program RFEND+0x44 on V208 open BLE path.
    synth_khz: u32,
    isr: IsrState,
    rx_dma: *mut u8,
    rx_dma_len: usize,
    /// Active RX DMA base (may differ from construction scratch during `rx_basic`).
    rx_active: *mut u8,
}

// Soft state only; MMIO runs through fixed bases. Safe to move across tasks.
unsafe impl Send for Ch32v208Radio {}

impl Ch32v208Radio {
    /// Build a radio that owns a DMA-capable RX scratch buffer.
    ///
    /// `rx_dma` must be at least [`RX_DMA_MIN`] bytes and 4-byte aligned. The HAL
    /// typically backs this with `StaticCell<[u8; RX_DMA_MIN]>` (or larger).
    pub fn new(rx_dma: &'static mut [u8]) -> Result<Self> {
        let ptr = rx_dma.as_mut_ptr();
        if rx_dma.len() < RX_DMA_MIN || (ptr as usize) & 0x3 != 0 {
            return Err(Error::InvalidState);
        }
        Ok(Self {
            channel: 0xff,
            phy_tx: PhyMode::Rate1m,
            phy_rx: PhyMode::Rate1m,
            whiten_disabled: false,
            encrypt: false,
            dtm: false,
            access_address: 0x8e89_bed6,
            crc_init: 0x55_5555,
            synth_khz: 0,
            isr: IsrState::default(),
            rx_dma: ptr,
            rx_dma_len: rx_dma.len(),
            rx_active: ptr,
        })
    }

    /// RX DMA scratch installed at construction.
    pub fn rx_dma_len(&self) -> usize {
        self.rx_dma_len
    }

    /// Last BB clock-capture timestamp (µs), valid after [`IsrState::rx_captured`].
    pub fn last_anchor_us(&self) -> u32 {
        self.isr.last_anchor_us
    }

    /// True after address match / clock-capture for the armed RX.
    pub fn rx_captured(&self) -> bool {
        self.isr.rx_captured
    }

    /// Select DTM demod CFG10 variant (open `wch_rf_dtm_set`).
    pub fn set_dtm(&mut self, enabled: bool) {
        self.dtm = enabled;
    }

    /// BB / LLE IRQ entry points for the HAL vector table (`BB_IRQn` / `LLE_IRQn`).
    pub fn lle_isr(&mut self) {
        let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
        let was_rx = self.isr.rx_armed;
        // Open passes os_cputime_get32() as the event payload. Without a clock in
        // this ISR entry, use last_anchor_us for RX_DONE after capture, else 0;
        // HAL may overwrite via InstantUs around the vector.

        if st & lle_irq::RX_DONE != 0 {
            let bb_st = unsafe { regs::read(BB_BASE, bb::IRQSTAT) };
            self.isr.rx_crc_ok = bb_st & bb_irq::CRC_ERR == 0;
            unsafe {
                regs::write(LLE_BASE, lle::IRQSTAT, lle_irq::RX_DONE);
            }
            if was_rx {
                let len = unsafe { core::ptr::read_volatile(self.rx_active.add(1)) };
                self.isr.last_rx_len = len;
                self.isr.rx_armed = false;
                let payload = if self.isr.rx_captured {
                    self.isr.last_anchor_us
                } else {
                    0
                };
                self.isr.dispatch(RfEvent::RxDone, payload);
            }
        }
        if st & lle_irq::TX_DONE != 0 {
            unsafe {
                regs::write(LLE_BASE, lle::IRQSTAT, lle_irq::TX_DONE);
            }
            self.isr.dispatch(RfEvent::TxDone, 0);
        }
        if st & lle_irq::CLEAR_ARM != 0 {
            unsafe {
                regs::write(LLE_BASE, lle::IRQSTAT, lle_irq::CLEAR_ARM);
            }
            if was_rx && st & lle_irq::RX_DONE == 0 {
                self.isr.rx_armed = false;
                self.isr.dispatch(RfEvent::RxTimeout, 0);
            }
        }
        unsafe {
            regs::write(LLE_BASE, lle::IRQSTAT, st & (0xffff & !0x2003));
        }
    }

    /// BB IRQ entry — clock-capture / address-match for basic RX.
    pub fn bb_isr(&mut self) {
        let st = unsafe { regs::read(BB_BASE, bb::IRQSTAT) };
        if st & bb_irq::CLKCAP != 0 {
            // HAL should prefer InstantUs; without a clock in ISR context we
            // leave last_anchor_us for the caller to overwrite, or keep prior.
            unsafe {
                regs::write(BB_BASE, bb::IRQSTAT, bb_irq::CLKCAP_CLR);
            }
            if self.isr.rx_armed && !self.isr.rx_captured {
                self.isr.rx_captured = true;
                let reload = v208_rx_capture_reload_half_us(self.phy_rx);
                unsafe {
                    regs::write(LLE_BASE, lle::WINDOW, reload);
                }
                self.isr
                    .dispatch(RfEvent::RxStart, self.isr.last_anchor_us);
            }
        }
        unsafe {
            regs::write(BB_BASE, bb::IRQSTAT, st & bb_irq::TIMER_ACK);
        }
    }

    /// Stamp the BB clock-capture time from the HAL's `InstantUs` (call at the
    /// start of `bb_isr` before or after [`Self::bb_isr`]).
    pub fn note_anchor_us(&mut self, now_us: u32) {
        self.isr.last_anchor_us = now_us;
    }

    fn lle_dev_init(&mut self) {
        // Open order: timeout baselines → RXBUFPTR → IRQSTAT → guard mask.
        unsafe {
            tables::apply_stores(LLE_BASE, LLE_DEV_INIT.stores);
            // Store the buffer *address*, never &pointer (open-driver warning).
            regs::write(LLE_BASE, lle::RXBUFPTR, self.rx_dma as u32);
            regs::write(LLE_BASE, lle::IRQSTAT, 0xffff);
            regs::write(LLE_BASE, lle::GUARD, 0xf00f);
        }
    }

    fn rf_reset<T: InstantUs>(&mut self, clock: &T) {
        let pulse = RFEND_INIT
            .reset_pulse
            .map(|r| r.value)
            .unwrap_or(rfend::CFG0C_RESET);
        unsafe {
            regs::write(RFEND_BASE, rfend::CFG0C, pulse);
            clock.delay_us(5);
            regs::write(RFEND_BASE, rfend::CFG0C, 0);
            clock.delay_us(5);
            regs::write(RFEND_BASE, rfend::CFG0C, pulse);
        }
    }

    /// Literal port of open `rf_dev_init` RMW soup (do not table-compress).
    fn rf_dev_init_rmw(&mut self) {
        unsafe {
            regs::write(RFEND_BASE, rfend::CFG28, RFEND_INIT.dev_init_0x28.value);

            // +0x48
            regs::rmw(RFEND_BASE, rfend::CFG48, !0x8fff_ffff, 0x2000_0000);
            regs::rmw(RFEND_BASE, rfend::CFG48, !0xf8ff_ffff, 0x0400_0000);
            regs::rmw(RFEND_BASE, rfend::CFG48, 0xf, 9);
            regs::rmw(RFEND_BASE, rfend::CFG48, !0xfff8_ffff, 0);
            regs::rmw(RFEND_BASE, rfend::CFG48, 0, 0x8000_0000);

            // +0x4C
            regs::rmw(RFEND_BASE, rfend::CFG4C, 7, 3);
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0x70, 0x30);
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0x700, 0x300);
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0x0100_0000, 0);
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0, 0x0200_0000);

            // +0x50 / +0x54
            regs::rmw(RFEND_BASE, rfend::CFG50, !0xffff_0fff, 0x4000);
            regs::rmw(RFEND_BASE, rfend::CFG54, 0xf, 0xc);
            regs::rmw(RFEND_BASE, rfend::CFG54, 0, 0x80);
            regs::rmw(RFEND_BASE, rfend::CFG54, 0x1000, 0);

            // +0x3C
            regs::rmw(RFEND_BASE, rfend::CFG3C, !0xffff_0fff, 0x8000);
            regs::rmw(RFEND_BASE, rfend::CFG3C, !0xf8ff_ffff, 0x0200_0000);
            regs::rmw(RFEND_BASE, rfend::CFG3C, !0x1fff_ffff, 0x4000_0000);

            // +0x2C
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0, 0x0070_0000);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, !0xf8ff_ffff, 0);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0x3000, 0x2000);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0x3_0000, 0x2_0000);

            // +0x30
            regs::rmw(RFEND_BASE, rfend::CFG30, 0xf, 0);
            regs::rmw(RFEND_BASE, rfend::CFG30, 0xf0, 0);
            regs::rmw(RFEND_BASE, rfend::CFG30, 0x700, 0);
            regs::rmw(RFEND_BASE, rfend::CFG30, 0, 0x0070_0000);
            regs::rmw(RFEND_BASE, rfend::CFG30, !0x8fff_ffff, 0x5000_0000);

            // +0x38
            regs::rmw(RFEND_BASE, rfend::CFG38, !0xff07_ffff, 0x0010_0000);
            regs::rmw(RFEND_BASE, rfend::CFG38, 0, 0x8000_0000);
        }
    }

    fn bb_dev_init(&mut self) {
        unsafe {
            if BB_DEV_INIT.set_bit23 {
                regs::rmw(BB_BASE, bb::RFCTRL, 0, rfctrl::TX_TRIG);
            }
            if BB_DEV_INIT.set_bit28 {
                regs::rmw(BB_BASE, bb::RFCTRL, 0, rfctrl::INIT_BIT28);
            }
            regs::write(BB_BASE, bb::CFG34, BB_DEV_INIT.cfg34.value);

            // Open bb_dev_init AUTOCFG pack (TX power enum 9 = 0 dBm).
            let cfg = autocfg::TX_POWER_0DBM;
            let mut v = (cfg << autocfg::CFG_SHIFT) | autocfg::INIT_LO;
            v &= autocfg::CFG_MASK;
            v |= (cfg & 0x3f) << autocfg::CFG_SHIFT;
            regs::write(BB_BASE, bb::AUTOCFG, v);

            if let Some(cfg20) = BB_DEV_INIT.cfg20 {
                regs::write(BB_BASE, bb::RXCFG20, cfg20.value);
            }
        }
    }

    fn rf_txctune<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        let wait = RFEND_INIT.wait_tune_half_us.value;
        let mut co = [0u8; 3];
        let mut ga = [0u8; 3];

        unsafe {
            regs::rmw(RFEND_BASE, rfend::TUNE, 0x100, 0);
            regs::rmw(RFEND_BASE, rfend::CFG28, 0x1000, 0);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0x10, 0);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, 0x2_0000);
            regs::rmw(RFEND_BASE, rfend::TUNE, 0, rfend::TUNE_FILT);

            // Open: (RF(0x38) & 0xfffe00ff) | (band << 8) → clear bits[16:8].
            for (i, &band) in TXCTUNE_BANDS.iter().enumerate() {
                let sample = TXCTUNE_SAMPLE_INDEX[i];
                regs::rmw(RFEND_BASE, rfend::TUNE, rfend::TUNE_TRIG, 0);
                regs::rmw(
                    RFEND_BASE,
                    rfend::CFG38,
                    !rfend::BANDCODE_MASK,
                    (u32::from(band)) << rfend::BANDCODE_SHIFT,
                );
                regs::rmw(RFEND_BASE, rfend::TUNE, 0, rfend::TUNE_TRIG);
                if analog::wait_tune(clock, LLE_BASE, RFEND_BASE, wait).is_err() {
                    regs::rmw(RFEND_BASE, rfend::TUNE, 0x11, 0);
                    regs::rmw(RFEND_BASE, rfend::CFG28, 0, 0x1000);
                    regs::rmw(RFEND_BASE, rfend::FREQMODE, 0, 0x10);
                    return Err(Error::Timeout);
                }
                co[sample] = (regs::read(RFEND_BASE, rfend::TUNE_CO) & rfend::TUNE_CO_MASK) as u8;
                ga[sample] = ((regs::read(RFEND_BASE, rfend::TUNE_GA) >> rfend::TUNE_GA_SHIFT)
                    & rfend::TUNE_GA_MASK) as u8;
            }

            let co_low = i32::from(co[0]) - i32::from(co[1]);
            let co_high = i32::from(co[1]) - i32::from(co[2]);
            let ga_low = i32::from(ga[0]) - i32::from(ga[1]);
            let ga_high = i32::from(ga[1]) - i32::from(ga[2]);

            for i in 0..40usize {
                analog::nibble_write(
                    RFEND_BASE,
                    rfend::VCOTAB,
                    i,
                    co_low * (39 - i as i32) / 39,
                );
            }
            for i in 1..=42usize {
                analog::nibble_write(
                    RFEND_BASE,
                    rfend::VCOTAB,
                    39 + i,
                    co_high * i as i32 / 40,
                );
            }
            for i in 0..10usize {
                analog::nibble_write(
                    RFEND_BASE,
                    rfend::VCOTAB_GA,
                    2 + i,
                    analog::tune_div(ga_high * (10 - i as i32), co_high) | 8,
                );
            }
            analog::nibble_write(RFEND_BASE, rfend::VCOTAB_GA, 12, 0);
            for i in 1..=10usize {
                analog::nibble_write(
                    RFEND_BASE,
                    rfend::VCOTAB_GA,
                    12 + i,
                    analog::tune_div(ga_low * i as i32, co_low),
                );
            }

            regs::rmw(RFEND_BASE, rfend::TUNE, rfend::TUNE_FILT, 0);
            regs::rmw(RFEND_BASE, rfend::TUNE, rfend::TUNE_TRIG, 0);
            regs::rmw(RFEND_BASE, rfend::CFG28, 0, 0x1000);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0, 0x10);
            regs::rmw(RFEND_BASE, rfend::CFG38, 0x3f, u32::from(co[1]));
            // Open: (RF(0x38) & 0x80ffffff) | (ga_mid << 24)
            regs::rmw(RFEND_BASE, rfend::CFG38, 0x7f00_0000, u32::from(ga[1]) << 24);
        }
        Ok(())
    }

    fn rf_rxfilter<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        unsafe {
            regs::rmw(RFEND_BASE, rfend::CFG50, rfend::CFG50_FILT_EN, 0);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RXFILT);
            regs::rmw(RFEND_BASE, rfend::CFG0C, 0, rfend::CFG0C_FILT_TOGGLE);
            regs::rmw(RFEND_BASE, rfend::CFG0C, rfend::CFG0C_FILT_TOGGLE, 0);
            analog::settle(clock);
            regs::rmw(RFEND_BASE, rfend::CFG0C, 0, rfend::CFG0C_FILT_TOGGLE);
            regs::rmw(RFEND_BASE, rfend::TUNE, 0, 0x1000);
            regs::write(LLE_BASE, lle::WINDOW, 80);

            let started = clock.now_us();
            loop {
                let now = clock.now_us();
                let st = regs::read(RFEND_BASE, rfend::FILTMEAS);
                if st & rfend::FILTMEAS_RDY != 0 {
                    break;
                }
                if regs::read(LLE_BASE, lle::WINDOW) == 0 {
                    break; // open: bounded fallback still applies result
                }
                if now.wrapping_sub(started) >= analog::CAL_TIMEOUT_US {
                    regs::rmw(RFEND_BASE, rfend::FECTRL, rfend::FECTRL_RXFILT, 0);
                    return Err(Error::Timeout);
                }
            }

            analog::settle(clock);
            let result = regs::read(RFEND_BASE, rfend::FILTMEAS);
            regs::rmw(RFEND_BASE, rfend::CFG50, 0, rfend::CFG50_FILT_EN);
            regs::rmw(
                RFEND_BASE,
                rfend::CFG50,
                rfend::FILTMEAS_MASK,
                result & rfend::FILTMEAS_MASK,
            );
            regs::rmw(RFEND_BASE, rfend::FECTRL, rfend::FECTRL_RXFILT, 0);
        }
        Ok(())
    }

    fn rf_rxadc(&mut self) {
        unsafe {
            regs::rmw(RFEND_BASE, rfend::CFG58, rfend::FECTRL_RXADC, 0);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RXADC);
            regs::rmw(RFEND_BASE, rfend::CFG0C, rfend::CFG0C_RXADC, 0);
            regs::rmw(RFEND_BASE, rfend::TUNE, rfend::TUNE_RXADC, 0);
            regs::rmw(RFEND_BASE, rfend::CFG0C, 0, rfend::CFG0C_RXADC);
            regs::rmw(RFEND_BASE, rfend::TUNE, 0, rfend::TUNE_RXADC);
        }
    }

    fn guard_enter(&mut self) -> u32 {
        let saved = unsafe { regs::read(LLE_BASE, lle::GUARD) };
        unsafe {
            regs::write(LLE_BASE, lle::GUARD, 0);
        }
        analog::fence_i();
        saved
    }

    fn guard_exit(&mut self, saved: u32) {
        analog::fence_i();
        unsafe {
            regs::write(LLE_BASE, lle::GUARD, saved);
        }
        analog::fence_i();
    }

    /// Open `engine_stop` / `phy_status_clear`.
    fn engine_stop(&mut self) {
        unsafe {
            regs::rmw(LLE_BASE, lle::MODE, lle_mode::DIR_MASK, 0);
            regs::rmw(LLE_BASE, lle::CMD, 0, lle_cmd::FORCE_STOP);
            regs::write(LLE_BASE, lle::WINDOW, 0);
        }
    }

    /// Open `dev_set_channel` — BLE channel-number mode (no RFEND+0x44 synth).
    fn program_channel(&mut self, channel: Channel, phy: PhyMode) {
        let whiten = if self.whiten_disabled {
            rfctrl::WHITEN_OFF
        } else {
            0
        };
        unsafe {
            regs::rmw(RFEND_BASE, rfend::FREQMODE, rfend::FREQMODE_EN, 0);
            let rfctrl_v = regs::read(BB_BASE, bb::RFCTRL);
            let v = (rfctrl_v & !(rfctrl::CH_MASK | rfctrl::WHITEN_OFF))
                | (u32::from(channel) & rfctrl::CH_MASK)
                | whiten;
            regs::write(BB_BASE, bb::RFCTRL, v);
        }
        self.channel = channel;
        self.synth_khz =
            timing::freq_for_channel_khz(channel).saturating_sub(u32::from(timing::lo_inject_khz(phy)));
    }

    fn phy_bits_tx(mode: PhyMode) -> u32 {
        match mode {
            PhyMode::Rate2m => rfctrl::PHY_2M,
            PhyMode::RateCodedS8 => rfctrl::PHY_CODED,
            PhyMode::RateCodedS2 => rfctrl::PHY_CODED | rfctrl::PHY_S2,
            PhyMode::Rate1m => rfctrl::PHY_1M,
        }
    }

    fn phy_bits_rx(mode: PhyMode) -> u32 {
        match mode {
            PhyMode::Rate2m => rfctrl::PHY_2M,
            PhyMode::RateCodedS2 | PhyMode::RateCodedS8 => rfctrl::PHY_CODED,
            PhyMode::Rate1m => rfctrl::PHY_1M,
        }
    }

    fn phy_is_coded(mode: PhyMode) -> bool {
        matches!(mode, PhyMode::RateCodedS2 | PhyMode::RateCodedS8)
    }

    /// Open `set_phy_tx_mode` — programs RFCTRL PHY bits + LLE TX window.
    fn set_phy_tx_mode_timed<T: InstantUs>(&mut self, clock: &T, mode: PhyMode, payload_len: u8) {
        let mut mask = rfctrl::PHY_MASK;
        if Self::phy_is_coded(mode) {
            mask |= rfctrl::CODING_MASK;
        }
        let saved_guard;
        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, mask, Self::phy_bits_tx(mode));
            saved_guard = regs::read(LLE_BASE, lle::GUARD);
            regs::write(LLE_BASE, lle::GUARD, saved_guard & !0x2000);
        }
        clock.delay_us(2);
        unsafe {
            regs::write(LLE_BASE, lle::IRQSTAT, lle_irq::CLEAR_ARM);
            regs::write(
                LLE_BASE,
                lle::WINDOW,
                v208_tx_window_half_us(mode, payload_len),
            );
            regs::write(LLE_BASE, lle::GUARD, saved_guard);
        }
    }

    /// Open `set_phy_rx_mode` — demod CFG group + RFCTRL PHY bits.
    fn set_phy_rx_mode(&mut self, mode: PhyMode) {
        unsafe {
            if Self::phy_is_coded(mode) {
                regs::rmw(
                    BB_BASE,
                    bb::RFCTRL,
                    rfctrl::PHY_MASK,
                    Self::phy_bits_rx(mode),
                );
                regs::write(BB_BASE, bb::RXCFG20, rxcfg::CFG20_CODED);
                regs::write(BB_BASE, bb::RXCFG14, rxcfg::CFG14_CODED);
                regs::write(BB_BASE, bb::RXCFG18, rxcfg::CFG18_CODED);
                regs::write(BB_BASE, bb::RXCFG28, rxcfg::CFG28_CODED);
                regs::write(BB_BASE, bb::RXCFG24, rxcfg::CFG24_CODED);
                regs::write(
                    BB_BASE,
                    bb::RXCFG10,
                    if self.dtm {
                        rxcfg::CFG10_CODED_DTM
                    } else {
                        rxcfg::CFG10_CODED
                    },
                );
            } else {
                regs::write(BB_BASE, bb::RXCFG20, rxcfg::CFG20_1M2M);
                regs::write(BB_BASE, bb::RXCFG14, rxcfg::CFG14_1M2M);
                regs::write(BB_BASE, bb::RXCFG18, rxcfg::CFG18_1M2M);
                regs::rmw(
                    BB_BASE,
                    bb::RFCTRL,
                    rfctrl::PHY_MASK,
                    Self::phy_bits_rx(mode),
                );
                regs::write(BB_BASE, bb::RXCFG28, rxcfg::CFG28_1M2M);
                regs::write(BB_BASE, bb::RXCFG24, rxcfg::CFG24_1M2M);
                regs::write(
                    BB_BASE,
                    bb::RXCFG10,
                    if self.dtm {
                        rxcfg::CFG10_1M2M_DTM
                    } else {
                        rxcfg::CFG10_1M2M
                    },
                );
            }
        }
    }

    fn apply_aa_crc_regs(&self) {
        unsafe {
            regs::write(BB_BASE, bb::ACCESSADDR, self.access_address);
            regs::write(BB_BASE, bb::CRCINIT, self.crc_init & 0x00ff_ffff);
            regs::rmw(LLE_BASE, lle::CRC_AA_CFG, 0x1, 0);
        }
    }
}

impl AnalogInit for Ch32v208Radio {
    fn rfend_dev_init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        self.rf_reset(clock);
        self.rf_dev_init_rmw();
        Ok(())
    }

    fn calibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        // Port of wch_rf_analog_init. Always restore guard / clear MODE+WINDOW.
        let saved_mask = unsafe { regs::read(LLE_BASE, lle::GUARD) };
        let mut result = Ok(());

        unsafe {
            regs::write(LLE_BASE, lle::GUARD, 0);
        }
        analog::fence_i();

        unsafe {
            // Force 1M + DIR_RX pattern; RF on; cal MODE word at +0x50.
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::PHY_MASK, rfctrl::PHY_1M);
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, 0);
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, rfctrl::DIR_RX);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RF_ON);
            regs::write(LLE_BASE, lle::MODE, lle_mode::CAL);
        }

        if let Err(e) = self.rf_txctune(clock) {
            result = Err(e);
        } else {
            unsafe {
                regs::rmw(RFEND_BASE, rfend::TUNE, 0, rfend::TUNE_TXFTUNE);
            }
            if let Err(e) = self.rf_rxfilter(clock) {
                result = Err(e);
            } else {
                self.rf_rxadc();
            }
        }

        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, rfctrl::SHUT);
            let fectrl = regs::read(RFEND_BASE, rfend::FECTRL);
            regs::write(RFEND_BASE, rfend::FECTRL, fectrl & rfend::FECTRL_SHUT_MASK);
            regs::write(LLE_BASE, lle::MODE, 0);
            regs::write(LLE_BASE, lle::WINDOW, 0);
        }
        analog::fence_i();
        unsafe {
            regs::write(LLE_BASE, lle::GUARD, saved_mask);
        }

        result
    }
}

impl Radio for Ch32v208Radio {
    fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        // Golden wch_rf_init order (RCC / HSE / NVIC stay in ch32-hal):
        //   LLE_DevInit → RFEND_DevInit → BB_DevInit → cal → IRQSTAT clear
        self.lle_dev_init();
        self.rfend_dev_init(clock)?;
        self.bb_dev_init();
        self.calibrate(clock)?;

        self.channel = 0xff;
        self.isr.clear_rx_flags();
        self.rx_active = self.rx_dma;
        unsafe {
            regs::write(BB_BASE, bb::IRQSTAT, bb_irq::POST_INIT_CLR);
            regs::write(LLE_BASE, lle::IRQSTAT, 0xffff);
            regs::write(LLE_BASE, lle::RXBUFPTR, self.rx_dma as u32);
        }
        let _ = (IRQ_BB, IRQ_LLE);
        Ok(())
    }

    fn recalibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        let busy = unsafe { regs::read(LLE_BASE, lle::CMD) & lle_cmd::BUSY_MASK };
        if busy != 0 {
            return Err(Error::Busy);
        }
        self.calibrate(clock)
    }

    fn shut(&mut self) {
        let saved = self.guard_enter();
        self.engine_stop();
        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, rfctrl::SHUT);
            let fectrl = regs::read(RFEND_BASE, rfend::FECTRL);
            regs::write(RFEND_BASE, rfend::FECTRL, fectrl & rfend::FECTRL_SHUT_MASK);
            regs::write(LLE_BASE, lle::MODE, 0);
        }
        self.isr.clear_rx_flags();
        self.guard_exit(saved);
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        if channel > 39 {
            return Err(Error::InvalidState);
        }
        let saved = self.guard_enter();
        self.program_channel(channel, self.phy_rx);
        self.guard_exit(saved);
        Ok(())
    }

    fn channel(&self) -> Channel {
        self.channel
    }

    fn set_aa_crc(&mut self, access_address: u32, crc_init: u32) {
        self.access_address = access_address;
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

    fn tx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        frame: &[u8],
        _timeout_half_us: u32,
        start_cputime: Option<u32>,
    ) -> Result<()> {
        if frame.len() < 2 {
            return Err(Error::InvalidState);
        }
        if self.channel > 39 {
            return Err(Error::InvalidState);
        }
        let busy = unsafe { regs::read(LLE_BASE, lle::CMD) & lle_cmd::BUSY_MASK };
        if busy != 0 {
            return Err(Error::Busy);
        }

        let saved = self.guard_enter();
        self.engine_stop();
        unsafe {
            regs::write(LLE_BASE, lle::WINDOW, 0);
            regs::write(LLE_BASE, lle::IRQSTAT, lle_irq::CLEAR_ARM);
        }

        self.program_channel(self.channel, self.phy_tx);

        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, rfctrl::DIR_RX);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RF_ON);
            regs::write(LLE_BASE, lle::MODE, lle_mode::TX);
        }
        self.apply_aa_crc_regs();

        // TX buffer pointer — frame must remain valid for the airtime.
        unsafe {
            regs::write(LLE_BASE, lle::TXBUFPTR, frame.as_ptr() as u32);
        }

        self.set_phy_tx_mode_timed(clock, self.phy_tx, frame[1]);
        let hw_window = unsafe { regs::read(LLE_BASE, lle::WINDOW) };

        if let Some(start) = start_cputime {
            unsafe {
                regs::write(LLE_BASE, lle::WINDOW, 0);
            }
            loop {
                let now = clock.now_us();
                if now.wrapping_sub(start) as i32 >= 0 {
                    if now.wrapping_sub(start) > 10 {
                        self.guard_exit(saved);
                        return Err(Error::Late);
                    }
                    break;
                }
            }
            unsafe {
                regs::write(LLE_BASE, lle::WINDOW, hw_window);
            }
        }

        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, 0, rfctrl::TX_TRIG);
            regs::rmw(BB_BASE, bb::AUTOCFG, autocfg::ARM_MASK, 0);
        }
        let started = clock.now_us();
        unsafe {
            regs::write(LLE_BASE, lle::CMD, lle_cmd::START_TX);
        }

        let deadline = started.wrapping_add(hw_window / 2).wrapping_add(200);
        let mut rc = Ok(());
        loop {
            let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
            if st & lle_irq::TX_DONE != 0 {
                break;
            }
            if clock.now_us().wrapping_sub(deadline) as i32 >= 0 {
                let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
                if st & lle_irq::TX_DONE == 0 {
                    rc = Err(Error::Timeout);
                }
                break;
            }
        }

        self.guard_exit(saved);
        rc
    }

    fn rx_basic<T: InstantUs>(
        &mut self,
        _clock: &T,
        rxbuf: &mut [u8],
        window_half_us: u32,
    ) -> Result<()> {
        if rxbuf.len() < RX_DMA_MIN {
            return Err(Error::InvalidState);
        }
        if self.channel > 39 {
            return Err(Error::InvalidState);
        }

        let saved = self.guard_enter();

        let busy = unsafe { regs::read(LLE_BASE, lle::CMD) & lle_cmd::BUSY_MASK };
        if busy != 0 {
            unsafe {
                regs::rmw(LLE_BASE, lle::MODE, lle_mode::DIR_MASK, 0);
                regs::rmw(LLE_BASE, lle::CMD, 0, lle_cmd::FORCE_STOP);
            }
        }

        unsafe {
            regs::write(LLE_BASE, lle::WINDOW, 0);
            regs::write(LLE_BASE, lle::IRQSTAT, lle_irq::CLEAR_ARM);
        }

        self.program_channel(self.channel, self.phy_rx);
        self.set_phy_rx_mode(self.phy_rx);
        self.apply_aa_crc_regs();

        let rx_ptr = rxbuf.as_mut_ptr();
        self.rx_active = rx_ptr;
        unsafe {
            regs::write(LLE_BASE, lle::RXBUFPTR, rx_ptr as u32);
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, rfctrl::DIR_RX);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RF_ON);
            regs::write(LLE_BASE, lle::MODE, lle_mode::RX);
            regs::write(LLE_BASE, lle::WINDOW, window_half_us);
            regs::write(BB_BASE, bb::IRQSTAT, bb_irq::POST_INIT_CLR);
        }

        self.isr.rx_armed = true;
        self.isr.rx_captured = false;

        unsafe {
            regs::write(LLE_BASE, lle::CMD, lle_cmd::START_RX);
        }

        self.guard_exit(saved);
        Ok(())
    }

    fn rssi(&self) -> i8 {
        let v = unsafe { regs::read(BB_BASE, bb::RSSICFO) };
        (v >> rssi::SHIFT) as u8 as i8
    }

    fn crc_ok(&self) -> bool {
        self.isr.rx_crc_ok
    }
}
