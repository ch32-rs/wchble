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
use crate::rf::regs::{self, autocfg, bb, bb_irq, lle, lle_cmd, lle_mode, rfctrl, rfend};
use crate::rf::txrx::RX_DMA_MIN;
use crate::rf::{Channel, PhyMode, Radio, RfCallback};
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
    access_address: u32,
    crc_init: u32,
    isr: IsrState,
    rx_dma: *mut u8,
    rx_dma_len: usize,
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
            access_address: 0x8e89_bed6,
            crc_init: 0x55_5555,
            isr: IsrState::default(),
            rx_dma: ptr,
            rx_dma_len: rx_dma.len(),
        })
    }

    /// RX DMA scratch installed at construction.
    pub fn rx_dma_len(&self) -> usize {
        self.rx_dma_len
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

            // Open: (RF(0x38) & 0xfffe00ff) | (band << 8)  → clear bits[15:8].
            const CLEAR_BAND: u32 = 0x00ff_00;

            for (i, &band) in TXCTUNE_BANDS.iter().enumerate() {
                let sample = TXCTUNE_SAMPLE_INDEX[i];
                regs::rmw(RFEND_BASE, rfend::TUNE, rfend::TUNE_TRIG, 0);
                regs::rmw(
                    RFEND_BASE,
                    rfend::CFG38,
                    CLEAR_BAND,
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
        unsafe {
            regs::write(BB_BASE, bb::IRQSTAT, bb_irq::POST_INIT_CLR);
            regs::write(LLE_BASE, lle::IRQSTAT, 0xffff);
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
        // TODO: assert RFCTRL.SHUT / force LLE stop (wch_rf_shut) — next cut.
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
        self.access_address = access_address;
        self.crc_init = crc_init;
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
        _clock: &T,
        frame: &[u8],
        _timeout_half_us: u32,
        _start_cputime: Option<u32>,
    ) -> Result<()> {
        if frame.len() < 2 {
            return Err(Error::InvalidState);
        }
        Err(Error::Unsupported)
    }

    fn rx_basic<T: InstantUs>(
        &mut self,
        _clock: &T,
        rxbuf: &mut [u8],
        _window_half_us: u32,
    ) -> Result<()> {
        if rxbuf.is_empty() {
            return Err(Error::InvalidState);
        }
        Err(Error::Unsupported)
    }

    fn rssi(&self) -> i8 {
        0
    }

    fn crc_ok(&self) -> bool {
        false
    }
}
