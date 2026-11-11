//! CH592 (CH59x) BLE IP bases and radio backend.
//!
//! Source: `openwch/ch592` EVT v1.7 (`EVT/EXAM/BLE/LIB/LIBCH59xBLE.a`). Every
//! register sequence below was recovered from the carved objects (`lle.o`,
//! `bb.o`, `rfend.o`, `rf_ip.o`, `ll_advertise.o`) and cross-checked on silicon
//! with firmware calling the vendor routines and printing live registers over
//! SDI.
//!
//! Map (confirmed in `BLE_RegInit`):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21
//!
//! **CH592 is not a CH585/CH595 alias.** `LLE_DevInit` writes the `0x6E` pair
//! at `+0x2C/+0x3C` (CH585: `0x6C`), `BB_DevInit` writes `BB+0x38 = 0xFF`
//! (CH585: `0x3FF`), and runtime differs: TX/RX DMA pointers are
//! `LLE+0x78`/`+0x7C`, TX completion is `IRQSTAT` bit0, RX completion bit3,
//! and the RX-arm clear is bit17 (`0x20000`). Do **not** reuse the V208 mode
//! words or the CH585 table.
//!
//! Runtime channel programming follows the BLE-stack path
//! (`ll_advertise_sync_tx` / `BLE_CheckChannel`): `BB+0[5:0]` = channel,
//! `BB+0` bit6 = whitening off, `BB+0x5C[8:0]` = channel. The RFEND fractional
//! synth (`+0x44`) is also programmed so the standalone-RF path and BLE path
//! agree; it is written exactly like vendor `RFIP_DevSetChannel`.

use super::ch58x_common::ch58x_common;
use crate::rf::analog::{self, AnalogInit};
use crate::rf::family::tables::{BbDevInit, Certainty, LleDevInit, RegInit, RfendInit};
use crate::rf::isr::IsrState;
use crate::rf::regs::{self, bb, bb_irq, lle, rfend};
use crate::rf::timing::{v208_rx_capture_reload_half_us, v208_tx_window_half_us};
use crate::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
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

/// CH5xx LLE register offsets missing from the shared V208 map.
mod lle5 {
    /// Halfword command/status at `LLE+0x06`. `LLE_DevInit` writes `0x78`;
    /// `RFIP_SetRx` writes `4`; `RFIP_SetTx` leaves/restores `0x78`.
    pub const CTRL06: usize = 0x06;
    /// TX packet DMA pointer (CH592: `+0x78`, V208: `+0x70`).
    pub const TXBUFPTR: usize = 0x78;
    /// RX packet DMA pointer (CH592: `+0x7C`).
    pub const RXBUFPTR: usize = 0x7c;
}

/// CH5xx LLE `IRQSTAT` bits (W1C). Recovered from the vendor `lleIrqHandler`
/// (`ip.o`) bit tests and the wait loops in `ll_tx_wait_finish` /
/// `ll_rx_wait_finish`:
///
/// | bit | vendor flag | meaning |
/// |-----|-------------|---------|
/// | 0   | `gBleIPPara+1` | RX finished (alternative) |
/// | 1   | `gBleIPPara+3` | TX finished (bit1 path, seen on silicon) |
/// | 2   | `gBleIPPara+0` | RX finished |
/// | 3   | `gBleIPPara+2` | TX finished |
/// | 5   | — | PHY re-arm ack (W1C helper) |
/// | 16  | `gBleLlPara+0x78` | LL state flags |
/// | 17  | — | RX arm cleared / window expired |
/// | 18  | TICK | LLE tick (`LLE+0x68 = -1`) |
/// | 19  | `gBleLlPara+0x79` | LL state flags |
mod lle5_irq {
    /// Any bit the vendor treats as a TX completion (bits 3 and 1).
    pub const TX_DONE: u32 = 0x0000_0008 | 0x0000_0002;
    /// Any bit the vendor treats as an RX completion (bits 0 and 2).
    pub const RX_DONE: u32 = 0x0000_0001 | 0x0000_0004;
    /// RX window expired / arm cleared.
    pub const CLEAR_ARM: u32 = 0x0002_0000;
    /// LLE tick — handler writes `-1` to `LLE+0x68`.
    pub const TICK: u32 = 0x0004_0000;
}

/// CH5xx LLE `MODE` (`+0x50`) words written by the vendor runtime.
mod lle5_mode {
    /// `BLE_RegInit` calibration entry (`0x30000 + 0x558`).
    pub const INIT: u32 = 0x0003_0558;
    /// `ll_advertise_sync_tx` / `RFIP_SetTx` (`0x30000 + 0x258`).
    pub const TX: u32 = 0x0003_0258;
    /// `RFIP_SetRx` / `BLE_CheckChannel` (`0x30000 + 0x158`).
    pub const RX: u32 = 0x0003_0158;
    /// Post-init idle written by `BLE_RegInit` (`0x30000`).
    pub const POST_INIT: u32 = 0x0003_0000;
    /// Busy-word clear mask used before idle.
    pub const BUSY_MASK: u32 = 0x700;
    /// Plain idle word (`ble_ll_hw_api_shut`).
    pub const IDLE: u32 = 0x30;
}

/// CH5xx BB offsets / bits used only by this family.
mod bb5 {
    /// Whitening channel / hop-map register (offset 92).
    pub const CH_IDX: usize = 0x5c;
    /// Direction bits in `BB+0` (vendor: `(v & ~0x300) | 0x200`).
    pub const DIR_MASK: u32 = 0x0300;
    pub const DIR_RX: u32 = 0x0200;
    pub const DIR_IDLE: u32 = 0x0100;
    /// 1M/2M PHY select in `BB+0`.
    pub const PHY_2M: u32 = 0x0080;
    /// Whitening-off flag in `BB+0` (same bit position as V208 RFCTRL).
    pub const WHITEN_OFF: u32 = 0x0040;
    /// Vendor `RFIP_SetTx` / `ll_tx_wait_finish` TX trigger.
    pub const TX_TRIG: u32 = 0x0080_0000;
}

/// CH5xx RFEND fractional-synth register (`+0x44`).
mod rfend5 {
    pub const FECTRL: usize = 0x08;
    pub const CFG0C: usize = 0x0c;
    pub const FREQMODE: usize = 0x2c;
    pub const CFG30: usize = 0x30;
    pub const CFG38: usize = 0x38;
    pub const CFG3C: usize = 0x3c;
    pub const CFG48: usize = 0x48;
    pub const CFG4C: usize = 0x4c;
    pub const CFG50: usize = 0x50;
    pub const CFG54: usize = 0x54;
    pub const CFG58: usize = 0x58;
    pub const CFG5C: usize = 0x5c;
    pub const TUNE: usize = 0x04;
    pub const TUNE_CO: usize = 0x90;
    pub const TUNE_GA: usize = 0x94;
    pub const FILTMEAS: usize = 0x9c;
}

/// CH592 `BB+0x18` demod config; 1M `0x132`, 2M `0x13a`.
const BB_RXCFG18_1M: u32 = 0x0000_0132;
const BB_RXCFG18_2M: u32 = 0x0000_013a;
/// `BB+0x13` (byte) fixed gain; 1M `0x7f`, 2M `0x78`.
const BB_RXGAIN_1M: u8 = 0x7f;
const BB_RXGAIN_2M: u8 = 0x78;

/// `RFEND_WaitTune` window (half-µs) from `rfend.o` (`0x1F40`).
const WAIT_TUNE_HALF_US: u32 = 8000;
/// `RFEND_RXFilter` LLE countdown (half-µs) from `rfend.o`.
const RX_FILTER_HALF_US: u32 = 100;
/// Default TX power byte (`LL_TX_POWEER_0_DBM`).
const TX_POWER_0_DBM: u8 = 0x15;

use Certainty::FromClosedDisasm as Disasm;

/// `LLE_DevInit` absolute stores (`lle.o`).
///
/// `BLE_LibInit` defaults `ble+0x14` (TxPower) to `0x15`, so a stock build
/// takes the `0x8C` branch (the table stores the `0x84` baseline); a negative
/// power byte uses `0x84` (see [`Ch592Radio::lle_dev_init`]).
///
/// The halfword `LLE+0x06`, the `LLE+0x54` sequence, and the `LLE+0x7C` DMA
/// pointer are applied by [`Ch592Radio::lle_dev_init`], not by this table.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x84, Disasm),
        RegInit::new(0x1c, 0x76, Disasm),
        RegInit::new(0x24, 0x84, Disasm),
        RegInit::new(0x2c, 0x6e, Disasm), // CH585 carved says 0x6c — do not copy
        RegInit::new(0x34, 0x84, Disasm),
        RegInit::new(0x3c, 0x6e, Disasm),
        RegInit::new(0x44, 0x84, Disasm),
        RegInit::new(0x4c, 0x76, Disasm),
        RegInit::new(0x08, 0xffff_ffff, Disasm),
        RegInit::new(0x0c, 0x001f_000f, Disasm),
    ],
    // CH592 does not do the CH585 `LLE+0x04 &= -0x1f` RMW.
    crc_aa_cfg_clear_mask: None,
};

/// `BB_DevInit` highlights (`bb.o`).
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x50, Disasm),
    cfg20: None,
    irqstat: Some(RegInit::new(0x38, 0xff, Disasm)),
    cfg3c: Some(RegInit::new(0x3c, 0x2_020c, Disasm)),
    set_bit23: true,
    set_bit28: false,
    certainty: Disasm,
};

/// RFEND / WaitTune / VCO markers (`rfend.o`).
///
/// There is no `RFEND_Reset` on CH592; `RFEND_DevInit` starts with
/// `+0x28 = 0x480` and a dense RMW block applied in
/// [`Ch592Radio::rfend_dev_init_rmw`].
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    wait_tune_half_us: RegInit::new(0x64, WAIT_TUNE_HALF_US, Disasm),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Disasm,
};

/// TXCtune band codes written to `RFEND+0x38[15:8]`, in vendor order
/// 2401→`0xBF`, 2480→`0xE7`, 2440→`0xD3`.
const TXCTUNE_BANDS: [u8; 3] = [0xbf, 0xe7, 0xd3];
/// Maps TXCtune loop index → sample slot {2401, 2440, 2480} = {0, 2, 1}.
const TXCTUNE_SAMPLE_INDEX: [usize; 3] = [0, 2, 1];

/// CH592 radio — DevInit, calibration, channel/TX/RX runtime.
#[derive(Debug)]
pub struct Ch592Radio {
    channel: Channel,
    phy_tx: PhyMode,
    phy_rx: PhyMode,
    whiten_disabled: bool,
    encrypt: bool,
    access_address: u32,
    crc_init: u32,
    tx_power: u8,
    isr: IsrState,
    rx_dma: *mut u8,
    rx_dma_len: usize,
    rx_active: *mut u8,
    /// Post-capture window reload computed by `BLE_SetPHYRxMode`.
    rx_reload_half_us: u32,
    tx_bounce: DmaBuf<MAX_PDU>,
}

// Soft state only; MMIO runs through fixed bases. Safe to move across tasks.
unsafe impl Send for Ch592Radio {}

impl Ch592Radio {
    /// `phy_status_clear`: drop a pending command and clear sticky status.
    ///
    /// The vendor version also touches PFIC enable bits and the `rfConfig`
    /// callback; only the engine/status part is needed here.
    fn phy_status_clear(&mut self) {
        let cmd = unsafe { regs::read(LLE_BASE, lle::CMD) };
        if cmd & 0x3 != 0 {
            unsafe {
                regs::write(LLE_BASE, lle::CMD, cmd | 0x8);
            }
        }
        unsafe {
            regs::write(LLE_BASE, lle::IRQSTAT, 0xffff_ffff);
            regs::write(BB_BASE, bb::IRQSTAT, 0xff);
        }
    }

    /// `LLE_DevInit` (`lle.o`): timeout pair, halfword, RX DMA, masks.
    fn lle_dev_init(&mut self) {
        // `LLE_DevInit` reads the signed `ble+0x14` byte: non-negative (the
        // stock `LL_TX_POWEER_0_DBM = 0x15`) takes `0x8C`, negative `0x84`.
        let tie = if (self.tx_power as i8) >= 0 {
            0x8c
        } else {
            0x84
        };
        unsafe {
            for store in LLE_DEV_INIT.stores {
                // The `0x84` timeout entries become `0x8C` when `ble+0x14`
                // (`LLE_DevInit`'s signed power byte) is non-negative.
                let value = if matches!(store.offset, 0x14 | 0x24 | 0x34 | 0x44) {
                    tie
                } else {
                    store.value
                };
                regs::write(LLE_BASE, store.offset as usize, value);
            }
            regs::write_u16(LLE_BASE, lle5::CTRL06, 0x78);
            // Vendor reads +0x54, ORs bit31, writes it, then overwrites with 0x14.
            let v = regs::read(LLE_BASE, 0x54);
            regs::write(LLE_BASE, 0x54, v | 0x8000_0000);
            regs::write(LLE_BASE, 0x54, 0x14);
            regs::write(LLE_BASE, lle5::RXBUFPTR, self.rx_dma as u32);
            regs::write(LLE_BASE, lle::IRQSTAT, 0xffff_ffff);
            regs::write(LLE_BASE, lle::GUARD, 0x001f_000f);
        }
    }

    /// `RFEND_DevInit` (`rfend.o`) — dense RMW block, no reset pulse.
    fn rfend_dev_init_rmw(&mut self) {
        unsafe {
            regs::write(RFEND_BASE, rfend::CFG28, RFEND_INIT.dev_init_0x28.value);

            // +0x3C
            regs::rmw(RFEND_BASE, rfend5::CFG3C, 0xf8ff_ffff, 0x2000_0000);
            regs::rmw(RFEND_BASE, rfend5::CFG3C, 0xe000_0000, 0x4000_0000);
            // `lui a3, 0xffff1; addi -1` = 0xffff0fff (bits 12..15), then
            // `lui a3, 5` = 0x5000 — a 4-bit field, not bit 16.
            regs::rmw(RFEND_BASE, rfend5::CFG3C, 0x0000_f000, 0x0000_5000);

            // +0x54: high bits preserved, low nibble = 9.
            regs::rmw(RFEND_BASE, rfend5::CFG54, 0xf, 9);

            // +0x30
            regs::rmw(RFEND_BASE, rfend5::CFG30, 0, 0x700);
            // `lui a3, 7` = 0x7000 (bits 12..14), not `ori 7`.
            regs::rmw(RFEND_BASE, rfend5::CFG30, 0, 0x7000);
            regs::rmw(RFEND_BASE, rfend5::CFG30, 0, 0x7_0000);
            regs::rmw(RFEND_BASE, rfend5::CFG30, 0x7000_0000, 0x1000_0000);

            // +0x4C / +0x5C
            regs::rmw(RFEND_BASE, rfend5::CFG4C, 7, 0);
            regs::rmw(RFEND_BASE, rfend5::CFG5C, 0x0007_0000, 0);
            regs::rmw(RFEND_BASE, rfend5::CFG5C, 0x0070_0000, 0);

            // +0x48 bit31 follows the power byte's upper bits.
            if self.tx_power & 0xc0 != 0 {
                regs::rmw(RFEND_BASE, rfend5::CFG48, 0, 0x8000_0000);
            } else {
                regs::rmw(RFEND_BASE, rfend5::CFG48, 0x8000_0000, 0);
            }
        }
    }

    /// `BB_DevInit` (`bb.o`) — includes the RFEND+0x5C power pack.
    fn bb_dev_init(&mut self) {
        let tp = self.tx_power;
        let signed = i32::from(tp as i8);
        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, 0, bb5::TX_TRIG);
            regs::write(BB_BASE, bb::IRQSTAT, 0xff);
            regs::write(BB_BASE, bb::CFG34, BB_DEV_INIT.cfg34.value);

            regs::rmw(BB_BASE, bb::AUTOCFG, 0, 0x8000_0000);
            regs::rmw(
                BB_BASE,
                bb::AUTOCFG,
                0x81ff_ffff,
                (u32::from(tp) & 0x3f) << 25,
            );

            // RFEND+0x5C power-class bits.
            if signed > 58 {
                regs::rmw(RFEND_BASE, rfend5::CFG5C, 0, 0x7000_0000);
            } else if signed > 34 {
                regs::rmw(RFEND_BASE, rfend5::CFG5C, 0xf8ff_ffff, 0x5000_0000);
            } else if signed > 26 {
                regs::rmw(RFEND_BASE, rfend5::CFG5C, 0xf8ff_ffff, 0x3000_0000);
            } else {
                regs::rmw(RFEND_BASE, rfend5::CFG5C, 0xf8ff_ffff, 0x1000_0000);
            }

            // BB+0x3C: the vendor picks a different value for negative power.
            let cfg3c = if signed < 0 { 0x0002_0210 } else { 0x0002_020c };
            regs::write(BB_BASE, 0x3c, cfg3c);

            // BB+0x10 low six bits = 0x0E.
            regs::rmw(BB_BASE, bb::RXCFG10, 0x3f, 0x0e);
        }
    }

    /// Vendor `RFEND_TXCtune`: measure 2401/2440/2480 and interpolate the VCO
    /// tables. Same algorithm as the open V208 path.
    fn rf_txctune<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        let mut co = [0u8; 3];
        let mut ga = [0u8; 3];

        unsafe {
            regs::rmw(RFEND_BASE, rfend5::TUNE, 0x100, 0);
            regs::rmw(RFEND_BASE, rfend::CFG28, 0x1000, 0);
            regs::rmw(RFEND_BASE, rfend5::FREQMODE, 0x10, 0);
            regs::rmw(RFEND_BASE, rfend5::FECTRL, 0, 0x2_0000);
            regs::rmw(RFEND_BASE, rfend5::TUNE, 0, rfend::TUNE_FILT);

            for (i, &band) in TXCTUNE_BANDS.iter().enumerate() {
                let sample = TXCTUNE_SAMPLE_INDEX[i];
                regs::rmw(RFEND_BASE, rfend5::TUNE, rfend::TUNE_TRIG, 0);
                regs::rmw(
                    RFEND_BASE,
                    rfend5::CFG38,
                    !rfend::BANDCODE_MASK,
                    (u32::from(band)) << rfend::BANDCODE_SHIFT,
                );
                regs::rmw(RFEND_BASE, rfend5::TUNE, 0, rfend::TUNE_TRIG);
                if self.wait_tune(clock).is_err() {
                    regs::rmw(RFEND_BASE, rfend5::TUNE, 0x111, 0);
                    return Err(Error::Timeout);
                }
                co[sample] = (regs::read(RFEND_BASE, rfend5::TUNE_CO) & rfend::TUNE_CO_MASK) as u8;
                ga[sample] = ((regs::read(RFEND_BASE, rfend5::TUNE_GA) >> rfend::TUNE_GA_SHIFT)
                    & rfend::TUNE_GA_MASK) as u8;
            }

            let co_low = i32::from(co[0]) - i32::from(co[1]);
            let co_high = i32::from(co[1]) - i32::from(co[2]);
            let ga_low = i32::from(ga[0]) - i32::from(ga[1]);
            let ga_high = i32::from(ga[1]) - i32::from(ga[2]);

            for i in 0..40usize {
                analog::nibble_write(RFEND_BASE, rfend::VCOTAB, i, co_low * (39 - i as i32) / 39);
            }
            for i in 1..=42usize {
                analog::nibble_write(RFEND_BASE, rfend::VCOTAB, 39 + i, co_high * i as i32 / 40);
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

            regs::rmw(RFEND_BASE, rfend5::TUNE, rfend::TUNE_FILT, 0);
            regs::rmw(RFEND_BASE, rfend5::TUNE, rfend::TUNE_TRIG, 0);
            regs::rmw(RFEND_BASE, rfend::CFG28, 0, 0x1000);
            regs::rmw(RFEND_BASE, rfend5::FREQMODE, 0, 0x10);
            regs::rmw(RFEND_BASE, rfend5::CFG38, 0x3f, u32::from(co[1]));
            regs::rmw(
                RFEND_BASE,
                rfend5::CFG38,
                0x7f00_0000,
                u32::from(ga[1]) << 24,
            );
        }
        Ok(())
    }

    /// Vendor `RFEND_RXFilter` (exact CH592 toggle order, LLE window 100).
    fn rf_rxfilter<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        unsafe {
            regs::rmw(RFEND_BASE, rfend5::CFG50, rfend::CFG50_FILT_EN, 0);
            regs::rmw(RFEND_BASE, rfend5::FECTRL, 0, rfend::FECTRL_RXFILT);
            regs::rmw(RFEND_BASE, rfend5::CFG0C, 0, rfend::CFG0C_FILT_TOGGLE);
            regs::rmw(RFEND_BASE, rfend5::CFG0C, rfend::CFG0C_FILT_TOGGLE, 0);
            for _ in 0..4 {
                core::hint::spin_loop();
            }
            regs::rmw(RFEND_BASE, rfend5::CFG0C, 0, rfend::CFG0C_FILT_TOGGLE);
            regs::rmw(RFEND_BASE, rfend5::TUNE, 0, 0x1_0000);
            regs::write(LLE_BASE, lle::WINDOW, RX_FILTER_HALF_US);

            let started = clock.now_us();
            loop {
                if regs::read(LLE_BASE, lle::WINDOW) == 0 {
                    break;
                }
                if regs::read(RFEND_BASE, rfend5::FILTMEAS) & rfend::FILTMEAS_RDY != 0 {
                    break;
                }
                if clock.now_us().wrapping_sub(started) >= analog::CAL_TIMEOUT_US {
                    regs::rmw(RFEND_BASE, rfend5::FECTRL, rfend::FECTRL_RXFILT, 0);
                    return Err(Error::Timeout);
                }
            }

            let result = regs::read(RFEND_BASE, rfend5::FILTMEAS);
            regs::rmw(RFEND_BASE, rfend5::CFG50, 0, rfend::CFG50_FILT_EN);
            regs::rmw(
                RFEND_BASE,
                rfend5::CFG50,
                rfend::FILTMEAS_MASK,
                result & rfend::FILTMEAS_MASK,
            );
            regs::rmw(RFEND_BASE, rfend5::FECTRL, rfend::FECTRL_RXFILT, 0);
        }
        Ok(())
    }

    /// Vendor `BLE_SetPHYTxMode` for the 1M/2M legacy paths.
    ///
    /// Vendor phy numbering is inverted relative to [`PhyMode`]: mode `1` is
    /// 2M, everything else is 1M. The LLE window formulas are identical to the
    /// open V208 ones (`v208_tx_window_half_us`).
    ///
    /// The `LLE+0x0C` guard toggle around the `IRQSTAT` arm-clear is not
    /// optional: on silicon the `0x20000` bit only clears with **bit 17** of
    /// the guard register cleared (`fence.i` between). V208 shadows its
    /// `0x2000` arm bit with guard bit 13; CH592's arm bit moved to bit 17.
    fn set_phy_tx_mode(&mut self, mode: PhyMode, payload_len: u8) {
        let is_2m = matches!(mode, PhyMode::Rate2m);
        if is_2m {
            unsafe { regs::rmw(BB_BASE, bb::RFCTRL, 0, bb5::PHY_2M) };
        } else {
            unsafe { regs::rmw(BB_BASE, bb::RFCTRL, bb5::PHY_2M, 0) };
        }
        unsafe {
            let saved = regs::read(LLE_BASE, lle::GUARD);
            regs::write(LLE_BASE, lle::GUARD, saved & !lle5_irq::CLEAR_ARM);
            analog::fence_i();
            regs::write(LLE_BASE, lle::IRQSTAT, lle5_irq::CLEAR_ARM);
            regs::write(
                LLE_BASE,
                lle::WINDOW,
                v208_tx_window_half_us(mode, payload_len),
            );
            regs::write(LLE_BASE, lle::GUARD, saved);
        }
    }

    /// Vendor `BLE_SetPHYRxMode` (also computes the post-capture reload).
    fn set_phy_rx_mode(&mut self, mode: PhyMode, rx_max_len: u16) {
        let is_2m = matches!(mode, PhyMode::Rate2m);
        self.rx_reload_half_us = v208_rx_capture_reload_half_us(mode);
        let _ = rx_max_len;
        unsafe {
            if is_2m {
                regs::rmw(BB_BASE, bb::RFCTRL, 0, bb5::PHY_2M);
                regs::rmw(BB_BASE, bb::RXCFG18, 0x3ff, BB_RXCFG18_2M);
                regs::write_u8(BB_BASE, 0x13, BB_RXGAIN_2M);
            } else {
                regs::rmw(BB_BASE, bb::RFCTRL, bb5::PHY_2M, 0);
                regs::rmw(BB_BASE, bb::RXCFG18, 0x3ff, BB_RXCFG18_1M);
                regs::write_u8(BB_BASE, 0x13, BB_RXGAIN_1M);
            }
        }
    }

    /// Vendor `ble_ll_hw_api_shut`.
    fn engine_shut(&mut self) {
        unsafe {
            regs::rmw(LLE_BASE, lle::MODE, lle5_mode::BUSY_MASK, 0);
            let cmd = regs::read(LLE_BASE, lle::CMD);
            regs::write(LLE_BASE, lle::CMD, cmd | 0x8);
            for _ in 0..4 {
                core::hint::spin_loop();
            }
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, bb5::DIR_IDLE);
            regs::rmw(RFEND_BASE, rfend5::FECTRL, rfend::FECTRL_RF_ON, 0);
            regs::write(LLE_BASE, lle::MODE, lle5_mode::IDLE);
        }
    }
}

ch58x_common! {
    Ch592Radio,
    fn tx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        frame: &[u8],
        _timeout_half_us: u32,
        start_cputime: Option<u32>,
    ) -> Result<()> {
        if frame.len() < 2 || frame.len() > MAX_PDU {
            return Err(Error::InvalidState);
        }
        if self.channel > 39 {
            return Err(Error::InvalidState);
        }
        if unsafe { regs::read(LLE_BASE, lle::CMD) & 0x3 } != 0 {
            // `phy_status_clear`: the vendor force-stops a stale LLE command
            // (`ble_ll_hw_api_shut`) instead of rejecting the packet.
            self.engine_shut();
        }
        // The LLE DMAs the frame straight out of `TXBUFPTR`; align it the same
        // way the vendor's TX buffer is aligned.
        let tx_ptr = if frame.as_ptr() as usize & 0x3 == 0 {
            frame.as_ptr()
        } else {
            self.tx_bounce.0[..frame.len()].copy_from_slice(frame);
            self.tx_bounce.0.as_ptr()
        };

        // `ll_advertise_sync_tx` pre-arm.
        unsafe {
            regs::write(LLE_BASE, lle::WINDOW, 0x78);
            regs::rmw(BB_BASE, bb::AUTOCFG, 0x3, 0x1);
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, 0);
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, bb5::DIR_RX);
            regs::rmw(RFEND_BASE, rfend5::FECTRL, 0, rfend::FECTRL_RF_ON);
            regs::write(LLE_BASE, lle::MODE, lle5_mode::TX);
        }

        // `ll_advertise_tx` clears the RFEND fractional-synth enable right
        // after `LLE+0x50 = TX`; the BLE path selects the carrier through
        // `BB+0[6:0]` alone and never programs `RFEND+0x44` (that is the
        // standalone-RF `RFIP_DevSetChannel` path).
        unsafe {
            regs::rmw(RFEND_BASE, rfend5::FREQMODE, rfend::FREQMODE_EN, 0);
        }
        self.program_channel_bb(self.channel);

        // `ll_advertise_tx` re-pulses the TX filter tune on every packet:
        // `TUNE &= ~0x100`, two nops, `TUNE |= 0x100`.
        unsafe {
            regs::rmw(RFEND_BASE, rfend5::TUNE, rfend::TUNE_TXFTUNE, 0);
            core::hint::spin_loop();
            core::hint::spin_loop();
            regs::rmw(RFEND_BASE, rfend5::TUNE, 0, rfend::TUNE_TXFTUNE);
        }

        // Before `BLE_SetPHYTxMode` rewrites `LLE+0x64`, the vendor's
        // `ll_tx_wait_finish` lets the `0x78` pre-arm countdown expire.
        let arm_wait = clock.now_us();
        while unsafe { regs::read(LLE_BASE, lle::WINDOW) } != 0 {
            if clock.now_us().wrapping_sub(arm_wait) > 100 {
                break;
            }
        }

        unsafe {
            self.apply_aa_crc();
            regs::write_u16(LLE_BASE, lle5::CTRL06, 0x78);
            regs::write(LLE_BASE, lle5::TXBUFPTR, tx_ptr as u32);
            // `ll_advertise_tx` enables CRC on `LLE+0x04` bit 0 before the
            // trigger. (V208's LLE uses the opposite polarity; do not share.)
            regs::rmw(LLE_BASE, lle::CRC_AA_CFG, 0, 0x1);
        }
        // Sticky W1C completions from a previous arm must not be mistaken for
        // this transmission's result.
        self.irq_clear_guarded(lle5_irq::TX_DONE);

        self.set_phy_tx_mode(self.phy_tx, frame[1]);
        let hw_window = unsafe { regs::read(LLE_BASE, lle::WINDOW) };

        if let Some(start) = start_cputime {
            unsafe {
                regs::write(LLE_BASE, lle::WINDOW, 0);
            }
            loop {
                let now = clock.now_us();
                if now.wrapping_sub(start) as i32 >= 0 {
                    if now.wrapping_sub(start) > 10 {
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
            regs::rmw(BB_BASE, bb::RFCTRL, 0, bb5::TX_TRIG);
            regs::rmw(BB_BASE, bb::AUTOCFG, 0x3, 0);
        }
        let started = clock.now_us();
        unsafe {
            regs::write(LLE_BASE, lle::CMD, 2);
        }

        let deadline = started.wrapping_add(hw_window / 2).wrapping_add(200);
        let mut rc = Ok(());
        loop {
            let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
            if st & lle5_irq::TX_DONE != 0 {
                break;
            }
            if clock.now_us().wrapping_sub(deadline) as i32 >= 0 {
                let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
                if st & lle5_irq::TX_DONE == 0 {
                    rc = Err(Error::Timeout);
                }
                break;
            }
        }

        unsafe {
            regs::write(LLE_BASE, lle::IRQSTAT, lle5_irq::TX_DONE);
        }
        rc
    }
}
