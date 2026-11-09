//! CH585 (CH58x) BLE IP bases and radio backend.
//!
//! Source: `~/.WCH/CH585EVT/EXAM/BLE/LIB/libCH58xBLE.a` carved objects (`lle.o`,
//! `bb.o`, `rfend.o`, `rf_ip.o`, `ip.o`, `ll_advertise.o`, `ll_scan.o`). Every
//! register sequence below was recovered from those objects; the on-silicon
//! gate lives in `examples/ch585-rf-smoke`.
//!
//! Map (confirmed in `BLE_RegInit`):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21
//!
//! **CH585 is not a CH592 alias.** The DevInit differences are real:
//! `LLE_DevInit` writes the `0x6C` pair at `+0x2C/+0x3C` (CH592: `0x6E`),
//! masks `LLE+0x04` with `0xFFFF_FFE1`, writes halfword `+0x06 = 2` and
//! `+0x54 = 0`; `BB_DevInit` writes `BB+0x38 = 0x3FF` (CH592: `0xFF`) and
//! `BB+0x3C = 0x0002_020C`; `RFEND_DevInit` is a different RMW soup (no
//! `+0x54` nibble write, no `+0x3C[15:12]` field); `RFEND_TXCtune` measures a
//! 4th band (2522 MHz, code `0xFC`) and `RFEND_RXFilter` arms `TUNE` bit 12
//! (not bit 16).
//!
//! Runtime stays on the CH58x map: TX/RX DMA at `LLE+0x78`/`+0x7C`, LLE mode
//! words `0x0003_0258`/`0x0003_0158`, TX completion in `IRQSTAT` bits 3|1
//! (`TRIG`/`SEQ`), RX completion bits 0|2, arm-clear bit 17 behind guard bit 17
//! of `LLE+0x0C`, CRC enable is `LLE+0x04` bit 0, and the channel goes to
//! `BB+0[6:0]` (plus `BB+0x5C[8:0]` in `BLE_CheckChannel`).

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
    /// Halfword command/status at `LLE+0x06`. `LLE_DevInit` stores `2`;
    /// `RFIP_SetRx` re-stores `2` on every arm.
    pub const CTRL06: usize = 0x06;
    /// TX packet DMA pointer (`ulle+0x78`; CH592 uses the same).
    pub const TXBUFPTR: usize = 0x78;
    /// RX packet DMA pointer (`ulle+0x7C`).
    pub const RXBUFPTR: usize = 0x7c;
}

/// CH5xx LLE `IRQSTAT` bits (W1C). Bit assignment recovered from the vendor
/// `lleIrqHandler` (`ip.o`): bit3 → `gBleIPPara[8]`, bit0 → `[4]` (both read by
/// `ll_tx_wait_finish`), bit2 → `[0]`, bit1 → `[0xC]` (both read by
/// `ll_rx_wait_finish`).
mod lle5_irq {
    /// Any bit the vendor treats as a TX completion (bits 3 and 1).
    pub const TX_DONE: u32 = 0x0000_0008 | 0x0000_0002;
    /// Any bit the vendor treats as an RX completion (bits 0 and 2).
    pub const RX_DONE: u32 = 0x0000_0001 | 0x0000_0004;
    /// RX window expired / arm cleared. Guarded by `LLE+0x0C` bit 17.
    pub const CLEAR_ARM: u32 = 0x0002_0000;
    /// LLE tick — handler writes `-1` to `LLE+0x68`.
    pub const TICK: u32 = 0x0004_0000;
}

/// CH5xx LLE `MODE` (`+0x50`) words written by the vendor runtime.
mod lle5_mode {
    /// `BLE_RegInit` calibration entry (`0x30000 + 0x558`).
    pub const INIT: u32 = 0x0003_0558;
    /// `ll_advertise_tx` / `RFIP_SetTx` (`0x30000 + 0x258`).
    pub const TX: u32 = 0x0003_0258;
    /// `LL_ScanSetRF` / `RFIP_SetRx` (`0x30000 + 0x158`).
    pub const RX: u32 = 0x0003_0158;
    /// Post-init / shutdown idle (`ble_ll_hw_api_shut`, `BLE_RegInit` tail).
    pub const POST_INIT: u32 = 0x0003_0000;
    /// Bits cleared before a forced stop: `0x10 | 0x700`.
    pub const SHUT_MASK: u32 = 0x710;
}

/// CH5xx BB offsets / bits used only by this family.
mod bb5 {
    /// Whitening channel / hop-map register (offset 92, mask `0x1FF`).
    pub const CH_IDX: usize = 0x5c;
    /// Direction bits in `BB+0` (vendor: `(v & ~0x300) | 0x200`).
    pub const DIR_MASK: u32 = 0x0300;
    pub const DIR_RX: u32 = 0x0200;
    pub const DIR_IDLE: u32 = 0x0100;
    /// 1M/2M PHY select in `BB+0` (vendor sets it for 2M).
    pub const PHY_2M: u32 = 0x0080;
    /// Whitening-off flag in `BB+0` (same bit position as V208 RFCTRL).
    pub const WHITEN_OFF: u32 = 0x0040;
    /// Vendor TX trigger (`ll_tx_wait_finish`, `RFIP_SetTx`).
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
    pub const CFG58: usize = 0x58;
    pub const CFG5C: usize = 0x5c;
    pub const TUNE: usize = 0x04;
    pub const TUNE_CO: usize = 0x90;
    pub const TUNE_GA: usize = 0x94;
    pub const FILTMEAS: usize = 0x9c;
}

/// CH585 `BB+0x18` demod config; 1M `0x132`, 2M `0x13a` (`BLE_SetPHYRxMode`).
const BB_RXCFG18_1M: u32 = 0x0000_0132;
const BB_RXCFG18_2M: u32 = 0x0000_013a;
/// `BB+0x13` (byte) fixed gain; 1M `0x7f`, 2M `0x78`.
const BB_RXGAIN_1M: u8 = 0x7f;
const BB_RXGAIN_2M: u8 = 0x78;

/// `RFEND_WaitTune` window (half-µs) from `rfend.o` (`0x1F40`).
const WAIT_TUNE_HALF_US: u32 = 8000;
/// `RFEND_RXFilter` LLE countdown (half-µs) from `rfend.o` (`100`).
const RX_FILTER_HALF_US: u32 = 100;
/// Default TX power byte (`LL_TX_POWEER_0_DBM`).
const TX_POWER_0_DBM: u8 = 0x15;
/// `RXFilter` arms `RFEND+0x04` bit 12 on CH585 (CH592 uses bit 16).
const TUNE_FILT_ARM: u32 = 0x0000_1000;

use Certainty::FromClosedDisasm as Disasm;

/// `LLE_DevInit` absolute stores (`lle.o`).
///
/// Unlike CH592 there is no power-byte branch: `0x8C` is unconditional. The
/// halfword `LLE+0x06 = 2`, the `LLE+0x54 = 0` store and the `LLE+0x7C` DMA
/// pointer are applied by [`Ch585Radio::lle_dev_init`] in vendor order.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x8c, Disasm),
        RegInit::new(0x1c, 0x76, Disasm),
        RegInit::new(0x24, 0x8c, Disasm),
        RegInit::new(0x2c, 0x6c, Disasm), // CH592: 0x6e — do not copy
        RegInit::new(0x34, 0x8c, Disasm),
        RegInit::new(0x3c, 0x6c, Disasm),
        RegInit::new(0x44, 0x8c, Disasm),
        RegInit::new(0x4c, 0x76, Disasm),
        RegInit::new(0x54, 0x00, Disasm), // CH585-only in this DevInit
        RegInit::new(0x08, 0xffff_ffff, Disasm),
        RegInit::new(0x0c, 0x001f_000f, Disasm),
    ],
    // `LLE+0x04 &= 0xFFFF_FFE1` (keeps the CRC-enable bit 0).
    crc_aa_cfg_clear_mask: Some(0xffff_ffe1),
};

/// `BB_DevInit` highlights (`bb.o`).
///
/// No `BB+0x20` write; `BB+0x38 = 0x3FF`; `BB+0x3C = 0x0002_020C`; only bit 23
/// of `BB+0` is touched (bit 28 is not).
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x50, Disasm),
    cfg20: None,
    irqstat: Some(RegInit::new(0x38, 0x3ff, Disasm)),
    cfg3c: Some(RegInit::new(0x3c, 0x2_020c, Disasm)),
    set_bit23: true,
    set_bit28: false,
    certainty: Disasm,
};

/// RFEND WaitTune / VCO markers (`rfend.o`). No `RFEND_Reset` symbol on CH585;
/// `RFEND_DevInit` is a dense RMW block applied in
/// [`Ch585Radio::rfend_dev_init_rmw`].
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    wait_tune_half_us: RegInit::new(0x64, WAIT_TUNE_HALF_US, Disasm),
    vco_mhz: &[2401, 2440, 2480, 2522],
    certainty: Disasm,
};

/// TXCtune band codes written to `RFEND+0x38[15:8]`, in vendor order
/// 2401→`0xBF`, 2480→`0xE8`, 2440→`0xD4`, 2522→`0xFC`.
const TXCTUNE_BANDS: [u8; 4] = [0xbf, 0xe8, 0xd4, 0xfc];
/// Maps TXCtune loop index → sample slot {2401, 2440, 2480, 2522}.
const TXCTUNE_SAMPLE_INDEX: [usize; 4] = [0, 2, 1, 3];

/// CH585 radio — DevInit, calibration, channel/TX/RX runtime.
#[derive(Debug)]
pub struct Ch585Radio {
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
unsafe impl Send for Ch585Radio {}

impl Ch585Radio {
    /// Build a radio that owns a DMA-capable RX scratch buffer.
    ///
    /// `rx_dma` must be at least [`RX_DMA_MIN`] bytes and 4-byte aligned.
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
            tx_power: TX_POWER_0_DBM,
            isr: IsrState::default(),
            rx_dma: ptr,
            rx_dma_len: rx_dma.len(),
            rx_active: ptr,
            rx_reload_half_us: v208_rx_capture_reload_half_us(PhyMode::Rate1m),
            tx_bounce: DmaBuf::zeroed(),
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

    /// TX power byte (vendor `bleConfig_t.TxPower` encoding). `0x15` = 0 dBm.
    pub fn set_tx_power(&mut self, power: u8) {
        self.tx_power = power;
    }

    /// BB / LLE interrupt entry points for the HAL vector table.
    ///
    /// Vendor `lleIrqHandler` bit map is identical to CH592 (bits 3|1 TX,
    /// 0|2 RX, 17 arm-clear, 18 tick).
    pub fn lle_isr(&mut self) {
        let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
        let was_rx = self.isr.rx_armed;

        if st & lle5_irq::RX_DONE != 0 {
            let bb_st = unsafe { regs::read(BB_BASE, bb::IRQSTAT) };
            self.isr.rx_crc_ok = bb_st & bb_irq::CRC_ERR == 0;
            unsafe {
                regs::write(LLE_BASE, lle::IRQSTAT, lle5_irq::RX_DONE);
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
        if st & lle5_irq::TX_DONE != 0 {
            unsafe {
                regs::write(LLE_BASE, lle::IRQSTAT, lle5_irq::TX_DONE);
            }
            self.isr.dispatch(RfEvent::TxDone, 0);
        }
        if st & lle5_irq::CLEAR_ARM != 0 {
            unsafe {
                regs::write(LLE_BASE, lle::IRQSTAT, lle5_irq::CLEAR_ARM);
            }
            if was_rx && st & lle5_irq::RX_DONE == 0 {
                self.isr.rx_armed = false;
                self.isr.dispatch(RfEvent::RxTimeout, 0);
            }
        }
        // Vendor `lleIrqHandler`: a tick reloads `LLE+0x68 = -1`.
        if st & lle5_irq::TICK != 0 {
            unsafe {
                regs::write(LLE_BASE, lle::TICK, 0xffff_ffff);
                regs::write(LLE_BASE, lle::IRQSTAT, lle5_irq::TICK);
            }
        }
    }

    /// BB IRQ entry — clock capture / address match.
    ///
    /// Vendor `BB_IRQLibHandler` acks `BB+0x38 = 0x60` and reloads
    /// `LLE+0x64` from `gBleIPPara+0x28` (the value `BLE_SetPHYRxMode`
    /// computed), exactly like the CH592 path.
    pub fn bb_isr(&mut self) {
        let st = unsafe { regs::read(BB_BASE, bb::IRQSTAT) };
        if st & bb_irq::CLKCAP != 0 {
            unsafe {
                regs::write(BB_BASE, bb::IRQSTAT, bb_irq::CLKCAP_CLR);
            }
            if self.isr.rx_armed && !self.isr.rx_captured {
                self.isr.rx_captured = true;
                unsafe {
                    regs::write(LLE_BASE, lle::WINDOW, self.rx_reload_half_us);
                }
                self.isr.dispatch(RfEvent::RxStart, self.isr.last_anchor_us);
            }
        }
        unsafe {
            regs::write(BB_BASE, bb::IRQSTAT, st & bb_irq::TIMER_ACK);
        }
    }

    /// Stamp the BB clock-capture time from the HAL's `InstantUs`.
    pub fn note_anchor_us(&mut self, now_us: u32) {
        self.isr.last_anchor_us = now_us;
    }

    /// `phy_status_clear`: force-stop a pending command.
    ///
    /// CH585's version returns immediately when the LLE is idle and otherwise
    /// disables the LLE IRQ (HAL-owned here), calls `ble_ll_hw_api_shut`, and
    /// restores the PFIC state; only the engine part belongs in this crate.
    /// Unlike CH592 it does **not** write `IRQSTAT` — `LLE_DevInit` does that.
    fn phy_status_clear(&mut self) {
        let cmd = unsafe { regs::read(LLE_BASE, lle::CMD) };
        if cmd & 0x3 != 0 {
            self.engine_shut();
        }
    }

    /// `LLE_DevInit` (`lle.o`): timeout block, `+0x04` mask, `+0x06` halfword,
    /// `+0x54 = 0`, RX DMA pointer, sticky status and guard value.
    fn lle_dev_init(&mut self) {
        unsafe {
            for store in LLE_DEV_INIT.stores {
                regs::write(LLE_BASE, store.offset as usize, store.value);
            }
            // `LLE+0x04 &= 0xFFFF_FFE1` keeps the CRC-enable bit 0.
            if let Some(mask) = LLE_DEV_INIT.crc_aa_cfg_clear_mask {
                regs::rmw(LLE_BASE, lle::CRC_AA_CFG, !mask, 0);
            }
            regs::write_u16(LLE_BASE, lle5::CTRL06, 2);
            // `+0x54 = 0` is already in the table above; re-store after the
            // halfword to keep the vendor's order cheap to follow.
            regs::write(LLE_BASE, 0x54, 0);
            regs::write(LLE_BASE, lle5::RXBUFPTR, self.rx_dma as u32);
            regs::write(LLE_BASE, lle::IRQSTAT, 0xffff_ffff);
            regs::write(LLE_BASE, lle::GUARD, 0x001f_000f);
        }
    }

    /// `RFEND_DevInit` (`rfend.o`) — dense RMW block, no reset pulse.
    fn rfend_dev_init_rmw(&mut self) {
        unsafe {
            regs::write(RFEND_BASE, rfend::CFG28, RFEND_INIT.dev_init_0x28.value);

            // +0x3C: vendor `w & 0xF8FFFFFF | bit25` — `rmw` takes a clear
            // mask, so clear bits 26..24 (not 31..27/23..0). Then clear the top
            // three bits (`slli 3 / srli 3`) and set bit30.
            regs::rmw(RFEND_BASE, rfend5::CFG3C, 0x0700_0000, 0x0200_0000);
            regs::rmw(RFEND_BASE, rfend5::CFG3C, 0xe000_0000, 0x4000_0000);

            // +0x30
            regs::rmw(RFEND_BASE, rfend5::CFG30, 0, 0x700);
            regs::rmw(RFEND_BASE, rfend5::CFG30, 0, 0x7000);
            regs::rmw(RFEND_BASE, rfend5::CFG30, 0, 0x7_0000);
            regs::rmw(RFEND_BASE, rfend5::CFG30, 0x7000_0000, 0x1000_0000);

            // +0x48: clear bits 16..18.
            regs::rmw(RFEND_BASE, rfend5::CFG48, 0x0007_0000, 0);

            // +0x4C: clear bits 0..2, 4..6, 16..17.
            regs::rmw(RFEND_BASE, rfend5::CFG4C, 0x0000_0007, 0);
            regs::rmw(RFEND_BASE, rfend5::CFG4C, 0x0000_0070, 0);
            regs::rmw(RFEND_BASE, rfend5::CFG4C, 0x0003_0000, 0);

            // +0x5C: clear bits 16..18 and 20..22 (CH592 also touches 16..22
            // via different masks; the net effect here is not identical).
            regs::rmw(RFEND_BASE, rfend5::CFG5C, 0x0007_0000, 0);
            regs::rmw(RFEND_BASE, rfend5::CFG5C, 0x0070_0000, 0);

            // Vendor ends with a 100-iteration `nop` settle loop.
            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }
    }

    /// `BB_DevInit` (`bb.o`) — includes the RFEND+0x5C power pack.
    fn bb_dev_init(&mut self) {
        let tp = self.tx_power;
        let signed = i32::from(tp as i8);
        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, 0, bb5::TX_TRIG);
            regs::write(BB_BASE, bb::IRQSTAT, 0x3ff);
            regs::write(BB_BASE, bb::CFG34, BB_DEV_INIT.cfg34.value);

            regs::rmw(BB_BASE, bb::AUTOCFG, 0, 0x8000_0000);
            // Vendor `w & 0x81FFFFFF | (tp & 0x3f) << 25`: clear the power
            // field bits 30..25, keep everything else (including bit31).
            regs::rmw(
                BB_BASE,
                bb::AUTOCFG,
                0x7e00_0000,
                (u32::from(tp) & 0x3f) << 25,
            );

            // RFEND+0x5C power-class bits. The lowest class sets bit24
            // (`bseti 0x18`) on CH585; CH592 uses bit28. The vendor masks with
            // `0xF8FFFFFF` (clears 26..24), so the clear mask here is 0x0700_0000.
            if signed > 58 {
                regs::rmw(RFEND_BASE, rfend5::CFG5C, 0, 0x7000_0000);
            } else if signed > 34 {
                regs::rmw(RFEND_BASE, rfend5::CFG5C, 0x0700_0000, 0x5000_0000);
            } else if signed > 26 {
                regs::rmw(RFEND_BASE, rfend5::CFG5C, 0x0700_0000, 0x3000_0000);
            } else {
                regs::rmw(RFEND_BASE, rfend5::CFG5C, 0x0700_0000, 0x0100_0000);
            }

            let cfg3c = BB_DEV_INIT.cfg3c.map_or(0, |r| r.value);
            regs::write(BB_BASE, 0x3c, cfg3c);

            // BB+0x10 low six bits = 0x0E.
            regs::rmw(BB_BASE, bb::RXCFG10, 0x3f, 0x0e);
        }
    }

    /// Program `BB+0` channel/whitening and the hop-map channel register.
    ///
    /// `ll_advertise_tx` / `LL_ScanSetRF` write `BB+0[6:0]`; `BLE_CheckChannel`
    /// additionally writes `BB+0x5C[8:0]` (present on CH585 — the CH59x map is
    /// the same here).
    fn program_channel_bb(&mut self, channel: u8) {
        let whiten = if self.whiten_disabled {
            bb5::WHITEN_OFF
        } else {
            0
        };
        let ch = u32::from(channel & 0x3f);
        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, 0x7f, ch | whiten);
            regs::rmw(BB_BASE, bb5::CH_IDX, 0x1ff, u32::from(channel));
        }
    }

    /// W1C `IRQSTAT` bits under the vendor guard toggle.
    ///
    /// `BLE_SetPHYTxMode` clears **bit 17 of `LLE+0x0C`** around the
    /// `0x0002_0000` write: without it the arm-clear W1C is dropped.
    fn irq_clear_guarded(&self, bits: u32) {
        unsafe {
            let saved = regs::read(LLE_BASE, lle::GUARD);
            regs::write(LLE_BASE, lle::GUARD, saved & !lle5_irq::CLEAR_ARM);
            analog::fence_i();
            regs::write(LLE_BASE, lle::IRQSTAT, bits);
            regs::write(LLE_BASE, lle::GUARD, saved);
        }
    }

    /// Vendor `RFEND_WaitTune` (`LLE+0x64 = 0x1F40`, TUNE_CO bits 25|26).
    fn wait_tune<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        unsafe { analog::wait_tune(clock, LLE_BASE, RFEND_BASE, WAIT_TUNE_HALF_US) }
    }

    /// Vendor `RFEND_TXCtune`: measure 2401/2480/2440/2522 and interpolate the
    /// VCO tables. The 4th (2522) sample is stored by the vendor but never
    /// used by the interpolation — reproduce it for fidelity.
    fn rf_txctune<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        let mut co = [0u8; 4];
        let mut ga = [0u8; 4];

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

            // Interpolation uses 2401 → 2440 (39 steps) and 2440 → 2480
            // (40 steps); the 2522 sample is unused.
            let co_low = i32::from(co[0]) - i32::from(co[1]);
            let co_high = i32::from(co[1]) - i32::from(co[2]);
            let ga_low = i32::from(ga[0]) - i32::from(ga[1]);
            let ga_high = i32::from(ga[1]) - i32::from(ga[2]);

            // VCOTAB nibbles 0..=39 (low side, 39 channels) and 40..=80
            // (high side, index 80 lands in the first nibble of the GA word).
            for i in 0..40usize {
                analog::nibble_write(RFEND_BASE, rfend::VCOTAB, i, co_low * (39 - i as i32) / 39);
            }
            for i in 1..=41usize {
                analog::nibble_write(RFEND_BASE, rfend::VCOTAB, 39 + i, co_high * i as i32 / 40);
            }
            // GA nibbles 2..=11 (high side, `| 8`), 12 = 0, 13..=22 (low side).
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

    /// Vendor `RFEND_TXFtune`.
    fn rf_txftune(&mut self) {
        unsafe {
            regs::rmw(RFEND_BASE, rfend5::TUNE, 0, rfend::TUNE_TXFTUNE);
        }
    }

    /// Vendor `RFEND_RXFilter` (CH585 arms `TUNE` bit 12, not bit 16).
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
            regs::rmw(RFEND_BASE, rfend5::TUNE, 0, TUNE_FILT_ARM);
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

    /// Vendor `RFEND_RXAdc`.
    fn rf_rxadc(&mut self) {
        unsafe {
            regs::rmw(RFEND_BASE, rfend5::CFG58, rfend::FECTRL_RXADC, 0);
            regs::rmw(RFEND_BASE, rfend5::FECTRL, 0, rfend::FECTRL_RXADC);
            regs::rmw(RFEND_BASE, rfend5::CFG0C, rfend::CFG0C_RXADC, 0);
            regs::rmw(RFEND_BASE, rfend5::TUNE, rfend::TUNE_RXADC, 0);
            regs::rmw(RFEND_BASE, rfend5::CFG0C, 0, rfend::CFG0C_RXADC);
            regs::rmw(RFEND_BASE, rfend5::TUNE, 0, rfend::TUNE_RXADC);
        }
    }

    /// Vendor `BLE_SetPHYTxMode` for the 1M/2M legacy paths.
    ///
    /// Vendor phy numbering: mode `1` is 2M, everything else (including coded
    /// on this path) takes the 1M branch. CH585 computes
    /// `2*((len<<3) + adj + 0xEE)` / `2*((len<<2) + adj + 0xCA)`, identical to
    /// [`v208_tx_window_half_us`] with a zero DTM adjustment byte.
    fn set_phy_tx_mode(&mut self, mode: PhyMode, payload_len: u8) {
        let is_2m = matches!(mode, PhyMode::Rate2m);
        let phy = if is_2m {
            PhyMode::Rate2m
        } else {
            PhyMode::Rate1m
        };
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
                v208_tx_window_half_us(phy, payload_len),
            );
            regs::write(LLE_BASE, lle::GUARD, saved);
        }
    }

    /// Vendor `BLE_SetPHYRxMode` (also computes the post-capture reload).
    ///
    /// CH585 computes `16*(len+5)+0x3C` (1M) / `8*(len+5)+0x3C` (2M) and
    /// stores it for the BB ISR; `LL_ScanSetRF` arms with `len = 255`. The same
    /// two-branch split applies to coded modes here.
    fn set_phy_rx_mode(&mut self, mode: PhyMode, rx_max_len: u16) {
        let is_2m = matches!(mode, PhyMode::Rate2m);
        let phy = if is_2m {
            PhyMode::Rate2m
        } else {
            PhyMode::Rate1m
        };
        self.rx_reload_half_us = v208_rx_capture_reload_half_us(phy);
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

    fn apply_aa_crc(&self) {
        unsafe {
            regs::write(BB_BASE, bb::ACCESSADDR, self.access_address);
            regs::write(BB_BASE, bb::CRCINIT, self.crc_init & 0x00ff_ffff);
        }
    }

    /// Vendor `ble_ll_hw_api_shut` (`ip.o`).
    fn engine_shut(&mut self) {
        unsafe {
            regs::rmw(LLE_BASE, lle::MODE, lle5_mode::SHUT_MASK, 0);
            for _ in 0..4 {
                core::hint::spin_loop();
            }
            let cmd = regs::read(LLE_BASE, lle::CMD);
            regs::write(LLE_BASE, lle::CMD, cmd | 0x8);
            for _ in 0..4 {
                core::hint::spin_loop();
            }
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, bb5::DIR_IDLE);
            let v = regs::read(RFEND_BASE, rfend5::FECTRL) & rfend::FECTRL_SHUT_MASK;
            regs::write(RFEND_BASE, rfend5::FECTRL, v);
            regs::write(LLE_BASE, lle::MODE, lle5_mode::POST_INIT);
        }
    }
}

impl AnalogInit for Ch585Radio {
    fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        // No reset pulse on CH585.
        self.rfend_dev_init_rmw();
        Ok(())
    }

    /// `BLE_RegInit` calibration block (steps after `BB_DevInit`).
    fn calibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, 0, bb5::PHY_2M);
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, 0);
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, bb5::DIR_RX);
            regs::rmw(RFEND_BASE, rfend5::FECTRL, 0, rfend::FECTRL_RF_ON);
            regs::write(LLE_BASE, lle::MODE, lle5_mode::INIT);
        }

        let result = self.rf_txctune(clock).and_then(|()| {
            self.rf_txftune();
            self.rf_rxfilter(clock)
        });
        if result.is_ok() {
            self.rf_rxadc();
        }

        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, bb5::DIR_IDLE);
            // `BLE_RegInit` tail: `FECTRL &= 0xFFCD_FFFF`. Bit 16 is the RF
            // block's steady-state enable and must survive.
            let v = regs::read(RFEND_BASE, rfend5::FECTRL) & rfend::FECTRL_SHUT_MASK;
            regs::write(RFEND_BASE, rfend5::FECTRL, v);
            regs::write(LLE_BASE, lle::MODE, lle5_mode::POST_INIT);
        }
        result
    }
}

impl Radio for Ch585Radio {
    fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        // `BLE_RegInit`: status clear → LLE → RFEND → BB → calibration.
        self.phy_status_clear();
        self.lle_dev_init();
        self.rfend_dev_init(clock)?;
        self.bb_dev_init();
        self.calibrate(clock)?;

        self.channel = 0xff;
        self.isr.clear_rx_flags();
        self.rx_active = self.rx_dma;
        unsafe {
            regs::write(LLE_BASE, lle5::RXBUFPTR, self.rx_dma as u32);
        }
        let _ = (IRQ_BB, IRQ_LLE);
        Ok(())
    }

    fn recalibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        if unsafe { regs::read(LLE_BASE, lle::CMD) & 0x3 } != 0 {
            return Err(Error::Busy);
        }
        self.calibrate(clock)
    }

    fn shut(&mut self) {
        self.engine_shut();
        self.isr.clear_rx_flags();
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        if channel > 39 {
            return Err(Error::InvalidState);
        }
        self.program_channel_bb(channel);
        self.channel = channel;
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

        // Unscheduled advertising retains its proven 60-us pre-arm. A
        // scheduled response follows the working V208 basic-TX ordering:
        // prepare with the countdown stopped, then wait for the absolute
        // deadline below. Spending an advertising pre-arm here made every
        // CH585 scan response miss the RX_DONE + 120-us starting deadline.
        let advertising_prearm = start_cputime.is_none();
        unsafe {
            regs::write(
                LLE_BASE,
                lle::WINDOW,
                if advertising_prearm { 0x78 } else { 0 },
            );
            regs::rmw(
                BB_BASE,
                bb::AUTOCFG,
                0x3,
                if advertising_prearm { 0x1 } else { 0 },
            );
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, 0);
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, bb5::DIR_RX);
            regs::rmw(RFEND_BASE, rfend5::FECTRL, 0, rfend::FECTRL_RF_ON);
            regs::write(LLE_BASE, lle::MODE, lle5_mode::TX);
        }

        // `ll_advertise_tx` clears the RFEND fractional-synth enable right
        // after `LLE+0x50 = TX`; the BLE path selects the carrier through
        // `BB+0[6:0]` alone.
        unsafe {
            regs::rmw(RFEND_BASE, rfend5::FREQMODE, rfend::FREQMODE_EN, 0);
        }
        self.program_channel_bb(self.channel);

        // Before `BLE_SetPHYTxMode` rewrites `LLE+0x64`, `ll_tx_wait_finish`
        // lets the `0x78` pre-arm countdown expire.
        let arm_wait = clock.now_us();
        while advertising_prearm && unsafe { regs::read(LLE_BASE, lle::WINDOW) } != 0 {
            if clock.now_us().wrapping_sub(arm_wait) > 100 {
                break;
            }
        }

        unsafe {
            self.apply_aa_crc();
            regs::write(LLE_BASE, lle5::TXBUFPTR, tx_ptr as u32);
            // `ll_advertise_tx` enables CRC on `LLE+0x04` bit 0 before the
            // trigger. (`LLE+0x06` stays at the `LLE_DevInit` value `2`.)
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

    fn rx_basic<T: InstantUs>(
        &mut self,
        _clock: &T,
        rxbuf: &mut [u8],
        window_half_us: u32,
    ) -> Result<()> {
        if rxbuf.len() < RX_DMA_MIN || (rxbuf.as_ptr() as usize) & 0x3 != 0 {
            return Err(Error::InvalidState);
        }
        if self.channel > 39 {
            return Err(Error::InvalidState);
        }

        // `LL_ScanSetRF` starts with `phy_status_clear(6)`: force-stop a stale
        // LLE command before re-arming.
        if unsafe { regs::read(LLE_BASE, lle::CMD) & 0x3 } != 0 {
            self.engine_shut();
        }

        // Follow `LL_ScanSetRF` (the BLE-stack scanner): AA/CRC, `CRC_AA_CFG`
        // bit 0, PHY mode, then `FREQMODE` off → channel → direction → RF on →
        // `LLE+0x50 = RX` → `CMD=1`. It never rewrites `LLE+0x06` and never
        // programs the RFEND fractional synth.
        self.apply_aa_crc();
        self.set_phy_rx_mode(self.phy_rx, rxbuf.len() as u16);
        unsafe {
            regs::rmw(LLE_BASE, lle::CRC_AA_CFG, 0, 0x1);
            regs::rmw(RFEND_BASE, rfend5::FREQMODE, rfend::FREQMODE_EN, 0);
        }
        self.program_channel_bb(self.channel);
        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, 0);
            regs::rmw(BB_BASE, bb::RFCTRL, bb5::DIR_MASK, bb5::DIR_RX);
        }

        let rx_ptr = rxbuf.as_mut_ptr();
        self.rx_active = rx_ptr;
        self.isr.rx_armed = true;
        self.isr.rx_captured = false;

        // `LL_ScanSetRF` clears `LLE+0x64` and W1C bit 17 before arming; the
        // arm-clear needs the guard toggle, the rest is plain W1C.
        self.irq_clear_guarded(lle5_irq::RX_DONE | lle5_irq::TX_DONE | lle5_irq::CLEAR_ARM);

        unsafe {
            regs::write(LLE_BASE, lle::WINDOW, 0);
            regs::write(LLE_BASE, lle5::RXBUFPTR, rx_ptr as u32);
            regs::write(LLE_BASE, lle::MODE, lle5_mode::RX);
            regs::rmw(RFEND_BASE, rfend5::FECTRL, 0, rfend::FECTRL_RF_ON);
            regs::write(LLE_BASE, lle::CMD, 1);
            if window_half_us != 0 {
                regs::write(LLE_BASE, lle::WINDOW, window_half_us);
            }
        }
        Ok(())
    }

    fn rssi(&self) -> i8 {
        let v = unsafe { regs::read(BB_BASE, bb::RSSICFO) };
        (v >> 15) as u8 as i8
    }

    fn crc_ok(&self) -> bool {
        unsafe { regs::read(BB_BASE, bb::IRQSTAT) & bb_irq::CRC_ERR == 0 }
    }
}
