//! CH573 BLE IP bases, DevInit tables from EVT, and DMA-block TX/RX bring-up.
//!
//! Tables recovered from `CH573EVT/EXAM/BLE/LIB/libCH57xBLE.a`
//! (`lle.o` / `bb.o` / `rfend.o` / `dma.o` / `ip.o` / `rf_fh.o`).
//!
//! Map (same CH5xx window as CH583/585/592):
//! - DMA   `0x4000_C000`  ← buffer pointers live here (not on LLE)
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21 (PAC / vector table)
//!
//! Hard constraint: SRAM is only `0x2000_3800..0x2000_8000` (18 KiB), and DMA
//! reaches just the high half (`0x2000_4000..0x2000_8000`) because pointer
//! registers keep the low 14 bits. Low-SRAM buffers alias and read back
//! garbage.

use crate::rf::analog::{self, AnalogInit};
use crate::rf::family::caps::FamilyCaps;
use crate::rf::family::tables::{self, BbDevInit, Certainty, LleDevInit, RegInit, RfendInit};
use crate::rf::isr::IsrState;
use crate::rf::regs::{self, autocfg, bb, lle, lle_cmd, lle_irq, lle_mode, rfctrl, rfend};
use crate::rf::txrx::{tx_frame_valid, RX_DMA_MIN};
use crate::rf::{Channel, PhyMode, Radio, RfCallback};
use crate::time::InstantUs;
use crate::{Error, Result};

/// Separate DMA register block (`gptrDMAReg` from `BLE_IPCoreInit`).
pub const DMA_BASE: usize = 0x4000_C000;
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

/// Inclusive start of the DMA-reachable SRAM window.
///
/// CH573 DMA address registers keep only the low 14 bits, so the engine reaches
/// `0x2000_4000 | (reg & 0x3FFF)` = the last 16 KiB of the 18 KiB SRAM. Buffers
/// below `0x4000` alias and read back garbage (see ch5xx-hal `docs/dma-window.md`).
pub const SRAM_START: usize = 0x2000_4000;
/// Exclusive end of the SRAM window.
pub const SRAM_END: usize = 0x2000_8000;

use Certainty::FromClosedDisasm as Disasm;

/// DMA-block offsets (`dma.o` / `RF_Tx` / `RF_Rx` / `ll_scan`).
///
/// `DMA_DevInit` seeds `+0x10/+0x14` from `gBleIPPara[0x14]` and
/// `+0x18/+0x1c` from `gBleIPPara[0x18]`; `llScanCreateCore` shows `[0x14]` is
/// the TX buffer and `[0x18]` the RX buffer the stack parses.
mod dma_reg {
    pub const CTRL: usize = 0x00;
    pub const CFG08: usize = 0x08;
    pub const CFG0C: usize = 0x0c;
    pub const TXBUFPTR: usize = 0x10;
    /// BLE stack TX buffer (`ll_scan` SCAN_REQ / `ll_slave` data TX).
    pub const TXBUFPTR_ALT: usize = 0x14;
    /// BLE stack RX buffer — where received PDUs land.
    pub const RXBUFPTR: usize = 0x18;
    pub const AUX1C: usize = 0x1c;
}

/// CH573 LLE countdown / window used by `RF_Tx` (not V208 `+0x64`).
const LLE_COUNT: usize = 0x60;

/// `LLE_DevInit` absolute stores (`lle.o`).
///
/// Differs from CH583 old tables: timeouts `0x50`/`0x0A`, mask `0xC303`,
/// and an extra `+0x58 = 0xF6`. No `+0x08` clear observed in this body.
/// UNCERTAIN on silicon: PFIC unmask at the end belongs in the HAL.
pub const LLE_DEV_INIT: LleDevInit = LleDevInit {
    stores: &[
        RegInit::new(0x14, 0x50, Disasm),
        RegInit::new(0x1c, 0x0a, Disasm),
        RegInit::new(0x24, 0x8c, Disasm),
        RegInit::new(0x2c, 0x3c, Disasm),
        RegInit::new(0x34, 0x8c, Disasm),
        RegInit::new(0x3c, 0x3c, Disasm),
        RegInit::new(0x44, 0x50, Disasm),
        RegInit::new(0x4c, 0x0a, Disasm),
        RegInit::new(0x58, 0xf6, Disasm),
        RegInit::new(0x0c, 0x0000_c303, Disasm),
    ],
    crc_aa_cfg_clear_mask: None,
};

/// `BB_DevInit` highlights (`bb.o`).
///
/// `BB+0x34 = 0x152` (not CH583/V208 `0x1D0`). Full `BB+0` packing and the
/// SYS SAFE_ACCESS poke stay outside this first apply path.
pub const BB_DEV_INIT: BbDevInit = BbDevInit {
    cfg34: RegInit::new(0x34, 0x152, Disasm),
    cfg20: None,
    irqstat: None,
    cfg3c: None,
    set_bit23: false,
    set_bit28: false,
    certainty: Disasm,
};

/// RFEND markers (`rfend.o`).
///
/// `RFEND_Reset` exists but is a multi-step `+0x0C` bit bang, not a single
/// `0x1101` store. `RFEND_WaitTune` busy-waits a software countdown
/// (`0x249F2`) while polling `RFEND+0x90` — it does **not** load `LLE+0x64`.
/// TXCtune is a large 3-pass calibrate; keep the usual 3-band markers.
pub const RFEND_INIT: RfendInit = RfendInit {
    reset_pulse: None,
    dev_init_0x28: RegInit::new(0x28, 0x480, Disasm),
    // Software poll iterations in `RFEND_WaitTune`, not an LLE+0x64 store.
    wait_tune_half_us: RegInit::new(0x64, 0x0002_49f2, Disasm),
    vco_mhz: &[2401, 2440, 2480],
    certainty: Disasm,
};

/// CH573: buffer pointers are on the DMA block, not LLE.
pub const CAPS: FamilyCaps = FamilyCaps {
    bb_base: BB_BASE,
    lle_base: LLE_BASE,
    aes_base: AES_BASE,
    rfend_base: RFEND_BASE,
    irq_bb: IRQ_BB,
    irq_lle: IRQ_LLE,
    bufptr_base: DMA_BASE,
    tx_bufptr_off: dma_reg::TXBUFPTR,
    rx_bufptr_off: dma_reg::RXBUFPTR,
    sram_start: SRAM_START,
    sram_end: SRAM_END,
    vco_mhz: RFEND_INIT.vco_mhz,
    wait_tune_half_us: RFEND_INIT.wait_tune_half_us.value,
};

/// CH573 radio — DevInit + DMA-block TX/RX (V208-shaped MODE words).
#[derive(Debug)]
pub struct Ch573Radio {
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
    /// Caller buffer armed by the current RX window.
    rx_buf: *mut u8,
    rx_buf_len: usize,
    /// `BB_IRQLibHandler` reloads `LLE+0x60` once per window.
    rx_reloaded: bool,
    /// `FILTMEAS[4:0]` that `RFEND_RXFilter` wrote into `CFG50`.
    rx_filter_code: u8,
    /// Whether `RFEND_RXFilter` saw the measurement-ready bit.
    rx_filter_ok: bool,
}

/// Result of servicing an armed RX window with [`Ch573Radio::rx_poll`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxPoll {
    /// Still listening; poll again.
    Armed,
    /// The window drained without a PDU.
    Timeout,
    /// A PDU completed; `len` is the PDU length byte, `rssi` in dBm.
    ///
    /// `crc_ok` is `BB+0x38` bit5 sampled when `RX_DONE` is seen — the same
    /// bit the vendor's `ble_ll_chkcrc` tests. The gate is conservative: it
    /// can reject weak-signal frames whose CRC the sniffer accepts.
    Done { len: u8, rssi: i8, crc_ok: bool },
}

/// `BB+0x38` events the vendor `BB_IRQLibHandler` serves.
const BB_PAYLOAD_EVENT: u32 = 0x40;
const BB_TIMER1_EVENT: u32 = 0x02;
const BB_TIMER2_EVENT: u32 = 0x10;
/// Sticky CRC-error flag; `ble_ll_chkcrc` tests `(BB+0x38 >> 5) & 1`.
const BB_CRC_ERR: u32 = 0x20;

// Soft state only; MMIO runs through fixed bases.
unsafe impl Send for Ch573Radio {}

impl Ch573Radio {
    /// Own a DMA-capable RX scratch; must sit inside [`CAPS`] SRAM.
    pub fn new(rx_dma: &'static mut [u8]) -> Result<Self> {
        let ptr = rx_dma.as_mut_ptr() as usize;
        if rx_dma.len() < RX_DMA_MIN || ptr & 0x3 != 0 || !CAPS.contains_dma(ptr, rx_dma.len()) {
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
            rx_dma: rx_dma.as_mut_ptr(),
            rx_dma_len: rx_dma.len(),
            rx_buf: core::ptr::null_mut(),
            rx_buf_len: 0,
            rx_reloaded: false,
            rx_filter_code: 0,
            rx_filter_ok: false,
        })
    }

    fn lle_dev_init(&mut self) {
        unsafe {
            tables::apply_stores(LLE_BASE, LLE_DEV_INIT.stores);
        }
    }

    /// DMA bufptr fields take a 16-bit offset from `0x2000_0000`.
    fn dma_off(ptr: usize) -> u32 {
        (ptr as u32) & 0xfffc
    }

    /// `DMA_DevInit` enables + seed RX/TX ptrs (`dma.o`).
    ///
    /// EVT seeds +0x10/+0x14 and +0x18/+0x1c from `gBleIPPara` buffers; we
    /// point all four at the owned RX scratch until per-transfer programming.
    fn dma_dev_init(&mut self) {
        let off = Self::dma_off(self.rx_dma as usize);
        unsafe {
            regs::write(DMA_BASE, dma_reg::TXBUFPTR, off);
            regs::write(DMA_BASE, dma_reg::TXBUFPTR_ALT, off);
            regs::write(DMA_BASE, dma_reg::RXBUFPTR, off);
            regs::write(DMA_BASE, dma_reg::AUX1C, off);
            // OR enables in EVT order: +0x08/+0x0c |= 0x2000, then |= 0x1000;
            // +0x00 |= 0x02 then |= 0x20.
            regs::rmw(DMA_BASE, dma_reg::CFG08, 0, 0x2000);
            regs::rmw(DMA_BASE, dma_reg::CFG0C, 0, 0x2000);
            regs::rmw(DMA_BASE, dma_reg::CFG08, 0, 0x1000);
            regs::rmw(DMA_BASE, dma_reg::CFG0C, 0, 0x1000);
            regs::rmw(DMA_BASE, dma_reg::CTRL, 0, 0x02);
            regs::rmw(DMA_BASE, dma_reg::CTRL, 0, 0x20);
        }
        let _ = self.rx_dma_len;
    }

    /// `RFEND_Reset` — pulse `+0x0C` bits with short settles (`rfend.o`).
    fn rfend_reset(&mut self) {
        fn settle() {
            for _ in 0..20 {
                core::hint::spin_loop();
            }
        }
        // Exact EVT order: tone bit12 {1,0,1}, bit0 {1,0,1}, bit8 {1,0,1}.
        for &(mask, val) in &[
            (0, 0x1000u32),
            (0x1000, 0),
            (0, 0x1000),
            (0, 0x1),
            (0x1, 0),
            (0, 0x1),
            (0, 0x100),
            (0x100, 0),
            (0, 0x100),
        ] {
            unsafe { regs::rmw(RFEND_BASE, rfend::CFG0C, mask, val) };
            settle();
        }
    }

    /// Absolute `+0x28` plus the dense RMW block from `RFEND_DevInit`.
    fn rfend_dev_init_abs(&mut self) {
        self.rfend_reset();
        unsafe {
            regs::write(RFEND_BASE, rfend::CFG28, RFEND_INIT.dev_init_0x28.value);

            // +0x48
            regs::rmw(RFEND_BASE, rfend::CFG48, 0x7000_0000, 0x2000_0000);
            regs::rmw(RFEND_BASE, rfend::CFG48, 0x0700_0000, 0x0400_0000);
            regs::rmw(RFEND_BASE, rfend::CFG48, 0x0000_000f, 0x0000_0009);
            regs::rmw(RFEND_BASE, rfend::CFG48, 0x0007_0000, 0);
            regs::rmw(RFEND_BASE, rfend::CFG48, 0, 0x8000_0000);

            // +0x4c
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0x7, 0x3);
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0x70, 0x30);
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0x700, 0x300);
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0x0100_0000, 0);
            regs::rmw(RFEND_BASE, rfend::CFG4C, 0, 0x0200_0000);

            // +0x50 / +0x54
            regs::rmw(RFEND_BASE, rfend::CFG50, 0x0000_f000, 0x0000_4000);
            regs::rmw(RFEND_BASE, rfend::CFG54, 0xf, 0xc);
            regs::rmw(RFEND_BASE, rfend::CFG54, 0, 0x80);
            regs::rmw(RFEND_BASE, rfend::CFG54, 0x0000_1000, 0);

            // +0x3c
            regs::rmw(RFEND_BASE, 0x3c, 0x0000_f000, 0x0000_8000);
            regs::rmw(RFEND_BASE, 0x3c, 0x0700_0000, 0x0200_0000);
            regs::rmw(RFEND_BASE, 0x3c, 0xe000_0000, 0x4000_0000);

            // +0x2c (FREQMODE)
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0, 0x0070_0000);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0x0700_0000, 0);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0x0000_3000, 0x0000_2000);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0x0003_0000, 0x0002_0000);

            // +0x30
            regs::rmw(RFEND_BASE, rfend::CFG30, 0xf, 0);
            regs::rmw(RFEND_BASE, rfend::CFG30, 0xf0, 0);
            regs::rmw(RFEND_BASE, rfend::CFG30, 0x700, 0);
            regs::rmw(RFEND_BASE, rfend::CFG30, 0, 0x0070_0000);
            regs::rmw(RFEND_BASE, rfend::CFG30, 0x7000_0000, 0x5000_0000);

            // +0x38
            regs::rmw(RFEND_BASE, rfend::CFG38, 0x0038_0000, 0x0018_0000);
            regs::rmw(RFEND_BASE, rfend::CFG38, 0, 0x8000_0000);

            for _ in 0..100 {
                core::hint::spin_loop();
            }
        }
    }

    /// `BB_DevInit` — RFCTRL power/trig, AUTOCFG, RXCFG18, CFG34, AUX_POWER.
    fn bb_dev_init_abs(&mut self) {
        const SAFE_ACCESS: usize = 0x4000_1040;
        const AUX_POWER_ADJ: usize = 0x4000_1022;
        // EVT default TX power class (~0 dBm).
        const TX_POWER: u32 = 0x14;
        unsafe {
            // OR 0x1008_0000, then replace bits[13:8] with power.
            let v = (regs::read(BB_BASE, bb::RFCTRL) | 0x1008_0000) & !0x0000_3f00
                | ((TX_POWER & 0x3f) << 8);
            regs::write(BB_BASE, bb::RFCTRL, v);

            // SAFE_ACCESS → AUX_POWER_ADJ bit4 (BLE LDO / aux rail).
            core::ptr::write_volatile(SAFE_ACCESS as *mut u8, 0x57);
            core::ptr::write_volatile(SAFE_ACCESS as *mut u8, 0xa8);
            let adj = core::ptr::read_volatile(AUX_POWER_ADJ as *const u16);
            core::ptr::write_volatile(AUX_POWER_ADJ as *mut u16, adj | 0x10);
            core::ptr::write_volatile(SAFE_ACCESS as *mut u8, 0);

            regs::write(BB_BASE, bb::AUTOCFG, 0x0001_0e78);
            regs::rmw(BB_BASE, bb::RXCFG18, 0, 0x8000);
            regs::rmw(BB_BASE, bb::RXCFG18, 0x7f80, 0x3500);
            regs::write(
                BB_BASE,
                BB_DEV_INIT.cfg34.offset as usize,
                BB_DEV_INIT.cfg34.value,
            );
        }
    }

    fn engine_stop(&mut self) {
        unsafe {
            // EVT `ble_ll_hw_api_shut`/`RF_Rx`: drop the mode direction bits,
            // request a forced stop, then wait for the engine to report idle.
            regs::rmw(LLE_BASE, lle::MODE, lle_mode::DIR_MASK, 0);
            regs::rmw(LLE_BASE, lle::CMD, 0, lle_cmd::FORCE_STOP);
            for _ in 0..10_000 {
                let cmd = regs::read(LLE_BASE, lle::CMD);
                if cmd & (lle_cmd::BUSY_MASK | lle_cmd::FORCE_STOP) == 0 {
                    break;
                }
            }
        }
    }

    /// LLE IRQ flags are plain read/write: clear by writing the bits back as 0.
    fn clear_lle_irq(bits: u32) {
        unsafe {
            let v = regs::read(LLE_BASE, lle::IRQSTAT);
            regs::write(LLE_BASE, lle::IRQSTAT, v & !bits);
        }
    }

    fn program_channel(&mut self, channel: Channel) {
        let whiten = if self.whiten_disabled {
            rfctrl::WHITEN_OFF
        } else {
            0
        };
        unsafe {
            // BLE channel-number mode: clear FREQMODE bits[1:0] (`ll_advertise_tx`).
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0x3, 0);
            // ADV RXCFG18 (`ll_advertise_tx`): clear bits[26:24], set bit25,
            // low = (low & ~0x7d) | 0x18.
            regs::rmw(BB_BASE, bb::RXCFG18, 0x0700_0000, 0x0200_0000);
            regs::rmw(BB_BASE, bb::RXCFG18, 0x7d, 0x18);
            let rfctrl_v = regs::read(BB_BASE, bb::RFCTRL);
            // Clear low 7 (channel + whiten) and SHUT; set channel.
            let v = (rfctrl_v & !(0x7f | rfctrl::SHUT))
                | (u32::from(channel) & rfctrl::CH_MASK)
                | whiten;
            regs::write(BB_BASE, bb::RFCTRL, v);
        }
        self.channel = channel;
    }

    fn apply_aa_crc_regs(&self) {
        unsafe {
            regs::write(BB_BASE, bb::ACCESSADDR, self.access_address);
            regs::write(BB_BASE, bb::CRCINIT, self.crc_init & 0x00ff_ffff);
        }
    }

    /// Clear `RB_SLP_CLK_BLE` so the RF block is clocked (SAFE_ACCESS).
    fn ble_clock_on(&mut self) {
        const SAFE_ACCESS: usize = 0x4000_1040;
        const SLP_CLK_OFF1: usize = 0x4000_100d;
        unsafe {
            core::ptr::write_volatile(SAFE_ACCESS as *mut u8, 0x57);
            core::ptr::write_volatile(SAFE_ACCESS as *mut u8, 0xa8);
            let v = core::ptr::read_volatile(SLP_CLK_OFF1 as *const u8);
            core::ptr::write_volatile(SLP_CLK_OFF1 as *mut u8, v & !0x80);
            core::ptr::write_volatile(SAFE_ACCESS as *mut u8, 0);
        }
    }

    /// Rough 1M airtime window (half-µs), enough for ADV PDUs.
    fn tx_window_half_us(payload_len: u8) -> u32 {
        // EVT RF_Tx: `(len << 4) + 0x1cc` style; keep a generous floor.
        let air = (u32::from(payload_len) << 4).saturating_add(0x1cc);
        air.max(0x200)
    }

    /// `RFEND_TXCtune` — bands `0xC0/0xE7/0xD3` (2401/2480/2440 order).
    fn rf_txctune<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        /// EVT band codes written to `RFEND+0x38[15:8]`.
        const TXCTUNE_BANDS: [u8; 3] = [0xc0, 0xe7, 0xd3];
        /// Maps loop index → sample slot {2401, 2440, 2480} = {0, 2, 1}.
        const TXCTUNE_SAMPLE_INDEX: [usize; 3] = [0, 2, 1];
        let mut co = [0u8; 3];
        let mut ga = [0u8; 3];

        // EVT `RFEND_WaitTune` polls TUNE_CO ready bits with a software budget
        // (`0x249F2`); it does **not** arm LLE+0x64. Use a wall-clock bound.
        let wait_us = 50_000u32;

        unsafe {
            regs::rmw(RFEND_BASE, rfend::TUNE, 0x100, 0);
            regs::rmw(RFEND_BASE, rfend::CFG28, 0x1000, 0);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0x10, 0);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, 0x2_0000);
            regs::rmw(RFEND_BASE, rfend::TUNE, 0, rfend::TUNE_FILT);

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
                let started = clock.now_us();
                loop {
                    let st = regs::read(RFEND_BASE, rfend::TUNE_CO);
                    if (st & rfend::TUNE_READY) == rfend::TUNE_READY {
                        break;
                    }
                    if clock.now_us().wrapping_sub(started) >= wait_us {
                        regs::rmw(RFEND_BASE, rfend::TUNE, 0x11, 0);
                        regs::rmw(RFEND_BASE, rfend::CFG28, 0, 0x1000);
                        regs::rmw(RFEND_BASE, rfend::FREQMODE, 0, 0x10);
                        return Err(Error::Timeout);
                    }
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

            regs::rmw(RFEND_BASE, rfend::TUNE, rfend::TUNE_FILT, 0);
            regs::rmw(RFEND_BASE, rfend::TUNE, rfend::TUNE_TRIG, 0);
            regs::rmw(RFEND_BASE, rfend::CFG28, 0, 0x1000);
            regs::rmw(RFEND_BASE, rfend::FREQMODE, 0, 0x10);
            regs::rmw(RFEND_BASE, rfend::CFG38, 0x3f, u32::from(co[1]));
            regs::rmw(
                RFEND_BASE,
                rfend::CFG38,
                0x7f00_0000,
                u32::from(ga[1]) << 24,
            );
        }
        Ok(())
    }

    /// `RFEND_RXFilter` (`rfend.o`): filter code into `CFG50[4:0]`, CAL mode.
    fn rfend_rx_filter<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        unsafe {
            // EVT clears `CFG50` bit16 (0xFFFEFFFF) before measuring.
            regs::rmw(RFEND_BASE, rfend::CFG50, 0x1_0000, 0);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RXFILT);
            regs::rmw(RFEND_BASE, rfend::CFG0C, 0, 0x10);
            regs::rmw(RFEND_BASE, rfend::CFG0C, 0x10, 0);
            for _ in 0..4 {
                core::hint::spin_loop();
            }
            // Vendor sets CFG0C bit4 a second time after the settle and leaves
            // it set; without it the measurement code is not stable.
            regs::rmw(RFEND_BASE, rfend::CFG0C, 0, 0x10);
            // EVT sets TUNE bit12 and never clears it.
            regs::rmw(RFEND_BASE, rfend::TUNE, 0, 0x1000);
            let start = clock.now_us();
            while regs::read(RFEND_BASE, rfend::FILTMEAS) & rfend::FILTMEAS_RDY == 0 {
                if clock.now_us().wrapping_sub(start) >= 200_000 {
                    self.rx_filter_ok = false;
                    return Err(Error::Timeout);
                }
            }
            regs::rmw(RFEND_BASE, rfend::CFG50, 0, rfend::CFG50_FILT_EN);
            let code = regs::read(RFEND_BASE, rfend::FILTMEAS);
            regs::rmw(RFEND_BASE, rfend::CFG50, 0x1f, code & rfend::FILTMEAS_MASK);
            self.rx_filter_code = (code & rfend::FILTMEAS_MASK) as u8;
            regs::rmw(RFEND_BASE, rfend::FECTRL, rfend::FECTRL_RXFILT, 0);
        }
        self.rx_filter_ok = true;
        Ok(())
    }

    /// `CFG50[4:0]` written by the last `RFEND_RXFilter`.
    pub fn rx_filter_code(&self) -> u8 {
        self.rx_filter_code
    }

    /// Whether the last `RFEND_RXFilter` reached the ready bit.
    pub fn rx_filter_calibrated(&self) -> bool {
        self.rx_filter_ok
    }

    /// `RFEND_RXAdc` (`rfend.o`, `gModeAdc == 0`): min ADC code into
    /// `CFG58[10:7]`, CAL mode.
    fn rfend_rx_adc<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        const MEAS: usize = 0x8c;
        let mut min = 0xfu32;
        let mut nonzero = 0u32;
        unsafe {
            // EVT clears `CFG58` bit16 (0xFFFEFFFF) before measuring.
            regs::rmw(RFEND_BASE, rfend::CFG58, 0x1_0000, 0);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RXADC);
            for _ in 0..16 {
                regs::rmw(RFEND_BASE, rfend::CFG0C, 0x100, 0);
                regs::rmw(RFEND_BASE, rfend::TUNE, 0, rfend::TUNE_RXADC);
                regs::rmw(RFEND_BASE, rfend::CFG0C, 0, 0x100);
                let start = clock.now_us();
                while regs::read(RFEND_BASE, MEAS) & 0x100 == 0 {
                    if clock.now_us().wrapping_sub(start) >= 10_000 {
                        return Err(Error::Timeout);
                    }
                }
                let code = regs::read(RFEND_BASE, MEAS) & 0xf;
                regs::rmw(RFEND_BASE, rfend::TUNE, 0x1000, 0);
                if code != 0xf {
                    nonzero += 1;
                }
                min = min.min(code);
                if nonzero == 3 {
                    break;
                }
            }
            // EVT normalises the min code before storing it.
            let code = if nonzero == 0 {
                0x280 >> 7
            } else if min > 8 {
                min - 3
            } else if min > 4 {
                min - 2
            } else if min > 1 {
                min - 1
            } else if min == 0 {
                3
            } else {
                min
            };
            regs::rmw(RFEND_BASE, rfend::CFG58, 0x781, code << 7);
        }
        Ok(())
    }

    /// `BB_IRQLibHandler` reload value: the payload window grows with the
    /// buffer (`(maxlen + 7) << 4`, EVT `RF_Rx` / `ble_ll_hw_api_rx`).
    fn rx_reload_count(buf_len: usize) -> u32 {
        let max_payload = buf_len.saturating_sub(8).min(0xff) as u32;
        ((max_payload.max(18) + 7) << 4).max(0x1b8)
    }

    /// Buffer offset of the RSSI byte: vendor `ble_ll_chkcrc` finds the status
    /// word at `(len + 5) & 0x1fc` and the RSSI right after it.
    fn rx_rssi_off(len: u8) -> usize {
        ((len as usize + 5) & 0x1fc) + 2
    }

    /// Service BB/LLE flags for the window at `buf` and report its state.
    ///
    /// Mirrors EVT `BB_IRQLibHandler` plus the LLE RX branch. The BB payload
    /// event reloads `LLE+0x60`; without that reload the engine never DMAs the
    /// PDU, so this must run repeatedly while a window is open.
    unsafe fn service_window(buf: *mut u8, buf_len: usize, reloaded: &mut bool) -> RxPoll {
        unsafe {
            // LLE first, then BB: if a frame completes between the two reads,
            // the BB sample still carries that frame's final CRC bit.
            let st = regs::read(LLE_BASE, lle::IRQSTAT);
            let bb = regs::read(BB_BASE, bb::IRQSTAT);
            if st & lle_irq::RX_DONE != 0 {
                // Read the PDU before clearing: once RX_DONE drops the engine
                // may start writing the next frame into the same buffer.
                let (len, rssi) = if buf.is_null() {
                    (0, 0)
                } else {
                    let len = core::ptr::read_volatile(buf.add(1));
                    let off = Self::rx_rssi_off(len);
                    let rssi = if off < buf_len {
                        core::ptr::read_volatile(buf.add(off)) as i8
                    } else {
                        0
                    };
                    (len, rssi)
                };
                // Sample a fresh word: the frame may have completed between
                // the reads above, so the earlier `bb` could predate its CRC.
                let bb = regs::read(BB_BASE, bb::IRQSTAT);
                let crc_ok = bb & BB_CRC_ERR == 0;
                // Write-zero-to-clear: ones leave the other bits alone, so a
                // bit that asserts after the read is not cleared by this write.
                regs::write(
                    BB_BASE,
                    bb::IRQSTAT,
                    !(BB_PAYLOAD_EVENT | BB_CRC_ERR),
                );
                Self::clear_lle_irq(0xffff);
                return RxPoll::Done { len, rssi, crc_ok };
            }
            if bb & BB_PAYLOAD_EVENT != 0 {
                // Clear only the payload event: this driver samples the CRC
                // bit at RX_DONE, and a snapshot-based write could clear a
                // CRC error that asserts before the write lands.
                regs::write(BB_BASE, bb::IRQSTAT, !BB_PAYLOAD_EVENT);
                if !*reloaded {
                    regs::write(LLE_BASE, LLE_COUNT, Self::rx_reload_count(buf_len));
                    *reloaded = true;
                }
            }
            if bb & BB_TIMER1_EVENT != 0 {
                // EVT parks the engine in RX briefly (`0x45`) on this timer.
                regs::write(BB_BASE, bb::IRQSTAT, !BB_TIMER1_EVENT);
                for _ in 0..24 {
                    core::hint::spin_loop();
                }
                regs::write(LLE_BASE, lle::MODE, 0x45);
            }
            if bb & BB_TIMER2_EVENT != 0 {
                regs::write(BB_BASE, bb::IRQSTAT, !BB_TIMER2_EVENT);
                regs::write(LLE_BASE, lle::MODE, 0);
            }

            if regs::read(LLE_BASE, LLE_COUNT) == 0 {
                return RxPoll::Timeout;
            }
        }
        RxPoll::Armed
    }

    /// Poll variant of [`Self::service_window`] for the window armed last.
    ///
    /// Either poll or [`rx_isr_take`], never both: the ISR shares the same
    /// window state. Do not call from an ISR of higher priority than BLE.
    pub unsafe fn rx_poll(&mut self) -> RxPoll {
        let state =
            unsafe { Self::service_window(self.rx_buf, self.rx_buf_len, &mut self.rx_reloaded) };
        if state != RxPoll::Armed {
            isr::armed_store(false);
        }
        state
    }
}

/// Interrupt-path state for [`ble_isr`].
///
/// Only the ISR touches the MMIO; `rx_basic` publishes the buffer and the
/// main loop drains results with [`rx_isr_take`]. Do not mix with `rx_poll`
/// on the same window.
mod isr {
    use core::sync::atomic::{AtomicBool, AtomicI8, AtomicU32, AtomicU8, AtomicUsize, Ordering};

    pub const IDLE: u8 = 0;
    pub const RX: u8 = 1;
    pub const TX: u8 = 2;

    /// Set by [`install_ble_irq`]; until then the polled paths are used.
    pub static INSTALLED: AtomicBool = AtomicBool::new(false);
    pub static MODE: AtomicU8 = AtomicU8::new(IDLE);
    pub static ARMED: AtomicBool = AtomicBool::new(false);
    pub static BUSY: AtomicBool = AtomicBool::new(false);
    pub static BUF: AtomicUsize = AtomicUsize::new(0);
    pub static BUF_LEN: AtomicUsize = AtomicUsize::new(0);
    pub static RELOADED: AtomicBool = AtomicBool::new(false);
    /// CRC status sampled at RX_DONE.
    pub static CRC_OK: AtomicBool = AtomicBool::new(false);
    pub static DONE: AtomicBool = AtomicBool::new(false);
    pub static TIMEOUT: AtomicBool = AtomicBool::new(false);
    pub static LEN: AtomicU8 = AtomicU8::new(0);
    pub static RSSI: AtomicI8 = AtomicI8::new(0);
    pub static TX_KICKED: AtomicBool = AtomicBool::new(false);
    pub static TX_DONE: AtomicBool = AtomicBool::new(false);
    /// Bit9 kicks serviced so far, so callers can tell a real kick apart.
    pub static TX_KICKS: AtomicU32 = AtomicU32::new(0);
    /// Raw SysTick counts: RX done observed, and the TX bit9 kick.
    pub static RX_DONE_TICKS: AtomicU32 = AtomicU32::new(0);
    pub static TX_KICK_TICKS: AtomicU32 = AtomicU32::new(0);
    /// Every `ble_isr` entry, including ones that find no window armed.
    pub static ENTRIES: AtomicU32 = AtomicU32::new(0);

    pub fn entries_add() {
        ENTRIES.fetch_add(1, Ordering::Relaxed);
    }

    pub fn armed_store(on: bool) {
        ARMED.store(on, Ordering::Release);
    }
}

/// PFIC base and interrupt-reset register (word 0 covers IRQs 0..31).
const PFIC_BASE: usize = 0xE000_E000;
const PFIC_ITHRESDR: usize = 0x004;
const PFIC_IRER: usize = 0x180;
const PFIC_IENR: usize = 0x100;
const PFIC_IPRR: usize = 0x280;
/// V3A SysTick free-running down-counter (ticks at HCLK).
const SYSTICK_CNTL: usize = 0xE000_F004;

fn now_ticks() -> u32 {
    unsafe { regs::read(SYSTICK_CNTL, 0) }
}

/// Mask both BLE lines. Once the window is over the LLE line stays asserted
/// by engine state (`LLE+0x08` bit14 / `TICK_CLR`) until the engine stops, so
/// the ISR has to quiet it instead of spinning on it.
///
/// Same sequence as vendor `PFIC_DisableIRQ`: park the threshold, write
/// `IRER`, restore it, then `fence.i` so the mask is visible.
unsafe fn mask_ble_lines() {
    unsafe {
        let thr = regs::read(PFIC_BASE, PFIC_ITHRESDR);
        regs::write(PFIC_BASE, PFIC_ITHRESDR, 0x10);
        regs::write(PFIC_BASE, PFIC_IRER, (1 << 21) | (1 << 20));
        regs::write(PFIC_BASE, PFIC_ITHRESDR, thr);
        core::arch::asm!("fence.i", options(nostack, preserves_flags));
    }
}

/// Unmask both BLE lines for the window just armed. Only called when
/// [`install_ble_irq`] has routed them through the VTF slots.
unsafe fn unmask_ble_lines() {
    unsafe { regs::write(PFIC_BASE, PFIC_IENR, (1 << 21) | (1 << 20)) };
}

/// `LLE_IRQLibHandler` kick: start the baseband when the LLE asks (bit9).
const TX_ARM_EVENT: u32 = 0x200;

unsafe fn tx_kick() {
    unsafe {
        regs::write(LLE_BASE, LLE_COUNT, 0x190);
        regs::rmw(BB_BASE, bb::AUTOCFG, 0x3, 0x2);
        regs::rmw(BB_BASE, bb::RFCTRL, 0, 0x1000_0000);
    }
}

/// Service an armed TX window (bit9 kick, then TX_DONE).
///
/// Runs under the same BUSY guard as the RX path; `tx_basic` is blocking, so
/// only one direction is ever armed.
fn tx_isr() {
    use core::sync::atomic::Ordering;

    if isr::BUSY.swap(true, Ordering::Acquire) {
        return;
    }
    unsafe {
        let st = regs::read(LLE_BASE, lle::IRQSTAT);
        // Kick once per window: the LLE can leave bit9 asserted until the
        // baseband reports done, and re-kicking from a level-triggered line
        // just starves the caller.
        if st & TX_ARM_EVENT != 0 && !isr::TX_KICKED.load(Ordering::Relaxed) {
            tx_kick();
            Ch573Radio::clear_lle_irq(TX_ARM_EVENT);
            isr::TX_KICK_TICKS.store(now_ticks(), Ordering::Relaxed);
            isr::TX_KICKS.fetch_add(1, Ordering::Relaxed);
            isr::TX_KICKED.store(true, Ordering::Release);
        }
        let st = regs::read(LLE_BASE, lle::IRQSTAT);
        if st & lle_irq::TX_DONE != 0 {
            Ch573Radio::clear_lle_irq(lle_irq::TX_DONE);
            mask_ble_lines();
            isr::TX_DONE.store(true, Ordering::Release);
        }
    }
    isr::BUSY.store(false, Ordering::Release);
}

/// Service the BLE IP from a `BLEB` (20) / `BLEL` (21) interrupt handler.
///
/// Cheap to call from both handlers: a second entry returns immediately and
/// the still-asserted PFIC line re-fires once the first one finishes. Only
/// windows armed by `rx_basic` are serviced. On `Done`/`Timeout` the handler
/// masks both lines itself; the caller re-enables them before the next window.
pub fn ble_isr() {
    use core::sync::atomic::Ordering;

    isr::entries_add();
    match isr::MODE.load(Ordering::Acquire) {
        isr::TX => {
            tx_isr();
            return;
        }
        isr::RX => {}
        _ => {
            unsafe { mask_ble_lines() };
            return;
        }
    }
    if !isr::ARMED.load(Ordering::Acquire) {
        unsafe { mask_ble_lines() };
        return;
    }
    if isr::BUSY.swap(true, Ordering::Acquire) {
        return;
    }
    let buf = isr::BUF.load(Ordering::Relaxed) as *mut u8;
    let buf_len = isr::BUF_LEN.load(Ordering::Relaxed);
    let mut reloaded = isr::RELOADED.load(Ordering::Relaxed);
    // SAFETY: `rx_basic` published this buffer and only one handler runs.
    let state = unsafe {
        let state = Ch573Radio::service_window(buf, buf_len, &mut reloaded);
        if state == RxPoll::Armed {
            // The LLE line is level-held by every low flag, and RX windows
            // leave engine bits (e.g. 0x200) set; keep only RX_DONE pending.
            Ch573Radio::clear_lle_irq(0xfffe);
        }
        state
    };
    isr::RELOADED.store(reloaded, Ordering::Relaxed);
    match state {
        RxPoll::Armed => {}
        RxPoll::Timeout => {
            unsafe { mask_ble_lines() };
            isr::armed_store(false);
            isr::TIMEOUT.store(true, Ordering::Release);
        }
        RxPoll::Done { len, rssi, crc_ok } => {
            unsafe { mask_ble_lines() };
            isr::LEN.store(len, Ordering::Relaxed);
            isr::RSSI.store(rssi, Ordering::Relaxed);
            isr::CRC_OK.store(crc_ok, Ordering::Relaxed);
            isr::RX_DONE_TICKS.store(now_ticks(), Ordering::Relaxed);
            isr::armed_store(false);
            isr::DONE.store(true, Ordering::Release);
        }
    }
    isr::BUSY.store(false, Ordering::Release);
}

// Fast-interrupt entry installed by `install_ble_irq`. The VTF path does no
// hardware register stacking (see `LLE_IRQLibFunction` in `lle.o`), so this
// saves every caller-saved register before calling `ble_isr` and `mret`s.
core::arch::global_asm!(
    r#"
    .section .highcode, "ax"
    .align 2
    .global __wchble_ch573_ble_vtf
    .type __wchble_ch573_ble_vtf, @function
__wchble_ch573_ble_vtf:
    addi sp, sp, -64
    sw   ra, 60(sp)
    sw   t0, 56(sp)
    sw   t1, 52(sp)
    sw   t2, 48(sp)
    sw   a0, 44(sp)
    sw   a1, 40(sp)
    sw   a2, 36(sp)
    sw   a3, 32(sp)
    sw   a4, 28(sp)
    sw   a5, 24(sp)
    sw   a6, 20(sp)
    sw   a7, 16(sp)
    sw   t3, 12(sp)
    sw   t4,  8(sp)
    sw   t5,  4(sp)
    sw   t6,  0(sp)
    call __wchble_ch573_ble_vtf_body
    lw   ra, 60(sp)
    lw   t0, 56(sp)
    lw   t1, 52(sp)
    lw   t2, 48(sp)
    lw   a0, 44(sp)
    lw   a1, 40(sp)
    lw   a2, 36(sp)
    lw   a3, 32(sp)
    lw   a4, 28(sp)
    lw   a5, 24(sp)
    lw   a6, 20(sp)
    lw   a7, 16(sp)
    lw   t3, 12(sp)
    lw   t4,  8(sp)
    lw   t5,  4(sp)
    lw   t6,  0(sp)
    addi sp, sp, 64
    mret
"#
);

#[unsafe(no_mangle)]
extern "C" fn __wchble_ch573_ble_vtf_body() {
    ble_isr();
}

extern "C" {
    fn __wchble_ch573_ble_vtf();
}

/// Route BLE IRQ 20/21 through PFIC fast-interrupt slots 2/3.
///
/// Mirrors `PFIC_FastINT2CFG`/`PFIC_FastINT3CFG`, which the vendor library
/// calls from `LLE_DevInit`/`BB_DevInit`. The entry must live in RAM, so the
/// final binary needs the `highcode` feature. Without this the LLE line
/// re-enters forever while `LLE+0x08` low bits read zero.
///
/// # Safety
/// Call once per boot, before enabling the BLE interrupts.
pub unsafe fn install_ble_irq() {
    let addr = __wchble_ch573_ble_vtf as *const () as usize as u32;
    unsafe {
        regs::write(PFIC_BASE, 0x44, addr & 0xF000_0000);
        regs::write(PFIC_BASE, 0x68, (21 << 24) | (addr & 0x000F_FFFF));
        regs::write(PFIC_BASE, 0x6c, (20 << 24) | (addr & 0x000F_FFFF));
    }
    isr::INSTALLED.store(true, core::sync::atomic::Ordering::Release);
}

/// Number of [`ble_isr`] entries so far (diagnostics; wraps).
pub fn irq_entries() -> u32 {
    isr::ENTRIES.load(core::sync::atomic::Ordering::Relaxed)
}

/// SysTick count captured when the ISR last reported RX `Done`.
pub fn rx_done_ticks() -> u32 {
    isr::RX_DONE_TICKS.load(core::sync::atomic::Ordering::Relaxed)
}

/// SysTick count captured at the last TX baseband kick (LLE bit9).
pub fn tx_kick_ticks() -> u32 {
    isr::TX_KICK_TICKS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Number of bit9 TX kicks serviced by the ISR so far (diagnostics; wraps).
pub fn tx_kick_count() -> u32 {
    isr::TX_KICKS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Take a result produced by [`ble_isr`], clearing it.
///
/// The next `rx_basic` discards an unconsumed result; take before re-arming.
/// Do not mix with [`Ch573Radio::rx_poll`] on the same window. Thread context
/// only; see `rx_basic` for the re-arm constraint.
pub fn rx_isr_take() -> Option<RxPoll> {
    use core::sync::atomic::Ordering;

    if isr::DONE.swap(false, Ordering::AcqRel) {
        Some(RxPoll::Done {
            len: isr::LEN.load(Ordering::Relaxed),
            rssi: isr::RSSI.load(Ordering::Relaxed),
            crc_ok: isr::CRC_OK.load(Ordering::Relaxed),
        })
    } else if isr::TIMEOUT.swap(false, Ordering::AcqRel) {
        Some(RxPoll::Timeout)
    } else {
        None
    }
}

impl AnalogInit for Ch573Radio {
    fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        self.rfend_dev_init_abs();
        Ok(())
    }

    fn calibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        // `BLE_RegInit`: put the LLE in CAL mode (0x5d) before TXCtune, then
        // return to idle. Without CAL the VCO tune never executes.
        unsafe { regs::write(LLE_BASE, lle::MODE, lle_mode::CAL) };
        let r = self.rf_txctune(clock);
        // `RFEND_TXFtune`: set TUNE bit8 (still under CAL mode).
        unsafe { regs::rmw(RFEND_BASE, rfend::TUNE, 0, rfend::TUNE_TXFTUNE) };
        // `BLE_RegInit` also runs the RX filter/ADC calibration here; the ADC
        // bias is shared with TX (`FECTRL` bit16 stays set afterwards).
        let _ = self.rfend_rx_filter(clock);
        let _ = self.rfend_rx_adc(clock);
        unsafe { regs::write(LLE_BASE, lle::MODE, 0) };
        // EVT `RFEND_WaitTune` soft-succeeds on counter exhaustion.
        let _ = r;
        Ok(())
    }
}

impl Radio for Ch573Radio {
    fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        // Order: BLE clk → LLE → DMA → RFEND (reset+RMW) → BB → cal.
        self.ble_clock_on();
        self.lle_dev_init();
        self.dma_dev_init();
        self.rfend_dev_init(clock)?;
        self.bb_dev_init_abs();
        self.calibrate(clock)?;
        // RMW clear only: `LLE+0x08` is plain R/W and its upper half carries
        // the DMA state field, so a full `0xffff` store would clobber it.
        Self::clear_lle_irq(0xffff);
        unsafe {
            regs::write(
                DMA_BASE,
                dma_reg::RXBUFPTR,
                Self::dma_off(self.rx_dma as usize),
            );
        }
        Ok(())
    }

    fn recalibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        self.calibrate(clock)
    }

    fn shut(&mut self) {
        self.engine_stop();
        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, rfctrl::SHUT);
            let fectrl = regs::read(RFEND_BASE, rfend::FECTRL);
            regs::write(RFEND_BASE, rfend::FECTRL, fectrl & rfend::FECTRL_SHUT_MASK);
            regs::write(LLE_BASE, lle::MODE, 0);
        }
        self.isr.clear_rx_flags();
        self.rx_buf = core::ptr::null_mut();
        self.rx_buf_len = 0;
        self.rx_reloaded = false;
        isr::armed_store(false);
    }

    fn set_channel(&mut self, channel: Channel) -> Result<()> {
        if channel > 39 {
            return Err(Error::InvalidState);
        }
        self.program_channel(channel);
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

    /// TX one PDU with a short busy-poll for the LLE TX-start event.
    ///
    /// The caller must not let an LLE ISR clear `LLE+0x08` bit9 during the
    /// call (no IRQ handler is installed by this backend).
    unsafe fn tx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        frame: &[u8],
        _timeout_half_us: u32,
        start_cputime: Option<u32>,
    ) -> Result<()> {
        if !tx_frame_valid(frame) {
            return Err(Error::InvalidState);
        }
        if self.channel > 39 {
            return Err(Error::InvalidState);
        }
        // The engine may still be finishing an RX window; stop it first.
        self.engine_stop();
        if unsafe { regs::read(LLE_BASE, lle::CMD) & lle_cmd::BUSY_MASK } != 0 {
            return Err(Error::Busy);
        }

        // Prefer an aligned in-window frame; else bounce through the caller's
        // RX scratch, which `new` already proved to be DMA-visible. A local
        // bounce buffer would inherit `Ch573Radio`'s (possibly low) address.
        let mut tx_ptr = frame.as_ptr();
        if tx_ptr as usize & 0x3 != 0 || !CAPS.contains_dma(tx_ptr as usize, frame.len()) {
            if frame.len() > self.rx_dma_len {
                return Err(Error::InvalidState);
            }
            // SAFETY: owned scratch, sized `RX_DMA_MIN`, word-aligned; TX
            // stops the engine first, so RX is not writing it.
            unsafe {
                core::ptr::copy_nonoverlapping(frame.as_ptr(), self.rx_dma, frame.len());
            }
            tx_ptr = self.rx_dma;
        }

        Self::clear_lle_irq(lle_irq::TX_DONE | lle_irq::CLEAR_ARM);

        self.program_channel(self.channel);
        self.apply_aa_crc_regs();

        // EVT `RF_Tx` / `ll_hw_api_tx_direct_test` arm:
        // MODE=0x5a → DMA+0x10 → wait COUNT==0 → GUARD=0x8303 →
        // COUNT=airtime → GUARD=0xc303 (fires). No CMD/TX_TRIG.
        let hw_window = Self::tx_window_half_us(frame[1]);
        unsafe {
            regs::rmw(
                BB_BASE,
                bb::RFCTRL,
                rfctrl::PHY_MASK | rfctrl::SHUT | rfctrl::DIR_MASK,
                rfctrl::PHY_1M,
            );
            // EVT only ever sets FECTRL bit17 (0x20000) for RF-on; the wider
            // `FECTRL_RF_ON` mask is a CH585 constant and can gate the PA off.
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, 0x2_0000);
            regs::write(LLE_BASE, lle::MODE, lle_mode::TX);
            // `ll_advertise_tx` pre-arm settle countdown.
            regs::write(LLE_BASE, LLE_COUNT, 0xa0);
            // `ll_advertise_tx` stores ADV TXCFG `0x1f` at LLE+0x04.
            regs::write(LLE_BASE, lle::CRC_AA_CFG, 0x1f);
            // Clear AUTOCFG arm bits and RFCTRL bit28 like the ADV path.
            regs::rmw(BB_BASE, bb::AUTOCFG, autocfg::ARM_MASK, 0);
            regs::rmw(BB_BASE, bb::RFCTRL, 0x1000_0000, 0);
            regs::write(DMA_BASE, dma_reg::TXBUFPTR, Self::dma_off(tx_ptr as usize));
        }

        if let Some(start) = start_cputime {
            loop {
                let now = clock.now_us();
                if now.wrapping_sub(start) as i32 >= 0 {
                    if now.wrapping_sub(start) > 10 {
                        return Err(Error::Late);
                    }
                    break;
                }
            }
        }

        // Wait for the pre-arm countdown, then GUARD/COUNT fire.
        let drain_deadline = clock.now_us().wrapping_add(2_000);
        while unsafe { regs::read(LLE_BASE, LLE_COUNT) } != 0 {
            if clock.now_us().wrapping_sub(drain_deadline) as i32 >= 0 {
                break;
            }
        }
        unsafe {
            regs::write(LLE_BASE, lle::GUARD, 0x0000_8303);
            regs::write(LLE_BASE, LLE_COUNT, hw_window);
            regs::write(LLE_BASE, lle::GUARD, 0x0000_c303);
        }
        // Drop any stale flag (e.g. a bit9 left set by an earlier clear
        // attempt) so the kick below can only come from this TX window.
        Self::clear_lle_irq(0xffff);
        unsafe {
            // EVT `ll_tx_set_wait_finish` pokes CMD=2 to start the TX.
            regs::write(LLE_BASE, lle::CMD, 0x2);
        }

        if isr::INSTALLED.load(core::sync::atomic::Ordering::Acquire) {
            use core::sync::atomic::Ordering;
            // The VTF handler does the bit9 kick and reports TX_DONE; this
            // thread only waits, so there is no 500 µs poll on the hot path.
            isr::TX_KICKED.store(false, Ordering::Release);
            isr::TX_DONE.store(false, Ordering::Release);
            isr::MODE.store(isr::TX, Ordering::Release);
            unsafe { unmask_ble_lines() };
            let deadline = clock
                .now_us()
                .wrapping_add((hw_window / 2).saturating_add(2_000));
            let mut ok = false;
            loop {
                if isr::TX_DONE.load(Ordering::Acquire) {
                    ok = true;
                    break;
                }
                if clock.now_us().wrapping_sub(deadline) as i32 >= 0 {
                    break;
                }
            }
            unsafe {
                mask_ble_lines();
                isr::MODE.store(isr::IDLE, Ordering::Release);
            }
            self.engine_stop();
            Self::clear_lle_irq(lle_irq::TX_DONE | lle_irq::CLEAR_ARM);
            unsafe { regs::write(LLE_BASE, lle::MODE, 0) };
            return if ok { Ok(()) } else { Err(Error::Timeout) };
        }

        // No ISR installed: `LLE_IRQLibHandler` kicks the baseband on LLE IRQ
        // bit9 (`0x200`) with COUNT=0x190, AUTOCFG bit1 and RFCTRL bit28.
        // Mirror that from a tight poll; give up after 500 µs.
        let kick_deadline = clock.now_us().wrapping_add(500);
        let mut kicked = false;
        loop {
            if unsafe { regs::read(LLE_BASE, lle::IRQSTAT) } & TX_ARM_EVENT != 0 {
                unsafe {
                    regs::write(LLE_BASE, LLE_COUNT, 0x190);
                    regs::rmw(BB_BASE, bb::AUTOCFG, 0x3, 0x2);
                    regs::rmw(BB_BASE, bb::RFCTRL, 0, 0x1000_0000);
                }
                Self::clear_lle_irq(TX_ARM_EVENT);
                kicked = true;
                break;
            }
            if clock.now_us().wrapping_sub(kick_deadline) as i32 >= 0 {
                break;
            }
        }
        if !kicked {
            self.engine_stop();
            return Err(Error::Timeout);
        }

        let armed = unsafe { regs::read(LLE_BASE, LLE_COUNT) };
        if armed == 0 {
            // COUNT must latch non-zero; otherwise we never armed.
            self.engine_stop();
            return Err(Error::InvalidState);
        }

        let started = clock.now_us();
        // Need real wall time for the countdown to run; half-µs units ≈ µs/2.
        let deadline = started.wrapping_add((hw_window / 2).saturating_add(1_000));
        let mut saw_tx_done = false;
        let mut last_count;
        loop {
            let st = unsafe { regs::read(LLE_BASE, lle::IRQSTAT) };
            last_count = unsafe { regs::read(LLE_BASE, LLE_COUNT) };
            if st & lle_irq::TX_DONE != 0 {
                saw_tx_done = true;
                break;
            }
            if last_count == 0 {
                break;
            }
            if clock.now_us().wrapping_sub(deadline) as i32 >= 0 {
                break;
            }
        }

        let rc = if saw_tx_done || last_count == 0 {
            Ok(())
        } else {
            Err(Error::Timeout)
        };

        self.engine_stop();
        Self::clear_lle_irq(lle_irq::TX_DONE | lle_irq::CLEAR_ARM);
        unsafe {
            regs::write(LLE_BASE, lle::MODE, 0);
        }
        let _ = (self.phy_tx, armed);
        rc
    }

    /// Arm a single RX window (MODE=0x59, CMD=1) and return.
    ///
    /// `Ok` means the engine is listening, **not** that a packet arrived.
    /// Completion is serviced with [`Self::rx_poll`]; the hardware writes the
    /// raw PDU into `DMA+0x18` as `[hdr][len][payload][pad]`, then a status
    /// word plus RSSI byte at `(len + 5) & 0x1fc` (no RSSI prefix).
    ///
    /// Arming masks the BLE lines and drops any unconsumed result from the
    /// previous window (software flags, pending PFIC entry, BB event bits).
    ///
    /// Call from thread context (or an ISR that cannot preempt BLE): masking
    /// only stops new entries, so a preempted BLE ISR could resume after the
    /// re-arm and publish into the new window. On `Err(Busy)` the BLE lines
    /// stay masked; the next successful arm re-enables them.
    unsafe fn rx_basic<T: InstantUs>(
        &mut self,
        clock: &T,
        rxbuf: &mut [u8],
        window_half_us: u32,
    ) -> Result<()> {
        if rxbuf.is_empty() || rxbuf.as_mut_ptr() as usize & 0x3 != 0 {
            return Err(Error::InvalidState);
        }
        if !CAPS.contains_dma(rxbuf.as_mut_ptr() as usize, rxbuf.len()) {
            return Err(Error::InvalidState);
        }
        if self.channel > 39 {
            return Err(Error::InvalidState);
        }
        // Mask before touching state: an ISR from the previous window must not
        // publish into this one. In thread context no entry can be running
        // while we execute; masking only keeps new ones out.
        unsafe {
            mask_ble_lines();
            regs::write(PFIC_BASE, PFIC_IPRR, (1 << 21) | (1 << 20));
        }
        // EVT `ble_ll_hw_api_rx` stops a busy engine and waits for idle.
        self.engine_stop();
        if unsafe { regs::read(LLE_BASE, lle::CMD) & lle_cmd::BUSY_MASK } != 0 {
            return Err(Error::Busy);
        }

        Self::clear_lle_irq(0xffff);
        // The level line can re-pend while `engine_stop` runs; drop it again.
        unsafe { regs::write(PFIC_BASE, PFIC_IPRR, (1 << 21) | (1 << 20)) };
        // Drop per-frame BB bits too; a CRC error left by a window that ended
        // without RX_DONE would otherwise mark the next frame bad. Ones leave
        // the other bits alone (write-zero-to-clear).
        unsafe { regs::write(BB_BASE, bb::IRQSTAT, !(BB_PAYLOAD_EVENT | BB_CRC_ERR)) };
        self.program_channel(self.channel);
        self.apply_aa_crc_regs();

        unsafe {
            // EVT `ble_ll_hw_api_rx` (libCH57xBLE.a `ip.o`): the BLE RX arm
            // used by scanning. Not the 2.4G `RF_Rx`, which differs in AA/CRC
            // cfg (0x1e vs 0x1f) and window handling.
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::PHY_MASK, rfctrl::PHY_1M);
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, rfctrl::DIR_RX);
            // CH573 RF-on is FECTRL bit17 only; the CH585 constant gates PA.
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, 0x2_0000);
            regs::rmw(BB_BASE, bb::AUTOCFG, autocfg::ARM_MASK, 0x2);
            regs::rmw(BB_BASE, bb::RFCTRL, 0, rfctrl::INIT_BIT28);
            // RX PHY cfg: clear bits[26:25]/[23:16], keep bit24, set bit29.
            regs::rmw(BB_BASE, bb::RXCFG18, 0xf900_0000, 0x2000_0000);
            regs::rmw(BB_BASE, bb::RXCFG18, 0x7d, 0x18);
            // BLE RX runs in channel-number mode.
            regs::rmw(RFEND_BASE, rfend::FREQMODE, rfend::FREQMODE_EN, 0);
            // Vendor BLE RX uses TX's 0x1f AA/CRC cfg, not `RF_Rx`'s 0x1e.
            regs::write(LLE_BASE, lle::CRC_AA_CFG, 0x1f);
            let rx_ptr = rxbuf.as_mut_ptr();
            self.rx_buf = rx_ptr;
            self.rx_buf_len = rxbuf.len();
            self.rx_reloaded = false;
            // Publish for the interrupt path; harmless when polling instead.
            isr::BUF.store(rx_ptr as usize, core::sync::atomic::Ordering::Release);
            isr::BUF_LEN.store(rxbuf.len(), core::sync::atomic::Ordering::Release);
            isr::RELOADED.store(false, core::sync::atomic::Ordering::Release);
            isr::CRC_OK.store(false, core::sync::atomic::Ordering::Release);
            // A late Done from the previous window must not leak into this one.
            isr::DONE.store(false, core::sync::atomic::Ordering::Release);
            isr::TIMEOUT.store(false, core::sync::atomic::Ordering::Release);
            isr::armed_store(true);
            regs::write(DMA_BASE, dma_reg::RXBUFPTR, Self::dma_off(rx_ptr as usize));
            // EVT `ble_ll_hw_api_rx` order: CMD=1 then MODE=0x59.
            regs::write(LLE_BASE, lle::CMD, lle_cmd::START_RX);
            regs::write(LLE_BASE, lle::MODE, lle_mode::RX);
            // EVT `ll_scan_process` arms the listen window as a guarded DMA
            // block, exactly like TX. A bare COUNT store does not fire.
            regs::write(LLE_BASE, lle::GUARD, 0x0000_8303);
            regs::write(LLE_BASE, LLE_COUNT, window_half_us.max(1));
            regs::write(LLE_BASE, lle::GUARD, 0x0000_c303);
        }

        // Arm only. Completion paths: `rx_poll`, or `ble_isr` when
        // `install_ble_irq` has routed the lines through the VTF slots.
        clock.delay_us(2);
        if isr::INSTALLED.load(core::sync::atomic::Ordering::Acquire) {
            isr::MODE.store(isr::RX, core::sync::atomic::Ordering::Release);
            // SAFETY: VTF slots were installed, so enabling the lines cannot
            // dispatch into an unconfigured vector.
            unsafe { unmask_ble_lines() };
        }
        let _ = self.phy_rx;
        Ok(())
    }

    fn rssi(&self) -> i8 {
        0
    }

    fn crc_ok(&self) -> bool {
        false
    }
}
