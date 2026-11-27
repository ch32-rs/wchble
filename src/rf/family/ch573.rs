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

/// DMA-block offsets (`dma.o` / `RF_Tx` / `RF_Rx`).
mod dma_reg {
    pub const CTRL: usize = 0x00;
    pub const CFG08: usize = 0x08;
    pub const CFG0C: usize = 0x0c;
    pub const TXBUFPTR: usize = 0x10;
    pub const RXBUFPTR: usize = 0x14;
    pub const AUX18: usize = 0x18;
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
}

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
    /// EVT seeds +0x10/+0x14 from `gBleIPPara` buffers; we point both at the
    /// owned RX scratch until TX programs `+0x10` per packet.
    fn dma_dev_init(&mut self) {
        let off = Self::dma_off(self.rx_dma as usize);
        unsafe {
            regs::write(DMA_BASE, dma_reg::TXBUFPTR, off);
            regs::write(DMA_BASE, dma_reg::RXBUFPTR, off);
            regs::write(DMA_BASE, dma_reg::AUX18, off);
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
            regs::rmw(LLE_BASE, lle::MODE, lle_mode::DIR_MASK, 0);
            regs::rmw(LLE_BASE, lle::CMD, 0, lle_cmd::FORCE_STOP);
            // EVT spins until the stop command self-clears; bail out bounded
            // so an idle engine (already clear) costs nothing.
            for _ in 0..1_000 {
                if regs::read(LLE_BASE, lle::CMD) & lle_cmd::FORCE_STOP == 0 {
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
            // EVT sets TUNE bit12 and never clears it.
            regs::rmw(RFEND_BASE, rfend::TUNE, 0, 0x1000);
            let start = clock.now_us();
            while regs::read(RFEND_BASE, rfend::FILTMEAS) & rfend::FILTMEAS_RDY == 0 {
                if clock.now_us().wrapping_sub(start) >= 200_000 {
                    return Err(Error::Timeout);
                }
            }
            regs::rmw(RFEND_BASE, rfend::CFG50, 0, rfend::CFG50_FILT_EN);
            let code = regs::read(RFEND_BASE, rfend::FILTMEAS);
            regs::rmw(RFEND_BASE, rfend::CFG50, 0x1f, code & rfend::FILTMEAS_MASK);
            regs::rmw(RFEND_BASE, rfend::FECTRL, rfend::FECTRL_RXFILT, 0);
        }
        Ok(())
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
        let busy = unsafe { regs::read(LLE_BASE, lle::CMD) & lle_cmd::BUSY_MASK };
        if busy != 0 {
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

        self.engine_stop();
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

        // `LLE_IRQLibHandler` kicks the baseband on LLE IRQ bit9 (`0x200`)
        // with COUNT=0x190, AUTOCFG bit1 and RFCTRL bit28. Mirror that from a
        // tight poll; the window is short, so give up after 500 µs.
        const TX_ARM_EVENT: u32 = 0x200;
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
        let busy = unsafe { regs::read(LLE_BASE, lle::CMD) & lle_cmd::BUSY_MASK };
        if busy != 0 {
            return Err(Error::Busy);
        }

        self.engine_stop();
        Self::clear_lle_irq(0xffff);
        self.program_channel(self.channel);
        self.apply_aa_crc_regs();

        unsafe {
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::PHY_MASK, rfctrl::PHY_1M);
            regs::rmw(BB_BASE, bb::RFCTRL, rfctrl::DIR_MASK, rfctrl::DIR_RX);
            regs::rmw(RFEND_BASE, rfend::FECTRL, 0, rfend::FECTRL_RF_ON);
            regs::write(
                DMA_BASE,
                dma_reg::RXBUFPTR,
                Self::dma_off(rxbuf.as_mut_ptr() as usize),
            );
            regs::write(LLE_BASE, LLE_COUNT, window_half_us.max(1));
            regs::write(LLE_BASE, lle::MODE, lle_mode::RX);
            regs::write(LLE_BASE, lle::CMD, lle_cmd::START_RX);
        }

        // Arm only; caller polls IRQSTAT. Keep a short settle so WINDOW sticks.
        clock.delay_us(2);
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
