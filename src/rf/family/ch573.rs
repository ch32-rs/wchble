//! CH573 BLE IP bases, DevInit tables from EVT, and first MMIO bring-up.
//!
//! Tables recovered from `CH573EVT/EXAM/BLE/LIB/libCH57xBLE.a`
//! (`lle.o` / `bb.o` / `rfend.o`). This backend applies the absolute stores and
//! leaves TX/RX/`TXCtune` for a later commit once silicon readback confirms the
//! runtime shape.
//!
//! Map (same CH5xx window as CH583/585/592):
//! - BB    `0x4000_C100`
//! - LLE   `0x4000_C200`
//! - AES   `0x4000_C300`
//! - RFEND `0x4000_D000`
//! - IRQs BB=`BLEB`=20, LLE=`BLEL`=21 (PAC / vector table)
//!
//! Hard constraint: SRAM is only `0x2000_3800..0x2000_8000` (18 KiB). DMA
//! buffers must land in that window — the low `0x2000_0000` map used by
//! CH572/CH585 is illegal on this die.

use crate::rf::analog::AnalogInit;
use crate::rf::family::caps::FamilyCaps;
use crate::rf::family::tables::{self, BbDevInit, Certainty, LleDevInit, RegInit, RfendInit};
use crate::rf::isr::IsrState;
use crate::rf::regs;
use crate::rf::txrx::RX_DMA_MIN;
use crate::rf::{Channel, PhyMode, Radio, RfCallback};
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

/// Inclusive SRAM window used by LLE DMA on this die.
pub const SRAM_START: usize = 0x2000_3800;
/// Exclusive end of the SRAM window.
pub const SRAM_END: usize = 0x2000_8000;

use Certainty::FromClosedDisasm as Disasm;

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

/// Hypothesize the CH585/CH592 BUFPTR class until silicon says otherwise.
pub const CAPS: FamilyCaps = FamilyCaps {
    bb_base: BB_BASE,
    lle_base: LLE_BASE,
    aes_base: AES_BASE,
    rfend_base: RFEND_BASE,
    irq_bb: IRQ_BB,
    irq_lle: IRQ_LLE,
    tx_bufptr_off: 0x78,
    rx_bufptr_off: 0x7c,
    sram_start: SRAM_START,
    sram_end: SRAM_END,
    vco_mhz: RFEND_INIT.vco_mhz,
    wait_tune_half_us: RFEND_INIT.wait_tune_half_us.value,
};

/// CH573 radio — DevInit apply for silicon readback; TX/RX still TBD.
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
            // Smoke 2026-11-26: absolute stores matched, but writing
            // `CAPS.rx_bufptr_off` (0x7c) did not stick (readback 0). Keep the
            // attempt for later silicon probing of 0x70/0x74/0x78/0x7c.
            regs::write(LLE_BASE, CAPS.rx_bufptr_off, self.rx_dma as u32);
            let _ = self.rx_dma_len;
        }
    }

    fn rfend_dev_init_abs(&mut self) {
        unsafe {
            regs::write(
                RFEND_BASE,
                RFEND_INIT.dev_init_0x28.offset as usize,
                RFEND_INIT.dev_init_0x28.value,
            );
        }
    }

    fn bb_dev_init_abs(&mut self) {
        unsafe {
            regs::write(
                BB_BASE,
                BB_DEV_INIT.cfg34.offset as usize,
                BB_DEV_INIT.cfg34.value,
            );
        }
    }
}

impl AnalogInit for Ch573Radio {
    fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        self.rfend_dev_init_abs();
        Ok(())
    }

    fn calibrate<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
        // TXCtune / RXFilter not ported yet; init still returns so smoke can
        // dump the absolute DevInit stores.
        Ok(())
    }
}

impl Radio for Ch573Radio {
    fn init<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        // Order: LLE → RFEND → BB → cal. HAL owns BLE clock / NVIC.
        self.lle_dev_init();
        self.rfend_dev_init(clock)?;
        self.bb_dev_init_abs();
        self.calibrate(clock)
    }

    fn recalibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
        self.calibrate(clock)
    }

    fn shut(&mut self) {}

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

    unsafe fn tx_basic<T: InstantUs>(
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

    unsafe fn rx_basic<T: InstantUs>(
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
