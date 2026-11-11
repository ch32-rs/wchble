//! Shared runtime for the CH58x / CH59x BLE backends.
//!
//! The two families share the LLE/BB/RFEND runtime shape but not all DevInit
//! values or low-level sequences. [`ch58x_common!`] generates the shared part
//! (basic RX/TX state, ISR dispatch, calibration envelope); each backend keeps
//! its own `tx_basic`, `engine_shut`, PHY modes, DevInit writes and tune path.
//!
//! The macro expects the caller to have the usual family imports in scope
//! (`regs`, `bb`, `lle`, `rfend`, the local `bb5`/`lle5`/`rfend5` modules and
//! the `Radio`/`AnalogInit` traits). `stub_radio!` uses the same convention.

#[allow(unused_macros)]
macro_rules! ch58x_common {
    ($ty:ty, $tx_basic:item) => {
        impl $ty {
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

            fn apply_aa_crc(&self) {
                unsafe {
                    regs::write(BB_BASE, bb::ACCESSADDR, self.access_address);
                    regs::write(BB_BASE, bb::CRCINIT, self.crc_init & 0x00ff_ffff);
                }
            }

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

            fn irq_clear_guarded(&self, bits: u32) {
                unsafe {
                    let saved = regs::read(LLE_BASE, lle::GUARD);
                    regs::write(LLE_BASE, lle::GUARD, saved & !lle5_irq::CLEAR_ARM);
                    analog::fence_i();
                    regs::write(LLE_BASE, lle::IRQSTAT, bits);
                    regs::write(LLE_BASE, lle::GUARD, saved);
                }
            }

            fn wait_tune<T: InstantUs>(&mut self, clock: &T) -> Result<()> {
                unsafe { analog::wait_tune(clock, LLE_BASE, RFEND_BASE, WAIT_TUNE_HALF_US) }
            }

            fn rf_txftune(&mut self) {
                unsafe {
                    regs::rmw(RFEND_BASE, rfend5::TUNE, 0, rfend::TUNE_TXFTUNE);
                }
            }

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

            pub fn last_anchor_us(&self) -> u32 {
                self.isr.last_anchor_us
            }

            pub fn note_anchor_us(&mut self, now_us: u32) {
                self.isr.last_anchor_us = now_us;
            }

            pub fn rx_captured(&self) -> bool {
                self.isr.rx_captured
            }

            pub fn rx_dma_len(&self) -> usize {
                self.rx_dma_len
            }

            pub fn set_tx_power(&mut self, power: u8) {
                self.tx_power = power;
            }
        }

        impl AnalogInit for $ty {
            fn rfend_dev_init<T: InstantUs>(&mut self, _clock: &T) -> Result<()> {
                self.rfend_dev_init_rmw();
                Ok(())
            }

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
                    // `BLE_RegInit` tail: `FECTRL &= 0xFFCD_FFFF`. Bit 16 is the
                    // RF block's steady-state enable and must survive.
                    let v = regs::read(RFEND_BASE, rfend5::FECTRL) & rfend::FECTRL_SHUT_MASK;
                    regs::write(RFEND_BASE, rfend5::FECTRL, v);
                    regs::write(LLE_BASE, lle::MODE, lle5_mode::POST_INIT);
                }
                result
            }
        }

        impl Radio for $ty {
            // Chip-specific: pre-arm ordering, TX-filter pulse and the
            // completion wait differ between CH585 and CH592.
            $tx_basic

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

                // `LL_ScanSetRF` starts with `phy_status_clear(6)`: force-stop a
                // stale LLE command before re-arming.
                if unsafe { regs::read(LLE_BASE, lle::CMD) & 0x3 } != 0 {
                    self.engine_shut();
                }

                // Follow `LL_ScanSetRF` (the BLE-stack scanner): AA/CRC,
                // `CRC_AA_CFG` bit 0, PHY mode, then `FREQMODE` off → channel →
                // direction → RF on → `LLE+0x50 = RX` → `CMD=1`. It never
                // rewrites `LLE+0x06` and never programs the RFEND fractional
                // synth.
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

                // `LL_ScanSetRF` clears `LLE+0x64` and W1C bit 17 before
                // arming; the arm-clear needs the guard toggle, the rest is
                // plain W1C.
                self.irq_clear_guarded(
                    lle5_irq::RX_DONE | lle5_irq::TX_DONE | lle5_irq::CLEAR_ARM,
                );

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
    };
}

pub(crate) use ch58x_common;
