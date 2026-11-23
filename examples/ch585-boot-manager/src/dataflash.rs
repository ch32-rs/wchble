//! Bridge the HAL DataFlash to `wchble::storage::FlashRegion` so the boot
//! manager and the app share one `DualCopyStore` record format.

use ch5xx_hal::flash::{Blocking, DataFlash, Error as HalError};
use wchble::storage::{FlashError, FlashRegion};

pub struct HalDataFlash<'f, 'd> {
    inner: DataFlash<'f, 'd, Blocking>,
}

impl<'f, 'd> HalDataFlash<'f, 'd> {
    pub fn new(inner: DataFlash<'f, 'd, Blocking>) -> Self {
        Self { inner }
    }
}

fn map(error: HalError) -> FlashError {
    match error {
        HalError::NotAligned | HalError::OutOfBounds => FlashError::OutOfRange,
        HalError::Timeout => FlashError::Timeout,
        HalError::Rejected | HalError::Unsupported => FlashError::Busy,
    }
}

impl FlashRegion for HalDataFlash<'_, '_> {
    fn page_size(&self) -> usize {
        0x100
    }

    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    #[inline(never)]
    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), FlashError> {
        self.inner.blocking_read(offset, out).map_err(map)
    }

    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    #[inline(never)]
    fn erase(&mut self, offset: u32) -> Result<(), FlashError> {
        let start = offset & !0xFF;
        self.inner.blocking_erase(start, start + 0x100).map_err(map)
    }

    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    #[inline(never)]
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), FlashError> {
        self.inner.blocking_write(offset, data).map_err(map)
    }
}
