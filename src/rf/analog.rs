//! RFEND DevInit + calibration envelope (TXCtune / TXFtune / RXFilter / RXAdc).
//!
//! Concrete register sequences are chip-family tables under [`crate::rf::family`].

use crate::Result;
use crate::time::InstantUs;

/// Analog bring-up hooks implemented per family.
pub trait AnalogInit {
    fn rfend_dev_init<T: InstantUs>(&mut self, clock: &T) -> Result<()>;
    fn calibrate<T: InstantUs>(&mut self, clock: &T) -> Result<()>;
}
