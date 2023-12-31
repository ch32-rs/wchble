#![no_std]

#[cfg(feature = "ch57x")]
use ch57x_ble as raw;

#[cfg(feature = "ch58x")]
use ch58x_ble as raw;

#[cfg(feature = "ch59x")]
use ch59x_ble as raw;

#[cfg(feature = "ch32v20x")]
use ch32v20x_ble as raw;

pub mod errors;
pub mod types;

pub use errors::RawError as Error;

pub type Result<T> = core::result::Result<T, Error>;

pub struct Config {
    raw: raw::bleConfig_t,
}

impl Config {
    pub fn new(heap_star_addr: *mut u8, heap_size: usize) -> Self {
        let mut cfg: raw::bleConfig_t = unsafe { core::mem::zeroed() };

        const BLE_TX_NUM_EVENT: u8 = 1;
        const BLE_BUFF_NUM: u8 = 5;
        const BLE_BUFF_MAX_LEN: u16 = 27;
        const BLE_TX_POWER: u8 = raw::LL_TX_POWER_0_DBM as _;
        const PERIPHERAL_MAX_CONNECTION: u8 = 1;
        const CENTRAL_MAX_CONNECTION: u8 = 3;

        cfg.MEMAddr = heap_star_addr as u32;
        cfg.MEMLen = heap_size as _;

        cfg.BufMaxLen = BLE_BUFF_MAX_LEN;
        cfg.BufNumber = BLE_BUFF_NUM;
        cfg.TxNumEvent = BLE_TX_NUM_EVENT;
        cfg.TxPower = BLE_TX_POWER;

        Config { raw: cfg }
    }
}

pub fn init(config: Config) -> Result<()> {
    Ok(())
}
