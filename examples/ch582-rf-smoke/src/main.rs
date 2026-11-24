#![no_std]
#![no_main]

use core::cell::Cell;
use core::fmt::Write;

use ch5xx_hal as hal;
use hal::mode::Blocking;
use hal::pac;
use hal::peripherals::UART1;
use hal::uart::{Config, UartTx};
use panic_halt as _;
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::rf::{
    new_radio_with_dma,
    txrx::{DmaBuf, RX_DMA_MIN},
    Backend, Radio, RfEvent,
};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use wchble::{Error, Result};

static RX_DMA: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
const CHANNELS: [u8; 3] = [37, 38, 39];
const PEER_MARKER: &[u8] = b"wch582-peer";
const ADV: &[u8] = &[
    0x42, 17, 0x01, 0x02, 0x58, 0xee, 0xff, 0xc1, 2, 1, 6, 7, 9, b'w', b'c', b'h', b'5', b'8', b'2',
];

struct Clock {
    ticks: Cell<ExtendingTicks>,
    rate: TickRate,
}

impl Clock {
    fn start() -> Self {
        Self {
            ticks: Cell::new(ExtendingTicks::new(pac::SYSTICK.cntl().read().cntl())),
            rate: TickRate::new(hal::delay::measured_sysclk().0).unwrap(),
        }
    }
}

impl InstantUs for Clock {
    fn now_us(&self) -> u32 {
        let mut ticks = self.ticks.get();
        let elapsed = ticks.sample(pac::SYSTICK.cntl().read().cntl());
        self.ticks.set(ticks);
        self.rate.micros(elapsed)
    }

    fn delay_us(&self, us: u32) {
        let start = self.now_us();
        while self.now_us().wrapping_sub(start) < us {
            core::hint::spin_loop();
        }
    }
}

fn with_safe_access(f: impl FnOnce()) {
    critical_section::with(|_| {
        let sig = pac::SYSTEM_CONTROL.safe_access_sig();
        unsafe { core::arch::asm!("fence.i") };
        sig.write(|w| w.set_safe_access_sig(0x57));
        sig.write(|w| w.set_safe_access_sig(0xa8));
        unsafe { core::arch::asm!("fence.i") };
        f();
        sig.write(|w| w.set_safe_access_sig(0));
        unsafe { core::arch::asm!("fence.i") };
    });
}

#[entry]
fn main() -> ! {
    let p = hal::init(hal::Config {
        rcc: hal::rcc::Config::PLL_60MHZ,
    });
    let mut serial = UartTx::new_blocking::<0>(p.UART1, p.PA9, Config::new(115_200)).unwrap();
    let clock = Clock::start();

    with_safe_access(|| {
        pac::SYS
            .ck32k_config()
            .modify(|w| w.set_clk_xt32k_pon(true))
    });
    clock.delay_us(25_000);
    with_safe_access(|| {
        pac::SYS
            .ck32k_config()
            .modify(|w| w.set_clk_osc32k_xt(true))
    });
    clock.delay_us(1_000);

    writeln!(serial, "wch582 RF smoke\r").unwrap();
    let result = new_radio_with_dma(&mut RX_DMA.init(DmaBuf::zeroed()).0)
        .and_then(|mut radio| run(&mut radio, &clock, &mut serial));
    writeln!(serial, "RF smoke stopped: {result:?}\r").unwrap();
    serial.blocking_flush().unwrap();
    loop {
        core::hint::spin_loop();
    }
}

fn run(radio: &mut Backend, clock: &Clock, serial: &mut UartTx<'_, UART1, Blocking>) -> Result<()> {
    radio.init(clock)?;
    writeln!(serial, "rf init ok\r").unwrap();

    // Check that an already missed turn does not transmit.
    let missed = clock.now_us().wrapping_sub(200);
    if unsafe { radio.tx_basic(clock, ADV, 10_000, Some(missed)) } != Err(Error::Late) {
        return Err(Error::InvalidState);
    }

    let mut rx = [0u8; RX_DMA_MIN];
    // SAFETY: rx stays live while the receive window is armed.
    unsafe { radio.rx_basic(clock, &mut rx, 20_000) }?;
    if !radio.stop(clock) || radio.poll(clock).is_some() {
        return Err(Error::InvalidState);
    }
    writeln!(serial, "late TX and RX cancellation ok\r").unwrap();
    serial.blocking_flush().unwrap();

    let mut sent = [0u32; 3];
    let mut received = [0u32; 3];
    let mut matched = [0u32; 3];
    let mut timed_out = 0u32;
    let mut round = 0u32;

    loop {
        for (i, channel) in CHANNELS.into_iter().enumerate() {
            radio.set_channel(channel)?;
            let start = clock.now_us().wrapping_add(180);
            let deadline = start.wrapping_add(70_000);
            // SAFETY: the radio owns its permanent DMA scratch. The separate
            // receive destination stays in scope through poll or stop.
            let scheduled = round.is_multiple_of(2).then_some(start);
            if let Err(error) = unsafe { radio.tx_basic(clock, ADV, 10_000, scheduled) } {
                writeln!(serial, "tx ch{channel} round {round}: {error:?}\r").unwrap();
                return Err(error);
            }
            sent[i] += 1;
            loop {
                let now = clock.now_us();
                if now.wrapping_sub(deadline) as i32 >= 0 {
                    break;
                }
                let remaining = deadline.wrapping_sub(now);
                unsafe { radio.rx_basic(clock, &mut rx, remaining * 2) }?;
                loop {
                    match radio.poll(clock) {
                        Some(RfEvent::RxDone) => {
                            if radio.crc_ok() {
                                received[i] += 1;
                                let len = 2 + usize::from(rx[1]);
                                if rx[2..len]
                                    .windows(PEER_MARKER.len())
                                    .any(|data| data == PEER_MARKER)
                                {
                                    matched[i] += 1;
                                }
                            }
                            break;
                        }
                        Some(RfEvent::RxTimeout) => {
                            timed_out += 1;
                            break;
                        }
                        Some(event) => {
                            writeln!(serial, "rx ch{channel} round {round}: {event:?}\r").unwrap();
                            return Err(Error::InvalidState);
                        }
                        None if clock.now_us().wrapping_sub(deadline.wrapping_add(2_000))
                            as i32
                            >= 0 =>
                        {
                            radio.stop(clock);
                            writeln!(serial, "rx ch{channel} round {round}: deadline missed\r")
                                .unwrap();
                            return Err(Error::Timeout);
                        }
                        None => core::hint::spin_loop(),
                    }
                }
            }
            if !radio.stop(clock) {
                return Err(Error::Busy);
            }
        }
        round += 1;
        if round.is_multiple_of(5) {
            for (i, channel) in CHANNELS.into_iter().enumerate() {
                writeln!(
                    serial,
                    "ch{channel} tx={} rx={} peer={}\r",
                    sent[i], received[i], matched[i]
                )
                .unwrap();
            }
            writeln!(serial, "rx timeouts={timed_out}\r").unwrap();
            serial.blocking_flush().unwrap();
        }
    }
}
