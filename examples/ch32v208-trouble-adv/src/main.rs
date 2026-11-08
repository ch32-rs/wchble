//! SoftRunner + Trouble Host join — Host-driven legacy ADV_IND on air.
//!
//! HAL owns clocks / HSE trim / Embassy time; SoftRunner pumps HCI; a single
//! interleaved task schedules `tx_basic` while advertising is enabled.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

use ch32_hal as hal;
use ch32_hal::interrupt;
use ch32_hal::rcc::{
    AHBPrescaler, APBPrescaler, Config as RccConfig, HsPllSource, Hse, HseMode, LsConfig, Pll,
    PllMul, PllPreDiv, PllSource, Sysclk,
};
use ch32_hal::time::Hertz;
use ch32_hal::try_println as println;
use embassy_executor::Spawner;
use embassy_futures::join::join3;
use embassy_time::{Duration, Instant, Timer};
use static_cell::StaticCell;
use trouble_host::advertise::{Advertisement, AdvertisementParameters};
use trouble_host::prelude::*;
use wchble::hci::SoftRunner;
use wchble::rf::family::ch32v208::Ch32v208Radio;
use wchble::rf::txrx::RX_DMA_MIN;
use wchble::rf::{PhyMode, Radio};
use wchble::time::InstantUs;
use {panic_halt as _, qingke_rt as _};

/// `RCC_AHBPeriph_BLE_CRC` — AHBPCENR bits 17/18 (BLE) + bit 6 (CRC).
const RCC_AHB_BLE_CRC: u32 = 0x0003_0040;
const RCC_AHBPCENR: *mut u32 = 0x4002_1014 as *mut u32;
/// `OSC->HSE_CAL_CTRL` (AHBPERIPH_BASE + 0x202C).
const OSC_HSE_CAL_CTRL: *mut u32 = 0x4002_202C as *mut u32;

const ADV_AA: u32 = 0x8e89_bed6;
const ADV_CRC_INIT: u32 = 0x55_5555;

/// Force 4-byte alignment — plain `StaticCell<[u8; N]>` can land at +1.
#[repr(align(4))]
struct RxDma([u8; RX_DMA_MIN]);

static RX_DMA: StaticCell<RxDma> = StaticCell::new();

/// InstantUs over Embassy time driver (SysTick). Do not steal SYSTICK.
struct EmbassyClock;

impl InstantUs for EmbassyClock {
    fn now_us(&self) -> u32 {
        Instant::now().as_micros() as u32
    }

    fn delay_us(&self, us: u32) {
        let start = Instant::now();
        let wait = Duration::from_micros(u64::from(us));
        while Instant::now().duration_since(start) < wait {}
    }
}

fn enable_ble_clock_and_hse_trim() {
    unsafe {
        let ahb = read_volatile(RCC_AHBPCENR);
        write_volatile(RCC_AHBPCENR, ahb | RCC_AHB_BLE_CRC);

        let mut cal = read_volatile(OSC_HSE_CAL_CTRL);
        cal &= !(0x07 << 28);
        cal |= 0x03 << 28;
        cal |= 3 << 24;
        write_volatile(OSC_HSE_CAL_CTRL, cal);
    }
}

/// SoftRunner HCI pump + RF TX while Host has advertising enabled.
async fn controller_task(
    soft: &mut SoftRunner,
    radio: &mut Ch32v208Radio,
    clock: &EmbassyClock,
) -> ! {
    let mut next_tx = Instant::now();
    let mut was_enabled = false;
    let mut bursts: u32 = 0;
    let mut pdu = [0u8; 40];

    loop {
        let _ = soft.poll_once().await;

        if soft.adv_enabled() {
            if !was_enabled {
                println!("adv enable");
                was_enabled = true;
                next_tx = Instant::now();
            }

            if Instant::now() >= next_tx {
                if let Some(n) = soft.build_adv_pdu(&mut pdu) {
                    // Ensure LLE is idle before the burst; back-to-back channel
                    // hops can see CMD busy if the previous TX was not shut.
                    radio.shut();
                    for ch in soft.adv_channels() {
                        if let Err(e) = radio.set_channel(ch) {
                            println!("set_channel {} err {:?}", ch, e);
                            continue;
                        }
                        match radio.tx_basic(clock, &pdu[..n], 0, None) {
                            Ok(()) => {
                                // Log the first few bursts only — SDI is slow.
                                if bursts < 3 {
                                    println!("tx ch{} ok", ch);
                                }
                            }
                            Err(e) => println!("tx ch{} err {:?}", ch, e),
                        }
                        radio.shut();
                        clock.delay_us(500);
                    }
                    bursts = bursts.saturating_add(1);
                    if bursts == 3 {
                        println!("tx ongoing");
                    }
                }
                let interval_us = soft.adv_interval_us().clamp(20_000, 200_000);
                next_tx = Instant::now() + Duration::from_micros(u64::from(interval_us));
            } else {
                Timer::after(Duration::from_millis(1)).await;
            }
        } else {
            was_enabled = false;
            bursts = 0;
            Timer::after(Duration::from_millis(5)).await;
        }
    }
}

async fn advertise_task<C, P>(mut peripheral: Peripheral<'_, C, P>)
where
    C: Controller,
    P: PacketPool,
{
    let adv_data = [
        0x02, 0x01, 0x06, // Flags: LE General Discoverable + BR/EDR Not Supported
        0x07, 0x09, b'w', b'c', b'h', b'b', b'l', b'e', // Complete Local Name
    ];

    let mut params = AdvertisementParameters::default();
    params.interval_min = Duration::from_millis(100);
    params.interval_max = Duration::from_millis(100);
    // SoftRunner set_adv_params currently requires Own_Address_Type = Random.
    params.own_addr_kind = Some(AddrKind::RANDOM);

    match peripheral
        .advertise(
            &params,
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data,
                scan_data: &[],
            },
        )
        .await
    {
        Ok(advertiser) => {
            println!("trouble adv running");
            // Hold advertising open; connections are out of scope for this cut.
            let _ = advertiser.accept().await;
            println!("adv stopped");
        }
        Err(e) => {
            println!("advertise err");
            let _ = e;
        }
    }

    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}

#[embassy_executor::main(entry = "ch32_hal::entry")]
async fn main(_spawner: Spawner) -> ! {
    hal::debug::SDIPrint::enable();
    let _p = hal::init(hal::Config {
        rcc: RccConfig {
            hse: Some(Hse {
                freq: Hertz(32_000_000),
                mode: HseMode::Oscillator,
            }),
            sys: Sysclk::PLL,
            pll_src: PllSource::HSE,
            pll: Some(Pll {
                prediv: PllPreDiv::DIV4,
                mul: PllMul::MUL12,
            }),
            pllx: None,
            ahb_pre: AHBPrescaler::DIV1,
            apb1_pre: APBPrescaler::DIV2,
            apb2_pre: APBPrescaler::DIV1,
            ls: LsConfig::default(),
            hspll_src: HsPllSource::HSI,
            hspll: None,
        },
        dma_interrupt_priority: interrupt::Priority::P0,
    });
    unsafe { hal::embassy::init() };

    println!("wchble ch32v208 trouble-adv");
    println!("chip {}", hal::signature::chip_id().name());

    enable_ble_clock_and_hse_trim();

    let hclk = hal::rcc::clocks().hclk.0;
    println!("hclk={} Hz", hclk);

    let clock = EmbassyClock;
    let rx = &mut RX_DMA.init(RxDma([0; RX_DMA_MIN])).0;
    let mut radio = match Ch32v208Radio::new(rx) {
        Ok(r) => r,
        Err(e) => {
            println!("radio new err {:?}", e);
            loop {
                Timer::after(Duration::from_secs(1)).await;
            }
        }
    };

    match radio.init(&clock) {
        Ok(()) => println!("rf init ok"),
        Err(e) => {
            println!("rf init err {:?}", e);
            loop {
                Timer::after(Duration::from_secs(1)).await;
            }
        }
    }

    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    radio.set_aa_crc(ADV_AA, ADV_CRC_INIT);

    let controller = wchble::hci::new();
    let mut soft = SoftRunner::new();
    soft.set_bd_addr([0x00, 0x00, 0x00, 0xc1, 0xff, 0xee]);

    let address = Address::random([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x42]);
    let mut resources: HostResources<DefaultPacketPool, 1, 2> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(address)
        .build();

    println!("hci host up");

    let mut runner = stack.runner();
    let peripheral = stack.peripheral();

    join3(
        controller_task(&mut soft, &mut radio, &clock),
        async {
            if let Err(_e) = runner.run().await {
                println!("host runner err");
            }
            loop {
                Timer::after(Duration::from_secs(1)).await;
            }
        },
        advertise_task(peripheral),
    )
    .await;

    #[allow(unreachable_code)]
    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}
