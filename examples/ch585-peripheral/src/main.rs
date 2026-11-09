//! P3 finite LE 1M peripheral. No HCI Host or GATT database is linked.
#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::cell::Cell;
use hal::{rcc, time::Hertz};
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::ll::acl::{DataPdu, LinkSequence, RxStatus};
use wchble::ll::adv::AdvState;
use wchble::ll::conn::{ConnectParams, PeripheralConnection};
use wchble::rf::family::ch585::{Ch585Radio, BB_BASE, LLE_BASE};
use wchble::rf::regs::{self, bb, bb_irq, lle};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use {panic_halt as _, portable_atomic as _};

mod upper;

static SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static ADV: StaticCell<DmaBuf<64>> = StaticCell::new();
static RSP: StaticCell<DmaBuf<64>> = StaticCell::new();
static DATA: StaticCell<DmaBuf<64>> = StaticCell::new();

#[no_mangle]
#[used]
pub static RUN_SECONDS: u32 = if cfg!(feature = "long-run") { 360 } else { 25 };
#[no_mangle]
static mut STATS: [u32; 64] = [0; 64];
#[no_mangle]
static mut TRACE: [u32; 128 * 8] = [0; 128 * 8];

fn put(i: usize, v: u32) {
    unsafe {
        core::ptr::addr_of_mut!(STATS)
            .cast::<u32>()
            .add(i)
            .write_volatile(v)
    }
}
fn get(i: usize) -> u32 {
    unsafe {
        core::ptr::addr_of!(STATS)
            .cast::<u32>()
            .add(i)
            .read_volatile()
    }
}
fn inc(i: usize) {
    put(i, get(i).wrapping_add(1));
}
fn reg(base: usize, offset: usize) -> u32 {
    unsafe { regs::read(base, offset) }
}
fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
fn reached(now: u32, deadline: u32) -> bool {
    now.wrapping_sub(deadline) as i32 >= 0
}

struct Clock {
    ticks: Cell<ExtendingTicks>,
    rate: TickRate,
}
impl InstantUs for Clock {
    fn now_us(&self) -> u32 {
        // CH585 SysTick is only 32 bits. This polling executor has one clock
        // owner and samples continuously, including all deadline waits.
        let mut ticks = self.ticks.get();
        let elapsed = ticks.sample(hal::pac::SYSTICK.stk_cntl().read().cntl());
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

fn trace(clock: &Clock, kind: u32, event: u16, channel: u8, header: u8, len: u8, a: u32, b: u32) {
    let count = get(39) as usize;
    // Keep a short opening trace plus a rolling tail; counters cover the run.
    let row = if count < 128 {
        count
    } else {
        64 + (count - 128) % 64
    };
    let words = [
        clock.now_us(),
        kind,
        u32::from(event),
        u32::from(channel),
        u32::from(header),
        u32::from(len),
        a,
        b,
    ];
    for (i, word) in words.into_iter().enumerate() {
        unsafe {
            core::ptr::addr_of_mut!(TRACE)
                .cast::<u32>()
                .add(row * 8 + i)
                .write_volatile(word);
        }
    }
    put(39, (count + 1) as u32);
    if count >= 128 {
        inc(40);
    }
}

fn stop(radio: &mut Ch585Radio, clock: &Clock) {
    radio.shut();
    let start = clock.now_us();
    while reg(LLE_BASE, lle::CMD) & 3 != 0 {
        if clock.now_us().wrapping_sub(start) >= 100 {
            inc(22);
            put(2, 0xee);
            park();
        }
    }
    // Same bounded CH585 policy as P2, not a new generic DMA lifetime API.
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack));
    }
}

struct Received {
    len: usize,
    end: u32,
}

#[link_section = ".highcode"]
#[inline(never)]
fn receive(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    until: u32,
    expires: u32,
) -> Option<Received> {
    unsafe {
        regs::write(BB_BASE, bb::IRQSTAT, 0xf0);
    }
    let now = clock.now_us();
    if reached(now, until) || reached(now, expires) {
        return None;
    }
    let window = until.wrapping_sub(now).saturating_mul(2);
    if radio.rx_basic(clock, &mut rx.0, window).is_err() {
        inc(21);
        stop(radio, clock);
        return None;
    }
    inc(6);
    let mut capture = None;
    let (end, crc_ok) = loop {
        let status = reg(LLE_BASE, lle::IRQSTAT);
        let now = clock.now_us();
        if reached(now, expires) {
            stop(radio, clock);
            return None;
        }
        if status & 5 != 0 {
            break (now, reg(BB_BASE, bb::IRQSTAT) & bb_irq::CRC_ERR == 0);
        }
        if capture.is_none() && reg(BB_BASE, bb::IRQSTAT) & bb_irq::CLKCAP != 0 {
            radio.note_anchor_us(now);
            radio.bb_isr();
            capture = Some(now);
        }
        let expired = match capture {
            Some(at) => now.wrapping_sub(at) >= 700,
            None => reached(now, until),
        };
        if expired {
            stop(radio, clock);
            return None;
        }
    };
    stop(radio, clock);
    put(54, clock.now_us().wrapping_sub(end));
    inc(7);
    if !crc_ok {
        inc(8);
        return None;
    }
    // Never inspect DMA until the engine has acknowledged the stop.
    let len = usize::from(rx.0[1]) + 2;
    if len > 40 {
        inc(9);
        return None;
    }
    put(55, clock.now_us().wrapping_sub(end));
    Some(Received { len, end })
}

#[link_section = ".highcode"]
#[inline(never)]
fn transmit(radio: &mut Ch585Radio, clock: &Clock, frame: &[u8], end: u32) -> bool {
    // P2 starting point, NOT an independent measurement of air IFS.
    put(56, clock.now_us().wrapping_sub(end));
    let result = radio.tx_basic(clock, frame, 0, Some(end.wrapping_add(120)));
    put(57, clock.now_us().wrapping_sub(end));
    match result {
        Ok(()) => inc(18),
        Err(wchble::Error::Late) => inc(19),
        Err(_) => inc(20),
    }
    stop(radio, clock);
    result.is_ok()
}

fn expired(
    conn: &PeripheralConnection,
    control: &wchble::ll::ctrl::ControlState,
    now: u32,
) -> bool {
    if control.termination_expired(now) {
        inc(60);
        put(37, 0x08);
        return true;
    }
    if conn.supervision_expired(now) {
        inc(if conn.established() { 29 } else { 30 });
        put(37, if conn.established() { 0x08 } else { 0x3e });
        return true;
    }
    false
}

fn earlier(a: u32, b: u32) -> u32 {
    if reached(a, b) {
        b
    } else {
        a
    }
}

#[link_section = ".highcode"]
#[inline(never)]
fn run_connection(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<64>,
    conn: &mut PeripheralConnection,
    finish: u32,
) {
    let began = clock.now_us();
    let mut link = LinkSequence::new();
    let mut pending: Option<DataPdu> = None;
    let mut control = wchble::ll::ctrl::ControlState::new();
    let mut outgoing_terminate = None;
    let local_version = wchble::ll::ctrl::LocalVersion {
        version: 0x0d,
        company_id: 0xffff,
        subversion: 1,
    };
    put(37, 0);
    radio.set_aa_crc(conn.params.access_addr, conn.params.crc_init);
    put(2, 3);
    'connection: while !reached(clock.now_us(), finish) {
        if expired(conn, &control, clock.now_us()) {
            break;
        }
        if !conn.established() && conn.event_counter() >= 6 {
            inc(30);
            put(37, 0x3e);
            break;
        }
        let event = conn.event_counter();
        let channel = conn.channel();
        put(51, u32::from(event));
        put(52, u32::from(channel));
        radio.set_channel(channel).unwrap();
        let prepare = conn.rx_start_us().wrapping_sub(100);
        let mut expires = earlier(finish, conn.supervision_deadline_us());
        if let Some(end) = control.termination_deadline_us() {
            expires = earlier(expires, end);
        }
        while !reached(clock.now_us(), prepare) {
            if reached(clock.now_us(), expires) {
                expired(conn, &control, clock.now_us());
                break 'connection;
            }
        }
        if expired(conn, &control, clock.now_us()) {
            break;
        }
        inc(16);
        let event_limit = conn
            .event_start_us()
            .wrapping_add(u32::from(conn.params.interval) * 1250)
            .wrapping_sub(600);
        let mut until = conn.rx_end_us();
        let mut any_rx = false;
        // Bound packet exchanges as well as wall time; a busy Central cannot
        // make this event consume the following event or the finite run budget.
        for _ in 0..32 {
            if reached(clock.now_us(), finish) || reached(clock.now_us(), event_limit) {
                break;
            }
            let Some(packet) = receive(radio, clock, rx, until, expires) else {
                break;
            };
            let header = rx.0[0];
            let payload = &rx.0[2..packet.len];
            if payload.len() > 27 {
                inc(9);
                break;
            }
            let accepted = link.on_rx(
                header,
                payload,
                true,
                payload.is_empty()
                    || (pending.is_none() && control.termination_deadline_us().is_none()),
            );
            if accepted.status == RxStatus::Invalid {
                inc(9);
                break;
            }
            if accepted.tx_acked {
                if let Some(reason) = outgoing_terminate {
                    inc(28);
                    put(37, u32::from(reason));
                    break 'connection;
                }
            }
            let sequence_us = clock.now_us().wrapping_sub(packet.end);
            let first = !conn.established();
            // CPU completion minus full packet airtime follows the V208
            // estimator. Its CH585 latency has not been independently measured.
            if !conn.on_rx_anchor(packet.end, payload.len() as u8) {
                expired(conn, &control, packet.end);
                break 'connection;
            }
            if first {
                inc(15);
                if get(36) == 0 {
                    put(36, packet.end);
                }
            }
            any_rx = true;
            inc(17);
            put(42, u32::from(header));
            put(43, payload.len() as u32);
            let mut terminate = None;
            match accepted.status {
                RxStatus::Accepted => {
                    inc(41);
                    match header & 3 {
                        3 => {
                            inc(26);
                            put(38, u32::from(payload[0]));
                            match control.on_pdu(conn, payload, local_version) {
                                Ok(wchble::ll::ctrl::ControlAction::Reply(pdu)) => {
                                    if pdu.as_bytes().first() == Some(&7) {
                                        inc(27);
                                    }
                                    pending = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                                }
                                Ok(wchble::ll::ctrl::ControlAction::Terminate(reason)) => {
                                    terminate = Some(reason)
                                }
                                Ok(wchble::ll::ctrl::ControlAction::None) => {}
                                Err(error) => {
                                    let reason = wchble::ll::ctrl::termination_reason(error);
                                    pending = Some(DataPdu::new(3, &[2, reason]).unwrap());
                                    put(37, u32::from(reason));
                                }
                            }
                        }
                        2 => {
                            let mut response = [0; 27];
                            match upper::reply(payload, &mut response) {
                                Ok(len) => {
                                    pending = Some(DataPdu::new(2, &response[..len]).unwrap())
                                }
                                Err(()) => {
                                    pending = Some(DataPdu::new(3, &[2, 0x13]).unwrap());
                                    put(37, 0x13);
                                }
                            }
                        }
                        1 if !payload.is_empty() => {
                            pending = Some(DataPdu::new(3, &[2, 0x13]).unwrap());
                            put(37, 0x13);
                        }
                        _ => {}
                    }
                }
                RxStatus::Duplicate => inc(24),
                RxStatus::Backpressure => inc(31),
                RxStatus::Invalid => unreachable!(),
            }
            if pending
                .as_ref()
                .is_some_and(|pdu| pdu.llid() == 3 && pdu.payload().first() == Some(&2))
            {
                control.start_termination(clock.now_us(), conn.params.timeout);
            }
            expires = earlier(finish, conn.supervision_deadline_us());
            if let Some(end) = control.termination_deadline_us() {
                expires = earlier(expires, end);
            }
            let handled_us = clock.now_us().wrapping_sub(packet.end);
            let retry = link.has_outstanding();
            if !link.has_outstanding() {
                if let Some(pdu) = pending.take() {
                    if pdu.llid() == 3 && pdu.payload().first() == Some(&2) {
                        outgoing_terminate = Some(pdu.payload()[1]);
                    }
                    link.queue(pdu.llid(), pdu.payload()).unwrap();
                }
            }
            let pdu = link.tx_pdu();
            let frame = pdu.as_bytes();
            tx.0[..frame.len()].copy_from_slice(frame);
            let sent = transmit(radio, clock, &tx.0[..frame.len()], packet.end);
            put(58, sequence_us);
            put(59, handled_us);
            if retry {
                inc(25);
            }
            trace(
                clock,
                3,
                event,
                channel,
                header,
                payload.len() as u8,
                packet.end,
                u32::from(pdu.header()),
            );
            if !sent {
                put(37, 0x3f);
                break 'connection;
            }
            if let Some(reason) = terminate {
                inc(28);
                put(37, u32::from(reason));
                trace(
                    clock,
                    4,
                    event,
                    channel,
                    header,
                    payload.len() as u8,
                    u32::from(reason),
                    0,
                );
                break 'connection;
            }
            // Local terminate remains outstanding until ACK or supervision.
            // Even with MD=0, listen briefly for a retry; an empty window is
            // normal when the Central has ended the event.
            until = clock.now_us().wrapping_add(500);
            if reached(until, event_limit) {
                until = event_limit;
            }
        }
        if !any_rx {
            inc(23);
            trace(
                clock,
                5,
                event,
                channel,
                0,
                0,
                conn.rx_start_us(),
                conn.rx_end_us(),
            );
        }
        if conn.next_event().is_err() {
            put(37, 0x28);
            break;
        }
    }
    stop(radio, clock);
    let duration = clock.now_us().wrapping_sub(began);
    if duration > get(44) {
        put(44, duration);
    }
    trace(
        clock,
        6,
        conn.event_counter(),
        conn.channel(),
        0,
        0,
        get(37),
        duration,
    );
    put(2, 2);
}

#[entry]
#[link_section = ".highcode"]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    let hz = hal::delay::measured_sysclk().0;
    let clock = Clock {
        ticks: Cell::new(ExtendingTicks::new(
            hal::pac::SYSTICK.stk_cntl().read().cntl(),
        )),
        rate: TickRate::new(hz).unwrap(),
    };
    put(0, 0x5033_3538);
    put(1, 1);
    put(2, 1);
    put(35, hz);
    let scratch = SCRATCH.init(DmaBuf::zeroed());
    let rx = RX.init(DmaBuf::zeroed());
    let adv_buf = ADV.init(DmaBuf::zeroed());
    let rsp_buf = RSP.init(DmaBuf::zeroed());
    let data_buf = DATA.init(DmaBuf::zeroed());
    let mut adv = AdvState {
        enabled: true,
        own_addr: [0x13, 0, 0, 0xee, 0xff, 0xc1],
        ..AdvState::default()
    };
    adv.set_adv_data(
        14,
        &[
            2, 1, 6, 10, 9, b'w', b'c', b'h', b'5', b'8', b'5', b'-', b'p', b'3',
        ],
    );
    adv.set_scan_rsp(
        11,
        &[10, 9, b'w', b'c', b'h', b'5', b'8', b'5', b'-', b'p', b'3'],
    );
    let adv_len = adv.build_adv_ind(&mut adv_buf.0).unwrap();
    let rsp_len = adv.build_scan_rsp(&mut rsp_buf.0).unwrap();
    let mut radio = new_radio_with_dma(&mut scratch.0).unwrap();
    if radio.init(&clock).is_err() {
        put(2, 0xe1);
        park();
    }
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    stop(&mut radio, &clock);
    clock.delay_us(500_000);
    // The runner reads this same retained ELF constant before touching a probe.
    let budget = *core::hint::black_box(&RUN_SECONDS) * 1_000_000;
    let started = clock.now_us();
    let finish = started.wrapping_add(budget);
    put(2, 2);
    while !reached(clock.now_us(), finish) {
        radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
        for channel in [37u8, 38, 39] {
            if reached(clock.now_us(), finish) {
                break;
            }
            radio.set_channel(channel).unwrap();
            inc(3);
            if radio
                .tx_basic(&clock, &adv_buf.0[..adv_len], 0, None)
                .is_err()
            {
                inc(5);
                stop(&mut radio, &clock);
                continue;
            }
            inc(4);
            let Some(packet) = receive(
                &mut radio,
                &clock,
                rx,
                clock.now_us().wrapping_add(600),
                finish,
            ) else {
                continue;
            };
            let pdu = &rx.0[..packet.len];
            if adv.validate_scan_req(pdu, true) {
                inc(10);
                match radio.tx_basic(
                    &clock,
                    &rsp_buf.0[..rsp_len],
                    0,
                    Some(packet.end.wrapping_add(120)),
                ) {
                    Ok(()) => inc(11),
                    Err(wchble::Error::Late) => inc(12),
                    Err(_) => inc(5),
                }
                stop(&mut radio, &clock);
            } else if pdu[0] & 0x0f == 5 {
                inc(13);
                match ConnectParams::parse(pdu, true, adv.own_addr, adv.random_addr) {
                    Ok(params) => {
                        inc(14);
                        put(45, u32::from(params.interval));
                        put(46, u32::from(params.hop));
                        put(
                            47,
                            u32::from_le_bytes(params.channel_map[..4].try_into().unwrap()),
                        );
                        put(48, u32::from(params.channel_map[4]));
                        let mut conn = PeripheralConnection::new(params, packet.end);
                        put(49, conn.event_start_us());
                        put(50, u32::from(params.win_size) * 1250);
                        put(53, u32::from(conn.channel()));
                        trace(
                            &clock,
                            1,
                            0,
                            channel,
                            pdu[0],
                            pdu[1],
                            params.access_addr,
                            packet.end,
                        );
                        run_connection(&mut radio, &clock, rx, data_buf, &mut conn, finish);
                        stop(&mut radio, &clock);
                        radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
                        break;
                    }
                    Err(error) => {
                        inc(9);
                        trace(
                            &clock,
                            2,
                            0,
                            channel,
                            pdu[0],
                            pdu[1],
                            error as u32,
                            packet.end,
                        );
                    }
                }
            } else {
                inc(9);
            }
        }
        clock.delay_us(20_000);
    }
    stop(&mut radio, &clock);
    put(32, clock.now_us().wrapping_sub(started));
    put(33, reg(LLE_BASE, lle::CMD));
    put(34, reg(LLE_BASE, lle::MODE));
    put(2, 9);
    park();
}
