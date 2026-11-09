//! Finite P4 radio/Controller pump with a real Trouble GATT Host.
#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Waker};
use hal::{rcc, time::Hertz};
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::hci::connection::{ConnectionBridge, ConnectionInfo, RadioRequest, TxTag};
use wchble::hci::SoftRunner;
use wchble::ll::acl::{DataPdu, LinkSequence, RxStatus};
use wchble::ll::conn::{ConnectParams, PeripheralConnection};
use wchble::ll::ctrl::{ControlAction, ControlState, LocalVersion};
use wchble::rf::family::ch585::{Ch585Radio, BB_BASE, LLE_BASE};
use wchble::rf::regs::{self, bb, bb_irq, lle};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use {panic_halt as _, portable_atomic as _};

mod host;

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
static mut HOST_STATS: [u32; 16] = [0; 16];
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
fn earlier(a: u32, b: u32) -> u32 {
    if reached(a, b) {
        b
    } else {
        a
    }
}

struct Clock {
    ticks: Cell<ExtendingTicks>,
    rate: TickRate,
}
impl InstantUs for Clock {
    fn now_us(&self) -> u32 {
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
                .write_volatile(word)
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
    arm_times: &mut [u32; 2],
) -> Option<Received> {
    unsafe {
        regs::write(BB_BASE, bb::IRQSTAT, 0xf0);
    }
    let now = clock.now_us();
    *arm_times = [now, 0];
    if reached(now, until) || reached(now, expires) {
        return None;
    }
    // `until` allows packet completion, not just its latest preamble start.
    // The hardware WINDOW and software no-capture timeout must agree.
    let window = until.wrapping_sub(now).saturating_mul(2);
    if radio.rx_basic(clock, &mut rx.0, window).is_err() {
        inc(21);
        stop(radio, clock);
        return None;
    }
    arm_times[1] = clock.now_us();
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
    put(56, clock.now_us().wrapping_sub(end));
    // Preserve the P3 command deadline; it is not calibrated air IFS.
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

struct Session {
    conn: PeripheralConnection,
    link: LinkSequence,
    control: ControlState,
    pending_control: Option<DataPdu>,
    acl_tag: Option<TxTag>,
    terminating: Option<u8>,
    terminate_requested: Option<u8>,
    update_instant: Option<u16>,
    update_report: Option<(u16, u16, u16)>,
    began: u32,
}
impl Session {
    fn new(params: ConnectParams, end: u32, now: u32) -> Self {
        Self {
            conn: PeripheralConnection::new(params, end),
            link: LinkSequence::new(),
            control: ControlState::new(),
            pending_control: None,
            acl_tag: None,
            terminating: None,
            terminate_requested: None,
            update_instant: None,
            update_report: None,
            began: now,
        }
    }
    fn expiration(&self, now: u32) -> Option<u8> {
        if self.control.termination_expired(now) {
            inc(60);
            return Some(0x08);
        }
        if self.conn.supervision_expired(now) {
            inc(if self.conn.established() { 29 } else { 30 });
            return Some(if self.conn.established() { 0x08 } else { 0x3e });
        }
        None
    }
    fn request_terminate(&mut self, reason: u8, now: u32) {
        self.terminate_requested.get_or_insert(reason);
        self.control
            .start_termination(now, self.conn.params.timeout);
    }
}

#[link_section = ".highcode"]
#[inline(never)]
fn connection_event(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<64>,
    s: &mut Session,
    bridge: &mut ConnectionBridge,
    finish: u32,
) -> Option<u8> {
    if let Some(reason) = s.expiration(clock.now_us()) {
        return Some(reason);
    }
    let event = s.conn.event_counter();
    let channel = s.conn.channel();
    put(51, u32::from(event));
    put(52, u32::from(channel));
    inc(16);
    let event_limit = s
        .conn
        .event_start_us()
        .wrapping_add(u32::from(s.conn.params.interval) * 1250)
        .wrapping_sub(600);
    let mut expires = earlier(
        event_limit,
        earlier(finish, s.conn.supervision_deadline_us()),
    );
    if let Some(end) = s.control.termination_deadline_us() {
        expires = earlier(expires, end);
    }
    // Once inside the Host guard, stay in this tight RF wait like P3. Returning
    // through idle snapshots and the outer loop can overshoot RX prepare.
    let prepare = s.conn.rx_start_us().wrapping_sub(100);
    while !reached(clock.now_us(), prepare) {
        let now = clock.now_us();
        if reached(now, expires) {
            return s.expiration(now);
        }
    }
    if let Some(reason) = s.expiration(clock.now_us()) {
        return Some(reason);
    }
    let mut until = s.conn.rx_complete_end_us();
    let mut any_rx = false;
    for _ in 0..32 {
        if reached(clock.now_us(), finish) || reached(clock.now_us(), event_limit) {
            break;
        }
        let first_exchange = !any_rx;
        let mut arm_times = [0; 2];
        let Some(packet) = receive(radio, clock, rx, until, expires, &mut arm_times) else {
            if first_exchange {
                trace(clock, 8, event, channel, 0, 0, arm_times[0], arm_times[1]);
            }
            break;
        };
        let header = rx.0[0];
        let payload = &rx.0[2..packet.len];
        if payload.len() > 27 {
            inc(9);
            break;
        }
        let llid = header & 3;
        let capacity = match llid {
            1 if payload.is_empty() => true,
            1 | 2 => bridge.can_receive_acl(llid, payload.len()),
            3 => {
                s.pending_control.is_none()
                    && s.terminate_requested.is_none()
                    && s.update_report.is_none()
            }
            _ => false,
        };
        let outcome = s.link.on_rx(header, payload, true, capacity);
        if outcome.status == RxStatus::Invalid {
            inc(9);
            break;
        }
        let acknowledged_acl = if outcome.tx_acked {
            s.acl_tag.take()
        } else {
            None
        };
        if outcome.tx_acked {
            if let Some(reason) = s.terminating {
                inc(28);
                return Some(reason);
            }
        }
        let sequence_us = clock.now_us().wrapping_sub(packet.end);
        let first = !s.conn.established();
        if !s.conn.on_rx_anchor(packet.end, payload.len() as u8) {
            return s.expiration(packet.end).or(Some(0x08));
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
        let mut remote_terminate = None;
        let mut deliver_acl = false;
        match outcome.status {
            RxStatus::Accepted => {
                inc(41);
                if llid == 3 {
                    inc(26);
                    put(38, u32::from(payload[0]));
                    let local = LocalVersion {
                        version: 0x0d,
                        company_id: 0xffff,
                        subversion: 1,
                    };
                    match s.control.on_pdu(&mut s.conn, payload, local) {
                        Ok(ControlAction::Reply(pdu)) => {
                            if pdu.as_bytes().first() == Some(&7) {
                                inc(27);
                            }
                            s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                        }
                        Ok(ControlAction::Terminate(reason)) => remote_terminate = Some(reason),
                        Ok(ControlAction::None) => {
                            if payload[0] == 0 && payload.len() == 12 {
                                s.update_instant =
                                    Some(u16::from_le_bytes([payload[10], payload[11]]));
                            }
                        }
                        Err(error) => s.request_terminate(
                            wchble::ll::ctrl::termination_reason(error),
                            packet.end,
                        ),
                    }
                } else {
                    deliver_acl = !(llid == 1 && payload.is_empty());
                }
            }
            RxStatus::Duplicate => inc(24),
            RxStatus::Backpressure => inc(31),
            RxStatus::Invalid => unreachable!(),
        }
        expires = earlier(
            event_limit,
            earlier(finish, s.conn.supervision_deadline_us()),
        );
        if let Some(end) = s.control.termination_deadline_us() {
            expires = earlier(expires, end);
        }
        let handled_us = clock.now_us().wrapping_sub(packet.end);
        let retry = s.link.has_outstanding();
        if !retry {
            if let Some(pdu) = s.pending_control.take() {
                s.link.queue(3, pdu.payload()).unwrap();
            } else if let Some(reason) = s.terminate_requested.take() {
                s.link.queue(3, &[2, reason]).unwrap();
                s.terminating = Some(reason);
            } else if let Some(acl) = bridge.take_tx_acl() {
                s.link.queue(acl.llid, &acl.bytes[..acl.len]).unwrap();
                s.acl_tag = Some(acl.tag);
            }
        }
        let pdu = s.link.tx_pdu();
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
        if first_exchange {
            trace(clock, 8, event, channel, 0, 0, arm_times[0], arm_times[1]);
        }
        if !sent {
            return Some(0x3f);
        }
        // Serialize HCI output only after the time-critical radio response.
        // No Host poll can consume the RX reservation in this interval.
        if first {
            let p = s.conn.params;
            let info = ConnectionInfo {
                handle: 1,
                peer_address_type: u8::from(p.peer_random),
                peer_address: p.peer_addr,
                interval: p.interval,
                latency: p.latency,
                supervision_timeout: p.timeout,
            };
            if bridge.connected(info).is_err() {
                inc(63);
                return Some(0x1f);
            }
        }
        if let Some(tag) = acknowledged_acl {
            if !bridge.ack_tx(tag) {
                inc(63);
                return Some(0x1f);
            }
        }
        if deliver_acl && bridge.receive_acl(llid, payload).is_err() {
            inc(63);
            return Some(0x1f);
        }
        if let Some(reason) = remote_terminate {
            inc(28);
            return Some(reason);
        }
        until = earlier(clock.now_us().wrapping_add(500), event_limit);
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
            s.conn.rx_start_us(),
            s.conn.rx_end_us(),
        );
    }
    if s.conn.next_event().is_err() {
        return Some(0x28);
    }
    if s.update_instant == Some(s.conn.event_counter()) {
        s.update_instant = None;
        s.update_report = Some((
            s.conn.params.interval,
            s.conn.params.latency,
            s.conn.params.timeout,
        ));
    }
    s.expiration(clock.now_us())
}

fn host_snapshot(stats: &host::HostStats) {
    for i in 0..16 {
        unsafe {
            core::ptr::addr_of_mut!(HOST_STATS)
                .cast::<u32>()
                .add(i)
                .write_volatile(stats.word(i));
        }
    }
}

fn idle<F: Future>(
    soft: &mut SoftRunner,
    mut future: Pin<&mut F>,
    stats: &host::HostStats,
    clock: &Clock,
    until: u32,
) {
    for _ in 0..4 {
        // A poll is non-preemptible. This guard is backed by measured maximum
        // poll time, not a promise that arbitrary futures are hard real-time.
        let before = clock.now_us();
        if reached(before.wrapping_add(2000), until) {
            break;
        }
        soft.pump_once();
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            inc(63);
        }
        let took = clock.now_us().wrapping_sub(before);
        if took > get(61) {
            put(61, took);
        }
        if reached(clock.now_us(), until) {
            inc(62);
            break;
        }
    }
    host_snapshot(stats);
}

#[entry]
#[link_section = ".highcode"]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    // HSE/PLL nominal is more accurate than the RC-referenced delay estimate.
    let hz = hal::rcc::clocks().sysclk.0;
    let clock = Clock {
        ticks: Cell::new(ExtendingTicks::new(
            hal::pac::SYSTICK.stk_cntl().read().cntl(),
        )),
        rate: TickRate::new(hz).unwrap(),
    };
    put(0, 0x5034_3538);
    put(1, 1);
    put(2, 1);
    put(35, hz);
    let scratch = SCRATCH.init(DmaBuf::zeroed());
    let rx = RX.init(DmaBuf::zeroed());
    let adv_buf = ADV.init(DmaBuf::zeroed());
    let rsp_buf = RSP.init(DmaBuf::zeroed());
    let data = DATA.init(DmaBuf::zeroed());
    let mut radio = new_radio_with_dma(&mut scratch.0).unwrap();
    if radio.init(&clock).is_err() {
        put(2, 0xe1);
        park();
    }
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    stop(&mut radio, &clock);
    let controller = wchble::hci::new();
    let mut soft = SoftRunner::new();
    let app_stats = host::HostStats::new();
    let mut app = core::pin::pin!(host::run(controller, &app_stats));
    let started = clock.now_us();
    let budget = *core::hint::black_box(&RUN_SECONDS) * 1_000_000;
    let finish = started.wrapping_add(budget);
    let mut session: Option<Session> = None;
    let mut next_adv = started;
    put(2, 2);
    while !reached(clock.now_us(), finish) {
        if let Some(request) = soft.bridge.take_radio_request() {
            match request {
                RadioRequest::Reset => {
                    stop(&mut radio, &clock);
                    session = None;
                    soft.bridge.reset_finished();
                    put(2, 2);
                }
                RadioRequest::Disconnect { reason } => {
                    if let Some(s) = session.as_mut() {
                        s.request_terminate(reason, clock.now_us());
                    }
                }
            }
        }
        if let Some(s) = session.as_mut() {
            let mut reason = s.expiration(clock.now_us());
            if let Some((interval, latency, timeout)) = s.update_report {
                if soft
                    .bridge
                    .connection_updated(interval, latency, timeout)
                    .is_ok()
                {
                    s.update_report = None;
                }
            }
            // Match P3: configure the channel before waiting for RX prepare,
            // not inside the final 100 us RF arming allowance.
            if reason.is_none() && radio.channel() != s.conn.channel() {
                radio.set_channel(s.conn.channel()).unwrap();
            }
            let prepare = s.conn.rx_start_us().wrapping_sub(100);
            if reason.is_none() && !reached(clock.now_us().wrapping_add(2000), prepare) {
                let mut until = earlier(prepare, earlier(finish, s.conn.supervision_deadline_us()));
                if let Some(end) = s.control.termination_deadline_us() {
                    until = earlier(until, end);
                }
                idle(&mut soft, app.as_mut(), &app_stats, &clock, until);
                continue;
            }
            if reason.is_none() {
                reason =
                    connection_event(&mut radio, &clock, rx, data, s, &mut soft.bridge, finish);
                if s.conn.established() {
                    soft.ll.adv.enabled = false;
                }
            }
            if let Some(reason) = reason {
                stop(&mut radio, &clock);
                let duration = clock.now_us().wrapping_sub(s.began);
                if duration > get(44) {
                    put(44, duration);
                }
                put(37, u32::from(reason));
                trace(
                    &clock,
                    6,
                    s.conn.event_counter(),
                    s.conn.channel(),
                    0,
                    0,
                    u32::from(reason),
                    duration,
                );
                if soft.bridge.is_connected() {
                    soft.bridge.disconnected(reason);
                }
                session = None;
                put(2, 2);
                next_adv = clock.now_us();
            }
            continue;
        }
        let now = clock.now_us();
        let idle_until = if soft.adv_enabled() && !reached(now, next_adv) {
            next_adv
        } else {
            now.wrapping_add(3000)
        };
        idle(
            &mut soft,
            app.as_mut(),
            &app_stats,
            &clock,
            earlier(finish, idle_until),
        );
        if !soft.adv_enabled() || !reached(clock.now_us(), next_adv) {
            continue;
        }
        radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
        let Some(adv_len) = soft.build_adv_pdu(&mut adv_buf.0) else {
            continue;
        };
        let Some(rsp_len) = soft.ll.adv.build_scan_rsp(&mut rsp_buf.0) else {
            inc(63);
            break;
        };
        for channel in [37u8, 38, 39] {
            if soft.ll.adv.channel_map & (1 << (channel - 37)) == 0 {
                continue;
            }
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
                &mut [0; 2],
            ) else {
                continue;
            };
            let pdu = &rx.0[..packet.len];
            if soft.ll.adv.validate_scan_req(pdu, true) {
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
                match ConnectParams::parse(pdu, true, soft.ll.adv.own_addr, soft.ll.adv.random_addr)
                {
                    Ok(params) => {
                        inc(14);
                        put(45, u32::from(params.interval));
                        put(46, u32::from(params.hop));
                        put(
                            47,
                            u32::from_le_bytes(params.channel_map[..4].try_into().unwrap()),
                        );
                        put(48, u32::from(params.channel_map[4]));
                        let s = Session::new(params, packet.end, clock.now_us());
                        put(49, s.conn.event_start_us());
                        put(50, u32::from(params.win_size) * 1250);
                        put(53, u32::from(s.conn.channel()));
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
                        trace(
                            &clock,
                            7,
                            0,
                            channel,
                            u8::from(params.peer_random),
                            6,
                            u32::from_le_bytes(params.peer_addr[..4].try_into().unwrap()),
                            u32::from(u16::from_le_bytes([
                                params.peer_addr[4],
                                params.peer_addr[5],
                            ])),
                        );
                        radio.set_aa_crc(params.access_addr, params.crc_init);
                        session = Some(s);
                        put(2, 3);
                        break;
                    }
                    Err(_) => inc(9),
                }
            } else {
                inc(9);
            }
        }
        next_adv = clock.now_us().wrapping_add(soft.adv_interval_us());
    }
    stop(&mut radio, &clock);
    host_snapshot(&app_stats);
    put(32, clock.now_us().wrapping_sub(started));
    put(33, reg(LLE_BASE, lle::CMD));
    put(34, reg(LLE_BASE, lle::MODE));
    put(2, 9);
    park();
}
