//! P3 finite LE 1M peripheral. No HCI Host or GATT database is linked.
#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::cell::Cell;
use hal::{rcc, time::Hertz};
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::crypto::{AesEngine, AesEngineError};
use wchble::hci::connection::{ConnectionInfo, RadioRequest, TxAcl, TxTag};
use wchble::hci::runner::LtkReply;
use wchble::ll::adv::AdvState;
use wchble::ll::conn::{ConnectParams, PeripheralConnection};
use wchble::ll::link::{self, AclReply, Control, LinkHost, Session, X1Snapshot};
use wchble::rf::family::ch585::{Ch585Radio, BB_BASE, LLE_BASE};
use wchble::rf::regs::{self, bb, bb_irq, lle};
use wchble::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use {panic_halt as _, portable_atomic as _};

mod upper;

static SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static ADV: StaticCell<DmaBuf<64>> = StaticCell::new();
static RSP: StaticCell<DmaBuf<64>> = StaticCell::new();
static DATA: StaticCell<DmaBuf<MAX_PDU>> = StaticCell::new();

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
        let elapsed = ticks.sample(hal::pac::SYSTICK.cntl().read().cntl());
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

fn trace_at(now_us: u32, kind: u32, event: u16, channel: u8, header: u8, len: u8, a: u32, b: u32) {
    let count = get(39) as usize;
    // Keep a short opening trace plus a rolling tail; counters cover the run.
    let row = if count < 128 {
        count
    } else {
        64 + (count - 128) % 64
    };
    let words = [
        now_us,
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

fn trace(clock: &Clock, kind: u32, event: u16, channel: u8, header: u8, len: u8, a: u32, b: u32) {
    trace_at(clock.now_us(), kind, event, channel, header, len, a, b);
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
    crc_ok: bool,
}

#[link_section = ".highcode"]
#[inline(never)]
fn receive_adv(
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
    // `until` allows packet completion, not just its latest preamble start.
    // The hardware WINDOW and software no-capture timeout must agree.
    let window = until.wrapping_sub(now).saturating_mul(2);
    // SAFETY: `rx` is a static DMA buffer and every path below stops the
    // engine before returning, so no window outlives this call.
    if unsafe { radio.rx_basic(clock, &mut rx.0, window) }.is_err() {
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
    // Never inspect DMA until the engine has acknowledged the stop.
    let len = usize::from(rx.0[1]) + 2;
    if len > 40 {
        if !crc_ok {
            // A header-only error still consumes the frame.
            inc(8);
            return Some(Received {
                len: 2,
                end,
                crc_ok,
            });
        }
        inc(9);
        return None;
    }
    put(55, clock.now_us().wrapping_sub(end));
    if !crc_ok {
        inc(8);
    }
    Some(Received { len, end, crc_ok })
}

/// Legacy LL payload P3 accepts and answers with.
const P3_PAYLOAD_LIMIT: usize = 27;
/// P3 advertises no optional features, so the engine gates encryption/DLE.
const P3_FEATURES: [u8; 8] = [0; 8];

/// P3 never advertises LE Encryption, so the AES engine must stay unreachable.
struct NoEncryption;

impl AesEngine for NoEncryption {
    fn encrypt_block(&mut self, _block: &mut [u8; 16]) -> Result<(), AesEngineError> {
        Err(AesEngineError::Timeout)
    }
}

/// P3 has no HCI bridge: requests are answered from `upper::reply`; an
/// unsupported or fragmented request terminates the link with 0x13.
struct P3Host<'a> {
    clock: &'a Clock,
}

impl LinkHost for P3Host<'_> {
    type Aes = NoEncryption;

    fn local_features(&self) -> [u8; 8] {
        P3_FEATURES
    }
    fn new_aes(&mut self, _key: &[u8; 16]) -> NoEncryption {
        NoEncryption
    }

    fn stat_inc(&mut self, slot: usize) {
        inc(slot);
    }
    fn stat_put(&mut self, slot: usize, value: u32) {
        put(slot, value);
    }
    fn stat_get(&self, slot: usize) -> u32 {
        get(slot)
    }
    fn sec_inc(&mut self, _slot: usize) {}
    fn sec_put(&mut self, _slot: usize, _value: u32) {}

    fn trace(
        &mut self,
        now_us: u32,
        kind: u32,
        event: u16,
        channel: u8,
        header: u8,
        len: u8,
        a: u32,
        b: u32,
    ) {
        trace_at(now_us, kind, event, channel, header, len, a, b);
    }

    fn diag_acl_raw(&mut self, _llid: u8, _payload: &[u8], _ciphertext: bool) {}
    fn diag_acl_plain(&mut self, _llid: u8, _payload: &[u8]) {}
    fn diag_control_opcode(&mut self, _opcode: u8) {}
    fn note_bad_pdu(&mut self, _header: u8, _len: usize) {}
    fn note_rx_frame(&mut self, _len: usize) {}
    fn note_rx_oversize(&mut self) {}
    fn note_start_req_queued(&mut self) {}
    fn note_start_rsp_queued(&mut self) {}
    fn diag_skipped_event(&mut self) {}

    fn can_receive_acl(&mut self, _llid: u8, len: usize) -> bool {
        len <= P3_PAYLOAD_LIMIT
    }
    fn receive_acl(&mut self, _llid: u8, _payload: &[u8]) -> bool {
        // The request side effect already ran in `acl_reply`.
        true
    }
    fn take_tx_acl(&mut self) -> Option<TxAcl> {
        None
    }
    fn ack_tx(&mut self, _tag: TxTag) -> bool {
        true
    }

    // Between packet end and the scheduled response: keep it in RAM.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    #[inline(never)]
    fn acl_reply(&mut self, llid: u8, payload: &[u8]) -> Option<AclReply> {
        if llid != 2 {
            // A non-empty continuation fragment is not an L2CAP packet.
            return Some(AclReply::terminate(0x13));
        }
        let mut out = [0u8; P3_PAYLOAD_LIMIT];
        match upper::reply(payload, &mut out) {
            Ok(len) => AclReply::new(2, &out[..len]),
            Err(()) => Some(AclReply::terminate(0x13)),
        }
    }
    fn rx_payload_limit(&self) -> usize {
        P3_PAYLOAD_LIMIT
    }
    fn rx_capture_timeout_us(&self) -> Option<u32> {
        Some(700)
    }
    fn rx_rearm_window_us(&self) -> Option<u32> {
        Some(500)
    }
    fn allows_feature_request(&self) -> bool {
        false
    }
    fn establishment_event_limit(&self) -> Option<u16> {
        Some(6)
    }

    fn is_connected(&self) -> bool {
        true
    }
    fn publish_connection(&mut self, _info: &mut ConnectionInfo) -> bool {
        true
    }
    fn disable_adv(&mut self) {}
    fn connection_closed(&mut self, _reason: u8) {}
    fn encryption_change(&mut self, _handle: u16, _status: u8, _enabled: u8) {}
    fn connection_updated(&mut self, _interval: u16, _latency: u16, _timeout: u16) -> bool {
        true
    }
    fn data_length_change(&mut self, _a: u16, _b: u16, _c: u16, _d: u16) -> bool {
        true
    }

    fn take_ltk_reply(&mut self) -> Option<LtkReply> {
        None
    }
    fn push_ltk_request(&mut self, _rand: [u8; 8], _ediv: u16) -> bool {
        false
    }
    fn take_data_length_request(&mut self) -> Option<(u16, u16)> {
        None
    }

    fn publish_x1(&mut self, _snapshot: &X1Snapshot) {}

    fn idle_gap(&mut self, _deadline: u32, until: u32) {
        // The outer loop re-enters `step`; spin like the old inner wait.
        while !reached(self.clock.now_us(), until) {
            core::hint::spin_loop();
        }
    }
    fn after_close(&mut self) {}
    fn on_reset(&mut self) {}
    fn on_disconnect_request(&mut self, _reason: u8) {}
    fn pre_iteration(&mut self) {}
    fn take_radio_request(&mut self) -> Option<RadioRequest> {
        None
    }
}

#[link_section = ".highcode"]
#[inline(never)]
fn run_connection(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    params: ConnectParams,
    end: u32,
    finish: u32,
) {
    let began = clock.now_us();
    let mut host = P3Host { clock };
    let mut session = Session::new(params, false, end, began, [0; 12], P3_FEATURES);
    radio.set_aa_crc(params.access_addr, params.crc_init);
    put(2, 3);
    put(37, 0);
    loop {
        match link::step(&mut session, &mut host, radio, clock, rx, tx, finish) {
            Control::Continue => {}
            Control::Closed(_) | Control::Reset => {
                put(2, 2);
                return;
            }
            Control::Finish => {
                stop(radio, clock);
                let duration = clock.now_us().wrapping_sub(began);
                if duration > get(44) {
                    put(44, duration);
                }
                trace_at(
                    clock.now_us(),
                    6,
                    session.event_counter(),
                    session.channel(),
                    0,
                    0,
                    get(37),
                    duration,
                );
                put(2, 2);
                return;
            }
            Control::StopTimeout => {
                inc(22);
                put(2, 0xee);
                park();
            }
        }
    }
}

#[entry]
#[link_section = ".highcode"]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    // HSE/PLL nominal is more accurate than the RC-referenced delay estimate.
    let hz = hal::rcc::clocks().sysclk.0;
    let clock = Clock {
        ticks: Cell::new(ExtendingTicks::new(hal::pac::SYSTICK.cntl().read().cntl())),
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
            // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or stops
            // the engine on error; the frame only has to live for the call.
            if unsafe { radio.tx_basic(&clock, &adv_buf.0[..adv_len], 0, None) }.is_err() {
                inc(5);
                stop(&mut radio, &clock);
                continue;
            }
            inc(4);
            let Some(packet) = receive_adv(
                &mut radio,
                &clock,
                rx,
                clock.now_us().wrapping_add(600),
                finish,
            ) else {
                continue;
            };
            let pdu = &rx.0[..packet.len];
            if adv.validate_scan_req(pdu, packet.crc_ok) {
                inc(10);
                // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or stops the
                // engine on error; the response frame only has to live for the call.
                match unsafe {
                    radio.tx_basic(
                        &clock,
                        &rsp_buf.0[..rsp_len],
                        0,
                        Some(packet.end.wrapping_add(120)),
                    )
                } {
                    Ok(()) => inc(11),
                    Err(wchble::Error::Late) => inc(12),
                    Err(_) => inc(5),
                }
                stop(&mut radio, &clock);
            } else if pdu[0] & 0x0f == 5 {
                inc(13);
                match ConnectParams::parse(pdu, packet.crc_ok, adv.own_addr, adv.random_addr) {
                    Ok(params) => {
                        inc(14);
                        put(45, u32::from(params.interval));
                        put(46, u32::from(params.hop));
                        put(
                            47,
                            u32::from_le_bytes(params.channel_map[..4].try_into().unwrap()),
                        );
                        put(48, u32::from(params.channel_map[4]));
                        let conn = PeripheralConnection::new(params, packet.end, false);
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
                        run_connection(
                            &mut radio, &clock, rx, data_buf, params, packet.end, finish,
                        );
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
