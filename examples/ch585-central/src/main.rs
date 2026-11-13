//! Finite C1 CH585 Central: scan, CONNECT_IND, TX-first link, Trouble GATT client.
#![no_std]
#![no_main]

use ch5xx_hal as hal;
use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::Ordering;
use portable_atomic::AtomicU64;
use core::task::{Context, Waker};
use hal::{rcc, time::Hertz};
use qingke_rt::entry;
use static_cell::StaticCell;
use wchble::hci::connection::{ConnectionBridge, ConnectionInfo, RadioRequest, TxAcl, TxTag};
use wchble::hci::SoftRunner;
use wchble::ll::acl::{DataPdu, LinkSequence, RxStatus};
use wchble::ll::central::CentralConnection;
use wchble::ll::conn::ConnectParams;
use wchble::ll::ctrl::{
    feature_bits, ControlAction, ControlState, LocalVersion, FEATURE_LE_CSA2,
    FEATURE_LE_DATA_LENGTH_EXTENSION,
};
use wchble::ll::enc::MAX_ENCRYPTED;
use wchble::ll::scan;

/// CSA #2 and DLE; this example does not drive encryption.
const LOCAL_FEATURES: [u8; 8] = feature_bits(&[
    FEATURE_LE_DATA_LENGTH_EXTENSION,
    FEATURE_LE_CSA2,
]);
use wchble::rf::family::ch585::{Ch585Radio, BB_BASE, LLE_BASE};
use wchble::rf::regs::{self, bb, bb_irq, lle};
use wchble::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use portable_atomic as _;

mod host;

static SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
/// The LLE fetch appears to read 32-byte blocks; keep CONNECT_IND on a
/// 32-byte boundary so the block containing its tail is unambiguous. Two
/// variants are prebuilt: offset 0 has ChSel=0, offset 64 has ChSel=1.
#[repr(align(32))]
struct ConnIndBuf(DmaBuf<128>);
const CONN_IND_CSEL_OFFSET: usize = 64;
static CONN_IND: StaticCell<ConnIndBuf> = StaticCell::new();
static DATA: StaticCell<DmaBuf<MAX_PDU>> = StaticCell::new();

#[no_mangle]
#[used]
pub static RUN_SECONDS: u32 = if cfg!(feature = "long-run") {
    180
} else if cfg!(feature = "short-run") {
    25
} else {
    60
};
#[no_mangle]
static mut STATS: [u32; 64] = [0; 64];
#[no_mangle]
static mut HOST_STATS: [u32; 16] = [0; 16];
#[no_mangle]
static mut TRACE: [u32; 128 * 8] = [0; 128 * 8];
#[no_mangle]
static mut TRACE_COUNT: u32 = 0;
#[no_mangle]
static mut TRACE_OVERFLOW: u32 = 0;
/// Temporary bring-up probe: CONNECT_IND parameters as built, before the LLE.
#[no_mangle]
static mut IND_DEBUG: [u32; 4] = [0; 4];

/// Image identity checked by the runner before it touches the probe.
#[no_mangle]
#[used]
pub static TARGET_NAME: [u8; 9] = *b"wch585-c1";
#[no_mangle]
#[used]
pub static AA: u32 = CONNECT_AA;
#[no_mangle]
#[used]
pub static CRC_INIT: u32 = CONNECT_CRC_INIT;
#[no_mangle]
#[used]
pub static WIN_SPEC: u32 = (WIN_SIZE as u32) | ((WIN_OFFSET as u32) << 8);
#[no_mangle]
#[used]
pub static CONNECT_OFFSET: u32 = CONNECT_OFFSET_US;
#[no_mangle]
#[used]
pub static BOGUS_PEER: u32 = if cfg!(feature = "bogus-peer") { 1 } else { 0 };
#[no_mangle]
#[used]
pub static SERVICE_UUID: [u8; 16] = *b"\x00\x00\x10\x00\xb0\xcd\x11\xec\x87\x1f\xd4\x5d\xdf\x13\x88\x40";

const CONNECT_AA: u32 = 0x1234_5678;
const CONNECT_CRC_INIT: u32 = 0x0055_5555;
const CONNECT_HOP: u8 = 5;
const CONNECT_SCA: u8 = 0;
/// All 37 data channels. The earlier 16-channel map and the tail rewrite came
/// from the nRF sniffer's synthesized CONNECT_IND report, which does not match
/// what the CH585 peripheral actually received on air.
const CONNECT_CHM: [u8; 5] = [0xff, 0xff, 0xff, 0xff, 0x1f];
const WIN_SIZE: u8 = 8;
const WIN_OFFSET: u16 = 0;
/// Retained for the runner's image metadata; the initiator now lets the LLE
/// start the packet at hardware T_IFS instead of using a software deadline.
const CONNECT_OFFSET_US: u32 = 0;
/// Program the event's first packet this long before the scheduled anchor so
/// `tx_basic` is not late. A constant error cancels because the peer anchors on
/// our actual packets. Not an air-IFS claim.
const EVENT_TX_LEAD_US: u32 = 100;
/// Latest start for the peer's response after our packet. The completion
/// allowance itself scales with the negotiated RX payload.
const RESPONSE_WINDOW_US: u32 = 2_000;
/// Give up on an initiator request if the target advertisement never arrives.
const INITIATOR_TIMEOUT_US: u32 = 6_000_000;
const SCAN_WINDOW_US: u32 = 15_000;
/// Extra time for the latest-starting LE1M advertising packet (at most 40
/// on-air octets) to complete. Connection PDUs use the negotiated scale.
const SCAN_RX_COMPLETE_US: u32 = 80 + 40 * 8;

const STAGE_INIT: u32 = 1;
const STAGE_SCANNING: u32 = 2;
const STAGE_CONNECTING: u32 = 3;
const STAGE_CONNECTED: u32 = 4;
const STAGE_GATT: u32 = 5;
const STAGE_DONE: u32 = 9;

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

/// `panic_halt` hides the failing location. Store it in STATS[63] with a magic
/// tag so a frozen run still tells us where it died; the runner reports it.
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    if let Some(loc) = info.location() {
        put(63, 0x9000_0000 | (loc.line() & 0xffff));
        put(59, u32::from(loc.column()));
    }
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

/// Cooperative embassy time: the host future is only polled at RF idle
/// boundaries, so a wake is simply a readiness hint and timers re-check `now`.
static EMBASSY_NOW_US: AtomicU64 = AtomicU64::new(0);

struct HostTime;

impl embassy_time_driver::Driver for HostTime {
    fn now(&self) -> u64 {
        EMBASSY_NOW_US.load(Ordering::Relaxed)
    }

    fn schedule_wake(&self, _at: u64, waker: &Waker) {
        waker.wake_by_ref();
    }
}

embassy_time_driver::time_driver_impl!(static HOST_TIME: HostTime = HostTime);

fn trace(clock: &Clock, kind: u32, event: u16, channel: u8, header: u8, len: u8, a: u32, b: u32) {
    let count = unsafe { core::ptr::addr_of!(TRACE_COUNT).read_volatile() } as usize;
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
    unsafe {
        core::ptr::addr_of_mut!(TRACE_COUNT).write_volatile((count + 1) as u32);
        if count >= 128 {
            let overflow = core::ptr::addr_of!(TRACE_OVERFLOW).read_volatile();
            core::ptr::addr_of_mut!(TRACE_OVERFLOW).write_volatile(overflow.wrapping_add(1));
        }
    }
}

fn stop(radio: &mut Ch585Radio, clock: &Clock) {
    radio.shut();
    let start = clock.now_us();
    while reg(LLE_BASE, lle::CMD) & 3 != 0 {
        if clock.now_us().wrapping_sub(start) >= 100 {
            inc(58);
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
    crc_ok: bool,
    /// This advertisement carried the address the initiator is waiting for.
    target_matched: bool,
    /// ChSel bit of the target advertisement (CSA #2 support).
    peer_chsel: bool,
    /// Completion time of an armed CONNECT_IND, present when this RX event was
    /// the target advertisement and the LLE accepted the TX arm.
    connect_done: Option<u32>,
}

/// One passive-scan window. Counts arms/completions/timeouts and CRC results.
#[link_section = ".highcode"]
#[inline(never)]
fn receive_scan(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    until: u32,
    expires: u32,
    initiator: Option<&Initiator>,
    conn_buf: &mut ConnIndBuf,
) -> Option<Received> {
    unsafe {
        regs::write(BB_BASE, bb::IRQSTAT, 0xf0);
    }
    let now = clock.now_us();
    if reached(now, until) || reached(now, expires) {
        return None;
    }
    let window = until.wrapping_sub(now).saturating_mul(2);
    inc(5);
    if radio.rx_basic(clock, &mut rx.0, window).is_err() {
        inc(7);
        stop(radio, clock);
        return None;
    }
    let mut capture = None;
    let (end, crc_ok) = loop {
        let status = reg(LLE_BASE, lle::IRQSTAT);
        let now = clock.now_us();
        if reached(now, expires) {
            inc(7);
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
            inc(7);
            stop(radio, clock);
            return None;
        }
    };
    inc(6);
    if !crc_ok {
        inc(9);
        stop(radio, clock);
        return Some(Received {
            len: 0,
            end,
            crc_ok: false,
            target_matched: false,
            peer_chsel: false,
            connect_done: None,
        });
    }
    let len = usize::from(rx.0[1]) + 2;
    if len > 40 {
        inc(9);
        stop(radio, clock);
        return Some(Received {
            len: 0,
            end,
            crc_ok: false,
            target_matched: false,
            peer_chsel: false,
            connect_done: None,
        });
    }

    // Arm the prepared CONNECT_IND before stopping: the vendor initiator
    // (`LL_InitiateSetRF` + `ll_initiate_tx`) keeps the LLE in its RX window
    // and lets the engine start the packet at hardware T_IFS. Nothing slow may
    // run between RX_DONE and this arm.
    let mut target_matched = false;
    let mut peer_chsel = false;
    let mut connect_done = None;
    if let Some(init) = initiator {
        let header = rx.0[0];
        let adv_random = header & 0x40 != 0;
        if header & 0x0f == 0
            && adv_random == init.request.peer_random
            && rx.0[2..8] == init.request.peer_addr
        {
            target_matched = true;
            peer_chsel = header & 0x20 != 0;
            inc(14);
            let arm_at = clock.now_us();
            let ind = if peer_chsel { CONN_IND_CSEL_OFFSET } else { 0 };
            match radio.initiate_tx(clock, &conn_buf.0 .0[ind..ind + init.ind_len]) {
                Ok(done) => {
                    inc(15);
                    connect_done = Some(done);
                    put(48, done.wrapping_sub(end));
                }
                Err(_) => inc(17),
            }
            let arm = arm_at.wrapping_sub(end);
            put(47, clock.now_us().wrapping_sub(end));
            put(50, arm);
            if arm < get(49) {
                put(49, arm);
            }
        }
    }
    stop(radio, clock);
    inc(8);
    Some(Received {
        len,
        end,
        crc_ok: true,
        target_matched,
        peer_chsel,
        connect_done,
    })
}

/// Listen for the peer's response immediately after our event packet.
#[link_section = ".highcode"]
#[inline(never)]
fn receive_response(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    until: u32,
    expires: u32,
    capture_us: u32,
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
        stop(radio, clock);
        return None;
    }
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
            Some(at) => now.wrapping_sub(at) >= capture_us,
            None => reached(now, until),
        };
        if expired {
            stop(radio, clock);
            return None;
        }
    };
    stop(radio, clock);
    if !crc_ok {
        return Some(Received {
            len: 0,
            end,
            crc_ok: false,
            target_matched: false,
            peer_chsel: false,
            connect_done: None,
        });
    }
    let len = usize::from(rx.0[1]) + 2;
    if len > MAX_ENCRYPTED + 2 {
        return Some(Received {
            len: 0,
            end,
            crc_ok: false,
            target_matched: false,
            peer_chsel: false,
            connect_done: None,
        });
    }
    Some(Received {
        len,
        end,
        crc_ok: true,
        target_matched: false,
        peer_chsel: false,
        connect_done: None,
    })
}

struct Initiator {
    request: wchble::hci::runner::CreateConnRequest,
    params: ConnectParams,
    ind_len: usize,
    deadline_us: u32,
}

/// Build CONNECT_IND once, when the Host's create-connection command is
/// processed. The target AdvA is already known from the HCI request, so the
/// hot path only has to transmit the prepared DMA bytes.
fn prepare_initiator(
    soft: &mut SoftRunner,
    conn_buf: &mut ConnIndBuf,
    request: wchble::hci::runner::CreateConnRequest,
) -> Option<Initiator> {
    let mut params = ConnectParams {
        peer_addr: request.peer_addr,
        peer_random: request.peer_random,
        chsel: false,
        access_addr: CONNECT_AA,
        crc_init: CONNECT_CRC_INIT,
        win_size: WIN_SIZE,
        win_offset: WIN_OFFSET,
        interval: request.interval_min,
        latency: request.latency,
        timeout: request.timeout,
        channel_map: CONNECT_CHM,
        hop: CONNECT_HOP,
        sca: CONNECT_SCA,
    };
    let (own_addr, own_random) = soft.own_addr();
    let Some(ind_len) = params.build_connect_ind(&mut conn_buf.0 .0, own_addr, own_random) else {
        inc(17);
        let _ = soft.bridge.connection_failed(0x12);
        soft.clear_pending_connect();
        return None;
    };
    // Second variant with ChSel=1; picked in the receive window based on the
    // target advertisement's own ChSel bit.
    params.chsel = true;
    if params.build_connect_ind(
        &mut conn_buf.0 .0[CONN_IND_CSEL_OFFSET..],
        own_addr,
        own_random,
    ) != Some(ind_len)
    {
        inc(17);
        let _ = soft.bridge.connection_failed(0x12);
        soft.clear_pending_connect();
        return None;
    }
    params.chsel = false;
    unsafe {
        let debug = core::ptr::addr_of_mut!(IND_DEBUG).cast::<u32>();
        debug.add(0).write_volatile(u32::from(params.channel_map[0]));
        debug.add(1).write_volatile(u32::from(params.hop));
        debug.add(2).write_volatile(u32::from(params.sca));
        debug.add(3).write_volatile(ind_len as u32);
    }
    Some(Initiator {
        request,
        params,
        ind_len,
        deadline_us: 0,
    })
}

/// Host ACL packet being split across LL PDUs. The Host may hand over up to
/// 251 octets even before DLE; each LL PDU takes the negotiated on-air size
/// and only the final fragment owns the HCI tag.
struct PendingHost {
    acl: TxAcl,
    offset: usize,
}

struct Session {
    conn: CentralConnection,
    link: LinkSequence,
    control: ControlState,
    pending_control: Option<DataPdu>,
    pending_host: Option<PendingHost>,
    acl_tag: Option<TxTag>,
    terminating: Option<u8>,
    terminate_requested: Option<u8>,
    began: u32,
    complete_sent: bool,
}

impl Session {
    fn new(params: ConnectParams, connect_end_us: u32, now: u32) -> Self {
        let conn = CentralConnection::new(params, connect_end_us)
            .with_first_event_bias_us(u32::from(WIN_SIZE) * 625);
        Self {
            conn,
            link: LinkSequence::new(),
            control: {
                let mut control = ControlState::new();
                control.local_features = LOCAL_FEATURES;
                control
            },
            pending_control: None,
            pending_host: None,
            acl_tag: None,
            terminating: None,
            terminate_requested: None,
            began: now,
            complete_sent: false,
        }
    }

    fn expiration(&self, now: u32) -> Option<u8> {
        if self.control.termination_expired(now) {
            return Some(0x08);
        }
        if self.conn.supervision_expired(now) {
            inc(31);
            return Some(if self.conn.established() { 0x08 } else { 0x3e });
        }
        None
    }

    fn request_terminate(&mut self, reason: u8, now: u32) {
        self.terminate_requested.get_or_insert(reason);
        self.control
            .start_termination(now, self.conn.params.timeout);
    }

    /// Copy the negotiated DLE limits into the link and the receive window.
    fn apply_data_length(&mut self) {
        let tx = self.control.data_length.tx_octets();
        let rx = self.control.data_length.rx_octets();
        self.link.set_max_payloads(tx, rx);
        self.conn.set_rx_max_payload(rx);
    }

    /// True while no control exchange or queued Host data owns the link.
    fn link_idle(&self) -> bool {
        self.pending_control.is_none()
            && self.pending_host.is_none()
            && self.terminate_requested.is_none()
            && self.terminating.is_none()
            && !self.link.has_outstanding()
    }
}

/// Queue the next LL fragment of the Host ACL packet, taking a new one from
/// the bridge when needed. Only the fragment that ends the Host packet owns
/// the HCI tag, so the bridge credit is returned once, after the LL
/// acknowledges the final fragment. Returns false when nothing was queued.
fn queue_next_host_fragment(bridge: &mut ConnectionBridge, s: &mut Session) -> bool {
    if s.pending_host.is_none() {
        let Some(acl) = bridge.take_tx_acl() else {
            return false;
        };
        if acl.len == 0 {
            let _ = bridge.ack_tx(acl.tag);
            return false;
        }
        s.pending_host = Some(PendingHost { acl, offset: 0 });
    }
    let max_fragment = usize::from(s.link.tx_max_payload());
    let done = {
        let host = s.pending_host.as_mut().unwrap();
        let remaining = host.acl.len - host.offset;
        let n = remaining.min(max_fragment);
        let llid = if host.offset == 0 { host.acl.llid } else { 1 };
        let start = host.offset;
        let end = start + n;
        s.link.queue(llid, &host.acl.bytes[start..end]).unwrap();
        host.offset = end;
        (end == host.acl.len).then_some(host.acl.tag)
    };
    if let Some(tag) = done {
        s.pending_host = None;
        s.acl_tag = Some(tag);
    }
    inc(61);
    true
}

/// Ask for DLE once features are known and the link is otherwise idle.
/// Encryption is not driven in this example, so an idle link is enough.
fn service_dle(soft: &mut SoftRunner, s: &mut Session) -> Option<u8> {
    if !s.conn.established() || !s.link_idle() {
        return None;
    }
    if let Some((octets, time)) = soft.take_data_length_request() {
        s.control.data_length.set_local(octets, time);
        let pdu = s.control.length_request();
        s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
        return None;
    }
    if s.control.data_length.requested() {
        return None;
    }
    if let Some(pdu) = s.control.request_length_if_supported() {
        s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
    } else if let Some(pdu) = s.control.feature_request() {
        s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
    }
    None
}

#[link_section = ".highcode"]
#[inline(never)]
fn connection_event(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    s: &mut Session,
    bridge: &mut ConnectionBridge,
    finish: u32,
) -> Option<u8> {
    if let Some(reason) = s.expiration(clock.now_us()) {
        return Some(reason);
    }
    let event = s.conn.event_counter();
    let channel = s.conn.channel();
    inc(19);

    let entry_now = clock.now_us();
    let event_start = s.conn.event_start_us();
    let event_limit = event_start
        .wrapping_add(u32::from(s.conn.params.interval) * 1250)
        .wrapping_sub(600);
    trace(
        clock,
        0,
        event,
        channel,
        0,
        0,
        event_start,
        event_start.wrapping_sub(entry_now),
    );
    let mut expires = earlier(
        event_limit,
        earlier(finish, s.conn.supervision_deadline_us()),
    );
    if let Some(end) = s.control.termination_deadline_us() {
        expires = earlier(expires, end);
    }
    let deadline = event_start.wrapping_sub(EVENT_TX_LEAD_US);
    let now = clock.now_us();
    if reached(now, deadline) {
        // Too late to transmit this anchor; skip a whole interval rather than
        // transmitting into the next one.
        inc(28);
        s.conn.skip_to(now).ok()?;
        return s.expiration(now);
    }
    radio.set_channel(channel).unwrap();

    let retry = s.link.has_outstanding();
    if !retry {
        if let Some(pdu) = s.pending_control.take() {
            s.link.queue(3, pdu.payload()).unwrap();
        } else if let Some(reason) = s.terminate_requested.take() {
            s.link.queue(3, &[2, reason]).unwrap();
            s.terminating = Some(reason);
        } else if !queue_next_host_fragment(bridge, s) {
            s.link.queue(1, &[]).unwrap();
        }
    }
    let pdu = s.link.tx_pdu();
    let frame = pdu.as_bytes();
    tx.0[..frame.len()].copy_from_slice(frame);
    let margin = deadline.wrapping_sub(clock.now_us());
    if margin < get(49) {
        put(49, margin);
    }
    inc(20);
    let sent = radio.tx_basic(clock, &tx.0[..frame.len()], 0, Some(deadline));
    let tx_return = clock.now_us();
    trace(
        clock,
        1,
        event,
        channel,
        tx.0[0],
        tx.0[1],
        tx_return.wrapping_sub(deadline),
        frame.len() as u32,
    );
    match &sent {
        Ok(()) => {
            inc(27);
            if retry {
                inc(29);
            }
        }
        Err(wchble::Error::Late) => inc(28),
        Err(_) => inc(28),
    }
    if sent.is_err() {
        stop(radio, clock);
        s.conn.skip_to(clock.now_us()).ok()?;
        return s.expiration(clock.now_us());
    }

    // TX_DONE leaves the LLE command engaged; `rx_basic` force-stops it and
    // re-arms, exactly like the O2 scan-request path.
    let capture_us = s.conn.rx_complete_allowance_us() + 64;
    let rx_until = earlier(tx_return.wrapping_add(RESPONSE_WINDOW_US), event_limit);
    let rx_expires = earlier(rx_until.wrapping_add(capture_us), expires);
    put(50, clock.now_us().wrapping_sub(tx_return));
    let packet = receive_response(radio, clock, rx, rx_until, rx_expires, capture_us);
    let mut remote_terminate = None;
    let mut first = false;
    if let Some(packet) = packet {
        if packet.crc_ok && packet.len >= 2 {
            // Every usable RX PDU is classified into exactly one of the empty /
            // ACL / control / rejected counters below.
            inc(23);
            let header = rx.0[0];
            let payload = &rx.0[2..packet.len];
            if payload.len() > usize::from(s.link.rx_max_payload()) {
                inc(63);
            } else {
                let llid = header & 3;
                let capacity = match llid {
                    1 if payload.is_empty() => true,
                    1 | 2 => bridge.can_receive_acl(llid, payload.len()),
                    3 => s.pending_control.is_none() && s.terminate_requested.is_none(),
                    _ => false,
                };
                let outcome = s.link.on_rx(header, payload, true, capacity);
                if outcome.status != RxStatus::Invalid {
                    let tx_acked = outcome.tx_acked;
                    let acknowledged_acl = tx_acked.then(|| s.acl_tag.take()).flatten();
                    if tx_acked {
                        if let Some(reason) = s.terminating {
                            // The peer's only packet in this event acknowledges
                            // our LL_TERMINATE_IND. Count it in the RX
                            // classification before returning.
                            match (header & 3, payload.is_empty()) {
                                (1, true) => inc(24),
                                (1, false) | (2, _) => inc(25),
                                (3, _) => inc(26),
                                _ => inc(63),
                            }
                            inc(32);
                            stop(radio, clock);
                            return Some(reason);
                        }
                    }
                    first = !s.conn.established();
                    if !s.conn.on_rx(packet.end, payload.len() as u8, true) {
                        return s.expiration(packet.end).or(Some(0x08));
                    }
                    if first {
                        inc(21);
                        put(44, event_start);
                        put(45, packet.end);
                        put(46, packet.end.wrapping_sub(event_start));
                    }
                    inc(22);
                    match outcome.status {
                        RxStatus::Accepted => match llid {
                            1 if payload.is_empty() => inc(24),
                            2 => {
                                inc(25);
                                // ATT-level evidence: first 8 ACL payload bytes.
                                let mut first = [0u8; 8];
                                for (slot, byte) in first.iter_mut().zip(payload.iter()) {
                                    *slot = *byte;
                                }
                                trace(
                                    clock,
                                    4,
                                    event,
                                    channel,
                                    payload.first().copied().unwrap_or(0),
                                    payload.len() as u8,
                                    u32::from_le_bytes(first[0..4].try_into().unwrap()),
                                    u32::from_le_bytes(first[4..8].try_into().unwrap()),
                                );
                                if bridge.receive_acl(llid, payload).is_err() {
                                    inc(59);
                                    return Some(0x1f);
                                }
                                inc(60);
                            }
                            3 => {
                                inc(26);
                                trace(
                                    clock,
                                    3,
                                    event,
                                    channel,
                                    header,
                                    payload.len() as u8,
                                    u32::from(payload.first().copied().unwrap_or(0)),
                                    0,
                                );
                                let local = LocalVersion {
                                    version: 0x0d,
                                    company_id: 0xffff,
                                    subversion: 1,
                                };
                                match s.control.on_pdu(&mut s.conn, payload, local) {
                                    Ok(ControlAction::Reply(reply)) => {
                                        s.apply_data_length();
                                        s.pending_control =
                                            Some(DataPdu::new(3, reply.as_bytes()).unwrap());
                                    }
                                    Ok(ControlAction::Terminate(reason)) => {
                                        s.apply_data_length();
                                        remote_terminate = Some(reason)
                                    }
                                    Ok(ControlAction::None) => s.apply_data_length(),
                                    Err(error) => s.request_terminate(
                                        wchble::ll::ctrl::termination_reason(error),
                                        packet.end,
                                    ),
                                }
                            }
                            _ => inc(63),
                        },
                        RxStatus::Duplicate => inc(63),
                        RxStatus::Backpressure => {
                            inc(59);
                            inc(63);
                        }
                        RxStatus::Invalid => inc(63),
                    }
                    if first && !s.complete_sent {
                        let p = s.conn.params;
                        let info = ConnectionInfo {
                            handle: 1,
                            role: wchble::ll::Role::Central,
                            peer_address_type: u8::from(p.peer_random),
                            peer_address: p.peer_addr,
                            interval: p.interval,
                            latency: p.latency,
                            supervision_timeout: p.timeout,
                            master_clock_accuracy: p.sca,
                        };
                        if bridge.connected(info).is_err() {
                            inc(59);
                            return Some(0x1f);
                        }
                        s.complete_sent = true;
                        inc(34);
                        put(2, STAGE_CONNECTED);
                    }
                    if let Some(tag) = acknowledged_acl {
                        if !bridge.ack_tx(tag) {
                            inc(59);
                            return Some(0x1f);
                        }
                    }
                    if let Some(reason) = remote_terminate {
                        // Acknowledge the peer's terminate with an empty PDU in
                        // the same event before leaving.
                        s.link.queue(1, &[]).unwrap();
                        let ack = s.link.tx_pdu();
                        let frame = ack.as_bytes();
                        tx.0[..frame.len()].copy_from_slice(frame);
                        if radio
                            .tx_basic(
                                clock,
                                &tx.0[..frame.len()],
                                0,
                                Some(clock.now_us().wrapping_add(120)),
                            )
                            .is_ok()
                        {
                            inc(27);
                        }
                        stop(radio, clock);
                        inc(33);
                        return Some(reason);
                    }
                }
            }
        }
    } else {
        inc(30);
        trace(clock, 5, event, channel, 0, 0, event_start, event_limit);
    }

    if s.conn.next_event().is_err() {
        return Some(0x28);
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
    // Mirror the Host's GATT view into the firmware STATS contract.
    let cycles = stats.word(host::STAT_CYCLES);
    let reads = stats.word(host::STAT_READS);
    let writes = stats.word(host::STAT_WRITES);
    put(37, cycles);
    put(38, cycles);
    put(39, reads);
    put(40, stats.word(host::STAT_GATT_ERRORS));
    put(41, writes);
    put(42, stats.word(host::STAT_GATT_ERRORS));
    put(43, reads.wrapping_add(writes));
}

fn idle<F: Future>(
    soft: &mut SoftRunner,
    mut future: Pin<&mut F>,
    stats: &host::HostStats,
    clock: &Clock,
    until: u32,
) {
    for _ in 0..4 {
        let before = clock.now_us();
        // Leave 500 us for the shortest RF wait; the scan loop only exposes
        // ~1.5 ms gaps, so the old 2 ms guard starved the Host entirely.
        if reached(before.wrapping_add(500), until) {
            break;
        }
        soft.pump_once();
        EMBASSY_NOW_US.store(u64::from(clock.now_us()), Ordering::Relaxed);
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            inc(59);
        }
        if reached(clock.now_us(), until) {
            break;
        }
    }
    host_snapshot(stats);
}

/// Open the central session after the hardware-timed CONNECT_IND completed.
///
/// The packet itself was armed and transmitted by `receive_scan` while the LLE
/// was still inside its advertising RX window, following the vendor initiator
/// (`LL_InitiateSetRF` + `ll_initiate_tx`). Nothing here re-transmits it; this
/// function only retunes the radio to the new connection and records data.
#[link_section = ".highcode"]
#[inline(never)]
fn start_connection(
    radio: &mut Ch585Radio,
    clock: &Clock,
    soft: &mut SoftRunner,
    initiator: &Initiator,
    peer_chsel: bool,
    adv_end_us: u32,
    connect_done_us: u32,
) -> Session {
    trace(
        clock,
        7,
        0,
        radio.channel(),
        0,
        initiator.ind_len as u8,
        adv_end_us,
        connect_done_us,
    );
    stop(radio, clock);
    soft.clear_pending_connect();
    let mut params = initiator.params;
    params.chsel = peer_chsel;
    radio.set_aa_crc(params.access_addr, params.crc_init);
    put(51, u32::from(params.interval));
    put(
        52,
        u32::from(params.hop) | (u32::from(params.sca) << 8),
    );
    put(53, params.access_addr);
    put(54, params.crc_init);
    put(
        55,
        u32::from(params.win_size) | (u32::from(params.win_offset) << 8),
    );
    Session::new(params, connect_done_us, clock.now_us())
}

/// Bring-up evidence for the 36-byte TX path: alternate a short advertising
/// PDU with the prepared CONNECT_IND on all three advertising channels. A
/// sniffer that hears the short PDU but not the long one proves a size-dependent
/// transmit problem; hearing both moves the fault back to scheduling.
#[cfg(feature = "tx-probe")]
#[no_mangle]
#[used]
pub static mut PROBE_STATS: [u32; 8] = [0; 8];

/// Copy of the CONNECT_IND buffer taken right after the first TX completes:
/// tells us whether the LLE rewrites the caller's bytes in place.
#[cfg(feature = "tx-probe")]
#[no_mangle]
#[used]
pub static mut PROBE_AFTER: [u8; 36] = [0; 36];

#[cfg(feature = "tx-probe")]
#[repr(align(32))]
struct ProbeFrame(DmaBuf<64>);

#[cfg(feature = "tx-probe")]
static PROBE_FRAME: StaticCell<ProbeFrame> = StaticCell::new();

#[cfg(feature = "tx-probe")]
fn tx_probe(radio: &mut Ch585Radio, clock: &Clock) {
    // 21 bytes on air: ADV_IND, AdvA, flags, complete name "wch585-p".
    let mut small = [0u8; 21];
    small[0] = 0xc0; // TxAdd + RxAdd bits set: does the LLE pass bit 7 through?
    small[1] = 19;
    small[2..8].copy_from_slice(&[0x02, 0x00, 0x00, 0xee, 0xff, 0xc1]);
    small[8..11].copy_from_slice(&[0x02, 0x01, 0x06]);
    small[11] = 9;
    small[12] = 0x09;
    small[13..21].copy_from_slice(b"wch585-p");

    // 39 bytes on air: ADV_IND with a 26-character name in the last bytes, so
    // a CoreBluetooth scan proves whether the tail survives the LLE.
    const LONG_NAME: &[u8] = b"wch585-tail-check-ABCDEFGH";
    let mut long = [0u8; 39];
    long[0] = 0x40; // TxAdd: random
    long[1] = 37;
    long[2..8].copy_from_slice(&[0x03, 0x00, 0x00, 0xee, 0xff, 0xc1]);
    long[8..11].copy_from_slice(&[0x02, 0x01, 0x06]);
    long[11] = LONG_NAME.len() as u8 + 1;
    long[12] = 0x09;
    long[13..13 + LONG_NAME.len()].copy_from_slice(LONG_NAME);

    // The same 36-byte CONNECT_IND the real initiator path uses.
    let params = ConnectParams {
        peer_addr: [0x34, 0x12, 0x00, 0xee, 0xff, 0xc2],
        peer_random: true,
        chsel: false,
        access_addr: 0x1a2b_3c4d,
        crc_init: 0x0065_4321,
        win_size: 3,
        win_offset: 2,
        interval: 30,
        latency: 1,
        timeout: 0x0123,
        channel_map: [0xff, 0xff, 0x00, 0x00, 0x00],
        hop: 5,
        sca: 0,
    };
    let big = PROBE_FRAME.init(ProbeFrame(DmaBuf::zeroed()));
    let Some(big_len) =
        params.build_connect_ind(&mut big.0 .0, [0xc2, 0xff, 0xee, 0, 0, 0x22], true)
    else {
        return;
    };
    // Pre-compensation test: the LLE transmits the tail as
    // [buf34, buf30, 0, 0, 0, swap(buf35)], so place the wire map's two
    // usable bytes and the wire hop/SCA byte where the LLE will pick them up.
    big.0 .0[30] = 0xff; // wire map byte 1
    big.0 .0[34] = 0xff; // wire map byte 0
    big.0 .0[35] = 0xa0; // wire(hop 5, SCA 0); hardware swaps fields
    for i in 0..1350u32 {
        let channel = [37u8, 38, 39][(i % 3) as usize];
        let _ = radio.set_channel(channel);
        radio.set_aa_crc(0x8e89_bed6, 0x00_55_5555);
        let (frame, kind): (&[u8], usize) = match i % 3 {
            0 => (&small[..], 0),
            1 => (&long[..], 1),
            _ => (&big.0 .0[..big_len], 2),
        };
        let result = radio.tx_basic(clock, frame, 0, None);
        unsafe {
            let stats = core::ptr::addr_of_mut!(PROBE_STATS).cast::<u32>();
            let slot = stats.add(kind);
            slot.write_volatile(slot.read_volatile() + 1);
            let outcome = stats.add(if result.is_ok() { 3 } else { 4 });
            outcome.write_volatile(outcome.read_volatile() + 1);
            if kind == 2 && result.is_ok() {
                let dst = core::ptr::addr_of_mut!(PROBE_AFTER).cast::<u8>();
                if dst.read_volatile() == 0 {
                    core::ptr::copy_nonoverlapping(big.0 .0.as_ptr(), dst, 36);
                }
            }
        }
        let until = clock.now_us().wrapping_add(10_000);
        while !reached(clock.now_us(), until) {}
    }
}

#[entry]
#[link_section = ".highcode"]
fn main() -> ! {
    let _p = hal::init(rcc::Config::hse_nearest(Hertz(60_000_000)).into());
    let hz = hal::rcc::clocks().sysclk.0;
    let clock = Clock {
        ticks: Cell::new(ExtendingTicks::new(
            hal::pac::SYSTICK.cntl().read().cntl(),
        )),
        rate: TickRate::new(hz).unwrap(),
    };
    core::hint::black_box(&TARGET_NAME);
    core::hint::black_box(&AA);
    core::hint::black_box(&CRC_INIT);
    core::hint::black_box(&WIN_SPEC);
    core::hint::black_box(&CONNECT_OFFSET);
    core::hint::black_box(&BOGUS_PEER);
    core::hint::black_box(&SERVICE_UUID);
    put(0, 0x4331_3538);
    put(1, 1);
    put(2, STAGE_INIT);
    put(4, hz);
    put(49, u32::MAX);
    put(51, 24); // slots, fixed 30 ms request
    put(52, u32::from(CONNECT_HOP) | (u32::from(CONNECT_SCA) << 8));
    put(53, CONNECT_AA);
    put(54, CONNECT_CRC_INIT);
    put(55, u32::from(WIN_SIZE) | (u32::from(WIN_OFFSET) << 8));

    let scratch = SCRATCH.init(DmaBuf::zeroed());
    let rx = RX.init(DmaBuf::zeroed());
    let conn_buf = CONN_IND.init(ConnIndBuf(DmaBuf::zeroed()));
    let data = DATA.init(DmaBuf::zeroed());
    let mut radio = new_radio_with_dma(&mut scratch.0).unwrap();
    if radio.init(&clock).is_err() {
        put(2, 0xe1);
        park();
    }
    radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
    stop(&mut radio, &clock);
    #[cfg(feature = "tx-probe")]
    tx_probe(&mut radio, &clock);
    let controller = wchble::hci::new();
    let mut soft = SoftRunner::new();
    soft.set_le_features(LOCAL_FEATURES);
    let app_stats = host::HostStats::new();
    let mut app = core::pin::pin!(host::run(controller, &app_stats));
    let started = clock.now_us();
    let budget = *core::hint::black_box(&RUN_SECONDS) * 1_000_000;
    let finish = started.wrapping_add(budget);
    let mut session: Option<Session> = None;
    let mut initiator: Option<Initiator> = None;
    let mut next_channel_index = 0usize;
    let mut session_failed = false;
    put(2, STAGE_SCANNING);
    while !reached(clock.now_us(), finish) {
        if let Some(request) = soft.bridge.take_radio_request() {
            match request {
                RadioRequest::Reset => {
                    stop(&mut radio, &clock);
                    session = None;
                    initiator = None;
                    soft.clear_pending_connect();
                    soft.bridge.reset_finished();
                    put(2, STAGE_SCANNING);
                }
                RadioRequest::Disconnect { reason } => {
                    if let Some(s) = session.as_mut() {
                        s.request_terminate(reason, clock.now_us());
                    }
                }
            }
        }
        if let Some(s) = session.as_mut() {
            if s.complete_sent {
                put(2, if s.conn.established() { STAGE_GATT } else { STAGE_CONNECTED });
            } else {
                put(2, STAGE_CONNECTING);
            }
            let mut reason = s.expiration(clock.now_us());
            if reason.is_none() && radio.channel() != s.conn.channel() {
                radio.set_channel(s.conn.channel()).unwrap();
            }
            let prepare = s
                .conn
                .event_start_us()
                .wrapping_sub(EVENT_TX_LEAD_US + 100);
            if reason.is_none()
                && !reached(clock.now_us().wrapping_add(2000), prepare)
            {
                let mut until = earlier(prepare, earlier(finish, s.conn.supervision_deadline_us()));
                if let Some(end) = s.control.termination_deadline_us() {
                    until = earlier(until, end);
                }
                idle(&mut soft, app.as_mut(), &app_stats, &clock, until);
                continue;
            }
            if reason.is_none() {
                let _ = service_dle(&mut soft, s);
                reason = connection_event(
                    &mut radio,
                    &clock,
                    rx,
                    data,
                    s,
                    &mut soft.bridge,
                    finish,
                );
            }
            if let Some(reason) = reason {
                stop(&mut radio, &clock);
                trace(
                    &clock,
                    6,
                    s.conn.event_counter(),
                    s.conn.channel(),
                    0,
                    0,
                    u32::from(reason),
                    clock.now_us().wrapping_sub(s.began),
                );
                if soft.bridge.is_connected() {
                    soft.bridge.disconnected(reason);
                    inc(35);
                } else {
                    // The first connection event never completed.
                    let _ = soft.bridge.connection_failed(0x3e);
                    inc(18);
                }
                session = None;
                session_failed = true;
                put(2, STAGE_SCANNING);
            }
            continue;
        }

        // Initiator bookkeeping before touching the scanner again.
        if let Some(request) = soft.pending_connect() {
            if initiator.is_none() {
                if let Some(mut prepared) = prepare_initiator(&mut soft, conn_buf, request) {
                    prepared.deadline_us =
                        clock.now_us().wrapping_add(INITIATOR_TIMEOUT_US);
                    initiator = Some(prepared);
                    inc(13);
                    put(2, STAGE_CONNECTING);
                }
            }
        } else {
            initiator = None;
        }
        if let Some(init) = initiator.as_ref() {
            if reached(clock.now_us(), init.deadline_us) {
                let _ = soft.bridge.connection_failed(0x3e);
                inc(18);
                soft.clear_pending_connect();
                initiator = None;
                put(2, STAGE_SCANNING);
            }
        }

        let scan_enabled = soft.scan_state().enabled || initiator.is_some();
        if !scan_enabled {
            let until = clock.now_us().wrapping_add(2000);
            idle(
                &mut soft,
                app.as_mut(),
                &app_stats,
                &clock,
                earlier(finish, until),
            );
            continue;
        }

        // One 15 ms window per channel, 37 -> 38 -> 39.
        let channel = [37u8, 38, 39][next_channel_index % 3];
        next_channel_index = next_channel_index.wrapping_add(1);
        radio.set_channel(channel).unwrap();
        radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
        let now = clock.now_us();
        let until = now.wrapping_add(SCAN_WINDOW_US);
        let expires = earlier(finish, until.wrapping_add(SCAN_RX_COMPLETE_US));
        if let Some(packet) = receive_scan(
            &mut radio,
            &clock,
            rx,
            until,
            expires,
            initiator.as_ref(),
            conn_buf,
        ) {
            if packet.crc_ok && packet.len >= 8 {
                if soft.scan_state().enabled {
                    if let Some(pdu) = scan::Pdu::parse(&rx.0[..packet.len], true) {
                        if soft.push_adv_report(&pdu, 0) {
                            inc(10);
                        } else {
                            inc(11);
                        }
                    }
                }
                if packet.target_matched {
                    inc(12);
                    put(62, get(62) | (1 << (channel - 37)));
                }
                if let (Some(init), Some(connect_done)) =
                    (initiator.as_ref(), packet.connect_done)
                {
                    let new_session = start_connection(
                        &mut radio,
                        &clock,
                        &mut soft,
                        init,
                        packet.peer_chsel,
                        packet.end,
                        connect_done,
                    );
                    let first_anchor = new_session.conn.event_start_us();
                    put(44, first_anchor);
                    initiator = None;
                    session = Some(new_session);
                    put(2, STAGE_CONNECTING);
                    trace(
                        &clock,
                        2,
                        0,
                        channel,
                        0,
                        36,
                        packet.end,
                        first_anchor,
                    );
                    continue;
                }
            }
        }
        let until = clock.now_us().wrapping_add(1500);
        idle(
            &mut soft,
            app.as_mut(),
            &app_stats,
            &clock,
            earlier(finish, until),
        );
    }
    stop(&mut radio, &clock);
    if soft.bridge.is_connected() {
        soft.bridge.disconnected(0x08);
    }
    host_snapshot(&app_stats);
    put(3, clock.now_us().wrapping_sub(started));
    put(56, reg(LLE_BASE, lle::CMD));
    put(57, reg(LLE_BASE, lle::MODE));
    put(2, STAGE_DONE);
    let _ = session_failed;
    park();
}
