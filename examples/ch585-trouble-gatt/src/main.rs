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
use wchble::hci::connection::{ConnectionInfo, RadioRequest, TxTag};
use wchble::hci::runner::LtkReply;
use wchble::hci::SoftRunner;
use wchble::ll::acl::{DataPdu, LinkSequence, RxStatus};
use wchble::ll::conn::{ConnectParams, PeripheralConnection};
use wchble::ll::ctrl::{ControlAction, ControlState, LocalVersion};
use wchble::ll::enc::{
    EncError, EncRole, Encryption, PeripheralStart, StartStage, MAX_ENCRYPTED, MAX_PLAINTEXT,
};
use wchble::rf::family::ch585::{Ch585Aes, Ch585Radio, BB_BASE, LLE_BASE};
use wchble::rf::regs::{self, bb, bb_irq, lle};
use wchble::rf::txrx::{DmaBuf, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use {panic_halt as _, portable_atomic as _};

mod host;
#[cfg(feature = "secure")]
mod rng;
#[cfg(feature = "secure")]
mod time_driver;

#[cfg(feature = "secure")]
use embassy_crypto_rustcrypto as _;

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
/// S2 encryption evidence, kept separate so the P4 STATS invariants and the
/// existing runner remain untouched.
#[no_mangle]
static mut SECURE_STATS: [u32; 16] = [0; 16];

const SEC_MAGIC: u32 = 0x5332_3538;
const SEC_ENC_REQ: usize = 2;
const SEC_ENC_RSP: usize = 3;
const SEC_LTK_REQUEST: usize = 4;
const SEC_LTK_REPLY: usize = 5;
const SEC_START_REQ: usize = 6;
const SEC_START_RSP: usize = 7;
const SEC_ENCRYPTED_TX: usize = 8;
const SEC_ENCRYPTED_RX: usize = 9;
const SEC_ACTIVE: usize = 10;
const SEC_MIC_FAILURE: usize = 11;
const SEC_ERRORS: usize = 12;
const SEC_PREPARED: usize = 13;
const SEC_PLAINTEXT_START_RETRY: usize = 14;
const SEC_LAST_ERROR: usize = 15;

#[cfg(feature = "secure")]
const LOCAL_FEATURES: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
#[cfg(not(feature = "secure"))]
const LOCAL_FEATURES: [u8; 8] = [0; 8];

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
fn sec_put(i: usize, v: u32) {
    unsafe {
        core::ptr::addr_of_mut!(SECURE_STATS)
            .cast::<u32>()
            .add(i)
            .write_volatile(v)
    }
}
fn sec_inc(i: usize) {
    let current = unsafe {
        core::ptr::addr_of!(SECURE_STATS)
            .cast::<u32>()
            .add(i)
            .read_volatile()
    };
    sec_put(i, current.wrapping_add(1));
}
fn sec_error(reason: u8) {
    sec_inc(SEC_ERRORS);
    sec_put(SEC_LAST_ERROR, u32::from(reason));
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

/// An encrypted PDU prepared before the connection event. The radio event
/// only copies it into the link layer; AES never runs inside the IFS window.
struct EncTx {
    llid: u8,
    bytes: [u8; MAX_ENCRYPTED],
    len: u8,
    tag: Option<TxTag>,
    /// When set, a successful acknowledgment ends the link with this reason.
    terminate: Option<u8>,
}

/// A received encrypted PDU held until after the event, when AES-CCM can run
/// outside the 150 us response deadline.
struct DeferredRx {
    header: u8,
    payload: [u8; MAX_ENCRYPTED],
    len: u8,
    end: u32,
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
    /// Start-encryption sequencing (peripheral role).
    start: PeripheralStart,
    /// Session cipher, present once the Host supplied the LTK.
    enc: Option<Encryption<Ch585Aes>>,
    /// Both directions encrypted; new TX PDUs must be pre-encrypted.
    enc_active: bool,
    /// Our encrypted LL_START_ENC_RSP was sent; incoming non-empty PDUs are
    /// ciphertext and must be deferred.
    rx_encrypted: bool,
    /// A plaintext LL_START_ENC_REQ was observed (possibly retransmitted).
    start_req_seen: bool,
    pending_enc_control: Option<EncTx>,
    pending_enc_acl: Option<EncTx>,
    deferred_rx: Option<DeferredRx>,
}
impl Session {
    fn new(params: ConnectParams, end: u32, now: u32) -> Self {
        let mut control = ControlState::new();
        control.local_features = LOCAL_FEATURES;
        Self {
            conn: PeripheralConnection::new(params, end),
            link: LinkSequence::new(),
            control,
            pending_control: None,
            acl_tag: None,
            terminating: None,
            terminate_requested: None,
            update_instant: None,
            update_report: None,
            began: now,
            start: PeripheralStart::new(),
            enc: None,
            enc_active: false,
            rx_encrypted: false,
            start_req_seen: false,
            pending_enc_control: None,
            pending_enc_acl: None,
            deferred_rx: None,
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
    soft: &mut SoftRunner,
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
        // After our encrypted START_ENC_RSP, every non-empty PDU is ciphertext
        // except a retransmitted plaintext START_ENC_REQ (the peer may not
        // have seen our response yet). Empty PDUs are never encrypted.
        let plaintext_start_retry = s.rx_encrypted && llid == 3 && payload == [0x05];
        if plaintext_start_retry {
            sec_inc(SEC_PLAINTEXT_START_RETRY);
        }
        let ciphertext =
            s.rx_encrypted && !plaintext_start_retry && !(llid == 1 && payload.is_empty());
        let capacity = if ciphertext {
            s.deferred_rx.is_none()
                && match llid {
                    1 | 2 => soft.bridge.can_receive_acl(llid, payload.len()),
                    3 => true,
                    _ => false,
                }
        } else {
            match llid {
                1 if payload.is_empty() => true,
                1 | 2 => soft.bridge.can_receive_acl(llid, payload.len()),
                3 => {
                    s.pending_control.is_none()
                        && s.terminate_requested.is_none()
                        && s.update_report.is_none()
                }
                _ => false,
            }
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
                if ciphertext {
                    // AES-CCM cannot fit in the 150 us response window; hold
                    // the PDU and decrypt it after the event.
                    let mut copy = [0u8; MAX_ENCRYPTED];
                    copy[..payload.len()].copy_from_slice(payload);
                    s.deferred_rx = Some(DeferredRx {
                        header,
                        payload: copy,
                        len: payload.len() as u8,
                        end: packet.end,
                    });
                } else if plaintext_start_retry {
                    s.start_req_seen = true;
                } else if llid == 3 {
                    inc(26);
                    put(38, u32::from(payload[0]));
                    match payload[0] {
                        0x03 if s.start.stage() == StartStage::Idle => {
                            let mut random = [0u8; 12];
                            soft.fill_random(&mut random);
                            let mut skds = [0u8; 8];
                            skds.copy_from_slice(&random[..8]);
                            let mut ivs = [0u8; 4];
                            ivs.copy_from_slice(&random[8..]);
                            match s.start.on_enc_req(payload, skds, ivs) {
                                Ok(rsp) => {
                                    s.pending_control =
                                        Some(DataPdu::new(3, rsp.as_bytes()).unwrap());
                                    sec_inc(SEC_ENC_REQ);
                                    sec_inc(SEC_ENC_RSP);
                                    let req = wchble::ll::ctrl::EncReq::parse(payload).unwrap();
                                    if soft.push_ltk_request(req.rand, req.ediv) {
                                        sec_inc(SEC_LTK_REQUEST);
                                    } else {
                                        sec_error(0x1e);
                                        s.request_terminate(0x1e, packet.end);
                                    }
                                }
                                Err(_) => {
                                    sec_error(0x1e);
                                    s.request_terminate(0x1e, packet.end);
                                }
                            }
                        }
                        0x05 => {
                            if !s.start_req_seen {
                                s.start_req_seen = true;
                                sec_inc(SEC_START_REQ);
                            }
                        }
                        _ => {
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
                                    s.pending_control =
                                        Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                                }
                                Ok(ControlAction::Terminate(reason)) => {
                                    remote_terminate = Some(reason)
                                }
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
                        }
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
            if s.enc_active {
                // Every new PDU was encrypted before the event; the IFS budget
                // only covers copying it into the link layer.
                if let Some(tx) = s
                    .pending_enc_control
                    .take()
                    .or_else(|| s.pending_enc_acl.take())
                {
                    s.link
                        .queue(tx.llid, &tx.bytes[..usize::from(tx.len)])
                        .unwrap();
                    s.acl_tag = tx.tag;
                    if tx.terminate.is_some() {
                        s.terminating = tx.terminate;
                    }
                    sec_inc(SEC_ENCRYPTED_TX);
                }
            } else if s.start_req_seen && s.start.stage() == StartStage::Prepared {
                let (start, enc) = (&mut s.start, &mut s.enc);
                match start.start_enc_req(enc.as_mut().unwrap()) {
                    Ok(bytes) => {
                        s.link.queue(3, bytes).unwrap();
                        s.rx_encrypted = true;
                        s.start_req_seen = false;
                        sec_inc(SEC_START_RSP);
                    }
                    Err(_) => {
                        sec_error(0x1e);
                        s.request_terminate(0x1e, packet.end);
                    }
                }
            } else if !s.rx_encrypted {
                // Between our START_ENC_RSP and the Central's response only
                // empty PDUs may be plaintext; defer controls and ACL data.
                if let Some(pdu) = s.pending_control.take() {
                    s.link.queue(3, pdu.payload()).unwrap();
                } else if let Some(reason) = s.terminate_requested.take() {
                    s.link.queue(3, &[2, reason]).unwrap();
                    s.terminating = Some(reason);
                } else if let Some(acl) = soft.bridge.take_tx_acl() {
                    s.link.queue(acl.llid, &acl.bytes[..acl.len]).unwrap();
                    s.acl_tag = Some(acl.tag);
                }
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
                role: wchble::ll::Role::Peripheral,
                peer_address_type: u8::from(p.peer_random),
                peer_address: p.peer_addr,
                interval: p.interval,
                latency: p.latency,
                supervision_timeout: p.timeout,
                master_clock_accuracy: p.sca,
            };
            if soft.bridge.connected(info).is_err() {
                inc(63);
                return Some(0x1f);
            }
        }
        if let Some(tag) = acknowledged_acl {
            if !soft.bridge.ack_tx(tag) {
                inc(63);
                return Some(0x1f);
            }
        }
        if deliver_acl && soft.bridge.receive_acl(llid, payload).is_err() {
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

/// Turn the Host's LTK answer into a session cipher and precompute the
/// encrypted START_ENC_RSP. Runs outside the radio event.
fn service_encryption(soft: &mut SoftRunner, s: &mut Session) -> Option<u8> {
    if s.enc.is_some() || s.start.stage() != StartStage::AwaitingKey {
        return None;
    }
    let reply = soft.take_ltk_reply()?;
    let ltk = match reply {
        LtkReply::Key(ltk) => ltk,
        LtkReply::Rejected => {
            sec_error(0x1e);
            return Some(0x1e);
        }
    };
    sec_inc(SEC_LTK_REPLY);
    let session = match s.start.session(&ltk) {
        Ok(session) => session,
        Err(_) => {
            sec_error(0x1e);
            return Some(0x1e);
        }
    };
    let engine = Ch585Aes::new(session.key());
    let mut enc = Encryption::new(session, EncRole::Peripheral, engine);
    if s.start.prepare_start_rsp(&mut enc).is_err() {
        sec_error(0x1e);
        return Some(0x1e);
    }
    s.enc = Some(enc);
    sec_inc(SEC_PREPARED);
    None
}

/// Produce at most one encrypted control PDU and one encrypted ACL fragment
/// before the next event. The event only queues the prepared ciphertext.
fn prefetch_encrypted(soft: &mut SoftRunner, s: &mut Session) -> Option<u8> {
    if !s.enc_active {
        return None;
    }
    let enc = s.enc.as_mut()?;
    if s.pending_enc_control.is_none() {
        let mut out = [0u8; MAX_ENCRYPTED];
        let prepared = if let Some(reason) = s.terminate_requested.take() {
            Some((enc.encrypt(3, &[2, reason], &mut out), Some(reason)))
        } else if let Some(pdu) = s.pending_control.take() {
            Some((enc.encrypt(3, pdu.payload(), &mut out), None))
        } else {
            None
        };
        if let Some((result, terminate)) = prepared {
            match result {
                Ok(len) => {
                    s.pending_enc_control = Some(EncTx {
                        llid: 3,
                        bytes: out,
                        len: len as u8,
                        tag: None,
                        terminate,
                    });
                }
                Err(_) => {
                    sec_error(0x1e);
                    return Some(0x1e);
                }
            }
        }
    }
    if s.pending_enc_control.is_none() && s.pending_enc_acl.is_none() {
        if let Some(acl) = soft.bridge.take_tx_acl() {
            let mut out = [0u8; MAX_ENCRYPTED];
            match enc.encrypt(acl.llid, &acl.bytes[..acl.len], &mut out) {
                Ok(len) => {
                    s.pending_enc_acl = Some(EncTx {
                        llid: acl.llid,
                        bytes: out,
                        len: len as u8,
                        tag: Some(acl.tag),
                        terminate: None,
                    });
                }
                Err(_) => {
                    sec_error(0x1e);
                    return Some(0x1e);
                }
            }
        }
    }
    None
}

/// Decrypt the PDU deferred by the last event and dispatch it. MIC failure
/// terminates the link with reason 0x3d, per Core 5.4 Vol 6 Part E.
fn finish_deferred(soft: &mut SoftRunner, s: &mut Session) -> Option<u8> {
    let rx = s.deferred_rx.take()?;
    let mut plain = [0u8; MAX_PLAINTEXT];
    let len = {
        let enc = s.enc.as_mut()?;
        match enc.decrypt(rx.header, &rx.payload[..usize::from(rx.len)], &mut plain) {
            Ok(len) => len,
            Err(EncError::MicFailure) => {
                sec_inc(SEC_MIC_FAILURE);
                sec_error(0x3d);
                return Some(0x3d);
            }
            Err(_) => {
                sec_error(0x1e);
                return Some(0x1e);
            }
        }
    };
    sec_inc(SEC_ENCRYPTED_RX);
    let llid = rx.header & 3;
    if !s.enc_active {
        // The first encrypted PDU must be the Central's START_ENC_RSP.
        if llid == 3 && len == 1 && plain[0] == 0x06 && s.start.on_start_enc_rsp().is_ok() {
            s.enc_active = true;
            sec_inc(SEC_ACTIVE);
            let _ = soft.encryption_change(1, 0, 1);
            return None;
        }
        sec_error(0x1e);
        return Some(0x1e);
    }
    match llid {
        3 => {
            put(38, u32::from(plain[0]));
            let local = LocalVersion {
                version: 0x0d,
                company_id: 0xffff,
                subversion: 1,
            };
            match s.control.on_pdu(&mut s.conn, &plain[..len], local) {
                Ok(ControlAction::Reply(pdu)) => {
                    if pdu.as_bytes().first() == Some(&7) {
                        inc(27);
                    }
                    s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                }
                Ok(ControlAction::Terminate(reason)) => s.request_terminate(reason, rx.end),
                Ok(ControlAction::None) => {
                    if plain[0] == 0 && len == 12 {
                        s.update_instant = Some(u16::from_le_bytes([plain[10], plain[11]]));
                    }
                }
                Err(error) => {
                    s.request_terminate(wchble::ll::ctrl::termination_reason(error), rx.end)
                }
            }
            None
        }
        1 | 2 => {
            if soft.bridge.receive_acl(llid, &plain[..len]).is_err() {
                inc(63);
                Some(0x1f)
            } else {
                None
            }
        }
        _ => None,
    }
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
        #[cfg(feature = "secure")]
        time_driver::advance(clock.now_us());
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
        ticks: Cell::new(ExtendingTicks::new(hal::pac::SYSTICK.cntl().read().cntl())),
        rate: TickRate::new(hz).unwrap(),
    };
    put(0, 0x5034_3538);
    put(1, 1);
    put(2, 1);
    put(35, hz);
    sec_put(0, SEC_MAGIC);
    sec_put(1, 1);
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
    // S2 must not pair from a deterministic stream. Collect ADC temperature
    // noise (the S0 source), refuse a stuck converter, then give the Host a
    // second DRBG stream drawn from the seeded controller DRBG.
    #[cfg(feature = "secure")]
    {
        use wchble::rand::EntropyPool;
        let mut pool = EntropyPool::new();
        let mut adc = hal::adc::Adc::new(_p.ADC, hal::adc::Config::default());
        let mut temperature = adc.enable_temperature();
        let mut values = [0u32; 32];
        let mut distinct = 0usize;
        let mut count = 0u32;
        let mut min = u32::MAX;
        let mut max = 0u32;
        for _ in 0..128 {
            if let Ok(value) = adc.blocking_read(&mut temperature) {
                let value = u32::from(value);
                pool.add_sample(value);
                pool.add_sample(hal::pac::SYSTICK.cntl().read().cntl());
                count += 1;
                min = min.min(value);
                max = max.max(value);
                if !values[..distinct].contains(&value) && distinct < values.len() {
                    values[distinct] = value;
                    distinct += 1;
                }
            }
        }
        let entropy_ok = count >= 64 && max.wrapping_sub(min) >= 2 && distinct >= 4;
        if !entropy_ok {
            put(2, 0xe2);
            park();
        }
        let seed = pool.seed();
        let _ = soft.set_entropy_seed(&seed);
        // Advance the controller stream, then seed the Host from fresh output.
        let mut host_seed = [0u8; 32];
        soft.fill_random(&mut host_seed);
        rng::seed(&host_seed);
        sec_put(
            1,
            1 | (1 << 8)
                | (u32::from(rng::seeded()) << 9)
                | (u32::from(soft.entropy_seeded()) << 10),
        );
    }
    soft.set_le_features(LOCAL_FEATURES);
    #[cfg(feature = "secure")]
    {
        // The Host fragments ACL data at this length, so every fragment fits
        // a 27-octet encrypted on-air payload (23 + 4-octet MIC).
        let _ = soft.set_acl_packet_length(23);
    }
    let app_stats = host::HostStats::new();
    let mut app = core::pin::pin!(host::run(controller, &app_stats));
    let started = clock.now_us();
    let budget = *core::hint::black_box(&RUN_SECONDS) * 1_000_000;
    let finish = started.wrapping_add(budget);
    let mut session: Option<Session> = None;
    let mut next_adv = started;
    put(2, 2);
    while !reached(clock.now_us(), finish) {
        #[cfg(feature = "secure")]
        time_driver::advance(clock.now_us());
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
            let prepare = s.conn.rx_start_us().wrapping_sub(100);
            // AES-CCM runs only while at least 3 ms remain before RX arming.
            // Pairing state advances when the Host answers the LTK request;
            // TX ciphertext is produced here, never inside the event.
            if reason.is_none() && !reached(clock.now_us().wrapping_add(3000), prepare) {
                reason = service_encryption(&mut soft, s);
                if reason.is_none() {
                    reason = prefetch_encrypted(&mut soft, s);
                }
            }
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
            if reason.is_none() && !reached(clock.now_us().wrapping_add(2000), prepare) {
                let mut until = earlier(prepare, earlier(finish, s.conn.supervision_deadline_us()));
                if let Some(end) = s.control.termination_deadline_us() {
                    until = earlier(until, end);
                }
                idle(&mut soft, app.as_mut(), &app_stats, &clock, until);
                continue;
            }
            if reason.is_none() {
                reason = connection_event(&mut radio, &clock, rx, data, s, &mut soft, finish);
                if s.conn.established() {
                    soft.ll.adv.enabled = false;
                }
                if reason.is_none() {
                    reason = finish_deferred(&mut soft, s);
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
