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
use wchble::hci::connection::{ConnectionBridge, ConnectionInfo, RadioRequest, TxAcl, TxTag};
use wchble::hci::runner::LtkReply;
use wchble::hci::SoftRunner;
use wchble::ll::acl::{DataPdu, LinkSequence, RxStatus};
use wchble::ll::conn::{ConnectParams, PeripheralConnection};
use wchble::ll::ctrl::{
    feature_bits, ControlAction, ControlPdu, ControlState, LocalVersion, FEATURE_LE_CSA2,
    FEATURE_LE_DATA_LENGTH_EXTENSION,
};
#[cfg(feature = "secure")]
use wchble::ll::ctrl::FEATURE_LE_ENCRYPTION;
use wchble::crypto::BLE_MIC_LEN;
use wchble::ll::dle::LL_LEGACY_PAYLOAD;
use wchble::ll::enc::{
    EncError, EncRole, Encryption, PeripheralStart, StartStage, MAX_ENCRYPTED, MAX_PLAINTEXT,
};
use wchble::rf::family::ch585::{Ch585Aes, Ch585Radio, BB_BASE, LLE_BASE};
#[cfg(feature = "secure")]
use wchble::rf::family::ch585::Ch585DataFlash;
#[cfg(feature = "secure")]
use wchble::storage::bond::{decode_bonds, encode_bonds, PersistedBond, MAX_BONDS, MAX_PAYLOAD};
#[cfg(feature = "secure")]
use wchble::storage::DualCopyStore;
use wchble::rf::regs::{self, bb, bb_irq, lle};
use wchble::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use {panic_halt as _, portable_atomic as _};

mod host;
#[cfg(feature = "secure")]
mod bond;
#[cfg(feature = "secure")]
mod rng;
// HID needs embassy-time in both builds: the report tick is a Timer even when
// the link is not encrypted, so the driver must always be installed.
mod time_driver;

#[cfg(feature = "secure")]
use embassy_crypto_rustcrypto as _;

static SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static ADV: StaticCell<DmaBuf<64>> = StaticCell::new();
static RSP: StaticCell<DmaBuf<64>> = StaticCell::new();
static DATA: StaticCell<DmaBuf<MAX_PDU>> = StaticCell::new();

#[no_mangle]
#[used]
// The secure flow is much slower than P4: the phone only starts bonding after
// its own service discovery, and the Just Works consent dialog needs a user
// decision. 25 s expires while the link is still in ENCRYPTION_PENDING.
pub static RUN_SECONDS: u32 = if cfg!(feature = "long-run") {
    360
} else if cfg!(feature = "secure") {
    60
} else {
    25
};
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
const SEC_LAST_ERROR: usize = 15;

#[cfg(feature = "secure")]
const LOCAL_FEATURES: [u8; 8] = feature_bits(&[
    FEATURE_LE_ENCRYPTION,
    FEATURE_LE_DATA_LENGTH_EXTENSION,
    FEATURE_LE_CSA2,
]);
#[cfg(not(feature = "secure"))]
const LOCAL_FEATURES: [u8; 8] = feature_bits(&[
    FEATURE_LE_DATA_LENGTH_EXTENSION,
    FEATURE_LE_CSA2,
]);

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

/// S2 pairing diagnostics: packed rings of the last ACL fragments forwarded to
/// the Host (RX) and requested by the Host (TX), plus Host disconnect requests.
///
/// Layout: `[0]` RX sequence, `[1]` TX sequence, `[2..18)` RX entries,
/// `[18..34)` TX entries, `[34]` last disconnect reason, `[35]` disconnect count.
/// Each entry packs `seq << 24 | llid << 16 | cid << 8 | opcode`, where `cid`
/// comes from the L2CAP header of a start fragment (`llid == 2`), `0xff` marks
/// a continuation fragment, and `opcode` is the first L2CAP/SMP byte.
#[no_mangle]
static mut SEC_DIAG: [u32; DIAG_WORDS] = [0; DIAG_WORDS];

const DIAG_RX_BASE: usize = 2;
const DIAG_TX_BASE: usize = 18;
const DIAG_DISCONNECT_REASON: usize = 34;
const DIAG_DISCONNECT_COUNT: usize = 35;
const DIAG_SLOW_POLLS: usize = 36;
const DIAG_SKIPPED_EVENTS: usize = 37;
/// The Peripheral's plaintext `LL_START_ENC_REQ` was handed to the link layer.
const DIAG_START_REQ_QUEUED: usize = 38;
/// The Peripheral's encrypted `LL_START_ENC_RSP` was handed to the link layer.
const DIAG_START_RSP_QUEUED: usize = 39;

/// Last HCI command the runner answered with a non-success status:
/// `(opcode << 8) | status`.
const DIAG_HCI_FAILURE: usize = 40;
/// Newest eight HCI commands, `(opcode << 8) | status`, oldest first.
const DIAG_HCI_LOG: usize = 41;
/// Total number of commands logged, so a wrapped ring is distinguishable.
const DIAG_HCI_LOG_LEN: usize = 49;
/// Newest eight command responses actually sent to the Host, oldest first:
/// `0xE000_0000 | opcode << 8 | status` (Complete), `0xF000_0000 | ...` (Status).
const DIAG_HCI_SENT: usize = 50;
const DIAG_HCI_SENT_LEN: usize = 58;
/// First connection PDU the link layer refused this run, packed as
/// `1 | header << 8 | length << 16` (zero when every PDU was accepted).
/// A refused PDU is never acknowledged, so the peer retransmits it until
/// supervision fails; this word names the frame that starts the stall.
const DIAG_BAD_PDU: usize = 63;
const DIAG_WORDS: usize = 64;

/// Static random address advertised this boot as two little-endian words
/// (bytes 0..4, then 4..6 with padding). The secure build rotates the low
/// octet from measured entropy so a bonded peer treats every run as a new
/// device; the test runner reads this symbol to aim the sniffer and the
/// capture filter.
#[no_mangle]
static mut PERIPHERAL_ADDRESS: [u32; 2] = [0; 2];

fn set_peripheral_address(address: &[u8; 6]) {
    let words = [
        u32::from_le_bytes([address[0], address[1], address[2], address[3]]),
        u32::from_le_bytes([address[4], address[5], 0, 0]),
    ];
    unsafe {
        let dst = core::ptr::addr_of_mut!(PERIPHERAL_ADDRESS).cast::<u32>();
        dst.add(0).write_volatile(words[0]);
        dst.add(1).write_volatile(words[1]);
    }
}

/// Per-opcode counters for start fragments, which never wrap in a 25 s run:
/// `[0..16)` SMP RX by instruction code, `[16..32)` SMP TX,
/// `[32..64)` ATT RX by opcode, `[64..96)` ATT TX.
#[no_mangle]
static mut SEC_OPCODES: [u32; 96] = [0; 96];

fn opcode_get(i: usize) -> u32 {
    unsafe {
        core::ptr::addr_of!(SEC_OPCODES)
            .cast::<u32>()
            .add(i)
            .read_volatile()
    }
}
fn opcode_inc(i: usize) {
    unsafe {
        core::ptr::addr_of_mut!(SEC_OPCODES)
            .cast::<u32>()
            .add(i)
            .write_volatile(opcode_get(i).wrapping_add(1))
    }
}

fn diag_get(i: usize) -> u32 {
    unsafe {
        core::ptr::addr_of!(SEC_DIAG)
            .cast::<u32>()
            .add(i)
            .read_volatile()
    }
}
fn diag_put(i: usize, v: u32) {
    unsafe {
        core::ptr::addr_of_mut!(SEC_DIAG)
            .cast::<u32>()
            .add(i)
            .write_volatile(v)
    }
}

/// Record the first connection PDU this run refused.
fn note_bad_pdu(header: u8, len: usize) {
    if diag_get(DIAG_BAD_PDU) == 0 {
        diag_put(
            DIAG_BAD_PDU,
            1 | (u32::from(header) << 8) | ((len as u32) << 16),
        );
    }
}

fn diag_acl(rx: bool, llid: u8, payload: &[u8]) {
    let (seq_index, base) = if rx {
        (0, DIAG_RX_BASE)
    } else {
        (1, DIAG_TX_BASE)
    };
    let seq = diag_get(seq_index);
    diag_put(seq_index, seq.wrapping_add(1));
    let (cid, opcode) = match llid {
        2 => (
            payload.get(2).copied().unwrap_or(0),
            payload.get(4).copied().unwrap_or(0),
        ),
        1 => (0xff, 0),
        _ => (0, payload.first().copied().unwrap_or(0)),
    };
    if llid == 2 {
        let slot = match cid {
            6 => Some(if rx { 0 } else { 16 } + usize::from(opcode & 0x0f)),
            4 => Some(if rx { 32 } else { 64 } + usize::from(opcode & 0x1f)),
            _ => None,
        };
        if let Some(slot) = slot {
            opcode_inc(slot);
        }
    }
    let entry = ((seq & 0xff) << 24)
        | (u32::from(llid) << 16)
        | (u32::from(cid) << 8)
        | u32::from(opcode);
    diag_put(base + (seq as usize & 0x0f), entry);
}

fn diag_disconnect(reason: u8) {
    diag_put(DIAG_DISCONNECT_REASON, u32::from(reason));
    diag_put(DIAG_DISCONNECT_COUNT, diag_get(DIAG_DISCONNECT_COUNT).wrapping_add(1));
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
    capture_timeout_us: u32,
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
            Some(at) => now.wrapping_sub(at) >= capture_timeout_us,
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
    if len > MAX_ENCRYPTED + 2 {
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

/// Host ACL packet being split across LL PDUs. The Host may hand over up to
/// 251 octets even before DLE; each LL PDU takes the negotiated plaintext
/// size and only the final fragment owns the HCI tag.
struct PendingHost {
    acl: TxAcl,
    offset: usize,
    /// LL fragments queued for this Host packet; only the last owns the tag.
    fragments: u32,
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
    /// End the link after the control PDU now in `pending_control` has been
    /// queued: its ACK is then the one that closes the connection.
    terminate_after_control: Option<u8>,
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
    /// Our plaintext LL_START_ENC_REQ was sent and RX decryption is on:
    /// incoming non-empty PDUs are ciphertext and must be deferred.
    rx_encrypted: bool,
    /// The prebuilt `LL_ENC_RSP` sits in `pending_control`.
    enc_rsp_queued: bool,
    /// The prebuilt `LL_ENC_RSP` was handed to the link layer; the next event
    /// may carry the Peripheral's own `LL_START_ENC_REQ`.
    enc_rsp_sent: bool,
    /// Encrypted `LL_START_ENC_RSP` decrypted; send our precomputed response
    /// in the next event (it is the Peripheral's TX counter 0).
    pending_start_rsp: Option<EncTx>,
    /// `LE Encryption Change` must be handed to the Host once our encrypted
    /// response is on air, outside the event path.
    enc_change_pending: bool,
    pending_enc_control: Option<EncTx>,
    pending_enc_acl: Option<EncTx>,
    pending_host: Option<PendingHost>,
    /// X1 telemetry: (our ADV ChSel, the CONNECT_IND ChSel).
    chsel: (bool, bool),
    max_tx_pdu: u16,
    max_rx_pdu: u16,
    tx_over_27: u32,
    rx_over_27: u32,
    tx_pdus: u32,
    rx_pdus: u32,
    host_fragments: u32,
    host_packets_segmented: u32,
    length_req_tx: u32,
    length_rsp_tx: u32,
    length_req_rx: u32,
    length_rsp_rx: u32,
    /// First DLE failure: 0x14 = peer answered LL_UNKNOWN_RSP to our
    /// LL_LENGTH_REQ, 0x1e = malformed or rejected length parameters.
    x1_last_error: u32,
    /// Negotiated `(tx octets, tx time, rx octets, rx time)` already exported
    /// through `LE Data Length Change`.
    dl_reported: Option<(u16, u16, u16, u16)>,
    deferred_rx: Option<DeferredRx>,
    /// SKDs/IVs for `LL_ENC_RSP`, generated before the event that carries the
    /// central's `LL_ENC_REQ`: the DRBG and the response build must not run
    /// inside the 150 us response deadline.
    enc_rsp_random: [u8; 12],
    /// Full `LL_ENC_RSP` payload (opcode + SKDs + IVs), built when the link is
    /// established. The event path only copies it into the link layer; parsing
    /// the request and building the response costs enough flash-fetch time to
    /// push the reply past T_IFS.
    enc_rsp_payload: [u8; 13],
    /// The central's `LL_ENC_REQ`, parsed after the event for the same reason.
    pending_enc_req: Option<[u8; 23]>,
    /// Time after which `LL_ENC_RSP` may be queued (0 = none pending). The
    /// reference peer (macOS) answers the request two events later, after its
    /// own empty PDUs have acknowledged it; this phone's controller never
    /// sends `LL_START_ENC_REQ` when the response arrives sooner.
    enc_rsp_at: u32,
    /// `LE LTK Request` handed to the Host after the event. Building the HCI
    /// event inside the response window made `LL_ENC_RSP` late, and a central
    /// that answers one event late abandons start encryption (Android only
    /// ACKs the late response and never sends `LL_START_ENC_REQ`).
    pending_ltk: Option<([u8; 8], u16)>,
}
impl Session {
    fn new(
        params: ConnectParams,
        advertiser_chsel: bool,
        end: u32,
        now: u32,
        enc_rsp_random: [u8; 12],
    ) -> Self {
        let initiator_chsel = params.chsel;
        let mut control = ControlState::new();
        control.local_features = LOCAL_FEATURES;
        let mut enc_rsp_payload = [0u8; 13];
        enc_rsp_payload[0] = 0x04;
        enc_rsp_payload[1..].copy_from_slice(&enc_rsp_random);
        Self {
            conn: PeripheralConnection::new(params, end, advertiser_chsel),
            link: LinkSequence::new(),
            control,
            pending_control: None,
            acl_tag: None,
            terminating: None,
            terminate_after_control: None,
            terminate_requested: None,
            update_instant: None,
            update_report: None,
            began: now,
            start: PeripheralStart::new(),
            enc: None,
            enc_active: false,
            rx_encrypted: false,
            enc_rsp_queued: false,
            enc_rsp_sent: false,
            pending_start_rsp: None,
            enc_change_pending: false,
            pending_enc_control: None,
            pending_enc_acl: None,
            pending_host: None,
            chsel: (advertiser_chsel, initiator_chsel),
            max_tx_pdu: 0,
            max_rx_pdu: 0,
            tx_over_27: 0,
            rx_over_27: 0,
            tx_pdus: 0,
            rx_pdus: 0,
            host_fragments: 0,
            host_packets_segmented: 0,
            length_req_tx: 0,
            length_rsp_tx: 0,
            length_req_rx: 0,
            length_rsp_rx: 0,
            x1_last_error: 0,
            dl_reported: None,
            deferred_rx: None,
            enc_rsp_random,
            enc_rsp_payload,
            pending_enc_req: None,
            enc_rsp_at: 0,
            pending_ltk: None,
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

    /// Copy the negotiated DLE limits into the link and the receive window.
    /// The LL octet fields are payload octets; the MIC rides on top of each
    /// already-encrypted direction, so both limits move when encryption turns
    /// on. A completed negotiation is reported to the Host once per change.
    fn apply_data_length(&mut self, bridge: &mut ConnectionBridge) {
        let tx = self.control.data_length.tx_octets(self.enc_active);
        let rx = self.control.data_length.rx_octets(self.rx_encrypted);
        self.link.set_max_payloads(tx, rx);
        self.conn.set_rx_max_payload(rx);
        let data = &self.control.data_length;
        let reported = (
            data.tx_payload(),
            data.tx_time_us(),
            data.rx_payload(),
            data.rx_time_us(),
        );
        if data.negotiated() && self.dl_reported != Some(reported) {
            if bridge
                .data_length_change(reported.0, reported.1, reported.2, reported.3)
                .is_ok()
            {
                self.dl_reported = Some(reported);
            }
        }
    }

    /// True while no encryption exchange or queued PDU owns the link.
    fn encryption_idle(&self) -> bool {
        // `rx_encrypted` and `enc_rsp_sent` are link state, not procedure
        // ownership: after START_ENC they stay true for the rest of the
        // connection, so they must not keep DLE out once it completed.
        matches!(self.start.stage(), StartStage::Idle | StartStage::Active)
            && !self.enc_rsp_queued
            && !self.enc_change_pending
            && self.pending_control.is_none()
            && self.pending_enc_control.is_none()
            && self.pending_enc_acl.is_none()
            && self.pending_start_rsp.is_none()
    }
}

#[link_section = ".highcode"]
#[inline(never)]
fn connection_event(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
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
        let capture_us = s.conn.rx_complete_allowance_us() + 64;
        let Some(packet) = receive(
            radio,
            clock,
            rx,
            until,
            expires,
            capture_us,
            &mut arm_times,
        ) else {
            if first_exchange {
                trace(clock, 8, event, channel, 0, 0, arm_times[0], arm_times[1]);
            }
            break;
        };
        let header = rx.0[0];
        let payload = &rx.0[2..packet.len];
        let llid = header & 3;
        if payload.len() > MAX_ENCRYPTED {
            note_bad_pdu(header, payload.len());
            inc(9);
            break;
        }
        note_rx_pdu(s, payload.len());
        // After our plaintext LL_START_ENC_REQ, the Central's next non-empty
        // PDU is its encrypted LL_START_ENC_RSP (the link's first encrypted
        // PDU); empty PDUs stay plaintext.
        let ciphertext = s.rx_encrypted && !(llid == 1 && payload.is_empty());
        let capacity = if ciphertext {
            // The bridge stores plaintext, so reserve room for the fragment
            // without the MIC, not for the on-air ciphertext.
            let plain_len = payload.len().saturating_sub(BLE_MIC_LEN);
            s.deferred_rx.is_none()
                && match llid {
                    1 | 2 => soft.bridge.can_receive_acl(llid, plain_len),
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
            note_bad_pdu(header, payload.len());
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
                if matches!(llid, 1 | 2) {
                    diag_acl(true, llid, payload);
                }
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
                } else if llid == 3 {
                    inc(26);
                    put(38, u32::from(payload[0]));
                    match payload[0] {
                        0x03 if s.start.stage() == StartStage::Idle => {
                            // Hand the request over for parsing once the event
                            // is over. This event answers with an empty PDU
                            // (acknowledging the request); the prebuilt
                            // response leaves two events later, as macOS does.
                            // Land in the idle gap after the next event, so
                            // the response is queued for the second event after
                            // the request, which is exactly what macOS does.
                            s.enc_rsp_at = packet.end.wrapping_add(
                                u32::from(s.conn.params.interval) * 1250 * 3 / 2,
                            );
                            if payload.len() == 23 {
                                let mut req = [0u8; 23];
                                req.copy_from_slice(payload);
                                s.pending_enc_req = Some(req);
                                sec_inc(SEC_ENC_REQ);
                            } else {
                                s.enc_rsp_at = 0;
                                sec_error(0x1e);
                                s.request_terminate(0x1e, packet.end);
                            }
                        }
                        0x05 => {
                            // Core §5.1.3.1 has the Peripheral send this PDU;
                            // a Central that sends one is not followed, but it
                            // is counted so the sniffer evidence can be tied
                            // to the firmware.
                            sec_inc(SEC_START_REQ);
                        }
                        _ => {
                            let local = LocalVersion {
                                version: 0x0d,
                                company_id: 0xffff,
                                subversion: 1,
                            };
                            note_control_rx(s, payload);
                            match s.control.on_pdu(&mut s.conn, payload, local) {
                                Ok(action) => {
                                    // DLE takes effect once the request or
                                    // response has been received.
                                    s.apply_data_length(&mut soft.bridge);
                                    match action {
                                        ControlAction::Reply(pdu) => {
                                            if pdu.as_bytes().first() == Some(&7) {
                                                inc(27);
                                            }
                                            if pdu.as_bytes().first() == Some(&0x15) {
                                                s.length_rsp_tx += 1;
                                            }
                                            s.pending_control =
                                                Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                                        }
                                        ControlAction::Terminate(reason) => {
                                            remote_terminate = Some(reason)
                                        }
                                        ControlAction::None => {
                                            if payload[0] == 0 && payload.len() == 12 {
                                                s.update_instant = Some(u16::from_le_bytes([
                                                    payload[10],
                                                    payload[11],
                                                ]));
                                            }
                                        }
                                    }
                                }
                                Err(error) => {
                                    if matches!(payload.first(), Some(0x14) | Some(0x15)) {
                                        s.x1_last_error = 0x1e;
                                    }
                                    s.request_terminate(
                                        wchble::ll::ctrl::termination_reason(error),
                                        packet.end,
                                    );
                                }
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
            } else if let Some(tx) = s.pending_start_rsp.take() {
                // The Central's encrypted LL_START_ENC_RSP was the previous
                // event's PDU: answer with our precomputed encrypted response
                // (Peripheral TX counter 0). The link is encrypted from here.
                s.link
                    .queue(tx.llid, &tx.bytes[..usize::from(tx.len)])
                    .unwrap();
                s.acl_tag = tx.tag;
                s.enc_active = true;
                s.enc_change_pending = true;
                // TX grows by the MIC now that our PDUs are encrypted.
                s.apply_data_length(&mut soft.bridge);
                sec_inc(SEC_START_RSP);
                sec_inc(SEC_ENCRYPTED_TX);
                sec_inc(SEC_ACTIVE);
                diag_put(
                    DIAG_START_RSP_QUEUED,
                    diag_get(DIAG_START_RSP_QUEUED).wrapping_add(1),
                );
            } else if s.rx_encrypted {
                // LL_START_ENC_REQ is outstanding: only Empty PDUs may share
                // this window until the Central's encrypted response.
            } else if s.enc_rsp_queued {
                // The prebuilt LL_ENC_RSP owns this event.
                let pdu = s.pending_control.take().unwrap();
                s.link.queue(3, pdu.payload()).unwrap();
                s.enc_rsp_queued = false;
                s.enc_rsp_sent = true;
                if let Some(reason) = s.terminate_after_control.take() {
                    s.terminating = Some(reason);
                }
            } else if s.enc_rsp_sent && s.start.stage() == StartStage::Prepared {
                // Core 5.4 Vol 6 Part B §5.1.3.1: the Peripheral owns this
                // step. Send the plaintext LL_START_ENC_REQ and start RX
                // decryption; the Central answers with the link's first
                // encrypted PDU.
                let (start, enc) = (&mut s.start, &mut s.enc);
                match start.start_enc_req(enc.as_mut().unwrap()) {
                    Ok(pdu) => {
                        s.link.queue(3, pdu.as_bytes()).unwrap();
                        s.rx_encrypted = true;
                        // The Central's PDUs carry the MIC from here on.
                        s.apply_data_length(&mut soft.bridge);
                        sec_inc(SEC_START_REQ);
                        diag_put(
                            DIAG_START_REQ_QUEUED,
                            diag_get(DIAG_START_REQ_QUEUED).wrapping_add(1),
                        );
                    }
                    Err(_) => {
                        sec_error(0x1e);
                        s.request_terminate(0x1e, packet.end);
                    }
                }
            } else if let Some(reason) = s.terminate_requested.take() {
                s.link.queue(3, &[2, reason]).unwrap();
                s.terminating = Some(reason);
            } else if let Some(pdu) = s.pending_control.take() {
                // Ordinary control replies wait for the encryption procedure
                // to finish; only Empty/TERMINATE PDUs may share that window.
                s.link.queue(3, pdu.payload()).unwrap();
                if let Some(reason) = s.terminate_after_control.take() {
                    s.terminating = Some(reason);
                }
            } else if s.enc_rsp_at == 0 || reached(clock.now_us(), s.enc_rsp_at) {
                // The encryption procedure owns the link until it ends:
                // no ACL data may share the event with LL_ENC_REQ/LL_ENC_RSP.
                queue_next_host_fragment(soft, s);
            }
        }
        let pdu = s.link.tx_pdu();
        let frame = pdu.as_bytes();
        tx.0[..frame.len()].copy_from_slice(frame);
        let sent = transmit(radio, clock, &tx.0[..frame.len()], packet.end);
        if sent {
            note_tx_pdu(s, frame.len() - 2);
        }
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
            // A late command means nothing went on air. That is a missed
            // event, not a failed link: the PDU stays queued and is
            // retransmitted in the next event, exactly as after a lost ACK.
            // Terminating here killed the link right after LL_ENC_REQ, when a
            // long pairing poll had already consumed most of the window.
            //
            // The received PDU, however, was already acknowledged in the LL
            // sequence (`on_rx` above) and the peer will never send it again:
            // dropping it here loses a fragment of a multi-PDU L2CAP frame.
            // Trouble then sees a continuation with no reassembly in progress,
            // returns `InvalidState`, and closes the link with 0x13. Deliver
            // it even though the response is late.
            if deliver_acl && soft.bridge.receive_acl(llid, payload).is_err() {
                inc(63);
                return Some(0x1f);
            }
            return None;
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
        until = earlier(
            clock.now_us()
                .wrapping_add(s.conn.rx_complete_allowance_us() + 64),
            event_limit,
        );
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
            // Core 5.4 Vol 6 Part B §5.1.4: a negative reply becomes
            // LL_REJECT_IND with 0x06 (PIN or Key Missing) on the encrypted
            // procedure, and the link ends. Reporting 0x06 is also what makes
            // the Central drop a stale bond instead of retrying the same LTK,
            // so the next connection can pair from scratch.
            sec_error(0x06);
            s.start.abort();
            s.enc_rsp_at = 0;
            s.enc_rsp_queued = false;
            s.pending_control =
                Some(DataPdu::new(3, ControlPdu::reject_ind(0x06).as_bytes()).expect("fits"));
            // End the link only once this PDU is queued and acknowledged; the
            // next event's ACK belongs to the PDU sent before it.
            s.terminate_after_control = Some(0x06);
            return None;
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

/// Queue the next plaintext LL fragment of the Host ACL packet, taking a new
/// one from the bridge when needed. Only the fragment that ends the Host
/// packet owns the HCI tag, so the bridge credit is returned once, after the
/// LL acknowledges the final fragment.
fn queue_next_host_fragment(soft: &mut SoftRunner, s: &mut Session) {
    if s.pending_host.is_none() {
        let Some(acl) = soft.bridge.take_tx_acl() else {
            return;
        };
        if acl.len == 0 {
            let _ = soft.bridge.ack_tx(acl.tag);
            return;
        }
        diag_acl(false, acl.llid, &acl.bytes[..acl.len]);
        s.pending_host = Some(PendingHost {
            acl,
            offset: 0,
            fragments: 0,
        });
    }
    let max = usize::from(s.link.tx_max_payload());
    let done = {
        let host = s.pending_host.as_mut().unwrap();
        let remaining = host.acl.len - host.offset;
        let n = remaining.min(max);
        let llid = if host.offset == 0 { host.acl.llid } else { 1 };
        let start = host.offset;
        let end = start + n;
        s.link.queue(llid, &host.acl.bytes[start..end]).unwrap();
        host.offset = end;
        host.fragments += 1;
        s.host_fragments += 1;
        if end == host.acl.len {
            Some((host.acl.tag, host.fragments))
        } else {
            None
        }
    };
    if let Some((tag, fragments)) = done {
        if fragments > 1 {
            s.host_packets_segmented += 1;
        }
        s.pending_host = None;
        s.acl_tag = Some(tag);
    }
}

/// Count DLE opcodes seen in a received LL control PDU.
fn note_control_rx(s: &mut Session, payload: &[u8]) {
    match payload.first() {
        Some(0x14) => s.length_req_rx += 1,
        Some(0x15) => s.length_rsp_rx += 1,
        // The peer rejected our LL_LENGTH_REQ.
        Some(0x07) if payload.len() >= 2 && matches!(payload[1], 0x14 | 0x15) => {
            if s.x1_last_error == 0 {
                s.x1_last_error = 0x14;
            }
        }
        _ => {}
    }
}

fn note_tx_pdu(s: &mut Session, len: usize) {
    let len = len as u16;
    s.tx_pdus += 1;
    s.max_tx_pdu = s.max_tx_pdu.max(len);
    if len > LL_LEGACY_PAYLOAD {
        s.tx_over_27 += 1;
    }
}

fn note_rx_pdu(s: &mut Session, len: usize) {
    let len = len as u16;
    s.rx_pdus += 1;
    s.max_rx_pdu = s.max_rx_pdu.max(len);
    if len > LL_LEGACY_PAYLOAD {
        s.rx_over_27 += 1;
    }
}

/// Publish the CSA #2 / DLE observations for the HID runner's checks. Called
/// once per connection event, outside the RF window.
fn publish_x1(s: &Session) {
    use host::{
        x1_put, X1_ADV_CHSEL, X1_ALGORITHM, X1_EVENT_COUNTER, X1_FEATURE_EXCHANGE,
        X1_HOST_FRAGMENTS, X1_HOST_PACKETS_SEGMENTED, X1_INIT_CHSEL, X1_LENGTH_REQ_RX,
        X1_LENGTH_REQ_TX, X1_LENGTH_RSP_RX, X1_LENGTH_RSP_TX, X1_MAGIC, X1_MAGIC_INDEX,
        X1_MAX_RX_PDU, X1_MAX_TX_PDU, X1_RX_OCTETS, X1_RX_OVER_27, X1_RX_PDUS, X1_RX_TIME,
        X1_TX_OCTETS, X1_TX_OVER_27, X1_TX_PDUS, X1_TX_TIME, X1_VERSION, X1_VERSION_INDEX,
        X1_LAST_ERROR,
    };
    let data_length = &s.control.data_length;
    x1_put(X1_MAGIC_INDEX, X1_MAGIC);
    x1_put(X1_VERSION_INDEX, X1_VERSION);
    x1_put(
        X1_ALGORITHM,
        match s.conn.channel_selection_algorithm() {
            wchble::ll::conn::ChannelSelectionAlgorithm::Csa2 => 2,
            _ => 1,
        },
    );
    x1_put(X1_EVENT_COUNTER, u32::from(s.conn.event_counter()));
    x1_put(X1_ADV_CHSEL, u32::from(s.chsel.0));
    x1_put(X1_INIT_CHSEL, u32::from(s.chsel.1));
    x1_put(X1_LENGTH_REQ_RX, s.length_req_rx);
    x1_put(X1_LENGTH_RSP_RX, s.length_rsp_rx);
    x1_put(X1_LENGTH_REQ_TX, s.length_req_tx);
    x1_put(X1_LENGTH_RSP_TX, s.length_rsp_tx);
    x1_put(
        X1_TX_OCTETS,
        u32::from(data_length.tx_octets(s.enc_active)),
    );
    x1_put(
        X1_RX_OCTETS,
        u32::from(data_length.rx_octets(s.rx_encrypted)),
    );
    x1_put(X1_TX_TIME, u32::from(data_length.tx_time_us()));
    x1_put(X1_RX_TIME, u32::from(data_length.rx_time_us()));
    x1_put(X1_MAX_TX_PDU, u32::from(s.max_tx_pdu));
    x1_put(X1_MAX_RX_PDU, u32::from(s.max_rx_pdu));
    x1_put(X1_RX_OVER_27, s.rx_over_27);
    x1_put(X1_TX_OVER_27, s.tx_over_27);
    x1_put(X1_HOST_PACKETS_SEGMENTED, s.host_packets_segmented);
    x1_put(X1_HOST_FRAGMENTS, s.host_fragments);
    x1_put(X1_TX_PDUS, s.tx_pdus);
    x1_put(X1_RX_PDUS, s.rx_pdus);
    x1_put(
        X1_FEATURE_EXCHANGE,
        u32::from(s.control.peer_features.is_some() || data_length.negotiated()),
    );
    x1_put(X1_LAST_ERROR, s.x1_last_error);
}

/// Start DLE from the peripheral side. Android Centrals have been observed
/// sending LL_FEATURE_REQ without LL_LENGTH_REQ, so the controller asks first
/// once the peer features are known and the encryption procedure is idle.
fn service_dle(soft: &mut SoftRunner, s: &mut Session) -> Option<u8> {
    if !s.conn.established() || s.link.has_outstanding() || !s.encryption_idle() {
        return None;
    }
    let requested = soft.take_data_length_request();
    if let Some((octets, time)) = requested {
        s.control.data_length.set_local_tx(octets, time);
        let pdu = s.control.length_request();
        s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
        s.length_req_tx += 1;
        return None;
    }
    if !s.control.data_length.requested() {
        if let Some(pdu) = s.control.request_length_if_supported() {
            s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
            s.length_req_tx += 1;
            return None;
        }
        if let Some(pdu) = s.control.feature_request(true) {
            s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
        }
    }
    None
}

/// Produce at most one prepared ciphertext PDU before the next event. The
/// event only queues what is already encrypted.
///
/// Encryption assigns the CCM counter, so exactly one slot may be occupied at
/// a time: a control PDU prepared later would otherwise be sent ahead of an
/// older ACL PDU whose counter was already handed out, and the peer would
/// reject it as a MIC failure. Control still wins, but only while both slots
/// are empty; the event's priority check then never reorders two ciphertexts.
fn prefetch_encrypted(soft: &mut SoftRunner, s: &mut Session) -> Option<u8> {
    if !s.enc_active || s.pending_enc_control.is_some() || s.pending_enc_acl.is_some() {
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
        if s.pending_host.is_none() {
            if let Some(acl) = soft.bridge.take_tx_acl() {
                if acl.len == 0 {
                    let _ = soft.bridge.ack_tx(acl.tag);
                } else {
                    diag_acl(false, acl.llid, &acl.bytes[..acl.len]);
                    s.pending_host = Some(PendingHost {
                        acl,
                        offset: 0,
                        fragments: 0,
                    });
                }
            }
        }
        // The MIC lives inside the negotiated on-air limit.
        let max_plain = usize::from(s.link.tx_max_payload()).saturating_sub(BLE_MIC_LEN);
        let prepared = if let Some(host) = s.pending_host.as_mut() {
            let remaining = host.acl.len - host.offset;
            let n = remaining.min(max_plain);
            let llid = if host.offset == 0 { host.acl.llid } else { 1 };
            let start = host.offset;
            let end = start + n;
            let mut out = [0u8; MAX_ENCRYPTED];
            match enc.encrypt(llid, &host.acl.bytes[start..end], &mut out) {
                Ok(len) => Some((
                    llid,
                    out,
                    len,
                    if end == host.acl.len {
                        Some(host.acl.tag)
                    } else {
                        None
                    },
                    end,
                    host.fragments + 1,
                )),
                Err(_) => {
                    sec_error(0x1e);
                    return Some(0x1e);
                }
            }
        } else {
            None
        };
        if let Some((llid, out, len, tag, offset, fragments)) = prepared {
            s.pending_enc_acl = Some(EncTx {
                llid,
                bytes: out,
                len: len as u8,
                tag,
                terminate: None,
            });
            if let Some(host) = s.pending_host.as_mut() {
                host.offset = offset;
                host.fragments = fragments;
            }
            s.host_fragments += 1;
            if tag.is_some() {
                if fragments > 1 {
                    s.host_packets_segmented += 1;
                }
                s.pending_host = None;
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
    let payload = &rx.payload[..usize::from(rx.len)];
    let len = {
        let enc = s.enc.as_mut()?;
        match enc.decrypt(rx.header, payload, &mut plain) {
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
        // The link's first encrypted PDU must be the Central's START_ENC_RSP;
        // our own encrypted response is queued for the next event.
        if llid == 3 && len == 1 && plain[0] == 0x06 {
            match s.start.on_start_enc_rsp() {
                Ok(bytes) => {
                    let mut out = [0u8; MAX_ENCRYPTED];
                    out[..bytes.len()].copy_from_slice(bytes);
                    s.pending_start_rsp = Some(EncTx {
                        llid: 3,
                        bytes: out,
                        len: bytes.len() as u8,
                        tag: None,
                        terminate: None,
                    });
                    return None;
                }
                Err(_) => {
                    sec_error(0x1e);
                    return Some(0x1e);
                }
            }
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
            note_control_rx(s, &plain);
            match s.control.on_pdu(&mut s.conn, &plain[..len], local) {
                Ok(action) => {
                    // DLE takes effect once the request or response has been
                    // received.
                    s.apply_data_length(&mut soft.bridge);
                    match action {
                        ControlAction::Reply(pdu) => {
                            if pdu.as_bytes().first() == Some(&7) {
                                inc(27);
                            }
                            if pdu.as_bytes().first() == Some(&0x15) {
                                s.length_rsp_tx += 1;
                            }
                            s.pending_control = Some(DataPdu::new(3, pdu.as_bytes()).unwrap());
                        }
                        ControlAction::Terminate(reason) => {
                            s.request_terminate(reason, rx.end)
                        }
                        ControlAction::None => {
                            if plain[0] == 0 && len == 12 {
                                s.update_instant =
                                    Some(u16::from_le_bytes([plain[10], plain[11]]));
                            }
                        }
                    }
                }
                Err(error) => {
                    if matches!(plain.first(), Some(0x14) | Some(0x15)) {
                        s.x1_last_error = 0x1e;
                    }
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

/// Time reserved between starting a bond save and the next RX prepare: the
/// measured worst case plus 2 ms, never below 8 ms. It is a software budget,
/// not an air-interface requirement.
#[cfg(feature = "secure")]
fn save_guard_us() -> u32 {
    let observed = bond::value(bond::STAT_MAX_SAVE_US) + 2_000;
    if observed < 8_000 {
        8_000
    } else {
        observed
    }
}

#[cfg(feature = "secure")]
fn record_save_time(clock: &Clock, started: u32) {
    let took = clock.now_us().wrapping_sub(started);
    bond::set(bond::STAT_LAST_SAVE_US, took);
    bond::observe_max(bond::STAT_MAX_SAVE_US, took);
}

/// Persist pending bond changes. `deadline` is the next RX prepare time when a
/// connection is active; the save is deferred instead of running into an event.
#[cfg(feature = "secure")]
fn flush_bonds(store: &mut DualCopyStore<Ch585DataFlash>, clock: &Clock, deadline: Option<u32>) {
    let signals = bond::signals();
    if let Some(deadline) = deadline {
        if reached(clock.now_us().wrapping_add(save_guard_us()), deadline) {
            bond::bump(bond::STAT_DEFERRED);
            return;
        }
    }
    if signals.wipe.take() {
        // Erasing the store also drops any snapshot captured before the wipe.
        signals.discard_pending();
        let started = clock.now_us();
        bond::bump(bond::STAT_CLEAR_REQUESTS);
        match store.erase_all() {
            Ok(()) => bond::bump(bond::STAT_CLEAR_OK),
            Err(_) => {
                bond::bump(bond::STAT_CLEAR_FAIL);
                bond::set(bond::STAT_LAST_ERROR, 1);
            }
        }
        record_save_time(clock, started);
        return;
    }
    if signals.delete.take() {
        signals.discard_pending();
        let started = clock.now_us();
        bond::bump(bond::STAT_CLEAR_REQUESTS);
        match store.clear() {
            Ok(()) => bond::bump(bond::STAT_CLEAR_OK),
            Err(_) => {
                bond::bump(bond::STAT_CLEAR_FAIL);
                bond::set(bond::STAT_LAST_ERROR, 1);
            }
        }
        record_save_time(clock, started);
        return;
    }
    if signals.fault.take() {
        #[cfg(feature = "bond-fault")]
        {
            // Re-write the stored payload, but stop part-way: the previous copy
            // must still load after the reboot.
            let mut payload = [0u8; MAX_PAYLOAD];
            let started = clock.now_us();
            match store.load(&mut payload) {
                Ok(Some(len)) => {
                    // Half the record reaches flash; the header still claims
                    // the full length, so its payload CRC must fail. A fixed
                    // prefix longer than the record would write it complete.
                    match store.save_with_fault(&payload[..len], len / 2) {
                        Err(wchble::storage::StoreError::Injected) => {
                            bond::bump(bond::STAT_FAULT_INJECTED)
                        }
                        _ => bond::bump(bond::STAT_SAVE_FAIL),
                    }
                }
                _ => bond::bump(bond::STAT_SAVE_FAIL),
            }
            record_save_time(clock, started);
        }
        #[cfg(not(feature = "bond-fault"))]
        bond::bump(bond::STAT_SAVE_FAIL);
        return;
    }
    let Some(snapshot) = signals.take_pending() else {
        return;
    };
    let mut records = [PersistedBond::empty(); MAX_BONDS];
    let mut count = 0usize;
    for entry in &snapshot {
        if count == MAX_BONDS {
            break;
        }
        records[count] = bond::from_bond(entry);
        count += 1;
    }
    let mut payload = [0u8; MAX_PAYLOAD];
    let len = match encode_bonds(&records[..count], &mut payload) {
        Ok(len) => len,
        Err(_) => {
            bond::bump(bond::STAT_SAVE_FAIL);
            bond::set(bond::STAT_LAST_ERROR, 2);
            return;
        }
    };
    bond::bump(bond::STAT_SAVE_ATTEMPTS);
    let started = clock.now_us();
    match store.save(&payload[..len]) {
        Ok(()) => {
            bond::bump(bond::STAT_SAVE_OK);
            if deadline.is_none() {
                bond::bump(bond::STAT_SAVE_ON_DISCONNECT);
            }
        }
        Err(_) => {
            bond::bump(bond::STAT_SAVE_FAIL);
            bond::set(bond::STAT_LAST_ERROR, 3);
        }
    }
    record_save_time(clock, started);
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
        time_driver::advance(clock.now_us());
        let before = clock.now_us();
        if reached(before.wrapping_add(2000), until) {
            break;
        }
        soft.pump_once();
        if let Some(failure) = soft.last_command_failure() {
            diag_put(DIAG_HCI_FAILURE, failure);
        }
        for (i, entry) in soft.command_log().into_iter().enumerate() {
            diag_put(DIAG_HCI_LOG + i, entry);
        }
        diag_put(DIAG_HCI_LOG_LEN, soft.command_log_len());
        for (i, entry) in soft.sent_log().into_iter().enumerate() {
            diag_put(DIAG_HCI_SENT + i, entry);
        }
        diag_put(DIAG_HCI_SENT_LEN, soft.sent_log_len());
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            inc(63);
        }
        let took = clock.now_us().wrapping_sub(before);
        if took > get(61) {
            put(61, took);
        }
        if took > 100_000 {
            diag_put(DIAG_SLOW_POLLS, diag_get(DIAG_SLOW_POLLS).wrapping_add(1));
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
    let peripheral_address = host::RANDOM_ADDRESS;
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
        // S3 keeps the identity fixed: the bond store answers the peer's old
        // LTK, so a reboot must look like the same device to reuse it.
        sec_put(
            1,
            1 | (1 << 8)
                | (u32::from(rng::seeded()) << 9)
                | (u32::from(soft.entropy_seeded()) << 10),
        );
    }
    soft.set_le_features(LOCAL_FEATURES);
    // CSA #2 is negotiated only when both ADV_IND ChSel (here) and the
    // initiator's CONNECT_IND ChSel are set.
    soft.ll.adv.chsel = true;
    // S3: restore bonds before the Host advertises. The read is a flash-engine
    // command, so it happens here with the radio stopped.
    #[cfg(feature = "secure")]
    let mut store = DualCopyStore::new(Ch585DataFlash, Ch585DataFlash::BOND_SLOTS);
    #[cfg(feature = "secure")]
    {
        bond::set(0, bond::BOND_MAGIC);
        bond::set(1, 1);
        let mut boot_bonds = [PersistedBond::empty(); MAX_BONDS];
        let mut payload = [0u8; MAX_PAYLOAD];
        let read_started = clock.now_us();
        match store.load(&mut payload) {
            Ok(Some(len)) => match decode_bonds(&payload[..len], &mut boot_bonds) {
                Ok(count) => {
                    bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_VALID);
                    bond::set(bond::STAT_RECORDS_LOADED, count as u32);
                    bond::set(bond::STAT_WINNER_SLOT, store.active_slot().unwrap_or(0) as u32);
                    bond::set(bond::STAT_WINNER_SEQ, store.seq());
                    bond::set_boot_bonds(&boot_bonds[..count]);
                }
                Err(_) => bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_CORRUPT),
            },
            Ok(None) => bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_NONE),
            Err(_) => {
                bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_IO);
                bond::set(bond::STAT_LAST_ERROR, 4);
            }
        }
        bond::set(
            bond::STAT_BOOT_READ_US,
            clock.now_us().wrapping_sub(read_started),
        );
    }
    let app_stats = host::HostStats::new();
    set_peripheral_address(&peripheral_address);
    let mut app = core::pin::pin!(host::run(controller, &app_stats, peripheral_address));
    let started = clock.now_us();
    let budget = *core::hint::black_box(&RUN_SECONDS) * 1_000_000;
    let finish = started.wrapping_add(budget);
    let mut session: Option<Session> = None;
    let mut next_adv = started;
    put(2, 2);
    while !reached(clock.now_us(), finish) {
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
                    diag_disconnect(reason);
                    if let Some(s) = session.as_mut() {
                        s.request_terminate(reason, clock.now_us());
                    }
                }
            }
        }
        if let Some(s) = session.as_mut() {
            let mut reason = s.expiration(clock.now_us());
            let mut prepare = s.conn.rx_start_us().wrapping_sub(100);
            // A Host poll is non-preemptible, and LESC key agreement blocks the
            // executor for more than a second. Transmitting into an event whose
            // window already closed is what kills the link (`!sent` below), so
            // step over the missed events instead: the anchor and channel map
            // stay authoritative, and the peer simply retransmits its PDU.
            while reached(clock.now_us().wrapping_sub(2_000), prepare) {
                if s.conn.next_event().is_err() {
                    break;
                }
                diag_put(DIAG_SKIPPED_EVENTS, diag_get(DIAG_SKIPPED_EVENTS).wrapping_add(1));
                prepare = s.conn.rx_start_us().wrapping_sub(100);
                if reason.is_none() {
                    reason = s.expiration(clock.now_us());
                }
            }
            // AES-CCM runs only while at least 3 ms remain before RX arming.
            // Pairing state advances when the Host answers the LTK request;
            // TX ciphertext is produced here, never inside the event.
            // Outside the connection event: parsing and the HCI event must not
            // extend the response window that LL_ENC_RSP has to fit in.
            if let Some(req) = s.pending_enc_req.take() {
                let random = s.enc_rsp_random;
                let mut skds = [0u8; 8];
                skds.copy_from_slice(&random[..8]);
                let mut ivs = [0u8; 4];
                ivs.copy_from_slice(&random[8..]);
                match s.start.on_enc_req(&req, skds, ivs) {
                    Ok(_) => {
                        let parsed = wchble::ll::ctrl::EncReq::parse(&req).unwrap();
                        s.pending_ltk = Some((parsed.rand, parsed.ediv));
                    }
                    Err(_) => {
                        sec_error(0x1e);
                        s.request_terminate(0x1e, clock.now_us());
                    }
                }
            }
            if s.enc_rsp_at != 0
                && s.start.stage() != StartStage::Idle
                && reached(clock.now_us(), s.enc_rsp_at)
            {
                s.enc_rsp_at = 0;
                s.pending_control = Some(DataPdu::new(3, &s.enc_rsp_payload).unwrap());
                s.enc_rsp_queued = true;
                sec_inc(SEC_ENC_RSP);
            }
            if let Some((rand, ediv)) = s.pending_ltk.take() {
                if soft.push_ltk_request(rand, ediv) {
                    sec_inc(SEC_LTK_REQUEST);
                } else {
                    sec_error(0x1e);
                    s.request_terminate(0x1e, clock.now_us());
                }
            }
            if reason.is_none() && !reached(clock.now_us().wrapping_add(4000), prepare) {
                reason = service_encryption(&mut soft, s);
                if reason.is_none() {
                    reason = service_dle(&mut soft, s);
                }
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
                #[cfg(feature = "secure")]
                flush_bonds(&mut store, &clock, Some(prepare));
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
                publish_x1(s);
                if s.enc_change_pending {
                    // Our encrypted START_ENC_RSP is on air: tell the Host the
                    // link is encrypted. HCI work stays outside the event.
                    s.enc_change_pending = false;
                    let _ = soft.encryption_change(1, 0, 1);
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
                // Drop key material queued for the link that just ended; the
                // epoch guards the next take, this also clears RAM early.
                soft.clear_encryption();
                session = None;
                put(2, 2);
                next_adv = clock.now_us();
                #[cfg(feature = "secure")]
                flush_bonds(&mut store, &clock, None);
            }
            continue;
        }
        let now = clock.now_us();
        #[cfg(feature = "secure")]
        flush_bonds(&mut store, &clock, None);
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
                700,
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
                        let mut enc_rsp_random = [0u8; 12];
                        soft.fill_random(&mut enc_rsp_random);
                        let mut s = Session::new(
                            params,
                            soft.ll.adv.chsel,
                            packet.end,
                            clock.now_us(),
                            enc_rsp_random,
                        );
                        if let Some((octets, time)) = soft.suggested_data_length_explicit() {
                            s.control.data_length.set_suggested_tx(octets, time);
                        }
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
    // A pairing that completed in the last event may still be pending.
    #[cfg(feature = "secure")]
    flush_bonds(&mut store, &clock, None);
    host_snapshot(&app_stats);
    put(32, clock.now_us().wrapping_sub(started));
    put(33, reg(LLE_BASE, lle::CMD));
    put(34, reg(LLE_BASE, lle::MODE));
    put(2, 9);
    park();
}
