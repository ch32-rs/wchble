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
use wchble::hci::connection::{ConnectionInfo, RadioRequest};
use wchble::hci::SoftRunner;
use wchble::ll::conn::ConnectParams;
use wchble::ll::ctrl::{feature_bits, FEATURE_LE_CSA2, FEATURE_LE_DATA_LENGTH_EXTENSION};
#[cfg(feature = "secure")]
use wchble::ll::ctrl::FEATURE_LE_ENCRYPTION;
use wchble::ll::link::X1Snapshot;
use wchble::rf::family::ch585::{Ch585Aes, Ch585Radio, LLE_BASE};
#[cfg(feature = "secure")]
use wchble::rf::family::ch585::Ch585DataFlash;
#[cfg(feature = "secure")]
use wchble::storage::bond::{decode_bonds, encode_bonds, PersistedBond, MAX_BONDS, MAX_PAYLOAD};
#[cfg(feature = "secure")]
use wchble::storage::DualCopyStore;
use wchble::rf::regs::{self, lle};
use wchble::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use {panic_halt as _, portable_atomic as _};

mod host;
#[cfg(feature = "secure")]
mod bond;
#[cfg(feature = "secure")]
mod client_att;
#[cfg(feature = "secure")]
mod rng;
#[cfg(feature = "privacy")]
mod privacy;
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
/// S4 acceptance: 5 s under `rpa-fast`, otherwise the 900 s default.
const RPA_TIMEOUT_SECS: u32 = if cfg!(feature = "rpa-fast") { 5 } else { 900 };
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
// SECURE_STATS slots 2..16 are written by `wchble::ll::link` through the
// `LinkHost` counters; the numerical layout is unchanged.
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
    // Polled inside the RAM RX/TX loop; a flash call there eats the window.
    #[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
    #[inline(never)]
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

fn trace(
    now_us: u32,
    kind: u32,
    event: u16,
    channel: u8,
    header: u8,
    len: u8,
    a: u32,
    b: u32,
) {
    let count = get(39) as usize;
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

type Session = wchble::ll::link::Session<Ch585Aes>;

/// Example-side hooks for the shared session engine (executor, persistence,
/// diagnostics). The SoftRunner wiring lives in `wchble::hci::link`.
struct Extra<'a, F: Future> {
    app: Pin<&'a mut F>,
    app_stats: &'a host::HostStats,
    clock: &'a Clock,
    #[cfg(feature = "secure")]
    store: &'a mut DualCopyStore<Ch585DataFlash>,
    #[cfg(feature = "secure")]
    att_store: &'a mut DualCopyStore<Ch585DataFlash>,
}

impl<'a, F: Future> wchble::hci::link::LinkExtras for Extra<'a, F> {
    type Aes = Ch585Aes;

    fn local_features(&self) -> [u8; 8] {
        LOCAL_FEATURES
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
    fn sec_inc(&mut self, slot: usize) {
        sec_inc(slot);
    }
    fn sec_put(&mut self, slot: usize, value: u32) {
        sec_put(slot, value);
    }

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
        trace(now_us, kind, event, channel, header, len, a, b);
    }

    fn diag_acl_raw(&mut self, llid: u8, payload: &[u8], _ciphertext: bool) {
        diag_acl(true, llid, payload);
    }
    fn diag_acl_plain(&mut self, _llid: u8, _payload: &[u8]) {}
    fn diag_control_opcode(&mut self, _opcode: u8) {}
    fn note_bad_pdu(&mut self, header: u8, len: usize) {
        note_bad_pdu(header, len);
    }
    fn note_rx_frame(&mut self, _len: usize) {}
    fn note_rx_oversize(&mut self) {}
    fn note_start_req_queued(&mut self) {
        diag_put(
            DIAG_START_REQ_QUEUED,
            diag_get(DIAG_START_REQ_QUEUED).wrapping_add(1),
        );
    }
    fn note_start_rsp_queued(&mut self) {
        diag_put(
            DIAG_START_RSP_QUEUED,
            diag_get(DIAG_START_RSP_QUEUED).wrapping_add(1),
        );
    }
    fn diag_skipped_event(&mut self) {
        diag_put(
            DIAG_SKIPPED_EVENTS,
            diag_get(DIAG_SKIPPED_EVENTS).wrapping_add(1),
        );
    }

    fn resolve_peer(&mut self, soft: &mut SoftRunner, info: &mut ConnectionInfo) {
        // A resolved identity is the only case where Peer_RPA is valid, and
        // the resolution runs here, on the idle path, before the Host sees it.
        #[cfg(feature = "privacy")]
        if info.peer_address_type != 0
            && wchble::ll::privacy::is_resolvable(info.peer_address)
        {
            info.peer_rpa = Some(info.peer_address);
            let started = self.clock.now_us();
            info.peer_identity = soft.resolve_pending_peer();
            privacy::note_resolve(self.clock.now_us().wrapping_sub(started));
        }
        #[cfg(not(feature = "privacy"))]
        let _ = (soft, info);
    }
    fn published_connection(&mut self, soft: &mut SoftRunner) {
        // The second reported link closes the rotation window.
        #[cfg(feature = "privacy")]
        privacy::note_connection(soft);
        #[cfg(not(feature = "privacy"))]
        let _ = soft;
    }

    fn publish_x1(&mut self, snapshot: &X1Snapshot) {
        publish_x1(snapshot);
    }

    fn idle_gap(&mut self, soft: &mut SoftRunner, deadline: u32, until: u32) {
        #[cfg(feature = "secure")]
        flush_bonds(self.store, self.att_store, self.clock, Some(deadline));
        #[cfg(not(feature = "secure"))]
        let _ = deadline;
        idle(soft, self.app.as_mut(), self.app_stats, self.clock, until);
    }
    fn after_close(&mut self, soft: &mut SoftRunner) {
        #[cfg(not(feature = "privacy"))]
        let _ = &soft;
        #[cfg(feature = "privacy")]
        privacy::snapshot(soft);
        #[cfg(feature = "secure")]
        flush_bonds(self.store, self.att_store, self.clock, None);
    }
    fn on_disconnect_request(&mut self, reason: u8) {
        diag_disconnect(reason);
    }
    fn pre_iteration(&mut self) {
        time_driver::advance(self.clock.now_us());
    }
}


/// Publish the CSA #2 / DLE observations for the runner's `--require-x1`
/// checks. Called once per connection event, outside the RF window.
fn publish_x1(x: &X1Snapshot) {
    use host::{
        x1_put, X1_ADV_CHSEL, X1_ALGORITHM, X1_EVENT_COUNTER, X1_FEATURE_EXCHANGE,
        X1_HOST_FRAGMENTS, X1_HOST_PACKETS_SEGMENTED, X1_INIT_CHSEL, X1_LENGTH_REQ_RX,
        X1_LENGTH_REQ_TX, X1_LENGTH_RSP_RX, X1_LENGTH_RSP_TX, X1_MAGIC, X1_MAGIC_INDEX,
        X1_MAX_RX_PDU, X1_MAX_TX_PDU, X1_RX_OCTETS, X1_RX_OVER_27, X1_RX_PDUS, X1_RX_TIME,
        X1_TX_OCTETS, X1_TX_OVER_27, X1_TX_PDUS, X1_TX_TIME, X1_VERSION, X1_VERSION_INDEX,
        X1_LAST_ERROR,
    };
    x1_put(X1_MAGIC_INDEX, X1_MAGIC);
    x1_put(X1_VERSION_INDEX, X1_VERSION);
    x1_put(X1_ALGORITHM, u32::from(x.algorithm));
    x1_put(X1_EVENT_COUNTER, u32::from(x.event_counter));
    x1_put(X1_ADV_CHSEL, u32::from(x.adv_chsel));
    x1_put(X1_INIT_CHSEL, u32::from(x.init_chsel));
    x1_put(X1_LENGTH_REQ_RX, x.length_req_rx);
    x1_put(X1_LENGTH_RSP_RX, x.length_rsp_rx);
    x1_put(X1_LENGTH_REQ_TX, x.length_req_tx);
    x1_put(X1_LENGTH_RSP_TX, x.length_rsp_tx);
    x1_put(X1_TX_OCTETS, u32::from(x.tx_octets));
    x1_put(X1_RX_OCTETS, u32::from(x.rx_octets));
    x1_put(X1_TX_TIME, u32::from(x.tx_time));
    x1_put(X1_RX_TIME, u32::from(x.rx_time));
    x1_put(X1_MAX_TX_PDU, u32::from(x.max_tx_pdu));
    x1_put(X1_MAX_RX_PDU, u32::from(x.max_rx_pdu));
    x1_put(X1_RX_OVER_27, x.rx_over_27);
    x1_put(X1_TX_OVER_27, x.tx_over_27);
    x1_put(X1_HOST_PACKETS_SEGMENTED, x.host_packets_segmented);
    x1_put(X1_HOST_FRAGMENTS, x.host_fragments);
    x1_put(X1_TX_PDUS, x.tx_pdus);
    x1_put(X1_RX_PDUS, x.rx_pdus);
    x1_put(X1_FEATURE_EXCHANGE, u32::from(x.feature_exchange));
    x1_put(X1_LAST_ERROR, x.last_error);
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

/// Store the local IRK with the loaded bonds before any advertising starts.
#[cfg(feature = "privacy")]
fn persist_irk(
    store: &mut DualCopyStore<Ch585DataFlash>,
    irk: &[u8; 16],
    bonds: &[PersistedBond],
) -> bool {
    let mut payload = [0u8; MAX_PAYLOAD];
    let Ok(len) = encode_bonds(&bond::local_identity(), irk, bonds, &mut payload) else {
        return false;
    };
    for _ in 0..2 {
        bond::bump(bond::STAT_SAVE_ATTEMPTS);
        if store.save(&payload[..len]).is_ok() {
            bond::bump(bond::STAT_SAVE_OK);
            return true;
        }
        bond::bump(bond::STAT_SAVE_FAIL);
    }
    false
}

/// Persist pending bond changes. `deadline` is the next RX prepare time when a
/// connection is active; the save is deferred instead of running into an event.
#[cfg(feature = "secure")]
fn flush_bonds(
    store: &mut DualCopyStore<Ch585DataFlash>,
    att_store: &mut DualCopyStore<Ch585DataFlash>,
    clock: &Clock,
    deadline: Option<u32>,
) {
    let signals = bond::signals();
    let att_signals = client_att::signals();
    if signals.writes_blocked.get() || signals.wipe_pending_restart.get() {
        if signals.take_pending().is_some() {
            bond::bump(bond::STAT_BLOCKED_SAVES);
        }
        att_signals.discard_pending();
    }
    if let Some(deadline) = deadline {
        if reached(clock.now_us().wrapping_add(save_guard_us()), deadline) {
            bond::bump(bond::STAT_DEFERRED);
            return;
        }
    }
    // One flash operation per call: a second 22 ms save in the same window
    // would miss connection events. Clear requests set for the ATT store are
    // handled on the next idle call.
    if att_signals.wipe.take() {
        att_signals.discard_pending();
        let started = clock.now_us();
        match att_store.erase_all() {
            Ok(()) => client_att::bump(client_att::STAT_SAVE_OK),
            Err(_) => {
                client_att::bump(client_att::STAT_SAVE_FAIL);
                client_att::set(client_att::STAT_LAST_ERROR, 1);
            }
        }
        record_save_time(clock, started);
        return;
    }
    if att_signals.delete.take() {
        att_signals.discard_pending();
        let started = clock.now_us();
        match att_store.clear() {
            Ok(()) => client_att::bump(client_att::STAT_SAVE_OK),
            Err(_) => {
                client_att::bump(client_att::STAT_SAVE_FAIL);
                client_att::set(client_att::STAT_LAST_ERROR, 2);
            }
        }
        record_save_time(clock, started);
        return;
    }
    if signals.wipe.take() {
        // Erasing the store also drops any snapshot captured before the wipe.
        signals.discard_pending();
        let started = clock.now_us();
        bond::bump(bond::STAT_CLEAR_REQUESTS);
        match store.erase_all() {
            Ok(()) => {
                bond::bump(bond::STAT_CLEAR_OK);
                // The Host still holds the old IRK; never write it back.
                signals.wipe_pending_restart.set(true);
                bond::set_local_irk(&[0; 16]);
                #[cfg(feature = "privacy")]
                privacy::set_flag(privacy::FLAG_WIPE_PENDING);
            }
            Err(_) => {
                bond::bump(bond::STAT_CLEAR_FAIL);
                bond::set(bond::STAT_LAST_ERROR, 1);
            }
        }
        record_save_time(clock, started);
        att_signals.wipe.set(true);
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
        att_signals.delete.set(true);
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
    if let Some(snapshot) = signals.take_pending() {
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
        let len = match encode_bonds(
            &bond::local_identity(),
            &bond::local_irk(),
            &records[..count],
            &mut payload,
        ) {
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
        return;
    }
    let Some(snapshot) = att_signals.take_pending() else {
        return;
    };
    let mut records = [client_att::ClientAttRecord::empty(); client_att::MAX_CLIENT_ATT];
    let mut count = 0usize;
    for record in &snapshot {
        if count == client_att::MAX_CLIENT_ATT {
            break;
        }
        records[count] = *record;
        count += 1;
    }
    let mut payload = [0u8; client_att::MAX_PAYLOAD];
    let len = match client_att::encode_client_att(
        &bond::local_identity(),
        &records[..count],
        &mut payload,
    ) {
        Ok(len) => len,
        Err(_) => {
            client_att::bump(client_att::STAT_SAVE_FAIL);
            client_att::set(client_att::STAT_LAST_ERROR, 3);
            return;
        }
    };
    client_att::bump(client_att::STAT_SAVE_ATTEMPTS);
    let started = clock.now_us();
    match att_store.save(&payload[..len]) {
        Ok(()) => client_att::bump(client_att::STAT_SAVE_OK),
        Err(_) => {
            client_att::bump(client_att::STAT_SAVE_FAIL);
            client_att::set(client_att::STAT_LAST_ERROR, 4);
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
    let mut privacy_irk: Option<[u8; 16]> = None;
    #[cfg(feature = "secure")]
    let mut store = DualCopyStore::new(Ch585DataFlash, Ch585DataFlash::BOND_SLOTS);
    #[cfg(feature = "secure")]
    let mut att_store = DualCopyStore::new(Ch585DataFlash, Ch585DataFlash::CLIENT_ATT_SLOTS);
    #[cfg(feature = "secure")]
    {
        bond::set(0, bond::BOND_MAGIC);
        bond::set(1, 1);
        client_att::set(client_att::STAT_MAGIC, client_att::CATT_MAGIC);
        client_att::set(client_att::STAT_VERSION, client_att::CATT_VERSION);
        let mut boot_bonds = [PersistedBond::empty(); MAX_BONDS];
        // Read in every secure build: a save from a build without privacy must
        // not zero a key that another image persisted.
        let mut local_irk = [0u8; 16];
        let mut payload = [0u8; MAX_PAYLOAD];
        let read_started = clock.now_us();
        match store.load(&mut payload) {
            Ok(Some(len)) => match decode_bonds(
                &payload[..len],
                &bond::local_identity(),
                &mut boot_bonds,
            ) {
                Ok(Some(decoded)) => {
                    local_irk = decoded.local_irk;
                    bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_VALID);
                    bond::set(bond::STAT_RECORDS_LOADED, decoded.bonds.len() as u32);
                    bond::set(bond::STAT_WINNER_SLOT, store.active_slot().unwrap_or(0) as u32);
                    bond::set(bond::STAT_WINNER_SEQ, store.seq());
                    bond::set_boot_bonds(decoded.bonds);
                }
                // Written by an image that advertised another address. The
                // peer paired with that identity, so these keys must not be
                // offered here and the slot must not be erased either.
                Ok(None) => {
                    bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_FOREIGN);
                    bond::bump(bond::STAT_IDENTITY_MISMATCH);
                }
                Err(_) => bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_CORRUPT),
            },
            Ok(None) => bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_NONE),
            Err(_) => {
                bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_IO);
                bond::set(bond::STAT_LAST_ERROR, 4);
            }
        }
        let mut boot_att = [client_att::ClientAttRecord::empty(); client_att::MAX_CLIENT_ATT];
        let mut att_payload = [0u8; client_att::MAX_PAYLOAD];
        match att_store.load(&mut att_payload) {
            Ok(Some(len)) => match client_att::decode_client_att(
                &att_payload[..len],
                &bond::local_identity(),
                &mut boot_att,
            ) {
                Ok(Some(count)) => {
                    client_att::set(client_att::STAT_LOAD_RESULT, client_att::LOAD_VALID);
                    client_att::set(client_att::STAT_RECORDS_LOADED, count as u32);
                    client_att::set_boot_records(&boot_att[..count]);
                }
                Ok(None) => {
                    client_att::set(client_att::STAT_LOAD_RESULT, client_att::LOAD_FOREIGN);
                    client_att::bump(client_att::STAT_IDENTITY_MISMATCH);
                }
                Err(_) => client_att::set(client_att::STAT_LOAD_RESULT, client_att::LOAD_CORRUPT),
            },
            Ok(None) => client_att::set(client_att::STAT_LOAD_RESULT, client_att::LOAD_NONE),
            Err(_) => {
                client_att::set(client_att::STAT_LOAD_RESULT, client_att::LOAD_IO);
                client_att::set(client_att::STAT_LAST_ERROR, 5);
            }
        }
        bond::set(
            bond::STAT_BOOT_READ_US,
            clock.now_us().wrapping_sub(read_started),
        );
        #[cfg(feature = "privacy")]
        {
            let load = bond::value(bond::STAT_LOAD_RESULT);
            let records = bond::value(bond::STAT_RECORDS_LOADED);
            if matches!(
                load,
                bond::LOAD_IO | bond::LOAD_CORRUPT | bond::LOAD_FOREIGN
            ) {
                bond::signals().writes_blocked.set(true);
                privacy::set_flag(privacy::FLAG_WRITES_BLOCKED);
                local_irk = [0; 16];
            } else if load == bond::LOAD_VALID && local_irk != [0; 16] {
                // Same identity key across the reboot.
            } else {
                // Bonds written before privacy carry no IRK. Keep them and add
                // a fresh one: the peer must re-pair to learn it, but the device
                // no longer keeps advertising its identity address forever.
                if load == bond::LOAD_VALID && records > 0 {
                    privacy::set_flag(privacy::FLAG_IRK_MISSING);
                }
                let mut fresh = [0u8; 16];
                rng::fill(&mut fresh);
                local_irk = fresh;
                if !persist_irk(&mut store, &local_irk, bond::boot_bonds()) {
                    privacy::set_flag(privacy::FLAG_IRK_UNPERSISTED);
                    local_irk = [0; 16];
                    bond::set(bond::STAT_LAST_ERROR, 6);
                }
            }
            bond::set_rl_expected(bond::boot_bonds());
            if local_irk != [0; 16] {
                privacy_irk = Some(local_irk);
            }
        }
        bond::set_local_irk(&local_irk);
    }
    let app_stats = host::HostStats::new();
    set_peripheral_address(&peripheral_address);
    let mut app = core::pin::pin!(host::run(
        controller,
        &app_stats,
        peripheral_address,
        privacy_irk,
        RPA_TIMEOUT_SECS,
    ));
    let started = clock.now_us();
    let budget = *core::hint::black_box(&RUN_SECONDS) * 1_000_000;
    let finish = started.wrapping_add(budget);
    let mut session: Option<Session> = None;
    let mut next_adv = started;
    put(2, 2);
    while !reached(clock.now_us(), finish) {
        if let Some(s) = session.as_mut() {
            let mut host = wchble::hci::link::RunnerHost::new(
                &mut soft,
                Extra {
                    app: app.as_mut(),
                    app_stats: &app_stats,
                    clock: &clock,
                    #[cfg(feature = "secure")]
                    store: &mut store,
                    #[cfg(feature = "secure")]
                    att_store: &mut att_store,
                },
            );
            match wchble::ll::link::step(s, &mut host, &mut radio, &clock, rx, data, finish) {
                wchble::ll::link::Control::Continue => continue,
                wchble::ll::link::Control::Closed(_) => {
                    session = None;
                    put(2, 2);
                    next_adv = clock.now_us();
                    continue;
                }
                wchble::ll::link::Control::Reset => {
                    session = None;
                    put(2, 2);
                    continue;
                }
                wchble::ll::link::Control::Finish => break,
                wchble::ll::link::Control::StopTimeout => {
                    inc(22);
                    put(2, 0xee);
                    park();
                }
            }
        }
        // No active link: controller requests that need no session.
        if let Some(request) = soft.bridge.take_radio_request() {
            match request {
                RadioRequest::Reset => {
                    stop(&mut radio, &clock);
                    soft.bridge.reset_finished();
                    soft.reset_radio_stopped();
                    put(2, 2);
                }
                RadioRequest::Disconnect { reason } => diag_disconnect(reason),
            }
        }
        let now = clock.now_us();
        #[cfg(feature = "secure")]
        flush_bonds(&mut store, &mut att_store, &clock, None);
        #[cfg(feature = "privacy")]
        bond::signals().rl_ready.set(bond::rl_expected().iter().all(
            |&(kind, address, irk)| soft.privacy_has_peer(kind, address, &irk),
        ));
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
        #[cfg(feature = "privacy")]
        soft.poll_privacy(clock.now_us());
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
            // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or stops
            // the engine on error; the frame only has to live for the call.
            if unsafe { radio.tx_basic(&clock, &adv_buf.0[..adv_len], 0, None) }.is_err() {
                inc(5);
                stop(&mut radio, &clock);
                continue;
            }
            inc(4);
            let packet = {
                let mut host = wchble::hci::link::RunnerHost::new(
                    &mut soft,
                    Extra {
                        app: app.as_mut(),
                        app_stats: &app_stats,
                        clock: &clock,
                        #[cfg(feature = "secure")]
                        store: &mut store,
                        #[cfg(feature = "secure")]
                        att_store: &mut att_store,
                    },
                );
                wchble::ll::link::receive(
                    &mut radio,
                    &clock,
                    &mut host,
                    rx,
                    clock.now_us().wrapping_add(600),
                    finish,
                    700,
                    &mut [0; 2],
                )
            };
            let packet = match packet {
                wchble::ll::link::RxResult::Packet(packet) => packet,
                wchble::ll::link::RxResult::Missed => continue,
                wchble::ll::link::RxResult::Stopped => {
                    inc(22);
                    put(2, 0xee);
                    park();
                }
            };
            let pdu = &rx.0[..packet.len];
            if soft.ll.adv.validate_scan_req(pdu, packet.crc_ok) {
                // Network-mode peers must scan us at an RPA (Vol 6 Part B §6.2.1).
                let scanner = [pdu[2], pdu[3], pdu[4], pdu[5], pdu[6], pdu[7]];
                if soft.scan_request_allowed(scanner, pdu[0] & 0x40 != 0) {
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
                }
            } else if pdu[0] & 0x0f == 5 {
                inc(13);
                match ConnectParams::parse(
                    pdu,
                    packet.crc_ok,
                    soft.ll.adv.own_addr,
                    soft.ll.adv.random_addr,
                ) {
                    Ok(params) => {
                        #[cfg(feature = "privacy")]
                        {
                            let started = clock.now_us();
                            let accepted =
                                soft.admit_connection(params.peer_addr, params.peer_random);
                            privacy::note_admit(clock.now_us().wrapping_sub(started));
                            if !accepted {
                                break;
                            }
                        }
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
                            LOCAL_FEATURES,
                        );
                        #[cfg(feature = "privacy")]
                        {
                            if soft.ll.adv.random_addr
                                && wchble::ll::privacy::is_resolvable(soft.ll.adv.own_addr)
                            {
                                s.set_own_rpa(soft.ll.adv.own_addr);
                            }
                        }
                        if let Some((octets, time)) = soft.suggested_data_length_explicit() {
                            s.set_suggested_data_length(octets, time);
                        }
                        put(49, s.event_start_us());
                        put(50, u32::from(params.win_size) * 1250);
                        put(53, u32::from(s.channel()));
                        trace(
                            clock.now_us(),
                            1,
                            0,
                            channel,
                            pdu[0],
                            pdu[1],
                            params.access_addr,
                            packet.end,
                        );
                        trace(
                            clock.now_us(),
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
    flush_bonds(&mut store, &mut att_store, &clock, None);
    host_snapshot(&app_stats);
    #[cfg(feature = "privacy")]
    privacy::publish(&soft);
    put(32, clock.now_us().wrapping_sub(started));
    put(33, reg(LLE_BASE, lle::CMD));
    put(34, reg(LLE_BASE, lle::MODE));
    put(2, 9);
    park();
}
