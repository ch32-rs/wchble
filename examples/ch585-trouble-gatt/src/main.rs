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
#[cfg(any(not(feature = "x2-ext-adv"), feature = "pp"))]
use wchble::ll::conn::ConnectParams;
#[cfg(feature = "secure")]
use wchble::ll::ctrl::FEATURE_LE_ENCRYPTION;
use wchble::ll::ctrl::{feature_bits, FEATURE_LE_CSA2, FEATURE_LE_DATA_LENGTH_EXTENSION};
use wchble::ll::link::X1Snapshot;
#[cfg(feature = "secure")]
use wchble::rf::family::ch585::Ch585DataFlash;
use wchble::rf::family::ch585::{Ch585Aes, Ch585Radio, LLE_BASE};
use wchble::rf::regs::{self, lle};
use wchble::rf::txrx::{DmaBuf, MAX_PDU, RX_DMA_MIN};
use wchble::rf::{new_radio_with_dma, PhyMode, Radio};
#[cfg(feature = "secure")]
use wchble::storage::bond::{decode_bonds, encode_bonds, PersistedBond, MAX_BONDS, MAX_PAYLOAD};
#[cfg(feature = "secure")]
use wchble::storage::DualCopyStore;
use wchble::time::{ExtendingTicks, InstantUs, TickRate};
use {panic_halt as _, portable_atomic as _};

#[cfg(all(feature = "pp", feature = "cp"))]
compile_error!("`pp` and `cp` are separate acceptance images; enable one");
#[cfg(all(feature = "x1b-2m", any(feature = "pp", feature = "cp")))]
compile_error!("`x1b-2m` opens the Peripheral-only PHY procedure; Central links cannot claim 2M");
#[cfg(all(feature = "x2-ext-adv", feature = "cp"))]
compile_error!("`x2-ext-adv` coexistence currently uses the PP Peripheral scheduler");

#[cfg(feature = "x2-ext-adv")]
mod beacon;
#[cfg(feature = "secure")]
mod bond;
#[cfg(feature = "secure")]
mod client_att;
#[cfg(feature = "cp")]
mod cp;
#[cfg(feature = "hogp")]
mod hogp;
mod host;
#[cfg(feature = "pp")]
mod pp;
#[cfg(feature = "privacy")]
mod privacy;
#[cfg(feature = "secure")]
mod rng;
#[cfg(any(feature = "secure", feature = "cp"))]
mod time_driver;

#[cfg(feature = "secure")]
use embassy_crypto_rustcrypto as _;

static SCRATCH: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static RX: StaticCell<DmaBuf<RX_DMA_MIN>> = StaticCell::new();
static ADV: StaticCell<DmaBuf<64>> = StaticCell::new();
static RSP: StaticCell<DmaBuf<64>> = StaticCell::new();
static DATA: StaticCell<DmaBuf<MAX_PDU>> = StaticCell::new();
/// Two CONNECT_IND variants (ChSel 0/1), built once per pending request.
#[cfg(feature = "cp")]
#[repr(align(32))]
struct CpConnInd(DmaBuf<128>);
#[cfg(feature = "cp")]
static CP_CONN_IND: StaticCell<CpConnInd> = StaticCell::new();

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
#[cfg_attr(
    any(feature = "pp", feature = "cp", feature = "x2-ext-adv"),
    allow(dead_code)
)]
const RPA_TIMEOUT_SECS: u32 = if cfg!(feature = "rpa-fast") { 5 } else { 900 };
#[no_mangle]
static mut STATS: [u32; 64] = [0; 64];
#[no_mangle]
static mut HOST_STATS: [u32; host::HOST_STATS_WORDS] = [0; host::HOST_STATS_WORDS];
#[no_mangle]
static mut TRACE: [u32; 128 * 8] = [0; 128 * 8];
/// S2 encryption evidence, kept separate so the P4 STATS invariants and the
/// existing runner remain untouched.
#[no_mangle]
static mut SECURE_STATS: [u32; 16] = [0; 16];

// X2a beacon evidence, written by the RF owner. `rounds` counts completed
// primary+AUX pairs and `events` the whole extended advertising events (one
// Terminated `Num_Completed` unit); the two differ by the channel sweep.
#[cfg(feature = "x2-ext-adv")]
pub const EXT_ADV_STATS_WORDS: usize = 16;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_ADV_TX: usize = 0;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_AUX_TX: usize = 1;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_AUX_LATE: usize = 2;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_ROUNDS: usize = 3;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_EVENTS: usize = 4;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_LAST_AUX_CHANNEL: usize = 5;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_LAST_AUX_PHY: usize = 6;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_TERMINATED: usize = 7;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_DID: usize = 8;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_DATA_LEN: usize = 9;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_AUX_AIR_US: usize = 10;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_AUX_SKIP: usize = 11;
#[cfg(feature = "x2-ext-adv")]
pub const EXT_MAX_OVERRUN_US: usize = 12;
#[cfg(feature = "x2-ext-adv")]
#[no_mangle]
static mut EXT_ADV_STATS: [u32; EXT_ADV_STATS_WORDS] = [0; EXT_ADV_STATS_WORDS];
/// The AUX_ADV_IND frame (2 + 10 + 245 payload bytes) needs its own DMA
/// buffer: `ADV` (64 B) only fits the ADV_EXT_IND.
#[cfg(feature = "x2-ext-adv")]
static EXT_AUX: StaticCell<DmaBuf<257>> = StaticCell::new();

// Inlined so the `.highcode` round path never calls back into flash.
#[cfg(feature = "x2-ext-adv")]
#[inline(always)]
fn ext_put(i: usize, v: u32) {
    // SAFETY: single-threaded example; only the RF owner writes EXT_ADV_STATS.
    unsafe {
        core::ptr::addr_of_mut!(EXT_ADV_STATS)
            .cast::<u32>()
            .add(i)
            .write_volatile(v)
    }
}
#[cfg(feature = "x2-ext-adv")]
#[inline(always)]
fn ext_inc(i: usize) {
    let current = unsafe {
        core::ptr::addr_of!(EXT_ADV_STATS)
            .cast::<u32>()
            .add(i)
            .read_volatile()
    };
    ext_put(i, current.wrapping_add(1));
}

const SEC_MAGIC: u32 = 0x5332_3538;
// SECURE_STATS slots 2..16 are written by `wchble::ll::link` through the
// `LinkHost` counters; the numerical layout is unchanged.

/// X1b-2 only: advertise LE 2M PHY so the Host can ask for it.
#[cfg(feature = "x1b-2m")]
const fn with_phy(mut bits: [u8; 8]) -> [u8; 8] {
    bits[1] |= 1;
    bits
}
#[cfg(not(feature = "x1b-2m"))]
const fn with_phy(bits: [u8; 8]) -> [u8; 8] {
    bits
}

/// X2a only: the extended advertising feature bit (index 12 = octet 1 bit 4).
#[cfg(feature = "x2-ext-adv")]
const fn with_ext_adv(mut bits: [u8; 8]) -> [u8; 8] {
    bits[1] |= 1 << 4;
    bits
}
#[cfg(not(feature = "x2-ext-adv"))]
const fn with_ext_adv(bits: [u8; 8]) -> [u8; 8] {
    bits
}

#[cfg(feature = "secure")]
const LOCAL_FEATURES: [u8; 8] = with_ext_adv(with_phy(feature_bits(&[
    FEATURE_LE_ENCRYPTION,
    FEATURE_LE_DATA_LENGTH_EXTENSION,
    FEATURE_LE_CSA2,
])));
#[cfg(not(feature = "secure"))]
const LOCAL_FEATURES: [u8; 8] = with_ext_adv(with_phy(feature_bits(&[
    FEATURE_LE_DATA_LENGTH_EXTENSION,
    FEATURE_LE_CSA2,
])));

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
/// Received air frames whose declared length exceeds the firmware's 40-byte
/// capture buffer; a peer that sends one PDU larger than this can never be
/// acknowledged, so these PDUs stall the link instead of failing loudly.
const DIAG_RX_OVERSIZE: usize = 59;
/// Longest declared air-frame length seen this run.
const DIAG_RX_MAX_FRAME: usize = 60;
/// Bit `opcode` set for every LL control opcode seen (0x00..=0x1f).
const DIAG_LL_CONTROL_MASK: usize = 61;
/// Most recent LL control opcode.
const DIAG_LL_CONTROL_LAST: usize = 62;
/// First connection PDU the link layer refused this run, packed as
/// `1 | header << 8 | length << 16` (zero when every PDU was accepted).
/// A refused PDU is never acknowledged, so the peer retransmits it until the
/// supervision timeout; this word names the frame that starts that stall.
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
    let entry =
        ((seq & 0xff) << 24) | (u32::from(llid) << 16) | (u32::from(cid) << 8) | u32::from(opcode);
    diag_put(base + (seq as usize & 0x0f), entry);
}

fn diag_control_opcode(opcode: u8) {
    diag_put(DIAG_LL_CONTROL_LAST, u32::from(opcode));
    diag_put(
        DIAG_LL_CONTROL_MASK,
        diag_get(DIAG_LL_CONTROL_MASK) | (1u32 << (opcode & 0x1f)),
    );
}

/// Record the first connection PDU this run refused. A refused PDU is never
/// acknowledged, so the peer retransmits it until supervision fails; keeping
/// the whole header and length names the frame that starts the stall.
fn note_bad_pdu(header: u8, len: usize) {
    if diag_get(DIAG_BAD_PDU) == 0 {
        diag_put(
            DIAG_BAD_PDU,
            1 | (u32::from(header) << 8) | ((len as u32) << 16),
        );
    }
}

fn diag_disconnect(reason: u8) {
    diag_put(DIAG_DISCONNECT_REASON, u32::from(reason));
    diag_put(
        DIAG_DISCONNECT_COUNT,
        diag_get(DIAG_DISCONNECT_COUNT).wrapping_add(1),
    );
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

fn trace(now_us: u32, kind: u32, event: u16, channel: u8, header: u8, len: u8, a: u32, b: u32) {
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

/// One X2a extended advertising event: an ADV_EXT_IND on each enabled primary
/// channel, each scheduled so its AUX_ADV_IND follows exactly 600 µs later on
/// the rotating data channel at the set's secondary PHY. The whole path stays
/// in RAM: the 600-µs window leaves ~430 µs for the AUX programming after the
/// primary is on air.
#[cfg(feature = "x2-ext-adv")]
#[cfg_attr(target_arch = "riscv32", link_section = ".highcode")]
#[inline(never)]
fn ext_adv_event(
    radio: &mut Ch585Radio,
    clock: &Clock,
    ext: &wchble::ll::adv::ExtAdvState,
    round: &mut u32,
    selected_channel: Option<u8>,
    adv_buf: &mut DmaBuf<64>,
    aux_buf: &mut DmaBuf<257>,
) -> bool {
    const PRIMARY_PREP_US: u32 = 300;
    const AUX_OFFSET_US: u32 = 600;
    let mut completed = false;
    radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
    let aux_phy = if ext.aux_phy & 0x02 != 0 {
        PhyMode::Rate2m
    } else {
        PhyMode::Rate1m
    };
    for channel in [37u8, 38, 39] {
        if selected_channel.is_some_and(|selected| selected != channel)
            || ext.channel_map & (1 << (channel - 37)) == 0
        {
            continue;
        }
        let aux_channel = wchble::ll::adv::ExtAdvState::aux_channel(*round);
        let Some(adv_len) = ext.build_adv_ext_ind(&mut adv_buf.0, aux_channel) else {
            break;
        };
        radio.set_channel(channel).unwrap();
        let primary_start = clock.now_us().wrapping_add(PRIMARY_PREP_US);
        // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or stops
        // the engine on error; the frame only has to live for the call.
        if unsafe { radio.tx_basic(clock, &adv_buf.0[..adv_len], 0, Some(primary_start)) }.is_err()
        {
            stop(radio, clock);
            continue;
        }
        ext_inc(EXT_ADV_TX);
        // Both packets ride the same scheduled-TX path, so the on-air gap is
        // exactly the AuxPtr offset the scanner expects.
        let Some(aux_len) = ext.build_aux_adv_ind(&mut aux_buf.0) else {
            break;
        };
        radio.set_channel(aux_channel).unwrap();
        radio.set_phy(aux_phy, aux_phy);
        match unsafe {
            radio.tx_basic(
                clock,
                &aux_buf.0[..aux_len],
                0,
                Some(primary_start.wrapping_add(AUX_OFFSET_US)),
            )
        } {
            Ok(()) => {
                ext_inc(EXT_AUX_TX);
                completed = true;
            }
            Err(wchble::Error::Late) => ext_inc(EXT_AUX_LATE),
            Err(_) => stop(radio, clock),
        }
        // The next primary is always 1M.
        radio.set_phy(PhyMode::Rate1m, PhyMode::Rate1m);
        ext_inc(EXT_ROUNDS);
        ext_put(EXT_LAST_AUX_CHANNEL, u32::from(aux_channel));
        *round = round.wrapping_add(1);
    }
    ext_put(
        EXT_LAST_AUX_PHY,
        if matches!(aux_phy, PhyMode::Rate2m) {
            2
        } else {
            1
        },
    );
    ext_put(EXT_AUX_AIR_US, ext.aux_air_us());
    completed
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

    fn diag_acl_raw(&mut self, llid: u8, payload: &[u8], ciphertext: bool) {
        // Ciphertext has no readable L2CAP/ATT header; counted after decrypt.
        if !ciphertext {
            diag_acl(true, llid, payload);
        }
    }
    fn diag_acl_tx(&mut self, llid: u8, payload: &[u8]) {
        diag_acl(false, llid, payload);
    }
    fn diag_acl_plain(&mut self, llid: u8, payload: &[u8]) {
        diag_acl(true, llid, payload);
    }
    fn diag_control_opcode(&mut self, opcode: u8) {
        diag_control_opcode(opcode);
    }
    fn note_bad_pdu(&mut self, header: u8, len: usize) {
        note_bad_pdu(header, len);
    }
    fn note_rx_frame(&mut self, len: usize) {
        if len as u32 > diag_get(DIAG_RX_MAX_FRAME) {
            diag_put(DIAG_RX_MAX_FRAME, len as u32);
        }
    }
    fn note_rx_oversize(&mut self) {
        diag_put(DIAG_RX_OVERSIZE, diag_get(DIAG_RX_OVERSIZE).wrapping_add(1));
    }
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
        if info.peer_address_type != 0 && wchble::ll::privacy::is_resolvable(info.peer_address) {
            info.peer_rpa = Some(info.peer_address);
            let started = self.clock.now_us();
            // Only an incoming CONNECT_IND records a pending address; a
            // Central must resolve the advertiser's RPA here, or the Host
            // would pair with the identity address and fail the DHKey check.
            info.peer_identity = soft
                .resolve_pending_peer()
                .or_else(|| soft.resolve_peer(info.peer_address, true))
                // Live IRKs, then the boot snapshot after BondLost cleared them.
                .or_else(|| resolve_accept_identity(info.peer_address));
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
        #[cfg(any(feature = "secure", feature = "cp"))]
        time_driver::advance(self.clock.now_us());
        #[cfg(not(any(feature = "secure", feature = "cp")))]
        let _ = self.clock;
    }
}

/// Publish the CSA #2 / DLE observations for the runner's `--require-x1`
/// checks. Called once per connection event, outside the RF window.
fn publish_x1(x: &X1Snapshot) {
    use host::{
        x1_put, X1_ADV_CHSEL, X1_ALGORITHM, X1_EVENT_COUNTER, X1_FEATURE_EXCHANGE,
        X1_HOST_FRAGMENTS, X1_HOST_PACKETS_SEGMENTED, X1_INIT_CHSEL, X1_LAST_ERROR,
        X1_LENGTH_REQ_RX, X1_LENGTH_REQ_TX, X1_LENGTH_RSP_RX, X1_LENGTH_RSP_TX, X1_MAGIC,
        X1_MAGIC_INDEX, X1_MAX_RX_PDU, X1_MAX_TX_PDU, X1_RX_OCTETS, X1_RX_OVER_27, X1_RX_PDUS,
        X1_RX_TIME, X1_TX_OCTETS, X1_TX_OVER_27, X1_TX_PDUS, X1_TX_TIME, X1_VERSION,
        X1_VERSION_INDEX,
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
    use host::{
        phy_put, PHY_CHANGES, PHY_IND_COUNTER, PHY_IND_INSTANT, PHY_IND_M2S, PHY_IND_S2M,
        PHY_INVALID, PHY_REQ_RX, PHY_REQ_TX, PHY_RSP_RX, PHY_RSP_TX, PHY_RX, PHY_TX, PHY_UPDATE_RX,
    };
    phy_put(PHY_TX, u32::from(x.phy_tx));
    phy_put(PHY_RX, u32::from(x.phy_rx));
    phy_put(PHY_REQ_TX, x.phy_req_tx);
    phy_put(PHY_REQ_RX, x.phy_req_rx);
    phy_put(PHY_RSP_TX, x.phy_rsp_tx);
    phy_put(PHY_RSP_RX, x.phy_rsp_rx);
    phy_put(PHY_UPDATE_RX, x.phy_update_rx);
    phy_put(PHY_CHANGES, x.phy_changes);
    phy_put(PHY_INVALID, x.phy_invalid);
    phy_put(PHY_IND_M2S, u32::from(x.phy_ind.0));
    phy_put(PHY_IND_S2M, u32::from(x.phy_ind.1));
    phy_put(PHY_IND_INSTANT, u32::from(x.phy_ind_instant));
    phy_put(PHY_IND_COUNTER, u32::from(x.phy_ind_counter));
}

fn host_snapshot(stats: &host::HostStats) {
    for i in 0..host::HOST_STATS_WORDS {
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
    // A failed boot load or a completed factory wipe must not be undone by a
    // later snapshot: drop it instead of rewriting unreadable/old state.
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
                // The Host future still holds the old IRK; a new snapshot must
                // not write it back, so this boot stops saving bonds.
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
        #[cfg(any(feature = "secure", feature = "cp"))]
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
        // A3 separates the pairing window: one LESC P-256 poll is ~1 s, while
        // steady-state polls must stay under 100 ms. Slot 61 = steady max,
        // slot 60 = pairing-window max. Polls with no live link cannot starve
        // a connection, so the boot keypair poll is not measured.
        #[cfg(all(feature = "secure", feature = "cp"))]
        let pairing = crate::cp::pairing_window();
        #[cfg(all(feature = "secure", not(feature = "cp")))]
        let pairing = matches!(
            stats.word(host::STAT_SECURITY),
            host::SECURITY_REQUESTED | host::SECURITY_PAIRED
        );
        #[cfg(not(feature = "secure"))]
        let pairing = false;
        #[cfg(feature = "secure")]
        if soft.any_link_connected() {
            let slot = if pairing { 60 } else { 61 };
            if took > get(slot) {
                put(slot, took);
            }
        }
        #[cfg(not(feature = "secure"))]
        let _ = pairing;
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

#[cfg(any(feature = "pp", feature = "cp"))]
enum PpAdv {
    /// Nothing to report: no usable packet, a scan request was answered, or
    /// the transmit failed.
    Idle,
    /// CONNECT_IND admitted; the caller builds the Session.
    Connect(ConnectParams, u32),
    /// Admission (privacy) refused the initiator.
    #[cfg(feature = "privacy")]
    Rejected,
    /// The run budget ended before the fragment started.
    Finished,
}

/// One advertising channel: ADV_IND, then a bounded scan-request window.
#[cfg(any(feature = "pp", feature = "cp"))]
#[allow(clippy::too_many_arguments)]
fn pp_adv_fragment<F: Future>(
    radio: &mut Ch585Radio,
    clock: &Clock,
    soft: &mut SoftRunner,
    channel: u8,
    adv_buf: &mut DmaBuf<64>,
    rsp_buf: &mut DmaBuf<64>,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    mut app: Pin<&mut F>,
    app_stats: &host::HostStats,
    #[cfg(feature = "secure")] store: &mut DualCopyStore<Ch585DataFlash>,
    #[cfg(feature = "secure")] att_store: &mut DualCopyStore<Ch585DataFlash>,
    finish: u32,
) -> PpAdv {
    if reached(clock.now_us(), finish) {
        return PpAdv::Finished;
    }
    radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
    #[cfg(feature = "privacy")]
    soft.poll_privacy(clock.now_us());
    let Some(adv_len) = soft.build_adv_pdu(&mut adv_buf.0) else {
        return PpAdv::Idle;
    };
    let Some(rsp_len) = soft.ll.adv.build_scan_rsp(&mut rsp_buf.0) else {
        inc(63);
        return PpAdv::Finished;
    };
    radio.set_channel(channel).unwrap();
    inc(3);
    // SAFETY: `tx_basic` completes the DMA, starts none on `Late`, or stops
    // the engine on error; the frame only has to live for the call.
    if unsafe { radio.tx_basic(clock, &adv_buf.0[..adv_len], 0, None) }.is_err() {
        inc(5);
        stop(radio, clock);
        return PpAdv::Idle;
    }
    inc(4);
    let packet = {
        let mut host = wchble::hci::link::RunnerHost::for_slot(
            0,
            soft,
            Extra {
                app: app.as_mut(),
                app_stats,
                clock,
                #[cfg(feature = "secure")]
                store,
                #[cfg(feature = "secure")]
                att_store,
            },
        );
        wchble::ll::link::receive(
            radio,
            clock,
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
        wchble::ll::link::RxResult::Missed => return PpAdv::Idle,
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
            // SAFETY: as above; the response frame outlives the call.
            match unsafe {
                radio.tx_basic(
                    clock,
                    &rsp_buf.0[..rsp_len],
                    0,
                    Some(packet.end.wrapping_add(120)),
                )
            } {
                Ok(()) => inc(11),
                Err(wchble::Error::Late) => inc(12),
                Err(_) => inc(5),
            }
            stop(radio, clock);
        }
        return PpAdv::Idle;
    }
    if pdu[0] & 0x0f != 5 {
        inc(9);
        return PpAdv::Idle;
    }
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
                let accepted = soft.admit_connection(params.peer_addr, params.peer_random);
                privacy::note_admit(clock.now_us().wrapping_sub(started));
                if !accepted {
                    return PpAdv::Rejected;
                }
            }
            inc(14);
            PpAdv::Connect(params, packet.end)
        }
        Err(_) => {
            inc(9);
            PpAdv::Idle
        }
    }
}

/// Next advertising channel that the current map allows.
#[cfg(any(feature = "pp", feature = "cp"))]
fn pp_adv_channel(soft: &SoftRunner, index: &mut u8) -> u8 {
    for _ in 0..3 {
        let channel = 37 + *index;
        *index = (*index + 1) % 3;
        if soft.ll.adv.channel_map & (1 << (channel - 37)) != 0 {
            return channel;
        }
    }
    37
}

#[cfg(feature = "x2-ext-adv-coex")]
fn ext_primary_channel(channel_map: u8, index: &mut u8) -> u8 {
    for _ in 0..3 {
        let channel = 37 + *index;
        *index = (*index + 1) % 3;
        if channel_map & (1 << (channel - 37)) != 0 {
            return channel;
        }
    }
    37
}

/// X3.4a RF loop: the scheduler interleaves up to two links with a
/// one-channel advertising fragment per interval.
#[cfg(feature = "pp")]
#[allow(clippy::too_many_arguments)]
fn pp_loop<F: Future>(
    radio: &mut Ch585Radio,
    clock: &Clock,
    soft: &mut SoftRunner,
    adv_buf: &mut DmaBuf<64>,
    rsp_buf: &mut DmaBuf<64>,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    #[cfg(feature = "x2-ext-adv-coex")] aux_buf: &mut DmaBuf<257>,
    mut app: Pin<&mut F>,
    app_stats: &host::HostStats,
    #[cfg(feature = "secure")] store: &mut DualCopyStore<Ch585DataFlash>,
    #[cfg(feature = "secure")] att_store: &mut DualCopyStore<Ch585DataFlash>,
    started: u32,
    finish: u32,
) {
    use wchble::ll::link::{Control, SessionLink};
    use wchble::ll::sched::{
        BackgroundKind, BackgroundWindow, Decision, EventOutcome, LinkTable, WorkId,
    };
    // One TX + bounded scan window + stop, admitted only inside a link gap.
    const ADV_SPAN_US: u32 = 900;
    // Leave enough time for radio PHY restoration and scheduler bookkeeping
    // after the AUX fragment; repeated coex overruns showed 160 us was too short.
    const ADV_EXIT_US: u32 = 1_000;
    const SWITCH_GUARD_US: u32 = 300;
    const ADV_SCHEDULE_LEAD_US: u32 = 10_000;
    // Acceptance counters in slots no other `pp` path writes: 45 fragment
    // failures, 46 fragments, 47 skips, 33 capacity rejects, 34 overruns.
    // The legacy CMD/MODE snapshot of 33/34 is cfg'd out under `pp`.

    let mut links: LinkTable<SessionLink<Ch585Aes>, 2> = LinkTable::new(SWITCH_GUARD_US);
    let mut adv_work: Option<WorkId> = None;
    let mut adv_channel = 0u8;
    #[cfg(feature = "x2-ext-adv-coex")]
    let mut ext_round = 0u32;
    #[cfg(feature = "x2-ext-adv-coex")]
    let mut ext_seen_enabled = false;
    let mut next_adv = started;
    while !reached(clock.now_us(), finish) {
        #[cfg(feature = "x2-ext-adv-coex")]
        let ext_enabled = soft.ll.ext_adv.enabled;
        #[cfg(feature = "x2-ext-adv-coex")]
        if ext_enabled && !ext_seen_enabled {
            soft.ext_adv_started(clock.now_us());
            ext_put(EXT_DID, u32::from(soft.ll.ext_adv.did));
            ext_put(EXT_DATA_LEN, soft.ll.ext_adv.data_len as u32);
            ext_seen_enabled = true;
        } else if !ext_enabled {
            ext_seen_enabled = false;
        }
        #[cfg(feature = "x2-ext-adv-coex")]
        let background_enabled = soft.ll.adv.enabled || ext_enabled;
        #[cfg(not(feature = "x2-ext-adv-coex"))]
        let background_enabled = soft.ll.adv.enabled;
        let now = clock.now_us();
        if adv_work.is_none() && background_enabled && reached(now, next_adv) {
            #[cfg(feature = "x2-ext-adv-coex")]
            let span_us = if ext_enabled {
                300u32.wrapping_add(soft.ll.ext_adv.round_span_us(0))
            } else {
                ADV_SPAN_US
            };
            #[cfg(not(feature = "x2-ext-adv-coex"))]
            let span_us = ADV_SPAN_US;
            let start_us = now.wrapping_add(ADV_SCHEDULE_LEAD_US);
            let window = BackgroundWindow {
                kind: BackgroundKind::Advertising,
                start_us,
                end_us: start_us.wrapping_add(span_us),
                exit_us: ADV_EXIT_US,
                priority: 0,
            };
            match links.insert_background(window, clock.now_us()) {
                Ok(id) => adv_work = Some(id),
                Err(_) => {
                    inc(45);
                    #[cfg(feature = "x2-ext-adv-coex")]
                    if ext_enabled {
                        ext_inc(EXT_AUX_SKIP);
                    }
                    #[cfg(feature = "x2-ext-adv-coex")]
                    let interval_us = if soft.ll.ext_adv.enabled {
                        u32::from(soft.ll.ext_adv.interval_slots) * 625
                    } else {
                        soft.adv_interval_us()
                    };
                    #[cfg(not(feature = "x2-ext-adv-coex"))]
                    let interval_us = soft.adv_interval_us();
                    next_adv = clock.now_us().wrapping_add(interval_us);
                }
            }
        }
        let now = clock.now_us();
        match links.select(now, finish) {
            Decision::Run { ticket, .. } => {
                // A refused begin leaves the ticket reserved; cancel it so the
                // next select cannot spin on Busy.
                if links.begin(ticket, now).is_err() {
                    let _ = links.cancel(ticket);
                    continue;
                }
                let slot = ticket.id().slot();
                let (control, served, idle) = {
                    let link = links.link_mut(ticket.id()).expect("dispatched link");
                    let mut host = wchble::hci::link::RunnerHost::for_slot(
                        slot,
                        soft,
                        Extra {
                            app: app.as_mut(),
                            app_stats,
                            clock,
                            #[cfg(feature = "secure")]
                            store,
                            #[cfg(feature = "secure")]
                            att_store,
                        },
                    );
                    let control = wchble::ll::link::step(
                        &mut link.session,
                        &mut host,
                        radio,
                        clock,
                        rx,
                        tx,
                        ticket.hard_end_us(),
                    );
                    let served = link.session.take_event_served();
                    (control, served, clock.now_us())
                };
                let outcome = EventOutcome::Done {
                    consumed_event: served,
                    idle_at_us: idle,
                };
                match control {
                    Control::Continue => {
                        let _ = links.complete(ticket, outcome);
                    }
                    Control::Closed(_) => {
                        let _ = links.complete(ticket, outcome);
                        let _ = links.remove(ticket.id());
                        put(2, 2);
                        next_adv = clock.now_us();
                    }
                    Control::Reset => {
                        let _ = links.complete(ticket, outcome);
                        // Reset is global: retire every slot, not just this one.
                        stop(radio, clock);
                        let _ = links.reset();
                        soft.bridge.reset_finished();
                        if let Some(slot1) = soft.link_bridge_mut(1) {
                            slot1.reset_finished();
                        }
                        soft.reset_radio_stopped();
                        put(2, 2);
                        next_adv = clock.now_us();
                    }
                    Control::Finish => break,
                    Control::StopTimeout => {
                        let _ = links.complete(ticket, EventOutcome::StopUnconfirmed);
                        inc(22);
                        put(2, 0xee);
                        park();
                    }
                }
                #[cfg(feature = "x2-ext-adv-coex")]
                if ext_enabled {
                    if let Some(work) = adv_work.take() {
                        let _ = links.remove_background(work);
                        ext_inc(EXT_AUX_SKIP);
                        next_adv = clock
                            .now_us()
                            .wrapping_add(u32::from(soft.ll.ext_adv.interval_slots) * 625);
                    }
                }
            }
            Decision::RunBackground { ticket, .. } => {
                if links.begin_background(ticket, now).is_err() {
                    let _ = links.cancel_background(ticket);
                    adv_work = None;
                    inc(45);
                    #[cfg(feature = "x2-ext-adv-coex")]
                    if ext_enabled {
                        ext_inc(EXT_AUX_SKIP);
                    }
                    #[cfg(feature = "x2-ext-adv-coex")]
                    let interval_us = if soft.ll.ext_adv.enabled {
                        u32::from(soft.ll.ext_adv.interval_slots) * 625
                    } else {
                        soft.adv_interval_us()
                    };
                    #[cfg(not(feature = "x2-ext-adv-coex"))]
                    let interval_us = soft.adv_interval_us();
                    next_adv = clock.now_us().wrapping_add(interval_us);
                    continue;
                }
                #[cfg(feature = "x2-ext-adv-coex")]
                let channel = if ext_enabled {
                    ext_primary_channel(soft.ll.ext_adv.channel_map, &mut adv_channel)
                } else {
                    pp_adv_channel(soft, &mut adv_channel)
                };
                #[cfg(not(feature = "x2-ext-adv-coex"))]
                let channel = pp_adv_channel(soft, &mut adv_channel);
                #[cfg(feature = "x2-ext-adv-coex")]
                let step = if soft.ll.ext_adv.enabled {
                    let completed = ext_adv_event(
                        radio,
                        clock,
                        &soft.ll.ext_adv,
                        &mut ext_round,
                        Some(channel),
                        adv_buf,
                        aux_buf,
                    );
                    if completed {
                        let terminated = soft.ext_adv_round_done(clock.now_us());
                        ext_inc(EXT_EVENTS);
                        if terminated {
                            ext_inc(EXT_TERMINATED);
                        }
                    }
                    PpAdv::Idle
                } else {
                    pp_adv_fragment(
                        radio,
                        clock,
                        soft,
                        channel,
                        adv_buf,
                        rsp_buf,
                        rx,
                        app.as_mut(),
                        app_stats,
                        #[cfg(feature = "secure")]
                        store,
                        #[cfg(feature = "secure")]
                        att_store,
                        finish,
                    )
                };
                #[cfg(not(feature = "x2-ext-adv-coex"))]
                let step = pp_adv_fragment(
                    radio,
                    clock,
                    soft,
                    channel,
                    adv_buf,
                    rsp_buf,
                    rx,
                    app.as_mut(),
                    app_stats,
                    #[cfg(feature = "secure")]
                    store,
                    #[cfg(feature = "secure")]
                    att_store,
                    finish,
                );
                let idle = clock.now_us();
                let hard_end_us = ticket.hard_end_us();
                if let Ok(wchble::ll::sched::CompleteResult::Overrun { actual_end_us, .. }) = links
                    .complete_background(
                        ticket,
                        EventOutcome::Done {
                            consumed_event: false,
                            idle_at_us: idle,
                        },
                    )
                {
                    inc(34);
                    #[cfg(feature = "x2-ext-adv-coex")]
                    if ext_enabled {
                        let overrun_us = actual_end_us.wrapping_sub(hard_end_us);
                        let max = unsafe {
                            core::ptr::addr_of!(EXT_ADV_STATS)
                                .cast::<u32>()
                                .add(EXT_MAX_OVERRUN_US)
                                .read_volatile()
                        };
                        if overrun_us > max {
                            ext_put(EXT_MAX_OVERRUN_US, overrun_us);
                        }
                    }
                }
                adv_work = None;
                inc(46);
                match step {
                    PpAdv::Connect(params, end) => {
                        let mut enc_rsp_random = [0u8; 12];
                        soft.fill_random(&mut enc_rsp_random);
                        let mut s = Session::new(
                            params,
                            soft.ll.adv.chsel,
                            end,
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
                        let (pref_tx, pref_rx) = soft.default_phy();
                        s.set_phy_prefs(pref_tx, pref_rx);
                        put(49, s.event_start_us());
                        put(50, u32::from(params.win_size) * 1250);
                        put(53, u32::from(s.channel()));
                        radio.set_aa_crc(params.access_addr, params.crc_init);
                        match links.insert(SessionLink::new(s)) {
                            Ok(_) => put(2, 3),
                            Err(_) => {
                                inc(33);
                                put(2, 2);
                            }
                        }
                    }
                    #[cfg(feature = "privacy")]
                    PpAdv::Rejected => {
                        inc(33);
                        put(2, 2);
                    }
                    PpAdv::Idle => {}
                    PpAdv::Finished => break,
                }
                #[cfg(feature = "x2-ext-adv-coex")]
                let interval_us = if soft.ll.ext_adv.enabled {
                    u32::from(soft.ll.ext_adv.interval_slots) * 625
                } else {
                    soft.adv_interval_us()
                };
                #[cfg(not(feature = "x2-ext-adv-coex"))]
                let interval_us = soft.adv_interval_us();
                next_adv = clock.now_us().wrapping_add(interval_us);
            }
            // A link event was skipped, not a background expiry: the
            // reservation (if any) stays in the table until RunBackground
            // or BackgroundMissed resolves it.
            Decision::Skipped { .. } => {
                inc(47);
            }
            Decision::BackgroundMissed { .. } => {
                adv_work = None;
                inc(45);
                #[cfg(feature = "x2-ext-adv-coex")]
                if ext_enabled {
                    ext_inc(EXT_AUX_SKIP);
                }
                #[cfg(feature = "x2-ext-adv-coex")]
                let interval_us = if soft.ll.ext_adv.enabled {
                    u32::from(soft.ll.ext_adv.interval_slots) * 625
                } else {
                    soft.adv_interval_us()
                };
                #[cfg(not(feature = "x2-ext-adv-coex"))]
                let interval_us = soft.adv_interval_us();
                next_adv = clock.now_us().wrapping_add(interval_us);
            }
            Decision::Close { id, reason, .. } => {
                stop(radio, clock);
                let _ = links.remove(id);
                // Keyed close: also clears this link's security work.
                soft.close_link_slot(id.slot(), reason);
                #[cfg(feature = "privacy")]
                privacy::snapshot(soft);
                #[cfg(feature = "secure")]
                flush_bonds(store, att_store, clock, None);
                put(2, 2);
                next_adv = clock.now_us();
            }
            Decision::Invalid { id, .. } => {
                stop(radio, clock);
                let _ = links.remove(id);
                soft.close_link_slot(id.slot(), 0x3e);
                #[cfg(feature = "privacy")]
                privacy::snapshot(soft);
                #[cfg(feature = "secure")]
                flush_bonds(store, att_store, clock, None);
                put(2, 2);
            }
            Decision::Busy { .. } => {
                // Synchronous completes make this unreachable; never sleep to
                // hard_end and miss the next link's prepare.
                idle(
                    soft,
                    app.as_mut(),
                    app_stats,
                    clock,
                    clock.now_us().wrapping_add(100),
                );
            }
            Decision::Idle { until_us } => {
                #[cfg(feature = "secure")]
                flush_bonds(store, att_store, clock, None);
                idle(
                    soft,
                    app.as_mut(),
                    app_stats,
                    clock,
                    earlier(finish, until_us),
                );
            }
            Decision::Budget => break,
            Decision::Faulted => {
                inc(22);
                put(2, 0xee);
                park();
            }
            Decision::Exhausted => break,
        }
        // A Reset or Disconnect that stops all RF needs no link to run.
        if links.is_empty() {
            let request = soft
                .bridge
                .take_radio_request()
                .or_else(|| soft.link_bridge_mut(1).and_then(|b| b.take_radio_request()));
            if let Some(request) = request {
                match request {
                    RadioRequest::Reset => {
                        stop(radio, clock);
                        soft.bridge.reset_finished();
                        if let Some(slot1) = soft.link_bridge_mut(1) {
                            slot1.reset_finished();
                        }
                        soft.reset_radio_stopped();
                        put(2, 2);
                        next_adv = clock.now_us();
                    }
                    RadioRequest::Disconnect { reason } => diag_disconnect(reason),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// X3.5 CP: background scan, hardware-timed CONNECT_IND, one Central slot.
// ---------------------------------------------------------------------------

#[cfg(feature = "cp")]
use wchble::rf::LinkRadio;

#[cfg(feature = "cp")]
struct CpInitiator {
    request: wchble::hci::runner::CreateConnRequest,
    params: ConnectParams,
    ind_len: usize,
    deadline_us: u32,
    /// Policy 1 snapshot: the CONNECT_IND is built before the AdvA is known.
    accept_list: bool,
    fal: [(u8, [u8; 6]); CP_FAL_MAX],
    fal_len: usize,
    /// Last RPA resolved for this accept list. Resolving inside the T_IFS
    /// budget is too slow, so the first advertisement is only a cache fill.
    resolved: Option<([u8; 6], u8, [u8; 6])>,
}

#[cfg(feature = "cp")]
enum CpScan {
    Idle,
    /// Target advertisement seen and the CONNECT_IND completed on air.
    Connect(ConnectParams, u32),
}

#[cfg(feature = "cp")]
struct CpScanPacket {
    len: usize,
    crc_ok: bool,
    peer_chsel: bool,
    peer_addr: [u8; 6],
    peer_random: bool,
    connect_done: Option<u32>,
}

#[cfg(feature = "cp")]
const CP_SCAN_WINDOW_US: u32 = 6_000;
/// A1 evidence: policy-1 initiator activity.
///
/// 0 magic, 1 prepares, 2 accept-list length, 3 connectable advertisements
/// seen while armed, 4 address matches, 5 CONNECT_INDs queued, 6 queue
/// failures, 7 last header, 8/9 last advertiser address and type, 10/11 first
/// accept-list member address and type.
#[cfg(feature = "cp")]
#[no_mangle]
static mut INIT_DIAG: [u32; 18] = [0; 18];

#[cfg(feature = "cp")]
fn init_get(index: usize) -> u32 {
    // SAFETY: see `init_put`.
    unsafe { core::ptr::addr_of!(INIT_DIAG).cast::<u32>().add(index).read_volatile() }
}

#[cfg(feature = "cp")]
fn init_put(index: usize, value: u32) {
    // SAFETY: single-threaded; the RF loop and the Host poll never overlap.
    unsafe {
        core::ptr::addr_of_mut!(INIT_DIAG)
            .cast::<u32>()
            .add(index)
            .write_volatile(value)
    }
}

#[cfg(feature = "cp")]
fn init_inc(index: usize) {
    // SAFETY: see `init_put`.
    let current = unsafe {
        core::ptr::addr_of!(INIT_DIAG)
            .cast::<u32>()
            .add(index)
            .read_volatile()
    };
    init_put(index, current.wrapping_add(1));
}
#[cfg(feature = "cp")]
const CP_SCAN_CAPTURE_US: u32 = 700;
#[cfg(feature = "cp")]
const CP_INITIATOR_TIMEOUT_US: u32 = 6_000_000;
#[cfg(feature = "cp")]
const CP_CONN_IND_CSEL_OFFSET: usize = 64;
#[cfg(feature = "cp")]
const CP_FAL_MAX: usize = wchble::ll::privacy::MAX_FILTER_ACCEPT_LIST;
#[cfg(feature = "cp")]
const CP_WIN_SIZE: u8 = 8;
#[cfg(feature = "cp")]
const CP_WIN_OFFSET: u16 = 0;
#[cfg(feature = "cp")]
const CP_CONNECT_CHM: [u8; 5] = [0xff, 0xff, 0xff, 0xff, 0x1f];
#[cfg(feature = "cp")]
const CP_CONNECT_HOP: u8 = 5;
#[cfg(feature = "cp")]
const CP_CONNECT_SCA: u8 = 0;
/// Data-channel access addresses that pass `valid_access_address`; the second
/// keeps the outbound link from colliding with a live inbound one.
#[cfg(feature = "cp")]
const CP_AAS: [(u32, u32); 2] = [(0x1234_5678, 0x0055_5555), (0x1a2b_3c4d, 0x0065_4321)];

/// A1: a cached RPA matches when its resolved identity is in the accept list.
#[cfg(feature = "cp")]
fn cp_accept_identity(
    accept: &[(u8, [u8; 6])],
    cached: Option<([u8; 6], u8, [u8; 6])>,
    address: [u8; 6],
) -> bool {
    match cached {
        Some((rpa, kind, identity)) if rpa == address => accept
            .iter()
            .any(|&(k, a)| a == identity && k & 1 == kind & 1),
        _ => false,
    }
}

/// Resolve an on-air RPA through live IRKs, then the boot snapshot after
/// BondLost pruned the live list (Host accept([identity]) still needs it).
#[cfg(feature = "secure")]
fn resolve_accept_identity(address: [u8; 6]) -> Option<(u8, [u8; 6])> {
    crate::bond::resolve_identity(address)
        .or_else(|| crate::bond::resolve_identity_boot(address))
}

#[cfg(not(feature = "secure"))]
fn resolve_accept_identity(address: [u8; 6]) -> Option<(u8, [u8; 6])> {
    let _ = address;
    None
}

/// Build both CONNECT_IND variants once per pending request, with an AA that
/// no live link is using.
#[cfg(feature = "cp")]
fn cp_prepare_initiator(
    soft: &mut SoftRunner,
    conn_buf: &mut CpConnInd,
    used: [u32; 2],
    request: wchble::hci::runner::CreateConnRequest,
) -> Option<CpInitiator> {
    let (access_addr, crc_init) = CP_AAS
        .iter()
        .copied()
        .find(|(aa, _)| !used.contains(aa))
        .unwrap_or(CP_AAS[0]);
    let mut params = ConnectParams {
        peer_addr: request.peer_addr,
        peer_random: request.peer_random,
        chsel: false,
        access_addr,
        crc_init,
        win_size: CP_WIN_SIZE,
        win_offset: CP_WIN_OFFSET,
        interval: request.interval_min,
        latency: request.latency,
        timeout: request.timeout,
        channel_map: CP_CONNECT_CHM,
        hop: CP_CONNECT_HOP,
        sca: CP_CONNECT_SCA,
    };
    let (own_addr, own_random) = soft.initiator_addr(&request);
    let Some(ind_len) = params.build_connect_ind(&mut conn_buf.0 .0, own_addr, own_random) else {
        let _ = soft.connection_failed(0x12);
        soft.clear_pending_connect();
        return None;
    };
    params.chsel = true;
    if params.build_connect_ind(
        &mut conn_buf.0 .0[CP_CONN_IND_CSEL_OFFSET..],
        own_addr,
        own_random,
    ) != Some(ind_len)
    {
        let _ = soft.connection_failed(0x12);
        soft.clear_pending_connect();
        return None;
    }
    params.chsel = false;
    let mut fal = [(0u8, [0u8; 6]); CP_FAL_MAX];
    let mut fal_len = 0;
    if request.use_accept_list {
        for index in 0..CP_FAL_MAX {
            if let Some(entry) = soft.filter_accept_entry(index) {
                fal[fal_len] = entry;
                fal_len += 1;
            }
        }
    }
    init_put(0, 0x3149_4e49);
    init_inc(1);
    init_put(2, fal_len as u32);
    if let Some(&(kind, address)) = fal[..fal_len].first() {
        let lo = u32::from(address[0]) | u32::from(address[1]) << 8
            | u32::from(address[2]) << 16 | u32::from(address[3]) << 24;
        let hi = u32::from(address[4]) | u32::from(address[5]) << 8 | u32::from(kind) << 16;
        init_put(10, lo);
        init_put(11, hi);
        // First prepare of the run: the address its CONNECT_IND targeted.
        if init_get(12) == 0 && init_get(13) == 0 {
            init_put(12, lo);
            init_put(13, hi);
        }
    }
    Some(CpInitiator {
        request,
        params,
        ind_len,
        deadline_us: 0,
        accept_list: request.use_accept_list,
        fal,
        fal_len,
        resolved: None,
    })
}

/// One scan window. The CONNECT_IND is armed while the LLE is still in its RX
/// window, so the engine starts the packet at hardware T_IFS.
#[cfg(feature = "cp")]
#[link_section = ".highcode"]
#[inline(never)]
fn cp_receive_scan(
    radio: &mut Ch585Radio,
    clock: &Clock,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    conn_buf: &mut CpConnInd,
    until: u32,
    expires: u32,
    mut initiator: Option<&mut CpInitiator>,
) -> Option<CpScanPacket> {
    radio.clear_rx_status();
    let now = clock.now_us();
    if reached(now, until) || reached(now, expires) {
        return None;
    }
    let window = until.wrapping_sub(now).saturating_mul(2);
    // SAFETY: `rx` is a static DMA buffer and every path below stops the
    // engine before returning, so no window outlives this call.
    if unsafe { radio.rx_basic(clock, &mut rx.0, window) }.is_err() {
        let _ = radio.stop(clock);
        return None;
    }
    let mut capture = None;
    let crc_ok = loop {
        let status = radio.rx_state();
        let now = clock.now_us();
        if reached(now, expires) {
            let _ = radio.stop(clock);
            return None;
        }
        if status.done {
            break status.crc_ok;
        }
        if capture.is_none() && status.captured {
            radio.note_capture(now);
            capture = Some(now);
        }
        let expired = match capture {
            Some(at) => now.wrapping_sub(at) >= CP_SCAN_CAPTURE_US,
            None => reached(now, until),
        };
        if expired {
            let _ = radio.stop(clock);
            return None;
        }
    };
    let len = usize::from(rx.0[1]) + 2;
    let mut packet = CpScanPacket {
        // A header claiming more than the fixture's buffer is never parsed.
        len: if crc_ok && len <= 40 { len } else { 0 },
        crc_ok,
        peer_chsel: false,
        peer_addr: [0; 6],
        peer_random: false,
        connect_done: None,
    };
    let mut late_resolve = None;
    if crc_ok && len <= 40 {
        if let Some(init) = initiator.as_deref_mut() {
            let header = rx.0[0];
            let adv_random = header & 0x40 != 0;
            let mut adv_addr = [0u8; 6];
            adv_addr.copy_from_slice(&rx.0[2..8]);
            init_put(7, u32::from(header));
            init_put(
                8,
                u32::from(adv_addr[0])
                    | u32::from(adv_addr[1]) << 8
                    | u32::from(adv_addr[2]) << 16
                    | u32::from(adv_addr[3]) << 24,
            );
            init_put(
                9,
                u32::from(adv_addr[4])
                    | u32::from(adv_addr[5]) << 8
                    | u32::from(adv_random) << 16,
            );
            if header & 0x0f == 0 {
                init_inc(3);
            }
            let matched = if init.accept_list {
                // Policy 1 ignores Peer_Address and matches the snapshot;
                // random vs public is part of the member identity.
                let kind = u8::from(adv_random);
                let accept = &init.fal[..init.fal_len];
                if accept.iter().any(|&(k, a)| k & 1 == kind && a == adv_addr) {
                    true
                } else if adv_random {
                    // The Host writes bonded peers under their identity, so an
                    // RPA matches only through the resolving list. The lookup
                    // uses the cached resolution; a miss fills it after the
                    // window and the next advertisement connects.
                    if cp_accept_identity(accept, init.resolved, adv_addr) {
                        true
                    } else {
                        late_resolve = Some(adv_addr);
                        false
                    }
                } else {
                    false
                }
            } else {
                adv_random == init.request.peer_random && adv_addr == init.request.peer_addr
            };
            if header & 0x0f == 0 && matched {
                packet.peer_chsel = header & 0x20 != 0;
                packet.peer_addr = adv_addr;
                packet.peer_random = adv_random;
                // Policy 1: both ChSel variants were built before the AdvA was
                // known, so patch RxAdd and AdvA in place.
                if init.accept_list {
                    for ind in [0, CP_CONN_IND_CSEL_OFFSET] {
                        conn_buf.0 .0[ind + 8..ind + 14].copy_from_slice(&adv_addr);
                        if adv_random {
                            conn_buf.0 .0[ind] |= 0x80;
                        } else {
                            conn_buf.0 .0[ind] &= !0x80;
                        }
                    }
                }
                let ind = if packet.peer_chsel {
                    CP_CONN_IND_CSEL_OFFSET
                } else {
                    0
                };
                init_inc(4);
                match radio.initiate_tx(clock, &conn_buf.0 .0[ind..ind + init.ind_len]) {
                    Ok(done) => {
                        init_inc(5);
                        packet.connect_done = Some(done);
                    }
                    Err(_) => {
                        init_inc(6);
                        inc(45);
                    }
                }
            }
        }
    }
    let _ = radio.stop(clock);
    if let (Some(init), Some(address)) = (initiator, late_resolve) {
        // Outside the RX window: one AES block per peer IRK is far more than
        // the 150 us T_IFS budget allows.
        if let Some((kind, identity)) = resolve_accept_identity(address) {
            init.resolved = Some((address, kind, identity));
        }
    }
    Some(packet)
}

/// Next scan channel; the initiator covers all three advertising channels.
#[cfg(feature = "cp")]
fn cp_scan_channel(index: &mut u8) -> u8 {
    let channel = 37 + *index;
    *index = (*index + 1) % 3;
    channel
}

/// One passive-scan background fragment: feed reports to the Host, and arm the
/// prepared CONNECT_IND when the pending request's address answers.
#[cfg(feature = "cp")]
#[allow(clippy::too_many_arguments)]
fn cp_scan_fragment<F: Future>(
    radio: &mut Ch585Radio,
    clock: &Clock,
    soft: &mut SoftRunner,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    conn_buf: &mut CpConnInd,
    scan_channel: u8,
    used: [u32; 2],
    initiator: &mut Option<CpInitiator>,
    mut app: Pin<&mut F>,
    app_stats: &host::HostStats,
    finish: u32,
) -> CpScan {
    if reached(clock.now_us(), finish) {
        return CpScan::Idle;
    }
    radio.set_aa_crc(0x8e89_bed6, 0x55_5555);
    // The Host may cancel a pending creation; drop the prepared frame with it
    // so the radio never sends a CONNECT_IND for a request already failed.
    if initiator.is_some() && soft.pending_connect().is_none() {
        *initiator = None;
    }
    if initiator.is_none() {
        if let Some(request) = soft.pending_connect() {
            if let Some(mut prepared) = cp_prepare_initiator(soft, conn_buf, used, request) {
                prepared.deadline_us = clock.now_us().wrapping_add(CP_INITIATOR_TIMEOUT_US);
                *initiator = Some(prepared);
                put(2, 4);
            }
        }
    }
    if let Some(init) = initiator.as_ref() {
        if reached(clock.now_us(), init.deadline_us) {
            inc(45);
            // Expired attempt diagnosis: target (10/11) vs the last address
            // on air (8/9). Equal words mean a match-logic defect; different
            // words mean the target went stale.
            init_put(14, init_get(10));
            init_put(15, init_get(11));
            init_put(16, init_get(8));
            init_put(17, init_get(9));
            let _ = soft.connection_failed(0x3e);
            soft.clear_pending_connect();
            *initiator = None;
        }
    }
    radio.set_channel(scan_channel).unwrap();
    let now = clock.now_us();
    let until = now.wrapping_add(CP_SCAN_WINDOW_US);
    let expires = earlier(finish, until.wrapping_add(CP_SCAN_CAPTURE_US));
    let mut out = CpScan::Idle;
    if let Some(packet) = cp_receive_scan(
        radio,
        clock,
        rx,
        conn_buf,
        until,
        expires,
        initiator.as_mut(),
    ) {
        if packet.crc_ok && packet.len >= 8 && soft.scan_state().enabled {
            if let Some(pdu) = wchble::ll::scan::Pdu::parse(&rx.0[..packet.len], true) {
                if soft.push_adv_report(&pdu, 0) {
                    put(50, get(50).wrapping_add(1));
                }
            }
        }
        if let (Some(init), Some(connect_done)) = (initiator.as_ref(), packet.connect_done) {
            let mut params = init.params;
            params.chsel = packet.peer_chsel;
            // Policy 1: the peer is whoever the accept list matched, not the
            // ignored Peer_Address field.
            params.peer_addr = packet.peer_addr;
            params.peer_random = packet.peer_random;
            out = CpScan::Connect(params, connect_done);
        }
    }
    if matches!(out, CpScan::Idle) {
        let until = clock.now_us().wrapping_add(1500);
        idle(soft, app.as_mut(), app_stats, clock, earlier(finish, until));
    }
    out
}

/// X3.5 CP RF loop: one table holds the peripheral link(s) and the outbound
/// central link, while background windows alternate advertising and scanning.
#[cfg(feature = "cp")]
#[allow(clippy::too_many_arguments)]
fn cp_loop<F: Future>(
    radio: &mut Ch585Radio,
    clock: &Clock,
    soft: &mut SoftRunner,
    adv_buf: &mut DmaBuf<64>,
    rsp_buf: &mut DmaBuf<64>,
    rx: &mut DmaBuf<RX_DMA_MIN>,
    tx: &mut DmaBuf<MAX_PDU>,
    conn_buf: &mut CpConnInd,
    mut app: Pin<&mut F>,
    app_stats: &host::HostStats,
    #[cfg(feature = "secure")] store: &mut DualCopyStore<Ch585DataFlash>,
    #[cfg(feature = "secure")] att_store: &mut DualCopyStore<Ch585DataFlash>,
    started: u32,
    finish: u32,
) {
    use wchble::ll::link::central::CentralLink;
    use wchble::ll::link::cp::CpLink;
    use wchble::ll::sched::{
        BackgroundKind, BackgroundWindow, CompleteResult, Decision, EventOutcome, LinkId,
        LinkTable, WorkId,
    };
    // Advertising fragment bound, scan window plus its capture tail, and the
    // gap admitted after a switch.
    const ADV_SPAN_US: u32 = 900;
    const ADV_EXIT_US: u32 = 160;
    const SCAN_SPAN_US: u32 = CP_SCAN_WINDOW_US + CP_SCAN_CAPTURE_US + 100;
    const SCAN_EXIT_US: u32 = 160;
    const SWITCH_GUARD_US: u32 = 300;

    let mut links: LinkTable<CpLink<Ch585Aes>, 2> = LinkTable::new(SWITCH_GUARD_US);
    let mut live: [Option<(LinkId, u32)>; 2] = [None; 2];
    let mut bg_work: Option<WorkId> = None;
    let mut bg_is_scan = false;
    let mut scan_bias = false;
    let mut adv_channel = 0u8;
    let mut scan_channel = 0u8;
    // Advertising and scanning keep separate due times: an advertising
    // fragment must not throttle the scan cadence the initiator depends on.
    let mut next_adv = started;
    let mut next_scan = started;
    let mut initiator: Option<CpInitiator> = None;
    while !reached(clock.now_us(), finish) {
        if bg_work.is_none() {
            let now = clock.now_us();
            let want_scan = soft.scan_state().enabled
                || soft.pending_connect().is_some()
                || initiator.is_some();
            let want_adv = soft.ll.adv.enabled && links.len() < 2;
            let scan_due = want_scan && reached(now, next_scan);
            let adv_due = want_adv && reached(now, next_adv);
            let scan = match (adv_due, scan_due) {
                (_, false) => false,
                (false, true) => true,
                (true, true) => {
                    scan_bias = !scan_bias;
                    scan_bias
                }
            };
            if scan_due || adv_due {
                let start_us = now;
                let window = if scan {
                    BackgroundWindow {
                        kind: BackgroundKind::Scanning,
                        start_us,
                        end_us: start_us.wrapping_add(SCAN_SPAN_US),
                        exit_us: SCAN_EXIT_US,
                        priority: 0,
                    }
                } else {
                    BackgroundWindow {
                        kind: BackgroundKind::Advertising,
                        start_us,
                        end_us: start_us.wrapping_add(ADV_SPAN_US),
                        exit_us: ADV_EXIT_US,
                        priority: 0,
                    }
                };
                match links.insert_background(window, now) {
                    Ok(id) => {
                        bg_work = Some(id);
                        bg_is_scan = scan;
                    }
                    Err(_) => {
                        inc(45);
                        next_scan = now.wrapping_add(1_000);
                        next_adv = now.wrapping_add(1_000);
                    }
                }
            }
        }
        let now = clock.now_us();
        match links.select(now, finish) {
            Decision::Run { ticket, .. } => {
                if links.begin(ticket, now).is_err() {
                    let _ = links.cancel(ticket);
                    continue;
                }
                let slot = ticket.id().slot();
                let (control, served, idle) = {
                    let link = links.link_mut(ticket.id()).expect("dispatched link");
                    let mut host = wchble::hci::link::RunnerHost::for_slot(
                        slot,
                        soft,
                        Extra {
                            app: app.as_mut(),
                            app_stats,
                            clock,
                            #[cfg(feature = "secure")]
                            store,
                            #[cfg(feature = "secure")]
                            att_store,
                        },
                    );
                    let control = link.step(&mut host, radio, clock, rx, tx, ticket.hard_end_us());
                    let served = link.take_event_served();
                    (control, served, clock.now_us())
                };
                let outcome = EventOutcome::Done {
                    consumed_event: served,
                    idle_at_us: idle,
                };
                match control {
                    wchble::ll::link::Control::Continue => {
                        let _ = links.complete(ticket, outcome);
                    }
                    wchble::ll::link::Control::Closed(_) => {
                        let _ = links.complete(ticket, outcome);
                        let _ = links.remove(ticket.id());
                        live[usize::from(slot)] = None;
                        put(2, 2);
                        next_scan = clock.now_us();
                        next_adv = clock.now_us();
                    }
                    wchble::ll::link::Control::Reset => {
                        let _ = links.complete(ticket, outcome);
                        stop(radio, clock);
                        let _ = links.reset();
                        live = [None; 2];
                        initiator = None;
                        soft.clear_pending_connect();
                        soft.bridge.reset_finished();
                        if let Some(slot1) = soft.link_bridge_mut(1) {
                            slot1.reset_finished();
                        }
                        soft.reset_radio_stopped();
                        put(2, 2);
                        next_scan = clock.now_us();
                        next_adv = clock.now_us();
                    }
                    wchble::ll::link::Control::Finish => break,
                    wchble::ll::link::Control::StopTimeout => {
                        let _ = links.complete(ticket, EventOutcome::StopUnconfirmed);
                        inc(22);
                        put(2, 0xee);
                        park();
                    }
                }
            }
            Decision::RunBackground { ticket, .. } => {
                if links.begin_background(ticket, now).is_err() {
                    let _ = links.cancel_background(ticket);
                    bg_work = None;
                    inc(45);
                    next_scan = clock.now_us().wrapping_add(1_000);
                    next_adv = clock.now_us().wrapping_add(1_000);
                    continue;
                }
                let mut connected = None;
                if bg_is_scan {
                    let channel = cp_scan_channel(&mut scan_channel);
                    if let CpScan::Connect(params, end) = cp_scan_fragment(
                        radio,
                        clock,
                        soft,
                        rx,
                        conn_buf,
                        channel,
                        [
                            live[0].map_or(0, |(_, aa)| aa),
                            live[1].map_or(0, |(_, aa)| aa),
                        ],
                        &mut initiator,
                        app.as_mut(),
                        app_stats,
                        finish,
                    ) {
                        connected = Some((params, end));
                    }
                } else {
                    let channel = pp_adv_channel(soft, &mut adv_channel);
                    match pp_adv_fragment(
                        radio,
                        clock,
                        soft,
                        channel,
                        adv_buf,
                        rsp_buf,
                        rx,
                        app.as_mut(),
                        app_stats,
                        #[cfg(feature = "secure")]
                        store,
                        #[cfg(feature = "secure")]
                        att_store,
                        finish,
                    ) {
                        PpAdv::Connect(params, end) => connected = Some((params, end)),
                        PpAdv::Finished => break,
                        _ => {}
                    }
                }
                let idle = clock.now_us();
                if let Ok(CompleteResult::Overrun { .. }) = links.complete_background(
                    ticket,
                    EventOutcome::Done {
                        consumed_event: false,
                        idle_at_us: idle,
                    },
                ) {
                    inc(34);
                }
                bg_work = None;
                if bg_is_scan {
                    put(48, get(48).wrapping_add(1));
                } else {
                    // 43 is outside the engine and trace slots; 40 is the
                    // trace-overflow counter and 44 the max-connection time.
                    put(43, get(43).wrapping_add(1));
                }
                inc(46);
                if bg_is_scan {
                    next_scan = clock.now_us().wrapping_add(1_000);
                } else {
                    let interval_us = soft.adv_interval_us();
                    next_adv = clock.now_us().wrapping_add(interval_us);
                }
                if let Some((params, end)) = connected {
                    if bg_is_scan {
                        // Outbound Central: the Host asked for this address.
                        soft.clear_pending_connect();
                        initiator = None;
                        radio.set_aa_crc(params.access_addr, params.crc_init);
                        let central = CentralLink::new(params, end, clock.now_us(), LOCAL_FEATURES);
                        match links.insert(CpLink::central(central)) {
                            Ok(id) => {
                                live[usize::from(id.slot())] = Some((id, params.access_addr));
                                put(2, 3);
                            }
                            Err(_) => {
                                inc(33);
                                let _ = soft.connection_failed(0x3e);
                                put(2, 2);
                            }
                        }
                    } else {
                        let mut enc_rsp_random = [0u8; 12];
                        soft.fill_random(&mut enc_rsp_random);
                        let mut s = Session::new(
                            params,
                            soft.ll.adv.chsel,
                            end,
                            clock.now_us(),
                            enc_rsp_random,
                            LOCAL_FEATURES,
                        );
                        if let Some((octets, time)) = soft.suggested_data_length_explicit() {
                            s.set_suggested_data_length(octets, time);
                        }
                        let (pref_tx, pref_rx) = soft.default_phy();
                        s.set_phy_prefs(pref_tx, pref_rx);
                        put(49, s.event_start_us());
                        radio.set_aa_crc(params.access_addr, params.crc_init);
                        match links.insert(CpLink::peripheral(s)) {
                            Ok(id) => {
                                live[usize::from(id.slot())] = Some((id, params.access_addr));
                                put(2, 3);
                            }
                            Err(_) => {
                                inc(33);
                                put(2, 2);
                            }
                        }
                    }
                }
            }
            Decision::Skipped { .. } => {
                inc(47);
            }
            Decision::BackgroundMissed { .. } => {
                bg_work = None;
                inc(45);
                next_scan = clock.now_us().wrapping_add(1_000);
                next_adv = clock.now_us().wrapping_add(1_000);
            }
            Decision::Close { id, reason, .. } => {
                stop(radio, clock);
                let _ = links.remove(id);
                live[usize::from(id.slot())] = None;
                soft.close_link_slot(id.slot(), reason);
                #[cfg(feature = "secure")]
                flush_bonds(store, att_store, clock, None);
                put(2, 2);
                next_scan = clock.now_us();
                next_adv = clock.now_us();
            }
            Decision::Invalid { id, .. } => {
                stop(radio, clock);
                let _ = links.remove(id);
                live[usize::from(id.slot())] = None;
                soft.close_link_slot(id.slot(), 0x3e);
                #[cfg(feature = "secure")]
                flush_bonds(store, att_store, clock, None);
                put(2, 2);
            }
            Decision::Busy { .. } => {
                idle(
                    soft,
                    app.as_mut(),
                    app_stats,
                    clock,
                    clock.now_us().wrapping_add(100),
                );
            }
            Decision::Idle { until_us } => {
                #[cfg(feature = "secure")]
                flush_bonds(store, att_store, clock, None);
                idle(
                    soft,
                    app.as_mut(),
                    app_stats,
                    clock,
                    earlier(finish, until_us),
                );
            }
            Decision::Budget => break,
            Decision::Faulted => {
                inc(22);
                put(2, 0xee);
                park();
            }
            Decision::Exhausted => break,
        }
        if links.is_empty() {
            let request = soft
                .bridge
                .take_radio_request()
                .or_else(|| soft.link_bridge_mut(1).and_then(|b| b.take_radio_request()));
            if let Some(request) = request {
                match request {
                    RadioRequest::Reset => {
                        stop(radio, clock);
                        soft.bridge.reset_finished();
                        if let Some(slot1) = soft.link_bridge_mut(1) {
                            slot1.reset_finished();
                        }
                        soft.reset_radio_stopped();
                        live = [None; 2];
                        initiator = None;
                        soft.clear_pending_connect();
                        put(2, 2);
                        next_scan = clock.now_us();
                        next_adv = clock.now_us();
                    }
                    RadioRequest::Disconnect { reason } => diag_disconnect(reason),
                }
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
    put(0, 0x5034_3538);
    put(1, 1);
    put(2, 1);
    put(35, hz);
    sec_put(0, SEC_MAGIC);
    sec_put(1, 1);
    let scratch = SCRATCH.init(DmaBuf::zeroed());
    let rx = RX.init(DmaBuf::zeroed());
    let adv_buf = ADV.init(DmaBuf::zeroed());
    // The beacon never answers a scan request, so `rsp_buf` is unused there.
    #[cfg_attr(feature = "x2-ext-adv", allow(unused_variables))]
    let rsp_buf = RSP.init(DmaBuf::zeroed());
    #[cfg(feature = "x2-ext-adv")]
    let aux_buf = EXT_AUX.init(DmaBuf::zeroed());
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
    // X3 decision A: two-link builds (pp or cp) advertise half the physical
    // credit pool so the Host cannot overcommit the TX slots.
    #[cfg(any(feature = "pp", feature = "cp"))]
    soft.set_acl_credits_report(2);
    // The pp table is a different database; give it its own on-air identity so
    // a peer's cached GATT handles cannot cross the two layouts.
    #[cfg(any(feature = "pp", feature = "cp"))]
    let peripheral_address = host::PP_RANDOM_ADDRESS;
    #[cfg(not(any(feature = "pp", feature = "cp")))]
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
    #[allow(unused_mut, unused_variables)]
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
            Ok(Some(len)) => {
                match decode_bonds(&payload[..len], &bond::local_identity(), &mut boot_bonds) {
                    Ok(Some(decoded)) => {
                        local_irk = decoded.local_irk;
                        bond::set(bond::STAT_LOAD_RESULT, bond::LOAD_VALID);
                        bond::set(bond::STAT_RECORDS_LOADED, decoded.bonds.len() as u32);
                        bond::set(
                            bond::STAT_WINNER_SLOT,
                            store.active_slot().unwrap_or(0) as u32,
                        );
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
                }
            }
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
        // S4: decide the local IRK before the Host is built. An unreadable or
        // foreign slot blocks writes; an IRK that cannot be persisted is not
        // used, so it is never handed to a peer and then lost.
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
    #[cfg(feature = "hogp")]
    hogp::init();
    set_peripheral_address(&peripheral_address);
    #[cfg(feature = "pp")]
    let mut app = core::pin::pin!(pp::run(controller, &app_stats));
    #[cfg(feature = "cp")]
    let mut app = core::pin::pin!(cp::run(controller, &app_stats));
    #[cfg(all(feature = "x2-ext-adv", not(any(feature = "pp", feature = "cp"))))]
    let mut app = core::pin::pin!(beacon::run(controller, &app_stats, peripheral_address));
    #[cfg(not(any(feature = "pp", feature = "cp", feature = "x2-ext-adv")))]
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
    #[cfg(not(any(feature = "pp", feature = "cp")))]
    let mut session: Option<Session> = None;
    #[cfg(not(any(feature = "pp", feature = "cp")))]
    let mut next_adv = started;
    put(2, 2);
    #[cfg(feature = "pp")]
    {
        pp_loop(
            &mut radio,
            &clock,
            &mut soft,
            adv_buf,
            rsp_buf,
            rx,
            data,
            #[cfg(feature = "x2-ext-adv-coex")]
            aux_buf,
            app.as_mut(),
            &app_stats,
            #[cfg(feature = "secure")]
            &mut store,
            #[cfg(feature = "secure")]
            &mut att_store,
            started,
            finish,
        );
    }
    #[cfg(feature = "cp")]
    {
        let conn_buf = CP_CONN_IND.init(CpConnInd(DmaBuf::zeroed()));
        cp_loop(
            &mut radio,
            &clock,
            &mut soft,
            adv_buf,
            rsp_buf,
            rx,
            data,
            conn_buf,
            app.as_mut(),
            &app_stats,
            #[cfg(feature = "secure")]
            &mut store,
            #[cfg(feature = "secure")]
            &mut att_store,
            started,
            finish,
        );
    }
    #[cfg(not(any(feature = "pp", feature = "cp")))]
    // X2a: round counter feeding the aux-channel rotation, plus the enable
    // edge that seeds the duration countdown.
    #[cfg(feature = "x2-ext-adv")]
    let mut ext_round: u32 = 0;
    #[cfg(feature = "x2-ext-adv")]
    let mut ext_seen_enabled = false;
    #[cfg(not(any(feature = "pp", feature = "cp")))]
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
        // Controller-side readiness: every boot peer's IRK must be loaded
        // before the Host is allowed to advertise as a resolvable address.
        #[cfg(feature = "privacy")]
        bond::signals().rl_ready.set(
            bond::rl_expected()
                .iter()
                .all(|&(kind, address, irk)| soft.privacy_has_peer(kind, address, &irk)),
        );
        #[cfg(feature = "x2-ext-adv")]
        let idle_until = if soft.ll.ext_adv.enabled && !reached(now, next_adv) {
            next_adv
        } else {
            now.wrapping_add(3000)
        };
        #[cfg(not(feature = "x2-ext-adv"))]
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
        // X2a beacon: one extended advertising event per interval, three
        // primary channels each pointing at its own AUX_ADV_IND.
        #[cfg(feature = "x2-ext-adv")]
        {
            if !soft.ll.ext_adv.enabled || !reached(clock.now_us(), next_adv) {
                continue;
            }
            // Seed the duration countdown once per enable.
            if !ext_seen_enabled {
                soft.ext_adv_started(clock.now_us());
                ext_seen_enabled = true;
            }
            ext_adv_event(
                &mut radio,
                &clock,
                &soft.ll.ext_adv,
                &mut ext_round,
                None,
                adv_buf,
                aux_buf,
            );
            ext_put(EXT_DID, u32::from(soft.ll.ext_adv.did));
            ext_put(EXT_DATA_LEN, soft.ll.ext_adv.data_len as u32);
            if soft.ext_adv_round_done(clock.now_us()) {
                // Duration or event cap ended the set; the Terminated event
                // is already queued on the bridge.
                ext_inc(EXT_TERMINATED);
                ext_seen_enabled = false;
            } else {
                ext_inc(EXT_EVENTS);
            }
            next_adv = clock
                .now_us()
                .wrapping_add(u32::from(soft.ll.ext_adv.interval_slots) * 625);
            continue;
        }
        #[cfg(not(feature = "x2-ext-adv"))]
        if !soft.adv_enabled() || !reached(clock.now_us(), next_adv) {
            continue;
        }
        #[cfg(not(feature = "x2-ext-adv"))]
        {
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
                                    // S4b rejected this initiator: no CONNECT_IND
                                    // goes back, so the link is never established.
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
                            let (pref_tx, pref_rx) = soft.default_phy();
                            s.set_phy_prefs(pref_tx, pref_rx);
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
    }
    stop(&mut radio, &clock);
    // A pairing that completed in the last event may still be pending.
    #[cfg(feature = "secure")]
    flush_bonds(&mut store, &mut att_store, &clock, None);
    host_snapshot(&app_stats);
    #[cfg(feature = "privacy")]
    privacy::publish(&soft);
    put(32, clock.now_us().wrapping_sub(started));
    // Under `pp`, 33/34 hold the loop's acceptance counters; the legacy
    // CMD/MODE snapshot would clobber them at the end of the run.
    #[cfg(not(any(feature = "pp", feature = "cp")))]
    put(33, reg(LLE_BASE, lle::CMD));
    #[cfg(not(any(feature = "pp", feature = "cp")))]
    put(34, reg(LLE_BASE, lle::MODE));
    put(2, 9);
    park();
}
