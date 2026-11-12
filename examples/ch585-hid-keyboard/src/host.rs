//! HID-over-GATT (HOGP) keyboard on the same Trouble Host poll as S2/S3.
//!
//! The RF/Host plumbing is the ch585-trouble-gatt pump copied verbatim; only
//! this module differs. Reports are emitted from a one-second timer tick, not
//! from a connection event, so a subscribed host sees a deterministic key
//! sequence without depending on other GATT traffic. Under `secure` the
//! reports only leave once the link is encrypted.

use core::cell::Cell;
use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Instant, Timer};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use trouble_host::prelude::*;

pub const LOCAL_NAME: &[u8] = b"wch585-hid";

// New static identity: macOS and Android cache a peer's GATT layout by
// address, and the P4/P5 databases do not contain a HID service. The address
// is fixed across boots so the S3 bond store can answer the peer's old LTK.
pub const RANDOM_ADDRESS: [u8; 6] = [0x17, 0x00, 0x00, 0xee, 0xff, 0xc1];

/// Appearance 0x03C1: Human Interface Device / Keyboard.
const APPEARANCE: u16 = 0x03C1;

/// Bond capacity of the Host. Matches `storage::bond::MAX_BONDS` so the stored
/// list always fits the Host's in-memory table.
#[cfg(feature = "secure")]
const BOND_CAPACITY: usize = crate::bond::MAX_BONDS;
#[cfg(not(feature = "secure"))]
const BOND_CAPACITY: usize = 10;

// HOGP requires report access on an encrypted link. The plain build keeps the
// same service readable so the GATT table can be exercised without a bond.
#[cfg(feature = "secure")]
const HID_PERMISSION: PermissionLevel = PermissionLevel::EncryptionRequired;
#[cfg(not(feature = "secure"))]
const HID_PERMISSION: PermissionLevel = PermissionLevel::Allowed;

/// Vendor control characteristic carrying the S3 bond commands (`DEL!`,
/// `WIPE`, `FALT`). Separate UUID from the P4/P5 vendor service so a phone
/// never confuses the two GATT layouts.
#[cfg(feature = "secure")]
pub const CONTROL_SERVICE_UUID: Uuid =
    Uuid::new_long(0x00001a00_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
#[cfg(feature = "secure")]
pub const BOND_CONTROL_UUID: Uuid =
    Uuid::new_long(0x00001a01_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
/// Diagnostic mirror of the HID input report. Apple's Accessory Design
/// Guidelines (GATT Server section) filter the BLE HID service out of
/// CoreBluetooth discovery, so no macOS app can subscribe to 0x2A4D. This
/// characteristic carries the same bytes on the same encrypted link for the
/// automated harness; it is not part of HOGP and HOGP hosts ignore it.
#[cfg(feature = "secure")]
pub const MIRROR_UUID: Uuid =
    Uuid::new_long(0x00001a02_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());

// HID Information: bcdHID 0x0111, country code 0, remote wake supported.
const HID_INFORMATION: [u8; 4] = [0x11, 0x01, 0x00, 0x01];

// Boot keyboard report map from the vendor `HID_Keyboard` example
// (CH585EVT/EXAM/BLE/HID_Keyboard/Profile/hidkbdservice.c): 8 modifier bits,
// one reserved byte, five LED bits plus three padding bits, six key bytes.
const REPORT_MAP: [u8; 63] = [
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01,
    0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06,
    0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xc0,
];

// Report Reference values: [report ID, report type]. Type 1 = input,
// type 2 = output. The boot reports reuse the same IDs and map, as in the
// vendor example.
const REPORT_REF_INPUT: [u8; 2] = [0x00, 0x01];
const REPORT_REF_OUTPUT: [u8; 2] = [0x00, 0x02];

const REPORT_INTERVAL_MS: u64 = 1_000;
/// Keys 'a'..'d' (HID usage 0x04..0x07), each pressed and released. The host
/// receives this exact cycle, so the client can assert bytes, not just counts.
const REPORT_CYCLE: [[u8; 8]; 8] = [
    [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00],
    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// Protocol Mode value: 1 = report protocol, 0 = boot protocol.
const PROTOCOL_REPORT: u8 = 1;

pub const HOST_STATS_WORDS: usize = 16;
pub const STAT_PHASE: usize = 0;
pub const STAT_CONNECTIONS: usize = 1;
pub const STAT_DISCONNECTS: usize = 2;
// Layout constant for both builds; only the secure build writes it.
#[allow(dead_code)]
pub const STAT_SECURITY: usize = 3;
pub const STAT_ERRORS: usize = 4;
pub const STAT_LAST_ERROR: usize = 5;
pub const STAT_ADVERTISE_ATTEMPTS: usize = 6;

#[cfg(feature = "secure")]
pub const SECURITY_REQUESTED: u32 = 1;
#[cfg(feature = "secure")]
pub const SECURITY_PAIRED: u32 = 2;
#[cfg(feature = "secure")]
pub const SECURITY_ENCRYPTED: u32 = 3;
#[cfg(feature = "secure")]
pub const SECURITY_FAILED: u32 = 4;

pub const PHASE_STARTING: u32 = 1;
pub const PHASE_ADVERTISING: u32 = 2;
pub const PHASE_CONNECTED: u32 = 3;
pub const PHASE_FATAL: u32 = 0xff;

/// HID evidence buffer, read over SWD by `tools/hid_run.py`.
pub const HID_STATS_WORDS: usize = 16;
pub const HID_MAGIC: u32 = 0x4849_4431;
pub const HID_VERSION: u32 = 1;
pub const HID_REPORTS_SENT: usize = 2;
pub const HID_NOTIFY_ERRORS: usize = 3;
pub const HID_SUBSCRIPTION_EDGES: usize = 4;
pub const HID_LED_WRITES: usize = 5;
pub const HID_LED_VALUE: usize = 6;
pub const HID_CONTROL_POINT_WRITES: usize = 7;
pub const HID_CONTROL_POINT_LAST: usize = 8;
pub const HID_PROTOCOL_MODE: usize = 9;
pub const HID_PROTOCOL_MODE_WRITES: usize = 10;
pub const HID_BOOT_INPUT_SENT: usize = 11;
pub const HID_REPORT_MAP_READS: usize = 12;
pub const HID_INFO_READS: usize = 13;
pub const HID_BLOCKED_UNENCRYPTED: usize = 14;
pub const HID_LAST_ERROR: usize = 15;

#[no_mangle]
static mut HID_STATS: [u32; HID_STATS_WORDS] = [0; HID_STATS_WORDS];

fn hid_put(index: usize, value: u32) {
    // SAFETY: single-threaded example; only the Host poll writes HID_STATS.
    unsafe {
        core::ptr::addr_of_mut!(HID_STATS)
            .cast::<u32>()
            .add(index)
            .write_volatile(value)
    }
}

fn hid_get(index: usize) -> u32 {
    // SAFETY: single-threaded example; only the Host poll reads HID_STATS.
    unsafe {
        core::ptr::addr_of!(HID_STATS)
            .cast::<u32>()
            .add(index)
            .read_volatile()
    }
}

fn hid_inc(index: usize) {
    hid_put(index, hid_get(index).wrapping_add(1));
}

/// Read a HID counter. The firmware runner uses the exported symbol; the
/// native host fixture uses this hook.
#[allow(dead_code)]
pub fn hid_word(index: usize) -> u32 {
    hid_get(index)
}

/// Debug text of the error that ended the Host runner. Word 0 is the byte
/// count; words 1.. carry the UTF-8 bytes little-endian, so the runner can
/// read the reason back over SWD without an allocator.
pub const HOST_ERROR_WORDS: usize = 32;
#[no_mangle]
pub static mut HOST_ERROR: [u32; HOST_ERROR_WORDS] = [0; HOST_ERROR_WORDS];

struct ErrorSink;

impl core::fmt::Write for ErrorSink {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        // SAFETY: signal-free single-threaded example; only the Host poll writes here.
        let words = unsafe { &mut *core::ptr::addr_of_mut!(HOST_ERROR) };
        let capacity = (HOST_ERROR_WORDS - 1) * 4;
        let mut length = words[0] as usize;
        for &byte in text.as_bytes() {
            if length == capacity {
                break;
            }
            words[1 + length / 4] |= u32::from(byte) << ((length % 4) * 8);
            length += 1;
        }
        words[0] = length as u32;
        Ok(())
    }
}

/// Main owns this value next to the pinned future; only that thread accesses it.
pub struct HostStats {
    words: [Cell<u32>; HOST_STATS_WORDS],
}

impl HostStats {
    pub const fn new() -> Self {
        Self {
            words: [const { Cell::new(0) }; HOST_STATS_WORDS],
        }
    }

    pub fn word(&self, index: usize) -> u32 {
        self.words.get(index).map_or(0, Cell::get)
    }

    fn set(&self, index: usize, value: u32) {
        self.words[index].set(value);
    }

    fn inc(&self, index: usize) {
        self.set(index, self.word(index).wrapping_add(1));
    }

    fn phase(&self, phase: u32) {
        if self.word(STAT_PHASE) != PHASE_FATAL {
            self.set(STAT_PHASE, phase);
        }
    }

    fn error(&self, stage: u32) {
        self.inc(STAT_ERRORS);
        self.set(STAT_LAST_ERROR, stage);
    }
}

async fn fatal(stats: &HostStats, stage: u32) -> ! {
    stats.error(stage);
    stats.set(STAT_PHASE, PHASE_FATAL);
    match pending::<Infallible>().await {}
}

/// Local HID bookkeeping; reset for every connection.
struct HidState {
    seq: usize,
    subscribed: bool,
    protocol_mode: u8,
}

impl HidState {
    fn new() -> Self {
        Self {
            seq: 0,
            subscribed: false,
            protocol_mode: PROTOCOL_REPORT,
        }
    }
}

/// Report scheduling state and the notifying characteristic handles.
/// `run` drives this from the connection loop; the pending report is sent on
/// the timer tick, never inside a connection event.
pub async fn run(
    controller: wchble::hci::SoftController,
    stats: &HostStats,
    address: [u8; 6],
) -> ! {
    stats.phase(PHASE_STARTING);
    hid_put(0, HID_MAGIC);
    hid_put(1, HID_VERSION);
    hid_put(HID_PROTOCOL_MODE, u32::from(PROTOCOL_REPORT));
    // One connection; ATT and the LE signaling channel, with no dynamic channels.
    let mut resources: HostResources<DefaultPacketPool, 1, 2, 1, BOND_CAPACITY> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(address))
        .build();
    // Restore bonds before advertising: the stack answers a peer's LTK request
    // from this table, so a rebooted device can resume encryption instead of
    // pairing again.
    #[cfg(feature = "secure")]
    for record in crate::bond::boot_bonds() {
        match stack.add_bond_information(crate::bond::to_bond(record)) {
            Ok(()) => crate::bond::bump(crate::bond::STAT_ADD_BOND_OK),
            Err(_) => crate::bond::bump(crate::bond::STAT_ADD_BOND_FAIL),
        }
    }
    // Remove every in-memory bond; the RF owner erases the flash copy after
    // the Host has dropped them.
    #[cfg(feature = "secure")]
    let remove_all_bonds = || {
        let identities = stack.with_bond_information(|bonds| {
            let mut list = heapless::Vec::<Identity, BOND_CAPACITY>::new();
            for bond in bonds {
                let _ = list.push(bond.identity);
            }
            list
        });
        for identity in identities {
            if stack.remove_bond_information(identity).is_ok() {
                crate::bond::bump(crate::bond::STAT_IN_MEMORY_REMOVED);
            }
        }
    };
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();

    let appearance = APPEARANCE.to_le_bytes();
    let mut protocol_mode_storage = [PROTOCOL_REPORT];
    let mut control_point_storage = [0u8; 1];
    let mut input_storage = [0u8; 8];
    let mut output_storage = [0u8; 1];
    let mut boot_input_storage = [0u8; 8];
    let mut boot_output_storage = [0u8; 1];
    #[cfg(feature = "secure")]
    let mut bond_control_storage = [0u8; 4];
    #[cfg(feature = "secure")]
    let mut mirror_storage = [0u8; 8];
    // GAP + GATT + DIS + HID + vendor control. `AttributeTable::push` panics
    // on overflow at the first poll, so the capacity is stated once here and
    // mirrored by the server's const generic below.
    let mut table: AttributeTable<'_, NoopRawMutex, 64> = AttributeTable::new();
    let mut gap = table.add_service(Service::new(0x1800u16));
    gap.add_characteristic_ro(0x2a00u16, LOCAL_NAME);
    gap.add_characteristic_ro(0x2a01u16, &appearance);
    gap.build();
    table.add_service(Service::new(0x1801u16)).build();

    // Standard Device Information Service, read-only so a client can identify
    // this build without any vendor-specific schema.
    let mut info = table.add_service(Service::new(0x180Au16));
    info.add_characteristic_ro(0x2a29u16, "wchble");
    info.add_characteristic_ro(0x2a24u16, "ch585-hid-keyboard");
    info.add_characteristic_ro(0x2a26u16, "x4b-0.1");
    info.build();

    // Standard HID service. Info/Map/Control Point/Protocol Mode are shared by
    // report and boot protocols; the two 0x2A4D characteristics are told apart
    // by their Report Reference descriptors.
    let mut hid = table.add_service(Service::new(0x1812u16));
    // HID Information and the Report Map carry no secret: HOGP hosts read
    // them while bonding, and a host that claims the HID service internally
    // (Apple) otherwise stalls its discovery on Insufficient Authentication.
    let hid_info: Characteristic<[u8; 4]> = hid
        .add_characteristic_ro(0x2a4au16, &HID_INFORMATION)
        .read_permission(PermissionLevel::Allowed)
        .build();
    let report_map: Characteristic<[u8; 63]> = hid
        .add_characteristic_ro(0x2a4bu16, &REPORT_MAP)
        .read_permission(PermissionLevel::Allowed)
        .build();
    let control_point: Characteristic<u8> = hid
        .add_characteristic(
            0x2a4cu16,
            &[CharacteristicProp::WriteWithoutResponse],
            0u8,
            &mut control_point_storage,
        )
        .write_permission(HID_PERMISSION)
        .build();
    let protocol_mode: Characteristic<u8> = hid
        .add_characteristic(
            0x2a4eu16,
            &[
                CharacteristicProp::Read,
                CharacteristicProp::WriteWithoutResponse,
            ],
            PROTOCOL_REPORT,
            &mut protocol_mode_storage,
        )
        .read_permission(HID_PERMISSION)
        .write_permission(HID_PERMISSION)
        .build();
    let mut input_builder = hid
        .add_characteristic(
            0x2a4du16,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            [0u8; 8],
            &mut input_storage,
        )
        .read_permission(HID_PERMISSION)
        .cccd_permission(HID_PERMISSION);
    // The Report Reference carries no secret, and a HOGP host may read it
    // before bonding: keep descriptor discovery unencrypted even under secure.
    input_builder.add_descriptor_ro(0x2908u16, PermissionLevel::Allowed, &REPORT_REF_INPUT);
    let input_report: Characteristic<[u8; 8]> = input_builder.build();
    let mut output_builder = hid
        .add_characteristic(
            0x2a4du16,
            &[
                CharacteristicProp::Read,
                CharacteristicProp::Write,
                CharacteristicProp::WriteWithoutResponse,
            ],
            [0u8; 1],
            &mut output_storage,
        )
        .read_permission(HID_PERMISSION)
        .write_permission(HID_PERMISSION);
    output_builder.add_descriptor_ro(0x2908u16, PermissionLevel::Allowed, &REPORT_REF_OUTPUT);
    let output_report: Characteristic<[u8; 1]> = output_builder.build();
    let boot_input: Characteristic<[u8; 8]> = hid
        .add_characteristic(
            0x2a22u16,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            [0u8; 8],
            &mut boot_input_storage,
        )
        .read_permission(HID_PERMISSION)
        .cccd_permission(HID_PERMISSION)
        .build();
    let boot_output: Characteristic<[u8; 1]> = hid
        .add_characteristic(
            0x2a32u16,
            &[CharacteristicProp::Read, CharacteristicProp::Write],
            [0u8; 1],
            &mut boot_output_storage,
        )
        .read_permission(HID_PERMISSION)
        .write_permission(HID_PERMISSION)
        .build();
    hid.build();

    // Secure-only bond control: `DEL!` removes the bond and writes a tombstone,
    // `WIPE` erases both slots, `FALT` truncates the next save. Deliberately
    // unauthenticated: the peer has to be able to erase a bond it cannot use.
    #[cfg(feature = "secure")]
    let (bond_control, mirror): (Characteristic<[u8; 4]>, Characteristic<[u8; 8]>) = {
        let mut control = table.add_service(Service::new(CONTROL_SERVICE_UUID));
        let characteristic = control
            .add_characteristic(
                BOND_CONTROL_UUID,
                &[CharacteristicProp::Write],
                [0u8; 4],
                &mut bond_control_storage,
            )
            .build();
        let channel = control
            .add_characteristic(
                MIRROR_UUID,
                &[CharacteristicProp::Read, CharacteristicProp::Notify],
                [0u8; 8],
                &mut mirror_storage,
            )
            .read_permission(HID_PERMISSION)
            .cccd_permission(HID_PERMISSION)
            .build();
        control.build();
        (characteristic, channel)
    };
    let server = AttributeServer::<NoopRawMutex, DefaultPacketPool, 64, 1>::new(table);

    let runner_task = async {
        use core::fmt::Write;
        if let Err(error) = runner.run().await {
            let _ = write!(ErrorSink, "{error:?}");
        }
        fatal(stats, 1).await;
    };
    let app_task = async {
        let mut adv_data = [0u8; 31];
        let hid_uuids = [[0x12u8, 0x18u8]];
        // Android commonly receives only ADV_IND, so the name and the HID
        // service UUID have to be in the advertising data itself.
        let adv_structures = [
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteServiceUuids16(&hid_uuids),
            AdStructure::Unknown {
                ty: 0x19,
                data: &appearance,
            },
            AdStructure::CompleteLocalName(LOCAL_NAME),
        ];
        let adv_len = match AdStructure::encode_slice(&adv_structures, &mut adv_data) {
            Ok(len) => len,
            Err(_) => fatal(stats, 2).await,
        };
        let mut scan_data = [0u8; 31];
        let scan_len = match AdStructure::encode_slice(
            &[AdStructure::CompleteLocalName(LOCAL_NAME)],
            &mut scan_data,
        ) {
            Ok(len) => len,
            Err(_) => fatal(stats, 3).await,
        };

        loop {
            stats.phase(PHASE_ADVERTISING);
            stats.inc(STAT_ADVERTISE_ATTEMPTS);
            let acceptor = match peripheral
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..adv_len],
                        scan_data: &scan_data[..scan_len],
                    },
                )
                .await
            {
                Ok(acceptor) => acceptor,
                Err(_) => fatal(stats, 4).await,
            };
            let connection = match acceptor.accept().await {
                Ok(connection) => connection,
                Err(_) => fatal(stats, 5).await,
            };
            // Bonding: without the bonding bit Android's SMP takes its
            // non-bonding path and never follows LL_ENC_RSP with
            // LL_START_ENC_REQ.
            #[cfg(feature = "secure")]
            if connection.set_bondable(true).is_err() {
                fatal(stats, 16).await;
            }
            let connection = match connection.with_attribute_server(&server) {
                Ok(connection) => connection,
                Err(_) => fatal(stats, 6).await,
            };
            stats.inc(STAT_CONNECTIONS);
            stats.phase(PHASE_CONNECTED);
            // The GATT table outlives a connection: a peer that left it in
            // boot protocol would otherwise poison the next connection.
            if connection.set(&protocol_mode, &PROTOCOL_REPORT).is_err() {
                fatal(stats, 18).await;
            }
            hid_put(HID_PROTOCOL_MODE, u32::from(PROTOCOL_REPORT));
            // The peripheral Security Request is what makes macOS show its
            // pairing prompt before the app touches an encrypted attribute.
            // It must not race an app-initiated pairing: Android aborts SMP
            // when a Security Request arrives while it is already pairing, so
            // only send it once the central's own flow had ample time.
            #[cfg(feature = "secure")]
            let mut security_deadline = Some(Instant::now() + Duration::from_millis(10_000));
            let mut hid_state = HidState::new();
            let mut next_report_at = Instant::now();

            loop {
                // Report tick. It runs between connection events: the Host
                // task is polled cooperatively by the RF pump, so awaiting the
                // notification here never touches a radio deadline.
                if Instant::now() >= next_report_at {
                    next_report_at = Instant::now() + Duration::from_millis(REPORT_INTERVAL_MS);
                    #[cfg(feature = "secure")]
                    let encrypted = matches!(
                        connection.raw().security_level(),
                        Ok(SecurityLevel::Encrypted)
                    );
                    #[cfg(not(feature = "secure"))]
                    let encrypted = true;
                    // Diagnostic only: with encryption-required CCCDs a
                    // subscribed link is already encrypted, so this counts
                    // ticks spent on a plain link, not lost reports.
                    if !encrypted {
                        hid_inc(HID_BLOCKED_UNENCRYPTED);
                    }
                    let boot = hid_state.protocol_mode == 0;
                    let hid_subscribed = if boot {
                        boot_input.should_notify(&connection)
                    } else {
                        input_report.should_notify(&connection)
                    };
                    // The diagnostic mirror is subscribed by the macOS harness,
                    // which cannot see the HID service through CoreBluetooth.
                    #[cfg(feature = "secure")]
                    let mirror_subscribed = mirror.should_notify(&connection);
                    #[cfg(not(feature = "secure"))]
                    let mirror_subscribed = false;
                    let subscribed = hid_subscribed || mirror_subscribed;
                    if subscribed && !hid_state.subscribed {
                        hid_state.seq = 0;
                        hid_inc(HID_SUBSCRIPTION_EDGES);
                    }
                    hid_state.subscribed = subscribed;
                    if subscribed && encrypted {
                        let bytes = REPORT_CYCLE[hid_state.seq % REPORT_CYCLE.len()];
                        let mut sent_any = false;
                        if hid_subscribed {
                            // `try_` keeps the Host poll non-blocking: a full
                            // queue is counted and the same report is retried
                            // on the next tick.
                            let sent = if boot {
                                boot_input.try_notify_raw(&connection, &bytes, false)
                            } else {
                                input_report.try_notify_raw(&connection, &bytes, false)
                            };
                            match sent {
                                Ok(()) => {
                                    if boot {
                                        hid_inc(HID_BOOT_INPUT_SENT);
                                    } else {
                                        hid_inc(HID_REPORTS_SENT);
                                    }
                                    sent_any = true;
                                }
                                Err(_) => {
                                    hid_inc(HID_NOTIFY_ERRORS);
                                    hid_put(HID_LAST_ERROR, 1);
                                }
                            }
                        }
                        #[cfg(feature = "secure")]
                        if mirror_subscribed {
                            match mirror.try_notify_raw(&connection, &bytes, false) {
                                Ok(()) => sent_any = true,
                                Err(_) => {
                                    hid_inc(HID_NOTIFY_ERRORS);
                                    hid_put(HID_LAST_ERROR, 2);
                                }
                            }
                        }
                        if sent_any {
                            hid_state.seq = (hid_state.seq + 1) % REPORT_CYCLE.len();
                        }
                    } else {
                        hid_state.seq = 0;
                    }
                }

                #[cfg(feature = "secure")]
                if security_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    security_deadline = None;
                    let unencrypted = matches!(
                        connection.raw().security_level(),
                        Ok(SecurityLevel::NoEncryption)
                    );
                    if unencrypted {
                        match connection.raw().request_security() {
                            Ok(()) => stats.set(STAT_SECURITY, SECURITY_REQUESTED),
                            Err(_) => {
                                stats.error(14);
                                stats.set(STAT_SECURITY, SECURITY_FAILED);
                            }
                        }
                    }
                }

                // The deadline also bounds the report timer, so the tick above
                // is never delayed past its interval by a long select.
                #[cfg(feature = "secure")]
                let deadline = match security_deadline {
                    Some(deadline) if deadline < next_report_at => deadline,
                    _ => next_report_at,
                };
                #[cfg(not(feature = "secure"))]
                let deadline = next_report_at;
                let event = match select(connection.next(), Timer::at(deadline)).await {
                    Either::First(event) => Some(event),
                    Either::Second(()) => None,
                };
                let Some(event) = event else {
                    continue;
                };
                match event {
                    GattConnectionEvent::Disconnected { .. } => {
                        stats.inc(STAT_DISCONNECTS);
                        break;
                    }
                    GattConnectionEvent::Gatt { event } => {
                        let mut wrote_output = false;
                        let mut wrote_boot_output = false;
                        let mut wrote_control_point = false;
                        let mut wrote_protocol = false;
                        #[cfg(feature = "secure")]
                        let mut wrote_bond_control = false;
                        match &event {
                            GattEvent::Read(event) if event.handle() == hid_info.handle => {
                                hid_inc(HID_INFO_READS);
                            }
                            GattEvent::Read(event) if event.handle() == report_map.handle => {
                                hid_inc(HID_REPORT_MAP_READS);
                            }
                            GattEvent::Write(event) if event.handle() == output_report.handle => {
                                wrote_output = true;
                            }
                            GattEvent::Write(event) if event.handle() == boot_output.handle => {
                                wrote_boot_output = true;
                            }
                            GattEvent::Write(event) if event.handle() == control_point.handle => {
                                wrote_control_point = true;
                            }
                            GattEvent::Write(event) if event.handle() == protocol_mode.handle => {
                                wrote_protocol = true;
                            }
                            #[cfg(feature = "secure")]
                            GattEvent::Write(event) if event.handle() == bond_control.handle => {
                                wrote_bond_control = true;
                            }
                            _ => {}
                        }
                        // Discovery, MTU exchange and CCCD writes also need replies.
                        match event.accept() {
                            Ok(reply) => reply.send().await,
                            Err(_) => fatal(stats, 7).await,
                        }
                        if wrote_output {
                            let led = match connection.get(&output_report) {
                                Ok(value) => value,
                                Err(_) => fatal(stats, 8).await,
                            };
                            hid_inc(HID_LED_WRITES);
                            hid_put(HID_LED_VALUE, u32::from(led[0]));
                        }
                        if wrote_boot_output {
                            let led = match connection.get(&boot_output) {
                                Ok(value) => value,
                                Err(_) => fatal(stats, 9).await,
                            };
                            hid_inc(HID_LED_WRITES);
                            hid_put(HID_LED_VALUE, u32::from(led[0]));
                        }
                        if wrote_control_point {
                            let command = match connection.get(&control_point) {
                                Ok(value) => value,
                                Err(_) => fatal(stats, 10).await,
                            };
                            hid_inc(HID_CONTROL_POINT_WRITES);
                            hid_put(HID_CONTROL_POINT_LAST, u32::from(command));
                        }
                        if wrote_protocol {
                            let mode = match connection.get(&protocol_mode) {
                                Ok(value) => value,
                                Err(_) => fatal(stats, 12).await,
                            };
                            hid_state.protocol_mode = mode;
                            hid_state.subscribed = false;
                            hid_state.seq = 0;
                            hid_inc(HID_PROTOCOL_MODE_WRITES);
                            hid_put(HID_PROTOCOL_MODE, u32::from(mode));
                        }
                        #[cfg(feature = "secure")]
                        if wrote_bond_control {
                            let command = match connection.get(&bond_control) {
                                Ok(command) => command,
                                Err(_) => fatal(stats, 17).await,
                            };
                            crate::bond::bump(crate::bond::STAT_CONTROL_WRITES);
                            match &command {
                                b"DEL!" => {
                                    crate::bond::bump(crate::bond::STAT_CLEAR_REQUESTS);
                                    remove_all_bonds();
                                    crate::bond::signals().delete.set(true);
                                }
                                b"WIPE" => {
                                    remove_all_bonds();
                                    crate::bond::signals().wipe.set(true);
                                }
                                b"FALT" => crate::bond::signals().fault.set(true),
                                _ => crate::bond::bump(crate::bond::STAT_MALFORMED_CONTROL_WRITES),
                            }
                        }
                    }
                    GattConnectionEvent::RequestConnectionParams(request) => {
                        if request.reject(&stack).await.is_err() {
                            stats.error(10);
                        }
                    }
                    #[cfg(feature = "secure")]
                    GattConnectionEvent::PairingComplete { bond, .. } => {
                        // Pairing Complete can arrive after Encryption Change;
                        // the encrypted state is the stronger fact.
                        if stats.word(STAT_SECURITY) != SECURITY_ENCRYPTED {
                            stats.set(STAT_SECURITY, SECURITY_PAIRED);
                        }
                        if let Some(bond) = bond {
                            // Trouble already inserted it; hand the full list to
                            // the RF owner, which persists it between events.
                            crate::bond::echo(&bond);
                            let snapshot = stack.with_bond_information(|bonds| {
                                let mut list = crate::bond::BondSnapshot::new();
                                for entry in bonds {
                                    let _ = list.push(entry.clone());
                                }
                                list
                            });
                            crate::bond::signals().set_pending(snapshot);
                        } else {
                            crate::bond::bump(crate::bond::STAT_PAIRS_WITHOUT_BOND);
                        }
                    }
                    #[cfg(feature = "secure")]
                    GattConnectionEvent::Encrypted { .. } => {
                        stats.set(STAT_SECURITY, SECURITY_ENCRYPTED);
                    }
                    #[cfg(feature = "secure")]
                    GattConnectionEvent::PairingFailed(_) => {
                        stats.error(15);
                        stats.set(STAT_SECURITY, SECURITY_FAILED);
                    }
                    _ => {}
                }
            }
        }
    };
    let _ = join(runner_task, app_task).await;
    match pending::<Infallible>().await {}
}
