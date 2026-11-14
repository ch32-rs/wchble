//! Real Trouble GATT host, cooperatively polled outside RF deadlines.

use core::cell::Cell;
use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
#[cfg(feature = "secure")]
use embassy_futures::select::{select, Either};
#[cfg(feature = "secure")]
use embassy_time::{Duration, Instant, Timer};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use heapless::Vec;
use trouble_host::prelude::*;

pub const LOCAL_NAME: &[u8] = b"wch585-p4";
#[allow(dead_code)]
pub const SERVICE_UUID_TEXT: &str = "00001000-b0cd-11ec-871f-d45ddf138840";
#[allow(dead_code)]
pub const VALUE_UUID_TEXT: &str = "00001001-b0cd-11ec-871f-d45ddf138840";
// Trouble's UUID constructor takes ATT (little-endian) bytes, not text order.
pub const SERVICE_UUID: Uuid =
    Uuid::new_long(0x00001000_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
pub const VALUE_UUID: Uuid =
    Uuid::new_long(0x00001001_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
// Nordic UART Service UUIDs: a de facto write/notify pipe understood by many
// phone BLE tools, without implying a product profile.
pub const UART_SERVICE_UUID: Uuid =
    Uuid::new_long(0x6e400001_b5a3_f393_e0a9_e50e24dcca9eu128.to_le_bytes());
pub const UART_RX_UUID: Uuid =
    Uuid::new_long(0x6e400002_b5a3_f393_e0a9_e50e24dcca9eu128.to_le_bytes());
pub const UART_TX_UUID: Uuid =
    Uuid::new_long(0x6e400003_b5a3_f393_e0a9_e50e24dcca9eu128.to_le_bytes());
#[allow(dead_code)]
pub const UART_CHARACTERISTIC_UUID_TEXT: &str = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
// P5 changes the service database, so use a new static identity. iOS caches a
// peer's GATT database by address and can otherwise keep the P4 layout.
//
// S3 fixes the address instead of rotating it per boot: the bond store keeps
// the peer's LTK, so a later boot has to present the same identity for the
// phone to reuse its bond. A phone that still holds a bond from the rotation
// era must forget it once.
// X4 changes the GATT database again, so this is a new identity: the old
// address's bond and cached layout must not be reused.
pub const RANDOM_ADDRESS: [u8; 6] = [0x18, 0x00, 0x00, 0xee, 0xff, 0xc1];

/// Bond capacity of the Host. Matches `storage::bond::MAX_BONDS` so the stored
/// list always fits the Host's in-memory table.
#[cfg(feature = "secure")]
const BOND_CAPACITY: usize = crate::bond::MAX_BONDS;
#[cfg(not(feature = "secure"))]
const BOND_CAPACITY: usize = 10;

/// Access level for the value characteristic.
#[cfg(feature = "secure")]
const VALUE_PERMISSION: PermissionLevel = PermissionLevel::EncryptionRequired;
#[cfg(not(feature = "secure"))]
const VALUE_PERMISSION: PermissionLevel = PermissionLevel::Allowed;

/// Test-only delete/wipe/fault command characteristic (secure build only).
#[cfg(feature = "secure")]
pub const BOND_CONTROL_UUID: Uuid =
    Uuid::new_long(0x00001002_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());

// X4: ATT MTU negotiation, long data and notification-queue pressure.
//
// A 128-byte packet pool caps the ATT MTU at 124, so a long read is answered
// with one 121-byte Read Response plus one Read Blob, and a 200-byte write
// needs Prepare/Execute (queued writes). The burst is exactly MTU-3 bytes so
// each notification fills a 124-byte ATT PDU (128-byte L2CAP PDU, six 23-byte
// ACL fragments on an encrypted link).
pub const BULK_UUID: Uuid =
    Uuid::new_long(0x00001005_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
pub const BURST_UUID: Uuid =
    Uuid::new_long(0x00001006_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
pub const X4_CONTROL_UUID: Uuid =
    Uuid::new_long(0x00001007_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
pub const BULK_LEN: usize = 200;
pub const BURST_LEN: usize = 121;
pub const BURST_ATTEMPTS: u32 = 12;

/// Pattern the bulk characteristic holds until a client overwrites it.
pub const fn x4_bulk_read_byte(index: usize) -> u8 {
    (index.wrapping_mul(7).wrapping_add(3) & 0xff) as u8
}

/// Pattern the Android client writes; firmware compares the stored value.
pub const fn x4_bulk_write_byte(index: usize) -> u8 {
    (255 - index) as u8
}

pub const fn x4_burst_byte(index: usize) -> u8 {
    (index.wrapping_mul(3).wrapping_add(1) & 0xff) as u8
}

pub const X4_STATS_WORDS: usize = 16;
pub const X4_MAGIC_INDEX: usize = 0;
pub const X4_VERSION_INDEX: usize = 1;
pub const X4_MAGIC: u32 = 0x5834_0001;
pub const X4_VERSION: u32 = 1;
pub const X4_MTU: usize = 2;
pub const X4_BULK_READS: usize = 3;
pub const X4_BULK_WRITES: usize = 4;
pub const X4_BULK_LEN: usize = 5;
pub const X4_BULK_SUM: usize = 6;
/// 1 when the last stored bulk value equals [`x4_bulk_write_byte`].
pub const X4_BULK_MATCH: usize = 7;
pub const X4_BURST_RUNS: usize = 8;
pub const X4_BURST_ATTEMPTS: usize = 9;
pub const X4_BURST_SENT: usize = 10;
/// `try_notify` found the Host's outbound queue full.
pub const X4_BURST_QUEUE_FULL: usize = 11;
/// `try_notify` asked for encryption instead of queueing.
pub const X4_BURST_BUSY: usize = 12;
pub const X4_BURST_OTHER: usize = 13;
pub const X4_BURST_LEN: usize = 14;
pub const X4_LAST_ERROR: usize = 15;

#[no_mangle]
static mut X4_STATS: [u32; X4_STATS_WORDS] = [0; X4_STATS_WORDS];

fn x4_put(index: usize, value: u32) {
    // SAFETY: single-threaded example; only the Host poll writes X4_STATS.
    unsafe {
        core::ptr::addr_of_mut!(X4_STATS)
            .cast::<u32>()
            .add(index)
            .write_volatile(value)
    }
}

fn x4_get(index: usize) -> u32 {
    // SAFETY: single-threaded example; only the Host poll reads X4_STATS.
    unsafe {
        core::ptr::addr_of!(X4_STATS)
            .cast::<u32>()
            .add(index)
            .read_volatile()
    }
}

fn x4_inc(index: usize) {
    x4_put(index, x4_get(index).wrapping_add(1));
}

/// Read an X4 counter. The firmware runner uses the exported symbol; the
/// native host fixture uses this hook.
#[allow(dead_code)]
pub fn x4_word(index: usize) -> u32 {
    x4_get(index)
}

fn x4_sum(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |sum, &byte| sum.wrapping_add(u32::from(byte)))
}

// X1 telemetry: CSA #2 selection and the bidirectional DLE negotiation. The
// RF owner writes these words; the runner validates them after a finite run.
pub const X1_STATS_WORDS: usize = 24;
pub const X1_MAGIC_INDEX: usize = 0;
pub const X1_VERSION_INDEX: usize = 1;
pub const X1_MAGIC: u32 = 0x5831_0001;
pub const X1_VERSION: u32 = 1;
/// 1 = CSA #1, 2 = CSA #2.
pub const X1_ALGORITHM: usize = 2;
pub const X1_EVENT_COUNTER: usize = 3;
/// ChSel bit this peripheral put in its own ADV_IND/ADV_SCAN_IND.
pub const X1_ADV_CHSEL: usize = 4;
/// ChSel bit the central put in CONNECT_IND.
pub const X1_INIT_CHSEL: usize = 5;
pub const X1_LENGTH_REQ_RX: usize = 6;
pub const X1_LENGTH_RSP_RX: usize = 7;
pub const X1_LENGTH_REQ_TX: usize = 8;
pub const X1_LENGTH_RSP_TX: usize = 9;
/// Effective on-air limits; 27/31 until the peer answers an `LL_LENGTH_REQ`.
pub const X1_TX_OCTETS: usize = 10;
pub const X1_RX_OCTETS: usize = 11;
pub const X1_TX_TIME: usize = 12;
pub const X1_RX_TIME: usize = 13;
pub const X1_MAX_TX_PDU: usize = 14;
pub const X1_MAX_RX_PDU: usize = 15;
pub const X1_RX_OVER_27: usize = 16;
pub const X1_TX_OVER_27: usize = 17;
/// Host ACL packets that needed more than one LL fragment.
pub const X1_HOST_PACKETS_SEGMENTED: usize = 18;
pub const X1_HOST_FRAGMENTS: usize = 19;
pub const X1_TX_PDUS: usize = 20;
pub const X1_RX_PDUS: usize = 21;
/// 1 once the peer feature set is known (0 = still unknown).
pub const X1_FEATURE_EXCHANGE: usize = 22;
pub const X1_LAST_ERROR: usize = 23;

#[no_mangle]
static mut X1_STATS: [u32; X1_STATS_WORDS] = [0; X1_STATS_WORDS];

pub fn x1_put(index: usize, value: u32) {
    // SAFETY: single-threaded example; only the RF owner writes X1_STATS.
    unsafe {
        core::ptr::addr_of_mut!(X1_STATS)
            .cast::<u32>()
            .add(index)
            .write_volatile(value)
    }
}

pub fn x1_get(index: usize) -> u32 {
    // SAFETY: single-threaded example; only the RF owner reads X1_STATS.
    unsafe {
        core::ptr::addr_of!(X1_STATS)
            .cast::<u32>()
            .add(index)
            .read_volatile()
    }
}

pub fn x1_inc(index: usize) {
    x1_put(index, x1_get(index).wrapping_add(1));
}

/// Read an X1 counter. The firmware runner uses the exported symbol; the
/// native host fixture uses this hook.
#[allow(dead_code)]
pub fn x1_word(index: usize) -> u32 {
    x1_get(index)
}

pub const HOST_STATS_WORDS: usize = 16;
pub const STAT_PHASE: usize = 0;
pub const STAT_CONNECTIONS: usize = 1;
pub const STAT_DISCONNECTS: usize = 2;
pub const STAT_READS: usize = 3;
pub const STAT_WRITES: usize = 4;
pub const STAT_NOTIFICATIONS: usize = 5;
pub const STAT_VALUE: usize = 6;
pub const STAT_ERRORS: usize = 7;
pub const STAT_LAST_ERROR: usize = 8;
pub const STAT_OTHER: usize = 9;
pub const STAT_SUBSCRIBED: usize = 10;
pub const STAT_ADVERTISE_ATTEMPTS: usize = 11;
pub const STAT_UART_WRITES: usize = 12;
pub const STAT_UART_NOTIFICATIONS: usize = 13;
pub const STAT_UART_LEN: usize = 14;
// 0 = not requested, 1 = L2CAP request sent, 2 = send failed (test feature).
#[allow(dead_code)]
pub const STAT_CONN_PARAMS: usize = 15;

#[cfg(feature = "secure")]
pub const STAT_SECURITY: usize = 15;
#[cfg(feature = "secure")]
pub const SECURITY_REQUESTED: u32 = 1;
#[cfg(feature = "secure")]
pub const SECURITY_PAIRED: u32 = 2;
#[cfg(feature = "secure")]
pub const SECURITY_ENCRYPTED: u32 = 3;
#[cfg(feature = "secure")]
pub const SECURITY_FAILED: u32 = 4;

/// See the comment on `security_deadline`: Android must get the first word.
#[cfg(feature = "secure")]
const SECURITY_REQUEST_DELAY_MS: u64 = 2_000;

#[cfg(feature = "conn-params-30")]
const CONN_INTERVAL_US: u64 = 30_000;
#[cfg(feature = "conn-params-48")]
const CONN_INTERVAL_US: u64 = 48_750;

pub const PHASE_STARTING: u32 = 1;
pub const PHASE_ADVERTISING: u32 = 2;
pub const PHASE_CONNECTED: u32 = 3;
pub const PHASE_FATAL: u32 = 0xff;

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

/// Run persistently; main must retain and pin this future across idle polls.
/// Fatal errors park on `Pending`, never in a blocking spin loop.
pub async fn run(
    controller: wchble::hci::SoftController,
    stats: &HostStats,
    address: [u8; 6],
) -> ! {
    stats.phase(PHASE_STARTING);
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
    #[cfg(feature = "accept-control")]
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

    let appearance = [0u8, 0];
    let mut storage = [0u8; 4];
    #[cfg(feature = "accept-control")]
    let mut control_storage = [0u8; 4];
    let mut bulk_storage = [0u8; 256];
    let mut burst_storage = [0u8; 128];
    let mut x4_control_storage = [0u8; 4];
    let mut uart_rx_storage = [0u8; 64];
    let mut uart_tx_storage = [0u8; 64];
    x4_put(X4_MAGIC_INDEX, X4_MAGIC);
    x4_put(X4_VERSION_INDEX, X4_VERSION);
    x4_put(X4_BULK_LEN, 0);
    x4_put(X4_BURST_LEN, BURST_LEN as u32);
    // GAP + GATT + DIS + vendor (value, control, long read/write, burst,
    // X4 command and CCCDs) + UART. The S3 control characteristic needed two
    // more slots than the S2 table had and X4 adds seven more;
    // `AttributeTable::push` panics on overflow at the first poll.
    let mut table: AttributeTable<'_, NoopRawMutex, 40> = AttributeTable::new();
    let mut gap = table.add_service(Service::new(0x1800u16));
    gap.add_characteristic_ro(0x2a00u16, LOCAL_NAME);
    gap.add_characteristic_ro(0x2a01u16, &appearance);
    gap.build();
    table.add_service(Service::new(0x1801u16)).build();

    // Standard Device Information Service, read-only so a client can identify
    // this build without any vendor-specific schema.
    let mut info = table.add_service(Service::new(0x180Au16));
    info.add_characteristic_ro(0x2a29u16, "wchble");
    info.add_characteristic_ro(0x2a24u16, "ch585-trouble-gatt");
    info.add_characteristic_ro(0x2a26u16, "p5-0.1");
    info.build();

    let mut vendor = table.add_service(Service::new(SERVICE_UUID));
    // S3: the secure build refuses unencrypted reads and writes instead of
    // trusting the peer to pair first.
    let value: Characteristic<u32> = vendor
        .add_characteristic(
            VALUE_UUID,
            &[
                CharacteristicProp::Read,
                CharacteristicProp::Write,
                CharacteristicProp::Notify,
            ],
            0u32,
            &mut storage,
        )
        .read_permission(VALUE_PERMISSION)
        .write_permission(VALUE_PERMISSION)
        .build();

    // S3 acceptance commands: `DEL!` removes the bond and writes a tombstone,
    // `WIPE` erases both slots, `FALT` truncates the next save. This is a test
    // control, not part of a product profile: it is unauthenticated (a peer
    // must be able to clear a bond it cannot use), so it only exists in images
    // built with the non-default `accept-control` feature.
    #[cfg(feature = "accept-control")]
    let control: Characteristic<[u8; 4]> = vendor
        .add_characteristic(
            BOND_CONTROL_UUID,
            &[CharacteristicProp::Write],
            [0u8; 4],
            &mut control_storage,
        )
        .build();

    // X4 fixtures. The bulk value is 200 bytes, longer than any single ATT PDU
    // at MTU 124, so a read needs Read Blob and a write needs Prepare/Execute.
    let mut bulk_value: Vec<u8, 256> = Vec::new();
    for index in 0..BULK_LEN {
        bulk_value.push(x4_bulk_read_byte(index)).unwrap();
    }
    let bulk: Characteristic<Vec<u8, 256>> = vendor
        .add_characteristic(
            BULK_UUID,
            &[CharacteristicProp::Read, CharacteristicProp::Write],
            bulk_value,
            &mut bulk_storage,
        )
        .read_permission(VALUE_PERMISSION)
        .write_permission(VALUE_PERMISSION)
        .build();
    let mut burst_value: Vec<u8, 128> = Vec::new();
    for index in 0..BURST_LEN {
        burst_value.push(x4_burst_byte(index)).unwrap();
    }
    let burst: Characteristic<Vec<u8, 128>> = vendor
        .add_characteristic(
            BURST_UUID,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            burst_value,
            &mut burst_storage,
        )
        .read_permission(VALUE_PERMISSION)
        .build();
    let x4_control: Characteristic<[u8; 4]> = vendor
        .add_characteristic(
            X4_CONTROL_UUID,
            &[CharacteristicProp::Write],
            [0u8; 4],
            &mut x4_control_storage,
        )
        .write_permission(VALUE_PERMISSION)
        .build();
    vendor.build();

    // UART pipe: writes to RX are echoed as notifications on TX.
    let mut uart = table.add_service(Service::new(UART_SERVICE_UUID));
    let uart_rx: Characteristic<Vec<u8, 64>> = uart
        .add_characteristic(
            UART_RX_UUID,
            &[CharacteristicProp::Write],
            Vec::new(),
            &mut uart_rx_storage,
        )
        .build();
    let uart_tx: Characteristic<Vec<u8, 64>> = uart
        .add_characteristic(
            UART_TX_UUID,
            &[CharacteristicProp::Notify],
            Vec::new(),
            &mut uart_tx_storage,
        )
        .build();
    uart.build();
    let server = AttributeServer::<NoopRawMutex, DefaultPacketPool, 40, 1>::new(table);

    let runner_task = async {
        use core::fmt::Write;
        if let Err(error) = runner.run().await {
            let _ = write!(ErrorSink, "{error:?}");
        }
        fatal(stats, 1).await;
    };
    let app_task = async {
        let mut adv_data = [0u8; 31];
        // Android scanners commonly receive only ADV_IND (no SCAN_REQ/RSP),
        // so the secure build carries the name in the advertising data as
        // well. The non-secure P4 build keeps its original layout.
        #[cfg(feature = "secure")]
        let adv_structures = [
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteLocalName(LOCAL_NAME),
        ];
        #[cfg(not(feature = "secure"))]
        let adv_structures = [AdStructure::Flags(
            LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED,
        )];
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

        // Per-peer client ATT shadow, seeded from the records read at boot.
        #[cfg(feature = "secure")]
        let mut att_shadow = crate::client_att::shadow_from_boot();
        #[cfg(feature = "secure")]
        crate::client_att::set(
            crate::client_att::STAT_SHADOW_RECORDS,
            att_shadow.len() as u32,
        );
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
            // Bonding, like the reference macOS peripheral: without the bonding
            // bit Android's SMP takes its non-bonding path, and this phone never
            // follows LL_ENC_RSP with LL_START_ENC_REQ.
            #[cfg(feature = "secure")]
            if connection.set_bondable(true).is_err() {
                fatal(stats, 16).await;
            }
            let connection = match connection.with_attribute_server(&server) {
                Ok(connection) => connection,
                Err(_) => fatal(stats, 6).await,
            };
            // Restore the bonded peer's CCCD state now that the Host has
            // allocated this connection's client-table slot.
            #[cfg(feature = "secure")]
            crate::client_att::restore(&server, &connection, &att_shadow);
            stats.inc(STAT_CONNECTIONS);
            stats.phase(PHASE_CONNECTED);
            stats.set(STAT_SUBSCRIBED, 0);
            // S2: a peripheral Security Request is what makes a macOS central
            // start pairing without a protected attribute. It must not be the
            // first SMP traffic, though: when Android receives one in SMP IDLE
            // before `createBond()` has issued its Pairing Request, its stack
            // moves to WAIT_APP_RSP waiting for an app callback that a plain
            // GATT client never registers, and pairing stalls until the link
            // drops. Delay it so the central's own flow always goes first.
            #[cfg(feature = "secure")]
            let mut security_deadline =
                Some(Instant::now() + Duration::from_millis(SECURITY_REQUEST_DELAY_MS));
            // CCCD descriptors accept writes before the peer bonds, so a
            // subscription can exist while `snapshot` still refuses to record
            // it. Remember the write and persist it once pairing completes.
            #[cfg(feature = "secure")]
            let mut cccd_written = false;

            loop {
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
                #[cfg(feature = "secure")]
                let event = {
                    let timer = async {
                        match security_deadline {
                            Some(deadline) => Timer::at(deadline).await,
                            None => pending::<()>().await,
                        }
                    };
                    match select(connection.next(), timer).await {
                        Either::First(event) => Some(event),
                        Either::Second(()) => None,
                    }
                };
                #[cfg(not(feature = "secure"))]
                let event = Some(connection.next().await);
                let Some(event) = event else {
                    continue;
                };
                match event {
                    GattConnectionEvent::Disconnected { .. } => {
                        // The GattConnection and its client table are still
                        // alive here; capture the final CCCD state before the
                        // drop clears it for non-bonded peers. A subscription
                        // written before pairing completed may only be
                        // recordable now that the peer is bonded.
                        #[cfg(feature = "secure")]
                        crate::client_att::snapshot(
                            &server,
                            &connection,
                            &mut att_shadow,
                            cccd_written,
                        );
                        stats.inc(STAT_DISCONNECTS);
                        stats.set(STAT_SUBSCRIBED, 0);
                        break;
                    }
                    GattConnectionEvent::Gatt { event } => {
                        let mut wrote_value = false;
                        let mut wrote_uart = false;
                        let mut read_bulk = false;
                        let mut wrote_bulk = false;
                        let mut wrote_x4_control = false;
                        #[cfg(feature = "accept-control")]
                        let mut wrote_control = false;
                        // The negotiated value is also the key input for the
                        // long-read/long-write evidence in the runner.
                        x4_put(X4_MTU, u32::from(connection.raw().att_mtu()));
                        #[cfg(any(feature = "conn-params-30", feature = "conn-params-48"))]
                        let is_write = matches!(&event, GattEvent::Write(_));
                        match &event {
                            GattEvent::Read(event) if event.handle() == value.handle => {
                                stats.inc(STAT_READS);
                            }
                            GattEvent::Write(event) if event.handle() == value.handle => {
                                wrote_value = true;
                            }
                            GattEvent::Write(event) if event.handle() == uart_rx.handle => {
                                wrote_uart = true;
                            }
                            GattEvent::Read(event) if event.handle() == bulk.handle => {
                                read_bulk = true;
                            }
                            GattEvent::Write(event) if event.handle() == bulk.handle => {
                                wrote_bulk = true;
                            }
                            GattEvent::Write(event) if event.handle() == x4_control.handle => {
                                wrote_x4_control = true;
                            }
                            #[cfg(feature = "accept-control")]
                            GattEvent::Write(event) if event.handle() == control.handle => {
                                wrote_control = true;
                            }
                            _ => stats.inc(STAT_OTHER),
                        }
                        // A CCCD write is the only GATT event that changes the
                        // client ATT table we persist.
                        #[cfg(feature = "secure")]
                        let wrote_cccd = match &event {
                            GattEvent::Write(event) => {
                                value.cccd_handle == Some(event.handle())
                                    || burst.cccd_handle == Some(event.handle())
                                    || uart_tx.cccd_handle == Some(event.handle())
                            }
                            _ => false,
                        };
                        // Discovery, MTU exchange and CCCD events also need replies.
                        match event.accept() {
                            Ok(reply) => reply.send().await,
                            Err(_) => fatal(stats, 7).await,
                        }
                        #[cfg(feature = "secure")]
                        if wrote_cccd {
                            cccd_written = true;
                            crate::client_att::snapshot(&server, &connection, &mut att_shadow, true);
                        }
                        #[cfg(feature = "accept-control")]
                        if wrote_control {
                            let command = match connection.get(&control) {
                                Ok(command) => command,
                                Err(_) => fatal(stats, 17).await,
                            };
                            crate::bond::bump(crate::bond::STAT_CONTROL_WRITES);
                            match &command {
                                b"DEL!" => {
                                    crate::bond::bump(crate::bond::STAT_CLEAR_REQUESTS);
                                    remove_all_bonds();
                                    // A snapshot queued before this command must
                                    // not be written after the tombstone, and
                                    // the shadow must not resurrect the deleted
                                    // peers on the next snapshot.
                                    crate::bond::signals().discard_pending();
                                    crate::client_att::clear_shadow(&mut att_shadow);
                                    crate::bond::signals().delete.set(true);
                                }
                                b"WIPE" => {
                                    remove_all_bonds();
                                    crate::bond::signals().discard_pending();
                                    crate::client_att::clear_shadow(&mut att_shadow);
                                    crate::bond::signals().wipe.set(true);
                                }
                                b"FALT" => crate::bond::signals().fault.set(true),
                                _ => crate::bond::bump(crate::bond::STAT_MALFORMED_CONTROL_WRITES),
                            }
                        }
                        if read_bulk {
                            x4_inc(X4_BULK_READS);
                        }
                        if wrote_bulk {
                            // A queued write reaches the application once, at
                            // Execute Write, after `accept` stored the value.
                            let current = match connection.get(&bulk) {
                                Ok(current) => current,
                                Err(_) => fatal(stats, 18).await,
                            };
                            x4_inc(X4_BULK_WRITES);
                            x4_put(X4_BULK_LEN, current.len() as u32);
                            x4_put(X4_BULK_SUM, x4_sum(&current));
                            let expected = current.len() == BULK_LEN
                                && current.iter().enumerate().all(|(index, byte)| {
                                    *byte == x4_bulk_write_byte(index)
                                });
                            x4_put(X4_BULK_MATCH, u32::from(expected));
                        }
                        if wrote_x4_control {
                            let command = match connection.get(&x4_control) {
                                Ok(command) => command,
                                Err(_) => fatal(stats, 19).await,
                            };
                            match &command {
                                b"BST!" => {
                                    x4_inc(X4_BURST_RUNS);
                                    if !burst.should_notify(&connection) {
                                        // No CCCD: nothing would reach the peer.
                                        x4_put(X4_LAST_ERROR, 0xb2);
                                    } else {
                                        let pattern: [u8; BURST_LEN] =
                                            core::array::from_fn(x4_burst_byte);
                                        // Bounded window: `try_notify` only
                                        // enqueues into the Host's outbound
                                        // queue, so once it is full every
                                        // further attempt must fail without
                                        // blocking or retrying.
                                        for _ in 0..BURST_ATTEMPTS {
                                            x4_inc(X4_BURST_ATTEMPTS);
                                            match burst.try_notify_raw(
                                                &connection,
                                                &pattern,
                                                false,
                                            ) {
                                                Ok(()) => x4_inc(X4_BURST_SENT),
                                                Err(Error::OutOfMemory) => {
                                                    x4_inc(X4_BURST_QUEUE_FULL)
                                                }
                                                Err(Error::Busy) => x4_inc(X4_BURST_BUSY),
                                                Err(_) => x4_inc(X4_BURST_OTHER),
                                            }
                                        }
                                    }
                                }
                                _ => x4_put(X4_LAST_ERROR, 0xb1),
                            }
                        }
                        // Test-only: after discovery settles, ask for one fixed
                        // interval over the LE signaling channel (L2CAP 0x12).
                        #[cfg(any(feature = "conn-params-30", feature = "conn-params-48"))]
                        if is_write && stats.word(STAT_CONN_PARAMS) == 0 {
                            let requested = RequestedConnParams {
                                min_connection_interval: embassy_time::Duration::from_micros(
                                    CONN_INTERVAL_US,
                                ),
                                max_connection_interval: embassy_time::Duration::from_micros(
                                    CONN_INTERVAL_US,
                                ),
                                max_latency: 0,
                                min_event_length: embassy_time::Duration::from_micros(0),
                                max_event_length: embassy_time::Duration::from_micros(0),
                                supervision_timeout: embassy_time::Duration::from_millis(5_000),
                            };
                            let sent = connection
                                .raw()
                                .update_connection_params(&stack, &requested)
                                .await;
                            if sent.is_ok() {
                                stats.set(STAT_CONN_PARAMS, 1);
                            } else {
                                stats.error(13);
                                stats.set(STAT_CONN_PARAMS, 2)
                            }
                        }
                        let subscribed = value.should_notify(&connection);
                        stats.set(STAT_SUBSCRIBED, u32::from(subscribed));
                        if wrote_value {
                            let current = match connection.get(&value) {
                                Ok(current) => current,
                                Err(_) => fatal(stats, 8).await,
                            };
                            stats.inc(STAT_WRITES);
                            stats.set(STAT_VALUE, current);
                            if subscribed {
                                // The client supplies the sequence number: echo it unchanged.
                                match value.notify(&connection, &current, false).await {
                                    Ok(()) => stats.inc(STAT_NOTIFICATIONS),
                                    Err(_) => stats.error(9),
                                }
                            }
                        }
                        if wrote_uart {
                            let bytes = match connection.get(&uart_rx) {
                                Ok(bytes) => bytes,
                                Err(_) => fatal(stats, 11).await,
                            };
                            stats.inc(STAT_UART_WRITES);
                            stats.set(STAT_UART_LEN, bytes.len() as u32);
                            if uart_tx.should_notify(&connection) {
                                match uart_tx.notify(&connection, &bytes, false).await {
                                    Ok(()) => stats.inc(STAT_UART_NOTIFICATIONS),
                                    Err(_) => stats.error(12),
                                }
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
                            // The peer may have subscribed before it bonded;
                            // snapshot() refused that write while the peer was
                            // not bonded, so fold it into the shadow now.
                            if cccd_written {
                                crate::client_att::snapshot(
                                    &server,
                                    &connection,
                                    &mut att_shadow,
                                    true,
                                );
                            }
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
