//! Real Trouble GATT host, cooperatively polled outside RF deadlines.

use core::cell::Cell;
use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
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
pub const RANDOM_ADDRESS: [u8; 6] = [0x15, 0x00, 0x00, 0xee, 0xff, 0xc1];

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
pub const STAT_CONN_PARAMS: usize = 15;

#[cfg(feature = "conn-params-30")]
const CONN_INTERVAL_US: u64 = 30_000;
#[cfg(feature = "conn-params-48")]
const CONN_INTERVAL_US: u64 = 48_750;

pub const PHASE_STARTING: u32 = 1;
pub const PHASE_ADVERTISING: u32 = 2;
pub const PHASE_CONNECTED: u32 = 3;
pub const PHASE_FATAL: u32 = 0xff;

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
pub async fn run(controller: wchble::hci::SoftController, stats: &HostStats) -> ! {
    stats.phase(PHASE_STARTING);
    // One connection; ATT and the LE signaling channel, with no dynamic channels.
    let mut resources: HostResources<DefaultPacketPool, 1, 2> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(RANDOM_ADDRESS))
        .build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();

    let appearance = [0u8, 0];
    let mut storage = [0u8; 4];
    let mut uart_rx_storage = [0u8; 64];
    let mut uart_tx_storage = [0u8; 64];
    let mut table: AttributeTable<'_, NoopRawMutex, 24> = AttributeTable::new();
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

    let value: Characteristic<u32> = table
        .add_service(Service::new(SERVICE_UUID))
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
        .build();

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
    let server = AttributeServer::<NoopRawMutex, DefaultPacketPool, 24, 1>::new(table);

    let runner_task = async {
        let _ = runner.run().await;
        fatal(stats, 1).await;
    };
    let app_task = async {
        let mut adv_data = [0u8; 31];
        let adv_len = match AdStructure::encode_slice(
            &[AdStructure::Flags(
                LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED,
            )],
            &mut adv_data,
        ) {
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
            let connection = match connection.with_attribute_server(&server) {
                Ok(connection) => connection,
                Err(_) => fatal(stats, 6).await,
            };
            stats.inc(STAT_CONNECTIONS);
            stats.phase(PHASE_CONNECTED);
            stats.set(STAT_SUBSCRIBED, 0);

            loop {
                match connection.next().await {
                    GattConnectionEvent::Disconnected { .. } => {
                        stats.inc(STAT_DISCONNECTS);
                        stats.set(STAT_SUBSCRIBED, 0);
                        break;
                    }
                    GattConnectionEvent::Gatt { event } => {
                        let mut wrote_value = false;
                        let mut wrote_uart = false;
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
                            _ => stats.inc(STAT_OTHER),
                        }
                        // Discovery, MTU exchange and CCCD events also need replies.
                        match event.accept() {
                            Ok(reply) => reply.send().await,
                            Err(_) => fatal(stats, 7).await,
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
                    _ => {}
                }
            }
        }
    };
    let _ = join(runner_task, app_task).await;
    match pending::<Infallible>().await {}
}
