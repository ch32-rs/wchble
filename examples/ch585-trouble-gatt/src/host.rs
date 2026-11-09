//! Real Trouble GATT host, cooperatively polled outside RF deadlines.

use core::cell::Cell;
use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
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
pub const RANDOM_ADDRESS: [u8; 6] = [0x14, 0x00, 0x00, 0xee, 0xff, 0xc1];

pub const HOST_STATS_WORDS: usize = 12;
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
    let mut table: AttributeTable<'_, NoopRawMutex, 10> = AttributeTable::new();
    let mut gap = table.add_service(Service::new(0x1800u16));
    gap.add_characteristic_ro(0x2a00u16, LOCAL_NAME);
    gap.add_characteristic_ro(0x2a01u16, &appearance);
    gap.build();
    table.add_service(Service::new(0x1801u16)).build();
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
    let server = AttributeServer::<NoopRawMutex, DefaultPacketPool, 10, 1>::new(table);

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
                        match &event {
                            GattEvent::Read(event) if event.handle() == value.handle => {
                                stats.inc(STAT_READS);
                            }
                            GattEvent::Write(event) if event.handle() == value.handle => {
                                wrote_value = true;
                            }
                            _ => stats.inc(STAT_OTHER),
                        }
                        // Discovery, MTU exchange and CCCD events also need replies.
                        match event.accept() {
                            Ok(reply) => reply.send().await,
                            Err(_) => fatal(stats, 7).await,
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
