//! Trouble central + GATT client, cooperatively polled outside RF deadlines.
//!
//! The app scans for one controlled peripheral name, connects with HCI LE
//! Create Connection, runs a real GATT client discovery/read/write cycle, then
//! disconnects and repeats. All radio timing stays in `main.rs`.

use core::cell::Cell;
use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
use embassy_futures::yield_now;
use embassy_time::Duration;
use trouble_host::advertise::AdStructure;
use trouble_host::prelude::*;

pub const TARGET_NAME: &[u8] = b"wch585-c1";
pub const SERVICE_UUID: Uuid =
    Uuid::new_long(0x00001000_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
pub const VALUE_UUID: Uuid =
    Uuid::new_long(0x00001001_b0cd_11ec_871f_d45ddf138840u128.to_le_bytes());
pub const RANDOM_ADDRESS: [u8; 6] = [0x21, 0x00, 0x00, 0xee, 0xff, 0xc1];
#[cfg(feature = "bogus-peer")]
pub const BOGUS_PEER: [u8; 6] = [0x7f, 0x00, 0x00, 0xee, 0xff, 0xc1];

pub const READ_INITIAL: u32 = 0x2a;
pub const WRITE_VALUE: u32 = 0x2b;
pub const CYCLES: u32 = 3;

pub const HOST_STATS_WORDS: usize = 16;
pub const STAT_PHASE: usize = 0;
pub const STAT_CONNECTIONS: usize = 1;
pub const STAT_DISCONNECTS: usize = 2;
pub const STAT_SCAN_REPORTS: usize = 3;
pub const STAT_TARGET_MATCHES: usize = 4;
pub const STAT_CONNECT_ERRORS: usize = 5;
pub const STAT_READS: usize = 6;
pub const STAT_WRITES: usize = 7;
pub const STAT_NOTIFICATIONS: usize = 8;
pub const STAT_SUBSCRIPTIONS: usize = 9;
pub const STAT_GATT_ERRORS: usize = 10;
pub const STAT_LAST_ERROR: usize = 11;
pub const STAT_CYCLES: usize = 12;
pub const STAT_LAST_HCI_STATUS: usize = 13;

pub const PHASE_STARTING: u32 = 1;
pub const PHASE_SCANNING: u32 = 2;
pub const PHASE_CONNECTING: u32 = 3;
pub const PHASE_CONNECTED: u32 = 4;
pub const PHASE_GATT: u32 = 5;
pub const PHASE_DONE: u32 = 9;
pub const PHASE_FATAL: u32 = 0xff;

/// Main owns this value next to the pinned future; only that thread accesses it.
pub struct HostStats {
    words: [Cell<u32>; HOST_STATS_WORDS],
    /// Value the peer is known to hold. The peripheral keeps its characteristic
    /// value across links, so after the first cycle the expected initial read
    /// is no longer `READ_INITIAL`.
    expected: Cell<u32>,
}

impl HostStats {
    pub const fn new() -> Self {
        Self {
            words: [const { Cell::new(0) }; HOST_STATS_WORDS],
            expected: Cell::new(READ_INITIAL),
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
        self.inc(STAT_GATT_ERRORS);
        self.set(STAT_LAST_ERROR, stage);
    }
}

struct TargetScan<'a> {
    stats: &'a HostStats,
    found: Cell<Option<Address>>,
}

impl EventHandler for TargetScan<'_> {
    fn on_adv_reports(&self, mut reports: LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = reports.next() {
            self.stats.inc(STAT_SCAN_REPORTS);
            let matched = AdStructure::decode(report.data).any(|ad| {
                matches!(
                    ad,
                    Ok(AdStructure::CompleteLocalName(name)) if name == TARGET_NAME
                )
            });
            if matched {
                self.stats.inc(STAT_TARGET_MATCHES);
                if self.found.get().is_none() {
                    self.found.set(Some(Address::new(report.addr_kind, report.addr)));
                }
            }
        }
    }
}

async fn fatal(stats: &HostStats, stage: u32) -> ! {
    stats.error(stage);
    stats.set(STAT_PHASE, PHASE_FATAL);
    match pending::<Infallible>().await {}
}

/// Discovery, initial read, write, and read-back on one connection.
async fn gatt_cycle<C, P>(
    client: &GattClient<'_, C, P, 4>,
    stats: &HostStats,
) -> Result<(), ()>
where
    C: Controller,
    P: PacketPool,
{
    let services = client
        .services_by_uuid(&SERVICE_UUID)
        .await
        .map_err(|_| stats.error(5))?;
    let service = services.first().ok_or_else(|| stats.error(5))?.clone();
    // Diagnostic: discovered service range and count (HOST_STATS 14/15).
    let range = service.handle_range();
    stats.set(14, (u32::from(*range.start()) << 16) | u32::from(*range.end()));
    stats.set(15, services.len() as u32);
    let characteristic: Characteristic<u32> = client
        .characteristic_by_uuid(&service, &VALUE_UUID)
        .await
        .map_err(|error| {
            stats.error(match error {
                BleHostError::BleHost(Error::Att(code)) => 0x100 | u32::from(code.to_u8()),
                BleHostError::BleHost(Error::NotFound) => 0x201,
                BleHostError::BleHost(Error::Timeout) => 0x202,
                BleHostError::BleHost(Error::Disconnected) => 0x203,
                BleHostError::BleHost(Error::MalformedCharacteristicDeclaration {
                    ..
                }) => 0x204,
                BleHostError::BleHost(_) => 0x205,
                BleHostError::Controller(_) => 0x206,
            })
        })?;

    let expected = stats.expected.get();
    let mut data = [0u8; 4];
    let len = client
        .read_characteristic(&characteristic, &mut data)
        .await
        .map_err(|_| stats.error(7))?;
    if len != 4 || u32::from_le_bytes(data) != expected {
        stats.error(7);
        return Err(());
    }
    stats.inc(STAT_READS);

    client
        .write_characteristic(&characteristic, &WRITE_VALUE.to_le_bytes())
        .await
        .map_err(|_| stats.error(8))?;
    stats.expected.set(WRITE_VALUE);
    stats.inc(STAT_WRITES);

    let mut echo = [0u8; 4];
    let len = client
        .read_characteristic(&characteristic, &mut echo)
        .await
        .map_err(|_| stats.error(9))?;
    if len != 4 || u32::from_le_bytes(echo) != WRITE_VALUE {
        stats.error(9);
        return Err(());
    }
    stats.inc(STAT_READS);
    Ok(())
}

/// Run persistently; main must retain and pin this future across idle polls.
pub async fn run(controller: wchble::hci::SoftController, stats: &HostStats) -> ! {
    stats.phase(PHASE_STARTING);
    // One connection: ATT, LE signaling, and one spare channel.
    let mut resources: HostResources<DefaultPacketPool, 1, 3> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(RANDOM_ADDRESS))
        .build();
    let mut runner = stack.runner();
    let mut central = stack.central();
    let scan = TargetScan {
        stats,
        found: Cell::new(None),
    };

    let runner_task = async {
        let _ = runner.run_with_handler(&scan).await;
        fatal(stats, 1).await;
    };
    let app_task = async {
        for _ in 0..CYCLES {
            #[cfg(not(feature = "bogus-peer"))]
            let target = {
                stats.phase(PHASE_SCANNING);
                scan.found.set(None);
                let mut scanner = Scanner::new(&mut central);
                let scan_config = ScanConfig {
                    active: false,
                    phys: PhySet::M1,
                    interval: Duration::from_millis(30),
                    window: Duration::from_millis(15),
                    timeout: Duration::from_secs(0),
                    ..Default::default()
                };
                let session = match scanner.scan(&scan_config).await {
                    Ok(session) => session,
                    Err(_) => fatal(stats, 2).await,
                };
                while scan.found.get().is_none() {
                    yield_now().await;
                }
                session.stop().await;
                scan.found.get().unwrap()
            };
            #[cfg(feature = "bogus-peer")]
            let target = Address::random(BOGUS_PEER);

            stats.phase(PHASE_CONNECTING);
            let connect_config = ConnectConfig {
                connect_params: RequestedConnParams {
                    min_connection_interval: Duration::from_millis(30),
                    max_connection_interval: Duration::from_millis(30),
                    max_latency: 0,
                    min_event_length: Duration::from_micros(0),
                    max_event_length: Duration::from_micros(0),
                    supervision_timeout: Duration::from_millis(2_000),
                },
                scan_config: ScanConfig {
                    active: false,
                    filter_accept_list: &[target],
                    phys: PhySet::M1,
                    interval: Duration::from_millis(30),
                    window: Duration::from_millis(15),
                    timeout: Duration::from_secs(0),
                    ..Default::default()
                },
            };
            let connection = match central.connect(&connect_config).await {
                Ok(connection) => connection,
                Err(_) => {
                    stats.inc(STAT_CONNECT_ERRORS);
                    continue;
                }
            };
            stats.inc(STAT_CONNECTIONS);
            stats.phase(PHASE_CONNECTED);

            let client = match GattClient::<_, DefaultPacketPool, 4>::new(&stack, &connection).await
            {
                Ok(client) => client,
                Err(_) => {
                    stats.error(4);
                    connection.disconnect();
                    let _ = client_task_fallback(&connection).await;
                    continue;
                }
            };
            stats.phase(PHASE_GATT);
            let operations = async {
                let result = gatt_cycle(&client, stats).await;
                connection.disconnect();
                result
            };
            // `task` returns once the host processes Disconnection Complete.
            let (_, cycle) = join(client.task(), operations).await;
            stats.inc(STAT_DISCONNECTS);
            if cycle.is_ok() {
                stats.inc(STAT_CYCLES);
            }
        }
        stats.phase(PHASE_DONE);
        match pending::<Infallible>().await {}
    };
    let _ = join(runner_task, app_task).await;
    match pending::<Infallible>().await {}
}

/// The GATT-client task only exists after `GattClient::new`; when creation
/// fails, wait for the disconnect event on the raw connection instead.
async fn client_task_fallback<P: PacketPool>(connection: &Connection<'_, P>) {
    while connection.is_connected() {
        yield_now().await;
    }
}
