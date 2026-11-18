//! X3.5 CP app: one Peripheral link (macOS client) and one Central link
//! (android-gatt server) on the same Host stack.
//!
//! The peripheral half mirrors `pp.rs`; the central half scans for the
//! controlled advertiser name, connects with HCI LE Create Connection, then
//! runs discovery, read, write, subscribe and waits for the server's
//! notification. All radio timing stays in `main.rs`.

use core::cell::Cell;
use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_futures::yield_now;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{with_timeout, Duration};
use trouble_host::advertise::AdStructure;
use trouble_host::prelude::*;

use crate::host::{self, HostStats, SERVICE_UUID, VALUE_UUID};

const BOND_CAPACITY: usize = 1;
/// The Android fixture advertises this name and starts at `READ_INITIAL`.
pub const TARGET_NAME: &[u8] = b"wch585-c1";
pub const READ_INITIAL: u32 = 0x2a;
pub const WRITE_VALUE: u32 = 0x2b;
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(2);

struct TargetScan<'a> {
    stats: &'a HostStats,
    found: Cell<Option<Address>>,
}

impl EventHandler for TargetScan<'_> {
    fn on_adv_reports(&self, mut reports: LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = reports.next() {
            self.stats.inc(host::STAT_OTHER);
            let matched = AdStructure::decode(report.data).any(|ad| {
                matches!(
                    ad,
                    Ok(AdStructure::CompleteLocalName(name)) if name == TARGET_NAME
                )
            });
            if matched && self.found.get().is_none() {
                self.found
                    .set(Some(Address::new(report.addr_kind, report.addr)));
            }
        }
    }
}

pub async fn run(controller: wchble::hci::SoftController, stats: &HostStats) -> ! {
    stats.phase(host::PHASE_STARTING);
    // Two connections; ATT plus the LE signaling channel, no dynamic channels.
    let mut resources: HostResources<DefaultPacketPool, 2, 2, 1, BOND_CAPACITY> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        // The pp identity: macOS caches GATT handles per address.
        .set_random_address(Address::random(host::PP_RANDOM_ADDRESS))
        .build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();
    let mut central = stack.central();

    let mut storage = [0u8; 4];
    let mut uart_rx_storage = [0u8; 4];
    let mut uart_tx_storage = [0u8; 4];
    let mut table: AttributeTable<'_, NoopRawMutex, 24> = AttributeTable::new();
    let mut gap = table.add_service(Service::new(0x1800u16));
    gap.add_characteristic_ro(0x2a00u16, host::LOCAL_NAME);
    gap.add_characteristic_ro(0x2a01u16, &[0u8, 0]);
    gap.build();
    let mut service = table.add_service(Service::new(SERVICE_UUID));
    let value: Characteristic<u32> = service
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
    service.build();
    let mut uart = table.add_service(Service::new(host::UART_SERVICE_UUID));
    let uart_rx: Characteristic<u32> = uart
        .add_characteristic(
            host::UART_RX_UUID,
            &[CharacteristicProp::Write],
            0u32,
            &mut uart_rx_storage,
        )
        .build();
    let uart_tx: Characteristic<u32> = uart
        .add_characteristic(
            host::UART_TX_UUID,
            &[CharacteristicProp::Read, CharacteristicProp::Notify],
            0u32,
            &mut uart_tx_storage,
        )
        .build();
    uart.build();
    let server = AttributeServer::<NoopRawMutex, DefaultPacketPool, 24, 2>::new(table);

    let scan = TargetScan {
        stats,
        found: Cell::new(None),
    };
    let peripheral_app = async {
        loop {
            stats.phase(host::PHASE_ADVERTISING);
            let first = accept(&mut peripheral, &server).await;
            stats.inc(host::STAT_CONNECTIONS);
            stats.phase(host::PHASE_CONNECTED);
            let second = match select(
                accept(&mut peripheral, &server),
                serve(&value, &uart_rx, &uart_tx, &first, None, stats),
            )
            .await
            {
                Either::First(second) => second,
                Either::Second(()) => {
                    stats.inc(host::STAT_DISCONNECTS);
                    continue;
                }
            };
            stats.inc(host::STAT_CONNECTIONS);
            match select(
                serve(&value, &uart_rx, &uart_tx, &first, Some(&second), stats),
                serve(&value, &uart_rx, &uart_tx, &second, Some(&first), stats),
            )
            .await
            {
                Either::First(()) => {
                    stats.inc(host::STAT_DISCONNECTS);
                    serve(&value, &uart_rx, &uart_tx, &second, None, stats).await;
                    stats.inc(host::STAT_DISCONNECTS);
                }
                Either::Second(()) => {
                    stats.inc(host::STAT_DISCONNECTS);
                    serve(&value, &uart_rx, &uart_tx, &first, None, stats).await;
                    stats.inc(host::STAT_DISCONNECTS);
                }
            }
        }
    };
    let central_app = async {
        central_cycle(&stack, &mut central, &scan, stats).await;
        // One cycle decides the round; keep the link state for the runner.
        match pending::<Infallible>().await {}
    };
    let _ = join(
        runner.run_with_handler(&scan),
        join(peripheral_app, central_app),
    )
    .await;
    stats.set(host::STAT_PHASE, host::PHASE_FATAL);
    match pending::<Infallible>().await {}
}

async fn accept<'d, 's, C: Controller>(
    peripheral: &mut Peripheral<'d, C, DefaultPacketPool>,
    server: &'s AttributeServer<'_, NoopRawMutex, DefaultPacketPool, 24, 2>,
) -> GattConnection<'d, 's, DefaultPacketPool> {
    let mut adv_data = [0u8; 14];
    adv_data[..3].copy_from_slice(&[0x02, 0x01, 0x06]);
    adv_data[3] = 0x0A;
    adv_data[4] = 0x09;
    adv_data[5..].copy_from_slice(host::LOCAL_NAME);
    let scan_data = [];
    let acceptor = peripheral
        .advertise(
            &AdvertisementParameters::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data,
                scan_data: &scan_data,
            },
        )
        .await
        .unwrap();
    let connection = acceptor.accept().await.unwrap();
    connection.with_attribute_server(server).unwrap()
}

/// Serve one connection until it disconnects, notifying every live link.
async fn serve<P: PacketPool>(
    value: &Characteristic<u32>,
    uart_rx: &Characteristic<u32>,
    uart_tx: &Characteristic<u32>,
    connection: &GattConnection<'_, '_, P>,
    peer: Option<&GattConnection<'_, '_, P>>,
    stats: &HostStats,
) {
    loop {
        match connection.next().await {
            GattConnectionEvent::Disconnected { .. } => return,
            GattConnectionEvent::Gatt { event } => {
                let mut updated = None;
                let reply = match &event {
                    GattEvent::Write(write) if write.handle() == value.handle => {
                        stats.inc(host::STAT_WRITES);
                        updated = write.value(value).ok();
                        event.accept()
                    }
                    GattEvent::Write(write) if write.handle() == uart_rx.handle => {
                        stats.inc(host::STAT_WRITES);
                        updated = write.value(uart_rx).ok();
                        event.accept()
                    }
                    GattEvent::Read(read) if read.handle() == value.handle => {
                        stats.inc(host::STAT_READS);
                        event.accept()
                    }
                    _ => event.accept(),
                };
                if let Ok(reply) = reply {
                    let _ = reply.send().await;
                }
                if let Some(updated) = updated {
                    stats.set(host::STAT_VALUE, updated);
                    let mut delivered = false;
                    for target in [Some(connection), peer].into_iter().flatten() {
                        delivered |= value.notify(target, &updated, false).await.is_ok();
                        delivered |= uart_tx.notify(target, &updated, false).await.is_ok();
                    }
                    if delivered {
                        stats.inc(host::STAT_NOTIFICATIONS);
                    }
                }
            }
            _ => {}
        }
    }
}

fn error(stats: &HostStats, stage: u32) {
    stats.inc(host::STAT_ERRORS);
    stats.set(host::STAT_LAST_ERROR, stage);
}

/// Scan, connect, and run one GATT client cycle against the Android server.
async fn central_cycle(
    stack: &Stack<'_, wchble::hci::SoftController, DefaultPacketPool>,
    central: &mut Central<'_, wchble::hci::SoftController, DefaultPacketPool>,
    scan: &TargetScan<'_>,
    stats: &HostStats,
) {
    scan.found.set(None);
    let mut scanner = Scanner::new(central);
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
        Err(_) => return error(stats, 2),
    };
    let mut waited = 0u32;
    while scan.found.get().is_none() {
        // Bounded: the app is polled four times per RF iteration, so this is
        // roughly ten seconds of scanning; the run budget is 25 s.
        if waited > 6_000 {
            return error(stats, 3);
        }
        waited += 1;
        yield_now().await;
    }
    session.stop().await;
    let target = scan.found.get().expect("target found");

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
            filter_accept_list: core::slice::from_ref(&target),
            phys: PhySet::M1,
            interval: Duration::from_millis(30),
            window: Duration::from_millis(15),
            timeout: Duration::from_secs(0),
            ..Default::default()
        },
    };
    let connection = match central.connect(&connect_config).await {
        Ok(connection) => connection,
        Err(_) => return error(stats, 4),
    };
    stats.inc(host::STAT_CONNECTIONS);
    let client = match GattClient::<_, DefaultPacketPool, 4>::new(stack, &connection).await {
        Ok(client) => client,
        Err(_) => {
            error(stats, 5);
            connection.disconnect();
            while connection.is_connected() {
                yield_now().await;
            }
            return;
        }
    };
    let operations = async {
        let result = gatt_cycle(&client, stats).await;
        connection.disconnect();
        result
    };
    let (_, cycle) = join(client.task(), operations).await;
    stats.inc(host::STAT_DISCONNECTS);
    if cycle.is_ok() {
        stats.inc(host::STAT_OTHER);
    } else {
        error(stats, 6);
    }
}

/// Discovery, read, subscribe, write, and the server's notification.
async fn gatt_cycle<C, P>(client: &GattClient<'_, C, P, 4>, stats: &HostStats) -> Result<(), ()>
where
    C: Controller,
    P: PacketPool,
{
    let services = client
        .services_by_uuid(&SERVICE_UUID)
        .await
        .map_err(|_| error(stats, 0x10))?;
    let service = services.first().ok_or_else(|| error(stats, 0x11))?.clone();
    let characteristic: Characteristic<u32> = client
        .characteristic_by_uuid(&service, &VALUE_UUID)
        .await
        .map_err(|_| error(stats, 0x12))?;

    let mut data = [0u8; 4];
    let len = client
        .read_characteristic(&characteristic, &mut data)
        .await
        .map_err(|_| error(stats, 0x13))?;
    if len != 4 || u32::from_le_bytes(data) != READ_INITIAL {
        error(stats, 0x14);
        return Err(());
    }
    stats.inc(host::STAT_READS);

    let mut listener = client
        .subscribe(&characteristic, false)
        .await
        .map_err(|_| error(stats, 0x15))?;
    stats.inc(host::STAT_SUBSCRIBED);

    client
        .write_characteristic(&characteristic, &WRITE_VALUE.to_le_bytes())
        .await
        .map_err(|_| error(stats, 0x16))?;
    stats.inc(host::STAT_WRITES);

    // The Android fixture notifies the written value back (hardware gate).
    let notification = with_timeout(NOTIFY_TIMEOUT, listener.next())
        .await
        .map_err(|_| error(stats, 0x17))?;
    let bytes = notification.as_ref();
    if bytes.len() != 4 || u32::from_le_bytes(bytes.try_into().unwrap()) != WRITE_VALUE {
        error(stats, 0x18);
        return Err(());
    }
    stats.inc(host::STAT_NOTIFICATIONS);

    let mut echo = [0u8; 4];
    let len = client
        .read_characteristic(&characteristic, &mut echo)
        .await
        .map_err(|_| error(stats, 0x19))?;
    if len != 4 || u32::from_le_bytes(echo) != WRITE_VALUE {
        error(stats, 0x1a);
        return Err(());
    }
    stats.inc(host::STAT_READS);
    Ok(())
}
