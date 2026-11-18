//! X3.4a PP app: two simultaneous Peripheral links.
//!
//! Advertising is re-enabled after the first link so a second central can
//! connect. Writes to the shared characteristic are notified to every link;
//! each connection's CCCD decides delivery.

use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use trouble_host::prelude::*;

use crate::host::{self, HostStats, SERVICE_UUID, VALUE_UUID};

const BOND_CAPACITY: usize = 1;

pub async fn run(controller: wchble::hci::SoftController, stats: &HostStats) -> ! {
    stats.phase(host::PHASE_STARTING);
    let mut resources: HostResources<DefaultPacketPool, 2, 2, 1, BOND_CAPACITY> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources).build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();

    let mut storage = [0u8; 4];
    let mut table: AttributeTable<'_, NoopRawMutex, 24> = AttributeTable::new();
    // The macOS client matches the advertised local name.
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
    let server = AttributeServer::<NoopRawMutex, DefaultPacketPool, 24, 2>::new(table);

    let app = async {
        loop {
            stats.phase(host::PHASE_ADVERTISING);
            let first = accept(&mut peripheral, &server).await;
            stats.inc(host::STAT_CONNECTIONS);
            stats.phase(host::PHASE_CONNECTED);
            // Keep advertising for the second slot while serving the first.
            let second = match select(
                accept(&mut peripheral, &server),
                serve(&value, &first, None, stats),
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
                serve(&value, &first, Some(&second), stats),
                serve(&value, &second, Some(&first), stats),
            )
            .await
            {
                Either::First(()) => {
                    stats.inc(host::STAT_DISCONNECTS);
                    serve(&value, &second, None, stats).await;
                    stats.inc(host::STAT_DISCONNECTS);
                }
                Either::Second(()) => {
                    stats.inc(host::STAT_DISCONNECTS);
                    serve(&value, &first, None, stats).await;
                    stats.inc(host::STAT_DISCONNECTS);
                }
            }
        }
    };
    let _ = join(runner.run(), app).await;
    stats.set(host::STAT_PHASE, host::PHASE_FATAL);
    match pending::<Infallible>().await {}
}

async fn accept<'d, 's, C: Controller>(
    peripheral: &mut Peripheral<'d, C, DefaultPacketPool>,
    server: &'s AttributeServer<'_, NoopRawMutex, DefaultPacketPool, 24, 2>,
) -> GattConnection<'d, 's, DefaultPacketPool> {
    // Flags plus the local name the macOS client matches exactly.
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
                    let ok = value.notify(connection, &updated, false).await.is_ok();
                    let peer_ok = match peer {
                        Some(peer) => value.notify(peer, &updated, false).await.is_ok(),
                        None => false,
                    };
                    if ok || peer_ok {
                        stats.inc(host::STAT_NOTIFICATIONS);
                    }
                }
            }
            _ => {}
        }
    }
}
