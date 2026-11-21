//! X3.4a PP app: two simultaneous Peripheral links.
//!
//! Advertising is re-enabled after the first link so a second central can
//! connect. Writes to the shared characteristic are notified to every link;
//! each connection's CCCD decides delivery.

use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
#[cfg(not(feature = "x2-ext-adv-coex"))]
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use trouble_host::prelude::*;

use crate::host::{self, HostStats, SERVICE_UUID, VALUE_UUID};

const BOND_CAPACITY: usize = 1;

pub async fn run(controller: wchble::hci::SoftController, stats: &HostStats) -> ! {
    stats.phase(host::PHASE_STARTING);
    let mut resources: HostResources<DefaultPacketPool, 2, 2, 1, BOND_CAPACITY> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        // The phone probe scans for this fixed static address.
        .set_random_address(Address::random(host::PP_RANDOM_ADDRESS))
        .build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();

    let mut storage = [0u8; 4];
    let mut uart_rx_storage = [0u8; 4];
    let mut uart_tx_storage = [0u8; 4];
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
    // NUS pipe for the adb-driven phone probe: RX accepts writes, TX notifies.
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

    let app = async {
        loop {
            stats.phase(host::PHASE_ADVERTISING);
            let first = accept(&mut peripheral, &server).await;
            stats.inc(host::STAT_CONNECTIONS);
            stats.phase(host::PHASE_CONNECTED);
            #[cfg(feature = "x2-ext-adv-coex")]
            {
                // Start X2a only after the connectable legacy advertiser has
                // been dropped by `accept`; the link table then owns all RF.
                let ext_task = async {
                    let data = crate::beacon::marker();
                    let params = AdvertisementParameters {
                        primary_phy: PhyKind::Le1M,
                        secondary_phy: PhyKind::Le1M,
                        interval_min: embassy_time::Duration::from_millis(160),
                        interval_max: embassy_time::Duration::from_millis(160),
                        ..AdvertisementParameters::default()
                    };
                    let sets = [AdvertisementSet {
                        params,
                        data: Advertisement::ExtNonconnectableNonscannableUndirected {
                            adv_data: &data,
                            anonymous: false,
                        },
                        address: None,
                    }];
                    let mut handles = AdvertisementSet::handles(&sets);
                    match peripheral.advertise_ext(&sets, &mut handles).await {
                        Ok(_advertiser) => core::future::pending::<()>().await,
                        Err(_) => stats.set(host::STAT_PHASE, host::PHASE_FATAL),
                    }
                };
                let _ = embassy_futures::select::select(
                    serve(&value, &uart_rx, &uart_tx, &first, None, stats),
                    ext_task,
                )
                .await;
                stats.inc(host::STAT_DISCONNECTS);
                continue;
            }
            #[cfg(not(feature = "x2-ext-adv-coex"))]
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
            #[cfg(not(feature = "x2-ext-adv-coex"))]
            stats.inc(host::STAT_CONNECTIONS);
            #[cfg(not(feature = "x2-ext-adv-coex"))]
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
                    // Both notify characteristics on every live link; each CCCD
                    // gates delivery, so the Mac (0x1001) and the phone (NUS)
                    // can subscribe independently.
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
