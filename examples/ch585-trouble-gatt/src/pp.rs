//! X3.4a PP app: two simultaneous Peripheral links.
//!
//! Advertising is re-enabled after the first link so a second central can
//! connect. Writes to the shared characteristic are notified to every link;
//! each connection's CCCD decides delivery.

use core::convert::Infallible;
use core::future::pending;

use embassy_futures::join::join;
#[cfg(any(not(feature = "x2-ext-adv-coex"), feature = "secure"))]
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
#[cfg(feature = "secure")]
use embassy_time::{Duration, Instant, Timer};
use trouble_host::prelude::*;

use crate::host::{self, HostStats, SERVICE_UUID, VALUE_UUID};

#[cfg(not(feature = "secure"))]
const BOND_CAPACITY: usize = 1;
// Two pre-bonded peers must fit alongside each other in the Host table.
#[cfg(feature = "secure")]
const BOND_CAPACITY: usize = crate::bond::MAX_BONDS;

/// Security Request delay: the central's own flow must go first (see the
/// matching constant in `host.rs` for the Android stall rationale).
#[cfg(feature = "secure")]
const SECURITY_REQUEST_DELAY_MS: u64 = 2_000;

#[cfg(feature = "secure")]
const PP_STATS_MAGIC: u32 = 0x5050_5331;
#[cfg(feature = "secure")]
const PP_MODE_COMMISSIONING: u32 = 0;
#[cfg(feature = "secure")]
const PP_MODE_DUAL_LINK: u32 = 1;

/// Dual-link pairing owner (spec `ch585-x3-pp-secure-spec.md` §3). One place
/// decides whether a fresh pairing may start: commissioning until two bonds
/// are persisted, then `set_bondable(false)` refuses new pairing while
/// encrypted links resume from the store.
#[cfg(feature = "secure")]
struct PairingOwner {
    dual_link: bool,
}

#[cfg(feature = "secure")]
impl PairingOwner {
    fn from_boot_bonds() -> Self {
        pp_put(0, PP_STATS_MAGIC);
        pp_put(1, 1);
        let dual_link = crate::bond::boot_bonds().len() >= 2;
        pp_put(
            PP_MODE,
            if dual_link {
                PP_MODE_DUAL_LINK
            } else {
                PP_MODE_COMMISSIONING
            },
        );
        Self { dual_link }
    }

    fn allows_new_pairing(&self) -> bool {
        !self.dual_link
    }
}

// PP_STATS slots: mode (2), accepts_in_dual (3), pairing_refused (4),
// encrypted_events (5), pairs_without_bond (6); 0/1 are magic and version.
#[cfg(feature = "secure")]
const PP_MODE: usize = 2;
#[cfg(feature = "secure")]
const PP_ACCEPTS_IN_DUAL: usize = 3;
#[cfg(feature = "secure")]
const PP_PAIRING_REFUSED: usize = 4;
#[cfg(feature = "secure")]
const PP_ENCRYPTED_EVENTS: usize = 5;
#[cfg(feature = "secure")]
const PP_PAIRS_WITHOUT_BOND: usize = 6;
#[cfg(feature = "secure")]
const PP_PAIRING_FAILED: usize = 7;
#[cfg(feature = "secure")]
const PP_SECURITY_REQ_FAILED: usize = 8;

/// Mode-owner counters the runner reads back over SWD.
#[cfg(feature = "secure")]
#[no_mangle]
pub static mut PP_STATS: [u32; 16] = [0; 16];

#[cfg(feature = "secure")]
fn pp_put(slot: usize, value: u32) {
    // SAFETY: single-threaded example; only the Host poll writes these slots.
    unsafe {
        let stats = core::ptr::addr_of_mut!(PP_STATS).cast::<u32>();
        stats.add(slot).write_volatile(value);
    }
}

#[cfg(feature = "secure")]
fn pp_bump(slot: usize) {
    // SAFETY: see pp_put.
    unsafe {
        let stats = core::ptr::addr_of_mut!(PP_STATS).cast::<u32>();
        let slot_ptr = stats.add(slot);
        let value = slot_ptr.read_volatile();
        slot_ptr.write_volatile(value.wrapping_add(1));
    }
}

pub async fn run(controller: wchble::hci::SoftController, stats: &HostStats) -> ! {
    stats.phase(host::PHASE_STARTING);
    let mut resources: HostResources<DefaultPacketPool, 2, 2, 1, BOND_CAPACITY> =
        HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        // The phone probe scans for this fixed static address.
        .set_random_address(Address::random(host::PP_RANDOM_ADDRESS))
        .build();
    // Restore bonds before advertising: the stack answers a peer's LTK
    // request from this table, so a rebooted device resumes encryption.
    #[cfg(feature = "secure")]
    for record in crate::bond::boot_bonds() {
        match stack.add_bond_information(crate::bond::to_bond(record)) {
            Ok(()) => crate::bond::bump(crate::bond::STAT_ADD_BOND_OK),
            Err(_) => crate::bond::bump(crate::bond::STAT_ADD_BOND_FAIL),
        }
    }
    // The pairing owner is fixed at boot from the persisted bond count; a
    // reset with fewer than two bonds returns to commissioning mode.
    #[cfg(feature = "secure")]
    let owner = PairingOwner::from_boot_bonds();
    #[cfg(feature = "secure")]
    let commissioning = owner.allows_new_pairing();
    // Hand a completed bond to the RF owner, which persists the snapshot
    // between connection events (same flow as the single-link host).
    #[cfg(feature = "secure")]
    let persist_bond = |bond: &BondInformation| {
        crate::bond::echo(bond);
        let snapshot = stack.with_bond_information(|bonds| {
            let mut list = crate::bond::BondSnapshot::new();
            for entry in bonds {
                let _ = list.push(entry.clone());
            }
            list
        });
        crate::bond::set_rl_expected_from_snapshot(&snapshot);
        crate::bond::signals().set_pending(snapshot);
    };
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
            let first = accept(
                &mut peripheral,
                &server,
                #[cfg(feature = "secure")]
                &owner,
            )
            .await;
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
                    serve(
                        &value,
                        &uart_rx,
                        &uart_tx,
                        &first,
                        None,
                        stats,
                        #[cfg(feature = "secure")]
                        &persist_bond,
                        #[cfg(feature = "secure")]
                        commissioning,
                    ),
                    ext_task,
                )
                .await;
                stats.inc(host::STAT_DISCONNECTS);
                continue;
            }
            #[cfg(not(feature = "x2-ext-adv-coex"))]
            let second = match select(
                accept(
                    &mut peripheral,
                    &server,
                    #[cfg(feature = "secure")]
                    &owner,
                ),
                serve(
                    &value,
                    &uart_rx,
                    &uart_tx,
                    &first,
                    None,
                    stats,
                    #[cfg(feature = "secure")]
                    &persist_bond,
                    #[cfg(feature = "secure")]
                    commissioning,
                ),
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
                serve(
                    &value,
                    &uart_rx,
                    &uart_tx,
                    &first,
                    Some(&second),
                    stats,
                    #[cfg(feature = "secure")]
                    &persist_bond,
                    #[cfg(feature = "secure")]
                    commissioning,
                ),
                serve(
                    &value,
                    &uart_rx,
                    &uart_tx,
                    &second,
                    Some(&first),
                    stats,
                    #[cfg(feature = "secure")]
                    &persist_bond,
                    #[cfg(feature = "secure")]
                    commissioning,
                ),
            )
            .await
            {
                Either::First(()) => {
                    stats.inc(host::STAT_DISCONNECTS);
                    serve(
                        &value,
                        &uart_rx,
                        &uart_tx,
                        &second,
                        None,
                        stats,
                        #[cfg(feature = "secure")]
                        &persist_bond,
                        #[cfg(feature = "secure")]
                        commissioning,
                    )
                    .await;
                    stats.inc(host::STAT_DISCONNECTS);
                }
                Either::Second(()) => {
                    stats.inc(host::STAT_DISCONNECTS);
                    serve(
                        &value,
                        &uart_rx,
                        &uart_tx,
                        &first,
                        None,
                        stats,
                        #[cfg(feature = "secure")]
                        &persist_bond,
                        #[cfg(feature = "secure")]
                        commissioning,
                    )
                    .await;
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
    #[cfg(feature = "secure")] owner: &PairingOwner,
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
    // One owner decides pairing permission: commissioning accepts new
    // bonds, dual-link refuses them while stored keys resume encryption.
    #[cfg(feature = "secure")]
    {
        let allow = owner.allows_new_pairing();
        if !allow {
            pp_bump(PP_ACCEPTS_IN_DUAL);
            pp_bump(PP_PAIRING_REFUSED);
        }
        connection.set_bondable(allow).expect("set_bondable");
    }
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
    #[cfg(feature = "secure")] persist: &dyn Fn(&BondInformation),
    #[cfg(feature = "secure")] commissioning: bool,
) {
    // Commissioning may need the delayed peripheral Security Request to make
    // a macOS central pair (host.rs rationale). Dual-link never asks.
    #[cfg(feature = "secure")]
    let mut security_deadline =
        commissioning.then(|| Instant::now() + Duration::from_millis(SECURITY_REQUEST_DELAY_MS));
    loop {
        #[cfg(feature = "secure")]
        let event = {
            if security_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                security_deadline = None;
                let unencrypted = matches!(
                    connection.raw().security_level(),
                    Ok(SecurityLevel::NoEncryption)
                );
                if unencrypted && connection.raw().request_security().is_err() {
                    pp_bump(PP_SECURITY_REQ_FAILED);
                }
            }
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
        let event = connection.next().await;
        #[cfg(feature = "secure")]
        let Some(event) = event
        else {
            continue;
        };
        match event {
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
            #[cfg(feature = "secure")]
            GattConnectionEvent::PairingComplete { bond, .. } => match bond {
                Some(bond) => persist(&bond),
                None => pp_bump(PP_PAIRS_WITHOUT_BOND),
            },
            #[cfg(feature = "secure")]
            GattConnectionEvent::Encrypted { .. } => pp_bump(PP_ENCRYPTED_EVENTS),
            #[cfg(feature = "secure")]
            GattConnectionEvent::PairingFailed(_) => pp_bump(PP_PAIRING_FAILED),
            _ => {}
        }
    }
}
