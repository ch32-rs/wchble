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
#[cfg(feature = "secure")]
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_futures::yield_now;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::{with_timeout, Duration, Instant, Timer};
use trouble_host::advertise::AdStructure;
use trouble_host::prelude::*;

use crate::host::{self, HostStats, SERVICE_UUID, VALUE_UUID};

#[cfg(not(feature = "secure"))]
const BOND_CAPACITY: usize = 1;
/// Secure builds restore every stored bond, and the scan IRKs must match.
#[cfg(feature = "secure")]
const BOND_CAPACITY: usize = crate::bond::MAX_BONDS;
/// The fixture advertises this name; `READ_INITIAL` is the C1 value.
#[cfg(feature = "hogp")]
pub const TARGET_NAME: &[u8] = b"wch585-h1";
#[cfg(not(feature = "hogp"))]
pub const TARGET_NAME: &[u8] = b"wch585-c1";
pub const READ_INITIAL: u32 = 0x2a;
pub const WRITE_VALUE: u32 = 0x2b;
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(2);
/// D1 waits for 100 input reports, or gives up after this long.
#[cfg(feature = "hogp")]
const HOGP_BUDGET: Duration = Duration::from_secs(15);
/// C3: scan/connect budget, bounded attempts and the backoff between them.
const SCAN_BUDGET: Duration = Duration::from_secs(8);
const CONNECT_ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// A3 pairing window: open from `connect()` until encryption resolves.
#[cfg(feature = "secure")]
static PAIRING_WINDOW: AtomicBool = AtomicBool::new(false);
/// The peer rejected the stored LTK; the next connect must pair fresh.
#[cfg(feature = "secure")]
static BOND_LOST: AtomicBool = AtomicBool::new(false);
/// A deleted peer bond costs one reconnect: pairing on the failed link keeps
/// the peer's STK empty (observed on Android's SMP).
#[cfg(feature = "secure")]
const RECOVERY_ROUNDS: u32 = 2;

/// Polls inside the window may hold the Host for the LESC P-256 work.
#[cfg(feature = "secure")]
pub fn pairing_window() -> bool {
    PAIRING_WINDOW.load(Ordering::Relaxed)
}

/// B1 evidence: the addresses the Host matched for this connection.
#[cfg(feature = "hogp")]
#[no_mangle]
static mut PEER_DIAG: [u32; 10] = [0; 10];

#[cfg(feature = "hogp")]
fn diag_put(index: usize, value: u32) {
    // SAFETY: single-threaded example; the Host task is the only writer.
    unsafe {
        core::ptr::addr_of_mut!(PEER_DIAG)
            .cast::<u32>()
            .add(index)
            .write_volatile(value)
    }
}

/// `base`: kind + bytes 0..2; `base + 1`: bytes 3..5.
#[cfg(feature = "hogp")]
fn diag_address(base: usize, address: &Address) {
    let bytes = address.addr.into_inner();
    diag_put(
        base,
        u32::from(address.kind.into_inner())
            | u32::from(bytes[0]) << 8
            | u32::from(bytes[1]) << 16
            | u32::from(bytes[2]) << 24,
    );
    diag_put(
        base + 1,
        u32::from(bytes[3]) | u32::from(bytes[4]) << 8 | u32::from(bytes[5]) << 16,
    );
}

/// B2 evidence: the peer rejected the stored LTK at word 8.
#[cfg(feature = "hogp")]
fn diag_bond_lost(removed: bool) {
    // SAFETY: single-threaded example; the Host task is the only writer.
    unsafe {
        let slot = core::ptr::addr_of_mut!(PEER_DIAG).cast::<u32>().add(8);
        let value = slot.read_volatile();
        slot.write_volatile(value | 1 | u32::from(removed) << 1);
    }
}

/// Record why the Host did or did not recognise the peer as bonded.
#[cfg(feature = "hogp")]
fn record_peer_diag(connection: &Connection<'_, DefaultPacketPool>, target: Option<Address>) {
    let peer = connection.peer_address();
    let identity = connection.peer_identity();
    let stored = crate::bond::boot_bonds().first().map(crate::bond::to_bond);
    // The observed advertising address is what the controller had to resolve.
    let observed = target.map(|address| address.addr).unwrap_or(peer.addr);
    let resolves = stored
        .as_ref()
        .and_then(|bond| bond.identity.irk)
        .is_some_and(|irk| irk.resolve_address(&observed));
    let matches = stored
        .as_ref()
        .is_some_and(|bond| bond.identity.match_identity(&identity));
    diag_put(0, 0x5044_5231);
    diag_put(
        1,
        u32::from(connection.is_bonded_peer())
            | u32::from(resolves) << 1
            | u32::from(matches) << 2
            | u32::from(stored.is_some()) << 3
            | u32::from(identity.addr != peer) << 4,
    );
    diag_address(2, &peer);
    diag_address(4, &identity.addr);
    if let Some(target) = target {
        diag_address(6, &target);
    }
    diag_put(9, 0x5044_5232);
}

struct TargetScan<'a> {
    stats: &'a HostStats,
    found: Cell<Option<Address>>,
    /// Bonded peer IRKs: a rotating RPA still identifies the peer (C3).
    #[cfg(feature = "secure")]
    irks: [Option<IdentityResolvingKey>; BOND_CAPACITY],
}

impl EventHandler for TargetScan<'_> {
    fn on_adv_reports(&self, mut reports: LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = reports.next() {
            self.stats.inc(host::STAT_OTHER);
            let mut matched = AdStructure::decode(report.data).any(|ad| {
                matches!(
                    ad,
                    Ok(AdStructure::CompleteLocalName(name)) if name == TARGET_NAME
                )
            });
            #[cfg(feature = "secure")]
            if !matched && report.addr_kind == AddrKind::RANDOM {
                matched = self
                    .irks
                    .iter()
                    .flatten()
                    .any(|irk| irk.resolve_address(&report.addr));
            }
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
    // Restore bonds before either role runs: the Host answers LTK requests
    // from this table, including the Central's bonded reconnect.
    #[cfg(feature = "secure")]
    for record in crate::bond::boot_bonds() {
        match stack.add_bond_information(crate::bond::to_bond(record)) {
            Ok(()) => crate::bond::bump(crate::bond::STAT_ADD_BOND_OK),
            Err(_) => crate::bond::bump(crate::bond::STAT_ADD_BOND_FAIL),
        }
    }
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

    #[cfg(feature = "secure")]
    let mut irks = [None; BOND_CAPACITY];
    #[cfg(feature = "secure")]
    for (slot, record) in irks.iter_mut().zip(crate::bond::boot_bonds()) {
        *slot = record.irk.and_then(IdentityResolvingKey::from_le_bytes);
    }
    let scan = TargetScan {
        stats,
        found: Cell::new(None),
        #[cfg(feature = "secure")]
        irks,
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

/// Central Host events while the GATT work runs. The peer's L2CAP parameter
/// update must be answered with HCI 0x2013, and secure builds keep the bond
/// table current here for the RF owner to persist.
async fn connection_events(
    connection: &Connection<'_, DefaultPacketPool>,
    stack: &Stack<'_, wchble::hci::SoftController, DefaultPacketPool>,
    stats: &HostStats,
) {
    loop {
        match connection.next().await {
            ConnectionEvent::Disconnected { .. } => {
                #[cfg(feature = "secure")]
                PAIRING_WINDOW.store(false, Ordering::Relaxed);
                return;
            }
            ConnectionEvent::RequestConnectionParams(request) => {
                #[cfg(feature = "hogp")]
                {
                    let params = request.params();
                    crate::hogp::note_interval_request(
                        params.min_connection_interval,
                        params.max_connection_interval,
                    );
                }
                match request.accept(None, stack).await {
                    Ok(()) => stats.inc(host::STAT_UPDATE_ACCEPTED),
                    Err(_) => error(stats, 9),
                }
            }
            #[cfg(feature = "hogp")]
            ConnectionEvent::ConnectionParamsUpdated { conn_interval, .. } => {
                crate::hogp::note_interval_applied(conn_interval);
            }
            #[cfg(feature = "secure")]
            ConnectionEvent::BondLost => {
                // The peer rejected the stored LTK (it deleted its bond).
                // Drop the stale entry and end this link: Android cannot
                // complete a re-pairing on a link whose bonded encryption
                // already failed, so the recovery has to be a fresh connect.
                let identity = connection.peer_identity();
                let removed = stack.remove_bond_information(identity).is_ok();
                #[cfg(feature = "hogp")]
                diag_bond_lost(removed);
                if removed {
                    let snapshot = stack.with_bond_information(|bonds| {
                        let mut list = crate::bond::BondSnapshot::new();
                        for entry in bonds {
                            let _ = list.push(entry.clone());
                        }
                        list
                    });
                    crate::bond::set_rl_expected_from_snapshot(&snapshot);
                    crate::bond::signals().set_pending(snapshot);
                }
                BOND_LOST.store(true, Ordering::Relaxed);
                connection.disconnect();
            }
            #[cfg(feature = "secure")]
            ConnectionEvent::PairingComplete { bond, .. } => {
                // Encryption Change may arrive first; the encrypted state is
                // the stronger fact.
                if stats.word(host::STAT_SECURITY) != host::SECURITY_ENCRYPTED {
                    stats.set(host::STAT_SECURITY, host::SECURITY_PAIRED);
                }
                match bond {
                    Some(bond) => {
                        crate::bond::echo(&bond);
                        // Trouble already inserted it; hand the full list to
                        // the RF owner, which writes it between events.
                        let snapshot = stack.with_bond_information(|bonds| {
                            let mut list = crate::bond::BondSnapshot::new();
                            for entry in bonds {
                                let _ = list.push(entry.clone());
                            }
                            list
                        });
                        crate::bond::set_rl_expected_from_snapshot(&snapshot);
                        crate::bond::signals().set_pending(snapshot);
                    }
                    None => crate::bond::bump(crate::bond::STAT_PAIRS_WITHOUT_BOND),
                }
            }
            #[cfg(feature = "secure")]
            ConnectionEvent::Encrypted { .. } => {
                stats.set(host::STAT_SECURITY, host::SECURITY_ENCRYPTED);
                PAIRING_WINDOW.store(false, Ordering::Relaxed);
            }
            #[cfg(feature = "secure")]
            ConnectionEvent::PairingFailed(cause) => {
                stats.set(host::STAT_SECURITY, host::SECURITY_FAILED);
                PAIRING_WINDOW.store(false, Ordering::Relaxed);
                // Diagnose the cause: 0x100 + SMP reason, 0x200 + generic.
                let code = match cause {
                    trouble_host::Error::Security(reason) => 0x100 | u32::from(u8::from(reason)),
                    trouble_host::Error::Timeout => 0x2f0,
                    _ => 0x2f1,
                };
                error(stats, code);
            }
            _ => {}
        }
    }
}

/// One scan window and one HCI create-connection attempt.
async fn connect_target<'d>(
    central: &mut Central<'d, wchble::hci::SoftController, DefaultPacketPool>,
    scan: &TargetScan<'_>,
) -> Result<Connection<'d, DefaultPacketPool>, u32> {
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
    let session = scanner.scan(&scan_config).await.map_err(|_| 2u32)?;
    let found = with_timeout(SCAN_BUDGET, async {
        while scan.found.get().is_none() {
            yield_now().await;
        }
        scan.found.get()
    })
    .await;
    session.stop().await;
    let mut target = found.map_err(|_| 3u32)?.ok_or(3u32)?;
    // BondLost dropped the bonded rewrite; without the identity here, a
    // mid-scan RPA rotation strands the initiator on a stale target.
    #[cfg(feature = "secure")]
    if target.kind.as_raw() & 1 == 1 {
        if let Some((kind, identity)) =
            crate::bond::resolve_identity_boot(target.addr.into_inner())
        {
            target = Address::new(AddrKind::new(kind & 1), BdAddr::new(identity));
        }
    }
    // A1: the Host only uses initiator policy 1 when the accept list holds
    // more than one member. The second member never advertises, so the connect
    // still targets `target` and proves the list (not Peer_Address) matched.
    let accept = [target, Address::new(AddrKind::new(0), BdAddr::new([0xAA; 6]))];
    let connect_config = ConnectConfig {
        connect_params: RequestedConnParams {
            min_connection_interval: Duration::from_millis(30),
            max_connection_interval: Duration::from_millis(30),
            max_latency: 0,
            min_event_length: Duration::from_micros(0),
            max_event_length: Duration::from_micros(0),
            // A3: 4 s in every pairing window (the Central never pairs alone).
            supervision_timeout: Duration::from_millis(4_000),
        },
        scan_config: ScanConfig {
            active: false,
            filter_accept_list: &accept,
            phys: PhySet::M1,
            interval: Duration::from_millis(30),
            window: Duration::from_millis(15),
            timeout: Duration::from_secs(0),
            ..Default::default()
        },
    };
    central.connect(&connect_config).await.map_err(|_| 4u32)
}

/// Wait for an encrypted link, treating a timeout as `error(11)`. The level
/// comes from the Host manager, so it holds even before the pump sees Encrypted.
#[cfg(feature = "secure")]
async fn wait_for_security(
    connection: &Connection<'_, DefaultPacketPool>,
    stats: &HostStats,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let encrypted = matches!(connection.security_level(),
            Ok(level) if !matches!(level, SecurityLevel::NoEncryption));
        if encrypted {
            // The manager state is the authority; a dropped Encrypted event
            // must not fail the gate's security check.
            stats.set(host::STAT_SECURITY, host::SECURITY_ENCRYPTED);
            return true;
        }
        if !connection.is_connected() {
            // A link torn down on purpose (BondLost) never encrypts; give up
            // now instead of logging a timeout later.
            return false;
        }
        if stats.word(host::STAT_SECURITY) == host::SECURITY_FAILED {
            return false;
        }
        if Instant::now() >= deadline {
            error(stats, 11);
            return false;
        }
        Timer::after(Duration::from_millis(20)).await;
    }
}

/// Scan, connect, and run one GATT client cycle against the Android server.
#[cfg_attr(not(feature = "secure"), allow(unused_variables, unused_assignments))]
async fn central_cycle(
    stack: &Stack<'_, wchble::hci::SoftController, DefaultPacketPool>,
    central: &mut Central<'_, wchble::hci::SoftController, DefaultPacketPool>,
    scan: &TargetScan<'_>,
    stats: &HostStats,
) {
    let mut round = 0;
    loop {
        round += 1;
        let mut attempt = 0;
        let connection = loop {
            attempt += 1;
            match connect_target(central, scan).await {
                Ok(connection) => break connection,
                Err(stage) => {
                    error(stats, stage);
                    if attempt == CONNECT_ATTEMPTS {
                        return;
                    }
                    Timer::after(RETRY_DELAY).await;
                }
            }
        };
        stats.inc(host::STAT_CONNECTIONS);
        #[cfg(feature = "hogp")]
        record_peer_diag(&connection, scan.found.get());
        #[cfg(feature = "secure")]
        PAIRING_WINDOW.store(true, Ordering::Relaxed);
        // `bondable` only sets the Bonding flag if pairing has to restart; a
        // working bond still re-encrypts without pairing. It must stay set:
        // a peer that deleted its bond gets 0x06 once, and the recovery pairing
        // has to persist a replacement or every reconnect repeats it.
        #[cfg(feature = "secure")]
        if connection.set_bondable(true).is_err() {
            error(stats, 7);
        }
        // The pump must be live while `GattClient::new` enables encryption with a
        // bonded peer: a deleted peer bond is reported as `BondLost`, and the stale
        // entry has to be gone before the recovery pairing installs its STK.
        let session = async {
            let client = match GattClient::<_, DefaultPacketPool, 4>::new(stack, &connection).await {
                Ok(client) => client,
                Err(_) => {
                    error(stats, 5);
                    connection.disconnect();
                    while connection.is_connected() {
                        yield_now().await;
                    }
                    return Err(());
                }
            };
            // First pairing: the Central is the initiator, so it sends the Pairing
            // Request itself. For a bonded peer this joins the encryption that
            // `GattClient::new` (or the peer's Security Request) already started.
            #[cfg(feature = "secure")]
            if matches!(connection.security_level(), Ok(SecurityLevel::NoEncryption)) {
                // Open the A3 pairing window first: the Host's P-256 keypair poll
                // runs inside `request_security` and belongs to pairing.
                stats.set(host::STAT_SECURITY, host::SECURITY_REQUESTED);
                // `Busy` means an encryption is already running; let the wait observe
                // its result instead of failing the link.
                match connection.request_security() {
                    Ok(()) | Err(trouble_host::Error::Busy) => {}
                    Err(cause) => {
                        stats.set(host::STAT_SECURITY, host::SECURITY_FAILED);
                        // Diagnose which failure: 0x80 + kind, security reasons 0x100+.
                        let code = match cause {
                            trouble_host::Error::Security(reason) => 0x100 | u32::from(u8::from(reason)),
                            trouble_host::Error::InvalidState => 0x82,
                            trouble_host::Error::Disconnected => 0x83,
                            trouble_host::Error::NotSupported => 0x84,
                            _ => 0x8f,
                        };
                        error(stats, code);
                    }
                }
            }
            let operations = async {
                // Protected attributes (CCCDs, reports) need the link encrypted; pair
                // before discovery. Inside the join so the pump drains pairing events.
                #[cfg(feature = "secure")]
                if !wait_for_security(&connection, stats).await {
                    connection.disconnect();
                    return Err(());
                }
                #[cfg(feature = "hogp")]
                let result = crate::hogp::cycle(&client, HOGP_BUDGET).await;
                #[cfg(not(feature = "hogp"))]
                let result = gatt_cycle(&client, stats).await;
                connection.disconnect();
                result
            };
            let (_, cycle) = join(client.task(), operations).await;
            cycle
        };
        let (cycle, _) = join(session, connection_events(&connection, stack, stats)).await;
        #[cfg(feature = "secure")]
        PAIRING_WINDOW.store(false, Ordering::Relaxed);
        stats.inc(host::STAT_DISCONNECTS);
        #[cfg(feature = "secure")]
        if BOND_LOST.load(Ordering::Relaxed) && round < RECOVERY_ROUNDS {
            // Reconnect so the fresh pairing starts without the stale key.
            BOND_LOST.store(false, Ordering::Relaxed);
            Timer::after(RETRY_DELAY).await;
            continue;
        }
        if cycle.is_ok() {
            stats.inc(host::STAT_OTHER);
        } else if stats.word(host::STAT_ERRORS) == 0 {
            // Keep an earlier, more specific code visible in `last_error`.
            error(stats, 6);
        } else {
            stats.inc(host::STAT_ERRORS);
        }
        break;
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
