//! Capacity-2 Trouble Host fixture: one Host, two connections over the
//! two-slot soft HCI. The GATT database is deliberately tiny (one read/write
//! characteristic) so the test can isolate routing and close behaviour.

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use trouble_host::attribute::AttributeTable;
use trouble_host::prelude::*;

use wchble::hci::SoftController;

pub const SERVICE_UUID: u16 = 0xffe0;
pub const VALUE_UUID: u16 = 0xffe1;
pub const ADDRESS: [u8; 6] = [0x22, 0x00, 0x00, 0xee, 0xff, 0xc2];

pub const PHASE_ADVERTISING: u32 = 1;
pub const PHASE_WAIT_SECOND: u32 = 2;
pub const PHASE_TWO_CONNECTED: u32 = 3;

#[derive(Default)]
pub struct Stats {
    pub connections: AtomicU32,
    pub disconnects: AtomicU32,
    pub phase: AtomicU32,
    pub writes: AtomicU32,
}

impl Stats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn connections(&self) -> u32 {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn disconnects(&self) -> u32 {
        self.disconnects.load(Ordering::SeqCst)
    }

    pub fn phase(&self) -> u32 {
        self.phase.load(Ordering::SeqCst)
    }
}

pub async fn run(controller: SoftController, stats: &Stats) -> ! {
    let mut resources: HostResources<DefaultPacketPool, 2, 2, 1, 1> = HostResources::new();
    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(Address::random(ADDRESS))
        .build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();

    let mut storage = [0u8; 4];
    let mut table: AttributeTable<'_, NoopRawMutex, 8> = AttributeTable::new();
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
    let server = AttributeServer::<NoopRawMutex, DefaultPacketPool, 8, 2>::new(table);

    let app = async {
        loop {
            stats.phase.store(PHASE_ADVERTISING, Ordering::SeqCst);
            let first = accept(&mut peripheral, &server).await;
            stats.connections.fetch_add(1, Ordering::SeqCst);
            stats.phase.store(PHASE_WAIT_SECOND, Ordering::SeqCst);
            // Serve the first link while waiting for the second: a single
            // connection must work even if no peer ever follows.
            let second = match select(
                accept(&mut peripheral, &server),
                serve(&value, &first, None, stats),
            )
            .await
            {
                Either::First(second) => second,
                Either::Second(()) => {
                    stats.disconnects.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
            };
            stats.connections.fetch_add(1, Ordering::SeqCst);
            stats.phase.store(PHASE_TWO_CONNECTED, Ordering::SeqCst);

            match select(
                serve(&value, &first, Some(&second), stats),
                serve(&value, &second, Some(&first), stats),
            )
            .await
            {
                Either::First(()) => {
                    stats.disconnects.fetch_add(1, Ordering::SeqCst);
                    serve(&value, &second, None, stats).await;
                    stats.disconnects.fetch_add(1, Ordering::SeqCst);
                }
                Either::Second(()) => {
                    stats.disconnects.fetch_add(1, Ordering::SeqCst);
                    serve(&value, &first, None, stats).await;
                    stats.disconnects.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    };
    // A controller error ends the Host; the fixture observes phase 0 and stops.
    let _ = join(runner.run(), app).await;
    stats.phase.store(0, Ordering::SeqCst);
    loop {
        core::future::pending::<()>().await;
    }
}

async fn accept<'d, 's, C: Controller>(
    peripheral: &mut Peripheral<'d, C, DefaultPacketPool>,
    server: &'s AttributeServer<'_, NoopRawMutex, DefaultPacketPool, 8, 2>,
) -> GattConnection<'d, 's, DefaultPacketPool> {
    // Connectable legacy advertising requires the flags field first.
    let adv_data = [0x02, 0x01, 0x06];
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

/// Serve one connection until it disconnects. `peer` is the other live link,
/// if any: a write is notified to every connection, and each connection's
/// CCCD decides delivery.
async fn serve<P: PacketPool>(
    value: &Characteristic<u32>,
    connection: &GattConnection<'_, '_, P>,
    peer: Option<&GattConnection<'_, '_, P>>,
    stats: &Stats,
) {
    loop {
        match connection.next().await {
            GattConnectionEvent::Disconnected { .. } => return,
            GattConnectionEvent::Gatt { event } => {
                let mut updated = None;
                let reply = match &event {
                    GattEvent::Write(write) if write.handle() == value.handle => {
                        stats.writes.fetch_add(1, Ordering::SeqCst);
                        updated = write.value(value).ok();
                        event.accept()
                    }
                    _ => event.accept(),
                };
                if let Ok(reply) = reply {
                    let _ = reply.send().await;
                }
                // Notify every link; each connection's CCCD gates delivery.
                if let Some(updated) = updated {
                    let _ = value.notify(connection, &updated, false).await;
                    if let Some(peer) = peer {
                        let _ = value.notify(peer, &updated, false).await;
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::pin::{pin, Pin};
    use core::task::{Context, Waker};

    use wchble::hci::{BridgeError, ConnectionInfo, RadioRequest, SoftRunner};

    use super::*;

    const PUMP_LIMIT: usize = 4096;
    const CONNECT_A: u16 = 1;
    const CONNECT_B: u16 = 2;

    struct Fixture<'a, F: Future> {
        host: Pin<&'a mut F>,
        stats: &'a Stats,
        controller: SoftRunner,
    }

    impl<F: Future> Fixture<'_, F> {
        fn pump(&mut self) {
            let mut cx = Context::from_waker(Waker::noop());
            let _ = self.host.as_mut().poll(&mut cx);
            assert_ne!(self.stats.phase(), 0, "Host runner ended");
            self.controller.pump_once();
            for slot in 0..2 {
                let Some(request) = self
                    .controller
                    .link_bridge_mut(slot)
                    .unwrap()
                    .take_radio_request()
                else {
                    continue;
                };
                match request {
                    RadioRequest::Reset => {
                        self.controller
                            .link_bridge_mut(slot)
                            .unwrap()
                            .reset_finished();
                        self.controller.reset_radio_stopped();
                    }
                    RadioRequest::Disconnect { reason } => {
                        panic!("unexpected Host disconnect request: {reason:#04x}");
                    }
                }
            }
        }

        fn until(&mut self, label: &str, ready: impl Fn(&Self) -> bool) {
            for _ in 0..PUMP_LIMIT {
                self.pump();
                if ready(self) {
                    return;
                }
            }
            panic!(
                "{label}: exceeded {PUMP_LIMIT} pumps (phase {}, connections {}, disconnects {})",
                self.stats.phase(),
                self.stats.connections(),
                self.stats.disconnects(),
            );
        }

        fn connect(&mut self, slot: u8, handle: u16) {
            assert!(
                self.controller.adv_enabled(),
                "slot {slot} handle {handle}: Host is not advertising (phase {}, connections {})",
                self.stats.phase(),
                self.stats.connections(),
            );
            self.controller.ll.adv.enabled = false;
            let target = self.stats.connections() + 1;
            self.controller
                .link_bridge_mut(slot)
                .unwrap()
                .connected(ConnectionInfo {
                    handle,
                    role: wchble::ll::Role::Peripheral,
                    peer_address_type: 1,
                    peer_address: [1, 2, 3, 4, handle as u8, 0xc6],
                    interval: 24,
                    latency: 0,
                    supervision_timeout: 200,
                    master_clock_accuracy: 0,
                    peer_rpa: None,
                    local_rpa: None,
                    peer_identity: None,
                })
                .unwrap();
            self.until("Host accepts the connection", |f| {
                f.stats.connections() == target
            });
        }

        fn inject(&mut self, slot: u8, att: &[u8]) {
            let mut l2cap = Vec::from((att.len() as u16).to_le_bytes());
            l2cap.extend_from_slice(&4u16.to_le_bytes());
            l2cap.extend_from_slice(att);
            for _ in 0..PUMP_LIMIT {
                match self
                    .controller
                    .link_bridge_mut(slot)
                    .unwrap()
                    .receive_acl(2, &l2cap)
                {
                    Ok(()) => return,
                    Err(BridgeError::Full) => self.pump(),
                    Err(error) => panic!("receive_acl: {error:?}"),
                }
            }
            panic!("bridge never accepted an ATT request");
        }

        fn take_replies(&mut self, slot: u8, out: &mut Vec<Vec<u8>>) -> bool {
            let mut progress = false;
            loop {
                let Some(tx) = self.controller.link_bridge_mut(slot).unwrap().take_tx_acl() else {
                    break;
                };
                assert!(
                    self.controller
                        .link_bridge_mut(slot)
                        .unwrap()
                        .ack_tx(tx.tag),
                    "duplicate ACK returned a credit"
                );
                assert_eq!(tx.llid, 2, "one ATT PDU per ACL packet in this fixture");
                let l2cap_len = u16::from_le_bytes([tx.bytes[0], tx.bytes[1]]) as usize;
                assert_eq!(tx.len, 4 + l2cap_len);
                assert_eq!(&tx.bytes[2..4], &4u16.to_le_bytes());
                out.push(tx.bytes[4..tx.len].to_vec());
                progress = true;
            }
            progress
        }

        fn burst(&mut self, slot: u8) -> Vec<Vec<u8>> {
            let mut replies = Vec::new();
            let mut quiet = 0;
            for _ in 0..PUMP_LIMIT {
                self.pump();
                let progress = self.take_replies(slot, &mut replies);
                quiet = if progress { 0 } else { quiet + 1 };
                if !replies.is_empty() && quiet >= 8 {
                    return replies;
                }
            }
            panic!("ATT burst did not settle: {replies:02x?}");
        }

        fn exchange(&mut self, slot: u8, att: &[u8], count: usize) -> Vec<Vec<u8>> {
            self.inject(slot, att);
            let mut replies = Vec::new();
            for _ in 0..PUMP_LIMIT {
                self.pump();
                self.take_replies(slot, &mut replies);
                if replies.len() >= count {
                    return replies;
                }
            }
            panic!("ATT exchange on slot {slot} timed out: {att:02x?} -> {replies:02x?}");
        }

        fn find_value_handle(&mut self, slot: u8) -> u16 {
            let [lo, hi] = VALUE_UUID.to_le_bytes();
            // Read By Type over every handle: characteristic declarations.
            self.inject(slot, &[0x08, 1, 0, 0xff, 0xff, 0x03, 0x28]);
            let replies = self.burst(slot);
            // The burst is a Read By Type probe; parse every characteristic
            // declaration response for our 16-bit UUID.
            for reply in &replies {
                if reply.len() < 2 || reply[0] != 0x09 {
                    continue;
                }
                let stride = reply[1] as usize;
                if stride == 0 {
                    continue;
                }
                for entry in reply[2..].chunks_exact(stride) {
                    if entry.len() >= 7 && entry[5] == lo && entry[6] == hi {
                        return u16::from_le_bytes([entry[3], entry[4]]);
                    }
                }
            }
            panic!("value characteristic not found: {replies:02x?}");
        }

        fn read(&mut self, slot: u8, handle: u16) -> Vec<u8> {
            let [lo, hi] = handle.to_le_bytes();
            let replies = self.exchange(slot, &[0x0a, lo, hi], 1);
            assert_eq!(replies[0][0], 0x0b);
            replies[0][1..].to_vec()
        }

        fn write(&mut self, slot: u8, handle: u16, value: &[u8]) -> Vec<Vec<u8>> {
            let [lo, hi] = handle.to_le_bytes();
            let mut request = vec![0x12, lo, hi];
            request.extend_from_slice(value);
            let replies = self.exchange(slot, &request, 1);
            assert_eq!(replies[0], [0x13]);
            replies
        }

        fn subscribe(&mut self, slot: u8, cccd: u16, enable: bool) {
            let [lo, hi] = cccd.to_le_bytes();
            let value = u16::from(enable).to_le_bytes();
            let request = [0x12, lo, hi, value[0], value[1]];
            let replies = self.exchange(slot, &request, 1);
            assert_eq!(replies[0], [0x13]);
        }

        /// Pump until the link has been quiet for a few rounds and return every
        /// ATT PDU it produced.
        fn collect(&mut self, slot: u8) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            let mut quiet = 0;
            for _ in 0..PUMP_LIMIT {
                self.pump();
                if self.take_replies(slot, &mut out) {
                    quiet = 0;
                } else {
                    quiet += 1;
                }
                if quiet >= 8 {
                    break;
                }
            }
            out
        }

        /// Hand one raw ACL fragment to a link, retrying while its queue is full.
        fn inject_fragment(&mut self, slot: u8, llid: u8, payload: &[u8]) {
            for _ in 0..PUMP_LIMIT {
                match self
                    .controller
                    .link_bridge_mut(slot)
                    .unwrap()
                    .receive_acl(llid, payload)
                {
                    Ok(()) => return,
                    Err(BridgeError::Full) => self.pump(),
                    Err(error) => panic!("receive_acl: {error:?}"),
                }
            }
            panic!("bridge never accepted a fragment");
        }
    }

    /// Value carried by an ATT Handle Value Notification (0x1b) for a u32.
    fn notification_value(pdu: &[u8]) -> Option<u32> {
        (pdu.len() >= 7 && pdu[0] == 0x1b)
            .then(|| u32::from_le_bytes([pdu[3], pdu[4], pdu[5], pdu[6]]))
    }

    fn l2cap(att: &[u8]) -> Vec<u8> {
        let mut l2cap = Vec::from((att.len() as u16).to_le_bytes());
        l2cap.extend_from_slice(&4u16.to_le_bytes());
        l2cap.extend_from_slice(att);
        l2cap
    }

    #[test]
    fn two_connections_interleave_and_close_isolates() {
        let _guard = crate::serialize();
        let stats = Stats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(run(wchble::hci::new(), &stats));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
        };

        fixture.until("Host starts advertising", |f| f.controller.adv_enabled());
        fixture.connect(0, CONNECT_A);
        fixture.until("Host advertises the second slot", |f| {
            f.stats.phase() == PHASE_WAIT_SECOND && f.controller.adv_enabled()
        });
        // A single connection must be served while the Host waits for the
        // second one, not only after both have arrived.
        let handle_a = fixture.find_value_handle(0);
        assert_eq!(fixture.read(0, handle_a), 0u32.to_le_bytes());
        fixture.write(0, handle_a, &5u32.to_le_bytes());
        assert_eq!(fixture.read(0, handle_a), 5u32.to_le_bytes());
        assert_eq!(fixture.stats.phase(), PHASE_WAIT_SECOND);

        fixture.connect(1, CONNECT_B);
        assert_eq!(fixture.stats.phase(), PHASE_TWO_CONNECTED);

        // Discovery on both links yields the same database; interleaved
        // read/write on one link is visible from the other.
        let handle_b = fixture.find_value_handle(1);
        assert_eq!(handle_a, handle_b);
        assert_eq!(fixture.read(1, handle_b), 5u32.to_le_bytes());

        fixture.write(1, handle_b, &7u32.to_le_bytes());
        assert_eq!(fixture.read(0, handle_a), 7u32.to_le_bytes());
        fixture.write(0, handle_a, &9u32.to_le_bytes());
        assert_eq!(fixture.read(1, handle_b), 9u32.to_le_bytes());
        assert_eq!(stats.writes.load(Ordering::SeqCst), 3);

        // Closing A must not disturb B's link or the shared server value.
        fixture
            .controller
            .link_bridge_mut(0)
            .unwrap()
            .disconnected(0x13);
        fixture.until("Host notices A closing", |f| f.stats.disconnects() == 1);
        assert_eq!(fixture.read(1, handle_b), 9u32.to_le_bytes());

        // Closing B returns the Host to advertising; a fresh handle opens a
        // new generation without touching the stale ones.
        fixture
            .controller
            .link_bridge_mut(1)
            .unwrap()
            .disconnected(0x13);
        fixture.until("Host restarts advertising", |f| {
            f.stats.disconnects() == 2
                && f.stats.phase() == PHASE_ADVERTISING
                && f.controller.adv_enabled()
        });
        assert!(fixture
            .controller
            .link_bridge(0)
            .unwrap()
            .handle()
            .is_none());
        assert!(fixture
            .controller
            .link_bridge(1)
            .unwrap()
            .handle()
            .is_none());

        fixture.connect(0, 3);
        assert_eq!(fixture.read(0, handle_a), 9u32.to_le_bytes());
        assert_eq!(fixture.stats.connections(), 3);
    }

    #[test]
    fn notifications_and_cccd_stay_per_connection() {
        let _guard = crate::serialize();
        let stats = Stats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(run(wchble::hci::new(), &stats));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
        };

        fixture.until("Host starts advertising", |f| f.controller.adv_enabled());
        fixture.connect(0, CONNECT_A);
        fixture.until("Host advertises the second slot", |f| {
            f.stats.phase() == PHASE_WAIT_SECOND && f.controller.adv_enabled()
        });
        fixture.connect(1, CONNECT_B);
        assert_eq!(fixture.stats.phase(), PHASE_TWO_CONNECTED);

        let handle = fixture.find_value_handle(0);
        let cccd = handle + 1;
        fixture.subscribe(0, cccd, true);
        fixture.subscribe(1, cccd, true);

        // A write is notified to every subscribed link, whoever wrote.
        let mut on_a = fixture.write(0, handle, &11u32.to_le_bytes());
        on_a.extend(fixture.collect(0));
        let mut on_b = fixture.collect(1);
        assert!(
            on_a.iter().any(|pdu| notification_value(pdu) == Some(11)),
            "the writing link must be notified: {on_a:02x?}"
        );
        assert!(
            on_b.iter().any(|pdu| notification_value(pdu) == Some(11)),
            "the other subscribed link must be notified: {on_b:02x?}"
        );

        on_b = fixture.write(1, handle, &12u32.to_le_bytes());
        on_b.extend(fixture.collect(1));
        on_a = fixture.collect(0);
        assert!(on_b.iter().any(|pdu| notification_value(pdu) == Some(12)));
        assert!(on_a.iter().any(|pdu| notification_value(pdu) == Some(12)));

        // Unsubscribing A leaves B's CCCD state intact.
        fixture.subscribe(0, cccd, false);
        let mut off_a = fixture.write(0, handle, &13u32.to_le_bytes());
        off_a.extend(fixture.collect(0));
        assert!(
            off_a.iter().all(|pdu| notification_value(pdu).is_none()),
            "an unsubscribed link gets no notification"
        );
        let mut still_b = fixture.collect(1);
        assert!(
            still_b
                .iter()
                .any(|pdu| notification_value(pdu) == Some(13)),
            "B is still subscribed and must see A's write"
        );
        still_b = fixture.write(1, handle, &14u32.to_le_bytes());
        still_b.extend(fixture.collect(1));
        assert!(still_b
            .iter()
            .any(|pdu| notification_value(pdu) == Some(14)));
        assert!(fixture
            .collect(0)
            .iter()
            .all(|pdu| notification_value(pdu).is_none()));

        // Closing A must not clear B's subscription.
        fixture
            .controller
            .link_bridge_mut(0)
            .unwrap()
            .disconnected(0x13);
        fixture.until("Host notices A closing", |f| f.stats.disconnects() == 1);
        let mut after = fixture.write(1, handle, &15u32.to_le_bytes());
        after.extend(fixture.collect(1));
        assert!(
            after.iter().any(|pdu| notification_value(pdu) == Some(15)),
            "B keeps its subscription after A closes"
        );
    }

    #[test]
    fn interleaved_fragments_reassemble_per_link() {
        let _guard = crate::serialize();
        let stats = Stats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(run(wchble::hci::new(), &stats));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
        };

        fixture.until("Host starts advertising", |f| f.controller.adv_enabled());
        fixture.connect(0, CONNECT_A);
        fixture.until("Host advertises the second slot", |f| {
            f.stats.phase() == PHASE_WAIT_SECOND && f.controller.adv_enabled()
        });
        fixture.connect(1, CONNECT_B);
        assert_eq!(fixture.stats.phase(), PHASE_TWO_CONNECTED);

        let handle = fixture.find_value_handle(0);
        fixture.write(0, handle, &0x1122_3344u32.to_le_bytes());
        let [lo, hi] = handle.to_le_bytes();

        // Split the same Read Request differently and interleave the halves:
        // each L2CAP channel must reassemble its own fragments.
        let request = l2cap(&[0x0a, lo, hi]);
        fixture.inject_fragment(0, 2, &request[..6]);
        fixture.inject_fragment(1, 2, &request[..5]);
        fixture.inject_fragment(0, 1, &request[6..]);
        fixture.inject_fragment(1, 1, &request[5..]);

        for slot in 0..2 {
            let replies = fixture.collect(slot);
            assert!(
                replies.iter().any(|pdu| pdu.len() == 5
                    && pdu[0] == 0x0b
                    && pdu[1..] == 0x1122_3344u32.to_le_bytes()),
                "slot {slot} did not reassemble its read: {replies:02x?}"
            );
        }
    }
}
