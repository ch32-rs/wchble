//! Native fixture for the real P4 Host and soft HCI bridge; no HAL or adapter.
//! Run from the repository root with:
//! `cargo test --manifest-path tests/trouble-host/Cargo.toml --locked`.

#[cfg(test)]
#[path = "../../../examples/ch585-trouble-gatt/src/host.rs"]
mod host;

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::pin::{pin, Pin};
    use core::task::{Context, Waker};

    use trouble_host::attribute::Uuid;
    use wchble::hci::{BridgeError, ConnectionInfo, RadioRequest, SoftRunner, TxAcl, TxTag};

    use super::host;

    const PUMP_LIMIT: usize = 2048;
    const HANDLE: u16 = 1;

    struct Fixture<'a, F: Future> {
        host: Pin<&'a mut F>,
        stats: &'a host::HostStats,
        controller: SoftRunner,
        acknowledged: usize,
    }

    impl<F: Future> Fixture<'_, F> {
        fn pump(&mut self) {
            let mut cx = Context::from_waker(Waker::noop());
            assert!(self.host.as_mut().poll(&mut cx).is_pending());
            self.controller.pump_once();
            if let Some(request) = self.controller.bridge.take_radio_request() {
                match request {
                    RadioRequest::Reset => self.controller.bridge.reset_finished(),
                    RadioRequest::Disconnect { reason } => {
                        panic!("unexpected Host disconnect request: {reason:#04x}");
                    }
                }
            }
            assert_eq!(
                self.stats.word(host::STAT_ERRORS),
                0,
                "Host error stage {}",
                self.stats.word(host::STAT_LAST_ERROR),
            );
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
                self.stats.word(host::STAT_PHASE),
                self.stats.word(host::STAT_CONNECTIONS),
                self.stats.word(host::STAT_DISCONNECTS),
            );
        }

        fn connect(&mut self, count: u32) {
            assert!(self.controller.adv_enabled());
            self.controller.ll.adv.enabled = false;
            self.controller
                .bridge
                .connected(ConnectionInfo {
                    handle: HANDLE,
                    role: wchble::ll::Role::Peripheral,
                    peer_address_type: 1,
                    peer_address: [1, 2, 3, 4, 5, 0xc6],
                    interval: 24,
                    latency: 0,
                    supervision_timeout: 200,
                    master_clock_accuracy: 0,
                })
                .unwrap();
            self.until("Host accepts connection", |f| {
                f.stats.word(host::STAT_CONNECTIONS) == count
                    && f.stats.word(host::STAT_PHASE) == host::PHASE_CONNECTED
            });
        }

        /// Inbound ACL payload: the Host fragments at the legacy ACL size, so
        /// the peer side of the fixture mirrors it (5 fragments for a 128-byte
        /// PDU; an encrypted link fragments at the same 27 plaintext octets).
        const ACL_FRAGMENT: usize = 27;

        fn inject(&mut self, att: &[u8]) {
            self.inject_fragmented(att);
        }

        fn inject_fragmented(&mut self, att: &[u8]) {
            let mut l2cap = Vec::from((att.len() as u16).to_le_bytes());
            l2cap.extend_from_slice(&4u16.to_le_bytes());
            l2cap.extend_from_slice(att);
            for (index, chunk) in l2cap.chunks(Self::ACL_FRAGMENT).enumerate() {
                self.send_fragment(if index == 0 { 2 } else { 1 }, chunk);
            }
        }

        fn send_fragment(&mut self, llid: u8, chunk: &[u8]) {
            assert!(chunk.len() <= Self::ACL_FRAGMENT);
            for _ in 0..PUMP_LIMIT {
                match self.controller.bridge.receive_acl(llid, chunk) {
                    Ok(()) => {
                        self.pump();
                        return;
                    }
                    Err(BridgeError::Full) => self.pump(),
                    Err(error) => panic!("receive_acl: {error:?}"),
                }
            }
            panic!("bridge never accepted an ACL fragment");
        }

        /// Append one fragment and return the ATT PDU once it is complete.
        fn push_fragment(partial: &mut Option<Vec<u8>>, tx: &TxAcl) -> Option<Vec<u8>> {
            match tx.llid {
                2 => {
                    assert!(partial.is_none(), "start fragment inside one PDU");
                    *partial = Some(tx.bytes[..tx.len].to_vec());
                }
                1 => partial
                    .as_mut()
                    .expect("continuation fragment without a start")
                    .extend_from_slice(&tx.bytes[..tx.len]),
                other => panic!("unexpected LLID {other}"),
            }
            let pdu = partial.as_ref()?;
            if pdu.len() < 4 {
                return None;
            }
            let l2cap_len = u16::from_le_bytes([pdu[0], pdu[1]]) as usize;
            if pdu.len() < 4 + l2cap_len {
                return None;
            }
            assert_eq!(pdu.len(), 4 + l2cap_len, "trailing bytes in one PDU");
            assert_eq!(&pdu[2..4], &4u16.to_le_bytes());
            let att = pdu[4..].to_vec();
            *partial = None;
            Some(att)
        }

        fn decode(tx: &TxAcl) -> Vec<u8> {
            assert_eq!(tx.llid, 2);
            assert!(tx.len >= 5);
            let l2cap_len = u16::from_le_bytes([tx.bytes[0], tx.bytes[1]]) as usize;
            assert_eq!(tx.len, 4 + l2cap_len);
            assert_eq!(&tx.bytes[2..4], &4u16.to_le_bytes());
            tx.bytes[4..tx.len].to_vec()
        }

        fn ack(&mut self, tag: TxTag) {
            assert!(self.controller.bridge.ack_tx(tag));
            assert!(
                !self.controller.bridge.ack_tx(tag),
                "duplicate ACK returned a credit"
            );
            self.acknowledged += 1;
        }

        fn exchange(&mut self, att: &[u8], count: usize) -> Vec<Vec<u8>> {
            self.inject(att);
            self.collect(count)
        }

        fn exchange_pdu(&mut self, att: &[u8], count: usize) -> Vec<Vec<u8>> {
            self.inject_fragmented(att);
            self.collect(count)
        }

        fn collect(&mut self, count: usize) -> Vec<Vec<u8>> {
            let mut replies = Vec::new();
            let mut partial = None;
            for _ in 0..PUMP_LIMIT {
                self.pump();
                // Drain at most the bridge's credit window; never loop unbounded.
                for _ in 0..wchble::hci::connection::ACL_CREDITS {
                    let Some(tx) = self.controller.bridge.take_tx_acl() else {
                        break;
                    };
                    assert!(tx.len <= Self::ACL_FRAGMENT);
                    self.ack(tx.tag);
                    if let Some(att) = Self::push_fragment(&mut partial, &tx) {
                        replies.push(att);
                    }
                }
                assert!(
                    replies.len() <= count,
                    "unexpected ATT output: {replies:02x?}"
                );
                if replies.len() == count {
                    // Route actual Number Of Completed Packets events back to the Host.
                    for _ in 0..16 {
                        self.pump();
                        while let Some(tx) = self.controller.bridge.take_tx_acl() {
                            self.ack(tx.tag);
                            assert!(
                                Self::push_fragment(&mut partial, &tx).is_none(),
                                "unexpected extra ATT output after {replies:02x?}",
                            );
                        }
                        assert!(partial.is_none(), "unexpected partial PDU");
                    }
                    return replies;
                }
            }
            panic!("ATT exchange timed out; replies {replies:02x?}");
        }

        /// Drive one request whose reply is a normal response plus zero or more
        /// notifications, and stop when the link goes quiet.
        fn exchange_burst(&mut self, att: &[u8]) -> Vec<Vec<u8>> {
            self.inject(att);
            let mut replies = Vec::new();
            let mut partial = None;
            let mut quiet = 0;
            for _ in 0..PUMP_LIMIT {
                self.pump();
                let mut progress = false;
                for _ in 0..wchble::hci::connection::ACL_CREDITS {
                    let Some(tx) = self.controller.bridge.take_tx_acl() else {
                        break;
                    };
                    progress = true;
                    self.ack(tx.tag);
                    if let Some(pdu) = Self::push_fragment(&mut partial, &tx) {
                        replies.push(pdu);
                    }
                }
                quiet = if progress { 0 } else { quiet + 1 };
                if !replies.is_empty() && quiet >= 8 {
                    return replies;
                }
            }
            panic!("burst did not settle; replies {replies:02x?}");
        }

        fn read(&mut self, handle: u16) -> Vec<u8> {
            let [lo, hi] = handle.to_le_bytes();
            let replies = self.exchange(&[0x0a, lo, hi], 1);
            assert_eq!(replies[0][0], 0x0b);
            replies[0][1..].to_vec()
        }

        fn find_service(&mut self, uuid: u16) -> (u16, u16) {
            let [lo, hi] = uuid.to_le_bytes();
            let replies = self.exchange(
                &[0x06, 1, 0, 0xff, 0xff, 0x00, 0x28, lo, hi],
                1,
            );
            assert_eq!(replies[0][0], 0x07);
            (
                u16::from_le_bytes([replies[0][1], replies[0][2]]),
                u16::from_le_bytes([replies[0][3], replies[0][4]]),
            )
        }

        fn find_service_long(&mut self, uuid: &Uuid) -> (u16, u16) {
            let mut bytes = [0; 16];
            uuid.bytes(&mut bytes);
            let mut request = vec![0x06, 1, 0, 0xff, 0xff, 0x00, 0x28];
            request.extend_from_slice(&bytes);
            let replies = self.exchange(&request, 1);
            assert_eq!(replies[0][0], 0x07);
            (
                u16::from_le_bytes([replies[0][1], replies[0][2]]),
                u16::from_le_bytes([replies[0][3], replies[0][4]]),
            )
        }

        fn find_characteristic_long(
            &mut self,
            start: u16,
            end: u16,
            uuid: &Uuid,
        ) -> (u16, u8, Option<u16>) {
            let [sl, sh] = start.to_le_bytes();
            let [el, eh] = end.to_le_bytes();
            let mut wanted = [0; 16];
            uuid.bytes(&mut wanted);
            let replies = self.exchange(&[0x08, sl, sh, el, eh, 0x03, 0x28], 1);
            assert_eq!(replies[0][0], 0x09);
            let stride = replies[0][1] as usize;
            for reply in &replies {
                for entry in reply[2..].chunks_exact(stride) {
                    if entry.len() == 21 && entry[5..] == wanted {
                        let value = u16::from_le_bytes([entry[3], entry[4]]);
                        let props = entry[2];
                        let [vl, vh] = value.wrapping_add(1).to_le_bytes();
                        let desc = self.exchange(&[0x04, vl, vh, el, eh], 1);
                        let cccd = cccd_from_find_info(&desc);
                        return (value, props, cccd);
                    }
                }
            }
            panic!("128-bit characteristic not found");
        }

        /// Returns value handle, properties and optional CCCD handle.
        fn find_characteristic(&mut self, start: u16, end: u16, uuid: u16) -> (u16, u8, Option<u16>) {
            let [sl, sh] = start.to_le_bytes();
            let [el, eh] = end.to_le_bytes();
            let [lo, hi] = uuid.to_le_bytes();
            let replies = self.exchange(&[0x08, sl, sh, el, eh, 0x03, 0x28], 1);
            assert_eq!(replies[0][0], 0x09);
            let stride = replies[0][1] as usize;
            let mut found = None;
            for reply in &replies {
                for entry in reply[2..].chunks_exact(stride) {
                    if entry.len() >= 7 && entry[5] == lo && entry[6] == hi {
                        let value = u16::from_le_bytes([entry[3], entry[4]]);
                        let props = entry[2];
                        let [vl, vh] = value.to_le_bytes();
                        let desc = self.exchange(&[0x04, vl, vh, el, eh], 1);
                        let cccd = cccd_from_find_info(&desc);
                        found = Some((value, props, cccd));
                    }
                }
            }
            found.expect("characteristic not found")
        }

        fn write(&mut self, handle: u16, value: &[u8], notifications: usize) -> Vec<Vec<u8>> {
            let [lo, hi] = handle.to_le_bytes();
            let mut request = vec![0x12, lo, hi];
            request.extend_from_slice(value);
            let replies = self.exchange(&request, 1 + notifications);
            assert_eq!(replies.iter().filter(|r| r.as_slice() == [0x13]).count(), 1);
            let notification_replies: Vec<_> =
                replies.into_iter().filter(|r| r[0] == 0x1b).collect();
            assert_eq!(notification_replies.len(), notifications);
            notification_replies
        }

        fn hold_read_response(&mut self, handle: u16) -> TxTag {
            let [lo, hi] = handle.to_le_bytes();
            self.inject(&[0x0a, lo, hi]);
            for _ in 0..PUMP_LIMIT {
                self.pump();
                if let Some(tx) = self.controller.bridge.take_tx_acl() {
                    assert_eq!(Self::decode(&tx), [0x0b, 110, 0, 0, 0]);
                    return tx.tag;
                }
            }
            panic!("read response to hold in flight timed out");
        }

        fn disconnect(&mut self, count: u32) {
            self.controller.bridge.disconnected(0x13);
            self.until("Host disconnects and restarts advertising", |f| {
                f.stats.word(host::STAT_DISCONNECTS) == count && f.controller.adv_enabled()
            });
            assert_eq!(self.stats.word(host::STAT_SUBSCRIBED), 0);
            assert!(self.controller.bridge.take_tx_acl().is_none());
        }
    }

    /// First 0x2902 descriptor in a (possibly multi-entry) Find Information
    /// response. Each response row is opcode, format, then 4-byte entries.
    fn cccd_from_find_info(replies: &[Vec<u8>]) -> Option<u16> {
        for row in replies {
            if row.len() < 2 || row[0] != 0x05 || row[1] != 1 {
                continue;
            }
            for entry in row[2..].chunks_exact(4) {
                if entry[2] == 0x02 && entry[3] == 0x29 {
                    return Some(u16::from_le_bytes([entry[0], entry[1]]));
                }
            }
        }
        None
    }

    #[test]
    fn real_host_discovery_read_write_notify_and_reconnect() {
        // The transport is process-global: keep the whole lifecycle in one test.
        let stats = host::HostStats::new();
        // The legacy 27-octet ACL buffer is also an encrypted link's plaintext
        // fragment size, so the X4 phase exercises the same ACL split.
        let controller = SoftRunner::new();
        let mut future = pin!(host::run(wchble::hci::new(), &stats, host::RANDOM_ADDRESS));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
            acknowledged: 0,
        };
        fixture.until("Host initializes and advertises", |f| {
            f.controller.adv_enabled()
        });
        assert_eq!(stats.word(host::STAT_VALUE), 0);
        fixture.connect(1);

        // Find By Type Value: primary service UUID 0x2800, custom UUID in ATT byte order.
        let mut service_uuid = [0; 16];
        host::SERVICE_UUID.bytes(&mut service_uuid);
        let mut request = vec![0x06, 1, 0, 0xff, 0xff, 0x00, 0x28];
        request.extend_from_slice(&service_uuid);
        let replies = fixture.exchange(&request, 1);
        assert_eq!(replies[0].len(), 5);
        assert_eq!(replies[0][0], 0x07);
        let start = u16::from_le_bytes([replies[0][1], replies[0][2]]);
        let end = u16::from_le_bytes([replies[0][3], replies[0][4]]);
        assert!(start < end);

        // Read By Type discovers the 128-bit characteristic declaration.
        let [sl, sh] = start.to_le_bytes();
        let [el, eh] = end.to_le_bytes();
        let replies = fixture.exchange(&[0x08, sl, sh, el, eh, 0x03, 0x28], 1);
        assert_eq!(replies[0].len(), 23);
        assert_eq!(&replies[0][..2], &[0x09, 21]);
        assert_eq!(replies[0][4], 0x1a); // Read | Write | Notify.
        let value_handle = u16::from_le_bytes([replies[0][5], replies[0][6]]);
        let mut value_uuid = [0; 16];
        host::VALUE_UUID.bytes(&mut value_uuid);
        assert_eq!(&replies[0][7..], &value_uuid);

        let [dl, dh] = (value_handle + 1).to_le_bytes();
        let replies = fixture.exchange(&[0x04, dl, dh, el, eh], 1);
        assert_eq!(&replies[0][..2], &[0x05, 0x01]);
        let cccd_handle = cccd_from_find_info(&replies).expect("value CCCD missing");
        assert_eq!(cccd_handle, value_handle + 1);

        assert_eq!(fixture.read(value_handle), 0u32.to_le_bytes());
        assert!(fixture
            .write(value_handle, &7u32.to_le_bytes(), 0)
            .is_empty());
        assert_eq!(fixture.read(value_handle), 7u32.to_le_bytes());
        assert_eq!(stats.word(host::STAT_VALUE), 7);
        assert!(fixture.write(cccd_handle, &[1, 0], 0).is_empty());
        assert_eq!(stats.word(host::STAT_SUBSCRIBED), 1);

        for n in 101u32..=110 {
            let notifications = fixture.write(value_handle, &n.to_le_bytes(), 1);
            let mut expected = vec![0x1b];
            expected.extend_from_slice(&value_handle.to_le_bytes());
            expected.extend_from_slice(&n.to_le_bytes());
            assert_eq!(notifications, [expected]);
            assert_eq!(fixture.read(value_handle), n.to_le_bytes());
        }
        assert_eq!(stats.word(host::STAT_NOTIFICATIONS), 10);
        assert_eq!(stats.word(host::STAT_VALUE), 110);
        assert!(fixture.acknowledged > 5);

        // Device Information Service: standard read-only identity.
        let (info_start, info_end) = fixture.find_service(0x180a);
        let (manufacturer, props, _) = fixture.find_characteristic(info_start, info_end, 0x2a29);
        assert_eq!(props & 0x02, 0x02);
        assert_eq!(fixture.read(manufacturer), b"wchble");
        let (model, _, _) = fixture.find_characteristic(info_start, info_end, 0x2a24);
        assert_eq!(fixture.read(model), b"ch585-trouble-gatt");
        let (revision, _, _) = fixture.find_characteristic(info_start, info_end, 0x2a26);
        assert_eq!(fixture.read(revision), b"p5-0.1");

        // Nordic UART pipe: a write to RX is echoed once as a TX notification.
        let (uart_start, uart_end) = fixture.find_service_long(&host::UART_SERVICE_UUID);
        let (uart_rx, rx_props, _) = fixture.find_characteristic_long(uart_start, uart_end, &host::UART_RX_UUID);
        assert_eq!(rx_props & 0x08, 0x08);
        // MTU 23 fits one 128-bit declaration per response, so continue after RX.
        let (uart_tx, tx_props, tx_cccd) =
            fixture.find_characteristic_long(uart_rx + 1, uart_end, &host::UART_TX_UUID);
        assert_eq!(tx_props & 0x10, 0x10);
        assert!(fixture.write(tx_cccd.unwrap(), &[1, 0], 0).is_empty());
        let notifications = fixture.write(uart_rx, b"hi", 1);
        let mut expected = vec![0x1b];
        expected.extend_from_slice(&uart_tx.to_le_bytes());
        expected.extend_from_slice(b"hi");
        assert_eq!(notifications, [expected]);
        assert_eq!(stats.word(host::STAT_UART_WRITES), 1);
        assert_eq!(stats.word(host::STAT_UART_NOTIFICATIONS), 1);
        assert_eq!(stats.word(host::STAT_UART_LEN), 2);

        // UTF-8 Chinese "中文" is six bytes and must echo unchanged.
        let cjk = [0xe4, 0xb8, 0xad, 0xe6, 0x96, 0x87];
        let notifications = fixture.write(uart_rx, &cjk, 1);
        let mut expected = vec![0x1b];
        expected.extend_from_slice(&uart_tx.to_le_bytes());
        expected.extend_from_slice(&cjk);
        assert_eq!(notifications, [expected]);
        assert_eq!(stats.word(host::STAT_UART_WRITES), 2);
        assert_eq!(stats.word(host::STAT_UART_NOTIFICATIONS), 2);
        assert_eq!(stats.word(host::STAT_UART_LEN), 6);

        // A full MTU-23 write: 20 value octets plus the 3-octet ATT header.
        // The resulting 27-octet ACL fragment is the largest plaintext packet;
        // encryption adds the 4-octet MIC on top.
        let full = [0x5a; 20];
        let notifications = fixture.write(uart_rx, &full, 1);
        let mut expected = vec![0x1b];
        expected.extend_from_slice(&uart_tx.to_le_bytes());
        expected.extend_from_slice(&full);
        assert_eq!(notifications, [expected]);
        assert_eq!(stats.word(host::STAT_UART_WRITES), 3);
        assert_eq!(stats.word(host::STAT_UART_NOTIFICATIONS), 3);
        assert_eq!(stats.word(host::STAT_UART_LEN), 20);

        // Leave a real Host ACL in flight. Disconnect must invalidate its credit/tag.
        let old_tag = fixture.hold_read_response(value_handle);
        fixture.disconnect(1);
        assert!(!fixture.controller.bridge.ack_tx(old_tag));
        fixture.connect(2);
        assert!(!fixture.controller.bridge.ack_tx(old_tag));
        assert_eq!(fixture.read(cccd_handle), [0, 0]);
        assert_eq!(fixture.read(value_handle), 110u32.to_le_bytes());

        // More than five new transactions exercise fresh credits on the reused handle.
        for n in 201u32..=212 {
            assert!(fixture.write(value_handle, &n.to_le_bytes(), 0).is_empty());
            assert_eq!(fixture.read(value_handle), n.to_le_bytes());
        }
        assert_eq!(stats.word(host::STAT_NOTIFICATIONS), 10);
        assert!(fixture.write(cccd_handle, &[1, 0], 0).is_empty());
        let notifications = fixture.write(value_handle, &301u32.to_le_bytes(), 1);
        assert_eq!(&notifications[0][3..], &301u32.to_le_bytes());
        assert!(fixture.write(cccd_handle, &[0, 0], 0).is_empty());
        assert!(fixture
            .write(value_handle, &302u32.to_le_bytes(), 0)
            .is_empty());
        fixture.disconnect(2);

        assert_eq!(stats.word(host::STAT_CONNECTIONS), 2);
        assert_eq!(stats.word(host::STAT_DISCONNECTS), 2);
        assert_eq!(stats.word(host::STAT_READS), 26);
        assert_eq!(stats.word(host::STAT_WRITES), 25);
        assert_eq!(stats.word(host::STAT_NOTIFICATIONS), 11);
        assert_eq!(stats.word(host::STAT_VALUE), 302);
        assert_eq!(stats.word(host::STAT_ERRORS), 0);
        assert_eq!(stats.word(host::STAT_LAST_ERROR), 0);
        assert_eq!(stats.word(host::STAT_PHASE), host::PHASE_ADVERTISING);
        assert_eq!(stats.word(host::STAT_ADVERTISE_ATTEMPTS), 3);
        // Includes DIS/NUS discovery and the three UART echo notifications.
        assert_eq!(fixture.acknowledged, 90);

        // X4: MTU exchange, long read (Read Blob), long write (Prepare/Execute)
        // and notification-queue pressure, all at 23-byte ACL fragments.
        fixture.connect(3);
        let replies = fixture.exchange(&[0x02, 0xf7, 0x00], 1);
        assert_eq!(replies[0], [0x03, 0x7c, 0x00], "MTU 247 must be capped at 124");

        let (vendor_start, vendor_end) = fixture.find_service_long(&host::SERVICE_UUID);
        let (bulk, bulk_props, _) =
            fixture.find_characteristic_long(vendor_start, vendor_end, &host::BULK_UUID);
        assert_eq!(bulk_props & 0x0a, 0x0a, "bulk must be Read + Write");
        let (burst, burst_props, burst_cccd) =
            fixture.find_characteristic_long(bulk + 1, vendor_end, &host::BURST_UUID);
        assert_eq!(burst_props & 0x10, 0x10, "burst must notify");
        let burst_cccd = burst_cccd.expect("burst needs a CCCD");
        let (x4_control, control_props, _) =
            fixture.find_characteristic_long(burst + 1, vendor_end, &host::X4_CONTROL_UUID);
        assert_eq!(control_props & 0x08, 0x08, "X4 command must be writable");
        // The MTU word is refreshed on every GATT event, so it only reflects
        // the exchange after the discovery reads above.
        assert_eq!(host::x4_word(host::X4_MTU), 124);

        let [bl, bh] = bulk.to_le_bytes();
        let first = fixture.exchange(&[0x0a, bl, bh], 1);
        assert_eq!(first[0][0], 0x0b);
        assert_eq!(first[0].len(), 124, "Read Response must fill the ATT MTU");
        let mut read_value = first[0][1..].to_vec();
        while read_value.len() < host::BULK_LEN {
            let [ol, oh] = (read_value.len() as u16).to_le_bytes();
            let more = fixture.exchange(&[0x0c, bl, bh, ol, oh], 1);
            assert_eq!(more[0][0], 0x0d);
            read_value.extend_from_slice(&more[0][1..]);
        }
        assert_eq!(read_value.len(), host::BULK_LEN);
        assert!((0..host::BULK_LEN)
            .all(|index| read_value[index] == host::x4_bulk_read_byte(index)));

        // Exactly what Android's reliable-write path sends for a value longer
        // than MTU-3: Prepare Write chunks followed by Execute Write.
        let write_value: Vec<u8> = (0..host::BULK_LEN).map(host::x4_bulk_write_byte).collect();
        let chunk = 124 - 5;
        let mut offset = 0;
        while offset < write_value.len() {
            let end = core::cmp::min(offset + chunk, write_value.len());
            let mut request = Vec::from([0x16, bl, bh]);
            request.extend_from_slice(&(offset as u16).to_le_bytes());
            request.extend_from_slice(&write_value[offset..end]);
            let replies = fixture.exchange_pdu(&request, 1);
            assert_eq!(replies[0][0], 0x17);
            assert_eq!(&replies[0][1..5], &request[1..5]);
            assert_eq!(&replies[0][5..], &write_value[offset..end]);
            offset = end;
        }
        let replies = fixture.exchange(&[0x18, 0x01], 1);
        assert_eq!(replies[0], [0x19]);
        assert_eq!(host::x4_word(host::X4_BULK_WRITES), 1);
        assert_eq!(host::x4_word(host::X4_BULK_LEN), host::BULK_LEN as u32);
        assert_eq!(host::x4_word(host::X4_BULK_MATCH), 1);

        let first = fixture.exchange(&[0x0a, bl, bh], 1);
        assert_eq!(first[0][0], 0x0b);
        let mut readback = first[0][1..].to_vec();
        while readback.len() < host::BULK_LEN {
            let [ol, oh] = (readback.len() as u16).to_le_bytes();
            let more = fixture.exchange(&[0x0c, bl, bh, ol, oh], 1);
            assert_eq!(more[0][0], 0x0d);
            readback.extend_from_slice(&more[0][1..]);
        }
        assert_eq!(readback, write_value);

        // The burst fills a 124-byte ATT PDU. The outbound queue is bounded, so
        // some attempts must be refused and the accepted ones must all arrive.
        assert!(fixture.write(burst_cccd, &[1, 0], 0).is_empty());
        let [xl, xh] = x4_control.to_le_bytes();
        let mut request = Vec::from([0x12, xl, xh]);
        request.extend_from_slice(b"BST!");
        let replies = fixture.exchange_burst(&request);
        assert_eq!(replies.iter().filter(|row| row.as_slice() == [0x13]).count(), 1);
        let notifications: Vec<_> = replies.iter().filter(|row| row[0] == 0x1b).collect();
        assert!(!notifications.is_empty());
        for note in &notifications {
            assert_eq!(&note[1..3], &burst.to_le_bytes());
            assert_eq!(note.len(), 3 + host::BURST_LEN);
            assert!((0..host::BURST_LEN).all(|index| note[3 + index] == host::x4_burst_byte(index)));
        }
        assert_eq!(host::x4_word(host::X4_BURST_RUNS), 1);
        assert_eq!(host::x4_word(host::X4_BURST_ATTEMPTS), host::BURST_ATTEMPTS);
        // Queue depth is 8; the write response takes one slot, so seven of the
        // twelve attempts are accepted and five see the queue full.
        assert_eq!(host::x4_word(host::X4_BURST_SENT), 7);
        assert_eq!(host::x4_word(host::X4_BURST_QUEUE_FULL), 5);
        assert_eq!(host::x4_word(host::X4_BURST_BUSY), 0);
        assert_eq!(host::x4_word(host::X4_BURST_OTHER), 0);
        assert_eq!(notifications.len(), 7);
        assert_eq!(host::x4_word(host::X4_LAST_ERROR), 0);

        fixture.disconnect(3);
        assert_eq!(stats.word(host::STAT_CONNECTIONS), 3);
        assert_eq!(stats.word(host::STAT_DISCONNECTS), 3);
        assert_eq!(stats.word(host::STAT_ADVERTISE_ATTEMPTS), 4);
        assert_eq!(stats.word(host::STAT_ERRORS), 0);
        // Ledger of ACL fragments acknowledged over the whole fixture. The
        // 90-fragment baseline includes the three UART echoes; X4 adds 77:
        // discovery, the 124-byte read, both writes and the seven queued
        // 128-byte notifications at the legacy 27-octet fragmentation.
        assert_eq!(fixture.acknowledged, 167);
    }
}
