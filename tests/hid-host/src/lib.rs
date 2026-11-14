//! Native fixture for the HID keyboard Host and soft HCI bridge; no HAL.
//! The report tick is driven by a manually advanced embassy-time clock.
//! Run from the repository root with:
//! `cargo test --manifest-path tests/hid-host/Cargo.toml --locked`.

#[cfg(test)]
#[path = "../../../examples/ch585-hid-keyboard/src/host.rs"]
mod host;

// A bare embassy-time driver, same shape as the firmware's `time_driver.rs`:
// the test advances the clock by hand and the Host's Timer fires on the next
// poll. This avoids the embassy executor queue integration entirely.
#[cfg(test)]
mod test_time {
    use core::task::Waker;

    use portable_atomic::{AtomicU64, Ordering};

    static NOW_US: AtomicU64 = AtomicU64::new(0);

    #[allow(dead_code)]
    pub fn advance(millis: u64) {
        NOW_US.fetch_add(millis * 1_000, Ordering::Relaxed);
    }

    struct TestDriver;

    impl embassy_time_driver::Driver for TestDriver {
        fn now(&self) -> u64 {
            NOW_US.load(Ordering::Relaxed)
        }

        fn schedule_wake(&self, _at: u64, _waker: &Waker) {
            // The fixture polls the Host future by hand after advancing.
        }
    }

    embassy_time_driver::time_driver_impl!(static DRIVER: TestDriver = TestDriver);
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::pin::{pin, Pin};
    use core::task::{Context, Waker};

    use wchble::hci::{ConnectionInfo, RadioRequest, SoftRunner, TxAcl, TxTag};

    use super::{host, test_time};

    const PUMP_LIMIT: usize = 4096;
    const HANDLE: u16 = 1;
    /// The vendor boot-keyboard report map, duplicated here as an independent
    /// expectation: the test must fail if the firmware constant drifts.
    const EXPECTED_MAP: [u8; 63] = [
        0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25,
        0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05,
        0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91,
        0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65,
        0x81, 0x00, 0xc0,
    ];

    const EXPECTED_CYCLE: [[u8; 8]; 8] = [
        [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00],
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];

    struct Fixture<'a, F: Future> {
        host: Pin<&'a mut F>,
        stats: &'a host::HostStats,
        controller: SoftRunner,
        /// Negotiated ATT MTU; 23 until an Exchange MTU Request succeeds.
        mtu: usize,
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

        fn disconnect(&mut self, count: u32) {
            self.controller.bridge.disconnected(0x13);
            self.until("Host disconnects and restarts advertising", |f| {
                f.stats.word(host::STAT_DISCONNECTS) == count && f.controller.adv_enabled()
            });
            assert!(self.controller.bridge.take_tx_acl().is_none());
        }

        fn inject(&mut self, att: &[u8]) {
            assert!(att.len() <= 23, "fixture sends one unfragmented ATT PDU");
            let mut l2cap = Vec::from((att.len() as u16).to_le_bytes());
            l2cap.extend_from_slice(&4u16.to_le_bytes());
            l2cap.extend_from_slice(att);
            self.controller.bridge.receive_acl(2, &l2cap).unwrap();
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
        }

        fn exchange(&mut self, att: &[u8], count: usize) -> Vec<Vec<u8>> {
            self.inject(att);
            let mut replies = Vec::new();
            for _ in 0..PUMP_LIMIT {
                self.pump();
                // There are exactly five bridge slots; never drain in an unbounded loop.
                for _ in 0..5 {
                    let Some(tx) = self.controller.bridge.take_tx_acl() else {
                        break;
                    };
                    replies.push(Self::decode(&tx));
                    self.ack(tx.tag);
                }
                assert!(
                    replies.len() <= count,
                    "unexpected ATT output: {replies:02x?}"
                );
                if replies.len() == count {
                    for _ in 0..16 {
                        self.pump();
                        assert!(
                            self.controller.bridge.take_tx_acl().is_none(),
                            "unexpected extra ATT output after {replies:02x?}",
                        );
                    }
                    return replies;
                }
            }
            panic!("ATT request {att:02x?} timed out; replies {replies:02x?}");
        }

        /// Write Command (no response). The pump runs a few times so the Host
        /// processes the event and updates its counters.
        fn write_cmd(&mut self, handle: u16, value: &[u8]) {
            let [lo, hi] = handle.to_le_bytes();
            let mut request = vec![0x52, lo, hi];
            request.extend_from_slice(value);
            self.inject(&request);
            for _ in 0..8 {
                self.pump();
                assert!(
                    self.controller.bridge.take_tx_acl().is_none(),
                    "a Write Command must not produce ATT output"
                );
            }
        }

        fn read(&mut self, handle: u16) -> Vec<u8> {
            let [lo, hi] = handle.to_le_bytes();
            let replies = self.exchange(&[0x0a, lo, hi], 1);
            assert_eq!(replies[0][0], 0x0b);
            replies[0][1..].to_vec()
        }

        /// Read Long (Read Request + Read Blob continuations).
        fn long_read(&mut self, handle: u16) -> Vec<u8> {
            let [lo, hi] = handle.to_le_bytes();
            let mut out = Vec::new();
            loop {
                let offset = out.len() as u16;
                let (request, opcode) = if offset == 0 {
                    (vec![0x0a, lo, hi], 0x0b)
                } else {
                    let [ol, oh] = offset.to_le_bytes();
                    (vec![0x0c, lo, hi, ol, oh], 0x0d)
                };
                let replies = self.exchange(&request, 1);
                assert_eq!(replies[0][0], opcode);
                let chunk = &replies[0][1..];
                let len = chunk.len();
                out.extend_from_slice(chunk);
                if len < self.mtu - 1 {
                    break;
                }
            }
            out
        }

        fn write(&mut self, handle: u16, value: &[u8], notifications: usize) -> Vec<Vec<u8>> {
            let [lo, hi] = handle.to_le_bytes();
            let mut request = vec![0x12, lo, hi];
            request.extend_from_slice(value);
            let replies = self.exchange(&request, 1 + notifications);
            assert_eq!(replies.iter().filter(|r| r.as_slice() == [0x13]).count(), 1);
            replies.into_iter().filter(|r| r[0] == 0x1b).collect()
        }

        /// Exchange MTU the way a desktop host does before discovering.
        fn exchange_mtu(&mut self, mtu: u16) -> u16 {
            let [lo, hi] = mtu.to_le_bytes();
            let replies = self.exchange(&[0x02, lo, hi], 1);
            assert_eq!(replies[0][0], 0x03);
            assert_eq!(replies[0].len(), 3);
            let negotiated = u16::from_le_bytes([replies[0][1], replies[0][2]]);
            self.mtu = usize::from(negotiated);
            negotiated
        }

        /// Read By Group Type 0x2800, the walk CoreBluetooth uses to list
        /// primary services. Entries are (start, end, uuid16).
        fn discover_groups(&mut self) -> Vec<(u16, u16, u16)> {
            let mut at = 1u16;
            let mut found = Vec::new();
            loop {
                let [sl, sh] = at.to_le_bytes();
                let replies = self.exchange(&[0x10, sl, sh, 0xff, 0xff, 0x00, 0x28], 1);
                if replies[0][0] == 0x01 {
                    break;
                }
                assert_eq!(replies[0][0], 0x11);
                let stride = replies[0][1] as usize;
                assert_eq!(stride, 6, "16-bit primary services only");
                let mut last = None;
                for entry in replies[0][2..].chunks_exact(stride) {
                    let start = u16::from_le_bytes([entry[0], entry[1]]);
                    let end = u16::from_le_bytes([entry[2], entry[3]]);
                    let uuid = u16::from_le_bytes([entry[4], entry[5]]);
                    found.push((start, end, uuid));
                    last = Some(end);
                }
                let Some(last_end) = last else { break };
                // The final service group uses 0xFFFF as "end of database".
                if last_end == u16::MAX || last_end <= at {
                    break;
                }
                at = last_end + 1;
            }
            found
        }

        fn find_service(&mut self, uuid: u16) -> (u16, u16) {
            let [lo, hi] = uuid.to_le_bytes();
            let replies = self.exchange(&[0x06, 1, 0, 0xff, 0xff, 0x00, 0x28, lo, hi], 1);
            assert_eq!(replies[0][0], 0x07);
            (
                u16::from_le_bytes([replies[0][1], replies[0][2]]),
                u16::from_le_bytes([replies[0][3], replies[0][4]]),
            )
        }

        /// Read By Type 0x2803 until the server answers Attribute Not Found.
        fn declarations(&mut self, start: u16, end: u16) -> Vec<(u16, u8, u16)> {
            let mut at = start;
            let mut found = Vec::new();
            loop {
                let [sl, sh] = at.to_le_bytes();
                let [el, eh] = end.to_le_bytes();
                let replies = self.exchange(&[0x08, sl, sh, el, eh, 0x03, 0x28], 1);
                if replies[0][0] == 0x01 {
                    break;
                }
                assert_eq!(replies[0][0], 0x09);
                let stride = replies[0][1] as usize;
                assert_eq!(stride, 7, "16-bit characteristic declarations only");
                let mut last = None;
                for entry in replies[0][2..].chunks_exact(stride) {
                    let props = entry[2];
                    let value = u16::from_le_bytes([entry[3], entry[4]]);
                    let uuid = u16::from_le_bytes([entry[5], entry[6]]);
                    found.push((uuid, props, value));
                    last = Some(value);
                }
                let Some(last_value) = last else { break };
                if last_value <= at {
                    break;
                }
                at = last_value;
            }
            found
        }

        /// Find Information for 16-bit UUIDs; handles are returned in order.
        fn find_information(&mut self, start: u16, end: u16) -> Vec<(u16, u16)> {
            let mut out = Vec::new();
            let mut at = start;
            while at <= end {
                let [sl, sh] = at.to_le_bytes();
                let [el, eh] = end.to_le_bytes();
                let replies = self.exchange(&[0x04, sl, sh, el, eh], 1);
                if replies[0][0] == 0x01 {
                    break;
                }
                assert_eq!(replies[0][0], 0x05);
                assert_eq!(replies[0][1], 0x01, "16-bit UUID format");
                let mut last = None;
                for entry in replies[0][2..].chunks_exact(4) {
                    let handle = u16::from_le_bytes([entry[0], entry[1]]);
                    let uuid = u16::from_le_bytes([entry[2], entry[3]]);
                    out.push((handle, uuid));
                    last = Some(handle);
                }
                let Some(last) = last else { break };
                if last >= end {
                    break;
                }
                at = last + 1;
            }
            out
        }

        /// Advance the shared mock clock by one report interval and collect
        /// the notification the Host emits on that tick.
        fn tick(&mut self) -> Option<Vec<u8>> {
            test_time::advance(1_000);
            for _ in 0..PUMP_LIMIT {
                self.pump();
                if let Some(tx) = self.controller.bridge.take_tx_acl() {
                    let att = Self::decode(&tx);
                    self.ack(tx.tag);
                    return Some(att);
                }
            }
            None
        }
    }

    fn hid(index: usize) -> u32 {
        host::hid_word(index)
    }

    fn value_of(chars: &[(u16, u8, u16)], uuid: u16) -> u16 {
        chars
            .iter()
            .find(|(u, _, _)| *u == uuid)
            .map(|(_, _, value)| *value)
            .unwrap_or_else(|| panic!("characteristic {uuid:#06x} not found"))
    }

    fn notification(handle: u16, data: &[u8]) -> Vec<u8> {
        let mut expected = vec![0x1b];
        expected.extend_from_slice(&handle.to_le_bytes());
        expected.extend_from_slice(data);
        expected
    }

    #[test]
    fn hid_keyboard_discovery_reports_boot_and_reconnect() {
        // The transport and the mock time driver are process-global: keep the
        // whole lifecycle in one test.
        let stats = host::HostStats::new();
        let mut future = pin!(host::run(wchble::hci::new(), &stats, host::RANDOM_ADDRESS));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller: SoftRunner::new(),
            mtu: 23,
        };
        fixture.until("Host initializes and advertises", |f| {
            f.controller.adv_enabled()
        });
        fixture.connect(1);

        // Desktop hosts discover primary services with Read By Group Type
        // after an MTU exchange, not with Find By Type Value. Replay that walk
        // first: a wrong group end handle makes macOS skip the HID service.
        let mtu = fixture.exchange_mtu(247);
        assert!(mtu >= 23 && mtu <= 128, "negotiated ATT MTU {mtu}");
        // This fixture compiles host.rs without `secure`, so the vendor bond
        // control service (0x1A00) does not exist here. The HID service is the
        // last 16-bit group, and Trouble reports the end of the database as
        // 0xFFFF for it; a walk must stop there without overflowing.
        let groups = fixture.discover_groups();
        let uuids: Vec<u16> = groups.iter().map(|(_, _, uuid)| *uuid).collect();
        assert_eq!(uuids, vec![0x1800, 0x1801, 0x180a, 0x180f, 0x1812]);
        assert_eq!(groups[0].0, 1, "first service starts at handle 1");
        for window in groups.windows(2) {
            assert_eq!(window[1].0, window[0].1 + 1, "service groups must be contiguous");
            assert!(window[0].0 <= window[0].1);
        }
        assert_eq!(groups.last().unwrap().1, u16::MAX, "last group ends the database");
        let hid_group = groups.iter().find(|(_, _, uuid)| *uuid == 0x1812).unwrap();
        assert!(hid_group.0 < hid_group.1);

        // HID service: nine characteristics, two of them 0x2A4D.
        let (start, end) = fixture.find_service(0x1812);
        assert_eq!((start, end), (hid_group.0, hid_group.1));
        assert!(start < end);
        let chars = fixture.declarations(start, end);
        let mut uuids: Vec<u16> = chars.iter().map(|(uuid, _, _)| *uuid).collect();
        uuids.sort_unstable();
        assert_eq!(
            uuids,
            vec![0x2a22, 0x2a32, 0x2a4a, 0x2a4b, 0x2a4c, 0x2a4d, 0x2a4d, 0x2a4e]
        );
        let props = |uuid: u16| chars.iter().find(|(u, _, _)| *u == uuid).unwrap().1;
        assert_eq!(props(0x2a4a), 0x02, "HID Information: Read");
        assert_eq!(props(0x2a4b), 0x02, "Report Map: Read");
        assert_eq!(props(0x2a4c), 0x04, "HID Control Point: Write Without Response");
        assert_eq!(props(0x2a4e), 0x06, "Protocol Mode: Read + Write Without Response");
        assert_eq!(props(0x2a22), 0x12, "Boot Keyboard Input: Read + Notify");
        assert_eq!(
            props(0x2a32),
            0x0e,
            "Boot Keyboard Output: Read + Write + Write Without Response"
        );

        let hid_info = value_of(&chars, 0x2a4a);
        let report_map = value_of(&chars, 0x2a4b);
        let control_point = value_of(&chars, 0x2a4c);
        let protocol_mode = value_of(&chars, 0x2a4e);
        let input_report = value_of(&chars, 0x2a4d);
        let output_report = chars
            .iter()
            .rev()
            .find(|(uuid, _, _)| *uuid == 0x2a4d)
            .unwrap()
            .2;
        let boot_input = value_of(&chars, 0x2a22);
        let boot_output = value_of(&chars, 0x2a32);
        assert!(input_report < output_report);

        // Fixed values, read over the same ATT path a host uses.
        assert_eq!(fixture.read(hid_info), [0x11, 0x01, 0x00, 0x00]);
        assert_eq!(fixture.long_read(report_map), EXPECTED_MAP);
        assert_eq!(fixture.read(protocol_mode), [0x01]);
        assert!(hid(host::HID_INFO_READS) >= 1);
        assert!(hid(host::HID_REPORT_MAP_READS) >= 1);

        // HOGP requires the PnP ID in DIS and a Battery Service; a Report Host
        // reads both while identifying the keyboard.
        let (dis_start, dis_end) = fixture.find_service(0x180a);
        let dis_chars = fixture.declarations(dis_start, dis_end);
        let pnp_id = value_of(&dis_chars, 0x2a50);
        assert_eq!(
            fixture.read(pnp_id),
            [0x02, 0x09, 0x12, 0x50, 0x58, 0x00, 0x01]
        );
        let (battery_start, battery_end) = fixture.find_service(0x180f);
        let battery_chars = fixture.declarations(battery_start, battery_end);
        assert_eq!(battery_chars.len(), 1, "one Battery Level characteristic");
        let battery_level = value_of(&battery_chars, 0x2a19);
        assert_eq!(fixture.read(battery_level), [100]);

        // Report Reference descriptors identify the two 0x2A4D values.
        let info = fixture.find_information(start, end);
        let references: Vec<u16> = info
            .iter()
            .filter(|(_, uuid)| *uuid == 0x2908)
            .map(|(handle, _)| *handle)
            .collect();
        assert_eq!(references.len(), 2);
        let mut reference_values: Vec<Vec<u8>> =
            references.iter().map(|handle| fixture.read(*handle)).collect();
        reference_values.sort();
        assert_eq!(reference_values, vec![vec![0x00, 0x01], vec![0x00, 0x02]]);

        // CCCDs exist only on the two notifying characteristics.
        let cccds: Vec<u16> = info
            .iter()
            .filter(|(_, uuid)| *uuid == 0x2902)
            .map(|(handle, _)| *handle)
            .collect();
        assert_eq!(cccds.len(), 2);
        let input_cccd = *cccds
            .iter()
            .find(|handle| **handle > input_report && **handle < output_report)
            .expect("input report CCCD");
        let boot_cccd = *cccds
            .iter()
            .find(|handle| **handle > boot_input && **handle < boot_output)
            .expect("boot input CCCD");

        // Subscribe in report protocol: the next eight ticks replay the
        // fixed cycle from its first report.
        assert!(fixture.write(input_cccd, &[1, 0], 0).is_empty());
        for expected in EXPECTED_CYCLE {
            let att = fixture.tick().expect("report notification");
            assert_eq!(att, notification(input_report, &expected));
        }
        assert_eq!(hid(host::HID_REPORTS_SENT), 8);
        assert_eq!(hid(host::HID_BOOT_INPUT_SENT), 0);
        assert_eq!(hid(host::HID_SUBSCRIPTION_EDGES), 1);
        assert_eq!(hid(host::HID_NOTIFY_ERRORS), 0);

        // LED output report (1 byte) and boot output report (1 byte).
        assert!(fixture.write(boot_output, &[0x02], 0).is_empty());
        assert!(fixture.write(output_report, &[0x07], 0).is_empty());
        assert_eq!(hid(host::HID_LED_WRITES), 2);
        assert_eq!(hid(host::HID_LED_VALUE), 0x07);

        // HID Control Point: Suspend, then Exit Suspend.
        fixture.write_cmd(control_point, &[0x00]);
        fixture.write_cmd(control_point, &[0x01]);
        assert_eq!(hid(host::HID_CONTROL_POINT_WRITES), 2);
        assert_eq!(hid(host::HID_CONTROL_POINT_LAST), 1);

        // Boot protocol: reports move to 0x2A22 and continue from index 0.
        fixture.write_cmd(protocol_mode, &[0x00]);
        assert_eq!(fixture.read(protocol_mode), [0x00]);
        assert_eq!(hid(host::HID_PROTOCOL_MODE), 0);
        assert_eq!(hid(host::HID_PROTOCOL_MODE_WRITES), 1);
        assert!(fixture.write(boot_cccd, &[1, 0], 0).is_empty());
        for expected in &EXPECTED_CYCLE[..2] {
            let att = fixture.tick().expect("boot notification");
            assert_eq!(att, notification(boot_input, expected));
        }
        assert_eq!(hid(host::HID_BOOT_INPUT_SENT), 2);
        assert_eq!(hid(host::HID_REPORTS_SENT), 8);
        fixture.write_cmd(protocol_mode, &[0x01]);
        assert_eq!(fixture.read(protocol_mode), [0x01]);
        assert_eq!(hid(host::HID_PROTOCOL_MODE_WRITES), 2);

        // Reconnect: the table is shared, so protocol mode and CCCDs must be
        // reset for the new link.
        fixture.disconnect(1);
        fixture.connect(2);
        assert_eq!(fixture.read(protocol_mode), [0x01]);
        assert_eq!(fixture.read(input_cccd), [0x00, 0x00]);
        assert_eq!(fixture.read(boot_cccd), [0x00, 0x00]);
        // No tick has fired for the second connection: nothing was sent.
        assert_eq!(hid(host::HID_REPORTS_SENT), 8);
        assert_eq!(hid(host::HID_BOOT_INPUT_SENT), 2);
        fixture.disconnect(2);

        assert_eq!(stats.word(host::STAT_CONNECTIONS), 2);
        assert_eq!(stats.word(host::STAT_DISCONNECTS), 2);
        assert_eq!(stats.word(host::STAT_ERRORS), 0);
        assert_eq!(stats.word(host::STAT_LAST_ERROR), 0);
        assert_eq!(stats.word(host::STAT_PHASE), host::PHASE_ADVERTISING);
        assert_eq!(stats.word(host::STAT_ADVERTISE_ATTEMPTS), 3);
        // Long read: one Read Request plus Read Blob continuations.
        assert!(hid(host::HID_REPORT_MAP_READS) >= 1);
    }
}
