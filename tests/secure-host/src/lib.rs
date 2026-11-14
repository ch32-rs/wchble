//! Native reproduction for the LESC pairing failure seen on CH585, plus the
//! bonded CCCD persistence path.
//!
//! Same Host source as `examples/ch585-trouble-gatt` with `secure` enabled,
//! driven by the real soft HCI bridge. The pairing scenario mirrors the air
//! capture: a peripheral connection, the Android Pairing Request, and the
//! fragmented 65-byte P-256 public key (24/24/21 LL payloads). The CCCD
//! scenario subscribes over ATT, captures what the Host would persist, and
//! reboots a fresh Host from that record.
//!
//! Run from the repository root:
//! `cargo test --manifest-path tests/secure-host/Cargo.toml --features secure`
//! and, for the `DEL!` shadow case,
//! `cargo test --manifest-path tests/secure-host/Cargo.toml --features secure,accept-control`

extern crate alloc;

// The backend registers the `embassy-crypto` driver symbols only when linked;
// the firmware does the same in `main.rs`.
#[cfg(feature = "secure")]
use embassy_crypto_rustcrypto as _;

#[cfg(feature = "secure")]
mod rng {
    use core::cell::UnsafeCell;

    use wchble::rand::ChaCha20Drbg;

    struct Cell(UnsafeCell<Option<ChaCha20Drbg>>);
    // Safety: the test polls one Host future from one thread.
    unsafe impl Sync for Cell {}

    static RNG: Cell = Cell(UnsafeCell::new(None));

    pub fn seed(seed: &[u8; 32]) {
        unsafe {
            *RNG.0.get() = Some(ChaCha20Drbg::from_seed(seed));
        }
    }

    struct Driver;

    impl embassy_crypto::driver::Rng for Driver {
        fn fill_bytes(buf: &mut [u8]) {
            unsafe {
                match (*RNG.0.get()).as_mut() {
                    Some(rng) => rng.fill(buf),
                    None => panic!("crypto RNG used before seeding"),
                }
            }
        }
    }

    embassy_crypto::rng_impl!(Driver);
}

#[cfg(feature = "secure")]
#[path = "../../../examples/ch585-trouble-gatt/src/bond.rs"]
mod bond;

#[cfg(feature = "secure")]
#[path = "../../../examples/ch585-trouble-gatt/src/client_att.rs"]
mod client_att;

#[cfg(feature = "secure")]
#[path = "../../../examples/ch585-trouble-gatt/src/host.rs"]
mod host;

#[cfg(test)]
#[cfg(feature = "secure")]
mod tests {
    use core::future::Future;
    use core::pin::{pin, Pin};
    use core::task::{Context, Waker};

    use wchble::hci::{ConnectionInfo, RadioRequest, SoftRunner, TxAcl};

    use super::{bond, client_att, host, rng};

    const PEER: [u8; 6] = [0x2e, 0x45, 0x87, 0xf3, 0xe5, 0x57];

    /// Install a boot bond exactly as a stored record would be restored.
    fn preload_bond(identity: trouble_host::prelude::Identity) {
        use trouble_host::prelude::*;
        let bond = BondInformation::new(
            identity,
            LongTermKey::from_le_bytes([7; 16]),
            SecurityLevel::Encrypted,
            true,
        );
        bond::set_boot_bonds(&[bond::from_bond(&bond)]);
    }

    /// 64-byte P-256 public key captured from the Android Central
    /// (`x1-att-5`, SMP Pairing Public Key).
    const PEER_PUBLIC_KEY: [u8; 64] = [
        0xd0, 0xba, 0x73, 0x74, 0x39, 0x0d, 0x09, 0x44, 0x06, 0xd0, 0x0a, 0xb4, 0x50, 0x57, 0xfa, 0x7d,
        0x2b, 0x17, 0x1c, 0xbb, 0x57, 0x1f, 0x08, 0x44, 0x1b, 0xc3, 0x3c, 0x54, 0xe3, 0xc6, 0xbb, 0x0a,
        0x5e, 0xee, 0x6a, 0x05, 0xeb, 0xcb, 0x26, 0x9f, 0x40, 0xd6, 0x8c, 0xf7, 0x93, 0xdc, 0x3a, 0xd7,
        0x70, 0x98, 0x1f, 0x7b, 0xf2, 0xf5, 0xc9, 0x34, 0x13, 0x55, 0x43, 0x9f, 0x8b, 0xcb, 0x57, 0x61,
    ];

    /// Android's Pairing Request from the same capture.
    const PAIRING_REQUEST: [u8; 7] = [0x01, 0x04, 0x00, 0x2d, 0x10, 0x0f, 0x0f];

    const SMP_CID: u16 = 0x0006;
    const ATT_CID: u16 = 0x0004;

    struct Fixture<'a, F: Future> {
        host: Pin<&'a mut F>,
        stats: &'a host::HostStats,
        controller: SoftRunner,
        /// Disconnect reason the Host asked the Controller for, if any.
        disconnect: Option<u8>,
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
                        self.disconnect = Some(reason);
                    }
                }
            }
        }

        fn pump_quiet(&mut self, count: usize) {
            for _ in 0..count {
                self.pump();
                // Drain controller-to-Host output so the bridge does not back up.
                while self.controller.pump_once() {}
            }
        }

        fn connect(&mut self, peer: [u8; 6]) {
            assert!(self.controller.adv_enabled());
            self.controller.ll.adv.enabled = false;
            self.controller
                .bridge
                .connected(ConnectionInfo {
                    handle: 1,
                    role: wchble::ll::Role::Peripheral,
                    peer_address_type: 1,
                    peer_address: peer,
                    interval: 39,
                    latency: 0,
                    supervision_timeout: 500,
                    master_clock_accuracy: 0,
                })
                .unwrap();
        }

        /// Push one L2CAP PDU split into LL payloads of `fragment` bytes the
        /// way the Android stack did (24 bytes each).
        fn inject_l2cap(&mut self, cid: u16, payload: &[u8], fragment: usize) {
            let mut l2cap = alloc::vec::Vec::new();
            l2cap.extend_from_slice(&(payload.len() as u16).to_le_bytes());
            l2cap.extend_from_slice(&cid.to_le_bytes());
            l2cap.extend_from_slice(payload);
            for (index, chunk) in l2cap.chunks(fragment).enumerate() {
                let llid = if index == 0 { 2 } else { 1 };
                assert!(self.controller.bridge.receive_acl(llid, chunk).is_ok());
            }
        }

        /// Collect every outbound Host ACL payload for a while.
        fn take_output(&mut self, pumps: usize) -> alloc::vec::Vec<TxAcl> {
            let mut out = alloc::vec::Vec::new();
            for _ in 0..pumps {
                self.pump();
                while let Some(tx) = self.controller.bridge.take_tx_acl() {
                    assert!(self.controller.bridge.ack_tx(tx.tag));
                    out.push(tx);
                }
            }
            out
        }

        /// Send one ATT Request and return the first ATT Response payload.
        fn att_request(&mut self, request: &[u8]) -> alloc::vec::Vec<u8> {
            self.inject_l2cap(ATT_CID, request, 24);
            for _ in 0..32 {
                for tx in self.take_output(1) {
                    if tx.len >= 5 && u16::from_le_bytes([tx.bytes[2], tx.bytes[3]]) == ATT_CID {
                        // Notifications and indications are unsolicited.
                        if tx.bytes[4] != 0x1b && tx.bytes[4] != 0x1d {
                            return tx.bytes[4..tx.len].to_vec();
                        }
                    }
                }
            }
            panic!("no ATT reply to {request:?}");
        }

        /// Find a characteristic's value handle with Read By Type (0x2803).
        fn value_handle(&mut self, uuid: &trouble_host::prelude::Uuid) -> u16 {
            let mut start = 0x0001u16;
            for _ in 0..64 {
                let mut request = [0x08, 0, 0, 0xff, 0xff, 0x03, 0x28];
                request[1..3].copy_from_slice(&start.to_le_bytes());
                let reply = self.att_request(&request);
                if reply[0] == 0x01 {
                    // ATT_ERROR: the range is exhausted.
                    break;
                }
                assert_eq!(reply[0], 0x09, "unexpected ATT reply: {reply:?}");
                let entry_len = reply[1] as usize;
                // Only the first entry is guaranteed complete: a response that
                // runs out of room may truncate later entries (they can have
                // different UUID sizes, so the length byte does not describe
                // them here).
                assert!(entry_len >= 7 && reply.len() >= 2 + entry_len);
                let entry = &reply[2..2 + entry_len];
                let declaration = u16::from_le_bytes([entry[0], entry[1]]);
                let value_handle = u16::from_le_bytes([entry[3], entry[4]]);
                // The tail is the UUID: two bytes (0x2803) or sixteen.
                if entry[5..] == *uuid.as_raw() {
                    return value_handle;
                }
                start = declaration + 1;
            }
            panic!("characteristic {:?} not found", uuid.as_raw());
        }

        /// Find a characteristic's CCCD handle: its value's first descriptor.
        fn cccd_handle(&mut self, uuid: &trouble_host::prelude::Uuid) -> u16 {
            self.value_handle(uuid) + 1
        }

        /// Start the Host and wait until it advertises.
        fn start(&mut self) {
            for _ in 0..4096 {
                self.pump();
                if self.controller.adv_enabled() {
                    return;
                }
            }
            panic!("Host never advertised");
        }

        /// Read one CCCD over ATT; returns its two value bytes.
        fn read_cccd(&mut self, handle: u16) -> [u8; 2] {
            let mut request = [0x0a, 0, 0];
            request[1..3].copy_from_slice(&handle.to_le_bytes());
            let reply = self.att_request(&request);
            assert_eq!(reply[0], 0x0b, "unexpected ATT reply: {reply:?}");
            [reply[1], reply[2]]
        }

        }

    fn fixture_start() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Warn)
            .filter_module("trouble_host", log::LevelFilter::Trace)
            .is_test(true)
            .try_init();
    }

    /// The crypto RNG and the boot-bond slot are process globals (the
    /// firmware has one instance of each), so the scenarios cannot overlap.
    fn serialize() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn seed_rng() {
        let mut seed = [0u8; 32];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8 ^ 0x5a;
        }
        rng::seed(&seed);
    }

    /// Replay the captured pairing sequence. With `drop_start` the first LL PDU
    /// of the Central's public key never reaches the Host, which is what a
    /// missed connect response does on hardware: the LL acknowledges the PDU
    /// but the Controller dropped it instead of queueing it for the Host.
    fn replay_captured_pairing(peer: [u8; 6], drop_start: bool) {
        fixture_start();

        let stats = host::HostStats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(host::run(
            wchble::hci::new(),
            &stats,
            host::RANDOM_ADDRESS
        ));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
            disconnect: None,
        };

        // Bring the Host up until it advertises.
        for _ in 0..4096 {
            fixture.pump();
            if fixture.controller.adv_enabled() {
                break;
            }
        }
        assert!(fixture.controller.adv_enabled(), "Host never advertised");

        fixture.connect(peer);
        fixture.pump_quiet(8);
        // The phone's LL_CONNECTION_UPDATE_REQ (frame 75) makes the firmware
        // report LE Connection Update Complete before the pairing starts.
        fixture
            .controller
            .bridge
            .connection_updated(39, 0, 500)
            .unwrap();
        fixture.pump_quiet(4);

        // Discovery traffic the phone produced before pairing (`x1-att-5`):
        // an indication for the GATT service-changed handle, a Read By Type
        // for an absent 0x2A2B, then a Read By Group for primary services.
        fixture.inject_l2cap(ATT_CID, &[0x1d, 0x03, 0x00, 0x01, 0x00, 0xff, 0xff], 24);
        fixture.take_output(8);
        fixture.inject_l2cap(ATT_CID, &[0x08, 0x01, 0x00, 0xff, 0xff, 0x2b, 0x2a], 24);
        fixture.take_output(8);

        // Android's Pairing Request, complete in one ACL packet.
        fixture.inject_l2cap(SMP_CID, &PAIRING_REQUEST, 24);
        let response = fixture.take_output(16);
        assert!(
            response.iter().any(|tx| tx.len >= 4
                && u16::from_le_bytes([tx.bytes[2], tx.bytes[3]]) == SMP_CID
                && tx.bytes[4] == 0x02),
            "no SMP Pairing Response: {:?}",
            response
                .iter()
                .map(|tx| (tx.llid, tx.len, tx.bytes[4]))
                .collect::<alloc::vec::Vec<_>>(),
        );

        // The phone asks for the primary-service list while the key exchange
        // runs; the Host answers from the same event loop.
        fixture.inject_l2cap(ATT_CID, &[0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28], 24);
        fixture.take_output(8);

        // The Central's public key spans three LL PDUs, exactly as captured:
        // the start in one connection event, the two continuations in the
        // next, with a Host poll in between.
        let mut key = alloc::vec::Vec::new();
        key.push(0x0c);
        key.extend_from_slice(&PEER_PUBLIC_KEY);
        let mut l2cap = alloc::vec::Vec::new();
        l2cap.extend_from_slice(&(key.len() as u16).to_le_bytes());
        l2cap.extend_from_slice(&SMP_CID.to_le_bytes());
        l2cap.extend_from_slice(&key);
        let mut answer = alloc::vec::Vec::new();
        if drop_start {
            for chunk in l2cap[24..].chunks(24) {
                if fixture.disconnect.is_some()
                    || fixture.controller.bridge.receive_acl(1, chunk).is_err()
                {
                    break;
                }
                fixture.take_output(8);
            }
        } else {
            fixture.controller.bridge.receive_acl(2, &l2cap[..24]).unwrap();
            answer.extend(fixture.take_output(8));
            for chunk in l2cap[24..].chunks(24) {
                fixture.controller.bridge.receive_acl(1, chunk).unwrap();
                answer.extend(fixture.take_output(8));
            }
            answer.extend(fixture.take_output(64));
        }

        if drop_start {
            // A continuation without a start fragment is `InvalidState` in the
            // Host, and `host.rs` turns that into HCI Disconnect 0x13 — the
            // exact reason the firmware recorded on air.
            assert_eq!(
                fixture.disconnect,
                Some(0x13),
                "dropping the start fragment must make the Host close the link"
            );
            assert!(
                !answer.iter().any(|tx| tx.len >= 5
                    && u16::from_le_bytes([tx.bytes[2], tx.bytes[3]]) == SMP_CID),
                "the Host answered a public key it never received"
            );
            return;
        }

        // The Host must answer with its own public key; an InvalidState here
        // is what terminated the real link.
        assert_eq!(
            fixture.disconnect, None,
            "Host closed the link on a complete public key"
        );
        assert!(
            answer.iter().any(|tx| tx.len >= 5
                && u16::from_le_bytes([tx.bytes[2], tx.bytes[3]]) == SMP_CID
                && tx.bytes[4] == 0x0c),
            "no SMP Pairing Public Key answer: {:?}",
            answer
                .iter()
                .map(|tx| (tx.llid, tx.len, tx.bytes[4]))
                .collect::<alloc::vec::Vec<_>>(),
        );
    }

    /// The captured run had no bond for the phone: `connect_with_rpas` is
    /// entered with the RPA as the peer address and no identity.
    #[test]
    fn lesc_public_key_reassembles_and_is_answered() {
        use trouble_host::prelude::{Address, Identity};

        let _guard = serialize();
        seed_rng();
        preload_bond(Identity {
            addr: Address::random(PEER),
            irk: None,
        });
        replay_captured_pairing(PEER, false);
    }

    /// A stored bond whose IRK resolves the Central's RPA: the Host then knows
    /// the peer's identity address, which differs from the link address.
    #[test]
    fn lesc_public_key_with_irk_resolved_rpa() {
        use trouble_host::prelude::{AddrKind, Address, BdAddr, Identity, IdentityResolvingKey};

        let _guard = serialize();
        seed_rng();
        let irk = IdentityResolvingKey::from_le_bytes([0x42; 16]).unwrap();
        // The Host resolves this RPA from the stored IRK, so the link address
        // and the bonded identity address are different.
        let peer = irk.generate_resolvable_address();
        assert_ne!(peer, PEER);
        preload_bond(Identity {
            addr: Address::new(AddrKind::PUBLIC, BdAddr::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
            irk: Some(irk),
        });
        replay_captured_pairing(peer, false);
    }

    /// The `x1-att-5` failure: the Controller accepted the first fragment of
    /// the key but the connect response was late, so it never queued the
    /// fragment for the Host. The Host then sees a bare continuation and closes
    /// the link with 0x13 after ~50 ms — before any ECDH could run.
    #[test]
    fn lesc_missing_start_fragment_closes_the_link() {
        use trouble_host::prelude::{Address, Identity};

        let _guard = serialize();
        seed_rng();
        preload_bond(Identity {
            addr: Address::random(PEER),
            irk: None,
        });
        replay_captured_pairing(PEER, true);
    }

/// Connect a bonded peer, subscribe to the vendor value characteristic and
/// return the record the Host would persist, plus the CCCD handle.
///
/// The Host future and its Controller are dropped on return, so the caller
/// starts from the same empty state a reboot leaves behind.
    fn capture_cccd_record() -> (client_att::ClientAttSnapshot, u16) {
        use trouble_host::prelude::{Address, Identity};

        preload_bond(Identity {
            addr: Address::random(PEER),
            irk: None,
        });
        client_att::set_boot_records(&[]);

        let stats = host::HostStats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(host::run(
            wchble::hci::new(),
            &stats,
            host::RANDOM_ADDRESS
        ));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
            disconnect: None,
        };
        fixture.start();
        fixture.connect(PEER);
        fixture.pump_quiet(16);

        let snapshots = client_att::value(client_att::STAT_SNAPSHOTS);
        let cccd = fixture.cccd_handle(&host::VALUE_UUID);
        let mut request = [0x12, 0, 0, 0x01, 0x00];
        request[1..3].copy_from_slice(&cccd.to_le_bytes());
        assert_eq!(fixture.att_request(&request).as_slice(), &[0x13]);
        fixture.pump_quiet(4);
        assert_eq!(client_att::value(client_att::STAT_SNAPSHOTS) - snapshots, 1);
        assert_eq!(
            fixture.read_cccd(cccd),
            [0x01, 0x00],
            "the write must enable notifications"
        );

        let pending = client_att::signals()
            .take_pending()
            .expect("a CCCD write must queue a snapshot");
        assert_eq!(pending.len(), 1);
        // Header: three CCCD entries, six value bytes.
        assert_eq!(&pending[0].raw[..4], &[3, 0, 6, 0]);
        assert_eq!(pending[0].raw_len, 22);

        // Leave the shared HCI channels empty for the next Host instance.
        fixture.pump_quiet(16);
        (pending, cccd)
    }

    /// A bonded peer's CCCD table is stored and served again after a reboot,
    /// without the peer writing it a second time.
    #[test]
    fn bonded_cccd_is_restored_after_reboot() {
        use trouble_host::prelude::{Address, Identity};

        let _guard = serialize();
        seed_rng();
        fixture_start();

        let (records, cccd) = capture_cccd_record();

        // Reboot: only the bond and the captured table survive.
        preload_bond(Identity {
            addr: Address::random(PEER),
            irk: None,
        });
        client_att::set_boot_records(&records);
        let restored = client_att::value(client_att::STAT_RESTORE_OK);
        let missing = client_att::value(client_att::STAT_RESTORE_NO_RECORD);

        let stats = host::HostStats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(host::run(
            wchble::hci::new(),
            &stats,
            host::RANDOM_ADDRESS
        ));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
            disconnect: None,
        };
        fixture.start();
        fixture.connect(PEER);
        fixture.pump_quiet(16);

        assert_eq!(client_att::value(client_att::STAT_RESTORE_NO_RECORD), missing);
        assert_eq!(
            client_att::value(client_att::STAT_RESTORE_OK) - restored,
            1,
            "the stored table must be applied to the rebound peer"
        );
        assert_eq!(fixture.read_cccd(cccd), [0x01, 0x00]);
    }

    /// A stored table from another GATT layout must not change any CCCD.
    ///
    /// `set_client_att_table` copies matching handles before the read-back can
    /// notice the mismatch, so `restore` has to roll the table back.
    #[test]
    fn incompatible_att_table_is_rejected_without_effect() {
        use trouble_host::prelude::{Address, Identity};

        let _guard = serialize();
        seed_rng();
        fixture_start();

        // Learn the value CCCD handle with a real connection.
        let (records, cccd) = capture_cccd_record();

        // Same value, different table shape: a single index entry at the value
        // CCCD's handle.
        let mut stored = records[0];
        let mut raw = [0u8; 10];
        raw[0] = 1; // attribute count
        raw[2] = 2; // value bytes
        raw[4..6].copy_from_slice(&cccd.to_le_bytes());
        raw[8..10].copy_from_slice(&[0x01, 0x00]);
        assert!(stored.set_raw(&raw));
        let mut list = client_att::ClientAttSnapshot::new();
        let _ = list.push(stored);
        client_att::set_boot_records(&list);
        preload_bond(Identity {
            addr: Address::random(PEER),
            irk: None,
        });

        let restored = client_att::value(client_att::STAT_RESTORE_OK);
        let invalid = client_att::value(client_att::STAT_RESTORE_INVALID);

        let stats = host::HostStats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(host::run(
            wchble::hci::new(),
            &stats,
            host::RANDOM_ADDRESS
        ));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
            disconnect: None,
        };
        fixture.start();
        fixture.connect(PEER);
        fixture.pump_quiet(16);

        assert_eq!(client_att::value(client_att::STAT_RESTORE_OK), restored);
        assert_eq!(
            client_att::value(client_att::STAT_RESTORE_INVALID) - invalid,
            1
        );
        assert_eq!(
            fixture.read_cccd(cccd),
            [0x00, 0x00],
            "a rejected table must not leave the CCCD enabled"
        );
    }

    /// A record keyed to another peer is never applied, even when the connected
    /// peer is bonded.
    #[test]
    fn cccd_record_for_another_peer_is_ignored() {
        use trouble_host::prelude::{Address, Identity};

        const OTHER: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let _guard = serialize();
        seed_rng();
        fixture_start();

        let (kind, address) = client_att::identity_parts(&Identity {
            addr: Address::random(OTHER),
            irk: None,
        });
        let mut record = client_att::ClientAttRecord {
            address_kind: kind,
            address,
            ..client_att::ClientAttRecord::empty()
        };
        // An empty table is still a well-formed raw record.
        assert!(record.set_raw(&[0, 0, 0, 0]));
        let mut records = client_att::ClientAttSnapshot::new();
        let _ = records.push(record);
        client_att::set_boot_records(&records);
        preload_bond(Identity {
            addr: Address::random(PEER),
            irk: None,
        });

        let restored = client_att::value(client_att::STAT_RESTORE_OK);
        let missing = client_att::value(client_att::STAT_RESTORE_NO_RECORD);

        let stats = host::HostStats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(host::run(
            wchble::hci::new(),
            &stats,
            host::RANDOM_ADDRESS
        ));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
            disconnect: None,
        };
        fixture.start();
        fixture.connect(PEER);
        fixture.pump_quiet(16);

        assert_eq!(
            client_att::value(client_att::STAT_RESTORE_NO_RECORD) - missing,
            1
        );
        assert_eq!(client_att::value(client_att::STAT_RESTORE_OK), restored);
        let cccd = fixture.cccd_handle(&host::VALUE_UUID);
        assert_eq!(fixture.read_cccd(cccd), [0x00, 0x00]);
    }

    /// `DEL!` deletes the bonds; the RAM shadow must be dropped with them, or
    /// the next bonded CCCD snapshot would write the deleted peers back.
    #[cfg(feature = "accept-control")]
    #[test]
    fn delete_clears_the_in_memory_shadow() {
        use trouble_host::prelude::{Address, Identity};

        let _guard = serialize();
        seed_rng();
        fixture_start();

        preload_bond(Identity {
            addr: Address::random(PEER),
            irk: None,
        });
        client_att::set_boot_records(&[]);

        let stats = host::HostStats::new();
        let controller = SoftRunner::new();
        let mut future = pin!(host::run(
            wchble::hci::new(),
            &stats,
            host::RANDOM_ADDRESS
        ));
        let mut fixture = Fixture {
            host: future.as_mut(),
            stats: &stats,
            controller,
            disconnect: None,
        };
        fixture.start();
        fixture.connect(PEER);
        fixture.pump_quiet(16);

        let cccd = fixture.cccd_handle(&host::VALUE_UUID);
        let mut subscribe = [0x12, 0, 0, 0x01, 0x00];
        subscribe[1..3].copy_from_slice(&cccd.to_le_bytes());
        assert_eq!(fixture.att_request(&subscribe).as_slice(), &[0x13]);
        fixture.pump_quiet(4);
        assert_eq!(client_att::value(client_att::STAT_SHADOW_RECORDS), 1);

        let clears = bond::value(bond::STAT_CLEAR_REQUESTS);
        let control = fixture.value_handle(&host::BOND_CONTROL_UUID);
        let mut delete = [0x12, 0, 0, b'D', b'E', b'L', b'!'];
        delete[1..3].copy_from_slice(&control.to_le_bytes());
        assert_eq!(fixture.att_request(&delete).as_slice(), &[0x13]);
        fixture.pump_quiet(4);

        assert_eq!(bond::value(bond::STAT_CLEAR_REQUESTS) - clears, 1);
        assert_eq!(
            client_att::value(client_att::STAT_SHADOW_RECORDS),
            0,
            "a deleted bond must not survive in the shadow"
        );
    }
}
