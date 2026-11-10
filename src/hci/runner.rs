//! Soft HCI command/ACL pump and bounded single-connection bridge.
//!
//! A cooperative RF owner calls [`SoftRunner::pump_once`] only while idle and
//! synchronizes connection lifecycle through [`SoftRunner::bridge`]. LL radio
//! timing, retransmission and sequence numbers remain outside this module.

use bt_hci::transport::PacketKind;

use crate::ll::{scan, LinkLayer};

use super::connection::{event_packet, BridgeError, ConnectionBridge};
use super::transport::{self, Packet};

/// HCI success.
const HCI_SUCCESS: u8 = 0x00;
/// Unknown HCI command.
const HCI_UNKNOWN_COMMAND: u8 = 0x01;
/// Invalid HCI command parameters.
const HCI_INVALID_PARAMETERS: u8 = 0x12;
/// Command disallowed.
const HCI_COMMAND_DISALLOWED: u8 = 0x0c;

/// ACL data packet length reported by `LE Read Buffer Size` (no DLE yet).
const ACL_DATA_PACKET_LENGTH: u16 = super::connection::ACL_DATA_PACKET_LENGTH as u16;
/// Number of ACL credits advertised to the Host.
const ACL_CREDITS: u8 = super::connection::ACL_CREDITS as u8;

/// Default public BD_ADDR placeholder (HAL / OTP can override later).
const DEFAULT_BD_ADDR: [u8; 6] = [0x00, 0x00, 0x00, 0xc1, 0xff, 0xee];

/// Passive-scan configuration accepted from `LE Set Scan Parameters`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanState {
    pub enabled: bool,
    pub active: bool,
    /// HCI units of 0.625 ms.
    pub interval_slots: u16,
    pub window_slots: u16,
    pub filter_duplicates: bool,
}

/// Pending `LE Create Connection` request, consumed by the RF owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnRequest {
    pub peer_addr: [u8; 6],
    pub peer_random: bool,
    pub own_random: bool,
    /// HCI units of 0.625 ms.
    pub scan_interval_slots: u16,
    pub scan_window_slots: u16,
    /// HCI units of 1.25 ms.
    pub interval_min: u16,
    pub interval_max: u16,
    pub latency: u16,
    /// HCI units of 10 ms.
    pub timeout: u16,
    pub min_ce: u16,
    pub max_ce: u16,
}

/// Drains Host→Controller packets and emits Command Complete / Status.
#[derive(Debug)]
pub struct SoftRunner {
    pub ll: LinkLayer,
    pub bridge: ConnectionBridge,
    scan: ScanState,
    pending_connect: Option<CreateConnRequest>,
    adv_reports_dropped: u32,
    pending_reply: Option<Packet>,
    pending_input: Option<(Packet, u32)>,
    reset_pending: bool,
    event_mask: u64,
    le_event_mask: u64,
    bd_addr: [u8; 6],
    /// Address from `LE Set Random Address` / HAL seed; `None` = public BD_ADDR.
    random_addr: Option<[u8; 6]>,
}

impl Default for SoftRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftRunner {
    pub fn new() -> Self {
        Self {
            ll: LinkLayer::new(),
            bridge: ConnectionBridge::new(),
            scan: ScanState::default(),
            pending_connect: None,
            adv_reports_dropped: 0,
            pending_reply: None,
            pending_input: None,
            reset_pending: false,
            event_mask: u64::MAX,
            le_event_mask: 0x1f,
            bd_addr: DEFAULT_BD_ADDR,
            random_addr: None,
        }
    }

    /// Override the public address returned by `Read BD_ADDR`.
    pub fn set_bd_addr(&mut self, addr: [u8; 6]) {
        self.bd_addr = addr;
        if !self.ll.adv.random_addr {
            self.ll.adv.own_addr = addr;
        }
    }

    /// Seed the LE random address used as AdvA when advertising with
    /// Own_Address_Type = Random.
    ///
    /// This is a HAL fallback, not a substitute for HCI: the pinned Trouble
    /// (`ControlRunner::run`) sends `Reset` followed by `LE Set Random Address`
    /// whenever `StackBuilder::set_random_address` was used. Hosts that omit
    /// 0x2005 (or HALs that want an address before Host init) can seed here;
    /// the value is re-applied when `Reset` rebuilds the link layer.
    pub fn set_random_addr(&mut self, addr: [u8; 6]) {
        self.random_addr = Some(addr);
        self.sync_adv_addr();
    }

    /// Point `AdvState` at the selected own address (random if one was set,
    /// otherwise the public BD_ADDR).
    fn sync_adv_addr(&mut self) {
        match self.random_addr {
            Some(addr) => {
                self.ll.adv.own_addr = addr;
                self.ll.adv.random_addr = true;
            }
            None => {
                self.ll.adv.own_addr = self.bd_addr;
                self.ll.adv.random_addr = false;
            }
        }
    }

    /// True while Host has advertising enabled.
    pub fn adv_enabled(&self) -> bool {
        self.ll.adv.enabled
    }

    /// Advertising interval in microseconds (from HCI slots).
    pub fn adv_interval_us(&self) -> u32 {
        self.ll.adv.interval_us()
    }

    /// Channels selected by the current advertising channel map.
    pub fn adv_channels(&self) -> impl Iterator<Item = u8> + '_ {
        self.ll.adv.channels()
    }

    /// Build the current ADV_IND PDU when advertising is enabled.
    pub fn build_adv_pdu(&self, out: &mut [u8]) -> Option<usize> {
        self.ll.adv.build_adv_ind(out)
    }

    pub fn scan_state(&self) -> ScanState {
        self.scan
    }

    pub fn pending_connect(&self) -> Option<CreateConnRequest> {
        self.pending_connect
    }

    /// The RF owner calls this once it has resolved the pending request
    /// (success or initiator timeout) so a later cancel is rejected.
    pub fn clear_pending_connect(&mut self) {
        self.pending_connect = None;
    }

    /// Currently selected own address and whether it is random.
    pub fn own_addr(&self) -> ([u8; 6], bool) {
        (self.ll.adv.own_addr, self.ll.adv.random_addr)
    }

    pub fn adv_reports_dropped(&self) -> u32 {
        self.adv_reports_dropped
    }

    /// Queue one HCI Advertising Report for a CRC-valid legacy PDU.
    /// Returns false when scan is disabled, the type is not reportable, or
    /// the event queue is full. Scan reports are droppable diagnostics.
    pub fn push_adv_report(&mut self, pdu: &scan::Pdu<'_>, rssi: i8) -> bool {
        if !self.scan.enabled || !self.bridge.le_event_enabled(2) {
            return false;
        }
        let event_type = match pdu.pdu_type() {
            scan::PduType::AdvInd => 0x00,
            scan::PduType::AdvDirectInd => 0x01,
            scan::PduType::AdvScanInd => 0x02,
            scan::PduType::AdvNonconnInd => 0x03,
            scan::PduType::ScanRsp => 0x04,
            _ => return false,
        };
        let adv_a = match pdu.adv_a() {
            Some(addr) => *addr,
            None => return false,
        };
        // Advertising Report Data excludes AdvA; ADV_DIRECT_IND carries none.
        let data: &[u8] = match pdu.pdu_type() {
            scan::PduType::AdvInd
            | scan::PduType::AdvScanInd
            | scan::PduType::AdvNonconnInd
            | scan::PduType::ScanRsp => pdu.payload().get(6..).unwrap_or(&[]),
            _ => &[],
        };
        let mut parameters = [0u8; 2 + 10 + scan::MAX_LEGACY_ADV_PAYLOAD];
        parameters[0] = 0x02; // LE Advertising Report
        parameters[1] = 1; // one report
        parameters[2] = event_type;
        parameters[3] = u8::from(pdu.tx_add());
        parameters[4..10].copy_from_slice(&adv_a);
        parameters[10] = data.len() as u8;
        parameters[11..11 + data.len()].copy_from_slice(data);
        parameters[11 + data.len()] = rssi as u8;
        let len = 12 + data.len();
        if !self.bridge.try_push_event(event_packet(0x3e, &parameters[..len])) {
            self.adv_reports_dropped = self.adv_reports_dropped.wrapping_add(1);
            return false;
        }
        true
    }

    /// Bounded, non-blocking idle-time pump. It never borrows the RF owner
    /// across an await, and retains owned input/output packets under backpressure.
    pub fn pump_once(&mut self) -> bool {
        let mut progressed = false;
        if self.reset_pending && self.bridge.take_reset_done() {
            self.finish_reset();
            progressed = true;
        }
        if let Some(reply) = self.pending_reply {
            if transport::try_send_controller_packet(reply).is_err() {
                return progressed;
            }
            self.pending_reply = None;
            return true;
        }
        if self.reset_pending {
            return progressed;
        }
        // One output at most, with lifecycle events ahead of ACL data.
        if self.bridge.flush_one() {
            return true;
        }
        let input = self
            .pending_input
            .take()
            .filter(|(_, epoch)| *epoch == self.bridge.epoch());
        let Some((packet, epoch)) = input.or_else(|| {
            transport::try_receive_host_packet().map(|packet| (packet, self.bridge.epoch()))
        }) else {
            return progressed;
        };
        match packet.kind {
            PacketKind::Cmd => self.handle_command(packet.payload()),
            PacketKind::AclData => {
                if self.bridge.enqueue_tx(&packet) == Err(BridgeError::Full) {
                    self.pending_input = Some((packet, epoch));
                    return progressed;
                }
            }
            _ => {}
        }
        if let Some(reply) = self.pending_reply {
            if transport::try_send_controller_packet(reply).is_ok() {
                self.pending_reply = None;
            }
        }
        true
    }

    /// Compatibility entry point for existing cooperative async callers.
    pub async fn poll_once(&mut self) -> bool {
        self.pump_once()
    }

    /// Legacy advertising-only async service. Connected RF applications use
    /// pump_once at idle boundaries instead of holding this future across RF.
    pub async fn serve_one(&mut self) {
        loop {
            let progressed = self.pump_once();
            if self.pending_reply.is_some() || self.bridge.has_output() {
                transport::wait_for_output_space().await;
            } else if progressed {
                return;
            } else {
                transport::wait_for_host_packet().await;
            }
        }
    }

    pub async fn run(&mut self) -> ! {
        loop {
            self.serve_one().await;
        }
    }

    fn finish_reset(&mut self) {
        self.reset_pending = false;
        self.pending_input = None;
        self.event_mask = u64::MAX;
        self.le_event_mask = 0x1f;
        self.bridge.set_masks(self.event_mask, self.le_event_mask);
        self.ll = LinkLayer::new();
        self.scan = ScanState::default();
        self.pending_connect = None;
        if self.random_addr.is_some() {
            self.sync_adv_addr();
        }
        self.pending_reply = Some(transport::command_complete_packet(0x0c03, HCI_SUCCESS, &[]));
    }

    fn handle_command(&mut self, bytes: &[u8]) {
        if bytes.len() < 3 || bytes.len() != 3 + usize::from(bytes[2]) {
            return;
        }
        let opcode = u16::from_le_bytes([bytes[0], bytes[1]]);
        let params = &bytes[3..];

        // Async commands answer with Command Status, not Complete.
        match opcode {
            0x0406 => {
                let status = if params.len() != 3
                    || !matches!(params[2], 0x05 | 0x13 | 0x14 | 0x15 | 0x1a | 0x29 | 0x3b)
                {
                    HCI_INVALID_PARAMETERS
                } else {
                    self.bridge
                        .request_disconnect(u16::from_le_bytes([params[0], params[1]]), params[2])
                };
                self.pending_reply = Some(transport::command_status_packet(opcode, status));
                return;
            }
            0x200d => {
                let status = self.create_connection(params);
                self.pending_reply = Some(transport::command_status_packet(opcode, status));
                return;
            }
            0x2013 => {
                self.pending_reply = Some(transport::command_status_packet(
                    opcode,
                    HCI_COMMAND_DISALLOWED,
                ));
                return;
            }
            0x0c03 if params.is_empty() => {
                if self.bridge.is_connected() || self.ll.adv.enabled {
                    self.reset_pending = true;
                    self.bridge.request_reset();
                } else {
                    self.bridge.request_reset();
                    self.bridge.reset_finished();
                    self.bridge.take_reset_done();
                    self.finish_reset();
                }
                return;
            }
            _ => {}
        }

        // Own the address while the command handler mutates advertising state.
        let bd_addr = self.bd_addr;

        let result: Result<&[u8], u8> = match opcode {
            // Set Event Mask / LE Set Event Mask
            0x0c01 | 0x2001 if params.len() == 8 => {
                let mask = u64::from_le_bytes(params.try_into().unwrap());
                if opcode == 0x0c01 {
                    self.event_mask = mask;
                } else {
                    self.le_event_mask = mask;
                }
                self.bridge.set_masks(self.event_mask, self.le_event_mask);
                Ok(&[][..])
            }
            // Set Event Mask Page 2
            0x0c63 if params.len() == 8 => Ok(&[][..]),
            // Set Controller To Host Flow Control — only "off" accepted.
            0x0c31 if params == [0] => Ok(&[][..]),
            0x0c31 => Err(HCI_INVALID_PARAMETERS),
            // Host Buffer Size — accept and ignore (no C→H flow control).
            0x0c33 if params.len() == 7 => Ok(&[][..]),
            // Host Number Of Completed Packets — accept empty work.
            0x0c35 => Ok(&[][..]),
            // Read BD_ADDR
            0x1009 if params.is_empty() => Ok(&bd_addr[..]),
            // Read RSSI — no connection; disallowed until Phase C.
            0x1405 => Err(HCI_COMMAND_DISALLOWED),
            // LE Read Buffer Size (v1)
            0x2002 if params.is_empty() => {
                static BUFFER_SIZE: [u8; 3] = [
                    ACL_DATA_PACKET_LENGTH as u8,
                    (ACL_DATA_PACKET_LENGTH >> 8) as u8,
                    ACL_CREDITS,
                ];
                Ok(&BUFFER_SIZE)
            }
            // Match the implemented, unencrypted LE 1M air-interface features.
            0x2003 if params.is_empty() => {
                static FEATURES: [u8; 8] = [0; 8];
                Ok(&FEATURES)
            }
            // LE Set Random Address
            0x2005 if params.len() == 6 => {
                if self.ll.adv.enabled {
                    Err(HCI_COMMAND_DISALLOWED)
                } else {
                    self.set_random_addr(params.try_into().unwrap());
                    Ok(&[][..])
                }
            }
            // LE Set Advertising Parameters (store interval / channel map only).
            0x2006 if params.len() == 15 => self.set_adv_params(params),
            // LE Set Advertising Data
            0x2008 if params.len() == 32 => {
                if self.ll.adv.enabled {
                    Err(HCI_COMMAND_DISALLOWED)
                } else if self.ll.adv.set_adv_data(params[0], &params[1..]) {
                    Ok(&[][..])
                } else {
                    Err(HCI_INVALID_PARAMETERS)
                }
            }
            // LE Set Scan Response Data
            0x2009 if params.len() == 32 => {
                if self.ll.adv.enabled {
                    Err(HCI_COMMAND_DISALLOWED)
                } else if self.ll.adv.set_scan_rsp(params[0], &params[1..]) {
                    Ok(&[][..])
                } else {
                    Err(HCI_INVALID_PARAMETERS)
                }
            }
            // LE Set Advertise Enable
            0x200a if params.len() == 1 && params[0] <= 1 => {
                let enable = params[0] != 0;
                if enable {
                    // Resolve AdvA right before use; 0x2005 normally did this
                    // already, but Hosts may skip it.
                    self.sync_adv_addr();
                }
                self.ll.adv.enabled = enable;
                Ok(&[][..])
            }
            // LE Set Scan Parameters — passive only.
            0x200b if params.len() == 7 => self.set_scan_params(params),
            // LE Set Scan Enable
            0x200c if params.len() == 2 && params.iter().all(|value| *value <= 1) => {
                let enable = params[0] != 0;
                if enable && (self.bridge.is_connected() || self.pending_connect.is_some()) {
                    self.reply_status(opcode, HCI_COMMAND_DISALLOWED);
                    return;
                }
                if enable {
                    self.sync_adv_addr();
                }
                self.scan.enabled = enable;
                self.scan.filter_duplicates = params[1] != 0;
                Ok(&[][..])
            }
            // LE Create Connection Cancel
            0x200e if params.is_empty() => {
                if self.pending_connect.take().is_none() {
                    self.reply_status(opcode, HCI_COMMAND_DISALLOWED);
                    return;
                }
                let _ = self.bridge.connection_failed(0x02);
                Ok(&[][..])
            }
            // Filter Accept List size / clear / add — report empty list.
            0x200f if params.is_empty() => Ok(&[0][..]),
            0x2010 if params.is_empty() => Ok(&[][..]),
            0x2011 => Err(HCI_COMMAND_DISALLOWED),
            // LE Rand
            0x2018 if params.is_empty() => {
                // Deterministic placeholder; HAL should seed real entropy later.
                self.pending_reply = Some(transport::command_complete_packet(
                    opcode,
                    HCI_SUCCESS,
                    &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                ));
                return;
            }
            // LE Set Ext Advertising / Scan Enable — legacy-only controller.
            0x2039 | 0x2042 => Err(HCI_COMMAND_DISALLOWED),
            _ => Err(HCI_UNKNOWN_COMMAND),
        };

        self.pending_reply = Some(match result {
            Ok(return_data) => transport::command_complete_packet(opcode, HCI_SUCCESS, return_data),
            Err(status) => transport::command_complete_packet(opcode, status, &[]),
        });
    }

    fn set_adv_params(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        if self.ll.adv.enabled {
            return Err(HCI_COMMAND_DISALLOWED);
        }
        let min = u16::from_le_bytes([params[0], params[1]]);
        let max = u16::from_le_bytes([params[2], params[3]]);
        if !(0x20..=0x4000).contains(&min) || !(min..=0x4000).contains(&max) {
            return Err(HCI_INVALID_PARAMETERS);
        }
        // ADV_IND + random own address + channel map only — match rusted-ch5 checks.
        if params[4] != 0
            || params[5] != 1
            || params[14] != 0
            || params[13] == 0
            || params[13] & !7 != 0
        {
            return Err(HCI_INVALID_PARAMETERS);
        }
        self.ll.adv.interval_slots = min;
        self.ll.adv.channel_map = params[13];
        Ok(&[])
    }

    fn reply_status(&mut self, opcode: u16, status: u8) {
        self.pending_reply = Some(transport::command_status_packet(opcode, status));
    }

    fn set_scan_params(&mut self, params: &[u8]) -> Result<&'static [u8], u8> {
        let scan_type = params[0];
        let interval = u16::from_le_bytes([params[1], params[2]]);
        let window = u16::from_le_bytes([params[3], params[4]]);
        if scan_type > 1
            || !(0x0004..=0x4000).contains(&interval)
            || !(0x0004..=0x4000).contains(&window)
            || window > interval
            || params[5] > 1
            || params[6] > 3
        {
            return Err(HCI_INVALID_PARAMETERS);
        }
        if scan_type == 1 {
            // Active scanning needs SCAN_REQ pacing that this probe does not
            // implement; reject it rather than silently scanning passively.
            return Err(HCI_INVALID_PARAMETERS);
        }
        self.scan.active = false;
        self.scan.interval_slots = interval;
        self.scan.window_slots = window;
        Ok(&[])
    }

    fn create_connection(&mut self, params: &[u8]) -> u8 {
        if params.len() != 25 {
            return HCI_INVALID_PARAMETERS;
        }
        if self.bridge.is_connected() || self.pending_connect.is_some() {
            return HCI_COMMAND_DISALLOWED;
        }
        let le16 = |index: usize| u16::from_le_bytes([params[index], params[index + 1]]);
        let scan_interval = le16(0);
        let scan_window = le16(2);
        let filter_policy = params[4];
        let peer_kind = params[5];
        let own_kind = params[12];
        let interval_min = le16(13);
        let interval_max = le16(15);
        let latency = le16(17);
        let timeout = le16(19);
        if filter_policy > 1
            || peer_kind > 1
            || own_kind > 1
            || !(0x0004..=0x4000).contains(&scan_interval)
            || !(0x0004..=0x4000).contains(&scan_window)
            || scan_window > scan_interval
            || !(0x0006..=0x0c80).contains(&interval_min)
            || interval_max < interval_min
            || interval_max > 0x0c80
            || latency > 499
            || !(0x000a..=0x0c80).contains(&timeout)
            || u32::from(timeout) * 10_000
                <= 2 * u32::from(latency + 1) * u32::from(interval_max) * 1250
        {
            return HCI_INVALID_PARAMETERS;
        }
        let mut peer_addr = [0; 6];
        peer_addr.copy_from_slice(&params[6..12]);
        self.pending_connect = Some(CreateConnRequest {
            peer_addr,
            peer_random: peer_kind == 1,
            own_random: own_kind == 1,
            scan_interval_slots: scan_interval,
            scan_window_slots: scan_window,
            interval_min,
            interval_max,
            latency,
            timeout,
            min_ce: le16(21),
            max_ce: le16(23),
        });
        // Initiating replaces scanning on the radio owner.
        self.scan.enabled = false;
        HCI_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use bt_hci::transport::PacketKind;
    use std::sync::{Mutex, OnceLock};

    /// Global HCI channels are shared; serialize tests that touch them.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn inject_cmd(opcode: u16, params: &[u8]) {
        let mut bytes = [0u8; transport::HCI_PACKET_CAPACITY];
        bytes[0..2].copy_from_slice(&opcode.to_le_bytes());
        bytes[2] = params.len() as u8;
        bytes[3..3 + params.len()].copy_from_slice(params);
        let packet = Packet::from_bytes(PacketKind::Cmd, &bytes[..3 + params.len()]).unwrap();
        transport::try_send_host_packet(packet).unwrap();
    }

    fn expect_command_complete(opcode: u16, status: u8, return_data: &[u8]) {
        let packet = transport::try_receive_controller_packet().expect("missing CC");
        assert_eq!(packet.kind, PacketKind::Event);
        let payload = packet.payload();
        assert_eq!(payload[0], 0x0e);
        assert_eq!(payload[1] as usize, 4 + return_data.len());
        assert_eq!(payload[2], 1);
        assert_eq!(u16::from_le_bytes([payload[3], payload[4]]), opcode);
        assert_eq!(payload[5], status);
        assert_eq!(&payload[6..6 + return_data.len()], return_data);
    }

    #[test]
    fn set_random_addr_survives_reset() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let addr = [0x42, 0x00, 0x00, 0xEE, 0xFF, 0xC1];
        runner.set_random_addr(addr);

        pollster::block_on(async {
            inject_cmd(0x0c03, &[]);
            runner.serve_one().await;
            expect_command_complete(0x0c03, HCI_SUCCESS, &[]);
        });

        assert_eq!(runner.ll.adv.own_addr, addr);
        assert!(runner.ll.adv.random_addr);
    }

    #[test]
    fn reset_and_read_bd_addr_roundtrip() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_bd_addr([1, 2, 3, 4, 5, 6]);

        pollster::block_on(async {
            inject_cmd(0x0c03, &[]);
            runner.serve_one().await;
            expect_command_complete(0x0c03, HCI_SUCCESS, &[]);

            inject_cmd(0x1009, &[]);
            runner.serve_one().await;
            expect_command_complete(0x1009, HCI_SUCCESS, &[1, 2, 3, 4, 5, 6]);
        });
    }

    #[test]
    fn le_set_adv_data_builds_pdu() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            // Random address + params + AdvData + enable.
            inject_cmd(0x2005, &[0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x01]);
            runner.serve_one().await;
            expect_command_complete(0x2005, HCI_SUCCESS, &[]);

            let mut params = [0u8; 15];
            params[0..2].copy_from_slice(&0x00a0u16.to_le_bytes()); // 100 ms
            params[2..4].copy_from_slice(&0x00a0u16.to_le_bytes());
            params[4] = 0; // ADV_IND
            params[5] = 1; // random own
            params[13] = 0x07; // 37/38/39
            inject_cmd(0x2006, &params);
            runner.serve_one().await;
            expect_command_complete(0x2006, HCI_SUCCESS, &[]);

            let mut adv = [0u8; 32];
            adv[0] = 3;
            adv[1..4].copy_from_slice(&[0x02, 0x01, 0x06]);
            inject_cmd(0x2008, &adv);
            runner.serve_one().await;
            expect_command_complete(0x2008, HCI_SUCCESS, &[]);

            inject_cmd(0x200a, &[1]);
            runner.serve_one().await;
            expect_command_complete(0x200a, HCI_SUCCESS, &[]);

            assert!(runner.adv_enabled());
            let mut chs = [0u8; 3];
            let mut n = 0;
            for ch in runner.adv_channels() {
                chs[n] = ch;
                n += 1;
            }
            assert_eq!(&chs[..n], &[37, 38, 39]);
            let mut pdu = [0u8; 40];
            let n = runner.build_adv_pdu(&mut pdu).unwrap();
            assert_eq!(n, 2 + 6 + 3);
            assert_eq!(pdu[0], 0x40);
            assert_eq!(&pdu[2..8], &[0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x01]);
            assert_eq!(&pdu[8..11], &[0x02, 0x01, 0x06]);
        });
    }

    fn connection_info() -> super::super::connection::ConnectionInfo {
        super::super::connection::ConnectionInfo {
            handle: 1,
            role: crate::ll::Role::Peripheral,
            peer_address_type: 1,
            peer_address: [1, 2, 3, 4, 5, 0xc6],
            interval: 24,
            latency: 0,
            supervision_timeout: 200,
            master_clock_accuracy: 0,
        }
    }

    fn acl(handle: u16, pb: u16, data: &[u8]) -> Packet {
        let mut packet = Packet::empty(PacketKind::AclData);
        packet.bytes[..2].copy_from_slice(&(handle | (pb << 12)).to_le_bytes());
        packet.bytes[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        packet.bytes[4..4 + data.len()].copy_from_slice(data);
        packet.len = data.len() + 4;
        packet
    }

    fn open(runner: &mut SoftRunner) {
        runner.bridge.connected(connection_info()).unwrap();
        assert!(runner.pump_once());
        let event = transport::try_receive_controller_packet().unwrap();
        assert_eq!(&event.payload()[..3], &[0x3e, 19, 1]);
        assert_eq!(&event.payload()[4..8], &[1, 0, 1, 1]);
    }

    #[test]
    fn acl_five_real_slots_and_more_than_five_credit_cycles() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        for cycle in 0..4 {
            for n in 0..5 {
                runner
                    .bridge
                    .enqueue_tx(&acl(1, n % 2, &[cycle as u8; 27]))
                    .unwrap();
            }
            assert_eq!(
                runner.bridge.enqueue_tx(&acl(1, 0, &[0])),
                Err(BridgeError::Full)
            );
            let mut tags = [None; 5];
            for (n, tag) in tags.iter_mut().enumerate() {
                let tx = runner.bridge.take_tx_acl().unwrap();
                assert_eq!(tx.llid, if n % 2 == 0 { 2 } else { 1 });
                assert_eq!(tx.len, 27);
                assert_eq!(&tx.bytes, &[cycle as u8; 27]);
                *tag = Some(tx.tag);
            }
            assert!(runner.bridge.take_tx_acl().is_none());
            assert_eq!(
                runner.bridge.enqueue_tx(&acl(1, 0, &[0])),
                Err(BridgeError::Full)
            );
            assert!(transport::try_receive_controller_packet().is_none());
            for tag in tags.into_iter().flatten() {
                assert!(runner.bridge.ack_tx(tag));
                assert!(!runner.bridge.ack_tx(tag));
            }
            assert!(runner.pump_once());
            assert_eq!(
                transport::try_receive_controller_packet()
                    .unwrap()
                    .payload(),
                &[0x13, 5, 1, 1, 0, 5, 0]
            );
            assert!(!runner.pump_once());
        }
    }

    #[test]
    fn acl_validates_handle_pb_bc_and_exact_27_byte_limit() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        assert_eq!(
            runner.bridge.enqueue_tx(&acl(1, 0, &[1])),
            Err(BridgeError::NotConnected)
        );
        open(&mut runner);
        for packet in [
            acl(2, 0, &[1]),
            acl(1, 2, &[1]),
            acl(1, 3, &[1]),
            acl(0x4001, 0, &[1]),
            acl(1, 0, &[1; 28]),
        ] {
            assert_eq!(
                runner.bridge.enqueue_tx(&packet),
                Err(BridgeError::InvalidPacket)
            );
        }
        let mut truncated = acl(1, 0, &[1, 2]);
        truncated.len -= 1;
        assert_eq!(
            runner.bridge.enqueue_tx(&truncated),
            Err(BridgeError::InvalidPacket)
        );
        assert!(runner.bridge.enqueue_tx(&acl(1, 0, &[1; 27])).is_ok());
    }

    #[test]
    fn rx_backpressure_pb_mapping_and_empty_control_packets() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.bridge.connected(connection_info()).unwrap();
        assert!(!runner.bridge.can_receive_acl(3, 1));
        assert!(!runner.bridge.can_receive_acl(2, 28));
        assert_eq!(
            runner.bridge.receive_acl(3, &[0]),
            Err(BridgeError::InvalidPacket)
        );
        for n in 0..5 {
            assert!(runner.bridge.can_receive_acl(2, 27));
            runner
                .bridge
                .receive_acl(if n == 0 { 2 } else { 1 }, &[n; 27])
                .unwrap();
        }
        assert!(!runner.bridge.can_receive_acl(2, 1));
        assert_eq!(runner.bridge.receive_acl(2, &[9]), Err(BridgeError::Full));
        assert!(runner.bridge.can_receive_acl(1, 0));
        runner.bridge.receive_acl(1, &[]).unwrap();
        assert!(runner.pump_once());
        assert_eq!(
            &transport::try_receive_controller_packet()
                .unwrap()
                .payload()[..3],
            &[0x3e, 19, 1]
        );
        for n in 0..5 {
            assert!(runner.pump_once());
            let packet = transport::try_receive_controller_packet().unwrap();
            assert_eq!(packet.kind, PacketKind::AclData);
            assert_eq!(packet.bytes[1] >> 4, if n == 0 { 2 } else { 1 });
            assert_eq!(&packet.payload()[4..], &[n; 27]);
        }
        assert!(!runner.pump_once()); // No ACL/credits for empty or control.
    }

    #[test]
    fn transport_full_retains_lifecycle_acl_and_command_reply() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        for _ in 0..4 {
            transport::try_send_controller_packet(transport::command_complete_packet(
                0x1009,
                0,
                &[],
            ))
            .unwrap();
        }
        inject_cmd(0x2003, &[]);
        assert!(runner.pump_once());
        runner.bridge.connected(connection_info()).unwrap();
        runner.bridge.receive_acl(2, &[7]).unwrap();
        assert!(!runner.pump_once());
        for _ in 0..4 {
            transport::try_receive_controller_packet().unwrap();
        }
        assert!(runner.pump_once());
        expect_command_complete(0x2003, 0, &[0; 8]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet().unwrap().bytes[0],
            0x3e
        );
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet().unwrap().kind,
            PacketKind::AclData
        );
    }

    #[test]
    fn disconnect_status_precedes_completion_and_old_epoch_cannot_ack() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        runner.bridge.enqueue_tx(&acl(1, 0, &[1])).unwrap();
        let old = runner.bridge.take_tx_acl().unwrap().tag;
        inject_cmd(0x0406, &[2, 0, 0x13]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 2, 1, 6, 4]
        );
        assert!(runner.bridge.take_radio_request().is_none());
        inject_cmd(0x0406, &[1, 0, 0x13]);
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x0f, 4, 0, 1, 6, 4]
        );
        assert_eq!(
            runner.bridge.take_radio_request(),
            Some(super::super::connection::RadioRequest::Disconnect { reason: 0x13 })
        );
        assert!(!runner.pump_once()); // Completion waits for actual RF teardown.
        runner.bridge.disconnected(0x16);
        runner.bridge.connected(connection_info()).unwrap();
        assert!(!runner.bridge.ack_tx(old));
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[5, 4, 0, 1, 0, 0x16]
        );
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet().unwrap().bytes[0],
            0x3e
        );
        assert!(!runner.pump_once());
    }

    #[test]
    fn connected_reset_waits_for_rf_and_preserves_next_command() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        runner.bridge.enqueue_tx(&acl(1, 0, &[1])).unwrap();
        let old = runner.bridge.take_tx_acl().unwrap().tag;
        runner.bridge.receive_acl(2, &[9]).unwrap();
        // RX may be published first; Reset must remove it before reusing handle.
        assert!(runner.pump_once());
        inject_cmd(0x0c03, &[]);
        assert!(runner.pump_once());
        assert_eq!(
            runner.bridge.take_radio_request(),
            Some(super::super::connection::RadioRequest::Reset)
        );
        inject_cmd(0x1009, &[]);
        assert!(!runner.pump_once());
        runner.bridge.reset_finished();
        assert!(transport::try_receive_controller_packet().is_none());
        assert!(runner.pump_once());
        expect_command_complete(0x0c03, 0, &[]);
        assert!(runner.pump_once());
        expect_command_complete(0x1009, 0, &DEFAULT_BD_ADDR);
        assert!(!runner.bridge.ack_tx(old));
        assert!(!runner.bridge.is_connected());
        open(&mut runner);
        assert!(!runner.pump_once());
    }

    #[test]
    fn update_mask_and_lifecycle_slots_remain_bounded() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        runner.bridge.connection_updated(30, 1, 300).unwrap();
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet()
                .unwrap()
                .payload(),
            &[0x3e, 10, 3, 0, 1, 0, 30, 0, 1, 0, 44, 1]
        );
        inject_cmd(0x2001, &[0; 8]);
        assert!(runner.pump_once());
        expect_command_complete(0x2001, 0, &[]);
        runner.bridge.connection_updated(32, 0, 300).unwrap();
        assert!(!runner.pump_once());
        runner.bridge.set_masks(u64::MAX, 0x1f);
        for _ in 0..15 {
            runner.bridge.connection_updated(32, 0, 300).unwrap();
        }
        assert_eq!(
            runner.bridge.connection_updated(32, 0, 300),
            Err(BridgeError::Full)
        );
        runner.bridge.disconnected(0x08); // Reserved slot, even with fifteen updates.
        assert!(!runner.bridge.is_connected());
        assert_eq!(
            runner.bridge.connected(connection_info()),
            Err(BridgeError::Full)
        );
        for _ in 0..15 {
            assert!(runner.pump_once());
            assert_eq!(
                transport::try_receive_controller_packet().unwrap().bytes[0],
                0x3e
            );
        }
        assert!(runner.pump_once());
        assert_eq!(
            transport::try_receive_controller_packet().unwrap().bytes[0],
            5
        );
    }

    #[test]
    fn stale_full_input_cannot_cross_handle_reuse() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        open(&mut runner);
        for _ in 0..5 {
            runner.bridge.enqueue_tx(&acl(1, 0, &[1])).unwrap();
        }
        transport::try_send_host_packet(acl(1, 0, &[99])).unwrap();
        assert!(!runner.pump_once());
        runner.bridge.disconnected(0x13);
        runner.bridge.connected(connection_info()).unwrap();
        for _ in 0..2 {
            assert!(runner.pump_once());
            transport::try_receive_controller_packet().unwrap();
        }
        runner.pump_once();
        assert!(runner.bridge.take_tx_acl().is_none());
    }

    #[test]
    fn le_read_buffer_size() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            inject_cmd(0x2002, &[]);
            runner.serve_one().await;
            expect_command_complete(
                0x2002,
                HCI_SUCCESS,
                &[
                    ACL_DATA_PACKET_LENGTH as u8,
                    (ACL_DATA_PACKET_LENGTH >> 8) as u8,
                    ACL_CREDITS,
                ],
            );
        });
    }

    fn expect_command_status(opcode: u16, status: u8) {
        let packet = transport::try_receive_controller_packet().expect("missing CS");
        assert_eq!(packet.kind, PacketKind::Event);
        let payload = packet.payload();
        assert_eq!(payload[0], 0x0f);
        assert_eq!(payload[1], 4);
        assert_eq!(payload[2], status);
        assert_eq!(payload[3], 1);
        assert_eq!(u16::from_le_bytes([payload[4], payload[5]]), opcode);
    }

    fn scan_params() -> [u8; 7] {
        // Passive, 30 ms interval, 15 ms window, random own address, no filter.
        [0, 0x30, 0x00, 0x18, 0x00, 1, 0]
    }

    fn create_params(peer: [u8; 6]) -> [u8; 25] {
        let mut params = [0u8; 25];
        params[0..2].copy_from_slice(&0x0030u16.to_le_bytes());
        params[2..4].copy_from_slice(&0x0018u16.to_le_bytes());
        params[5] = 1;
        params[6..12].copy_from_slice(&peer);
        params[12] = 1;
        params[13..15].copy_from_slice(&24u16.to_le_bytes());
        params[15..17].copy_from_slice(&24u16.to_le_bytes());
        params[19..21].copy_from_slice(&200u16.to_le_bytes());
        params
    }

    #[test]
    fn scan_reports_exclude_adv_a_and_encode_rssi() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_random_addr([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x21]);

        pollster::block_on(async {
            inject_cmd(0x200b, &scan_params());
            runner.serve_one().await;
            expect_command_complete(0x200b, HCI_SUCCESS, &[]);

            inject_cmd(0x200c, &[1, 0]);
            runner.serve_one().await;
            expect_command_complete(0x200c, HCI_SUCCESS, &[]);
        });
        assert!(runner.scan_state().enabled);

        // ADV_IND with AdvA 06:05:04:03:02:01 and one local-name AD field.
        let mut dma = [0u8; 2 + 6 + 11];
        dma[0] = 0x00; // ADV_IND, public TxAdd
        dma[1] = 17;
        dma[2..8].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        dma[8] = 10;
        dma[9] = 0x09;
        dma[10..19].copy_from_slice(b"wch585-c1");
        let pdu = scan::Pdu::parse(&dma, true).unwrap();
        assert!(runner.push_adv_report(&pdu, -42));

        assert!(runner.pump_once());
        let packet = transport::try_receive_controller_packet().unwrap();
        let payload = packet.payload();
        assert_eq!(payload[0], 0x3e);
        assert_eq!(payload[2], 0x02);
        assert_eq!(payload[3], 1);
        assert_eq!(payload[4], 0x00); // ADV_IND
        assert_eq!(payload[5], 0); // public address
        assert_eq!(&payload[6..12], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(payload[12], 11); // AdvA removed
        assert_eq!(&payload[13..24], &dma[8..19]);
        assert_eq!(payload[24], (-42i8) as u8);
    }

    #[test]
    fn create_connection_status_and_cancel_failure_event() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        runner.set_random_addr([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x21]);
        let peer = [1, 2, 3, 4, 5, 6];

        pollster::block_on(async {
            inject_cmd(0x200d, &create_params(peer));
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_SUCCESS);
        });
        let request = runner.pending_connect().unwrap();
        assert_eq!(request.peer_addr, peer);
        assert!(request.peer_random && request.own_random);
        assert_eq!(runner.own_addr(), ([0xC1, 0xFF, 0xEE, 0x00, 0x00, 0x21], true));

        pollster::block_on(async {
            inject_cmd(0x200e, &[]);
            runner.serve_one().await;
            expect_command_complete(0x200e, HCI_SUCCESS, &[]);
        });
        assert!(runner.pending_connect().is_none());
        // `serve_one` already flushed the failure event after the command reply.
        let event = transport::try_receive_controller_packet().unwrap();
        let payload = event.payload();
        assert_eq!(payload[0], 0x3e);
        assert_eq!(payload[2], 0x01); // LE Connection Complete
        assert_eq!(payload[3], 0x02); // Unknown Connection Identifier
    }

    #[test]
    fn create_connection_rejects_invalid_parameters() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();

        pollster::block_on(async {
            let mut params = create_params([1, 2, 3, 4, 5, 6]);
            params[4] = 2; // filter policy
            inject_cmd(0x200d, &params);
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_INVALID_PARAMETERS);
            assert!(runner.pending_connect().is_none());

            let mut params = create_params([1, 2, 3, 4, 5, 6]);
            params[19] = 0x06; // 60 ms is not above 2 x interval
            inject_cmd(0x200d, &params);
            runner.serve_one().await;
            expect_command_status(0x200d, HCI_INVALID_PARAMETERS);
        });
    }

    #[test]
    fn connection_complete_reports_central_role_and_clock_accuracy() {
        let _guard = test_lock();
        transport::drain_channels_for_test();
        let mut runner = SoftRunner::new();
        let mut info = connection_info();
        info.role = crate::ll::Role::Central;
        info.master_clock_accuracy = 3;
        runner.bridge.connected(info).unwrap();
        assert!(runner.pump_once());
        let event = transport::try_receive_controller_packet().unwrap();
        let payload = event.payload();
        assert_eq!(payload[0], 0x3e);
        assert_eq!(payload[2], 0x01);
        assert_eq!(payload[6], 0); // Central (parameters[4])
        assert_eq!(payload[20], 3); // master clock accuracy (parameters[18])
    }
}
