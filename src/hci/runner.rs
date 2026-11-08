//! Soft HCI command pump (Phase A).
//!
//! Owns LL scaffold state and answers Host commands arriving on
//! [`super::transport`]. Radio TX/RX stays out of this module until Phase B
//! (legacy adv on air).

use bt_hci::transport::PacketKind;

use crate::ll::LinkLayer;

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
const ACL_DATA_PACKET_LENGTH: u16 = 27;
/// Number of ACL credits advertised to the Host.
const ACL_CREDITS: u8 = 5;

/// Default public BD_ADDR placeholder (HAL / OTP can override later).
const DEFAULT_BD_ADDR: [u8; 6] = [0x00, 0x00, 0x00, 0xc1, 0xff, 0xee];

/// Drains Host→Controller packets and emits Command Complete / Status.
#[derive(Debug)]
pub struct SoftRunner {
    pub ll: LinkLayer,
    event_mask: u64,
    le_event_mask: u64,
    bd_addr: [u8; 6],
    random_addr: [u8; 6],
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
            event_mask: u64::MAX,
            le_event_mask: 0x1f,
            bd_addr: DEFAULT_BD_ADDR,
            random_addr: [0; 6],
        }
    }

    /// Override the public address returned by `Read BD_ADDR`.
    pub fn set_bd_addr(&mut self, addr: [u8; 6]) {
        self.bd_addr = addr;
    }

    /// Process one pending Host packet if present. Returns `true` if work ran.
    pub async fn poll_once(&mut self) -> bool {
        let Some(packet) = transport::try_receive_host_packet() else {
            return false;
        };
        self.dispatch(packet).await;
        true
    }

    /// Block until a Host packet arrives, then handle it.
    pub async fn serve_one(&mut self) {
        let packet = transport::receive_host_packet().await;
        self.dispatch(packet).await;
    }

    /// Forever pump — HAL apps `join` this with Trouble's runner.
    pub async fn run(&mut self) -> ! {
        loop {
            self.serve_one().await;
        }
    }

    async fn dispatch(&mut self, packet: Packet) {
        match packet.kind {
            PacketKind::Cmd => self.handle_command(packet.payload()).await,
            PacketKind::AclData => {
                // Phase A: no connections yet.
                let _ = packet;
            }
            _ => {}
        }
    }

    async fn handle_command(&mut self, bytes: &[u8]) {
        if bytes.len() < 3 || bytes.len() != 3 + usize::from(bytes[2]) {
            return;
        }
        let opcode = u16::from_le_bytes([bytes[0], bytes[1]]);
        let params = &bytes[3..];

        // Async commands answer with Command Status, not Complete.
        match opcode {
            // Disconnect / LE Create Connection / LE Connection Update
            0x0406 | 0x200d | 0x2013 => {
                transport::command_status(opcode, HCI_COMMAND_DISALLOWED).await;
                return;
            }
            _ => {}
        }

        // Copy BD_ADDR before any await that needs &mut self across the reply.
        let bd_addr = self.bd_addr;

        let result: Result<&[u8], u8> = match opcode {
            // Reset
            0x0c03 if params.is_empty() => {
                self.event_mask = u64::MAX;
                self.le_event_mask = 0x1f;
                self.ll = LinkLayer::new();
                self.random_addr = [0; 6];
                Ok(&[][..])
            }
            // Set Event Mask / LE Set Event Mask
            0x0c01 | 0x2001 if params.len() == 8 => {
                let mask = u64::from_le_bytes(params.try_into().unwrap());
                if opcode == 0x0c01 {
                    self.event_mask = mask;
                } else {
                    self.le_event_mask = mask;
                }
                let _ = (self.event_mask, self.le_event_mask);
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
            // LE Read Local Supported Features — peripheral + conn (no encryption).
            0x2003 if params.is_empty() => {
                static FEATURES: [u8; 8] = [0x06, 0, 0, 0, 0, 0, 0, 0];
                Ok(&FEATURES)
            }
            // LE Set Random Address
            0x2005 if params.len() == 6 => {
                if self.ll.adv.enabled {
                    Err(HCI_COMMAND_DISALLOWED)
                } else {
                    self.random_addr.copy_from_slice(params);
                    Ok(&[][..])
                }
            }
            // LE Set Advertising Parameters (store interval / channel map only).
            0x2006 if params.len() == 15 => self.set_adv_params(params),
            // LE Set Advertising Data / Scan Response Data
            0x2008 | 0x2009 if params.len() == 32 => Ok(&[][..]),
            // LE Set Advertise Enable
            0x200a if params.len() == 1 && params[0] <= 1 => {
                self.ll.adv.enabled = params[0] != 0;
                Ok(&[][..])
            }
            // LE Set Scan Enable — central not Phase A.
            0x200c if params.len() == 2 => Err(HCI_COMMAND_DISALLOWED),
            // LE Create Connection Cancel
            0x200e if params.is_empty() => Err(HCI_COMMAND_DISALLOWED),
            // Filter Accept List size / clear / add — report empty list.
            0x200f if params.is_empty() => Ok(&[0][..]),
            0x2010 if params.is_empty() => Ok(&[][..]),
            0x2011 => Err(HCI_COMMAND_DISALLOWED),
            // LE Rand
            0x2018 if params.is_empty() => {
                // Deterministic placeholder; HAL should seed real entropy later.
                transport::command_complete(
                    opcode,
                    HCI_SUCCESS,
                    &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                )
                .await;
                return;
            }
            // LE Set Ext Advertising / Scan Enable — legacy-only controller.
            0x2039 | 0x2042 => Err(HCI_COMMAND_DISALLOWED),
            _ => Err(HCI_UNKNOWN_COMMAND),
        };

        match result {
            Ok(return_data) => transport::command_complete(opcode, HCI_SUCCESS, return_data).await,
            Err(status) => transport::command_complete(opcode, status, &[]).await,
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use bt_hci::transport::PacketKind;

    fn inject_cmd(opcode: u16, params: &[u8]) {
        let mut bytes = [0u8; transport::HCI_PACKET_CAPACITY];
        bytes[0..2].copy_from_slice(&opcode.to_le_bytes());
        bytes[2] = params.len() as u8;
        bytes[3..3 + params.len()].copy_from_slice(params);
        let packet =
            Packet::from_bytes(PacketKind::Cmd, &bytes[..3 + params.len()]).unwrap();
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
    fn reset_and_read_bd_addr_roundtrip() {
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
    fn le_read_buffer_size() {
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
}
