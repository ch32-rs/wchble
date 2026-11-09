//! Minimal, explicit responses for incidental Central traffic, not a GATT Host.

/// Handle one complete, unfragmented legacy L2CAP packet. An unsupported or
/// fragmented packet is an explicit error; the caller must terminate, not ACK
/// and silently discard it. A reply fits the default 27-byte LL payload.
pub fn reply(packet: &[u8], out: &mut [u8; 27]) -> Result<usize, ()> {
    if packet.len() < 5 {
        return Err(());
    }
    let length = usize::from(u16::from_le_bytes([packet[0], packet[1]]));
    if length + 4 != packet.len() || length > 23 {
        return Err(());
    }
    let cid = u16::from_le_bytes([packet[2], packet[3]]);
    match cid {
        0x0004 => {
            let att = &packet[4..];
            if att[0] == 0x02 && att.len() == 3 {
                out[..7].copy_from_slice(&[3, 0, 4, 0, 3, 23, 0]);
                Ok(7)
            } else if att[0] & 0x40 == 0 && att[0] & 1 == 0 && att[0] != 0 {
                // ATT request: explicit Request Not Supported. Do not reply to
                // commands, responses or notifications with an ATT error loop.
                let handle = if att.len() >= 3 {
                    [att[1], att[2]]
                } else {
                    [0, 0]
                };
                out[..9].copy_from_slice(&[5, 0, 4, 0, 1, att[0], handle[0], handle[1], 6]);
                Ok(9)
            } else {
                Err(())
            }
        }
        0x0005 if length >= 4 && packet[5] != 0 => {
            let command_len = usize::from(u16::from_le_bytes([packet[6], packet[7]]));
            if command_len + 4 != length || packet[4] == 1 {
                return Err(());
            }
            // LE signaling: Command Reject / command not understood.
            out[..10].copy_from_slice(&[6, 0, 5, 0, 1, packet[5], 2, 0, 0, 0]);
            Ok(10)
        }
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::reply;

    #[test]
    fn mtu_is_default_and_unsupported_requests_get_explicit_error() {
        let mut out = [0; 27];
        assert_eq!(reply(&[3, 0, 4, 0, 2, 0xf7, 0], &mut out), Ok(7));
        assert_eq!(&out[..7], &[3, 0, 4, 0, 3, 23, 0]);
        assert_eq!(
            reply(&[5, 0, 4, 0, 0x10, 1, 0, 0xff, 0xff], &mut out),
            Ok(9)
        );
        assert_eq!(&out[..9], &[5, 0, 4, 0, 1, 0x10, 1, 0, 6]);
    }

    #[test]
    fn truncation_fragments_and_response_loops_are_not_accepted() {
        let mut out = [0; 27];
        for packet in [
            &[][..],
            &[3, 0, 4, 0, 2],
            &[1, 0, 4, 0, 1],
            &[1, 0, 4, 0, 0x52],
        ] {
            assert!(reply(packet, &mut out).is_err());
        }
    }

    #[test]
    fn signaling_reject_is_bounded_and_preserves_identifier() {
        let mut out = [0; 27];
        assert_eq!(reply(&[4, 0, 5, 0, 0xff, 7, 0, 0], &mut out), Ok(10));
        assert_eq!(&out[..10], &[6, 0, 5, 0, 1, 7, 2, 0, 0, 0]);
    }
}
