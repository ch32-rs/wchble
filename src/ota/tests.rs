use super::*;
use crate::storage::{crc32, crc32_finish, crc32_update, CRC32_INIT};

const HEADER_GOLDEN: [u8; 32] = [
    0x43, 0x48, 0x35, 0x58, 0x01, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0xf2, 0x3a, 0x0f, 0x8e,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x84, 0x42, 0x5b, 0x4b, 0x00, 0x00, 0x00, 0x00,
];

const META_GOLDEN: [u8; 32] = [
    0x4f, 0x54, 0x41, 0x4d, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xfb, 0xcc, 0x5f,
];

fn image() -> [u8; 64] {
    let mut image = [0u8; 64];
    for (i, byte) in image.iter_mut().enumerate().skip(32) {
        *byte = i as u8;
    }
    image
}

fn streamed_crc(image: &[u8; 64]) -> u32 {
    let header = ImageHeader::parse(image[..32].try_into().unwrap()).unwrap();
    let mut state = crc32_update(CRC32_INIT, &header.raw_zeroed());
    state = crc32_update(state, &image[32..]);
    crc32_finish(state)
}

#[test]
fn crc_vector_matches_ieee() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    let mut state = crc32_update(CRC32_INIT, b"1234");
    state = crc32_update(state, b"56789");
    assert_eq!(crc32_finish(state), 0xCBF4_3926);
}

#[test]
fn header_stamp_matches_golden() {
    let mut image = image();
    ImageHeader::stamp(&mut image, 2, FLAG_HOST_VERIFIED).unwrap();
    assert_eq!(image[..32], HEADER_GOLDEN);
    let header = ImageHeader::parse(&HEADER_GOLDEN).unwrap();
    assert_eq!(header.image_len, 64);
    assert_eq!(header.sequence, 2);
    assert_eq!(header.flags, FLAG_HOST_VERIFIED);
    assert_eq!(streamed_crc(&image), header.image_crc32);
}

#[test]
fn header_rejects_bad_fields() {
    let mut raw = HEADER_GOLDEN;
    raw[0] ^= 0xFF;
    assert_eq!(ImageHeader::parse(&raw), Err(HeaderError::BadMagic));

    let mut raw = HEADER_GOLDEN;
    raw[4] = 2;
    assert_eq!(ImageHeader::parse(&raw), Err(HeaderError::BadFormat));

    let mut raw = HEADER_GOLDEN;
    raw[8..12].copy_from_slice(&32u32.to_le_bytes());
    // The CRC no longer matches either; length is checked first.
    assert_eq!(ImageHeader::parse(&raw), Err(HeaderError::BadLength));

    let mut raw = HEADER_GOLDEN;
    raw[16..20].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(ImageHeader::parse(&raw), Err(HeaderError::BadSequence));

    let mut raw = HEADER_GOLDEN;
    raw[25] ^= 0x01;
    assert_eq!(ImageHeader::parse(&raw), Err(HeaderError::BadHeaderCrc));
}

#[test]
fn header_rejects_a_nonzero_reserved_tail() {
    let mut raw = HEADER_GOLDEN;
    raw[30] = 1;
    assert_eq!(ImageHeader::parse(&raw), Err(HeaderError::BadFormat));
}

#[test]
fn header_crc_ignores_the_crc_fields() {
    // Re-stamping the same image must produce identical bytes twice.
    let mut image = image();
    ImageHeader::stamp(&mut image, 2, FLAG_HOST_VERIFIED).unwrap();
    let first = image;
    ImageHeader::stamp(&mut image, 2, FLAG_HOST_VERIFIED).unwrap();
    assert_eq!(image, first);
}

#[test]
fn image_crc_detects_body_damage() {
    let mut image = image();
    ImageHeader::stamp(&mut image, 2, FLAG_HOST_VERIFIED).unwrap();
    let header = ImageHeader::parse(&image[..32].try_into().unwrap()).unwrap();
    assert_eq!(streamed_crc(&image), header.image_crc32);

    image[40] ^= 0x01;
    assert_eq!(
        header.stream_check(streamed_crc(&image)),
        Err(HeaderError::BadImageCrc)
    );
}

#[test]
fn metadata_matches_golden() {
    let meta = Metadata {
        candidate_slot: SLOT_B,
        attempts_done: 1,
        flags: 0,
        active_slot: SLOT_A,
        candidate_seq: 3,
        good_seq: 2,
        failed_seq_a: 0,
        failed_seq_b: 0,
    };
    assert_eq!(meta.encode(), META_GOLDEN);
    assert_eq!(Metadata::decode(&META_GOLDEN), Some(meta));
}

#[test]
fn metadata_rejects_corruption() {
    let mut raw = META_GOLDEN;
    raw[0] ^= 0xFF;
    assert_eq!(Metadata::decode(&raw), None);

    let mut raw = META_GOLDEN;
    raw[4] = 2;
    assert_eq!(Metadata::decode(&raw), None);

    let mut raw = META_GOLDEN;
    raw[30] ^= 0x01;
    assert_eq!(Metadata::decode(&raw), None);
}

#[test]
fn metadata_rejects_impossible_fields() {
    for (offset, value) in [(6, 2u8), (9, 7), (7, MAX_ATTEMPTS + 1)] {
        let mut raw = META_GOLDEN;
        raw[offset] = value;
        let crc = crc32(&raw[..28]);
        raw[28..32].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(Metadata::decode(&raw), None, "offset {offset}");
    }
}

fn good(a_seq: u32) -> Option<Metadata> {
    Some(on_good(None, SLOT_A, a_seq))
}

#[test]
fn on_good_clears_markers() {
    let mut meta = Metadata::default();
    meta.candidate_slot = SLOT_B;
    meta.attempts_done = 1;
    meta.flags = META_FLAG_ROLLBACK;
    meta.failed_seq_b = 9;
    let meta = on_good(Some(meta), SLOT_B, 4);
    assert_eq!(meta.active_slot, SLOT_B);
    assert_eq!(meta.good_seq, 4);
    assert_eq!(meta.attempts_done, 0);
    assert_eq!(meta.failed_seq_b, 0);
    assert_eq!(meta.flags, 0);
    assert!(meta.is_good(SLOT_B, 4));
}

#[test]
fn select_boots_the_only_valid_slot() {
    let decision = select(None, [true, false], [2, 0]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_A,
            sequence: 2,
            attempts_done: 1,
            rollback: false
        }
    );
    assert_eq!(decision.persist.unwrap().candidate_slot, SLOT_A);
}

#[test]
fn select_prefers_the_higher_sequence() {
    let decision = select(good(2), [true, true], [2, 3]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_B,
            sequence: 3,
            attempts_done: 1,
            rollback: false
        }
    );
}

#[test]
fn select_resumes_the_candidate_until_attempts_run_out() {
    let meta = Metadata {
        candidate_slot: SLOT_B,
        attempts_done: 1,
        candidate_seq: 3,
        ..Metadata::default()
    };
    let decision = select(Some(meta), [true, true], [2, 3]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_B,
            sequence: 3,
            attempts_done: 2,
            rollback: false
        }
    );
    assert_eq!(decision.persist.unwrap().attempts_done, 2);
}

#[test]
fn exhausted_candidate_rolls_back_with_a_failed_marker() {
    let meta = Metadata {
        candidate_slot: SLOT_B,
        attempts_done: MAX_ATTEMPTS,
        candidate_seq: 3,
        active_slot: SLOT_A,
        good_seq: 2,
        ..Metadata::default()
    };
    let decision = select(Some(meta), [true, true], [2, 3]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_A,
            sequence: 2,
            attempts_done: 0,
            rollback: true
        }
    );
    let persisted = decision.persist.unwrap();
    assert_eq!(persisted.failed_seq_b, 3);
    assert_eq!(persisted.flags, META_FLAG_ROLLBACK);
    assert_eq!(persisted.active_slot, SLOT_A);
}

#[test]
fn same_sequence_does_not_revive_a_failed_slot() {
    let mut meta = Metadata::default();
    meta.failed_seq_b = 3;
    let decision = select(Some(meta), [true, true], [2, 3]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_A,
            sequence: 2,
            attempts_done: 1,
            rollback: false
        }
    );

    // A new build with a new sequence is eligible again.
    let decision = select(Some(meta), [true, true], [2, 4]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_B,
            sequence: 4,
            attempts_done: 1,
            rollback: false
        }
    );
}

#[test]
fn select_tie_prefers_the_good_slot_then_a() {
    // Same sequence on both slots: the good one wins.
    let mut meta = Metadata::default();
    meta.active_slot = SLOT_B;
    meta.good_seq = 2;
    let decision = select(Some(meta), [true, true], [2, 2]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_B,
            sequence: 2,
            attempts_done: 0,
            rollback: false
        }
    );

    // Neither good: A wins.
    let decision = select(None, [true, true], [2, 2]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_A,
            sequence: 2,
            attempts_done: 1,
            rollback: false
        }
    );
}

#[test]
fn select_parks_when_nothing_is_usable() {
    assert_eq!(
        select(None, [false, false], [0, 0]).action,
        BootAction::Park(ParkReason::NoValidSlot)
    );

    let mut meta = Metadata::default();
    meta.failed_seq_a = 2;
    meta.failed_seq_b = 3;
    assert_eq!(
        select(Some(meta), [true, true], [2, 3]).action,
        BootAction::Park(ParkReason::AllFailed)
    );
}

#[test]
fn select_does_not_persist_an_unchanged_good_boot() {
    let meta = on_good(None, SLOT_A, 2);
    let decision = select(Some(meta), [true, false], [2, 0]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_A,
            sequence: 2,
            attempts_done: 0,
            rollback: false
        }
    );
    assert_eq!(decision.persist, None);
}

#[test]
fn recovery_prefers_the_factory_slot_over_the_newest() {
    let decision = select_recovery([true, true], [2, 9]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_A,
            sequence: 2,
            attempts_done: 1,
            rollback: false
        }
    );
    let meta = decision.persist.unwrap();
    assert_eq!(meta.candidate_slot, SLOT_A);
    assert_eq!(meta.candidate_seq, 2);
    assert_eq!(meta.attempts_done, 1);
    assert_eq!((meta.failed_seq_a, meta.failed_seq_b), (0, 0));
}

#[test]
fn recovery_uses_b_when_a_is_invalid() {
    let decision = select_recovery([false, true], [0, 9]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_B,
            sequence: 9,
            attempts_done: 1,
            rollback: false
        }
    );
}

#[test]
fn recovery_parks_when_no_slot_is_valid() {
    let decision = select_recovery([false, false], [0, 0]);
    assert_eq!(decision.action, BootAction::Park(ParkReason::NoValidSlot));
    assert_eq!(decision.persist, None);
}

#[test]
fn sequence_comparison_survives_wrap() {
    // B just re-stamped over the wrap: it is newer than A near the top.
    let decision = select(None, [true, true], [0xFFFF_FFF0, 5]);
    assert_eq!(
        decision.action,
        BootAction::Boot {
            slot: SLOT_B,
            sequence: 5,
            attempts_done: 1,
            rollback: false
        }
    );
}
