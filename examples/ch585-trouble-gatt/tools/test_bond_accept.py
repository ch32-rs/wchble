#!/usr/bin/env python3
"""Offline bond-store acceptance tests; no serial, Bluetooth or probe access."""
import importlib.util
import struct
from pathlib import Path
import tempfile
import unittest
import zlib

_spec = importlib.util.spec_from_file_location('s3_bond_accept',
                                               Path(__file__).with_name('bond_accept.py'))
bond = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bond)
secure = bond.secure

LTK = bytes(range(16))
ADDRESS = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
LOCAL = bytes([1]) + ADDRESS


def record(ltk=LTK):
    return (ltk + ADDRESS + bytes([1, 0b11]) + bytes(16) + bytes([2, 0, 0])
            + bytes(8) + bytes([16]))


def payload(count=1, ltk=LTK):
    return LOCAL + bytes([count]) + record(ltk) * count


def page(seq, body, flags=0):
    header = struct.pack('<IHHIHHI', bond.STORE_MAGIC, bond.STORE_VERSION, flags, seq,
                         len(body), 0, zlib.crc32(body))
    header += struct.pack('<I', zlib.crc32(header))
    return header + body + b'\xff' * (bond.PAGE - len(header) - len(body))


def erased():
    return b'\xff' * bond.PAGE


def dumped(*pages):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'dump.bin'
        path.write_bytes(b''.join(pages))
        return bond.parse_dump(path)


def att_dumped(*pages):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'att.bin'
        path.write_bytes(b''.join(pages))
        return bond.parse_att_dump(path)


def att_payload(count=1):
    raw = b'\x00\x00\x00\x00'
    record = bytes([1]) + bytes.fromhex('a1b2c3d4e5f6') + bytes([len(raw)]) + raw
    return bytes([1]) + bytes(6) + bytes([count]) + record * count


def echo_for(ltk=LTK):
    return {'present': True, 'ltk': ltk.hex()}


def set_sec(named, **overrides):
    named['SECURE_STATS'] = dict(zip(secure.SEC_NAMES, secure_stats(**overrides)))


def bond_stats(**overrides):
    values = dict.fromkeys(secure.BOND_NAMES, 0)
    values.update({'magic': secure.BOND_MAGIC, 'version': 1})
    values.update(overrides)
    return values


def secure_stats(**overrides):
    sec = [0] * 16
    sec[0] = secure.SEC_MAGIC
    sec[1] = 1 | (1 << 8) | (1 << 9) | (1 << 10)
    for index in range(2, 8):
        sec[index] = 1
    sec[8] = sec[9] = 2
    sec[10] = 1
    for index, value in overrides.items():
        sec[secure.SEC_NAMES.index(index)] = value
    return sec


def host_stats(security=secure.SECURITY_ENCRYPTED):
    host = [0] * 16
    host[bond.HOST_SECURITY] = security
    return host


def stats_block(seconds=60):
    stats = [0] * 64
    stats[:3] = [0x5034_3538, 1, 9]
    stats[14] = stats[15] = 1
    stats[32] = seconds * 1_000_000
    stats[34] = 0x30000
    return stats


def catt_stats(**overrides):
    catt = dict.fromkeys(secure.CATT_NAMES, 0)
    catt['magic'] = bond.CATT_MAGIC
    catt['restore_attempts'] = 1
    catt.update(overrides)
    return catt


def observations(bonds=None, sec=None, host=None, seconds=60, catt=None):
    named = {
        'BOND_STATS': bond_stats(**(bonds or {})),
        'CATT_STATS': catt_stats(**(catt or {})),
        'SECURE_STATS': dict(zip(secure.SEC_NAMES, sec or secure_stats())),
        'HOST_STATS': dict(zip(secure.HOST_NAMES, host or host_stats())),
        'STATS': dict(zip(secure.STAT_NAMES, stats_block(seconds))),
    }
    raw = {
        'SECURE_STATS': sec or secure_stats(),
        'HOST_STATS': host or host_stats(),
        'STATS': stats_block(seconds),
    }
    return named, raw


def summary(reason='encrypted_read_write_ok', passed=True):
    return [{'event': 'summary', 'pass': passed, 'reason': reason}]


class DumpTests(unittest.TestCase):
    def test_valid_and_erased_slots(self):
        slots = dumped(page(1, payload()), erased())
        self.assertEqual(len(bond.valid_slots(slots)), 1)
        self.assertEqual([slot['slot'] for slot in slots], [0, 1])
        self.assertFalse(slots[1]['header_ok'])

    def test_tombstone_is_not_a_valid_bond(self):
        slots = dumped(page(2, b''), erased())
        self.assertTrue(slots[0]['tombstone'])
        self.assertEqual(bond.valid_slots(slots), [])

    def test_truncated_payload_fails_its_crc(self):
        # The page stays 256 bytes, so only the payload bytes are damaged.
        image = bytearray(page(3, payload()))
        image[24 + len(payload()) - 1] ^= 0x01
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'dump.bin'
            path.write_bytes(bytes(image))
            slots = bond.parse_dump(path)
        self.assertTrue(slots[0]['header_ok'])
        self.assertFalse(slots[0]['payload_ok'])
        self.assertEqual(bond.valid_slots(slots), [])

    def test_wrong_magic_or_version_is_not_a_header(self):
        image = bytearray(page(1, payload()))
        image[4] = 9
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'dump.bin'
            path.write_bytes(bytes(image))
            slots = bond.parse_dump(path)
        self.assertFalse(slots[0]['header_ok'])

    def test_dump_must_match_the_key_the_host_used(self):
        slots = dumped(page(1, payload()), erased())
        self.assertEqual(bond.dump_matches_echo(slots, echo_for()), [])
        self.assertTrue(bond.dump_matches_echo(slots, echo_for(bytes(16))))
        self.assertTrue(bond.dump_matches_echo(slots, {'present': False}))
        self.assertTrue(bond.dump_matches_echo([], echo_for()))

    def test_dump_checks_the_local_identity(self):
        slots = dumped(page(1, payload()), erased())
        echo = echo_for()
        echo.update({'local_present': True, 'local_address': 'aa:bb:cc:dd:ee:ff',
                     'local_address_kind': 1})
        self.assertEqual(bond.dump_matches_echo(slots, echo), [])
        echo['local_address'] = 'aa:bb:cc:dd:ee:00'
        self.assertTrue(any('local identity' in error
                            for error in bond.dump_matches_echo(slots, echo)))


class CheckTests(unittest.TestCase):
    def test_pair_accepts_one_saved_copy(self):
        named, raw = observations({'load_result': 0, 'pairs_complete': 1, 'save_ok': 1,
                                   'add_bond_ok': 1})
        slots = dumped(page(1, payload()), erased())
        att = att_dumped(erased(), erased())
        errors = bond.checks_pair(named, raw, echo_for(), summary(), slots, 60, att)
        self.assertEqual(errors, [])
        # This app did not subscribe, so `loaded` must reject the round.
        self.assertTrue(bond.checks_pair(named, raw, echo_for(), summary(), slots, 60,
                                         att, 'loaded'))

    def test_pair_accepts_a_saved_client_att_record(self):
        named, raw = observations({'load_result': 0, 'pairs_complete': 1, 'save_ok': 1,
                                   'add_bond_ok': 1},
                                  catt={'snapshots': 1, 'save_ok': 1})
        slots = dumped(page(1, payload()), erased())
        att = att_dumped(page(1, att_payload()), erased())
        self.assertEqual(bond.checks_pair(named, raw, echo_for(), summary(), slots, 60,
                                          att, 'loaded'), [])
        # A save counter without a record in flash must not pass.
        self.assertTrue(bond.checks_pair(named, raw, echo_for(), summary(), slots, 60,
                                         att_dumped(erased(), erased()), 'loaded'))
        named, raw = observations({'load_result': 0, 'pairs_complete': 1, 'save_ok': 1},
                                  catt={'save_fail': 1})
        self.assertTrue(bond.checks_pair(named, raw, echo_for(), summary(), slots, 60,
                                         att_dumped(erased(), erased())))

    def test_pair_rejects_a_stale_store_or_missing_save(self):
        slots = dumped(page(1, payload()), erased())
        att = att_dumped(erased(), erased())
        for bonds in ({'load_result': 1, 'pairs_complete': 1, 'save_ok': 1},
                      {'load_result': 0, 'pairs_complete': 1},
                      {'load_result': 0, 'pairs_complete': 1, 'save_ok': 1, 'save_fail': 1}):
            named, raw = observations(bonds)
            with self.subTest(bonds=bonds):
                self.assertTrue(bond.checks_pair(named, raw, echo_for(), summary(),
                                                 slots, 60, att))

    def test_pair_rejects_a_dump_with_another_key(self):
        named, raw = observations({'load_result': 0, 'pairs_complete': 1, 'save_ok': 1,
                                   'add_bond_ok': 1})
        slots = dumped(page(1, payload(ltk=bytes(16))), erased())
        att = att_dumped(erased(), erased())
        self.assertTrue(bond.checks_pair(named, raw, echo_for(), summary(), slots, 60, att))

    def test_reconnect_requires_the_stored_key_and_no_new_save(self):
        bonds = {'load_result': 1, 'records_loaded': 1, 'add_bond_ok': 1}
        catt = {'records_loaded': 1, 'restore_ok': 1}
        named, raw = observations(bonds, catt=catt)
        rows = summary('reconnect_encrypted_read_write_ok')
        att = att_dumped(page(1, att_payload()), erased())
        self.assertEqual(bond.checks_reconnect(named, raw, rows, 60, att), [])
        for bonds in ({'load_result': 0, 'records_loaded': 1, 'add_bond_ok': 1},
                      {'load_result': 1, 'records_loaded': 1, 'add_bond_ok': 1,
                       'pairs_complete': 1},
                      {'load_result': 1, 'records_loaded': 1, 'add_bond_ok': 1,
                       'save_attempts': 1},
                      {'load_result': 1, 'records_loaded': 1}):
            named, raw = observations(bonds, catt=catt)
            with self.subTest(bonds=bonds):
                self.assertTrue(bond.checks_reconnect(named, raw, rows, 60, att))

    def test_reconnect_requires_the_client_att_restore(self):
        rows = summary('reconnect_encrypted_read_write_ok')
        bonds = {'load_result': 1, 'records_loaded': 1, 'add_bond_ok': 1}
        att = att_dumped(page(1, att_payload()), erased())
        named, raw = observations(bonds, catt={'records_loaded': 1, 'restore_ok': 1})
        self.assertEqual(bond.checks_reconnect(named, raw, rows, 60, att), [])
        for catt in ({'restore_ok': 1, 'restore_no_record': 1},
                     {'records_loaded': 1, 'restore_ok': 1, 'save_fail': 1},
                     {'restore_invalid': 1},
                     {'restore_ok': 1},
                     {'restore_attempts': 0}):
            named, raw = observations(bonds, catt=catt)
            with self.subTest(catt=catt):
                self.assertTrue(bond.checks_reconnect(named, raw, rows, 60, att))
        # A stored record that the dump cannot see is not proof either.
        named, raw = observations(bonds, catt={'records_loaded': 1, 'restore_ok': 1})
        self.assertTrue(bond.checks_reconnect(
            named, raw, rows, 60, att_dumped(erased(), erased())))

    def test_expect_att_decides_whether_a_round_proves_persistence(self):
        rows = summary('reconnect_encrypted_read_write_ok')
        bonds = {'load_result': 1, 'records_loaded': 1, 'add_bond_ok': 1}
        empty_att = att_dumped(erased(), erased())
        empty_catt = {'restore_attempts': 1}
        named, raw = observations(bonds, catt=empty_catt)
        # Self-consistent but nothing persisted: only the default passes.
        self.assertEqual(bond.checks_reconnect(named, raw, rows, 60, empty_att), [])
        self.assertTrue(bond.checks_reconnect(named, raw, rows, 60, empty_att, 'loaded'))
        self.assertEqual(
            bond.checks_reconnect(named, raw, rows, 60, empty_att, 'empty'), [])

        full_att = att_dumped(page(1, att_payload()), erased())
        named, raw = observations(
            bonds, catt={'records_loaded': 1, 'restore_ok': 1})
        self.assertEqual(
            bond.checks_reconnect(named, raw, rows, 60, full_att, 'loaded'), [])
        self.assertTrue(
            bond.checks_reconnect(named, raw, rows, 60, full_att, 'empty'))

    def test_att_dump_decodes_the_stored_table(self):
        record = bytes([1]) + bytes.fromhex('a1b2c3d4e5f6') + bytes([4, 0, 0, 0, 0])
        payload = bytes([1]) + bytes(6) + bytes([1]) + record
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'att.bin'
            path.write_bytes(page(3, payload) + erased())
            slots = bond.parse_att_dump(path)
        self.assertEqual(len(bond.valid_slots(slots)), 1)
        self.assertEqual(slots[0]['count'], 1)
        self.assertEqual(slots[0]['records'][0]['raw'], '00000000')
        self.assertEqual(slots[0]['records'][0]['address'], 'a1b2c3d4e5f6')

    def test_reconnect_requires_an_ltk_request(self):
        named, raw = observations({'load_result': 1, 'records_loaded': 1,
                                   'add_bond_ok': 1},
                                  sec=secure_stats(ltk_request=0),
                                  catt={'records_loaded': 1, 'restore_ok': 1})
        att = att_dumped(page(1, att_payload()), erased())
        errors = bond.checks_reconnect(named, raw,
                                       summary('reconnect_encrypted_read_write_ok'),
                                       60, att)
        self.assertTrue(any('ltk' in error.lower() for error in errors))

    def test_delete_requires_a_tombstone_and_a_rejection(self):
        named, raw = observations({'clear_requests': 1, 'clear_ok': 1,
                                   'in_memory_removed': 1})
        slots = dumped(page(2, b''), erased())
        att = att_dumped(page(2, b''), erased())
        reject_named, _ = observations({'load_result': 0})
        set_sec(reject_named, ltk_request=1, start_req=0, last_error=6)
        errors = bond.checks_delete(named, raw, summary('bond_delete_ok'), slots,
                                    att, reject_named,
                                    summary('reconnect_encrypted_read_write_ok', False),
                                    60)
        self.assertEqual(errors, [])

    def test_delete_rejects_a_second_encryption_or_a_missing_tombstone(self):
        named, raw = observations({'clear_requests': 1, 'clear_ok': 1,
                                   'in_memory_removed': 1})
        att = att_dumped(page(2, b''), erased())
        reject_named, _ = observations()
        set_sec(reject_named, ltk_request=1, last_error=6)
        errors = bond.checks_delete(named, raw, summary('bond_delete_ok'),
                                    dumped(page(2, b''), erased()), att, reject_named,
                                    summary('reconnect_encrypted_read_write_ok', False),
                                    60)
        self.assertTrue(any('encryption started' in error for error in errors))
        errors = bond.checks_delete(named, raw, summary('bond_delete_ok'),
                                    dumped(page(2, b''), erased()), att, reject_named,
                                    summary('reconnect_encrypted_read_write_ok'), 60)
        self.assertTrue(any('unexpectedly passed' in error for error in errors))

    def test_delete_requires_the_client_att_clear(self):
        named, raw = observations({'clear_requests': 1, 'clear_ok': 1,
                                   'in_memory_removed': 1})
        reject_named, _ = observations()
        set_sec(reject_named, ltk_request=1, last_error=6)
        slots = dumped(page(2, b''), erased())
        # The ATT store still holds the deleted peer's subscription.
        att = att_dumped(page(1, att_payload()), erased())
        errors = bond.checks_delete(named, raw, summary('bond_delete_ok'), slots,
                                    att, reject_named,
                                    summary('reconnect_encrypted_read_write_ok', False),
                                    60)
        self.assertTrue(any('client ATT record survived' in error for error in errors))
        # A failed ATT flash operation must fail the phase even if the dump
        # looks clean.
        named, raw = observations({'clear_requests': 1, 'clear_ok': 1,
                                   'in_memory_removed': 1}, catt={'save_fail': 1})
        errors = bond.checks_delete(named, raw, summary('bond_delete_ok'), slots,
                                    att_dumped(page(2, b''), erased()), reject_named,
                                    summary('reconnect_encrypted_read_write_ok', False),
                                    60)
        self.assertTrue(any('client ATT flash' in error for error in errors))

    def test_wipe_requires_both_slots_empty(self):
        named, _ = observations({'clear_requests': 1, 'clear_ok': 1})
        att = att_dumped(erased(), erased())
        self.assertEqual(bond.checks_wipe(named, summary('bond_wipe_ok'),
                                          dumped(erased(), erased()), att), [])
        self.assertTrue(bond.checks_wipe(named, summary('bond_wipe_ok'),
                                         dumped(page(1, payload()), erased()), att))
        self.assertTrue(bond.checks_wipe(
            named, summary('bond_wipe_ok'), dumped(erased(), erased()),
            att_dumped(page(1, att_payload()), erased())))

    def test_fault_keeps_the_previous_copy(self):
        named, _ = observations({'fault_injected': 1})
        truncated = bytearray(page(2, payload()))
        truncated[24 + 20] ^= 0x01  # damage the payload, keep the header
        slots = dumped(page(1, payload()), bytes(truncated))
        reconnect_named, reconnect_raw = observations(
            {'load_result': 1, 'records_loaded': 1, 'add_bond_ok': 1},
            catt={'records_loaded': 1, 'restore_ok': 1})
        att = att_dumped(page(1, att_payload()), erased())
        errors = bond.checks_fault(
            named, summary('fault_injected_ok'), slots, reconnect_named, reconnect_raw,
            summary('reconnect_encrypted_read_write_ok'), 60, att)
        self.assertEqual(errors, [])
        self.assertTrue(bond.checks_fault(
            named, summary('fault_injected_ok'), dumped(erased(), erased()),
            reconnect_named, reconnect_raw,
            summary('reconnect_encrypted_read_write_ok'), 60, att))


class TranscriptTests(unittest.TestCase):
    def test_only_the_last_app_launch_is_kept(self):
        rows = [{'event': 'mode', 'mode': 'delete'}, {'event': 'summary', 'pass': True},
                {'event': 'mode', 'mode': 'reconnect'}, {'event': 'read'},
                {'event': 'summary', 'pass': False}]
        kept = bond.after_last_mode(rows)
        self.assertEqual([row.get('event') for row in kept], ['mode', 'read', 'summary'])
        self.assertEqual(bond.after_last_mode([]), [])


class ArgumentTests(unittest.TestCase):
    def test_defaults_match_the_secure_image(self):
        args = bond.options(['pair', '--out', '/tmp/s3-out'])
        self.assertEqual(args.run_seconds, 60)
        self.assertEqual(args.dataflash_addr, 0x77E00)
        self.assertEqual(args.dataflash_len, 512)

    def test_dataflash_length_must_cover_pages(self):
        for length in ('100', '256', '0'):
            with self.subTest(length=length), self.assertRaises(SystemExit):
                bond.options(['pair', '--out', '/tmp/s3-out',
                              '--dataflash-len', length])
        args = bond.options(['pair', '--out', '/tmp/s3-out', '--dataflash-len', '0x400'])
        self.assertEqual(args.dataflash_len, 1024)

    def test_every_phase_is_offered(self):
        for phase in bond.PHASES:
            args = bond.options([phase, '--out', '/tmp/s3-out'])
            self.assertEqual(args.phase, phase)
        with self.assertRaises(SystemExit):
            bond.options(['frobnicate', '--out', '/tmp/s3-out'])


if __name__ == '__main__':
    unittest.main()
