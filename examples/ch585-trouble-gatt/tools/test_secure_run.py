#!/usr/bin/env python3
"""Offline tests for the secure runner's rejection gates; no hardware access."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


secure = load('s3_secure_run_test', HERE / 'secure_run.py')
capture = load('s3_secure_capture_test', HERE / 'secure_capture.py')


def sec(**values):
    words = [0] * 16
    words[0] = secure.SEC_MAGIC
    for index in range(2, 8):
        words[index] = 1
    for name, value in values.items():
        words[secure.SEC_NAMES.index(name)] = value
    return words


def x1(**values):
    words = [0] * 24
    words[0] = secure.X1_MAGIC
    words[1] = 1
    words[2], words[4], words[5] = 2, 1, 1
    words[10] = words[11] = 251
    words[12] = words[13] = 2120
    words[14] = words[15] = 251
    for name, value in values.items():
        words[secure.X1_NAMES.index(name)] = value
    return words


class X1Tests(unittest.TestCase):
    def test_csa2_and_dle_stats_pass(self):
        words = x1(feature_exchange=1, tx_over_27=4, rx_over_27=6,
                   host_packets_segmented=2)
        self.assertEqual(secure.evaluate_x1(words), [])
        self.assertEqual(secure.evaluate_x1(words, require_dle=True), [])

    def test_selection_bits_must_agree_with_the_algorithm(self):
        errors = secure.evaluate_x1(x1(adv_chsel=0))
        self.assertTrue(any('CSA#2 selected' in error for error in errors))
        errors = secure.evaluate_x1(x1(algorithm=1))
        self.assertTrue(any('CSA#1 selected' in error for error in errors))

    def test_limits_must_stay_inside_the_spec_window(self):
        errors = secure.evaluate_x1(x1(tx_octets=20))
        self.assertTrue(any('tx_octets=20' in error for error in errors))
        errors = secure.evaluate_x1(x1(max_rx_pdu=252))
        self.assertTrue(any('251 octets' in error for error in errors))
        errors = secure.evaluate_x1(x1(rx_time=300))
        self.assertTrue(any('rx_time=300' in error for error in errors))

    def test_require_dle_demands_observed_widening(self):
        errors = secure.evaluate_x1(x1(), require_dle=True)
        self.assertTrue(any('feature set' in error for error in errors))
        self.assertTrue(any('transmitted PDU' in error for error in errors))
        self.assertTrue(any('received PDU' in error for error in errors))
        self.assertTrue(any('Host ACL packet' in error for error in errors))

    def test_bad_magic_is_rejected(self):
        self.assertTrue(secure.evaluate_x1([0] * 24))
        self.assertTrue(secure.evaluate_x1([0] * 16))


class RejectionTests(unittest.TestCase):
    def test_app_side_rejection(self):
        rows = [{'event': 'summary', 'pass': False, 'reason': 'read_failed'}]
        self.assertEqual(secure.evaluate_rejection(rows), [])
        for bad in ([], rows * 2,
                    [{'event': 'summary', 'pass': True, 'reason': 'read_failed'}],
                    [{'event': 'summary', 'pass': False, 'reason': 'timeout'}]):
            with self.subTest(rows=bad):
                self.assertTrue(secure.evaluate_rejection(bad))

    def test_firmware_side_rejection(self):
        host = [0] * 16
        host[15] = 1
        errors = secure.evaluate_rejected_link(
            sec(ltk_request=1, start_req=0, last_error=6, active=0), host)
        self.assertEqual(errors, [])
        for words, expected in ((sec(ltk_request=0, last_error=6), 'LTK'),
                                (sec(ltk_request=1, start_req=1, last_error=6), 'started'),
                                (sec(ltk_request=1, last_error=5), '0x06'),
                                (sec(ltk_request=1, last_error=6, active=1), 'active')):
            with self.subTest(words=words):
                errors = secure.evaluate_rejected_link(words, host)
                self.assertTrue(any(expected in error for error in errors))

    def test_capture_reject_mode_requires_the_ll_rejection(self):
        assessed = {'target': capture.TARGET, 'access_address': '0x50654000',
                    'll_control': [{'name': 'ENC_REQ'}, {'name': 'REJECT_IND'}],
                    'smp': [], 'smp_opcodes_captured': [],
                    'encryption_start': {'frame': 2}, 'att_after_encryption_start': []}
        self.assertEqual(capture.evaluate(assessed, 'reject'), [])
        assessed['ll_control'] = [{'name': 'ENC_REQ'}]
        self.assertTrue(capture.evaluate(assessed, 'reject'))
        assessed['ll_control'] = [{'name': 'REJECT_IND'}, {'name': 'START_ENC_REQ'}]
        self.assertTrue(capture.evaluate(assessed, 'reject'))

    def test_reject_mode_drives_the_reconnect_app_flow(self):
        capture_options, args = capture.options([
            '--sniffer', '/tmp/sniffer', '--sniffer-port', '/dev/test',
            '--nrfutil-home', '/tmp/state', '--mode', 'reject',
            '--out', '/tmp/evidence', '--run-seconds', '60', '--timeout', '45'])
        self.assertEqual(capture_options.mode, 'reject')
        self.assertEqual(args.mode, 'reconnect')
        self.assertTrue(args.reject)


def privacy(**values):
    words = [0] * 24
    words[0] = secure.PRIVACY_MAGIC
    words[1] = 1
    words[2] = secure.P_ADV_USES_RPA | secure.P_LOCAL_IRK | secure.P_STAMP_VALID
    words[3], words[4] = 10, 9
    words[5], words[6] = 2, 2
    words[10], words[11] = 3, 132
    words[13] = int.from_bytes(bytes([0x11, 0x22, 0x33, 0x44]), 'little')
    words[14] = int.from_bytes(bytes([0x55, 0x66, 0, 0]), 'little')
    words[16] = 0x00B7_7A90
    words[17], words[18], words[19] = 1, 1, 0
    words[20], words[21], words[22] = 6, 2, 5
    words[23] = 0
    for name, value in values.items():
        words[secure.PRIVACY_NAMES.index(name)] = value
    return words


class PrivacyTests(unittest.TestCase):
    def test_valid_privacy_run_passes(self):
        stats = secure.decode_privacy(privacy())
        self.assertEqual(secure.evaluate_privacy(
            stats, pairs_complete=stats['stage_pairs_complete']), [])

    def test_attempts_without_a_controller_resolution_fail(self):
        # The Host resolves on its own, so attempts alone prove nothing.
        stats = secure.decode_privacy(
            privacy(resolve_ok=1, stage_resolve_ok=1, reconnect_resolve_ok=1))
        errors = secure.evaluate_privacy(stats, pairs_complete=0)
        self.assertTrue(any('never resolved' in error for error in errors))

    def test_rotations_after_the_reconnect_do_not_count(self):
        # Final totals keep rotating while the app holds the second link.
        stats = secure.decode_privacy(privacy(rotations=12, reconnect_rotations=1))
        errors = secure.evaluate_privacy(stats, pairs_complete=0)
        self.assertTrue(any('fewer than two RPA rotations' in error for error in errors))

    def test_a_second_pairing_after_the_disconnect_fails(self):
        stats = secure.decode_privacy(privacy(stage_pairs_complete=1))
        errors = secure.evaluate_privacy(stats, pairs_complete=2)
        self.assertTrue(any('paired again' in error for error in errors))

    def test_missing_pairing_counter_fails(self):
        stats = secure.decode_privacy(privacy())
        errors = secure.evaluate_privacy(stats)
        self.assertTrue(any('pairs_complete missing' in error for error in errors))

    def test_capture_counts_plaintext_per_link(self):
        att = [{'frame': 30, 'aa': '0x1'}, {'frame': 110, 'aa': '0x2'}]
        control = [{'frame': 20, 'aa': '0x1', 'name': 'START_ENC_REQ'},
                   {'frame': 120, 'aa': '0x2', 'name': 'START_ENC_REQ'}]
        after, start = capture.att_after_encryption(att, control)
        self.assertEqual(start['aa'], '0x1')
        self.assertEqual([entry['frame'] for entry in after], [30])

    def test_missing_reconnect_snapshot_fails(self):
        stats = secure.decode_privacy(privacy(reconnect_generations=0))
        errors = secure.evaluate_privacy(stats, pairs_complete=0)
        self.assertTrue(any('reconnect was never reported' in error for error in errors))

    def test_capture_privacy_allows_the_first_pairing_only(self):
        assessed = {'target': capture.TARGET, 'access_address': '0x1',
                    'connect_addresses': ['aa:00:00:00:00:01', 'bb:00:00:00:00:02'],
                    'rotate_phase': [{'frame': 10, 'address': 'aa:00:00:00:00:01'},
                                     {'frame': 100, 'address': 'bb:00:00:00:00:02'}],
                    'smp': [{'frame': 20, 'name': 'PairingRequest'},
                            {'frame': 30, 'name': 'PairingDHKeyCheck'}],
                    'smp_opcodes_captured': ['PairingRequest', 'PairingDHKeyCheck'],
                    'll_control': [], 'encryption_start': {'frame': 40},
                    'att_after_encryption_start': []}
        self.assertEqual(capture.evaluate(assessed, 'privacy'), [])
        assessed['smp'].append({'frame': 150, 'name': 'PairingRequest'})
        self.assertTrue(capture.evaluate(assessed, 'privacy'))

    def test_capture_privacy_with_one_link_does_not_claim_a_repair(self):
        # Without the second CONNECT_IND the pairing frames cannot be placed;
        # the firmware counters, not the capture, decide that stage.
        assessed = {'target': capture.TARGET, 'access_address': '0x1',
                    'connect_addresses': ['aa:00:00:00:00:01'],
                    'rotate_phase': [{'frame': 10, 'address': 'aa:00:00:00:00:01'}],
                    'smp': [{'frame': 20, 'name': 'PairingRequest'},
                            {'frame': 30, 'name': 'PairingDHKeyCheck'}],
                    'smp_opcodes_captured': ['PairingRequest', 'PairingDHKeyCheck'],
                    'll_control': [], 'encryption_start': {'frame': 40},
                    'att_after_encryption_start': []}
        self.assertEqual(capture.evaluate(assessed, 'privacy'), [])


if __name__ == '__main__':
    unittest.main()
