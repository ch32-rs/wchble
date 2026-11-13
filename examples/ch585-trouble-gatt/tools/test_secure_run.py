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


if __name__ == '__main__':
    unittest.main()
