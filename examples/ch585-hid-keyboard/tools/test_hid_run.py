#!/usr/bin/env python3
"""Offline tests for the HID acceptance runner; no hardware access."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hid = load('x4b_hid_run_test', HERE / 'hid_run.py')


def client_rows(gate=False, **overrides):
    events = ['start', 'bluetooth_state', 'scan_started', 'connecting', 'connected',
              'hold_complete', 'services_discovered', 'characteristics_discovered']
    summary = {'event': 'summary', 'exit_code': 0, 'hid_service_visible': False}
    if gate:
        events += ['notify_requested', 'security_gate', 'cancel_requested', 'disconnected']
        summary.update({'reason': 'hid_security_gate_ok', 'reports': 0,
                        'security_gate': True, 'gate_code': 5})
    else:
        events += ['notify_requested', 'notify_state', 'read_requested', 'read_result']
        events += ['notification'] * 8
        events += ['notify_state', 'cancel_requested', 'disconnected']
        summary.update({'reason': 'hid_mirror_ok', 'reports': 8, 'security_gate': False})
    rows = [{'event': name} for name in events]
    rows.append(dict(summary, **overrides))
    return rows


def hid_stats(**overrides):
    words = [0] * 16
    words[0] = hid.HID_MAGIC
    words[1] = 1
    values = {'reports_sent': 8, 'subscription_edges': 2, 'led_writes': 1,
              'led_value': 0x07, 'control_point_writes': 2, 'control_point_last': 1,
              'protocol_mode': 1, 'protocol_mode_writes': 2, 'boot_input_sent': 2,
              'report_map_reads': 1, 'hid_info_reads': 1, 'blocked_unencrypted': 3}
    for name, value in {**values, **overrides}.items():
        words[hid.HID_NAMES.index(name)] = value
    return words


def host_stats(**overrides):
    words = [0] * 16
    values = {'phase': 2, 'connections': 1, 'disconnects': 1, 'security': 3,
              'advertise_attempts': 2}
    for name, value in {**values, **overrides}.items():
        words[hid.HOST_NAMES.index(name)] = value
    return words


def secure_stats(**overrides):
    words = [0] * 16
    words[0] = hid.SEC_MAGIC
    words[1] = 1 | (1 << 8) | (1 << 9) | (1 << 10)
    values = {'enc_req': 1, 'enc_rsp': 1, 'ltk_request': 1, 'ltk_reply': 1,
              'start_req': 1, 'start_rsp': 1, 'encrypted_tx': 4, 'encrypted_rx': 4,
              'active': 1}
    for name, value in {**values, **overrides}.items():
        words[hid.SEC_NAMES.index(name)] = value
    return words


def run_stats(run_seconds=60):
    words = [0] * 64
    words[0] = 0x5034_3538
    words[1] = 1
    words[2] = 9
    words[14] = 1
    words[15] = 1
    words[32] = run_seconds * 1_000_000 + 21
    words[34] = 0x30000
    return words


def gated_secure_stats():
    """No bond: entropy/DRBG flags set, every encryption counter zero."""
    return secure_stats(enc_req=0, enc_rsp=0, ltk_request=0, ltk_reply=0,
                        start_req=0, start_rsp=0, encrypted_tx=0, encrypted_rx=0,
                        active=0)


def firmware_errors(mirror_mode=True, **overrides):
    host = overrides.get('host')
    if host is None:
        host = host_stats(**({} if mirror_mode else {'security': 1}))
    sec = overrides.get('sec')
    if sec is None:
        sec = secure_stats() if mirror_mode else gated_secure_stats()
    hid_words = overrides.get('hid')
    if hid_words is None:
        hid_words = hid_stats(**({} if mirror_mode else {
            'subscription_edges': 0, 'reports_sent': 0, 'boot_input_sent': 0}))
    return hid.evaluate_firmware(
        hid_words, host, sec, overrides.get('stats', run_stats()),
        overrides.get('run_seconds', 60), mirror_mode)


class ClientTests(unittest.TestCase):
    def test_mirror_transcript_passes(self):
        self.assertEqual(hid.evaluate_client(client_rows(), 0), [])

    def test_security_gate_transcript_passes(self):
        self.assertEqual(hid.evaluate_client(client_rows(gate=True), 0), [])
        # 0x0F is the firmware's EncryptionRequired answer; macOS surfaces it
        # directly when the reply arrives before its own ATT timeout.
        self.assertEqual(hid.evaluate_client(
            client_rows(gate=True, **{'gate_code': 15}), 0), [])

    def test_failures_are_reported(self):
        cases = [
            (client_rows(), 1),
            (client_rows()[:-1], 0),
            (client_rows(**{'reason': 'hid_reports_ok'}), 0),
            (client_rows(**{'reports': 7}), 0),
            (client_rows(**{'hid_service_visible': True}), 0),
            (client_rows(gate=True, **{'gate_code': 4}), 0),
            (client_rows(gate=True, reports=1), 0),
        ]
        for rows, code in cases:
            with self.subTest(code=code):
                self.assertTrue(hid.evaluate_client(rows, code))

    def test_event_counts_are_checked(self):
        rows = client_rows()
        rows = [row for row in rows if row.get('event') != 'read_result']
        self.assertTrue(any('mirror' in error for error in hid.evaluate_client(rows, 0)))
        rows = client_rows()
        rows = [row for row in rows if row.get('event') != 'notify_state']
        self.assertTrue(hid.evaluate_client(rows, 0))
        rows = client_rows(gate=True)
        rows = [row for row in rows if row.get('event') != 'security_gate']
        self.assertTrue(hid.evaluate_client(rows, 0))
        rows = client_rows()
        rows.insert(5, {'event': 'error', 'reason': 'x'})
        self.assertTrue(hid.evaluate_client(rows, 0))

    def test_malformed_lines_do_not_hide_a_summary(self):
        path = HERE / '.malformed-test.jsonl'
        try:
            path.write_text('not json\n{"event": "summary", "exit_code": 0, '
                            '"reason": "hid_discovery_ok", "reports": 0, "writes": 0}\n')
            rows = hid.client_rows(path)
            self.assertEqual(rows[0]['event'], 'malformed')
            self.assertEqual(len([r for r in rows if r.get('event') == 'summary']), 1)
        finally:
            path.unlink(missing_ok=True)


class FirmwareTests(unittest.TestCase):
    def test_clean_counters_pass(self):
        self.assertEqual(firmware_errors(), [])
        self.assertEqual(firmware_errors(mirror_mode=False), [])

    def test_mirror_gates(self):
        for name, value in (('notify_errors', 1), ('protocol_mode', 0),
                            ('subscription_edges', 0), ('last_error', 1)):
            with self.subTest(name=name):
                errors = firmware_errors(hid=hid_stats(**{name: value}))
                self.assertTrue(errors)

    def test_gate_mode_rejects_plaintext_and_absent_encryption(self):
        self.assertTrue(firmware_errors(mirror_mode=False,
                                        hid=hid_stats(subscription_edges=0, reports_sent=1,
                                                      boot_input_sent=0)))
        self.assertTrue(any('blocked_unencrypted' in error for error in
                            firmware_errors(mirror_mode=False,
                                            hid=hid_stats(subscription_edges=0, reports_sent=0,
                                                          boot_input_sent=0,
                                                          blocked_unencrypted=0))))
        self.assertTrue(firmware_errors(mirror_mode=False, sec=secure_stats()))
        self.assertTrue(firmware_errors(mirror_mode=False, host=host_stats(security=3)))

    def test_security_and_host_gates(self):
        self.assertTrue(firmware_errors(sec=secure_stats(encrypted_tx=1)))
        self.assertTrue(firmware_errors(sec=secure_stats(enc_req=0)))
        self.assertTrue(firmware_errors(sec=secure_stats(active=0)))
        self.assertTrue(firmware_errors(sec=secure_stats(errors=1)))
        self.assertTrue(firmware_errors(host=host_stats(security=2)))
        self.assertTrue(firmware_errors(host=host_stats(connections=0)))
        self.assertTrue(firmware_errors(host=host_stats(errors=1)))

    def test_stats_and_budget_gates(self):
        stats = run_stats()
        stats[2] = 8
        self.assertTrue(firmware_errors(stats=stats))
        stats = run_stats()
        stats[32] = 30 * 1_000_000
        self.assertTrue(any('finite-run' in error for error in firmware_errors(stats=stats)))
        stats = run_stats()
        stats[14] = 0
        self.assertTrue(firmware_errors(stats=stats))
        self.assertTrue(any('magic' in error for error in firmware_errors(hid=[0] * 16)))


class OptionTests(unittest.TestCase):
    def test_run_seconds_choices(self):
        self.assertEqual(hid.options(['--out', '/tmp/x', '--run-seconds', '60']).run_seconds, 60)
        self.assertEqual(hid.options(['--out', '/tmp/x', '--run-seconds', '360']).run_seconds, 360)
        with self.assertRaises(SystemExit):
            hid.options(['--out', '/tmp/x', '--run-seconds', '25'])

    def test_switches(self):
        parsed = hid.options(['--out', '/tmp/x', '--no-pair-click'])
        self.assertFalse(parsed.pair_click)
        parsed = hid.options(['--out', '/tmp/x', '--hold', '0'])
        self.assertEqual(parsed.hold, 0)

    def test_unique_stat_names(self):
        self.assertEqual(len(hid.HID_NAMES), 16)
        self.assertEqual(len(hid.HOST_NAMES), 16)
        self.assertEqual(len(set(hid.HID_NAMES)), 16)


if __name__ == '__main__':
    unittest.main()
