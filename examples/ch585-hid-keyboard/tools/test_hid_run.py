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


def client_rows(discover_only=False, **overrides):
    events = ['start', 'bluetooth_state', 'scan_started', 'connecting', 'connected',
              'hold_complete', 'services_discovered', 'characteristics_discovered',
              'descriptor_read', 'descriptor_read', 'read_result', 'read_result',
              'read_result']
    summary = {'event': 'summary', 'exit_code': 0,
               'reason': 'hid_discovery_ok' if discover_only else 'hid_reports_ok',
               'reports': 0 if discover_only else 8,
               'boot_reports': 0 if discover_only else 2,
               'writes': 0 if discover_only else 1,
               'notifications': 0 if discover_only else 10}
    if not discover_only:
        events += ['notify_state', 'notification'] + ['notification'] * 7
        events += ['write_ack', 'write_sent', 'write_sent', 'write_sent',
                   'notify_state', 'boot_notification', 'boot_notification']
    events += ['cancel_requested', 'disconnected']
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


def firmware_errors(discover_only=False, **overrides):
    return hid.evaluate_firmware(
        overrides.get('hid', hid_stats()), overrides.get('host', host_stats()),
        overrides.get('sec', secure_stats()), overrides.get('stats', run_stats()),
        overrides.get('run_seconds', 60), discover_only)


class ClientTests(unittest.TestCase):
    def test_full_transcript_passes(self):
        rows = client_rows()
        self.assertEqual(hid.evaluate_client(rows, 0), [])

    def test_discovery_transcript_passes(self):
        rows = client_rows(discover_only=True)
        self.assertEqual(hid.evaluate_client(rows, 0, True), [])

    def test_failures_are_reported(self):
        cases = [
            (client_rows(), 1, False),
            (client_rows()[:-1], 0, False),
            (client_rows(**{'reason': 'hid_discovery_ok'}), 0, False),
            (client_rows(**{'reports': 7}), 0, False),
            (client_rows(**{'boot_reports': 1}), 0, False),
            (client_rows(**{'writes': 0}), 0, False),
            (client_rows(discover_only=True, reports=1), 0, True),
        ]
        for rows, code, discover in cases:
            with self.subTest(code=code, discover=discover):
                self.assertTrue(hid.evaluate_client(rows, code, discover))

    def test_event_counts_are_checked(self):
        rows = client_rows()
        rows = [row for row in rows if row.get('event') != 'descriptor_read']
        self.assertTrue(any('Report Reference' in error
                            for error in hid.evaluate_client(rows, 0)))
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
        self.assertEqual(firmware_errors(discover_only=True), [])

    def test_report_gates(self):
        for name, value in (('reports_sent', 7), ('boot_input_sent', 1),
                            ('notify_errors', 1), ('led_value', 0),
                            ('control_point_last', 0), ('protocol_mode', 0),
                            ('report_map_reads', 0), ('hid_info_reads', 0),
                            ('last_error', 1)):
            with self.subTest(name=name):
                errors = firmware_errors(hid=hid_stats(**{name: value}))
                self.assertTrue(errors)

    def test_discovery_gates_do_not_require_reports(self):
        errors = firmware_errors(discover_only=True,
                                 hid=hid_stats(reports_sent=0, boot_input_sent=0,
                                               led_writes=0, control_point_writes=0,
                                               protocol_mode_writes=0,
                                               subscription_edges=0))
        self.assertEqual(errors, [])

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
        parsed = hid.options(['--out', '/tmp/x', '--discover-only', '--no-pair-click'])
        self.assertTrue(parsed.discover_only)
        self.assertFalse(parsed.pair_click)

    def test_unique_stat_names(self):
        self.assertEqual(len(hid.HID_NAMES), 16)
        self.assertEqual(len(hid.HOST_NAMES), 16)
        self.assertEqual(len(set(hid.HID_NAMES)), 16)


if __name__ == '__main__':
    unittest.main()
