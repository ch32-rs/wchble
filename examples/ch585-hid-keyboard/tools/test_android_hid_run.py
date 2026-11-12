#!/usr/bin/env python3
"""Offline tests for the Android HID acceptance runner's judgement."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    'android_hid_run', Path(__file__).with_name('android_hid_run.py'))
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

hid = runner.hid


def app_rows(reason='hid_system_input_ok'):
    rows = [
        {'event': 'mode', 'mode': 'hid'},
        {'event': 'hid_service', 'status': 0, 'service': True,
         'characteristics': 8, 'reports': 2, 'notify_report': True},
        {'event': 'hid_access_denied', 'error': 'Need BLUETOOTH PRIVILEGED permission'},
        {'event': 'input_device', 'id': 11, 'name': 'wch585-hid',
         'descriptor': 'abc', 'sources': 257, 'keyboard_type': 2},
        {'event': 'summary', 'pass': True, 'reason': reason},
    ]
    return rows


def firmware_words(**overrides):
    values = {name: 0 for name in hid.HID_NAMES}
    values['magic'] = hid.HID_MAGIC
    values['version'] = 1
    values['protocol_mode'] = 1
    values.update(overrides)
    return [values[name] for name in hid.HID_NAMES]


def host_words(security=3, connections=1):
    values = {name: 0 for name in hid.HOST_NAMES}
    values['phase'] = 2
    values['connections'] = connections
    values['security'] = security
    return [values[name] for name in hid.HOST_NAMES]


def secure_words(**overrides):
    values = {name: 0 for name in hid.SEC_NAMES}
    values['magic'] = hid.SEC_MAGIC
    values['version_flags'] = 0x700 | 1
    values['enc_req'] = values['enc_rsp'] = 1
    values['start_req'] = values['start_rsp'] = 1
    values['encrypted_tx'] = 1
    values['active'] = 1
    values.update(overrides)
    return [values[name] for name in hid.SEC_NAMES]


def stats_words(run_seconds=60):
    values = [0] * 64
    values[0], values[1], values[2] = 0x5034_3538, 1, 9
    values[14] = values[15] = 1
    values[32] = run_seconds * 1_000_000
    values[34] = 0x30000
    return values


class TranscriptTests(unittest.TestCase):
    def test_app_success(self):
        errors = runner.evaluate_transcript(
            app_rows(), 'Device 11: wch585-hid KeyboardType: 2')
        self.assertEqual(errors, [], errors)

    def test_app_requires_privilege_gate(self):
        rows = [row for row in app_rows() if row['event'] != 'hid_access_denied']
        errors = runner.evaluate_transcript(rows, 'Device 11: wch585-hid')
        self.assertTrue(any('hid_access_denied' in error for error in errors))

    def test_app_requires_input_device(self):
        rows = [row for row in app_rows() if row['event'] != 'input_device']
        errors = runner.evaluate_transcript(rows, 'Device 11: wch585-hid')
        self.assertTrue(any('input device' in error for error in errors))

    def test_app_requires_dumpsys_view(self):
        errors = runner.evaluate_transcript(app_rows(), 'no keyboard here')
        self.assertTrue(any('dumpsys input' in error for error in errors))

    def test_service_layout_is_checked(self):
        rows = app_rows()
        rows[1]['characteristics'] = 9
        errors = runner.evaluate_transcript(rows, 'wch585-hid')
        self.assertTrue(any('HID service' in error for error in errors))

    def test_reports_mode_needs_full_cycle(self):
        rows = app_rows('hid_reports_ok')
        errors = runner.evaluate_transcript(rows, 'wch585-hid')
        self.assertTrue(any('hid_info' in error for error in errors))
        self.assertTrue(any('reports' in error for error in errors))

    def test_failed_summary_is_rejected(self):
        rows = app_rows()
        rows[-1]['pass'] = False
        errors = runner.evaluate_transcript(rows, 'wch585-hid')
        self.assertTrue(any('HID success' in error for error in errors))


class FirmwareTests(unittest.TestCase):
    def test_app_mode_allows_no_subscription(self):
        errors = runner.evaluate_firmware(
            firmware_words(), host_words(), secure_words(), stats_words(), 60, 'app')
        self.assertEqual(errors, [], errors)

    def test_app_mode_requires_encryption(self):
        errors = runner.evaluate_firmware(
            firmware_words(), host_words(security=1), secure_words(), stats_words(), 60, 'app')
        self.assertTrue(any('security=1' in error for error in errors))

    def test_payload_mode_requires_reports(self):
        errors = runner.evaluate_firmware(
            firmware_words(), host_words(), secure_words(), stats_words(), 60, 'payload')
        self.assertTrue(any('reports_sent' in error for error in errors))
        self.assertTrue(any('subscription_edges' in error for error in errors))

    def test_payload_mode_success(self):
        errors = runner.evaluate_firmware(
            firmware_words(reports_sent=22, subscription_edges=1), host_words(),
            secure_words(encrypted_tx=40), stats_words(), 60, 'payload')
        self.assertEqual(errors, [], errors)

    def test_clean_stop_is_required(self):
        stats = stats_words()
        stats[34] = 0
        errors = runner.evaluate_firmware(
            firmware_words(), host_words(), secure_words(), stats, 60, 'app')
        self.assertTrue(any('RF stop' in error for error in errors))

    def test_runtime_must_match_budget(self):
        stats = stats_words()
        stats[32] = 5_000_000
        errors = runner.evaluate_firmware(
            firmware_words(), host_words(), secure_words(), stats, 60, 'app')
        self.assertTrue(any('runtime' in error for error in errors))


class OptionTests(unittest.TestCase):
    def test_defaults(self):
        args = runner.options(['--out', '/tmp/out'])
        self.assertEqual(args.expect, 'app')
        self.assertFalse(args.bt_reset)
        self.assertFalse(args.wipe_bond)
        self.assertEqual(args.run_seconds, 60)

    def test_payload_expect(self):
        args = runner.options(['--out', '/tmp/out', '--expect', 'payload'])
        self.assertEqual(args.expect, 'payload')

    def test_unknown_expect_rejected(self):
        with self.assertRaises(SystemExit):
            with open('/dev/null', 'w') as sink:
                import contextlib
                with contextlib.redirect_stderr(sink):
                    runner.options(['--out', '/tmp/out', '--expect', 'guess'])


if __name__ == '__main__':
    unittest.main()
