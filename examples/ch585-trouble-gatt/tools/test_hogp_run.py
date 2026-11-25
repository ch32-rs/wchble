#!/usr/bin/env python3
"""Offline tests for the D1 HOGP runner's gates; no hardware access."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hogp_run = load('d1_hogp_run_test', HERE / 'hogp_run.py')
gatt = hogp_run.gatt
secure = hogp_run.secure


def host(security=3, **values):
    # Slot 15 is the security state, not part of the named HOST_STATS layout.
    words = [0] * len(gatt.HOST_NAMES)
    words[0], words[1], words[2], words[15] = 0, 1, 1, security
    for name, value in values.items():
        words[gatt.HOST_NAMES.index(name)] = value
    return words


def stats(**values):
    words = [0] * 64
    words[15], words[16], words[7] = 1, 1, 1
    for name, value in values.items():
        words[gatt.STAT_NAMES.index(name)] = value
    return words


def hogp(**values):
    words = [0] * 18
    words[hogp_run.HOGP_NAMES.index('magic')] = hogp_run.HOGP_MAGIC
    words[hogp_run.HOGP_NAMES.index('version')] = 1
    words[hogp_run.HOGP_NAMES.index('reports')] = 150
    words[hogp_run.HOGP_NAMES.index('motion')] = 150
    words[hogp_run.HOGP_NAMES.index('buttons')] = 20
    words[hogp_run.HOGP_NAMES.index('subscriptions')] = 1
    words[hogp_run.HOGP_NAMES.index('references')] = 1
    words[hogp_run.HOGP_NAMES.index('map_len')] = len(hogp_run.MOUSE_REPORT_MAP)
    words[hogp_run.HOGP_NAMES.index('map_hash')] = hogp_run.fnv1a(hogp_run.MOUSE_REPORT_MAP)
    words[hogp_run.HOGP_NAMES.index('map_reports')] = 1
    for name, value in values.items():
        words[hogp_run.HOGP_NAMES.index(name)] = value
    return words


def bonds(**values):
    words = [0] * 32
    for name, value in values.items():
        words[secure.BOND_NAMES.index(name)] = value
    return words


def sec(**values):
    words = [0] * 16
    words[secure.SEC_NAMES.index('magic')] = secure.SEC_MAGIC
    words[secure.SEC_NAMES.index('version_flags')] = 1
    words[secure.SEC_NAMES.index('active')] = 1
    words[secure.SEC_NAMES.index('encrypted_tx')] = 1
    words[secure.SEC_NAMES.index('encrypted_rx')] = 1
    for name, value in values.items():
        words[secure.SEC_NAMES.index(name)] = value
    return words


def evaluate(host_words=None, stats_words=None, hogp_words=None, require_params=False):
    return hogp_run.evaluate(host_words or host(), stats_words or stats(),
                             hogp_words or hogp(), require_params)


class GateTests(unittest.TestCase):
    def test_baseline_passes(self):
        self.assertEqual(evaluate(), [])

    def test_peer_diag_decodes_the_matched_addresses(self):
        # public 48:74:12:A4:AA:38 stored LSB-first: 38 aa a4 12 74 48
        raw = [0x38, 0xAA, 0xA4, 0x12, 0x74, 0x48]
        words = [0x50445231, 0b11000, 0, 0, 0, 0, 0, 0, 0, 0x50445232]
        for base in (2, 4, 6):
            words[base] = raw[0] << 8 | raw[1] << 16 | raw[2] << 24
            words[base + 1] = raw[3] | raw[4] << 8 | raw[5] << 16
        decoded = hogp_run.decode_peer_diag(words)
        self.assertEqual(decoded['peer']['address'], '48:74:12:a4:aa:38')
        self.assertFalse(decoded['is_bonded_peer'])
        self.assertFalse(decoded['stored_irk_resolves_peer'])
        self.assertTrue(decoded['stored_bond_present'])
        self.assertTrue(decoded['identity_differs_from_peer'])
        self.assertFalse(decoded['stored_bond_matches_identity'])

    def test_peer_diag_decodes_the_stale_bond_bits(self):
        words = [0x50445231] + [0] * 7 + [3, 0x50445232]
        decoded = hogp_run.decode_peer_diag(words)
        self.assertTrue(decoded['stale_bond_rejected'])
        self.assertTrue(decoded['stale_bond_removed'])

    def test_unencrypted_link_fails(self):
        errors = evaluate(host(security=1))
        self.assertTrue(any('expected encrypted' in error for error in errors))

    def test_host_error_fails(self):
        self.assertTrue(evaluate(host(errors=1)))
        self.assertTrue(evaluate(host(last_error=11)))

    def test_no_subscription_fails(self):
        self.assertTrue(evaluate(hogp_words=hogp(subscriptions=0)))

    def test_reference_shortfall_fails(self):
        self.assertTrue(evaluate(hogp_words=hogp(subscriptions=2)))

    def test_few_reports_fail(self):
        self.assertTrue(evaluate(hogp_words=hogp(reports=99)))
        self.assertTrue(evaluate(hogp_words=hogp(motion=99)))
        self.assertTrue(evaluate(hogp_words=hogp(buttons=0)))

    def test_wrong_map_hash_fails(self):
        self.assertTrue(evaluate(hogp_words=hogp(map_hash=1)))

    def test_hogp_errors_fail(self):
        self.assertTrue(evaluate(hogp_words=hogp(errors=1)))

    def test_tx_late_fails(self):
        self.assertTrue(evaluate(stats_words=stats(tx_late=1)))

    def test_supervision_expiry_fails(self):
        self.assertTrue(evaluate(stats_words=stats(supervision=1)))

    def test_poll_limits_fail(self):
        self.assertTrue(evaluate(stats_words=stats(max_host_poll_us=100_001)))
        self.assertTrue(evaluate(stats_words=stats(pairing_max_poll_us=2_000_000)))

    def test_engine_silence_fails(self):
        self.assertTrue(evaluate(stats_words=stats(events=0)))
        self.assertTrue(evaluate(stats_words=stats(rx_done=0)))

    def test_params_gate(self):
        params = dict(req_min=24, req_max=40, interval=32)
        self.assertEqual(evaluate(hogp_words=hogp(**params)), [])
        self.assertEqual(evaluate(hogp_words=hogp(**params), require_params=True), [])
        # No peer request: only the real-HID rounds gate it.
        self.assertEqual(evaluate(hogp_words=hogp(), require_params=False), [])
        self.assertTrue(evaluate(hogp_words=hogp(), require_params=True))
        self.assertTrue(evaluate(hogp_words=hogp(req_min=24, req_max=40,
                                                 interval=48), require_params=True))


class BondTests(unittest.TestCase):
    def test_fresh_bond_passes(self):
        self.assertEqual(hogp_run.evaluate_bonds(
            bonds(pairs_complete=1, save_ok=1), False), [])

    def test_fresh_without_pairing_fails(self):
        self.assertTrue(hogp_run.evaluate_bonds(bonds(save_ok=1), False))
        self.assertTrue(hogp_run.evaluate_bonds(
            bonds(pairs_complete=1, save_ok=0), False))
        # The boot IRK save alone must not look like a fresh pairing.
        self.assertTrue(hogp_run.evaluate_bonds(bonds(save_ok=1), False))

    def test_fresh_with_a_stored_bond_fails(self):
        self.assertTrue(hogp_run.evaluate_bonds(
            bonds(records_loaded=1, pairs_complete=1, save_ok=1), False))

    def test_bonded_passes_and_rejects_repairing(self):
        self.assertEqual(hogp_run.evaluate_bonds(
            bonds(load_result=1, records_loaded=1, save_ok=1), True), [])
        self.assertTrue(hogp_run.evaluate_bonds(bonds(load_result=0, save_ok=1), True))
        # A valid store without records is not a bonded reconnect.
        self.assertTrue(hogp_run.evaluate_bonds(
            bonds(load_result=1, save_ok=1), True))
        self.assertTrue(hogp_run.evaluate_bonds(
            bonds(load_result=1, records_loaded=1, pairs_complete=1, save_ok=1), True))


    def test_recover_bond_passes_only_with_a_replacement(self):
        self.assertEqual(hogp_run.evaluate_bonds(
            bonds(load_result=1, records_loaded=1, pairs_complete=1, save_ok=1),
            False, True), [])
        # No stored bond to reject, no re-pairing, or no replacement save.
        self.assertTrue(hogp_run.evaluate_bonds(
            bonds(load_result=1, pairs_complete=1, save_ok=1), False, True))
        self.assertTrue(hogp_run.evaluate_bonds(
            bonds(load_result=1, records_loaded=1, save_ok=1), False, True))
        self.assertTrue(hogp_run.evaluate_bonds(
            bonds(load_result=1, records_loaded=1, pairs_complete=1), False, True))


class PhoneTests(unittest.TestCase):
    def rows(self, **overrides):
        base = [
            {'event': 'hid_ready'},
            {'event': 'connected'},
            {'event': 'cccd_write', 'subscribed': True},
            {'event': 'report_reference_read'},
            {'event': 'hid_read', 'uuid': '00002a4b-0000-1000-8000-00805f9b34fb'},
        ] + [{'event': 'report', 'sent': True} for _ in range(120)]
        for name, value in overrides.items():
            rows = [row for row in base if row.get('event') != name]
            rows.extend(value)
            base = rows
        return base

    def test_phone_passes(self):
        self.assertEqual(hogp_run.evaluate_phone(self.rows()), [])

    def test_missing_subscription_fails(self):
        errors = hogp_run.evaluate_phone(
            self.rows(cccd_write=[{'event': 'cccd_write', 'subscribed': False}]))
        self.assertTrue(any('CCCD subscription' in error for error in errors))

    def test_failed_notifications_fail(self):
        errors = hogp_run.evaluate_phone(
            self.rows(report=[{'event': 'report', 'sent': False}]))
        self.assertTrue(any('failed' in error for error in errors))


if __name__ == '__main__':
    unittest.main()
