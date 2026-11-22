#!/usr/bin/env python3
"""Offline tests for the pp+secure runner's gates; no hardware access."""
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('ch585_pp_secure_run_test', HERE / 'pp_secure_run.py')
secure = runner.secure
pprun = runner.pprun


def pp(**values):
    words = [0] * 16
    words[0] = runner.PP_MAGIC
    words[1] = 1
    for name, value in values.items():
        words[runner.PP_NAMES.index(name)] = value
    return words


def sec(**values):
    words = [0] * 16
    words[0] = secure.SEC_MAGIC
    words[1] = (1 << 8) | (1 << 9) | (1 << 10) | 1
    for name, value in values.items():
        words[secure.SEC_NAMES.index(name)] = value
    return words


def host(**values):
    words = [0] * 16
    words[0] = 2  # back to advertising
    words[3] = words[4] = words[5] = 1
    for name, value in values.items():
        words[runner.gatt.HOST_NAMES.index(name)] = value
    return words


def stats(**values):
    words = [0] * 64
    words[:3] = [0x50343538, 1, 9]
    words[14] = words[15] = 1
    words[32] = 60_000_000
    for name, value in values.items():
        words[runner.gatt.STAT_NAMES.index(name)] = value
    return words


def bonds(**values):
    words = [0] * 32
    words[0] = secure.BOND_MAGIC
    for name, value in values.items():
        words[secure.BOND_NAMES.index(name)] = value
    return words


class PPStatsTests(unittest.TestCase):
    def test_bond_rounds_stay_commissioning(self):
        words = pp(mode=0, encrypted_events=1)
        self.assertEqual(runner.evaluate_pp(words, 'bond-phone'), [])
        self.assertEqual(runner.evaluate_pp(words, 'bond-mac'), [])

    def test_bond_round_rejects_a_second_encryption_or_pairing(self):
        errors = runner.evaluate_pp(pp(mode=0, encrypted_events=1,
                                       pairs_without_bond=1), 'bond-phone')
        self.assertTrue(any('pairs_without_bond' in error for error in errors))
        errors = runner.evaluate_pp(pp(mode=0, encrypted_events=1,
                                       pairing_failed=1), 'bond-mac')
        self.assertTrue(any('pairing_failed' in error for error in errors))

    def test_dual_requires_two_encrypted_events_and_no_pairing(self):
        self.assertEqual(
            runner.evaluate_pp(pp(mode=1, accepts_in_dual=2,
                                  pairing_refused=2, encrypted_events=2),
                               'dual'), [])
        errors = runner.evaluate_pp(pp(mode=1, accepts_in_dual=2,
                                       pairing_refused=2, encrypted_events=1),
                                    'dual')
        self.assertTrue(any('encrypted_events' in error for error in errors))
        errors = runner.evaluate_pp(pp(mode=1, accepts_in_dual=2,
                                       pairing_refused=2, encrypted_events=2,
                                       pairing_failed=1), 'dual')
        self.assertTrue(any('pairing_failed' in error for error in errors))

    def test_reject_requires_refused_accepts_without_a_new_bond(self):
        self.assertEqual(
            runner.evaluate_pp(pp(mode=1, accepts_in_dual=2,
                                  pairing_refused=2, encrypted_events=1),
                               'reject'), [])
        # pairing_failed is archived, not gated: a silent stall also refuses.
        self.assertEqual(
            runner.evaluate_pp(pp(mode=1, accepts_in_dual=2,
                                  pairing_refused=2, encrypted_events=1,
                                  pairing_failed=1), 'reject'), [])
        errors = runner.evaluate_pp(pp(mode=1, accepts_in_dual=2,
                                       pairing_refused=1, encrypted_events=1),
                                    'reject')
        self.assertTrue(any('pairing_refused' in error for error in errors))
        errors = runner.evaluate_pp(pp(mode=1, accepts_in_dual=2,
                                       pairing_refused=2, encrypted_events=1,
                                       pairs_without_bond=1), 'reject')
        self.assertTrue(any('pairs_without_bond' in error for error in errors))

    def test_magic_and_size_are_validated(self):
        self.assertEqual(len(runner.evaluate_pp([], 'dual')), 1)
        bad = pp(mode=1)
        bad[0] = 0
        self.assertEqual(len(runner.evaluate_pp(bad, 'dual')), 1)


class SecureStatsTests(unittest.TestCase):
    def test_dual_expects_two_encryption_procedures(self):
        words = sec(enc_req=2, ltk_request=2, start_req=2)
        self.assertEqual(runner.evaluate_secure(words, 2), [])

    def test_single_link_expects_one(self):
        words = sec(enc_req=1, ltk_request=1, start_req=1)
        self.assertEqual(runner.evaluate_secure(words, 1), [])

    def test_mic_failures_fail_but_lingering_active_is_archived(self):
        errors = runner.evaluate_secure(sec(enc_req=2, ltk_request=2,
                                            start_req=2, mic_failure=1), 2)
        self.assertTrue(any('MIC' in error for error in errors))
        # `active` stays 1 after the finite run (single-link baseline agrees),
        # so it must not fail the round.
        words = sec(enc_req=2, ltk_request=2, start_req=2, active=1)
        self.assertEqual(runner.evaluate_secure(words, 2), [])

    def test_encryption_count_mismatch_fails(self):
        errors = runner.evaluate_secure(sec(enc_req=1, ltk_request=1,
                                            start_req=1), 2)
        self.assertTrue(any('enc_req' in error for error in errors))

    def test_unseeded_rng_fails(self):
        words = sec(enc_req=1, ltk_request=1, start_req=1)
        words[1] = 1
        self.assertTrue(any('seeded' in error for error in
                            runner.evaluate_secure(words, 1)))


class HostStatsTests(unittest.TestCase):
    def test_dual_round_counts_two_connections(self):
        words = host(connections=2, disconnects=2)
        self.assertEqual(runner.evaluate_host(words, 'dual'), ([], dict(
            zip(runner.gatt.HOST_NAMES, words))))

    def test_bond_round_counts_one_connection(self):
        errors, _ = runner.evaluate_host(host(connections=2, disconnects=1),
                                        'bond-phone')
        self.assertTrue(any('connections' in error for error in errors))

    def test_dirty_host_fails(self):
        errors, _ = runner.evaluate_host(host(connections=2, disconnects=2,
                                              errors=1), 'dual')
        self.assertTrue(any('not clean' in error for error in errors))


class EngineStatsTests(unittest.TestCase):
    def test_clean_round_passes_with_engine_zeros(self):
        words = stats(connect_valid=2, connections_with_data=2)
        errors, detail = runner.evaluate_stats(words, 'bond-mac', 60)
        self.assertEqual(errors, [])
        errors, detail = runner.evaluate_stats(stats(), 'bond-phone', 60)
        self.assertEqual(errors, [])
        self.assertIn('max_host_poll_us', detail)

    def test_tx_late_is_a_hard_gate(self):
        errors, _ = runner.evaluate_stats(stats(tx_late=1), 'dual', 60)
        self.assertTrue(any('tx_late' in error for error in errors))

    def test_bond_mac_archives_the_consent_wait_retry(self):
        errors, _ = runner.evaluate_stats(stats(connect_valid=2,
                                               connections_with_data=2,
                                               retries=1), 'bond-mac', 60)
        self.assertEqual(errors, [])
        errors, _ = runner.evaluate_stats(stats(connect_valid=2,
                                               connections_with_data=2,
                                               retries=1), 'dual', 60)
        self.assertTrue(any('retries' in error for error in errors))

    def test_reject_archives_the_pairing_burst_retransmits(self):
        # The pairing-crypto burst retransmits once on the LL, same family
        # as the bond-mac consent wait; the dual round keeps the hard zero.
        words = stats(connect_valid=5, connections_with_data=2,
                      duplicates=1, retries=1)
        errors, _ = runner.evaluate_stats(words, 'reject', 60)
        self.assertEqual(errors, [])

    def test_dual_needs_two_links_but_reject_only_one_with_data(self):
        errors, _ = runner.evaluate_stats(stats(), 'dual', 60)
        self.assertTrue(any('connect_valid' in error for error in errors))
        # The refused phone link still carries its ATT discovery, and the
        # refused peer's LL retries must not fail the round.
        errors, _ = runner.evaluate_stats(stats(connect_valid=5,
                                               connections_with_data=2),
                                          'reject', 60)
        self.assertEqual(errors, [])
        errors, _ = runner.evaluate_stats(stats(connect_valid=2,
                                               connections_with_data=1),
                                          'reject', 60)
        self.assertTrue(any('links with data' in error for error in errors))

    def test_runtime_outside_the_budget_fails(self):
        errors, _ = runner.evaluate_stats(stats(runtime_us=10_000_000), 'dual', 60)
        self.assertTrue(any('runtime' in error for error in errors))


class BondStatsTests(unittest.TestCase):
    def test_phone_bond_persists_exactly_one_record(self):
        words = bonds(records_loaded=0, pairs_complete=1, save_ok=1)
        self.assertEqual(runner.evaluate_bonds(words, 'bond-phone'), ([], dict(
            zip(secure.BOND_NAMES, words))))

    def test_dual_boot_restores_both_records_and_never_pairs(self):
        words = bonds(records_loaded=2, add_bond_ok=2)
        errors, _ = runner.evaluate_bonds(words, 'dual')
        self.assertEqual([e for e in errors if 'records_loaded' in e], [])
        errors, _ = runner.evaluate_bonds(bonds(records_loaded=2,
                                                 pairs_complete=1), 'dual')
        self.assertTrue(any('paired again' in error for error in errors))

    def test_reject_keeps_the_boot_records(self):
        errors, _ = runner.evaluate_bonds(bonds(records_loaded=2), 'reject')
        self.assertTrue(any('records_loaded' in error for error in errors)
                        is False)
        errors, _ = runner.evaluate_bonds(bonds(records_loaded=1), 'reject')
        self.assertTrue(any('records_loaded' in error for error in errors))


class PhoneWallTests(unittest.TestCase):
    def test_rows_anchor_on_the_launch_wall(self):
        rows = [{'t_ms': 1000, 'event': 'mode'},
                {'t_ms': 2500, 'event': 'read'}]
        wall = runner.phone_wall(rows, rows[1], launch_wall=10.0)
        self.assertAlmostEqual(wall, 11.5)

    def test_missing_stamps_return_none(self):
        rows = [{'event': 'mode'}, {'t_ms': 2500, 'event': 'read'}]
        self.assertIsNone(runner.phone_wall(rows, rows[1], launch_wall=10.0))


def reconnect_rows(t_base=10_000, t_step=1_000, extra=()):
    """A passing 2-cycle reconnect transcript; `extra` rows are appended."""
    def t(s):
        return t_base + s * t_step

    rows = [
        {'t_ms': t(0), 'event': 'mode', 'mode': 'reconnect'},
        {'t_ms': t(1), 'event': 'scan_started'},
        {'t_ms': t(2), 'event': 'found'},
        {'t_ms': t(3), 'event': 'connecting'},
        {'t_ms': t(4), 'event': 'connection_state'},
        {'t_ms': t(5), 'event': 'services_discovered', 'status': 0},
        {'t_ms': t(6), 'event': 'value_subscribed', 'status': 0},
        {'t_ms': t(7), 'event': 'encrypted_gatt_start'},
        {'t_ms': t(8), 'event': 'read', 'status': 0, 'value': 0, 'index': 1},
        {'t_ms': t(9), 'event': 'write_requested', 'ok': True},
        {'t_ms': t(10), 'event': 'write_ack', 'status': 0},
        {'t_ms': t(11), 'event': 'notification', 'value': 1001},
        {'t_ms': t(12), 'event': 'notification', 'value': 43},
        {'t_ms': t(13), 'event': 'read', 'status': 0, 'value': 43,
         'index': 2},
        {'t_ms': t(14), 'event': 'cycle', 'index': 1},
        {'t_ms': t(20), 'event': 'summary', 'pass': True,
         'reason': 'reconnect_encrypted_read_write_ok', 'bonded': True},
    ]
    rows.extend(extra)
    return rows


class PhoneDualTests(unittest.TestCase):
    # The Mac exits between the write (t=9s) and the read-back (t=13s).
    MAC_EXIT = 11.0

    class Args:
        gatt_cycles = 2

    def test_full_transcript_with_hold_passes(self):
        rows = reconnect_rows()
        errors, detail = runner.evaluate_phone_dual(
            rows, self.Args(), mac_exit_wall=self.MAC_EXIT, launch_wall=0.0)
        self.assertEqual(errors, [])
        self.assertEqual(detail['notifications'], 2)

    def test_missing_own_echo_or_mac_value_fails(self):
        rows = [row for row in reconnect_rows()
                if not (row['event'] == 'notification' and row['value'] == 43)]
        errors, _ = runner.evaluate_phone_dual(rows, self.Args(),
                                               mac_exit_wall=self.MAC_EXIT,
                                               launch_wall=0.0)
        self.assertTrue(any('echoed the phone write' in error for error in errors))
        rows = [row for row in reconnect_rows()
                if not (row['event'] == 'notification' and row['value'] == 1001)]
        errors, _ = runner.evaluate_phone_dual(rows, self.Args(),
                                               mac_exit_wall=self.MAC_EXIT,
                                               launch_wall=0.0)
        self.assertTrue(any('Mac write value' in error for error in errors))

    def test_cycle_count_must_match_the_hold_request(self):
        rows = reconnect_rows(extra=[{'t_ms': 15_000, 'event': 'cycle',
                                      'index': 2}])
        errors, _ = runner.evaluate_phone_dual(rows, self.Args(),
                                               mac_exit_wall=self.MAC_EXIT,
                                               launch_wall=0.0)
        self.assertTrue(any('extra cycles' in error for error in errors))

    def test_gatt_window_must_straddle_the_mac_exit(self):
        rows = reconnect_rows()
        # Mac leaves after every phone GATT event: one-drop-one-keep failed.
        errors, _ = runner.evaluate_phone_dual(rows, self.Args(),
                                               mac_exit_wall=16.0, launch_wall=0.0)
        self.assertTrue(any('after the Mac dropped' in error for error in errors))
        # Mac leaves before the phone did any GATT: no overlap.
        errors, _ = runner.evaluate_phone_dual(rows, self.Args(),
                                               mac_exit_wall=7.0, launch_wall=0.0)
        self.assertTrue(any('before the Mac dropped' in error for error in errors))


class PhoneRejectTests(unittest.TestCase):
    def rows(self, reason):
        return [
            {'event': 'mode', 'mode': 'pair'},
            {'event': 'scan_started'},
            {'event': 'found'},
            {'event': 'connecting'},
            {'event': 'connection_state'},
            {'event': 'bond_requested'},
            {'event': 'bond_state', 'state': 10, 'previous': 10},
            {'event': 'summary', 'pass': False, 'reason': reason},
        ]

    def test_a_refused_bond_is_the_expected_failure(self):
        errors, detail = runner.evaluate_phone_reject(self.rows('bond_rejected'))
        self.assertEqual(errors, [])
        self.assertEqual(detail['reason'], 'bond_rejected')

    def test_a_silent_smp_stall_also_counts(self):
        errors, _ = runner.evaluate_phone_reject(self.rows('timeout'))
        self.assertEqual(errors, [])

    def test_an_accepted_pairing_fails_the_gate(self):
        rows = self.rows('bond_rejected')
        rows[-1] = {'event': 'summary', 'pass': True,
                    'reason': 'encrypted_read_write_ok'}
        errors, _ = runner.evaluate_phone_reject(rows)
        self.assertTrue(any('unexpectedly succeeded' in error for error in errors))

    def test_a_residual_phone_bond_fails_the_gate(self):
        rows = self.rows('bond_rejected')
        rows.insert(2, {'event': 'already_bonded'})
        errors, _ = runner.evaluate_phone_reject(rows)
        self.assertTrue(any('residual bond' in error for error in errors))


class SmpOpcodeTests(unittest.TestCase):
    def opcodes(self, rx=0, tx_failed=0):
        return {'smp': {'rx': {'PairingRequest': rx}, 'tx': {}},
                'att': {'rx': {}, 'tx': {}}}

    def test_bond_and_reject_rounds_need_on_air_pairing(self):
        self.assertEqual(runner.evaluate_smp(self.opcodes(rx=1), 'bond-phone'), [])
        self.assertEqual(runner.evaluate_smp(self.opcodes(rx=1), 'reject'), [])
        errors = runner.evaluate_smp(self.opcodes(), 'bond-mac')
        self.assertTrue(any('SMP pairing traffic' in error for error in errors))

    def test_dual_round_must_not_pair(self):
        errors = runner.evaluate_smp(self.opcodes(rx=2), 'dual')
        self.assertTrue(any('saw SMP pairing traffic' in error for error in errors))
        self.assertEqual(runner.evaluate_smp(self.opcodes(), 'dual'), [])


class MacClientTests(unittest.TestCase):
    def rows(self, peer_value):
        rows = [
            {'event': 'start', 'role': 1, 'monotonic_seconds': 0.0},
            {'event': 'connected', 'monotonic_seconds': 1.0},
            {'event': 'notify_state', 'enabled': True},
            {'event': 'write_ack', 'value': 1001, 'monotonic_seconds': 2.0},
            {'event': 'notification', 'value': 1001, 'monotonic_seconds': 2.1},
            {'event': 'notification', 'value': peer_value, 'monotonic_seconds': 2.2},
            {'event': 'disconnected', 'expected': True, 'monotonic_seconds': 9.0},
            {'event': 'summary', 'exit_code': 0, 'reason': 'pp_complete',
             'writes': 6, 'notifications': 8, 'monotonic_seconds': 9.5},
        ]
        return rows

    def test_dual_mac_sees_the_phone_value(self):
        errors, _ = runner.evaluate_mac(1, self.rows(43), 0, 16.0, True)
        self.assertEqual(errors, [])

    def test_solo_mac_has_no_peer_requirement(self):
        errors, _ = runner.evaluate_mac(1, self.rows(1001), 0, 30.0, False)
        self.assertEqual(errors, [])
        # The unfiltered pp_run gate still reports the missing peer fanout.
        errors, _ = pprun.evaluate_client(1, self.rows(1001), 0, 30.0)
        self.assertTrue(any("other role's value" in error for error in errors))


class OptionsTests(unittest.TestCase):
    def test_phase_defaults(self):
        args = runner.options(['dual', '--out', '/tmp/pp-out'])
        self.assertEqual((args.client_seconds, args.phone_delay, args.gatt_cycles),
                         (16.0, 3.0, 5))
        args = runner.options(['reject', '--out', '/tmp/pp-out'])
        self.assertEqual((args.client_seconds, args.phone_delay), (30.0, 2.0))
        args = runner.options(['bond-mac', '--out', '/tmp/pp-out',
                               '--run-seconds', '360'])
        self.assertEqual((args.client_seconds, args.pair_wait), (30.0, 240.0))

    def test_bond_mac_requires_a_long_run_image(self):
        with self.assertRaises(SystemExit):
            runner.options(['bond-mac', '--out', '/tmp/pp-out'])

    def test_a_short_hold_is_refused(self):
        with self.assertRaises(SystemExit):
            runner.options(['dual', '--out', '/tmp/pp-out',
                           '--gatt-cycles', '2'])

    def test_wipe_requires_the_control_image(self):
        with self.assertRaises(ValueError):
            runner.run_wipe(type('A', (), {
                'out': Path('/tmp/pp-out'), 'wipe_elf': None,
                'smoke_elf': Path('/tmp/smoke'), 'serial': 'x',
                'wipe_run_seconds': 60})())


if __name__ == '__main__':
    unittest.main()
