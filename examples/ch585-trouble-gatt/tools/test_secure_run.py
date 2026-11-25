#!/usr/bin/env python3
"""Offline tests for the secure runner's rejection gates; no hardware access."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

    def test_fragmentation_is_skipped_when_the_mtu_fits_one_pdu(self):
        words = x1(feature_exchange=1, tx_over_27=4, rx_over_27=2,
                   max_tx_pdu=132, max_rx_pdu=132)
        # 124+4 octets fit the 128-octet post-DLE plaintext PDU exactly.
        self.assertEqual(secure.evaluate_x1(words, require_dle=True,
                                            att_mtu=124), [])
        # A larger MTU must still prove the fragmenter ran.
        self.assertTrue(any('Host ACL packet' in error
                            for error in secure.evaluate_x1(words, True, att_mtu=200)))

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
        host = [0] * len(secure.HOST_NAMES)
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
            stats, pairings=stats['stage_pairings']), [])

    def test_attempts_without_a_controller_resolution_fail(self):
        # The Host resolves on its own, so attempts alone prove nothing.
        stats = secure.decode_privacy(
            privacy(resolve_ok=1, stage_resolve_ok=1, reconnect_resolve_ok=1))
        errors = secure.evaluate_privacy(stats, pairings=0)
        self.assertTrue(any('never resolved' in error for error in errors))

    def test_rotations_after_the_reconnect_do_not_count(self):
        # Final totals keep rotating while the app holds the second link.
        stats = secure.decode_privacy(privacy(rotations=12, reconnect_rotations=1))
        errors = secure.evaluate_privacy(stats, pairings=0)
        self.assertTrue(any('fewer than two RPA rotations' in error for error in errors))

    def test_a_second_pairing_after_the_disconnect_fails(self):
        stats = secure.decode_privacy(privacy(stage_pairings=1))
        errors = secure.evaluate_privacy(stats, pairings=2)
        self.assertTrue(any('paired again' in error for error in errors))

    def test_missing_pairing_counter_fails(self):
        stats = secure.decode_privacy(privacy())
        errors = secure.evaluate_privacy(stats)
        self.assertTrue(any('pairing counters missing' in error for error in errors))

    def test_capture_counts_plaintext_per_link(self):
        att = [{'frame': 30, 'aa': '0x1'}, {'frame': 110, 'aa': '0x2'}]
        control = [{'frame': 20, 'aa': '0x1', 'name': 'START_ENC_REQ'},
                   {'frame': 120, 'aa': '0x2', 'name': 'START_ENC_REQ'}]
        after, start = capture.att_after_encryption(att, control)
        self.assertEqual(start['aa'], '0x1')
        self.assertEqual([entry['frame'] for entry in after], [30])

    def test_missing_reconnect_snapshot_fails(self):
        stats = secure.decode_privacy(privacy(reconnect_generations=0))
        errors = secure.evaluate_privacy(stats, pairings=0)
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


def fal_privacy(policy=2, **values):
    settings = {'rejected_not_listed': 1}
    settings.update(values)
    words = privacy(**settings)
    words[2] |= secure.P_FAL_NONEMPTY
    words[secure.PRIVACY_NAMES.index('list_state')] = 1 | (policy << 8)
    return words


def fal_bonds(**values):
    bonds = {'pairs_complete': 0, 'pairs_without_bond': 0,
             'fal_builds': 1, 'fal_busy_retries': 0, 'fal_members_max': 1}
    bonds.update(values)
    return bonds


def fal_stats():
    stats = [0] * 64
    stats[14] = 1
    return stats


class FalTests(unittest.TestCase):
    def test_valid_fal_run_passes(self):
        stats = secure.decode_privacy(fal_privacy())
        self.assertEqual(secure.evaluate_fal(stats, fal_bonds(), {'connections': 1},
                                             fal_stats()), [])

    def test_unfiltered_advertising_fails(self):
        stats = secure.decode_privacy(fal_privacy(policy=0))
        errors = secure.evaluate_fal(stats, fal_bonds(), {'connections': 1}, fal_stats())
        self.assertTrue(any('filter policy' in error for error in errors))

    def test_no_rejected_attempt_fails(self):
        stats = secure.decode_privacy(fal_privacy(rejected_not_listed=0))
        errors = secure.evaluate_fal(stats, fal_bonds(), {'connections': 1}, fal_stats())
        self.assertTrue(any('rejected by the accept list' in error for error in errors))

    def test_rebuilding_after_the_last_advertisement_fails(self):
        stats = secure.decode_privacy(fal_privacy())
        errors = secure.evaluate_fal(stats, fal_bonds(fal_builds=0),
                                     {'connections': 1}, fal_stats())
        self.assertTrue(any('never rebuilt' in error for error in errors))

    def test_any_new_pairing_fails(self):
        stats = secure.decode_privacy(fal_privacy())
        errors = secure.evaluate_fal(stats, fal_bonds(pairs_complete=1),
                                     {'connections': 1}, fal_stats())
        self.assertTrue(any('paired again' in error for error in errors))

    def test_a_second_host_connection_fails(self):
        stats = secure.decode_privacy(fal_privacy())
        errors = secure.evaluate_fal(stats, fal_bonds(), {'connections': 2}, fal_stats())
        self.assertTrue(any('one Host connection' in error for error in errors))

    def test_fallback_flag_fails(self):
        stats = secure.decode_privacy(
            fal_privacy(flags=secure.P_ADV_USES_RPA | secure.P_LOCAL_IRK
                        | secure.P_STAMP_VALID | secure.P_FAL_NONEMPTY
                        | secure.P_FAL_REBUILD_FAILED))
        errors = secure.evaluate_fal(stats, fal_bonds(), {'connections': 1}, fal_stats())
        self.assertTrue(any('could not be rebuilt' in error for error in errors))

    def test_probe_rejection_passes(self):
        report, errors = secure.evaluate_probe(
            [{'event': 'connecting'}, {'event': 'connect_rejected'}], 0)
        self.assertTrue(report['rejected'])
        self.assertEqual(errors, [])

    def test_probe_connection_is_a_failure(self):
        _, errors = secure.evaluate_probe(
            [{'event': 'connecting'}, {'event': 'unexpected_connected'}], 4)
        self.assertTrue(any('connected although' in error for error in errors))

    def test_probe_silence_after_an_attempt_is_recorded_not_judged(self):
        # CoreBluetooth stays silent when the peripheral never answers; the
        # firmware counter decides whether the attempt was refused.
        report, errors = secure.evaluate_probe([{'event': 'connecting'}], 6)
        self.assertEqual(report['outcome'], 'silent')
        self.assertEqual(errors, [])

    def test_probe_that_never_connected_fails(self):
        report, errors = secure.evaluate_probe([{'event': 'scan_started'}], 6)
        self.assertEqual(report['outcome'], 'no_attempt')
        self.assertTrue(any('never started a connection' in error for error in errors))
        _, errors = secure.evaluate_probe([], 3)
        self.assertTrue(any('never started a connection' in error for error in errors))

    def test_the_whole_probe_budget_must_fit_the_firmware_run(self):
        argv = ['--out', '/tmp/x', '--run-seconds', '60', '--timeout', '10',
                '--mode', 'fal', '--fal-settle', '0', '--connect-wait', '1',
                '--probe-timeout', '120']
        with self.assertRaises(SystemExit):
            secure.options(argv)
        argv[-1] = '30'
        self.assertEqual(secure.options(argv).probe_timeout, 30)

    def test_connect_wait_must_fit_inside_the_probe(self):
        argv = ['--out', '/tmp/x', '--run-seconds', '60', '--timeout', '40',
                '--mode', 'fal', '--fal-settle', '2', '--connect-wait', '40',
                '--probe-timeout', '30']
        with self.assertRaises(SystemExit):
            secure.options(argv)
        argv[-1] = '45'
        self.assertEqual(secure.options(argv).connect_wait, 40)

    def test_capture_classifies_a_central_only_link_as_refused(self):
        rows = [{'btle.access_address': '0x1', 'nordic_ble.direction': 'True'},
                {'btle.access_address': '0x2', 'nordic_ble.direction': 'True'},
                {'btle.access_address': '0x2', 'nordic_ble.direction': 'False'}]
        accepted, refused, unknown = capture.classify_links(['0x1', '0x2', '0x3'], rows)
        self.assertEqual(accepted, ['0x2'])
        self.assertEqual(refused, ['0x1'])
        # No captured PDU is a missed follow, not a refusal.
        self.assertEqual(unknown, ['0x3'])

    def test_capture_fal_rejects_an_unknown_link_as_negative_evidence(self):
        assessed = {'target': capture.TARGET, 'access_address': '0x1',
                    'accepted_links': ['0x1'], 'rejected_links': [],
                    'inconclusive_links': ['0x2'],
                    'smp': [], 'smp_opcodes_captured': [],
                    'll_control': [{'aa': '0x1', 'name': 'START_ENC_REQ'}],
                    'encryption_start': {'aa': '0x1', 'frame': 40},
                    'att_after_encryption_start': []}
        errors = capture.evaluate(assessed, 'fal')
        self.assertTrue(any('inconclusive' in error for error in errors))

    def test_capture_fal_needs_one_refused_and_one_encrypted_link(self):
        assessed = {'target': capture.TARGET, 'access_address': '0x1',
                    'accepted_links': ['0x1'], 'rejected_links': ['0x2'],
                    'smp': [], 'smp_opcodes_captured': [],
                    'll_control': [{'aa': '0x1', 'name': 'START_ENC_REQ'}],
                    'encryption_start': {'aa': '0x1', 'frame': 40},
                    'att_after_encryption_start': []}
        self.assertEqual(capture.evaluate(assessed, 'fal'), [])
        assessed['rejected_links'] = []
        self.assertTrue(any('refused' in error for error in capture.evaluate(assessed, 'fal')))
        assessed['rejected_links'] = ['0x2']
        assessed['smp'] = [{'aa': '0x1', 'name': 'PairingRequest'}]
        self.assertTrue(any('SMP again' in error for error in capture.evaluate(assessed, 'fal')))
        assessed['smp'] = []
        assessed['ll_control'] = []
        self.assertTrue(any('never started encryption' in error
                            for error in capture.evaluate(assessed, 'fal')))


class PhyTests(unittest.TestCase):
    def test_phy_stats_require_the_two_mega_switch(self):
        words = [0] * secure.PHY_STATS_WORDS
        for name, value in (('tx', 2), ('rx', 2), ('req_tx', 1), ('rsp_rx', 1),
                            ('update_rx', 1), ('changes', 1),
                            ('read_tx', 2), ('read_rx', 2)):
            words[secure.PHY_NAMES.index(name)] = value
        self.assertEqual(secure.evaluate_phy(words, True), [])
        self.assertEqual(secure.evaluate_phy(words, False), [])
        # A peer-started procedure needs no Host REQ.
        peer = [0] * secure.PHY_STATS_WORDS
        for name, value in (('tx', 2), ('rx', 2), ('req_rx', 1), ('rsp_tx', 1),
                            ('update_rx', 1), ('changes', 1),
                            ('read_tx', 2), ('read_rx', 2)):
            peer[secure.PHY_NAMES.index(name)] = value
        self.assertEqual(secure.evaluate_phy(peer, True), [])
        # A slave-initiated REQ is answered by the IND alone; no RSP is legal.
        lone = [0] * secure.PHY_STATS_WORDS
        for name, value in (('tx', 2), ('rx', 2), ('req_tx', 1),
                            ('update_rx', 1), ('changes', 1),
                            ('read_tx', 2), ('read_rx', 2)):
            lone[secure.PHY_NAMES.index(name)] = value
        self.assertEqual(secure.evaluate_phy(lone, True), [])
        self.assertEqual(secure.evaluate_phy([0] * secure.PHY_STATS_WORDS, False), [])
        self.assertTrue(any('never written' in error
                            for error in secure.evaluate_phy([0] * secure.PHY_STATS_WORDS, True)))
        words[secure.PHY_NAMES.index('read_rx')] = 1
        self.assertTrue(any('LE Read PHY' in error
                            for error in secure.evaluate_phy(words, True)))
        words[secure.PHY_NAMES.index('invalid')] = 1
        self.assertTrue(any('invalid PDUs' in error
                            for error in secure.evaluate_phy(words, False)))

    def test_peer_run_rejects_a_host_started_procedure(self):
        peer = [0] * secure.PHY_STATS_WORDS
        for name, value in (('tx', 2), ('rx', 2), ('req_rx', 1), ('rsp_tx', 1),
                            ('update_rx', 1), ('changes', 1),
                            ('read_tx', 2), ('read_rx', 2)):
            peer[secure.PHY_NAMES.index(name)] = value
        self.assertEqual(secure.evaluate_phy(peer, True, peer=True), [])
        host = list(peer)
        host[secure.PHY_NAMES.index('req_rx')] = 0
        host[secure.PHY_NAMES.index('rsp_tx')] = 0
        host[secure.PHY_NAMES.index('req_tx')] = 1
        errors = secure.evaluate_phy(host, True, peer=True)
        self.assertTrue(any('Host requested' in error for error in errors))
        self.assertTrue(any('peer PHY procedure incomplete' in error
                            for error in errors))


class PreflightTests(unittest.TestCase):
    def test_missing_manifest_never_touches_hardware(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / 'image.elf'
            elf.write_bytes(b'\x7fELF-test')
            wanted = ('HOST_STATS', 'SECURE_STATS', 'SEC_DIAG', 'SEC_OPCODES',
                      'HOST_ERROR', 'BOND_STATS', 'BOND_ECHO', 'CATT_STATS',
                      'X4_STATS', 'X1_STATS', 'PHY_STATS', 'PERIPHERAL_ADDRESS')
            text = '\n'.join(f'20000200 T {name}' for name in wanted)
            text += '\n20000300 T _embassy_crypto_aes128ecb_encrypt_blocks'
            args = argparse.Namespace(out=root / 'out', elf=elf, smoke_elf=elf,
                                      nm='nm', mode='att', run_seconds=60,
                                      timeout=40, expect_irk_fingerprint=None,
                                      manifest=None)
            calls = []

            def command(argv, *rest, **kwargs):
                calls.append(argv[0])
                return text

            with patch.object(secure.io, 'command', side_effect=command), \
                    patch.object(secure, 'validate_observation_buffers',
                                 side_effect=lambda image, symbols, extra=(): symbols), \
                    patch.object(secure.p4, 'symbols_from',
                                 return_value={'RUN_SECONDS': 0x2000}), \
                    patch.object(secure.p4, 'validate_ram_layout', return_value={}), \
                    patch.object(secure.p4, 'embedded_u32', return_value=60), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = secure.execute(args)
            result = json.loads((args.out / 'result.json').read_text())
            self.assertEqual(code, 1)
            self.assertEqual(calls, ['nm'])
            self.assertTrue(any('manifest' in error.lower() for error in result['errors']))
            self.assertEqual(result['smoke_recovery'], 'NOT ATTEMPTED')


if __name__ == '__main__':
    unittest.main()
