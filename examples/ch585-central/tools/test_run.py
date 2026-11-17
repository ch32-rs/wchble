#!/usr/bin/env python3
"""Offline tests for the C1 runner's pure evaluation and preflight logic."""
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
_spec = importlib.util.spec_from_file_location('c1_runner', HERE / 'run.py')
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)


def stats(**values):
    out = [0] * 64
    out[0] = 0x43313538
    out[1] = 1
    out[2] = 9
    out[57] = 0x30000
    for key, value in values.items():
        out[int(key[1:])] = value
    return out


def host(**values):
    out = [0] * 16
    for key, value in values.items():
        out[int(key[1:])] = value
    return out


class Evaluation(unittest.TestCase):
    def positive_stats(self):
        return stats(s5=4, s6=3, s7=1, s8=3, s9=0, s10=10, s12=3, s13=3,
                     s14=3, s15=3, s21=3, s22=3, s23=30, s24=10, s25=15,
                     s26=5, s34=3, s35=3, s37=3, s38=3, s39=6, s41=3,
                     s43=9)

    def test_positive_accepts_full_cycle(self):
        s = self.positive_stats()
        h = host(h0=9, h1=3, h2=3, h3=10, h4=3, h6=6, h7=3, h12=3)
        self.assertEqual(runner.evaluate_stats(s, h, 'positive', 3, 60, {}), [])

    def test_positive_rejects_missing_connection(self):
        s = self.positive_stats()
        s[34] = 2
        h = host(h0=9, h1=3, h2=3, h3=10, h4=3, h6=6, h7=3, h12=3)
        errors = runner.evaluate_stats(s, h, 'positive', 3, 60, {})
        self.assertTrue(any('lifecycle' in error for error in errors))

    def test_invariants(self):
        s = self.positive_stats()
        s[63] = 1
        errors = runner.invariants(s)
        self.assertTrue(any('RX PDU' in error for error in errors))
        s = self.positive_stats()
        s[15] = 2
        self.assertTrue(any('connect attempt' in error for error in runner.invariants(s)))

    def test_nosource(self):
        s = stats(s5=4, s6=2, s7=2, s8=2, s10=5)
        h = host(h3=5)
        self.assertEqual(runner.evaluate_stats(s, h, 'negative-nosource', 3, 60, {}), [])
        s[12] = 1
        self.assertTrue(runner.evaluate_stats(s, h, 'negative-nosource', 3, 60, {}))

    def test_wrong_name(self):
        s = stats(s5=4, s6=2, s7=2, s8=2, s10=5)
        h = host(h3=5)
        self.assertEqual(
            runner.evaluate_stats(s, h, 'negative-wrong-name', 3, 60, {}), [])
        h[4] = 1
        self.assertTrue(runner.evaluate_stats(s, h, 'negative-wrong-name', 3, 60, {}))

    def test_no_service(self):
        s = stats(s5=4, s6=2, s7=2, s8=2, s10=5, s12=3, s13=3, s14=3,
                  s15=3, s21=3, s22=3, s34=3, s35=3, s37=0)
        h = host(h1=3, h2=3, h10=3, h12=0)
        self.assertEqual(
            runner.evaluate_stats(s, h, 'negative-no-service', 3, 60, {}), [])
        h[12] = 1
        self.assertTrue(
            runner.evaluate_stats(s, h, 'negative-no-service', 3, 60, {}))

    def test_bogus_peer(self):
        s = stats(s5=8, s6=4, s7=4, s8=4, s18=3)
        h = host(h5=3)
        self.assertEqual(
            runner.evaluate_stats(s, h, 'negative-bogus-peer', 3, 60, {}), [])
        s[14] = 1
        self.assertTrue(
            runner.evaluate_stats(s, h, 'negative-bogus-peer', 3, 60, {}))

    def test_dirty_shutdown_rejected(self):
        s = self.positive_stats()
        s[58] = 1
        h = host(h0=9, h1=3, h2=3, h3=10, h4=3, h6=6, h7=3, h12=3)
        self.assertTrue(runner.evaluate_stats(s, h, 'positive', 3, 60, {}))


class Sources(unittest.TestCase):
    def test_phase_sources(self):
        self.assertIsNone(runner.source_for('negative-nosource'))
        self.assertIsNone(runner.source_for('negative-bogus-peer'))
        self.assertEqual(runner.source_for('negative-wrong-name')['name'],
                         runner.NAME + '-neg')
        self.assertTrue(runner.source_for('negative-no-service')['no_service'])
        self.assertEqual(runner.source_for('positive')['name'], runner.NAME)

    def test_phase_order(self):
        self.assertEqual(runner.PHASES[0], 'positive')
        self.assertIn('negative-bogus-peer', runner.PHASES)
        self.assertEqual(runner.PHASES[-1], 'peer-vanish')
        self.assertEqual(len(runner.PHASES), len(set(runner.PHASES)))

    def test_stat_names_complete(self):
        self.assertEqual(len(runner.STAT_NAMES), 64)
        self.assertEqual(len(runner.HOST_NAMES), 16)
        self.assertEqual(runner.STAT_NAMES[0], 'magic')
        self.assertEqual(runner.STAT_NAMES[62], 'channel_mask')


class Preflight(unittest.TestCase):
    """A failed manifest check must not reach the probe, adb, or the scanner."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.out = self.root / 'out'
        self.elf = self.root / 'image.elf'
        self.elf.write_bytes(b'\x7fELF-test')
        self.args = argparse.Namespace(
            out=self.out, elf=self.elf, bogus_elf=self.elf, smoke_elf=self.elf,
            nm='nm', source='android', run_seconds=60, cycles=3, manifest=None)
        self.calls = []

    def tearDown(self):
        self.directory.cleanup()

    def record(self, name, result=None):
        def call(*args, **kwargs):
            self.calls.append(name)
            return result
        return call

    def record_command(self, argv, *args, **kwargs):
        self.calls.append(('command', argv[0]))
        return ''

    def run_phase(self, phase, manifest=None, verify_error=None):
        symbols = {name: 0x20000100 for name in
                   ('STATS', 'HOST_STATS', 'TRACE', 'TRACE_COUNT', 'TRACE_OVERFLOW',
                    'RUN_SECONDS')}
        verify = (patch.object(runner.build_manifest, 'verify',
                               side_effect=ValueError(verify_error))
                  if verify_error else patch.object(runner.build_manifest, 'verify'))
        with patch.object(runner, 'observation_symbols', return_value=symbols), \
                patch.object(runner, 'validate_observations'), \
                patch.object(runner, 'check_identity', return_value={}), \
                patch.object(runner.p3, 'validate_ram_layout', return_value={}), \
                patch.object(runner.p3, 'embedded_u32', return_value=60), \
                patch.object(runner, 'start_source', side_effect=self.record('source')), \
                patch.object(runner.io, 'flash', side_effect=self.record('flash')), \
                patch.object(runner.io, 'command', side_effect=self.record_command), \
                verify, \
                contextlib.redirect_stderr(io.StringIO()):
            self.args.manifest = manifest
            return runner.run_phase(self.args, phase, self.out / phase)

    def test_missing_manifest_stops_before_hardware(self):
        for phase in ('positive', 'peer-vanish'):
            with self.subTest(phase=phase):
                self.calls.clear()
                errors, touched = self.run_phase(phase)
                self.assertFalse(touched)
                self.assertTrue(any('manifest' in error.lower() for error in errors), errors)
                hardware = [call for call in self.calls
                            if call == 'flash' or call == 'source'
                            or (isinstance(call, tuple) and call[1] in ('adb', 'swift'))]
                self.assertEqual(hardware, [])
        result = json.loads((self.out / 'peer-vanish' / 'result.json').read_text())
        self.assertFalse(result['touched_hardware'])

    def test_manifest_mismatch_stops_before_hardware(self):
        manifest = self.root / 'manifest.json'
        manifest.write_text('{}')
        errors, touched = self.run_phase('positive', manifest,
                                         verify_error='manifest ELF deadbeef != beef')
        self.assertFalse(touched)
        self.assertTrue(any('manifest' in error.lower() for error in errors), errors)
        self.assertNotIn('flash', self.calls)
        self.assertNotIn('source', self.calls)

    def test_restore_only_after_hardware_attempt(self):
        for touched, expected in ((False, 'NOT ATTEMPTED'), (True, 'PASS')):
            with self.subTest(touched=touched), \
                    patch.object(runner, 'run_phase', return_value=([], touched)), \
                    patch.object(runner.io, 'flash', side_effect=self.record('flash')), \
                    patch.object(runner.io, 'command', side_effect=self.record('command')):
                self.calls.clear()
                out = self.root / f'restore-{touched}'
                args = argparse.Namespace(out=out, smoke_elf=self.elf, phase='positive')
                code = runner.execute(args)
                result = json.loads((out / 'result.json').read_text())
                self.assertEqual(code, 0)
                self.assertTrue(result['phases']['smoke_recovery'].startswith(expected))
                self.assertEqual('flash' in self.calls, touched)
                self.assertEqual(bool(self.calls), touched)


if __name__ == '__main__':
    unittest.main()
