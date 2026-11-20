#!/usr/bin/env python3
"""Offline checks for the X2a round runner: marker fixture, gates, log parser."""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'examples/ch585-trouble-gatt/tools'))

_spec = importlib.util.spec_from_file_location(
    'ch585_ext_adv_run', ROOT / 'examples/ch585-trouble-gatt/tools/ext_adv_run.py')
ext_adv_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ext_adv_run)


def marker_report(marker, secondary_phy=1, rssi=-55):
    hex_bytes = marker.hex()
    return (f'11-20 14:00:00.000 D/WCHBLE: {{"event":"ext_report",'
            f'"address":"C1:FF:EE:00:00:01","rssi":{rssi},"len":128,'
            f'"marker":true,"primary_phy":1,'
            f'"secondary_phy":{secondary_phy},"hex":"{hex_bytes}"}}')


def noise_report():
    return ('11-20 14:00:00.000 D/WCHBLE: {"event":"ext_report",'
            '"address":"AA:BB:CC:DD:EE:FF","rssi":-70,"len":31,'
            '"marker":false,"primary_phy":1,"secondary_phy":0,'
            '"hex":"0201060303c8fe"}')


def summary(reports, matches):
    return (f'11-20 14:00:20.000 D/WCHBLE: {{"event":"ext_summary",'
            f'"reports":{reports},"matches":{matches}}}')


class MarkerTests(unittest.TestCase):
    def test_fixture_marker_matches_beacon_layout(self):
        marker = ext_adv_run.fixture_marker()
        self.assertEqual(len(marker), 128)
        # One AD structure exactly fills the payload: 127 covers type + 126.
        self.assertEqual(marker[0], 127)
        self.assertEqual(marker[1], 0xff)
        self.assertEqual(marker[2:4], b'WC')
        for i in range(4, 124):
            self.assertEqual(marker[i], (i * 7 + 5) & 0xff)
        # The embedded CRC is the CRC-32 of the first 124 bytes.
        crc = 0xffffffff
        for byte in marker[:124]:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0xedb88320 & -(crc & 1))
        self.assertEqual(marker[124:128], (crc ^ 0xffffffff).to_bytes(4, 'little'))


class GateTests(unittest.TestCase):
    def base_word(self):
        return {
            'adv_tx': 60, 'aux_tx': 60, 'aux_late': 0, 'rounds': 60,
            'events': 20, 'last_aux_channel': 5, 'last_aux_phy': 1,
            'terminated': 0, 'did': 1234, 'data_len': 128,
            'aux_air_us': 1184, 'aux_skip': 0,
        }

    def test_passing_round(self):
        self.assertEqual(ext_adv_run.evaluate_ext(
            [self.base_word()[name] for name in ext_adv_run.EXT_NAMES]
            + [0] * (16 - len(ext_adv_run.EXT_NAMES)), 'x2-ext-adv'), [])

    def test_never_written(self):
        self.assertEqual(ext_adv_run.evaluate_ext([0] * 16, 'x2-ext-adv'),
                         ['EXT_ADV_STATS was never written'])

    def test_wrong_width(self):
        self.assertEqual(len(ext_adv_run.evaluate_ext([0] * 12, 'x2-ext-adv')), 1)

    def test_each_counter_gate(self):
        cases = {
            'adv_tx': ('adv/aux/rounds disagree', 61),
            'aux_late': ('missed the 600-us window', 1),
            'aux_skip': ('rounds were skipped', 2),
            'events': ('too few extended advertising events', 9),
            'last_aux_phy': ('last aux PHY is 2', 2),
            'data_len': ('marker length is 64', 64),
        }
        for name, (needle, value) in cases.items():
            word = self.base_word()
            word[name] = value
            errors = ext_adv_run.evaluate_ext(
                [word[n] for n in ext_adv_run.EXT_NAMES] + [0] * 4, 'x2-ext-adv')
            self.assertTrue(any(needle in error for error in errors),
                            f'{name} gate missing: {errors}')


class LogcatTests(unittest.TestCase):
    def write_log(self, path, lines):
        Path(path).write_text('\n'.join(lines) + '\n')

    def test_byte_exact_pass(self):
        marker = ext_adv_run.fixture_marker()
        log = self.__class__.__name__ + '-pass.txt'
        self.write_log(log, [noise_report(), marker_report(marker),
                             noise_report(), marker_report(marker),
                             summary(40, 2)])
        errors, detail = ext_adv_run.read_ext_logcat(log, 'x2-ext-adv')
        self.assertEqual(errors, [])
        self.assertEqual(detail['byte_exact'], 2)
        Path(log).unlink()

    def test_truncated_record_is_reported(self):
        marker = ext_adv_run.fixture_marker()[:31]
        log = self.__class__.__name__ + '-trunc.txt'
        self.write_log(log, [marker_report(marker), summary(40, 1)])
        errors, _ = ext_adv_run.read_ext_logcat(log, 'x2-ext-adv')
        self.assertTrue(any('truncated' in error for error in errors), errors)
        Path(log).unlink()

    def test_marker_with_wrong_payload_is_reported(self):
        marker = bytearray(ext_adv_run.fixture_marker())
        marker[30] ^= 0xff
        log = self.__class__.__name__ + '-wrong.txt'
        self.write_log(log, [marker_report(bytes(marker)), summary(40, 1)])
        errors, _ = ext_adv_run.read_ext_logcat(log, 'x2-ext-adv')
        self.assertTrue(any('differ from the fixture' in error for error in errors), errors)
        Path(log).unlink()

    def test_missing_summary_and_empty_window(self):
        log = self.__class__.__name__ + '-empty.txt'
        self.write_log(log, [noise_report()])
        errors, _ = ext_adv_run.read_ext_logcat(log, 'x2-ext-adv')
        self.assertTrue(any('ext_summary' in error for error in errors), errors)
        self.write_log(log, [summary(0, 0)])
        errors, _ = ext_adv_run.read_ext_logcat(log, 'x2-ext-adv')
        self.assertTrue(any('no extended advertisements' in error for error in errors), errors)
        self.assertTrue(any('never matched the marker head' in error for error in errors), errors)
        Path(log).unlink()

    def test_two_m_round_requires_secondary_phy_2(self):
        marker = ext_adv_run.fixture_marker()
        log = self.__class__.__name__ + '-2m.txt'
        self.write_log(log, [marker_report(marker, secondary_phy=1),
                             summary(40, 1)])
        errors, _ = ext_adv_run.read_ext_logcat(log, 'x2-ext-adv-2m')
        self.assertTrue(any('secondary PHY 2M' in error for error in errors), errors)
        self.write_log(log, [marker_report(marker, secondary_phy=2),
                             summary(40, 1)])
        errors, _ = ext_adv_run.read_ext_logcat(log, 'x2-ext-adv-2m')
        self.assertFalse(any('secondary PHY' in error for error in errors), errors)
        Path(log).unlink()


class SymbolTests(unittest.TestCase):
    def test_observation_symbols_parse_and_reject(self):
        text = ('20000000 B STATS\n'
                '20000100 B HOST_STATS\n'
                '20000400 B TRACE\n'
                '20007538 B EXT_ADV_STATS\n'
                '00000400 D RUN_SECONDS\n')
        symbols = ext_adv_run.observation_symbols(text)
        self.assertEqual(symbols['EXT_ADV_STATS'], 0x20007538)
        with self.assertRaises(ValueError):
            ext_adv_run.observation_symbols(text.replace('EXT_ADV_STATS', 'GONE'))
        with self.assertRaises(ValueError):
            ext_adv_run.observation_symbols(text + '20007600 B EXT_ADV_STATS\n')


if __name__ == '__main__':
    unittest.main()
