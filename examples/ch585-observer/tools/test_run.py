#!/usr/bin/env python3
"""Offline checks for the Observer runner's gates and decoders."""
import importlib.util
import unittest
from pathlib import Path

RUN = Path(__file__).resolve().parent / 'run.py'
spec = importlib.util.spec_from_file_location('ch585_observer_runner', RUN)
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


def good_stats():
    stats = [0] * 48
    stats[0] = run.MAGIC
    stats[1] = 1
    stats[2] = 3
    stats[3] = 30_000_000
    stats[6] = 100
    stats[8] = 90
    stats[9] = 10
    stats[12] = 80
    stats[13] = 10
    stats[14] = 2
    stats[17], stats[18], stats[19] = 30, 30, 30
    stats[20], stats[21], stats[22] = 27, 26, 27
    stats[23] = 60            # ADV_IND
    stats[26] = 18            # SCAN_RSP
    stats[32] = 50            # named
    stats[33] = 7             # matches
    stats[34] = 78            # samples == parsed PDUs
    stats[35] = 78 - run.SAMPLE_ROWS
    stats[36] = 7             # match ring count
    stats[42] = 0
    stats[43] = 0x30000
    stats[45] = 1
    return stats


def row(ad_type, value, channel=37, length=None, valid=True):
    payload = bytes([1, 2, 3, 4, 5, 6]) + bytes([len(value) + 1, ad_type]) + value
    raw = bytes([0x00, len(payload)]) + payload
    length = len(raw) - 2 if length is None else length
    meta = channel | (length << 8) | (1 << 16) | (0 << 17)
    if valid:
        meta |= 1 << 24
    words = [1000, meta, 0xC4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    padded = raw.ljust(40, b'\0')
    for i in range(10):
        words[3 + i] = int.from_bytes(padded[i * 4:i * 4 + 4], 'little')
    return words


def good_row():
    payload = bytes([1, 2, 3, 4, 5, 6])
    payload += bytes([len(run.NAME.encode()) + 1, 0x09]) + run.NAME.encode()
    payload += bytes([len(run.MANUFACTURER) + 1, 0xFF]) + run.MANUFACTURER
    raw = bytes([0x00, len(payload)]) + payload
    length = len(raw) - 2
    meta = 37 | (length << 8) | (1 << 16) | (1 << 24)
    words = [1000, meta, 0xC4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    padded = raw.ljust(40, b'\0')
    for i in range(10):
        words[3 + i] = int.from_bytes(padded[i * 4:i * 4 + 4], 'little')
    return words


class DecodeTests(unittest.TestCase):
    def test_rows_require_valid_bit(self):
        words = row(0x09, b'x') + [0] * run.ROW_WORDS
        decoded = run.decode_rows(words, 2)
        self.assertEqual(len(decoded), 1)
        self.assertEqual(decoded[0]['channel'], 37)
        self.assertTrue(decoded[0]['crc_ok'])

    def test_ad_elements_and_name_match(self):
        decoded = run.decode_rows(good_row(), 1)[0]
        raw = bytes.fromhex(decoded['raw'])
        self.assertEqual(run.ad_elements(raw)[0], (0x09, run.NAME.encode()))
        self.assertTrue(run.row_has_name(decoded))
        self.assertTrue(run.row_has_manufacturer(decoded))

    def test_truncated_ad_data_is_ignored(self):
        payload = bytes([1, 2, 3, 4, 5, 6]) + bytes([9, 0x09, 1, 2])
        raw = bytes([0x00, len(payload)]) + payload
        self.assertEqual(run.ad_elements(raw), [])


class GateTests(unittest.TestCase):
    def test_positive_passes(self):
        stats = good_stats()
        rows = run.decode_rows(good_row(), 1)
        self.assertEqual(run.evaluate_positive(stats, rows, 30), [])

    def test_positive_rejects_few_matches(self):
        stats = good_stats()
        stats[33] = 2
        stats[36] = 2
        self.assertTrue(run.evaluate_positive(stats, [], 30))

    def test_positive_rejects_stop_failure(self):
        stats = good_stats()
        stats[16] = 1
        self.assertTrue(run.evaluate_positive(stats, run.decode_rows(good_row(), 1), 30))

    def test_positive_rejects_bad_runtime(self):
        stats = good_stats()
        stats[3] = 1_000_000
        self.assertTrue(run.evaluate_positive(stats, run.decode_rows(good_row(), 1), 30))

    def test_positive_rejects_inconsistent_counts(self):
        stats = good_stats()
        stats[8] += 1
        self.assertTrue(run.evaluate_positive(stats, run.decode_rows(good_row(), 1), 30))

    def test_positive_rejects_missing_controlled_name(self):
        stats = good_stats()
        rows = run.decode_rows(row(0x09, b'some-other-name'), 1)
        errors = run.evaluate_positive(stats, rows, 30)
        self.assertTrue(any('local name' in error for error in errors))

    def test_positive_accepts_name_without_manufacturer_data(self):
        # macOS CoreBluetooth advertises the local name but drops manufacturer data.
        stats = good_stats()
        rows = run.decode_rows(row(0x09, run.NAME.encode()), 1)
        self.assertEqual(run.evaluate_positive(stats, rows, 30), [])

    def test_negative_passes_without_matches(self):
        stats = good_stats()
        stats[33] = 0
        stats[36] = 0
        self.assertEqual(run.evaluate_negative(stats, []), [])

    def test_negative_rejects_matches(self):
        stats = good_stats()
        self.assertTrue(run.evaluate_negative(stats, run.decode_rows(good_row(), 1)))


class SymbolTests(unittest.TestCase):
    def test_symbols_from_requires_all(self):
        lines = '\n'.join(f'{0x20000000 + i:08x} B {name}'
                          for i, name in enumerate(run.SYMBOLS))
        symbols = run.symbols_from(lines)
        self.assertEqual(set(symbols), set(run.SYMBOLS))
        with self.assertRaises(ValueError):
            run.symbols_from(lines.rsplit('\n', 1)[0])


if __name__ == '__main__':
    unittest.main()
