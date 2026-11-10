#!/usr/bin/env python3
"""Offline checks for the O2 runner's decoders, gates and invariants."""
import importlib.util
import unittest
from pathlib import Path

RUN = Path(__file__).resolve().parent / 'run.py'
spec = importlib.util.spec_from_file_location('ch585_active_scanner_runner', RUN)
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

ADV_A = bytes([0xB5, 0x45, 0xB0, 0xF3, 0x89, 0xC8])


def manufacturer(marker):
    return bytes([1 + len(marker), 0xFF]) + marker


def good_stats():
    stats = [0] * 64
    stats[0] = run.MAGIC
    stats[1] = 1
    stats[2] = 3
    stats[3] = 30_000_000
    stats[6] = 100
    stats[8] = 90
    stats[9] = 10
    stats[10] = 80
    stats[11] = 10
    stats[12] = 2
    stats[13] = 78
    stats[14:22] = [50, 10, 15, 1, 1, 0, 0, 1]
    stats[22] = 20
    stats[23] = 20
    stats[26] = 20
    stats[27] = 20
    stats[30] = 20
    stats[32] = 18
    stats[33] = 2
    stats[34] = 15
    stats[35] = 3
    stats[36] = 12
    stats[37] = 1
    stats[38] = 1
    stats[39] = 1
    stats[41:44] = [30, 30, 30]
    stats[53] = 40
    stats[58] = 0x30000
    stats[59] = 48_000_000
    stats[60] = 1
    stats[61] = 114
    stats[62] = 0b111
    stats[63] = 0b111
    return stats


def words_for(pdu_type, payload, channel=37):
    raw = bytes([pdu_type, len(payload)]) + payload
    meta = (channel | (len(payload) << 8) | (1 << 16) | (pdu_type << 17)
            | (1 << 21) | (1 << 24))
    words = [1000, meta, 0xC4] + [0] * 10
    padded = raw.ljust(40, b'\0')
    for i in range(10):
        words[3 + i] = int.from_bytes(padded[i * 4:i * 4 + 4], 'little')
    return words


def adv_rows(marker=run.MARKER_ADV, pdu_type=0x06, channel=37):
    payload = ADV_A + manufacturer(marker)
    return run.decode_rows(words_for(pdu_type, payload, channel), 1)


def rsp_rows(marker=run.MARKER_RSP, adv_a=ADV_A, pdu_type=0x04, channel=37):
    payload = adv_a + manufacturer(marker)
    return run.decode_rows(words_for(pdu_type, payload, channel), 1)


class DecodeTests(unittest.TestCase):
    def test_rows_require_valid_bit(self):
        words = words_for(0x06, ADV_A + manufacturer(run.MARKER_ADV)) + [0] * run.ROW_WORDS
        rows = run.decode_rows(words, 2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['channel'], 37)
        self.assertEqual(rows[0]['pdu_type'], 0x06)
        self.assertEqual(rows[0]['adv_a'], ADV_A.hex())

    def test_truncated_row_is_cut_to_length(self):
        rows = adv_rows()
        self.assertEqual(len(bytes.fromhex(rows[0]['raw'])), rows[0]['length'] + 2)


class PositiveGateTests(unittest.TestCase):
    def test_positive_passes(self):
        self.assertEqual(
            run.evaluate_positive(good_stats(), adv_rows(), rsp_rows(), 30), [])

    def test_positive_rejects_few_advertisements(self):
        stats = good_stats()
        stats[23] = 2
        stats[26] = 2
        stats[27] = 2
        stats[30] = 2
        stats[32] = 2
        stats[34] = 1
        stats[36] = 1
        stats[37] = 0
        stats[38] = 0
        stats[39] = 0
        self.assertTrue(run.evaluate_positive(stats, adv_rows(), rsp_rows(), 30))

    def test_positive_rejects_late_request(self):
        stats = good_stats()
        stats[28] = 1
        self.assertTrue(run.evaluate_positive(stats, adv_rows(), rsp_rows(), 30))

    def test_positive_rejects_attempt_mismatch(self):
        stats = good_stats()
        stats[26] += 1
        self.assertTrue(run.evaluate_positive(stats, adv_rows(), rsp_rows(), 30))

    def test_positive_rejects_missing_channel(self):
        stats = good_stats()
        stats[63] = 0b011
        errors = run.evaluate_positive(stats, adv_rows(), rsp_rows(), 30)
        self.assertTrue(any('37/38/39' in error for error in errors))

    def test_positive_rejects_adv_marker_in_response(self):
        rows = rsp_rows(marker=run.MARKER_ADV)
        errors = run.evaluate_positive(good_stats(), adv_rows(), rows, 30)
        self.assertTrue(any('O2RSP' in error for error in errors))

    def test_positive_rejects_response_from_other_address(self):
        rows = rsp_rows(adv_a=bytes([1, 2, 3, 4, 5, 6]))
        errors = run.evaluate_positive(good_stats(), adv_rows(), rows, 30)
        self.assertTrue(any('AdvA' in error for error in errors))

    def test_positive_rejects_non_scannable_adv_row(self):
        rows = adv_rows(pdu_type=0x02)
        errors = run.evaluate_positive(good_stats(), rows, rsp_rows(), 30)
        self.assertTrue(any('not scannable' in error for error in errors))


class CommonInvariantTests(unittest.TestCase):
    def test_window_invariant(self):
        stats = good_stats()
        stats[6] += 1
        self.assertTrue(any('window/completion' in e for e in run.common_errors(stats, 30)))

    def test_response_classification_invariant(self):
        stats = good_stats()
        stats[39] += 1
        self.assertTrue(any('response classification' in e
                            for e in run.common_errors(stats, 30)))

    def test_embedding_gates(self):
        stats = good_stats()
        stats[60] = 0
        self.assertTrue(any('target-src' in e for e in run.common_errors(stats, 30)))
        stats = good_stats()
        stats[61] = 150
        self.assertTrue(any('offset' in e for e in run.common_errors(stats, 30)))


class NegativeGateTests(unittest.TestCase):
    def nonconn_stats(self):
        stats = good_stats()
        stats[14:22] = [36, 0, 40, 1, 1, 0, 0, 0]
        stats[22] = 20
        stats[23] = 0
        stats[24] = 20
        stats[26] = 0
        stats[27] = 0
        stats[30] = 0
        stats[32] = 0
        stats[33] = 0
        stats[34] = 0
        stats[35] = 0
        stats[36] = 0
        stats[37] = 0
        stats[38] = 0
        stats[39] = 0
        stats[62] = 0
        stats[63] = 0
        return stats

    def test_nonconn_passes(self):
        self.assertEqual(
            run.evaluate_negative_nonconn(self.nonconn_stats(), 30), [])

    def test_nonconn_rejects_request(self):
        stats = self.nonconn_stats()
        stats[26] = 1
        stats[27] = 1
        self.assertTrue(run.evaluate_negative_nonconn(stats, 30))

    def test_nonconn_rejects_missing_marker(self):
        stats = self.nonconn_stats()
        stats[24] = 0
        stats[22] = 0
        self.assertTrue(run.evaluate_negative_nonconn(stats, 30))

    def wrong_stats(self):
        stats = good_stats()
        stats[22] = 0
        stats[23] = 0
        stats[25] = 20
        stats[26] = 0
        stats[27] = 0
        stats[30] = 0
        stats[32] = 0
        stats[33] = 0
        stats[34] = 0
        stats[35] = 0
        stats[36] = 0
        stats[37] = 0
        stats[38] = 0
        stats[39] = 0
        stats[62] = 0
        stats[63] = 0
        return stats

    def test_wrong_marker_passes(self):
        self.assertEqual(
            run.evaluate_negative_marker(self.wrong_stats(), 30), [])

    def test_wrong_marker_rejects_expected_marker(self):
        stats = self.wrong_stats()
        stats[22] = 1
        stats[23] = 1
        self.assertTrue(run.evaluate_negative_marker(stats, 30))

    def nosource_stats(self):
        stats = good_stats()
        stats[14] = 50
        stats[15] = 5
        stats[16] = 20
        stats[17] = 1
        stats[22] = 0
        stats[23] = 0
        stats[24] = 0
        stats[25] = 0
        stats[26] = 0
        stats[27] = 0
        stats[30] = 0
        stats[32] = 0
        stats[33] = 0
        stats[34] = 0
        stats[35] = 0
        stats[36] = 0
        stats[37] = 0
        stats[38] = 0
        stats[39] = 0
        stats[62] = 0
        stats[63] = 0
        return stats

    def test_nosource_passes(self):
        self.assertEqual(
            run.evaluate_negative_nosource(self.nosource_stats(), 30), [])

    def test_nosource_requires_liveness(self):
        stats = self.nosource_stats()
        stats[10] = 0
        stats[11] = 90
        stats[12] = 0
        stats[13] = 0
        stats[14:22] = [0] * 8
        self.assertTrue(any('liveness' in e
                            for e in run.evaluate_negative_nosource(stats, 30)))


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
