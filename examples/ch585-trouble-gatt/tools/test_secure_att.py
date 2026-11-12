#!/usr/bin/env python3
"""Offline tests for the X4 `att` phase gates; no hardware access."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


secure = load('x4_secure_run_test', HERE / 'secure_run.py')


def transcript(notifications=7):
    rows = [
        {'event': 'mode', 'mode': 'att'},
        {'event': 'scan_started'},
        {'event': 'found'},
        {'event': 'connecting'},
        {'event': 'connection_state', 'status': 0, 'state': 2},
        {'event': 'mtu_requested', 'ok': True},
        {'event': 'mtu', 'status': 0, 'mtu': 124},
        {'event': 'services_discovered', 'status': 0, 'service': True,
         'bulk': True, 'burst': True, 'control': True},
        {'event': 'att_start', 'mtu': 124},
        {'event': 'bulk_read', 'status': 0, 'length': 200, 'pattern_ok': True},
        {'event': 'bulk_write_requested', 'ok': True, 'length': 200},
        {'event': 'bulk_write_ack', 'status': 0},
        {'event': 'bulk_verify', 'status': 0, 'length': 200, 'match': True},
        {'event': 'burst_cccd_requested'},
        {'event': 'burst_cccd', 'status': 0},
        {'event': 'burst_requested', 'ok': True, 'attempts': 12},
        {'event': 'burst_command_ack', 'status': 0},
    ]
    for index in range(notifications):
        rows.append({'event': 'burst_notification', 'index': index + 1,
                     'length': 121, 'pattern_ok': True})
    rows.append({'event': 'summary', 'pass': True, 'reason': 'att_mtu_long_burst_ok',
                 'bonded': True, 'mtu': 124, 'notifications': notifications})
    return rows


def x4_words(**values):
    words = {name: 0 for name in secure.X4_NAMES}
    words.update({'magic': secure.X4_MAGIC, 'version': 1, 'mtu': 124,
                  'bulk_reads': 2, 'bulk_writes': 1, 'bulk_len': 200,
                  'bulk_sum': secure.BULK_WRITE_SUM, 'bulk_match': 1,
                  'burst_runs': 1, 'burst_attempts': secure.BURST_ATTEMPTS,
                  'burst_sent': 7, 'burst_queue_full': 5, 'burst_len': 121})
    words.update(values)
    return [words[name] for name in secure.X4_NAMES]


def opcodes(**values):
    att = {'rx': {'MtuReq': 1, 'ReadReq': 2, 'ReadBlobReq': 2,
                  'PrepareWriteReq': 2, 'ExecuteWriteReq': 1},
           'tx': {'MtuRsp': 1, 'ReadBlobRsp': 2, 'PrepareWriteRsp': 2,
                  'ExecuteWriteRsp': 1, 'Notification': 7}}
    for name, count in values.items():
        side = 'rx' if name.endswith('Req') else 'tx'
        att[side][name] = count
    return {'att': att}


class TranscriptTests(unittest.TestCase):
    def test_success(self):
        self.assertEqual(secure.evaluate_att_transcript(transcript()), [])

    def test_mtu_must_be_negotiated(self):
        rows = transcript()
        rows[6]['status'] = 1
        self.assertTrue(any('MTU' in error
                            for error in secure.evaluate_att_transcript(rows)))

    def test_long_read_pattern_is_required(self):
        rows = transcript()
        rows[9]['length'] = 22
        self.assertTrue(any('long read' in error
                            for error in secure.evaluate_att_transcript(rows)))

    def test_long_write_readback_is_required(self):
        rows = transcript()
        rows[12]['match'] = False
        self.assertTrue(any('read-back' in error
                            for error in secure.evaluate_att_transcript(rows)))

    def test_burst_notification_is_required(self):
        rows = [row for row in transcript(notifications=0)
                if row.get('event') != 'burst_notification']
        self.assertTrue(any('burst notification' in error
                            for error in secure.evaluate_att_transcript(rows)))

    def test_summary_must_pass(self):
        rows = transcript()
        rows[-1]['pass'] = False
        self.assertTrue(any('summary is not a pass' in error
                            for error in secure.evaluate_att_transcript(rows)))

    def test_event_order_marker_is_required(self):
        rows = [row for row in transcript() if row.get('event') != 'bulk_write_ack']
        self.assertTrue(any('bulk_write_ack' in error
                            for error in secure.evaluate_att_transcript(rows)))


class FirmwareTests(unittest.TestCase):
    def evaluate(self, **overrides):
        return secure.evaluate_att(x4_words(**overrides), opcodes(), 7)

    def test_success(self):
        self.assertEqual(self.evaluate(), [])

    def test_missing_blob_evidence(self):
        opcodes_missing = opcodes(ReadBlobReq=0)
        errors = secure.evaluate_att(x4_words(), opcodes_missing, 7)
        self.assertTrue(any('ReadBlobReq' in error for error in errors))

    def test_write_bytes_are_checked(self):
        errors = self.evaluate(bulk_sum=secure.BULK_WRITE_SUM + 1)
        self.assertTrue(any('checksum' in error for error in errors))
        errors = self.evaluate(bulk_match=0)
        self.assertTrue(any('write pattern' in error for error in errors))

    def test_burst_queue_must_fill(self):
        errors = self.evaluate(burst_queue_full=0)
        self.assertTrue(any('full notification queue' in error for error in errors))

    def test_delivery_must_match_what_was_queued(self):
        errors = secure.evaluate_att(x4_words(), opcodes(), 6)
        self.assertTrue(any('received 6' in error for error in errors))

    def test_mtu_must_be_above_23(self):
        errors = self.evaluate(mtu=23)
        self.assertTrue(any('MTU' in error for error in errors))

    def test_invalid_magic_is_fatal(self):
        errors = secure.evaluate_att([0] * 16, opcodes(), 7)
        self.assertEqual(len(errors), 1)
        self.assertIn('X4_STATS', errors[0])


class RefusedPduTests(unittest.TestCase):
    def test_clean_run_has_no_refused_pdus(self):
        self.assertEqual(secure.evaluate_att(x4_words(), opcodes(), 7, 0), [])

    def test_refused_payload_fails_the_run(self):
        sample = 1 | (0x12 << 8) | (28 << 16)
        errors = secure.evaluate_att(x4_words(), opcodes(), 7, sample)
        self.assertTrue(any('refused an on-air PDU' in error for error in errors))

    def test_first_refusal_sample_is_decoded(self):
        self.assertIsNone(secure.decode_refused_pdu(0))
        self.assertEqual(
            secure.decode_refused_pdu(1 | (0x12 << 8) | (28 << 16)),
            {'header': '0x12', 'llid': 2, 'length': 28})


if __name__ == '__main__':
    unittest.main()
