"""Evidence integrity checks; never connects to a target."""
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import read_trace as reader


class CaptureTests(unittest.TestCase):
    def header(self, count=4):
        obs = [0] * 20
        obs[:2] = [0x52584f31, 2]
        obs[2], obs[4], obs[12] = 11, 1, count
        return obs

    def test_stage_marker_alone_cannot_certify_complete_capture(self):
        obs = self.header(0)
        self.assertFalse(reader.complete_trace(obs, reader.decode(obs, [])))

    def test_shutdown_checkpoints_and_order_required(self):
        obs = self.header()
        words = sum(([i * 100, phase] + [0] * 10
                     for i, phase in enumerate([2, 3, 4, 5])), [])
        rows = reader.decode(obs, words)
        self.assertTrue(reader.complete_trace(obs, rows))
        rows[-1]['phase'] = 4
        self.assertFalse(reader.complete_trace(obs, rows))
        rows[-1]['phase'], rows[-1]['elapsed_us'] = 5, 0
        self.assertFalse(reader.complete_trace(obs, rows))

    def test_corrupt_size_and_version_rejected(self):
        for obs, words in [(self.header(), [0] * 47),
                           (self.header(65), []), ([0] * 20, [])]:
            with self.assertRaises(ValueError):
                reader.decode(obs, words)

    def test_partial_read_preserved_after_probe_error(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / 'obs.bin'
            def failed(command, **kwargs):
                dest.write_bytes(b'partial')
                kwargs['stdout'].write('transport failed\n')
                return subprocess.CompletedProcess(command, 1)
            with patch.object(reader.subprocess, 'run', side_effect=failed):
                with self.assertRaises(ValueError):
                    reader.read_words(0x20000000, 20, dest)
            self.assertEqual(dest.read_bytes(), b'partial')
            self.assertIn('transport failed', dest.with_suffix('.log').read_text())
            meta = json.loads(dest.with_suffix('.command.json').read_text())
            self.assertEqual(meta['returncode'], 1)
            self.assertIn(reader.PROBE, meta['command'])

    def test_timeout_preserves_diagnostics(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / 'obs.bin'
            with patch.object(reader.subprocess, 'run',
                              side_effect=subprocess.TimeoutExpired('probe-rs', 30)):
                with self.assertRaises(subprocess.TimeoutExpired):
                    reader.read_words(0x20000000, 20, dest)
            self.assertIn('state unknown', dest.with_suffix('.command.json').read_text())

    def test_short_successful_read_is_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / 'obs.bin'
            def short(command, **kwargs):
                dest.write_bytes(struct.pack('<I', 1))
                return subprocess.CompletedProcess(command, 0)
            with patch.object(reader.subprocess, 'run', side_effect=short):
                with self.assertRaises(ValueError):
                    reader.read_words(0x20000000, 20, dest)
            self.assertTrue(dest.exists())


if __name__ == '__main__':
    unittest.main()
