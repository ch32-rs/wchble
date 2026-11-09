"""Runner must reject partial success even when the scanner sees a name."""
from pathlib import Path
import unittest
from unittest.mock import patch
import run as runner


class ResultTests(unittest.TestCase):
    def good(self):
        obs = [0] * 32
        obs[:3] = [0x50323538, 1, 9]
        obs[3] = obs[4] = 10
        obs[11] = obs[12] = 3
        obs[27] = 0x30000
        return obs

    def test_success_with_unrelated_bad_crc_packets(self):
        obs = self.good()
        obs[9], obs[10] = 2, 4
        self.assertEqual(runner.evaluate_stats(obs, 0), [])

    def test_a_seen_name_cannot_hide_lost_or_late_responses(self):
        for index, value in [(12, 2), (18, 1), (19, 1), (5, 1), (15, 1)]:
            with self.subTest(index=index):
                obs = self.good()
                obs[index] = value
                self.assertTrue(runner.evaluate_stats(obs, 0))

    def test_no_requests_or_scan_failure_is_not_success(self):
        obs = self.good()
        obs[11] = obs[12] = 0
        self.assertTrue(runner.evaluate_stats(obs, 0))
        self.assertTrue(runner.evaluate_stats(self.good(), 1))

    def test_stopped_hardware_and_finished_firmware_required(self):
        for index, value in [(0, 0), (2, 4), (14, 1), (26, 1), (27, 0x30158)]:
            with self.subTest(index=index):
                obs = self.good()
                obs[index] = value
                self.assertTrue(runner.evaluate_stats(obs, 0))


class IdleTests(unittest.TestCase):
    def check_idle(self, initial, confirmations):
        reads = [[value] for value in [initial, 0x30710, 0x300, 0xffffffff, *confirmations]]
        with patch.object(runner, 'read32', side_effect=reads) as read, \
                patch.object(runner, 'write32') as write, \
                patch.object(runner.time, 'sleep') as sleep:
            if any(value & 3 for value in confirmations):
                with self.assertRaisesRegex(RuntimeError, 'refusing flash'):
                    runner.idle(Path('/unused'), 'test')
            else:
                runner.idle(Path('/unused'), 'test')
                self.assertEqual(read.call_count, 6)
                self.assertEqual(sleep.call_count, 2)
            self.assertEqual(write.call_count, 6)
            self.assertEqual(write.call_args_list[2].args[:2], (0x4000c200, initial | 8))
            self.assertEqual(write.call_args_list[-1].args[:2], (0x4000c250, 0x30000))
            return read.call_count

    def test_initial_zero_still_requires_explicit_shut(self):
        self.check_idle(0, [0, 0])

    def test_active_engine_requires_shut_and_two_idle_acknowledgements(self):
        self.check_idle(2, [0, 0])

    def test_first_active_confirmation_refuses_without_retry(self):
        self.assertEqual(self.check_idle(0, [2]), 5)

    def test_second_active_confirmation_refuses_without_retry(self):
        self.assertEqual(self.check_idle(0, [0, 2]), 6)


if __name__ == '__main__':
    unittest.main()
