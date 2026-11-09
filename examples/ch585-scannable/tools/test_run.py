"""Runner must reject partial success even when the scanner sees a name."""
import unittest
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


if __name__ == '__main__':
    unittest.main()
