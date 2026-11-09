#!/usr/bin/env python3
"""Offline capture tests; no serial, Bluetooth, probe or hardware commands."""
import argparse
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

_spec = importlib.util.spec_from_file_location('p4_capture', Path(__file__).with_name('capture.py'))
capture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture)


def pcap(payload=b'abc'):
    return (b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65535, 272)
            + struct.pack('<IIII', 1, 0, len(payload), len(payload)) + payload)


def row(number, **values):
    result = dict.fromkeys(capture.FIELDS, '')
    result.update({'frame.number': str(number), 'nordic_ble.crcok': 'True'})
    result.update(values)
    return result


def good_rows(cycles=1):
    rows = []
    for cycle in range(cycles):
        aa = f'0x506540{cycle:02x}'
        rows.append(row(len(rows) + 1, **{'btle.advertising_header.pdu_type': '0x05',
                          'btle.advertising_address': capture.TARGET,
                          'btle.link_layer_data.access_address': aa}))
        for opcode, count, direction in (('0x0a', 5, 'True'), ('0x0b', 5, 'False'),
                                        ('0x12', 13, 'True'), ('0x13', 13, 'False')):
            for _ in range(count):
                rows.append(row(len(rows) + 1, **{'btle.access_address': aa,
                                'nordic_ble.direction': direction, 'btatt.opcode': opcode}))
        for value in range(101, 111):
            rows.append(row(len(rows) + 1, **{'btle.access_address': aa,
                            'nordic_ble.direction': 'False', 'btatt.opcode': '0x1b',
                            'btatt.value': value.to_bytes(4, 'little').hex()}))
    return rows


class CaptureTests(unittest.TestCase):
    def test_structural_pcap_and_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            path.write_bytes(pcap())
            self.assertEqual(capture.validate_pcap(path)['records'], 1)
            for image in (b'', pcap()[:23], pcap()[:-1], pcap() + b'\0'):
                path.write_bytes(image)
                with self.subTest(image=image), self.assertRaises(ValueError):
                    capture.validate_pcap(path)
            image = bytearray(pcap())
            struct.pack_into('<I', image, 20, 1)
            path.write_bytes(image)
            with self.assertRaises(ValueError):
                capture.validate_pcap(path)

    def test_nordic_big_endian_pcap_dlt_not_wireshark_internal_encapsulation(self):
        image = (b'\xa1\xb2\xc3\xd4' + struct.pack('>HHIIII', 2, 4, 0, 0, 65535, 272)
                 + struct.pack('>IIII', 1, 0, 3, 3) + b'abc')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'
            path.write_bytes(image)
            self.assertEqual(capture.validate_pcap(path)['records'], 1)
            wrong = bytearray(image)
            struct.pack_into('>I', wrong, 20, 186)
            path.write_bytes(wrong)
            with self.assertRaises(ValueError):
                capture.validate_pcap(path)

    def test_complete_each_link_and_retransmitted_notifications(self):
        for cycles in (1, 3):
            rows = good_rows(cycles)
            rows.insert(46, dict(rows[45]))
            self.assertTrue(capture.analyze_rows(rows, cycles)['passed'])

    def test_bad_connect_is_not_follow_evidence(self):
        rows = good_rows()
        rows[0]['nordic_ble.crcok'] = 'False'
        result = capture.analyze_rows(rows, 1)
        self.assertFalse(result['passed'])
        self.assertEqual(result['bad_crc_connects'], 1)
        self.assertEqual(result['links'], [])

    def test_advertising_or_connect_alone_does_not_pass(self):
        for rows in ([], good_rows()[:1]):
            self.assertFalse(capture.analyze_rows(rows, 1)['passed'])
        rows = good_rows()
        for packet in rows[1:]:
            packet['nordic_ble.direction'] = 'True'
        self.assertFalse(capture.analyze_rows(rows, 1)['passed'])

    def test_missing_corrupt_wrong_and_extra_link_fail(self):
        for key, value in (('btatt.opcode', ''), ('btle.access_address', '0x12345678'),
                           ('nordic_ble.crcok', 'False'), ('btatt.value', 'ff')):
            rows = good_rows()
            rows[-1][key] = value
            with self.subTest(key=key):
                self.assertFalse(capture.analyze_rows(rows, 1)['passed'])
        self.assertFalse(capture.analyze_rows(good_rows(2), 1)['passed'])
        self.assertFalse(capture.analyze_rows(good_rows(1), 3)['passed'])

    def test_shutdown_clean_interrupt(self):
        process = Mock(pid=123, returncode=0)
        process.poll.return_value = None
        with patch.object(capture.os, 'killpg') as kill:
            result = capture.stop_capture(process)
        self.assertTrue(result['clean'])
        kill.assert_called_once_with(123, signal.SIGINT)
        process.wait.assert_called_once_with(timeout=5)

    def test_term_or_kill_are_not_clean_even_with_valid_pcap(self):
        for timeouts, code in ((1, -15), (2, -9)):
            process = Mock(pid=123, returncode=code)
            process.poll.return_value = None
            process.wait.side_effect = ([subprocess.TimeoutExpired('sniffer', 5)] * timeouts + [code])
            with patch.object(capture.os, 'killpg'):
                result = capture.stop_capture(process)
            self.assertFalse(result['clean'])
            self.assertEqual(len(result['actions']), timeouts + 1)

    def test_shutdown_is_bounded_and_no_process_wide_kill(self):
        process = Mock(pid=456)
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired('sniffer', 2)
        with patch.object(capture.os, 'killpg') as kill, self.assertRaises(RuntimeError):
            capture.stop_capture(process)
        self.assertEqual(kill.call_count, 3)
        self.assertTrue(all(call.args[0] == 456 for call in kill.call_args_list))
        self.assertEqual([call.kwargs['timeout'] for call in process.wait.call_args_list], [5, 2, 2])

    def test_startup_is_configuration_not_claimed_follow(self):
        process = Mock()
        process.poll.return_value = None
        log = Mock()
        log.read_text.return_value = 'Firmware version 4.1.1\nSending follow request to follow device'
        capture.await_initialized(process, log, 1)
        process.poll.return_value = 1
        with self.assertRaises(RuntimeError):
            capture.await_initialized(process, log, 1)
        process.poll.return_value = None
        with patch.object(capture.time, 'monotonic', side_effect=[0, 2]), self.assertRaises(RuntimeError):
            capture.await_initialized(process, log, 1)

    def test_name_startup_waits_for_scanning_not_an_unflashed_device(self):
        process = Mock()
        process.poll.return_value = None
        log = Mock()
        log.read_text.return_value = 'Firmware version 4.1.1\nSending scan packet'
        capture.await_initialized(process, log, 1, follow_by_name=True)
        with patch.object(capture.time, 'monotonic', side_effect=[0, 2]), self.assertRaises(RuntimeError):
            capture.await_initialized(process, log, 1)

    def test_child_signal_defaults_are_explicit(self):
        with patch.object(capture.signal, 'signal') as handler:
            capture.reset_child_signals()
        self.assertEqual([call.args for call in handler.call_args_list],
                         [(signal.SIGINT, signal.SIG_DFL), (signal.SIGTERM, signal.SIG_DFL)])

    def test_option_passthrough_and_serial_timeout(self):
        options, run = capture.options(['--sniffer', '/tmp/sniffer', '--sniffer-port', '/dev/test',
                                       '--nrfutil-home', '/tmp/state', '--out', '/tmp/evidence',
                                       '--cycles', '3', '--run-seconds', '25', '--timeout', '20'])
        self.assertEqual(options.serial_timeout_ms, 100)
        self.assertEqual((run.cycles, run.run_seconds, run.timeout), (3, 25, 20))

    def run_mocked(self, directory, runner_code=0, runner_error=None, shutdown_clean=True,
                   startup_error=None, follow_by_name=False):
        out = Path(directory) / 'evidence'
        image = Path(directory) / 'image.elf'
        image.write_bytes(b'fake image')
        options = argparse.Namespace(sniffer=image, sniffer_port='/dev/test',
                                     sniffer_serial='serial', nrfutil_home=Path('/tmp/state'),
                                     serial_timeout_ms=100, startup_timeout=1, tshark='tshark',
                                     follow_by_name=follow_by_name)
        args = argparse.Namespace(out=out, elf=image, nm='nm', run_seconds=25, cycles=3, timeout=20)
        process = Mock(pid=1)
        process.poll.return_value = None
        with ExitStack() as stack:
            mocks = {}
            for name, value in (('observation_symbols', {'RUN_SECONDS': 0}), ('validate_ram_layout', {}),
                                ('embedded_u32', 25), ('execute', runner_code)):
                mocks[name] = stack.enter_context(patch.object(capture.runner, name, return_value=value))
            if runner_error:
                mocks['execute'].side_effect = runner_error
            stack.enter_context(patch.object(capture.subprocess, 'check_output', return_value='revision'))
            popen = stack.enter_context(patch.object(capture.subprocess, 'Popen', return_value=process))
            startup = stack.enter_context(patch.object(capture, 'await_initialized', side_effect=startup_error))
            stop = stack.enter_context(patch.object(capture, 'stop_capture',
                                                   return_value={'clean': shutdown_clean, 'exit': 0}))
            stack.enter_context(patch.object(capture, 'analyze', return_value={'passed': True}))
            stack.enter_context(patch('builtins.print'))
            code = capture.execute(options, args)
        metadata = json.loads((out / 'capture-result.json').read_text())
        return code, metadata, mocks, popen, startup, stop

    def test_wraps_safe_runner_and_keeps_gates_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            code, result, mocks, popen, _, stop = self.run_mocked(directory, shutdown_clean=False)
        self.assertEqual(code, 1)
        self.assertTrue(result['function_passed'])
        self.assertTrue(result['capture_passed'])
        self.assertFalse(result['shutdown_passed'])
        mocks['execute'].assert_called_once()
        stop.assert_called_once()
        self.assertIs(popen.call_args.kwargs['preexec_fn'], capture.reset_child_signals)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])

    def test_name_follow_uses_scan_response_and_keeps_address_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            code, result, mocks, popen, startup, _ = self.run_mocked(directory, follow_by_name=True)
        self.assertEqual(code, 0)
        self.assertEqual(result['follow_mode'], 'name')
        command = popen.call_args.args[0]
        self.assertIn('--scan-follow-rsp', command)
        self.assertEqual(command[command.index('--follow-by-name') + 1], capture.runner.NAME)
        self.assertNotIn('--follow', command)
        self.assertTrue(startup.call_args.args[-1])
        mocks['execute'].assert_called_once()

    def test_runner_failure_still_stops_capture_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            code, result, mocks, _, _, stop = self.run_mocked(directory, runner_error=RuntimeError('RF failure'))
        self.assertEqual(code, 1)
        self.assertFalse(result['function_passed'])
        mocks['execute'].assert_called_once()
        stop.assert_called_once()

    def test_capture_startup_failure_never_calls_hardware_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            code, _, mocks, _, _, stop = self.run_mocked(directory, startup_error=RuntimeError('not ready'))
        self.assertEqual(code, 1)
        mocks['execute'].assert_not_called()
        stop.assert_called_once()


if __name__ == '__main__':
    unittest.main()
