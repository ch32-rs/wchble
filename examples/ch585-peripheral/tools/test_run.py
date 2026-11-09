#!/usr/bin/env python3
"""Offline runner tests: every compiler, Bluetooth, and probe command is mocked."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location('p3_runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)


SYMBOLS = {'RUN_SECONDS': 0x2000, 'STATS': 0x3000, 'TRACE': 0x4000,
           'memcpy': 0x20000020, 'memset': 0x20000024,
           '_highcode_vma_start': 0x20000000, '_highcode_vma_end': 0x20000030,
           '_highcode_lma': 4,
           '_RNvNtNtCtest17compiler_builtins3mem6memcpy': 0x20000028}
SYMBOL_TEXT = ''.join(f'{address:08x} T {name}\n' for name, address in SYMBOLS.items())


def elf_image(seconds=25):
    image = bytearray(600)
    image[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<II', image, 28, 52, 128)
    struct.pack_into('<HHHHH', image, 42, 32, 1, 40, 5, 4)
    struct.pack_into('<8I', image, 52, 1, 512, 0x20000000, 4, 48, 48, 5, 4)
    names = b'\0.highcode\0.highcode_mem\0.rodata\0.shstrtab\0'
    image[352:352 + len(names)] = names
    sections = [(b'.highcode', 1, 6, 0x20000000, 512, 32),
                (b'.highcode_mem', 1, 6, 0x20000020, 544, 16),
                (b'.rodata', 1, 2, 0x2000, 560, 4),
                (b'.shstrtab', 3, 0, 0, 352, len(names))]
    for index, (name, kind, flags, address, offset, size) in enumerate(sections, 1):
        struct.pack_into('<10I', image, 128 + index * 40,
                         names.index(name + b'\0'), kind, flags, address, offset, size, 0, 0, 4, 0)
    struct.pack_into('<I', image, 560, seconds)
    return bytes(image)


def good_stats(cycles=1, hold=1, seconds=25):
    stats = [0] * 64
    for index, value in {0: 0x50333538, 1: 1, 2: 9, 3: 10, 4: 10, 6: 1000,
                         7: 100, 14: cycles, 15: cycles, 16: 100, 17: 100, 18: 100,
                         28: cycles, 32: seconds * 1_000_000, 34: 0x30000,
                         35: 60_000_000, 36: cycles, 39: 1, 41: cycles,
                         44: int((hold + .1) * 1_000_000)}.items():
        stats[index] = value
    return stats


def good_client(cycles=1, hold=1, timeout=20):
    identifier = '00000000-0000-0000-0000-000000000001'
    rows = [{'event': 'start', 'name': 'wch585-p3', 'cycles': cycles,
             'hold_seconds': hold, 'timeout_seconds': timeout, 'gatt_operations': 0,
             'monotonic_seconds': 0}]
    now = 1.0
    for cycle in range(1, cycles + 1):
        for event, delta in [('connecting', .1), ('connected', .1),
                             ('cancel_requested', hold + .1), ('disconnected', .1),
                             ('cycle_complete', .1)]:
            now += delta
            row = {'event': event, 'cycle': cycle, 'id': identifier, 'monotonic_seconds': now}
            if event == 'connecting':
                row['local_name'] = 'wch585-p3'
            if event in ('cancel_requested', 'cycle_complete'):
                row['held_seconds'] = hold + .1
            if event == 'disconnected':
                row.update(expected=True, error=None)
            rows.append(row)
    rows.append({'event': 'summary', 'exit_code': 0, 'reason': 'cycles_complete',
                 'cycles_completed': cycles, 'cycles_requested': cycles,
                 'hold_seconds': hold, 'timeout_seconds': timeout, 'locked_id': identifier,
                 'gatt_operations': 0, 'monotonic_seconds': now + .1})
    return rows


class ValidationTests(unittest.TestCase):
    def test_profile_names_keep_indices(self):
        self.assertEqual(len(runner.STAT_NAMES), 64)
        self.assertEqual(runner.STAT_NAMES[54:60], ['rx_stop_delay_us', 'rx_return_delay_us',
                         'tx_entry_delay_us', 'tx_return_delay_us', 'sequence_delay_us', 'handler_delay_us'])
        self.assertEqual(runner.STAT_NAMES[60], 'terminate_timeout')
        self.assertEqual(runner.STAT_NAMES[61:], [f'reserved_{i}' for i in range(61, 64)])

    def test_halt_confirmation_requires_real_positive_status(self):
        valid = ['Stopped on your request.\n',
                 'Stopped on your request at 0x20000100.\r\n',
                 'Stopped on your request at \x1b[32m0x20000100 (/src/main.rs:40:7)\x1b[0m.\n']
        invalid = ['', 'Debug Session Terminated\n', 'The core is running.\n',
                   'halt failed\n', 'Not halted\n', 'error: Stopped on your request.\n']
        for output in valid + invalid:
            with self.subTest(output=output), patch.object(runner.io, 'command', return_value=output), \
                    patch.object(runner.io, 'idle') as idle:
                if output in valid:
                    runner.halt_and_idle(Path('/unused'), 'test')
                    idle.assert_called_once_with(Path('/unused'), 'test')
                else:
                    with self.assertRaisesRegex(RuntimeError, 'confirmation missing'):
                        runner.halt_and_idle(Path('/unused'), 'test')
                    idle.assert_not_called()

    def test_embedded_budget(self):
        self.assertEqual(runner.embedded_u32(elf_image(), 0x2000), 25)
        self.assertEqual(runner.embedded_u32(elf_image(360), 0x2000), 360)
        for image, address in [(b'', 0x2000), (elf_image(), 0x2004), (elf_image()[:70], 0x2000)]:
            with self.subTest(length=len(image), address=address), self.assertRaises(ValueError):
                runner.embedded_u32(image, address)

    def test_ram_layout_checks_symbols_sections_and_physical_load(self):
        layout = runner.validate_ram_layout(elf_image(), SYMBOLS)
        self.assertEqual(layout, {'vma_start': 0x20000000, 'vma_end': 0x20000030,
                                 'load_address': 4, 'file_offset': 512, 'copy_bytes': 48})
        for name, address in [('memcpy', 0x4508), ('memset', 0x2000002e),
                              ('_highcode_vma_start', 0), ('_highcode_lma', 8),
                              ('_highcode_vma_end', 0x2000002c),
                              ('_RNvNtNtCtest17compiler_builtins3mem6memcpy', 0x4508)]:
            with self.subTest(symbol=name):
                symbols = dict(SYMBOLS)
                symbols[name] = address
                with self.assertRaises(ValueError):
                    runner.validate_ram_layout(elf_image(), symbols)
        for offset, value in [(220, 0x20000024), (224, 548), (228, 12),
                              (212, 8), (216, 2), (208, 23), (64, 8), (68, 47), (56, 513)]:
            with self.subTest(offset=offset):
                image = bytearray(elf_image())
                struct.pack_into('<I', image, offset, value)
                with self.assertRaises(ValueError):
                    runner.validate_ram_layout(bytes(image), SYMBOLS)
        with self.assertRaises(ValueError):
            runner.validate_ram_layout(elf_image()[:550], SYMBOLS)

    def test_symbols(self):
        self.assertEqual(runner.symbols_from(SYMBOL_TEXT), SYMBOLS)
        with self.assertRaises(ValueError):
            runner.symbols_from('3000 B STATS\n')
        with self.assertRaisesRegex(ValueError, 'undefined compiler memory'):
            runner.symbols_from(SYMBOL_TEXT + ' U _ZN17compiler_builtins3mem6memset17hashE\n')
        legacy = '_ZN17compiler_builtins3mem6memset17hashE'
        self.assertEqual(runner.symbols_from(SYMBOL_TEXT + f'2000002c t {legacy}\n')[legacy], 0x2000002c)

    def test_stats_success(self):
        self.assertEqual(runner.evaluate_stats(good_stats(), 1, 1, 25), [])
        self.assertEqual(runner.evaluate_stats(good_stats(10, 10, 360), 10, 10, 360), [])
        stats = good_stats()
        stats[41] = 80  # Accepted is a PDU count, not a connection count.
        stats[39], stats[40] = 300, 172
        self.assertEqual(runner.evaluate_stats(stats, 1, 1, 25), [])

    def test_stats_failures(self):
        for index, value in [(0, 0), (2, 0xee), (5, 1), (12, 1), (14, 2), (15, 0),
                             (17, 0), (18, 0), (19, 1), (20, 1), (21, 1), (22, 1),
                             (28, 0), (29, 1), (30, 1), (31, 1), (32, 1), (33, 1),
                             (34, 0), (35, 0), (36, 0), (39, 129), (41, 0), (44, 1), (60, 1)]:
            with self.subTest(index=index):
                stats = good_stats()
                stats[index] = value
                self.assertTrue(runner.evaluate_stats(stats, 1, 1, 25))
        self.assertTrue(runner.evaluate_stats([], 1, 1, 25))

    def test_terminate_timeout_is_fatal(self):
        stats = good_stats()
        stats[60] = 1
        self.assertIn('firmware terminate_timeout=1', runner.evaluate_stats(stats, 1, 1, 25))

    def test_client_success(self):
        self.assertEqual(runner.evaluate_client(good_client(), 1, 1, 20, 0), [])
        self.assertEqual(runner.evaluate_client(good_client(10, 10, 180), 10, 10, 180, 0), [])

    def test_client_failures(self):
        mutations = [lambda rows: rows.pop(),
                     lambda rows: rows[1].update(local_name='wch585-p3-other'),
                     lambda rows: rows[2].update(id='wrong-uuid'),
                     lambda rows: rows[3].update(held_seconds=.9),
                     lambda rows: rows[3].update(monotonic_seconds=1.3),
                     lambda rows: rows[4].update(expected=False),
                     lambda rows: rows[4].update(error='link lost'),
                     lambda rows: rows[-1].update(cycles_completed=0),
                     lambda rows: rows[-1].update(gatt_operations=1),
                     lambda rows: rows.insert(1, dict(rows[1])),
                     lambda rows: rows.insert(1, {'event': 'error', 'monotonic_seconds': .5})]
        for mutate in mutations:
            rows = good_client()
            mutate(rows)
            with self.subTest(mutate=mutate):
                self.assertTrue(runner.evaluate_client(rows, 1, 1, 20, 0))
        self.assertTrue(runner.evaluate_client(good_client(), 1, 1, 20, 5))

    def test_cli_budget(self):
        args = runner.options(['--out', '/tmp/unused'])
        self.assertEqual((args.cycles, args.hold, args.timeout, args.run_seconds), (1, 1, 20, 25))
        for extra in [['--hold', 'nan'], ['--timeout', 'inf'], ['--cycles', '0'],
                      ['--cycles', '10', '--hold', '10'], ['--timeout', '25'],
                      ['--run-seconds', '30']]:
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.options(['--out', '/tmp/unused', *extra])

    def test_trace_opening_and_rolling_tail_order(self):
        for total in (0, 1, 63, 64, 65, 127, 128, 129, 191, 192, 193, 500):
            with self.subTest(total=total):
                words = [0] * (min(total, 128) * 8)
                for index in range(total):
                    slot = index if index < 128 else 64 + (index - 128) % 64
                    words[slot * 8] = index
                rows = runner.ordered_trace(words, total)
                expected = list(range(total)) if total <= 128 else list(range(64)) + list(range(total - 64, total))
                self.assertEqual([row['time_us'] for row in rows], expected)
        with self.assertRaises(ValueError):
            runner.ordered_trace([0] * 8, 2)

    def test_jsonl_malformed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'central.jsonl'
            for text in ('not-json\n', '[]\n'):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    runner.read_client(path)

    def test_stop_client_kills_bounded(self):
        class Stalled:
            def poll(self): return None
            def terminate(self): calls.append('terminate')
            def kill(self): calls.append('kill')
            def wait(self, timeout):
                calls.append(('wait', timeout))
                if calls.count(('wait', timeout)) == 1:
                    raise subprocess.TimeoutExpired('central', timeout)
        calls = []
        runner.stop_client(Stalled())
        self.assertEqual(calls, ['terminate', ('wait', 3), 'kill', ('wait', 3)])


class ExecutionTests(unittest.TestCase):
    def run_mocked(self, mode='pass', seconds=25):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf, smoke, out = root / 'test.elf', root / 'smoke.elf', root / 'out'
            image = bytearray(elf_image(seconds))
            if mode == 'ram_gap': struct.pack_into('<I', image, 220, 0x20000024)
            elf.write_bytes(image)
            smoke.write_bytes(b'smoke')
            args = argparse.Namespace(out=out, elf=elf, smoke_elf=smoke, nm='mock-nm',
                                      run_seconds=25, cycles=1, hold=1, timeout=20)
            now, calls = [100.0], []

            def command(argv, path, timeout=40):
                calls.append(('command', argv[0], now[0]))
                if argv[0] == 'mock-nm':
                    symbols = dict(SYMBOLS)
                    if mode == 'flash_memcpy': symbols['memcpy'] = 0x4508
                    if mode == 'flash_memcpy_body':
                        symbols['_RNvNtNtCtest17compiler_builtins3mem6memcpy'] = 0x4508
                    text = ''.join(f'{address:08x} T {name}\n' for name, address in symbols.items())
                elif argv[0] == 'swiftc' and mode == 'compiler_fail':
                    raise RuntimeError('compiler failed')
                elif argv[0] == 'swift' and mode == 'recovery_scan_fail':
                    raise RuntimeError('smoke not discovered')
                else:
                    text = ''
                path.write_text(text)
                return text

            def flash(path, destination, prefix, check_idle=True):
                # The helper owns halt, engine shutdown, both idle checks, and
                # verified download; simulate its former halt failures here.
                calls.append(('flash', prefix, now[0]))
                self.assertFalse(check_idle, 'the preflight helper owns the idle gate')
                self.assertEqual(path.read_bytes(), elf.read_bytes() if prefix == 'test' else smoke.read_bytes())
                if mode == f'{prefix}_halt_fail':
                    raise RuntimeError('preflight halt failed')
                if mode == f'{prefix}_halt_timeout':
                    raise subprocess.TimeoutExpired(['mock-preflight'], 1)
                if mode == f'{prefix}_halt_unconfirmed':
                    raise RuntimeError('halt not confirmed')
                if mode == f'{prefix}_halt_panic':
                    raise RuntimeError('command failed (101): mock')
                if prefix == 'test' and mode == 'flash_fail':
                    raise RuntimeError('download failed after possible boot')

            def read(address, count, path):
                self.assertGreaterEqual(now[0], 128.0, 'probe read occurred during firmware execution')
                calls.append(('read', count, now[0]))
                if mode == 'read_fail':
                    raise RuntimeError('probe read failed')
                if count == 64:
                    stats = good_stats()
                    if mode == 'stats_fail': stats[2] = 0xee
                    return stats
                return [0] * count

            class Client:
                returncode = None
                def __init__(self, argv, stdout, stderr, text):
                    calls.append(('client', 'start', now[0]))
                    if mode == 'popen_fail':
                        raise OSError('cannot start central')
                    rows = good_client()
                    if mode == 'client_fail':
                        rows[-1]['exit_code'] = 5
                    if mode == 'malformed':
                        stdout.write('bad JSON\n')
                    else:
                        stdout.write(''.join(json.dumps(row) + '\n' for row in rows))
                    stdout.flush()
                def poll(self): return self.returncode
                def terminate(self):
                    calls.append(('client', 'terminate', now[0]))
                    self.returncode = -15
                def kill(self): self.returncode = -9
                def wait(self, timeout):
                    if self.returncode is not None and self.returncode < 0:
                        return self.returncode
                    now[0] += 3
                    if mode == 'interrupt': raise KeyboardInterrupt()
                    if mode == 'client_timeout':
                        raise subprocess.TimeoutExpired('central', timeout)
                    self.returncode = 5 if mode == 'client_fail' else 0
                    return self.returncode

            with patch.object(runner.io, 'command', side_effect=command), \
                    patch.object(runner.io, 'idle', side_effect=lambda out, prefix: calls.append(('idle', prefix, now[0]))), \
                    patch.object(runner.io, 'flash', side_effect=flash), \
                    patch.object(runner.io, 'read32', side_effect=read), \
                    patch.object(runner.subprocess, 'Popen', Client), \
                    patch.object(runner.time, 'monotonic', side_effect=lambda: now[0]), \
                    patch.object(runner.time, 'sleep', side_effect=lambda seconds: now.__setitem__(0, now[0] + seconds)), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = runner.execute(args)
            result = json.loads((out / 'result.json').read_text())
            files = {path.name for path in out.iterdir()}
            return code, result, calls, files

    def test_success_archives_and_orders(self):
        code, result, calls, files = self.run_mocked()
        self.assertEqual(code, 0, result['errors'])
        self.assertTrue(result['passed'])
        self.assertIn('PASS', result['smoke_recovery'])
        self.assertTrue({'firmware.elf', 'smoke.elf', 'symbols.txt', 'central.jsonl',
                         'stats.json', 'trace.json', 'result.json'}.issubset(files))
        # One combined helper flash gate replaces the former halt/idle/download
        # sequence for both test and restore.
        self.assertLess(calls.index(('flash', 'test', 100.0)), calls.index(('client', 'start', 100.0)))
        self.assertLess(calls.index(('read', 8, 128.0)), calls.index(('flash', 'restore', 128.0)))
        self.assertFalse(any(call[0] in ('halt', 'idle') for call in calls))
        self.assertEqual(sum(call[:2] == ('flash', 'test') for call in calls), 1)
        self.assertEqual(sum(call[:2] == ('flash', 'restore') for call in calls), 1)

    def test_preflight_no_hardware(self):
        for mode, seconds in [('pass', 360), ('compiler_fail', 25), ('flash_memcpy', 25),
                              ('flash_memcpy_body', 25), ('ram_gap', 25)]:
            with self.subTest(mode=mode):
                code, result, calls, _ = self.run_mocked(mode, seconds)
                self.assertEqual(code, 1)
                self.assertFalse(any(call[0] in ('read', 'flash', 'idle', 'client', 'halt') for call in calls))
                self.assertIn('NOT ATTEMPTED', result['smoke_recovery'])

    def test_initial_preflight_failure_prevents_client_but_recovery_flashes(self):
        messages = {'test_halt_fail': 'preflight halt failed',
                    'test_halt_timeout': 'TimeoutExpired',
                    'test_halt_unconfirmed': 'halt not confirmed',
                    'test_halt_panic': '(101)'}
        for mode, message in messages.items():
            with self.subTest(mode=mode):
                code, result, calls, _ = self.run_mocked(mode)
                self.assertEqual(code, 1)
                self.assertFalse(any(call[0] == 'client' for call in calls))
                self.assertFalse(any(call[0] in ('halt', 'idle') for call in calls))
                # The failing combined flash gate is attempted exactly once.
                self.assertEqual(sum(call[:2] == ('flash', 'test') for call in calls), 1)
                self.assertTrue(any(message in error for error in result['errors']))
                self.assertIn('PASS', result['smoke_recovery'])
                self.assertEqual(sum(call[:2] == ('flash', 'restore') for call in calls), 1)

    def test_recovery_preflight_failure_prevents_restore_scan(self):
        messages = {'restore_halt_fail': 'preflight halt failed',
                    'restore_halt_timeout': 'timed out',
                    'restore_halt_unconfirmed': 'halt not confirmed',
                    'restore_halt_panic': '(101)'}
        for mode, message in messages.items():
            with self.subTest(mode=mode):
                code, result, calls, _ = self.run_mocked(mode)
                self.assertEqual(code, 1)
                self.assertEqual(result['smoke_recovery'], 'NOT VERIFIED')
                self.assertTrue(result['errors'])
                self.assertTrue(any(message in error for error in result['errors']))
                # No separate halt/idle step; the combined restore flash failed.
                self.assertEqual(sum(call[:2] == ('flash', 'restore') for call in calls), 1)
                self.assertFalse(any(call[0] in ('halt', 'idle') for call in calls))
                self.assertFalse(any(call[:2] == ('command', 'swift') for call in calls))

    def test_preflight_panic_exit_101_is_fatal(self):
        for mode in ('test_halt_panic', 'restore_halt_panic'):
            with self.subTest(mode=mode):
                code, result, calls, _ = self.run_mocked(mode)
                self.assertEqual(code, 1)
                self.assertTrue(any('(101)' in error for error in result['errors']))
                prefix = mode.split('_')[0]
                self.assertEqual(sum(call[:2] == ('flash', prefix) for call in calls), 1)
                self.assertFalse(any(call[0] in ('halt', 'idle') for call in calls))

    def test_all_failures_recover_after_finite_run_without_retry(self):
        for mode in ('flash_fail', 'popen_fail', 'client_fail', 'client_timeout', 'malformed',
                     'stats_fail', 'read_fail', 'interrupt', 'recovery_scan_fail'):
            with self.subTest(mode=mode):
                code, result, calls, _ = self.run_mocked(mode)
                self.assertEqual(code, 1)
                self.assertFalse(result['passed'])
                self.assertTrue(result['errors'])
                self.assertEqual(sum(call[:2] == ('flash', 'test') for call in calls), 1)
                recovery = [call for call in calls if call[:2] == ('flash', 'restore')]
                self.assertEqual(len(recovery), 1)
                self.assertGreaterEqual(recovery[0][2], 128)
                self.assertTrue(all(call[2] >= 128 for call in calls if call[0] == 'read'),
                                'observations must wait for the full embedded budget')
                self.assertTrue(any(call[:2] == ('command', 'swift') for call in calls))
                if mode != 'recovery_scan_fail': self.assertIn('PASS', result['smoke_recovery'])


if __name__ == '__main__':
    unittest.main()
