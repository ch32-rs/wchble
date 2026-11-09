#!/usr/bin/env python3
"""Offline P4 tests; every compiler, Bluetooth, and probe command is mocked."""
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

_spec = importlib.util.spec_from_file_location('p4_runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

SYMBOLS = {'RUN_SECONDS': 0x2000, 'STATS': 0x20001000, 'HOST_STATS': 0x20001100,
           'TRACE': 0x20001200, 'memcpy': 0x20000020, 'memset': 0x20000024,
           '_highcode_vma_start': 0x20000000, '_highcode_vma_end': 0x20000030,
           '_highcode_lma': 4, '_RNvNtNtCtest17compiler_builtins3mem6memcpy': 0x20000028}
SYMBOL_TEXT = ''.join(f'{address:08x} T {name}\n' for name, address in SYMBOLS.items())


def elf_image(seconds=25):
    image = bytearray(900)
    image[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<II', image, 28, 52, 128)
    struct.pack_into('<HHHHH', image, 42, 32, 1, 40, 6, 4)
    struct.pack_into('<8I', image, 52, 1, 768, 0x20000000, 4, 48, 48, 5, 4)
    names = b'\0.highcode\0.highcode_mem\0.rodata\0.shstrtab\0.bss\0'
    image[400:400 + len(names)] = names
    sections = [(b'.highcode', 1, 6, 0x20000000, 768, 32),
                (b'.highcode_mem', 1, 6, 0x20000020, 800, 16),
                (b'.rodata', 1, 2, 0x2000, 816, 4),
                (b'.shstrtab', 3, 0, 0, 400, len(names)),
                (b'.bss', 8, 3, 0x20001000, 820, 0x2000)]
    for index, (name, kind, flags, address, offset, size) in enumerate(sections, 1):
        struct.pack_into('<10I', image, 128 + index * 40,
                         names.index(name + b'\0'), kind, flags, address, offset, size, 0, 0, 4, 0)
    struct.pack_into('<I', image, 816, seconds)
    return bytes(image)


def good_stats(cycles=1, seconds=25):
    stats = [0] * 64
    for index, value in {0: 0x50343538, 1: 1, 2: 9, 3: 10, 4: 10, 6: 1000,
                         7: 100, 14: cycles, 15: cycles, 16: 100, 17: 100, 18: 100,
                         28: cycles, 32: seconds * 1_000_000, 34: 0x30000,
                         35: 60_000_000, 36: cycles, 39: 1, 41: cycles,
                         44: 1_000_000, 61: 100}.items():
        stats[index] = value
    return stats


def good_host(cycles=1):
    return [2, cycles, cycles, 5 * cycles, 13 * cycles, 10 * cycles, 110,
            0, 0, 0, 0, cycles + 1, 0, 0, 0, 0]


def good_client(cycles=1, timeout=20, notification_first=False):
    identifier = '00000000-0000-0000-0000-000000000001'
    rows = [{'event': 'start', 'name': runner.NAME, 'cycles': cycles,
             'timeout_seconds': timeout, 'service': runner.SERVICE,
             'characteristic': runner.CHARACTERISTIC, 'monotonic_seconds': 0}]
    for cycle in range(1, cycles + 1):
        for group in runner.cycle_steps():
            for item in reversed(group) if notification_first else group:
                row = dict(item, cycle=cycle, id=identifier, monotonic_seconds=len(rows) * .001)
                if row['event'] in ('read_result', 'notification', 'write_requested'):
                    row.setdefault('value', 110 if cycle > 1 else 73)  # Initial value is not required to be zero.
                    row['bytes'] = list(row['value'].to_bytes(4, 'little'))
                rows.append(row)
    rows.append({'event': 'summary', 'exit_code': 0, 'reason': 'cycles_complete',
                 'cycles_completed': cycles, 'cycles_requested': cycles,
                 'timeout_seconds': timeout, 'locked_id': identifier,
                 'reads': 5 * cycles, 'writes': 13 * cycles, 'notifications': 10 * cycles,
                 'subscriptions': 2 * cycles, 'monotonic_seconds': len(rows) * .001})
    return rows


class ValidationTests(unittest.TestCase):
    def test_shared_policy_and_indices(self):
        self.assertIs(runner.io, runner.p3.io)
        self.assertIs(runner.halt_and_idle, runner.p3.halt_and_idle)
        self.assertIs(runner.wait_until, runner.p3.wait_until)
        self.assertEqual(len(runner.STAT_NAMES), 64)
        self.assertEqual(runner.STAT_NAMES[31], 'backpressure')
        self.assertEqual(runner.STAT_NAMES[61:], ['max_host_poll_us', 'host_poll_overrun', 'bridge_error'])
        self.assertEqual(runner.HOST_NAMES[:12], ['phase', 'connections', 'disconnects', 'reads',
                         'writes', 'notifications', 'value', 'errors', 'last_error', 'gatt_other',
                         'subscribed', 'advertise_attempts'])
        self.assertEqual(len(runner.HOST_NAMES), 16)
        self.assertIn('F93', ' '.join(runner.PROBE))

    def test_symbols_and_ram_preflight(self):
        image = elf_image()
        self.assertEqual(runner.observation_symbols(SYMBOL_TEXT, image), SYMBOLS)
        self.assertEqual(runner.validate_ram_layout(image, SYMBOLS)['copy_bytes'], 48)
        self.assertEqual(runner.embedded_u32(image, SYMBOLS['RUN_SECONDS']), 25)
        for text in (SYMBOL_TEXT.replace('20001100 T HOST_STATS\n', ''),
                     SYMBOL_TEXT + '20001100 B HOST_STATS\n',
                     SYMBOL_TEXT.replace('20001100', '00001100'),
                     SYMBOL_TEXT.replace('20001100', '20001101'),
                     SYMBOL_TEXT.replace('20001100', '20001080'),
                     SYMBOL_TEXT.replace('20001100', '20002ff0')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runner.observation_symbols(text, image)
        image = bytearray(image)
        struct.pack_into('<I', image, 128 + 5 * 40 + 8, 2)
        with self.assertRaises(ValueError):
            runner.observation_symbols(SYMBOL_TEXT, image)

    def test_stats_success_backpressure_and_diagnostics_not_fatal(self):
        for cycles, seconds in ((1, 25), (10, 360)):
            stats, host = good_stats(cycles, seconds), good_host(cycles)
            stats[31], stats[61], host[9] = 123, 1000, 15
            self.assertEqual(runner.evaluate_stats(stats, host, cycles, seconds), [])

    def test_stats_failures(self):
        for index, value in ((0, 0), (1, 0), (2, 8), (5, 1), (12, 1), (14, 2), (15, 0),
                             (17, 0), (18, 0), (19, 1), (20, 1), (21, 1), (22, 1),
                             (28, 0), (29, 1), (30, 1), (32, 1), (33, 1), (34, 0),
                             (35, 0), (36, 0), (39, 129), (41, 0), (60, 1), (62, 1), (63, 1)):
            with self.subTest(index=index):
                stats = good_stats()
                stats[index] = value
                self.assertTrue(runner.evaluate_stats(stats, good_host(), 1, 25))
        for index, value in ((0, 0), (0, 255), (1, 0), (1, 2), (2, 0), (2, 2), (3, 4), (4, 12),
                             (5, 9), (6, 109), (7, 1), (8, 1), (10, 1), (11, 0), (11, 1)):
            with self.subTest(host_index=index):
                host = good_host()
                host[index] = value
                self.assertTrue(runner.evaluate_stats(good_stats(), host, 1, 25))
        self.assertTrue(runner.evaluate_stats([], good_host(), 1, 25))
        self.assertTrue(runner.evaluate_stats(good_stats(), [], 1, 25))

    def test_client_success_either_ack_notification_order(self):
        for cycles in (1, 10):
            for first in (False, True):
                rows = good_client(cycles, notification_first=first)
                self.assertEqual(runner.evaluate_client(rows, cycles, 20, 0), [])
                self.assertEqual(sum(row['event'] == 'read_result' for row in rows), 5 * cycles)
                self.assertEqual(sum(row['event'] == 'write_ack' for row in rows), 13 * cycles)
                self.assertEqual(sum(row['event'] == 'notification' for row in rows), 10 * cycles)

    def test_client_missing_duplicate_wrong_or_out_of_order_fails(self):
        rows = good_client()
        for index in range(1, len(rows) - 1):
            for mutation in ('remove', 'duplicate', 'wrong_id', 'wrong_cycle'):
                with self.subTest(index=index, mutation=mutation):
                    bad = [dict(row) for row in rows]
                    if mutation == 'remove': bad.pop(index)
                    elif mutation == 'duplicate': bad.insert(index, dict(bad[index]))
                    elif mutation == 'wrong_id': bad[index]['id'] = 'another UUID'
                    else: bad[index]['cycle'] = 2
                    self.assertTrue(runner.evaluate_client(bad, 1, 20, 0))
        self.assertTrue(runner.evaluate_client(rows, 1, 20, 5))

    def test_client_wrong_value_properties_identity_and_summary(self):
        changes = [('start', {'name': 'wch585-p4-other'}),
                   ('start', {'service': 'wrong-service'}),
                   ('characteristics_discovered', {'notify': False}),
                   ('characteristics_discovered', {'write': False}),
                   ('characteristics_discovered', {'read': False}),
                   ('connecting', {'local_name': 'wch585-p4-extra'}),
                   ('disconnected', {'expected': False}),
                   ('disconnected', {'error': 'link lost'}),
                   ('read_result', {'bytes': [0]}),
                   ('notification', {'value': 999}),
                   ('notification', {'bytes': [0, 0, 0, 101]}),
                   ('summary', {'notifications': 9}),
                   ('summary', {'reads': 15}),
                   ('summary', {'cycles_completed': 0}),
                   ('summary', {'locked_id': None}),
                   ('summary', {'monotonic_seconds': float('nan')}),
                   ('summary', {'monotonic_seconds': 21})]
        for event, fields in changes:
            with self.subTest(event=event, fields=fields):
                rows = good_client()
                next(row for row in rows if row['event'] == event).update(fields)
                self.assertTrue(runner.evaluate_client(rows, 1, 20, 0))

    def test_read_callback_cannot_count_as_notification(self):
        for event in ('read_requested', 'read_result'):
            rows = good_client()
            index = next(i for i, row in enumerate(rows) if row['event'] == 'notification')
            rows[index].update(event=event, purpose='verify')
            self.assertTrue(runner.evaluate_client(rows, 1, 20, 0))
        rows = good_client()
        index = next(i for i, row in enumerate(rows) if row['event'] == 'notification')
        rows[index]['value'] = 102  # Correct later values may not mask a missed 101.
        self.assertTrue(runner.evaluate_client(rows, 1, 20, 0))

    def test_cli_finite_budget(self):
        defaults = runner.options(['--out', '/tmp/unused'])
        self.assertEqual((defaults.cycles, defaults.timeout, defaults.run_seconds), (1, 20, 25))
        self.assertEqual(defaults.elf, runner.DEFAULT_ELF)
        for flags in (['--cycles', '0'], ['--cycles', '1001'], ['--timeout', 'nan'],
                      ['--timeout', 'inf'], ['--timeout', '0'], ['--timeout', '25'],
                      ['--run-seconds', '30'], ['--hold', '1'], ['--name', 'other']):
            with self.subTest(flags=flags), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.options(['--out', '/tmp/unused', *flags])
        self.assertEqual(runner.options(['--out', '/tmp/unused', '--run-seconds', '360',
                                         '--timeout', '350', '--cycles', '10']).cycles, 10)


class ExecutionTests(unittest.TestCase):
    def run_mocked(self, mode='pass', seconds=25):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf, smoke, out = root / 'test.elf', root / 'smoke.elf', root / 'out'
            image = bytearray(elf_image(360 if mode == 'budget_mismatch' else seconds))
            if mode == 'ram_gap': struct.pack_into('<I', image, 220, 0x20000024)
            elf.write_bytes(image)
            smoke.write_bytes(b'smoke')
            args = argparse.Namespace(out=out, elf=elf, smoke_elf=smoke, nm='mock-nm',
                                      run_seconds=seconds, cycles=1, timeout=20)
            now, calls = [100.0], []

            def command(argv, path, timeout=40):
                calls.append(('command', argv[0], now[0]))
                if argv[0] == 'mock-nm':
                    text = SYMBOL_TEXT
                    if mode == 'missing_host': text = text.replace('20001100 T HOST_STATS\n', '')
                    if mode == 'flash_memcpy': text = text.replace('20000020 T memcpy', '00004508 T memcpy')
                    if mode == 'flash_memcpy_body':
                        text = text.replace('20000028 T _RN', '00004508 T _RN')
                elif argv[0] == 'swiftc':
                    if mode == 'compiler_fail': raise RuntimeError('compiler failed')
                    self.assertEqual(Path(argv[1]).read_bytes(), (runner.EXAMPLE / 'tools/central.swift').read_bytes())
                    text = ''
                elif argv[0] == 'swift':
                    self.assertEqual(argv, ['swift', str(runner.io.SCANNER), 'wch585', '8'])
                    if mode == 'recovery_scan_fail': raise RuntimeError('smoke not discovered')
                    text = 'exact-name smoke discovered\n'
                else:
                    raise AssertionError(f'unexpected command: {argv}')
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
                if prefix == 'restore' and mode == 'restore_flash_fail':
                    raise RuntimeError('recovery download failed')

            def read(address, count, path):
                self.assertGreaterEqual(now[0], 100 + seconds + 3, 'probe read during finite firmware run')
                calls.append(('read', count, now[0]))
                if mode == 'read_fail' or (count == 64 and mode == 'stats_read_fail'):
                    raise RuntimeError('probe read failed')
                if count == 64:
                    self.assertEqual(address, SYMBOLS['STATS'])
                    words = good_stats(seconds=seconds)
                    if mode == 'stats_fail': words[2] = 0xee
                elif count == 16:
                    self.assertEqual(address, SYMBOLS['HOST_STATS'])
                    words = good_host()
                    if mode == 'host_fail': words[7] = 1
                else:
                    self.assertEqual(address, SYMBOLS['TRACE'])
                    words = [0] * count
                path.write_text(' '.join(f'{word:x}' for word in words) + '\n')
                return words

            class Client:
                returncode = None
                def __init__(self, argv, stdout, stderr, text):
                    calls.append(('client', 'start', now[0]))
                    if mode == 'popen_fail': raise OSError('cannot start central')
                    self.argv = argv
                    if argv[1:] != ['--cycles', '1', '--timeout', '20', '--name', runner.NAME]:
                        raise AssertionError(f'wrong central arguments: {argv}')
                    rows = good_client()
                    if mode == 'client_fail': rows[-1]['exit_code'] = 5
                    if mode == 'malformed': stdout.write('bad JSON\n')
                    else: stdout.write(''.join(json.dumps(row) + '\n' for row in rows))
                    stdout.flush()
                def poll(self): return self.returncode
                def terminate(self):
                    calls.append(('client', 'terminate', now[0]))
                    self.returncode = -15
                def kill(self): self.returncode = -9
                def wait(self, timeout):
                    if self.returncode is not None and self.returncode < 0: return self.returncode
                    now[0] += 3
                    if mode == 'interrupt': raise KeyboardInterrupt()
                    if mode == 'client_timeout': raise subprocess.TimeoutExpired('central', timeout)
                    self.returncode = 5 if mode == 'client_fail' else 0
                    return self.returncode

            interrupted = [False]

            def sleep(delay):
                if mode == 'wait_interrupt' and not interrupted[0]:
                    interrupted[0] = True
                    raise KeyboardInterrupt()
                now[0] += delay

            with patch.object(runner.io, 'command', side_effect=command), \
                    patch.object(runner.io, 'idle', side_effect=lambda out, prefix: calls.append(('idle', prefix, now[0]))), \
                    patch.object(runner.io, 'flash', side_effect=flash), \
                    patch.object(runner.io, 'read32', side_effect=read), \
                    patch.object(runner.subprocess, 'Popen', Client), \
                    patch.object(runner.subprocess, 'run', side_effect=AssertionError('external command forbidden')), \
                    patch.object(runner.time, 'monotonic', side_effect=lambda: now[0]), \
                    patch.object(runner.time, 'sleep', side_effect=sleep), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = runner.execute(args)
            result = json.loads((out / 'result.json').read_text())
            files = {path.name for path in out.iterdir()}
            self.assertEqual((out / 'firmware.elf').read_bytes(), elf.read_bytes())
            self.assertEqual((out / 'smoke.elf').read_bytes(), smoke.read_bytes())
            return code, result, calls, files

    def test_success_archives_and_orders_short_and_long(self):
        for seconds in (25, 360):
            with self.subTest(seconds=seconds):
                code, result, calls, files = self.run_mocked(seconds=seconds)
                self.assertEqual(code, 0, result['errors'])
                self.assertTrue(result['passed'])
                self.assertIn('PASS', result['smoke_recovery'])
                self.assertTrue({'firmware.elf', 'smoke.elf', 'central.swift', 'symbols.txt',
                                 'central.jsonl', 'stats.json', 'host_stats.json', 'trace.json',
                                 'result.json', 'central.command.json'}.issubset(files))
                expected_time = 100 + seconds + 3
                self.assertEqual([call[1] for call in calls if call[0] == 'read'], [64, 16, 8])
                # One combined helper flash gate replaces the former
                # halt/idle/download sequence for both test and restore.
                self.assertLess(calls.index(('flash', 'test', 100.0)), calls.index(('client', 'start', 100.0)))
                self.assertLess(calls.index(('read', 8, expected_time)), calls.index(('flash', 'restore', expected_time)))
                self.assertFalse(any(call[0] in ('halt', 'idle') for call in calls))
                self.assertEqual(sum(call[:2] == ('flash', 'test') for call in calls), 1)
                self.assertEqual(sum(call[:2] == ('flash', 'restore') for call in calls), 1)

    def test_preflight_failure_never_touches_hardware(self):
        for mode in ('budget_mismatch', 'compiler_fail', 'missing_host', 'flash_memcpy',
                     'flash_memcpy_body', 'ram_gap'):
            with self.subTest(mode=mode):
                code, result, calls, _ = self.run_mocked(mode)
                self.assertEqual(code, 1)
                self.assertFalse(any(call[0] in ('read', 'flash', 'idle', 'client', 'halt') for call in calls))
                self.assertIn('NOT ATTEMPTED', result['smoke_recovery'])

    def test_initial_preflight_failure_prevents_client_but_recovery_flashes(self):
        messages = {'fail': 'preflight halt failed', 'timeout': 'TimeoutExpired',
                    'unconfirmed': 'halt not confirmed', 'panic': '(101)'}
        for suffix, message in messages.items():
            with self.subTest(suffix=suffix):
                code, result, calls, _ = self.run_mocked(f'test_halt_{suffix}')
                self.assertEqual(code, 1)
                self.assertFalse(any(call[0] == 'client' for call in calls))
                self.assertFalse(any(call[0] in ('halt', 'idle') for call in calls))
                # The failing combined flash gate is attempted exactly once.
                self.assertEqual(sum(call[:2] == ('flash', 'test') for call in calls), 1)
                self.assertTrue(any(message in error for error in result['errors']))
                self.assertIn('PASS', result['smoke_recovery'])
                self.assertEqual(sum(call[:2] == ('flash', 'restore') for call in calls), 1)

    def test_recovery_preflight_failure_prevents_restore_scan(self):
        messages = {'fail': 'preflight halt failed', 'timeout': 'timed out',
                    'unconfirmed': 'halt not confirmed', 'panic': '(101)'}
        for suffix, message in messages.items():
            with self.subTest(suffix=suffix):
                code, result, calls, _ = self.run_mocked(f'restore_halt_{suffix}')
                self.assertEqual(code, 1)
                self.assertEqual(result['smoke_recovery'], 'NOT VERIFIED')
                self.assertTrue(any(message in error for error in result['errors']))
                # No separate halt/idle step; the combined restore flash failed.
                self.assertEqual(sum(call[:2] == ('flash', 'restore') for call in calls), 1)
                self.assertFalse(any(call[0] in ('halt', 'idle') for call in calls))
                self.assertFalse(any(call[:2] == ('command', 'swift') for call in calls))

    def test_all_failures_keep_evidence_wait_and_restore_without_retry(self):
        for mode in ('flash_fail', 'popen_fail', 'client_fail', 'client_timeout', 'malformed',
                     'stats_fail', 'host_fail', 'read_fail', 'stats_read_fail', 'interrupt',
                     'wait_interrupt', 'recovery_scan_fail', 'restore_flash_fail'):
            with self.subTest(mode=mode):
                code, result, calls, _ = self.run_mocked(mode)
                self.assertEqual(code, 1)
                self.assertFalse(result['passed'])
                self.assertTrue(result['errors'])
                self.assertEqual(sum(call[:2] == ('flash', 'test') for call in calls), 1)
                self.assertEqual(sum(call[:2] == ('flash', 'restore') for call in calls), 1)
                self.assertTrue(all(call[2] >= 128 for call in calls if call[0] == 'read'))
                self.assertTrue(all(call[2] >= 128 for call in calls if call[:2] == ('flash', 'restore')))
                self.assertIn(16, [call[1] for call in calls if call[0] == 'read'])
                self.assertTrue(any(call[0] == 'read' and call[1] in (8, 1024) for call in calls))
                if mode not in ('recovery_scan_fail', 'restore_flash_fail'):
                    self.assertIn('PASS', result['smoke_recovery'])

    def test_failed_stats_read_still_reads_host_and_full_trace(self):
        code, result, calls, files = self.run_mocked('stats_read_fail')
        self.assertEqual(code, 1)
        self.assertEqual([call[1] for call in calls if call[0] == 'read'], [64, 16, 1024])
        self.assertTrue({'host_stats.json', 'trace.json'}.issubset(files))
        self.assertIn('host_stats', result)


if __name__ == '__main__':
    unittest.main()
