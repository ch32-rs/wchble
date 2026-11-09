#!/usr/bin/env python3
"""Run a finite P4 GATT test, archive evidence, then restore/scan smoke."""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    'ch585_p3_runner', ROOT / 'examples/ch585-peripheral/tools/run.py')
p3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p3)
io, PROBE, NM = p3.io, p3.PROBE, p3.NM
symbols_from, validate_ram_layout, embedded_u32 = p3.symbols_from, p3.validate_ram_layout, p3.embedded_u32
halt_and_idle, wait_until = p3.halt_and_idle, p3.wait_until
ordered_trace, read_client, stop_client = p3.ordered_trace, p3.read_client, p3.stop_client
EXAMPLE = ROOT / 'examples/ch585-trouble-gatt'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
SMOKE = p3.SMOKE
NAME = 'wch585-p4'
SERVICE = '00001000-b0cd-11ec-871f-d45ddf138840'
CHARACTERISTIC = '00001001-b0cd-11ec-871f-d45ddf138840'
STAT_NAMES = p3.STAT_NAMES[:61] + ['max_host_poll_us', 'host_poll_overrun', 'bridge_error']
STAT_NAMES[31] = 'backpressure'
HOST_NAMES = '''phase connections disconnects reads writes notifications value errors last_error
    gatt_other subscribed advertise_attempts reserved_12 reserved_13 reserved_14 reserved_15'''.split()
FAILURES = (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt)


def observation_symbols(text, image):
    symbols = symbols_from(text)
    matches = [parts for line in text.splitlines()
               if len(parts := line.split()) == 3 and parts[2] == 'HOST_STATS']
    if len(matches) != 1:
        raise ValueError('missing or ambiguous HOST_STATS symbol')
    symbols['HOST_STATS'] = int(matches[0][0], 16)
    sections = p3.elf_sections(image)
    ranges = []
    for name, count in (('STATS', 64), ('HOST_STATS', 16), ('TRACE', 128 * 8)):
        address, size = symbols[name], count * 4
        if (address % 4 or not 0x20000000 <= address < address + size <= 0x30000000
                or not any(section['flags'] & 3 == 3 and section['address'] <= address
                           and address + size <= section['address'] + section['size']
                           for section in sections)):
            raise ValueError(f'{name} is not an aligned writable RAM observation buffer')
        if any(address < end and start < address + size for start, end in ranges):
            raise ValueError(f'{name} overlaps another observation buffer')
        ranges.append((address, address + size))
    return symbols


def cycle_steps():
    """Exact operation transcript; only a write ACK/notification pair may reorder."""
    steps = [({'event': 'connecting', 'local_name': NAME},), ({'event': 'connected'},),
             ({'event': 'services_requested', 'service': SERVICE},),
             ({'event': 'services_discovered', 'service': SERVICE},),
             ({'event': 'characteristics_requested', 'characteristic': CHARACTERISTIC},),
             ({'event': 'characteristics_discovered', 'characteristic': CHARACTERISTIC,
               'read': True, 'write': True, 'notify': True},),
             ({'event': 'read_requested', 'purpose': 'initial'},),
             ({'event': 'read_result', 'purpose': 'initial'},)]
    for value in range(1, 4):
        steps.extend([({'event': 'write_requested', 'mode': 'readback', 'value': value},),
                      ({'event': 'write_ack', 'value': value},),
                      ({'event': 'read_requested', 'purpose': 'verify'},),
                      ({'event': 'read_result', 'purpose': 'verify', 'value': value},)])
    steps.extend([({'event': 'notify_requested', 'enabled': True},),
                  ({'event': 'notify_state', 'enabled': True},)])
    for value in range(101, 111):
        steps.extend([({'event': 'write_requested', 'mode': 'notify', 'value': value},),
                      ({'event': 'write_ack', 'value': value}, {'event': 'notification', 'value': value})])
    steps.extend([({'event': 'notify_requested', 'enabled': False},),
                  ({'event': 'notify_state', 'enabled': False},),
                  ({'event': 'read_requested', 'purpose': 'final'},),
                  ({'event': 'read_result', 'purpose': 'final', 'value': 110},),
                  ({'event': 'cancel_requested'},),
                  ({'event': 'disconnected', 'expected': True, 'error': None},),
                  ({'event': 'cycle_complete'},)])
    return steps


def evaluate_client(rows, cycles, timeout, returncode):
    errors = []
    if returncode != 0:
        errors.append(f'central exited with status {returncode}')
    starts = [row for row in rows if row.get('event') == 'start']
    summaries = [row for row in rows if row.get('event') == 'summary']
    start_fields = {'name': NAME, 'cycles': cycles, 'timeout_seconds': timeout,
                    'service': SERVICE, 'characteristic': CHARACTERISTIC}
    summary_fields = {'exit_code': 0, 'reason': 'cycles_complete', 'cycles_completed': cycles,
                      'cycles_requested': cycles, 'timeout_seconds': timeout, 'reads': 5 * cycles,
                      'writes': 13 * cycles, 'notifications': 10 * cycles, 'subscriptions': 2 * cycles}
    if (len(starts) != 1 or not rows or rows[0].get('event') != 'start'
            or any(starts[0].get(key) != value for key, value in start_fields.items())):
        errors.append('central start does not match requested P4 test')
    if (len(summaries) != 1 or not rows or rows[-1].get('event') != 'summary'
            or any(summaries[0].get(key) != value for key, value in summary_fields.items())):
        errors.append('central completion summary/counters are missing or invalid')
    identifier = summaries[0].get('locked_id') if len(summaries) == 1 else None
    if not isinstance(identifier, str) or not identifier:
        errors.append('central locked UUID is missing')
    expected = [(cycle, list(group)) for cycle in range(1, cycles + 1) for group in cycle_steps()]
    cursor, last_time = 0, -1.0
    for row in rows:
        stamp = row.get('monotonic_seconds')
        if (not isinstance(stamp, (int, float)) or isinstance(stamp, bool)
                or not math.isfinite(stamp) or stamp < last_time):
            errors.append('central JSONL has invalid monotonic timestamps')
            break
        last_time = stamp
        event = row.get('event')
        if event in ('start', 'summary', 'bluetooth_state', 'scan_started'):
            continue
        if cursor == len(expected):
            errors.append(f'central recorded extra event after requested cycles: {event}')
            continue
        cycle, group = expected[cursor]
        matches = [item for item in group if all(row.get(key) == value for key, value in item.items())]
        if len(matches) != 1 or row.get('cycle') != cycle or row.get('id') != identifier:
            errors.append(f'central unexpected, failed, or out-of-order cycle {cycle} event: {event}')
            continue
        if event in ('read_result', 'notification', 'write_requested'):
            value, data = row.get('value'), row.get('bytes')
            if (not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xffffffff
                    or not isinstance(data, list) or data != list(value.to_bytes(4, 'little'))):
                errors.append(f'central {event} did not contain an exact u32LE value')
        group.remove(matches[0])
        if not group:
            cursor += 1
    if cursor != len(expected):
        errors.append('central did not complete exactly the requested GATT cycles without retries')
    if rows and isinstance(rows[0].get('monotonic_seconds'), (int, float)) and last_time - rows[0]['monotonic_seconds'] > timeout:
        errors.append('central exceeded the requested total timeout')
    return errors


def evaluate_stats(obs, host, cycles, run_seconds):
    if len(obs) != 64:
        return ['invalid STATS size']
    # Reuse P3's shared LL invariants, except its identity and P4's bounded
    # host bridge backpressure counter (index 31), which is not an RF failure.
    common = list(obs)
    common[0], common[31] = 0x50333538, 0
    errors = p3.evaluate_stats(common, cycles, 0, run_seconds)
    if obs[:3] != [0x50343538, 1, 9]:
        errors.append(f'P4 firmware did not finish: magic/version/stage={obs[:3]}')
    for index in (62, 63):
        if obs[index]:
            errors.append(f'firmware {STAT_NAMES[index]}={obs[index]}')
    if len(host) != 16:
        return errors + ['invalid HOST_STATS size']
    if host[1] != cycles or host[2] != cycles or host[1] != obs[14] or host[2] != obs[28]:
        errors.append('host connection/disconnect counters do not match client and LL cycles')
    if host[3] < 5 * cycles or host[4] < 13 * cycles or host[5] < 10 * cycles:
        errors.append('host did not observe every requested read/write/notification')
    if host[0] != 2 or host[6] != 110 or host[7] or host[8] or host[10]:
        errors.append('host final advertising phase/value/errors/last_error/subscription are not clean')
    if host[11] < cycles + 1:
        errors.append('host did not restart advertising after every completed cycle')
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {'probe': PROBE, 'air_ifs': 'UNMEASURED', 'scope': 'u32LE Read/Write/Notify',
                            'run_seconds': args.run_seconds, 'cycles': args.cycles,
                            'client_timeout': args.timeout,
                            'restart': 'verified idle then debug boot; not a power cycle'}
    client = log = stderr_log = None
    touched, safe_read_at, symbols = False, 0.0, None
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        shutil.copyfile(args.elf, archived)
        shutil.copyfile(args.smoke_elf, smoke)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        symbols = observation_symbols(nm_text, image)
        metadata['symbols'] = symbols
        metadata['ram_layout'] = validate_ram_layout(image, symbols)
        embedded_seconds = embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded_seconds
        if embedded_seconds != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={embedded_seconds}, but --run-seconds={args.run_seconds}')
        source, binary = args.out / 'central.swift', (args.out / 'central').resolve()
        shutil.copyfile(EXAMPLE / 'tools/central.swift', source)
        io.command(['swiftc', str(source), '-o', str(binary)], args.out / 'central-build.log', timeout=120)
        touched = True
        halt_and_idle(args.out, 'test')
        try:
            io.flash(archived, args.out, 'test', check_idle=False)
        finally:
            # Even a failed download may boot the finite image. Never probe it
            # until its entire embedded budget plus the cleanup margin elapses.
            safe_read_at = time.monotonic() + embedded_seconds + 3
        client_args = [str(binary), '--cycles', str(args.cycles), '--timeout', str(args.timeout), '--name', NAME]
        (args.out / 'central.command.json').write_text(json.dumps(client_args) + '\n')
        log, stderr_log = (args.out / 'central.jsonl').open('w'), (args.out / 'central.stderr.log').open('w')
        client = subprocess.Popen(client_args, stdout=log, stderr=stderr_log, text=True)
        try:
            client.wait(timeout=args.timeout + 6)
        except subprocess.TimeoutExpired:
            errors.append('central exceeded timeout plus bounded cleanup')
            stop_client(client)
        finally:
            log.close()
            stderr_log.close()
            log = stderr_log = None
        metadata['client_exit'] = client.returncode
        rows = read_client(args.out / 'central.jsonl')
        metadata['client_summary'] = next((row for row in reversed(rows) if row.get('event') == 'summary'), None)
        errors.extend(evaluate_client(rows, args.cycles, args.timeout, client.returncode))
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        try:
            stop_client(client)
        except FAILURES as error:
            errors.append(f'client cleanup: {type(error).__name__}: {error}')
        for stream in (log, stderr_log):
            if stream is not None:
                stream.close()
        if touched:
            while True:
                try:
                    wait_until(safe_read_at)
                    break
                except KeyboardInterrupt:
                    errors.append('interrupted while waiting for finite firmware; retaining safe-read deadline')
            observations = {}
            if symbols is not None and safe_read_at:
                # Independent reads preserve HOST_STATS and trace evidence even
                # when one observation command or its validation fails.
                for name, count, names in (('STATS', 64, STAT_NAMES), ('HOST_STATS', 16, HOST_NAMES)):
                    try:
                        words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
                        observations[name] = words
                        metadata[name.lower()] = dict(zip(names, words))
                        (args.out / f'{name.lower()}.json').write_text(json.dumps(metadata[name.lower()], indent=2) + '\n')
                    except FAILURES as error:
                        errors.append(f'{name} observations: {error}')
                obs = observations.get('STATS', [])
                try:
                    # Without STATS, retain the raw full buffer rather than
                    # pretending its chronological count is known.
                    count = min(obs[39], 128) * 8 if len(obs) == 64 else 128 * 8
                    words = io.read32(symbols['TRACE'], count, args.out / 'trace.txt') if count else []
                    if not count:
                        (args.out / 'trace.txt').write_text('')
                    trace = ordered_trace(words, obs[39]) if len(obs) == 64 else {'unordered_words': words}
                    (args.out / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
                except FAILURES as error:
                    errors.append(f'TRACE observations: {error}')
                errors.extend(evaluate_stats(obs, observations.get('HOST_STATS', []), args.cycles, args.run_seconds))
            try:
                halt_and_idle(args.out, 'restore')
                io.flash(args.out / 'smoke.elf', args.out, 'restore', check_idle=False)
                io.command(['swift', str(io.SCANNER), 'wch585', '8'], args.out / 'restore-scan.log', 20)
                metadata['smoke_recovery'] = 'flash verify and exact-name macOS discovery PASS'
            except FAILURES as error:
                errors.append(f'recovery: {error}')
                metadata['smoke_recovery'] = 'NOT VERIFIED'
        else:
            metadata['smoke_recovery'] = 'NOT ATTEMPTED: preflight failed before hardware access'
        metadata['errors'], metadata['passed'] = errors, not errors
        (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--run-seconds', type=int, choices=(25, 360), default=25)
    parser.add_argument('--cycles', type=int, default=1)
    parser.add_argument('--timeout', type=float, default=20)
    args = parser.parse_args(argv)
    if not 1 <= args.cycles <= 1000:
        parser.error('--cycles must be in 1...1000')
    if not (math.isfinite(args.timeout) and args.timeout > 0 and args.timeout + 3 <= args.run_seconds):
        parser.error('require finite timeout > 0 and timeout + 3 <= run-seconds')
    args.out, args.elf, args.smoke_elf = args.out.resolve(), args.elf.resolve(), args.smoke_elf.resolve()
    return args


if __name__ == '__main__':
    sys.exit(execute(options()))
