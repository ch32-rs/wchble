#!/usr/bin/env python3
"""X3.5a CP round: DUT central -> android-gatt fixture, archive, restore smoke.

The DUT image advertises for the peripheral role but no Mac central connects in
this round; the only traffic is the DUT's outbound central link to the phone.
Hardware policy is inherited from the P4 runner: fixed probe, one retained
preflight session before every flash, no probe access while RF may run, and the
full RUN_SECONDS + 3 s wait before any read. Failures are never retried.
"""
import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / 'examples/ch585-trouble-gatt'
sys.path.insert(0, str(EXAMPLE / 'tools'))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gatt = _load('ch585_gatt_run', EXAMPLE / 'tools/run.py')
c1 = _load('ch585_c1_run', ROOT / 'examples/ch585-central/tools/run.py')
io, PROBE, NM = gatt.io, gatt.PROBE, gatt.NM
SMOKE = gatt.SMOKE
wait_until = gatt.wait_until
FAILURES = gatt.FAILURES

DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
STAT_NAMES = gatt.STAT_NAMES
HOST_NAMES = gatt.HOST_NAMES
# Engine stat slots (wchble::ll::link) this round gates on.
FIRST_ANCHOR = 15
EVENTS = 16
RX_DONE = 7
TX_LATE = 19
CONNECT_FAIL = 30
TARGET_NAME = 'wch585-c1'


def evaluate(host, stats):
    errors = []
    phase, connections, disconnects = host[0], host[1], host[2]
    reads, writes, notifications = host[3], host[4], host[5]
    subscribed, host_errors = host[10], host[7]
    if phase == 0xff:
        errors.append('host entered the fatal phase')
    if connections < 1:
        errors.append('host never reported a connection')
    if disconnects < 1:
        errors.append('host never reported a clean disconnect')
    if reads < 2:
        errors.append(f'host saw {reads} reads, expected the initial and read-back')
    if writes < 1:
        errors.append('host never wrote the value')
    if subscribed < 1:
        errors.append('host never subscribed to the value characteristic')
    if notifications < 1:
        errors.append('host never received a notification')
    if host_errors or host[8]:
        errors.append(f'host errors={host_errors} last_error={host[8]}')
    if stats[FIRST_ANCHOR] == 0:
        errors.append('central engine never published (FIRST_ANCHOR=0)')
    if stats[EVENTS] == 0:
        errors.append('central engine ran no connection events')
    if stats[RX_DONE] == 0:
        errors.append('central engine received no packets')
    if stats[TX_LATE] != 0:
        errors.append(f'TX_LATE={stats[TX_LATE]} (must be 0)')
    if stats[CONNECT_FAIL] != 0:
        errors.append(f'CONNECT_FAIL={stats[CONNECT_FAIL]}')
    return errors


def evaluate_phone(rows):
    errors = []
    events = lambda name: [row for row in rows if row.get('event') == name]
    if not events('start') or not events('advertising'):
        errors.append('phone never started advertising')
    if not events('connected'):
        errors.append('phone never reported a connection')
    cccd = events('cccd_write')
    if not any(row.get('subscribed') for row in cccd):
        errors.append(f'phone saw no CCCD subscription ({len(cccd)} writes)')
    values = [row.get('value') for row in events('write')]
    if 0x2b not in values:
        errors.append(f'phone never saw the 0x2b write (saw {values})')
    sent = [row for row in events('notify') if row.get('sent')]
    if not sent:
        errors.append('phone sent no successful notification')
    reads = [row.get('value') for row in events('read')]
    if 0x2a not in reads:
        errors.append(f'phone never served the initial 0x2a read (saw {reads})')
    if 0x2b not in reads:
        errors.append(f'phone never served the 0x2b read-back (saw {reads})')
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors = []
    metadata = {
        'probe': PROBE,
        'round': 'X3.5a',
        'run_seconds': args.run_seconds,
        'target': TARGET_NAME,
        'restart': 'verified idle then debug boot; not a power cycle',
    }
    phone = None
    touched = False
    safe_read_at = 0.0
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        shutil.copyfile(args.elf, archived)
        shutil.copyfile(args.smoke_elf, smoke)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([NM, str(archived)], args.out / 'symbols.txt')
        symbols = gatt.observation_symbols(nm_text, image)
        metadata['symbols'] = symbols
        metadata['ram_layout'] = gatt.validate_ram_layout(image, symbols)
        embedded = gatt.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded
        if embedded != args.run_seconds:
            raise ValueError(
                f'ELF RUN_SECONDS={embedded}, but --run-seconds={args.run_seconds}')

        # The phone must already advertise when the DUT boots and scans.
        phone = c1.AndroidSource(args.out, TARGET_NAME, False, 0)
        phone.name = TARGET_NAME
        phone.start(timeout=args.phone_timeout)
        time.sleep(1.0)

        touched = True
        try:
            io.flash(archived, args.out, 'test', check_idle=False)
        finally:
            safe_read_at = time.monotonic() + embedded + 3

        wait_until(safe_read_at)
        observations = {}
        for name, count, names in (('STATS', 64, STAT_NAMES),
                                   ('HOST_STATS', len(HOST_NAMES), HOST_NAMES)):
            words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
            observations[name] = words
            metadata[name.lower()] = dict(zip(names, words))
            (args.out / f'{name.lower()}.json').write_text(
                json.dumps(metadata[name.lower()], indent=2) + '\n')
        host = observations.get('HOST_STATS', [])
        stats = observations.get('STATS', [])
        if len(stats) != 64 or len(host) != len(HOST_NAMES):
            errors.append(f'short STATS read: {len(stats)}/{len(host)}')
        else:
            errors.extend(evaluate(host, stats))
        if 'SEC_DIAG' in symbols:
            diag = io.read32(symbols['SEC_DIAG'], 64, args.out / 'sec_diag.txt')
            (args.out / 'sec_diag.json').write_text(json.dumps(diag) + '\n')
            metadata['sec_diag'] = diag
            (args.out / 'diag2.txt').write_text(
                ' '.join(f'{word:08x}' for word in diag) + '\n')
        try:
            count = min(stats[39], 128) * 8 if len(stats) == 64 else 0
            words = io.read32(symbols['TRACE'], count, args.out / 'trace.txt') if count else []
            if not count:
                (args.out / 'trace.txt').write_text('')
            trace = gatt.ordered_trace(words, stats[39]) if len(stats) == 64 else {'unordered_words': words}
            (args.out / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
        except FAILURES as error:
            errors.append(f'TRACE observations: {error}')
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        if phone is not None:
            try:
                phone.stop()
                time.sleep(0.5)
                errors.extend(evaluate_phone(phone.logs()))
            except FAILURES as error:
                errors.append(f'phone cleanup/evaluation: {type(error).__name__}: {error}')
        if touched:
            try:
                io.flash(args.out / 'smoke.elf', args.out, 'restore', check_idle=False)
                io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                           args.out / 'restore-scan.log', 20)
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
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--run-seconds', type=int, default=25)
    parser.add_argument('--phone-timeout', type=int, default=90)
    return parser.parse_args(argv)


if __name__ == '__main__':
    sys.exit(execute(options()))
