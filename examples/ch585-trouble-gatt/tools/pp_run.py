#!/usr/bin/env python3
"""X3.4a PP round: flash the pp image, hold two Mac centrals, archive, restore smoke.

Both clients run `central --mode pp --role 1|2`: connect, read, subscribe, then
write a role-specific sequence until their timeout and count notifications.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / 'examples/ch585-trouble-gatt'

_spec = importlib.util.spec_from_file_location(
    'ch585_gatt_run', EXAMPLE / 'tools/run.py')
gatt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gatt)
io = gatt.io
PROBE = gatt.PROBE
NM = gatt.NM
stop_client = gatt.stop_client
read_client = gatt.read_client
wait_until = gatt.wait_until

DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
SMOKE = gatt.SMOKE
NAME = 'wch585-p4'
HOST_NAMES = gatt.HOST_NAMES
FAILURES = gatt.FAILURES

# Counters added by the pp loop; indices 54..58 are otherwise reserved.
PP_FRAGMENT_FAILURES = 54
PP_FRAGMENTS = 55
PP_SKIPS = 56
PP_CAPACITY_REJECTS = 57
PP_BACKGROUND_OVERRUNS = 58


def evaluate_client(role, rows, returncode, timeout):
    errors = []
    tag = f'role {role}'
    if returncode != 0:
        errors.append(f'{tag}: central exited with status {returncode}')
    if not rows:
        return errors + [f'{tag}: no client events']
    if rows[0].get('event') != 'start' or rows[0].get('role') != role:
        errors.append(f'{tag}: start row missing or wrong role')
    summary = next((row for row in reversed(rows) if row.get('event') == 'summary'), None)
    if summary is None:
        return errors + [f'{tag}: no summary']
    if summary.get('exit_code') != 0 or summary.get('reason') != 'pp_complete':
        errors.append(f'{tag}: summary {summary.get("reason")} exit {summary.get("exit_code")}')
    enabled = [row for row in rows if row.get('event') == 'notify_state' and row.get('enabled')]
    if len(enabled) != 1:
        errors.append(f'{tag}: expected exactly one CCCD enable')
    disconnects = [row for row in rows if row.get('event') == 'disconnected']
    if len(disconnects) != 1 or not disconnects[0].get('expected'):
        errors.append(f'{tag}: expected disconnect missing')
    if any(row.get('event') in ('error', 'write_timeout') for row in rows):
        errors.append(f'{tag}: client recorded an error/timeout event')
    writes = summary.get('writes', 0)
    notifications = summary.get('notifications', 0)
    if writes < 5:
        errors.append(f'{tag}: only {writes} acknowledged writes')
    # Both links receive every write, so notifications should exceed own writes.
    if notifications < writes:
        errors.append(f'{tag}: {notifications} notifications for {writes} writes')
    values = {row.get('value') for row in rows
              if row.get('event') == 'notification' and isinstance(row.get('value'), int)}
    peer = {value for value in values if value // 1000 != role}
    if not peer:
        errors.append(f'{tag}: no notification carried the other role\'s value')
    start = next((row['monotonic_seconds'] for row in rows if row.get('event') == 'connected'), None)
    end = next((row['monotonic_seconds'] for row in rows if row.get('event') == 'disconnected'), None)
    if start is None or end is None or end <= start:
        errors.append(f'{tag}: connected window is invalid')
    first = rows[0].get('monotonic_seconds')
    last = rows[-1].get('monotonic_seconds')
    if not all(isinstance(v, (int, float)) for v in (first, last)) or last - first > timeout:
        errors.append(f'{tag}: run exceeded the requested timeout')
    return errors, (start, end)


def evaluate_stats(stats, host, run_seconds):
    errors = []
    if len(stats) != 64:
        return ['invalid STATS size'], {}
    if stats[:3] != [0x50343538, 1, 9]:
        errors.append(f'firmware did not finish: magic/version/stage={stats[:3]}')
    for index in (22, 62, 63, PP_CAPACITY_REJECTS):
        if stats[index]:
            errors.append(f'firmware counter {index}={stats[index]}')
    if not stats[PP_FRAGMENTS]:
        errors.append('no advertising fragment was served')
    if len(host) != 16:
        return errors + ['invalid HOST_STATS size'], {}
    names = dict(zip(HOST_NAMES, host))
    if host[0] != 2:
        errors.append(f'host did not return to advertising (phase {host[0]})')
    if host[1] != 2:
        errors.append(f'host connections={host[1]}, expected 2')
    if host[2] != 2:
        errors.append(f'host disconnects={host[2]}, expected 2')
    if not host[4] or not host[5]:
        errors.append('host did not observe writes and notifications')
    if host[7] or host[8] or host[10]:
        errors.append('host errors/last_error/subscription are not clean')
    return errors, {
        'host': names,
        'pp_fragment_failures': stats[PP_FRAGMENT_FAILURES],
        'pp_fragments': stats[PP_FRAGMENTS],
        'pp_skips': stats[PP_SKIPS],
        'pp_capacity_rejects': stats[PP_CAPACITY_REJECTS],
        'pp_overruns': stats[PP_BACKGROUND_OVERRUNS],
    }


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {'probe': PROBE, 'scope': 'pp two-central plaintext GATT',
                            'run_seconds': args.run_seconds,
                            'client_seconds': args.client_seconds}
    clients, logs = [], []
    touched, safe_read_at, symbols = False, 0.0, None
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        _copy(args.elf, archived)
        _copy(args.smoke_elf, smoke)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        symbols = gatt.observation_symbols(nm_text, image)
        metadata['ram_layout'] = gatt.validate_ram_layout(image, symbols)
        embedded = gatt.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded
        if embedded != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={embedded}, but --run-seconds={args.run_seconds}')
        source, binary = args.out / 'central.swift', (args.out / 'central').resolve()
        _copy(EXAMPLE / 'tools' / 'central.swift', source)
        io.command(['swiftc', '-O', str(source), '-o', str(binary)],
                   args.out / 'central-build.log', timeout=180)
        touched = True
        try:
            io.flash(archived, args.out, 'pp', check_idle=False)
        finally:
            safe_read_at = time.monotonic() + embedded + 3
        for role in (1, 2):
            command = [str(binary), '--mode', 'pp', '--role', str(role),
                       '--timeout', str(args.client_seconds), '--name', NAME]
            (args.out / f'central-{role}.command.json').write_text(json.dumps(command) + '\n')
            log = (args.out / f'central-{role}.jsonl').open('w')
            logs.append(log)
            clients.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True))
        windows = {}
        for index, client in enumerate(clients):
            role = index + 1
            try:
                client.wait(timeout=args.client_seconds + 8)
            except subprocess.TimeoutExpired:
                errors.append(f'role {role}: exceeded timeout plus cleanup')
                stop_client(client)
            metadata[f'client_{role}_exit'] = client.returncode
            rows = read_client(args.out / f'central-{role}.jsonl')
            result = evaluate_client(role, rows, client.returncode, args.client_seconds)
            if isinstance(result, tuple):
                found, window = result
                errors.extend(found)
                windows[role] = window
            else:
                errors.extend(result)
        if len(windows) == 2:
            overlap = min(windows[1][1], windows[2][1]) - max(windows[1][0], windows[2][0])
            metadata['overlap_seconds'] = overlap
            if overlap <= 1:
                errors.append(f'links did not overlap ({overlap:.2f} s)')
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        for client in clients:
            try:
                stop_client(client)
            except FAILURES:
                pass
        for log in logs:
            log.close()
        if touched:
            while True:
                try:
                    wait_until(safe_read_at)
                    break
                except KeyboardInterrupt:
                    errors.append('interrupted while waiting for the finite firmware')
            observations = {}
            if symbols is not None and safe_read_at:
                for name, count, names in (('STATS', 64, gatt.STAT_NAMES),
                                           ('HOST_STATS', 16, HOST_NAMES)):
                    try:
                        words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
                        observations[name] = words
                        (args.out / f'{name.lower()}.json').write_text(
                            json.dumps(dict(zip(names, words)), indent=2) + '\n')
                    except FAILURES as error:
                        errors.append(f'{name} observations: {error}')
                found, detail = evaluate_stats(observations.get('STATS', []),
                                               observations.get('HOST_STATS', []),
                                               args.run_seconds)
                errors.extend(found)
                metadata['counters'] = detail
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


def _copy(source, target):
    target.write_bytes(Path(source).read_bytes())


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--run-seconds', type=int, choices=(25, 360), default=25)
    parser.add_argument('--client-seconds', type=float, default=16.0)
    return parser.parse_args(argv)


if __name__ == '__main__':
    sys.exit(execute(options()))
