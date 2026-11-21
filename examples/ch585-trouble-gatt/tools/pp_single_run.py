#!/usr/bin/env python3
"""X3.6 single-slot regression: the `pp` image with one Mac central.

The two-slot image must not depend on the second slot: one gatt client connects,
runs the P4 transcript, and disconnects while the image keeps advertising.
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
io, PROBE, NM = gatt.io, gatt.PROBE, gatt.NM
ext = _load('ch585_ext_adv_run', EXAMPLE / 'tools/ext_adv_run.py')
SMOKE = gatt.SMOKE
wait_until = gatt.wait_until
read_client, stop_client = gatt.read_client, gatt.stop_client
FAILURES = gatt.FAILURES
STAT_NAMES, HOST_NAMES = gatt.STAT_NAMES, gatt.HOST_NAMES
EXT_APK = ext.APK
EXT_PACKAGE = ext.PACKAGE

DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
NAME = 'wch585-p4'
# PP background counters (example-owned slots, seen in pp_run.py).
PP_FRAGMENT_FAILURES, PP_FRAGMENTS, PP_SKIPS = 45, 46, 47
PP_BACKGROUND_OVERRUNS = 34
FIRST_ANCHOR, EVENTS, RX_DONE, TX_LATE, CONNECT_FAIL = 15, 16, 7, 19, 30
# Slot 39 (DIAG_START_RSP_QUEUED) is cfg'd out under `pp` and reused as the
# TRACE row count, matching secure_run's decode contract.
TRACE_COUNT = 39


def evaluate_stats(obs, host, cycles):
    errors = []
    if len(obs) != 64 or len(host) != 16:
        return [f'short STATS read: {len(obs)}/{len(host)}']
    if obs[:3] != [0x50343538, 1, 9]:
        errors.append(f'image did not finish: magic/version/stage={obs[:3]}')
    for index in (62, 63):
        if obs[index]:
            errors.append(f'{STAT_NAMES[index]}={obs[index]}')
    if obs[FIRST_ANCHOR] == 0:
        errors.append('engine never published (FIRST_ANCHOR=0)')
    if obs[EVENTS] == 0:
        errors.append('engine ran no connection events')
    if obs[RX_DONE] == 0:
        errors.append('engine received no packets')
    if obs[TX_LATE] != 0:
        errors.append(f'TX_LATE={obs[TX_LATE]} (must be 0)')
    if obs[PP_BACKGROUND_OVERRUNS] != 0:
        errors.append(f'PP background overruns={obs[PP_BACKGROUND_OVERRUNS]} (must be 0)')
    if obs[CONNECT_FAIL] != 0:
        errors.append(f'CONNECT_FAIL={obs[CONNECT_FAIL]}')
    phase, connections, disconnects = host[0], host[1], host[2]
    if phase == 0xff:
        errors.append('host entered the fatal phase')
    if connections != 1 or disconnects != 1:
        errors.append(f'host connections/disconnects={connections}/{disconnects}, expected 1/1')
    if host[3] < 5 * cycles or host[4] < 13 * cycles or host[5] < 10 * cycles:
        errors.append('host did not serve every requested read/write/notification')
    if host[7] or host[8]:
        errors.append(f'host errors={host[7]} last_error={host[8]}')
    # The pp app leaves STAT_SUBSCRIBED at zero; the Mac transcript's
    # subscriptions=2 and notifications=10 already prove the CCCD path.
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors = []
    metadata = {
        'probe': PROBE,
        'round': 'X3.6-pp-single',
        'run_seconds': args.run_seconds,
        'cycles': args.cycles,
        'restart': 'verified idle then debug boot; not a power cycle',
    }
    client = None
    log = stderr_log = None
    scan_started = None
    touched = False
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        shutil.copyfile(args.elf, archived)
        shutil.copyfile(args.smoke_elf, smoke)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([NM, str(archived)], args.out / 'symbols.txt')
        symbols = (ext.observation_symbols(nm_text) if args.coex
                   else gatt.observation_symbols(nm_text, image))
        metadata['symbols'] = symbols
        metadata['ram_layout'] = (ext.validate_ram_layout(image, symbols) if args.coex
                                  else gatt.validate_ram_layout(image, symbols))
        embedded = gatt.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded
        if embedded != args.run_seconds:
            raise ValueError(
                f'ELF RUN_SECONDS={embedded}, but --run-seconds={args.run_seconds}')

        source, binary = args.out / 'central.swift', (args.out / 'central').resolve()
        shutil.copyfile(EXAMPLE / 'tools/central.swift', source)
        io.command(['swiftc', str(source), '-o', str(binary)],
                   args.out / 'central-build.log', timeout=120)

        touched = True
        try:
            if args.coex:
                ext.secure.adb(args.serial, 'get-state')
                ext.secure.adb(args.serial, 'install', '-g', '-r', str(EXT_APK), timeout=120)
                ext.secure.adb(args.serial, 'shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
                ext.secure.adb(args.serial, 'shell', 'wm', 'dismiss-keyguard')
                ext.secure.adb(args.serial, 'shell', 'logcat', '-c')
            io.flash(archived, args.out, 'test', check_idle=False)
        finally:
            safe_read_at = time.monotonic() + embedded + 3
        if args.coex:
            ext.secure.adb(args.serial, 'shell', 'am', 'start', '-n',
                           f'{EXT_PACKAGE}/.MainActivity', '--es', 'mode', 'ext_scan')
            scan_started = time.monotonic()
            metadata['phone_scan_started'] = True

        client_args = [str(binary), '--cycles', str(args.cycles),
                       '--timeout', str(args.timeout), '--name', NAME]
        (args.out / 'central.command.json').write_text(json.dumps(client_args) + '\n')
        log, stderr_log = (args.out / 'central.jsonl').open('w'), \
            (args.out / 'central.stderr.log').open('w')
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
        metadata['client_summary'] = next(
            (row for row in reversed(rows) if row.get('event') == 'summary'), None)
        errors.extend(gatt.evaluate_client(rows, args.cycles, args.timeout, client.returncode))
        if args.coex:
            wait_until(scan_started + 22)
            phone_log = ext.secure.adb(args.serial, 'logcat', '-d', '-s', 'WCHBLE', timeout=60)
            (args.out / 'phone-logcat.txt').write_text(phone_log)
            phone_errors, phone_detail = ext.read_ext_logcat(
                args.out / 'phone-logcat.txt', 'x2-ext-adv-coex')
            metadata['phone'] = phone_detail
            errors.extend(phone_errors)

        wait_until(safe_read_at)
        observations = {}
        for name, count, names in (('STATS', 64, STAT_NAMES),
                                   ('HOST_STATS', 16, HOST_NAMES)):
            words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
            observations[name] = words
            metadata[name.lower()] = dict(zip(names, words))
            (args.out / f'{name.lower()}.json').write_text(
                json.dumps(metadata[name.lower()], indent=2) + '\n')
        host = observations.get('HOST_STATS', [])
        stats = observations.get('STATS', [])
        if 'TRACE' in symbols and len(stats) == 64:
            # Rows 0..127 linear, then a 64-row ring survives; decode with the
            # count so a long run still yields its latest 64 rows in order.
            trace_rows = ext.secure.decode_trace(
                io.read32(symbols['TRACE'], 128 * 8, args.out / 'trace.txt'),
                stats[TRACE_COUNT])
            metadata['trace'] = trace_rows
            (args.out / 'trace.json').write_text(
                json.dumps(trace_rows, indent=2) + '\n')
        errors.extend(evaluate_stats(stats, host, args.cycles))
        if len(stats) == 64:
            metadata['pp_bridge'] = {
                'fragment_failures': stats[PP_FRAGMENT_FAILURES],
                'fragments': stats[PP_FRAGMENTS],
                'skips': stats[PP_SKIPS],
                'overruns': stats[PP_BACKGROUND_OVERRUNS],
            }
        if args.coex:
            ext_words = io.read32(symbols['EXT_ADV_STATS'], 16,
                                  args.out / 'ext_adv_stats.txt')
            metadata['ext_adv_stats'] = dict(zip(ext.EXT_NAMES, ext_words))
            errors.extend(ext.evaluate_ext(ext_words, 'x2-ext-adv-coex'))
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        if args.coex:
            try:
                ext.secure.adb(args.serial, 'shell', 'am', 'force-stop', EXT_PACKAGE, timeout=15)
            except (OSError, subprocess.SubprocessError):
                pass
        try:
            stop_client(client)
        except FAILURES as error:
            errors.append(f'client cleanup: {type(error).__name__}: {error}')
        for stream in (log, stderr_log):
            if stream is not None:
                stream.close()
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
    parser.add_argument('--cycles', type=int, default=1)
    parser.add_argument('--timeout', type=float, default=20)
    parser.add_argument('--coex', action='store_true',
                        help='run Android ext_scan concurrently with the Mac GATT central; ELF must use x2-ext-adv-coex')
    parser.add_argument('--serial', default=ext.ADB_SERIAL)
    return parser.parse_args(argv)


if __name__ == '__main__':
    sys.exit(execute(options()))
