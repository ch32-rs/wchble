#!/usr/bin/env python3
"""X3.5b CP round: DUT runs peripheral and central in the same round.

The DUT advertises as `wch585-p4` and scans for the Android fixture
`wch585-c1`; the Mac `central --mode gatt` drives the P4 transcript on the
peripheral link while the phone serves the central link. The phone must be
advertising before the image boots because the app's scanner has no retry.

`--no-phone` runs the same image without the phone: the only live link is the
Mac one and the outbound scan/initiate must not disturb it.
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
cp = _load('ch585_cp_run', EXAMPLE / 'tools/cp_run.py')
c1 = _load('ch585_c1_run', ROOT / 'examples/ch585-central/tools/run.py')
io, PROBE, NM = gatt.io, gatt.PROBE, gatt.NM
SMOKE = gatt.SMOKE
wait_until = gatt.wait_until
read_client, stop_client = gatt.read_client, gatt.stop_client
FAILURES = gatt.FAILURES
STAT_NAMES, HOST_NAMES = gatt.STAT_NAMES, gatt.HOST_NAMES

DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
NAME = 'wch585-p4'
PHONE_NAME = 'wch585-c1'
FIRST_ANCHOR, EVENTS, RX_DONE = cp.FIRST_ANCHOR, cp.EVENTS, cp.RX_DONE
TX_LATE, CONNECT_FAIL = cp.TX_LATE, cp.CONNECT_FAIL


def evaluate_stats(obs, host, phone_expected, cycles):
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
    if obs[CONNECT_FAIL] != 0:
        errors.append(f'CONNECT_FAIL={obs[CONNECT_FAIL]}')
    connections, disconnects = host[1], host[2]
    errors += gatt_evaluate_host(host, phone_expected)
    expected = 2 if phone_expected else 1
    if connections < expected:
        errors.append(f'host connections={connections}, expected >= {expected}')
    if disconnects < expected:
        errors.append(f'host disconnects={disconnects}, expected >= {expected}')
    # The Mac gatt cycle alone accounts for these peripheral-side counters.
    if host[3] < 5 * cycles or host[4] < 13 * cycles or host[5] < 10 * cycles:
        errors.append('host did not serve every requested read/write/notification')
    if phone_expected:
        if host[10] < 1:
            errors.append('host never saw the CCCD subscription')
    return errors


def gatt_evaluate_host(host, phone_expected):
    errors = []
    if host[0] == 0xff:
        errors.append('host entered the fatal phase')
    if phone_expected:
        if host[7] or host[8]:
            errors.append(f'host errors={host[7]} last_error={host[8]}')
    else:
        # The absent fixture must surface as one scanner timeout, nothing else.
        if host[7] != 1 or host[8] != 3:
            errors.append(
                f'host errors={host[7]} last_error={host[8]}, expected one stage-3 scan timeout')
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors = []
    metadata = {
        'probe': PROBE,
        'round': 'X3.5b',
        'run_seconds': args.run_seconds,
        'cycles': args.cycles,
        'phone': not args.no_phone,
        'phone_after_mac': args.phone_after_mac,
        'restart': 'verified idle then debug boot; not a power cycle',
    }
    phone = None
    client = None
    log = stderr_log = None
    touched = False
    safe_read_at = 0.0
    symbols = None
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

        source, binary = args.out / 'central.swift', (args.out / 'central').resolve()
        shutil.copyfile(EXAMPLE / 'tools/central.swift', source)
        io.command(['swiftc', str(source), '-o', str(binary)],
                   args.out / 'central-build.log', timeout=120)

        if not args.no_phone and not args.phone_after_mac:
            phone = c1.AndroidSource(args.out, PHONE_NAME, False, 0)
            phone.name = PHONE_NAME
            phone.start(timeout=args.phone_timeout)
            time.sleep(1.0)

        touched = True
        try:
            io.flash(archived, args.out, 'test', check_idle=False)
        finally:
            safe_read_at = time.monotonic() + embedded + 3

        client_args = [str(binary), '--cycles', str(args.cycles),
                       '--timeout', str(args.timeout), '--name', NAME]
        (args.out / 'central.command.json').write_text(json.dumps(client_args) + '\n')
        log, stderr_log = (args.out / 'central.jsonl').open('w'), \
            (args.out / 'central.stderr.log').open('w')
        client = subprocess.Popen(client_args, stdout=log, stderr=stderr_log, text=True)
        if args.phone_after_mac:
            # Reverse-order round: the peripheral link must exist before the
            # phone appears, so the DUT connects outbound with a live link.
            deadline = time.monotonic() + args.phone_delay
            while time.monotonic() < deadline and not mac_connected(args.out):
                time.sleep(0.2)
            metadata['phone_started_after_mac_connected'] = mac_connected(args.out)
            phone = c1.AndroidSource(args.out, PHONE_NAME, False, 0)
            phone.name = PHONE_NAME
            phone.start(timeout=args.phone_timeout)
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
        if args.no_phone:
            errors += evaluate_isolated_client(rows, client.returncode)
        else:
            errors += gatt.evaluate_client(rows, args.cycles, args.timeout, client.returncode)

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
        errors += evaluate_stats(stats, host, not args.no_phone, args.cycles)
        if 'SEC_DIAG' in symbols:
            diag = io.read32(symbols['SEC_DIAG'], 64, args.out / 'sec_diag.txt')
            metadata['sec_diag'] = diag
            (args.out / 'sec_diag.json').write_text(json.dumps(diag) + '\n')
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
        try:
            stop_client(client)
        except FAILURES as error:
            errors.append(f'client cleanup: {type(error).__name__}: {error}')
        for stream in (log, stderr_log):
            if stream is not None:
                stream.close()
        if phone is not None:
            try:
                phone.stop()
                time.sleep(0.5)
                errors.extend(cp.evaluate_phone(phone.logs()))
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


def mac_connected(out):
    """Tolerate the client's partially written last line while polling."""
    try:
        text = (out / 'central.jsonl').read_text()
    except OSError:
        return False
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict) and row.get('event') == 'connected':
            return True
    return False


def evaluate_isolated_client(rows, returncode):
    """The Mac link is the only link; the outbound scan must leave it intact."""
    errors = []
    if returncode != 0:
        errors.append(f'central exited with status {returncode}')
    summaries = [row for row in rows if row.get('event') == 'summary']
    if len(summaries) != 1 or summaries[0].get('reason') != 'cycles_complete':
        errors.append('central did not complete its cycles')
    if any(row.get('event') in ('error', 'write_timeout') for row in rows):
        errors.append('central recorded an error/timeout event')
    return errors


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--run-seconds', type=int, default=25)
    parser.add_argument('--cycles', type=int, default=1)
    parser.add_argument('--timeout', type=float, default=20)
    parser.add_argument('--phone-timeout', type=int, default=90)
    parser.add_argument('--no-phone', action='store_true')
    parser.add_argument('--phone-after-mac', action='store_true')
    parser.add_argument('--phone-delay', type=float, default=10.0)
    return parser.parse_args(argv)


if __name__ == '__main__':
    sys.exit(execute(options()))
