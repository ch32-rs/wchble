#!/usr/bin/env python3
"""S2 secure run: flash the encrypted firmware, drive an Android pairing and
encrypted GATT read/write, collect SECURE_STATS + logcat, then restore smoke.

The script never probes while RF may be running: it flashes through the
single-session preflight helper, launches the phone app afterwards, and reads
RAM only once the embedded finite-run budget plus the cleanup margin elapsed.
"""
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
    'ch585_p4_runner', ROOT / 'examples/ch585-trouble-gatt/tools/run.py')
p4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p4)
io, PROBE, NM = p4.io, p4.PROBE, p4.NM

EXAMPLE = ROOT / 'examples/ch585-trouble-gatt'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
APK = EXAMPLE / 'tools/android-pair/build/android-pair.apk'
PACKAGE = 'com.example.wchble.pair'
ACTIVITY = PACKAGE + '/.MainActivity'
ADB_SERIAL = '55VS4H8TRW45KVQS'
SMOKE = p4.SMOKE

SEC_MAGIC = 0x5332_3538
SEC_NAMES = '''magic version_flags enc_req enc_rsp ltk_request ltk_reply
    start_req start_rsp encrypted_tx encrypted_rx active mic_failure errors prepared
    plaintext_start_retry last_error'''.split()
HOST_NAMES = p4.HOST_NAMES
STAT_NAMES = p4.STAT_NAMES
FAILURES = (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt)

SECURITY_ENCRYPTED = 3


def symbols_from(text):
    symbols = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in 'TtDdBbRr':
            symbols[parts[2]] = int(parts[0], 16)
    return symbols


def validate_observation_buffers(image, symbols):
    sections = p4.p3.elf_sections(image)
    ranges = []
    for name, count in (('STATS', 64), ('HOST_STATS', 16), ('SECURE_STATS', 16),
                        ('TRACE', 128 * 8)):
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


def adb(serial, *args, timeout=30):
    return subprocess.run(['adb', '-s', serial, *args], capture_output=True, text=True,
                          timeout=timeout, check=True).stdout


def read_log(lines):
    rows = []
    for line in lines:
        index = line.find('WCHBLE')
        if index < 0:
            continue
        start, end = line.find('{', index), line.rfind('}')
        if start < 0 or end < start:
            continue
        try:
            row = json.loads(line[start:end + 1])
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def evaluate_transcript(rows):
    errors = []
    events = [row.get('event') for row in rows]
    summaries = [row for row in rows if row.get('event') == 'summary']
    if len(summaries) != 1:
        return [f'expected exactly one app summary, saw {len(summaries)}: {events}']
    summary = summaries[0]
    if summary.get('pass') is not True or summary.get('reason') != 'encrypted_read_write_ok':
        errors.append(f'app summary is not a pass: {summary}')
    if summary.get('bonded') is not True:
        errors.append('app summary did not observe a completed bond')
    for required in ('scan_started', 'found', 'connecting', 'connection_state',
                     'bond_requested', 'bond_state', 'services_discovered',
                     'encrypted_gatt_start', 'read', 'write_requested', 'write_ack'):
        if required not in events:
            errors.append(f'app transcript is missing {required}')
    bond_states = [row.get('state') for row in rows if row.get('event') == 'bond_state']
    if 12 not in bond_states:  # BOND_BONDED
        errors.append(f'bond state never reached BOND_BONDED: {bond_states}')
    reads = [row for row in rows if row.get('event') == 'read' and row.get('status') == 0]
    if not reads or reads[0].get('value') != 0:
        errors.append(f'first encrypted read did not return the initial value 0: {reads[:1]}')
    if len(reads) < 2 or reads[-1].get('value') != 43:
        errors.append(f'read-back after write did not return 43: {reads}')
    writes = [row for row in rows if row.get('event') == 'write_ack' and row.get('status') == 0]
    if not writes:
        errors.append('no successful ATT write response')
    return errors


def evaluate_security(sec, host, stats, run_seconds):
    errors = []
    if len(sec) != 16:
        return ['invalid SECURE_STATS size']
    if sec[0] != SEC_MAGIC or sec[1] & 0xff != 1:
        return [f'SECURE_STATS magic/version wrong: {sec[:2]}']
    flags = sec[1]
    if not flags & (1 << 8):
        errors.append('firmware did not pass the ADC entropy health check')
    if not flags & (1 << 9):
        errors.append('Host crypto RNG was not seeded')
    if not flags & (1 << 10):
        errors.append('controller DRBG was not seeded')
    minimum = {2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 2, 9: 2}
    for index, count in minimum.items():
        if sec[index] < count:
            errors.append(f'{SEC_NAMES[index]}={sec[index]} < {count}')
    if sec[10] != 1:
        errors.append(f'encryption became active {sec[10]} times, expected 1')
    if sec[11]:
        errors.append(f'MIC failures: {sec[11]}')
    if sec[12]:
        errors.append(f'encryption errors: {sec[12]} (last 0x{sec[15]:02x})')
    if sec[14]:
        errors.append(f'plaintext START_ENC_REQ retransmissions: {sec[14]}')
    if len(host) != 16:
        errors.append('invalid HOST_STATS size')
    elif host[15] != SECURITY_ENCRYPTED:
        errors.append(f'Host security state={host[15]}, expected encrypted ({SECURITY_ENCRYPTED})')
    if len(stats) == 64:
        if stats[:3] != [0x5034_3538, 1, 9]:
            errors.append(f'firmware did not finish: magic/version/stage={stats[:3]}')
        if stats[33] & 3 or stats[34] != 0x30000 or stats[22]:
            errors.append('RF stop was not clean (CMD/MODE/stop_err)')
        if not (run_seconds * 1_000_000 <= stats[32] <= (run_seconds + 3) * 1_000_000):
            errors.append('firmware runtime does not match the finite-run budget')
        if stats[14] != 1 or stats[15] != 1:
            errors.append(f'expected one connected link with data: {stats[14:16]}')
    else:
        errors.append('invalid STATS size')
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {
        'probe': PROBE, 'scope': 'S2 Just Works pairing + encrypted GATT',
        'run_seconds': args.run_seconds, 'timeout': args.timeout,
        'air_ifs': 'UNMEASURED', 'mitm': 'not protected (Just Works)',
    }
    touched, safe_read_at, symbols = False, 0.0, None
    log = None
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        shutil.copyfile(args.elf, archived)
        shutil.copyfile(args.smoke_elf, smoke)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        symbols = validate_observation_buffers(image, symbols_from(nm_text))
        metadata['symbols'] = symbols
        metadata['ram_layout'] = p4.validate_ram_layout(image, symbols)
        embedded_seconds = p4.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded_seconds
        if embedded_seconds != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={embedded_seconds}, requested {args.run_seconds}')

        if args.build_apk:
            io.command([str(APK.parent.parent / 'build.sh')], args.out / 'apk-build.log', timeout=180)
        if not APK.is_file():
            raise ValueError(f'missing APK: {APK}')
        metadata['apk_sha256'] = hashlib.sha256(APK.read_bytes()).hexdigest()
        metadata['adb_serial'] = args.serial
        adb(args.serial, 'get-state')
        adb(args.serial, 'install', '-g', '-r', str(APK), timeout=120)

        touched = True
        try:
            # One retained probe session: halt, engine shutdown, idle checks,
            # verified download.
            io.flash(archived, args.out, 'test', check_idle=False)
        finally:
            safe_read_at = time.monotonic() + embedded_seconds + 3

        adb(args.serial, 'logcat', '-c')
        adb(args.serial, 'shell', 'am', 'force-stop', PACKAGE)
        adb(args.serial, 'shell', 'am', 'start', '-W', '-n', ACTIVITY)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            pid = adb(args.serial, 'shell', 'pidof', PACKAGE).strip()
            if not pid:
                break
            time.sleep(0.5)
        else:
            errors.append('phone app did not finish within its timeout')
        log_path = args.out / 'logcat.txt'
        log_path.write_text(adb(args.serial, 'logcat', '-d', '-s', 'WCHBLE:I', timeout=60))
        rows = read_log(log_path.read_text().splitlines())
        (args.out / 'transcript.jsonl').write_text(
            '\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n')
        metadata['client_summary'] = next(
            (row for row in reversed(rows) if row.get('event') == 'summary'), None)
        errors.extend(evaluate_transcript(rows))

        io.wait_until(safe_read_at)
        observations = {}
        for name, count, names in (('STATS', 64, STAT_NAMES),
                                   ('HOST_STATS', 16, HOST_NAMES),
                                   ('SECURE_STATS', 16, SEC_NAMES)):
            words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
            observations[name] = words
            metadata[name.lower()] = dict(zip(names, words))
            (args.out / f'{name.lower()}.json').write_text(
                json.dumps(metadata[name.lower()], indent=2) + '\n')
        errors.extend(evaluate_security(observations.get('SECURE_STATS', []),
                                        observations.get('HOST_STATS', []),
                                        observations.get('STATS', []), args.run_seconds))

        try:
            io.flash(smoke, args.out, 'restore', check_idle=False)
            io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                       args.out / 'restore-scan.log', 20)
            metadata['smoke_recovery'] = 'flash verify and exact-name macOS discovery PASS'
        except FAILURES as error:
            errors.append(f'recovery: {error}')
            metadata['smoke_recovery'] = 'NOT VERIFIED'
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        if log is not None:
            log.close()
        metadata['errors'], metadata['passed'] = errors, not errors
        metadata['smoke_recovery'] = metadata.get('smoke_recovery',
                                                   'NOT ATTEMPTED' if not touched else 'NOT VERIFIED')
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
    parser.add_argument('--serial', default=ADB_SERIAL)
    parser.add_argument('--run-seconds', type=int, default=25)
    parser.add_argument('--timeout', type=float, default=45)
    parser.add_argument('--build-apk', action='store_true')
    args = parser.parse_args(argv)
    if not (math.isfinite(args.timeout) and 0 < args.timeout <= args.run_seconds):
        parser.error('require finite timeout <= run-seconds')
    args.out, args.elf, args.smoke_elf = (args.out.resolve(), args.elf.resolve(),
                                          args.smoke_elf.resolve())
    return args


if __name__ == '__main__':
    sys.exit(execute(options()))
