#!/usr/bin/env python3
"""X4b HID keyboard acceptance: flash the secure HID firmware, drive the macOS
CoreBluetooth client, collect HID/secure/Host counters, then restore smoke.

The script never probes while RF may be running: it flashes through the
single-session preflight helper, runs the client first, and reads RAM only once
the embedded finite-run budget plus the cleanup margin elapsed. Failures are
kept as evidence and never retried automatically.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p4 = load('hid_p4_runner', ROOT / 'examples/ch585-trouble-gatt/tools/run.py')
secure = load('hid_secure_runner', ROOT / 'examples/ch585-trouble-gatt/tools/secure_run.py')
io, PROBE, NM = p4.io, p4.PROBE, p4.NM
SMOKE = p4.SMOKE
EXAMPLE = ROOT / 'examples/ch585-hid-keyboard'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-hid-keyboard'
CLIENT = EXAMPLE / 'tools/hid_host.swift'
PAIR_CLICK = EXAMPLE / 'tools/hid_pair_click.py'
STAT_NAMES = p4.STAT_NAMES
SEC_NAMES = secure.SEC_NAMES
SEC_MAGIC = secure.SEC_MAGIC

HID_MAGIC = 0x4849_4431
HID_NAMES = '''magic version reports_sent notify_errors subscription_edges led_writes
    led_value control_point_writes control_point_last protocol_mode protocol_mode_writes
    boot_input_sent report_map_reads hid_info_reads blocked_unencrypted last_error'''.split()
HOST_NAMES = '''phase connections disconnects security errors last_error
    advertise_attempts reserved_7 reserved_8 reserved_9 reserved_10 reserved_11
    reserved_12 reserved_13 reserved_14 reserved_15'''.split()
REQUIRED_SYMBOLS = ('STATS', 'HOST_STATS', 'HID_STATS', 'SECURE_STATS', 'SEC_DIAG',
                    'SEC_OPCODES', 'HOST_ERROR', 'BOND_STATS', 'BOND_ECHO',
                    'PERIPHERAL_ADDRESS', 'TRACE')
RUN_SECONDS_CHOICES = (60, 360)
SECURITY_ENCRYPTED = 3
FAILURES = (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt)


def validate_hid_buffers(image, symbols):
    """Shared observation-buffer checks plus the HID evidence buffer."""
    symbols = secure.validate_observation_buffers(image, symbols)
    sections = p4.p3.elf_sections(image)
    address, size = symbols['HID_STATS'], 16 * 4
    if (address % 4 or not 0x20000000 <= address < address + size <= 0x30000000
            or not any(section['flags'] & 3 == 3 and section['address'] <= address
                       and address + size <= section['address'] + section['size']
                       for section in sections)):
        raise ValueError('HID_STATS is not an aligned writable RAM observation buffer')
    return symbols


def client_rows(path):
    rows = []
    if not path.is_file():
        return rows
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            rows.append({'event': 'malformed', 'raw': line})
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def evaluate_client(rows, returncode, discover_only=False):
    """Byte-level evidence from the macOS client's JSONL transcript."""
    errors = []
    events = [row.get('event') for row in rows]
    summaries = [row for row in rows if row.get('event') == 'summary']
    if returncode != 0:
        errors.append(f'client exited with {returncode}')
    if len(summaries) != 1:
        errors.append(f'expected one client summary, found {len(summaries)}')
        return errors
    summary = summaries[0]
    reason = 'hid_discovery_ok' if discover_only else 'hid_reports_ok'
    if summary.get('exit_code') != 0 or summary.get('reason') != reason:
        errors.append(f'client summary is not {reason}: {summary.get("reason")}')
    if events.count('services_discovered') != 1:
        errors.append('HID service discovery did not complete exactly once')
    if events.count('characteristics_discovered') != 1:
        errors.append('HID characteristic discovery did not complete exactly once')
    if events.count('descriptor_read') != 2:
        errors.append(f'expected two Report Reference reads, got {events.count("descriptor_read")}')
    if events.count('read_result') < 3:
        errors.append('client did not read HID Information, Report Map and Protocol Mode')
    if events.count('error'):
        errors.append('client reported an error event')
    if discover_only:
        if summary.get('reports') != 0 or summary.get('writes') != 0:
            errors.append('discovery-only run produced reports or writes')
        return errors
    if summary.get('reports') != 8:
        errors.append(f'client verified {summary.get("reports")} reports, expected 8')
    if summary.get('boot_reports') != 2:
        errors.append(f'client verified {summary.get("boot_reports")} boot reports, expected 2')
    if (summary.get('writes') or 0) < 1:
        errors.append('client did not acknowledge the LED output write')
    if events.count('notification') != 8:
        errors.append(f'expected 8 report notifications, got {events.count("notification")}')
    if events.count('boot_notification') != 2:
        errors.append(f'expected 2 boot notifications, got {events.count("boot_notification")}')
    if events.count('notify_state') != 2:
        errors.append('client did not observe both subscription state changes')
    if events.count('write_sent') != 3:
        errors.append(f'expected 3 response-less writes, got {events.count("write_sent")}')
    return errors


def evaluate_firmware(hid, host, sec, stats, run_seconds, discover_only=False):
    """Firmware-side counters; gates are fixed, never relaxed after a failure."""
    errors = []
    if len(hid) != 16:
        return ['invalid HID_STATS size']
    if hid[0] != HID_MAGIC or hid[1] != 1:
        return [f'HID_STATS magic/version wrong: {hid[:2]}']
    index = HID_NAMES.index
    minimum = {'report_map_reads': 1, 'hid_info_reads': 1}
    if not discover_only:
        minimum.update({'reports_sent': 8, 'boot_input_sent': 2,
                        'subscription_edges': 2, 'led_writes': 1,
                        'control_point_writes': 2, 'protocol_mode_writes': 2})
    for name, count in minimum.items():
        if hid[index(name)] < count:
            errors.append(f'HID {name}={hid[index(name)]} < {count}')
    if hid[index('notify_errors')]:
        errors.append(f'HID notify_errors={hid[index("notify_errors")]}')
    if hid[index('last_error')]:
        errors.append(f'HID last_error={hid[index("last_error")]}')
    if not discover_only:
        if hid[index('led_value')] != 0x07:
            errors.append(f'HID led_value={hid[index("led_value")]}, expected 0x07')
        if hid[index('control_point_last')] != 1:
            errors.append(f'HID control_point_last={hid[index("control_point_last")]}, expected 1')
    if hid[index('protocol_mode')] != 1:
        errors.append(f'HID protocol_mode={hid[index("protocol_mode")]}, expected 1')

    if len(sec) != 16:
        errors.append('invalid SECURE_STATS size')
    elif sec[0] != SEC_MAGIC or sec[1] & 0xff != 1:
        errors.append(f'SECURE_STATS magic/version wrong: {sec[:2]}')
    else:
        flags = sec[1]
        if not flags & (1 << 8):
            errors.append('firmware did not pass the ADC entropy health check')
        if not flags & (1 << 9):
            errors.append('Host crypto RNG was not seeded')
        if not flags & (1 << 10):
            errors.append('controller DRBG was not seeded')
        for name, count in (('enc_req', 1), ('enc_rsp', 1), ('ltk_request', 1),
                            ('ltk_reply', 1), ('start_req', 1), ('start_rsp', 1),
                            ('encrypted_tx', 2), ('encrypted_rx', 2)):
            if sec[SEC_NAMES.index(name)] < count:
                errors.append(f'SECURE {name}={sec[SEC_NAMES.index(name)]} < {count}')
        if sec[SEC_NAMES.index('active')] != 1:
            errors.append(f'SECURE active={sec[SEC_NAMES.index("active")]}, expected 1')
        for name in ('mic_failure', 'errors', 'plaintext_start_retry'):
            if sec[SEC_NAMES.index(name)]:
                errors.append(f'SECURE {name}={sec[SEC_NAMES.index(name)]}')

    if len(host) != 16:
        errors.append('invalid HOST_STATS size')
    else:
        if host[HOST_NAMES.index('connections')] < 1:
            errors.append('Host did not accept a connection')
        if host[HOST_NAMES.index('disconnects')] < 1:
            errors.append('Host did not observe the disconnect')
        if host[HOST_NAMES.index('security')] != SECURITY_ENCRYPTED:
            errors.append(f'Host security state={host[HOST_NAMES.index("security")]}, '
                          f'expected {SECURITY_ENCRYPTED}')
        for name in ('errors', 'last_error'):
            if host[HOST_NAMES.index(name)]:
                errors.append(f'Host {name}={host[HOST_NAMES.index(name)]}')

    if len(stats) != 64:
        errors.append('invalid STATS size')
    else:
        if stats[:3] != [0x5034_3538, 1, 9]:
            errors.append(f'firmware did not finish: magic/version/stage={stats[:3]}')
        if stats[33] & 3 or stats[34] != 0x30000 or stats[22]:
            errors.append('RF stop was not clean (CMD/MODE/stop_err)')
        if not (run_seconds * 1_000_000 <= stats[32] <= (run_seconds + 3) * 1_000_000):
            errors.append('firmware runtime does not match the finite-run budget')
        if stats[14] < 1 or stats[15] < 1:
            errors.append(f'expected at least one connected link with data: {stats[14:16]}')
    return errors


def stop_client(client):
    if client is not None and client.poll() is None:
        client.terminate()
        try:
            client.wait(timeout=5)
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait(timeout=5)


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {
        'probe': PROBE,
        'scope': 'X4b HOGP keyboard on a Just Works encrypted link',
        'run_seconds': args.run_seconds, 'timeout': args.timeout,
        'discover_only': args.discover_only,
        'pair_click': args.pair_click,
        'air_ifs': 'UNMEASURED', 'mitm': 'not protected (Just Works)',
    }
    touched, safe_read_at, symbols = False, 0.0, None
    client = clicker = None
    client_log = client_err = None
    observations = {}
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        shutil.copyfile(args.elf, archived)
        shutil.copyfile(args.smoke_elf, smoke)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        symbols = p4.symbols_from(nm_text)
        for name in REQUIRED_SYMBOLS + ('RUN_SECONDS',):
            matches = [parts for line in nm_text.splitlines()
                       if len(parts := line.split()) == 3 and parts[2] == name]
            if len(matches) != 1:
                raise ValueError(f'missing or ambiguous {name} symbol')
            symbols[name] = int(matches[0][0], 16)
        symbols = validate_hid_buffers(image, symbols)
        # A plain `cargo build` after a secure build silently replaces the
        # same output path; refuse to spend a probe session on it.
        if '_embassy_crypto_aes128ecb_encrypt_blocks' not in nm_text:
            raise ValueError('ELF was not built with --features secure (no crypto backend)')
        metadata['symbols'] = symbols
        metadata['ram_layout'] = p4.validate_ram_layout(image, symbols)
        embedded = p4.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded
        if embedded != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={embedded}, requested {args.run_seconds}')
        if args.timeout + 3 > args.run_seconds:
            raise ValueError('--timeout plus the cleanup margin exceeds RUN_SECONDS')

        source = args.out / 'hid_host.swift'
        binary = (args.out / 'hid_host').resolve()
        shutil.copyfile(CLIENT, source)
        io.command(['swiftc', str(source), '-o', str(binary)],
                   args.out / 'client-build.log', timeout=180)

        touched = True
        try:
            # One retained probe session: halt, engine shutdown, idle checks,
            # verified download. The secure image needs more than the default.
            secure.flash(archived, args.out, 'test')
        finally:
            safe_read_at = time.monotonic() + embedded + 3

        if args.pair_click:
            clicker = subprocess.Popen(
                [sys.executable, str(PAIR_CLICK), '--seconds', str(args.timeout + 10)],
                stdout=(args.out / 'pair_click.log').open('w'),
                stderr=subprocess.STDOUT, text=True)
        client_args = [str(binary), '--timeout', str(args.timeout), '--hold', str(args.hold)]
        if args.discover_only:
            client_args.append('--discover-only')
        (args.out / 'client.command.json').write_text(json.dumps(client_args) + '\n')
        client_log = (args.out / 'hid_host.jsonl').open('w')
        client_err = (args.out / 'hid_host.stderr.log').open('w')
        client = subprocess.Popen(client_args, stdout=client_log, stderr=client_err, text=True)
        try:
            client.wait(timeout=args.timeout + 10)
        except subprocess.TimeoutExpired:
            errors.append('client exceeded timeout plus bounded cleanup')
        finally:
            client_log.close()
            client_err.close()
            client_log = client_err = None
        metadata['client_exit'] = client.returncode
        rows = client_rows(args.out / 'hid_host.jsonl')
        metadata['client_summary'] = next(
            (row for row in reversed(rows) if row.get('event') == 'summary'), None)
        errors.extend(evaluate_client(rows, client.returncode, args.discover_only))
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        try:
            stop_client(client)
            stop_client(clicker)
        except FAILURES as error:
            errors.append(f'client cleanup: {type(error).__name__}: {error}')
        for stream in (client_log, client_err):
            if stream is not None:
                stream.close()
        if touched:
            while True:
                try:
                    p4.wait_until(safe_read_at)
                    break
                except KeyboardInterrupt:
                    errors.append('interrupted while waiting for finite firmware; '
                                  'retaining safe-read deadline')
            if symbols is not None and safe_read_at:
                for name, count, names in (('STATS', 64, STAT_NAMES),
                                           ('HOST_STATS', 16, HOST_NAMES),
                                           ('HID_STATS', 16, HID_NAMES),
                                           ('SECURE_STATS', 16, SEC_NAMES)):
                    try:
                        words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
                        observations[name] = words
                        metadata[name.lower()] = dict(zip(names, words))
                        (args.out / f'{name.lower()}.json').write_text(
                            json.dumps(metadata[name.lower()], indent=2) + '\n')
                    except FAILURES as error:
                        errors.append(f'{name} observations: {error}')
                if all(name in observations for name in ('HID_STATS', 'HOST_STATS',
                                                        'SECURE_STATS', 'STATS')):
                    errors.extend(evaluate_firmware(
                        observations['HID_STATS'], observations['HOST_STATS'],
                        observations['SECURE_STATS'], observations['STATS'],
                        args.run_seconds, args.discover_only))
            try:
                io.flash(args.out / 'smoke.elf', args.out, 'restore')
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
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--run-seconds', type=int, choices=RUN_SECONDS_CHOICES, default=60)
    parser.add_argument('--timeout', type=float, default=45)
    parser.add_argument('--hold', type=float, default=6)
    parser.add_argument('--discover-only', action='store_true',
                        help='stop after service/characteristic/descriptor reads')
    parser.add_argument('--no-pair-click', dest='pair_click', action='store_false',
                        help='do not auto-click the macOS pairing dialog')
    return parser.parse_args(argv)


def main(argv=None):
    return execute(options(argv))


if __name__ == '__main__':
    sys.exit(main())
