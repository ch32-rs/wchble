#!/usr/bin/env python3
"""X4b HID keyboard acceptance: flash the secure HID firmware, drive the macOS
CoreBluetooth client over the vendor report mirror (Apple filters 0x1812 from
app discovery), collect HID/secure/Host counters, then restore smoke.

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
                    'CATT_STATS', 'PERIPHERAL_ADDRESS', 'TRACE', 'X1_STATS')
X1_NAMES = secure.X1_NAMES
RUN_SECONDS_CHOICES = (60, 360)
SECURITY_REQUESTED = 1
SECURITY_ENCRYPTED = 3
# 5 = Insufficient Authentication, 15 (0x0F) = Insufficient Encryption. Both
# prove a plaintext access was refused; which one CoreBluetooth surfaces
# depends on whether the firmware answered before or after its ATT timeout.
GATE_CODES = (5, 15)
FAILURES = (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt)


def validate_hid_buffers(image, symbols):
    """Shared observation-buffer checks plus the HID evidence buffer."""
    symbols = secure.validate_observation_buffers(
        image, symbols, extra=(('X1_STATS', 24),))
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


def evaluate_client(rows, returncode):
    """Discovery and security evidence from the macOS client's JSONL transcript.

    Apple filters the HID service out of CoreBluetooth discovery (Accessory
    Design Guidelines, GATT Server section), and bluetoothd checks an unsigned
    CLI in with fProgrammaticPairing 0. A protected access therefore ends in
    Insufficient Authentication (0x05) or Insufficient Encryption (0x0F) - the
    security gate. With 0x0F macOS can answer with a pairing attempt, whose
    LESC key agreement blocks the peripheral RF pump past the supervision
    timeout; the gate was already observed, so the client treats the following
    disconnect as the expected end of the run. If the Mac already holds a
    bond, the same client verifies the mirrored report bytes instead.
    """
    errors = []
    events = [row.get('event') for row in rows]
    summaries = [row for row in rows if row.get('event') == 'summary']
    if returncode != 0:
        errors.append(f'client exited with {returncode}')
    if len(summaries) != 1:
        errors.append(f'expected one client summary, found {len(summaries)}')
        return errors
    summary = summaries[0]
    reason = summary.get('reason')
    if summary.get('exit_code') != 0 or reason not in ('hid_mirror_ok', 'hid_security_gate_ok'):
        errors.append(f'client summary is not a passing reason: {reason}')
    if events.count('services_discovered') != 1:
        errors.append('vendor service discovery did not complete exactly once')
    if events.count('characteristics_discovered') != 1:
        errors.append('vendor characteristic discovery did not complete exactly once')
    if summary.get('hid_service_visible'):
        errors.append('HID service was visible to CoreBluetooth; Apple filters it')
    if events.count('error'):
        errors.append('client reported an error event')
    if reason == 'hid_security_gate_ok':
        if not summary.get('security_gate'):
            errors.append('security-gate summary lacks the gate marker')
        if events.count('security_gate') != 1:
            errors.append(f'expected one security gate event, got {events.count("security_gate")}')
        if summary.get('reports') != 0 or events.count('notification'):
            errors.append('unencrypted run delivered report notifications')
        if summary.get('gate_code') not in GATE_CODES:
            errors.append(f'security gate code={summary.get("gate_code")}, expected one of '
                          f'{sorted(GATE_CODES)} (Insufficient Authentication/Encryption)')
        return errors
    if events.count('read_result') < 1:
        errors.append('client did not read the mirror value')
    if events.count('notify_state') != 2:
        errors.append('client did not observe both mirror subscription state changes')
    if summary.get('reports') != 8:
        errors.append(f'client verified {summary.get("reports")} reports, expected 8')
    if events.count('notification') != 8:
        errors.append(f'expected 8 mirror notifications, got {events.count("notification")}')
    return errors


def evaluate_firmware(hid, host, sec, stats, run_seconds, mirror_mode):
    """Firmware-side counters; gates are fixed, never relaxed after a failure.

    mirror_mode is the bonded-host path (protected access succeeded, reports
    verified). Without a bond the macOS run must show the security gate: the
    peripheral requested security, no SMP/encryption completed, and no report
    left the device on the unencrypted link.
    """
    errors = []
    if len(hid) != 16:
        return ['invalid HID_STATS size']
    if hid[0] != HID_MAGIC or hid[1] != 1:
        return [f'HID_STATS magic/version wrong: {hid[:2]}']
    index = HID_NAMES.index
    if hid[index('notify_errors')]:
        errors.append(f'HID notify_errors={hid[index("notify_errors")]}')
    if hid[index('last_error')]:
        errors.append(f'HID last_error={hid[index("last_error")]}')
    if hid[index('protocol_mode')] != 1:
        errors.append(f'HID protocol_mode={hid[index("protocol_mode")]}, expected 1')
    if mirror_mode:
        if hid[index('subscription_edges')] < 1:
            errors.append(f'HID subscription_edges={hid[index("subscription_edges")]} < 1')
    else:
        if hid[index('subscription_edges')]:
            errors.append(f'HID subscription_edges={hid[index("subscription_edges")]} on a gated link')
        for name in ('reports_sent', 'boot_input_sent'):
            if hid[index(name)]:
                errors.append(f'HID {name}={hid[index(name)]} on an unencrypted link')
        if hid[index('blocked_unencrypted')] < 1:
            errors.append('HID blocked_unencrypted=0; the report tick never observed a plain link')

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
        if mirror_mode:
            for name, count in (('enc_req', 1), ('enc_rsp', 1), ('ltk_request', 1),
                                ('ltk_reply', 1), ('start_req', 1), ('start_rsp', 1),
                                ('encrypted_tx', 2), ('encrypted_rx', 2)):
                if sec[SEC_NAMES.index(name)] < count:
                    errors.append(f'SECURE {name}={sec[SEC_NAMES.index(name)]} < {count}')
            if sec[SEC_NAMES.index('active')] != 1:
                errors.append(f'SECURE active={sec[SEC_NAMES.index("active")]}, expected 1')
        else:
            for name in ('enc_req', 'enc_rsp', 'start_req', 'start_rsp', 'active',
                         'encrypted_tx', 'encrypted_rx'):
                if sec[SEC_NAMES.index(name)]:
                    errors.append(f'SECURE {name}={sec[SEC_NAMES.index(name)]} without a bond')
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
        expected_security = SECURITY_ENCRYPTED if mirror_mode else SECURITY_REQUESTED
        if host[HOST_NAMES.index('security')] != expected_security:
            errors.append(f'Host security state={host[HOST_NAMES.index("security")]}, '
                          f'expected {expected_security}')
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
        'scope': 'X4b HOGP keyboard report bytes through the vendor mirror on '
                 'a Just Works encrypted link (Apple filters 0x1812)',
        'run_seconds': args.run_seconds, 'timeout': args.timeout,
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
        mirror_mode = (metadata['client_summary'] or {}).get('reason') == 'hid_mirror_ok'
        metadata['mirror_mode'] = mirror_mode
        errors.extend(evaluate_client(rows, client.returncode))
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
                                           ('SECURE_STATS', 16, SEC_NAMES),
                                           ('X1_STATS', 24, X1_NAMES),
                                           ('CATT_STATS', 16, secure.CATT_NAMES),
                                           ('BOND_STATS', 32, secure.BOND_NAMES)):
                    try:
                        words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
                        observations[name] = words
                        metadata[name.lower()] = dict(zip(names, words))
                        (args.out / f'{name.lower()}.json').write_text(
                            json.dumps(metadata[name.lower()], indent=2) + '\n')
                    except FAILURES as error:
                        errors.append(f'{name} observations: {error}')
                if all(name in observations for name in ('HID_STATS', 'HOST_STATS',
                                                        'SECURE_STATS', 'STATS',
                                                        'X1_STATS')):
                    errors.extend(evaluate_firmware(
                        observations['HID_STATS'], observations['HOST_STATS'],
                        observations['SECURE_STATS'], observations['STATS'],
                        args.run_seconds, mirror_mode))
                    errors.extend(secure.evaluate_x1(observations['X1_STATS'],
                                                     args.require_dle))
                # SMP/ATT start-fragment counts and the RF-pump diagnostics:
                # they show whether macOS answered the 0x0F with a pairing
                # attempt (the LESC stall is what loses the link).
                try:
                    opcodes = secure.decode_opcodes(io.read32(
                        symbols['SEC_OPCODES'], 96, args.out / 'sec_opcodes.txt'))
                    diag = io.read32(symbols['SEC_DIAG'], 64, args.out / 'sec_diag.txt')
                    opcodes['slow_polls_over_100ms'] = diag[36]
                    opcodes['skipped_events'] = diag[37]
                    metadata['sec_opcodes'] = opcodes
                    (args.out / 'sec_opcodes.json').write_text(
                        json.dumps(opcodes, indent=2) + '\n')
                except FAILURES as error:
                    errors.append(f'SEC_OPCODES observations: {error}')
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
    parser.add_argument('--require-dle', action='store_true',
                        help='require observed >27-byte PDUs and a fragmented Host packet')
    parser.add_argument('--run-seconds', type=int, choices=RUN_SECONDS_CHOICES, default=60)
    parser.add_argument('--timeout', type=float, default=50)
    # The firmware sends its peripheral Security Request 10 s after the link
    # comes up. Holding the first protected access past that deadline keeps
    # the request and the macOS pairing attempt (triggered by the 0x0F answer)
    # from racing, so the run records `Host security == 1` before the gate.
    parser.add_argument('--hold', type=float, default=11)
    parser.add_argument('--no-pair-click', dest='pair_click', action='store_false',
                        help='do not auto-click the macOS pairing dialog')
    return parser.parse_args(argv)


def main(argv=None):
    return execute(options(argv))


if __name__ == '__main__':
    sys.exit(main())
