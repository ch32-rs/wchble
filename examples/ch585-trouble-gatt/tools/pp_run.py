#!/usr/bin/env python3
"""X3.4a PP round: flash the pp image, hold two centrals, archive, restore smoke.

The default hybrid round pairs the Mac `central --mode pp --role 1` with the
adb-driven `dev.wchble.probe` phone app (role 2 over the NUS pipe). With
`--no-phone` both centrals are Mac clients, the earlier two-laptop shape.
"""
import argparse
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / 'examples/ch585-trouble-gatt'
sys.path.insert(0, str(EXAMPLE / 'tools'))
import secure_run as secure  # noqa: E402

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

# Phone probe: the same apk used for the pairing work, pointed at the pp app's
# random address and the NUS pipe. Its 4-byte write carries role 2.
PROBE_APK = ROOT / 'local-docs/research/android-probe/build/wchble-probe.apk'
PROBE_PACKAGE = 'dev.wchble.probe'
PROBE_ACTIVITY = PROBE_PACKAGE + '/.ProbeActivity'
PP_ADDRESS = 'C1:FF:EE:00:00:1A'
MAC_ROLE = 1
PHONE_ROLE = 2
PHONE_PAYLOAD = struct.pack('<I', PHONE_ROLE * 1000 + 1).hex()

# pp-loop counters in slots the legacy paths never write under `pp`.
PP_CAPACITY_REJECTS = 33
PP_BACKGROUND_OVERRUNS = 34
PP_FRAGMENT_FAILURES = 45
PP_FRAGMENTS = 46
PP_SKIPS = 47


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


def adb(serial, *args, **kwargs):
    try:
        return secure.adb(serial, *args, **kwargs)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or '').strip()
        raise RuntimeError(f'adb {" ".join(args[:3])} failed: {detail}') from error


def start_phone(serial, repeats, repeat_ms, hold_ms, scan_ms, timeout_ms):
    adb(serial, 'shell', 'am', 'force-stop', PROBE_PACKAGE)
    adb(serial, 'logcat', '-c')
    adb(serial, 'shell', 'am', 'start', '-W', '-n', PROBE_ACTIVITY,
        '--es', 'addr', PP_ADDRESS,
        '--es', 'payload', PHONE_PAYLOAD,
        '--ez', 'subscribe', 'true',
        '--ei', 'repeats', str(repeats),
        '--el', 'repeat_ms', str(repeat_ms),
        '--el', 'hold_ms', str(hold_ms),
        '--el', 'scan_ms', str(scan_ms),
        '--el', 'timeout_ms', str(timeout_ms))


def phone_rows(serial):
    text = adb(serial, 'logcat', '-d', '-s', 'WCHBLE:I', timeout=60)
    return secure.read_log(text.splitlines())


def await_phone_summary(serial, seconds=6.0):
    """The probe writes and holds after the Mac leaves; wait for its summary."""
    deadline = time.monotonic() + seconds
    rows = phone_rows(serial)
    while not any(row.get('event') == 'summary' for row in rows):
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)
        rows = phone_rows(serial)
    return rows


PHONE_FATAL = {'watchdog', 'scan_timeout', 'scan_failed', 'no_bluetooth',
               'no_scanner', 'connect_gatt_null', 'bad_address', 'no_service',
               'no_cccd'}


def wait_phone_connected(serial, timeout):
    """Poll logcat until the probe reports a live connection or a fatal exit."""
    deadline = time.monotonic() + timeout
    while True:
        rows = phone_rows(serial)
        events = {row.get('event') for row in rows}
        if any(row.get('event') == 'connection' and row.get('state') == 2
               for row in rows):
            return rows, True
        if events & PHONE_FATAL or time.monotonic() >= deadline:
            return rows, False
        time.sleep(0.5)


def decode_le_hex(text):
    try:
        raw = bytes.fromhex(text or '')
    except ValueError:
        return None
    return int.from_bytes(raw, 'little') if raw else None


def evaluate_phone(rows, repeats):
    """The phone's own logcat proof: connected over NUS, wrote, saw the Mac."""
    errors = []
    if not rows:
        return ['phone: no probe events']
    fatal = [row.get('event') for row in rows if row.get('event') in PHONE_FATAL]
    if any(row.get('event') == 'connection' and row.get('state') == 2
           for row in rows):
        # The probe's scan timer keeps running past the match; only a scan
        # that never matched is fatal.
        fatal = [event for event in fatal if event != 'scan_timeout']
    if fatal:
        errors.append(f'phone: fatal events {fatal}')
    start = next((row for row in rows if row.get('event') == 'start'), None)
    if (start is None or start.get('addr') != PP_ADDRESS
            or not start.get('subscribe')):
        errors.append('phone: start row missing, wrong address, or unsubscribed')
    connections = [row for row in rows
                   if row.get('event') == 'connection' and row.get('state') == 2]
    if len(connections) != 1:
        errors.append(f'phone: saw {len(connections)} connected states')
    services = next((row for row in rows if row.get('event') == 'services'), None)
    if services is None or services.get('status') != 0:
        errors.append('phone: service discovery did not succeed')
    chars = next((row for row in rows if row.get('event') == 'characteristics'), None)
    if chars is None or not chars.get('rx') or not chars.get('tx'):
        errors.append('phone: NUS RX/TX not both present')
    subscribe = next((row for row in rows
                      if row.get('event') == 'subscribe_local'), None)
    if subscribe is None or not subscribe.get('ok'):
        errors.append('phone: local notify enable failed')
    cccd = [row for row in rows if row.get('event') == 'cccd_write']
    if len(cccd) != 1 or cccd[0].get('status') != 0:
        errors.append(f'phone: CCCD write rows {cccd}')
    requested = [row for row in rows if row.get('event') == 'write_requested']
    if any(not row.get('ok') for row in requested):
        errors.append('phone: a write request was refused')
    callbacks = [row for row in rows if row.get('event') == 'write_callback']
    if any(row.get('status') != 0 for row in callbacks):
        errors.append('phone: a write callback reported an error')
    if len(callbacks) < repeats:
        errors.append(f'phone: {len(callbacks)} acknowledged writes, expected {repeats}')
    notifications = [decode_le_hex(row.get('hex')) for row in rows
                     if row.get('event') == 'notification']
    peer = [value for value in notifications
            if value is not None and value // 1000 == MAC_ROLE]
    summary = next((row for row in reversed(rows) if row.get('event') == 'summary'), None)
    if summary is None:
        errors.append('phone: no summary')
    elif not summary.get('notifications'):
        errors.append('phone: summary counted no notifications')
    if not peer:
        errors.append('phone: no notification carried the Mac role\'s value')
    if not any(row.get('event') == 'disconnect' for row in rows):
        errors.append('phone: no disconnect event')
    return errors, {'writes': len(callbacks), 'notifications': len(notifications),
                    'mac_values': sorted(set(peer))}


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
    if len(host) != len(HOST_NAMES):
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
    shape = 'mac+phone NUS' if args.phone else 'mac+mac'
    # The phone preflight eats flash-relative seconds; keep the Mac inside the
    # finite firmware window.
    client_seconds = min(args.client_seconds, 12.0) if args.phone else args.client_seconds
    errors, metadata = [], {'probe': PROBE,
                            'scope': f'pp two-central plaintext GATT ({shape})',
                            'serial': args.serial if args.phone else None,
                            'run_seconds': args.run_seconds,
                            'client_seconds': client_seconds}
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
        # Install and unlock before the flash: the firmware window starts at
        # flash return, so no adb install may eat into it.
        if args.phone:
            if not args.probe_apk.is_file():
                raise ValueError(f'probe apk missing: {args.probe_apk}')
            adb(args.serial, 'get-state')
            adb(args.serial, 'shell', 'am', 'force-stop', PROBE_PACKAGE)
            adb(args.serial, 'install', '-g', '-r', str(args.probe_apk), timeout=120)
            adb(args.serial, 'shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
            adb(args.serial, 'shell', 'wm', 'dismiss-keyguard')
            adb(args.serial, 'shell', 'svc', 'power', 'stayon', 'true')
        touched = True
        try:
            io.flash(archived, args.out, 'pp', check_idle=False)
        finally:
            flash_at = time.monotonic()
            safe_read_at = flash_at + embedded + 3
        phone_connected = False
        if args.phone:
            phone_started_at = time.monotonic()
            scan_ms = int(args.phone_scan_seconds * 1000)
            start_phone(args.serial, args.phone_repeats, args.phone_repeat_ms,
                        args.phone_hold_ms, scan_ms, args.phone_timeout_ms)
            metadata['phone_payload'] = PHONE_PAYLOAD
            connected_rows, phone_connected = wait_phone_connected(
                args.serial, args.phone_scan_seconds + 3)
            (args.out / 'phone-preflight.jsonl').write_text(
                '\n'.join(json.dumps(row, sort_keys=True) for row in connected_rows) + '\n')
            metadata['phone_connected_before_mac'] = phone_connected
            if not phone_connected:
                errors.append('phone did not connect before the Mac client started')
        roles = (MAC_ROLE,) if args.phone else (1, 2)
        mac_started_at = time.monotonic()
        if args.phone:
            metadata['mac_start_after_flash_s'] = round(mac_started_at - flash_at, 2)
        for role in roles:
            command = [str(binary), '--mode', 'pp', '--role', str(role),
                       '--timeout', str(client_seconds), '--name', NAME]
            (args.out / f'central-{role}.command.json').write_text(json.dumps(command) + '\n')
            log = (args.out / f'central-{role}.jsonl').open('w')
            logs.append(log)
            clients.append(subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True))
        windows = {}
        for index, client in enumerate(clients):
            role = roles[index]
            try:
                client.wait(timeout=client_seconds + 8)
            except subprocess.TimeoutExpired:
                errors.append(f'role {role}: exceeded timeout plus cleanup')
                stop_client(client)
            metadata[f'client_{role}_exit'] = client.returncode
            rows = read_client(args.out / f'central-{role}.jsonl')
            result = evaluate_client(role, rows, client.returncode, client_seconds)
            if isinstance(result, tuple):
                found, window = result
                errors.extend(found)
                windows[role] = window
                if args.phone and window[0] is not None and window[1] is not None:
                    # central.swift stamps absolute uptime; anchor on its own
                    # first row so only durations cross the two clocks.
                    origin = rows[0].get('monotonic_seconds', 0)
                    offset = mac_started_at - flash_at
                    metadata[f'client_{role}_window_after_flash_s'] = [
                        round(offset + window[0] - origin, 2),
                        round(offset + window[1] - origin, 2)]
            else:
                errors.extend(result)
        if args.phone:
            rows = await_phone_summary(args.serial)
            (args.out / 'phone.jsonl').write_text(
                '\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n')
            result = evaluate_phone(rows, args.phone_repeats)
            if isinstance(result, tuple):
                found, detail = result
                errors.extend(found)
                metadata['phone'] = detail
            else:
                errors.extend(result)
            if phone_connected:
                # Log-relative offsets from flash, so a short window can be
                # told apart from a protocol failure.
                offset = phone_started_at - flash_at
                marks = []
                for event, state in (('connection', 2), ('disconnect', None)):
                    row = next((row for row in rows if row.get('event') == event
                                and (state is None or row.get('state') == state)), None)
                    if row is not None and isinstance(row.get('elapsed_ms'), (int, float)):
                        marks.append(round(offset + row['elapsed_ms'] / 1000, 2))
                metadata['phone_window_after_flash_s'] = marks
            # Live-link fan-out is proven by cross-observed values, not by
            # comparing two unsynchronised clocks.
            metadata['overlap_seconds'] = None
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
        if args.phone:
            try:
                adb(args.serial, 'shell', 'am', 'force-stop', PROBE_PACKAGE,
                    timeout=15)
            except FAILURES:
                pass
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
                                           ('HOST_STATS', len(HOST_NAMES), HOST_NAMES)):
                    try:
                        words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
                        observations[name] = words
                        (args.out / f'{name.lower()}.json').write_text(
                            json.dumps(dict(zip(names, words)), indent=2) + '\n')
                    except FAILURES as error:
                        errors.append(f'{name} observations: {error}')
                if 'SEC_DIAG' in symbols:
                    # The HCI rings name the commands behind a silent slot,
                    # e.g. whether a second LE Set Advertising Enable landed.
                    try:
                        diagnostic = io.read32(symbols['SEC_DIAG'], 64,
                                               args.out / 'sec_diag.txt')
                        metadata['sec_diag'] = {
                            'hci_failure': diagnostic[40],
                            'hci_log': diagnostic[41:49],
                            'hci_log_len': diagnostic[49],
                            'hci_sent': diagnostic[50:58],
                            'hci_sent_len': diagnostic[58],
                        }
                    except FAILURES as error:
                        errors.append(f'SEC_DIAG observations: {error}')
                if 'TRACE' in symbols:
                    try:
                        words = io.read32(symbols['TRACE'], 128 * 8,
                                          args.out / 'trace.txt')
                    except FAILURES as error:
                        errors.append(f'TRACE observations: {error}')
                    else:
                        rows = []
                        for index in range(128):
                            row = words[index * 8:index * 8 + 8]
                            if not any(row):
                                continue
                            rows.append({
                                'slot': index, 'now_us': row[0], 'kind': row[1],
                                'event': row[2] & 0xffff, 'channel': row[3] & 0xff,
                                'header': row[4] & 0xff, 'len': row[5] & 0xff,
                                'a': row[6], 'b': row[7],
                            })
                        rows.sort(key=lambda row: row['now_us'])
                        (args.out / 'trace.jsonl').write_text(
                            '\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n')
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
    parser.add_argument('--no-phone', dest='phone', action='store_false',
                        help='use two Mac clients instead of the adb phone probe')
    parser.add_argument('--serial', default=secure.ADB_SERIAL)
    parser.add_argument('--probe-apk', type=Path, default=PROBE_APK)
    # A write plus its notification takes ~450 ms, so 20 repeats plus the hold
    # end near 14 s, inside the Mac's 12 s window and the 25 s image.
    parser.add_argument('--phone-repeats', type=int, default=20)
    parser.add_argument('--phone-repeat-ms', type=int, default=300)
    parser.add_argument('--phone-hold-ms', type=int, default=3000)
    # The Host needs ~4 s after flash before it advertises at all.
    parser.add_argument('--phone-scan-seconds', type=float, default=8.0)
    parser.add_argument('--phone-timeout-ms', type=int, default=24000)
    return parser.parse_args(argv)


if __name__ == '__main__':
    sys.exit(execute(options()))
