#!/usr/bin/env python3
"""X4b Android system-HID acceptance.

Flashes the secure finite image, drives the shared `android-pair` helper in
`hid` mode (bond, then HID Information/Report Map/Protocol Mode and the exact
input-report cycle at app level), waits for the system HID host to register an
input device, reads the firmware counters, and always restores the smoke image.

The app taps the Just Works dialog through the runner: on ROMs whose pairing
window is short, pass `--pair-tap X,Y` with the Pair button coordinates
(CPH2411 / 1080x2400: 786,2121); otherwise the uiautomator dump is used.
"""
import argparse
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p4 = load('x4b_hid_p4', ROOT / 'examples/ch585-trouble-gatt/tools/run.py')
secure = load('x4b_hid_secure', ROOT / 'examples/ch585-trouble-gatt/tools/secure_run.py')
hid = load('x4b_hid_run', ROOT / 'examples/ch585-hid-keyboard/tools/hid_run.py')
io = p4.io

EXAMPLE = ROOT / 'examples/ch585-hid-keyboard'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-hid-keyboard'
APK = ROOT / 'examples/ch585-trouble-gatt/tools/android-pair/build/android-pair.apk'
PACKAGE = 'com.example.wchble.pair'
ACTIVITY = PACKAGE + '/.MainActivity'
SERIAL = '55VS4H8TRW45KVQS'
TARGET = 'wch585-hid'
ACTIVE = 1
SECURITY_ENCRYPTED = 3
FAILURES = (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt)
REQUIRED_SYMBOLS = ('STATS', 'HOST_STATS', 'HID_STATS', 'SECURE_STATS', 'RUN_SECONDS')


def adb(*args, check=True, timeout=30):
    # Logcat buffers are not guaranteed UTF-8; replace bytes instead of dying.
    return subprocess.run(['adb', '-s', SERIAL, *args], capture_output=True, text=True,
                          encoding='utf-8', errors='replace',
                          timeout=timeout, check=check).stdout


def tap_settings_connect(out):
    """Open Bluetooth Settings and tap the paired keyboard once.

    Android's HID host only opens its own GATT client when Settings (or a
    previous HID session) asks it to; a bonded peer does not get an automatic
    background connection after a reboot. Settings is the deterministic
    trigger, so the runner drives it through the uiautomator dump.
    """
    adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
    adb('shell', 'wm', 'dismiss-keyguard')
    adb('shell', 'am', 'force-stop', 'com.android.settings')
    time.sleep(1)
    adb('shell', 'am', 'start', '-W', '-a', 'android.settings.BLUETOOTH_SETTINGS',
        timeout=60)
    pattern = re.compile(r'text="' + re.escape(TARGET)
                         + r'"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"')
    for _ in range(12):
        try:
            adb('shell', 'uiautomator', 'dump', '/sdcard/wchble-bt-ui.xml',
                timeout=30)
            dump = adb('shell', 'cat', '/sdcard/wchble-bt-ui.xml', timeout=30)
        except subprocess.CalledProcessError:
            time.sleep(1)
            continue
        match = pattern.search(dump)
        if match:
            x1, y1, x2, y2 = (int(part) for part in match.groups())
            adb('shell', 'input', 'tap', str((x1 + x2) // 2), str((y1 + y2) // 2))
            print('SETTINGS tap', (x1 + x2) // 2, (y1 + y2) // 2, flush=True)
            return True
        time.sleep(1)
    return False


def parse_rows(logcat):
    rows = []
    for line in logcat.splitlines():
        index = line.find('WCHBLE')
        if index < 0:
            continue
        start, end = line.find('{', index), line.rfind('}')
        if 0 <= start < end:
            try:
                rows.append(json.loads(line[start:end + 1]))
            except json.JSONDecodeError:
                continue
    return rows


def evaluate_transcript(rows, dumpsys):
    errors = []
    summaries = [row for row in rows if row.get('event') == 'summary']
    if len(summaries) != 1:
        errors.append(f'expected one app summary, found {len(summaries)}')
        return errors
    summary = summaries[0]
    reason = summary.get('reason')
    if not summary.get('pass') or reason not in ('hid_reports_ok', 'hid_system_input_ok'):
        errors.append(f'app summary is not a HID success: {summary}')
    events = [row.get('event') for row in rows]
    service = [row for row in rows if row.get('event') == 'hid_service']
    if (len(service) != 1 or not service[0].get('service')
            or not service[0].get('notify_report')
            or service[0].get('characteristics') != 8
            or service[0].get('reports') != 2):
        errors.append(f'HID service not usable by the app: {service}')
    if reason == 'hid_system_input_ok':
        # Stock Android refuses HID-service access to third-party apps; the
        # app proves the platform gate and then verifies the OS input device.
        if not any(row.get('event') == 'hid_access_denied' for row in rows):
            errors.append('expected hid_access_denied for the unprivileged HID path')
        if not any(row.get('event') == 'input_device' for row in rows):
            errors.append('app did not observe a system input device for wch585-hid')
    else:
        reads = {}
        for row in rows:
            if row.get('event') == 'hid_read':
                reads[row.get('field')] = row
        for field in ('hid_info', 'report_map', 'protocol_mode'):
            row = reads.get(field)
            if row is None or row.get('status') != 0:
                errors.append(f'{field} was not read successfully: {row}')
        if (reads.get('hid_info') or {}).get('bytes') != '11010001':
            errors.append('HID Information bytes differ from 11010001')
        if (reads.get('report_map') or {}).get('length') != 63:
            errors.append('Report Map length is not 63')
        if events.count('notification') < 8:
            errors.append(f'app received {events.count("notification")} reports, expected >= 8')
        cccd = [row for row in rows if row.get('event') == 'cccd_write']
        if len(cccd) != 1 or cccd[0].get('status') != 0:
            errors.append(f'report CCCD write missing or failed: {cccd}')
    if TARGET not in dumpsys:
        errors.append('dumpsys input does not list wch585-hid')
    if events.count('error'):
        errors.append('app reported an error event')
    return errors


def evaluate_firmware(stats_words, host, sec, stats, run_seconds, expect):
    errors = []
    if len(stats_words) != 16 or stats_words[0] != hid.HID_MAGIC or stats_words[1] != 1:
        return [f'HID_STATS magic/version wrong: {stats_words[:2]}']
    index = hid.HID_NAMES.index
    if expect == 'payload':
        # Fresh-bond round: the system HID host performs its own discovery and
        # subscribes to the input report CCCD.
        for name, count in (('reports_sent', 8), ('subscription_edges', 1)):
            if stats_words[index(name)] < count:
                errors.append(f'HID {name}={stats_words[index(name)]} < {count}')
    else:
        # App round: an unprivileged app cannot read the HID service, so the
        # payload counters come from the separate fresh-bond round.
        if stats_words[index('reports_sent')] and not stats_words[index('subscription_edges')]:
            errors.append('HID reports were sent without a subscription edge')
    for name in ('notify_errors', 'last_error'):
        if stats_words[index(name)]:
            errors.append(f'HID {name}={stats_words[index(name)]}')
    if stats_words[index('protocol_mode')] != 1:
        errors.append(f'HID protocol_mode={stats_words[index("protocol_mode")]}, expected 1')

    if len(sec) != 16 or sec[0] != hid.SEC_MAGIC:
        errors.append('invalid SECURE_STATS')
    else:
        if sec[1] & 0xff != 1:
            errors.append(f'SECURE_STATS version={sec[1] & 0xff}')
        for bit, label in ((8, 'entropy health'), (9, 'Host RNG seed'), (10, 'DRBG seed')):
            if not sec[1] & (1 << bit):
                errors.append(f'SECURE flags missing {label}')
        # The app round intentionally has two clients (the helper app and the
        # system HID host), so encryption can become active once per connection.
        # The single-client S2/S3 fixture keeps its exact-one rule separately.
        if sec[hidex('active')] < ACTIVE:
            errors.append(f'SECURE active={sec[hidex("active")]}, expected at least 1')
        for name in ('enc_req', 'enc_rsp', 'start_req', 'start_rsp'):
            if sec[hidex(name)] < 1:
                errors.append(f'SECURE {name}={sec[hidex(name)]} < 1')
        if sec[hidex('encrypted_tx')] < (2 if expect == 'payload' else 1):
            errors.append(f'SECURE encrypted_tx={sec[hidex("encrypted_tx")]} is below the {expect} floor')
        for name in ('mic_failure', 'errors', 'plaintext_start_retry'):
            if sec[hidex(name)]:
                errors.append(f'SECURE {name}={sec[hidex(name)]}')

    if len(host) != 16:
        errors.append('invalid HOST_STATS')
    else:
        hindex = hid.HOST_NAMES.index
        if host[hindex('connections')] < 1:
            errors.append('Host did not accept a connection')
        if host[hindex('security')] != SECURITY_ENCRYPTED:
            errors.append(f'Host security={host[hindex("security")]}, expected encrypted')
        for name in ('errors', 'last_error'):
            if host[hindex(name)]:
                errors.append(f'Host {name}={host[hindex(name)]}')

    if len(stats) != 64:
        errors.append('invalid STATS')
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


def hidex(name):
    return hid.SEC_NAMES.index(name)


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=p4.SMOKE)
    parser.add_argument('--nm', default=p4.NM)
    parser.add_argument('--serial', default=SERIAL)
    parser.add_argument('--run-seconds', type=int, choices=(60, 360), default=60)
    parser.add_argument('--timeout', type=float, default=40)
    parser.add_argument('--pair-tap', default=None,
                        help='fast Pair-button coordinates X,Y instead of uiautomator')
    parser.add_argument('--wipe-bond', action='store_true',
                        help='write DEL! over the plaintext vendor control first '
                             '(requires --features secure,accept-control)')
    parser.add_argument('--bt-reset', action='store_true',
                        help='cycle the adapter after the app so the HID host '
                             'reconnects with a fresh client and subscribes')
    parser.add_argument('--settings-connect', action='store_true',
                        help='tap the paired keyboard in Bluetooth Settings so '
                             'the system HID host opens its own GATT client')
    parser.add_argument('--expect', choices=('app', 'payload'), default='app',
                        help='app: OS input-device recognition (bonded peer); '
                             'payload: encrypted report flow on a fresh bond')
    parser.add_argument('--settle-seconds', type=float, default=15,
                        help='wait after the app exits for the system HID host')
    return parser.parse_args(argv)


def execute(args):
    global SERIAL
    SERIAL = args.serial
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {'scope': 'X4b HOGP keyboard via the Android system HID host',
                            'target': TARGET, 'serial': SERIAL,
                            'air_ifs': 'UNMEASURED', 'mitm': 'not protected (Just Works)'}
    touched, safe_read_at, symbols = False, 0.0, None
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        archived.write_bytes(args.elf.read_bytes())
        smoke.write_bytes(args.smoke_elf.read_bytes())
        nm_text = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        # secure.symbols_from enforces the observation/RAM/highcode symbols.
        symbols = secure.symbols_from(nm_text)
        named = {}
        for line in nm_text.splitlines():
            parts = line.split()
            if len(parts) == 3:
                named.setdefault(parts[2], []).append(int(parts[0], 16))
        for name in REQUIRED_SYMBOLS:
            if len(named.get(name, [])) != 1:
                raise ValueError(f'missing or ambiguous {name} symbol')
            symbols[name] = named[name][0]
        for name in ('SEC_DIAG', 'SEC_OPCODES', 'HOST_ERROR', 'BOND_STATS',
                     'BOND_ECHO', 'PERIPHERAL_ADDRESS', 'TRACE'):
            if len(named.get(name, [])) != 1:
                raise ValueError(f'missing or ambiguous {name} symbol')
            symbols[name] = named[name][0]
        symbols = hid.validate_hid_buffers(archived.read_bytes(), symbols)
        if '_embassy_crypto_aes128ecb_encrypt_blocks' not in nm_text:
            raise ValueError('ELF was not built with --features secure (no crypto backend)')
        if args.wipe_bond and 'BOND_ACCEPT_CONTROL_BUILD' not in named:
            raise ValueError('--wipe-bond needs an ELF built with '
                             '--features secure,accept-control')
        run_seconds = p4.embedded_u32(archived.read_bytes(), symbols['RUN_SECONDS'])
        if run_seconds != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={run_seconds}, requested {args.run_seconds}')
        metadata['embedded_run_seconds'] = run_seconds
        if not APK.is_file():
            raise ValueError(f'missing APK: {APK}')
        adb('get-state')
        adb('install', '-g', '-r', str(APK), timeout=120)

        touched = True
        try:
            secure.flash(archived, args.out, 'test')
        finally:
            safe_read_at = time.monotonic() + run_seconds + 3

        if args.wipe_bond:
            # The Host keys bonds by peer address only. When the phone lost its
            # half of an old bond but the firmware kept it, a fresh pairing dies
            # in PairingFailed; drop the stored bond before the app connects.
            wipe_log = io.command(
                ['swift', str(EXAMPLE / 'tools/bond_wipe.swift')],
                args.out / 'bond-wipe.jsonl', 30)
            wipe_rows = hid.client_rows(args.out / 'bond-wipe.jsonl')
            wipe_summary = next((row for row in reversed(wipe_rows)
                                 if row.get('event') == 'summary'), None)
            metadata['bond_wipe'] = wipe_summary
            if (wipe_summary or {}).get('reason') != 'bond_delete_written':
                errors.append(f'bond wipe did not complete: {wipe_summary}')

        adb('logcat', '-c')
        adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
        adb('shell', 'wm', 'dismiss-keyguard')
        adb('shell', 'svc', 'power', 'stayon', 'true')
        adb('shell', 'am', 'force-stop', PACKAGE)
        adb('shell', 'am', 'start', '-W', '-n', ACTIVITY,
            '--es', 'mode', 'hid', '--es', 'target_name', TARGET, timeout=60)
        if args.settings_connect:
            time.sleep(2)
            metadata['settings_connect'] = tap_settings_connect(args.out)
            if not metadata['settings_connect']:
                errors.append('could not find the paired keyboard in Bluetooth settings')
        tap = tuple(int(part) for part in args.pair_tap.split(',')) if args.pair_tap else None
        consents = []
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            if not adb('shell', 'pidof', PACKAGE, check=False).strip():
                break
            if tap is not None:
                focus = adb('shell', 'dumpsys', 'window', timeout=20)
                if 'BluetoothPairingDialog' in focus:
                    adb('shell', 'input', 'tap', str(tap[0]), str(tap[1]), timeout=20)
                    consents.append({'action': 'confirm_fast', 'tap': list(tap)})
                    print('CONSENT fast tap', flush=True)
            else:
                consent = secure.confirm_pairing_dialog(SERIAL)
                if consent is not None:
                    consents.append(consent)
                    print('CONSENT', json.dumps(consent), flush=True)
            time.sleep(0.15 if tap is not None else 0.5)
        else:
            errors.append('phone app did not finish within its timeout')
        logcat = adb('logcat', '-d', '-s', 'WCHBLE:I', timeout=60)
        (args.out / 'logcat.txt').write_text(logcat)
        (args.out / 'crash.txt').write_text(adb('logcat', '-d', '-b', 'crash', timeout=60))
        (args.out / 'system-tail.txt').write_text(
            adb('logcat', '-d', '-b', 'main', '-b', 'system', '-t', '4000', timeout=120))
        rows = parse_rows(logcat)
        (args.out / 'transcript.jsonl').write_text(
            '\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n')
        metadata['app_summary'] = next(
            (row for row in reversed(rows) if row.get('event') == 'summary'), None)
        metadata['pairing_consent'] = consents

        dumpsys_pre = adb('shell', 'dumpsys', 'input', timeout=60)
        (args.out / 'dumpsys-input-app.txt').write_text(dumpsys_pre)
        errors.extend(evaluate_transcript(rows, dumpsys_pre))

        if args.bt_reset:
            # The system HID host only runs its HOGP discovery on a fresh
            # client connection. Once this app has encrypted the shared link,
            # the host's own security wait never resolves and it keeps the
            # cached layout without subscribing. Cycling the adapter forces a
            # clean host connection, which then subscribes and receives
            # reports; the firmware counters prove that path.
            adb('shell', 'svc', 'bluetooth', 'disable')
            gone = time.monotonic() + 10
            while time.monotonic() < gone:
                if TARGET not in adb('shell', 'dumpsys', 'input', timeout=60):
                    break
                time.sleep(0.5)
            adb('shell', 'svc', 'bluetooth', 'enable')
            back, until = False, time.monotonic() + 30
            while time.monotonic() < until:
                if TARGET in adb('shell', 'dumpsys', 'input', timeout=60):
                    back = True
                    break
                time.sleep(1)
            metadata['bt_reset'] = {'input_device_reappeared': back}
            if not back:
                errors.append('system HID host did not re-register the keyboard '
                              'after a Bluetooth reset')

        time.sleep(args.settle_seconds)
        dumpsys = adb('shell', 'dumpsys', 'input', timeout=60)
        (args.out / 'dumpsys-input.txt').write_text(dumpsys)
        with (args.out / 'screencap.png').open('wb') as image:
            subprocess.run(['adb', '-s', SERIAL, 'exec-out', 'screencap', '-p'],
                           stdout=image, timeout=60)

        p4.wait_until(safe_read_at)
        observations = {}
        for name, count, names in (('STATS', 64, hid.STAT_NAMES),
                                   ('HOST_STATS', 16, hid.HOST_NAMES),
                                   ('HID_STATS', 16, hid.HID_NAMES),
                                   ('SECURE_STATS', 16, hid.SEC_NAMES)):
            words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
            observations[name] = words
            metadata[name.lower()] = dict(zip(names, words))
            (args.out / f'{name.lower()}.json').write_text(
                json.dumps(metadata[name.lower()], indent=2) + '\n')
        if all(name in observations for name in ('HID_STATS', 'HOST_STATS',
                                                'SECURE_STATS', 'STATS')):
            errors.extend(evaluate_firmware(
                observations['HID_STATS'], observations['HOST_STATS'],
                observations['SECURE_STATS'], observations['STATS'], run_seconds,
                args.expect))
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        metadata['errors'] = errors
        metadata['passed'] = not errors
        (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
        if touched:
            try:
                p4.wait_until(safe_read_at)
                io.flash(args.out / 'smoke.elf', args.out, 'restore')
                io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                           args.out / 'restore-scan.log', 20)
                metadata['smoke_recovery'] = 'flash verify and exact-name discovery PASS'
            except FAILURES as error:
                errors.append(f'recovery: {error}')
                metadata['smoke_recovery'] = 'NOT VERIFIED'
            (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


def main(argv=None):
    return execute(options(argv))


if __name__ == '__main__':
    sys.exit(main())
