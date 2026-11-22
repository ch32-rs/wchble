#!/usr/bin/env python3
"""X3 pp+secure rounds: encrypted dual-link evidence for the pp image.

Phases (spec `local-docs/ch585-x3-pp-secure-spec.md` §10):
  bond-phone  phase 1: optional store wipe + phone bond A (`android-pair pair`)
  bond-mac    phase 1: Mac bond B via the delayed Security Request + dialog click
  dual        phase 2: two encrypted reconnects, Mac drop mid-cycle, phone held
  reject      3a: dual-link boot, one live encrypted link, a cleared-bond phone
              has its new pairing refused (`0x05 peer-visible refusal` stays an
              unverified in-scope row; this counts the firmware-side refusal)

The script never probes while RF may be running: flash through the retained
preflight session, drive the peers afterwards, read RAM only once the finite
run budget plus the cleanup margin elapsed.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / 'examples/ch585-trouble-gatt'
TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import secure_run as secure  # noqa: E402

_spec = importlib.util.spec_from_file_location('ch585_gatt_run', TOOLS / 'run.py')
gatt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gatt)
_spec = importlib.util.spec_from_file_location('ch585_pp_run', TOOLS / 'pp_run.py')
pprun = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pprun)
io = gatt.io
FAILURES = gatt.FAILURES

DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
SMOKE = gatt.SMOKE
NM = gatt.NM
NAME = 'wch585-p4'
APK = TOOLS / 'android-pair/build/android-pair.apk'
PACKAGE = 'com.example.wchble.pair'
ACTIVITY = PACKAGE + '/.MainActivity'
ADB_SERIAL = secure.ADB_SERIAL
MAC_ROLE = 1
# android-pair WRITE_VALUE (0x2b); every phone cycle echoes this back as a
# notification on its own link.
PHONE_WRITE_VALUE = 43

PP_MAGIC = 0x5050_5331
PP_NAMES = '''magic version mode accepts_in_dual pairing_refused encrypted_events
    pairs_without_bond pairing_failed security_req_failed reserved9 reserved10
    reserved11 reserved12 reserved13 reserved14 reserved15'''.split()
PP_MODE_COMMISSIONING = 0
PP_MODE_DUAL_LINK = 1

# Observation buffers the pp+secure image carries. HOST_ERROR and the X1/X4/
# PHY fixtures are single-link host paths and stay absent here.
PP_BUFFERS = (('STATS', 64), ('HOST_STATS', 16), ('SECURE_STATS', 16),
              ('SEC_DIAG', 64), ('SEC_OPCODES', 96), ('BOND_STATS', 32),
              ('BOND_ECHO', 16), ('CATT_STATS', 16), ('PERIPHERAL_ADDRESS', 2),
              ('TRACE', 128 * 8), ('PP_STATS', 16))

CLIENT_SECONDS = {'bond-mac': 30.0, 'dual': 16.0, 'reject': 30.0}
# The Mac needs ~6 s from flash to its first write; the reject round only
# counts once the encrypted link is already live.
PHONE_DELAY = {'dual': 3.0, 'reject': 2.0}
# bond-mac waits for the user's Settings pairing before the central starts.
# Needs a long-run image (--run-seconds 360) so the window covers it.


def adb(serial, *args, **kwargs):
    try:
        return secure.adb(serial, *args, **kwargs)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or '').strip()
        raise RuntimeError(f'adb {" ".join(args[:3])} failed: {detail}') from error


def validate_pp_buffers(image, symbols):
    """Same checks as the secure validator, minus the single-link fixtures."""
    sections = gatt.p3.elf_sections(image)
    ranges = []
    for name, count in PP_BUFFERS:
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


def phone_rows(serial):
    text = adb(serial, 'logcat', '-d', '-s', 'WCHBLE:I', timeout=60)
    return secure.read_log(text.splitlines())


def phone_wall(rows, row, launch_wall):
    """Wall-clock estimate for one transcript row, anchored on `am start -W`."""
    first = rows[0].get('t_ms') if rows else None
    stamp = row.get('t_ms')
    if not isinstance(first, (int, float)) or not isinstance(stamp, (int, float)):
        return None
    return launch_wall + (stamp - first) / 1000.0


def launch_phone(args, out, mode, cycles=None, watch=None, on_connect=None,
                 connect_marker='already_bonded'):
    """Start the app and wait for its own exit; returns transcript rows.

    `watch` runs once per poll so a concurrent client's exit can be stamped
    on the runner's wall clock while the phone is still being waited on.
    `on_connect` fires once when logcat shows `connect_marker`, so a peer
    can start strictly after the phone link (or pairing) is under way.
    """
    launch = ['shell', 'am', 'start', '-W', '-n', ACTIVITY, '--es', 'mode', mode]
    if cycles is not None:
        launch += ['--ei', 'gatt_cycles', str(cycles)]
    adb(args.serial, *launch)
    launch_wall = time.monotonic()
    deadline = launch_wall + args.phone_timeout
    consents = []
    connected = False
    while True:
        pid = adb(args.serial, 'shell', 'pidof', PACKAGE, check=False,
                  timeout=15).strip()
        if not pid:
            break
        if args.consent:
            confirmed = secure.confirm_pairing_dialog(args.serial)
            if confirmed is not None:
                consents.append(confirmed)
                print('CONSENT', json.dumps(confirmed), flush=True)
        if on_connect is not None and not connected:
            dump = adb(args.serial, 'shell', 'logcat', '-d', '-e',
                       connect_marker, check=False, timeout=15)
            if connect_marker in dump:
                connected = True
                on_connect()
        if watch is not None:
            watch()
        if time.monotonic() >= deadline:
            try:
                adb(args.serial, 'shell', 'am', 'force-stop', PACKAGE, timeout=15)
            except FAILURES:
                pass
            return None, consents, launch_wall, True
        time.sleep(0.5)
    rows = phone_rows(args.serial)
    (out / 'phone.jsonl').write_text(
        '\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n')
    return rows, consents, launch_wall, False


def run_wipe(args):
    """Bond-store wipe on the accept-control image; its own gates run inside."""
    if args.wipe_elf is None:
        raise ValueError('--wipe requires --wipe-elf (build with '
                         '--features secure,accept-control first)')
    wipe_out = args.out / 'wipe'
    command = [sys.executable, str(TOOLS / 'bond_accept.py'), 'wipe',
               '--out', str(wipe_out), '--elf', str(args.wipe_elf),
               '--smoke-elf', str(args.smoke_elf), '--serial', args.serial,
               '--run-seconds', str(args.wipe_run_seconds)]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=900)
    except subprocess.TimeoutExpired:
        return {'command': command, 'error': 'bond_accept wipe timed out'}
    record = {'command': command, 'exit': result.returncode}
    (args.out / 'wipe.log').write_text(result.stdout + result.stderr)
    passed = wipe_out / 'result.json'
    if passed.is_file():
        record['result'] = json.loads(passed.read_text())
        record['passed'] = bool(record['result'].get('passed'))
    else:
        record['passed'] = False
    return record


def evaluate_pp(words, phase):
    """PP_STATS gates: one owner, per-phase mode and refusal expectations."""
    if len(words) != 16:
        return ['invalid PP_STATS size']
    if words[0] != PP_MAGIC or words[1] != 1:
        return [f'PP_STATS magic/version wrong: {words[:2]}']
    named = dict(zip(PP_NAMES, words))
    errors = []

    def exact(name, want):
        if named[name] != want:
            errors.append(f'PP_STATS {name}={named[name]}, expected {want}')

    def at_least(name, want):
        if named[name] < want:
            errors.append(f'PP_STATS {name}={named[name]} < {want}')

    zeros = ('accepts_in_dual', 'pairs_without_bond', 'pairing_failed',
             'security_req_failed')
    if phase in ('bond-phone', 'bond-mac'):
        exact('mode', PP_MODE_COMMISSIONING)
        at_least('encrypted_events', 1)
        for name in zeros:
            exact(name, 0)
        exact('pairing_refused', 0)
    elif phase == 'dual':
        exact('mode', PP_MODE_DUAL_LINK)
        exact('encrypted_events', 2)
        # Both accepts happen in dual mode; neither link may pair again.
        exact('accepts_in_dual', 2)
        exact('pairing_refused', 2)
        exact('pairs_without_bond', 0)
        exact('pairing_failed', 0)
        exact('security_req_failed', 0)
    elif phase == 'reject':
        exact('mode', PP_MODE_DUAL_LINK)
        # Mac + phone accepts, both refused by the boot-time owner.
        at_least('accepts_in_dual', 2)
        at_least('pairing_refused', 2)
        exact('pairs_without_bond', 0)
        at_least('encrypted_events', 1)
        exact('security_req_failed', 0)
        # pairing_failed only fires when SMP answers on air; a silent stall is
        # also a refusal, so the count is archived rather than gated.
    return errors


def evaluate_secure(words, encryptions, minimum=False):
    """SECURE_STATS gates; merged across both links (spec §5).

    `minimum` covers bond-mac, whose MacPair pairing link always encrypts
    while the scripted central adds a second procedure only in rounds after
    the always-armed Security Request.
    """
    errors = []
    if len(words) != 16:
        return ['invalid SECURE_STATS size']
    if words[0] != secure.SEC_MAGIC or words[1] & 0xff != 1:
        return [f'SECURE_STATS magic/version wrong: {words[:2]}']
    flags = words[1]
    if not flags & (1 << 8):
        errors.append('firmware did not pass the ADC entropy health check')
    if not flags & (1 << 9):
        errors.append('Host crypto RNG was not seeded')
    if not flags & (1 << 10):
        errors.append('controller DRBG was not seeded')
    named = dict(zip(secure.SEC_NAMES, words))
    if minimum:
        if named['enc_req'] < encryptions:
            errors.append(f"enc_req={named['enc_req']} < {encryptions}")
    elif named['enc_req'] != encryptions:
        errors.append(f"enc_req={named['enc_req']}, expected {encryptions}")
    if named['ltk_request'] < encryptions:
        errors.append(f"ltk_request={named['ltk_request']} < {encryptions}")
    if named['start_req'] < encryptions:
        errors.append(f"start_req={named['start_req']} < {encryptions}")
    if named['mic_failure']:
        errors.append(f"MIC failures: {named['mic_failure']}")
    if named['errors']:
        errors.append(f"encryption errors: {named['errors']} "
                      f"(last 0x{named['last_error']:02x})")
    if named['plaintext_start_retry']:
        errors.append(f"plaintext START_ENC_REQ retransmissions: "
                       f"{named['plaintext_start_retry']}")
    # `active` stays 1 after the finite run stops: the LL session counter is
    # not cleared at disconnect (single-link baseline agrees), archive only.
    return errors


def evaluate_host(host, phase):
    errors = []
    if len(host) != 16:
        return ['invalid HOST_STATS size'], {}
    named = dict(zip(gatt.HOST_NAMES, host))
    # bond-mac counts the MacPair pairing link plus the scripted central.
    connections = 1 if phase == 'bond-phone' else 2
    if host[0] != 2:
        errors.append(f'host did not return to advertising (phase {host[0]})')
    if host[1] != connections:
        errors.append(f'host connections={host[1]}, expected {connections}')
    if host[2] != connections:
        errors.append(f'host disconnects={host[2]}, expected {connections}')
    if not host[3] or not host[4] or not host[5]:
        errors.append('host did not observe reads, writes and notifications')
    if host[7] or host[8] or host[10]:
        errors.append('host errors/last_error/subscription are not clean')
    return errors, named


def evaluate_stats(stats, phase, run_seconds):
    """Finite-run and engine gates; TX_LATE/retries/duplicates are hard."""
    errors = []
    if len(stats) != 64:
        return ['invalid STATS size'], {}
    if stats[:3] != [0x50343538, 1, 9]:
        errors.append(f'firmware did not finish: magic/version/stage={stats[:3]}')
    # Under `pp` the RF owner reuses slots 33/34 for capacity/overrun counts;
    # the single-link `cmd/mode` clean check does not apply (pp_run agrees).
    # host_poll_overrun is archived without a threshold (spec §8, first-round
    # calibration; the pairing window stalls a poll, HID precedent 562 ms).
    if stats[22] or stats[63]:
        errors.append('RF stop was not clean (stop_err/bridge)')
    if not (run_seconds * 1_000_000 <= stats[32] <= (run_seconds + 3) * 1_000_000):
        errors.append('firmware runtime does not match the finite-run budget')
    expected = 2 if phase != 'bond-phone' else 1
    # bond-mac: the MacPair pairing link plus the scripted central.
    # reject: the refused phone link still carries its ATT discovery, and
    # Android retries the LL connect while the pairing stalls, so only the
    # links-with-data count is exact.
    if stats[14] < expected:
        errors.append(f'connect_valid={stats[14]}, expected at least {expected}')
    if stats[15] != expected:
        errors.append(f'links with data={stats[15]}, expected {expected}')
    # fragment_failures and background_overruns are nonzero in the plaintext
    # pp baselines too (7/0, 10/1): archived, not gated. Pairing-window rounds
    # archive `retries` (and `duplicates` for the concurrent reject attempt):
    # the pairing-crypto burst stalls the host poll ~0.5 s and retransmits on
    # the LL, exactly as the bond-mac consent wait does.
    zero_slots = ((19, 'tx_late'), (20, 'tx_err'), (21, 'rx_err'),
                  (33, 'capacity_rejects'))
    if phase != 'reject':
        zero_slots += ((24, 'duplicates'),)
    if phase not in ('bond-mac', 'reject'):
        zero_slots += ((25, 'retries'),)
    for slot, name in zero_slots:
        if stats[slot]:
            errors.append(f'engine counter {name}={stats[slot]}')
    detail = {'max_host_poll_us': stats[61], 'host_poll_overrun': stats[62],
              'bridge_error': stats[63], 'missed': stats[23],
              'fragment_failures': stats[45], 'background_overruns': stats[34],
              'retries': stats[25]}
    return errors, detail


def evaluate_bonds(words, phase):
    """BOND_STATS gates: what the boot restored and what the round changed."""
    errors = []
    if len(words) != 32 or words[0] != secure.BOND_MAGIC:
        return ['invalid BOND_STATS'], {}
    named = dict(zip(secure.BOND_NAMES, words))
    loaded = {'bond-phone': 0, 'bond-mac': 1, 'dual': 2, 'reject': 2}[phase]
    if named['records_loaded'] != loaded:
        errors.append(f"records_loaded={named['records_loaded']}, "
                       f"expected {loaded}")
    if named['add_bond_fail']:
        errors.append(f"boot restore failed for a record: {named['add_bond_fail']}")
    if phase == 'bond-phone':
        if named['pairs_complete'] != 1:
            errors.append(f"pairs_complete={named['pairs_complete']}, expected 1")
        if not named['save_ok']:
            errors.append('the new bond was never persisted')
    elif phase == 'bond-mac':
        if named['pairs_complete'] != 1:
            errors.append(f"pairs_complete={named['pairs_complete']}, expected 1")
        if not named['save_ok']:
            errors.append('the Mac bond was never persisted')
    else:
        pairs = named['pairs_complete'] + named['pairs_without_bond']
        if pairs:
            errors.append(f'the run paired again ({pairs} PairingComplete event(s))')
    if named['pairs_without_bond']:
        errors.append(f"pairs_without_bond={named['pairs_without_bond']}")
    if named['save_fail']:
        errors.append(f"bond saves failed: {named['save_fail']}")
    if named['in_memory_removed']:
        errors.append(f"in_memory_removed={named['in_memory_removed']}")
    return errors, named


def evaluate_mac(role, rows, returncode, timeout, expect_peer):
    """pp_run's client gates, minus the peer-fanout check when the phone
    never writes (bond-mac, reject)."""
    result = pprun.evaluate_client(role, rows, returncode, timeout)
    if not isinstance(result, tuple):
        return result, None
    errors, window = result
    if not expect_peer:
        errors = [error for error in errors
                  if "other role's value" not in error]
    return errors, window


def evaluate_phone_dual(rows, args, mac_exit_wall, launch_wall):
    """Phase-2 phone gates: reconnect transcript, notify evidence, hold."""
    errors = secure.evaluate_transcript(rows, 'reconnect')
    subscribed = [row for row in rows if row.get('event') == 'value_subscribed']
    if not subscribed or subscribed[0].get('status') != 0:
        errors.append(f'phone: value CCCD subscription failed: {subscribed}')
    notifications = [row.get('value') for row in rows
                     if row.get('event') == 'notification'
                     and isinstance(row.get('value'), int)]
    if PHONE_WRITE_VALUE not in notifications:
        errors.append('phone: no notification echoed the phone write '
                      f'({PHONE_WRITE_VALUE})')
    mac_values = [value for value in notifications
                  if MAC_ROLE * 1000 < value < (MAC_ROLE + 1) * 1000]
    if not mac_values:
        errors.append('phone: no notification carried a Mac write value')
    cycles = [row for row in rows if row.get('event') == 'cycle']
    if len(cycles) != args.gatt_cycles - 1:
        errors.append(f'phone: {len(cycles)} extra cycles, '
                      f'expected {args.gatt_cycles - 1}')
    # One-drop-one-keep: the phone GATT window must straddle the Mac exit.
    gatt_rows = [row for row in rows
                 if row.get('event') in ('write_ack', 'notification', 'read')]
    walls = [wall for wall in (phone_wall(rows, row, launch_wall)
                              for row in gatt_rows)
            if wall is not None]
    if len(walls) != len(gatt_rows):
        errors.append('phone: transcript rows missing t_ms stamps')
    elif mac_exit_wall is not None:
        if not any(wall < mac_exit_wall for wall in walls):
            errors.append('phone: no GATT event before the Mac dropped '
                          '(links did not overlap)')
        if not any(wall > mac_exit_wall for wall in walls):
            errors.append('phone: no GATT event after the Mac dropped '
                          '(one-drop-one-keep failed)')
    return errors, {'notifications': len(notifications),
                    'mac_values': sorted(set(mac_values)),
                    'gatt_span_s': [round(min(walls), 2), round(max(walls), 2)]
                    if walls else None}


def evaluate_phone_reject(rows):
    """3a phone gates: the new pairing must fail without touching the store."""
    errors = []
    if not rows:
        return ['phone: no transcript']
    summaries = [row for row in rows if row.get('event') == 'summary']
    if len(summaries) != 1:
        return [f'phone: expected exactly one summary, saw {len(summaries)}']
    summary = summaries[0]
    if summary.get('pass') is not False:
        errors.append(f'phone: the refused pairing unexpectedly succeeded: '
                      f'{summary}')
    if summary.get('reason') not in ('bond_rejected', 'timeout'):
        errors.append(f"phone: unexpected refusal reason: {summary.get('reason')}")
    if any(row.get('event') == 'already_bonded' for row in rows):
        errors.append('phone: a residual bond to the target survived the '
                      'pre-round unpair')
    states = [row.get('state') for row in rows if row.get('event') == 'bond_state']
    if 12 in states:  # BOND_BONDED
        errors.append(f'phone: the bond completed despite refusal: {states}')
    return errors, {'bond_states': states,
                    'reason': summary.get('reason')}


def evaluate_smp(opcodes, phase):
    """On-air SMP proof: pairing traffic where a bond must form, none where it
    must not (a dual round resumes encryption without SMP)."""
    errors = []
    smp = opcodes.get('smp', {})
    pairing_rx = sum(smp.get('rx', {}).get(name, 0) for name in
                     ('PairingRequest', 'PairingConfirm', 'PairingRandom',
                      'PairingPublicKey', 'PairingDHKeyCheck'))
    if phase in ('bond-phone', 'bond-mac', 'reject'):
        if not pairing_rx:
            errors.append('no on-air SMP pairing traffic was observed')
    elif pairing_rx:
        errors.append(f'the dual round saw SMP pairing traffic ({pairing_rx} PDUs)')
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {
        'probe': gatt.PROBE, 'scope': 'X3 pp+secure dual encrypted links',
        'phase': args.phase, 'run_seconds': args.run_seconds,
        'serial': args.serial,
    }
    clients = []
    pairer, pair_log = None, None
    mac = None
    touched, safe_read_at, symbols = False, 0.0, None
    mac_exit_wall = None
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        for source, target in ((args.elf, archived), (args.smoke_elf, smoke)):
            target.write_bytes(Path(source).read_bytes())
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        symbols = secure.symbols_from(nm_text)
        for name, _ in PP_BUFFERS:
            matches = [parts for line in nm_text.splitlines()
                       if len(parts := line.split()) == 3 and parts[2] == name]
            if len(matches) != 1:
                raise ValueError(f'missing or ambiguous {name} symbol')
            symbols[name] = int(matches[0][0], 16)
        symbols = validate_pp_buffers(image, symbols)
        # Refuse to spend a probe session on the wrong feature set: the pp
        # dispatch must be linked in, and secure needs the crypto backend.
        if '_ZN18ch585_trouble_gatt2pp3run' not in nm_text:
            raise ValueError('ELF was not built with --features pp '
                             '(pp::run is not dispatched)')
        if '_embassy_crypto_aes128ecb_encrypt_blocks' not in nm_text:
            raise ValueError('ELF was not built with --features secure '
                             '(no crypto backend)')
        embedded = gatt.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded
        if embedded != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={embedded}, '
                             f'requested {args.run_seconds}')
        source, binary = args.out / 'central.swift', (args.out / 'central').resolve()
        (args.out / 'central.swift').write_bytes((TOOLS / 'central.swift').read_bytes())
        io.command(['swiftc', '-O', str(source), '-o', str(binary)],
                   args.out / 'central-build.log', timeout=180)
        if not APK.is_file():
            raise ValueError(f'missing APK: {APK}')
        metadata['apk_sha256'] = hashlib.sha256(APK.read_bytes()).hexdigest()
        adb(args.serial, 'get-state')
        adb(args.serial, 'install', '-g', '-r', str(APK), timeout=120)
        mac_state = secure.mac_bluetooth_state(args.out)
        bonded_mac = NAME in mac_state
        metadata['mac_knows_target'] = bonded_mac
        if args.phase == 'bond-mac' and bonded_mac:
            raise ValueError(f'the Mac already knows {NAME}; remove it in '
                             'System Settings > Bluetooth before bonding it')
        if args.phase in ('dual', 'reject') and not bonded_mac:
            raise ValueError(f'the Mac has no bond to {NAME}; run the '
                             'bond-mac phase first')

        if args.phase == 'bond-phone' and args.wipe:
            record = run_wipe(args)
            metadata['wipe'] = record
            if not record.get('passed'):
                raise ValueError('the bond-store wipe did not pass its own gates')

        touched = True
        try:
            secure.flash(archived, args.out, args.phase)
        finally:
            safe_read_at = time.monotonic() + embedded + 3
        adb(args.serial, 'logcat', '-c')
        adb(args.serial, 'shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
        adb(args.serial, 'shell', 'wm', 'dismiss-keyguard')
        adb(args.serial, 'shell', 'svc', 'power', 'stayon', 'true')
        adb(args.serial, 'shell', 'am', 'force-stop', PACKAGE)

        if args.phase == 'bond-phone':
            rows, consents, _, timed_out = launch_phone(args, args.out, 'pair')
            metadata['pairing_consent'] = consents
            if timed_out:
                errors.append('phone app did not finish within its timeout')
            elif rows is not None:
                errors.extend(secure.evaluate_transcript(rows, 'pair'))
                if not consents:
                    errors.append('no Just Works consent dialog was confirmed')
                metadata['client_summary'] = next(
                    (row for row in reversed(rows)
                     if row.get('event') == 'summary'), None)
        else:
            if args.phase == 'bond-mac':
                # macOS never lists an unknown-service BLE peripheral in
                # System Settings, and a CLI central cannot present pairing
                # consent — the SMP exchange stalls at PairingResponse with
                # no dialog (spec §9 risk 2, screenshot-verified). MacPair.app
                # is a regular foreground app holding the link when the
                # firmware's 2 s Security Request lands; the runner takes
                # over once the bond shows up in the Mac's Bluetooth table.
                app_binary = TOOLS / 'MacPair.app/Contents/MacOS/MacPair'
                if not app_binary.is_file():
                    raise ValueError(f'missing {app_binary}; build it with '
                                     'swiftc -O -o MacPair.app/Contents/MacOS/'
                                     'MacPair mac_pair.swift')
                pair_log = (args.out / 'mac-pair.jsonl').open('w')
                pairer = subprocess.Popen(
                    [str(app_binary), '--timeout', str(args.pair_wait)],
                    stdout=pair_log, stderr=subprocess.STDOUT, text=True)
                # A table entry alone is too weak: macOS lists the device as
                # "known" after any app connection. The hard signal is the
                # app's own transcript: while the pairing consent is pending,
                # even service discovery stalls, so `services_discovered`
                # (or a completed read) means the bond went through.
                pair_deadline = time.monotonic() + args.pair_wait
                unblocked = False
                while time.monotonic() < pair_deadline:
                    if pairer.poll() is not None:
                        break
                    try:
                        rows = [json.loads(line) for line
                                in (args.out / 'mac-pair.jsonl').read_text().splitlines()
                                if line.strip()]
                    except (OSError, ValueError):
                        rows = []
                    if any(row.get('event') in ('services_discovered',
                                                 'characteristics_discovered',
                                                 'read_result') for row in rows):
                        unblocked = True
                        break
                    time.sleep(2)
                metadata['mac_pair_unblocked'] = unblocked
                if pairer.poll() is None:
                    pairer.terminate()
                rows = []
                if pair_log is not None:
                    pair_log.close()
                    for line in (args.out / 'mac-pair.jsonl').read_text().splitlines():
                        try:
                            rows.append(json.loads(line))
                        except ValueError:
                            pass
                metadata['mac_pair_rows'] = rows
                if not unblocked:
                    raise ValueError(f'the Mac never bonded to {NAME}; the '
                                     'pairing consent never completed '
                                     '(macOS presented no dialog and stalled '
                                     'the app)')
                # Drop the pairing link so the advertiser comes back before
                # the scripted central scans.
                time.sleep(3)
            command = [str(binary), '--mode', 'pp', '--role', str(MAC_ROLE),
                       '--timeout', str(args.client_seconds), '--name', NAME]
            (args.out / 'central.command.json').write_text(json.dumps(command) + '\n')
            log = (args.out / 'central.jsonl').open('w')
            clients.append(log)

            def start_mac():
                # The Mac central starts only after the phone link is up, so
                # the dual round is order-deterministic: phone = first accept,
                # Mac = the dropped link of one-drop-one-keep.
                nonlocal mac
                time.sleep(args.phone_delay)
                mac = subprocess.Popen(command, stdout=log,
                                       stderr=subprocess.STDOUT, text=True)

            def watch_mac():
                # Stamp the Mac exit on the runner clock while the phone loop
                # keeps polling; ordering gates compare against this wall time.
                nonlocal mac_exit_wall
                if mac is None or mac_exit_wall is not None:
                    return
                if mac.poll() is not None:
                    mac_exit_wall = time.monotonic()

            if args.phase == 'dual':
                # Phone-first: the initial value must be 0 and the cycle-0
                # read-back must echo the phone's own write, which only holds
                # before the Mac's concurrent writes land.
                rows, consents, launch_wall, timed_out = launch_phone(
                    args, args.out, 'reconnect', cycles=args.gatt_cycles,
                    watch=watch_mac, on_connect=start_mac)
                if mac is None:
                    errors.append('the phone never connected; the Mac '
                                  'central was not launched')
                    timed_out = True
            elif args.phase == 'reject':
                # Pairing attempt first: the ~565 ms pairing-crypto burst
                # (archived host-poll stall) would drop any link alive at
                # that instant (reject#2 evidence). The Mac central starts
                # once the pairing is under way, connects into the steady
                # stall, and proves the existing link's GATT runs through
                # the refused attempt.
                def start_mac_in_stall():
                    nonlocal mac
                    time.sleep(args.phone_delay)
                    mac = subprocess.Popen(command, stdout=log,
                                           stderr=subprocess.STDOUT, text=True)
                args.consent = False
                rows, consents, launch_wall, timed_out = launch_phone(
                    args, args.out, 'pair', watch=watch_mac,
                    on_connect=start_mac_in_stall,
                    connect_marker='pairing_request')
                if mac is None:
                    errors.append('the phone never started pairing; the '
                                  'Mac central was not launched')
                    timed_out = True
            else:
                mac = subprocess.Popen(command, stdout=log,
                                       stderr=subprocess.STDOUT, text=True)
            if mac is not None:
                try:
                    mac.wait(timeout=args.client_seconds + 10)
                except subprocess.TimeoutExpired:
                    errors.append('mac central exceeded timeout plus cleanup')
                    gatt.stop_client(mac)
                if mac_exit_wall is None:
                    mac_exit_wall = time.monotonic()
                metadata['mac_exit_code'] = mac.returncode
                metadata['mac_exit_wall'] = mac_exit_wall
                mac_rows = gatt.read_client(args.out / 'central.jsonl')
                expect_peer = args.phase == 'dual'
                result = evaluate_mac(MAC_ROLE, mac_rows, mac.returncode,
                                      args.client_seconds, expect_peer)
            else:
                mac_rows, result = [], ['the Mac central never ran']
            if isinstance(result, tuple):
                found, window = result
                errors.extend(found)
                metadata['mac_window'] = window
            else:
                errors.extend(result)
            if args.phase == 'dual':
                if timed_out:
                    errors.append('phone app did not finish within its timeout')
                elif rows is not None:
                    found, detail = evaluate_phone_dual(rows, args,
                                                        mac_exit_wall, launch_wall)
                    errors.extend(found)
                    metadata['phone'] = detail
                    metadata['client_summary'] = next(
                        (row for row in reversed(rows)
                         if row.get('event') == 'summary'), None)
            elif args.phase == 'reject':
                if timed_out:
                    errors.append('phone app did not finish within its timeout')
                elif rows is not None:
                    found, detail = evaluate_phone_reject(rows)
                    errors.extend(found)
                    metadata['phone'] = detail
                    metadata['client_summary'] = next(
                        (row for row in reversed(rows)
                         if row.get('event') == 'summary'), None)

    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        for log in clients:
            log.close()
        if pairer is not None and pairer.poll() is None:
            pairer.terminate()
        if pair_log is not None and not pair_log.closed:
            pair_log.close()
        try:
            adb(args.serial, 'shell', 'am', 'force-stop', PACKAGE, timeout=15)
        except FAILURES:
            pass
        if touched and symbols is not None and safe_read_at:
            try:
                gatt.wait_until(safe_read_at)
                observations = {}
                for name, count, names in (('STATS', 64, gatt.STAT_NAMES),
                                            ('HOST_STATS', 16, gatt.HOST_NAMES),
                                            ('SECURE_STATS', 16, secure.SEC_NAMES),
                                            ('PP_STATS', 16, PP_NAMES),
                                            ('BOND_STATS', 32, secure.BOND_NAMES)):
                    words = io.read32(symbols[name], count,
                                      args.out / f'{name.lower()}.txt')
                    observations[name] = words
                    metadata[name.lower()] = dict(zip(names, words))
                    (args.out / f'{name.lower()}.json').write_text(
                        json.dumps(metadata[name.lower()], indent=2) + '\n')
                encryptions = 2 if args.phase == 'dual' else 1
                errors.extend(evaluate_pp(observations['PP_STATS'], args.phase))
                errors.extend(evaluate_secure(observations['SECURE_STATS'],
                                              encryptions,
                                              minimum=args.phase == 'bond-mac'))
                found, _ = evaluate_host(observations['HOST_STATS'], args.phase)
                errors.extend(found)
                found, engine = evaluate_stats(observations['STATS'], args.phase,
                                               args.run_seconds)
                errors.extend(found)
                metadata['engine'] = engine
                found, _ = evaluate_bonds(observations['BOND_STATS'], args.phase)
                errors.extend(found)
                diag_words = io.read32(symbols['SEC_DIAG'], 64,
                                        args.out / 'sec_diag.txt')
                metadata['sec_diag'] = secure.decode_diag(diag_words)
                opcode_words = io.read32(symbols['SEC_OPCODES'], 96,
                                         args.out / 'sec_opcodes.txt')
                metadata['sec_opcodes'] = secure.decode_opcodes(opcode_words)
                errors.extend(evaluate_smp(metadata['sec_opcodes'], args.phase))
                echo_words = io.read32(symbols['BOND_ECHO'], 16,
                                        args.out / 'bond_echo.txt')
                metadata['bond_echo'] = secure.decode_bond_echo(echo_words)
                address_words = io.read32(symbols['PERIPHERAL_ADDRESS'], 2,
                                          args.out / 'address.txt')
                address = bytes(byte for word in address_words
                                for byte in word.to_bytes(4, 'little'))[:6]
                metadata['peripheral_address'] = ':'.join(
                    f'{byte:02x}' for byte in reversed(address))
                trace_rows = secure.decode_trace(
                    io.read32(symbols['TRACE'], 128 * 8, args.out / 'trace.txt'),
                    observations['STATS'][39])
                (args.out / 'trace.jsonl').write_text(
                    '\n'.join(json.dumps(row, sort_keys=True)
                              for row in trace_rows) + '\n')
                print('SMP', json.dumps(metadata['sec_opcodes']['smp'],
                                        sort_keys=True))
            except FAILURES as error:
                errors.append(f'observations: {type(error).__name__}: {error}')
            try:
                secure.flash(smoke, args.out, 'restore')
                io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                           args.out / 'restore-scan.log', 20)
                metadata['smoke_recovery'] = 'flash verify and exact-name macOS discovery PASS'
            except FAILURES as error:
                errors.append(f'recovery: {error}')
                metadata['smoke_recovery'] = 'NOT VERIFIED'
        metadata['errors'], metadata['passed'] = errors, not errors
        metadata['smoke_recovery'] = metadata.get(
            'smoke_recovery',
            'NOT ATTEMPTED' if not touched else 'NOT VERIFIED')
        (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('bond-phone', 'bond-mac', 'dual', 'reject'))
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--serial', default=ADB_SERIAL)
    # Secure builds embed 60 s (the pairing window needs it); plain pp is 25.
    parser.add_argument('--run-seconds', type=int, default=60)
    parser.add_argument('--client-seconds', type=float, default=None,
                        help='Mac pp window (default 30/16/30 by phase)')
    parser.add_argument('--phone-delay', type=float, default=None,
                        help='seconds between the Mac start and the phone '
                             'launch (default 3/8 by phase)')
    parser.add_argument('--gatt-cycles', type=int, default=5,
                        help='phone reconnect write cycles (dual hold)')
    parser.add_argument('--phone-timeout', type=float, default=55.0)
    parser.add_argument('--pair-wait', type=float, default=240.0,
                        help='bond-mac: seconds to wait for the user to pair '
                             'the Mac in System Settings')
    parser.add_argument('--no-consent', dest='consent', action='store_false',
                        help='never tap the phone pairing dialog')
    parser.add_argument('--wipe', action='store_true',
                        help='bond-phone: wipe the bond store first')
    parser.add_argument('--wipe-elf', type=Path, default=None,
                        help='secure,accept-control image for the wipe round')
    parser.add_argument('--wipe-run-seconds', type=int, default=60)
    args = parser.parse_args(argv)
    if args.client_seconds is None:
        # bond-phone drives the phone only; there is no Mac window.
        args.client_seconds = CLIENT_SECONDS.get(args.phase, 0.0)
    if args.phone_delay is None:
        args.phone_delay = PHONE_DELAY.get(args.phase, 0.0)
    if args.phase == 'dual' and args.gatt_cycles < 3:
        parser.error('--gatt-cycles must be at least 3 for the dual hold')
    if args.phase == 'reject' and args.phone_delay < 1:
        parser.error('the reject phase needs the Mac link live before the '
                     'phone attempt (--phone-delay >= 1)')
    if args.phase == 'bond-mac':
        # The user pairs from System Settings while the firmware idles;
        # a 60 s image cannot cover that window.
        if args.run_seconds < 360:
            parser.error('bond-mac needs a long-run image '
                         '(--run-seconds 360, build with --features '
                         'pp,secure,long-run)')
        if not (math.isfinite(args.pair_wait) and 0 < args.pair_wait
                <= args.run_seconds - 60):
            parser.error('require 0 < --pair-wait <= run-seconds - 60 so the '
                         'central still has its window inside the firmware run')
    args.out, args.elf, args.smoke_elf = (args.out.resolve(), args.elf.resolve(),
                                          args.smoke_elf.resolve())
    return args


if __name__ == '__main__':
    sys.exit(execute(options()))
