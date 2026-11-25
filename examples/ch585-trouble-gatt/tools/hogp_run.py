#!/usr/bin/env python3
"""Phase 1 D1: HOGP central round against the android-gatt HID fixture.

Starts the phone as a scripted HID mouse (`--ez hid true`), flashes the `hogp`
image, taps the Just Works dialog when it appears, then reads HOGP_STATS,
HOST_STATS and STATS after the embedded run. `--require-params` additionally
gates the peer's L2CAP parameter request (real HID device rounds: the Android
GATT server API cannot emit one).

Hardware policy is inherited from the P4/C1 runners: fixed probe, one retained
preflight session before every flash, no probe access while RF may run, never
retry a failed flash, restore smoke in `finally`.
"""
import argparse
import hashlib
import importlib.util
import json
import shutil
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
secure = _load('ch585_secure_run', EXAMPLE / 'tools/secure_run.py')
bond = _load('ch585_bond_accept', EXAMPLE / 'tools/bond_accept.py')
io, PROBE, NM = gatt.io, gatt.PROBE, gatt.NM
SMOKE = gatt.SMOKE
wait_until = gatt.wait_until
FAILURES = gatt.FAILURES

DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
TARGET_NAME = 'wch585-h1'
ADB_SERIAL = secure.ADB_SERIAL

FIRST_ANCHOR, EVENTS, RX_DONE, TX_LATE, CONNECT_FAIL = 15, 16, 7, 19, 30
# Uptime of the first connection-event packet: the link exists by then (C3).
FIRST_ANCHOR_US = 36
SUPERVISION = 29
PAIRING_MAX_POLL, STEADY_MAX_POLL = 60, 61

HOGP_NAMES = '''magic version reports motion buttons subscriptions map_len map_hash
    map_reports references req_min req_max interval protocol hid_flags errors
    last_error reserved_17'''.split()
HOGP_MAGIC = 0x48475001
# Same descriptor as android-gatt's MainActivity.MOUSE_REPORT_MAP; the hash
# proves the DUT read the map byte-exact.
MOUSE_REPORT_MAP = bytes([
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01,
    0x85, 0x01,
    0x09, 0x01, 0xA1, 0x00,
    0x05, 0x09, 0x19, 0x01, 0x29, 0x03,
    0x15, 0x00, 0x25, 0x01,
    0x95, 0x03, 0x75, 0x01, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x05, 0x81, 0x01,
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31,
    0x16, 0x01, 0x80, 0x26, 0xFF, 0x7F,
    0x75, 0x10, 0x95, 0x02, 0x81, 0x06,
    0x09, 0x38,
    0x15, 0x81, 0x25, 0x7F,
    0x75, 0x08, 0x95, 0x01, 0x81, 0x06,
    0xC0, 0xC0,
])


def fnv1a(data):
    value = 0x811C9DC5
    for byte in data:
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    return value


def evaluate(host, stats, hogp, require_params):
    errors = []
    if host[0] == 0xFF:
        errors.append('host entered the fatal phase')
    if host[1] < 1:
        errors.append('host never reported a connection')
    if host[2] < 1:
        errors.append('host never reported a clean disconnect')
    if host[7] or host[8]:
        errors.append(f'host errors={host[7]} last_error={host[8]}')
    if host[15] != 3:
        errors.append(f'host security state={host[15]}, expected encrypted (3)')
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
    if stats[SUPERVISION] != 0:
        errors.append(f'{stats[SUPERVISION]} supervision expiries (A3)')
    if stats[STEADY_MAX_POLL] > 100_000:
        errors.append(f'steady max host poll {stats[STEADY_MAX_POLL]} us > 100 ms (A3)')
    if stats[PAIRING_MAX_POLL] >= 2_000_000:
        errors.append(f'pairing max host poll {stats[PAIRING_MAX_POLL]} us >= 2 s (A3)')

    if hogp[0] != HOGP_MAGIC:
        errors.append(f'HOGP_STATS magic={hogp[0]:#x}')
    if hogp[1] != 1:
        errors.append(f'HOGP_STATS version={hogp[1]}')
    if hogp[2] < 100:
        errors.append(f'{hogp[2]} input reports decoded, expected >= 100')
    if hogp[3] < 100:
        errors.append(f'{hogp[3]} reports with motion, expected >= 100')
    if hogp[4] < 1:
        errors.append('no input report carried a button')
    if hogp[5] < 1:
        errors.append('no input Report characteristic subscribed')
    if hogp[9] < hogp[5]:
        errors.append(f'{hogp[9]} Report References found for {hogp[5]} subscriptions')
    if hogp[6] != len(MOUSE_REPORT_MAP):
        errors.append(f'report map length {hogp[6]}, expected {len(MOUSE_REPORT_MAP)}')
    if hogp[7] != fnv1a(MOUSE_REPORT_MAP):
        errors.append(f'report map hash {hogp[7]:#x}, expected {fnv1a(MOUSE_REPORT_MAP):#x}')
    if hogp[8] < 1:
        errors.append('report map declares no input report ID')
    if require_params:
        if hogp[10] == 0:
            errors.append('peer never sent an L2CAP parameter update request')
        elif not hogp[10] <= hogp[12] <= hogp[11]:
            errors.append(f'interval {hogp[12]} outside requested [{hogp[10]}, {hogp[11]}]')
    if hogp[15] or hogp[16]:
        errors.append(f'hogp errors={hogp[15]} last_error={hogp[16]}')
    return errors


def evaluate_secure(sec, stale_rejections=0):
    errors = []
    name = secure.SEC_NAMES.index
    if sec[0] != secure.SEC_MAGIC or sec[1] & 0xFF != 1:
        errors.append(f'SECURE_STATS magic/version wrong: {sec[0]:#x}/{sec[1]}')
        return errors
    if sec[name('mic_failure')]:
        errors.append(f'MIC failures: {sec[name("mic_failure")]}')
    count = sec[name('errors')]
    last = sec[name('last_error')]
    if stale_rejections:
        # B2: the peer refuses the deleted LTK exactly once; the recovery
        # pairing must then encrypt normally.
        if count != stale_rejections or last != 0x06:
            errors.append(f'encryption procedure errors: {count} '
                          f'(last 0x{last:02x}), expected {stale_rejections} stale '
                          'rejection (0x06)')
    elif count:
        errors.append(f'encryption procedure errors: {count}')
    if sec[name('active')] < 1:
        errors.append('the link never reached SEC_ACTIVE')
    if sec[name('encrypted_tx')] < 1 or sec[name('encrypted_rx')] < 1:
        errors.append('no encrypted TX/RX PDUs were counted')
    return errors


def read_bond_store(out):
    """Dump both DataFlash bond slots: the runner needs the stored level/IRK."""
    slots = bond.parse_dump(bond.dump_path(out, 0x77E00, 512))
    for slot in slots:
        record = slot.get('record')
        if record:
            raw = bytes.fromhex(record)
            slot['decoded'] = {
                'address': raw[16:22][::-1].hex(':'),
                'address_kind': raw[22],
                'irk': bool(raw[23] & 1),
                'bonded': bool(raw[23] & 2),
                'security_level': raw[40],
                'key_len': raw[51],
            }
    return slots


def decode_peer_diag(words):
    """B1: which peer address the Host matched, and why it found no bond."""
    def address(low, high):
        raw = bytes([(low >> 8) & 0xFF, (low >> 16) & 0xFF, (low >> 24) & 0xFF,
                     high & 0xFF, (high >> 8) & 0xFF, (high >> 16) & 0xFF])
        return {'kind': low & 0xFF,
                'address': ':'.join(f'{byte:02x}' for byte in reversed(raw))}

    if words[0] != 0x50445231 or words[9] != 0x50445232:
        return {'raw': words}
    flags = words[1]
    return {
        'is_bonded_peer': bool(flags & 1),
        'stored_irk_resolves_peer': bool(flags & 2),
        'stored_bond_matches_identity': bool(flags & 4),
        'stored_bond_present': bool(flags & 8),
        'identity_differs_from_peer': bool(flags & 16),
        # B2: word 8 is set when the peer rejected the stored LTK.
        'stale_bond_rejected': bool(words[8] & 1),
        'stale_bond_removed': bool(words[8] & 2),
        'peer': address(words[2], words[3]),
        'identity': address(words[4], words[5]),
        'target': address(words[6], words[7]),
        'raw': words,
    }


def evaluate_bonds(bonds, bonded, recover_bond=False):
    errors = []
    field = secure.BOND_NAMES.index
    # `load_result` only says the store belongs to this identity; the image
    # persists its local IRK at boot, so peer bonds are `records_loaded`.
    load_result = bonds[field('load_result')]
    records = bonds[field('records_loaded')]
    pairs = bonds[field('pairs_complete')]
    save_ok = bonds[field('save_ok')]
    save_fail = bonds[field('save_fail')]
    if recover_bond:
        # B2 deleted bond: the store still had a bond, the peer rejected it,
        # and the recovery pairing must save a replacement.
        if load_result != 1:
            errors.append(f'recovery run did not load a valid store (load_result={load_result})')
        if records < 1:
            errors.append('recovery run had no stored bond to reject')
        if pairs < 1:
            errors.append('recovery run never re-paired after BondLost')
        if save_ok < 1:
            errors.append('recovery run did not save the replacement bond')
    elif bonded:
        if load_result != 1:
            errors.append(f'bonded run did not load a valid store (load_result={load_result})')
        if records < 1:
            errors.append('bonded run loaded no peer bond')
        if pairs != 0:
            errors.append(f'bonded reconnect re-paired ({pairs} pairings)')
    else:
        if records != 0:
            errors.append(f'fresh run found {records} stored bond(s)')
        if pairs < 1:
            errors.append('fresh run never completed a pairing')
        if save_ok < 1:
            errors.append('the new bond was never saved')
    if save_fail:
        errors.append(f'bond saves failed: {save_fail}')
    return errors


def evaluate_phone(rows):
    errors = []
    events = lambda name: [row for row in rows if row.get('event') == name]
    if not events('hid_ready'):
        errors.append('phone never published the HID service')
    if not events('connected'):
        errors.append('phone never reported a connection')
    cccd = events('cccd_write')
    if not any(row.get('subscribed') for row in cccd):
        errors.append(f'phone saw no Report CCCD subscription ({len(cccd)} writes)')
    if not events('report_reference_read'):
        errors.append('phone never served the Report Reference descriptor')
    reads = [row for row in events('hid_read') if row.get('uuid', '').startswith('00002a4b')]
    if not reads:
        errors.append('phone never served the Report Map read')
    sent = [row for row in events('report') if row.get('sent')]
    if len(sent) < 100:
        errors.append(f'phone sent {len(sent)} reports, expected >= 100')
    failures = [row for row in events('report') if not row.get('sent')]
    if failures:
        errors.append(f'phone failed {len(failures)} report notifications')
    return errors


def evaluate_rejection(host, stats, bonds, sec, consents, store, run_seconds):
    """B2 rejected pairing: the Host must fail cleanly, not hang or bond."""
    errors = []
    if not any(row.get('action') == 'cancel' for row in consents):
        errors.append('the Just Works dialog was never cancelled')
    if host[0] == 0xFF:
        errors.append('host entered the fatal phase')
    if host[1] < 1:
        errors.append('host never reported a connection')
    if host[2] < 1:
        errors.append('host never reported a disconnect after the rejection')
    if host[15] != 4:
        errors.append(f'host security state={host[15]}, expected failed (4)')
    # 0x1xx carries the SMP failure reason; 0x2f0 is the SMP timeout.
    if not (0x100 <= host[8] < 0x200 or host[8] == 0x2f0):
        errors.append(f'host last_error={host[8]:#x}, expected an SMP failure cause')
    name = secure.BOND_NAMES.index
    if bonds[name('records_loaded')] != 0 or bonds[name('pairs_complete')] != 0 \
            or bonds[name('add_bond_ok')] != 0:
        errors.append('the rejected pairing still produced a bond')
    # The boot IRK persist is the only save a rejected run may perform.
    if bonds[name('save_on_disconnect')] != 0:
        errors.append('a bond save ran after the rejected pairing')
    if any(slot.get('record') or slot.get('count') for slot in store):
        errors.append('the bond store holds a record after the rejected pairing')
    sec_name = secure.SEC_NAMES.index
    if sec[sec_name('active')] != 0:
        errors.append('the rejected pairing still activated encryption')
    if sec[sec_name('mic_failure')]:
        errors.append(f'MIC failures: {sec[sec_name("mic_failure")]}')
    if sec[sec_name('errors')]:
        errors.append(f'encryption procedure errors: {sec[sec_name("errors")]}')
    index = gatt.STAT_NAMES.index
    if stats[:3] != [0x5034_3538, 1, 9]:
        errors.append(f'firmware did not finish: magic/version/stage={stats[:3]}')
    if not (run_seconds * 1_000_000 <= stats[index('runtime_us')]
            <= (run_seconds + 3) * 1_000_000):
        errors.append('firmware runtime does not match the finite-run budget')
    if stats[index('stop_err')]:
        errors.append('RF stop was not clean')
    if stats[index('rx_done')] == 0:
        errors.append('central engine received no packets')
    if stats[TX_LATE] != 0:
        errors.append(f'TX_LATE={stats[TX_LATE]} (must be 0)')
    if stats[CONNECT_FAIL] != 0:
        errors.append(f'CONNECT_FAIL={stats[CONNECT_FAIL]}')
    if stats[SUPERVISION] != 0:
        errors.append(f'{stats[SUPERVISION]} supervision expiries (the link hung)')
    if stats[index('terminated')] < 1:
        errors.append('the rejected link was never terminated')
    if stats[index('last_reason')] not in (0x05, 0x08, 0x13):
        errors.append(f'unexpected termination reason {stats[index("last_reason")]:#x}')
    if stats[STEADY_MAX_POLL] > 100_000:
        errors.append(f'steady max host poll {stats[STEADY_MAX_POLL]} us > 100 ms (A3)')
    if stats[PAIRING_MAX_POLL] >= 2_000_000:
        errors.append(f'pairing max host poll {stats[PAIRING_MAX_POLL]} us >= 2 s (A3)')
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors = []
    metadata = {
        'probe': PROBE,
        'round': 'D1',
        'run_seconds': args.run_seconds,
        'target': TARGET_NAME,
        'require_params': args.require_params,
        'recover_bond': args.recover_bond,
        'fresh': args.fresh,
        'reject_pairing': args.reject_pairing,
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
        symbols = gatt.observation_symbols(
            nm_text, image,
            extra=(('HOGP_STATS', 18), ('BOND_STATS', 32), ('SECURE_STATS', 16),
                   ('PEER_DIAG', 10), ('INIT_DIAG', 18)))
        metadata['symbols'] = symbols
        metadata['ram_layout'] = gatt.validate_ram_layout(image, symbols)
        embedded = gatt.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded
        if embedded != args.run_seconds:
            raise ValueError(
                f'ELF RUN_SECONDS={embedded}, but --run-seconds={args.run_seconds}')

        phone = c1.AndroidSource(args.out, TARGET_NAME, False, hid=True)
        # The fixture idles while the preflight and flash run; a small ring
        # buffer evicts `hid_ready` before the log is read.
        io.command(['adb', '-s', ADB_SERIAL, 'logcat', '-G', '16M'],
                   args.out / 'logcat-size.log', 20)
        phone.start(timeout=args.phone_timeout)
        time.sleep(1.0)

        touched = True
        try:
            if args.fresh or args.reject_pairing:
                # A first pairing needs a factory-fresh DUT: erase both bond
                # slots and the client ATT store. The phone side is unpaired by
                # the operator before the run.
                io.command([str(io.PREFLIGHT), '--probe', PROBE[1], '--chip', 'CH585',
                            '--protocol', 'jtag', '--erase-dataflash',
                            '--dataflash-addr', '0x77C00', '--dataflash-len', '1024'],
                           args.out / 'erase-store.log', 120)
            io.flash(archived, args.out, 'test', check_idle=False)
        finally:
            safe_read_at = time.monotonic() + embedded + 3

        # The DUT central initiates pairing; the phone shows the system dialog.
        # Android's SMP fixed-channel timer is ~5 s, so poll tightly. The
        # rejection round cancels the dialog instead.
        tap_dialog = (secure.deny_pairing_dialog if args.reject_pairing
                      else secure.confirm_pairing_dialog)
        consents = []
        while time.monotonic() < safe_read_at:
            consent = tap_dialog(ADB_SERIAL)
            if consent:
                consents.append(consent)
            time.sleep(0.5)
        metadata['pairing_consent'] = consents
        wait_until(safe_read_at)

        observations = {}
        for name, count, names in (('STATS', 64, gatt.STAT_NAMES),
                                   ('HOST_STATS', len(gatt.HOST_NAMES), gatt.HOST_NAMES),
                                   ('HOGP_STATS', 18, HOGP_NAMES),
                                   ('BOND_STATS', 32, secure.BOND_NAMES),
                                   ('SECURE_STATS', 16, secure.SEC_NAMES)):
            words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
            observations[name] = words
            metadata[name.lower()] = dict(zip(names, words))
            (args.out / f'{name.lower()}.json').write_text(
                json.dumps(metadata[name.lower()], indent=2) + '\n')
        if 'SEC_DIAG' in symbols:
            diag = io.read32(symbols['SEC_DIAG'], 64, args.out / 'sec_diag.txt')
            (args.out / 'sec_diag.json').write_text(json.dumps(diag) + '\n')
            metadata['sec_diag'] = diag
        peer_words = io.read32(symbols['PEER_DIAG'], 10, args.out / 'peer_diag.txt')
        metadata['peer_diag'] = decode_peer_diag(peer_words)
        init_words = io.read32(symbols['INIT_DIAG'], 18, args.out / 'init_diag.txt')
        metadata['init_diag'] = dict(zip(
            ('magic', 'prepares', 'accept_len', 'advs', 'matches', 'tx_ok', 'tx_err',
             'last_header', 'last_addr_lo', 'last_addr_hi', 'fal_addr_lo',
             'fal_addr_hi', 'first_target_lo', 'first_target_hi',
             'expire_target_lo', 'expire_target_hi',
             'expire_seen_lo', 'expire_seen_hi'), init_words))
        # Last link-layer PDUs; the ring is diagnostic only, never gated.
        trace_count = min(observations.get('STATS', [0] * 40)[39], 128)
        trace_words = io.read32(symbols['TRACE'], trace_count * 8,
                                 args.out / 'trace.txt') if trace_count else []
        metadata['trace'] = gatt.ordered_trace(trace_words, trace_count)
        (args.out / 'trace.json').write_text(json.dumps(metadata['trace'], indent=2) + '\n')
        if args.recover_bond:
            diag = metadata['peer_diag']
            if not diag.get('stale_bond_rejected'):
                errors.append('recovery run never saw the peer reject the stored LTK')
            elif not diag.get('stale_bond_removed'):
                errors.append('recovery run left the stale bond in the Host store')
        metadata['bond_store'] = read_bond_store(args.out)
        host = observations.get('HOST_STATS', [])
        stats = observations.get('STATS', [])
        hogp = observations.get('HOGP_STATS', [])
        bonds = observations.get('BOND_STATS', [])
        sec = observations.get('SECURE_STATS', [])
        if len(stats) != 64 or len(host) != len(gatt.HOST_NAMES) or len(hogp) != 18 \
                or len(bonds) != 32 or len(sec) != 16:
            errors.append(f'short stats read: STATS {len(stats)}/64, HOST {len(host)}/{len(gatt.HOST_NAMES)}, '
                          f'HOGP {len(hogp)}/18, BOND {len(bonds)}/32, SEC {len(sec)}/16')
        else:
            if args.reject_pairing:
                errors.extend(evaluate_rejection(host, stats, bonds, sec,
                                                 metadata['pairing_consent'],
                                                 metadata['bond_store'],
                                                 args.run_seconds))
            else:
                errors.extend(evaluate(host, stats, hogp, args.require_params))
                errors.extend(evaluate_bonds(bonds, args.bonded, args.recover_bond))
                errors.extend(evaluate_secure(sec, 1 if args.recover_bond else 0))
                if args.bonded:
                    # C3: from off, the stored bond reconnects within 10 s of
                    # boot, needs no dialog and re-pairs nothing.
                    anchor = stats[FIRST_ANCHOR_US]
                    if anchor == 0 or anchor > 10_000_000:
                        errors.append(f'bonded reconnect first anchor at {anchor} us, '
                                      'expected > 0 and <= 10 s')
                    if metadata['pairing_consent']:
                        errors.append('bonded reconnect raised a pairing dialog')
            if (args.fresh or args.reject_pairing) \
                    and bonds[secure.BOND_NAMES.index('load_result')] != 0:
                errors.append('fresh run did not boot on an erased store '
                              f'(load_result={bonds[secure.BOND_NAMES.index("load_result")]})')
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        if phone is not None:
            try:
                phone.stop()
                time.sleep(0.5)
                rows = phone.logs()
                # The rejected round never reaches the HID service.
                if not args.reject_pairing:
                    errors.extend(evaluate_phone(rows))
                try:
                    # Diagnostic evidence for bonding failures: the phone's own
                    # SMP/HCI view, not gated.
                    (args.out / 'phone-bt.logcat.txt').write_text(secure.adb(
                        ADB_SERIAL, 'shell', 'logcat', '-d', '-b', 'all',
                        '-s', 'smp', 'ble_sec', 'bt_stack', 'btm_acl', 'btm_dev',
                        'bt_bta_dm', 'bt_btif_dm', 'bt_shim_hci', 'bluetooth',
                        timeout=120))
                except FAILURES as error:
                    errors.append(f'phone BT log: {type(error).__name__}: {error}')
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
    parser.add_argument('--run-seconds', type=int, default=60)
    parser.add_argument('--phone-timeout', type=int, default=180)
    parser.add_argument('--require-params', action='store_true',
                        help='gate the peer L2CAP parameter request (real HID device)')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--bonded', action='store_true',
                      help='expect a stored bond at boot and no re-pairing (B1 reconnect)')
    mode.add_argument('--recover-bond', action='store_true',
                      help='B2 deleted bond: the peer rejects the stored LTK, recovery must re-pair and save')
    mode.add_argument('--fresh', action='store_true',
                      help='B1 first pairing: erase the DUT store before flashing (unpair the phone first)')
    mode.add_argument('--reject-pairing', action='store_true',
                      help='B2 rejected pairing: cancel the Just Works dialog on a fresh store, '
                           'the Host must surface the failure, terminate and never hang')
    return parser.parse_args(argv)


if __name__ == '__main__':
    sys.exit(execute(options()))
