#!/usr/bin/env python3
"""S3 bond-store acceptance, one phase per invocation.

Phases run in this order; each invocation is independent so a failure stays on
disk and is never retried automatically:

    wipe -> pair -> reconnect -> delete -> (forget the bond on the phone)
    repair -> fault -> powercycle

`pair` keeps the image in flash so `reconnect` can be a reset instead of a
download; `fault` keeps it for `powercycle`, where the operator unplugs and
replugs the board. Every other exit restores and scans the smoke image. Bond
records live in DataFlash: neither a download nor a reset erases them, so the
smoke restore does not destroy evidence.

The runner never probes while RF may still be running: it waits the embedded
`RUN_SECONDS + 3` after the image starts before reading RAM or DataFlash.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time
import zlib

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('s3_secure_run', HERE / 'secure_run.py')
secure = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(secure)
p4, io = secure.p4, secure.io

PROBE = '1a86:8010:F93D8F067E10'
PAGE = 256
STORE_MAGIC = 0x3344_4E42
HOST_SECURITY = 15  # HOST_STATS.reserved_15 carries the Host security state
LL_REJECT_UNKNOWN_KEY = 0x06
PHASES = ('wipe', 'pair', 'reconnect', 'delete', 'repair', 'fault', 'powercycle')
STORE_VERSION = 2
LOCAL_IDENTITY_LEN = 7
BOND_HEADER_LEN = LOCAL_IDENTITY_LEN + 1


def run_logged(args, out, prefix, timeout=240):
    return io.command(args, out / f'{prefix}.log', timeout=timeout)


def reset(out):
    run_logged([str(io.PREFLIGHT), '--probe', PROBE, '--chip', 'CH585',
                '--protocol', 'jtag', '--reset'], out, 'reset')


def dump(out, address, length, prefix='dataflash'):
    path = out / f'{prefix}.bin'
    run_logged([str(io.PREFLIGHT), '--probe', PROBE, '--chip', 'CH585',
                '--protocol', 'jtag', '--dump-dataflash', str(path),
                '--dataflash-addr', hex(address), '--dataflash-len', str(length)],
               out, prefix)
    return parse_dump(path)


def parse_dump(path):
    """Decode the store's two slots straight from the recorded bytes."""
    data = Path(path).read_bytes()
    slots = []
    for index in range(len(data) // PAGE):
        page = data[index * PAGE:(index + 1) * PAGE]
        magic, version, flags, seq, length, _reserved, payload_crc, header_crc = \
            struct.unpack_from('<IHHIHHII', page)
        header_ok = (magic == STORE_MAGIC and version == STORE_VERSION
                     and header_crc == zlib.crc32(page[:20]))
        payload_ok = header_ok and payload_crc == zlib.crc32(page[24:24 + length])
        record = None
        local = None
        count = 0
        if header_ok and length > BOND_HEADER_LEN:
            payload = page[24:24 + length]
            local = payload[:LOCAL_IDENTITY_LEN].hex()
            count = payload[LOCAL_IDENTITY_LEN]
            if count:
                start = BOND_HEADER_LEN
                record = payload[start:start + 52].hex()
        slots.append({
            'slot': index,
            'magic': f'{magic:#010x}',
            'version': version,
            'seq': seq,
            'length': length,
            'header_ok': header_ok,
            'payload_ok': payload_ok,
            'tombstone': header_ok and length == 0,
            'local': local,
            'count': count,
            'record': record,
        })
    return slots


def valid_slots(slots):
    return [slot for slot in slots if slot['payload_ok'] and not slot['tombstone']]


def start_app(args, mode):
    # One phase can start the app twice (delete, then the rejection run); the
    # transcript must only contain the new run's lines.
    secure.adb(args.serial, 'logcat', '-c')
    secure.adb(args.serial, 'shell', 'am', 'force-stop', secure.PACKAGE)
    secure.adb(args.serial, 'shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
    secure.adb(args.serial, 'shell', 'wm', 'dismiss-keyguard')
    secure.adb(args.serial, 'shell', 'svc', 'power', 'stayon', 'true')
    secure.adb(args.serial, 'shell', 'am', 'start', '-W', '-n', secure.ACTIVITY,
               '--es', 'mode', mode)


def wait_for_app(args, out, mode, consent=False):
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        # `pidof` exits 1 once the app is gone; that is the success signal.
        pid = secure.adb(args.serial, 'shell', 'pidof', secure.PACKAGE,
                         check=False).strip()
        if not pid:
            break
        if consent:
            secure.confirm_pairing_dialog(args.serial)
        time.sleep(0.5)
    else:
        raise RuntimeError(f'phone app ({mode}) did not finish within {args.timeout}s')
    log_path = out / f'logcat-{mode}.txt'
    log_path.write_text(secure.adb(args.serial, 'logcat', '-d', '-s', 'WCHBLE:I',
                                   timeout=60))
    rows = after_last_mode(secure.read_log(log_path.read_text().splitlines()))
    (out / f'transcript-{mode}.jsonl').write_text(
        '\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n')
    return rows


def after_last_mode(rows):
    """Drop lines from an earlier app launch in the same log buffer."""
    starts = [index for index, row in enumerate(rows) if row.get('event') == 'mode']
    return rows[starts[-1]:] if starts else rows


def summary(rows):
    summaries = [row for row in rows if row.get('event') == 'summary']
    return summaries[0] if len(summaries) == 1 else None


def collect(out, symbols, seconds, prefix=''):
    """Read every observation buffer and judge the firmware completion first."""
    named, raw = {}, {}
    for name, count, names in (('STATS', 64, secure.STAT_NAMES),
                               ('HOST_STATS', 16, secure.HOST_NAMES),
                               ('SECURE_STATS', 16, secure.SEC_NAMES),
                               ('BOND_STATS', 32, secure.BOND_NAMES)):
        words = io.read32(symbols[name], count, out / f'{prefix}{name.lower()}.txt')
        raw[name] = words
        named[name] = dict(zip(names, words))
    echo = secure.decode_bond_echo(
        io.read32(symbols['BOND_ECHO'], 16, out / f'{prefix}bond_echo.txt'))
    (out / f'{prefix}stats.json').write_text(json.dumps(
        {'stats': named, 'echo': echo}, indent=2) + '\n')
    errors = []
    if named['BOND_STATS']['magic'] != secure.BOND_MAGIC:
        errors.append('BOND_STATS magic missing')
    if named['BOND_STATS']['version'] != 1:
        errors.append('BOND_STATS version is not 1')
    return named, raw, echo, errors


def security_errors(named, raw, seconds, prefix=''):
    return secure.evaluate_security(raw['SECURE_STATS'], raw['HOST_STATS'],
                                    raw['STATS'], seconds)


def app_errors(rows, reason, pass_expected=True):
    app = summary(rows)
    if app is None:
        return [f'expected exactly one app summary, got {app}']
    if pass_expected and (app.get('pass') is not True or app.get('reason') != reason):
        return [f'app summary is not {reason}: {app}']
    if not pass_expected and app.get('pass') is not False:
        return [f'app summary unexpectedly passed: {app}']
    return []


def dump_matches_echo(slots, echo):
    valid = valid_slots(slots)
    if len(valid) != 1:
        return [f'expected one valid stored copy, saw {len(valid)}']
    record = bytes.fromhex(valid[0]['record'] or '')
    if len(record) < 52:
        return ['stored record is too short']
    if not echo.get('present'):
        return ['the Host never recorded a bond to compare against']
    if record[0:16].hex() != echo['ltk']:
        return ['stored LTK differs from the key the Host used']
    if echo.get('local_present'):
        expected = bytes([echo['local_address_kind']]) + bytes.fromhex(
            echo['local_address'].replace(':', ''))
        if valid[0].get('local') != expected.hex():
            return [f'stored local identity {valid[0].get("local")} differs from '
                    f'the advertised one {expected.hex()}']
    return []


def checks_pair(named, raw, echo, rows, slots, seconds):
    errors = security_errors(named, raw, seconds)
    errors += app_errors(rows, 'encrypted_read_write_ok')
    bonds = named['BOND_STATS']
    if bonds['load_result'] != 0:
        errors.append(f'expected a fresh store before pairing, load_result={bonds["load_result"]}')
    if bonds['pairs_complete'] != 1:
        errors.append(f'expected one completed pairing, saw {bonds["pairs_complete"]}')
    if bonds['save_ok'] < 1:
        errors.append('the new bond was never saved')
    if bonds['save_fail']:
        errors.append(f'{bonds["save_fail"]} bond saves failed')
    errors += dump_matches_echo(slots, echo)
    return errors


def checks_reconnect(named, raw, rows, seconds):
    errors = security_errors(named, raw, seconds)
    errors += app_errors(rows, 'reconnect_encrypted_read_write_ok')
    bonds = named['BOND_STATS']
    sec = named['SECURE_STATS']
    if bonds['load_result'] != 1:
        errors.append(f'bond was not restored: load_result={bonds["load_result"]}')
    if bonds['records_loaded'] < 1:
        errors.append('no bond record was decoded at boot')
    if bonds['pairs_complete'] != 0:
        errors.append('the resumed session paired again instead of reusing the bond')
    if bonds['save_attempts'] != 0:
        errors.append(f'{bonds["save_attempts"]} bond writes on a resumed session')
    if bonds['add_bond_ok'] < bonds['records_loaded']:
        errors.append('the boot restore did not hand every record to the Host')
    if sec['ltk_request'] < 1 or sec['ltk_reply'] < 1:
        errors.append(f'controller did not use the stored LTK: '
                      f'request={sec["ltk_request"]} reply={sec["ltk_reply"]}')
    if sec['mic_failure']:
        errors.append('MIC failures on the resumed link')
    return errors


def checks_delete(delete_named, delete_raw, delete_rows, slots,
                  reject_named, reject_rows, seconds):
    errors = security_errors(delete_named, delete_raw, seconds)
    errors += app_errors(delete_rows, 'bond_delete_ok')
    bonds = delete_named['BOND_STATS']
    if bonds['clear_requests'] < 1 or bonds['clear_ok'] != 1:
        errors.append(f'store was not cleared: requests={bonds["clear_requests"]} '
                      f'ok={bonds["clear_ok"]}')
    if bonds['in_memory_removed'] < 1:
        errors.append('the Host bond table was not cleared')
    if valid_slots(slots):
        errors.append('a valid bond survived deletion')
    if not any(slot['tombstone'] for slot in slots):
        errors.append('no tombstone was written')
    errors += app_errors(reject_rows, 'reconnect_encrypted_read_write_ok', pass_expected=False)
    sec = reject_named['SECURE_STATS']
    if sec['ltk_request'] < 1:
        errors.append('the controller never asked for the deleted LTK')
    if sec['start_req'] != 0:
        errors.append(f'encryption started after deletion: start_req={sec["start_req"]}')
    if sec['last_error'] != LL_REJECT_UNKNOWN_KEY:
        errors.append(f'expected LL_REJECT_IND 0x06, last_error={sec["last_error"]}')
    if reject_named['BOND_STATS']['pairs_complete'] != 0:
        errors.append('the rejection run paired instead of being refused')
    return errors


def checks_wipe(named, rows, slots):
    errors = app_errors(rows, 'bond_wipe_ok')
    bonds = named['BOND_STATS']
    if bonds['clear_requests'] < 1 or bonds['clear_ok'] != 1:
        errors.append(f'wipe did not erase both slots: requests={bonds["clear_requests"]} '
                      f'ok={bonds["clear_ok"]}')
    if valid_slots(slots):
        errors.append('a valid record survived the wipe')
    if any(slot['header_ok'] for slot in slots):
        errors.append('a store header survived the wipe')
    return errors


def checks_fault(named, rows, slots, reconnect_named, reconnect_raw,
                 reconnect_rows, seconds):
    errors = app_errors(rows, 'fault_injected_ok')
    bonds = named['BOND_STATS']
    if bonds['fault_injected'] != 1:
        errors.append(f'fault was not injected once: {bonds["fault_injected"]}')
    if len(valid_slots(slots)) != 1:
        errors.append(f'expected the previous copy to survive, saw '
                      f'{len(valid_slots(slots))} valid copies')
    if not any(slot['header_ok'] and not slot['payload_ok'] for slot in slots):
        errors.append('the interrupted copy has a valid payload; expected a CRC mismatch')
    errors += checks_reconnect(reconnect_named, reconnect_raw,
                               reconnect_rows, seconds)
    return errors


def phase_pair(args, out, symbols, image, seconds):
    secure.flash(image, out, 'test')
    started = time.monotonic()
    start_app(args, 'pair')
    rows = wait_for_app(args, out, 'pair', consent=True)
    p4.wait_until(started + seconds + 3)
    named, raw, echo, errors = collect(out, symbols, seconds)
    slots = dump(out, args.dataflash_addr, args.dataflash_len)
    errors += checks_pair(named, raw, echo, rows, slots, seconds)
    return errors, {'stats': named, 'echo': echo, 'dataflash': slots}


def phase_wipe(args, out, symbols, image, seconds):
    secure.flash(image, out, 'test')
    started = time.monotonic()
    start_app(args, 'wipe')
    rows = wait_for_app(args, out, 'wipe')
    p4.wait_until(started + seconds + 3)
    named, _raw, echo, errors = collect(out, symbols, seconds)
    slots = dump(out, args.dataflash_addr, args.dataflash_len)
    errors += checks_wipe(named, rows, slots)
    return errors, {'stats': named, 'echo': echo, 'dataflash': slots}


def phase_reconnect(args, out, symbols, seconds):
    reset(out)
    started = time.monotonic()
    start_app(args, 'reconnect')
    rows = wait_for_app(args, out, 'reconnect')
    p4.wait_until(started + seconds + 3)
    named, raw, echo, errors = collect(out, symbols, seconds)
    errors += checks_reconnect(named, raw, rows, seconds)
    return errors, {'stats': named, 'echo': echo}


def phase_powercycle(args, out, symbols, seconds):
    """The operator unplugged and replugged USB, so this is a real power cycle."""
    started = time.monotonic()
    start_app(args, 'reconnect')
    rows = wait_for_app(args, out, 'reconnect')
    p4.wait_until(started + seconds + 3)
    named, raw, echo, errors = collect(out, symbols, seconds)
    errors += checks_reconnect(named, raw, rows, seconds)
    return errors, {'stats': named, 'echo': echo}


def phase_delete(args, out, symbols, image, seconds):
    secure.flash(image, out, 'test')
    started = time.monotonic()
    start_app(args, 'delete')
    rows = wait_for_app(args, out, 'delete')
    p4.wait_until(started + seconds + 3)
    named, raw, echo, errors = collect(out, symbols, seconds)
    slots = dump(out, args.dataflash_addr, args.dataflash_len)

    # Same image, fresh boot: the phone still holds the key, the board no
    # longer does, so the controller must reject it.
    reset(out)
    started = time.monotonic()
    start_app(args, 'reconnect')
    reject_rows = wait_for_app(args, out, 'reject')
    p4.wait_until(started + seconds + 3)
    reject_named, reject_raw, _, reject_errors = collect(out, symbols, seconds,
                                                         prefix='reject-')
    errors += reject_errors
    errors += checks_delete(named, raw, rows, slots, reject_named, reject_rows, seconds)
    return errors, {'stats': named, 'echo': echo, 'dataflash': slots,
                    'reject': reject_named}


def phase_fault(args, out, symbols, image, seconds, nm_text):
    if 'BOND_FAULT_BUILD' not in nm_text:
        raise ValueError('the fault phase needs an image built with --features bond-fault')
    secure.flash(image, out, 'test')
    started = time.monotonic()
    start_app(args, 'fault')
    rows = wait_for_app(args, out, 'fault')
    p4.wait_until(started + seconds + 3)
    named, _raw, echo, errors = collect(out, symbols, seconds)
    slots = dump(out, args.dataflash_addr, args.dataflash_len)

    reset(out)
    started = time.monotonic()
    start_app(args, 'reconnect')
    reconnect_rows = wait_for_app(args, out, 'reconnect')
    p4.wait_until(started + seconds + 3)
    reconnect_named, reconnect_raw, _, reconnect_errors = collect(
        out, symbols, seconds, prefix='reconnect-')
    errors += reconnect_errors
    errors += checks_fault(named, rows, slots, reconnect_named, reconnect_raw,
                           reconnect_rows, seconds)
    return errors, {'stats': named, 'echo': echo, 'dataflash': slots,
                    'reconnect': reconnect_named}


def load_symbols(image):
    nm_text = io.command([p4.NM, str(image)], Path(f'{image}.nm.txt'))
    symbols = p4.symbols_from(nm_text)
    for name in ('STATS', 'HOST_STATS', 'SECURE_STATS', 'SEC_DIAG', 'SEC_OPCODES',
                 'HOST_ERROR', 'BOND_STATS', 'BOND_ECHO', 'PERIPHERAL_ADDRESS',
                 'TRACE', 'RUN_SECONDS'):
        matches = [parts for line in nm_text.splitlines()
                   if len(parts := line.split()) == 3 and parts[2] == name]
        if len(matches) != 1:
            raise ValueError(f'missing or ambiguous {name} symbol')
        symbols[name] = int(matches[0][0], 16)
    return symbols, nm_text


def execute(args):
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    metadata = {'phase': args.phase, 'errors': []}
    errors = []
    keep = args.keep_image
    try:
        archived = out / 'firmware.elf'
        shutil.copyfile(args.elf, archived)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        symbols, nm_text = load_symbols(archived)
        symbols = secure.validate_observation_buffers(image, symbols)
        metadata['symbols'] = symbols
        seconds = p4.embedded_u32(image, symbols['RUN_SECONDS'])
        if seconds != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={seconds}, requested {args.run_seconds}')
        secure.adb(args.serial, 'get-state')
        secure.adb(args.serial, 'install', '-g', '-r', str(secure.APK), timeout=120)
        secure.adb(args.serial, 'logcat', '-c')

        if args.phase == 'wipe':
            errors, detail = phase_wipe(args, out, symbols, archived, seconds)
        elif args.phase == 'pair' or args.phase == 'repair':
            errors, detail = phase_pair(args, out, symbols, archived, seconds)
        elif args.phase == 'reconnect':
            errors, detail = phase_reconnect(args, out, symbols, seconds)
        elif args.phase == 'delete':
            errors, detail = phase_delete(args, out, symbols, archived, seconds)
        elif args.phase == 'fault':
            errors, detail = phase_fault(args, out, symbols, archived, seconds, nm_text)
        else:
            errors, detail = phase_powercycle(args, out, symbols, seconds)
        metadata['detail'] = detail
    except (*secure.FAILURES, subprocess.CalledProcessError) as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        # `pair` keeps the image for `reconnect`; `fault` keeps it for the
        # operator's unplug/replug before `powercycle`.
        keep = keep or (args.phase in ('pair', 'fault') and not errors)
        restored = False
        if not keep:
            try:
                secure.flash(args.smoke_elf, out, 'restore')
                io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                           out / 'restore-scan.log', 20)
                restored = True
            except (*secure.FAILURES, subprocess.CalledProcessError) as error:
                errors.append(f'recovery: {error}')
        metadata['errors'] = errors
        metadata['smoke_recovery'] = ('PASS' if restored
                                      else 'kept test image' if keep else 'NOT VERIFIED')
        metadata['passed'] = not errors
        (out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps({'phase': args.phase, 'passed': metadata['passed'],
                      'errors': metadata['errors'],
                      'smoke_recovery': metadata['smoke_recovery']}, indent=2))
    return int(not metadata['passed'])


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=PHASES)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=secure.DEFAULT_ELF,
                        help='image to flash (secure,accept-control build; '
                             'bond-fault build for `fault`)')
    parser.add_argument('--smoke-elf', type=Path, default=secure.SMOKE)
    parser.add_argument('--serial', default=secure.ADB_SERIAL)
    parser.add_argument('--run-seconds', type=int, default=60)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--dataflash-addr', type=lambda text: int(text, 0),
                        default=0x77E00)
    parser.add_argument('--dataflash-len', type=lambda text: int(text, 0),
                        default=512)
    parser.add_argument('--keep-image', action='store_true',
                        help='leave the test image in flash instead of restoring smoke')
    args = parser.parse_args(argv)
    if args.dataflash_len % PAGE or not 2 * PAGE <= args.dataflash_len <= 0x8000:
        parser.error('--dataflash-len must cover whole 256-byte pages')
    args.out, args.elf, args.smoke_elf = (args.out.resolve(), args.elf.resolve(),
                                          args.smoke_elf.resolve())
    return args


if __name__ == '__main__':
    sys.exit(execute(options()))
