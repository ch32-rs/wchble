#!/usr/bin/env python3
"""X2a extended advertising round: flash the beacon, scan it from the phone,
gate on EXT_ADV_STATS plus the byte-exact marker, then restore smoke.

The firmware is the `x2-ext-adv` (1M AUX) or `x2-ext-adv-2m` (2M AUX) image:
non-connectable, non-scannable, one 128-byte manufacturer marker. The phone
runs the APK `ext_scan` mode (`setLegacy(false)`), so the beacon set is only
visible to an extended scanner; a legacy scan never reports it.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
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
io = gatt.p3.io
NM = gatt.NM
wait_until = gatt.wait_until

_spec = importlib.util.spec_from_file_location(
    'ch585_build_manifest',
    ROOT / 'examples/ch585-scannable/tools/build_manifest.py')
build_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_manifest)

APK = EXAMPLE / 'tools/android-pair/build/android-pair.apk'
PACKAGE = 'com.example.wchble.pair'
SMOKE = gatt.SMOKE
DEFAULT_ELF = (EXAMPLE / 'target/riscv32imc-unknown-none-elf/release'
               '/ch585-trouble-gatt')
ADB_SERIAL = secure.ADB_SERIAL

# EXT_ADV_STATS words (see main.rs for the writer side).
EXT_NAMES = ('adv_tx', 'aux_tx', 'aux_late', 'rounds', 'events',
             'last_aux_channel', 'last_aux_phy', 'terminated', 'did',
             'data_len', 'aux_air_us', 'aux_skip')
EXPECTED_PHY = {'x2-ext-adv': 1, 'x2-ext-adv-2m': 2}


def fixture_marker():
    """The `beacon.rs` marker, recomputed offline for byte comparison."""
    data = bytearray(128)
    data[0] = 0x7f
    data[1] = 0xff
    data[2] = ord('W')
    data[3] = ord('C')
    for i in range(4, 124):
        data[i] = (i * 7 + 5) & 0xff
    crc = 0xffffffff
    for byte in data[:124]:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xedb88320 & -(crc & 1))
    data[124:128] = (crc ^ 0xffffffff).to_bytes(4, 'little')
    return bytes(data)


MARKER_HEAD = fixture_marker()[:4]


def observation_symbols(text):
    """Beacon image buffers: the shared core plus EXT_ADV_STATS."""
    symbols = {}
    for name in ('STATS', 'HOST_STATS', 'TRACE', 'EXT_ADV_STATS', 'RUN_SECONDS'):
        matches = [int(line.split()[0], 16) for line in text.splitlines()
                   if len(parts := line.split()) == 3 and parts[2] == name]
        if not matches:
            raise ValueError(f'missing {name} symbol')
        if len(matches) > 1:
            raise ValueError(f'ambiguous {name} symbol')
        symbols[name] = matches[0]
    return symbols


def validate_ram_layout(image, symbols):
    """Aligned, writable, non-overlapping buffers inside mapped RAM."""
    sections = gatt.p3.elf_sections(image)
    ranges = []
    for name, count in (('STATS', 64), ('HOST_STATS', 16), ('EXT_ADV_STATS', 16),
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
    return [f'{name}@0x{symbols[name]:08x}' for name in ('STATS', 'EXT_ADV_STATS')]


def evaluate_ext(ext, feature):
    """The beacon's own account of the round."""
    if len(ext) != 16:
        return [f'invalid EXT_ADV_STATS: {len(ext)} words']
    word = dict(zip(EXT_NAMES, ext))
    errors = []
    if not any(ext):
        return ['EXT_ADV_STATS was never written']
    if word['adv_tx'] != word['aux_tx'] or word['aux_tx'] != word['rounds']:
        errors.append(f"adv/aux/rounds disagree: {word['adv_tx']}/"
                      f"{word['aux_tx']}/{word['rounds']}")
    if word['aux_late']:
        errors.append(f"aux packets missed the 600-us window: {word['aux_late']}")
    if word['aux_skip']:
        errors.append(f"rounds were skipped: {word['aux_skip']}")
    if word['events'] < 10:
        errors.append(f"too few extended advertising events: {word['events']}")
    if word['last_aux_phy'] != EXPECTED_PHY[feature]:
        errors.append(f"last aux PHY is {word['last_aux_phy']}, "
                      f"expected {EXPECTED_PHY[feature]}")
    if word['data_len'] != 128:
        errors.append(f"marker length is {word['data_len']}, expected 128")
    return errors


def read_ext_logcat(path, feature):
    """Phone-side evidence: raw extended reports and the marker bytes."""
    text = Path(path).read_text() if Path(path).exists() else ''
    expected = fixture_marker()
    reports = re.findall(r'"event":"ext_report".*?"hex":"([0-9a-f]*)"', text)
    matches, byte_exact, truncated = [], [], []
    for row in reports:
        raw = bytes.fromhex(row)
        if raw[:4] == MARKER_HEAD:
            matches.append(raw)
            if raw == expected:
                byte_exact.append(raw)
            elif len(raw) != len(expected):
                truncated.append(len(raw))
    summary = re.search(r'"event":"ext_summary","reports":(\d+),"matches":(\d+)', text)
    errors = []
    if summary is None:
        errors.append('no ext_summary: the ext_scan window never closed')
    else:
        if int(summary.group(1)) == 0:
            errors.append('phone saw no extended advertisements at all')
        if int(summary.group(2)) == 0:
            errors.append('phone never matched the marker head')
    if matches and not byte_exact and not truncated:
        errors.append('marker matched but the payload bytes differ from the fixture')
    if truncated:
        errors.append(f'phone truncated the record: saw lengths {sorted(set(truncated))}')
    if feature == 'x2-ext-adv-2m':
        # The record bytes ride the AUX_ADV_IND, so a reported 2M secondary PHY
        # proves the aux itself was received at 2M.
        phy_rows = re.findall(r'"event":"ext_report".*?"marker":true,'
                              r'"primary_phy":\d+,"secondary_phy":(\d+)', text)
        seen = sorted({int(value) for value in phy_rows})
        if 2 not in seen:
            errors.append(f'no marker report carried secondary PHY 2M (saw {seen})')
    detail = {'reports': len(reports), 'marker_matches': len(matches),
              'byte_exact': len(byte_exact)}
    return errors, detail


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--serial', default=ADB_SERIAL)
    parser.add_argument('--feature', choices=EXPECTED_PHY, default='x2-ext-adv',
                        help='which acceptance image is on the board')
    parser.add_argument('--run-seconds', type=int, default=25)
    args = parser.parse_args(argv)
    args.out, args.elf, args.smoke_elf = (args.out.resolve(), args.elf.resolve(),
                                          args.smoke_elf.resolve())
    return args


def main(argv=None):
    args = options(argv)
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {'feature': args.feature,
                            'run_seconds': args.run_seconds,
                            'elf': str(args.elf)}
    symbols, ext_words = None, []
    touched = False
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        shutil.copyfile(args.elf, archived)
        shutil.copyfile(args.smoke_elf, smoke)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        symbols = observation_symbols(nm_text)
        metadata['ram_layout'] = validate_ram_layout(image, symbols)
        embedded = gatt.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded
        if embedded != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={embedded}, but --run-seconds={args.run_seconds}')
        if args.manifest is not None:
            manifest = args.out / 'manifest.json'
            shutil.copyfile(args.manifest.resolve(), manifest)
            build_manifest.verify(manifest, archived, 'ext-adv', args.run_seconds,
                                  nm=args.nm)
            metadata['manifest_verified'] = True
        if not APK.is_file():
            raise ValueError(f'APK missing: {APK}')

        # Phone prep before the flash: the firmware window starts at flash.
        secure.adb(args.serial, 'get-state')
        secure.adb(args.serial, 'install', '-g', '-r', str(APK), timeout=120)
        secure.adb(args.serial, 'shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
        secure.adb(args.serial, 'shell', 'wm', 'dismiss-keyguard')
        secure.adb(args.serial, 'shell', 'svc', 'power', 'stayon', 'true')
        secure.adb(args.serial, 'shell', 'am', 'force-stop', PACKAGE)
        secure.adb(args.serial, 'shell', 'logcat', '-c')

        touched = True
        try:
            io.flash(archived, args.out, 'ext-adv')
        finally:
            flash_at = time.monotonic()
        metadata['flash_to_app_s'] = None
        secure.adb(args.serial, 'shell', 'am', 'start', '-n', f'{PACKAGE}/.MainActivity',
                   '--es', 'mode', 'ext_scan')
        metadata['flash_to_app_s'] = round(time.monotonic() - flash_at, 2)
        # The beacon never bonds; the ext_scan window closes on its own.
        time.sleep(args.run_seconds + 5)
        (args.out / 'logcat.txt').write_text(secure.adb(
            args.serial, 'logcat', '-d', '-s', 'WCHBLE', timeout=60))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        try:
            secure.adb(args.serial, 'shell', 'am', 'force-stop', PACKAGE, timeout=15)
        except (OSError, subprocess.SubprocessError):
            pass
        if touched:
            wait_until(time.monotonic() + max(0, args.run_seconds + 3))
            if symbols is not None:
                try:
                    ext_words = io.read32(symbols['EXT_ADV_STATS'], 16,
                                          args.out / 'ext_adv_stats.txt')
                    metadata['ext_adv_stats'] = dict(zip(EXT_NAMES, ext_words))
                    (args.out / 'ext_adv_stats.json').write_text(
                        json.dumps(metadata['ext_adv_stats'], indent=2) + '\n')
                except (OSError, subprocess.SubprocessError) as error:
                    errors.append(f'EXT_ADV_STATS observations: {error}')
            try:
                io.flash(smoke, args.out, 'smoke')
                metadata['smoke_recovery'] = 'restored'
            except (OSError, subprocess.SubprocessError) as error:
                errors.append(f'smoke recovery: {error}')
    log_errors, detail = read_ext_logcat(args.out / 'logcat.txt', args.feature)
    errors.extend(log_errors)
    metadata['phone'] = detail
    if ext_words:
        errors.extend(evaluate_ext(ext_words, args.feature))
    else:
        errors.append('EXT_ADV_STATS was never read')
    (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
