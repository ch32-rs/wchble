#!/usr/bin/env python3
"""Run the finite CH585 active scanner against a controlled Android source.

Phases, each on the same target-src image:
  positive x2      scannable Android advertisement -> SCAN_REQ -> SCAN_RSP
  negative-nonconn ADV_NONCONN_IND with the same ADV marker -> no request
  negative-marker  scannable advertisement with marker O2ADX -> no request
  negative-nosource no controlled source -> no request, radio still receiving

The Android app is started and confirmed advertising before the board is
flashed. The probe is never touched during a run. Every run restores the smoke
image and requires exact-name macOS discovery; failures are preserved.
"""
import argparse
import hashlib
import importlib.util
import json
import os
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


# Reuse the existing command/read/flash policy, including its fixed probe.
io = load('ch585_scannable_runner', ROOT / 'examples/ch585-scannable/tools/run.py')
p3 = load('ch585_peripheral_runner', ROOT / 'examples/ch585-peripheral/tools/run.py')
assert io.ROOT == ROOT
PROBE, NM = io.PROBE, io.NM
EXAMPLE = ROOT / 'examples/ch585-active-scanner'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-active-scanner'
SMOKE = ROOT / 'examples/ch585-rf-smoke/target/riscv32imc-unknown-none-elf/release/ch585-rf-smoke'
APK_DIR = EXAMPLE / 'tools/android-advertiser'
APK = APK_DIR / 'build/wchble-o2adv.apk'
PACKAGE = 'dev.wchble.o2adv'
ACTIVITY = PACKAGE + '/.AdvActivity'

ROW_WORDS = 13
ADV_ROWS = 4
RSP_ROWS = 4
MAGIC = 0x4F323538
SYMBOLS = ('STATS', 'ADV_RING', 'RSP_RING', 'RUN_SECONDS_SYM', 'TARGET_SRC',
           'SCAN_REQ_OFFSET', 'SCAN_ADDR_SYM')
MARKER_ADV = bytes.fromhex('ffff') + b'O2ADV' + b'\x01'
MARKER_RSP = bytes.fromhex('ffff') + b'O2RSP' + b'\x01'
MARKER_WRONG = bytes.fromhex('ffff') + b'O2ADX' + b'\x01'
SCAN_ADDR = bytes.fromhex('310000eeffc1')

# STATS indices (README and src/main.rs must agree).
STAGE, RUN_US, WINDOWS, ARM_ERRORS = 2, 3, 6, 7
COMPLETIONS, TIMEOUTS, CRC_OK, CRC_ERR = 8, 9, 10, 11
BAD_LENGTH, PARSED = 12, 13
PDU_ADV_IND, PDU_ADV_SCAN_IND, PDU_ADV_NONCONN_IND, PDU_ADV_DIRECT_IND = 14, 15, 16, 17
PDU_SCAN_RSP_SEEN, PDU_SCAN_REQ_SEEN, PDU_CONNECT_IND_SEEN, PDU_OTHER = 18, 19, 20, 21
MARKER_ADVS, MARKER_SCANNABLE, MARKER_NONCONN, MARKER_WRONG = 22, 23, 24, 25
ATTEMPTS, SENT, LATE, REQ_ERR = 26, 27, 28, 29
RSP_WINDOWS, RSP_ARM_ERRORS, RSP_COMPLETIONS, RSP_TIMEOUTS = 30, 31, 32, 33
RSP_CRC_OK, RSP_CRC_ERR, RSP_ACCEPTED = 34, 35, 36
RSP_REJECT_TYPE, RSP_REJECT_ADV_A, RSP_REJECT_MARKER = 37, 38, 39
STOP_FAILURES = 40
CH_COMPLETIONS = 41
LAST_TX_ENTRY, MAX_TX_ENTRY, LAST_TX_RETURN, MAX_TX_RETURN = 48, 49, 50, 51
LAST_MARGIN, MIN_MARGIN, LAST_RSP_ARM, MAX_RSP_ARM = 52, 53, 54, 55
LAST_RSP_LATENCY, FINAL_CMD, FINAL_MODE, CLOCK_HZ = 56, 57, 58, 59
TARGET_SRC_STAT, SCAN_REQ_OFFSET_STAT = 60, 61
ADV_CH_MASK, RSP_CH_MASK = 62, 63


def symbols_from(text):
    symbols = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in SYMBOLS:
            symbols[parts[2]] = int(parts[0], 16)
    missing = set(SYMBOLS) - set(symbols)
    if missing:
        raise ValueError(f'missing ELF observation symbols: {sorted(missing)}')
    return symbols


def embedded_bytes(image, address, count):
    """Read a file-backed ELF32 little-endian section, never target memory."""
    for section in p3.elf_sections(image):
        start, size = section['address'], section['size']
        if section['type'] != 8 and start <= address and address + count <= start + size:
            offset = section['offset'] + address - start
            return image[offset:offset + count]
    raise ValueError('symbol is not backed by the expected ELF bytes')


def decode_rows(words, rows):
    out = []
    for slot in range(rows):
        base = words[slot * ROW_WORDS:(slot + 1) * ROW_WORDS]
        if len(base) != ROW_WORDS:
            raise ValueError('short observation row')
        meta = base[1]
        if not meta & (1 << 24):
            continue
        length = (meta >> 8) & 0xFF
        raw = b''.join(word.to_bytes(4, 'little') for word in base[3:])
        raw = raw[:min(length + 2, len(raw))]
        out.append({
            'ticks_us': base[0],
            'channel': meta & 0x3F,
            'length': length,
            'crc_ok': bool(meta & (1 << 16)),
            'pdu_type': (meta >> 17) & 0xF,
            'manufacturer_present': bool(meta & (1 << 21)),
            'rssi_raw': base[2] & 0xFF,
            'adv_a': raw[2:8].hex() if len(raw) >= 8 else '',
            'raw': raw.hex(),
        })
    return out


def common_errors(stats, run_seconds):
    errors = []
    if stats[0] != MAGIC or stats[1] != 1:
        errors.append('unexpected statistics magic or version')
    if stats[STAGE] != 3:
        errors.append(f'firmware did not finish cleanly (stage={stats[STAGE]})')
    if not run_seconds * 1_000_000 - 50_000 <= stats[RUN_US] <= run_seconds * 1_000_000 + 200_000:
        errors.append(f'run duration {stats[RUN_US]} us is outside the expected window')
    if stats[TARGET_SRC_STAT] != 1:
        errors.append('image was not built with the target-src test selector')
    if stats[SCAN_REQ_OFFSET_STAT] != 114:
        errors.append(f'unexpected SCAN_REQ software offset {stats[SCAN_REQ_OFFSET_STAT]}')
    if stats[STOP_FAILURES]:
        errors.append('RF stop was not acknowledged')
    if stats[ARM_ERRORS]:
        errors.append('RX arm or channel error recorded')
    if stats[FINAL_CMD] & 3 or stats[FINAL_MODE] != 0x30000:
        errors.append('radio did not finish idle')
    if stats[WINDOWS] == 0:
        errors.append('no RX window was armed')
    if stats[WINDOWS] != stats[COMPLETIONS] + stats[TIMEOUTS]:
        errors.append('window/completion/timeout counts are inconsistent')
    if stats[COMPLETIONS] != stats[CRC_OK] + stats[CRC_ERR]:
        errors.append('completion/CRC counts are inconsistent')
    if stats[CRC_OK] != stats[BAD_LENGTH] + stats[PARSED]:
        errors.append('CRC-valid/bad-length/parsed counts are inconsistent')
    if stats[PARSED] != sum(stats[PDU_ADV_IND:PDU_OTHER + 1]):
        errors.append('PDU type counts are inconsistent')
    if stats[MARKER_ADVS] != stats[MARKER_SCANNABLE] + stats[MARKER_NONCONN]:
        errors.append('marker advertisement counts are inconsistent')
    if stats[ATTEMPTS] != stats[SENT] + stats[LATE] + stats[REQ_ERR]:
        errors.append('scan-request attempt counts are inconsistent')
    if stats[SENT] != stats[RSP_WINDOWS] + stats[RSP_ARM_ERRORS]:
        errors.append('sent/response-window/arm-error counts are inconsistent')
    if stats[RSP_WINDOWS] != stats[RSP_COMPLETIONS] + stats[RSP_TIMEOUTS]:
        errors.append('response window/completion/timeout counts are inconsistent')
    if stats[RSP_COMPLETIONS] != stats[RSP_CRC_OK] + stats[RSP_CRC_ERR]:
        errors.append('response completion/CRC counts are inconsistent')
    if stats[RSP_CRC_OK] != (stats[RSP_ACCEPTED] + stats[RSP_REJECT_TYPE]
                             + stats[RSP_REJECT_ADV_A] + stats[RSP_REJECT_MARKER]):
        errors.append('response classification counts are inconsistent')
    if sum(stats[CH_COMPLETIONS:CH_COMPLETIONS + 3]) != stats[COMPLETIONS]:
        errors.append('per-channel completion counts are inconsistent')
    return errors


def row_has(row, marker):
    return marker in bytes.fromhex(row['raw'])


def evaluate_positive(stats, adv_rows, rsp_rows, run_seconds):
    errors = common_errors(stats, run_seconds)
    if stats[MARKER_SCANNABLE] < 3:
        errors.append(f'only {stats[MARKER_SCANNABLE]} marked scannable advertisements')
    if stats[ATTEMPTS] != stats[MARKER_SCANNABLE]:
        errors.append('attempt count does not match marked scannable advertisements')
    if stats[SENT] < 3:
        errors.append(f'only {stats[SENT]} SCAN_REQ accepted for transmission')
    if stats[LATE]:
        errors.append('SCAN_REQ missed its software deadline')
    if stats[REQ_ERR]:
        errors.append('SCAN_REQ build or transmit error recorded')
    if stats[RSP_ACCEPTED] < 3:
        errors.append(f'only {stats[RSP_ACCEPTED]} scan responses accepted')
    if stats[RSP_CH_MASK] != 0b111:
        errors.append(f'responses did not cover 37/38/39 (mask={stats[RSP_CH_MASK]:#x})')
    if stats[ADV_CH_MASK] != 0b111:
        errors.append(f'advertisements did not cover 37/38/39 (mask={stats[ADV_CH_MASK]:#x})')
    if not adv_rows:
        errors.append('no marked advertisement rows in ADV_RING')
    for row in adv_rows:
        if not row_has(row, MARKER_ADV):
            errors.append('ADV_RING row lacks the O2ADV marker')
        if row_has(row, MARKER_RSP):
            errors.append('ADV_RING row contains the response marker')
        if row['pdu_type'] not in (0x00, 0x06):
            errors.append(f'ADV_RING row is not scannable (type={row["pdu_type"]})')
    if not rsp_rows:
        errors.append('no accepted response rows in RSP_RING')
    adv_addrs = {row['adv_a'] for row in adv_rows}
    for row in rsp_rows:
        if not row_has(row, MARKER_RSP):
            errors.append('RSP_RING row lacks the O2RSP marker')
        if row_has(row, MARKER_ADV):
            errors.append('RSP_RING row contains the advertisement marker')
        if row['pdu_type'] != 0x04:
            errors.append(f'RSP_RING row is not a SCAN_RSP (type={row["pdu_type"]})')
        if row['adv_a'] not in adv_addrs:
            errors.append('RSP_RING AdvA does not match any answered advertisement')
    return errors


def evaluate_negative_nonconn(stats, run_seconds):
    errors = common_errors(stats, run_seconds)
    if stats[PDU_ADV_NONCONN_IND] == 0:
        errors.append('no ADV_NONCONN_IND received from the non-scannable source')
    if stats[MARKER_NONCONN] == 0:
        errors.append('non-scannable source marker was not received')
    if stats[MARKER_SCANNABLE]:
        errors.append('scannable marker received although the source is non-scannable')
    if stats[ATTEMPTS] or stats[RSP_WINDOWS] or stats[RSP_ACCEPTED]:
        errors.append('scan requests were made to a non-scannable source')
    return errors


def evaluate_negative_marker(stats, run_seconds):
    errors = common_errors(stats, run_seconds)
    if stats[MARKER_WRONG] == 0:
        errors.append('wrong-marker scannable advertisement was not received')
    if stats[MARKER_ADVS]:
        errors.append('expected marker received from the wrong-marker source')
    if stats[ATTEMPTS] or stats[RSP_WINDOWS] or stats[RSP_ACCEPTED]:
        errors.append('scan requests were made to a wrong-marker advertisement')
    return errors


def evaluate_negative_nosource(stats, run_seconds):
    errors = common_errors(stats, run_seconds)
    if stats[CRC_OK] == 0:
        errors.append('no CRC-valid ambient traffic: receiver liveness not shown')
    if stats[MARKER_ADVS] or stats[MARKER_WRONG]:
        errors.append('controlled markers recorded without a source')
    if stats[ATTEMPTS] or stats[RSP_WINDOWS] or stats[RSP_ACCEPTED]:
        errors.append('scan requests were made without a controlled source')
    return errors


def find_adb():
    candidates = [
        os.environ.get('ADB'),
        str(Path.home() / 'Library/Android/sdk/platform-tools/adb'),
        shutil.which('adb'),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise RuntimeError('adb not found; set ADB or ANDROID_SDK_ROOT')


ADB = None
SERIAL = None


def adb(args, timeout=40):
    command = [ADB] + (['-s', SERIAL] if SERIAL else []) + args
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'adb {" ".join(args)} failed: {result.stderr.strip()}')
    return result.stdout


def adb_serial():
    global SERIAL
    if SERIAL:
        return SERIAL
    lines = [line.split()[0] for line in adb(['devices']).splitlines()[1:]
             if line.strip() and line.split()[1] == 'device']
    if len(lines) != 1:
        raise RuntimeError(f'expected exactly one authorized adb device, got {lines}')
    SERIAL = lines[0]
    return SERIAL


def ensure_apk(out):
    if not APK.is_file():
        log = (out / 'apk-build.log').open('w')
        try:
            result = subprocess.run([str(APK_DIR / 'build.sh')], stdout=log,
                                    stderr=subprocess.STDOUT)
        finally:
            log.close()
        if result.returncode:
            raise RuntimeError('android-advertiser build.sh failed')
    adb(['shell', 'am', 'force-stop', PACKAGE])
    # `-g` grants runtime permissions at install; some vendor ROMs refuse a
    # later `pm grant` from the adb shell (observed on CPH2411/ColorOS).
    adb(['install', '-g', '-r', str(APK)], timeout=120)
    for permission in ('android.permission.BLUETOOTH_ADVERTISE',
                       'android.permission.BLUETOOTH_CONNECT'):
        try:
            adb(['shell', 'pm', 'grant', PACKAGE, permission])
        except RuntimeError:
            pass  # already granted, or the ROM forbids shell grants
    return hashlib.sha256(APK.read_bytes()).hexdigest()


def logcat_text():
    try:
        return adb(['logcat', '-d', '-s', 'WCHBLE:I'])
    except RuntimeError:
        return ''


def start_source(out, mode, seconds):
    adb(['shell', 'am', 'force-stop', PACKAGE])
    adb(['logcat', '-c'])
    adb(['shell', 'am', 'start', '-n', ACTIVITY, '--es', 'mode', mode,
         '--ei', 'seconds', str(seconds)])
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        text = logcat_text()
        # `startAdvertisingSet` starts advertising immediately; some ROMs omit
        # the later onAdvertisingEnabled callback, so `started` (status 0) is
        # the readiness event. The board's marker count is the on-air proof.
        if '"event":"advertising"' in text or '"event":"started"' in text:
            return
        if '"event":"error"' in text:
            raise RuntimeError(f'advertiser failed: {text.strip().splitlines()[-1]}')
        if '"event":"permission-request"' in text:
            raise RuntimeError('advertiser needs a runtime permission grant on the phone')
        time.sleep(0.25)
    raise RuntimeError('advertiser did not start advertising in time')


def stop_source(out, phase):
    try:
        adb(['shell', 'am', 'force-stop', PACKAGE])
    finally:
        (out / f'advertiser-{phase}.log').write_text(logcat_text())


def run_phase(args, symbols, elf, phase, mode):
    if mode is None:
        adb(['shell', 'am', 'force-stop', PACKAGE])
    else:
        start_source(args.out, mode, args.run_seconds + 15)
    try:
        io.flash(elf, args.out, phase, check_idle=False)
        wait = time.monotonic() + args.run_seconds + 3
        while time.monotonic() < wait:
            time.sleep(max(0, wait - time.monotonic()))
    finally:
        stop_source(args.out, phase)
    stats = io.read32(symbols['STATS'], 64, args.out / f'stats-{phase}.txt')
    adv = decode_rows(io.read32(symbols['ADV_RING'], ADV_ROWS * ROW_WORDS,
                                args.out / f'adv-{phase}.txt'), ADV_ROWS)
    rsp = decode_rows(io.read32(symbols['RSP_RING'], RSP_ROWS * ROW_WORDS,
                                args.out / f'rsp-{phase}.txt'), RSP_ROWS)
    (args.out / f'stats-{phase}.json').write_text(json.dumps(stats, indent=2) + '\n')
    (args.out / f'adv-{phase}.json').write_text(json.dumps(adv, indent=2) + '\n')
    (args.out / f'rsp-{phase}.json').write_text(json.dumps(rsp, indent=2) + '\n')
    return stats, adv, rsp


def describe(stats):
    return (f'arms={stats[WINDOWS]} done={stats[COMPLETIONS]} '
            f'crc_ok={stats[CRC_OK]} marker={stats[MARKER_ADVS]} '
            f'attempts={stats[ATTEMPTS]} sent={stats[SENT]} late={stats[LATE]} '
            f'accepted={stats[RSP_ACCEPTED]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--run-seconds', type=int, default=30)
    parser.add_argument('--positive-rounds', type=int, default=2)
    parser.add_argument('--skip-negative-nonconn', action='store_true')
    parser.add_argument('--skip-negative-marker', action='store_true')
    parser.add_argument('--skip-negative-nosource', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    elf = args.elf.resolve()
    metadata = {
        'probe': PROBE,
        'run_seconds': args.run_seconds,
        'scan_address': 'C1:FF:EE:00:00:31',
        'scan_req_software_offset_us': 114,
        'air_ifs': 'UNVERIFIED: the 114 us constant is a software offset, not T_IFS',
        'rssi': 'RAW UNCALIBRATED',
    }
    errors = []
    global ADB
    started = False
    try:
        ADB = find_adb()
        metadata['adb_serial'] = adb_serial()
        metadata['phone_model'] = adb(['shell', 'getprop', 'ro.product.model']).strip()
        metadata['phone_sdk'] = adb(['shell', 'getprop', 'ro.build.version.sdk']).strip()

        image = elf.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        (args.out / 'firmware.elf').write_bytes(image)
        nm_text = subprocess.check_output([args.nm, str(elf)], text=True)
        symbols = symbols_from(nm_text)
        metadata['symbols'] = symbols
        run_seconds = p3.embedded_u32(image, symbols['RUN_SECONDS_SYM'])
        target_src = p3.embedded_u32(image, symbols['TARGET_SRC'])
        offset = p3.embedded_u32(image, symbols['SCAN_REQ_OFFSET'])
        scan_addr = embedded_bytes(image, symbols['SCAN_ADDR_SYM'], len(SCAN_ADDR))
        metadata['embedded_run_seconds'] = run_seconds
        metadata['embedded_target_src'] = target_src
        metadata['embedded_scan_req_offset_us'] = offset
        metadata['embedded_scan_address'] = scan_addr.hex()
        if run_seconds != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS is {run_seconds}, expected {args.run_seconds}')
        if target_src != 1:
            raise ValueError('ELF was not built with --features target-src')
        if offset != 114:
            raise ValueError(f'ELF SCAN_REQ_OFFSET is {offset}, expected 114')
        for marker in (MARKER_ADV, MARKER_RSP, MARKER_WRONG):
            if marker not in image:
                raise ValueError(f'marker {marker.hex()} is not embedded in the ELF')
        if scan_addr != SCAN_ADDR:
            raise ValueError(f'ELF scan address is {scan_addr.hex()}, expected {SCAN_ADDR.hex()}')

        metadata['apk_sha256'] = ensure_apk(args.out)

        def phase(name, mode, evaluate):
            stats, adv, rsp = run_phase(args, symbols, elf, name, mode)
            metadata[f'stats_{name}'] = stats
            metadata[f'adv_rows_{name}'] = adv
            metadata[f'rsp_rows_{name}'] = rsp
            found = evaluate(stats, adv, rsp)
            metadata[f'errors_{name}'] = found
            errors.extend(f'{name}: {error}' for error in found)
            print(f'{name}: {describe(stats)}')

        started = True
        for round_index in range(1, args.positive_rounds + 1):
            phase(f'positive-{round_index}', 'scannable',
                  lambda s, a, r: evaluate_positive(s, a, r, args.run_seconds))
            time.sleep(3)
        if not args.skip_negative_nonconn:
            phase('negative-nonconn', 'non-scannable',
                  lambda s, a, r: evaluate_negative_nonconn(s, args.run_seconds))
        if not args.skip_negative_marker:
            phase('negative-marker', 'wrong-marker',
                  lambda s, a, r: evaluate_negative_marker(s, args.run_seconds))
        if not args.skip_negative_nosource:
            phase('negative-nosource', None,
                  lambda s, a, r: evaluate_negative_nosource(s, args.run_seconds))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        errors.append(str(error))
    finally:
        if ADB:
            try:
                adb(['shell', 'am', 'force-stop', PACKAGE])
            except (OSError, RuntimeError):
                pass
        if started:
            try:
                io.flash(args.smoke_elf, args.out, 'restore', check_idle=False)
                io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                           args.out / 'restore-scan.log', 20)
                metadata['smoke_recovery'] = 'flash verify and exact-name macOS discovery PASS'
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                errors.append(f'recovery: {error}')
                metadata['smoke_recovery'] = 'NOT VERIFIED'
        else:
            metadata['smoke_recovery'] = 'NOT ATTEMPTED: preflight failed before hardware access'
        metadata['errors'] = errors
        metadata['passed'] = not errors
        (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
