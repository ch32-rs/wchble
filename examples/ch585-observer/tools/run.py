#!/usr/bin/env python3
"""Run the finite CH585 Observer against a controlled Mac advertiser.

Positive phase: a CBPeripheralManager advertises a known local name and
manufacturer data while the board listens. Negative phase: the same image runs
with no controlled source and must record zero matches. Every phase restores
the smoke image afterwards and checks exact-name macOS discovery.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
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
EXAMPLE = ROOT / 'examples/ch585-observer'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-observer'
SMOKE = ROOT / 'examples/ch585-rf-smoke/target/riscv32imc-unknown-none-elf/release/ch585-rf-smoke'
ADVERTISER = EXAMPLE / 'tools/advertise.swift'
NAME = 'wch585-obs-src'
MANUFACTURER = bytes.fromhex('ffff4f310001')

ROW_WORDS = 13
SYMBOLS = ('STATS', 'SAMPLE', 'MATCH', 'RUN_SECONDS_SYM', 'TARGET_SRC')
SAMPLE_ROWS = 32
MATCH_ROWS = 4
MAGIC = 0x4F313538


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
        out.append({
            'ticks_us': base[0],
            'channel': meta & 0x3F,
            'length': length,
            'crc_ok': bool(meta & (1 << 16)),
            'pdu_type': (meta >> 17) & 0xF,
            'manufacturer_present': bool(meta & (1 << 21)),
            'name_present': bool(meta & (1 << 22)),
            'rssi_raw': base[2] & 0xFF,
            'raw': raw[:min(length + 2, len(raw))].hex(),
        })
    return out


def ad_elements(raw):
    """Parse [header, length, payload] into AD elements; tolerate truncation."""
    payload = raw[2:]
    if len(payload) < 6:
        return []
    elements = []
    data = payload[6:]
    index = 0
    while index < len(data):
        length = data[index]
        if length == 0 or index + 1 + length > len(data):
            break
        elements.append((data[index + 1], data[index + 2:index + 1 + length]))
        index += 1 + length
    return elements


def row_has_name(row):
    return any(ad_type in (0x08, 0x09) and value == NAME.encode() for ad_type, value in ad_elements(bytes.fromhex(row['raw'])))


def row_has_manufacturer(row):
    return any(ad_type == 0xFF and value == MANUFACTURER for ad_type, value in ad_elements(bytes.fromhex(row['raw'])))


def common_errors(stats):
    errors = []
    if stats[0] != MAGIC or stats[1] != 1:
        errors.append('unexpected statistics magic or version')
    if stats[2] != 3:
        errors.append(f'firmware did not finish cleanly (stage={stats[2]})')
    if stats[16]:
        errors.append('RF stop was not acknowledged')
    if stats[7]:
        errors.append('RX arm or channel error recorded')
    if stats[42] & 3 or stats[43] != 0x30000:
        errors.append('radio did not finish idle')
    if stats[6] == 0:
        errors.append('no RX window was armed')
    if stats[6] != stats[8] + stats[9]:
        errors.append('window/completion/timeout counts are inconsistent')
    if stats[8] != stats[12] + stats[13]:
        errors.append('completion/CRC counts are inconsistent')
    if stats[11] > stats[9]:
        errors.append('more captured-without-completion than timeouts')
    if stats[17] + stats[18] + stats[19] != stats[8]:
        errors.append('per-channel completion counts are inconsistent')
    if stats[20] + stats[21] + stats[22] != stats[12]:
        errors.append('per-channel CRC counts are inconsistent')
    if stats[12] != stats[14] + sum(stats[23:32]):
        errors.append('PDU type counts are inconsistent')
    if stats[34] != sum(stats[23:32]):
        errors.append('sample count does not match parsed PDUs')
    if stats[35] != max(0, stats[34] - SAMPLE_ROWS):
        errors.append('sample overflow counter is inconsistent')
    return errors


def evaluate_positive(stats, rows, run_seconds):
    errors = common_errors(stats)
    if not run_seconds * 1_000_000 - 50_000 <= stats[3] <= run_seconds * 1_000_000 + 200_000:
        errors.append(f'run duration {stats[3]} us is outside the expected window')
    if stats[45] != 1:
        errors.append('image was not built with the target-src test selector')
    if stats[33] < 3:
        errors.append(f'only {stats[33]} controlled-source matches recorded')
    if stats[33] != stats[36]:
        errors.append('match counter and match ring count disagree')
    if stats[12] < stats[33]:
        errors.append('more matches than CRC-valid advertisements')
    if stats[32] == 0:
        errors.append('no advertisement carried a local name')
    valid = [row for row in rows if row['channel'] in (37, 38, 39)]
    if not valid:
        errors.append('no valid match rows in the ring')
    # The exact local name is the controlled identifier. macOS does not put
    # CBAdvertisementDataManufacturerDataKey into ADV_IND (observed on 15.x
    # with the sniffer), so manufacturer data is recorded when present but is
    # not a gate.
    if not any(row_has_name(row) for row in valid):
        errors.append('no match row carries the controlled local name')
    return errors


def evaluate_negative(stats, rows):
    errors = common_errors(stats)
    if stats[45] != 1:
        errors.append('image was not built with the target-src test selector')
    if stats[33] != 0 or stats[36] != 0:
        errors.append('controlled-source matches recorded without a source')
    if any(row['channel'] in (37, 38, 39) for row in rows):
        errors.append('match ring was not empty')
    return errors


def compile_advertiser(out):
    binary = out / 'advertise'
    with (out / 'advertise-build.log').open('w') as log:
        result = subprocess.run(['swiftc', str(ADVERTISER), '-o', str(binary)],
                                stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError('advertise.swift failed to compile')
    return binary


def start_advertiser(binary, out, seconds, timeout):
    log_path = out / 'advertiser.log'
    log = log_path.open('w')
    process = subprocess.Popen([str(binary), '--seconds', str(seconds),
                                '--name', NAME, '--manufacturer', MANUFACTURER.hex()],
                               stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log.close()
            raise RuntimeError('advertiser exited before advertising')
        if log_path.exists() and '"event":"advertising"' in log_path.read_text():
            return process, log
        time.sleep(0.2)
    stop_advertiser(process, log)
    raise RuntimeError('advertiser did not start advertising in time')


def stop_advertiser(process, log):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if log is not None:
        log.close()


def read_phase(symbols, out, prefix):
    stats = io.read32(symbols['STATS'], 48, out / f'stats-{prefix}.txt')
    sample = io.read32(symbols['SAMPLE'], SAMPLE_ROWS * ROW_WORDS,
                       out / f'samples-{prefix}.txt')
    match = io.read32(symbols['MATCH'], MATCH_ROWS * ROW_WORDS,
                      out / f'matches-{prefix}.txt')
    (out / f'stats-{prefix}.json').write_text(json.dumps(stats, indent=2) + '\n')
    (out / f'samples-{prefix}.json').write_text(json.dumps(decode_rows(sample, SAMPLE_ROWS), indent=2) + '\n')
    matches = decode_rows(match, MATCH_ROWS)
    (out / f'matches-{prefix}.json').write_text(json.dumps(matches, indent=2) + '\n')
    return stats, matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--run-seconds', type=int, default=30)
    parser.add_argument('--advertiser-timeout', type=float, default=15)
    parser.add_argument('--no-advertiser', action='store_true',
                        help='skip the positive phase; run only the negative control')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    elf = args.elf.resolve()
    metadata = {
        'probe': PROBE,
        'run_seconds': args.run_seconds,
        'controlled_name': NAME,
        'controlled_manufacturer': MANUFACTURER.hex(),
        'air_coverage': 'UNVERIFIED: finite windows with gaps between arms',
        'rssi': 'RAW UNCALIBRATED',
    }
    errors = []
    process = None
    log = None
    binary = None
    advertises = False
    started = False
    try:
        image = elf.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        (args.out / 'firmware.elf').write_bytes(image)
        nm_text = subprocess.check_output([args.nm, str(elf)], text=True)
        symbols = symbols_from(nm_text)
        metadata['symbols'] = symbols
        run_seconds = p3.embedded_u32(image, symbols['RUN_SECONDS_SYM'])
        target_src = p3.embedded_u32(image, symbols['TARGET_SRC'])
        metadata['embedded_run_seconds'] = run_seconds
        metadata['embedded_target_src'] = target_src
        if run_seconds != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS is {run_seconds}, expected {args.run_seconds}')
        if target_src != 1:
            raise ValueError('ELF was not built with --features target-src')
        if NAME.encode() not in image:
            raise ValueError('controlled name is not embedded in the ELF')

        if not args.no_advertiser:
            binary = compile_advertiser(args.out)
            process, log = start_advertiser(binary, args.out, args.run_seconds + 30,
                                            args.advertiser_timeout)
            advertises = True
        started = True
        if advertises:
            io.flash(elf, args.out, 'positive', check_idle=False)
            wait = time.monotonic() + args.run_seconds + 3
            while time.monotonic() < wait:
                time.sleep(max(0, wait - time.monotonic()))
            stop_advertiser(process, log)
            process, log = None, None
            stats, matches = read_phase(symbols, args.out, 'positive')
            metadata['stats_positive'] = stats
            metadata['match_rows_positive'] = matches
            metadata['advertiser'] = 'PASS'
            errors.extend(evaluate_positive(stats, matches, args.run_seconds))
            # Let the controlled source stop propagating before the control run.
            time.sleep(5)
        else:
            metadata['advertiser'] = 'NOT RUN: --no-advertiser'
        io.flash(elf, args.out, 'negative', check_idle=False)
        wait = time.monotonic() + args.run_seconds + 3
        while time.monotonic() < wait:
            time.sleep(max(0, wait - time.monotonic()))
        stats, matches = read_phase(symbols, args.out, 'negative')
        metadata['stats_negative'] = stats
        metadata['match_rows_negative'] = matches
        errors.extend(evaluate_negative(stats, matches))
        positive = metadata.get('stats_positive')
        if positive:
            print(f'positive: arms={positive[6]} done={positive[8]} '
                  f'timeout={positive[9]} crc_ok={positive[12]} '
                  f'match={positive[33]} '
                  f'ch=[{positive[17]},{positive[18]},{positive[19]}]')
        print(f'negative: arms={stats[6]} done={stats[8]} crc_ok={stats[12]} '
              f'match={stats[33]}')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        errors.append(str(error))
    finally:
        stop_advertiser(process, log)
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
