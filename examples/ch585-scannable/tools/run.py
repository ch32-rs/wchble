#!/usr/bin/env python3
"""Run the finite CH585 example, capture results, then restore/scan smoke."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
PROBE = ['--probe', '1a86:8010:F93D8F067E10', '--chip', 'CH585',
         '--protocol', 'jtag', '--non-interactive']
PREFLIGHT = Path(os.environ.get(
    'CH585_PREFLIGHT', ROOT / 'tools/ch585-preflight/target/release/ch585-preflight'))
NM = '/opt/homebrew/opt/llvm/bin/llvm-nm'
SCANNER = ROOT / 'examples/ch585-rf-smoke/tools/scan_ch585.swift'


def command(args, path, timeout=40):
    path.with_suffix('.command.json').write_text(json.dumps(args) + '\n')
    with path.open('w') as log:
        result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {path}')
    return path.read_text()


def read32(address, count, path):
    output = command(['probe-rs', 'read', *PROBE, '--format', 'simple-hex',
                      'b32', hex(address), str(count)], path)
    tokens = output.split()
    if len(tokens) != count or any(not re.fullmatch('[0-9a-fA-F]{8}', x) for x in tokens):
        raise RuntimeError(f'invalid word read: {path}')
    return [int(x, 16) for x in tokens]


def write32(address, value, path):
    command(['probe-rs', 'write', *PROBE, 'b32', hex(address), hex(value)], path)


def idle(out, prefix):
    # CLI reads are intrusive. A continuous smoke may be halted mid-TX;
    # stop the known CH585 engine explicitly instead of waiting for that
    # halted firmware or pretending debug reset means a power cycle.
    value = read32(0x4000c200, 1, out / f'{prefix}-cmd-before.txt')[0]
    mode = read32(0x4000c250, 1, out / f'{prefix}-mode-before.txt')[0]
    bb = read32(0x4000c100, 1, out / f'{prefix}-bb-before.txt')[0]
    rf = read32(0x4000d008, 1, out / f'{prefix}-rf-before.txt')[0]
    # Always shut, like the backend: one idle-looking CMD sample cannot prove
    # no pending RF work. Separate MODE writes retain the settling intervals.
    write32(0x4000c250, mode & ~0x10, out / f'{prefix}-stop-mode1.log')
    write32(0x4000c250, mode & ~0x710, out / f'{prefix}-stop-mode2.log')
    write32(0x4000c200, value | 8, out / f'{prefix}-stop-cmd.log')
    write32(0x4000c100, (bb & ~0x300) | 0x100, out / f'{prefix}-stop-bb.log')
    write32(0x4000d008, rf & 0xffcdffff, out / f'{prefix}-stop-rf.log')
    write32(0x4000c250, 0x30000, out / f'{prefix}-stop-mode3.log')
    for i in range(2):
        if read32(0x4000c200, 1, out / f'{prefix}-cmd-{i}.txt')[0] & 3:
            raise RuntimeError('RF did not acknowledge stop; refusing flash')
        time.sleep(.02)


def flash(elf, out, prefix, check_idle=True):
    # One retained probe session halts, stops the engine, requires two zero
    # acknowledgements, then downloads and starts. Standalone reads would resume
    # the core between those steps, so this helper replaces the old sequence.
    if not PREFLIGHT.is_file():
        raise RuntimeError(f'preflight helper missing: {PREFLIGHT}; run cargo build --release in tools/ch585-preflight')
    command([str(PREFLIGHT), '--probe', '1a86:8010:F93D8F067E10', '--chip', 'CH585',
             '--protocol', 'jtag', '--verify', str(elf)],
            out / f'{prefix}-flash.log')


def evaluate_stats(obs, scan_result):
    errors = []
    if (obs[:2] != [0x50323538, 1] or obs[2] != 9 or obs[14]
            or obs[26] & 3 or obs[27] != 0x30000):
        errors.append('firmware did not finish cleanly')
    if (not obs[3] or obs[3] != obs[4] or any(obs[i] for i in [5, 15, 18, 19])):
        errors.append('advertisement, receive-arm or response errors recorded')
    if not obs[11] or obs[11] != obs[12] or scan_result:
        errors.append('complete SCAN_REQ / SCAN_RSP interoperability not confirmed')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--nm', default=NM)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    example = ROOT / 'examples/ch585-scannable'
    elf = example / 'target/riscv32imc-unknown-none-elf/release/ch585-scannable'
    smoke = ROOT / 'examples/ch585-rf-smoke/target/riscv32imc-unknown-none-elf/release/ch585-rf-smoke'
    metadata = {'probe': PROBE, 'clock': 'measured SysTick, short finite run',
                'air_ifs': 'UNVERIFIED', 'restart': 'verified idle then debug boot; no power cycle',
                'elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest()}
    symbols = {}
    for line in subprocess.check_output([args.nm, str(elf)], text=True).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in ('STATS', 'LAST_REQ'):
            symbols[parts[2]] = int(parts[0], 16)
    if set(symbols) != {'STATS', 'LAST_REQ'}:
        raise RuntimeError('missing observation symbols')
    metadata['symbols'] = symbols
    (args.out / 'firmware.elf').write_bytes(elf.read_bytes())
    started = False
    scanner = None
    scan_log = None
    errors = []
    try:
        # Do not call `info` or read RAM during the radio run. Identity was
        # established using this fixed probe; preflight only checks idle.
        scan_log = (args.out / 'scan-response.log').open('w')
        scanner = subprocess.Popen(['swift', str(SCANNER), 'wch585-p2', '14'],
                                   stdout=scan_log, stderr=subprocess.STDOUT)
        idle(args.out, 'test')
        started = True  # recovery also runs if the subsequent download fails
        flash(elf, args.out, 'test', check_idle=False)
        time.sleep(10)
        scan_result = scanner.wait(timeout=25)
        metadata['response_name_scan_exit'] = scan_result
        obs = read32(symbols['STATS'], 32, args.out / 'stats.txt')
        metadata['stats'] = obs
        (args.out / 'stats.json').write_text(json.dumps(obs, indent=2) + '\n')
        errors.extend(evaluate_stats(obs, scan_result))
        req_words = read32(symbols['LAST_REQ'], 4, args.out / 'last-request.txt')
        metadata['last_req'] = b''.join(x.to_bytes(4, 'little') for x in req_words)[:14].hex()
        print(f'adv={obs[4]}/{obs[3]} rx_done={obs[8]} valid_req={obs[11]} '
              f'rsp={obs[12]} late={obs[18]} rsp_err={obs[19]} stop_err={obs[14]}')
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        errors.append(str(error))
    finally:
        if scanner is not None and scanner.poll() is None:
            scanner.terminate()
            scanner.wait(timeout=5)
        if scan_log is not None:
            scan_log.close()
        if started:
            try:
                flash(smoke, args.out, 'restore')
                command(['swift', str(SCANNER), 'wch585', '8'], args.out / 'restore-scan.log', 20)
                metadata['smoke_recovery'] = 'flash verify and macOS discovery PASS'
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                errors.append(f'recovery: {error}')
                metadata['smoke_recovery'] = 'NOT VERIFIED'
        metadata['errors'] = errors
        (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
