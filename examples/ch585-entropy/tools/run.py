#!/usr/bin/env python3
"""Run the CH585 entropy measurement image and archive its RAM results.

The image never initializes the RF block, so reading RAM cannot race a radio.
Flashing still uses the shared single-session preflight helper: halt, stop the
known RF engine, require two zero acknowledgements, then verified download.

Policy: fixed probe 1a86:8010:F93D8F067E10 only; no automatic retries; a
failure is archived as-is. `--out` must not already exist.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    'ch585_scannable_io', ROOT / 'examples/ch585-scannable/tools/run.py')
io = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(io)
assert io.ROOT == ROOT
PROBE, NM = io.PROBE, io.NM
EXAMPLE = ROOT / 'examples/ch585-entropy'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-entropy'

STAT_NAMES = '''magic version stage jitter_rounds jitter_min jitter_max
jitter_distinct jitter_mean adc_samples adc_min adc_max adc_distinct
adc_ticks_min adc_ticks_max adc_ticks_distinct seed_w0 seed_w1 rand0_w0
rand0_w1 rand1_w0 rand1_w1 seeded rand_differs adc_errors sysclk_hz
jitter_zero health raw_range'''.split()
STAT_NAMES += [f'reserved_{i}' for i in range(len(STAT_NAMES), 32)]
assert len(STAT_NAMES) == 32
MAGIC = 0x45303538
LOG_BYTES = 2048


def symbols_from(text):
    symbols = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and re.fullmatch('[0-9a-fA-F]+', parts[0]):
            symbols[parts[2]] = int(parts[0], 16)
    return symbols


def read_log(address, out):
    words = io.read32(address, LOG_BYTES // 4, out / 'log.words.txt')
    raw = b''.join(word.to_bytes(4, 'little') for word in words)
    length = int.from_bytes(raw[:4], 'little')
    if length > LOG_BYTES - 4:
        raise RuntimeError(f'log length {length} exceeds buffer')
    text = raw[4:4 + length].decode('utf-8', errors='replace')
    (out / 'console.txt').write_text(text)
    return text


def evaluate(obs, text):
    errors = []
    if obs[0] != MAGIC or obs[1] != 1:
        errors.append('STATS magic/version mismatch')
    if obs[2] != 9:
        errors.append(f'stage {obs[2]} != 9 (did not finish)')
    if obs[26] != 1:
        errors.append('entropy health check failed (stuck source)')
    if obs[21] != 1:
        errors.append('DRBG was not seeded')
    if obs[22] != 1:
        errors.append('two HCI_LE_Rand replies were identical')
    if obs[8] == 0:
        errors.append('no ADC samples collected')
    if 'le rand 0' not in text or 'le rand 1' not in text:
        errors.append('HCI_LE_Rand markers missing from the console')
    if 'entropy done' not in text:
        errors.append('no completion marker')
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    archived = args.out / 'firmware.elf'
    shutil.copyfile(args.elf, archived)
    image = archived.read_bytes()
    metadata = {
        'probe': PROBE,
        'elf_sha256': hashlib.sha256(image).hexdigest(),
        'rf_started': False,
        'wait_seconds': args.wait_seconds,
        'restore': 'none: image never initializes RF',
    }
    errors = []
    try:
        nm_output = io.command([NM, str(archived)], args.out / 'symbols.txt')
        symbols = symbols_from(nm_output)
        metadata['symbols'] = {name: hex(symbols[name]) for name in ('LOG', 'STATS') if name in symbols}
        missing = [name for name in ('LOG', 'STATS') if name not in symbols]
        if missing:
            raise RuntimeError(f'missing symbols: {missing}')
        # SRAM is 0x20000000..+0x20000; the two RAM buffers must not overlap.
        sram = range(0x20000000, 0x20000000 + 128 * 1024)
        for name, size in (('LOG', LOG_BYTES), ('STATS', 32 * 4)):
            if symbols[name] not in sram or symbols[name] + size - 1 not in sram:
                raise RuntimeError(f'{name} at {symbols[name]:#x} is outside SRAM')
        log_range = set(range(symbols['LOG'], symbols['LOG'] + LOG_BYTES))
        if set(range(symbols['STATS'], symbols['STATS'] + 128)) & log_range:
            raise RuntimeError('LOG and STATS overlap')

        io.flash(archived, args.out, 'test')
        time.sleep(args.wait_seconds)

        obs = io.read32(symbols['STATS'], 32, args.out / 'stats.words.txt')
        text = read_log(symbols['LOG'], args.out)
        metadata['stats'] = dict(zip(STAT_NAMES, obs))
        errors.extend(evaluate(obs, text))
        print(text, end='' if text.endswith('\n') else '\n')
        print(json.dumps(metadata['stats'], indent=2))
    except Exception as exc:  # archive the failure, do not retry
        errors.append(str(exc))
        metadata['exception'] = repr(exc)
    metadata['errors'] = errors
    metadata['ok'] = not errors
    (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    if errors:
        print('FAIL:', '; '.join(errors), file=sys.stderr)
        return 1
    print('PASS')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--wait-seconds', type=float, default=2.0)
    args = parser.parse_args(argv)
    return execute(args)


if __name__ == '__main__':
    sys.exit(main())
