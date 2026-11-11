#!/usr/bin/env python3
"""Run the CH585 software-crypto benchmark and archive its RAM results.

The image never initializes the RF block. Flashing uses the shared
single-session preflight helper (halt, stop the RF engine, two zero
acknowledgements, verified download). Fixed probe only; no automatic retries.
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
EXAMPLE = ROOT / 'examples/ch585-crypto-bench'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-crypto-bench'

STAT_NAMES = '''magic version stage sysclk_hz aes_iters aes_ticks key_iters
key_ticks ccm27_iters ccm27_ticks ccm251_iters ccm251_ticks ccm251_dec_iters
ccm251_dec_ticks drbg_iters drbg_ticks aes_ticks_per_block'''.split()
STAT_NAMES += [f'reserved_{i}' for i in range(len(STAT_NAMES), 32)]
assert len(STAT_NAMES) == 32
MAGIC = 0x42303538
LOG_BYTES = 1024


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


def per_op(ticks, iters, hz):
    if not iters:
        return None
    return round(ticks / iters * 1e6 / hz, 3)


def summarize(obs):
    hz = obs[3]
    return {
        'key_expand_us': per_op(obs[7], obs[6], hz),
        'aes_block_us': per_op(obs[5], obs[4], hz),
        'ccm27_encrypt_us': per_op(obs[9], obs[8], hz),
        'ccm251_encrypt_us': per_op(obs[11], obs[10], hz),
        'ccm251_decrypt_us': per_op(obs[13], obs[12], hz),
        'drbg64_us': per_op(obs[15], obs[14], hz),
    }


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
        sram = range(0x20000000, 0x20000000 + 128 * 1024)
        for name, size in (('LOG', LOG_BYTES), ('STATS', 32 * 4)):
            if symbols[name] not in sram or symbols[name] + size - 1 not in sram:
                raise RuntimeError(f'{name} at {symbols[name]:#x} is outside SRAM')

        io.flash(archived, args.out, 'test')
        time.sleep(args.wait_seconds)

        obs = io.read32(symbols['STATS'], 32, args.out / 'stats.words.txt')
        text = read_log(symbols['LOG'], args.out)
        metadata['stats'] = dict(zip(STAT_NAMES, obs))
        metadata['timings'] = summarize(obs)
        print(text, end='' if text.endswith('\n') else '\n')
        print(json.dumps(metadata['timings'], indent=2))
        if obs[0] != MAGIC or obs[1] != 1:
            errors.append('STATS magic/version mismatch')
        if obs[2] != 9:
            errors.append(f'stage {obs[2]} != 9 (did not finish)')
        if 'crypto bench done' not in text:
            errors.append('no completion marker')
        if not obs[4] or not obs[8] or not obs[10] or not obs[14]:
            errors.append('a timing phase did not run')
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
