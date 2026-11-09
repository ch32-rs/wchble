#!/usr/bin/env python3
"""Read only OBS/TRACE from a parked CH585; CLI may halt/resume the core."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

PROBE = '1a86:8010:F93D8F067E10'
FIELDS = ['elapsed_us', 'phase', 'lle_irq', 'bb_irq', 'cmd', 'window',
          'mode', 'guard', 'rfctrl', 'fectrl', 'rxptr', 'systick_raw']


def symbols(elf, nm):
    output = subprocess.check_output([nm, str(elf)], text=True)
    found = {}
    for line in output.splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]+)\s+\w\s+(OBS|TRACE)', line.strip())
        if match:
            found[match[2]] = int(match[1], 16)
    if set(found) != {'OBS', 'TRACE'}:
        raise ValueError('ELF must contain OBS and TRACE symbols')
    return found


def read_words(address, count, destination):
    # Keep partial output and diagnostics even if probe-rs fails or times out.
    command = ['probe-rs', 'read', '--probe', PROBE, '--chip', 'CH585',
               '--protocol', 'jtag', '--non-interactive',
               '--output', str(destination), '--format', 'binary',
               'b32', hex(address), str(count)]
    metadata = {'command': command}
    try:
        with destination.with_suffix('.log').open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    timeout=30, check=False)
        metadata['returncode'] = result.returncode
    except subprocess.TimeoutExpired:
        metadata['error'] = 'probe-rs timed out; target state unknown'
        raise
    finally:
        destination.with_suffix('.command.json').write_text(
            json.dumps(metadata, indent=2) + '\n')
    if result.returncode:
        raise ValueError(f'probe-rs failed; raw evidence retained at {destination.parent}')
    data = destination.read_bytes()
    if len(data) != count * 4:
        raise ValueError('short probe read; partial binary retained')
    return list(struct.unpack(f'<{count}I', data))


def decode(obs, words):
    if len(obs) != 20 or obs[:2] != [0x52584f31, 2]:
        raise ValueError('wrong OBS magic/version; use the matching v2 ELF')
    count = obs[12]
    if count > 64 or len(words) != count * 12:
        raise ValueError('invalid trace size')
    return [dict(zip(FIELDS, words[i:i + 12])) for i in range(0, len(words), 12)]


def complete_trace(obs, rows):
    # A stage marker alone must not turn a truncated/corrupted capture green.
    if obs[2] != 11 or obs[4] != 1 or obs[13] or len(rows) < 4:
        return False
    if [row['phase'] for row in rows[-4:]] != [2, 3, 4, 5]:
        return False
    if any(row['phase'] != 1 for row in rows[:-4]):
        return False
    return all(a['elapsed_us'] <= b['elapsed_us'] for a, b in zip(rows, rows[1:]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--nm', required=True, help='RISC-V capable nm executable')
    parser.add_argument('--out', type=Path, required=True, help='new evidence directory')
    args = parser.parse_args()
    locations = symbols(args.elf, args.nm)
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'capture.json').write_text(json.dumps({
        'elf': str(args.elf.resolve()),
        'elf_sha256': hashlib.sha256(args.elf.read_bytes()).hexdigest(),
        'symbols': locations, 'probe': PROBE,
    }, indent=2) + '\n')
    obs = read_words(locations['OBS'], 20, args.out / 'obs.bin')
    # Save the raw header even when the firmware faulted or the ELF is wrong.
    (args.out / 'obs.json').write_text(json.dumps(obs, indent=2) + '\n')
    if obs[:2] != [0x52584f31, 2] or obs[12] > 64:
        raise ValueError('invalid header; raw OBS saved, no trace read')
    words = read_words(locations['TRACE'], obs[12] * 12, args.out / 'trace.bin') if obs[12] else []
    (args.out / 'trace-words.json').write_text(json.dumps(words) + '\n')
    rows = decode(obs, words)
    with (args.out / 'trace.csv').open('w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f'stage={obs[2]} tx={obs[3]} rx_arm={obs[4]} rows={obs[12]} '
          f'overflow={obs[13]} mode={obs[14]} reset_status={obs[18]:#x}')
    print(f'ticks/us={obs[17]} tx_call_us={obs[19]} '
          f'tx_return_to_rx_arm_us={obs[16]} (CPU intervals, not air IFS)')
    print('us phase LLE_IRQ BB_IRQ CMD WINDOW MODE')
    for row in rows:
        print(f'{row["elapsed_us"]:6} {row["phase"]} '
              + ' '.join(f'{row[key]:08x}' for key in FIELDS[2:7]))
    print('DMA completion/ownership, full SCAN_REQ and air timing: UNVERIFIED')
    if not complete_trace(obs, rows):
        return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
