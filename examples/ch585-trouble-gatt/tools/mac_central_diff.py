#!/usr/bin/env python3
"""Differential S2 test from the other side: the CH585 secure firmware stays
the peripheral, but the central is macOS CoreBluetooth (tools/central.swift).

The Android differential proved the phone completes LESC + encryption with a
macOS peripheral, so the open question is whether the CH585 peripheral ever
gets LL_START_ENC_REQ from a known-good central. Flashes once through the
single-session preflight helper, captures with the Nordic sniffer, reads RAM
only after the embedded finite-run budget, then restores smoke.
"""
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import secure_run as secure  # noqa: E402
import capture as cap  # noqa: E402

p4 = secure.p4
io = secure.io
SNIFFER = Path('/private/tmp/wchble-nrfutil-state-20261109/bin/nrfutil-ble-sniffer')
NRFUTIL_HOME = Path('/private/tmp/wchble-nrfutil-state-20261109')
SNIFFER_PORT = '/dev/cu.usbmodem21301'
TARGET = 'c1:ff:ee:00:00:15'


def analyze(pcap):
    """LL/SMP evidence: did the macOS central run the encryption procedure?"""
    rows = subprocess.check_output(
        ['tshark', '-r', str(pcap), '-Y', 'btle.control_opcode || btsmp.opcode',
         '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_relative',
         '-e', 'nordic_ble.direction', '-e', 'btle.control_opcode',
         '-e', 'btsmp.opcode'],
        text=True, stderr=subprocess.DEVNULL)
    (pcap.parent / 'control-pdus.tsv').write_text(rows)
    ll, smp = {}, {}
    for line in rows.splitlines():
        fields = line.split('\t')
        if len(fields) > 3 and fields[3]:
            opcode = int(fields[3], 16)
            ll[opcode] = ll.get(opcode, 0) + 1
        if len(fields) > 4 and fields[4]:
            opcode = int(fields[4], 16)
            smp[opcode] = smp.get(opcode, 0) + 1
    return {
        'll_control_counts': {f'0x{k:02x}': v for k, v in sorted(ll.items())},
        'smp_opcode_counts': {f'0x{k:02x}': v for k, v in sorted(smp.items())},
        'll_start_enc_req': 0x05 in ll,
        'll_start_enc_rsp': 0x06 in ll,
    }


def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    elf = Path(secure.DEFAULT_ELF).resolve()
    smoke = Path(secure.SMOKE).resolve()
    run_seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    # Hold past the firmware's 2 s peripheral Security Request, then let
    # CoreBluetooth's automatic pairing run.
    hold = sys.argv[3] if len(sys.argv) > 3 else '15'
    archived, smoke_copy = out / 'firmware.elf', out / 'smoke.elf'
    import shutil
    shutil.copyfile(elf, archived)
    shutil.copyfile(smoke, smoke_copy)
    metadata = {'elf_sha256': hashlib.sha256(archived.read_bytes()).hexdigest()}
    nm_text = io.command([secure.NM, str(archived)], out / 'symbols.txt')
    symbols = {}
    for name in ('SECURE_STATS', 'SEC_DIAG', 'SEC_OPCODES', 'HOST_STATS'):
        matches = [parts for line in nm_text.splitlines()
                   if len(parts := line.split()) == 3 and parts[2] == name]
        symbols[name] = int(matches[0][0], 16)
    metadata['symbols'] = symbols

    errors = []
    safe_read_at = None
    sniffer = None
    touched = False
    try:
        secure.flash(archived, out, 'test')
        touched = True
        safe_read_at = time.monotonic() + run_seconds + 3
        log = open(out / 'sniffer.log', 'w')
        sniffer = subprocess.Popen(
            [str(SNIFFER), 'sniff', '--port', SNIFFER_PORT, '--timeout', '100',
             '--follow', f'{TARGET} random',
             '--output-pcap-file', str(out / 'capture.pcap'),
             '--log-output', 'stdout', '--log-level', 'info'],
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            env=dict(__import__('os').environ, NRFUTIL_HOME=str(NRFUTIL_HOME)))
        cap.await_initialized(sniffer, out / 'sniffer.log', 20)
        time.sleep(3)
        result = subprocess.run(
            ['swift', str(TOOLS / 'central.swift'), '--cycles', '1', '--timeout', '35',
             '--hold', hold],
            capture_output=True, text=True, timeout=40)
        (out / 'central.log').write_text(result.stdout + result.stderr)
        print(result.stdout[-2000:])
    finally:
        if sniffer is not None:
            cap.reset_child_signals()
            metadata['shutdown'] = cap.stop_capture(sniffer)
            try:
                metadata['ll'] = analyze(out / 'capture.pcap')
                print('LL', json.dumps(metadata['ll'], sort_keys=True))
            except (OSError, subprocess.SubprocessError, ValueError) as error:
                errors.append(f'capture analysis: {error}')
        if not touched:
            raise
        p4.wait_until(safe_read_at)
        stats = io.read32(symbols['SECURE_STATS'], 16, out / 'secure_stats.txt')
        metadata['secure_stats'] = dict(zip(secure.SEC_NAMES, stats))
        (out / 'secure_stats.json').write_text(json.dumps(metadata['secure_stats'], indent=2) + '\n')
        try:
            secure.flash(smoke_copy, out, 'restore')
            io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                       out / 'restore-scan.log', 20)
            metadata['smoke_recovery'] = 'PASS'
        except secure.FAILURES as error:
            errors.append(f'recovery: {error}')
            metadata['smoke_recovery'] = 'NOT VERIFIED'
    metadata['errors'] = errors
    (out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata['secure_stats'], indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
