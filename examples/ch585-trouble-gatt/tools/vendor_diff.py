#!/usr/bin/env python3
"""Vendor-stack differential: same phone, same sniffer, but the peripheral is
WCH's own CH585 EVT example (prebuilt `RunningSensor.hex`, GAPBondMgr pairing).

The open S2 question is whether this phone's controller ever sends
`LL_START_ENC_REQ` to a CH585 peripheral. Our firmware answers `LL_ENC_REQ`
with a valid `LL_ENC_RSP`, the phone ACKs it, and nothing follows; a macOS
peripheral completes the same flow. Running the vendor stack on the same
silicon separates "our LL state" from "phone + CH585 hardware".

The vendor image runs forever, so the probe stays untouched until the
preflight helper's halt + engine-shutdown + idle-ack path restores smoke.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import secure_run as secure  # noqa: E402
import capture as cap  # noqa: E402

SNIFFER = Path('/private/tmp/wchble-nrfutil-state-20261109/bin/nrfutil-ble-sniffer')
NRFUTIL_HOME = Path('/private/tmp/wchble-nrfutil-state-20261109')
SNIFFER_PORT = '/dev/cu.usbmodem21301'
VENDOR_HEX = Path('/tmp/ch585-vendor-rs/EVT/EXAM/BLE/RunningSensor/obj/RunningSensor.hex')
VENDOR_NAME = 'RSC Sensor'


def adb(serial, *args, **kwargs):
    return secure.adb(serial, *args, **kwargs)


def start_app(serial, scan_only=False):
    # adb joins arguments into one remote shell command, so a value with a
    # space ("RSC Sensor") must carry its own quoting.
    arguments = ['shell', 'am', 'start', '-W', '-n', secure.ACTIVITY,
                 '--es', 'target_name', f"'{VENDOR_NAME}'"]
    if scan_only:
        arguments += ['--ez', 'scan_only', 'true']
    adb(serial, *arguments)


def logcat(serial, out, name):
    text = adb(serial, 'logcat', '-d', '-s', 'WCHBLE:I', timeout=60)
    (out / name).write_text(text)
    return secure.read_log(text.splitlines())


def find_address(rows):
    for row in rows:
        if row.get('event') == 'found' and row.get('address'):
            return row['address']
    return None


def analyze(pcap, out):
    command = [
        'tshark', '-r', str(pcap), '-Y', 'btle.control_opcode || btsmp.opcode',
        '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time_relative',
        '-e', 'nordic_ble.direction', '-e', 'btle.control_opcode',
        '-e', 'btsmp.opcode', '-e', 'btle.data_header.llid',
    ]
    rows = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    (out / 'control-pdus.tsv').write_text(rows)
    ll, smp = {}, {}
    for line in rows.splitlines():
        fields = line.split('\t')
        if len(fields) > 3 and fields[3]:
            opcode = int(fields[3], 16)
            ll[opcode] = ll.get(opcode, 0) + 1
        if len(fields) > 4 and fields[4]:
            opcode = int(fields[4], 16)
            smp[opcode] = smp.get(opcode, 0) + 1
    ll_flow = subprocess.check_output(
        ['tshark', '-r', str(pcap), '-Y', 'btle.data_header.llid == 2',
         '-T', 'fields', '-e', 'frame.number'],
        text=True, stderr=subprocess.DEVNULL).split()
    result = {
        'll_control_counts': {f'0x{k:02x}': v for k, v in sorted(ll.items())},
        'smp_opcode_counts': {f'0x{k:02x}': v for k, v in sorted(smp.items())},
        'data_start_frames': len(ll_flow),
        'll_enc_req': 0x03 in ll,
        'll_enc_rsp': 0x04 in ll,
        'll_start_enc_req': 0x05 in ll,
        'll_start_enc_rsp': 0x06 in ll,
    }
    (out / 'analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def capture(serial, out, address, address_type, label, seconds):
    pcap = out / f'{label}.pcap'
    log_path = out / f'{label}-sniffer.log'
    log = open(log_path, 'w')
    process = subprocess.Popen(
        [str(SNIFFER), 'sniff', '--port', SNIFFER_PORT, '--timeout', str(seconds + 40),
         '--follow', f'{address} {address_type}',
         '--output-pcap-file', str(pcap), '--log-output', 'stdout', '--log-level', 'info'],
        stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
        env=dict(__import__('os').environ, NRFUTIL_HOME=str(NRFUTIL_HOME)))
    try:
        cap.await_initialized(process, log_path, 20, follow_by_name=False)
        time.sleep(2.5)
        adb(serial, 'shell', 'am', 'force-stop', secure.PACKAGE)
        adb(serial, 'logcat', '-c')
        start_app(serial)
        consents = []
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            pid = adb(serial, 'shell', 'pidof', secure.PACKAGE, check=False).strip()
            if not pid:
                break
            consent = secure.confirm_pairing_dialog(serial)
            if consent:
                consents.append(consent)
                print('CONSENT', json.dumps(consent), flush=True)
            time.sleep(0.5)
    finally:
        cap.reset_child_signals()
        shutdown = cap.stop_capture(process)
        log.close()
    rows = logcat(serial, out, f'{label}-logcat.txt')
    (out / f'{label}-transcript.jsonl').write_text(
        '\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n')
    summary = next((row for row in reversed(rows) if row.get('event') == 'summary'), None)
    return summary, consents, shutdown


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', default=secure.ADB_SERIAL)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--hex', type=Path, default=VENDOR_HEX)
    parser.add_argument('--seconds', type=float, default=45)
    parser.add_argument('--follow-type', default='public')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    hex_path, smoke = args.hex.resolve(), Path(secure.SMOKE).resolve()
    archived, smoke_copy = args.out / 'vendor.hex', args.out / 'smoke.elf'
    shutil.copyfile(hex_path, archived)
    shutil.copyfile(smoke, smoke_copy)
    metadata = {
        'vendor_hex_sha256': hashlib.sha256(archived.read_bytes()).hexdigest(),
        'vendor_hex': str(archived), 'vendor_name': VENDOR_NAME,
        'scope': 'vendor EVT stack differential for LL_START_ENC_REQ',
        'follow_type': args.follow_type,
    }
    errors, touched = [], False
    try:
        adb(args.serial, 'get-state')
        adb(args.serial, 'install', '-g', '-r', str(secure.APK), timeout=120)
        adb(args.serial, 'shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
        adb(args.serial, 'shell', 'wm', 'dismiss-keyguard')
        adb(args.serial, 'shell', 'svc', 'power', 'stayon', 'true')

        touched = True
        secure.flash(archived, args.out, 'vendor')
        time.sleep(3)

        # Address discovery first: Android reports the peer address, while a
        # CoreBluetooth scan only yields an opaque UUID the sniffer cannot use.
        adb(args.serial, 'logcat', '-c')
        adb(args.serial, 'shell', 'am', 'force-stop', secure.PACKAGE)
        start_app(args.serial, scan_only=True)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if not adb(args.serial, 'shell', 'pidof', secure.PACKAGE,
                       check=False).strip():
                break
            time.sleep(0.5)
        scan_rows = logcat(args.serial, args.out, 'scan-logcat.txt')
        address = find_address(scan_rows)
        metadata['vendor_address'] = address
        if address is None:
            raise RuntimeError(f'vendor peripheral {VENDOR_NAME!r} was not discovered')

        summary, consents, shutdown = capture(
            args.serial, args.out, address, args.follow_type, 'vendor', args.seconds)
        metadata['app_summary'] = summary
        metadata['pairing_consent'] = consents
        metadata['sniffer_shutdown'] = shutdown
        if summary is None or summary.get('pass') is not True:
            errors.append(f'phone app did not complete pairing: {summary}')
        analysis = analyze(args.out / 'vendor.pcap', args.out)
        metadata['analysis'] = analysis
        if not (analysis['ll_start_enc_req'] and analysis['ll_start_enc_rsp']):
            errors.append('vendor stack capture does not show START_ENC_REQ/RSP')
    except secure.FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        if touched:
            try:
                secure.flash(smoke_copy, args.out, 'restore')
                secure.io.command(['swift', str(secure.io.SCANNER), 'wch585', '8'],
                                  args.out / 'restore-scan.log', 20)
                metadata['smoke_recovery'] = 'PASS'
            except secure.FAILURES as error:
                errors.append(f'recovery: {error}')
                metadata['smoke_recovery'] = 'NOT VERIFIED'
        else:
            metadata['smoke_recovery'] = 'NOT ATTEMPTED'
        metadata['errors'], metadata['passed'] = errors, not errors
        (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
