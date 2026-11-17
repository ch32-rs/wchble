#!/usr/bin/env python3
"""Differential S2 test: same Android app, same GATT shape, but the peripheral
is macOS CoreBluetooth instead of the CH585 firmware.

It answers one question with a known-good controller underneath: does this
phone's controller ever send LL_START_ENC_REQ? If it does here, the stall seen
with the CH585 is on our side; if it does not, the phone's controller is the
blocker. Read-only on the firmware side: nothing is flashed here.
"""
import argparse
import json
import signal
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
PERIPHERAL = TOOLS / 'mac_peripheral.swift'
TARGET_NAME = 'wch585-p4'


def adb(args, *rest, **kwargs):
    return secure.adb(args.serial, *rest, **kwargs)


def analyze(pcap, out):
    command = [
        'tshark', '-r', str(pcap), '-Y',
        'btle.control_opcode || btsmp.opcode', '-T', 'fields',
        '-e', 'frame.number', '-e', 'frame.time_relative',
        '-e', 'nordic_ble.direction', '-e', 'btle.control_opcode',
        '-e', 'btsmp.opcode', '-e', 'btle.data_header.llid',
        '-e', 'btle.data_header.length',
    ]
    rows = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    (out / 'control-pdus.tsv').write_text(rows)
    opcodes = set()
    for line in rows.splitlines():
        fields = line.split('\t')
        if len(fields) > 3 and fields[3]:
            opcodes.add(int(fields[3], 16))
    result = {
        'll_enc_req': 0x03 in opcodes,
        'll_enc_rsp': 0x04 in opcodes,
        'll_start_enc_req': 0x05 in opcodes,
        'll_start_enc_rsp': 0x06 in opcodes,
    }
    (out / 'analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', default='55VS4H8TRW45KVQS')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--seconds', type=float, default=50.0)
    parser.add_argument('--follow-address', default='c8:89:f3:b0:45:b5')
    parser.add_argument('--follow-type', default='public')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    adb(args, 'shell', 'am', 'force-stop', secure.PACKAGE)
    adb(args, 'logcat', '-c')
    adb(args, 'install', '-g', '-r', str(secure.APK), timeout=120)

    peripheral_log = open(args.out / 'peripheral.log', 'w')
    peripheral = subprocess.Popen(['swift', str(PERIPHERAL)], stdout=peripheral_log,
                                  stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if 'advertising' in (args.out / 'peripheral.log').read_text(errors='replace'):
            break
        if peripheral.poll() is not None:
            raise SystemExit('macOS peripheral exited early')
        time.sleep(.1)
    else:
        raise SystemExit('macOS peripheral never advertised')
    # Give the sniffer's scanner a chance to see the advertisement before the
    # follow request is sent; a name/address it has not seen yet is not followed.
    time.sleep(2.0)

    pcap = args.out / 'capture.pcap'
    sniffer_log_path = args.out / 'sniffer.log'
    sniffer_log = open(sniffer_log_path, 'w')
    sniffer = subprocess.Popen(
        [str(SNIFFER), 'sniff', '--port', SNIFFER_PORT, '--timeout', '100',
         '--follow', f'{args.follow_address} {args.follow_type}',
         '--output-pcap-file', str(pcap), '--log-output', 'stdout',
         '--log-level', 'info'],
        stdout=sniffer_log, stderr=subprocess.STDOUT, start_new_session=True,
        env=dict(__import__('os').environ, NRFUTIL_HOME=str(NRFUTIL_HOME)))
    try:
        cap.await_initialized(sniffer, sniffer_log_path, 20, follow_by_name=False)
        adb(args, 'shell', 'am', 'start', '-W', '-n', secure.ACTIVITY)
        consents = []
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            pid = adb(args, 'shell', 'pidof', secure.PACKAGE, check=False).strip()
            if not pid:
                break
            consent = secure.confirm_pairing_dialog(args.serial)
            if consent:
                consents.append(consent)
                print('CONSENT', consent)
            time.sleep(.5)
        (args.out / 'logcat.txt').write_text(
            adb(args, 'logcat', '-d', '-s', 'WCHBLE:I', timeout=60))
    finally:
        cap.reset_child_signals()
        shutdown = cap.stop_capture(sniffer)
        peripheral.send_signal(signal.SIGINT)
        try:
            peripheral.wait(timeout=5)
        except subprocess.TimeoutExpired:
            peripheral.kill()
    (args.out / 'shutdown.json').write_text(json.dumps(shutdown) + '\n')
    result = analyze(pcap, args.out)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
