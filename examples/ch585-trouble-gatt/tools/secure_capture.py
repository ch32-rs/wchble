#!/usr/bin/env python3
"""Wrap one S2 secure run with a bounded Nordic capture.

The run itself is unchanged (`secure_run.py`): same preflight flash, same
finite image, same restore. The sniffer only listens, so a capture failure is
recorded as evidence rather than retried, and never aborts the firmware run.
"""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


secure = load('s2_secure_run', HERE / 'secure_run.py')
cap = load('s2_capture_lib', HERE / 'capture.py')
p4 = secure.p4

# SMP and link-layer evidence only; ATT values after START_ENC have no key.
FIELDS = ['frame.number', 'nordic_ble.crcok', 'nordic_ble.direction',
          'btle.access_address', 'btle.advertising_address',
          'btle.advertising_header.pdu_type',
          'btle.link_layer_data.access_address', 'btl2cap.cid', 'btl2cap.length',
          'btatt.opcode', 'btle.control_opcode',
          'btsmp.opcode', 'btsmp.io_capability', 'btsmp.oob_data_flags',
          'btsmp.authreq', 'btsmp.bonding_flags', 'btsmp.mitm_flag',
          'btsmp.sc_flag', 'btsmp.max_enc_key_size',
          'btsmp.initiator_key_distribution', 'btsmp.responder_key_distribution']
# host.rs RANDOM_ADDRESS is fixed since S3 so a bonded peer can find the key it
# stored on an earlier boot. Printed in Bluetooth (most-significant-first) order.
TARGET = 'c1:ff:ee:00:00:18'
SMP_NAMES = dict(secure.SMP_OPCODES)
LL_CONTROL = {0x02: 'TERMINATE_IND', 0x03: 'ENC_REQ', 0x04: 'ENC_RSP',
              0x05: 'START_ENC_REQ', 0x06: 'START_ENC_RSP',
              0x0a: 'PAUSE_ENC_REQ', 0x0b: 'PAUSE_ENC_RSP',
              0x0c: 'VERSION_IND', 0x0d: 'REJECT_IND',
              0x14: 'LENGTH_REQ', 0x15: 'LENGTH_RSP'}


def run_target(out):
    """Address this run advertised; the secure image rotates it per boot."""
    try:
        result = json.loads((out / 'run' / 'result.json').read_text())
    except (OSError, ValueError):
        return TARGET
    return result.get('peripheral_address', TARGET)


def decode(path, out, tshark, target):
    command = [tshark, '-r', str(path), '-T', 'fields',
               '-E', 'header=y', '-E', 'separator=/t']
    for field in FIELDS:
        command.extend(['-e', field])
    cap.save(out / 'decode.command.json', command)
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (out / 'decode.stderr.log').write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f'tshark exited {result.returncode}: {result.stderr[-400:]}')
    (out / 'packets.tsv').write_text(result.stdout)
    rows = list(csv.DictReader(io.StringIO(result.stdout), delimiter='\t'))
    return analyze(rows, out, target)


def analyze(rows, out, target):
    """Only the link this firmware opened is evidence; neighbouring BLE traffic
    (the 37/38/39 scan sees plenty) must not be counted or decoded."""
    connects = [row for row in rows
                if row['btle.advertising_header.pdu_type'] == '0x05'
                and row['btle.advertising_address'].lower() == target
                and row['nordic_ble.crcok'] == 'True']
    link = next((row['btle.link_layer_data.access_address'].lower()
                 for row in connects if row['btle.link_layer_data.access_address']), None)
    good = [row for row in rows if row['nordic_ble.crcok'] == 'True'
            and link is not None and row['btle.access_address'].lower() == link]
    smp, control, att = [], [], []
    for row in good:
        frame = int(row['frame.number'])
        direction = 'central' if row['nordic_ble.direction'] == 'True' else 'peripheral'
        cid = row.get('btl2cap.cid', '')
        if row.get('btsmp.opcode'):
            opcode = row['btsmp.opcode']
            entry = {'frame': frame, 'dir': direction, 'opcode': opcode,
                     'name': SMP_NAMES.get(int(opcode, 0), opcode)}
            for key in ('btsmp.io_capability', 'btsmp.authreq', 'btsmp.mitm_flag',
                        'btsmp.sc_flag', 'btsmp.bonding_flags',
                        'btsmp.max_enc_key_size'):
                if row.get(key):
                    entry[key.split('.', 1)[1]] = row[key]
            smp.append(entry)
        if row.get('btle.control_opcode'):
            opcode = row['btle.control_opcode']
            control.append({'frame': frame, 'dir': direction, 'opcode': opcode,
                            'name': LL_CONTROL.get(int(opcode, 0), opcode)})
        if row.get('btatt.opcode'):
            att.append({'frame': frame, 'dir': direction,
                        'opcode': row['btatt.opcode'], 'cid': cid})
    assessed = {'target': target, 'connect_frame': int(connects[0]['frame.number']) if connects else None,
                'access_address': link, 'smp': smp, 'll_control': control,
                'att_frames': len(att), 'att_last_frame': att[-1]['frame'] if att else None,
                'crc_valid_link_pdus': len(good)}
    # First LL encryption control PDU on the link marks the plaintext boundary.
    start = next((entry for entry in control
                  if entry['name'] in ('ENC_REQ', 'START_ENC_REQ', 'START_ENC_RSP')),
                 None)
    if start is not None:
        assessed['encryption_start'] = start
        assessed['att_after_encryption_start'] = [
            entry for entry in att if entry['frame'] > start['frame']]
    # The pairing response is the only frame that explains the chosen method.
    response = next((entry for entry in smp
                     if entry['name'] == 'PairingResponse' and entry['dir'] == 'peripheral'),
                    None)
    request = next((entry for entry in smp
                    if entry['name'] == 'PairingRequest' and entry['dir'] == 'central'), None)
    assessed['pairing_request'] = request
    assessed['pairing_response'] = response
    assessed['smp_opcodes_captured'] = sorted({entry['name'] for entry in smp})
    out.joinpath('capture-analysis.json').write_text(
        json.dumps(assessed, indent=2) + '\n')
    return assessed


def evaluate(assessed, mode='pair'):
    """Mode-specific capture gates.

    `pair` is the S2 matrix. `reconnect` and `fault` must show encryption
    resumed without any new SMP pairing. `delete`/`reject` must show the
    controller rejecting the peer's LTK with LL_REJECT_IND and never starting
    encryption; `reject` is the run where the board's bond is already gone.
    """
    errors = []
    if assessed.get('access_address') is None:
        errors.append(f'capture saw no CRC-valid CONNECT_IND to {assessed.get("target")}')
    if mode in ('delete', 'reject'):
        if not any(entry['name'] == 'REJECT_IND' for entry in assessed['ll_control']):
            errors.append('capture saw no LL_REJECT_IND after the delete command')
        if any(entry['name'] in ('START_ENC_REQ', 'START_ENC_RSP')
               for entry in assessed['ll_control']):
            errors.append('capture showed encryption starting after the bond was deleted')
        return errors
    if not assessed['smp'] and mode == 'pair':
        errors.append('capture saw no SMP traffic')
    if mode == 'pair':
        if assessed.get('pairing_request') is None:
            errors.append('capture saw no central Pairing Request')
        if assessed.get('pairing_response') is None:
            errors.append('capture saw no peripheral Pairing Response')
        if 'PairingDHKeyCheck' not in assessed['smp_opcodes_captured']:
            errors.append('capture saw no DHKey Check in either direction')
    elif mode == 'att':
        # A reused bond skips SMP; a fresh one must show the whole exchange.
        if assessed['smp']:
            if assessed.get('pairing_request') is None:
                errors.append('capture saw no central Pairing Request')
            if assessed.get('pairing_response') is None:
                errors.append('capture saw no peripheral Pairing Response')
            if 'PairingDHKeyCheck' not in assessed['smp_opcodes_captured']:
                errors.append('capture saw no DHKey Check in either direction')
    else:
        pairing = {'PairingRequest', 'PairingResponse', 'PairingConfirm', 'PairingRandom',
                   'PairingDHKeyCheck', 'PairingPublicKey'}
        seen = pairing & set(assessed['smp_opcodes_captured'])
        if seen:
            errors.append(f'capture showed a new pairing during {mode}: {sorted(seen)}')
    if 'encryption_start' not in assessed:
        errors.append('capture saw no LL encryption start')
    elif assessed.get('att_after_encryption_start'):
        errors.append('capture decoded plaintext ATT after encryption start: '
                      f'{assessed["att_after_encryption_start"][:3]}')
    return errors


class SnifferHook:
    """Start the sniffer only once the firmware is advertising.

    `--follow-by-name` resolves the name once, ~0.7 s after startup, against
    the device list the dongle had already reported. That lookup races the
    scan results themselves: run47 and run48 both logged the warning a few
    milliseconds before the very device it was looking for. The dongle's
    address follow, by contrast, is accepted blindly, so this hook first runs
    a short scan to learn the rotated address from the sniffer's own log and
    then follows that address.
    """

    NAME = 'wch585-p4'
    # {"address":{"address":".."},"address_type":"Random","name":{"name":"..",
    ADDRESS = re.compile(r'"address":\{"address":"([0-9a-f:]{17})"\},"address_type":"Random",'
                         r'"name":\{"name":"' + NAME + '"')

    def __init__(self, capture, out, metadata, log_path):
        self.capture, self.out, self.metadata = capture, out, metadata
        self.log_path = log_path
        self.process = None
        self.follow_confirmed = False

    def before_app(self, _args):
        time.sleep(0.3)
        if not self.capture.follow_by_name:
            self.start(['--follow', f'{TARGET} random'])
            self.follow_confirmed = self.await_follow()
            return
        address = self.discover()
        if address is None:
            self.metadata['sniffer_follow_note'] = (
                f'{self.NAME} never appeared in the sniffer scan')
            return
        self.metadata['sniffer_target'] = address
        for _ in range(2):
            self.start(['--follow', f'{address} random', '--scan-follow-rsp'])
            if self.await_follow():
                self.follow_confirmed = True
                return
            self.stop()
            time.sleep(0.5)

    def discover(self, timeout=2.5):
        """Scan-only pass: the dongle reports the advertised name and address.

        The dongle keeps its device list across runs, so earlier boots with
        this same name appear in a burst immediately after start (run49 saw
        the previous run's address 0.6 s before this boot's). The live device
        can only be reported once a scan pass hears it, so the last match is
        the one currently advertising.
        """
        self.start([])
        found, deadline = [], time.monotonic() + timeout
        while time.monotonic() < deadline:
            found.extend(self.ADDRESS.findall(self.log_path.read_text(errors='replace')))
            if self.process.poll() is not None:
                break
            time.sleep(0.05)
        self.stop()
        self.metadata['sniffer_candidates'] = list(dict.fromkeys(found))
        return found[-1] if found else None

    def start(self, follow):
        capture, out = self.capture, self.out
        command = [str(capture.sniffer), 'sniff', '--port', capture.sniffer_port,
                   '--timeout', str(capture.serial_timeout_ms), *follow,
                   '--output-pcap-file', str(out / 'capture.pcap'),
                   '--log-output', 'stdout', '--log-level', 'info']
        cap.save(out / 'capture.command.json', command)
        with self.log_path.open('w') as log:
            self.process = subprocess.Popen(
                command, stdout=log, stderr=subprocess.STDOUT,
                env=dict(os.environ, NRFUTIL_HOME=str(capture.nrfutil_home)),
                start_new_session=True, preexec_fn=cap.reset_child_signals)
        # No follow arguments means a plain scan, which also ends with "Sending
        # scan packet"; with a follow argument the request line is the marker.
        cap.await_initialized(self.process, self.log_path, capture.startup_timeout,
                              follow_by_name=not follow)

    def await_follow(self, timeout=5.0):
        """The follow request is sent once, ~1 s after the sniffer boots.

        A miss is recorded separately rather than as a run error: the decoded
        pcap gate below is the authoritative judgement of the capture.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            log = self.log_path.read_text(errors='replace')
            if 'Changing state from SCANNING to FOLLOWING' in log:
                return True
            if self.process.poll() is not None:
                break
            time.sleep(0.05)
        self.metadata['sniffer_follow_note'] = 'no follow request observed'
        return False

    def stop(self):
        if self.process is None:
            # Nothing to shut down; a missing capture is judged by the pcap gate.
            return {'clean': True, 'exit': None, 'actions': ['not started']}
        with cap.bounded_cleanup():
            shutdown = cap.stop_capture(self.process)
        self.process = None
        return shutdown


def execute(capture, args):
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    args.out = out / 'run'
    metadata = {'scope': 'one S2 secure run under passive capture',
                'sniffer_serial': capture.sniffer_serial,
                'sniffer_port': capture.sniffer_port,
                'serial_timeout_ms': capture.serial_timeout_ms,
                'capture_mode': capture.mode,
                'follow_mode': 'name->address' if capture.follow_by_name else 'address',
                'errors': []}
    hook = SnifferHook(capture, out, metadata, out / 'capture.log')
    args.capture_hook = hook
    runner_exit = None
    t0 = time_now()
    try:
        metadata['sniffer_binary_sha256'] = hashlib.sha256(capture.sniffer.read_bytes()).hexdigest()
        metadata['sniffer_version'] = subprocess.check_output(
            [str(capture.sniffer), '--version'], text=True, timeout=10,
            env=dict(os.environ, NRFUTIL_HOME=str(capture.nrfutil_home))).strip()
        metadata['git_revision'] = subprocess.check_output(
            ['git', '-C', str(p4.ROOT), 'rev-parse', 'HEAD'], text=True,
            timeout=10).strip()
        metadata['started_at'] = t0
        try:
            # A lost capture must never abort a running finite image.
            runner_exit = secure.execute(args)
        finally:
            metadata['sniffer_follow'] = hook.follow_confirmed
            metadata['shutdown'] = hook.stop()
    except (*secure.FAILURES, subprocess.CalledProcessError) as error:
        metadata['errors'].append(f'{type(error).__name__}: {error}')
    finally:
        metadata.setdefault('shutdown', hook.stop())
        try:
            cap.validate_pcap(out / 'capture.pcap')
            metadata['capture'] = assess_pcap(out, capture.tshark, capture.mode)
        except (*secure.FAILURES, subprocess.CalledProcessError) as error:
            metadata['capture'] = {'errors': [f'{type(error).__name__}: {error}']}
        metadata['runner_exit'] = runner_exit
        metadata['function_passed'] = runner_exit == 0
        metadata['capture_passed'] = not metadata['capture'].get('errors')
        metadata['shutdown_passed'] = metadata.get('shutdown', {}).get('clean', False)
        metadata['passed'] = (not metadata['errors'] and metadata['function_passed']
                              and metadata['capture_passed']
                              and metadata['shutdown_passed'])
        cap.save(out / 'capture-result.json', metadata)
    print(json.dumps(metadata, indent=2), flush=True)
    return int(not metadata['passed'])


def time_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')


def assess_pcap(out, tshark, mode='pair'):
    structure = cap.validate_pcap(out / 'capture.pcap')
    assessed = decode(out / 'capture.pcap', out, tshark, run_target(out))
    assessed['structure'] = structure
    assessed['mode'] = mode
    assessed['errors'] = evaluate(assessed, mode)
    return assessed


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        'Remaining options pass to secure_run.py: --out, --elf, --smoke-elf, '
        '--nm, --serial, --run-seconds, --timeout, --build-apk.'))
    parser.add_argument('--sniffer', type=Path, required=True)
    parser.add_argument('--sniffer-port', required=True)
    parser.add_argument('--sniffer-serial', default='8D4391AA608D9EE4')
    parser.add_argument('--follow-by-name', action='store_true')
    parser.add_argument('--nrfutil-home', type=Path, required=True)
    parser.add_argument('--tshark', default='tshark')
    parser.add_argument('--mode', choices=('pair', 'reconnect', 'delete', 'reject', 'fault', 'att'),
                        default='pair')
    parser.add_argument('--serial-timeout-ms', type=int, default=100)
    parser.add_argument('--startup-timeout', type=float, default=10)
    capture, remaining = parser.parse_known_args(argv)
    if not 1 <= capture.serial_timeout_ms <= 1000 or not 0 < capture.startup_timeout <= 30:
        parser.error('require serial timeout 1..1000ms and startup timeout 0..30s')
    args = secure.options(remaining)
    # One mode drives both the phone flow and the capture gates. `reject`
    # reuses the reconnect app flow but expects the board to refuse the key.
    args.mode = 'reconnect' if capture.mode == 'reject' else capture.mode
    args.reject = capture.mode == 'reject'
    capture.sniffer = capture.sniffer.resolve()
    capture.nrfutil_home = capture.nrfutil_home.resolve()
    return capture, args


if __name__ == '__main__':
    raise SystemExit(execute(*options()))
