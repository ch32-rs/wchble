#!/usr/bin/env python3
"""Wrap one safe P4 run with bounded Nordic capture; never retry a failed run."""
import argparse
from contextlib import contextmanager
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location('p4_runner', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)
TARGET = 'c1:ff:ee:00:00:14'
FIELDS = ['frame.number', 'nordic_ble.crcok', 'nordic_ble.direction', 'btle.access_address',
          'btle.advertising_header.pdu_type', 'btle.advertising_address',
          'btle.link_layer_data.access_address', 'btatt.opcode', 'btatt.value']


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def validate_pcap(path):
    """Reject a partial last record rather than silently trimming evidence."""
    image = path.read_bytes()
    magic = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
             b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
    if len(image) < 24 or image[:4] not in magic:
        raise ValueError('missing classic PCAP header')
    endian = magic[image[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack_from(endian + 'HHIIII', image, 4)
    if (major, minor) != (2, 4) or linktype != 272 or not snaplen:
        raise ValueError('expected PCAP v2.4 with Nordic BLE DLT 272')
    offset = 24
    records = 0
    while offset < len(image):
        if offset + 16 > len(image):
            raise ValueError('partial PCAP record header')
        _, _, captured, original = struct.unpack_from(endian + 'IIII', image, offset)
        offset += 16
        if captured > min(snaplen, original) or offset + captured > len(image):
            raise ValueError('invalid or partial PCAP record payload')
        offset += captured
        records += 1
    return {'bytes': len(image), 'records': records, 'sha256': hashlib.sha256(image).hexdigest()}


def analyze_rows(rows, cycles):
    """Require valid target CONNECTs, bidirectional data, and actual GATT values."""
    connects = [row for row in rows if row['btle.advertising_header.pdu_type'] == '0x05'
                and row['btle.advertising_address'].lower() == TARGET]
    good = [row for row in connects if row['nordic_ble.crcok'] == 'True']
    errors = []
    if len(good) != cycles:
        errors.append(f'expected {cycles} CRC-valid target CONNECT_IND, captured {len(good)}')
    links = []
    for connect in good:
        start = int(connect['frame.number'])
        end = min((int(row['frame.number']) for row in connects
                   if int(row['frame.number']) > start), default=float('inf'))
        aa = connect['btle.link_layer_data.access_address'].lower()
        packets = [row for row in rows if start < int(row['frame.number']) < end
                   and row['btle.access_address'].lower() == aa
                   and row['nordic_ble.crcok'] == 'True'] if aa else []
        directions = {key: sum(row['nordic_ble.direction'] == key for row in packets)
                      for key in ('True', 'False')}
        counts = {opcode: sum(row['btatt.opcode'] == opcode for row in packets)
                  for opcode in ('0x0a', '0x0b', '0x12', '0x13', '0x1b')}
        notifications = []
        for row in packets:
            if row['btatt.opcode'] != '0x1b':
                continue
            try:
                value = bytes.fromhex(row['btatt.value'].replace(':', ''))
            except ValueError:
                value = b''
            number = int.from_bytes(value, 'little') if len(value) == 4 else None
            # Adjacent over-air retransmissions do not create extra application values.
            if not notifications or notifications[-1] != number:
                notifications.append(number)
        link = {'connect_frame': start, 'access_address': aa, 'crc_valid_data': len(packets),
                'central_packets': directions['True'], 'peripheral_packets': directions['False'],
                'att_counts': counts, 'notification_values': notifications}
        links.append(link)
        if not all(directions.values()):
            errors.append(f'frame {start}: NO FOLLOW or missing one data direction')
        if any(counts[opcode] < count for opcode, count in
               (('0x0a', 5), ('0x0b', 5), ('0x12', 13), ('0x13', 13))):
            errors.append(f'frame {start}: incomplete captured ATT read/write cycle')
        if notifications != list(range(101, 111)):
            errors.append(f'frame {start}: incomplete captured notification sequence101..110')
    return {'target_connects': len(connects), 'crc_valid_connects': len(good),
            'bad_crc_connects': len(connects) - len(good), 'links': links,
            'errors': errors, 'passed': not errors}


def analyze(path, out, cycles, tshark):
    structure = validate_pcap(path)
    command = [tshark, '-r', str(path), '-T', 'fields', '-E', 'header=y', '-E', 'separator=/t']
    for field in FIELDS:
        command.extend(['-e', field])
    save(out / 'decode.command.json', command)
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=True)
    (out / 'packets.tsv').write_text(result.stdout)
    (out / 'decode.stderr.log').write_text(result.stderr)
    rows = list(csv.DictReader(io.StringIO(result.stdout), delimiter='\t'))
    return dict(analyze_rows(rows, cycles), structure=structure)


def reset_child_signals():
    # This wrapper is single-threaded. Do not inherit a shell's ignored Ctrl-C.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


@contextmanager
def bounded_cleanup():
    previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def stop_capture(process):
    actions = []
    if process.poll() is not None:
        return {'clean': False, 'exit': process.returncode, 'actions': actions,
                'reason': 'capture exited before requested stop'}
    # The dongle side occasionally needs more than 5 s to flush its pcap and
    # stop scanning; a longer SIGINT budget keeps the clean-stop criterion
    # instead of falling through to SIGTERM.
    for signum, budget in ((signal.SIGINT, 12), (signal.SIGTERM, 2), (signal.SIGKILL, 2)):
        actions.append(signum.name)
        try:
            os.killpg(process.pid, signum)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=budget)
            return {'clean': signum == signal.SIGINT and process.returncode == 0,
                    'exit': process.returncode, 'actions': actions}
        except subprocess.TimeoutExpired:
            continue
    raise RuntimeError('capture process did not exit within SIGINT/TERM/KILL budgets')


def await_initialized(process, log_path, timeout, follow_by_name=False):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('sniffer exited before startup completed')
        log = log_path.read_text(errors='replace')
        configured = 'Sending scan packet' if follow_by_name else 'Sending follow request'
        if 'Firmware version' in log and configured in log:
            return
        time.sleep(.05)
    raise RuntimeError('sniffer startup log not ready within bounded timeout')


def execute(capture, args):
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    args.out = out / 'run'
    metadata = {'scope': 'one controlled run; function, capture and shutdown gates are separate',
                'sniffer_serial': capture.sniffer_serial, 'sniffer_port': capture.sniffer_port,
                'serial_timeout_ms': capture.serial_timeout_ms,
                'follow_mode': 'name' if capture.follow_by_name else 'address', 'errors': []}
    process = None
    runner_exit = None
    log_path = out / 'capture.log'
    try:
        # Pure ELF preflight before the serial port or probe is opened.
        image = args.elf.read_bytes()
        nm = subprocess.check_output([args.nm, str(args.elf)], text=True, timeout=30)
        symbols = runner.observation_symbols(nm, image)
        metadata['ram_layout'] = runner.validate_ram_layout(image, symbols)
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        if runner.embedded_u32(image, symbols['RUN_SECONDS']) != args.run_seconds:
            raise ValueError('ELF and requested finite budgets differ')
        metadata['sniffer_binary_sha256'] = hashlib.sha256(capture.sniffer.read_bytes()).hexdigest()
        metadata['sniffer_version'] = subprocess.check_output(
            [str(capture.sniffer), '--version'], text=True, timeout=10,
            env=dict(os.environ, NRFUTIL_HOME=str(capture.nrfutil_home))).strip()
        metadata['runner_parameters'] = {'run_seconds': args.run_seconds, 'cycles': args.cycles,
                                         'timeout': args.timeout, 'elf': str(args.elf)}
        metadata['git_revision'] = subprocess.check_output(
            ['git', '-C', str(runner.ROOT), 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
        metadata['trouble_revision'] = subprocess.check_output(
            ['git', '-C', str(runner.ROOT.parent / 'trouble'), 'rev-parse', 'HEAD'],
            text=True, timeout=10).strip()
        sources = [Path(__file__), Path(__file__).with_name('run.py'),
                   runner.EXAMPLE / 'src/main.rs', runner.EXAMPLE / 'src/host.rs',
                   runner.EXAMPLE / 'Cargo.lock']
        source_dir = out / 'sources'
        source_dir.mkdir()
        metadata['sources'] = {}
        for source in sources:
            target = source_dir / source.name
            target.write_bytes(source.read_bytes())
            metadata['sources'][str(source)] = hashlib.sha256(target.read_bytes()).hexdigest()
        follow = (['--follow-by-name', runner.NAME, '--scan-follow-rsp']
                  if capture.follow_by_name else ['--follow', TARGET + ' random'])
        command = [str(capture.sniffer), 'sniff', '--port', capture.sniffer_port,
                   '--timeout', str(capture.serial_timeout_ms), *follow,
                   '--output-pcap-file', str(out / 'capture.pcap'),
                   '--log-output', 'stdout', '--log-level', 'info']
        save(out / 'capture.command.json', command)
        metadata['inherited_sigint_ignored'] = signal.getsignal(signal.SIGINT) == signal.SIG_IGN
        with log_path.open('w') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       env=dict(os.environ, NRFUTIL_HOME=str(capture.nrfutil_home)),
                                       start_new_session=True, preexec_fn=reset_child_signals)
            await_initialized(process, log_path, capture.startup_timeout, capture.follow_by_name)
            # Name mode waits for the DUT to appear after flashing. Startup only
            # confirms scanning; neither mode proves actual connection following.
            metadata['startup'] = ('firmware/version and scan-command logs observed; awaiting name'
                                   if capture.follow_by_name else
                                   'firmware/version and follow-command logs observed')
            save(out / 'capture-session.json', metadata)
            try:
                # Never abort a running finite image because capture was lost.
                runner_exit = runner.execute(args)
            finally:
                with bounded_cleanup():
                    metadata['shutdown'] = stop_capture(process)
                process = None
    except (*runner.FAILURES, subprocess.CalledProcessError) as error:
        metadata['errors'].append(f'{type(error).__name__}: {error}')
    finally:
        with bounded_cleanup():
            if process is not None:
                try:
                    metadata['shutdown'] = stop_capture(process)
                except RuntimeError as error:
                    metadata['errors'].append(str(error))
        try:
            metadata['capture'] = analyze(out / 'capture.pcap', out, args.cycles, capture.tshark)
        except (*runner.FAILURES, subprocess.CalledProcessError) as error:
            metadata['capture'] = {'passed': False, 'errors': [f'{type(error).__name__}: {error}']}
        metadata['runner_exit'] = runner_exit
        metadata['function_passed'] = runner_exit == 0
        metadata['capture_passed'] = metadata['capture']['passed']
        metadata['shutdown_passed'] = metadata.get('shutdown', {}).get('clean', False)
        metadata['passed'] = (not metadata['errors'] and metadata['function_passed']
                              and metadata['capture_passed'] and metadata['shutdown_passed'])
        save(out / 'capture-result.json', metadata)
    print(json.dumps(metadata, indent=2), flush=True)
    return int(not metadata['passed'])


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        'Remaining options pass to run.py: --out, --elf, --smoke-elf, --nm, '
        '--run-seconds, --cycles and --timeout (the central total timeout).'))
    parser.add_argument('--sniffer', type=Path, required=True)
    parser.add_argument('--sniffer-port', required=True)
    parser.add_argument('--sniffer-serial', default='8D4391AA608D9EE4')
    parser.add_argument('--follow-by-name', action='store_true',
                        help='scan until wch585-p4 appears, then follow it; still verify target address')
    parser.add_argument('--nrfutil-home', type=Path, required=True)
    parser.add_argument('--tshark', default='tshark')
    parser.add_argument('--serial-timeout-ms', type=int, default=100)
    parser.add_argument('--startup-timeout', type=float, default=10)
    capture, remaining = parser.parse_known_args(argv)
    if not 1 <= capture.serial_timeout_ms <= 1000 or not 0 < capture.startup_timeout <= 30:
        parser.error('require serial timeout1..1000ms and startup timeout0..30s')
    args = runner.options(remaining)
    capture.sniffer = capture.sniffer.resolve()
    capture.nrfutil_home = capture.nrfutil_home.resolve()
    return capture, args


if __name__ == '__main__':
    raise SystemExit(execute(*options()))
