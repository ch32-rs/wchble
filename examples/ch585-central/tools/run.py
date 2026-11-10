#!/usr/bin/env python3
"""Run finite C1 CH585 central phases, archive evidence, then restore smoke.

Hardware policy is inherited from the P3 runner: fixed probe
1a86:8010:F93D8F067E10, one retained preflight session before every flash,
no probe access while RF may be running, and the full RUN_SECONDS + 3 s wait
before any read. Failures are never retried automatically.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    'ch585_c1_p3', ROOT / 'examples/ch585-peripheral/tools/run.py')
p3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p3)
io = p3.io
PROBE, NM = p3.PROBE, p3.NM
EXAMPLE = ROOT / 'examples/ch585-central'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-central'
DEFAULT_BOGUS_ELF = DEFAULT_ELF
SMOKE = p3.SMOKE
NAME = 'wch585-c1'
SERVICE = '00001000-b0cd-11ec-871f-d45ddf138840'
CHARACTERISTIC = '00001001-b0cd-11ec-871f-d45ddf138840'
STAT_NAMES = '''magic version stage run_us clock_hz scan_arms scan_completions scan_timeouts
scan_crc_ok scan_crc_err adv_reports_pushed adv_reports_dropped target_reports
create_conn_commands connect_attempts connect_sent connect_late connect_errors
create_conn_timeouts events_scheduled events_run first_rx established rx_pdu rx_empty
rx_acl rx_control tx_pdu tx_late retries missed_events supervision local_term
remote_term conn_complete_events disconn_complete_events reconnect_cycles
gatt_service_found gatt_char_found gatt_reads_ok gatt_reads_err gatt_writes_ok
gatt_writes_err gatt_ops first_anchor_us first_rx_done_us first_rx_delta_us
connect_entry_delta_us connect_return_delta_us min_deadline_margin_us rx_arm_delta_us
conn_interval conn_hop_sca aa crc_init win_size_offset final_cmd final_mode
stop_failures bridge_errors host_acl_rx host_acl_tx channel_mask rx_invalid'''.split()
assert len(STAT_NAMES) == 64
HOST_NAMES = '''phase connections disconnects scan_reports target_matches connect_errors
reads writes notifications subscriptions gatt_errors last_error cycles_completed
last_hci_status reserved_14 reserved_15'''.split()
PHASES = ('positive', 'negative-nosource', 'negative-wrong-name',
          'negative-no-service', 'negative-bogus-peer', 'peer-vanish')
ANDROID_SERIAL = '55VS4H8TRW45KVQS'
PKG = 'com.example.wchble.gatt'


class PhaseError(RuntimeError):
    pass


def observation_symbols(text):
    symbols = p3.symbols_from(text)
    wanted = {'HOST_STATS', 'TARGET_NAME', 'AA', 'CRC_INIT', 'WIN_SPEC',
              'CONNECT_OFFSET', 'BOGUS_PEER', 'SERVICE_UUID',
              'TRACE_COUNT', 'TRACE_OVERFLOW'}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in wanted:
            symbols[parts[2]] = int(parts[0], 16)
    missing = wanted - set(symbols)
    if missing:
        raise PhaseError(f'missing image identity symbols: {sorted(missing)}')
    return symbols


def embedded_bytes(image, address, count):
    for section in p3.elf_sections(image):
        start, size = section['address'], section['size']
        if section['type'] != 8 and start <= address and address + count <= start + size:
            offset = section['offset'] + address - start
            return image[offset:offset + count]
    raise PhaseError('identity symbol is not backed by ELF bytes')


def validate_observations(image, symbols):
    sections = p3.elf_sections(image)
    ranges = []
    for name, count in (('STATS', 64), ('HOST_STATS', 16), ('TRACE', 128 * 8),
                        ('TRACE_COUNT', 1), ('TRACE_OVERFLOW', 1)):
        address, size = symbols[name], count * 4
        backed = any(section['flags'] & 3 == 3 and section['address'] <= address
                     and address + size <= section['address'] + section['size']
                     for section in sections)
        if address % 4 or not backed:
            raise PhaseError(f'{name} is not an aligned writable RAM observation buffer')
        if any(address < end and start < address + size for start, end in ranges):
            raise PhaseError(f'{name} overlaps another observation buffer')
        ranges.append((address, address + size))


def check_identity(image, symbols, phase):
    checks = {
        'target_name': (embedded_bytes(image, symbols['TARGET_NAME'], 9), NAME.encode()),
        'aa': (p3.embedded_u32(image, symbols['AA']), 0x12345678),
        'crc_init': (p3.embedded_u32(image, symbols['CRC_INIT']), 0x00555555),
        'service_uuid': (embedded_bytes(image, symbols['SERVICE_UUID'], 16),
                         bytes.fromhex('00001000b0cd11ec871fd45ddf138840')),
        'bogus_flag': (p3.embedded_u32(image, symbols['BOGUS_PEER']),
                       1 if phase == 'negative-bogus-peer' else 0),
    }
    for label, (actual, expected) in checks.items():
        if actual != expected:
            raise PhaseError(f'image {label} mismatch: {actual!r} != {expected!r}')
    win = p3.embedded_u32(image, symbols['WIN_SPEC'])
    if not (1 <= win & 0xff <= 10 and win >> 8 <= 24):
        raise PhaseError(f'encoded WIN_SPEC is invalid: {win:#x}')
    offset = p3.embedded_u32(image, symbols['CONNECT_OFFSET'])
    # 0 marks the hardware-timed initiator: the LLE starts CONNECT_IND at
    # T_IFS after the advertisement, so there is no software offset to
    # calibrate. The older software-deadline build carries 60..200 us instead.
    if offset != 0 and not 60 <= offset <= 200:
        raise PhaseError(f'CONNECT_OFFSET outside calibrated range: {offset}')
    return {'aa': 0x12345678, 'crc_init': 0x00555555, 'win_spec': win,
            'connect_offset_us': offset}


def source_for(phase):
    if phase in ('negative-nosource', 'negative-bogus-peer'):
        return None
    if phase == 'negative-wrong-name':
        return {'name': NAME + '-neg', 'no_service': False}
    if phase == 'negative-no-service':
        return {'name': NAME, 'no_service': True}
    if phase == 'peer-vanish':
        # Hold the first ATT read response long enough for the runner to turn
        # the phone's Bluetooth off, then let the link die underneath it.
        return {'name': NAME, 'no_service': False, 'hold_ms': 5000}
    return {'name': NAME, 'no_service': False}


class MacSource:
    def __init__(self, out, name, no_service):
        self.out = out
        self.name = name
        self.no_service = no_service
        self.binary = out / 'peripheral'
        self.proc = None
        self.log = None

    def build(self):
        source = self.out / 'peripheral.swift'
        shutil.copyfile(EXAMPLE / 'tools/peripheral.swift', source)
        io.command(['swiftc', str(source), '-o', str(self.binary)],
                   self.out / 'peripheral-build.log', timeout=120)

    def start(self, timeout):
        if self.no_service:
            raise PhaseError('Mac source always exposes the service; no-service needs Android')
        args = [str(self.binary), '--name', self.name, '--timeout', str(timeout)]
        (self.out / 'peripheral.command.json').write_text(json.dumps(args) + '\n')
        self.log = (self.out / 'peripheral.jsonl').open('w')
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT, text=True)
        time.sleep(0.8)
        if self.proc.poll() is not None:
            raise PhaseError('Mac source exited before advertising')

    def stop(self):
        p3.stop_client(self.proc)
        if self.log is not None:
            self.log.close()
            self.log = None

    def evaluate(self, phase, cycles, run_seconds):
        errors = []
        if not (self.out / 'peripheral.jsonl').is_file():
            return ['Mac source produced no log']
        rows = p3.read_client(self.out / 'peripheral.jsonl')
        if len(rows) < 3 or rows[0].get('event') != 'start':
            errors.append('Mac source start/state log is missing')
        if not any(row.get('event') == 'advertising' for row in rows):
            errors.append('Mac source never confirmed advertising')
        reads = sum(row.get('event') == 'read' for row in rows)
        writes = sum(row.get('event') == 'write' for row in rows)
        values = [row.get('value') for row in rows if row.get('event') == 'write']
        if phase == 'positive':
            if reads != 2 * cycles:
                errors.append(f'Mac source saw {reads} reads, expected {2 * cycles}')
            if writes != cycles or values != [0x2b] * cycles:
                errors.append(f'Mac source saw writes {values}, expected {cycles} x 0x2b')
        elif phase == 'negative-wrong-name':
            if reads or writes:
                errors.append('wrong-name source saw traffic that should not exist')
        return errors


class AndroidSource:
    def __init__(self, out, name, no_service, hold_ms=0):
        self.out = out
        self.name = name
        self.no_service = no_service
        self.hold_ms = hold_ms
        self.started = False

    def build(self):
        build = EXAMPLE / 'tools/android-gatt/build.sh'
        if not build.is_file():
            raise PhaseError(f'missing Android source build script: {build}')
        output = io.command([str(build)], self.out / 'android-build.log', timeout=180)
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        self.apk = Path(lines[-1]) if lines else None
        if self.apk is not None and not self.apk.is_absolute():
            self.apk = build.parent / self.apk
        if self.apk is None or not self.apk.is_file():
            raise PhaseError(f'Android build did not print an APK path: {output!r}')

    def adb(self, *args, timeout=30):
        return io.command(['adb', '-s', ANDROID_SERIAL, *args],
                          self.out / f'adb-{len(list(self.out.glob("adb-*.log")))}.log',
                          timeout=timeout)

    def start(self, timeout):
        self.build()
        self.adb('install', '-r', '-g', str(self.apk), timeout=90)
        self.adb('logcat', '-c')
        self.adb('shell', 'am', 'force-stop', PKG)
        args = ['shell', 'am', 'start', '-W', '-n', f'{PKG}/.MainActivity',
                '--es', 'name', self.name,
                '--ez', 'no_service', 'true' if self.no_service else 'false',
                '--ei', 'timeout', str(timeout)]
        if self.hold_ms:
            args.extend(['--ei', 'hold_ms', str(self.hold_ms)])
        self.adb(*args, timeout=30)
        self.started = True
        time.sleep(0.8)

    def stop(self):
        if self.started:
            try:
                self.adb('shell', 'am', 'force-stop', PKG)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                pass
        self.started = False

    def logs(self):
        output = self.adb('logcat', '-d', '-s', 'WCHBLE', timeout=30)
        (self.out / 'peripheral.logcat.txt').write_text(output)
        rows = []
        for line in output.splitlines():
            start = line.find('{')
            if start < 0:
                continue
            try:
                row = json.loads(line[start:])
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
        return rows

    def evaluate(self, phase, cycles, run_seconds):
        errors = []
        rows = self.logs()
        events = lambda name: [row for row in rows if row.get('event') == name]
        if not events('start') or not events('advertising'):
            errors.append('Android source start/advertising log is missing')
        reads, writes = events('read'), events('write')
        values = [row.get('value') for row in writes]
        if phase == 'positive':
            if len(events('connected')) < cycles or len(events('disconnected')) < cycles:
                errors.append('Android source did not log all connection cycles')
            if len(reads) != 2 * cycles:
                errors.append(f'Android source saw {len(reads)} reads, expected {2 * cycles}')
            if len(writes) != cycles or values != [0x2b] * cycles:
                errors.append(f'Android source saw writes {values}, expected {cycles} x 0x2b')
        elif phase == 'negative-wrong-name':
            if reads or writes:
                errors.append('wrong-name source saw traffic that should not exist')
        elif phase == 'negative-no-service':
            if not events('connected'):
                errors.append('no-service source never logged a connection')
            if reads or writes:
                errors.append('no-service source saw GATT traffic')
        return errors


def invariants(s):
    errors = []
    if s[5] != s[6] + s[7]:
        errors.append(f'scan arm invariant broken: {s[5]} != {s[6]} + {s[7]}')
    if s[6] != s[8] + s[9]:
        errors.append(f'scan completion invariant broken: {s[6]} != {s[8]} + {s[9]}')
    if s[14] != s[15] + s[16] + s[17]:
        errors.append(f'connect attempt invariant broken: {s[14]} != {s[15]}+{s[16]}+{s[17]}')
    if s[23] != s[24] + s[25] + s[26] + s[63]:
        errors.append(f'RX PDU invariant broken: {s[23]} != {s[24]}+{s[25]}+{s[26]}+{s[63]}')
    if s[43] != s[39] + s[41]:
        errors.append('GATT op count does not equal reads + writes')
    return errors


def evaluate_stats(s, host, phase, cycles, run_seconds, identity):
    errors = invariants(s)
    if s[:2] != [0x43313538, 1] or s[2] != 9:
        errors.append(f'firmware did not reach clean stage 9: stage={s[2]:#x}')
    if s[56] & 3 or s[57] != 0x30000 or s[58]:
        errors.append(f'RF did not finish idle: cmd={s[56]:#x} mode={s[57]:#x} stop={s[58]}')
    if s[1] != 1:
        errors.append('STATS version mismatch')

    host_ok = host is not None
    if phase == 'positive':
        if not (s[8] and s[10] and s[12]):
            errors.append('scan never produced valid target advertising reports')
        if s[14] != s[15] or s[16] or s[17] or s[18]:
            errors.append(f'CONNECT_IND attempts failed: {s[14:19]}')
        if s[21] < cycles or s[22] < cycles or s[34] != cycles or s[35] != cycles:
            errors.append(f'connection lifecycle counts wrong: first_rx={s[21]} est={s[22]} '
                          f'complete={s[34]} disconn={s[35]} cycles={cycles}')
        if s[37] < cycles or s[38] < cycles:
            errors.append('Host did not complete GATT discovery every cycle')
        if s[39] < 2 * cycles or s[41] < cycles:
            errors.append(f'GATT read/write counts too low: {s[39]}/{s[41]}')
        if s[59]:
            errors.append(f'bridge errors recorded: {s[59]}')
        if host_ok:
            if (host[1] != cycles or host[2] != cycles or host[12] != cycles
                    or host[6] < 2 * cycles or host[7] != cycles or host[10]
                    or host[0] != 9):
                errors.append(f'Host counters wrong: {host[:14]}')
            if host[3] == 0 or host[4] == 0:
                errors.append('Host saw no scan reports or no target match')
    elif phase == 'negative-nosource':
        if s[12] or s[13] or s[14] or s[34]:
            errors.append('initiator ran without a source')
        if not s[8]:
            errors.append('receiver never decoded a valid ambient advertising packet')
        if host_ok and (host[3] == 0 or host[4] or host[1]):
            errors.append(f'Host scan counters wrong without source: {host[:5]}')
    elif phase == 'negative-wrong-name':
        if s[12] or s[13] or s[14] or s[34]:
            errors.append('initiator ran for the wrong-name source')
        if not s[8] or not s[10]:
            errors.append('scan did not receive the wrong-name source')
        if host_ok and (host[4] or host[1]):
            errors.append(f'Host matched/connected despite wrong name: {host[:5]}')
    elif phase == 'negative-no-service':
        if not s[34] or not s[35] or s[37]:
            errors.append(f'no-service phase lifecycle wrong: {s[34]}/{s[35]}/{s[37]}')
        if s[59]:
            errors.append(f'bridge errors recorded: {s[59]}')
        if host_ok:
            if not host[10] or host[1] == 0:
                errors.append('Host did not report a GATT discovery error')
            if host[12] != 0:
                errors.append('GATT cycle counted as complete without the service')
    elif phase == 'peer-vanish':
        # The peer is made unreachable mid-connection. Exactly one connection
        # and one disconnection must be observed, and the link must end through
        # exactly one mechanism: supervision timeout or a peer terminate.
        if s[34] != 1:
            errors.append(f'expected exactly one completed connection, got {s[34]}')
        if s[35] != 1:
            errors.append(f'expected exactly one disconnection event, got {s[35]}')
        if s[31] + s[33] != 1:
            errors.append(f'link ended {s[31] + s[33]} times '
                          f'(supervision={s[31]} remote_term={s[33]})')
        if s[59]:
            errors.append(f'bridge errors recorded: {s[59]}')
        if host_ok and (host[1] != 1 or host[2] != 1):
            errors.append(f'Host disconnect counts wrong: {host[:3]}')
        if not s[21]:
            errors.append('first connection event RX never observed')
    elif phase == 'negative-bogus-peer':
        if s[14] or s[34]:
            errors.append('CONNECT_IND/complete happened for a nonexistent peer')
        if s[18] < cycles:
            errors.append(f'initiator timeouts {s[18]} < {cycles}')
        if s[59]:
            errors.append(f'bridge errors recorded: {s[59]}')
        if host_ok and (host[1] or host[5] < cycles or host[4]):
            errors.append(f'Host connect-error counters wrong: {host[:6]}')
    else:
        errors.append(f'unknown phase {phase}')
    return errors


def start_source(args, phase, out, run_seconds):
    spec = source_for(phase)
    if spec is None:
        return None
    if args.source == 'mac':
        source = MacSource(out, spec['name'], spec['no_service'])
    else:
        source = AndroidSource(out, spec['name'], spec['no_service'],
                               spec.get('hold_ms', 0))
    source.build()
    source.start(run_seconds + 10)
    return source


def run_phase(args, phase, out):
    out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {'phase': phase, 'source': args.source,
                            'probe': ' '.join(PROBE), 'run_seconds': args.run_seconds,
                            'cycles': args.cycles}
    elf = args.bogus_elf if phase == 'negative-bogus-peer' else args.elf
    source = None
    touched = False
    safe_read_at = 0.0
    symbols = None
    try:
        archived = out / 'firmware.elf'
        shutil.copyfile(elf, archived)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        smoke = out / 'smoke.elf'
        shutil.copyfile(args.smoke_elf, smoke)
        symbols = observation_symbols(io.command([args.nm, str(archived)], out / 'symbols.txt'))
        metadata['symbols'] = symbols
        metadata['ram_layout'] = p3.validate_ram_layout(image, symbols)
        validate_observations(image, symbols)
        metadata['identity'] = check_identity(image, symbols, phase)
        embedded = p3.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded
        if embedded != args.run_seconds:
            raise PhaseError(f'ELF RUN_SECONDS={embedded}, but --run-seconds={args.run_seconds}')

        if phase == 'peer-vanish' and args.source != 'android':
            raise PhaseError('peer-vanish needs the Android source (adapter off)')
        source = start_source(args, phase, out, args.run_seconds)
        touched = True
        try:
            io.flash(archived, out, 'test', check_idle=False)
        finally:
            safe_read_at = time.monotonic() + args.run_seconds + 3
        started = time.monotonic()
        vanished = False
        while time.monotonic() - started < args.run_seconds + 3:
            if (phase == 'peer-vanish' and not vanished
                    and time.monotonic() - started >= 5.5):
                io.command(['adb', '-s', ANDROID_SERIAL, 'shell',
                            'svc', 'bluetooth', 'disable'],
                           out / 'vanish.log', 30)
                metadata['vanish_at_seconds'] = round(time.monotonic() - started, 2)
                vanished = True
            time.sleep(0.25)
        metadata['safe_read_at_seconds'] = round(safe_read_at - started, 3)
        if source is not None:
            errors.extend(source.evaluate(phase, args.cycles, args.run_seconds))
        obs = io.read32(symbols['STATS'], 64, out / 'stats.txt')
        host = io.read32(symbols['HOST_STATS'], 16, out / 'host-stats.txt')
        metadata['stats'] = dict(zip(STAT_NAMES, obs))
        metadata['host_stats'] = dict(zip(HOST_NAMES, host))
        metadata['end_mechanism'] = ('supervision' if obs[31] else
                                     'remote_terminate' if obs[33] else 'none')
        trace_count = io.read32(symbols['TRACE_COUNT'], 1, out / 'trace-count.txt')[0]
        trace_overflow = io.read32(symbols['TRACE_OVERFLOW'], 1, out / 'trace-overflow.txt')[0]
        metadata['trace_count'] = trace_count
        metadata['trace_overflow'] = trace_overflow
        trace_words = min(trace_count, 128) * 8
        words = io.read32(symbols['TRACE'], trace_words, out / 'trace.txt') if trace_words else []
        if not trace_words:
            (out / 'trace.txt').write_text('')
        trace = p3.ordered_trace(words, trace_count)
        (out / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
        metadata['trace_rows'] = len(trace)
        errors.extend(evaluate_stats(obs, host, phase, args.cycles, args.run_seconds,
                                     metadata['identity']))
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        if phase == 'peer-vanish':
            try:
                io.command(['adb', '-s', ANDROID_SERIAL, 'shell',
                            'svc', 'bluetooth', 'enable'],
                           out / 'restore-bt.log', 30)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                errors.append(f'bluetooth restore: {error}')
        if source is not None:
            try:
                source.stop()
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                errors.append(f'source cleanup: {error}')
        metadata['errors'] = errors
        metadata['passed'] = not errors
        (out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
        if touched:
            pass  # smoke restore is owned by execute(), after all phases
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    phases = PHASES if args.phase == 'all' else (args.phase,)
    results = {}
    errors = []
    symbols = None
    for phase in phases:
        phase_errors = run_phase(args, phase, args.out / phase)
        results[phase] = 'PASS' if not phase_errors else 'FAIL'
        errors.extend(f'{phase}: {error}' for error in phase_errors)
    try:
        if len(phases) > 1 or args.phase in PHASES:
            smoke = args.out / 'smoke-restore.elf'
            shutil.copyfile(args.smoke_elf, smoke)
            io.flash(smoke, args.out, 'restore', check_idle=False)
            io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                       args.out / 'restore-scan.log', 20)
            results['smoke_recovery'] = 'PASS'
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        errors.append(f'recovery: {error}')
        results['smoke_recovery'] = 'FAIL'
    (args.out / 'result.json').write_text(json.dumps(
        {'phases': results, 'errors': errors, 'passed': not errors}, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--bogus-elf', type=Path, default=DEFAULT_BOGUS_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--source', choices=('mac', 'android'), default='android')
    parser.add_argument('--phase', choices=(*PHASES, 'all'), default='positive')
    parser.add_argument('--run-seconds', type=int, choices=(25, 60, 180), default=60)
    parser.add_argument('--cycles', type=int, default=3)
    args = parser.parse_args(argv)
    if not 1 <= args.cycles <= 100:
        parser.error('--cycles must be in 1...100')
    args.out = args.out.resolve()
    args.elf = args.elf.resolve()
    args.bogus_elf = args.bogus_elf.resolve()
    args.smoke_elf = args.smoke_elf.resolve()
    return args


if __name__ == '__main__':
    sys.exit(execute(options()))
