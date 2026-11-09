#!/usr/bin/env python3
"""Run one finite P3 connection test, archive evidence, then restore/scan smoke."""
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
    'ch585_scannable_runner', ROOT / 'examples/ch585-scannable/tools/run.py')
io = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(io)
# Reuse the existing command/read/idle/flash policy, including its fixed probe.
assert io.ROOT == ROOT
PROBE = io.PROBE
NM = io.NM
EXAMPLE = ROOT / 'examples/ch585-peripheral'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-peripheral'
SMOKE = ROOT / 'examples/ch585-rf-smoke/target/riscv32imc-unknown-none-elf/release/ch585-rf-smoke'
STAT_NAMES = '''magic version stage adv_attempt adv_ok adv_fail rx_arm rx_done bad_crc
bad_pdu scan_req scan_rsp scan_late connect_seen connect_valid connections_with_data
events data_rx data_tx tx_late tx_err rx_err stop_err missed duplicates retries
ctrl_rx unsupported terminated supervision first_timeout rx_full runtime_us cmd mode
clock_hz first_rx last_reason last_opcode trace_count trace_overflow accepted
last_header last_len max_connected_us last_interval last_hop map_lo map_hi win_start
win_width event_counter last_channel first_channel rx_stop_delay_us rx_return_delay_us
tx_entry_delay_us tx_return_delay_us sequence_delay_us handler_delay_us terminate_timeout'''.split()
STAT_NAMES += [f'reserved_{i}' for i in range(len(STAT_NAMES), 64)]


def elf_sections(image):
    if len(image) < 52 or image[:7] != b'\x7fELF\x01\x01\x01':
        raise ValueError('expected a little-endian ELF32 firmware')
    shoff = struct.unpack_from('<I', image, 32)[0]
    entry_size, count, names_index = struct.unpack_from('<HHH', image, 46)
    if entry_size < 40 or not count or names_index >= count or shoff + entry_size * count > len(image):
        raise ValueError('invalid ELF section table')
    sections = []
    for index in range(count):
        fields = struct.unpack_from('<10I', image, shoff + index * entry_size)
        section = dict(zip(('name_offset', 'type', 'flags', 'address', 'offset', 'size',
                            'link', 'info', 'alignment', 'entry_size'), fields))
        if section['type'] != 8 and section['offset'] + section['size'] > len(image):
            raise ValueError('truncated ELF section')
        sections.append(section)
    names = sections[names_index]
    strings = image[names['offset']:names['offset'] + names['size']]
    for section in sections:
        offset = section['name_offset']
        end = strings.find(b'\0', offset)
        if offset >= len(strings) or end < 0:
            raise ValueError('invalid ELF section name')
        section['name'] = strings[offset:end].decode('ascii')
    return sections


def embedded_u32(image, address):
    """Read a file-backed ELF32 little-endian section, never target memory."""
    for section in elf_sections(image):
        start, size = section['address'], section['size']
        if section['type'] != 8 and start <= address and address + 4 <= start + size:
            return struct.unpack_from('<I', image, section['offset'] + address - start)[0]
    raise ValueError('symbol is not backed by four ELF bytes')


def validate_ram_layout(image, symbols):
    """Verify the exact startup-copy image, not just RAM-valued symbols."""
    start, end, lma = (symbols[name] for name in
                       ('_highcode_vma_start', '_highcode_vma_end', '_highcode_lma'))
    if not (0x20000000 <= start < end <= 0x30000000 and 0 <= lma < 0x20000000):
        raise ValueError('highcode copy is not Flash-to-RAM')
    sections = elf_sections(image)
    code = [section for section in sections if section['name'] == '.highcode']
    memory = [section for section in sections if section['name'] == '.highcode_mem']
    if len(code) != 1 or len(memory) != 1:
        raise ValueError('missing or ambiguous .highcode/.highcode_mem section')
    code, memory = code[0], memory[0]
    if any(section['type'] != 1 or section['flags'] & 6 != 6 or not section['size']
           for section in (code, memory)):
        raise ValueError('highcode sections must contain file-backed executable RAM bytes')
    if (code['address'] != start or code['address'] + code['size'] != memory['address']
            or memory['address'] + memory['size'] != end
            or code['offset'] + code['size'] != memory['offset']):
        raise ValueError('highcode startup-copy sections are not contiguous in VMA and file')
    for name in ('memcpy', 'memset'):
        address = symbols[name]
        if not (start <= address < end and memory['address'] <= address
                and address + 4 <= memory['address'] + memory['size']):
            raise ValueError(f'{name} is not in the copied RAM .highcode_mem section')
        embedded_u32(image, address)
    for name, address in symbols.items():
        if compiler_memory_symbol(name):
            if not start <= address <= end - 4:
                raise ValueError(f'compiler memory routine body is outside RAM copy: {name}')
            embedded_u32(image, address)
    phoff = struct.unpack_from('<I', image, 28)[0]
    entry_size, count = struct.unpack_from('<HH', image, 42)
    if entry_size < 32 or phoff + entry_size * count > len(image):
        raise ValueError('invalid ELF program header table')
    for index in range(count):
        kind, offset, vma, physical, size, _, flags, _ = struct.unpack_from(
            '<8I', image, phoff + index * entry_size)
        if (kind == 1 and flags & 1 and offset + size <= len(image)
                and vma <= start and end <= vma + size
                and offset + start - vma == code['offset']
                and physical + start - vma == lma):
            return {'vma_start': start, 'vma_end': end, 'load_address': lma,
                    'file_offset': code['offset'], 'copy_bytes': end - start}
    raise ValueError('no file-backed PT_LOAD maps the entire highcode copy to _highcode_lma')


def compiler_memory_symbol(name):
    # Match both legacy _ZN... and nightly v0 _R... mangling, not only entry stubs.
    return 'compiler_builtins' in name and 'mem' in name


def symbols_from(text):
    required = {'STATS', 'TRACE', 'RUN_SECONDS', 'memcpy', 'memset',
                '_highcode_vma_start', '_highcode_vma_end', '_highcode_lma'}
    symbols = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and compiler_memory_symbol(parts[-1]):
            raise ValueError(f'undefined compiler memory symbol: {parts[-1]}')
        if len(parts) == 3 and (parts[2] in required or compiler_memory_symbol(parts[2])):
            symbols[parts[2]] = int(parts[0], 16)
    if not required.issubset(symbols):
        raise ValueError(f'missing ELF observation/RAM symbols: {sorted(required - set(symbols))}')
    return symbols


def evaluate_client(rows, cycles, hold, timeout, returncode):
    """Reject incomplete, retried, wrong-identity, or short-hold JSONL sessions."""
    errors = []
    if returncode != 0:
        errors.append(f'central exited with status {returncode}')
    starts = [row for row in rows if row.get('event') == 'start']
    summaries = [row for row in rows if row.get('event') == 'summary']
    if (len(starts) != 1 or not rows or rows[0].get('event') != 'start'
            or starts[0].get('name') != 'wch585-p3' or starts[0].get('gatt_operations') != 0
            or starts[0].get('cycles') != cycles or starts[0].get('hold_seconds') != hold
            or starts[0].get('timeout_seconds') != timeout):
        errors.append('central start does not match requested P3 test')
    if (len(summaries) != 1 or not rows or rows[-1].get('event') != 'summary'
            or summaries[0].get('exit_code') != 0 or summaries[0].get('timeout_seconds') != timeout
            or summaries[0].get('reason') != 'cycles_complete'
            or summaries[0].get('cycles_completed') != cycles
            or summaries[0].get('cycles_requested') != cycles
            or summaries[0].get('hold_seconds') != hold
            or summaries[0].get('gatt_operations') != 0):
        errors.append('central completion summary is missing or invalid')
    identifier = summaries[0].get('locked_id') if len(summaries) == 1 else None
    phase, cycle, last_time, connected_at = 'connecting', 1, -1.0, None
    counts = {'connecting': 0, 'connected': 0, 'cancel_requested': 0,
              'disconnected': 0, 'cycle_complete': 0}
    sequence = list(counts)
    for row in rows:
        timestamp = row.get('monotonic_seconds')
        if (not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp)
                or timestamp < last_time):
            errors.append('central JSONL has invalid monotonic timestamps')
            break
        last_time = timestamp
        event = row.get('event')
        if event in ('error', 'connect_failed', 'cleanup_timeout'):
            errors.append(f'central recorded {event}: {row}')
        if event not in counts:
            continue
        counts[event] += 1
        if event != phase or row.get('cycle') != cycle or not identifier or row.get('id') != identifier:
            errors.append('central cycle order, count, or locked UUID mismatch')
        if event == 'connecting' and row.get('local_name') != 'wch585-p3':
            errors.append('central did not match the exact advertised local name')
        if event == 'connected':
            connected_at = timestamp
        if event in ('cancel_requested', 'cycle_complete'):
            duration = row.get('held_seconds')
            if (not isinstance(duration, (int, float)) or not math.isfinite(duration)
                    or duration < hold or connected_at is None or timestamp - connected_at < hold):
                errors.append('central did not complete the requested monotonic hold')
        if event == 'disconnected' and (row.get('expected') is not True or row.get('error') is not None):
            errors.append('central recorded an unexpected or erroneous disconnect')
        if event == 'cycle_complete':
            cycle += 1
            phase = 'connecting'
        else:
            phase = sequence[sequence.index(event) + 1]
    if any(count != cycles for count in counts.values()) or cycle != cycles + 1 or phase != 'connecting':
        errors.append('central did not complete exactly the requested cycles without retries')
    return errors


def evaluate_stats(obs, cycles, hold, run_seconds):
    errors = []
    if len(obs) != 64:
        return ['invalid STATS size']
    if obs[:3] != [0x50333538, 1, 9]:
        errors.append(f'firmware did not finish: magic/version/stage={obs[:3]}')
    if obs[33] & 3 or obs[34] != 0x30000 or obs[22]:
        errors.append('firmware RF stop was not clean (CMD/MODE/stop_err)')
    if not obs[3] or obs[3] != obs[4]:
        errors.append('advertisements were not all successful')
    # Misses, duplicate PDUs, retries, and unsupported LL requests remain visible
    # diagnostics; none of them is an assertion of air timing compliance.
    fatal = (5, 12, 19, 20, 21, 29, 30, 31, 60)
    for index in fatal:
        if obs[index]:
            errors.append(f'firmware {STAT_NAMES[index]}={obs[index]}')
    if obs[14] != cycles or obs[15] != cycles:
        errors.append('CONNECT validity or links with data do not match client cycles')
    if not (cycles <= obs[41] <= obs[17]):
        errors.append('accepted data PDU count is inconsistent with links and data RX')
    if obs[16] < cycles or obs[17] < cycles or obs[18] < cycles:
        errors.append('connection events and bidirectional data not observed for every requested link')
    if obs[17] > obs[7] or obs[26] > obs[17] or obs[15] > obs[14]:
        errors.append('firmware receive/control/connection counts are inconsistent')
    if obs[28] != cycles:
        errors.append('firmware termination count does not match clean central disconnect cycles')
    if obs[44] < hold * 1_000_000:
        errors.append('firmware maximum connected duration is shorter than requested hold')
    if not (run_seconds * 1_000_000 <= obs[32] <= (run_seconds + 3) * 1_000_000):
        errors.append('firmware runtime does not match the embedded finite-run budget')
    if not obs[35] or not obs[36]:
        errors.append('firmware clock or first-data observation missing')
    if obs[39] > 128 and not obs[40]:
        errors.append('trace count exceeds capacity without trace_overflow')
    return errors


def ordered_trace(words, total):
    """Keep the opening 64 rows and restore chronological order of the tail."""
    count = min(total, 128)
    if len(words) != count * 8:
        raise ValueError('invalid TRACE word count')
    slots = list(range(count))
    if total > 128:
        oldest = 64 + (total - 128) % 64
        slots = slots[:64] + list(range(oldest, 128)) + list(range(64, oldest))
    names = ('time_us', 'kind', 'event', 'channel', 'header', 'length', 'arg0', 'arg1')
    return [dict(zip(names, words[slot * 8:slot * 8 + 8])) for slot in slots]


def read_client(path):
    rows = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f'invalid central JSONL line {number}: {error}') from error
        if not isinstance(row, dict):
            raise ValueError(f'central JSONL line {number} is not an object')
        rows.append(row)
    return rows


def wait_until(deadline):
    # Do not probe even after a client failure; the finite firmware must finish.
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(remaining)


def stop_client(client):
    if client is None or client.poll() is not None:
        return
    client.terminate()
    try:
        client.wait(timeout=3)
    except subprocess.TimeoutExpired:
        client.kill()
        client.wait(timeout=3)


def halt_and_idle(out, prefix):
    # Legacy diagnostic only: standalone reads resume the core after each
    # access, so this cannot establish continuous halt ownership. Runners use
    # io.flash and its single-session preflight helper instead.
    # probe-rs b580f1a0b calls an argument-free `break` a halt. `quit`
    # suspends on disconnect; `halt`/`exit` are not console commands.
    # The debug CLI constructs Readline even after `quit`; macOS needs a PTY.
    # BSD script forwards the child's exit status, including panic exit 101.
    output = io.command(['/usr/bin/script', '-q', '/dev/null', 'probe-rs', 'debug',
                         *PROBE, '-c', 'break', '-c', 'quit'],
                        out / f'{prefix}-halt.log', timeout=15)
    # CoreStatus::Halted(Request) is rendered by short_long_status as
    # "Stopped on your request[ at <PC/source>]."; remove optional ANSI style.
    plain = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
    if not any(re.fullmatch(r'\s*Stopped on your request(?: at .+)?\.\s*', line)
               for line in plain.splitlines()):
        raise RuntimeError(f'explicit core-halt confirmation missing: {prefix}-halt.log')
    io.idle(out, prefix)


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {'probe': PROBE, 'air_ifs': 'UNMEASURED', 'scope': 'connect-only prototype',
                            'run_seconds': args.run_seconds, 'cycles': args.cycles, 'hold': args.hold,
                            'client_timeout': args.timeout,
                            'restart': 'verified idle then debug boot; not a power cycle'}
    client = log = stderr_log = None
    touched = False
    safe_read_at = 0.0
    symbols = None
    try:
        # Archive first, inspect and flash this exact copy, not a mutable build output.
        archived = args.out / 'firmware.elf'
        shutil.copyfile(args.elf, archived)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        smoke = args.out / 'smoke.elf'
        shutil.copyfile(args.smoke_elf, smoke)
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_output = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        symbols = symbols_from(nm_output)
        metadata['symbols'] = symbols
        metadata['ram_layout'] = validate_ram_layout(image, symbols)
        embedded_seconds = embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded_seconds
        if embedded_seconds != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={embedded_seconds}, but --run-seconds={args.run_seconds}')
        source = args.out / 'central.swift'
        shutil.copyfile(EXAMPLE / 'tools/central.swift', source)
        binary = (args.out / 'central').resolve()
        io.command(['swiftc', str(source), '-o', str(binary)], args.out / 'central-build.log', timeout=120)
        touched = True
        try:
            # The helper performs halt, engine shutdown, both idle checks and
            # verified download in one retained probe session.
            io.flash(archived, args.out, 'test', check_idle=False)
        finally:
            # A failed download can still have started firmware. Wait the full
            # embedded budget after the download returns, including error paths.
            safe_read_at = time.monotonic() + embedded_seconds + 3
        client_args = [str(binary), '--cycles', str(args.cycles), '--hold', str(args.hold),
                       '--timeout', str(args.timeout)]
        (args.out / 'central.command.json').write_text(json.dumps(client_args) + '\n')
        log = (args.out / 'central.jsonl').open('w')
        stderr_log = (args.out / 'central.stderr.log').open('w')
        client = subprocess.Popen(client_args, stdout=log, stderr=stderr_log, text=True)
        try:
            client.wait(timeout=args.timeout + 6)
        except subprocess.TimeoutExpired:
            errors.append('central exceeded timeout plus bounded cleanup')
            stop_client(client)
        finally:
            log.close()
            stderr_log.close()
            log = stderr_log = None
        metadata['client_exit'] = client.returncode
        rows = read_client(args.out / 'central.jsonl')
        metadata['client_summary'] = next((row for row in reversed(rows) if row.get('event') == 'summary'), None)
        errors.extend(evaluate_client(rows, args.cycles, args.hold, args.timeout, client.returncode))
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        try:
            stop_client(client)
        except (OSError, subprocess.TimeoutExpired) as error:
            errors.append(f'client cleanup: {error}')
        if log is not None:
            log.close()
        if stderr_log is not None:
            stderr_log.close()
        if touched:
            wait_until(safe_read_at)
            if symbols is not None and safe_read_at:
                try:
                    obs = io.read32(symbols['STATS'], 64, args.out / 'stats.txt')
                    metadata['stats'] = dict(zip(STAT_NAMES, obs))
                    (args.out / 'stats.json').write_text(json.dumps(metadata['stats'], indent=2) + '\n')
                    trace_words = min(obs[39], 128) * 8
                    if trace_words:
                        words = io.read32(symbols['TRACE'], trace_words, args.out / 'trace.txt')
                    else:
                        words = []
                        (args.out / 'trace.txt').write_text('')
                    trace = ordered_trace(words, obs[39])
                    (args.out / 'trace.json').write_text(json.dumps(trace, indent=2) + '\n')
                    errors.extend(evaluate_stats(obs, args.cycles, args.hold, args.run_seconds))
                except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                    errors.append(f'observations: {error}')
            try:
                io.flash(args.out / 'smoke.elf', args.out, 'restore', check_idle=False)
                io.command(['swift', str(io.SCANNER), 'wch585', '8'], args.out / 'restore-scan.log', 20)
                metadata['smoke_recovery'] = 'flash verify and macOS discovery PASS'
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                errors.append(f'recovery: {error}')
                metadata['smoke_recovery'] = 'NOT VERIFIED'
        else:
            metadata['smoke_recovery'] = 'NOT ATTEMPTED: preflight failed before hardware access'
        metadata['errors'] = errors
        metadata['passed'] = not errors
        (args.out / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


def options(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--elf', type=Path, default=DEFAULT_ELF)
    parser.add_argument('--smoke-elf', type=Path, default=SMOKE)
    parser.add_argument('--nm', default=NM)
    parser.add_argument('--run-seconds', type=int, choices=(25, 360), default=25)
    parser.add_argument('--cycles', type=int, default=1)
    parser.add_argument('--hold', type=float, default=1)
    parser.add_argument('--timeout', type=float, default=20)
    args = parser.parse_args(argv)
    if not (1 <= args.cycles <= 1000):
        parser.error('--cycles must be in 1...1000')
    if not (math.isfinite(args.hold) and math.isfinite(args.timeout)
            and args.hold > 0 and args.cycles * args.hold < args.timeout
            and args.timeout + 3 <= args.run_seconds):
        parser.error('require hold > 0, cycles * hold < timeout, and timeout + 3 <= run-seconds')
    args.out = args.out.resolve()
    args.elf = args.elf.resolve()
    args.smoke_elf = args.smoke_elf.resolve()
    return args


if __name__ == '__main__':
    sys.exit(execute(options()))
