#!/usr/bin/env python3
"""S2 secure run: flash the encrypted firmware, drive an Android pairing and
encrypted GATT read/write, collect SECURE_STATS + logcat, then restore smoke.

The script never probes while RF may be running: it flashes through the
single-session preflight helper, launches the phone app afterwards, and reads
RAM only once the embedded finite-run budget plus the cleanup margin elapsed.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location(
    'ch585_p4_runner', ROOT / 'examples/ch585-trouble-gatt/tools/run.py')
p4 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p4)
io, PROBE, NM = p4.io, p4.PROBE, p4.NM

EXAMPLE = ROOT / 'examples/ch585-trouble-gatt'
DEFAULT_ELF = EXAMPLE / 'target/riscv32imc-unknown-none-elf/release/ch585-trouble-gatt'
APK = EXAMPLE / 'tools/android-pair/build/android-pair.apk'
PACKAGE = 'com.example.wchble.pair'
ACTIVITY = PACKAGE + '/.MainActivity'
ADB_SERIAL = '55VS4H8TRW45KVQS'
SMOKE = p4.SMOKE

SEC_MAGIC = 0x5332_3538
SEC_NAMES = '''magic version_flags enc_req enc_rsp ltk_request ltk_reply
    start_req start_rsp encrypted_tx encrypted_rx active mic_failure errors prepared
    plaintext_start_retry last_error'''.split()
BOND_NAMES = '''magic version load_result records_loaded winner_slot winner_seq
    save_attempts save_ok save_fail deferred_no_window save_on_disconnect
    clear_requests clear_ok clear_fail fault_injected last_error max_save_us
    last_save_us boot_read_us pairs_complete pairs_without_bond in_memory_removed
    control_writes malformed_control_writes add_bond_ok add_bond_fail
    identity_mismatch reserved1 reserved2 reserved3 reserved4 reserved5'''.split()
BOND_MAGIC = 0x4233_5330
X4_MAGIC = 0x5834_0001
X4_NAMES = '''magic version mtu bulk_reads bulk_writes bulk_len bulk_sum bulk_match
    burst_runs burst_attempts burst_sent burst_queue_full burst_busy burst_other
    burst_len last_error'''.split()
X1_MAGIC = 0x5831_0001
X1_NAMES = '''magic version algorithm event_counter adv_chsel init_chsel length_req_rx
    length_rsp_rx length_req_tx length_rsp_tx tx_octets rx_octets tx_time rx_time
    max_tx_pdu max_rx_pdu rx_over_27 tx_over_27 host_packets_segmented host_fragments
    tx_pdus rx_pdus feature_exchange last_error'''.split()
BULK_LEN = 200
BULK_WRITE_SUM = sum(255 - index for index in range(BULK_LEN))
BURST_LEN = 121
BURST_ATTEMPTS = 12
ATT_REASON = 'att_mtu_long_burst_ok'
HOST_NAMES = p4.HOST_NAMES
STAT_NAMES = p4.STAT_NAMES
FAILURES = (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired, KeyboardInterrupt)

SECURITY_ENCRYPTED = 3
SUMMARY_REASONS = {
    'pair': 'encrypted_read_write_ok',
    'reconnect': 'reconnect_encrypted_read_write_ok',
    'delete': 'bond_delete_ok',
    'wipe': 'bond_wipe_ok',
    'fault': 'fault_injected_ok',
    'att': 'att_mtu_long_burst_ok',
}
ui_path = '/sdcard/wchble-ui.xml'


def symbols_from(text):
    symbols = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in 'TtDdBbRr':
            symbols[parts[2]] = int(parts[0], 16)
    return symbols


DIAG_RX_BASE, DIAG_TX_BASE, DIAG_ENTRIES = 2, 18, 16
DIAG_DISCONNECT_REASON, DIAG_DISCONNECT_COUNT = 34, 35
DIAG_NAMES = {4: 'ATT', 5: 'LE-signaling', 6: 'SMP'}
SMP_OPCODES = {
    0x01: 'PairingRequest', 0x02: 'PairingResponse', 0x03: 'PairingConfirm', 0x04: 'PairingRandom',
    0x05: 'PairingFailed', 0x06: 'EncryptionInformation', 0x07: 'MasterIdentification',
    0x08: 'IdentityInformation', 0x09: 'IdentityAddressInformation', 0x0a: 'SigningInformation',
    0x0b: 'SecurityRequest', 0x0c: 'PairingPublicKey', 0x0d: 'PairingDHKeyCheck',
    0x0e: 'KeypressNotification',
}
ATT_OPCODES = {
    0x01: 'ErrorRsp', 0x02: 'MtuReq', 0x03: 'MtuRsp', 0x04: 'FindInfoReq', 0x05: 'FindInfoRsp',
    0x06: 'FindByTypeValueReq', 0x07: 'FindByTypeValueRsp', 0x08: 'ReadByTypeReq', 0x09: 'ReadByTypeRsp',
    0x0a: 'ReadReq', 0x0b: 'ReadRsp', 0x0c: 'ReadBlobReq', 0x0d: 'ReadBlobRsp', 0x0e: 'ReadMultiReq',
    0x0f: 'ReadMultiRsp', 0x10: 'ReadByGroupReq', 0x11: 'ReadByGroupRsp', 0x12: 'WriteReq',
    0x13: 'WriteRsp', 0x16: 'PrepareWriteReq', 0x17: 'PrepareWriteRsp',
    0x18: 'ExecuteWriteReq', 0x19: 'ExecuteWriteRsp',
    0x1b: 'Notification', 0x1d: 'Indication', 0x1e: 'Confirm', 0x52: 'WriteCmd',
}


def decode_opcodes(words):
    """Per-opcode start-fragment counts; no ring wrap, unlike SEC_DIAG."""
    smp = {'rx': {SMP_OPCODES.get(i, f'0x{i:02x}'): words[i] for i in range(16) if words[i]},
           'tx': {SMP_OPCODES.get(i, f'0x{i:02x}'): words[16 + i] for i in range(16) if words[16 + i]}}
    att = {'rx': {ATT_OPCODES.get(i, f'0x{i:02x}'): words[32 + i] for i in range(32) if words[32 + i]},
           'tx': {ATT_OPCODES.get(i, f'0x{i:02x}'): words[64 + i] for i in range(32) if words[64 + i]}}
    return {'smp': smp, 'att': att}


TRACE_KINDS = {1: 'advertise', 2: 'advertise_done', 3: 'event', 4: 'connect',
               5: 'terminate', 8: 'first_exchange', 9: 'bridge'}


def decode_trace(words, count):
    """Decode the 8-word TRACE rows; `count` is STATS[39].

    Rows 0..127 are filled in order; past that the firmware keeps a 64-row
    ring in rows 64..127, so only the latest 64 survive.
    """
    rows = []
    if count <= 128:
        order = range(count)
    else:
        start = (count - 64) % 64
        order = [64 + (start + i) % 64 for i in range(64)]
    for row in order:
        base = row * 8
        entry = words[base:base + 8]
        if not entry or not any(entry):
            continue
        rows.append({
            'us': entry[0],
            'kind': TRACE_KINDS.get(entry[1], str(entry[1])),
            'event': entry[2] & 0xFFFF,
            'channel': entry[3],
            'header': entry[4] & 0xFF,
            'len': entry[5] & 0xFF,
            'a': entry[6],
            'b': entry[7],
        })
    return rows


def decode_refused_pdu(word):
    """Decode the first connection PDU the link layer refused (SEC_DIAG[63]).

    Packed as `1 | header << 8 | length << 16`; zero means every PDU was
    accepted. A refused PDU is never acknowledged, so a non-zero value names
    the frame the peer retransmits until supervision fails.
    """
    if not word:
        return None
    return {
        'header': f'0x{(word >> 8) & 0xFF:02x}',
        'llid': (word >> 8) & 3,
        'length': (word >> 16) & 0xFF,
    }


def decode_diag(words):
    """Turn the packed diagnostic rings into an ordered transcript."""
    rows = []
    for direction, seq_index, base in (('rx', 0, DIAG_RX_BASE), ('tx', 1, DIAG_TX_BASE)):
        for offset in range(DIAG_ENTRIES):
            entry = words[base + offset]
            if entry == 0:
                continue
            rows.append({
                'dir': direction,
                'seq': (entry >> 24) & 0xff,
                'llid': (entry >> 16) & 0xff,
                'cid': (entry >> 8) & 0xff,
                'opcode': entry & 0xff,
                'channel': DIAG_NAMES.get((entry >> 8) & 0xff, 'continuation'
                                          if (entry >> 8) & 0xff == 0xff else 'other'),
            })
    rows.sort(key=lambda row: (row['dir'] != 'rx', row['seq']))
    return {
        'rx_total': words[0],
        'tx_total': words[1],
        'host_disconnect_requests': words[DIAG_DISCONNECT_COUNT],
        'last_host_disconnect_reason': words[DIAG_DISCONNECT_REASON],
        'entries': rows,
    }


def validate_observation_buffers(image, symbols, extra=()):
    """Check the shared observation buffers, plus `extra` fixture buffers.

    `extra` is opt-in so examples that share this validator without the X4
    GATT fixture (HID, bond store) do not have to define `X4_STATS`.
    """
    sections = p4.p3.elf_sections(image)
    ranges = []
    buffers = (('STATS', 64), ('HOST_STATS', 16), ('SECURE_STATS', 16),
               ('SEC_DIAG', 64), ('SEC_OPCODES', 96), ('HOST_ERROR', 32),
               ('BOND_STATS', 32), ('BOND_ECHO', 16),
               ('PERIPHERAL_ADDRESS', 2),
               ('TRACE', 128 * 8)) + tuple(extra)
    for name, count in buffers:
        address, size = symbols[name], count * 4
        if (address % 4 or not 0x20000000 <= address < address + size <= 0x30000000
                or not any(section['flags'] & 3 == 3 and section['address'] <= address
                           and address + size <= section['address'] + section['size']
                           for section in sections)):
            raise ValueError(f'{name} is not an aligned writable RAM observation buffer')
        if any(address < end and start < address + size for start, end in ranges):
            raise ValueError(f'{name} overlaps another observation buffer')
        ranges.append((address, address + size))
    return symbols


def flash(elf, out, prefix, timeout=240):
    """Single retained preflight session. The secure image is ~280 KiB of
    text, so program+verify needs well over the helper's 40 s default."""
    io.command([str(io.PREFLIGHT), '--probe', '1a86:8010:F93D8F067E10', '--chip', 'CH585',
                '--protocol', 'jtag', '--verify', str(elf)],
               out / f'{prefix}-flash.log', timeout=timeout)


def adb(serial, *args, timeout=30, check=True):
    return subprocess.run(['adb', '-s', serial, *args], capture_output=True, text=True,
                          timeout=timeout, check=check).stdout


def confirm_pairing_dialog(serial):
    """Confirm the system Just Works dialog on behalf of the user.

    This ROM rejects `BluetoothDevice.setPairingConfirmation` from an
    unprivileged app (BLUETOOTH_PRIVILEGED), so the only path is the system
    dialog. Tap it only when that dialog owns the focus; returns a record of
    the tap, or None when there is nothing to confirm.
    """
    try:
        focus = adb(serial, 'shell', 'dumpsys', 'window', timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if 'BluetoothPairingDialog' not in focus:
        return None
    try:
        adb(serial, 'shell', 'uiautomator', 'dump', ui_path, timeout=25)
        dump = adb(serial, 'shell', 'cat', ui_path, timeout=20)
        root = ElementTree.fromstring(dump)
    except (OSError, subprocess.SubprocessError, ElementTree.ParseError):
        return None
    for node in root.iter('node'):
        if node.get('resource-id') != 'android:id/button1' or not node.get('bounds'):
            continue
        x1, y1, x2, y2 = (int(value) for value in re.findall(r'\d+', node.get('bounds')))
        tap = [x // 2 for x in (x1 + x2, y1 + y2)]
        try:
            adb(serial, 'shell', 'input', 'tap', str(tap[0]), str(tap[1]), timeout=20)
        except (OSError, subprocess.SubprocessError):
            return None
        return {'action': 'confirm', 'button': node.get('text', ''), 'tap': tap}
    return None


def read_log(lines):
    rows = []
    for line in lines:
        index = line.find('WCHBLE')
        if index < 0:
            continue
        start, end = line.find('{', index), line.rfind('}')
        if start < 0 or end < start:
            continue
        try:
            row = json.loads(line[start:end + 1])
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def evaluate_att_transcript(rows):
    """App-side proof of MTU exchange, long read/write and burst delivery."""
    errors = []
    events = [row.get('event') for row in rows]
    summaries = [row for row in rows if row.get('event') == 'summary']
    if len(summaries) != 1:
        return [f'expected exactly one app summary, saw {len(summaries)}: {events}']
    summary = summaries[0]
    if summary.get('pass') is not True or summary.get('reason') != ATT_REASON:
        errors.append(f'app summary is not a pass: {summary}')
    if summary.get('bonded') is not True:
        errors.append('app summary did not observe a completed bond')
    required = ('scan_started', 'found', 'connecting', 'connection_state',
                'mtu_requested', 'mtu', 'services_discovered', 'att_start',
                'bulk_read', 'bulk_write_requested', 'bulk_write_ack',
                'bulk_verify', 'burst_cccd_requested', 'burst_cccd',
                'burst_requested', 'burst_command_ack')
    for required_event in required:
        if required_event not in events:
            errors.append(f'app transcript is missing {required_event}')
    mtu = next((row for row in rows if row.get('event') == 'mtu'), None)
    if mtu is None or mtu.get('status') != 0 or not (mtu.get('mtu') or 0) >= 60:
        errors.append(f'MTU exchange did not succeed above 60: {mtu}')
    first = next((row for row in rows if row.get('event') == 'bulk_read'), None)
    if first is None or first.get('status') != 0 or first.get('length') != BULK_LEN \
            or first.get('pattern_ok') is not True:
        errors.append(f'long read did not return the {BULK_LEN}-byte pattern: {first}')
    write = next((row for row in rows if row.get('event') == 'bulk_write_requested'), None)
    if write is None or write.get('ok') is not True or write.get('length') != BULK_LEN:
        errors.append(f'long write was not issued with {BULK_LEN} bytes: {write}')
    ack = [row for row in rows if row.get('event') == 'bulk_write_ack']
    if not ack or any(row.get('status') != 0 for row in ack):
        errors.append(f'long write was not acknowledged: {ack}')
    verify = next((row for row in rows if row.get('event') == 'bulk_verify'), None)
    if verify is None or verify.get('status') != 0 or verify.get('length') != BULK_LEN \
            or verify.get('match') is not True:
        errors.append(f'long write read-back does not match: {verify}')
    cccd = next((row for row in rows if row.get('event') == 'burst_cccd'), None)
    if cccd is None or cccd.get('status') != 0:
        errors.append(f'burst CCCD write failed: {cccd}')
    command = next((row for row in rows if row.get('event') == 'burst_command_ack'), None)
    if command is None or command.get('status') != 0:
        errors.append(f'burst command was not acknowledged: {command}')
    notifications = [row for row in rows if row.get('event') == 'burst_notification']
    if not notifications:
        errors.append('no burst notification reached the app')
    for row in notifications:
        if row.get('length') != BURST_LEN or row.get('pattern_ok') is not True:
            errors.append(f'burst notification is not a {BURST_LEN}-byte pattern row: {row}')
    if summary.get('notifications') != len(notifications):
        errors.append('summary notification count disagrees with the logged rows')
    return errors


def evaluate_x1(x1, require_dle=False):
    """Firmware-side X1 proof: CSA #2 selection and bidirectional DLE."""
    if len(x1) != 24 or x1[0] != X1_MAGIC or x1[1] != 1:
        return [f'invalid X1_STATS: {x1[:2]}']
    word = dict(zip(X1_NAMES, x1))
    errors = []
    algorithm, adv, init = word['algorithm'], word['adv_chsel'], word['init_chsel']
    if algorithm not in (1, 2):
        errors.append(f"unknown channel selection algorithm {algorithm}")
    elif algorithm == 2 and not (adv and init):
        errors.append(f"CSA#2 selected with adv_chsel={adv} init_chsel={init}")
    elif algorithm == 1 and adv and init:
        errors.append('both ChSel bits set but CSA#1 selected')
    for name in ('tx_octets', 'rx_octets'):
        if not 27 <= word[name] <= 251:
            errors.append(f"{name}={word[name]} outside 27..=251")
    for name in ('tx_time', 'rx_time'):
        if not 328 <= word[name] <= 2120:
            errors.append(f"{name}={word[name]} outside 328..=2120 us")
    if word['max_tx_pdu'] > 251 or word['max_rx_pdu'] > 251:
        errors.append(f"on-air PDU exceeds 251 octets: {word['max_tx_pdu']}/{word['max_rx_pdu']}")
    if word['last_error']:
        errors.append(f"X1 last_error=0x{word['last_error']:02x}")
    if require_dle:
        if not word['feature_exchange']:
            errors.append('peer feature set was never observed')
        if word['tx_over_27'] < 1:
            errors.append('no transmitted PDU above the legacy 27 octets')
        if word['rx_over_27'] < 1:
            errors.append('no received PDU above the legacy 27 octets')
        if word['host_packets_segmented'] < 1:
            errors.append('no Host ACL packet needed more than one LL fragment')
    return errors


def evaluate_att(x4, opcodes, delivered, refused=0):
    """Firmware-side proof: negotiated MTU, Blob/Prepare/Execute and the burst."""
    errors = []
    if len(x4) != 16 or x4[0] != X4_MAGIC or x4[1] != 1:
        return [f'invalid X4_STATS: {x4[:2]}']
    sample = decode_refused_pdu(refused)
    if sample is not None:
        # A refused PDU is never acknowledged, so the peer keeps
        # retransmitting it until supervision fails.
        errors.append(f'link layer refused an on-air PDU: {sample}')
    word = dict(zip(X4_NAMES, x4))
    if word['mtu'] < 60:
        errors.append(f"negotiated ATT MTU={word['mtu']} is not above 60")
    if word['bulk_reads'] < 2:
        errors.append(f"long read used {word['bulk_reads']} ATT reads, expected at least 2")
    if word['bulk_writes'] != 1:
        errors.append(f"long write produced {word['bulk_writes']} write events, expected 1")
    if word['bulk_len'] != BULK_LEN:
        errors.append(f"stored bulk length {word['bulk_len']}, expected {BULK_LEN}")
    if word['bulk_sum'] != BULK_WRITE_SUM:
        errors.append(f"stored bulk checksum {word['bulk_sum']}, expected {BULK_WRITE_SUM}")
    if word['bulk_match'] != 1:
        errors.append('stored bulk value does not match the write pattern')
    if word['burst_runs'] != 1:
        errors.append(f"burst ran {word['burst_runs']} times, expected 1")
    if word['burst_attempts'] != BURST_ATTEMPTS:
        errors.append(f"burst attempted {word['burst_attempts']} notifications, expected {BURST_ATTEMPTS}")
    if word['burst_sent'] < 1:
        errors.append('burst queued no notification')
    if word['burst_queue_full'] < 1:
        errors.append('burst never observed a full notification queue')
    if word['burst_len'] != BURST_LEN:
        errors.append(f"burst payload length {word['burst_len']}, expected {BURST_LEN}")
    if word['last_error']:
        errors.append(f"X4 last_error=0x{word['last_error']:02x}")
    queued = word['burst_sent']
    if delivered != queued:
        errors.append(f'app received {delivered} burst notifications, Host queued {queued}')
    att = opcodes.get('att', {})
    rx, tx = att.get('rx', {}), att.get('tx', {})
    for name, direction in (('MtuReq', rx), ('MtuRsp', tx), ('ReadReq', rx),
                            ('ReadBlobReq', rx), ('ReadBlobRsp', tx),
                            ('PrepareWriteReq', rx), ('PrepareWriteRsp', tx),
                            ('ExecuteWriteReq', rx), ('ExecuteWriteRsp', tx)):
        if direction.get(name, 0) < 1:
            errors.append(f'no {name} on air')
    if tx.get('Notification', 0) < 1:
        errors.append('no notification on air')
    elif tx.get('Notification', 0) > word['burst_sent']:
        errors.append('more notifications on air than the Host queued')
    return errors


def evaluate_transcript(rows, mode='pair'):
    if mode == 'att':
        return evaluate_att_transcript(rows)
    errors = []
    events = [row.get('event') for row in rows]
    summaries = [row for row in rows if row.get('event') == 'summary']
    if len(summaries) != 1:
        return [f'expected exactly one app summary, saw {len(summaries)}: {events}']
    summary = summaries[0]
    if summary.get('pass') is not True or summary.get('reason') != SUMMARY_REASONS[mode]:
        errors.append(f'app summary is not a pass: {summary}')
    # A reused bond has no BOND_BONDED broadcast; the Host counters prove the
    # session resumed the stored key instead.
    already_bonded = 'already_bonded' in events
    if mode in ('pair', 'reconnect') and summary.get('bonded') is not True:
        errors.append('app summary did not observe a completed bond')
    if mode == 'wipe':
        required = ('scan_started', 'found', 'connecting', 'connection_state',
                    'services_discovered', 'control_start', 'write_ack')
    elif mode in ('pair', 'reconnect'):
        required = ('scan_started', 'found', 'connecting', 'connection_state',
                    'services_discovered', 'encrypted_gatt_start', 'read',
                    'write_requested', 'write_ack')
        if mode == 'pair' and not already_bonded:
            required += ('bond_requested', 'bond_state')
    else:
        required = ('scan_started', 'found', 'connecting', 'connection_state',
                    'services_discovered', 'encrypted_gatt_start', 'read',
                    'control_write', 'write_ack')
    for required_event in required:
        if required_event not in events:
            errors.append(f'app transcript is missing {required_event}')
    if mode == 'pair' and not already_bonded:
        bond_states = [row.get('state') for row in rows if row.get('event') == 'bond_state']
        if 12 not in bond_states:  # BOND_BONDED
            errors.append(f'bond state never reached BOND_BONDED: {bond_states}')
    if mode in ('pair', 'reconnect'):
        reads = [row for row in rows if row.get('event') == 'read' and row.get('status') == 0]
        if not reads or reads[0].get('value') != 0:
            errors.append(f'first encrypted read did not return the initial value 0: {reads[:1]}')
        if len(reads) < 2 or reads[-1].get('value') != 43:
            errors.append(f'read-back after write did not return 43: {reads}')
    writes = [row for row in rows if row.get('event') == 'write_ack' and row.get('status') == 0]
    if not writes:
        errors.append('no successful ATT write response')
    return errors


def evaluate_rejection(rows):
    """Same app flow as `reconnect`, but the board no longer holds the key."""
    errors = []
    summaries = [row for row in rows if row.get('event') == 'summary']
    if len(summaries) != 1:
        return [f'expected exactly one app summary, saw {len(summaries)}']
    app = summaries[0]
    if app.get('pass') is not False:
        errors.append(f'the reconnect unexpectedly succeeded: {app}')
    if app.get('reason') not in ('read_failed', 'disconnected', 'reconnect_not_bonded'):
        errors.append(f'unexpected rejection reason: {app.get("reason")}')
    return errors


def evaluate_rejected_link(sec, host):
    """Firmware-side proof that the controller refused the deleted key."""
    errors = []
    if len(sec) != 16 or sec[0] != SEC_MAGIC:
        return ['invalid SECURE_STATS']
    ltk, start, active = (SEC_NAMES.index(name) for name in
                          ('ltk_request', 'start_req', 'active'))
    if sec[ltk] < 1:
        errors.append('the controller never asked for the deleted LTK')
    if sec[start] != 0:
        errors.append(f'encryption started after deletion: start_req={sec[start]}')
    if sec[SEC_NAMES.index("last_error")] != 0x06:
        errors.append(f'expected LL_REJECT_IND 0x06, last_error={sec[SEC_NAMES.index("last_error")]}')
    if sec[active] != 0:
        errors.append('the run reports an active encrypted link')
    if len(host) == 16 and host[15] == SECURITY_ENCRYPTED:
        errors.append('the Host still reports an encrypted link')
    return errors


def decode_bond_echo(words):
    """Key material the Host last stored, for comparison with the flash dump."""
    if not words or words[0] != 0x4F48_4345:
        return {'present': False}
    address = words[2].to_bytes(4, 'big') + bytes([words[3] >> 24, (words[3] >> 16) & 0xFF])
    ltk = b''.join(word.to_bytes(4, 'little') for word in words[4:8])
    local = words[9].to_bytes(4, 'big') + bytes([words[10] >> 24, (words[10] >> 16) & 0xFF])
    return {
        'present': True,
        'count': words[1],
        'address': ':'.join(f'{byte:02x}' for byte in address),
        'address_kind': (words[3] >> 8) & 0xFF,
        'is_bonded': bool(words[3] & 0xFF),
        'ltk': ltk.hex(),
        'security_level': (words[8] >> 8) & 0xFF,
        'has_irk': bool((words[8] >> 16) & 1),
        'key_len': (words[8] >> 24) & 0xFF,
        'local_address': ':'.join(f'{byte:02x}' for byte in local),
        'local_address_kind': (words[10] >> 8) & 0xFF,
        'local_present': bool(words[10] & 0xFF),
    }


def evaluate_security(sec, host, stats, run_seconds):
    errors = []
    if len(sec) != 16:
        return ['invalid SECURE_STATS size']
    if sec[0] != SEC_MAGIC or sec[1] & 0xff != 1:
        return [f'SECURE_STATS magic/version wrong: {sec[:2]}']
    flags = sec[1]
    if not flags & (1 << 8):
        errors.append('firmware did not pass the ADC entropy health check')
    if not flags & (1 << 9):
        errors.append('Host crypto RNG was not seeded')
    if not flags & (1 << 10):
        errors.append('controller DRBG was not seeded')
    minimum = {2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 8: 2, 9: 2}
    for index, count in minimum.items():
        if sec[index] < count:
            errors.append(f'{SEC_NAMES[index]}={sec[index]} < {count}')
    if sec[10] != 1:
        errors.append(f'encryption became active {sec[10]} times, expected 1')
    if sec[11]:
        errors.append(f'MIC failures: {sec[11]}')
    if sec[12]:
        errors.append(f'encryption errors: {sec[12]} (last 0x{sec[15]:02x})')
    if sec[14]:
        errors.append(f'plaintext START_ENC_REQ retransmissions: {sec[14]}')
    if len(host) != 16:
        errors.append('invalid HOST_STATS size')
    elif host[15] != SECURITY_ENCRYPTED:
        errors.append(f'Host security state={host[15]}, expected encrypted ({SECURITY_ENCRYPTED})')
    errors.extend(evaluate_finite_run(stats, run_seconds))
    return errors


def evaluate_finite_run(stats, run_seconds):
    """Gates that apply to every mode, encrypted or not."""
    errors = []
    if len(stats) == 64:
        if stats[:3] != [0x5034_3538, 1, 9]:
            errors.append(f'firmware did not finish: magic/version/stage={stats[:3]}')
        if stats[33] & 3 or stats[34] != 0x30000 or stats[22]:
            errors.append('RF stop was not clean (CMD/MODE/stop_err)')
        if not (run_seconds * 1_000_000 <= stats[32] <= (run_seconds + 3) * 1_000_000):
            errors.append('firmware runtime does not match the finite-run budget')
        if stats[14] != 1 or stats[15] != 1:
            errors.append(f'expected one connected link with data: {stats[14:16]}')
    else:
        errors.append('invalid STATS size')
    return errors


def execute(args):
    args.out.mkdir(parents=True, exist_ok=False)
    errors, metadata = [], {
        'probe': PROBE, 'scope': 'S2/S3 Just Works + encrypted GATT',
        'mode': args.mode,
        'run_seconds': args.run_seconds, 'timeout': args.timeout,
        'air_ifs': 'UNMEASURED', 'mitm': 'not protected (Just Works)',
    }
    touched, safe_read_at, symbols = False, 0.0, None
    log = None
    try:
        archived, smoke = args.out / 'firmware.elf', args.out / 'smoke.elf'
        shutil.copyfile(args.elf, archived)
        shutil.copyfile(args.smoke_elf, smoke)
        image = archived.read_bytes()
        metadata['elf_sha256'] = hashlib.sha256(image).hexdigest()
        metadata['smoke_sha256'] = hashlib.sha256(smoke.read_bytes()).hexdigest()
        nm_text = io.command([args.nm, str(archived)], args.out / 'symbols.txt')
        symbols = p4.symbols_from(nm_text)
        for name in ('HOST_STATS', 'SECURE_STATS', 'SEC_DIAG', 'SEC_OPCODES', 'HOST_ERROR',
                     'BOND_STATS', 'BOND_ECHO', 'X4_STATS', 'X1_STATS',
                     'PERIPHERAL_ADDRESS'):
            matches = [parts for line in nm_text.splitlines()
                       if len(parts := line.split()) == 3 and parts[2] == name]
            if len(matches) != 1:
                raise ValueError(f'missing or ambiguous {name} symbol')
            symbols[name] = int(matches[0][0], 16)
        symbols = validate_observation_buffers(
            image, symbols, extra=(('X4_STATS', 16), ('X1_STATS', 24)))
        # Both feature sets write the same output path, so a plain `cargo
        # build` right after a secure build silently replaces this image.
        # Refuse to spend a probe session on a Host without the crypto backend.
        if '_embassy_crypto_aes128ecb_encrypt_blocks' not in nm_text:
            raise ValueError('ELF was not built with --features secure (no crypto backend)')
        metadata['symbols'] = symbols
        metadata['ram_layout'] = p4.validate_ram_layout(image, symbols)
        embedded_seconds = p4.embedded_u32(image, symbols['RUN_SECONDS'])
        metadata['embedded_run_seconds'] = embedded_seconds
        if embedded_seconds != args.run_seconds:
            raise ValueError(f'ELF RUN_SECONDS={embedded_seconds}, requested {args.run_seconds}')

        if args.build_apk:
            io.command([str(APK.parent.parent / 'build.sh')], args.out / 'apk-build.log', timeout=180)
        if not APK.is_file():
            raise ValueError(f'missing APK: {APK}')
        metadata['apk_sha256'] = hashlib.sha256(APK.read_bytes()).hexdigest()
        metadata['adb_serial'] = args.serial
        adb(args.serial, 'get-state')
        adb(args.serial, 'install', '-g', '-r', str(APK), timeout=120)

        touched = True
        try:
            # One retained probe session: halt, engine shutdown, idle checks,
            # verified download.
            flash(archived, args.out, 'test')
        finally:
            safe_read_at = time.monotonic() + embedded_seconds + 3

        adb(args.serial, 'logcat', '-c')
        # Android 15 blocks BLE scans for a backgrounded/dozing app; keep the
        # activity foregrounded and the screen on for the whole finite run.
        adb(args.serial, 'shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
        adb(args.serial, 'shell', 'wm', 'dismiss-keyguard')
        adb(args.serial, 'shell', 'svc', 'power', 'stayon', 'true')
        adb(args.serial, 'shell', 'am', 'force-stop', PACKAGE)
        # The sniffer follows by advertised name, so it can only attach once the
        # firmware is up: the finite image advertises from boot, which is
        # already true here (flash completed above). The capture wrapper uses
        # this hook to start listening before the phone connects.
        hook = getattr(args, 'capture_hook', None)
        if hook is not None:
            hook.before_app(args)
        adb(args.serial, 'shell', 'am', 'start', '-W', '-n', ACTIVITY,
            '--es', 'mode', args.mode)
        deadline = time.monotonic() + args.timeout
        metadata['pairing_consent'] = []
        while time.monotonic() < deadline:
            # `pidof` exits 1 once the app is gone; that is the success signal,
            # so this call must not be checked.
            pid = adb(args.serial, 'shell', 'pidof', PACKAGE, check=False).strip()
            if not pid:
                break
            confirmed = confirm_pairing_dialog(args.serial)
            if confirmed is not None:
                metadata['pairing_consent'].append(confirmed)
                print('CONSENT', json.dumps(confirmed), flush=True)
            time.sleep(0.5)
        else:
            errors.append('phone app did not finish within its timeout')
        log_path = args.out / 'logcat.txt'
        log_path.write_text(adb(args.serial, 'logcat', '-d', '-s', 'WCHBLE:I', timeout=60))
        if args.full_logcat:
            # The Bluetooth stack's own SMP/encryption diagnostics are the only
            # view of the phone's side; they are not on the WCHBLE tag.
            (args.out / 'logcat-all.txt').write_text(
                adb(args.serial, 'logcat', '-d', '-b', 'all', timeout=120))
        rows = read_log(log_path.read_text().splitlines())
        (args.out / 'transcript.jsonl').write_text(
            '\n'.join(json.dumps(row, sort_keys=True) for row in rows) + '\n')
        metadata['client_summary'] = next(
            (row for row in reversed(rows) if row.get('event') == 'summary'), None)
        if args.reject:
            errors.extend(evaluate_rejection(rows))
        else:
            errors.extend(evaluate_transcript(rows, args.mode))

        p4.wait_until(safe_read_at)
        observations = {}
        for name, count, names in (('STATS', 64, STAT_NAMES),
                                   ('HOST_STATS', 16, HOST_NAMES),
                                   ('SECURE_STATS', 16, SEC_NAMES)):
            words = io.read32(symbols[name], count, args.out / f'{name.lower()}.txt')
            observations[name] = words
            metadata[name.lower()] = dict(zip(names, words))
            (args.out / f'{name.lower()}.json').write_text(
                json.dumps(metadata[name.lower()], indent=2) + '\n')
        if args.reject:
            errors.extend(evaluate_rejected_link(observations.get('SECURE_STATS', []),
                                                 observations.get('HOST_STATS', [])))
        elif args.mode == 'wipe':
            # The wipe phase deliberately talks to the control characteristic
            # before any bond exists, so only the finite-run gates apply.
            errors.extend(evaluate_finite_run(observations.get('STATS', []),
                                              args.run_seconds))
        else:
            errors.extend(evaluate_security(observations.get('SECURE_STATS', []),
                                            observations.get('HOST_STATS', []),
                                            observations.get('STATS', []),
                                            args.run_seconds))
        bond_words = io.read32(symbols['BOND_STATS'], 32, args.out / 'bond_stats.txt')
        metadata['bond_stats'] = dict(zip(BOND_NAMES, bond_words))
        echo_words = io.read32(symbols['BOND_ECHO'], 16, args.out / 'bond_echo.txt')
        metadata['bond_echo'] = decode_bond_echo(echo_words)
        (args.out / 'bond_stats.json').write_text(
            json.dumps({'stats': metadata['bond_stats'], 'echo': metadata['bond_echo']},
                       indent=2) + '\n')
        diag_words = io.read32(symbols['SEC_DIAG'], 64, args.out / 'sec_diag.txt')
        metadata['sec_diag'] = decode_diag(diag_words)
        metadata['sec_diag'].update({
            'rx_oversize': diag_words[59],
            'rx_max_frame': diag_words[60],
            'll_control_mask': f'0x{diag_words[61]:04x}',
            'll_control_last': f'0x{diag_words[62]:02x}',
            'refused_pdu': decode_refused_pdu(diag_words[63]),
        })
        if diag_words[40]:
            metadata['sec_diag']['last_hci_failure'] = {
                'opcode': f'0x{diag_words[40] >> 8:04x}',
                'status': f'0x{diag_words[40] & 0xFF:02x}',
            }
        metadata['sec_diag']['hci_log_len'] = diag_words[49]
        metadata['sec_diag']['hci_log'] = [
            {'opcode': f'0x{word >> 8:04x}', 'status': f'0x{word & 0xFF:02x}'}
            for word in diag_words[41:49] if word]
        metadata['sec_diag']['hci_sent_len'] = diag_words[58]
        metadata['sec_diag']['hci_sent'] = [
            {'kind': 'complete' if word >> 28 == 0xE else 'status',
             'opcode': f'0x{(word >> 8) & 0xFFFF:04x}',
             'status': f'0x{word & 0xFF:02x}'}
            for word in diag_words[50:58] if word]
        (args.out / 'sec_diag.json').write_text(
            json.dumps(metadata['sec_diag'], indent=2) + '\n')
        x4_words = io.read32(symbols['X4_STATS'], 16, args.out / 'x4_stats.txt')
        metadata['x4_stats'] = dict(zip(X4_NAMES, x4_words))
        (args.out / 'x4_stats.json').write_text(
            json.dumps(metadata['x4_stats'], indent=2) + '\n')
        x1_words = io.read32(symbols['X1_STATS'], 24, args.out / 'x1_stats.txt')
        metadata['x1_stats'] = dict(zip(X1_NAMES, x1_words))
        (args.out / 'x1_stats.json').write_text(
            json.dumps(metadata['x1_stats'], indent=2) + '\n')
        opcode_words = io.read32(symbols['SEC_OPCODES'], 96, args.out / 'sec_opcodes.txt')
        metadata['sec_opcodes'] = decode_opcodes(opcode_words)
        metadata['sec_opcodes']['slow_polls_over_100ms'] = diag_words[36]
        metadata['sec_opcodes']['skipped_events'] = diag_words[37]
        metadata['sec_opcodes']['start_req_queued'] = diag_words[38]
        metadata['sec_opcodes']['start_rsp_queued'] = diag_words[39]
        # LSO-first static random address. S3 keeps it fixed so a bonded peer
        # can find the bond it saved on an earlier boot.
        address_words = io.read32(symbols['PERIPHERAL_ADDRESS'], 2,
                                  args.out / 'address.txt')
        address = bytes(byte for word in address_words
                        for byte in word.to_bytes(4, 'little'))[:6]
        metadata['peripheral_address'] = ':'.join(f'{byte:02x}' for byte in reversed(address))
        error_words = io.read32(symbols['HOST_ERROR'], 32, args.out / 'host_error.txt')
        length = min(error_words[0], (len(error_words) - 1) * 4)
        metadata['host_error'] = bytes(
            byte for word in error_words[1:] for byte in word.to_bytes(4, 'little')
        )[:length].decode('utf-8', 'replace')
        if metadata['host_error']:
            errors.append(f'Host runner stopped: {metadata["host_error"]}')
        (args.out / 'sec_opcodes.json').write_text(
            json.dumps(metadata['sec_opcodes'], indent=2) + '\n')
        trace_rows = decode_trace(
            io.read32(symbols['TRACE'], 128 * 8, args.out / 'trace.txt'),
            observations.get('STATS', [0] * 64)[39] if observations.get('STATS') else 0)
        metadata['trace'] = trace_rows
        (args.out / 'trace.json').write_text(json.dumps(trace_rows, indent=2) + '\n')
        print('SMP', json.dumps(metadata['sec_opcodes']['smp'], sort_keys=True))
        print('ATT', json.dumps(metadata['sec_opcodes']['att'], sort_keys=True))
        errors.extend(evaluate_x1(x1_words, args.require_dle))
        if args.mode == 'att':
            delivered = sum(1 for row in rows if row.get('event') == 'burst_notification')
            errors.extend(evaluate_att(x4_words, metadata['sec_opcodes'], delivered,
                                       diag_words[63]))

        try:
            flash(smoke, args.out, 'restore')
            io.command(['swift', str(io.SCANNER), 'wch585', '8'],
                       args.out / 'restore-scan.log', 20)
            metadata['smoke_recovery'] = 'flash verify and exact-name macOS discovery PASS'
        except FAILURES as error:
            errors.append(f'recovery: {error}')
            metadata['smoke_recovery'] = 'NOT VERIFIED'
    except FAILURES as error:
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        if log is not None:
            log.close()
        metadata['errors'], metadata['passed'] = errors, not errors
        metadata['smoke_recovery'] = metadata.get('smoke_recovery',
                                                   'NOT ATTEMPTED' if not touched else 'NOT VERIFIED')
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
    parser.add_argument('--serial', default=ADB_SERIAL)
    parser.add_argument('--run-seconds', type=int, default=25)
    parser.add_argument('--timeout', type=float, default=45)
    parser.add_argument('--mode', choices=tuple(SUMMARY_REASONS), default='pair',
                        help='app phase: pair, reconnect, delete, wipe, fault or att')
    parser.add_argument('--require-dle', action='store_true',
                        help='require observed >27-byte PDUs and a fragmented Host packet')
    parser.add_argument('--reject', action='store_true',
                        help='expect the reconnect to be refused after a delete')
    parser.add_argument('--build-apk', action='store_true')
    parser.add_argument('--full-logcat', action='store_true')
    args = parser.parse_args(argv)
    if not (math.isfinite(args.timeout) and 0 < args.timeout <= args.run_seconds):
        parser.error('require finite timeout <= run-seconds')
    if args.reject and args.mode == 'att':
        parser.error('--reject is meaningless for the att phase')
    args.out, args.elf, args.smoke_elf = (args.out.resolve(), args.elf.resolve(),
                                          args.smoke_elf.resolve())
    return args


if __name__ == '__main__':
    sys.exit(execute(options()))
