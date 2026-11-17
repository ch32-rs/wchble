#!/usr/bin/env python3
"""Hash-bound build manifest for CH585 acceptance images.

Capture the exact recipe (tree, path inputs, toolchain, features, ELF) after a
build, then verify an archived ELF against it before any probe access.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
NM = '/opt/homebrew/opt/llvm/bin/llvm-nm'
OBJDUMP = '/opt/homebrew/opt/llvm/bin/llvm-objdump'
SCHEMA = 2

ROLE_SYMBOLS = {
    'peripheral': ('STATS', 'TRACE', 'RUN_SECONDS'),
    'central': ('STATS', 'TRACE', 'RUN_SECONDS'),
    'secure': ('STATS', 'SECURE_STATS', 'BOND_STATS', 'RUN_SECONDS'),
    'hid': ('STATS', 'SECURE_STATS', 'HID_STATS', 'RUN_SECONDS'),
}
# Demangled item names of the RAM-resident entry points. The RX/response roots
# are separate highcode functions, not necessarily inlined into `main`.
ROLE_ROOTS = {
    'peripheral': ('run_connection', 'receive', 'transmit', 'main'),
    'central': ('main', 'connection_event', 'start_connection', 'receive_scan',
                'receive_response'),
    'secure': ('main', 'receive', 'transmit'),
    'hid': ('main', 'receive', 'transmit'),
}
# Radio/LL entry points a reviewer expects on the RX/TX hot path. `None` means
# no standalone symbol: read the root's disassembly for inlining or aliasing.
HOT_SYMBOLS = ('rx_basic', 'tx_basic', 'rx_stop', 'tx_stop', 'program_channel_bb',
               'set_channel', 'set_aa_crc', 'note_anchor_us', 'bb_isr',
               'on_rx_anchor', 'on_rx_anchor_crc')
REQUIRED_PATH_INPUTS = {
    'peripheral': ('ch5xx-hal',),
    'central': ('ch5xx-hal', 'trouble'),
    'secure': ('ch5xx-hal', 'trouble'),
    'hid': ('ch5xx-hal', 'trouble'),
}
CONTROL = {'jal', 'jalr', 'call', 'tail', 'j', 'jr', 'c.j', 'c.jal', 'c.jr', 'c.jalr',
           'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu', 'c.beqz', 'c.bnez'}
INDIRECT = {'jalr', 'jr', 'c.jr', 'c.jalr', 'tail'}


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256(path):
    return sha256_bytes(Path(path).read_bytes())


def report_digest(report):
    return sha256_bytes(json.dumps(report, sort_keys=True, separators=(',', ':')).encode())


def command(args, timeout=120):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f'{Path(args[0]).name} failed: {result.stderr.strip()}')
    return result.stdout


def tree_state(root):
    """Staged, unstaged, and untracked inputs relative to HEAD."""
    def git(*args):
        return command(['git', '-C', str(root), *args])

    head = git('rev-parse', 'HEAD').strip()
    staged = git('diff', '--cached', '--binary')
    unstaged = git('diff', '--binary')
    untracked = sorted(git('ls-files', '--others', '--exclude-standard').split())
    digest = hashlib.sha256()
    digest.update(staged.encode())
    digest.update(unstaged.encode())
    content = hashlib.sha256()
    for name in untracked:
        digest.update(b'=== ' + name.encode() + b'\n')
        path = root / name
        if path.is_file():
            data = path.read_bytes()
            digest.update(data)
            content.update(name.encode() + b'\0' + data)
    return {'head': head,
            'staged_sha256': sha256_bytes(staged.encode()),
            'unstaged_sha256': sha256_bytes(unstaged.encode()),
            'untracked_names_sha256': sha256_bytes('\n'.join(untracked).encode()),
            'untracked_content_sha256': content.hexdigest(),
            'digest': digest.hexdigest(),
            'dirty': bool(staged or unstaged or untracked)}


def external_path_inputs(example):
    """Sibling repositories referenced by the example's Cargo.toml."""
    names = set()
    for line in (example / 'Cargo.toml').read_text().splitlines():
        match = re.search(r'path\s*=\s*"\.\./\.\./\.\./([A-Za-z0-9_-]+)', line)
        if match:
            names.add(match.group(1))
    if not names:
        raise RuntimeError(f'{example} declares no external path inputs')
    return sorted(names)


def linker_version():
    """rust-lld or ld.lld path and version, when one is reachable."""
    candidates = []
    try:
        sysroot = command(['rustc', '--print', 'sysroot']).strip()
        host = next((line.split(':', 1)[1].strip()
                     for line in command(['rustc', '-vV']).splitlines()
                     if line.startswith('host:')), '')
        if host:
            candidates.append(Path(sysroot) / 'lib/rustlib' / host / 'bin/rust-lld')
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        pass
    for path in ('/opt/homebrew/opt/llvm/bin/ld.lld', '/usr/bin/ld.lld'):
        candidates.append(Path(path))
    for path in candidates:
        if not path.exists():
            continue
        commands = [[str(path), '--version']]
        if path.name == 'rust-lld':
            commands.insert(0, [str(path), '-flavor', 'gnu', '--version'])
        for argv in commands:
            try:
                version = command(argv).splitlines()[0].strip()
            except (OSError, RuntimeError, subprocess.TimeoutExpired, IndexError):
                continue
            return {'path': str(path), 'version': version}
    return {'path': None, 'version': 'UNKNOWN'}


def write_snapshot(out_dir, sources):
    """Recoverable tar.gz of each source's HEAD, binary diff, and untracked files."""
    import io
    import tarfile
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data, digest = {}, hashlib.sha256()
    for name, root in sources:
        head = command(['git', '-C', str(root), 'rev-parse', 'HEAD']).strip()
        patch = command(['git', '-C', str(root), 'diff', 'HEAD', '--binary'])
        untracked = sorted(command(['git', '-C', str(root), 'ls-files', '--others',
                                    '--exclude-standard']).split())
        data[f'{name}/tracked.patch'] = patch.encode()
        data[f'{name}/HEAD'] = (head + '\n').encode()
        digest.update(name.encode() + head.encode() + patch.encode())
        for item in untracked:
            path = root / item
            if path.is_file():
                content = path.read_bytes()
                data[f'{name}/untracked/{item}'] = content
                digest.update(item.encode() + content)
    path = out_dir / f'sources-{digest.hexdigest()[:12]}.tar.gz'
    import gzip
    with open(path, 'wb') as raw, \
            gzip.GzipFile(filename='', mtime=0, fileobj=raw, mode='wb') as gz, \
            tarfile.open(fileobj=gz, mode='w') as tar:
        for key in sorted(data):
            info = tarfile.TarInfo(key)
            info.size, info.mtime, info.mode = len(data[key]), 0, 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            tar.addfile(info, io.BytesIO(data[key]))
    return path


def nm_symbols(elf, nm=NM, demangle=True):
    """Demangled or mangled symbol name -> (address, size) for defined symbols."""
    args = [nm, '-S'] + (['-C'] if demangle else []) + ['--defined-only', str(elf)]
    symbols = {}
    for line in command(args).splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue
        try:
            address, size = int(parts[0], 16), int(parts[1], 16)
        except ValueError:
            continue
        name = parts[3] if len(parts) == 4 else parts[2]
        symbols.setdefault(name, (address, size))
    return symbols


def find_symbol(symbols, needle):
    # Legacy mangling keeps a ::h<hex> suffix after llvm-nm -C.
    pattern = re.compile(r'(^|::)' + re.escape(needle) + r'(::h[0-9a-f]+)?$')
    for name, (address, size) in symbols.items():
        if pattern.search(name):
            return name, address, size
    return None


def sections(elf, objdump=OBJDUMP):
    """Section name -> {vma, lma, size, type} from llvm-objdump -h."""
    table = {}
    pattern = re.compile(r'^\s*\d+\s+(\S+)\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+'
                         r'([0-9a-f]{8})\s+(\S*)\s*$')
    for line in command([objdump, '-h', str(elf)]).splitlines():
        match = pattern.match(line)
        if match:
            name, size, vma, lma, kind = match.groups()
            table[name] = {'size': int(size, 16), 'vma': int(vma, 16),
                           'lma': int(lma, 16), 'type': kind}
    return table


def highcode_range(symbols):
    start = symbols.get('_highcode_vma_start')
    end = symbols.get('_highcode_vma_end')
    if not start or not end or not (0x20000000 <= start[0] < end[0]):
        raise RuntimeError('invalid highcode range symbols')
    return start[0], end[0]


def instruction_lines(elf, address, size, objdump=OBJDUMP):
    """(call site, mnemonic, target symbol or None) for control-flow instructions."""
    text = command([objdump, '-d', f'--start-address={address}',
                    f'--stop-address={address + size}', str(elf)])
    pattern = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f]+)\s+(\S+)\s*(.*)$')
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        mnemonic = match.group(3)
        if mnemonic not in CONTROL:
            continue
        target = re.search(r'<([^>]+)>', match.group(4))
        yield int(match.group(1), 16), mnemonic, (target.group(1) if target else None)


def call_report(elf, roots, table, start, end, depth=6):
    """Per-root chains from a RAM root through shared helpers to Flash callees."""
    cache = {}

    def edges(address, size):
        if (address, size) not in cache:
            cache[(address, size)] = list(instruction_lines(elf, address, size))
        return cache[(address, size)]

    report, coverage = {}, {}
    for root in roots:
        seen, queue = {}, [(root['name'], root['address'], root['size'], [root['name']])]
        unresolved, unknown, depth_limited = 0, 0, False
        while queue:
            name, address, size, chain = queue.pop(0)
            if not size or (address, size) in seen:
                continue
            seen[(address, size)] = chain
            for site, mnemonic, target in edges(address, size):
                if target is None:
                    if mnemonic in INDIRECT:
                        unresolved += 1
                    continue
                hit = table.get(target)
                if not hit:
                    unknown += 1
                    continue
                if start <= hit[0] < end:
                    if len(chain) >= depth:
                        depth_limited = True
                        continue
                    queue.append((target, hit[0], hit[1], chain + [target]))
                else:
                    report[(root['name'], site, target)] = {
                        'root': root['name'], 'chain': chain + [target],
                        'call_site': site, 'mnemonic': mnemonic,
                        'target': target, 'target_address': hit[0]}
        coverage[root['name']] = {'functions': len(seen), 'depth_limited': depth_limited,
                                  'unresolved_indirect': unresolved,
                                  'unknown_targets': unknown}
    return [report[key] for key in sorted(report)], coverage


def capture(args):
    example = Path(args.example).resolve()
    elf = Path(args.elf).resolve()
    symbols = nm_symbols(elf, args.nm)
    missing = [name for name in ROLE_SYMBOLS[args.role]
               if find_symbol(symbols, name) is None]
    if missing:
        raise SystemExit(f'missing role symbols {missing} for {args.role}')
    start, end = highcode_range(symbols)
    roots, missing_roots, role_symbols = [], [], {}
    for needle in ROLE_ROOTS[args.role]:
        hit = find_symbol(symbols, needle)
        if not hit:
            missing_roots.append(needle)
            continue
        name, address, size = hit
        roots.append({'name': name, 'address': address, 'size': size,
                      'in_highcode': start <= address < end})
    if missing_roots:
        raise SystemExit(f'missing RAM root symbols {missing_roots}')
    for needle in ROLE_SYMBOLS[args.role]:
        name, address, _ = find_symbol(symbols, needle)
        role_symbols[name] = address
    report, coverage = call_report(elf, roots, nm_symbols(elf, args.nm, demangle=False),
                                   start, end)
    config = {'cargo_config': None,
              'rust_toolchain': sha256(ROOT / 'rust-toolchain.toml')}
    cargo_config = example / '.cargo/config.toml'
    if cargo_config.exists():
        config['cargo_config'] = sha256(cargo_config)
    paths = external_path_inputs(example)
    snapshot = None
    if args.snapshot_dir:
        sources = [('wchble', ROOT)] + [(name, ROOT.parent / name) for name in paths]
        path = write_snapshot(ROOT / args.snapshot_dir, sources)
        snapshot = {'path': str(path.relative_to(ROOT)), 'sha256': sha256(path),
                    'sources': ['wchble', *paths]}
    payload = {
        'schema': SCHEMA,
        'captured_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'role': args.role,
        'example': str(example.relative_to(ROOT)),
        'features': args.features,
        'recipe_source': args.recipe_source,
        'recipe_note': args.recipe_note,
        'capture_context': 'tree/path/toolchain fields are capture-time; '
                           'the recipe is declared unless recipe_source is build-time',
        'run_seconds': args.run_seconds,
        'build': {'target': args.target, 'cwd': str(example.relative_to(ROOT)),
                  'command': args.command,
                  'env': dict(item.split('=', 1) for item in args.env)},
        'toolchain': {
            'rustc': command(['rustc', '-vV']).strip(),
            'cargo': command(['cargo', '-V']).strip(),
            'llvm_nm': command([args.nm, '--version']).strip(),
            'llvm_objdump': command([args.objdump, '--version']).strip(),
            'linker': linker_version(),
        },
        'config': config,
        'tree': tree_state(ROOT),
        'path_inputs': {name: tree_state(ROOT.parent / name) for name in paths},
        'snapshot': snapshot,
        'locks': {name: sha256(example / name) for name in ('Cargo.lock',)
                  if (example / name).exists()},
        'elf': {'sha256': sha256(elf), 'size': elf.stat().st_size},
        'highcode': {'start': start, 'end': end},
        'symbols': role_symbols,
        'hot_symbols': {name: (find_symbol(symbols, name) or (None, None, None))[1]
                        for name in HOT_SYMBOLS},
        'roots': roots,
        'call_report': report,
        'call_coverage': coverage,
        'review': None,
    }
    if args.review_note:
        payload['review'] = {'status': 'reviewed', 'reviewer': args.reviewer,
                             'utc': payload['captured_utc'],
                             'elf_sha256': payload['elf']['sha256'],
                             'report_sha256': report_digest(report),
                             'note': args.review_note}
    Path(args.out).write_text(json.dumps(payload, indent=2) + '\n')
    return payload


def _string(data, key, allow_empty=False):
    value = data.get(key)
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(f'manifest {key} is not a non-empty string')
    return value


def _digest(value, key):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError(f'manifest {key} is not a sha256 digest')
    return value


def _head(value, key):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError(f'manifest {key} is not a git HEAD')
    return value


def _source_fields(data, role, root):
    """Recipe provenance and the recorded build inputs."""
    source = data.get('recipe_source')
    if source not in ('build-time', 'declared', 'unknown'):
        raise ValueError(f'manifest recipe_source {source!r} is not build-time/declared/unknown')
    if source == 'unknown' and not str(data.get('recipe_note') or '').strip():
        raise ValueError('manifest with an unknown recipe needs a recipe_note')
    if not isinstance(data.get('features'), str):
        raise ValueError('manifest features is not a string')
    build = data.get('build')
    if not isinstance(build, dict):
        raise ValueError('manifest build is not an object')
    _string(build, 'target')
    _string(build, 'cwd')
    _string(build, 'command', allow_empty=source == 'unknown')
    env = build.get('env')
    if not isinstance(env, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise ValueError('manifest build.env is not a string map')
    _string(data, 'capture_context')
    toolchain = data.get('toolchain')
    if not isinstance(toolchain, dict):
        raise ValueError('manifest toolchain is not an object')
    for key in ('rustc', 'cargo', 'llvm_nm', 'llvm_objdump'):
        _string(toolchain, key)
    if 'LLVM version' not in toolchain['rustc']:
        raise ValueError('manifest toolchain.rustc lacks the LLVM version')
    linker = toolchain.get('linker')
    if not isinstance(linker, dict):
        raise ValueError('manifest toolchain.linker is missing')
    _string(linker, 'version')
    tree = data.get('tree')
    if not isinstance(tree, dict):
        raise ValueError('manifest tree is not an object')
    _head(tree.get('head'), 'tree.head')
    for key in ('staged_sha256', 'unstaged_sha256', 'untracked_names_sha256',
                'untracked_content_sha256', 'digest'):
        _digest(tree.get(key), f'tree.{key}')
    if not isinstance(tree.get('dirty'), bool):
        raise ValueError('manifest tree.dirty is not a boolean')
    inputs = data.get('path_inputs')
    if not isinstance(inputs, dict) or not inputs:
        raise ValueError('manifest path_inputs is empty')
    for name in REQUIRED_PATH_INPUTS[role]:
        if name not in inputs:
            raise ValueError(f'manifest lacks the required path input {name}')
    for name, entry in inputs.items():
        if not isinstance(entry, dict) or entry.get('missing'):
            raise ValueError(f'manifest path input {name} is missing')
        _head(entry.get('head'), f'path_inputs.{name}.head')
        _digest(entry.get('digest'), f'path_inputs.{name}.digest')
    snapshot = data.get('snapshot')
    if not isinstance(snapshot, dict):
        raise ValueError('manifest has no recoverable source snapshot')
    _string(snapshot, 'path')
    _digest(snapshot.get('sha256'), 'snapshot.sha256')
    snapshot_path = root / snapshot['path']
    if not snapshot_path.is_file() or sha256(snapshot_path) != snapshot['sha256']:
        raise ValueError(f'manifest source snapshot {snapshot_path} is missing or changed')
    config = data.get('config')
    if not isinstance(config, dict):
        raise ValueError('manifest config is not an object')
    _digest(config.get('rust_toolchain'), 'config.rust_toolchain')
    if config.get('cargo_config') is not None:
        _digest(config['cargo_config'], 'config.cargo_config')
    locks = data.get('locks')
    if not isinstance(locks, dict):
        raise ValueError('manifest locks is not an object')
    if 'Cargo.lock' not in locks:
        raise ValueError('manifest lacks the example Cargo.lock digest')
    for name, value in locks.items():
        _digest(value, f'locks.{name}')


def verify(manifest_path, elf, role, run_seconds, nm=NM, symbols=None,
           section_table=None, root=None):
    """Fail before hardware access on any recipe or static-report mismatch."""
    root = Path(root) if root is not None else ROOT
    data = json.loads(Path(manifest_path).read_text())
    if data.get('schema') != SCHEMA:
        raise ValueError(f"manifest schema {data.get('schema')} != {SCHEMA}")
    if data.get('role') != role:
        raise ValueError(f"manifest role {data.get('role')} != {role}")
    if data.get('run_seconds') != run_seconds:
        raise ValueError(f"manifest run_seconds {data.get('run_seconds')} != {run_seconds}")
    _source_fields(data, role, root)
    digest = sha256(elf)
    if data.get('elf', {}).get('sha256') != digest:
        raise ValueError(f'manifest ELF {data.get("elf", {}).get("sha256")} != {digest}')
    if data.get('elf', {}).get('size') != Path(elf).stat().st_size:
        raise ValueError('manifest ELF size does not match')
    actual = symbols if symbols is not None else nm_symbols(elf, nm)
    try:
        start, end = highcode_range(actual)
    except RuntimeError as error:
        raise ValueError(str(error)) from error
    recorded = data.get('highcode') or {}
    if (recorded.get('start'), recorded.get('end')) != (start, end):
        raise ValueError('manifest highcode range does not match the ELF')
    for needle in ROLE_SYMBOLS[role]:
        entry = data.get('symbols', {}).get(needle)
        hit = find_symbol(actual, needle)
        if hit is None:
            raise ValueError(f'ELF has no role symbol {needle}')
        if entry != hit[1] or not entry:
            raise ValueError(f'manifest symbol {needle}={entry} != ELF {hit[1]}')
    roots = data.get('roots') or []
    if not isinstance(roots, list):
        raise ValueError('manifest roots is not a list')
    loaded = sections(elf) if section_table is None else section_table
    for needle in ROLE_ROOTS[role]:
        matches = [root for root in roots
                   if re.search(r'(^|::)' + re.escape(needle) + r'(::h[0-9a-f]+)?$',
                                str(root.get('name')))]
        if len(matches) != 1:
            raise ValueError(f'manifest needs exactly one RAM root {needle}, got {len(matches)}')
        root = matches[0]
        hit = find_symbol(actual, needle)
        if hit is None:
            raise ValueError(f'ELF has no RAM root {needle}')
        name, address, size = hit
        if (root.get('name'), root.get('address'), root.get('size')) != (name, address, size):
            raise ValueError(f'manifest RAM root {needle} does not match the ELF')
        if not size or address < start or address + size > end:
            raise ValueError(f'RAM root {needle} is not a sized .highcode range')
        if root.get('in_highcode') is not True:
            raise ValueError(f'RAM root {needle} is not marked in .highcode')
        backed = [name for name, section in loaded.items()
                  if section['type'] in ('TEXT', 'DATA')
                  and section['vma'] <= address
                  and address + size <= section['vma'] + section['size']]
        if not backed:
            raise ValueError(f'RAM root {needle} is not inside a file-backed section')
    extra = [root.get('name') for root in roots
             if not any(re.search(r'(^|::)' + re.escape(needle) + r'(::h[0-9a-f]+)?$',
                                  str(root.get('name'))) for needle in ROLE_ROOTS[role])]
    if extra:
        raise ValueError(f'manifest has unrelated RAM roots {extra}')
    report = data.get('call_report')
    if not isinstance(report, list) or not report:
        raise ValueError('manifest has no static Flash-call report')
    hot = data.get('hot_symbols')
    if not isinstance(hot, dict) or set(hot) != set(HOT_SYMBOLS):
        raise ValueError('manifest has no hot-symbol report')
    for name in HOT_SYMBOLS:
        hit = find_symbol(actual, name)
        expected = hit[1] if hit else None
        if hot[name] != expected:
            raise ValueError(f'manifest hot symbol {name}={hot[name]} != ELF {expected}')
    root_names = {root['name'] for root in roots}
    for row in report:
        if not isinstance(row, dict) or not isinstance(row.get('chain'), list) \
                or not row.get('chain') or not isinstance(row.get('call_site'), int) \
                or not isinstance(row.get('target'), str) \
                or not isinstance(row.get('target_address'), int) \
                or not str(row.get('mnemonic') or '').strip():
            raise ValueError('manifest Flash-call report row is malformed')
        if row.get('root') not in root_names or row['chain'][0] != row.get('root') \
                or row['chain'][-1] != row.get('target'):
            raise ValueError('manifest Flash-call report row is not bound to its root')
    coverage = data.get('call_coverage')
    if not isinstance(coverage, dict) or set(coverage) != root_names:
        raise ValueError('manifest call coverage does not cover every RAM root')
    for name, entry in coverage.items():
        if not isinstance(entry, dict) or not isinstance(entry.get('functions'), int) \
                or entry['functions'] < 1 or not isinstance(entry.get('depth_limited'), bool) \
                or not isinstance(entry.get('unresolved_indirect'), int) \
                or not isinstance(entry.get('unknown_targets'), int):
            raise ValueError(f'manifest call coverage for {name} is malformed')
    review = data.get('review')
    if not isinstance(review, dict) or review.get('status') != 'reviewed' \
            or not str(review.get('note') or '').strip():
        raise ValueError('manifest Flash-call report has not been reviewed')
    if review.get('elf_sha256') != data['elf']['sha256'] \
            or review.get('report_sha256') != report_digest(report):
        raise ValueError('manifest review is not bound to this ELF and call report')
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    cap = sub.add_parser('capture')
    cap.add_argument('--example', required=True)
    cap.add_argument('--elf', required=True)
    cap.add_argument('--role', required=True, choices=sorted(ROLE_SYMBOLS))
    cap.add_argument('--features', default='')
    cap.add_argument('--run-seconds', type=int, required=True)
    cap.add_argument('--command', default='')
    cap.add_argument('--target', default='riscv32imc-unknown-none-elf')
    cap.add_argument('--env', action='append', default=[])
    cap.add_argument('--recipe-source', default='declared',
                     choices=('build-time', 'declared', 'unknown'))
    cap.add_argument('--recipe-note', default='')
    cap.add_argument('--reviewer', default='')
    cap.add_argument('--review-note', default='')
    cap.add_argument('--snapshot-dir', default='')
    cap.add_argument('--nm', default=NM)
    cap.add_argument('--objdump', default=OBJDUMP)
    cap.add_argument('--out', required=True)
    ver = sub.add_parser('verify')
    ver.add_argument('--manifest', required=True)
    ver.add_argument('--elf', required=True)
    ver.add_argument('--role', required=True, choices=sorted(ROLE_SYMBOLS))
    ver.add_argument('--run-seconds', type=int, required=True)
    ver.add_argument('--nm', default=NM)
    args = parser.parse_args(argv)
    if args.action == 'capture':
        payload = capture(args)
        print(f"captured {payload['role']} {payload['elf']['sha256'][:8]} "
              f"roots={len(payload['roots'])} flash_calls={len(payload['call_report'])}")
        return 0
    try:
        verify(args.manifest, args.elf, args.role, args.run_seconds, nm=args.nm)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f'manifest check failed: {error}', file=sys.stderr)
        return 1
    print('manifest check PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
