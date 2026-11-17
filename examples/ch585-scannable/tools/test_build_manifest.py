#!/usr/bin/env python3
"""Offline tests for the hash-bound build manifest."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

_spec = importlib.util.spec_from_file_location(
    'build_manifest', Path(__file__).with_name('build_manifest.py'))
manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(manifest)

DIGEST = '1' * 64
HEAD = '2' * 40
SECTIONS = {'.highcode': {'size': 0x1000, 'vma': 0x20000000, 'lma': 4, 'type': 'TEXT'},
            '.bss': {'size': 0x100, 'vma': 0x20001000, 'lma': 0x20001000, 'type': 'BSS'}}


def elf_symbols(role='peripheral'):
    symbols = {name: (0x20000400, 4) for name in manifest.ROLE_SYMBOLS[role]}
    symbols['_highcode_vma_start'] = (0x20000000, 0)
    symbols['_highcode_vma_end'] = (0x20001000, 0)
    for index, needle in enumerate(manifest.ROLE_ROOTS[role]):
        symbols[f'example::{needle}::h{index:04x}'] = (0x20000100 + index * 0x40, 0x40)
    return symbols


def payload(elf_bytes, role='peripheral', run_seconds=25, symbols=None, snapshot='snap.tar.gz'):
    symbols = symbols or elf_symbols(role)
    roots = []
    for needle in manifest.ROLE_ROOTS[role]:
        name = manifest.find_symbol(symbols, needle)[0]
        address, size = symbols[name]
        roots.append({'name': name, 'address': address, 'size': size,
                      'in_highcode': True})
    report = [{'root': roots[0]['name'], 'chain': [roots[0]['name'], 'tx_basic'],
               'call_site': 0x20000110, 'mnemonic': 'jal',
               'target': 'tx_basic', 'target_address': 0x4000}]
    snapshot_data = b'snapshot-bytes'
    return {
        'schema': 2, 'role': role, 'run_seconds': run_seconds,
        'features': '', 'recipe_source': 'declared', 'recipe_note': '',
        'capture_context': 'capture-time tree',
        'build': {'target': 'riscv32imc-unknown-none-elf', 'cwd': 'examples/x',
                  'command': 'cargo build --release', 'env': {}},
        'toolchain': {'rustc': 'rustc 1.95.0\nLLVM version: 21.1.2',
                      'cargo': 'cargo 1.95.0', 'llvm_nm': 'LLVM version 21.1.2',
                      'llvm_objdump': 'LLVM version 21.1.2',
                      'linker': {'path': 'rust-lld', 'version': 'LLD 21'}},
        'config': {'cargo_config': None, 'rust_toolchain': DIGEST},
        'tree': {'head': HEAD, 'staged_sha256': DIGEST, 'unstaged_sha256': DIGEST,
                 'untracked_names_sha256': DIGEST,
                 'untracked_content_sha256': DIGEST, 'digest': DIGEST, 'dirty': False},
        'path_inputs': {'ch5xx-hal': {'head': HEAD, 'digest': DIGEST, 'dirty': False},
                        'trouble': {'head': HEAD, 'digest': DIGEST, 'dirty': False}},
        'snapshot': {'path': snapshot,
                     'sha256': hashlib.sha256(snapshot_data).hexdigest(),
                     'sources': ['wchble', 'ch5xx-hal', 'trouble']},
        'locks': {'Cargo.lock': DIGEST},
        'elf': {'sha256': hashlib.sha256(elf_bytes).hexdigest(),
                'size': len(elf_bytes)},
        'highcode': {'start': 0x20000000, 'end': 0x20001000},
        'symbols': {name: symbols[manifest.find_symbol(symbols, name)[0]][0]
                    for name in manifest.ROLE_SYMBOLS[role]},
        'hot_symbols': {name: (symbols.get(name) or (None,))[0]
                        for name in manifest.HOT_SYMBOLS},
        'roots': roots,
        'call_report': report,
        'call_coverage': {root['name']: {'functions': 1, 'depth_limited': False,
                                         'unresolved_indirect': 0, 'unknown_targets': 0}
                          for root in roots},
        'review': {'status': 'reviewed', 'reviewer': 'test', 'utc': 'now',
                   'elf_sha256': hashlib.sha256(elf_bytes).hexdigest(),
                   'report_sha256': manifest.report_digest(report),
                   'note': 'checked'},
    }


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.elf = self.root / 'firmware.elf'
        self.elf.write_bytes(b'\x7fELF-test-image')
        (self.root / 'snap.tar.gz').write_bytes(b'snapshot-bytes')

    def tearDown(self):
        self.directory.cleanup()

    def verify(self, data=None, role='peripheral', run_seconds=25, section_table=None):
        data = data if data is not None else payload(self.elf.read_bytes())
        path = self.root / 'manifest.json'
        path.write_text(json.dumps(data))
        return manifest.verify(path, self.elf, role, run_seconds,
                               symbols=elf_symbols(role),
                               section_table=section_table or SECTIONS,
                               root=self.root)

    def reject(self, data=None, role='peripheral', run_seconds=25, section_table=None):
        with self.assertRaises(ValueError):
            self.verify(data, role, run_seconds, section_table)

    def test_accepts_matching_recipe(self):
        self.assertEqual(self.verify()['role'], 'peripheral')

    def test_rejects_schema_role_and_budget(self):
        data = payload(self.elf.read_bytes())
        data['schema'] = 1
        self.reject(data)
        self.reject(role='central')
        data = payload(self.elf.read_bytes())
        data['run_seconds'] = 60
        self.reject(data)

    def test_rejects_other_elf(self):
        data = payload(self.elf.read_bytes())
        self.elf.write_bytes(b'\x7fELF-rebuilt-here')
        self.reject(data)

    def test_rejects_unknown_recipe_without_note(self):
        data = payload(self.elf.read_bytes())
        data['recipe_source'] = 'unknown'
        self.reject(data)
        data['recipe_note'] = 'opt-z vs opt-3 not recorded'
        data['build']['command'] = ''
        self.assertEqual(self.verify(data)['role'], 'peripheral')
        data['recipe_source'] = 'guessed'
        self.reject(data)

    def test_rejects_null_or_typed_source_fields(self):
        for field in ('features', 'capture_context'):
            with self.subTest(field=field):
                data = payload(self.elf.read_bytes())
                data[field] = None
                self.reject(data)
        for field in ('build', 'toolchain', 'tree', 'path_inputs', 'config', 'locks'):
            with self.subTest(field=field):
                data = payload(self.elf.read_bytes())
                data[field] = None
                self.reject(data)
        data = payload(self.elf.read_bytes())
        data['toolchain']['rustc'] = 'rustc 1.95.0'
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['tree']['head'] = None
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['tree']['staged_sha256'] = 'abc'
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['path_inputs']['trouble'] = {'missing': True}
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['build']['env'] = {'CARGO_PROFILE_RELEASE_OPT_LEVEL': None}
        self.reject(data)

    def test_rejects_symbol_and_root_mismatches(self):
        data = payload(self.elf.read_bytes())
        data['symbols']['STATS'] = 0
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['roots'][0]['address'] = 0
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['roots'][0]['size'] = 0
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['roots'][1]['name'] = data['roots'][0]['name']
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['roots'].append(dict(data['roots'][0], name='unrelated::h0000'))
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['roots'][0]['in_highcode'] = False
        self.reject(data)

    def test_rejects_bad_highcode_range(self):
        data = payload(self.elf.read_bytes())
        data['highcode']['start'] = 0x1000
        self.reject(data)
        data = payload(self.elf.read_bytes())
        del data['highcode']
        self.reject(data)

    def test_requires_reviewed_call_report(self):
        data = payload(self.elf.read_bytes())
        data['review'] = None
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['review']['note'] = ' '
        self.reject(data)
        data = payload(self.elf.read_bytes())
        del data['call_report']
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['call_report'] = []
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['call_report'][0]['call_site'] = '0x10'
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['call_report'][0]['chain'] = ['other']
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['hot_symbols']['tx_basic'] = 'none'
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['hot_symbols']['tx_basic'] = 0x1000
        self.reject(data)
        data = payload(self.elf.read_bytes())
        del data['hot_symbols']['rx_basic']
        self.reject(data)
        data = payload(self.elf.read_bytes())
        del data['call_coverage'][data['roots'][1]['name']]
        self.reject(data)

    def test_review_is_bound_to_the_elf_and_report(self):
        data = payload(self.elf.read_bytes())
        data['review']['report_sha256'] = DIGEST
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['review']['elf_sha256'] = DIGEST
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['call_report'][0]['call_site'] = 0x20000118
        self.reject(data)

    def test_requires_locks_path_inputs_and_snapshot(self):
        data = payload(self.elf.read_bytes())
        data['locks'] = {}
        self.reject(data)
        data = payload(self.elf.read_bytes())
        del data['path_inputs']['ch5xx-hal']
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['snapshot'] = None
        self.reject(data)
        data = payload(self.elf.read_bytes())
        data['snapshot']['sha256'] = DIGEST
        self.reject(data)
        data = payload(self.elf.read_bytes())
        (self.root / 'snap.tar.gz').write_bytes(b'changed')
        self.reject(data)

    def test_rejects_ram_root_outside_highcode_end(self):
        symbols = elf_symbols('peripheral')
        name = manifest.find_symbol(symbols, 'receive')[0]
        symbols[name] = (0x20000f00, 0x200)
        data = payload(self.elf.read_bytes(), symbols=symbols)
        path = self.root / 'manifest.json'
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            manifest.verify(path, self.elf, 'peripheral', 25, symbols=symbols,
                            section_table=SECTIONS, root=self.root)

    def test_rejects_ram_root_without_file_backed_section(self):
        small = {'.highcode': dict(SECTIONS['.highcode'], size=0x100)}
        self.reject(section_table=small)
        bss = {'.highcode': dict(SECTIONS['.highcode'], type='BSS')}
        self.reject(section_table=bss)


class SymbolTests(unittest.TestCase):
    def test_find_symbol_handles_mangled_suffix(self):
        symbols = {'hal::run_connection::h1a2b': (0x10, 8), 'run_connection': (0x20, 4)}
        self.assertEqual(manifest.find_symbol(symbols, 'run_connection')[1:], (0x10, 8))
        self.assertIsNone(manifest.find_symbol(symbols, 'connection'))

    def test_nm_symbols_reads_sizes(self):
        text = '20000000 00000010 T main\n20000100 00000004 R RUN_SECONDS\n'
        with patch.object(manifest, 'command', return_value=text):
            symbols = manifest.nm_symbols('elf')
        self.assertEqual(symbols['main'], (0x20000000, 0x10))
        self.assertEqual(symbols['RUN_SECONDS'], (0x20000100, 4))

    def test_call_report_follows_ram_helpers(self):
        roots = [{'name': 'main', 'address': 0x20000000, 'size': 0x20}]
        table = {'tx_basic': (0x3000, 40), 'helper': (0x20000010, 0x10)}
        disassembly = {
            0x20000000: [(0x20000004, 'jal', 'helper')],
            0x20000010: [(0x20000014, 'jal', 'tx_basic')],
        }

        def fake(elf, address, size):
            return disassembly[address]

        with patch.object(manifest, 'instruction_lines', side_effect=fake):
            report, coverage = manifest.call_report('elf', roots, table, 0x20000000,
                                                    0x20001000)
        self.assertEqual(report[0]['chain'], ['main', 'helper', 'tx_basic'])
        self.assertEqual(report[0]['call_site'], 0x20000014)
        self.assertEqual(coverage['main']['functions'], 2)

    def test_shared_helper_keeps_both_roots(self):
        roots = [{'name': 'root_a', 'address': 0x20000000, 'size': 0x10},
                 {'name': 'root_b', 'address': 0x20000010, 'size': 0x10}]
        table = {'helper': (0x20000020, 0x10), 'tx_basic': (0x3000, 40)}
        disassembly = {
            0x20000000: [(0x20000004, 'jal', 'helper')],
            0x20000010: [(0x20000014, 'jal', 'helper')],
            0x20000020: [(0x20000024, 'jal', 'tx_basic')],
        }

        def fake(elf, address, size):
            return disassembly[address]

        with patch.object(manifest, 'instruction_lines', side_effect=fake):
            report, _ = manifest.call_report('elf', roots, table, 0x20000000, 0x20001000)
        self.assertEqual({row['root'] for row in report}, {'root_a', 'root_b'})

    def test_depth_limit_is_reported(self):
        roots = [{'name': 'main', 'address': 0x20000000, 'size': 0x10}]
        table = {f'h{i}': (0x20000010 + i * 0x10, 0x10) for i in range(8)}
        table['tx_basic'] = (0x3000, 40)

        def fake(elf, address, size):
            index = (address - 0x20000000) // 0x10
            target = 'h0' if index == 0 else (f'h{index}' if index < 8 else None)
            return [(address, 'jal', target)] if target else []

        with patch.object(manifest, 'instruction_lines', side_effect=fake):
            _, coverage = manifest.call_report('elf', roots, table, 0x20000000,
                                               0x20001000, depth=3)
        self.assertTrue(coverage['main']['depth_limited'])


class TreeTests(unittest.TestCase):
    def test_staged_changes_enter_the_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'tracked').write_text('one\n')
            subprocess.run(['git', '-C', str(root), 'add', 'tracked'], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=t', '-c',
                            'user.email=t@t', 'commit', '-qm', 'init'], check=True)
            clean = manifest.tree_state(root)
            self.assertFalse(clean['dirty'])
            (root / 'tracked').write_text('two\n')
            subprocess.run(['git', '-C', str(root), 'add', 'tracked'], check=True)
            staged = manifest.tree_state(root)
            self.assertTrue(staged['dirty'])
            self.assertNotEqual(clean['digest'], staged['digest'])
            self.assertNotEqual(clean['staged_sha256'], staged['staged_sha256'])


if __name__ == '__main__':
    unittest.main()
