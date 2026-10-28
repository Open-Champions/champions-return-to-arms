"""Synthetic ELF/ledger fixtures for exact-function verification; no game data."""
import contextlib
import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import rebuild


def elf_fixture(code=b'\x01\x02\x03\x04', kind=1, symbol='candidate', relocation=False, symbol_size=None,
                externs=(), relocations=()):
    # ELF32 records are assembled directly so tests do not require a MIPS compiler.
    # externs become undefined symbols 2, 3, ...; relocations are (offset, type, symbol).
    names = b'\0.text\0.symtab\0.strtab\0.rel.text\0.shstrtab\0'
    strings = b'\0' + symbol.encode() + b'\0'
    symbols = b'\0' * 16 + struct.pack('<IIIBBH', 1, 0, len(code) if symbol_size is None else symbol_size, 0x12, 0, 1)
    for name in externs:
        symbols += struct.pack('<IIIBBH', len(strings), 0, 0, 0x10, 0, 0)
        strings += name.encode() + b'\0'
    records = b''.join(struct.pack('<II', offset, (index << 8) | kind) for offset, kind, index in relocations)
    parts = [(b'', 0, 0, 0, 0, 0, 0),
             (code, 1, 6, 0x1000 if kind == 2 else 0, 0, 0, 0),
             (symbols, 2, 0, 0, 3, 1, 16),
             (strings, 3, 0, 0, 0, 0, 0),
             (struct.pack('<II', 0, 0x102) if relocation else records, 9, 0, 0, 2, 1, 8),
             (names, 3, 0, 0, 0, 0, 0)]
    section_names = ('', '.text', '.symtab', '.strtab', '.rel.text', '.shstrtab')
    data = bytearray(52)
    sections = []
    for name, (blob, typ, flags, addr, link, info, entsize) in zip(section_names, parts):
        data.extend(b'\0' * ((-len(data)) % 4))
        offset = len(data)
        data.extend(blob)
        sections.append((names.index(name.encode() + b'\0'), typ, flags, addr, offset, len(blob), link, info, 4, entsize))
    data.extend(b'\0' * ((-len(data)) % 4))
    shoff = len(data)
    for row in sections:
        data.extend(struct.pack('<10I', *row))
    data[:16] = b'\x7fELF\x01\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIIIIIHHHHHH', data, 16, kind, 8, 1, 0, 0, shoff, 0, 52, 0, 0, 40, len(sections), 5)
    return bytes(data)


class RebuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='rebuild fixture ')
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'candidate.cpp'
        self.source.write_text('extern "C" unsigned candidate() { return 1; }\n', encoding='utf-8')
        self.index = self.root / 'functions.tsv'
        self.index.write_text('00001000\tfixture\t00001000-00001003\n', encoding='utf-8')
        self.game = self.root / 'fixture.elf'
        self.game.write_bytes(elf_fixture(kind=2))
        self.compiler = self.root / 'synthetic compiler'
        self.compiler.write_bytes(b'synthetic compiler identity')
        self.ledger = {'schema_version': 1, 'target': {'id': 'fixture', 'baseline_sha256': rebuild.digest(self.game.read_bytes()),
                        'elf_machine': 8, 'text': {'address': '0x00001000', 'size': 4}},
                       'function_index': 'functions.tsv', 'functions': [{'id': 'fixture', 'address': '0x00001000', 'size': 4,
                        'source': 'candidate.cpp', 'symbol': 'candidate', 'language': 'c++', 'compiler_args': ['--no-default-config', '--target=mipsel-none-elf', '-O2']}]}
        self.path = self.root / 'rebuild.json'
        self.output = self.root / 'output objects'

    def tearDown(self):
        self.temporary.cleanup()

    def load(self):
        self.path.write_text(json.dumps(self.ledger), encoding='utf-8')
        return rebuild.load_ledger(self.path, self.root)

    @contextlib.contextmanager
    def compiler_fixture(self, object_data=None, returncode=0, source_mutation=None):
        previous_run, previous_which = rebuild.subprocess.run, rebuild.shutil.which
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            self.assertNotIn('shell', kwargs)
            self.assertIn('env', kwargs)
            self.assertFalse(any(name in kwargs['env'] for name in ('CCC_OVERRIDE_OPTIONS', 'CL', '_CL_')))
            if command[-1] == '--version':
                return subprocess.CompletedProcess(command, 0, b'Synthetic C++ compiler 1.0\n', b'')
            self.assertEqual(command[-3], str(self.source))
            self.assertEqual(command[-2], '-o')
            if returncode == 0:
                Path(command[-1]).write_bytes(object_data or elf_fixture())
            if source_mutation is not None:
                source_mutation()
            return subprocess.CompletedProcess(command, returncode, b'', b'synthetic diagnostic')

        rebuild.shutil.which = lambda value: str(self.compiler)
        rebuild.subprocess.run = run
        try:
            yield calls
        finally:
            rebuild.subprocess.run, rebuild.shutil.which = previous_run, previous_which

    def verify(self, object_data=None, returncode=0):
        ledger, index, index_hash = self.load()
        with self.compiler_fixture(object_data, returncode):
            report = rebuild.verify(ledger, index_hash, self.game, self.compiler, self.output, self.root)
        return ledger, index, index_hash, report

    def test_valid_elf_function_and_baseline(self):
        self.assertEqual(rebuild.Elf32(elf_fixture()).function('candidate'), b'\x01\x02\x03\x04')
        ledger, _, _ = self.load()
        self.assertEqual(rebuild.baseline_bytes(self.game, ledger), b'\x01\x02\x03\x04')

    def test_malformed_elf_bounds_machine_and_symbol_rejected(self):
        wrong_machine = bytearray(elf_fixture())
        struct.pack_into('<H', wrong_machine, 18, 62)
        for data in (b'not an ELF', elf_fixture()[:70], bytes(wrong_machine)):
            with self.subTest(data_length=len(data)), self.assertRaises(ValueError):
                rebuild.Elf32(data)
        with self.assertRaisesRegex(ValueError, 'symbol'):
            rebuild.Elf32(elf_fixture()).function('missing')
        with self.assertRaisesRegex(ValueError, 'extent'):
            rebuild.Elf32(elf_fixture(symbol_size=40)).function('candidate')

    def test_relocations_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'relocations'):
            rebuild.Elf32(elf_fixture(relocation=True)).function('candidate')

    def test_wide_relocation_before_symbol_is_rejected(self):
        data = bytearray(elf_fixture(code=b'\0' * 8, relocation=True, symbol_size=4))
        elf = rebuild.Elf32(bytes(data))
        _, symbols = elf.named_section('.symtab')
        _, relocations = elf.named_section('.rel.text')
        # Function starts at byte4, but R_MIPS_64 at byte0 rewrites bytes0..7.
        struct.pack_into('<I', data, symbols[4] + 16 + 4, 4)
        struct.pack_into('<II', data, relocations[4], 0, (1 << 8) | 18)
        with self.assertRaisesRegex(ValueError, 'relocations'):
            rebuild.Elf32(bytes(data)).function('candidate')

    def test_recorded_symbols_resolve_hi16_lo16_and_26_at_the_original_address(self):
        # lui $2,0; lw $2,0($2); jal 0; nop -- data at 0x44fd44, callee 0x355490, local jump.
        code = struct.pack('<5I', 0x3c020000, 0x8c420000, 0x0c000000, 0x08000000, 0)
        relocations = ((0, 5, 2), (4, 6, 2), (8, 4, 3), (12, 4, 1))
        elf = rebuild.Elf32(elf_fixture(code=code, externs=('D_0044FD44', 'func_00355490'), relocations=relocations))
        symbols = {'D_0044FD44': '0x0044fd44', 'func_00355490': '0x00355490'}
        self.assertEqual(struct.unpack('<5I', elf.function('candidate', 0x19d8a4, symbols)),
                         (0x3c020045, 0x8c42fd44, 0x0c000000 | 0x355490 >> 2, 0x08000000 | 0x19d8a4 >> 2, 0))
        with self.assertRaisesRegex(ValueError, 'relocations'):
            elf.function('candidate')
        with self.assertRaisesRegex(ValueError, 'func_00355490'):
            elf.function('candidate', 0x19d8a4, {'D_0044FD44': '0x0044fd44'})

    def test_unpaired_and_unsupported_relocations_are_rejected(self):
        code = struct.pack('<2I', 0x3c020000, 0x8c420000)
        for relocations, message in ((((0, 5, 2),), 'HI16'),
                                     (((0, 5, 2), (4, 6, 1)), 'paired'),
                                     (((4, 7, 2),), 'type 7'),
                                     (((0, 2, 2),), 'type 2')):
            elf = rebuild.Elf32(elf_fixture(code=code, externs=('D_0044FD44',), relocations=relocations))
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                elf.function('candidate', 0x1000, {'D_0044FD44': '0x0044fd44'})

    def test_ee_gcc_entries_use_their_own_flags_compiler_and_receipt(self):
        item = self.ledger['functions'][0]
        item.update({'toolchain': 'ee-gcc-2.96', 'compiler_args': ['-Os', '-G0'], 'symbols': {}})
        ledger, index, index_hash = self.load()
        with self.compiler_fixture() as calls:
            report = rebuild.verify(ledger, index_hash, self.game, None, self.output, self.root, ee_gcc=self.compiler)
        self.assertEqual(calls[0][1:], ['--version'])
        self.assertEqual((report['functions'][0]['toolchain'], report['functions'][0]['status']), ('ee-gcc-2.96', 'matched'))
        self.assertEqual(rebuild.progress(ledger, index, index_hash, report, self.root)['functions_matched'], 1)
        with self.compiler_fixture():
            report = rebuild.verify(ledger, index_hash, self.game, self.compiler, self.output, self.root)
        self.assertIn('no compiler supplied', report['functions'][0]['reason'])
        for flags in (['--no-default-config'], ['-I../headers'], ['-Os', '-include=private.h'], ['-B/private']):
            item['compiler_args'] = flags
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                self.load()
        item['compiler_args'] = ['-Os']
        for symbols in ({'bad name': '0x1000'}, {'D_1': 'nowhere'}, ['D_1']):
            item['symbols'] = symbols
            with self.subTest(symbols=symbols), self.assertRaises(ValueError):
                self.load()
        item['toolchain'] = 'ee-gcc-3.2'
        with self.assertRaisesRegex(ValueError, 'toolchain'):
            self.load()

    def test_wrong_baseline_hash_fails_before_compiler_probe(self):
        ledger, _, index_hash = self.load()
        self.game.write_bytes(b'wrong original')
        with self.compiler_fixture() as calls, self.assertRaisesRegex(ValueError, 'SHA-256'):
            rebuild.verify(ledger, index_hash, self.game, self.compiler, self.output, self.root)
        self.assertEqual(calls, [])

    def test_baseline_text_extent_is_verified(self):
        ledger, _, _ = self.load()
        ledger['target']['text']['size'] = 8
        with self.assertRaisesRegex(ValueError, '.text'):
            rebuild.baseline_bytes(self.game, ledger)

    def test_environment_compiler_options_fail_before_running_compiler(self):
        ledger, _, index_hash = self.load()
        for name in rebuild.ENVIRONMENT_OPTIONS:
            with self.subTest(name=name), patch.dict(os.environ, {name: 'private-option-value'}):
                with self.compiler_fixture() as calls, self.assertRaises(ValueError) as failure:
                    rebuild.verify(ledger, index_hash, self.game, self.compiler, self.output, self.root)
                self.assertEqual(calls, [])
                self.assertIn(name, str(failure.exception))
                self.assertNotIn('private-option-value', str(failure.exception))

    def test_changed_source_cannot_receive_a_matching_receipt(self):
        ledger, _, index_hash = self.load()
        def change_source():
            self.source.write_text('extern "C" unsigned candidate() { return 2; }\n', encoding='utf-8')
        with self.compiler_fixture(source_mutation=change_source):
            report = rebuild.verify(ledger, index_hash, self.game, self.compiler, self.output, self.root)
        self.assertEqual(report['functions'][0]['status'], 'failed')
        self.assertIn('source changed during compilation', report['functions'][0]['reason'])
        self.assertNotIn('rebuilt_sha256', report['functions'][0])

    def test_ledger_rejects_interior_partial_and_duplicate_entries(self):
        valid = copy.deepcopy(self.ledger)
        for mutation in ('interior', 'partial', 'duplicate'):
            self.ledger = copy.deepcopy(valid)
            if mutation == 'interior':
                self.ledger['functions'][0]['address'] = '0x1001'
            elif mutation == 'partial':
                self.ledger['functions'][0]['size'] = 8
            else:
                self.ledger['functions'].append(copy.deepcopy(self.ledger['functions'][0]))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.load()

    def test_source_and_flags_cannot_claim_assembly_or_external_inputs(self):
        for source in ('asm("nop");', '#include "private.h"\n', '#import "private.h"\n', '%:include "private.h"\n', '#inc\\\nlude "private.h"\n', '#define X asm\n'):
            self.source.write_text(source, encoding='utf-8', newline='\n')
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.load()
        self.source.write_text('extern "C" unsigned candidate() {return 1;}', encoding='utf-8')
        for flag in ('-oother.o', '@response.txt', '-include=private.h', '-I../headers', '-S', 'other.cpp', '-DVALUE=1', '--config=private.cfg'):
            self.ledger['functions'][0]['compiler_args'] = ['--no-default-config', flag]
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                self.load()
        self.ledger['functions'][0]['compiler_args'] = ['--no-default-config']
        self.ledger['functions'][0]['source'] = '../outside.cpp'
        with self.assertRaisesRegex(ValueError, 'escapes'):
            self.load()

    def test_literal_comment_markers_cannot_hide_external_inputs_or_assembly(self):
        for forbidden in ('#include "value.hpp"', '%:include "value.hpp"',
                          'asm("nop");', '__asm__("nop");'):
            for marker in ('/*', '//'):
                source = ('static const char* marker = "' + marker + '";\n'
                          + forbidden + '\n// */\n')
                self.source.write_text(source, encoding='utf-8', newline='\n')
                with self.subTest(forbidden=forbidden, marker=marker), self.assertRaises(ValueError):
                    rebuild.source_bytes(self.source)

    def test_literals_and_comments_preserve_lexical_boundaries(self):
        benign = [
            'const char* s = "/* #include \\\"value.hpp\\\" asm */ //";\n',
            'const char* s = "escaped \\\" quote /*"; char c = \'\\\'\';\n',
            '// /* comment markers do not start a block here\nextern "C" int f() { return 1; }\n',
            '/* #include "value.hpp"\nasm("nop"); */\n',
            'auto value = 1\'000; auto hex = 0xF\'F;\n',
        ]
        for source in benign:
            self.source.write_text(source, encoding='utf-8', newline='\n')
            with self.subTest(source=source):
                self.assertEqual(rebuild.source_bytes(self.source), source.encode())
        # Comments separate tokens rather than joining them, but retain newlines.
        self.assertEqual(rebuild.source_code('a/**/sm'), 'a    sm')
        for source in ('// /*\n#include "value.hpp"\n// */\n',
                       '/* lead\ncomment */ #include "value.hpp"\n',
                       'asm/**/("nop");'):
            self.source.write_text(source, encoding='utf-8', newline='\n')
            with self.subTest(source=source), self.assertRaises(ValueError):
                rebuild.source_bytes(self.source)

    def test_line_endings_and_clang_extended_splices_are_normalized(self):
        for newline in ('\n', '\r\n', '\r'):
            for gap in ('', ' ', '\t'):
                for body in ('#inc\\' + gap + newline + 'lude "value.hpp"',
                             'a\\' + gap + newline + 'sm("nop");'):
                    self.source.write_bytes(body.encode())
                    with self.subTest(newline=newline, gap=gap, body=body), self.assertRaises(ValueError):
                        rebuild.source_bytes(self.source)
            # A real CR line ending terminates a line comment before directives.
            self.source.write_bytes(('// comment' + newline + '#include "value.hpp"').encode())
            with self.subTest(newline=newline), self.assertRaises(ValueError):
                rebuild.source_bytes(self.source)
        # Unicode whitespace is not a Clang splice: do not let its preceding
        # line comment consume the real directive on the next line.
        self.source.write_text('// comment\\\u00a0\n#include "value.hpp"\n', encoding='utf-8')
        with self.assertRaises(ValueError):
            rebuild.source_bytes(self.source)

    def test_nul_cannot_hide_a_directive_from_the_source_gate(self):
        # Clang treats NUL as whitespace, including before a directive marker.
        for prefix in ('\0', ' \0', '\t\0'):
            self.source.write_bytes((prefix + '#include "value.hpp"\n').encode())
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, 'NUL'):
                rebuild.source_bytes(self.source)

    def test_raw_and_unterminated_literals_are_explicitly_rejected(self):
        for prefix in ('', 'u8', 'u', 'U', 'L'):
            self.source.write_text('auto s = ' + prefix + 'R"tag(/*)tag";', encoding='utf-8')
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, 'raw strings'):
                rebuild.source_bytes(self.source)
        for source in ('"unterminated', "'unterminated", '/* unterminated', '"line\nbreak"'):
            self.source.write_text(source, encoding='utf-8', newline='\n')
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'unterminated'):
                rebuild.source_bytes(self.source)

    def test_match_report_and_progress_never_credit_without_evidence(self):
        ledger, index, index_hash, report = self.verify()
        self.assertEqual(report['functions'][0]['status'], 'matched')
        self.assertNotIn(str(self.root), json.dumps(report))
        self.assertEqual(rebuild.progress(ledger, index, index_hash, root=self.root)['functions_matched'], 0)
        stats = rebuild.progress(ledger, index, index_hash, report, self.root)
        self.assertEqual((stats['functions_matched'], stats['bytes_matched']), (1, 4))
        self.assertIn('no linked-game', stats['scope'])
        ET.fromstring(rebuild.svg_report(stats))

    def test_mismatch_extent_and_relocations_do_not_credit_progress(self):
        for object_data, status in ((elf_fixture(code=b'\x00'*4), 'mismatched'),
                                    (elf_fixture(code=b'\x01'*8), 'failed'),
                                    (elf_fixture(relocation=True), 'failed')):
            with self.subTest(status=status):
                ledger, index, index_hash, report = self.verify(object_data)
                self.assertEqual(report['functions'][0]['status'], status)
                self.assertEqual(rebuild.progress(ledger, index, index_hash, report, self.root)['bytes_matched'], 0)

    def test_compile_failure_removes_stale_object(self):
        self.output.mkdir()
        stale = self.output / 'fixture.o'
        stale.write_bytes(elf_fixture())
        _, _, _, report = self.verify(returncode=1)
        self.assertEqual(report['functions'][0]['status'], 'failed')
        self.assertFalse(stale.exists())

    def test_reports_reject_changed_source_ledger_index_and_duplicate_evidence(self):
        ledger, index, index_hash, report = self.verify()
        for kind in ('source', 'ledger', 'index', 'duplicate', 'verifier'):
            changed_ledger, changed_report = copy.deepcopy(ledger), copy.deepcopy(report)
            changed_hash = index_hash
            if kind == 'source':
                changed_report['functions'][0]['source_sha256'] = '0'*64
            elif kind == 'ledger':
                changed_ledger['functions'][0]['compiler_args'].append('-fno-exceptions')
            elif kind == 'index':
                changed_hash = '0'*64
            elif kind == 'verifier':
                changed_report['verifier_sha256'] = '0'*64
            else:
                changed_report['functions'].append(copy.deepcopy(changed_report['functions'][0]))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                rebuild.progress(changed_ledger, index, changed_hash, changed_report, self.root)

    def test_direct_cli_help_on_current_python_and_isolated_mode(self):
        for flags in ([], ['-I']):
            result = subprocess.run([sys.executable] + flags + ['-B', rebuild.__file__, '--help'],
                                    capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('verify', result.stdout)


if __name__ == '__main__':
    unittest.main()
