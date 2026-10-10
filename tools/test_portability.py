"""Portable synthetic tests; no LLVM installation or game assets required."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import gen_disasm
import symtab
from textinput import text_lines


class TextInputTests(unittest.TestCase):
    def test_utf8_and_windows_bom_encodings_decode_identically(self):
        content = '00001000\tfixture\tCafé — evidence\r\n00001004\tsecond\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inputs.txt'
            for encoding in ('utf-8', 'utf-8-sig', 'utf-16', 'utf-16-be'):
                with self.subTest(encoding=encoding):
                    blob = content.encode(encoding)
                    if encoding == 'utf-16-be':
                        blob = b'\xfe\xff' + blob
                    path.write_bytes(blob)
                    self.assertEqual(list(text_lines(path)), content.replace('\r\n', '\n').splitlines(True))

    def test_invalid_and_unmarked_encodings_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inputs.txt'
            for blob in (b'bad\xff\n', 'text'.encode('utf-16-le'), 'text'.encode('utf-32'), b'\xff\xfea'):
                with self.subTest(blob=blob):
                    path.write_bytes(blob)
                    with self.assertRaises((ValueError, UnicodeError)):
                        list(text_lines(path))

    def test_windows_symbol_files_merge_with_unicode_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'merged.tsv'
            for encoding in ('utf-8-sig', 'utf-16'):
                with self.subTest(encoding=encoding):
                    (root / 'names.tsv').write_bytes('00001000\tfixture\tCafé — evidence\r\n'.encode(encoding))
                    with contextlib.redirect_stdout(io.StringIO()):
                        result = symtab.main(['merge', str(output)], root=str(root))
                    self.assertEqual(result, 0)
                    self.assertEqual(output.read_text(encoding='utf-8'), '00001000\tfixture\tCafé — evidence\n')


class DisassemblyGeneratorTests(unittest.TestCase):
    def setUp(self):
        self.original_run = gen_disasm.subprocess.run
        self.original_which = gen_disasm.shutil.which
        self.original_candidates = gen_disasm.objdump_candidates

    def tearDown(self):
        gen_disasm.subprocess.run = self.original_run
        gen_disasm.shutil.which = self.original_which
        gen_disasm.objdump_candidates = self.original_candidates

    def test_real_cli_help_does_not_shadow_standard_library(self):
        for flags in ([], ['-I']):
            with self.subTest(flags=flags):
                result = subprocess.run([sys.executable] + flags + ['-B', gen_disasm.__file__, '--help'],
                                        capture_output=True, text=True, encoding='utf-8', timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('--objdump', result.stdout)
                self.assertIn('--output', result.stdout)

    def test_importing_generator_keeps_search_path_unchanged(self):
        program = (
            'import importlib.util, sys; before = sys.path[:]; '
            'spec = importlib.util.spec_from_file_location("generator", sys.argv[1]); '
            'module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); '
            'assert sys.path == before, "helper import changed sys.path"'
        )
        result = subprocess.run([sys.executable, '-I', '-B', '-c', program, gen_disasm.__file__],
                                capture_output=True, text=True, encoding='utf-8', timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_discovery_skips_apple_and_accepts_mips_from_stderr(self):
        gen_disasm.objdump_candidates = lambda: iter(['apple-llvm', 'mips-llvm'])
        commands = []

        def probe(command, **kwargs):
            commands.append(command)
            self.assertEqual(kwargs['timeout'], 10)
            self.assertNotIn('shell', kwargs)
            targets = b'  arm64 - ARM64\n' if command[0] == 'apple-llvm' else b'  mipsel - MIPS (little endian)\n'
            return subprocess.CompletedProcess(command, 0, stdout=b'LLVM version\n', stderr=targets)

        gen_disasm.subprocess.run = probe
        self.assertEqual(gen_disasm.discover_objdump(), 'mips-llvm')
        self.assertEqual(commands, [['apple-llvm', '--version'], ['mips-llvm', '--version']])

    def test_explicit_unsupported_tool_fails_without_fallback(self):
        gen_disasm.shutil.which = lambda path: path
        gen_disasm.objdump_candidates = lambda: self.fail('explicit tool must not fall back')
        gen_disasm.subprocess.run = lambda command, **kwargs: subprocess.CompletedProcess(command, 0, stdout=b'arm64 - ARM\n', stderr=b'')
        with self.assertRaisesRegex(RuntimeError, 'MIPS'):
            gen_disasm.discover_objdump('C:/Program Files/LLVM/llvm-objdump.exe')

    def test_discovery_timeout_is_actionable(self):
        gen_disasm.objdump_candidates = lambda: iter(['hung-llvm'])

        def timeout(command, **kwargs):
            raise subprocess.TimeoutExpired(command, kwargs['timeout'])

        gen_disasm.subprocess.run = timeout
        with self.assertRaisesRegex(RuntimeError, 'Install LLVM'):
            gen_disasm.discover_objdump()

    def test_paths_with_spaces_and_complete_bytes_replace_output(self):
        with tempfile.TemporaryDirectory(prefix='champions space ') as directory:
            root = Path(directory)
            elf = root / 'game source.elf'
            elf.write_bytes(b'SYNTHETIC FIXTURE')
            output = root / 'result space' / 'text.asm'
            expected = b'fixture:\n1000: nop\n1004: nop\n'

            def generate(command, **kwargs):
                self.assertEqual(command[0], 'C:/Program Files/LLVM/bin/llvm-objdump.exe')
                self.assertEqual(command[-1], str(elf.resolve()))
                self.assertIn('--disassemble-zeroes', command)
                self.assertNotIn('shell', kwargs)
                kwargs['stdout'].write(expected)
                return subprocess.CompletedProcess(command, 0, stderr=b'')

            gen_disasm.subprocess.run = generate
            result = gen_disasm.generate_disassembly(elf, output, 'C:/Program Files/LLVM/bin/llvm-objdump.exe')
            self.assertEqual(result, output.resolve())
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_failed_or_empty_llvm_output_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf, output = root / 'fixture.elf', root / 'existing.asm'
            elf.write_bytes(b'SYNTHETIC FIXTURE')
            for code, listing in ((1, b'partial output'), (0, b'file header only\n')):
                with self.subTest(code=code):
                    output.write_bytes(b'KEEP EXISTING')
                    before = set(root.iterdir())

                    def generate(command, **kwargs):
                        kwargs['stdout'].write(listing)
                        return subprocess.CompletedProcess(command, code, stderr=b'failed target')

                    gen_disasm.subprocess.run = generate
                    with self.assertRaises(RuntimeError):
                        gen_disasm.generate_disassembly(elf, output, 'synthetic-llvm')
                    self.assertEqual(output.read_bytes(), b'KEEP EXISTING')
                    self.assertEqual(set(root.iterdir()), before)


if __name__ == '__main__':
    unittest.main()
