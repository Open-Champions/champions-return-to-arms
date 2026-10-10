"""Synthetic fixtures only: no game binary/disassembly required.

Run: python3 -m unittest discover -s tools -p test_audit_tools.py
"""
import contextlib
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('champions_dis', TOOLS / 'dis.py')
dis_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dis_tool)
symtab = dis_tool.symtab


class FakeElf:
    def __init__(self, path):
        self.text = (0x1000, 0, 0x1000)
        self.calls = {0x1000: [0x1100]}
        self.refs = {}

    def analyze(self):
        pass

    def in_text(self, addr):
        return 0x1000 <= addr < 0x2000

    def func_of(self, addr):
        # Mimic an interior heuristic boundary that wrongly splits the real function.
        if addr < 0x1004:
            return 0x1000, 0x1004
        return 0x1004, 0x1010


class ToolFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / 'symbols').mkdir()
        (self.root / 'disasm').mkdir()
        (self.root / 'names.tsv').write_text('00001000\tfixture_entry\n00001004\tinterior_label\n')
        (self.root / 'disasm/text.asm').write_text('header\n' + ''.join(
            f'{addr:x}: nop\n' for addr in range(0x1000, 0x1020, 4)))
        self.original_elf = dis_tool.Elf
        dis_tool.Elf = FakeElf

    def tearDown(self):
        dis_tool.Elf = self.original_elf
        self.tmp.cleanup()

    def run_dis(self, addr='1000', limit=None):
        args = [str(self.root / 'fixture.elf'), addr]
        if limit is not None:
            args.append(limit)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = dis_tool.main(args)
        return status, stdout.getvalue(), stderr.getvalue()

    def body(self, body='00001000-0000100f'):
        (self.root / 'ghidra_funcs.tsv').write_text(f'00001000\tfixture_entry\t{body}\n')

    def test_ghidra_body_ignores_interior_symbol_and_heuristic_split(self):
        self.body()
        status, out, err = self.run_dis('1008', 'all')
        self.assertEqual(status, 0)
        self.assertIn('Ghidra body', out)
        self.assertIn('00001000: nop', out)
        self.assertIn('0000100c: nop', out)
        self.assertNotIn('00001010: nop', out)
        self.assertEqual(err, '')

    def test_windows_utf16_disassembly_and_metadata(self):
        self.body()
        for relative in ('ghidra_funcs.tsv', 'names.tsv', 'disasm/text.asm'):
            path = self.root / relative
            content = path.read_text(encoding='utf-8')
            path.write_bytes(content.replace('\n', '\r\n').encode('utf-16'))
        status, out, err = self.run_dis('1008', 'all')
        self.assertEqual(status, 0)
        self.assertIn('fixture_entry', out)
        self.assertIn('0000100c: nop', out)
        self.assertEqual(err, '')

    def test_discontiguous_body_from_secondary_range(self):
        self.body('00001000-00001007,00001018-0000101f')
        status, out, err = self.run_dis('101c', 'all')
        self.assertEqual(status, 0)
        self.assertIn('00001000: nop', out)
        self.assertIn('0000101c: nop', out)
        self.assertNotIn('00001008: nop', out)
        self.assertNotIn('00001014: nop', out)

    def test_truncation_and_unlimited_and_exact_limit(self):
        self.body()
        status, out, err = self.run_dis(limit='2')
        self.assertEqual(status, 0)
        self.assertIn('shown 2 of 4 instructions (2 omitted)', out)
        self.assertNotIn('00001008: nop', out)
        for limit in ('all', '0', '4'):
            with self.subTest(limit=limit):
                status, out, err = self.run_dis(limit=limit)
                self.assertEqual(status, 0)
                self.assertIn('0000100c: nop', out)
                self.assertNotIn('truncated', out)

    def test_default_400_limit_has_notice(self):
        self.body('00001000-00001643')
        (self.root / 'disasm/text.asm').write_text(''.join(
            f'{addr:x}: nop\n' for addr in range(0x1000, 0x1644, 4)))
        status, out, err = self.run_dis()
        self.assertEqual(status, 0)
        self.assertIn('shown 400 of 401 instructions (1 omitted)', out)

    def test_heuristic_fallback_warns(self):
        status, out, err = self.run_dis()
        self.assertEqual(status, 0)
        self.assertIn('heuristic bounds', err)
        self.assertIn('00001000: nop', out)

    def test_absent_function_and_outside_code_fail_cleanly(self):
        class NoFunctions(FakeElf):
            def func_of(self, addr):
                return None, None
        dis_tool.Elf = NoFunctions
        for addr, message in [('1000', 'no function found'), ('2000', 'outside .text'), ('fff', 'outside .text')]:
            with self.subTest(addr=addr):
                status, out, err = self.run_dis(addr)
                self.assertEqual(status, 1)
                self.assertIn(message, err)
                self.assertNotIn('Traceback', err)

    def test_explicit_range_does_not_require_function(self):
        status, out, err = self.run_dis('1004:100c', 'all')
        self.assertEqual(status, 0)
        self.assertIn('00001004: nop', out)
        self.assertIn('00001008: nop', out)
        self.assertNotIn('0000100c: nop', out)
        self.assertEqual(err, '')

    def test_invalid_input_or_empty_disassembly_fails(self):
        for addr, limit in [('2000:2004', 'all'), ('1008:1000', 'all'), ('1000', '-1'), ('oops', 'all')]:
            with self.subTest(addr=addr, limit=limit):
                self.assertEqual(self.run_dis(addr, limit)[0], 1)
        (self.root / 'disasm/text.asm').write_text('header only\n')
        self.assertEqual(self.run_dis()[0], 1)

    def run_merge(self, output):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return symtab.main(['merge', str(output)], root=str(self.root))

    def test_valid_merge_sorts_and_deduplicates(self):
        (self.root / 'symbols/fixture.tsv').write_text('00001000\tfixture_entry\n00000020\tfirst\tevidence\n')
        output = self.root / 'merged.tsv'
        self.assertEqual(self.run_merge(output), 0)
        self.assertEqual(output.read_text(), '00000020\tfirst\tevidence\n00001000\tfixture_entry\t\n00001004\tinterior_label\t\n')

    def test_conflict_or_malformed_merge_preserves_existing_output(self):
        for row in ['00001000\tconflicting\n', 'nothex\tbad\n', '00001008\t\n',
                    '00001008\tname\tnote\textra\n', '-1\tnegative\n']:
            with self.subTest(row=row):
                (self.root / 'symbols/fixture.tsv').write_text(row)
                output = self.root / 'merged.tsv'
                original = b'KEEP EXISTING OUTPUT\x00\xff'
                output.write_bytes(original)
                self.assertEqual(self.run_merge(output), 1)
                self.assertEqual(output.read_bytes(), original)
                output.unlink()
                self.assertEqual(self.run_merge(output), 1)
                self.assertFalse(output.exists())

    def test_cli_invalid_merge_returns_nonzero_and_preserves_output(self):
        # Run the actual CLI from a synthetic repository so no game files are needed.
        fixture_tools = self.root / 'tools'
        fixture_tools.mkdir()
        script = fixture_tools / 'symtab.py'
        shutil.copyfile(TOOLS / 'symtab.py', script)
        shutil.copyfile(TOOLS / 'textinput.py', fixture_tools / 'textinput.py')
        output = self.root / 'merged.tsv'
        original = b'EXISTING OUTPUT\x00\xff'
        for row, diagnostic in [('00001000\tconflicting\n', 'conflict'),
                                ('nothex\tmalformed\n', 'malformed')]:
            with self.subTest(diagnostic=diagnostic):
                (self.root / 'symbols/fixture.tsv').write_text(row)
                output.write_bytes(original)
                result = subprocess.run([sys.executable, str(script), 'merge', str(output)],
                                        cwd=self.root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn(diagnostic, result.stdout)
                self.assertIn('output unchanged', result.stderr)
                self.assertEqual(output.read_bytes(), original)

    def test_replace_failure_preserves_output_and_cleans_temporary_file(self):
        output = self.root / 'merged.tsv'
        original = b'EXISTING OUTPUT\x00\xff'
        output.write_bytes(original)
        before = set(self.root.iterdir())
        replacements = []
        original_replace = symtab.os.replace

        def fail_replace(source, destination):
            self.assertEqual(Path(destination), output)
            self.assertEqual(Path(source).parent, output.parent)
            self.assertIn('00001000\tfixture_entry', Path(source).read_text())
            replacements.append(source)
            raise OSError('simulated filesystem replacement failure')

        symtab.os.replace = fail_replace
        try:
            self.assertEqual(self.run_merge(output), 1)
        finally:
            symtab.os.replace = original_replace
        self.assertEqual(len(replacements), 1)
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual(set(self.root.iterdir()), before)


if __name__ == '__main__':
    unittest.main()
