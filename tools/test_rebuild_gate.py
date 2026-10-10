import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('rebuild_gate', Path(__file__).with_name('rebuild_gate.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class GateTests(unittest.TestCase):
    def test_cli_help(self):
        result = subprocess.run([sys.executable, str(Path(gate.__file__)), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_reconstruction_paths_trigger(self):
        self.assertFalse(gate.affects_rebuild(['docs/STATUS.md', 'native/src/main.cpp']))
        self.assertTrue(gate.affects_rebuild(['reconstructed/leaf.cpp']))
        self.assertTrue(gate.affects_rebuild(['targets/SLUS-20973/rebuild.json']))

    def test_preserve_existing_hooks_and_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            hook = root / '.git/hooks/pre-commit'
            hook.write_text('# user hook\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'existing pre-commit'):
                gate.install(root)
            self.assertEqual(hook.read_text(), '# user hook\n')
            hook.unlink()
            gate.install(root)
            self.assertEqual(hook.read_text(), gate.HOOK)
            gate.git('config', '--local', 'core.hooksPath', 'custom-hooks', root=root)
            with self.assertRaisesRegex(ValueError, 'core.hooksPath'):
                gate.install(root)
