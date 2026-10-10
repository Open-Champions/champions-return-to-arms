import importlib.util
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

spec = importlib.util.spec_from_file_location('rebuild_claims', Path(__file__).with_name('rebuild_claims.py'))
claims = importlib.util.module_from_spec(spec)
spec.loader.exec_module(claims)


class ClaimTests(unittest.TestCase):
    def test_cli_starts_without_local_dis_shadowing(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('rebuild_claims.py')), 'list'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_conflict_release_and_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            claims.update(folder, 'claim', '00100000', 'codex', 1, now=100)
            with self.assertRaisesRegex(ValueError, 'claimed by codex'):
                claims.update(folder, 'claim', '00100000', 'other', now=110)
            with self.assertRaisesRegex(ValueError, 'Only the recorded owner'):
                claims.update(folder, 'release', '00100000', 'other', now=110)
            second = claims.update(folder, 'claim', '00100000', 'other', now=161)
            self.assertEqual(second['owner'], 'other')
            claims.update(folder, 'release', '00100000', 'other', now=162)
            self.assertFalse((folder / '00100000.json').exists())

    def test_lock_excludes_writer_and_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / '.lock').mkdir()
            with self.assertRaisesRegex(ValueError, 'in progress'):
                claims.update(folder, 'claim', '00100000', 'codex')
            self.assertTrue((folder / '.lock').is_dir())
            self.assertFalse((folder / '00100000.json').exists())

    def test_owner_can_renew_without_unlocking_others(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            claims.update(folder, 'claim', '00100000', 'codex', 1, now=100)
            result = claims.update(folder, 'claim', '00100000', 'codex', 2, now=120)
            self.assertEqual(result['expires_at'], 240)
            self.assertFalse((folder / '.lock').exists())

    def test_invalid_duration_and_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                claims.update(Path(tmp), 'claim', '00100000', 'codex', 0)
        self.assertEqual(claims.address('0x00100000'), '00100000')
        for invalid in ('../x', '100001', 'ffffffff'):
            with self.assertRaises(Exception):
                claims.address(invalid)
