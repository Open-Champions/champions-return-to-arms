"""Synthetic native-preflight tests; no disc executable or external tools required.

Run: python3 -m unittest discover -s tools -p test_doctor.py
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('champions_doctor', Path(__file__).with_name('doctor.py'))
doctor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(doctor)


def arguments(**kwargs):
    values = dict(strict_re=False, game=None, llvm_objdump=None, java=None,
                  ghidra_home=None, ee_extension=None, json=False)
    values.update(kwargs)
    return SimpleNamespace(**values)


def check(report, name):
    return next(c for c in report['checks'] if c['name'] == name)


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.which = patch.object(doctor.shutil, 'which', return_value=None)
        self.which.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.which.stop)
        self.discovery = patch.object(doctor, 'discover_objdump', side_effect=RuntimeError('missing'))
        self.mock_discovery = self.discovery.start()
        self.addCleanup(self.discovery.stop)

    def test_no_game_or_optional_dependencies_pass_basic(self):
        with patch.object(doctor, 'version_probe') as probe:
            report = doctor.build_report(arguments())
        self.assertEqual(report['exit_code'], 0)
        self.assertFalse(report['native_game_runtime'])
        self.assertEqual(check(report, 'game')['status'], 'warn')
        probe.assert_not_called()

    def test_missing_dependencies_fail_strict(self):
        report = doctor.build_report(arguments(strict_re=True))
        self.assertEqual(report['exit_code'], 1)
        for name in ('game', 'llvm_mips', 'java', 'ghidra', 'emotion_engine'):
            self.assertEqual(check(report, name)['status'], 'fail', name)

    def test_explicit_game_mismatch_fails_basic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'synthetic.bin'
            path.write_bytes(b'original synthetic test data')
            report = doctor.build_report(arguments(game=str(path)))
        self.assertEqual(report['exit_code'], 1)
        self.assertIn('Wrong executable', check(report, 'game')['message'])

    def test_matching_digest_with_synthetic_expected_hash(self):
        data = b'original fixture, not game data'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'synthetic.bin'
            path.write_bytes(data)
            with patch.object(doctor, 'GAME_SHA256', hashlib.sha256(data).hexdigest()):
                report = doctor.build_report(arguments(game=str(path)))
        self.assertEqual(check(report, 'game')['status'], 'pass')

    def test_missing_game_and_directory_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for path in (tmp, str(Path(tmp) / 'missing')):
                self.assertEqual(doctor.build_report(arguments(game=path))['exit_code'], 1)

    def test_llvm_detection_uses_shared_discovery_and_explicit_override(self):
        report = doctor.build_report(arguments(llvm_objdump='/explicit/llvm-objdump'))
        self.mock_discovery.assert_called_with('/explicit/llvm-objdump')
        self.assertEqual(check(report, 'llvm_mips')['status'], 'warn')
        self.mock_discovery.side_effect = None
        self.mock_discovery.return_value = '/usual/installation/llvm-objdump'
        report = doctor.build_report(arguments())
        self.mock_discovery.assert_called_with(None)
        self.assertEqual(check(report, 'llvm_mips')['status'], 'pass')

    def test_version_probe_combines_stderr_without_shell(self):
        result = SimpleNamespace(stdout='', stderr='openjdk version "21.0.1"', returncode=0)
        with patch.object(doctor.subprocess, 'run', return_value=result) as run:
            output, error = doctor.version_probe('C:/Program Files/JDK/bin/java.exe', '-version')
        self.assertIsNone(error)
        self.assertIn('21.0.1', output)
        self.assertEqual(run.call_args.args[0], ['C:/Program Files/JDK/bin/java.exe', '-version'])
        self.assertFalse(run.call_args.kwargs['shell'])
        self.assertEqual(run.call_args.kwargs['timeout'], doctor.TIMEOUT)

    def test_failed_probe_does_not_echo_process_output(self):
        result = SimpleNamespace(stdout='private output', stderr='private error', returncode=1)
        with patch.object(doctor.subprocess, 'run', return_value=result):
            output, error = doctor.version_probe('java', '-version')
        self.assertIsNone(output)
        self.assertNotIn('private', error)

    def test_timeout_and_missing_executable_are_actionable(self):
        for failure in (subprocess.TimeoutExpired('java', 8), FileNotFoundError()):
            with patch.object(doctor.subprocess, 'run', side_effect=failure):
                output, error = doctor.version_probe('java', '-version')
            self.assertIsNone(output)
            self.assertTrue(error)

    def configured_distribution(self, root, windows=False):
        (root / 'Ghidra').mkdir()
        (root / 'Ghidra' / 'application.properties').write_text(
            'application.java.min=21\napplication.java.max=25\n', encoding='utf-8')
        (root / 'support').mkdir()
        (root / 'support' / ('analyzeHeadless.bat' if windows else 'analyzeHeadless')).touch()
        extension = root / 'Ghidra' / 'Extensions' / 'ghidra-emotionengine-reloaded'
        (extension / 'data' / 'languages').mkdir(parents=True)
        (extension / 'extension.properties').write_text('name=ghidra-emotionengine-reloaded\n', encoding='utf-8')
        (extension / 'data' / 'languages' / 'fixture.ldefs').write_text(
            '<language id="r5900:LE:32:default"/>', encoding='utf-8')
        return extension

    def test_configured_windows_and_macos_strict_preflight(self):
        self.mock_discovery.side_effect = None
        self.mock_discovery.return_value = '/fixture/llvm-objdump'
        for host in ('Windows', 'Darwin'):
            with self.subTest(host=host), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.configured_distribution(root, windows=host == 'Windows')
                game = root / 'synthetic.bin'
                game.write_bytes(b'fixture')
                def probe(command, flag):
                    return ('LLVM\n mips - MIPS' if flag == '--version' else 'openjdk version "21.0.1"', None)
                with patch.object(doctor.platform, 'system', return_value=host), \
                     patch.object(doctor, 'GAME_SHA256', hashlib.sha256(b'fixture').hexdigest()), \
                     patch.object(doctor, 'version_probe', side_effect=probe):
                    report = doctor.build_report(arguments(strict_re=True, game=str(game),
                        llvm_objdump='llvm-objdump', java='java', ghidra_home=str(root)))
                self.assertEqual(report['exit_code'], 0, report)

    def test_java_version_checked_against_ghidra_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.configured_distribution(root)
            for version, expected in [('1.8.0', 'fail'), ('17.0.2', 'fail'), ('21.0.1', 'pass'), ('26', 'fail')]:
                with patch.object(doctor, 'version_probe', return_value=('java version "' + version + '"', None)):
                    report = doctor.build_report(arguments(strict_re=True, java='java', ghidra_home=str(root)))
                self.assertEqual(check(report, 'java')['status'], expected)

    def test_explicit_extension_does_not_fall_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.configured_distribution(root)
            report = doctor.build_report(arguments(ghidra_home=str(root), ee_extension=str(root / 'missing')))
        self.assertEqual(check(report, 'emotion_engine')['status'], 'warn')

    def test_unknown_java_requirement_fails_strict_without_guessing(self):
        with patch.object(doctor, 'version_probe', return_value=('openjdk 21.0.1', None)):
            report = doctor.build_report(arguments(strict_re=True, java='java'))
        self.assertEqual(check(report, 'java')['status'], 'fail')
        self.assertIn('unverified', check(report, 'java')['message'])

    def test_real_cli_help_does_not_shadow_standard_library(self):
        for flags in ([], ['-I']):
            result = subprocess.run([sys.executable] + flags + ['-B', doctor.__file__, '--help'],
                                    capture_output=True, text=True, encoding='utf-8', timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--strict-re', result.stdout)

    def test_json_cli_returns_documented_exit_code(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = doctor.main(['--json'])
        report = json.loads(output.getvalue())
        self.assertEqual(code, report['exit_code'])
        self.assertEqual(report['mode'], 'basic')

    def test_java_home_path_is_used_without_environment_dump(self):
        with patch.dict(os.environ, {'JAVA_HOME': '/explicit/jdk', 'UNRELATED_SECRET': 'do-not-print'}), \
             patch.object(doctor, 'version_probe', return_value=('openjdk version "21"', None)) as probe:
            report = doctor.build_report(arguments())
        self.assertTrue(str(probe.call_args.args[0]).startswith('/explicit/jdk'))
        self.assertNotIn('do-not-print', json.dumps(report))


if __name__ == '__main__':
    unittest.main()
