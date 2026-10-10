#!/usr/bin/env python3
"""Read-only native tooling preflight; this repository has no native game runtime.

Run: python3 tools/doctor.py [--json]
     python3 tools/doctor.py --strict-re --game /path/to/SLUS_209.73
Checks explicit files, PATH/usual LLVM install locations, and GHIDRA_HOME/JAVA_HOME.
Version commands have a timeout; Ghidra and the game are never launched.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

# Load the shared sibling by file, without making tools/dis.py shadow stdlib dis.
_spec = importlib.util.spec_from_file_location(
    'champions_gen_disasm', Path(__file__).with_name('gen_disasm.py'))
_generator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_generator)
discover_objdump = _generator.discover_objdump

GAME_SHA256 = '292f6f48e3609c0026def2307d76c222cd5b389303d53b89b0e107d7b1dcd675'
TIMEOUT = 8


def version_probe(command, flag):
    """Return version output only to the caller; never echo arbitrary diagnostics."""
    try:
        result = subprocess.run([str(command), flag], capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=TIMEOUT,
                                check=False, shell=False)
    except subprocess.TimeoutExpired:
        return None, 'Version command timed out.'
    except OSError:
        return None, 'Version command could not run; check its path and permissions.'
    if result.returncode:
        return None, 'Version command failed; check the selected installation.'
    return result.stdout + '\n' + result.stderr, None


def properties(path):
    """Read a small configuration file, not arbitrary environment contents."""
    with path.open('r', encoding='utf-8', errors='replace') as stream:
        text = stream.read(65537)
    if len(text) > 65536:
        raise ValueError('Configuration file exceeds 64 KiB.')
    values = {}
    for line in text.splitlines():
        if '=' in line and not line.lstrip().startswith(('#', '!')):
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip()
    return values


def executable(override, name):
    # An explicit choice must never silently fall back to an unrelated executable.
    if override:
        return str(Path(override).expanduser())
    return shutil.which(name)


def extension_ready(root):
    """Check only the selected extension's metadata and immediate language folder."""
    try:
        props = properties(root / 'extension.properties')
        if 'emotionengine' not in props.get('name', '').lower():
            return False
        folder = root / 'data' / 'languages'
        for path in folder.glob('*.ldefs'):
            with path.open('r', encoding='utf-8', errors='replace') as stream:
                if 'r5900:LE:32:default' in stream.read(65536):
                    return True
    except (OSError, ValueError):
        pass
    return False


def build_report(args):
    checks = []

    def add(name, ok, message, required=False):
        status = 'pass' if ok else ('fail' if required else 'warn')
        checks.append({'name': name, 'status': status, 'message': message})

    checks.append({'name': 'host', 'status': 'info',
                   'message': '{} / {}'.format(platform.system(), platform.machine())})
    add('python', sys.version_info >= (3, 8),
        'Python {}.{}.{}; tooling preflight requires Python 3.8 or newer.'.format(
            *sys.version_info[:3]), required=True)
    checks.append({'name': 'native_tools', 'status': 'info',
                   'message': 'Python analysis and symbol tools run natively without an emulator. '
                              'Some analysis commands need your local disc files or generated disassembly.'})
    checks.append({'name': 'native_game', 'status': 'info',
                   'message': 'No native Mac or Windows game runtime exists in this repository. '
                              'Passing these checks does not make the game playable.'})

    if args.game:
        try:
            path = Path(args.game).expanduser()
            if not path.is_file():
                raise OSError('Not a regular file')
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            actual = digest.hexdigest()
            add('game', actual == GAME_SHA256,
                'SHA-256 {}. {}'.format(actual, 'Matches US v2.00.' if actual == GAME_SHA256
                                       else 'Wrong executable for this address map; use your US v2.00 disc executable.'),
                required=True)
        except OSError:
            add('game', False, 'Cannot read --game as a regular file; select your local SLUS_209.73.', True)
    else:
        add('game', False, 'No game file checked. Supply --game /path/to/SLUS_209.73 for an identity check.',
            args.strict_re)

    try:
        discover_objdump(args.llvm_objdump)
        add('llvm_mips', True,
            'MIPS-capable llvm-objdump found using the disassembly generator discovery; decoding was not executed.')
    except RuntimeError:
        add('llvm_mips', False,
            'No usable MIPS-capable llvm-objdump found. Select a working build with --llvm-objdump; '
            'the selected program must successfully list a MIPS target with --version.', args.strict_re)

    ghidra_value = args.ghidra_home or os.environ.get('GHIDRA_HOME')
    ghidra = Path(ghidra_value).expanduser() if ghidra_value else None
    props = {}
    configured = False
    if ghidra:
        try:
            props = properties(ghidra / 'Ghidra' / 'application.properties')
            launcher = ghidra / 'support' / ('analyzeHeadless.bat' if platform.system() == 'Windows' else 'analyzeHeadless')
            configured = launcher.is_file()
        except (OSError, ValueError):
            pass
    add('ghidra', configured,
        'Ghidra configuration and host launcher found; startup not tested.' if configured else
        'Set --ghidra-home or GHIDRA_HOME to an extracted Ghidra distribution with its support launcher.', args.strict_re)

    java = args.java
    if not java and os.environ.get('JAVA_HOME'):
        java = str(Path(os.environ['JAVA_HOME']) / 'bin' / ('java.exe' if platform.system() == 'Windows' else 'java'))
    java = executable(java, 'java')
    output, error = version_probe(java, '-version') if java else (None, 'Java not found; set --java or JAVA_HOME, or add java to PATH.')
    match = re.search(r'(?:openjdk|java)\s+(?:version\s+)?"?(\d+)(?:\.(\d+))?', output or '', re.I)
    major = int(match.group(2)) if match and match.group(1) == '1' and match.group(2) else int(match.group(1)) if match else None
    minimum = props.get('application.java.min', '')
    maximum = props.get('application.java.max', '')
    limits_known = minimum.isdigit()
    compatible = major is not None and (not limits_known or major >= int(minimum)) and (not maximum.isdigit() or major <= int(maximum))
    java_ok = compatible and (limits_known or not args.strict_re)
    if error:
        message = error + ' Select a Ghidra-supported JDK using --java or JAVA_HOME.'
    elif major is None:
        message = 'Java version could not be recognized; select --java for your Ghidra-supported JDK.'
    elif limits_known:
        message = 'Java {} detected; configured Ghidra requires {}{}.'.format(major, minimum, '–' + maximum if maximum.isdigit() else '+')
        if not compatible:
            message += ' Select a compatible JDK with --java or JAVA_HOME.'
    else:
        message = 'Java {} detected; Ghidra Java compatibility is unverified (no numeric application.java.min).'.format(major)
    add('java', java_ok, message, args.strict_re)

    roots = [Path(args.ee_extension).expanduser()] if args.ee_extension else []
    if not roots and ghidra:
        # Only distribution-local extension names; no home-directory or disk search.
        directory = ghidra / 'Ghidra' / 'Extensions'
        try:
            roots = [p for p in directory.iterdir() if 'emotionengine' in p.name.lower() and p.is_dir()]
        except OSError:
            pass
    ready = any(extension_ready(p) for p in roots)
    add('emotion_engine', ready,
        'Emotion Engine extension metadata and r5900 language definition found; Ghidra loading not tested.' if ready else
        'Select the installed ghidra-emotionengine-reloaded folder with --ee-extension; r5900 language configuration is unverified.', args.strict_re)
    code = int(any(check['status'] == 'fail' for check in checks))
    return {'mode': 'strict-re' if args.strict_re else 'basic', 'native_game_runtime': False,
            'checks': checks, 'exit_code': code}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--strict-re', action='store_true', help='Require game identity and optional RE prerequisites too.')
    parser.add_argument('--game', help='Explicit path to a local disc executable; never executed.')
    parser.add_argument('--llvm-objdump', help='Path to LLVM objdump; only --version is run.')
    parser.add_argument('--java', help='Path to Java; only -version is run.')
    parser.add_argument('--ghidra-home', help='Ghidra distribution root (otherwise GHIDRA_HOME).')
    parser.add_argument('--ee-extension', help='Installed Emotion Engine extension root.')
    parser.add_argument('--json', action='store_true', help='Emit a machine-readable report.')
    args = parser.parse_args(argv)
    report = build_report(args)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for check in report['checks']:
            print('[{}] {}: {}'.format(check['status'].upper(), check['name'], check['message']))
        print('Result: {} ({} preflight; no game execution).'.format(
            'PASS' if not report['exit_code'] else 'FAIL', report['mode']))
    return report['exit_code']


if __name__ == '__main__':
    # Direct script execution puts tools/ first; argparse may lazily import inspect.
    # All sibling code is already loaded above, so prefer the real standard library.
    tool_dir = Path(__file__).resolve().parent
    sys.path[:] = [entry for entry in sys.path if Path(entry).resolve() != tool_dir]
    sys.exit(main())
