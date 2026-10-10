#!/usr/bin/env python3
"""Install/run an optional fresh-byte-verification pre-commit hook."""
from pathlib import Path
import sys
if __name__ == '__main__':
    sys.path[:] = [p for p in sys.path if Path(p or '.').resolve() != Path(__file__).resolve().parent]
import argparse
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MARKER = '# Open Champions reconstruction gate v1'
HOOK = '''#!/bin/sh
# Open Champions reconstruction gate v1
if command -v python3 >/dev/null 2>&1; then
    exec python3 tools/rebuild_gate.py
elif command -v python >/dev/null 2>&1; then
    exec python tools/rebuild_gate.py
else
    echo "Python 3 is required for the reconstruction gate." >&2
    exit 1
fi
'''


def git(*args, root=ROOT):
    result = subprocess.run(['git', *args], cwd=root, capture_output=True,
                            text=True, encoding='utf-8', check=False)
    if result.returncode:
        raise ValueError(result.stderr.strip() or 'Git command failed.')
    return result.stdout.strip()


def affects_rebuild(paths):
    return any(p.startswith('reconstructed/') or p.startswith('targets/SLUS-20973/') for p in paths)


def install(root=ROOT, compiler=None):
    configured = subprocess.run(['git', 'config', '--get', 'core.hooksPath'], cwd=root,
                                capture_output=True, text=True, check=False)
    if configured.returncode not in (0, 1):
        raise ValueError('Cannot inspect the configured hooks directory.')
    if configured.stdout.strip():
        raise ValueError('An existing core.hooksPath is configured; integrate the gate into that hook manually.')
    hook_path = Path(git('rev-parse', '--git-path', 'hooks/pre-commit', root=root))
    if not hook_path.is_absolute():
        hook_path = root / hook_path
    if hook_path.exists() and hook_path.read_text(encoding='utf-8') != HOOK:
        raise ValueError('An existing pre-commit hook is present; preserve it and integrate the gate manually.')
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    hook_path.write_text(HOOK, encoding='utf-8', newline='\n')
    hook_path.chmod(hook_path.stat().st_mode | 0o111)
    if compiler:
        git('config', '--local', 'champions.rebuildCompiler', str(Path(compiler).resolve()), root=root)
    print('Installed reconstruction gate. Original disc executable stays private.')


def run(root=ROOT):
    staged = git('diff', '--cached', '--name-only', '-z', root=root).split('\0')
    if not affects_rebuild(staged):
        return 0
    # Never verify an unstaged working copy and then commit different source/metadata.
    changed = git('diff', '--name-only', '-z', '--', 'reconstructed/',
                  'targets/SLUS-20973/', 'tools/rebuild.py', 'ghidra_funcs.tsv', root=root)
    if changed:
        raise ValueError('Reconstruction inputs contain unstaged edits; stage the intended reviewed versions before verification.')
    configured = subprocess.run(['git', 'config', '--get', 'champions.rebuildCompiler'],
                                cwd=root, capture_output=True, text=True, check=False)
    compiler = os.environ.get('CHAMPIONS_CXX') or configured.stdout.strip() or 'clang++'
    game = os.environ.get('CHAMPIONS_GAME') or str(root / 'SLUS_209.73')
    tool = str(root / 'tools/rebuild.py')
    for args in ([sys.executable, tool, 'check'],
                 [sys.executable, tool, 'verify', '--game', game, '--compiler', compiler,
                  '--report', str(root / 'work/rebuild/precommit-verification.json')]):
        result = subprocess.run(args, cwd=root, check=False)
        if result.returncode:
            return result.returncode
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--compiler', help='Remember an existing compiler path in local Git configuration during installation.')
    args = parser.parse_args()
    try:
        if args.install:
            install(compiler=args.compiler)
            return 0
        if args.compiler:
            raise ValueError('--compiler is an installation option; use CHAMPIONS_CXX when running the gate.')
        return run()
    except (OSError, ValueError) as exc:
        print(f'Reconstruction gate: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
