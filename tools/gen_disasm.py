#!/usr/bin/env python3
"""Generate complete disassembly using MIPS-capable LLVM on macOS, Windows or Linux.

  python tools/gen_disasm.py SLUS_209.73
  python tools/gen_disasm.py SLUS_209.73 --objdump "C:\\Program Files\\LLVM\\bin\\llvm-objdump.exe"

Writes disasm/text.asm next to the ELF, including zero-valued instructions. --output
selects another destination. Existing output is replaced only after LLVM succeeds.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def objdump_candidates():
    """Yield installed candidates without requiring a shell or changing PATH."""
    for name in ['llvm-objdump'] + [f'llvm-objdump-{version}' for version in range(30, 13, -1)]:
        found = shutil.which(name)
        if found:
            yield found
    if sys.platform == 'darwin':
        for root in ('/opt/homebrew/opt', '/usr/local/opt'):
            for path in sorted(Path(root).glob('llvm*/bin/llvm-objdump'), reverse=True):
                if path.is_file():
                    yield str(path)
    if os.name == 'nt':
        for variable in ('ProgramFiles', 'ProgramFiles(x86)', 'LOCALAPPDATA'):
            root = os.environ.get(variable)
            if root:
                for relative in ('LLVM/bin/llvm-objdump.exe', 'Programs/LLVM/bin/llvm-objdump.exe'):
                    path = Path(root) / relative
                    if path.is_file():
                        yield str(path)


def discover_objdump(explicit=None):
    """Return a MIPS-capable executable path, or raise RuntimeError with diagnostics.

    An explicit executable is authoritative: an unsupported choice is an error,
    rather than silently selecting another installation. Probes have a 10s timeout.
    """
    if explicit:
        found = shutil.which(str(explicit))
        if not found:
            raise RuntimeError(f'LLVM executable not found: {explicit}')
        candidates = [found]
    else:
        candidates = objdump_candidates()
    failures, seen = [], set()
    for candidate in candidates:
        key = os.path.normcase(os.path.realpath(candidate))
        if key in seen:
            continue
        seen.add(key)
        try:
            result = subprocess.run([str(candidate), '--version'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=10, check=False)
            version = (result.stdout + result.stderr).decode('utf-8', errors='replace')
            if result.returncode == 0 and re.search(r'^\s*mips(?:64)?(?:el)?\s+-', version, re.MULTILINE):
                return str(candidate)
            failures.append(f'{candidate}: no usable MIPS target')
        except (OSError, subprocess.TimeoutExpired) as exc:
            failures.append(f'{candidate}: {exc}')
    detail = '; '.join(failures) if failures else 'no llvm-objdump executable found'
    raise RuntimeError(f'{detail}. Install LLVM with MIPS support or use --objdump PATH. '
                       'Apple\'s bundled LLVM does not include MIPS.')


def generate_disassembly(elf, output, executable):
    """Write native LLVM stdout bytes atomically, avoiding PowerShell transcoding."""
    elf, output = Path(elf).resolve(), Path(output).resolve()
    if not elf.is_file():
        raise ValueError(f'ELF file not found: {elf}')
    if elf == output:
        raise ValueError('output must differ from the ELF input')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=output.parent, delete=False) as target:
            temporary = Path(target.name)
            result = subprocess.run([str(executable), '-d', '-j', '.text', '--disassemble-zeroes',
                                     '--no-show-raw-insn', '--mcpu=mips3', str(elf)],
                                    stdout=target, stderr=subprocess.PIPE, check=False)
        if result.returncode:
            detail = result.stderr.decode('utf-8', errors='replace').strip()
            raise RuntimeError(f'LLVM failed (exit {result.returncode}): {detail}')
        # An empty/incorrect listing must never replace a previous usable file.
        with temporary.open('rb') as source:
            if not any(re.match(rb'\s*[0-9a-fA-F]+:\s+\S', line) for line in source):
                raise RuntimeError('LLVM returned no instruction lines; output unchanged')
        os.replace(temporary, output)  # All file handles are closed, including on Windows.
        return output
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--objdump', help='Path to a MIPS-capable llvm-objdump executable')
    parser.add_argument('--output', type=Path, help='Default: disasm/text.asm next to the ELF')
    args = parser.parse_args(argv)
    output = args.output or args.elf.resolve().parent / 'disasm' / 'text.asm'
    try:
        executable = discover_objdump(args.objdump)
        result = generate_disassembly(args.elf, output, executable)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    print(f'Wrote {result}\nLLVM: {executable}')
    return 0


if __name__ == '__main__':
    # Python 3.14 argparse lazily imports inspect; tools/dis.py must not shadow
    # its standard-library namesake. Keep imports of this helper side-effect free.
    tool_dir = Path(__file__).resolve().parent
    sys.path[:] = [entry for entry in sys.path if Path(entry).resolve() != tool_dir]
    sys.exit(main())
