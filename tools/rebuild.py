#!/usr/bin/env python3
"""Record original C++ function rebuilds against a privately supplied PS2 baseline.

check validates the ledger; candidates lists small unclaimed Ghidra bodies;
verify compiles self-contained C++ and compares complete function bytes;
progress reports recorded matches, never whole-game linking or playability.
No original bytes are included in reports or SVGs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LEDGER = ROOT / 'targets' / 'SLUS-20973' / 'rebuild.json'
HASH = re.compile(r'^[0-9a-f]{64}$')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, field):
    require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
            f'{field} must be a nonnegative integer')
    return value


def address(value):
    require(isinstance(value, str) and re.fullmatch(r'(?:0x)?[0-9a-fA-F]{1,8}', value),
            'address must be a 32-bit hexadecimal string')
    return int(value, 16)


def local_path(root, value):
    require(isinstance(value, str) and value and not Path(value).is_absolute(), 'expected a relative path')
    path = (root / value).resolve()
    require(path.is_relative_to(root.resolve()), f'path escapes repository: {value}')
    return path


class Elf32:
    """Bounded ELF32/little-endian/MIPS reader, including object function symbols."""
    def __init__(self, data):
        self.data = data
        require(len(data) >= 52 and data[:7] == b'\x7fELF\x01\x01\x01', 'expected ELF32 little-endian version 1')
        fields = struct.unpack_from('<HHIIIIIHHHHHH', data, 16)
        self.kind, self.machine = fields[:2]
        require(self.machine == 8, 'expected MIPS ELF machine 8')
        shoff, shentsize, shnum, shstrndx = fields[5], fields[10], fields[11], fields[12]
        require(shentsize >= 40 and 0 < shnum and shstrndx < shnum, 'unsupported ELF section table')
        self.slice(shoff, shentsize * shnum)
        self.sections = [struct.unpack_from('<10I', data, shoff + i * shentsize) for i in range(shnum)]
        strings = self.section_data(shstrndx)
        self.names = [self.string(strings, section[0]) for section in self.sections]

    def slice(self, offset, size):
        require(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset, 'ELF range exceeds file')
        return self.data[offset:offset + size]

    def section_data(self, index):
        require(0 <= index < len(self.sections), 'invalid ELF section index')
        section = self.sections[index]
        require(section[1] != 8, 'cannot read bytes from ELF NOBITS section')
        return self.slice(section[4], section[5])

    @staticmethod
    def string(table, offset):
        require(0 <= offset < len(table), 'ELF string offset exceeds table')
        end = table.find(b'\0', offset)
        require(end >= 0, 'unterminated ELF string')
        return table[offset:end].decode('utf-8', errors='strict')

    def named_section(self, name):
        indices = [i for i, value in enumerate(self.names) if value == name]
        require(len(indices) == 1, f'expected exactly one ELF {name} section')
        return indices[0], self.sections[indices[0]]

    def function(self, symbol):
        require(self.kind == 1, 'compiled output must be a relocatable ELF object')
        matches = []
        for table_index, section in enumerate(self.sections):
            if section[1] != 2:  # SHT_SYMTAB
                continue
            require(section[9] >= 16 and section[5] % section[9] == 0, 'malformed ELF symbol table')
            names = self.section_data(section[6])
            records = self.section_data(table_index)
            for offset in range(0, len(records), section[9]):
                name, value, size, info, other, index = struct.unpack_from('<IIIBBH', records, offset)
                if self.string(names, name) == symbol:
                    require(info & 15 == 2 and 0 < index < len(self.sections), 'symbol must be a defined ELF function')
                    matches.append((index, value, size))
        require(len(matches) == 1, f'expected exactly one defined function symbol: {symbol}')
        index, start, size = matches[0]
        section = self.sections[index]
        require(section[2] & 4 and size > 0, 'function must have a nonempty executable extent')
        contents = self.section_data(index)
        require(start <= len(contents) and size <= len(contents) - start, 'function extent exceeds its section')
        for table_index, relocation in enumerate(self.sections):
            if relocation[1] not in (4, 9) or relocation[7] != index:
                continue
            # Relocation widths vary (R_MIPS_64 writes eight bytes). Initially
            # require an entirely relocation-free candidate code section, rather
            # than guessing an instruction-width overlap for unknown kinds.
            require(relocation[5] == 0, 'candidate code section contains unresolved relocations')
        return contents[start:start + size]


def source_code(text):
    """Expose code tokens without mistaking literal contents for comments.

    This is a conservative lexical gate, not a C++ parser. Comments become
    whitespace (including their original newlines); literals become one inert
    token so a following # cannot incorrectly become a directive at line start.
    Raw strings are explicitly outside this initial supported source subset.
    """
    require('??' not in text, 'trigraph syntax is outside the initial self-contained scope')
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    # Clang also accepts whitespace between a splice's backslash and newline.
    text = re.sub(r'\\[ \t\v\f]*\n', '', text)
    numeric_token = re.compile(r"[0-9](?:[a-zA-Z0-9_.]|'(?=[a-zA-Z0-9_]))*")
    output, i = [], 0
    while i < len(text):
        start = i
        if text.startswith('//', i):
            end = text.find('\n', i + 2)
            i = len(text) if end < 0 else end
            output.append(' ' * (i - start))
        elif text.startswith('/*', i):
            end = text.find('*/', i + 2)
            require(end >= 0, 'unterminated C++ block comment')
            i = end + 2
            output.append(''.join('\n' if c == '\n' else ' ' for c in text[start:i]))
        elif text.startswith(('R"', 'u8R"', 'uR"', 'UR"', 'LR"'), i):
            raise ValueError('raw strings are outside the initial self-contained scope')
        elif text[i] in ('"', "'"):
            quote = text[i]
            i += 1
            while i < len(text) and text[i] != quote:
                require(text[i] != '\n', 'unterminated C++ literal')
                if text[i] == '\\':
                    i += 1
                i += 1
            require(i < len(text), 'unterminated C++ literal')
            i += 1
            output.append('L' + ' ' * (i - start - 1))
        elif '0' <= text[i] <= '9':
            # Keep numeric digit separators from being read as character quotes.
            token = numeric_token.match(text, i)[0]
            output.append(token)
            i += len(token)
        else:
            output.append(text[i])
            i += 1
    return ''.join(output)


def source_bytes(path):
    data = path.read_bytes()
    clean = source_code(data.decode('utf-8-sig'))
    require(not re.search(r'^\s*(?:#|%:)', clean, re.MULTILINE),
            'initial matching sources must be self-contained (no preprocessor directives)')
    require(not re.search(r'\b(?:asm|__asm|__asm__)\b', clean),
            'inline assembly is not credited as rebuilt C++')
    return data


def load_ledger(path=DEFAULT_LEDGER, root=ROOT):
    root = Path(root).resolve()
    ledger = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    require(isinstance(ledger, dict) and ledger.get('schema_version') == 1, 'unsupported ledger schema')
    target = ledger['target']
    require(isinstance(target, dict) and isinstance(target.get('text'), dict), 'invalid target definition')
    require(isinstance(target['id'], str) and target['id'], 'target id is required')
    require(isinstance(target['baseline_sha256'], str) and HASH.fullmatch(target['baseline_sha256']), 'invalid baseline SHA-256')
    require(target['elf_machine'] == 8, 'only MIPS machine 8 is supported')
    start, size = address(target['text']['address']), number(target['text']['size'], 'text.size')
    require(size > 0 and start + size <= 2**32, 'invalid target .text bounds')
    index_path = local_path(root, ledger['function_index'])
    index_data = index_path.read_bytes()
    index = {}
    for n, line in enumerate(index_data.decode('utf-8-sig').splitlines(), 1):
        parts = line.split('\t')
        require(len(parts) == 3, f'function index line {n}: expected three fields')
        entry = address(parts[0])
        ranges = []
        for extent in parts[2].split(','):
            bounds = extent.split('-')
            require(len(bounds) == 2, f'function index line {n}: bad extent')
            lo, hi = map(address, bounds)
            require(start <= lo <= hi < start + size, f'function index line {n}: outside .text')
            ranges.append((lo, hi + 1))
        require(entry not in index and any(lo <= entry < hi for lo, hi in ranges), 'duplicate or invalid Ghidra entry')
        index[entry] = {'name': parts[1], 'ranges': ranges}
    require(isinstance(ledger['functions'], list), 'functions must be a list')
    ids, extents = set(), []
    for item in ledger['functions']:
        require(isinstance(item, dict), 'function entries must be objects')
        ident = item['id']
        require(isinstance(ident, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', ident) and ident not in ids, 'invalid or duplicate function id')
        ids.add(ident)
        entry, length = address(item['address']), number(item['size'], 'function.size')
        require(length > 0 and entry % 4 == 0 and length % 4 == 0, 'function extent must contain whole MIPS instructions')
        require(entry in index and index[entry]['ranges'] == [(entry, entry + length)], 'function must match one complete contiguous Ghidra body')
        require(item['language'] == 'c++', 'only hand-authored C++ is credited')
        source = local_path(root, item['source'])
        require(source.suffix in ('.cpp', '.cc', '.cxx'), 'source must be a C++ file')
        source_bytes(source)
        require(isinstance(item['symbol'], str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', item['symbol']), 'use an unmangled extern C symbol')
        flags = item['compiler_args']
        require(isinstance(flags, list) and all(isinstance(flag, str) and flag.startswith('-') and '\0' not in flag for flag in flags), 'compiler_args must contain flags only (use = forms)')
        allowed = {'--no-default-config', '-ffreestanding', '-fno-pic', '-mno-abicalls',
                   '-fno-stack-protector', '-fno-exceptions', '-fno-rtti', '-fomit-frame-pointer',
                   '-fno-omit-frame-pointer', '-fno-builtin', '-fno-unwind-tables',
                   '-fno-asynchronous-unwind-tables', '-msoft-float', '-mhard-float',
                   '-fno-strict-aliasing', '-fwrapv', '-std=c++17'}
        require('--no-default-config' in flags, 'compiler_args must disable Clang default config')
        for flag in flags:
            require(flag in allowed or re.fullmatch(
                r'--target=mipsel-(?:none|unknown)-elf|-march=(?:mips[1-5]|r5900)|-mabi=(?:32|o32|n32|64)|-O[0123sz]', flag),
                f'unsupported compiler flag in initial leaf scope: {flag}')
        extents.append((entry, entry + length))
    ordered = sorted(extents)
    require(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), 'ledger function extents overlap')
    return ledger, index, digest(index_data)


def baseline_bytes(game, ledger):
    data = Path(game).read_bytes()
    require(digest(data) == ledger['target']['baseline_sha256'], 'baseline SHA-256 mismatch; no comparisons performed')
    elf = Elf32(data)
    require(elf.kind == 2, 'baseline must be an executable ELF')
    index, section = elf.named_section('.text')
    text = ledger['target']['text']
    require(section[3] == address(text['address']) and section[5] == text['size'] and section[2] & 4,
            'baseline .text bounds/flags do not match ledger')
    return elf.section_data(index)


def verify(ledger, index_hash, game, compiler, output_dir, root=ROOT):
    baseline = baseline_bytes(game, ledger)
    # Clang reads these outside argv, including with --no-default-config. Keep
    # effective options tied to the reviewed ledger and never echo their values.
    compiler_env = os.environ.copy()
    for name in ('CCC_OVERRIDE_OPTIONS', 'CL', '_CL_'):
        require(not compiler_env.get(name),
                f'unset {name} before verification; environment compiler options are not recorded')
        compiler_env.pop(name, None)
    executable = shutil.which(str(compiler))
    require(executable is not None, f'compiler not found: {compiler}')
    executable = str(Path(executable).resolve())
    probe = subprocess.run([executable, '--no-default-config', '--version'], capture_output=True,
                           timeout=15, check=False, env=compiler_env)
    require(probe.returncode == 0, 'compiler version probe failed')
    version = (probe.stdout + probe.stderr).decode('utf-8', errors='replace').strip().splitlines()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = {'schema_version': 1, 'scope': 'recorded-byte-exact-cpp-functions',
              'target': ledger['target']['id'], 'baseline_sha256': ledger['target']['baseline_sha256'],
              'ledger_sha256': digest(canonical(ledger)), 'function_index_sha256': index_hash,
              'verifier_sha256': digest(Path(__file__).read_bytes()),
              'recorded_at': datetime.now(timezone.utc).isoformat(),
              'compiler': {'name': Path(executable).name, 'sha256': digest(Path(executable).read_bytes()),
                           'version': version[0] if version else 'unknown'}, 'functions': []}
    base = address(ledger['target']['text']['address'])
    for item in ledger['functions']:
        source = local_path(Path(root), item['source'])
        result = {'id': item['id'], 'source_sha256': digest(source_bytes(source)),
                  'compiler_args': item['compiler_args'], 'status': 'failed'}
        obj = output_dir / (item['id'] + '.o')
        obj.unlink(missing_ok=True)  # Never accept a stale object from a failed compilation.
        command = [executable] + item['compiler_args'] + ['-c', str(source), '-o', str(obj.resolve())]
        try:
            compiled = subprocess.run(command, cwd=root, capture_output=True, timeout=120,
                                      check=False, env=compiler_env)
            require(digest(source.read_bytes()) == result['source_sha256'],
                    'source changed during compilation; retry with stable inputs')
            if compiled.returncode != 0:
                result['reason'] = f'compiler exited {compiled.returncode}; see private build log'
                (output_dir / (item['id'] + '.log')).write_bytes(compiled.stdout + compiled.stderr)
            else:
                object_data = obj.read_bytes()
                code = Elf32(object_data).function(item['symbol'])
                result['object_sha256'] = digest(object_data)
                require(len(code) == item['size'], 'emitted function extent differs from complete original body')
                offset = address(item['address']) - base
                original = baseline[offset:offset + item['size']]
                result.update({'size': len(code), 'original_sha256': digest(original), 'rebuilt_sha256': digest(code),
                               'status': 'matched' if code == original else 'mismatched'})
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            # Keep absolute local paths out of the shareable report.
            result['reason'] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        report['functions'].append(result)
    return report


def recorded_matches(report, ledger, index_hash, root=ROOT):
    require(report.get('schema_version') == 1 and report.get('scope') == 'recorded-byte-exact-cpp-functions', 'unsupported verification report')
    require(report.get('target') == ledger['target']['id'] and report.get('baseline_sha256') == ledger['target']['baseline_sha256'], 'report target/baseline mismatch')
    require(report.get('verifier_sha256') == digest(Path(__file__).read_bytes()), 'stale report: verifier changed')
    require(report.get('ledger_sha256') == digest(canonical(ledger)) and report.get('function_index_sha256') == index_hash, 'stale report: ledger or function index changed')
    require(HASH.fullmatch(report.get('compiler', {}).get('sha256', '')) is not None, 'report lacks compiler hash')
    results = report.get('functions')
    require(isinstance(results, list) and len(results) == len(ledger['functions']), 'report must cover exactly the ledger functions')
    by_id = {item['id']: item for item in ledger['functions']}
    seen, matched = set(), []
    for result in results:
        ident = result.get('id')
        require(ident in by_id and ident not in seen, 'unknown or duplicate report function')
        seen.add(ident)
        item = by_id[ident]
        require(result.get('source_sha256') == digest(source_bytes(local_path(Path(root), item['source'])))
                and result.get('compiler_args') == item['compiler_args'], 'stale report: source or compiler flags changed')
        require(result.get('status') in ('matched', 'mismatched', 'failed'), 'invalid report status')
        if result['status'] == 'matched':
            require(result.get('size') == item['size'] and HASH.fullmatch(result.get('object_sha256', ''))
                    and HASH.fullmatch(result.get('original_sha256', ''))
                    and result['original_sha256'] == result.get('rebuilt_sha256'), 'inconsistent match evidence')
            matched.append(item)
    return matched


def progress(ledger, index, index_hash, report=None, root=ROOT):
    matches = recorded_matches(report, ledger, index_hash, root) if report is not None else []
    size = sum(item['size'] for item in matches)
    total = ledger['target']['text']['size']
    return {'scope': 'recorded byte-exact C++ functions; no linked-game or runtime proof',
            'functions_matched': len(matches), 'functions_total': len(index),
            'bytes_matched': size, 'text_bytes_total': total, 'byte_percent': 100 * size / total,
            'report_supplied': report is not None}


def svg_report(stats):
    width = 560 * stats['byte_percent'] / 100
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="640" height="150" viewBox="0 0 640 150">'
            '<rect width="640" height="150" fill="#141923"/><g font-family="sans-serif" fill="#ffffff">'
            '<text x="24" y="30" font-size="18">Recorded byte-exact C++ functions</text>'
            f'<text x="24" y="56" font-size="14">{stats["functions_matched"]} / {stats["functions_total"]} functions; '
            f'{stats["byte_percent"]:.4f}% of original .text bytes</text>'
            '<rect x="24" y="76" width="560" height="14" fill="#343c4e"/>'
            f'<rect x="24" y="76" width="{width:.6f}" height="14" fill="#d9b66f"/>'
            '<text x="24" y="122" font-size="12">Recorded comparison only. No linked-game or gameplay claim.</text></g></svg>\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('check', 'candidates', 'verify', 'progress'):
        child = sub.add_parser(command)
        child.add_argument('--ledger', type=Path, default=DEFAULT_LEDGER)
        if command in ('check', 'progress'):
            child.add_argument('--report', type=Path)
        if command == 'candidates':
            child.add_argument('--limit', type=int, default=20)
            child.add_argument('--json', action='store_true')
        if command == 'verify':
            child.add_argument('--game', type=Path, required=True)
            child.add_argument('--compiler', required=True)
            child.add_argument('--output-dir', type=Path, default=ROOT / 'work/rebuild')
            child.add_argument('--report', type=Path)
        if command == 'progress':
            child.add_argument('--json', action='store_true')
            child.add_argument('--svg', type=Path)
    args = parser.parse_args(argv)
    try:
        ledger, index, index_hash = load_ledger(args.ledger)
        if args.command in ('check', 'progress') and args.report is None:
            sibling_report = args.ledger.with_name('verification.json')
            if sibling_report.is_file():
                args.report = sibling_report
        if args.command == 'check':
            if args.report:
                recorded_matches(json.loads(args.report.read_text(encoding='utf-8')), ledger, index_hash)
            print(f'Ledger valid: {len(ledger["functions"])} C++ candidates, {len(index)} indexed functions')
        elif args.command == 'candidates':
            require(args.limit >= 0, 'limit must be nonnegative')
            claimed = {address(item['address']) for item in ledger['functions']}
            candidates = [{'address': f'0x{entry:08x}', 'size': body['ranges'][0][1] - entry, 'name': body['name']}
                          for entry, body in index.items() if entry not in claimed and len(body['ranges']) == 1
                          and body['ranges'][0][0] == entry and (body['ranges'][0][1] - entry) % 4 == 0]
            candidates.sort(key=lambda item: (item['size'], item['address']))
            candidates = candidates[:args.limit]
            print(json.dumps(candidates, indent=2) if args.json else '\n'.join(f'{item["address"]}\t{item["size"]}\t{item["name"]}' for item in candidates))
        elif args.command == 'verify':
            report = verify(ledger, index_hash, args.game, args.compiler, args.output_dir)
            destination = args.report or args.output_dir / 'verification.json'
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
            matched = sum(item['status'] == 'matched' for item in report['functions'])
            print(f'{matched}/{len(report["functions"])} complete C++ functions byte-exact; report: {destination}')
            return 0 if matched == len(report['functions']) else 1
        else:
            report = json.loads(args.report.read_text(encoding='utf-8')) if args.report else None
            stats = progress(ledger, index, index_hash, report)
            if args.svg:
                args.svg.parent.mkdir(parents=True, exist_ok=True)
                args.svg.write_text(svg_report(stats), encoding='utf-8')
            print(json.dumps(stats, indent=2) if args.json else f'{stats["functions_matched"]}/{stats["functions_total"]} recorded byte-exact C++ functions; {stats["byte_percent"]:.4f}% of .text; no linked-game/runtime proof')
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    # Keep the local dis.py from shadowing inspect's standard-library dependency.
    tool_dir = Path(__file__).resolve().parent
    sys.path[:] = [entry for entry in sys.path if Path(entry).resolve() != tool_dir]
    sys.exit(main())
