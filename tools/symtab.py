#!/usr/bin/env python3
"""Symbol table loader shared by the tools.

Symbols live in tab-separated files: address (hex, no 0x), name, optional note.
  names.tsv        the core list
  symbols/*.tsv    one file per subsystem (see CONTRIBUTING.md)
Lines starting with # are comments. Later files do not override earlier ones; a conflict
(same address, different name) is reported by `python3 tools/symtab.py check`.

  python3 tools/symtab.py check            # report conflicts and malformed lines
  python3 tools/symtab.py merge OUT.tsv    # write one combined file (for ApplyNames.java)
"""
import glob, os, re, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def files(root=ROOT):
    core = os.path.join(root, 'names.tsv')
    out = [core] if os.path.exists(core) else []
    return out + sorted(glob.glob(os.path.join(root, 'symbols', '*.tsv')))


def rows(root=ROOT):
    """Yield (addr, name, note, file, lineno) for every well-formed line."""
    for f in files(root):
        with open(f, encoding='utf-8', errors='replace') as source:
            for n, l in enumerate(source, 1):
                l = l.rstrip('\n')
                if not l.strip() or l.startswith('#'):
                    continue
                p = l.split('\t')
                if (len(p) not in (2, 3) or not re.fullmatch(r'[0-9a-fA-F]{1,8}', p[0])
                        or not p[1].strip() or '\ufffd' in l):
                    yield None, l, '', f, n
                    continue
                yield int(p[0], 16), p[1].strip(), (p[2] if len(p) > 2 else ''), f, n


def load(root=ROOT):
    """addr -> name. First definition of an address wins."""
    names = {}
    for a, name, note, f, n in rows(root):
        if a is not None:
            names.setdefault(a, name)
    return names


def main(argv=None, root=ROOT):
    args = sys.argv[1:] if argv is None else argv
    cmd = args[0] if args else 'check'
    if cmd not in ('check', 'merge') or (cmd == 'merge' and len(args) != 2) or (cmd == 'check' and len(args) > 1):
        print('usage: symtab.py check | symtab.py merge OUT.tsv', file=sys.stderr)
        return 2
    seen, bad, conflicts = {}, 0, 0
    merged = []
    for a, name, note, f, n in rows(root):
        rel = os.path.relpath(f, root)
        if a is None:
            bad += 1
            print('malformed  %s:%d  %s' % (rel, n, name[:60]))
            continue
        if a in seen and seen[a][0] != name:
            conflicts += 1
            print('conflict   %08x  %s (%s) vs %s (%s:%d)' % (a, seen[a][0], seen[a][1], name, rel, n))
            continue
        if a not in seen:
            seen[a] = (name, rel)
            merged.append((a, name, note))
    print('%d symbols from %d files, %d conflicts, %d malformed lines' % (len(seen), len(files(root)), conflicts, bad))
    if bad or conflicts:
        if cmd == 'merge':
            print('merge aborted; output unchanged', file=sys.stderr)
        return 1
    if cmd == 'merge':
        # Validate every row before creating a temporary file, then replace atomically.
        out = os.path.abspath(args[1])
        temp = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                             dir=os.path.dirname(out), delete=False) as o:
                temp = o.name
                for a, name, note in sorted(merged):
                    o.write('%08x\t%s\t%s\n' % (a, name, note))
            os.replace(temp, out)
        except OSError as exc:
            print('merge failed: %s' % exc, file=sys.stderr)
            return 1
        finally:
            if temp and os.path.exists(temp):
                os.unlink(temp)
    return 0


if __name__ == '__main__':
    sys.exit(main())
