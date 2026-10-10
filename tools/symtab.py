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
import glob, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def files(root=ROOT):
    core = os.path.join(root, 'names.tsv')
    out = [core] if os.path.exists(core) else []
    return out + sorted(glob.glob(os.path.join(root, 'symbols', '*.tsv')))


def rows(root=ROOT):
    """Yield (addr, name, note, file, lineno) for every well-formed line."""
    for f in files(root):
        for n, l in enumerate(open(f, encoding='utf-8', errors='replace'), 1):
            l = l.rstrip('\n')
            if not l.strip() or l.startswith('#'):
                continue
            p = l.split('\t')
            try:
                a = int(p[0], 16)
            except ValueError:
                yield None, l, '', f, n
                continue
            if len(p) < 2 or not p[1].strip():
                yield None, l, '', f, n
                continue
            yield a, p[1].strip(), (p[2] if len(p) > 2 else ''), f, n


def load(root=ROOT):
    """addr -> name. First definition of an address wins."""
    names = {}
    for a, name, note, f, n in rows(root):
        if a is not None:
            names.setdefault(a, name)
    return names


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'check'
    seen, bad, conflicts = {}, 0, 0
    merged = []
    for a, name, note, f, n in rows():
        rel = os.path.relpath(f, ROOT)
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
    if cmd == 'merge':
        with open(sys.argv[2], 'w') as o:
            for a, name, note in sorted(merged):
                o.write('%08x\t%s\t%s\n' % (a, name, note))
    print('%d symbols from %d files, %d conflicts, %d malformed lines' % (len(seen), len(files()), conflicts, bad))
    sys.exit(1 if (bad or conflicts) and cmd == 'check' else 0)


if __name__ == '__main__':
    main()
