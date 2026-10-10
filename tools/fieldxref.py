#!/usr/bin/env python3
"""fieldxref.py ELF off[,off...] [--stores]  -- list load/store instructions using a struct displacement.
Reads disasm/text.asm (llvm-objdump output). Groups hits by containing function (heuristic boundaries)."""
import sys, re, os, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps2elf import Elf
import symtab
from textinput import text_lines

def main():
    e = Elf(sys.argv[1]); e.analyze()
    offs = [int(x, 16) for x in sys.argv[2].split(',')]
    stores_only = '--stores' in sys.argv
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    names = symtab.load(root)
    pat = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')
    mem = re.compile(r'(-?0x[0-9a-f]+)\((\$\w+)\)')
    loads = {'lw','lh','lhu','lb','lbu','lwc1','ld','lwu','lq'}
    stores = {'sw','sh','sb','swc1','sd','sq'}
    hits = collections.defaultdict(list)
    for l in text_lines(os.path.join(root, 'disasm/text.asm')):
        m = pat.match(l)
        if not m: continue
        op = m.group(2)
        if op not in loads and op not in stores: continue
        mm = mem.search(m.group(3))
        if not mm or mm.group(2) == '$sp': continue
        o = int(mm.group(1), 16)
        if o not in offs: continue
        if stores_only and op not in stores: continue
        a = int(m.group(1), 16)
        f = e.func_of(a); f = f[0] if isinstance(f, tuple) else f
        hits[f].append('%x:%s+%x' % (a, op, o))
    for f in sorted(hits, key=lambda x: x or 0):
        print('%s %-22s %s' % (hex(f) if f else '?', names.get(f, ''), ' '.join(hits[f])))

if __name__ == '__main__':
    main()
