#!/usr/bin/env python3
"""gxref.py ELF ADDRHEX [...] -- list instructions that load/store a global via lui+displacement
(or gp-less absolute addressing), marking reads (R) and writes (W). Uses disasm/text.asm annotations
computed here by tracking the most recent lui per register inside a small window."""
import sys, re, os, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps2elf import Elf
import symtab
from textinput import text_lines

def main():
    e = Elf(sys.argv[1]); e.analyze()
    targets = {int(x, 16) for x in sys.argv[2:]}
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    names = symtab.load(root)
    pat = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')
    mem = re.compile(r'^(\$\w+), (-?0x[0-9a-f]+)\((\$\w+)\)$')
    loads = {'lw','lh','lhu','lb','lbu','lwc1','ld','lwu'}
    stores = {'sw','sh','sb','swc1','sd'}
    lui = {}
    hits = collections.defaultdict(list)
    n = 0
    for l in text_lines(os.path.join(root, 'disasm/text.asm')):
        m = pat.match(l)
        if not m: continue
        a = int(m.group(1), 16); op = m.group(2); args = m.group(3)
        n += 1
        if op == 'lui':
            r, v = [x.strip() for x in args.split(',')]
            lui[r] = (int(v, 16) << 16, n)
            continue
        if op == 'addiu':
            p = [x.strip() for x in args.split(',')]
            if len(p) == 3 and p[1] in lui and n - lui[p[1]][1] < 64:
                try: v = (lui[p[1]][0] + int(p[2], 16)) & 0xffffffff
                except ValueError: continue
                if v in targets:
                    f = e.func_of(a); f = f[0] if isinstance(f, tuple) else f
                    hits[(v, f)].append('%x:&' % a)
            continue
        mm = mem.match(args)
        if not mm or (op not in loads and op not in stores): continue
        base = mm.group(3)
        if base in lui and n - lui[base][1] < 64:
            v = (lui[base][0] + int(mm.group(2), 16)) & 0xffffffff
            if v in targets:
                f = e.func_of(a); f = f[0] if isinstance(f, tuple) else f
                hits[(v, f)].append('%x:%s' % (a, 'W' if op in stores else 'R'))
    for (v, f) in sorted(hits, key=lambda k: (k[0], k[1] or 0)):
        print('%08x %s %-26s %s' % (v, hex(f) if f else '?', names.get(f, ''), ' '.join(hits[(v, f)])))

if __name__ == '__main__':
    main()
