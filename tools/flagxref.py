#!/usr/bin/env python3
"""flagxref.py ELF MASKHEX [fieldoff=0xc] -- find tests/sets/clears of a flag bit in a struct word.
Heuristic: an andi/ori (or lui+and/or for high bits) whose source register was loaded from fieldoff(reg)
within the previous 6 instructions."""
import sys, re, os, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps2elf import Elf
import symtab

def main():
    e = Elf(sys.argv[1]); e.analyze()
    mask = int(sys.argv[2], 16)
    off = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0xc
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    names = symtab.load(root)
    pat = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')
    ins = []
    for l in open(os.path.join(root, 'disasm/text.asm')):
        m = pat.match(l)
        if m: ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
    hi = mask >> 16 if mask & 0xffff == 0 else None
    inv = (~mask) & 0xffffffff
    out = collections.defaultdict(list)
    ld = re.compile(r'^(\$\w+), 0x%x\((\$\w+)\)$' % off)
    for i, (a, op, args) in enumerate(ins):
        kind = None
        parts = [x.strip() for x in args.split(',')]
        if hi is None:
            if op == 'andi' and len(parts) == 3 and parts[2] == hex(mask): kind = 'test'
            elif op == 'ori' and len(parts) == 3 and parts[2] == hex(mask): kind = 'set'
            elif op == 'addiu' and len(parts) == 3 and parts[1] == '$zero' and parts[2] == '-0x%x' % (mask + 1): kind = 'clrmask'
        else:
            if op == 'lui' and len(parts) == 2 and parts[1] == hex(hi): kind = 'lui'
            elif op == 'lui' and len(parts) == 2 and parts[1] == hex((inv >> 16) & 0xffff) and (inv & 0xffff) == 0xffff: kind = 'clrmask'
        if not kind: continue
        win = ins[max(0, i - 6):i + 7]
        loads = [x for x in win if x[1] == 'lw' and ld.match(x[2])]
        stores = [x for x in win if x[1] == 'sw' and ld.match(x[2])]
        if not loads and not stores: continue
        if kind == 'lui':
            reg = parts[0]
            nxt = ins[i + 1:i + 5]
            if any(o == 'or' and reg in ar for _, o, ar in nxt): kind = 'set'
            elif any(o == 'and' and reg in ar for _, o, ar in nxt): kind = 'test'
            else: continue
        if kind == 'clrmask':
            kind = 'clear'
        f = e.func_of(a); f = f[0] if isinstance(f, tuple) else f
        out[f].append('%x:%s' % (a, kind))
    for f in sorted(out, key=lambda x: x or 0):
        print('%s %-24s %s' % (hex(f) if f else '?', names.get(f, ''), ' '.join(out[f])))

if __name__ == '__main__':
    main()
