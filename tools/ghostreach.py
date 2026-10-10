#!/usr/bin/env python3
"""ghostreach.py ROOTHEX [LO HI] [--depth N] [--all]

Static audit of what the local-player prediction ghost can touch.
Walks the direct-call graph (jal / j) from ROOT using Ghidra's function boundaries
(ghidra_funcs.tsv), and lists every store to an absolute address in [LO, HI) made by a
reachable function. Each function is tagged:
  G  contains a test of object flag 0x20000 (the ghost flag)
  P  reads one of the in-prediction byte flags 0x402795 / 0x4027a2 / 0x402796
  -  neither (nothing in the function can tell a ghost from a real player)
Virtual calls are not followed. Default range is the slot-0 player record."""
import sys, re, os, bisect, pickle, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import symtab

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_funcs():
    funcs = []
    for l in open(os.path.join(ROOT, 'ghidra_funcs.tsv')):
        ent, name, body = l.rstrip('\n').split('\t')
        rs = [tuple(int(x, 16) for x in r.split('-')) for r in body.split(',') if r]
        funcs.append((int(ent, 16), name, min(r[0] for r in rs), max(r[1] for r in rs)))
    funcs.sort(key=lambda f: f[2])
    return funcs

def load_ins():
    cache = os.path.join(ROOT, 'disasm/text.ins.pickle')
    src = os.path.join(ROOT, 'disasm/text.asm')
    if os.path.exists(cache) and os.path.getmtime(cache) > os.path.getmtime(src):
        return pickle.load(open(cache, 'rb'))
    pat = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')
    ins = []
    for l in open(src):
        m = pat.match(l)
        if m:
            ins.append((int(m.group(1), 16), m.group(2), m.group(3).split('<')[0].strip()))
    pickle.dump(ins, open(cache, 'wb'))
    return ins

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    depth = 99
    if '--depth' in sys.argv:
        depth = int(sys.argv[sys.argv.index('--depth') + 1]); args = [a for a in args if a != str(depth)]
    show_all = '--all' in sys.argv
    root = int(args[0], 16)
    lo, hi = (int(args[1], 16), int(args[2], 16)) if len(args) >= 3 else (0x4d8af0, 0x4d8af0 + 0x4c30)
    funcs = load_funcs()
    starts = [f[2] for f in funcs]
    def fn_of(a):
        i = bisect.bisect_right(starts, a) - 1
        if i >= 0 and funcs[i][2] <= a <= funcs[i][3]:
            return funcs[i][0]
        return None
    names = {f[0]: f[1] for f in funcs}
    names.update(symtab.load(ROOT))
    ins = load_ins()
    mem = re.compile(r'^(\$\w+), (-?0x[0-9a-f]+)\((\$\w+)\)$')
    stores = {'sw', 'sh', 'sb', 'swc1', 'sd'}
    loads = {'lw', 'lh', 'lhu', 'lb', 'lbu', 'lwc1', 'ld'}
    callees = collections.defaultdict(set)
    gstores = collections.defaultdict(list)   # fn -> [(addr, target)]
    tag = collections.defaultdict(set)
    vcalls = collections.Counter()
    reg = {}
    cur = None
    NODEST = stores | {'beq', 'bne', 'beqz', 'bnez', 'beql', 'bnel', 'beqzl', 'bnezl', 'bgez', 'bltz', 'blez', 'bgtz',
                       'bgezl', 'bltzl', 'blezl', 'bgtzl', 'b', 'jr', 'mtc1', 'dmtc1', 'ctc1', 'mthi', 'mtlo', 'nop',
                       'bc1f', 'bc1t', 'bc1fl', 'bc1tl', 'mult', 'multu', 'div', 'divu', 'syscall', 'break', 'sq',
                       'sdl', 'sdr', 'swl', 'swr', 'cache', 'sync', 'teq'}
    CALLER_SAVED = ['$%d' % n for n in list(range(1, 16)) + [24, 25, 31]] + ['$ra', '$at', '$v0', '$v1']
    for i, (a, op, ar) in enumerate(ins):
        f = fn_of(a)
        if f != cur:
            cur = f; reg = {}
        if f is None:
            continue
        parts = [x.strip() for x in ar.split(',')] if ar else []
        if op in ('jal', 'j'):
            try: t = int(ar, 16)
            except ValueError: t = None
            if t is not None:
                tf = fn_of(t)
                if tf is not None and (op == 'jal' or tf != f):
                    callees[f].add(tf)
            if op == 'jal':
                # the delay slot runs before the callee: handle it on the next iteration, then clobber
                pending_clobber = i + 1
            continue
        if op == 'jalr':
            vcalls[f] += 1
            continue
        if op == 'lui' and len(parts) == 2:
            reg[parts[0]] = ('c', int(parts[1], 16) << 16)
            continue
        if op == 'and' and len(parts) == 3:
            if reg.get(parts[1]) == ('c', 0x20000) or reg.get(parts[2]) == ('c', 0x20000):
                tag[f].add('G')
            reg.pop(parts[0], None)
            continue
        if op in ('addiu', 'ori') and len(parts) == 3:
            st = reg.get(parts[1])
            try: imm = int(parts[2], 16)
            except ValueError: imm = None
            if st and imm is not None:
                reg[parts[0]] = (st[0], ((st[1] + imm) if op == 'addiu' else (st[1] | imm)) & 0xffffffff)
            else:
                reg.pop(parts[0], None)
            continue
        if op in ('addu', 'daddu') and len(parts) == 3:
            s1, s2 = reg.get(parts[1]), reg.get(parts[2])
            if s1 and s2 and s1[0] == 'c' and s2[0] == 'c':
                reg[parts[0]] = ('c', (s1[1] + s2[1]) & 0xffffffff)
            elif (s1 or s2) and not (s1 and s2) and (s1 or s2)[1] >= 0x400000:
                reg[parts[0]] = ('b', (s1 or s2)[1])
            else:
                reg.pop(parts[0], None)
            continue
        if op == 'move' and len(parts) == 2:
            if parts[1] in reg: reg[parts[0]] = reg[parts[1]]
            else: reg.pop(parts[0], None)
            continue
        m = mem.match(ar)
        if m:
            st = reg.get(m.group(3))
            if st and st[1] >= 0x400000:
                v = (st[1] + int(m.group(2), 16)) & 0xffffffff
                if op in loads and v in (0x402795, 0x4027a2, 0x402796):
                    tag[f].add('P')
                if op in stores:
                    gstores[f].append((a, v))
        if op not in NODEST and parts and parts[0].startswith('$') and not parts[0].startswith('$f'):
            reg.pop(parts[0], None)
        if i and ins[i - 1][1] in ('jal', 'jalr'):
            for r in CALLER_SAVED: reg.pop(r, None)
    # BFS
    dist = {root: 0}; parent = {}
    q = collections.deque([root])
    while q:
        f = q.popleft()
        if dist[f] >= depth:
            continue
        for c in sorted(callees[f]):
            if c not in dist:
                dist[c] = dist[f] + 1; parent[c] = f; q.append(c)
    print('reachable functions: %d (virtual call sites not followed: %d)' % (len(dist), sum(vcalls[f] for f in dist)))
    rows = []
    for f in dist:
        hits = [(a, v) for a, v in gstores[f] if lo <= v < hi]
        if hits or show_all:
            rows.append((dist[f], f, hits))
    for d, f, hits in sorted(rows):
        path = []; x = f
        while x in parent and len(path) < 4:
            x = parent[x]; path.append(names.get(x, hex(x)))
        t = ''.join(sorted(tag[f])) or '-'
        offs = collections.Counter(v - lo for a, v in hits)
        print('d%d %s %08x %-22s via %s' % (d, t, f, names.get(f, ''), ' < '.join(path)))
        print('      ' + ' '.join('+%x%s' % (o, '' if n == 1 else 'x%d' % n) for o, n in sorted(offs.items())))

if __name__ == '__main__':
    main()
