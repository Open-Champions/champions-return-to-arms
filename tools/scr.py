#!/usr/bin/env python3
"""Snowblind script.scr helpers (RTA layout).

  python3 scr.py info <script.scr>                 # entry points, imported built-ins, string pool
  python3 scr.py dis <script.scr>                  # readable listing of every entry point
  python3 scr.py scan-iso <game.iso> name [name..] # which level scripts import these built-ins

Header lives at +0x60:  +0x0c codeOff, +0x10 stringsOff, +0x14 endOff, +0x20 nInternal,
+0x24 internalOff, +0x28 nExternal, +0x2c externalOff (all relative to +0x60).
Internal/external records are 24 bytes: u32 value, char name[20]. Strings are stored as
big-endian 32-bit words, so each 4-byte group has to be reversed to read them.
"""
import mmap, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gob import gob_entries, lmp_entries
from find_hosts import iso_files

BASE = 0x60


def parse(d):
    code_off, str_off, end_off = struct.unpack_from("<III", d, BASE + 0x0c)
    n_int, int_off, n_ext, ext_off = struct.unpack_from("<IIII", d, BASE + 0x20)

    def recs(n, off):
        out = []
        for i in range(n):
            o = BASE + off + i * 24
            val, = struct.unpack_from("<I", d, o)
            out.append((val, d[o + 4:o + 24].split(b"\0")[0].decode("latin1")))
        return out
    return {
        "code": (BASE + code_off, BASE + str_off),
        "strings": (BASE + str_off, BASE + end_off),
        "internals": recs(n_int, int_off),
        "externals": recs(n_ext, ext_off),
    }


def strings(d, s, e):
    """Word-swap the string pool and split on NULs, keeping pool offsets."""
    raw = bytearray()
    for i in range(s, min(e, len(d)) - 3, 4):
        raw += d[i:i + 4][::-1]
    out, start = [], 0
    for i, c in enumerate(raw):
        if c == 0:
            if i > start:
                out.append((start, raw[start:i].decode("latin1", "replace")))
            start = i + 1
    return out


def info(path):
    d = open(path, "rb").read()
    p = parse(d)
    print(f"code 0x{p['code'][0]:x}..0x{p['code'][1]:x}  strings 0x{p['strings'][0]:x}..0x{p['strings'][1]:x}")
    print("entry points:")
    for val, name in p["internals"]:
        print(f"  0x{val:05x} {name}")
    print("imports:", " ".join(n for _, n in p["externals"]))
    print("strings:")
    for off, s in strings(d, *p["strings"]):
        if all(32 <= ord(c) < 127 for c in s):
            print(f"  +0x{off:04x} {s!r}")


def scan_iso(iso, wanted):
    with open(iso, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    hits = {w: [] for w in wanted}
    n = 0
    for path, lba, size in sorted(iso_files(m)):
        if not path.upper().endswith(".GOB"):
            continue
        gob = m[lba * 2048:lba * 2048 + size]
        for lname, loff, lsize in gob_entries(gob):
            lump = gob[loff:loff + lsize]
            try:
                ents = lmp_entries(lump)
            except Exception:
                continue
            for fname, foff, fsize in ents:
                if fname != "script.scr":
                    continue
                n += 1
                ext = {nm for _, nm in parse(lump[foff:foff + fsize])["externals"]}
                for w in wanted:
                    if w in ext:
                        hits[w].append(os.path.basename(path)[:-4])
    print(f"scanned {n} level scripts")
    for w in wanted:
        print(f"{w}: {' '.join(sorted(set(hits[w]))) or '-'}")


# Opcode semantics read out of the interpreter at 0x13ecf8 (threaded code; the loader at
# 0x13e6d0 swaps each opcode for a handler address from the table at 0x403150).
# A = accumulator, X = index register, sp = script stack. All 51 opcodes that the 120
# level scripts on the disc use are named; anything else prints as opNN.
OPS = {
    0x01: ("A = var[{0:#x}]", 1), 0x02: ("X = var[{0:#x}]", 1), 0x03: ("A = local[{0}]", 1), 0x04: ("X = local[{0}]", 1),
    0x09: ("A = mem[A]", 0), 0x0b: ("A = {0}", 1), 0x0c: ("X = {0}", 1), 0x0f: ("var[{0:#x}] = A", 1),
    0x11: ("local[{0}] = A", 1), 0x17: ("mem[X] = A", 0), 0x19: ("A = mem[X + A*4]", 0), 0x1b: ("A = X + A*4", 0),
    0x21: ("A = X", 0), 0x22: ("X = A", 0), 0x24: ("push A", 0), 0x25: ("push X", 0), 0x27: ("push {0}", 1),
    0x28: ("push var[{0:#x}]", 1), 0x2b: ("X = pop", 0), 0x2c: ("pop {0}", 1), 0x2e: ("enter", 0), 0x30: ("return", 0),
    0x31: ("call {0:#x}", 1), 0x33: ("jump {0:#x}", 1), 0x35: ("if A == 0 jump {0:#x}", 1),
    0x36: ("if A != 0 jump {0:#x}", 1), 0x37: ("if A == X jump {0:#x}", 1), 0x38: ("if A != X jump {0:#x}", 1),
    0x3d: ("if A < X jump {0:#x}", 1), 0x3e: ("if A <= X jump {0:#x}", 1), 0x3f: ("if A > X jump {0:#x}", 1),
    0x40: ("if A >= X jump {0:#x}", 1), 0x48: ("A = X * A", 0), 0x4a: ("A, X = X / A, X % A", 0),
    0x4e: ("A = X + A", 0), 0x50: ("A = X - A", 0), 0x54: ("A = !A", 0), 0x57: ("A = A + {0}", 1),
    0x58: ("A = A * {0}", 1), 0x59: ("A = 0", 0), 0x5a: ("X = 0", 0), 0x5b: ("var[{0:#x}] = 0", 1),
    0x5f: ("A = (A == X)", 0), 0x65: ("A = (A < X)", 0), 0x67: ("A = (X < A)", 0), 0x69: ("A = (A == {0})", 1),
    0x6d: ("var[{0:#x}]++", 1), 0x72: ("var[{0:#x}]--", 1), 0x79: ("check 0 <= A <= {0}", 1),
}
# opcodes whose single operand is a code address (relocated by the loader)
CODE_OPERAND = {0x31, 0x33, *range(0x35, 0x41), 0x81}
NO_OPERAND = {0x09, 0x17, 0x19, 0x1b, 0x21, 0x22, 0x23, 0x24, 0x25, 0x2a, 0x2b, 0x2e, 0x2f, 0x30, 0x32,
              *range(0x41, 0x44), *range(0x48, 0x57), 0x59, 0x5a, *range(0x5d, 0x69), 0x6b, 0x6c,
              0x6f, 0x70, 0x71, 0x74, 0x7a, 0x80}


def disassemble(path):
    d = open(path, "rb").read()
    p = parse(d)
    cs, ce = p["code"]
    pool = dict(strings(d, *p["strings"]))
    ext = [n for _, n in p["externals"]]
    entry = {val: name for val, name in p["internals"]}
    words = struct.unpack_from("<%dI" % ((ce - cs) // 4), d, cs)
    i, line = 0, None
    pending = []          # pushes since the last call, to print calls as f(a, b)
    while i < len(words):
        off, op = i * 4, words[i]
        if off in entry:
            print(f"\n{entry[off]}:")
        if op == 0x7d:    # source line marker
            line = words[i + 1]
            i += 3
            continue
        if op == 0x7b:
            n = words[i + 1]
            args = pending[:-1][::-1] if pending else []      # last push is the arg byte count
            print(f"  {off:04x}  A = {ext[n]}({', '.join(args)})" + (f"    ; line {line}" if line else ""))
            pending = []
            i += 2
            continue
        if op == 0x27:
            v = words[i + 1]
            pending.append(repr(pool[v]) if v in pool and v >= 8 else str(v if v < 0x80000000 else v - (1 << 32)))
            i += 2
            continue
        if op == 0x28:
            pending.append(f"var[{words[i + 1]:#x}]")
            i += 2
            continue
        if pending and op != 0x2c:
            print(f"  {off:04x}  (pushed {', '.join(pending)})")
            pending = []
        if op == 0x2c:
            pending = []
            i += 2
            continue
        if op in OPS:
            text, n = OPS[op]
            args = [w - (1 << 32) if w >= 0x80000000 and "#x" not in text else w for w in words[i + 1:i + 1 + n]]
            print(f"  {off:04x}  " + text.format(*args))
            i += 1 + n
        else:
            n = 0 if op in NO_OPERAND else 1
            print(f"  {off:04x}  op{op:02x} " + " ".join(f"{w:#x}" for w in words[i + 1:i + 1 + n]))
            i += 1 + n


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    if sys.argv[1] == "info":
        info(sys.argv[2])
    elif sys.argv[1] == "dis":
        disassemble(sys.argv[2])
    else:
        scan_iso(sys.argv[2], sys.argv[3:])
