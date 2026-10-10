#!/usr/bin/env python3
"""Tiny helpers for poking at the stripped SLUS_209.73 ELF: address<->file mapping,
string lookup, lui/addiu cross references and a heuristic function table.

  python3 ps2elf.py <elf> strxref <substring>     # who references strings containing <substring>
  python3 ps2elf.py <elf> xref <hexaddr>          # who references / calls this address
  python3 ps2elf.py <elf> func <hexaddr>          # start/end of the function containing addr
  python3 ps2elf.py <elf> ptrs <hexaddr>          # data words that hold this address
  python3 ps2elf.py <elf> table <hexaddr> <n> [stride words]  # dump n rows of a pointer table
"""
import bisect, pickle, os, struct, sys


class Elf:
    def __init__(self, path):
        self.path = path
        self.d = open(path, "rb").read()
        d = self.d
        phoff, = struct.unpack_from("<I", d, 28)
        phentsize, phnum = struct.unpack_from("<HH", d, 42)
        self.segs = []
        for i in range(phnum):
            t, off, va, pa, fsz, msz, fl, al = struct.unpack_from("<8I", d, phoff + i * phentsize)
            if t == 1:
                self.segs.append((va, off, fsz, msz))
        shoff, = struct.unpack_from("<I", d, 32)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 46)
        secs = [struct.unpack_from("<10I", d, shoff + i * shentsize) for i in range(shnum)]
        stro = secs[shstrndx][4]
        self.sections = {}
        for s in secs:
            nm = d[stro + s[0]:d.index(b"\0", stro + s[0])].decode("latin1")
            self.sections[nm] = (s[3], s[4], s[5])  # addr, off, size
        self.text = self.sections[".text"]

    def off(self, va):
        for sva, soff, fsz, msz in self.segs:
            if sva <= va < sva + fsz:
                return soff + (va - sva)
        return None

    def u32(self, va):
        o = self.off(va)
        return None if o is None else struct.unpack_from("<I", self.d, o)[0]

    def cstr(self, va, maxlen=200):
        o = self.off(va)
        if o is None:
            return None
        e = self.d.find(b"\0", o, o + maxlen)
        if e < 0:
            e = o + maxlen
        s = self.d[o:e]
        if len(s) >= 2 and all(32 <= c < 127 or c in (9, 10, 13) for c in s):
            return s.decode("latin1")
        return None

    def in_text(self, va):
        a, _, sz = self.text
        return a <= va < a + sz

    # ---- analysis (cached) -------------------------------------------------
    def analyze(self):
        cache = self.path + ".xref.pickle"
        if os.path.exists(cache) and os.path.getmtime(cache) > os.path.getmtime(self.path):
            self.funcs, self.calls, self.refs = pickle.load(open(cache, "rb"))
            return
        ta, toff, tsz = self.text
        words = struct.unpack_from(f"<{tsz // 4}I", self.d, toff)
        funcs = set()
        calls = {}  # target -> [callsite]
        for i, w in enumerate(words):
            if w >> 26 == 3:  # jal
                tgt = ((ta + i * 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
                if self.in_text(tgt):
                    funcs.add(tgt)
                    calls.setdefault(tgt, []).append(ta + i * 4)
        # function pointers stored in data (vtables, script tables, ctors)
        for nm in (".data", ".rodata", ".ctors", ".dtors", ".sdata"):
            a, o, sz = self.sections[nm]
            for j in range(0, sz - 3, 4):
                v, = struct.unpack_from("<I", self.d, o + j)
                if self.in_text(v) and v % 4 == 0:
                    funcs.add(v)
        # code after "jr $ra; <delay>" that starts with a stack adjust is a function too
        for i in range(len(words) - 2):
            if words[i] == 0x03E00008:
                j = i + 2
                while j < len(words) and words[j] == 0:
                    j += 1
                if j < len(words) and (words[j] & 0xFFFF8000) == 0x27BD8000:  # addiu sp,sp,-N
                    funcs.add(ta + j * 4)
        funcs = sorted(funcs)
        fset = set(funcs)
        # lui/addiu|ori|load|store pairing, register state reset at function starts
        refs = {}  # target -> [site]
        hi = {}
        for i, w in enumerate(words):
            pc = ta + i * 4
            if pc in fset:
                hi = {}
            op = w >> 26
            rs, rt, imm = (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            if op == 0x0F:  # lui
                hi[rt] = imm << 16
            elif op in (0x09, 0x19) and rs in hi:  # addiu / daddiu
                v = (hi[rs] + simm) & 0xFFFFFFFF
                refs.setdefault(v, []).append(pc)
                if rt != rs:
                    pass
                else:
                    hi.pop(rs, None)
                    hi["v%d" % rt] = v
            elif op == 0x0D and rs in hi:  # ori
                refs.setdefault(hi[rs] | imm, []).append(pc)
            elif op in (0x20, 0x21, 0x23, 0x24, 0x25, 0x27, 0x28, 0x29, 0x2B, 0x31, 0x39, 0x37, 0x3F, 0x1E, 0x1F) and rs in hi:
                refs.setdefault((hi[rs] + simm) & 0xFFFFFFFF, []).append(pc)
        self.funcs, self.calls, self.refs = funcs, calls, refs
        pickle.dump((funcs, calls, refs), open(cache, "wb"))

    def func_of(self, va):
        i = bisect.bisect_right(self.funcs, va) - 1
        if i < 0:
            return None, None
        end = self.funcs[i + 1] if i + 1 < len(self.funcs) else self.text[0] + self.text[2]
        return self.funcs[i], end

    def find_strings(self, sub):
        out = []
        b = sub.encode()
        for nm in (".rodata", ".data", ".sdata"):
            a, o, sz = self.sections[nm]
            blob = self.d[o:o + sz]
            p = blob.find(b)
            while p >= 0:
                s = p
                while s > 0 and 32 <= blob[s - 1] < 127:
                    s -= 1
                out.append((a + s, self.cstr(a + s, 400)))
                p = blob.find(b, p + 1)
        return sorted(set(out))

    def ptrs_to(self, va):
        out = []
        pat = struct.pack("<I", va)
        for nm in (".data", ".rodata", ".sdata", ".ctors"):
            a, o, sz = self.sections[nm]
            blob = self.d[o:o + sz]
            p = blob.find(pat)
            while p >= 0:
                if p % 4 == 0:
                    out.append(a + p)
                p = blob.find(pat, p + 1)
        return out


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    e = Elf(sys.argv[1])
    e.analyze()
    cmd, arg = sys.argv[2], sys.argv[3]
    if cmd == "strxref":
        for va, s in e.find_strings(arg):
            print(f"0x{va:08x} {s!r}")
            for site in e.refs.get(va, []):
                f, _ = e.func_of(site)
                print(f"    ref @0x{site:08x}  in func 0x{f:08x}")
            for p in e.ptrs_to(va):
                print(f"    ptr @0x{p:08x}")
    elif cmd == "xref":
        va = int(arg, 16)
        for site in e.calls.get(va, []):
            f, _ = e.func_of(site)
            print(f"call @0x{site:08x}  in func 0x{f:08x}")
        for site in e.refs.get(va, []):
            f, _ = e.func_of(site)
            print(f"ref  @0x{site:08x}  in func 0x{f:08x}")
        for p in e.ptrs_to(va):
            print(f"ptr  @0x{p:08x}")
    elif cmd == "func":
        f, end = e.func_of(int(arg, 16))
        print(f"0x{f:08x} 0x{end:08x} size={end - f}")
    elif cmd == "ptrs":
        for p in e.ptrs_to(int(arg, 16)):
            print(f"0x{p:08x}")
    elif cmd == "table":
        va, n = int(arg, 16), int(sys.argv[4])
        stride = int(sys.argv[5]) if len(sys.argv) > 5 else 2
        for i in range(n):
            row = [e.u32(va + (i * stride + k) * 4) for k in range(stride)]
            desc = []
            for v in row:
                s = e.cstr(v) if v else None
                desc.append(f"0x{v:08x}" + (f" {s!r}" if s else (" <code>" if e.in_text(v) else "")))
            print(f"0x{va + i * stride * 4:08x}: " + " | ".join(desc))


if __name__ == "__main__":
    main()
