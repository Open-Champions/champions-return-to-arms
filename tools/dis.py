#!/usr/bin/env python3
"""Print an annotated disassembly of the function containing an address.

  python3 dis.py <elf> <hexaddr> [max_lines]      # function containing addr
  python3 dis.py <elf> <start>:<end>              # explicit range

Needs disasm/text.asm next to the ELF (llvm-objdump -d -j .text --no-show-raw-insn --mcpu=mips3)
and optional names.tsv / symbols/*.tsv (addr<TAB>name) for known names.
"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps2elf import Elf
import symtab


def load_names(base):
    return symtab.load(base)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    e = Elf(sys.argv[1])
    e.analyze()
    base = os.path.dirname(os.path.abspath(sys.argv[1]))
    names = load_names(base)
    if ":" in sys.argv[2]:
        s, t = (int(x, 16) for x in sys.argv[2].split(":"))
    else:
        s, t = e.func_of(int(sys.argv[2], 16))
    maxl = int(sys.argv[3]) if len(sys.argv) > 3 else 400
    site2tgt = {}
    for tgt, sites in e.refs.items():
        for site in sites:
            site2tgt[site] = tgt
    asm = os.path.join(base, "disasm", "text.asm")
    ta = e.text[0]
    # objdump emits exactly one line per instruction after a 6 line header; seek by scanning
    want = set(range(s, t, 4))
    n = 0
    print(f"; func 0x{s:08x}..0x{t:08x} {names.get(s, '')}  callers={len(e.calls.get(s, []))}")
    with open(asm) as f:
        for line in f:
            m = re.match(r"\s*([0-9a-f]+):\s+(.*)", line)
            if not m:
                continue
            pc = int(m.group(1), 16)
            if pc < s:
                continue
            if pc >= t or n >= maxl:
                break
            ins = re.sub(r"\s*<\.text\+0x[0-9a-f]+>", "", m.group(2)).replace("\t", " ")
            note = ""
            if pc in site2tgt:
                tg = site2tgt[pc]
                st = e.cstr(tg)
                note = f"  ; -> 0x{tg:08x}" + (f" {st!r}" if st else "") + (f" [{names[tg]}]" if tg in names else "")
            mj = re.match(r"jal\s+0x([0-9a-f]+)", ins)
            if mj:
                tg = int(mj.group(1), 16)
                if tg in names:
                    note += f"  ; {names[tg]}"
            print(f"{pc:08x}: {ins}{note}")
            n += 1


if __name__ == "__main__":
    main()
