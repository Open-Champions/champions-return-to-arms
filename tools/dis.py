#!/usr/bin/env python3
"""Print an annotated disassembly of the function containing an address.

  python3 dis.py <elf> <hexaddr> [max_lines|all]  # function containing addr
  python3 dis.py <elf> <start>:<end> [max_lines|all]  # end-exclusive range

Defaults to 400 instructions; use all (or 0) for an unlimited listing.
Needs disasm/text.asm next to the ELF (llvm-objdump -d -j .text --no-show-raw-insn --mcpu=mips3).
Uses exact bodies in ghidra_funcs.tsv when available, otherwise warns about heuristic
bounds. Optional names.tsv / symbols/*.tsv supply annotations, not body boundaries.
"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps2elf import Elf
import symtab


def load_names(base):
    return symtab.load(base)


def ghidra_function(base, addr):
    """Return (entry, end-exclusive body ranges), or None if no body contains addr."""
    path = os.path.join(base, "ghidra_funcs.tsv")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip() or line.startswith("#"):
                continue
            try:
                entry, name, body = line.rstrip("\n").split("\t")
                entry = int(entry, 16)
                ranges = []
                for part in body.split(","):
                    if not part:
                        continue
                    lo, hi = (int(x, 16) for x in part.split("-"))
                    if hi < lo:
                        raise ValueError("reversed body range")
                    ranges.append((lo, hi + 1))  # Ghidra exports inclusive byte ends.
                if not ranges:
                    raise ValueError("empty body")
            except ValueError as exc:
                raise ValueError(f"{path}:{n}: malformed function body") from exc
            if any(lo <= addr < hi for lo, hi in ranges):
                return entry, sorted(ranges)
    return None


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if not 2 <= len(args) <= 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        maxl = 400 if len(args) == 2 else (0 if args[2] == "all" else int(args[2]))
        if maxl < 0:
            raise ValueError("max_lines must be nonnegative, or all")
        e = Elf(args[0])
        base = os.path.dirname(os.path.abspath(args[0]))
        names = load_names(base)
        if ":" in args[1]:
            s, t = (int(x, 16) for x in args[1].split(":"))
            if s >= t or not e.in_text(s) or not e.in_text(t - 1):
                raise ValueError("range must be nonempty and inside .text")
            ranges = [(s, t)]
            source = "explicit range"
        else:
            addr = int(args[1], 16)
            if not e.in_text(addr):
                raise ValueError(f"address 0x{addr:08x} is outside .text")
            body = ghidra_function(base, addr)
            if body:
                s, ranges = body
                source = "Ghidra body"
            else:
                e.analyze()
                s, t = e.func_of(addr)
                if s is None or t is None or not s <= addr < t:
                    raise ValueError(f"no function found containing 0x{addr:08x}")
                ranges = [(s, t)]
                source = "heuristic bounds"
                print("warning: no Ghidra body contains this address; using heuristic bounds, "
                      "which may split or combine functions", file=sys.stderr)
        e.analyze()
        site2tgt = {site: tgt for tgt, sites in e.refs.items() for site in sites}
        spans = ", ".join(f"0x{lo:08x}..0x{hi:08x}" for lo, hi in ranges)
        print(f"; func 0x{s:08x} {names.get(s, '')}  callers={len(e.calls.get(s, []))} "
              f"[{source}; end-exclusive ranges: {spans}]")
        n = 0
        total = 0
        with open(os.path.join(base, "disasm", "text.asm")) as f:
            for line in f:
                m = re.match(r"\s*([0-9a-fA-F]+):\s+(.*)", line)
                if not m:
                    continue
                pc = int(m.group(1), 16)
                if not any(lo <= pc < hi for lo, hi in ranges):
                    continue
                total += 1
                if maxl and n >= maxl:
                    continue
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
        if total > n:
            print(f"; truncated: shown {n} of {total} instructions ({total - n} omitted); "
                  "use max_lines=all (positional 'all') for the full listing")
        if not total:
            print("error: no disassembly instructions found in selected body/range", file=sys.stderr)
            return 1
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
