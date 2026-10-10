#!/usr/bin/env python3
"""GCC 2.95 vtable helpers for SLUS_209.73 (entries are {s16 delta, s16 pad, u32 fn};
entry 0's fn is the class's type_info getter, which references the mangled class name).

  python3 vtab.py <elf> list                 # every vtable found, with class name
  python3 vtab.py <elf> show <hexaddr|Class> # entries of one vtable, marking functions
                                             # that appear in no other class's vtable
"""
import os, re, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ps2elf import Elf


def tf_name(e, fn):
    """Class name referenced by a type_info getter function, or None."""
    s, t = e.func_of(fn)
    if s != fn or t - s > 0x100:
        return None
    site2tgt = {}
    for tgt, sites in e.refs.items():
        for site in sites:
            if s <= site < t:
                st = e.cstr(tgt)
                if st and re.match(r"^P?\d+[A-Za-z_]\w*$", st):
                    return re.sub(r"^\d+", "", st)
    return None


def find_vtables(e):
    """Scan .data for {0, tf_fn} headers followed by {delta, fn} entries."""
    a, o, sz = e.sections[".data"]
    cache = {}
    out = {}
    for j in range(0, sz - 15, 4):
        d0, fn0 = struct.unpack_from("<II", e.d, o + j)
        if d0 != 0 or not e.in_text(fn0):
            continue
        if fn0 not in cache:
            cache[fn0] = tf_name(e, fn0)
        name = cache[fn0]
        if not name:
            continue
        ents = []
        k = j + 8
        while k + 8 <= sz:
            delta, pad, fn = struct.unpack_from("<hhI", e.d, o + k)
            if not (e.in_text(fn) or fn == 0) or pad != 0 or (fn == 0 and delta != 0):
                break
            if fn == 0 and len(ents) > 0 and ents[-1][1] == 0:
                break
            ents.append((delta, fn))
            k += 8
        while ents and ents[-1][1] == 0:
            ents.pop()
        if len(ents) >= 2:
            out[a + j] = (name, ents)
    # vtables sit back to back, so a table ends where the next one's header begins
    starts = sorted(out)
    for cur, nxt in zip(starts, starts[1:]):
        name, ents = out[cur]
        out[cur] = (name, ents[:max(0, (nxt - cur) // 8 - 1)])
    return out


def main():
    e = Elf(sys.argv[1])
    e.analyze()
    vts = find_vtables(e)
    if sys.argv[2] == "list":
        for addr, (name, ents) in sorted(vts.items()):
            print(f"0x{addr:08x} {name:28} {len(ents)} entries")
        return
    key = sys.argv[3]
    targets = [a for a, (n, _) in vts.items() if n == key or f"{a:x}" == key.lower().replace("0x", "")]
    owners = {}
    for a, (n, ents) in vts.items():
        for _, fn in ents:
            owners.setdefault(fn, set()).add(n)
    for a in sorted(targets):
        name, ents = vts[a]
        print(f"vtable 0x{a:08x} class {name}")
        for i, (delta, fn) in enumerate(ents):
            others = sorted(owners[fn] - {name})
            tag = "UNIQUE" if not others else f"shared with {len(others)}: {', '.join(others[:4])}"
            s, t = e.func_of(fn) if fn else (0, 0)
            print(f"  [{i + 1:3}] delta={delta:<4} fn=0x{fn:08x} size={t - s:<5} {tag}")


if __name__ == "__main__":
    main()
