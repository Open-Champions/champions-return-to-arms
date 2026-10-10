#!/usr/bin/env python3
"""Unpack Snowblind .GOB archives and the .LMP lumps inside them (RTA layout).

  python3 gob.py list <file.GOB|file.LMP>
  python3 gob.py extract <file.GOB|file.LMP> <outdir>

GOB: 40-byte records  name[32], offset u32, size u32   (terminated by an empty name)
LMP: u32 count, then count x (nameOffset u32, dataOffset u32, dataSize u32)
"""
import os, struct, sys


def gob_entries(d):
    out, i = [], 0
    while i + 40 <= len(d) and d[i] != 0:
        name = d[i:i + 32].split(b"\0")[0].decode("latin1")
        off, size = struct.unpack_from("<II", d, i + 32)
        out.append((name, off, size))
        i += 40
    return out


def lmp_entries(d):
    n, = struct.unpack_from("<I", d, 0)
    out = []
    for i in range(n):
        no, do, ds = struct.unpack_from("<III", d, 4 + i * 12)
        name = d[no:d.index(b"\0", no)].decode("latin1")
        out.append((name, do, ds))
    return out


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    cmd, path = sys.argv[1], sys.argv[2]
    d = open(path, "rb").read()
    is_gob = path.upper().endswith(".GOB")
    ents = gob_entries(d) if is_gob else lmp_entries(d)
    for name, off, size in ents:
        blob = d[off:off + size]
        if cmd == "list":
            print(f"{name:32} off=0x{off:08x} size={size}")
            if is_gob:
                for n2, o2, s2 in lmp_entries(blob):
                    print(f"    {n2:32} off=0x{o2:08x} size={s2}")
        else:
            out = sys.argv[3]
            if is_gob:
                sub = os.path.join(out, name)
                os.makedirs(sub, exist_ok=True)
                for n2, o2, s2 in lmp_entries(blob):
                    open(os.path.join(sub, n2), "wb").write(blob[o2:o2 + s2])
            else:
                os.makedirs(out, exist_ok=True)
                open(os.path.join(out, name), "wb").write(blob)


if __name__ == "__main__":
    main()
