#!/usr/bin/env python3
"""Scan a PS2 ISO for hostnames / URLs / IPv4 literals and say which file each one lives in.

Usage: python3 find_hosts.py <game.iso> [--all]
"""
import mmap, re, struct, sys

TLDS = rb"(?:com|net|org|jp|co\.jp|co\.uk|info|biz|edu|gov|de|fr|eu)"
HOST = re.compile(rb"(?<![A-Za-z0-9._-])((?:[a-z0-9](?:[a-z0-9-]{0,40}[a-z0-9])?\.){1,5}" + TLDS + rb")(?![A-Za-z0-9-])", re.I)
URL = re.compile(rb"(?:https?|ftp)://[\x21-\x7e]{4,200}")
IPV4 = re.compile(rb"(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![0-9.])")
# skip the big asset caches unless --all: they are compressed/texture data and only yield noise
NOISY_EXT = (".TEX", ".VAT", ".DAT", ".VAG", ".VA1", ".SMG", ".RGB", ".BD", ".PF", ".BIN", ".ICO")


def iso_files(m):
    """Yield (path, lba, size) for every file on an ISO9660 volume."""
    pvd = 16 * 2048
    assert m[pvd + 1:pvd + 6] == b"CD001", "not an ISO9660 image"
    root = m[pvd + 156:pvd + 190]
    stack = [("", struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0])]
    while stack:
        path, lba, size = stack.pop()
        data = m[lba * 2048:lba * 2048 + size]
        i = 0
        while i < len(data):
            n = data[i]
            if n == 0:  # records never span sectors; skip padding to the next one
                i = (i // 2048 + 1) * 2048
                continue
            rec = data[i:i + n]
            e_lba, e_size = struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0]
            flags, nlen = rec[25], rec[32]
            name = rec[33:33 + nlen]
            i += n
            if name in (b"\x00", b"\x01"):
                continue
            name = name.decode("latin1").split(";")[0]
            full = f"{path}/{name}"
            if flags & 2:
                stack.append((full, e_lba, e_size))
            else:
                yield full, e_lba, e_size


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    scan_all = "--all" in sys.argv
    with open(sys.argv[1], "rb") as f:
        m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    files = sorted(iso_files(m), key=lambda t: t[1])
    hits = {}
    for path, lba, size in files:
        if not scan_all and path.upper().endswith(NOISY_EXT):
            continue
        blob = m[lba * 2048:lba * 2048 + size]
        for kind, rx in (("host", HOST), ("url", URL), ("ipv4", IPV4)):
            for mt in rx.finditer(blob):
                s = mt.group(0).decode("latin1")
                if kind == "ipv4" and (s.startswith("0.") or s.count("0") > 5 or s in ("1.0.0.0", "1.1.1.1", "2.0.0.0")):
                    if s != "0.0.0.0":
                        continue
                hits.setdefault((kind, s.lower()), []).append((path, lba * 2048 + mt.start(), mt.start()))
    for (kind, s), where in sorted(hits.items()):
        print(f"[{kind}] {s}")
        seen = set()
        for path, iso_off, file_off in where:
            if (path, file_off) in seen or len(seen) >= 6:
                continue
            seen.add((path, file_off))
            print(f"    {path}  file+0x{file_off:x}  iso+0x{iso_off:x}")
        if len(where) > len(seen):
            print(f"    ... {len(where) - len(seen)} more")


if __name__ == "__main__":
    main()
