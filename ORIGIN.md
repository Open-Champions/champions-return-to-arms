# Repository origin and metadata snapshot

This dedicated Return to Arms PS2 reconstruction repository was split from
[Open Champions research](https://github.com/Open-Champions/champions-return-to-arms-re)
at commit [`1dfcf606e4c1b85eeb34508053c9822942f539ca`](https://github.com/Open-Champions/champions-return-to-arms-re/commit/1dfcf606e4c1b85eeb34508053c9822942f539ca).

The full inherited Git history is preserved. The separation commit removes research,
emulator experiments and native-inspector files from this repository's current tree;
it does not rewrite their earlier commits. The research repository and its active
work remain independent. Existing authored-source licensing stays in [LICENSE](LICENSE).

## Frozen function index

`ghidra_funcs.tsv` is retained byte-for-byte from that research commit as the boundary
metadata snapshot for the US v2.00 `SLUS_209.73` target:

- 7,732 indexed functions.
- SHA-256: `4c597317e64e41bc48752b4b69dbadf6d7eb592004c94bed22842bc0e63d0ac3`.
- Fields: entry address, analysis name and inclusive body ranges.
- No executable bytes, disassembly or game assets are included in this file.

The index supplies candidate boundaries and the progress denominator. Ghidra boundaries
are analysis evidence, not proof that every function is understood. A match must use the
entire independently checked eligible body. Research naming coverage is not matching
progress.

## Controlled updates

Do not live-sync this file or maintain a second active symbol database here. Propose an
index update as a focused change that identifies a specific reviewed research commit,
old/new hashes, changed boundaries and why the change is needed. Inspect every affected
reconstruction extent. Run the synthetic suite and ledger checks, then freshly reverify
all recorded functions against the pinned private baseline because the index fingerprint
invalidates existing receipts. Refresh the sanitized receipt and progress chart, and
record the new snapshot provenance here. Do not copy raw Ghidra project databases or
original game data into either commit.

The current authored function, ledger, verifier and sanitized receipt were preserved
through the split. They record one complete eight-byte leaf at `0x00108968`. Rechecking
that record does not establish a whole linked game, native gameplay or a second game's
baseline.

Related repositories:
[Champions of Norrath reconstruction](https://github.com/Open-Champions/champions-of-norrath)
and [the shared Godot implementation](https://github.com/Open-Champions/open-champions-godot).
