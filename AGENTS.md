# Working on the Return to Arms reconstruction

This repository owns the PS2 source reconstruction for `SLUS_209.73`, US v2.00.
Read `CONTRIBUTING.md`, `docs/REBUILD.md` and `ORIGIN.md` before editing.

## Keep ownership separate

- Research, subsystem naming and emulator experiments belong in
  https://github.com/Open-Champions/champions-return-to-arms-re . Do not resume or
  duplicate another agent's research just because a reconstruction needs evidence.
- First-game reconstruction belongs in
  https://github.com/Open-Champions/champions-of-norrath . Never reuse this target's
  executable hash, addresses or matching credit for Norrath.
- Native gameplay for both games belongs in
  https://github.com/Open-Champions/open-champions-godot . Keep Godot and host-native
  builds out of this repository's PS2 matching progress.
- `ghidra_funcs.tsv` is a frozen research snapshot, not a live duplicated symbol
  database. Follow the controlled update process in `ORIGIN.md`.

## Coordinate before editing

Inspect `git status`, recent commits and current ownership. Assign separate files to
parallel agents and preserve unrelated work. Check `python tools/rebuild_claims.py list`
before claiming an entry with `python tools/rebuild_claims.py claim <hex-entry> --owner <name>`.
Claims are checkout-local four-hour leases under ignored `work/rebuild/claims/`.
Coordinate separate checkouts in a GitHub issue as well. An expired lease does not
authorize overwriting unfinished files.

## Complete one proven function

1. Run `python tools/rebuild.py check`; use `candidates` as leads, not proven semantics.
2. Establish the complete body, callers, ABI and data dependencies from private
   reference material and addressed research. Use address-based names when uncertain.
3. Author readable C++ in `reconstructed/`. Keep experiments and compiler outputs in
   ignored `work/`. Inline assembly, instruction arrays and copied decompiler output
   do not count as reconstructed C++.
4. Run a fresh `verify` against the pinned private executable. Compare the complete
   function extent; never shorten a body, mask differing bytes or ignore relocations.
   The current tool accepts only self-contained C++ leaves in relocation-free code
   sections and a reviewed subset of Clang options.
5. Review the source, ledger and sanitized receipt together. Reverify when source,
   options, verifier or function-index inputs change. A saved receipt is historical
   evidence; metadata checks are not a fresh compilation.
6. Refresh `docs/rebuild-progress.svg`, report the actual byte gain and release the
   lease with `python tools/rebuild_claims.py release <hex-entry> --owner <name>`.
   Preserve a concise local blocker for nonmatching attempts; zero gain is valid.

## Validation and publication

Run `python -m unittest discover -s tools -p 'test_*.py'`, `python tools/rebuild.py check`
and `python tools/rebuild.py progress --svg docs/rebuild-progress.svg`. Check the diff.
Fresh matching requires private game input and the selected compiler; public CI has
neither. A function match does not prove whole-program linking or runtime behavior.

Stage only reviewed files you own. Never reset, stash, clean or revert someone else's
work. Commit/push actions follow the user's task authorization. Never publish original
executables, assets, disc/BIOS/SDK files, raw disassembly, raw decompiler output or
proprietary toolchains. Third-party source reuse requires preserving its license and
provenance; the BFME workflow is methodological inspiration, not imported source.
