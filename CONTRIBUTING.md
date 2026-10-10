# Contributing

Help reconstruct one complete Return to Arms PS2 function at a time. Read
[the workflow](docs/REBUILD.md), [agent instructions](AGENTS.md), and the
[snapshot provenance](ORIGIN.md). Coordinate substantial work in an issue and reserve
individual entries through the checkout-local claim tool.

## What belongs here

Independently authored, readable C++ goes in `reconstructed/`. The target ledger
records exact extents, compiler options and evidence. Sanitized verification receipts
contain hashes and results, never original bytes. Keep speculative attempts in ignored
`work/` until their status is clear.

Subsystem research belongs in the [research repository](https://github.com/Open-Champions/champions-return-to-arms-re).
Native Godot behavior for both games belongs in [Open Champions Godot](https://github.com/Open-Champions/open-champions-godot).
Norrath has its own [reconstruction repository](https://github.com/Open-Champions/champions-of-norrath).

## What may not be committed

Do not publish game executables, disc images, BIOS files, extracted models/textures/audio,
level files, compiled scripts, original object files, raw disassembly or raw decompiler
output. Proprietary SDK/toolchain files stay private. The `.gitignore` is a whitelist;
do not weaken it to add a reference file.

Address metadata, independently chosen identifiers, verified struct layouts, original
explanations and authored C++ are welcome. This repository retains earlier research
history; [ORIGIN.md](ORIGIN.md) explains the separation and current ownership.

## Evidence and review

Mark claims **Observed**, **Inferred**, or **Unknown** and provide addresses or a
reproducible check. A proposed name costs more than a missing one when others build on
it. A complete constant-return leaf can be valid; an invented placeholder cannot.
Do not claim playability, whole-game linking or runtime-tested behavior from a function
match or metadata check.

For a reconstruction change:

1. Establish the whole body, callers and dependencies; preserve unresolved questions.
2. Compile from current authored source and compare against the pinned private baseline.
3. Include the function's source, ledger update, sanitized receipt and refreshed chart
   in one focused review. State the address, complete extent, actual byte gain and command.
4. Run all synthetic tests, ledger checks and chart regeneration. A saved receipt must
   match current source, flags, index and verifier fingerprints.

Public CI needs no original disc and validates metadata only. The optional local commit
gate can require fresh comparison; see [installation and limitations](docs/REBUILD.md#optional-local-commit-gate).
Follow user authorization for commits and pushes. Authored contributions use the existing
[MIT license](LICENSE); third-party code needs explicit provenance and license review.
