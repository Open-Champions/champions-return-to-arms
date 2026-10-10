# Working on Open Champions

Read `CONTRIBUTING.md` and the document for the area you change. This repository has
two related targets: a source reconstruction that reproduces the original PS2 code,
and a portable C++ core with a Godot client for native Mac and Windows play. Read
`docs/REBUILD.md` for reconstruction and `docs/NATIVE_PORT.md` for the native client.
Success in one target does not prove the other.

## Coordinate before editing

- Inspect `git status`, recent commits, and current agent ownership. Preserve every
  unrelated change. Claude's active subsystem research is not an unassigned backlog.
- Assign separate files to parallel agents. Check `python3 tools/rebuild_claims.py list`
  before claiming a reconstruction function. Claim it with
  `python3 tools/rebuild_claims.py claim 00123450 --owner <agent-name>`; substitute its
  real entry address. Leases last four hours and can be renewed by the same owner.
- Claims live under ignored `work/rebuild/claims/` and coordinate this checkout only.
  For separate checkouts or outside contributors, also coordinate in a GitHub issue.
  An expired lease does not authorize overwriting another agent's unfinished files.
- Do not stage whole directories. Stage only the reviewed files you own. Never reset,
  stash, clean, or revert another agent's work to make your checks pass.

## Reconstruction loop

1. Run `python3 tools/rebuild.py check`. Use `candidates` to find an unrecorded
   function, then claim it. Automatic function boundaries are leads, not proof.
2. Read the complete function and the surrounding file, callers, data and ABI evidence.
   Use address-based names when identity is uncertain; do not invent class meanings.
3. Write understandable C++ in `reconstructed/`. Keep attempts and compiler outputs
   in ignored `work/`. Raw instruction arrays, inline assembly, prebuilt objects and
   copied decompiler output do not count as reconstructed C++.
4. Run the documented fresh `verify` command against the pinned private executable.
   Check every byte, the full function extent, and relocations. The initial verifier
   accepts only relocation-free functions; do not bypass that limit by truncating a
   function or ignoring operands. General R5900 code generation and linking remain
   separate work.
5. Commit one verified function with its ledger and sanitized receipt. Record the
   address, measured byte gain, compiler and verification command. Changes to shared
   source or compile options require re-verifying all affected functions.
6. Run `progress`, report the actual gain, and release the lease with
   `python3 tools/rebuild_claims.py release <address> --owner <agent-name>`.
   If a candidate is blocked, preserve a concise local attempt and try another bounded
   candidate. Zero byte gain is an honest result; never manufacture matching credit.

## Evidence and verification

- Keep named functions, decompiled functions, reconstructed C++ bytes, linked PS2
  executable completion, and native gameplay milestones separate.
- A saved match receipt records an earlier run. Only a fresh build and private-baseline
  comparison verifies the current compiler. Public CI without the disc checks metadata,
  source hashes and synthetic tests, not the retail game.
- Use `python3 -m unittest discover -s tools -p 'test_*.py'` for Python tool changes.
  Verify C++ native changes with the existing CMake/CTest workflow. For symbol changes,
  run `tools/symtab.py check` and update `docs/STATUS.md` with `tools/coverage.py --write`.
- Never publish original executables, disc/BIOS files, proprietary toolchains, extracted
  assets, raw disassembly or raw decompiler output. Reimplement the workflow in original
  code; importing another project's source requires preserving its applicable license.
- No gameplay fix is runtime-confirmed without a recorded execution. Godot exports and
  a passing archive-inspector build do not establish a playable Champions port.
