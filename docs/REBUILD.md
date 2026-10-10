# Rebuild workflow

This repository owns the Return to Arms PS2 source reconstruction: independently
authored C++ verified against the identified original executable, one complete function
at a time. The [research repository](https://github.com/Open-Champions/champions-return-to-arms-re)
owns reverse-engineering maps and findings. The [separate Norrath reconstruction](https://github.com/Open-Champions/champions-of-norrath)
owns the first game's baseline. The [shared Godot implementation](https://github.com/Open-Champions/open-champions-godot)
owns native Mac and Windows gameplay for both games. Those are separate proof boundaries.

Read [ORIGIN.md](../ORIGIN.md) for the retained history and frozen function-index snapshot.
No native game build, executable reconstruction or gameplay completion is claimed here.

## What we take from BFME1

The inspiration is a disciplined process: reserve a bounded task, establish identity
and dependencies, author readable source, compile and verify it, then land a small
reviewable result. Progress should follow verification rather than persuasive names,
generated listings or optimistic status fields. See Open-BFME-1's
[contributor workflow](https://github.com/Open-BFME/Open-BFME-1/blob/master/AGENTS.md)
and [matching guide](https://github.com/Open-BFME/Open-BFME-1/blob/master/docs/matching.md).

These are references for methodology. This guide and the Champions tooling are
independently authored; copying this workflow does not import BFME source, headers,
scripts, generated files, compiler binaries or its licensing into this repository.
The existing [LICENSE](../LICENSE) remains unchanged. Any future third-party code
reuse needs its own explicit provenance and license review before integration.

## Baseline and toolchain

The preservation target is the US v2.00 `SLUS_209.73` executable:

```text
SHA-256: 292f6f48e3609c0026def2307d76c222cd5b389303d53b89b0e107d7b1dcd675
CPU: R5900, little endian, 32-bit pointers
ELF entry: 0x14fa88
.text: address 0x100000, size 3,038,272 bytes
```

These values identify the target, not a reconstructed build. Keep the baseline from
your own disc private. Do not change the expected hash to accept a different edition,
a patched executable or a generated candidate. Model another edition as a separate
reviewed target if it is ever needed.

**Current blocker:** [the research overview](https://github.com/Open-Champions/champions-return-to-arms-re/blob/main/docs/OVERVIEW.md) identifies GCC 2.9x-era C++ conventions,
but the exact original EE compiler build, options, SDK headers/libraries and linker
recipe have not been established. A generic modern MIPS compiler, or host Clang
compiling C++ successfully, does not settle this. The PS2 target needs the correct
R5900 instruction behavior, register/calling conventions, structure layout, old C++
vtable/type-info conventions and relocation/linker rules. Preserve unknowns rather
than guessing signatures to silence a compiler.

Use a locally supplied authorized toolchain. Record its version and executable hash,
target flags, language mode, relevant header inputs and command line with each real
attempt. Compiler executable identity alone does not identify all its subprocesses,
libraries or headers; keep a private dependency inventory for reproducibility.
Do not publish proprietary SDK/compiler binaries, headers, baseline bytes or object
files made from the original game. Public verification reports should describe
results using hashes, addresses, sizes, commands without private paths, and original
explanations. [CONTRIBUTING.md](../CONTRIBUTING.md) also excludes raw decompiler output.

## One complete function at a time

1. **Claim the work.** Follow the current coordination instructions in root
   `AGENTS.md`. Identify the target address, intended source file and shared headers
   you expect to touch. Run `python3 tools/rebuild_claims.py list`, then
   `python3 tools/rebuild_claims.py claim <hex-entry> --owner <agent-name>` for your
   selected body. Avoid another agent's active body or dependency file. Claims are
   checkout-local four-hour leases under ignored `work/rebuild/claims/`; an expired
   lease does not authorize overwriting unfinished files. Coordinate separate
   checkouts in an issue too. A candidate list is a suggestion, not a reservation.
2. **Establish the whole body and dependencies.** Check machine instructions,
   boundaries, callers and referenced data. Include all branches, return paths and
   delay slots, plus switch tables or separate ranges where applicable. Document
   callee signatures, globals, object offsets, ownership and side effects. A recovered
   name or decompiler signature is evidence to check, not an authoritative contract.
3. **Author source.** Use `reconstructed/` for an understandable implementation and
   the minimum proven declarations it needs. Keep speculative experiments private
   until their status is clear. A placeholder return that omits original behavior,
   raw instruction array, copied assembly dump or embedded slice of the baseline is
   not a recovered implementation. A constant return is valid when evidence proves
   that it is the complete original function and its compiled body matches. Do not trim a
   mismatching tail, hide a missing dependency or change the ledger's extent to make
   an attempt pass.
4. **Verify the exact candidate.** Recompile from current source with the selected
   toolchain and validate the private baseline identity. Compare the entire declared
   function extent. Diagnose every differing byte; do not mask constants, addresses,
   delay slots or relocation differences and call the result exact. Run meaningful
   synthetic behavior checks when useful, while retaining the distinction between
   behavior evidence and byte equality.
5. **Land one verified body.** Review the source, dependency changes, ledger record
   and verification evidence together. Make a focused commit for that body and its
   necessary proven dependencies under the repository's current contribution rules.
   Include the target, complete extent, toolchain identity and result. This workflow
   is not blanket permission for a tool to commit or push without task authorization.
6. **Refresh progress.** Compute it from fresh successful verification records.
   Source, ledger, baseline, compiler or dependency changes require re-verification;
   do not carry a previous passing label over a changed attempt. Mark an unresolved
   attempt blocked or nonmatching and retain the specific reason for the next owner.
   Release the lease after landing or parking the bounded attempt:
   `python3 tools/rebuild_claims.py release <hex-entry> --owner <agent-name>`.
7. **Make only the supported release claim.** A function match is a function match.
   A linked artifact needs its own layout/content checks. A runnable or playable
   release additionally needs target execution, behavior, visual and interaction
   evidence. Native multiplayer needs cross-platform deterministic traces and actual
   peer tests; naming all networking routines is insufficient.

## Verification levels

| Result | What it establishes | What it does not establish |
|---|---|---|
| Symbol or structural recovery | A proposed identity, interface or behavior backed by addressed evidence | Compilable source, exact bytes, or tested gameplay |
| Authored source with synthetic tests | Tested behavior for the covered inputs | Original compiler identity, whole-game equivalence or a byte match |
| Complete function byte match | The compiled function's entire eligible extent equals the identified baseline bytes | Correctness of all callees/data, whole-program linking or runtime execution |
| Whole linked-image verification | A particular linked candidate matches the explicitly defined baseline scope and layout | A tested gameplay session or a native Godot port |
| Native scene or game verification | The specifically exercised exported behavior works on the recorded target | PS2 byte equality or untested systems/platforms |

Whole-image verification must define its scope. Comparing only `.text` cannot prove
all data, imports, relocation results or load layout match. Comparing selected bodies
cannot prove an entire section matches. Only an actual complete-file comparison may
be called an identical ELF; a narrower comparison must name the excluded parts.
Reconstructing a link also requires ownership of shared data, initialization, vtables,
runtime support and external calls. No whole-program verifier or completed linked
Champions game is claimed by this first function-verification workflow.

## Local commands

The native Python tooling needs no emulator. Use `python3` on macOS/Linux or replace
it with `py -3` in Windows PowerShell. Select compiler and game paths explicitly.

```sh
python3 tools/rebuild.py check
python3 tools/rebuild.py candidates --limit 10
python3 tools/rebuild.py verify --game /private/path/SLUS_209.73 --compiler /private/path/clang++
python3 tools/rebuild.py progress --report work/rebuild/verification.json --json
```

`check` validates the default ledger at `targets/SLUS-20973/rebuild.json`;
`--ledger PATH` selects another ledger. With no `--report`, `check` and `progress`
use `verification.json` beside the selected ledger when present. Without a report,
progress credits zero matches. `candidates` helps select a bounded body; it does not
prove a function's semantics or acquire a claim. `verify` compiles the ledger's source
with the supplied compiler and compares against the supplied private baseline. It
does not download a compiler or execute the game. Run only reviewed ledger/source
inputs and a trusted compiler: compilation executes a program and writes local build
artifacts. The default build/report location is ignored `work/rebuild/`, with a
report at `work/rebuild/verification.json`; `--output-dir` and `--report` select
explicit alternatives. Keep compiler outputs private.

The initial verifier supports complete, contiguous functions represented by a
size-bearing `STT_FUNC` symbol in an ELF32 little-endian MIPS object. It rejects
any relocations targeting the candidate code section, including ones outside the
function itself. Initial source is self-contained C++: preprocessor directives and
inline assembly are outside this verifier's accepted scope so that
unrecorded header inputs or instruction dumps cannot masquerade as source recovery.
This deliberately limits the first usable cases; noncontiguous functions, unresolved
relocations, jump-table/data dependencies and whole-program linking need additional
work. Do not flatten or discard those
features to inflate eligible coverage. A rejected function is an unsupported or
failed attempt, not automatically bad recovered behavior.

Use `progress --report PATH --json` to inspect a chosen report, or
`progress --report PATH --svg PATH` to render its chart. Report fingerprints bind the
ledger, function index, verifier and current source to the recorded comparison. They do not
independently prove that somebody ran the compiler. A fresh
`verify --game ... --compiler ...` run is the reproducibility check; never edit a
report into a pass.
A sanitized report can be published after review, without object files or baseline
bytes. Its date and source revision should accompany any progress claim.

Progress is **recorded byte-exact source evidence**, not a fresh build each time the
chart is read. Zero verified functions is an honest result when there is no passing
authored reconstruction. A small leaf can match using a candidate compiler before
the original toolchain is established; that does not settle general R5900 code
generation or linking. Keep these measures distinct:

- named functions / indexed functions: navigation coverage;
- successfully decompiled functions: analysis-tool output coverage;
- verified reconstructed function bodies and bytes: preservation evidence;
- target-native systems and scenarios actually exercised: playable-client progress.

Neither the 7,732-function index nor the generated C count is a native-port completion
percentage. Byte totals also weight large routines more heavily and omit data and
runtime integration; they must not be advertised as “percent of the game playable.”

## Optional local commit check

Install the repository's pre-commit check with an existing compiler path:

```sh
python3 tools/rebuild_gate.py --install --compiler /absolute/path/to/clang++
```

This installs a local Git hook, not a compiler or other software. It preserves a
custom hooks directory or existing unrelated hook by refusing to overwrite it;
integrate `python3 tools/rebuild_gate.py` into such a hook manually. The selected
compiler path is stored in this checkout's Git configuration, outside tracked files.

For staged changes under `reconstructed/` or `targets/SLUS-20973/`, the hook runs a
ledger check and fresh private-baseline comparison. It refuses unstaged reconstruction
inputs to avoid verifying different source from the proposed commit. The original
executable defaults to the repo-local `SLUS_209.73`; set `CHAMPIONS_GAME` to use another
private path. `CHAMPIONS_CXX` overrides the saved compiler; without either setting,
the fallback is `clang++` on PATH. A default compiler name is only a discovery fallback,
not evidence that its target or output is suitable.

The hook writes its local receipt to `work/rebuild/precommit-verification.json`.
Review and update any public receipt separately; the hook does not stage files or
publish results. This optional local check can be absent or bypassed, so reviewers
must still inspect the evidence and source. Passing it verifies eligible function
bytes, not whole-program linking or gameplay.

## First recorded result and next work

On October 10, 2026, `reconstructed/function_00108968.cpp` was freshly compiled with
Clang 20.1.8 into the exact eight bytes of the complete function at `0x00108968`.
The ledger records the boundary and caller evidence. This is one constant-return
leaf: 1 of 7,732 indexed functions and 8 of 3,038,272 original `.text` bytes. It
establishes neither general R5900 compiler support nor a linked or playable game.
The sanitized [receipt](../targets/SLUS-20973/verification.json) binds the source,
compiler, options, verifier and comparison hashes; original bytes remain private.

Choose one small eligible function with reliable boundaries and no unresolved
relocations, establish its inputs and outputs, and determine whether a local candidate
compiler can reproduce it from authored source. The initial command interface uses
Clang flags, disables implicit compiler configuration, and accepts a reviewed subset
of options; it is not yet an adapter for the original EE compiler. Record an honest mismatch when it
cannot. Settling compiler/ABI differences is useful work even when matched progress
remains zero. Native Godot work continues in its own repository; it does not add matching credit here.
