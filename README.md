# Champions: Return to Arms — reverse engineering

An open effort to understand, document and eventually rebuild the code of *Champions:
Return to Arms* (PS2, US release SLUS-20973, v2.00), the Snowblind-engine action RPG whose
online service was shut down years ago.

The first goal is practical: make online play dependable again on community servers such as
[Champions Reborn](https://github.com/HikikoMarmy/Champions-Reborn-Server) by finding and
fixing the bugs that put players "OUT OF SYNC" and make the game lag. The long-term goal is
a complete, readable account of how the game works.

**This repository contains no game code and no game assets.** You need your own copy of the
disc to use it. See [What may not be committed](CONTRIBUTING.md#what-may-not-be-committed).

## Where it stands

- The executable is 3.0 MB of MIPS code in 7,732 functions. About 6% of it is named so far;
  [docs/STATUS.md](docs/STATUS.md) breaks that down by area.
- All 403 C++ class names are recovered and 399 are tied to their virtual tables.
- The level-script language is fully decoded: all 120 level scripts decompile to readable
  pseudo-code, and all 191 built-in script commands are located.
- The online model is mapped: deterministic lockstep, the per-frame sync check, the input
  codec and the local-player prediction system.
- Several real sources of desync have been found by reading the code. **None has been
  confirmed on a running game yet** — that needs two emulators side by side, and it is the
  most useful thing a new contributor could do. [FINDINGS.md](FINDINGS.md) is the evidence
  ledger; every claim there is marked observed, inferred or unknown, with addresses.

## What is here

| Path | What |
|---|---|
| [docs/OVERVIEW.md](docs/OVERVIEW.md) | How the game is put together — start here |
| [docs/](docs/) | One document per subsystem, plus file formats and status |
| [FINDINGS.md](FINDINGS.md) | Evidence ledger for the online bugs |
| `names.tsv`, `symbols/*.tsv` | Symbol map: address, name, note |
| `rtti_classes.txt`, `vtables.txt`, `ghidra_funcs.tsv` | Class names, virtual tables, function boundaries |
| `tools/` | Python tools: cross-references, script decompiler, archive unpacker, sync audits |
| `ghidra/scripts/` | Ghidra scripts: apply the symbol map, decompile everything |
| `patches/` | PCSX2 patches for testing hypotheses |

## Getting started

You need Python 3, `llvm-objdump`, and [Ghidra](https://ghidra-sre.org/) with the
[ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded)
extension.

```bash
# 1. Copy SLUS_209.73 from your own disc into the repository root. It is git-ignored.
shasum -a 256 SLUS_209.73
# expect 292f6f48e3609c0026def2307d76c222cd5b389303d53b89b0e107d7b1dcd675

# 2. Disassembly used by the Python tools
mkdir -p disasm
llvm-objdump -d -j .text --no-show-raw-insn --mcpu=mips3 SLUS_209.73 > disasm/text.asm

# 3. Ghidra project with the symbol map applied, and one decompiled file per function
mkdir -p build ghidra/proj
python3 tools/symtab.py merge build/all_names.tsv
analyzeHeadless ghidra/proj crta -import SLUS_209.73 -processor r5900:LE:32:default
analyzeHeadless ghidra/proj crta -process SLUS_209.73 -noanalysis -scriptPath ghidra/scripts \
    -postScript ApplyNames.java "$PWD/build/all_names.tsv" \
    -postScript DecompAll.java "$PWD/decomp/all" "$PWD/ghidra/scripts/extra_entries.txt"
```

Then, for example:

```bash
python3 tools/dis.py SLUS_209.73 0x139e88          # annotated disassembly of a function
python3 tools/vtab.py SLUS_209.73 show Player      # a class's virtual functions
python3 tools/gxref.py SLUS_209.73 404464          # who reads and writes a global
python3 tools/fieldxref.py SLUS_209.73 2fc         # who uses a struct offset
python3 tools/ghostreach.py 1a5030                 # what the prediction copy can write
python3 tools/gob.py extract DRUNARE.GOB out/      # unpack a level from your disc
python3 tools/scr.py dis out/drunare.lmp/script.scr  # decompile its script
```

## How to help

Read [CONTRIBUTING.md](CONTRIBUTING.md). The short version: pick an area from
[docs/STATUS.md](docs/STATUS.md), say so in an issue, name what you can prove, and write
down how you know. Testing on a running game, tool improvements and file-format work are
just as welcome as naming functions.

## Thanks

- [Champions Reborn Server](https://github.com/HikikoMarmy/Champions-Reborn-Server) for
  bringing the lobby back.
- [ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded)
  for making Ghidra read PS2 code properly.
- [rea](https://github.com/morluto/rea) and [Open-BFME](https://github.com/Open-BFME) for
  the working method: an evidence ledger, honest names, one measured change at a time.

## Legal

*Champions: Return to Arms* belongs to its rights holders. This project is not affiliated
with them. It documents the behaviour of software its contributors own copies of, for
interoperability and preservation, and distributes none of it. The tools and notes here are
under the [MIT license](LICENSE).
