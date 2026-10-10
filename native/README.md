# Native data inspector

`champions-data` is an authored C++17 archive metadata tool. It reads GOB and LMP
files from your own copy of Champions: Return to Arms. It needs no game executable,
BIOS, emulator or third-party library. It is a foundation for native development,
not a playable game client.

## Build and test

Requirements: a C++17 compiler and CMake 3.21 or newer.

```sh
cmake -S native -B build/native
cmake --build build/native --config Release
ctest --test-dir build/native -C Release --output-on-failure
```

For a single-configuration generator the executable is
`build/native/champions-data` (or `.exe`); Visual Studio places it under
`build/native/Release/`. On Windows choose a native target with `-A x64` or
`-A ARM64` when configuring the Visual Studio generator. All dependencies must
match the target architecture; this tool has only standard-library dependencies.

```sh
build/native/champions-data list "/path with spaces/level.GOB" "/path/config.LMP"
```

Windows uses the wide-character command-line entry point and filesystem paths,
so Unicode input paths do not depend on the active console code page. macOS/Linux
paths are read as UTF-8. File extensions are case-insensitive.

## Output contract

For each valid file, output begins with a `file` row and a column heading:

```text
kind    parent    name    offset    size
```

The actual separator is a tab. Rows retain archive-table order. `gob-entry`
identifies a GOB record; `lmp-entry` identifies a top-level or nested LMP record.
`parent` is empty for top-level entries and contains the GOB entry name for nested
entries. Offsets are **decimal bytes relative to the input file**, including
nested entries. Sizes are decimal bytes.

Backslash, tab, carriage return and newline are escaped as `\\`, `\t`, `\r` and
`\n`. Other control and non-ASCII bytes are escaped as lowercase `\xNN`; this
keeps the report deterministic and prevents a name from creating extra rows.
Archive names are preserved as bytes rather than guessed Unicode. File paths are
converted to UTF-8 before escaping.

GOB children ending in `.LMP` are inspected as nested lumps. Other GOB entries
are listed without assuming their payload format. Files are read in memory;
this first version is not a streaming reader. It performs no extraction or writes
to the input. It validates table/count/name/payload bounds; it does not certify
semantic validity of models, scripts or other entry contents.

Exit status: `0` for all files successfully inspected, `1` if any input fails,
`2` for invalid command usage. Errors go to standard error. A malformed file
produces no partial metadata for that file; other requested files are still
processed. Script metadata and actual script execution are deferred.

## Verification boundary

The synthetic C++ tests cover valid/empty archives, nested offsets, incomplete
headers/tables, extreme counts and offsets, unterminated names, fixed-width names,
zero-length entries, endianness and TSV escaping. CTest also runs CLI checks for
nested inputs, Unicode paths, malformed input, help and missing arguments. Test
fixtures contain only authored bytes.

The first local validation used Apple Clang 21 on arm64 macOS, with warnings as
errors and AddressSanitizer/UndefinedBehaviorSanitizer on parser tests: 30 checks
passed. CLI checks passed, and 100 metadata rows across 11 private local archives
matched `tools/gob.py`; no game contents were published. The resulting CLI was
verified as Mach-O arm64 with only system C++/OS dynamic dependencies. CMake and
Windows/Intel/Linux target execution require their own build/test results; the
local direct-compiler run does not establish those targets.

See [native-port assessment](../docs/NATIVE_PORT.md) for remaining game-engine work.
