# Native Mac and Windows feasibility

Assessment: 10 October 2026. **Observed** means inspected in this checkout or the
linked primary documentation. **Proposed** means future implementation; **Unknown**
means a remaining proof requirement. This assessment does not claim a playable port.

A native Champions client is a plausible engineering target. This repository now
has an authored native archive inspector in `native/`, alongside research tools
and recovered behavior. It still lacks a playable authored game engine that can
be compiled for a MacBook or Windows PC. The practical route to a client
without a PS2 emulator is to implement portable systems from the documented
behavior and load the user's original data. Simply compiling the Ghidra output
will not produce that client.

## What exists now

| Component | Observed state | What it proves |
|---|---|---|
| Native data inspector | `native/` contains a standard-library-only C++17 GOB/LMP parser, CLI, CMake build and synthetic tests | A native data-tool foundation, locally compiled and run on arm64 macOS; not a game engine. |
| Python research tools | Archive readers, script inspection/decompilation, symbols and executable analysis in `tools/` | Useful format knowledge and repeatable analysis; no playable native client. |
| Local generated C | `decomp/all/` contains Ghidra output with absolute globals, inferred types, unresolved calls and machine-specific operations | Analysis material. These are not original source files or a complete compilable engine. |
| Authored game runtime | No gameplay simulation or rendering engine build target exists; the authored `native/` target inspects archive metadata | Rendering, simulation, audio, assets and input still need implementations. New files from active research agents can improve the map without changing this fact. |
| Local community-server checkout | Ignored `server/upstream/` contains C++ lobby/discovery/account/session services, `build.sh`, Visual Studio project and a Winsock/BSD socket wrapper | A separate service implementation, not a native game client. |
| Existing local server binary | `server/upstream/bin/champions-server` identifies as Mach-O arm64 | An Apple Silicon server binary exists. It was not launched or rebuilt for this assessment; this alone proves neither live service health nor client gameplay. |
| Configured public checks | The CI matrix targets macOS arm64/Intel, Windows x64/arm64 and Linux, running CMake/CTest plus Python checks; Linux also covers another Python version | Configured coverage is not a passing remote run. Inspect actual job results before claiming each target is verified. |

The server smoke test implements a limited lobby/discovery client. Its success
would not prove world loading, rendering, combat or multiplayer lockstep. No server
connection or account creation was performed in this assessment.

The source-inventory distinction matters: the disc contains data and executable
machine code, not the missing Snowblind source tree. See [OVERVIEW.md](OVERVIEW.md),
[FORMATS.md](FORMATS.md), and findings S1–S3 in [FINDINGS.md](../FINDINGS.md).

## Platform work that cannot be skipped

| Boundary | Repository evidence | Proposed native replacement / missing work |
|---|---|---|
| CPU and memory model | R5900 little-endian 32-bit target; old GCC object/vtable conventions in `OVERVIEW.md` | Use fixed-width file fields, explicit handles and checked offsets. Do not truncate 64-bit host pointers or reinterpret on-disc records as host C++ objects. Preserve numeric behavior intentionally. |
| Graphics and geometry | GIF DMA submission `0x3201b0`; frame/media processing `0x3205ec`; `.world`, `.vif`, `.tex`, `.anm` listed as incomplete in `FORMATS.md` | Recover the required geometry, texture, material and animation formats and write a renderer. Graphics-command bytes and VU programs are not portable GPU shaders. |
| Console kernel and timing | Loading uses `CreateThread` at `0x321e60`; frame completion `0x19da78` uses semaphores and timer register `0x10000000` | Host threads/jobs and monotonic timing, with simulation ticks independent of rendering and loading speed. Retain necessary ordering rather than console addresses. |
| I/O and media | `.GOB` / `.LMP` readers exist; local asynchronous resource checks gate warm-up (`0x322eb0–0x322fd0`) | Checked native archive access and asynchronous resource ownership. Decoder/audio formats and failure behavior remain work. |
| Audio | `audio_streamPosition` at `0x216480` obtains local sound-driver state through IOP RPC | Host audio playback and a documented completion/position contract. Keep audio timing out of shared simulation, addressing rather than accidentally retaining known D8 behavior. |
| Input, menus and saves | Pad codec/prediction documented in `OVERVIEW.md`; save/UI research is still being mapped | Gamepad/keyboard bindings, portable save serialization and explicit local/shared state. Existing PS2 input records must not be host structs. |
| Game systems | Objects, collision, AI, scripts, abilities, inventory, cutscenes and world setup have maps and partial semantic recovery | Implement each system and its contracts. All 51 script opcodes being decoded does not implement the 191 imported built-ins or the objects those commands control. |
| Networking | Lockstep, peer inputs, checksums and prediction in `OVERVIEW.md` and `FINDINGS.md` | Reproducible simulation, transport and protocol integration. Matching native peers is one target; interoperability with unmodified PS2 clients is a separate, harder compatibility target. |

**Proposed:** specify integer overflow, conversions, random streams, iteration
order and floating-point behavior in the simulation contract. Compare arm64 and
x64 frame traces before claiming cross-platform lockstep. The original seed/position
checksum is useful but too narrow to prove every relevant state matches.

## Recommended implementation direction

**Proposed:** an authored portable C++ core with explicit interfaces for data,
simulation, graphics, audio, input and networking. Keep game behavior independent
of desktop windows and render rate. A game-script interpreter is compatible with
this direction; it is not a PS2 CPU or hardware emulator.

SDL3 is a reasonable candidate for the desktop shell: its official documentation
covers Windows/macOS, input and audio. Its GPU API offers Metal and Direct3D 12
backends, but supplying equivalent shaders remains application work. This is a
candidate, not an installed dependency or proof the game renders correctly.
[SDL3 overview](https://wiki.libsdl.org/SDL3/FrontPage),
[SDL GPU](https://wiki.libsdl.org/SDL3/CategoryGPU).

| Intended build | Proposed toolchain and graphics direction | Required evidence |
|---|---|---|
| Apple Silicon MacBook | Apple Clang, CMake arm64 target; Metal-capable renderer | Mach-O arm64 binary; launch and interaction on a Mac; no Rosetta or PS2 emulator process. |
| Intel Mac | Apple Clang, CMake x86_64 target; Metal-capable renderer | Mach-O x86_64 binary; launch on an Intel Mac and matching data/simulation outputs. |
| Windows x64 | MSVC or compatible native compiler, CMake x64 target; Direct3D 12 candidate | PE x64 binary; launch and interaction on Windows x64; matching data/simulation outputs. |
| Windows arm64 | Native ARM64 compiler and dependencies; renderer verified on target hardware | PE ARM64 binary and actual Windows-on-Arm test; x64 translation does not count as this target passing. |

CMake supports explicit Apple architecture selection, and its Visual Studio
generator supports selecting the target platform. Microsoft documents native
Windows-on-Arm development. These establish toolchain routes, not this project's
compatibility. Dependency architectures and graphics support still need testing.
[CMake Apple architecture](https://cmake.org/cmake/help/latest/variable/CMAKE_OSX_ARCHITECTURES.html),
[CMake Visual Studio](https://cmake.org/cmake/help/latest/generator/Visual%20Studio%2017%202022.html),
[Microsoft Windows on Arm](https://learn.microsoft.com/en-us/windows/arm/overview).

### Static recompilation as a separate experiment

**Observed in upstream documentation:** PS2Recomp translates R5900 instructions
to C++ and supplies a runtime, but describes itself as experimental. Its stated
requirements include mainly MSVC testing and SSE4/AVX support for some vector
paths. It also includes IOP execution/emulation, partial hardware handling and
stubs. Its own limitations warn about VU/GS performance.
[PS2Recomp official repository](https://github.com/ran-j/PS2Recomp).

**Assessment:** this may help an isolated compatibility experiment, but it does
not establish native arm64 support or satisfy a strict requirement to remove
console emulation. A native executable can still contain emulated console
subsystems. No Champions recompilation or execution was performed here.

**Proposed experiment gate:** first demonstrate a tiny, known computation on
x64 and arm64, inventory every runtime stub needed for the next stage, and stop
if a required subsystem is unimplemented. Do not treat dummy-success stubs or a
boot logo as game completion. Keep generated game-derived code private under
this repository's existing contribution rule; keep any third-party licensing
boundaries explicit before integrating a recompiler runtime.

## Smallest useful native milestone

**Delivered first slice: a native archive inspector.** `champions-data list`
accepts one or more user-selected `.GOB`/`.LMP` files and emits deterministic,
escaped TSV metadata, including nested LMP entries with absolute file offsets.
It performs no extraction and requires only C++17 and the standard library.
The parser checks record counts, field/name bounds, payload ranges and arithmetic
overflow; Windows uses wide-character arguments for Unicode file paths. Script
metadata and script execution are explicitly deferred. See [build and usage](../native/README.md).

**Observed local validation:** Apple Clang 21 compiled both targets on arm64 macOS
with warnings as errors. All 30 parser checks passed under AddressSanitizer and
UndefinedBehaviorSanitizer; CLI checks covered nested data, Unicode/space paths,
missing input, invalid input and usage. A private comparison matched 100 metadata
rows across 11 local archives to `tools/gob.py`, without publishing contents. The
CLI identifies as Mach-O arm64 and links only system C++ and OS libraries. A second
read-only review independently verified malformed nested inputs produce no partial
stdout and extreme offsets are rejected. CMake was unavailable locally, so this
was a direct-compiler verification; configured remote CMake/CTest jobs and other
architectures still need observed results.

Remaining acceptance evidence and follow-on script-inspector scope:

1. CMake builds and target execution on macOS arm64/Intel, Windows x64 and Windows arm64; record source
   revision, compiler, architecture and binary hash for each. A cross-build is
   build evidence only until the binary runs on its target OS/architecture.
2. Run original, authored synthetic fixtures covering nested entries, truncated
   headers, invalid counts and out-of-range offsets. All platforms must return
   identical metadata and deterministic errors; no game assets enter the tests.
3. Compare the inspector's metadata for a privately supplied known-good archive
   against `tools/gob.py`; once script metadata is added, compare it to `tools/scr.py` too. Keep game contents private; publish
   only the test method and non-content result.
4. Run without the original ELF, BIOS, PCSX2 or a console runtime. Show the
   executable's architecture and dependency list. This proves the milestone is
   native data tooling; it does not claim a playable game.

**Proposed next milestones:** an authored script VM executing synthetic programs
with deterministic state traces; a local asset viewer after the required texture
and geometry formats are documented; one small offline gameplay scene with
input/collision/animation/save; finally two native peers with replay and divergent
frame diagnostics. Each milestone requires its own behavior and visual tests.
A blank window is an integration check, not evidence of a recovered renderer.

## Completion boundary

The authored archive parser and CLI are delivered and locally verified on
Apple Silicon. No third-party dependencies were installed; the server and Claude
area files were not modified by this work. The project still has no verified
playable native client or defensible completion date. Next steps are observing
the cross-platform CMake/CTest results, adding script metadata, and expanding
from the ongoing research without duplicating its reverse-engineering passes.
