# Native Mac and Windows feasibility

Assessment: 10 October 2026. **Observed** means inspected in this checkout or the
linked primary documentation. **Proposed** means future implementation; **Unknown**
means a remaining proof requirement. This assessment does not claim a playable port.

A native Champions client is a plausible engineering target. This repository now
has an authored native archive inspector in `native/`, alongside research tools
and recovered behavior. It still lacks a playable authored game engine that can
be compiled for a MacBook or Windows PC. The practical route to a client
without a PS2 emulator is to implement portable systems from the documented
behavior and load the user's original data. **Recommended engine direction: Godot 4
for presentation and platform services, with the existing C++ core retained.** Simply compiling the Ghidra output
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
| Graphics and geometry | GIF DMA submission `0x3201b0`; frame/media processing `0x3205ec`; `.world`, `.vif`, `.tex`, `.anm` listed as incomplete in `FORMATS.md` | Recover the required geometry, texture, material and animation formats, then create Godot mesh, texture, material and animation resources. Graphics-command bytes and VU programs are not portable GPU shaders. |
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

## Recommended implementation direction: Godot 4 with a C++ core

**Recommendation:** use Godot 4 for the native client shell, scene rendering,
cameras, input, UI and audio; keep archive/data code and fidelity-sensitive game
behavior in a portable C++ core. Add a thin GDExtension adapter when a real asset
can be decoded. The existing inspector and parser tests remain useful unchanged.
This replaces the earlier custom SDL-renderer proposal; no Godot installation or
project scaffold was created in this assessment.

**Observed precedent:** Open-BFME has a dedicated `openbfme-godot` project, separate
from its binary-matching BFME repositories. Its current README describes C++ game
logic in a GDExtension and Godot as the device layer, reading original files from
the user's installation. That is a useful architectural precedent, not proof that
Champions formats or gameplay can be imported automatically. Its SAGE/BFME code
is a different engine and is not incorporated here.
[Open-BFME Godot repository](https://github.com/Open-BFME/openbfme-godot).

**Observed capability:** GDExtension loads native shared libraries without
rebuilding Godot. Official `godot-cpp` bindings provide the C++ integration route.
**Proposed boundary:** keep the current `champions-archive` library independent
of Godot, and translate validated metadata/decoded resources in the adapter.
Preserve byte-buffer ownership across calls; never expose temporary parser views
or original 32-bit addresses as host pointers. Pin a compatible stable Godot,
`godot-cpp` and export-template set, then build the extension for each target.
[GDExtension overview](https://docs.godotengine.org/en/stable/engine_details/engine_api/gdextension/what_is_gdextension.html),
[official C++ bindings](https://github.com/godotengine/godot-cpp).

| Intended client build | Verified Godot export route / proposed extension build | Required project evidence |
|---|---|---|
| Apple Silicon MacBook | Official Universal 2 macOS app export includes arm64; build extension with matching arm64 slice | Launch exported app and load extension on Apple Silicon without Rosetta or a PS2 emulator. |
| Intel Mac | The same Universal 2 export includes x86_64; extension must include its matching slice | Launch and render the same private test asset on Intel; compare data/simulation outputs. |
| Windows x64 | Native x86_64 export; matching x64 extension | Launch exported executable on Windows x64; verify extension and asset rendering. |
| Windows arm64 | Native arm64 export; matching ARM64 extension | Launch on Windows-on-Arm without x64 translation; verify extension and renderer. |

These export routes are documented by Godot. They do not establish this project's
compatibility until the extension, assets and interactions run on each target.
Mac distribution also requires appropriate application signing/packaging, which
is separate from local launch verification.
[macOS export](https://docs.godotengine.org/en/stable/tutorials/export/exporting_for_macos.html),
[Windows export](https://docs.godotengine.org/en/stable/tutorials/export/exporting_for_windows.html).

### What Godot solves, and what remains Champions-specific

**Assessment:** adopting a maintained engine avoids building a complete desktop
renderer and editor first. It supplies a place to display recovered resources and
iterate on scenes. It does not translate an ELF or Snowblind game into a working
Godot project.

- **Assets:** `.GOB`/`.LMP` containment is implemented. Texture swizzling/palettes,
  geometry/VIF data, animation/skeleton bindings, materials and `.world` layout
  still need format-specific conversion based on the existing research. GOB
  entry listing proves access, not that a model is decoded.
- **Gameplay and navigation:** combat, abilities, object state, triggers, script
  built-ins, camera behavior, pathfinding and movement rules must be authored and
  checked. A Godot navigation mesh or physics node cannot be assumed equivalent
  to Snowblind collision/pathfinding. A first controllable scene may use clearly
  labelled provisional movement while these contracts are recovered.
- **Saving:** persist an explicit native game-state schema. Reading or writing
  original PS2 saves needs separate format and round-trip evidence; saving a
  Godot scene is not character-save compatibility.
- **Networking:** preserve the separation between local presentation and shared
  simulation. Do not let render rate, audio progress or scene callback order
  choose authoritative outcomes. Test deterministic core traces on arm64/x64;
  fixed physics ticks alone are not proof of identical simulation.

**Observed:** Godot supports replaceable multiplayer interfaces. **Assessment:**
its default scene multiplayer cannot be assumed compatible with the documented
original SOE protocol;
Champions Reborn lobby compatibility and original-client interoperability need
explicit protocol work; adding Godot RPC calls does not establish either. Keep
initial native multiplayer tests between native peers until compatibility is
actually demonstrated.
[Godot MultiplayerAPI](https://docs.godotengine.org/en/stable/classes/class_multiplayerapi.html).

### Next useful Godot milestone

**Proposed:** first display a real texture from the user's own archive, then
one real static mesh/material, and then a small controllable scene. Avoid treating
a blank window or generated placeholder character as recovered Champions content.

1. Select one small texture whose layout is established by the active research
   pass. Add an authored decoder with synthetic fixtures, using the existing
   archive library to locate its bytes. Keep original assets outside the repo.
2. Expose the decoded texture through a thin GDExtension and display it in Godot.
   Verify dimensions, palette/alpha and orientation against a private reference;
   show a useful error for unsupported formats. Repeat on native Mac and Windows
   exports, not solely in the editor.
3. Decode one static mesh and its material, inspect scale, winding and UVs, and
   add orbit/zoom inspection. This is an asset-viewer milestone with explicit
   visual evidence, not a playable port.
4. Build one bounded offline scene: a controllable character, collision, camera,
   one trigger and save/reload. Add recovered animation as its format becomes
   available; label provisional behavior. Record movement and state traces before
   expanding combat, navigation or multiplayer.

The public artifact contains authored decoders, extension code, scenes and
synthetic tests. The application selects the user's game-data folder at runtime;
original game files are not embedded in exported packages. Reuse Claude's format
and behavior findings when they land rather than starting duplicate area audits.

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
architectures were subsequently verified by [CI run 38032707157](https://github.com/Open-Champions/champions-return-to-arms-re/actions/runs/38032707157)
at source revision `cf00c28`: macOS arm64/x64, Windows arm64/x64 and Linux x64
all built the inspector and passed its seven CTest cases. Python checks passed
on all targets, including a separate Linux Python 3.14 job. These results verify
the inspector and tested tools, not a Godot export.

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

**Proposed next milestones:** the Godot real-asset viewer and controllable scene
defined above, alongside an authored script VM with synthetic deterministic traces;
finally two native peers with replay and divergent-frame diagnostics. Each milestone requires its own behavior and visual tests.
A blank window is an integration check, not evidence of a recovered renderer.

## Completion boundary

The authored archive parser and CLI are delivered and locally verified on
Apple Silicon. No third-party dependencies were installed; the server and Claude
area files were not modified by this work. The project still has no verified
playable native client or defensible completion date. Cross-platform inspector
checks passed; the next step is the first real-asset Godot integration from
the ongoing research. Godot is the recommended next engine layer;
no engine migration or graphical prototype is represented as completed here.
