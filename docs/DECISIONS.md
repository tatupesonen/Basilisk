# Architecture decision records

Append new records; never silently rewrite an accepted one. To change a
decision, add a record that supersedes it and mark the old one
`Superseded by ADR-NNN`. Status is **Accepted** unless a record says
otherwise.

## ADR-001 — Port Ghidra's behaviour, write idiomatic Rust
basilisk reproduces what Ghidra *does* — algorithms, heuristics, defaults,
names, messages, output — with Ghidra's source (`../ghidra`, pinned at commit
`42db038f3c`) as the specification. It does not reproduce how Ghidra is
*structured*: no class hierarchies transliterated from Java or C++, no
plugin/service-locator framework, no global singletons. Where reading the
source shows a better design that gives the same observable behaviour, use
it.

basilisk is **not a one-to-one port, and improving on Ghidra is allowed**
(owner decision, 2026-11-12). Ghidra's behaviour is the baseline: match it
by default, because users, spec files and ported tests all assume it. Depart
from it when the result is better — a Ghidra bug fixed, a faster or simpler
algorithm, a clearer result, a missing case handled — and make every
departure deliberate: record it under "Differences from Ghidra" in the
feature doc (and in an ADR when it is not obvious), and let the ported test
accept Ghidra's form as the documented alternative (ADR-007). An accidental
difference is a bug. Consequence: every feature doc names the Ghidra sources
it derives from, so behaviour can be re-checked.

## ADR-002 — Ghidra's processor specifications are consumed unchanged
basilisk reads Ghidra's language data as-is: SLEIGH sources (`.slaspec`,
`.sinc`), compiled SLEIGH (`.sla`, format version 4), `.ldefs`, `.pspec`,
`.cspec`, `.opinion`, function-start pattern XML and the per-processor
`data/` files. This gives all 150 SLEIGH languages and 110 compiler specs
without rewriting 310,000 lines of specification, and lets a user drop in a
processor module written for Ghidra. The files are not copied into this
repository: tools and tests locate them through a *spec root*
(`BASILISK_GHIDRA_DIR`, default `../ghidra`), and release builds bundle the
`Ghidra/Processors/*/data` trees. Processor-specific Java code (59,000
lines under `Ghidra/Processors`: relocation handlers, analyzers, loaders'
extensions) is not data and is ported like any other code.

## ADR-003 — Own program database, not Ghidra-compatible
basilisk stores programs in its own format, designed around the queries
analysis and the UI actually run. It does not read or write Ghidra's
project, `.gzf` or packed-database formats (owner decision). The **storage
engine is not chosen yet**: it is decided at the start of milestone M4 by a
benchmark spike that measures the candidates (SQLite through `rusqlite`,
`redb`, and a purpose-built memory-mapped store) against the M4 budgets in
`PERF.md` — bulk insert of 10 million instructions, address-ordered range
scans, transaction rollback and undo. Requirements fixed now: transactions
with undo/redo, crash safety, one writer with many readers, memory use
bounded by working set rather than program size, and a versioned schema with
forward migrations. Ghidra's `Framework/DB` tests (280) are ported against
the storage API wherever they describe behaviour the API has (tables,
indexes, iteration order, transactions); tests of Ghidra's on-disk B-tree
node layout are marked not applicable. An importer for Ghidra projects may
be added later without changing this decision.

## ADR-004 — The decompiler is an in-process Rust port, with Ghidra's output as baseline
Ghidra's decompiler (190,000 lines of C++ in
`Ghidra/Features/Decompiler/src/decompile/cpp`: 167 rewrite rules, 77
actions) is ported module by module with the same pipeline, the same rule
and action names, the same ordering and the same options, so that output
matches Ghidra's. It runs **in process** as a library: there is no separate
decompiler executable and no pipe protocol; the queries Ghidra's
`DecompileCallback` answers over the pipe (bytes, p-code, symbols, data
types, comments, injections) become a Rust trait the program model
implements. Rationale for fidelity: the engine's value is thousands of
tuned heuristics, and output parity is the only practical correctness test.
Consequences: the internal IR may be redesigned for Rust (ADR-012: arenas
and indices, not pointer graphs), and rule behaviour may not drift
*accidentally*. Improvements to the decompiler's output are welcome under
ADR-001, but only on top of measured parity: first reproduce Ghidra's output
for the affected tests, then change it deliberately, with the before/after
recorded in the feature doc. Parity
is checked by Ghidra's 93 data tests, its 205 C++ unit tests and
differential runs against the reference `decomp` binary (ADR-007).

## ADR-005 — Pure Rust; Ghidra's code is an oracle, never a dependency
The product contains no FFI to Ghidra's C++ and does not shell out to a
Ghidra installation or a JVM. Ghidra's native tools (`sleigh`, `decomp`)
built from source, and optionally a full Ghidra installation, are
**development-only oracles** for differential tests (ADR-007). A C
dependency in the product needs its own ADR. `unsafe` is forbidden
workspace-wide (`unsafe_code = "forbid"`); a crate that needs it (for
example a memory-mapped store) is named in an ADR and isolates the unsafe
code in one small, documented module.

## ADR-006 — Test parity: every Ghidra test has a Rust counterpart
Every automated Ghidra test is tracked in `docs/inventory/tests/`
(generated by `scripts/gen-test-inventory.py`) and ends up in one of two
states: **ported** (`- [x]`, with the Rust test named) or **not
applicable** (`- [-]`, with the reason). Rules:

* Port what the test *checks* — inputs, expected outputs, edge cases — not
  its literal code. Many small Java test classes may become one
  table-driven Rust test. If basilisk's design differs from Ghidra's
  (ADR-001), the ported test asserts the same behaviour through basilisk's
  API.
* **GUI tests** (801 classes drive Swing) become `egui_kittest` tests of
  the equivalent basilisk feature, asserting the same user-visible
  behaviour. Where a GUI test is really checking a command or model
  underneath, that part is also ported as a headless test.
* **Not applicable** is allowed only for tests of machinery basilisk does
  not have by decision: Swing/docking-framework internals, look-and-feel,
  Java-specific utilities replaced by the Rust standard library, Ghidra's
  on-disk database node layout (ADR-003). Each mark carries its reason.
* A feature is not done until its lines in the checklist are marked.
* Ghidra's tests are a floor. Parsers additionally get property tests and
  fuzz targets (ADR-009), and behaviour Ghidra never tests gets tests
  derived from its source.

## ADR-007 — Differential testing against reference Ghidra
Where behaviour is defined by Ghidra's output, tests compare basilisk with
Ghidra itself:

* **Reference tools** — Ghidra's C++ `sleigh` compiler and `decomp`
  console, built from a copy of the source into `../reference/` by
  `scripts/build-reference.sh`. They give compiled `.sla` files for every
  language, per-instruction disassembly and p-code, and decompiler output.
* **Full Ghidra** (optional, `GHIDRA_INSTALL_DIR`) — headless runs that dump
  loader, analysis and program-model results for whole binaries.

Tests that need an oracle or the spec root skip themselves with a clear
message when it is absent, so the default `cargo test` runs anywhere;
expected outputs that are small and stable are checked in as goldens so CI
does not need the oracle. Where basilisk is deliberately better, the test
accepts Ghidra's form as an alternative and documents the improvement.
`bk-testkit` owns the oracle wrappers.

## ADR-008 — GUI stack: eframe/egui, egui_dock, deferred viewports
The UI is eframe/egui (wgpu) with `egui_dock` for the docked main layout
and deferred viewports for native pop-out windows — the stack postmortem
uses (its ADR-008). Exact versions are pinned when milestone M7 starts.
All program-database and analysis work runs off the UI thread; views are
virtualised over indexed queries. UI tests use `egui_kittest`. Library
crates never depend on UI crates.

## ADR-009 — Panic-free handling of untrusted input, enforced by lints
Binaries under analysis are hostile, and spec files and saved programs may
be malformed. No input may panic, overflow, recurse without bound or
allocate without bound. `clippy::indexing_slicing` and `unwrap_used` are
denied outside tests; parsers use checked accessors and `checked_*`
arithmetic, with explicit size and depth limits. Where an index is provably
in range and the checked form hurts clarity or a measured hot path, use
`#[expect(clippy::indexing_slicing, reason = "...")]`. Every binary-format
parser has a `proptest` "never panics" test and a `cargo-fuzz` target.
Ghidra throws exceptions in these places; basilisk returns typed errors
(`thiserror`) and recovers what is readable.

## ADR-010 — Licence: Apache-2.0
basilisk is Apache-2.0, the same as Ghidra, of which it is a derivative
work. Ghidra's notice is reproduced in `NOTICE`. Dependencies must be
Apache-2.0-compatible (MIT, BSD, ISC, Zlib, Unicode; MPL-2.0 unmodified);
no GPL or proprietary code. Ghidra's GPL modules (`GPL/`: the GNU demangler
and disassembler wrappers, DMG) are not ported from their GPL sources;
their function is provided by permissively licensed Rust code. Enforced
with `cargo-deny` once it joins the gate.

*Superseded by ADR-018 (2026-11-12): the project is GPL-3.0-or-later and
Ghidra's GPL modules are ported like any other code.*

## ADR-011 — Prefer existing crates when they meet requirements
For every component, first evaluate existing crates against: behavioural
parity with Ghidra (the tests in `docs/inventory/tests/` must be
portable against it), robustness on hostile input (ADR-009), performance
(ADR-012), licence (ADR-010), maintenance and maturity. Adopt when the
crate passes; otherwise write it and keep the crate as a dev-only
differential oracle. Record each evaluation here.

Evaluations so far:
- **Compression: `flate2` with the `zlib-rs` backend → adopt.** Pure Rust.
  `.sla` files are zlib streams; decompressed content is compared, never
  compressed bytes.
- **XML reading: `roxmltree` → adopt provisionally** for `.ldefs`,
  `.pspec`, `.cspec`, `.opinion` and decompiler data tests. The foundation
  track verifies that every XML file under `../ghidra/Ghidra/Processors`
  and `datatests/` parses, and falls back to porting Ghidra's `xml.cc` if
  any does not.
- **Object-file parsing: `object`, `goblin` → oracle only.** Ghidra's
  loaders expose format details (every header field, relocation and
  dynamic-table entry, vendor extensions) and tolerate malformed files in
  specific ways that its tests assert. The format crates are ports of
  Ghidra's parsers; `object` is a dev-dependency for differential tests.
- **To evaluate when reached**: `gimli` (DWARF), `pdb`/`pdb2`,
  `cpp_demangle`, `msvc-demangler`, `symbolic-demangle`, `tree-sitter` or
  `lang-c` (C parser), `petgraph`, `rustc-hash`, `smallvec`, `indexmap`,
  `bumpalo`, `egui_dock`, `rusqlite`, `redb`.

## ADR-012 — Performance principles
Speed and memory are design inputs. Budgets and measurements live in
`PERF.md`; a feature with a hot path lands with a benchmark.

* **Data layout.** Graph-shaped IR (p-code ops, varnodes, basic blocks,
  SLEIGH decision trees, data types) lives in arenas addressed by typed
  `u32` indices, not in `Rc<RefCell<…>>` or `Box` webs. Names and other
  repeated strings are interned. Small collections use inline storage.
  Hot structs are kept small and their sizes asserted in tests.
* **No hidden allocation in inner loops.** Instruction decoding and p-code
  emission reuse buffers; byte sources are borrowed slices or positional
  readers, never copied per instruction.
* **Parallelism.** Work that is independent per function or per address
  range (disassembly of disjoint ranges, decompilation, analysis passes
  that allow it) runs on a thread pool; shared read-mostly data
  (compiled languages, data types) is `Send + Sync` and immutable after
  load. Determinism is kept: parallel results are merged in a defined
  order so output does not depend on scheduling.
* **Memory bounded by working set**, not program size (ADR-003).
* **Targets** (enforced by benchmarks as they become measurable): SLEIGH
  language load, disassembly throughput and per-function decompile time at
  least as good as Ghidra's on the same input; the UI never blocks on
  analysis or storage.
* Measure before optimising beyond these principles; record numbers.

## ADR-013 — Workspace layout: focused `bk-*` crates, small files
One Cargo workspace; crates are named `bk-<component>` and the binary is
`basilisk`. A component that can be used or tested on its own is its own
crate: each file format, the SLEIGH syntax, compiler and runtime, the
p-code core, the program model, each analysis family, the decompiler, the
UI. Dependencies point one way (crate map in `PLAN.md`); parsers know
nothing about programs or storage; nothing below the UI depends on it.
Inside a crate, one module per concept; a source file over about 600 lines
is a signal to split, and 1,000 lines is a hard ceiling enforced by
`scripts/check-file-size.sh` (generated tables and ported test vectors may
opt out with a stated reason). Ghidra's large files (`ruleaction.cc` is
11,000 lines) become module trees — one file per rule family — never one
Rust file.

## ADR-014 — Plugin API in Python through PyO3
(Owner decision, 2026-11-12: "use pyo3 for the plugin api, so users will
still be able to build their own plugins.")

Ghidra's extension surface is its Java API: scripts, analyzers, loaders and
plugins, written in Java or Python. basilisk cannot run those, but users
must still be able to build their own plugins. The plugin API is **Python,
bound with PyO3**:

* A `bk-plugin` crate embeds CPython through PyO3 and exposes the program
  model, analysis, the decompiler and (from M7) UI hooks as a Python
  package. A plugin is a Python module or package that registers what it
  provides: scripts, analyzers, loaders, exporters, and later UI actions
  and views — the kinds Ghidra's extension points cover.
* The same bindings are published as an importable Python module, so
  basilisk can also be driven from an ordinary Python process (the role
  PyGhidra plays for Ghidra).
* The Python API is designed for Python, with a flat scripting layer
  modelled on Ghidra's `FlatProgramAPI`/`GhidraScript` so existing Ghidra
  scripts port with small changes. It is versioned; breaking it bumps the
  version plugins declare.
* The Rust API of the `bk-*` crates remains available to anyone who builds
  against basilisk as a library, but it is not the stable plugin contract.

Consequences. CPython is a C dependency and PyO3 uses `unsafe` internally:
both are confined to `bk-plugin` (and the Python-module build), which is an
optional feature of the product, so the core stays pure Rust with
`unsafe_code = "forbid"` (this ADR is the exception ADR-005 requires).
Plugins run in process with the user's privileges — they are trusted code,
as Ghidra's are — and Python plugins hold the GIL, so long-running native
work (analysis, decompilation) releases it and parallelism stays on the
Rust side. The design is detailed in a feature spec before milestone M9;
core APIs are shaped from the start so that binding them is direct
(owned or reference-counted handles at the boundary, no lifetimes in types
that plugins hold, errors convertible to Python exceptions).

## ADR-015 — Development by coordinated parallel agents
Work proceeds in waves. For each wave the coordinator writes one feature
spec per track in `docs/features/`, with disjoint crate ownership, then
starts one implementation agent per track in its own git worktree and
branch. Agents commit locally; the coordinator reviews each branch against
its spec, runs the gate, merges to `master`, and writes the next wave's
specs from what was learned. Tracks in one wave must not depend on each
other's unmerged code; a dependency between them is cut with a small trait
or deferred to the next wave. Rules: `docs/agents/RULES.md`; protocol:
`docs/LOOP.md`.

## ADR-016 — Ghidra's GPL helpers are ported, as separate GPL programs
*Superseded by ADR-018 (2026-11-12). The table of what Ghidra's GPL modules
are still stands; the separate programs and the `gpl/` directory do not.*

(Owner decision, 2026-11-12: "just port the ghidras gpl helpers."
Supersedes the GPL clause of ADR-010.)

Ghidra keeps three GPL-licensed modules under `GPL/`, apart from its
Apache-2.0 code, and runs them as separate programs:

| Ghidra module | What it is | basilisk |
|---|---|---|
| `GPL/DemanglerGnu` | The GNU demangler from binutils' libiberty (two versions, 2.24 and 2.41; 34,000 lines of C), built as `demangler_gnu_v2_24`/`v2_41` executables that Ghidra feeds mangled names over a pipe | `gpl/bk-gpl-demangler-gnu` |
| `GPL/GnuDisassembler` | `gdis`, a small C program over binutils' libopcodes that the user builds, used as an external disassembler for comparison | `gpl/bk-gpl-gdis` |
| `GPL/DMG` | A Java program over the GPL HFSExplorer libraries that reads Apple DMG/HFS+ images for the file-system browser | `gpl/bk-gpl-dmg` |

basilisk ports them and keeps Ghidra's separation, which is what lets the
rest stay Apache-2.0 (ADR-010):

* They live in a top-level `gpl/` directory, outside `crates/`, each crate
  with `license = "GPL-3.0-or-later"` and the GPL text beside it. A Rust
  port of GPL code is a derivative work and carries the GPL.
* Each builds a **separate helper executable**. The Apache-2.0 crates talk
  to it as a subprocess over a pipe, as Ghidra does, and never link it:
  no `bk-*` crate under `crates/` may depend on a crate under `gpl/`
  (checked by `cargo-deny` and a gate script when the first one lands).
  Linking them in would put the whole distributed binary under GPL-3.0.
* The Apache-2.0 side of each feature — Ghidra's `Features/GnuDemangler`
  (the parser of demangler output and the analyzer), the external
  disassembler field, the DMG file system client — is ported in `crates/`
  as usual and works when the helper is absent by reporting that it is
  missing, as Ghidra does.
* Release archives ship the helpers with their source offer and licence
  texts; a build without `gpl/` is still a complete Apache-2.0 product.

Schedule: the GNU demangler with milestone M6 (it is self-contained and a
candidate for an earlier wave); `gdis` and DMG with M10.

## ADR-017 — One binary: the GPL ports are linked in, behind a default feature
*Superseded by ADR-018 (2026-11-12). basilisk is still one binary; the
`gpl` feature, the `gpl/` directory and the dual licensing do not stand.*

(Owner decision, 2026-11-12: "I want a single binary though." Supersedes
the separate-program arrangement of ADR-016.)

basilisk ships as **one executable**. The ports of Ghidra's GPL helpers
(ADR-016) are ordinary library crates under `gpl/`, licensed
GPL-3.0-or-later, and are linked into the `basilisk` binary instead of
being run as helper processes.

Licensing consequence, stated plainly: **a binary that includes the GPL
crates is distributed under GPL-3.0-or-later.** Apache-2.0 code may be
combined into a GPL-3.0 work, so this is permitted, but the combined
binary carries the GPL's terms (source availability for whoever receives
the binary). What does not change: every crate under `crates/` remains
Apache-2.0 source that anyone may reuse under Apache-2.0.

Structure:

* The GPL crates are pulled in only by the `basilisk` binary crate (and
  `bk-plugin`'s Python module build), through a Cargo feature **`gpl`,
  on by default**. Library crates under `crates/` never depend on `gpl/`
  crates: they define the interface (for the demangler, a trait the
  analyzer calls) and the binary plugs the GPL implementation in. This
  keeps the Apache-2.0 crates free of GPL dependencies, checked by
  `cargo-deny` and a gate script when the first `gpl/` crate lands.
* `cargo build --no-default-features` (without `gpl`) gives an
  Apache-2.0 binary in which those three functions report that they are
  not built in. Release archives are the default, GPL-3.0 build; they
  ship both licence texts and state the binary's licence.
* `basilisk --version` and the About view say which licence the running
  binary is under.

Open point for milestone M10: Ghidra's `gdis` is a 576-line wrapper around
binutils' libopcodes, which Ghidra does not ship (the user builds
binutils). A single binary cannot wrap an external C library the user must
build, and porting libopcodes itself is out of proportion to a comparison
aid. How `gdis` is provided is decided when M10 is planned.

Alternative not taken, recorded so it can be revisited: an Apache-2.0
single binary is possible if the GNU demangler is written from
permissively licensed sources (the Itanium C++ ABI specification, LLVM's
demangler) instead of ported from libiberty. The owner chose to port
Ghidra's helpers.

## ADR-018 — The project is GPL-3.0-or-later; GPL code is ported like any other
(Owner decisions, 2026-11-12: "Not any wrappers and such. Just port the
code" and "i dont mind gpl3". Supersedes ADR-010, ADR-016 and ADR-017.)

basilisk is licensed **GPL-3.0-or-later** as a whole, and ships as a
single binary. Ghidra's GPL modules (`GPL/DemanglerGnu`,
`GPL/GnuDisassembler`, `GPL/DMG`; described in ADR-016) are ported to Rust
exactly as Ghidra's Apache-2.0 code is: ordinary crates under `crates/`,
called directly. There are no helper processes, no pipe protocol, no
`gpl/` directory, no Cargo feature and no licence boundary between
crates.

* `LICENSE` is the GPL, version 3. Code ported from Ghidra's Apache-2.0
  source is included under the terms that licence allows (Apache-2.0 code
  may be part of a GPL-3.0 work): Ghidra stays attributed in `NOTICE`, and
  the Apache licence text is kept as `LICENSE-APACHE`.
* Where Ghidra runs a GPL program over a pipe and parses its text output
  (`Features/GnuDemangler` drives `demangler_gnu` this way), basilisk
  calls the ported code as a library and takes structured results;
  Ghidra's tests of the text protocol are ported against the direct API.
* Dependencies must be GPL-3.0-compatible: Apache-2.0, MIT, BSD, ISC,
  Zlib, Unicode, MPL-2.0, LGPL, GPL-2.0-or-later, GPL-3.0. No
  GPL-2.0-only, no proprietary code. Enforced with `cargo-deny` once it
  joins the gate.
* Schedule: the GNU demangler (libiberty's, 34,000 lines of C in two
  versions; self-contained) with milestone M6 or an earlier wave; DMG and
  the GNU disassembler with M10.

Ghidra's `gdis` is a 576-line program over binutils' libopcodes, which
Ghidra does not include (the user builds binutils 2.41). How basilisk
provides it is settled by ADR-019.

## ADR-019 — binutils is built from source as its own crate
(Owner decision, 2026-11-12: "You can clone binutils source yourself and
build it as its own crate." Resolves the open point of ADR-018.)

Ghidra's GNU disassembler module (`GPL/GnuDisassembler`) lets the user
compare SLEIGH's disassembly with GNU's. It is a small C program, `gdis`,
over binutils' libopcodes and libbfd, and Ghidra makes the user fetch and
build binutils 2.41 themselves. basilisk builds binutils in:

* A crate **`bk-binutils-sys`** compiles the parts of binutils 2.41 the
  disassembler needs (libopcodes, libbfd, libiberty and their headers)
  from source and links them statically, so the feature works in the one
  binary with nothing for the user to install. A safe crate
  **`bk-gnu-disasm`** on top ports what `gdis` does (`disasm_1.c`,
  `gdis.h`: pick the architecture and machine, feed bytes, collect
  instruction text) as a Rust API.
* The binutils source is pinned to the release Ghidra names
  (`binutils-2_41`). A reference clone is at `../binutils`; how the source
  reaches the build (a git submodule under `vendor/`, or a vendored
  subset) and how it is compiled on every supported platform, Windows
  included, is specified in the feature doc when the work is scheduled.
* This is C code and FFI, so it is the exception ADR-005 requires:
  `unsafe` and the C toolchain are confined to `bk-binutils-sys`, whose
  whole surface is a handful of documented functions; everything above it
  is safe Rust. The disassembler is given bytes from binaries under
  analysis, so the wrapper bounds every length it passes and the crate
  gets a fuzz target.
* binutils is GPL-3.0-or-later, which matches the project (ADR-018).

The GNU demangler is a different case: Ghidra carries libiberty's
demangler source in its own tree (`GPL/DemanglerGnu`), and that is ported
to Rust (ADR-018), not built from C.

Schedule: milestone M10 with the rest of the comparison tooling, or
earlier if a differential test wants GNU's disassembly as a second oracle.
