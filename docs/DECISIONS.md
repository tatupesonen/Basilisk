# Architecture decision records

Append new records; never silently rewrite an accepted one. To change a
decision, add a record that supersedes it and mark the old one
`Superseded by ADR-NNN`. Status is **Accepted** unless a record says
otherwise.

## ADR-001 — Port Ghidra's behaviour, write idiomatic Rust
Basilisk reproduces what Ghidra *does* — algorithms, heuristics, defaults,
names, messages, output — with Ghidra's source (`../ghidra`, pinned at commit
`42db038f3c`) as the specification. It does not reproduce how Ghidra is
*structured*: no class hierarchies transliterated from Java or C++, no
plugin/service-locator framework, no global singletons. Where reading the
source shows a better design that gives the same observable behaviour, use
it.

Basilisk is **not a one-to-one port, and improving on Ghidra is allowed**
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
Basilisk reads Ghidra's language data as-is: SLEIGH sources (`.slaspec`,
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
Basilisk stores programs in its own format, designed around the queries
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
  table-driven Rust test. If Basilisk's design differs from Ghidra's
  (ADR-001), the ported test asserts the same behaviour through Basilisk's
  API.
* **GUI tests** (801 classes drive Swing) become `egui_kittest` tests of
  the equivalent Basilisk feature, asserting the same user-visible
  behaviour. Where a GUI test is really checking a command or model
  underneath, that part is also ported as a headless test.
* **Not applicable** is allowed only for tests of machinery Basilisk does
  not have by decision: Swing/docking-framework internals, look-and-feel,
  Java-specific utilities replaced by the Rust standard library, Ghidra's
  on-disk database node layout (ADR-003). Each mark carries its reason.
* A feature is not done until its lines in the checklist are marked.
* Ghidra's tests are a floor. Parsers additionally get property tests and
  fuzz targets (ADR-009), and behaviour Ghidra never tests gets tests
  derived from its source.

## ADR-007 — Differential testing against reference Ghidra
Where behaviour is defined by Ghidra's output, tests compare Basilisk with
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
does not need the oracle. Where Basilisk is deliberately better, the test
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
Ghidra throws exceptions in these places; Basilisk returns typed errors
(`thiserror`) and recovers what is readable.

## ADR-010 — Licence: Apache-2.0
Basilisk is Apache-2.0, the same as Ghidra, of which it is a derivative
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

Among crates that pass, **prefer the industry-standard one** (owner rule,
2026-11-12): the widely used crate with a large download count and many
dependents on crates.io, over a newer or niche alternative, even where the
niche one is somewhat nicer. Choosing a little-used crate needs a stated
reason (the standard one fails a requirement above), and the evaluation
records the download figures that were compared.

Evaluations so far:
- **Compression: `flate2` with the `zlib-rs` backend → adopt.** Pure Rust.
  `.sla` files are zlib streams; decompressed content is compared, never
  compressed bytes.
- **XML reading: `quick-xml` → adopt; `roxmltree` → oracle only**
  (2026-11-12, from the `core-marshal` track's corpus check, superseding
  the provisional choice of `roxmltree`). `roxmltree` parses all 501 XML
  files under Ghidra's processor and data-test trees, but it merges text,
  entity references and CDATA into one node, so Ghidra's rule of dropping
  white-space-only content pieces (`xml.y`) cannot be reproduced: three
  corpus elements decode differently (one `<com>` in
  `datatests/injectoverride.xml`, two `<body>` in `hexagon.cspec`).
  `quick-xml`'s events map one-to-one onto `xml.y`'s rules, and it is the
  more widely used crate (542 million downloads and 2,935 dependents
  against 104 million and 994). `bk-marshal` builds its own small DOM on
  `quick-xml` events; `roxmltree` stays as a dev-only oracle in the corpus
  test. Crates that read Ghidra XML should go through `bk-marshal`'s
  document rather than a second XML crate; `bk-lang`, written in the same
  wave on `roxmltree`, moves over after both merge.
- **ELF parsing: `object`, `goblin` → oracle only** (confirmed 2026-11-12
  by experiment in the `bin-elf` track; the program is kept under
  `docs/agents/bin-elf-crate-eval/`). A real `.so` was damaged in eleven
  ways that Ghidra tolerates and both crates were run on each. `object`
  0.40.0 (712 million downloads): a cut-off or over-counted section table
  or an out-of-range `e_shstrndx` yields no sections at all where Ghidra
  keeps what fits; an invalid `EI_DATA` is rejected where Ghidra assumes
  little-endian; there is no path from the dynamic table to dynamic symbols
  in stripped files; no Android packed relocations or entry-size
  validation. `goblin` 0.10.7 (88 million): strict mode aborts on any bad
  table, permissive mode replaces bad tables with empty ones and logs
  globally instead of returning diagnostics; a bad `e_phoff` is fatal
  either way; no extended numbering, RELR or Android relocations; parses
  eagerly from one slice. Neither can carry Ghidra's tolerance rules, which
  are the reason an analysis tool's ELF reader exists, so `bk-elf` is its
  own parser and `object` is a dev-dependency used as a differential
  oracle on well-formed files. The same question is asked afresh for PE and
  Mach-O when those tracks start.
- **`roxmltree` must be 0.21.2 or later** (2026-11-12). Version 0.21.1
  overflows the stack on deeply nested elements — a crash on hostile
  input (ADR-009); 0.21.2 (released 2026-10-24) parses element content
  iteratively. Found at the merge gate, when the lock file was held at
  0.21.1 and `bk-lang`'s 100,000-deep nesting test aborted. Lesson: holding
  a dependency back to an older "vetted" version can remove a fix; read
  the changelog before pinning downward.
- **SLEIGH lexer and parser: hand-written; `logos`, `winnow`, `nom`,
  `pest`, `lalrpop`, `chumsky` → not adopted** (2026-11-12, `sleigh-syntax`
  track; figures and detail in `features/sleigh-syntax.md` §8). SLEIGH's
  lexer has three modes that the *parser* switches per token, with
  re-lexing from arbitrary offsets; the parser needs per-construct error
  recovery and an explicit nesting limit. `logos` (101 million downloads)
  cannot share token definitions across the mode enums; each parser
  library fails one of the three needs. Adopted for the crate:
  `string-interner` (a process-global atom table such as `string_cache`
  is excluded by the no-global-state rule), `rustc-hash`, `num-bigint`.
- **Lock-file versions follow the two-week rule too** (2026-11-12). When a
  merge regenerates `Cargo.lock`, a transitive dependency may float to a
  release only days old; hold it at the newest version that is at least
  two weeks old (`cargo update -p <crate> --precise <version>`), unless the
  newer release fixes something we need — check its changelog first, as
  the `roxmltree` case above shows. Held at the bin-elf merge: `flate2`
  1.1.10, `itoa` 1.0.18, `smallvec` 1.16.4.
- **`dhat` 0.3.3 → adopt as a dev-dependency** (`bin-elf`; 15.6 million
  downloads): heap profiling in a test, used to assert `bk-elf`'s
  allocation bound on damaged files.
- **`encoding_rs` → not adopted for `bk-bin`** (tried, 0.8.35): it maps
  ASCII and Latin-1 labels to windows-1252 and has no UTF-32, and its
  UTF-8/16 decoding equals the standard library's, so it would replace
  nothing and break two of the charsets Ghidra's reader defines.
- **Other adoptions recorded in feature docs**: `num-bigint`,
  `primitive-types`, `libm` (`features/pcode.md`); `walkdir`,
  `wait-timeout`, `insta` (`features/reference-tools.md`,
  `features/lang.md`); `quick-xml` (above).
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
plugins, written in Java or Python. Basilisk cannot run those, but users
must still be able to build their own plugins. The plugin API is **Python,
bound with PyO3**:

* A `bk-plugin` crate embeds CPython through PyO3 and exposes the program
  model, analysis, the decompiler and (from M7) UI hooks as a Python
  package. A plugin is a Python module or package that registers what it
  provides: scripts, analyzers, loaders, exporters, and later UI actions
  and views — the kinds Ghidra's extension points cover.
* The same bindings are published as an importable Python module, so
  Basilisk can also be driven from an ordinary Python process (the role
  PyGhidra plays for Ghidra).
* The Python API is designed for Python, with a flat scripting layer
  modelled on Ghidra's `FlatProgramAPI`/`GhidraScript` so existing Ghidra
  scripts port with small changes. It is versioned; breaking it bumps the
  version plugins declare.
* The Rust API of the `bk-*` crates remains available to anyone who builds
  against Basilisk as a library, but it is not the stable plugin contract.

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

| Ghidra module | What it is | Basilisk |
|---|---|---|
| `GPL/DemanglerGnu` | The GNU demangler from binutils' libiberty (two versions, 2.24 and 2.41; 34,000 lines of C), built as `demangler_gnu_v2_24`/`v2_41` executables that Ghidra feeds mangled names over a pipe | `gpl/bk-gpl-demangler-gnu` |
| `GPL/GnuDisassembler` | `gdis`, a small C program over binutils' libopcodes that the user builds, used as an external disassembler for comparison | `gpl/bk-gpl-gdis` |
| `GPL/DMG` | A Java program over the GPL HFSExplorer libraries that reads Apple DMG/HFS+ images for the file-system browser | `gpl/bk-gpl-dmg` |

Basilisk ports them and keeps Ghidra's separation, which is what lets the
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
*Superseded by ADR-018 (2026-11-12). Basilisk is still one binary; the
`gpl` feature, the `gpl/` directory and the dual licensing do not stand.*

(Owner decision, 2026-11-12: "I want a single binary though." Supersedes
the separate-program arrangement of ADR-016.)

Basilisk ships as **one executable**. The ports of Ghidra's GPL helpers
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

Basilisk is licensed **GPL-3.0-or-later** as a whole, and ships as a
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
  (`Features/GnuDemangler` drives `demangler_gnu` this way), Basilisk
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
Ghidra does not include (the user builds binutils 2.41). How Basilisk
provides it is settled by ADR-019.

## ADR-019 — binutils is built from source as its own crate
(Owner decision, 2026-11-12: "You can clone binutils source yourself and
build it as its own crate." Resolves the open point of ADR-018.)

Ghidra's GNU disassembler module (`GPL/GnuDisassembler`) lets the user
compare SLEIGH's disassembly with GNU's. It is a small C program, `gdis`,
over binutils' libopcodes and libbfd, and Ghidra makes the user fetch and
build binutils 2.41 themselves. Basilisk builds binutils in:

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

binutils' code is used unmodified (owner, 2026-11-12: "just use existing
binutils, no value in rewriting them"). The one exception the owner allows:
a particular part may be rewritten in Rust if it is really slow — shown by
a benchmark recorded in `PERF.md`, not assumed.

Schedule: milestone M10 with the rest of the comparison tooling, or
earlier if a differential test wants GNU's disassembly as a second oracle.

## ADR-020 — `unsafe` only when absolutely necessary, and then checked with Miri
(Owner rule, 2026-11-12: "do not use unsafe unless absolutely necessary,
and check that all code with miri that does need unsafe." Tightens the
`unsafe` clause of ADR-005.)

* **Default: none.** `unsafe_code = "forbid"` is a workspace lint and
  every crate inherits it. Performance is not by itself a reason: a safe
  design is tried and measured first, and `unsafe` is considered only when
  a benchmark shows a safe version cannot meet a budget in `PERF.md`, or
  when the thing cannot be expressed safely at all (calling C, a
  memory-mapped file). Prefer a well-used crate that encapsulates the
  unsafe code (ADR-011) over writing our own.
* **Opting out is explicit.** A crate that needs `unsafe` is listed in
  `unsafe-crates.txt` with the reason; `scripts/check-unsafe.sh` (in the
  gate) rejects `unsafe` anywhere else. In such a crate the unsafe code
  sits in one small module behind a safe API; every `unsafe` block has a
  `// SAFETY:` comment stating why it is sound
  (`clippy::undocumented_unsafe_blocks`), holds one unsafe operation
  (`multiple_unsafe_ops_per_block`), and `unsafe_op_in_unsafe_fn` is
  denied.
* **Miri.** Every crate listed with `miri` has tests that exercise each
  unsafe path, and `scripts/miri.sh` runs them under Miri (nightly, with
  strict provenance and symbolic alignment checking). It must pass before
  the crate merges and whenever its unsafe code changes; CI runs it.
* **What Miri cannot check.** Miri interprets Rust; it cannot execute
  foreign code. A crate whose `unsafe` is calls into C — today only
  `bk-binutils-sys` (ADR-019), later the PyO3 boundary in `bk-plugin`
  (ADR-014) — is listed `no-miri:<reason>` and is instead checked with
  AddressSanitizer and UndefinedBehaviorSanitizer builds of its tests and
  fuzz targets, with the Rust-side wrappers kept thin enough to review by
  eye. Any pure-Rust unsafe in such a crate is split into a module that
  Miri does run.

Currently no crate on `master` contains `unsafe`.

## ADR-021 — Where Ghidra's result depends on the host, Basilisk takes x86-64's
(Proposed by the `pcode` track, accepted 2026-11-12.)

Some of Ghidra's C++ behaviour is not defined by its source but by the
machine it runs on: the sign of a NaN an operation creates, conversions of
out-of-range floats to integers, and decimal printing of floats through the
C++ standard library. Ghidra's own tests show it: on macOS on Apple silicon
the reference build fails one unit test (`double_decimal_precision`) and
two `floatprint.xml` checks that pass on x86-64 Linux.

Basilisk's results must not depend on the host. Where Ghidra's does,
Basilisk produces **the result Ghidra gives on x86-64 Linux** (its
reference platform, and the one its tests were written on), on every
platform — unless a Ghidra test pins a different value, in which case the
test wins and the case is recorded in the feature doc. Examples in
`bk-pcode`: a created NaN is negative (so `0.0f/0.0f` prints `-NAN`, as
`floatprint.xml` expects); out-of-range `FLOAT_TRUNC` saturates, because
Ghidra's Java tests pin saturation.

Consequence for differential tests (ADR-007): an oracle built on another
host disagrees with Basilisk in exactly these documented cases; tests list
them rather than loosen the comparison. The x86-64 behaviour that no test
pins is taken from reading the source until someone runs the oracle on
x86-64 Linux, which `scripts/build-reference.sh` in a container can do.

## ADR-022 — Windows, macOS and Linux are all first-class, from now
(Owner decision, 2026-11-12: Windows is "first-class from now".)

Basilisk builds, passes its tests and offers every feature on Windows,
macOS and Linux. A track does not merge until that holds on all three; a
feature gap on one platform is fixed in the track, not recorded and
deferred.

* **How it is checked.** CI (`.github/workflows/ci.yml`) runs the tests on
  `ubuntu-latest`, `macos-latest` and `windows-latest`; a red job on any of
  them blocks the merge. Development happens on macOS, where Windows
  cannot be run, so before reporting a track also cross-checks what can be
  checked locally (`cargo check --target x86_64-pc-windows-msvc` for
  crates without C code) and avoids the usual traps: path separators and
  drive letters, case-insensitive file systems, line endings, file
  locking and deletion of open files, `std::os::unix` without a Windows
  counterpart, shell scripts in anything the product or its tests need at
  run time.
* **Development-only tooling may stay Unix-only**: the reference build
  (`scripts/build-reference.sh`), the fuzz crate and the gate script are
  not part of the product. Tests that need the reference tools skip
  without them on any platform.
* **Known gap to close now**: `bk-binutils-sys` (ADR-019) was accepted
  with a Windows stub; that acceptance is withdrawn. The GNU disassembler
  must build and work on Windows.
* Tier definitions: x86-64 and AArch64 on each of the three systems where
  the Rust toolchain and CI offer them; CI covers what GitHub's hosted
  runners provide, and anything not covered by CI is stated as unverified.

## ADR-023 — The compiled language is its own crate, `bk-sla`; SLEIGH is built in six tracks
(Coordinator, 2026-11-13, from the `spec-sleigh` track;
`inventory/01-sleigh.md`, `features/sla.md`.)

The model of a compiled `.sla` file — symbols, constructors, decision
trees, pattern blocks, expressions, p-code templates — lives in **`bk-sla`**
together with the validating reader and the writers that reproduce Ghidra's
bytes. It is one immutable value of flat arenas with typed `u32` indices,
laid out for decoding (ADR-012). The runtime (`bk-sleigh`) decodes straight
from it; the compiler (`bk-sleigh-compiler`) lowers into it through a
builder. `decodeSlaSpaces` belongs to `bk-sla`.

* **Why a separate crate.** The format is checked against Ghidra (all 150
  reference files re-encoded byte for byte, XML text equal to `sleigh -y`)
  before either user of it exists; the runtime and the compiler no longer
  depend on each other and are built in parallel; the compiler's tests get
  a structural diff instead of "bytes differ at offset N".
* **Tracks and order** (each has a spec in `docs/features/`):
  `sla` → `sleigh-decode` → `sleigh-pcode` (runtime, crate `bk-sleigh`);
  `sla` → `sleigh-compiler-front` → `sleigh-compiler-back` (crate
  `bk-sleigh-compiler`); `sleigh-compiler-front` → `sleigh-snippet` (crate
  `bk-sleigh-snippet`, p-code snippets of `.cspec`/`.pspec` for injection);
  `sleigh-language` (crates `bk-sleigh`, `bk-language`: registers as a
  model, flow and operand types, overrides, compile on demand) is a later
  wave and its spec is a draft.
* **Oracles.** Runtime: `pcodedump` records for every language, over
  directed samples per decision-tree leaf, random bytes and real code,
  with coverage thresholds. Compiler: Ghidra's **C++** compiler, and
  acceptance is byte equality of the inflated stream for all 150
  specifications. Two places follow the Java compiler instead (the
  unsigned range test in `EqualEquation`; the command line's `-f`, `-d`,
  `-i`). Snippets: a new reference tool `snippetdump`, added to
  `scripts/build-reference.sh` by the `sleigh-snippet` track.
* **`basilisk disasm`** writes `pcodedump`'s record format in M1, because
  that is what the differential test compares. The user-facing listing
  format is decided with the CLI in M6; the record format then stays
  available as an option.

## ADR-024 — Where Ghidra's C++ SLEIGH engine is undefined, Basilisk defines the result
(Coordinator, 2026-11-13, from the `spec-sleigh` track; extends ADR-021.)

Ghidra's C++ SLEIGH runtime has undefined behaviour on some inputs. A
panic-free port (ADR-009) needs a defined result for each; they are:

* **Shifts in pattern expressions**: counts are taken modulo 64; right
  shift of a signed value is arithmetic.
* **Division by zero in a pattern expression** is a decode error for that
  instruction (the Java engine throws; the C++ is undefined).
* **Instruction bytes past index 15** read as zero.
* **Constructors with more than 20 operands are decoded.** The C++ engine
  cannot: PowerPC AltiVec constructors with 24 and 27 operands make
  `pcodedump` print "SLEIGH parser out of state space". The differential
  harness expects the oracle's error for these and checks Basilisk's
  result by other means (the spec says how). The M1 goal "match the
  reference tool for every language" carries this exception.
* **No address-keyed parse cache.** Each decode starts from the context
  database. This differs from Ghidra only for an instruction that both
  uses `inst_next2` and commits context affecting the next one; of the
  shipped languages only Toy uses `inst_next2`.
* **`bk-sla` rejects a file whose use would be undefined behaviour in
  Ghidra** (dangling ids, decision nodes wider than 8 bits, operand
  expression cycles, …; `features/sla.md` 4.3) even though Ghidra would
  load it. No shipped or compiler-produced file may be rejected; the rules
  were checked on the 150 reference files.
* **Decision-tree scoring uses a host-independent `log`** (the `libm`
  crate, subject to the ADR-011 evaluation in the track) so the compiler's
  output cannot depend on the host's C library. Whether Ghidra's own
  output differs between hosts is unverified until the x86-64 reference
  build is read (`PROGRESS.md`, Blockers).

Each is listed under "Differences from Ghidra" in the feature document of
the track that implements it.

## ADR-025 — Decompiler improvements live in profiles; the port carries the hooks for them from the start
(Coordinator, 2026-11-13, as proposed by the `decomp-research` track; evidence and reasons in
`docs/research/decompiler-quality.md`.)

ADR-004 ports Ghidra's decompiler to measured parity and allows improvements
afterwards. This record says how the two coexist and what the port must
contain so that the improvements are possible without rewriting it.

1. **Profiles.** Every rule, action, merge pass, structuring step and output
   pass of `bk-decomp` is a named unit with an origin (`ghidra` or `basilisk`)
   and a group. A pipeline is built from the unit table by a named profile.
   The `ghidra` profile is Ghidra's pipeline and nothing else; it reproduces
   Ghidra's output including its faults, and it is the target of every
   differential test (ADR-007), permanently. The `basilisk` profile is the
   `ghidra` profile plus accepted improvements. The default profile is
   `ghidra` until M3 is accepted and `basilisk` afterwards.
2. **Ghidra's units are not edited to improve them.** An improvement is a new
   unit, or a replacement unit selected by the `basilisk` profile, with one
   switch in the option registry. A difference in the `ghidra` profile is a
   bug (ADR-001).
3. **The port has these properties from its first version**, none of which
   changes output:
   a. the IR can be evaluated at every stage, and every edit of it goes
      through one mutation interface to which a recorder of unit applications
      can be attached;
   b. the structurer runs on a copy of the block graph and returns a
      hierarchy with a measure of it;
   c. the engine hands the printer a typed output tree whose nodes refer to
      ops, varnodes and addresses; output passes work on that tree;
   d. decompiling a function produces a function summary (parameters, return,
      whether it can return, tail call, accesses through pointer parameters),
      and the program trait can serve summaries of callees to the engine,
      including an answer to "does this call return" that depends on the call
      site;
   e. the type system has a category of inferred types, and type recovery
      fills a per-function table of observed accesses;
   f. names and types carry their provenance (user, debug information,
      import, library signature, analysis, model) across the program trait.
   Item c is confirmed by a spike on Ghidra's 93 data tests when the printer
   is specified; if the tree cannot reproduce `printc.cc` token for token,
   output passes work on the structured block hierarchy instead and this item
   is revised by a new record.
4. **Quality is measured, not asserted.** `docs/QUALITY.md` holds a scorecard
   with three columns — Ghidra's reference build, the `ghidra` profile, the
   default profile — over a fixed corpus that starts from
   `docs/research/decompiler-quality/`. The gate runs, without tools from
   outside the repository: parity of the `ghidra` profile against checked-in
   snapshots, per-case assertions for the default profile, the counters, and
   a bounded stage-equivalence check (lifted p-code against final IR on the
   same inputs). Compiler matrices, the reference tools, ground truth from
   debug information and long equivalence runs are nightly.
5. **An improvement is accepted with**: its entry under "Differences from
   Ghidra"; snapshots of the affected cases in both profiles; the change in
   the scorecard; and, if it acts before structuring, a clean
   stage-equivalence run. Improvements are taken in order of how little they
   disturb: output passes first, then units outside the engine (summaries),
   then rules, then type propagation and merging.
6. **Language models never edit decompiled code.** They may propose names,
   comments and types through the plugin interface (ADR-014); the decompiler
   applies proposals with its own rename and retype operations, records their
   provenance and can remove them. This is off by default.

Consequences: each improved case has two snapshots; the program trait is
larger than the set of queries Ghidra's `DecompileCallback` answers; the
printer is ported as two stages. Not decided here: the method for
cross-function type unification (a licence and patent check comes first), and
which readability counters, if any, may fail the gate on their own.

## ADR-026 — The decompiler is state crates and pass crates; `bk-cspec` stands outside it
(Coordinator, 2026-11-13, from the `spec-decompiler` track;
`features/decomp-plan.md` section 2, `inventory/02-decompiler.md`.)

ADR-004 ports Ghidra's C++ decompiler. In C++ it is one strongly connected
component of 48 modules, so the crate split follows what each part calls,
not the include graph. **State sits in low crates and passes in crates
above them; `Funcdata` and `Architecture` are plain data and passes are
functions over them.** This replaces `bk-decomp` + `bk-decomp-print` in the
crate map:

`bk-decomp-range` (circle ranges), `bk-decomp-types` (types, factory, C
declaration parser), `bk-cspec` (`.cspec` reader, prototype models),
`bk-decomp-cfg` (block graph, dominators, structuring), `bk-decomp-ir`
(varnodes, ops, blocks, covers, the mutation interface, state load and
dump), `bk-decomp-symbols` (scopes, symbols, the ADR-004 host trait),
`bk-decomp-core` (function and architecture state, the unit table,
profiles, drivers), `bk-decomp-typeop`, the rule families
`bk-decomp-rules-{basic,bits,compare,piece,divide,pointer,subflow,double,bitfield}`,
`bk-decomp-{flow,heritage,actions,jumptable,merge,struct}`,
`bk-decomp-out` and `bk-decomp-print` (the two-stage printer of ADR-025
3c), and `bk-decomp` (pipeline assembly, public API, parallel driver).

* **Why**: passes can be written by several agents at once without sharing
  files (`ruleaction.cc` alone becomes six crates of one-rule modules), and
  a change to the IR is confined to the state crates.
* **`bk-cspec` is not decompiler-specific.** It sees types through a small
  query trait (about ten questions, three kinds of type it creates), so it
  does not depend on `bk-decomp-types`, the types and prototype tracks run
  in parallel, and the M4 program model uses the same crate. It also holds
  `FunctionSummary` (ADR-025 3d).
* **`Provenance` lives in `bk-core`** (ADR-025 3f): the types, cspec and
  symbols crates all carry it.
* **The context database (`globalcontext`) belongs to the SLEIGH runtime**
  (`bk-sleigh`, `features/sleigh-decode.md` 4.2), which needs it first;
  the decompiler's symbol and flow crates use it from there.
* **Per-function type overlays are built with the type system**, not
  deferred to the parallel driver (`features/decomp-types.md` 4.10): a
  forked factory per function is what makes inferred types a category
  (ADR-025 3e) and ids independent of what other functions create.
* **Counts corrected** (measured by the track; earlier records say 167
  rules and 77 actions): 163 classes derive from `Rule`, 161 are in the
  pipeline; 71 leaf `Action` classes with 80 instances; 107 `.cspec` files
  under `Ghidra/Processors`; the engine is about 126,000 hand-written
  lines of the directory's 190,000.
* Tracks, waves and acceptance per track: `features/decomp-plan.md`.

## ADR-027 — Decompiler parity is measured at six levels, with Ghidra's own state as the starting point
(Coordinator, 2026-11-13, from the `spec-decompiler` track;
`features/decomp-plan.md` sections 4 and 6. Extends ADR-007.)

The decompiler cannot wait for "whole output equals Ghidra's" to learn
whether a pass is right. Parity is measured at six levels: ported unit
tests; replayed oracle tables; **state after a pass, starting from
Ghidra's state before it**; the trace of rule applications; the 760
data-test checks; whole output. To make the middle levels possible:

* **A Basilisk-defined dump format for complete function state.** A
  console extension, compiled into the reference build's copy of the
  decompiler with `-fno-access-control`, writes it; `bk-decomp-ir` loads
  it. Heritage, the actions and the rule families are then each accepted
  from Ghidra's state before their pass and do not wait for each other.
  The extension is C++ under `tools/reference/` plus one file added to the
  build's copy; nothing in `../ghidra` changes (ADR-002's rule stands).
* **The debug console** (`CPUI_DEBUG`) is added to `../reference`: it logs
  one record per rule or action application with each modified op before
  and after.
* **Rule-subset configurations are an accepted oracle.** The reference
  console with exactly the rules Basilisk has ported enabled
  (`option togglerule`) is what a rule family is compared with. It is
  still the `ghidra` profile in ADR-025's sense: the same units, fewer
  enabled.
* **Recorded p-code is the interim lifter.** Until `bk-sleigh` exists, the
  decompiler reads p-code recorded inside the reference console by a proxy
  `Translate`, through a `PcodeSource` trait. The recordings are later
  handed to the SLEIGH tracks as a differential test.
* **Coverage is known and incomplete**: 32 of the 161 rules apply in
  neither the 93 data tests nor the research corpus. Such a rule can be
  ported but is not accepted until the corpus track (D19) has a case that
  applies it.
* Each track's acceptance has checks that run without the live tools
  (checked-in tables and dumps, on all three platforms); no track rests
  on the live reference tools alone.

## ADR-028 — How ADR-025's properties meet Ghidra's code
(Coordinator, 2026-11-13. `features/decomp-plan.md` section 8 found four
places where ADR-025 as worded does not fit what Ghidra does; this record
says how each is read. ADR-025 otherwise stands.)

* **3a, "evaluable at every stage"** means at unit boundaries, with free
  varnodes denoting storage and `special` ops needing an environment.
  Several of Ghidra's units change meaning on purpose under an assumption
  (`ignorenan`, dead-code removal driven by prototype effect lists,
  read-only memory taken as constant, parameter recovery). Every unit
  therefore declares its **soundness** — `Exact` or `Assumes(name)` — in
  the unit table, and the stage-equivalence check qualifies or skips a
  unit by it. A correct port of such a unit is not a failure of the check.
* **3b, "the structurer runs on a copy"**: Ghidra's already does, but it
  edits the original through the copy (ten `negateCondition` sites flip
  the real `CBRANCH` and swap the real block's out-edges). In Basilisk the
  structurer takes per-block facts as input and **returns** the condition
  flips and goto edges as part of its result; the track that puts
  structuring on the IR applies them. Unverified: that no structuring
  rule reads back a flag it flipped (not every rule was read for it); the
  structuring track checks this first.
* **3c** stands as written; the interleavings the printer spike must
  examine are listed in `decomp-plan.md` 8.1.
* **3e and 3f**: the category of a type and its provenance are attributes
  of the factory entry and **take no part in type identity, comparison,
  hashing or interning**. Otherwise interning, and so the `ghidra`
  profile's output, would change.

## ADR-029 — Ghidra's SLEIGH compiler output depends on the host; the reference is x86-64 Linux until the cause is known
(Coordinator, 2026-11-14. Measured; follows ADR-021 and settles the item
ADR-024 left unverified.)

The reference build was run on x86-64 Linux (GCC 14.4, the lent box) and
compared with the one on macOS AArch64 (Apple clang 17), same Ghidra
commit, same build script:

* **x86-64 Linux passes everything**: 205/205 unit tests and 760/760
  data-test checks. On both AArch64 hosts two `-NAN` checks fail, as
  ADR-021 expected.
* **14 of the 150 compiled `.sla` files differ in content** between the
  two hosts (inflated streams compared, not compressed bytes): `AARCH64`,
  `AARCH64BE`, `AARCH64_AppleSilicon`, `ARM8_le`, `ARM8m_le`, `mips32le`,
  `mips32R6le`, `ppc_64_isa_le`, `ppc_64_isa_altivec_le`, `TI_MSP430`,
  `TI_MSP430X`, `tricore`, `x86`, `x86-64`. Some differ in length, and
  the differences start late in the file. The other 136 are identical.
  So "the C++ compiler's bytes" is not one thing.
* **Decision**: for the SLEIGH compiler's byte-equality acceptance
  (ADR-023) the oracle is the **x86-64 Linux** build, kept beside the
  checkout in `../reference-x86_64/x86_64-linux/` (150 `.sla`, `STAMP`,
  logs). The macOS build in `../reference/` remains the oracle for
  everything where the two agree and for running the tools locally.
* **Not known: the cause.** Candidates are a decision-tree score tie
  decided by the host's `log`, an unstable `std::sort` (libstdc++ and
  libc++ order equal elements differently), or iteration over a
  pointer-keyed container. Which it is decides what Basilisk must do: a
  floating-point tie is settled by ADR-024's host-independent `log`; a
  sort-order dependence means Basilisk needs a defined order, and equality
  with either host's bytes for those 14 files may then be the wrong
  acceptance test. The `sleigh-compiler-back` track does not start until
  this is established (`PROGRESS.md`, queue item `sla-host-diff`), using
  `bk-sla`'s structural diff on the 14 pairs. Whether the two variants
  decode identically is part of that question.
* **`bk-pcode`'s oracle table** (`tests/data/opbehavior_cpp.txt.gz`) was
  generated on AArch64. Regenerated on x86-64 Linux, 161 of the 77,148
  rows with the same inputs have a different result, all NaN signs in
  float operations. Replaying the x86-64 table through Basilisk's test,
  the "created NaN sign" class disappears as intended, but **106 rows
  differ**: Basilisk does not yet follow x86-64 where an input is itself
  a NaN. Under ADR-021 the x86-64 table becomes the checked-in one and
  those rows are fixed (queue item `x86-oracle`). The generator's inputs
  also depend on the host (argument evaluation order), so tables are
  compared by input, not by line.

## ADR-030 — The user documentation is a static Starlight site, built in a container
(Owner decision, 2026-11-14: "use starlight but build docs in a container
as I do not want to install nodejs"; a static site with Mermaid diagrams.)

Basilisk's documentation for users — how to use the whole program and how
each part of it works — is a site under `site/`, generated by **Starlight**
(Astro) into plain static files.

* **Static.** The output is HTML, CSS and assets with no server. Pages are
  readable without scripts; scripts are limited to search and the theme
  switch. Hosting is GitHub Pages.
* **Diagrams are Mermaid**, written as fenced `mermaid` blocks and rendered
  to SVG when the site is built, in both themes. A diagram that does not
  parse fails the build.
* **Node.js is never installed on a developer's machine.** The site is
  built, previewed and link-checked only inside a container:
  `scripts/site.sh build|serve|check` runs a pinned image (by digest) with
  the repository mounted, and nothing else in the repository needs Node.
  CI uses the same image, so the two cannot drift. Agents must not install
  Node, npm packages or browsers on the host for any reason.
* **Dependencies follow the project's rules where they can**: exact
  versions in a committed lock file, each published at least two weeks
  before it is added (as for crates), installed with the lock file frozen.
  The site's dependencies are development tooling, not part of the product
  (ADR-018's licence statement covers what Basilisk ships).
* **Content is generated where it can be**, so it cannot go stale:
  screenshots by `bk-ui`'s screenshot renderer, the key-binding table from
  the action registry, command-line help from the binary, the Python API
  reference from the plugin package when it exists. Hand-written pages say
  plainly what exists today and what is planned.
* **A track that changes behaviour a user can see updates its page** in
  the same branch (`docs/agents/RULES.md`, added by the `docs-site` track).
* Alternatives the owner was shown: mdBook, MkDocs Material and Zensical,
  Sphinx with Furo, Docusaurus, VitePress, Zola, Hugo.

## ADR-031 — One static site in the monorepo: the product site and the documentation share a project
(Owner, 2026-11-14: "design a great looking site for Basilisk. You can
choose tech freely but make it static. In same monorepo." Technology
chosen by the coordinator. Extends ADR-030.)

Basilisk's public website and its user documentation are **one Astro
project under `site/`**: the product site is hand-designed Astro pages at
the root (`/`), and the documentation is the Starlight collection of
ADR-030 under `/docs/`. One build produces one static tree for GitHub
Pages.

* **Why one project**: one container image and one script
  (`scripts/site.sh`, ADR-030 — still no Node on a developer's machine),
  one CI job, one set of design tokens, so the landing page, the
  documentation and the program look like one product, and a link between
  them cannot break unnoticed.
* **Static**: no server, no client-side framework at run time. Pages are
  HTML and CSS; scripts only where a page needs them (search, theme
  switch, a screenshot viewer) and the page still reads without them.
* **Design**: Basilisk's own — the mark, Ember on Soot, the interface's
  fonts — designed by an agent briefed as a designer, with real
  screenshots of the interface from `bk-ui`'s renderer, never mock-ups.
* **Honest content**: the site says what works today and what is planned.
  The parity table is generated from `docs/PARITY.md`, not written by
  hand, so the site cannot claim more than the matrix does. Ghidra is
  credited as the work Basilisk reimplements (`NOTICE`), and nothing
  suggests affiliation with or endorsement by Ghidra's authors. The
  licence (GPL-3.0-or-later) and the source link are on every page's
  footer.
* **Tracks**: `site-design` builds the project, the container tooling,
  the design system, the product pages and the documentation's shell;
  `docs-content` then fills the documentation (ADR-030's content rules).

## ADR-032 — Ghidra's SLEIGH compiler output depends on floating-point contraction; Basilisk computes the score as x86-64 does
(Coordinator, 2026-11-14, as proposed by the `sla-host-diff` track;
evidence in `docs/research/sla-host-dependence.md`. Follows ADR-021.
**Replaces ADR-029's "cause not known" and its conditions, and ADR-024's
bullet on a host-independent `log` from the `libm` crate**: decision-tree
scoring follows this record.)

14 of the 150 reference `.sla` files differ between macOS AArch64 and
x86-64 Linux. Cause, established by experiment: `DecisionNode::getScore`
computes `sc -= p * log(p)` (`slghsymbol.cc:2135`), which AArch64
compilers (clang and GCC, any C++ library, any OS) fuse into one
multiply-subtract while x86-64 compilers without FMA round the product.
At 25 decision nodes two candidate fields have mathematically equal
scores (same bin-count multiset); the last-bit difference decides
`chooseOptimalField`'s strict `>`. macOS with `-ffp-contract=off`
reproduces x86-64 for all 150; x86-64 with `-mfma` reproduces macOS. Only
the decision trees below those nodes differ, and they resolve every input
to the same constructor (checked exhaustively): the two variants decode
identically. Ghidra's Java compiler never contracts and agrees with
x86-64 at all 25 nodes, but its `Math.log` is host-dependent (Homebrew's
12.0 built on Apple silicon differs from the 11.4.2 release in ARM8_le
and ARM8m_le).

* **Basilisk's score** is unfused IEEE `f64` arithmetic in Ghidra's
  order, with a `log` bit-equal to glibc's (FMA variant) on every `k/n`,
  1 ≤ k < n ≤ 16,384, verified against a checked-in table. Not
  `libm::log`: fdlibm's `log` changes ARM8_le and ARM8m_le. The output is
  then the same on every host and equals x86-64 Linux's.
* **Oracle**: byte equality with the x86-64 Linux build for all 150
  specifications, no tolerated ties. The reference build adds
  `-ffp-contract=off`, after which a build on any host gives those bytes
  and `../reference` serves again; until it is rebuilt,
  `../reference-x86_64/x86_64-linux` is the oracle for the 14.
* `bk-pcode`'s oracle-table item (x86-64 NaN results, queue item
  `x86-oracle`) is unchanged.
* The `sleigh-compiler-back` track may start once
  `features/sleigh-compiler-back.md` carries the edits listed in the
  research document's section 6.3 and the reference build has the flag
  (`PROGRESS.md`, queue item `ref-nofma`).
* Not established: nothing was run on real x86-64 hardware (emulation
  reproduced the lent box's files exactly; the confirming command is in
  the research document, section 2); Ghidra's Java compiler was read and
  its shipped files measured, not run.

## ADR-033 — `bk-pcode` follows x86-64 for NaN signs; float-to-integer truncation saturates
(Coordinator, 2026-11-14, from the `x86-oracle` track; applies ADR-021
and corrects ADR-029's last bullet.)

* The checked-in oracle table for `bk-pcode`
  (`crates/bk-pcode/tests/data/opbehavior_cpp.txt.gz`) is the one
  generated on x86-64 Linux (GCC 14.4, the reference build there). The
  generator now draws its random operands in a fixed order, so a table
  made on any host has the same inputs line for line; regenerated on the
  x86-64 box with the fixed generator, the text is identical to the
  checked-in table (SHA-256 of the decompressed text `463b1dca…`,
  2026-11-14).
* **Two NaN inputs**: on x86-64 `FLOAT_ADD` and `FLOAT_MULT` return a NaN
  with the sign of the second operand, `FLOAT_SUB` and `FLOAT_DIV` with
  the sign of the first; AArch64 uses the first for all four. Basilisk
  computes x86-64's result from the inputs' bits on every host. With one
  NaN input the result has that input's sign on both hosts; a NaN made
  from non-NaN inputs is negative, as on x86-64. The wide and exact paths
  follow Java's `BigFloat`, which has no NaN sign (always the positive
  quiet NaN).
* **`FLOAT_TRUNC` of a NaN or of a value outside `i64`** gives
  `0x8000000000000000` cut to the output size in x86-64's C++, and
  saturates in Ghidra's Java, where tests pin it
  (`FloatFormatTest.testOpTruncLongInt`, `OpBehaviorFloatTruncTest`).
  **Basilisk saturates** (NaN gives 0): the Java behaviour is the tested
  and the saner one. This is a documented difference from the C++ engine
  (58 oracle rows, class `TruncSaturates`).
* Correction: of the 161 rows that differ between the AArch64 and x86-64
  tables on equal inputs, 111 are NaN signs and 50 are `FLOAT_TRUNC`
  results, not all NaN signs as ADR-029 says.
* `ceil`, `floor` and `round` go through `libm`, not the host's C library
  (MinGW's `round()` is wrong for 0.49999999999999994).
* A table of 188 directed cases with literal expected bits
  (`tests/host_independence.rs`) runs on Linux x86-64, macOS AArch64 and
  Windows in CI, so a host difference fails there.

## ADR-034 — The reference build is unfused; one oracle for the SLEIGH compiler again
(Coordinator, 2026-11-14, from the `ref-nofma` track. Closes the "until it
is rebuilt" clause of ADR-032 and the split oracle of ADR-029.)

`scripts/build-reference.sh` passes `-ffp-contract=off` to every compile
(the decompiler's Makefile, `pcodedump`, the bundled zlib) and records it
in `STAMP`. Rebuilt on macOS AArch64 that way, all 150 `.sla` are
byte-identical to x86-64 Linux's; Ghidra's own unit and data tests, the
`pcodedump` output on ten languages and the `decomp` console's output on
all 93 data tests are unchanged from the fused build. `../reference` was
replaced file by file (281 files) on 2026-11-14 and **is the oracle for
all 150 specifications again**; `../reference-x86_64/x86_64-linux/` stays
as the independent copy from real x86-64 hardware, and the 14 old
fused-variant files are kept in `../reference.aarch64-fused/`. The flag
does not make AArch64 equal x86-64 everywhere: the two `-NAN` checks and
one decimal-precision unit test still fail on AArch64 (ADR-021, ADR-033).

Ghidra's `pcodedump` crashes when a delay-slot (or crossbuild) instruction
has no p-code: `SleighBuilder::delaySlot` leaves the builder pointing at a
walker on its own stack when `UnimplError` unwinds, and the handler in
`oneInstruction` uses it (`research/pcodedump-crashes.md`). Basilisk
returns "instruction not implemented in p-code" with the full flow length
there, naming the innermost such instruction, and never leaves stale
builder state behind an early return (ADR-009).

## ADR-035 — Python hosts Basilisk: the plugin bindings are an extension module, not an embedded interpreter
(Owner decision, 2026-11-14, on the finding of the `spec-plugin` track;
`features/plugin-api.md`, `docs/agents/spec-plugin.md`. **Replaces the
embedding in ADR-014**; the rest of ADR-014 stands: plugins are Python
through PyO3, with a flat scripting layer modelled on Ghidra's.)

ADR-014 had `bk-plugin` embed CPython in the `basilisk` binary. Measured:
a binary linked against libpython does not start where that library is
missing, even when Python is never used, and is tied to one Python minor
version and install path; linking CPython statically makes Python
mandatory, fixes its version and stops third-party C extensions loading
on Windows; PyO3 cannot load libpython at run time. That cannot coexist
with "basilisk is a single binary" (`DIRECTION.md`) and ADR-022.

* Basilisk's Python bindings are a **Python extension module** (crate
  `basilisk-py`, a `cdylib` built for the stable ABI), hosted by the
  user's own CPython: `python -m basilisk` and `import basilisk`. This is
  how Ghidra's PyGhidra works.
* The `basilisk` binary contains no Python. When plugins or scripts are
  wanted it hands over to a CPython it finds; without one, everything
  except plugins works and the binary says what is missing.
* **Supported Python: 3.10 and newer** (owner, 2026-11-14), one `abi3`
  build for all of them (verified on 3.10 to 3.14 on macOS).
* PyO3's macros put no `unsafe` into the binding crate (verified with
  PyO3 0.30.1), so it keeps `forbid(unsafe_code)`; ADR-020's sentence
  about `bk-plugin` is narrowed accordingly.
* Not verified yet, and the first acceptance items of the host track
  (P1): the hand-over from the binary to `python -m basilisk`, the
  interface running inside a Python-hosted process, wheels on Linux and
  Windows.

## ADR-036 — Plugin API conventions; a failed script keeps its changes, as in Ghidra
(Owner decisions, 2026-11-14, and the `spec-plugin` track's proposals.)

* **A script that throws or is cancelled keeps the changes it has made**
  (owner: "Keep changes, like Ghidra"). Ghidra commits a script's
  transaction on every exit path, and scripts ported from Ghidra behave
  identically. A script may **opt in** to rolling back on failure. This
  reverses the default `features/plugin-api.md` proposed (roll back, opt
  out); the spec is corrected by the first plugin track.
* The flat scripting layer keeps Ghidra's method names
  (`FlatProgramAPI`, `GhidraScript`: all 225 public methods are mapped in
  the spec), and the object model keeps Ghidra's getter names beside
  Python properties, so bundled scripts port with mechanical changes.
* The plugin API has its own version, declared by each plugin package and
  separate from Basilisk's release version.
* Plugin-defined views are declarative (described to the interface, not
  drawn by Python); actions go through the interface's action registry,
  which has to accept run-time entries first.
* Proposers of names, comments and types (ADR-025 item 6) are off by
  default; every applied proposal records its origin and the value it
  replaced, so it can be removed.
* A plugin that raises is isolated: it is reported and disabled, and the
  tool keeps running.

## ADR-037 — Specs state how they meet the plugin binding constraints
(Coordinator, 2026-11-14, from the `spec-plugin` track.)

`features/plugin-binding-constraints.md` lists 15 rules a Rust API must
meet to be bound to Python without redesign (handles without lifetimes at
the boundary, `Send + Sync` shared data, errors convertible to exceptions,
paged iteration, identifiers stable across transactions, cancellation and
progress through a monitor type that does not live in a UI crate, …).
Every feature spec for the program model, storage, loaders, analysis, the
decompiler's host trait and results, and the interface has a section
saying which rules apply and how they are met, and reviews check it.
Known work this causes: the monitor type moves out of `bk-ui` into a low
crate; model edits record an origin and the replaced value; variables get
a stable identity; decompiler results are `Arc` + `Sync` and outlive the
call; `bk-ui`'s action registry and view kinds accept run-time entries.

## ADR-038 — Where Ghidra's p-code depends on its parse cache or on uninitialised memory, Basilisk gives the result of a fresh parse

Date: 2026-11-14. Status: accepted. Extends ADR-024 (defined results
where Ghidra's SLEIGH engine has undefined behaviour) to p-code
generation. Proposed by track `sleigh-pcode`.

**Context.** `bk-sleigh`'s p-code is compared with `pcodedump` for every
language (ADR-007). Three kinds of record cannot be equal, because
Ghidra's result is not a function of the instruction bytes and context:

1. *Unset handles* (1,543 records in 18 languages at the time of
   writing). A template reads the handle of a subtable operand whose
   constructor exports nothing. Ghidra reads a `FixedHandle` that was
   never set for this parse and holds whatever an earlier parse left
   there.
2. *A clobbered parse cache* (1 record: Toy `harvard_rev`, a branch with
   `skvs` in its delay slot). The delay-slot instruction uses
   `inst_next2`; looking that instruction up evicts the branch's own
   parse from Ghidra's two-entry cache, and the branch is then built from
   the wrong parse.
3. *A crossbuild target that is not in the cache* (1 record). Ghidra
   fails; the target is perfectly decodable.

Separately, 37 instructions crash `pcodedump` outright (a walker left
dangling after an error in a delay slot; six ARM v8-m `vpt…` cases that
read an unset handle whose space pointer is null).

**Decision.** Basilisk's result for an instruction depends only on the
bytes, the address and the context. An unset handle reads as the constant
0. Delay-slot, `inst_next2` and crossbuild targets are decoded on demand,
never taken from a cache whose content depends on what was decoded
before. Where `pcodedump` crashes, Basilisk returns its ordinary typed
error or lifts the instruction.

**How the difference is kept honest.** The differential harness does not
skip these records. It models Ghidra's two-entry parse cache and the
unset-handle condition, recognises each record as one of the three kinds,
and counts them per language; a record that differs and is not recognised
fails the test. The crashing inputs are regression tests.

**Consequences.** A user comparing Basilisk's p-code with Ghidra's for
such an instruction can see a difference; `features/sleigh-pcode.md`
section 8 lists the kinds. The three behaviours and the two crashes are
candidates for bug reports to Ghidra.

## ADR-039 — The decision-tree `log` reproduces every multiply-add GCC fuses in glibc, not one

Date: 2026-11-14. Status: accepted. Amends ADR-032 (which stays as
written: the score itself is computed unfused, and the `log` must equal
glibc's on x86-64). Found by track `sleigh-compiler-back`.

**Context.** ADR-032 and `features/sleigh-compiler-back.md` section 4.3
said the `log` used by `DecisionNode::getScore` could be ported from
glibc's source with its one explicit FMA "and no other fusion". That
port was written and tested against the checked-in table of glibc
results (`research/sla-host-dependence/logtable-glibc.txt.gz`, 16,383
lines): it differed on 1,134 lines, and equalled musl instead.

**Cause.** glibc is compiled as GNU C, where GCC's default is
`-ffp-contract=fast`. On x86-64 with FMA available through glibc's
function multiversioning, GCC fuses every product whose only uses are
additions or subtractions, not just the one the source spells out. The
shipped `log` is therefore the source *as contracted by GCC*.

**Decision.** `bk-sleigh-compiler`'s `log` is a port of Arm
optimized-routines' `log` (revision
`20859d3fd9e797dde592c489c8ef7d383f778620`, MIT OR Apache-2.0 WITH
LLVM-exception, recorded in the module and in `NOTICE`; glibc's `log` is
that code) in which each of those contractions is written out as an
explicit `fma`. It is bit-equal to the table on all 16,383 lines, on
every host, because nothing is left to the compiler: Rust does not
contract floating-point expressions.

**Verification.** The table test runs in the gate on every platform. The
150-specification comparison is byte for byte with no tolerated
difference, and a mutation that computes the score with fused arithmetic
makes exactly the 14 files of ADR-029 differ, so the comparison is known
to see decision-tree differences.

**Consequence.** The oracle is one build of glibc's `log`; a future
glibc that changes its `log`, or a reference build on a host without
FMA, could order tied decision nodes differently again. The table is the
definition; if the reference is ever rebuilt on another libc, the table
test says so before any `.sla` differs.

## ADR-040 — Where Ghidra's answer depends on the C++ library's sort, Basilisk sorts stably

*2026-11-14. Proposed by track `cspec-host` (its report calls it
ADR-038, a number already taken); evidence in `docs/agents/cspec-host.md`.*

**Context.** Ghidra's decompiler sorts effect lists and parameter trials
with `std::sort`, which leaves elements that compare equal in an order
the C++ library chooses, and then answers lookups from that order. The
`bk-cspec` oracle, generated from the same Ghidra commit on macOS
(libc++) and on x86-64 Linux (libstdc++), differs in 119 of 152,046
rows, all from four causes:

* (A) effect records at one address — `ProtoModel::decode`
  (`fspec.cc:2680`) sorts by space and offset only; 56 rows in 28 lists
  (NDS32 and twelve RISC-V gcc pairs);
* (B) `hasEffect` at such an address, which takes the last record of
  the tie (`lookupEffect`, `fspec.cc:2463`); 24 rows;
* (C) two identical trials of one entry, of which the first after the
  sort is kept (`sortTrials`, `fspec.hh:322`, from `buildTrialMap`,
  `fspec.cc:921`); 38 rows (tricore, Loongarch lp64f);
* (D) trials without an entry, which the comparator calls equal
  (`fspec.cc:1881`); 1 row (x86-64 golang).

valgrind finds no uninitialised read behind any row, and the libstdc++
table is the same before and after the build host's CPU model changed:
the differences are sort order and nothing else. Ghidra's releases ship
decompilers built against libstdc++ (Linux), libc++ (macOS) and
Microsoft's library (Windows), so one Ghidra release already gives
different answers per platform, and none of them follows from the
source. `ParamTrial::operator<` is, besides, not a strict weak ordering,
which is undefined behaviour in `std::sort` (and a possible panic in
Rust's `sort_by`).

**Decision.** Basilisk gives one result on every platform, defined by
the specification file alone: every such sort is stable.

* (A) Effect records at one address keep document order, with the
  default return address that `ProtoModel::decode` appends coming last.
* (B) A lookup that Ghidra answers with the last tied record answers
  with the last in document order.
* (C, D) Trials that compare equal keep the order they had before the
  sort: registration (slot) order on input, and the order the previous
  sorts left in the output fallback. Trials are sorted with a stable
  insertion sort, which gives a defined order and cannot panic whatever
  the comparator does.

The rule extends to the other spots of the same kind that no table row
exercises today: the merged-model effect intersection
(`intersectEffects`, `fspec.cc:2767`), `lookupRecord` (`fspec.cc:2501`),
the `FuncProto` effect sort (`fspec.cc:3673`) and prototype scoring
(`ScoreProtoModel::doScore`, `fspec.cc:2728`).

**Consequences.** Basilisk equals Ghidra built with libc++ on every row
of A–C in today's corpus — as an outcome of that library's algorithm on
these inputs, not a guarantee — and equals each library wherever it
uses insertion sort (lists of at most 16 elements in libstdc++); D
equals neither table. The oracle is kept for both libraries
(`crates/bk-cspec/tests/data/cspec_oracle.{libcxx,libstdcxx}.txt.gz`,
the second generated on the build host). The replay requires rows where
the tables agree to equal Basilisk's, and recognises and counts each row
where they disagree (A 56, B 24, C 38, D 1), so a new cause, or a
regenerated table that moves a count, fails the test. This is the form
of ADR-024 and ADR-038: a defined result, each tolerated row recognised
by cause and counted.

**Open.** Microsoft's library was not run. Its `std::sort` uses
insertion sort up to 32 elements, so on paper it equals the rule for
the 32-record RISC-V lists and the tricore and Loongarch rows; NDS32 (35
effects), the 64-record RISC-V lists and the golang row are unknown. A
third table would enter the harness as one more library.

## ADR-041 — Undefined arithmetic in `CircleRange` is computed as the x86-64 Linux build computes it

*2026-11-14. Proposed by track `decomp-range`; evidence in
`docs/agents/decomp-range.md` and
`crates/bk-decomp-range/tests/data/README.md`.*

**Context.** Ghidra's `CircleRange` (`rangeutil.cc`) does arithmetic
that C++ leaves undefined for some inputs: shifts by 64 or more or by a
negative count, an `int4` step shifted past 31 bits, signed overflow
(`valRight + 1`, line 1331; `(int4)in2.left * 8`, line 1283), reads of
the bounds of an empty range that no constructor initialised. The
oracle was generated from the same Ghidra commit by Apple clang on
AArch64 and by g++ on x86-64 Linux, and run on x86-64 under
UndefinedBehaviorSanitizer (with handlers that record every event
against its row) and under valgrind: 13,085 of 152,913 rows hit
undefined arithmetic at 18 sites, and 2,777 rows read uninitialised
bounds. On all of those the two builds give the same result, with one
exception: the `INT_LEFT` push-forward with a shift amount of 64 or
more (`rangeutil.cc:1269–1270`), where g++ on x86-64 shifts modulo 64
and Apple clang on AArch64 turns the two shifts into one vector `USHL`
that reads the amount's low byte as a signed count — 834 rows (5,185 in
the extended case set). Two more inputs make Ghidra crash or hang: a
step bound above 2³⁰ in the `INT_LEFT` push-forward (the step doubles to
0 and `normalize` divides by it, SIGFPE on x86-64) and in the `INT_MULT`
push-forward with a constant whose low 32 bits are 0 (the doubling loop
never ends).

**Decision.** `bk-decomp-range` defines every such case, by these rules:

* Undefined arithmetic is computed as the x86-64 Linux build computes
  it (ADR-021's platform): shift counts modulo 64, the `int4` step shift
  modulo 32, wrapping signed arithmetic, and the `SUBPIECE` offset case
  as both compilers compile it. Where the AArch64 build differs
  (`INT_LEFT`), Basilisk follows x86-64; each differing row of the
  macOS table is recognised by recomputing the `USHL` result and the
  count is pinned (ADR-040's form, for a compiler instead of a library).
* An empty range has defined fields (bounds 0, mask 0, step 1), and the
  methods that read them compute with those; the oracle is generated
  with the same values, so its rows are comparable.
* Where Ghidra crashes or hangs, Basilisk returns: a division by a zero
  step gives `x / 0 = 0`, `x % 0 = x`; the `INT_MULT` loop returns
  `false`. The oracle stays below those bounds and the results are
  pinned by the crate's own edge-case tests.

Logic defects that are not undefined behaviour — the unsound results
listed in `docs/GHIDRA-BUGS.md` entry 21 — are **kept as Ghidra has
them**, since the decompiler's output depends on them (ADR-001); the
soundness properties exclude each by name.

**Consequences.** Every row of the x86-64 table equals Basilisk's
result; the macOS table equals it except in the counted `INT_LEFT`
rows. The rows that depend on undefined behaviour are marked in the
table (` #ub=…`, ` #uninit`), so a change in either compiler shows as a
moved count, not as a silent difference. Microsoft's compiler was not
run; a third table would enter as one more host. Ghidra's own callers
bound the step at 32, so none of the crash or hang inputs is reachable
from the decompiler today; they matter because the type is public API.

## ADR-042 — The decompiler oracle is a console extension in separate reference consoles; dumps name objects by reproducible keys

*2026-11-14. Proposed by track `spec-decomp-wave1` (as ADR-041, a
number taken meanwhile); the specification is
`docs/features/decomp-oracle.md`, the runs behind it
`docs/research/decomp-wave1/runs.md`. Supersedes ADR-027's "one file
added to the build's copy"; amends ADR-028.*

**Context.** ADR-027 measures decompiler parity from Ghidra's own
state, dumped by an addition to the reference console. Writing the D00
specification against the source and the built console showed three
things the plan did not have. (1) The extension cannot be compiled
inside Ghidra's Makefile: it needs `-fno-access-control`, the Makefile
has no per-file flags, so the flag would reach Ghidra's own files, and
the file would also enter `decomp`, `decomp_test` and `libdecomp`. (2)
Ghidra's own listings are not reproducible: the varnode bank orders
`iop`, `fspec` and space-constant varnodes by the heap pointers stored
in their offsets (`varnode.cc:39`, `73`), so two runs of the same
binary differ (43 of the 93 data tests on the Mac), and stripping
`internal=` attributes is not enough. (3) Breakpoints by name cannot
address an action whose name occurs twice (`action.cc:456`, `481`,
`777`), for example the top-level `blockstructure`. Besides, `structure
blocks` — the console's only way to run the structurer on a bare graph
— is too lossy to be D04's oracle: its XML drops edge labels, writes
`ifnoexit` as `ifelse`, has no overflow flag and no condition flips,
treats every plain block as complex and never calls `orderBlocks`.

**Decision.**

* Basilisk's commands (`bk …`) are C++ under
  `tools/reference/consoleext/`, compiled with `-fno-access-control`
  outside Ghidra's Makefile and linked with the Makefile's own objects
  into two extra consoles, `bin/decomp_bk` and `bin/decomp_bk_dbg`.
  `bin/decomp` and `decomp_dbg` stay Ghidra's, byte for byte.
* Every dump names varnodes by creation index, ops by sequence number,
  blocks by index and call specifications by position, and writes the
  three kinds of host pointer that Ghidra stores in varnode offsets as
  canonical keys; the bank orders are written with those keys
  substituted. Breakpoints can be given by position.
* `bk structure` runs the structurer on a graph file that carries the
  per-block facts and dumps the hierarchy, the condition flips and the
  goto marks; `structure blocks` stays as a cross-check that works
  before D00 exists.
* Every oracle output is generated twice on each of the two reference
  builds (libc++ on macOS arm64, libstdc++ on x86-64 Linux, both built
  natively by the same script — the plan's "x86-64 Linux container
  target" is obsolete); a difference between builds is recognised by
  cause and counted (ADR-040's form).

**Amendment to ADR-028, item 3b.** "Unverified: that no structuring
rule reads back a flag it flipped" is now verified by reading: the
structurer reaches a basic block only through `isComplex`,
`negateCondition` and, from the `BlockSwitch` constructor,
`getJumptable`, and none of them depends on what a negation changed.
The structurer (`bk-decomp-cfg`) takes four per-block facts
(`complex`, `switch_out`, `ends_in_return`,
`negation_changes_dataflow`) and the graph's analyses as given —
`ActionBlockStructure` does not recompute them — and returns the
hierarchy, flip events, goto marks with their causes, the change count
and a measure; the track that applies it (D15) toggles the flags and
swaps the edges of each block flipped an odd number of times.

**Consequences.** `docs/features/decomp-plan.md` is amended in the
places the specification found wrong (its section "Amendments,
2026-11-14"). The reference is rebuilt with the new script on both
machines when D00 lands, and both stamps are recorded. Ghidra headless
as an oracle for whole-program results stays a later track (M5).
