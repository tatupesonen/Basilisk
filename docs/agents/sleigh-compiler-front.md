# Track `sleigh-compiler-front` — status report

Status: **done** (2026-11-14). Spec: `docs/features/sleigh-compiler-front.md`
(sections 8 and 9 filled in). Crate `crates/bk-sleigh-compiler`. Worktree
`/Users/tatu/slop/basilisk-wt/sleigh-compiler-front`, branch
`sleigh-compiler-front`; everything committed, nothing pushed.

"Verified" means I ran it.

## Built

Crate `bk-sleigh-compiler` (depends on `bk-sleigh-syntax`, `bk-sla`,
`bk-pcode`, `rustc-hash`; dev: `bk-testkit`, `insta`, `proptest`; no
`unsafe`, no new third-party crate).

| Module | What |
|---|---|
| `lib.rs` | `elaborate(&Parsed, Options) -> Outcome { diagnostics, spec: Option<Elaborated> }` |
| `compiler/` | the walk in Ghidra's order: `define` (alignment, token, context fields, space, varnodes, bitrange, pcodeop, attach), `context_layout`, `ctor` (create, table, `buildConstructor`), `display` (`addSyntax`), `pattern_atoms` (equations, operand definitions, invisible operands, `selfDefine`, context blocks, `globalset`, `calc_maskword`), `pexpr`, `with`, `sections`, `macros` (definition, expansion, `transfer`), `finalize` (labels, macros, `fillinBuild`, sizes, export size, delay slots), `resolver` (the builder's view of the symbol table) |
| `pcode/` | **public** `Builder` over `SymbolResolver` (`NameRef`, `BuildEnv`, `Stop`, `LabelId`); `expr`, `stmt`, `bitrange`, `sizes` (`force_size`, `propagate_size`), `snippet` (`compile_snippet`) |
| `check/` | `post_parse` in Ghidra's order: NOPs, case check, default space, consistency (`sizes`: post order, `recoverSize`, `sizeRestriction`, `printOpError`; `truncation`: `adjustTruncation`, the driver; `optimize`: `UniqueState`, records, rules, unused temporaries; large temporaries), `collisions`, unreferenced tables, register cross references, `unique` (crossbuild shift) |
| `symbols/` | `SymbolTable` (ids, scopes, lookup, `replaceSymbol`), `SymbolKind`, `OperandData` |
| `template`, `pattern` | the working IR: `Tpl`/`Op`/`Vn` with `bk_sla` constants and Ghidra's `ConstTpl::operator==`; pattern expressions and equations as resolved trees for the back half |
| `purge`, `elaborated` | the purge and renumbering; the public result with final ids |
| `canon` | the canonical comparison form (spec 6.2) of an `Elaborated` and of a `bk_sla::Sla`, `diff`, categories |
| `options`, `diag`, `spaces`, `ids` | switches `-u -l -c -n -t -e -s`; diagnostics with span, severity, Ghidra's text and whether Ghidra prefixes `FILE:LINE: ` |

Shared files touched: root `Cargo.toml` (one line in
`[workspace.dependencies]`), `Cargo.lock` (adds `bk-sleigh-compiler` only),
`fuzz/Cargo.toml` (one dependency, one `[[bin]]`), `fuzz/Cargo.lock` (adds
`bk-sleigh-compiler`, and `bk-binutils-sys`, which `master`'s fuzz lock was
missing), `fuzz/fuzz_targets/bk_sleigh_compiler_elaborate.rs`,
`docs/PERF.md` (appended), `docs/features/sleigh-compiler-front.md`
(sections 8 and 9).

## Results

* **6.2, differential, all 150** (`tests/reference_sla.rs`, verified with
  `BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`, 3–4 s): **150 of
  150** specifications equal the reference `.sla` with no tolerated
  difference. Per category, specifications agreeing: header and spaces
  150/150, scopes 150/150, symbol ids 150/150, symbol contents 150/150,
  constructors (location, `first`, operand id sets) 150/150, print pieces
  150/150, context changes 87/87 (the others have none), templates
  148/148 (two have no template). Remaining differences: none.
  Mutation check (each run on all 150): compiling the right operand of a
  binary operator before the left → templates of 133 specifications
  differ; allocating the export temporary at the start of the section →
  82 differ; skipping the context-layout sort → 18 differ (symbols and
  context changes).
* **6.3, diagnostics** (`tests/diagnostics.rs`, 92 cases in
  `tests/diagnostics/`, each an `insta` snapshot; with `REF/bin/sleigh`
  the success and the multiset of (severity, message) must be equal —
  verified equal for all 92). Every message of this half that can occur
  has a case (`MESSAGES` in the test, 103 patterns). Two cases make
  Ghidra die (null equation from `constrainOperand`; dangling op after a
  failed macro expansion): listed in `GHIDRA_CRASHES`, the test checks
  that everything Ghidra printed is reported. Messages found unreachable
  (and why) are in the feature doc, section 8.
* **6.4**: 16 feature fixtures (`tests/features.rs`: definitions, bit
  ranges in both endiannesses, context layout, attach, `with` nesting,
  every expression and statement form, exports and builds, named sections
  and crossbuild, macros, size propagation, the optimiser's two forms and
  interference, truncation fix-up, display) — snapshot of the canonical
  form, the equations and every template in the XML form; each is also
  compiled by Ghidra when present and must be equal (verified, all 16).
  `snippet_builder_without_a_constructor` drives `compile_snippet` over a
  hand-written resolver (acceptance 4). Property tests
  (`tests/properties.rs`, 256 cases each): generated bodies never panic;
  straight-line bodies over fixed-size registers have no zero-size
  varnode. `tests/crlf.rs`: every diagnostic case read with CRLF endings
  from a differently spelled directory gives the same diagnostics and
  canonical form. Unit tests: 13.
* **Fuzz**: `bk_sleigh_compiler_elaborate` (first byte: switches and
  whole-spec / body-after-prelude mode), 60 s, 216,321 runs, no finding.
* **Benchmark** (`tests/bench.rs`, release, one thread, loaded machine):
  x86-64 parse 12.9 ms + elaborate 29.3 ms; AARCH64 12.7 + 41.4 ms; all
  150 parse 338 ms + elaborate 654 ms = 1.03 s (budget 4 s; reference
  compiler 11.5–11.8 s for the whole compile). `docs/PERF.md`.
* **Ghidra tests ported**: none — the spec lists none for this half
  (`EqualEquationTest`, `SleighCompileRegressionTest`,
  `SleighCompileOptionsTest` are part 2's); checklist not touched.

## Platforms (what ran where)

* macOS arm64: everything above; `cargo clippy -p bk-sleigh-compiler
  --all-targets -- -D warnings` clean; the gate (result below).
* Windows: `cargo clippy -p bk-sleigh-compiler --all-targets --target
  x86_64-pc-windows-msvc -- -D warnings` clean (verified). The
  self-contained tests ran for `x86_64-pc-windows-gnu` under Wine in the
  `bk-gnu-disasm-win` linux/amd64 container (`target/windows/dock.sh gnu
  test -p bk-sleigh-compiler`, scripts copied from the windows-ci
  worktree): all passed (unit 13, diagnostics 2 with 92 snapshots,
  features 16, properties 2, CRLF 1; the reference test skipped), on the
  final tree (commit eb50366).
* Linux: not run locally; rests on CI. The Wine run was on x86-64 Linux
  (emulated) but tested the Windows build.
* Without oracles (`BASILISK_REFERENCE_DIR`/`BASILISK_GHIDRA_DIR` unset):
  the reference test prints `SKIPPED …` and passes; diagnostics and
  features compare with their snapshots only and say so. With the
  non-canonical spelling `/Users/tatu/slop/basilisk-wt/../reference`:
  all pass.

## What runs in CI (no Ghidra tree, no reference build)

Unit tests; the 92 diagnostic snapshots; the 16 feature snapshots and the
snippet-builder test; the property tests; the CRLF/path test. Not in CI:
the 150-specification comparison and the comparisons with Ghidra's
compiler (they skip with a printed reason).

## Differences from Ghidra

In the feature doc, section 8 (appended): continuing where Ghidra crashes;
unrecoverable errors as ordinary errors that stop elaboration;
token-class syntax errors abandon one constructor; recursion-safe
collision check; out-of-range `BUILD`; x86 shift semantics for out-of-range
masks; reachability standing in for "has a pattern"; limits; messages that
cannot occur.

## Gaps

None against the spec's acceptance known to me. Not verified: Linux
natively (CI), Windows MSVC execution (only the Wine run of the GNU
target), CRLF end to end through the file system on Windows (the CRLF test
uses an in-memory loader).

## Follow-ups (for `sleigh-compiler-back` and the coordinator)

* **Seams for the back half.** `elaborate` runs `check::post_parse`
  (`crates/bk-sleigh-compiler/src/check/mod.rs`): NOPs, case check,
  default space, consistency, collisions, then — where Ghidra calls
  `buildPatterns` and `buildDecisionTrees` — basilisk's "Unreferenced
  table" warnings from reachability, then register cross references, the
  crossbuild shift, and the purge (`purge::finish`). The back half should
  insert pattern building and decision trees after
  `check_local_collisions` and before `check_xrefs` (Ghidra's order), or
  run on the `Elaborated` result: purge and shift do not affect patterns.
  The `Elaborated` holds what it needs: constructors with operands in
  parse order (`OperandId`), each operand's defining symbol or expression
  and `offset_irrelevant` flag, pattern equations (`Equation`, with the
  `with` prefixes already applied) and expressions (`PExpr`, operands by
  `OperandId`), context changes, templates with handle indices in parse
  order (reorder them with the operand order the back half computes, as
  `Constructor::orderOperands` does with `changeHandleIndex`), print pieces
  with parse-order operand indices.
* The back half must lower to `bk_sla` through `SlaBuilder`;
  `canon::of_elaborated` vs `canon::of_sla` is a ready check of its
  lowering, and `tests/reference_sla.rs` can grow to byte equality.
* Diagnostics carry `located` (Ghidra's inner `FILE:LINE: `) and a span;
  the command line renders `FILE:LINE - ERROR TEXT` with the lexer's line,
  which basilisk approximates by the span's line.
* `bk-testkit` could own `module_options` (per-module `sleigh` switches
  from `REF/.state/lang/<Module>.opts`), now copied in three test files
  across crates.
* `bk-sleigh-syntax` could expose whether a `define`/`attach` list was
  bracketed (needed to choose between "N: redefined" and "syntax error");
  the elaborator looks for `[` in the source text instead
  (`compiler/define.rs`, `bracket_between`).

## Gate

`CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` → `0`; last
line `tests: 1743 passed, 0 failed` (macOS arm64, run without the oracle
variables, commit eb50366). `scripts/check-dep-age.py master`: 0 new
registry packages.

## Commits

`git log --oneline master..HEAD` is in the final message.
