# Track `sleigh-compiler-back` — status report

Status: **done** (2026-11-14). Spec: `docs/features/sleigh-compiler-back.md`
(sections 8 and 9 filled in). Crate `crates/bk-sleigh-compiler` (part 2) and
`basilisk sleigh compile`. Worktree
`/Users/tatu/slop/basilisk-wt/sleigh-compiler-back`, branch
`sleigh-compiler-back`; everything committed, nothing pushed.

"Verified" means I ran it.

## Built

Crate `bk-sleigh-compiler` (new dependencies: `libm`, `thiserror`, both
already in the workspace; dev: `flate2`; no `unsafe`, no new registry
package — `scripts/check-dep-age.py master`: 0 new).

| Module | What |
|---|---|
| `pattern/{block, disjoint, algebra, token_pattern}` | `PatternBlock` (canonical form via `bk_sla::normalize_block`, zero-extended `getMask`/`getValue`, intersect, common, specializes, identical, the three block builders); disjoint patterns with the decision-tree helpers; `Pattern::{and, or, common, simplified}` with Ghidra's dispatch and `doOr` order table; `TokenPattern` (`resolveTokens`, `doAnd`/`doOr`/`doCat`/`commonSubPattern`) with `Tok` (index, size) — `PatValue::Token` now carries it |
| `equation/{generate, resolve, order}` | `genPattern` of every equation (constraint enumeration in `advance_combo` order, Java's unsigned `EqualEquation` range test, wrapping arithmetic, shifts mod 64, division by zero an error), `resolveOperandLeft`, `operandOrder` |
| `build/{mod, constructor, reorder, trees}` | `buildPatterns` (tables depth first, recursion rule, error text accumulated per table, "Unreferenced table"), `Constructor::buildPattern` (operand patterns, min lengths, variable length, offsets, unravelling, context validation), `orderOperands` and the handle map, `buildDecisionTrees` with identical/conflict errors |
| `decision/{node, order, score, log, log_data}` | `split` (explicit stack), `chooseOptimalField`, `consistentValues`, `orderPatterns`, `DecisionProperties`; the score in unfused `f64`; `log` bit-equal to glibc's |
| `lower` | `Elaborated` → `bk_sla::SlaBuilder` → validated `Sla`, applying the operand order (templates' handles and `BUILD` operands, print pieces, `operand_exp` indices) |
| `driver` | `compile(path, &Defines, Options, &mut dyn FileLoader) -> (Parsed, Compiled)`, `compile_parsed(&Parsed, Options) -> Compiled { sla: Option<Sla>, diagnostics }`; a UTF-8 BOM is ignored |
| `diag` | `Diagnostic::location`, `Diagnostic::ghidra_text` (Ghidra's `FILE:LINE: ` inner prefix) |
| `options` | `-f` (`warn_unused_fields`); `symbols` tracks lookups (Java's `wasSought`) |

Binary `basilisk`: `src/cmd/sleigh_compile/{mod, args}.rs`, registered as
`basilisk sleigh compile`. Shared files touched: root `Cargo.lock` (edges
only), `fuzz/Cargo.toml` (one `[[bin]]`), `fuzz/Cargo.lock`,
`fuzz/fuzz_targets/bk_sleigh_compiler_compile.rs`, `NOTICE` (appended:
Arm optimized-routines), `docs/PERF.md` (appended),
`docs/inventory/tests/{framework-softwaremodeling,test-integrationtest}.md`
(three lines), the spec's sections 8 and 9.

## The `log` (ADR-032)

Port of Arm optimized-routines `math/log.c` + `math/log_data.c`, **revision
20859d3fd9e797dde592c489c8ef7d383f778620** (downloaded from GitHub; MIT OR
Apache-2.0 WITH LLVM-exception; recorded in the module docs and `NOTICE`).
Finding: a port with only the explicit `fma(z, invc, -1.0)` differs from
the checked-in glibc table on 1,134 of 16,383 lines (musl's behaviour).
glibc is built as GNU C, where GCC contracts every product whose uses are
all additions/subtractions; writing each of those fusions out as
`libm::fma` makes the port **bit-equal on all 16,383 lines** (the table
test, `decision/log_table_test.rs`, under a second). The score itself is
unfused; the `TI_MSP430` tie test checks the trace's exact bits (unfused
`0x3ff859d146267a17` for both fields, fused `…a15`).

## Tests

* **6.2, all 150 specifications** (`tests/reference_sla.rs`, verified with
  `BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`):
  **150 of 150 byte-identical** inflated packed streams; **150 of 150** `-y`
  texts identical to `REF/bin/sleigh -y` run in the test (full text, no
  skipped lines); **150 of 150** warning sequences identical to
  `REF/logs/sleigh/<Module>/<name>.log` (with Ghidra's inner `FILE:LINE:`).
  The canonical-form comparison of part 1 still runs (150/150). **Tolerated
  differences: none.** Mutation check: computing the score with a fused
  multiply-subtract makes exactly the 14 files of ADR-029 differ (AARCH64,
  AARCH64BE, AARCH64_AppleSilicon, ARM8_le, ARM8m_le, mips32le, mips32R6le,
  ppc_64_isa_le, ppc_64_isa_altivec_le, TI_MSP430, TI_MSP430X, tricore,
  x86, x86-64), so the comparison is live. The behavioural cross-check of
  6.2 was not run separately: with byte-identical files the runtime reads
  identical models.
* **6.1 ported**: `EqualEquationTest` (3) → `src/equation/generate.rs`;
  `SleighCompileOptionsTest` (5) → `crates/basilisk/src/cmd/sleigh_compile/args.rs`;
  `SleighCompileRegressionTest` → 6.2 (stricter: no skipped lines, packed
  bytes too). `SleighLanguageProviderTest`: not this track (spec).
  Checklist lines marked.
* **6.3**: 25 new diagnostic cases (`tests/diagnostics/pat_*.slaspec`,
  snapshots), one per back-half message, plus `-l`/lenient and resolved
  conflicts and `-f`; compared with `REF/bin/sleigh` (success, multiset of
  messages; the token-mismatch text is normalised because Ghidra prints
  pointers): all agree. Not compared (listed in the test): `-f` (Java-only
  option), division by zero (undefined in Ghidra's C++). Not constructed:
  "Notequal constraint is impossible", "Circular offset dependency",
  "Child has as many Patterns as parent" (spec section 8). Command line
  (`crates/basilisk/tests/sleigh_compile.rs`, 6 tests): exit status and
  standard error equal to Ghidra's for bad option, missing input, too many
  parameters, bad `-D`, unreadable file, a successful compile (same
  output), and an undefined-operand failure (same text after ` - ERROR `;
  the `FILE:LINE` differs by design: Basilisk prints the diagnostic's
  location, Ghidra its lexer position); `-a` over a directory with one
  failing specification continues and exits 255 (Ghidra's C++ stops —
  expected difference); `-i`, `-f`; CRLF, BOM and path spellings give the
  same bytes.
* **6.4**: unit tests 58 in the crate (blocks in both endiannesses and
  across bytes, 8-byte tokens, normalize, each operation, every row of the
  `doOr` table, `resolveTokens` cases, ellipses and concatenation offsets,
  unravelling, `orderOperands` with dependent offsets, `chooseOptimalField`
  incl. context-vs-instruction tie and the `maxfixed` reset, `orderPatterns`
  with nested/resolved/conflicting patterns, the score tie, the `log`
  table, Send+Sync, BOM); property tests (block operations' set meaning;
  the tree resolves every input to a matching pattern, the only one when
  only one matches, and — when no identical/conflicting patterns are
  recorded — to the linear scan of the specialisation-ordered list):
  verified at `PROPTEST_CASES=200000`, no failure (so no regression file).
  Fuzz `bk_sleigh_compiler_compile`: 60 s, 462,111 runs, no finding
  (nothing to replay).
* **Gate**: see below.

## Benchmarks (spec 6.5, `docs/PERF.md`)

Same session, release, one thread, load average ~4 (one other agent):
x86-64 195 ms vs reference 378 ms; AARCH64 156 vs 319 ms;
`RISCV/andestar_v5` 103 vs 1,670 ms; all 150 one after another 3.83 s vs
11.21 s. Command:
`BASILISK_REFERENCE_DIR=../reference cargo test --release -p bk-sleigh-compiler --test bench -- --ignored --nocapture --test-threads=1`.

## Differences from Ghidra

Spec section 8 (appended): the `log` port's contractions; `OrPattern::doOr`
left-operand mutation not reproduced (unobservable); enumeration limit
2^20 and depth limits (512 equations/expressions, 256 tables); linear `or`
accumulation; defaults for uninitialised operand offsets; loop guard in
unravelling; `-f`, `-d` and `-a` semantics; no XML job files; error-line
locations; BOM; lowering errors as "Unrecoverable error"; messages not
constructed.

## Plugin binding constraints (ADR-037)

Applicable items: **1** (no lifetimes) — `compile` returns owned
`(Parsed, Compiled)`; `Sla` is an owned value. **2** (`Send + Sync +
'static`) and **6** (owned, immutable, keepable results) — asserted by
`driver::tests::results_are_send_and_sync` for `Compiled`, `Sla`,
`Diagnostic`, `Parsed`, `LowerError`. **4** (typed errors) — `LowerError`
is a `#[non_exhaustive]` `thiserror` enum; compile problems are
`Diagnostic` values (severity, span, Ghidra's text), not strings in an
error. **12** (no Rust-only generics) — `compile` takes
`&mut dyn FileLoader`, concrete `Defines`/`Options`. **15** (callable as a
library) — the command is a thin layer over `compile`. **7** (one monitor
type): not met — a compile cannot be cancelled or report progress (it
takes up to 0.2 s for the largest specification); a `Monitor` parameter
can be added when the monitor type exists in a low crate. Items 3, 5,
8–11, 13, 14 do not apply (no program entities, collections or
transactions).

## Platforms (what ran where)

* macOS arm64: everything above; the gate (below).
* Windows: `cargo clippy -p bk-sleigh-compiler -p basilisk --all-targets
  --all-features --target x86_64-pc-windows-msvc -- -D warnings` clean
  (verified). Under Wine (`x86_64-pc-windows-gnu`, the `bk-gnu-disasm-win`
  linux/amd64 image; scripts in `target/windows/`): all of
  `bk-sleigh-compiler`'s tests pass — unit 56, crlf 1, diagnostics 2 (with
  every snapshot), features 16, properties 2, reference_sla 2 (skipped:
  no reference), bench ignored — including the `log` table on x86-64
  emulation. (Insta needs `INSTA_WORKSPACE_ROOT='Z:\work\build\src'` under
  Wine.) `basilisk` under Wine: unit 8 (incl. `SleighCompileOptionsTest`)
  and the 6 command tests pass (output written by rename, also over an
  existing file; CRLF, BOM, path spellings); the Ghidra comparison skipped.
  Build directories deleted afterwards; scripts kept.
* Linux: not run locally; rests on CI.
* Without the oracle variables: reference tests print `SKIPPED …` and pass.

## Spec items found wrong

* 4.3 point 2 says to follow glibc's FMA path "with no other fusion". That
  does not give glibc's results: glibc's binary has GCC's contractions.
  Implemented the closest correct thing — every fusion GCC performs,
  written out (verified bit-equal on the whole table).
* 4.7 BOM: `bk-sleigh-syntax` does not ignore a BOM; handled in
  `bk-sleigh-compiler::compile` (see Follow-ups).

## Gaps

* No cancellation/progress (plugin constraint 7).
* The behavioural cross-check of 6.2 was not run as a separate test
  (redundant: files byte-identical).
* "Circular offset dependency" and "Child has as many Patterns as parent"
  have no case (not constructible as far as I found).

## Follow-ups

* `bk-sleigh-syntax`: strip a leading U+FEFF in `FsLoader::load`/
  `MemoryLoader` (or in the preprocessor) so every user of the syntax
  crate gets it; then `driver::WithoutBom` can go.
* `bk-testkit` could own `module_options` (now in four test files).
* Decision-tree speed: `chooseOptimalField` re-extracts bits through
  `Block::mask`/`value` for every candidate field; caching flattened
  pattern bits would cut the 2.4 s of elaboration for all 150 further.
* The Wine `run.sh` needs `INSTA_WORKSPACE_ROOT` set; worth putting in the
  windows-ci scripts.

## Gate

`scripts/gate.sh > gate.log 2>&1; echo $?` (default cargo parallelism, as
the owner allowed on 2026-11-14), macOS arm64, final tree:

* both oracle variables unset: `0`, last line `tests: 2026 passed, 0 failed`
  (the first attempt failed only on the known flaky `bk-ui`
  `task::tests::requests_complete_off_thread_and_wake`; rerun green);
* `BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra
  BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`: `0`, last line
  `tests: 2026 passed, 0 failed`.
