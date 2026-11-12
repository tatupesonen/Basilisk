# Track `sleigh-syntax` — status report

Status: **done** (2026-11-12). Spec: `docs/features/sleigh-syntax.md`
(sections 8 and 9 filled in). Branch `sleigh-syntax`, everything committed,
not pushed. Started from the checkpoint handover of the first agent; this
file replaces that handover.

"Verified" below means I ran it; anything else is said to be read or
inferred.

## Built

Crate `crates/bk-sleigh-syntax` (no `bk-*` dependencies, no `unsafe`):

| Module | What |
|---|---|
| `preprocess/` | `@include/@define/@undef/@ifdef/@ifndef/@if/@elif/@else/@endif`, `$(NAME)`, `BooleanExpression.g` evaluator, include resolution, limits |
| `source/` | `SourceMap` (preprocessed text, line runs, expansion records; `locate`, `include_chain`, `source_range`, `render`, `to_ghidra_text`), `SourceFile`, `SourceFileIndexer` |
| `loader.rs` | `FileLoader` (with `identity`, so file identity does not depend on path spelling), `FsLoader`, `MemoryLoader` |
| `lex/` | one scanner, `Mode::{Base, Display, Semantic}` chosen per token by the parser; `IntValue`/`Radix` literals of any width |
| `ast/` | symbol-free tree; recursive nodes in arenas (`Nodes`, typed `ExprId`/`PatExprId`/`EquationId`); `dump/` (S-expressions for tests and goldens), `print.rs` (back to SLEIGH) |
| `parse/` | recursive descent with precedence climbing, parser-driven lexer modes with re-seek, contextual keywords, per-statement/per-item recovery, `MAX_DEPTH` 128, `MAX_ERRORS` 500 |
| `lib.rs` | `parse_file`, `parse_str`, `parse_preprocessed`, `preprocess`, `parse_semantic_body`, `Parsed`, `ParsedBody` |

Shared files touched: root `Cargo.toml` (the three dependency lines; the
duplicate `num-bigint` removed after `master` added it), `Cargo.lock`,
`fuzz/Cargo.toml` (one dependency, one `[[bin]]`), `fuzz/Cargo.lock`,
`fuzz/fuzz_targets/bk_sleigh_syntax_parse.rs`, `docs/PERF.md` (appended),
`docs/inventory/tests/framework-softwaremodeling.md` (four marks),
`docs/features/sleigh-syntax.md` (sections 8 and 9).

Changes to existing code in this session (all verified by tests): lint
fixes for `master`'s configuration; `IntLit` packed from 32 to 24 bytes
(radix shares the representation tag; wide values stay boxed); output
limit now checked per expanded piece (a line of many references to a long
value could otherwise allocate without bound); included files identified
by loader identity (canonical path) rather than path spelling; `dump.rs`
and `source.rs` split; `FileId` doc corrected (it is include order, not
the `.sla` source index).

## Corpus

Verified, with no preprocessor definitions (what Ghidra's build passes —
see "Bug found"): 150 of 150 shipped `.slaspec` files preprocess and parse
with zero diagnostics. 348 unique source files, 931 inclusions, 1,117,804
preprocessed lines (28.7 MB), 7,821,930 tokens, 133,065 constructors
(2,725 `unimpl`), 2,578 macros, 157 `with` blocks, 32,714 definitions,
353,983 statements, 850,064 expression nodes, 1,547,835 equation nodes.
404,508 spans resolved to the original file and compared with the
expected token there, now including the 87,559 on lines that contain a
`$(NAME)` reference (the old check skipped them; all are right).

**Bug found in the old corpus test.** It passed every processor-module
name as a preprocessor definition, believing Ghidra does. It does not:
`gradle/processorProject.gradle` passes only each module's
`sleighCompileOptions`, and no shipped module sets `-D`/`-d`. Because
`HCS08` is both a module name and a conditional symbol, HC05 and HC08 were
parsed with the wrong branches (174 instruction constructors instead of
86). The `.sla` comparison exposed it; the tests now use no definitions
(`tests/common::build_defines`).

## Tests (verified: `cargo test -p bk-sleigh-syntax` with both env vars set)

317 passed, 0 failed, 4 ignored (benchmarks):

| Kind | Where | Count |
|---|---|---:|
| Unit | `src/**` | 98 |
| Doctest | `lib.rs` | 1 |
| Ported Ghidra | `ghidra_boolean_expression.rs` (31 + 3), `ghidra_preprocessor.rs` (2) | 36 |
| Corpus | `corpus.rs` | 1 |
| Differential vs Ghidra's compiler | `reference_sla.rs` (corpus `.sla` comparison; 15 edge cases) | 2 |
| Token fidelity | `token_fidelity.rs` | 1 |
| Precedence (tables from `slghparse.y`) | `precedence.rs` | 14 |
| Statement/operand forms | `statements.rs` | 121 |
| Preprocessor end to end | `preprocessor.rs` | 15 |
| Spans | `spans.rs` | 7 |
| Recovery and limits | `recovery.rs` | 6 |
| Goldens (`insta`, `tests/golden/`) | `golden.rs` | 10 |
| Property (`proptest`) | `properties.rs` | 5 |
| Benchmarks (`#[ignore]`) | `bench.rs` | 4 |

Ported and marked in `docs/inventory/tests/framework-softwaremodeling.md`:
`BooleanExpressionDefTest`, `BooleanExpressionTest`,
`SleighPreprocessorTest`, `SourceFileIndexerTest`. None marked not
applicable.

Also verified: with `BASILISK_GHIDRA_DIR=/Users/tatu/slop/basilisk/../ghidra`
(non-canonical) every test passes; with the variables unset the Ghidra- and
reference-dependent tests print `SKIPPED: …` and pass.

## Independent checks of the trees, and what each establishes

1. **Differential against Ghidra's C++ compiler, whole corpus**
   (`reference_sla.rs`, verified, 14 s). For each of the 150 specs the
   reference `sleigh -y` writes the `.sla` as XML; a model built from it is
   compared with one built from our tree using the compiler's own rules
   (`Constructor::addSyntax` for print pieces, `defineVarnodes` /
   `defineBitrange` for offsets, `WithBlock` for prefixes, reachability from
   `instruction` for which tables are written). Compared and equal for all
   150: 131,955 constructors, each in the same table, order, file and line;
   684,123 print pieces with operand names; 13,636 context changes and
   5,078 compound operand definitions by expression shape (operators,
   nesting, integer values); `globalset` counts, `unimpl`, `export`, named
   sections, label counts; 84,032 varnodes with space/offset/size; 29,319
   token and context fields with bit ranges, sign and flow; 7,721 attach
   lists; user ops; spaces. Mutation check: making `+` bind tighter than
   `*` in pattern expressions makes 59 specs fail.
   *Establishes:* constructor boundaries, table attribution through
   `with`, constructor lines through includes, display sections exactly as
   Ghidra prints them, pattern-expression trees in real use, and every
   definition's values. *Does not establish:* semantic-section trees
   (Ghidra keeps only compiled p-code; only `export`, sections and labels
   are compared), pattern *equation* structure (compiled into decision
   trees), anything about inputs Ghidra rejects, and it compares with the
   C++ front end, not Java. One allowance: a register in a pattern
   expression is the constant 0 in Ghidra's output (a compiler
   substitution), so our `leaf` matches an integer there.
2. **Token fidelity** (`token_fidelity.rs`, verified, 2.6 s): every
   semantic body, pattern equation and context block is printed back,
   re-lexed and compared token by token with its source span (5.9 million
   tokens); every display section's pieces tile the text between `:` and
   `is`. Mutation check: three printer changes give 1,091 failures.
   *Establishes:* the tree loses and invents no token. Printer and parser
   share one author's reading, so it does not establish grouping; item 1,
   the precedence tables and the property tests do that.
3. **Generated expressions** (`properties.rs`): random trees over all 36
   binary and 4 unary semantic operators, written with minimal parentheses
   from a precedence table written out in the test, parse to the expected
   S-expression and print back to the same tree.
4. **Edge cases through Ghidra's C++ compiler** (verified): 15
   hand-written specs; for each the test checks that we and C++
   accept/reject as recorded (table in spec section 8).

## Fuzzing (verified)

Target `bk_sleigh_syntax_parse` in the shared `fuzz/` crate (input split at
NUL into a root and three includable files; also fed to
`parse_semantic_body`), seeded with four Ghidra spec files in the
git-ignored corpus. `cargo +nightly fuzz list` shows it. Runs: 601 s,
212,426 executions, no finding (large seed inputs, about 350 exec/s);
then 301 s with `-max_len=2048`: 695,867 executions, no finding. Nothing to save under
`fuzz/regressions/`.

## Benchmarks (verified; `docs/PERF.md`)

`BASILISK_GHIDRA_DIR=../ghidra CARGO_BUILD_JOBS=2 cargo test --release -p bk-sleigh-syntax --test bench -- --ignored --nocapture --test-threads=1`
(Apple M1 Pro, other builds running): x86-64 15.6 ms (39,229 lines,
2.5 M lines/s), AARCH64 16.7 ms, PowerPC VLE 5.4 ms, whole corpus 325 ms
(3.4 M lines/s; budget 10 s). Peak RSS from `/usr/bin/time -l`, an upper
bound: 69 / 43 / 17 / 49 MB.

Node sizes, asserted in `ast::tests::hot_node_sizes`: `Expr` 72 bytes
(was 88), `Statement` 88 (was 104), `PatExpr` 32, `Equation` 36, `IntLit`
24 (was 32), `Ident` 12, `DisplayPiece` 16, `ContextStmt` 36. Decision on
wide literals: they were already out of line (boxed `BigUint`); the extra
size was padding from storing the radix beside a 16-byte value, so the
radix now shares the enum tag. Moving all literals to an arena would save
more but force every consumer through `Nodes`; not done.

## Differences from Ghidra

In the spec, section 8: nine deliberate departures, a table of every input
where Java and C++ differ with what each does and what is implemented
(Java throughout), marked where I ran the C++ compiler. Confirmed by
running C++: comparison chains are a syntax error there; `0n12` operands
are rejected; `0x10` in a display is split into `0` and operand `x10`;
display `_`, `0n12`, `with` are rejected (as operands); string escapes are
rejected; `!` in `@if` is rejected; nested unary is accepted; an open
`@if` at end of file is accepted; indented directives are not directives;
`0xg` is a syntax error (consistent with `0` then a name, which cannot be
told apart there from an invalid token). **Not confirmed by running:** any
Java behaviour (no Java compiler available).

## Gaps

* The Java front end was never run; Java-only behaviour is from its
  grammar.
* Semantic-section trees have no oracle beyond our own tests (see check 1).
* `Severity::Warning` is never produced.
* Error recovery inside a `with` block: a broken constructor is skipped to
  the block's `}`, losing the constructors after it in that block (Ghidra's
  C++ `error '}'` rule does the same).
* An unterminated string runs to the end of the input (Java strings may
  span lines), so it can swallow the rest of a file.

## Follow-ups for the SLEIGH compiler (M2) and the coordinator

* AST: identifiers are unresolved; `Expr::Apply` covers built-ins, user
  ops, macros and `x(n)` — resolve by name. `export` may appear anywhere
  syntactically; enforce "first section only". Integer widths: check
  `IntLit::to_u64()` where Ghidra says "exceeds Java long". `Paren` nodes
  are kept. Display: `DisplayPiece::Whitespace` prints as one space;
  leading whitespace is kept (decide Java's or C++'s rule); apply
  `Constructor::addSyntax`'s merging (the differential test's
  `ast_side.rs` is a working reference). A register in a pattern
  expression must become the constant 0.
* Spans: byte ranges in the preprocessed text; `SourceMap::locate` gives
  file/line/column (characters) and `in_expansion`. For the `.sla` source
  table use `SourceFileIndexer` over `SourceFile::name()` in order of first
  constructor (`FileId` is include order). The constructor's line is the
  line of its `:` (verified against all 131,955 constructors).
* Unreferenced tables are dropped from the `.sla` by Ghidra (warning
  "Unreferenced table"); reachability from `instruction` decides.
* `tests/reference/` (the `.sla` XML model) is reusable for M2's own
  differential tests.
* `tests/common/mod.rs` keeps a local `ghidra_dir()`; move to `bk-testkit`
  when allowed. The reference compiler lookup (`BASILISK_REFERENCE_DIR`)
  is also local to `tests/reference_sla.rs`.
* ADR-011 text for the three adopted crates and the rejected parser and
  lexer crates is in spec section 8.

## Gate

`CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` → `0`;
last line of `gate.log`: `tests: 653 passed, 0 failed` (workspace; run
without `BASILISK_GHIDRA_DIR`, so the corpus, reference and golden-Toy
tests skipped there; they pass with it set, see "Tests"). Verified on the
final commit.

## Commits

`git log --oneline master..HEAD` is in the final message to the
coordinator (this file's own commit is the last one).
