# Track `sleigh-compiler-back` — status report

Status: **in progress** (2026-11-14). Spec: `docs/features/sleigh-compiler-back.md`.
Crate `crates/bk-sleigh-compiler` (part 2), command `basilisk sleigh compile`.
Worktree `/Users/tatu/slop/basilisk-wt/sleigh-compiler-back`, branch
`sleigh-compiler-back`.

## Findings from the reading

* **Seam.** `elaborate` (`src/lib.rs`) runs `check::post_parse`
  (`src/check/mod.rs`): NOPs, case check, default space, consistency,
  local collisions, then `warn_unreferenced_tables` (reachability standing
  in for "has a pattern"), xrefs, crossbuild shift; then `purge::finish`
  builds the `Elaborated` with final ids. Ghidra's `buildPatterns` and
  `buildDecisionTrees` sit between collisions and xrefs. Plan: run the back
  half there, on the compiler's pre-purge tables/constructors (same tables,
  same constructor order), replacing `warn_unreferenced_tables` with
  `buildPatterns`' own warnings (assert the set equals the reachability
  set), and carry the results (per constructor: minimum length, operand
  order, operand offset/base/min length; per table: decision tree) through
  the purge into `Elaborated`.
* **Tokens.** `resolveTokens` compares tokens by identity and needs their
  sizes; `PatValue::Token(Field)` carries neither. Change it to carry a
  token reference (index, size in bytes).
* **Lowering.** `bk_sla::SlaBuilder` takes symbols in id order, subtables
  with `TableDef { constructors, decision }`; blocks are normalised by the
  builder. `canon::of_elaborated` already maps the elaboration to the file's
  view and agrees with all 150 references; the lowering follows the same
  mapping, then applies the operand reorder (handle remap in templates,
  print pieces, `operand_exp` indices).
* **Score.** Unfused `f64`, a `log` bit-equal to glibc's FMA variant. The
  `libm` crate's `log` is fdlibm (not usable). Port Arm optimized-routines'
  `log` (Szabolcs Nagy), FMA path, with `libm::fma`. Open question: glibc
  is compiled with GCC's default `-ffp-contract=fast`, so the shipped binary
  may contract more than the explicit `fma`; the checked-in table
  (`docs/research/sla-host-dependence/logtable-glibc.txt.gz`) decides.

## Step plan

1. `score::log` port + table test (oracle-free). Commit.
2. Pattern algebra (`pattern/{block, disjoint, or, token_pattern}`) with unit
   tests and property tests. Commit.
3. Equations → patterns (`equation/{gen, resolve, order}`), `PatValue`
   token reference. Commit.
4. `build/{constructor, table, offsets, reorder}` wired into `post_parse`;
   diagnostics of 10 (c). Commit.
5. `decision/{node, score, order, properties}`. Commit.
6. `lower` to `bk_sla`, `driver::compile`, temp-file-and-rename write.
   Extend `tests/reference_sla.rs` to byte equality (packed, XML, warnings).
7. `basilisk sleigh compile` (options, `-i`, `-d`, `-a`, messages, exit
   codes); `SleighCompileOptionsTest`, `EqualEquationTest`.
8. Diagnostics cases (6.3), CRLF/path tests, fuzz target, benchmarks,
   Windows clippy / Wine, gate twice, report.

## Done

* Reading; this plan.

## In progress

* Step 1.

## Next

* Step 2.
