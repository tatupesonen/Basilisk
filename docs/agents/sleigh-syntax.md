# Track `sleigh-syntax` — handover

Status: **stopped at a checkpoint on the owner's instruction (2026-11-12);
not finished.** The crate builds, its tests pass, everything is committed
on branch `sleigh-syntax`. This file is the starting point for whoever
finishes the track. Spec: `docs/features/sleigh-syntax.md`.

Summary: the preprocessor, modal lexer, AST and parser are written and all
150 shipped `.slaspec` files preprocess and parse with zero diagnostics.
What is missing is mostly verification and paperwork: structural tests for
definitions/display/`with`, recovery tests, goldens, property tests, the
fuzz target, the benchmark, the checklist marks, the spec's "Differences"
and "Status" sections, `PERF.md`, and the full gate.

## 1. Done

Crate `crates/bk-sleigh-syntax` (about 8,400 lines under `src/`, unit tests
included, and 1,150 lines of integration tests). No dependency on other `bk-*` crates. No `unsafe`.

| Module | What it is | Against the spec |
|---|---|---|
| `span.rs` | `Span` (byte range in the *preprocessed* text), `FileId`, `IncludeId`, `Location` | complete |
| `diag.rs` | `Diagnostic { severity, span, message }`, `Severity` | complete (`Severity::Warning` is currently never produced, see §5) |
| `intern.rs` | `Symbol(u32)`, `Interner` (wrapper over `string-interner` + `rustc-hash`), `kw::*` keyword constants at fixed indices | complete |
| `loader.rs` | `FileLoader` trait, `FsLoader` (UTF-8, falling back to ISO-8859-1), `MemoryLoader`, `LoadError` | complete |
| `source.rs` | `SourceMap`: preprocessed text + line runs + expansion records; `locate`, `include_chain`, `source_range`, `render`, `to_ghidra_text`; `SourceFile`; `SourceFileIndexer`; `EXPANSION_MARK` | complete for §4.1 "origin of every line"; `render` is a one-line format only |
| `preprocess/` | `mod.rs` driver and conditional stack, `directive.rs` (the regex forms of `SleighPreprocessor.java`), `expr.rs` (`BooleanExpression.g`), `expand.rs` (`$(NAME)`), `include.rs` (path resolution), `defines.rs` (`Defines`) | §4.1 complete |
| `lex/` | `mod.rs` one scanner with a `Mode` parameter (Base, Display, Semantic), `token.rs`, `literal.rs` (`IntValue`, `Radix`) | §4.2 complete |
| `ast/` | `mod.rs` (`Spec`, `Item`, `Constructor`, `DisplayPiece`, `WithBlock`, `MacroDef`), `definitions.rs`, `pattern.rs`, `semantic.rs`, `nodes.rs` (arenas and ids), `dump.rs` (S-expression rendering for tests/goldens), `print.rs` (back to SLEIGH source) | §4.3 complete as designed; `print.rs` covers semantic bodies, equations and pattern expressions only, and is **untested** |
| `parse/` | `mod.rs` (token handling, mode switching, diagnostics, limits, entry points), `definitions.rs` (item dispatch, `define`, `attach`, item recovery), `constructor.rs` (constructor, display section, `with`, `macro`), `pattern.rs` (equations, pattern expressions, context block), `semantic.rs` (statements), `expr.rs` (semantic expressions) | §4.3 complete; §4.4 recovery is written but only lightly tested |
| `lib.rs` | `parse_file`, `parse_str`, `parse_preprocessed`, `preprocess`, `parse_semantic_body` (bare statements, for the M1 p-code snippet parser), `Parsed`, `ParsedBody` | complete |

Shared files touched: root `Cargo.toml` (three lines appended under
`[workspace.dependencies]`: `string-interner`, `rustc-hash`, `num-bigint`)
and `Cargo.lock`. Nothing else outside the crate except this file.

## 2. Verified (what I ran, and the result)

All with `BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra`.

* `CARGO_BUILD_JOBS=2 cargo test -p bk-sleigh-syntax` — **265 passed, 0
  failed**: 92 unit, 1 corpus, 34 + 2 ported Ghidra tests, 14 precedence,
  121 statement-form, 1 doctest. With `BASILISK_GHIDRA_DIR` pointing
  nowhere the same command also passes (the three Ghidra-dependent tests
  print `SKIPPED: …` and return).
* `cargo clippy -p bk-sleigh-syntax --all-targets -- -D warnings` — clean
  (against the lint set on *this branch*; `master` is stricter now).
* `cargo fmt -p bk-sleigh-syntax --check` and `scripts/check-file-size.sh`
  — clean (largest file 792 lines: `ast/dump.rs`, over the 600-line
  split signal).
* **Not run:** the full gate (`scripts/gate.sh`), any fuzzing, any
  benchmark, anything after merging `master`.

Corpus (`tests/corpus.rs`, one test, single-threaded):

* **150 of 150 `.slaspec` files get through the preprocessor, the lexer
  and the parser with zero diagnostics.** There are no failures at any
  stage.
* Totals: 348 unique source files, 931 inclusions, 1,117,804 preprocessed
  lines (28.7 MB), 7,827,801 tokens, 133,191 constructors (2,725
  `unimpl`), 2,578 macros, 157 `with` blocks, 32,719 definitions, 354,446
  statements, 851,218 semantic expression nodes, 1,548,273 pattern
  equation nodes.
* Spans: for every constructor (start, `:`, body `{` or `unimpl`), macro
  and `with` block, the span is resolved to file/line/column and the
  original file's text at that position is compared with the expected
  token: 317,327 positions checked and correct; 87,559 more were skipped
  because their line contains a `$(NAME)` reference.
* Time: 0.61 s for the whole corpus inside the test (test profile,
  `opt-level = 1`). This is a wall-clock print from the test, not a
  benchmark; the spec's target is under 10 s.

Ported Ghidra tests (all pass):

* `BooleanExpressionTest` (31) and `BooleanExpressionDefTest` (3) →
  `tests/ghidra_boolean_expression.rs`.
* `SleighPreprocessorTest` (1) → `tests/ghidra_preprocessor.rs::
  sleigh_preprocessor_test_external`: all 9 `*.input` files under
  `SoftwareModeling/src/test/resources` are preprocessed with
  `REPLACE=includes` and compared line by line with Ghidra's `*.output`
  files, through `SourceMap::to_ghidra_text` (which renders Ghidra's
  `\bfile###line\b` / `\b$(NAME)\b` marker format).
* `SourceFileIndexerTest` (1) → same file,
  `source_file_indexer_basic_test` (the null-location and null-filename
  inputs cannot be expressed in Rust and are noted in the test).

Structure checks that exist:

* `tests/precedence.rs`: all 36 × 36 pairs of semantic binary operators,
  all pairs of equation operators (`| ; &`), all pairs of pattern
  expression operators in constraints and in context blocks, unary
  binding, ellipses, constraints. Expected trees are computed from
  precedence tables transcribed in the test from `slghparse.y`, not from
  the parser's tables.
* `tests/statements.rs`: every statement, jump-destination, lvalue,
  export and operand form of `SemanticParser.g`; keywords used as names;
  reserved words; 25 rejected inputs with their messages; `sections()`.
* Unit tests: 50 directive forms, expression evaluator, expansion,
  include path rules, lexer in all three modes, literals, interner,
  source map basics.

Written but **not tested beyond "the corpus parses"**:

* definitions (`define`/`attach` forms) — no test looks at the tree;
* display sections — pieces, whitespace, `^`, quoted strings, the
  rejected `_`/`0n`/`with` pieces;
* `with` blocks (nesting, missing table/pattern/context);
* macros; context blocks beyond the expression shape;
* item-level error recovery (`recover_item`), `MAX_ERRORS`, `MAX_DEPTH`;
* preprocessor error paths (unknown directive, `else`/`elif`/`endif`
  misuse, unknown variable, undefined name in `@if`, missing include,
  include cycle, `MAX_INCLUDE_DEPTH`, `MAX_INCLUSIONS`,
  `MAX_OUTPUT_BYTES`) — implemented, no test triggers them;
* spans through `$(NAME)` expansions (`in_expansion`, column mapping) —
  only the unit tests in `source.rs` without expansions, and the corpus
  check, which skips exactly those lines;
* `SourceMap::render`, `source_range`, `include_chain`;
* `ast::print::Printer` (no test at all);
* `ast::dump::spec` (item-level rendering; only expression, equation,
  context and statement renderings are exercised);
* `parse_str`, `LoadError::TooLarge`.

## 3. Remaining, in the order I would do it

1. Merge `master` (stricter lints, licence change, `unsafe` rule) and fix
   what it reports.
2. **Derived tests** (spec §6), using the helpers already in
   `tests/common/mod.rs` (`dump_items`, `equation`, `context`, `errors`):
   each definition form; display sections with awkward whitespace and
   punctuation; `with` nesting; keyword-as-identifier in definitions
   (`define token offset = …` rule, context field named like a modifier);
   each preprocessor directive end to end, nested conditionals, skipped
   regions, every error path listed above; spans through includes *and*
   expansions (acceptance 3 needs a direct test, not only the corpus).
3. **Error recovery tests**: several errors in one file, each with the
   right line, including inside an include; no cascades; `MAX_ERRORS`.
4. **Corpus-wide token fidelity** (my planned answer to "a lenient parser
   could build the wrong tree"): for every semantic body and pattern
   equation, print it with `ast::print::Printer`, lex the result, and
   compare with the tokens of the original span (integers by value and
   radix; `$or`≡`|` in context blocks). For display sections, check the
   pieces tile the text between `:` and `is` exactly. This proves the
   tree loses no token; `tests/precedence.rs` covers the shape.
5. **Goldens** under `tests/golden/` with `UPDATE_GOLDEN=1`: the `Toy`
   processor's AST (`ast::dump::spec` with `Some(&sources)` adds
   `@file:line:col` per item) and hand-written fragments for each
   construct of spec §4.
6. **Property tests** (`proptest` is already a dev-dependency): arbitrary
   strings/bytes never panic in `preprocess`, the lexer (all modes) and
   the parser; generated expression trees → source with minimal parens →
   parse → same tree; parse → `Printer` → parse gives the same dump.
7. **Fuzz target** (`cargo-fuzz 0.13.2` and a nightly toolchain are
   installed). `docs/LOOP.md` says `fuzz/` at the workspace root; every
   track will create `fuzz/Cargo.toml` there, so expect an add/add merge
   conflict — tell the coordinator or use a per-crate fuzz directory.
   Run 60 s (acceptance 4).
8. **Benchmark** as `#[ignore]` release tests: x86-64, AARCH64, PowerPC
   and the whole corpus; lines/s and peak allocation; record in
   `docs/PERF.md`. Assert `size_of::<Expr>()` etc. (see §4).
9. **Checklist marks** in `docs/inventory/tests/framework-softwaremodeling.md`
   (lines 91–94; the ports exist and pass, the marks are **not made**):
   `BooleanExpressionDefTest` and `BooleanExpressionTest` →
   `crates/bk-sleigh-syntax/tests/ghidra_boolean_expression.rs`;
   `SleighPreprocessorTest` and `SourceFileIndexerTest` →
   `crates/bk-sleigh-syntax/tests/ghidra_preprocessor.rs`.
10. **Spec paperwork**: append §6 and §7 of this file to "Differences from
    Ghidra" in `docs/features/sleigh-syntax.md`, fill in "Status".
11. Split `ast/dump.rs` (792 lines) into definitions/pattern/semantic
    parts; consider `source.rs` (626).
12. Full gate: `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?`.
13. Rewrite this file as the final status report (`docs/agents/RULES.md`).

## 4. In flight, and the design choices

I was between units when told to stop: `tests/statements.rs` had just been
committed; the next file would have been a definitions/display/`with`
test. Nothing is half-written.

**Source positions.** A `Span` is a byte range in the preprocessed text.
`SourceMap` holds that text, one entry per output line start, *runs*
(consecutive output lines that come from consecutive lines of one
inclusion), a kind per line (text / directive / skipped) and one record
per `$(NAME)` expansion. Directive and skipped lines produce an empty
output line, so output line *n* always exists and line bookkeeping is
trivial; an expanded `@include` line produces none and starts a new run.
An `IncludeId` is one inclusion of a file (a file included twice has one
`FileId`, two `IncludeId`s, two include chains). Rejected alternative:
lexing straight from the include stack — `$(NAME)` expansion in the Java
front end is textual, so a line buffer is needed anyway.

**Expansion mark.** Every expanded value is preceded by one U+0008 in the
preprocessed text (`EXPANSION_MARK`); the lexer skips it in every mode and
no token spans it. This is not decoration: Ghidra writes `\b$(NAME)\b`
there and its lexer hides it, which makes the *start* of a value a token
boundary. `ARMneon.sinc` has `{ export$(FPRounding_TIEEVEN); }` and
`mips64Instructions.sinc` has `is$(AMODE)`; without the mark these lex as one identifier and
8 ARM specs fail. (First attempt, plain textual substitution, failed
exactly there.) The end of a value is *not* a boundary in Java.

**Parser-driven lexer modes.** One `Lexer::next_token(mode, &mut
Interner)`; the parser passes the mode per token. The parser keeps the
current token plus a `VecDeque` of lookahead tokens scanned in the current
mode. `set_mode` clears the lookahead and re-seeks the lexer to the end of
the current token, so nothing scanned in the wrong mode survives. Mode
changes happen only at `:` (→ Display), `is` (→ Base), `{` (→ Semantic)
and `}` (→ Base), which lex identically in all modes. Lexical error tokens
stay in the lookahead queue and are reported only when they would become
current, so wrong-mode lookahead never reports spurious errors.

**Keywords are contextual.** The lexer returns every word as `Ident` with
its `Symbol`; keywords are pre-interned so `tok.is_word(kw::DEFINE)` is an
integer compare. The parser decides by position, mirroring ANTLR's
`key_as_id`. Reserved: `with` everywhere; `if` in semantic mode; `is`
ends a display section and is an ordinary identifier elsewhere.

**AST layout.** Recursive nodes (`Expr`, `PatExpr`, `Equation`) live in
arenas in `ast::Nodes`, addressed by `ExprId`/`PatExprId`/`EquationId`
(`nodes[id]`; a foreign id yields an `Error` node, never a panic). Call
arguments are ranges (`ExprList`) into a shared pool, collected on a
parser scratch stack so nested calls do not allocate. Items, statements,
display pieces and context statements are plain `Vec`s (allocation per
constructor, not per token). `Paren` nodes are kept. Named sections are
flat `Statement::Section` markers with `SemanticBody::sections()` to split
them. `Parsed.spec.nodes` owns the arenas; `parse_semantic_body` returns
them beside the body.

**Known weak spot:** `IntLit` is stored inline (about 32 bytes), so `Expr`
is probably 72–80 bytes and `Statement` about 96. I did not measure or
assert sizes. If it matters, move integer literals of expressions into
their own arena (`IntId`).

**Diagnostics.** Parser errors are deduplicated per token position;
statement errors skip to `;`, context-statement errors to `;`/`]`, item
errors to `;` or through the closing `}` (brace depth tracked; inside a
`with` its own `}` is left). After `MAX_ERRORS` (500) one "too many
errors" is added and the parser jumps to end of input. Nesting of
parentheses, unary operators, `&` and `with` is capped at `MAX_DEPTH`
(128). Preprocessor limits: include depth 64, 10,000 inclusions, 1 GiB of
output, 4,096 digits per integer literal.

## 5. What Ghidra's sources say that the spec does not

Preprocessor (`SleighPreprocessor.java`):

* **The spec is wrong about indentation.** The regexes allow leading
  whitespace, but the code only treats a line as a directive when
  `line.charAt(0) == '@'`; the C++ scanner also requires column one
  (`^@`). Implemented: column one only.
* A line matching `^\s*#.*` is blanked before anything else. In a
  directive line everything from the first `#` is dropped *even inside
  quotes* (`@define X "a#b"` defines `X` as `"a`).
* `@define NAME value` takes one run of non-space characters; `@define X
  a b` is "unrecognized preprocessor directive". Values are not expanded.
* `$(NAME)` expansion is textual, leftmost-first, not recursive, and also
  happens inside trailing comments and strings (an unknown name in a
  trailing comment is an error in Ghidra and here).
* Inside a false conditional `@include/@define/@undef` are inert, but
  `@if/@elif` expressions are still evaluated, so an undefined name there
  is still an error; an unknown or malformed directive there is still an
  error. `@elif` is not evaluated once a branch was taken.
* Conditionals are per file in Java (fresh stack per include), global in
  C++. Neither front end complains about a conditional left open at end
  of file, and `ARMv8.sinc` relies on it — I first made it a warning and
  the corpus test failed, so nothing is reported.
* Undefined name in a comparison: reported (`Macro: X is undefined`),
  compares unequal to everything, so `X != "a"` is true.
* `BooleanExpression.g`: `!` applies only to a parenthesised expression
  (`!defined(X)` is a syntax error); precedence `||` < `^^` < `&&`; both
  operands are always evaluated. The C++ evaluator has no `!` and no
  precedence (left to right). On a *syntax* error ANTLR prints to stderr,
  returns whatever it has and the compile continues; here it is an error
  diagnostic and the condition is false.
* Java reports the file *name*, not the path, in locations and in the
  `.sla` source-file table, and `SourceFileIndexer` assigns indices in
  order of first *constructor*, not include order — so `FileId` (include
  order) is not the `.sla` index; use `SourceFileIndexer`.
* Module definitions: `-DNAME=VALUE` and `-dMODULE` (module name → module
  directory). No shipped spec uses them; the corpus test passes them
  anyway.

Lexers (`BaseLexer.g`, `DisplayLexer.g`, `SemanticLexer.g`, `slghscan.l`):

* Identifiers are `[A-Za-z_.][A-Za-z0-9_.]*`; a lone `_` is the wildcard
  token and `...` the ellipsis, but `...x`, `x...`, `....` are identifiers
  (longest match, both front ends).
* `s<`, `s>>`, `f+`, `f==` … are single tokens in semantic mode only, so a
  varnode named `s` or `f` directly followed by such an operator is
  mis-lexed by design, and `<s>` cannot be a label.
* Strings: Java accepts backslash escapes and line breaks inside strings
  and never unescapes (the tree walker uses the raw text); C++ accepts no
  control characters, no escapes, and `""` for a quote.
* `0n123` is an explicit-decimal literal that only Java has, and only as
  an operand in a semantic section (`int_lit`), not where `integer` or
  `constant` is required.
* `//` is always an error token in Java. A prefix without digits (`0xg`)
  is `0` followed by an identifier in flex; I believe ANTLR's lookahead
  does the same and implemented that, but did not run Ghidra to confirm.
* Display mode: whitespace runs are tokens, `#` is a print piece (no
  comments between `:` and `is`), `@ $ ?` are legal, numbers are single
  pieces (`0x10` is one literal in Java; in C++ it is `0` then the symbol
  `x10`, which could be an operand). `DisplayParser.g`'s `printpiece`
  omits a lone `_`, `0n` integers and `with`: implemented as errors. No
  shipped spec contains them, and I did not confirm against a running
  Ghidra.
* Leading whitespace after `:` is kept as a piece. The Java tree walker
  treats only the very first piece specially (mnemonic in the root table),
  so `: ADD` differs from `:ADD` there, while C++ skips leading spaces.
  The compiler must decide; the AST keeps the whitespace.

Parsers (`SleighParser.g`, `SemanticParser.g`, `slghparse.y`):

* Precedence is identical in both: `||`; `&&` `^^`; `|`; `^`; `&`;
  equality; comparison; shifts; additive; multiplicative; unary. C++
  makes comparisons non-associative, Java left-associative (implemented:
  left). Equations: `|` < `;` < `&`.
* Java allows one unary operator in front of a call or term (`- -x` and
  `!~x` are errors; in pattern expressions not even `-f(x)`); C++ allows
  nesting. Implemented: nesting accepted (the union; trees agree wherever
  both accept).
* In a constraint only `$or/$xor/$and` are value operators (`pexpression2`),
  because `|` and `&` combine equations; in a context block `| ^ &` work
  too (`pexpression`).
* A token field's name must not be a keyword (`strict_id`); a context
  field's may be. `define alignment` is allowed inside `with` in Java but
  not in C++.
* `zext`, `carry`, `delayslot`, `globalset`, `x(n)` … are plain
  `Apply` nodes in the Java tree (C++ has tokens for them); the compiler
  resolves them by name. `globalset(a, b)` is the only context-block call
  the tree walker accepts.
* An empty statement (`;`) aborts Java with "Empty statement at …"; here
  it is an error and parsing continues.
* `export` may syntactically appear anywhere in a body; the compiler must
  enforce "only in the first section".
* The compiler checks literal widths ("Integer representation exceeds
  Java long"), so literals must be exact beyond 64 bits: `IntValue`.

## 6. Decisions and crate evaluations

Figures from crates.io on 2026-11-12: total downloads / recent (90 days) /
reverse dependencies / newest version and date.

Adopted:

* **`string-interner` 0.20.0** (41.5M / 6.3M / 76 / 2026-04-30) for
  `Interner` and `SourceFileIndexer`. Per-instance, symbols documented as
  contiguous from 0 (needed for the fixed keyword symbols; a unit test
  asserts it), custom hasher. Wrapped so the dependency is not in the
  public API. Rejected: `lasso` (14.9M / 3.8M / 89; no release since
  2024-08-19); `string_cache` (214M / 65M / 79) — the most downloaded, but
  a process-global atom table with build-script static atoms, which the
  no-global-state rule excludes; `internment` (16.6M / 2.4M / 34) and
  `ustr` (4.6M / 1.7M / 95), also global.
* **`rustc-hash` 2.1.3** (1,010M / 300M / 3,801 / 2026-07-02) as the
  interner's hasher.
* **`num-bigint` 0.4.8** (741M / 211M / 2,599 / 2026-07-05) for literals
  wider than 64 bits. `BigUint` allocates per value, so `IntValue` keeps
  values up to 64 bits inline and boxes a `BigUint` otherwise. Rejected as
  niche: `dashu-int` (6.1M / 3.3M / 32), `ibig` (0.96M / 0.15M / 39, 2022).
* `memchr`, `thiserror` (already in the workspace); dev: `proptest`
  (not used yet), `rstest`.

Evaluated and not adopted (hand-written instead):

* **Lexer — `logos` 0.16.1** (101M / 32.5M / 579). It could express the
  tokens, and has a `forbid_unsafe` feature (required here, at a speed
  cost). Not adopted because the three modes share all but about 20
  tokens and logos cannot share definitions between token enums (three
  near-copies, or one enum plus a wrapper that splits `s<` back apart in
  base mode and `#…` comments in display mode); because the parser must
  re-lex from an arbitrary offset when it switches mode; and because
  identifiers are interned and expansion marks skipped inside the scanner.
  The hand-written scanner is 320 lines.
* **Parser — `winnow`** 1.0.4/1.0.5 (1,163M / 370M / 465; error recovery
  is the `unstable-recover` feature), **`nom`** 8.0.0 (886M / 228M /
  2,631; no recovery), **`pest`** 2.9.6 (390M / 88M / 1,283; stops at the
  first error, untyped tree needing a second pass, no nesting guard),
  **`lalrpop`** 0.23.2 (79.5M / 15.1M / 273; LR lookahead is fetched
  before an action can switch the lexer mode — the hazard Ghidra's
  grammar README describes — keywords-as-identifiers conflict in LR(1),
  heavy build dependencies), **`chumsky`** 0.13.0 (31.9M / 5.6M / 329;
  deep nesting relies on its `stacker` feature, a native stack-switching
  dependency, where this track needs an explicit depth limit). The spec
  requires parser-driven modes, per-construct recovery, bounded nesting
  and spans through the source map; recursive descent gives all four
  directly.
* **Diagnostics rendering — `codespan-reporting`** 0.13.1 (168M / 38.4M /
  262), `miette` 7.6.0 (92M / 25.5M / 1,692), `annotate-snippets` 0.12.18
  (72M / 30M / 179), `ariadne` 0.6.0 (14.6M / 4.7M / 345). Nothing was
  reimplemented: this crate produces structured diagnostics and a
  one-line `path:line:col: error: message` with the include chain.
  Snippet rendering belongs in the CLI/UI; `SourceMap::source_range`
  gives the `(file, byte range)` such a crate needs. I would use
  `codespan-reporting`.

Differences from Ghidra (deliberate; to be copied into the spec):

1. Locations come from a `SourceMap`, not marker lines; one U+0008 before
   each expanded value keeps Ghidra's token boundary.
2. Errors are collected and parsing continues; Ghidra's preprocessor
   aborts at the first error (Java exception, C++ `exit(1)`). An unknown
   `$(NAME)` expands to nothing after being reported.
3. A syntax error in an `@if`/`@elif` expression is an error (Java prints
   to stderr and carries on).
4. Files are decoded as UTF-8 when valid, otherwise ISO-8859-1 (Java
   always uses ISO-8859-1; seven shipped files have UTF-8 in comments).
5. Include cycles and the limits in §4 are diagnostics (Ghidra overflows
   the stack or runs on). Include file-name case is not checked (Java's
   `existsAndIsCaseDependent`).
6. Nested unary operators are accepted (C++ yes, Java no).
7. `define endian` missing or not first is reported, and the rest is
   still parsed (`Spec.endian` is `Option`).
8. An empty statement is an error, not an abort.
9. Where Java and C++ differ (comparison associativity, `0n`, string
   escapes, display numbers, `!` in `@if`, per-file conditionals, textual
   expansion that can join the following text) the Java behaviour is
   implemented.

## 7. Follow-ups for the coordinator and the M2 compiler

* `tests/common/mod.rs` has a local `ghidra_dir()` (rule of
  `docs/LOOP.md`); replace with `bk-testkit` when the crate may depend on
  it.
* The three new workspace dependencies need their ADR-011 entries (§6 has
  the text).
* The compiler must: resolve `Apply` by name; enforce `export` placement;
  check `IntValue::to_u64()` where Ghidra says "exceeds Java long";
  decide the leading-display-whitespace question; index source files with
  `SourceFileIndexer` by `SourceFile::name()`; treat
  `DisplayPiece::Whitespace` as one space.
* No differential check against real Ghidra exists for the tree (Ghidra
  does not dump its AST); it becomes possible in M2 through `.sla`
  output.

## 8. Commits

`git log --oneline master..HEAD` at the checkpoint (this file's own commit
comes last):

    3474283 test(sleigh-syntax): precedence of every operator pair, statement and operand forms
    d213bbc feat(sleigh-syntax): modal lexer, AST and recursive-descent parser
    692cc4d feat(sleigh-syntax): preprocessor with source map, ported Ghidra preprocessor tests
