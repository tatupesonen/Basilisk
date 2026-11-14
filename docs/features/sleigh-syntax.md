# SLEIGH syntax: preprocessor, lexer, parser (`bk-sleigh-syntax`)

Track `sleigh-syntax`, wave 1, milestone M0 (front end of M2). Format of
this document: `docs/LOOP.md`, "Feature documents".

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`SM/` = `Ghidra/Framework/SoftwareModeling/src/main/java/`,
`G/` = `Ghidra/Framework/SoftwareModeling/src/main/antlr/ghidra/sleigh/grammar/`,
`SMT/` = `Ghidra/Framework/SoftwareModeling/src/test/java/`, all under
`../ghidra`. The language manual is
`GhidraDocs/languages/html/sleigh*.html` (or the `.xml` beside it).

## 1. Purpose

SLEIGH is the language Ghidra's processors are specified in. This crate
turns `.slaspec` source (and its `.sinc` includes) into a syntax tree with
exact source locations. The SLEIGH compiler (milestone M2) builds on it;
so can tooling such as formatters and editors.

## 2. Ghidra sources

Ghidra has two front ends, and they are shaped differently:

| Source | What it is |
|---|---|
| `G/SleighLexer.g`, `BaseLexer.g`, `DisplayLexer.g`, `SemanticLexer.g`, `SleighParser.g`, `DisplayParser.g`, `SemanticParser.g`, `BooleanExpression.g`, `README.txt` | The **Java/ANTLR front end**: a modal lexer (base, display and semantic modes switched by the parser) and a parser that builds an AST **without consulting a symbol table**. `SleighCompiler.g` is the tree walker that resolves symbols afterwards. **This is the model for Basilisk's AST.** |
| `SM/ghidra/sleigh/grammar/` (`SleighPreprocessor`, `ConditionalHelper`, `ExpressionEnvironment`, `Location`, `LocationUtil`, `SourceFileIndexer`, `LineArrayListWriter`, …) | The Java preprocessor and the source-location bookkeeping |
| `CPP/slghscan.l` | The **C++ lexer and preprocessor**: start states for the display section, semantic section, pattern section and macro bodies; the preprocessor (`@define`, `@undef`, `@include`, `@ifdef`, `@ifndef`, `@if`, `@elif`, `@else`, `@endif`, `$(NAME)` expansion). Its tokens depend on symbol-table lookups, which Basilisk's parser does not do |
| `CPP/slghparse.y` | The C++ grammar. Use it as the precise statement of what is legal and of operator precedence |
| `SM/ghidra/pcodeCPort/slgh_compile/SleighCompileLauncher.java`, `SleighCompileOptions.java` | How defines reach the preprocessor from the command line (`-D name=value`) and from module paths |
| `SMT/ghidra/sleigh/grammar/` | The tests (section 6) |

Both front ends accept the same language (Ghidra ships `.sla` files built
by the Java compiler and its decompiler tests use the C++ one). Where they
differ on an input, note it and follow the Java front end, which is what
Ghidra's build uses.

## 3. Scope

**In:** preprocessor; lexer; parser; AST; source locations; diagnostics.
**Crate owned:** `bk-sleigh-syntax`. It has **no dependency on other
`bk-*` crates** (do not depend on `bk-core`, `bk-marshal` or `bk-pcode`,
which other tracks are writing in this wave; p-code operator names in the
AST are syntax, not opcodes).

**Not in this track:** symbol resolution, type and size checking, pattern
resolution, decision trees, p-code template construction, `.sla` output —
all M2 (`bk-sleigh-compiler`). The p-code snippet parser used for
injection (`CPP/pcodeparse.y`) is M1; design the semantic-section parser
so it can be reused for it (it is the same statement language without
constructors).

## 4. Behaviour

*Corrections from the track's reading of both front ends (2026-11-12),
which override the text below where they differ: directives must start in
column one (no leading whitespace); an unclosed conditional at end of file
is accepted silently (`ARMv8.sinc` relies on it); `!` in `@if` applies only
to a parenthesised expression; `0n` integers exist only in the Java front
end and only as semantic operands; an expanded `$(NAME)` value starts a new
token (eight ARM specs depend on it).*

### 4.1 Preprocessor
Line-oriented, run before lexing. Directives start with `@` at the start
of a line (after optional whitespace) — take the exact forms from the
regular expressions at the top of `SleighPreprocessor.java`:

- `@include "file"` — path relative to the including file's directory;
  include depth is bounded (report a cycle as an error, do not recurse
  forever).
- `@define NAME "value"`, `@define NAME value`, `@define NAME` (empty
  value); `@undef NAME`.
- `@ifdef NAME`, `@ifndef NAME`, `@if expr`, `@elif expr`, `@else`,
  `@endif`, nested. The expression language is `BooleanExpression.g`:
  `defined(NAME)`, `NAME == "str"`, `NAME != "str"`, comparisons between
  names, `!`, `&&`, `||`, `^^`, parentheses — implement exactly what the
  grammar and `ExpressionEnvironment` define, including how undefined
  names behave. Handling of skipped regions (`ConditionalHelper`): which
  directives are still interpreted while skipping.
- `$(NAME)` expands to the definition's value anywhere in a non-directive
  line; an undefined name is an error with the location.
- Definitions may be supplied from outside (command-line `-D`, and Ghidra
  passes one definition per module mapping the module name to its
  directory so specs can include across modules). The API takes an initial
  definition map.
- Comments (`#` to end of line) and how they interact with directives and
  strings.

Every output line must keep its origin: file, line, and the include chain.
Ghidra threads this through as marker lines in the preprocessed text
(`\b` location markers) and re-reads them in the lexer; Basilisk keeps a
line map beside the text instead (or lexes straight from the include
stack) so every token carries a `(file, line, column)` span that points
at the original source. `SourceFileIndexer` shows what the compiler later
needs from this: a stable index per source file.

### 4.2 Lexer
Modal, as the ANTLR lexers are. The modes and where they switch:

- **Base**: definitions (`define endian`, `define alignment`, `define
  space`, `define register`/varnode, `define token`, `define context`,
  `define bitrange`, `define pcodeop`, `attach variables|names|values`),
  `macro` headers, `with` blocks, constructor heads.
- **Display**: from the `:` after a table name (or the bare `:` of a
  root constructor) up to the keyword `is`. Whitespace is significant
  here, `^` concatenates, quoted strings are literal, and most
  punctuation is literal print text. Get this from `DisplayLexer.g` and
  the `print` start state in `slghscan.l`.
- **Pattern / context**: after `is` — bit-pattern equations with `&`,
  `|`, `;`, `...`, parentheses, constraints (`=`, `!=`, `<`, `>`, `<=`,
  `>=`) and pattern expressions; then the optional `[ ... ]` context
  block (assignments and `globalset`).
- **Semantic**: inside `{ ... }` — the p-code statement language:
  assignments, `local` declarations, `*[space]:size` dereference, `&`
  address-of, bit ranges `x[lsb,len]`, truncation `x:size` and `x(n)`,
  `goto`/`call`/`return`, `if (cond) goto`, labels `<name>`, `build`,
  `crossbuild`, `export`, `unimpl`, named sections `<<name>>`, user-op
  and macro calls, and the full operator set (integer, signed `s`-prefixed
  and float `f`-prefixed operators, boolean, comparisons) with the
  precedence and associativity of `SemanticParser.g`/`slghparse.y`.

Integer literals: decimal, `0x` hex, `0b` binary, arbitrary width (the
Java uses `RadixBigInteger` and remembers the radix; keep both the value
and the radix). Identifiers may contain `.` and `_`; check the exact
character sets per mode. Keywords are contextual: several are ordinary
identifiers outside the position where they are meaningful.

### 4.3 Parser and AST
The parser produces a tree without a symbol table: identifiers stay
identifiers, and the compiler decides later whether one is a register, a
field, a table or a macro. The tree covers everything `SleighParser.g`
and its imports produce:

- the endian definition (must come first), alignment, spaces (with
  `type`, `size`, `wordsize`, `default`), varnode definitions (`offset`,
  `size`, name list with `_` placeholders), bit ranges, tokens and their
  fields (`signed`, `hex`, `dec`, endianness), context definitions (with
  `noflow`), p-code op declarations, the three `attach` forms;
- macros (name, parameters, body);
- `with` blocks (table, pattern prefix, context prefix, nested);
- constructors: table, display pieces, pattern equation, context changes,
  the semantic body with named sections, or `unimpl`.

Every node carries its span. The AST is plain owned data (enums and
structs), cheap to walk, with no interior mutability. Identifiers and
strings are interned or borrowed so that parsing the largest specs does
not allocate per token.

### 4.4 Diagnostics
Errors carry a span and a message, and parsing continues after an error
to the next definition or constructor so that one run reports many
errors, as Ghidra's does. Where a Ghidra test or commonly seen message
fixes the wording, use Ghidra's wording; otherwise write clear messages.
No input may panic or loop (ADR-009): unterminated strings, unbalanced
braces, runaway includes and absurd nesting all end in diagnostics.

## 5. Design

- Hand-written lexer and recursive-descent parser (Pratt parsing for
  semantic and pattern expressions) is the expected choice: the modal
  lexing is driven by the parser, error recovery and spans are easier,
  and it is fast. A parser-generator crate may be adopted instead if it
  passes ADR-011; record the evaluation.
- Modules: `preprocess/{directive, expr, expand, include, linemap}`,
  `lex/{base, display, pattern, semantic, token, literal}`,
  `parse/{definitions, constructor, display, pattern, context, semantic,
  expr}`, `ast/{…}`, `span`, `diag`, `intern`.
- Public API sketch: `parse_file(path, &Defines, &mut dyn FileLoader) ->
  (Spec, Vec<Diagnostic>)`, `preprocess(...)` on its own, and
  `parse_semantic_body(...)` on its own for later reuse. File access goes
  through a trait so tests and tools can supply sources from memory.
- Performance: one pass, no backtracking over more than a few tokens;
  budget and benchmark below.

## 6. Tests

- **Port** `ghidra.sleigh.grammar.BooleanExpressionTest` (31),
  `BooleanExpressionDefTest` (3), `SleighPreprocessorTest` (1, with its
  resource files — find them under `SoftwareModeling/src/test/resources`)
  and `SourceFileIndexerTest` (1); mark them in
  `docs/inventory/tests/framework-softwaremodeling.md`.
- **Corpus test:** all 150 `.slaspec` files under
  `../ghidra/Ghidra/Processors/*/data/languages` preprocess and parse with
  zero diagnostics (skips when `../ghidra` is absent). Supply the module
  definitions Ghidra would (read `SleighCompileLauncher` for what they
  are) if any spec needs them. Report the totals: files including
  includes, lines, constructors, tokens.
- **Golden tests:** the AST of small specs (`Toy` processor, and
  hand-written fragments for every construct in section 4), as readable
  snapshots under the crate's `tests/golden/`.
- **Derived tests:** each directive form; nested conditionals; every
  operator's precedence and associativity against `slghparse.y`; display
  sections with awkward whitespace and punctuation; each definition form;
  `with` nesting; error recovery (several errors in one file each
  reported with the right line, including inside includes).
- **Property tests and fuzz target:** the preprocessor and parser never
  panic or hang on arbitrary input; printing the token stream of a parsed
  body and re-parsing gives the same tree for generated expressions.
- **Benchmark:** preprocess and parse the largest specs (x86-64 with its
  includes, AARCH64, PowerPC); record lines per second and peak
  allocations in `PERF.md`. Target: the whole 150-spec corpus in under
  ten seconds on this machine, single-threaded.

## 7. Acceptance

1. The four Ghidra test classes pass in ported form and are marked.
2. The corpus test passes: every shipped spec parses with no diagnostics.
3. Spans are correct through includes and expansions (tested).
4. No panics; the fuzz target runs 60 seconds without a finding.
5. Gate green; files within the size limit; public items documented.

## 8. Differences from Ghidra

- Source locations are carried in a line map and token spans, not as
  marker lines in the preprocessed text.
- One front end (symbol-free AST) rather than two.

Appended by the implementing track (2026-11-12). "Java" is Ghidra's
ANTLR front end (`SleighPreprocessor`, `*.g`), the authority; "C++" is
`slghscan.l`/`slghparse.y`. Claims marked *(run)* were checked by running
Ghidra's C++ `sleigh` compiler on hand-written specifications
(`tests/reference_sla.rs`, `edge_cases_against_ghidras_cpp_compiler`); no
Java compiler was available, so Java behaviour is from reading its source.

**Deliberate departures**

1. Locations come from a `SourceMap` (one record per output line, per
   run of lines from one inclusion, and per `$(NAME)` expansion), not from
   marker lines. One U+0008 is written before each expanded value and
   skipped by the lexer, which keeps Ghidra's token boundary there
   (`export$(X)`, `is$(AMODE)` in eight ARM and MIPS specs).
2. Errors are collected and parsing continues; Ghidra's preprocessor
   aborts at the first error (Java exception, C++ `exit(1)`). An unknown
   `$(NAME)` is reported and expands to nothing.
3. A syntax error in an `@if`/`@elif` expression is an error and the
   condition is false (Java prints to stderr and carries on).
4. Files are decoded as UTF-8 when valid, otherwise ISO-8859-1 (Java always
   uses ISO-8859-1; seven shipped files have UTF-8 in comments). Columns
   count characters.
5. Include cycles, include depth (64), number of inclusions (10,000),
   preprocessed size (1 GiB, checked per expanded piece, so references
   multiplying a long value are caught within a line), integer literal
   length (4,096 digits), nesting depth (128) and error count (500) are
   bounded and reported (Ghidra overflows its stack or runs on). An
   included file is recognised by its loader identity (canonical path), so
   path spelling does not matter; include file-name case is not checked
   (Java's `existsAndIsCaseDependent`).
6. Nested unary operators (`- -x`, `!~x`) are accepted: C++ accepts them
   *(run)*, Java's grammar does not.
7. `define endian` missing or not first is reported and the rest is still
   parsed (`Spec.endian` is an `Option`).
8. An empty statement (`;`) is an error and parsing continues (Java aborts
   with "Empty statement"; C++ reports a syntax error *(run)*).
9. Leading whitespace after `:` is kept as a display piece; the compiler
   decides (Java treats only the very first piece specially, C++ skips
   leading spaces *(run)*).

**Where Java and C++ differ, and what is implemented (Java in each case)**

| Input | Java | C++ | Here |
|---|---|---|---|
| `a < b < c` | left-associative | syntax error *(run)* | left-associative |
| `0n12` operand in a semantic section | decimal 12 | syntax error *(run)* | decimal 12 |
| `0x10` in a display section | one literal piece | `0` and operand `x10` (error) *(run)* | one literal piece |
| `_`, `0n12`, `with` in a display section | not a print piece (error) | an operand, undefined (error) *(run)* | error |
| `"a\"b"` | backslash escapes, kept raw | syntax error *(run)* | accepted, kept raw |
| `@if !(defined(X))` | negation | no `!` (error) *(run)* | negation |
| `@if !defined(X)` | syntax error (`!` needs `(`) | error *(run)* | error |
| `@if` precedence | `\|\|` < `^^` < `&&` | left to right | Java |
| conditionals across files | per file | global | per file |
| `@if` left open at end of file | closed silently | closed silently *(run)* | closed silently |
| directive with leading whitespace | not a directive | not a directive *(run)* | not a directive |
| `0xg` (prefix without digits) | `0` then a name (reading of ANTLR's lookahead) | syntax error, consistent with `0` then `xg` *(run)* | `0` then a name |
| `define alignment` inside `with` | allowed | not allowed | allowed |

**Ghidra's build defines nothing.** `gradle/processorProject.gradle` passes
each module's `sleighCompileOptions`, and no shipped module sets `-D` or
`-d`. The corpus tests therefore preprocess with no definitions (an earlier
version passed every module name, which made HC05 and HC08 take their
HCS08 branches; the `.sla` comparison found it).

**Crate evaluations (ADR-011).** Figures from crates.io on 2026-11-12:
total downloads / recent (90 days) / reverse dependencies / newest version
and date.

Adopted:

* `string-interner` 0.20.0 (41.5M / 6.3M / 76 / 2026-04-30) for `Interner`
  and `SourceFileIndexer`: per-instance, symbols contiguous from 0 (the
  fixed keyword symbols rely on it; a unit test asserts it), custom hasher;
  wrapped so it is not in the public API. Rejected: `lasso` (14.9M / 3.8M /
  89; no release since 2024-08-19); `string_cache` (214M / 65M / 79), the
  most downloaded but a process-global atom table with build-script static
  atoms, which the no-global-state rule excludes; `internment` (16.6M /
  2.4M / 34) and `ustr` (4.6M / 1.7M / 95), also global.
* `rustc-hash` 2.1.3 (1,010M / 300M / 3,801 / 2026-07-02) as the
  interner's hasher.
* `num-bigint` 0.4.8 (741M / 211M / 2,599 / 2026-07-05) for literals wider
  than 64 bits; values up to 64 bits stay inline. Rejected as niche:
  `dashu-int` (6.1M / 3.3M / 32), `ibig` (0.96M / 0.15M / 39, 2022).
* Dev-dependencies: `proptest`, `rstest`, `insta` (goldens), `roxmltree`
  (reading the reference compiler's XML `.sla` in the differential test),
  `tempfile`; all already in the workspace.

Evaluated and not adopted (the lexer and parser are hand-written):

* Lexer: `logos` 0.16.1 (101M / 32.5M / 579). It could express the tokens
  and has a `forbid_unsafe` feature, but the three modes share all but
  about 20 tokens and logos cannot share definitions between token enums
  (three near-copies, or one enum plus a wrapper that splits `s<` back
  apart in base mode and `#…` comments in display mode); the parser must
  re-lex from an arbitrary offset when it switches mode; and identifiers
  are interned and expansion marks skipped inside the scanner. The
  hand-written scanner is about 320 lines.
* Parser: `winnow` 1.0.4/1.0.5 (1,163M / 370M / 465; error recovery only
  behind `unstable-recover`), `nom` 8.0.0 (886M / 228M / 2,631; no
  recovery), `pest` 2.9.6 (390M / 88M / 1,283; stops at the first error,
  untyped tree needing a second pass, no nesting guard), `lalrpop` 0.23.2
  (79.5M / 15.1M / 273; LR lookahead is fetched before an action can
  switch the lexer mode, the hazard Ghidra's grammar README describes;
  keywords-as-identifiers conflict in LR(1); heavy build dependencies),
  `chumsky` 0.13.0 (31.9M / 5.6M / 329; deep nesting relies on its
  `stacker` feature, a native stack-switching dependency, where this track
  needs an explicit depth limit). The spec requires parser-driven modes,
  per-construct recovery, bounded nesting and spans through the source
  map; recursive descent gives all four directly.
* Diagnostic rendering: `codespan-reporting` 0.13.1 (168M / 38.4M / 262),
  `miette` 7.6.0 (92M / 25.5M / 1,692), `annotate-snippets` 0.12.18 (72M
  / 30M / 179), `ariadne` 0.6.0 (14.6M / 4.7M / 345). Nothing was
  reimplemented: this crate returns structured diagnostics and a one-line
  `path:line:column: error: message` with the include chain;
  `SourceMap::source_range` gives the `(file, byte range)` a renderer
  needs. Snippet rendering belongs in the CLI/UI (`codespan-reporting` is
  the suggested choice).

## 9. Status

**Implemented (2026-11-12), track `sleigh-syntax`.** Crate
`crates/bk-sleigh-syntax`, no dependency on other `bk-*` crates, no
`unsafe`. Status report with the full detail: `docs/agents/sleigh-syntax.md`.

* Preprocessor (`preprocess/`), source map (`source/`), modal lexer
  (`lex/`, three modes chosen by the parser), symbol-free AST with typed
  arena ids (`ast/`, with an S-expression dumper and a printer back to
  SLEIGH), recursive-descent parser with per-construct recovery (`parse/`).
  Entry points: `parse_file`, `parse_str`, `parse_preprocessed`,
  `preprocess`, `parse_semantic_body` (the p-code snippet language for M1).
* All four acceptance items about the Ghidra tests, the corpus, spans and
  panics hold: the four Ghidra test classes are ported and marked; all 150
  shipped specs parse with no diagnostics; spans are tested through
  includes and expansions; the fuzz target ran without a finding.
* The tree is checked against Ghidra's own compiler: for every shipped
  spec, the reference C++ `sleigh -y` output agrees with the tree on
  constructors per table with file and line, print pieces and operands,
  pattern-expression shapes of operand definitions and context changes,
  `globalset` commits, `unimpl`, `export`, named sections, labels,
  varnodes and their offsets, token and context fields, attach lists, user
  ops and spaces (`tests/reference_sla.rs`). Semantic-section trees are not
  covered by that comparison (Ghidra stores compiled p-code, not the tree);
  they are covered by the precedence tables, the statement-form tests, the
  generated-expression property tests and corpus-wide token fidelity.
* Node sizes (asserted): `Expr` 72 bytes, `Statement` 88, `PatExpr` 32,
  `Equation` 36, `IntLit` 24. Whole corpus in 0.33 s (`docs/PERF.md`).

**Gaps.** The Java front end could not be run; where it and C++ differ,
Java's behaviour is implemented from reading its grammar and is not
confirmed by execution (section 8 marks what was run). `Severity::Warning`
is never produced. A constructor whose error recovery reaches the `}` of
an enclosing `with` block takes the rest of that block with it (as Ghidra's
`constructorlike: error '}'` rule does).
