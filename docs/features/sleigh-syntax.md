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
| `G/SleighLexer.g`, `BaseLexer.g`, `DisplayLexer.g`, `SemanticLexer.g`, `SleighParser.g`, `DisplayParser.g`, `SemanticParser.g`, `BooleanExpression.g`, `README.txt` | The **Java/ANTLR front end**: a modal lexer (base, display and semantic modes switched by the parser) and a parser that builds an AST **without consulting a symbol table**. `SleighCompiler.g` is the tree walker that resolves symbols afterwards. **This is the model for basilisk's AST.** |
| `SM/ghidra/sleigh/grammar/` (`SleighPreprocessor`, `ConditionalHelper`, `ExpressionEnvironment`, `Location`, `LocationUtil`, `SourceFileIndexer`, `LineArrayListWriter`, …) | The Java preprocessor and the source-location bookkeeping |
| `CPP/slghscan.l` | The **C++ lexer and preprocessor**: start states for the display section, semantic section, pattern section and macro bodies; the preprocessor (`@define`, `@undef`, `@include`, `@ifdef`, `@ifndef`, `@if`, `@elif`, `@else`, `@endif`, `$(NAME)` expansion). Its tokens depend on symbol-table lookups, which basilisk's parser does not do |
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
(`\b` location markers) and re-reads them in the lexer; basilisk keeps a
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

(The implementing agent appends further differences here, including any
inputs the Java and C++ front ends treat differently.)

## 9. Status

Not implemented yet.
