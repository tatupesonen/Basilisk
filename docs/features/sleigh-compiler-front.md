# SLEIGH compiler, part 1: symbols, constructors, p-code templates, checks (`bk-sleigh-compiler`)

Track `sleigh-compiler-front`, milestone M2. Starts when `sla`
(`features/sla.md`) is merged; runs in parallel with the runtime tracks
(disjoint crates). Part 2 (`features/sleigh-compiler-back.md`) follows in
the same crate. Format of this document: `docs/LOOP.md`. Background this
spec relies on and does not repeat: `docs/inventory/01-sleigh.md`
sections 1, 2, 9, 10 (d) and 10 (c.5); `docs/features/sleigh-syntax.md`
and `docs/agents/sleigh-syntax.md` ("Follow-ups for the SLEIGH compiler").

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`
under `../ghidra`; `REF` = `../reference`.

## 1. Purpose

Take the syntax tree `bk-sleigh-syntax` produces and give it meaning:
resolve every name, lay out the context register, build the tables and
constructors with their display pieces, operands and context changes,
compile every semantic section into p-code templates, expand macros,
check sizes and optimise the templates — everything a compiled language
contains except what is derived from the bit patterns (operand offsets
and order, decision trees), which is part 2.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/slgh_compile.cc`, `slgh_compile.hh` | `SleighCompile` (definitions, `with`, constructors, macros, sections, `finalizeSections`, unique offsets, `checkNops`, `checkCaseSensitivity`, `checkLocalCollisions`), `ConsistencyChecker`, `MacroBuilder`, `WithBlock`, `SectionVector` |
| `CPP/slghparse.y`, `slghscan.l` | Which action each construct triggers and in what order; how identifiers are classified; where the context layout is locked |
| `CPP/pcodecompile.cc`, `pcodecompile.hh` | `PcodeCompile`: expression and statement templates, temporaries, labels, bit ranges, size propagation |
| `CPP/slghsymbol.cc` | `SymbolTable` (ids, scopes, `replaceSymbol`, `purge`, `renumber`), `Constructor::addSyntax`, `getVarnode` of each symbol, `calc_maskword`, `ContextOp::validate` |
| `CPP/semantics.cc` | `ConstructTpl::fillinBuild`, `VarnodeTpl::transfer`/`adjustTruncation`, `ConstTpl::transfer` |
| `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/pcodeCPort/**`, `…/antlr/…/SleighCompiler.g` | The Java twin; consult where the C++ is undefined |

**C++ is authoritative** from the tree onward (it is the runnable
oracle). Front-end (syntax) decisions are `bk-sleigh-syntax`'s.

## 3. Scope

**In.** Crate **`bk-sleigh-compiler`** (new, owned by this track), the
part that ends with an *elaborated specification*: spaces, the symbol
table with final ids, tables and constructors (display, operands with
their definitions, context changes, source positions), templates for
every section after macro expansion, size checks, truncation fix-up,
optimisation and the crossbuild shift; the diagnostics of all of this;
a public template builder reusable for p-code snippets.

**Not in.** Pattern equations → patterns, operand offsets, minimum
lengths, operand reordering, decision trees, the pattern diagnostics,
writing the `.sla`, the command line (`sleigh-compiler-back`). The
syntax (`bk-sleigh-syntax`; this track may not change it — report gaps to
the coordinator, per `docs/agents/RULES.md`).

Dependencies: `bk-sleigh-syntax`, `bk-sla` (model value types, the file
model for comparison in tests), `bk-core`, `bk-pcode`; dev: `bk-testkit`.

## 4. Behaviour

Inventory section 9 is normative: definitions (9.3), `with` (9.4),
constructors (9.5), templates (9.6), macros (9.7), finishing sections
(9.8), unique offsets (9.9), purge (9.10); section 10 (d) for the
consistency checker and 10 (c.5) for collisions. What this section adds
is what a tree-based implementation must take care of.

### 4.1 Order is part of the output
Symbol ids and temporary offsets are assigned as a side effect of
Ghidra's single parsing pass and are written to the file. The elaborator
therefore walks the tree in **source order**, and inside one constructor:
display section left to right (operands created); pattern section left
to right (invisible operands created, operands defined); context block;
semantic sections in order, statements in order, and inside an
expression **post-order, left operand first** (a temporary is allocated
when an operator is reached, after its operands; `export *[sp]:n v`
allocates its temporary when the `export` is reached; `name = expr`
allocates after `expr` and creates the symbol after that). Macro
expansion and its extra temporaries (inventory 9.7) happen when the
constructor's sections are finished, i.e. after all its statements.

Name resolution is positional: a name refers to what is defined **at
that point** of the walk (inventory 9.2); the lexer-driven distinctions
the C++ grammar makes — for instance an identifier in a pattern being an
operand of this constructor, a global field, a table, or unknown — are
made by looking the name up in the scope chain at that point.

One corner is **[unverified]**: a `with` header's pattern is parsed
before any constructor of the block exists, yet the grammar action for a
table or field atom there (`defineInvisibleOperand`) adds an operand to
"the current constructor" — whichever was compiled last. No shipped
specification was checked for such a header; the differential test of
6.2 decides, and the implementer reads `SleighCompile::pushWith` and
`defineInvisibleOperand` (`CPP/slgh_compile.cc` 3044-3070, 3676) if a
`with` pattern containing a table name or a bare field turns up.

Context fields become symbols when the layout is locked: at the first
constructor, `attach` or `with` in source order (inventory 9.3). Their
ids therefore follow those of everything defined before that point and
are in (register name, low bit) order.

### 4.2 Display sections
The syntax tree keeps display pieces and white space separately
(`sleigh-syntax.md` §8 departure 9). Apply `Constructor::addSyntax`
exactly (inventory 9.5); `crates/bk-sleigh-syntax/tests/reference/ast_side.rs`
is a working reference that already agrees with Ghidra for all 131,955
shipped constructors — move its logic here, do not depend on test code.

### 4.3 Integers
Literals wider than 64 bits are "Parsed integer is too big (overflow)"
(C++ `BADINTEGER`); `IntLit::to_u64()` decides. Arithmetic on offsets,
sizes and bit positions is done in the widths the C++ uses (`uintb` =
`u64`, `uint4` = `u32`, `int4` = `i32`) with wrapping where the C++
wraps and a diagnostic where a value cannot be represented in the file.

### 4.4 Diagnostics
Every error and warning of inventory sections 9 and 10 (d), 10 (c.5),
with Ghidra's message text. A diagnostic carries the span of the
construct it is about (Basilisk's own, better than Ghidra's "current
lexer line"), a severity and the text. Rendering as Ghidra prints them
(`FILE:LINE - ERROR TEXT`, `WARN  TEXT`) is part 2's command line.
Elaboration continues after an error wherever the C++ does (it reports
many errors in one run), bounded by `bk-sleigh-syntax`'s error limit;
nothing is produced when any error occurred. Options that change
diagnostics: `-u`, `-c`, `-n`, `-t`, `-e`, `-s` (inventory 9.1).

Ghidra's unrecoverable errors in this half (thrown `SleighError`s that
abort the compile: "Read of temporary before write", "Could not recover
varnode template size", "Subtable out of order", "Bad constant type as
varnode template size", `Localtemp size mismatch`, …) are ordinary
errors here; the compile fails either way.

### 4.5 Hostile and degenerate input (ADR-009)
A specification is untrusted text. Bounded: number of symbols and scopes
(the `.sla` limits), macro expansion (a macro can only use macros
defined before it, so depth is bounded by definition order; expansion
size is capped at 1,000,000 ops per section with an error), size
propagation (terminates by construction; assert the loop bound),
optimisation passes per constructor (each pass removes an op), context
size (1,024 words). No recursion on tree depth beyond what the parser
already bounded.

### 4.6 Platforms (ADR-022)
The elaborator sees no files: sources arrive through
`bk-sleigh-syntax`'s `FileLoader`. Source-file names recorded for
constructors are **base names** taken with `Path::file_name`, so the
result does not depend on directory separators, the current directory or
absolute paths. Line endings are the lexer's concern (`\r` is white
space); part 2 tests CRLF end to end.

## 5. Design

* Modules: `symbols/{table, scope, kinds}`, `define/{space, varnode,
  token, context_layout, attach, userop, bitrange}`, `ctor/{display,
  pattern_atoms, context_block, with, sections}`, `pcode/{builder, expr,
  stmt, bitrange, labels, sizes}`, `macro`, `check/{sizes, truncation,
  optimize, temps, collisions, nops, case}`, `unique`, `purge`, `diag`,
  `elaborated` (the result type), `options`.
* The compiler's working IR is its own: owned, mutable templates
  (`Vec` of ops with `bk_sla::VarnodeTpl`/`ConstTpl` values), symbols in
  an arena with typed ids, pattern equations kept as resolved trees for
  part 2. It is lowered to `bk_sla` at the end of part 2; this track
  provides a lowering of everything it owns for its tests.
* **The template builder is public** (`pcode::Builder` over a `trait
  SymbolResolver`): given a parsed semantic body
  (`bk_sleigh_syntax::parse_semantic_body`) and a resolver that answers
  "what is this name here" and "allocate a temporary", it produces a
  template. The constructor elaborator is one client; `bk-sleigh-snippet`
  is the other. Its API is frozen when this track merges.
* Performance: one walk; no quadratic behaviour in the number of
  constructors (the C++ `force_size` scans the section per assignment —
  keep its results, not necessarily its cost). Budget in section 6.

## 6. Tests

### 6.1 Ghidra tests to port
* `docs/inventory/tests/framework-softwaremodeling.md`:
  `ghidra.pcodeCPort.slghpatexpress.EqualEquationTest` (unit, 3 tests) —
  part 2 (it tests a pattern-equation helper).
* None of Ghidra's tests exercises this half alone; the compile tests
  (`SleighCompileRegressionTest`, `SleighCompileOptionsTest`) are ported
  in part 2. The independent check here is 6.2.

### 6.2 Differential test against Ghidra's compiled files — all 150 specs
For each `.slaspec` (compiled with its module's options, which
`bk-testkit` knows), elaborate with Basilisk, lower to the comparison
form, and compare with the reference `.sla` read through `bk_sla`. The
two sides are put in a **canonical form keyed by operand symbol id**,
because Ghidra's file has operands reordered by part 2's algorithm:
wherever the file refers to an operand by position (`opprint`,
`const_handle`, `BUILD`, `operand_exp.index`), the position is replaced
by that operand's symbol id through the constructor's `oper` list.
Compared and required equal:

1. Header: endianness, alignment, `uniqbase`, `maxdelay`, `uniqmask`,
   `numsections`; source-file table; spaces.
2. The symbol table: scope count and parents; for every symbol its id,
   name, scope and kind — **all ids must agree**, which pins the
   elaboration order and the purge.
3. Symbol contents: user-op indices; varnodes; value, value-map, name and
   varnode-list symbols with their field expressions and tables; context
   symbols (`varnode`, `low`, `high`, `flow`, field); for operand symbols
   the defining symbol or expression, and `code`.
4. Per table: the number of constructors; per constructor `first`,
   `source`, `line`, the *set* of operand ids, the print pieces, the
   context changes in order (expressions included), and for the main and
   each named section the complete template (attributes, export handle,
   every op and varnode constant).

Not compared in this track (part 2's): constructor `length`; operand
`off`, `base`, `minlen`, `index` and order; everything under `decision`.

The comparison reports through `bk_sla::diff`-style paths, so a failure
names the table, constructor (file:line) and position. Tolerated
differences: **none**. A mutation check is part of the track's report
(for example: allocate the export temporary before the expression; swap
operand evaluation order; skip the context-layout sort — each must fail
the test).

### 6.3 Diagnostics against Ghidra's compiler
`tests/diagnostics/`: small hand-written specifications, at least one per
message of this half (the test holds the list of message patterns from
inventory 9 and 10 (d) and fails if one has no case). Each is compiled by
`REF/bin/sleigh` with the same options and by Basilisk; required equal:
success or failure, and the multiset of (severity, message text) —
Ghidra's location prefix is stripped, because Ghidra reports many
messages at the lexer's current line. Where Ghidra aborts with
"Unrecoverable error" and Basilisk reports an ordinary error, the case
lists that as expected. The warnings of the 150 shipped specs are
compared in part 2 (they need the whole pipeline).

### 6.4 Derived, property, fuzz, benchmark
* Unit tests for each definition form, the context layout (overlapping
  fields, word bumping, several registers, sort stability), `attach`
  replacement, `with` nesting (table inheritance from the outermost
  block, pattern and context order), every statement and expression form
  of inventory 9.6 with its template as an `insta` snapshot in the XML
  form, bit ranges in both endiannesses, macros (label offsetting,
  parameter transfer, truncation of a temporary argument), size
  propagation fix-point, every `sizeRestriction` rule, the optimiser's
  two rewrite forms and their interference rules, the crossbuild shift.
* `proptest`: generated semantic bodies never panic the builder; for
  generated straight-line bodies over fixed-size registers, the template
  has no zero-size varnode after propagation.
* Fuzz target `bk_sleigh_compiler_elaborate` in the shared `fuzz/` crate
  (bytes → `parse_str` → elaborate); 60 s without a finding.
* Benchmark: parse + elaborate x86-64, AARCH64, and all 150; recorded in
  `PERF.md`. The whole-compiler budget is part 2's (at least as fast as
  the reference: 11.5–11.8 s for all 150 one at a time); this half must
  leave room: all 150 in under 4 s on the `PERF.md` machine.

## 7. Acceptance

1. 6.2 passes for all 150 specifications with no tolerated difference;
   the mutation check is reported.
2. 6.3 passes with every message of this half covered.
3. 6.4 passes; fuzz target 60 s clean; the benchmark figure is met.
4. `pcode::Builder` and `SymbolResolver` are documented public API with a
   test that drives them without a constructor (the snippet use).
5. Gate green on macOS; `cargo check --target x86_64-pc-windows-msvc`
   passes; tests that need neither `REF` nor the Ghidra tree pass on all
   three systems in CI.

## 8. Differences from Ghidra

* A tree is elaborated in Ghidra's order instead of acting inside a
  parser; diagnostics carry real spans.
* Ghidra's unrecoverable errors of this half are ordinary errors.
* Limits of 4.5.

(The implementing track appends.)

Appended by the implementing track (2026-11-14):

* **Where Ghidra's compiler dies, Basilisk reports and goes on.**
  `constrainOperand` returns a null equation for "Constraining currently
  undefined operand", which the grammar then combines with `&` (Ghidra
  crashes); `expandMacros` deletes the macro placeholder and returns
  without replacing the op list after an expansion error, leaving a
  dangling op (Ghidra dies of a memory error after "Cannot currently
  assign to bitrange of macro parameter that is a temporary"). Basilisk
  abandons the constructor in the first case and reports "Could not expand
  macros" with the usual "in table …" lines in the second. The diagnostic
  test lists both (`GHIDRA_CRASHES` in `tests/diagnostics.rs`) and checks
  that everything Ghidra printed before dying is reported.
* **Unrecoverable errors stop the elaboration** at the point Ghidra
  aborts ("Localtemp size mismatch", "Read of temporary before write",
  "Requested bit range out of bounds", "No register attached to: N",
  "Context field not contained within one machine int", …); they are
  ordinary errors with Ghidra's text, without "Unrecoverable error: ".
* **Errors that come from a name's token class** (an unknown name in a
  pattern, a table name where a varnode is expected, …) are reported as
  Ghidra's "syntax error" at the construct, and the constructor is
  abandoned. Ghidra's parser recovers at the next `}`, which after an
  `unimpl` constructor can swallow following constructors; Basilisk
  resumes at the next item, so later diagnostics can differ in such
  files.
* **Operand collisions**: a table already visited while collecting one
  operand's exported temporaries is not entered again. The set of offsets
  is the same; Ghidra would recurse forever on a table that exports its
  own operand.
* **A `BUILD` of an operand index the constructor does not have** (only
  possible through a macro parameter) is "Unnecessary BUILD statements";
  Ghidra indexes out of bounds.
* **Masks of bit ranges wider than 64 bits** are computed with the shift
  count taken modulo 64 (x86-64's result, ADR-021) where the C++ shift is
  undefined; such ranges are errors anyway unless they truncate to whole
  bytes, where the mask is unused.
* **Reachability stands in for "has a pattern"** in this half: the purge
  and the "Unreferenced table" warnings use the tables reachable from
  `instruction` through operands defined by tables, which is exactly the
  set `buildPatterns` gives a pattern when it succeeds. The back half's
  pattern errors stop the compile before the purge in Ghidra; in Basilisk
  they will stop it after this half has run.
* **Limits** (4.5): 2^24 symbols, 2^20 scopes, 1,000,000 ops per section
  after macro expansion, 1,024 context words, 1,000,000 errors ("Too many
  errors: Aborting", Ghidra's limit). Each breach is an error.
* **Messages this half cannot produce.** "Duplicate symbol name 'N'"
  (a section name is looked up first, so it is never new and taken),
  "Superfluous bitrange" and "Problem with bit range operator in macro"
  (their conditions cannot hold after the checks that precede them),
  "Could not construct requested bit range" (a varnode with a real offset
  always has a real size), "Expression has no output", and "Unknown
  pointer varnode" (Ghidra's parser reduces the name to an assignment
  target first and reports "Unknown assignment varnode", which Basilisk
  does too). "Expecting integer but saw", "Must specify an indirect
  parameter for return" and the "redefined" forms of a single
  unbracketed name are found by `bk-sleigh-syntax` before elaboration.

## 9. Status

Done (2026-11-14), branch `sleigh-compiler-front`. Crate
`crates/bk-sleigh-compiler`, modules: `compiler/` (the walk: definitions,
context layout, attach, constructors, display, pattern atoms and context
blocks, `with`, sections, macros, finalize, the resolver), `pcode/` (the
public builder over `SymbolResolver`, expressions, statements, bit ranges,
size propagation, snippets), `check/` (sizes, truncations, optimisation,
collisions, crossbuild shift, NOPs, case check, cross references),
`symbols/`, `template`, `pattern`, `purge`, `elaborated`, `canon`,
`options`, `diag`.

* 6.2: all **150 of 150** shipped specifications equal the reference
  `.sla` in every compared category (header and spaces, scopes, every
  symbol id, name, scope and kind, every symbol's contents, print pieces,
  context changes, every template). Mutation check: swapping operand
  evaluation order (templates of 133 specifications differ), allocating
  the export temporary at the start of the section (82 fail), skipping the
  context-layout sort (18 fail on symbols and context changes).
* 6.3: 92 cases in `tests/diagnostics/`, every message of this half that
  can occur (list in the test), equal to `REF/bin/sleigh` in success and
  the multiset of messages; two listed Ghidra crashes.
* 6.4: 16 feature fixtures with `insta` snapshots, each also compared
  with Ghidra's compiled file when the reference tools are present (all
  equal); 2 property tests; fuzz target `bk_sleigh_compiler_elaborate`
  60 s clean (216,321 runs); benchmark: all 150 parsed and elaborated in
  1.03 s (budget 4 s), `docs/PERF.md`.
* The builder is driven without a constructor in
  `tests/features.rs::snippet_builder_without_a_constructor`.

Gaps: none against section 7 known to the track; see the status report
(`docs/agents/sleigh-compiler-front.md`) for what was verified on which
platform.
