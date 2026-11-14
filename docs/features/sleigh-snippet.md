# P-code snippets: compiling p-code text against a loaded language (`bk-sleigh-snippet`)

Track `sleigh-snippet`. Starts when `sleigh-compiler-front` is merged (it
uses that crate's public template builder) — in parallel with
`sleigh-compiler-back` and the runtime tracks (disjoint crates). Needed
by milestone M3 (prototype models and call fix-ups in `.cspec` files
carry p-code). Format of this document: `docs/LOOP.md`. Background:
`docs/inventory/01-sleigh.md` sections 1.7, 9.6 and 11 ("P-code
snippets"); `docs/features/sleigh-pcode.md` §4.5 (how a compiled snippet
is turned into p-code).

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`SM/` = `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/`, under
`../ghidra`; `REF` = `../reference`.

## 1. Purpose

Compiler and processor specifications embed small pieces of p-code
source — call fix-ups, `uponentry`/`uponreturn` injections, `CALLOTHER`
fix-ups, segment operators, jump-table helpers (132 `<pcode>` elements in
47 of the shipped `.cspec`/`.pspec` files [run]). They are written in the
semantic-section language of SLEIGH but compiled later, against an
already compiled language, into a template that the runtime expands at
the injection site. This crate is that compiler.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/pcodeparse.y` | `PcodeSnippet` (symbols visible to a snippet, `addOperand`, `allocateTemp`, `lex`, `parseStream`, error reporting) and the grammar: which statements and expressions a snippet may contain |
| `CPP/pcodecompile.cc` | The template construction shared with the SLEIGH compiler (already ported as `bk_sleigh_compiler::pcode::Builder`) |
| `CPP/inject_sleigh.cc` | `PcodeInjectLibrarySleigh::parseInject`: parameters, unique-offset bases, the error text |
| `SM/program/model/lang/PcodeParser.java`, `InjectPayloadSleigh.java` | The Java twin; `PcodeParserTest` |

**C++ is authoritative** (the decompiler's results depend on it).

## 3. Scope

**In.** Crate **`bk-sleigh-snippet`** (new, owned by this track):
`compile(text, &Sla, &[Parameter], &mut TempAllocator, &Options) ->
Result<bk_sla::Template, SnippetError>`; the symbol resolver for
snippets; a reference tool and its `bk-testkit` wrapper for the
differential test (section 6.2) — this track is assigned
`tools/reference/snippetdump.cc`, one build step in
`scripts/build-reference.sh`, and one module in `bk-testkit`.

**Not in.** Reading `.cspec`/`.pspec` and deciding which snippet applies
where (the decompiler's injection library, M3); expanding a template
into p-code (`bk-sleigh`, `build_template`); dynamic (Java-implemented)
injections.

Dependencies: `bk-sleigh-syntax` (`parse_semantic_body`),
`bk-sleigh-compiler` (template builder only), `bk-sla`, `bk-core`.

## 4. Behaviour

### 4.1 Names a snippet can use [verified: `pcodeparse.y` `PcodeSnippet::PcodeSnippet`, `lex`, `addOperand`]
Resolved in this order: the snippet's own symbols, then the language's
global scope.

* Own: one space symbol for each space of the language of type constant,
  processor, spacebase or unique, by the space's name; `inst_dest` and
  `inst_ref` (they resolve to `const_flowdest` / `const_flowref` address
  constants, with their `_size` companions where an address size is
  needed); each parameter as an operand symbol with its given handle
  index; labels and local temporaries defined in the snippet.
* From the language: user ops, varnode symbols (registers), `inst_start`,
  `inst_next`, `inst_next2`. **Every other kind of language symbol is
  invisible** (fields, tables, context symbols, …) and reads as an
  unknown name.

### 4.2 Statements and expressions [to verify against the grammar of `pcodeparse.y`, lines 1–270, before the track starts]
The statement language of inventory 9.6 without what needs a constructor:
no `build`, `delayslot`, `crossbuild`, macros, named sections or
`export`. Expected from `PcodeParserTest` and the shipped snippets:
assignments (with `local`, sizes, bit ranges), loads and stores, user-op
calls, `goto`/`call`/`return` with fixed, indirect, `inst_*` and label
destinations, `if … goto`, labels. The implementer lists the grammar's
productions in the feature doc's status and rejects the rest with
Ghidra's syntax-error behaviour.

### 4.3 Temporaries [verified: `pcodeparse.cc:3133`, `inject_sleigh.cc:377, 422-465`]
A snippet's temporaries are allocated from a caller-supplied base in
steps of **16** (not 256 as in the SLEIGH compiler). The decompiler's
library starts the base at `uniqbase + 0x200` (`UniqueLayout::INJECT`)
and carries it from one snippet to the next, so no two snippets share a
temporary; executable p-code (`EXECUTABLEPCODE_TYPE`) always starts at
0x2000. `TempAllocator { next, step }` models this; the step is an option
because Java uses 0x100 (`PcodeParserTest` expects `uniqueBase +
n·0x100`).

### 4.4 Result and errors
The result is an owned `bk_sla::Template` (label count set; no export)
after the same finishing steps as a constructor section where they
apply: label checks and size propagation (inventory 9.8, steps 1 and 4)
[to verify in `PcodeSnippet::parseStream`/`releaseResult` which of these
run and what happens to an unresolved size]. A failure is one error
carrying every message, to be reported by the caller as Ghidra does:
`<source>: Unable to compile pcode: <messages>`. Snippet text is
untrusted (ADR-009): same bounds as the compiler front half.

### 4.5 Platforms (ADR-022)
Pure computation on strings; nothing platform-specific. Line endings in
snippet bodies (they come from XML files that may be CRLF) do not change
the result.

## 5. Design

One module for the resolver (a small scope over an `&Sla`), one for the
driver. The builder is `bk_sleigh_compiler::pcode::Builder`; if its
public API lacks something a snippet needs, that is reported to the
coordinator rather than patched across crates.

## 6. Tests

### 6.1 Ghidra tests to port
* `docs/inventory/tests/test-integrationtest.md`:
  `ghidra.program.model.lang.PcodeParserTest` (slow, 1 tests). It loads
  the x86 32-bit language, adds operands `in1` (index 0) and `in2`
  (index 1), compiles
  `tmp:1 = inst_next; if (AX == 0) goto inst_next; tmp2:1 = inst_next2;
  if (BX == 0) goto inst_next2; call [ECX]; if (BX != 1) goto <lab>;
  CX = 0; <lab> BX = CX << 2; in1 = in2 + 7;`
  and asserts the template: no export, 1 label, 13 ops, and for each op
  the opcode and each varnode's constant kinds and values. Ported with
  step 0x100 (its literal expectations); needs only the reference
  `x86.sla` through `bk_sla`.
* `framework-emulation.md`: `SleighProgramCompilerTest` (3) and
  `SleighUtilsTest` (29) compile p-code *programs* for the emulator
  (`ghidra.pcode.exec`); they belong to the emulator (M6) and use a
  different front end (`SleighProgramCompiler`). Not here.

### 6.2 Differential test against Ghidra's snippet compiler
There is no existing oracle that shows a compiled snippet, so the track
adds one: `tools/reference/snippetdump.cc`, linked against the reference
build like `pcodedump`. It loads a language, reads snippet records from
standard input (a source name, the parameter names with indices, the
unique base to start from or "continue", the body), compiles each with
Ghidra's `PcodeSnippet`, and prints either the template as XML
(`ConstructTpl::encode` through `XmlEncode`) or the error text. Its
record format is documented in `tools/reference/README.md` like
`pcodedump`'s, with a version number.

The test extracts every `<pcode>` element (body text, `<input>` and
`<output>` names in order) from all `.cspec` and `.pspec` files of the
Ghidra tree with `bk-marshal`'s XML reader, assigns parameter indices in
order (inputs, then outputs), runs each language's snippets through the
tool and through Basilisk in the same order with the same starting base,
and requires **the same XML text** per snippet (`Template::encode_xml`),
or the same failure. Tolerated differences: none.

### 6.3 Derived, property, fuzz
Unit tests for each visible and invisible symbol kind, parameter
handles, `inst_dest`/`inst_ref`, temporaries continuing across snippets,
each statement form, each error. `proptest`: generated bodies never
panic. Fuzz target `bk_sleigh_snippet_compile` (bytes as the body,
against a fixture `Sla`); 60 s without a finding.

## 7. Acceptance

1. `PcodeParserTest` is ported and marked.
2. 6.2 passes for every `<pcode>` body in the tree (the test prints how
   many were compiled and how many Ghidra itself rejects).
3. 6.3 passes; fuzz target 60 s clean.
4. The [to verify] items of section 4 are resolved in the feature doc.
5. Gate green on macOS; `cargo check --target x86_64-pc-windows-msvc`
   passes; oracle-free tests pass on all three systems in CI.

## 8. Differences from Ghidra

Appended by the implementing track (2026-11-14). Behaviour follows Ghidra's
C++ `PcodeSnippet` everywhere it is defined; the oracle `snippetdump`
decides. What a user can meet:

* **Text past a NUL byte and very long tokens.** Ghidra's lexer copies a
  token into a 256-byte buffer without a bound check (`PcodeLexer::curtoken`,
  undefined behaviour past 255 characters); Basilisk reads any length. A NUL
  ends the text in both.
* **Limits** (ADR-009): a text over `Options::max_text_len` (1 MiB by
  default) is refused with `SnippetError::TooLong`; expressions nested more
  than `Options::max_depth` (1,000) levels fail with Ghidra's text "memory
  exhausted", which Ghidra's parser gives at a stack of 10,000 states (a
  different depth).
* **Every message is kept.** Ghidra keeps the first error only;
  `SnippetError::messages()` has all of them, the first being Ghidra's, and
  errors Ghidra reports but ignores on a successful compile are returned as
  `Compiled::warnings` (and logged at debug level).
* **Message order inside a failing statement** is Ghidra's for everything
  the tests exercise: Basilisk evaluates the expressions Ghidra's parser had
  reduced before failing, so their errors come first. Where Ghidra would
  have reduced a larger expression than Basilisk's precedence climbing, the
  difference adds only operators, which report nothing.
* **Bit ranges with values near 2³²** (`r[0,0xffffffff]`): Ghidra computes
  `(numbits+7)/8`, `bitoffset+numbits` and `byteoffset+numbytes` in 32-bit
  unsigned arithmetic, which wraps (`pcodecompile.cc` `createBitRange`,
  `assignBitRange`, `buildTruncatedVarnode`; the grammar casts both numbers to
  `uint4`, `pcodeparse.y` 114, 187); the shared builder of
  `bk-sleigh-compiler` does not wrap, so such a snippet can get a different
  template or error. Not a choice: a bug in that crate's builder, reported
  as a follow-up; 41 of 20,000 generated snippets hit it, none of the shipped.
* **Host-dependent number reading** (ADR-021): an octal literal holding an 8
  or a 9 (`09`, `0189`) reads as 0 quietly with libstdc++ (x86-64 Linux, the
  reference) and as a `BADINTEGER` ("Parsed integer is too big (overflow)",
  value 0) with libc++ (macOS), whose `num_get` fails when `strtoull` stops
  before the end of the collected digits. Basilisk gives the x86-64 result.
* **Extra address spaces** (`Options::extra_spaces`): Ghidra's snippets see
  every space of the program's space manager of type constant, processor,
  spacebase or internal at the time of the compile, including the `.cspec`'s
  stack space; Basilisk sees the `.sla`'s and the ones the caller adds.

Spec items this section corrects (spec text left as written):

* §4.2 The grammar is not the SLEIGH semantic section's: `PcodeSnippet` has
  its own lexer (`#` comments, `.` in names, a leading `0` means octal, a
  NUL ends the text, an unknown character ends the input) and grammar
  (productions in §9). `goto`/`call` destinations are `inst_*` symbols,
  integers, `k[space]` and labels — not operands or registers. Not
  available: `build`, `delayslot`, `crossbuild`, `export`, macros, sections,
  `cpool`, `newobject`, `popcount`, `lzcount`; `borrow` is a keyword without
  a rule.
* §4.1 `inst_dest`/`inst_ref` give `const_flowdest`/`const_flowref` with size
  0, never the `_size` constants.
* §4.4 Only size propagation runs: no label check (a label used but never
  placed compiles; placing one twice is an ignored error); the failure
  message is the first error of the whole compile; errors of the builder
  that do not stop Ghidra's parser (bit-range problems, integer overflow,
  duplicate parameter names) do not fail the compile; `SleighError`s thrown
  by `PcodeCompile` ("Requested bit range out of bounds", "Could not
  construct requested bit range", "Localtemp size mismatch") escape
  `parseInject` bare, without `<source>: Unable to compile pcode:`
  (`SnippetError::Aborted`).
* §1/§6.2 The shipped trees hold **137** snippet elements outside XML
  comments (130 `<pcode>` and 7 jump-table `*_pcode`) in 49 files; the
  count of 132 included two commented-out elements of `x86win.cspec` and
  left out the jump-table elements. 16 are dynamic payloads without a body,
  which Ghidra never compiles.
* §6.2 The tool's record format and the `<truncate_space>` handling are in
  `tools/reference/README.md`; languages with `<truncate_space>` (AARCH64
  ilp32, MIPS 64-32addr, PowerPC 64-32) need `Options::truncate_space`.

## 9. Status

Done (track `sleigh-snippet`, 2026-11-14). Crate `bk-sleigh-snippet`:

* `SnippetCompiler::new(&Sla, &Options)` (visible names and spaces computed
  once; `Send + Sync`), `compile(text, &[Parameter], &mut TempAllocator) ->
  Result<Compiled, SnippetError>`; `compile(text, &Sla, &[Parameter], &mut
  TempAllocator, &Options) -> Result<Template, SnippetError>` as the spec's
  one-shot form. `TempAllocator::{for_injection, for_executable}` give
  Ghidra's bases (`unique_base + 0x200`, 0x2000) and step 16; the allocator
  advances only on success. `space_table()` for encoding.
* Modules: `lex` (PcodeLexer), `scope` (the snippet's tree, the language's
  visible symbols, the builder's resolver), `parse/` (the grammar,
  recursive descent over the bison automaton), `compile` (driver),
  `options`, `error`. The template is built by
  `bk_sleigh_compiler::pcode::Builder` and `propagate_size`.
* Grammar accepted (`pcodeparse.y` 98–225): statements `lhs = e;`, `name =
  e;`, `name:n = e;`, `local name [:n] [= e];`, `*[space]:n e = e;`,
  `lhs[lo,len] = e;`, `userop(args);`, `goto dest;`, `goto [e];`, `call
  dest;`, `call [e];`, `return [e];`, `if e goto dest;`, `<label>`;
  expressions: integers (`k`, `k:n`), `&v`, `&:n v`, names, `name:n`,
  `name(k)`, `name[lo,len]`, `userop(args)` (a leading comma allowed after
  `(`), the fourteen built-ins, unary `- ~ ! f-`, loads `*[space]:n e`, the
  binary operators with SLEIGH's precedence (comparisons non-associative).
  Error rules: "Unknown varnode parameter", "Unknown assignment varnode",
  "Unknown jump destination", "Redefinition of symbol", "Illegal truncation
  on left-hand side of assignment", "Illegal subpiece on left-hand side of
  assignment", "Must specify an indirect parameter for return", "syntax
  error".
* Results: all 588 compilations of the 121 shipped bodies (116 languages)
  equal Ghidra's XML; 236 hand-written cases and 20,000 generated snippets
  equal Ghidra's results except the counted cases in §8. Gaps: none against
  §7; the bit-range wrap is a follow-up for `bk-sleigh-compiler`.
