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

(The implementing track fills this in.)

## 9. Status

Not started.
