# Track `sleigh-snippet` — status report

Spec: `docs/features/sleigh-snippet.md`. Crate: `crates/bk-sleigh-snippet` (new).
Worktree `/Users/tatu/slop/basilisk-wt/sleigh-snippet`, branch `sleigh-snippet`.

## State

In progress. Reading done; oracle (`tools/reference/snippetdump.cc`) written
and working against the reference build (built by hand into
`target/snip/snippetdump`, build step in `scripts/build-reference.sh` next).

## Findings from reading (the "[to verify]" items of spec section 4)

Ghidra's C++ snippet compiler is `PcodeSnippet` (`CPP/pcodeparse.y`), a
**separate lexer and grammar** from the SLEIGH semantic section, sharing only
`PcodeCompile`. Consequences:

* **Lexer** (`PcodeLexer`): identifiers `[A-Za-z_.][A-Za-z0-9_.]*`; `#`
  comments; no strings; integers parsed by `istream >> uintb` with base
  detection: `0x…` hex, **a leading `0` means octal** (`010` = 8; `09` = 0
  with no error, verified with the oracle), overflow and `0x` alone =
  `BADINTEGER`. A NUL byte ends the text (the rest is ignored). Any other
  character (`@`, `$`, `{`, non-ASCII …) is token 0 = end of input → syntax
  error. Keywords: `if goto call return local` and the built-ins `abs borrow
  carry ceil float2float floor int2float nan round sborrow scarry sext sqrt
  trunc zext`; **not** `cpool newobject popcount lzcount build export
  delayslot crossbuild` (these are plain names; `borrow` is a keyword with no
  rule, so always a syntax error). Tokens over 255 characters overflow a
  fixed buffer in Ghidra (undefined behaviour; Basilisk accepts them).
* **Names** (`PcodeSnippet::lex`): looked up when lexed, local tree first
  (spaces of type constant/processor/spacebase/internal, `inst_dest`,
  `inst_ref`, parameters, locals, labels), then the language's global scope;
  only user ops, varnodes, `inst_start/next/next2` are visible. A `.sla` has
  no space symbols, so spaces come only from the local tree. Duplicate
  parameter names: "Duplicate symbol name: X", first one wins, **not fatal**.
* **Grammar** (lines 98–225; productions listed in the feature doc): no
  `build`, `delayslot`, `crossbuild`, `export`, macros, sections, `cpool`,
  `newobject`, `popcount`, `lzcount`. `goto`/`call` destinations: `inst_*`
  symbols, integers, `int[space]`, labels — **not operands or registers**
  (syntax error). `local` declarations allowed between statements. Comparison
  operators non-associative.
* **Errors**: Ghidra keeps only the **first** error message. `parseStream`
  fails only on a syntax/`YYERROR` error or failed size propagation; errors
  reported without aborting (bit-range problems, "Parsed integer is too big",
  "Label … placed more than once", duplicate symbols) **do not fail the
  compile** — the template is used. If it fails, the message is the first
  error of the whole compile (e.g. an earlier overflow, not the later syntax
  error). `SleighError`s thrown by `PcodeCompile` ("Requested bit range out
  of bounds", "Could not construct requested bit range", "Localtemp size
  mismatch", "Expression has no output") escape `parseInject` bare, without
  the "Unable to compile pcode" prefix.
* **Finishing**: only `propagateSize`; **no label check** (a label used but
  never placed compiles; placing twice is a non-fatal error). Label count =
  number of `LABEL` ops.
* **Temporaries**: step 16 from the base; `parseInject` updates the carried
  base only on success; executable p-code always 0x2000 and does not touch
  the carried base; the library's first base is `unique_base + 0x200`.
* `inst_dest`/`inst_ref` produce `const_flowdest`/`const_flowref` with size
  0 (never the `_size` constants; the spec's "with their `_size`
  companions" does not happen in the compiler).
* `<truncate_space>` changes a space's address size (AARCH64 ilp32, MIPS
  64-32addr, PPC 64-32 have snippets) → an option.
* Spaces added by the `.cspec` (`stack`, spacebase) are visible to snippets
  compiled after them in Ghidra → an option for extra spaces.
* The corpus: 132 `<pcode>` elements in 47 files, plus 7 jump-assist
  `*_pcode` elements (Dalvik, JVM) — all 139 are compiled.

## Design

* Own lexer (`lex.rs`) and recursive-descent parser (`parse/`) that follow
  `pcodeparse.y`'s automaton (bison report generated from a copy in the
  scratch dir; same table sizes as Ghidra's checked-in 3.5.1 parser), classify
  names at lex time like Ghidra, and report Ghidra's parse-time messages in
  Ghidra's order. They produce `bk_sleigh_syntax` AST nodes, which
  `bk_sleigh_compiler::pcode::Builder` compiles through this crate's
  `SymbolResolver` (`scope.rs`). Not `compile_snippet`: it checks labels and
  treats every error as fatal, unlike Ghidra.
* Driver orders messages: parameters' duplicates, then the builder's messages
  of the complete statements before a parse failure, then the parse failure
  (with the overflows consumed before it); builder `Fatal` = Ghidra's
  exception. `propagate_size` last.
* `SnippetCompiler::new(&Sla, &Options)` precomputes the visible names and
  the build environment (hot path: many snippets per language);
  `compile()` is the spec's one-shot form.

## Step plan

1. Crate skeleton, workspace entries; status file. ← now
2. Lexer + unit tests against the oracle's behaviour.
3. Scope/resolver from `Sla`; parser; driver; errors.
4. `PcodeParserTest` port (step 0x100, x86 `.sla`).
5. Oracle build step + README format; differential test over all
   `<pcode>` bodies for every language that uses each spec file.
6. Error-case differential corpus against the oracle; unit tests per
   symbol kind/statement/error; proptest; fuzz target + replay.
7. Benchmarks, PERF.md, feature doc §8/§9, checklist mark, platforms, gates.

## Done / in progress / next

Paused by the coordinator (usage limit), 2026-11-14.

* Done: reading; oracle `tools/reference/snippetdump.cc` (format: input
  `S<TAB>source<TAB>base<TAB>body[<TAB>index:name]...`, base `continue` |
  `0x…` (start carried base) | `fixed:0x…` (executable, carried base
  untouched), fields escaped `\\ \t \n \r \0`; output `H`, then per record
  `O source base next errcount first-error xml` or `F source base
  rejected|exception message`, then `T ok failed`). Built by hand into
  `target/snip/snippetdump` and checked: PcodeParserTest body gives the
  expected template (step 16); `010` = 8, `09` = 0, `0x` = BADINTEGER;
  non-fatal errors leave the template in place.
* Done (crate `bk-sleigh-snippet`, builds, clippy clean, 4 unit tests):
  `lex.rs` (PcodeLexer), `scope.rs` (Language/Locals/Resolver, name
  mangling for the builder's extra keywords), `options.rs` (Parameter,
  TempAllocator, ExtraSpace, Options with truncations, limits),
  `parse/{mod,stmt,expr}.rs` (grammar per the bison automaton, pending
  expressions for message order), `error.rs` (Rejected/Aborted/TooLong,
  `ghidra_message`), `compile.rs` (SnippetCompiler, driver), `lib.rs`
  (`compile`). Root `Cargo.toml`: one `[workspace.dependencies]` line.
* In progress: `tests/common/mod.rs` written (roots, snippetdump lookup,
  registry, load_sla); `tests/common/corpus.rs` and `oracle.rs` not yet
  written (declared in mod.rs — the test crate does not compile until they
  exist).
* Next (after `git merge master`, then build/test via `scripts/remote.sh`):
  1. corpus.rs: per language (registry), pspec then each cspec in document
     order; `<pcode>` and `*_pcode` elements; params inputs then outputs;
     executable (parent `segmentop` or `*_pcode`) → `fixed:0x2000`, others
     carried from `unique_base+0x200` per (language, cspec); dynamic bodies
     compiled too but counted apart. oracle.rs: write records, run tool,
     parse results.
  2. tests/differential.rs (XML equal, failure equal, next base equal, first
     warning equal); error-case corpus vs oracle; PcodeParserTest port (step
     0x100); unit tests per symbol kind/statement/error; proptest; fuzz
     target `bk_sleigh_snippet_compile` + replay; benches; PERF.md.
  3. build step for snippetdump in `scripts/build-reference.sh`, README
     section; feature doc §8/§9; checklist mark in
     `docs/inventory/tests/test-integrationtest.md`; Windows clippy on Mac;
     both remote gates; check-dep-age.
