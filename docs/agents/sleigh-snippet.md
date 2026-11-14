# Track `sleigh-snippet` — status report

Spec: `docs/features/sleigh-snippet.md` (sections 8 and 9 filled in).
Crate: `crates/bk-sleigh-snippet` (new). Worktree
`/Users/tatu/slop/basilisk-wt/sleigh-snippet`, branch `sleigh-snippet`;
`master` merged once on the coordinator's instruction (for
`scripts/remote.sh`). Everything committed, nothing pushed.

## State

Done, pending review. Both remote gates green (below).

## Built

`bk-sleigh-snippet` (≈1,900 lines of source in 8 files, none over 420; no
`unsafe`; no new third-party crate). Dependencies: `bk-pcode`, `bk-sla`,
`bk-sleigh-compiler`, `bk-sleigh-syntax`, `rustc-hash`, `thiserror`,
`tracing`; dev: `bk-lang`, `bk-marshal`, `bk-testkit`, `insta`, `proptest`.

* `SnippetCompiler::new(&Sla, &Options)` computes the visible names and
  spaces once (`Send + Sync`); `compile(text, &[Parameter], &mut
  TempAllocator) -> Result<Compiled { template, warnings }, SnippetError>`;
  `space_table()` for encoding. One-shot `compile(text, &Sla, &[Parameter],
  &mut TempAllocator, &Options) -> Result<bk_sla::Template, SnippetError>`
  as the spec names it.
* `TempAllocator { next, step }` with `for_injection(unique_base)` (base +
  0x200, step 16) and `for_executable()` (0x2000); it advances only on
  success, as Ghidra's library does.
* `Options`: `truncate_space` (`<truncate_space>`), `with_space`
  (`ExtraSpace`: the `.cspec`'s stack space and other program spaces),
  `max_text_len` (1 MiB), `max_depth` (1,000).
* `SnippetError::{Rejected { messages }, Aborted { message, earlier },
  TooLong}`, `ghidra_message(source)` (Ghidra's exact text), `messages()`.
* Modules: `lex` (Ghidra's `PcodeLexer`), `scope` (the snippet's symbol
  tree, the language's visible symbols, the builder's `SymbolResolver`),
  `parse/{mod,stmt,expr}` (recursive descent following `pcodeparse.y`'s
  bison automaton, names classified when read, Ghidra's error rules),
  `compile` (driver: message order, builder, `propagate_size`), `options`,
  `error`. Templates come from `bk_sleigh_compiler::pcode::Builder`.
* Oracle: `tools/reference/snippetdump.cc`, build step `[3b/5]` in
  `scripts/build-reference.sh`, format in `tools/reference/README.md`.
* Fuzz target `bk_sleigh_snippet_compile` (`fuzz/`); `cargo metadata` on
  the fuzz crate passes.

Shared files touched: root `Cargo.toml` (one `[workspace.dependencies]`
line), `Cargo.lock` (adds `bk-sleigh-snippet` only), `fuzz/Cargo.toml`
(one dependency, one `[[bin]]`), `fuzz/Cargo.lock`, `docs/PERF.md`
(appended), `docs/inventory/tests/test-integrationtest.md` (one mark),
`scripts/build-reference.sh`, `tools/reference/README.md`, the feature
doc's sections 8 and 9. `bk-sleigh-compiler`: no change.

## Tests

| File | Kind | What |
|---|---|---|
| `differential.rs` | oracle | spec 6.2, below |
| `oracle_cases.rs` | snapshot + oracle | 236 hand-written bodies (`tests/cases/fixture.txt`): every statement and expression form, every error rule, lexer quirks (octal, `0x`, NUL, illegal characters, comments, CRLF), labels, locals, bit ranges, "Localtemp size mismatch", "Requested bit range out of bounds". `insta` snapshot always; equal to `snippetdump` when present |
| `oracle_random.rs` | oracle | generated bodies (grammar-built, half corrupted); 3,000 by default, `SNIPPET_RANDOM_CASES` for more |
| `pcode_parser_test.rs` | port | `PcodeParserTest.testCompilePcode`, step 0x100, on the fixture (always) and the reference `x86.sla` |
| `api.rs` | unit | 10: temporaries across snippets and on failure, parameter handles, duplicate parameters, invisible symbol kinds (token/context fields, tables, name fields), visible ones (`inst_*`, spaces, user ops), names that are SLEIGH keywords (`build`, `cpool`, …), extra spaces, truncation, error forms and messages, limits, CRLF, one-shot = compiler, `Send + Sync` |
| `properties.rs` | property | 3: arbitrary text, token soup, statement soup never panic; failures take no temporaries; compiled templates read back from XML unchanged. Regressions file checked in (one case: a branch to a label never placed, which `bk_sla` refuses to read; the property skips such templates) |
| `fuzz_regressions.rs` | replay | `fuzz/regressions/bk_sleigh_snippet_compile/` (none saved) |
| `bench.rs` | bench | 2 `#[ignore]` |
| unit (lib) | unit | 3 lexer tests |

The fixture language (`tests/fixture/fixture.slaspec`) is compiled by
`bk-sleigh-compiler` in the tests and written as a `.sla` + `.ldefs` for the
oracle, so the case and property tests run in CI without the reference.

Ghidra tests ported: `ghidra.program.model.lang.PcodeParserTest` (1) →
`tests/pcode_parser_test.rs`, marked. `SleighProgramCompilerTest`,
`SleighUtilsTest` belong to the emulator (spec 6.1), not touched.

Runs: properties at `PROPTEST_CASES=1000000` (release) on the build host and
the Mac, pass. Fuzz 60 s on the build host: 721,421 runs, no finding.

## Differential result (spec 6.2)

`snippets: 137 elements in 49 files, 16 of them dynamic without a body;
116 languages, 588 compilations; Ghidra compiled 588, rejected 0, threw 0;
distinct elements compiled 121; differences 0` — the same on the build
host (libstdc++ oracle) and the Mac (libc++ oracle). No tolerated
difference in the shipped corpus.

Hand-written cases: 236 compared, 0 differ on the build host; on the Mac
4 octal cases (`09`, `08`, `0779`, `0189`) are counted as host-dependent:
the libc++ oracle reads them as BADINTEGER (`num_get` fails when
`strtoull` stops before the end of the collected digits;
`pcodeparse.y`, `PcodeLexer::getNextToken`, `s1 >> curnum`); Basilisk
follows x86-64 Linux (ADR-021), where they read as their octal prefix.

Generated: 200,000 bodies, 19,625 compiled by Ghidra, **0 differ**, 456
counted: bit ranges whose numbers make Ghidra's 32-bit arithmetic wrap
(`pcodecompile.cc` `createBitRange`, `assignBitRange`,
`buildTruncatedVarnode`; `pcodeparse.y` 114, 187 cast to `uint4`), which the
shared builder in `bk-sleigh-compiler` computes without wrapping — a bug in
that crate (follow-up below), not reachable by any shipped snippet. One
real difference the generator found was fixed (the arguments of a user-op
statement whose `;` is missing were not evaluated before the syntax error).

## Benchmarks

`cargo test -p bk-sleigh-snippet --release --test bench -- --ignored
--nocapture --test-threads=1`. Build host (x86-64 Linux VM, 20 vCPUs, host
CPU model (AMD Zen 4 class), idle): `SnippetCompiler::new` for x86-64
0.15 ms; the 16 snippets of `x86-64-gcc.cspec` 27.6 µs together; a
10-statement snippet 5.5 µs. Mac (M1 Pro, shared): 0.16 ms, 36.7 µs,
6.4 µs. In `docs/PERF.md`.

## Differences from Ghidra

Feature doc section 8: token length unbounded (Ghidra overflows a 256-byte
buffer); text and nesting limits ("memory exhausted" at a different depth);
every message kept (`messages()`, `warnings`); message order inside a
failing statement modelled by evaluating the reduced expressions; the
bit-range wrap (builder bug, counted); x86-64 number reading; extra spaces
supplied by the caller.

## Plugin binding constraints

Items that apply (`docs/features/plugin-binding-constraints.md`):
`SnippetCompiler`, `Compiled`, `Template`, `SnippetError`, `Options`,
`TempAllocator`, `Parameter` are owned, lifetime-free and `Send + Sync +
'static` (tested), so a binding holds a compiler in an `Arc` beside a
language; inputs are plain strings and numbers; `SnippetError` is a
`thiserror` enum, `#[non_exhaustive]`, with structured fields
(`messages`, `message`, `earlier`, `len`, `limit`) and `ghidra_message`
for display, convertible to an exception; results are owned values
(the template encodes to XML or packed form). No large collections, no
long-running operation, no identifiers across transactions: the paging,
monitor and cancellation items do not apply.

## Platforms

* Linux x86-64 (build host): all tests, oracle tests, 200k generated
  cases, 1M properties, fuzz 60 s, benchmarks, both gates.
* macOS arm64: all crate tests with and without the reference, oracle
  tests (libc++ oracle; counted octal cases), properties 1M, benchmarks.
* Windows: `cargo clippy -p bk-sleigh-snippet --all-targets --all-features
  --target x86_64-pc-windows-msvc -- -D warnings` clean on the Mac. Tests on
  Windows: not run (rest on CI). The crate is pure string computation; line
  endings are tested (CRLF = LF).

## Gate

`scripts/remote.sh gate; echo $?` → 0, `tests: 2053 passed, 0 failed`;
`scripts/remote.sh gate --no-ref; echo $?` → 0, `tests: 2053 passed, 0
failed`. Both on the build host, commit 46ad590 (docs edits after that
commit change no code). `scripts/check-dep-age.py master`: 0 new registry
packages; `git diff master -- Cargo.lock` only adds `bk-sleigh-snippet`.

What ran on the Mac and why: editing, the Windows clippy cross-check, and
small per-crate builds/tests while the build host was being restarted and
before the oracle existed there. `scripts/build-reference.sh` was run once
on the Mac to add `bin/snippetdump` to `/Users/tatu/slop/reference`; the
script also rebuilt `bin/pcodedump` there (its fingerprint did not match:
the recorded one predates a change to its inputs; same source, same
objects) and rewrote `STAMP`. Nothing else there changed.

`scripts/remote.sh` from this worktree: `status`, `setup`, `run`, `gate`,
`gate --no-ref`, `log` all worked. `setup` rebuilt only the new step (it does
update an existing reference incrementally). One note: `run` printed
"cargo fetch failed; continuing" once (the run then succeeded).

## Spec items found wrong

* §4.2: the snippet language has its own lexer and grammar (octal literals,
  `#` comments, NUL ends the text, unknown characters end the input; no
  `build`/`delayslot`/`crossbuild`/`export`/macros/sections/`cpool`/
  `newobject`/`popcount`/`lzcount`; `goto`/`call` cannot target operands or
  registers; `borrow` is a keyword without a rule). Productions in §9.
* §4.1: `inst_dest`/`inst_ref` never give the `_size` constants.
* §4.4: Ghidra reports only the first error; no label check; errors that do
  not stop the parser do not fail the compile; `SleighError`s escape without
  the "Unable to compile pcode" prefix.
* §1/§6.2: 137 elements outside comments (130 `<pcode>` + 7 `*_pcode`),
  not 132/139: two `<pcode>` of `x86win.cspec` are in an XML comment; 16
  are dynamic without a body.
* §6.2: `<truncate_space>` must be applied (three languages with snippets).
* §3: the `bk-testkit` wrapper module could not be added (other crate); the
  oracle wrapper is in this crate's `tests/common/oracle.rs`.

## Gaps

None against section 7. Not done: Windows and macOS CI runs (CI's job).

## Follow-ups

* `bk-sleigh-compiler` (`src/pcode/bitrange.rs`): compute as Ghidra's
  `uint4`: `create_bit_range` `final_size = bits.wrapping_add(7) / 8`;
  `assign_bit_range` `small_size = bits.wrapping_add(7) / 8` and
  `bit_offset.wrapping_add(bits) > 64` instead of the `u64` sum;
  `truncated_varnode` `byte_offset.wrapping_add(num_bytes)` before the
  comparison. Then remove the tolerance in `tests/oracle_random.rs`
  (`wraps_32_bits`). Affects SLEIGH specifications too, though none ship
  such numbers.
* `bk-testkit`: add `Tool::Snippetdump` and move `tests/common/oracle.rs`'s
  record writer and parser there (ADR-007 puts oracle wrappers in
  `bk-testkit`).
* The decompiler's injection library (M3): use one `SnippetCompiler` per
  program, `TempAllocator::for_injection` carried in payload order (pspec,
  then cspec, document order) and `for_executable` for segment operators
  and jump-table helpers; pass `<truncate_space>` and the stack space;
  `bk-cspec`'s `InjectPayload` maps to `Parameter`s by `index`.
* `bk_sla::Template` validation refuses a branch to an unplaced label, which
  Ghidra compiles (and fails on only when the snippet is injected): a
  reader that must load Ghidra's snippets would need to accept it.

## Commits

See `git log --oneline master..HEAD` (in the final message).
