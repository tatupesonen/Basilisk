# Track `sla` — final report

Branch `sla`, worktree `/Users/tatu/slop/basilisk-wt/sla`. Crate
`crates/bk-sla` (new). Spec: `docs/features/sla.md` (sections 8 and 9
filled in). Nothing pushed, nothing merged.

## Built

`crates/bk-sla` — the compiled SLEIGH language file, version 4.

| Module | What |
|---|---|
| `ids` | Format-scope element and attribute ids (88 / 54), `id_table()` for the XML form, numeric `a::`/`e::` constants for matching |
| `model` | `Sla`: one immutable value of flat arenas (`Arenas`) with typed `u32` ids (`SymbolId`, `ScopeId`, `ConstructorId`, `ExprId`, `FieldId`, `TemplateId`, `DecisionId`, `BlockId`, `HandleId`, `StrId`, `Span`). Symbols (`SymbolKind` enum), constructors (ranges into operand/print/context/template arenas), decision nodes with contiguous child runs (`first_child + v`), pattern blocks normalised as `PatternBlock::normalize`, expressions (16 bytes), templates (`ConstTpl` 16 bytes, `VarnodeTpl` 48), `TemplateRef` borrowed view. Struct sizes and `Sla: Send + Sync` asserted |
| `read` | `Sla::read` / `read_file` (header, zlib inflate with size limit, trailing-byte check), `decode_packed` (own cursor over the bytes), `decode_packed_using(.., PackedReader::Marshal)` (through `bk-marshal`'s `PackedDecoder`), `decode_xml` (through `bk-marshal`'s `XmlDecoder`). One generic decoder over a small `Source` trait; errors carry the element path, symbol, constructor and byte offset |
| `validate` | Rules 1–6 of spec 4.3 and the limits of 4.4 (`Limits`), shared by the reader and the builder |
| `write` | `encode_packed`, `encode_xml` (= `sleigh -y` text), `write` (container), `write_file` (temporary file renamed into place); generic `encode<E: bk_marshal::Encoder>` |
| `builder` | `SlaBuilder` with owned definitions (`SymbolDef`, `TableDef`, `ConstructorDef`, `DecisionDef`, `PatternDef`, `BlockDef`, `SpaceDef`, `PrintDef`); `finish()` lays out like the reader and validates |
| `diff` | `diff(a, b, cap) -> Vec<Difference>` with paths such as `table "instruction" constructor 0 (a.sinc:10) main op 0 output`; `Sla: PartialEq` is structural through it |
| `spaces` | `build_spaces() -> SpaceManager` (`decodeSlaSpaces`) |
| `template_codec` | Standalone `Template` (`encode_xml`/`encode_packed`/`decode_xml`/`decode_packed`/`validate`) with a `SpaceTable` |

## Tests

Counts: 5 unit tests; integration: `reference` 3 (differential), `fixtures`
7, `validation` 6 (60 one-violation XML cases, 5 builder cases, 10 limits,
container errors), `properties` 4 (proptest), `fuzz_regressions` 2,
`bench`/`bench_heap` 3 ignored.

* **Ghidra tests ported**: none — the spec states none targets the format
  (checklist not touched).
* **Differential (need `REF`)**, all pass on macOS arm64:
  1. packed round trip byte-exact for all 150 `.sla`, through both packed
     decoders, models compared;
  2. `encode_xml` equals `sleigh -y` text (module options from
     `REF/.state/lang/<Module>.opts`, `-DBaseDir=REF`) for all 150;
  3. `decode_xml` of that text equals the packed model; all 150 validate.
  4. Mutation check: 12 single-attribute model mutations (header
     `uniqbase`, space delay, symbol name, varnode offset, constructor line,
     print piece, operand minlen, token-field signbit, decision number,
     mask-word value, `const_real`, opcode) each make tests 1 and 2 fail
     (`mutated_models_fail_the_differential_checks`). Code mutations tried by
     hand: writing `wordsize` when it is 1, always writing `code`, swapping
     `startbyte`/`endbyte` — each failed tests 1 and 2; skipping block
     normalisation on read survived 1–2 (reference blocks are already
     normalised) and is caught by `normalize_matches_ghidra` and the fixture
     accessor test. Two mutations I first chose were rejected by validation
     itself (duplicate global name; a `BUILD` operand index out of range).
* Ran with both variables unset (all three skip with a printed
  `SKIPPED ...` line) and with `/Users/tatu/slop/basilisk-wt/../reference`
  (pass).
* Fuzz: `bk_sla_read` and `bk_sla_decode_packed` (shared body
  `fuzz/fuzz_targets/bk_sla_shared/mod.rs`, replayed by
  `tests/fuzz_regressions.rs`); seeds = six smallest reference files. One
  finding (a decoded string with NUL could not be re-encoded) fixed and kept
  in `fuzz/regressions/bk_sla_decode_packed/encode-decode-1`; then 60 s each
  clean (255,679 and 700,811 runs).
* Gate: `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` printed 0; last line `tests: 1635 passed, 0 failed` (macOS arm64, 2026-11-14).

## Benchmarks

`BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 cargo test --release -p bk-sla --test bench --test bench_heap -- --ignored --nocapture --skip profile`
Reference loader: `crates/bk-sla/tests/reference_loader/slaload.cc` (build
line in the file). 2026-11-14, M1 Pro, load 8–11, same session:

| | basilisk | Ghidra C++ `Sleigh::initialize` |
|---|---:|---:|
| x86-64 `read_file` | 17.9 ms (inflate 2.5, decode+validate 15.4) | 30.8 ms |
| AARCH64BE `read_file` | 16.1 ms | 28.0 ms |
| all 150 `read_file`, one thread | 415 ms | — |
| `encode_packed` x86-64 / all 150 | 5.9 ms / 128 ms | — |
| x86-64 model heap | 13.4 MB = 3.0x stream (peak 15.6 MB) | — |

All acceptance-3 budgets met. Numbers are in `docs/PERF.md`.

## Differences from Ghidra

Listed in `docs/features/sla.md` section 8 (appended): values that do not
fit Ghidra's C++ field are rejected; NUL in strings rejected; stricter
grammar where the C++ guesses (body kind = head kind, unknown elements,
`or_pat`, subtable without decision, sparse source-file indices, trailing
data); extra validation (value-symbol fields are values, context symbol has
a context field, positive varnode sizes, definable `subsym`, block offsets
bounded, expression children precede parents); context-word margin zero;
space attributes kept per space; space references resolved from the file's
records instead of a `SpaceManager` directory; last duplicate attribute
wins; structural model equality.

## Spec items found wrong or underspecified

* 4.6 suggests decoding on `SpaceManager::directory()`; resolving from the
  file's own space records is simpler and equivalent, so `build_spaces()` is
  separate. (Implemented the closest correct thing; noted in section 8.)
* 4.3 rule 3's "small margin" on context words is unspecified; zero is used
  and `Sla::context_words()` is exposed for the runtime.
* "contextfield ... at most 32 bits" was read as field width ≤ 32 bits.
* Model equality cannot be the derived arena equality (layout depends on
  document order), so `PartialEq` is structural.

## Gaps

None against section 7, except what rests on CI: the tests that do not
need `REF` were run on macOS only; Windows was checked with
`cargo clippy -p bk-sla --all-targets --target x86_64-pc-windows-msvc -- -D warnings`
(clean); Linux not run locally.

## Follow-ups

* No new third-party crate; `Cargo.lock` only gains `bk-sla` (and the fuzz
  crate's lock gains it). `flate2` is used at the workspace version with the
  `zlib-rs` backend.
* `bk-testkit` was not changed; the per-module `sleigh` options are read
  from `REF/.state/lang/<Module>.opts` in `tests/reference.rs`. A
  `ReferenceDir::module_options()` in `bk-testkit` would serve the compiler
  tracks too.
* For `sleigh-decode`: use `Sla::context_words()` to size the context; a
  constructor's flow-through is `print_pieces == [Operand(i)]`; decision
  child for value `v` is `decision_child(node, v)`.
* For `sleigh-compiler-*`: `SlaBuilder` + `diff` are the intended interface;
  `Template` is the shared template value; `diff` caps its output.
* `bk-marshal`'s generic packed decoder is about 2x slower than this
  crate's cursor here; finding from tuning: `Option::ok_or(error)` with an
  error type that has drop glue cost a third of the decode time.

## Commits

See `git log --oneline master..HEAD` in the final message.
