# Track `lang` — final report

Branch `lang`, worktree `/Users/tatu/slop/basilisk-wt/lang`, crate `bk-lang`.
Spec: `docs/features/lang.md` (sections 8 and 9 filled in). The track was
built by one agent up to a checkpoint and finished by a second; this report
replaces the first agent's handover.

## Verified (what was run, and the result)

All on an Apple M1 Pro, macOS, Rust 1.97.1, Ghidra at commit `42db038f3c`,
`BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra`, other agents building on
the machine (load average about 10 on 8 cores).

| Check | Result |
|---|---|
| `git merge master` | clean, no conflicts (merge commit `81d8c15`) |
| `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?` | **exit 0**; last line `tests: 233 passed, 0 failed`; `cargo deny`: `bans ok, licenses ok, sources ok` (one warning: `syn` 2 and 3 both in the tree, from `rstest`/`tracing` and `thiserror`) |
| `cargo test -p bk-lang` | 233 passed, 0 failed, 1 ignored (the benchmark) |
| Benchmark (release, `--ignored`) | registry scan median 14.97 ms (budget 50 ms); see "Benchmarks" |
| Fuzzing, `lang_readers`, 30 min (1,801 s) | 2,742,873 executions, no crash, panic, leak or out-of-memory; one "slow unit" report (see "Fuzzing") that replays in 4 ms |
| New multi-match resolution test | fails when the branch it covers is broken (checked by mutating the code, then restored) |

Carried over from the first agent and **not re-run by me**: the skip path
with `BASILISK_GHIDRA_DIR=/nonexistent`; the one-time RELAX NG differential
(the validator is no longer a dependency); the JVM order check with
OpenJDK 25. The corpus counts below are asserted by tests that passed in
the gate, so those I did verify.

## Built

`crates/bk-lang`, no dependency on other `bk-*` crates. Third-party:
`roxmltree`, `thiserror`, `tracing`, `walkdir`; dev: `insta`, `proptest`,
`rstest`, `tempfile`.

| Module | What it is |
|---|---|
| `id` | `LanguageId` (non-empty, `Arc<str>`), `CompilerSpecId`, `LanguageCompilerSpecPair` (ordering, `lang:compiler` display), `Processor` (typed index into the registry's name table) |
| `endian` | `Endian`: names, short names, `parse` (= `Endian.toEndian`), `parse_long_name` (= the `.ldefs` reader) |
| `value` | `SpecXmlUtils` number and boolean decoding (`0x` hex, leading `0` octal, Java wrap-around), Java `String.split` |
| `schema` | The three grammars as public static tables: elements, attributes, requiredness, value types, cardinality, order |
| `reader` | Strict/lenient checking of each element against the tables, positions, `Parsed<T> { value, warnings }` |
| `error` | `Position`, `Mode`, `Violation`, `Warning`, `ParseError`, `ReadError`, `RegistryError` |
| `ldefs/{model, read}` | `LanguageDefinitions`, `LanguageDefinition`, `LanguageVersion`, `TruncatedSpace`, `CompilerDefinition`, `ExternalName` |
| `pspec/{model, read, address, context, registers, symbols, memory, segment}` | `ProcessorSpec` with every schema element; unresolved `AddressSpec`/`AddressRange` and the `AddressResolver` hook; p-code bodies as source text; `sections` keeps top-level order |
| `opinion/{model, read, query, javahash}` | `Opinions` (flat pre-order constraints with parent ids, no recursion), `OpinionDatabase::{add, query, loaders, order_is_exact}`, Java `HashMap` iteration order |
| `registry/{mod, scan, paths, query}` | `RegistryBuilder`, immutable `Send + Sync` `LanguageRegistry`: discovery as Ghidra does it, lookups, pair and external queries, default language, lazy cached `.pspec`, `sla_file` with an overlay, lazy opinions |

Since the handover: `ReadError::Encoding` now carries the `Utf8Error` as
its source (a lint fix that also improves the message); all code passes
`master`'s lint configuration with no new suppressions.

## Tests

| Kind | Count | Where |
|---|---:|---|
| Unit | 127 | `src/**` |
| Reader tests (hand-written documents, every element form, errors with positions, lenient warnings) | 54 | `tests/read_ldefs.rs` (19), `read_pspec.rs` (25), `read_opinion.rs` (10) |
| Registry on temporary module trees | 14 | `tests/registry.rs` (one added: a file name found in several modules) |
| Queries | 7 | `tests/queries.rs` |
| Ported Ghidra tests | 7 | `tests/ported.rs` |
| Corpus (skip without Ghidra) | 8 | `tests/corpus.rs` |
| Golden snapshots (`insta`) | 6 | `tests/golden.rs` |
| Property tests (`proptest`, never panics) | 6 | `tests/robustness.rs` |
| Schema coverage against the `.rxg` files | 4 | `tests/schema_coverage.rs` |
| Benchmark (ignored) | 1 | `tests/bench.rs` |
| Fuzz target | 1 | `fuzz/fuzz_targets/lang_readers.rs` |

Ghidra tests:

- `ghidra.app.util.opinion.QueryOpinionServiceTest` (4): **ported** in
  full, `crates/bk-lang/tests/ported.rs` (`ghidra_*`); marked `- [x]` in
  `docs/inventory/tests/features-base.md`.
- `ghidra.app.plugin.processors.sleigh.SleighLanguageProviderTest` (4):
  **partly ported, left unmarked.** All four tests are about compiling a
  `.sla` under a cross-process file lock. The parts that apply now are in
  `tests/ported.rs`: a provider over `x86.ldefs` describes
  `x86:LE:32:default` with its files, and `fromSlaFilename` finds
  `mylang.slaspec`/`mylang.sla`. The lock, timeout, read-only-directory and
  compilation assertions wait for the SLEIGH compiler (M2); a partial port
  is not a port, so the checklist line stays `- [ ]`.
- No other test of the section-2 classes that runs without a program or a
  `.sla` was found in `docs/inventory/tests/` (searched by class name).
  `VectorRegisterPspecTest` and `DecompilerPspecVolatilityTest` need a
  loaded language or program (M1, M3); the `.pspec` data they use is read
  and tested here.

Schema coverage: the `oxixml-relaxng` dev-dependency is **removed**
(coordinator's decision: 361 downloads, 2 dependents). Kept, without a
validator: the element and attribute names reachable in each `.rxg` file
equal those in `schema.rs`; the fullest document each table describes
reads in strict mode; every shipped file reads. The one-time differential
is recorded in the spec's section 9: on 2026-11-12, with
`oxixml-relaxng` 0.1.2, all 173 corpus files validated and 1,049
single-step mutations (119 `.ldefs`, 817 `.pspec`, 113 `.opinion`) gave no
disagreement between the strict readers and the validator, other than
schema-valid values neither reader can decode (`size="maybe"`).
`Cargo.lock` no longer contains any `oxixml` crate.

## Fuzzing

Target `lang_readers` (`fuzz/fuzz_targets/lang_readers.rs`): arbitrary
bytes, if UTF-8, through `ldefs::parse`, `pspec::parse` and
`opinion::parse` in strict and lenient mode; for parsed `.pspec` files the
memory blocks' start-address offsets are decoded, and for parsed
`.opinion` files every resolved `secondary` pattern is matched against two
keys.

Run, 2026-11-12 16:47–17:18 UTC, one process, alongside other agents'
builds:

```text
cd fuzz
cp <Ghidra>/Ghidra/**/*.{ldefs,pspec,opinion} corpus/lang_readers/   # 172 seeds, test dirs excluded
cargo +nightly fuzz run lang_readers -- -max_total_time=1800 -max_len=131072 -rss_limit_mb=2048
```

Result: `Done 2742873 runs in 1801 second(s)`, about 1,520 executions per
second; coverage grew from 2,213 to 4,265 edges (17,053 features), the
corpus from 142 to 2,421 inputs. **No crash, panic or out-of-memory.**
libFuzzer reported one slow unit ("Slowest unit: 303 s", a 6 kB mangled
`.pspec`); replayed on its own it runs in **4 ms**, so the 303 s was the
process being stalled on the loaded machine, not the input. As nothing
failed, there is nothing under `fuzz/regressions/`. The corpus and
artifacts stay in the git-ignored `fuzz/corpus` and `fuzz/artifacts`.

## Benchmarks

`BASILISK_GHIDRA_DIR=… cargo test -p bk-lang --release --test bench -- --ignored --nocapture`,
fastest / median, recorded in `docs/PERF.md`:

| Run | Registry scan (52 `.ldefs`, 202 languages) | + opinion database | + all 87 `.pspec` | One opinion query |
|---|---|---|---|---|
| 2026-11-12, this session (load average 10, fuzzer running) | 13.05 / 14.97 ms | 16.77 / 21.40 ms | 21.58 / 25.60 ms | 6.0 / 6.1 µs |
| 2026-11-12, first agent | 11.8 / 12.8 ms | — / 15.6 ms | — / 22.1 ms | — / 5.8 µs |

Budget for the scan: 50 ms.

## Differences from Ghidra

All are in `docs/features/lang.md` section 8: missing files drop one
language, not the rest of the `.ldefs`; readers are atomic per file;
`.opinion` files are schema-checked in strict mode; files within a module
are visited in name order (decides `RISCV`'s default language); all
schema spellings of `<memory_block>` booleans accepted; negative sizes and
versions rejected; DTDs refused; opinion nesting read without recursion
or depth limit; strict mode by tables, not a RELAX NG validator;
`SegmentOp::far_pointer` is `Option<bool>` because Java and C++ disagree;
lenient mode and `LoadFailure` values; Java `HashMap` order reproduced
except for treeified bins (`order_is_exact`).

## Gaps

- Old-language translators (`data/languages/old/*.lang`, `*.trans`) are
  not read (out of scope, M8). `.cspec`, `.dwarf` and pattern files are
  out of scope.
- UTF-16 spec files are refused (`ReadError::Encoding`); none exist.
- Java's treeified hash bins are not emulated, only reported.
- Not tested: symlinked module or data directories (walkdir follows links;
  loops are skipped with a `tracing::warn!`); the exact-case file rule on
  a case-sensitive file system or on Windows (tested on macOS's
  case-insensitive APFS only).
- `SleighLanguageProviderTest` is only partly ported (above).
- The spec's design note "scanning 51 small files must not parse 88
  processor specs" (section 4.5) keeps the old counts; the rule holds
  (52 files, 87 distinct `.pspec` parsed only on demand).

## Follow-ups

**For the SLEIGH runtime track (M1/M2)**

- Start from `LanguageRegistry::from_ghidra_root(spec_root_from_env())`,
  or the builder with `.sla_overlay(reference_dir)`. `find("x86:LE:64:default")`
  gives the description; paths in `description.files()`; the compiled file
  through `registry.sla_file(id)`; the `.pspec` through
  `registry.processor_spec(id)` (an `Arc<ProcessorSpec>`).
- `.pspec` names and addresses are unresolved strings. Replay
  `ProcessorSpec::sections` in order when resolving register names (a
  `rename` applies to what follows); implement `pspec::AddressResolver`.
- `slafile` resolves through the `.slaspec` of the same stem, with the
  `.sla` expected beside it (it need not exist); the source tree has no
  `.sla` files.
- `SleighLanguageProviderTest`'s lock and compilation assertions are
  waiting for M2; its checklist line is still open.

**For the loader tracks**

- `registry.query_opinions(loader_name, Some(primary), secondary)`. Keys
  are strings: the opinion files key ELF by decimal `e_machine` and match
  the secondary key as a signed 32-bit decimal (`e_flags`); PE by decimal
  machine number (34404 for x86-64). Neither agent read `ElfLoader`,
  `PeLoader` or `LoadSpec` to confirm what each passes — the loader track
  must. Preferred results are the default choices; an empty answer means
  the opinions offer no language. Five shipped constraints select no
  language (`avr8`, `minidump`, `pagedump`, `PIC24`, `V850`).

**For the coordinator**

- **Moving to `bk-marshal`'s XML document.** What depends on `roxmltree`
  specifically: (1) `reader.rs` turns `node.range().start` into line and
  column with `Document::text_pos_at` for every error and warning, and
  takes roxmltree's syntax-error position (`Error::pos`) and message
  (`ParseErrorKind::Xml(String)`); the new document must give each
  element's start position. (2) `ParsingOptions { allow_dtd: false }`
  refuses DTDs. (3) `roxmltree::Node<'_, '_>` is the parameter type of
  every reader function (33 sites in 10 files: `reader.rs`, `ldefs/read.rs`,
  `opinion/read.rs`, and seven `pspec` modules); the calls used are
  `children`, `is_element`, `is_text`, `text`, `tag_name().name()` and
  `.namespace()` (namespaced elements are rejected), `attribute`, and
  `attributes()` (to find unknown attributes). (4) Element text is the
  untrimmed concatenation of text children, as Ghidra's pull parser
  reports it. (5) roxmltree accepts XML 1.1 declarations (four shipped
  `.ldefs` files) and a BOM; tests check both. Nothing else in the crate
  touches the XML library, so the move is confined to `reader.rs` plus a
  type change in the reader functions.
- `fuzz/Cargo.toml` is new on this branch (package `basilisk-fuzz`, one
  `[[bin]]`, `lang_readers`) with its own `fuzz/Cargo.lock`; other tracks
  create the same files, so expect to merge the `[[bin]]` and
  `[dependencies]` lines and regenerate the lock.
- `cargo-deny` warns about `syn` 2 and 3 in the tree (`thiserror-impl`
  uses 3; `rstest_macros` and `tracing-attributes` use 2). Not fixable in
  this crate.
- The gate failed once with `cargo deny --offline` unable to fetch
  `encode_unicode` (a dependency of `insta`); `cargo fetch` fixed it. A
  fresh checkout needs `cargo fetch` before the gate.
- The first commit after the merge (`158d2ee`) renamed the oracle test
  file before the following commit rewrote it, so that one intermediate
  commit does not pass clippy; every later commit does.

## What Ghidra's sources say that the spec did not

Kept from the first agent's investigation (the spec's counts and discovery
rule were corrected on `master` from these findings; the rest is reference
for whoever touches this code).

**Discovery.** Ghidra finds *modules* (directories with `Module.manifest`,
up to three levels below `<root>/Ghidra` and `<root>/GPL`, never inside
`build`, never named `bin`) and walks each module's whole `data` tree (and
`build/data`) for files ending in the extension, skipping `.svn`, `bin`,
`classes`, `developer_scripts`, `ghidra_scripts`, `help`, `os`,
`resources`, `src`, `test`, any `DATA SEARCH IGNORE DIR:` of the manifest,
and files starting with `._`. Module order is code-point order of the
directory names (a `TreeMap`). A file named in a `.ldefs` is looked up
beside it, then application-wide by name and extension
(`SleighLanguageFile.findFile`; the deprecated RISCV languages need this);
when several files share the name, the first is taken. File names must
match letter case exactly, also on case-insensitive file systems.
`hidden="true"` languages are skipped outside development mode. A
duplicate language id: the later definition replaces the earlier one in
its position, with an error. A missing `.cspec`/`.pspec`/`.slaspec`
abandons the rest of the `.ldefs` file; a missing manual index is only
logged.

**`.ldefs`.** Sizes and versions go through `decodeInt` (`0x` hex, leading
`0` octal). A repeated compiler `id` replaces the earlier entry in place;
`external_name` with an empty tool or name is dropped; description text is
not trimmed. `getCompilerSpecDescriptionByID` has no fallback, `default`
included; the default compiler spec is the first listed.

**`.pspec`.** Both readers schema-validate first, so the schema is the
grammar. The spec's element list missed `volatile` on `<register>` and
`<symbol>`, `size`/`description` on `<symbol>`, `overlay` on
`<memory_block>`, `ptr_wordsize` on `<data_space>`, `type` on
`<segmented_address>`, `format` on `<volatile>`, and
`paramshift`/`dynamic`/`incidentalcopy`/`<varnode>` in p-code elements.
The C++ reader tolerates `<address_shift_amount>`, which the schema lacks.
`farpointer` is decoded by Java and presence-tested by C++.
`<memory_block>` needs exactly one of `bit_mapped_address`,
`byte_mapped_address`, `initialized`. `<symbol address="next">` is the
previous symbol's address plus its raw `size` (0 without one). `<set
val=…>` is decimal or `0x` hex, anything else 0. `<volatile>` with a
`<register>` child is read by the decompiler but rejected by Java.
Top-level order is free but matters (renames). `<jumpassist>`: the
decompiler requires `addr_pcode` and `default_pcode`. Address strings
split at the last `:`; the offset is hexadecimal, `0x` optional, with an
optional `.unit` suffix.

**Opinions.** Not schema-validated by Ghidra. Every `<constraint>`
registers, not only leaves. Results live in a `HashSet` whose equality
ignores the preferred flag, so the first added keeps its flag. Order is
`HashSet` iteration order. Primary key: exact match, else the first
comma-separated `primary` containing it (MIPS `"8,10"`). Secondary key:
exact string, else the union of `0x…`/`0b…` patterns the signed decimal
key matches, else the constraints without `secondary`. Languages match by
processor, endian, size and variant against non-deprecated descriptions;
preferred = compiler spec id equals the constraint's. `endian` accepts
`big`/`little`/`BE`/`LE` in any case; `size` is decimal only.

**Queries.** `getLanguageDescriptions(processor, …)` includes deprecated
languages; `getLanguageCompilerSpecPairs` excludes them.
`getDefaultLanguage` is the processor's first language in load order.
External query: no name matches everything, a name without a tool
nothing; names compare ignoring case, tools exactly.

## Decisions and crate evaluations

Figures from crates.io on 2026-11-12 (total / recent downloads / reverse
dependencies).

| Need | Crate | Decision |
|---|---|---|
| XML reading | `roxmltree` 0.21.1 (104 M / 40 M / 994) | Adopted (ADR-011 at the time). Read-only DOM with positions. To move to `bk-marshal`'s `quick-xml` document after both branches merge (see Follow-ups) |
| Directory walking | `walkdir` 2.5.0 (767 M / 203 M / 7,234) | Adopted: sorted walks, link following with loop detection |
| Snapshots, property tests, tables, temp dirs | `insta`, `proptest`, `rstest`, `tempfile` | Workspace crates |
| Fuzzing | `libfuzzer-sys` 0.4.13 (79 M / 22 M; released 2026-06-04) | Adopted in `fuzz/` only (the `cargo fuzz` standard) |
| RELAX NG validation | `oxixml-relaxng` 0.1.2 (361 / 290 / 2) | Used once as a test oracle, then **removed** (coordinator's decision). The widely used alternatives fail a requirement: `libxml` reaches RELAX NG only through raw FFI (`unsafe`, C library), `xmloxide` ignores `<include>` |
| Version parsing | `semver` | Not used: Ghidra's versions are `<major>[.<minor>]` with `0x`/octal integers |
| Java `HashMap` order | — | Hand-written (`opinion/javahash.rs`); no crate does this |
| One fixed pattern (`RELATIVE_PATHS_PATTERN`) | `regex` | Hand-written (`discard_relative_path`, 30 lines) |

## Commits

`git log --oneline master..HEAD` before this report's own commit (which
follows as `docs(lang): final report for the lang track`):

```text
13d660a docs(lang): fuzzing result in the lang spec's status
ba6b3c9 docs(lang): differences from Ghidra and status in the lang spec
10f55df test(lang): cargo-fuzz target for the three readers
ab88b7f docs(lang): bk-lang benchmark numbers in PERF.md
236ca65 docs(lang): mark QueryOpinionServiceTest ported
e1d434e test(lang): a file name found in several modules resolves to the first
72f1419 test(lang): check the schema tables without a RELAX NG validator
158d2ee fix(lang): pass master's stricter lint configuration
81d8c15 Merge branch 'master' into lang
9a7c775 docs(lang): handover for the lang track
de7452e test(lang): golden snapshots of x86 and 6502 models, registry benchmark
c76f668 test(lang): readers, registry, queries, opinions and the ported Ghidra tests
c39707c test(lang): corpus tests and RELAX NG oracle for the schema tables
4ba78b9 feat(lang): bk-lang crate with .ldefs, .pspec and .opinion readers and the language registry
```
