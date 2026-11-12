# Track `lang` — handover

Branch `lang`, worktree `/Users/tatu/slop/basilisk-wt/lang`, crate `bk-lang`.
Spec: `docs/features/lang.md`. This is a **handover at a checkpoint**, not a
final report: the code and tests are in place and green; the documentation
chores, the fuzz target and the full gate are not done (see "Remaining").

State at handover: everything committed, `git status --porcelain` empty.

## Verified (what was actually run, and the result)

All on an Apple M1 Pro, macOS, Rust 1.97.1, Ghidra at commit `42db038f3c`,
with `BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra`.

| Check | Result |
|---|---|
| `CARGO_BUILD_JOBS=2 cargo test -p bk-lang` | **232 passed, 0 failed, 1 ignored** (the benchmark) |
| same with `BASILISK_GHIDRA_DIR=/nonexistent` (skip path) | 232 passed; corpus-dependent tests print a skip line and return |
| `cargo clippy -p bk-lang --all-targets -- -D warnings` | clean (with the lint set on this branch, not `master`'s stricter one) |
| `cargo fmt -p bk-lang --check`, `scripts/check-file-size.sh` | clean; largest file 495 lines |
| **Full gate (`scripts/gate.sh`)** | **not run** |
| Benchmark (release, `--ignored`) | registry scan median 12.8 ms (budget 50 ms) |

Corpus results (tests in `crates/bk-lang/tests/corpus.rs` and
`schema_oracle.rs`):

- **Strict mode reads every file**: 52 of 52 `.ldefs`, 89 of 89 `.pspec`,
  29 of 29 `.opinion` under `Ghidra/Processors`, plus the 3 `.opinion`
  files in `Ghidra/Features/FileFormats/data/languages`.
- **No corpus file violates its schema.** Confirmed independently: every
  one of those files validates against Ghidra's own `.rxg` with a real
  RELAX NG validator (`oxixml-relaxng`).
- **The registry finds 202 languages from 52 `.ldefs` files** (190 not
  deprecated), no duplicate ids, no load failures, 60 processors, 87
  distinct `.pspec` files in use, 32 `.opinion` files, 22 loaders, 339
  opinion constraints. **The spec's "194 from 51" is wrong on both
  counts**: the 51 files directly in a `data/languages` directory hold 193
  languages (the survey's grep presumably counted a commented-out one), and
  Ghidra also finds `RISCV/data/languages/old/riscv_deprecated.ldefs` (9
  deprecated languages) because it searches `data` trees recursively.
- Every file a description names exists (`.slaspec`, `.pspec`, `.cspec`,
  manual index); no compiled `.sla` exists in the source tree (0 of 202),
  as expected.
- All 87 `.pspec` files load through the registry's lazy cache.
- **Five opinion constraints select no language** (valid files; the
  constraints just never match): `avr8.opinion` AVR8/16/extended,
  `minidump.opinion` ARM/little/64, `pagedump.opinion` SuperH3/little/32,
  `PIC24.opinion` PIC24/little/16 (the `.ldefs` spells it `PIC-24`),
  `V850.opinion` V850/32/default. The spec's "every `.opinion` entry maps
  to at least one language" therefore cannot hold; the test asserts exactly
  this list instead.
- **Opinion result order equals a real JVM's.** A throwaway Java program
  (OpenJDK 25, `/usr/bin/java`) put the pairs of three real queries into a
  `java.util.HashSet` with Ghidra's `hashCode` formulas; the iteration
  order was identical to `query_opinions` for 284, 56 and 4 results. Two
  JVM-produced vectors (20 and 100 elements, plus a `HashMap<String,…>` key
  order) are checked in as tests (`queries.rs`, `opinion/javahash.rs`).
- Strict readers vs. the RELAX NG validator on **1,049 single-step
  mutations** of full documents generated from the schema tables (119
  ldefs, 817 pspec, 113 opinion): zero disagreements, other than
  schema-valid documents whose values the reader cannot decode
  (`size="maybe"`), which Ghidra's reader also throws on.

Written but **not** covered by a test:

- `FileIndex::resolve`'s branch for *several* files sharing a name in the
  application (returns the first if the looked-for path ends with the
  name's non-relative part). `discard_relative_path` itself is unit-tested.
- Symlinked module/data directories (walkdir follows links; loop errors are
  skipped with a `tracing::warn!`).
- Anything on Windows or a case-sensitive Linux file system (the
  exact-case file check is tested on macOS's case-insensitive APFS only).
- `JavaHashMap` beyond the point where Java would treeify a bin: not
  emulated, only flagged (`order_is_exact()`); see "Learned".

## Done — module by module

`crates/bk-lang/src` (about 5,800 lines including unit tests), no dependency on other `bk-*`
crates. Third-party: `roxmltree`, `thiserror`, `tracing`, `walkdir`.

| Module | What it is | Against the spec |
|---|---|---|
| `id.rs` | `LanguageId` (non-empty, `Arc<str>`), `CompilerSpecId` (`DEFAULT`), `LanguageCompilerSpecPair` (ordering, `lang:compiler` display, `from_strs` rejecting empties), `Processor` (typed index into the registry's name table) | §4.1 complete |
| `endian.rs` | `Endian` with `name`/`short_name`/`display_name`, `parse` (= `Endian.toEndian`: long or short name, any case), `parse_long_name` (= `.ldefs` reader), `FromStr` | §4.1 complete |
| `value.rs` | `SpecXmlUtils.decodeInt/decodeLong/decodeNullableBoolean` semantics (`0x` hex, leading `0` **octal**, BigInteger-style wrap), Java `String.split` | support |
| `schema.rs` | The three grammars as public static tables (`ElementDef`/`AttrDef`/`ChildDef`/`Card`/`AttrType`): every element, attribute, requiredness, value type, cardinality, order group. Roots: `LANGUAGE_DEFINITIONS`, `PROCESSOR_SPEC`, `OPINIONS` | §7.3 complete (tested against the `.rxg`) |
| `reader.rs` | `Reader`: roxmltree parse (DTD refused), per-element `check` against the tables, strict = error / lenient = `Warning`, positions, `Parsed<T> { value, warnings }` | §5 complete |
| `error.rs` | `Position`, `Mode`, `Violation`, `Warning`, `ParseError{position, kind}`, `ReadError{path,…}`, `RegistryError` (thiserror) | §5 complete |
| `ldefs/{model,read}` | `LanguageDefinitions`/`LanguageDefinition` (all attributes incl. `hidden`, `instructionEndian`, `manualindexfile`), `LanguageVersion` (parse as Ghidra, `Ord`), `TruncatedSpace`, `CompilerDefinition`, `ExternalName`; `parse`, `read_file` | §4.2 complete |
| `pspec/{model,read,address,context,registers,symbols,memory,segment}` | `ProcessorSpec` with every schema element; `AddressSpec` (unresolved `space:offset`), `AddressRange`, `AddressResolver` trait (the resolver hook), `ContextBlock`, `RegisterData`, `DefaultSymbol` (`SymbolAddress::Next`), `MemoryBlock`/`MemoryBlockKind`/`ByteMappingRatio`, `SegmentOp`, `JumpAssist`, `PcodeInject` (body as source text), `Volatile`, `property_keys`, `Section` (top-level element order) | §4.3 complete |
| `opinion/{model,read}` | `Opinions`: flat pre-order `Vec<Constraint>` with `parent` ids (no recursion anywhere, unlimited nesting), `resolved()` = inherited attributes | §4.4 complete |
| `opinion/javahash.rs` | `String.hashCode`, and `JavaHashMap`: iteration order of `java.util.HashMap` (spread, 16-bin start, 0.75 load factor, resize when a bin passes 8 in a table under 64) | §4.4 "ordering of results" |
| `opinion/query.rs` | `OpinionDatabase::{add, query, loaders, order_is_exact}`, `QueryResult`, `secondary_attribute_matches` | §4.4 complete |
| `registry/{mod,scan,paths,query}` | `RegistryBuilder` (`ghidra_root`, `module`, `sla_overlay`, `mode`, `include_hidden`), `LanguageRegistry` (immutable, `Send + Sync`), `LanguageDescription`, `CompilerSpecDescription`, `LanguageFiles`, `LoadFailure`; queries `find`/`language`/`compiler_spec`/`matching`/`for_processor`/`default_language`/`pairs`/`external_descriptions`/`external_pairs`/`defined_external_tool_names`; lazy cached `processor_spec`; `sla_file`; lazy `opinions`/`query_opinions`; `spec_root_from_env`, `SPEC_ROOT_ENV` | §4.5 complete |

Tests (`crates/bk-lang/tests`, about 3,700 lines; 127 unit tests in `src`):

| File | Tests | What |
|---|---:|---|
| `corpus.rs` | 8 | corpus reads strict; registry counts; files exist; RISCV deprecated languages; lazy shared `.pspec`; opinion constraints; real lookups and opinion queries |
| `schema_oracle.rs` | 4 | tables vs `.rxg`: name sets equal; mutation differential with `oxixml-relaxng`; every shipped file validates |
| `read_ldefs.rs` / `read_pspec.rs` / `read_opinion.rs` | 19 / 25 / 10 | every element form, Ghidra's rejections, strict errors with positions, lenient warnings and fallbacks, malformed input, XML 1.1 and BOM, 100,000-deep nesting |
| `robustness.rs` | 6 | proptest: never panics on arbitrary bytes, arbitrary markup, damaged valid documents, arbitrary attribute values |
| `registry.rs` | 13 | discovery on temporary module trees: order, resolution, missing files, exact case, duplicate ids, hidden, excluded directories, `build/data`, GPL, user module, overlay, lazy `.pspec`, thread sharing |
| `queries.rs` | 7 | lookups, pair queries, external queries, opinion inheritance/override/matching, first-result-wins, JVM order vectors |
| `ported.rs` | 7 | `QueryOpinionServiceTest` (4), derived edge cases (1), `SleighLanguageProviderTest` discovery parts (2) |
| `golden.rs` | 6 | insta snapshots: `x86.ldefs`, `x86.pspec`, `x86-16.pspec`, `x86.opinion`, `6502.ldefs`, `6502.pspec` (regenerate with `INSTA_UPDATE=always`) |
| `bench.rs` | 1 ignored | registry scan, opinions, all `.pspec`, one query |
| `common/` | — | local spec-root helper (stand-in for `bk-testkit`), document fixtures, module-tree fixture |

Ghidra tests:

- `ghidra.app.util.opinion.QueryOpinionServiceTest` (4) — **ported**, all
  four, `crates/bk-lang/tests/ported.rs` (`ghidra_*`). Checklist line not
  yet marked.
- `ghidra.app.plugin.processors.sleigh.SleighLanguageProviderTest` (4) —
  **partly ported**: all four are about compiling a `.sla` under a
  cross-process file lock. What applies here is ported: a provider from
  `x86.ldefs` describes `x86:LE:32:default` with its language files (from
  `testSlaThunderingHerds`, `testSlaLockTimeout`), and
  `SleighLanguageFile.fromSlaFilename` finds `mylang.slaspec`/`mylang.sla`
  (from the two lock-file tests). The lock, timeout and read-only-directory
  assertions wait for the SLEIGH compiler (M2). Checklist line not yet
  marked.
- Looked for other tests of the section-2 classes that need no program or
  `.sla` (`LanguageID`, `CompilerSpecID`, `Endian`, pair, query classes) by
  searching every file of `docs/inventory/tests/` for those class names:
  **none found**. `ghidra.framework.main.VectorRegisterPspecTest` (6) and
  `DecompilerPspecVolatilityTest` (4) need a loaded language/program (M1,
  M3); the `.pspec` data they rely on (`vector_lane_sizes`, `volatile`) is
  read and tested here.

## Remaining (in the order I would do it)

1. **Merge `master`** into the branch and fix what its stricter lints
   report (the coordinator said the next agent does this first).
2. **Mark the checklist**: `docs/inventory/tests/features-base.md` line
   `QueryOpinionServiceTest` → `- [x] … → crates/bk-lang/tests/ported.rs`;
   `framework-softwaremodeling.md` line `SleighLanguageProviderTest` → note
   the partial port and that the lock assertions wait for M2 (decide with
   the coordinator whether a partial port is `[x]`).
3. **`docs/features/lang.md`**: append the items under "Differences from
   Ghidra" below to §8 and fill §9 "Status"; correct nothing else in the
   spec (report spec errors instead — they are listed under "Learned").
4. **`docs/PERF.md`**: append under a `bk-lang` heading — Apple M1 Pro,
   release, `BASILISK_GHIDRA_DIR=… cargo test -p bk-lang --release --test
   bench -- --ignored --nocapture`: registry scan (every module of the Ghidra
   tree walked, 52 `.ldefs`, 202 languages) fastest 11.8 ms / median 12.8 ms; scan + opinion
   database 15.6 ms median; scan + all 87 `.pspec` 22.1 ms median; one
   opinion query (ELF MIPS, binary pattern) 5.8 µs median. Other agents were
   building on the machine at the time.
5. **Fuzz target** (`fuzz/`, cargo-fuzz): not started. The spec accepts a
   property test instead (present: `robustness.rs`), but `LOOP.md` asks for
   a fuzz target for every parser of untrusted bytes. One target feeding
   the bytes to the three `parse` functions in both modes is enough.
   `fuzz/Cargo.toml` will be shared with other tracks — expect a merge
   conflict there.
6. A test for the multi-match branch of `FileIndex::resolve` (two modules
   each with `same.cspec`, referenced from a third directory).
7. **Run the full gate**: `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log
   2>&1; echo $?`.
8. Write the final report in this file (replace this handover).

Known gaps to carry into the final report: old-language translators
(`data/languages/old/*.lang`, `*.trans`) are not read (out of scope, M8);
`.cspec`, `.dwarf`, pattern files out of scope; UTF-16 spec files are
refused (`ReadError::Encoding`; none exist); Java's treeified hash bins are
not emulated.

## In flight

Nothing is half-written. The last unit finished was the golden snapshots
and the benchmark. Next would have been items 2–5 above.

Things tried that did not work or surprised, so they are not rediscovered:

- `rustfmt` roughly doubles the line count of test files full of long
  string literals and `assert_eq!` on tuples: two test files that were 600
  lines as written came out at 1,200. That is why the tests are split into
  many small files with shared fixtures in `tests/common/`.
- Integration-test lints are pedantic too: `items_after_statements`,
  `needless_raw_string_hashes`, `format_collect`,
  `redundant_closure_for_method_calls`. `cargo clippy --fix --allow-dirty`
  handles most.
- My first corpus expectations were guesses and wrong (language counts,
  x86-64's compiler ids, which languages share a `.pspec`); the numbers in
  the tests now come from running the code and were cross-checked by hand
  against the files.
- A self-referential `static` (`CONSTRAINT` lists itself as a child) works
  in Rust; no indirection needed.
- The Java programs used for the order vectors are not checked in. To
  regenerate: a `record Q(String lang, String comp)` whose `hashCode` is
  `31 + (31 * (31 + (31 + comp.hashCode())) + (31 + lang.hashCode()))`,
  inserted in order into a `HashSet`, then printed. Run with
  `java File.java`.

## What Ghidra's sources say that the spec does not

**Discovery**

- Ghidra does not glob `Processors/*/data/languages/*.ldefs`. It finds
  *modules* (directories with `Module.manifest`, up to three levels below
  `<root>/Ghidra` and `<root>/GPL`, never inside `build`, never named
  `bin`) and walks each module's whole `data` tree (and `build/data`)
  recursively for files ending in the extension, skipping directories named
  `.svn`, `bin`, `classes`, `developer_scripts`, `ghidra_scripts`, `help`,
  `os`, `resources`, `src`, `test`, any `DATA SEARCH IGNORE DIR:` of the
  manifest, and files starting with `._`. Hence the 52nd `.ldefs` file and
  the three `.opinion` files in `Features/FileFormats`.
- Module order is by directory name in code-point order (a `TreeMap`):
  digits, upper case, lower case — `Z80` before `eBPF`, `tricore`, `x86`.
  Within a module Ghidra uses `File.listFiles` order, which is
  **unspecified**; basilisk sorts by name. This decides
  `default_language`: for `RISCV` it is `RISCV:LE:32:AndeStar_v5`, because
  `andestar_v5.ldefs` sorts before `riscv.ldefs`.
- A file named in a `.ldefs` is looked up beside the `.ldefs` first and
  then **application-wide by file name and extension**
  (`SleighLanguageFile.findFile`). The deprecated RISCV languages depend on
  this: their `.ldefs` is in `old/` and their files one level up.
- File names must match the file system's **letter case exactly**
  (`existsAndIsCaseDependent`), also on case-insensitive file systems.
- `slafile` is resolved through the `.slaspec` of the same stem; the `.sla`
  is expected beside it and need not exist. Only if there is no `.slaspec`
  does Ghidra accept an existing `.sla`.
- `hidden="true"` languages are skipped outside development mode (the spec
  does not mention `hidden`). None exist in the corpus.
- A duplicate language id: the **later** definition replaces the earlier
  one, in the earlier one's position, with an error message.
- A missing `.cspec`/`.pspec`/`.slaspec` makes Ghidra abandon the *rest of
  that `.ldefs` file* (languages before it stay). A missing manual index is
  only logged.

**`.ldefs`**

- `size`, `truncate_space/@size` and both version numbers go through
  `SpecXmlUtils.decodeInt`: `0x` is hexadecimal and a leading `0` is
  **octal**.
- A repeated compiler `id` within a language replaces the earlier entry in
  place (a `LinkedHashMap`); `external_name` entries with an empty tool or
  name are dropped; the description text is not trimmed.
- `getCompilerSpecDescriptionByID` has **no fallback**: an unknown id
  throws, `default` included. The default compiler spec is simply the first
  listed (the schema says so in a comment).

**`.pspec`**

- Both Ghidra readers validate against the schema first, so the schema is
  the real grammar. The spec's element list is right except: `volatile` on
  `<register>` and on `<symbol>`, `size` and `description` on `<symbol>`,
  `overlay` on `<memory_block>`, `ptr_wordsize` on `<data_space>`, `type`
  on `<segmented_address>`, `format` on `<volatile>`, `paramshift`/
  `dynamic`/`incidentalcopy` on p-code elements and `<varnode>` are in the
  schema and were not in the spec's list. The C++ reader additionally
  tolerates `<address_shift_amount>`, which the schema does not have (so it
  is rejected in strict mode).
- **`farpointer` means different things to the two readers.** Java decodes
  the value; C++ treats the attribute's presence as true. Two shipped
  `<segmentop>`s say `farpointer="no"`. `SegmentOp::far_pointer` is
  `Option<bool>` so each consumer can apply its own rule.
- `<memory_block>` booleans: the schema allows `yes`/`no`/`1`/`0`, but
  `MemoryBlockDefinition` only takes `y`/`n`/`true`/`false` and throws on
  the rest. The corpus only uses `true`/`false`.
- `<memory_block>` requires exactly one of `bit_mapped_address`,
  `byte_mapped_address`, `initialized` (an attribute choice): an
  uninitialised block must say `initialized="false"`.
- `<symbol address="next">` is the previous symbol's address plus its
  *raw* `size` attribute — plus 0 when the previous symbol has none.
- `<set val=…>`: decimal or `0x` hex; anything undecodable is read as 0.
- `<volatile>` with a `<register>` child is valid and the decompiler reads
  it, but Java throws "no support for volatile registers yet".
- Top-level element order is free (interleave) but **matters**: a
  `rename` in `<register_data>` applies to everything after it. The model
  keeps the order in `ProcessorSpec::sections`.
- `<jumpassist>`: the decompiler requires `addr_pcode` and
  `default_pcode`; the schema makes all four optional.
- Address strings split at the **last** `:`; the offset is always
  hexadecimal, `0x` optional, with an optional `.unit` suffix.

**Opinions**

- Ghidra does **not** schema-validate `.opinion` files; strict mode here is
  stricter than Ghidra, lenient mode is closer to it.
- **Every `<constraint>` element registers**, not only leaves. An outer
  `<constraint loader="…" compilerSpecID="gcc">` therefore stores *every
  language* under (loader, no primary, no secondary); a query with no
  primary key returns them all.
- Results live in `HashSet<QueryResult>` whose equality ignores the
  preferred flag: of two equal results under the same keys **the first
  added keeps its flag**. Consequence: a parent that already has the keys
  but no `compilerSpecID` shadows the preference of its children.
- Result order is `HashSet` iteration order — a function of
  `String.hashCode` and `HashMap`'s table size. Reproduced exactly while no
  bin holds nine results in a table of 64 or more bins (then Java builds a
  tree; never the case in the corpus — `order_is_exact()` reports it).
- Primary key: exact match, else the first `primary` (in `HashMap` order)
  that is a comma-separated list containing the key, white space removed
  (MIPS: `"8,10"`).
- Secondary key: exact string match; else the union of all constraints
  whose `secondary` is a `0x…` or `0b…` pattern the (signed decimal) key
  matches; else the constraints without `secondary`.
- Languages are matched by processor, endian, size and variant against the
  **non-deprecated** descriptions, with all their compiler specs; preferred
  = the compiler spec id equals the constraint's.
- `endian` accepts `big`/`little`/`BE`/`LE` in any case; `size` is
  `Integer.parseInt` (decimal only). A bad value throws, and Ghidra keeps
  the constraints read before it.

**Queries**

- `getLanguageDescriptions(processor, endian, size, variant)` includes
  deprecated languages; `getLanguageCompilerSpecPairs` excludes them.
- `getDefaultLanguage(processor)` is the first language of the processor in
  load order, deprecated or not.
- External query: no name matches everything; a name without a tool matches
  nothing; names compare ignoring case, tools exactly; the query's compiler
  spec is taken where a language has it, otherwise the language contributes
  all its compiler specs.

## Differences from Ghidra (to append to `docs/features/lang.md` §8)

- A language whose files are missing is reported (`LoadFailure`) and left
  out; later languages of the same `.ldefs` file are still registered.
  Ghidra abandons the rest of the file.
- Readers are atomic per file: a bad `endian`/`size` in an `.opinion` file
  rejects the file; Ghidra keeps the constraints before the failure.
- `.opinion` files are schema-checked in strict mode; Ghidra never
  validates them.
- Within a module, files are visited in name order; Ghidra's order is
  whatever the file system returns.
- `<memory_block>` booleans accept every spelling the schema allows;
  Ghidra throws on `yes`/`no`/`1`/`0`.
- Negative sizes and versions are rejected; Ghidra's `decodeInt` would
  accept them.
- Documents with a DTD are refused (no spec file has one; entity
  expansion is a denial-of-service vector).
- Opinion nesting is read without recursion and without a depth limit.
- Strict mode is implemented by tables restating the schemas rather than by
  running a RELAX NG validator on the `.rxg` files: the schema files are
  not part of what releases bundle (ADR-002 bundles only
  `Processors/*/data`), and the only pure-Rust validator that handles them
  is too young for production input (see below). The tables are proven
  against the real schemas in tests.
- Lenient mode (not in Ghidra) and `LoadFailure` reporting instead of
  message boxes.

## Decisions and crate evaluations

Figures from crates.io on 2026-11-12 (total downloads / recent downloads /
reverse dependencies / last release).

| Need | Crate | Figures | Decision |
|---|---|---|---|
| XML reading | `roxmltree` 0.21.1 | 104 M / 40 M / 994 / 2026-10-24 | **Adopted** (ADR-011, the brief). Read-only DOM with line/column positions, which is what the readers need. `quick-xml` is more downloaded (542 M / 173 M / 2,935) but is a pull parser without a tree or positions. Reads all files, including the four that declare XML 1.1 |
| Directory walking | `walkdir` 2.5.0 | 767 M / 203 M / 7,234 / 2024-03-01 | **Adopted** (added to `[workspace.dependencies]`). Sorted walks, link following with loop detection, `skip_current_dir`. Alternatives: `ignore` (212 M; gitignore semantics not wanted), `jwalk` (13 M; parallel, order not needed), `glob` (724 M; Ghidra matches by extension over a recursive walk, not by pattern) |
| Snapshots | `insta` 1.49.0 | 128 M / 39 M / 5,291 | **Adopted** (already in the workspace) |
| Property tests, tables, temp dirs | `proptest`, `rstest`, `tempfile` | workspace | used |
| RELAX NG validation (test oracle) | `oxixml-relaxng` 0.1.2 | **361 / 290 / 2** / 2026-08-10, Apache-2.0, pure Rust, `forbid(unsafe_code)` | **Adopted as a dev-dependency only — a niche crate, flagged for the coordinator.** It is the only candidate that loads Ghidra's schemas and validates correctly (handles `<include>`, interleave, attribute choices; all 173 corpus files valid; ten hand probes correct). The more-used options fail a requirement: `libxml` (2.6 M / 595 k / 38) wraps only XSD in its safe API — RELAX NG is reachable only through raw FFI, which `unsafe_code = "forbid"` rules out, and it needs the C library (ADR-005); `xmloxide` (86 k / 52 k / 4) ignores `<include>`, which two of the three schemas use, and matches interleave greedily. Rejected: `relaxng-validator` 0.1.0 (35 downloads; 378 lines, a toy), `relaxng` 0.1.0 (12 downloads; published 2026-11-06, younger than the two-week rule) |
| Version parsing | `semver` | 1.19 G / 282 M / 4,313 | **Not used**: Ghidra's version is `<major>[.<minor>]` with `0x`/octal integers and ignored extra parts; `semver` wants three decimal parts. Six lines by hand |
| Java `HashMap` order | — | no crate | Hand-written (`opinion/javahash.rs`, about 120 lines): specific to matching Ghidra's result order |
| Regex for one fixed pattern (`RELATIVE_PATHS_PATTERN`) | `regex` | not evaluated in detail | Hand-written (`discard_relative_path`, 30 lines) rather than a dependency for one pattern; easy to switch if the coordinator prefers |

Design decisions worth knowing before changing things:

- The schema tables (`schema.rs`) are both the strictness engine and the
  proof of coverage. If Ghidra's schemas change, `schema_oracle.rs` fails
  and names what differs.
- `Reader::check` validates one element (attributes, child names,
  cardinality, order, stray text); each reader function calls it for the
  element it handles, then extracts values. Rules the tables cannot express
  (`<memory_block>`'s attribute choice, `first`/`last` together, "at least
  one child") are `Violation::Rule`s raised by the reader function.
- A missing required attribute is an error in both modes; lenient mode
  tolerates unknown or misplaced things and mistyped values where Ghidra's
  reader has a fallback.
- The registry does its file-existence checks from one in-memory listing
  of the module trees (`FileIndex`), which gives the exact-case rule for
  free and keeps the scan at 13 ms.
- `sla_overlay(root)` is how the `../reference` tree is used: it mirrors a
  Ghidra root's layout but has no `Module.manifest`s, so it is not scanned
  for languages; `sla_file()` looks there by the `.sla`'s path relative to
  the Ghidra root.

## For the SLEIGH runtime and loader tracks

- Start from `LanguageRegistry::from_ghidra_root(spec_root_from_env())`
  (or the builder, adding `.sla_overlay(reference_dir)`); get a language by
  `find("x86:LE:64:default")`; paths in `description.files()`; the compiled
  file through `registry.sla_file(id)`; the `.pspec` through
  `registry.processor_spec(id)` (an `Arc<ProcessorSpec>`).
- `.pspec` names are unresolved. Replay `ProcessorSpec::sections` in order
  when resolving register names, because of renames; implement
  `pspec::AddressResolver` for addresses and ranges.
- Loaders: `registry.query_opinions(loader_name, Some(primary),
  secondary)`. Keys are strings. The opinion files key ELF by the decimal
  `e_machine` and match the secondary key as a signed 32-bit decimal
  (`e_flags`), and key PE by the decimal machine number (34404 for x86-64);
  I did **not** read the loaders themselves (`ElfLoader`, `PeLoader`,
  `LoadSpec`) to confirm what each passes — the loader track must. The
  preferred results are the default choices; an empty answer means the
  opinions offer no language.
