# Track `decomp-symbols` — status

Spec: `docs/features/decomp-symbols.md` (D06). Crates: `crates/bk-context`
(step 0, ADR-043), `crates/bk-decomp-symbols` (new). State: done, awaiting review.

## Status and how to continue

### (a) Done, by spec section

| Spec | What | Commit |
|---|---|---|
| Step 0 / ADR-043 | `bk-sleigh`'s context store moved to `crates/bk-context`, re-exported as `bk_sleigh::context`; `PartMap` public | `de37c32` |
| 4.2 | `EntryMap` (`src/entrymap/{mod,bucket,look}.rs`): fragments in buckets per `(last, subsort)`, C++ hinted-insert order, record list; property test against a literal transliteration of `rangemap.hh` (`tests/entrymap_props.rs`, `tests/common/rangemap_model.rs`) | `fc99a5f` |
| 4.1, 4.4–4.10 | `Database` (`src/database/{mod,resolve,tree}.rs`), data (`src/model.rs`), scope behaviour (`src/scope/{add,build,find,query,names,mutate}.rs`), flags, errors, ids | `89ed526` |
| 4.4, 4.11 | printing and symbol helpers (`src/print.rs`), codecs (`src/codec/{symbol,scope}.rs`, `FunctionCodec` hook) | `0f8d053` |
| 6.2 scope | generator `tests/oracle/scope.cc` (header rows `H P C T` added to the prototype), table `tests/data/scope.txt.gz`, replay `tests/scope_oracle.rs` + `tests/common/{oracle,scope_gen}.rs`: **all 205,104 case rows equal** | `085e561` |
| 4.16, 6.2 context | `src/context.rs` (`ContextNames` over `bk_context::ContextDb`; `bk-context` gained `grow`, `set_tracked_at`, `tracked_points`, `tracked_default`, `has_split_points`); generator `tests/oracle/context.cc`, table `tests/data/context.txt.gz`, replay `tests/context_oracle.rs`: **all 85,713 case rows equal** | `d2ded67` |
| 4.12–4.15, 4.17 | `src/comment.rs`, `src/strings.rs`, `src/cpool.rs`, `src/image/{mod,hex,xml,raw}.rs`, `src/overrides.rs` | `bb47a11` |
| 4.18, 6.2 image, 6.3 G | `src/arch.rs` (decode_volatile, decode_incidental_copy, decode_register_data, decode_readonly, decode_global, add_to_global_scope, add_other_space, build_default_symbols, fill_readonly_from_image, read_loader_symbols, globalify); replay `tests/image_oracle.rs` (needs reference + Ghidra; skips otherwise): **all 8,435 rows equal, 93 data tests** (B/M rows are `print map`) | `96ad501` |
| 5.7 | `src/overlay.rs`: `Overlay` (clone on first write, logged ops, `commit` replays and translates new ids by creation order); `tests/overlay.rs` (sequential commits equal direct changes; two overlays from one base; Send + Sync) | overlay commit |
| 5.5 | `src/spacebase.rs`: `DatabaseScopes` implements `SpacebaseScopes` (frame/scope, `getSubType`, `nearestArrayedComponent*`); `tests/spacebase.rs` | spacebase commit |
| 5.5 | `TypeFactory::type_spacebase` in `bk-decomp-types` with a test | `ab73fdc` |
| 6.4 | `src/restore.rs` (`ScopeImage`, `restore_scope`, `scope_image`), `EntryMap::from_parts`; `tests/state_dump.rs`: every v2 sample of `bk-testkit` (5; the v1 sample skips with a reason) rebuilt from `@scope` (subsorts read from `R`), every `S M Z-ranges I C E R F Q` record equal and the whole dump written back byte-equal; a second test restores an API-built scope (overlaps, use points, multi-entry, dynamic, category holes) and compares 1,700 queries (`query_by_addr`, `query_container`) with the original | state-dump commit |
| 6.5 | `tests/pspec_volatility.rs`: the 12 property assertions of `DecompilerPspecVolatilityTest` (3 tests; the 4th only asserts a decompilation exists, D17) on the pspec variants of `SleighLanguageVolatilityTest.setUp`, plus all 27 variants equal in both element orders; the inventory line stays open for D17 | pspec commit |
| 6.1 names | `tests/names.rs`: `makeNameUnique` (15 cases incl. x form, non-conforming names, the taken-answer error), `buildUndefinedName` (10 cases incl. the predecessor-only look and C++ `>> hex` reading), `buildVariableName` (every rule, the index bumps and the ten-bump fallback) | names commit |
| 6.1 entries | `SymbolData::is_value_close` (was missing; database.cc:726–743); `tests/entries.rs`: addMap flags by scope / global range / use limit (the kludge, properties), the wrap error leaving the scope unchanged, join pieces (endian order, precis flags only for primitive types, constant padding), `getMapEntryPosition`'s quirk, category holes, `isValueClose` (14 cases) | entries commit |
| 6.1 codecs | `tests/codecs.rs` (11): comments (uniq numbering, no-duplicate, clearType, decode renumbering, unknown type, missing text, the comment past uniq 65535 refused), every `getCodepoint` branch (27 cases) and `writeUtf8` (12), the string cache (32-byte reads keeping bytes after the terminator, wide conversion, cached failures), internal strings (hash, truncation), `<stringmanage>` round trip and appending, the constant pool round trip (unknown tag as primitive, short `<data>` error, duplicate key), overrides (`printRaw`, messages, `hasDeadcodeDelay`, round trip skipping unknown children), the XML image (reads, padding grows by one pad per round trip as in Ghidra) | codecs commit |
| 6.6 properties | `tests/properties.rs` (6, proptest, `PROPTEST_CASES` honoured; 20,000 cases each passed on the Mac): `<db>` round trip (exact up to internal ids without read-only symbols; stable from the second round with them), provenance never changes encoding / printed maps / queries, comments, strings, constant pool, overrides round trips | properties commit |
| 6.6 fuzz | seven targets `fuzz/fuzz_targets/bk_decomp_symbols_{scope,binaryimage,commentdb,stringmanage,constantpool,context_points,override}.rs` over `bk_decomp_symbols_shared` (built-in sample + edits, as `bk_testkit_shared`); `tests/fuzz_regressions.rs` replays `fuzz/regressions/bk_decomp_symbols_*` and 65 sample edits per target through the same code | fuzz commit |
| 5.8 | `tests/bench.rs` (`#[ignore]`); numbers in `docs/PERF.md` | bench commit |
| 8, 9 | spec "Differences" appended, "Status" filled | spec commit |
| acceptance follow-ups | image replay prints `image table: 93 data tests replayed, 8435 rows equal` and asserts 93 files; `print_map_equals_the_reference_console` (6.3 L, `#[ignore]`): 93 of 93 equal on the host and the Mac; `all_captured_dumps_rebuild_their_scope_exactly` (6.4 L, `#[ignore]`, `BK_STATE_CAPTURES=<bk-oracle capture all dir>`): 3,642 of 3,642 (harness fixes: parent namespace by id, a stack based on a non-`ram` space, as in 8051's `boolless`); `tests/queries.rs` (7, every row of 4.6 with its database.cc lines; it confirmed the hinted-insert order of equal fragments); constructor/destructor cpool records; properties at 1,000,000 cases; `image_load_budget` (5.8) | follow-up commits |
| 4.19, 5.4 | `src/host/{mod,cache,services,test}.rs`: `ProgramHost` (with `function_summary`, `call_returns` defaulting to `None`, `data_type`), `HostTypes` (TypeSource adapter), `HostDatabase` (ScopeGhidra rules), `HostComments/Strings/ConstantPool/Image/Tracked`, `ScriptedHost`; `tests/host_cache.rs` (6 tests: unasked spaces, holes, clear restores properties, namespace path + hole + ownership, FUN_/DAT_, labels, one comment fill per clear, string/cpool caches, 3d defaults) | `aafa1a6`, tests in the next commit |

All three oracle tables were generated twice on each reference build
(`tests/oracle/regen.sh`): byte-identical between libc++ (Mac) and
libstdc++ (build host): scope sha256 `aeba1648…cb7cd0`, context `327094a1…`
(after header rows; earlier version `b9c75574…`), image `fc4be5c8…`. One
copy of each is checked in; the replays pin an FNV-1a of the text.

### (b) In progress

- Clippy is clean (`cargo clippy -p bk-decomp-symbols -p bk-context
  --all-targets -- -D warnings`), commit "fix(decomp-symbols): clippy".
  Exceptions taken with `#[expect]`: `too_many_arguments` on
  `decode_scope`, `add_equate_symbol`, `add_union_facet_symbol`,
  `build_variable_name` (Ghidra's arguments plus scope and type factory);
  `indexing_slicing` on the const CRC table (compile-time evaluation);
  `many_single_char_names` on three oracle generator functions (they
  follow the C++ generators line by line).
- All tests pass: `cargo test -p bk-decomp-symbols` (state dump 2 + 1 ignored, queries 7, pspec volatility 2, names 3, entries 6, codecs 12, properties 6, fuzz regressions 1, bench 3 ignored, unit 7, entrymap props
  5, scope oracle 1, context oracle 1, image oracle 1 + 2 ignored (skips without
  reference), host cache 6, overlay 3, spacebase 1), `-p bk-context` 10.

### (c) Testbed results, and what is left

- `scripts/remote.sh long fuzz 300 <seven targets>` (at `e791b8f`):
  `fuzz: 7 targets x 300 s on 12 cores, 0 findings` (1.5–3.1 M executions
  per target).
- `scripts/remote.sh wine -- -p bk-decomp-symbols -p bk-context`:
  `wine gnu: 66 passed, 0 failed, 3 ignored`.
- `scripts/remote.sh arm64 -- -p bk-decomp-symbols -p bk-context`:
  `arm64 (qemu): 66 passed, 0 failed, 3 ignored, 0 SKIPPED`.
- Mac: clippy for `x86_64-pc-windows-msvc` clean; 25 s per fuzz target, no
  finding; `scripts/check-dep-age.py master`: `0 new registry packages
  against master; 0 younger than 14 days; 0 lookups failed`, exit 0.
- Acceptance follow-ups (on the build host):
  - `cargo test -p bk-decomp-symbols --test image_oracle -- --nocapture`:
    `image table: 93 data tests replayed, 8435 rows equal`.
  - `cargo test -p bk-decomp-symbols --test image_oracle -- --ignored --nocapture print_map`:
    `print map: 93 of 93 data tests equal to the reference console`.
  - `cargo run --release -p bk-testkit --bin bk-oracle -- capture all target/oracle-captures --runs 1`
    (`run 1: 167 scripts, 8536 files, 0 errors`), then
    `BK_STATE_CAPTURES=$PWD/target/oracle-captures cargo test -p bk-decomp-symbols --release --test state_dump -- --ignored --nocapture all_captured`:
    `state dumps: 3642 rebuilt equal, 0 differ, 0 without a local scope, of 3642`.
  - Properties at `PROPTEST_CASES=1000000` (release, debug assertions and
    overflow checks on, as `tools/testbed/proptest.sh`): `entrymap_props`
    exit 0 in 83 s, `properties` (6) exit 0 in 213 s. `bk-context` has no
    property suite.
  - `image_load_budget`: `load 93 data-test images: basilisk 1827 ms,
    reference console 5056 ms (ratio 0.36)`.
- Final gates at `2a862d8`: `scripts/remote.sh gate` exit 0, `tests: 2490 passed, 0 failed`; `scripts/remote.sh gate --no-ref` exit 0, `tests: 2490 passed, 0 failed`.

### (d) Decisions and traps

- API shape: scope behaviour is methods on `Database` taking a `ScopeId`;
  mutations needing types take `&TypeFactory`/`&mut TypeFactory` (the
  symbol caches its type's size, "unknown" metatype and primitive-whole
  flag so queries need no factory). `resolution_depth` takes `&mut self`
  (its cache).
- Function scopes are created by `create_function_scope` (D07 calls it);
  the scope oracle's replay calls it at `+func`. `Funcdata::getName` is a
  snapshot (the replay keeps the creation-time name).
- `isGlobal()` in Ghidra is "not a function scope" — namespaces are
  global for `persist` and properties.
- Defined where Ghidra is undefined: entry past the end of its space
  checked before any change (ADR-045); stray fragments of a stretched
  record removed on erase; empty category slots skipped; cpool `<data>`
  needs `length` hex tokens; `retypeSymbol` re-add checked for wrap first.
- Entry printing uses `' '` for a space without shortcut — Ghidra's own placeholder (space.cc:72, 99), not a difference.
- Image replay space setup: the language's spaces, then `fspec`, `iop`,
  `join`, then the `.cspec` (stack) — the order Ghidra's indices show.
- Oracle commands: `sh crates/bk-decomp-symbols/tests/oracle/regen.sh REF
  GHIDRA OUTDIR libcxx|libstdcxx` (builds the three generators with
  `build.sh`, runs each twice, compares). On the build host:
  `scripts/remote.sh run -- bash -c 'CXX=g++ sh crates/bk-decomp-symbols/tests/oracle/regen.sh "$BASILISK_REFERENCE_DIR" "$BASILISK_GHIDRA_DIR" target/oracle-host libstdcxx'`.
- Rerun tests on the host: `scripts/remote.sh run -- cargo test -p bk-decomp-symbols`.

### (e) Gate and merges

- Final gates: see (c). Earlier gates: step 0 at `de37c32`, `scripts/remote.sh gate`, exit 0,
  `tests: 2359 passed, 0 failed`. After the clippy fixes at `8b2e16d`:
  `scripts/remote.sh gate`, exit 0, `tests: 2451 passed, 0 failed`.
- Pushing: every commit is pushed to `origin decomp-symbols` (plain push).
- `git merge master`: 1 of 2 used (`dd1746a`, bkstate version 2).

### (f) Open questions, proposed ADRs, Ghidra defects

- Ghidra defects (confirmed with `tests/oracle/rangemap_defects.cc`,
  compiled against Ghidra's own `rangemap.hh`, on the Mac reference):
  1. `rangemap::insert` (rangemap.hh, `insert`, the `if (f <= b)` after the
     loop): a record ending at an existing piece end gets its last
     fragment twice. Harmless; reproduced.
  2. `rangemap::erase` (rangemap.hh, `erase`, `if ((*low).a-1 == b)`): the
     right re-sew looks at the first following fragment only, so a record
     starting at `b+1` that is not first in its piece is stretched left;
     `findContainer` then returns it for addresses it does not cover.
     Reproduced (behaviour).
  3. Follow-on: erasing such a stretched record walks from its own start
     and leaves fragments pointing at the freed list node (use after
     free). Basilisk removes them.
- Spec items found wrong: 4.3 (`getLastAddrOpen` is never invalid); 4.21
  row 16 (`decodeFlowOverride` closes once in this commit); 4.7 (the
  duplicate-scope message has an empty full name); 4.5/5.4 "Model"
  provenance for pspec default symbols (`Provenance::Model` is the AI
  one; Basilisk uses `Imported`); 4.5/4.21 row 4 (dump uses the real index —
  coordinator's correction); 4.12 the comment-key error comes at the
  65,537th comment at one address; `smallvec` is not in the workspace
  (buckets use a small enum instead).
- Follow-up for `bk-cspec`: `FuncProto` has no public `set_override`
  (Ghidra's `insertProtoOverride` marks the prototype); the `ProtoCodec`
  hook's `decode` must return it marked.

## Step 0 — measurement

Build host, `crates/bk-sleigh/tests/reference_bench/compare.sh
$BASILISK_REFERENCE_DIR 7 7` (pinned, 7 rounds), after / before (master
`4d12e6e`) / after in one job; ratio Basilisk / Ghidra, median:

| | after (1) | before | after (2) |
|---|---|---|---|
| decode only | 1.174 | 1.111 | 1.169 |
| decode + lift (counting emitter) | 1.033 | 1.008 | 1.032 |
| decode + text | 1.509 | 1.449 | 1.533 |
| decode + text + lift | 1.215 | 1.185 | 1.227 |

bk decode only 5.36 / 5.20 / 5.39 M instructions/s (best): no slowdown.
