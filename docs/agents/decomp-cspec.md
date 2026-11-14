# Track `decomp-cspec` (D03) — status report

Spec: `docs/features/decomp-cspec.md`. Crate: `crates/bk-cspec`.
Worktree `/Users/tatu/slop/basilisk-wt/decomp-cspec`, branch `decomp-cspec`
(master merged in once, on the coordinator's instruction, for Rust 1.100.0).

## State

Done, pending the coordinator's review. Gate results at the end.

## Built

`bk-cspec` (about 10,500 lines of source in 36 modules, none over 600):

- `types` — `ParamTypes` (size, aligned size, alignment, metatype, name,
  array element, fields, pointed-to; creates pointer, `void`, unknown;
  encodes a type reference and decodes a type), `TypeHandle(u32)`,
  `Metatype`, `TypeClass` with Ghidra's numbers. Object safe.
- `spec/` — `CompilerSpec::read(text, &mut SpaceManager, ReadOptions)`
  (Ghidra `parseCompilerConfig` and every `decode*`, `createModelAlias`,
  `setDefaultModel`), `<specextensions>` read with its own decoder,
  `apply_spaces`/`apply_properties` for another manager,
  `find_cspec_path` through `bk-lang`'s registry. Immutable, `Send + Sync`;
  models in a `Vec` by `ModelId`, names in a `BTreeMap` (Ghidra's map order).
- `entry/` — `ParamEntry` and its decode with `resolveFirst/Join/Overlap`.
- `list/` — `ParamList` with `ListKind` (standard, standard-out, register,
  register-out, merged): assignment (`assignAddressFallback`,
  `assignAddress`, `assignMap`), trial classification (`fillinMap` of each
  kind with every helper), every query, the resolver as sorted partitions
  with binary search, merged folding.
- `rules/` — filters, qualifiers, the ten actions as one enum,
  `MultiSlotAssign`, `MultiMemberAssign`, `DualClassAssign`, the primitive
  extractor, `ModelRule`.
- `model/` — `ProtoModel` (decode, queries, `assign_parameter_storage`,
  effects), merged models, `ScoreProtoModel`, `select_model`, shared actions.
- `proto/` — `PrototypePieces`, `ParameterPieces`, `ParameterBasic`,
  `ProtoStoreInternal`, `FuncProto` (locks, `set_pieces`,
  `update_all_types`, `param_shift`, `resolve_model`, the locked/unlocked
  queries, `is_compatible`, `print_raw`, `encode`/`decode` with
  `EncodeMode::{Ghidra, Basilisk}`), `ModelRef` (an unknown model name with
  the default's behaviour).
- `trial` — `ParamTrial`, `ParamActive`. `effect`, `status` (inline
  per-group state, no allocation), `inject` (payload declarations,
  segment ops, jump assists), `summary` (`FunctionSummary`, `CallSite`,
  serde), `error` (`CspecError` with element path, `ParamUnassigned`).

Dependencies: `bk-core`, `bk-marshal`, `bk-lang`, and workspace crates
`bitflags`, `serde`, `thiserror`, `tracing`. No new third-party crate; no
`unsafe`. Not `bk-decomp-types`, not even as a dev-dependency.

## Tests (all pass; macOS AArch64, Rust 1.100.0)

| File | Kind | What |
|---|---|---|
| `funcproto.rs` | S | `testfuncproto.cc`, 21 tests, Toy:LE:32 built in test code |
| `funcproto_real.rs` | G | the same cases on the real `toy.cspec` + the test's extensions, equal answers |
| `paramstore.rs` | G | `testparamstore.cc`, 5 tests |
| `java_protomodel.rs` | G | the nine Java classes: 12 tests (the spec says 13; the classes have 12), through the C++ model, no exceptions |
| `oracle_replay.rs` | G | 294 pairs, 106 readable `.cspec` files (V850's fails in Ghidra too), 127,088 rows, 0 unexplained differences |
| `corpus.rs` | G | every file decodes; 180/6/1,558/230 counts; per file models/entries/rules = file contents (comments stripped) |
| `derived.rs` | S | 50: every decode error path with Ghidra's message (41 cases), element paths, defaults/aliases/`__thiscall`, merged scoring and selection, `FuncProto` XML round trip for every signature under three models, Ghidra's form, provenance, locked queries, payloads, summary serde |
| `properties.rs` | S | 4 properties: arbitrary text and mutated models never panic; assigned storage disjoint, aligned, in bounds and recovered by `fillinMap`; provenance changes nothing. `PROPTEST_CASES` honoured; regressions file checked in; run once at 1,000,000 cases in release (25 s, all pass, 2026-11-15) |
| `fuzz_regressions.rs` | S | replays `fuzz/regressions/bk_cspec_decode/` (none saved) |
| `bench.rs` | G | two `#[ignore]` benchmarks |
| unit tests | S | 9 |

**What runs without the live tools (CI):** everything. The G tests need
only the Ghidra source tree (the `.cspec` files); spaces and registers come
from the checked-in table. Without the spec root (CI): `funcproto.rs` (21),
`derived.rs` (50), `properties.rs` (4), units (9), fuzz replay — 85 tests,
covering decoding, every error message, assignment, recovery, FuncProto XML,
merged models, summaries. The G tests print `SKIPPED` with the reason.
Verified with both variables unset and with the spelling
`/Users/tatu/slop/basilisk-wt/../ghidra`.

**Oracle (L):** `tests/oracle/cspec_oracle.cc` + `regen.sh` (C++11 pinned,
`-fno-access-control -fsigned-char -ffp-contract=off`, against
`reference/src/cpp/com_opt/*.o`, rebuilt reference); `signatures.txt`
(186 prototypes, 31 structures). Table `tests/data/cspec_oracle.txt.gz`,
152k records, 856 kB, provenance in `tests/data/README.md`. **Host
dependence:** no floating point, `long`, unordered or pointer-keyed
container, no argument-order dependence. Ghidra itself sorts effects and
trials with `std::sort`: equal keys are in libc++ order here and would be in
libstdc++ order on x86-64 Linux. 89 effect-list ties exist (Xtensa, CR16C
…) and matched our stable order on libc++; one trial row differs only in
order. **The table could differ on x86-64 Linux in those tie orders**;
regenerating there would show it (not done; no access to that machine by
instruction).

Fuzz: `bk_cspec_decode` in `fuzz/`, 60 s, 1,164,365 runs, no finding
(nightly, macOS, seeded with three `.cspec` files in the git-ignored corpus).

## Benchmarks

`BASILISK_GHIDRA_DIR=../ghidra CARGO_BUILD_JOBS=2 cargo test -p bk-cspec
--release --test bench -- --ignored --nocapture --test-threads=1`: reading
`x86-64-golang.cspec` (largest, 16 kB) 160 µs; 1,000,000 assignments on
x86-64 gcc `__stdcall` in 460 ms (460 ns each). In `docs/PERF.md`.

## How D02's hooks are met (no dependency either way)

- **`PrototypeCodec`** (D02 `xml/proto.rs`): a later crate that depends on
  both (D07 `bk-decomp-core`, or a small bridge module there) implements it
  as `CspecPrototypeCodec { spec: Arc<CompilerSpec>, manager:
  Arc<SpaceManager> }`. It wraps the factory in an adapter implementing
  `ParamTypes` (`TypeId` ↔ `TypeHandle`, the factory's `encode_ref` /
  `decode_type`, `pointer`, `void`, `base(size, unknown)`); `encode` builds a
  `FuncProto` (`set_internal` + `set_pieces` from the `CodeSignature`) and
  calls `FuncProto::encode(EncodeMode::Ghidra)`; `decode` calls
  `FuncProto::decode` and returns `pieces()`. Because `encode` gets
  `&TypeFactory` while assignment may create pointer types, the adapter
  assigns in a fork (`TypeFactory::fork`) of the factory.
- **`TypeEnv::default_model`**: `CompilerSpec::default_model_name()`.
- **`has_model` callback of D02's C parser**: `|n| spec.has_model(n)`;
  `__thiscall` is always there (the reader adds the alias when absent, as
  Ghidra does).
- **Parameter count after storage assignment** (D02's `compareBasic`): the
  count is `FuncProto::num_params()` after `set_pieces` (hidden return
  included; 0 with `ERROR_INPUTPARAM` when assignment fails, as on 8051).
  This needs a D02 change, see Follow-ups.
- **Expected to disappear when wired:** the 48 `<prototype>`-encoding
  records (the codec writes Ghidra's text) and, with the follow-up, the 11
  function-type `compare`/`compareDependency` records (8051). The one
  `<typegrp>` order record is D02's own and stays.

## Plugin binding (constraints doc)

Items 1–4 and 6 apply: `CompilerSpec`, `ProtoModel`, `FuncProto`,
`FunctionSummary` are owned, lifetime-free, `Send + Sync + 'static`
(checked by a test); ids (`ModelId`, `TypeHandle`) are plain values;
`CspecError` is a `thiserror` enum, `#[non_exhaustive]`, with structured
fields; results (pieces, trials, summaries) are owned values. Queries take
`&SpaceManager`/`&CompilerSpec` explicitly (item 6: a binding holds them in
an `Arc` beside the handle). Items 5, 7–10 do not apply (no large
collections, no long operations).

## Differences from Ghidra

Appended to the spec, section 8: prototype before `<stackpointer>`;
stable sorts; hostile values refused and recursion bounded; unknown
elements as errors in lists, segment ops, jump assists, prototypes;
`separatefloat="false"`; merged-list fields defined; `FuncProto::decode`
skips `<retparam>` (Ghidra's own round trip does not hold); rules name
entries by index; payload ids continue after the `.pspec`'s; kept
elements. Reproduced and noted: default model first by name, prefer-split
sorted, alias share-stack reset, `checkFit`, locked
`getBiggestContainedInputParam`, merged output list class.

## Spec corrections

- The Java classes hold 12 tests, not 13.
- "The default model is the first model if none was named": Ghidra takes
  the first by name (`std::map`).
- "Decode without a stack": Ghidra crashes there (see differences).
- 4.5: the rules never ask whether a structure has bitfields (Ghidra's C++
  extractor walks fields only); the trait has no such method.
- 6.6 "equality with the oracle's encode": the oracle has no `FuncProto`
  encode records — Ghidra's type references carry factory ids the test type
  model cannot reproduce. Instead the XML form is checked against Ghidra's
  element and attribute set and round-tripped for every signature.
- The oracle's heavy tables cover one pair per `.cspec` (106 files); the
  decode dump covers all 294 pairs.

## Gaps

- No `FuncProto` encode records in the oracle (above).
- Registers for the G tests come from the table; the second
  `testfuncproto` version uses the real Toy `.cspec` with those registers,
  not a `.sla`-backed register source (none exists yet).
- `<global>` ranges are kept unresolved (`RangeProperties`); resolution
  with the OTHER space is done in the replay, as D06 will.
- User ops named by fix-ups and segment ops are not checked against the
  language (needs D07).
- Not run: Windows tests (Docker/Wine not used in this session); Linux
  tests; regeneration of the table on x86-64 Linux.

## Follow-ups

- **D02 (`bk-decomp-types`)**: to fix the 11 8051 records, give
  `TypeFactory` a hook at function-type creation, e.g.
  `PrototypeCodec::finish_signature(&self, f: &mut TypeFactory, sig:
  CodeSignature) -> CodeSignature`, called from `type_code_from_signature`,
  so the signature holds the parameters `FuncProto` ends with (or a
  `params_after_storage: Option<u32>` field compared by `compare_basic`).
- **D07**: wire `CspecPrototypeCodec` as above; resolve user ops of
  `call_other_fixups()` and `segment_ops()`; pass the `.pspec`'s payloads
  through `ReadOptions::injects` so ids match Ghidra's; own the program's
  manager (`apply_spaces`, `apply_properties`).
- **D06**: resolve `globals()` into the global scope, plus the OTHER space
  (Ghidra `addOtherSpace`).
- Regenerate the oracle table on x86-64 Linux to settle the tie orders.

## Commits

See `git log --oneline master..HEAD` (listed in the final message).
