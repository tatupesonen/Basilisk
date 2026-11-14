# Track `decomp-types` (D02) — status

Spec: `docs/features/decomp-types.md`. Crate: `crates/bk-decomp-types`.
State: **done**, pending the coordinator's review and merge.

## Built

`bk-decomp-types` (≈7,100 lines of source in 30 modules, none over 650):

- `meta` — `Metatype`, `SubMetatype`, `TypeClass` with Ghidra's numbers
  and names (`metatype2string`, `string2metatype`, `string2typeclass`).
- `ids` — `TypeId(u32)`; the top bit marks an entry of a fork's overlay.
- `entry` — `TypeEntry` (common part + `TypeKind`, one variant per class of
  `type.hh`), `TypeFlags`, `Field`, `BitField`, `CodeSignature`,
  `hash_name`/`hash_name_bytes` (sign-extending, ADR-021), `hash_size`.
- `org` — `TypeEnv` (architecture facts), `DataOrganization`
  (`decodeDataOrganization`, `parseEnumConfig`, `setupSizes`,
  `from_cspec`).
- `compare/identity`, `compare/propagation` — `compareDependency` (with a
  hash consistent with it), `compare`, `typeOrder`, `typeOrderFormal`.
- `factory/*` — `TypeFactory`: interning (`findAdd`, `insert`), base types
  and caches, default core types, pointers (plain, named, with space,
  relative ephemeral/named, resized, strip-array, truncation),
  arrays, structure/union stubs and `setFields`, `assignRawFields` with
  bitfield layout, enumerations (`assign_values`, `set_enum_values`,
  `enum_matches`), typedefs, rename, incomplete typedefs, partial types,
  `exact_piece`, `concretize`, `resize_integer`, function types from a
  signature, `destroy_type`, `clear`, `clear_noncore`, warnings,
  `sorted_ids`, `dependent_order`; `fork` (per-function overlay).
- `query/*` — `sub_type`, `hole_size`, nearest arrayed components,
  `find_smallest_container`, `is_primitive_whole`, bitfield collection,
  `struct_truncation`, `down_chain`, `is_ptrsub_matching`,
  `is_offset_valid`, `evaluate_thru_parent`, `ptr_to_from_parent`,
  `print_raw`.
- `xml/*` — encode/decode of every kind, the factory (`<typegrp>`) and
  `<coretypes>`; hooks `TypeSource` (host types on demand, with
  provenance), `SpacebaseScopes` (D06), `PrototypeCodec` (D03) with the
  default `SignatureCodec`.
- `cdecl/*` — lexer (Ghidra's state machine and line buffer, for identical
  error messages), recursive-descent parser with bison's error timing,
  `parse_type`, `parse_prototype`, `parse_declaration`.

## Tests (all pass; macOS AArch64)

- Ported (S): `type_ordering`, `enum_matching`, `enum_matching2`
  (`tests/cpp_testtypes.rs`). The `testtypes.cc` line is annotated "3 of
  8" in `docs/inventory/tests/decompiler-cpp.md`; the five `cast_*` tests
  belong to D08, which ticks the line.
- Oracle replay (S, `tests/oracle_replay.rs`): 197,330 records over six
  languages equal Ghidra's except 60 listed known differences (48
  `<prototype>` encodings, 11 function-type comparisons that depend on
  storage assignment on 8051, 1 `<typegrp>` order); 1,000 `hashName`
  values equal.
- Kind G (`tests/oracle_dataorg.rs`, skip with a printed reason without
  the spec root): data organisation of all 294 language/compiler pairs
  (106 `.cspec` files) equal; all 232 data-test `parse line`
  declarations parse.
- `tests/xml_smoke.rs` (round trip, warnings, bitfield quirk, `TypeSource`
  hook and provenance), 15 unit tests, 11 property tests (9 `proptest`
  properties at 1,024 cases: interning idempotent, `compare` antisymmetric,
  `compareDependency` + id a total order, dependency order, fork equals a
  flat factory and dropping it leaves the parent's encoding, provenance
  changes nothing, decoders and parser never panic; plus nesting limits,
  fork rules and two directed fork tests from proptest's regressions file
  `tests/properties.proptest-regressions`). `PROPTEST_CASES` raises the
  count above 1,024: every property passed at 100,000 and at 1,000,000
  cases (2026-11-14, release, 8 s and 87 s).
- Fuzz: `bk_decomp_types_xml`, `bk_decomp_types_cdecl` in `fuzz/`, each
  60 s without a finding (3.4 million runs each).
- Run with `BASILISK_GHIDRA_DIR` set, unset (G tests print `SKIPPED`), and
  with `/Users/tatu/slop/basilisk-wt/../ghidra`.
- `cargo clippy -p bk-decomp-types --all-targets --target
  x86_64-pc-windows-msvc -- -D warnings` clean. Windows and Linux test runs
  rest on CI.
- Gate (`scripts/gate.sh`, 2026-11-14), after the fork fix, run twice: exit 0 both times, "tests: 1719 passed, 0 failed" (before the fix: 1717).

Oracle generation (L): `tests/oracle/regen.sh` compiles
`tests/oracle/types_oracle.cc` (`c++ -std=c++11 -fno-access-control
-fsigned-char`) against `reference/src/cpp/com_opt/*.o`; tables in
`tests/data/` with provenance in `tests/data/README.md` (Apple clang
17.0.0, Darwin arm64). **Host dependence:** the tables involve no floating
point, no `long`, no unordered containers; `char` signedness is pinned by
the reference build's `-fsigned-char` (so `hashName` is x86-64's). Only the
order of `<typegrp>` (`dependentOrder`, pointer-keyed in Ghidra) may
differ on x86-64 Linux, and the replay already compares it up to order.
Regenerating on the x86-64 box would confirm this.

## Fix after the first merge attempt (2026-11-14)

The integration gate found a counter-example to
`fork_answers_as_a_flat_factory`: the base factory left a structure stub
incomplete (its field list was refused), and the fork completed it. The
fork was wrong, not the test: Ghidra has one factory and completes a stub
in place (`TypeFactory::setFields`, also reached from `decodeStruct` when a
host supplies a type during decompilation), keeping its id, and spec 4.10
requires the fork to answer as that flat factory. The fork refused with
`FrozenParent`, a restriction of my own. Now a fork copies a parent entry
it changes into its own layer under the same `TypeId`, masks the parent's
index entries for it and indexes the copy; the parent never changes. A
second counter-example then showed that raising a found parent type's
provenance made such a copy without indexing it (duplicate on the next
look-up); fixed. Both seeds are in the checked-in regressions file, and
both cases have directed tests
(`fork_completes_a_parent_stub_under_the_same_id`,
`fork_finds_a_parent_type_whose_provenance_it_raised`). The first gate run
had not hit the case because proptest draws new cases each run and the
regressions file was not checked in.

## Benchmarks

`CARGO_BUILD_JOBS=2 cargo test -p bk-decomp-types --release --test bench -- --ignored --nocapture --test-threads=1`:
interning 1,000,000 requests with ~90 % repeats in 33.5 ms (33 ns each);
decoding a 10,003-type `<typegrp>` in 16.1 ms (1.6 µs/type). In
`docs/PERF.md`.

## Differences from Ghidra

Recorded in the spec, section 8 (appended): hash indexes with on-demand
identity order, no name interning; defined order where Ghidra would cast
to the wrong class; `level` clamp; tombstones; fork rules and provenance
merge; function types as declared signatures and the reduced
`<prototype>`; `parse_declaration` returns `extern` prototypes; lexer
newline fix, input/nesting limits; `decodeTypeWithCodeFlags` opens the
inner element; reproduced quirks (bitfields not round-trippable,
`partenum` unreadable, `struct <existing>` a syntax error, char-constant
values, `int4 int4`); `getBase`/`getAlignment` edge cases; spacebase via
hook; data organisation read here.

## Gaps

- Function prototypes' storage (extrapop, addresses, effects, hidden
  return parameters) is D03's, through `PrototypeCodec`. Until then,
  `encode` of a function type is not Ghidra's text, and comparing function
  types whose model would add or drop parameters can differ (8051).
- `TypeSpacebase` look-ups are D06's, through `SpacebaseScopes`.
- `testtypes.cc` stays open for the five `cast_*` tests (D08).
- Tables generated on macOS AArch64 only (see host dependence above).

## Follow-ups

- **D03 (`bk-cspec`)**: implement `PrototypeCodec` for `FuncProto`;
  supply the default model name (`TypeEnv::default_model`) and the model
  names the parser's `has_model` callback should accept (Ghidra always adds
  `__thiscall`). Ghidra's `TypeCode::compareBasic` counts parameters after
  storage assignment — a hidden return parameter counts — so D03 should
  give the signature the parameters `FuncProto` ends with.
- **D06**: implement `SpacebaseScopes` (scope ↔ frame, `sub_type`,
  `nearest`) and `TypeSource` for the host trait; `getTypeSpacebase` is
  reached by building a `Spacebase` entry (no public constructor yet — add
  one when D06 needs it).
- **D08**: the resolution algorithms use `union_field`, `fields()`,
  `struct_truncation`; port the five `cast_*` tests and tick the line.
- **D09**: the console's `pointer setting` (offset form) is emulated in
  `tests/oracle_dataorg.rs`; the real command belongs to the data-test
  runner.
- Ghidra bug worth noting upstream: `TypeBitField::encode` omits the `id`
  that `TypeBitField`'s decoder requires.
- No new third-party crates; `Cargo.lock` only adds `bk-decomp-types`.
