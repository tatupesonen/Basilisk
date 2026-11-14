# Track `decomp-types` (D02) — status

Spec: `docs/features/decomp-types.md`. Crate: `crates/bk-decomp-types`.

## Done
- Crate skeleton: `meta` (metatypes, sub-metatypes, type classes), `ids`
  (`TypeId` with overlay bit), `entry` (`TypeEntry`, `TypeKind`, flags,
  `hash_name`, `hash_size`), `org` (`TypeEnv`, `DataOrganization`, decode of
  `<data_organization>`/`<enum>`, `setup_sizes`), `compare/identity`
  (`compareDependency` + consistent hash), `compare/propagation`
  (`compare`, `typeOrder`, `typeOrderFormal`), `factory/*` (interning via
  hash indexes, base types and caches, core types, pointers, arrays,
  structures/unions with bitfield layout, enumerations and `getMatches`,
  typedefs, rename, partial types, `getExactPiece`, `concretize`,
  `resizeInteger`, function types from a signature, fork/overlay,
  `dependentOrder`), `query/*` (`getSubType`, holes, nearest arrayed
  components, bitfield collection, `downChain`, `isPtrsubMatching`,
  `printRaw`).

- XML encode/decode (`xml/`) with `TypeSource`, `SpacebaseScopes`,
  `PrototypeCodec` hooks; C declaration parser (`cdecl/`).
- Ported `type_ordering`, `enum_matching`, `enum_matching2`
  (`tests/cpp_testtypes.rs`).
- Oracle generator `tests/oracle/types_oracle.cc` + `regen.sh`; tables
  `tests/data/types_oracle.txt.gz` (198,336 records, six languages) and
  `types_orgs.txt.gz` (all language/compiler pairs). Replay
  `tests/oracle_replay.rs`: all records equal except listed known
  differences (prototype encoding, function-signature storage on 8051,
  `<typegrp>` order). G tests `tests/oracle_dataorg.rs`: 294 pairs' data
  organisation equal; 232 data-test `parse line` declarations parse.

## In progress
- Property tests, fuzz targets.

## Next
- Benchmarks + PERF.md; clippy (incl. Windows target); gate; spec Status
  and Differences; inventory checklist note.
