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

## In progress
- XML encode/decode (`xml/`), C declaration parser (`cdecl/`).

## Next
- Port `type_ordering`, `enum_matching`, `enum_matching2`.
- Oracle generator under `tests/oracle/`, tables, replay tests.
- Property tests, fuzz targets, benchmarks, PERF.md, spec Status.
