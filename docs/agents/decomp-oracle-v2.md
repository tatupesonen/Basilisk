# Track `decomp-oracle-v2` — report

`bkstate` version 2: the `@scope` records D06 needs to rebuild a function
scope exactly. Branch `decomp-oracle-v2`.

## The format's new records

After the `G` records of `@scope`, when the function has a local scope
(one line each, tab-separated; example from `switchind` at the end):

```
I	0x4000000000000000	0x3	switchind	0x0	-
E	-
R	stack	s4000000000000000:0	0xfffffffffffffff4	0xfffffffffffffff7	0	0x0
F	stack	0xfffffffffffffff4	0xfffffffffffffff7	s4000000000000000:0
Q	-
```

| Record | Fields |
|---|---|
| `I` | the scope's Ghidra id (`uniqueId`), `nextUniqueId`, display name, parent's id (or `-`), children's ids in id order |
| `C` | per category vector, in category order: category, slots in `catindex` order (`s<id>`, `null` for an empty slot); e.g. `C	0	s4000000000000000,s4000000000000001` |
| `E` | `multiEntrySet` in order (name, dedup) |
| `R` | per record of each space's entry map (spaces in index order, records in record-list order): space, entry ref, first, last, subsort use index, use offset |
| `F` | per fragment (same spaces, multiset order): space, first, last, entry ref |
| `Q` | the dynamic entry list in order |

Entry ref: `s<symbol id>:<index of the entry in the symbol's mapentry>`.
Header `BKSTATE	2	…`. Documented in `tools/reference/README.md`.

**Version 1** remains readable: `StateDump::parse` accepts both versions,
`StateDump::version` says which, `ScopeSection::orders` is `None` for
version 1, and the writer writes back the version it read. A version-1
header with version-2 records is an error.

## Checked in the source, and where it differed from the proposal

- `database.hh/.cc`, `rangemap.hh`: `EntryMap = rangemap<SymbolRange>`
  holds `std::list<SymbolRange> record` and `std::multiset<AddrRange>
  tree`; fragments carry `first, last, a, b, subsort` and a link to their
  record. `subsort` (`SymbolRange::getSubsort`, database.cc:49) is computed
  once, at insertion, from the symbol's `addrtied` flag and the first range
  of the entry's use limit — and the flag can change afterwards
  (`setAttribute`). So each record's stored subsort is written. **Change
  from the proposal:** `R` is one line per record (entry ref, range,
  subsort), not one list line per space.
- **Change:** the ids are in a new `I` record, not in `Z`. That leaves
  version 1's `Z` and its Rust type unchanged, and `I` also carries the
  display name, the parent's id and the child ids.
- **Added:** `C`. `vector<vector<Symbol*>> category` can hold empty slots
  (GHIDRA-BUGS 35); a reader cannot recreate them from `S` records.
- **Added:** `E`. `multiEntrySet` membership is set when `wholeCount`
  reaches 2 (`addMapInternal`, `addDynamicMapInternal`, database.cc:1998, 2025) and is not revisited when a type's
  size changes, so it is not derivable from `wholeCount`.
- **Not added:** the name tree's order (`(name, nameDedup)` is unique),
  the child order (id order: the ids are written), `Scope::owner` (a cache
  link), whether a space has an empty entry map (queries answer the same),
  the database's resolve map (no function scopes in it).
- **Entry refs** use the entry's real index in `mapentry`, in version 1 as
  well. `decomp-symbols.md` 4.5 and 4.21 row 4 say D00's dump writes
  `Symbol::getMapEntryPosition` (which returns 0 for every piece). It does
  not, so D06 should not reproduce the bug to match the dump.
- The dump only reads containers: it calls none of `addMapSym`,
  `addUnassigned`, `clearCategory` or `FuncProto::encode`, so GHIDRA-BUGS
  32–35 cannot be reached. Empty category slots are written as `null`.
- **Scope coverage:** only the function's local scope. D06's test (6.4)
  loads a function scope; the global scope is the architecture's, and
  other scopes' symbols stay `G` references.

## Counts on both builds

`bk-oracle capture all`, twice per build, identical:
- 167 scripts, 607 decompiles, 0 errors.
- Mac against host: 5 files differ, all `floatprint`, by the known causes
  (nan-sign 48 lines, nan-order 8).
- Over the 3,642 state dumps (same on both builds):
  - 2,983 `C` records, 0 empty slots;
  - `multiEntrySet` never non-empty;
  - 42 dumps with dynamic entries;
  - 7,750 `R` records and 8,242 `F` fragments;
  - every record list equals the `(last, subsort)` order. The format does
    not rely on that.
- Fixtures regenerated (`fixtures/decomp-oracle/`).

## Shared references (one step each)

Every file hashed before and after (2,207 files on each machine).
- Changed: `STAMP`, `bin/decomp_bk`, `bin/decomp_bk_dbg`,
  `.state/consoleext.fp` and extension objects under `src/consoleext/`
  (all 11 `dbg/` objects, because their debug info names the new worktree
  path; three `opt/` objects).
- Nothing gone, nothing added, nothing else changed. `bin/decomp` is
  byte-identical (Mac `3f6606af…71ae5`, host `a6183fe3…ccdc04`).
- Host STAMP now: `decomp_bk 7e06d989…`, `decomp_bk_dbg dca65e04…`,
  `console_extension 53bdd852…`.

## Breaking changes for D05 and D06

1. `StateDump` has a new public field `version: u32`, and `ScopeSection` a
   new public field `orders: Option<ScopeOrders>`. Code that builds them
   with struct literals must add the fields; field access is unchanged.
2. New public types: `ScopeOrders`, `ScopeIdRecord`, `CategoryRecord`,
   `MultiEntryRecord`, `EntryMapRecord`, `FragmentRecord`,
   `DynamicListRecord` (`oracle::state`, re-exported).
3. The extension writes version 2. The `switchind.*.state.gz` samples are
   version 2; `switchind.end.v1.state.gz` keeps a version-1 sample.
4. No existing record type, field or name changed.

## Checks

- `scripts/check-dep-age.py master`: 0 new packages.
- Windows-target clippy for `bk-testkit`: clean.
- `cargo metadata --manifest-path fuzz/Cargo.toml`: fine.
- `scripts/remote.sh long fuzz 300 bk_testkit_state`: 0 findings.
- `scripts/remote.sh wine -- -p bk-testkit`: 170 passed, 0 failed.
- `tools/testbed/oracle.sh` from this branch on the host: exit 0, 0
  failures, no drift against the fixtures, 21 s.

## Gates

- `scripts/remote.sh gate; echo $?` → `0`, `tests: 2422 passed, 0 failed`
- `scripts/remote.sh gate --no-ref; echo $?` → `0`, `tests: 2422 passed, 0 failed`

## Commits

`git log --oneline master..HEAD`.
