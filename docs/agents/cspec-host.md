# Track `cspec-host` — status report

Brief: make `bk-cspec`'s oracle table host-independent. Ghidra's own answers
differ between libc++ (macOS, clang) and libstdc++ (x86-64 Linux, g++);
find why row by row, define Basilisk's result, test against both tables.

## State

In progress.

- [x] 1. Generator deterministic and robust (commit dc1e325).
- [x] 2. Both tables generated and diffed (in scratch, not yet checked in).
- [x] 3. Every differing row traced (below); valgrind run pending.
- [ ] 4. ADR text.
- [ ] 5. Two-table replay harness; `bk-cspec` already follows the rules.
- [ ] 6. Tests on both machines.
- [ ] 7. Gates.

## 1. Generator fixes (`tests/oracle/cspec_oracle.cc`, `regen.sh`)

- Pairs in byte order of id (Ghidra lists them in `readdir` order of the
  `.ldefs` files, `FileManage::matchListDir`, filemanage.cc:177–203).
- Heavy pair = first pair of a `.cspec` in that order that Ghidra builds.
- Merged models: `defineMergedFields` sets `numgroup`, `maxdelay`,
  `thisbeforeret`, `autoKilledByCall` of a `ParamListMerged` to 0/false
  before use (Ghidra defect: fspec.hh:630/732 leave them uninitialised;
  fspec.cc:2416 → 790 `status.resize(numgroup,0)` reads the garbage before
  `ParamListMerged::assignMap`, fspec.hh:737, throws as intended).
- `regen.sh` names the table by library (`cspec_oracle.libcxx.txt.gz`,
  `cspec_oracle.libstdcxx.txt.gz`), takes an output directory, and with
  `REGEN_RUNS=N` runs N times and requires byte-identical output.
- Mac: `REGEN_RUNS=20`: 20/20 complete and identical, 152,046 lines, sha256
  `5b7fe23acdc8cef0…` (Apple clang 17, libc++). Build host: 20/20, identical,
  152,046 lines, sha256 `48c44f43da7d5185…` (g++ 14.2, libstdc++). Run again
  after the host's CPU gained FMA/AVX2: 20/20, byte-identical to the
  earlier Linux table — no row depends on floating point.
- With the new heavy rule the libc++ table replays with the same result as
  before (127,088 rows, the one known trial row).

## 2./3. Differences libc++ vs libstdc++ (row by row, same line count)

119 rows differ, nothing else (no SPACE/REG/ORG/MODEL/LIST/ENTRY/ASSIGN/Q/
JOIN/SPLITQ/TSET row):

| Cause | Rows | Where |
|---|---|---|
| A. effect tie order | 56 EFFECT (28 lists × 2) | NDS32 BE/LE, 12 RISC-V gcc pairs; `__stdcall`, `__thiscall` |
| B. lookup in a tie group | 24 EFF | NDS32:BE 4, RV32 AndeStar 4, RV32I 4, RV64G 6, RV64I 6 |
| C. identical trials | 38 TRES | tricore `__stdcall in` 24, Loongarch lp64f `__stdcall in` 14 |
| D. entry-less trials | 1 TRES | x86:LE:64 golang `abi-internal out` set 107 |

A. `ProtoModel::decode`, fspec.cc:2680 `sort(effectlist…, compareByAddress)`
(fspec.hh:1786: space index, offset only). Ties: RISC-V names `ra` in
`<killedbycall>` and as the compiler-level `<returnaddress>`; the model has
none, so fspec.cc:2676–2678 appends the default return address last. NDS32
names `lp` in `<unaffected>`, same default appended. 85 of 778 effect lists
have ties (89 tie groups = the 89 known ties); 45 have ≤ 16 records, where
both libraries use insertion sort (stable); of the 40 longer lists libstdc++'s
introsort (> 16, `_S_threshold`) reorders 28; libc++ (partition above 30
records for trivially copyable types) keeps document order in all 85 by
outcome of its algorithm on these inputs, not by any guarantee.

B. `ProtoModel::lookupEffect`, fspec.cc:2463: `upper_bound` then `--iter`
picks the last record of a tie group, so the answer is that record's kind:
libc++ 3 (return address, appended last), libstdc++ 2/1 (killedbycall /
unaffected). Every differing EFF row probes a tied address (4:2008/4:2004
`ra`, 4:78 `lp`).

C. `ParamActive::sortTrials`, fspec.hh:322 (`std::sort`, operator<
fspec.cc:1881) from `buildTrialMap`, fspec.cc:921. Two trials with equal
address, size and entry compare equal; the generator's candidate list holds
such duplicates (two entries over 4:ff90:4 on tricore, 5:10e0:4 on
Loongarch). The later passes keep the first one used, mark the second
not-used; which registered trial (slot) is first is the library's choice.
Only trial lists > 16 differ (17 on tricore, 17/23 on Loongarch).

D. Same sort: operator< returns false both ways for two trials without an
entry (fspec.cc:1883–1884), so those trials (sorted last) come in library
order. Both libraries scramble the 48-trial tail differently; neither is
registration order.

## Notes

- Other order-dependent spots in Ghidra, no row in the table: merged effect
  intersection `ProtoModelMerged::intersectEffects` fspec.cc:2767 (pairs
  equal-address records positionally); `lookupRecord` fspec.cc:2501;
  `FuncProto::decode` effect sort fspec.cc:3673; `ScoreProtoModel::doScore`
  fspec.cc:2728 (PEntry by slot; equal slots with different sizes change the
  score). Basilisk uses stable sorts in all of them.
