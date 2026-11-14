# Track `cspec-host` — status report

Brief: make `bk-cspec`'s oracle table host-independent. Ghidra's own answers
differ between libc++ (macOS, clang) and libstdc++ (x86-64 Linux, g++);
find why row by row, define Basilisk's result, test against both tables.

## State

- [x] 1. Generator deterministic and robust (commit dc1e325).
- [x] 2. Both tables generated, diffed, checked in (73a7505).
- [x] 3. Every differing row traced (below).
- [x] 4. ADR text (below, for the coordinator to record as ADR-038).
- [x] 5. Two-table strict replay; stable, non-panicking trial sort.
- [x] 6. `cargo test -p bk-cspec` on the Mac (both env vars set): all pass.
- [x] 6b. Same on the build host; valgrind (below).
- [x] 7. Gates, both on the build host (a 20-vCPU x86-64 Linux VM):
      `scripts/remote.sh gate` (reference set) on 5881376: last line
      `tests: 2033 passed, 0 failed`, exit 0; `scripts/remote.sh gate
      --no-ref` on 3c1bedd: `tests: 2033 passed, 0 failed`, exit 0.
      Commits after 5881376 change only this file. Run from detached HEADs
      of those commits (own `remote.sh` slugs) because the valgrind job
      held the branch's lock.

Done.

## 1. Generator fixes (`tests/oracle/cspec_oracle.cc`, `regen.sh`)

- **Pair order:** byte order of pair id. Ghidra lists pairs in `readdir`
  order of the `.ldefs` files (`FileManage::matchListDir`,
  filemanage.cc:177–203), i.e. the filesystem's (APFS gave `Toy` first,
  ext4 `tricore`).
- **Heavy pair rule:** the first pair of a `.cspec` in that order that
  Ghidra builds gets the signature, trial, query and effect tables. (This
  moves most heavy pairs relative to the old table; Basilisk's replay was
  as clean on the new choice as on the old.)
- **Merged models:** `defineMergedFields` sets `numgroup`, `maxdelay`,
  `thisbeforeret`, `autoKilledByCall` of a `ParamListMerged` to 0/false
  before any use. Ghidra defect: `ParamListMerged(void) :
  ParamListStandard()` (fspec.hh:732) and `ParamListStandard(void) {}`
  (fspec.hh:630) leave them uninitialised; only `ParamListStandard::decode`
  (fspec.cc:1447) sets them, and merged lists are built by
  `ProtoModelMerged::foldIn` (fspec.cc:2829). `assignParameterStorage`
  (fspec.cc:2416) calls `allocateStatus` = `status.resize(numgroup,0)`
  (fspec.cc:790) before `ParamListMerged::assignMap` (fspec.hh:737) throws
  the intended "Cannot assign prototype before model has been resolved";
  garbage that is negative or huge throws `std::length_error` instead.
  With the fields defined, Ghidra's own code runs and gives its intended
  error (the 1,116 `ASSIGN … ERR` rows are unchanged).
- **`regen.sh`:** names the table by library (`cspec_oracle.libcxx.txt.gz`,
  `cspec_oracle.libstdcxx.txt.gz`, detected from `_LIBCPP_VERSION` /
  `__GLIBCXX__`), optional output directory, `REGEN_RUNS=N` runs N times
  and requires byte-identical output.
- **Runs:** Mac `REGEN_RUNS=20`: 20/20 complete, identical, 152,046 lines,
  sha256 `5b7fe23acdc8cef0…` (Apple clang 17, libc++). Build host
  `REGEN_RUNS=20`: 20/20, identical, 152,046 lines, sha256
  `48c44f43da7d5185…` (g++ 14.2, libstdc++). After the owner switched the
  host's CPU model (FMA, AVX2, AVX-512 now visible): 20/20 again,
  **byte-identical to the table from before** — no row depends on floating
  point or the CPU's math variants.
- **valgrind memcheck** (build host, generator built with `-g`): the fixed
  generator completes (exit 0); result line: see "valgrind" below.

## 2./3. libc++ vs libstdc++, row by row

Same pairs, same records, same line count; **119 rows differ**, nothing
else (no SPACE, REG, ORG, MODEL, LIST, ENTRY, RULE, ASSIGN, TSET, Q, JOIN,
SPLITQ row):

| Cause | Rows | Pairs/lists |
|---|---|---|
| A. effect tie order | 56 `EFFECT` | 28 lists: NDS32 BE/LE, RISC-V gcc ×12 (RV32 default/AndeStar_v5/G/GC/I/IC/IMC, RV64 default/G/GC/I/IC); `__stdcall`, `__thiscall`; one swap each |
| B. lookup in a tie group | 24 `EFF` | NDS32:BE 4, RV32 AndeStar_v5 4, RV32I 4, RV64G 6, RV64I 6 (the heavy pairs of those files) |
| C. identical trials | 38 `TRES` | tricore `__stdcall in` 24, Loongarch lp64f `__stdcall in` 14 |
| D. entry-less trials | 1 `TRES` | x86:LE:64 golang `abi-internal out` set 107 |

**A.** `ProtoModel::decode`, fspec.cc:2680, `sort(effectlist…,
EffectRecord::compareByAddress)`; the comparator (fspec.hh:1786) looks at
space index and offset only, so records at one address are equal. RISC-V
names `ra` in `<killedbycall>` and as the compiler-level `<returnaddress>`;
its models name none, so fspec.cc:2676–2678 append the default return
address (kind 3) after decoding. NDS32: `lp` in `<unaffected>`, same
default appended. Corpus-wide 85 of 778 effect lists have ties (89 tie
groups — the "89 ties" known before). Lists of ≤ 16 records (45) come out in
document order from both libraries (libstdc++'s `std::sort` is insertion
sort below `_S_threshold` = 16; libc++ also uses insertion sort for short
ranges). Of the 40 longer lists libstdc++'s introsort partitioning reorders
28 and leaves 12 (tricore ×8, Loongarch lp64f ×2, Hexagon ×2) in document
order by chance; libc++ leaves all 85 in document order, an outcome of its
algorithm on these inputs, not a guarantee.

**B.** `ProtoModel::lookupEffect`, fspec.cc:2463: `upper_bound` with the
same comparator, then `--iter`: the answer is the kind of the *last* record
of the tie group, i.e. whichever the sort put last. libc++ 3 (the appended
return address), libstdc++ 2 (`ra` killedbycall) or 1 (`lp` unaffected).
Every differing EFF probe lies in a tied register (4:2008/4:2004 `ra`, 4:78
`lp`), within the last record's range.

**C.** `ParamActive::sortTrials`, fspec.hh:322 (`std::sort` with
`ParamTrial::operator<`, fspec.cc:1881), from
`ParamListStandard::buildTrialMap`, fspec.cc:921. Two trials with equal
address, size and entry compare equal (the generator's candidate list
contains such duplicates: two entries over 4:ff90:4 on tricore, 5:10e0:4 on
Loongarch). `forceExclusionGroup` (fspec.cc:1017) keeps the first active
trial of the exclusion group and `markGroupNoUse` (fspec.cc:961) marks the
second not used (flags 43 vs 37), so which registered trial (slot) is kept
is the library's choice. Only lists > 16 trials differ (17 on tricore, 17
and 23 on Loongarch); libc++ keeps registration order.

**D.** Same sort: operator< returns false both ways for two trials without
an entry (fspec.cc:1883–1884), so they (sorted last) are all equal. In the
fallback output fill-in, `ParamListStandardOut::fillinMapFallback` sorts
again for each candidate entry with entries set and cleared
(fspec.cc:1659, 1708), so the final order of entry-less trials is whatever
the chain of sorts left. Both libraries scramble the 48-trial tail, each
differently; neither is registration order.

**Other order-dependent code, no row in the table:** merged models'
`ProtoModelMerged::intersectEffects` (fspec.cc:2767) pairs records at one
address positionally (the 6 tie groups in merged models agree in both
tables: their component lists have ≤ 16 records); `lookupRecord`
(fspec.cc:2501, same rule as B); `FuncProto::decode`'s effect sort
(fspec.cc:3673, same as A); `ScoreProtoModel::doScore` (fspec.cc:2728,
`PEntry` by slot only: equal slots with different sizes change the score
with the order). Basilisk sorts all of these stably.

**Comparator defect:** `ParamTrial::operator<` is not a strict weak
ordering in two corner cases: the reverse-stack test uses only the left
trial's entry (two entries of one group, one reverse-stack, compare
inconsistently), and the offset test applies only within one exclusive
entry (trials of one entry with offsets and another entry of the same group
compared by address can form a cycle). `std::sort` with such a comparator is
undefined behaviour (libstdc++'s unguarded insertion can run past the
range). Not reached by any shipped file in the table; Rust's `sort_by` may
panic on it, which was a latent ADR-009 violation in `bk-cspec`.

## 4. Proposed ADR (record as ADR-038)

> ### ADR-038: Ghidra answers that depend on the C++ library's sort
>
> **Context.** Ghidra's decompiler sorts effect lists and parameter trials
> with `std::sort`, which leaves elements that compare equal in an order the
> C++ library chooses, and then answers lookups from that order. The
> `bk-cspec` oracle, generated from the same Ghidra commit on macOS
> (libc++) and x86-64 Linux (libstdc++), differs in 119 of 152,046 rows,
> all from four causes: (A) effect records at one address (`ProtoModel::decode`,
> fspec.cc:2680), (B) `hasEffect` at such an address, which takes the last
> record of the tie (`lookupEffect`, fspec.cc:2463), (C) two trials of one
> entry at one address and size, of which the first after the sort is kept
> (`sortTrials` fspec.hh:322 from `buildTrialMap` fspec.cc:921), (D) trials
> without an entry, which the comparator calls equal (fspec.cc:1881).
> Ghidra's official releases ship decompilers built against libstdc++
> (Linux), libc++ (macOS) and the MSVC library (Windows), so the same Ghidra
> release already gives different answers per platform; none of the three
> results follows from the source.
>
> **Decision.** Basilisk gives one result, defined by the specification
> file alone: every such sort is stable. (A) Effect records at one address
> keep document order, the default return address that `ProtoModel::decode`
> appends last; (B) a lookup that Ghidra answers with the last tied record
> answers with the last in document order (so the model's own or the
> implicit return-address record decides for `ra`/`lp`); (C, D) trials that
> compare equal keep their order from before the sort — registration
> (slot) order on input, the order the previous sorts left in the output
> fallback. Trials are sorted with a stable insertion sort, which gives a
> defined order and never panics even where Ghidra's comparator is not a
> strict weak ordering.
>
> **Consequences.** Basilisk equals Ghidra built with libc++ on every row
> of A–C in today's corpus, and Ghidra built with libstdc++ (and, by its
> insertion-sort threshold of 32, MSVC) on every list short enough for that
> library's insertion sort; D equals neither. The oracle is kept for both
> libraries (`tests/data/cspec_oracle.{libcxx,libstdcxx}.txt.gz`); the
> replay requires rows where they agree to match and recognises and counts
> each row where they disagree (A 56, B 24, C 38, D 1), so a new cause or a
> regenerated table that moves a count fails the test. The rule extends to
> the other order-dependent spots of the same kind (merged-effect
> intersection, `lookupRecord`, `FuncProto` effect decode, prototype
> scoring).

## 5. What changed in `bk-cspec`

- `src/trial.rs`: `sort_trials` and `sort_fixed_position` use a private
  stable insertion sort (`insertion_sort_by`) instead of `sort_by`: same
  result for a strict weak ordering, no panic possible for any comparator,
  libstdc++'s algorithm up to 16 elements. Two unit tests (stability; a
  comparator that is no order: no panic, deterministic, a permutation).
- `src/effect.rs`: doc comments state the rule (behaviour was already
  document order, last-of-group lookup).
- No other behaviour change was needed: Basilisk already sorted stably,
  which is why the libc++ table matched; nothing in `bk-cspec` matched
  libc++ by accident where Ghidra's source defines another answer.
- Tests: `tests/oracle_replay.rs` reads both tables, requires identical
  pair lists and record shapes, compares every row with both; rows where
  they agree must equal Basilisk's, rows where they disagree must be
  recognised by `tests/oracle_common/host.rs` (A: same address in both, the
  lists permutations, Basilisk's tie group in the `.cspec`'s document order
  read by a small independent reader; B: the probe hits a tie group, both
  answers are kinds in it, Basilisk's is the last; C: rows differ only in
  slots of identical trials, Basilisk's row equals the rule; D: rows differ
  only in the entry-less tail, Basilisk has the same head and the same tail
  set) and the counts must be exactly A 56, B 24, C 38, D 1; and every one of
  the 83 tie groups in non-merged models across all pairs must be in
  document order in Basilisk's lists. `tests/oracle_regen.rs` (new):
  with `BASILISK_REFERENCE_DIR`, runs `regen.sh` and requires the fresh
  table to equal the checked-in table of the host's library (5.5 s on the
  Mac); skipped with a reason without it, without bash/c++, or without
  the reference objects.
- Tables: `cspec_oracle.txt.gz` replaced by `cspec_oracle.libcxx.txt.gz`
  (857 kB) and `cspec_oracle.libstdcxx.txt.gz` (859 kB); README rewritten.

## valgrind

Build host, `valgrind --tool=memcheck --track-origins=yes`, both
generators built with `-g` against the x86-64 reference objects
(`vg.sh`-style job, logs under the branch's `~/bk/tmp`):

- **Fixed generator:** completes, 152,046 lines, `ERROR SUMMARY: 0 errors
  from 0 contexts` (only leaks at exit). So no uninitialised read is
  behind any row of either table: all 119 differences are sort order.
- **Generator before the fix:** `Conditional jump or move depends on
  uninitialised value(s)` at `ghidra::ProtoModel::assignParameterStorage`
  and in `std::vector<int>::_M_fill_insert` called from it (from
  `assignTable`), the value "created by a heap allocation" in
  `ghidra::ProtoModelMerged::foldIn` ← `ProtoModelMerged::decode` ←
  `Architecture::decodeProto` — the `numgroup` defect exactly. Under
  valgrind it had produced 30,991 lines after 40 minutes (huge
  `resize`s); it is bounded by the job limit (90 min).

## Test runs

- Mac (macOS AArch64), `BASILISK_GHIDRA_DIR` and `BASILISK_REFERENCE_DIR`
  set, `cargo test -p bk-cspec`: all pass (units 11, derived 50, funcproto
  21, java 12, paramstore 5, properties 4, replay 1, regen 1, corpus 1,
  funcproto_real 1, fuzz replay 1, bench 2 ignored).
- Mac: `cargo clippy -p bk-cspec --all-targets --all-features --target
  x86_64-pc-windows-msvc -- -D warnings` clean.
- Build host (x86-64 Linux, a 20-vCPU VM), with the reference variables,
  `cargo test -p bk-cspec`: all pass, the same counts; the replay prints
  A 56, B 24, C 38, D 1, 0 unexplained, 83 tie groups; `oracle_regen`
  regenerated the libstdc++ table and found it equal (4.95 s). (Run from a
  detached HEAD of the same commit because the valgrind job held the
  branch's lock; `remote.sh` gives a detached HEAD its own slug.)
- `scripts/check-dep-age.py master`: 0 new registry packages.

## Ghidra defects worth reporting upstream

1. `ParamListMerged` leaves `numgroup`, `maxdelay`, `thisbeforeret`,
   `autoKilledByCall` uninitialised (fspec.hh:630, 732);
   `ProtoModel::assignParameterStorage` (fspec.cc:2416) reads `numgroup` in
   `allocateStatus` (fspec.cc:790) before the merged list throws, so the
   intended error can become `std::length_error` or a huge allocation.
   Fix: initialise the fields in `ParamListStandard(void)`, or throw before
   `allocateStatus` for an unresolved merged model.
2. `ParamTrial::operator<` (fspec.cc:1881) is not a strict weak ordering
   (reverse-stack flag read from one side only; offset compared only within
   one exclusive entry), which makes `std::sort` undefined behaviour.
3. Results that depend on the library's `std::sort` order for equal keys:
   effect lists (fspec.cc:2680, 3673) feeding `lookupEffect`/`lookupRecord`
   (fspec.cc:2463, 2501) and `intersectEffects` (fspec.cc:2767); trials
   (fspec.hh:322/323) feeding which duplicate trial is kept and the order
   of entry-less trials; `ScoreProtoModel::doScore` (fspec.cc:2728). Ghidra's
   own Linux, macOS and Windows builds answer differently for RISC-V and
   NDS32 (`hasEffect` on `ra`/`lp`). Fix: `std::stable_sort`.

## Gaps

- **Windows (MSVC's library)** is a third `std::sort`, not run. MSVC's
  `std::sort` uses insertion sort (stable) for ranges of ≤ 32 elements
  (`_ISORT_MAX`) and introsort above. So a Windows Ghidra should equal the
  rule on every effect list and trial list of ≤ 32 records — among the
  differing rows: the RV32I/IC/IMC and RV64I/IC lists (32 records), the
  tricore (17) and Loongarch (17, 23) trial rows — and is unknown on
  NDS32 (35 effects), the 64-record RISC-V lists and the x86-64 golang trial
  row (54). To check: build the reference objects and the generator with
  MSVC (or clang-cl against the MSVC STL), run `regen.sh`'s steps, and diff
  the result with both tables; if it is a third table the harness takes it
  as one more column (`Lib`).
- Cause D's exact order is not computed independently by the test (it is
  what a chain of stable sorts leaves); the test checks the head and the
  set, and the unit tests check that the sort is stable.
- The valgrind run of the generator from before the fix did not finish
  (it had already reported the uninitialised read; see "valgrind").

## Follow-ups

- Coordinator: record the ADR text above as ADR-038 (the code and README
  already cite that number).
- Nothing needed in `bk-decomp-types` or `bk-lang`.
- `docs/agents/decomp-cspec.md` and `docs/agents/remote-build.md` still
  describe the single table; superseded by this report (not mine to edit).
