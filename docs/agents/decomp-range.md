# Track `decomp-range` — report

Spec: `docs/features/decomp-range.md` (D01). Crate: `crates/bk-decomp-range`.
State: finished; both gate runs green (below).

## Built

`bk-decomp-range`: Ghidra's `CircleRange` (`rangeutil.cc` 21–1,490), every
method of spec section 3, depending on `bk-core` (bit helpers) and `bk-pcode`
(`OpCode`; op behaviours for the test model).

- `range.rs` — `CircleRange { left, right, mask: u64, step: i32, empty: bool }`
  (32 bytes, `Copy`); constructors `empty`, `new`, `from_bool`, `single`,
  `full`, `from_parts`; `set_range`, `set_single`, `set_full`; queries
  `is_empty`, `is_full`, `is_single`, `min`, `max`, `end`, `mask`, `step`,
  `count` (getSize, with the "lie by one"), `max_info`, `next`,
  `contains_value`; Ghidra's `operator==`; `Display` = `printRaw`.
- `setops.rs` — `contains`, `intersect` and `circle_union` (→ `Combined::{Done,
  TwoPieces}`), `minimal_container`, `invert`, `set_nz_mask`, `set_stride`,
  `widen`, private `newStride`/`newDomain`.
- `pull.rs` — `pull_back_unary`, `pull_back_binary`. `push.rs` —
  `push_forward_unary`, `push_forward_binary`, `push_forward_trinary` (inputs as
  `[&CircleRange; 3]`, under clippy's argument limit). `compare.rs` —
  `translate_2op` (→ `Translated::{Comparison{op,constant,slot}, Always,
  NotPossible, Never}`), private `convertToBoolean`. `overlap.rs` —
  `encodeRangeOverlaps` with Ghidra's `arrange` string. `arith.rs` — the C++
  conversions written out (`int4` step sign-extended to `uintb`, `uint4`
  arithmetic in `newStride`, shift counts modulo 64, `x/0 = 0`, `x%0 = x`, a
  `sign_extend` that narrows as both reference builds do).

No allocation, no `unsafe`, no `unwrap`/indexing; largest source file 449 lines (`setops.rs`), largest test file 467.

## Tests

All counts from `cargo test -p bk-decomp-range` (macOS) and the gate (Linux):

| Kind | File | Count |
|---|---|---|
| Ported Ghidra tests (S) | `tests/ghidra_unit.rs` — all 117 of `testcirclerange.cc`, same names, with the C++ test's brute-force model (`tests/common/model.rs`, incl. `getStartStopStep`) | 117 + 1 host unit |
| Oracle replay (S) | `tests/oracle_replay.rs` — both tables, 152,913 rows each, every row | 2 (+1) |
| Live regeneration (L) | `tests/oracle_regen.rs` — regenerates, compares the base table, replays the extended set (592,213 rows) | 1 (+1) |
| Properties (S) | `tests/properties.rs` — 11 proptests at 4,096 cases, + size test | 12 (+1) |
| Edge cases (S) | `tests/edge_cases.rs` | 7 |
| No allocation (S) | `tests/no_allocation.rs` (dhat) | 1 |
| Unit (S) | `src/arith.rs`, `src/overlap.rs` | 6 |
| Benchmark | `tests/bench.rs` (`#[ignore]`) | 3 |
| Fuzz | `fuzz/fuzz_targets/bk_decomp_range_ops.rs` | 44.3 M runs / 301 s on the build host, no finding |

`docs/inventory/tests/decompiler-cpp.md`: `testcirclerange.cc` marked.

### Oracle

- Generator `tests/oracle/circlerange_oracle.cc`, linked against the
  reference objects; `tests/oracle/regen.sh [--marks] [--extended]`. Row
  formats, provenance and counts: `tests/data/README.md`.
- Base table: 152,913 rows (Q 88,041 — every 1-byte range with step 1/2/4/8
  and aligned bounds plus random ones; P 20,000 pairs; S 2,000; UP/UF 8,000
  each; B 7,184; F 6,100; N 8,505; K 2,000; T 2,000; M 1,083). Extended set:
  592,213 rows (the spec's 300-range sample squared and 200,000 random pairs,
  12,000 ranges through the unary ops, …), 21 MB compressed: not checked in,
  replayed live by `oracle_regen.rs` whenever the reference exists (the
  `gate` run does this on the build host).
- Determinism: `REGEN_RUNS=3`, byte-identical on both machines, base and
  extended. Two fixes were needed: random draws sequenced one per statement
  (g++ and clang evaluate arguments in opposite orders), and the generator
  never reading an empty range's mask itself.
- **The two hosts' tables are not identical**: 834 rows of the base table
  (5,185 of the extended set) differ, all of one cause, `INT_LEFT`
  push-forward with a shift of 64 or more (rangeutil.cc:1269–1270): g++
  (x86-64) shifts modulo 64; Apple clang (AArch64) vectorises both shifts
  into one `USHL`, which reads the low byte of the count as signed. Both
  tables are checked in (`circlerange_oracle.libstdcxx.txt.gz`, marked, 2.5
  MB; `circlerange_oracle.libcxx.txt.gz`, 2.4 MB) in the form of `bk-cspec`:
  rows where they agree must equal Basilisk; each differing row is recognised
  by recomputing what `USHL` gives (`tests/common/host.rs`) and counted.
  Basilisk follows x86-64. Every x86-64 row agrees with Basilisk.
- **UndefinedBehaviorSanitizer** (clang 19, minimal runtime, `rangeutil.cc`
  and `address.cc` rebuilt into a temporary directory on the build host,
  with replaced handlers so that every event is attributed to its row; pcs
  resolved with addr2line): 13,085 rows, 18 sites — shifts out of range at
  rangeutil.cc:696, 949, 975, 961–962/989–990, 1269–1270, 1288, 1292–1293,
  1308–1309, 1313, 1334–1335, address.cc:1003, address.hh:605; `int4`
  multiplication overflow at 1283; `int64` addition overflow at 1331. Each
  row is marked ` #ub=<check>@<file>:<line>`; all agree with Basilisk; counts
  pinned in `oracle_replay.rs`.
- **valgrind** (3.24, `--track-origins=yes`, fields of every empty input
  left undefined, `VALGRIND_COUNT_ERRORS` per row): 2,777 rows marked
  ` #uninit` — `getMax`/`getMaxInfo` of an empty range (119), `setStride` of
  one (119), `minimalContainer`/`widen` with an empty side (2,539). Basilisk
  uses its zero fields; the table was generated with the same, so they agree.
- Two crashes of Ghidra kept the oracle away from some inputs (below,
  Follow-ups); the generator caps `INT_LEFT` step bounds at 2^30.

### Gate

- `scripts/remote.sh gate; echo $?` → `tests: 2206 passed, 0 failed`,
  `remote: gate exit 0`, 0 (with the reference: `oracle_regen` ran there and
  replayed all 592,213 extended rows of libstdc++ with no difference).
- `scripts/remote.sh gate --no-ref; echo $?` → `tests: 2206 passed, 0
  failed`, `remote: gate exit 0`, 0.
- macOS: crate tests, clippy; Windows: `cargo clippy -p bk-decomp-range
  --all-targets --target x86_64-pc-windows-msvc -- -D warnings` clean (no
  run: rests on CI). `scripts/check-dep-age.py master`: 0 new packages.
  `cargo metadata --manifest-path fuzz/Cargo.toml`: ok.

## Benchmarks

Build host (20-vCPU x86-64 Linux VM), `cargo test -p bk-decomp-range --release
--test bench -- --ignored --nocapture --test-threads=1`: `intersect` 8.0
ns/call, `pull_back_binary` 5.8, `push_forward_binary` 7.8. In `docs/PERF.md`.

## Differences from Ghidra

All in spec section 8 (appended): `translate2Op` has four codes; undefined
C++ computed as both builds compute it (shift counts mod 64, the `int4` step
shift mod 32, wrapping signed overflow, the `SUBPIECE` offset overflow as both
compilers treat it); the one host disagreement (`INT_LEFT` ≥ 64) follows
x86-64; step 0 divides as AArch64 (`x/0 = 0`, `x%0 = x`); `INT_LEFT` with a
step bound above 2^30 gives a defined result where Ghidra traps; `INT_MULT`
returns `false` where Ghidra loops forever; empty ranges have zero fields.

## Gaps

- The checked-in table has fewer pairs than spec 6.2 (100-range sample, 10,000
  random pairs) to keep it at 2.5 MB per host; the full counts are in the
  extended set, which is regenerated and replayed live only where the
  reference exists (the build-host gate; not CI on Windows/macOS).
- Rows where Ghidra crashes (step 0; `INT_LEFT` step bound > 2^30) or hangs
  (`INT_MULT` bound > 2^30) cannot be in the oracle; Basilisk's results there
  are pinned by `tests/edge_cases.rs` only.
- Microsoft's compiler was not run (a third table would slot into
  `host.rs`).

## Spec items found wrong

- 4.2 / 5: `translate2Op` returns 0–3 (also 1 = full, 3 = empty), not "0 or 2".
- 6.2: the 1-byte ranges with steps 1, 2, 4, 8 and aligned bounds number
  87,040, not "about 12,000".
- 6.2: "rows that depend on undefined behaviour are detected by running the
  oracle under UBSan once" — the stock runtime reports each source location
  only once per process, so per-row marks need replaced minimal-runtime
  handlers (done) — and uninitialised reads need valgrind, not UBSan.
- 4.3 says the Rust code computes "what the x86-64 build does" and to list a
  difference only where hosts disagree — they do disagree in one kind
  (`INT_LEFT`), listed.
- 4.2: Ghidra's claim that a failed `intersect`/`circleUnion` leaves the
  receiver unchanged holds (checked by the properties and the table).

## Plugin binding constraints

`CircleRange`, `Combined` and `Translated` are small `Copy` values: items 1
(no lifetimes), 2 (`Send + Sync + 'static`), 6 (owned, keepable) and 12 (no
generics) apply and hold (`edge_cases.rs::public_types_are_plain_values`);
item 4 (typed errors) is moot — no method fails with an error, results are
`bool` or the two enums, which are exhaustive closed sets (Ghidra's return
codes). Items 3, 5, 7–11, 13–15 do not apply to this crate.

## Follow-ups

Defects found in Ghidra itself (for `docs/GHIDRA-BUGS.md`); Basilisk
reproduces the logic defects (they are Ghidra's behaviour) and defines the
crashes:

1. **Crash, x86-64**: `CircleRange::pushForwardBinary`, `INT_LEFT`
   (rangeutil.cc:1265–1275): with `maxStep` above 2^30 the `int4` `step <<= 1`
   overflows to 0 and `normalize()` (rangeutil.cc:30) divides by it — SIGFPE.
   Confirmed: the oracle died with "Floating point exception" on the build host
   when given bound 0x7fffffff. Basilisk: wraps to 0, remainder by 0 = value.
2. **Hang**: `pushForwardBinary`, `INT_MULT` (1235–1239): constant with low 32
   bits 0 and `maxStep` above 2^30 — the doubling reaches 0 and never ends.
   Basilisk returns `false`. (ValueSet uses `MAX_STEP` 32, so unreachable
   from Ghidra's own callers.)
3. **Host-dependent result**: `INT_LEFT` push-forward shifts by `sa` ≥ 64
   (1269–1270, UB): x86-64 and AArch64 builds give different ranges (834 rows).
4. **UB, same on both hosts**: the 18 UBSan sites above, notably
   `(int4)in2.left * 8` (1283), which both compilers optimise into
   "`sa == 0` iff offset 0" while shifting by the wrapped value.
5. **Uninitialised reads**: `getMax`, `getMaxInfo`, `setStride`,
   `minimalContainer`, `widen` on an empty range (valgrind, 2,777 rows).
6. **Unsound results** (found by the enumeration properties, each pinned or
   excluded by name in `tests/properties.rs`/`edge_cases.rs`):
   `contains` of a full stepped range ignores phase (314); `intersect` never
   compares phases of equal steps, and `newStride` misreads wrapping ranges or
   bounds that round past the top as empty/everything (111–128, 595);
   `pullBackBinary(INT_SUB, slot 1)` does not reverse the bounds (942–943);
   `INT_RIGHT`/`INT_SRIGHT` push-forward of a wrapping range is one value short
   (1313, 1329–1335); comparison pull-backs of a both-outcomes range give
   `[0,2)` not everything (820 etc.); `minimalContainer` of a full range
   returns the other range and leaves `right - step + 1` unmasked (478–495);
   `getMaxInfo` ignores step and sign bit, so `INT_MULT`/`INT_LEFT` miss wraps
   (280–297, 1241, 1272); `SUBPIECE` of a full stepped range loses its phase
   (1289); `pullBackUnary(INT_SEXT)` takes `left & step` where `left % step`
   is meant (774).
7. Proposed ADR (coordinator's call): "Where Ghidra's `CircleRange` is
   undefined, Basilisk computes the x86-64 result; the AArch64 build's
   different `INT_LEFT` result is recorded, recognised and counted" — the
   ADR-040 form applied to a compiler rather than a library difference.
8. `bk_core::bits::sign_extend` defines narrowing as truncation; Ghidra's
   builds compute something else. This crate has its own copy (`arith.rs`);
   nothing was changed in `bk-core`.

## Commits

See `git log --oneline master..HEAD` (listed in the final message).
