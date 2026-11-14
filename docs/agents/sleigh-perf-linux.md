# Track `sleigh-perf-linux`: `bk-sleigh` at least as fast as Ghidra's C++ on x86-64 Linux

Status: in progress (2026-11-14).

## How to measure

On the build host (x86-64 Linux; pinned to one core, both engines
interleaved in one job):

    scripts/remote.sh run -- bash -c 'crates/bk-sleigh/tests/reference_bench/build.sh "$BASILISK_REFERENCE_DIR" && crates/bk-sleigh/tests/reference_bench/compare.sh "$BASILISK_REFERENCE_DIR" 5 7'

On the Mac (unpinned; macOS cannot pin):

    crates/bk-sleigh/tests/reference_bench/build.sh ../reference
    crates/bk-sleigh/tests/reference_bench/compare.sh ../reference 5

`build.sh` now runs on Linux as well (clang++ -O2, ELF `.text`; on the
Mac Apple clang `-arch x86_64`, Mach-O `__text` as before). The two
hosts' inputs therefore differ (Linux: 410,462 bytes, 107,047
instructions, 454,144 ops; Mac: 538,553 bytes, 147,953 instructions,
608,674 ops); each comparison is between engines on one host and one
input. `compare.sh` runs `bench_pcode` with `BK_BENCH_SINGLE=1` (the
four single-thread sweeps, best of 5 inside) and `slabench` (the same
four, best of 5 inside), REPS rounds, and prints best and median over
the rounds.

Profiling on the host: `BK_PROFILE_MODE=decode|text|lift
BK_PROFILE_SECONDS=5 perf record … bench_pcode profile_lift_x86_64
--exact --ignored`; `slabench … RUNS MODES` (modes digits 0–3) for the
reference. `perf annotate` cannot read this toolchain's debug
information on the host (objdump fails, llvm-objdump makes perf crash),
so `reference_bench/hot.py` gives an instruction-level profile of one
symbol from `perf script` and `llvm-objdump -l`.

## Measurements

### Before (master 12f1705)

Build host: a 20-vCPU x86-64 Linux VM, host CPU model **AMD Ryzen
Threadripper 7970X** (Zen 4; AVX2, BMI1/2, AVX-512 exposed), Rust
1.100.0, reference g++ 14.2 -O2. Load average 3.5–4.0 at the start
(another branch idle, the testbed idle). 5 rounds, M instructions/s,
best / median:

| | basilisk | Ghidra C++ | basilisk / Ghidra (median) |
|---|---:|---:|---:|
| decode only | 3.98 / 3.87 | 4.67 / 4.52 | 0.86 |
| decode + text | 2.83 / 2.69 | 2.20 / 2.16 | 1.24 |
| decode + lift (counting emitter) | 1.74 / 1.69 | 2.26 / 2.22 | 0.76 |
| decode + text + lift | 1.47 / 1.42 | 1.47 / 1.44 | 0.99 |

With the host CPU exposed the gap is smaller than the 25–30 % recorded
with the baseline virtual CPU, but it is still there: decode 14 % and
decode + lift 24 % behind.

Mac (M1 Pro, shared; load average 2.5 before, 9.5 after the build), 5
rounds:

| | basilisk | Ghidra C++ (Apple clang) |
|---|---:|---:|
| decode only | 3.33 / 3.32 | 3.25 / 3.24 |
| decode + text | 2.45 / 2.44 | 1.53 / 1.53 |
| decode + lift | 1.62 / 1.62 | 1.60 / 1.60 |
| decode + text + lift | 1.39 / 1.39 | 1.02 / 1.02 |

### What the profile showed (build host, before)

`perf stat`, decode only, pinned: basilisk executes about 4,700 machine
instructions per decoded instruction at 3.6–3.7 instructions per cycle;
Ghidra about 3,000 at 2.5–2.8. Branch mispredictions (raw event
`r00c3`): 1.16 per decoded instruction for basilisk, 1.38 for Ghidra.
So basilisk is not losing on mispredictions, cache misses or the
allocator (it allocates nothing per instruction; Ghidra's sweep does
not show `malloc` either once loaded): it simply executes about 55 %
more instructions, at a higher IPC that does not make up for it.

`perf record`, decode only: `resolve::walk` 41 %, `Env::choose`
(decision tree) 17 %, `set_constructor` 17 %, `Env::eval` 7 %,
`resolve` 6 %, `context_match` 4 %. Decode + lift: `walk` 21 %, the
p-code `Builder::build` 19 %, `resolve_handles` 14 %, `choose` 10 %,
`set_constructor` 7 %, `eval` 6 %.

### Changes so far (build host, 5–7 rounds each, median basilisk / Ghidra)

| After commit | decode | decode + lift |
|---|---|---|
| before (12f1705) | 3.87 / 4.52 (0.86) | 1.69 / 2.22 (0.76) |
| `Env` by reference, handles apart from nodes (b9653a1) | 4.21 / 4.60 (0.92) | 1.75 / 2.24 (0.78) |
| laid-out decision trees, context changes per constructor (6eb8370) | 4.09 / 4.17 (0.98) | 1.68 / 2.04 (0.82) |
| handle and varnode helpers inlined (62d6baf) | 4.39 / 4.59 (0.96) | 1.88 / 2.26 (0.83) |
| window loaded in place, `fix`/`locate` forced inline (ce170a4) | 4.33 / 4.32 (1.00) | 1.86 / 2.17 (0.86) |
| exports beside the constructor tables, walk keeps a node index (d2c50c2) | 4.48 / 4.61 (0.97) | 1.95 / 2.27 (0.86) |
| two-byte `Fault` for inner decode functions (09cbe2b) | 4.69 / 4.63 (1.01) | 2.09 / 2.26 (0.93) |
| decision nodes in 16 bytes (889fac8) | 4.95 / 4.50 (1.10) | 2.12 / 2.22 (0.96) |
| fixed-varnode fast path, leaf evaluation, no handle refill (d7a9eb9) | 4.85 / 4.54 (1.07) | 2.16 / 2.23 (0.97) |
| tree walk with plain branches (8374b87) | 5.11 / 4.64 (1.10) | 2.15 / 2.24 (0.96) |
| walks share the instruction's constants (b634fe0) | 4.75 / 4.62 (1.03) | 2.16 / 2.24 (0.97) |

The host's speed drifts by a few per cent between runs even at load
average below 1 (another tenant of the physical machine); only the
ratio within one run is meaningful.

The main x86-64-specific finding: several hot values were written field
by field and read back with a wider load (the node vector's header copied
into `Env` right after it grew; `FixedHandle` and `VarnodeData` returned
through memory and copied with 16-byte loads; a walk's 32-bit child range
read as one 64-bit load; the 16-byte window assembled byte by byte and
copied). x86-64 cannot forward a load from several smaller stores and
stalls until they retire; the M1 is far more forgiving, which is most of
why the Mac was ahead and the Linux host behind. The rest is less work
per instruction: decision trees, constructor exports and context changes
laid out for the decoder, `Result`s that fit in registers.

Mac (M1 Pro) after d2c50c2: decode 3.68 / 3.28, decode + lift 1.86 /
1.62 (both up from 3.32 and 1.62 before).

## Corrections

- (a) Label numbers are 32 bits (ce11410): `pcode/build.rs`
  `label_number`, used by `LABEL` and by `resolve_relatives`; tests
  `pcode_units::label_numbers_are_32_bits` (both sides of 2³², the bound
  below and above it).
- (b) The coverage snapshot holds `unset-or-crash` (unset-handle records
  plus oracle crashes) instead of the two host-dependent counts; the run
  prints both and a summary; thresholds are asserted before the snapshot
  (f1c70e8, 9b132aa). Passed on the build host (every_language, 175
  languages, 0 differing records, 36 oracle crashes).

## Done / in progress / next

- Done: measurement tooling (`build.sh` on Linux, `compare.sh`,
  `slabench` modes, `BK_PROFILE_MODE`, `hot.py`); re-measured gap; the
  changes above; corrections (a) and (b).
- In progress: decode + lift is within noise of the reference (0.96–0.99);
  the remaining time is spread over the p-code builder.
- Next: Mac measurements and tests, PERF.md, feature-doc notes, gates.
