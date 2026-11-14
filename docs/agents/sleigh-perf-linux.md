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

## Done / in progress / next

- Done: measurement tooling (`build.sh` on Linux, `compare.sh`,
  `slabench` modes, `BK_PROFILE_MODE`, `hot.py`); re-measured gap.
- In progress: reducing instructions per decode.
