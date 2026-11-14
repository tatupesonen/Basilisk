# Track `sleigh-perf-linux`: `bk-sleigh` at least as fast as Ghidra's C++ on x86-64 Linux

Status: done (2026-11-14). Everything ran on the build host through
`scripts/remote.sh` except what has to be the Mac's: the Mac's
measurements, the crate's tests and `every_language` against the Mac's
reference, and the Windows cross-check clippy.

## Summary

- **Re-measured gap** (build host: a 20-vCPU x86-64 Linux VM, host CPU
  model AMD Ryzen Threadripper 7970X, Zen 4): with the host CPU exposed
  the gap was smaller than the 25–30 % recorded on the baseline virtual
  CPU, but still there: decode 0.86 and decode + lift 0.76 of the g++
  reference (text 1.24, text + lift 0.99).
- **Now** (median of the per-round ratio over 11 rounds, both engines
  back to back on one pinned core): decode **1.11**, decode + text
  **1.50**, decode + lift **1.00** (range 0.94–1.05), decode + text +
  lift **1.18**; end to end `--quiet` 1.25× and full listing 1.45×
  faster than `pcodedump`. On the M1 Pro: 1.32, 1.95, 1.38, 1.74 (all
  up; nothing given back).
- **ADR-012 on x86-64 Linux**: met for decode, decode + text, decode +
  text + lift and end to end; decode + lift is level (median ratio
  0.99–1.00 in the last four runs, best-of rounds ≥ 1.00), not clearly
  ahead. What remains is spread over the p-code builder and handle
  resolution (below).
- Corrections (a) label numbers truncated to 32 bits as Ghidra does, with
  the allocation bound kept; (b) the coverage snapshot holds only what
  every host gives, thresholds asserted first; passes on both hosts.
- No `unsafe`, no new dependency, no output change, no change outside
  `crates/bk-sleigh` and the documents this track owns. `bk-sla`
  untouched.

## How to measure

On the build host (x86-64 Linux; pinned to one core, both engines
interleaved in one job):

    scripts/remote.sh run -- bash -c 'crates/bk-sleigh/tests/reference_bench/build.sh "$BASILISK_REFERENCE_DIR" && crates/bk-sleigh/tests/reference_bench/compare.sh "$BASILISK_REFERENCE_DIR" 11 7'

On the Mac (unpinned; macOS cannot pin):

    crates/bk-sleigh/tests/reference_bench/build.sh ../reference
    crates/bk-sleigh/tests/reference_bench/compare.sh ../reference 7

`build.sh` now runs on Linux as well (clang++ -O2, ELF `.text`; on the
Mac Apple clang `-arch x86_64`, Mach-O `__text` as before). The two
hosts' inputs therefore differ (Linux: 410,462 bytes, 107,047
instructions, 454,144 ops; Mac: 538,553 bytes, 147,953 instructions,
608,674 ops); each comparison is between engines on one host and one
input. `compare.sh` runs `bench_pcode` with `BK_BENCH_SINGLE=1` (the four
single-thread sweeps, best of 5 inside; `decode + text` was added to it)
and `slabench` (the same four, best of 5 inside), REPS rounds, and prints
best and median over the rounds and the median of the per-round ratio.
The host drifts by several per cent between runs even at load average
below 1 (other tenants of the physical machine), so only the per-round
ratio is worth comparing between runs.

Profiling on the host: `BK_PROFILE_MODE=decode|text|lift
BK_PROFILE_SECONDS=5 perf record … bench_pcode profile_lift_x86_64
--exact --ignored` (it prints how many instructions it swept, for
per-instruction counts); `slabench SLA PSPEC CODE RUNS MODES` (modes:
digits 0–3) for the reference. `perf annotate` cannot read this
toolchain's debug information on the host (objdump fails, llvm-objdump
makes perf crash), so `reference_bench/hot.py` gives an instruction- or
line-level profile of one symbol from `perf script` and `llvm-objdump -l`.
Hardware events that count in the VM: `cycles` (not core cycles; do not
derive frequencies from it), `instructions`, raw `r00c3` (retired
mispredicted branches). `branch-misses` and the cache events read 0.

## What the profile showed (build host, before)

- `perf stat`, decode only: basilisk ≈ 4,700 machine instructions per
  decoded instruction at IPC 3.6–3.7; Ghidra ≈ 2,990 (load subtracted)
  at IPC 2.5–2.8. Mispredicted branches: 1.2–1.8 per instruction for
  basilisk, no more than Ghidra. Not the allocator (basilisk allocates
  nothing per instruction; Ghidra's sweep shows no `malloc` either once
  loaded), not cache misses, not mispredictions.
- `perf record`, decode only: `resolve::walk` 41 %, `Env::choose` 17 %,
  `set_constructor` 17 %, `Env::eval` 7 %. Decode + lift: `walk` 21 %,
  `Builder::build` 19 %, `resolve_handles` 14 %, `choose` 10 %. Ghidra:
  `DecisionNode::resolve`, `Sleigh::resolve`, `resolveHandles`,
  `ConstTpl::fix`, `SleighBuilder::{appendBuild, dump,
  generateLocation}`, `PcodeBuilder::build`, `TokenField::getValue`.
- Instruction-level: a third of `walk`'s samples sat on one load right
  after `set_constructor` grew the node vector: building an `Env` copied
  the vector's pointer and length with one 16-byte load from two 8-byte
  stores. The same pattern recurred: `FixedHandle`/`VarnodeData` returned
  through memory, written field by field and copied with 16-byte loads
  (22 % + 27 % of `resolve_handles`); a walk's 32-bit child range read as
  one 64-bit load (`build`); the instruction window assembled byte by
  byte and copied. x86-64 cannot forward a load from several smaller
  stores and waits for them to retire; the M1 is much more forgiving,
  which is why only Linux was behind.
- The rest was more work per instruction than Ghidra: model look-ups
  per decision node and per pattern block, `Result<_, DecodeError>`
  (≈ 48 bytes) returned through memory from every inner function,
  constructor exports reached through three arenas, the handle vector
  refilled per instruction, a 64-byte node with an embedded handle.

## Changes (build host ratios, median per-round or medians of one run; basilisk / Ghidra)

| Commit | Change | decode | decode + lift |
|---|---|---|---|
| (12f1705) | before | 3.87 / 4.52 (0.86) | 1.69 / 2.22 (0.76) |
| b9653a1 | `Env` holds the parse by reference; handles in a vector beside 24-byte nodes | 4.21 / 4.60 (0.92) | 1.75 / 2.24 (0.78) |
| 6eb8370 | decision trees laid out for the decoder; context changes per constructor | 4.09 / 4.17 (0.98) | 1.68 / 2.04 (0.82) |
| 62d6baf | handle and varnode helpers inlined | 4.39 / 4.59 (0.96) | 1.88 / 2.26 (0.83) |
| ce170a4 | window loaded in place; `fix`, `operand_handle`, `locate` forced inline | 4.33 / 4.32 (1.00) | 1.86 / 2.17 (0.86) |
| aed46f4, d2c50c2 | exports beside the constructor tables; a walk keeps only its node index | 4.48 / 4.61 (0.97) | 1.95 / 2.27 (0.86) |
| 09cbe2b | two-byte `Fault` for the inner decode functions | 4.69 / 4.63 (1.01) | 2.09 / 2.26 (0.93) |
| 889fac8 | decision nodes packed into 16 bytes, context arithmetic precomputed | 4.95 / 4.50 (1.10) | 2.12 / 2.22 (0.96) |
| df5b3e5, d7a9eb9 | fixed varnodes located directly; leaf evaluation; no handle refill | 4.85 / 4.54 (1.07) | 2.16 / 2.23 (0.97) |
| 8374b87 | tree walk with plain branches, leaf after the loop | 5.11 / 4.64 (1.10) | 2.15 / 2.24 (0.96) |
| b634fe0, fd7e64d | walks share one `Consts` per instruction; constructor info borrowed | 5.04 / 4.63 (1.09) | 2.22 / 2.25 (0.99) |
| eb464e5, 6ec1c15, 94c1cd6, e7e8f04 | byte swap in one instruction; table handles via their span; delay-slot list only when needed; leaf expressions with their field | 5.11 / 4.61 (**1.11**) | 2.26 / 2.26 (**1.00**) |

On the Mac the same code went from 3.32 / 3.24 to 4.30 / 3.27 (decode)
and from 1.62 / 1.60 to 2.21 / 1.60 (decode + lift).

Tried and dropped: `dump` out of line (no gain, reverted in 2815d99).
Measured, not proposed: a fat-LTO build (`CARGO_PROFILE_RELEASE_LTO=fat`)
gives decode 1.13 and decode + lift 1.00, within noise of the workspace's
thin LTO; no profile change is needed.

### Final table

| | Build host, basilisk | Build host, Ghidra C++ | ratio | M1 Pro, basilisk | M1 Pro, Ghidra C++ | ratio |
|---|---:|---:|---:|---:|---:|---:|
| decode only | 5.11 | 4.61 | 1.11 | 4.30 | 3.27 | 1.32 |
| decode + text | 3.35 | 2.23 | 1.50 | 2.99 | 1.53 | 1.95 |
| decode + lift | 2.26 | 2.26 | 1.00 | 2.21 | 1.60 | 1.38 |
| decode + text + lift | 1.74 | 1.48 | 1.18 | 1.77 | 1.02 | 1.74 |

M instructions/s, medians; ratio = median of the per-round ratio. Load:
build host 4.7 falling to 2 (another agent's job ending), Mac 6–7.5.

### What remains on x86-64 Linux

Decode + lift is level, not ahead. Per decoded instruction basilisk
still executes ≈ 8,260 machine instructions to Ghidra's ≈ 6,300 (decode
4,050 to 2,990), made up by a higher IPC. By instruction samples the
excess is in handle resolution (≈ 220 against ≈ 130: bounds checks and
`Option`/`Result` tests in `resolve_backwards`, `fix` and the
expression leaves) and less so in the builder (≈ 290 against ≈ 257).
The next step would be a compiled form of the p-code templates (each
varnode template reduced to "whole operand", "fixed varnode" or
"general", ops with their varnodes inline, laid out like the decision
trees) and the same for constructor exports; that is a larger change
than this track's and is listed under Follow-ups.

## Corrections

- **(a) Label numbers are 32 bits** (ce11410, fab1adb). Ghidra's C++
  `SleighBuilder::setLabel` passes `getReal() + getLabelBase()` to
  `PcodeCacher::addLabel(uint4)` (`sleigh.cc` 69–74, 375–378) and
  `resolveRelatives` reads `uint4 id = ptr->offset` (96–110); the Java
  engine (`PcodeEmit.setLabel`, `PcodeEmitObjects/Packed.resolveRelatives`)
  casts to `int`. Both make 2³² + n label n; they differ only in
  [2³¹, 2³²) where both fail (C++ tries to grow its vector to 16 GiB,
  Java throws). Basilisk now truncates (`pcode::build::label_number`, used
  for `LABEL` and in `OpBuffer::resolve_relatives`) and keeps its bound:
  a truncated number ≥ `MAX_OPS` is `MissingLabel`, no allocation. Tests:
  `pcode_units::label_numbers_are_32_bits` (7 cases: both sides of 2³²,
  placed and referenced, the bound below 2³² and after the wrap); the
  existing `unplaced_labels_fail_with_ghidras_message` still passes.
  Recorded in `features/sleigh-pcode.md` section 8.
- **(b) Host-dependent snapshot** (f1c70e8, 9b132aa). The snapshot row
  of `every_language` now has `unset-or-crash` (unset-handle records plus
  oracle crashes, the same on every host: ARM v8-m LE 145 + 5 on macOS,
  146 + 4 on Linux) in place of the two counts; the run prints both per
  language and a summary line; the threshold assertions run before the
  snapshot. `every_language` passed on the build host (175 languages, 0
  differing records, 36 oracle crashes) and on the Mac against the Mac's
  reference (175, 0, 37).

## Built

- `crates/bk-sleigh/src/language/decide.rs` (new): `Trees` — 16-byte
  decision nodes (`Step`, `Kind`), pairs with both blocks inline, a root
  and constructor range per subtable.
- `crates/bk-sleigh/src/decode/fault.rs` (new): `Fault`, `What` — the
  two-byte error of the inner decode functions, turned into
  `DecodeError` where decoding returns (`Fault::at`).
- `language/tables.rs`: per-constructor context changes and exports,
  `ops_of`, `Leaf` expressions.
- `decode`: `Env` holds `&Parse`; `Parse::handle(n)` and a handle vector
  beside the nodes (public API change: `Node::handle()` removed; no other
  crate used it); window loaded in place; `SliceBytes::load` copies 16
  bytes at once when it can.
- `pcode`: `Walk` = handle source + `&Consts`; fixed-varnode fast path in
  `locate`; label numbers truncated.
- Tooling in `tests/reference_bench/`: `build.sh` on Linux, `compare.sh`,
  `hot.py`; `slabench` mode selection; `bench_pcode`: decode + text sweep,
  `BK_BENCH_SINGLE`, `BK_PROFILE_MODE`, instruction count of the
  profiling loop.

## Tests

The crate's tests on the build host and on the Mac (with the reference):
all pass. New: `pcode_units::label_numbers_are_32_bits` (7 cases),
`decode::fault::tests::faults_come_back_in_registers`,
`language::decide::tests::steps_are_small`, the byte-swap test extended
to compare the fast form with Ghidra's loop for sizes 0–10. Every
differential test is unchanged and byte-equal to `pcodedump`.
`every_language` (ignored, long) passes on both hosts.

Gate results: see the end of this report.

## Differences from Ghidra

- Label numbers: none any more below 2³¹; at or above `MAX_OPS` after
  truncation Basilisk returns `MissingLabel` without allocating (C++
  allocates, Java throws). In `features/sleigh-pcode.md`.

## Gaps

- Decode + lift on x86-64 Linux is level with Ghidra (ratio 1.00), not
  ahead; see "What remains".

## Follow-ups

- A compiled form of p-code templates and exports (see "What remains")
  for a clear margin in decode + lift on x86-64.
- No Ghidra defect found beyond those already recorded (the `addLabel`
  resource exhaustion from `sleigh-fixups`; the label behaviour of the
  two Ghidra engines differs in [2³¹, 2³²) as described above, both
  failing).
- `build.sh` input differs per host; a checked-in or downloadable common
  input would make the hosts' numbers directly comparable.

## Commits

See `git log --oneline master..sleigh-perf-linux`.
