# Performance

Budgets, benchmark commands and measured numbers (ADR-012). Every hot path
lands with a benchmark; record the machine, the command and the result
here, newest first under the crate's heading. Sizes use SI prefixes.

## Budgets

| Area | Budget | Measured against |
|---|---|---|
| SLEIGH language load (`.sla` → ready to decode) | at least as fast as Ghidra's C++ loader for the same file; x86-64 in under 100 ms | reference `sleigh`/`decomp` |
| Instruction decode + p-code lift | at least as fast as Ghidra's C++ `Sleigh::oneInstruction`; no heap allocation per instruction in steady state | reference `decomp` |
| SLEIGH compile (`.slaspec` → `.sla`) | at least as fast as Ghidra's C++ `sleigh` | reference `sleigh` |
| Decompile one function | at least as fast as Ghidra's `decomp` on the same function | data tests, reference `decomp` |
| Whole-program analysis | scales with cores; memory bounded by working set | Ghidra headless (M5) |
| Program store (ADR-003) | bulk insert of 10 million instructions, address-ordered range scans, rollback — figures set by the M4 spike | — |
| UI | no frame blocked by storage or analysis | M7 |

## Measurements

### Reference tools (baseline)

What basilisk's SLEIGH compiler, decoder and decompiler are held against
(track `reference-tools`, `docs/features/reference-tools.md`).

* **Host**: Apple-silicon Mac, 8 cores, 16 GB, macOS (Darwin arm64), Apple
  clang 17.0.0; Ghidra 42db038f3c; tools built by
  `scripts/build-reference.sh` (`sleigh` and `decomp` at `-O2`;
  `decomp_test` is the Makefile's debug build, `-g` without `-O`).
* **Date**: 2026-11-12. Measured twice that day, by two agents, with
  agreeing results (the second run is the table below where they differ).
* **Command**: `BASILISK_REFERENCE_DIR=<reference> tools/reference/measure.sh`
  (one job at a time; it writes only below `<reference>/measure` and
  removes it). The build rows come from the build script's own summary.
* **Caveat**: the machine was **not idle** — other agents' builds ran
  throughout (load average 8–13 on 8 cores). Treat the times as upper
  bounds; best-of-N is used where noted. Re-measure on an idle machine
  before holding a basilisk number tightly against them.

| Measurement | Result |
|---|---|
| Compile all 150 languages, one at a time (sum of per-file wall times) | 11.5–11.8 s (mean 76–79 ms) |
| Compile all 150 languages, 4 at a time, inside the build script | 5 s wall |
| Slowest five | `RISCV/andestar_v5` 1.74–1.83 s; then `MIPS/mips64le`, `MIPS/mips32le`, `MIPS/mips32R6le`, `MIPS/mips32R6be`, `MIPS/mips32be` at 0.44–0.49 s, whose order changes between runs (`AARCH64/AARCH64_AppleSilicon` at 0.45 s in one run is within that noise) |
| `.sla` sizes | 150 files, 12.3 MB total, median 36.2 kB, smallest 0.4 kB |
| Largest five `.sla` | `AARCH64/AARCH64BE` 501.5 kB; `x86/x86-64` 501.1 kB; `AARCH64/AARCH64_AppleSilicon` 497.1 kB; `AARCH64/AARCH64` 495.3 kB; `x86/x86` 439.2 kB |
| `pcodedump` language load, `x86:LE:64:default` (`.ldefs` scan, `.sla`, `.pspec`; best of 5) | 41–48 ms |
| `pcodedump --quiet`, x86-64 decode + lift, no output (best of 5) | 213,187 instructions, 872,740 p-code ops in 0.141–0.142 s: **1.5 M instructions/s**, 6.1–6.2 M ops/s, 5.5 MB/s, 660–667 ns per instruction |
| `pcodedump`, decode + lift + text listing to `/dev/null` (best of 5) | 0.65 s: 0.33 M instructions/s |
| Input for the two rows above | 778,001 bytes: text sections of Ghidra's `ruleaction.cc`, `coreaction.cc`, `fspec.cc`, `type.cc`, `printc.cc`, `funcdata_varnode.cc`, `block.cc`, `database.cc` compiled `-O2 -arch x86_64`; 1,794 positions do not decode (jump tables clang places in the text section on macOS) |
| Data tests, 93 files / 760 checks (`decomp_test … datatests`, debug build, best of 3) | 2.2–2.4 s (includes loading each language once) |
| Unit tests, 205 (`decomp_test … unittests`, debug build, best of 3) | 0.77–0.8 s |
| `scripts/build-reference.sh`, clean, 4 jobs | 70 s wall, 197 s CPU |
| `scripts/build-reference.sh`, nothing to do | 1.9 s |

Not measured: a per-function decompile time with the optimised
`bin/decomp`.
