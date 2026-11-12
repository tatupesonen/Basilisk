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

### bk-bin

2026-11-12, Apple M1 Pro (8 cores, 16 GiB), macOS, Rust 1.97.1, release profile.
Command: `cargo test -p bk-bin --release --test bench -- --ignored --nocapture`
(best of three runs; MB = 10⁶ bytes).

| Benchmark | Throughput | Per item |
|---|---:|---:|
| `read_u32` over 64 MiB, reader on a slice (`from_slice`) | 39,740 MB/s | 0.10 ns/read |
| `read_u32`, `MemoryProvider` (slice fast path) | 8,840 MB/s | 0.45 ns/read |
| `read_u32` big-endian, `MemoryProvider` | 7,058 MB/s | 0.57 ns/read |
| `read_u32_array_at` (one call for 16 M values), `MemoryProvider` | 17,598 MB/s | 0.23 ns/value |
| `read_u32`, provider without a slice (through `read_into`) | 8,241 MB/s | 0.49 ns/read |
| `read_u32`, `FileProvider` (block cache, one thread) | 265 MB/s | 15.1 ns/read |
| `read_terminated_bytes_at`, 4 M 15-byte strings, borrowed | 1,477 MB/s | 10.8 ns/string |
| `read_utf8`, same strings, allocating a `String` each | 470 MB/s | 34 ns/string |

No budget is set for these yet. The `FileProvider` figure is the cost of a
shared slot lock plus a copy per read; table parsers that need more should
read a table with one `read_bytes` call and decode from the slice.

### bk-elf

Not measured: the symbol-table benchmark the spec asks for needs the fixture
builder and `ElfFile`, which do not exist yet (see `docs/agents/bin-elf.md`).

### `bk-pcode`

2026-11-12, Apple M1 Pro, macOS, rustc 1.97.1, `--release` (thin LTO), one
test thread, other agents' builds running on the machine (numbers are
indicative, ±15 %). Command:

    CARGO_BUILD_JOBS=2 cargo test -p bk-pcode --release --test bench -- --ignored --nocapture --test-threads=1

| Benchmark | ns/op |
|---|---:|
| `evaluate_binary`, 12-op integer mix (add, sub, mult, and, xor, left, sright, less, sless, carry, div, srem), sizes 1–8 | 2.4 |
| native arithmetic, same mix and dispatch shape (baseline) | 2.0 |
| ratio `evaluate_binary` / native | 1.2 |
| `FloatFormat::encoding`, f64 → binary32 | 8.8 |
| `FloatFormat::encoding`, f64 → binary64 | 5.9 |
| `FloatFormat::host_float`, binary32 → f64 | 3.0 |
| `FloatFormat::host_float`, binary64 → f64 | 2.9 |
| `op_add` host level, binary32 | 8.4 |
| `op_add` host level, binary64 | 13.7 |
| native f64 add (baseline) | 0.45 |
| `wide::evaluate_binary` INT_ADD / INT_MULT / INT_DIV / INT_SLESS, 16 bytes | 7.5 / 15.7 / 28.2 / 25.9 |
| `wide::evaluate_binary` INT_ADD / INT_MULT / INT_DIV / INT_SLESS, 64 bytes | 6.0 / 24.3 / 27.9 / 17.3 |
| `wide::evaluate_binary` FLOAT_ADD / MULT / DIV, 8 bytes (exact level, `BigFloat`) | 216 / 251 / 290 |
| `wide::evaluate_binary` FLOAT_ADD / MULT / DIV, 16 bytes (exact level) | 377 / 345 / 630 |

The `u64` path is within 1.2× of native arithmetic and allocates nothing.
The host float level decodes and re-encodes through `f64` as Ghidra's C++
does (about 30× a bare native add). The exact level allocates
(`num-bigint` significands), as Java's `BigFloat` does; it is the emulator's
path for operands over 8 bytes only. Not benchmarked: decimal text
(`to_decimal_string`), which for the 32-byte format's extreme exponents
expands about 80,000 digits before rounding, as Java does (about 0.1 s).

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
