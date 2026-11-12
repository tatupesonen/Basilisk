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

### `bk-sleigh-syntax`

2026-11-12, Apple M1 Pro, macOS, rustc 1.97.1, `--release` (thin LTO), one
test thread, other agents' builds running on the machine (indicative,
±15 %). Preprocess + lex + parse, reading the files from disk each run;
median of 11 runs (5 for the corpus). Command:

    BASILISK_GHIDRA_DIR=../ghidra CARGO_BUILD_JOBS=2 cargo test --release -p bk-sleigh-syntax --test bench -- --ignored --nocapture --test-threads=1

| Input | Preprocessed lines | Tokens | Preprocess | Preprocess + parse | Lines/s | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| x86-64 (`x86-64.slaspec` and includes, 1.6 MB) | 39,229 | 399,631 | 3.5 ms | 15.6 ms | 2.5 M | 69 MB |
| AARCH64 (1.6 MB) | 62,046 | 454,486 | 3.0 ms | 16.7 ms | 3.7 M | 43 MB |
| PowerPC (`ppc_64_isa_altivec_vle_be`, 0.4 MB) | 14,481 | 105,092 | 1.0 ms | 5.4 ms | 2.7 M | 17 MB |
| All 150 shipped specs, one after another (28.7 MB) | 1,117,804 | 7,821,930 | 98 ms | 325 ms | 3.4 M | 49 MB |

Budget (spec): the whole corpus in under 10 s single-threaded; measured
0.33 s. Peak RSS is the process maximum from `/usr/bin/time -l` running one
benchmark (`--exact bench_x86_64`, …) on the test binary; it includes the
test harness and memory the allocator kept after earlier runs, so it is an
upper bound on the parse's own peak. Hot node sizes are asserted in
`ast::tests::hot_node_sizes`: `Expr` 72 bytes, `Statement` 88, `PatExpr`
32, `Equation` 36, `IntLit` 24, `DisplayPiece` 16.
