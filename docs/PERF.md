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

### `bk-marshal`

2026-11-12, Apple M1 Pro (8 cores), macOS, rustc 1.97.1, release profile
(thin LTO, one codegen unit). Best of 5 runs. The machine was shared with
other builds (load average 20–35 during the runs), so treat these as
lower bounds on throughput.

Command:

    BASILISK_GHIDRA_DIR=../ghidra cargo test --release -p bk-marshal --test bench -- --ignored --nocapture --test-threads 1

Document: 1,000,000 `<input>` elements under one `<data>` root, each with a
space, an unsigned offset, a signed size, a boolean and an 8-byte string
(packed form 26.9 MB, XML 74.2 MB).

| Operation | Time | Throughput |
|---|---|---|
| packed encode | 28 ms | 953 MB/s, 35 M elements/s |
| packed decode, attributes looked up by id | 170 ms | 159 MB/s, 5.9 M elements/s |
| packed decode, attributes read in order | 117 ms | 230 MB/s, 8.5 M elements/s |
| XML encode (unformatted) | 102 ms | 730 MB/s, 9.8 M elements/s |
| XML parse into the DOM | 332 ms | 223 MB/s, 3.0 M elements/s |
| XML decode of the parsed DOM, by id | 112 ms | 665 MB/s, 9.0 M elements/s |
| XML decode of the parsed DOM, in order | 194 ms | 382 MB/s, 5.2 M elements/s |
| XML parse + decode of the largest `.cspec` (`x86-64-golang.cspec`, 16 kB, 421 elements) | 85 µs | 188 MB/s |

Notes: a lookup by id in the packed form rescans the element's
attributes from its start, as Ghidra's `PackedDecode` does, so code that
reads every attribute is faster iterating them in order. In XML the
opposite holds: iteration maps each attribute name to its id through the
name table, while a lookup by id compares names directly. Parsing
dominates XML input. Not compared with Ghidra yet (no reference build on
this branch).

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
