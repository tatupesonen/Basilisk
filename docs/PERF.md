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

### `bk-lang`

Command (release, Ghidra tree at commit `42db038f3c`):

```text
BASILISK_GHIDRA_DIR=/path/to/ghidra cargo test -p bk-lang --release --test bench -- --ignored --nocapture
```

Each figure is the fastest and the median of repeated runs. The scan walks
every module of the Ghidra tree (39 processor modules plus the rest of
`Ghidra/`), finds 52 `.ldefs` files and registers 202 languages; budget
50 ms (`docs/features/lang.md`).

| Date | Machine | Registry scan | Scan + opinion database (32 files, 339 constraints) | Scan + all 87 `.pspec` | One opinion query (ELF MIPS, binary pattern) |
|---|---|---|---|---|---|
| 2026-11-12 | Apple M1 Pro, macOS, Rust 1.97.1; load average 10 on 8 cores (other agents building, a fuzzer running) | 13.05 / 14.97 ms | 16.77 / 21.40 ms | 21.58 / 25.60 ms | 6.0 / 6.1 µs |
| 2026-11-12 | same machine, other agents building | 11.8 / 12.8 ms | — / 15.6 ms | — / 22.1 ms | — / 5.8 µs |
