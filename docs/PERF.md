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
