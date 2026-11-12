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

### bk-marshal

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
