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

### `bk-sla`

2026-11-14, Apple M1 Pro (8 cores), macOS, rustc 1.97.1, release profile
(thin LTO, one codegen unit), best of 20 runs (3 for the 150-file rows);
load average 8–11 (other agents building). Commands:

    BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 cargo test --release -p bk-sla \
        --test bench --test bench_heap -- --ignored --nocapture --skip profile

Reference loader, same session: `crates/bk-sla/tests/reference_loader/slaload.cc`
(build command in the file; `Sleigh::initialize` = file read, inflate,
decode, cross references), best of 20.

| Measurement | basilisk | Ghidra C++ |
|---|---:|---:|
| `read_file("x86-64.sla")` (read, inflate, decode, validate) | **17.9 ms** (inflate 2.5, decode+validate 15.4) | 30.8 ms |
| `read_file("AARCH64BE.sla")` | 16.1 ms | 28.0 ms |
| `read_file` of all 150 files in sequence, one thread | 415 ms | — |
| `encode_packed`, x86-64 / AARCH64BE | 5.9 / 5.2 ms | — |
| `encode_packed`, all 150 | 128 ms | — |
| `write` (encode + zlib default level), x86-64 | 35.4 ms | — |
| `encode_xml`, x86-64 | 31.2 ms | — |
| x86-64 model heap (`dhat`) | 13.4 MB = 2.99x the 4.47 MB stream; peak 15.6 MB during decode; 4,634 allocations | — |

Budget (`features/sla.md` acceptance 3): x86-64 at most 25 ms and not
slower than the reference loader — met (17.9 vs 30.8 ms); all 150 under
1 s — met; heap at most 8x the stream — met (3.0x). Validation is about
1–2 ms of the decode time. One finding while tuning: building an error
value eagerly (`Option::ok_or(error)`) on every attribute cost a third of
the decode time through the error type's drop glue; the hot path now
builds errors only on failure.

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

2026-11-12, Apple M1 Pro (8 cores, 16 GiB), macOS, Rust 1.97.1, release
profile, best of 3–20 runs; a fuzzer was running on two cores at the time
(indicative figures). Command:
`cargo test -p bk-elf --release --test bench -- --ignored --nocapture --test-threads=1`.
Input: a 64-bit file of 41 MB with one `.symtab` of 1,000,001 symbols
named `function_NNNNNNN`, written by the test fixture builder.

| Benchmark | Time | Per symbol |
|---|---:|---:|
| `ElfFile::parse` (header, header tables, tables located; no symbol read) | 1.3 µs | — |
| decode every symbol (`MemoryProvider`) | 3.8 ms | 3.8 ns |
| decode every symbol and borrow its name (`MemoryProvider`) | 27.8 ms | 27.8 ns |
| decode every symbol and collect owned names | 50.5 ms | 50.5 ns |
| decode every symbol (`FileProvider`) | 23.8 ms | 23.8 ns |
| decode every symbol and read its name (`FileProvider`) | 215 ms | 215 ns |

Opening is independent of the symbol count because symbols, names and
relocations are read on demand. Through `FileProvider` each name costs a
block-cache lookup and a copy (a name may cross a block); a caller that
reads every name of a large table should read the string table once with
`section_data` and resolve names from that slice.

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

### `bk-sleigh-compiler` (front half: elaboration)

2026-11-14, Apple M1 Pro, macOS, rustc 1.97.1, `--release` (thin LTO), one
test thread, other agents' builds running on the machine (indicative).
Parse = preprocess + lex + parse (`bk-sleigh-syntax`, reading from disk);
elaborate = everything of `bk_sleigh_compiler::elaborate` (definitions,
constructors, templates, macro expansion, the consistency checker and
optimiser, purge, building the result). Best of 5 for the two largest,
one run each for the corpus. Command:

    BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 cargo test --release -p bk-sleigh-compiler --test bench -- --ignored --nocapture --test-threads=1

| Input | Parse | Elaborate | Reference `sleigh`, whole compile (STAMP) |
|---|---:|---:|---:|
| x86-64 | 12.9 ms | 29.3 ms | 400 ms |
| AARCH64 | 12.7 ms | 41.4 ms | 349 ms |
| All 150, one after another | 338 ms | 654 ms (1.03 s with parse) | 11.5–11.8 s |

Budget (spec 6.4): all 150 in under 4 s for this half, leaving room for the
back half within the reference compiler's 11.5–11.8 s; measured 1.03 s.
Peak memory not measured separately.
None yet.

### `bk-sleigh-compiler` (whole compile, back half included)

2026-11-14, Apple M1 Pro, macOS, rustc 1.100.0, `--release`, one test
thread; load average 3.6–4.5 (one other agent on the machine, indicative).
"Basilisk" is parse + elaborate + patterns + decision trees + lowering +
encoding and writing the compressed `.sla`; "reference" is
`REF/bin/sleigh` (built with `-ffp-contract=off`) on the same file with
the module's options, timed in the same session. Command:

    BASILISK_REFERENCE_DIR=../reference cargo test --release -p bk-sleigh-compiler --test bench -- --ignored --nocapture --test-threads=1

| Input | Basilisk | Reference `sleigh` |
|---|---:|---:|
| x86-64 (best of 3) | 195 ms | 378 ms |
| AARCH64 (best of 3) | 156 ms | 319 ms |
| `RISCV/andestar_v5` (best of 3) | 103 ms | 1,670 ms |
| All 150, one after another | 3.83 s | 11.21 s |

Spec 6.5's figures are met (each faster than the reference; all 150 in
under the reference's total). The same run's split for the front-half
benchmark: x86-64 parse 13.0 ms, elaborate (now including patterns and
trees) 128.7 ms; all 150 parse 291 ms, elaborate 2.42 s. The decision trees
read pattern bits through `Block::mask`/`value` on every candidate field;
caching flattened bits per pattern is the obvious next step if it matters.

### bk-ui

**Scrolling a ten-million-row listing** (budget: 60 frames per second,
16.7 ms a frame). 2026-11-12, Apple M1 Pro (8 cores, shared with other
agents' builds), release build. Command:

    CARGO_BUILD_JOBS=2 cargo test -p bk-ui --release --test perf -- --ignored --nocapture

The synthetic program (`demo::synthetic`, 10,000,026 rows, 94,341
functions) is shown in the full interface at 1440×900 points; each frame
is measured from input through layout to tessellated triangles (the UI
thread's whole share; GPU submission not included). The test asserts the
listing moved (different functions on screen) and that each jump arrived.

| Scenario | Frames | Mean | p95 | Max |
|---|---|---|---|---|
| Wheel scrolling, 60 px (3 rows) a frame | 600 | 0.63 ms | 1.66 ms | 12.26 ms |
| Go to 200 addresses spread over the 10 M rows | 400 | 0.44 ms | 1.40 ms | 11.00 ms |
| Idle redraw of a full screen | 200 | 0.44 ms | 1.63 ms | 2.97 ms |

Why it holds: rows are uniform, so the scroller keeps its position as a
`u64` row plus a pixel offset (no `f32` precision loss at 2·10⁸ px) and
jumping to any row is O(1); only visible rows are touched; rows arrive in
64-row pages from worker threads (the frame draws placeholders, never
waits); each row's text is laid out once into a cached galley and only
re-painted afterwards. The worst frames (≈ 11–12 ms) are the frames in
which several pages arrive and are laid out at once.
### `bk-gnu-disasm` / `bk-binutils-sys`

2026-11-12, Apple silicon (8 cores), macOS 25.5, Apple clang 17, rustc
1.97.1, with other agents' builds and a 3-CPU fuzzing container running
(load average 9–16): wall times are pessimistic.

Throughput, `--release`, one thread, 1 MiB of a repeated real function:

    CARGO_BUILD_JOBS=2 cargo test --release -p bk-gnu-disasm --test bench -- --ignored --nocapture

| Architecture | `block` | `instruction_at` per instruction |
|---|---:|---:|
| x86-64 | 2.14 M instructions/s | 1.89 M instructions/s |
| AArch64 | 1.36 M instructions/s | 1.23 M instructions/s |

Each instruction allocates its text (`String`); binutils' own printing
dominates. `instruction_at` hands binutils a 320-byte window, so per-call
cost does not grow with the slice.

Building `bk-binutils-sys` (`cargo clean -p bk-binutils-sys`, then
`time CARGO_BUILD_JOBS=2 cargo build [--release] -p bk-binutils-sys`; 280
C files through the `cc` crate and Cargo's jobserver):

| | dev (C at `-O1`) | release (C at `-O3`) |
|---|---:|---:|
| clean build | 15.8 s (20.1 s with C debug info) | 19.6 s |
| after a change to Rust only | 0.2 s | 0.4 s |
| nothing changed | 0.07 s | — |
| static library | 18.6 MB (40.2 MB with C debug info) | 18.7 MB |

C debug info is off by default (`CFLAGS=-g` to have it). Size added to a
stripped `dist`-profile binary (fat LTO) by using `bk-gnu-disasm`:
13.4 MB (13.7 MB against 0.3 MB for the same program without it) — the
tables of every libopcodes target.

### `bk-decomp-types`

2026-11-14, Apple M1 Pro, macOS, `--release` (thin LTO), one test thread,
other agents' builds running on the machine (indicative). Command:

    CARGO_BUILD_JOBS=2 cargo test -p bk-decomp-types --release --test bench -- --ignored --nocapture --test-threads=1

| Benchmark | Result |
|---|---:|
| Intern 1,000,000 base/pointer/array requests, about 90 % repeats (28,791 types at the end) | 33.5 ms, 33 ns/request |
| Decode a `<typegrp>` of 10,003 types (1.87 MB of XML: structures, named pointers, arrays, typedefs, enumerations), factory with core types | 16.1 ms, 1.6 µs/type |

`base` of a cached size/metatype is an array read; `pointer` and `array`
are one hash lookup of a candidate built on the stack (no allocation when
the type exists). Forking a factory for a function copies only the
environment and the base-type cache.
### `bk-sleigh` (decoding, track `sleigh-decode`)

    crates/bk-sleigh/tests/reference_bench/build.sh ../reference
    BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 \
      cargo test --release -p bk-sleigh --test bench -- --ignored --nocapture --test-threads=1
    BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 \
      cargo test -p bk-sleigh --test bench_heap -- --nocapture

Input: 538,553 bytes of x86-64 code, the text sections of Ghidra's
`ruleaction.cc`, `coreaction.cc`, `fspec.cc` and `type.cc` built with Apple
clang 17 `-O2 -arch x86_64` (`build.sh`); 147,953 instructions and 1,331
undecodable positions on both sides (the counts of inventory 8a). Context:
the `.pspec` defaults. Reference: `tests/reference_bench/slabench.cc` linked
against the reference build's `libsla.a`, run by the benchmark in the same
session. Best of 5. 2026-11-14, M1 Pro (8 cores), load average 10–15 (other
agents' builds and the differential test running).

| Benchmark | basilisk | Ghidra C++ (same session) | Required |
|---|---:|---:|---|
| `Language::load` x86-64 (module registry + `.sla` + `.ldefs` + `.pspec`) | **20.3 ms** (`Sla::read_file` 19.0 ms) | 32.2 ms (`Sleigh::initialize` + `<context_data>`) | ≤ reference and ≤ 40 ms — met |
| decode only (`Decoder::decode` / `instructionLength`) | **3.25 M instructions/s** (308 ns) | 3.17 M/s | ≥ reference — met |
| decode + text (`decode` + `mnemonic` + `body` / `printAssembly`) | **2.41 M/s** (415 ns) | 1.50 M/s | ≥ reference — met |
| allocations per instruction, steady state (`dhat`, 100,000 instructions) | **0** (x86-64 and the `bkfix` fixture; the only blocks counted are the context database's, built once) | — | 0 — met |
| 8 threads sharing one `Language`, decode only | 2 threads 1.98×, 4 threads 3.60×, **8 threads 4.78×** | — | ≥ 6× on an idle 8-core machine — not met on this loaded machine (load average 14 with three agents' work); recorded, see the track report |

### `bk-sleigh` (p-code generation, track `sleigh-pcode`)

    crates/bk-sleigh/tests/reference_bench/build.sh ../reference
    CARGO_BUILD_JOBS=2 cargo build --release -p basilisk
    BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 \
      cargo test --release -p bk-sleigh --test bench_pcode -- --ignored --nocapture --test-threads=1
    BASILISK_REFERENCE_DIR=../reference CARGO_BUILD_JOBS=2 \
      cargo test -p bk-sleigh --test bench_heap -- --nocapture

Input as for decoding (538,553 bytes of x86-64, 147,953 instructions);
the end-to-end rows use the 778,001-byte input of the reference-tools rows
above (`build.sh` now writes it as `target/bench/x86-64-code-778k.bin`).
Reference: `slabench` (now also `instructionLength` + `oneInstruction` into
a counting emitter, and `printAssembly` + `oneInstruction`) and
`pcodedump`, run by the benchmark in the same session. Best of 5.
2026-11-14, M1 Pro, load average about 6–12, Rust 1.97.1 (before the
master merge; the code measured is the final one).

| Benchmark | basilisk | Ghidra C++ (same session) | Required |
|---|---:|---:|---|
| decode + lift, counting emitter (`decode` … `lift` / `instructionLength` + `oneInstruction`) | **1.61 M instructions/s, 6.60 M ops/s** (623 ns) | 1.60 M/s, 6.57 M ops/s | ≥ reference — met; both sides emit 608,674 ops |
| decode + text + lift (`decode`, `mnemonic`, `body`, `lift_decoded`) | **1.38 M/s** | 1.01 M/s | ≥ reference — met |
| `basilisk disasm --quiet` end to end, 778 kB (process start, load, sweep) | **0.190 s** | `pcodedump --quiet` 0.201 s | no slower — met |
| `basilisk disasm`, full listing to a null device | **0.396 s** | `pcodedump` 0.714 s | no slower — met |
| allocations per instruction lifting, steady state (`dhat`, 100,000 instructions) | **0** (`bkpc` fixture incl. delay slots and crossbuild; x86-64) | — | 0 — met |
| 8 threads sharing one `Language` | decode 4.0–4.7×, decode + lift 4.7–5.7× (load average 6–20 at the time) | — | ≥ 6× on an idle machine — not shown; the machine was never idle |

What made the difference (from 1.36 to 1.61 M/s): `lift_decoded` (Ghidra's
parse cache gives `oneInstruction` the parse `printAssembly` made; basilisk
reuses the last decode explicitly instead of decoding twice), handles
resolved last node first instead of the depth-first walk with re-entry,
precomputed main-template ids, varnode symbols and space classes, operand
varnodes resolved with one handle look-up, and no `Arc` clone per lift.

### `bk-sleigh` thread scaling on an idle x86-64 Linux virtual machine (track `remote-build`)

Machine: QEMU/KVM virtual machine, 20 vCPUs (1 thread per core, one
socket, one NUMA node), 32 GB, Debian 13, Rust 1.100.0; idle apart from
the benchmark (load average below 1 before each run). Virtual CPUs share
the physical host with whatever else runs on it, so this shows scaling
on an otherwise idle 20-core machine, not on bare metal. Code at master
12056c8. Input: the Mac's `build.sh` output copied over (same 538,553
bytes, 147,953 instructions). The thread lists in `tests/bench.rs` and
`tests/bench_pcode.rs` were widened to `[2, 4, 8, 16]` in the remote
checkout only (not committed). The reference is `slabench` built on the
machine with `build.sh`'s flags (g++ 14.2 -O2) against the reference
build there. Commands, in a checkout with `target/bench` filled:

    scripts/remote.sh run -- bash -c 'cargo test --release -p bk-sleigh --test bench -- --ignored --nocapture --test-threads=1'
    scripts/remote.sh run -- bash -c 'cargo test --release -p bk-sleigh --test bench_pcode -- --ignored --nocapture --test-threads=1'

Speed-up over one thread, each thread sweeping the whole input with its
own `Decoder` on one shared `Language` (best of 3 against the best of 5
single-thread sweeps), three runs on 2026-11-14:

| Threads | decode only (`bench`) | decode only (`bench_pcode`) | decode + lift (`bench_pcode`) |
|---:|---|---|---|
| 1 | 1.00× | 1.00× | 1.00× |
| 2 | 2.04 / 1.96 / 1.93× | 1.90 / 1.82 / 1.84× | 1.87 / 1.84 / 1.93× |
| 4 | 4.01 / 3.63 / 3.78× | 3.54 / 3.60 / 3.71× | 3.87 / 3.57 / 3.77× |
| 8 | **7.88 / 6.71 / 7.26×** | **6.85 / 7.06 / 6.89×** | **7.25 / 6.91 / 7.14×** |
| 16 | 15.18 / 12.62 / 13.31× | 13.75 / 13.04 / 14.56× | 14.06 / 13.99 / 13.57× |

**The 8-thread target of 6× is met** on an idle machine (6.7–7.9×), and
scaling stays nearly linear to 16 threads (12.6–15.2×). This supports the
track's reading that the 4.7–5.7× on the Mac was the machine's load and
its efficiency cores, not shared state in the code.

Single-thread figures from the same runs, for the record. They differ
from the Mac's in an important way: here the C++ reference is faster.

| | basilisk | Ghidra C++ (`slabench`, g++ 14.2 -O2, same session) |
|---|---:|---:|
| `Language::load` x86-64 | 25.7–28.7 ms | 28.7–31.3 ms |
| decode only | 2.98–3.30 M instructions/s | 4.01–4.19 M/s |
| decode + text | 2.28–2.40 M/s | 1.93–2.01 M/s |
| decode + lift, counting emitter | 1.46–1.50 M/s, 6.01–6.15 M ops/s | 2.08–2.12 M/s, 8.61–8.71 M ops/s |
| decode + text + lift | 1.27–1.29 M/s | 1.32–1.37 M/s |
| end to end `--quiet`, 778 kB | 0.177–0.180 s | `pcodedump --quiet` 0.159–0.173 s |
| end to end, full listing to a null device | 0.357–0.362 s | `pcodedump` 0.480–0.496 s |

On this host basilisk's decode-only and decode + lift rates are 25–30 %
below the reference built by g++, where on the M1 Pro (against Apple
clang) they were equal or ahead; `--quiet` end to end is 3–12 % slower.
Requirement "≥ reference" is therefore **not met on x86-64 Linux** for
decode only, decode + lift and `--quiet`. Text and full listings remain
ahead. Not investigated in this track (it changes no crate); a follow-up
for `bk-sleigh`.

### `bk-sleigh` single-thread speed against Ghidra's C++ on x86-64 Linux and the M1 Pro (track `sleigh-perf-linux`)

    # build host (x86-64 Linux): inputs and slabench built there, both engines pinned to one core
    scripts/remote.sh run -- bash -c 'crates/bk-sleigh/tests/reference_bench/build.sh "$BASILISK_REFERENCE_DIR" && crates/bk-sleigh/tests/reference_bench/compare.sh "$BASILISK_REFERENCE_DIR" 11 7'
    # Mac (unpinned; macOS cannot pin a thread)
    crates/bk-sleigh/tests/reference_bench/build.sh ../reference
    crates/bk-sleigh/tests/reference_bench/compare.sh ../reference 7

`compare.sh` runs, per round, `bench_pcode` with `BK_BENCH_SINGLE=1` (the
four single-thread sweeps, best of 5 inside) and then `slabench` (the
same four sweeps, best of 5 inside), and prints the best and the median
of the rounds and the median of the per-round ratio (the two engines run
back to back, so the ratio cancels the host's drift). `build.sh` now also
runs on Linux (clang++ -O2, ELF `.text`), so each host has its own input:
the build host 410,462 bytes, 107,047 instructions, 454,144 ops (both
engines agree on both counts); the Mac 538,553 bytes, 147,953
instructions, 608,674 ops. One language sample (x86-64) exists; the
other languages are covered for correctness by the differential tests,
not timed. M instructions/s, best / median of the rounds.

**Build host: a 20-vCPU x86-64 Linux VM, host CPU model AMD Ryzen
Threadripper 7970X (Zen 4; AVX2, BMI1/2, AVX-512 exposed)**, Rust 1.100.0,
reference built by g++ 14.2 -O2. Before: master 12f1705, 5 rounds, load
average 3.5–4.0 (another branch idle, the testbed idle). After:
e7e8f04, 11 rounds, load average 4.7 falling to 2 (another agent's job
finishing).

| | basilisk before | basilisk after | Ghidra C++ | after / Ghidra (per-round median, range) |
|---|---:|---:|---:|---|
| decode only | 3.98 / 3.87 | **5.22 / 5.11** | 4.69 / 4.61 | **1.11** (1.07–1.19) |
| decode + text | 2.83 / 2.69 | **3.40 / 3.35** | 2.30 / 2.23 | **1.50** (1.45–1.58) |
| decode + lift, counting emitter | 1.74 / 1.69 | **2.29 / 2.26** | 2.32 / 2.26 | **1.00** (0.94–1.05) |
| decode + text + lift | 1.47 / 1.42 | **1.78 / 1.74** | 1.51 / 1.48 | **1.18** (1.12–1.23) |
| `basilisk disasm --quiet` end to end, 606,673 bytes | — | **0.106 s** | `pcodedump --quiet` 0.132 s | 1.25× faster |
| `basilisk disasm`, full listing to a null device | — | **0.240 s** | `pcodedump` 0.347 s | 1.45× faster |

Before, the ratios were 0.86 (decode), 1.24 (text), 0.76 (lift) and 0.99
(text + lift); the earlier measurement on the same VM with a baseline
virtual CPU (no AVX/BMI) had 0.73–0.79 for decode and 0.70–0.72 for lift.

**Mac: M1 Pro, shared** (load average 2.5–9 before, 6–7.5 after; Apple
clang reference). Before: master 12f1705, 5 rounds; after: e7e8f04, 7
rounds.

| | basilisk before | basilisk after | Ghidra C++ | after / Ghidra (per-round median) |
|---|---:|---:|---:|---|
| decode only | 3.33 / 3.32 | **4.31 / 4.30** | 3.28 / 3.27 | **1.32** |
| decode + text | 2.45 / 2.44 | **3.01 / 2.99** | 1.54 / 1.53 | **1.95** |
| decode + lift, counting emitter | 1.62 / 1.62 | **2.22 / 2.21** | 1.61 / 1.60 | **1.38** |
| decode + text + lift | 1.39 / 1.39 | **1.79 / 1.77** | 1.02 / 1.02 | **1.74** |

What the build host's profile showed and what changed it (details and a
row per commit in `docs/agents/sleigh-perf-linux.md`): basilisk executed
about 4,700 machine instructions per decoded instruction where Ghidra
executes about 3,000, and several hot values were stored piecewise and
read back with a wider load, which x86-64 cannot forward from the stores
(the M1 can, which is why only Linux was behind). Fixed by keeping `Env`
to references, handles apart from nodes, the instruction window loaded in
place, handle and varnode resolution inlined, a build walk keeping only a
node index and sharing its constants; and by less work: decision trees
laid out for the decoder (16-byte nodes, shifts precomputed, plain
branches), context changes, exports and leaf expressions beside the
constructor tables, a two-byte internal error so `Result`s come back in
registers, fixed varnodes located directly, no refill of the handle
vector. Now about 4,050 instructions per decode (Ghidra 2,990) and 8,260
per decode + lift (Ghidra 6,300), at a higher IPC. A fat-LTO build of the
same code (`CARGO_PROFILE_RELEASE_LTO=fat`) measured decode + lift 1.00
and decode 1.13: no reason to change the workspace profile.

### `bk-cspec`

Command: `BASILISK_GHIDRA_DIR=../ghidra CARGO_BUILD_JOBS=2 cargo test -p
bk-cspec --release --test bench -- --ignored --nocapture --test-threads=1`
(kind G: reads the real `.cspec` files; spaces and registers from the
checked-in oracle table). 2026-11-14, M1 Pro, Rust 1.100.0, other agents'
builds running.

| Benchmark | Result |
|---|---:|
| Read the largest `.cspec` (`x86-64-golang.cspec`, 15,994 bytes, 3 models with 100+ entries and rules each) into a `CompilerSpec` | **160 µs** per read (2,000 reads) |
| Storage assignment, x86-64 gcc `__stdcall`, four signatures in turn (2–8 parameters, a hidden return, a `join_dual_class` structure) | **1,000,000 assignments in 460 ms (460 ns each)**; the status array is inline (no allocation per call beyond the output vector, which is reused) |

### `bk-sleigh-snippet`

Command: `BASILISK_GHIDRA_DIR=… BASILISK_REFERENCE_DIR=… cargo test -p
bk-sleigh-snippet --release --test bench -- --ignored --nocapture
--test-threads=1` (on the build host: `scripts/remote.sh run -- cargo test
…`). 2026-11-14, Rust 1.100.0. The hot paths are preparing a compiler for a
language (once per program) and compiling a payload (once per payload,
when a language's specifications are loaded). Ghidra's own snippet
compiler was not timed (it has no standalone driver beyond `snippetdump`,
whose time is dominated by loading the language).

| Benchmark | x86-64 Linux VM, 20 vCPUs, host CPU model (AMD Zen 4 class), idle | Mac (M1 Pro, shared with other agents' builds) |
|---|---:|---:|
| `SnippetCompiler::new` for x86-64 (visible names and spaces of a 3,000-register `.sla`) | **0.15 ms** | 0.16 ms |
| The 16 snippets of `x86-64-gcc.cspec` compiled in library order | **27.6 µs** together | 36.7 µs |
| One 10-statement snippet (fixture language), 200,000 compiles | **5.5 µs** per compile | 6.4 µs |

Per compile the parser builds a small syntax tree and the builder a
template; there is no per-language work after `new`. The whole shipped
corpus (588 compilations in 116 languages) is compiled in well under a
millisecond of compile time; the differential test's 0.5 s is spent
loading `.sla` files and running the oracle.

### `bk-decomp-range`

2026-11-14, the Linux build host (a 20-vCPU x86-64 Linux VM, AMD Ryzen
Threadripper 7970X), rustc 1.100.0, `--release` (thin LTO), one test
thread. 4,096 well-formed ranges of 1–8 bytes with steps 1–8, 500 rounds.
Command:

    cargo test -p bk-decomp-range --release --test bench -- --ignored --nocapture --test-threads=1

| Benchmark | ns/call |
|---|---:|
| `intersect`, consecutive pairs of the set | 8.0 |
| `pull_back_binary`, mix of `INT_ADD`, `INT_SUB`, `INT_LESS`, `INT_EQUAL`, `INT_RIGHT`, `INT_SRIGHT`, constants 0–7 | 5.8 |
| `push_forward_binary`, mix of `INT_ADD` (two ranges), `INT_MULT`, `INT_LEFT`, `INT_RIGHT`, `SUBPIECE` (constant second input), `INT_EQUAL` | 7.8 |

Every method is a handful of branches on a 32-byte `Copy` value and
allocates nothing (`tests/no_allocation.rs`).

### `bk-decomp-cfg`

2026-11-15, the Linux build host (a 20-vCPU x86-64 Linux VM, AMD Ryzen
Threadripper 7970X), rustc 1.100.0, `--release` (thin LTO), one test
thread, best of 3–5 runs. Generated graphs (`tests/support/graphgen.rs`):
"function-like" are random graphs with every node reachable from node 0
(about two edges per node, many cross edges); "reducible" are lowered from
nested structured statements. Command:

    cargo test -p bk-decomp-cfg --release --test bench -- --ignored --nocapture --test-threads=1

| Benchmark | Nodes | Edges | Time |
|---|---:|---:|---:|
| `structure_loops` + `forward_dominators`, function-like | 1,000 | 2,016 | 0.35 ms |
| the same | 10,000 | 20,242 | 32 ms |
| the same | 100,000 | 201,937 | 4.3 s |
| `structure` (bare: analyses + collapse), reducible | 616 | 875 | 0.27 ms |
| the same | 7,177 | 10,588 | 21 ms |
| the same, function-like (768 gotos) | 1,000 | 2,036 | 22 ms |
| the same, function-like (2,502 gotos) | 3,000 | 6,193 | 224 ms |
| reference console `structure blocks` (run minus load; includes its XML I/O), reducible | 7,177 | 10,588 | 51 ms |
| the same, function-like | 1,000 | 2,036 | 23 ms |

Memory: 160 bytes per node without its lists, 24 bytes per edge (two
12-byte halves), 4 bytes per component.

Both costs that grow faster than linearly are Ghidra's algorithms, kept
because their order is behaviour: `findIrreducible` rebuilds a reach-under
set per loop head with a one-level `FIND` (`copymap`), which is quadratic on
random graphs with many back edges; and every goto chosen by `selectGoto`
is followed by a full sweep of the rules over the top level, so structuring
costs about (nodes + edges)² rule attempts when most edges become gotos.
The work counter (`Limits::max_steps`, default `2·(n+e)² + 10⁶`) measured
at most 0.97·(n+e)² steps on 1,200 generated graphs of up to 1,000 nodes
and 0.85·(n+e)² on the 3,000-node graph above; reducible graphs take
0.02·(n+e)².

Corpus (2026-11-15, same host): the largest structuring graph of the 767
captured runs (`datatests/elseif`, 42 nodes, 61 edges) structures as given
in 7 µs and 798 steps; command `cargo test -p bk-decomp-cfg --release
--test corpus -- --ignored largest_corpus_graph --nocapture`.


### `bk-decomp-symbols`

2026-11-16, the Linux build host (a 20-vCPU x86-64 Linux VM, AMD Ryzen
Threadripper 7970X), rustc 1.100.0, `--release`, one test thread, best of
five runs inside each of two jobs (the two columns; the host was shared,
so the spread is load). Command:

    cargo test -p bk-decomp-symbols --release --test bench -- --ignored --nocapture --test-threads=1

| Benchmark | Run 1 | Run 2 |
|---|---:|---:|
| insert 100,000 global symbols (1–24 bytes, a tenth overlapping) | 73 ms (732 ns/symbol) | 91 ms (914 ns/symbol) |
| 1,000,000 `query_by_addr` at random addresses over them | 409 ns/call | 563 ns/call |
| 1,000,000 `query_container` (size 4) | 397 ns/call | 676 ns/call |
| `print_entries` of a 10,000-entry scope (329 kB of text) | 1.39 ms | 1.68 ms |
| 1,000,000 context look-ups (`variable_at` + `context`) over 10,000 split points | — | 133 ns |

A query resolves the address's scope, then searches one space's fragment
tree (`O(log n)`) and walks the overlapping fragments of one piece; it
allocates nothing. The random probes miss the caches on most calls over a
1.6 MB address range.

Spec 5.8's budget, loading the 93 data-test images (`<binaryimage>`, the
language's `.sla`/`.pspec`/`.cspec`, 4.18's steps, loader symbols)
against the reference console's `load test file` of the same files (one
console process per file, as `bk-oracle` runs it, so its time includes
process start), best of three, the same day and host:

    cargo test -p bk-decomp-symbols --release --test image_oracle -- --ignored --nocapture budget

| | Basilisk | Reference console | Ratio |
|---|---:|---:|---:|
| build host | 1,827 ms | 5,056 ms | 0.36 |
| Mac (M1 Pro) | 1,711 ms | 4,831 ms | 0.35 |
