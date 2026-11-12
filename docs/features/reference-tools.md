# Reference tools and test kit (`bk-testkit`, `scripts/build-reference.sh`)

Track `reference-tools`, wave 1, milestone M0. Format of this document:
`docs/LOOP.md`, "Feature documents".

Path abbreviations: `DEC/` = `Ghidra/Features/Decompiler/src/decompile/`,
`CPP/` = `DEC/cpp/`, `P/` = `Ghidra/Processors/`, all under `../ghidra`.

## 1. Purpose

basilisk's correctness is measured against Ghidra itself (ADR-007). This
track builds Ghidra's native tools from source into a directory outside
both repositories, produces the compiled `.sla` file for every language
(Ghidra's source tree does not contain them), and gives every other crate
a small Rust test kit for finding the spec tree, running the reference
tools and comparing output. Nothing here ships in the product.

## 2. Ghidra sources

| Source | What it is |
|---|---|
| `CPP/Makefile` | Builds `sleigh_opt` (the SLEIGH compiler), `decomp_opt` (the decompiler console), `decomp_test_dbg` (the test runner), `libsla.a`, `libdecomp.a`. Source groups `CORE`, `DECCORE`, `SLEIGH`, `SLACOMP`, `EXTRA` |
| `CPP/slgh_compile.cc` (`main`, near the end) | `sleigh [-x] [-dNAME=VALUE] inputfile [outputfile]` and the directory mode (`-a`); read the option handling for the full list |
| `CPP/consolemain.cc`, `CPP/ifacedecomp.cc`, `CPP/interface.cc` | The `decomp` console: `-i script`, `-s specpath`, the `SLEIGHHOME` environment variable, and its commands (`load file`, `restore`, `lo fu`, `decompile`, `print C`, `disassemble`, `print raw`, …) |
| `CPP/test.cc`, `CPP/testfunction.cc` | `decomp_test`: `-path <datatests dir>`, `-sleighpath <root>`, `-usesleighenv`, `unittests [names]`, `datatests [names]`; how a `<decompilertest>` file is run and judged (`<script>` commands, `<stringmatch>` regular expressions with `min`/`max` counts) |
| `CPP/sleighexample.cc` | A minimal program that loads a `.sla`, disassembles and prints p-code — the model for the p-code dump tool below |
| `CPP/filemanage.cc` (`discoverGhidraRoot`, `scanDirectoryRecursive`), `CPP/sleigh_arch.cc` (`collectSpecFiles`, `.ldefs` handling) | How the tools find `.ldefs`/`.sla` files under a root |
| `DEC/zlib/` | The zlib sources the Makefile compiles in |
| `DEC/datatests/` (93 files), `DEC/unittests/` | The decompiler's tests |
| `P/*/data/languages/` | 150 `.slaspec` files to compile |

## 3. Scope

**In:**
1. `scripts/build-reference.sh` — builds the reference tools and the
   compiled-language overlay into `../reference/`.
2. `tools/reference/pcodedump.cc` — basilisk's own small C++ oracle
   program (Apache-2.0, kept in this repository), linked against the
   reference objects.
3. `bk-testkit` — the Rust test-support crate.
4. Baseline measurements of the reference tools for `PERF.md`.

**Crates and paths owned:** `crates/bk-testkit`, `scripts/build-reference.sh`,
`tools/reference/`. `bk-testkit` has **no dependency on other `bk-*`
crates** (they depend on it, as a dev-dependency).

**Not in this track:** running a full Ghidra installation headless
(M5, when there is something to compare); fixture builders for specific
formats (each format crate owns its builder for now; shared ones move
here later).

## 4. Behaviour

### 4.1 The reference directory
Everything is produced under one root, `../reference` relative to the
basilisk checkout (override: `BASILISK_REFERENCE_DIR`). **Nothing is ever
written into `../ghidra`.** Layout:

```
../reference/
  src/                 copy of DEC/cpp and DEC/zlib the build runs in
  bin/sleigh           Ghidra's SLEIGH compiler        (sleigh_opt)
  bin/decomp           Ghidra's decompiler console     (decomp_opt)
  bin/decomp_test      Ghidra's test runner            (decomp_test_dbg)
  bin/pcodedump        basilisk's p-code dump oracle
  Ghidra/Processors/<Module>/data/languages/…   copy of each language directory,
                       with a compiled .sla beside every .slaspec
  STAMP                Ghidra commit, tool versions, date, per-file hashes
```

The `Ghidra/Processors/…` part mirrors Ghidra's layout on purpose: the
reference tools find their languages by scanning a root for `.ldefs`
files, and basilisk's language registry (`features/lang.md`) can add this
root to get `.sla` paths.

### 4.2 `scripts/build-reference.sh`
Idempotent and incremental: a second run with nothing changed does
nothing; a changed Ghidra commit or a missing output rebuilds what is
needed. Steps:

1. Locate Ghidra (`BASILISK_GHIDRA_DIR`, default `../ghidra`); record its
   commit.
2. Copy `DEC/cpp` and `DEC/zlib` into `../reference/src` and build
   `sleigh_opt`, `decomp_opt` and `decomp_test_dbg` with the Makefile,
   using parallel make. The generated parser sources (`slghparse.cc`,
   `slghscan.cc`, `grammar.cc`, `xml.cc`, `pcodeparse.cc`, `ruleparse.cc`)
   are in the tree; avoid regenerating them where the host's `bison`/`flex`
   are too old (macOS ships bison 2.3) — touch them newer than their
   grammars, or install nothing and document what is needed. The build
   must work on macOS (Apple clang) and Linux (g++) without BFD
   (`decomp_opt` is built without `loadimage_bfd`; check how the Makefile
   selects it). Compiler warnings from Ghidra's code are not our problem;
   errors are — if the unmodified source does not build on this host,
   apply the smallest patch to the **copy**, keep the patch as a file
   under `tools/reference/patches/`, and report it.
3. Copy each `P/<Module>/data/languages` directory into the overlay and
   compile every `.slaspec` with `bin/sleigh`, in parallel, supplying the
   same preprocessor definitions Ghidra's build does (read
   `SleighCompileLauncher.java` and the Gradle `sleighCompile` task under
   `gradle/` for what they are; some specs include files from other
   processor modules). All 150 must compile; a failure stops the script
   with the compiler's message.
4. Build `bin/pcodedump`.
5. Run `bin/decomp_test` over the unit tests and data tests with the
   overlay as its SLEIGH root and write the result summary to the stamp:
   this is the baseline the Rust decompiler is measured against. Expected:
   every test passes; report any that do not on this host.
6. Write `STAMP`.

The script prints what it is doing in plain lines and ends with a short
summary (tools built, languages compiled, tests passed, elapsed time).

### 4.3 `pcodedump`
A deterministic oracle for disassembly and p-code, so `bk-sleigh` (M1) can
be compared instruction by instruction with Ghidra:

```
pcodedump <root> <language-id> <base-address> [--context name=value ...] < bytes
```

It loads the language's `.sla` and applies the `.pspec` context defaults
(as `SleighArchitecture` does), reads raw bytes from standard input (or a
hex string argument), and for each instruction from the base address
prints, in a stable line-oriented text format: the address, length, raw
bytes, mnemonic and operand text, then one line per p-code op (opcode
name, output varnode, input varnodes as `(space, offset, size)` with
register names resolved where exact). Decode errors are printed as a
marked line and decoding resumes at the next byte so a run never aborts
half-way. Document the format in `tools/reference/README.md`; it is a
contract for golden files.

### 4.4 `bk-testkit`
The Rust API other crates' tests use:

- **Locations:** `ghidra_dir()` and `reference_dir()` resolve the two
  roots from the environment variables or the defaults relative to the
  workspace root, returning `None` when absent. Helpers for the common
  paths (a processor's language directory, the data-test directory, a
  tool binary).
- **Skipping:** a way for a test to require a root or a tool and
  otherwise skip — printing one clear line saying what is missing and how
  to get it (`scripts/build-reference.sh`) and returning early. A skipped
  test must be visible in output; it must never be reported as a failure,
  and when the requirement is present the test must really run. An
  environment variable (`BASILISK_REQUIRE_REFERENCE=1`) turns skips into
  failures, for machines that are supposed to have everything.
- **Running tools:** typed wrappers that run `sleigh`, `decomp` (with a
  script), `decomp_test` and `pcodedump` with a timeout, capture output,
  and return typed results (for `pcodedump`: parsed instructions and ops;
  for `decomp_test`: per-test pass/fail). No shell interpolation of
  arguments.
- **Golden files:** compare text or bytes against a file under the
  calling crate's `tests/golden/`, with readable diffs on mismatch and
  regeneration when `UPDATE_GOLDEN=1` (`LOOP.md`, Testing rules).
- **Data tests:** a parser for Ghidra's `<decompilertest>` files into a
  typed structure (binary image: architecture, byte chunks with space and
  offset, symbols; the script lines; the string matches with their
  expected counts), since both the oracle wrappers and the future
  `bk-decomp` runner need it. Use `roxmltree`.
- **Corpus iteration:** iterate all `.slaspec` files, all language
  directories, all data tests.

## 5. Design

- `bk-testkit` modules: `paths`, `skip`, `tools/{sleigh, decomp,
  decomp_test, pcodedump}`, `golden`, `datatest/{model, parse}`,
  `corpus`. Errors use `thiserror`; this is a library, so the workspace
  lints apply to it like any other crate.
- The script is POSIX `bash` (macOS ships bash 3.2: no associative
  arrays, no `mapfile`), uses only tools present on a stock developer
  machine, and never uses `sudo`.
- Parallelism: honour `CARGO_BUILD_JOBS` or a `JOBS` variable; default to
  half the cores, since other agents are building at the same time.

## 6. Tests

- Unit tests for path resolution, skip behaviour (present, absent,
  required), golden comparison and regeneration (in a temporary
  directory), the `pcodedump` output parser (against sample text) and the
  data-test parser.
- **Corpus test:** all 93 data-test files parse; counts of byte chunks,
  script lines and string matches are reported.
- **Integration tests** (skip without `../reference`): each tool wrapper
  runs and returns sane results — `sleigh` compiles the `Toy` spec into a
  temporary directory, `pcodedump` dumps a few x86-64 and ARM instructions
  with expected mnemonics, `decomp_test` runs one data test.
- The script itself is exercised by running it; record the run in the
  status section (host, time taken, results).

## 7. Acceptance

1. `scripts/build-reference.sh` completes on this machine from a clean
   state: three Ghidra tools and `pcodedump` built, all 150 `.slaspec`
   files compiled, the baseline test run recorded. A second run is a
   no-op.
2. Nothing under `../ghidra` is created or modified
   (`git -C ../ghidra status --porcelain` is empty afterwards).
3. `bk-testkit` tests pass with and without `../reference` present (run
   both ways and say so).
4. `PERF.md` has the baseline numbers: total time to compile all
   languages and the slowest five; `.sla` sizes; `pcodedump` language
   load time and instructions per second on a large byte buffer for
   x86-64; data-test total time.
5. Gate green; files within the size limit; public items documented.

## 8. Differences from Ghidra

Not applicable (tooling). Patches applied to the copied Ghidra source, if
any, are listed here by the implementing agent.

## 9. Status

Not implemented yet.
