# Track `reference-tools` — final status report

Spec: `docs/features/reference-tools.md` (sections 8 and 9 are filled in).
Finished 2026-11-12 by a second agent from the first agent's handover; the
first agent built and tested everything below except where this report says
otherwise. Paths: `DEC/` = `Ghidra/Features/Decompiler/src/decompile/`,
`REF` = `/Users/tatu/slop/reference`.

From a worktree the documented defaults (`../ghidra`, `../reference`) do not
resolve, so commands marked "with the variables" were run with
`BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra
BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`.

Every claim is marked **[run]** (run by me, the finishing agent, on
2026-11-12), **[run, first agent]** (run by the first agent and reported in
its handover; not re-run by me) or **[not run]**.

## Built

* **`scripts/build-reference.sh [--force] [--jobs N]`** (bash 3.2). Five
  steps, each skipped when a sha256 fingerprint of its inputs (in
  `REF/.state`) is unchanged and its outputs exist: (1) copy `DEC/{cpp,zlib,
  unittests}` to staging, apply `tools/reference/patches/*.patch`, sync
  changed files into `REF/src`, build the bundled zlib, run Ghidra's
  Makefile for `sleigh_opt decomp_opt decomp_test_dbg libsla.a`, install
  `bin/{sleigh,decomp,decomp_test}`; (2) copy each processor's
  `data/languages` and compile every `.slaspec` in parallel with the
  options Ghidra's Gradle build passes; (3) build `bin/pcodedump`; (4) run
  Ghidra's unit and data tests against the overlay and record the result;
  (5) write `REF/STAMP`. Parallelism: `--jobs`, `JOBS`, `CARGO_BUILD_JOBS`,
  else half the cores. Ghidra test failures are recorded, not fatal.
* **`REF`** exists and is consistent: `bin/{sleigh,decomp,decomp_test,
  pcodedump}`, 150 `.sla`, `STAMP`. I never deleted it. I ran the script
  on it twice **[run]**: once rebuilding only `bin/pcodedump` (a comment
  changed), and once after adding `-fsigned-char`, which cleaned the
  objects in `REF/src/cpp` and rebuilt the three tools and `pcodedump`
  (103 s with 4 jobs; the 150 `.sla` stayed, because `sleigh` relinked
  byte-identical), re-ran Ghidra's tests (same 204/205, 758/760) and
  rewrote `STAMP`. A following run was a no-op (2.3 s).
* **`tools/reference/pcodedump.cc`** — the p-code oracle (format below),
  `tools/reference/README.md` (usage, format contract, Makefile overrides),
  `tools/reference/measure.sh` (the baseline numbers),
  `tools/reference/patches/0001-opbehavior-int-min-macro.patch`.
  `pcodedump.cc` now carries `SPDX-License-Identifier: GPL-3.0-or-later`;
  no basilisk file claimed Apache-2.0 (checked with `grep`) **[run]**.
* **`crates/bk-testkit`** — modules `paths`, `skip`, `tools/{process,
  sleigh, decomp, decomp_test, pcodedump}`, `datatest/{model, parse}`,
  `corpus`. The `golden` module, its `golden!()` macro and the direct
  `similar` dependency are gone; golden output is `insta` snapshots.
  No dependency on another `bk-*` crate; no `unsafe`; largest file
  `src/paths.rs`, 379 lines.

### `pcodedump` format (version 1)

`pcodedump <root> <language-id> <base-address> [--context N=V]... [--hex H]
[--quiet] [--timing] < bytes`. Tab-separated records:

```
H  version  language  code-space  base(0x)  byte-count
I  address(0x)  length  flow-length  bytes(hex)  mnemonic  operand-text
P  OPCODE  output-varnode|-  input-varnode...
U  kind  message          (the I above disassembles but did not lift)
E  address(0x)  length  bytes  kind  message   (not an instruction; resume at next byte)
T  instruction-count  error-count
```

A varnode is `(space,0xOFFSET,SIZE)`, plus a register name as a fourth
element when a register is exactly that location; the `LOAD`/`STORE` space
constant is `(const,0x3,8,ram)`. Full contract in
`tools/reference/README.md`.

### `bk-testkit` API in brief

```rust
// paths: env var, else <workspace>/../ghidra and <workspace>/../reference (needs STAMP)
bk_testkit::ghidra_dir() -> Option<GhidraDir>
bk_testkit::reference_dir() -> Option<ReferenceDir>
GhidraDir::{root, processors_dir, processor_dir, language_dir, decompiler_cpp_dir, data_tests_dir, unit_tests_dir}
ReferenceDir::{root, stamp_file, tool_path, tool, processors_dir, language_dir, sla_file}
enum Tool { Sleigh, Decomp, DecompTest, Pcodedump }

// skip: one SKIPPED line on the real stderr and None; a failure if BASILISK_REQUIRE_REFERENCE is set
let Some(ghidra) = bk_testkit::require_ghidra() else { return };
let Some(reference) = bk_testkit::require_reference() else { return };
let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else { return };

// tools (each has .timeout(Duration)); errors are tools::ToolError
reference.sleigh().define(n, v).switch('l').compile(&slaspec, &sla) -> ToolOutput
reference.decomp().run_script([...]) / run_data_test(&data_test) -> DecompTranscript
reference.decomp_test().run_unit_tests(names) -> UnitTestReport
reference.decomp_test().run_data_tests(dir, files) / run_data_test(file) -> DataTestReport
reference.pcodedump().context("TMode", 1).dump(lang, base, bytes) -> PcodeDump
reference.pcodedump().dump_text(lang, base, bytes) -> String   // deterministic; snapshot it with insta
tools::parse_dump(text) -> PcodeDump

// data tests and corpus
bk_testkit::read_data_test(path) / parse_data_test(xml) -> DataTest { image, script, matches }
ghidra.language_dirs() / ghidra.slaspec_files() / ghidra.data_tests(); reference.sla_files()
```

Golden output: `insta::assert_snapshot!(name, text)` in the calling crate's
tests, `.snap` files in `tests/snapshots/`, updated with
`INSTA_UPDATE=always` or `cargo insta review`. `bk-testkit` adds no
normalising helper: `pcodedump`'s output is already deterministic (the
snapshot is byte-identical to the old golden file, trailing tab included
**[run]**), so a helper would have no user yet.

## Tests

* `bk-testkit`, **with the variables** **[run]**: 88 unit + 4 corpus + 13
  integration + 2 doc tests pass, nothing skipped. (Before the move to
  `insta` the first agent reported 98 + 4 + 13 + 3; the difference is the
  golden module's 10 unit tests and its doc test, removed with it.)
* **Without them** (unset, in this worktree, so the defaults do not
  resolve) **[run]**: the same counts pass; 19 `SKIPPED …
  scripts/build-reference.sh …` lines on stderr.
* `BASILISK_REQUIRE_REFERENCE=1` without the oracles **[run]**: all 13
  integration tests fail, as intended.
* A changed snapshot fails the test with insta's diff **[run]** (edited
  the `.snap`, ran, restored).
* The corpus counts (93 data tests, 181 byte chunks, 1,102 script
  commands, 760 matches, 248 symbols; 150 `.slaspec`, 39 language
  directories) agree with `grep` and with `decomp_test` **[run, first
  agent]**; the corpus test asserts them and passes **[run]**.
* Ghidra's own tests ported: none apply — this track builds the oracle;
  the decompiler tests are run *by* the script as the baseline.
* **Gate**: see the end of this report.

### Ghidra's tests on this host (the baseline in `STAMP`)

**[run]** (my script run) — Darwin 25.5.0 arm64, Apple clang 17.0.0:

* Unit tests **204 / 205** pass. Fails: `double_decimal_precision`
  (`testfloatemu.cc:187`; expects `1.79769313486232e+308`, prints
  `1.7976931348623157e+308`).
* Data tests **758 / 760** checks pass in 93 files. Fail: `Float print #6`
  and `Float print #13` (`floatprint.xml`; expect `floatv6 = -NAN;` /
  `double6 = -NAN;`, the console prints `NAN`).
* Measured cause, first agent **[run, first agent]**: Apple's libc++
  parses the 15-digit text of `DBL_MAX` to `inf` with failbit, so
  `FloatFormat::printDecimal` keeps adding digits to 17. **Inference, not
  verified**: libstdc++ returns `DBL_MAX` there, and the NaN sign is an
  arm64-vs-x86 difference; see the Linux result below.
* These three are host-dependent Ghidra results, not basilisk targets; a
  Rust port should match Ghidra's intended output (`-NAN`, 15 digits).

### Linux run (optional item, done)

**[run]** in a `gcc:14` container (Linux aarch64, g++ 14.4.0, GNU make
4.4.1, 2 CPUs, 4 GB), Ghidra mounted read-only, everything written under
`target/linux-ref/` of this worktree (git-ignored; script `run.sh`, logs
`run*.log`, reference directories `out/`, `out-signed/`):

* As committed at the handover, the script built all tools and all 150
  languages (6 min 14 s with 2 jobs) and a second run was a no-op (1.9 s).
  Unit tests **205 / 205**. But `decomp_test`'s data-test run spun at full
  CPU and was killed after 193 s (exit 137; probably the 4–8 GB memory
  limit, not verified), and the script printed `/ passed` with bash's job
  message as the time and cached that result. Run one file at a time,
  every file timed out at 30 s.
* Cause, measured by changing one thing: rebuilt with
  `CXX="g++ -fsigned-char"`, the data tests run in 2 s with **758 / 760**,
  failing the same two `floatprint.xml` checks as macOS. Ghidra's C++
  assumes a signed `char`; aarch64 Linux's is unsigned. Where exactly it
  loops I did not trace.
* Fixes (committed): the script always passes `-fsigned-char` (a no-op
  where `char` is signed — on macOS `sleigh` relinked byte-identical, as the
  unchanged language fingerprints show), cleans objects when its make flags
  change, and reports a killed runner as `unit_crash` / `data_crash` with
  "did not finish" instead of empty counts, without caching it.
* So: `double_decimal_precision` passes with libstdc++ (the first agent's
  inference, now measured on aarch64), and the `-NAN` failures are not a
  macOS matter — they also occur on Linux aarch64. That they pass on
  x86-64 is still an inference; Linux x86-64 was not tried.

* With the fixes committed, the same reference directory rebuilt in the
  container (the flag change cleaned the objects; 5 min 6 s with 2 jobs):
  tools, 150 languages, unit **205 / 205**, data **758 / 760** (the two
  `Float print` checks), exit 0; a second run was a no-op (2.2 s), exit 0.

## Benchmarks

In `docs/PERF.md`, "Reference tools (baseline)", with host, date, command
and the caveat that other builds were running. I re-ran
`tools/reference/measure.sh` **[run]** and it agreed with the first
agent's run within a few percent: 150 languages in 11.8 s one at a time
(slowest `RISCV/andestar_v5` 1.74 s, then MIPS specs at about 0.46 s);
`.sla` total 12.3 MB, median 36.2 kB, largest `AARCH64BE` 501.5 kB;
x86-64 language load 48 ms; decode + lift **1.51 M instructions/s** (660
ns/instruction, 6.2 M ops/s) over 778 kB of x86-64 code; 0.33 M
instructions/s with the text listing; data tests 2.27 s; unit tests 0.77 s.
The clean-build figures (70 s wall with 4 jobs, 1.9 s no-op) are the first
agent's **[run, first agent]**. My measurement ran before the
`-fsigned-char` rebuild; on this host the flag does not change `char`, so
the numbers stand, but I did not re-measure after it.

## Differences from Ghidra

In spec section 8: one patch to the copied source (`#undef INT_MIN` in
`opbehavior.cc` for Apple clang); Makefile overrides instead of patches
(host arch, bundled zlib as Gradle builds it, no BFD and the four BFD
sources dropped from `EXTRA`); `pcodedump` departures from the spec's
wording (raw offset plus register name, flow-length field, space constant
by name, `--context` over the whole space, `.pspec` context only).

## Gaps

* No `cargo fuzz` targets. The two parsers read Ghidra's checked-in test
  files and our own tool's output, not untrusted bytes; each has
  `proptest` never-panics tests.
* `pcodedump` applies the `.pspec` `<context_data>` only; three Go `.cspec`
  files also carry some.
* `DataTestReport` cannot attribute checks to files when several files run
  at once (the runner does not print file names); `run_data_test` runs one.
* `bk-testkit` does not evaluate `<stringmatch>` patterns (that needs a
  regex engine and belongs to the `bk-decomp` runner). By `grep`, none of
  the 760 patterns uses lookaround or back-references; 47 are multi-line.
* No typed reader for `STAMP`.
* A per-function decompile timing with the optimised `bin/decomp` was not
  measured.
* Nothing was tried on Windows (`process.rs`'s tests are `cfg(unix)`).
* No case was found that `insta` cannot serve. The only byte-level
  comparison the old module offered (`assert_bytes`) had no user; `.sla`
  determinism is checked by a plain `assert_eq!` against the overlay's
  copy, which needs no checked-in file.

## Follow-ups

* **Adopting `bk-testkit`** (other tracks): add `bk-testkit.workspace =
  true` (and `insta.workspace = true` for snapshots) under
  `[dev-dependencies]`; replace local "is `../ghidra` there" helpers with
  `let Some(ghidra) = bk_testkit::require_ghidra() else { return };`, and
  `require_reference` / `require_tool` for `.sla` files and oracles; take
  paths from `GhidraDir` / `ReferenceDir` (`reference.sla_file(module,
  name)`, or `reference.root()` as a spec root) instead of joining strings;
  snapshot large output with `insta::assert_snapshot!` and parse the tool's
  output (not the `.snap`) when a test also needs structure. Integration
  test files keep the `#![allow(…, reason = "test code")]` header from
  `LOOP.md`.
* Spec corrections for the coordinator (I did not edit the spec body):
  sections 5 and 6 still name a `golden` module and "golden comparison and
  regeneration" tests, which no longer exist; section 2 says the Makefile
  compiles `DEC/zlib` (Gradle does; the Makefile links `-lz`); section 4.2
  step 3 says some specs include files from other modules (none do at this
  commit; no module passes a `-D` and none uses `$(BaseDir)`); `ruleparse.cc`
  is not in the tree (and is not needed).
* `RULES.md` still gives the `Claude Fable 5.2` trailer; this track's last
  commits use the trailer from the brief (`Claude Opus 5.5`).
* The decompiler track may want a typed `STAMP` reader ("which Ghidra
  tests fail on this host").

## Decisions and crate evaluations

crates.io figures fetched 2026-11-12 by the first agent (downloads total /
last 90 days / reverse dependencies / latest).

| Need | Crate | Decision |
|---|---|---|
| Golden output | `insta` 1.49.0 (128 M / 39 M / 5,291) | **Adopted** (coordinator's decision): snapshots replace the hand-written `golden.rs` |
| Diffs | `similar` 2.7.0 | No longer a direct dependency (still in the tree through `insta`); removed from `[workspace.dependencies]` |
| Child-process time limit | `wait-timeout` 0.2.1 (274 M / 74 M / 298) | Adopted; already in the tree through `proptest`. Pipe draining is ~30 lines in `process.rs` |
| | `process_control`, `duct`, `subprocess` | Rejected: niche, or less used with a larger surface |
| Directory walking | `walkdir` 2.5.0 (767 M / 203 M / 7,234) | Adopted |
| Data-test XML | `roxmltree` (ADR-011) | Used as the ADR decides; all 93 files parse |
| Temporary files, errors, tests | `tempfile`, `thiserror`, `rstest`, `proptest` | Used (workspace) |

Lint fixes after merging `master` were real changes except one:
`DataTestError::BadNumber` now keeps the `ParseIntError` as its source; a
pipe thread's panic message is reported; varnode fields parse through
`Option` helpers instead of discarding errors; `or_else` where the
argument is a call; the process tests are `#[cfg(test)] #[cfg(unix)]`.
The exception is `skip::report`, which panics to fail a test whose
required oracle is missing: `#[expect(clippy::panic, reason = "…")]`.

## Gate

Run exactly as `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1; echo $?`
after the last code commit (`dfe665b`; only this report changed after it)
**[run]**:

* With `BASILISK_GHIDRA_DIR` and `BASILISK_REFERENCE_DIR` set: **exit 0**,
  `tests: 107 passed, 0 failed` (all from `bk-testkit`; no other crate on
  this branch has tests yet). File size, unsafe check, fmt, clippy
  `-D warnings`, rustdoc `-D warnings`, `cargo deny` (bans, licences,
  sources ok) all passed.
* Without them: **exit 0**, `tests: 107 passed, 0 failed` (the oracle
  tests skip visibly).
* `git -C /Users/tatu/slop/ghidra status --porcelain` is empty **[run]**.

## Commits

`git log --oneline master..HEAD` (before the commit adding this report):

```
dfe665b docs(reference-tools): differences and status, with the macOS and Linux baselines
93c145b fix(reference-tools): build Ghidra's tools with signed char
3aeff96 fix(reference-tools): report a killed test runner instead of empty counts
98b694e docs(perf): reference-tools baseline numbers
c0e6d00 docs(reference-tools): pcodedump is GPL-3.0-or-later; the format contract is for snapshots
f8bac75 refactor(testkit): golden output is an insta snapshot
7ab37b5 fix(testkit): pass master's lint configuration
203a342 Merge branch 'master' into reference-tools
2a35ea0 docs(reference-tools): handover at the requested checkpoint
72ce03f test(testkit): exercise the wrappers against the real tools and corpus
f6ee2c0 feat(testkit): add bk-testkit, the test-support crate for differential tests
3bbd8dc feat(reference-tools): add measure.sh for the reference baseline numbers
98c0402 feat(reference-tools): add the pcodedump disassembly and p-code oracle
ae58eef feat(reference-tools): build Ghidra's native tools and every .sla outside both trees
```

plus the commit that adds this report. The merge of `master` had no
conflicts.
