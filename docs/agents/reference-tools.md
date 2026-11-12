# Track `reference-tools` — handover

Written 2026-11-12 at a requested checkpoint. The track was stopped before
its paperwork was finished, not because anything was blocked: the script,
`pcodedump` and `bk-testkit` are built, tested and committed; what is left
is recording results in the shared docs and running the full gate (see
"Remaining"). The next agent can start from this file alone.

Spec: `docs/features/reference-tools.md`. Paths below: `DEC/` =
`Ghidra/Features/Decompiler/src/decompile/`, `REF` =
`/Users/tatu/slop/reference`.

From this worktree the documented defaults (`../ghidra`, `../reference`) do
not resolve, so every command that needs them was run with

```
export BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra
export BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference
```

## Done

| Spec section | State | Where |
|---|---|---|
| 4.1 reference directory | complete | `REF`, built and consistent (last script run finished; nothing is mid-run). Layout as in the spec plus `src/unittests`, `logs/`, `.state/` |
| 4.2 `scripts/build-reference.sh` | complete on macOS; **never run on Linux** | `scripts/build-reference.sh` |
| 4.3 `pcodedump` | complete | `tools/reference/pcodedump.cc`, format in `tools/reference/README.md` |
| 4.4 `bk-testkit` locations | complete | `crates/bk-testkit/src/paths.rs` |
| 4.4 skipping | complete | `src/skip.rs` |
| 4.4 running tools | complete | `src/tools/{process,sleigh,decomp,decomp_test}.rs`, `src/tools/pcodedump/{mod,model,parse}.rs` |
| 4.4 golden files | complete | `src/golden.rs` |
| 4.4 data tests | complete | `src/datatest/{model,parse}.rs` |
| 4.4 corpus iteration | complete | `src/corpus.rs` |
| 6 tests | complete | unit tests beside the code, `tests/corpus.rs`, `tests/reference.rs`, `tests/golden/pcodedump/x86-64.pcode` |
| Scope item 4, baseline measurements | measured, **not yet in `docs/PERF.md`** | `tools/reference/measure.sh`; numbers under "Baseline numbers" below |
| 8 Differences / 9 Status in the feature doc | **not started** | — |
| 7.5 gate | **not run** | — |

### The script

`scripts/build-reference.sh [--force] [--jobs N]`, bash 3.2 compatible. Five
steps, each skipped when a sha256 fingerprint of its inputs (kept in
`REF/.state`) is unchanged and its outputs exist:

1. Tools: copies `DEC/{cpp,zlib,unittests}` to a staging directory, applies
   `tools/reference/patches/*.patch`, copies only files whose content
   changed into `REF/src` (so `make` rebuilds the minimum), builds the
   bundled zlib, runs Ghidra's Makefile for `sleigh_opt decomp_opt
   decomp_test_dbg libsla.a`, installs `bin/{sleigh,decomp,decomp_test}`.
2. Languages: copies each `Ghidra/Processors/<Module>/data/languages` into
   the overlay (fingerprint per module), compiles every `.slaspec` without
   a `.sla` through `xargs -P`, logs and times each under
   `REF/logs/sleigh/<Module>/`. Any failure prints the compiler's output
   and exits 1.
3. `bin/pcodedump` from `tools/reference/pcodedump.cc` + `libsla.a`.
4. Ghidra's unit tests and data tests with the overlay as SLEIGH root;
   results to `REF/.state/tests.summary`. Test failures are recorded and
   printed but do not fail the script (it records a baseline).
5. `REF/STAMP` (only rewritten when something was rebuilt).

Parallelism: `--jobs`, else `JOBS`, else `CARGO_BUILD_JOBS`, else half the
cores.

### `pcodedump`

`pcodedump <root> <language-id> <base-address> [--context N=V]... [--hex H]
[--quiet] [--timing] < bytes`. Finds the language's `.ldefs` under the root
(same directory scan as `SleighArchitecture::scanForSleighDirectories`),
loads the `.sla`, applies the `.ldefs` `<truncate_space>` entries and the
`.pspec` `<context_data>`, then decodes a linear sweep. Output format
version 1, tab-separated records (full contract in
`tools/reference/README.md`):

```
H  version  language  code-space  base(0x)  byte-count
I  address(0x)  length  flow-length  bytes(hex)  mnemonic  operand-text
P  OPCODE  output-varnode|-  input-varnode...
U  kind  message          (the I above disassembles but did not lift)
E  address(0x)  length  bytes  kind  message   (not an instruction; resume at next byte)
T  instruction-count  error-count
```

A varnode is `(space,0xOFFSET,SIZE)` plus a fourth element when a register
is exactly that location, e.g. `(register,0x20,8,RSP)`. The space constant
of `LOAD`/`STORE` is printed as the space's index and name,
`(const,0x3,8,ram)`, instead of the host pointer Ghidra holds there.

Departures from the spec's wording, deliberate: the raw offset is always
printed and the register name is added, rather than replacing the offset
(a consumer needs the offset to compare; the name is a bonus check); an
extra *flow length* field (delay slots); `--context` sets the variable over
the whole code space, because a `.pspec` sets ranges, not defaults, and a
default would not override it.

### `bk-testkit` API in brief

```rust
// paths
bk_testkit::ghidra_dir() -> Option<GhidraDir>        // BASILISK_GHIDRA_DIR or <workspace>/../ghidra
bk_testkit::reference_dir() -> Option<ReferenceDir>  // BASILISK_REFERENCE_DIR or <workspace>/../reference; needs STAMP
GhidraDir::{root, processors_dir, processor_dir, language_dir, decompiler_cpp_dir, data_tests_dir, unit_tests_dir}
ReferenceDir::{root, stamp_file, tool_path, tool, processors_dir, language_dir, sla_file}
enum Tool { Sleigh, Decomp, DecompTest, Pcodedump }

// skip: one SKIPPED line on the real stderr and None; panics if BASILISK_REQUIRE_REFERENCE is set
let Some(ghidra) = bk_testkit::require_ghidra() else { return };
let Some(reference) = bk_testkit::require_reference() else { return };
let Some(reference) = bk_testkit::require_tool(Tool::Pcodedump) else { return };

// tools (each has .timeout(Duration)); errors are tools::ToolError
reference.sleigh().define(n, v).switch('l').compile(&slaspec, &sla) -> ToolOutput
reference.decomp().run_script(["load file x.xml", "lo fu main", "decompile", "print C"]) -> DecompTranscript
reference.decomp().run_data_test(&data_test) -> DecompTranscript      // .steps, .outputs_of("print C")
reference.decomp_test().run_unit_tests(names) -> UnitTestReport
reference.decomp_test().run_data_tests(dir, files) / run_data_test(file) -> DataTestReport
reference.pcodedump().context("TMode", 1).dump(lang, base, bytes) -> PcodeDump   // .instructions(), .errors()
reference.pcodedump().dump_text(lang, base, bytes) -> String                      // for golden files
tools::parse_dump(text) -> PcodeDump

// golden files under the calling crate's tests/golden/, UPDATE_GOLDEN=1 rewrites
let golden = bk_testkit::golden!();
golden.assert_text("x/y.txt", &text); golden.assert_bytes(..); golden.check_text(..) -> Result<GoldenOutcome, GoldenError>

// data tests
bk_testkit::read_data_test(path) / parse_data_test(xml) -> DataTest { image: BinaryImage, script, matches }
BinaryImage::{language_id, byte_count, to_xml}

// corpus (sorted)
ghidra.language_dirs() / ghidra.slaspec_files() / ghidra.data_tests(); reference.sla_files()
```

No dependency on another `bk-*` crate. No `unsafe`.

## Verified

Everything in this section was run by me on this host (macOS, Apple
silicon, Apple clang 17.0.0, GNU make 3.81, bash 3.2) unless it says
otherwise.

* **Clean build**: `rm -rf REF` then `JOBS=4 scripts/build-reference.sh`
  exited 0 in **70 s wall** (197 s CPU; the machine's load average was about
  8 from other agents). Built `bin/sleigh`, `bin/decomp`, `bin/decomp_test`,
  `bin/pcodedump`; **150 of 150 `.slaspec` compiled** (5 s wall with 4
  jobs); `STAMP` written.
* **Second run is a no-op**: every step "up to date", **1.9 s**, `STAMP`
  byte-identical (checked with `cmp` on an earlier pair of runs).
* **Ghidra tree untouched**: `git -C /Users/tatu/slop/ghidra status
  --porcelain` is empty after all of the above.
* **Ghidra's own tests on this host** (the baseline):
  * unit tests **204 / 205 pass**. Fails: `double_decimal_precision`
    (`testfloatemu.cc:187`, expects `1.79769313486232e+308`, gets
    `1.7976931348623157e+308`).
  * data tests **758 / 760 checks pass** in 93 files, no file fails to
    run. Fail: `Float print #6` and `Float print #13` (`floatprint.xml`;
    expected `floatv6 = -NAN;` / `double6 = -NAN;`, the console prints
    `NAN`).
  * Cause, partly verified: `FloatFormat::printDecimal` stops adding
    digits when the text parses back to the same double; I checked that
    Apple's libc++ parses the overflowing 15-digit text to `inf` with
    failbit, so the loop runs on to 17 digits. That libstdc++ returns
    `DBL_MAX` there (which would make the test pass on Linux) is my
    inference, not verified. For the NaN sign I only verified the output
    (`NAN`); that it is a host difference (arm64 vs x86) is an inference.
    Either way these three are **host-dependent Ghidra results, not
    basilisk targets**; a Rust port should match Ghidra's intended output
    (`-NAN`, 15 digits), and the baseline on a Linux x86-64 host should be
    taken before relying on them.
* **Incremental behaviour**, on a scratch copy of the Ghidra inputs (5
  modules, not a git checkout) built into a scratch reference directory,
  both deleted afterwards: no-op rerun; deleting one `.sla` recompiles
  exactly that one; editing a `.sinc` recompiles that module's 13 specs
  only; deleting `bin/decomp` relinks without recompiling; appending a
  comment to `sleigh.cc` recompiles exactly 3 objects and rebuilds
  `pcodedump`; a broken `.slaspec` stops the script with exit 1 and the
  compiler's message, and fixing it recovers. With modules missing, the
  script reported the resulting data-test errors and unit failures by name.
* **`.sla` output is deterministic**: the Toy spec compiled from the Ghidra
  tree into a temporary directory is byte-identical to the overlay's copy
  (asserted by an integration test).
* **`bk-testkit` tests, with the reference directory and Ghidra tree
  present**: 98 unit + 4 corpus + 13 integration + 3 doc tests pass, no
  skips (run again after the final clean rebuild of `REF`).
* **Without them** (`BASILISK_GHIDRA_DIR` / `BASILISK_REFERENCE_DIR`
  pointing nowhere, and also with the variables unset in this worktree):
  the same counts pass, and each of the 17 integration tests that needs
  an oracle prints one `SKIPPED <test> (<file>:<line>): … build them with
  scripts/build-reference.sh …` line to stderr, visible without
  `--nocapture` (19 lines in all: one unit test asks for both roots). The
  plain `CARGO_BUILD_JOBS=2 cargo test -p bk-testkit` with the variables
  unset was the last thing run before this file was committed: exit 0.
* **`BASILISK_REQUIRE_REFERENCE=1`**: absent roots make those tests fail
  with the same message; present roots pass.
* `cargo fmt --all --check`, `scripts/check-file-size.sh` and
  `cargo clippy -p bk-testkit --all-targets -- -D warnings` are clean at
  the last code commit.
* The corpus test's counts (93 data tests, 181 byte chunks, 1,102 script
  commands, 760 string matches, 248 symbols; 150 `.slaspec`, 39 language
  directories) agree with `grep` over the files and with `decomp_test`'s
  "Total tests applied = 760".

**Not verified / not run:**

* The **full gate** (`scripts/gate.sh`) was not run. Workspace-wide clippy
  was not run (only `-p bk-testkit`).
* **Linux**: the script and `measure.sh` have never run on Linux. They
  avoid macOS-only constructs as far as I know (`sha256sum` fallback,
  native `ARCH_TYPE`, bundled zlib so no `zlib1g-dev`), but that is
  untested. Docker is installed on this machine (linux/aarch64); I did
  not use it, because pulling an image writes outside the directories this
  track may write to.
* `process.rs`'s own tests are `#[cfg(all(test, unix))]`; nothing was
  tried on Windows.

## Baseline numbers (measured, to be put in `docs/PERF.md`)

Command: `BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference
tools/reference/measure.sh`, 2026-11-12, Ghidra 42db038f3c, Apple-silicon
Mac (8 cores, 16 GB), Apple clang 17.0.0, reference tools built `-O2`.
The machine was **not idle** (load average 8–13 from other agents), so
treat these as upper bounds on time; best-of-N is used where noted. Three
runs of the script agreed within a few percent.

| Measurement | Result |
|---|---|
| Compile all 150 languages, one at a time (sum of per-file wall times) | 11.5 s (mean 76 ms) |
| Compile all 150 languages, 4 at a time, inside the build script | 5 s wall |
| Slowest five | `RISCV/andestar_v5` 1.83 s; `MIPS/mips64le` 0.45 s; `MIPS/mips32le` 0.45 s; `MIPS/mips32R6le` 0.45 s; `MIPS/mips32R6be` 0.44 s (the next ones, including `AARCH64/AARCH64_AppleSilicon` at 0.45 s in another run, are within noise of these) |
| `.sla` sizes | 150 files, 12.3 MB total, median 36.2 kB, smallest 0.4 kB |
| Largest five `.sla` | `AARCH64/AARCH64BE` 501.5 kB; `x86/x86-64` 501.1 kB; `AARCH64/AARCH64_AppleSilicon` 497.1 kB; `AARCH64/AARCH64` 495.3 kB; `x86/x86` 439.2 kB |
| `pcodedump` language load, `x86:LE:64:default` (`.ldefs` scan + `.sla` + `.pspec`, best of 5) | 41–45 ms |
| `pcodedump --quiet`, decode + lift, no output (best of 5) | 213,187 instructions, 872,740 p-code ops in 0.142 s: **1.50 M instructions/s**, 6.1 M ops/s, 5.5 MB/s, 667 ns per instruction |
| `pcodedump`, decode + lift + text listing to `/dev/null` (best of 5) | 0.65 s: 0.32 M instructions/s |
| Input for the two rows above | 778,001 bytes: the text sections of Ghidra's `ruleaction.cc, coreaction.cc, fspec.cc, type.cc, printc.cc, funcdata_varnode.cc, block.cc, database.cc` compiled `-O2 -arch x86_64`; 1,794 positions do not decode (jump tables that clang places in the text section on macOS) |
| Data tests, all 93 files / 760 checks (`decomp_test … datatests`, best of 3) | 2.2–2.4 s |
| Unit tests, 205 (`decomp_test … unittests`, best of 3) | 0.8 s |
| Whole script, clean, 4 jobs | 70 s wall, 197 s CPU |
| Whole script, nothing to do | 1.9 s |

`decomp_test` is the debug build (`-g`, no `-O`), as Ghidra's Makefile
builds it, so the data-test time is not the optimised decompiler's speed;
`bin/decomp` is `-O2`. A per-function decompile timing with `bin/decomp`
was not measured.

## What it took to build on this machine

* **One patch to the copied source**,
  `tools/reference/patches/0001-opbehavior-int-min-macro.patch`:
  `opbehavior.cc` (lines 515 and 542 at this commit) declares
  `constexpr intb INT_MIN`; with Apple clang 17, `<limits.h>` reaches the
  file through the standard headers and `INT_MIN` is a macro, so the
  unmodified file fails with "expected unqualified-id". The patch adds
  `#undef INT_MIN` after the includes. This is independent of our build
  flags (checked by compiling the file without them). Patches apply to the
  staging copy with `patch -p1` relative to `REF/src`; a patch that no
  longer applies stops the script.
* **Makefile overrides instead of patches** (all on the `make` command
  line; table with reasons in `tools/reference/README.md`): `ARCH_TYPE=`
  (the Makefile forces `-arch x86_64` on macOS), `ADDITIONAL_FLAGS="-w
  -DLOCAL_ZLIB"`, `LNK=../zlib/libz.a`, `BFDLIB=`, and `EXTRA` recomputed
  without the BFD-dependent sources.
* **BFD**: the Makefile has no switch for it — `EXTRA` is "every `*.cc` not
  in another group", which sweeps in `loadimage_bfd.cc`, `bfd_arch.cc`,
  `codedata.cc` and `analyzesigs.cc` (the four files that include
  `loadimage_bfd.hh` / `bfd_arch.hh`; the script finds them by that
  `#include`). They are excluded by passing `EXTRA='$(filter-out <those>
  $(CORE) … ,$(ALL_NAMES))'` unexpanded so make evaluates it in place.
* **zlib**: the Makefile links `-lz`; it is Ghidra's *Gradle* build
  (`Ghidra/Features/Decompiler/buildNatives.gradle`) that compiles
  `DEC/zlib/*.c` with `NO_GZIP` and defines `LOCAL_ZLIB`. The script does
  what Gradle does, so no system zlib headers are needed.
* **bison/flex**: not used. `grammar.cc`, `xml.cc`, `pcodeparse.cc`,
  `slghparse.cc`, `slghparse.hh`, `slghscan.cc` are in the tree; after
  syncing, the script touches a generated file only when `find -newer`
  says a file it depends on in the Makefile is newer. `ruleparse.cc` is
  **not** in the tree (the spec says it is) and is not needed: nothing
  compiles it unless `CPUI_RULECOMPILE` is defined.
* **Preprocessor definitions for `.slaspec` compilation**: from
  `gradle/processorProject.gradle` (task `sleighCompile`, function
  `resolveSleighArg`) and
  `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/pcodeCPort/slgh_compile/SleighCompileOptions.java`:
  Gradle passes each module's `sleighCompileOptions` (from its
  `build.gradle`) plus `-DBaseDir=<root>`, and replaces `%%Module%%` in an
  option by the module's path under the root. At this commit the only
  options are `-l` for 12 modules (AARCH64, Dalvik, HCS08, HCS12, Hexagon,
  M16C, MCS96, MIPS, NDS32, Xtensa, Z80, eBPF) and `-t` for Hexagon; **no
  module passes a `-D`, and no `.slaspec`/`.sinc` references `$(BaseDir)`
  or includes a file from another module** (the spec expected some to).
  The script still parses the options with `awk`, resolves `%%Module%%` to
  `/Ghidra/Processors/<Module>` and passes `-DBaseDir=REF`, and drops
  options the C++ compiler lacks (`-f`, `-i`, `-d`) with a note. All 150
  compile with exactly that.
* **Things that failed along the way**:
  * `tools.fp`-style hashing through `xargs` cannot call a shell function;
    the hash command is a variable (`$SHA`).
  * `decomp` refuses to start on macOS when stdin is `/dev/null`
    (`tcgetattr` gives `ENODEV`, which `IfaceTerm` treats as fatal), so the
    Rust wrapper always gives tools a pipe.
  * `decomp -s <dir>` adds one literal directory, it does not scan a root;
    the wrapper sets `SLEIGHHOME=<reference root>` instead.
  * `decomp_test` unit tests also need the SLEIGH root (two
    `paramstore_*` tests failed in a run where their languages were
    missing), so the script passes `-sleighpath` to both modes.
  * Under `set -o pipefail`, `tail -c +N | head -c M` exits 141; handled in
    `measure.sh`.

## Remaining, in the order I would do it

1. **Merge `master`** (stricter lints, licence change to GPL-3.0-or-later)
   and fix what the new lint configuration reports in `bk-testkit`.
   `pcodedump.cc` already carries no licence header of its own.
2. **`docs/PERF.md`**: append a "Reference tools (baseline)" heading under
   "Measurements" with the table above and the command. Re-measure on an
   idle machine if one is available; say so if not.
3. **`docs/features/reference-tools.md`**: append to §8 the patch and the
   Makefile overrides (text in "What it took" above), and fill §9 Status
   (host, 70 s clean / 1.9 s warm, 150 languages, 204/205 and 758/760 with
   the three names, the spec corrections below).
4. **Run the gate**: `CARGO_BUILD_JOBS=2 scripts/gate.sh > gate.log 2>&1;
   echo $?` with the two environment variables exported, and once without
   them. Fix what it reports. Record the final "tests: N passed, 0 failed"
   line.
5. **Rewrite this file as the final status report** in the `RULES.md`
   format (Built / Tests / Benchmarks / Differences / Gaps / Follow-ups /
   Commits); most of the content is here.
6. Optional, if the coordinator wants it: a Linux run of the script (for
   example in a `gcc` container with the Ghidra tree mounted read-only),
   to turn "written for Linux" into "verified on Linux" and to see whether
   the three float tests pass there.

Spec statements that turned out wrong, for the coordinator (I did not edit
the spec):

* "`DEC/zlib/` — the zlib sources the Makefile compiles in": the Makefile
  uses `-lz`; Gradle compiles them in.
* "`ruleparse.cc` … [is] in the tree": it is not.
* "some specs include files from other processor modules": none do at this
  commit.
* "Expected: every test passes": three do not on this host (above).

Gaps I would list in the final report:

* No `cargo fuzz` targets. The two parsers here read Ghidra's checked-in
  test files and our own tool's output, not untrusted bytes; each has
  `proptest` never-panics tests. Say so rather than add targets, unless the
  coordinator disagrees.
* `pcodedump` applies the `.pspec` context only; three Go `.cspec` files
  also carry `<context_data>` (documented in the README).
* `DataTestReport` cannot attribute checks to files when several files are
  run at once (the runner does not print file names); `run_data_test` runs
  one file.
* `bk-testkit` does not evaluate `<stringmatch>` patterns; that needs a
  regular-expression engine and belongs to the `bk-decomp` runner. Useful
  for that track: by `grep`, none of the 760 patterns uses lookaround or
  back-references (the only escapes besides punctuation are `\n`, `\t`,
  `\x`), and 47 patterns are multi-line.
* There is no typed reader for `STAMP` (e.g. to ask "which Ghidra tests
  fail on this host"); not in the spec, but the decompiler track may want
  it.

What other tracks do to adopt `bk-testkit`: add `bk-testkit.workspace =
true` under `[dev-dependencies]`; replace local "is `../ghidra` there"
helpers with `let Some(ghidra) = bk_testkit::require_ghidra() else {
return };` (and `require_reference` / `require_tool` for `.sla` files and
oracles); take paths from `GhidraDir` / `ReferenceDir` instead of joining
strings; replace hand-rolled golden comparison with `bk_testkit::golden!()`;
integration-test files keep the `#![allow(…, reason = "test code")]` header
from `LOOP.md`. Tests that need compiled languages use
`reference.sla_file(module, name)` or add `reference.root()` as a spec root.

## In flight

Nothing is half-done. When the stop request arrived I had just finished the
final clean rebuild of `REF` and was running the test suite and
`measure.sh` against it to take the final numbers; both completed (results
above). The next thing would have been item 2 of "Remaining".

## Decisions and crate evaluations

crates.io figures fetched 2026-11-12 (total downloads / last 90 days /
reverse dependencies / latest release).

| Need | Crate | Figures | Decision |
|---|---|---|---|
| Readable diffs for golden mismatches | `similar` | 248 M / 72 M / 1,371 / 3.2.1 (2026-10-24) | **Adopted at 2.7.0** (2025-01-19, 151 M downloads of that version): `insta` 1.49.0, already declared in the workspace, requires `similar ^2.1`, so 2.x avoids building two majors. Moving to 3.x is a one-line change once `insta` does |
| | `pretty_assertions` | 237 M / 46 M / 5,842 / 1.4.1 | Rejected: prints the whole of both texts with no context trimming; golden files are large |
| | `diff`, `dissimilar` | 250 M / 48 M / 178; 70 M / 14 M / 56 | Rejected: no unified-diff output; fewer dependents than `similar` |
| Golden / snapshot handling | `insta` | 128 M / 39 M / 5,291 / 1.49.0 | **Not used for this**: the spec and `LOOP.md` require plain files under `tests/golden/` updated with `UPDATE_GOLDEN=1`, compared as text *or bytes*; insta's snapshots carry a metadata header, live in `snapshots/`, and use `INSTA_UPDATE` / `cargo insta`. `golden.rs` is about 150 lines over `similar`. If the coordinator prefers insta's workflow to the spec's, this is the place to switch |
| | `expect-test` | 45 M / 11 M / 356 / 1.5.1 | Rejected: text only, `UPDATE_EXPECT`, paths relative to the source file |
| | `goldenfile` | 4.7 M / 1.1 M / 36 / 1.11.0 | Rejected: niche; `UPDATE_GOLDENFILES`, compares on drop |
| Time limit on a child process | `wait-timeout` | 274 M / 74 M / 298 / 0.2.1 (2025-02-03) | **Adopted 0.2.1**; already in the dependency tree through `proptest`. Output capture is two reader threads in `process.rs` (about 30 lines) |
| | `process_control` | 1.5 M / 0.16 M / 10 / 5.2.0 | Rejected: does capture + limit in one call, but niche |
| | `duct`, `subprocess` | 45 M / 9 M / 272; 21 M / 2.9 M / 170 | Rejected: less used than `wait-timeout`, larger surface than needed |
| Directory walking | `walkdir` | 767 M / 203 M / 7,234 / 2.5.0 (2024-03-01) | **Adopted 2.5.0** (sorted, depth-limited walks in `corpus.rs`) |
| | `glob`, `ignore` | 724 M / 170 M / 4,157; 212 M / 54 M / 2,911 | Rejected: `glob` needs the root escaped; `ignore` is for gitignore semantics |
| XML for data tests | `roxmltree` | 104 M / 40 M / 994 / 0.21.2 | **Used** as ADR-011 already decided (resolved to 0.21.2). All 93 data-test files parse with it, CDATA included. `quick-xml` (542 M / 173 M / 2,935) is the more downloaded crate; I followed the ADR |
| Temporary files | `tempfile` | 988 M / 250 M / 40,862 / 3.27.0 | **Used** (workspace); a normal dependency because the console wrapper writes its script and image to temporary files |
| Errors, tests | `thiserror`, `rstest`, `proptest` | workspace | Used |

Hand-written where a crate exists, and why: `golden.rs` (above: the spec's
file layout and environment variable); pipe draining in `process.rs` (30
lines; the widely used crate, `wait-timeout`, covers only the waiting).

Other decisions:

* A skipped test writes its line with one `write_all` to `io::stderr()`,
  not `eprintln!`: the test harness captures the macro's output for passing
  tests, which would hide skips. Path resolution and the skip decision take
  an `Environment` trait so they are tested without `std::env::set_var`
  (which is `unsafe` in edition 2024).
* `reference_dir()` is `Some` only when `STAMP` exists, i.e. the script
  ran to completion once.
* The data-test parser is stricter than Ghidra on malformed input (typed
  errors where Ghidra computes garbage) and otherwise follows
  `testfunction.cc` / `loadimage_xml.cc`, including how a pattern is split
  into per-line expressions.
* The script succeeds when Ghidra's own tests fail: its job is to record
  the baseline, and the three failures above are not ours to fix.

## Commits

See `git log --oneline master..HEAD`; at the time of writing:

```
72ce03f test(testkit): exercise the wrappers against the real tools and corpus
f6ee2c0 feat(testkit): add bk-testkit, the test-support crate for differential tests
3bbd8dc feat(reference-tools): add measure.sh for the reference baseline numbers
98c0402 feat(reference-tools): add the pcodedump disassembly and p-code oracle
ae58eef feat(reference-tools): build Ghidra's native tools and every .sla outside both trees
```

plus the commit that adds this file.
