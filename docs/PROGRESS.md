# Progress

## Now — RESUME HERE (2026-11-14, 10:20)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Milestone M0 is complete and on `master`**; `master` also has `bk-ui`
and the GNU disassembler crates
(gate green, 1,677 tests). M0:
`bk-core`, `bk-marshal`, `bk-pcode`, `bk-sleigh-syntax`, `bk-lang`,
`bk-bin`, `bk-elf`, `bk-testkit`, the shared `fuzz/` crate (5 targets), the
reference tools in `../reference/`. Per-track history is in the log below.

Workers count helpers; agents are told to start none. Fable 5.2 (high effort) for research and
specs, Opus 5.5 (medium) for implementation.

**Hard cap: three running workers** (owner, 2026-11-14; replaces the four
above).

**`master` is red in CI on Linux and Windows** (run 43456260254, the push
of 2026-11-13 18:00; macOS, miri and `cargo-deny` green). Fixing it comes
before any other merge:

* **Linux (and the lint and rustdoc jobs, which run on Linux)**:
  `bk-binutils-sys` does not compile with GCC on `ubuntu-latest` —
  `vendor/binutils-2.41/opcodes/mips-formats.h:52: error: expected
  identifier or '(' before 'static_assert'`. The track had verified Linux
  only with clang on aarch64, and the local gate runs on macOS.
* **Windows**: three Windows-only tests added by `windows-ci` fail
  (`windows_spellings` in `bk-lang` cases 02 and 03 and in
  `bk-sleigh-syntax`): a lower-case drive letter is not upper-cased
  (left `c:\a\b`, right `C:\a\b`). The three tests that failed before
  now pass. `bk-binutils-sys` showed no error on Windows in that run; the
  `gnu-disasm` agent is asked to confirm from the log that it built and
  ran there.

Lesson for merges: a branch with C code, or with platform-specific code,
is run on Linux x86-64 with GCC (container) and for Windows under Wine
before it is merged; "not run" on a platform in an agent's report is a
reason to send it back, not a note.

### Running (resumed 2026-11-14 10:20 after the usage-limit stop of 2026-11-13 18:00)

| Branch | Model | Agent id | State |
|---|---|---|---|
| `windows-ci2` (worktree `../basilisk-wt/windows-ci`) | Opus | `af713570d2e64dbed` | fixes the three failing Windows tests; told to run Windows tests under Wine with the scripts in `../basilisk-wt/gnu-disasm/target/windows/` and to say whether Wine reproduces the CI failure. |
| `gnu-disasm` (worktree kept, fast-forwarded to master) | Opus | `a5b2605fa521b5dd2` | fixes the GCC/Linux build of `bk-binutils-sys`; verifies in a `linux/amd64` Ubuntu 24.04 container with GCC. |
| `sla` | Opus | `a10095edf70216b9d` | resumed; had 3 commits (model, reader, structural diff in progress). First SLEIGH track, `features/sla.md`. |

Stopped by the limit, to resume by id when a slot frees (work is in their
worktrees, committed up to the stop):

| Branch | Model | Agent id | State at the stop |
|---|---|---|---|
| `decomp-types` | Opus | `ae9088c291801e2f1` | nothing on disk yet (it was reading `grammar.y`); D02, `features/decomp-types.md`. |
| `store-spike` | Fable | `a8012f27279847feb` | 3 commits (workload section, verified notes) plus uncommitted files; `research/storage-engine.md`. |
| `spec-pe` | Fable | `a53aca50251d9e64c` | 2 commits (core PE fact sheet, crate evaluation started) plus uncommitted files; `features/pe.md`. |

An agent stopped by a usage limit or a session restart can be resumed with
its context intact by sending a message to its agent id. If that fails,
start a fresh agent briefed from the branch's files.

### In the coordinator's hands

* When `windows-ci2` and `gnu-disasm` report: review, merge `--no-ff`,
  gate, `scripts/check-dep-age.py`, `cargo deny check advisories`, push,
  and **read the CI run of that push on all three systems** before
  starting anything that depends on it.
* **Windows tests can be run locally under Wine**, as `gnu-disasm` did
  (MinGW and MSVC targets, cross-compiled; `cargo-xwin` for the MSVC CRT
  and SDK). Its container scripts are scratch files in
  `../basilisk-wt/gnu-disasm/target/windows/` and `target/linux/`
  (sanitizers), not committed. Queue item `win-local` turns them into
  committed tooling. Do not remove that worktree before then.
* ADR to write once CI shows the build working on Windows: builds of
  `bk-binutils-sys` for MSVC targets use `clang-cl`, not `cl.exe`
  (amends ADR-019).
* `cargo-xwin` downloaded Microsoft's CRT and SDK to this Mac
  (Microsoft's licence terms accepted on the machine's behalf); the owner
  was told on 2026-11-13.

### Queue (start as slots free, in this order)

0. Resume the three stopped agents above: `decomp-types` first (critical
   path), then `spec-pe`, then `store-spike`.
0a. **`spec-plugin`** (Fable; the owner asked for it on 2026-11-14) —
   `inventory/05-extension-points.md` and `features/plugin-api.md` for
   ADR-014 (Python through PyO3): Ghidra's extension surface
   (`GhidraScript`/`FlatProgramAPI`, analyzers, loaders, exporters,
   plugins and their services, PyGhidra, the bundled scripts), the Python
   API's shape and versioning, plugin discovery and registration, the
   embedded and the importable build, GIL and threading rules — and above
   all **the binding constraints the crates being built now must meet**
   (handles without lifetimes at the boundary, errors convertible to
   exceptions, what the program trait and the decompiler's host trait must
   expose), as a checklist the other specs and reviews can use. Start it
   as soon as a slot frees, ahead of the resumes of `spec-pe` and
   `store-spike`.
0b. **`x86-oracle`** (Opus, small): make the x86-64 table
   (`../reference-x86_64/opbehavior_cpp.x86_64.txt.gz`) `bk-pcode`'s
   checked-in oracle, fix the 106 rows where basilisk does not follow
   x86-64 (NaN inputs), drop the "created NaN sign" exception, record the
   provenance (ADR-029).
0c. **`sla-host-diff`** (Fable, small; needs `bk-sla` merged for its
   structural diff): find why 14 `.sla` files differ between x86-64 Linux
   and macOS AArch64 (ADR-029), whether the variants decode identically,
   and what the compiler's acceptance test must be. Before
   `sleigh-compiler-back`.
1. `sleigh-decode` and `sleigh-compiler-front` (Opus) — both start when
   `sla` is merged, in parallel (ADR-023). Then `sleigh-pcode`,
   `sleigh-compiler-back`, `sleigh-snippet`.
2. Decompiler wave 1 (`features/decomp-plan.md`; ADR-026, 027, 028):
   a. **Specs for D00 (oracle tooling) and D04 (`bk-decomp-cfg`)** — resume
      the spec agent `a0c25da932de14a37` (Fable; its worktree
      `../basilisk-wt/spec-decompiler` is kept, at master) to write
      `features/decomp-oracle.md` and `features/decomp-cfg.md`; the plan's
      sections 4.2, 6 and 9.1 are the briefs. Both tracks can start as
      soon as their specs exist, and D05 (IR) needs both.
   b. D03 `decomp-cspec` (Opus) — `bk-cspec` from
      `features/decomp-cspec.md`; spec complete, can start now.
   c. D01 `decomp-range` (Opus, small) — `bk-decomp-range` from
      `features/decomp-range.md`; spec complete, can start now.
   d. Then D00 and D04 implementation, then wave 2 (D05 needs D00, D02,
      D04; D06 needs D02, D03; D16a printer spike).
3. `spec-program-model` (Fable) — `inventory/03-program-model.md`,
   `features/program-model-plan.md` (M4); reads the store-spike notes and,
   when it exists, `research/storage-engine.md`.
4. `spec-pe` (Fable) — `features/pe.md`, crate decision by experiment as
   for ELF (M4). Four helper fact sheets wait in
   `../basilisk-wt/spec-pe/docs/agents/notes-pe-*.md` (debug directory,
   load config/exception/security, resources/rich header, CLI metadata).
5. `spec-macho` (Fable) — `features/macho.md` (M4).
6. `win-local` (Opus, small): `scripts/windows-test.sh` (and the
   sanitizer runner) from `gnu-disasm`'s scratch container scripts — run a
   crate's or the workspace's tests for `x86_64-pc-windows-gnu` and
   `-msvc` under Wine, bounded, documented in `LOOP.md` and `RULES.md`.
   Also from `gnu-disasm`'s follow-ups: make `bk-binutils-sys` an
   optional feature of the fuzz crate so other targets' fuzz builds do
   not compile binutils; wire `bk-lang`'s external names (`gnu`,
   `gdis.disassembler.options.file`) to `Architecture` and `gdis_config`;
   mark Hexagon's `0x18:0x5` (binutils 2.41 has no Hexagon disassembler;
   the number decodes as M9S12X).
6b. `followups` (Opus): move `bk-lang` and `bk-testkit` XML reading onto
   `bk-marshal`'s document (ADR-011); crates adopt `bk-testkit` in place
   of local "find Ghidra" helpers; differential test of `bk-marshal`'s
   encoders against Ghidra's binary; move `windows_spelling` (duplicated
   in `bk-lang` and `bk-sleigh-syntax` by `windows-ci`) into a shared
   foundation crate; evaluate `dunce` for showing plain `C:\…` paths.
7. `ui` follow-ups (Opus), when the owner has looked at the merged UI:
   the weak spots its report lists (empty Console on first open, no
   draggable horizontal scroll bar in a narrow Listing, key-binding page
   controls, snapshot tab hiding the live view), and whether the GUI
   crates should leave the default workspace build (a clean build of the
   GUI stack takes about 5 minutes and the gate about 20).

### Coordinator's next steps

1. Get CI green on all three systems (above).
2. `sla` reports → review against `features/sla.md` section 7, merge,
   start `sleigh-decode` and `sleigh-compiler-front`.
3. `decomp-types` reports → review against `features/decomp-types.md`,
   merge; with D00 and D04 merged, start D05.
4. `store-spike` reports → decide ADR-003's engine; then
   `spec-program-model`.
5. `features/sleigh-language.md` is a draft with open `[to verify]` items
   (nothing Java was run); complete it before its wave.

### Working notes

* **`kassini`** (x86-64 Linux, Debian 13, 4 cores, 1.8 GB memory, Docker
  with `gcc:14`): reachable on the owner's tailnet since 2026-11-14.
  Login is by password, given in the session and never written to files;
  `/Users/tatu/slop/reference-x86_64/kssh.exp` takes it from the `KP`
  environment variable (`KT` is its timeout in seconds; `scp` as first
  argument copies). On the box everything is under `~/basilisk-ref`
  (`reference/` is the finished build, `oracle/` the op-behaviour
  generator). Copied to this Mac: `../reference-x86_64/x86_64-linux/`
  (150 `.sla`, `STAMP`, logs) and
  `../reference-x86_64/opbehavior_cpp.x86_64.txt.gz`. `kssh.exp` prints
  nothing and exits 0 when the host does not resolve: check
  `tailscale status` first.

* In a worktree `../ghidra` does not resolve; agents set
  `BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra` and
  `BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`, and must also test
  with the variable unset and with a non-canonical path.
* This Mac has no `timeout` command: use the Bash tool's timeout or
  `perl -e 'alarm N; exec @ARGV' <cmd> …`.
* The unattended loop is the session's self-paced `/loop` (restarted by
  the owner 2026-11-13); the earlier 30-minute cron job is gone. The
  `/compact` failures of 2026-11-13 came from the usage limit (owner);
  compaction works otherwise.
* CI: `gh` is authenticated. macOS and Linux jobs green; the Windows test
  job is red on `master` (see `windows-ci`).
* Keep-awake: `caffeinate -ims -t 604800` restarted 2026-11-13 17:05. It
  does not stop a closed lid from sleeping the machine.
* Orphaned helper reports are saved with
  `../basilisk-wt/save-handback.py <task-id> <file>` — never by printing
  a transcript.
* The UI is on `master`: `cargo run -p basilisk` opens it on the demo
  program; screenshots in `docs/features/ui-screenshots/`. The owner saw
  an earlier build on 2026-11-12; no feedback recorded.
* Docker: the `gcc:14` tag on this Mac points at the amd64 image
  (`2534543d1c5c`); the arm64 image is `e750467579a2`, untagged. Tracks
  that need a particular platform use image ids, not the tag.
* History of the stop: on 2026-11-12 at about 20:25 every agent was
  stopped by the account's 5-hour usage limit; the session was later
  restarted. Nothing destructive happened; uncommitted work survived in
  the worktrees.

## Blockers

None. (The x86-64 reference build was read on 2026-11-14: ADR-029.)

## Log

### 2026-11-14 — x86-64 reference build read; owner decisions
* **x86-64 Linux reference build** (GCC 14.4): 205/205 unit tests and
  760/760 data-test checks; the two `-NAN` checks that fail on AArch64
  pass there (ADR-021 confirmed).
* **Ghidra's SLEIGH compiler output is host-dependent**: 14 of 150 `.sla`
  files differ in content between x86-64 Linux and macOS AArch64. Cause
  not yet known. ADR-029; `sleigh-compiler-back` waits for
  `sla-host-diff`.
* **`bk-pcode` against the x86-64 oracle table**: 106 rows differ (NaN
  inputs). Queue item `x86-oracle`.
* Owner, 2026-11-14: three workers; feature branches may be pushed for CI
  after local testing; the usage pace is fine; `cargo-xwin` may be used;
  the merged UI "looks great"; the plugin system (ADR-014) is to be worked
  on now — `spec-plugin` queued first.
* CI on `master` is red on Linux (GCC build of `bk-binutils-sys`) and
  Windows (three new path tests); two fix agents are running.

### 2026-11-13 — work resumed; `ui`, `windows-ci`, `gnu-disasm`, SLEIGH and decompiler specs, decompiler research merged
* **`bk-ui` merged** (gate on the merge: green, 1,608 tests). Design
  system (two themes, two densities, contrast asserted in tests), Ghidra's
  menus, tool bar and key bindings from one action registry, docking with
  native pop-out windows, Listing over `u64` rows, Decompiler view with
  cross-highlighting, tables and trees, all against a paged
  `ProgramSource` and the `licd` demo program. 79 tests (21 headless
  flows). Ten-million-row listing: 0.63 ms mean per frame. Verified by
  running on macOS only; Windows and Linux are compile-checked.
  egui 0.36.2 because `egui_dock` has no 0.37 release.
* **Lock file at the merge**: the UI branch had moved `flate2`, `itoa` and
  `smallvec` past master's versions (held back), and seven of its 329 new
  packages were younger than two weeks (pinned back: `async-executor`
  1.13.3, `async-lock` 3.4.2, `cc` 1.10.0, `crc32fast` 1.5.3,
  `serde_spanned` 1.1.2, `toml` 1.1.8, `uuid` 1.29.0). Eight more were
  published exactly 14 days before and were left. Nothing checks this
  rule mechanically yet.
* **`spec-sleigh` merged**: `inventory/01-sleigh.md` and seven specs. Its
  proposals are ADR-023 (the compiled language is its own crate `bk-sla`;
  six tracks and their order) and ADR-024 (defined results where Ghidra's
  C++ engine is undefined). Found: Ghidra's C++ engine cannot decode
  PowerPC AltiVec constructors with more than 20 operands, so "match the
  reference tool for every language" has an exception;
  `SleighCompileRegressionTest` checks Java/C++ output equality, not
  diagnostics; the snippet parser needs the compiler's template builder.
  `sleigh-language.md` is a draft.
* **`spec-decompiler` merged**: `inventory/02-decompiler.md`,
  `features/decomp-plan.md` (31 tracks in seven waves, acceptance per
  track, six levels of parity), and specs for D01 range, D02 types, D03
  cspec and D05 IR. Its proposals are ADR-026 (state crates and pass
  crates; `bk-cspec` outside the decompiler), ADR-027 (parity from
  Ghidra's own state: a dump format, the debug console, rule-subset
  oracles, recorded p-code as the interim lifter) and ADR-028 (where
  ADR-025's wording did not fit Ghidra's code). Measured: 163 rule
  classes, 161 in the pipeline (not 167); 32 of them apply in no corpus
  yet; the C++ engine is one 48-module cycle. Two Ghidra bugs in
  `parseCompilerConfig` not to reproduce. No specs yet for D00, D04 and
  D06 onward. `bk_core::Provenance` was added by the coordinator at the
  plan's request (types, cspec and symbols all carry it).
* **`decomp-research` merged**: `research/decompiler-quality.md` with a
  corpus of 36 C cases (74 builds, 209 decompiled functions) and a
  harness. Measured on Ghidra's reference build: 25 of 174 non-`void`
  functions print as `void` (one heuristic); float comparisons are wrong
  for NaN by two mechanisms; code runs on after an unmarked non-returning
  call. Its proposal is ADR-025 (profiles; the hooks the port carries
  from the start; a quality scorecard). Not established: how full Ghidra
  with its Java analyzers prints the analysis-dependent cases.
* **`gnu-disasm` merged** (gate on the merge: green, 1,677 tests):
  `bk-binutils-sys` builds binutils 2.41's disassemblers with `cc` on
  Unix and Windows targets; `bk-gnu-disasm` is the safe API
  (`Architecture::from_gnu_name`, `Disassembler`, `gdis_config`). Three
  patches to the vendored tree for state that leaked between requests
  (ARM IT/VPT, the CGEN descriptor cache's byte order, xgate/CRIS);
  RISC-V decoding nothing after the first request fixed in the shim; an
  aborting family is quarantined for the rest of the process. 69 tests,
  37 golden snapshots checked against GNU objdump 2.41; ASan and UBSan
  clean on Linux aarch64; 30 M fuzz executions over all 90 families
  clean. Windows: MinGW and MSVC (clang-cl) targets pass under Wine;
  `cl.exe` is not supported; never run on a real Windows machine. Adds
  13.4 MB to a stripped release binary and 29 MB of vendored source.
* **`windows-ci` merged** (gate on the merge: green, 1,612 tests): the three failing Windows
  tests were test assumptions about `/`; two product bugs on Windows
  fixed besides (verbatim `\\?\C:\…` paths; a definition's file name
  with a directory part never matched).
* Owner, 2026-11-13: hard cap of four running workers. The 2026-11-12
  stop was the account's 5-hour usage limit; agents were resumed by id
  with their context.

### 2026-11-12 — `bk-bin` and `bk-elf` merged; milestone M0 complete
* `bk-bin`: providers and `BinaryReader`; 162 tests, 78 of them Ghidra
  ports. `bk-elf`: 160 tests. Verified against `object` on 35 real files
  (Ghidra's 18 plus 17 clang/lld fixtures incl. Android and big-endian),
  packed relocations (RELR, APS2) against lld's unpacked twins with a
  sensitivity check, 34 tolerance tests, allocation bound measured with
  `dhat`, 15-minute fuzz run clean. Only self-consistency behind: ABI tag,
  GNU property, debug links, `SHT_SYMTAB_SHNDX`, `DT_GNU_XHASH`, prelink.
  No MIPS/PowerPC/SPARC fixtures. Ghidra itself was never run on these.
* Ghidra has no ELF parser tests; ELF is covered only through the
  processor emulator tests and three Version Tracking GUI tests (M4+).
* Gate on the merge: green, 1,529 tests.
* **M0 is complete**: `bk-core`, `bk-marshal`, `bk-pcode`,
  `bk-sleigh-syntax`, `bk-lang`, `bk-bin`, `bk-elf`, `bk-testkit` on
  master, with the shared fuzz crate (5 targets). Still running outside
  M0: `gnu-disasm`, `ui`. Next: plan wave 2 (see `## Now`).

### 2026-11-12 — `bk-sleigh-syntax` merged
* Preprocessor + source map, parser-driven modal lexer, arena AST, parser.
  317 tests. Corpus: 150 specs, 348 files, 1.12 million lines, 133,065
  constructors, 0 diagnostics, 325 ms for all of it.
* The independent check asked for at handover paid off: comparing the tree
  with Ghidra's compiled `.sla` (`sleigh -y` XML) for all 150 specs showed
  the corpus test had been passing module names as preprocessor
  definitions, so HC05/HC08 parsed the wrong conditional branches (174
  constructors instead of 86) — with zero diagnostics. Ghidra's build
  passes no definitions. "Everything parses" had hidden it.
* Not covered by any external check: semantic-section trees (Ghidra keeps
  only compiled p-code) — M2's differential tests will cover them. The Java
  front end was never run; its behaviour is from reading the grammar.
* `tests/reference/` (a model of the `.sla` XML) is reusable for M2.
* Gate on the merge: green, 1,208 tests. M0 lacks only `bin-elf`.

### 2026-11-12 — `bk-marshal`, `bk-core` and `bk-lang` merged
* `bk-marshal` + `bk-core`: XML (quick-xml) and packed encode/decode,
  byte-exact; address spaces, manager, addresses, ranges, joins. 212
  tests; two fuzz targets (60 s each, no finding). Not yet checked against
  Ghidra's binary — only against a transliteration of `marshal.cc`; now
  that `bk-testkit` is on master, a differential test is a wave 2 item.
* `bk-lang`: 236 tests; 202 languages from 52 `.ldefs`; 30-minute fuzz run
  clean. Second attempt: the first failed the merge gate (two spellings of
  the same path under a `..` root — also silently broke the `.sla` overlay
  lookup). Fixed by canonicalising roots once; `spec_root_from_env()` now
  returns `Option` (a library cannot know where the checkout is).
* The merge gate then caught a second thing, of my making: I held
  `roxmltree` at 0.21.1 on an agent's word that it was the vetted version,
  and 0.21.1 overflows the stack on deep nesting. 0.21.2 is now required
  (ADR-011).
* Follow-ups for wave 2: move `bk-lang` and `bk-testkit` XML reading onto
  `bk-marshal`'s document; tracks adopt `bk-testkit` in place of local
  "find Ghidra" helpers; differential test of `bk-marshal` encoders.
* Gate on the merge: green, 891 tests. M0 lacks only `sleigh-syntax` and
  `bin-elf`.

### 2026-11-12 — reference tools and `bk-testkit` merged; fuzzing unified
* `scripts/build-reference.sh` → `../reference/` (Ghidra's `sleigh`,
  `decomp`, `decomp_test`, `pcodedump`, all 150 `.sla`); 70 s clean, 2 s
  when nothing changed. One patch to the copied source (`#undef INT_MIN`
  for Apple clang) and `-fsigned-char` always (on Linux aarch64 Ghidra's
  data-test runner hangs with unsigned `char`).
* Ghidra's own tests, the baseline: macOS arm64 204/205 unit, 758/760
  data-test checks; Linux aarch64 (container) 205/205 and 758/760. The two
  `-NAN` checks fail on both aarch64 hosts; x86-64 not run (ADR-021).
* `bk-testkit`: locate/require the oracles (skips print one line; fail
  under `BASILISK_REQUIRE_REFERENCE=1`), tool wrappers, `pcodedump` parser,
  data-test parser, corpus iterators. Goldens are `insta` snapshots.
  107 tests, pass with and without the oracles. Baselines in `PERF.md`.
* **Fuzzing unified** (owner): one root `fuzz/` crate for all targets,
  `scripts/fuzz-smoke.sh`, rule in `LOOP.md`; tracks told to move theirs.
* **Merge gate caught a bug in `lang`**: its corpus test passed in the
  worktree (absolute `BASILISK_GHIDRA_DIR`) and failed in the main
  checkout (default root with `..`). Sent back. Lesson, now told to every
  track: run tests with the variable unset and with a non-canonical path.
* Gate on the merge: green, 443 tests.

### 2026-11-12 — `bk-pcode` merged (first code on master)
* Opcodes (73, not 74), `u64` op behaviours matching Ghidra's C++, wide
  behaviours (to 64 bytes) matching the Java, host-level and exact float
  formats, multiprecision on `u128`. Started by Fable, finished by Opus.
* Tests: 336 (4 benchmarks ignored). Ported and marked: `testfloatemu.cc`
  31, `testmultiprec.cc` 5, `BigFloatTest` 26, `FloatFormatTest` 58, all 40
  `OpBehavior*Test` classes. A differential test replays 87,176 cases
  evaluated by Ghidra's compiled C++ (`tests/data/opbehavior_cpp.txt.gz`);
  basilisk differs only in three documented classes.
* Learned: Ghidra's float behaviour is host-dependent in places (ADR-021:
  take x86-64's). The oracle found an undocumented difference (`INT_SEXT`
  with odd sizes, 280 rows), which was reverted to Ghidra's behaviour — the
  differential test earned its keep. Not run on x86-64.
* Gate on the merge: green.

### 2026-11-12 — logo merged
* `assets/brand/`: mark (dark, light, mono), logos, app icon and a
  simplified small-size icon, PNGs at 16–1,024 px, palette and usage in its
  README. Ember `#FF6A2B` on Soot `#150F0D`; Ember deep `#E8551A` on light
  backgrounds. Known weak spot: the 16 px icon is soft. Ember is a
  red-orange (hue 18°), the nearest of the variants to Ghidra's red; the
  owner chose it knowing that.

### 2026-11-12 — project set up
* Surveyed Ghidra at commit `42db038f3c` (`inventory/00-overview.md`).
* Owner decisions recorded in `DIRECTION.md`; ADR-001 to ADR-015 written.
* Workspace skeleton: lints, gate (`scripts/gate.sh`, with a file-size
  check), toolchain pin 1.97.1, CI, Apache-2.0 licence and NOTICE.
* Test-parity checklist generated (`scripts/gen-test-inventory.py` →
  `inventory/tests/`): 1,706 JUnit classes with 19,092 tests (801 classes
  drive the GUI), 205 C++ unit tests, 93 decompiler data tests.
* Wave 1 feature specs written; agents started.
