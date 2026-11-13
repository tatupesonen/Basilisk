# Progress

## Now — RESUME HERE (2026-11-13, 17:20)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Milestone M0 is complete and on `master`**; `master` also has `bk-ui`
(gate green, 1,608 tests). M0:
`bk-core`, `bk-marshal`, `bk-pcode`, `bk-sleigh-syntax`, `bk-lang`,
`bk-bin`, `bk-elf`, `bk-testkit`, the shared `fuzz/` crate (5 targets), the
reference tools in `../reference/`. Per-track history is in the log below.

**Hard cap: four running workers** (owner, 2026-11-13), counting helpers;
agents are told to start none. Fable 5.2 (high effort) for research and
specs, Opus 5.5 (medium) for implementation.

### Running (state at 2026-11-13 about 17:20)

| Branch | Model | Agent id | State |
|---|---|---|---|
| `spec-decompiler` | Fable | `a0c25da932de14a37` | resumed 17:05; writes `inventory/02-decompiler.md`, `features/decomp-plan.md` and the first decompiler track specs. Told at 17:20 that ADR-025 binds the plan (profiles; six properties the port has from its first version) and to say so with evidence if any of them is unworkable. |
| `gnu-disasm` | Opus | `a5b2605fa521b5dd2` | resumed 17:00; had 20 commits plus 12 uncommitted files; finishing the Windows container driver (MinGW/MSVC under Wine). |
| `sla` | Opus | `a10095edf70216b9d` | started 17:20; implements `bk-sla` from `features/sla.md` (first SLEIGH track, ADR-023). |
| `store-spike` | Fable | `a8012f27279847feb` | started 17:20 (fresh agent); `research/storage-engine.md` plus benchmarks in `tools/store-spike/` (its own workspace), recommends the engine for ADR-003. |

An agent stopped by a usage limit or a session restart can be resumed with
its context intact by sending a message to its agent id (worked on
2026-11-13 for agents stopped the day before). If that fails, start a
fresh agent briefed from the branch's files.

### In the coordinator's hands

* **`windows-ci`** (branch and worktree still present): finished about 17:10,
  reviewed, **not merged yet** — merge `--no-ff`, gate, push, then read
  the Windows job (`gh run list`, `gh run view <id> --log-failed`). The
  agent (`af713570d2e64dbed`, resumable) fixes whatever CI still shows.
  Its report: `../basilisk-wt/windows-ci/docs/agents/windows-ci.md`. After
  the merge, record under "Differences from Ghidra" in `features/lang.md`
  that a `/` in a file name of a definition stands for the platform's
  separator (Ghidra's text comparison never matches on Windows).
* **Two-week rule is not checked by the gate.** The UI branch's lock file
  had seven crates younger than two weeks. Add `scripts/check-dep-age.py`
  (compare `Cargo.lock` with `master`'s, ask crates.io for each new
  package's publish date, fail on anything under 14 days) and run it at
  every merge; a first version is in the session scratchpad only, so
  write it again if the session is gone. Not part of the offline gate.

### Queue (start as slots free, in this order)

1. `sleigh-decode` and `sleigh-compiler-front` (Opus) — both start when
   `sla` is merged, in parallel (ADR-023). Then `sleigh-pcode`,
   `sleigh-compiler-back`, `sleigh-snippet`.
2. Decompiler leaf tracks named by `spec-decompiler` when it reports.
3. `spec-program-model` (Fable) — `inventory/03-program-model.md`,
   `features/program-model-plan.md` (M4); reads the store-spike notes and,
   when it exists, `research/storage-engine.md`.
4. `spec-pe` (Fable) — `features/pe.md`, crate decision by experiment as
   for ELF (M4). Four helper fact sheets wait in
   `../basilisk-wt/spec-pe/docs/agents/notes-pe-*.md` (debug directory,
   load config/exception/security, resources/rich header, CLI metadata).
5. `spec-macho` (Fable) — `features/macho.md` (M4).
6. `followups` (Opus): move `bk-lang` and `bk-testkit` XML reading onto
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

1. Merge `windows-ci` (above).
2. `gnu-disasm` reports → review against `features/gnu-disasm.md`; the
   branch is far behind master, so merge with care (lock file: keep
   master's versions, check the age of every new package) and gate.
3. `sla` reports → review against `features/sla.md` section 7, merge,
   start `sleigh-decode` and `sleigh-compiler-front`.
4. `spec-decompiler` reports → read critically, check it against ADR-025,
   merge, start the leaf tracks.
5. `store-spike` reports → decide ADR-003's engine; then
   `spec-program-model`.
6. `features/sleigh-language.md` is a draft with open `[to verify]` items
   (nothing Java was run); complete it before its wave.

### Working notes

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

* **x86-64 Linux reference build (ADR-021) — the box is not reachable.**
  The build started on the lent box `kassini` on 2026-11-12 at 20:25
  (`~/remote-build.sh`, output `~/basilisk-ref/reference/`, log
  `~/basilisk-ref/run.log` ending in `exit=<code>`) has not been read.
  The owner gave the login again on 2026-11-13 (kept in the session only,
  never written to files). Tailscale on this Mac was stopped and was
  brought up again at 17:15, but **no machine named `kassini` is on the
  tailnet** (`tailscale status` does not list it; the name does not
  resolve), so it is off, removed, or on another tailnet. Owner: turn it
  on or re-add it, or give its address. Note that
  `/Users/tatu/slop/reference-x86_64/kssh.exp` (password from the `KP`
  environment variable) prints nothing and exits 0 when the host does not
  resolve — check `tailscale status` first. The emulated Docker build on
  this Mac was killed for lack of memory (`exit=137`). When access is
  back: read `reference/STAMP` (the two `-NAN` checks should pass on
  x86-64), regenerate `bk-pcode`'s C++ oracle table there
  (`crates/bk-pcode/tests/data/README.md`) and compare it with the
  checked-in aarch64 one. Nothing else waits on this.

## Log

### 2026-11-13 — work resumed; `ui`, SLEIGH specs and decompiler research merged
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
* **`decomp-research` merged**: `research/decompiler-quality.md` with a
  corpus of 36 C cases (74 builds, 209 decompiled functions) and a
  harness. Measured on Ghidra's reference build: 25 of 174 non-`void`
  functions print as `void` (one heuristic); float comparisons are wrong
  for NaN by two mechanisms; code runs on after an unmarked non-returning
  call. Its proposal is ADR-025 (profiles; the hooks the port carries
  from the start; a quality scorecard). Not established: how full Ghidra
  with its Java analyzers prints the analysis-dependent cases.
* **`windows-ci` finished**, merge pending: the three failing Windows
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
