# Progress

## Now — RESUME HERE (2026-11-12)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Wave 1 (milestone M0) is in progress.** Six implementation agents and one design agent
(Fable 5.2, started at high effort; agents started from now on run at medium), one per track, each in its own worktree under
`../basilisk-wt/<track>` on branch `<track>`:

| Track / branch | Crates | Spec |
|---|---|---|
| `core-marshal` | `bk-core`, `bk-marshal` | `features/core-marshal.md` — **merged 2026-11-12** |
| `pcode` | `bk-pcode` | `features/pcode.md` — **merged 2026-11-12** |
| `sleigh-syntax` | `bk-sleigh-syntax` | `features/sleigh-syntax.md` — **merged 2026-11-12** |
| `lang` | `bk-lang` | `features/lang.md` — **merged 2026-11-12** (second attempt, after the root-path fix) |
| `bin-elf` | `bk-bin`, `bk-elf` | `features/bin-elf.md` — checkpointed by Fable (`bk-bin` complete; `bk-elf` about half written; tests pass by its report, clippy not clean); continued by Opus 5.5 |
| `reference-tools` | `bk-testkit`, `scripts/build-reference.sh` | `features/reference-tools.md` — **merged 2026-11-12** |
| `ui` | `bk-ui`, GUI entry in `basilisk` | `features/ui-shell.md` — started 2026-11-12 at the owner's request, ahead of M7: design system, shell and core views against a demo data source (Opus 5.5) |
| `logo` | `assets/brand/` (no crates) | **merged 2026-11-12**: crowned serpent ring, ember orange (the owner's pick, variant A4) |
| `gnu-disasm` | `bk-binutils-sys`, `bk-gnu-disasm`, `vendor/binutils-2.41/` | `features/gnu-disasm.md` (ADR-019) — checkpointed by Fable (vendored subset and `bk-binutils-sys` building on macOS; `bk-gnu-disasm` not started); continued by Opus 5.5 |

In a worktree `../ghidra` does not resolve; agents set
`BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra` and
`BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`.

**Handover to Opus 5.5** (owner, 2026-11-12): each wave 1 agent was told to
stop at its first checkpoint — crates building, current tests passing,
everything committed, `docs/agents/<track>.md` written with done/remaining.
When a track checkpoints: read its report, start an Opus 5.5 agent (medium
effort) in the same worktree to finish the spec, beginning with
`git merge master` (stricter lints, ADR-018 licence, ADR-020 unsafe rule).

Next steps for the coordinator:
1. As each agent reports, review its branch against its spec
   (`git -C ../basilisk-wt/<track> log --oneline master..HEAD`, read the
   diff and `docs/agents/<track>.md`), run the gate on the merge, merge to
   `master`, remove the worktree.
2. After `core-marshal` and `lang` are both merged, move `bk-lang`'s XML
   reading from `roxmltree` onto `bk-marshal`'s document (ADR-011). The
   opcode attribute needs no glue: `bk-marshal` has generic
   `read_enum`/`write_enum`.
3. Tick M0 in `PLAN.md`, update `PARITY.md`, log the wave below.
4. Plan wave 2 (`PLAN.md`, "Working in waves"): write the inventory
   sections and feature specs for the SLEIGH runtime, the SLEIGH compiler's
   semantic analysis, the decompiler IR and type system, PE and Mach-O
   parsers, and the Microsoft demangler; then start the agents.

## Blockers

None. Open owner decisions are listed in `DIRECTION.md`.

## Log

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
