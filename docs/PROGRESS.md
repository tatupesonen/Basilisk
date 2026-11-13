# Progress

## Now — RESUME HERE (2026-11-13, 17:10)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Milestone M0 is complete and on `master`** (gate green, 1,529 tests):
`bk-core`, `bk-marshal`, `bk-pcode`, `bk-sleigh-syntax`, `bk-lang`,
`bk-bin`, `bk-elf`, `bk-testkit`, the shared `fuzz/` crate (5 targets), the
reference tools in `../reference/`. Per-track history is in the log below.

**Hard cap: four running workers** (owner, 2026-11-13), counting helpers;
agents are told to start none. Fable 5.2 (high effort) for research and
specs, Opus 5.5 (medium) for implementation.

### Running (started or resumed 2026-11-13 about 17:00)

| Branch | Model | Agent id | State |
|---|---|---|---|
| `spec-sleigh` | Fable | `a45f182816cbd805f` | resumed; had read the C++ runtime and run a `.sla` census and a `libsla` benchmark but written nothing; told to write the inventory and the runtime specs to disk first, then the compiler specs. Planned specs: `sla`, `sleigh-decode`, `sleigh-pcode`, `sleigh-language`, `sleigh-compiler-front`, `sleigh-compiler-back`, `sleigh-snippet`. |
| `gnu-disasm` | Opus | `a5b2605fa521b5dd2` | resumed; 20 commits plus 12 uncommitted files; was writing the Windows container driver (MinGW/MSVC under Wine). |
| `ui` | Opus | `a605f5e614e41a56c` | resumed; 7 commits plus uncommitted self-test work. |
| `windows-ci` | Opus | `af713570d2e64dbed` | new; makes the Windows test job green (three `bk-lang` `tests/registry.rs` failures known from run 43279380556) and sweeps the workspace for path assumptions. It cannot run Windows tests: after the merge and push the coordinator reads the Windows job and sends back any failure. |

An agent stopped by a usage limit or a session restart can be resumed with
its context intact by sending a message to its agent id (worked on
2026-11-13 for agents stopped the day before). If that fails, start a
fresh agent briefed from the branch's files.

### Queue (start as slots free, in this order)

1. `spec-decompiler` (Fable) — resume `a0c25da932de14a37`; nothing on
   disk. Writes `inventory/02-decompiler.md`, `features/decomp-plan.md`,
   specs for the first decompiler tracks (M3).
2. `decomp-research` (Fable) — resume `a53d43ea3e956d593`; 2 commits
   (experiment corpus and harness) plus an uncommitted 1,084-line
   `docs/research/decompiler-quality.md`.
3. Implementation tracks from `spec-sleigh` as its specs are merged (M1
   runtime first) — these go ahead of the remaining specs.
4. `store-spike` (Fable) — fresh agent; notes from its interrupted run in
   `../basilisk-wt/store-spike/docs/research/notes-ghidra-db-engine.md`,
   `notes-ghidra-program-db.md`, and `tools/store-spike/` (uncommitted).
   Writes `research/storage-engine.md` + benchmarks (ADR-003).
5. `spec-program-model` (Fable) — `inventory/03-program-model.md`,
   `features/program-model-plan.md` (M4); reads the store-spike notes.
6. `spec-pe` (Fable) — `features/pe.md`, crate decision by experiment as
   for ELF (M4). Four helper fact sheets wait in
   `../basilisk-wt/spec-pe/docs/agents/notes-pe-*.md` (debug directory,
   load config/exception/security, resources/rich header, CLI metadata).
7. `spec-macho` (Fable) — `features/macho.md` (M4).
8. `followups` (Opus): move `bk-lang` and `bk-testkit` XML reading onto
   `bk-marshal`'s document (ADR-011); crates adopt `bk-testkit` in place
   of local "find Ghidra" helpers; differential test of `bk-marshal`'s
   encoders against Ghidra's binary.

### Coordinator's next steps

1. `windows-ci` reports → review, merge `--no-ff`, gate, push, read the
   Windows job (`gh run list`, `gh run view <id> --log-failed`); send the
   agent any failure. Under ADR-022 the other merges wait for a green
   Windows job, or at least must not add Windows failures.
2. `gnu-disasm`, `ui` report → review against `features/gnu-disasm.md`,
   `features/ui-shell.md`; both branches are far behind master, so merge
   master's changes with care (lock file: keep versions at least two
   weeks old) and gate the merge result.
3. `spec-sleigh` reports → read critically (claims verified, acceptance
   checks independent of the implementer, each track finishable by one
   agent), merge the docs, ADRs and `PLAN.md` changes, start M1 tracks.
4. Reconcile `spec-decompiler` with `decomp-research` in an ADR before the
   decompiler core IR track starts; leaf tracks need not wait. Reconcile
   `spec-program-model` with `store-spike` the same way (ADR-003 engine).

### Working notes

* In a worktree `../ghidra` does not resolve; agents set
  `BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra` and
  `BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`, and must also test
  with the variable unset and with a non-canonical path.
* This Mac has no `timeout` command: use the Bash tool's timeout or
  `perl -e 'alarm N; exec @ARGV' <cmd> …`.
* The unattended loop is the session's self-paced `/loop` (restarted by
  the owner 2026-11-13); the earlier 30-minute cron job is gone. The
  session cannot compact its context until the Claude desktop app is
  updated (2.1.290 or newer), so the coordinator keeps its own reading
  small and relies on these files.
* CI: `gh` is authenticated. macOS and Linux jobs green; the Windows test
  job is red on `master` (see `windows-ci`).
* Keep-awake: `caffeinate -ims -t 604800` restarted 2026-11-13 17:05. It
  does not stop a closed lid from sleeping the machine.
* Orphaned helper reports are saved with
  `../basilisk-wt/save-handback.py <task-id> <file>` — never by printing
  a transcript.
* The UI build was shown to the owner on 2026-11-12 at about 20:40 and
  again at 20:24 the same evening on request; no feedback recorded.
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
* **Update the Claude desktop app** (2.1.290 or newer): `/compact` fails
  in the coordinator session on the current version, so a long unattended
  run will eventually fill its context.

## Log

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
