# Progress

## Now — RESUME HERE (2026-11-12, evening)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Milestone M0 is complete and on `master`** (gate green, 1,529 tests):
`bk-core`, `bk-marshal`, `bk-pcode`, `bk-sleigh-syntax`, `bk-lang`,
`bk-bin`, `bk-elf`, `bk-testkit`, the shared `fuzz/` crate (5 targets), the
reference tools in `../reference/`. Per-track history is in the log below.

**Wave 2 is being specified.** The owner asked for specs to be written by
subagents: Fable 5.2 research agents (high effort), one per area, each in a
worktree under `../basilisk-wt/<branch>`, writing only new files:

The owner capped the project at about four agents at once, so only
`spec-sleigh`, `spec-decompiler` and `decomp-research` are running; the
other four were stopped minutes after starting (nothing written) and are
**queued** — restart each with the same brief when a slot frees, in this
order: `store-spike`, `spec-program-model`, `spec-pe`, `spec-macho`.

| Branch | Writes | For |
|---|---|---|
| `spec-sleigh` | `inventory/01-sleigh.md`, runtime and compiler specs, the shared-model crate decision | M1, M2 |
| `spec-decompiler` | `inventory/02-decompiler.md`, `features/decomp-plan.md`, specs for the first decompiler tracks | M3 |
| `spec-pe` | `features/pe.md` (crate decision by experiment, as for ELF) | M4 |
| `spec-macho` | `features/macho.md` (same) | M4 |
| `spec-program-model` | `inventory/03-program-model.md`, `features/program-model-plan.md` | M4 |
| `store-spike` | `research/storage-engine.md` + `tools/store-spike/` benchmarks | ADR-003 |
| `decomp-research` | `research/decompiler-quality.md` | M3 design, an ADR |

Still running from before (Opus 5.5, implementation):

| Branch | Crates | State |
|---|---|---|
| `gnu-disasm` | `bk-binutils-sys`, `bk-gnu-disasm`, `vendor/binutils-2.41/` | build crate done by the first agent; shim review, sanitizers, safe API in progress |
| `ui` | `bk-ui`, GUI entry in `basilisk` | data layer, design tokens, views written; shell in progress; no window yet |

Next steps for the coordinator:
1. As each spec agent reports: read its documents critically (are claims
   verified, are acceptance checks independent of the implementer, is each
   track finishable by one agent), merge the docs to `master`, turn its
   proposals into ADRs and `PLAN.md` changes, then start one Opus 5.5
   implementation agent (medium effort) per track that can start.
2. Reconcile `spec-decompiler` with `decomp-research` when both are in: the
   research may overturn IR or rule-machinery design; settle it in an ADR
   before the core IR track starts. Leaf tracks (types, circle ranges,
   `.cspec`/prototype models) need not wait.
3. Reconcile `spec-program-model` with `store-spike` the same way; decide
   ADR-003's engine.
4. Small follow-ups track (Opus), once capacity allows: move `bk-lang` and
   `bk-testkit` XML reading onto `bk-marshal`'s document (ADR-011); crates
   adopt `bk-testkit` in place of local "find Ghidra" helpers;
   differential test of `bk-marshal`'s encoders against Ghidra's binary;
   run the reference build on x86-64 Linux to confirm ADR-021's assumed
   behaviour.
5. Merge `gnu-disasm` and `ui` when they report (gate on the merge, as
   always — it has caught three real problems so far).

In a worktree `../ghidra` does not resolve; agents set
`BASILISK_GHIDRA_DIR=/Users/tatu/slop/ghidra` and
`BASILISK_REFERENCE_DIR=/Users/tatu/slop/reference`, and must also test
with the variable unset and with a non-canonical path.

**Unattended loop** (set up 2026-11-12 20:10, the owner is away): a cron
job in the coordinator's session fires every 30 minutes with the
coordinator prompt (job `045f7c32`; session-only, expires after 7 days).
Each firing follows `LOOP.md` from these files. Nothing may wait without a
time limit.

**CI is visible** (`gh` is authenticated): `gh run list`, `gh run view
<id> --log-failed`. State at 20:15: macOS and Linux jobs green; **the
Windows test job is red on `master`** — `bk-lang`
`tests/registry.rs:195` compares messages containing paths and expects `/`
where Windows gives `\`. CI stopped at the first failing binary, so more
may hide behind it; CI now runs with `--no-fail-fast` to list them all.
Under ADR-022 this must be fixed before further merges: **first in the
queue** is a small Opus track `windows-ci` — make the Windows job green
(fix path-separator assumptions in tests and, where the product formats
paths, decide the rule once), using `gh` to read each run.

**x86-64 Linux reference build**: the emulated Docker run on this Mac
was stopped (slow). The owner lent a throwaway x86-64 Linux machine on
Tailscale instead: host `kassini`, user `kassini` (Debian 13, 4 cores, 3 GB
memory, Docker). The build was started there at 20:25 by
`~/remote-build.sh` (shallow-fetches Ghidra at the pinned commit, runs
`scripts/build-reference.sh` in a `gcc:14` container, 90-minute limit);
output in `~/basilisk-ref/reference/`, log `~/basilisk-ref/run.log` (ends
with `exit=<code>`). When it finishes: read `reference/STAMP` for the test
results (ADR-021 expects the two `-NAN` checks to pass on x86-64), then
regenerate `bk-pcode`'s C++ oracle table there
(`crates/bk-pcode/tests/data/README.md`) and compare with the checked-in
aarch64 one.
*Access:* password login only; the password was given in the session and
is deliberately **not written anywhere**. The helper
`/Users/tatu/slop/reference-x86_64/kssh.exp` runs a remote command with
the password taken from the `KP` environment variable. Installing an SSH
key on the box was blocked by the session's permission system, so if the
session no longer knows the password, ask the owner (or have them install
a key) rather than guessing. Treat the box as disposable and shared: keep
everything under `~/basilisk-ref`.

**Keeping the Mac awake**: `caffeinate -ims -t 604800` is running from the
coordinator session (7 days). It does not stop a closed lid from sleeping
the machine; only the owner can do that (`sudo pmset -a disablesleep 1`).

**Queue** (start as slots free, keeping about four agents in total):
1. `windows-ci` (Opus) — above.
2. `store-spike` (Fable) — brief in this session's history; notes from its
   interrupted first run are in
   `../basilisk-wt/store-spike/docs/research/notes-ghidra-db-engine.md`
   and `notes-ghidra-program-db.md` (also useful to `spec-program-model`).
3. `spec-program-model`, `spec-pe`, `spec-macho` (Fable) — worktrees exist,
   empty; briefs as described in the table above.
4. `followups` (Opus) — step 4 below.
5. Implementation tracks from `spec-sleigh` and `spec-decompiler` as those
   specs are merged.

## Blockers

None. Open owner decisions are listed in `DIRECTION.md`.

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
