# Progress

## Now — RESUME HERE (2026-11-14 15:48)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Milestone M0 is complete and on `master`**; `master` also has `bk-ui`
the GNU disassembler crates, `bk-sla`, `bk-decomp-types`, `bk-sleigh`
part 1, `bk-sleigh-compiler` part 1 and the website (gate green, 1,819
tests). M0:
`bk-core`, `bk-marshal`, `bk-pcode`, `bk-sleigh-syntax`, `bk-lang`,
`bk-bin`, `bk-elf`, `bk-testkit`, the shared `fuzz/` crate (5 targets), the
reference tools in `../reference/`. Per-track history is in the log below.

Workers count helpers; agents are told to start none. Fable 5.2 (high effort) for research and
specs, Opus 5.5 (medium) for implementation.

**Hard cap: three running workers** (owner, 2026-11-14; replaces the four
above).

**`master` is green in CI on Linux, macOS and Windows** since the merge
of branch `integration` on 2026-11-14 11:30 (CI run 43578142514 on the
branch: every job green; local gate 1,708 tests). It holds `bk-sla`, the
GCC 15 build fix for `bk-binutils-sys` and the Windows path fixes.

**How merges are done now** (owner allows pushing tested feature
branches, 2026-11-14): finished branches are merged into a branch
`integration` cut from `master`; the gate, `scripts/check-dep-age.py
master` and `cargo deny check advisories` run on it; it is pushed and CI
started with `gh workflow run CI --ref integration`; it is merged to
`master` (`--no-ff`) only when every job is green on all three systems,
and then deleted. A red job goes back to the agent whose crate it is.
A report that says "not run" for a platform is not a reason to skip this.

**Resumed 2026-11-14 15:07 after the usage-limit stop of 13:30.** Cap:
**two workers** (owner, 15:07; three and briefly five earlier the same
day). Existing work is never thrown away (owner): pause agents at a safe
point, keep worktrees and branches until their content is on `master`.
`sleigh-pcode` was asked at 15:07 to pause cleanly (commit, clean status,
stop) and is **first to resume** when a slot frees.

**`master` is RED on Rust 1.100.0** (`144859f`, committed directly at the
owner's choice on 2026-11-14 at 15:50; released 2026-11-09). The gate on
`master` fails at its format step: rustfmt 1.100 formats six places in
`crates/bk-elf` differently (macro invocations in
`src/constants/mod.rs` and others). The gate stops at the first failing
step, so what clippy, rustdoc and the tests say on 1.100.0 is not known
yet; CI on the push will show the lint job red at least. **Nothing is
merged to `master` until this is fixed.** Track `toolchain-1.100` (Opus)
takes the slot of `decomp-cspec`, which was asked to pause cleanly at
16:00: on a branch from `master`, `cargo fmt`, then fix everything clippy
(`-D warnings`, all targets), rustdoc and the tests report on 1.100.0
across the workspace and the fuzz crate, without weakening lints; check
the Windows target and Wine; gate; integration branch; CI; merge. The
running agents keep their worktrees on 1.97.1 until then (they were NOT
told to change it); after the merge each is told to set
`rust-toolchain.toml` to 1.100.0, run `cargo fmt` and clippy on its own
crate, and continue.

**On `master` since 15:27 (CI run 43598927755 green on every job on all
three systems, including the new `site` job; gate 1,819 tests):
`bk-sleigh` part 1 (`sleigh-decode`), `bk-sleigh-compiler` part 1
(`sleigh-compiler-front`), `bk-pcode` on the x86-64 oracle (`x86-oracle`,
ADR-033; the regeneration on `kassini` with the fixed generator gave text
identical to the checked-in table) and the website with the
documentation's shell (`site/`, ADR-030, ADR-031). Their worktrees and
branches are removed; `integration` is deleted.

**For the owner, to publish the site**: GitHub → Settings → Pages →
Build and deployment → Source "GitHub Actions"; then the `Pages` workflow
is run (`gh workflow run Pages`). It goes live at
`https://tatupesonen.github.io/basilisk/`, or at a custom domain if one
is set in the same settings.

### Running (updated 15:28; state at 2026-11-14 15:07)

| Branch | Model | Agent id | State |
|---|---|---|---|
| `decomp-cspec` | Opus | `aaa90a7df42087601` | resumed 15:07 (three uncommitted files); D03, `bk-cspec`. |
| `sleigh-pcode` | Opus | `a392a8e6a16d0c340` | resumed 15:28 from its status file (reading done, six-step plan); given the `pcodedump` crash analysis. `bk-sleigh` part 2 from `features/sleigh-pcode.md`. |

Stopped by the limit on 2026-11-13, to resume by id when a slot frees:

| Branch | Model | Agent id | State at the stop |
|---|---|---|---|
| `store-spike` | Fable | `a8012f27279847feb` | 3 commits (workload section, verified notes) plus uncommitted files; `research/storage-engine.md`. |
| `spec-pe` | Fable | `a53aca50251d9e64c` | 2 commits (core PE fact sheet, crate evaluation started) plus uncommitted files; `features/pe.md`. |

An agent stopped by a usage limit or a session restart can be resumed with
its context intact by sending a message to its agent id. If that fails,
start a fresh agent briefed from the branch's files.

### In the coordinator's hands

* **Windows tests can be run locally under Wine** (MinGW target; it
  reproduced the three CI failures of 2026-11-13, but it is not MSVC and
  its symbolic links differ, so CI stays the final check). The scripts
  are scratch files, not committed: `../basilisk-wt/windows-ci/target/windows/`
  (`dock.sh`, `run.sh`: any crate without C code, Ghidra tree mounted),
  `../basilisk-wt/gnu-disasm/target/windows/` (C crates, MSVC through
  `cargo-xwin`), `target/linux/` (sanitizers) and `target/ubuntu2604/`
  (GCC 15, both architectures) there. Queue item `win-local` turns them
  into committed tooling. Do not remove those two worktrees before then.
* ADR to write: builds of `bk-binutils-sys` for MSVC targets use
  `clang-cl`, not `cl.exe`, and every compiler is pinned to `gnu17`
  (amends ADR-019). CI has shown both crates passing on the Windows
  runner.
* `cargo-xwin` downloaded Microsoft's CRT and SDK to this Mac
  (Microsoft's licence terms accepted on the machine's behalf); the owner
  was told on 2026-11-13.

### Queue (start as slots free, in this order)

0. Resume the two stopped agents above: `spec-pe`, then `store-spike`.
0a. **Plugin tracks** (`features/plugin-api.md`; ADR-035, ADR-036,
   ADR-037; unblocked by the owner on 2026-11-14): P0 reference fixtures,
   P1 host and packaging, P3 flat scripting layer can start; the first of
   them also corrects the spec's script-failure default (keep changes,
   roll back only on opt-in). They come after the SLEIGH compiler back
   half in the order below. Also from the spec, independent of those:
   (i) move the monitor type (cancel and progress) out of `bk-ui` into a
   low crate before the M4/M5 specs — a small Opus track; (ii) the next
   UI track lets the action registry and the view kinds accept run-time
   entries; (iii) the program-model, storage, analysis and decompiler
   D07/D17 specs state compliance with binding-constraint items 3, 6, 7,
   9, 11 and 13.
0a2. (running) `site-design`.
0a3. **`docs-content`** (Opus; after `site-design` and `spec-plugin`) —
   the documentation itself: Getting started, the interface (one page per
   view, from `features/ui-shell.md`), the command line, analysis, the
   decompiler, scripting and plugins (from `features/plugin-api.md`),
   formats and processors, and "How it works" (SLEIGH, p-code, the
   decompiler pipeline, the program database) with Mermaid diagrams of
   the data flow, the pipelines and the crate map; each page says plainly
   what exists today and what is planned; the key-binding table is
   generated from the action registry, CLI help from the binary, the
   Python API reference from the plugin package when it exists; adds the
   rule to `RULES.md` that a track changing user-visible behaviour
   updates its page.
0b. **`x86-oracle`** (Opus, small): make the x86-64 table
   (`../reference-x86_64/opbehavior_cpp.x86_64.txt.gz`) `bk-pcode`'s
   checked-in oracle, fix the 106 rows where basilisk does not follow
   x86-64 (NaN inputs), drop the "created NaN sign" exception, record the
   provenance (ADR-029).
0c. `ref-nofma` is merged (2026-11-14; ADR-034): `../reference` is the
   unfused build and the oracle for all 150 specifications;
   `features/sleigh-compiler-back.md` carries ADR-032's edits. Left over:
   `tools/reference/README.md` still lists `ADDITIONAL_FLAGS` without the
   flag (give it to the next tooling track); the five ARM v8-m
   `pcodedump` crashes are not reproduced (probably a second bug:
   `sleigh-pcode` is to record their bytes and context); Docker image
   `e750467579a2` (arm64 `gcc:14`, untagged, 1.5 GB) can be removed when
   nothing needs it.
1. `sleigh-compiler-front` (Opus) — can start now (`sleigh-decode` is
   running). Then `sleigh-pcode` (after `sleigh-decode`),
   `sleigh-compiler-back` (after the front half and `ref-nofma`),
   `sleigh-snippet`.
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

1. As slots free, in this order (owner, 2026-11-14: finish SLEIGH
   first): `toolchain-1.100` only if the gate or CI is red on 1.100.0;
   `sleigh-compiler-back`; `sleigh-snippet`; then the decompiler's first
   wave: D01
   `decomp-range`, an Opus agent to write the D00 and D04 specs,
   `ref-nofma`, `win-local`, the monitor-type move (queue item 0a), then
   the rest of the queue.
2. `decomp-types`: in CI (above). Follow-ups it names for D03
   (`PrototypeCodec`, `TypeEnv::default_model`), D06 (`SpacebaseScopes`,
   `TypeSource`) and D08 (the five `cast_*` tests) go into those briefs.
3. `sleigh-decode` reports → review against `features/sleigh-decode.md`,
   integration branch, merge; start `sleigh-pcode`.
4. `site-design` reports → look at its screenshots, integration branch
   (it adds a CI job), merge; tell the owner what to enable for Pages;
   start `docs-content`.
5. Owner answers the plugin-host Blocker → adopt the ADRs, plan P0–P7.
6. `store-spike` reports → decide ADR-003's engine; then
   `spec-program-model`.
7. `features/sleigh-language.md` is a draft with open `[to verify]` items
   (nothing Java was run); complete it before its wave.

### Working notes

* **Idea recorded, not queued** (owner, 2026-11-14: "Not now"): improving
  the SLEIGH specifications themselves — testing each instruction's
  p-code against an emulator or a CPU to find specification bugs, and
  basilisk-owned overlays for unimplemented instructions and for vector
  operations that Ghidra models as opaque user ops. Needs an ADR
  (ADR-002 says the specifications are used unchanged) if it is taken up.
* **The site is built but not published** (owner, 2026-11-14: "Not until
  there is more to show"). When the owner says so: Settings → Pages →
  Source "GitHub Actions", then `gh workflow run Pages`.
* `spec-pe` and `store-spike` (Fable, paused since 2026-11-13) are
  resumed as they are when their turn comes (owner, 2026-11-14).

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

None. The owner answered the open questions on 2026-11-14 (`DIRECTION.md`,
"Owner's answers of 2026-11-14"; ADR-035, ADR-036).

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
* **`bk-sla` merged** (first SLEIGH track, M1): all 150 reference files
  round-trip byte for byte through two decoders; XML equals `sleigh -y`;
  `x86-64.sla` reads in 17.9 ms against 30.8 ms for Ghidra's loader;
  model heap 13.4 MB; 16 mutations tried, one caught only by a unit
  test; a fuzz finding (NUL in strings) fixed.
* **CI green on all three systems** after two fix rounds: GitHub's
  `ubuntu-latest` is Ubuntu 26.04 whose GCC 15 defaults to C23
  (`static_assert` is a keyword) — `bk-binutils-sys` now pins `gnu17`;
  Rust's `Prefix::Disk` already upper-cases the drive letter, so the
  lower-case check never fired; under MinGW the C library's `round()` is
  wrong for 0.49999999999999994 — `bk-pcode` rounds with `libm`; CR16 in
  binutils printed a stale operand (patch 0004). Both GNU disassembler
  crates pass on the real Windows runner. Merges now go through an
  `integration` branch with CI before `master`.
* **`ref-nofma` merged** (ADR-034): the reference tools are built with
  `-ffp-contract=off`; on this Mac all 150 `.sla` now equal x86-64
  Linux's, with Ghidra's tests, `pcodedump` and the `decomp` console
  unchanged. The `pcodedump` crash on SPARC and MIPS is one Ghidra bug (a
  dangling walker after `UnimplError` in a delay slot), with two 8-byte
  reproducers.
* **`bk-sleigh` part 1 merged** (`sleigh-decode`): no `I`/`E`/`T` record
  differs from `pcodedump` over 175 language configurations (99.33 % of
  root pairs, 97.2 % of constructors); decode 3.25 M instructions/s
  against 3.17 M for Ghidra, decode + text 2.41 M against 1.50 M; no
  allocation per instruction. Missed target: 8-thread scaling 4.78×
  against 6×, measured on a loaded machine. `pcodedump` crashes on a
  delay-slot instruction with an `unimpl` body (36 cases).
* **`bk-sleigh-compiler` part 1 merged** (`sleigh-compiler-front`): for
  all 150 specifications the symbols, constructors, print pieces, context
  changes and templates equal Ghidra's compiled files; three mutations
  made the comparison fail on 133, 82 and 18 specifications; 92
  diagnostic cases equal to Ghidra's compiler (which crashes on two
  inputs); parse + elaborate of all 150 in 1.03 s against about 11.5 s
  for Ghidra's whole compile.
* **`bk-pcode` on the x86-64 oracle** (`x86-oracle`, ADR-033) and **the
  website** (`site-design`; its CI job first failed on the runner's two
  CPUs, fixed by sizing the container from `docker info`) merged.
* Coordinator's mistake, 13:25: a "keep both sides" script produced
  invalid TOML in `fuzz/Cargo.toml` on the integration branch, and
  neither the gate nor CI builds the fuzz crate. Found by comparing bin
  entries with target files; the branch was rebuilt and resolved by hand.
  A gate step that parses the fuzz manifest is queued (`win-local`).
* Owner, 2026-11-14 afternoon: Rust toolchain 1.100.0 (staged in the main
  checkout, lands through track `toolchain-1.100`); two running workers
  for now; existing work is never thrown away.
* **`bk-decomp-types` merged** (D02, first decompiler crate; CI green on
  all three systems, gate on `master` 1,747 tests): every type kind, the
  factory, both orderings, XML, the C declaration parser, provenance and
  per-function overlays. 197,330 oracle records from Ghidra's compiled
  `TypeFactory` replay with 60 listed differences (prototype storage is
  D03's); data organisation of all 294 language/compiler pairs matches.
  The first merge attempt failed on the integration gate: a property
  test found that a fork refused to complete a parent's incomplete
  structure; forks are now copy-on-write under the same id. Lesson, now
  in the briefs: check in `*.proptest-regressions` and run properties at
  a high case count once before reporting.
* **`site-design` finished** (not merged: its CI job asks Docker for 3
  CPUs and the runner has 2): the website and the documentation's shell
  as one static Astro/Starlight project built only in a container;
  status table and milestone marker generated from `PARITY.md` and
  `PLAN.md`; Mermaid rendered to SVG at build time; no external requests.
  The owner was sent screenshots.
* **`sla-host-diff` merged — the cause of the 14 differing `.sla` files
  is floating-point contraction** (ADR-032): `DecisionNode::getScore`
  computes `sc -= p * log(p)`, which AArch64 compilers fuse into one
  multiply-subtract and x86-64 compilers without FMA do not; at 25
  decision nodes two fields tie mathematically and the last bit decides.
  Shown by 14 container builds (macOS with `-ffp-contract=off` gives
  x86-64's bytes for all 150; x86-64 with `-mfma` gives macOS's) and an
  instrumented build printing exactly those 25 ties. The variants decode
  identically (checked exhaustively per node, and by `pcodedump`). The
  `log` implementation matters too: fdlibm's (the `libm` crate) changes
  two files, so basilisk needs a `log` bit-equal to glibc's. Ghidra's
  shipped Java-built files agree with x86-64 at all 25 nodes.
* **`spec-plugin` merged**: `inventory/05-extension-points.md` (335
  bundled scripts counted and classified), `features/plugin-api.md` (all
  225 public methods of `FlatProgramAPI` and `GhidraScript` mapped; nine
  tracks) and `features/plugin-binding-constraints.md` (15 rules for the
  other specs). Found: ADR-014's embedding cannot coexist with a single
  binary (Blockers); Ghidra commits a script's changes even when it
  throws (basilisk rolls back, with an opt-out); PyO3 0.30.1 needs no
  `unsafe` in `bk-plugin`; 28 % of the bundled scripts port mechanically
  once the program model is bound, 53 % with decompiler, data-type and
  analysis bindings. Not verified: anything on Linux or Windows.
* Owner, 2026-11-14 (later): the coordinator does no hands-on work, all
  of it goes to Opus 5.5 subagents; a static website and user
  documentation in the monorepo (Starlight, Mermaid, built in a
  container, basilisk's own style: ADR-030, ADR-031).

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
