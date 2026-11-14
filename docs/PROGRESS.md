# Progress

## Now — RESUME HERE (2026-11-14 19:03)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Milestone M0 is complete and on `master`**; `master` (`a961ff3` plus
docs) also has `bk-ui`, the GNU disassembler crates, `bk-sla`,
`bk-decomp-types`, `bk-cspec`, `bk-sleigh` parts 1 and 2 (decoding and
p-code generation, `basilisk disasm`), `bk-sleigh-compiler` part 1 and
the website; the gate is green on Rust 1.100.0 with 1,966 tests and the
last CI run on the merged tree, 43610564062, is green on every job on
Linux, macOS and Windows. M0: `bk-core`, `bk-marshal`, `bk-pcode`,
`bk-sleigh-syntax`, `bk-lang`, `bk-bin`, `bk-elf`, `bk-testkit`, the
shared `fuzz/` crate, the reference tools in `../reference/`. Per-track
history is in the log below.

**Working rules in force** (all in `DIRECTION.md`): **one running
worker** (owner, 2026-11-14; `remote-build` is merged), counting helpers
(agents start none); every agent builds, tests and gates on kassini
through `scripts/remote.sh`; new agents are Opus 5.5 at
medium effort; the coordinator does no hands-on work; existing work is
never thrown away — agents are paused at a safe point and resumed by id,
worktrees and branches are removed only when their content is on
`master`.

**How merges are done**: finished branches are merged into a branch
`integration` cut from `master` (in its own worktree if the main checkout
is busy); the gate, `scripts/check-dep-age.py master` and
`cargo deny check advisories` run on it; it is pushed and CI started with
`gh workflow run CI --ref integration`; it is merged to `master`
(`--no-ff`) only when every job is green on all three systems, then
deleted. A red job goes back to the agent whose crate it is. Conflicts in
manifests are resolved by reading them, never by a script that keeps both
sides (that broke `fuzz/Cargo.toml` once; neither the gate nor CI builds
the fuzz crate — check it with `cargo metadata --manifest-path
fuzz/Cargo.toml`). Branches that touch only docs and development scripts
may be merged directly.

**Disk space is a working constraint** (460 GB disk; it ran completely
full at 17:15 on 2026-11-14 and stopped every agent and every command).
Each worktree's `target/` grows to 7–17 GB. The owner has said the
coordinator fixes a full disk without asking ("You can autonomously fix
it in the future"): delete regenerable build output only — Cargo's
`target/debug`, `release`, `doc` and target-triple folders — never the
scratch scripts some worktrees keep under `target/` (`windows/`,
`linux/`, `ubuntu2604/`, `brand-name/`, …) and never uncommitted work.
When a branch is merged, delete its build output at once and remove the
worktree when its content is on `master`. Check `df -h
/System/Volumes/Data` before starting a gate or an agent; keep 15 GB
free. If no command can start at all (the harness cannot create its
output file), empty a regenerable log with the Write tool (a `gate.log`,
a fuzz log) to get the first megabyte back. Docker's engine crashes when
the disk fills and Docker Desktop then hangs at "engine stopping": quit
does not work, so `pkill -9 -f '/Applications/Docker.app/'`, then `open
-a Docker` and wait for `docker version` to answer (done at 17:52 on
2026-11-14: images, volumes and build cache were intact).

**`master` is green on Rust 1.100.0** (`9a156d9`, 2026-11-14 16:34; CI
run 43605009924 on `integration`, every job green on Linux, macOS and
Windows). The pin was committed directly at the owner's choice
(`144859f`) and track `toolchain-1.100` made the workspace pass: rustfmt
in `bk-elf`; 52 clippy findings from four new lints (`assert_is_empty`
44, `float_cmp_const` 5, `chunks_exact_to_as_chunks` 2,
`manual_bit_width` 1); no lint weakened, no `#[expect]` added, lock files
unchanged; report `docs/agents/toolchain-1.100.md`. Both running agents
were told at 16:34 to commit, run `git merge master` in their worktrees
(a one-time exception to the no-merge rule), `cargo fmt --all`, clippy on
their own crates, and to run their final gates only after that. Agents
resumed later (the paused Fable ones write no Rust) and new agents start
from `master` and need nothing special.

Left over from that track, not urgent: 8 new cargo manifest warnings
(seven unused `[workspace.dependencies]` entries — `anyhow`,
`bk-decomp-types`, `bk-gnu-disasm`, `bk-sleigh`, `bk-sleigh-compiler`,
`memmap2`, `rayon` — and an unused `authors` field), to clean up once the
running tracks have merged, since they may use some; `rust-version`
stays 1.97 (raising it turns on 17 `map_unwrap_or` sites); the Wine image
`bk-gnu-disasm-win` ships Rust 1.97.1 and installs 1.100.0 on every run
until rebuilt (goes with the `win-local` tooling track).

**On `master`** besides M0: `bk-ui`, the GNU disassembler crates,
`bk-sla`, `bk-decomp-types`, `bk-sleigh` part 1, `bk-sleigh-compiler`
part 1, `bk-pcode` on the x86-64 oracle, the website and documentation
shell (`site/`), the unfused reference build. Last green CI: run 43605009924 (all jobs, all three
systems; gate 1,819 tests).

**The site is published** at `https://tatupesonen.github.io/Basilisk/`
(the owner renamed the repository to `tatupesonen/Basilisk` on
2026-11-14; `origin` points there)
(docs under `/docs/`), at the owner's word on 2026-11-14 ("you can do it,
set up auto build as well"). Pages is enabled with source "GitHub
Actions"; `.github/workflows/pages.yml` deploys on every push to `master`
that changes `site/**`, `docs/PARITY.md`, `docs/PLAN.md`,
`scripts/site.sh` or the workflow itself, and by hand with
`gh workflow run Pages`. The parity matrix and milestones on the site are
read from `PARITY.md` and `PLAN.md`, so updating those republishes. The
documentation is still a shell; `docs-content` fills it.
The site's base path is the repository name as GitHub reports it: after
the rename the first deployment (built for `/basilisk/`) served pages
whose assets returned 404; a redeploy (run 43606229878) built it for
`/Basilisk/` and every asset on the home and docs pages answers 200. A
rename of the repository needs a redeploy.

### Running (state at 2026-11-14 19:03) — USAGE LIMIT REACHED

The usage limit was reached at 19:03. **The cap is now one agent**
(`remote-build` is merged). The only agent, `sleigh-snippet`, was told
to commit, write its status file and stop at a safe point; resume it by
id when usage is back.

| Branch | Model | Agent id | State |
|---|---|---|---|
| `sleigh-snippet` (worktree `../basilisk-wt/sleigh-snippet`, cut from what is now `master` `8762851`) | Opus | `af1bd08864645b02b` | started 18:37, paused by the usage limit at 19:03. New crate `bk-sleigh-snippet` from `features/sleigh-snippet.md`. It has the remote-script instructions (merge `master` once, then `scripts/remote.sh gate` / `gate --no-ref` / `run -- …`; final gates on kassini). Check its status file and `git log` before resuming. |

**Merged: `remote-build`** (`add42668f53ed4fa3`; worktree
`../basilisk-wt/kassini-setup` and branch `kassini-setup` still exist —
remove them, the content is on `master`). `scripts/remote.sh` (`setup`,
`sync`, `gate [--no-ref]`, `run -- CMD`, `log`, `status`, `clean
BRANCH|--merged|--all`) reads the host from `~/.config/basilisk/remote`
(written on the Mac) or the environment; exit 2 = no host, 75 = branch
busy, 124 = time bound, 255 = connection dropped. On kassini: Rust
1.100.0 and nightly, cargo-deny 0.20.2, cargo-fuzz, everything under
`~/bk` (one `target/` per branch, 13–15 GB each; jobs survive a dropped
connection; a job refuses to start under 40 GB free); the reference
tools rebuilt into `~/bk/reference` (all 150 `.sla` byte-identical to
the Mac's). The gate on Linux x86-64: exit 0, 1,966 tests, 174 s cold,
about 64 s warm, peak memory 8.5 GB.

**Still to do from its report (not done because of the limit):**
1. Put its proposed text into `docs/LOOP.md` ("The build host") and
   `docs/agents/RULES.md` (it is in the "Proposed text" section of
   `docs/agents/remote-build.md`), and into every later brief.
2. **`bk-cspec`'s oracle is host-dependent** — queue a track: on Linux
   x86-64 the regenerated table differs from the checked-in (macOS,
   libc++) one in 20 `EFF` rows (Ghidra's `hasEffect` gives 1 or 2
   where the Mac gives 3), 39 `TRES` rows (tricore 24, Loongarch lp64f
   14, x86 golang 1), 48 reordered `EFFECT` rows, the pair order, and
   which pair carries the full tables for 3 `.cspec` files. By ADR-034
   the x86-64 Linux build is the oracle, so the table is regenerated
   there and `bk-cspec` made to match or the difference defined
   (ADR-024). The generator also crashes in 25–75 % of runs on Linux:
   Ghidra's `ParamListMerged` never sets `numgroup`; skip merged models
   in `assignTable`.
3. **`bk-sleigh` is slower than the g++-built reference on x86-64 Linux
   single-threaded** (decode 3.0–3.3 against 4.0–4.2 M instructions/s;
   decode + lift 1.5 against 2.1 M/s) — the reverse of the Mac. Queue a
   performance track. Thread scaling there meets the target: 6.7–7.9×
   at 8 threads, 12.6–15.2× at 16.
4. `cargo deny --offline` needs `cargo fetch --locked` first on a fresh
   machine (the script does it; the gate could).
5. `remote.sh clean` has no "build output only" option; `miri.sh` and
   the fuzz smoke were not run on kassini; optional `apt-get install
   gdb` there.

**Merged:** `sleigh-compiler-back` (`8762851`, CI run 43616696840 green
on every job, integration gate 2,030 tests, 0 new packages, advisories
ok). The SLEIGH compiler is complete: all 150 specifications compile to
`.sla` byte-identical to the reference, the `-y` XML and the warning
sequences are identical too, no tolerated difference; `basilisk sleigh
compile`; 2.9× faster than the reference compiler over all 150. ADR-039
records the `log` finding (every multiply-add GCC fuses in glibc is
written out as an FMA). Worktree and branch removed (its Wine scripts are kept in
`../basilisk-wt/windows-ci/target/windows-from-sleigh-compiler-back`).
Follow-ups: `bk-sleigh-syntax` should strip a leading byte-order
mark (done in the compiler for now); `module_options` is copied in four
test files (`bk-testkit` should own it); Wine runs need
`INSTA_WORKSPACE_ROOT`; no cancellation or progress in a compile (plugin
constraint 7; needs the monitor type in a low crate); three diagnostics
have no test because no input reaching them was found; a cache of
pattern bits would speed decision-tree construction further.

**Merged:** `ui-flake` (`afdc9312b2424f522`; CI run 43613387498 green
on every job, local gate 1,970 tests; worktree and branch removed). The
flaky `bk-ui` test was a test bug (the worker stores the result, then
wakes; the test asserted the wake at once: 308 failures in 3,000 runs
under load before, 0 in 5,000 after). Fixed on the way: `set_waker` now
wakes once (a request finished before the waker was installed woke
nobody), the busy count is given back before the wake and on every path,
and a panicking task delivers `SourceError::TaskPanicked` instead of
leaving the spinner on. The flake note in agents' briefs is no longer
needed.

**When `remote-build` reports** (owner, 2026-11-14: "Once the remote
script finishes, explain running agents how they can use it to offload
work to a faster x86 computer"): review and merge it, then message every
running agent with the exact commands — how to get `scripts/remote.sh`
into its worktree (`git merge master`, on the coordinator's word), `sync`,
`gate`, `run -- <command>`, `status`, `clean`, what runs there (builds,
tests, both gates, fuzz, benchmarks) and what stays on the Mac (editing)
— and put the same text in every later brief. From that merge the cap is
one agent.

**kassini is the build host** (owner, 2026-11-14: "You can use this
computer heavily and install whatever you'd like on it", "If you are
stuck without compute to use, then you can at any point use that"). The
owner enlarged it that day to 20 cores, 32 GB of memory and a 480 GB
disk; the coordinator grew the root filesystem to 471 GB (the swap
partition that blocked it was replaced by an 8 GB swap file; the old
partition table and fstab are saved on the machine), installed the build
tools and verified that it reboots cleanly. Login is by a dedicated SSH
key on the Mac, installed with the owner's approval, so agents need no
password; the password stays out of every project file (the owner had it
recorded in the coordinator's own memory instead). Once `scripts/remote.sh`
is merged: integration gates, Linux runs before CI, x86-64 oracle
regeneration and benchmarks go there, and the Mac keeps its disk and CPU
for the agents' editing and small builds.

**Merged on 2026-11-14 after the toolchain fix** (worktrees and branches
removed, build output deleted; the Wine scratch scripts of the two code
tracks are kept in `../basilisk-wt/windows-ci/target/windows-from-*`):

* `name-case` (`2250a58`, CI run 43608295113): the name is written
  "Basilisk" in prose, UI strings and the site; 163 files, text only. The
  Haiku agent was stopped at the owner's word with its work committed.
* `brand-name`, `sleigh-pcode`, `decomp-cspec` together (`a961ff3`, CI
  run 43610564062, local gate 1,966 tests, 0 new packages, advisories
  ok). `brand-name`: the wordmark reads "Basilisk", the emblem is
  byte-identical, the brand set's generator scripts were recovered from
  the logo agent's transcript into `assets/brand/tools/` (`build.py`
  runs the chain and reproduces every brand file byte for byte).
  `sleigh-pcode`: all 175 language pairs match `pcodedump` on every
  record kind; the tolerated differences are the three Ghidra behaviours
  of ADR-038; 37 instructions that crash `pcodedump` lift; decode + lift
  1.61 M instructions/s against Ghidra's 1.60 M, no allocation per
  instruction. `decomp-cspec`: D03 `bk-cspec`, 294 language/compiler
  pairs replayed, 127,088 rows, none unexplained.

Open from those reports, none blocking:
* `bk-sleigh` 8-thread scaling ≥ 6× is not shown (4.7–5.7× measured on a
  loaded machine); re-measure on an idle machine. Its benchmarks were
  taken on Rust 1.97.1; the CLI tests were not run under Wine.
* `bk-cspec`: regenerate its oracle table on x86-64 Linux (kassini) —
  Ghidra's `std::sort` ties (89 effect-list ties, one trial row) may be
  ordered differently by libstdc++; a hook at function-type creation in
  `bk-decomp-types` (`PrototypeCodec::finish_signature` or a stored
  parameter count) removes the 11 8051 compare records (goes into the
  D07 brief, which also installs the codec); `<global>` ranges and the
  user ops of fix-ups are resolved by D06/D07.
* Three Ghidra bugs worth reporting upstream (delay-slot walker left
  dangling after an error; uninitialised `FixedHandle` read for
  export-less subtables; parse cache clobbered by a delay slot's
  `inst_next2` look-up) — the owner's call whether and how.
* Second `name-case` pass over `crates/bk-sleigh`, `crates/basilisk`,
  `fuzz/`, `docs/PERF.md`, `docs/inventory/tests/` and the two specs and
  status files the first pass skipped; best done when
  `sleigh-compiler-back` is not editing `crates/basilisk`, or limited to
  the files it does not own.
* 8 cargo warnings about unused `[workspace.dependencies]` entries.

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

-2. **`testbed` (Opus), after `remote-build` is merged** — the owner's
   idea of 2026-11-14: kassini as the project's testbed, since it has
   the cores and memory the Mac lacks. On top of `scripts/remote.sh`:
   (a) the Windows build and tests under Wine and the Ubuntu 26.04 / GCC
   15 container run natively there (on the Mac both run under x86-64
   emulation), as `remote.sh` subcommands, with the scratch scripts kept
   in `../basilisk-wt/windows-ci/target/windows*` and
   `../basilisk-wt/gnu-disasm/target/{windows,linux,ubuntu2604}` turned
   into committed ones (this replaces the old `win-local` item); (b)
   the long runs that are too heavy for the Mac: the full differential
   over every language, fuzz targets for minutes rather than seconds,
   property tests at high case counts, on a schedule there with a
   summary the coordinator reads; (c) Ghidra itself, built and run
   headless there, as the oracle the decompiler and analysis tracks will
   need (D00 oracle tooling: state dumps, recorded p-code) — to be
   specified with the D00 spec. Nothing of it changes what CI runs.
-1. Second `name-case` pass (after `sleigh-pcode` and `decomp-cspec`
   merge): the files the first pass skipped, and a second look at what
   it left.
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
   checked-in oracle, fix the 106 rows where Basilisk does not follow
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
  Basilisk-owned overlays for unimplemented instructions and for vector
  operations that Ghidra models as opaque user ops. Needs an ADR
  (ADR-002 says the specifications are used unchanged) if it is taken up.
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
  two files, so Basilisk needs a `log` bit-equal to glibc's. Ghidra's
  shipped Java-built files agree with x86-64 at all 25 nodes.
* **`spec-plugin` merged**: `inventory/05-extension-points.md` (335
  bundled scripts counted and classified), `features/plugin-api.md` (all
  225 public methods of `FlatProgramAPI` and `GhidraScript` mapped; nine
  tracks) and `features/plugin-binding-constraints.md` (15 rules for the
  other specs). Found: ADR-014's embedding cannot coexist with a single
  binary (Blockers); Ghidra commits a script's changes even when it
  throws (Basilisk rolls back, with an opt-out); PyO3 0.30.1 needs no
  `unsafe` in `bk-plugin`; 28 % of the bundled scripts port mechanically
  once the program model is bound, 53 % with decompiler, data-type and
  analysis bindings. Not verified: anything on Linux or Windows.
* Owner, 2026-11-14 (later): the coordinator does no hands-on work, all
  of it goes to Opus 5.5 subagents; a static website and user
  documentation in the monorepo (Starlight, Mermaid, built in a
  container, Basilisk's own style: ADR-030, ADR-031).

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
  Basilisk differs only in three documented classes.
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
