# Progress

## Now — RESUME HERE (2026-11-14 23:31)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Milestones M0 and M2 are complete and on `master`**; `master`
(`31c529e` plus docs) also has `bk-decomp-range`, `bk-ui`, the GNU disassembler crates,
`bk-sla`, `bk-decomp-types`, `bk-cspec`, `bk-sleigh` parts 1 and 2
(decoding and p-code generation, `basilisk disasm`), the whole SLEIGH
compiler (`bk-sleigh-compiler`, `basilisk sleigh compile`,
`bk-sleigh-snippet`), `scripts/remote.sh` and the website; the gate is
green on Rust 1.100.0 with 2,254 tests and the last CI run on the merged
tree, 43642488252, is green on every job on Linux, macOS and Windows. M0: `bk-core`, `bk-marshal`, `bk-pcode`,
`bk-sleigh-syntax`, `bk-lang`, `bk-bin`, `bk-elf`, `bk-testkit`, the
shared `fuzz/` crate, the reference tools in `../reference/`. Per-track
history is in the log below.

**Working rules in force** (all in `DIRECTION.md`): **two running
workers** (owner, evening of 2026-11-14), counting helpers
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

### Running (state at 2026-11-14 23:31)

**The cap is two agents** (owner, 2026-11-14 about 20:17: "You can
start two agents", "That's the limit for now"), and every agent builds,
tests and gates on kassini through `scripts/remote.sh`. **Both slots
are kept filled; the coordinator picks the order; defects found in
Ghidra go into `docs/GHIDRA-BUGS.md`** (owner, 20:35, before leaving the
coordinator to work alone). The Mac must stay awake: `caffeinate` runs,
but a closed lid needs `sudo pmset -a disablesleep 1`, which only the
owner can run (told at 20:38).

**Merged: `sleigh-snippet`** (`af1bd08864645b02b`; `98537a8`, CI run
43627941051 green on all 8 jobs, integration gate on the build host
2,053 tests, 0 new packages, advisories ok; worktree and branches
removed, the host's checkouts cleaned). **M2 (the SLEIGH compiler) is
complete.** New crate `bk-sleigh-snippet`: all 137 shipped snippet
elements (130 `<pcode>` outside XML comments plus 7 jump-table
`*_pcode`) compiled for every language that uses each file — 116
languages, 588 compilations, no difference from Ghidra's template; 236
hand-written cases and 200,000 generated ones against the new oracle
`snippetdump` (456 counted bit-range cases, 4 octal cases on the Mac
only); `PcodeParserTest` ported. Follow-ups, all still open: **a bug in
`bk-sleigh-compiler`'s shared builder** (`pcode/bitrange.rs`: Ghidra
does the bit-range arithmetic in 32 bits and wraps; ours does not; then
remove `wraps_32_bits` from the snippet crate's
`tests/oracle_random.rs`); `bk-testkit` should own `Tool::Snippetdump`
(the wrapper is in the snippet crate's `tests/common/oracle.rs`);
`bk-sla`'s template reader refuses a branch to a label that is never
placed, which Ghidra compiles; the decompiler's injection library (D18)
uses one compiler per program and carries the temporary allocator in
payload order (`docs/agents/sleigh-snippet.md`, Follow-ups). These are
queue item 3 below (`sleigh-fixups`). On the Mac the track added
`bin/snippetdump` to `../reference` (the script also rebuilt
`bin/pcodedump` from the same source and rewrote `STAMP`).

**Merged: `sleigh-perf-linux`** (`a20fadd7bd1040732`; `31c529e`, CI run
43642488252 green on all 8 jobs, integration gate on the build host
2,254 tests, 0 new packages, advisories ok, and `long differential
sleigh-every-language` passes on the host now; worktree and branches
removed, the host cleaned and `master` published). M1's benchmark item
is ticked in `PLAN.md`.
`bk-sleigh` single-threaded against the g++ reference on the build host
(host CPU model), Basilisk ÷ Ghidra, before → after: decode 0.86 →
1.11; decode + text 1.24 → 1.50; decode + p-code 0.76 → **1.00**
(0.94–1.05; level, not ahead); decode + text + p-code 0.99 → 1.18. The
Mac got faster too (decode 1.32, p-code 1.38 against its reference).
Cause found with `perf`: store-to-load forwarding stalls on x86-64
(values written in pieces and read back with one wider load) plus extra
work per instruction (model look-ups at every decision node, a 48-byte
`Result` through memory); fixed by data layout (handles beside 24-byte
nodes, decision trees laid out for the decoder, 16-byte decision nodes,
a two-byte internal error type), no `unsafe`, no new dependency, every
differential test still byte-equal. Label numbers are 32 bits as in
both Ghidra engines; the `every_language` snapshot holds
`unset-or-crash` (the sum is the same on both hosts) and the thresholds
run first. Public API: `Node::handle()` became `Parse::handle(n)`. New
tools in `crates/bk-sleigh/tests/reference_bench/` (`compare.sh`,
`hot.py`; `build.sh` runs on Linux). Its gates: 2,104 tests. Follow-up
(queue): a compiled form of p-code templates and exports for a clear
margin in decode + p-code on x86-64 (Basilisk still runs about 8,260
machine instructions per instruction to Ghidra's 6,300 there); a shared
benchmark input across hosts.

**Merged: `spec-decomp-wave1`** (`a3e1e4fb110ba60cf`; `d702880`, merged
directly at 23:08, docs only; worktree and branch removed).
`features/decomp-oracle.md` (D00, 829 lines) and
`features/decomp-cfg.md` (D04, 997 lines), each statement read from the
source or run on the reference (runs R1–R9 and the inventory of every
`std::sort` and pointer-keyed container in the engine are in
`docs/research/decomp-wave1/`). What it found is decided in **ADR-042**
(the oracle is a console extension in separate consoles; dumps use
reproducible keys; ADR-028 item 3b verified) and listed in
`decomp-plan.md` section 11 "Amendments" and at the end of
`decomp-ir.md` (corrections for D05). On both reference builds 3,000
random graphs structure byte-identically; the data tests agree between
the hosts except for lines carrying heap pointers and the known
`NAN`/`-NAN` case. `GHIDRA-BUGS.md` entries 24–28 and three smaller
observations. Open items it left (the specs' section 10): how often two
`RETURN` blocks tie in `orderBlocks`; whether `selectBadEdge`'s empty
list is reachable; the structurer's default work limit; whether the
dump's jump-table, load-guard and trial fields are enough for D13, D10
and D07; whether the hook patches for the optional logs are practical;
17 `std::sort` sites to be classified by the tracks that port their
modules (`research/decomp-wave1/sorts.md`). For the briefs: D04's
`structure blocks` cross-check works before D00 exists, its `rand` and
`rand_chacha` need the dependency-age check, edge-order mutations are
ported exactly; D05 takes ids and both bank orders from the dump; D15
applies flips by parity and needs `finalizePrinting`'s case order; D07
and D11 address duplicated action names by position.

**Merged: `decomp-range`** (`a8550db77f2254819`; `5f3c417`, CI run
43638494204 green on all 8 jobs, integration gate on the build host
2,245 tests, 0 new packages, advisories ok; worktree and branches
removed, the host cleaned and `master` published). New crate
`bk-decomp-range`: `CircleRange` (D01), a 32-byte `Copy` value, no
allocation, no panic on any field values. All 117 `testcirclerange`
tests ported and passing; oracle tables from both reference builds
(152,913 rows each, checked in; the full-size set of 592,213 rows is
regenerated and replayed wherever the reference exists); 11 properties;
fuzz 44 M runs, no finding; 5.8–8.0 ns per call. The two builds differ
in 834 rows, one cause (an undefined `INT_LEFT` shift that g++ and
Apple clang compile differently); UBSan marks 13,085 rows at 18 sites
and valgrind 2,777 rows with uninitialised reads, all of which Basilisk
matches. **ADR-041** records the rule (undefined arithmetic as x86-64
Linux computes it; empty ranges have defined fields; a defined result
where Ghidra crashes or hangs; Ghidra's unsound results kept).
`GHIDRA-BUGS.md` entries 19–23. Its gates: 2,206 tests. Gap: the
checked-in table is smaller than the spec's counts (the full set runs
only with the reference); Microsoft's compiler not run. Follow-up for
`followups`: `bk_core::bits::sign_extend` treats narrowing as
truncation, which is not what Ghidra's builds compute (undefined in
Ghidra, `address.cc:1003`); the crate has its own copy.

**Merged: `testbed`** (`ab8ffc5547650775f`; `1cf2735`, merged directly
at 22:04 — scripts, `tools/testbed/` and docs only; both gates green on
the branch after it merged `master`, 2,095 tests; worktree and branch
removed). The build host is the testbed (`LOOP.md`, "Testbed";
`RULES.md` says which checks a track runs before its report):
`scripts/remote.sh wine [--msvc]`, `ubuntu`, `arm64`, `long
miri|fuzz|proptest|sanitizers|differential|all`, `publish`, `nightly
install|remove|run|status`, `report`, `clean --target`. Results on
`master`'s content, 12 cores: Wine GNU target 2,036 passed (2 min 11 s)
and MSVC target through cargo-xwin 2,036 passed (2 min 45 s; Microsoft's
CRT/SDK licence accepted on the host on the machine's behalf); Ubuntu
26.04 / GCC 15: C crates pass, reference tools build and give all 150
`.sla` byte-identical; Linux AArch64 under qemu: 447 passed, all 150
`.sla` equal the reference's bytes from an AArch64 build (supports
ADR-039 off x86); ASan/UBSan: only the two known binutils sites; 16
fuzz targets × 600 s, no finding; the 8 property suites that honour
`PROPTEST_CASES` pass at 1,000,000 cases; differential with the
reference required: 2,095 passed, none skipped; `cspec` table
regenerates byte-identical. **The nightly run is installed** (the host
user's crontab, 01:30 host time; gate + Wine + one rotating slot; 12
cores, at most 6 h; refuses under 60 GB free); the run triggered by
hand passed 6 of 6 items in 12 minutes. **After every merge to `master`
run `scripts/remote.sh publish`** (done for `28dee4d`), and read
`scripts/remote.sh report` at the start of a day's work. One item
fails on the host until `sleigh-perf-linux` fixes it:
`long differential sleigh-every-language` (the host-dependent snapshot).
Follow-ups: the Wine runs do not mount the reference's `.sla` files;
Ghidra headless on the host needs JDK 21, Gradle through Ghidra's
wrapper, about 10 GB (for the D00 spec). The old scratch scripts in
`../basilisk-wt/windows-ci/target/` and `../basilisk-wt/gnu-disasm/target/`
(15 GB with their worktrees, both branches merged) are superseded by
`tools/testbed/`; remove those worktrees when disk is wanted.

**Merged: `sleigh-fixups`** (`a729d10fd3ad89e8d`; `5664c61`, CI run
43632387623 green on all 8 jobs, integration gate on the build host
2,095 tests, 0 new packages, advisories ok; worktree and branches
removed, the host's checkouts cleaned). (a) Bit-range
arithmetic wraps at 32 bits as in Ghidra (`pcode/bitrange.rs`, and
`defineBitrange` in `compiler/define.rs`, which overflowed in debug
builds); the snippet crate's generated comparison has no tolerated row
any more (200,000 bodies, 0 differ), all 150 specifications still
byte-identical. (b) `bk-testkit` has `Tool::Snippetdump` and
`ReferenceDir::module_options()`. (c) `bk-sla` reads a branch to an
unplaced label as Ghidra does; the check is explicit
(`Template::check_labels`, `Sla::check_labels`); `bk-sleigh` gives
Ghidra's error when p-code is built. (d) **Ghidra rejects a byte-order
mark** in both compilers, so the stripping stays in the compiler's
driver as a documented difference and was not moved. (e) Manifest
warnings 8 → 4: `authors`, `anyhow`, `memmap2`, `rayon` removed; the
entries for `bk-cspec`, `bk-decomp-types`, `bk-gnu-disasm`,
`bk-sleigh-snippet` stay until a crate depends on them (cargo's
`unused_workspace_dependencies` lint could silence them; not done, it
would hide real dead entries). Both of its gates 2,092 tests. On
`integration` the coordinator removed a pending snapshot file
(`assign_bitrange_wrap.snap.new`) committed by accident; `*.snap.new`
is now git-ignored. Follow-up for whoever next owns `bk-sleigh`: Ghidra
truncates label numbers to 32 bits and `bk-sleigh` does not (only a
hand-made `.sla` shows it) — truncate, or record under ADR-024.

**Merged: `cspec-host`** (`a85106d421cedbda2`; `60936c3`, CI run
43630477395 green on all 8 jobs, integration gate on the build host
2,056 tests, 0 new packages, advisories ok; worktree and branches
removed, the host's checkouts cleaned). The `bk-cspec` oracle exists
for both C++ libraries (`cspec_oracle.{libcxx,libstdcxx}.txt.gz`), from
a generator that is deterministic (pairs sorted by id; the
uninitialised `ParamListMerged` fields set before use; 20 of 20 runs
byte-identical on each machine, valgrind clean). The tables differ in
119 of 152,046 rows, all from `std::sort` on equal keys: 56 effect
rows, 24 `hasEffect` answers, 39 trial rows. **ADR-040**: every such
sort is stable (document order for effects, slot order for trials);
`bk-cspec` already sorted stably, and its trial sort is now an insertion
sort that cannot panic on Ghidra's comparator (not a strict weak
ordering); the replay compares with both tables and requires the counts
A 56, B 24, C 38, D 1 exactly; `oracle_regen.rs` regenerates the host's
table when the reference is present. The agent's "ADR-038" citations
were renumbered to ADR-040 on `integration`. `GHIDRA-BUGS.md` entries
6, 15 and 17 carry its findings. Open: Microsoft's library was not run
(a third table, built with clang-cl or MSVC — a candidate job for the
testbed's Wine set-up); `docs/agents/decomp-cspec.md` and
`remote-build.md` still describe the single table (historical reports,
left as they are).

| Branch | Model | Agent id | State |
|---|---|---|---|
| `decomp-cfg` (worktree `../basilisk-wt/decomp-cfg`, cut from `master` `bf8d45b`) | Opus | `ae8492491a7ef480f` | started 23:18. D04 from `features/decomp-cfg.md`: crate `bk-decomp-cfg` (block graph, graph algorithms, structured hierarchy, the structurer; `structure(graph, facts, options)`). Starts with what needs no D00 (the `structure blocks` cross-check, properties, fuzz, benchmark); its `bk structure`/`bk cfg` oracle tests are written to the specified formats and skip until `decomp_bk` exists. **When D00's commands are on `master`, message it** (it may then `git merge master`, at most twice); if it hands back first with only the oracle acceptance open, resume it after D00 merges. |
| `decomp-oracle` (worktree `../basilisk-wt/decomp-oracle`, cut from `master` `e8041d6`) | Opus | `a5bfa968bedb8543f` | started 23:09. D00 from `features/decomp-oracle.md` (ADR-042): the console extension (`tools/reference/consoleext/`, consoles `decomp_bk`, `decomp_bk_dbg`, plus `decomp_dbg`), the dump, graph, structure, trace and p-code-recording formats, their readers in `bk-testkit`, a nightly `oracle` item. Told to deliver `bk structure` and `bk cfg` first (D04 needs them), to develop against scratch copies of the reference, and to run the new build script on the two shared reference directories only at the end, adding files only, with before/after hashes in its report. |

**Build host CPU model changed** (20:26, by the owner): from QEMU's
baseline to the host's (AMD Zen 4 class). Checked afterwards: 20 cores,
31 GB, disk and `~/bk` intact, Docker up; the reference rebuilt from
scratch on the new CPU into a temporary directory (Ghidra's unit tests
205/205, data tests 760/760) gives all 150 `.sla` byte-identical to the
build made on the baseline CPU — so the SLEIGH compiler's output does
not depend on whether glibc selects its FMA `log` (ADR-039's caution
about a host without FMA did not materialise for these 150 files). Both
agents were told to hold their remote jobs during the stop and to
resume; `cspec-host` regenerates its libstdc++ table on the new CPU and
reports whether any row changed.

**Merged: `remote-build`** (`add42668f53ed4fa3`, `7b0cfa6`; worktree and
branch removed, its checkout on the host cleaned). `scripts/remote.sh`
(`setup`, `sync`, `gate [--no-ref]`, `run -- CMD`, `log`, `status`,
`clean BRANCH|--merged|--all`) reads the host from
`~/.config/basilisk/remote` (written on the Mac) or the environment;
exit 2 = no host, 75 = branch busy, 124 = time bound, 255 = connection
dropped. On kassini: Rust 1.100.0 and nightly, cargo-deny 0.20.2,
cargo-fuzz, everything under `~/bk` (one `target/` per branch, 13–15 GB
each; jobs survive a dropped connection; a job refuses to start under
40 GB free); the reference tools rebuilt into `~/bk/reference` (all 150
`.sla` byte-identical to the Mac's). The gate on Linux x86-64: exit 0,
1,966 tests, 174 s cold, about 64 s warm, peak memory 8.5 GB. Thread
scaling of `bk-sleigh` there: 6.7–7.9× at 8 threads, 12.6–15.2× at 16
(the 6× target is met). `LOOP.md` and `RULES.md` have the build-host
text. The two findings of its report are queue items 1 and 4 below.
Small things left: `cargo deny --offline` needs `cargo fetch --locked`
first on a fresh machine (the script does it; the gate could);
`remote.sh clean` has no "build output only" option; `miri.sh` and the
fuzz smoke were not run on the host. The coordinator installed `gdb`,
`perf` and `valgrind` there on 2026-11-14 and set
`kernel.perf_event_paranoid=1` (`/etc/sysctl.d/90-bk-perf.conf`), for
the `cspec-host` and `sleigh-perf-linux` tracks.

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

### Queue (two agents at a time; in this order)

1. **`cspec-host` (merged 21:16; the text below is the brief it had)** — `bk-cspec`'s oracle table depends on the
   C++ standard library. Regenerated on Linux x86-64 (g++ 14, libstdc++)
   it differs from the checked-in table (macOS, libc++): 20 `EFF` rows
   where Ghidra's `hasEffect` answers 1 or 2 instead of 3 (so a lookup
   result, not only an order), 39 `TRES` rows (tricore 24, Loongarch
   lp64f 14, x86 golang 1), 48 `EFFECT` rows in 12 pairs (NDS32, every
   RISC-V gcc pair) with two effects at one address swapped; besides,
   the pair order follows the directory-scan order of the filesystem and
   the pair that carries the full tables changes for 3 `.cspec` files
   (HCS08, AARCH64_golang, riscv32-fp). The generator also aborts in
   25–75 % of runs on Linux (`ParamListMerged` never sets `numgroup`;
   `assignParameterStorage` on the merged `__cdecl/__regparm` model of
   x86gcc.cspec resizes a vector to the uninitialised value before the
   expected exception). To do: make the generator deterministic (sorted
   scan; skip merged models in `assignTable`); for every differing row
   trace the cause in Ghidra's source (an unstable `std::sort` on equal
   keys, an uninitialised read, …) and say what each library does;
   decide per cause what Basilisk gives — the result must be the same on
   every platform and defined by the specification file, not by a sort's
   tie order (ADR-024/038 form: a defined result, counted, the harness
   recognising each tolerated row against both libraries' tables) —
   and bring `bk-cspec` and its table in line, with the table generated
   on the build host and the libc++ rows kept as the second witness.
   The exact rows are in `docs/agents/remote-build.md`. (An earlier
   note here said ADR-034 makes the Linux build "the oracle"; it does
   not — `../reference` is the oracle and equals x86-64 Linux for the
   SLEIGH compiler. This is a new case: Ghidra's own answer differs
   between its platforms.)
2. **`testbed`** — merged 22:04.
3. **`sleigh-fixups` (merged 21:36; the text below is the brief it had)** (before
   `sleigh-perf-linux`, whose measurements need the build host quiet,
   which it is not while `testbed` runs its long jobs). Small
   corrections left by the SLEIGH tracks, each checked against Ghidra's
   source: (a) `bk-sleigh-compiler` `src/pcode/bitrange.rs` computes bit
   ranges in 64 bits where Ghidra's `uint4` wraps (`pcodecompile.cc`
   `createBitRange`, `assignBitRange`, `buildTruncatedVarnode`) — follow
   Ghidra, then remove `wraps_32_bits` from
   `crates/bk-sleigh-snippet/tests/oracle_random.rs` and rerun the
   200,000 generated cases with no tolerated row; (b) `bk-testkit` gets
   `Tool::Snippetdump` and the oracle wrapper now in the snippet crate's
   `tests/common/oracle.rs` (ADR-007), and `module_options`; (c)
   `bk-sla`'s template reader accepts a branch to a label that is never
   placed (Ghidra compiles it), and the skip in the snippet crate's
   property test goes; (d) `bk-sleigh-syntax` strips a byte-order mark
   if Ghidra's reader does (read the source first); (e) the 8 cargo
   manifest warnings (unused `[workspace.dependencies]` entries, the
   unused `authors` field).
4. **`sleigh-perf-linux` (merged 23:30; the text below is the brief it had)** — on x86-64 Linux `bk-sleigh` is
   slower than the g++-built reference single-threaded (decode 3.0–3.3
   against 4.0–4.2 M instructions/s; decode + lift 1.5 against 2.1 M/s),
   the reverse of the Mac, so "at least as fast as Ghidra" (ADR-012) is
   not met there. Profile on the build host (`perf` is installed), find where the time goes (allocator, bounds
   checks, code layout, the x86-64 code generator against AArch64's),
   fix it without `unsafe`, and report numbers on both machines.
   Note (coordinator, 2026-11-14): those numbers were measured while
   the build host's virtual CPU was QEMU's baseline model (no AVX, AVX2,
   FMA, BMI1/2, LZCNT). At 20:26 the owner switched the VM to the host
   CPU model (AMD Zen 4 class; AVX2, FMA, BMI1/2 and AVX-512 visible).
   Measure again first and say which CPU model each number is for.
5. **D01 `decomp-range` (merged 22:46)** — `bk-decomp-range` from
   `features/decomp-range.md` (117 `testcirclerange` tests); spec
   complete. The decompiler (M3, `features/decomp-plan.md`; ADR-026,
   027, 028) is the main line from here on: one slot stays on it.
6. **Specs for D00 and D04 written and merged (23:08); D00 `decomp-oracle` running since 23:09; D04 `decomp-cfg` next.** The brief the spec agent had — an
   Opus agent writes `features/decomp-oracle.md` and
   `features/decomp-cfg.md`; the plan's sections 4.2, 6 and 9.1 are the
   briefs (the earlier spec agent `a0c25da932de14a37` was Fable; its
   worktree `../basilisk-wt/spec-decompiler` is kept, at an old
   `master`). D00 includes Ghidra itself built and run headless on the
   build host (state dumps, recorded p-code) — what `testbed` leaves
   for it is in its report. Then D00 and D04 are implemented, which
   ends wave 1; wave 2 is D05 `bk-decomp-ir` (needs D00, D02, D04), D06
   symbols and the host trait (needs D02, D03) and the D16a printer
   spike. Briefs carry `decomp-types`' follow-ups: `PrototypeCodec`
   and `TypeEnv::default_model` (D03, check what `decomp-cspec` did),
   `SpacebaseScopes` and `TypeSource` (D06), the five `cast_*` tests
   (D08); D18 gets the injection notes in
   `docs/agents/sleigh-snippet.md`.

Side work for the other slot, in this order:

6b. **`sleigh-templates` (Opus), not urgent**: a compiled form of p-code
   templates and exports in `bk-sleigh`, laid out like the decision
   trees, for a clear single-thread margin in decode + p-code on x86-64
   Linux (level with Ghidra after `sleigh-perf-linux`); and one
   benchmark input shared by both hosts.
7. **The monitor type** (cancel and progress) moves out of `bk-ui` into
   a low crate (plugin spec, binding constraints) — small, Opus; the
   SLEIGH compile then accepts it.
8. **Second `name-case` pass**: the files the first pass skipped and a
   second look at what it left.
9. **M4 preparation**: resume `spec-pe` (`a53aca50251d9e64c`;
   `features/pe.md`, crate decision by experiment as for ELF; four
   helper fact sheets in
   `../basilisk-wt/spec-pe/docs/agents/notes-pe-*.md`), then
   `store-spike` (`a8012f27279847feb`; `research/storage-engine.md`,
   decides ADR-003's engine) — both as they are (owner, 2026-11-14);
   then `spec-program-model` (`inventory/03-program-model.md`,
   `features/program-model-plan.md`; reads the spike's result) and
   `spec-macho` (`features/macho.md`). The program-model, storage,
   analysis and decompiler D07/D17 specs state compliance with
   binding-constraint items 3, 6, 7, 9, 11 and 13.
10. **Plugin tracks** (`features/plugin-api.md`; ADR-035, 036, 037): P0
   reference fixtures, P1 host and packaging, P3 the flat scripting
   layer can start; the first of them also corrects the spec's
   script-failure default (keep changes, roll back only on opt-in).
   The next UI track lets the action registry and the view kinds accept
   run-time entries (P6 needs it).
11. **`docs-content`** (Opus) — the documentation on the site: Getting
   started, the interface (one page per view, from
   `features/ui-shell.md`), the command line, analysis, the decompiler,
   scripting and plugins, formats and processors, and "How it works"
   (SLEIGH, p-code, the decompiler pipeline, the program database) with
   Mermaid diagrams; each page says plainly what exists today and what
   is planned; the key-binding table is generated from the action
   registry, CLI help from the binary, the Python API reference from
   the plugin package when it exists; adds the rule to `RULES.md` that
   a track changing user-visible behaviour updates its page.
12. **`followups`** (Opus): `bk_core::bits::sign_extend` on narrowing against what Ghidra's builds compute (`docs/agents/decomp-range.md`, Follow-ups 8); the 11 property-test files that fix their case count and so ignore `PROPTEST_CASES` (list in `docs/agents/testbed.md`); `bk-lang` and `bk-testkit` XML reading onto
   `bk-marshal`'s document (ADR-011); crates adopt `bk-testkit` in
   place of local "find Ghidra" helpers; a differential test of
   `bk-marshal`'s encoders against Ghidra's binary; `windows_spelling`
   (duplicated in `bk-lang` and `bk-sleigh-syntax`) into a shared
   foundation crate; evaluate `dunce`. From `gnu-disasm`:
   `bk-binutils-sys` as an optional feature of the fuzz crate; wire
   `bk-lang`'s external names (`gnu`, `gdis.disassembler.options.file`)
   to `Architecture` and `gdis_config`; mark Hexagon's `0x18:0x5`.
   From `ref-nofma`: `tools/reference/README.md` still lists
   `ADDITIONAL_FLAGS` without the flag; Docker image `e750467579a2`
   (arm64 `gcc:14`, 1.5 GB) can be removed.
13. **`ui` follow-ups** (Opus), when the owner has looked at the merged
   UI: the weak spots its report lists (empty Console on first open, no
   draggable horizontal scroll bar in a narrow Listing, key-binding page
   controls, snapshot tab hiding the live view), and whether the GUI
   crates should leave the default workspace build.
14. `features/sleigh-language.md` is a draft with open `[to verify]`
   items (nothing Java was run); complete it before its wave (M1's last
   open track).

Done and no longer queued: every SLEIGH track of M1/M2 except
`sleigh-language`, `x86-oracle` (ADR-033), `ref-nofma` (ADR-034),
`site-design`, `remote-build`; `win-local` is part of `testbed`.

### Coordinator's next steps

1. `cspec-host` is merged (above).
2. `sleigh-fixups` and `testbed` are merged (above).
   `decomp-range` and `spec-decomp-wave1` are merged (above).
   `sleigh-perf-linux` is merged (above).
   `decomp-oracle` reports → check the before/after hashes of both
   reference directories, merge through `integration`, **message
   `decomp-cfg`** that the commands are on `master`, start queue item 7
   (the monitor type). `decomp-cfg` reports → merge (or resume it for
   the oracle acceptance if D00 was not merged yet). After each merge:
   `scripts/remote.sh publish`.
3. After that the queue above, one slot on the decompiler line (5, 6),
   the other on the side work (7 onwards).

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
