# Track `remote-build`: the Linux build host

Status: done (2026-11-14).

The project has a dedicated x86-64 Linux machine for heavy work (a QEMU
virtual machine: 20 cores, 32 GB memory, about 430 GB free disk, Debian 13).
`scripts/remote.sh` makes it the build host: it sends a worktree's committed
`HEAD` there and runs the gate or any command in a per-branch checkout. It
is the place for gates, whole-workspace builds and long test, fuzz and
benchmark runs, for every agent, several at a time; the Mac keeps small
per-crate builds. No host name, user or key is in the repository.

## Configuration

`BK_REMOTE` (ssh destination, `user@host`) and `BK_REMOTE_KEY` (identity
file) come from the environment, else from `~/.config/basilisk/remote`
(override the path with `BK_REMOTE_CONFIG`), lines `KEY=VALUE`, `~` allowed:

    BK_REMOTE=user@host
    BK_REMOTE_KEY=~/.ssh/some_key

The file is outside every repository, so nothing needs ignoring and every
worktree sees it. The owner's file is written on the development Mac.
Without a destination every command prints that and exits **2**: an agent
on a machine without the build host runs `scripts/gate.sh` locally.

Optional: `BK_REMOTE_JOBS` (`CARGO_BUILD_JOBS` there; default 20),
`BK_REMOTE_TIMEOUT` (seconds for one gate or run; default 5400). Both can
also go in the file.

## Commands

    scripts/remote.sh setup                      # once, idempotent
    scripts/remote.sh gate                       # sync + scripts/gate.sh with the reference; exit = gate's
    scripts/remote.sh gate --no-ref              # the same with BASILISK_GHIDRA_DIR/REFERENCE_DIR unset
    scripts/remote.sh run -- cargo test -p bk-sleigh
    scripts/remote.sh run -- bash -c 'cd crates/x && …'   # anything needing a shell
    scripts/remote.sh run --no-ref -- cargo test -p bk-cspec
    scripts/remote.sh sync                       # only send HEAD and check it out
    scripts/remote.sh log                        # reattach to this branch's latest job after a dropped connection
    scripts/remote.sh status                     # disk, load, memory, checkouts (busy/idle, target size)
    scripts/remote.sh clean <branch>             # remove a branch's checkout, build output, logs and ref
    scripts/remote.sh clean --merged             # … of every branch whose remote HEAD is in local master
    scripts/remote.sh clean --all

`gate` writes the whole log to `gate-remote.log` in the worktree
(git-ignored; streamed as it runs, never piped through anything that hides
the status), prints its last 25 lines and `remote: gate exit N`, and exits
with N. `run` streams the output to the terminal and exits with the
command's code. Only the committed `HEAD` is sent; a dirty worktree is
reported and its changes are not included. Commit first.

Exit codes of the script itself: 2 no build host configured (or bad
usage); 75 the branch is busy there (another sync, gate or run of the same
branch is in progress: wait and retry); 124 the job hit its time bound;
255 the connection was lost (the job goes on; `remote.sh log` reattaches).

## How it works

On the machine (all under `~/bk`, plus `~/.rustup` and `~/.cargo`):

    ~/bk/repo.git          bare repository; each branch is pushed to refs/heads/<branch>
    ~/bk/wt/<branch>/      a `git clone --shared` of it per branch, checked out detached at the pushed commit
    ~/bk/wt/<branch>/target/   that branch's build output
    ~/bk/logs/<branch>/    one log per job (+ .pid, .exit)
    ~/bk/locks/<branch>.lock
    ~/bk/reference/        the reference tools (scripts/build-reference.sh, native gcc 14.2)
    ~/basilisk-ref/ghidra  Ghidra at the pinned commit (read only; was there before)

* `sync`: `git push --force` of `HEAD` to the bare repository over ssh
  (`GIT_SSH_COMMAND`; no remote is added to the local configuration), then
  `checkout -f --detach <sha>` and `git clean -fd` in the branch checkout
  (ignored files, i.e. `target/`, are kept).
* Branch names are made path-safe (`/` and other characters become `-`).
* Locking: `flock -n` on `~/bk/locks/<branch>.lock`. The job inherits the
  lock and holds it until it ends, so a second sync/gate/run of the same
  branch is refused (exit 75), never interleaved. Different branches run
  at the same time; each has its own checkout and `target/`. Concurrent
  pushes of different branches to the bare repository are safe (ref locks).
* The job is started with `setsid nohup timeout -k 60 <bound> …`, detached
  from the ssh session, writing to its log; the local side follows the log
  with `tail -F --pid` over a second ssh connection (with keep-alives).
  A dropped connection neither stops the job nor loses the log, and the
  remote `timeout` (which signals the whole process group) ends it at the
  bound. Every local ssh call is also bounded (`perl alarm`; the Mac has no
  `timeout`).
* Before a job: refuses when less than 40 GB is free.
* Environment of a job: `~/.cargo/env`, `CARGO_BUILD_JOBS`,
  `BASILISK_GHIDRA_DIR=~/basilisk-ref/ghidra`,
  `BASILISK_REFERENCE_DIR=~/bk/reference` (both unset with `--no-ref`;
  the checkout's `../ghidra` and `../reference` do not exist, so tests skip).
* The bare repository has `gc.auto 0`: the checkouts borrow its objects.
* The script prints no credential and stores none; the key path is passed
  to ssh only.

## Installed

* rustup (`~/.rustup`, `~/.cargo`; `--no-modify-path`, so no shell profile
  was changed; the script sources `~/.cargo/env`), toolchain 1.100.0 with
  clippy and rustfmt (default), nightly with miri and rust-src.
* `cargo-deny 0.20.2` and `cargo-fuzz 0.13.2` (the Mac's versions),
  `cargo install --locked` from crates.io.
* Nothing needed root. Docker, gcc 14.2, clang, git and the rest were there.

## Reference tools

`~/basilisk-ref/reference` (built 2026-11-12 in a `gcc:14` container by an
older `build-reference.sh`) has the layout the tests expect and the same
150 `.sla` bytes, but it is stale: built without `-ffp-contract=off`, its
STAMP records `ghidra_commit: unknown`, and it predates later changes to the
script. It was left as it is. `remote.sh setup` builds a fresh one with the
repository's own script, natively (the script needs only a C++ compiler,
`make` and `patch`; no container), into `~/bk/reference`: Ghidra
42db038f3c, g++ 14.2.0 (Debian), 150 languages, unit tests 205/205, data
tests 760/760, 24 s with 20 jobs. **All 150 `.sla` files are byte-identical
to the Mac's `../reference` (Darwin arm64, Apple clang 17,
`-ffp-contract=off`)**, which confirms ADR-032 on a real x86-64 host.

## The gate on Linux x86-64 (Deliverable 2)

This track's branch (master 12056c8 plus this track's script and docs;
no crate changed), `CARGO_BUILD_JOBS=20`, test threads the default (20).
Wall times are measured on the Mac around `scripts/remote.sh gate` and so
include the push, checkout and `cargo fetch` (about 3 s).

| Run | Exit | Tests | Wall |
|---|---|---|---|
| reference set, cold (fresh branch, empty `target/`) | 0 | 1,966 passed, 0 failed | **174 s** |
| reference set, warm (nothing changed) | 0 | 1,966 passed, 0 failed | **64 s** |
| both variables unset, warm | 0 | 1,966 passed, 0 failed (54 tests print SKIPPED) | 13 s |
| two branches at once, both warm, reference set | 0 / 0 | 1,966 / 1,966 | 66 s / 75 s |

The Mac's last gate on `master`: 1,966 tests with the variables set. Same
count here, and with the reference set nothing prints SKIPPED (32 tests
are `#[ignore]`d, benchmarks among them, as on the Mac). The Mac was not
timed: other agents were building (load average 4–9), so a number would
not mean much.

Findings:

* **One failure in one run, not Linux-specific**: the first complete
  test run failed `bk-ui` `task::tests::requests_complete_off_thread_and_wake`
  (task.rs:320, the wake count asserted right after the result is seen).
  This is the known flake the `ui-flake` track is fixing (PROGRESS.md); it
  did not recur in the six later full test runs. Because `cargo test` stops at the
  first failing binary, that run counted only 1,937 tests.
* **cargo-deny on a fresh machine**: `cargo deny --offline` failed with
  `failed to download accesskit_consumer` because a build downloads only
  the host platform's crates and `cargo metadata` wants all of them. On
  the Mac the registry cache already had everything. `remote.sh` now runs
  `cargo fetch --locked` before every job. Any new machine or CI runner
  running the gate's deny step offline needs the same.
* Cargo 1.100 prints `unused workspace dependency` warnings for `anyhow`,
  `bk-cspec`, `bk-decomp-types`, `bk-gnu-disasm`, `bk-sleigh-compiler`,
  `memmap2`, `rayon` and an unused `workspace.package.authors`; the gate
  does not fail on them (Cargo.toml is not mine to change).

## Build output: one `target/` per branch

Measured (gate with the reference set, 20 jobs):

| | Wall |
|---|---|
| new branch, own empty `target/` (cold) | 174 s |
| new branch, `CARGO_TARGET_DIR` = another branch's warm `target/` | 91 s |
| same branch again, own `target/` (warm) | 64 s |

A shared target saves about 80 s the first time a branch is built (the
third-party crates; the workspace crates rebuild anyway, since their
fingerprints include the checkout's path). It costs cargo's build-directory
lock: two agents building different branches at once would wait for each
other for the whole build, which is exactly the case this machine is for.
Disk is not the constraint: a branch's `target/` after a gate is 13 GB, so
430 GB holds about 30 branches, and `remote.sh` refuses to start below
40 GB free. **Decision: one `target/` per branch** (`~/bk/wt/<branch>/target`),
removed with `remote.sh clean`.

`CARGO_BUILD_JOBS` default **20** (all cores): peak memory in use during
the cold gate was 8.5 GB of 31 GB (sampled every 2 s), the load average
peaked about 12, so neither memory at link time nor anything else
measured is a reason to go lower; two cold builds at once would need
about 17 GB by that figure (estimated, not measured; two warm gates at
once were measured, above). Override with `BK_REMOTE_JOBS`.

## `bk-cspec` oracle table on x86-64 Linux (Deliverable 3.1)

`regen.sh` takes the reference directory as its argument, so it ran
unmodified (`regen.sh ~/bk/reference`, Debian g++ 14.2 / libstdc++).
Because it writes into the checkout and aborts some of the time (below),
the comparison used its steps by hand with the same compile line, output
to a temporary file. Nothing in `crates/bk-cspec` was changed or
committed.

**1. The generator aborts intermittently on Linux.** `regen.sh` died in 3
of 4 runs, and the compiled generator in 2 of 8 and 6 of 12 parallel runs.
Each abort comes within 1–3 s with `terminate called after throwing an
instance of 'std::length_error' what(): vector::_M_fill_insert`. A
backtrace (an `LD_PRELOAD` SIGABRT handler; there is no gdb) shows
`ProtoModel::assignParameterStorage`, called from `assignTable`
(`cspec_oracle.cc:483`), for x86gcc.cspec's merged model
`__cdecl/__regparm`. Cause, in Ghidra: `ParamListMerged`'s default
constructor (`fspec.hh:732`, via `ParamListStandard(void) {}`) never
initialises `numgroup`; only `ParamListStandard::decode` sets it, and
merged lists are built by `foldIn`. `assignParameterStorage` first calls
`input->allocateStatus(inputStatus)`, which is `status.resize(numgroup, 0)`
on that uninitialised value, and only then `assignMap`, which throws the
expected `Cannot assign prototype before model has been resolved`. When
the garbage happens to be small the run continues and records that ERR
row (1,116 such ASSIGN rows in the table). When it is negative or huge,
`resize` throws `length_error`, which is not a `LowlevelError`, so the
generator dies. This is undefined behaviour that depends on heap
contents; on macOS it has so far always come out small. Suggested fix
for the generator's owner: skip merged models in `assignTable` (Ghidra
itself never assigns through an unresolved merged model) and record them
as such. The replay's expected rows would then need the same change.

**2. When it completes, the Linux output is deterministic**: 6 of 6
complete runs gave the same 152,046 lines (sha256 `e5ec51d70c65f1b0…`),
the same count as the checked-in table. It differs from the checked-in
table as follows (the table and this comparison count 296 pairs, i.e. the
README's 294 plus the two V850 `PAIRERR`s):

* **Pair order differs everywhere.** The generator emits pairs in
  `SleighArchitecture::getDescriptions()` order, which follows
  `FileManage::scanDirectoryRecursive`, i.e. `readdir` order. That is
  filesystem order: APFS on the Mac gives `Toy:…` first, ext4 here
  `tricore:…` first. The README's "pairs are in `.ldefs` order" holds
  within one `.ldefs` file only.
* **The "heavy" pair moves for 3 `.cspec` files** (the first pair seen gets
  the signature, trial, query and effect tables): `HCS08.cspec`
  (HC08:BE:16:default:default on the Mac, HCS08:BE:16:default:default here),
  `AARCH64_golang.cspec` (AARCH64:LE:64:v8A:golang, here
  …:AppleSilicon:golang) and `riscv32-fp.cspec` (RISCV:LE:32:default:gcc,
  here RISCV:LE:32:AndeStar_v5:gcc). The first two give identical heavy
  records apart from the pair name. The RISC-V pair's differ because the
  languages differ (AndeStar has an extra `ExecTable` space, which shifts
  space indices).
* **EFFECT order, 48 rows in 12 pairs** (pairs whose heavy status did not
  move), all pure reorderings of the same records: two effects at one
  address swap. In NDS32:BE/LE:32 `__stdcall` and `__thiscall` at `4:78:4`,
  in every RISC-V gcc pair (RV64 default, RV64I, RV64IC, RV64G, RV64GC,
  RV32I, RV32IC, RV32IMC, RV32G, RV32GC, and the moved RV32 pair) at
  `4:2008:8` / `4:2004:4`. This is the `std::sort` tie the README predicts,
  libstdc++ against libc++.
* **…and so `hasEffect` answers differently, 20 EFF rows**: NDS32:BE
  4 rows (`4:78:1`, `4:78:4`, `4:79:1`, `4:7b:1`: 3 on the Mac, 1 here),
  RISCV:LE:64:default and RV64I 6 rows each (`4:2008:*`, `4:2009:*`:
  3 against 2), RV32I 4 rows (`4:2004:*` … `4:2007:1`: 3 against 2), plus
  the moved RV32 heavy pair. So Ghidra's own effect lookup at a tied
  address is library-dependent, not only the list's order.
* **TRES (trial classification), 39 rows in 3 pairs**:
  `tricore:LE:32:default:default __stdcall in` (24 rows: two trials at
  `4:ff90:4` of different classes swap their slot numbers),
  `Loongarch:LE:64:lp64f:default __stdcall in` (14 rows: one trial's slot
  8 against 9) and `x86:LE:64:default:golang abi-internal out` set 107
  (1 row; the README's known row). These are ties in a `std::sort` of
  trials.

Nothing else differs: no SPACE, REG, ORG, MODEL, LIST, ENTRY, ASSIGN,
Q, JOIN or SPLITQ row of a pair whose heavy status is unchanged.
The changed table was not committed. Implications for `bk-cspec`
(not mine to change): the replay's comparison should be keyed by pair,
not by position; the heavy pair per `.cspec` should be chosen
deterministically (for example the first pair in sorted order) in the
generator; the EFF/TRES tie rows need to be marked library-dependent;
and the generator needs the merged-model fix above to run reliably on
Linux.

## `bk-sleigh` thread scaling (Deliverable 3.2)

Appended to `docs/PERF.md` under `bk-sleigh` ("thread scaling on an idle
x86-64 Linux virtual machine"). Three runs, 1/2/4/8/16 threads: 8
threads give **6.7–7.9× decode only and 6.9–7.3× decode + lift**, so the
6× target is met on an idle machine, and 16 threads give 12.6–15.2×. The
input is the Mac's `build.sh` output copied over: `build.sh` uses `otool`
and `-arch x86_64` and so runs on macOS only. The thread lists were
widened to 16 in the remote checkout only. Caveat: a virtual machine.

New finding in the same runs: single-threaded, the reference built by
g++ 14.2 -O2 is faster than Basilisk here. Decode is 4.0–4.2 against
3.0–3.3 M instructions/s and decode + lift 2.1 against 1.5 M/s, where on
the M1 Pro against Apple clang Basilisk was equal or ahead. So "≥
reference" is not met on x86-64 Linux for decode, decode + lift and
`--quiet` end to end. A follow-up for `bk-sleigh`.

## Needs root

Nothing. Optional, to debug crashes of the C++ oracles on the host:
`sudo apt-get install -y gdb`.

## Proposed text

For `docs/LOOP.md`, after "Quality gate":

> #### The build host
>
> When a build host is configured (`~/.config/basilisk/remote` or
> `BK_REMOTE`; see `docs/agents/remote-build.md`), run the gate there:
> `scripts/remote.sh gate; echo $?`. It sends the worktree's committed
> `HEAD` (commit first; uncommitted changes are not sent) to the Linux
> x86-64 build host, runs `scripts/gate.sh` there with
> `BASILISK_GHIDRA_DIR` and `BASILISK_REFERENCE_DIR` set to the host's
> copies, writes the whole log to `gate-remote.log` (git-ignored), prints
> its tail and exits with the gate's status; `--no-ref` runs it with both
> unset. Whole-workspace builds, long tests, fuzzing and benchmarks go
> there too: `scripts/remote.sh run -- <command>`. Exit 2 means no build
> host is configured: run `scripts/gate.sh` locally. A green remote gate
> is a Linux x86-64 result; platform-specific code still needs the Mac
> or CI as well.

For `docs/agents/RULES.md`, "Build hygiene":

> - **The build host.** Run the full gate, whole-workspace builds, long
>   test runs, fuzzing and benchmarks on the build host with
>   `scripts/remote.sh` (`gate`, `run -- <command>`); keep small per-crate
>   builds on the Mac. It sends committed work only: commit, then
>   `scripts/remote.sh gate; echo $?` (log in `gate-remote.log`). Exit 2:
>   no build host configured (run `scripts/gate.sh` locally); 75: your
>   branch already has a job there (wait); 124: the job hit its time
>   bound; 255: the connection dropped (the job goes on;
>   `scripts/remote.sh log` reattaches). Check `scripts/remote.sh status`
>   before long jobs; `scripts/remote.sh clean <branch>` when done. Use
>   nothing on the host outside `~/bk`.

## Not done / limits

* `remote.sh` was tested from this worktree and from a scratch clone (a
  second and third branch name), not yet from another agent's worktree.
  It should behave the same, since it needs only `git` and the config
  file.
* The Mac's gate was not timed (the Mac was busy).
* No investigation of the single-thread gap of `bk-sleigh` on Linux, nor
  of the oracle crash beyond the cause; no crate changed.
* `scripts/miri.sh` and `scripts/fuzz-smoke.sh` were not run on the host;
  their toolchains (nightly with miri and rust-src, cargo-fuzz 0.13.2) are
  installed: `scripts/remote.sh run -- scripts/fuzz-smoke.sh 60`.
* `clean` removes a branch's whole checkout (and so its `target/`); there
  is no "build output only" variant. A branch that is cleaned simply
  rebuilds cold next time (174 s).
