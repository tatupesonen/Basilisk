# Track `remote-build`: the Linux build host

Status: in progress.

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

## Done / in progress / next

- [x] `scripts/remote.sh` and the setup on the machine
- [x] Reference tools checked / rebuilt into `~/bk/reference`
- [ ] Gate on Linux x86-64, cold and warm, with and without the reference
- [ ] Build-output decision (per-branch or shared `target/`)
- [ ] `bk-cspec` oracle table regenerated on Linux and compared
- [ ] `bk-sleigh` thread scaling at 1–16 threads
