# Track `testbed`: the build host as the project's testbed

Status: in progress (2026-11-14).

The Linux build host (`docs/agents/remote-build.md`) is also where the
checks that are slow or impossible on the development Mac run: Windows
tests under Wine, a newer distribution's GCC, sanitizers, Miri, fuzzing and
property tests at length, the full differential runs, and a nightly run
with a report. All of it is committed scripts under `tools/testbed/`,
started through `scripts/remote.sh`, which stays a thin dispatcher.

## Done / in progress / next

- Done: `remote.sh` plumbing (results copied back, `clean --target`,
  informative `cargo fetch`), `wine` (whole workspace passes), `long miri`,
  `long sanitizers`, `long fuzz` script.
- In progress: first runs of `long fuzz`, `long differential`,
  `long proptest`, `ubuntu`; nightly install and first run.
- Next: measurements into this file, final gates.

## Commands

All take the usual `--no-ref` right after the subcommand (the Ghidra tree
and reference tools are then not given to the job). Each sends the
committed `HEAD`, runs on the host in the branch's checkout, below normal
priority (`nice 10`), with a core budget (`BK_TESTBED_CORES`, default
**12** of 20) and a time bound (`BK_TESTBED_TIMEOUT`; default 5,400 s for
`wine`/`ubuntu`, 14,400 s for `long`). The log streams into
`<mode>-remote.log` in the worktree (git-ignored), its last 25 lines are
printed, and the results directory comes back to
`target/testbed/<date>-<mode>/` (`summary.txt`, `failures.txt`, logs, crash
inputs). Exit codes as for `gate`: the check's own (0 = everything passed),
2 no host, 75 branch busy, 124 time bound, 255 connection lost
(`scripts/remote.sh log` reattaches, writes the same local log and fetches
the results).

    scripts/remote.sh wine [--no-ref] [--msvc] [-- CARGO-TEST-ARGS]
    scripts/remote.sh ubuntu [--no-ref] [-- CARGO-TEST-ARGS]
    scripts/remote.sh long [--no-ref] miri
    scripts/remote.sh long fuzz [SECONDS [TARGET...]]      # default 600 s per target
    scripts/remote.sh long proptest [CASES]                # default 1,000,000
    scripts/remote.sh long sanitizers [asan|ubsan]
    scripts/remote.sh long differential [ITEM...]
    scripts/remote.sh long all
    scripts/remote.sh publish                              # local master -> the host's master
    scripts/remote.sh nightly install [CRON-SCHEDULE] | remove | run | status
    scripts/remote.sh report [--all | DATE]
    scripts/remote.sh clean --target BRANCH                # build output only

The scripts also run on any Linux x86-64 machine with Docker, clang 19
(with `libclang-rt-19-dev`), the pinned toolchain, nightly and cargo-fuzz,
from the root of a checkout: `tools/testbed/wine.sh`, `ubuntu.sh`,
`long.sh <what>`, `fuzz.sh`, `proptest.sh`, `sanitizers.sh`,
`differential.sh`. Each writes `summary.txt` and `failures.txt` to
`$BK_OUT` (default `target/testbed/out`); `lib.sh` documents the contract.
