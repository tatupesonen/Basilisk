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

## Proposed text (not edited by this track)

For `docs/LOOP.md`, a subsection after "The build host":

> #### Testbed
>
> The build host is also the project's testbed: the checks that are slow or
> impossible on the Mac run there, through `scripts/remote.sh` (scripts in
> `tools/testbed/`, details in `docs/agents/testbed.md`). They take 12 of the
> 20 cores by default, run below normal priority, are bounded in time, and
> copy their results back to `target/testbed/`:
>
> - `wine [-- -p <crate>…]` — the tests built for `x86_64-pc-windows-gnu`
>   and run under Wine, with the Ghidra tree as `Z:\ghidra`. It catches
>   path, separator, C-library and `cfg(windows)` problems before CI;
>   CI's `windows-latest` job (MSVC, real Windows, NTFS links) stays the
>   final word. `wine --msvc` builds with cargo-xwin and clang-cl instead.
> - `ubuntu` — the crates that compile C and the reference tools with
>   Ubuntu 26.04's GCC 15.
> - `long miri|sanitizers|fuzz|proptest|differential|all` — Miri, ASan and
>   UBSan on the C-binding crates, every fuzz target for 10 minutes, the
>   property tests at 1,000,000 cases (where a suite leaves the count to
>   `PROPTEST_CASES`), and the full differential runs.
>
> A nightly run (the host user's crontab, 01:30 host time) tests the host's
> `master` — fed by `scripts/remote.sh sync` from a checkout on `master`, or
> `scripts/remote.sh publish` — with the gate, the Wine check and one
> rotating slot of the long runs, and writes one report per night;
> `scripts/remote.sh report` prints the latest, `report --all` lists them.
> The coordinator reads it each morning; a new failure there is a task.

For `docs/agents/RULES.md`, "Build hygiene", after the build-host bullet:

> - **Testbed checks before the final report.** Besides both gate runs: a
>   track that touches paths, files, processes, floating point, C code or
>   anything under `cfg(windows)` runs `scripts/remote.sh wine -- -p
>   <crate> …` for its crates and reports the counts; a track that adds or
>   changes a parser runs `scripts/remote.sh long fuzz 300 <its targets>`;
>   a track that changes C code or `build.rs` of a C-binding crate runs
>   `scripts/remote.sh long sanitizers` and `scripts/remote.sh ubuntu`; a
>   track with `unsafe` runs `scripts/remote.sh long miri`. The whole-
>   workspace Wine run, fuzzing at length, the million-case property tests
>   and the full differential runs belong to the nightly run; do not start
>   them yourself unless your brief says so.
