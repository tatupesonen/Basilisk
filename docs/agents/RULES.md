# Rules for implementation agents

Several agents work at once, each in its own git worktree and branch, and
the coordinator merges their branches into `master` (ADR-015). Follow these
rules so merges are clean and the result is shippable.

## Read first

1. `docs/DIRECTION.md` — the owner's decisions.
2. `docs/LOOP.md` — engineering rules, testing rules, the quality gate.
3. `docs/DECISIONS.md` — at least ADR-001 (port behaviour, improvements
   allowed and documented), ADR-006 (test parity), ADR-007 (differential
   testing), ADR-009 (panic-free), ADR-011 (existing crates), ADR-012
   (performance), ADR-013 (crates and file size).
4. Your feature spec, `docs/features/<feature>.md`. It is your contract.
5. The Ghidra sources your spec cites, under `../ghidra` (relative to the
   main checkout; the absolute path is in your brief). **Read-only: never
   modify, build inside, or write files into the Ghidra tree.**

## Your worktree

- Work only inside the worktree directory named in your brief, on the
  branch already checked out there. Do not touch the main checkout or
  other agents' worktrees.
- Commit locally, often. Never push, never add remotes, never rebase or
  merge other branches.

## Ownership (avoid merge conflicts)

- You own the crates your spec assigns. Do not edit other crates.
- Do not depend on crates that another track is writing in the same wave
  (your spec lists them). Where you need something from one, cut the
  dependency as your spec says (usually a small trait or a deferred item),
  and list it under "Follow-ups" in your status report.
- Shared files — keep edits minimal and append-only:
  - root `Cargo.toml`: your internal crates are already listed in
    `[workspace.dependencies]`; add third-party dependencies there with
    exact versions, each at least two weeks old, after an ADR-011
    evaluation. Check what the workspace already has before adding.
    Before your final commit run `scripts/check-dep-age.py master`: every
    package your branch adds to `Cargo.lock`, transitive ones included,
    must be at least two weeks old (pin a younger one back with
    `cargo update -p <name> --precise <version>`), and no version that
    `master` has may move (`git diff master -- Cargo.lock` only adds).
  - `docs/inventory/tests/*.md`: mark only the lines for your tests.
  - `docs/features/<feature>.md`: append to "Differences from Ghidra" and
    fill in "Status". Do not rewrite the spec; if the spec is wrong or
    unimplementable, say so in your status report and implement the
    closest correct thing.
  - `docs/PERF.md`: append your benchmark numbers under your crate.
- Do not edit `docs/PLAN.md`, `docs/PROGRESS.md`, `docs/PARITY.md`,
  `docs/DECISIONS.md` or `docs/DIRECTION.md`; propose changes (including
  ADRs you think are needed) in your status report.
- Write your status report to `docs/agents/<track>.md`.

## Build hygiene (a shared Mac for editing; a build machine for the heavy work)

- **No job limit** (owner, 2026-11-14; the earlier `CARGO_BUILD_JOBS=2`
  rule is withdrawn). The project has a Linux build machine with 20
  cores and 32 GB of memory, and the owner wants it used as much as
  possible: full gates, whole-workspace builds, long test, fuzz and
  benchmark runs go there, at full parallelism, through
  `scripts/remote.sh` once your worktree has it (your brief says how
  until then). On the Mac (8 cores, 16 GB, shared with other agents)
  cargo's default parallelism is fine for the small builds you do while
  developing.
- While developing, build and test only your crates
  (`cargo test -p <crate>`, `cargo clippy -p <crate> --all-targets`).
- Before your final commit run the full gate exactly as
  `scripts/gate.sh > gate.log 2>&1; echo $?` — never
  pipe it — and fix everything it reports. `gate.log` is git-ignored.
- Temporary files go in your worktree's `target/` or a directory you
  create with a unique name; never in the Ghidra tree.
- **Disk space is shared and finite.** A full disk stops every agent on
  the machine. Check `df -h /System/Volumes/Data` before a full gate or
  any large build; if less than 10 GB is free, stop, commit and report
  instead of building. Delete the build directory of a Wine, container or
  cross build when you are done with it (keep the scripts), and do not
  keep several profiles or target triples built when one will do.

## Quality bar

- **Behaviour from Ghidra, structure from Rust** (ADR-001). Read the
  Ghidra code until you understand what it does and why, then write the
  Rust that does it well. Do not transliterate. If you find a better way,
  take it and record it under "Differences from Ghidra".
- **Crates and files** (ADR-013): one module per concept; split a file
  when it passes about 600 lines; the gate rejects files over 1,000.
- **Rust best practices** as listed in `LOOP.md`: newtypes and typed
  indices, enums for closed sets, `thiserror` errors with context, no
  `unwrap`/`expect`/`panic!`/indexing panics outside tests, no global
  state, documented public items, `tracing` for logs. The lint
  configuration (`LOOP.md`, "Lint configuration") is strict and the gate
  enforces it; suppress a lint only with `#[expect(…, reason = "…")]`.
- **No `unsafe` unless absolutely necessary** (ADR-020). If you believe
  your track needs it, the crate goes in `unsafe-crates.txt` with the
  reason, the unsafe code is isolated and commented, and
  `scripts/miri.sh <crate>` must pass; report the Miri result. Reaching
  for `unsafe` to save a bounds check is not a reason.
- **Existing crates first** (ADR-011): use a maintained, widely used crate
  when one fits; write your own only for a stated reason.
- **Performance** (ADR-012): design the data layout first; no per-item
  allocation in hot loops; add a benchmark for each hot path and record
  the numbers.
- **Tests** (ADR-006, `LOOP.md` Testing rules): port every Ghidra test
  your spec lists and mark the checklist; add differential, property and
  fuzz tests as the spec says. Tests that need `../ghidra` or
  `../reference` must skip with a printed reason when it is absent.
- Do not leave `todo!()`, stubs or silently ignored cases. Something you
  could not finish is listed under "Gaps" in your status report.

## Platforms and concurrency

- **Windows, macOS and Linux are all first-class** (ADR-022). Your track
  must build, pass its tests and work on all three; a platform gap is
  yours to fix, not to defer. You develop on macOS, so cross-check what
  you can (`cargo check --target x86_64-pc-windows-msvc` for crates
  without C code) and say in your report exactly what was verified on
  which platform and what rests on CI.
- **Nothing waits forever.** The owner is often away, so a hung command
  stalls the project. Give every command an explicit timeout; bound
  background jobs (fuzz runs with `-max_total_time`, containers and builds
  with a time limit) and kill anything that has run far past its expected
  time; never poll in an unbounded loop. If something does not finish in
  its budget, stop it, record what happened, and move on.
- **No `timeout` command on the development Mac.** Bound a command with
  the Bash tool's timeout parameter or
  `perl -e 'alarm N; exec @ARGV' <cmd> …` (N in seconds).
- **Do not fan out.** The owner caps the number of running workers (two
  as of 2026-11-14; `DIRECTION.md` has the current figure), and the
  coordinator fills every slot. Work alone: start no
  helper subagents.
- **A usage limit can stop you at any moment.** Write results to files as
  you go, commit every finished piece, and keep `docs/agents/<track>.md`
  current (done / in progress / next) so the work can be continued from
  the files alone. Research held only in your context is lost.

## Commits

Conventional messages (`feat(elf): …`), small and frequent, each ending
with the Co-Authored-By trailer of the model you are, for example

    Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>

## Final report

Write `docs/agents/<track>.md` and repeat its substance in your final
message:

- **Built**: crates, modules, public API in brief.
- **Tests**: counts by kind; which Ghidra tests were ported, which were
  marked not applicable and why; the gate's final result line.
- **Benchmarks**: numbers and the commands that produce them.
- **Differences from Ghidra**: each deliberate departure.
- **Gaps**: anything in the spec not done, stated plainly.
- **Follow-ups**: what the next wave needs to know (cut dependencies,
  proposed ADRs, things found in Ghidra that the plan missed).
- **Commits**: `git log --oneline master..HEAD`.
