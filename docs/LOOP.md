# Development protocol

Basilisk is built by a coordinator and implementation agents (ADR-015).
Every session starts from zero conversational memory and must be able to
continue purely from the files in this repository. This document is the
contract every session follows.

## State files (source of truth)

| File | Purpose |
|------|---------|
| `docs/DIRECTION.md` | The owner's standing decisions and working rules. Read first. |
| `docs/LOOP.md` | This protocol. Change only when the process itself needs to change. |
| `docs/PLAN.md` | Architecture, crate map, milestones and the task checklist (`- [ ]` / `- [x]`). |
| `docs/PROGRESS.md` | `## Now` (current wave and next steps), `## Blockers`, and an append-only `## Log` (newest first). |
| `docs/DECISIONS.md` | Architecture decision records (ADR-NNN). Append; never silently rewrite. |
| `docs/PARITY.md` | Status of every Ghidra module against Basilisk. |
| `docs/PERF.md` | Performance budgets, benchmark commands and measured numbers. |
| `docs/features/*.md` | One document per feature: the spec before it is built, the reference after. |
| `docs/inventory/*.md` | What Ghidra contains, by area. `inventory/tests/` is the test-parity checklist. |
| `docs/agents/RULES.md` | Rules for implementation agents; `docs/agents/<track>.md` is each track's status report. |

The Ghidra source at `../ghidra` is **read-only reference**. Never modify it.

## The coordinator's loop

1. **Orient**: read `DIRECTION.md`, then `PROGRESS.md` `## Now` and
   `## Blockers`, then the `PLAN.md` milestone that holds the current work.
   `git log --oneline -10` and `git worktree list` show where things stand.
2. **Baseline**: `master` must pass the gate. If it is red, fixing it is the
   task.
3. **Plan a wave**: pick the next unchecked tasks. For each track, read the
   Ghidra sources, write or update the inventory section and the feature
   spec (`docs/features/<feature>.md`, format below), and assign disjoint
   crates. Record an ADR for every non-obvious decision.
4. **Start agents** (models and effort: `DIRECTION.md`, "Agent models" —
   Fable 5.2 for research, Opus 5.5 for implementation): one per track,
   each in its own worktree
   (`git worktree add ../basilisk-wt/<track> -b <track>`), briefed with its
   spec and `agents/RULES.md`.
5. **Review and merge** each finished branch: read the diff against the
   spec, check the test-checklist marks are honest, run the gate on the
   merge result, merge to `master`. Send work back if it misses the spec.
6. **Record**: tick `PLAN.md`, update `PARITY.md`, update `## Now`, prepend
   a dated `## Log` entry (what landed, test counts, what was learned).
7. **Continue** with the next wave. Stop only when every milestone is
   complete or a blocker needs the owner; record blockers under
   `## Blockers` and continue with unblocked work.

## Feature documents

`docs/features/<feature>.md` is written by the coordinator **before** the
code and kept true afterwards; it is the comprehensive documentation of the
feature. Sections:

1. **Purpose** — what the feature is for, in two or three sentences.
2. **Ghidra sources** — the files and classes it derives from (paths under
   `../ghidra`), and which is authoritative where Java and C++ both
   implement it.
3. **Scope** — what is in this feature, what is explicitly not, crate
   ownership.
4. **Behaviour** — the rules, formats, algorithms and edge cases, precise
   enough to implement and to review against.
5. **Design** — crate and module layout, public API sketch, data layout
   and performance notes.
6. **Tests** — the Ghidra tests to port (checklist ids), differential
   tests, property and fuzz tests, benchmarks.
7. **Acceptance** — the conditions for the track to be done.
8. **Differences from Ghidra** — every deliberate departure (ADR-001).
   The implementing agent appends to this.
9. **Status** — filled in after implementation: what was built, gaps.

## Quality gate

Run `scripts/gate.sh` from the repository root (file-size check, unsafe
check, fmt check, clippy with `-D warnings`, rustdoc with `-D warnings`,
`cargo-deny` for licences and sources, all tests), writing its output to a
log file:
`scripts/gate.sh > gate.log 2>&1; echo $?`. **Never pipe the gate**
(`gate.sh | tail` returns tail's exit status and hides a red gate). Use
`cargo check`, `cargo clippy -p <crate>` and the changed crates' tests
while iterating; run the full gate before every merge to `master`.

### The build host

When a build host is configured (`~/.config/basilisk/remote` or
`BK_REMOTE`; see `docs/agents/remote-build.md`), the gate runs there:
`scripts/remote.sh gate; echo $?`. It sends the worktree's committed
`HEAD` (commit first; uncommitted changes are not sent) to the Linux
x86-64 build host, runs `scripts/gate.sh` there with
`BASILISK_GHIDRA_DIR` and `BASILISK_REFERENCE_DIR` set to the host's
copies, writes the whole log to `gate-remote.log` (git-ignored), prints
its tail and exits with the gate's status; `--no-ref` runs it with both
unset. Whole-workspace builds, long tests, fuzzing and benchmarks go
there too: `scripts/remote.sh run -- <command>`. Exit 2 means no build
host is configured: run `scripts/gate.sh` locally. A green remote gate
is a Linux x86-64 result; platform-specific code still needs the Mac or
CI as well. The coordinator's integration gate before a merge runs there
too, followed by CI on the three systems as before.

## Lint configuration

Lint levels live in the root `Cargo.toml` under `[workspace.lints]` and
every crate inherits them with `[lints] workspace = true`; thresholds and
test allowances are in `clippy.toml`; licences and sources in `deny.toml`;
formatting in `rustfmt.toml`. The gate turns every warning into an error.

- To silence a lint in one place use `#[expect(lint, reason = "…")]`, never
  a bare `#[allow]` (`allow_attributes`, `allow_attributes_without_reason`):
  the reason is read in review, and `expect` stops compiling when the
  suppression is no longer needed.
- Do not weaken the workspace configuration from inside a crate, and do not
  add crate-level `#![allow(...)]` beyond the test-file line given under
  Testing rules. If a lint is wrong for the whole project, say so in your
  report; the coordinator changes it in one place.

## Engineering rules

- **Workspace of focused crates** (ADR-013, `PLAN.md` crate map). A
  component that can stand alone is its own crate. Dependencies point one
  way. Library crates never depend on UI crates.
- **Small files.** One module per concept. Split a source file when it
  passes about 600 lines; 1,000 lines is a hard ceiling checked by the
  gate. Never port a large Ghidra file as one Rust file.
- **Port behaviour, write Rust** (ADR-001). No transliterated class
  hierarchies: use enums for closed sets (opcodes, symbol kinds, rule
  results), traits for open extension points, plain data plus functions
  elsewhere. No global mutable state; pass context explicitly. Improve on
  Ghidra where it is better, and record the difference in the feature doc.
- **Types carry meaning.** Newtypes for ids, offsets and sizes that must
  not be mixed (`SpaceId`, `VarnodeId`, …); typed `u32` indices into
  arenas; `Option`/`Result` instead of sentinel values; builders for
  structs with many optional fields; `#[non_exhaustive]` on public enums
  that will grow.
- **Errors**: `thiserror` enums in libraries, with enough context to act on
  (offset, name, what was expected); `anyhow` only in binaries and tests.
  No `unwrap`/`expect` outside tests; no panics on any input (ADR-009).
- **No `unsafe` unless absolutely necessary** (ADR-020). It is forbidden by
  lint; a crate that cannot do without it is listed in `unsafe-crates.txt`
  with the reason, keeps the unsafe code in one small module with
  `// SAFETY:` comments, and passes `scripts/miri.sh`. Code that calls C
  cannot run under Miri and is checked with sanitizers instead.
- **Performance** (ADR-012): arenas and indices for graph-shaped data;
  interned strings; no allocation per instruction or per op in hot loops;
  borrow instead of clone; iterators instead of intermediate `Vec`s;
  `Send + Sync` immutable shared data; deterministic parallelism. A hot
  path lands with a benchmark and its numbers in `PERF.md`.
- **Logging**: `tracing`. No `println!` in libraries.
- **Documentation**: every public item has a doc comment that says what it
  is for; each crate's `lib.rs` opens with what the crate does and which
  Ghidra code it corresponds to. `missing_docs` is a warning the gate
  rejects.
- **Dependencies**: prefer an existing crate when it passes ADR-011;
  record the evaluation. Exact versions in `[workspace.dependencies]`,
  each at least two weeks old — and so is every package a change adds to
  `Cargo.lock`, transitive ones included: `scripts/check-dep-age.py
  [base-ref]` asks crates.io and fails on anything younger (it needs the
  network, so it is not in the gate; the coordinator runs it on every
  merge result, together with `cargo deny check advisories`, which CI
  runs and the offline gate cannot). A change to `Cargo.lock` only adds packages; it never
  moves a version `master` already has. Pure Rust; a C dependency needs
  an ADR.
- **Metric units** (SI prefixes) and ISO-8601 timestamps in all output.

## Testing rules

- **Test parity with Ghidra** (ADR-006): before a feature is finished,
  port the tests listed for it in its feature doc and
  `docs/inventory/tests/`, and mark each line `- [x]` with the Rust test's
  path after `→`, or `- [-]` with the reason. Port what the test checks,
  not its text; table-driven tests (`rstest`) are preferred to many
  near-identical functions.
- **Differential tests** (ADR-007) wherever Ghidra's output defines
  correct behaviour, through `bk-testkit`. Tests needing the spec root
  (`BASILISK_GHIDRA_DIR`; in tests the default is `../ghidra` beside the
  Basilisk checkout, resolved from the workspace root, not the current
  directory — library code takes an explicit root) or the reference tools
  (`../reference/`) skip with a printed reason when those are absent — they
  never fail for that reason and never pass silently when present.
- Every public behaviour gets a test. Unit tests sit next to the code;
  cross-crate behaviour goes in `tests/`.
- **Paths** (ADR-022): product code prints a path as the operating system
  gives it (`Path::display`) and never rewrites separators; tests never
  assume a separator — they build expected strings from `Path` values or
  compare components. Where the product compares paths (file identity,
  roots) every spelling of one file must compare equal on every platform,
  including Windows verbatim (`\\?\C:\…`) forms.
- Integration-test crates (`tests/*.rs`) start with
  `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::print_stderr, clippy::allow_attributes, clippy::tests_outside_test_module, reason = "test code")]`
  because helper functions there are not covered by `clippy.toml`'s test
  allowances.
- **Fixtures**: built in Rust test code where possible (builders in
  `bk-testkit`); small checked-in files under `fixtures/` with provenance
  recorded in `fixtures/README.md`. Never copy Ghidra's spec files into
  the repository (ADR-002); test binaries taken from Ghidra's test
  resources are referenced in place.
- **Property tests** (`proptest`) for parsers and codecs: never panics,
  round-trips.
- **Fuzz targets** for every parser of untrusted bytes, all in the **one
  fuzz crate at the repository root** (`fuzz/`, see `fuzz/README.md`): a
  crate adds a dependency line, a `[[bin]]` entry and
  `fuzz_targets/<crate>_<what>.rs` there. No crate has a fuzz directory of
  its own. `scripts/fuzz-smoke.sh` runs every target briefly. Every crash
  is fixed, its input saved under `fuzz/regressions/<target>/` and
  replayed by a normal test in the crate.
- **Golden files** for large structured output (disassembly, p-code,
  decompiled C, parsed models) are `insta` snapshots: `.snap` files beside
  the tests, updated with `INSTA_UPDATE=always` (or `cargo insta review`)
  and the diff reviewed before committing — never blindly. `insta` is the
  widely used crate for this; do not hand-roll golden comparison.
- **UI**: `egui_kittest` interaction tests for every ported GUI test.
- **Benchmarks** for hot paths as `#[ignore]` release tests or `divan`
  benches; commands and results in `PERF.md`.

## Commits

Conventional messages (`feat(sleigh): …`, `test(elf): …`, `docs: …`), small
and frequent, each ending with the Co-Authored-By trailer of the model that
wrote it. Agents commit in their worktree only and never push or add
remotes. The coordinator pushes `master` to `origin` after each green gate
(`DIRECTION.md`).
