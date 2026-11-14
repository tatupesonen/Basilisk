# Direction — the owner's standing decisions

Decisions and working rules given by the project owner, collected so any
session on any machine follows them without re-asking. Newest first within
each section. Architecture decisions with rationale live in `DECISIONS.md`
(ADRs); this file records *what the owner decided*.

## Goal

**basilisk is a reimplementation of Ghidra in Rust, aiming for full
parity** with every Ghidra module, headless core first. Continuously compare
features and behaviour against the Ghidra source (`../ghidra`, read-only,
commit `42db038f3c`), port its tests, and keep performance, good Rust design
and a sane architecture in mind.

## Scope

| Decision | Date |
|---|---|
| **Full Ghidra parity** is the end goal: every module is eventually reimplemented (including Debugger, PDB, demanglers, Version Tracking, BSim, Ghidra Server). | 2026-11-12 |
| **First milestone is the headless core**: a Rust library plus CLI that loads binaries, disassembles through SLEIGH, lifts to p-code, auto-analyses and decompiles. | 2026-11-12 |
| **Not a one-to-one port: improving on Ghidra is allowed.** Ghidra is the baseline for behaviour and the reference to learn from, not a ceiling. Where a better design, algorithm or result is found, take it, and document the difference (ADR-001). | 2026-11-12 |
| **Reuse Ghidra's processor specs unchanged** (`.slaspec`/`.sinc`/`.sla`, `.ldefs`, `.pspec`, `.cspec`, `.opinion`, pattern files). basilisk designs **its own program database**; it does not read or write Ghidra projects (ADR-002, ADR-003). | 2026-11-12 |
| **The decompiler is ported from Ghidra's C++ engine** — same pipeline as the starting point, validated against Ghidra's own tests and by diffing output with the original; improvements over Ghidra's output are allowed once parity is the measured baseline (ADR-004). | 2026-11-12 |
| **The decompiler should be more accurate than Ghidra's and its output really good: readable pseudocode.** A research track (`docs/research/decompiler-quality.md`, in progress) works out how — where Ghidra is weak, what is known to work, how to measure it, and what must be designed into the port from the start. | 2026-11-12 |
| **The UI is egui**, and it should be **good-looking and intuitive**; work on it started early, against demo data, with the agent briefed as an expert UI designer (`features/ui-shell.md`). | 2026-11-12 |
| **The UI stays familiar to Ghidra users**: "make the UI somewhat represent old Ghidra; if you are proficient in Ghidra it should be easy to work in basilisk." Same default layout, names, menus and key bindings; the improvement is in look, feel and additions, not in moving things. | 2026-11-12 |
| **The interface can be reordered and its windows popped out**: panes are dockable and rearrangeable, and any pane can be detached into its own native window. | 2026-11-12 |
| **The plugin API is Python through PyO3**, so users can still build their own plugins (ADR-014). | 2026-11-12 |
| **Licence: GPL-3.0-or-later** for the whole project (first Apache-2.0; the owner does not mind GPL-3.0). Ghidra stays attributed in `NOTICE` (ADR-018). | 2026-11-12 |
| **Ghidra's GPL helpers are ported like any other code** (GNU demangler, GNU disassembler wrapper, DMG): plain crates, called directly — no wrappers, helper processes or feature flags (ADR-018). | 2026-11-12 |
| **basilisk is a single binary.** | 2026-11-12 |
| **Windows is first-class from now**, alongside macOS and Linux: every track must build and pass on all three before merging, and gaps (such as the GNU disassembler's Windows stub) are fixed now (ADR-022). | 2026-11-12 |
| **binutils is built from source as its own crate** for the GNU disassembler comparison, so nothing has to be installed separately (ADR-019). Reference clone: `../binutils` (2.41, the version Ghidra names). | 2026-11-12 |
| **binutils is used as it is, not rewritten**: there is no value in rewriting it. A particular part may be rewritten in Rust only if it is measured to be really slow (benchmark first, numbers in `PERF.md`). | 2026-11-12 |

## Tests

| Decision | Date |
|---|---|
| **Every Ghidra test gets a Rust counterpart.** The checklist is `docs/inventory/tests/` (1,706 JUnit classes with 19,092 tests, 205 C++ unit tests, 93 decompiler data tests). A module's tests are ported when that module lands. | 2026-11-12 |
| **Tests port behaviour, not text.** A test need not be reproduced literally: if reading Ghidra's source shows a better way to build something, build it the better way and carry over what the Ghidra test was checking. | 2026-11-12 |
| **GUI tests become `egui_kittest` tests** of the equivalent basilisk feature. Tests of Swing-only plumbing are marked not applicable, with the reason (ADR-006). | 2026-11-12 |

## Engineering

| Decision | Date |
|---|---|
| **Performant.** Speed and memory are design inputs from the first line, not a later pass (ADR-012, `PERF.md`). | 2026-11-12 |
| **Best Rust practices** throughout (`LOOP.md`, Engineering rules). | 2026-11-12 |
| **Lints configured with sensible, strict rules**: clippy (pedantic plus chosen restriction lints), rustdoc, rustfmt, `cargo-deny`, all enforced by the gate (`Cargo.toml` `[workspace.lints]`, `clippy.toml`, `deny.toml`). | 2026-11-12 |
| **No `unsafe` unless absolutely necessary; any code that needs it is checked with Miri** (ADR-020). | 2026-11-12 |
| **Use existing crates when they fit.** There is no value in reimplementing something from scratch unless there is a good reason; when there is one, state it (ADR-011 records each evaluation). **Prefer "industry standard" crates** — widely used ones with lots of downloads — over obscure alternatives. | 2026-11-12 |
| **Separate components live in their own crates**, split sensibly; **no huge Rust files** — split modules as they grow (`LOOP.md`; `scripts/check-file-size.sh` enforces a ceiling). | 2026-11-12 |
| **Project structure follows postmortem** (`../postmortem`): a workspace of focused crates, ADRs in `DECISIONS.md`, a plan, a parity matrix, inventories, and **comprehensive docs for every feature** (`docs/features/`). | 2026-11-12 |

## Working rules

* **Division of labour** (owner, 2026-11-12): the coordinator (Claude Fable)
  writes the docs — ADRs, plan, feature specs, agent rules — and manages
  subagents, which write the code from those docs. The coordinator spawns
  the agents, reviews and merges their branches. Rules for agents:
  `docs/agents/RULES.md`.
* **The coordinator does not do the work itself; work goes to Opus 5.5
  subagents** (owner, 2026-11-14: "Do not do work yourself, direct work
  to opus 5.5 subagents"). Code, experiments, investigations, tooling and
  measurements are briefed to a subagent, however small. The coordinator
  briefs, reviews, merges, and keeps the documents of record
  (`DIRECTION`, `PLAN`, `PROGRESS`, `PARITY`, `DECISIONS`). New subagents
  are Opus 5.5 at medium effort, including specification and research
  tracks, until the owner says otherwise; a Fable agent stopped mid-track
  is resumed as it is, so its context is not lost.
* **Agent models** (owner, 2026-11-12; superseded for new agents by the
  entry above on 2026-11-14; this replaces the several earlier
  rules of the same day): **Fable 5.2 for all research, Opus 5.5 for all
  implementation.** Research means work whose product is knowledge — a
  survey, an investigation, an evaluation, a design study — written up as a
  document. Implementation means work whose product is code, tests or
  assets in the repository. Effort: **high for Fable** research agents,
  **medium for Opus** implementation agents. The coordinator (Fable) writes
  the docs and specs itself.
* **At most two running workers, for now** (owner, 2026-11-14: "limit to
  two agents for now"; earlier the same day three, briefly five; four on
  2026-11-13; "about four" on 2026-11-12), counting helper subagents. The
  coordinator fills the slots itself, so agents start no helpers. Start
  the next track when a slot frees; queue the rest in `PROGRESS.md`.
* **Existing work is never thrown away** (owner, 2026-11-14: "remember to
  not throw away existing work"). An agent that has to stop is paused at a
  safe point with its work committed and is resumed later by its id; its
  worktree, branch and uncommitted files are kept. Branches and worktrees
  are removed only after their content is on `master`.
* **x86-64 Linux results come from Docker emulation on this Mac** (owner,
  2026-11-12): the reference build runs in a `linux/amd64` container into
  `../reference-x86_64/` (ADR-021).
* **While the owner is away, be inventive** (owner, 2026-11-12: "you can
  create innovative solutions while I'm away"). Where a better approach
  than Ghidra's is found, take it without waiting to ask — within ADR-001:
  deliberate, documented, and measured against Ghidra's behaviour. Owner
  decisions that cannot be inferred still go to `PROGRESS.md` Blockers.
* **A throwaway x86-64 Linux box is available** (`kassini` on Tailscale,
  owner, 2026-11-12; reachable again from 2026-11-14 after a tailnet
  change) for builds and tests that need x86-64 Linux; details
  and access notes in `PROGRESS.md`. Credentials are never written to
  files, commits or notes.
* **Feature branches may be pushed to GitHub once they have been tested
  locally** (owner, 2026-11-14), so CI runs on all three systems before a
  merge: the coordinator pushes the branch and starts the workflow on it,
  and merges only what is green. Agents still never push.
* **The usage pace is fine** (owner, 2026-11-14): keep Fable 5.2 at high
  effort for research and Opus 5.5 at medium for implementation, within
  the worker cap.
* **`cargo-xwin` may be used** (owner, 2026-11-14) for local Windows
  checks; it downloads Microsoft's CRT and SDK under Microsoft's licence
  terms. Nothing from it is committed.
* **The UI as merged on 2026-11-13 "looks great"** (owner, 2026-11-14):
  its design choices stand (dark default theme, fixed-height listing rows
  with instruction bytes cut at six, Functions/Defined Strings/References
  open beside the Console, twelve syntax colours).
* **A website for basilisk** (owner, 2026-11-14): "design a great
  looking site for Basilisk. You can choose tech freely but make it
  static. In same monorepo." It shares one Astro project with the
  documentation (ADR-031). Tracks `site-design` and `docs-content` in
  `PROGRESS.md`.
* **A documentation site for users** (owner, 2026-11-14): "great
  looking docs for the usage of the whole program and how each aspect of
  the program works" — a **static** site made with **Starlight**, with
  **Mermaid** diagrams, **built in a container: Node.js is not installed
  on this machine** (ADR-030). Its style is customised "for a basilisk
  twist": the site and the program look like one product. Track
  `docs-site` in `PROGRESS.md`.
* **Owner's answers of 2026-11-14 (asked with the question tool)**:
  - *Plugin host*: basilisk is a Python extension module run by the user's
    own Python; the binary stays Python-free (ADR-035). Python 3.10 and
    newer.
  - *A plugin script that fails or is cancelled keeps its changes, like
    Ghidra* (ADR-036); rolling back is opt-in.
  - *The two paused Fable agents (`spec-pe`, `store-spike`) are resumed as
    they are*; all new agents are Opus 5.5.
  - *No track on improving the SLEIGH specifications for now* (testing
    p-code against an emulator, overlays for unimplemented and vector
    instructions): the idea is recorded in `PROGRESS.md`, not queued.
  - *The site is not published until there is more to show*: no Pages
    deployment until the documentation content exists and the owner says
    so. **Superseded the same day** (owner, 2026-11-14, later: "you can
    do it, set up auto build as well"): the site is published on GitHub
    Pages at `https://tatupesonen.github.io/basilisk/` and is redeployed
    automatically on every push to `master` that changes it.
  - *Priority with two slots: finish SLEIGH first* (the compiler back
    half), then the decompiler's remaining first-wave tracks.
  - *Rust 1.100.0 is committed directly* (done, `144859f`); what the newer
    compiler or clippy reports is fixed afterwards. It was released on
    2026-11-09, inside the two-week window that applies to crates: the
    owner's choice.
* **The plugin system is to be worked on now, not left to M9** (owner,
  2026-11-14: "remember to work on the plugin system"). What was decided
  is ADR-014: Python through PyO3. Its design spec is written now so the
  crates being built are shaped for it.
* **Commits and pushes** (owner, 2026-11-12): the coordinator commits on
  its own and pushes on its own to `origin`
  (`git@github.com:tatupesonen/basilisk.git`, branch `master`) after each
  green gate. Agents commit in their worktrees only and never push.
* **Brand**: a minimal logo, in the spirit of Ghidra's but its own design
  (`assets/brand/`). Colour: ember orange (owner's pick, 2026-11-12).
* **Feature spec before code.** No implementation agent starts without a
  spec in `docs/features/`.
* The Ghidra source at `../ghidra` is **read-only reference**. Never modify
  it; build reference tools from a copy outside it (`../reference/`).
* Use metric units.
