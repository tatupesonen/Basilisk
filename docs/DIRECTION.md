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
| **The UI is egui.** | 2026-11-12 |
| **The plugin API is Python through PyO3**, so users can still build their own plugins (ADR-014). | 2026-11-12 |
| **Licence: Apache-2.0**, Ghidra attributed in `NOTICE` (ADR-010). | 2026-11-12 |

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
| **Separate components live in their own crates**, split sensibly; **no huge Rust files** — split modules as they grow (`LOOP.md`; `scripts/check-file-size.sh` enforces a ceiling). | 2026-11-12 |
| **Project structure follows postmortem** (`../postmortem`): a workspace of focused crates, ADRs in `DECISIONS.md`, a plan, a parity matrix, inventories, and **comprehensive docs for every feature** (`docs/features/`). | 2026-11-12 |

## Working rules

* **Division of labour** (owner, 2026-11-12): the coordinator (Claude Fable)
  writes the docs — ADRs, plan, feature specs, agent rules — and manages
  **Fable 5.2 subagents at high effort** (for now; the owner first named
  Opus 5.5 and may switch back), which write the code from those docs.
  The coordinator spawns the agents, reviews and merges their branches.
  Rules for agents: `docs/agents/RULES.md`.
* **Feature spec before code.** No implementation agent starts without a
  spec in `docs/features/`.
* The Ghidra source at `../ghidra` is **read-only reference**. Never modify
  it; build reference tools from a copy outside it (`../reference/`).
* Use metric units.

## Open owner decisions

* **Git remote**: the repository is local only so far. Nothing is pushed
  until the owner names a remote.
