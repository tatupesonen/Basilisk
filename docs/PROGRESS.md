# Progress

## Now — RESUME HERE (2026-11-12)

Read `docs/DIRECTION.md` first (owner decisions and working rules), then
`docs/LOOP.md`.

**Wave 1 (milestone M0) is in progress.** Six implementation agents
(Fable 5.2, high effort), one per track, each in its own worktree under
`../basilisk-wt/<track>` on branch `<track>`:

| Track / branch | Crates | Spec |
|---|---|---|
| `core-marshal` | `bk-core`, `bk-marshal` | `features/core-marshal.md` |
| `pcode` | `bk-pcode` | `features/pcode.md` |
| `sleigh-syntax` | `bk-sleigh-syntax` | `features/sleigh-syntax.md` |
| `lang` | `bk-lang` | `features/lang.md` |
| `bin-elf` | `bk-bin`, `bk-elf` | `features/bin-elf.md` |
| `reference-tools` | `bk-testkit`, `scripts/build-reference.sh` | `features/reference-tools.md` |

Next steps for the coordinator:
1. As each agent reports, review its branch against its spec
   (`git -C ../basilisk-wt/<track> log --oneline master..HEAD`, read the
   diff and `docs/agents/<track>.md`), run the gate on the merge, merge to
   `master`, remove the worktree.
2. After `core-marshal` and `pcode` are both merged, add the opcode
   attribute helpers to `bk-marshal` (`read_opcode`/`write_opcode`, cut out
   of wave 1 so the two tracks stay independent).
3. Tick M0 in `PLAN.md`, update `PARITY.md`, log the wave below.
4. Plan wave 2 (`PLAN.md`, "Working in waves"): write the inventory
   sections and feature specs for the SLEIGH runtime, the SLEIGH compiler's
   semantic analysis, the decompiler IR and type system, PE and Mach-O
   parsers, and the Microsoft demangler; then start the agents.

## Blockers

None. Open owner decisions are listed in `DIRECTION.md`.

## Log

### 2026-11-12 — project set up
* Surveyed Ghidra at commit `42db038f3c` (`inventory/00-overview.md`).
* Owner decisions recorded in `DIRECTION.md`; ADR-001 to ADR-015 written.
* Workspace skeleton: lints, gate (`scripts/gate.sh`, with a file-size
  check), toolchain pin 1.97.1, CI, Apache-2.0 licence and NOTICE.
* Test-parity checklist generated (`scripts/gen-test-inventory.py` →
  `inventory/tests/`): 1,706 JUnit classes with 19,092 tests (801 classes
  drive the GUI), 205 C++ unit tests, 93 decompiler data tests.
* Wave 1 feature specs written; agents started.
