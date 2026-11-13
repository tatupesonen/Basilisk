# Track `spec-decompiler` — status

Research track (docs only). Branch `spec-decompiler`, worktree
`/Users/tatu/slop/basilisk-wt/spec-decompiler`. Product: the decompiler
inventory, the port plan, and feature specs for the first decompiler
tracks. This file is kept current so another agent can continue from the
files alone.

Wording: **ran** = executed and the result seen; **read** = concluded from
reading Ghidra's source, not executed.

## Deliverables

| File | State |
|---|---|
| `docs/inventory/02-decompiler.md` | in progress |
| `docs/features/decomp-plan.md` | next |
| `docs/features/decomp-range.md` (circle ranges) | next |
| `docs/features/decomp-types.md` (type system, C declaration parser) | next |
| `docs/features/decomp-cspec.md` (compiler spec, prototype models) | next |
| `docs/features/decomp-ir.md` (varnodes, ops, blocks; waits for research reconciliation) | next |

## Measurements and how to repeat them

All commands read Ghidra at `/Users/tatu/slop/ghidra` (commit
`42db038f3c`) and the reference tools at `/Users/tatu/slop/reference`.
`CPP` = `Ghidra/Features/Decompiler/src/decompile/cpp`.

* **The console needs a pipe on standard input** (ran). Started with a
  terminal-less, non-pipe stdin it exits with `Interface error: Unknown
  error with input file stream` (`ifaceterm.cc`: `tcgetattr` must fail with
  `ENOTTY`). Working form:
  `echo | SLEIGHHOME=/Users/tatu/slop/reference /Users/tatu/slop/reference/bin/decomp -i script.txt`.
  `bk-testkit`'s wrapper already pipes stdin.
* **Pipeline listing** (ran): script `load test file <datatest.xml>` /
  `list action` prints the current root action (`decompile`) as a numbered
  tree, 243 lines (0–242).
* **Intermediate state from the optimised console** (ran): `break start
  <action-or-rule>`, `break action <name>`, `decompile`, then `print raw`,
  `print tree varnode`, `print tree block`, `print actionstats`,
  `continue`. These work in `bin/decomp` (no debug build needed).
* **Rule-by-rule trace needs a debug build** (ran): `trace address`,
  `trace enable`, `trace list`, `debug action` are compiled only with
  `OPACTION_DEBUG` (set by `CPUI_DEBUG`, Makefile target `decomp_dbg`).
  Built in a scratch copy of `reference/src/cpp` with the reference
  script's `make` overrides and target `decomp_dbg` (about 3 minutes with
  `-j3`); `trace address r0x1006ca r0x100944` + `trace enable` +
  `decompile` on `datatests/elseif.xml` printed 1,347 numbered records
  `DEBUG n: <rule or action name>` each followed by every modified op
  before and after. `scripts/build-reference.sh` does not build this
  binary yet.
* **Counts from source** (ran, scripts over `CPP/*.hh`, `CPP/coreaction.cc`):
  163 classes derive from `Rule` (137 `ruleaction.hh`, 12 `subflow.hh`, 6
  `bitfield.hh`, 4 `double.hh`, 2 `constseq.hh`, 1 `condexe.hh`, 1
  `rulecompile.hh`); 161 are instantiated by
  `ActionDatabase::universalAction` (`RuleEquality` and `RuleGeneric` are
  not); 71 leaf `Action` classes (63 `coreaction.hh`, 7 `blockaction.hh`, 1
  `condexe.hh`) with 80 instances in the universal action, plus the
  containers `ActionGroup`, `ActionRestartGroup`, `ActionPool`.
* **Include graph** (ran): headers alone are acyclic; with the `.cc`
  includes, 48 of the decompiler's modules form one strongly connected
  component.
* **Data tests** (ran `grep` over `datatests/*.xml`): 71 use
  `x86:LE:64:default:gcc`; the rest x86 (32/64, windows), MIPS, AARCH64,
  PowerPC, ARM, Toy, 8051, 68000.
* **Compiler specs**: 107 `.cspec` files under `Ghidra/Processors`
  (112 in the whole tree; the overview says 110), 180 `<prototype>`
  elements.

## Log

* 2026-11-12: read the project docs, the C++ headers of the object model,
  `action.cc`, `coreaction.cc` (`universalAction`, `buildDefaultGroups`),
  the four not-yet-ported unit tests, `testfunction.cc`,
  `ifacedecomp.cc`, `ghidra_process.cc`, `ghidra_arch.cc`; ran the
  console as above. Stopped by a usage limit before writing.
* 2026-11-13: resumed; writing documents first, committing after each.
