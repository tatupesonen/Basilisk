# Track `spec-decompiler` — status

Research track (docs only). Branch `spec-decompiler`, worktree
`/Users/tatu/slop/basilisk-wt/spec-decompiler`. Product: the decompiler
inventory, the port plan, and feature specs for the first decompiler
tracks. This file is kept current so another agent can continue from the
files alone.

Wording: **ran** = executed and the result seen; **read** = concluded from
reading Ghidra's source, not executed.

## Deliverables

All committed on branch `spec-decompiler` (not pushed, not merged).

| File | State |
|---|---|
| `docs/inventory/02-decompiler.md` | done |
| `docs/features/decomp-plan.md` | done; ADR-025 folded in (sections 3, 4.6, 5, 8, 9) |
| `docs/features/decomp-range.md` (D01, `bk-decomp-range`) | done — can start now |
| `docs/features/decomp-types.md` (D02, `bk-decomp-types`) | done — can start now |
| `docs/features/decomp-cspec.md` (D03, `bk-cspec`) | done — can start now |
| `docs/features/decomp-ir.md` (D05, `bk-decomp-ir`) | done — needs D00, D02, D04 merged |
| Feature documents for D00 (`decomp-oracle`) and D04 (`decomp-cfg`) | **not written**; both are leaf tracks, described in the plan (4.2, 6, 9.1) to the level of a brief. Next thing to write |
| Specs for D06 onward | not written |

## What a successor should do next

1. Write `docs/features/decomp-oracle.md` (D00) and
   `docs/features/decomp-cfg.md` (D04) from plan sections 4.2, 6 and 9.1.
   For D04 read `block.cc` (`BlockGraph`), `blockaction.cc`
   (`CollapseStructure`, `LoopBody`, `TraceDAG`) and run the console's
   `structure blocks` once to fix the XML it reads and writes (not run
   in this track).
2. Before D02 and D03 start, `bk_core::Provenance` must exist (plan
   9.2 item 5).
3. The scratch debug console used here was built outside the
   repositories and is gone; D00 rebuilds it properly.

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
* **Single rules can be switched off in the reference console** (ran):
  `option togglerule <rulename> off` (also with the full path
  `universal:fullloop:mainloop:stackstall:oppool1:propagatecopy`) answers
  "Successfully disabled rule"; decompilation of `elseif.xml` still
  completes and the other rules' counts change (`earlyremoval` applied 179
  times instead of 483). `option currentaction <root> <group> on|off`
  toggles a whole group (read).
* **How much of the rule set the data tests exercise** (ran): for each of
  the 93 files, `load test file F` / `execute test command 1-N` (N = the
  script without its final `quit`) / `print actionstats`, summed with a
  Python script (about one minute in total). 32,788 rule applications;
  `earlyremoval` 12,757 and `propagatecopy` 7,846 are 63 % of them; 124 of
  the 161 rules apply at least once; **37 never apply** (`scarry`,
  `rightshiftand`, `highorderand`, `andcommute`, `concatshift`,
  `leftright`, `carryelim`, `bxor2notequal`, `less2zero`,
  `lessequal2zero`, `threewaycomp`, `transformcpool`, `slesstoless`,
  `zextsless`, `boolzext`, `concatleftshift`, `humptyor`,
  `negateidentity`, `positivediv`, `signform2`, `signnearmult`,
  `switchsingle`, `popcountboolxor`, `xorswap`, `splitflow`, `ptrflow`,
  `negatenegate`, `orpredicate`, `floatcast`, `ptrsubundo`, `segment`,
  `piecepathology`, `doublestore`, `subright`, `floatsigncleanup`,
  `extensionpush`, `andstructure`) and 54 more apply in at most two files.
  The full table is reproduced in `docs/features/decomp-plan.md`.
* **Console extensions and private state** (ran): the Makefile compiles
  every `*.cc` in the directory into the console, so a file added to the
  reference *copy* (`reference/src/cpp`) becomes part of it; Apple clang
  17 accepts `-fno-access-control`, which lets such a file read private
  members without patching Ghidra's source.
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
* 2026-11-13: resumed; wrote and committed, in order: this file, the
  inventory, the plan, the range spec, the types spec, the cspec spec,
  the IR spec. Read ADR-022, ADR-023, ADR-024, ADR-025 and the research
  report's sections 2.2 and 5.3 from the main checkout and revised the
  plan and the IR spec for ADR-025. Further measurements: rule coverage
  of the research corpus (same script as for the data tests, over
  `docs/research/decompiler-quality/frag/*.script` with `print
  actionstats` appended: five more rules apply; 32 apply in neither
  corpus); no `.cspec` has a prototype before `<stackpointer>` (shell
  loop over the 107 files).
