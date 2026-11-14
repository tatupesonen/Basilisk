# Decompiler quality: making Basilisk's output more accurate and more readable than Ghidra's

Research for the "then improve" part of ADR-004 and for the parts of the M3
port that have to be decided early. Written 2026-11-12 against Ghidra commit
`42db038f3c` and its reference `decomp` build (`../reference`, macOS arm64).
No Rust code; experiment inputs, commands and Ghidra's output are in
`decompiler-quality/` beside this file (`decompiler-quality/README.md`).

**How claims are marked.** Every claim that matters carries its basis:

| Mark | Meaning |
|---|---|
| **[E]** | An experiment in this repository: source in `decompiler-quality/src/`, Ghidra's output in `decompiler-quality/out/`. Reproducible with `tools/run.py` |
| **[G]** | Read in Ghidra's source at the pinned commit (file named) |
| **[S✓]** | A cited source that I opened and checked for this claim |
| **[S]** | A cited source opened and read by a research helper I briefed; I did not re-open it |
| **[S?]** | Known only from a search-result snippet or an abstract; the full text was not read |
| **[P]** | My prior knowledge, not checked against a source |
| **[J]** | My judgement: an inference or a recommendation |

Numbers from papers are the papers' own, on the benchmark named; they are not
predictions for Basilisk.

**Where to find what.**

| Question | Section |
|---|---|
| Where is Ghidra's output weak, and how is each claim known? | 3 (catalogue, all **[E]**), 1.1 (summary) |
| What must the port decide at the start, and what can follow parity? | 2.2 (table by area, then D1–D8), 2.1 (staging) |
| What to improve, in what order, at what cost and risk? | 2.3 |
| How is quality measured, and what runs in the gate? | 5 (5.3 for gate and nightly) |
| What is known to work elsewhere? | 4 |
| The decision to record | 8 (proposed ADR, ready to paste) |

---

## 1. Conclusions

### 1.1 What was found

1. **Ghidra's engine drops return values, and this is its most frequent
   accuracy fault in these experiments.** A function whose returned register is
   also used inside the function, or comes straight from its last call, or
   ends in a tail call, is printed as `void` with a bare `return;`. In the
   corpus here 25 of 174 non-`void` functions come out `void`; 10 of those are
   in cases written to show something else. The cause is one deliberate
   heuristic (`ActionReturnRecovery` → `Funcdata::ancestorOpUse`), and the same
   code is printed correctly as soon as a prototype is supplied. **[E][G]**
2. **Ghidra prints floating-point comparisons that are wrong for NaN, by two
   separate mechanisms.** `!(a >= b)` is printed as `a < b` because the engine
   removes NaN terms on purpose (`nan_ignore_compare` defaults to true); with
   the option off it prints `(NAN(a) || NAN(b)) || a < b`, which is right and
   unreadable. And `a < b ? a : b` is printed as `if (b <= a) a = b;`, which
   picks the other operand when one is NaN, because the engine's negation of
   `a < b` is `b <= a` (`TypeOpFloatLess`); no option changes that. The form
   that is both right and readable — `!(a >= b)`, `!(a < b)` — is never
   produced. **[E][G]**
3. **The engine depends on facts it does not compute.** Whether a callee
   returns, whether a jump is a tail call, what a callee's parameters are: all
   come from outside (in Ghidra, from Java analyzers; the one that stores
   prototypes, "Decompiler Parameter ID", is off by default except for small
   PE files **[G]**). Without them the output is wrong, not merely ugly: code
   after a call to an unmarked non-returning function runs on into the next
   function's body; arguments passed through unchanged are dropped from calls
   (`ext_pair()` for `ext_pair(x)`). **[E]**
4. **Readability losses are dominated by a few systematic causes**, each with
   a known remedy: pointers typed as integers and structure access printed as
   arithmetic; loops printed in the compiler's rotated shape (63 `do … while`
   against 10 `for` in the output, where the sources have 31 `for`/`while`
   loops and one `do`); switches that the compiler lowered to compare trees or
   bit tests and that are never turned back; inline expansions of `memcpy`,
   struct copies, range checks and the stack protector printed operation by
   operation; names that carry no meaning (2,520 automatic names in 2,695
   lines); every declaration at the top of the function. **[E]**
5. **Ghidra is already good at several things, and effort there would be
   wasted.** Division and remainder by constants are recovered (`x / 7`,
   `x % 10`, `secs % 3600 / 60`); jump-table switches are recovered, cleanly
   for GCC's tables; short-circuit conditions, nested `if`/`else` chains and
   rotations are fine; variables are already named after the parameters of
   known callees (`buf`, `n`); with types supplied, `v->id` and `&v[3].w`
   appear. At `-O0` loops come out as `for` and return values are kept: most
   of the damage is optimisation, which is why reversing optimisations is the
   productive frame. **[E]**
6. **The published evidence agrees on direction.** Structuring should aim at
   the source's shape, not at zero gotos: both goto-free approaches measured
   by SAILR have the worst similarity to source, and Binary Ninja abandoned its
   goto-free method **[S✓]**. Missing type information is the largest single
   cause of unfaithful output after names **[S]**. Free rewriting by language
   models breaks correct code at a high rate (D-LiFT: one such model made
   93.2% of functions that Ghidra had decompiled accurately inaccurate
   **[S✓]**), and predicted names did not measurably help in a 2025 human study
   although users liked them **[S✓]**.

### 1.2 What to do first

In order; details, evidence, effort and risk are in section 2.

| # | Improvement | Why first |
|---|---|---|
| 0 | **A quality harness and a stage-equivalence check**, built during the port | Nothing else can be judged without it; it changes no output |
| 1 | **Function summaries computed bottom-up over the call graph** (returns a value or not, does not return, parameters, tail calls) and used by callers and callees | Removes the largest class of *wrong* output found here; Basilisk's in-process, parallel decompiler makes affordable what Ghidra leaves off by default |
| 2 | **NaN-correct comparison printing** (`!(a >= b)`) | Small, self-contained, turns a known unsoundness into correct and readable output |
| 3 | **Pointer, array and structure recovery in three steps**: pointer-ness from use, per-function structure synthesis, then cross-function unification | The largest readability gain with the strongest outside evidence |
| 4 | **Compiler-aware structuring on top of the ported collapse engine**: un-rotate loops, rebuild switches from compare trees and bit tests, undo tail merging — each tried speculatively and kept only if the structure improves | The measured way to fewer gotos without the costs of goto-free methods |
| 5 | **Idiom outlining and noise removal**: inline `memcpy`/`memset`/struct copy, stack strings, stack-protector code, range-check and bit-test idioms | Cheap rules, visible on almost every function of real programs |
| 6 | **A presentation pass**: declarations at first use, single-use temporaries folded, consistent constant radix, names from more sources | Evidence-backed and confined to the last stage |
| 7 | **Language models only as suggesters of names, comments and types**, applied through the decompiler's own rename and retype, off by default | The only use the evidence supports; belongs in the plugin layer |

### 1.3 What must be designed into the port from day one

These cost little now and are expensive to retrofit (section 2.2):

1. **Profiles and per-unit switches.** Every rule, action and output pass is a
   named unit with an origin (`ghidra` or `basilisk`); a *profile* is a set of
   units. `ghidra` profile = Ghidra's pipeline exactly, and stays the target of
   differential tests for ever. Improvements exist only in other profiles.
2. **A typed output tree between the engine and the printer**, so that
   improvements after structuring are tree-to-tree passes that can be switched
   off, and printing in the `ghidra` profile reproduces `printc.cc` token for
   token.
3. **An executable IR at every stage and a record of which unit changed
   what**, so that "is the final IR equivalent to the lifted p-code" is a test
   the project can run, and a wrong output can be traced to a rule.
4. **Function summaries as a first-class output of decompilation**, and a
   program-side trait that can serve them back, so inter-procedural facts
   need no second mechanism later.
5. **A structurer that can be re-run on a copy of the block graph**, because
   every published de-optimisation works by "transform, re-structure, keep if
   better".
6. **Type facts kept as facts**: what was observed (base, offset, size,
   stride, direction) separately from the type chosen, and a notion of
   *inferred* types that are visibly provisional.
7. **Provenance on names and types** (user, debug information, library
   signature, heuristic, model), so presentation and trust can depend on it.

### 1.4 How to measure

A three-layer harness (section 5): text assertions and counters on a fixed
corpus (cheap, built first; a working prototype is `tools/metrics.py`);
ground truth from debug information for signatures, types and variables; and
a stage-equivalence check that executes lifted p-code and final IR on the
same inputs. Recompile-and-run and similarity to source come later. Every
metric is reported for three columns — Ghidra's reference build, Basilisk in
the `ghidra` profile, Basilisk in the default profile — in a `docs/QUALITY.md`
kept like `PERF.md`.

### 1.5 What could not be established

* How a **full Ghidra** (with its Java analyzers) prints the cases that depend
  on analysis outside the engine. No Ghidra installation with Java was run;
  the harness stands in for the analyzers that matter and each catalogue entry
  says whether it is an engine fault or depends on the stand-in.
* How **Hex-Rays, Binary Ninja or angr** print this corpus: none was run.
  Everything said about them rests on cited sources.
* **Prevalence.** The corpus is 36 files written to show weaknesses. Counts
  over it are not rates for real programs.
* An **unsound integer rewrite**: none was found here. That Ghidra has such
  bugs rests on cited testing papers.
* The **cost** in run time of any recommendation; nothing was measured.
* Whether the **Retypd patent** claim reported by Trail of Bits constrains a
  GPL implementation: that needs a lawyer, not a researcher.
* MSVC, C++, Rust, Go, Swift and Objective-C output; exception handling.

---

## 2. Recommendations

### 2.1 Staging and gating: how improvements coexist with parity

The plan of record is parity first (ADR-004), tested by diffing against
Ghidra (ADR-007). An improvement that changes output makes that diff useless
unless it can be switched off. The proposal **[J]**:

* **Two named profiles from the first line of `bk-decomp`.** `ghidra` is the
  pipeline of `ActionDatabase::universalAction` with Ghidra's groups
  (`decompile`, `jumptable`, `normalize`, `paramid`, `register`, `firstpass`
  **[G]** `coreaction.cc`) and nothing else. `basilisk` is `ghidra` plus the
  improvements that have been accepted. Until M3's acceptance the default is
  `ghidra`; afterwards the default becomes `basilisk` and `ghidra` remains as
  a compatibility profile and as the test target.
* **One switch per improvement**, in the same option registry that carries
  Ghidra's own toggles (`OptionToggleRule`, `OptionSetAction` **[G]**
  `options.hh`). A profile is a list of switches. A test names its profile.
* **Ghidra's units are never edited in place.** A Basilisk improvement to a
  Ghidra rule is a second unit that replaces the first in the `basilisk`
  profile. This keeps "accidental difference = bug" (ADR-001) checkable and
  keeps a later re-synchronisation with a newer Ghidra commit mechanical.
* **Bugs are reproduced in the `ghidra` profile.** Where Ghidra is wrong
  (the dropped return values, the NaN comparisons), the `ghidra` profile is
  wrong in the same way, and the `basilisk` profile carries the fix.
* **Each improvement lands with**: an entry under "Differences from Ghidra"
  in the feature document; a before/after pair of snapshots for the cases it
  touches; the change in the harness counters; and, for anything upstream of
  structuring, a clean stage-equivalence run.
* **Order by blast radius.** Improvements at the end of the pipeline (output
  tree passes, naming, printing) cannot disturb the interplay of Ghidra's
  rules and go first. Improvements in the middle (type propagation, variable
  merging) change everything downstream and go later, one at a time, with the
  whole corpus re-reviewed. Improvements outside the engine (summaries) change
  the engine's inputs and are tested as "what Ghidra prints when given the
  same facts".

The tension that remains is honest work, not design: every improvement
doubles the snapshots for the cases it touches.

### 2.2 Design requirements for the port

Each is a decision for the M3 feature specs. "Why now" says what breaks if it
is left out. The table is the short form, by area of the port; D1–D8 below
give the reasons. Everything in the right-hand column can wait until parity is
measured; nothing in the middle column changes Ghidra's output.

| Area of the port (M3 task) | Decide at the start | Can follow parity |
|---|---|---|
| **IR**: varnodes, ops, blocks, function data | Every op can be evaluated at every stage, with defined meaning for `MULTIEQUAL` and `INDIRECT` (D3). All edits of the IR go through one small mutation interface, as they do through `Funcdata`'s `op…` methods in Ghidra (`PcodeOp`'s setters are private to it **[G]** `op.hh`, `funcdata.hh`), so that a recorder can be attached (D3). Ops keep the address and instruction they came from (D8). The block graph can be copied cheaply (D5). No global state; the same input gives the same output | Nothing: later improvements add units, not IR |
| **Rule and action machinery** | Rules and actions are values in a table with Ghidra's name, an origin (`ghidra` or `basilisk`) and a group; the pipeline is built from the table by a named profile; a unit can be replaced or added by a profile without editing another unit; switches live in the option registry (D1). An optional record of applications (D3) | Every new rule; replacements of Ghidra rules (R2, R5) |
| **Prototypes and parameters** (`fspec`, `modelrules`) | A `FunctionSummary` type as an output of decompilation and as an input through the program trait; the trait's "does this call return" question takes the call site, not only the callee (D4). Prototype facts carry provenance (D7) | The inference that fills summaries; bottom-up scheduling (R1) |
| **Type system and recovery** | A category of *inferred* types distinct from user and debug-information types (D6). A per-function table of observed accesses, filled while types are propagated (D6). Propagation policy per op kind is a unit like any rule, so that a profile can change one edge (R3 step 1) | Pointer-ness from use, structure synthesis, cross-function unification (R3) |
| **Variables and merging** | Each merge pass is a unit (D1). A high-level variable records which merges formed it (D3) | Changed merge policy, splitting reused parameters (R6) |
| **Structuring** | The structurer is a function of a block graph and options that returns a hierarchy and a measure of it (gotos, depth), runnable on a copy (D5). Goto selection is a replaceable unit. Loop bodies and induction variables found before structuring are kept (D8) | All de-optimisations (R4) |
| **C printing** | The engine produces a typed output tree with links back to ops, varnodes and addresses; printing is a separate stage; tree passes are units (D2) | All presentation passes (R6), idiom rendering (R5), suggested names (R7) |
| **Interface to the program** (ADR-004 trait) | Summaries in both directions (D4); names and types with provenance in both directions (D7) | The analyzers that compute and store them |
| **Tests** | Every decompiler test names its profile; snapshots are per profile; the corpus runner and the stage-equivalence check exist as soon as there is IR to run them on (R0) | Ground truth from debug information; recompile-and-run |

**D1. Units, origins, profiles.** Rules and actions are values registered in
a table with a stable name (Ghidra's), an origin and a group; the pipeline is
built from the table by a profile. *Why now:* retrofitting a switch into 167
rules after they are written means touching all of them. *Cost:* almost none;
Ghidra already has names and groups.

**D2. A typed output tree (`bk-decomp` → `bk-decomp-print`).** Ghidra has no
syntax tree: `PrintC` walks the structured blocks and pushes operators and
atoms on a reverse-Polish stack (`PrintLanguage::revpol` **[G]**
`printlanguage.hh`) that an emitter turns into tokens. Every other decompiler
surveyed has a tree at this point — Hex-Rays' ctree, Binary Ninja's HLIL,
RetDec's back-end IR, rev.ng's Clift — and does its last-mile clean-up there
**[S]**. Recommendation **[J]**: the engine produces a tree of statements and
expressions whose nodes point back to ops, varnodes and addresses; the
`ghidra` profile builds exactly the nodes `PrintC` would push and prints them
with `PrintC`'s rules; improvements are tree passes. *Why now:* loop shapes,
switch rebuilding from `if` chains, declaration placement, idiom rendering
and renaming are all far simpler on a tree, and the printer is ported once.
*Risk:* `printc.cc` (3,556 lines) mixes printing decisions with tree shape
(cast elision, precedence, the comma and `break` conventions); the port must
separate them without changing a token. The 93 data tests and differential
runs detect a slip. I am fairly confident this is feasible, because the
reverse-Polish stack already *is* an implicit tree builder; it has not been
tried.

**D3. Executable IR and a change record.** Ghidra's IR can be evaluated op by
op (`OpBehavior`), and `bk-pcode` already has the behaviours. Keep that true
for the decompiler's IR at every stage, including SSA form (`MULTIEQUAL`
evaluated by predecessor, `INDIRECT` as the call's effect), and keep a cheap
optional record of unit applications (unit, op, before/after) — Ghidra has
this only in debug builds (`OPACTION_DEBUG` **[G]** `action.hh`). *Why now:*
this is what makes the stage-equivalence check of section 5 possible, what
lets a wrong output be traced to the unit that caused it (the method D-Helix
uses to localise decompiler bugs **[S]**), and what the UI needs to answer
"where did this expression come from". Binary Ninja validated its new
structurer the same way, executing generated tests against simulators of each
IL level **[S✓]**.

**D4. Function summaries.** Decompiling a function yields, besides text, a
summary: parameters and their storage, whether and where a value is returned
and whether any path leaves one, whether it can return at all, whether it ends
in a tail call, what it reads and writes through each pointer parameter
(offsets, sizes, strides), its callees. The trait through which the engine
reaches the program (ADR-004) serves summaries of callees back. *Why now:*
recommendations 1 and 3 are inter-procedural; without summaries each would
invent its own side channel, as Ghidra's separate Java analyzers do
(`DecompilerFunctionAnalyzer`, `DecompilerCallConventionAnalyzer`,
`DecompilerSwitchAnalyzer`, `FindNoReturnFunctionsAnalyzer`,
`SharedReturnAnalyzer` **[G]**). *Cost:* a data type and a trait method in
M3; the scheduler (bottom-up over strongly connected components of the call
graph, re-running callers when a summary changes) is M5 work.

**D5. A re-runnable structurer.** Ghidra keeps the structured hierarchy
(`sblocks`) apart from the basic blocks (`bblocks`) and can reset it
(`Funcdata::structureReset` **[G]**). Keep that separation, add the ability
to structure a *copy* of the block graph and compare two results (gotos,
depth), and keep Ghidra's block-surgery helpers (`nodeSplit`,
`nodeJoinCreateBlock` **[G]** `funcdata.hh`) usable from new units. *Why now:*
angr's de-optimisation passes all have this shape — apply, re-structure,
reject if gotos increase (`StructuringOptimizationPass` with
`prevent_new_gotos`, `must_improve_rel_quality` **[S]**) — and arenas make
copying a block graph cheap if it is planned for.

**D6. Type facts and provisional types.** Ghidra propagates one concrete
data-type per varnode (`Varnode::type` **[G]** `varnode.hh`) and, as far as I
read `typeop.cc` and `coreaction.cc`, keeps no record of *why* **[P]**. Keep a per-function table
of observed accesses (base value, offset, size, stride, read or write, the
op), which costs nothing to collect and feeds structure synthesis, summaries
and any later constraint solver. Give the type system a category of types
created by inference (not user, not debug information) that can be refined
or discarded and that the printer can mark. *Why now:* the type system is an
early M3 task; adding a category later touches every match on type kinds.

**D7. Provenance on names and types.** A symbol or type records where it came
from and how sure the source was. Ghidra's program model has this for symbols
(`SourceType`: `USER_DEFINED`, `IMPORTED`, `ANALYSIS` and — already at the
pinned commit — `AI`, then `DEFAULT` **[G]**) and the engine reduces it to
"locked or not". *Why now:* it is
one field while the symbol table is being designed; it decides later which
names a model may overwrite and how the UI shows a guessed name.

**D8. What must survive the pipeline.** The address and instruction of every
op (Ghidra has this); whether a branch was a tail call; the original
comparison before normalisation, where a rewrite depends on it (the NaN
guards); the stack pointer's value at each call (so a pushed return address
is never printed as a store, catalogue A11); loop membership and induction
variables found before structuring; which idiom rule produced an expression
(`RuleDivOpt` and friends), so the output can be explained. The change record
of D3 carries most of this.

### 2.3 Improvements, in priority order

Effort: S = days, M = weeks, L = months, for one implementation agent with a
spec; these are **[J]** estimates, not measurements. "When" says whether the
improvement can wait until parity; all of them can — only the design
requirements above cannot.

#### R0. Quality harness and stage-equivalence check

* **Gain:** makes every later claim testable; finds port bugs during M3.
* **Evidence:** section 5. Ghidra's and angr's own regression practice is
  text assertions on a fixed corpus **[S]**; Binary Ninja's is executing IL
  against simulators **[S✓]**; D-Helix found 17 new bugs in Ghidra and angr by
  comparing binaries with recompiled decompiler output **[S]**.
* **Effort:** S for counters and corpus (prototype exists here); M for the
  equivalence check; M for debug-information ground truth.
* **Risk:** proxies get optimised instead of quality; section 5.1 lists how
  each can be gamed.
* **Where:** `bk-testkit` and a dev-only tool. **When:** with M3.

#### R1. Function summaries used by callers and callees

* **Gain:** fixes catalogue A1 (return value dropped), A3 (fall-through after
  a call that does not return), A4 (arguments dropped at calls), A7 (indirect
  tail calls) and part of A5/A6. In the corpus: 25 of 174 non-`void`
  functions printed `void`; every call to an unmarked `die()` followed by
  wrong code. **[E]**
* **How:** (a) a function *returns a value* if any caller reads the return
  register after the call, or — locally — if the register is written on every
  path to a return by something other than leftover scratch; callers'
  evidence comes through summaries, which is what lets the local rule stay
  cautious. (b) *Does not return* is inferred bottom-up (every path ends in a
  non-returning call or an endless loop), plus the local evidence that a call
  is followed by another function's entry or by padding, plus per-call-site
  conditions for known library functions (SAILR's example: glibc `error()`
  does not return when its first argument is a non-zero constant **[S]**).
  (c) Call sites take argument lists from the callee's summary instead of
  guessing from the caller alone. (d) A jump through a register at a point
  where the stack is balanced is a tail call, not an unrecovered jump table.
* **Evidence:** **[E]** a04, a05, a06, a11, a16; that the right answer is
  available is shown by a17 (same code, prototypes given, printed correctly).
  Dramko et al. measured, on source code, that the rule "a function returns
  `void` when no caller uses its value" holds 76.1% of the time **[S✓]** — so
  caller evidence alone is not enough either, and both ends should be used.
  SAILR lists non-returning calls among the nine causes of spurious gotos
  **[S✓]**.
* **Effort:** M (summaries and the scheduler), S for each rule on top.
* **Risk:** a wrong "returns a value" prints a garbage value as meaningful;
  a wrong "does not return" hides live code. Both must be visible in the
  output when they rest on inference (a provenance mark, D7), and both are
  checked by the debug-information ground truth of section 5.
* **Where:** outside the engine (analysis, M5) plus small engine units
  (`ActionReturnRecovery`, `ActionActiveParam` replacements in the `basilisk`
  profile). **When:** after parity; needs D4.
* **Tension with parity:** none in the engine if summaries arrive through the
  same trait as Ghidra's stored prototypes; the `ghidra` profile simply runs
  with Ghidra's defaults (no stored prototypes for ELF).

#### R2. NaN-correct comparisons

* **Gain:** removes two unsoundnesses, one of them not switchable; output
  equal to the source in the common cases (`!(a >= b)`, `a < b ? a : b`).
* **How:** two changes. (a) Instead of dropping `NAN(a) || NAN(b)`
  (`RuleIgnoreNan`), fold `NAN(a) || NAN(b) || a < b` into `!(a >= b)` and
  the dual forms; print a bare `a < b` only where the NaN case is provably
  excluded. (b) Stop treating `b <= a` as the negation of `a < b` for
  floating-point operands: the negation is printed as `!(a < b)`, and a
  conditional is flipped only when that does not need the negation.
* **Evidence:** **[E]** a13 (`below`, `fmin2`), both verified against the
  lifted p-code, `fmin2` also with `option nanignore none` (unchanged);
  **[G]** `architecture.cc` (default), `ruleaction.hh` (`RuleIgnoreNan`),
  `typeop.cc` (`TypeOpFloatLess`: `booleanFlip = CPUI_FLOAT_LESSEQUAL` with
  `boolean_reorder`), `printc.cc` (`opCbranch`, `checkPrintNegation`).
* **Effort:** S. **Risk:** low; more `!(…)` in float code, and (b) touches
  how conditions are normalised before structuring, so the corpus must be
  re-reviewed for changed `if`/`else` order.
* **Where:** one rule, the Boolean-negation table and its users. **When:**
  after parity.

#### R3. Pointer, array and structure recovery

* **Gain:** turns `*(int4 *)(param_1 + param_2 * 4)` into `a[i]`,
  `(**(code **)(*param_2 + 8))(param_2, …)` into `out->ops->write(out, …)`,
  and removes most casts. Dramko et al. coded pointer arithmetic for
  structure members 22 times in the 25 Ghidra functions they studied — more
  often than any other class in the rows of their table reported to me, names
  aside, which they did not count — and judged a group of issue classes
  fixable "deterministically given types" **[S]** (the table was read by a
  helper; I verified two other figures of the paper, not this one). TRex reports better types than
  Ghidra on 123 of 125 binaries while analysing one function at a time
  **[S✓]** (abstract).
* **How, in three steps of rising cost:**
  1. *Pointer-ness from use (S–M).* Ghidra refuses to propagate a pointer
     type from the result of an addition back to its operand
     (`TypeOpIntAdd::propagateType`: "Don't propagate pointer types this
     direction" **[G]** `typeop.cc`), which is why a parameter that is only
     ever dereferenced with an index stays an integer. Propagate it when the
     other operand is provably an index (a multiple of the element size).
     Derive the element type from the access and the stride.
  2. *Per-function structure synthesis (M).* From the access table of D6,
     build a provisional structure for each pointer whose accesses do not fit
     an array, as Ghidra's own "Auto Fill in Structure" does on request in
     Java (`FillOutStructureHelper` **[G]**) and Hex-Rays' "Create new struct
     type" does on request **[S]** — but automatically, as an inferred type.
  3. *Cross-function unification (L).* Merge the provisional structures that
     flow into each other through calls, seeded by known library prototypes,
     using summaries. The candidates are a Retypd-style subtype-constraint
     solver or its faster reformulation BinSub (0.024 s against 1.51 s per
     function at equal precision, on the paper's 1,568-function benchmark
     **[S]**), TRex's structural types (Rust, BSD-3-Clause, consumes exported
     Ghidra p-code **[S]**), and TypeForge's type-flow graph (Ghidra
     extension, BSD-3-Clause **[S]**).
* **Evidence:** **[E]** a01, a14, a15, r14, r17, r18; sources above.
* **Risk:** wrong inferred types mislead more than missing ones; they must be
  marked as inferred and easy to discard. Trail of Bits reports that Retypd's
  method is covered by a GrammaTech patent **[S]**: step 3 should start from
  BinSub's or TRex's formulation and needs a legal check before it starts.
  Step 1 changes type propagation and so touches output everywhere: it is the
  improvement that most needs the whole-corpus review of 2.1.
* **Where:** `typeop`/`ActionInferTypes` (step 1), a new unit after type
  recovery (step 2), analysis layer (step 3). **When:** after parity; needs
  D4, D6, D7.

#### R4. Compiler-aware structuring

* **Gain:** fewer gotos and source-like loops and switches. SAILR's
  measurements on 7,355 functions of 26 Debian packages (GCC 9.5, `-O2`):
  source 1,367 gotos; SAILR 2,673; Hex-Rays 8.0 6,115; Ghidra 10.1 6,575;
  the two goto-free methods 0 gotos but the worst structural distance to the
  source (CFGED 338,231 and 524,248 against 166,468 for SAILR and 187,509 for
  Ghidra), with seven times the source's Boolean operators (DREAM) or three
  times its calls (Combing) **[S✓]**.
* **How:** keep Ghidra's collapse engine and add units, each tried on a copy
  and kept only if the result is better (D5):
  1. *Loop un-rotation* — a guarded `do … while` whose guard equals the loop
     condition becomes `while`, then `for` by Ghidra's existing loop-variable
     logic. RetDec does this on its tree (`IfBeforeLoopOptimizer` **[S]**);
     DREAM++ shows it in its for-loop recovery **[S?]**.
  2. *Switch rebuilding* — an `if` cascade or compare tree on one value
     becomes a `switch` (RetDec `IfToSwitch`, Reko
     `IfCascadeToSwitchRewriter`, angr `lowered_switch_simplifier` **[S]**);
     a shift-and-mask bit test becomes a `switch` with the set bits as cases;
     a jump table's bounds check becomes the `default` (Binary Ninja **[S✓]**).
  3. *Tail-merge and cross-jump reversal* — duplicate small shared tails,
     returns first (Ghidra's `ActionReturnSplit` does a narrow version; angr's
     return duplicators bound it by the number of calls in the region **[S]**).
  4. *Better goto selection* when structuring is stuck (Ghidra's `TraceDAG`
     scoring; SAILR names edge choice as a remaining cause **[S]**).
* **Evidence:** **[E]** r02 (loops), a07 and r03 (switches: compare trees and
  bit tests never become `switch`; AArch64 GCC's lowered switch gives 7 gotos
  and a duplicated loop body), r01 and a07 (tail merging), a17 (a goto that
  appears only once the return type is known).
* **Effort:** L in total, S–M per unit. **Risk:** duplication can bloat
  output and each unit must preserve semantics; the equivalence check and the
  "keep only if better" rule bound both. SAILR's own run time is over 20 times
  Ghidra's (median 1.16 s against 0.05 s per function), which its authors
  attribute to Python and a naive search **[S✓]**; a budget per function is
  needed.
* **Where:** units between `ActionBlockStructure` and final structure, and
  tree passes (D2). **When:** after parity; needs D2, D5.
* **Not recommended:** replacing the collapse engine with a goto-free method.

#### R5. Idiom outlining and compiler noise

* **Gain:** each of these shrinks several lines to one, on most functions of
  real programs.
* **What:**
  * `memcpy`/`memset`/`strcpy` and struct copies from groups of loads and
    stores (catalogue R9; Binary Ninja's documented design: data-flow over
    out-of-order stores, classification of the bytes, thresholds of more than
    16 bytes for memory operations and at least four printable characters for
    strings, default on **[S]**). Ghidra has a narrower version
    (`constseq.cc`: `builtin_strncpy`, `builtin_memcpy`) that catches one of
    the three stack strings in the corpus **[E]**.
  * Stack-protector prologue and epilogue recognised per platform
    (`fs:0x28`, `__stack_chk_guard`, `__stack_chk_fail`) and folded into an
    annotation, behind a switch.
  * Range checks and bit tests back to comparisons: `(uint1)(c + 0xbf) < 0x1a`
    → `c >= 'A' && c <= 'Z'`; `(b & c) < 0` → `b < 0 && c < 0`;
    `x * -0x55555555 < 0x55555556` → `x % 3 == 0`.
  * Disjoint-bit additions printed as `|`, constant multiplications by powers
    of two that came from shifts printed as shifts in bit-packing context,
    64-bit comparisons on 32-bit targets (`SBORROW4` chains), 128-bit
    multiply-high, `bsr`/`clz` loops produced by instruction semantics.
* **Evidence:** **[E]** a08, a10, a12, a14, r04, r05, r06, r07, r09, r18;
  Hex-Rays' release notes show the same class of work and its hazard (a
  `memset` recognition that was "too aggressive") **[S]**.
* **Effort:** S per idiom, M for the copy outliner. **Risk:** a pattern that
  matches something else; every idiom rule needs a soundness argument and an
  equivalence test.
* **Where:** rules in the simplification pool or tree passes. **When:** after
  parity.

#### R6. Presentation

* **Gain:** less to read, in the order a reader needs it.
* **What:**
  * Fold variables written once and read once. On the DIRE data set, 85.9% of
    such non-parameter variables are inventions of the decompiler **[S✓]**.
  * Declare variables at first use in the narrowest scope, as an option;
    Ghidra prints all 320 declarations of the corpus at function tops
    (`PrintC::emitLocalVarDecls` **[G]**).
  * Do not reuse a parameter's variable for unrelated values (`param_1 =
    param_2; … param_3 = param_1` in r01); do not introduce a flag for a loop
    condition that could be tested directly (`bVar1 = 9 < x; x = x / 10; }
    while (bVar1)` in r05).
  * One radix policy per context instead of `mostNaturalBase` per constant
    (`0x14` beside `10`; `0x241, 0x1a4` for `open` flags and mode; `9`,
    `0x20`, `10` for characters; `x + -100`).
  * Names from more sources than Ghidra uses: results of known calls (`len`
    from `strlen`, `fd` from `open`, `p` from `malloc`), loop counters,
    the returned variable. Binary Ninja 3.5 ships names taken from callees'
    parameters and `i`, `j`, `k` for loop counters; Hex-Rays 7.6 ships names
    inferred from assignments and calls **[S]** (vendors' release notes).
* **Evidence:** **[E]** throughout; surveys by the dewolf authors conclude
  that preferences differ by user and task and that output should be
  configurable **[S]**.
* **Effort:** S each. **Risk:** low; taste. **Where:** tree passes and the
  printer (D2). **When:** after parity; the first improvements to land.

#### R7. Language models as suggesters

* **Gain:** better names and comments for those who want them.
* **How:** a plugin (ADR-014) asks a model — local or remote, the user's
  choice — for names, comments and candidate types given the output tree;
  the decompiler applies them through its own rename and retype operations,
  marks their provenance (D7) and can drop them all at once. No model edits
  code.
* **Evidence:** renames and comments cannot change what the code means; a
  retype is checked by the decompiler's own propagation (**[J]**; no source
  demonstrates this division, it follows from the mechanism). Against free
  rewriting: D-LiFT's 93.2% **[S✓]**; DecompileBench's "52.2% lower
  functionality correctness" for model-based methods despite better judged
  readability **[S✓]**. On names: VarBERT's top-1 accuracy on its own
  deduplicated corpus is 40–46% when the test binaries are unseen and 54–60%
  when only the test functions are, after it showed 65.5% and 79.9%
  train/test overlap in the two earlier data sets **[S✓]**; one study of 27 students found gains with predicted names
  **[S✓]**, a DSN 2025 study found no significant gain in speed or accuracy
  although participants preferred them **[S✓]**; a 2026 study found that
  model-made names, comments and types did not correlate with understanding
  and that about a fifth of sessions chased false leads **[S]**.
* **Effort:** M. **Risk:** plausible wrong names mislead; hence provenance,
  off by default, and never in the core. **When:** after M9's plugin API.

#### Later, with less certainty

* **Re-rolling unrolled loops and undoing induction-variable rewrites**
  (`pfVar1 + 4` walking instead of `v[i].w`). Visible everywhere at `-O2`
  **[E]** (t_smoke, a01, a15, r02); I found no published method that does it
  reliably. Open question.
* **Variadic functions and `va_list`, variable-length arrays, SIMD loops.**
  Unreadable today **[E]** (r11, r12, r16); each is a recogniser of a
  per-platform pattern. M each; lower frequency.
* **Return and parameter storage from the calling convention's intent**
  (AArch64 `float8` returned as a 16-byte array, A6). S–M; architecture by
  architecture.
* **Recompilable output** as a printing mode. Needed for recompile-and-run
  measurement (section 5); otherwise low value for a reader.
* **C++, exception handling, other languages.** Not studied here. Hex-Rays'
  `try`/`catch` recovery exists only for 64-bit MSVC and its region
  boundaries are approximate **[S]**.

### 2.4 Confidence

| Confident (experiment plus source, or mechanism read in the code) | Plausible, unproven here | Open |
|---|---|---|
| R0, R1 (a)–(c), R2; R3 step 1; loop un-rotation and switch rebuilding in R4; canary and copy outlining in R5; folding single-use variables in R6; "models suggest, the decompiler applies" in R7; D1, D3, D4, D5 | D2 (the tree can reproduce `printc` exactly); R3 steps 2–3 at acceptable error rates; tail-merge reversal without bloat; that summaries are cheap enough to be on by default; R1 (d) | Loop re-rolling; which type-unification method; whether any readability proxy tracks comprehension well enough to gate on; the patent question |

---

## 3. Evidence: where Ghidra's output is weak

### 3.1 Method and limits

36 C files (104 functions) in `decompiler-quality/src/`, compiled with
clang 20.1.8 for x86-64, x86 and AArch64 and with GCC 14.4.0 for AArch64 and
(seven cases) x86-64, mostly at `-O2`: 74 builds, 209 decompiled functions.
Each build is a small static ELF converted to the `<binaryimage>` form of
Ghidra's data tests and run through the reference `decomp` console. Sources,
fragments, console scripts and output are checked in.

The console is the engine alone. The harness supplies what a full Ghidra
would for library prototypes, data symbol names, read-only memory and direct
tail calls, and deliberately supplies nothing for program-defined
non-returning functions or stored prototypes (the README has the table). The
column **Scope** below says what a finding depends on:

* **engine** — follows from engine code and would be the same in a full
  Ghidra given the same facts;
* **engine+defaults** — the engine's behaviour when the facts are absent, and
  they are absent in a default Ghidra analysis of an ELF file (prototype
  storage off);
* **analysis** — a full Ghidra's analyzers may supply the missing fact; the
  finding shows what happens when they do not.

Auto-vectorisation is off except in r16; the console prints `int4`, `uint8`,
`xunknown4` where the GUI prints `int`, `ulong`, `undefined4`.

Two mistakes were made and caught while building the harness, and are worth
recording because the same traps wait for the test corpus: a jump to another
function's entry is followed *into* that function unless a flow override is in
force (a first run appeared to show calls "vanishing"); and a container image
tag that moved to another platform silently produced x86-64 code for AArch64
targets (the runner now checks the ELF machine).

### 3.2 Accuracy: output that is wrong or misleading

**A1. Return value dropped.** Scope: engine.

```c
int inc(int *p) { return ++*p; }                     /* a16 */
int find_first(const int *a, int n, int key) { … return i; }   /* r02 */
int bump(int by) { counter += by; …; return counter; }         /* r15 */
int after_call(const char *s) { char b[32]; strcpy(b, s); return puts(b); }
```

Ghidra prints (x86-64 clang; the same on AArch64 and x86-64 GCC for most):

```c
void inc(int4 *param_1) { *param_1 = *param_1 + 1; return; }
void find_first(int8 param_1,int4 param_2,int4 param_3) { … return; }
void bump(int4 param_1) { counter = counter + param_1; …; return; }
void after_call(char *param_1) { …; puts(acStack_28); return; }
```

Wanted: `int` functions returning the value. Cause: `ActionReturnRecovery`
(`coreaction.cc`) accepts the return register only if
`Funcdata::ancestorOpUse` (`funcdata_varnode.cc`) finds a value whose *only*
use is the return; a value also used in the function fails the test, and for a
value produced by a call the code says "A call is never a good indication of
a single op use". Tail calls print as `callee(…); return;` for the same
reason, even when the callee's prototype is known (r01 `classify`, r10
`create`). 25 of 174 non-`void` functions in the corpus; with prototypes
given (a17) all are right.

**A2. Floating-point comparisons wrong for NaN.** Scope: engine; `below` with
the default option, `fmin2` always.

```c
int below(double a, double b) { return !(a >= b); }      /* a13 */
double fmin2(double a, double b) { return a < b ? a : b; }
```

```c
bool below(float8 param_1,float8 param_2) { return param_1 < param_2; }
float8 fmin2(float8 param_1,float8 param_2)
{ if (param_2 <= param_1) { param_1 = param_2; } return param_1; }
```

Two mechanisms, both read in the source and checked on the lifted p-code:

* `below`: the machine code returns 1 for `below(NaN, x)`; the printed C
  returns 0. The lifted p-code has `CF = NAN(a) || NAN(b) || a < b`;
  `RuleIgnoreNan` removes the NaN terms because `nan_ignore_compare` is true by
  default. With `option nanignore none`: `return (NAN(param_1) ||
  NAN(param_2)) || param_1 < param_2;`. Wanted: `return !(param_1 >=
  param_2);`.
* `fmin2`: the lifted p-code is "if `a < b` keep `a`, else `a = b`", so
  `fmin2(NaN, 1.0)` is 1.0. The printed C tests `param_2 <= param_1`, which is
  false for NaN, and returns NaN. The engine negates `a < b` to `b <= a`
  (`TypeOpFloatLess` in `typeop.cc` registers `CPUI_FLOAT_LESSEQUAL` with
  reordered operands as its Boolean flip; `PrintC::opCbranch` uses it), which
  is not a negation when an operand is NaN. `option nanignore none` does not
  change this output. Wanted: `if (!(param_1 < param_2)) { param_1 =
  param_2; }`, or the source's conditional expression.

**A3. Code after a call that does not return.** Scope: analysis.

```c
__attribute__((noreturn, noinline)) void die(const char *msg) { puts(msg); exit(1); }
int checked_get(const int *p) { if (!p) die("null pointer"); return *p; }
int after(int x) { return x * 7 + 1; }                   /* a05 */
```

```c
int4 checked_get(int4 *param_1)
{
  int4 iVar1;
  if (param_1 == (int4 *)0x0) {
    iVar1 = 0x200120;
    die(0x200120);
    return iVar1 * 7 + 1;          /* the body of after() */
  }
  return *param_1;
}
```

On all three compilers. The engine knows `die` cannot return only if told
(`FuncProto::isNoReturn`); while decompiling `die` itself it prints
"Subroutine does not return" for `exit`, and does not carry that to callers.
A full Ghidra's `FindNoReturnFunctionsAnalyzer` may catch this from evidence
in the listing; when it does not, this is the result.

**A4. Arguments dropped at calls.** Scope: engine+defaults.

```c
long use_pair(int x) { struct pair p = ext_pair(x); return p.a * p.b; }   /* a04 */
int caller(int x) { return helper(x, 3, 5) + helper(7, x, x); }           /* a11, x86 */
```

```c
int8 use_pair(void) { … axVar1 = ext_pair(); return axVar1._0_8_ * axVar1._8_8_; }
int4 caller(xunknown4 param_1) { iVar1 = helper(5); iVar2 = helper(param_1); … }
```

An argument that reaches the call in the register it arrived in leaves no
write for the caller-side analysis to see, so both the call's argument and
the function's own parameter disappear (the analysis is `ActionActiveParam`
with `AncestorRealistic`; that this is the reason is my reading of the
output, not traced in the source **[J]**). In a11 the callee, decompiled alone, is
`__regparm3 helper(param_1 … param_4)` — four parameters, one of them
spurious — while its callers show one argument.

**A5. Parameter order and unused parameters.** Scope: engine. `double
mixed(int a, double b, int c, double d)` is printed as `mixed(float8
param_1, float8 param_2, int4 param_3, int4 param_4)`; `third(int a, int b,
int c)` as `third(xunknown8 param_1, xunknown8 param_2, int4 param_3)` (a03).
The order across register classes is not in the binary; the output presents a
guess as a signature.

**A6. Return storage on AArch64.** Scope: engine. `double fmin2(double,
double)` is printed as `xunknown1 [16] fmin2(float8 param_1, float8 param_2)`
ending `axVar1._8_8_ = 0; axVar1._0_8_ = param_1; return axVar1;`, and
`fabs2(double)` takes `xunknown1 param_1 [16]` (a03, a13, AArch64 GCC): my
reading, not traced in the source **[J]**, is that a write to `d0` also
clears the upper half of `v0` in the lifted p-code and the widest written
register is taken as the return storage.

**A7. Indirect tail calls.** Scope: engine.

```c
int indirect_tail(handler h, int x) { return h(x + 1); }              /* a06 */
```

```c
void indirect_tail(code *UNRECOVERED_JUMPTABLE,int4 param_2)
{
                    /* WARNING: Could not recover jumptable at 0x00200136. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*UNRECOVERED_JUMPTABLE)(param_2 + 1);
  return;
}
```

Two warnings, a parameter named after the failure (`coreaction.cc`), the
return value lost; on AArch64 GCC the second of two such calls in `dispatch`
also loses its argument.

**A8. Stack arrays and structures split into unrelated variables.** Scope:
engine.

```c
int local_array(void) { int a[4]; ext_p(a); return a[1] + a[3]; }     /* a08 */
```

```c
int4 local_array(void)
{
  xunknown1 axStack_18 [4];
  int4 iStack_14;
  int4 iStack_c;
  ext_p(axStack_18);
  return iStack_c + iStack_14;
}
```

The reader sees a 4-byte buffer passed away and two variables returned that
nothing ever writes. Stack layout recovery is in `varmap.cc`.

**A9. Pointer parameters typed as integers.** Scope: engine. `int get(const
int *a, long i) { return a[i]; }` → `xunknown4 get(int8 param_1, int8
param_2) { return *(xunknown4 *)(param_1 + param_2 * 4); }` (a01). Cause in
R3 step 1. Whether a pointer is recovered depends on the compiler's choice of
addressing: the same loop is `int8 param_1` from clang (indexed) and `int4
*param_1` from GCC (pointer walking).

**A10. Wrong field named, with types known.** Scope: engine. Given the
structure and the prototype (a15), the remainder loop of clang's unrolled
`total` is printed as `*(float8 *)(v[uVar1].name + uVar2 + 0x14)`: the field
`w` reached as an offset from the neighbouring field `name`.

**A11. An invented store and a raw stack pointer for a variable-length
array.** Scope: engine. In r12 the return address pushed by the call to
`puts` is printed as a statement, `*(xunknown8 *)((int8)&xStack_10 + iVar2) =
0x2001ec;` (`0x2001ec` is the address of the instruction after the call,
checked in the disassembly), and the array is addressed through
`register_RSP`.

**A12. An invented loop.** Scope: language definition plus engine.
`__builtin_clz` compiled to `bsr` is printed as `for (; param_1 >> uVar1 ==
0; uVar1 = uVar1 - 1) {}` (r09): the instruction's p-code is a loop (`BSR` in
`Processors/x86/data/languages/ia.sinc` **[G]**) and nothing recognises it.

**Not found.** No case here shows an unsound *integer* rewrite; the
overflow-check cases (a09) are printed correctly, if oddly (`CARRY4(param_1,
param_2)`). The literature reports such bugs: D-Helix reports 17 new bugs in
Ghidra and angr **[S]**, Bin2Wrong 48 across seven decompilers **[S]**,
FuzzFlesh 12 control-flow miscompilations **[S]**.

### 3.3 Readability

| Id | Class | Example (case) | Ghidra prints | Wanted | Stage |
|---|---|---|---|---|---|
| R1 | Loop shape | `for (i = 0; i < n; i++) a[i] = v + i;` (r02, AArch64 GCC) | `if (0 < param_2) { iVar1 = 0; do { …; iVar1 = iVar1 + 1; } while (iVar1 != param_2); }` | the `for` | `block.cc`: `for` is made in `BlockWhileDo::finalTransform`, that is, only from a loop already recognised as top-tested **[G]** |
| R2 | Unrolled loops | the same loop from clang (r02, t_smoke, a01) | a 4× or 8× body, then a remainder loop: 25 lines for 1 | one loop | none; open problem |
| R3 | Switch lowered to compares | `switch (x) { case 1: … case 10000: … }` (a07 `sparse`; `dense` on AArch64 GCC) | nested `if (param_1 == 100) … if (param_1 < 0x65) …` | `switch` | jump-table recovery starts from an indirect branch (`jumptable.cc`) **[P]**; nothing rebuilds a `switch` from comparisons |
| R4 | Switch lowered to a bit test | `case ' ': case '\t': case '\n': case '\r': case ',': case ';': return 1;` (a07) | `(param_1 < 0x3c) && ((0x800100100002600U >> ((uint8)param_1 & 0x3f) & 1) != 0)` | the `switch`, or the six comparisons | none |
| R5 | Lowered switch in a loop | the interpreter of r03, AArch64 GCC | 7 gotos, the loop body printed twice | as from x86-64 GCC, where the jump table gives a clean `switch` | structuring |
| R6 | Gotos from tail merging | goto-free `classify` (r01, clang) | 2 gotos, `param_1 = param_2;` … `param_3 = param_1;` | no goto | structuring; merging |
| R7 | Casts | throughout: 424 casts in 2,695 lines | `(int8)(int4)(uVar2 & 0xf) * 4`, `(uint8)(uint4)n` | far fewer once types are right | `ActionSetCasts`, `cast.cc` |
| R8 | `CONCAT`/`SUB`/carry operators | `a < b` on `long long`, x86 (a12) | `(SBORROW4(param_2,param_4) != SBORROW4(param_2 - param_4,(uint4)(param_1 < param_3))) != (int4)((param_2 - param_4) - (uint4)(param_1 < param_3)) < 0` | `a < b` | `double.cc` when the pieces are separate parameters |
| R9 | Inline copies and zeroing | `*dst = *src;` for 48 bytes (a10); `memcpy(c.tag, "basilisk", 8)` (a08) | five temporaries and six stores; `xStack_8 = 0x6b73696c69736162;` | `*dst = *src;` / the `memcpy` | `constseq.cc` covers a narrow case |
| R10 | Strings | `printf("error %d: %s\n", code, "disk full")`; `char name[] = "basilisk decompiler"` (r07) | `printf("error %d: %s\n",param_1 & 0xffffffff,0x200120)`; five hexadecimal words | the strings | no format-driven typing of variadic arguments in the engine (a full Ghidra has `FormatStringAnalyzer`); `constseq.cc` |
| R11 | Field and index access as arithmetic | `out->ops->write(out, buf, n)`; `out->err = 1` (r14) | `(**(code **)(*param_2 + 8))(param_2,axStack_128,iVar1)`; `*(xunknown4 *)((int8)param_2 + 0xc) = 1` | field access | no structure recovery in the engine |
| R12 | Range-check and bit idioms | `c >= 'A' && c <= 'Z'`; `x % 3 == 0`; `b < 0 && c < 0`; `a << 24 \| b << 16 \| c` | `(uint1)(param_1 + 0xbfU) < 0x1a`; `(uint4)(param_1 * -0x55555555) < 0x55555556`; `(int4)(param_2 & param_3) < 0`; `param_2 * 0x10000 + param_1 * 0x1000000 \| param_3` | the source forms | no rule |
| R13 | Names | throughout: 2,520 automatic names | `uVar3`, `param_1`, `iStack_14`, `in_FS_OFFSET` | names with meaning | `ActionNameVars`, `database.cc` |
| R14 | Temporaries | `if (v[i].id == id) return &v[i];` (a15, GCC) | `piVar1 = &v->id; piVar2 = v; v = v + 1; if (*piVar1 == id) { return piVar2; }` | one comparison | merging and explicit-variable marking |
| R15 | Declarations | throughout: 320 declarations, all at function tops | 19 declarations, 14 of them `float4` temporaries, before the first statement (r16) | at first use | `PrintC::emitLocalVarDecls` |
| R16 | Stack protector | any function with a buffer (r06) | `iStack_8 = *(int8 *)(in_FS_OFFSET + 0x28);` … `if (*(int8 *)(in_FS_OFFSET + 0x28) != iStack_8) { __stack_chk_fail(); }` | nothing, or a one-line note | none |
| R17 | Variadic functions | `va_arg` loop (r11) | `aiStack_b8 [46]`, `iStack0000000000000008`, offset arithmetic on the register save area | `va_list` operations | none |
| R18 | Constants | `open(path, O_WRONLY\|O_CREAT\|O_TRUNC, 0644)`; `c == ' ' \|\| c == '\t' \|\| c == '\n'` (r10) | `open(param_1,0x241,0x1a4)`; `(param_1 != 9) && (param_1 != 0x20)` … `param_1 == 10`; `0x14` beside `10` | flag names, octal mode, characters | `PrintLanguage::mostNaturalBase`; no enumeration data in the console |
| R19 | Vector code | `d[i] = a[i] + b[i]` vectorised (r16) | about 85 lines, 14 scalar `float4` temporaries | a loop, or vector operations | none |
| R20 | Assignments and commas in conditions | the unrolled table search (r15) | `if (((((table._0_4_ == param_1) \|\| (pxVar1 = table + 0x10, table._16_4_ == param_1)) \|\| …` | a loop | structuring |

### 3.4 Counters over the corpus

From `tools/metrics.py` over all 209 function bodies (2,695 lines) **[E]**:
12 gotos; 424 casts; 29 `CONCAT`/`SUB`/carry artefacts; 63 `do … while`,
10 `for`, 13 `while`; 3 `switch` (the sources have five switch functions,
built three times each); 21 warnings; 83 raw addresses; 2,520 automatic names;
320 declarations; 49 `void` functions of which 25 are not `void` in the
source. These are the baseline the `ghidra` profile must reproduce and the
`basilisk` profile should move.

---

## 4. Evidence: what is known to work

For each technique: the problem, how well established, cost, and fit to a
p-code SSA pipeline. The fit statements are **[J]** unless marked.

### 4.1 Control-flow structuring

| Technique | Problem solved | How established | Cost and trade-off | Fit |
|---|---|---|---|---|
| Schema matching (structural analysis; Ghidra's collapse rules) | Regions that match a fixed set of shapes become `if`/`while`/`switch`; the rest get gotos | The baseline of Ghidra, Hex-Rays, RetDec, Reko **[S]** | Fast (Ghidra 0.05 s median per function in SAILR's timing **[S✓]**); gotos wherever the compiler broke the shapes | Already the plan |
| Phoenix (Schwartz et al., 2013) | Semantics-preserving schemas plus iterative refinement: remove one edge as a goto and continue | Reimplemented in angr and Reko; evaluated by its authors on 107 coreutils programs **[S]** | No short-circuit schema, so gotos there (per SAILR **[S]**) | Ghidra already has the equivalent (`ruleBlockOr`, goto selection) |
| DREAM (Yakdan et al., 2015) | Goto-free output from reaching conditions, no schemas | Reimplemented in angr and dewolf; Binary Ninja's method up to 4.0 was "similar in nature" and was replaced because of "condition complexity explosion" and unsoundness once gotos appear **[S✓]** | 0 gotos but 43,661 Boolean operators against the source's 6,180 on SAILR's Debian set **[S✓]** | Not recommended as the main method |
| Combing (rev.ng, 2020) | Goto-free output by duplicating code | Authors' own evaluation on coreutils **[S]**; in SAILR's reimplementation, calls grow to 166,798 against 53,995 in the source **[S✓]**; rev.ng's current code appears to structure with gotos first and recover loops afterwards (read from source comments only **[S]**) | Code duplication | Bounded duplication only (returns, small tails) |
| SAILR (Basque et al., 2024) | Reverts nine goto-causing compiler transformations (jump threading, common-subexpression elimination, switch conversion, cross jumping, software thread cache reordering, loop header copying, builtin inlining, switch lowering, non-returning calls) around each goto, then re-structures | Implemented in angr; evaluated by its authors, who also reimplemented the baselines; numbers in R4 **[S✓]** | 1.16 s median per function in Python **[S✓]** | The model for R4; needs D5 |
| Binary Ninja 4.1 restructurer | A list of graph transformations (`&&`/`\|\|` merging, condition duplication, sub-region resolution, code duplication, jump-table default, goto as last resort) | Vendor's description; validated on about 7,000 generated tests executed against IL simulators; no goto counts published; the post admits possible goto regressions **[S✓]** | Not published | Confirms the transform-list design and the testing method |
| Tree clean-up passes (RetDec, Reko) | `while (true)` to `for`/`while`, `if` cascades to `switch`, removal of the guard before a loop | In shipping open-source decompilers **[S]** | Cheap | Needs D2 |

Head-to-head numbers that include Ghidra: SAILR's tables (R4) and rev.ng's
coreutils counts (Ghidra 2,062 gotos at `-O2` against IDA's 2,082 **[S]**).
SAILR's finer-grained result is that Ghidra's structure is competitive
(median CFGED 7.0 against Hex-Rays' 8.0, the lowest total on its Linux kernel
sample) while its goto count is the highest of the schema-based tools
**[S]** — which is why the recommendation is to add to the engine, not
replace it. Caveats: SAILR and Binary Ninja's post are each the authors' own
evaluations; SAILR used Ghidra 10.1.

Sources: SAILR <https://www.usenix.org/system/files/usenixsecurity24-basque.pdf>
(text: <https://adamdoupe.com/publications/sailr-usenix2024.md>); DREAM
<https://www.ndss-symposium.org/wp-content/uploads/2017/09/11_4_2.pdf>;
Phoenix <https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/schwartz>;
Combing slides <https://rev.ng/downloads/asiaccs-2020-presentation.pdf>;
Binary Ninja <https://binary.ninja/2024/06/19/restructuring-the-decompiler.html>;
dewolf <https://arxiv.org/abs/2205.06719>; angr's pass framework
<https://github.com/angr/angr/blob/master/angr/analyses/decompiler/optimization_passes/optimization_pass.py>;
Hex-Rays exception handling <https://docs.hex-rays.com/user-guide/decompiler/exception-handler>.

### 4.2 Types and data structures

| Technique | Problem solved | How established | Cost | Fit |
|---|---|---|---|---|
| Local lattice propagation (Ghidra; TIE, 2011) | Scalar types from operations | Deployed | Cheap | The plan |
| Seeding from known prototypes: type libraries, FLIRT/Lumina, Function ID, WARP | Types and names of library functions, which then type their arguments | Deployed in IDA, Binary Ninja, Ghidra **[S]** | Cheap; signature data must exist per library and compiler | Highest yield per unit of effort; arrives with M4–M6 (archives, Function ID, DWARF, PDB) |
| On-request structure creation (Ghidra `FillOutStructureHelper`, Hex-Rays "Create new struct type") | A structure from the offsets one pointer is used with | Deployed, interactive **[S][G]** | Cheap | R3 step 2 makes it automatic |
| Retypd (2016); BinSub (2024) | Subtype constraints with recursive and polymorphic types across functions | Retypd: GPL-3.0 Python implementation and a Ghidra plug-in by GrammaTech, a Ghidra integration by Trail of Bits, a partial reimplementation in angr; BinSub: implemented in angr, 63 times faster at equal precision on its benchmark **[S]** | Retypd slow; BinSub cheap | Constraints come straight from copies, loads, stores, pointer additions and calls; needs summaries. Patent caveat in R3 |
| TRex (2025) | "Structural" types deduced from behaviour, without guessing source types | Rust, BSD-3-Clause, input is Ghidra p-code; better than Ghidra on 123 of 125 binaries **[S✓]**; one function at a time **[S]** | Not reported | A directly usable reference for R3 steps 2–3 |
| TypeForge (2025) | Composite types by a type-flow graph, with an optional model-assisted phase | Ghidra extension, BSD-3-Clause **[S]**; evaluation numbers known from snippets only **[S?]** | Moderate | Reference for step 3 |
| OSPREY (2021); learned models (DIRTY, TYGR, XTRIDE) | Probabilistic or learned recovery | Research; DIRTY's data has heavy train/test overlap **[S✓]**; TYGR reports 45.2% structure accuracy on its own data set **[S]** | Heavy, or a model at run time | Not for the core |
| Dynamic recovery (REWARDS, Howard) | Layouts from executions | Research; needs traces **[S?]** | — | Poor fit for a static tool |

Sources: Retypd <https://arxiv.org/abs/1603.05495>,
<https://github.com/grammatech/retypd>; Trail of Bits on Retypd in Ghidra
<https://blog.trailofbits.com/2024/02/07/binary-type-inference-in-ghidra/>;
BinSub <https://arxiv.org/abs/2409.01841>; TRex
<https://www.usenix.org/conference/usenixsecurity25/presentation/bosamiya>,
<https://github.com/secure-foundations/trex>; TypeForge
<https://github.com/noobone123/TypeForge>; TYGR
<https://adamdoupe.com/publications/tygr-usenix2024.md>; Hex-Rays structure
creation <https://hex-rays.com/blog/igors-tip-of-the-week-118-structure-creation-in-the-decompiler>;
the fidelity taxonomy (Dramko et al.)
<https://www.usenix.org/system/files/usenixsecurity24-dramko.pdf>.

### 4.3 Variables

* **Merging.** Ghidra merges by cover intersection (`merge.cc`). The
  compiler literature's refinement is value-based interference — two
  variables holding the same value do not interfere (Boissinot et al., 2009)
  **[S?]** — which is the principled way to remove copies such as R14's.
  Plausible, not demonstrated for a decompiler **[J]**.
* **Splitting.** Hex-Rays and Binary Ninja expose manual split and merge of
  variables for reused stack slots **[S]**; Ghidra has a split override
  (`isolate` in the console, `IfcIsolate` **[G]**). No automatic method with
  evidence was found.
* **Folding single-use variables.** 85.9% of once-written, once-read locals
  are decompiler-made on the DIRE data **[S✓]**; a print-time rule.
* **Stack layout.** Value-set analysis recovers more (DIVINE: 88% of locals
  on its benchmark **[S?]**) at whole-program cost; not proposed.

### 4.4 Expressions and idioms

* **Division by multiplication** (Granlund and Montgomery, 1994): Ghidra's
  `RuleDivOpt` family recovers every plain case tried here **[E]**; the gap
  is divisibility tests.
* **Outlining of inline library code**: Binary Ninja's documented design
  (R5) is the reference; Hex-Rays' notes show the risk of over-matching
  **[S]**.
* **Stack and obfuscated strings**: FLOSS is the reference tool **[S?]**;
  Ghidra's `constseq.cc` (`RuleStringCopy`, `RuleStringStore` **[G]**, names
  only) produced the `builtin_strncpy` of r06 and missed r07 and a08 **[E]**.
* **Constants to names**: library constants are recoverable from typed
  prototypes; the general case is guesswork (Dramko et al. call it
  "probabilistic") **[S]**.

Sources: outlining <https://docs.binary.ninja/dev/outlining.html>; Hex-Rays
7.6 notes <https://docs.hex-rays.com/9.1/release-notes/7_6>; division
<https://gmplib.org/~tege/divcnst-pldi94.pdf>.

### 4.5 Naming

* **Without learning**: debug information, exports and imports, signature
  databases, run-time type information, and names derived from calls. Ghidra
  already borrows a callee's parameter names **[E]**; Binary Ninja 3.5 adds
  loop counters, Hex-Rays 7.6 names inferred from assignments and calls
  **[S]**. Cheap and deterministic: R6.
* **Learned**: DIRE, DIRTY, VarBERT, GenNm and others. Reported accuracies
  fell once train/test leakage was removed: VarBERT measured 79.9% and 65.5%
  overlap in the DIRE and DIRTY data and reports 40–46% top-1 on its own
  deduplicated corpus when test binaries are unseen **[S✓]**. GenNm reports
  22.8% for names never seen in training **[S?]**.
* **Do predicted names help?** Mixed: R7.

Sources: VarBERT <https://adamdoupe.com/publications/varbert-oakland2024.md>;
DSN 2025 study
<https://edmcman.github.io/blog/2025-06-16--a-human-study-of-automatically-generated-decompiler-annotations-published-at-dsn-2025>;
Binary Ninja 3.5 <https://binary.ninja/2023/09/15/3.5-expanded-universe.html>;
DIRTY <https://github.com/CMUSTRUDEL/DIRTY> (MIT).

### 4.6 Presentation

* Dramko et al.'s taxonomy (15 classes, 52 codes, 25 functions from each of
  four decompilers; the authors warn the sample is small): names outnumber
  everything and were not counted; among the counted classes reported to me,
  non-idiomatic dereference and extra variables lead for Ghidra (22 and 16
  occurrences). Ghidra had the fewest non-equivalent expressions
  (2, against 9 for Hex-Rays, 28 for RetDec, 52 for angr) **[S]** — its
  conservatism is an asset to keep.
* DREAM++ (2016) added expression and control simplification and
  semantics-aware naming to DREAM and reports large gains in a study with 21
  students and 9 professionals **[S?]** (slides only).
* dewolf's three surveys (135 responses) conclude that readability depends
  on the user and the task, hence configurable output **[S]**.

### 4.7 Language models

| Use | What sources show | Trust |
|---|---|---|
| End-to-end neural decompilation (LLM4Decompile, Nova, SLaDe, Idioms, …) | Re-executability on small self-contained functions: LLM4Decompile reports 45–64% on HumanEval-Decompile against 20% for Ghidra's output recompiled as-is **[S]**; results fall sharply under obfuscation **[S]** | None beyond the benchmark's tests |
| Rewriting decompiler output (DeGPT, LLM4Decompile-Ref, FidelityGPT, Wong et al.) | More readable by judges; D-LiFT measured that a rewriting model broke 93.2% of functions Ghidra had right **[S✓]**; FidelityGPT's authors state repaired code often cannot be recompiled to verify it **[S]** | Needs an oracle |
| Rewriting with an oracle (D-LiFT's score; PCodeTrans's hot-swap and differential tracing) | D-LiFT's checker handled 80.7% of functions (tool errors, time-outs) **[S✓]**; PCodeTrans reports over 99% test-validated consistency on coreutils and binutils **[S]** | As good as the oracle's coverage |
| Assistants in tools (Gepetto, GhidrAssist, ReVa): names, comments, explanations | Help novices most; experts little; about 20% of sessions misled in one 2026 study **[S]** | Semantics untouched; understanding can still be misled |
| Names and types with program-analysis cross-checks (ReSym) | Beats DIRTY on its authors' data **[S]** | Partial |

Licences of the open models differ from their cards' labels in places (a
model card says MIT while the base model has its own terms **[S]**); any
bundled model needs its base licence checked. Local inference with 1–9
billion-parameter models is realistic on one GPU **[S]**.

Sources: D-LiFT <https://arxiv.org/abs/2506.10125>; LLM4Decompile
<https://arxiv.org/abs/2403.05286>; DeGPT
<https://www.ndss-symposium.org/ndss-paper/degpt-optimizing-decompiler-output-with-llm>;
Wong et al. <https://arxiv.org/abs/2310.06530>; FidelityGPT
<https://arxiv.org/abs/2510.19615>; PCodeTrans
<https://arxiv.org/abs/2603.14855>; DecompileBench
<https://arxiv.org/abs/2505.11340>; the human–model study
<https://www.s3.eurecom.fr/post/2025/12/18/decompiling-the-synergy-how-humans-and-ai-team-up-in-reverse-engineering/>;
ReSym <https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf>.

---

## 5. Measurement

### 5.1 What to measure

**Correctness**

| Metric | What it tells | How | Weakness | Cost |
|---|---|---|---|---|
| Text assertions per case | A known fault is fixed and stays fixed | Ghidra's data-test form: patterns with minimum and maximum counts on the printed C; `insta` snapshots for whole outputs | Checks text, not meaning | Lowest; exists in `bk-testkit` |
| Stage equivalence | The engine did not change behaviour between lifted p-code and final IR | Execute both on the same random register and memory states; compare the returned value, the memory written, and the sequence of calls with their arguments. Callees are stubs that return recorded values | Coverage of inputs; does not test the printer; floating point needs NaN and infinity in the inputs (it would have caught A2) | Medium; needs D3 and a small interpreter (`bk-emu`'s core, pulled forward) |
| Signature ground truth | Parameters, return, calling convention are right | Compile the corpus with `-g`, decompile the stripped build, compare with DWARF: `void` or not, parameter count, pointer or integer or float per parameter, order | Needs debug information; inlining and optimised-away parameters need care | Medium; `llvm-dwarfdump` output at first, `bk-dwarf` later |
| Type and variable ground truth | Types and variable boundaries match | Per variable with a DWARF location: same storage, compatible type; structure fields recalled | Optimised code loses variables; "compatible" must be defined (TIE's distance and conservativeness **[S?]**) | Medium–high |
| Recompile and run | The printed C means what the binary does | Self-checking programs (GCC's `c-torture/execute` tests call `abort()` on failure **[S?]**; Csmith programs print a checksum **[P]**), decompile, recompile, run | Output must compile first: DecompileBench reports 41.3% recompile success for Ghidra and 58.3% for Hex-Rays **[S✓]**; passing tests is not equivalence | High; needs a recompilable printing mode |
| Equivalence by symbolic execution (D-Helix) | As above, without tests | Symbolic comparison of binary and recompiled output | Return values only; path explosion; D-LiFT's use of it covered 80.7% of functions **[S✓]** | High; outside tools |

**Readability**

| Metric | What it tells | Weakness |
|---|---|---|
| Gotos | Structuring failures | Zero is not the goal: goto-free methods score worst on similarity to source **[S✓]**; rewarded by duplication |
| Casts, `CONCAT`/`SUB`/carry artefacts, raw addresses, warnings (per 100 lines) | Type and idiom failures | A wrong type can remove casts |
| Loop shapes (`for` : `while` : `do`) and `switch` count against the source's | Loop and switch recovery | Needs the source; legitimate differences exist |
| Automatic names as a share of identifiers | Naming coverage | Says nothing about whether names are right |
| Declarations and their distance to first use; single-use variables | Presentation | Taste |
| Lines, nesting depth, cyclomatic complexity | Size | All three can be improved by making output worse: SAILR and dewolf both show duplication lowering or preserving complexity **[S]** |
| Statement-shape distance to source | Similarity of structure | A histogram of statement kinds and nesting from a C parser, source against output; crude but cheap. SAILR's CFGED is the published version: needs its Python pipeline, is approximate on large functions (it reported 306 where the exact distance was 4) **[S]** |
| Relative readability (R2I), model judges | An overall score | R2I's weights come from surveyed preferences **[S?]**; judge agreement with humans was measured on 30 samples in DecompileBench **[S✓]**; one 2026 paper finds such scores saturate **[S]** |

No proxy has been shown to track human comprehension well; the DSN 2025 study
found that intrinsic metrics did not predict it for names **[S]**. So the
counters are regression alarms, and the judge of "really good" stays a
person reading a fixed sample at each milestone.

### 5.2 Corpus and ground truth

1. **Ghidra's 93 data tests** — parity.
2. **The weakness corpus** — `decompiler-quality/src/`, to be moved under the
   test kit when `bk-decomp` exists. Each case gets assertions in two forms:
   what the `ghidra` profile prints (today's output, as a snapshot) and what
   the `basilisk` profile must and must not print. Cases are added whenever a
   fault is found; every case states its scope (engine or analysis).
3. **Compiler matrix** — the same sources through GCC and clang, `-O0`,
   `-O2`, `-Os`, for x86-64, AArch64, x86 and one big-endian target, with
   `-g` for ground truth and stripped for input. Containers pin the
   compilers; the harness names image *and* platform (section 3.1).
4. **Real programs**, once loaders exist (M4–M5): a small fixed set with
   permissive licences built from source in the matrix — coreutils and a few
   of SAILR's 26 Debian packages are the natural choice because published
   numbers exist for them. Later, OSS-Fuzz projects for DecompileBench-style
   execution checks.
5. **Generated programs** for the equivalence check: Csmith and, for control
   flow, direct generation of machine code as Binary Ninja does **[S✓]** and
   FuzzFlesh does from random graphs **[S]**.

### 5.3 How it runs in this project

`bk-testkit` already runs Ghidra's `decomp` with a time limit and parses data
tests. The harness adds three things to it — a corpus runner, a counter
module (what `tools/metrics.py` prototypes) and, later, the comparison with
debug information — and one dev-only command that writes a scorecard. It runs
at two rates, split by what each run needs **[J]**:

| | In the gate (every merge) | Nightly (or on demand) |
|---|---|---|
| **Needs** | Nothing outside the repository: no compiler, no container, no reference tools | Pinned compilers in containers (named by digest *and* platform), the reference tools, later a full Ghidra |
| **Input** | The checked-in fragments (`frag/*.xml`, the `<binaryimage>` form; 0.5 MB for the present corpus) and Ghidra's 93 data tests | Fragments rebuilt from `src/` across the compiler matrix; generated programs; real programs |
| **Parity** | `ghidra` profile output equals the checked-in snapshot of the reference output (`insta`) | The reference `decomp` is re-run on everything and compared directly; the checked-in snapshots are checked for drift |
| **Assertions** | Per-case "must print / must not print" patterns for the default profile | The same over the matrix |
| **Counters** | Computed for both profiles and compared with the checked-in scorecard; a counter that gets worse fails unless the scorecard was updated in the same commit | Scorecard for the matrix and the real programs; trend kept |
| **Equivalence** | Lifted p-code against final IR on a fixed seed and a small number of inputs per function (bounded: a budget per function, a total budget) | Many inputs, NaN and boundary values, generated programs |
| **Ground truth** | — | Signatures, then types and variables, against DWARF |
| **Cost** | Seconds: the reference console runs all 74 fragments of this corpus (430 decompilations, counting the repeated ones) in 4.7 s on this machine; a full rebuild takes about 100 s, almost all of it container start-up **[E]** | Minutes to hours; every tool run has a time limit and every function a budget, so a hang is a recorded failure and not a stuck run |

* The scorecard has three columns — **Ghidra reference | Basilisk `ghidra`
  profile | Basilisk default profile** — per corpus. `docs/QUALITY.md` records
  it with the command that produces it, as `PERF.md` does for speed.
* Tests that need the reference tools skip when they are absent and fail
  under `BASILISK_REQUIRE_REFERENCE=1`, as everywhere else (ADR-007).
* Fragments are rebuilt only nightly, and a rebuilt fragment that differs
  from the checked-in one is reported, not silently replaced: a compiler or
  image that changed under the harness is exactly the failure that produced
  wrong output during this research (section 3.1).
* Milestone reviews: the owner reads the same 30 functions each time. This is
  the only check of whether the counters still mean anything.

**Cheap first.** (1) The corpus, the counters and snapshots of the reference
output: done here in prototype, needs no decompiler. (2) Signature ground
truth from DWARF on the same corpus: a few days. (3) The equivalence check as
soon as the IR exists: it will pay for itself in port bugs before any
improvement is written.

---

## 6. Open questions

1. Can the output tree (D2) reproduce `printc.cc` token for token? A spike on
   the 93 data tests when the printer is specified would answer it.
2. How expensive are bottom-up summaries on a large binary, and can they be
   on by default? The description of Ghidra's own analyzer says "WARNING: This
   can take a SIGNIFICANT Amount of Time!" **[G]**
   (`DecompilerFunctionAnalyzer.java`).
3. Which unification method for R3 step 3, and is there a patent obstacle?
4. Is there a reliable way to re-roll unrolled loops and undo induction
   variable rewrites? Nothing published was found.
5. Which readability proxy, if any, is worth gating on?
6. How much of section 3 changes under a full Ghidra? Running the corpus
   through headless Ghidra (ADR-007's optional oracle) would settle the
   "analysis" rows.
7. How do the other decompilers print this corpus? Decompiler Explorer
   (<https://github.com/decompiler-explorer/decompiler-explorer>, MIT) runs
   several in containers; it was not used because it means sending files to
   an outside service or licensing the commercial ones.

---

## 7. Further sources

Read by a research helper unless marked; all opened unless marked **[S?]**.

* Liu and Wang, "How far we have come: testing decompilation correctness of C
  decompilers", ISSTA 2020 **[S?]**:
  <https://conf.researchr.org/details/issta-2020/issta-2020-papers/26/How-Far-We-Have-Come-Testing-Decompilation-Correctness-of-C-Decompilers>
* Zou et al., D-Helix, USENIX Security 2024:
  <https://www.usenix.org/conference/usenixsecurity24/presentation/zou>
* Yang et al., Bin2Wrong, USENIX ATC 2025:
  <https://www.usenix.org/conference/atc25/presentation/yang-zao>
* FuzzFlesh, ECOOP 2025:
  <https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ECOOP.2025.13>
* Cao et al., "Evaluating the Effectiveness of Decompilers", ISSTA 2024
  **[S?]**:
  <https://2024.issta.org/details/issta-2024-papers/40/Evaluating-the-Effectiveness-of-Decompilers>
* R2I, FSE 2024 **[S?]**:
  <https://2024.esec-fse.org/details/fse-2024-research-papers/123/R2I-A-Relative-Readability-Metric-for-Decompiled-Code>
* DREAM++ slides, IEEE S&P 2016 **[S?]**:
  <https://www.ieee-security.org/TC/SP2016/slides/yakdan.pdf>
* "Decompiling for Constant-Time Analysis" (decompiler transformations can
  hide what a downstream analysis looks for):
  <https://arxiv.org/abs/2501.04183>
* "A Memorization Floor for LLM Refinement": <https://arxiv.org/abs/2609.17236>
* Idioms (joint code and type prediction): <https://arxiv.org/abs/2502.04536>
* GenNm, NDSS 2025 **[S?]**:
  <https://www.ndss-symposium.org/ndss-paper/unleashing-the-power-of-generative-model-in-recovering-variable-names-from-stripped-binary>
* WARP signatures: <https://github.com/vector35/warp>
* `sailreval`, SAILR's evaluation pipeline **[S?]**:
  <https://pypi.org/project/sailreval>
* GCC test idioms (`c-torture`) **[S?]**:
  <https://gcc.gnu.org/onlinedocs/gccint/Test-Idioms.html>

Corrections the helpers made to my brief, kept for the record: FidelityGPT
and the human–model study are NDSS 2026, not 2025; Guilfanov's "Decompilers
and beyond" could not be found; no documentation of Hex-Rays' structuring
algorithm exists (SAILR says the same).

---

## 8. Proposed ADR

Ready to paste into `docs/DECISIONS.md`; the coordinator assigns the number.
It records decisions only; the reasons and evidence stay in this document.

```markdown
## ADR-NNN — Decompiler improvements live in profiles; the port carries the hooks for them from the start
(Proposed by the `decomp-research` track; evidence and reasons in
`docs/research/decompiler-quality.md`.)

ADR-004 ports Ghidra's decompiler to measured parity and allows improvements
afterwards. This record says how the two coexist and what the port must
contain so that the improvements are possible without rewriting it.

1. **Profiles.** Every rule, action, merge pass, structuring step and output
   pass of `bk-decomp` is a named unit with an origin (`ghidra` or `basilisk`)
   and a group. A pipeline is built from the unit table by a named profile.
   The `ghidra` profile is Ghidra's pipeline and nothing else; it reproduces
   Ghidra's output including its faults, and it is the target of every
   differential test (ADR-007), permanently. The `basilisk` profile is the
   `ghidra` profile plus accepted improvements. The default profile is
   `ghidra` until M3 is accepted and `basilisk` afterwards.
2. **Ghidra's units are not edited to improve them.** An improvement is a new
   unit, or a replacement unit selected by the `basilisk` profile, with one
   switch in the option registry. A difference in the `ghidra` profile is a
   bug (ADR-001).
3. **The port has these properties from its first version**, none of which
   changes output:
   a. the IR can be evaluated at every stage, and every edit of it goes
      through one mutation interface to which a recorder of unit applications
      can be attached;
   b. the structurer runs on a copy of the block graph and returns a
      hierarchy with a measure of it;
   c. the engine hands the printer a typed output tree whose nodes refer to
      ops, varnodes and addresses; output passes work on that tree;
   d. decompiling a function produces a function summary (parameters, return,
      whether it can return, tail call, accesses through pointer parameters),
      and the program trait can serve summaries of callees to the engine,
      including an answer to "does this call return" that depends on the call
      site;
   e. the type system has a category of inferred types, and type recovery
      fills a per-function table of observed accesses;
   f. names and types carry their provenance (user, debug information,
      import, library signature, analysis, model) across the program trait.
   Item c is confirmed by a spike on Ghidra's 93 data tests when the printer
   is specified; if the tree cannot reproduce `printc.cc` token for token,
   output passes work on the structured block hierarchy instead and this item
   is revised by a new record.
4. **Quality is measured, not asserted.** `docs/QUALITY.md` holds a scorecard
   with three columns — Ghidra's reference build, the `ghidra` profile, the
   default profile — over a fixed corpus that starts from
   `docs/research/decompiler-quality/`. The gate runs, without tools from
   outside the repository: parity of the `ghidra` profile against checked-in
   snapshots, per-case assertions for the default profile, the counters, and
   a bounded stage-equivalence check (lifted p-code against final IR on the
   same inputs). Compiler matrices, the reference tools, ground truth from
   debug information and long equivalence runs are nightly.
5. **An improvement is accepted with**: its entry under "Differences from
   Ghidra"; snapshots of the affected cases in both profiles; the change in
   the scorecard; and, if it acts before structuring, a clean
   stage-equivalence run. Improvements are taken in order of how little they
   disturb: output passes first, then units outside the engine (summaries),
   then rules, then type propagation and merging.
6. **Language models never edit decompiled code.** They may propose names,
   comments and types through the plugin interface (ADR-014); the decompiler
   applies proposals with its own rename and retype operations, records their
   provenance and can remove them. This is off by default.

Consequences: each improved case has two snapshots; the program trait is
larger than the set of queries Ghidra's `DecompileCallback` answers; the
printer is ported as two stages. Not decided here: the method for
cross-function type unification (a licence and patent check comes first), and
which readability counters, if any, may fail the gate on their own.
```
