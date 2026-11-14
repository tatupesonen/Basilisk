# Track `spec-decomp-wave1` — status report

Specification track for D00 (`decomp-oracle`) and D04 (`decomp-cfg`) of
`docs/features/decomp-plan.md`. Writes no shipping code. Done.

## State

- [x] Rules, plan, ADRs, earlier specs and their reports read.
- [x] D04 research: `block.*` and `blockaction.*` read in full for the
      graph, hierarchy and structurer; the reference console run.
- [x] D00 research: console commands, action framework, debug trace,
      varnode/op fields and printing, side-state classes, `Translate`;
      determinism runs on both reference builds; `decomp_dbg` built and
      run on the build host.
- [x] `docs/features/decomp-cfg.md` and `docs/features/decomp-oracle.md`.
- [x] Cross-check of the two documents (commands, formats, counts).
- [x] This report.

## What each document covers

**`docs/features/decomp-cfg.md` (D04, `bk-decomp-cfg`).** Scope method by
method (graph surgery and queries, the analyses, the hierarchy, the
structurer, XML encoding in; `BlockBasic`, op-level transforms,
for-loops, jump-table labels, all `Action`s and `ConditionalJoin` out,
with reasons). Behaviour with file:line for every rule: edge labels and
derived tests; the four per-block facts (`complex`, `switch_out`,
`ends_in_return`, `negation_changes_dataflow`) with their neutral values;
`findSpanningTree`, `findIrreducible`, `calcLoop`,
`calcForwardDominator`; when the pipeline runs them (`structureReset`)
versus when it structures (`ActionBlockStructure` copies labels as they
are), hence `Analyse::AsGiven | Recompute`; `identifyInternal`/
`selfIdentify` edge order; every factory's fix-ups; negation and flips;
`LoopBody` (labelling, merging, containment, exits, tails, likely edges);
`TraceDAG` and `selectGoto` with the scoring; the collapse loop with the
exact iteration semantics; every rule's conditions; finishing
(`orderBlocks`, `scopeBreak`, `markUnstructured`, `markLabelBumpUp`);
XML and `printTree`; order dependence. Design: arena layout, scratch
reuse, the public API including ADR-025 3b's `structure(graph, facts,
options) -> Structured { hierarchy, flips, goto_edges, dataflow_changes,
measure, trace }`, a `GotoSelector` trait as the replaceable unit,
errors with Ghidra's messages, limits, no recursion, plugin constraints.
Tests: unit, `structure blocks` cross-check (works before D00 exists),
the full oracle through D00's commands (12,000 generated graphs in four
classes, every corpus structuring run), trace, properties, fuzzing,
benchmarks. Acceptance from plan 6.

**`docs/features/decomp-oracle.md` (D00).** The console as it is, with
output shapes (ran); the build (`decomp_dbg`, `decomp_bk`,
`decomp_bk_dbg` linked from the Makefile's objects plus the extension;
`bin/decomp` untouched); identity rules and canonical keys for
pointer-valued offsets; the state dump format v1, section by section and
field by field, what is left out and why, what can and cannot be
restored; taking dumps at positional breakpoints; graph files, `bk cfg
analyze`, `bk structure` and the structure dump (shared with D04);
recorded p-code (proxy `Translate`, format, by-address replay); the
trace grammar; the command list; determinism and host dependence with
the measured results and a table of order sources; the optional logs
(separate instrumented build); Ghidra headless as a later track; corpus,
check kinds, gate, the nightly `oracle` item, reporting; the `bk-testkit`
design; tests and acceptance.

## What was run, and where

All recorded in `docs/research/decomp-wave1/runs.md` (R1–R9) with the
scripts beside it (`gen_graphs.py`, `dt_scripts.py`, `dt_run.sh`,
`dt_compare.py`, `dt_hash.sh`, `build_dbg.sh`); the sort and container
inventory is `docs/research/decomp-wave1/sorts.md`.

- Mac (`../reference`, Darwin arm64, Apple clang 17, libc++): `print tree
  block` and `print raw` on `elseif.xml` (R1); `structure blocks` on a
  hand-made graph (R2) and on 3,000 random graphs, twice (R3); every data
  test with `print raw`, `print tree varnode`, `print tree block` after
  each `decompile`, twice (R5); `list action`, breakpoints, statistics,
  options (R7).
- Build host (`scripts/remote.sh run`, its reference: Debian g++ 14.2,
  libstdc++): the 3,000 graphs (R4); the data tests twice and against
  the Mac (R6); a scratch `decomp_dbg` build in the branch's `target/`
  and the data tests through it (R8); the debug trace on `elseif.xml`,
  twice (R9).

Results that matter: `structure blocks` is deterministic and
host-independent on 3,000 graphs (161 end in Ghidra's own error, 5 of
them reachable graphs); the reference's `print tree varnode` is **not**
deterministic between runs of one binary (heap-address order of `iop`,
`fspec` and space-constant varnodes; 43 of 93 tests on the Mac, 41 on
the host); apart from those lines the two hosts agree on all 93 tests
except `floatprint` (`NAN`/`-NAN`, ADR-021); `decomp_dbg` equals `decomp`
and its trace (1,347 records for `elseif.xml`) is deterministic; the
top-level `blockstructure` cannot be stopped at by any breakpoint name.

No gate run: docs-only branch, and `scripts/gate.sh` has no
documentation check (its file-size check covers only `crates/**/*.rs`).

## Where the plan is wrong or cannot work as written

1. **D04's oracle `structure blocks` is lossy** (plan 6 D04, 8 3b). Its
   XML drops edge labels (block.cc:35–53), encodes `ifnoexit` as
   `ifelse` (block.cc:675), has no overflow flag, no flips, no goto
   causes; its plain blocks are always "complex", never switches below
   three out-edges, never end in `RETURN`; and the command never calls
   `orderBlocks` (ifacedecomp.cc:3219–3269; `StructureGraph::rawAction`
   does, ghidra_process.cc:352). The specs keep it as a cross-check
   (decomp-cfg.md 6.2) and add `bk structure` on fact-carrying graphs
   (decomp-oracle.md 4.7).
2. **"Compiled into the source copy so the Makefile compiles it, with
   `-fno-access-control`"** (plan 4.2) cannot give per-file flags, and
   the file would enter `decomp`, `decomp_test` and `libdecomp`. The
   extension is compiled separately and linked into new consoles
   `decomp_bk`/`decomp_bk_dbg` (decomp-oracle.md 4.2).
3. **Breakpoints by name** (plan 4.1, 4.2, 6 D04/D05/D11): Ghidra's
   specifier cannot reach an action whose name occurs twice (R7;
   `blockstructure`, `prefercomplement`, `structuretransform`,
   `dynamicsymbols`, `deadcode`, …). D00 adds positional breakpoints.
4. **"Varnodes kept in the two orders of `VarnodeBank` … tested against
   Ghidra's dumps"** (plan 3.3; decomp-ir.md 4.2, 6.3): Ghidra's orders
   depend on heap addresses for `iop`, `fspec` and space-constant
   varnodes (ran, R5). The dump writes the orders with canonical keys
   (op time, call-spec position, space index); D05 reproduces those.
5. **Plan 4.1 / inventory 8: "drop `internal=`"** is not enough to make
   `print tree varnode` comparable: pointer constants and their order
   also vary (R5).
6. **"An x86-64 Linux container target"** (plan 6 D00, 7): obsolete; the
   build host builds the reference natively with the same script.
7. **Plan 9.1 item 1 / ADR-028**: eight `negateCondition` sites, not
   ten; and the open point is settled by reading — no rule reads back
   what a negation changed (decomp-cfg.md 4.1).
8. **Plan 9.1's facts "two-way branch, complexity, last-op kind"**: the
   facts needed are `complex`, `switch_out`, `ends_in_return` and
   `negation_changes_dataflow`; and the structurer must accept the
   analyses as given (labels, order, indices), because
   `ActionBlockStructure` does not recompute them and flips between
   `structureReset` and structuring could change a recomputed result.
9. **Inventory 8** says `structure blocks` runs `orderBlocks`; it does
   not (item 1). Inventory 11 listed it as not run; it now is.
10. **decomp-ir.md 6 item 1, "dumps … after `ActionStart`"**: there is no
    "break after"; it is `break start` at the following action
    (`constbase`, position 0002).
11. **Plan 6 D04 "exported with `bk dump state`"** for corpus graphs: the
    graph input is `bk dump blocks` at each actual structuring run, and
    one function can give several runs (the `mainloop` instance re-runs
    after every `structureReset`).

## Open items

From the documents' section 10:

- How often `orderBlocks` ties (two top-level blocks ending in `RETURN`)
  occur in the corpora (D04's capture reports it).
- Whether `TraceDAG::selectBadEdge`'s empty-list case is reachable
  (D04's random-graph table would show it).
- The default work limit of the structurer (benchmarks first).
- Whether the field lists of `JumpTable`, `LoadGuard`, `ParamTrial` in
  the dump suffice for D13, D10, D07 (amend to format v2 if not).
- Whether the hook patches for the optional logs are practical.
- Whether any pass iterates a varnode range over pointer-valued offsets
  in a way that reaches output (none seen in the data tests).
- The 17 `std::sort` sites marked "to be classified" in `sorts.md` are left
  for the tracks that port their modules to classify.

## Proposed ADRs

**ADR-042 (proposed as ADR-041, a number taken meanwhile) — The decompiler oracle is a console extension linked into
separate reference consoles; dumps name objects by reproducible keys.**
Basilisk's commands (`bk …`) are C++ under `tools/reference/consoleext/`,
compiled with `-fno-access-control` outside Ghidra's Makefile and linked
with the Makefile's own objects into `REF/bin/decomp_bk` and
`decomp_bk_dbg`; `bin/decomp` and `decomp_dbg` stay Ghidra's. Every dump
names varnodes by creation index, ops by sequence number, blocks by
index, call specs by position, and writes the three kinds of host
pointer Ghidra stores in varnode offsets (`iop`, `fspec`, `LOAD`/`STORE`
space constants) as canonical keys; the varnode bank orders are written
with those keys substituted, because Ghidra's own order among those
varnodes follows heap addresses and differs between runs. Every oracle
output is generated twice on each of the two reference builds; a
difference between builds is recognised by cause and counted (ADR-040's
form). Supersedes ADR-027's "one file added to the build's copy".

**ADR-028 amendment (3b, verified).** "Unverified: that no structuring
rule reads back a flag it flipped" becomes verified by reading: the
structurer reaches a basic block only through `isComplex`,
`negateCondition` and, from the `BlockSwitch` constructor,
`getJumptable`; none depends on what a negation changes. The structurer
takes four per-block facts and the graph's analyses as given, and
returns flip events, goto marks with causes, the change count and a
measure; the track that applies it toggles `boolean_flip`/`fallthru_true`
and swaps the edges of each block flipped an odd number of times.

## Defects found in Ghidra (for `docs/GHIDRA-BUGS.md`)

1. **Latent non-termination in `BlockGraph::structureLoops`**
   (block.cc:2212–2228 with `findSpanningTree`, block.cc:1058): when
   `findIrreducible` reports an irreducible *tree* edge it asks for a
   rebuild, but `findSpanningTree` clears `f_irreducible` at the start of
   every pass, so the same tree and the same edge come back forever.
   Confirmed by reading; by the same reading the branch is unreachable
   (a tree edge can never be reported). Basilisk bounds it.
2. **Possible empty-list dereference in `TraceDAG::selectBadEdge`**
   (blockaction.cc:749): `(*iter).exitproto` on `badedgelist.begin()`
   without a non-empty check. Read; not reproduced on 3,000 random graphs.
3. **`FlowBlock::compareFinalOrder` is not a strict weak ordering**
   (block.cc:718, used by `orderBlocks`, block.hh:448): index 0 compares
   less than itself, and two blocks ending in `RETURN` compare equal, so
   `std::sort` leaves their order to the C++ library (libc++ sorts short
   ranges with unstable networks). Read.
4. **`BlockCondition`'s opcode** (block.cc:1790, 3073, 3091, 3107;
   printc.cc:3001): created as `INT_OR`/`INT_AND`, toggled between
   `BOOL_AND` and `BOOL_OR`, printed by testing `== BOOL_AND` — correct
   only because `ruleBlockOr` always creates the `INT_OR` case; the
   encoded `opcode` attribute shows `INT_OR`. Read.
5. **Uninitialised edges on malformed block XML**
   (`FlowBlock::decodeNextInEdge`, block.cc:89–101): out-slots not named
   by any in-edge stay default-constructed with an indeterminate pointer;
   `structure blocks` on such a document is undefined behaviour. Read.
6. **Varnode bank order depends on heap addresses** (varnode.cc:39, 73):
   `iop`/`fspec` offsets and `LOAD`/`STORE` space constants are pointers;
   `print tree varnode` prints a different order in two runs of one
   binary (ran, R5: 43 of 93 data tests on the Mac). No effect on
   decompiled output was observed.
7. **Breakpoint specifiers cannot address duplicated action names**
   (`ActionGroup::getSubAction`, action.cc:456; `getSubRule`, 481, 777):
   ran (R7), `break start blockstructure` and `universal:blockstructure`
   both fail. A usability defect of the console.
8. **`ruleCaseFallthru`'s comment "Check exit block matches the 1
   nonfallthru exit"** (blockaction.cc:1761) has no code behind it. Read;
   behaviour as coded is what Basilisk ports.

## What the implementation tracks should be told beyond their documents

- **D00**: rebuild the build host's reference with the new script
  (`scripts/remote.sh setup`) and record both STAMPs; never write into
  either reference directory during experiments (build scratch copies in
  `target/`, as `docs/research/decomp-wave1/build_dbg.sh` does, keeping
  time stamps so `make` does not call bison); the host's `perl` prints
  locale warnings on standard error (set `LC_ALL=C`, keep standard error
  out of captures); start with `bk structure`/`bk cfg` and their formats,
  because D04 is waiting on them, then the state dump.
- **D04**: section 6.2 works with today's reference, before D00; the five
  reachable graphs that end in `Could not finish collapsing block
  structure` are in runs.md R3 (rebuild them from the generator with
  seed 1); `rand`/`rand_chacha` need the dependency-age check; port the
  list and edge-order mutations exactly (Vec with shifting deletion), the
  rules read edge positions.
- **D05**: take varnode and op ids and both bank orders from the dump;
  `CallSpecId` is the call spec's position in `qlst` at dump time, the
  `iop` offset the op's time; "after `ActionStart`" means `bk break start`
  at `constbase`.
- **D15**: apply flips by parity; `finalizePrinting` runs between
  `orderBlocks` and `scopeBreak` and decides the switch case order that
  `markUnstructured` depends on; D04's `finish` takes the case labels as
  input.
- **D07/D11**: actions with duplicated names are addressed by position
  (D00's `bk list actions` gives the paths).

## Commits

See `git log --oneline master..spec-decomp-wave1`; at the time of
writing:

```
docs(decomp-cfg,decomp-oracle): libc++ small-sort caveat; why not Ghidra's encode
docs(decomp-oracle,decomp-cfg): link lines, xml output of bk structure, asgiven inputs
docs(decomp-oracle): D00 specification, first complete draft; align D04 corpus capture with positional breakpoints
docs(spec-decomp-wave1): runs R8-R9 (decomp_dbg, trace)
docs(spec-decomp-wave1): keep generated parsers newer in the dbg build
docs(spec-decomp-wave1): decomp_dbg build experiment script
docs(spec-decomp-wave1): breakpoint run R7, sort and container inventory
docs(spec-decomp-wave1): determinism runs R5-R6
docs(spec-decomp-wave1): ignore perl locale noise in capture hash
docs(spec-decomp-wave1): drop path lines from capture hash
docs(spec-decomp-wave1): pointer-free hash of captures
docs(spec-decomp-wave1): data-test capture scripts
docs(decomp-cfg): D04 specification, first complete draft
docs(spec-decomp-wave1): research notes and graph generator
```
