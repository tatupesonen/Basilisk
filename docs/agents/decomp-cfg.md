# Track `decomp-cfg` — status report

D04 of `docs/features/decomp-plan.md`: crate `bk-decomp-cfg` (block graph,
analyses, structured hierarchy, structurer). Contract:
`docs/features/decomp-cfg.md`. Status: **done except the parts that wait
for D00** (listed under Gaps); the coordinator resumes the track when D00
is merged.

## State (kept current; continue from here)

- [x] Every "In" item of spec 3; the structurer, `finish`, codec, printing.
- [x] 6.2 `structure blocks` cross-check: 4,000 generated graphs, all equal,
      tables from the Mac and the build host byte-identical.
- [x] 6.1 unit tests, 6.5 properties, 6.6 fuzz targets, 6.7 benchmarks,
      `docs/PERF.md`, spec sections 8–10 appended.
- [x] 6.3/6.4 oracle tests written against D00's formats; they skip until
      `decomp_bk` and the table exist.
- [x] Testbed checks and both gates (results under Verification).
- [ ] **When D00 lands** (coordinator's message, or `bin/decomp_bk` in the
      reference directories and D00 on `master`): `git merge master`;
      replace `tests/support/dump.rs` and the console runner in
      `tests/oracle_bk.rs` by `bk-testkit`'s readers, writers and
      `decomp_bk` runner (and adjust to D00's exact field spellings — e.g.
      whether flags and labels carry `0x`); run
      `crates/bk-decomp-cfg/tests/oracle/regen.sh /path/to/reference` on the
      Mac and `scripts/remote.sh run -- crates/bk-decomp-cfg/tests/oracle/regen.sh "" "$BK_OUT/cfg_oracle.host.txt.gz"`
      on the build host (fetch with `scripts/remote.sh log`); compare the
      two tables, add a host-difference classification (ADR-040 form,
      expected cause: `orderBlocks` RETURN ties, 25 candidate rows of 17+
      top-level nodes for libstdc++, 119 of 4+ for libc++) if they differ;
      replay; then the corpus captures of 6.3.2 with D00's capture driver
      and the `R` record comparison of 6.4; confirm `CaseDetached` (below).

## Built

Crate `crates/bk-decomp-cfg` (about 5,000 lines of source, every file
under 600 lines), dependencies `bk-marshal` and `thiserror` only (the
condition opcode is a four-valued enum of the crate, printing Ghidra's
names, so no `bk-pcode`).

| Module | Ghidra | What |
|---|---|---|
| `graph/{mod,surgery,ops}` | `BlockEdge`, `FlowBlock` edge methods, `BlockGraph` edits | arena of nodes (`NodeId(u32)`, never freed), ordered edge lists with Ghidra's shifting deletion, every edge-surgery and edit method |
| `analysis/{spanning,dominators}` | `findSpanningTree`, `findIrreducible`, `calcLoop`, `structureLoops`, `calcForwardDominator`, `buildDom*`, `collectReachable`, `findCommonBlock`, `findCondition`, `dominates`, `restrictedByConditional` | iterative, bounded |
| `hierarchy/{identify,factories,negate,query,switch}` | `addBlock`, `selfIdentify`, `identifyInternal`, `forceOutputNum`, `forceFalseEdge`, the 14 factories, `negateCondition`, `getFrontLeaf`/`getExitLeaf`/`lastOp`/`isComplex`/`nextFlowAfter`/`gotoPrints`, `CaseOrder`, `addCase`, `grabCaseBasic`, the `finalizePrinting` sort | |
| `structure/{collapse,rules,switch_rules}` | `CollapseStructure::collapseAll/collapseInternal/collapseConditions` and every rule | |
| `gotos/{loopbody,tracedag,selector}` | `FloatingEdge`, `LoopBody`, `TraceDAG`, `labelLoops`, `orderLoopBodies`, `updateLoopBody`, `selectGoto`, `clipExtraRoots` | the replaceable unit |
| `finish` | `orderBlocks`, `scopeBreak`, `markUnstructured`, `markLabelBumpUp` (all kinds) | explicit stacks |
| `codec/{xml,tree}` | block XML encode/decode, `BlockMap`, `printTree`/`printHeader` | |
| `limits`, `error`, `facts`, `flags`, `cfg` | | |

Public API (ADR-025 3b):

- `Cfg` — the graph as a value: `add_node`, `add_edge`, `add_edge_at`,
  `remove_edge`, `switch_edge`, `move_out_edge`, `remove_node`,
  `remove_from_flow`, `remove_from_flow_split`, `splice_node`, `set_start`,
  `start`, `set_goto_branch`, `set_default_switch`, `swap_out_edges`, edge
  labels, index/idom/numdesc/flags accessors, `structure_loops`,
  `forward_dominators`, `dom_tree`, `dom_depth`, `dom_sub_tree`,
  `reachable`, `unreachable`, `dominates`, `restricted_by_conditional`,
  `find_common_block(_set)`, `find_condition`, `is_jump_target`,
  `has_loop_in/out`, `in_index`, `out_index`, `clear_edge_labels`,
  `order_by_final`, `decode_xml`, `encode`.
- `BlockFacts`/`Fact` — `complex`, `switch_out`, `ends_in_return`,
  `negation_changes_dataflow`; `BlockFacts::neutral(n)`.
- `structure(&Cfg, &BlockFacts, &StructureOptions, &mut dyn GotoSelector)
  -> Result<Structured, CfgError>`; `StructureOptions { analyse: AsGiven |
  Recompute, limits, record: None | Trace }`; `Structured { hierarchy,
  flips, goto_edges (GotoMark with cause Selected/ClippedRoot/SwitchSkip/
  CaseFallthru, in the oracle's order), dataflow_changes, measure, trace }`.
- `GotoSelector` trait (`start`, `select`) with `CollapseView`;
  `GhidraGotoSelector` is Ghidra's. Unit name `UNIT_SELECTGOTO`
  (`selectgoto`), rule names `RULE_*` (`blockgoto` … `casefallthru`).
- `finish(&mut Hierarchy, &BlockFacts, Option<&dyn CaseLabels>) ->
  FinishMeasure { printed_gotos, breaks }`.
- `Hierarchy` accessors: kind, components, parent, index, flags, depth,
  leaf count, edges (`EdgeView` with the label tests), goto target/type,
  multigoto targets, condition opcode, overflow, cases, exit/front leaf,
  split point, `next_flow_after`, `goto_prints`, unstructured target, label
  bump-up, `is_complex`, `swap_components`, `negate_condition`,
  `print_tree`, `header`, `encode`.
- `loop_bodies(&Cfg, …) -> Vec<LoopInfo>` (what `bk cfg analyze` lists).
- `CfgError` (Ghidra's messages; plus `LimitExceeded`, `SpanningTreeRebuild`,
  `NoBadEdge`, `TraceCycle`, `BadEdgeSlots`, `BadDocument`, `Decode`,
  `BadIndex`, `NoSuchNode`, `Internal`), `Limits`.

Plugin binding constraints (spec 5.5): `Structured`, `Hierarchy`, `Cfg`,
`CfgError` are owned, `Send + Sync + 'static` and work behind an `Arc`
(test `api::plugin_binding_constraints`); the only generic in the API is
the `&mut dyn GotoSelector` trait object.

## Tests

104 tests run in the gate (rstest cases counted), 7 ignored (regeneration
and benchmarks):

| Kind | File | Count |
|---|---|---:|
| Unit (internal): surgery, identification and factory edge order, `forceOutputNum`, `forceFalseEdge`, opcode sequence `INT_OR → BOOL_AND → BOOL_OR`, negation, sizes | `src/hierarchy/tests.rs` | 16 |
| Unit: every rule positive and negative, flips and change count, overflow, goto/if-goto/multigoto, `checkSwitchSkips` and `ruleCaseFallthru` reporting applied with only goto marks, selected gotos, the five reachable seed-1 graphs ending in `Could not finish collapsing block structure`, the endless-trace graph, input untouched, as-given = recompute | `tests/rules.rs` | 34 |
| API: edits and their errors, analyses, dominators, reachability, queries, every Ghidra message, limits, XML round trip and every decode error, encoding, `orderBlocks`, `finish`, `print tree`, plugin constraints | `tests/api.rs` | 47 |
| Differential S (6.2): 4,000 graphs replayed against `structure blocks` | `tests/structure_blocks.rs` | 1 (+ `regen`, L) |
| Oracle S (6.3/6.4, waits for D00), dump determinism, RETURN-tie counts | `tests/oracle_bk.rs` | 3 (+ `regen`, L) |
| Properties (6.5): repeatability, input untouched, every leaf once, parents, edge halves, isolated top level, goto count = marks, finish, loop edges cut every cycle, as-given = recompute, no rebuild, no `NoBadEdge`, dominators = naive on function-like graphs, graphs of up to 1,000 nodes within the default limit | `tests/properties.rs` | 3 (256 / 24 cases; 3,000 cases run clean) |
| Benchmarks (6.7) | `tests/bench.rs` | 4 ignored |
| Fuzz (6.6) | `fuzz/fuzz_targets/bk_decomp_cfg_{structure,xml}.rs` | 2 targets |

Ghidra has no unit test for blocks (spec 6); no line of
`docs/inventory/tests/` applies (the `BlockGraph*Test` classes there are
Java program-graph tests).

## Cross-check and oracle results

- **`structure blocks` (6.2)**: 4,000 graphs (1,000 per class: function-like,
  arbitrary, reducible, irreducible; up to 40 nodes) — 3,894 structured,
  105 `Could not finish collapsing block structure`, 1 on which the
  reference never finishes (`hang` row; Basilisk: `TraceCycle`). Basilisk
  equals the reference on all 4,000, byte for byte, errors included. The
  table was generated twice on the Mac (libc++) and twice on the build host
  (libstdc++): all four byte-identical. Earlier scratch run of
  `gen_graphs.py 1 3000 40`: 3,000 of 3,000 equal, the 161 errors included.
- **`bk cfg` / `bk structure` (6.3.1), corpus graphs (6.3.2), trace (6.4)**:
  not run — D00's `decomp_bk` does not exist yet. The tests and both
  regeneration scripts are in place.

## Benchmarks

`docs/PERF.md`, `bk-decomp-cfg`: analyses 0.35 ms / 32 ms / 4.3 s for
10³/10⁴/10⁵-node function-like graphs (the growth is Ghidra's
`findIrreducible`); structuring 0.27 ms (616-node reducible), 21 ms
(7,177-node reducible), 22 ms (1,000-node function-like with 768 gotos);
the reference console takes 51 ms and 23 ms on the last two (including its
XML I/O). 160 bytes per node, 24 per edge. Command:
`cargo test -p bk-decomp-cfg --release --test bench -- --ignored --nocapture --test-threads=1`.

## Differences from Ghidra

All in spec section 8 (original list plus the appended ones): facts in,
flips out; stable `orderBlocks`; the bounded spanning-tree rebuild; the
empty bad-edge list as an error; rejected malformed documents; `Limits`
and no recursion; **`TraceCycle`** for Ghidra's endless `pushBranches`;
debug-build checks only at the public API; errors instead of null
dereferences on hostile input; the measured step-limit default; hashed
oracle table.

## Gaps

- Everything that needs D00's `decomp_bk`: the 6.3.1 table and its replay
  (acceptance 2, second half, 4 and 6 for `bk structure`), the corpus
  captures and comparisons of 6.3.2 (acceptance 3), the `R`-record trace
  comparison of 6.4, the corpus benchmark (largest corpus function) and the
  corpus count of `orderBlocks` RETURN ties (open item 1).
- Not confirmed against Ghidra: `Case block has become detached from
  switch` on graphs with an input default-switch label (generated arbitrary
  and reducible graphs with facts). The trigger cannot be expressed in
  block XML; by reading, Ghidra raises the same (a multigoto collects a
  goto to itself through the self-edge `forceOutputNum` adds, and
  `addCase` finds no edge from the switch block to its own original). The
  6.3.1 table will settle it.
- Test helpers for D00's formats are local (`tests/support/dump.rs`) and
  written from the spec text; the field spellings will follow D00's
  `bk-testkit` when it lands.

## Follow-ups

**Ghidra defects** (for `docs/GHIDRA-BUGS.md`):

1. **`TraceDAG::pushBranches` never ends when the loop-DAG view has a
   cycle** (`blockaction.cc:983–1014`, with `openBranch` 839 and
   `retireBranch` 900; every turn allocates a `BranchPoint` that is kept in
   `branchlist`). Confirmed: the generated function-like graph `func` seed
   530 of `tests/support/graphgen.rs` (25 nodes, built by the test
   `rules::endless_trace_is_an_error`; its XML is the `hang` row of
   `structure_blocks.txt.gz`) made the reference console run at full CPU
   with growing memory until killed (60 s, then 10 s in the regeneration);
   Basilisk's port reproduces the loop exactly (one trace alternately opens
   and retires a branch point on a two-node cycle, nodes 15 and a list
   holding 5 … 19, both edges labelled tree). Mechanism, read: the graph has
   irreducible edges; `FlowBlock::eliminateInDups` (block.cc:450–476) ORs a
   merged edge's label into the kept in-half only (and `eliminateOutDups`
   into the out-half only), `ruleBlockCat` tests the out-half
   (`isDecisionOut`), so a list can absorb what was a back edge (9→19) and
   leave a cycle without a back, loop-exit, goto or irreducible label. What
   Basilisk does: `CfgError::TraceCycle` once a trace opens more than
   `2·nodes + 8` branch points (at most `nodes` in an acyclic view). 1 of
   4,000 generated graphs.
2. **The dedup label asymmetry itself** (block.cc:463, 492): the two halves
   of a merged edge can carry different labels, and different rules read
   different halves (`isDecisionOut` vs `isLoopDAGIn`). Reproduced as is
   (the rules depend on it).
3. Entries 24 and 25 of `docs/GHIDRA-BUGS.md`: 24 (rebuild loop) — kept
   bounded, never reached in any run; **25 (empty `selectBadEdge` list)
   is unreachable by reading** (proof in spec section 10, item 4), so it
   can be reclassified as "not a defect" or "defensive check missing".
4. The virtual root of `calcForwardDominator` keeps index 0
   (`FlowBlock::FlowBlock`, block.cc:65), so with several roots the finger
   arithmetic (block.cc:2022–2028) treats it as list position 0: an
   intersection that should reach the virtual root yields the first node
   instead. Read; reproduced as is (no effect on the single-root graphs of
   the pipeline's functions).

**Other**:

- `Limits::max_steps` default changed from the spec's guess to
  `2·(n+e)² + 10⁶` after measuring (spec 10 item 5); revisit with corpus
  numbers when D00's captures exist.
- `rand` 0.8.8 and `rand_chacha` 0.3.1 were added as workspace
  dev-dependencies. ADR-011: they are the industry-standard seeded RNG
  crates (the spec named them), both already in `Cargo.lock` through
  `proptest`, so the lock file gains no package (`check-dep-age.py master`:
  0 new registry packages). `wait-timeout` (already in the workspace) is a
  dev-dependency for the `decomp_bk` runner.
- When D00 delivers its `bk-testkit` formats, `tests/support/dump.rs` and
  the runner in `tests/oracle_bk.rs` are to be replaced (see State).
- Nothing was needed from `bk-core`, `bk-marshal` or `bk-pcode` beyond what
  exists; the block XML ids (`altindex` 75 … `edge` 105) are defined in this
  crate (`codec::xml`), as other crates do for theirs.

## Verification

- Mac: development builds and tests; `cargo clippy -p bk-decomp-cfg
  --all-targets --target x86_64-pc-windows-msvc -- -D warnings` clean;
  `cargo metadata --manifest-path fuzz/Cargo.toml` clean;
  `scripts/check-dep-age.py master`: 0 new packages; the `structure blocks`
  table (libc++).
- Build host: the `structure blocks` table (libstdc++), benchmarks, and:
  - `scripts/remote.sh long fuzz 300 bk_decomp_cfg_structure bk_decomp_cfg_xml`:
    0 findings (120,332 and 10,900,372 executions);
  - `scripts/remote.sh wine -- -p bk-decomp-cfg`: 104 passed, 0 failed,
    6 ignored;
  - `scripts/remote.sh arm64 -- -p bk-decomp-cfg`: 104 passed, 0 failed,
    6 ignored, 0 skipped;
  - `scripts/remote.sh gate; echo $?` → `0` (tests: 2349 passed, 0 failed);
  - `scripts/remote.sh gate --no-ref; echo $?` → `0` (tests: 2349 passed,
    0 failed).

## Commits

See `git log --oneline master..decomp-cfg`.
