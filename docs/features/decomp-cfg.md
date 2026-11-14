# Block graph and control-flow structuring (`bk-decomp-cfg`)

Track `decomp-cfg` (D04 of `docs/features/decomp-plan.md`), milestone M3,
wave 1. Format of this document: `docs/LOOP.md`, "Feature documents".
Leaf track: no other decompiler crate is needed. Its oracle commands and
file formats are delivered by D00 (`docs/features/decomp-oracle.md`,
sections 4.6 and 4.7); until D00 is merged the tests of section 6.3 run
against the reference console's own `structure blocks` (section 6.2).

Path abbreviations: `CPP/` = `Ghidra/Features/Decompiler/src/decompile/cpp/`,
`DT/` = `…/decompile/datatests/`, under `../ghidra` (commit `42db038f3c`);
`REF/` = `../reference/`. Line numbers are for that commit. **(read)**
marks a statement taken from reading the source, **(ran)** one checked
by running the reference build; the commands are in
`docs/research/decomp-wave1/runs.md` (R1–R4).

## 1. Purpose

The control-flow graph of a function as a value, the analyses Ghidra
runs on it (spanning tree, reverse post-order, back, cross, forward and
irreducible edges, loop edges, dominators), and Ghidra's structurer: the
algorithm that collapses the graph into a hierarchy of `if`, `else`,
loops, `switch`, `goto`, `break` — `CollapseStructure` with `LoopBody`
and `TraceDAG`. It is ADR-025 property 3b: the structurer is a pure
function of a graph, per-block facts and options, returning a hierarchy,
the edits it wants made to the basic blocks, and a measure. Nothing here
touches p-code; D05 attaches ops to the nodes, D15 applies the results.

## 2. Ghidra sources

| Source | What to take |
|---|---|
| `CPP/block.hh`, `CPP/block.cc` | `BlockEdge`, `FlowBlock`, `BlockGraph` and every structured kind (`BlockCopy`, `BlockGoto`, `BlockMultiGoto`, `BlockList`, `BlockCondition`, `BlockIf`, `BlockIfElse`, `BlockIfNoExit`, `BlockIfGoto`, `BlockWhileDo`, `BlockDoWhile`, `BlockInfLoop`, `BlockSwitch`), `BlockMap` — the graph-only methods listed in section 3. **Authoritative** |
| `CPP/blockaction.hh`, `CPP/blockaction.cc` lines 20–1904 | `FloatingEdge`, `LoopBody`, `TraceDAG`, `CollapseStructure`. **Authoritative** |
| `CPP/blockaction.cc` 2178–2212 | `ActionBlockStructure::apply`, `ActionFinalStructure::apply`: the order in which the pipeline calls this crate's functions (the actions themselves are D15's) |
| `CPP/funcdata_block.cc` 723–750 | `Funcdata::structureReset`: when the pipeline computes the analyses (D07/D15 call this crate) |
| `CPP/ifacedecomp.cc` 3219–3269 | `IfcStructureBlocks` (`structure blocks <in> <out>`): the reference's own command for structuring a bare graph |
| `CPP/ghidra_process.cc` 340–359 | `StructureGraph::rawAction`: the same for the Java side, plus `orderBlocks` |
| `CPP/printc.cc` 2380–2400, 2990–3010, 3360–3380 | Only to see what the printer reads from the hierarchy (goto type, condition opcode, `isUnstructuredTarget`, `isLabelBumpUp`); printing is D16's |

There is a Java twin of the hierarchy's data model
(`ghidra.program.model.pcode.BlockGraph` and friends) used to read the
encoded result; it has no algorithms and is not ported here.

## 3. Scope

Every method of the classes above was read and is classified here. "Pure"
means it reads and writes only the graph, the hierarchy and the per-block
facts of section 4.1.

**In (crate `bk-decomp-cfg`):**

1. *The graph.* `BlockEdge`; `FlowBlock`'s fields (`parent`, `immed_dom`,
   `copymap` as a working map, `intothis`, `outofthis`, `flags`, `index`,
   `visitcount` as working state, `numdesc`, `leafCount`,
   `structureDepth`) and its edge surgery: `addInEdge`, `halfDeleteInEdge`,
   `halfDeleteOutEdge`, `removeInEdge`, `removeOutEdge`, `replaceInEdge`,
   `replaceOutEdge`, `replaceEdgesThru`, `swapEdges`, `setOutEdgeFlag`,
   `clearOutEdgeFlag`, `eliminateInDups`, `eliminateOutDups`, `findDups`,
   `dedup`, `replaceUsingMap`, `checkEdges` (as a debug invariant); the
   queries `getIn/Out*`, `size*`, `is*In/Out`, `isDecision*`,
   `isLoopDAG*`, `isGoto*`, `getInIndex`, `getOutIndex`, `hasLoopIn`,
   `hasLoopOut`, `isJumpTarget`, `getFrontLeaf`, `calcDepth`, `dominates`,
   `restrictedByConditional`, `getFalseOut`, `getTrueOut`; the static
   `compareBlockIndex`, `compareFinalOrder` (with the facts),
   `findCommonBlock` (both forms), `findCondition`, `typeToName`,
   `nameToType`; `setGotoBranch`, `setDefaultSwitch`, the flag accessors.
2. *Graph algorithms* of `BlockGraph`: `addEdge`, `addLoopEdge`,
   `removeEdge`, `switchEdge`, `moveOutEdge`, `removeBlock`,
   `removeFromFlow`, `removeFromFlowSplit`, `spliceBlock`,
   `setStartBlock`, `getStartBlock`, `newBlock`, the node-creation half of
   `newBlockBasic`, `clearVisitCount`, `clearEdgeFlags`,
   `createVirtualRoot`, `findSpanningTree`, `findIrreducible`, `calcLoop`,
   `structureLoops`, `calcForwardDominator`, `buildDomTree`,
   `buildDomDepth`, `buildDomSubTree`, `collectReachable`, `buildCopy`,
   `orderBlocks`. These are what the IR passes (D05, D07, D09–D12) call on
   the basic-block graph; they are pure.
3. *The hierarchy*: `addBlock`, `forceOutputNum`, `selfIdentify`,
   `identifyInternal`, `forceFalseEdge`, `swapBlocks`, `markCopyBlock`,
   the fourteen `newBlock*` factories for structured kinds, and per kind
   `getType`, `subBlock`, `getExitLeaf`, `negateCondition` (the graph
   half: see 4.5), `getSplitPoint`, `isComplex` (delegation), `nextFlowAfter`,
   `markUnstructured`, `markLabelBumpUp`, `scopeBreak`, `gotoPrints`,
   `printHeader`, `printTree`, the `BlockSwitch` case bookkeeping
   (`addCase`, `grabCaseBasic`, `CaseOrder::compare`, and the sorting part
   of `finalizePrinting` with case labels as input), `BlockCondition`'s
   opcode, `BlockWhileDo`'s overflow flag.
4. *The structurer*: all of `FloatingEdge`, `LoopBody`, `TraceDAG`,
   `CollapseStructure` (blockaction.cc 20–1904).
5. *Encoding*: `BlockEdge::encode/decode`, `FlowBlock::encode/decode`,
   `encodeHeader/decodeHeader`, `encodeEdges/decodeEdges`,
   `decodeNextInEdge`, `BlockGraph::encodeBody/decodeBody/decode`, the
   `encodeBody` of `BlockGoto`, `BlockMultiGoto`, `BlockIfGoto`, the
   `encodeHeader` of `BlockCopy` and `BlockCondition`, `BlockMap` — the
   XML that `structure blocks` reads and writes and that `Funcdata::encode`
   embeds (through `bk-marshal`).

**Out, with the reason:**

| Ghidra | Why not here | Where |
|---|---|---|
| `BlockBasic` (op list, `insert`, `setOrder`, `removeOp`, ranges, `getStart/Stop`, `firstOp`, `lastOp`, `isComplex`'s body, `negateCondition`'s op half, `flipInPlaceTest/Execute`, `unblockedMulti`, `hasNoImmediateCopy`, `hasOnlyMarkers`, `isDoNothing`, `noInterveningStatement`, `findMultiequal`, `earliestUse`, `liftVerifyUnroll`, `printRaw`, `encodeBody`, `decodeBody`) | Reads or edits ops and varnodes | D05 (op list, ranges, printing) and D05/D15 (the facts and edits of 4.1, 4.5) |
| `FlowBlock::nextInFlow`, `getHaltType`, `getJumptable`, `printRaw`, `printRawImpliedGoto`, `emit`, `firstOp`, `lastOp` | Read ops (`CBRANCH` fall-through, halt type), the function's jump tables, or print ops | D05, D15, D16 |
| `preferComplement` (`BlockIfElse`, `BlockIfNoExit`), `BlockCondition::flipInPlaceTest/Execute`, `finalTransform` (all kinds), `BlockWhileDo::findLoopVariable`, `findInitializer`, `testTerminal`, `testIterateForm`, `finalizePrinting`, `BlockSwitch::getSwitchType`, `getNumLabels`, `getLabel`, `getDisplayFormat` | Op-level edits and for-loop recovery, jump-table labels, types | D15 (the hierarchy accessors they need are here) |
| `ConditionalJoin` and every `Action` of `blockaction.cc` (`ActionStructureTransform`, `ActionNormalizeBranches`, `ActionPreferComplement`, `ActionBlockStructure`, `ActionFinalStructure`, `ActionReturnSplit`, `ActionNodeJoin`) | Actions on `Funcdata`; they call this crate | D15 (and D12 for `ActionNormalizeBranches`, `ActionNodeJoin`, `ActionReturnSplit` as the plan places them) |
| `BlockGraph::printRaw`, `emit` | Print ops | D05, D16 |
| `BLOCKCONSISTENT_DEBUG` (`isConsistent`, `checkEdges`) | Debug-build checks | Ported as debug assertions and as property tests (6.5) |

**Crate owned:** `bk-decomp-cfg`. Dependencies: `bk-core` (nothing more
than error helpers if wanted), `bk-marshal` (encoding), `bk-pcode` (only
for the `OpCode` names `BlockCondition` stores: `INT_OR`, `BOOL_AND`,
`BOOL_OR`; a three-valued enum of this crate is acceptable instead,
printing Ghidra's names). No dependency on `bk-decomp-ir` or any later
crate; D05 depends on this one.

## 4. Behaviour

Port the methods of section 3 exactly. Everything below is where a port
goes wrong; each point is pinned by the oracle of section 6.

### 4.1 The graph and the per-block facts

A graph is a list of nodes (Ghidra's `BlockGraph::list`, **in order** —
the order is behaviour, see 4.9) and, per node, an ordered list of
in-edges and an ordered list of out-edges. An edge is (label word, other
end, reverse index); both halves of one edge carry the same label
(`setOutEdgeFlag`, block.cc:263, sets both). Multi-edges and self-loops
are allowed. For a node with two out-edges, out-edge 0 is the **false**
branch and 1 the **true** branch (block.hh:129–134).

* **Node flags** (block.hh:91–111): keep every bit with Ghidra's value;
  dumps print the word in hex. Structuring reads `f_switch_out`,
  `f_interior_gotoin`, `f_interior_gotoout`, `f_entry_point` (copied, not
  read), `f_whiledo_overflow`, `f_mark`, `f_mark2`; writes
  `f_interior_goto*`, `f_unstructured_targ`, `f_label_bumpup`,
  `f_flip_path`.
* **Edge labels** (block.hh:113–124): `f_goto_edge` 1, `f_loop_edge` 2,
  `f_defaultswitch_edge` 4, `f_irreducible` 8, `f_tree_edge` 0x10,
  `f_forward_edge` 0x20, `f_cross_edge` 0x40, `f_back_edge` 0x80,
  `f_loop_exit_edge` 0x100, `f_immed_copy` 0x200. Derived tests
  (block.hh:348–359): *decision* = none of irreducible, back, goto;
  *loop-DAG* = none of irreducible, back, loop-exit, goto; *goto* = any of
  irreducible, goto.
* **Per-block facts** — what Ghidra's structurer obtains from a basic
  block through virtual calls, given as input (plan 9.1, ADR-028):

  | Fact | Ghidra's source in the pipeline | Neutral value (`structure blocks` on a bare graph) |
  |---|---|---|
  | `complex` | `BlockBasic::isComplex` (block.cc:2417): counts statements from ops, readers, `max_implied_ref` | `true` (`FlowBlock::isComplex`, block.hh:259) |
  | `switch_out` | the `f_switch_out` flag the flow pass sets on a block ending in `BRANCHIND` | `false`; `newBlockCopy` still sets it for a node with more than two out-edges (block.cc:1697) |
  | `ends_in_return` | `lastOp()->code() == CPUI_RETURN`, read only by `compareFinalOrder` (block.cc:718) | `false` (`FlowBlock::lastOp` is null) |
  | `negation_changes_dataflow` | `BlockBasic::negateCondition` returns `true` (block.cc:2369); `FlowBlock`'s returns `false` (block.cc:298) | `false` |

  **Verified (read), settling ADR-028's open point**: no rule of
  `CollapseStructure` reads back anything a negation changed on the
  original block. The only calls from `blockaction.cc` 20–1904 and the
  `newBlock*` factories into a basic block are `isComplex` (through
  `BlockCopy::isComplex`, which depends on ops and readers only, not on
  `boolean_flip`, `fallthru_true` or edge order), `negateCondition`
  (through `BlockCopy::negateCondition`, block.hh:557), and
  `getJumptable` from the `BlockSwitch` constructor (block.cc:3608),
  which stores a pointer used only by printing. The structurer reads its
  own copy's edges, which `BlockCopy::negateCondition` swaps itself. So
  "facts in, flips out" gives Ghidra's result exactly.
* **Edge input labels.** Besides the analysis labels of 4.2, the
  pipeline's basic-block graph can carry `f_goto_edge` (from
  `Funcdata::forceGoto`, funcdata_block.cc:760, driven by `override.cc:225`)
  with `f_interior_gotoout`/`gotoin` on its ends, and
  `f_defaultswitch_edge` (from `Funcdata::installSwitchDefaults`, called
  by `ActionBlockStructure` just before copying, blockaction.cc:2185).
  These enter as labels of the input graph.

### 4.2 Analyses: spanning tree, irreducible edges, loops, dominators

`structureLoops(rootlist)` (block.cc:2212) repeats `findSpanningTree` +
`findIrreducible` while the latter asks for a rebuild, then runs
`calcLoop` if any irreducible edge was found.

* **`findSpanningTree`** (block.cc:1022), iterative DFS: every node gets
  `index = -1`, `visitcount = -1`, `copymap = self`; roots = nodes with no
  in-edges, in list order, then the **last root is swapped with the
  first** (so the original head is visited last and is first in reverse
  post-order); with no root, `list[0]` is the root. For each pass (at most
  two): clear the labels irreducible, tree, forward, cross, back, loop,
  loop-exit on every edge (block.cc:1058); visit roots in `rootlist` order,
  dropping a root already visited; when no root is left but nodes remain,
  take the first unvisited node in list order as an extra root. Children
  are tried in out-edge order; an irreducible out-edge is skipped (only
  relevant within one pass, since the pass cleared them). Edge kinds:
  tree (child unvisited), back + loop (child on the stack: `index == -1`),
  forward (child finished and `visitcount` larger), cross (otherwise).
  `numdesc` counts the subtree. `index` is the reverse post-order number.
  If extra roots were needed, the entry block is moved to the end of the
  root list and the pass repeats once; extra roots on the second pass
  throw `Could not generate spanning tree`. Finally the head is moved to
  the front of `rootlist` and **`list` is replaced by the reverse
  post-order** — the node order changes.
* **`findIrreducible`** (block.cc:1160): Tarjan's reducibility test over
  the pre-order in reverse, using `copymap` as the union-find `FIND` and
  `f_mark` for reach-under membership. A predecessor whose `FIND` is not a
  descendant of `x` (`x.visitcount > y'.visitcount` or `x.visitcount +
  x.numdesc <= y'.visitcount`) makes the edge **irreducible**
  (`irreduciblecount += 1`); if it is a tree edge a rebuild is requested,
  otherwise its cross/forward label is cleared. Reach-under nodes then get
  `copymap = x`.
* **Unreachable path, and what Basilisk does.** A tree edge can never be
  reported (the tree parent of a reach-under node is a descendant of `x`
  or collapsed into a descendant of `x`; read), so the rebuild branch
  never runs on any input. If it did, it would not terminate:
  `findSpanningTree` clears `f_irreducible` at the start of every pass
  (block.cc:1058), so the rebuilt tree is the same tree and the same edge
  is found again. Basilisk keeps the branch, bounds it at one rebuild, and
  returns `CfgError::SpanningTreeRebuild` beyond that (ADR-009); the
  property test of 6.5 asserts it never happens. Listed for
  `docs/GHIDRA-BUGS.md` as a latent non-termination.
* **`calcLoop`** (block.cc:2122): DFS from `list[0]` skipping loop edges;
  an edge to a node on the current path gets `f_loop_edge` (`addLoopEdge`)
  — after irreducible edges are excluded, this guarantees the loop edges
  cut every cycle.
* **`calcForwardDominator(rootlist)`** (block.cc:1972): Cooper–Harvey–
  Kennedy over the post-order implied by `index` (requires
  `findSpanningTree` to have run). With more than one root a temporary
  virtual root with edges to every root is appended; if the official
  start node has in-edges (only legal when it is the single root) a
  virtual root is created too, else `Problems finding root node of graph`.
  The first processed predecessor is the one with a non-null `immed_dom`
  in in-edge order. At the end links to the virtual root become null, its
  edges are removed (so no edge of a real node changes) and the root's
  `immed_dom` is null.
* `buildDomTree`, `buildDomDepth` (depth 1 for a node without dominator;
  entry `list.size()` holds 0), `buildDomSubTree` (relies on the
  dominator-tree order of `list`), `collectReachable`: as written.

**When the analyses run** (plan 9.1, reading `funcdata_block.cc`):
`Funcdata::structureReset` runs `structureLoops` and
`calcForwardDominator` on the basic-block graph every time the blocks
change; `ActionBlockStructure` then copies that graph **with its labels,
order, indices and dominators as they are** (`buildCopy`,
blockaction.cc:2186) and does not re-run them. Between the two, block
edges can be swapped without a reset (`ActionNormalizeBranches` and
`ActionPreferComplement` flip conditions), so recomputing the analyses at
structuring time could give a different reverse post-order. The API
therefore separates "analyse" from "structure" (section 5.2): the
pipeline passes the graph as it is; the bare-graph mode (as `structure
blocks`, which runs `structureLoops` and `calcForwardDominator` on the
copy, ifacedecomp.cc:3247–3249) analyses first.

### 4.3 The copy

`buildCopy` (block.cc:1943) makes one `BlockCopy` per node in list order
with `newBlockCopy` (block.cc:1686): edges (with labels), `immed_dom`,
`index`, `numdesc` and **all flags** are copied; `visitcount` starts at
0; a node with more than two out-edges gets `f_switch_out`. Edge ends are
then remapped to the copies. In Basilisk the structurer builds its own
working graph from the borrowed input, so the input is untouched by
construction.

### 4.4 Collapsing into structured nodes

All structured kinds are made by `identifyInternal(new, nodes)`
(block.cc:953) followed by kind-specific fix-ups. Port this exactly; the
**edge order it produces decides which edge is "false" later**:

1. For each node of `nodes` in order: it must be in the current graph
   (else `Bad block identify`); it is marked, appended to the new node's
   list (`addBlock`: the new node's `index` is the minimum of its
   components' indices, `leafCount` the sum, `structureDepth` one more
   than the deepest component, block.cc:871), and its
   `f_interior_gotoout | f_interior_gotoin` are OR-ed into the new node.
2. The graph's list keeps the unmarked nodes in order; the **new node is
   appended at the end** (by the caller's `addBlock`).
3. `selfIdentify` (block.cc:908): for each component in order, each
   in-edge from outside the new node — found by scanning the component's
   in-list from the front, without advancing after a replacement — is
   redirected by `otherbl->replaceOutEdge(j, new)` **for every out-slot `j`
   of `otherbl` that points at the component**; then each out-edge to
   outside likewise by `otherbl->replaceInEdge(j, new)` for every in-slot
   of the target pointing at the component, and `f_switch_out` is set on
   the new node if that component is a switch. `replace*Edge` keeps the
   slot on the outside node and appends to the new node's list
   (block.cc:164, 182). Internal edges stay on the components.
4. `dedup` (block.cc:529): duplicate in-edges from one node, then
   duplicate out-edges to one node, are merged into the first, OR-ing
   labels.

Fix-ups per factory (block.cc:1707–1941):

| Factory | After `identifyInternal` |
|---|---|
| `newBlockGoto(bl)` | target = `bl.out[0]`; `forceOutputNum(1)`; the out-edge is removed (a goto has no structured exit) |
| `newBlockMultiGoto(bl, e)` | If `bl` already is a multigoto: add the target, remove that edge, mark default if the edge was the switch default. Else create one; if identifying collapsed a self-edge (fewer out-edges than before) `forceOutputNum(size+1)` keeps it; remove the edge to the target unless the target is `bl` itself |
| `newBlockList(nodes)` | `forceOutputNum(last.sizeOut())`; with two outs, `forceFalseEdge(last.out[0])` |
| `newBlockCondition(b1, b2)` | opcode `INT_OR` if `b1`'s false out is `b2`, else `INT_AND`; `forceOutputNum(2)`; `forceFalseEdge(b2.out[0])` |
| `newBlockIfGoto(cond)` | requires `cond`'s true edge to be a goto (else `Building ifgoto where true branch is not the goto`); target = true out; `forceOutputNum(2)`; `forceFalseEdge(old out[0])`; the true edge is removed |
| `newBlockIf`, `newBlockIfElse`, `newBlockWhileDo`, `newBlockDoWhile` | `forceOutputNum(1)` |
| `newBlockIfNoExit`, `newBlockInfLoop` | nothing |
| `newBlockSwitch(cases, hasExit)` | the root's exit leaf must be a copy (else `Could not get switch leaf`); `grabCaseBasic` **before** identifying; with an exit `forceOutputNum(1)`; `f_switch_out` cleared |

`forceOutputNum(i)` (block.cc:893) adds **self-edges labelled loop + back**
until the node has `i` out-edges (`Bad block output force` if it already
has more): this is how a collapsed loop body becomes a self-loop that the
loop rules then see. `forceFalseEdge(out0)` (block.cc:1217) swaps the two
out-edges unless out-edge 0 already goes to `out0` (or to the new node
itself when `out0` was absorbed), else `Unable to preserve condition`.

**The condition opcode quirk.** `ruleBlockOr` always arranges `b2` to be
`b1`'s false out before calling `newBlockCondition`, so the opcode is
always `INT_OR` when created. `BlockCondition::negateCondition` and
`flipInPlaceExecute` toggle with `opc = (opc == BOOL_AND) ? BOOL_OR :
BOOL_AND` (block.cc:3073, 3091), and the printer and `printHeader` test
only `== BOOL_AND` (printc.cc:3001, block.cc:3107). So a fresh condition
prints `||`, negated once `&&`, twice `||` — correct by accident — and the
encoded `opcode` attribute reads `INT_OR`, `BOOL_AND` or `BOOL_OR`.
Reproduce the stored value exactly (dumps and encoding show it).

### 4.5 Negation (the flips)

`negateCondition(toporbottom)` per kind:

* `FlowBlock` (block.cc:298): if `toporbottom`, swap the two out-edges
  (`swapEdges`, which throws `Swapping edges for block that doesn't have
  two edges` otherwise and toggles `f_flip_path`); returns `false`.
* `BlockCopy` (block.hh:557): negate the **original** block with `true`
  (→ a *flip event* on that leaf, returning the leaf's
  `negation_changes_dataflow` fact), then `FlowBlock::negateCondition` on
  the copy with the given argument.
* `BlockList` (block.cc:3029): last component with `false`, then itself.
* `BlockCondition` (block.cc:3085): both components with `false`, toggle
  the opcode, then itself; returns the OR of the components' results.
* Other kinds inherit `FlowBlock`'s.

Every rule site calls `negateCondition(true)` and adds 1 to
`dataflow_changecount` when it returns `true` (eight sites:
blockaction.cc 1359, 1363, 1401, 1462, 1506, 1513, 1548, 1575; the plan's
"ten" counted differently). Basilisk
records each flip event (the leaf, in order) and counts the changes; the
pipeline applies the flips to the basic blocks afterwards (D15: for a
leaf flipped an odd number of times, toggle `boolean_flip` and
`fallthru_true` on its `CBRANCH` and swap the basic block's two
out-edges — what `BlockBasic::negateCondition` would have done; the
toggles commute, so parity is enough). `dataflow_changecount` is what
`ActionBlockStructure` adds to its change count (blockaction.cc:2189).

### 4.6 Loop bodies (`LoopBody`, blockaction.cc 46–498, 1021–1050, 1126–1191)

`orderLoopBodies` (1148):

1. `labelLoops` (1126): for each node in list order, for each in-edge in
   order that is a **back edge**, a `LoopBody(head = node)` with one tail
   (the edge's source) is appended to the body list; pointers to all of
   them go to `looporder`, which is sorted by (head index, first tail
   index) with `std::sort` (1142). Equal keys arise only for two back
   edges from the same tail to the same head; the two bodies are
   identical and adjacent in the body list, so the unspecified order is
   not observable (read). Basilisk sorts stably.
2. `mergeIdenticalHeads` (446): consecutive entries with the same head are
   merged into the first (its tail list gains the other's first tail);
   subsumed bodies are erased from the body list.
3. For each body in list order: `findBase` (119: mark head and tails,
   `uniquecount` = their number, then walk in-edges backwards from index 1
   on, skipping goto in-edges) and `labelContainments` (327: every other
   loop whose head is in this body gets `depth += 1`, and its
   `immed_container` becomes this loop if it has none or its container is
   shallower; the comment at 343–354 proves this yields the innermost).
4. `loopbody.sort()` by **descending depth** — `std::list::sort`, stable.
5. For each body, deepest first: `findBase`; `findExit` (182: the first
   non-goto out-edge of a tail, then of the head and non-tail body nodes,
   leaving the body — taken at once if there is no container; otherwise
   collected, and the exit is the first candidate inside the container's
   extended body `extendToContainer` (46), else none); `orderTails` (245:
   the first tail with an edge to the exit is swapped to the front);
   `extend` (150: add nodes all of whose in-edges come from the body,
   never the exit, through non-goto edges, using `visitcount`, which it
   resets); `labelExitEdges` (270: exits of non-head/tail body nodes, then
   of the head, then of the tails **from last to first**, with every edge
   to the chosen exit postponed to the end); `clearMarks`.
6. `likelylistfull = false`; the current loop is the first body.

`update(graph)` (94) moves head and tails up the parent chain to the
current graph level and returns the first tail that is not the head, else
the head if it has a self out-edge, else null (the loop is collapsed).
`emitLikelyEdges` (364): after updating head, exit and tails (a tail that
became the exit clears the exit), the current forms of the exit edges in
order, except that a last edge to the exit is held back and emitted just
before the back edges of `tails[0]`; back edges of tails from last to
first. `setExitMarks`/`clearExitMarks` set or clear `f_loop_exit_edge` on
the current forms of the exit edges.

### 4.7 Choosing gotos (`TraceDAG`, blockaction.cc 499–1019; `updateLoopBody`, `selectGoto`)

`updateLoopBody` (1193) walks the body list from the current loop: a body
whose `update` returns null is finished; a loop whose bottom is its head
(a self-loop that no rule collapsed — "likely a switch") gets the single
likely goto (head, head). Otherwise, unless the current loop's likely
list is full and not exhausted, a `TraceDAG` runs: for a loop, rooted at
the head with the bottom as *finish block* and the loop's exit edges
marked; with no loop left, rooted at every node without in-edges in list
order. After the trace, a loop appends its `emitLikelyEdges`; with no loop
and no likely edge, `finaltrace` is set and the answer is "nothing left".
`selectGoto` (1260) takes likely edges in order, skipping those whose
current form no longer exists (`FloatingEdge::getCurrentEdge`, 27: both
ends lifted to the current level, then `getOutIndex`), marks the first one
found with `setGotoBranch` and returns its source. When no edge is left
it tries `clipExtraRoots` (1108: the first node after `list[0]` without
in-edges whose "only reachable from it" set (`onlyReachableFromRoot`,
1052) has edges leaving it gets those edges marked as gotos); if nothing,
`Could not finish collapsing block structure` (**ran**: 161 of 3,000
random graphs end in this error, 156 of them with unreachable nodes;
runs.md R3).

The trace (`pushBranches`, 983) keeps a circular cursor over the active
traces (a list in insertion order). At each step, in this priority:

1. if `missedactivecount >= activecount`, `selectBadEdge` picks a trace,
   `removeTrace` records it as a likely goto (bottom → destination),
   adds its edge count to the destination's `visitcount`, and either makes
   the trace terminal (if it has moved past its branch point) or deletes it
   from its branch point, renumbering later siblings' `pathout` and their
   derived branch points'; the cursor restarts at the front;
2. else if the trace can retire (`checkRetirement`, 866: only the
   first sibling checks; the root retires when all its paths are active
   and terminal; another branch point when all paths are active and the
   non-terminal ones share one destination), `retireBranch` (900) removes
   the siblings and reactivates the parent trace with the shared exit and
   the summed `edgelump` (or terminal if all were terminal);
3. else if it can open (`checkOpen`, 810: the destination's loop-DAG
   in-edges number at most `edgelump + visitcount`; the finish block opens
   only from the root; an artificial root path always opens),
   `openBranch` (839) makes a branch point at the destination with one
   trace per loop-DAG out-edge (none → the trace becomes terminal) and the
   cursor moves to its first path;
4. else the cursor advances and `missedactivecount += 1`.

`selectBadEdge` (730) scores every non-terminal trace except virtual
root edges: `exitproto` = destination, `terminal` = 1 if the destination
has no out-edges, `distance` = −1, `siblingedge` = 0; the list is sorted
(`std::list::sort`, stable) by (destination index, branch-point block
index or −1, `pathout`); for each run with the same destination
`processExitConflict` (694) counts traces from the same branch point
(`siblingedge`) and the minimum branch-point distance (`distance`, via
`markPath` toggling marks to the root and `BranchPoint::distance`, 524).
The chosen trace is the **first** maximum of `compareFinal` (617): more
siblings is less likely bad; then terminal; then smaller distance; then
smaller depth — "maximum" here means the last that `compareFinal` keeps
replacing, scanning in sorted order. `clearVisitCount` (940) resets the
destinations of the recorded edges.

**Undefined behaviour to guard**: `selectBadEdge` dereferences the first
element of the score list without checking it is non-empty (749). The
list is empty if every active trace is terminal or a virtual root edge
when no trace can move. Not observed (R3), not proven unreachable;
Basilisk returns `CfgError::NoBadEdge` there and the random-graph test
reports any graph that reaches it as a Ghidra defect (crash or garbage in
the reference).

### 4.8 The collapse loop and the rules (blockaction.cc 1284–1904)

`collapseAll` (1885): `finaltrace = false`; clear every `visitcount`;
`orderLoopBodies`; `collapseConditions` (1862: repeat sweeps of
`ruleBlockOr` over the list by index until a sweep changes nothing — the
list grows and shrinks during the sweep and the index is **not** reset);
`isolated = collapseInternal(null)`; while `isolated < list.size()`:
`collapseInternal(selectGoto())`.

`collapseInternal(target)` (1776):

```
repeat
  repeat
    change = false; index = 0; isolated = 0
    while index < list.size():
      if target: bl = target; change = true; target = null; index = list.size()
      else: bl = list[index]; index += 1
      if bl has no in- and no out-edges: isolated += 1; continue
      try in this order, stopping at the first that applies (change = true):
        ruleBlockGoto, ruleBlockCat, ruleBlockProperIf, ruleBlockIfElse,
        ruleBlockWhileDo, ruleBlockDoWhile, ruleBlockInfLoop, ruleBlockSwitch
  until not change
  fullchange = false
  for each node of the list in order:
    if ruleBlockIfNoExit(bl) or ruleCaseFallthru(bl): fullchange = true; break
until not fullchange
return isolated
```

After a rule applies the sweep **continues at the same `index`** over the
modified list (components removed, the new node appended); this order is
behaviour. The rules (each "requires" line is a condition that, if
false, makes the rule not apply to `bl`):

* **`ruleBlockGoto`** (1450): for the first out-edge that is a goto: a
  switch → `newBlockMultiGoto(bl, i)`; two outs → if out-edge 1 is not a
  goto, negate `bl`; `newBlockIfGoto`; one out → `newBlockGoto`. (Three
  or more outs without the switch flag: not applicable.)
* **`ruleBlockCat`** (1284): requires one out-edge, not a switch, not the
  middle of a chain (`sizeIn == 1` and the predecessor has one out), the
  successor not `bl`, with one in-edge, the edge a decision edge, the
  successor not a switch. Extends while the last node has one out-edge to
  a node that is not `bl`, has one in-edge, is reached by a decision edge
  and is not a switch. `newBlockList`.
* **`ruleBlockOr`** (1321; only in `collapseConditions`): requires two
  out-edges, neither a goto, not a switch. For `i` in 0, 1: `orblock =
  out[i]` must not be `bl`, have one in-edge and two out-edges, not be an
  interior goto target or a switch, not be reached by a back edge, and not
  be **complex**; `clause = out[1-i]` must not be `bl` or `orblock` and
  must be an out of `orblock` at slot `j`; `orblock`'s other out must not
  be `bl`. Then: if `i == 1` negate `bl`; if `j == 0` negate `orblock`;
  `newBlockCondition(bl, orblock)`.
* **`ruleBlockProperIf`** (1378): two outs, not a switch, no out to
  itself, neither out a goto; for `i` in 0, 1: `clause = out[i]` with one
  in, one out, not a switch, reached by a decision edge, its out not a
  goto and equal to `out[1-i]`; if `i == 0` negate `bl`; `newBlockIf(bl,
  clause)`.
* **`ruleBlockIfElse`** (1416): two outs, not a switch, both decision
  edges; true and false clauses each one in, one out, the same successor,
  which is not `bl`; neither clause a switch nor its out a goto;
  `newBlockIfElse(bl, true, false)`.
* **`ruleBlockWhileDo`** (1526): two outs, not a switch, no out to itself,
  not an interior goto target, neither out a goto; for `i` in 0, 1: clause
  `out[i]` with one in, one out, not a switch, whose out is `bl`;
  `overflow = bl.complex` (through the copy); if `(i == 0) != overflow`
  negate `bl`; `newBlockWhileDo`, with `f_whiledo_overflow` when
  `overflow`.
* **`ruleBlockDoWhile`** (1563): two outs, not a switch, neither a goto;
  the first `i` with `out[i] == bl`: if `i == 0` negate; `newBlockDoWhile`.
* **`ruleBlockInfLoop`** (1587): one out, not a goto, to itself (a switch
  is deliberately allowed); `newBlockInfLoop`.
* **`ruleBlockSwitch`** (1657) with `checkSwitchSkips` (1615): the exit is
  the first out that is `bl`, has more than one out or more than one in;
  failing that, every out must have no goto in-edge, not be a switch, and
  the outs with one out-edge (not a goto) must agree on their successor,
  which becomes the exit. With an exit chosen first: no goto edge into or
  out of the exit; every other case has one in-edge (not a goto), at most
  one out (not a goto, to the exit), and is not a switch.
  `checkSwitchSkips`: if some non-default edge goes straight to the exit
  and the default edge does not (or the multigoto holds a default goto),
  those skip edges are marked goto and the rule reports **applied**
  without building anything. Otherwise `newBlockSwitch([bl] + outs except
  the exit, exit != null)`.
* **`ruleBlockIfNoExit`** (1481): two outs, not a switch, no out to
  itself, neither a goto; for `i` in 0, 1: clause `out[i]` with one in,
  **no** out, not a switch, reached by a decision edge. If `i == 0` and
  `out[1]` also qualifies: negate `bl`, `newBlockIfNoExit(bl, out[0],
  out[1])`. Else if `i == 0` negate; `newBlockIf(bl, clause)`.
* **`ruleCaseFallthru`** (1737): a switch with no out to itself; counts
  outs with more than two ins or more than one out (`nonfallthru`, at most
  one allowed); collects outs with one out-edge whose target has exactly
  two ins, at most one out, and whose other in-edge comes from `bl`; marks
  each collected out-edge as a goto and reports applied. (The comment
  "Check exit block matches the 1 nonfallthru exit" has no code behind it;
  port the code.)

`setGotoBranch(i)` (block.cc:309) labels the edge goto (both halves) and
sets `f_interior_gotoout` on the source and `f_interior_gotoin` on the
target; `Could not find block edge to mark unstructured` for a bad slot.

### 4.9 Finishing: order, breaks, gotos, labels

What `ActionFinalStructure` (blockaction.cc:2195) does after structuring,
minus the op-level `finalizePrinting` that D15 runs between steps 1 and
3:

1. **`orderBlocks`** (block.hh:447): if the top-level list has more than
   one node, `std::sort` with `compareFinalOrder` (block.cc:718): index 0
   first; then blocks not ending in `RETURN` (by the fact, through
   `lastOp`) by index; blocks ending in `RETURN` last. **Two blocks that
   both end in `RETURN` compare equal**, so their order is whatever the
   C++ library's sort leaves (and the comparator also returns `true` for
   index 0 against itself, which is not a strict weak ordering). Under
   ADR-040 Basilisk sorts **stably** by the key (index ≠ 0, ends in
   `RETURN`, index if not `RETURN`), keeping list order among `RETURN`
   blocks. libstdc++'s `std::sort` is a plain insertion sort below 17
   elements, so this equals the x86-64 reference (ADR-021) for top-level
   lists of up to 16 nodes; libc++ sorts very short ranges with
   compare-and-swap networks that can reorder equal elements (four or more
   elements), so the Mac build may differ even on short lists. How often
   such ties occur is open (section 10); any row where the two builds
   differ for this reason is a counted cause (6.3.3).
2. *(D15: `finalizePrinting`; for a switch it sorts the cases by label
   with `stable_sort`, block.cc:3679 — this crate provides that sort given
   each case's first label as input.)*
3. **`scopeBreak(-1, -1)`** (per kind, block.cc 1284, 2928, 2980, 3096,
   3129, 3153, 3184, 3236, 3444, 3557, 3585, 3736): passes down the index
   of the block that follows (the "exit") and of the innermost loop's
   exit; a goto whose target index equals the loop exit becomes
   `f_break_goto`; in a switch a goto case going straight to the exit
   becomes a break. (`f_continue_goto` is never assigned in this Ghidra
   version.)
4. **`markUnstructured`**: a `BlockGoto` whose type is still goto and whose
   goto *prints* (`gotoPrints`, block.cc:2943: the target's front leaf is
   not what flows next, by `nextFlowAfter` of the parent, which for a
   switch depends on the case order of step 2), a `BlockIfGoto` of goto
   type, and goto cases of a switch mark their target's front leaf
   `f_unstructured_targ`.
5. **`markLabelBumpUp(false)`**: a graph passes `true` to its first
   component only; while/do-while/infinite loops pass `true` down and keep
   their own flag only if told to.

### 4.10 Encoding and printing

* **XML** (as `structure blocks` reads and writes it, **ran** R2):
  `<block index=…>` with, for a graph, one `<bhead index type>` per
  component, then the components' `<block>`s, then this block's in-edges
  `<edge end=… rev=…/>`. Edge labels are **not** encoded and decode as 0
  (block.cc:35–53). `typeToName` maps `t_ifnoexit` to `"ifelse"`
  (block.cc:675): the two kinds cannot be told apart in XML. `nameToType`
  knows only `graph` and `copy` (everything else decodes as a plain
  block), so only bare graphs can be read. A copy carries `altindex` =
  its original's index; a condition its opcode name; goto kinds a
  `<target index depth [type]>` naming the target's front leaf and its
  depth below the target. `decodeNextInEdge` (block.cc:89) grows the
  source's out-list to the given reverse index, leaving unfilled slots
  default-constructed (uninitialised in C++): Basilisk rejects a
  document whose out-slots are not all filled exactly once
  (`CfgError::BadEdgeSlots`), a deliberate difference for hostile input.
* **`printTree`** (`print tree block`, **ran** R1): two spaces per level,
  `printHeader` per node: `List block`, `Condition block(&&)` /
  `Condition block(||)`, `If block`, `If/else block`, `If (no exit)
  block`, `If goto block`, `Whiledo block` (`(overflow) ` added),
  `Dowhile block`, `Infinite loop block`, `Switch block`, `Plain goto
  block`, `Multi goto block`, `Basic(copy) block`, each followed by the
  index and, for basic blocks, ` <start>-<stop>`. A copy prints through
  its original (so as `Basic Block …`); the leaf line is produced by a
  callback the IR crate supplies.

### 4.11 What makes the result depend on order

Everything is driven by list order and edge order, never by addresses or
hashing: `findSpanningTree` (roots in list order, children in out-edge
order), `labelLoops` (list order, in-edge order), `collapseInternal` and
`collapseConditions` (index sweeps over a mutating list), `selfIdentify`
(component order, in-list and out-list scans), `TraceDAG` (root order,
out-edge order, active-list insertion order), `orderBlocks` (4.9). The
only sorts are `std::sort` in `labelLoops` (ties unobservable, 4.6),
`std::sort` in `orderBlocks` (ties among `RETURN` blocks, 4.9),
`std::sort` in `BlockMap::sortList` (block.cc:3827; ties only for
duplicate indices in a hostile document, rejected by Basilisk), and the
stable `list::sort`/`stable_sort` calls. No container keyed by pointer is
iterated (`grep` over `block.*` and `blockaction.*`: the only map is
`ConditionalJoin::mergeneed`, keyed by creation index, D15's). **Ran**:
3,000 random graphs give byte-identical output on the Mac (libc++) and
the build host (libstdc++), and on repeated runs (R3, R4).

## 5. Design

### 5.1 Data layout (ADR-012, ADR-013)

* `NodeId(u32)` indexes one arena per structuring run; leaves keep the
  input node's id (`0..n`), structured nodes are appended. Nothing is
  freed during a run (`removeBlock` is not used by the structurer), so
  ids never dangle.
* Per node: kind (enum), flags (`u32`), `index: i32`, `parent:
  Option<NodeId>`, `leaf_count`, `depth`, `visit` (working), `mark` bits,
  in- and out-edge lists, component list (for structured kinds), and
  kind data (goto target and type; multigoto targets and default flag;
  condition opcode; switch cases). Edge lists are `SmallVec<[Edge; 2]>`
  out / `SmallVec<[Edge; 3]>` in, with Ghidra's shifting deletion
  (order is behaviour); `Edge { label: u16, other: NodeId, rev: u32 }`.
  Assert the sizes of `Edge` and the node struct in a test.
* The top-level list and each component list are `Vec<NodeId>`;
  `identifyInternal`'s filtering reuses a scratch vector held in the
  structurer. Every per-call scratch (`body`, `trial`, `reachunder`, the
  rule's `nodes`) lives in one `Scratch` struct reused across steps: **no
  allocation per rule attempt** in `collapseInternal`'s sweep.
* `LoopBody`s in a `Vec` with stable indices plus an order vector (the
  list and its stable sort); `TraceDAG`'s branch points and traces in
  arenas with indices (`BranchId`, `TraceId`), the active list as an
  index-linked list (O(1) removal by stored position, like Ghidra's
  stored iterator).
* The input `Cfg` (5.2) is plain vectors: `Clone` is a few memcpys, which
  is what "the block graph is cheap to copy" (plan 8, 3b) needs.

### 5.2 Public API (sketch)

```rust
pub struct Cfg { /* nodes in list order, edges, flags, index, idom */ }
impl Cfg {
    pub fn new() -> Self;
    pub fn add_node(&mut self, flags: NodeFlags) -> NodeId;
    pub fn add_edge(&mut self, from: NodeId, to: NodeId) -> Result<(), CfgError>; // addEdge
    // remove_edge, switch_edge, move_out_edge, remove_node, remove_from_flow,
    // remove_from_flow_split, splice_node, set_start, start, set_goto_branch,
    // set_default_switch, swap_out_edges, edges with labels, index, idom, ...
    pub fn structure_loops(&mut self) -> Result<Roots, CfgError>;      // 4.2
    pub fn forward_dominators(&mut self, roots: &Roots) -> Result<(), CfgError>;
    pub fn dom_tree(&self) -> DomTree; pub fn dom_depth(&self) -> (Vec<u32>, u32);
    pub fn reachable(&self, from: NodeId) -> Vec<NodeId>; pub fn unreachable(&self, from: NodeId) -> Vec<NodeId>;
    pub fn order_by_final(&mut self, facts: &BlockFacts);              // orderBlocks on a flat graph
}
pub struct BlockFacts { /* per input node: complex, switch_out, ends_in_return, negation_changes_dataflow */ }
impl BlockFacts { pub fn neutral(n: usize) -> Self; /* setters */ }
pub struct StructureOptions {
    pub analyse: Analyse,                 // AsGiven (pipeline) | Recompute (bare graph, `structure blocks`)
    pub limits: Limits,                   // nodes, edges, work steps
    pub record: Record,                   // None | Trace (rule applications and goto choices)
}
pub fn structure(graph: &Cfg, facts: &BlockFacts, options: &StructureOptions,
                 goto_selector: &mut dyn GotoSelector) -> Result<Structured, CfgError>;
pub struct Structured {
    pub hierarchy: Hierarchy,             // arena of nodes, the top-level list, per-node accessors
    pub flips: Vec<NodeId>,               // flip events on leaves, in order (4.5)
    pub goto_edges: Vec<GotoMark>,        // every setGotoBranch: (source node, target node, cause)
    pub dataflow_changes: u32,
    pub measure: Measure,
    pub trace: Option<Vec<TraceRecord>>,
}
pub fn finish(h: &mut Hierarchy, facts: &BlockFacts, case_labels: Option<&dyn CaseLabels>); // 4.9 steps 1-5
pub trait GotoSelector { fn select(&mut self, view: &mut CollapseView<'_>) -> Result<Option<NodeId>, CfgError>; }
pub struct GhidraGotoSelector;            // LoopBody + TraceDAG + clipExtraRoots, exactly 4.6-4.7
```

* `Analyse::AsGiven` structures the graph with its labels, order,
  indices and dominators as passed (what `ActionBlockStructure` does);
  `Analyse::Recompute` runs `structure_loops` and `forward_dominators` on
  the working copy first (what `structure blocks` does). Facts are
  indexed by input node.
* `GotoSelector` is the replaceable unit the plan names ("goto selection
  as a replaceable step", plan 5 D04 row; ADR-025 item 1). It receives a
  view that exposes the current level, `setGotoBranch`, and the loop-body
  state; the Ghidra implementation is the default and the only one in
  the `ghidra` profile. The unit's name for the unit table (D05/D07) is
  `selectgoto`, its rules' names are the method names without `rule`
  (`blockgoto`, `blockcat`, `blockor`, `blockproperif`, `blockifelse`,
  `blockwhiledo`, `blockdowhile`, `blockinfloop`, `blockswitch`,
  `blockifnoexit`, `casefallthru`), exported as `&'static str` constants;
  this crate cannot depend on the unit table, which lives in
  `bk-decomp-ir` (D05) above it.
* **`Measure`**: `goto_marks` by cause (`Selected` from `selectGoto`,
  `ClippedRoot` from `clipExtraRoots`, `SwitchSkip`, `CaseFallthru`) and
  `input_gotos` (edges labelled goto in the input); `depth` (largest
  `structureDepth` of a top-level node), `leaves`, `nodes_by_kind`,
  `flips`, `dataflow_changes`; after `finish`: `printed_gotos` (goto
  kinds still of goto type whose goto prints), `breaks`. Plan 8's "the
  measure's goto count equals the number of goto edges Ghidra marks" is
  checked as `sum(goto_marks)` against the oracle's `G` records (D00
  section 4.7).
* Hierarchy accessors for D15/D16: kind, components, exit leaf, front
  leaf, split point, goto target and type, condition opcode, overflow,
  switch cases (`CaseOrder` fields), flags, `next_flow_after`,
  `is_unstructured_target`, `is_label_bump_up`, `print_tree(callback)`,
  `encode(&mut Encoder)`; and `Cfg::decode`/`encode` for bare graphs.
* **Errors**: `CfgError` (`thiserror`), one variant per Ghidra
  `LowlevelError` reachable from this code, carrying Ghidra's message
  text as its `Display` (`Could not finish collapsing block structure`,
  `Could not generate spanning tree`, `Problems finding root node of
  graph`, `Bad block output force`, `Unable to preserve condition`,
  `Could not get switch leaf`, `Case block has become detached from
  switch`, `Building ifgoto where true branch is not the goto`,
  `Swapping edges for block that doesn't have two edges`, `Could not find
  block edge to mark unstructured`, `Bad block identify`, `Bad edge
  create`, `Bad edge remove`, `Bad edge move`, `Bad block remove`, `Bad
  remove from flow`, `Illegal remove from flow`, `Bad remove from flow
  split`, `Illegal remove from flow split`, `Can only splice a block with 1
  output to a block with 1 input`, `Bad set start`, `No start block
  registered`, `Bad serialized edge in block graph`), plus Basilisk's
  `LimitExceeded { what, limit }`, `SpanningTreeRebuild`, `NoBadEdge`,
  `BadEdgeSlots`. A failed structuring leaves the input untouched (it is
  borrowed) and is an error result for the function (plan 3.9).

### 5.3 Limits against hostile input (ADR-009)

Ghidra has none. Basilisk: `Limits { max_nodes (default 1,000,000),
max_edges (default 4,000,000), max_steps }` where a step is one rule
attempt, one trace step or one analysis visit; `max_steps` defaults to
`64 * (nodes + edges)^2 / 1000 + 10^6` (generous: the measured cost on
the corpora is to be recorded in `PERF.md`, and the default revisited
then). No recursion anywhere: `scopeBreak`, `markUnstructured`,
`markLabelBumpUp`, `printTree`, `encode`, `getFrontLeaf` and the
parent-chain walks are iterative or use an explicit stack (Ghidra recurses
over the hierarchy, whose depth grows with nesting: an `else if` chain of
length *k* nests *k* deep, R1). No arithmetic can overflow (`index` and
counts in `i32`/`u32` with checked conversion from `usize`).

### 5.4 Modules

`graph/{node, edge, surgery, query}`, `analysis/{spanning, irreducible,
loops, dominators, reach}`, `hierarchy/{kinds, identify, factories,
negate, query, switch}`, `structure/{collapse, rules, conditions}`,
`gotos/{loopbody, tracedag, selector}`, `finish/{order, scope, unstructured,
labels}`, `codec/{xml, tree}`, `limits`, `error`. Every file under 600
lines.

### 5.5 Plugin binding constraints

`features/plugin-binding-constraints.md`: the structurer is internal to
the decompiler, but `Hierarchy` reaches plugins through decompiler
results (D17). Rule 1 and 2: `Hierarchy` owns its data, no lifetimes,
`Send + Sync` — meets. Rule 3: `NodeId`s are stable within one result;
results are immutable — meets. Rule 4: `CfgError` is a closed `thiserror`
enum with stable variant names — meets. Rule 6: `Structured` is owned and
can be put behind an `Arc` by D17 — meets. Rule 7 (monitor): not taken
here; one call is bounded by `Limits` and the driver checks the monitor
between passes — departs, because a structuring call is a bounded inner
step. Rule 12: the public API has no generics except the `&mut dyn
GotoSelector` trait object — meets. Rules 5, 8–11, 13–15 do not apply.

## 6. Tests

Kinds as in plan 4.5: **S** self-contained, **G** needs the Ghidra tree,
**L** needs the live reference tools. Ghidra has no unit test for blocks;
everything below is derived from the source or from the oracle.

### 6.1 Unit tests (S)

Hand-built graphs for each rule's positive and negative conditions (one
test per "requires" line of 4.8), each factory's edge order (4.4), the
condition opcode sequence `INT_OR → BOOL_AND → BOOL_OR`, `forceOutputNum`
self-edges, `checkSwitchSkips` and `ruleCaseFallthru` returning
"applied" with only goto marks, every `CfgError` message, the rebuild
bound of 4.2, and the five reachable graphs of R3 that end in `Could not
finish collapsing block structure` (they are in
`docs/research/decomp-wave1/runs.md`; rebuild them in test code).

### 6.2 `structure blocks` cross-check (S replay, L regeneration)

Before and independently of D00: graphs in Ghidra's XML, structured by
the reference console's own command, compared through the XML encoder of
4.10. Generator: a Rust test-support module of this crate,
`tests/support/graphgen.rs`, writing the same graph classes as 6.3 with a
seeded `rand_chacha` stream (ADR-011: `rand`/`rand_chacha` are the
industry standard; add them as dev-dependencies after the age check).
`tests/oracle/regen_xml.sh <REF>` writes the graphs, runs one console
session (`load test file <DT>/elseif.xml` to give `XmlDecode` an
architecture, then `structure blocks <in> <out>` per graph — the
reference's own command, unchanged), and stores `graph → output or error
message` in `tests/data/structure_blocks.txt.gz`. Replay: decode each
graph, `structure(…, Analyse::Recompute, neutral facts)` **without**
`finish` (the command does not order blocks), encode, compare bytes; an
error must be the same message. What this cannot check: flips, goto
labels, the overflow flag, `ifnoexit` vs `ifelse`, non-neutral facts,
input labels — hence 6.3.

### 6.3 The full oracle (S replay, L regeneration; needs D00)

D00 delivers, in the reference build's extended console `decomp_bk`
(D00 4.6, 4.7):

* `bk cfg analyze <graph> <out>` — the analyses of 4.2 and the loop
  bodies of 4.6 on a graph file;
* `bk structure <graph> <out> [bare|asgiven] [finish] [trace]` — 4.3–4.9
  on a graph file with facts and input labels, writing a structure dump
  (flips, goto marks with causes, every node with kind, kind data, flags,
  edges; the trace when asked);
* `bk dump blocks <out>` / `bk dump structure <out>` — the current
  function's basic-block graph with its real facts and labels, and its
  structured hierarchy, in the same two formats.

The formats are D00's (decomp-oracle.md 4.6, 4.7) and are the contract;
this crate's test support parses and writes them.

1. **Generated graphs** (`tests/oracle/regen.sh <REF>`, table
   `tests/data/cfg_oracle.txt.gz`, about 12,000 graphs): 4,000
   *function-like* graphs (every node reachable from node 0, node 0
   without in-edges, no node with two out-edges to one target, switch
   nodes with distinct targets), 4,000 *arbitrary* graphs (any out-degree
   0–6 — degree ≥ 3 makes a switch by `newBlockCopy`'s rule — multi-edges,
   self-loops, unreachable parts, in-edges to node 0), 2,000 reducible
   graphs built from nested structured shapes (sequences, if, if-else,
   loops with breaks and continues, switches with fall-through, gotos),
   2,000 irreducible graphs (a structured graph plus random cross edges
   into loop bodies); sizes 1–64 nodes, 10 % with random facts (`complex`,
   `ends_in_return` on nodes without outs, input goto and default-switch
   labels). Each graph is run with `bk cfg analyze` and with `bk
   structure` in modes `bare trace` and `bare finish`; the function-like
   ones also in mode `asgiven`, on a graph file written from Ghidra's own
   analysis of the graph (the `bk cfg analyze` output: its list order,
   indices, dominators and labels). The table
   holds, per graph, its seed and generator class (the graph is
   regenerated in the test, not stored) and the three outputs. Replay
   compares Basilisk's outputs byte for byte, including error messages.
   **Measured (R3) cost of the reference**: 3,000 graphs of ≤ 40 nodes in
   0.9 s, so regeneration takes seconds.
2. **Corpus graphs**: for every `decompile` of every data test (193
   `decompile` commands in 93 files; **ran**: `grep -o "<com>[^<]*</com>"
   DT/*.xml`) and every function of the research corpus (209 functions,
   `docs/research/decompiler-quality/README.md`), D00's capture driver
   stops with positional breakpoints (`bk break start <n>`, D00 4.10 —
   the console cannot stop at the top-level `blockstructure` by name, D00
   4.1) at **both** `blockstructure` instances (positions 0168 in
   `mainloop` and 0231 for the `decompile` root) and at the action after
   each; it writes `bk dump blocks` at a `blockstructure` start when the
   function's structured graph is empty (otherwise the action returns at
   once, blockaction.cc:2182, and there is no case), `bk dump structure`
   at the next action's start, and `bk dump structure` plus `bk dump
   state` at `finalstructure`'s successor and at the end. Each actual
   structuring run is one case: the test structures the `bk dump blocks`
   graph with `Analyse::AsGiven` and the real facts and compares with the
   following `bk dump structure` (hierarchy and flips as the parity per
   leaf); the last run is then finished with `finish`, the case labels
   taken from the state dump's `@jumptables`, and compared with the final
   structure. The number of graphs is what D00's
   capture produced (it reports the count; one function can give several
   cases, since `structureReset` empties the structured graph whenever the
   blocks change and the `mainloop` instance runs again). Checked-in subset: all of them if the compressed captures stay
   under 2 MB, else a mechanically chosen subset covering every node kind
   and every rule (the selection script is checked in), with the rest L.
3. **Ghidra's own determinism** is part of the table: `regen.sh` runs the
   generation twice and requires byte-identical tables, and the table is
   generated on both reference builds (`regen.sh` on the Mac, the same
   script through `scripts/remote.sh run` for the build host). They are
   expected to be equal (R3/R4 found the 3,000-graph run identical); a
   row that differs fails regeneration with the cause stated, and is then
   handled in ADR-040's form (recognised by cause and counted in the
   replay) — the expected cause is `orderBlocks`' `RETURN` ties of 4.9,
   which generated graphs reach only through the `ends_in_return` fact on
   top-level lists longer than 16.

### 6.4 Trace (S)

For the generated graphs and the corpus graphs, Basilisk's `TraceRecord`s
(rule name and block index per application, goto choice with cause)
equal the `R`/`G` records of `bk structure … trace`. D00 checks that its
traced run gives the same structure dump as the untraced one, so the
trace is Ghidra's sequence.

### 6.5 Properties (`proptest`, S)

On generated graphs (all four classes): structuring the same graph twice,
or a clone, gives equal results and leaves the input unchanged (ADR-025
3b, plan 8); every input node appears exactly once as a leaf of the
hierarchy; every node's components have it as parent; edge halves agree
(`checkEdges`) after every step in debug builds; the loop edges of
`structure_loops` cut every cycle; the dominator of every reachable node
dominates it on every path (checked against a naive dataflow
computation); the rebuild branch of 4.2 is never taken; `NoBadEdge` never
occurs; no input panics; structuring finishes within `Limits` for every
graph of up to 1,000 nodes; flip parity applied to the input's edges and
then `structure` again (with the flipped blocks' facts) is not required
to be idempotent and is not tested.

### 6.6 Fuzzing

`fuzz/fuzz_targets/bk_decomp_cfg_structure.rs`: arbitrary bytes → a graph
(node count, edge list, facts, labels; capped at 512 nodes) →
`structure` in both modes and `finish`; must not panic, hang or exceed
`Limits`. `fuzz/fuzz_targets/bk_decomp_cfg_xml.rs`: arbitrary bytes →
`Cfg::decode`. Crashes go to `fuzz/regressions/` and become tests.

### 6.7 Benchmarks

`#[ignore]` release tests or `divan`: `structure_loops` +
`forward_dominators` on graphs of 10³, 10⁴, 10⁵ nodes; `structure` on the
largest corpus function graph and on generated reducible graphs of 10³
and 10⁴ nodes; bytes per node and per edge. Numbers in `PERF.md` beside
the reference console's time for `structure blocks` on the same graphs.

## 7. Acceptance

1. Section 3's "In" list is implemented; each item names its Ghidra
   member in its doc comment.
2. 6.2 replays clean on every graph (S), and 6.3.1 replays clean on every
   generated graph in every mode (S), on Windows, macOS and Linux.
3. 6.3.2: every corpus graph structured from the `blockstructure` dump
   equals Ghidra's hierarchy, flips and change count, and after `finish`
   the final hierarchy (S for the checked-in subset, L for all); any
   exception is listed with the first differing line.
4. The measure's goto count equals the number of `G` records Ghidra's
   run produced, for every graph of 6.3 (plan 8, 3b).
5. 6.4, 6.5 pass; the fuzz targets have run 300 s each on the build host
   (`scripts/remote.sh long fuzz 300 …`) without finding.
6. Both oracle tables were generated twice on each reference build with
   identical results, or every difference is recognised by cause and
   counted (6.3.3).
7. Benchmarks recorded; no `unsafe`; no recursion over input-sized
   structures; gate green on both remote gate runs; files within the size
   limit.

## 8. Differences from Ghidra

- Facts in, flips out: the structurer does not call into basic blocks;
  `isComplex` and the other per-block answers are inputs and negations of
  basic blocks are returned as events (ADR-028; 4.1, 4.5). Same result.
- `orderBlocks` is stable among blocks ending in `RETURN` (ADR-040; 4.9).
- The spanning-tree rebuild is bounded (4.2); `selectBadEdge` on an empty
  list is an error (4.7); a document with unfilled edge slots is rejected
  (4.10); `Limits` and no recursion (5.3).
- Sorting ties in `labelLoops` and `BlockMap` are resolved stably (no
  observable difference on valid input).

(The implementing agent appends further differences here.)

Added by the implementing track (`docs/agents/decomp-cfg.md`):

- `TraceDAG::pushBranches` stops with `CfgError::TraceCycle` when one trace
  opens more than `2·nodes + 8` branch points. In an acyclic view each node
  opens at most once; past that the view has a cycle on which Ghidra opens
  and retires branch points forever, allocating one per turn (a new Ghidra
  defect, reproduced on a 25-node function-like graph; the 6.2 table has it
  as a `hang` row). Ghidra never finishes such a graph, so no output
  differs.
- The checks Ghidra makes only in debug builds (`BLOCKCONSISTENT_DEBUG`) are
  made only at the public `Cfg` entry points (`Bad edge create`, …); inside
  the structurer the release behaviour is ported (`forceOutputNum` with too
  many outputs does nothing, as the reference build does).
- Where Ghidra would dereference null or index out of bounds on hostile
  input — a null front leaf in `addCase` (reported as `Case block has become
  detached from switch`), a null dominator or an index that is not a list
  position in `calcForwardDominator` (`CfgError::BadIndex`), the finger
  loop failing to meet (the work limit) — Basilisk returns an error.
- A block document whose `<bhead>` declares a nested `graph` or `copy`
  block is rejected (`CfgError::BadDocument`): Ghidra's decoder builds a
  `BlockCopy` with a null original that the structurer later dereferences.
- `Limits::max_steps` defaults to `2·(n+e)² + 10⁶` (measured, `docs/PERF.md`),
  not the provisional `64·(n+e)²/1000 + 10⁶`, which 720-node graphs exceed.
- The oracle table of 6.3.1 stores, per graph and mode, the dump's header
  line and a 128-bit FNV-1a fingerprint of the dump instead of the dump
  (about 12,000 graphs times four dumps of several kilobytes would not fit
  the repository); the 6.2 table stores the full outputs (1.1 MB).

## 9. Status

Implemented by track `decomp-cfg` (report: `docs/agents/decomp-cfg.md`).
Everything of section 3 is built; the structurer equals the reference's
`structure blocks` byte for byte on 4,000 generated graphs on both
reference builds (6.2), whose tables are identical. Waiting for D00: the
`bk cfg`/`bk structure` table of 6.3.1 (the tests are written and skip),
the corpus captures of 6.3.2 and the trace comparison of 6.4 against
Ghidra's `R` records, and with them the confirmation that
`Case block has become detached from switch` on graphs with input
default-switch labels is Ghidra's result too.

## 10. Open items

1. How often a top-level list longer than 16 nodes with two blocks ending
   in `RETURN` occurs in real functions (4.9). D00's capture of 6.3.2
   counts top-level lists by length and `RETURN` blocks; until it runs
   the answer is unknown. If it never occurs in the corpora the stable
   sort is a difference without a measured case.
2. Whether `selectBadEdge`'s empty-list case (4.7) is reachable. The
   random-graph table of 6.3.1 will show it as a crash or a garbage result
   of the reference on some graph if it is.
3. The default of `max_steps` (5.3) is a guess until the corpus
   benchmarks exist.

Settled by the implementing track:

4. Item 2: **unreachable, by reading.** When no trace can move, take a
   deepest open branch point (one whose paths are all active; it exists
   because every inactive path has a derived branch point and the chain is
   finite). Its paths are not empty (a lone non-terminal path retires its
   branch point before it can be chosen as a bad edge, so `removeTrace`
   never empties one). If all its paths are terminal, its path 0 retires it
   (`checkRetirement`), and the cursor visits path 0 before
   `missedactivecount` reaches `activecount`; a non-terminal path is either
   a virtual root path, which always opens, or a candidate. So the list is
   never empty when `selectBadEdge` runs. The property test asserts
   `NoBadEdge` never occurs; no run produced it. (A different
   non-termination does exist: see section 8, `TraceCycle`.)
5. Item 3: `max_steps` defaults to `2·(n+e)² + 10⁶` (section 8). The
   corpus benchmark waits for D00's captures.
6. Item 1, generated graphs only: of 11,661 finished runs over the 6.3.1
   graph set, 120 end with two or more top-level nodes ending in `RETURN`
   (119 of them on a top level of four or more nodes, where libc++ may
   reorder, 25 of 17 or more, where libstdc++ may); pinned in
   `tests/oracle_bk.rs`. Whether the libraries actually differ on them is
   seen when the D00 table exists on both builds; the corpora count waits
   for D00's capture.
7. Spec items found wrong (the source wins): the messages `Bad block output
   force`, `Bad block identify`, `Bad edge create/remove/move`, `Bad block
   remove`, `Bad (or Illegal) remove from flow (split)`, `Bad set start` and
   `Swapping edges for block that doesn't have two edges` are debug-build
   checks that the reference never raises (4.4 says `forceOutputNum`
   raises one); `forceFalseEdge` also raises `Can only preserve binary
   condition` (block.cc:1221), missing from 5.2; 4.1 "both halves of one
   edge carry the same label" does not hold after `dedup`, which ORs a
   merged label into one half only (block.cc:463, 492); 4.9 step 5 — a
   graph passes its *own* argument to its first component, not `true`
   (block.cc:1278; only loops pass `true`); 4.9 step 1 — `compareFinalOrder`
   reads `lastOp()` of top-level *structured* nodes, which delegates by
   kind (goto kinds to component 0, list to its last, condition to
   component 1, if-no-exit to component 2, others null), so
   `ends_in_return` is asked of that leaf; 4.2 — the virtual root of
   `calcForwardDominator` has index 0, so Ghidra's finger arithmetic maps
   it to list position 0 and an intersection reaching it yields `list[0]`
   (reproduced); 5.3 — the default step limit (item 5).

