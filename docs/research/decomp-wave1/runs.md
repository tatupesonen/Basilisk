# Runs against the reference tools

All on the development Mac (`../reference`, Darwin arm64, Apple clang 17,
libc++) unless marked. `CONSOLE` = `echo | SLEIGHHOME=../reference
perl -e 'alarm 300; exec @ARGV' ../reference/bin/decomp -i SCRIPT`.
`DT` = `../ghidra/Ghidra/Features/Decompiler/src/decompile/datatests`.

## R1. `print tree block` (elseif.xml)

Script: `load test file DT/elseif.xml`, `execute test command 1-7`,
`print tree block`, `decompile`, `print tree block`. Before `decompile`
nothing is printed (`Funcdata::printBlockTree` prints only when the
structured graph is non-empty). After: two spaces of indent per level,
`printHeader` per block (`List block 0`, `If/else block 5`,
`Condition block(&&) 27`, `If goto block 32`, `Whiledo block 34`,
`Basic Block 3 0x001006de-0x001006f4`). A `BlockCopy` prints as its basic
block (`BlockCopy::printTree` delegates).

## R2. `structure blocks` on a hand-written graph

`load test file DT/elseif.xml` (any architecture: `XmlDecode` needs one),
then `structure blocks g1.xml g1.out.xml` on a five-node graph (0→1,2;
1→3; 2→3; 3→4,0). Output: nested `<block index=…>` with `<bhead index
type>` children (`list`, `dowhile`, `ifelse`, `copy`), copies carry
`altindex` = the input block's index, `index` = the reverse-post-order
index structureLoops assigned. `orderBlocks` is not called by this
command (it is by `StructureGraph::rawAction`, ghidra_process.cc:352).

## R3. 3,000 random graphs through `structure blocks`

`python3 -I gen_graphs.py 1 3000 40 rand`, one console session with one
`structure blocks` per graph: 0.9 s in total, exit 0, no crash, no hang.
161 graphs end in `Could not finish collapsing block structure`
(`CollapseStructure::selectGoto`); 156 of them have nodes unreachable from
block 0 (an unreachable cycle has no root for `clipExtraRoots` or
`TraceDAG`); the other 5 are reachable graphs with two out-edges of one
block to the same target or with in-edges to the entry. Two runs:
outputs byte-identical (sha256 of all outputs `124c7654…`) and logs
identical.
